import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";

import type { EmuCallInput, EmuCallOutput, EmuOpenInput, EmuOpenOutput } from "../../contracts/areas/emulation.js";
import { planDigest } from "../../domain/callModel/classify.js";
import { resolveFpEnv, WINDOWS_DEFAULT_FPCW, WINDOWS_DEFAULT_MXCSR } from "../../domain/callModel/fpEnv.js";
import type { CallOutcomeColumns, CallScalarType } from "../../domain/callModel/types.js";
import { canonicalDigest, sha256Hex } from "../../domain/canonical.js";
import { Deadline } from "../../domain/deadline.js";
import type { DumpManifest } from "../../domain/dumpBundle.js";
import {
  EMU_PROTOCOL,
  type BatchResult,
  type CallResult,
  type OpenParams,
  type OpenResult,
  type RunOptions,
  type StateWire,
  type StopRecord,
  type SweepParams,
  type SweepResult,
} from "../../domain/emuProtocol.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError, withPartial } from "../../domain/errors/constructors.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import { CORE_LIMITATIONS } from "../../domain/evidence/limitations.js";
import { CALL_LIMITATIONS } from "../../domain/evidence/limitations/call.js";
import { EMULATION_LIMITATIONS } from "../../domain/evidence/limitations/emulation.js";
import type { BlobRef, Subject } from "../../domain/evidence/record.js";
import type { EvId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { ResolvedAddress } from "../../ports/address.js";
import type { BundleCaptureResult } from "../../ports/dumps.js";
import type { EmuRequestOptions, EmuSessionHandle, PartialBatch } from "../../ports/emu.js";
import type { SensitiveLiterals } from "../../ports/evidence.js";
import type { OperationContext } from "../../ports/sessions.js";
import { formatHex, type Hex } from "../../shared/hex.js";
import type { BeaApplication } from "../BeaApplication.js";
import { verifyDumpBundle } from "../dump/verifyDumpBundle.js";
import type { HandlerContext } from "../handlerContext.js";
import { emuOp, liveOp } from "../sessionAccess.js";
import {
  canonical,
  classifyRequest,
  invalid,
  lowerPlan,
  requestAddressExprs,
  requestColumns,
  requestVectors,
  scalarBytes,
  wireVectors,
  type CallModelRequest,
  type ClassifiedRequest,
  type WindowVectors,
} from "./callPrep.js";
import { buildCoverageBlob, COVERAGE_BLOB_ROLE, COVERAGE_MEDIA_TYPE } from "./coverageBlob.js";
import { assessEmulation } from "./deviations.js";
import { deliver, EMU_BATCH_DECODERS, EMU_SWEEP_DECODERS, writeRowStream, type WrittenStream } from "./envelope.js";
import {
  afterDigest,
  baselineDigest,
  digestHex,
  LineageStore,
  queryId,
  type SessionRecord,
  type StateDigest,
} from "./lineage.js";
import { BEA_PACKAGE_VERSION } from "./packageVersion.js";
import {
  batchRow,
  byStatus,
  byStatusOfSummary,
  deviationView,
  emulatorOutcome,
  eventsView,
  fieldTypes,
  hex64,
  inlineColumns,
  MAX_FAULTS,
  outBuffersView,
  OUTPUT_ARRAY_INLINE_CAP,
  outputsOf,
  PREVIEW_ROWS,
  previewRow,
  rawView,
  retStats,
  retValue,
  singleOutcome,
  stopView,
  sweepMatches,
  sweepRow,
  traceView,
} from "./views.js";
import { checkLocalInputPath } from "../localPaths.js";

/**
 * emu_open and emu_call (S5 §8.1–§8.2, DESIGN §6.2 #31/#32). The service owns the application half of emulation:
 * dump capture/verification and image identity before the open, the per-session state lineage (§11.2), call-model
 * preparation against the EMULATION address space (AddressService emulation spaces, init_from through mem.read), the
 * deadline/continuation discipline (§5.5: the bridge gets the host deadline − 500 ms; a deadline is a successful
 * partial result with `continuation`, a cancel records the completed prefix before the `cancelled` error), result
 * shaping, row streams, coverage blobs and the evidence records (observed, authority emulation, D-INT-19).
 */
const MiB = 1024 * 1024;
const BRIDGE_DEADLINE_MARGIN_MS = 500;
/** time kept back from the handler budget for streams, blobs and the evidence record */
const FINALIZE_RESERVE_MS = 1_000;
const SHA256_RE = /^[a-f0-9]{64}$/u;
/** the address forms the bridge resolves itself in emu_open patches (S5 §8.1 step 6) */
const PATCH_ADDRESS_RE = /^(?:0[xX][0-9a-fA-F]{1,16}|[^+!\s]+\+0[xX][0-9a-fA-F]{1,16}|[^+!\s]+![^+!\s]+)$/u;
const MAX_PATCH_BYTES = MiB;
const PROVIDER = { id: "unicorn", name: "Unicorn via bea-emu bridge" } as const;
const MAX_FAULT_DETAILS = 4;
/** indices of the first and last PREVIEW_ROWS rows (no duplicates) */
const previewRows = (completed: number): number[] => [
  ...new Set([
    ...Array.from({ length: Math.min(PREVIEW_ROWS, completed) }, (_, k) => k),
    ...Array.from(
      { length: Math.min(PREVIEW_ROWS, completed) },
      (_, k) => completed - Math.min(PREVIEW_ROWS, completed) + k,
    ),
  ]),
];

let nextOpId = 1_000_000;

/**
 * An emulator error as the tool reports it: a provider_timeout names the tool's own timeout_ms (the port only sees
 * the absolute deadline, so it cannot say which budget ran out).
 */
export const toolError = (error: BeaError, operation: string, timeoutMs: number): BeaError =>
  error._tag === "ProviderTimeout" ? { ...error, operation, timeout_ms: timeoutMs } : { ...error, operation };

/**
 * A single call the deadline watchdog stopped (see the single-call branch of `call`) reports cause "deadline", as a
 * batch vector stopped at the batch deadline does (S5 §3.10), not the per-call watchdog the request never set.
 */
const deadlineStop = (call: CallResult): CallResult =>
  call.status === "timeout" && call.stop !== null && call.stop.cause === "watchdog"
    ? { ...call, stop: { ...call.stop, cause: "deadline" } }
    : call;

/** An OperationContext for work that has no session yet (emu_open): the tool's own signal and budget. */
export const operationFor = (name: string, ctx: HandlerContext, budgetMs: number): OperationContext => {
  nextOpId += 1;
  return {
    opId: nextOpId,
    name,
    signal: ctx.signal,
    deadline: Deadline.after(budgetMs),
    progress: (phase, message) => ctx.progress.report(phase, message),
  };
};

const sha256File = (path: string, signal: AbortSignal): Promise<Result<string, BeaError>> =>
  new Promise((resolve) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path, { signal });
    stream.on("data", (chunk) => hash.update(chunk));
    stream.once("error", (cause: NodeJS.ErrnoException) =>
      resolve(
        err({
          _tag: "FileOperationFailed",
          operation: "emu_open",
          file_operation: "read",
          path,
          reason:
            cause.code === "ENOENT"
              ? "missing"
              : cause.code === "EISDIR"
                ? "not-file"
                : cause.code === "EACCES"
                  ? "permission"
                  : "io",
        }),
      ),
    );
    stream.once("end", () => resolve(ok(hash.digest("hex"))));
  });

const sha256OrNull = (text: string | null | undefined): string | null =>
  text !== null && text !== undefined && SHA256_RE.test(text.toLowerCase()) ? text.toLowerCase() : null;

const bytesOfHex = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
};

const toCallRequest = (input: {
  readonly signature: EmuCallInput["signature"];
  readonly buffers: EmuCallInput["buffers"];
  readonly args?: EmuCallInput["args"];
  readonly fields?: EmuCallInput["fields"];
  readonly vectors?: EmuCallInput["vectors"];
  readonly generate?: EmuCallInput["generate"];
  readonly vector_offset: number;
}): CallModelRequest => ({
  signature: input.signature,
  buffers: input.buffers,
  args: input.args,
  fields: input.fields,
  vectors: input.vectors,
  generate: input.generate,
  vector_offset: input.vector_offset,
});

export interface FpChoice {
  readonly mxcsr: number;
  readonly fpcw: number;
  readonly source: "explicit" | "dump-thread" | "windows-default";
}

/** FP state of the captured thread (WP-DUMP's context carries mxcsr/fpcw beside the GPRs). */
const dumpThreadFp = (manifest: DumpManifest, threadId: number | undefined): { mxcsr: number; fpcw: number } | null => {
  const thread = manifest.threads.find((t) => (threadId === undefined ? t.primary : t.tid === threadId));
  const context = thread?.context as { mxcsr?: string; fpcw?: string } | undefined;
  if (context?.mxcsr === undefined || context.fpcw === undefined) return null;
  return { mxcsr: Number(BigInt(context.mxcsr) & 0xffffn), fpcw: Number(BigInt(context.fpcw) & 0xffffn) };
};

/** D-INT-43 for emulation: explicit > the dump's thread (auto/thread) > the Windows default. */
const chooseFp = (
  request: EmuOpenInput["fp"],
  dumpThread: { mxcsr: number; fpcw: number } | null,
  operation: string,
): Result<FpChoice, BeaError> => {
  const fp = request ?? { source: "auto" as const };
  if (fp.source === "thread" && dumpThread === null && (fp.mxcsr === undefined || fp.fpcw === undefined))
    return err(
      inputError(operation, [
        {
          path: "fp.source",
          reason: "invalid_value",
          message:
            'fp.source "thread" needs a dump-backed session whose captured thread carries its FP state; pass fp.mxcsr/fp.fpcw or use "auto".',
        },
      ]),
    );
  const resolved = resolveFpEnv(
    { ...fp, source: fp.source === "thread" ? "auto" : fp.source, thread_id: undefined },
    { threadId: null, env: null, dumpThread },
  );
  if (!resolved.ok) return err(inputError(operation, [resolved.error]));
  const source = resolved.value.source === "thread" ? "dump-thread" : resolved.value.source;
  return ok({ mxcsr: resolved.value.mxcsr, fpcw: resolved.value.fpcw, source });
};

/** The FP environment of one call: the session default, with explicit fields of the request on top. */
const callFp = (record: SessionRecord, request: EmuCallInput["fp"], operation: string): Result<FpChoice, BeaError> => {
  if (request === undefined) return ok(record.fp);
  if (request.source === "windows-default" && request.mxcsr === undefined && request.fpcw === undefined)
    return ok({ mxcsr: WINDOWS_DEFAULT_MXCSR, fpcw: WINDOWS_DEFAULT_FPCW, source: "windows-default" });
  if (
    request.source === "thread" &&
    record.fp.source !== "dump-thread" &&
    (request.mxcsr === undefined || request.fpcw === undefined)
  )
    return chooseFp(request, null, operation);
  const mxcsr = request.mxcsr === undefined ? record.fp.mxcsr : Number.parseInt(request.mxcsr, 16) & 0xffc0;
  const fpcw = request.fpcw === undefined ? record.fp.fpcw : Number.parseInt(request.fpcw, 16) & 0xffff;
  const explicit = request.mxcsr !== undefined && request.fpcw !== undefined;
  return ok({
    mxcsr,
    fpcw,
    source: explicit ? "explicit" : request.source === "windows-default" ? "windows-default" : record.fp.source,
  });
};

const fpOut = (fp: FpChoice) => ({ mxcsr: formatHex(fp.mxcsr), fpcw: formatHex(fp.fpcw), source: fp.source });

/** Normalized open options (identity: no paths, label or timeout). */
const normalizedOpen = (input: EmuOpenInput, params: OpenParams): JsonObject => ({
  memory: { ...params.memory } as JsonObject,
  protections: params.protections ?? "sections",
  imports: JSON.parse(JSON.stringify(params.imports ?? {})) as JsonObject,
  patches: (params.patches ?? []).map((p) => ({
    address: p.address,
    sha256: sha256Hex(p.hex),
    bytes: p.hex.length / 2,
  })),
  cpu: { mxcsr: params.cpu?.mxcsr ?? WINDOWS_DEFAULT_MXCSR, fpcw: params.cpu?.fpcw ?? WINDOWS_DEFAULT_FPCW },
  isa_guard: params.isaGuard ?? "stop",
  snapshots: params.snapshots ?? "cow",
  fault_policy: params.faultPolicy ?? "stop",
  image_base: input.image_base === undefined ? null : canonical(input.image_base),
  thread_id: input.thread_id ?? null,
  primary_module: input.primary_module ?? null,
});

export class EmulationService {
  readonly #app: BeaApplication;
  readonly lineage: LineageStore;

  constructor(app: BeaApplication, lineage: LineageStore = new LineageStore()) {
    this.#app = app;
    this.lineage = lineage;
  }

  #literals(): Result<SensitiveLiterals, BeaError> {
    return this.#app.services.evidence.literals(undefined);
  }

  // ================================================================ emu_open
  async open(input: EmuOpenInput, ctx: HandlerContext): Promise<Result<EmuOpenOutput, BeaError>> {
    const operation = ctx.operation;
    const { services, config } = this.#app;
    // SEC-2: caller-supplied image and dump paths are local files only (no UNC: NTLM to a remote host)
    for (const [field, path] of [
      ["image_path", input.image_path],
      ["dump_path", input.dump_path],
    ] as const)
      if (path !== undefined) {
        const local = await checkLocalInputPath(operation, field, path, config.platform);
        if (!local.ok) return local;
      }
    const literals = this.#literals();
    if (!literals.ok) return literals;
    const budgetMs = Math.min(input.timeout_ms, ctx.remainingMs());
    const started = this.#app.clock.monoMs();
    this.lineage.prune((id) => services.emulator.lookup(id) !== null);

    let capture: BundleCaptureResult | null = null;
    let bundlePath = input.dump_path ?? null;
    if (input.live_session_id !== undefined) {
      const captured = await liveOp(
        this.#app,
        ctx,
        input.live_session_id,
        { mode: "exclusive", need: "agent", path: "live_session_id" },
        (session, op) =>
          services.dumps.captureBundle(
            session,
            {
              modules: input.capture_modules ?? ["$main"],
              regions: input.capture_regions ?? [],
              ...(input.capture_thread_id === undefined ? {} : { threadId: input.capture_thread_id }),
              mode: "running",
            },
            op,
          ),
      );
      if (!captured.ok) return captured;
      capture = captured.value;
      bundlePath = capture.bundlePath;
    }
    let manifest: DumpManifest | null = null;
    if (bundlePath !== null) {
      const verified = await verifyDumpBundle(bundlePath, {
        maxTotalBytes: config.emu.dumpMaxMb.value * MiB,
        memoryLimitBytes: config.emu.memoryLimitMb.value * MiB,
        ...(input.thread_id === undefined ? {} : { threadId: input.thread_id }),
        path: input.live_session_id === undefined ? "dump_path" : "live_session_id",
        operation,
        signal: ctx.signal,
      });
      if (!verified.ok) return verified;
      manifest = verified.value.manifest;
    }
    let hostSha: string | null = null;
    if (input.image_path !== undefined) {
      const hashed = await sha256File(input.image_path, ctx.signal);
      if (!hashed.ok) return err({ ...hashed.error, operation });
      hostSha = hashed.value;
    }
    const fp = chooseFp(input.fp, manifest === null ? null : dumpThreadFp(manifest, input.thread_id), operation);
    if (!fp.ok) return fp;
    const elapsed = this.#app.clock.monoMs() - started;
    const params = this.#openParams(
      input,
      bundlePath,
      fp.value,
      Math.max(1_000, budgetMs - elapsed - BRIDGE_DEADLINE_MARGIN_MS),
    );
    if (!params.ok) return params;

    const op = operationFor(operation, ctx, Math.max(1_000, budgetMs - elapsed));
    const openStarted = this.#app.clock.monoMs();
    const opened = await services.emulator.open(params.value, op);
    if (!opened.ok) return err(toolError(opened.error, operation, input.timeout_ms));
    const openMs = this.#app.clock.monoMs() - openStarted;
    const { runtime, open } = opened.value;
    const abandon = async (error: BeaError): Promise<Result<never, BeaError>> => {
      await services.emulator.close(runtime).catch(() => undefined);
      await services.sessions.close(runtime.sessionId, { force: false }, op).catch(() => undefined);
      return err(error);
    };
    const bridgeSha = sha256OrNull(open.primary.sha256);
    if (hostSha !== null && bridgeSha !== null && bridgeSha !== hostSha)
      return abandon({
        _tag: "EvidenceIntegrity",
        operation,
        reason: "id-mismatch",
        message: "The image changed on disk while the emulation session was opening.",
        remediation: "Make sure the file is not being rebuilt or replaced, then emu_open again.",
      });

    const availability = services.emulator.availability();
    const engines = availability.versions;
    const imageSha =
      hostSha ??
      bridgeSha ??
      (manifest !== null ? manifest.bundle_id.slice(5) : canonicalDigest(open.primary as unknown as JsonValue));
    const options = normalizedOpen(input, params.value);
    const baseline = baselineDigest({
      source:
        manifest === null
          ? { kind: "image", sha256: imageSha, mappedBase: hex64(open.primary.mappedBase) }
          : { kind: "dump", bundleId: manifest.bundle_id },
      open: options,
      bridge: { protocol: EMU_PROTOCOL, version: BEA_PACKAGE_VERSION },
      engines: { unicorn: engines?.unicorn ?? "", capstone: engines?.capstone ?? "", pefile: engines?.pefile ?? "" },
    });
    const configDigest = canonicalDigest({
      protocol: EMU_PROTOCOL,
      bridge: { version: BEA_PACKAGE_VERSION },
      engines: engines === null ? null : ({ ...engines } as JsonObject),
      image_sha256: imageSha,
      mapped_base: hex64(open.primary.mappedBase),
      options,
    });
    const status = services.emulator.status(runtime);
    const result = this.#openResult(input, open, runtime, {
      manifest,
      capture,
      fp: fp.value,
      baseline,
      bridge: { pid: status.bridgePid, childPid: status.childPid },
      openMs,
    });
    const engineUnvalidated = availability.pin === "compatible";
    const assessment = assessEmulation({
      deviations: open.loaderDeviations,
      extraLimitations: [
        ...(manifest === null ? [] : [EMULATION_LIMITATIONS.EMU_DUMP_STATE]),
        ...(manifest?.capture.mode === "running" ? [EMULATION_LIMITATIONS.EMU_DUMP_RUNNING] : []),
        ...(engineUnvalidated ? [EMULATION_LIMITATIONS.EMU_ENGINE_UNVALIDATED] : []),
      ],
    });
    const recorded = await services.evidence.recorder.record({
      predicate_type: "bea.emu.session",
      operation,
      input: {
        source: manifest === null ? "image" : "dump",
        image_path: input.image_path ?? null,
        dump_path: bundlePath,
        live_session_id: input.live_session_id ?? null,
        options,
      },
      subject: {
        kind: "emulation",
        image_sha256: imageSha,
        config_digest: configDigest,
        state: manifest === null ? { basis: "baseline" } : { basis: "dump", dump_digest: manifest.bundle_id.slice(5) },
        module_map_id: null,
      },
      provider: { ...PROVIDER, version: engines?.unicorn ?? null },
      result: result as unknown as JsonObject,
      coverage: COMPLETE,
      limitations: assessment.limitations,
      ...(capture === null ? {} : { evidence_links: [capture.evidenceId] }),
      literals: literals.value,
    });
    if (!recorded.ok) return abandon(recorded.error);
    this.lineage.add(
      {
        sessionId: runtime.sessionId,
        source: manifest === null ? "image" : "dump",
        imageSha256: imageSha,
        configDigest,
        bundleId: manifest?.bundle_id ?? null,
        producerInstance: manifest?.producer.instance_id ?? null,
        sessionEvidence: recorded.value.record.evidence_id as EvId,
        fp: fp.value,
        faultPolicy: input.fault_policy,
        syntheticBase: hex64(open.layout.syntheticBase),
        engineUnvalidated,
        baseline,
      },
      runtime.generation,
    );
    return ok(deliver(recorded.value) as unknown as EmuOpenOutput);
  }

  #openParams(
    input: EmuOpenInput,
    bundlePath: string | null,
    fp: FpChoice,
    deadlineMs: number,
  ): Result<OpenParams, BeaError> {
    const operation = "emu_open";
    const issues: { path: string; reason: "invalid_value" | "out_of_range"; message: string }[] = [];
    const overrides: NonNullable<NonNullable<OpenParams["imports"]>["overrides"]> = [];
    (input.imports?.overrides ?? []).forEach((o, i) => {
      if (o.action === "stop") overrides.push({ key: o.import, action: "stop" });
      else if (o.action === "model") overrides.push({ key: o.import, action: "model", model: o.model ?? "" });
      else {
        const type = o.returns_type ?? "void";
        if (type === "void") {
          overrides.push({ key: o.import, action: "return", returns: { kind: "void", bits: "0x0" } });
          return;
        }
        const bits = scalarBytes(type, o.returns_value ?? 0, () => undefined);
        if (!bits.ok) {
          issues.push({
            path: `imports.overrides[${String(i)}].returns_value`,
            reason: "invalid_value",
            message: bits.error,
          });
          return;
        }
        const lane = BigInt(`0x${bits.value.match(/../gu)?.reverse().join("") ?? "0"}`);
        overrides.push({
          key: o.import,
          action: "return",
          returns: { kind: type === "f32" || type === "f64" ? type : "int", bits: formatHex(lane) },
        });
      }
    });
    const patches: { address: string; hex: string }[] = [];
    let patchBytes = 0;
    (input.patches ?? []).forEach((p, i) => {
      if (!PATCH_ADDRESS_RE.test(p.address)) {
        issues.push({
          path: `patches[${String(i)}].address`,
          reason: "invalid_value",
          message:
            'Patch addresses take "0x…", "module+0xRVA" or "module!export" (resolved by the emulator before the baseline).',
        });
        return;
      }
      const address = /^0[xX]/u.test(p.address) ? canonical(p.address) : p.address;
      let hex = p.hex?.toLowerCase();
      if (hex === undefined) {
        const bytes = scalarBytes(p.type as CallScalarType, p.value ?? 0, () => undefined);
        if (!bytes.ok) {
          issues.push({ path: `patches[${String(i)}].value`, reason: "invalid_value", message: bytes.error });
          return;
        }
        hex = bytes.value;
      }
      patchBytes += hex.length / 2;
      patches.push({ address, hex });
    });
    if (patchBytes > MAX_PATCH_BYTES)
      issues.push({ path: "patches", reason: "out_of_range", message: "Patches total at most 1 MiB." });
    if (issues.length > 0) return err(inputError(operation, issues));
    const imports = input.imports;
    return ok({
      source:
        input.image_path !== undefined
          ? {
              kind: "image",
              path: input.image_path,
              ...(input.image_base === undefined ? {} : { base: canonical(input.image_base) }),
            }
          : {
              kind: "dump",
              bundlePath: bundlePath ?? "",
              ...(input.thread_id === undefined ? {} : { thread: input.thread_id }),
              ...(input.primary_module === undefined ? {} : { primaryModule: input.primary_module }),
            },
      memory: {
        heapBytes: (input.memory?.heap_mb ?? 64) * MiB,
        scratchBytes: (input.memory?.scratch_mb ?? 16) * MiB,
        stackBytes: (input.memory?.stack_kb ?? 1024) * 1024,
      },
      protections: input.protections,
      imports: {
        builtin: imports?.builtin ?? true,
        unhandled: imports?.unhandled ?? "stop",
        dumpPolicy: imports?.dump_policy ?? "auto",
        overrides,
      },
      patches,
      cpu: { mxcsr: fp.mxcsr, fpcw: fp.fpcw },
      isaGuard: input.isa_guard,
      snapshots: input.snapshots,
      faultPolicy: input.fault_policy,
      deadlineMs: Math.round(deadlineMs),
    });
  }

  #openResult(
    input: EmuOpenInput,
    open: OpenResult,
    runtime: EmuSessionHandle,
    extra: {
      readonly manifest: DumpManifest | null;
      readonly capture: BundleCaptureResult | null;
      readonly fp: FpChoice;
      readonly baseline: StateDigest;
      readonly bridge: { readonly pid: number | null; readonly childPid: number | null };
      readonly openMs: number;
    },
  ): Omit<EmuOpenOutput, "evidence_id" | "predicate_type" | "confidence" | "authority" | "coverage" | "limitations"> {
    const availability = this.#app.services.emulator.availability();
    const p = open.primary;
    const preferred = p.preferredBase === null ? null : hex64(p.preferredBase);
    const t = open.timings;
    return {
      session_id: runtime.sessionId,
      kind: "emulation",
      source: extra.manifest === null ? "image" : "dump",
      bundle_id: extra.manifest?.bundle_id ?? null,
      primary: {
        name: p.name,
        path: p.path,
        sha256: sha256OrNull(p.sha256),
        preferred_base: preferred,
        mapped_base: hex64(p.mappedBase),
        static_base: preferred,
        static_base_source: preferred === null ? null : "pe-header",
        relocated: p.relocated,
        size: p.size,
        sections: p.sections.length,
        exports: p.exports,
        pdata_functions: p.pdataFunctions,
        tls_callbacks: p.tlsCallbacks.length,
        delay_imports: p.delayImports,
      },
      modules: open.modules.slice(0, 64).map((m) => ({
        name: m.name,
        mapped_base: hex64(m.mappedBase),
        size: m.size,
        captured: m.captured,
        sha256: sha256OrNull(m.sha256),
      })),
      thread: open.thread === null ? null : { tid: open.thread.tid, teb: hex64(open.thread.teb) },
      imports: {
        total: open.imports.total,
        models: { ...open.imports.models },
        unhandled_sample: open.imports.unhandled.slice(0, 50),
      },
      isa: {
        cache: open.isa.cache,
        scan_ms: Math.round(open.isa.scanMs),
        sites: { ...open.isa.sites },
        guarded: { ...open.isa.guarded },
        functions_with_vex_sample: open.isa.functionsWithVex.slice(0, 20).map((rva) => hex64(rva)),
      },
      fp: fpOut(extra.fp),
      snapshots: open.snapshots,
      memory: {
        heap_mb: input.memory?.heap_mb ?? 64,
        scratch_mb: input.memory?.scratch_mb ?? 16,
        stack_kb: input.memory?.stack_kb ?? 1024,
        mapped_mb: Math.ceil(open.layout.mappedBytes / MiB),
        synthetic_base: hex64(open.layout.syntheticBase),
        limit_mb: this.#app.config.emu.memoryLimitMb.value,
      },
      loader_deviations: deviationView(open.loaderDeviations),
      bridge: {
        pid: extra.bridge.pid,
        child_pid: extra.bridge.childPid,
        version: BEA_PACKAGE_VERSION,
        protocol: EMU_PROTOCOL,
        generation: runtime.generation,
        engines: availability.versions === null ? {} : { ...availability.versions },
        python: {
          source: availability.source ?? "unknown",
          version: availability.versions?.python ?? "",
          pin: availability.pin ?? "compatible",
        },
      },
      capture:
        extra.capture === null
          ? null
          : {
              bundle_path: extra.capture.bundlePath,
              evidence_id: extra.capture.evidenceId,
              regions: extra.capture.regions,
              modules: extra.capture.modules,
              threads: extra.capture.threads,
            },
      baseline_state: extra.baseline,
      timings_ms: {
        bridge_start: Math.max(0, Math.round(extra.openMs - t.totalMs)),
        load: Math.round(t.loadMs),
        isa: Math.round(t.isaMs),
        bind: Math.round(t.bindMs),
        snapshot: Math.round(t.snapshotMs),
        total: Math.round(extra.openMs),
      },
    };
  }

  /** The lineage record of a session (synthesized for a session this service did not open, e.g. after a restart). */
  record(handle: EmuSessionHandle): SessionRecord {
    const known = this.lineage.get(handle.sessionId, handle.generation);
    if (known !== null) return known;
    const modules = this.#app.services.emulator.modules(handle);
    const primary = modules.find((m) => m.primary) ?? modules[0];
    const imageSha = sha256OrNull(primary?.sha256) ?? canonicalDigest({ session: handle.sessionId });
    return this.lineage.add(
      {
        sessionId: handle.sessionId,
        source: "image",
        imageSha256: imageSha,
        configDigest: canonicalDigest({ session: handle.sessionId, image_sha256: imageSha }),
        bundleId: null,
        producerInstance: null,
        sessionEvidence: null,
        fp: { mxcsr: WINDOWS_DEFAULT_MXCSR, fpcw: WINDOWS_DEFAULT_FPCW, source: "windows-default" },
        faultPolicy: "stop",
        syntheticBase: null,
        engineUnvalidated: this.#app.services.emulator.availability().pin === "compatible",
        baseline: `es_${canonicalDigest({ session: handle.sessionId, kind: "unknown-baseline" })}`,
      },
      handle.generation,
    );
  }

  // ================================================================ emu_call
  call(input: EmuCallInput, ctx: HandlerContext): Promise<Result<EmuCallOutput, BeaError>> {
    return emuOp(this.#app, ctx, input.session_id, (handle, op) => this.#call(input, ctx, handle, op));
  }

  /** emulation-space resolution of every AddrExpr the request carries (target, ptr positions, state writes) */
  async resolveAll(
    handle: EmuSessionHandle,
    exprs: readonly string[],
    op: OperationContext,
    path: string,
  ): Promise<Result<Map<string, ResolvedAddress>, BeaError>> {
    const out = new Map<string, ResolvedAddress>();
    for (const expr of exprs) {
      const r = await this.#app.services.address.resolve({ kind: "emulation", sessionId: handle.sessionId }, expr, op, {
        path,
      });
      if (!r.ok) return r;
      out.set(expr, r.value);
    }
    return ok(out);
  }

  /** init_from bytes through mem.read (≤ 16 MiB per buffer; CI-I2: once per call). */
  async readInitFrom(
    handle: EmuSessionHandle,
    buffers: CallModelRequest["buffers"],
    resolved: ReadonlyMap<string, ResolvedAddress>,
    o: EmuRequestOptions,
    operation: string,
  ): Promise<Result<Map<string, Uint8Array>, BeaError>> {
    const out = new Map<string, Uint8Array>();
    for (const [i, buffer] of buffers.entries()) {
      if (buffer.init_from === undefined) continue;
      const source = resolved.get(buffer.init_from);
      if (source === undefined)
        return err(invalid(operation, `buffers[${String(i)}].init_from`, "The address could not be resolved."));
      const read = await this.#app.services.emulator.readMemory(handle, formatHex(source.va), buffer.size, o);
      if (!read.ok) return err({ ...read.error, operation });
      const hex =
        read.value.encoding === "hex"
          ? read.value.data.toLowerCase()
          : Buffer.from(read.value.data, "base64").toString("hex");
      if (hex.length / 2 < buffer.size)
        return err({
          _tag: "MemoryAccessFailed",
          operation,
          address: formatHex(source.va),
          access: "read",
          size: buffer.size,
          message: "init_from: the emulated memory is not readable for the whole buffer size.",
        });
      out.set(buffer.name, bytesOfHex(hex.slice(0, buffer.size * 2)));
    }
    return ok(out);
  }

  async #call(
    input: EmuCallInput,
    ctx: HandlerContext,
    handle: EmuSessionHandle,
    op: OperationContext,
  ): Promise<Result<EmuCallOutput, BeaError>> {
    const operation = ctx.operation;
    const { services } = this.#app;
    const literals = this.#literals();
    if (!literals.ok) return literals;
    // EMU-8: a lost bridge is re-opened BEFORE the lineage is read, so from_digest, the after digest and save_as are
    // computed against the generation the run really executes in (baseline after a re-open)
    const ready =
      (await services.emulator.ensureReady?.(handle, {
        signal: op.signal,
        deadlineAt: this.#app.clock.monoMs() + Math.max(1_000, Math.min(input.timeout_ms, ctx.remainingMs())),
      })) ?? ok(handle);
    if (!ready.ok) return ready;
    const record = this.record(ready.value);
    const mode: "single" | "batch" | "sweep" =
      input.sweep !== undefined
        ? "sweep"
        : input.vectors !== undefined || input.generate !== undefined
          ? "batch"
          : "single";
    if (mode === "single" && input.vector_offset !== 0)
      return err(invalid(operation, "vector_offset", "vector_offset applies to batches (vectors or generate)."));
    const trace = input.trace;
    if (mode !== "single" && trace !== undefined && (trace.blocks || trace.memory !== "off" || trace.instructions))
      return err(
        invalid(
          operation,
          "trace",
          "Batches and sweeps take trace.coverage, trace.imports and trace.count_instructions only; blocks, memory and instructions are single-call traces.",
        ),
      );
    const budgetMs = Math.max(1_000, Math.min(input.timeout_ms, ctx.remainingMs()) - FINALIZE_RESERVE_MS);
    const now = (): number => this.#app.clock.monoMs();
    const deadlineAt = now() + budgetMs;
    const o: EmuRequestOptions = {
      signal: op.signal,
      deadlineAt,
      onProgress: (completed, total) =>
        ctx.progress.report("emulate", `${mode}: ${String(completed)}/${total === null ? "?" : String(total)}`),
    };
    const request = toCallRequest(input);
    const columns = requestColumns(request, operation);
    if (!columns.ok) return columns;

    // ---- addresses in the emulation space: target, ptr positions, init_from, state writes
    const exprs = new Set(requestAddressExprs(request, columns.value));
    for (const b of request.buffers) if (b.init_from !== undefined) exprs.add(b.init_from);
    for (const w of input.state?.writes ?? []) exprs.add(w.address);
    if (input.address !== undefined) exprs.add(input.address);
    const resolved = await this.resolveAll(handle, [...exprs].sort(), op, "address");
    if (!resolved.ok) return resolved;
    const vaOf = (expr: string): bigint | undefined => resolved.value.get(expr)?.va;
    const target = input.address === undefined ? null : (resolved.value.get(input.address) ?? null);

    const initFrom = await this.readInitFrom(handle, request.buffers, resolved.value, o, operation);
    if (!initFrom.ok) return initFrom;
    const classified = classifyRequest(request, columns.value, initFrom.value, vaOf, operation);
    if (!classified.ok) return classified;
    const window = requestVectors(
      request,
      classified.value,
      columns.value,
      vaOf,
      operation,
      mode === "single" ? 1 : undefined,
    );
    if (!window.ok) return window;
    const wire = lowerPlan(classified.value.plan, target === null ? "0x0" : formatHex(target.va), vaOf, operation);
    if (!wire.ok) return wire;

    // ---- state, FP, options
    const fp = callFp(record, input.fp, operation);
    if (!fp.ok) return fp;
    const writes: { address: Hex; hex: string }[] = [];
    for (const [i, w] of (input.state?.writes ?? []).entries()) {
      const va = vaOf(w.address);
      if (va === undefined)
        return err(invalid(operation, `state.writes[${String(i)}].address`, "The address could not be resolved."));
      let hex = w.hex?.toLowerCase();
      if (hex === undefined) {
        const bytes = scalarBytes(w.type as CallScalarType, w.value ?? 0, vaOf);
        if (!bytes.ok) return err(invalid(operation, `state.writes[${String(i)}].value`, bytes.error));
        hex = bytes.value;
      }
      writes.push({ address: formatHex(va), hex });
    }
    const from = input.state?.from ?? "baseline";
    const fromDigest: StateDigest | undefined =
      from === "baseline" ? record.baseline : from === "current" ? record.current : record.named.get(from);
    // EMU-8: an unknown named state is an input error, never silently the current state's digest
    if (fromDigest === undefined)
      return err(
        invalid(
          operation,
          "state.from",
          `No named state "${from.slice(0, 64)}" in this session (snapshots are lost when the bridge restarts).`,
        ),
      );
    const stateWire: StateWire = { from, writes, saveAs: null };
    const options: RunOptions = {
      maxInstructions: input.budget?.max_instructions ?? 1_000_000,
      timeoutMs: input.budget?.timeout_ms_per_call ?? 0,
      mxcsr: fp.value.mxcsr,
      fpcw: fp.value.fpcw,
      faultPolicy: input.fault_policy ?? record.faultPolicy,
      trace: {
        imports: trace?.imports ?? (mode === "single" ? "full" : "counts"),
        blocks: trace?.blocks ?? false,
        coverage: trace?.coverage ?? false,
        countInstructions: trace?.count_instructions ?? false,
        memory: trace?.memory ?? "off",
        instructions: trace?.instructions ?? false,
        disassemble: trace?.disassemble ?? false,
        maxEvents: trace?.max_events ?? 10_000,
      },
    };
    const bridgeDeadlineMs = (): number => Math.max(500, Math.round(deadlineAt - now() - BRIDGE_DEADLINE_MARGIN_MS));
    const plan = classified.value.plan;
    const targetRef = target?.ref ?? null;
    const digest = planDigest(plan, {
      module: targetRef?.module ?? null,
      rva: (targetRef?.rva as Hex | null | undefined) ?? null,
      va: formatHex(target?.va ?? 0n),
    });
    const optionsDigest = canonicalDigest({
      ...options,
      trace: { ...options.trace },
      isolation: input.isolation,
      stop_on_fault: input.stop_on_fault,
    } as unknown as JsonObject);
    const writesDigest = canonicalDigest(writes as unknown as JsonValue);
    const vectors = window.value;
    const common: CallCommon = {
      input,
      handle,
      record,
      plan: classified.value,
      vectors,
      target: targetRef,
      fp: fp.value,
      from,
      fromDigest,
      fromWasBaseline: from === "baseline" || (from === "current" && record.currentIsBaseline),
      planDigest: digest,
      optionsDigest,
      writesDigest,
      literals: literals.value,
      operation,
      o,
    };

    if (mode === "single") {
      // emu.call carries no deadline in bea-emu/0.1 (only batches, sweeps and opens do): the per-call watchdog stands
      // in for the bridge deadline when the request sets none or a looser one. A call the tool deadline cuts then ends
      // as a `timeout` status (cause "deadline") inside timeout_ms, like a batch vector (S5 §3.10, §5.5), instead of
      // the host backstop cancelling it after timeout_ms with a provider_timeout. The options digest above keeps the
      // requested watchdog, so evidence identity never depends on timing.
      const deadlineWatchdogMs = bridgeDeadlineMs();
      const byDeadline = options.timeoutMs === 0 || options.timeoutMs > deadlineWatchdogMs;
      const reply = await services.emulator.call(
        handle,
        {
          plan: wire.value,
          vectors: wireVectors(vectors.vectors, vectors.offset),
          state: stateWire,
          options: byDeadline ? { ...options, timeoutMs: deadlineWatchdogMs } : options,
        },
        o,
      );
      if (!reply.ok) return err(toolError(reply.error, operation, input.timeout_ms));
      return this.#finishSingle(common, byDeadline ? deadlineStop(reply.value) : reply.value);
    }
    if (mode === "batch") {
      const reply = await services.emulator.batch(
        handle,
        {
          plan: wire.value,
          vectors: wireVectors(vectors.vectors, vectors.offset),
          state: stateWire,
          options: {
            ...options,
            isolation: input.isolation,
            stopOnFault: input.stop_on_fault,
            deadlineMs: bridgeDeadlineMs(),
          },
        },
        o,
      );
      if (reply.ok) return this.#finishBatch(common, reply.value, null);
      const failure = reply.error;
      if ("kind" in failure && failure.kind === "partial")
        return this.#finishBatch(common, failure.result, failure.reason);
      return err(toolError(failure as BeaError, operation, input.timeout_ms));
    }
    // sweep
    const sweep = input.sweep;
    if (sweep === undefined) return err(invalid(operation, "sweep", "sweep is required in sweep mode."));
    const modules = services.emulator.modules(handle);
    const primary = modules.find((m) => m.primary) ?? modules[0];
    const moduleName = sweep.module ?? primary?.name ?? "";
    let functions: SweepParams["functions"];
    if (sweep.targets !== undefined) {
      const targets = await this.resolveAll(handle, [...new Set(sweep.targets)], op, "sweep.targets");
      if (!targets.ok) return targets;
      functions = { targets: sweep.targets.map((t) => formatHex(targets.value.get(t)?.va ?? 0n)) };
    } else
      functions = {
        module: moduleName,
        rvaStart: canonical(sweep.rva_start ?? "0x0"),
        rvaEnd: canonical(sweep.rva_end ?? "0x0"),
        offset: sweep.offset,
        limit: sweep.limit,
      };
    const reply = await services.emulator.sweep(
      handle,
      {
        plan: wire.value,
        vectors: wireVectors(vectors.vectors, vectors.offset),
        functions,
        options: { ...options, deadlineMs: bridgeDeadlineMs() },
        match:
          sweep.match === undefined
            ? null
            : {
                returns: sweep.match.returns,
                argsFrom: [...sweep.match.args],
                known: [sweep.match.known],
                toleranceUlp: sweep.match.tolerance_ulp,
              },
      },
      o,
    );
    if (!reply.ok) return err(toolError(reply.error, operation, input.timeout_ms));
    return this.#finishSweep(common, reply.value, moduleName);
  }

  /** save_as / drop after the run; the lineage moves to the after-state (S5 §11.2). */
  async #advanceState(
    common: CallCommon,
    method: "emu.call" | "emu.batch" | "emu.sweep",
    slice: { offset: number; count: number },
    deterministic: boolean,
  ): Promise<Result<{ readonly after: StateDigest; readonly savedAs: string | null }, BeaError>> {
    const { record, input, handle } = common;
    const after = afterDigest(
      common.fromDigest,
      {
        method,
        planDigest: common.planDigest,
        vectorsDigest: common.vectors.vectors.digest,
        slice,
        writesDigest: common.writesDigest,
        optionsDigest: common.optionsDigest,
        isolation: input.isolation,
      },
      deterministic ? null : randomUUID(),
    );
    record.current = after;
    record.currentIsBaseline = false;
    let savedAs: string | null = null;
    const saveAs = input.state?.save_as;
    if (saveAs !== undefined) {
      const saved = await this.#app.services.emulator.state(handle, { save: saveAs }, common.o);
      if (!saved.ok) return err({ ...saved.error, operation: common.operation });
      record.named.set(saveAs, after);
      savedAs = saveAs;
    }
    for (const name of input.state?.drop ?? []) {
      const dropped = await this.#app.services.emulator.state(handle, { drop: name }, common.o);
      if (!dropped.ok) return err({ ...dropped.error, operation: common.operation });
      record.named.delete(name);
    }
    return ok({ after, savedAs });
  }

  async #coverageBlob(
    common: CallCommon,
    wire: NonNullable<NonNullable<CallResult["trace"]>["coverage"]> | undefined,
    vectors: number,
  ): Promise<Result<{ readonly ref: BlobRef; readonly blocks: number } | null, BeaError>> {
    if (wire === undefined) return ok(null);
    const blob = buildCoverageBlob({
      wire,
      modules: this.#app.services.emulator.modules(common.handle),
      addressSpace: common.record.source === "dump" ? "emulation-dump" : "emulation-image",
      sessionId: common.handle.sessionId,
      evidenceId: common.record.sessionEvidence,
      vectors,
      syntheticBase: common.record.syntheticBase as Hex | null,
    });
    const put = await this.#app.services.evidence.blobs.put(
      new TextEncoder().encode(JSON.stringify(blob)),
      { role: COVERAGE_BLOB_ROLE, media_type: COVERAGE_MEDIA_TYPE, literals: common.literals },
      common.o.signal,
    );
    if (!put.ok) return put;
    if ("redacted" in put.value) return ok(null);
    return ok({ ref: put.value, blocks: blob.totals.distinct_blocks });
  }

  #subject(common: CallCommon): Subject {
    return emulationSubject(common.record, common.from, common.fromDigest, common.fromWasBaseline);
  }

  #parameters(common: CallCommon, mode: string, extra: JsonObject): JsonObject {
    const target = common.target;
    return {
      mode,
      address: common.input.address ?? null,
      target: target === null ? null : { module: target.module, rva: target.rva },
      plan_digest: common.planDigest,
      vectors_digest: common.vectors.vectors.digest,
      vectors_source: common.vectors.vectors.source.kind,
      slice: { offset: common.vectors.offset, count: common.vectors.vectors.count },
      options_digest: common.optionsDigest,
      writes_digest: common.writesDigest,
      state_from: common.from,
      state_from_digest: common.fromDigest,
      fp: fpOut(common.fp),
      query_id: queryId({
        initialState: common.fromDigest,
        imageSha256: common.record.imageSha256,
        rva: target?.rva ?? null,
        planDigest: common.planDigest,
        vectorsDigest: common.vectors.vectors.digest,
        optionsDigest: common.optionsDigest,
      }),
      ...extra,
    };
  }

  #extraLimitations(common: CallCommon): string[] {
    const out: string[] = [];
    if (common.record.engineUnvalidated) out.push(EMULATION_LIMITATIONS.EMU_ENGINE_UNVALIDATED);
    if (common.record.source === "dump") out.push(EMULATION_LIMITATIONS.EMU_DUMP_STATE);
    if (common.fp.source === "windows-default" && common.record.source === "dump")
      out.push(CALL_LIMITATIONS.CALL_FP_DEFAULT);
    return out;
  }

  async #record(
    common: CallCommon,
    predicate: "bea.emu.run" | "bea.emu.batch" | "bea.emu.sweep",
    result: JsonObject,
    parameters: JsonObject,
    coverage: Coverage,
    limitations: readonly string[],
    blobs: readonly BlobRef[],
    links: readonly (EvId | null)[],
  ) {
    return this.#app.services.evidence.recorder.record({
      predicate_type: predicate,
      operation: common.operation,
      input: { session_id: common.handle.sessionId, ...parameters },
      subject: this.#subject(common),
      provider: { ...PROVIDER, version: this.#app.services.emulator.availability().versions?.unicorn ?? null },
      result,
      coverage,
      limitations,
      blobs,
      evidence_links: links.filter((l): l is EvId => l !== null),
      literals: common.literals,
    });
  }

  async #finishSingle(common: CallCommon, call: CallResult): Promise<Result<EmuCallOutput, BeaError>> {
    const { plan, layout } = common.plan;
    const outcome = singleOutcome(plan, layout, call);
    const types = fieldTypes(layout);
    const state = await this.#advanceState(common, "emu.call", { offset: 0, count: 1 }, call.deterministic);
    if (!state.ok) return state;
    const coverageBlob = await this.#coverageBlob(common, call.trace?.coverage, 1);
    if (!coverageBlob.ok) return coverageBlob;
    const trace = traceView(call.trace);
    const harness = call.status !== "returned" && (call.attribution ?? "target") === "harness" ? 1 : 0;
    const notes = { truncatedValues: false };
    const outputs = outputsOf(outcome, types, 0, notes);
    const assessed = assessEmulation({
      deviations: call.deviations,
      importModels: Object.values(call.trace?.imports ?? []).map((e) => e.model),
      harnessStops: harness,
      isaStops: call.status === "unsupported_instruction" ? 1 : 0,
      endedEarly:
        call.status === "cancelled"
          ? "cancelled"
          : call.status === "timeout" && call.stop?.cause === "deadline"
            ? "deadline"
            : null,
      deterministic: call.deterministic,
      traceTruncated: trace.truncatedAt,
      extraLimitations: this.#extraLimitations(common),
    });
    // EMU-11: inline array outputs are capped (the full bytes stay in the out buffers and the evidence)
    const assessment = notes.truncatedValues
      ? {
          coverage: mergeCoverage(assessed.coverage, { status: "partial", truncated: true, reasons: ["value_cap"] }),
          limitations: [...assessed.limitations, CORE_LIMITATIONS.CAP("inline value", OUTPUT_ARRAY_INLINE_CAP)],
        }
      : assessed;
    const result = {
      mode: "single" as const,
      target: common.target,
      fp: fpOut(common.fp),
      call: {
        status: call.status,
        attribution: call.status === "returned" ? null : (outcome.attribution[0] ?? null),
        ret: retValue(plan, outcome, 0),
        outputs,
        out_buffers: outBuffersView(call),
        raw: rawView(call),
        stop: call.stop === null ? null : stopView(call.stop, common.input.detail),
        metrics: {
          wall_us: Math.round(call.metrics.wallUs),
          instructions: call.metrics.instructions ?? null,
          blocks: call.metrics.blocks ?? null,
        },
        trace: trace.view,
        events: eventsView(call.events),
        deviations: deviationView(call.deviations),
        deterministic: call.deterministic,
      },
      state: {
        from: common.from,
        from_digest: common.fromDigest,
        after_digest: state.value.after,
        saved_as: state.value.savedAs,
      },
      coverage_blob:
        coverageBlob.value === null
          ? null
          : {
              sha256: coverageBlob.value.ref.sha256,
              bytes: coverageBlob.value.ref.bytes,
              blocks: coverageBlob.value.blocks,
            },
    };
    const recorded = await this.#record(
      common,
      "bea.emu.run",
      result as unknown as JsonObject,
      this.#parameters(common, "single", call.deterministic ? {} : { nondeterministic: true }),
      assessment.coverage,
      assessment.limitations,
      coverageBlob.value === null ? [] : [coverageBlob.value.ref],
      [common.record.sessionEvidence],
    );
    if (!recorded.ok) return recorded;
    return ok(deliver(recorded.value) as unknown as EmuCallOutput);
  }

  async #finishBatch(
    common: CallCommon,
    batch: BatchResult,
    partial: PartialBatch["reason"] | null,
  ): Promise<Result<EmuCallOutput, BeaError>> {
    const { plan, layout } = common.plan;
    const { input } = common;
    const outcome = emulatorOutcome(plan, layout, batch);
    const types = fieldTypes(layout);
    const summary = batch.summary;
    const completed = summary.completed;
    const sent = common.vectors.vectors.count;
    const state = await this.#advanceState(
      common,
      "emu.batch",
      { offset: summary.offset, count: completed },
      summary.deterministic,
    );
    if (!state.ok) return state;
    const coverageBlob = await this.#coverageBlob(common, batch.aggregates.coverage, completed);
    if (!coverageBlob.ok) return coverageBlob;
    const inline = completed <= input.inline_limit;
    let stream: WrittenStream | null = null;
    if (!inline) {
      const rows = Array.from({ length: completed }, (_, k) => batchRow(outcome, k, batch.columns.instructions));
      const written = await writeRowStream(
        this.#app.services.evidence,
        { kind: "emu-batch", channel: "emu_call", decoders: EMU_BATCH_DECODERS },
        rows,
        common.literals,
      );
      if (!written.ok) return written;
      stream = written.value;
    }
    const harness = outcome.attribution.filter((a) => a === "harness").length;
    const isaStops = outcome.status.filter((s) => s === "unsupported_instruction").length;
    const deviations = Object.entries(batch.aggregates.deviations).map(([kind, value]) => ({
      kind: kind as Parameters<typeof deviationView>[0][number]["kind"],
      note: "",
      count: value?.vectors ?? 0,
      ...(typeof value?.detail === "object" && value.detail !== null
        ? { detail: value.detail as Record<string, unknown> }
        : {}),
    }));
    const endedEarly = partial ?? (summary.cancelled ? "cancelled" : summary.deadlineReached ? "deadline" : null);
    // stop_on_fault ends a batch early by request: that is not a continuation (S5 §8.2.2)
    const stoppedOnFault = input.stop_on_fault && completed < sent && outcome.status.at(-1) !== "returned";
    const continued = completed < sent && !stoppedOnFault;
    const nextOffset = continued
      ? summary.offset + completed
      : common.vectors.windowCapped && completed === sent
        ? summary.offset + completed
        : null;
    // review fix EMU-6: a chain batch that could not place the next vector's buffers ends with the completed prefix;
    // the result says so (partial coverage) instead of looking like a complete run with a continuation
    const stopped = summary.stopped ?? null;
    const stoppedResource =
      stopped?.data?.["resource"] === "heap" || stopped?.data?.["resource"] === "scratch"
        ? (stopped.data["resource"] as "heap" | "scratch")
        : null;
    const assessment = assessEmulation({
      deviations,
      importModels: Object.values(batch.aggregates.imports).map((i) => i.model),
      harnessStops: harness,
      isaStops,
      endedEarly,
      deterministic: summary.deterministic,
      extraLimitations: [
        ...this.#extraLimitations(common),
        ...(stopped === null ? [] : [EMULATION_LIMITATIONS.EMU_BATCH_STOPPED(stopped.index, stoppedResource)]),
      ],
    });
    const coverage = mergeCoverage(
      assessment.coverage,
      stream?.coverage ?? COMPLETE,
      stopped === null ? COMPLETE : { status: "partial", truncated: false, reasons: ["stopped_early"] },
    );
    const result = {
      mode: "batch" as const,
      target: common.target,
      fp: fpOut(common.fp),
      batch: {
        offset: summary.offset,
        vectors: sent,
        completed,
        returned: outcome.status.filter((s) => s === "returned").length,
        by_status: byStatusOfSummary(summary),
        // EMU-9: the bridge's summary counts every vector (its fault list stops at 1000)
        by_attribution: { target: summary.byAttribution.target, harness: summary.byAttribution.harness },
        elapsed_ms: Math.round(summary.elapsedMs),
        calls_per_second: summary.callsPerSecond,
        isolation: summary.isolation,
        path: summary.path,
        deterministic: summary.deterministic,
        deadline_reached: summary.deadlineReached || partial === "deadline",
        cancelled: summary.cancelled || partial === "cancelled",
        continuation: nextOffset === null ? null : { vector_offset: nextOffset },
        columns: inline ? inlineColumns(plan, outcome, types) : null,
        status: inline ? [...outcome.status] : null,
        preview: inline ? null : previewRows(completed).map((k) => previewRow(outcome, k, batch.columns.instructions)),
        ret_stats: retStats(plan, outcome),
        faults: batch.faults.slice(0, MAX_FAULTS).map((f) => ({
          index: f.index,
          status: f.status,
          attribution: f.attribution,
          cause: f.cause,
          pc_rva: f.pcRva === null ? null : hex64(f.pcRva),
        })),
        fault_details: batch.faults
          .filter((f) => f.detail !== undefined)
          .slice(0, MAX_FAULT_DETAILS)
          .map((f) => ({ index: f.index, ...stopView(f.detail as StopRecord, input.detail) })),
        stream_id: stream?.stream_id ?? null,
        imports: Object.fromEntries(
          Object.entries(batch.aggregates.imports).map(([k, v]) => [k, { calls: v.calls, model: v.model }]),
        ),
        deviations: deviationView(deviations).map((d) => ({ kind: d.kind, vectors: d.count ?? 0, note: d.note })),
      },
      state: {
        from: common.from,
        from_digest: common.fromDigest,
        after_digest: state.value.after,
        saved_as: state.value.savedAs,
      },
      coverage_blob:
        coverageBlob.value === null
          ? null
          : {
              sha256: coverageBlob.value.ref.sha256,
              bytes: coverageBlob.value.ref.bytes,
              blocks: coverageBlob.value.blocks,
            },
    };
    const recorded = await this.#record(
      common,
      "bea.emu.batch",
      result as unknown as JsonObject,
      this.#parameters(common, "batch", {
        isolation: input.isolation,
        ...(summary.deterministic ? {} : { nondeterministic: true }),
      }),
      coverage,
      assessment.limitations,
      coverageBlob.value === null ? [] : [coverageBlob.value.ref],
      [common.record.sessionEvidence, stream?.manifest ?? null],
    );
    if (!recorded.ok) return recorded;
    if (partial === "cancelled")
      return err(
        withPartial(
          { _tag: "Cancelled", operation: common.operation, by: "client" },
          recorded.value.record.evidence_id,
        ),
      );
    return ok(deliver(recorded.value) as unknown as EmuCallOutput);
  }

  async #finishSweep(
    common: CallCommon,
    sweep: SweepResult,
    moduleName: string,
  ): Promise<Result<EmuCallOutput, BeaError>> {
    const { input } = common;
    const modules = this.#app.services.emulator.modules(common.handle);
    let stream: WrittenStream | null = null;
    if (sweep.rows.length > input.inline_limit) {
      const written = await writeRowStream(
        this.#app.services.evidence,
        { kind: "emu-sweep", channel: "emu_call", decoders: EMU_SWEEP_DECODERS },
        sweep.rows.map(sweepRow),
        common.literals,
      );
      if (!written.ok) return written;
      stream = written.value;
    }
    const summary = sweep.summary;
    const endedEarly = summary.cancelled ? "cancelled" : summary.deadlineReached ? "deadline" : null;
    const assessment = assessEmulation({
      deviations: [],
      endedEarly,
      extraLimitations: this.#extraLimitations(common),
    });
    const coverage = mergeCoverage(assessment.coverage, stream?.coverage ?? COMPLETE);
    const result = {
      mode: "sweep" as const,
      target: null,
      fp: fpOut(common.fp),
      sweep: {
        module: moduleName,
        functions: summary.functions,
        completed: summary.completed,
        by_outcome_profile: { ...summary.byOutcomeProfile },
        matched: sweepMatches(sweep, modules),
        next_offset: summary.nextOffset,
        deadline_reached: summary.deadlineReached,
        stream_id: stream?.stream_id ?? null,
      },
      state: null,
      coverage_blob: null,
    };
    const recorded = await this.#record(
      common,
      "bea.emu.sweep",
      result as unknown as JsonObject,
      this.#parameters(common, "sweep", { sweep_module: moduleName }),
      coverage,
      assessment.limitations,
      [],
      [common.record.sessionEvidence, stream?.manifest ?? null],
    );
    if (!recorded.ok) return recorded;
    if (summary.cancelled)
      return err(
        withPartial(
          { _tag: "Cancelled", operation: common.operation, by: "client" },
          recorded.value.record.evidence_id,
        ),
      );
    return ok(deliver(recorded.value) as unknown as EmuCallOutput);
  }
}

interface CallCommon {
  readonly input: EmuCallInput;
  readonly handle: EmuSessionHandle;
  readonly record: SessionRecord;
  readonly plan: ClassifiedRequest;
  readonly vectors: WindowVectors;
  readonly target: ResolvedAddress["ref"] | null;
  readonly fp: FpChoice;
  readonly from: string;
  readonly fromDigest: StateDigest;
  /** the run started from the baseline itself (also `current` before any call) */
  readonly fromWasBaseline: boolean;
  readonly planDigest: string;
  readonly optionsDigest: string;
  readonly writesDigest: string;
  readonly literals: SensitiveLiterals;
  readonly operation: string;
  readonly o: EmuRequestOptions;
}

/** Status histogram of decoded outcome columns (diff legs). */
export const statusCounts = (outcome: CallOutcomeColumns) => byStatus(outcome.status);

/** The emulation subject of a run (S2 subjectSchema): the state basis the run started from. */
export const emulationSubject = (
  record: SessionRecord,
  from: string,
  fromDigest: StateDigest,
  fromWasBaseline: boolean,
): Subject => ({
  kind: "emulation",
  image_sha256: record.imageSha256,
  config_digest: record.configDigest,
  state: fromWasBaseline
    ? record.source === "dump" && record.bundleId !== null
      ? { basis: "dump", dump_digest: record.bundleId.slice(5) }
      : { basis: "baseline" }
    : from === "current"
      ? { basis: "chained" }
      : { basis: "snapshot", snapshot_digest: digestHex(fromDigest) },
  module_map_id: null,
});
