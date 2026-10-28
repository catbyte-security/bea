// =================================================================================================
// src/application/watch/ExportCoverage.ts — export_coverage (DESIGN §6.2 #25; S6 §4.27; S5 §11.4; D-INT-42;
// WP9-WATCH). Sources: a trace recording (coverage or block_counts; WP9 builds and stores its bea.coverage/1 blob) or
// the evidence id of a record that carries a bea.coverage/1 blob (call_function coverage, emu_call trace coverage).
// The file is written with exclusive create (writers never overwrite) at out_path, which must pass checkOutputPath,
// or under <run>/exports/. Records bea.coverage.export (derived; links the source evidence).
// =================================================================================================
import { createHash } from "node:crypto";
import { mkdir, open } from "node:fs/promises";
import { dirname, join } from "node:path";

import type { z } from "zod";

import type { WATCH_TOOLS } from "../../contracts/areas/watch.js";
import type { CoverageBlobV1 } from "../../domain/artifacts.js";
import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError, referenceNotFound } from "../../domain/errors/constructors.js";
import { COMPLETE, type Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { BlobRef, Subject } from "../../domain/evidence/record.js";
import type { EvId } from "../../domain/ids.js";
import { isJsonObject, type JsonObject, type JsonValue } from "../../domain/json.js";
import { checkOutputPath } from "../../domain/outputPaths.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { OperationContext } from "../../ports/sessions.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";
import { attributeFunctions, readTraceBlocks } from "./blocks.js";
import {
  buildStalkerCoverage,
  drcovBytes,
  modoffText,
  parseCoverageBlob,
  type CoverageModuleFacts,
} from "./coverage.js";
import { traceDecodersOf, type LegendEntry } from "./decoders.js";
import { envelopeOf } from "./envelope.js";
import { CodeLocator } from "./locate.js";

type ExportContract = (typeof WATCH_TOOLS)[2];
export type ExportInput = z.output<ExportContract["inputSchema"]>;
export type ExportOutput = z.output<ExportContract["outputSchema"]>;

const OPERATION = "export_coverage";
const COVERAGE_SOURCES = new Set(["bea.call.oracle", "bea.emu.run", "bea.emu.batch"]);
const noCoverage = (path: string): BeaError =>
  inputError(OPERATION, [{ path, reason: "invalid_value", message: "The source has no block coverage." }]);

interface Source {
  readonly blob: CoverageBlobV1;
  readonly id: string;
  readonly subject: Subject | null;
  readonly links: readonly EvId[];
  readonly blobs: readonly BlobRef[];
}

const fileFacts = async (app: BeaApplication, e: LegendEntry, signal: AbortSignal): Promise<CoverageModuleFacts> => {
  const path = e[3];
  let timestamp: number | null = null;
  let entryRva: number | null = null;
  let preferred: bigint | null = null;
  let sha: string | null = null;
  if (path !== null) {
    const image = await app.services.pe.images.open(path, signal).catch(() => null);
    if (image?.ok === true) {
      timestamp = image.value.time_date_stamp;
      entryRva = image.value.entry_rva;
      preferred = BigInt(image.value.image_base);
    }
    const hash = await app.services.pe.hashes.sha256(path, signal).catch(() => null);
    if (hash?.ok === true) sha = hash.value;
  }
  return {
    name: e[0],
    path,
    base: BigInt(e[1]),
    size: e[2],
    fileSha256: sha,
    preferredBase: preferred,
    entryRva,
    timestamp,
  };
};

/** A detached op for sources whose session is gone (recordings stay readable until the run ends). */
const detachedOp = (ctx: HandlerContext): OperationContext => ({
  opId: 0,
  name: OPERATION,
  signal: ctx.signal,
  deadline: Deadline.after(ctx.remainingMs()),
});

const fromRecording = async (
  app: BeaApplication,
  ctx: HandlerContext,
  id: string,
): Promise<Result<Source, BeaError>> => {
  const rec = app.services.recordings.get(id);
  if (rec === undefined) return err(referenceNotFound(OPERATION, "recording", id));
  if (rec.create.kind !== "trace") return err(noCoverage("recording_id"));
  const d = traceDecodersOf(rec.create.decoders);
  if (d.mode === "calls") return err(noCoverage("recording_id"));
  const links: EvId[] = [];
  const collect = async (op: OperationContext) => readTraceBlocks(app.services.recordings, id, op);
  let read = await liveOp(app, ctx, rec.create.sessionId, { mode: "concurrent", need: "host" }, async (session, op) => {
    const agentStream = rec.create.agentStream;
    const manifest = agentStream === null ? null : await session.streams.writer(agentStream)?.checkpoint(op.signal);
    if (manifest?.ok === true) links.push(manifest.value.record.evidence_id);
    return collect(op);
  });
  if (!read.ok && read.error._tag === "SessionNotFound") read = await collect(detachedOp(ctx));
  if (!read.ok) return read;
  const facts = await Promise.all(d.modules.map((e) => fileFacts(app, e, ctx.signal)));
  const blob = buildStalkerCoverage(
    { sessionId: rec.create.sessionId, evidenceId: null, threads: d.threads },
    facts,
    read.value.blocks,
    read.value.truncated,
  );
  const literals = app.services.evidence.literals(undefined);
  if (!literals.ok) return literals;
  const stored = await app.services.evidence.blobs.put(
    new TextEncoder().encode(JSON.stringify(blob)),
    { role: "coverage", media_type: "application/json", literals: literals.value },
    ctx.signal,
  );
  if (!stored.ok) return stored;
  return ok({
    blob,
    id,
    subject:
      d.instance_id === null
        ? null
        : ({ kind: "process-instance", instance_id: d.instance_id, module_map_id: null } as Subject),
    links,
    blobs: "redacted" in stored.value ? [] : [stored.value],
  });
};

const fromEvidence = async (app: BeaApplication, ctx: HandlerContext, id: EvId): Promise<Result<Source, BeaError>> => {
  const complete = await app.services.evidence.query.complete(id);
  if (!complete.ok) return complete;
  // EvidenceQuery.complete answers {record_kind, origin, value} (the get_evidence `record` shape; integrator fix,
  // WP14 change request: the record is `value`, not `record`)
  const inner = complete.value["value"];
  const record = (
    complete.value["record_kind"] === "evidence" && isJsonObject(inner) ? inner : complete.value
  ) as JsonObject;
  if (!COVERAGE_SOURCES.has(String(record["predicate_type"]))) return err(noCoverage("evidence_id"));
  const refs = Array.isArray(record["blobs"]) ? (record["blobs"] as JsonValue[]) : [];
  for (const ref of refs) {
    if (!isJsonObject(ref) || ref["media_type"] !== "application/json") continue;
    const sha = String(ref["sha256"]);
    const size = typeof ref["bytes"] === "number" ? ref["bytes"] : 0;
    const bytes = await app.services.evidence.blobs.read(sha, 0, size);
    if (!bytes.ok) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(bytes.value));
    } catch {
      continue;
    }
    const blob = parseCoverageBlob(parsed);
    if (blob === null) continue;
    const subject = isJsonObject(record["subject"]) ? (record["subject"] as unknown as Subject) : null;
    return ok({ blob, id, subject, links: [id], blobs: [] });
  }
  return err(noCoverage("evidence_id"));
};

const writeExclusive = async (
  path: string,
  bytes: Uint8Array,
  createParents: boolean,
): Promise<Result<void, BeaError>> => {
  try {
    if (createParents) await mkdir(dirname(path), { recursive: true });
    const handle = await open(path, "wx");
    try {
      await handle.writeFile(bytes);
    } finally {
      await handle.close();
    }
    return ok(undefined);
  } catch (cause) {
    const code = (cause as { code?: unknown }).code;
    return err({
      _tag: "FileOperationFailed",
      operation: OPERATION,
      file_operation: "write",
      path,
      reason:
        code === "EEXIST"
          ? "exists"
          : code === "ENOENT"
            ? "missing"
            : code === "EACCES" || code === "EPERM"
              ? "permission"
              : "io",
      cause,
    });
  }
};

const outputPath = (
  app: BeaApplication,
  input: ExportInput,
  id: string,
): Result<{ path: string; parents: boolean }, BeaError> => {
  const exportsDir = app.config.layout.exportsDir(app.run.runId);
  if (input.out_path === undefined)
    return ok({ path: join(exportsDir, `${id}.${input.format === "drcov" ? "drcov" : "txt"}`), parents: true });
  const platform = app.config.platform;
  const systemRoots =
    platform === "win32"
      ? [process.env["SystemRoot"], process.env["windir"]].filter(
          (r): r is string => typeof r === "string" && r.length > 0,
        )
      : ["/etc", "/usr", "/bin", "/sbin", "/lib"];
  const checked = checkOutputPath(input.out_path, {
    platform,
    exportsDir,
    allowedRoots: app.config.exports.allowedRoots.value,
    systemRoots,
  });
  if (!checked.ok)
    return err({ _tag: "AccessDenied", operation: OPERATION, reason: "policy", message: checked.message });
  return ok({ path: checked.path, parents: false });
};

export const exportCoverage = async (
  app: BeaApplication,
  input: ExportInput,
  ctx: HandlerContext,
): Promise<Result<ExportOutput, BeaError>> => {
  const sourceId = input.recording_id ?? (input.evidence_id as string);
  const target = outputPath(app, input, sourceId); // the policy refuses before any source is read
  if (!target.ok) return target;
  const source =
    input.recording_id !== undefined
      ? await fromRecording(app, ctx, input.recording_id)
      : await fromEvidence(app, ctx, input.evidence_id as EvId);
  if (!source.ok) return source;
  const { blob } = source.value;
  if (blob.blocks.length === 0 && blob.unattributed.length === 0)
    return err(noCoverage(input.recording_id !== undefined ? "recording_id" : "evidence_id"));
  const bytes = input.format === "drcov" ? drcovBytes(blob) : new TextEncoder().encode(modoffText(blob));
  const written = await writeExclusive(target.value.path, bytes, target.value.parents);
  if (!written.ok) return written;
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const perModule = blob.modules.map((m) => ({
    name: m.name,
    blocks: blob.blocks.filter((b) => b[0] === m.id).length,
  }));
  const legend: LegendEntry[] = blob.modules.map((m) => [m.name, m.base as `0x${string}`, m.size, m.path] as const);
  const locator = new CodeLocator(app.services.pe.images, ctx.signal);
  const rawBlocks = blob.blocks.map(([id, rva, size, hits]) => {
    const m = blob.modules.find((x) => x.id === id);
    return { va: BigInt(m?.base ?? "0x0") + BigInt(rva), size, hits };
  });
  const attributed = await attributeFunctions(locator, legend, rawBlocks, new Map());
  const limitations: string[] = [LIMITATIONS.COVERAGE_DRCOV_LAYOUT];
  if (blob.unattributed.length > 0) limitations.push(LIMITATIONS.COVERAGE_UNATTRIBUTED(blob.unattributed.length));
  if (attributed.unresolved > 0) limitations.push(LIMITATIONS.TRACE_FUNCTIONS_UNRESOLVED(attributed.unresolved));
  const coverage: Coverage = blob.totals.truncated
    ? { status: "partial", truncated: true, reasons: ["row_cap"] }
    : COMPLETE;
  const result = {
    path: target.value.path,
    bytes: bytes.length,
    sha256,
    format: input.format,
    blocks: blob.blocks.length,
    modules: perModule.slice(0, 64),
    functions: attributed.functions.map((f) => ({ func: f.func, sym: f.sym, blocks: f.blocks })),
  };
  const literals = app.services.evidence.literals(undefined);
  if (!literals.ok) return literals;
  const recorded = await app.services.evidence.recorder.record({
    predicate_type: "bea.coverage.export",
    operation: OPERATION,
    input: input as unknown as JsonObject,
    identityExclude: ["out_path"],
    subject: source.value.subject,
    provider: { id: "bea", name: "bea-coverage", version: null },
    result: {
      ...result,
      source: { kind: input.recording_id !== undefined ? "recording" : "evidence", id: source.value.id },
    },
    blobs: source.value.blobs,
    coverage,
    limitations,
    evidence_links: source.value.links,
    literals: literals.value,
  });
  if (!recorded.ok) return recorded;
  return ok({ ...envelopeOf(recorded.value as never), ...result } as ExportOutput);
};
