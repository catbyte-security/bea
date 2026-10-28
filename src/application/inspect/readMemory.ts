import type { z } from "zod";

import type { readMemoryInputSchema, readMemoryOutputSchema } from "../../contracts/areas/inspect.js";
import { INSPECT_CAPS } from "../../contracts/areas/inspect.js";
import type { AddressRef } from "../../domain/address/addressRef.js";
import type { BeaError, BeaErrorOf } from "../../domain/errors/beaError.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import type { JsonObject } from "../../domain/json.js";
import { bytesContainLiteral } from "../../domain/redaction/redact.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AddressService, AddressSpace } from "../../ports/address.js";
import type { EmuSessionHandle } from "../../ports/emu.js";
import type { SensitiveLiterals } from "../../ports/evidence.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import { formatHex, MASK64 } from "../../shared/hex.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { anySessionOp } from "../sessionAccess.js";
import { pointerFrom, walkChain, type ChainResult } from "./chain.js";
import {
  bareRef,
  clip,
  deliver,
  emuOptions,
  jsonInput,
  literalsOf,
  recordEmulation,
  recordLive,
  type InspectRequest,
} from "./common.js";
import { decodeView } from "./views.js";

type Input = z.output<typeof readMemoryInputSchema>;
type Output = z.output<typeof readMemoryOutputSchema>;
type Region = Output["region"];

/** Reads [va, va + size): the readable prefix (≥ 1 byte) or the session's own error for an unreadable first byte. */
type Reader = (va: bigint, size: number) => Promise<Result<Uint8Array, BeaError>>;

const accessFailed = (operation: string, va: bigint, size: number): BeaErrorOf<"MemoryAccessFailed"> => ({
  _tag: "MemoryAccessFailed",
  operation,
  address: formatHex(va & MASK64),
  access: "read",
  size,
});

/** The pointer chain, then the final read; shared by live and emulation sessions. */
const readThrough = async (
  read: Reader,
  operation: string,
  { start, input }: { readonly start: bigint; readonly input: Input },
): Promise<Result<{ readonly chain: ChainResult; readonly bytes: Uint8Array }, BeaError>> => {
  const chain = await walkChain(
    async (va) => {
      const got = await read(va, 8);
      if (!got.ok) return got;
      const pointer = pointerFrom(got.value);
      return pointer === null ? err(accessFailed(operation, va + BigInt(got.value.length), 8)) : ok(pointer);
    },
    start,
    input.deref,
  );
  if (!chain.ok) return chain;
  const bytes = await read(chain.value.final, input.size);
  if (!bytes.ok)
    return input.deref === undefined
      ? bytes
      : err({
          ...bytes.error,
          diagnostics: {
            ...bytes.error.diagnostics,
            chain: chain.value.steps.map((s) => ({ address: s.address, value: s.value })),
          },
        });
  return ok({ chain: chain.value, bytes: bytes.value });
};

/** The final address as an AddressRef: the resolved input itself, or the chain's end resolved as a plain VA. */
const finalRef = async (
  address: AddressService,
  space: AddressSpace,
  { resolved, chain }: { readonly resolved: AddressRef; readonly chain: ChainResult },
  op: OperationContext,
): Promise<AddressRef> => {
  if (chain.steps.length === 0) return resolved;
  const again = await address.resolve(space, formatHex(chain.final), op, { path: "address" });
  return again.ok ? again.value.ref : bareRef(chain.final);
};

/** The 8 little-endian bytes of a chain step's pointer value. */
const pointerBytes = (value: string): Uint8Array => {
  const out = new Uint8Array(8);
  let v = BigInt(value);
  for (let i = 0; i < 8; i++, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
};

/**
 * Result body + coverage (partial read = `complete:false`, never an error; value cap = truncated). Review fix SEC-3:
 * the Recorder matches literals only in text and in the hex/base64 `data` field, so typed views (numbers, decimal and
 * hex scalars) would carry a sensitive value past it. The raw bytes decide instead: when they (or a chain pointer)
 * contain a literal's UTF-8 or UTF-16LE spelling, the whole payload is withheld whatever the view (`data`, `values`,
 * `text` → null; the chain dropped) and the pointers are reported as redactions.
 */
const buildResult = (
  input: Input,
  ref: AddressRef,
  read: { readonly chain: ChainResult; readonly bytes: Uint8Array },
  region: Region,
  literals: SensitiveLiterals,
): {
  readonly result: JsonObject;
  readonly coverage: Coverage;
  readonly limitations: string[];
  readonly pre_redactions: readonly string[];
} => {
  const { chain, bytes } = read;
  const decoded = decodeView(bytes, input.view);
  const complete = bytes.length === input.size;
  const parts: Coverage[] = [];
  const limitations: string[] = [];
  if (!complete) parts.push({ status: "partial", truncated: false, reasons: ["unreadable_memory"] });
  if (decoded.valuesCapped) {
    parts.push({ status: "partial", truncated: true, reasons: ["value_cap"] });
    limitations.push(LIMITATIONS.CAP("value", INSPECT_CAPS.readValues));
  }
  const sensitive = literals.count > 0 && bytesContainLiteral(bytes, literals);
  const chainSensitive =
    literals.count > 0 && chain.steps.some((s) => bytesContainLiteral(pointerBytes(s.value), literals));
  const withheld: string[] = [];
  const payload = <T>(key: "data" | "values" | "text", value: T | undefined): Record<string, T | null> => {
    if (value === undefined) return {};
    if (!sensitive) return { [key]: value };
    withheld.push(`/result/${key}`);
    return { [key]: null };
  };
  if (chainSensitive && input.deref !== undefined) withheld.push("/result/chain");
  const result: Record<string, unknown> = {
    address: ref,
    ...(input.deref === undefined || chainSensitive
      ? {}
      : { chain: chain.steps.map((s) => ({ address: s.address, value: s.value })) }),
    requested: input.size,
    returned: bytes.length,
    complete,
    ...payload("data", decoded.data),
    ...payload("values", decoded.values === undefined ? undefined : [...decoded.values]),
    ...payload("text", decoded.text === undefined ? undefined : clip(decoded.text, INSPECT_CAPS.readBytes)),
    region,
  };
  return {
    result: result as JsonObject,
    coverage: parts.length === 0 ? COMPLETE : mergeCoverage(...parts),
    limitations,
    pre_redactions: withheld.sort(),
  };
};

const live = async (
  call: InspectRequest<Input>,
  session: LiveSession,
  op: OperationContext,
): Promise<Result<Output, BeaError>> => {
  const { app, ctx, input, literals } = call;
  const space: AddressSpace = { kind: "live", session };
  const resolved = await app.services.address.resolve(space, input.address, op, { path: "address" });
  if (!resolved.ok) return resolved;
  const read: Reader = async (va, size) => {
    const reply = await session.agent.call("readMemory", { address: formatHex(va & MASK64), size }, { op });
    if (!reply.ok) return reply;
    const n = Math.min(reply.value.value.returned, reply.value.data.length);
    if (n === 0) return err(accessFailed(ctx.operation, va, size));
    return ok(new Uint8Array(reply.value.data.buffer, reply.value.data.byteOffset, n));
  };
  const got = await readThrough(read, ctx.operation, { start: resolved.value.va, input });
  if (!got.ok) return got;
  const capture = app.services.evidence.instances.capture(session.instanceId);
  const described = await session.agent.call(
    "describeAddresses",
    { addresses: [formatHex(got.value.chain.final)] },
    { op },
  );
  const d = described.ok ? described.value.results[0] : undefined;
  const region: Region =
    d?.range === null || d?.range === undefined
      ? null
      : {
          base: d.range.base,
          size: d.range.size,
          prot: d.range.protection.slice(0, 8),
          module: d.module === null ? null : clip(d.module, INSPECT_CAPS.moduleName),
        };
  const ref = await finalRef(app.services.address, space, { resolved: resolved.value.ref, chain: got.value.chain }, op);
  const built = buildResult(input, ref, got.value, region, literals);
  const recorded = await recordLive(call, session, capture, {
    predicate: "bea.memory.read",
    input: jsonInput(input),
    ...built,
    literals,
  });
  if (!recorded.ok) return recorded;
  return ok(deliver(recorded.value) as unknown as Output);
};

const decodeBridgeData = (data: string, encoding: "hex" | "base64"): Uint8Array =>
  new Uint8Array(Buffer.from(data, encoding));

const emulation = async (
  call: InspectRequest<Input>,
  handle: EmuSessionHandle,
  op: OperationContext,
): Promise<Result<Output, BeaError>> => {
  const { app, ctx, input, literals } = call;
  const emulator = app.services.emulator;
  const space: AddressSpace = { kind: "emulation", sessionId: handle.sessionId };
  const resolved = await app.services.address.resolve(space, input.address, op, { path: "address" });
  if (!resolved.ok) return resolved;
  const read: Reader = async (va, size) => {
    const reply = await emulator.readMemory(handle, formatHex(va & MASK64), size, emuOptions(op));
    if (!reply.ok) return reply;
    const bytes = decodeBridgeData(reply.value.data, reply.value.encoding).subarray(0, size);
    return bytes.length === 0 ? err(accessFailed(ctx.operation, va, size)) : ok(bytes);
  };
  const got = await readThrough(read, ctx.operation, { start: resolved.value.va, input });
  if (!got.ok) return got;
  const regions = await emulator.regions(handle, emuOptions(op));
  const final = got.value.chain.final;
  const hit = regions.ok
    ? regions.value.regions.find((r) => BigInt(r.start) <= final && final < BigInt(r.end))
    : undefined;
  const region: Region =
    hit === undefined
      ? null
      : {
          base: hit.start,
          size: Number(BigInt(hit.end) - BigInt(hit.start)),
          prot: hit.perms.slice(0, 8),
          module: hit.module === undefined ? null : clip(hit.module, INSPECT_CAPS.moduleName),
        };
  const ref = await finalRef(app.services.address, space, { resolved: resolved.value.ref, chain: got.value.chain }, op);
  const built = buildResult(input, ref, got.value, region, literals);
  const recorded = await recordEmulation(call, handle, {
    predicate: "bea.emu.memory.read",
    input: jsonInput(input),
    ...built,
    limitations: [...built.limitations, LIMITATIONS.NOT_REAL_PROCESS],
    literals,
  });
  if (!recorded.ok) return recorded;
  return ok(deliver(recorded.value) as unknown as Output);
};

export const readMemory = (
  app: BeaApplication,
  input: Input,
  ctx: HandlerContext,
): Promise<Result<Output, BeaError>> => {
  const literals = literalsOf(app, input.sensitive_values);
  if (!literals.ok) return Promise.resolve(literals);
  return anySessionOp(
    app,
    ctx,
    input.session_id,
    { mode: "exclusive", need: "agent" },
    {
      live: (session, op) => live({ app, ctx, input, literals: literals.value }, session, op),
      emulation: (handle, op) => emulation({ app, ctx, input, literals: literals.value }, handle, op),
    },
  );
};
