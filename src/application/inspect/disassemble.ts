import type { z } from "zod";

import type { disassembleInputSchema, disassembleOutputSchema } from "../../contracts/areas/inspect.js";
import { INSPECT_CAPS } from "../../contracts/areas/inspect.js";
import type { Addr } from "../../domain/address/addressRef.js";
import type { Insn } from "../../domain/emuProtocol.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE, mergeCoverage, type Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { ok, type Result } from "../../domain/result.js";
import type { AddressSpace } from "../../ports/address.js";
import type { EmuSessionHandle } from "../../ports/emu.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { DisassembleResult, InsnRow } from "../../shared/agentProtocol.js";
import { formatHex, MASK64 } from "../../shared/hex.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { anySessionOp } from "../sessionAccess.js";
import {
  clip,
  deliver,
  emuOptions,
  jsonInput,
  literalsOf,
  recordEmulation,
  recordLive,
  refText,
  splitAt,
  type InspectRequest,
} from "./common.js";

type Input = z.output<typeof disassembleInputSchema>;
type Output = z.output<typeof disassembleOutputSchema>;
type Row = Output["rows"][number];

/** Intel text of one agent row: `mnemonic op_str`. */
export const insnText = (row: Pick<InsnRow, "mnemonic" | "op_str">): string =>
  clip(row.op_str.length > 0 ? `${row.mnemonic} ${row.op_str}` : row.mnemonic, INSPECT_CAPS.insnText);

/** The one target a row refers to: its branch/call target, else its first RIP-relative operand. */
export const rowTarget = (row: Pick<InsnRow, "branch_target" | "mem_targets">): bigint | null => {
  const target = row.branch_target ?? row.mem_targets[0] ?? null;
  return target === null ? null : BigInt(target);
};

const BRANCH_MNEMONIC = /^(?:j[a-z]{1,4}|call|loop[a-z]{0,2}|jrcxz|jecxz|xbegin)$/u;
/**
 * Target of a capstone text line from the emulator bridge (absolute branch targets are printed as `0x…`;
 * RIP-relative operands as `[rip ± 0x…]`, relative to the next instruction).
 */
export const textTarget = (text: string, va: bigint, size: number): bigint | null => {
  const space = text.indexOf(" ");
  const mnemonic = space < 0 ? text : text.slice(0, space);
  const operands = space < 0 ? "" : text.slice(space + 1).trim();
  if (BRANCH_MNEMONIC.test(mnemonic) && /^0x[0-9a-f]+$/iu.test(operands)) return BigInt(operands);
  const rip = /\[rip\s*([+-])\s*(0x[0-9a-f]+|\d+)\]/iu.exec(operands);
  if (rip !== null) {
    const disp = BigInt(rip[2] ?? "0");
    return (va + BigInt(size) + (rip[1] === "-" ? -disp : disp)) & MASK64;
  }
  return null;
};

interface RowSource {
  readonly va: bigint;
  readonly bytes: string;
  readonly text: string;
  readonly target: bigint | null;
}

/** Output rows: rva from the row's own `at` when it lies in the start module, ref from the target's address forms. */
const buildRows = async (
  app: BeaApplication,
  space: AddressSpace,
  { sources, start }: { readonly sources: readonly RowSource[]; readonly start: bigint },
  op: OperationContext,
): Promise<{ readonly module: string | null; readonly rows: Row[] }> => {
  const address = app.services.address;
  const targets = sources.flatMap((s) => (s.target === null ? [] : [s.target]));
  await address.prepare(space, [start, ...targets], op);
  const startModule = splitAt(address.describe(space, start).at)?.module ?? null;
  const rows = sources.map((s): Row => {
    const at = splitAt(address.describe(space, s.va).at);
    const target: Addr | null = s.target === null ? null : address.describe(space, s.target);
    return {
      rva: at !== null && at.module === startModule ? at.rva : null,
      va: formatHex(s.va),
      b: s.bytes.slice(0, INSPECT_CAPS.insnHexChars),
      t: clip(s.text, INSPECT_CAPS.insnText),
      ref: target === null ? null : clip(refText(target), INSPECT_CAPS.ref),
    };
  });
  return { module: startModule === null ? null : clip(startModule, INSPECT_CAPS.moduleName), rows };
};

/** Coverage + limitations of an agent disassembly (S4 §4 DisassembleResult.stop/truncated/overlay_used). */
export const liveCoverage = (
  result: Pick<DisassembleResult, "stop" | "truncated" | "overlay_used">,
): { readonly coverage: Coverage; readonly limitations: string[] } => {
  const parts: Coverage[] = [];
  const limitations: string[] = [];
  if (result.stop?.reason === "access-violation")
    parts.push({ status: "partial", truncated: false, reasons: ["unreadable_memory"] });
  if (result.stop?.reason === "decode-error") limitations.push(LIMITATIONS.DISASM_DECODE_STOP(result.stop.at));
  if (result.truncated) {
    parts.push({ status: "partial", truncated: true, reasons: ["row_cap"] });
    limitations.push(LIMITATIONS.CAP("instruction", INSPECT_CAPS.disasmRows));
  }
  if (result.overlay_used) limitations.push(LIMITATIONS.HOOKED_BYTES_RESTORED);
  return { coverage: parts.length === 0 ? COMPLETE : mergeCoverage(...parts), limitations };
};

const live = async (
  call: InspectRequest<Input>,
  session: LiveSession,
  op: OperationContext,
): Promise<Result<Output, BeaError>> => {
  const { app, input, literals } = call;
  const space: AddressSpace = { kind: "live", session };
  const resolved = await app.services.address.resolve(space, input.address, op, { path: "address" });
  if (!resolved.ok) return resolved;
  const reply = await session.agent.call(
    "disassemble",
    {
      address: formatHex(resolved.value.va),
      mode: input.function ? "function" : "count",
      ...(input.function ? {} : { count: input.count }),
      original_bytes: true,
      operands: false,
      cfg: false,
    },
    { op },
  );
  if (!reply.ok) return reply;
  const capture = app.services.evidence.instances.capture(session.instanceId);
  const value = reply.value;
  const insns = value.instructions.slice(0, INSPECT_CAPS.disasmRows);
  const sources = insns.map((r) => ({
    va: BigInt(r.address),
    bytes: r.bytes,
    text: insnText(r),
    target: rowTarget(r),
  }));
  const { module, rows } = await buildRows(app, space, { sources, start: BigInt(value.start) }, op);
  const truncated = value.truncated || value.instructions.length > insns.length;
  const { coverage, limitations } = liveCoverage({ ...value, truncated });
  const recorded = await recordLive(call, session, capture, {
    predicate: "bea.code.disassembly",
    input: jsonInput(input),
    result: {
      module,
      func: value.function === null ? null : { start: value.function.base, size: value.function.size },
      rows,
      hooked_bytes_restored: value.overlay_used,
    },
    coverage,
    limitations,
    literals,
  });
  if (!recorded.ok) return recorded;
  return ok(deliver(recorded.value) as unknown as Output);
};

const emulation = async (
  call: InspectRequest<Input>,
  handle: EmuSessionHandle,
  op: OperationContext,
): Promise<Result<Output, BeaError>> => {
  const { app, input, literals } = call;
  const emulator = app.services.emulator;
  const space: AddressSpace = { kind: "emulation", sessionId: handle.sessionId };
  const resolved = await app.services.address.resolve(space, input.address, op, { path: "address" });
  if (!resolved.ok) return resolved;
  const reply = await emulator.disassemble(
    handle,
    formatHex(resolved.value.va),
    input.function ? { function: true } : { count: input.count },
    emuOptions(op),
  );
  if (!reply.ok) return reply;
  const insns: readonly Insn[] = reply.value.instructions.slice(0, INSPECT_CAPS.disasmRows);
  const fn = reply.value.function;
  const fnModule = fn === null ? undefined : emulator.modules(handle).find((m) => m.name === fn.module);
  const func =
    fn === null || fnModule === undefined
      ? null
      : {
          start: formatHex(BigInt(fnModule.base) + BigInt(fn.beginRva)),
          size: Number(BigInt(fn.endRva) - BigInt(fn.beginRva)),
        };
  const first = insns[0];
  const start: bigint = func !== null ? BigInt(func.start) : first !== undefined ? BigInt(first.va) : resolved.value.va;
  const sources = insns.map((i) => {
    const va = BigInt(i.va);
    return { va, bytes: i.bytes, text: i.text, target: textTarget(i.text, va, i.bytes.length / 2) };
  });
  const { module, rows } = await buildRows(app, space, { sources, start }, op);
  const truncated = reply.value.instructions.length > insns.length;
  const recorded = await recordEmulation(call, handle, {
    predicate: "bea.code.disassembly",
    input: jsonInput(input),
    result: { module, func, rows, hooked_bytes_restored: false },
    coverage: truncated ? { status: "partial", truncated: true, reasons: ["row_cap"] } : COMPLETE,
    limitations: [
      LIMITATIONS.NOT_REAL_PROCESS,
      ...(truncated ? [LIMITATIONS.CAP("instruction", INSPECT_CAPS.disasmRows)] : []),
    ],
    literals,
  });
  if (!recorded.ok) return recorded;
  return ok(deliver(recorded.value) as unknown as Output);
};

export const disassemble = (
  app: BeaApplication,
  input: Input,
  ctx: HandlerContext,
): Promise<Result<Output, BeaError>> =>
  anySessionOp(
    app,
    ctx,
    input.session_id,
    { mode: "exclusive", need: "agent" },
    {
      live: async (session, op) => {
        const literals = literalsOf(app);
        return literals.ok ? live({ app, ctx, input, literals: literals.value }, session, op) : literals;
      },
      emulation: async (handle, op) => {
        const literals = literalsOf(app);
        return literals.ok ? emulation({ app, ctx, input, literals: literals.value }, handle, op) : literals;
      },
    },
  );
