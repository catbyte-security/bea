import type {
  AgentLimits,
  AgentResult,
  AgentRpcImpl,
  CfgBlock,
  DisassembleParams,
  DisassembleResult,
  InsnRow,
} from "../shared/agentProtocol.js";
import { AGENT_LIMIT_DEFAULTS, AGENT_LIMIT_HARD } from "../shared/agentLimits.js";
import { bytesToHex, formatHex, type Hex } from "../shared/hex.js";
import { fail, ok } from "./errors.js";
import {
  anyOverlay,
  CFG_MAX_BLOCKS,
  FUNCTION_MAX_INSNS,
  hexAt,
  immToBigInt,
  isRelativeBranch,
  overlayMask,
  pageChunks,
  planWindow,
  relocate,
  rewriteBranchText,
  ripRelative,
  SCRATCH_PAD,
  stopForOverrun,
  touchesOverlay,
  type DisasmMode,
  type DisasmWindow,
} from "./pure/codeDisasm.js";
import type { AgentCore } from "./state.js";

/**
 * Agent feature file of WP-INSPECT (S4 §8.4 `disassemble`; DESIGN §5.3 D-INT-36: `disasm` core vs `code` feature).
 *
 * Every window is copied into one module-scope scratch allocation, BEA's own original bytes are overlaid on the copy
 * (Instruction.parse at a hooked address would show the hook's jmp [ext-frida §3.6]) and the copy is decoded with
 * Instruction.parse; relative branch targets are moved back from the scratch to the real address and RIP-relative
 * operands are resolved against the real `next` [ext-frida §3.12]. Reading the window first also means a decode can
 * never fault on a page that becomes unreadable mid-call.
 *
 * Core services are reached structurally (`originals`, `guards`, `config.limits`): the WP-AGENT core shape is not
 * frozen in §4, so a missing service degrades (no overlay, no guard suspension) instead of failing the build.
 */
interface OriginalsView {
  /** S4 §8.4: any BEA patch inside the range */
  readonly isPatched?: (range: { readonly base: NativePointer; readonly size: number }) => boolean;
  /** S4 §8.4: write the saved original bytes of every BEA patch inside [base, base + buf.byteLength) into buf */
  readonly overlay?: (buf: ArrayBuffer, base: NativePointer) => unknown;
}
interface GuardsView {
  /** D-INT-44: run fn with BEA guard pages intersecting `ranges` temporarily unguarded */
  readonly withBeaGuardsSuspended?: <T>(
    ranges: readonly { readonly base: NativePointer; readonly size: number }[],
    fn: () => T,
  ) => T;
}
interface CoreServicesView {
  readonly limits?: AgentLimits;
  readonly config?: { readonly limits?: AgentLimits };
  readonly originals?: OriginalsView;
  readonly guards?: GuardsView;
}

let core: AgentCore | null = null;
/** Kept referenced from module scope: QJS frees a local allocation (VERIFIED for code pages, S4 §13). */
let scratch: NativePointer | null = null;
let scratchBytes = 0;

const services = (): CoreServicesView => (core ?? {}) as unknown as CoreServicesView;
const limitsOf = (): AgentLimits => services().config?.limits ?? services().limits ?? AGENT_LIMIT_DEFAULTS;
const clampLimit = (value: number, key: "disasm_max_bytes" | "disasm_max_insns"): number =>
  Math.max(1, Math.min(Math.floor(value), AGENT_LIMIT_HARD[key]));

const ensureScratch = (bytes: number): NativePointer => {
  if (scratch === null || scratchBytes < bytes) {
    scratch = Memory.alloc(bytes);
    scratchBytes = bytes;
  }
  return scratch;
};

/** The readable prefix of [base, base + length): one read, else page by page up to the first unreadable page. */
const readPrefix = (base: NativePointer, length: number): ArrayBuffer => {
  const direct = (): ArrayBuffer => {
    try {
      const whole = base.readByteArray(length);
      if (whole !== null && whole.byteLength === length) return whole;
    } catch {
      // fall through to the page-wise read (S4 §8.2 step 2)
    }
    const parts: Uint8Array[] = [];
    let total = 0;
    for (const chunk of pageChunks(BigInt(base.toString()), length, Process.pageSize)) {
      let part: ArrayBuffer | null = null;
      try {
        part = base.add(chunk.offset).readByteArray(chunk.length);
      } catch {
        part = null;
      }
      if (part === null || part.byteLength === 0) break;
      parts.push(new Uint8Array(part));
      total += part.byteLength;
      if (part.byteLength < chunk.length) break;
    }
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out.buffer;
  };
  const guards = services().guards;
  if (typeof guards?.withBeaGuardsSuspended === "function") {
    try {
      return guards.withBeaGuardsSuspended([{ base, size: length }], direct);
    } catch {
      // a core that cannot suspend still lets us read what is readable
    }
  }
  return direct();
};

/** Original bytes of BEA patches overlaid on a copy of `live` (null when the core has no originals service). */
const overlayOriginals = (base: NativePointer, live: ArrayBuffer): ArrayBuffer | null => {
  const originals = services().originals;
  if (typeof originals?.overlay !== "function") return null;
  try {
    if (typeof originals.isPatched === "function" && !originals.isPatched({ base, size: live.byteLength })) return null;
    const copy = live.slice(0);
    originals.overlay(copy, base);
    return copy;
  } catch {
    return null;
  }
};

const badParams = (path: string, problem: string): AgentResult<never> =>
  fail({ _tag: "BadParams", message: "invalid disassemble parameters", issues: [{ path, problem }] });

const MODES: readonly DisasmMode[] = ["count", "function", "range"];

const cfgBlocks = (fnBase: NativePointer): CfgBlock[] | null => {
  try {
    const graph = new ControlFlowGraph(fnBase);
    return graph.blocks.slice(0, CFG_MAX_BLOCKS).map((block) => ({
      start: formatHex(BigInt(block.start.toString())),
      end: formatHex(BigInt(block.end.toString())),
      successors: block.successors.map((s) => formatHex(BigInt(s.start.toString()))),
    }));
  } catch {
    return null;
  }
};

interface Plan {
  readonly start: NativePointer;
  readonly range: MemoryRange | null;
  readonly window: DisasmWindow;
}

/** Step 1 (S4 §8.4): the start and byte window of the call, or BadParams/NoFunctionRange. */
const planCall = (p: DisassembleParams): AgentResult<Plan> => {
  if (typeof p.address !== "string" || !/^0x[0-9a-f]{1,16}$/iu.test(p.address))
    return badParams("address", "a 0x-prefixed hex address is required");
  if (!MODES.includes(p.mode)) return badParams("mode", "mode must be count, function or range");
  const limits = limitsOf();
  const maxBytes = clampLimit(limits.disasm_max_bytes, "disasm_max_bytes");
  const requested = ptr(p.address);
  const range = Process.findFunctionRange(requested);
  if (p.mode === "function") {
    if (range === null) return fail({ _tag: "NoFunctionRange", message: "no .pdata function", address: p.address });
    const maxInsns = Math.min(FUNCTION_MAX_INSNS, AGENT_LIMIT_HARD.disasm_max_insns);
    return ok({ start: range.base, range, window: planWindow("function", range.size, { maxBytes, maxInsns }) });
  }
  const wanted = p.mode === "count" ? p.count : p.size;
  if (wanted === undefined || !Number.isInteger(wanted) || wanted < 1)
    return badParams(p.mode === "count" ? "count" : "size", "a positive integer is required");
  const maxInsns = clampLimit(limits.disasm_max_insns, "disasm_max_insns");
  return ok({ start: requested, range, window: planWindow(p.mode, wanted, { maxBytes, maxInsns }) });
};

interface Decoded {
  readonly scratchBase: bigint;
  readonly realBase: bigint;
  readonly shown: Uint8Array;
  readonly mask: Uint8Array;
}

/** One decoded instruction as a row: real addresses, relocated branch text, RIP-relative targets, overlay flag. */
const rowOf = (insn: X86Instruction, offset: number, d: Decoded, operands: boolean): InsnRow => {
  const next = d.realBase + BigInt(offset + insn.size);
  let opStr = insn.opStr;
  let branchTarget: Hex | null = null;
  if (isRelativeBranch(insn.groups)) {
    const imm = insn.operands.find((o) => o.type === "imm");
    const scratchTarget = imm === undefined ? null : immToBigInt(imm.value);
    if (scratchTarget !== null) {
      const real = relocate(scratchTarget, d.scratchBase, d.realBase);
      opStr = rewriteBranchText(opStr, scratchTarget, real);
      branchTarget = formatHex(real);
    }
  }
  const memTargets: Hex[] = [];
  for (const operand of insn.operands)
    if (operand.type === "mem" && operand.value.base === "rip")
      memTargets.push(formatHex(ripRelative(next, operand.value.disp)));
  const row: InsnRow = {
    address: hexAt(d.realBase, offset),
    size: insn.size,
    bytes: bytesToHex(d.shown.subarray(offset, offset + insn.size)),
    mnemonic: insn.mnemonic,
    op_str: opStr,
    groups: [...insn.groups],
    branch_target: branchTarget,
    mem_targets: memTargets,
    overlay: touchesOverlay(d.mask, offset, insn.size),
  };
  if (operands) {
    row.regs_read = [...insn.regsAccessed.read];
    row.regs_written = [...insn.regsAccessed.written];
  }
  return row;
};

/** Steps 3–4: decode the scratch copy until the window, the instruction cap, a decode error or an overrun. */
const decodeAll = (
  scratchPtr: NativePointer,
  d: Decoded,
  plan: Plan,
  p: DisassembleParams,
): { readonly instructions: InsnRow[]; readonly stop: DisassembleResult["stop"] } => {
  const { window } = plan;
  const readable = d.shown.length;
  const instructions: InsnRow[] = [];
  let offset = 0;
  while (offset < readable) {
    if (instructions.length >= window.maxInsns)
      return { instructions, stop: p.mode === "count" ? null : { reason: "limit", at: hexAt(d.realBase, offset) } };
    let insn: X86Instruction;
    try {
      insn = Instruction.parse(scratchPtr.add(offset)) as X86Instruction;
    } catch {
      return { instructions, stop: { reason: "decode-error", at: hexAt(d.realBase, offset) } };
    }
    if (offset + insn.size > readable)
      return {
        instructions,
        stop: { reason: stopForOverrun(readable, window.bytes), at: hexAt(d.realBase, offset) },
      };
    instructions.push(rowOf(insn, offset, d, p.operands));
    offset += insn.size;
  }
  const wantedMore = p.mode !== "count" || instructions.length < window.maxInsns;
  // the read stopped short of the window: the next page is unreadable
  if (readable < window.bytes && wantedMore)
    return { instructions, stop: { reason: "access-violation", at: hexAt(d.realBase, readable) } };
  // the function/range was longer than the byte cap
  if (p.mode !== "count" && window.clipped)
    return { instructions, stop: { reason: "limit", at: hexAt(d.realBase, offset) } };
  return { instructions, stop: null };
};

function disassemble(p: DisassembleParams): AgentResult<DisassembleResult> {
  const planned = planCall(p);
  if (!planned.ok) return planned;
  const plan = planned.value;
  const { start, range, window } = plan;

  // 2. the bytes, guard-aware (S4 §8.2)
  const live = readPrefix(start, window.bytes);
  const startHex: Hex = formatHex(BigInt(start.toString()));
  if (live.byteLength === 0)
    return fail({
      _tag: "AccessViolation",
      message: "the first byte is unreadable",
      address: startHex,
      operation: "read",
      partial_bytes: 0,
    });
  const liveBytes = new Uint8Array(live);

  // 3./4. overlay of BEA's original bytes (S4 §8.4 steps 3–4); decoded from scratch either way
  const original = p.original_bytes ? overlayOriginals(start, live) : null;
  const shown = original === null ? liveBytes : new Uint8Array(original);
  const mask = original === null ? new Uint8Array(liveBytes.length) : overlayMask(liveBytes, shown);
  const scratchPtr = ensureScratch(window.bytes + SCRATCH_PAD);
  scratchPtr.writeByteArray(shown.buffer.slice(shown.byteOffset, shown.byteOffset + shown.length) as ArrayBuffer);
  scratchPtr.add(shown.length).writeByteArray(new ArrayBuffer(SCRATCH_PAD + window.bytes - shown.length));
  const decoded: Decoded = {
    scratchBase: BigInt(scratchPtr.toString()),
    realBase: BigInt(start.toString()),
    shown,
    mask,
  };
  const { instructions, stop } = decodeAll(scratchPtr, decoded, plan, p);

  // 5. optional CFG over live bytes (best effort when patched)
  return ok({
    start: startHex,
    function:
      range === null ? null : { base: formatHex(BigInt(range.base.toString())), size: range.size, source: "pdata" },
    instructions,
    truncated: stop?.reason === "limit",
    overlay_used: anyOverlay(mask),
    stop,
    blocks: p.cfg && range !== null ? cfgBlocks(range.base) : null,
  });
}

/** Agent feature file. WP-INSPECT owns it. Methods: disassemble. */
export function init(c: AgentCore): void {
  core = c;
}
export const rpc = {
  disassemble: (p) => disassemble(p),
} satisfies Partial<AgentRpcImpl>;
