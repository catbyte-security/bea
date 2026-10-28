// =================================================================================================
// src/agent/pure/coreErrors.ts — WP3-AGENT pure helper: the mapThrown table (S4 §5.2). Frida error text and stolen
// NativeFunction exception fields → a tagged AgentError. Pure: errors.ts extracts the fields from the thrown value.
// The host never shows `frida_message` (CT-M8); `message` is always a curated text.
// =================================================================================================
import type { AgentError, Hex } from "../../shared/agentProtocol.js";

/** What errors.ts extracts from a thrown value (all optional except the text). */
export interface ThrownInfo {
  readonly text: string;
  /** stolen NativeFunction exception: ExceptionDetails.type */
  readonly type?: string;
  /** stolen exception: faulting instruction */
  readonly address?: string;
  readonly memoryOperation?: string;
  readonly memoryAddress?: string;
}

export const FRIDA_MESSAGE_MAX = 512;

const HOOK_ALTERNATIVES = [
  "watch_memory {method:'debug-register', access:'execute'} at the entry",
  "trace_execution coverage",
  "hook the call sites (disassemble callers)",
];

const asHex = (text: string | undefined): Hex => {
  const m = text === undefined ? null : /^0x([0-9a-f]+)$/iu.exec(text.trim());
  if (m === null || m[1] === undefined) return "0x0";
  const digits = m[1].toLowerCase().replace(/^0+(?=.)/u, "");
  return `0x${digits}`;
};

/** A hook that could not be installed at `address` (review fix EMU-14: callers pass the address they asked for). */
export const hookInstallFailedAt = (address: string, text: string): AgentError => ({
  _tag: "HookInstallFailed",
  message: "the hook could not be installed",
  address: asHex(address),
  attempts: ["default"],
  frida_message: text.slice(0, FRIDA_MESSAGE_MAX),
  alternatives: [...HOOK_ALTERNATIVES],
});

const memOp = (op: string | undefined): "read" | "write" | "execute" | null =>
  op === "read" || op === "write" || op === "execute" ? op : null;

/** A stolen NativeFunction exception (`e.type` present, [ext-frida §3.7]). */
const fromStolen = (info: ThrownInfo, where: string): AgentError | null => {
  if (info.type === "access-violation")
    return {
      _tag: "AccessViolation",
      message: "access violation",
      address: asHex(info.memoryAddress ?? info.address),
      operation: memOp(info.memoryOperation),
    };
  if (info.type === "guard-page")
    return { _tag: "GuardPage", message: "guard page hit", address: asHex(info.memoryAddress), owner: "target" };
  if (info.type !== undefined)
    return {
      _tag: "Internal",
      message: `native exception (${info.type})`,
      where,
      frida_message: info.text.slice(0, FRIDA_MESSAGE_MAX),
    };
  return null;
};

type Rule = readonly [RegExp, (m: RegExpExecArray, info: ThrownInfo, where: string) => AgentError];

const RULES: readonly Rule[] = [
  [
    /access violation accessing (0x[0-9a-f]+)/iu,
    (m, info) => ({
      _tag: "AccessViolation",
      message: "access violation",
      address: asHex(m[1]),
      operation: memOp(info.memoryOperation),
    }),
  ],
  [
    /guard page was hit accessing (0x[0-9a-f]+)/iu,
    (m) => ({ _tag: "GuardPage", message: "guard page hit", address: asHex(m[1]), owner: "target" }),
  ],
  [
    // Frida prints the address with or without 0x depending on the platform's %p (Windows: no prefix; EMU-14)
    /unable to intercept function(?: at (?:0x)?([0-9a-f]+))?/iu,
    (m, info) => hookInstallFailedAt(m[1] === undefined ? "0x0" : `0x${m[1]}`, info.text),
  ],
  [
    /already replaced this function/iu,
    () => ({
      _tag: "HookConflict",
      message: "the function is already replaced",
      address: "0x0",
      existing: "",
      kind: "replace",
    }),
  ],
  [
    /unable to find module '([^']+)'/iu,
    (m) => ({ _tag: "ModuleNotFound", message: "module not found", module: m[1] ?? "" }),
  ],
  [
    /unable to find (?:global )?export '([^']+)'/iu,
    (m) => ({ _tag: "ExportNotFound", message: "export not found", module: "", export: m[1] ?? "" }),
  ],
  [
    /invalid match pattern/iu,
    () => ({
      _tag: "BadParams",
      message: "invalid match pattern",
      issues: [{ path: "pattern", problem: "invalid match pattern" }],
    }),
  ],
];

/** The mapThrown table: stolen-exception fields first, then the text rules, else Internal{where, frida_message}. */
export const agentErrorFromThrown = (info: ThrownInfo, where: string): AgentError => {
  const stolen = fromStolen(info, where);
  if (stolen !== null) return stolen;
  for (const [re, make] of RULES) {
    const m = re.exec(info.text);
    if (m !== null) return make(m, info, where);
  }
  return {
    _tag: "Internal",
    message: "agent internal error",
    where,
    frida_message: info.text.slice(0, FRIDA_MESSAGE_MAX),
  };
};

/** The address of a "guard page was hit accessing 0x…" text, or null (stolen-guard re-arm, CT-I5). */
export const guardPageAddressOf = (text: string): bigint | null => {
  const m = /guard page was hit accessing (0x[0-9a-f]+)/iu.exec(text);
  return m?.[1] === undefined ? null : BigInt(m[1]);
};

/** Structural param check helper: an issue list → BadParams (null when no issues). */
export const badParams = (issues: readonly { path: string; problem: string }[]): AgentError | null =>
  issues.length === 0
    ? null
    : {
        _tag: "BadParams",
        message: `invalid parameters: ${issues.map((i) => i.path).join(", ")}`,
        issues: [...issues],
      };
