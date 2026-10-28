import { ADDRESS_TOOLS } from "./areas/address.js";
import { BEHAVIOR_TOOLS } from "./areas/behavior.js";
import { CALL_TOOLS } from "./areas/call.js";
import { DUMP_TOOLS } from "./areas/dump.js";
import { EMULATION_TOOLS } from "./areas/emulation.js";
import { EVIDENCE_TOOLS } from "./areas/evidence.js";
import { INSPECT_TOOLS } from "./areas/inspect.js";
import { INSTRUMENT_TOOLS } from "./areas/instrument.js";
import { MODIFY_TOOLS } from "./areas/modify.js";
import { SCAN_TOOLS } from "./areas/scan.js";
import { SESSION_TOOLS } from "./areas/sessions.js";
import { WATCH_TOOLS } from "./areas/watch.js";

/**
 * PRE-WIRED REGISTRY. Every area file is imported from day one so area work
 * packages never edit this file. Order here is catalog order (tools/list order);
 * nothing may select a contract by position.
 */
export const TOOL_CONTRACTS = [
  ...SESSION_TOOLS,
  ...INSPECT_TOOLS,
  ...ADDRESS_TOOLS,
  ...SCAN_TOOLS,
  ...INSTRUMENT_TOOLS,
  ...BEHAVIOR_TOOLS,
  ...WATCH_TOOLS,
  ...CALL_TOOLS,
  ...MODIFY_TOOLS,
  ...DUMP_TOOLS,
  ...EMULATION_TOOLS,
  ...EVIDENCE_TOOLS,
] as const;

export type AnyToolContract = (typeof TOOL_CONTRACTS)[number];
export type ToolName = AnyToolContract["name"];
export type ContractOf<N extends ToolName> = Extract<AnyToolContract, { readonly name: N }>;

const BY_NAME: ReadonlyMap<string, AnyToolContract> = new Map(
  TOOL_CONTRACTS.map((contract) => [contract.name, contract]),
);

/** Exact literal type, so a handler's input/output are fully typed from zod. */
export const toolContract = <N extends ToolName>(name: N): ContractOf<N> => {
  const found = BY_NAME.get(name);
  if (found === undefined) throw new Error(`Unknown tool contract ${name}`);
  return found as ContractOf<N>;
};

/** Untyped lookup for adapters (CLI argv, scenario steps). */
export const findToolContract = (name: string): AnyToolContract | undefined => BY_NAME.get(name);
