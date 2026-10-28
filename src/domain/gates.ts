/**
 * Server-level opt-in gates (orchestrator decision; names aligned with the S6
 * catalog: a gate is named after the tool it unlocks). A gate can only be
 * enabled at server start, through the environment or BEA_HOME/config.json.
 */
export const GATE_IDS = ["write_memory", "override_function", "run_script", "call_attached"] as const;

export type GateId = (typeof GATE_IDS)[number];

export interface GateSpec {
  /** Environment variable that enables the gate ("1"/"true"/"yes"/"on"). */
  readonly env: string;
  /** Key under `gates` in BEA_HOME/config.json (equals the gate id). */
  readonly configKey: GateId;
  /** One line shown by bea_status, doctor and the GateDisabled error. */
  readonly enables: string;
}

export const GATE_SPECS: { readonly [G in GateId]: GateSpec } = {
  write_memory: {
    env: "BEA_ALLOW_WRITE_MEMORY",
    configKey: "write_memory",
    enables: "write_memory: writes or patches target memory",
  },
  override_function: {
    env: "BEA_ALLOW_OVERRIDE",
    configKey: "override_function",
    enables: "override_function: rewrites arguments or return values",
  },
  run_script: {
    env: "BEA_ALLOW_RUN_SCRIPT",
    configKey: "run_script",
    enables: "run_script: runs caller-written Frida JavaScript",
  },
  call_attached: {
    env: "BEA_ALLOW_CALL_ATTACHED",
    configKey: "call_attached",
    enables: "call_function and the live leg of diff_function on attached (not BEA-spawned) targets",
  },
};

/** The exact instruction S6 puts in GateDisabled details (`details.enable`). */
export const gateEnableInstruction = (gate: GateId): string =>
  `set ${GATE_SPECS[gate].env}=1 (or gates.${gate}=true in BEA_HOME/config.json) and restart the server`;
