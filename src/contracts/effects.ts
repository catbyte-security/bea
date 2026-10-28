/**
 * Audited effects of one tool across all its supported inputs (REA toolEffects.ts,
 * extended for dynamic analysis). Annotations are only ever derived from this.
 */
export interface ToolEffects {
  /** Reads target memory, registers or module state through the (already loaded) agent. */
  readonly readsTargetMemory: boolean;
  /** Changes target data or code semantics: writes, patches, argument/return overrides, scratch writes for calls. */
  readonly writesTargetMemory: boolean;
  /** Loads the BEA agent or a caller script into a target (frida-agent.dll + 24 DLLs; 11 stay after detach). */
  readonly injectsCode: boolean;
  /** Reversible observation changes: hooks, debug registers, guard pages, Stalker. */
  readonly instrumentsTarget: boolean;
  /** Makes target code run: resume, in-process call, raw script. */
  readonly executesTargetCode: boolean;
  /** Leaves the target paused (spawn). */
  readonly suspendsTarget: boolean;
  /** Starts a target process. BEA's own helpers (jobhost, emulator bridge) do not count. */
  readonly launchesProcess: boolean;
  /** Terminates a target. Only BEA-owned targets can be killed. */
  readonly killsProcess: boolean;
  /** Writes caller-visible files (dumps, exports, coverage). BEA_HOME run storage does not count. */
  readonly writesFilesystem: boolean;
  /** Can overwrite or destroy state the caller cannot recover from BEA. */
  readonly mayDiscardData: boolean;
  /** Talks to a remote device. Always false in v0.1 (local device only). */
  readonly accessesNetwork: boolean;
  /** Appends to BEA's ledger or creates/destroys BEA handles. Not part of readOnlyHint (D5). */
  readonly mutatesSession: boolean;
  /** Repeating the call with the same input has no further effect. */
  readonly idempotent: boolean;
}

export const EFFECT_FLAGS = [
  "readsTargetMemory",
  "writesTargetMemory",
  "injectsCode",
  "instrumentsTarget",
  "executesTargetCode",
  "suspendsTarget",
  "launchesProcess",
  "killsProcess",
  "writesFilesystem",
  "mayDiscardData",
  "accessesNetwork",
  "mutatesSession",
  "idempotent",
] as const satisfies readonly (keyof ToolEffects)[];

/** Every flag explicit; defaults: all false except idempotent. */
export const fx = (overrides: Partial<ToolEffects> = {}): ToolEffects =>
  Object.freeze({
    readsTargetMemory: false,
    writesTargetMemory: false,
    injectsCode: false,
    instrumentsTarget: false,
    executesTargetCode: false,
    suspendsTarget: false,
    launchesProcess: false,
    killsProcess: false,
    writesFilesystem: false,
    mayDiscardData: false,
    accessesNetwork: false,
    mutatesSession: false,
    idempotent: true,
    ...overrides,
  });

export interface DerivedToolAnnotations {
  readonly readOnlyHint: boolean;
  readonly destructiveHint: boolean;
  readonly idempotentHint: boolean;
  readonly openWorldHint: boolean;
}

/**
 * D5 (orchestrator): readOnlyHint ignores BEA's own ledger/handle state
 * (mutatesSession) and reads through an already-injected agent
 * (readsTargetMemory); injection is declared on spawn/attach (injectsCode).
 */
export const annotationsFromEffects = (e: ToolEffects): DerivedToolAnnotations => ({
  readOnlyHint: !(
    e.injectsCode ||
    e.instrumentsTarget ||
    e.writesTargetMemory ||
    e.executesTargetCode ||
    e.suspendsTarget ||
    e.launchesProcess ||
    e.killsProcess ||
    e.writesFilesystem ||
    e.mayDiscardData ||
    e.accessesNetwork
  ),
  destructiveHint: e.writesTargetMemory || e.executesTargetCode || e.killsProcess || e.mayDiscardData,
  idempotentHint: e.idempotent,
  openWorldHint: e.launchesProcess || e.accessesNetwork,
});

/** The true flags, in EFFECT_FLAGS order; advertised as tools/list `_meta["bea/effects"]`. */
export const effectFlags = (e: ToolEffects): string[] => EFFECT_FLAGS.filter((flag) => e[flag]);
