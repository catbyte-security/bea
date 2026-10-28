import type { BeaCore } from "../../application/BeaApplication.js";
import type { RunId } from "../../domain/ids.js";
import type { EvidenceRuntime } from "../../ports/evidence.js";
import { LedgerEvidenceRuntime } from "./EvidenceRuntimeImpl.js";
import type { RunKind } from "./RunStore.js";

const KIND: { readonly [T in BeaCore["run"]["transport"]]: RunKind } = {
  stdio: "mcp-stdio",
  http: "mcp-http",
  cli: "cli",
};

/**
 * WP-EVID factory. Synchronous-cheap construction: nothing touches the disk until the first write (CI-M20). Registers
 * the `finalize-evidence` lifecycle closer (fenced first, CT-M6) and the bea_status `storage` contributor (CI-M17).
 * CLI runs are finalized like any run; deleting an ephemeral CLI run directory (no --keep-run, no export) is the CLI
 * runner's job (it knows the flags), after lifecycle.closeAll.
 */
export const createEvidenceRuntime = (core: BeaCore, deps: Record<never, never>): EvidenceRuntime => {
  void deps;
  const runtime = new LedgerEvidenceRuntime({
    config: core.config,
    runId: core.run.runId as RunId,
    kind: KIND[core.run.transport],
    startedWall: core.run.startedAt,
    clock: core.clock,
    seq: core.seq,
    logger: core.logger.child({ component: "evidence" }),
  });
  core.lifecycle.register({
    name: "finalize-evidence",
    phase: "finalize-evidence",
    close: async () => {
      const result = await runtime.finalize(core.run.transport === "cli" ? "cli-exit" : "shutdown");
      if (!result.ok) throw new Error(`evidence finalize failed (${result.error._tag})`);
    },
  });
  core.status.add({ name: "evidence", storage: () => runtime.storageStatus() });
  return runtime;
};
