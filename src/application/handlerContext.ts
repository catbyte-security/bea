import type { z } from "zod";

import type { ToolContract } from "../contracts/toolContract.js";
import type { BeaError, BeaErrorOf } from "../domain/errors/beaError.js";
import type { GateId } from "../domain/gates.js";
import type { Logger } from "../domain/logger.js";
import type { Result } from "../domain/result.js";

export type Surface = "mcp" | "cli" | "scenario";

/** Why ctx.signal fired. Classified by which source signal aborted, never by parsing reasons. */
export type AbortCause =
  | { readonly kind: "client" }
  | { readonly kind: "deadline"; readonly budget_ms: number }
  | { readonly kind: "shutdown" };

export interface ProgressSink {
  /**
   * Fire-and-forget; rate-limited to 100 ms unless `final`; a no-op when the
   * caller asked for no progress. Messages are BEA-authored (counts, phases),
   * never target content.
   */
  readonly report: (phase: string, message: string, final?: boolean) => void;
}

export const silentProgress: ProgressSink = { report: () => undefined };

export type TargetOwnership = "owned" | "attached" | "none";

export interface GateEvaluator {
  readonly isEnabled: (gate: GateId) => boolean;
  readonly require: (gate: GateId, operation: string) => Result<void, BeaErrorOf<"GateDisabled">>;
  /** For scope "attached-targets": passes for BEA-owned targets, else requires the gate. */
  readonly requireUnlessOwned: (
    gate: GateId,
    operation: string,
    ownership: TargetOwnership,
  ) => Result<void, BeaErrorOf<"GateDisabled">>;
}

/** Everything a handler gets besides its parsed input. Identical for MCP, CLI and scenarios. */
export interface HandlerContext {
  readonly operation: string;
  readonly surface: Surface;
  /** Correlation id for logs (the JSON-RPC id on MCP). */
  readonly requestId: string;
  /** Aborts on client cancel, the contract's maxBlockingMs deadline, or server shutdown. */
  readonly signal: AbortSignal;
  readonly abortCause: () => AbortCause | null;
  /** Milliseconds left before the contract deadline. Pass min(remainingMs(), own budget) to providers. */
  readonly remainingMs: () => number;
  readonly progress: ProgressSink;
  readonly log: Logger;
  readonly gates: GateEvaluator;
}

export type ToolHandler<C extends ToolContract> = (
  input: z.output<C["inputSchema"]>,
  ctx: HandlerContext,
) => Promise<Result<z.output<C["outputSchema"]>, BeaError>>;

/** One handler per contract of an area; exhaustive by key remapping. */
export type HandlersFor<Cs extends readonly ToolContract[]> = {
  readonly [C in Cs[number] as C["name"]]: ToolHandler<C>;
};
