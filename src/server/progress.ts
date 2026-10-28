import type { ServerContext } from "@modelcontextprotocol/server";

import { silentProgress, type ProgressSink } from "../application/handlerContext.js";
import type { Clock } from "../domain/clock.js";

const MIN_INTERVAL_MS = 100;

/**
 * Progress only when the caller sent a progressToken (rea-mcp §1.8). `progress`
 * is a strictly increasing sequence; no invented total; phase in the message.
 * Notification failures are swallowed: progress is observational.
 */
export const mcpProgressSink = (ctx: Pick<ServerContext, "mcpReq">, clock: Clock): ProgressSink => {
  const token = ctx.mcpReq._meta?.progressToken;
  if (token === undefined) return silentProgress;
  let sequence = 0;
  let last = Number.NEGATIVE_INFINITY;
  return {
    report: (phase, message, final = false) => {
      const now = clock.monoMs();
      if (!final && now - last < MIN_INTERVAL_MS) return;
      last = now;
      sequence += 1;
      void ctx.mcpReq
        .notify({
          method: "notifications/progress",
          params: { progressToken: token, progress: sequence, message: `${phase}: ${message}`.slice(0, 512) },
        })
        .catch(() => undefined);
    },
  };
};
