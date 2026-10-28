import { describe, expect, it } from "vitest";

import type { BeaApplication } from "../../../src/application/BeaApplication.js";
import type { HandlerContext } from "../../../src/application/handlerContext.js";
import { emuOp } from "../../../src/application/sessionAccess.js";
import { Deadline } from "../../../src/domain/deadline.js";
import { ok } from "../../../src/domain/result.js";
import type { OperationContext } from "../../../src/ports/sessions.js";

/**
 * Review fix EMU-4: tool operations on one emulation session run one at a time (FIFO), so a bridge request sequence
 * (run, then state.save, then the lineage update) of one call never interleaves with another call's.
 */
const fakeApp = (): BeaApplication => {
  let ops = 0;
  return {
    services: {
      sessions: {
        admit: async (name: string, req: { signal?: AbortSignal }, fn: (op: OperationContext) => Promise<unknown>) =>
          fn({
            opId: ++ops,
            name,
            signal: req.signal ?? new AbortController().signal,
            deadline: Deadline.after(30_000),
          }),
        kindOf: () => "emulation",
      },
      emulator: { lookup: (id: string) => ({ sessionId: id, generation: 0 }) },
    },
  } as unknown as BeaApplication;
};

const ctxOf = (signal = new AbortController().signal): HandlerContext =>
  ({ operation: "emu_call", signal, remainingMs: () => 30_000 }) as unknown as HandlerContext;

describe("emulation operations are exclusive per session (EMU-4)", () => {
  it("a second call on the same session starts only after the first finished; other sessions run concurrently", async () => {
    const app = fakeApp();
    const events: string[] = [];
    let releaseFirst: () => void = () => undefined;
    const first = emuOp(app, ctxOf(), "s1", async () => {
      events.push("A:start");
      await new Promise<void>((resolve) => {
        releaseFirst = resolve;
      });
      events.push("A:end");
      return ok("A");
    });
    const second = emuOp(app, ctxOf(), "s1", async () => {
      events.push("B:start");
      return ok("B");
    });
    const other = emuOp(app, ctxOf(), "s2", async () => {
      events.push("C:start");
      return ok("C");
    });
    await other;
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(events).toEqual(["A:start", "C:start"]);
    releaseFirst();
    expect(await first).toEqual(ok("A"));
    expect(await second).toEqual(ok("B"));
    expect(events).toEqual(["A:start", "C:start", "A:end", "B:start"]);
  });

  it("a queued call that is cancelled while waiting never runs and does not block the queue", async () => {
    const app = fakeApp();
    let releaseFirst: () => void = () => undefined;
    const first = emuOp(app, ctxOf(), "s1", async () => {
      await new Promise<void>((resolve) => {
        releaseFirst = resolve;
      });
      return ok(1);
    });
    const controller = new AbortController();
    let ran = false;
    const queued = emuOp(app, ctxOf(controller.signal), "s1", async () => {
      ran = true;
      return ok(2);
    });
    controller.abort();
    const cancelled = await queued;
    expect(!cancelled.ok && cancelled.error._tag).toBe("Cancelled");
    releaseFirst();
    await first;
    expect(ran).toBe(false);
    expect(await emuOp(app, ctxOf(), "s1", async () => ok(3))).toEqual(ok(3));
  });
});
