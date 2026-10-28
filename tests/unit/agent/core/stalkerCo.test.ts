// WP3-AGENT unit tests: the StalkerCoordinator's busy answers (S4 §12.1). A thread settling after an unfollow names
// the instrument that released it (review fix AGENT-12: it said owner "call", an owner no code path ever claims).
// stalkerCo.ts is a GumJS file (Stalker in its methods, NativePointer in its types): imported at run time only, the
// root typecheck has no frida-gum types; claim/release touch neither.
import { describe, expect, it } from "vitest";

interface CoordinatorLike {
  claim(tid: number, owner: string): Record<string, unknown> | null;
  release(tid: number): void;
  forget(tid: number): void;
}
const STALKER_CO_MODULE = "../../../../src/agent/stalkerCo.js";

const coordinator = async (clock: { now: number }): Promise<CoordinatorLike> => {
  const { StalkerCoordinator } = (await import(STALKER_CO_MODULE)) as {
    StalkerCoordinator: new (core: unknown) => CoordinatorLike;
  };
  return new StalkerCoordinator({
    jsTid: 1,
    limits: { stalker_settle_ms: 300 },
    fault: () => undefined,
    native: { nowUs: () => clock.now },
  });
};

describe("StalkerCoordinator busy answers (review fix AGENT-12)", () => {
  it("names the following instrument (state followed), then the releasing one while the thread settles", async () => {
    const clock = { now: 1_000_000 };
    const co = await coordinator(clock);
    expect(co.claim(7, "t5")).toBeNull();
    expect(co.claim(7, "t6")).toMatchObject({ _tag: "StalkerBusy", owner: "t5", state: "followed", retry_after_ms: 0 });
    co.release(7);
    clock.now += 100_000; // 100 ms into the 300 ms settle
    const settling = co.claim(7, "t6");
    expect(settling).toMatchObject({
      _tag: "StalkerBusy",
      thread_id: 7,
      owner: "t5",
      state: "settling",
      retry_after_ms: 200,
    });
    expect(settling?.["owner"]).not.toBe("call");
    clock.now += 250_000;
    expect(co.claim(7, "t6")).toBeNull();
  });

  it("forget drops a thread without a settle period; the agent thread is never traced", async () => {
    const clock = { now: 0 };
    const co = await coordinator(clock);
    expect(co.claim(9, "t1")).toBeNull();
    co.forget(9);
    expect(co.claim(9, "t2")).toBeNull();
    expect(co.claim(1, "t3")).toMatchObject({ _tag: "BadParams" });
  });
});
