import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";

/**
 * BEA-FEEDBACK item 6, through the BUILT server (BEA_DIST_DIR snapshot). trace_execution threads mode follows a thread
 * that is blocked in a system call from its next entry into that stub, through a listener on the stub (the Frida
 * 17.23.2 deadlock workaround). Every thread of the process waits in such stubs: on Chrome's GPU process a JS listener
 * there sent each wait through a JS callback and the agent's script lock, for the whole trace, and the process wedged.
 * The listener is native now (other threads never enter JS) and is removed once its target is followed.
 *
 * waiters.exe: 16 workers block and wake about 700,000 times a second in ntdll!NtWaitForSingleObject (a semaphore ring
 * with 2 tokens, about one core), and one more thread is parked in a 3 s wait on the same stub. The trace of the parked
 * thread starts right after one of its wake-ups, so the listener is attached for the next ~3 s while the workers run
 * through it; then the parked thread re-enters the stub, is followed, and the listener must go away while the trace
 * still runs. The workers' wake-up rate (the fixture's own counter and clock, g_meter) is compared with the rate before
 * the trace, measured the same way. "Agent busy" windows keep the agent's JS thread working (heavy disassemble calls
 * back to back), so it holds the script lock most of the time: a listener that takes that lock stalls every wait.
 * Tool-level calibration on the test host (ratios to the matching baseline):
 *
 *   listener                 attached, quiet   attached, agent busy   target followed, quiet   after the stop
 *   JS (before item 6)       0.52–0.68         0.39–0.47              0.53–0.65 (attached)     0.88–1.20
 *   native (this change)     0.71–0.88         0.81–0.94              0.79–1.07 (removed)      0.84–1.08
 *
 * While attached, the native listener still costs the workers 10–30 % at this extreme rate (Interceptor's own
 * trampoline on every wait); a realistic process waits orders of magnitude less often.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();

/** Listener attached, agent busy: the share of the (agent busy) baseline the workers keep; see the calibration. */
const MIN_RATE_ATTACHED_AGENT_BUSY = 0.65;
/** Every other phase: near the baseline (the acceptance bar of item 6). */
const MIN_RATE = 0.5;
const PARK_MS = 3000;
const TRACE_MS = 7000;
const WINDOW_MS = 1800;
/** shorter: the attached window (and its agent load) must end before the parked thread's next wake-up */
const BUSY_WINDOW_MS = 1500;

let waiters: FixtureArtifact;
let ledger: OwnedPidLedger;

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "waiters");
  if (artifact === null) throw new Error("waiters fixture unavailable");
  waiters = artifact;
  ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
});

afterAll(async () => {
  if (skip !== false) return;
  await ledger.assertClean();
});

const out = (r: unknown): Readonly<Record<string, unknown>> => expectToolSuccess(r as Record<string, unknown>);
const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const hex = (v: bigint): string => `0x${v.toString(16)}`;

/** The canonical stub's first bytes, `mov r10, rcx; mov eax, …`; a hooked stub starts with a jmp. */
const PLAIN_STUB_HEAD = "4c8bd1b8";

interface Probe {
  /** the workers' wake-ups per second over `ms`, by the fixture's own clock */
  rate(ms: number): Promise<number>;
  /** the same while the agent's JS thread is kept busy */
  rateAgentBusy(ms: number): Promise<number>;
  u64(name: string): Promise<bigint>;
  u32(name: string): Promise<number>;
  /** the first 4 bytes of ntdll!NtWaitForSingleObject, hex */
  stubHead(): Promise<string>;
}

const probe = (bea: BeaConnection, session: string): Probe => {
  const read = async (address: string, size: number, view: string): Promise<Readonly<Record<string, unknown>>> =>
    out(await bea.call("read_memory", { session_id: session, address, size, view }));
  const values = async (address: string, size: number, view: string): Promise<unknown[]> =>
    (await read(address, size, view))["values"] as unknown[];
  /** g_meter = {u64 wakeups; u64 clock_us}, written together by the fixture's meter thread */
  const meter = async (): Promise<{ wakeups: number; us: number }> => {
    const [wakeups, us] = await values("waiters.exe!g_meter", 16, "u64");
    return { wakeups: Number(BigInt(String(wakeups))), us: Number(BigInt(String(us))) };
  };
  const rate = async (ms: number): Promise<number> => {
    const a = await meter();
    await delay(ms);
    const b = await meter();
    return ((b.wakeups - a.wakeups) * 1e6) / Math.max(1, b.us - a.us);
  };
  /** one large .pdata function (≤ 4096 instructions) per call: about 0.1 s of agent JS each on the test host */
  const busy = async (until: { stop: boolean }): Promise<void> => {
    while (!until.stop)
      out(
        await bea.call("disassemble", {
          session_id: session,
          address: "kernelbase.dll!CreateProcessInternalW",
          function: true,
        }),
      );
  };
  return {
    rate,
    rateAgentBusy: async (ms) => {
      const flag = { stop: false };
      const load = busy(flag);
      try {
        await delay(100);
        return await rate(ms);
      } finally {
        flag.stop = true;
        await load;
      }
    },
    u64: async (name) => BigInt(String((await values(`waiters.exe!${name}`, 8, "u64"))[0])),
    u32: async (name) => Number((await values(`waiters.exe!${name}`, 4, "u32"))[0]),
    stubHead: async () => String((await read("ntdll.dll!NtWaitForSingleObject", 4, "hex"))["data"]).toLowerCase(),
  };
};

/** Hits of the block at `va` in a block_counts recording (the agent may flush one block in several deltas). */
const blockHits = async (bea: BeaConnection, recording: string, va: bigint): Promise<number> => {
  const page = out(
    await bea.call("query_events", {
      recording_id: recording,
      view: "rows",
      fields: ["va", "hits"],
      where: [{ field: "va", op: "eq", value: hex(va) }],
      limit: 500,
    }),
  );
  return (page["rows"] as unknown[][]).reduce((n, r) => n + Number(r[2]), 0);
};

describe.skipIf(skip !== false)(
  `trace_execution threads mode on a thread parked in a stub every thread waits in${skipNote(skip)}`,
  () => {
    it("the other threads keep their wake-up rate, the listener goes away once the target is followed, its next round is traced", async () => {
      const bea = await connectBea({ ledger });
      try {
        const spawned = out(
          await bea.call("spawn_process", {
            program: waiters.path,
            args: [
              "--mode",
              "ring",
              "--workers",
              "16",
              "--tokens",
              "2",
              "--park-ms",
              String(PARK_MS),
              "--seconds",
              "180",
            ],
          }),
        );
        const session = String(spawned["session_id"]);
        const base = BigInt(String((spawned["main_module"] as { base: string }).base));
        out(await bea.call("resume_process", { session_id: session }));
        out(
          await bea.call("wait", {
            session_id: session,
            until: "output",
            output_contains: "READY",
            timeout_ms: 15_000,
          }),
        );
        const p = probe(bea, session);
        const parked = await p.u32("g_parked_tid");
        expect(parked).toBeGreaterThan(0);
        expect(await p.stubHead()).toBe(PLAIN_STUB_HEAD);
        const baseline = await p.rate(2000);
        const baselineBusy = await p.rateAgentBusy(BUSY_WINDOW_MS);
        expect(baseline, "the workers wake up").toBeGreaterThan(10_000);
        const ratio = (rate: number, of: number, phase: string): [number, string] => [
          rate / of,
          `${phase}: ${Math.round(rate)}/s against a baseline of ${Math.round(of)}/s`,
        ];

        // start right after a wake-up of the parked thread: it is back in its 3 s wait, so the listener stays ~3 s
        const rounds0 = await p.u64("g_parked_rounds");
        await vi.waitFor(async () => expect(await p.u64("g_parked_rounds")).toBeGreaterThan(rounds0), {
          timeout: PARK_MS + 3000,
          interval: 25,
        });
        const trace = out(
          await bea.call("trace_execution", {
            session_id: session,
            thread_ids: [parked],
            mode: "block_counts",
            duration_ms: TRACE_MS,
            wait_ms: 0,
          }),
        );
        const recording = (trace["instrument"] as { recording_id: string }).recording_id;
        // the parked thread was blocked in the stub: its follow is deferred through a listener there
        expect(await p.stubHead(), "a listener on the stub the parked thread waits in").not.toBe(PLAIN_STUB_HEAD);
        const [attached, attachedDetail] = ratio(
          await p.rateAgentBusy(BUSY_WINDOW_MS),
          baselineBusy,
          "listener attached, agent busy",
        );
        // the window lay inside the attached phase (the parked thread has not re-entered the stub yet)
        expect(await p.stubHead(), "still attached after the measurement window").not.toBe(PLAIN_STUB_HEAD);
        expect(attached, attachedDetail).toBeGreaterThanOrEqual(MIN_RATE_ATTACHED_AGENT_BUSY);

        // the parked thread wakes up, re-enters the stub and is followed: the listener goes away while the trace runs
        await vi.waitFor(async () => expect(await p.stubHead()).toBe(PLAIN_STUB_HEAD), {
          timeout: PARK_MS + 1000,
          interval: 50,
        });
        const running = out(
          await bea.call("wait", { session_id: session, until: "done", ids: [recording], timeout_ms: 1 }),
        );
        expect(running["satisfied"], "the stub was restored before the trace ended").toBe(false);
        const [followed, followedDetail] = ratio(await p.rate(WINDOW_MS), baseline, "target followed");
        expect(followed, followedDetail).toBeGreaterThanOrEqual(MIN_RATE);

        const done = out(
          await bea.call("wait", {
            session_id: session,
            until: "done",
            ids: [recording],
            timeout_ms: TRACE_MS + 10_000,
          }),
        );
        expect(done["recordings"]).toEqual([
          expect.objectContaining({ recording_id: recording, state: "finished", end_reason: "duration" }),
        ]);
        // the parked thread's round after its follow ran under Stalker
        const parkedWork = base + BigInt(waiters.pe.exportRvas["parked_work"] ?? -1);
        expect(await blockHits(bea, recording, parkedWork), "parked_work traced").toBeGreaterThanOrEqual(1);

        // healthy after the stop: the workers run, the parked thread keeps its rounds, no wrong system call ran
        const [after, afterDetail] = ratio(await p.rate(WINDOW_MS), baseline, "after the trace");
        expect(after, afterDetail).toBeGreaterThanOrEqual(MIN_RATE);
        const rounds1 = await p.u64("g_parked_rounds");
        await vi.waitFor(async () => expect(await p.u64("g_parked_rounds")).toBeGreaterThan(rounds1), {
          timeout: PARK_MS + 3000,
          interval: 50,
        });
        expect(await p.u64("g_bad_syscalls")).toBe(0n);
        expect(await p.stubHead()).toBe(PLAIN_STUB_HEAD);
        expect(out(await bea.call("session_status", { session_id: session }))["state"]).toBe("running");
        out(await bea.call("close_session", { session_id: session }));
      } finally {
        await bea.close();
      }
    }, 120_000);
  },
);
