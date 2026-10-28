import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { buildHookPlan } from "../../../src/application/handlers/instrument.js";
import { INSTRUMENT_TOOLS } from "../../../src/contracts/areas/instrument.js";
import type { HookDecoders } from "../../../src/application/instruments/kinds/hook.js";
import type { HookInstallParams, HookInstallResult } from "../../../src/shared/agentProtocol.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import {
  buildRawHookAgent,
  decodeStream,
  shutdownRawFrida,
  startRawTarget,
  until,
  useLivenessProbe,
  type RawTarget,
} from "./support/rawHookAgent.js";

/**
 * WP7 raw-agent acceptance (DESIGN §8.4 wave rule: raw agent RPCs only). The hook engine (JS tier + native tier) runs
 * in game_sim through its standalone core link; params come from the production host mapping (buildHookPlan) and rows
 * are decoded by the production hook kind. S6 §10.8 hook_function rows, the native ≥ 1 M events/s row, and the
 * moved "hook installed before resume sees frame 0" row (raw form).
 */
const skip = fridaSkip() !== false ? fridaSkip() : gccSkip();
const note = skipNote(skip);
const hookTool = INSTRUMENT_TOOLS[0];
const SID = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";

let bundle = "";
let gameSim: FixtureArtifact | null = null;
const targets: RawTarget[] = [];
beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  gameSim = fixtureArtifact(manifest, "game_sim");
  useLivenessProbe(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
  bundle = await buildRawHookAgent();
}, 120_000);
/** Close every target this test started (bounded: a stuck detach must not hang the file). */
const closeAll = async (): Promise<void> => {
  for (const t of targets.splice(0)) await Promise.race([t.close(), new Promise<void>((r) => setTimeout(r, 10_000))]);
};
afterEach(closeAll, 60_000);
afterAll(async () => {
  await closeAll();
  await shutdownRawFrida(); // after every target is gone: Frida then removes its %TEMP%\frida-<id> agent copy
}, 60_000);

const start = async (args: readonly string[], opts: { paused?: boolean } = {}): Promise<RawTarget> => {
  if (gameSim === null) throw new Error("game_sim fixture unavailable");
  const t = await startRawTarget(bundle, [gameSim.path, ...args], opts);
  targets.push(t);
  return t;
};
/** Tool input → agent params + decoders, exactly as hook_function builds them. */
const plan = (va: string, input: Record<string, unknown>, paused = false) =>
  buildHookPlan(hookTool.inputSchema.parse({ session_id: SID, address: va, ...input }), BigInt(va), paused);
const install = async (t: RawTarget, params: HookInstallParams): Promise<HookInstallResult> => {
  const r = (await t.rpc("hookInstall", params)) as { ok: boolean; value?: HookInstallResult; error?: unknown };
  if (!r.ok || r.value === undefined) throw new Error(`hookInstall failed: ${JSON.stringify(r.error)}`);
  return r.value;
};
const stopped = async (t: RawTarget, id: string): Promise<Record<string, unknown>> => {
  const summary = (await t.rpc("stop", id)) as Record<string, unknown>;
  expect(await until(() => t.ended.has(id), 5000)).toBe(true);
  return summary;
};
const exportVa = async (t: RawTarget, name: string): Promise<string> =>
  (await t.rpc("exportVa", "game_sim.exe", name)) as string;
const events = (t: RawTarget, r: HookInstallResult, d: HookDecoders) => decodeStream(t.batches, r.stream_id, d);

describe.skipIf(skip !== false)(`hook engine in game_sim (raw agent)${note}`, () => {
  it("physics_step: dt from xmm1 is exactly 1/60 f32, speed deref before/after, ret == speed@leave, car == READY car", async () => {
    const t = await start([]);
    expect(await until(() => t.stdout().includes("READY"), 10_000)).toBe(true);
    const car = /car=([0-9A-Fa-f]+)/u.exec(t.stdout())?.[1];
    const va = await exportVa(t, "physics_step");
    const { params, decoders } = plan(va, {
      capture: [
        { name: "car", arg: 0, type: "ptr" },
        { name: "dt", arg: 1, type: "f32" },
        { name: "speed", arg: 0, type: "f32", deref: [8], when: "both" },
        { name: "frame", arg: 0, type: "u32", deref: [0x38] },
      ],
      returns: "f32",
      backtrace: 4,
      duration_ms: 60_000,
    });
    const r = await install(t, params);
    expect(r).toMatchObject({ row_kind: "hook/1", relocation: "default", thunk: null });
    expect(r.effect.before[0]?.hex.length).toBeGreaterThanOrEqual(64); // ≥ 32 original bytes
    expect(await until(() => events(t, r, decoders).length >= 10, 10_000)).toBe(true);
    const evs = events(t, r, decoders);
    for (const e of evs) {
      expect(e["dt:bits"]).toBe("0x3c888889");
      expect(e["ret:bits"]).toBe(e["speed@leave:bits"]);
      expect(BigInt(String(e["car"]))).toBe(BigInt(`0x${car ?? "0"}`));
      expect(typeof e["dur_us"]).toBe("number");
      expect(Array.isArray(e["bt"])).toBe(true);
      expect(String((e["bt"] as string[])[0])).toMatch(/^game_sim\.exe\+0x/u);
    }
    const frames = evs.map((e) => e["frame"] as number);
    expect(frames.every((f, i) => i === 0 || f === (frames[i - 1] ?? 0) + 1)).toBe(true);
    const summary = await stopped(t, r.instrument_id);
    expect(summary).toMatchObject({
      end_reason: "requested",
      reverted: true,
      verification: { kind: "bytes", ok: true },
    });
    expect(t.batches.filter((b) => b.stream === r.stream_id).at(-1)?.final).toBe(true);
  }, 60_000);

  it("mix_args: stack floats and ints exact; tiny_add needs forced relocation and returns a+b", async () => {
    const t = await start(["--no-threads"]);
    const mix = plan(await exportVa(t, "mix_args"), {
      capture: [
        { name: "a", arg: 0, type: "i32" },
        { name: "b", arg: 1, type: "f32" },
        { name: "c", arg: 2, type: "f64" },
        { name: "d", arg: 3, type: "f32" },
        { name: "e", arg: 4, type: "i32" },
        { name: "f", arg: 5, type: "f64" },
      ],
      returns: "f64",
    });
    const tiny = plan(await exportVa(t, "tiny_add"), {
      capture: [
        { name: "a", arg: 0, type: "i32" },
        { name: "b", arg: 1, type: "i32" },
      ],
      returns: "i32",
    });
    const rm = await install(t, mix.params);
    const rt = await install(t, tiny.params);
    expect(rt.relocation).toBe("forced");
    expect(
      await until(() => events(t, rm, mix.decoders).length >= 5 && events(t, rt, tiny.decoders).length >= 5, 10_000),
    ).toBe(true);
    for (const e of events(t, rm, mix.decoders)) {
      expect([e["b"], e["c"], e["d"], e["e"], e["f"]]).toEqual([1.5, 2.25, 3.125, 7, 0.5]);
      expect(e["ret"]).toBe((e["a"] as number) + 1.5 + 2.25 + 3.125 + 7 + 0.5);
    }
    for (const e of events(t, rt, tiny.decoders)) expect(e["ret"]).toBe((e["a"] as number) + (e["b"] as number));
    const before = (await t.rpc("read", rt.patched_at[0], 4)) as string;
    expect(before.startsWith("e9") || before.startsWith("ff25")).toBe(true);
    await stopped(t, rm.instrument_id);
    const s = await stopped(t, rt.instrument_id);
    expect(s).toMatchObject({ reverted: true });
    expect(((await t.rpc("read", rt.patched_at[0], 8)) as string).slice(0, 8)).toBe(
      rt.effect.before[0]?.hex.slice(0, 8),
    );
  }, 60_000);

  it("a probe at the speed writer captures rax == the READY car; max_events ends the hook with exactly 50 rows", async () => {
    const t = await start(["--no-threads"]);
    expect(await until(() => t.stdout().includes("READY"), 10_000)).toBe(true);
    const car = BigInt(`0x${/car=([0-9A-Fa-f]+)/u.exec(t.stdout())?.[1] ?? "0"}`);
    const writers = gameSim?.expectations["speedWriters"] as { rva: number; base: string }[] | undefined;
    const writer = writers?.[0];
    const base = BigInt((await t.rpc("mainBase")) as string);
    const probeVa = `0x${(base + BigInt(writer?.rva ?? 0)).toString(16)}`;
    const p = plan(probeVa, { probe: true, capture: [{ name: "base", reg: writer?.base ?? "rax", type: "ptr" }] });
    const rp = await install(t, p.params);
    const capped = plan(await exportVa(t, "physics_step"), { capture: [{ arg: 1, type: "f32" }], max_events: 50 });
    const rc = await install(t, capped.params);
    expect(await until(() => t.ended.has(rc.instrument_id), 15_000)).toBe(true);
    expect(t.ended.get(rc.instrument_id)).toMatchObject({ end_reason: "max_hits", reverted: true });
    expect(events(t, rc, capped.decoders)).toHaveLength(50);
    const probes = events(t, rp, p.decoders);
    expect(probes.length).toBeGreaterThan(0);
    for (const e of probes) expect(BigInt(String(e["base"]))).toBe(car);
    await stopped(t, rp.instrument_id);
  }, 60_000);
});

describe.skipIf(skip !== false)(`hook engine safety, multiplexing and native tier (raw agent)${note}`, () => {
  it("multiplexes two hooks on one address and keeps the shared patch until the last one stops", async () => {
    const t = await start(["--no-threads"]);
    const va = await exportVa(t, "physics_step");
    const one = plan(va, { capture: [{ name: "dt", arg: 1, type: "f32" }] });
    const two = plan(va, { capture: [{ name: "car", arg: 0, type: "ptr" }] });
    const r1 = await install(t, one.params);
    const r2 = await install(t, two.params);
    expect(
      await until(() => events(t, r1, one.decoders).length >= 3 && events(t, r2, two.decoders).length >= 3, 10_000),
    ).toBe(true);
    const s1 = await stopped(t, r1.instrument_id);
    expect(s1).toMatchObject({
      reverted: true,
      verification: { detail: "listener kept for other instruments at this address" },
    });
    const after = events(t, r2, two.decoders).length;
    expect(await until(() => events(t, r2, two.decoders).length > after + 2, 10_000)).toBe(true);
    const s2 = await stopped(t, r2.instrument_id);
    expect(s2).toMatchObject({ reverted: true, verification: { ok: true, detail: "original bytes restored" } });
  }, 60_000);

  it("refuses the deny-listed NtAllocateVirtualMemory (and its kernel32 thunk path) with HookDenied", async () => {
    const t = await start(["--no-threads"]);
    const va = (await t.rpc("exportVa", "ntdll.dll", "NtAllocateVirtualMemory")) as string;
    const r = (await t.rpc("hookInstall", plan(va, {}).params)) as { ok: boolean; error?: Record<string, unknown> };
    expect(r.ok).toBe(false);
    expect(r.error).toMatchObject({
      _tag: "HookDenied",
      reason: "deadlock-risk",
      api: "ntdll.dll!NtAllocateVirtualMemory",
    });
    const k32 = (await t.rpc("exportVa", "kernel32.dll", "VirtualAlloc")) as string;
    const r2 = (await t.rpc("hookInstall", plan(k32, {}).params)) as { ok: boolean; error?: Record<string, unknown> };
    expect(r2.ok).toBe(false);
    expect(r2.error).toMatchObject({ _tag: "HookDenied", api: "kernelbase.dll!VirtualAlloc" });
  }, 60_000);

  it("a hook installed before resume sees frame 0 (raw form of the moved resume_process row)", async () => {
    const t = await start(["--no-threads"], { paused: true });
    const p = plan(
      await exportVa(t, "physics_step"),
      { capture: [{ name: "frame", arg: 0, type: "u32", deref: [0x38] }] },
      true,
    );
    const r = await install(t, p.params);
    await t.resume();
    expect(await until(() => events(t, r, p.decoders).length >= 1, 10_000)).toBe(true);
    expect(events(t, r, p.decoders)[0]?.["frame"]).toBe(0);
  }, 60_000);

  it("native tier: hot_hash at >= 1M events/s for 5 s with zero torn records and exact values", async () => {
    const t = await start(["--no-threads", "--hz", "0", "--hot", "20000"]);
    expect((await t.rpc("features")) as string[]).toEqual(
      expect.arrayContaining(["hooks.js", "hooks.native", "hooks.native.xmm"]),
    );
    await t.rpc("setLimits", { native_ring_records: 262_144 });
    const p = plan(await exportVa(t, "hot_hash"), {
      engine: "native",
      capture: [{ name: "x", arg: 0, type: "u32" }],
      returns: "u32",
      max_events: 10_000_000,
      duration_ms: 60_000,
    });
    const r = await install(t, p.params);
    expect(r.row_kind).toBe("hook-native/1");
    const count = (): number => t.batches.filter((b) => b.stream === r.stream_id).reduce((n, b) => n + b.n, 0);
    await until(() => count() > 100_000, 10_000);
    const n0 = count();
    const t0 = performance.now();
    await new Promise((res) => setTimeout(res, 5000)); // a fixed measurement window, not synchronization
    const n1 = count();
    const rate = ((n1 - n0) * 1000) / (performance.now() - t0);
    const summary = await stopped(t, r.instrument_id);
    const dropped = t.batches
      .filter((b) => b.stream === r.stream_id)
      .reduce(
        (acc, b) => {
          for (const [k, v] of Object.entries(b.dropped)) acc[k] = (acc[k] ?? 0) + v;
          return acc;
        },
        {} as Record<string, number>,
      );
    // eslint-disable-next-line no-console -- the measured rate is part of the acceptance record
    console.log(
      `native tier: ${Math.round(rate)} events/s delivered; dropped ${JSON.stringify(dropped)}; summary counters ${JSON.stringify(summary["counters"])}`,
    );
    expect(dropped["torn_record"] ?? 0).toBe(0);
    expect(rate).toBeGreaterThanOrEqual(1_000_000);
    const sample = decodeStream(t.batches.filter((b) => b.stream === r.stream_id).slice(0, 2), r.stream_id, p.decoders);
    expect(sample.length).toBeGreaterThan(100);
    for (const e of sample)
      expect(e["ret"]).toBe(Number((BigInt(e["x"] as number) * 2654435761n) & 0xffffffffn) >>> 16);
  }, 90_000);
});
