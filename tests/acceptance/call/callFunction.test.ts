import { spawn } from "node:child_process";

import type { CallToolResult } from "@modelcontextprotocol/client";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import type { GateId } from "../../../src/domain/gates.js";
import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
  type FixtureManifest,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger, pidStatus } from "../../support/process/ownedPidLedger.js";
import { buildFtzTarget, FTZ_TARGET_EXE, type BuiltTarget } from "./support/ftzTarget.js";

/**
 * call_function through the BUILT server (S6 §10.8 call_function row + the WP11 card; DESIGN §8.4 wave rule: only
 * spawn_process / resume_process / attach_process / close_session of earlier waves besides call_function itself —
 * target memory is read with call_function on ntdll!memcpy and thread ids come from kernel32!GetCurrentThreadId run at
 * a safe point, never from read_memory or list_threads). One built server per describe (≤ 3 spawned targets each,
 * S6 §10.7), sessions closed and the owned-PID ledger audited. Run with BEA_DIST_DIR from
 * `node scripts/snapshot-dist.mjs <id>`.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();
type Obj = Readonly<Record<string, unknown>>;

const f32 = (x: number): string => `0x${(new Uint32Array(new Float32Array([x]).buffer)[0] ?? 0).toString(16)}`;
const fromF32 = (bits: string): number =>
  new Float32Array(new Uint32Array([Number(BigInt(bits))]).buffer)[0] ?? Number.NaN;

interface Server {
  readonly bea: () => BeaConnection;
  readonly ok: (name: string, args: Obj) => Promise<Obj>;
  readonly call: (name: string, args: Obj) => Promise<CallToolResult>;
  readonly fixtures: () => FixtureManifest;
  readonly ledger: () => OwnedPidLedger;
  /** spawn_process + resume_process; the session is closed in afterAll */
  readonly start: (program: string, argv: readonly string[]) => Promise<string>;
}

/** One built server per describe; afterClose runs once the server (and so every owned target) is gone. */
const useServer = (
  options: { readonly gates?: Partial<Record<GateId, boolean>>; readonly afterClose?: () => Promise<void> } = {},
): Server => {
  let manifest: FixtureManifest | undefined;
  let bea: BeaConnection | undefined;
  let ledger: OwnedPidLedger | undefined;
  const sessions: string[] = [];
  const conn = (): BeaConnection => {
    if (bea === undefined) throw new Error("server not started");
    return bea;
  };
  const ok = async (name: string, args: Obj): Promise<Obj> => expectToolSuccess(await conn().call(name, args));

  beforeAll(async () => {
    const loaded = await loadFixtures();
    if ("unavailable" in loaded) throw new Error(loaded.unavailable);
    manifest = loaded;
    ledger = new OwnedPidLedger(fixtureArtifact(loaded, "pidcheck")?.path ?? null);
    bea = await connectBea({ ledger, ...(options.gates === undefined ? {} : { gates: options.gates }) });
  }, 60_000);

  afterAll(async () => {
    for (const id of sessions) await bea?.call("close_session", { session_id: id }).catch(() => undefined);
    await bea?.close();
    await options.afterClose?.();
    await ledger?.assertClean();
  }, 60_000);

  return {
    bea: conn,
    ok,
    call: (name, args) => conn().call(name, args),
    fixtures: () => {
      if (manifest === undefined) throw new Error("fixtures not loaded");
      return manifest;
    },
    ledger: () => {
      if (ledger === undefined) throw new Error("ledger not created");
      return ledger;
    },
    start: async (program, argv) => {
      const spawned = await ok("spawn_process", { program, args: [...argv] });
      const id = spawned["session_id"] as string;
      sessions.push(id);
      await ok("resume_process", { session_id: id });
      return id;
    },
  };
};

const artifact = (server: Server, id: "game_sim" | "pidcheck"): FixtureArtifact => {
  const found = fixtureArtifact(server.fixtures(), id);
  if (found === null) throw new Error(`fixture ${id} unavailable`);
  return found;
};

/** [address] as a pointer, read through call_function(ntdll!memcpy) into an out buffer (wave rule). */
const readPtr = async (server: Server, session: string, address: string): Promise<string> => {
  const out = await server.ok("call_function", {
    session_id: session,
    address: "ntdll.dll!memcpy",
    signature: { args: [{ type: "buffer_ptr", buffer: "out" }, { type: "ptr" }, { type: "u64" }], returns: "ptr" },
    buffers: [{ name: "out", size: 8, out: true, fields: [{ name: "p", offset: 0, type: "ptr" }] }],
    args: [null, address, 8],
  });
  return ((out["call"] as { outputs: Record<string, { value: string }> }).outputs["out.p"] as { value: string }).value;
};

/** `size` bytes at `address` as lowercase hex, read through call_function(ntdll!memcpy). */
const readHex = async (server: Server, session: string, address: string, size: number): Promise<string> => {
  const out = await server.ok("call_function", {
    session_id: session,
    address: "ntdll.dll!memcpy",
    signature: { args: [{ type: "buffer_ptr", buffer: "out" }, { type: "ptr" }, { type: "u64" }], returns: "ptr" },
    buffers: [{ name: "out", size, out: true }],
    args: [null, address, size],
  });
  return (out["call"] as { out_buffers: Record<string, { hex: string }> }).out_buffers["out"]?.hex ?? "";
};

/** game_sim's live Car: [[g_world]+8], once main() published g_world (polled at 25 ms, never slept on). */
const liveCar = async (server: Server, session: string): Promise<string> => {
  let world = "0x0";
  await vi.waitFor(
    async () => {
      world = await readPtr(server, session, "game_sim.exe!g_world");
      expect(world).not.toBe("0x0");
    },
    { timeout: 15_000, interval: 25 },
  );
  return readPtr(server, session, `0x${(BigInt(world) + 8n).toString(16)}`);
};

/** The id of the thread that reaches `safePoint`: GetCurrentThreadId run there in hook mode (thread_at). */
const threadAt = async (server: Server, session: string, safePoint: string): Promise<number> => {
  const out = await server.ok("call_function", {
    session_id: session,
    address: "kernel32.dll!GetCurrentThreadId",
    signature: { args: [], returns: "u32" },
    args: [],
    thread_at: safePoint,
  });
  return (out["call"] as { ret: { value: number } }).ret.value;
};

/** JS reference of game_sim.c physics_step: f32 fields, f32 SSE arithmetic (every input rounded to f32 first). */
const physicsRef = (
  car: { speed: number; throttle: number; steer: number; drag: number; posx: number; posz: number; temp: number },
  dt: number,
) => {
  const fr = Math.fround;
  const [speed, throttle, steer, drag, d] = [fr(car.speed), fr(car.throttle), fr(car.steer), fr(car.drag), fr(dt)];
  let accel = fr(fr(throttle * fr(8)) - fr(drag * speed));
  if (speed > 80) accel = -2;
  let v = fr(speed + fr(accel * d));
  if (v < 0) v = 0;
  const velx = fr(v * steer);
  return {
    v,
    rpm: fr(fr(v * 60) + 800),
    velx,
    posx: fr(fr(car.posx) + fr(velx * d)),
    posz: fr(fr(car.posz) + fr(v * d)),
    temp: fr(fr(car.temp) + fr(fr(v * fr(0.001)) * d)),
  };
};

/**
 * The bytes of game_sim's Car that stay fixed at the `--no-threads --speed 20 --throttle 0.125` equilibrium (steer 0):
 * everything but pos.z (+0x20) and odometer/frame (+0x30..+0x3C), which every frame advances.
 */
const stableCarBytes = (hex: string): string =>
  hex.slice(0, 0x20 * 2) + hex.slice(0x24 * 2, 0x30 * 2) + hex.slice(0x3c * 2);

describe.skipIf(skip !== false)(`call_function init_from on the live car (built server)${skipNote(skip)}`, () => {
  const server = useServer();
  const game = (): string => artifact(server, "game_sim").path;

  it("init_from <car> feeds identical bytes once: 20.0 exactly for every dt; only the copy changes, the game's car does not", async () => {
    const session = await server.start(game(), ["--no-threads", "--speed", "20", "--throttle", "0.125"]);
    const car = await liveCar(server, session);
    const live = await readHex(server, session, car, 128);
    expect(live.slice(0, 8)).toBe("43415231"); // 'CAR1'
    // a reader on the scratch copy leaves it as copied: the copy's bytes are the live struct's
    const copied = await server.ok("call_function", {
      session_id: session,
      address: "game_sim.exe!telemetry_sample",
      signature: { args: [{ type: "buffer_ptr", buffer: "car" }], returns: "f32" },
      buffers: [{ name: "car", size: 128, init_from: car, out: true }],
      args: [null],
    });
    const single = copied["call"] as { ret: { bits: string }; out_buffers: Record<string, { hex: string }> };
    expect(single.ret.bits).toBe(f32(72));
    expect(stableCarBytes(single.out_buffers["car"]?.hex ?? "")).toBe(stableCarBytes(live));
    const out = await server.ok("call_function", {
      session_id: session,
      address: "game_sim.exe!physics_step",
      signature: {
        args: [
          { type: "buffer_ptr", buffer: "car" },
          { type: "f32", name: "dt" },
        ],
        returns: "f32",
      },
      buffers: [
        { name: "car", size: 128, init_from: car, fields: [{ name: "speed", offset: 8, type: "f32" }], out: true },
      ],
      vectors: { columns: { dt: [1 / 60, 1 / 30, 0.1, 0.5, 1, "0x00000001"] } },
    });
    const batch = out["batch"] as { columns: Record<string, { bits: string[] }> };
    expect(batch.columns["ret"]?.bits).toEqual(Array.from({ length: 6 }, () => f32(20)));
    expect(batch.columns["car.speed"]?.bits).toEqual(Array.from({ length: 6 }, () => f32(20)));
    expect(out["effects_applied"]).toHaveLength(1);
    // away from the equilibrium (the copy's speed patched per vector): the copy moves, the game's car does not
    const moved = await server.ok("call_function", {
      session_id: session,
      address: "game_sim.exe!physics_step",
      signature: {
        args: [
          { type: "buffer_ptr", buffer: "car" },
          { type: "f32", name: "dt" },
        ],
        returns: "f32",
      },
      buffers: [
        { name: "car", size: 128, init_from: car, fields: [{ name: "speed", offset: 8, type: "f32" }], out: true },
      ],
      vectors: { columns: { dt: [0.5, 0.5], "car.speed": [50, 5] } },
    });
    const at = { throttle: 0.125, steer: 0, drag: 0.05, posx: 0, posz: 0, temp: 20 };
    expect((moved["batch"] as { columns: Record<string, { bits: string[] }> }).columns["ret"]?.bits).toEqual([
      f32(physicsRef({ ...at, speed: 50 }, 0.5).v),
      f32(physicsRef({ ...at, speed: 5 }, 0.5).v),
    ]);
    expect(stableCarBytes(await readHex(server, session, car, 128))).toBe(stableCarBytes(live));
    const speedNow = await server.ok("call_function", {
      session_id: session,
      address: "game_sim.exe!telemetry_sample",
      signature: { args: [{ type: "ptr" }], returns: "f32" },
      args: [car],
    });
    expect((speedNow["call"] as { ret: { bits: string } }).ret.bits).toBe(f32(72));
  });
});

describe.skipIf(skip !== false)(
  `call_function on game_sim scratch structs, faults and coverage (built server)${skipNote(skip)}`,
  () => {
    const server = useServer();
    const game = (): string => artifact(server, "game_sim").path;

    it("physics_step on a struct built from hex + fields (tyres via ptr_to) equals a JS Math.fround reference over 16 vectors", async () => {
      const session = await server.start(game(), ["--no-threads"]);
      const speeds = [0, 0.5, 1, 5, 10, 19.5, 20, 33.25, 50, 79.9, 80, 80.5, 100, 3e-5, 7, 64];
      const dt = 1 / 60;
      const out = await server.ok("call_function", {
        session_id: session,
        address: "game_sim.exe!physics_step",
        signature: {
          args: [
            { type: "buffer_ptr", buffer: "car" },
            { type: "f32", name: "dt", default: dt },
          ],
          returns: "f32",
        },
        buffers: [
          {
            name: "car",
            size: 128,
            init_hex: "43415231" + "07000000",
            out: true,
            fields: [
              { name: "speed", offset: 8, type: "f32" },
              { name: "throttle", offset: 12, type: "f32", default: "0.5" },
              { name: "steer", offset: 16, type: "f32", default: "0.25" },
              { name: "rpm", offset: 20, type: "f32" },
              { name: "pos", offset: 24, type: "f32[]", count: 3, default: "1, 0, 2" },
              { name: "velx", offset: 36, type: "f32" },
              { name: "odometer", offset: 48, type: "f64", default: "0" },
              { name: "frame", offset: 56, type: "u32", default: "41" },
              { name: "tyres", offset: 64, type: "ptr_to", buffer: "tyres" },
              { name: "mass", offset: 72, type: "f32", default: "1200" },
              { name: "drag", offset: 76, type: "f32", default: "0.05" },
            ],
          },
          {
            name: "tyres",
            size: 64,
            init_fill: 0,
            out: true,
            fields: [{ name: "temp0", offset: 4, type: "f32", default: "20" }],
          },
        ],
        vectors: { columns: { "car.speed": speeds } },
      });
      const columns = (out["batch"] as { columns: Record<string, { bits: (string | string[])[] }> }).columns;
      speeds.forEach((speed, i) => {
        const r = physicsRef({ speed, throttle: 0.5, steer: 0.25, drag: 0.05, posx: 1, posz: 2, temp: 20 }, dt);
        expect(columns["ret"]?.bits[i], `ret[${String(i)}]`).toBe(f32(r.v));
        expect(columns["car.rpm"]?.bits[i], `rpm[${String(i)}]`).toBe(f32(r.rpm));
        expect(columns["car.velx"]?.bits[i], `velx[${String(i)}]`).toBe(f32(r.velx));
        const pos = columns["car.pos"]?.bits[i] as string[] | undefined;
        expect(pos?.[0], `pos.x[${String(i)}]`).toBe(f32(r.posx));
        expect(pos?.[2], `pos.z[${String(i)}]`).toBe(f32(r.posz));
        expect(columns["car.frame"]?.bits[i]).toBe("0x2a");
        expect(fromF32(columns["tyres.temp0"]?.bits[i] as string), `tyre temp[${String(i)}]`).toBe(r.temp);
      });
    });

    it("mix_args = 15.375; a NULL pointer is a per-vector fault and the next call works; coverage gives blocks", async () => {
      const session = await server.start(game(), ["--no-threads"]);
      const mix = await server.ok("call_function", {
        session_id: session,
        address: "game_sim.exe!mix_args",
        signature: {
          args: [{ type: "i32" }, { type: "f32" }, { type: "f64" }, { type: "f32" }, { type: "i32" }, { type: "f64" }],
          returns: "f64",
        },
        args: [1, 1.5, 2.25, 3.125, 7, 0.5],
        coverage: true,
      });
      expect((mix["call"] as { ret: { value: number } }).ret.value).toBe(15.375);
      expect((mix["block_coverage"] as { blocks: number }).blocks).toBeGreaterThan(0);
      const fault = await server.ok("call_function", {
        session_id: session,
        address: "game_sim.exe!physics_step",
        signature: { args: [{ type: "ptr" }, { type: "f32" }], returns: "f32" },
        args: [0, 0.1],
      });
      expect(fault["call"]).toMatchObject({
        status: "fault",
        fault: { type: "access-violation", code: "0xc0000005", memory: { operation: "read" } },
      });
      const again = await server.ok("call_function", {
        session_id: session,
        address: "game_sim.exe!tiny_add",
        signature: { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" },
        args: [2, 3],
      });
      expect((again["call"] as { ret: { value: number } }).ret.value).toBe(5);
    });
  },
);

describe.skipIf(skip !== false)(
  `call_function batch delivery on the real stack (built server)${skipNote(skip)}`,
  () => {
    const server = useServer();
    const TINY = { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" };

    it("a batch above inline_limit becomes a call-batch row stream; a deadline ends it with a vector_offset continuation", async () => {
      const session = await server.start(artifact(server, "game_sim").path, ["--no-threads"]);
      const n = 100;
      const streamed = await server.ok("call_function", {
        session_id: session,
        address: "game_sim.exe!tiny_add",
        signature: TINY,
        vectors: {
          columns: { arg0: Array.from({ length: n }, (_, i) => i), arg1: Array.from({ length: n }, () => 1000) },
        },
      });
      const batch = streamed["batch"] as {
        completed: number;
        columns: unknown;
        stream_id: string | null;
        continuation: unknown;
        preview: { first: { i: number; s: string; r: string }[]; last: { i: number; s: string; r: string }[] };
      };
      expect(batch).toMatchObject({ completed: n, columns: null, continuation: null });
      expect(batch.stream_id).toMatch(/^st_[0-9a-f]{64}$/u);
      expect(batch.preview.first[0]).toMatchObject({ i: 0, s: "returned", r: "0x3e8" });
      expect(batch.preview.last.at(-1)).toMatchObject({ i: n - 1, s: "returned", r: "0x44b" });
      // a budget too short for 20,000 generated vectors: one chunk runs, the rest continues with vector_offset
      const generate = {
        seed: 7,
        count: 20_000,
        columns: { arg0: { dist: "uniform", min: 0, max: 1000 }, arg1: { dist: "constant", value: "1" } },
      };
      const first = (
        await server.ok("call_function", {
          session_id: session,
          address: "game_sim.exe!tiny_add",
          signature: TINY,
          generate,
          timeout_ms: 1000,
        })
      )["batch"] as { offset: number; completed: number; continuation: { vector_offset: number } | null };
      expect(first.offset).toBe(0);
      expect(first.completed).toBeGreaterThan(0);
      expect(first.continuation?.vector_offset).toBe(first.completed);
      expect(first.completed).toBeLessThan(20_000);
      const next = (
        await server.ok("call_function", {
          session_id: session,
          address: "game_sim.exe!tiny_add",
          signature: TINY,
          generate,
          timeout_ms: 1000,
          vector_offset: first.completed,
        })
      )["batch"] as { offset: number; completed: number };
      expect(next.offset).toBe(first.completed);
      expect(next.completed).toBeGreaterThan(0);
    });
  },
);

describe.skipIf(skip !== false)(`call_function on target threads (built server)${skipNote(skip)}`, () => {
  const server = useServer();
  const game = (): string => artifact(server, "game_sim").path;
  const TINY = { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" };

  it("thread_at runs at the game's safe point; thread_id on the main thread sleeping in a system call is invalid_state", async () => {
    // --hz 1: one frame per second, so the main thread spends all but microseconds in Sleep (NtDelayExecution)
    const session = await server.start(game(), ["--no-threads", "--hz", "1"]);
    const main = await threadAt(server, session, "game_sim.exe!mix_args");
    const atSafePoint = await server.ok("call_function", {
      session_id: session,
      address: "game_sim.exe!tiny_add",
      signature: TINY,
      args: [20, 22],
      thread_at: "game_sim.exe!mix_args",
      thread_id: main,
      hooks: "observe",
    });
    expect((atSafePoint["call"] as { ret: { value: number } }).ret.value).toBe(42);
    // fp auto with a known thread reads that thread's environment (status bits cleared)
    expect(atSafePoint["fp"]).toMatchObject({ source: "thread", mxcsr: "0x1f80" });
    // a sample can only miss the wait in the microseconds of a frame: then the call simply runs (a retry is fair)
    let refused: ReturnType<typeof parseToolError> | null = null;
    for (let attempt = 0; attempt < 3 && refused === null; attempt++) {
      const result = await server.call("call_function", {
        session_id: session,
        address: "game_sim.exe!tiny_add",
        signature: TINY,
        args: [2, 3],
        thread_id: main,
      });
      if (result.isError === true) refused = parseToolError(result);
    }
    expect(refused).toMatchObject({
      code: "invalid_state",
      details: { state: "thread-in-syscall", expected: ["thread-running-user-code"] },
    });
  });

  it("thread_id:<main> runs the call on the game's busy main thread (fp auto reads its environment)", async () => {
    // --hz 0 --hot: the main loop never sleeps; it enters the kernel only for its occasional FRAME line
    const session = await server.start(game(), ["--no-threads", "--hz", "0", "--hot", "300000"]);
    const main = await threadAt(server, session, "game_sim.exe!mix_args");
    let ran: Obj | null = null;
    for (let attempt = 0; attempt < 10 && ran === null; attempt++) {
      const result = await server.call("call_function", {
        session_id: session,
        address: "game_sim.exe!tiny_add",
        signature: TINY,
        args: [2, 3],
        thread_id: main,
      });
      if (result.isError !== true) ran = expectToolSuccess(result);
      // the only acceptable refusal: the sample caught the thread inside its WriteFile
      else
        expect(parseToolError(result)).toMatchObject({
          code: "invalid_state",
          details: { state: "thread-in-syscall" },
        });
    }
    expect((ran?.["call"] as { ret: { value: number } } | undefined)?.ret.value).toBe(5);
    expect(ran?.["fp"]).toMatchObject({ source: "thread", mxcsr: "0x1f80" });
  });
});

describe.skipIf(skip !== false)(
  `call_function on an attached target and the call_attached gate${skipNote(skip)}`,
  () => {
    let manifest: FixtureManifest | null = null;
    beforeAll(async () => {
      const loaded = await loadFixtures();
      if ("unavailable" in loaded) throw new Error(loaded.unavailable);
      manifest = loaded;
    });

    it("an attached target needs the call_attached gate (refused before any agent RPC), works with it and survives", async () => {
      const game = manifest === null ? null : fixtureArtifact(manifest, "game_sim");
      const pidcheck = manifest === null ? null : (fixtureArtifact(manifest, "pidcheck")?.path ?? null);
      if (game === null) throw new Error("fixtures unavailable");
      // a test-spawned attach target (never BEA-owned), killed by this test
      const target = spawn(game.path, ["--no-threads"], { stdio: "ignore", windowsHide: true });
      try {
        const pid = target.pid ?? 0;
        for (const gates of [{}, { call_attached: true }]) {
          const server = await connectBea({ gates });
          try {
            const attached = expectToolSuccess(await server.call("attach_process", { pid }));
            const result = await server.call("call_function", {
              session_id: attached["session_id"],
              address: "game_sim.exe!tiny_add",
              signature: { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" },
              args: [1, 2],
            });
            if ("call_attached" in gates) {
              const called = expectToolSuccess(result);
              expect((called["call"] as { ret: { value: number } }).ret.value).toBe(3);
              expect(called["effects_applied"]).toHaveLength(1);
            } else {
              const refused = parseToolError(result);
              expect(refused.code).toBe("capability_unavailable");
              expect(refused.details).toMatchObject({ gate: "call_attached" });
              // nothing ran: no function-called effect was registered (the boundary spy proves no agent RPC at all)
              expect(refused.details["effects_applied"]).toEqual([]);
            }
            expectToolSuccess(await server.call("close_session", { session_id: attached["session_id"] }));
          } finally {
            await server.close();
          }
          // BEA never kills an attached process
          expect(pidStatus(pidcheck, pid).alive).toBe(true);
        }
      } finally {
        target.kill();
      }
    });
  },
);

describe.skipIf(skip !== false)(`call_function timeouts (built server)${skipNote(skip)}`, () => {
  const server = useServer();

  it("a callee that never returns ends in provider_timeout and close_session still kills the owned target", async () => {
    const session = await server.start(artifact(server, "game_sim").path, ["--no-threads", "--load-mathlib-at", "1"]);
    const LERP = { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" };
    // mathlib.dll is loaded by frame 1: poll (25 ms) until its export resolves and runs
    await vi.waitFor(
      async () => {
        const lerp = await server.ok("call_function", {
          session_id: session,
          address: "mathlib.dll!mf_lerp",
          signature: LERP,
          args: [0, 10, 0.25],
        });
        expect((lerp["call"] as { ret: { value: number } }).ret.value).toBe(2.5);
      },
      { timeout: 15_000, interval: 25 },
    );
    const timedOut = parseToolError(
      await server.call("call_function", {
        session_id: session,
        address: "mathlib.dll!mf_spin",
        signature: { args: [{ type: "i32" }], returns: "i32" },
        args: [1],
        timeout_ms: 2000,
      }),
    );
    expect(timedOut.code).toBe("provider_timeout");
    expect(timedOut.details["effects_applied"]).toHaveLength(1);
    // the agent's JS thread is still inside mf_spin: the session is wedged and later calls time out too
    const wedged = parseToolError(
      await server.call("call_function", {
        session_id: session,
        address: "game_sim.exe!tiny_add",
        signature: { args: [{ type: "i32" }, { type: "i32" }], returns: "i32" },
        args: [2, 3],
        timeout_ms: 1000,
      }),
    );
    expect(wedged.code).toBe("provider_timeout");
    const closed = await server.ok("close_session", { session_id: session });
    expect(closed).toMatchObject({ target_state: "killed" });
  });
});

describe.skipIf(skip !== false)(
  `call_function FP environment of a target thread (built server)${skipNote(skip)}`,
  () => {
    let target: BuiltTarget | null = null;
    const server = useServer({ afterClose: async () => target?.cleanup() });
    beforeAll(async () => {
      target = await buildFtzTarget();
    }, 120_000);

    it('fp.source "thread" on a thread running with MXCSR 0x9FC0 reproduces the FTZ/DAZ result; the default does not', async () => {
      if (target === null) throw new Error("target not built");
      const session = await server.start(target.path, []);
      const main = await threadAt(server, session, `${FTZ_TARGET_EXE}!ftz_tick`);
      const four = {
        session_id: session,
        address: `${FTZ_TARGET_EXE}!four_floats`,
        signature: { args: [{ type: "f32" }, { type: "f32" }, { type: "f32" }, { type: "f32" }], returns: "f32" },
        // S5 §9.6 denormal vector: 0x03480020 under round-to-nearest, 0x0 when inputs and results flush to zero
        args: ["0x00000001", "0x00400000", "0x00000003", "0x00000005"],
      };
      const byThread = await server.ok("call_function", { ...four, fp: { source: "thread", thread_id: main } });
      expect(byThread["fp"]).toMatchObject({ source: "thread", mxcsr: "0x9fc0" });
      expect((byThread["call"] as { ret: { bits: string } }).ret.bits).toBe("0x0");
      const byDefault = await server.ok("call_function", four);
      expect(byDefault["fp"]).toEqual({ source: "windows-default", mxcsr: "0x1f80", fpcw: "0x27f" });
      expect((byDefault["call"] as { ret: { bits: string } }).ret.bits).toBe("0x3480020");
      // auto + the call's own thread at its safe point: that thread's environment again
      const atSafePoint = await server.ok("call_function", {
        ...four,
        thread_at: `${FTZ_TARGET_EXE}!ftz_tick`,
        thread_id: main,
      });
      expect(atSafePoint["fp"]).toMatchObject({ source: "thread", mxcsr: "0x9fc0" });
      expect((atSafePoint["call"] as { ret: { bits: string } }).ret.bits).toBe("0x0");
    });
  },
);
