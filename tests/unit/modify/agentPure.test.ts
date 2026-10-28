import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { ApplicationGate, planOverride, stackArgOffset } from "../../../src/agent/pure/modifyOverride.js";
import { bindModifySeam, LocalIds } from "../../../src/agent/pure/modifySeam.js";
import {
  bitsToFloat,
  bytesToBits,
  cellOf,
  floatToBits,
  fromHexBytes,
  nativeTypeOf,
  replaceLowLane,
  scalarBits,
  toHexBytes,
  typedBytes,
} from "../../../src/agent/pure/modifyValues.js";
import {
  dataWriteMethod,
  pagesOf,
  sameBytes,
  WriteRegistry,
  writeBytesOf,
} from "../../../src/agent/pure/modifyWrites.js";
import { AGENT_LIMIT_DEFAULTS } from "../../../src/shared/agentLimits.js";
import type { OverrideInstallParams, WriteMemoryParams } from "../../../src/shared/agentProtocol.js";

const LIMITS = {
  max_duration_ms: AGENT_LIMIT_DEFAULTS.max_duration_ms,
  max_hits_cap: AGENT_LIMIT_DEFAULTS.max_hits_cap,
};
const lifetime = { duration_ms: 2000, max_hits: 5 };

describe("agent value helpers", () => {
  it("encodes typed writes and refuses strings", () => {
    const typed = typedBytes("f32", [1, { bits: "0x40000000" }]);
    expect(typed.ok && toHexBytes(typed.bytes)).toBe("0000803f00000040");
    expect(typedBytes("utf8", ["x"]).ok).toBe(false);
    expect(typedBytes("i32", []).ok).toBe(false);
    expect(typedBytes("u8", [256]).ok).toBe(false);
  });

  it("keeps float bit patterns exact", () => {
    expect(floatToBits(1, 4)).toBe(0x3f800000n);
    expect(Object.is(bitsToFloat(0x80000000n, 4), -0)).toBe(true);
    expect(bitsToFloat(floatToBits(42.5, 8), 8)).toBe(42.5);
    expect(scalarBits("f32", "Infinity")).toEqual({ ok: true, bits: 0x7f800000n });
    expect(scalarBits("f64", "x").ok).toBe(false);
  });

  it("renders original values as cells (S4 §4.6)", () => {
    expect(cellOf("i32", 0xffffffffn)).toBe(-1);
    expect(cellOf("u32", 0xffffffffn)).toBe(4294967295);
    expect(cellOf("i8", 0x1ff80n)).toBe(-128);
    expect(cellOf("bool8", 1n)).toBe(1);
    expect(cellOf("f32", 0x41a00000n)).toBe("0x41a00000");
    expect(cellOf("u64", 0x1_0000_0000n)).toBe("0x100000000");
    expect(cellOf("ptr", 0x7ff6_1234_0000n)).toBe("0x7ff612340000");
  });

  it("replaces only the low lane of an XMM image", () => {
    const current = new Uint8Array(16).map((_v, i) => i + 1);
    const f32 = replaceLowLane(current, 0x3f800000n, 4);
    expect(toHexBytes(f32)).toBe("0000803f05060708090a0b0c0d0e0f10");
    const f64 = replaceLowLane(current, 0n, 8);
    expect(toHexBytes(f64.subarray(8))).toBe("090a0b0c0d0e0f10");
    expect(toHexBytes(current)).toBe("0102030405060708090a0b0c0d0e0f10"); // input untouched
  });

  it("maps return types to NativeCallback types (bool is one byte)", () => {
    expect(nativeTypeOf("bool8")).toBe("uint8");
    expect(nativeTypeOf("f32")).toBe("float");
    expect(nativeTypeOf("ptr")).toBe("pointer");
    expect(nativeTypeOf("void")).toBe("void");
  });

  it("round-trips hex and bits", () => {
    expect(fromHexBytes("zz")).toBeNull();
    expect(bytesToBits(fromHexBytes("0100") ?? new Uint8Array())).toBe(1n);
  });
});

describe("gated write planning (S4 §8.3)", () => {
  const base: WriteMemoryParams = { address: "0x1000", mode: "data", bytes: "0102", allow_protect_change: true };

  it("validates params structurally", () => {
    expect(writeBytesOf(base, 64)).toMatchObject({ ok: true, address: 0x1000n });
    const both = writeBytesOf({ ...base, typed: { type: "u8", values: [1] } }, 64);
    expect(both.ok).toBe(false);
    const big = writeBytesOf({ ...base, bytes: "00".repeat(65) }, 64);
    expect(big.ok || big.issues.map((i) => i.path)).toEqual(["bytes"]);
    const odd = writeBytesOf({ ...base, address: "0x0" }, 64);
    expect(odd.ok || odd.issues[0]?.path).toBe("address");
    const cas = writeBytesOf({ ...base, expect_before: "00" }, 64);
    expect(cas.ok || cas.issues[0]?.path).toBe("expect_before");
    const { bytes: _bytes, ...rest } = base;
    void _bytes;
    const typed = writeBytesOf({ ...rest, typed: { type: "i16", values: [-2] } }, 64);
    expect(typed.ok && toHexBytes(typed.bytes)).toBe("feff");
  });

  it("picks direct, protect-and-restore or refuses", () => {
    expect(dataWriteMethod(["rw-", "rwx"], false)).toBe("direct");
    expect(dataWriteMethod(["rw-", "r--"], true)).toBe("protect-and-restore");
    expect(dataWriteMethod(["r--"], false)).toBe("refuse");
    expect(dataWriteMethod([], true)).toBe("protect-and-restore");
  });

  it("covers every page a write touches", () => {
    expect(pagesOf(0x1ffen, 4, 0x1000)).toEqual([0x1000n, 0x2000n]);
    expect(pagesOf(0x1000n, 1, 0x1000)).toEqual([0x1000n]);
  });

  it("tracks writes, refuses overlaps and never reuses ids", () => {
    const registry = new WriteRegistry();
    const a = registry.allocate();
    const b = registry.allocate();
    expect([a, b]).toEqual(["wr1", "wr2"]);
    registry.add({
      id: a,
      address: 0x100n,
      size: 4,
      before: new Uint8Array(4),
      after: new Uint8Array(4),
      mode: "data",
    });
    expect(registry.overlapping(0x103n, 1)?.id).toBe(a);
    expect(registry.overlapping(0x104n, 4)).toBeUndefined();
    expect(registry.overlapping(0xfcn, 4)).toBeUndefined();
    registry.add({
      id: b,
      address: 0x200n,
      size: 1,
      before: new Uint8Array(1),
      after: new Uint8Array(1),
      mode: "code",
    });
    expect(registry.all().map((r) => r.id)).toEqual([b, a]);
    registry.delete(a);
    expect(registry.size).toBe(1);
    expect(registry.allocate()).toBe("wr3");
    expect(sameBytes(new Uint8Array([1]), new Uint8Array([1]))).toBe(true);
  });
});

describe("override planning (S4 §14)", () => {
  const rewrite = (args: NonNullable<OverrideInstallParams["rewrite"]>): OverrideInstallParams => ({
    target: { va: "0x1000" },
    relocation: "auto",
    mode: "rewrite",
    rewrite: args,
    lifetime,
    record: true,
  });

  it("places int, xmm and stack-float arguments per the Win64 ABI", () => {
    const planned = planOverride(
      rewrite({
        args: [
          { slot: 0, class: "int", type: "i32", value: -1 },
          { slot: 1, class: "float", type: "f32", value: 0 },
          { slot: 5, class: "float", type: "f64", value: { bits: "0x3ff0000000000000" } },
        ],
      }),
      LIMITS,
    );
    if (!planned.ok) throw new Error(JSON.stringify(planned.issues));
    expect(planned.plan.args.map((a) => [a.slot, a.location, a.bits])).toEqual([
      [0, "int", 0xffffffffn],
      [1, "xmm", 0n],
      [5, "stack", 0x3ff0000000000000n],
    ]);
    expect(stackArgOffset(5)).toBe(48);
    expect(planned.plan.clock).toBe("install");
  });

  it("plans return rewrites and constant replacements", () => {
    const ret = planOverride(rewrite({ ret: { type: "f32", value: { bits: "0x42f60000" } } }), LIMITS);
    expect(ret.ok && ret.plan.ret).toEqual({ type: "f32", float: true, width: 4, bits: 0x42f60000n });
    const replace = planOverride(
      {
        target: { va: "0x1000" },
        relocation: "forced",
        mode: "replace",
        replace: { ret_type: "i32", arg_types: [], returns: "0x2a" },
        lifetime: { duration_ms: 0, max_hits: 0, clock: "resume" },
        record: false,
      },
      LIMITS,
    );
    if (!replace.ok) throw new Error(JSON.stringify(replace.issues));
    expect(replace.plan.replace).toEqual({ retType: "i32", bits: 42n });
    expect([replace.plan.durationMs, replace.plan.maxHits, replace.plan.clock]).toEqual([30_000, 10_000, "resume"]);
  });

  it("refuses inconsistent requests with issue paths", () => {
    const paths = (p: OverrideInstallParams): string[] => {
      const planned = planOverride(p, LIMITS);
      return planned.ok ? [] : planned.issues.map((i) => i.path);
    };
    expect(paths(rewrite({}))).toEqual(["rewrite"]);
    expect(
      paths(
        rewrite({
          args: [
            { slot: 1, class: "int", type: "f32", value: 0 },
            { slot: 1, class: "int", type: "i32", value: 0 },
          ],
        }),
      ),
    ).toEqual(["rewrite.args[0]", "rewrite.args[1]"]);
    expect(
      paths({
        target: { va: "0x1000" },
        relocation: "auto",
        mode: "replace",
        replace: { ret_type: "i32", arg_types: [], returns: null },
        when: { every_n: 2 },
        lifetime,
        record: true,
      }),
    ).toEqual(["replace.returns"]); // `when` is valid in replace mode: filtered calls run the original
    expect(paths({ ...rewrite({ ret: { type: "u8", value: 300 } }) })).toEqual(["rewrite.ret.value"]);
  });

  it("clamps lifetimes to the agent caps", () => {
    const planned = planOverride(
      { ...rewrite({ ret: { type: "i32", value: 1 } }), lifetime: { duration_ms: 99_999_999, max_hits: 1e12 } },
      LIMITS,
    );
    expect(planned.ok && [planned.plan.durationMs, planned.plan.maxHits]).toEqual([
      LIMITS.max_duration_ms,
      LIMITS.max_hits_cap,
    ]);
  });
});

describe("override application gate", () => {
  it("filters threads, samples every n-th call and counts applications", () => {
    const gate = new ApplicationGate(new Set([7]), 2, 2);
    expect(gate.decide(8)).toBe("skip");
    expect(gate.decide(7)).toBe("apply");
    expect(gate.applyOne()).toBe(false);
    expect(gate.decide(7)).toBe("skip");
    expect(gate.decide(7)).toBe("apply");
    expect(gate.applyOne()).toBe(true); // reached max_hits
    expect(gate.decide(7)).toBe("inactive");
    expect([gate.hits, gate.seen]).toEqual([2, 3]);
  });

  it("goes inactive at once on stop (detached guard)", () => {
    const gate = new ApplicationGate(null, 1, 100);
    gate.stop();
    expect(gate.decide(1)).toBe("inactive");
    expect(gate.active).toBe(false);
  });
});

describe("core seam binding (WP3 AgentCore shapes)", () => {
  const counters = {
    hits: 0,
    recorded: 0,
    sampled_out: 0,
    filtered: 0,
    agent_calls_suppressed: 0,
    unreturned: 0,
    errors: 0,
    dropped: {},
    bea_guard_suspended: 0,
  };

  it("adapts OriginalBytes (site-keyed, S4 save(site, n, owner)) to owner-keyed calls", () => {
    const calls: unknown[][] = [];
    const core = {
      originals: {
        save: (site: number, n: number, owner: string) => calls.push(["save", site, n, owner]),
        release: (site: number, owner: string) => calls.push(["release", site, owner]),
        isPatched: (address: number, size: number) => address <= 0x10 && address + size > 0x10,
        markPatched: (site: number) => calls.push(["markPatched", site]),
      },
    };
    const originals = bindModifySeam<number>(core).originals;
    originals?.save("wr1", 0x10, 4);
    originals?.markPatched("wr1");
    originals?.release("wr1");
    originals?.release("wr1"); // second release: no site left, no call
    expect(calls).toEqual([
      ["save", 0x10, 4, "wr1"],
      ["markPatched", 0x10],
      ["release", 0x10, "wr1"],
    ]);
    expect([originals?.isPatched(0xe, 4), originals?.isPatched(0x20, 4)]).toEqual([true, false]);
  });

  it("adapts guards, Stalker, oracle-call bypass and dispose hooks", () => {
    const invalidated: number[][] = [];
    const onDispose: (() => void)[] = [];
    const seam = bindModifySeam<number>({
      guards: { intersecting: (base: number) => (base === 1 ? [{}] : []) },
      stalkerCo: { invalidateAll: (sites: number[]) => invalidated.push(sites) },
      calls: { bypassesOverrides: (tid: number) => tid === 12 },
      hooks: { onDispose },
    });
    expect([seam.isGuarded?.(1, 4), seam.isGuarded?.(2, 4)]).toEqual([true, false]);
    seam.invalidate?.([7]);
    expect(invalidated).toEqual([[7]]);
    expect([seam.bypass(12), seam.bypass(13)]).toEqual([true, false]);
    seam.onDispose?.(() => undefined);
    expect(onDispose).toHaveLength(1);
  });

  it("registers overrides with the InstrumentRegistry and stamps override/1 rows through the StreamRegistry", async () => {
    const registered: Record<string, unknown>[] = [];
    const emitted: unknown[][] = [];
    const closed: unknown[] = [];
    const stopped: string[] = [];
    let state = "active";
    const inst = {
      id: "o3",
      counters,
      get active() {
        return state === "active";
      },
      hit: () => (state === "active" ? "record" : "ignore"),
    };
    const seam = bindModifySeam<number>({
      native: { nextG: () => 41, nowUs: () => 9000 },
      streams: {
        open: (spec: unknown) => (registered.push({ stream: spec }), { id: "s5" }),
        emit: (stream: unknown, row: unknown[]) => emitted.push([stream, ...row]),
        close: (stream: unknown) => closed.push(stream),
      },
      instruments: {
        register: (spec: Record<string, unknown>) => (registered.push(spec), inst),
        stop: async (_i: unknown, reason: string) => void stopped.push(reason),
      },
    });
    const revert = async () => ({ reverted: true, verification: { kind: "bytes" as const, ok: true, detail: "x" } });
    const reg = seam.instruments?.register({
      label: null,
      lifetime: { duration_ms: 100, max_hits: 2, clock: "resume" },
      targets: ["0x10"],
      sites: [0x10],
      record: true,
      revert,
    });
    if (reg === undefined || "_tag" in reg) throw new Error("registration failed");
    expect(registered[0]).toEqual({ stream: { instrument: null, kind: "override/1", enc: "json" } });
    expect(registered[1]).toMatchObject({
      kind: "override",
      lifetime: { duration_ms: 100, max_hits: 2, clock: "resume" },
      targets: ["0x10"],
      sites: [0x10],
      stream: { id: "s5" },
    });
    const coreRevert = registered[1]?.["revert"] as ((i: unknown, r: string) => Promise<unknown>) | undefined;
    expect(await coreRevert?.(inst, "duration")).toEqual(await revert());
    expect([reg.id, reg.streamId, reg.active, reg.hit()]).toEqual(["o3", "s5", true, true]);
    reg.emit([7, "o3", "ret", ["0x1"]]);
    expect(emitted).toEqual([[{ id: "s5" }, 41, 9000, 7, "o3", "ret", ["0x1"]]]);
    state = "stopping";
    expect([reg.active, reg.hit()]).toEqual([false, false]);
    reg.discard();
    expect(stopped).toEqual(["error"]);
    expect(closed).toEqual([]);
  });

  it("returns registry refusals and closes the stream it opened", () => {
    const closed: unknown[] = [];
    const seam = bindModifySeam<number>({
      native: { nextG: () => 1, nowUs: () => 1 },
      streams: { open: () => ({ id: "s1" }), emit: () => true, close: (s: unknown) => closed.push(s) },
      instruments: {
        register: () => ({ _tag: "ResourceLimit", message: "x", resource: "instruments", limit: 16 }),
        stop: async () => undefined,
      },
    });
    const reg = seam.instruments?.register({
      label: null,
      lifetime: { duration_ms: 1, max_hits: 1 },
      targets: [],
      sites: [],
      record: true,
      revert: async () => ({ reverted: true, verification: null }),
    });
    expect(reg).toMatchObject({ _tag: "ResourceLimit" });
    expect(closed).toEqual([{ id: "s1" }]);
  });

  it("degrades to local fallbacks on the day-0 core", () => {
    const seam = bindModifySeam<number>({ phase: "ready", instruments: { register: () => null } });
    expect([seam.originals, seam.isGuarded, seam.invalidate, seam.instruments, seam.onDispose]).toEqual([
      null,
      null,
      null,
      null,
      null,
    ]);
    expect(seam.bypass(1)).toBe(false);
    const ids = new LocalIds("o");
    expect([ids.allocate(), ids.allocate()]).toEqual(["o1", "o2"]);
  });
});

/**
 * Review fix AGENT-9: the seam bound to the REAL WP3 OriginalBytes (not a stand-in with the adapter's own signature).
 * OriginalBytes only needs NativePointer's toString/readByteArray and `instanceof`: a stand-in over a 0x100-byte buffer.
 * It is a GumJS file, so it is imported at run time only (the root typecheck has no frida-gum types).
 */
interface OriginalsLike {
  list(): { readonly bytes: Uint8Array; readonly owners: Map<string, number>; patchedHead: Uint8Array | null }[];
  overlay(buf: ArrayBuffer, base: unknown): { offset: number; size: number }[];
}
const ORIGINALS_MODULE = "../../../src/agent/originals.js";

describe("modify seam over the real OriginalBytes (review fix AGENT-9)", () => {
  const memory = new Uint8Array(0x100).map((_, i) => i);
  const BASE = 0x10000n;
  class FakePointer {
    constructor(readonly value: bigint) {}
    toString(): string {
      return `0x${this.value.toString(16)}`;
    }
    add(n: number | bigint): FakePointer {
      return new FakePointer(this.value + BigInt(n));
    }
    readByteArray(n: number): ArrayBuffer | null {
      const off = Number(this.value - BASE);
      if (off < 0 || off + n > memory.length) throw new Error("access violation");
      return memory.slice(off, off + n).buffer;
    }
  }
  const globals = globalThis as Record<string, unknown>;
  const saved = globals["NativePointer"];
  let OriginalBytes: new () => OriginalsLike;
  beforeAll(async () => {
    globals["NativePointer"] = FakePointer;
    ({ OriginalBytes } = (await import(ORIGINALS_MODULE)) as { OriginalBytes: new () => OriginalsLike });
  });
  afterAll(() => {
    if (saved === undefined) delete globals["NativePointer"];
    else globals["NativePointer"] = saved;
  });
  const at = (offset: number): FakePointer => new FakePointer(BASE + BigInt(offset));

  it("records a write's own size and owner, so neighbouring fields stay writable", () => {
    const real = new OriginalBytes();
    const originals = bindModifySeam<FakePointer>({ originals: real }).originals;
    originals?.save("wr1", at(0x10), 4);
    originals?.markPatched("wr1");
    const [record] = real.list();
    expect(record?.bytes.length).toBe(4);
    expect([...(record?.owners.keys() ?? [])]).toEqual(["wr1"]);
    expect(record?.patchedHead?.length).toBe(4);
    // the next struct field (+0x14) and one 0x1c bytes later were refused as "overlaps a BEA patch" before the fix
    expect(originals?.isPatched(at(0x14), 4)).toBe(false);
    expect(originals?.isPatched(at(0x2c), 4)).toBe(false);
    expect(originals?.isPatched(at(0x12), 4)).toBe(true);
    // the dump/disassembly overlay restores exactly the written bytes
    const buf = new Uint8Array(0x40).buffer;
    expect(real.overlay(buf, at(0))).toEqual([{ offset: 0x10, size: 4 }]);
    originals?.release("wr1");
    expect(real.list()).toEqual([]);
  });

  it("covers a code write longer than 32 bytes in full", () => {
    const real = new OriginalBytes();
    const originals = bindModifySeam<FakePointer>({ originals: real }).originals;
    originals?.save("wr2", at(0x20), 0x48);
    expect(real.list()[0]?.bytes.length).toBe(0x48);
    expect(originals?.isPatched(at(0x20 + 0x40), 4)).toBe(true);
    originals?.release("wr2");
  });
});
