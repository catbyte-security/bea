import { afterEach, describe, expect, it } from "vitest";

import { READ_VIEWS } from "../../../../src/contracts/areas/inspect.js";
import { toolContract } from "../../../../src/contracts/index.js";
import { ok } from "../../../../src/domain/result.js";
import { LIMITATIONS } from "../../../../src/domain/evidence/limitations.js";
import type { BeaServices } from "../../../../src/application/services/index.js";
import type {
  DisassembleParams,
  InsnRow,
  ListRangesParams,
  RangeRow,
  ThreadInfo,
} from "../../../../src/shared/agentProtocol.js";
import { formatHex, type Hex } from "../../../../src/shared/hex.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import {
  EMU_ID,
  EMU_SHA,
  FakeAgent,
  FakeMemory,
  GAME,
  LIVE_ID,
  memoryHandlers,
  MM,
  newEvidenceLog,
  NTDLL,
  PI,
  UNKNOWN_ID,
  fakeAddress,
  fakeEmulator,
  fakeEvidence,
  fakeLiveSession,
  fakePe,
  fakeSessions,
  type AgentHandler,
  type FakeAddressLog,
  type FakeEvidenceLog,
  type FakeLive,
} from "./inspectFakes.js";

/**
 * MCP boundary tests of the inspect area (S6 §10.6 with WP6-local fakes): the production server over an in-memory
 * transport; every result is checked against the tool's own output schema and carries the untrusted marker; live
 * and emulation sessions go through anySessionOp / liveOp exactly as in production.
 */
interface World {
  readonly bea: InMemoryBea;
  readonly live: FakeLive;
  readonly log: FakeEvidenceLog;
  readonly addressLog: FakeAddressLog;
  readonly memory: FakeMemory;
}
let open: InMemoryBea | null = null;
afterEach(async () => {
  await open?.close();
  open = null;
});

const u32 = (v: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, true);
  return b;
};
const f32 = (v: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setFloat32(0, v, true);
  return b;
};

const HEAP = 0x2000_0000n;
const CAR = HEAP + 0x100n;

const world = async (
  handlers: Partial<Record<string, AgentHandler>> = {},
  emu?: Partial<BeaServices>,
): Promise<World> => {
  const memory = new FakeMemory();
  memory.map(GAME.base, new Uint8Array(GAME.size), "r--", GAME.name);
  memory.map(HEAP, new Uint8Array(0x1000), "rw-", null);
  // g_world holds World*; World+8 = cars[0]; car+8 = speed 20.5
  memory.writeU64(GAME.base + 0x10000n, HEAP);
  memory.writeU64(HEAP + 8n, CAR);
  memory.write(CAR + 8n, f32(20.5));
  memory.write(GAME.base + 0x11000n, new Uint8Array(Buffer.from("BEA_MARKER\0junk", "latin1")));
  const agent = new FakeAgent({ ...memoryHandlers(memory), ...handlers } as never);
  const live = fakeLiveSession(agent);
  const log = newEvidenceLog();
  const addressLog: FakeAddressLog = { prepared: [] };
  const bea = await connectInMemoryBea({
    services: {
      sessions: fakeSessions(live, [EMU_ID]),
      evidence: fakeEvidence(log),
      address: fakeAddress([GAME, NTDLL], addressLog),
      pe: fakePe([GAME, NTDLL]),
      ...emu,
    },
  });
  open = bea;
  return { bea, live, log, addressLog, memory };
};

const call = async (w: World, name: string, args: Record<string, unknown>) => {
  const result = await w.bea.client.callTool({ name, arguments: args });
  if (result.isError !== true) {
    expect(result._meta, `${name} untrusted marker`).toMatchObject({ provenance: { untrusted_content: true } });
    const parsed = toolContract(name as "list_modules").outputSchema.safeParse(result.structuredContent);
    expect(parsed.success, `${name} output schema: ${parsed.success ? "" : parsed.error.message}`).toBe(true);
  }
  return result;
};

const MODULES = {
  listModules: (() =>
    ok({
      module_map_epoch: 3,
      modules: [GAME, NTDLL].map((m) => ({
        name: m.name,
        path: m.path,
        base: formatHex(m.base),
        size: m.size,
        pe: { time_date_stamp: m.timestamp } as never,
      })),
    })) as AgentHandler,
};

describe("list_modules", () => {
  it("lists live modules with on-disk preferred bases, main flag, hashes, paging and the module-map envelope", async () => {
    const w = await world(MODULES);
    const out = expectToolSuccess(await call(w, "list_modules", { session_id: LIVE_ID, hash: true, limit: 1 }));
    expect(out).toMatchObject({
      epoch: 3,
      rows: [
        {
          name: "game.exe",
          base: formatHex(GAME.base),
          preferred_base: "0x140000000",
          timestamp: GAME.timestamp,
          main: true,
        },
      ],
      page: { offset: 0, limit: 1, total: 2, next_offset: 1 },
      predicate_type: "bea.modules.list",
      authority: "live-process",
      instance_id: PI,
      module_map_id: MM,
      coverage: { status: "complete" },
    });
    expect((out["rows"] as { sha256: string }[])[0]?.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(out["limitations"]).toContain(LIMITATIONS.AGENT_CLOAKED);
    expect(w.log.applied).toEqual([{ op: "snapshot", epoch: 3 }]);
    const second = expectToolSuccess(await call(w, "list_modules", { session_id: LIVE_ID, offset: 1, limit: 1 }));
    expect(second).toMatchObject({ rows: [{ name: "ntdll.dll", main: false }], page: { next_offset: null } });
    const filtered = expectToolSuccess(await call(w, "list_modules", { session_id: LIVE_ID, filter: "NTDLL" }));
    expect(filtered).toMatchObject({ rows: [{ name: "ntdll.dll", main: false, sha256: null }], page: { total: 1 } });
  });

  it("answers emulation sessions from the cached module table, unrecorded", async () => {
    const emulator = fakeEmulator({
      memory: new FakeMemory(),
      modules: [
        {
          name: "mathlib.dll",
          path: "C:\\x\\mathlib.dll",
          sha256: EMU_SHA,
          base: "0x180000000",
          size: 0x9000,
          preferredBase: "0x180000000",
          primary: true,
        },
      ],
    });
    const w = await world({}, { emulator });
    const out = expectToolSuccess(await call(w, "list_modules", { session_id: EMU_ID, hash: true }));
    expect(out).toMatchObject({
      epoch: 2,
      rows: [{ name: "mathlib.dll", main: true, sha256: EMU_SHA, timestamp: null }],
      evidence_id: null,
      predicate_type: null,
      limitations: [LIMITATIONS.EMU_MODULES_UNRECORDED, LIMITATIONS.NOT_REAL_PROCESS],
    });
    expect(w.log.drafts).toHaveLength(0);
  });

  it("maps unknown, exited and detached sessions through the session-access table", async () => {
    const w = await world(MODULES);
    expect(parseToolError(await call(w, "list_modules", { session_id: UNKNOWN_ID })).code).toBe("session_not_found");
    w.live.state = "exited";
    expect(parseToolError(await call(w, "list_modules", { session_id: LIVE_ID })).code).toBe("target_exited");
    w.live.state = "detached";
    const detached = parseToolError(await call(w, "list_modules", { session_id: LIVE_ID }));
    expect(detached).toMatchObject({ code: "capability_unavailable" });
    expect(w.live.agent.count("listModules")).toBe(0);
  });
});

describe("list_memory_ranges", () => {
  const ranges: RangeRow[] = [
    { base: formatHex(GAME.base), size: 0x1000, protection: "r--", module: "game.exe", kind: "module" },
    { base: formatHex(GAME.base + 0x1000n), size: 0x9000, protection: "r-x", module: "game.exe", kind: "module" },
    { base: formatHex(HEAP), size: 0x1000, protection: "rw-", module: null, kind: "private" },
    { base: "0x30000000", size: 0x2000, protection: "rw-", module: null, kind: "malloc" },
  ];
  const listRanges = (pageSize: number) =>
    ((p: ListRangesParams) => {
      const items = ranges.slice(p.offset, p.offset + Math.min(p.limit, pageSize));
      const next = p.offset + items.length < ranges.length ? p.offset + items.length : null;
      return ok({ total: ranges.length, offset: p.offset, items, next_offset: next, snapshot: "ss1", taken_t: 1 });
    }) as AgentHandler;

  it("enumerates every agent page for total_bytes, maps kinds and pages a cached snapshot", async () => {
    const w = await world({ listRanges: listRanges(3) });
    const first = expectToolSuccess(await call(w, "list_memory_ranges", { session_id: LIVE_ID, limit: 2 }));
    expect(first).toMatchObject({
      total_bytes: 0x1000 + 0x9000 + 0x1000 + 0x2000,
      rows: [
        { base: formatHex(GAME.base), prot: "r--", module: "game.exe", kind: "image" },
        { kind: "image", prot: "r-x" },
      ],
      page: { total: 4, next_offset: 2 },
      predicate_type: "bea.memory.ranges",
    });
    expect(first["limitations"]).toEqual(
      expect.arrayContaining([LIMITATIONS.AGENT_CLOAKED, LIMITATIONS.RANGE_KIND_MAPPED_UNDISTINGUISHED]),
    );
    expect(w.live.agent.count("listRanges")).toBe(2); // 3 + 1 rows, the second page reuses snapshot ss1
    expect((w.live.agent.calls[1]!.params as ListRangesParams).snapshot).toBe("ss1");
    const second = expectToolSuccess(await call(w, "list_memory_ranges", { session_id: LIVE_ID, limit: 2, offset: 2 }));
    expect(second).toMatchObject({ rows: [{ kind: "private" }, { kind: "private" }], page: { next_offset: null } });
    expect(w.live.agent.count("listRanges")).toBe(2); // continuation page served from the host snapshot
    await call(w, "list_memory_ranges", { session_id: LIVE_ID, limit: 2 });
    expect(w.live.agent.count("listRanges")).toBe(4); // offset 0 always enumerates afresh
  });

  it("passes filters to the agent and restarts once when the agent snapshot expired", async () => {
    let expired = true;
    const w = await world({
      listRanges: ((p: ListRangesParams) => {
        if (p.snapshot !== undefined && expired) {
          expired = false;
          return {
            ok: false,
            error: { _tag: "ReferenceNotFound", operation: "x", reference: { kind: "snapshot", id: "ss1" } },
          };
        }
        return (listRanges(2) as (q: ListRangesParams) => unknown)(p);
      }) as AgentHandler,
    });
    const out = expectToolSuccess(
      await call(w, "list_memory_ranges", {
        session_id: LIVE_ID,
        kind: "image",
        module: "game.exe",
        protection: "r-x",
      }),
    );
    expect(out).toMatchObject({ page: { total: 4 } });
    const params = w.live.agent.calls[0]?.params as ListRangesParams;
    expect(params).toMatchObject({ kind: "module", module: "game.exe", protection: "r-x", coalesce: true, offset: 0 });
  });

  it("refuses an emulation session (live-only tool)", async () => {
    const emulator = fakeEmulator({ memory: new FakeMemory(), modules: [] });
    const w = await world({}, { emulator });
    const e = parseToolError(await call(w, "list_memory_ranges", { session_id: EMU_ID }));
    expect(e.code).toBe("invalid_request");
  });
});

describe("list_threads", () => {
  const entry = GAME.base + 0x1400n;
  const threads: ThreadInfo[] = [
    {
      id: 10,
      state: "running",
      entry: formatHex(entry),
      teb: null,
      stack: null,
      name: null,
      regs: { rax: "0x1", rip: "0x2", xmm0: "0x3" } as never,
      bea_role: null,
    },
    {
      id: 11,
      state: "running",
      entry: formatHex(GAME.base + 0x1940n),
      teb: null,
      stack: null,
      name: null,
      regs: null,
      bea_role: null,
    },
    { id: 12, state: "running", entry: null, teb: null, stack: null, name: null, regs: null, bea_role: "agent" },
  ];
  const handlers = {
    listThreads: (() => ok({ threads })) as AgentHandler,
    processInfo: (() =>
      ok({
        main_module: {
          name: "game.exe",
          path: GAME.path,
          base: formatHex(GAME.base),
          size: GAME.size,
          pe: { entry_rva: "0x1400" },
        },
      })) as AgentHandler,
  };

  it("hides the agent thread, marks main by entry point, describes entries and keeps only GPRs", async () => {
    const w = await world(handlers);
    const out = expectToolSuccess(await call(w, "list_threads", { session_id: LIVE_ID, registers: true }));
    expect(out).toMatchObject({
      rows: [
        {
          tid: 10,
          main: true,
          entry: { at: "game.exe+0x1400", static: "game.exe:0x140001400" },
          registers: { rax: "0x1", rip: "0x2" },
        },
        { tid: 11, main: false, registers: {} },
      ],
      page: { total: 2 },
      predicate_type: "bea.threads.list",
    });
    expect((out["rows"] as { registers: object }[])[0]?.registers).not.toHaveProperty("xmm0");
    expect(w.addressLog.prepared).toContain(entry);
    expect(out["limitations"]).toContain(LIMITATIONS.AGENT_THREADS_CLOAKED);
    expect((w.live.agent.calls[0]!.params as { registers: string }).registers).toBe("gpr");
  });

  it("omits registers unless asked and says when no main thread is known", async () => {
    const w = await world({
      ...handlers,
      processInfo: (() => ok({ main_module: { base: formatHex(GAME.base), pe: null } })) as AgentHandler,
    });
    const out = expectToolSuccess(await call(w, "list_threads", { session_id: LIVE_ID }));
    expect((out["rows"] as object[])[0]).not.toHaveProperty("registers");
    expect(out["limitations"]).toContain(LIMITATIONS.MAIN_THREAD_UNKNOWN);
  });
});

describe("read_memory", () => {
  it("reads hex at an export and decodes utf8 up to the NUL", async () => {
    const w = await world();
    const hex = expectToolSuccess(
      await call(w, "read_memory", { session_id: LIVE_ID, address: "game.exe!g_marker", size: 10 }),
    );
    expect(hex).toMatchObject({
      address: { module: "game.exe", rva: "0x11000" },
      requested: 10,
      returned: 10,
      complete: true,
      data: Buffer.from("BEA_MARKER").toString("hex"),
      region: { module: "game.exe", prot: "r--" },
      predicate_type: "bea.memory.read",
      coverage: { status: "complete" },
    });
    const text = expectToolSuccess(
      await call(w, "read_memory", { session_id: LIVE_ID, address: "game.exe!g_marker", size: 16, view: "utf8" }),
    );
    expect(text["text"]).toBe("BEA_MARKER");
    expect(text).not.toHaveProperty("data");
  });

  it("follows a Cheat Engine chain [[g_world]+8]+8 to an exact f32 and reports each step", async () => {
    const w = await world();
    const out = expectToolSuccess(
      await call(w, "read_memory", {
        session_id: LIVE_ID,
        address: "game.exe!g_world",
        deref: [8, 8],
        size: 4,
        view: "f32",
      }),
    );
    expect(out).toMatchObject({
      address: { va: formatHex(CAR + 8n), module: null },
      chain: [
        { address: formatHex(GAME.base + 0x10000n), value: formatHex(HEAP) },
        { address: formatHex(HEAP + 8n), value: formatHex(CAR) },
      ],
      values: [20.5],
      region: { base: formatHex(HEAP), prot: "rw-", module: null },
    });
  });

  it("is complete:false (coverage partial) across an unmapped page and memory_access_failed at 0x10", async () => {
    const w = await world();
    const partial = expectToolSuccess(
      await call(w, "read_memory", { session_id: LIVE_ID, address: formatHex(HEAP + 0xff0n), size: 64 }),
    );
    expect(partial).toMatchObject({
      requested: 64,
      returned: 16,
      complete: false,
      coverage: { status: "partial", reasons: ["unreadable_memory"] },
    });
    const failed = parseToolError(await call(w, "read_memory", { session_id: LIVE_ID, address: "0x10", size: 4 }));
    expect(failed).toMatchObject({ code: "memory_access_failed", details: { address: "0x10" } });
    const chainFail = parseToolError(
      await call(w, "read_memory", { session_id: LIVE_ID, address: formatHex(HEAP + 0x200n), deref: [0x10, 4] }),
    );
    expect(chainFail.code).toBe("memory_access_failed");
    expect(chainFail.details["diagnostics"]).toMatchObject({
      chain: [{ address: formatHex(HEAP + 0x200n), value: "0x0" }],
      chain_failed_at: "0x10",
    });
  });

  it("caps typed values at 16384 with a truncated coverage and the cap limitation", async () => {
    const w = await world();
    w.memory.map(0x5000_0000n, new Uint8Array(65_536), "rw-");
    const out = expectToolSuccess(
      await call(w, "read_memory", { session_id: LIVE_ID, address: "0x50000000", size: 65_536, view: "u8" }),
    );
    expect((out["values"] as number[]).length).toBe(16_384);
    expect(out).toMatchObject({
      complete: true,
      coverage: { status: "partial", truncated: true, reasons: ["value_cap"] },
    });
    expect(out["limitations"]).toContain(LIMITATIONS.CAP("value", 16_384));
  });
});

describe("read_memory redaction, errors and emulation", () => {
  it("delivers the redacted record: a sensitive value nulls the field and counts a redaction", async () => {
    const w = await world();
    const out = expectToolSuccess(
      await call(w, "read_memory", {
        session_id: LIVE_ID,
        address: "game.exe!g_marker",
        size: 10,
        view: "utf8",
        sensitive_values: ["MARKER"],
      }),
    );
    expect(out["text"]).toBeNull();
    expect(out["redactions"]).toBe(1);
    expect(out["coverage"]).toMatchObject({ status: "partial", reasons: ["explicit_sensitive_value"] });
    const short = parseToolError(
      await call(w, "read_memory", { session_id: LIVE_ID, address: "0x10", sensitive_values: ["ab"] }),
    );
    expect(short.code).toBe("invalid_request");
  });

  it("withholds every view when the raw bytes contain a sensitive value, typed views included (SEC-3/4)", async () => {
    const w = await world();
    for (const view of READ_VIEWS) {
      const out = expectToolSuccess(
        await call(w, "read_memory", {
          session_id: LIVE_ID,
          address: "game.exe!g_marker",
          size: 16,
          view,
          sensitive_values: ["MARKER"],
        }),
      );
      const payload = ["data", "values", "text"].filter((k) => k in out);
      expect(payload.length, view).toBe(1);
      for (const key of payload) expect(out[key], `${view}.${key}`).toBeNull();
      expect(out["redactions"], view).toBe(1);
      expect(out["coverage"], view).toMatchObject({ status: "partial", reasons: ["explicit_sensitive_value"] });
    }
    // without the literal the typed view is delivered
    const plain = expectToolSuccess(
      await call(w, "read_memory", { session_id: LIVE_ID, address: "game.exe!g_marker", size: 16, view: "u16" }),
    );
    expect((plain["values"] as number[]).length).toBe(8);
  });

  it("rejects a bad address expression with invalid_request on the address path", async () => {
    const w = await world();
    const e = parseToolError(await call(w, "read_memory", { session_id: LIVE_ID, address: "not an address" }));
    expect(e).toMatchObject({ code: "invalid_request" });
    expect(JSON.stringify(e.details)).toContain("address");
    expect(
      parseToolError(await call(w, "read_memory", { session_id: LIVE_ID, address: "0x10", size: 65_537 })).code,
    ).toBe("invalid_request");
  });

  it("reads emulation memory through the EmuPort and records bea.emu.memory.read on an emulation subject", async () => {
    const memory = new FakeMemory();
    memory.map(0x1_8000_0000n, new Uint8Array(0x100), "r-x", "mathlib.dll");
    memory.write(0x1_8000_0010n, u32(0xdeadbeef));
    const emulator = fakeEmulator({
      memory,
      modules: [
        {
          name: "mathlib.dll",
          path: null,
          sha256: EMU_SHA,
          base: "0x180000000",
          size: 0x100,
          preferredBase: "0x180000000",
          primary: true,
        },
      ],
    });
    const w = await world({}, { emulator });
    const out = expectToolSuccess(
      await call(w, "read_memory", { session_id: EMU_ID, address: "0x180000010", size: 4, view: "u32" }),
    );
    expect(out).toMatchObject({
      values: [0xdeadbeef],
      complete: true,
      region: { base: "0x180000000", size: 0x100, prot: "r-x", module: "mathlib.dll" },
      predicate_type: "bea.emu.memory.read",
      authority: "emulation",
    });
    expect(out).not.toHaveProperty("instance_id");
    expect(out["limitations"]).toContain(LIMITATIONS.NOT_REAL_PROCESS);
    const draft = w.log.drafts[0];
    expect(draft?.subject).toMatchObject({ kind: "emulation", image_sha256: EMU_SHA, state: { basis: "chained" } });
    expect(draft?.capture).toBeUndefined();
    expect(parseToolError(await call(w, "read_memory", { session_id: EMU_ID, address: "0x10" })).code).toBe(
      "address_unmapped",
    );
  });
});

/** Agent rows of game.exe!physics_step+0 (movss, RIP-relative comiss, ja rel32, call rax). */
const DIS_START = GAME.base + 0x1760n;
const DIS_ROWS: InsnRow[] = [
  {
    address: formatHex(DIS_START),
    size: 5,
    bytes: "f30f104108",
    mnemonic: "movss",
    op_str: "xmm0, dword ptr [rcx + 8]",
    groups: [],
    branch_target: null,
    mem_targets: [],
    overlay: true,
  },
  {
    address: formatHex(DIS_START + 5n),
    size: 7,
    bytes: "0f2f0560aa0000",
    mnemonic: "comiss",
    op_str: "xmm0, dword ptr [rip + 0xaa60]",
    groups: [],
    branch_target: null,
    mem_targets: [formatHex(DIS_START + 12n + 0xaa60n)],
    overlay: false,
  },
  {
    address: formatHex(DIS_START + 12n),
    size: 6,
    bytes: "0f87fb000000",
    mnemonic: "ja",
    op_str: formatHex(DIS_START + 0x110n),
    groups: ["jump", "branch_relative"],
    branch_target: formatHex(DIS_START + 0x110n),
    mem_targets: [],
    overlay: false,
  },
  {
    address: formatHex(DIS_START + 18n),
    size: 2,
    bytes: "ffd0",
    mnemonic: "call",
    op_str: "rax",
    groups: ["call"],
    branch_target: null,
    mem_targets: [],
    overlay: false,
  },
];
const disasmHandler = (
  stop: { reason: "access-violation" | "decode-error" | "limit"; at: Hex } | null = null,
  truncated = false,
) =>
  ((p: DisassembleParams) =>
    ok({
      start: formatHex(DIS_START),
      function: { base: formatHex(DIS_START), size: 0x11d, source: "pdata" },
      instructions: p.mode === "function" ? DIS_ROWS : DIS_ROWS.slice(0, p.count ?? 32),
      truncated,
      overlay_used: true,
      stop,
      blocks: null,
    })) as AgentHandler;

describe("disassemble", () => {
  it("returns module-relative rows with resolved branch and RIP-relative refs over original bytes", async () => {
    const w = await world({ disassemble: disasmHandler() });
    const out = expectToolSuccess(
      await call(w, "disassemble", { session_id: LIVE_ID, address: "game.exe+0x1760", function: true }),
    );
    expect(out).toMatchObject({
      module: "game.exe",
      func: { start: formatHex(DIS_START), size: 0x11d },
      hooked_bytes_restored: true,
      predicate_type: "bea.code.disassembly",
      authority: "live-process",
      rows: [
        { rva: "0x1760", va: formatHex(DIS_START), b: "f30f104108", t: "movss xmm0, dword ptr [rcx + 8]", ref: null },
        {
          rva: "0x1765",
          ref: `game.exe+${formatHex(0x1760n + 12n + 0xaa60n)} game.exe:${formatHex(0x1_4000_1760n + 12n + 0xaa60n)}`,
        },
        { rva: "0x176c", t: `ja ${formatHex(DIS_START + 0x110n)}`, ref: "game.exe+0x1870 game.exe:0x140001870" },
        { rva: "0x1772", t: "call rax", ref: null },
      ],
    });
    expect(out["limitations"]).toContain(LIMITATIONS.HOOKED_BYTES_RESTORED);
    const params = w.live.agent.calls[0]?.params as DisassembleParams;
    expect(params).toMatchObject({ mode: "function", original_bytes: true, cfg: false });
    expect(params).not.toHaveProperty("count");
  });

  it("passes count, reports unreadable stops as partial coverage and decode stops as a limitation", async () => {
    const w = await world({
      disassemble: disasmHandler({ reason: "access-violation", at: formatHex(DIS_START + 20n) }),
    });
    const out = expectToolSuccess(
      await call(w, "disassemble", { session_id: LIVE_ID, address: "game.exe+0x1760", count: 2 }),
    );
    expect(out).toMatchObject({ rows: [{}, {}], coverage: { status: "partial", reasons: ["unreadable_memory"] } });
    expect((w.live.agent.calls[0]!.params as DisassembleParams).count).toBe(2);
    await open?.close();
    const v = await world({
      disassemble: disasmHandler({ reason: "decode-error", at: formatHex(DIS_START + 20n) }, false),
    });
    const decoded = expectToolSuccess(
      await call(v, "disassemble", { session_id: LIVE_ID, address: "game.exe+0x1760" }),
    );
    expect(decoded["limitations"]).toContain(LIMITATIONS.DISASM_DECODE_STOP(formatHex(DIS_START + 20n)));
    expect(decoded).toMatchObject({ coverage: { status: "complete" } });
  });

  it("maps a missing .pdata function to invalid_request and an unknown module to address_unmapped", async () => {
    const w = await world({
      disassemble: (() => ({
        ok: false,
        error: {
          _tag: "InputError",
          operation: "disassemble",
          issues: [{ path: "address", reason: "invalid_value", message: "No .pdata function contains this address." }],
        },
      })) as AgentHandler,
    });
    expect(
      parseToolError(await call(w, "disassemble", { session_id: LIVE_ID, address: "0x20000000", function: true })).code,
    ).toBe("invalid_request");
    expect(parseToolError(await call(w, "disassemble", { session_id: LIVE_ID, address: "nope.dll+0x10" })).code).toBe(
      "address_unmapped",
    );
  });

  it("disassembles emulation sessions through the EmuPort with text-derived refs", async () => {
    const emulator = fakeEmulator({
      memory: new FakeMemory(),
      modules: [
        {
          name: "mathlib.dll",
          path: null,
          sha256: EMU_SHA,
          base: "0x180000000",
          size: 0x9000,
          preferredBase: "0x180000000",
          primary: true,
        },
      ],
      insns: [
        {
          va: "0x180001000",
          rva: "0x1000",
          module: "mathlib.dll",
          bytes: "f30f100508000000",
          text: "movss xmm0, dword ptr [rip + 8]",
        },
        { va: "0x180001008", rva: "0x1008", module: "mathlib.dll", bytes: "e8f3ffffff", text: "call 0x180001000" },
      ],
      fn: { module: "mathlib.dll", beginRva: "0x1000", endRva: "0x1040", source: "pdata" },
    });
    const mathlib = {
      name: "mathlib.dll",
      base: 0x1_8000_0000n,
      size: 0x9000,
      path: "",
      preferredBase: 0x1_8000_0000n,
      exports: {},
      timestamp: 0,
    };
    const w = await world({}, { emulator, address: fakeAddress([mathlib]) });
    const out = expectToolSuccess(
      await call(w, "disassemble", { session_id: EMU_ID, address: "0x180001000", function: true }),
    );
    expect(out).toMatchObject({
      module: "mathlib.dll",
      func: { start: "0x180001000", size: 0x40 },
      hooked_bytes_restored: false,
      authority: "emulation",
      rows: [
        { rva: "0x1000", ref: "mathlib.dll+0x1010 mathlib.dll:0x180001010" },
        { rva: "0x1008", ref: "mathlib.dll+0x1000 mathlib.dll:0x180001000" },
      ],
    });
    expect(w.log.drafts[0]?.subject).toMatchObject({ kind: "emulation" });
  });
});
