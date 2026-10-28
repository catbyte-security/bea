import { describe, expect, it } from "vitest";

import { HandleCache } from "../../../src/agent/pure/profileHandles.js";
import { AgentSim } from "./support/agentSim.js";
import { MINUS_ONE } from "./support/fakeMem.js";

/** S4 §10.6 generic listener: filters, rows, parent tracking, handle cache (pure engine over FakeMem). */
describe("profile engine", () => {
  it("emits ApiRow tuples [g, t, tid, depth, parent, api, args, ret, caller] with NTSTATUS as u32 hex", () => {
    const sim = new AgentSim();
    sim.call("NtQueryAttributesFile", [sim.mem.oa("\\??\\C:\\x"), 0n], 0xc000_0034n, { tid: 7, caller: "0x401234" });
    expect(sim.rows).toHaveLength(1);
    const [g, t, tid, depth, parent, api, args, ret, caller] = sim.rows[0] ?? [];
    expect({ g, tid, depth, parent, api, ret, caller }).toEqual({
      g: 1,
      tid: 7,
      depth: 0,
      parent: 0,
      api: 3,
      ret: "0xc0000034",
      caller: "0x401234",
    });
    expect(typeof t).toBe("number");
    expect(args).toMatchObject({ path: { s: "\\??\\C:\\x" } });
  });

  it("thread filter, emit_when and per-API caps count filtered/dropped instead of emitting", () => {
    const sim = new AgentSim({ threadIds: [1], perApiMax: 2 });
    sim.call("NtClose", [0x10n], 0n, { tid: 2 });
    expect(sim.engine.counters.filtered).toBe(1);
    for (let i = 0; i < 3; i++) sim.call("NtQueryAttributesFile", [sim.mem.oa("x"), 0n], 0n, { tid: 1 });
    expect(sim.rows).toHaveLength(2);
    expect(sim.engine.counters.dropped).toEqual({ per_api_cap: 1 });
    // NtWriteVirtualMemory on the own process is not a cross-process write (emit_when ProcessHandle ne -1)
    const remote = new AgentSim();
    remote.call("NtWriteVirtualMemory", [MINUS_ONE, 0x1000n, 0n, 16n, 0n], 0n);
    remote.call("NtWriteVirtualMemory", [0x88n, 0x1000n, 0n, 16n, 0n], 0n);
    expect(remote.rows.map((r) => r[6].process)).toEqual(["0x88"]);
    expect(remote.engine.counters.filtered).toBe(1);
  });

  it("NtTerminateProcess(self) is emitted at enter with ret null (noreturn_when); NULL handles are skipped", () => {
    const sim = new AgentSim();
    expect(sim.begin("NtTerminateProcess", [MINUS_ONE, 3n])).toBeNull();
    expect(sim.rows).toHaveLength(1);
    expect(sim.rows[0]?.[7]).toBeNull();
    expect(sim.rows[0]?.[6]).toMatchObject({ process: "0xffffffffffffffff", status: 3 });
    sim.call("NtTerminateProcess", [0n, 0n], 0n);
    expect(sim.rows).toHaveLength(1);
  });

  it("max_hits: rows stop at the cap, onMaxHits fires once, later calls count instrument_cap/stopped", () => {
    const sim = new AgentSim({ maxHits: 2 });
    for (let i = 0; i < 4; i++) sim.call("NtQueryAttributesFile", [sim.mem.oa("x"), 0n], 0n);
    expect(sim.rows).toHaveLength(2);
    expect(sim.maxHitsCalls).toBe(1);
    expect(sim.engine.active).toBe(false);
  });

  it("a call whose instrument stopped between enter and leave is dropped as stopped (detached guard)", () => {
    const sim = new AgentSim();
    const state = sim.begin("NtQueryAttributesFile", [sim.mem.oa("x"), 0n]);
    sim.engine.active = false;
    sim.end(state, 0n);
    expect(sim.rows).toHaveLength(0);
    expect(sim.engine.counters.dropped.stopped).toBe(1);
  });

  it("parent tracking per thread; an unreturned frame is discarded at the next outermost call", () => {
    const sim = new AgentSim();
    const outer = sim.begin("LdrLoadDll", [1n, 0n, sim.mem.ustr("a.dll"), sim.mem.slot()], { tid: 5 });
    sim.call("NtOpenFile", [sim.mem.slot(), 1n, sim.mem.oa("x"), sim.mem.iosb(), 0n, 0n], 0n, { tid: 5, depth: 1 });
    sim.call("NtOpenFile", [sim.mem.slot(), 1n, sim.mem.oa("y"), sim.mem.iosb(), 0n, 0n], 0n, { tid: 6, depth: 1 });
    sim.end(outer, 0n);
    const byPath = (p: string) => sim.rows.find((r) => JSON.stringify(r[6]).includes(`"${p}"`));
    expect(byPath("x")?.[4]).toBe(1); // child of the LdrLoadDll row (g 1)
    expect(byPath("y")?.[4]).toBe(0); // other thread
    sim.begin("LdrLoadDll", [1n, 0n, sim.mem.ustr("lost.dll"), sim.mem.slot()], { tid: 9 }); // leave never seen
    sim.call("NtClose", [0x1n], 0n, { tid: 9 });
    sim.call("NtQueryAttributesFile", [sim.mem.oa("z"), 0n], 0n, { tid: 9, depth: 0 });
    expect(byPath("z")?.[4]).toBe(0);
    expect(sim.engine.counters.unreturned).toBe(1);
  });

  it("handle cache: successful opens name handles, NtClose evicts (row-less), unknown handles stay unnamed", () => {
    const sim = new AgentSim();
    const ph = sim.mem.slot();
    sim.call("NtCreateFile", [ph, 1n, sim.mem.oa("\\??\\C:\\f.txt"), sim.mem.iosb(), 0n, 0n, 0n, 1n, 0n], 0n, {
      kernel: () => sim.mem.writeUInt(ph, 0x44n, 8),
    });
    sim.call("NtReadFile", [0x44n, 0n, 0n, 0n, sim.mem.iosb(), sim.mem.alloc(8), 8n, 0n], 0n);
    expect(sim.lastCells()).toMatchObject({ handle: "0x44", handle_name: { s: "\\??\\C:\\f.txt" } });
    sim.call("NtClose", [0x44n], 0n);
    expect(sim.rows).toHaveLength(2); // NtClose produces no row
    sim.call("NtReadFile", [0x44n, 0n, 0n, 0n, sim.mem.iosb(), sim.mem.alloc(8), 8n, 0n], 0n);
    expect(sim.lastCells()).toMatchObject({ handle: "0x44", handle_name: null });
    // a failed open never names its out-handle
    const bad = sim.mem.slot(0x48n);
    sim.call("NtOpenFile", [bad, 1n, sim.mem.oa("\\??\\C:\\nope"), sim.mem.iosb(), 0n, 0n], 0xc000_0034n);
    expect(sim.lastCells().handle).toBeNull();
    expect(sim.cache.get("0x48")).toBeUndefined();
  });

  it("sockets: protocol from WSASocketW, bind to port 0 resolved with getsockname, WSAEWOULDBLOCK connects named, last_error on failure", () => {
    const sim = new AgentSim();
    sim.call("WSASocketW", [2n, 2n, 17n, 0n, 0n, 0n], 0x500n);
    expect(sim.cache.get("0x500")).toEqual({ kind: "socket", name: null, proto: "udp" });
    sim.call("bind", [0x500n, sim.mem.sockaddrIn("0.0.0.0", 0), 16n], 0n); // no getsockname answer: stays :0
    expect(sim.cache.get("0x500")?.name).toBe("0.0.0.0:0");
    sim.endpoints.set(0x500n, { family: 2, addr: "0.0.0.0", port: 6000 });
    sim.call("bind", [0x500n, sim.mem.sockaddrIn("0.0.0.0", 0), 16n], 0n);
    expect(sim.lastCells().local_bound).toEqual({ s: "0.0.0.0:6000" });
    sim.call("WSASocketW", [2n, 1n, 6n, 0n, 0n, 0n], 0x504n);
    sim.call("connect", [0x504n, sim.mem.sockaddrIn("10.0.0.9", 80), 16n], 0xffff_ffffn, { lastError: 10035 });
    expect(sim.lastCells().last_error).toBe(10035);
    expect(sim.cache.get("0x504")).toEqual({ kind: "socket", name: "10.0.0.9:80", proto: "tcp" });
    sim.call("send", [0x504n, sim.mem.alloc(4), 4n, 0n], 4n);
    expect(sim.lastCells()).toMatchObject({
      socket_name: { s: "10.0.0.9:80" },
      socket_proto: { s: "tcp" },
      buffer_len: 4,
    });
    sim.call("closesocket", [0x504n], 0n);
    expect(sim.cache.get("0x504")).toBeUndefined();
    sim.call("WSASocketW", [2n, 1n, 6n, 0n, 0n, 0n], 0xffff_ffff_ffff_ffffn, { lastError: 10093 });
    expect(sim.lastCells().last_error).toBe(10093);
  });

  it("HTTP handles carry host:port into requests", () => {
    const sim = new AgentSim();
    sim.call("WinHttpConnect", [0x600n, sim.mem.wstr("example.test"), 443n, 0n], 0x604n);
    sim.call(
      "WinHttpOpenRequest",
      [0x604n, sim.mem.wstr("GET"), sim.mem.wstr("/a?b=c"), 0n, 0n, 0n, 0x0080_0000n],
      0x608n,
    );
    expect(sim.lastCells()).toMatchObject({
      connection_name: { s: "example.test:443" },
      verb: { s: "GET" },
      object: { s: "/a?b=c" },
    });
    expect(sim.cache.get("0x608")?.name).toBe("example.test:443");
  });

  it("pseudo rows (observers) use depth 0, parent 0 and caller 0x0", () => {
    const sim = new AgentSim();
    sim.pseudo(201, { ev: { s: "L" }, path: { s: "C:\\m.dll" } }, 12);
    expect(sim.rows[0]).toEqual([
      1,
      expect.any(Number),
      12,
      0,
      0,
      201,
      { ev: { s: "L" }, path: { s: "C:\\m.dll" } },
      null,
      "0x0",
    ]);
  });
});

describe("HandleCache", () => {
  it("drops the oldest 25% on overflow and ignores NULL / -1 handles", () => {
    const cache = new HandleCache(8);
    for (let i = 1; i <= 9; i++) cache.set(`0x${i.toString(16)}`, { kind: "file", name: String(i) });
    expect(cache.size).toBe(7);
    expect(cache.get("0x1")).toBeUndefined();
    expect(cache.get("0x2")).toBeUndefined();
    expect(cache.get("0x9")?.name).toBe("9");
    expect(cache.evicted).toBe(2);
    cache.set("0x0", { kind: "file", name: "null" });
    cache.set("0xffffffffffffffff", { kind: "file", name: "self" });
    expect(cache.size).toBe(7);
  });
});
