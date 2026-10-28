import { describe, expect, it } from "vitest";

import { DEFAULT_API_DECODERS, decodeApiRow, type ApiDecoders } from "../../../src/application/behavior/apiEvents.js";
import { apiSummaryBuilder } from "../../../src/application/behavior/ApiSummary.js";
import type { JsonObject, JsonValue } from "../../../src/domain/json.js";
import type { EventRecord } from "../../../src/ports/recordings.js";
import type { ApiRow } from "../../../src/shared/agentProtocol.js";
import { AgentSim } from "./support/agentSim.js";
import { SCENARIO, runBehaviorScenario } from "./support/behaviorScenario.js";

/** agent engine rows → host events → ApiSummary, for behavior.exe's steps (S6 §10.1 table). */
const events = (rows: readonly ApiRow[], decoders: ApiDecoders = DEFAULT_API_DECODERS): EventRecord[] =>
  rows
    .map((row, i) =>
      decodeApiRow(row as unknown as JsonValue, {
        seq: i + 1,
        startedAtUs: 1_000,
        decoders,
        frame: (va) => (va === `0x${SCENARIO.mathlibBase.toString(16)}` ? "mathlib.dll+0x0" : null),
      }),
    )
    .filter((e): e is EventRecord => e !== null);

const summarize = (evs: readonly EventRecord[]): JsonObject => {
  const state = apiSummaryBuilder.init();
  for (const e of evs) apiSummaryBuilder.add(state, e);
  return apiSummaryBuilder.finish(state);
};

const D = SCENARIO.dir;

const sim = new AgentSim();
runBehaviorScenario(sim);
const evs = events(sim.rows);
const summary = summarize(evs);

describe("behavior.exe pipeline (pure agent engine → host summary): file, registry, network", () => {
  it("file rows: paths under out-dir with ops, byte counts and the NAME_NOT_FOUND probe", () => {
    expect(summary.file).toEqual({
      distinct: 7,
      rows: [
        {
          path: `${D}\\bea_behavior_a.txt`,
          kind: "file",
          ops: ["create", "write", "open", "read", "rename"],
          ok: 6,
          failed: 0,
          read_bytes: 5,
          write_bytes: 5,
        },
        { path: `${D}\\bea_behavior_b.txt`, kind: "file", ops: ["rename_dest", "open", "delete"], ok: 3, failed: 0 },
        {
          path: `${D}\\does_not_exist.txt`,
          kind: "file",
          ops: ["stat"],
          ok: 0,
          failed: 1,
          first_status: "STATUS_OBJECT_NAME_NOT_FOUND",
        },
        { path: `${D}\\sub`, kind: "dir", ops: ["create", "open", "delete"], ok: 3, failed: 0 },
        { path: D, kind: "dir", ops: ["open", "list"], ok: 2, failed: 0 },
        {
          path: "C:\\T\\bea_missing_dll.dll",
          kind: "file",
          ops: ["stat"],
          ok: 0,
          failed: 1,
          first_status: "STATUS_OBJECT_NAME_NOT_FOUND",
        },
        {
          path: "C:\\Windows\\system32\\bea_missing_dll.dll",
          kind: "file",
          ops: ["stat"],
          ok: 0,
          failed: 1,
          first_status: "STATUS_OBJECT_NAME_NOT_FOUND",
        },
      ],
    });
  });

  it("registry rows: the HKCU fixture key with its values, the HKLM read resolved through NtQueryKey", () => {
    expect(summary.registry).toEqual({
      distinct: 3,
      rows: [
        { key: "HKCU", ops: ["open"], values: [], ok: 1, failed: 0 },
        {
          key: `HKCU\\Software\\BEA-Fixture\\${SCENARIO.regKey}`,
          ops: ["create", "set_value", "query_value", "delete_value", "open", "delete_key"],
          values: ["Answer", "Name"],
          ok: 7,
          failed: 0,
        },
        {
          key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
          ops: ["open", "query_value"],
          values: ["ProductName"],
          ok: 2,
          failed: 0,
        },
      ],
    });
    expect(sim.keyNameCalls).toEqual([0x14cn]); // only the root missing from the handle cache was queried
  });

  it("network: 127.0.0.1 TCP with 16 B each way (listener port from getsockname), the UDP row and DNS", () => {
    const port = String(SCENARIO.port);
    expect(summary.network).toEqual({
      endpoints: [
        {
          endpoint: `127.0.0.1:${port}/tcp`,
          ops: ["bind", "listen", "connect", "accept", "send", "recv", "close"],
          sent: 16,
          received: 16,
          failed: 0,
          host: "localhost",
        },
        { endpoint: `127.0.0.1:${port}/udp`, ops: ["sendto"], sent: 16, received: 0, failed: 0, host: "localhost" },
      ],
      dns: [{ name: "localhost", ok: true }],
      http: [],
    });
  });
});

describe("behavior.exe pipeline: process, modules, memory, nesting, fields", () => {
  it("process: one spawn (the nested NtCreateUserProcess is deduplicated) with the child pid, then open_process", () => {
    expect(summary.process).toEqual({
      rows: [
        {
          op: "spawn",
          image: "C:\\T\\behavior.exe",
          cmdline: '"C:\\T\\behavior.exe" --child --hold-ms 0',
          pid: SCENARIO.childPid,
          ok: true,
        },
        { op: "open_process", pid: SCENARIO.childPid, access: ["query_limited_information"], ok: true },
      ],
    });
  });

  it("module_load: mathlib loaded, the missing DLL failed, mf_lerp resolved", () => {
    expect(summary.module_load).toEqual({
      loaded: [{ path: "C:\\T\\mathlib.dll", base: `0x${SCENARIO.mathlibBase.toString(16)}`, size: 0x9000 }],
      failed: [{ name: "bea_missing_dll.dll", status: "STATUS_DLL_NOT_FOUND" }],
      resolved: [{ name: "mathlib.dll!mf_lerp", count: 1 }],
    });
  });

  it("memory: RW→RX flagged x_added, the RWX region flagged wx, RX→RW plain; frees aggregated", () => {
    expect(summary.memory_protection).toEqual({
      rows: [
        { op: "protect", va: "0x2000000", size: 4096, from: "rw-", to: "r-x", flags: ["x_added"] },
        { op: "alloc", va: "0x3000000", size: 4096, to: "rwx", flags: ["wx", "seen_at_free"] },
        { op: "protect", va: "0x2000000", size: 4096, from: "r-x", to: "rw-", flags: [] },
      ],
      aggregated: { allocs: 0, alloc_bytes: 0, protects: 2 },
    });
    expect(summary.totals).toMatchObject({ frees: 2 });
    expect(summary.truncated).toBe(false);
  });

  it("parent tracking: the DLL search probes are children of the failed LdrLoadDll row", () => {
    const load = evs.find((e) => e.op === "load_request" && e.ok === false);
    const probes = evs.filter(
      (e) => typeof e.target === "string" && e.target.endsWith("bea_missing_dll.dll") && e.op === "stat",
    );
    expect(load).toBeDefined();
    expect(probes).toHaveLength(2);
    for (const p of probes) expect(p.parent).toBe(load?.g);
    const spawn = evs.find((e) => e.api === "kernelbase!CreateProcessInternalW");
    const nt = evs.find((e) => e.api === "ntdll!NtCreateUserProcess");
    expect(nt?.parent).toBe(spawn?.g);
  });

  it("include_failed:false drops failed calls from events and the summary", () => {
    const okOnly = summarize(events(sim.rows, { ...DEFAULT_API_DECODERS, include_failed: false }));
    const files = (okOnly.file as { rows: { path: string }[] }).rows.map((r) => r.path);
    expect(files).not.toContain(`${D}\\does_not_exist.txt`);
    expect((okOnly.module_load as { failed: unknown[] }).failed).toEqual([]);
  });

  it("every event carries the S6 §5.4 api fields", () => {
    for (const e of evs)
      for (const k of [
        "seq",
        "t_ms",
        "tid",
        "profile",
        "op",
        "api",
        "target",
        "kind",
        "status",
        "ok",
        "bytes",
        "handle",
        "caller",
        "detail",
      ])
        expect(e).toHaveProperty(k);
    expect(evs.find((e) => e.op === "write")).toMatchObject({
      profile: "file",
      api: "ntdll!NtWriteFile",
      bytes: 5,
      status: "STATUS_SUCCESS",
      ok: true,
      caller: "0x401000",
    });
  });
});
