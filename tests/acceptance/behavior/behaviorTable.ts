import { join } from "node:path";

import { expect } from "vitest";

/** reg.exe by absolute path (registry-key cleanup check). */
export const REG_EXE = join(process.env["SystemRoot"] ?? String.raw`C:\Windows`, "System32", "reg.exe");

/**
 * The behavior.exe expectation table (S6 §10.1 steps; S6 §10.8 trace_api row) asserted on an ApiSummary. Shared by
 * the raw-Frida acceptance (profilesRaw.test.ts) and the MCP acceptance (traceApi.test.ts).
 */
export interface BehaviorRun {
  readonly outDir: string;
  readonly regKey: string;
  readonly netPort: number;
  readonly childPid: number;
  readonly exePath: string;
  readonly mathlibPath: string;
}

export const expectBehaviorTable = (summary: Readonly<Record<string, unknown>>, t: BehaviorRun): void => {
  const text = JSON.stringify(summary);

  // ------------------------------------------------------------ file
  const files = (
    summary.file as {
      rows: {
        path: string;
        kind: string;
        ops: string[];
        read_bytes?: number;
        write_bytes?: number;
        failed: number;
        first_status?: string;
      }[];
    }
  ).rows;
  const file = (leaf: string) => files.find((r) => r.path.toLowerCase() === `${t.outDir}\\${leaf}`.toLowerCase());
  expect(file("bea_behavior_a.txt"), text).toMatchObject({ kind: "file", read_bytes: 5, write_bytes: 5 });
  expect(file("bea_behavior_a.txt")?.ops).toEqual(
    expect.arrayContaining(["create", "write", "open", "read", "rename"]),
  );
  expect(file("bea_behavior_b.txt")?.ops).toEqual(expect.arrayContaining(["rename_dest", "delete"]));
  expect(file("does_not_exist.txt")).toMatchObject({
    ops: ["stat"],
    failed: 1,
    first_status: "STATUS_OBJECT_NAME_NOT_FOUND",
  });
  expect(file("sub")).toMatchObject({ kind: "dir" });
  expect(file("sub")?.ops).toEqual(expect.arrayContaining(["create", "delete"]));
  const listed = files.find((r) => r.path.toLowerCase() === t.outDir.toLowerCase());
  expect(listed?.ops, JSON.stringify(files.map((f) => [f.path, f.ops]))).toContain("list");

  // ------------------------------------------------------------ registry
  const keys = (summary.registry as { rows: { key: string; ops: string[]; values: string[] }[] }).rows;
  const fixtureKey = keys.find((k) => k.key === `HKCU\\Software\\BEA-Fixture\\${t.regKey}`);
  expect(fixtureKey, JSON.stringify(keys.map((k) => k.key))).toBeDefined();
  expect(fixtureKey?.ops).toEqual(
    expect.arrayContaining(["create", "set_value", "query_value", "delete_value", "delete_key"]),
  );
  expect(fixtureKey?.values).toEqual(expect.arrayContaining(["Answer", "Name"]));
  const nt = keys.find((k) => k.key.toLowerCase() === "hklm\\software\\microsoft\\windows nt\\currentversion");
  expect(nt?.values).toContain("ProductName");

  // ------------------------------------------------------------ network
  const net = summary.network as {
    endpoints: { endpoint: string; sent: number; received: number; ops: string[] }[];
    dns: { name: string; ok: boolean }[];
  };
  const tcp = net.endpoints.find((e) => e.endpoint === `127.0.0.1:${String(t.netPort)}/tcp`);
  expect(tcp, JSON.stringify(net.endpoints)).toMatchObject({ sent: 16, received: 16 });
  expect(tcp?.ops).toEqual(expect.arrayContaining(["bind", "listen", "connect", "accept", "send", "recv"]));
  expect(net.endpoints.find((e) => e.endpoint === `127.0.0.1:${String(t.netPort)}/udp`)).toMatchObject({ sent: 16 });
  expect(net.dns).toContainEqual({ name: "localhost", ok: true });

  // ------------------------------------------------------------ process
  const procs = (
    summary.process as { rows: { op: string; image?: string; cmdline?: string; pid?: number; ok: boolean }[] }
  ).rows;
  const spawn = procs.filter((p) => p.op === "spawn");
  expect(spawn, JSON.stringify(procs)).toHaveLength(1);
  expect(spawn[0]).toMatchObject({ pid: t.childPid, ok: true });
  expect(spawn[0]?.image?.toLowerCase()).toBe(t.exePath.toLowerCase());
  expect(spawn[0]?.cmdline).toContain("--child");
  expect(procs).toContainEqual(expect.objectContaining({ op: "open_process", pid: t.childPid, ok: true }));

  // ------------------------------------------------------------ module_load
  const mods = summary.module_load as {
    loaded: { path: string }[];
    failed: { name: string; status: string }[];
    resolved: { name: string }[];
  };
  expect(mods.loaded.map((m) => m.path.toLowerCase())).toContain(t.mathlibPath.toLowerCase());
  expect(mods.failed).toContainEqual({ name: "bea_missing_dll.dll", status: "STATUS_DLL_NOT_FOUND" });
  expect(mods.resolved.map((r) => r.name)).toContain("mathlib.dll!mf_lerp");

  // ------------------------------------------------------------ memory_protection
  const mem = (summary.memory_protection as { rows: { op: string; from?: string; to: string; flags: string[] }[] })
    .rows;
  expect(mem, JSON.stringify(mem)).toContainEqual(
    expect.objectContaining({ op: "protect", from: "rw-", to: "r-x", flags: ["x_added"] }),
  );
  expect(mem.some((r) => r.op === "protect" && r.from === "r-x" && r.to === "rw-")).toBe(true);
  expect(mem.some((r) => r.op === "alloc" && r.flags.includes("wx"))).toBe(true);

  // ------------------------------------------------------------ BEA/Frida's own activity is absent
  expect(text.toLowerCase()).not.toContain("frida");
};
