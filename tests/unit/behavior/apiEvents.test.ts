import { describe, expect, it } from "vitest";

import {
  DEFAULT_API_DECODERS,
  decodeApiRow,
  parseApiDecoders,
  type ApiRowContext,
} from "../../../src/application/behavior/apiEvents.js";
import { API_SUMMARY_LIST_CAP, apiSummaryBuilder } from "../../../src/application/behavior/ApiSummary.js";
import { API_KIND } from "../../../src/application/instruments/kinds/api.js";
import { RECORDING_KINDS } from "../../../src/application/instruments/kinds/index.js";
import type { JsonObject, JsonValue } from "../../../src/domain/json.js";
import type { EventRecord } from "../../../src/ports/recordings.js";

const ctx = (over: Partial<ApiRowContext> = {}): ApiRowContext => ({
  seq: 1,
  startedAtUs: 0,
  decoders: DEFAULT_API_DECODERS,
  frame: () => null,
  ...over,
});
const row = (
  api: number,
  args: JsonObject,
  ret: JsonValue,
  extra: { g?: number; parent?: number; caller?: string } = {},
): JsonValue => [extra.g ?? 1, 12_345, 7, 0, extra.parent ?? 0, api, args, ret, extra.caller ?? "0x401000"];

describe("api/1 row decoding (S6 §5.4)", () => {
  it("rejects malformed tuples and unknown ids without throwing", () => {
    for (const bad of [null, 3, "x", [], [1, 2, 3], { a: 1 }, [1, 2, 3, 4, 5, "id", {}, null, "0x0"]] as JsonValue[])
      expect(decodeApiRow(bad, ctx())).toBeNull();
    expect(decodeApiRow(row(9999, {}, "0x0"), ctx())).toBeNull();
    // mistyped cells degrade to placeholders, never exceptions
    expect(decodeApiRow(row(1, { path: 5, iosb: "zz", disposition: "x" }, "0x0"), ctx())).toMatchObject({
      op: "overwrite",
      target: "<handle ?>",
    });
  });

  it("file: NtCreateFile op from IoStatus (created/opened/overwritten), else from the disposition", () => {
    const created = decodeApiRow(
      row(1, { path: { s: "\\??\\C:\\a" }, iosb: "0x2", disposition: 5, access: 0x40100080, options: 0x60 }, "0x0"),
      ctx(),
    );
    expect(created).toMatchObject({
      op: "create",
      target: "C:\\a",
      kind: "file",
      status: "STATUS_SUCCESS",
      ok: true,
      t_ms: 12.35,
      tid: 7,
    });
    expect(created?.detail).toEqual({ access: ["read", "write"], disposition: "overwrite_if", result: "created" });
    expect(decodeApiRow(row(1, { path: { s: "\\??\\C:\\a" }, iosb: "0x3", disposition: 5 }, "0x0"), ctx())?.op).toBe(
      "overwrite",
    );
    expect(
      decodeApiRow(row(1, { path: { s: "\\??\\C:\\d" }, disposition: 1, options: 1 }, "0xc0000034"), ctx()),
    ).toMatchObject({ op: "open", kind: "dir", ok: false, status: "STATUS_OBJECT_NAME_NOT_FOUND" });
  });

  it("file: set_info classes (rename with destination, delete, truncate) and async reads without byte counts", () => {
    const rename = decodeApiRow(
      row(
        5,
        { handle: "0x10", handle_name: { s: "\\??\\C:\\a" }, class: 10, info_target: { s: "\\??\\C:\\b" } },
        "0x0",
      ),
      ctx(),
    );
    expect(rename).toMatchObject({ op: "rename", target: "C:\\a", detail: { class: 10, to: "C:\\b" } });
    expect(decodeApiRow(row(5, { handle: "0x10", class: 64, info_delete: 1 }, "0x0"), ctx())).toMatchObject({
      op: "delete",
      target: "<handle 0x10>",
    });
    expect(decodeApiRow(row(5, { handle: "0x10", class: 20 }, "0x0"), ctx())?.op).toBe("truncate");
    expect(decodeApiRow(row(9, { handle: "0x10", buffer_len: null }, "0x103"), ctx())).toMatchObject({
      op: "read",
      bytes: null,
      ok: true,
      detail: { bytes_unknown: true },
    });
  });

  it("registry: open/create (disposition), values with type names", () => {
    expect(
      decodeApiRow(row(22, { key: { s: "\\REGISTRY\\MACHINE\\X" }, disposition: 2, access: 0xf003f }, "0x0"), ctx()),
    ).toMatchObject({ op: "open", target: "HKLM\\X", kind: "key" });
    expect(
      decodeApiRow(
        row(
          24,
          { handle: "0x20", handle_name: { s: "\\REGISTRY\\MACHINE\\X" }, value: { s: "V" }, type: 4, size: 4 },
          "0x0",
        ),
        ctx(),
      ),
    ).toMatchObject({
      op: "set_value",
      target: "HKLM\\X",
      detail: { value: "V", type: "REG_DWORD", size: 4 },
    });
  });
});

describe("api/1 row decoding (S6 §5.4): network, process, memory, switches", () => {
  it("network: Winsock failures name the WSA error; DNS rc codes; HTTP queries stripped", () => {
    expect(
      decodeApiRow(
        row(
          64,
          {
            socket: "0x1",
            socket_proto: { s: "tcp" },
            remote_family: 2,
            remote_addr: { s: "10.0.0.1" },
            remote_port: 81,
            last_error: 10061,
          },
          -1,
        ),
        ctx(),
      ),
    ).toMatchObject({
      op: "connect",
      target: "10.0.0.1:81/tcp",
      ok: false,
      status: "WSAECONNREFUSED",
    });
    expect(decodeApiRow(row(77, { node: { s: "nx.test" } }, 11001), ctx())).toMatchObject({
      op: "dns",
      target: "nx.test",
      ok: false,
      status: "WSAHOST_NOT_FOUND",
    });
    expect(
      decodeApiRow(row(87, { url: { s: "https://h.test/p?secret=1" }, flags: 0x0080_0000 }, "0x99"), ctx()),
    ).toMatchObject({
      op: "http_request",
      target: "https://h.test/p",
      detail: { secure: true, query_stripped: true },
    });
  });

  it("process: remote vs local threads, self-termination, flagged access", () => {
    expect(decodeApiRow(row(104, { process: "0xffffffffffffffff", start: "0x401500" }, "0x0"), ctx())).toMatchObject({
      op: "create_thread",
      target: "self",
      detail: { remote: false },
    });
    expect(decodeApiRow(row(104, { process: "0x88", process_name: { s: "pid:12" } }, "0x0"), ctx())).toMatchObject({
      target: "pid:12",
      detail: { remote: true },
    });
    expect(decodeApiRow(row(103, { process: "0xffffffffffffffff", status: 3 }, null), ctx())).toMatchObject({
      op: "terminate",
      target: "self",
      status: "no_return",
      ok: true,
    });
    expect(decodeApiRow(row(102, { client_pid: 9, access: 0x1fffff }, "0x0"), ctx())?.detail).toEqual({
      access: ["all_access"],
      flagged: ["all_access"],
    });
  });

  it("memory: x_added / wx / remote flags; kernelbase allocations use the returned address", () => {
    expect(
      decodeApiRow(
        row(
          50,
          {
            process: "0xffffffffffffffff",
            base: "0x1000",
            base_out: "0x1000",
            size: "0x2000",
            size_out: "0x2000",
            new: 0x40,
            old: 0x04,
          },
          "0x0",
        ),
        ctx(),
      )?.detail,
    ).toEqual({
      size: 0x2000,
      to: "rwx",
      from: "rw-",
      flags: ["wx", "x_added"],
    });
    expect(
      decodeApiRow(
        row(52, { process: "0x88", base: "0x0", size: "0x1000", protect: 0x20, type: 0x3000 }, "0x7000000"),
        ctx(),
      ),
    ).toMatchObject({
      op: "alloc",
      target: "0x7000000",
      detail: { flags: ["remote", "x"], type: ["commit", "reserve"], to: "r-x" },
    });
  });

  it("decoders: include_failed and caller switches; parse tolerates junk", () => {
    const failed = row(3, { path: { s: "\\??\\C:\\x" } }, "0xc0000034");
    expect(decodeApiRow(failed, ctx({ decoders: { ...DEFAULT_API_DECODERS, include_failed: false } }))).toBeNull();
    expect(decodeApiRow(failed, ctx({ decoders: { ...DEFAULT_API_DECODERS, caller: false } }))?.caller).toBeNull();
    expect(
      decodeApiRow(failed, ctx({ frame: (va) => (va === "0x401000" ? "behavior.exe+0x1000" : null) }))?.caller,
    ).toBe("behavior.exe+0x1000");
    expect(parseApiDecoders(null)).toEqual(DEFAULT_API_DECODERS);
    expect(
      parseApiDecoders({ include_failed: false, caller: false, user_sid: "S-1-5-21-1", catalog_minor: 0 }),
    ).toEqual({
      catalog_minor: 0,
      include_failed: false,
      caller: false,
      user_sid: "S-1-5-21-1",
    });
  });
});

describe("recording kind api (RecordingKindSpec)", () => {
  it("is registered in the pre-wired kind index with the api field dictionary", () => {
    expect(RECORDING_KINDS.api).toBe(API_KIND);
    expect(API_KIND.rowKinds).toEqual(["api/1"]);
    expect(API_KIND.fields.map((f) => f.name)).toEqual(
      expect.arrayContaining([
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
      ]),
    );
  });

  it("decodes stream records with the recording's decoders and frame mapper", () => {
    const out = [
      ...API_KIND.decode(
        { seq: 42, module_map_epoch: 1, fields: row(3, { path: { s: "\\??\\C:\\x" } }, "0x0") },
        {
          sessionId: "s",
          decoders: { include_failed: true, caller: true },
          startedAtUs: 2_345,
          frame: () => ({ at: "m.exe+0x1", static: null }),
        },
      ),
    ];
    expect(out).toEqual([
      expect.objectContaining({ seq: 42, op: "stat", target: "C:\\x", t_ms: 10, caller: "m.exe+0x1" }),
    ]);
    expect([
      ...API_KIND.decode(
        { seq: 1, module_map_epoch: null, fields: "junk" },
        { sessionId: "s", decoders: null, startedAtUs: 0, frame: () => ({ at: null, static: null }) },
      ),
    ]).toEqual([]);
  });

  it("folds CreateProcess's own writes into the child into its spawn row; other writes stay rows (ONBOARD-1)", () => {
    const state = apiSummaryBuilder.init();
    const ev = (fields: Record<string, unknown>) =>
      ({ seq: 1, profile: "process", ok: true, ...fields }) as EventRecord;
    // leave order: the NtCreateUserProcess and the two parameter writes (children of g=34) come before the spawn
    apiSummaryBuilder.add(
      state,
      ev({ op: "spawn", api: "ntdll!NtCreateUserProcess", g: 35, parent: 34, target: "C:\\b.exe" }),
    );
    apiSummaryBuilder.add(
      state,
      ev({
        op: "write_process_memory",
        api: "ntdll!NtWriteVirtualMemory",
        g: 36,
        parent: 34,
        target: "C:\\b.exe",
        size: 4544,
      }),
    );
    apiSummaryBuilder.add(
      state,
      ev({
        op: "write_process_memory",
        api: "ntdll!NtWriteVirtualMemory",
        g: 37,
        parent: 34,
        target: "C:\\b.exe",
        size: 8,
      }),
    );
    apiSummaryBuilder.add(
      state,
      ev({
        op: "spawn",
        api: "kernelbase!CreateProcessInternalW",
        g: 34,
        parent: 0,
        target: "C:\\b.exe",
        detail: { pid: 13292 },
      }),
    );
    // a real injection: a top-level write and one nested in a non-spawn wrapper
    apiSummaryBuilder.add(
      state,
      ev({ op: "write_process_memory", api: "ntdll!NtWriteVirtualMemory", g: 50, parent: 0, target: "C:\\victim.exe" }),
    );
    apiSummaryBuilder.add(
      state,
      ev({
        op: "write_process_memory",
        api: "ntdll!NtWriteVirtualMemory",
        g: 61,
        parent: 60,
        target: "C:\\victim.exe",
      }),
    );
    const rows = (apiSummaryBuilder.finish(state).process as { rows: { op: string; image?: string }[] }).rows;
    expect(rows.filter((r) => r.op === "spawn")).toEqual([
      expect.objectContaining({ image: "C:\\b.exe", pid: 13292, setup_writes: 2, setup_write_bytes: 4552 }),
    ]);
    expect(rows.filter((r) => r.op === "write_process_memory").map((r) => r.image)).toEqual([
      "C:\\victim.exe",
      "C:\\victim.exe",
    ]);
  });

  it("summary lists are capped at 50 with truncated:true; only traced profiles appear", () => {
    const state = apiSummaryBuilder.init();
    for (let i = 0; i < API_SUMMARY_LIST_CAP + 5; i++) {
      const e = decodeApiRow(
        row(3, { path: { s: `\\??\\C:\\f${String(i)}` } }, "0x0", { g: i + 1 }),
        ctx({ seq: i + 1 }),
      );
      if (e !== null) apiSummaryBuilder.add(state, e as EventRecord);
    }
    const summary = apiSummaryBuilder.finish(state);
    expect((summary.file as { rows: unknown[]; distinct: number }).rows).toHaveLength(API_SUMMARY_LIST_CAP);
    expect(summary.truncated).toBe(true);
    expect(summary.totals).toEqual({ file: API_SUMMARY_LIST_CAP + 5 });
    expect(Object.keys(summary).sort()).toEqual(["file", "totals", "truncated"]);
  });
});
