import { describe, expect, it } from "vitest";

import {
  API_CATALOG,
  HOOK_CAUTION_LIST,
  HOOK_DENY_LIST,
  PROFILE_SUB_OPTIONS,
  PSEUDO_API,
  apiById,
  apiName,
} from "../../../src/shared/apiProfiles.js";

/** S4 §10.5 catalog invariants: stable wire ids, the level rules of §10.1, decoder argument references. */
describe("API catalog (src/shared/apiProfiles.ts)", () => {
  it("ids are the S4 §10.5 wire ids, unique, and resolvable", () => {
    const ids = API_CATALOG.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 40, 41, 42, 50, 51, 52, 53, 54, 55,
      56, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
      87, 100, 101, 102, 103, 104, 105, 106, 107, 108,
    ]);
    for (const s of API_CATALOG) expect(apiById(s.id)).toBe(s);
    expect(apiById(9999)).toBeUndefined();
  });

  it("pseudo API ids never collide with catalog ids", () => {
    for (const p of Object.values(PSEUDO_API)) expect(apiById(p.id)).toBeUndefined();
  });

  it("never kernel32; kernelbase only for CreateProcessInternalW and VirtualAllocEx/VirtualAlloc2 (S4 §10.1 rules 3-4)", () => {
    expect(API_CATALOG.some((s) => (s.module as string) === "kernel32.dll")).toBe(false);
    expect(API_CATALOG.filter((s) => s.module === "kernelbase.dll").map((s) => s.export)).toEqual([
      "VirtualAllocEx",
      "VirtualAlloc2",
      "CreateProcessInternalW",
    ]);
  });

  it("no deny-listed or caution-listed API is in the catalog (F8, S4 §10.8)", () => {
    const names = new Set(API_CATALOG.map((s) => apiName(s).toLowerCase()));
    for (const d of HOOK_DENY_LIST) expect(names.has(d.api.toLowerCase())).toBe(false);
    for (const c of HOOK_CAUTION_LIST) expect(names.has(c.toLowerCase())).toBe(false);
    expect(HOOK_DENY_LIST.map((d) => d.api)).toEqual([
      "ntdll.dll!NtAllocateVirtualMemory",
      "kernelbase.dll!VirtualAlloc",
    ]);
  });

  it("argument slots are unique per API and decoder references stay inside the Win64 argument list", () => {
    for (const s of API_CATALOG) {
      const slots = s.args.map((a) => a.slot);
      expect(new Set(slots).size, apiName(s)).toBe(slots.length);
      const names = s.args.map((a) => a.name);
      expect(new Set(names).size, apiName(s)).toBe(names.length);
      for (const a of s.args) {
        expect(a.slot).toBeGreaterThanOrEqual(0);
        expect(a.slot).toBeLessThan(12);
        const d = a.d;
        const refs = [
          "len_arg" in d ? d.len_arg : null,
          "count_arg" in d ? d.count_arg : null,
          "class_arg" in d ? d.class_arg : null,
          d.k === "regdata" ? d.type_arg : null,
          d.k === "regdata" ? d.size_arg : null,
        ].filter((x): x is number => x !== null);
        for (const r of refs) expect(r, `${apiName(s)} ${a.name}`).toBeLessThan(12);
      }
      for (const rule of [s.emit_when, s.noreturn_when])
        if (rule !== undefined) expect(names, apiName(s)).toContain(rule.arg);
    }
  });

  it("InternetConnectW never reads the user name or password slots (S6 §6.1)", () => {
    const spec = API_CATALOG.find((s) => s.export === "InternetConnectW");
    expect(spec?.args.map((a) => a.slot)).not.toContain(3);
    expect(spec?.args.map((a) => a.slot)).not.toContain(4);
  });

  it("only NtClose is row-less; lazy modules are exactly the non-ntdll/kernelbase ones", () => {
    expect(API_CATALOG.filter((s) => !s.rows).map((s) => s.export)).toEqual(["NtClose"]);
    for (const s of API_CATALOG)
      expect(s.lazy_module, apiName(s)).toBe(s.module !== "ntdll.dll" && s.module !== "kernelbase.dll");
  });

  it("every non-core sub belongs to its profile's sub-options; defaults follow S4 (io, enumerate, query_key, frees, sections, http, apc off)", () => {
    for (const s of API_CATALOG)
      if (s.sub !== "core" && s.sub !== "track_handles")
        expect(PROFILE_SUB_OPTIONS[s.profile], apiName(s)).toContain(s.sub);
    const off = API_CATALOG.filter((s) => !s.default_on).map((s) => s.sub);
    expect(new Set(off)).toEqual(
      new Set(["io", "enumerate", "query_key", "frees", "sections", "http", "cross_process_memory", "apc_and_context"]),
    );
  });
});
