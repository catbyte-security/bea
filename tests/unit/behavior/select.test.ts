import { describe, expect, it } from "vitest";

import { diffExecRanges, selectApis, type RangeView } from "../../../src/agent/pure/profileSelect.js";
import type { Hex } from "../../../src/shared/hex.js";

const exportsOf = (r: ReturnType<typeof selectApis>) => r.specs.map((s) => s.export);

describe("profile selection (S4 §10.6 Install step 1)", () => {
  it("core APIs only by default; NtClose joins file/registry; nothing denied", () => {
    const file = selectApis(["file"], {});
    expect(exportsOf(file)).toEqual([
      "NtCreateFile",
      "NtOpenFile",
      "NtQueryAttributesFile",
      "NtQueryFullAttributesFile",
      "NtSetInformationFile",
      "NtQueryDirectoryFileEx",
      "NtQueryDirectoryFile",
      "NtDeleteFile",
      "NtClose",
    ]);
    expect(file.denied).toEqual([]);
    expect(exportsOf(selectApis(["registry"], {}))).toContain("NtClose");
    expect(exportsOf(selectApis(["network"], {}))).not.toContain("NtClose");
  });

  it("sub-options switch their families on and off", () => {
    expect(exportsOf(selectApis(["file"], { file: { io: true, capture_bytes: 0, track_handles: false } }))).toEqual(
      expect.arrayContaining(["NtReadFile", "NtWriteFile"]),
    );
    expect(
      exportsOf(selectApis(["file"], { file: { io: false, capture_bytes: 0, track_handles: false } })),
    ).not.toContain("NtClose");
    const mem = selectApis(["memory_protection"], {
      memory_protection: { frees: true, sections: false, exec_region_scan_ms: 0 },
    });
    expect(exportsOf(mem)).toContain("NtFreeVirtualMemory");
    expect(exportsOf(mem)).not.toContain("NtMapViewOfSection");
    const net = selectApis(["network"], { network: { capture_payload_bytes: 0, http: false, dns: false } });
    expect(exportsOf(net)).not.toContain("GetAddrInfoW");
    expect(exportsOf(net)).not.toContain("WinHttpConnect");
    expect(exportsOf(selectApis(["module_load"], { module_load: { resolve_procedures: false } }))).toEqual([
      "LdrLoadDll",
      "LdrUnloadDll",
    ]);
  });

  it("all six profiles with trace_api's options stay under max_profile_api_hooks (128)", () => {
    const all = selectApis(["file", "registry", "network", "process", "module_load", "memory_protection"], {
      file: { io: true, capture_bytes: 0, track_handles: true },
      registry: { capture_value_bytes: 0, query_key: true, enumerate: true },
      network: { capture_payload_bytes: 0, http: true, dns: true },
      process: { cross_process_memory: true, apc_and_context: true },
      module_load: { resolve_procedures: true },
      memory_protection: { frees: true, sections: true, exec_region_scan_ms: 1000 },
    });
    expect(all.specs.length).toBe(69);
    expect(all.specs.length).toBeLessThanOrEqual(128);
  });
});

describe("memmap diff (S4 §10.7)", () => {
  const r = (base: string, protection: string, size = 4096, module: string | null = null): RangeView => ({
    base: base as Hex,
    size,
    protection,
    module,
  });

  it("reports new-exec / new-rwx for non-module regions, then prot-change and gone", () => {
    const tracked = new Map<Hex, RangeView>();
    expect(diffExecRanges(tracked, [r("0x1000", "r-x", 4096, "a.dll")], () => null)).toEqual([]);
    const first = diffExecRanges(tracked, [r("0x2000", "r-x"), r("0x3000", "rwx")], () => null);
    expect(first.map((e) => [e.ev, e.base])).toEqual([
      ["new-exec", "0x2000"],
      ["new-rwx", "0x3000"],
    ]);
    expect(diffExecRanges(tracked, [r("0x2000", "r-x"), r("0x3000", "rwx")], () => null)).toEqual([]);
    const second = diffExecRanges(tracked, [r("0x2000", "rwx")], (base) => (base === "0x3000" ? null : null));
    expect(second.map((e) => [e.ev, e.base, e.protection])).toEqual([
      ["prot-change", "0x2000", "rwx"],
      ["gone", "0x3000", "rwx"],
    ]);
    // left the executable set but still mapped (RX → RW): prot-change with the current protection
    const third = diffExecRanges(tracked, [], (base) => (base === "0x2000" ? r("0x2000", "rw-") : null));
    expect(third).toEqual([{ ev: "prot-change", base: "0x2000", size: 4096, protection: "rw-", module: null }]);
    expect(tracked.size).toBe(0);
  });
});
