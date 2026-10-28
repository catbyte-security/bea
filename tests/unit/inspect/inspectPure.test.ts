import { describe, expect, it } from "vitest";

import { pointerFrom, walkChain } from "../../../src/application/inspect/chain.js";
import { pageOf, refText, splitAt } from "../../../src/application/inspect/common.js";
import { insnText, liveCoverage, rowTarget, textTarget } from "../../../src/application/inspect/disassemble.js";
import { rangeKind, snapshotKey } from "../../../src/application/inspect/listMemoryRanges.js";
import { matchesFilter } from "../../../src/application/inspect/listModules.js";
import { gprsOf, mainEntryOf } from "../../../src/application/inspect/listThreads.js";
import { decodeView, shortestF32, shortestF64 } from "../../../src/application/inspect/views.js";
import { listMemoryRangesInputSchema } from "../../../src/contracts/areas/inspect.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import { err, ok, type Result } from "../../../src/domain/result.js";
import type { ProcessInfo } from "../../../src/shared/agentProtocol.js";

/** Pure parts of the inspect services (WP6): views, chains, row text/targets, coverage, paging, filters. */
const bytesOf = (...parts: number[]) => new Uint8Array(parts);
const le = (width: 4 | 8, setter: (dv: DataView) => void) => {
  const b = new Uint8Array(width);
  setter(new DataView(b.buffer));
  return b;
};

describe("read_memory views (S6 §2.3)", () => {
  it("prints f32 as the shortest decimal that round-trips, and float specials as names", () => {
    expect(shortestF32(Math.fround(14.905))).toBe(14.905);
    expect(shortestF32(Math.fround(0.1))).toBe(0.1);
    expect(shortestF32(20)).toBe(20);
    expect(shortestF32(Number.NaN)).toBe("NaN");
    expect(shortestF32(-Infinity)).toBe("-Infinity");
    expect(shortestF64(0.1 + 0.2)).toBe(0.30000000000000004);
    expect(shortestF64(Infinity)).toBe("Infinity");
  });

  it("decodes integer, 64-bit, pointer, bool and float views little-endian", () => {
    const b = le(8, (dv) => dv.setBigUint64(0, 0xfffffffffffffffen, true));
    expect(decodeView(b, "u64").values).toEqual(["18446744073709551614"]);
    expect(decodeView(b, "i64").values).toEqual(["-2"]);
    expect(decodeView(b, "ptr").values).toEqual(["0xfffffffffffffffe"]);
    expect(decodeView(b, "i32").values).toEqual([-2, -1]);
    expect(decodeView(b, "u16").values).toEqual([0xfffe, 0xffff, 0xffff, 0xffff]);
    expect(decodeView(bytesOf(0, 1, 2), "bool").values).toEqual([false, true, true]);
    expect(
      decodeView(
        le(4, (dv) => dv.setFloat32(0, 20.5, true)),
        "f32",
      ).values,
    ).toEqual([20.5]);
    expect(
      decodeView(
        le(8, (dv) => dv.setFloat64(0, -0.25, true)),
        "f64",
      ).values,
    ).toEqual([-0.25]);
    // a trailing partial element is not decoded
    expect(decodeView(bytesOf(1, 2, 3, 4, 5), "u32").values).toEqual([0x04030201]);
    expect(decodeView(bytesOf(0xab, 0x01), "hex").data).toBe("ab01");
    expect(decodeView(bytesOf(0xff, 0xfe), "base64").data).toBe("//4=");
  });

  it("stops text at the first NUL (utf16: an aligned zero unit) and caps typed values", () => {
    expect(decodeView(new Uint8Array(Buffer.from("héllo\u0000rest", "utf8")), "utf8").text).toBe("héllo");
    expect(decodeView(new Uint8Array(Buffer.from("BEA_WIDE\u0000x", "utf16le")), "utf16").text).toBe("BEA_WIDE");
    expect(decodeView(bytesOf(0x41, 0x00, 0x00, 0x42, 0x00, 0x00), "utf16").text).toBe("A䈀");
    const big = decodeView(new Uint8Array(20_000), "u8");
    expect(big.values?.length).toBe(16_384);
    expect(big).toMatchObject({ valuesCapped: true, elements: 20_000 });
  });
});

describe("pointer chains (Cheat Engine semantics)", () => {
  const memory = new Map<bigint, bigint>([
    [0x1000n, 0x2000n],
    [0x2008n, 0x3000n],
  ]);
  const reader = async (va: bigint): Promise<Result<bigint, BeaError>> => {
    const v = memory.get(va);
    return v === undefined
      ? err({ _tag: "MemoryAccessFailed", operation: "t", address: `0x${va.toString(16)}`, access: "read", size: 8 })
      : ok(v);
  };

  it("walks [[A]+d0]+d1 and records every step", async () => {
    expect(await walkChain(reader, 0x1000n, [8, 8])).toEqual({
      ok: true,
      value: {
        final: 0x3008n,
        steps: [
          { address: "0x1000", value: "0x2000" },
          { address: "0x2008", value: "0x3000" },
        ],
      },
    });
    expect(await walkChain(reader, 0x1000n, undefined)).toEqual({ ok: true, value: { final: 0x1000n, steps: [] } });
    const negative = await walkChain(reader, 0x1000n, [-0x1000]);
    expect(negative.ok && negative.value.final).toBe(0x1000n);
  });

  it("returns the failing step's error with the chain so far", async () => {
    const r = await walkChain(reader, 0x1000n, [8, 0x10, 4]);
    expect(r.ok).toBe(false);
    if (!r.ok)
      expect(r.error.diagnostics).toEqual({
        chain: [
          { address: "0x1000", value: "0x2000" },
          { address: "0x2008", value: "0x3000" },
        ],
        chain_failed_at: "0x3010",
      });
    expect(pointerFrom(bytesOf(1, 0, 0, 0, 0, 0, 0, 0x80))).toBe(0x8000000000000001n);
    expect(pointerFrom(bytesOf(1, 2, 3))).toBeNull();
  });
});

describe("rows, refs and paging", () => {
  it("pages without coverage and splits module text", () => {
    expect(pageOf(0, 100, 250)).toEqual({ offset: 0, limit: 100, total: 250, next_offset: 100 });
    expect(pageOf(200, 100, 250).next_offset).toBeNull();
    expect(splitAt("game.exe+0x1a2b")).toEqual({ module: "game.exe", rva: "0x1a2b" });
    expect(splitAt("a+b.dll@0x7ff0000+0x10")).toEqual({ module: "a+b.dll@0x7ff0000", rva: "0x10" });
    expect(splitAt("0x1234")).toBeNull();
    expect(splitAt(null)).toBeNull();
    expect(refText({ va: "0x1", at: "m.dll+0x1", static: "m.dll:0x180000001" })).toBe("m.dll+0x1 m.dll:0x180000001");
    expect(refText({ va: "0x20000000", at: null, static: null })).toBe("0x20000000");
  });

  it("derives agent row text, targets and emulator text targets", () => {
    expect(insnText({ mnemonic: "ret", op_str: "" })).toBe("ret");
    expect(insnText({ mnemonic: "ja", op_str: "0x10" })).toBe("ja 0x10");
    expect(rowTarget({ branch_target: "0x10", mem_targets: ["0x20"] })).toBe(0x10n);
    expect(rowTarget({ branch_target: null, mem_targets: ["0x20"] })).toBe(0x20n);
    expect(rowTarget({ branch_target: null, mem_targets: [] })).toBeNull();
    expect(textTarget("call 0x180001000", 0x180001008n, 5)).toBe(0x180001000n);
    expect(textTarget("jne 0x10", 0n, 2)).toBe(0x10n);
    expect(textTarget("movss xmm0, dword ptr [rip + 0x8]", 0x1000n, 8)).toBe(0x1010n);
    expect(textTarget("lea rax, [rip - 0x10]", 0x1000n, 7)).toBe(0xff7n);
    expect(textTarget("mov eax, 0x10", 0n, 5)).toBeNull();
    expect(textTarget("call rax", 0n, 2)).toBeNull();
  });

  it("maps agent stops to coverage and limitations", () => {
    expect(liveCoverage({ stop: null, truncated: false, overlay_used: false })).toEqual({
      coverage: { status: "complete", truncated: false, reasons: [] },
      limitations: [],
    });
    const capped = liveCoverage({ stop: { reason: "limit", at: "0x10" }, truncated: true, overlay_used: true });
    expect(capped.coverage).toMatchObject({ status: "partial", truncated: true, reasons: ["row_cap"] });
    expect(capped.limitations).toEqual([LIMITATIONS.CAP("instruction", 4096), LIMITATIONS.HOOKED_BYTES_RESTORED]);
    expect(
      liveCoverage({ stop: { reason: "access-violation", at: "0x10" }, truncated: false, overlay_used: false })
        .coverage,
    ).toMatchObject({ status: "partial", truncated: false, reasons: ["unreadable_memory"] });
  });

  it("filters modules, maps range kinds and keys snapshots by filters", () => {
    expect(matchesFilter("KERNEL32.DLL", "kernel")).toBe(true);
    expect(matchesFilter("game.exe", undefined)).toBe(true);
    expect(matchesFilter("game.exe", "ntdll")).toBe(false);
    expect([rangeKind("module"), rangeKind("private"), rangeKind("malloc")]).toEqual(["image", "private", "private"]);
    const a = listMemoryRangesInputSchema.parse({ session_id: "11111111-1111-4111-8111-111111111111" });
    expect(snapshotKey(a)).toBe(snapshotKey({ ...a, offset: 200, limit: 5 }));
    expect(snapshotKey(a)).not.toBe(snapshotKey({ ...a, protection: "rw-" }));
  });

  it("finds the main entry and keeps only general registers", () => {
    const info = { main_module: { base: "0x7ff600000000", pe: { entry_rva: "0x1400" } } } as unknown as ProcessInfo;
    expect(mainEntryOf(info)).toBe(0x7ff600001400n);
    expect(mainEntryOf({ main_module: { base: "0x1", pe: null } } as unknown as ProcessInfo)).toBeNull();
    expect(gprsOf({ rax: "0x1", RIP: "0x2", xmm0: "0x3" })).toEqual({ rax: "0x1", rip: "0x2" });
    expect(gprsOf(null)).toEqual({});
  });
});
