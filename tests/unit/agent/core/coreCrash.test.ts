// BEA-FEEDBACK.md item 4 (pure/coreCrash.ts): the agent's crash policy defaults and clamping, and the first-chance
// pass-through rules (ASan runtime modules, configured module patterns, ASan's shadow range).
import { describe, expect, it } from "vitest";

import {
  ASAN_RUNTIME_PATTERNS,
  ASAN_SHADOW_BYTES,
  asanShadowRange,
  clampCrashPolicy,
  DEFAULT_CRASH_POLICY,
  isCallReturnSite,
  isPassthroughPattern,
  MAX_PASSTHROUGH_PATTERNS,
  modulePatternMatcher,
  normalizePassthroughModules,
} from "../../../../src/agent/pure/coreCrash.js";

describe("crash policy defaults", () => {
  it("blocking first-chance reports are opt-in; rows, last chance and the other defaults are unchanged", () => {
    expect(DEFAULT_CRASH_POLICY).toEqual({
      first_chance_rows: true,
      first_chance_blocking: false,
      crash_class: ["access-violation", "illegal-instruction", "stack-overflow", "arithmetic", "abort"],
      ack_timeout_ms: 1000,
      last_chance_ack_timeout_ms: 2000,
      max_blocking_per_10s: 8,
      rows_per_sec: 1000,
      stack_bytes: 256,
      backtrace_depth: 32,
      include_xmm: false,
      passthrough_modules: [],
    });
  });

  it("an empty or missing host policy takes the defaults (an older host sends no passthrough_modules)", () => {
    expect(clampCrashPolicy(undefined)).toEqual(DEFAULT_CRASH_POLICY);
    expect(clampCrashPolicy({})).toEqual(DEFAULT_CRASH_POLICY);
    const { passthrough_modules: _absent, ...older } = DEFAULT_CRASH_POLICY;
    expect(clampCrashPolicy({ ...older, first_chance_blocking: true })).toEqual({
      ...DEFAULT_CRASH_POLICY,
      first_chance_blocking: true,
    });
  });

  it("a host can still opt in to blocking first-chance reports; numbers clamp to the documented maxima", () => {
    const p = clampCrashPolicy({
      first_chance_blocking: true,
      ack_timeout_ms: 60_000,
      max_blocking_per_10s: -3,
      backtrace_depth: 1000,
      stack_bytes: 1e9,
      crash_class: ["access-violation", "bogus" as never, "system"],
    });
    expect(p.first_chance_blocking).toBe(true);
    expect(p.ack_timeout_ms).toBe(5000);
    expect(p.max_blocking_per_10s).toBe(0);
    expect(p.backtrace_depth).toBe(64);
    expect(p.stack_bytes).toBe(4096);
    expect(p.crash_class).toEqual(["access-violation", "system"]);
  });
});

describe("pass-through module patterns", () => {
  it("accepts module file names with * wildcards, refuses paths, control characters and bare wildcards", () => {
    for (const ok of ["vehcommit.exe", "nvwgf2um*.dll", "*.dll", "clang_rt.asan_dynamic-x86_64.dll", "a"])
      expect(isPassthroughPattern(ok), ok).toBe(true);
    for (const bad of [
      "",
      "*",
      "** *",
      "C:\\Windows\\x.dll",
      "dir/x.dll",
      "c:x.dll",
      "x\u0000.dll",
      "x\n.dll",
      "x".repeat(129),
      42,
      null,
    ])
      expect(isPassthroughPattern(bad), JSON.stringify(bad)).toBe(false);
  });

  it("normalizes a host list: invalid entries dropped, lower-cased, de-duplicated, at most 32", () => {
    expect(normalizePassthroughModules(undefined)).toEqual([]);
    expect(normalizePassthroughModules("x.dll")).toEqual([]);
    expect(normalizePassthroughModules(["VehCommit.EXE", "vehcommit.exe", "C:\\x.dll", 7, "*", "V8*.dll"])).toEqual([
      "vehcommit.exe",
      "v8*.dll",
    ]);
    const many = Array.from({ length: 40 }, (_, i) => `m${String(i)}.dll`);
    const kept = normalizePassthroughModules(many);
    expect(kept).toHaveLength(MAX_PASSTHROUGH_PATTERNS);
    expect(kept.at(-1)).toBe("m31.dll");
    expect(clampCrashPolicy({ passthrough_modules: ["A.dll", "a.dll", "b/c.dll"] }).passthrough_modules).toEqual([
      "a.dll",
    ]);
  });

  it("matches module names case-insensitively, `*` spanning any run, other characters literally", () => {
    const m = modulePatternMatcher(["nvwgf2um*.dll", "vehcommit.exe", "a+b(1).dll"])!;
    expect(m("nvwgf2umx.dll")).toBe(true);
    expect(m("NVWGF2UMX_CFG.DLL")).toBe(true);
    expect(m("nvwgf2um.dll")).toBe(true);
    expect(m("vehcommit.exe")).toBe(true);
    expect(m("a+b(1).dll")).toBe(true);
    // "." is literal, the whole name must match
    expect(m("vehcommitXexe")).toBe(false);
    expect(m("xvehcommit.exe")).toBe(false);
    expect(m("nvwgf2umx.dll.mui")).toBe(false);
    expect(m("aab(1).dll")).toBe(false);
    expect(modulePatternMatcher([])).toBeNull();
  });

  it("the built-in ASan runtime pattern covers clang's and MSVC's runtime DLLs and nothing else", () => {
    const asan = modulePatternMatcher(ASAN_RUNTIME_PATTERNS)!;
    for (const name of [
      "clang_rt.asan_dynamic-x86_64.dll",
      "clang_rt.asan_dbg_dynamic-x86_64.dll",
      "CLANG_RT.ASAN_DYNAMIC-X86_64.DLL",
      "clang_rt.asan-x86_64.dll",
    ])
      expect(asan(name), name).toBe(true);
    for (const name of ["chrome.dll", "clang_rt.ubsan_standalone-x86_64.dll", "asan.dll", "clang_rt.asan.lib"])
      expect(asan(name), name).toBe(false);
  });
});

describe("ASan shadow range", () => {
  it("spans the shadow of the 47-bit user address space (2^44 bytes) from the published offset", () => {
    expect(ASAN_SHADOW_BYTES).toBe(0x1000_0000_0000n);
    const offset = 0x7ff8_0000_0000n;
    expect(asanShadowRange(offset)).toEqual({ lo: offset, hi: offset + 0x1000_0000_0000n });
    // the shadow of the highest user address lies inside the range
    const shadowOfTop = (0x7fff_ffff_ffffn >> 3n) + offset;
    const range = asanShadowRange(offset)!;
    expect(shadowOfTop >= range.lo && shadowOfTop < range.hi).toBe(true);
  });

  it("is null before the runtime published an offset, and for an offset that would wrap", () => {
    expect(asanShadowRange(0n)).toBeNull();
    expect(asanShadowRange(-1n)).toBeNull();
    expect(asanShadowRange((1n << 64n) - 0x1000n)).toBeNull();
  });
});

describe("return-site check for the leaf rule at a pc outside every image", () => {
  /** The 8 bytes before a return address: filler, then the instruction that ends right at it. */
  const site = (...insn: number[]): Uint8Array => new Uint8Array([...Array(8 - insn.length).fill(0x90), ...insn]);

  it.each([
    ["call rel32", [0xe8, 0x10, 0x20, 0x30, 0x40]],
    ["call [rip+disp32]", [0xff, 0x15, 0x10, 0x20, 0x30, 0x40]],
    ["call rax", [0xff, 0xd0]],
    ["call r11", [0x41, 0xff, 0xd3]],
    ["call [rax]", [0xff, 0x10]],
    ["call [rax+8]", [0xff, 0x50, 0x08]],
    ["call [rsp+8]", [0xff, 0x54, 0x24, 0x08]],
    ["call [rax+disp32]", [0xff, 0x90, 0x00, 0x01, 0x00, 0x00]],
    ["call [rsp+disp32]", [0xff, 0x94, 0x24, 0x00, 0x01, 0x00, 0x00]],
    ["rex.w call [rip+disp32]", [0x48, 0xff, 0x15, 0x10, 0x20, 0x30, 0x40]],
    ["call [r12+8]", [0x41, 0xff, 0x54, 0x24, 0x08]],
  ])("accepts %s", (_name, insn) => {
    expect(isCallReturnSite(site(...insn))).toBe(true);
  });

  it.each([
    ["jmp rax", [0xff, 0xe0]],
    ["jmp [rip+disp32]", [0xff, 0x25, 0x10, 0x20, 0x30, 0x40]],
    ["push rbx", [0x53]],
    ["nops", []],
    ["zeros", [0, 0, 0, 0, 0, 0, 0, 0]],
  ])("refuses %s", (_name, insn) => {
    expect(isCallReturnSite(site(...insn))).toBe(false);
  });

  it("refuses an empty or short window", () => {
    expect(isCallReturnSite(new Uint8Array(0))).toBe(false);
    expect(isCallReturnSite(new Uint8Array([0xd0]))).toBe(false);
  });
});
