// WP3-AGENT unit tests: the mapThrown table (S4 §5.2) and the Windows x64 decoding helpers (S4 §5.6, §7.4, §10.3, F13):
// CONTEXT offsets, NTSTATUS → exception type, access-violation operations, page protections, MEMORY_BASIC_INFORMATION
// and the Win64 parameter slot mapping (with the hidden return pointer shift).
import { describe, expect, it } from "vitest";

import {
  agentErrorFromThrown,
  badParams,
  guardPageAddressOf,
  hookInstallFailedAt,
} from "../../../../src/agent/pure/coreErrors.js";
import {
  contextOffsetOf,
  CTX,
  exceptionTypeOfStatus,
  guardToggle,
  isGuardProtect,
  isReadableProtect,
  memoryOperationOf,
  parseContext,
  parseMbi,
  protectionText,
  reprotectedSince,
  slotSource,
  withGuard,
  withoutGuard,
} from "../../../../src/agent/pure/coreWin64.js";

describe("mapThrown table", () => {
  it("maps Frida error text to tags", () => {
    expect(agentErrorFromThrown({ text: "Error: access violation accessing 0x10" }, "readMemory")).toEqual({
      _tag: "AccessViolation",
      message: "access violation",
      address: "0x10",
      operation: null,
    });
    expect(agentErrorFromThrown({ text: "guard page was hit accessing 0x27A0B690000" }, "scan")).toMatchObject({
      _tag: "GuardPage",
      address: "0x27a0b690000",
      owner: "target",
    });
    expect(
      agentErrorFromThrown({ text: "unable to intercept function at 0x7ff6aa001000; please file a bug" }, "h"),
    ).toMatchObject({
      _tag: "HookInstallFailed",
      address: "0x7ff6aa001000",
      attempts: ["default"],
    });
    // review fix EMU-14: Windows' %p has no 0x prefix; the address was reported as 0x0
    expect(
      agentErrorFromThrown({ text: "unable to intercept function at 00007FF6AA001000; please file a bug" }, "h"),
    ).toMatchObject({ _tag: "HookInstallFailed", address: "0x7ff6aa001000" });
    expect(hookInstallFailedAt("0x7FF6AA001234", "unable to intercept function")).toMatchObject({
      _tag: "HookInstallFailed",
      address: "0x7ff6aa001234",
    });
    expect(agentErrorFromThrown({ text: "already replaced this function" }, "o")).toMatchObject({
      _tag: "HookConflict",
      kind: "replace",
    });
    expect(agentErrorFromThrown({ text: "unable to find module 'nope.dll'" }, "x")).toEqual({
      _tag: "ModuleNotFound",
      message: "module not found",
      module: "nope.dll",
    });
    expect(agentErrorFromThrown({ text: "unable to find global export 'Foo'" }, "x")).toMatchObject({
      _tag: "ExportNotFound",
      export: "Foo",
    });
    expect(agentErrorFromThrown({ text: "invalid match pattern" }, "scan")).toMatchObject({
      _tag: "BadParams",
      issues: [{ path: "pattern", problem: "invalid match pattern" }],
    });
  });

  it("prefers the fields of a stolen NativeFunction exception", () => {
    expect(
      agentErrorFromThrown(
        {
          text: "access violation accessing 0x0",
          type: "access-violation",
          address: "0x7ff6aa0017b6",
          memoryOperation: "write",
          memoryAddress: "0x0",
        },
        "call",
      ),
    ).toEqual({ _tag: "AccessViolation", message: "access violation", address: "0x0", operation: "write" });
    expect(agentErrorFromThrown({ text: "x", type: "guard-page", memoryAddress: "0x1000" }, "w")).toMatchObject({
      _tag: "GuardPage",
      address: "0x1000",
    });
    expect(agentErrorFromThrown({ text: "illegal instruction", type: "illegal-instruction" }, "call")).toMatchObject({
      _tag: "Internal",
      where: "call",
    });
  });

  it("falls back to Internal with a bounded frida_message", () => {
    const e = agentErrorFromThrown({ text: "x".repeat(2000) }, "boot");
    expect(e).toMatchObject({ _tag: "Internal", where: "boot", message: "agent internal error" });
    expect((e as { frida_message: string }).frida_message).toHaveLength(512);
    expect(guardPageAddressOf("Error: guard page was hit accessing 0x1f000")).toBe(0x1f000n);
    expect(guardPageAddressOf("access violation accessing 0x1")).toBeNull();
    expect(badParams([])).toBeNull();
    expect(badParams([{ path: "size", problem: "too big" }])).toMatchObject({
      _tag: "BadParams",
      issues: [{ path: "size" }],
    });
  });
});

describe("Windows x64 structures", () => {
  it("decodes a CONTEXT at the VERIFIED offsets", () => {
    const b = new Uint8Array(CTX.size);
    const dv = new DataView(b.buffer);
    dv.setUint32(CTX.MxCsr, 0x1fa0, true);
    dv.setUint32(CTX.EFlags, 0x10246, true);
    dv.setBigUint64(CTX.Dr0 + 8, 0x7ff6aa000008n, true);
    dv.setBigUint64(CTX.Dr7, 0x90104n, true);
    dv.setBigUint64(CTX.Rax, 0x34n, true);
    dv.setBigUint64(CTX.R8 + 7 * 8, 0xf15n, true); // r15
    dv.setBigUint64(CTX.Rip, 0x7ffa14ca23d4n, true);
    dv.setUint16(CTX.FltControlWord, 0x37f, true);
    b[CTX.Xmm0 + 16 * 3] = 0xab;
    const c = parseContext(b);
    expect(c.mxcsr).toBe(0x1fa0);
    expect(c.eflags).toBe(0x10246);
    expect(c.fpcw).toBe(0x37f);
    expect(c.dr[1]).toBe(0x7ff6aa000008n);
    expect(c.dr7).toBe(0x90104n);
    expect(c.gpr.rax).toBe(0x34n);
    expect(c.gpr.r15).toBe(0xf15n);
    expect(c.gpr.rip).toBe(0x7ffa14ca23d4n);
    expect(c.xmm[3]![0]).toBe(0xab);
    expect(contextOffsetOf("rsp")).toBe(0x98);
    expect(contextOffsetOf("r9")).toBe(0xc0);
  });

  it("maps NTSTATUS codes to exception types and AV operations", () => {
    expect(exceptionTypeOfStatus(0xc0000005)).toBe("access-violation");
    expect(exceptionTypeOfStatus(0x80000001)).toBe("guard-page");
    expect(exceptionTypeOfStatus(0xc000001d)).toBe("illegal-instruction");
    expect(exceptionTypeOfStatus(0xc00000fd)).toBe("stack-overflow");
    expect(exceptionTypeOfStatus(0xc0000094)).toBe("arithmetic");
    expect(exceptionTypeOfStatus(0xc000008e)).toBe("arithmetic");
    expect(exceptionTypeOfStatus(0x80000004)).toBe("single-step");
    expect(exceptionTypeOfStatus(0xe06d7363)).toBe("system"); // C++ throw
    expect(memoryOperationOf(0n)).toBe("read");
    expect(memoryOperationOf(1n)).toBe("write");
    expect(memoryOperationOf(8n)).toBe("execute");
    expect(memoryOperationOf(3n)).toBeNull();
  });

  it("renders page protections like Frida and tracks PAGE_GUARD", () => {
    expect(protectionText(0x04)).toBe("rw-");
    expect(protectionText(0x20)).toBe("r-x");
    expect(protectionText(0x40)).toBe("rwx");
    expect(protectionText(0x02 | 0x100)).toBe("r--");
    expect(protectionText(0x01)).toBe("---");
    expect(isReadableProtect(0x10)).toBe(false);
    expect(isReadableProtect(0x08)).toBe(true);
    expect(isGuardProtect(0x104)).toBe(true);
    expect(withGuard(0x04)).toBe(0x104);
    expect(withoutGuard(0x104)).toBe(0x04);
    const m = new Uint8Array(48);
    const dv = new DataView(m.buffer);
    dv.setBigUint64(0, 0x1000n, true);
    dv.setBigUint64(0x18, 0x3000n, true);
    dv.setUint32(0x20, 0x1000, true);
    dv.setUint32(0x24, 0x104, true);
    expect(parseMbi(m)).toMatchObject({ base: 0x1000n, regionSize: 0x3000n, state: 0x1000, protect: 0x104 });
  });

  it("toggles BEA's guard relative to the CURRENT protection, never a remembered one (review fix AGENT-2)", () => {
    // armed on a PAGE_READONLY page; the target made it PAGE_READWRITE (which also dropped the guard): re-arming keeps RW
    expect(guardToggle(0x04, true)).toBe(0x104);
    // a stop while the target's RW stands writes nothing (the guard is already gone): RO is never put back
    expect(guardToggle(0x04, false)).toBe("unchanged");
    // a stop while BEA's guard is on removes only the guard, over whatever base protection is current (RX here)
    expect(guardToggle(0x120, false)).toBe(0x20);
    expect(guardToggle(0x104, true)).toBe("unchanged");
    // PAGE_NOACCESS takes no guard: the arm is refused (and counted by the caller), not faked as applied
    expect(guardToggle(0x01, true)).toBe("refused");
    expect(guardToggle(0x01, false)).toBe("unchanged");
    // re-protection is detected on the base protection only
    expect(reprotectedSince(0x02, 0x04)).toBe(true);
    expect(reprotectedSince(0x02, 0x102)).toBe(false);
    expect(reprotectedSince(0x04, 0x104)).toBe(false);
    expect(reprotectedSince(0x04, 0x20)).toBe(true);
  });

  it("maps Win64 parameter slots by position, with the hidden return pointer shift", () => {
    expect(slotSource(0, "int", false)).toEqual({ kind: "reg", reg: "rcx" });
    expect(slotSource(1, "float", false)).toEqual({ kind: "xmm", index: 1 });
    expect(slotSource(3, "int", false)).toEqual({ kind: "reg", reg: "r9" });
    expect(slotSource(4, "float", false)).toEqual({ kind: "stack", rspOffset: 0x28 });
    expect(slotSource(5, "int", false)).toEqual({ kind: "stack", rspOffset: 0x30 });
    expect(slotSource(0, "int", true)).toEqual({ kind: "reg", reg: "rdx" });
    expect(slotSource(3, "float", true)).toEqual({ kind: "stack", rspOffset: 0x28 });
  });
});
