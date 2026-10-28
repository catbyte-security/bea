import { describe, expect, it } from "vitest";

import {
  DEFERRED_SLOTS,
  DeferredSlots,
  onInvokeCandidates,
  redirectOf,
  relocatedPrologue,
  syscallStubAt,
  SYSCALL_STUB_BYTES,
  SYSCALL_STUB_PROLOGUE,
  SYSCALL_STUB_RETURN,
} from "../../../../src/agent/pure/traceDeferred.js";
import { AGENT_LIMIT_HARD } from "../../../../src/shared/agentLimits.js";

const bytes = (hex: string): Uint8Array => Uint8Array.from(Buffer.from(hex.replaceAll(" ", ""), "hex"));

/** ntdll!NtWaitForSingleObject on Windows 11 x64 (syscall 4), through the `int 2e; ret` tail. */
const WAIT_STUB = "4c 8b d1 b8 04 00 00 00 f6 04 25 08 03 fe 7f 01 75 03 0f 05 c3 cd 2e c3";

describe("deferred-follow target table", () => {
  it("holds every thread a trace may follow", () => {
    expect(DEFERRED_SLOTS).toBeGreaterThanOrEqual(AGENT_LIMIT_HARD.stalker_max_threads);
  });

  it("frees a slot once (followed or exited) and reports empty when every target left", () => {
    const slots = new DeferredSlots([1204, 88, 31000]);
    expect(slots.size).toBe(3);
    expect(slots.has(88)).toBe(true);
    expect(slots.take(88)).toBe(1);
    expect(slots.has(88)).toBe(false);
    expect(slots.take(88)).toBe(-1); // a second entry of the same thread finds nothing
    expect(slots.table()).toEqual([1204, 0, 31000]); // the native table keeps its length; 0 never matches
    expect(slots.empty).toBe(false);
    expect(slots.take(1204)).toBe(0);
    expect(slots.take(31000)).toBe(2);
    expect(slots.empty).toBe(true);
    expect(slots.size).toBe(3);
  });

  it("never matches thread id 0 (a freed slot)", () => {
    const slots = new DeferredSlots([12]);
    slots.take(12);
    expect(slots.has(0)).toBe(false);
    expect(slots.take(0)).toBe(-1);
  });

  it("refuses more targets than the native table holds, and ids that are not 32-bit thread ids", () => {
    expect(() => new DeferredSlots(Array.from({ length: DEFERRED_SLOTS + 1 }, (_, i) => 4 * (i + 1)))).toThrow(
      RangeError,
    );
    expect(() => new DeferredSlots([0])).toThrow(RangeError);
    expect(() => new DeferredSlots([2 ** 32])).toThrow(RangeError);
    expect(() => new DeferredSlots([1.5])).toThrow(RangeError);
  });
});

describe("system-call stubs", () => {
  it("recognizes the canonical stub a blocked thread returns into", () => {
    const stub = bytes(WAIT_STUB);
    expect(SYSCALL_STUB_BYTES).toBeLessThanOrEqual(stub.length);
    expect(stub[SYSCALL_STUB_RETURN]).toBe(0xc3);
    expect(syscallStubAt(stub)).toBe("plain");
    expect(syscallStubAt(stub.slice(0, SYSCALL_STUB_BYTES))).toBe("plain");
  });

  it("recognizes the same stub when another instrument hooked its prologue (near or 16-byte redirect)", () => {
    const near = bytes(WAIT_STUB);
    near.set(bytes("e9 43 f6 e8 ff 0f 1f 00"), 0); // jmp rel32 + nop padding over the relocated 8 bytes
    expect(syscallStubAt(near)).toBe("hooked");
    const full = bytes(WAIT_STUB);
    full.set(bytes("ff 25 00 00 00 00 08 0e b3 14 fa 7f 00 00 90 90"), 0); // jmp qword ptr [rip] + address
    expect(syscallStubAt(full)).toBe("hooked");
  });

  it("rejects anything else: not after a syscall, a short read, a foreign prologue", () => {
    const stub = bytes(WAIT_STUB);
    expect(syscallStubAt(stub.slice(0, SYSCALL_STUB_BYTES - 1))).toBeNull();
    const noSyscall = bytes(WAIT_STUB);
    noSyscall[0x13] = 0x90;
    expect(syscallStubAt(noSyscall)).toBeNull();
    const notRet = bytes(WAIT_STUB);
    notRet[SYSCALL_STUB_RETURN] = 0x90;
    expect(syscallStubAt(notRet)).toBeNull();
    const foreign = bytes(WAIT_STUB);
    foreign.set(bytes("48 89 5c 24"), 0); // mov [rsp+…], rbx: a function, not a stub
    expect(syscallStubAt(foreign)).toBeNull();
  });
});

describe("Interceptor redirects and trampolines", () => {
  it("follows a near jmp and a jmp through a RIP-relative slot", () => {
    const at = 0x7ffa_16ca_1dc0n;
    expect(redirectOf(bytes("e9 43 f0 e8 ff"), at)).toEqual({ kind: "near", target: at + 5n - 0x1_70fbdn });
    expect(redirectOf(bytes("e9 10 00 00 00"), at)).toEqual({ kind: "near", target: at + 0x15n });
    expect(redirectOf(bytes("ff 25 00 00 00 00"), at)).toEqual({ kind: "slot", slot: at + 6n });
    expect(redirectOf(bytes("4c 8b d1 b8 04"), at)).toBeNull();
    expect(redirectOf(bytes("e9 00 00"), at)).toBeNull();
  });

  it("searches the plain stub's whole relocated prologue, else (hooked before) its head", () => {
    const plain = bytes(WAIT_STUB).slice(0, SYSCALL_STUB_PROLOGUE);
    expect([...relocatedPrologue(plain)]).toEqual([...plain]);
    expect([...relocatedPrologue(bytes("e9 43 f0 e8 ff 0f 1f 00"))]).toEqual([0x4c, 0x8b, 0xd1, 0xb8]);
  });

  it("finds on_invoke after the on_enter and on_leave parts, with and without an IBT landing pad", () => {
    const prologue = bytes(WAIT_STUB).slice(0, SYSCALL_STUB_PROLOGUE);
    // on_enter: push qword ptr [rip-0xe]; jmp enter_thunk | on_leave: push …; jmp leave_thunk | on_invoke
    const head = "ff 35 f2 ff ff ff e9 11 22 33 44 ff 35 e7 ff ff ff e9 55 66 77 88";
    const window = bytes(`${head} 4c 8b d1 b8 04 00 00 00 e9 aa bb cc dd`);
    const base = 0x7ffa_14b3_0e08n;
    expect(onInvokeCandidates(window, base, prologue)).toEqual([base + 22n]);
    const ibt = bytes(`${head} f3 0f 1e fa 4c 8b d1 b8 04 00 00 00 e9 aa bb cc dd`);
    expect(onInvokeCandidates(ibt, base, prologue)).toEqual([base + 22n, base + 26n]);
    // another stub's prologue (a different system call number) is not this one
    expect(onInvokeCandidates(bytes(`${head} 4c 8b d1 b8 05 00 00 00`), base, prologue)).toEqual([]);
    expect(onInvokeCandidates(window, base, new Uint8Array(0))).toEqual([]);
  });
});
