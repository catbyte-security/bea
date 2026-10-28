import { describe, expect, it } from "vitest";

import { jobHostEventSchema } from "../../../src/domain/jobhostProtocol.js";
import { BEA_KILL_EXIT_CODE, exitInfoOf, exitKindOf, ntstatusName } from "../../../src/domain/process/ntstatus.js";
import {
  mapHelperError,
  protocolViolationError,
  startAbortedError,
} from "../../../src/providers/process/jobhostErrors.js";
import {
  COMMAND_LINE_MAX_CHARS,
  quotedLength,
  validateAdopt,
  validateSpawn,
  validateWatch,
} from "../../../src/providers/process/requests.js";
import {
  createStatusLineParser,
  parseStatusLine,
  STATUS_LINE_MAX_BYTES,
  type StatusViolation,
} from "../../../src/providers/process/statusLines.js";
import { Deadline } from "../../../src/domain/deadline.js";

describe("ntstatus (S3 §14.3)", () => {
  it("names crash codes and classifies exits", () => {
    expect(ntstatusName(0xc000_0005)).toBe("STATUS_ACCESS_VIOLATION");
    expect(ntstatusName(0xc000_0409)).toBe("STATUS_STACK_BUFFER_OVERRUN");
    expect(ntstatusName(0x8000_0003)).toBe("STATUS_BREAKPOINT");
    expect(ntstatusName(0)).toBeNull();
    expect(ntstatusName(-1)).toBeNull();
    expect(exitKindOf(0xc000_0005, false)).toBe("ntstatus");
    expect(exitKindOf(0, false)).toBe("normal");
    expect(exitKindOf(0x8000_0003, false)).toBe("normal");
    expect(exitKindOf(BEA_KILL_EXIT_CODE, true)).toBe("bea-kill");
    expect(exitKindOf(null, false)).toBe("unknown");
  });

  it("builds ExitInfo with canonical hex and the BEA kill marker only with byKill", () => {
    expect(exitInfoOf(0xc000_0005)).toEqual({
      code: 0xc000_0005,
      code_hex: "0xc0000005",
      kind: "ntstatus",
      name: "STATUS_ACCESS_VIOLATION",
    });
    expect(exitInfoOf(0xbea, true)).toEqual({
      code: 3050,
      code_hex: "0xbea",
      kind: "bea-kill",
      name: "BEA_JOB_TERMINATED",
    });
    expect(exitInfoOf(0xbea, false)).toEqual({ code: 3050, code_hex: "0xbea", kind: "normal", name: null });
    expect(exitInfoOf(null)).toEqual({ code: null, code_hex: null, kind: "unknown", name: null });
  });
});

const collect = () => {
  const events: unknown[] = [];
  const violations: StatusViolation[] = [];
  const parser = createStatusLineParser({ onEvent: (e) => events.push(e), onViolation: (v) => violations.push(v) });
  return { parser, events, violations };
};
const hello = {
  event: "hello",
  protocol: 1,
  version: "0.1.0",
  mode: "probe",
  helperPid: 7,
  helperInJob: false,
  statusFd3: true,
};

describe("status line parser (S3 §5.2)", () => {
  it("splits lines across chunks and ignores CR and blank lines", () => {
    const { parser, events, violations } = collect();
    const text = `${JSON.stringify(hello)}\r\n\n{"event":"proc-start","pid":5}\n`;
    const bytes = Buffer.from(text);
    for (let i = 0; i < bytes.length; i += 7) parser.push(bytes.subarray(i, i + 7));
    parser.end();
    expect(violations).toEqual([]);
    expect(events).toEqual([hello, { event: "proc-start", pid: 5 }]);
  });

  it("reports invalid JSON, schema failures, protocol mismatches and long or unterminated lines", () => {
    expect(parseStatusLine("{nope")).toEqual({ ok: false, violation: { kind: "invalid-json" } });
    expect(parseStatusLine('{"event":"proc-start","pid":-1}')).toEqual({
      ok: false,
      violation: { kind: "schema", event: "proc-start" },
    });
    expect(parseStatusLine('{"event":"proc-start","pid":1,"extra":1}')).toMatchObject({ ok: false });
    expect(parseStatusLine(JSON.stringify({ ...hello, protocol: 2 }))).toEqual({
      ok: false,
      violation: { kind: "protocol-mismatch", protocol: 2 },
    });
    // 64-bit values must be decimal strings
    expect(
      parseStatusLine(
        JSON.stringify({ event: "watching", pid: 1, creationTime100ns: 133000000000000000, imagePath: null }),
      ).ok,
    ).toBe(false);

    const long = collect();
    long.parser.push(Buffer.alloc(STATUS_LINE_MAX_BYTES + 1, 0x61));
    expect(long.violations).toEqual([{ kind: "line-too-long", bytes: STATUS_LINE_MAX_BYTES + 1 }]);
    long.parser.push(Buffer.from(`${JSON.stringify(hello)}\n`));
    expect(long.events).toEqual([]);

    const partial = collect();
    partial.parser.push(Buffer.from('{"event":"status"'));
    partial.parser.end();
    expect(partial.violations).toEqual([{ kind: "unterminated-line", bytes: 17 }]);
  });

  it("accepts a line of exactly the cap", () => {
    const { parser, violations } = collect();
    const padded = JSON.stringify({
      ...hello,
      version: "v".repeat(STATUS_LINE_MAX_BYTES - JSON.stringify(hello).length + 5),
    });
    expect(Buffer.byteLength(padded)).toBe(STATUS_LINE_MAX_BYTES);
    parser.push(Buffer.from(`${padded}\n`));
    expect(violations).toEqual([]);
  });

  it("validates the documented ordering events with jobHostEventSchema", () => {
    for (const line of [
      { event: "settled", active: 0, timedOut: false, peakJobMemoryBytes: 0, elapsedMs: 3 },
      { event: "killed", reason: "eof", activeBefore: 1, ok: true, win32: 0 },
      { event: "error", stage: "identity", win32: 0, detail: "creation-time", expected: "1", actual: "2" },
      { event: "watch-ended", reason: "eof" },
    ])
      expect(jobHostEventSchema.safeParse(line).success).toBe(true);
  });
});

const deadline = () => Deadline.after(1000);

describe("request validation and argv (S3 §5.1)", () => {
  it("builds adopt and watch argv with decimal 64-bit values", () => {
    const adopt = validateAdopt("op", {
      pid: 42,
      creationTime100ns: 2n ** 60n,
      tolerance100ns: 10n,
      expectImage: "C:\\t\\a.exe",
      expectParentPid: 7,
      memLimitBytes: 4096,
      deadline: deadline(),
    });
    expect(adopt).toEqual({
      ok: true,
      value: [
        "42",
        "1152921504606846976",
        "--tolerance-100ns",
        "10",
        "--expect-image",
        "C:\\t\\a.exe",
        "--expect-parent",
        "7",
        "--mem-limit",
        "4096",
      ],
    });
    expect(validateWatch("op", { pid: 1, creationTime100ns: 5n, tolerance100ns: 0n, deadline: deadline() })).toEqual({
      ok: true,
      value: ["1", "5", "--tolerance-100ns", "0"],
    });
  });

  it("refuses out-of-range identities and relative paths as invalid_request", () => {
    const bad = validateAdopt("op", {
      pid: -1,
      creationTime100ns: -1n,
      tolerance100ns: 2n ** 64n,
      expectImage: "a.exe",
      expectParentPid: 2 ** 32,
      memLimitBytes: 0,
      deadline: deadline(),
    });
    expect(bad.ok).toBe(false);
    if (bad.ok) return;
    expect(bad.error._tag).toBe("InputError");
    expect(bad.error._tag === "InputError" && bad.error.issues.map((i) => i.path)).toEqual([
      "pid",
      "creationTime100ns",
      "tolerance100ns",
      "expectImage",
      "expectParentPid",
      "memLimitBytes",
    ]);
  });

  it("builds spawn argv in the helper's option order and bounds the command line", () => {
    const base = {
      exe: "C:\\bin\\py.exe",
      args: ["-I", "bridge.py"],
      cwd: "C:\\work",
      env: { SystemRoot: "C:\\Windows" },
      suspended: true,
      stdin: "pipe" as const,
      killOnRootExit: true,
      memLimitBytes: 268_435_456,
      deadline: deadline(),
    };
    expect(validateSpawn("op", base)).toEqual({
      ok: true,
      value: [
        "--suspended",
        "--stdin-fd4",
        "--mem-limit",
        "268435456",
        "--kill-on-root-exit",
        "--",
        "C:\\bin\\py.exe",
        "-I",
        "bridge.py",
      ],
    });
    expect(validateSpawn("op", { ...base, exe: "py.exe" }).ok).toBe(false);
    expect(validateSpawn("op", { ...base, args: ["a\u0000b"] }).ok).toBe(false);
    expect(validateSpawn("op", { ...base, env: { "A=B": "x" } }).ok).toBe(false);
    expect(validateSpawn("op", { ...base, env: { "=C:": "C:\\" } }).ok).toBe(true);
    expect(validateSpawn("op", { ...base, args: ["x".repeat(COMMAND_LINE_MAX_CHARS)] }).ok).toBe(false);
  });

  it("measures MSVCRT quoting like bea-jobhost appendArg", () => {
    expect(quotedLength("abc")).toBe(3);
    expect(quotedLength("")).toBe(2);
    expect(quotedLength("a b")).toBe(5);
    expect(quotedLength('a"b')).toBe(6); // "a\"b"
    expect(quotedLength("a b\\")).toBe(7); // "a b\\"
    expect(quotedLength('a\\"b c')).toBe(10); // "a\\\"b c"
  });
});

describe("helper error mapping (S3 §5.7)", () => {
  const event = (stage: string, win32: number, detail = "") =>
    ({ event: "error", stage, win32, detail }) as Parameters<typeof mapHelperError>[1];

  it("maps each stage to the documented tag", () => {
    const identity = mapHelperError(
      "op",
      { ...event("identity", 0, "creation-time"), expected: "1", actual: "9" },
      { pid: 5 },
    );
    expect(identity).toMatchObject({
      _tag: "InstanceMismatch",
      observed: { pid: 5, start_time: "9" },
      diagnostics: { stage: "identity", detail: "creation-time", expected: "1", actual: "9" },
    });
    expect(identity.message).toBeUndefined(); // creation-time keeps the catalog's pid-reuse/restart text
    // review fix LIFE-5: image-path is a genuinely different file now, with its own message
    expect(mapHelperError("op", event("identity", 0, "image-path"), { pid: 5 })).toMatchObject({
      _tag: "InstanceMismatch",
      message: expect.stringMatching(/different file from the requested program/u),
    });
    expect(mapHelperError("op", event("open", 87), { pid: 5 })).toMatchObject({
      _tag: "InputError",
      issues: [{ path: "pid" }],
    });
    expect(mapHelperError("op", event("open", 5), {})).toMatchObject({ _tag: "AccessDenied", reason: "os-denied" });
    expect(mapHelperError("op", event("assign", 5), {})).toMatchObject({
      _tag: "CapabilityUnavailable",
      capability: "containment",
    });
    expect(mapHelperError("op", event("create", 740), {})).toMatchObject({
      _tag: "AccessDenied",
      reason: "elevation-required",
    });
    expect(mapHelperError("op", event("create", 2), {})).toMatchObject({
      _tag: "InputError",
      issues: [{ path: "exe" }],
    });
    expect(mapHelperError("op", event("create", 3), {})).toMatchObject({ _tag: "InputError" });
    expect(mapHelperError("op", event("usage", 0, "command-line-too-long"), {})).toMatchObject({ _tag: "InputError" });
    expect(mapHelperError("op", event("job-policy", 1, "readback-mismatch"), {})).toMatchObject({
      _tag: "ProviderFailure",
      provider: "jobhost",
    });
  });

  it("maps protocol violations and aborts", () => {
    expect(protocolViolationError("op", { kind: "protocol-mismatch", protocol: 2 })).toMatchObject({
      _tag: "CapabilityUnavailable",
      reason: "protocol-mismatch",
    });
    expect(protocolViolationError("op", { kind: "invalid-json" })).toMatchObject({
      _tag: "ProviderFailure",
      diagnostics: { reason: "protocol-violation", violation: "invalid-json" },
    });
    expect(startAbortedError("op", { kind: "deadline", ms: 5 }, 5, "jobhost-adopt")).toMatchObject({
      _tag: "ProviderTimeout",
      timeout_ms: 5,
      phase: "jobhost-adopt",
    });
    expect(startAbortedError("op", { kind: "shutdown" }, 5, "p")).toMatchObject({
      _tag: "Cancelled",
      by: "server-shutdown",
    });
    expect(startAbortedError("op", new Error("x"), 5, "p")).toMatchObject({ _tag: "Cancelled", by: "signal" });
  });
});
