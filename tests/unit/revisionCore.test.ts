import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";

import { describe, expect, it } from "vitest";

import type { BeaApplication } from "../../src/application/BeaApplication.js";
import { createApplication } from "../../src/application/createApplication.js";
import type { HandlerContext, ToolHandler } from "../../src/application/handlerContext.js";
import { createToolHandlers } from "../../src/application/handlers/index.js";
import { invokeTool } from "../../src/application/invokeTool.js";
import { Lifecycle } from "../../src/application/lifecycle.js";
import { notImplementedPort } from "../../src/application/notImplemented.js";
import { liveOp, emuOp } from "../../src/application/sessionAccess.js";
import { parseCliNumber, parseCommandArgs, type DerivedCommand } from "../../src/cli/argv.js";
import { TOOL_CONTRACTS } from "../../src/contracts/index.js";
import { callInputBudget, CALL_INPUT_LIMITS } from "../../src/contracts/schemas/callModel.js";
import type { ToolContract } from "../../src/contracts/toolContract.js";
import { composeSignal } from "../../src/domain/abort.js";
import { systemClock } from "../../src/domain/clock.js";
import { loadConfig } from "../../src/domain/config.js";
import { isBeaError } from "../../src/domain/errors/beaError.js";
import { silentLogger } from "../../src/domain/logger.js";
import { checkOutputPath } from "../../src/domain/outputPaths.js";
import { isDriveAbsolute } from "../../src/domain/paths.js";
import { ok } from "../../src/domain/result.js";
import type { DynamicSessionPort, LiveSession } from "../../src/ports/sessions.js";
import { fakeServices } from "../support/fakes/fakeServices.js";

/** WP0 tests for the revision amendments (DESIGN Appendix C). */

const appWith = async (overrides: Parameters<typeof fakeServices>[0] = {}): Promise<BeaApplication> => {
  const loaded = await loadConfig({
    env: { BEA_HOME: "C:/bea-test-home" },
    platform: "win32",
    accountHome: "C:/Users/t",
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error(JSON.stringify(loaded.error));
  return createApplication({
    config: loaded.value,
    logger: silentLogger,
    transport: "cli",
    services: fakeServices(overrides),
  });
};

describe("composeSignal (CT-I2)", () => {
  it("forwards the first abort reason and detaches on dispose", () => {
    const longLived = new AbortController();
    const other = new AbortController();
    const composed = composeSignal([longLived.signal, other.signal]);
    other.abort("why");
    expect(composed.signal.aborted).toBe(true);
    expect(composed.signal.reason).toBe("why");
    const already = composeSignal([AbortSignal.abort("pre")]);
    expect(already.signal.reason).toBe("pre");
  });

  it("retains < 64 B per composition over a long-lived source", () => {
    setFlagsFromString("--expose-gc");
    const gc = runInNewContext("gc") as () => void;
    const longLived = new AbortController();
    const round = (): void => {
      for (let i = 0; i < 100_000; i += 1) composeSignal([longLived.signal, new AbortController().signal]).dispose();
    };
    round();
    gc();
    const before = process.memoryUsage().heapUsed;
    round();
    gc();
    const perCall = (process.memoryUsage().heapUsed - before) / 100_000;
    expect(perCall).toBeLessThan(64);
  });
});

describe("invokeTool input ceiling (CT-B3)", () => {
  it("refuses arguments above contract.maxInputBytes before parsing", async () => {
    const app = await appWith();
    const table = createToolHandlers(app) as unknown as Record<string, ToolHandler<ToolContract>>;
    const contract = TOOL_CONTRACTS.find((c) => c.name === "bea_status");
    if (contract === undefined) throw new Error("bea_status missing");
    const result = await invokeTool(
      app,
      (n) => table[n],
      contract,
      { pad: "x".repeat(contract.maxInputBytes) },
      {
        surface: "cli",
        clientSignal: new AbortController().signal,
        progress: { report: () => undefined },
        requestId: "t",
      },
    );
    expect(result.ok).toBe(false);
    if (!result.ok && result.error._tag === "InputError")
      expect(result.error.issues[0]).toMatchObject({ path: "$", reason: "out_of_range" });
    else throw new Error("expected InputError");
  });

  it("bounds aggregate call-model input", () => {
    const issues: unknown[] = [];
    const ctx = { addIssue: (issue: unknown) => void issues.push(issue) } as unknown as Parameters<
      typeof callInputBudget
    >[1];
    callInputBudget({ vectors: { columns: { arg0: new Array(CALL_INPUT_LIMITS.maxVectorCells + 1).fill(1) } } }, ctx);
    callInputBudget({ buffers: [{ init_hex: "00".repeat(CALL_INPUT_LIMITS.maxInitHexChars / 2 + 1) }] }, ctx);
    expect(issues).toHaveLength(2);
  });
});

describe("shutdown (CT-I3)", () => {
  it("reports a slow best-effort closer as abandoned and stays ok", async () => {
    const lifecycle = new Lifecycle(systemClock, silentLogger);
    lifecycle.register({
      name: "admission",
      phase: "stop-admission",
      bestEffort: true,
      close: () => new Promise<void>(() => undefined),
    });
    lifecycle.register({ name: "kill", phase: "teardown-targets", close: async () => undefined });
    const report = await lifecycle.closeAll("test");
    expect(report.ok).toBe(true);
    expect(report.phases[0]).toMatchObject({ phase: "stop-admission", failed: [], abandoned: ["admission"] });
  });
});

describe("day-0 stubs (CI-M22)", () => {
  it("throw synchronously and are never thenables", async () => {
    const port = notImplementedPort<{ literals(): string[]; then?: unknown }>("evidence");
    expect(() => port.literals()).toThrow();
    try {
      port.literals();
    } catch (cause: unknown) {
      expect(isBeaError(cause)).toBe(true);
    }
    expect(port.then).toBeUndefined();
    expect(await Promise.resolve(port)).toBe(port);
  });
});

describe("CLI argv (CI-I11, CT-M12)", () => {
  const command = (over: Partial<DerivedCommand>): DerivedCommand => ({
    contract: { name: "map_address" } as unknown as ToolContract,
    command: "map",
    tier: "session-oneshot",
    positional: ["addresses"],
    options: [
      { field: "addresses", flag: "addresses", kind: "string-list", values: [], required: true, description: "" },
      { field: "pe_path", flag: "pe-path", kind: "string", values: [], required: false, description: "" },
      { field: "verify_bytes", flag: "verify-bytes", kind: "number", values: [], required: false, description: "" },
    ],
    jsonOnly: [],
    offlineField: "pe_path",
    fileFields: [],
    ...over,
  });

  it("parses numbers with the schema grammar", () => {
    expect(parseCliNumber("0x10")).toBe(16);
    expect(parseCliNumber("-0x10")).toBe(-16);
    expect(parseCliNumber("1e3")).toBe(1000);
    expect(Number.isNaN(parseCliNumber(""))).toBe(true);
    expect(Number.isNaN(parseCliNumber("12abc"))).toBe(true);
  });

  it("waives the target in offline mode and keeps the variadic positional", () => {
    const parsed = parseCommandArgs(command({}), [
      "game.exe:0x1400010a0",
      "+0x2000",
      "--pe-path",
      "C:/g/game.exe",
      "--verify-bytes=-1",
    ]);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.target).toBeNull();
      expect(parsed.value.input).toMatchObject({
        addresses: ["game.exe:0x1400010a0", "+0x2000"],
        pe_path: "C:/g/game.exe",
        verify_bytes: -1,
      });
    }
    expect(parseCommandArgs(command({}), ["+0x2000"]).ok).toBe(false); // no target, not offline
    expect(parseCommandArgs(command({}), ["+0x2000", "--pe-path", "C:/x.exe", "--pid", "4"]).ok).toBe(false);
  });

  it("turns fileFields into file references", () => {
    const script = command({
      contract: { name: "run_script" } as unknown as ToolContract,
      command: "script",
      positional: ["source"],
      options: [{ field: "source", flag: "source", kind: "string", values: [], required: true, description: "" }],
      offlineField: null,
      fileFields: ["source"],
    });
    const parsed = parseCommandArgs(script, ["hook.js", "--pid", "1234"]);
    expect(parsed.ok && parsed.value.fileInputs).toEqual([{ field: "source", path: "hook.js" }]);
    expect(parsed.ok && "source" in parsed.value.input).toBe(false);
  });
});

describe("output paths (CT-I8) and home paths (CT-M7)", () => {
  const policy = {
    platform: "win32" as const,
    exportsDir: "C:\\bea\\runs\\r1\\exports",
    allowedRoots: ["D:\\re-work"],
    systemRoots: ["C:\\Windows"],
  };
  it("allows the exports dir and user roots, refuses everything else", () => {
    expect(checkOutputPath("C:\\bea\\runs\\r1\\exports\\a.bin", policy).ok).toBe(true);
    expect(checkOutputPath("D:/re-work/dumps/game.dmp", policy).ok).toBe(true);
    const reasons = [
      "relative\\a.bin",
      "C:\\bea\\runs\\r1\\exports\\..\\x.bin",
      "C:\\bea\\runs\\r1\\exports\\a.txt:ads",
      "C:\\bea\\runs\\r1\\exports\\run.cmd",
      "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\a.bin",
      "C:\\Windows\\Temp\\a.bin",
      "C:\\Users\\u\\a.bin",
    ].map((p) => {
      const check = checkOutputPath(p, policy);
      return check.ok ? "ok" : check.reason;
    });
    expect(reasons).toEqual([
      "not-absolute",
      "traversal",
      "alternate-stream",
      "refused-extension",
      "startup-folder",
      "system-directory",
      "outside-roots",
    ]);
    expect(checkOutputPath("D:\\re-work\\..\\Windows\\a.bin", { ...policy, allowedRoots: ["D:\\"] }).ok).toBe(false);
  });
  it("requires drive-absolute local paths on win32", () => {
    expect(isDriveAbsolute("C:\\bea", "win32")).toBe(true);
    expect(isDriveAbsolute("\\bea", "win32")).toBe(false);
    expect(isDriveAbsolute("\\\\host\\share\\bea", "win32")).toBe(false);
  });
});

describe("session access (CI-I14)", () => {
  const ctx: HandlerContext = {
    operation: "read_memory",
    surface: "mcp",
    requestId: "1",
    signal: new AbortController().signal,
    abortCause: () => null,
    remainingMs: () => 1000,
    progress: { report: () => undefined },
    log: silentLogger,
    gates: { isEnabled: () => false, require: () => ok(undefined), requireUnlessOwned: () => ok(undefined) },
  };
  const sessionsWith = (
    kind: ReturnType<DynamicSessionPort["kindOf"]>,
    state: LiveSession["state"],
  ): DynamicSessionPort =>
    ({
      admit: (_n: string, _r: unknown, fn: (op: never) => unknown) => fn({} as never),
      kindOf: () => kind,
      withSession: (_id: string, _op: unknown, _mode: unknown, fn: (s: LiveSession) => unknown) =>
        fn({
          id: "s",
          state,
          instanceId: "pi_x",
          liveness: () => ({
            state: "exited",
            basis: "jobhost-root-exit",
            exit: { code: 5, code_hex: "0x5", kind: "ntstatus", name: null, source: "jobhost" },
            tree: null,
          }),
        } as unknown as LiveSession),
    }) as unknown as DynamicSessionPort;
  const run = async (kind: ReturnType<DynamicSessionPort["kindOf"]>, state: LiveSession["state"]) => {
    const app = await appWith({ sessions: sessionsWith(kind, state) });
    return liveOp(app, ctx, "s", { mode: "exclusive", need: "agent" }, async () => ok("ran"));
  };
  it("maps kinds and states to one error table", async () => {
    const tag = (r: Awaited<ReturnType<typeof run>>) => (r.ok ? r.value : r.error._tag);
    expect(tag(await run(null, "running"))).toBe("SessionNotFound");
    expect(tag(await run("closed", "running"))).toBe("SessionNotFound");
    expect(tag(await run("emulation", "running"))).toBe("InputError");
    expect(tag(await run("live", "exited"))).toBe("TargetExited");
    expect(tag(await run("live", "detached"))).toBe("CapabilityUnavailable");
    expect(tag(await run("live", "running"))).toBe("ran");
    const app = await appWith({ sessions: sessionsWith("live", "running") });
    const wrong = await emuOp(app, ctx, "s", async () => ok("ran"));
    expect(wrong.ok ? "ran" : wrong.error._tag).toBe("InputError");
  });

  it("is the only application code that touches session dispatch, and AbortSignal.any is unused", () => {
    const walk = (dir: string): string[] =>
      readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : [join(dir, n)]));
    const root = join(import.meta.dirname, "..", "..");
    const offenders: string[] = [];
    for (const file of walk(join(root, "src")).filter((f) => f.endsWith(".ts"))) {
      const rel = relative(root, file).replaceAll("\\", "/");
      const text = readFileSync(file, "utf8");
      const sessionsArea =
        rel === "src/application/handlers/sessions.ts" || rel.startsWith("src/application/sessions/");
      if (
        rel.startsWith("src/application/") &&
        rel !== "src/application/sessionAccess.ts" &&
        !sessionsArea &&
        /\.(withSession|kindOf|admit)\(/u.test(text)
      )
        offenders.push(rel);
      if (rel !== "src/domain/abort.ts" && /AbortSignal\.any\(/u.test(text)) offenders.push(`${rel} (AbortSignal.any)`);
    }
    expect(offenders).toEqual([]);
  });
});
