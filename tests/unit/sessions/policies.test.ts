import { describe, expect, it } from "vitest";

import type { ProcessInspection } from "../../../src/ports/jobhost.js";
import {
  ancestrySignals,
  antiCheatVerdict,
  directorySignals,
  importSignals,
  machineWideAntiCheat,
  machineWideNote,
  moduleSignals,
} from "../../../src/providers/frida/antiCheatSignals.js";
import { evaluateAttachPolicy, type AttachSelfFacts } from "../../../src/providers/frida/attachPolicy.js";
import {
  canTransition,
  IllegalTransitionError,
  assertTransition,
  SESSION_STATES,
  TRANSITIONS,
  visibleState,
} from "../../../src/providers/frida/sessionStates.js";
import { buildTargetEnvironment, isAllowlisted, parseEnvEntries } from "../../../src/providers/frida/spawnEnv.js";
import {
  allowedProgram,
  crtCommandLineLength,
  isInterpreterOrLolbin,
  programRefusal,
  quoteCrtArgument,
  refusedLocations,
  versionInfoRefusal,
} from "../../../src/providers/frida/spawnPolicy.js";
import { isoToFiletime100ns } from "../../../src/providers/frida/spawnSession.js";

describe("session state machine (S3 §6.2, case 1)", () => {
  it("allows exactly the table's edges and throws on every other one", () => {
    let allowed = 0;
    for (const from of SESSION_STATES)
      for (const to of SESSION_STATES) {
        const legal = TRANSITIONS[from].includes(to);
        expect(canTransition(from, to), `${from} -> ${to}`).toBe(legal);
        if (legal) {
          allowed += 1;
          expect(() => assertTransition(from, to)).not.toThrow();
        } else expect(() => assertTransition(from, to)).toThrow(IllegalTransitionError);
      }
    expect(allowed).toBe(28);
  });

  it("never surfaces startup states; a failed startup reads as closed", () => {
    expect(visibleState("paused")).toBe("paused");
    expect(visibleState("cleanup_pending")).toBe("cleanup_pending");
    expect(visibleState("failed")).toBe("closed");
    expect(TRANSITIONS.closed).toEqual([]);
    expect(TRANSITIONS.exited).toEqual(["closing"]);
  });
});

const inspection = (over: Partial<ProcessInspection> = {}): ProcessInspection => ({
  pid: 5000,
  access: "limited+synchronize",
  exited: false,
  exitCode: null,
  creationTime100ns: 1n,
  imagePath: "C:\\games\\game.exe",
  parentPid: 100,
  osSessionId: 1,
  critical: false,
  protectionLevel: 0xfffffffe,
  protected: false,
  wow64: false,
  processMachine: 0,
  nativeMachine: 0x8664,
  inJob: false,
  elevated: false,
  integrityRid: 0x2000,
  sameUser: true,
  ...over,
});
const self: AttachSelfFacts = {
  pid: 10,
  ppid: 11,
  helperPids: [12],
  sessionPids: new Map([[6000, "s-1"]]),
  elevated: false,
  integrityRid: 0x2000,
  systemRoot: "C:\\Windows",
};
const config = {
  allowSession0: false,
  extraDenylist: ["notepad++.exe"],
  allowAntiCheat: false,
  allowAntiCheatImages: [],
};
const decide = (pid: number, over: Partial<ProcessInspection> = {}, signals: readonly string[] = []) =>
  evaluateAttachPolicy({
    pid,
    inspection: inspection({ pid, ...over }),
    self,
    config,
    antiCheatSignals: signals,
    imageSha256: null,
  }).refusal;

describe("attach refusal policy (S3 §5.8 rules 1–11 + D-INT-1 rule 12, case 12)", () => {
  it.each([
    ["1 system idle/System", 4, {}, "AccessDenied", "system-process"],
    ["2 server", 10, {}, "AccessDenied", "bea-process-tree"],
    ["2 MCP client", 11, {}, "AccessDenied", "bea-process-tree"],
    ["2 helper", 12, {}, "AccessDenied", "bea-process-tree"],
    ["3 already in a session", 6000, {}, "InputError", null],
    ["4 exited", 5000, { exited: true }, "InputError", null],
    ["5 protected", 5000, { protected: true }, "AccessDenied", "protected-process"],
    ["6 critical", 5000, { critical: true }, "AccessDenied", "critical-process"],
    ["7 session 0", 5000, { osSessionId: 0 }, "AccessDenied", "session-0"],
    ["8 WoW64", 5000, { wow64: true }, "UnsupportedTarget", "wow64"],
    ["8 machine", 5000, { processMachine: 0x14c }, "UnsupportedTarget", "wow64"],
    ["9 system denylist", 5000, { imagePath: "C:\\Windows\\System32\\lsass.exe" }, "AccessDenied", "system-process"],
    ["9 extra denylist", 5000, { imagePath: "D:\\apps\\notepad++.exe" }, "AccessDenied", "system-process"],
    ["10 other user", 5000, { sameUser: false }, "AccessDenied", "other-user"],
    ["11 elevated", 5000, { elevated: true }, "AccessDenied", "higher-integrity"],
    ["11 integrity", 5000, { integrityRid: 0x3000 }, "AccessDenied", "higher-integrity"],
  ] as const)("rule %s", (_name, pid, over, tag, reason) => {
    const refusal = decide(pid, over);
    expect(refusal?._tag).toBe(tag);
    if (reason !== null) expect((refusal as { reason?: string } | null)?.reason).toBe(reason);
  });

  it("rule 12 refuses target-scoped anti-cheat signals unless the user allowed them", () => {
    expect(decide(5000, {}, ["dir:BattlEye"])?._tag).toBe("AccessDenied");
    const allowed = evaluateAttachPolicy({
      pid: 5000,
      inspection: inspection(),
      self,
      config: { ...config, allowAntiCheatImages: ["AA".repeat(32)] },
      antiCheatSignals: ["dir:BattlEye"],
      imageSha256: "aa".repeat(32),
    });
    expect(allowed.refusal).toBeNull();
    expect(allowed.antiCheat.kind).toBe("allowed");
  });

  it("null facts never refuse alone; unknown protection is noted", () => {
    const decision = evaluateAttachPolicy({
      pid: 5000,
      inspection: inspection({
        protected: null,
        critical: null,
        osSessionId: null,
        wow64: null,
        sameUser: null,
        integrityRid: null,
      }),
      self,
      config,
      antiCheatSignals: [],
      imageSha256: null,
    });
    expect(decision.refusal).toBeNull();
    expect(decision.protectionUnknown).toBe(true);
  });
  it("a session-0 process is allowed with attach.allow_session0", () => {
    const decision = evaluateAttachPolicy({
      pid: 5000,
      inspection: inspection({ osSessionId: 0 }),
      self,
      config: { ...config, allowSession0: true },
      antiCheatSignals: [],
      imageSha256: null,
    });
    expect(decision.refusal).toBeNull();
  });
});

describe("anti-cheat signals (D-INT-1)", () => {
  it("(a) directory components, (b) imports and live modules, (c) ancestry — labels from BEA's fixed lists", () => {
    expect(directorySignals(["EasyAntiCheat", "data", "BEService_x64.exe", "start_protected_game.exe"])).toEqual([
      "dir:BEService*.exe",
      "dir:EasyAntiCheat",
      "dir:start_protected_game.exe",
    ]);
    expect(importSignals(["KERNEL32.dll", "EasyAntiCheat_x64.dll", "npggNT64.des"])).toEqual([
      "import:EasyAntiCheat_x64.dll",
      "import:npggNT*",
    ]);
    expect(moduleSignals(["C:\\g\\BEClient_x64.dll", "ntdll.dll"])).toEqual(["module:BEClient_x64.dll"]);
    const processes = [
      { pid: 1, name: "FACEITService.exe", ppid: null },
      { pid: 2, name: "launcher.exe", ppid: 1 },
      { pid: 3, name: "game.exe", ppid: 2 },
    ];
    expect(ancestrySignals(3, processes)).toEqual(["ancestor:FACEIT*.exe"]);
    expect(ancestrySignals(2, processes)).toEqual(["ancestor:FACEIT*.exe"]);
    expect(ancestrySignals(1, processes)).toEqual([]);
  });

  it("machine-wide processes only produce a note", () => {
    const labels = machineWideAntiCheat(["explorer.exe", "vgc.exe", "FACEITService.exe"]);
    expect(labels).toEqual(["FACEIT*.exe", "vgc.exe"]);
    expect(machineWideNote(labels)).toBe(
      "A machine-wide anti-cheat service is running (FACEIT*.exe, vgc.exe); BEA refuses only targets that show anti-cheat signals themselves.",
    );
    expect(antiCheatVerdict({ signals: [], allowGlobal: false, allowedImages: [], imageSha256: null }).kind).toBe(
      "clean",
    );
    expect(
      antiCheatVerdict({ signals: ["dir:BattlEye"], allowGlobal: true, allowedImages: [], imageSha256: null }),
    ).toMatchObject({
      kind: "allowed",
      by: "global",
    });
  });
});

describe("spawn policy and environment (D-INT-41/42)", () => {
  it("refuses interpreters and LOLBins case-insensitively by basename", () => {
    for (const program of [
      "C:\\Windows\\System32\\CMD.EXE",
      "C:\\x\\pwsh.exe",
      "C:\\Python\\python.exe",
      "C:\\n\\node.exe",
      "C:\\w\\rundll32.exe",
    ])
      expect(isInterpreterOrLolbin(program), program).toBe(true);
    for (const program of ["C:\\games\\game.exe", "C:\\x\\cmd_helper.exe", "C:\\games\\pygame_demo.exe"])
      expect(isInterpreterOrLolbin(program)).toBe(false);
  });

  it("refuses conhost, taskkill and python/pip variants by name (SEC-1)", () => {
    for (const program of [
      "D:\\copy\\conhost.exe",
      "D:\\copy\\taskkill.exe",
      "D:\\copy\\python3.exe",
      "D:\\copy\\python3.14-64.exe",
      "D:\\copy\\pythonw3-64.exe",
      "D:\\copy\\pip3.14.exe",
      "D:\\copy\\pyw.exe",
      "D:\\copy\\ssh.exe",
      "D:\\copy\\wt.exe",
    ])
      expect(isInterpreterOrLolbin(program), program).toBe(true);
  });

  it("refuses system, alias and interpreter/toolchain locations from the server environment (SEC-1)", () => {
    const env = {
      SystemRoot: "C:\\WINDOWS",
      LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local",
      ProgramFiles: "C:\\Program Files",
      "ProgramFiles(x86)": "C:\\Program Files (x86)",
    };
    const locations = refusedLocations(env);
    const refused = (path: string) => programRefusal(path, path, locations);
    expect(refused("C:\\Windows\\System32\\whoami.exe")).toEqual({ rule: "location", location: "system-root" });
    expect(refused("C:\\Windows\\explorer.exe")).toEqual({ rule: "name" });
    expect(refused("C:\\Users\\u\\AppData\\Local\\Microsoft\\WindowsApps\\ubuntu.exe")).toEqual({
      rule: "location",
      location: "windowsapps-alias",
    });
    expect(refused("C:\\Users\\u\\AppData\\Local\\Python\\bin\\launcher.exe")).toMatchObject({
      location: "python-install",
    });
    expect(refused("C:\\Program Files\\Python314\\tool.exe")).toMatchObject({ location: "python-install" });
    expect(refused("C:\\Program Files\\Git\\usr\\bin\\env.exe")).toMatchObject({ location: "git-install" });
    expect(refused("C:\\msys64\\ucrt64\\bin\\addr2line.exe")).toMatchObject({ location: "posix-toolchain" });
    expect(refused("C:\\Python312\\Scripts\\x.exe")).toMatchObject({ location: "python-install" });
    // a sibling of a refused root, a game, and an MSYS2 home directory are not refused
    for (const ok of [
      "C:\\Windows2\\game.exe",
      "C:\\Games\\game.exe",
      "C:\\Program Files\\MyGame\\game.exe",
      "C:\\msys64\\home\\u\\proj\\game.exe",
    ])
      expect(refused(ok), ok).toBeNull();
    // the resolved final path decides as well (junction or 8.3 name to a refused root)
    expect(programRefusal("C:\\Tools\\link\\cn.exe", "C:\\Windows\\System32\\cn.exe", locations)).toMatchObject({
      rule: "location",
    });
  });

  it("refuses renamed copies by VERSIONINFO names and honours the user's allowed_programs (SEC-1)", () => {
    expect(versionInfoRefusal(["Cmd.Exe.MUI", "cmd"])).toEqual({ rule: "version-info" });
    expect(versionInfoRefusal(["CONHOST.EXE.MUI"])).toEqual({ rule: "version-info" });
    expect(versionInfoRefusal(["python.exe"])).toEqual({ rule: "version-info" });
    expect(versionInfoRefusal(["Game-Win64-Shipping.exe", "Game"])).toBeNull();
    expect(versionInfoRefusal([])).toBeNull();
    const sha = "ab".repeat(32);
    expect(allowedProgram([], ["C:\\Windows\\System32\\notepad.exe"], sha)).toBe(false);
    expect(allowedProgram(["c:/windows/system32/NOTEPAD.EXE"], ["C:\\Windows\\System32\\notepad.exe"], null)).toBe(
      true,
    );
    expect(allowedProgram([sha], ["C:\\x\\y.exe"], sha)).toBe(true);
    expect(allowedProgram([sha], ["C:\\x\\y.exe"], null)).toBe(false);
  });

  it("measures the CRT-quoted command line", () => {
    expect(quoteCrtArgument("plain")).toBe("plain");
    expect(quoteCrtArgument("two words")).toBe('"two words"');
    expect(quoteCrtArgument('say "hi"')).toBe('"say \\"hi\\""');
    expect(quoteCrtArgument("C:\\dir\\")).toBe("C:\\dir\\");
    expect(quoteCrtArgument("C:\\my dir\\")).toBe('"C:\\my dir\\\\"');
    expect(quoteCrtArgument("")).toBe('""');
    expect(crtCommandLineLength(["a.exe", "x y"])).toBe("a.exe".length + 1 + '"x y"'.length);
  });

  it("builds the allowlisted environment, strips BEA_* from both sources, counts only", () => {
    const env = buildTargetEnvironment({
      server: {
        Path: "C:\\bin",
        SystemRoot: "C:\\Windows",
        PROCESSOR_ARCHITECTURE: "AMD64",
        AWS_SECRET: "x",
        BEA_HOME: "h",
        undefinedKey: undefined,
      },
      caller: { GAME: "1", BEA_ALLOW_WRITE_MEMORY: "1", path: "D:\\mine" },
      mode: "allowlist",
      platform: "win32",
    });
    expect(env.env).toEqual({
      SystemRoot: "C:\\Windows",
      PROCESSOR_ARCHITECTURE: "AMD64",
      GAME: "1",
      path: "D:\\mine",
    });
    expect(env).toMatchObject({ droppedKeys: 2, callerKeys: 2, callerDropped: 1, allowlistVersion: 1 });
    const inherit = buildTargetEnvironment({
      server: { A: "1", BEA_X: "2" },
      caller: {},
      mode: "inherit",
      platform: "win32",
    });
    expect(inherit.env).toEqual({ A: "1" });
    expect(inherit.droppedKeys).toBe(1);
    expect(isAllowlisted("LC_ALL", "linux")).toBe(true);
    expect(isAllowlisted("lc_all", "linux")).toBe(false);
    expect(parseEnvEntries(["A=1", "B=x=y", "=bad", "C="])).toEqual({ A: "1", B: "x=y", C: "" });
  });

  it("converts Frida's µs `started` to FILETIME with its precision (S3 §8.2)", () => {
    const parsed = isoToFiletime100ns("2026-10-28T10:00:00.123456Z");
    expect(parsed?.precision100ns).toBe(10n);
    expect(parsed?.value).toBe(
      BigInt(Date.UTC(2026, 9, 28, 10, 0, 0)) * 10_000n + 1_234_560n + 116_444_736_000_000_000n,
    );
    expect(isoToFiletime100ns("2026-10-28T12:00:00+02:00")?.value).toBe(
      isoToFiletime100ns("2026-10-28T10:00:00Z")?.value,
    );
    expect(isoToFiletime100ns("yesterday")).toBeNull();
    expect(isoToFiletime100ns(undefined)).toBeNull();
  });
});
