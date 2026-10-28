import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { distLayoutAt } from "../../../src/application/distLayout.js";
import { projectBeaError } from "../../../src/domain/errors/projection.js";
import { ok } from "../../../src/domain/result.js";
import { locateBridge } from "../../../src/providers/emulator/bridgeLocator.js";
import {
  noOutputReason,
  PythonResolver,
  runBridgeProbe,
  venvPython,
  type ProbeOutcome,
  type ProbeRequest,
} from "../../../src/providers/emulator/pythonResolver.js";
import { fakeSpawn, tempDir, writeScenario, type TempDir } from "../../support/emu/harness.js";

/** Python resolution (F7, S5 §6.1, CI-M7, CT-M11) and the bridge locator (S5 §4.2 step 2). */
let work: TempDir;
beforeAll(async () => {
  work = await tempDir("resolver");
});
afterAll(async () => {
  await work.cleanup();
});

const line = (engines: Record<string, string> = {}, version = "3.14.6"): ProbeOutcome => ({
  kind: "line",
  ms: 120,
  exitCode: 0,
  line: {
    probe: "bea-emu/0.1",
    ok: true,
    bridge: { version: "0.1.0", sha256: "a".repeat(64) },
    python: { version, executable: "C:\\py\\python.exe", inVenv: false },
    engines: { unicorn: "2.1.4", unicornCore: "2.1", capstone: "5.0.9", pefile: "2024.8.26", ...engines },
  },
});
const missing: ProbeOutcome = {
  kind: "line",
  ms: 80,
  exitCode: 3,
  line: { probe: "bea-emu/0.1", ok: false, missing: ["unicorn"] },
};

const resolverWith = (
  configured: { value: string | null; source: "env" | "config-file" | "default" },
  outcomes: Readonly<Record<string, ProbeOutcome>>,
  existing: readonly string[],
  platform: "win32" | "linux" = "win32",
) => {
  const probed: string[] = [];
  const resolver = new PythonResolver({
    platform,
    configured,
    venvDir: platform === "win32" ? "C:\\home\\emu\\venv" : "/home/u/emu/venv",
    bridge: async () => ok({ path: "C:\\bea\\bridge\\emu\\bea_emu_bridge.py", sha256: "a".repeat(64) }),
    probe: async (request: ProbeRequest) => {
      const key = [request.command.command, ...request.command.prefixArgs].join(" ");
      probed.push(key);
      return outcomes[key] ?? { kind: "not-found" };
    },
    exists: async (path) => existing.includes(path),
  });
  return { resolver, probed };
};

describe("PythonResolver", () => {
  it("uses BEA_PYTHON first and never falls through", async () => {
    const { resolver, probed } = resolverWith(
      { value: "C:\\py\\python.exe", source: "env" },
      { "C:\\py\\python.exe": missing, python: line() },
      ["C:\\py\\python.exe"],
    );
    const result = await resolver.resolve("emu_open");
    expect(result.ok).toBe(false);
    expect(probed).toEqual(["C:\\py\\python.exe"]);
    if (!result.ok) {
      const projected = projectBeaError(result.error);
      expect(projected).toMatchObject({
        code: "capability_unavailable",
        details: { reason: "configured-python-unusable" },
      });
      expect(projected.message).toContain("BEA_PYTHON");
      expect(projected.message).toContain("-I");
      expect(projected.remediation.action).toContain("bea setup --emulator");
    }
    expect(resolver.status()).toMatchObject({ state: "unavailable" });
  });

  it("reports a BEA_PYTHON that does not exist as configuration_invalid", async () => {
    const { resolver } = resolverWith({ value: "C:\\nope\\python.exe", source: "env" }, {}, []);
    const result = await resolver.resolve("emu_open");
    expect(!result.ok && projectBeaError(result.error)).toMatchObject({ code: "configuration_invalid" });
  });

  it("takes config.json python as the next explicit source", async () => {
    const { resolver } = resolverWith(
      { value: "C:\\py\\python.exe", source: "config-file" },
      { "C:\\py\\python.exe": line({}, "3.12.1") },
      ["C:\\py\\python.exe"],
    );
    const result = await resolver.resolve("emu_open");
    expect(result.ok && result.value).toMatchObject({ source: "config", version: "3.12.1", pin: "exact" });
    expect(resolver.status()).toMatchObject({ state: "available", source: "config", pin: "exact" });
  });

  it("falls through a broken BEA venv to PATH, skipping missing aliases and rejecting mismatches", async () => {
    const venv = venvPython("C:\\home\\emu\\venv", "win32");
    const { resolver, probed } = resolverWith(
      { value: null, source: "default" },
      { [venv]: missing, python: line({ unicorn: "2.0.1" }), "py -3": line({ unicorn: "2.1.3" }) },
      [venv],
    );
    const result = await resolver.resolve("emu_open");
    expect(probed).toEqual([venv, "python", "py -3"]);
    expect(result.ok && result.value).toMatchObject({
      source: "path",
      command: "py",
      prefixArgs: ["-3"],
      pin: "compatible",
    });
    const report = resolver.report();
    expect(report.candidates.map((c) => c.source)).toEqual(["bea-venv", "path", "path"]);
    expect(report.candidates[0]?.outcome).toContain("bea setup --emulator");
    expect(report.candidates[0]?.outcome).not.toContain("--repair"); // ONBOARD-4: no such flag
    expect(report.candidates[1]?.outcome).toContain("rejected");
  });

  it("uses the venv when it works, linux candidates otherwise, and memoizes until invalidate()", async () => {
    const venv = venvPython("/home/u/emu/venv", "linux");
    expect(venv).toBe("/home/u/emu/venv/bin/python3");
    const { resolver, probed } = resolverWith({ value: null, source: "default" }, { [venv]: line() }, [venv], "linux");
    expect((await resolver.resolve("emu_open")).ok).toBe(true);
    await resolver.resolve("emu_open");
    expect(probed).toEqual([venv]);
    resolver.invalidate();
    expect(resolver.status().state).toBe("not-resolved");
    await resolver.resolve("emu_open");
    expect(probed).toEqual([venv, venv]);
    const none = resolverWith({ value: null, source: "default" }, {}, [], "linux");
    const result = await none.resolver.resolve("emu_open");
    expect(none.probed).toEqual(["python3", "python"]);
    expect(!result.ok && projectBeaError(result.error)).toMatchObject({
      code: "capability_unavailable",
      details: { reason: "python-unavailable" },
    });
  });

  it("does not keep a failed resolution: a venv created later is picked up without a restart (ONBOARD-2)", async () => {
    const venv = venvPython("/home/u/emu/venv", "linux");
    const existing: string[] = [];
    const outcomes: Record<string, ProbeOutcome> = {};
    const probed: string[] = [];
    const resolver = new PythonResolver({
      platform: "linux",
      configured: { value: null, source: "default" },
      venvDir: "/home/u/emu/venv",
      bridge: async () => ok({ path: "/bea/bridge/emu/bea_emu_bridge.py", sha256: "a".repeat(64) }),
      probe: async (request: ProbeRequest) => {
        probed.push(request.command.command);
        return outcomes[request.command.command] ?? { kind: "not-found" };
      },
      exists: async (path) => existing.includes(path),
    });
    expect((await resolver.resolve("emu_open")).ok).toBe(false);
    expect(resolver.status().state).toBe("unavailable");
    // `bea setup --emulator` creates the venv while the server runs
    existing.push(venv);
    outcomes[venv] = line();
    const again = await resolver.resolve("emu_open");
    expect(again.ok).toBe(true);
    expect(resolver.status().state).toBe("available");
    // a success stays memoized
    const count = probed.length;
    await resolver.resolve("emu_open");
    expect(probed.length).toBe(count);
  });

  it("explains a probe that printed nothing with its stderr tail and the install-manager exit code (ONBOARD-11)", () => {
    expect(noOutputReason(0xa0000006, "")).toContain("py install default");
    expect(noOutputReason(0xc0000135, "")).toBe("no output (exit 0xc0000135)");
    expect(noOutputReason(1, "Traceback (most recent call last):\nModuleNotFoundError: No module named 'x'\n")).toBe(
      "no output (exit 1): ModuleNotFoundError: No module named 'x'",
    );
  });

  it("runs the bridge probe as a child process and parses its last line", async () => {
    const file = await writeScenario(work.dir, {}, "probe.json");
    const outcome = await runBridgeProbe(
      { command: { command: "python", prefixArgs: [] }, bridgePath: file.path, mode: "--probe", timeoutMs: 10_000 },
      fakeSpawn,
    );
    expect(outcome.kind).toBe("line");
    if (outcome.kind === "line")
      expect(outcome.line).toMatchObject({ probe: "bea-emu/0.1", ok: true, bridge: { sha256: file.sha256 } });
    const absent = await runBridgeProbe({
      command: { command: "bea-no-such-python-xyz", prefixArgs: [] },
      bridgePath: file.path,
      mode: "--probe",
      timeoutMs: 10_000,
    });
    expect(absent.kind).toBe("not-found");
  });
});

describe("bridgeLocator", () => {
  it("computes the digest from source, matches a manifest and refuses a swapped bridge", async () => {
    const root = join(work.dir, "pkg");
    await mkdir(join(root, "bridge", "emu"), { recursive: true });
    await mkdir(join(root, "dist"), { recursive: true });
    await writeFile(join(root, "bridge", "emu", "bea_emu_bridge.py"), "print('bridge')\n");
    const fromSource = distLayoutAt(join(root, "dist"), true);
    const computed = await locateBridge(fromSource, "emu_open");
    expect(computed.ok && computed.value).toMatchObject({ source: "computed", version: "0.1.0" });
    const sha = computed.ok ? computed.value.sha256 : "";
    const built = distLayoutAt(join(root, "dist"), false);
    const noManifest = await locateBridge(built, "emu_open");
    expect(!noManifest.ok && projectBeaError(noManifest.error).details).toMatchObject({
      reason: "bridge-manifest-missing",
    });
    await writeFile(
      built.bridgeManifest,
      JSON.stringify({
        schema: "bea.bridge-build/1",
        protocol: "bea-emu/0.1",
        sha256: sha,
        requirements_lock_sha256: "b".repeat(64),
      }),
    );
    const matched = await locateBridge(built, "emu_open");
    expect(matched.ok && matched.value).toMatchObject({ source: "manifest", sha256: sha, lockSha256: "b".repeat(64) });
    await writeFile(join(root, "bridge", "emu", "bea_emu_bridge.py"), "print('swapped')\n");
    const swapped = await locateBridge(built, "emu_open");
    expect(!swapped.ok && projectBeaError(swapped.error).details).toMatchObject({ reason: "bridge-file-mismatch" });
    await writeFile(built.bridgeManifest, JSON.stringify({ protocol: "bea-emu/0.2", sha256: sha }));
    const protocol = await locateBridge(built, "emu_open");
    expect(!protocol.ok && projectBeaError(protocol.error).details).toMatchObject({
      reason: "bridge-protocol-mismatch",
    });
    const nowhere = await locateBridge(distLayoutAt(join(work.dir, "nowhere", "dist"), true), "emu_open");
    expect(!nowhere.ok && projectBeaError(nowhere.error).details).toMatchObject({ reason: "bridge-missing" });
  });
});
