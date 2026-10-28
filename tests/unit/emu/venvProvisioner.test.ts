import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { distLayoutAt } from "../../../src/application/distLayout.js";
import { loadConfig, type BeaConfig } from "../../../src/domain/config.js";
import { projectBeaError } from "../../../src/domain/errors/projection.js";
import type { HostPlatform } from "../../../src/domain/paths.js";
import type { ProbeOutcome, ProbeRequest } from "../../../src/providers/emulator/pythonResolver.js";
import {
  createEmulatorProvisioner,
  parseRequirementsLock,
  VENV_MARKER_FILE,
  type CommandOutcome,
  type CommandRunner,
} from "../../../src/providers/emulator/venvProvisioner.js";
import { tempDir, type TempDir } from "../../support/emu/harness.js";

/**
 * `bea setup --emulator` behind the WP0 port (S5 §6.4) with a scripted command runner and probe: no network, no
 * real venv. The real uv/pip install was verified in the S5 lab (S5-E3); this pins the plan, the staging/commit
 * protocol, the ownership refusal, the rollback and the setup lock.
 */
const LOCK = `# BEA emulator bridge: exact pins
unicorn==2.1.4 \\
    --hash=sha256:d7107500c64ce5c168fbff6bef9485b5db1350050036f4cea568650cf8bdbdf5
capstone==5.0.9 \\
    --hash=sha256:732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0
pefile==2024.8.26 \\
    --hash=sha256:76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f
`;
let work: TempDir;
beforeAll(async () => {
  work = await tempDir("setup");
});
afterAll(async () => {
  await work.cleanup();
});

const ok = (stdout = ""): CommandOutcome => ({ exitCode: 0, stdout, stderr: "", timedOut: false, notFound: false });
const BASE = JSON.stringify({ v: "3.14.6", impl: "cpython", bits: 64, exe: "C:\\py\\python.exe" });

let counter = 0;
const fixture = async (
  options: { uv?: boolean; installFails?: boolean; probeExact?: boolean; reprobeFails?: boolean } = {},
) => {
  counter += 1;
  const root = join(work.dir, `case-${String(counter)}`);
  await mkdir(join(root, "pkg", "bridge", "emu"), { recursive: true });
  await mkdir(join(root, "pkg", "dist"), { recursive: true });
  await writeFile(join(root, "pkg", "bridge", "emu", "requirements.lock"), LOCK);
  await writeFile(join(root, "pkg", "bridge", "emu", "bea_emu_bridge.py"), "# bridge\n");
  const loaded = await loadConfig({
    env: { BEA_HOME: join(root, "home") },
    platform: process.platform as HostPlatform,
    accountHome: root,
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error("config");
  const config: BeaConfig = loaded.value;
  const commands: string[][] = [];
  const run: CommandRunner = async (argv) => {
    commands.push([...argv]);
    if (argv[0] === "uv" && argv[1] === "--version")
      return options.uv === false ? { ...ok(), exitCode: null, notFound: true } : ok("uv 0.13.1");
    if (argv[0] === "uv" && argv[1] === "python") return ok("C:\\py\\python.exe\n");
    if (argv.includes("-c")) return ok(`${BASE}\n`);
    if (argv[0] === "uv" && argv[1] === "venv") {
      await mkdir(argv[2] ?? "", { recursive: true });
      return ok();
    }
    if (argv.includes("venv") && argv.includes("-m")) {
      await mkdir(argv.at(-1) ?? "", { recursive: true });
      return ok();
    }
    if (argv.includes("install"))
      return options.installFails === true ? { ...ok(), exitCode: 1, stderr: "hash mismatch" } : ok();
    return ok();
  };
  let probes = 0;
  const probe = async (request: ProbeRequest): Promise<ProbeOutcome> => {
    probes += 1;
    if (request.mode === "--selftest")
      return {
        kind: "line",
        ms: 5,
        exitCode: 0,
        line: {
          probe: "x",
          ok: true,
          results: {
            mxcsr_flags_modeled: { ok: true, observed: false, expected: false },
            ...Object.fromEntries(
              [
                "fp_reset",
                "vex128_misexecutes",
                "vex256_rejected",
                "bmi_ok",
                "tb_hook_gotcha",
                "count_budget_gotcha",
                "cow_lifo_ok",
                "context_mode_toggle",
                "int3_rip",
                "x87_reset",
                "insn_hooks",
                "gs_base",
                "memory_limit",
              ].map((n) => [n, { ok: true }]),
            ),
          },
        } as never,
      };
    if (options.reprobeFails === true && !request.command.command.includes("staging"))
      return { kind: "failed", reason: "launcher", exitCode: 1 };
    return {
      kind: "line",
      ms: 100,
      exitCode: 0,
      line: {
        probe: "bea-emu/0.1",
        ok: true,
        python: { version: "3.14.6" },
        engines: {
          unicorn: options.probeExact === false ? "2.1.3" : "2.1.4",
          unicornCore: "2.1",
          capstone: "5.0.9",
          pefile: "2024.8.26",
        },
      },
    };
  };
  const provisioner = createEmulatorProvisioner(
    { config },
    {
      run,
      probe,
      layout: distLayoutAt(join(root, "pkg", "dist"), true),
      randomId: () => `id${String(counter).padStart(6, "0")}`,
      nowIso: () => "2026-10-28T08:00:00.000Z",
    },
  );
  return { provisioner, config, commands, root, probes: () => probes };
};

describe("venv provisioner (S5 §6.4)", () => {
  it("parses the exact pins of requirements.lock", () => {
    expect(parseRequirementsLock(LOCK)).toEqual(["unicorn==2.1.4", "capstone==5.0.9", "pefile==2024.8.26"]);
  });

  it("plans the uv route with hash-locked, binary-only flags", async () => {
    const { provisioner, config } = await fixture();
    const planned = await provisioner.plan(config, new AbortController().signal);
    expect(planned.ok).toBe(true);
    if (!planned.ok) return;
    expect(planned.value).toMatchObject({
      kind: "provision_emulator",
      tool: "uv",
      venv: config.layout.venvDir,
      python: "C:\\py\\python.exe",
      packages: ["unicorn==2.1.4", "capstone==5.0.9", "pefile==2024.8.26"],
    });
    expect(planned.value.commands[1]).toEqual(
      expect.arrayContaining(["--require-hashes", "--only-binary", ":all:", "--no-deps"]),
    );
  });

  it("plans the venv+pip route when uv is absent", async () => {
    const { provisioner, config } = await fixture({ uv: false });
    const planned = await provisioner.plan(config, new AbortController().signal);
    expect(planned.ok && planned.value.tool).toBe("venv+pip");
    if (planned.ok)
      expect(planned.value.commands[1]).toEqual(
        expect.arrayContaining(["--require-hashes", "--only-binary=:all:", "--no-deps", "--no-input"]),
      );
  });

  it("builds in staging, verifies, writes the marker and commits by rename", async () => {
    const { provisioner, config } = await fixture();
    const planned = await provisioner.plan(config, new AbortController().signal);
    if (!planned.ok) throw new Error("plan");
    const applied = await provisioner.apply(planned.value, new AbortController().signal);
    expect(applied.ok && applied.value.versions).toEqual({
      python: "3.14.6",
      unicorn: "2.1.4",
      capstone: "5.0.9",
      pefile: "2024.8.26",
    });
    const marker = JSON.parse(await readFile(join(config.layout.venvDir, VENV_MARKER_FILE), "utf8")) as Record<
      string,
      unknown
    >;
    expect(marker).toMatchObject({
      schema: "bea.emu-venv/1",
      tool: "uv",
      created_by: { package: "bea-agents", version: "0.1.0" },
    });
    expect(String(marker["lock_sha256"])).toMatch(/^[a-f0-9]{64}$/u);
    await expect(stat(join(config.layout.emuDir, ".setup.lock"))).rejects.toThrow();
    // a repair over an owned venv replaces it
    const again = await provisioner.plan(config, new AbortController().signal);
    if (!again.ok) throw new Error("plan");
    expect((await provisioner.apply(again.value, new AbortController().signal)).ok).toBe(true);
  });

  it("refuses to replace a directory it does not own BEFORE building anything, and cleans its staging", async () => {
    const { provisioner, config, commands } = await fixture();
    await mkdir(config.layout.venvDir, { recursive: true });
    await writeFile(join(config.layout.venvDir, "user-file.txt"), "mine");
    const planned = await provisioner.plan(config, new AbortController().signal);
    if (!planned.ok) throw new Error("plan");
    const before = commands.length;
    const applied = await provisioner.apply(planned.value, new AbortController().signal);
    // ONBOARD-4: no create/install command ran for a refused target, and the refusal says what to do
    expect(commands.length).toBe(before);
    expect(!applied.ok && applied.error.message).toContain("delete or move");
    expect(!applied.ok && projectBeaError(applied.error)).toMatchObject({
      code: "file_operation_failed",
      details: { reason: "exists" },
    });
    expect(await readFile(join(config.layout.venvDir, "user-file.txt"), "utf8")).toBe("mine");
    await expect(stat(join(config.layout.emuDir, `venv.staging-${planned.value.id}`))).rejects.toThrow();
  });

  it("fails on an install error or an unpinned engine, and rolls back when the committed venv does not run", async () => {
    const failing = await fixture({ installFails: true });
    const p1 = await failing.provisioner.plan(failing.config, new AbortController().signal);
    if (!p1.ok) throw new Error("plan");
    const a1 = await failing.provisioner.apply(p1.value, new AbortController().signal);
    expect(!a1.ok && projectBeaError(a1.error)).toMatchObject({
      code: "execution_failure",
      details: { diagnostics: { step: "install", exit_code: 1 } },
    });
    const unpinned = await fixture({ probeExact: false });
    const p2 = await unpinned.provisioner.plan(unpinned.config, new AbortController().signal);
    if (!p2.ok) throw new Error("plan");
    const a2 = await unpinned.provisioner.apply(p2.value, new AbortController().signal);
    expect(!a2.ok && projectBeaError(a2.error).message).toContain("pinned engine set");
    const relocated = await fixture({ reprobeFails: true });
    const p3 = await relocated.provisioner.plan(relocated.config, new AbortController().signal);
    if (!p3.ok) throw new Error("plan");
    const a3 = await relocated.provisioner.apply(p3.value, new AbortController().signal);
    expect(a3.ok).toBe(false);
    await expect(stat(relocated.config.layout.venvDir)).rejects.toThrow();
  });

  it("refuses while another setup holds the lock", async () => {
    const { provisioner, config } = await fixture();
    await mkdir(config.layout.emuDir, { recursive: true });
    await writeFile(join(config.layout.emuDir, ".setup.lock"), "{}");
    const planned = await provisioner.plan(config, new AbortController().signal);
    if (!planned.ok) throw new Error("plan");
    const applied = await provisioner.apply(planned.value, new AbortController().signal);
    expect(!applied.ok && projectBeaError(applied.error).code).toBe("resource_constraint");
  });
});
