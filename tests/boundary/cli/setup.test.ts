import { mkdir, readdir, readFile, realpath, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { parse as parseToml } from "smol-toml";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { DistLayout } from "../../../src/application/distLayout.js";
import { editCodexToml, editJsonEntry } from "../../../src/cli/setup/configDocument.js";
import { removeCodexTable } from "../../../src/cli/setup/removeEntry.js";
import { publishConfigFile, snapshotFile } from "../../../src/cli/setup/transaction.js";
import { notImplementedPort } from "../../../src/application/notImplemented.js";
import { ok } from "../../../src/domain/result.js";
import type { EmulatorProvisioner, ProvisionEmulatorAction } from "../../../src/ports/provisioner.js";
import { runCliInProcess, type CliHarnessOptions } from "../../support/cli/harness.js";
import { createPackageLayout, SKILL_TEXT } from "../../support/cli/packageLayout.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

let home: TempHome;
let layout: DistLayout;
let dispatcher: string;

beforeEach(async () => {
  home = await createTempHome("cli-setup");
  layout = await createPackageLayout(join(home.root, "pkg"));
  dispatcher = await realpath(layout.dispatcher);
});
afterEach(async () => {
  await home.cleanup();
});

const setup = (argv: readonly string[], extra: Partial<CliHarnessOptions> = {}) =>
  runCliInProcess(["setup", ...argv], { home, layout, ...extra });

const claudeJson = () => join(home.home, ".claude.json");
const readJson = async (path: string) => JSON.parse(await readFile(path, "utf8")) as Record<string, any>;
const entry = () => ({ command: process.execPath, args: [dispatcher, "mcp"] });
const listing = async (dir: string) => (await readdir(dir, { recursive: true })).sort();

describe("client registrations (S1 §7.9)", () => {
  it("claude_code: create, then an idempotent rerun is aligned (no write, no backup)", async () => {
    await mkdir(join(home.home, ".claude"));
    const created = await setup(["--client", "claude_code", "--no-skill", "--yes", "--json"]);
    expect(created.code).toBe(0);
    expect(created.doc()).toMatchObject({
      schema: "bea.setup/1",
      status: "ready",
      applied_actions: ["configured_claude_code"],
      clients: { claude_code: { state_before: "missing", outcome: "configured" } },
      restart: ["claude_code"],
      doctor: { healthy: true },
    });
    expect((await readJson(claudeJson()))["mcpServers"]["bea"]).toEqual(entry());
    expect(created.stderr).toContain("Restart Claude Code");
    const before = await listing(home.home);
    const again = await setup(["--client", "claude_code", "--no-skill", "--yes", "--json"]);
    expect(again.code).toBe(0);
    expect(again.doc()).toMatchObject({
      status: "ready",
      clients: { claude_code: { state_before: "aligned", outcome: "unchanged" } },
    });
    expect(await listing(home.home)).toEqual(before);
  });
  it("stale owned entry: update keeps BEA_* env only, other keys and a one-time backup", async () => {
    const original = JSON.stringify(
      {
        numStartups: 3,
        mcpServers: {
          rea: { command: "npx" },
          bea: { command: "node", args: [dispatcher, "mcp", "--old"], env: { BEA_LOG_LEVEL: "info", SECRET: "x" } },
        },
      },
      null,
      2,
    );
    await writeFile(claudeJson(), original);
    const r = await setup(["--client", "claude_code", "--no-skill", "--yes", "--json"]);
    expect(r.code).toBe(0);
    expect(r.doc()).toMatchObject({ clients: { claude_code: { state_before: "stale", outcome: "configured" } } });
    const after = await readJson(claudeJson());
    expect(after["mcpServers"]["bea"]).toEqual({ ...entry(), env: { BEA_LOG_LEVEL: "info" } });
    expect(after["numStartups"]).toBe(3);
    expect(after["mcpServers"]["rea"]).toEqual({ command: "npx" });
    expect(await readFile(`${claudeJson()}.bea.backup`, "utf8")).toBe(original);
  });
  it("a differing existing backup is kept and the current bytes get a .recovery copy", async () => {
    await writeFile(
      claudeJson(),
      JSON.stringify({ mcpServers: { bea: { command: "node", args: [dispatcher, "mcp", "--old"] } } }),
    );
    await writeFile(`${claudeJson()}.bea.backup`, "{}");
    const r = await setup(["--client", "claude_code", "--no-skill", "--yes"]);
    expect(r.code).toBe(0);
    expect(await readFile(`${claudeJson()}.bea.backup`, "utf8")).toBe("{}");
    expect(
      (await readdir(home.home)).some((name) => /^\.claude\.json\.bea\.backup\.[0-9a-f]{12}\.recovery$/u.test(name)),
    ).toBe(true);
  });
  for (const [state, content] of [
    ["foreign", JSON.stringify({ mcpServers: { bea: { command: "npx", args: ["-y", "someone-elses-bea"] } } })],
    [
      "unknown",
      JSON.stringify({ mcpServers: { bea: { command: "node", args: ["C:/elsewhere/scripts/bea.mjs", "mcp"] } } }),
    ],
    ["invalid", '{ // comments are not strict JSON\n "mcpServers": {} }'],
  ] as const)
    it(`${state} entry → needs_human, exit 1, nothing written`, async () => {
      await writeFile(claudeJson(), content);
      const before = await listing(home.home);
      const r = await setup(["--client", "claude_code", "--no-skill", "--yes", "--json"]);
      expect(r.code).toBe(1);
      expect(r.doc()).toMatchObject({
        status: "needs_human",
        applied_actions: [],
        clients: { claude_code: { state_before: state } },
      });
      expect(await readFile(claudeJson(), "utf8")).toBe(content);
      expect(await listing(home.home)).toEqual(before);
    });
  it("one blocked client blocks the whole setup (pre-validation)", async () => {
    await writeFile(claudeJson(), JSON.stringify({ mcpServers: { bea: { command: "npx", args: ["x"] } } }));
    const r = await setup(["--client", "claude_code", "--client", "cursor", "--no-skill", "--yes", "--json"]);
    expect(r.code).toBe(1);
    expect(r.doc()).toMatchObject({ status: "needs_human" });
    await expect(readFile(join(home.home, ".cursor", "mcp.json"))).rejects.toThrow();
  });
  it("codex: table edit keeps other tables, sub-tables and a larger tool timeout; dotted keys are manual", async () => {
    const codexDir = join(home.home, ".codex");
    await mkdir(codexDir);
    const original = `model = "gpt-x"\n# keep me\n[mcp_servers.rea]\ncommand = "npx"\n\n[mcp_servers.bea]\ncommand = "node"\nargs = ["${dispatcher.replaceAll("\\", "\\\\")}", "mcp", "--old"]\ntool_timeout_sec = 600\n\n[mcp_servers.bea.tools.read_memory]\napproval_mode = "approve"\n`;
    await writeFile(join(codexDir, "config.toml"), original);
    const r = await setup(["--client", "codex", "--yes", "--json"]);
    expect(r.code).toBe(0);
    const text = await readFile(join(codexDir, "config.toml"), "utf8");
    const toml = parseToml(text) as Record<string, any>;
    expect(toml["mcp_servers"]["bea"]).toMatchObject({
      command: process.execPath,
      args: [dispatcher, "mcp"],
      startup_timeout_sec: 30,
      tool_timeout_sec: 600,
    });
    expect(toml["mcp_servers"]["bea"]["tools"]["read_memory"]).toEqual({ approval_mode: "approve" });
    expect(text).toContain("# keep me");
    expect(toml["model"]).toBe("gpt-x");
    await writeFile(join(codexDir, "config.toml"), '[mcp_servers]\nbea.command = "x"\n');
    const manual = await setup(["--client", "codex", "--yes", "--json"]);
    expect(manual.doc()).toMatchObject({ status: "needs_human", clients: { codex: { state_before: "manual" } } });
  });
  it("vscode JSONC keeps comments and writes servers.bea with type stdio; cursor, gemini_cli, claude_desktop create", async () => {
    const vscodeDir = join(home.env["APPDATA"] ?? "", "Code", "User");
    await mkdir(vscodeDir, { recursive: true });
    await writeFile(
      join(vscodeDir, "mcp.json"),
      '{\n\t// my servers\n\t"servers": {\n\t\t"other": { "type": "stdio", "command": "x" }, // trailing\n\t},\n}\n',
    );
    const r = await setup([
      "--client",
      "vscode",
      "--client",
      "cursor",
      "--client",
      "gemini_cli",
      "--client",
      "claude_desktop",
      "--yes",
      "--json",
    ]);
    expect(r.code).toBe(0);
    const vscode = await readFile(join(vscodeDir, "mcp.json"), "utf8");
    expect(vscode).toContain("// my servers");
    expect(vscode).toContain("// trailing");
    expect(r.doc()).toMatchObject({
      applied_actions: ["configured_vscode", "configured_cursor", "configured_gemini_cli", "configured_claude_desktop"],
    });
    expect((await readJson(join(home.home, ".cursor", "mcp.json")))["mcpServers"]["bea"]).toEqual(entry());
    expect((await readJson(join(home.home, ".gemini", "settings.json")))["mcpServers"]["bea"]).toEqual(entry());
    const desktop =
      process.platform === "win32" ? join(home.env["APPDATA"] ?? "", "Claude") : join(home.home, ".config", "Claude");
    expect((await readJson(join(desktop, "claude_desktop_config.json")))["mcpServers"]["bea"]).toEqual(entry());
  });
});

describe("approval and scope (S1 §7.9.3)", () => {
  it("--dry-run plans and writes nothing; non-interactive without --yes needs confirmation", async () => {
    await mkdir(join(home.home, ".claude"));
    const before = await listing(home.root);
    const planned = await setup(["--client", "claude_code", "--dry-run", "--json"]);
    expect(planned.code).toBe(0);
    const doc = planned.doc() as {
      status: string;
      planned_actions: { kind: string; operation: string; path: string }[];
    };
    expect(doc.status).toBe("planned");
    expect(doc.planned_actions.map((a) => [a.kind, a.operation])).toEqual([
      ["configure_client", "create"],
      ["install_skill", "create"],
    ]);
    const confirm = await setup(["--client", "claude_code", "--json"]);
    expect(confirm.code).toBe(1);
    expect(confirm.doc()).toMatchObject({ status: "needs_confirmation" });
    expect(await listing(home.root)).toEqual(before);
  });
  it("interactive approval on a TTY: plan and prompt on stderr; y applies, anything else cancels", async () => {
    const tty = { stdin: true, stdout: true, stderr: true };
    const no = await setup(["--client", "cursor"], { tty, answers: ["n"] });
    expect(no.code).toBe(0);
    expect(no.prompts).toEqual(["Apply these 1 changes? [y/N] "]);
    expect(no.stderr).toContain("create bea in");
    expect(no.doc()).toMatchObject({ status: "cancelled" });
    const yes = await setup(["--client", "cursor"], { tty, answers: ["y"] });
    expect(yes.doc()).toMatchObject({ status: "ready", applied_actions: ["configured_cursor"] });
  });
  it("--yes without --client refreshes only owned registrations; --all-detected adds detected clients", async () => {
    await mkdir(join(home.home, ".claude"));
    await mkdir(join(home.home, ".cursor"));
    await writeFile(
      join(home.home, ".cursor", "mcp.json"),
      JSON.stringify({ mcpServers: { bea: { command: "node", args: [dispatcher, "mcp", "x"] } } }),
    );
    const refresh = await setup(["--yes", "--json"]);
    expect(refresh.doc()).toMatchObject({ status: "ready", applied_actions: ["configured_cursor"] });
    await expect(readFile(claudeJson())).rejects.toThrow();
    const all = await setup(["--all-detected", "--no-skill", "--yes", "--json"]);
    expect(all.doc()).toMatchObject({
      applied_actions: ["configured_claude_code"],
      clients: { cursor: { outcome: "unchanged" } },
    });
  });
  it("nothing selected → ready with a remediation", async () => {
    const r = await setup(["--yes", "--json"]);
    expect(r.code).toBe(0);
    expect(r.doc()).toMatchObject({ status: "ready", planned_actions: [] });
    expect(String(r.doc()["remediation"])).toContain("--client");
  });
  it("a dispatcher inside npm's _npx cache is refused", async () => {
    const npx = await createPackageLayout(join(home.root, "_npx", "abc", "pkg"));
    const r = await setup(["--client", "cursor", "--yes", "--json"], { layout: npx });
    expect(r.code).toBe(1);
    expect(r.doc()).toMatchObject({ status: "needs_human" });
  });
  it("unknown --client ids and flags are invalid_request", async () => {
    expect((await setup(["--client", "notepad", "--json"])).doc()).toMatchObject({
      error: { code: "invalid_request" },
    });
    expect((await setup(["--frobnicate"])).code).toBe(1);
  });
});

describe("skill install (S1 §7.9.6)", () => {
  const skillDir = () => join(home.home, ".claude", "skills", "bea-dynamic-analysis");
  it("installs, is unchanged on rerun, updates an owned stale copy, refuses an unmanaged directory", async () => {
    const first = await setup(["--skill", "--yes", "--json"]);
    expect(first.doc()).toMatchObject({
      status: "ready",
      applied_actions: ["installed_skill"],
      doctor: { healthy: true },
    });
    expect(await readFile(join(skillDir(), "SKILL.md"), "utf8")).toBe(SKILL_TEXT());
    expect(await readFile(join(skillDir(), "references", "address-model.md"), "utf8")).toBe("# Address model\n");
    const again = await setup(["--skill", "--yes", "--json"]);
    expect(again.doc()).toMatchObject({ status: "ready", applied_actions: [] });
    const newer = await createPackageLayout(join(home.root, "pkg2"), { skill: SKILL_TEXT("2", 38) });
    const update = await setup(["--skill", "--yes", "--json"], { layout: newer });
    expect(update.doc()).toMatchObject({ applied_actions: ["installed_skill"] });
    expect(await readFile(join(skillDir(), "SKILL.md"), "utf8")).toBe(SKILL_TEXT("2", 38));
    expect((await readdir(join(home.home, ".claude", "skills"))).sort()).toEqual(["bea-dynamic-analysis"]);
    await writeFile(join(skillDir(), "SKILL.md"), "---\nname: someone-else\n---\n");
    const foreign = await setup(["--skill", "--yes", "--json"]);
    expect(foreign.code).toBe(1);
    expect(foreign.doc()).toMatchObject({ status: "needs_human" });
  });
  it("a missing bundled skill blocks with a build remediation", async () => {
    const bare = await createPackageLayout(join(home.root, "bare"), { skill: null });
    const r = await setup(["--skill", "--yes", "--json"], { layout: bare });
    expect(r.code).toBe(1);
    expect(String(r.doc()["remediation"])).toContain("npm run build");
  });
});

describe("--emulator (CI-I7 EmulatorProvisioner port)", () => {
  const action: ProvisionEmulatorAction = {
    id: "provision_emulator",
    kind: "provision_emulator",
    venv: "C:\\bea\\emu\\venv",
    tool: "uv",
    python: "C:\\Python314\\python.exe",
    packages: ["unicorn==2.1.4", "capstone==5.0.9", "pefile==2024.8.26"],
    network_origins: ["https://pypi.org"],
    commands: [["uv", "venv", "C:\\bea\\emu\\venv"]],
  };
  it("plans through the port, applies only with --yes", async () => {
    const applied: ProvisionEmulatorAction[] = [];
    const provisioner = (): EmulatorProvisioner => ({
      plan: async () => ok(action),
      apply: async (a) => {
        applied.push(a);
        return ok({ python: "C:\\bea\\emu\\venv\\Scripts\\python.exe", versions: { unicorn: "2.1.4" } });
      },
    });
    const dry = await setup(["--emulator", "--dry-run", "--json"], { provisioner });
    expect(dry.doc()).toMatchObject({ status: "planned", planned_actions: [action] });
    expect(applied).toHaveLength(0);
    const yes = await setup(["--emulator", "--yes", "--json"], { provisioner });
    expect(yes.doc()).toMatchObject({ status: "ready", applied_actions: ["provisioned_emulator"] });
    expect(applied).toEqual([action]);
  });
  it("the WP0 stub (not implemented) is a needs_human plan blocker, not a crash", async () => {
    const r = await setup(["--emulator", "--yes", "--json"], {
      provisioner: () => notImplementedPort<EmulatorProvisioner>("provisioner"),
    });
    expect(r.code).toBe(1);
    expect(r.doc()).toMatchObject({ status: "needs_human" });
  });
});

describe("transaction and document edits (VERIFIED-S1 lab cases)", () => {
  it("target_changed when the file changed after planning; nothing is written", async () => {
    const path = join(home.work, "mcp.json");
    await writeFile(path, '{\n  "servers": {}\n}\n');
    const snap = await snapshotFile(path);
    if (snap === null || snap === "symlink") throw new Error("unexpected");
    const edit = editJsonEntry(snap.bytes.toString("utf8"), ["servers", "bea"], { command: "x" }, "jsonc");
    if (edit.kind !== "edited") throw new Error(edit.reason);
    await writeFile(path, '{\n  "servers": {}\n} ');
    const result = await publishConfigFile(path, snap, edit.text, () => true);
    expect(result).toEqual({ ok: false, failure: "target_changed", backupPath: null, recoveryPath: null });
    expect(await readFile(path, "utf8")).toBe('{\n  "servers": {}\n} ');
  });
  it("a failed read-back verification rolls back to the snapshot bytes", async () => {
    const path = join(home.work, "c.json");
    await writeFile(path, "{}");
    const snap = await snapshotFile(path);
    if (snap === null || snap === "symlink") throw new Error("unexpected");
    const result = await publishConfigFile(path, snap, '{"a":1}', () => false);
    expect(result).toMatchObject({ ok: false, failure: "readback" });
    expect(await readFile(path, "utf8")).toBe("{}");
  });
  it("Codex removal drops the table and its sub-tables only", () => {
    const text =
      'model = "m"\n[mcp_servers.rea]\ncommand = "npx"\n\n[mcp_servers.bea]\ncommand = "node"\n\n[mcp_servers.bea.env]\nBEA_LOG_LEVEL = "info"\n\n[profiles.x]\na = 1\n';
    const removed = removeCodexTable(text);
    expect(removed.kind).toBe("edited");
    const parsed = parseToml(removed.kind === "edited" ? removed.text : "") as Record<string, any>;
    expect(parsed["mcp_servers"]).toEqual({ rea: { command: "npx" } });
    expect(parsed["profiles"]).toEqual({ x: { a: 1 } });
    expect(
      editCodexToml('[mcp_servers]\nbea = { command = "x" }\n', {
        command: "n",
        args: [],
        startup_timeout_sec: 30,
        tool_timeout_sec: 240,
      }).kind,
    ).toBe("manual");
  });
});

describe("uninstall", () => {
  it("removes owned registrations (JSON and Codex) and the owned skill; leaves foreign entries", async () => {
    await mkdir(join(home.home, ".codex"));
    await writeFile(join(home.home, ".codex", "config.toml"), 'model = "m"\n');
    const installed = await setup(["--client", "claude_code", "--client", "codex", "--skill", "--yes", "--json"]);
    expect(installed.doc()).toMatchObject({ status: "ready" });
    expect(installed.code).toBe(0);
    await mkdir(join(home.home, ".cursor"));
    const foreign = JSON.stringify({ mcpServers: { bea: { command: "npx", args: ["other"] } } });
    await writeFile(join(home.home, ".cursor", "mcp.json"), foreign);
    const dry = await runCliInProcess(["uninstall", "--dry-run", "--json"], { home, layout });
    expect(dry.doc()).toMatchObject({ status: "planned" });
    const r = await runCliInProcess(["uninstall", "--yes", "--json"], { home, layout });
    expect(r.code).toBe(0);
    expect(r.doc()).toMatchObject({
      status: "ready",
      applied_actions: ["removed_claude_code", "removed_codex", "removed_skill"],
    });
    expect((await readJson(claudeJson()))["mcpServers"]).toEqual({});
    expect(parseToml(await readFile(join(home.home, ".codex", "config.toml"), "utf8"))).toEqual({ model: "m" });
    expect(await readFile(join(home.home, ".cursor", "mcp.json"), "utf8")).toBe(foreign);
    await expect(readdir(join(home.home, ".claude", "skills", "bea-dynamic-analysis"))).rejects.toThrow();
  });
});

const canSymlink = await (async () => {
  const probe = await createTempHome("symlink-probe");
  try {
    await writeFile(join(probe.work, "a"), "x");
    await symlink(join(probe.work, "a"), join(probe.work, "b"), "file");
    return true;
  } catch {
    return false;
  } finally {
    await probe.cleanup();
  }
})();

describe("symlinks", () => {
  it.skipIf(!canSymlink)("a symlinked config file is never edited (needs symlink privilege on Windows)", async () => {
    const real = join(home.work, "real.json");
    await writeFile(real, "{}");
    await symlink(real, join(home.home, ".claude.json"), "file");
    const r = await setup(["--client", "claude_code", "--no-skill", "--yes", "--json"]);
    expect(r.doc()).toMatchObject({ status: "needs_human", clients: { claude_code: { state_before: "symlink" } } });
    expect(await readFile(real, "utf8")).toBe("{}");
  });
});
