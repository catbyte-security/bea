import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { deriveCommand, parseCommandArgs, type DerivedCommand } from "../../../src/cli/argv.js";
import { buildCommandTable, matchCommand } from "../../../src/cli/commands.js";
import { renderCommandHelp } from "../../../src/cli/help.js";
import { TOOL_CONTRACTS } from "../../../src/contracts/index.js";
import { FAKE_CONTRACTS } from "../../support/cli/fakeCatalog.js";
import { runCliInProcess } from "../../support/cli/harness.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

const commandFor = (name: string): DerivedCommand => {
  const contract = FAKE_CONTRACTS.find((c) => c.name === name);
  const derived = contract === undefined ? null : deriveCommand(contract);
  if (derived === null) throw new Error(`${name} has no command`);
  return derived;
};

describe("S1 §7.3 argv table (labCliProbe cases)", () => {
  const read = commandFor("read_memory");
  it("positional pid, address, size plus flags, lists and --no-*", () => {
    const parsed = parseCommandArgs(read, [
      "1234",
      "demo.exe+0x8000",
      "64",
      "--format",
      "values",
      "--types",
      "f32",
      "--types",
      "u32",
      "--no-follow-pointers",
    ]);
    expect(parsed.ok && parsed.value).toMatchObject({
      input: { address: "demo.exe+0x8000", size: 64, format: "values", follow_pointers: false, types: ["f32", "u32"] },
      target: { kind: "pid", pid: 1234 },
      format: "toon",
    });
  });
  it("--pid removes the pid slot; --json selects JSON", () => {
    const parsed = parseCommandArgs(read, ["demo.exe+0x8000", "--pid", "77", "--json"]);
    expect(parsed.ok && parsed.value).toMatchObject({
      input: { address: "demo.exe+0x8000" },
      target: { kind: "pid", pid: 77 },
      format: "json",
    });
  });
  it("everything after -- is the spawned program's argv", () => {
    const parsed = parseCommandArgs(read, ["demo.exe+0x8000", "--spawn", "C:/lab/demo.exe", "--", "serve", "--fast"]);
    expect(parsed.ok && parsed.value.target).toEqual({
      kind: "spawn",
      program: "C:/lab/demo.exe",
      args: ["serve", "--fast"],
    });
  });
  it("two target flags conflict; an unknown flag and a missing target are invalid_request issues", () => {
    const conflict = parseCommandArgs(read, ["demo.exe+0x8000", "--name", "demo.exe", "--pid", "1"]);
    expect(!conflict.ok && conflict.error.issues[0]?.reason).toBe("conflicting_arguments");
    const unknown = parseCommandArgs(read, ["1234", "x", "--bogus"]);
    expect(!unknown.ok && unknown.error.issues[0]?.reason).toBe("unknown_argument");
    const missing = parseCommandArgs(read, ["--size", "64"]);
    expect(!missing.ok && missing.error.issues[0]?.reason).toBe("missing_argument");
  });
  it("emu-oneshot takes --image (the generated emu_call command is `emulate`, CI-M15)", () => {
    const parsed = parseCommandArgs(commandFor("emu_call"), ["bea_step", "--image", "C:/lab/bea_fixture.dll"]);
    expect(parsed.ok && parsed.value).toMatchObject({
      input: { address: "bea_step" },
      target: { kind: "image", path: "C:/lab/bea_fixture.dll" },
    });
  });
  it("offline field waives the target; a list-typed last positional is variadic (CI-I11)", () => {
    const parsed = parseCommandArgs(commandFor("map_address"), ["0x140001000", "+0x2000", "--pe-path", "C:/x.exe"]);
    expect(parsed.ok && parsed.value).toMatchObject({
      input: { addresses: ["0x140001000", "+0x2000"], pe_path: "C:/x.exe" },
      target: null,
    });
  });
  it("fileFields leave the input and become file references (bea script hook.js --pid N)", () => {
    const parsed = parseCommandArgs(commandFor("run_script"), ["hook.js", "--pid", "1234"]);
    expect(parsed.ok && parsed.value).toMatchObject({ input: {}, fileInputs: [{ field: "source", path: "hook.js" }] });
  });
});

describe("router", () => {
  const table = buildCommandTable(FAKE_CONTRACTS);
  it("matches built-ins first, then the longest command prefix", () => {
    expect(matchCommand(table, ["doctor", "--json"])).toMatchObject({
      kind: "builtin",
      name: "doctor",
      rest: ["--json"],
    });
    expect(matchCommand(table, ["evidence", "show", "ev_1"])).toMatchObject({ kind: "generated", rest: ["ev_1"] });
    expect(matchCommand(table, ["evidence"])).toMatchObject({ kind: "group", group: "evidence" });
    expect(matchCommand(table, ["read", "1", "x"])).toMatchObject({ kind: "generated", rest: ["1", "x"] });
    expect(matchCommand(table, [])).toEqual({ kind: "help" });
    expect(matchCommand(table, ["frobnicate"])).toEqual({ kind: "unknown", word: "frobnicate" });
  });
  it("tools without a command are listed with their tier", () => {
    expect(table.withoutCommand.map((c) => c.name)).toContain("record_unknown");
    expect(table.generated.map((c) => c.command).sort()).toEqual(
      ["emulate", "evidence export", "evidence show", "hook", "map", "read", "script", "status"].sort(),
    );
  });
});

describe("built-in commands (in-process)", () => {
  let home: TempHome;
  beforeAll(async () => {
    home = await createTempHome("cli-router");
  });
  afterAll(async () => {
    await home.cleanup();
  });

  it("bea help lists tiers, scenario-only and MCP-only tools; exit 0", async () => {
    const r = await runCliInProcess(["help"], { home });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("Session commands (--pid N | --name EXE | --spawn PROG [-- args…]):");
    expect(r.stdout).toContain("read [pid] <address> [size]");
    expect(r.stdout).toContain("map <addresses…>");
    expect(r.stdout).toMatch(/Scenario steps only[^\n]*\n {2}.*spawn_process/u);
    expect(r.stdout).toMatch(/MCP only:\n {2}record_unknown/u);
    expect((await runCliInProcess([], { home })).stdout).toBe(r.stdout);
  });
  it("<command> --help prints the injection notice for session commands, before any parsing", async () => {
    const r = await runCliInProcess(["read", "--help", "--bogus"], { home });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain(
      "Usage: bea read [pid] <address> [size] (--pid N | --name EXE | --spawn PROG [-- args…]) [options]",
    );
    expect(r.stdout).toContain("11 stay loaded after detach");
    expect(r.stdout).toContain("--follow-pointers | --no-follow-pointers");
    const script = await runCliInProcess(["help", "script"], { home });
    expect(script.stdout).toContain('File arguments (a path; "-" reads stdin): source.');
    expect(script.stdout).toContain("Gated: the user must enable gate run_script");
  });
  it("bea help <built-in> prints that command's usage instead of failing (ONBOARD-12)", async () => {
    for (const [word, text] of [
      ["setup", "Usage: bea setup"],
      ["run", "Usage: bea run"],
      ["tools", "bea tools"],
      ["schema", "bea schema"],
      ["version", "bea version"],
      ["mcp", "bea mcp"],
    ] as const) {
      const r = await runCliInProcess(["help", word], { home });
      expect(r.code, word).toBe(0);
      expect(r.stdout, word).toContain(text);
    }
  });
  it("hook help documents the --capture shorthand instead of calling capture input-only (ONBOARD-12)", () => {
    const hook = buildCommandTable(TOOL_CONTRACTS).generated.find((c) => c.contract.name === "hook_function");
    expect(hook).toBeDefined();
    const text = hook === undefined ? "" : renderCommandHelp(hook);
    expect(text).toContain("--capture SPEC (repeatable)");
    const inputOnly = text.split("\n").find((line) => line.startsWith("Only through --input")) ?? "";
    expect(inputOnly).not.toContain("capture");
  });
  it("bea tools prints one row per contract; bea schema prints JSON Schema 2020-12", async () => {
    const tools = await runCliInProcess(["tools", "--json"], { home });
    expect(tools.code).toBe(0);
    const rows = tools.doc()["tools"] as { name: string; cli: string; read_only: boolean }[];
    expect(rows).toHaveLength(FAKE_CONTRACTS.length);
    expect(rows.find((row) => row.name === "read_memory")).toMatchObject({ cli: "bea read", read_only: true });
    const schema = await runCliInProcess(["schema", "read"], { home });
    expect(schema.code).toBe(0);
    const parsed = JSON.parse(schema.stdout) as { $schema: string; required: string[] };
    expect(parsed.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect(parsed.required).toEqual(["session_id", "address"]);
    const output = JSON.parse((await runCliInProcess(["schema", "read_memory", "--output"], { home })).stdout) as {
      required: string[];
    };
    expect(output.required).toContain("evidence_id");
    expect((await runCliInProcess(["schema", "nope"], { home })).code).toBe(1);
  });
  it("unknown commands and bare groups fail with an invalid_request document on stdout", async () => {
    const unknown = await runCliInProcess(["frobnicate", "--json"], { home });
    expect(unknown.code).toBe(1);
    expect(unknown.doc()).toMatchObject({ error: { code: "invalid_request" } });
    expect(unknown.stderr).toContain("bea help");
    const group = await runCliInProcess(["evidence"], { home });
    expect(group.code).toBe(1);
    expect(group.stderr).toContain("bea evidence has these subcommands");
    const version = await runCliInProcess(["version"], { home });
    expect(version.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/u);
  });
  it("argv errors honour --json and use the contract's operation name", async () => {
    const r = await runCliInProcess(["read", "x", "--pid", "1", "--name", "a.exe", "--json"], { home });
    expect(r.code).toBe(1);
    expect(r.doc()).toMatchObject({ error: { code: "invalid_request" } });
    const toon = await runCliInProcess(["read", "x"], { home });
    expect(toon.code).toBe(1);
    expect(toon.doc()).toMatchObject({ error: { code: "invalid_request" } });
  });
});
