import { EventEmitter } from "node:events";

import { decode } from "@toon-format/toon";

import type { BeaCore } from "../../../src/application/BeaApplication.js";
import { distLayoutAt, resolveDistLayout, type DistLayout } from "../../../src/application/distLayout.js";
import type { BeaServices } from "../../../src/application/services/index.js";
import type { CliDeps } from "../../../src/cli/io.js";
import { runCli } from "../../../src/cli/runCli.js";
import type { BeaConfig } from "../../../src/domain/config.js";
import type { HostPlatform } from "../../../src/domain/paths.js";
import type { EmulatorProvisioner } from "../../../src/ports/provisioner.js";
import { fakeServices } from "../fakes/fakeServices.js";
import type { TempHome } from "../workspace/tempHome.js";
import { createFakeBackend, type FakeBackend } from "./fakeCatalog.js";

/**
 * In-process `bea <argv>` (WP15): the real router and runners over captured stdout/stderr, a temp home as the whole
 * environment (never the test process's), the fake catalog by default, and an EventEmitter as the signal source.
 */
export interface CliHarnessOptions {
  readonly home: TempHome;
  /** Added to the temp home's environment (gates, BEA_* settings, CLAUDE_CONFIG_DIR …). */
  readonly env?: Readonly<Record<string, string>>;
  readonly backend?: FakeBackend;
  readonly services?: (core: BeaCore) => Promise<BeaServices>;
  readonly provisioner?: (config: BeaConfig) => EmulatorProvisioner;
  readonly stdin?: string | Buffer;
  readonly tty?: { readonly stdin?: boolean; readonly stdout?: boolean; readonly stderr?: boolean };
  /** Answers to interactive prompts, in order. */
  readonly answers?: readonly string[];
  readonly signals?: EventEmitter;
  readonly layout?: DistLayout;
  readonly cwd?: string;
  readonly execPath?: string;
  readonly platform?: HostPlatform;
}

export interface CliRunResult {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly prompts: readonly string[];
  /** stdout parsed as JSON (when --json was given) or TOON. */
  readonly doc: () => Record<string, unknown>;
}

/** The repository's (or BEA_DIST_DIR's) layout for code running from sources. */
export const sourceLayout = (): DistLayout => resolveDistLayout(process.env);
export const layoutAt = distLayoutAt;

export const cliDeps = (
  options: CliHarnessOptions,
  out: { stdout: string; stderr: string; prompts: string[] },
): CliDeps => {
  const backend = options.backend ?? createFakeBackend();
  const answers = [...(options.answers ?? [])];
  const stdin = options.stdin === undefined ? Buffer.alloc(0) : Buffer.from(options.stdin);
  return {
    io: {
      stdout: (text) => {
        out.stdout += text;
      },
      stdoutIsTty: options.tty?.stdout ?? false,
    },
    stderr: (text) => {
      out.stderr += text;
    },
    env: { ...options.home.env, ...options.env },
    platform: options.platform ?? (process.platform as HostPlatform),
    arch: process.arch,
    nodeVersion: process.versions.node,
    accountHome: options.home.home,
    cwd: options.cwd ?? options.home.work,
    execPath: options.execPath ?? process.execPath,
    isTty: { stdin: options.tty?.stdin ?? false, stderr: options.tty?.stderr ?? false },
    readStdin: async (maxBytes) => (stdin.length > maxBytes ? null : stdin),
    prompt: async (question) => {
      out.prompts.push(question);
      return answers.shift() ?? "";
    },
    signals: options.signals ?? new EventEmitter(),
    layout: options.layout ?? sourceLayout(),
    contracts: backend.contracts,
    createHandlers: backend.createHandlers,
    services: options.services ?? fakeServices(),
    provisioner:
      options.provisioner ??
      (() => {
        throw new Error("no provisioner in this test");
      }),
  };
};

export const runCliInProcess = async (argv: readonly string[], options: CliHarnessOptions): Promise<CliRunResult> => {
  const out = { stdout: "", stderr: "", prompts: [] as string[] };
  const code = await runCli(cliDeps(options, out), argv);
  return {
    code,
    stdout: out.stdout,
    stderr: out.stderr,
    prompts: out.prompts,
    doc: () => {
      const text = out.stdout.trim();
      return (text.startsWith("{") ? JSON.parse(text) : decode(text)) as Record<string, unknown>;
    },
  };
};
