import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { minimalEnv, harnessLayout } from "../../../support/mcp/stdioSubprocess.js";
import type { OwnedPidLedger } from "../../../support/process/ownedPidLedger.js";
import type { TempHome } from "../../../support/workspace/tempHome.js";

/**
 * The investigations lane (DESIGN §10.2, WP18): each S6 §1 investigation is a `bea-scenario/1` file run by the BUILT
 * CLI (`node <dist>/../scripts/bea.mjs run <file> --json`, BEA_DIST_DIR snapshot) in a temp home. A step is one of
 *   - analysis: a call of the S6 §1 table (counted against S6 §1.8, CI-M26);
 *   - sync: a scenario sync step such as `wait {until:"output"}` (not counted, CI-M26);
 *   - setup: session set-up the S6 table does not list (resuming a spawned target before a 3-call investigation);
 *   - oracle: a read the TEST needs as ground truth (output lines, containment facts; not counted — an agent would
 *     not make it, it only lets the assertions stay independent of the result under test).
 * The scenario target and the teardown's close_session count when the S6 table lists the session's creation / close.
 */
export type StepRole = "analysis" | "sync" | "setup" | "oracle";

export interface ScenarioStep {
  readonly tool: string;
  readonly input?: Readonly<Record<string, unknown>>;
  readonly save_as?: string;
  readonly expect?: "ok" | "error" | "any";
  readonly role: StepRole;
}

export interface InvestigationScenario {
  readonly target?: Readonly<Record<string, unknown>>;
  readonly steps: readonly ScenarioStep[];
  /** the S6 §1 table counts the target's creation (spawn/attach) and the teardown close */
  readonly countsSession: boolean;
  readonly limits?: { readonly total_ms: number };
}

export interface StepRecord {
  readonly index: number;
  readonly tool: string;
  readonly ok: boolean;
  readonly passed: boolean;
  readonly ms: number;
  readonly save_as?: string;
  readonly result?: Readonly<Record<string, unknown>>;
  readonly error?: Readonly<Record<string, unknown>>;
}

export interface ScenarioDocument {
  readonly schema: string;
  readonly ok: boolean;
  readonly session_id: string | null;
  readonly target: (StepRecord & { readonly result?: Readonly<Record<string, unknown>> }) | null;
  readonly steps: readonly StepRecord[];
  readonly sessions: readonly { readonly session_id: string; readonly tool: string }[];
  readonly teardown: { readonly closed: readonly StepRecord[]; readonly cleanup_ok: boolean };
}

export interface ScenarioRun {
  readonly code: number | null;
  readonly doc: ScenarioDocument;
  readonly stderr: string;
  readonly file: string;
  /** analysis calls: counted steps, plus the target and the teardown closes when the table counts the session */
  readonly analysisCalls: number;
  /** the step results by save_as */
  readonly saved: (name: string) => Readonly<Record<string, unknown>>;
}

const RUN_TIMEOUT_MS = 240_000;

/** The scenario file as `bea run` reads it (roles are test-side only: the strict schema has no such field). */
export const scenarioFile = (scenario: InvestigationScenario): Readonly<Record<string, unknown>> => ({
  schema: "bea-scenario/1",
  ...(scenario.target === undefined ? {} : { target: scenario.target }),
  steps: scenario.steps.map((step) => ({
    tool: step.tool,
    input: step.input ?? {},
    ...(step.save_as === undefined ? {} : { save_as: step.save_as }),
    ...(step.expect === undefined ? {} : { expect: step.expect }),
  })),
  teardown: "close",
  on_error: "stop",
  ...(scenario.limits === undefined ? {} : { limits: scenario.limits }),
});

/**
 * Runs one scenario through the built CLI. `--keep-run` keeps the run's exports (drcov files, dumps) readable after
 * the CLI exits; the temp home is the test's to remove. Owned identities (target and session-creating steps) and the
 * emulation bridges are recorded in the ledger.
 */
export const runScenario = async (
  name: string,
  scenario: InvestigationScenario,
  options: {
    readonly home: TempHome;
    readonly ledger: OwnedPidLedger;
    readonly env?: Readonly<Record<string, string>>;
    readonly keepRun?: boolean;
  },
): Promise<ScenarioRun> => {
  const layout = harnessLayout();
  if (!existsSync(layout.dispatcher))
    throw new Error(`No built CLI at ${layout.dispatcher}: run npm run build and set BEA_DIST_DIR (docs/testing.md)`);
  const file = join(options.home.work, `${name}.scenario.json`);
  await writeFile(file, `${JSON.stringify(scenarioFile(scenario), null, 2)}\n`);
  const args = [layout.dispatcher, "run", file, "--json", ...(options.keepRun === true ? ["--keep-run"] : [])];
  const child = spawn(process.execPath, args, {
    cwd: options.home.work,
    env: minimalEnv(options.home, options.env),
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
  child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
  const code = await new Promise<number | null>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`bea run ${name} did not finish within ${String(RUN_TIMEOUT_MS)} ms\n${stderr.slice(-4000)}`));
    }, RUN_TIMEOUT_MS);
    child.once("error", reject);
    child.once("exit", (exit) => {
      clearTimeout(timer);
      resolve(exit);
    });
  });
  let doc: ScenarioDocument;
  try {
    doc = JSON.parse(stdout) as ScenarioDocument;
  } catch {
    throw new Error(`bea run ${name}: stdout is not one JSON document (exit ${String(code)})\n${stdout}\n${stderr}`);
  }
  recordOwned(doc, options.ledger, name);
  const counted = scenario.steps.filter((step) => step.role === "analysis").length;
  const sessionCalls = scenario.countsSession ? (doc.target === null ? 0 : 1) + doc.teardown.closed.length : 0;
  const byName = new Map<string, Readonly<Record<string, unknown>>>();
  for (const step of doc.steps)
    if (step.save_as !== undefined && step.result !== undefined) byName.set(step.save_as, step.result);
  return {
    code,
    doc,
    stderr,
    file,
    analysisCalls: counted + sessionCalls,
    saved: (key) => {
      const value = byName.get(key);
      if (value === undefined) throw new Error(`scenario ${name}: no saved result "${key}"`);
      return value;
    },
  };
};

/** spawn identities (target or steps) are owned; emulation bridges are owned helpers. */
const recordOwned = (doc: ScenarioDocument, ledger: OwnedPidLedger, label: string): void => {
  const results = [doc.target, ...doc.steps].filter((r): r is StepRecord => r !== null && r.ok);
  for (const step of results) {
    const result = step.result ?? {};
    const identity = result["identity"];
    if ((step.tool === "spawn_process" || step.tool === "attach_process") && typeof identity === "object")
      ledger.recordIdentity(identity as Readonly<Record<string, unknown>>, `${label} ${step.tool}`);
    const bridge = result["bridge"] as { readonly pid?: number; readonly child_pid?: number } | undefined;
    if (step.tool === "emu_open" && bridge !== undefined)
      for (const pid of new Set([bridge.pid, bridge.child_pid]))
        if (typeof pid === "number") ledger.recordOwned(pid, null, `${label} emulation bridge`);
  }
};

/** Every step passed, the teardown closed every session and cleaned up; the message carries the failing step. */
export const expectScenarioPassed = (run: ScenarioRun): void => {
  const failed = run.doc.steps.find((step) => !step.passed);
  const before =
    failed === undefined
      ? []
      : run.doc.steps
          .slice(Math.max(0, failed.index - 2), failed.index)
          .map(
            (step) =>
              `step ${String(step.index)} ${step.tool} -> ${JSON.stringify(step.result ?? step.error).slice(0, 700)}`,
          );
  const why =
    failed === undefined
      ? `${run.stderr.slice(-2000)}`
      : [
          ...before,
          `step ${String(failed.index)} ${failed.tool}: ${JSON.stringify(failed.error ?? failed.result).slice(0, 2000)}`,
        ].join("\n");
  expect(run.doc.schema).toBe("bea-scenario-result/1");
  expect(run.doc.ok, why).toBe(true);
  expect(run.code, why).toBe(0);
  expect(run.doc.teardown.cleanup_ok).toBe(true);
  expect(run.doc.teardown.closed.every((close) => close.ok)).toBe(true);
};

/** "0x…" (float bits) of a JS number as f32. */
export const f32Bits = (v: number): string => {
  const view = new DataView(new ArrayBuffer(4));
  view.setFloat32(0, v, true);
  return `0x${view.getUint32(0, true).toString(16)}`;
};
