import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { dirname, join } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { connectBea, type BeaConnection } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureId,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger, pidStatus } from "../../support/process/ownedPidLedger.js";

/**
 * BEA-FEEDBACK items 1 and 5 over the BUILT server (BEA_DIST_DIR snapshot). attach_process refuses a process that
 * enforces Code Integrity Guard or Arbitrary Code Guard before injecting anything: frida-agent.dll never appears in its
 * loader list (tasklist /M, the OS's view; BEA's cloaking does not touch it) and the process stays alive (Frida
 * 17.23.2's injection crashes an ACG process). Without the mitigations the same fixture attaches (the agent then
 * shows up in tasklist: the probe works), the attach evidence carries the target's mitigation policies, and
 * list_threads reports the names the fixture set with SetThreadDescription. Targets are mitigated.exe processes this
 * file starts (attach targets: BEA must never kill them; the ledger checks they survive).
 */
const skip = gccSkip() || fridaSkip() || jobhostSkip();
/** Registered in scripts/lib/fixtures.mjs; the FixtureId union in fixtures.d.mts does not list it yet. */
const MITIGATED: FixtureId = "mitigated";
type Obj = Readonly<Record<string, unknown>>;

let ledger: OwnedPidLedger;
let pidcheck: string | null = null;
let exe = "";
let bea: BeaConnection | undefined;
const children: ChildProcess[] = [];
const conn = (): BeaConnection => {
  if (bea === undefined) throw new Error("server not started");
  return bea;
};

/** mitigated.exe with `flags`, started by the test; resolves once its mitigations are on (the READY line). */
const startTarget = async (flags: readonly string[]): Promise<{ readonly pid: number; readonly ready: string }> => {
  const child = spawn(exe, [...flags, "--lifetime-ms", "300000"], {
    cwd: dirname(exe),
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  });
  children.push(child);
  let out = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    out += chunk.toString();
  });
  await vi.waitFor(() => expect(out).toMatch(/^(READY|ERROR) [^\r\n]*\r?\n/mu), { interval: 20, timeout: 10_000 });
  const ready = /^READY .*$/mu.exec(out)?.[0];
  if (ready === undefined) throw new Error(`mitigated.exe ${flags.join(" ")}: ${out}`);
  const pid = child.pid ?? 0;
  ledger.recordAttachTarget(pid, null, `test-spawned mitigated.exe ${flags.join(" ")}`);
  return { pid, ready };
};

/** The system's tasklist.exe by absolute path (no PATH search). */
const TASKLIST = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32", "tasklist.exe");

/** frida-agent.dll in the target's loaded-module list, as the OS reports it. */
const agentLoaded = (pid: number): boolean => {
  const run = spawnSync(TASKLIST, ["/M", "frida-agent.dll", "/FI", `PID eq ${String(pid)}`, "/FO", "CSV", "/NH"], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 30_000,
  });
  if (run.status !== 0) throw new Error(`tasklist failed: ${run.stderr || String(run.error)}`);
  return run.stdout.includes(`"${String(pid)}"`);
};

beforeAll(async () => {
  if (skip !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, MITIGATED);
  if (artifact === null) throw new Error("fixtures unavailable");
  exe = artifact.path;
  pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
  ledger = new OwnedPidLedger(pidcheck);
  bea = await connectBea({ ledger });
}, 60_000);

afterAll(async () => {
  if (skip !== false) return;
  try {
    await bea?.close();
    await ledger.assertClean();
  } finally {
    await ledger.killAttachTargets();
    for (const child of children) if (child.exitCode === null) child.kill();
  }
}, 60_000);

describe.skipIf(skip !== false)(`attach and process mitigations (BEA-FEEDBACK 1, 5)${skipNote(skip)}`, () => {
  it("Code Integrity Guard: refused before injection with code-integrity-guard; the agent never loads", async () => {
    const { pid, ready } = await startTarget(["--cig"]);
    expect(ready).toContain("cig=1");
    const error = parseToolError(await conn().call("attach_process", { pid }));
    expect(error).toMatchObject({
      code: "access_denied",
      retryable: false,
      details: {
        reason: "code-integrity-guard",
        diagnostics: {
          mitigation: "ProcessSignaturePolicy.MicrosoftSignedOnly",
          blocking: ["ProcessSignaturePolicy.MicrosoftSignedOnly"],
        },
      },
    });
    expect(error.message).toContain("Code Integrity Guard");
    expect(error.remediation.action).toContain("--disable-gpu-sandbox");
    expect(agentLoaded(pid)).toBe(false);
    expect(pidStatus(pidcheck, pid).alive).toBe(true);
  });

  it("Arbitrary Code Guard: refused before injection with arbitrary-code-guard; the process survives", async () => {
    const { pid, ready } = await startTarget(["--acg"]);
    expect(ready).toContain("acg=1");
    const error = parseToolError(await conn().call("attach_process", { pid }));
    expect(error).toMatchObject({
      code: "access_denied",
      details: {
        reason: "arbitrary-code-guard",
        diagnostics: { mitigation: "ProcessDynamicCodePolicy.ProhibitDynamicCode" },
      },
    });
    expect(agentLoaded(pid)).toBe(false);
    expect(pidStatus(pidcheck, pid).alive).toBe(true);
  });

  it("without mitigations the fixture attaches; the evidence carries its policies and list_threads its thread names", async () => {
    const { pid, ready } = await startTarget([]);
    const workerTid = Number(/worker_tid=(\d+)/u.exec(ready)?.[1]);
    const attached = expectToolSuccess(await conn().call("attach_process", { pid }));
    const id = attached["session_id"] as string;
    try {
      // the probe of the refusal tests sees an injected agent
      expect(agentLoaded(pid)).toBe(true);

      const identity = attached["identity"] as { readonly instance_id: string };
      const summary = expectToolSuccess(
        await conn().call("get_evidence", {
          filters: { instance_id: identity.instance_id, predicate_type: "bea.process.instance" },
        }),
      )["summary"] as { readonly rows: readonly { readonly evidence_id: string }[] };
      const first = summary.rows[0];
      if (first === undefined) throw new Error("no bea.process.instance record");
      const complete = expectToolSuccess(
        await conn().call("get_evidence", { detail: "complete", id: first.evidence_id }),
      );
      const record = (complete["record"] as { readonly value: { readonly result: Obj } }).value;
      expect((record.result["containment"] as Obj)["target_mitigations"]).toMatchObject({
        signature: { microsoft_signed_only: false },
        dynamic_code: { prohibit_dynamic_code: false },
        user_shadow_stack: { strict_mode: false },
        unreadable: [],
      });

      const threads = expectToolSuccess(await conn().call("list_threads", { session_id: id }));
      const rows = threads["rows"] as readonly {
        readonly tid: number;
        readonly name: string | null;
        readonly main: boolean;
      }[];
      expect(rows).toContainEqual(expect.objectContaining({ tid: workerTid, name: "bea-worker-é" }));
      expect(rows.find((row) => row.name === "bea-main")).toMatchObject({ main: true });
      for (const row of rows) expect(row.name === null || row.name.length > 0).toBe(true);
    } finally {
      expectToolSuccess(await conn().call("close_session", { session_id: id }));
    }
    expect(pidStatus(pidcheck, pid).alive).toBe(true);
  });
});
