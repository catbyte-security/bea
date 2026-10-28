import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { type BeaConnection, connectBea } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";
import { REG_EXE, expectBehaviorTable } from "./behaviorTable.js";

/**
 * S6 §10.8 trace_api row through the BUILT server (run with BEA_DIST_DIR from `node scripts/snapshot-dist.mjs <id>`).
 * Wave rule (DESIGN §8.4): only earlier-wave tools — spawn_process/resume_process/close_session (WP4), wait and
 * query_events (WP7) — plus trace_api itself. Investigation 4 as a tool sequence.
 */
const skip = fridaSkip() || gccSkip() || jobhostSkip();
const ALL = ["file", "registry", "network", "process", "module_load", "memory_protection"];

/**
 * The target's stdout as one string: the output recording's rows are columnar and chunked as written (the fixture's
 * unbuffered stdout arrives about one character per row), so every page is read and the `text` cells are joined.
 */
const readOutput = async (bea: BeaConnection, recordingId: string | undefined): Promise<string> => {
  let text = "";
  let offset: number | null = 0;
  while (offset !== null) {
    const page = expectToolSuccess(
      await bea.call("query_events", { recording_id: recordingId, view: "rows", offset, limit: 500 }),
    );
    const col = (page.columns as string[]).indexOf("text");
    expect(col).toBeGreaterThanOrEqual(0);
    for (const row of page.rows as unknown[][]) text += String(row[col] ?? "");
    offset = (page.page as { next_offset: number | null }).next_offset;
  }
  return text;
};

const homes: TempHome[] = [];
const dirs: string[] = [];

/** Spawned behavior.exe, all profiles installed before resume (Investigation 4). */
const spawnedAllProfiles = async (): Promise<void> => {
  const manifest = await loadFixtures();
  const exe = fixtureArtifact(manifest, "behavior");
  const mathlib = fixtureArtifact(manifest, "mathlib");
  const pidcheck = fixtureArtifact(manifest, "pidcheck");
  if (exe === null || mathlib === null) throw new Error("fixtures unavailable");
  const home = await createTempHome("wp8-trace-api");
  homes.push(home);
  const ledger = new OwnedPidLedger(pidcheck?.path ?? null);
  const outDir = await mkdtemp(join(tmpdir(), "bea-wp8-mcp-"));
  dirs.push(outDir);
  const regKey = `wp8-${randomBytes(4).toString("hex")}`;
  const bea = await connectBea({ home, ledger });
  try {
    const spawned = expectToolSuccess(
      await bea.call("spawn_process", {
        program: exe.path,
        args: ["--out-dir", outDir, "--reg-key", regKey, "--hold-ms", "1500"],
      }),
    );
    const sessionId = spawned.session_id as string;
    const traced = expectToolSuccess(
      await bea.call("trace_api", { session_id: sessionId, profiles: ALL, duration_ms: 60_000 }),
    );
    expect(traced.hooks_installed as number).toBeGreaterThan(40);
    expect(traced.limitations).toEqual(expect.arrayContaining([expect.stringContaining("Direct system calls")]));
    const recordingId = (traced.instrument as { recording_id: string }).recording_id;
    expectToolSuccess(await bea.call("resume_process", { session_id: sessionId }));
    const waited = expectToolSuccess(
      await bea.call("wait", {
        session_id: sessionId,
        until: "output",
        output_contains: "DONE",
        timeout_ms: 30_000,
      }),
    );
    expect(waited.satisfied).toBe(true);
    expectToolSuccess(await bea.call("stop_instrumentation", { session_id: sessionId, ids: [recordingId] }));
    const queried = expectToolSuccess(await bea.call("query_events", { recording_id: recordingId, view: "summary" }));
    // review fix UX-2: view:"summary" carries the digest once, at the top level (recording keeps state and counts)
    const summary = (queried as { summary: Readonly<Record<string, unknown>> }).summary;
    expect(queried.recording).not.toHaveProperty("summary");
    const outputRec = (spawned.recordings as { kind: string; recording_id: string }[]).find((r) => r.kind === "output");
    const stdout = await readOutput(bea, outputRec?.recording_id);
    const netPort = Number(/NET port=(\d+)/u.exec(stdout)?.[1]);
    // every step passed under tracing; "STEP process ok" means the parent saw the child exit with code 7
    for (const step of ["file", "registry", "network", "process", "module", "memory"])
      expect(stdout).toContain(`STEP ${step} ok`);
    expect(stdout).toContain("DONE ok=1");
    expect(queried.recording).toMatchObject({ kind: "api", state: "finished", end_reason: "stopped" });
    expect((queried.recording as { events: number }).events).toBeGreaterThan(0);
    // child process + exit (containment facts): the job saw exactly one child and at most the root is still alive.
    // The child pid comes from the job, because the child's own "CHILDMODE pid=" line shares the pipe with the
    // parent's "CHILD pid=" line and both write unbuffered, so the two can interleave character by character
    // (seen once in 15 runs). When the parent's line is intact it must name the same pid.
    const status = expectToolSuccess(await bea.call("session_status", { session_id: sessionId }));
    const containment = status.containment as { active_processes: number | null; children_seen: number[] };
    expect(containment.children_seen).toHaveLength(1);
    const childPid = containment.children_seen[0] ?? 0;
    ledger.recordOwned(childPid, null, "behavior.exe --child");
    const printed = /CHILD pid=(\d+)/u.exec(stdout)?.[1];
    if (printed !== undefined) expect(Number(printed)).toBe(childPid);
    expect(containment.active_processes).toBeLessThanOrEqual(1);
    // BEA's own paths are absent too: the server's temp home (BEA_HOME, its TEMP holds Frida's agent DLLs), with
    // or without the drive letter (an unmapped \Device\HarddiskVolumeN prefix keeps the rest of the path)
    const summaryText = JSON.stringify(summary).toLowerCase();
    const homeTail = JSON.stringify(home.root.replace(/^[a-z]:/iu, "").toLowerCase()).slice(1, -1);
    expect(summaryText).not.toContain(homeTail);
    expectBehaviorTable(summary, {
      outDir,
      regKey,
      netPort,
      childPid,
      exePath: exe.path,
      mathlibPath: mathlib.path,
    });
    expectToolSuccess(await bea.call("close_session", { session_id: sessionId }));
  } finally {
    await bea.close();
  }
  const reg = spawnSync(REG_EXE, ["query", `HKCU\\Software\\BEA-Fixture\\${regKey}`], { windowsHide: true });
  expect(reg.status).toBe(1);
  await ledger.assertClean();
};

/** behavior.exe started by the test, attached during its --delay-ms window, file profile only. */
const attachedLate = async (): Promise<void> => {
  const manifest = await loadFixtures();
  const exe = fixtureArtifact(manifest, "behavior");
  const pidcheck = fixtureArtifact(manifest, "pidcheck");
  if (exe === null) throw new Error("fixtures unavailable");
  const home = await createTempHome("wp8-trace-api-attach");
  homes.push(home);
  const outDir = await mkdtemp(join(tmpdir(), "bea-wp8-mcp-"));
  dirs.push(outDir);
  const child = (await import("node:child_process")).spawn(
    exe.path,
    ["--out-dir", outDir, "--delay-ms", "2000", "--steps", "file", "--hold-ms", "3000"],
    { stdio: ["ignore", "pipe", "ignore"], windowsHide: true },
  );
  let stdout = "";
  child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
  const ledger = new OwnedPidLedger(pidcheck?.path ?? null);
  if (child.pid !== undefined) ledger.recordAttachTarget(child.pid, null, "behavior.exe (attach target)");
  const bea = await connectBea({ home, ledger });
  try {
    while (!stdout.includes("READY")) await new Promise((r) => setTimeout(r, 25));
    const attached = expectToolSuccess(await bea.call("attach_process", { pid: child.pid }));
    const sessionId = attached.session_id as string;
    const traced = expectToolSuccess(
      await bea.call("trace_api", { session_id: sessionId, profiles: ["file"], duration_ms: 20_000 }),
    );
    const recordingId = (traced.instrument as { recording_id: string }).recording_id;
    while (!stdout.includes("DONE")) await new Promise((r) => setTimeout(r, 25));
    expectToolSuccess(await bea.call("stop_instrumentation", { session_id: sessionId, ids: [recordingId] }));
    const queried = expectToolSuccess(await bea.call("query_events", { recording_id: recordingId, view: "summary" }));
    const rows = (
      queried as { summary: { file: { rows: { path: string; ops: string[] }[] } } }
    ).summary.file.rows.filter((r) => r.path.toLowerCase().startsWith(outDir.toLowerCase()));
    expect(rows.map((r) => r.path.slice(outDir.length))).toEqual(
      expect.arrayContaining(["\\bea_behavior_a.txt", "\\bea_behavior_b.txt", "\\does_not_exist.txt", "\\sub", ""]),
    );
    expect(stdout).toContain("DONE ok=1");
    expectToolSuccess(await bea.call("close_session", { session_id: sessionId }));
    // closing an attached session detaches and never kills: the target is still in its --hold-ms window
    await ledger.assertClean();
  } finally {
    await bea.close();
    if (child.exitCode === null) child.kill();
  }
};

/** trace_api on a paused target: the duration clock starts at resume_process (clock resume). */
const resumeClock = async (): Promise<void> => {
  const manifest = await loadFixtures();
  const exe = fixtureArtifact(manifest, "behavior");
  const pidcheck = fixtureArtifact(manifest, "pidcheck");
  if (exe === null) throw new Error("fixtures unavailable");
  const home = await createTempHome("wp8-trace-api-clock");
  homes.push(home);
  const ledger = new OwnedPidLedger(pidcheck?.path ?? null);
  const outDir = await mkdtemp(join(tmpdir(), "bea-wp8-mcp-"));
  dirs.push(outDir);
  const bea = await connectBea({ home, ledger });
  try {
    const spawned = expectToolSuccess(
      await bea.call("spawn_process", {
        program: exe.path,
        args: ["--out-dir", outDir, "--steps", "file", "--hold-ms", "8000"],
      }),
    );
    const sessionId = spawned.session_id as string;
    const traced = expectToolSuccess(
      await bea.call("trace_api", { session_id: sessionId, profiles: ["file"], duration_ms: 1500 }),
    );
    const recordingId = (traced.instrument as { recording_id: string }).recording_id;
    // a paused target: 2.5 s pass (wait's timeout is a normal poll result) and the 1.5 s duration must not run
    const idle = expectToolSuccess(
      await bea.call("wait", { session_id: sessionId, ids: [recordingId], timeout_ms: 2500 }),
    );
    expect(idle).toMatchObject({ satisfied: false, reason: "timeout" });
    expect(idle.recordings).toEqual([expect.objectContaining({ recording_id: recordingId, state: "active" })]);
    expectToolSuccess(await bea.call("resume_process", { session_id: sessionId }));
    const done = expectToolSuccess(
      await bea.call("wait", { session_id: sessionId, ids: [recordingId], timeout_ms: 20_000 }),
    );
    expect(done.satisfied).toBe(true);
    expect(done.recordings).toEqual([
      expect.objectContaining({ recording_id: recordingId, state: "finished", end_reason: "duration" }),
    ]);
    // the file step ran right after resume, inside the window, so its rows were recorded
    const queried = expectToolSuccess(await bea.call("query_events", { recording_id: recordingId, view: "summary" }));
    const rows = (queried as { summary: { file: { rows: { path: string }[] } } }).summary.file.rows.map((r) =>
      r.path.toLowerCase(),
    );
    expect(rows).toContain(`${outDir}\\bea_behavior_a.txt`.toLowerCase());
    expectToolSuccess(await bea.call("close_session", { session_id: sessionId }));
  } finally {
    await bea.close();
  }
  await ledger.assertClean();
};

describe.skipIf(skip !== false)(`trace_api acceptance (MCP, behavior.exe)${skipNote(skip)}`, () => {
  afterAll(async () => {
    for (const h of homes) await h.cleanup();
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  it(
    "spawned, all profiles: the summary is the behavior table; BEA activity absent; registry key gone",
    { timeout: 120_000 },
    spawnedAllProfiles,
  );
  it("attached late (--delay-ms 2000): the same out-dir file rows", { timeout: 120_000 }, attachedLate);
  it(
    "installed before resume: duration_ms runs from resume_process (clock resume), then ends with reason duration",
    { timeout: 120_000 },
    resumeClock,
  );
});
