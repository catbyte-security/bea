import { spawn, type ChildProcess } from "node:child_process";
import { dirname } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { connectBea } from "../../support/acceptance/harness.js";
import {
  fixtureArtifact,
  fridaSkip,
  gccSkip,
  jobhostSkip,
  loadFixtures,
  skipNote,
  type FixtureArtifact,
} from "../../support/acceptance/fixtures.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { OwnedPidLedger, pidStatus } from "../../support/process/ownedPidLedger.js";

/**
 * S6 §10.8 rows of the seven session tools over the BUILT server (stdio; every structuredContent validated against the
 * advertised output schema by the harness) and the WP4 lifecycle rows that need a real server process: stdin EOF with
 * 3 piped owned + 1 attached exits 0 in < 2 s with the owned targets dead and the attached one alive, and a hard-killed
 * server leaves no owned target (kill-on-close job). Run with a snapshot: BEA_DIST_DIR (docs/testing.md).
 */
const skipReason = gccSkip() || fridaSkip() || jobhostSkip();

let ledger: OwnedPidLedger;
let game: FixtureArtifact;
let pidcheck: string | null = null;
const children: ChildProcess[] = [];
const GAME_ARGS = ["--frames", "0", "--no-threads"];

/** A game_sim the TEST starts for attach_process; recorded as an attach target (must stay alive). */
const startForeignGame = async (): Promise<ChildProcess> => {
  const child = spawn(game.path, GAME_ARGS, {
    cwd: dirname(game.path),
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  });
  children.push(child);
  let out = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    out += chunk.toString();
  });
  await vi.waitFor(() => expect(out).toContain("READY"), { interval: 20, timeout: 10_000 });
  ledger.recordAttachTarget(child.pid ?? 0, null, "test-spawned game_sim (stdio)");
  return child;
};

beforeAll(async () => {
  if (skipReason !== false) return;
  const manifest = await loadFixtures();
  const artifact = fixtureArtifact(manifest, "game_sim");
  if (artifact === null) throw new Error("fixtures unavailable");
  game = artifact;
  pidcheck = fixtureArtifact(manifest, "pidcheck")?.path ?? null;
  ledger = new OwnedPidLedger(pidcheck);
});

afterAll(async () => {
  if (skipReason !== false) return;
  try {
    await ledger.assertClean();
  } finally {
    await ledger.killAttachTargets();
    for (const child of children) if (child.exitCode === null) child.kill();
  }
}, 30_000);

describe.skipIf(skipReason !== false)(`session tools over the built server (S6 §10.8)${skipNote(skipReason)}`, () => {
  it("bea_status backends, list_processes, spawn → session_status → resume → close, and the error rows", async () => {
    const bea = await connectBea({ ledger });
    try {
      const backends = bea.status["backends"] as { id: string; state: string }[];
      expect(backends.find((b) => b.id === "agent")?.state).toBe("available");
      expect(backends.map((b) => b.id)).toContain("frida");

      const relative = parseToolError(await bea.call("spawn_process", { program: "game_sim.exe" }));
      expect(relative.code).toBe("invalid_request");
      const unknown = parseToolError(
        await bea.call("session_status", { session_id: "3f2b8c1e-4d5a-4e6f-9a0b-1c2d3e4f5a6b" }),
      );
      expect(unknown.code).toBe("session_not_found");

      const spawned = expectToolSuccess(await bea.call("spawn_process", { program: game.path, args: GAME_ARGS }));
      const id = spawned["session_id"] as string;
      expect(spawned).toMatchObject({ state: "paused", containment: { kind: "win32-job" } });
      const status = expectToolSuccess(await bea.call("bea_status", {}));
      expect(status["sessions"]).toContainEqual(
        expect.objectContaining({ session_id: id, kind: "live", state: "paused", ownership: "owned" }),
      );
      const listed = expectToolSuccess(await bea.call("list_processes", { filter: "game_sim" }));
      expect(listed["rows"]).toContainEqual(
        expect.objectContaining({ pid: (spawned["identity"] as { pid: number }).pid, bea_session: id }),
      );
      expect(expectToolSuccess(await bea.call("session_status", { session_id: id }))).toMatchObject({
        state: "paused",
        kind: "live",
      });
      expect(expectToolSuccess(await bea.call("resume_process", { session_id: id, wait_ms: 300 }))).toMatchObject({
        state: "running",
        exit: null,
      });
      const again = parseToolError(await bea.call("resume_process", { session_id: id }));
      expect(again.code).toBe("invalid_state");
      expect(expectToolSuccess(await bea.call("close_session", { session_id: id }))).toMatchObject({
        already_closed: false,
        target_state: "killed",
      });
      expect(expectToolSuccess(await bea.call("close_session", { session_id: id }))).toMatchObject({
        already_closed: true,
      });
      expect(expectToolSuccess(await bea.call("session_status", { session_id: id }))).toMatchObject({
        state: "closed",
      });
    } finally {
      await bea.close();
    }
  }, 90_000);

  it("bea_status rows (A.4 #3): jobhost probe ok, frida loads on first use, gates closed unless the env opens one", async () => {
    type Backend = { id: string; state: string; version: string | null; detail: string | null };
    type Gate = { enabled: boolean; source: string; env: string };
    const bea = await connectBea({ ledger });
    try {
      const fresh = bea.status["backends"] as Backend[];
      expect(fresh.find((b) => b.id === "jobhost")).toMatchObject({ state: "available", detail: "probe ok" });
      // bea_status never loads Frida: the binding loads on the first session
      expect(fresh.find((b) => b.id === "frida")).toMatchObject({ state: "not-loaded" });
      const gates = bea.status["gates"] as Record<string, Gate>;
      expect(Object.keys(gates).sort()).toEqual(["call_attached", "override_function", "run_script", "write_memory"]);
      for (const gate of Object.values(gates)) expect(gate.enabled).toBe(false);
      const spawned = expectToolSuccess(await bea.call("spawn_process", { program: game.path, args: GAME_ARGS }));
      const after = expectToolSuccess(await bea.call("bea_status", {}))["backends"] as Backend[];
      expect(after.find((b) => b.id === "frida")).toMatchObject({ state: "available", version: "17.23.2" });
      expect(after.find((b) => b.id === "jobhost")).toMatchObject({ state: "available", detail: "probe ok" });
      expectToolSuccess(await bea.call("close_session", { session_id: spawned["session_id"] }));
    } finally {
      await bea.close();
    }
    const gated = await connectBea({ ledger, gates: { write_memory: true } });
    try {
      const gates = gated.status["gates"] as Record<string, Gate>;
      expect(gates["write_memory"]).toMatchObject({ enabled: true, source: "env", env: "BEA_ALLOW_WRITE_MEMORY" });
      for (const id of ["call_attached", "override_function", "run_script"]) expect(gates[id]?.enabled).toBe(false);
    } finally {
      await gated.close();
    }
  }, 90_000);

  it("stdin EOF with 3 piped owned + 1 attached: exit 0 in < 2 s, owned targets dead, the attached one alive", async () => {
    const bea = await connectBea({ ledger });
    let outcome;
    try {
      for (let i = 0; i < 3; i += 1)
        expectToolSuccess(await bea.call("spawn_process", { program: game.path, args: GAME_ARGS }));
      const foreign = await startForeignGame();
      expectToolSuccess(await bea.call("attach_process", { pid: foreign.pid }));
    } finally {
      outcome = await bea.close();
    }
    expect(outcome).toMatchObject({ exitCode: 0, signal: null });
    expect(outcome.closeMs).toBeLessThan(2000);
    const audit = await ledger.audit();
    expect(audit.leaks).toEqual([]);
    expect(audit.deadAttachTargets).toEqual([]);
  }, 90_000);

  it("a hard-killed server leaves no owned target (kill-on-close job held by bea-jobhost); an attached one runs on", async () => {
    const bea = await connectBea({ ledger });
    try {
      const owned: { pid: number; creation: string | null }[] = [];
      for (let i = 0; i < 2; i += 1) {
        const spawned = expectToolSuccess(await bea.call("spawn_process", { program: game.path, args: GAME_ARGS }));
        expectToolSuccess(await bea.call("resume_process", { session_id: spawned["session_id"] }));
        const identity = spawned["identity"] as { pid: number; start_time: { source: string; value: string } };
        const creation = identity.start_time.source === "os-creation-time" ? identity.start_time.value : null;
        expect(pidStatus(pidcheck, identity.pid, creation).alive).toBe(true);
        owned.push({ pid: identity.pid, creation });
      }
      const foreign = await startForeignGame();
      expectToolSuccess(await bea.call("attach_process", { pid: foreign.pid }));
      process.kill(bea.pid ?? 0, "SIGKILL"); // TerminateProcess: no shutdown handler runs in the server
      for (const target of owned)
        await vi.waitFor(() => expect(pidStatus(pidcheck, target.pid, target.creation).alive).toBe(false), {
          interval: 100,
          timeout: 10_000,
        });
      // the attached target lost its agent's host but keeps running (BEA never kills what it attached to)
      expect(pidStatus(pidcheck, foreign.pid ?? 0).alive).toBe(true);
      expect(foreign.exitCode).toBeNull();
    } finally {
      await bea.close();
    }
  }, 60_000);
});
