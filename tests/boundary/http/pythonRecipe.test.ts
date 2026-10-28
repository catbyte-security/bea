import { existsSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

import { readConnectionFile } from "../../../src/server/http/connectionFile.js";
import { fixtureArtifact, fridaSkip, gccSkip, jobhostSkip, loadFixtures } from "../../support/acceptance/fixtures.js";
import { builtHttpUnavailable, httpLayout, SERVER_ENTRY, TS_HOOKS } from "../../support/http/httpServerProcess.js";
import {
  connectionFileFor,
  RecipeFailure,
  resolvePython,
  runRecipe,
  type RecipeReport,
} from "../../support/http/pythonRecipe.js";
import { OwnedPidLedger } from "../../support/process/ownedPidLedger.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";

/**
 * WP16 acceptance (DESIGN §8.4 row, CT-I10): the docs/http.md Python recipe, run verbatim with the system Python and
 * urllib, initializes, calls bea_status, reconnects with a new MCP session while a BEA session persists, deletes its
 * MCP session in `finally`, and stops the server via POST /shutdown (exit 0, connection file removed).
 * - source: the server from the TypeScript sources with a fake process-owned BEA session (wave rule §8.4);
 * - built: exactly `node <abs>/scripts/bea.mjs mcp --http` from BEA_DIST_DIR / dist, once with bea_status only and
 *   once with REAL BEA sessions (spawn_process of game_sim in MCP session 1, DELETE, reconnect, the sessions are still
 *   listed, close_session of one, POST /shutdown kills the other). That variant needs Frida, gcc fixtures and the
 *   jobhost (named skips otherwise) and audits the targets with the owned-PID ledger.
 */
const PYTHON = resolvePython();
const PYTHON_SKIP = "skip" in PYTHON ? PYTHON.skip : null;
const python = "executable" in PYTHON ? PYTHON.executable : "python";
const BUILD_SKIP = builtHttpUnavailable();
const skipNote = (reason: string | null): string => (reason === null ? "" : ` [skipped: ${reason}]`);
const firstReason = (...reasons: readonly (string | false | null)[]): string | null =>
  reasons.find((reason): reason is string => typeof reason === "string") ?? null;
/** The Frida, gcc and jobhost probes run only when Python and the built server are available. */
const realSessionSkip = (): string | null =>
  firstReason(PYTHON_SKIP, BUILD_SKIP) ?? firstReason(gccSkip(), fridaSkip(), jobhostSkip());
const REAL_SKIP = realSessionSkip();

const homes: TempHome[] = [];
afterEach(async () => {
  for (const home of homes.splice(0)) {
    // A failed driver may leave its server running: stop only the process this test started.
    const connection = await readConnectionFile(connectionFileFor(home));
    if (connection !== null)
      try {
        process.kill(connection.pid);
      } catch {
        // already gone
      }
    await home.cleanup();
  }
});

const isAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

describe("docs/http.md Python recipe (urllib)", () => {
  it.skipIf(PYTHON_SKIP !== null)(
    `initializes, reconnects while a BEA session persists, DELETEs in finally, 413s, stops via /shutdown${skipNote(PYTHON_SKIP)}`,
    async () => {
      const home = await createTempHome("http-recipe");
      homes.push(home);
      const report = await runRecipe(python, home, {
        beaMjs: httpLayout().dispatcher,
        launch: [
          process.execPath,
          "--experimental-transform-types",
          "--disable-warning=ExperimentalWarning",
          "--import",
          pathToFileURL(TS_HOOKS).href,
          SERVER_ENTRY,
        ],
        fakeSession: true,
        oversize: true,
      });
      expect(report.pid).toBe(report.conn_pid); // node launched directly: the Popen pid is the server
      expect(report.transport).toBe("http");
      expect(report.run_id_2).toBe(report.run_id_1); // same process-owned application after reconnecting
      expect(report.deleted).toBe(true);
      expect(report.stale_status).toBe(404);
      expect(report.fake_session).toMatchObject({ exists: true, open_sessions: 0 });
      expect(report.oversize_status).toBe(413);
      expect(report.after_oversize_error).toBe(false);
      expect(report.exit_code).toBe(0);
      expect(report.connection_file_exists).toBe(false);
      expect(isAlive(report.pid)).toBe(false);
    },
    120_000,
  );

  it.skipIf(PYTHON_SKIP !== null || BUILD_SKIP !== null)(
    `drives the BUILT server launched as node <abs>/scripts/bea.mjs mcp --http${skipNote(PYTHON_SKIP ?? BUILD_SKIP)}`,
    async () => {
      const home = await createTempHome("http-recipe-dist");
      homes.push(home);
      const report = await runRecipe(python, home, {
        beaMjs: httpLayout().dispatcher,
        launch: null,
        fakeSession: false,
        oversize: false,
      });
      expect(report.pid).toBe(report.conn_pid);
      expect(report.transport).toBe("http");
      expect(report.run_id_2).toBe(report.run_id_1);
      expect(report.deleted).toBe(true);
      expect(report.stale_status).toBe(404);
      expect(report.exit_code).toBe(0);
      expect(report.connection_file_exists).toBe(false);
      expect(existsSync(connectionFileFor(home))).toBe(false);
      expect(isAlive(report.pid)).toBe(false);
    },
    120_000,
  );

  it.skipIf(REAL_SKIP !== null)(
    `keeps REAL BEA sessions across MCP reconnects on the BUILT server; /shutdown kills what is left${skipNote(REAL_SKIP)}`,
    async () => {
      const manifest = await loadFixtures();
      const game = fixtureArtifact(manifest, "game_sim");
      if (game === null) throw new Error(`fixtures unavailable: ${JSON.stringify(manifest)}`);
      const ledger = new OwnedPidLedger(fixtureArtifact(manifest, "pidcheck")?.path ?? null);
      const home = await createTempHome("http-recipe-real");
      homes.push(home);
      const recordTargets = (partial: Partial<RecipeReport> | null): void => {
        for (const [label, target] of Object.entries(partial?.targets ?? {}))
          ledger.recordIdentity(target.identity, `game_sim (${label})`);
      };
      let report: RecipeReport;
      try {
        report = await runRecipe(
          python,
          home,
          {
            beaMjs: httpLayout().dispatcher,
            launch: null,
            fakeSession: false,
            oversize: false,
            target: { program: game.path, args: ["--no-threads", "--hz", "30"] },
          },
          150_000,
        );
      } catch (cause) {
        if (cause instanceof RecipeFailure) recordTargets(cause.report);
        await ledger.assertClean().catch(() => undefined); // reap proven leaks; the driver failure is the error
        throw cause;
      }
      recordTargets(report);
      const { closed, shutdown } = report.targets ?? expect.unreachable("no targets in the report");
      expect(closed.identity["ownership"]).toBe("owned");
      expect(shutdown.identity["ownership"]).toBe("owned");
      // MCP session 1 was DELETEd; MCP session 2 of the same server process still lists both BEA sessions.
      expect(report.deleted).toBe(true);
      expect(report.stale_status).toBe(404);
      expect(report.run_id_2).toBe(report.run_id_1);
      expect(report.listed_after_reconnect).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ session_id: closed.session_id, kind: "live", ownership: "owned", state: "paused" }),
          expect.objectContaining({
            session_id: shutdown.session_id,
            kind: "live",
            ownership: "owned",
            state: "running",
          }),
        ]),
      );
      expect(report.listed_after_reconnect).toHaveLength(2);
      expect(report.status_after_reconnect).toEqual({ state: "paused", pid: closed.identity.pid });
      expect(report.close).toEqual({ target_state: "killed", already_closed: false });
      expect(report.status_after_close).toBe("closed");
      expect(report.open_before_shutdown).toEqual([shutdown.session_id]);
      // Graceful stop: exit 0, connection file removed, the server and both job trees gone.
      expect(report.exit_code).toBe(0);
      expect(report.connection_file_exists).toBe(false);
      expect(isAlive(report.pid)).toBe(false);
      await ledger.assertClean();
    },
    180_000,
  );
});
