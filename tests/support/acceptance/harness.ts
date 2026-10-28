import type { CallToolResult } from "@modelcontextprotocol/client";

import { GATE_SPECS, type GateId } from "../../../src/domain/gates.js";
import { expectToolSuccess } from "../mcp/parseToolError.js";
import { connectStdioBea, type CloseOutcome, type StdioBea } from "../mcp/stdioSubprocess.js";
import type { OwnedPidLedger } from "../process/ownedPidLedger.js";
import type { TempHome } from "../workspace/tempHome.js";

/**
 * Acceptance harness (S6 §10.7, DESIGN §8.1 "Acceptance environment"): the BUILT server over stdio (BEA_DIST_DIR or
 * dist/), a temp BEA_HOME, opt-in gates through their environment variables, every advertised schema meta-validated,
 * outputs validated against the advertised schemas. It records the machine-wide anti-cheat notes bea_status reports
 * (fixtures have no target-scoped signal and must still spawn and attach), feeds spawn/attach identities to the
 * owned-PID ledger and enforces the hygiene budget of at most 3 spawned targets per server.
 */
export interface ConnectBeaOptions {
  readonly home?: TempHome;
  /** Gates to enable at server start (BEA_ALLOW_*=1). */
  readonly gates?: Partial<Record<GateId, boolean>>;
  /** BEA_ALLOW_ANTI_CHEAT=1 (user-level override; only for the tests that exercise it). */
  readonly allowAntiCheat?: boolean;
  readonly env?: Readonly<Record<string, string>>;
  /** spawn_process / attach_process identities are recorded here. */
  readonly ledger?: OwnedPidLedger;
  /** Spawned-target budget per server (default 3; S6 §10.7). */
  readonly maxSpawns?: number;
  readonly distDir?: string;
}

export interface BeaConnection extends StdioBea {
  /** bea_status at connect time. */
  readonly status: Readonly<Record<string, unknown>>;
  /** bea_status notes about machine-wide anti-cheat services/processes seen at connect (CI-I12). */
  readonly antiCheatNotes: readonly string[];
  readonly spawned: () => number;
}

const ANTI_CHEAT_NOTE = /anti-?cheat|easyanticheat|battleye|vanguard|faceit|\bvgc\b/iu;

export const connectBea = async (options: ConnectBeaOptions = {}): Promise<BeaConnection> => {
  const env: Record<string, string> = { ...options.env };
  for (const [gate, enabled] of Object.entries(options.gates ?? {}))
    if (enabled === true) env[GATE_SPECS[gate as GateId].env] = "1";
  if (options.allowAntiCheat === true) env["BEA_ALLOW_ANTI_CHEAT"] = "1";
  const bea = await connectStdioBea({
    env,
    clientName: "bea-acceptance",
    ...(options.home === undefined ? {} : { home: options.home }),
    ...(options.distDir === undefined ? {} : { distDir: options.distDir }),
  });
  let status: Readonly<Record<string, unknown>>;
  try {
    status = expectToolSuccess(await bea.call("bea_status", {}));
  } catch (cause) {
    await bea.close();
    throw cause;
  }
  const notes = Array.isArray(status["notes"])
    ? (status["notes"] as unknown[]).filter((n): n is string => typeof n === "string")
    : [];
  const maxSpawns = options.maxSpawns ?? 3;
  let spawned = 0;
  const call: StdioBea["call"] = async (name, args, callOptions) => {
    if (name === "spawn_process" && spawned >= maxSpawns)
      throw new Error(
        `acceptance hygiene: at most ${maxSpawns} spawned targets per server (S6 §10.7); start another server`,
      );
    const result: CallToolResult = await bea.call(name, args, callOptions);
    if ((name === "spawn_process" || name === "attach_process") && result.isError !== true) {
      if (name === "spawn_process") spawned += 1;
      const identity = (result.structuredContent as Readonly<Record<string, unknown>> | undefined)?.["identity"];
      if (options.ledger !== undefined && typeof identity === "object" && identity !== null)
        options.ledger.recordIdentity(
          identity as Readonly<Record<string, unknown>>,
          `${name} ${JSON.stringify(args ?? {}).slice(0, 80)}`,
        );
    }
    return result;
  };
  return {
    ...bea,
    call,
    status,
    antiCheatNotes: notes.filter((note) => ANTI_CHEAT_NOTE.test(note)),
    spawned: () => spawned,
  };
};

/**
 * One server shared by the read-only tests of a file (rea-testing §4.3): started on first use, closed in afterAll.
 * Lifecycle tests use their own connectBea() per test instead.
 */
export const sharedBea = (options: ConnectBeaOptions = {}) => {
  let connection: Promise<BeaConnection> | undefined;
  return {
    get: (): Promise<BeaConnection> => (connection ??= connectBea(options)),
    close: async (): Promise<CloseOutcome | null> => {
      if (connection === undefined) return null;
      const current = connection;
      connection = undefined;
      return (await current).close();
    },
  };
};
