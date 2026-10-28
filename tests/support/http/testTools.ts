import { randomUUID } from "node:crypto";

import { z } from "zod";

import type { AbortCause, HandlerContext, ToolHandler } from "../../../src/application/handlerContext.js";
import type { HandlerLookup } from "../../../src/application/invokeTool.js";
import { fx } from "../../../src/contracts/effects.js";
import { pollOutput } from "../../../src/contracts/schemas/envelope.js";
import { defineTool, type ToolContract } from "../../../src/contracts/toolContract.js";
import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import { ok, type Result } from "../../../src/domain/result.js";
import type { Gate } from "../frida/gate.js";

/**
 * WP16 test tools, registered through HttpRuntimeDeps.extraContracts (never in the production catalog):
 * - `http_test_slow`: sleeps `ms` (or until a named in-process gate opens) and records how its signal ended, so a
 *   test can prove that a client-side abort reached the handler (S1 §8 "cancellation");
 * - `http_test_last_abort`: reports that record (subprocess tests ask over HTTP);
 * - `http_test_open_session` / `http_test_get_session`: a process-owned fake "BEA session" that must survive MCP
 *   session reconnects (D-INT-12: the application belongs to the process). Wave rule §8.4: a fake, not WP4's sessions.
 */
const envelope = { evidence_id: null, coverage: COMPLETE, limitations: [] as string[] };
const mcpOnly = { tier: "mcp-only", reason: "HTTP boundary test double; never part of the catalog." } as const;

export interface HttpTestState {
  /** How the most recent http_test_slow call ended. */
  lastAbort: { readonly label: string; readonly cause: AbortCause | null; readonly aborted: boolean } | null;
  readonly sessions: Set<string>;
  /** In-process tests: http_test_slow with `gate: name` waits for this gate (or its signal). */
  readonly gates: Map<string, Gate>;
  started: number;
}

export const createHttpTestState = (): HttpTestState => ({
  lastAbort: null,
  sessions: new Set(),
  gates: new Map(),
  started: 0,
});

const slow = defineTool({
  name: "http_test_slow",
  area: "sessions",
  phase: "P1",
  description: "HTTP boundary test double: waits ms milliseconds (or for a named test gate) and reports cancellation.",
  inputSchema: z.strictObject({
    ms: z.number().int().min(0).max(110_000).default(0),
    gate: z.string().min(1).max(64).optional(),
    label: z.string().max(64).default(""),
  }),
  outputSchema: pollOutput({ slept_ms: z.number().int().min(0).max(120_000), aborted: z.boolean() }),
  effects: fx({}),
  returnsTargetContent: false,
  cli: mcpOnly,
  maxBlockingMs: 120_000,
  examples: [],
});

const lastAbort = defineTool({
  name: "http_test_last_abort",
  area: "sessions",
  phase: "P1",
  description: "HTTP boundary test double: reports how the most recent http_test_slow call ended (abort cause).",
  inputSchema: z.strictObject({}),
  outputSchema: pollOutput({
    label: z.string().nullable(),
    aborted: z.boolean(),
    cause: z.string().nullable(),
    started: z.number().int().min(0).max(1_000_000),
  }),
  effects: fx({}),
  returnsTargetContent: false,
  cli: mcpOnly,
  examples: [],
});

const fakeSessionId = z.uuid();

const openSession = defineTool({
  name: "http_test_open_session",
  area: "sessions",
  phase: "P1",
  description: "HTTP boundary test double: opens a fake process-owned BEA session that outlives MCP sessions.",
  inputSchema: z.strictObject({}),
  outputSchema: pollOutput({ fake_session_id: fakeSessionId }),
  effects: fx({ mutatesSession: true, idempotent: false }),
  returnsTargetContent: false,
  cli: mcpOnly,
  examples: [],
});

const getSession = defineTool({
  name: "http_test_get_session",
  area: "sessions",
  phase: "P1",
  description: "HTTP boundary test double: reports whether a fake BEA session opened earlier still exists.",
  inputSchema: z.strictObject({ fake_session_id: fakeSessionId, close: z.boolean().default(false) }),
  outputSchema: pollOutput({ exists: z.boolean(), open_sessions: z.number().int().min(0).max(1_000_000) }),
  effects: fx({ mutatesSession: true }),
  returnsTargetContent: false,
  cli: mcpOnly,
  examples: [],
});

export const HTTP_TEST_CONTRACTS: readonly ToolContract[] = [slow, lastAbort, openSession, getSession];

const sleep = (ms: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const timer = setTimeout(done, ms);
    function done(): void {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    }
    signal.addEventListener("abort", done, { once: true });
  });

const abortable = (gate: Gate, signal: AbortSignal): Promise<void> =>
  Promise.race([gate.wait().catch(() => undefined), sleep(2_147_000_000, signal)]);

type Out = Result<Readonly<Record<string, unknown>>, BeaError>;

/** Handlers over one state object (one per server process / in-process server). */
export const httpTestHandlers = (state: HttpTestState): HandlerLookup => {
  const table: Readonly<Record<string, (input: never, ctx: HandlerContext) => Promise<Out>>> = {
    http_test_slow: async (input: z.output<typeof slow.inputSchema>, ctx) => {
      state.started += 1;
      const started = Date.now();
      const gate = input.gate === undefined ? undefined : state.gates.get(input.gate);
      await (gate === undefined ? sleep(input.ms, ctx.signal) : abortable(gate, ctx.signal));
      const cause = ctx.abortCause();
      state.lastAbort = { label: input.label, cause, aborted: ctx.signal.aborted };
      return ok({ slept_ms: Math.min(120_000, Date.now() - started), aborted: ctx.signal.aborted, ...envelope });
    },
    http_test_last_abort: async () =>
      ok({
        label: state.lastAbort?.label ?? null,
        aborted: state.lastAbort?.aborted ?? false,
        cause: state.lastAbort?.cause?.kind ?? null,
        started: state.started,
        ...envelope,
      }),
    http_test_open_session: async () => {
      const id = randomUUID();
      state.sessions.add(id);
      return ok({ fake_session_id: id, ...envelope });
    },
    http_test_get_session: async (input: z.output<typeof getSession.inputSchema>) => {
      const exists = state.sessions.has(input.fake_session_id);
      if (input.close) state.sessions.delete(input.fake_session_id);
      return ok({ exists, open_sessions: state.sessions.size, ...envelope });
    },
  };
  return (name) => table[name] as ToolHandler<ToolContract> | undefined;
};
