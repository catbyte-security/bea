import type { SESSION_TOOLS } from "../../contracts/areas/sessions.js";
import { HARD_LIMITS } from "../../domain/config.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError, sessionNotFound } from "../../domain/errors/constructors.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { GATE_IDS, GATE_SPECS } from "../../domain/gates.js";
import type { JsonObject } from "../../domain/json.js";
import { err, ok } from "../../domain/result.js";
import { PRODUCT_IDENTITY } from "../../identity.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext, HandlersFor } from "../handlerContext.js";
import { hostFactsOf } from "../sessions/hostFacts.js";
import {
  closedAnswer,
  keyDigest,
  lifecycleOf,
  peek,
  peekResult,
  pick,
  pollEnvelope,
  recordTool,
  startupOutcome,
  targetStateOf,
  visibleEmulation,
  waitConditionFor,
  type OutOf,
} from "../sessions/sessionTools.js";
import {
  crashOutput,
  exitOf,
  identityOf,
  outputTail,
  sessionEffects,
  sessionInstruments,
  sessionScans,
  visibleOf,
  type StatusResult,
} from "../sessions/statusProjection.js";

/**
 * Handlers for the sessions area (DESIGN §6.2 A). bea_status keeps the S1 seed (backends, sessions and notes come from
 * StatusRegistry contributors; SESS contributes from createSessionService). The six session tools admit through the
 * DynamicSessionPort (this area answers tombstones itself, so it calls admit/kindOf/withSession directly; every other
 * area goes through sessionAccess.ts). Recorded tools write their evidence before returning (record-before-deliver) and
 * reference the lifecycle effects the session's evidence sink applied.
 */
type Tools = typeof SESSION_TOOLS;

const admitRequest = (ctx: HandlerContext, sessionId?: string) => ({
  signal: ctx.signal,
  timeoutMs: ctx.remainingMs(),
  ...(sessionId === undefined ? {} : { sessionId }),
});

const clip = (text: string | null, max: number): string | null => (text === null ? null : text.slice(0, max));

/** How long resume_process lets the recording registry catch up after its wait condition held (bounded by wait_ms). */
const SETTLE_MAX_MS = 2000;
const SETTLE_POLL_MS = 25;

/**
 * After resume_process's wait held, the recordings it waited for may still read "active": the agent's final batch
 * (an instrument's end, or the exit-time flush of a target that is exiting) ends the stream before the registry has
 * ended the recording, and before the root-exit report of an exiting target arrives. The contract promises finished
 * summaries, so wait — bounded — until every such recording left "active" (it ends with target_exited once the exit
 * report lands). Integrator fix (WP18): a trace_api installed before resume made resume_process {wait_ms} return in
 * ~40 ms as "running" with the recording still active while behavior.exe was exiting.
 */
const settleRecordings = async (
  app: BeaApplication,
  sessionId: string,
  streams: readonly string[],
  limit: { readonly budgetMs: number; readonly signal: AbortSignal },
): Promise<void> => {
  const { budgetMs, signal } = limit;
  const until = performance.now() + Math.min(budgetMs, SETTLE_MAX_MS);
  const waiting = new Set(streams);
  const pending = (): boolean =>
    app.services.recordings
      .list(sessionId)
      .some((r) => r.create.agentStream !== null && waiting.has(r.create.agentStream) && r.view().state === "active");
  while (pending() && !signal.aborted && performance.now() < until)
    await new Promise<void>((resolve) => setTimeout(resolve, SETTLE_POLL_MS));
};

const wrongKind = (operation: string): BeaError =>
  inputError(operation, [
    {
      path: "session_id",
      reason: "invalid_value",
      message: `session_id names an emulation session; ${operation} needs a live session (spawn_process or attach_process).`,
      expected: "live session id",
    },
  ]);

export const createSessionHandlers = (app: BeaApplication): HandlersFor<Tools> => ({
  bea_status: async () => {
    const { backends, sessions, storage, notes } = await app.status.collect();
    const { config, run } = app;
    return ok({
      server: {
        name: PRODUCT_IDENTITY.mcpServerKey,
        version: PRODUCT_IDENTITY.packageVersion,
        run_id: run.runId,
        pid: run.pid,
        started_at: run.startedAt,
        transport: run.transport,
        platform: config.platform,
        home: config.home.value,
      },
      gates: Object.fromEntries(
        GATE_IDS.map((gate) => [
          gate,
          {
            enabled: config.gates[gate].value,
            source: config.gates[gate].source,
            env: GATE_SPECS[gate].env,
            enables: GATE_SPECS[gate].enables,
          },
        ]),
      ) as {
        [G in (typeof GATE_IDS)[number]]: {
          enabled: boolean;
          source: "default" | "config-file" | "env";
          env: string;
          enables: string;
        };
      },
      limits: {
        max_wait_ms: HARD_LIMITS.maxWaitMs,
        max_tool_call_ms: HARD_LIMITS.maxToolCallMs,
        recommended_client_tool_timeout_s: HARD_LIMITS.recommendedClientToolTimeoutSeconds,
        max_response_bytes: config.mcpMaxResponseBytes.value,
        max_tool_input_bytes: HARD_LIMITS.maxToolInputBytes,
        max_live_sessions: config.limits.maxLiveSessions.value,
        max_piped_targets: 3,
        max_emulation_sessions: config.emu.maxSessions.value,
        max_instruments_per_session: 16,
        debug_register_slots: 4,
        max_scans_per_session: 8,
        quotas_mb: {
          ledger: config.quotas.ledgerMb.value,
          ledger_reserve: config.quotas.ledgerReserveMb.value,
          stream: config.quotas.streamMb.value,
          stream_total: config.quotas.streamTotalMb.value,
          blobs: config.quotas.blobMb.value,
        },
        anti_cheat_allowed: config.attach.allowAntiCheat.value,
      },
      backends,
      sessions,
      storage,
      notes,
      evidence_id: null,
      coverage: COMPLETE,
      limitations: [],
    });
  },

  list_processes: async (input, ctx) =>
    app.services.sessions.admit(ctx.operation, admitRequest(ctx), async (op) => {
      const listed = await app.services.sessions.processes(op);
      if (!listed.ok) return listed;
      const bySession = new Map<number, string>();
      for (const s of app.services.sessions.list())
        if (s.kind === "live" && s.pid !== null) bySession.set(s.pid, s.session_id);
      const needle = input.filter?.toLowerCase();
      const matching = listed.value
        .filter(
          (p) =>
            needle === undefined ||
            p.name.toLowerCase().includes(needle) ||
            (p.path ?? "").toLowerCase().includes(needle),
        )
        .sort((a, b) => {
          const an = a.name.toLowerCase();
          const bn = b.name.toLowerCase();
          return an < bn ? -1 : an > bn ? 1 : a.pid - b.pid;
        });
      const rows = matching.slice(input.offset, input.offset + input.limit).map((p) => ({
        pid: p.pid,
        name: p.name.slice(0, 260),
        path: clip(p.path, 1024),
        ppid: p.ppid,
        started: clip(p.started, 40),
        user: clip(p.user, 256),
        bea_session: bySession.get(p.pid) ?? null,
      }));
      const nextOffset = input.offset + rows.length;
      return ok({
        rows,
        page: {
          offset: input.offset,
          limit: input.limit,
          total: matching.length,
          next_offset: nextOffset < matching.length ? nextOffset : null,
        },
        evidence_id: null,
        coverage: COMPLETE,
        limitations: [],
      });
    }),

  spawn_process: async (input, ctx) =>
    app.services.sessions.admit(ctx.operation, admitRequest(ctx), async (op) => {
      const env: Record<string, string> = {};
      for (const entry of input.env) {
        const eq = entry.indexOf("=");
        env[entry.slice(0, eq)] = entry.slice(eq + 1);
      }
      const spawned = await app.services.sessions.spawn(
        {
          program: input.program,
          argv: input.args,
          ...(input.cwd === undefined ? {} : { cwd: input.cwd }),
          env,
          captureOutput: input.capture_output,
          resume: false,
          ...(input.expect_sha256 === undefined ? {} : { expectSha256: input.expect_sha256.toLowerCase() }),
          redactLiterals: input.redact_literals,
        },
        op,
      );
      if (!spawned.ok) return spawned;
      return startupOutcome(
        app,
        op,
        spawned.value,
        {
          program: input.program,
          args_count: input.args.length,
          cwd: input.cwd ?? null,
          capture_output: input.capture_output,
          env_keys_count: Object.keys(env).length,
          env_keys_sha256: keyDigest(Object.keys(env)),
          expect_sha256: input.expect_sha256?.toLowerCase() ?? null,
          redact_literals_count: input.redact_literals.length,
        },
        input.redact_literals,
      );
    }),

  attach_process: async (input, ctx) =>
    app.services.sessions.admit(ctx.operation, admitRequest(ctx), async (op) => {
      let pid = input.pid;
      if (pid === undefined) {
        const wanted = (input.name ?? "").toLowerCase();
        const listed = await app.services.sessions.processes(op);
        if (!listed.ok) return listed;
        const matches = listed.value.filter((p) => p.name.toLowerCase() === wanted);
        if (matches.length === 0)
          return err(
            inputError(op.name, [
              { path: "name", reason: "invalid_value", message: "No running process has this exact image name." },
            ]),
          );
        if (matches.length > 1)
          return err({
            ...inputError(op.name, [
              {
                path: "name",
                reason: "invalid_value",
                message: `${String(matches.length)} processes have this image name; attach by pid (see details.diagnostics.candidates).`,
              },
            ]),
            diagnostics: { candidates: matches.slice(0, 32).map((p) => p.pid) },
          });
        pid = matches[0]?.pid ?? 0;
      }
      const attached = await app.services.sessions.attach(
        {
          pid,
          ...(input.expect_sha256 === undefined ? {} : { expectSha256: input.expect_sha256.toLowerCase() }),
          redactLiterals: input.redact_literals,
        },
        op,
      );
      if (!attached.ok) return attached;
      return startupOutcome(
        app,
        op,
        attached.value,
        {
          pid,
          by_name: input.name !== undefined,
          expect_sha256: input.expect_sha256?.toLowerCase() ?? null,
          redact_literals_count: input.redact_literals.length,
        },
        input.redact_literals,
      );
    }),

  resume_process: async (input, ctx) =>
    app.services.sessions.admit<OutOf<"resume_process">>(
      ctx.operation,
      admitRequest(ctx, input.session_id),
      async (op) => {
        const sessions = app.services.sessions;
        const kind = sessions.kindOf(input.session_id);
        if (kind === null || kind === "closed") return err(sessionNotFound(op.name, input.session_id));
        if (kind === "emulation") return err(wrongKind(op.name));
        const activeStreams = app.services.recordings
          .list(input.session_id)
          .filter(
            (r) => r.create.agentInstrumentId !== null && r.create.agentStream !== null && r.view().state === "active",
          )
          .map((r) => r.create.agentStream as string);
        const resumed = await sessions.resume(input.session_id, op);
        if (!resumed.ok) return resumed;
        return peekResult(app, input.session_id, op, async (session) => {
          let waited = 0;
          const cond = input.wait_ms > 0 ? waitConditionFor(input.until, activeStreams) : null;
          if (cond !== null) {
            const outcome = await session.waitFor(cond, op, input.wait_ms);
            waited = outcome.waitedMs;
            // UX-5: once the target exited, EVERY agent-streamed recording (the built-in exceptions, modules and
            // output ones included) is settled: they end with target_exited when the exit report lands, which a
            // clean exit or a fast fail reaches after the process-exit condition held
            const exitedNow = exitOf(session.liveness()) !== null;
            const settle = exitedNow
              ? app.services.recordings
                  .list(session.id)
                  .filter((r) => r.create.agentStream !== null && r.view().state === "active")
                  .map((r) => r.create.agentStream as string)
              : activeStreams;
            if (outcome.satisfied && settle.length > 0) {
              const started = performance.now();
              await settleRecordings(app, session.id, settle, {
                budgetMs: input.wait_ms - waited,
                signal: op.signal,
              });
              waited += Math.round(performance.now() - started);
            }
          }
          const exit = exitOf(session.liveness());
          const crash = exit === null ? null : await session.crash(op);
          const result = {
            state: session.state === "exited" || exit !== null ? ("exited" as const) : ("running" as const),
            waited_ms: waited,
            exit,
            crash: crash === null || !crash.ok ? null : crashOutput(crash.value, false),
            instruments: sessionInstruments(app.services.recordings, session.id, 16, true),
          };
          const effects = pick(await lifecycleOf(session), ["process-resumed"]).slice(-1);
          const facts = hostFactsOf(session);
          // UX-5: an exited target whose listed recordings still read active is not a complete picture yet
          const stillActive = result.state === "exited" && result.instruments.some((i) => i.state === "active");
          const envelope = await recordTool(app, {
            predicate: "bea.process.instance",
            operation: op.name,
            params: { session_id: input.session_id, wait_ms: input.wait_ms, until: input.until },
            instanceId: session.instanceId,
            result: result as unknown as JsonObject,
            ...(stillActive
              ? { coverage: { status: "partial" as const, truncated: false, reasons: ["recording_active"] } }
              : {}),
            limitations: [...(facts?.limitations() ?? []), ...(stillActive ? [LIMITATIONS.RECORDING_ACTIVE] : [])],
            effects,
            ...(crash !== null && crash.ok && crash.value !== null && crash.value.evidence_id !== null
              ? { links: [crash.value.evidence_id] }
              : {}),
          });
          if (!envelope.ok) return envelope;
          return ok({ ...result, ...envelope.value });
        });
      },
    ),

  session_status: async (input, ctx) =>
    app.services.sessions.admit<OutOf<"session_status">>(
      ctx.operation,
      admitRequest(ctx, input.session_id),
      async (op) => {
        const sessions = app.services.sessions;
        const kind = sessions.kindOf(input.session_id);
        if (kind === null) return err(sessionNotFound(op.name, input.session_id));
        const driver = sessions.external(input.session_id);
        if (kind === "emulation" || (kind === "closed" && driver !== null)) {
          if (driver === null) return err(sessionNotFound(op.name, input.session_id));
          const detail = await driver.detail(input.detail, op);
          if (!detail.ok) return detail;
          const summary = driver.summary();
          return ok({
            session_id: input.session_id,
            kind: "emulation" as const,
            state: kind === "closed" ? ("closed" as const) : visibleEmulation(summary.state),
            identity: null,
            exit: null,
            crash: null,
            instruments: [],
            effects: [],
            scans: [],
            output_tail: null,
            module_map_epoch: null,
            emulation: detail.value,
            ...pollEnvelope(),
          });
        }
        return peekResult<OutOf<"session_status">>(app, input.session_id, op, async (session) => {
          const complete = input.detail === "complete";
          const exit = exitOf(session.liveness());
          const crash = exit === null ? null : await session.crash(op);
          const facts = hostFactsOf(session);
          const containment = facts?.containment() ?? null;
          const body: StatusResult = {
            session_id: session.id,
            kind: "live",
            state: visibleOf(session.state),
            identity: identityOf(session.instanceId, session.identity, session.ownership),
            exit,
            crash: crash === null || !crash.ok ? null : crashOutput(crash.value, complete),
            ...(containment === null
              ? {}
              : {
                  containment: {
                    kind: containment.kind,
                    active_processes: containment.activeProcesses,
                    children_seen: [...containment.childrenSeen].slice(0, 64),
                  },
                }),
            instruments: sessionInstruments(app.services.recordings, session.id, 64, false),
            effects: await sessionEffects(app.services.evidence, app.services.recordings, session),
            scans: sessionScans(app.services.handles, session.id),
            output_tail: outputTail(session),
            module_map_epoch: app.services.evidence.modules.current(session.instanceId)?.epoch ?? null,
            emulation: null,
          };
          const limitations = facts?.limitations() ?? [];
          if (!complete) return ok({ ...body, ...pollEnvelope(limitations) });
          const envelope = await recordTool(app, {
            predicate: "bea.session.status",
            operation: op.name,
            params: { session_id: input.session_id, detail: input.detail },
            instanceId: session.instanceId,
            result: body as unknown as JsonObject,
            limitations,
            effects: [],
          });
          if (!envelope.ok) return envelope;
          return ok({ ...body, ...envelope.value });
        });
      },
    ),

  close_session: async (input, ctx) =>
    app.services.sessions.admit<OutOf<"close_session">>(
      ctx.operation,
      admitRequest(ctx, input.session_id),
      async (op) => {
        const sessions = app.services.sessions;
        const kind = sessions.kindOf(input.session_id);
        if (kind === null) return err(sessionNotFound(op.name, input.session_id));
        if (kind === "closed") return closedAnswer(app, input.session_id, op);
        if (kind === "emulation") {
          const closed = await sessions.close(input.session_id, { force: input.force }, op);
          if (!closed.ok) return closed;
          return ok({
            session_id: input.session_id,
            already_closed: false,
            target_state: "none" as const,
            reverted: [],
            exit: null,
            manifests: [],
            ...pollEnvelope(closed.value.limitations),
          });
        }
        const before = await peek(app, input.session_id, op, async (session) => ({
          session,
          effects: (await sessionEffects(app.services.evidence, app.services.recordings, session)).filter(
            (row) => row.status === "active" || row.status === "revert-failed",
          ),
        }));
        if (!before.ok) return before;
        const { session } = before.value;
        const closed = await sessions.close(input.session_id, { force: input.force }, op);
        if (!closed.ok) return closed;
        const report = closed.value;
        const reverted = before.value.effects
          .map((row) => {
            const status = app.services.evidence.effects.state(row.effect)?.status;
            const mapped =
              status === "reverted"
                ? "reverted"
                : status === "revert-failed"
                  ? "revert-failed"
                  : status === undefined
                    ? null
                    : "implicit-end";
            return mapped === null
              ? null
              : { effect: row.effect, kind: row.kind, status: mapped as "reverted" | "revert-failed" | "implicit-end" };
          })
          .filter((row): row is NonNullable<typeof row> => row !== null)
          .slice(0, 256);
        const facts = hostFactsOf(session);
        const manifests = (facts?.manifests() ?? []).slice(0, 64);
        const result = {
          session_id: input.session_id,
          already_closed: false,
          target_state: targetStateOf(report.targetState),
          reverted,
          exit:
            report.exit === null
              ? null
              : {
                  code: report.exit.code,
                  code_hex: report.exit.code_hex,
                  kind: report.exit.kind,
                  name: report.exit.name,
                },
          manifests,
        };
        const effects = pick(await lifecycleOf(session), ["process-killed"]);
        const envelope = await recordTool(app, {
          predicate: "bea.process.exit",
          operation: op.name,
          params: { session_id: input.session_id, force: input.force },
          instanceId: session.instanceId,
          result: result as unknown as JsonObject,
          limitations: report.limitations,
          effects,
          links: manifests,
        });
        if (!envelope.ok) return envelope;
        return ok({ ...result, ...envelope.value });
      },
    ),
});
