import type { BeaError, BeaErrorOf } from "../domain/errors/beaError.js";
import { inputError, invalidState, sessionNotFound } from "../domain/errors/constructors.js";
import type { ExitInfo } from "../domain/process/instance.js";
import { err, type Result } from "../domain/result.js";
import type { EmuSessionHandle } from "../ports/emu.js";
import type { LiveSession, OperationContext, SessionId } from "../ports/sessions.js";
import type { BeaApplication } from "./BeaApplication.js";
import type { HandlerContext } from "./handlerContext.js";

/**
 * CI-I14: THE way handlers and application services reach a session by id (WP0, complete). One admission, one kind
 * dispatch, one error table for all 12 areas (contract test: outside this file, src/providers/** and the sessions
 * area — which answers tombstones itself — no code calls `.withSession(`, `.kindOf(` or `.admit(`):
 *
 * | situation                                   | error                                                        |
 * |---------------------------------------------|--------------------------------------------------------------|
 * | unknown id, or a closed session (tombstone)  | session_not_found                                            |
 * | live id given to an emulation-only tool      | invalid_request {path, reason:"invalid_value"} naming emu_*  |
 * | emulation id given to a live-only tool       | invalid_request {path, reason:"invalid_value"} naming the live tool family |
 * | need "agent", state exited                   | target_exited (exit facts from liveness())                   |
 * | need "agent", state detached                 | capability_unavailable {capability:"agent", reason:"agent-gone"} |
 * | need "agent", state cleanup_pending          | invalid_state {expected:["paused","running"]}                |
 * | state closing / closed                       | session_not_found                                            |
 *
 * `need:"host"` (status, wait, query_events, stop of host handles) passes every non-closed state.
 */
export type LiveNeed = "agent" | "host";

export interface LiveOpOptions {
  readonly mode: "exclusive" | "concurrent";
  readonly need: LiveNeed;
  /** input path used in invalid_request issues (default "session_id"; diff_function passes "live_session_id") */
  readonly path?: string;
}

const wrongKind = (operation: string, path: string, given: "live" | "emulation"): BeaErrorOf<"InputError"> =>
  inputError(operation, [
    {
      path,
      reason: "invalid_value",
      message:
        given === "emulation"
          ? `${path} names an emulation session; ${operation} needs a live session (spawn_process or attach_process). For emulation use emu_call.`
          : `${path} names a live session; ${operation} needs an emulation session (emu_open). For live calls use call_function.`,
      expected: given === "emulation" ? "live session id" : "emulation session id",
    },
  ]);

const UNKNOWN_EXIT: ExitInfo = { code: null, code_hex: null, kind: "unknown", name: null };

const targetExited = (operation: string, session: LiveSession): BeaErrorOf<"TargetExited"> => {
  const liveness = session.liveness();
  const exit = liveness.state === "exited" && liveness.exit !== null ? liveness.exit : UNKNOWN_EXIT;
  return {
    _tag: "TargetExited",
    operation,
    instance_id: session.instanceId,
    exit: { code: exit.code, code_hex: exit.code_hex, kind: exit.kind, name: exit.name },
    detach_reason: null,
  };
};

/** The state table above for need:"agent" (null = proceed). */
export const agentStateError = (operation: string, session: LiveSession): BeaError | null => {
  switch (session.state) {
    case "exited":
      return targetExited(operation, session);
    case "detached":
      return { _tag: "CapabilityUnavailable", operation, capability: "agent", reason: "agent-gone", retryable: false };
    case "cleanup_pending":
      return invalidState(operation, "cleanup_pending", ["paused", "running"]);
    case "closing":
    case "closed":
      return sessionNotFound(operation, session.id);
    default:
      return null;
  }
};

const admitRequest = (ctx: HandlerContext, sessionId: SessionId) => ({
  signal: ctx.signal,
  timeoutMs: ctx.remainingMs(),
  sessionId,
});

/** A live session through admission + the per-session FIFO. */
export const liveOp = <T>(
  app: BeaApplication,
  ctx: HandlerContext,
  sessionId: SessionId,
  options: LiveOpOptions,
  fn: (session: LiveSession, op: OperationContext) => Promise<Result<T, BeaError>>,
): Promise<Result<T, BeaError>> =>
  app.services.sessions.admit(ctx.operation, admitRequest(ctx, sessionId), async (op) => {
    const kind = app.services.sessions.kindOf(sessionId);
    if (kind === null || kind === "closed") return err(sessionNotFound(ctx.operation, sessionId));
    if (kind === "emulation") return err(wrongKind(ctx.operation, options.path ?? "session_id", "emulation"));
    return app.services.sessions.withSession(sessionId, op, options.mode, async (session) => {
      const blocked = options.need === "agent" ? agentStateError(ctx.operation, session) : null;
      return blocked !== null ? err(blocked) : fn(session, op);
    });
  });

/**
 * Review fix EMU-4: emulation tool operations are exclusive per session, FIFO, from address resolution through the
 * bridge requests (run, save_as/drop) to the state lineage update. The bridge serializes single requests only, so two
 * parallel emu_call requests interleaved (A.run, B.run, A.state.save): a named snapshot held another call's state and
 * the es_ lineage digests named the wrong state. Per application (WeakMap), per session id.
 */
const emuQueues = new WeakMap<BeaApplication, Map<SessionId, Promise<void>>>();

const exclusiveEmu = async <T>(
  app: BeaApplication,
  sessionId: SessionId,
  op: OperationContext,
  fn: () => Promise<Result<T, BeaError>>,
): Promise<Result<T, BeaError>> => {
  let queues = emuQueues.get(app);
  if (queues === undefined) {
    queues = new Map();
    emuQueues.set(app, queues);
  }
  const previous = queues.get(sessionId) ?? Promise.resolve();
  let release: () => void = () => undefined;
  const mine = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.then(() => mine);
  queues.set(sessionId, tail);
  try {
    const turn = await new Promise<boolean>((resolve) => {
      if (op.signal.aborted) {
        resolve(false);
        return;
      }
      const onAbort = (): void => resolve(false);
      op.signal.addEventListener("abort", onAbort, { once: true });
      void previous.then(() => {
        op.signal.removeEventListener("abort", onAbort);
        resolve(true);
      });
    });
    if (!turn) return err({ _tag: "Cancelled", operation: op.name, by: "client" });
    return await fn();
  } finally {
    release();
    if (queues.get(sessionId) === tail) queues.delete(sessionId);
  }
};

/** An emulation session (EmuPort.lookup resolves the current generation), exclusive per session (EMU-4). */
export const emuOp = <T>(
  app: BeaApplication,
  ctx: HandlerContext,
  sessionId: SessionId,
  fn: (handle: EmuSessionHandle, op: OperationContext) => Promise<Result<T, BeaError>>,
  path = "session_id",
): Promise<Result<T, BeaError>> =>
  app.services.sessions.admit(ctx.operation, admitRequest(ctx, sessionId), async (op) => {
    const kind = app.services.sessions.kindOf(sessionId);
    if (kind === null || kind === "closed") return err(sessionNotFound(ctx.operation, sessionId));
    if (kind === "live") return err(wrongKind(ctx.operation, path, "live"));
    return exclusiveEmu(app, sessionId, op, async () => {
      // looked up inside the turn: a bridge restart while queued gives the current generation
      const handle = app.services.emulator.lookup(sessionId);
      return handle === null ? err(sessionNotFound(ctx.operation, sessionId)) : fn(handle, op);
    });
  });

/** Tools that accept both kinds (list_modules, read_memory, disassemble, list_module_symbols, map_address). */
export const anySessionOp = <T>(
  app: BeaApplication,
  ctx: HandlerContext,
  sessionId: SessionId,
  options: LiveOpOptions,
  branches: {
    readonly live: (session: LiveSession, op: OperationContext) => Promise<Result<T, BeaError>>;
    readonly emulation: (handle: EmuSessionHandle, op: OperationContext) => Promise<Result<T, BeaError>>;
  },
): Promise<Result<T, BeaError>> =>
  app.services.sessions.kindOf(sessionId) === "emulation"
    ? emuOp(app, ctx, sessionId, branches.emulation, options.path ?? "session_id")
    : liveOp(app, ctx, sessionId, options, branches.live);
