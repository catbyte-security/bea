import { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { JsonValue } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { OperationContext, UserScriptOutcome, UserScriptPort, UserScriptRequest } from "../../ports/sessions.js";
import { classifyAbort } from "./aborts.js";
import type { CancellableLike, FridaMessage, FridaScriptLike, FridaSessionLike } from "./fridaPorts.js";
import { createNativeCancel } from "./NativeCancel.js";

/**
 * CI-B4: a caller script in its OWN Frida script, never inside the BEA agent (S4 §16): createScript (a compile error is
 * invalid_request) → its own logHandler and message capture (bounded count and bytes) → load → optional RPC call →
 * duration cap → unload. MODIFY (run_script) keeps the gate, the agent fingerprint before/after, the effect and the
 * evidence; this port only hosts the script. `unloaded:false` makes the caller report effect_unreverted.
 */
export interface UserScriptDeps {
  readonly session: () => FridaSessionLike | null;
  readonly createCancellable: () => CancellableLike;
  readonly logger: Logger;
  readonly now: () => number;
  readonly maxMessageBytes: number;
  readonly maxErrors: number;
  readonly unloadMs: number;
}

let userScripts = 0;

const lineOf = (text: string): number | null => {
  const match = /\((?:[^:()]*:)?(\d+)(?::\d+)?\)|line (\d+)/u.exec(text);
  const value = match?.[1] ?? match?.[2];
  return value === undefined ? null : Number(value);
};

const toJson = (value: unknown): JsonValue => {
  try {
    return JSON.parse(JSON.stringify(value ?? null)) as JsonValue;
  } catch {
    return null;
  }
};

export const createUserScriptPort = (deps: UserScriptDeps): UserScriptPort => ({
  run: async (req: UserScriptRequest, op: OperationContext): Promise<Result<UserScriptOutcome, BeaError>> => {
    const session = deps.session();
    if (session === null || session.isDetached())
      return err({
        _tag: "CapabilityUnavailable",
        operation: op.name,
        capability: "agent",
        reason: "agent-gone",
        retryable: false,
      });
    userScripts += 1;
    const createCancel = createNativeCancel(deps.createCancellable(), {
      deadline: op.deadline.min(10_000),
      signal: op.signal,
    });
    let script: FridaScriptLike;
    try {
      script = await session.createScript(
        req.source,
        { name: `bea-user-${String(userScripts)}`, runtime: req.runtime },
        createCancel.token,
      );
    } catch (cause) {
      const text = cause instanceof Error ? cause.message : String(cause);
      if (op.signal.aborted) return err(classifyAbort(op.signal, op.name, { deadline: op.deadline }));
      deps.logger.debug("user script compile failed", { text: text.slice(0, 512) });
      const line = lineOf(text);
      return err({
        _tag: "InputError",
        operation: op.name,
        issues: [
          {
            path: "source",
            reason: "invalid_value",
            message: `The script does not compile${line === null ? "" : ` (line ${String(line)})`}. Fix the syntax and retry.`,
          },
        ],
      });
    } finally {
      createCancel.dispose();
    }
    const messages: JsonValue[] = [];
    const errors: { description: string; line: number | null }[] = [];
    let bytes = 0;
    let truncated = false;
    const capture = (value: JsonValue): void => {
      const size = JSON.stringify(value).length;
      if (messages.length >= req.maxMessages || bytes + size > deps.maxMessageBytes) {
        truncated = true;
        return;
      }
      bytes += size;
      messages.push(value);
    };
    const onMessage = (message: FridaMessage): void => {
      try {
        if (message.type === "send") capture(toJson(message.payload));
        else if (errors.length < deps.maxErrors)
          errors.push({ description: String(message.description).slice(0, 512), line: message.lineNumber ?? null });
        else truncated = true;
      } catch {
        truncated = true;
      }
    };
    script.logHandler = (level, text) => capture({ log: level, text: String(text).slice(0, 4096) });
    script.message.connect(onMessage);
    const loadStarted = deps.now();
    let rpcResult: JsonValue | undefined;
    try {
      const loadCancel = createNativeCancel(deps.createCancellable(), {
        deadline: op.deadline.min(10_000),
        signal: op.signal,
      });
      try {
        await script.load(loadCancel.token);
      } finally {
        loadCancel.dispose();
      }
      if (req.rpcMethod !== undefined) {
        const fn = script.exports[req.rpcMethod];
        const rpcCancel = createNativeCancel(deps.createCancellable(), {
          deadline: op.deadline.min(req.durationMs),
          signal: op.signal,
        });
        try {
          if (fn !== undefined) rpcResult = toJson(await fn(...req.rpcArgs, rpcCancel.token));
        } catch (cause) {
          errors.push({
            description: (cause instanceof Error ? cause.message : String(cause)).slice(0, 512),
            line: null,
          });
        } finally {
          rpcCancel.dispose();
        }
      }
      await sleepUntil(loadStarted + req.durationMs, deps.now, op.signal, op.deadline);
    } catch (cause) {
      errors.push({ description: (cause instanceof Error ? cause.message : String(cause)).slice(0, 512), line: null });
    } finally {
      script.message.disconnect(onMessage);
    }
    const unloadCancel = createNativeCancel(deps.createCancellable(), {
      deadline: Deadline.after(deps.unloadMs, deps.now),
    });
    let unloaded: boolean;
    try {
      await script.unload(unloadCancel.token);
      unloaded = true;
    } catch {
      unloaded = script.isDestroyed;
    } finally {
      unloadCancel.dispose();
      script.logHandler = () => undefined;
    }
    return ok({
      messages,
      errors,
      ...(rpcResult === undefined ? {} : { rpcResult }),
      truncated,
      unloaded,
    });
  },
});

const sleepUntil = (at: number, now: () => number, signal: AbortSignal, deadline: Deadline): Promise<void> =>
  new Promise((resolve) => {
    const ms = Math.max(0, Math.min(at - now(), deadline.remaining()));
    if (ms === 0 || signal.aborted) {
      resolve();
      return;
    }
    const done = (): void => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal.addEventListener("abort", done, { once: true });
  });
