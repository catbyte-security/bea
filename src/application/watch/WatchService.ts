// =================================================================================================
// src/application/watch/WatchService.ts — watch_memory (DESIGN §6.2 #23, D-INT-20 as amended by CT-I4; S6 §4.22;
// WP9-WATCH). Method choice: `auto` = a debug register on every target whenever size and alignment fit (the agent
// then refuses only when no slot is free, and the watch falls back to page_guard); page_guard when asked for or when
// a debug register cannot express the watch; poll only when asked for. The agent arms; the host records.
// =================================================================================================
import type { z } from "zod";

import type { WATCH_TOOLS } from "../../contracts/areas/watch.js";
import type { AddressRef } from "../../domain/address/addressRef.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { inputError } from "../../domain/errors/constructors.js";
import type { Coverage } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { formatHex } from "../../domain/hex.js";
import type { JsonObject } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { InstrumentStateView } from "../../ports/recordings.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { WatchInstallParams, WatchInstallResult } from "../../shared/agentProtocol.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";
import type { LegendEntry, WatchDecoders } from "./decoders.js";
import { envelopeOf } from "./envelope.js";
import type { RateLimited } from "./events.js";
import { completeInstall, waitForEnd, type Installed } from "./install.js";
import { CodeLocator } from "./locate.js";
import { coveringWatch, isDrSize, pageCount } from "./plan.js";

type WatchContract = (typeof WATCH_TOOLS)[0];
export type WatchInput = z.output<WatchContract["inputSchema"]>;
export type WatchOutput = z.output<WatchContract["outputSchema"]>;
type Method = "debug_register" | "page_guard" | "poll";

const AGENT_METHOD: { readonly [M in Method]: WatchInstallParams["method"] } = {
  debug_register: "debug-register",
  page_guard: "page-guard",
  poll: "poll",
};
const MAX_LEGEND = 1024;

/** The module legend of the decoders: every loaded module (name, base, size, path), from the host's module map. */
export const moduleLegend = (app: BeaApplication, session: LiveSession): LegendEntry[] => {
  try {
    const current = app.services.evidence.modules.current(session.instanceId);
    if (current === undefined) return [];
    return current
      .map()
      .modules.slice(0, MAX_LEGEND)
      .map((m) => [m.display.name ?? m.base, m.base, m.size, m.display.path] as const);
  } catch {
    return [];
  }
};

/** Corrective input errors that need the resolved address (DESIGN §6.2 #23: name the nearest valid value). */
const planError = (input: WatchInput, va: bigint, method: Method): BeaError | null => {
  if (method === "debug_register" && input.access !== "execute" && (va & BigInt(input.size - 1)) !== 0n) {
    const cover = coveringWatch(va, input.size);
    return inputError("watch_memory", [
      {
        path: "address",
        reason: "invalid_value",
        message:
          cover === null
            ? `A ${String(input.size)}-byte debug-register watch must be ${String(input.size)}-aligned and this range crosses an 8-byte boundary; use method page_guard or two watches.`
            : `A ${String(input.size)}-byte debug-register watch must be ${String(input.size)}-aligned; watch ${String(cover.size)} bytes at ${formatHex(cover.address)} or use method page_guard.`,
      },
    ]);
  }
  if (method === "page_guard" && pageCount(va, input.size) > 16)
    return inputError("watch_memory", [
      {
        path: "size",
        reason: "out_of_range",
        message: "A page_guard watch covers at most 16 pages (64 KiB).",
        maximum: 16,
      },
    ]);
  return null;
};

/** auto (CT-I4): a debug register when it can express the watch; the agent's no-free-slot refusal falls back. */
const initialMethod = (input: WatchInput, va: bigint): Method => {
  if (input.method !== "auto") return input.method;
  if (input.access === "execute") return "debug_register";
  return isDrSize(input.size) && (va & BigInt(input.size - 1)) === 0n ? "debug_register" : "page_guard";
};

const agentParams = (input: WatchInput, va: bigint, method: Method, paused: boolean): WatchInstallParams => ({
  method: AGENT_METHOD[method],
  address: formatHex(va),
  size: method === "debug_register" && input.access === "execute" ? 1 : input.size,
  ...(method === "poll" ? { interval_ms: input.interval_ms } : {}),
  access: input.access === "read_write" ? "read-write" : input.access,
  threads: "all",
  capture: { registers: input.registers.length > 0 ? "gpr" : "none", backtrace: input.backtrace, values: true },
  ...(method === "page_guard" ? { rate_limit: { max_per_sec: input.rate_limit_per_sec, window_ms: 100 } } : {}),
  lifetime: { duration_ms: input.duration_ms, max_hits: input.max_events, clock: paused ? "resume" : "install" },
});

/** WatchInvalid arrives as a generic size issue (agentErrorMap); restate it at the address with what to do. */
const WATCH_INVALID: Readonly<Record<string, string>> = {
  range: "The page is not committed, is not readable, or already carries the target's own guard.",
  "stack-page": "The range lies on a thread stack; page_guard cannot watch stacks. Use debug_register.",
  "module-code": "The range lies in module code; page_guard watches data. Use access execute or debug_register.",
  "agent-page": "The address belongs to the BEA agent.",
  size: "debug_register watches 1, 2, 4 or 8 bytes.",
  alignment: "A debug-register watch must be aligned to its size.",
};
const restate = (error: BeaError): BeaError => {
  if (error._tag !== "InputError" || error.diagnostics?.["agent_tag"] !== "WatchInvalid") return error;
  const reason = String(error.diagnostics["reason"] ?? "");
  return inputError("watch_memory", [
    { path: "address", reason: "invalid_value", message: WATCH_INVALID[reason] ?? "The watch is invalid." },
  ]);
};

interface Armed {
  readonly method: Method;
  readonly result: WatchInstallResult;
}
const arm = async (
  session: LiveSession,
  op: OperationContext,
  input: WatchInput,
  va: bigint,
): Promise<Result<Armed, BeaError>> => {
  const first = initialMethod(input, va);
  const planned = planError(input, va, first);
  if (planned !== null) return err(planned);
  const call = (method: Method) =>
    session.agent.call("watchInstall", agentParams(input, va, method, session.paused), { op });
  const r = await call(first);
  if (r.ok) return ok({ method: first, result: r.value });
  const noSlot = r.error._tag === "InstrumentationFailed" && r.error.reason === "no-free-slot";
  if (input.method === "auto" && first === "debug_register" && input.access !== "execute" && noSlot) {
    const fallback = planError(input, va, "page_guard") ?? null;
    if (fallback !== null) return err(fallback);
    const second = await call("page_guard");
    return second.ok ? ok({ method: "page_guard", result: second.value }) : err(restate(second.error));
  }
  return err(restate(r.error));
};

/**
 * Review fix UX-9: a no-free-slot refusal names the agent's internal owners ("w1"); the caller can only stop rec_
 * handles. The owners become the session's recording ids (details.diagnostics.holders, conflicting_id the first).
 */
const withHolders = (app: BeaApplication, session: LiveSession, error: BeaError): BeaError => {
  if (error._tag !== "InstrumentationFailed" || error.reason !== "no-free-slot") return error;
  const inUse = error.diagnostics?.["in_use"];
  const owners = Array.isArray(inUse)
    ? inUse.flatMap((slot) =>
        typeof slot === "object" && slot !== null && !Array.isArray(slot) && typeof slot["owner"] === "string"
          ? [slot["owner"]]
          : [],
      )
    : [];
  const byAgentId = new Map(
    app.services.recordings
      .list(session.id)
      .filter((r) => r.create.agentInstrumentId !== null)
      .map((r) => [r.create.agentInstrumentId, r.id] as const),
  );
  const holders = [...new Set(owners.flatMap((owner) => byAgentId.get(owner) ?? []))];
  const { in_use: _agentOwners, ...rest } = error.diagnostics ?? {};
  return {
    ...error,
    conflicting_id: holders[0] ?? null,
    diagnostics: { ...rest, holders, slots_in_use: owners.length },
  };
};

const recordedLimitations = (input: WatchInput, armed: Armed): string[] => {
  const out: string[] = [LIMITATIONS.NOT_OBSERVED_WINDOW];
  if (armed.method === "debug_register" && input.access !== "execute") out.push(LIMITATIONS.WATCH_DR_TRAP_AFTER);
  if (armed.method === "debug_register" && input.access === "read_write") out.push(LIMITATIONS.WATCH_DR_READ_WRITE);
  if (armed.method === "debug_register" && armed.result.arm_errors.length > 0)
    out.push(LIMITATIONS.WATCH_ARM_ERRORS(armed.result.arm_errors.length));
  const verified = armed.result.verified;
  if (armed.method === "debug_register" && verified !== null && verified.ok < verified.threads_checked)
    out.push(LIMITATIONS.WATCH_UNVERIFIED);
  if (armed.method === "page_guard")
    out.push(
      LIMITATIONS.WATCH_PAGE_GUARD_COST,
      LIMITATIONS.WATCH_PAGE_GUARD_CONCURRENT,
      LIMITATIONS.WATCH_KERNEL_ACCESS,
    );
  // review fix AGENT-3: say when auto picked page_guard, whose guard makes the target's system calls on the page fail
  if (armed.method === "page_guard" && input.method === "auto") out.push(LIMITATIONS.WATCH_AUTO_PAGE_GUARD);
  if (armed.method === "poll") out.push(LIMITATIONS.WATCH_POLL_SAMPLED(input.interval_ms));
  return out;
};

interface WatchInstalled {
  readonly installed: Installed;
  readonly armed: Armed;
  readonly target: AddressRef;
  readonly legend: readonly LegendEntry[];
}

const install = async (
  app: BeaApplication,
  session: LiveSession,
  op: OperationContext,
  input: WatchInput,
): Promise<Result<WatchInstalled, BeaError>> => {
  const resolved = await app.services.address.resolve({ kind: "live", session }, input.address, op, {
    path: "address",
  });
  if (!resolved.ok) return resolved;
  const va = resolved.value.va;
  // UX-10 (CI-I10): the main image's preferred base (most writers are there), so hit rows decode their static form
  await app.services.address.prepare({ kind: "live", session }, [], op);
  const armed = await arm(session, op, input, va);
  if (!armed.ok) return err(withHolders(app, session, armed.error));
  const capture = app.services.evidence.instances.capture(session.instanceId);
  const { method, result } = armed.value;
  const legend = method === "poll" ? [] : moduleLegend(app, session);
  const size = method === "debug_register" && input.access === "execute" ? 1 : input.size;
  const decoders: WatchDecoders | JsonObject =
    method === "poll"
      ? { v: 1, kind: "poll", view: input.view, size, address: formatHex(va), interval_ms: input.interval_ms }
      : {
          v: 1,
          kind: "watch",
          method,
          view: input.view,
          size,
          address: formatHex(va),
          registers: [...input.registers],
          modules: legend.map((e) => [...e]),
        };
  const ref = resolved.value.ref;
  const installed = await completeInstall(app, session, op, {
    tool: "watch_memory",
    kind: method === "poll" ? "poll" : "watch",
    agentInstrumentId: result.instrument_id,
    agentStream: result.stream_id,
    encoding: { kind: "json-rows", row_kind: method === "poll" ? "poll/1" : "watch/1" },
    decoders: decoders as JsonObject,
    effect:
      method === "poll"
        ? null
        : {
            kind: "watch-armed",
            target: {
              address: {
                va: ref.va,
                module_map_id: ref.module_map_id,
                module_key: ref.module?.toLowerCase() ?? null,
                rva: ref.rva,
              },
              size,
              threads: "all",
            },
            parameters: {
              method,
              access: input.access,
              size,
              slot: result.slot,
              pages: result.pages === null ? null : [...result.pages],
            },
            display: ref.module === null || ref.rva === null ? ref.va : `${ref.module}+${ref.rva}`,
          },
    durationMs: input.duration_ms,
    maxEvents: input.max_events,
    input: input as unknown as JsonObject,
    target: { ref, size },
    limitations: recordedLimitations(input, armed.value),
    capture,
    result: (ids) => ({
      recording_id: ids.recordingId,
      kind: method === "poll" ? "poll" : "watch",
      method,
      target: ref as unknown as JsonObject,
      size,
      access: input.access,
      slot: result.slot,
      pages: result.pages === null ? null : [...result.pages],
      threads_armed: method === "debug_register" ? result.armed_threads : null,
      arm_errors: result.arm_errors.length,
      verified: result.verified === null ? null : { ...result.verified },
      initial_value: result.initial_value,
      stream_id: ids.streamId,
      effect_id: ids.effectId,
      agent: { instrument_id: result.instrument_id, stream_id: result.stream_id },
    }),
  });
  if (!installed.ok) return installed;
  return ok({ installed: installed.value, armed: armed.value, target: ref, legend });
};

/** func/sym of the summary's writers from the images on disk (summaries are built without I/O). */
const enrichWriters = async (
  app: BeaApplication,
  summary: JsonObject,
  legend: readonly LegendEntry[],
  signal: AbortSignal,
) => {
  const writers = summary["writers"];
  if (!Array.isArray(writers) || legend.length === 0) return summary;
  const locator = new CodeLocator(app.services.pe.images, signal);
  const out = [];
  for (const w of writers) {
    const insn = (w as { insn?: { va?: unknown } }).insn;
    const va = typeof insn?.va === "string" ? BigInt(insn.va) : null;
    const fn = va === null ? null : await locator.functionOf(legend, va).catch(() => null);
    // UX-10: the static VA the description promises (the summary is built without I/O, so it is filled here)
    const staticVa = va === null ? null : await locator.staticOf(legend, va).catch(() => null);
    out.push({
      ...(w as JsonObject),
      insn: {
        ...(insn as JsonObject),
        ...(fn === null ? {} : { func: fn.func, sym: fn.sym }),
        ...(staticVa === null ? {} : { static: staticVa }),
      },
    });
  }
  return { ...summary, writers: out };
};

/** Delivery-time coverage and limitations of an instrument that finished while the call waited (CT-I4, CT-I5). */
const finishedExtras = (view: InstrumentStateView): { coverage: Coverage[]; limitations: string[] } => {
  const coverage: Coverage[] = [];
  const limitations: string[] = [];
  const summary = view.summary;
  if (summary === undefined) return { coverage, limitations };
  const rate = summary["rate_limited"] as Partial<RateLimited> | null | undefined;
  if (rate !== null && rate !== undefined) {
    coverage.push({ status: "partial", truncated: false, reasons: ["watch_rate_limit"] });
    limitations.push(
      rate.cause === "busy"
        ? LIMITATIONS.WATCH_RATE_LIMIT_BUSY(Number(rate.busy_pct ?? 0))
        : LIMITATIONS.WATCH_RATE_LIMIT(Number(rate.limit_per_sec ?? 0)),
    );
  }
  const guard = summary["guard"] as { bea_guard_suspended?: unknown; kernel_rearms?: unknown } | null | undefined;
  const windows = Number(guard?.bea_guard_suspended ?? 0);
  if (windows > 0) {
    coverage.push({ status: "partial", truncated: false, reasons: ["guard_suspended"] });
    limitations.push(LIMITATIONS.WATCH_SUSPEND_WINDOWS(windows));
  }
  // review fix AGENT-3: the agent's final marker counts guards consumed outside a trap (kernel or foreign accesses;
  // since AGENT-2 a VirtualProtect by the target is not counted): the target's system calls on the page failed
  const kernel = Number(guard?.kernel_rearms ?? 0);
  if (kernel > 0) limitations.push(LIMITATIONS.WATCH_KERNEL_ACCESS_SEEN(kernel));
  return { coverage, limitations };
};

export const watchMemory = async (
  app: BeaApplication,
  input: WatchInput,
  ctx: HandlerContext,
): Promise<Result<WatchOutput, BeaError>> => {
  const done = await liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "agent" }, (session, op) =>
    install(app, session, op, input),
  );
  if (!done.ok) return done;
  const { installed, armed, target, legend } = done.value;
  await waitForEnd(app, ctx, installed.recording, input.wait_ms);
  const view = installed.recording.view();
  const summary =
    view.summary !== undefined && armed.method !== "poll"
      ? await enrichWriters(app, view.summary, legend, ctx.signal)
      : view.summary;
  const extras = finishedExtras(view);
  return ok({
    ...envelopeOf(installed.evidence, extras),
    instrument: { ...view, ...(summary === undefined ? {} : { summary }) },
    method: armed.method,
    target,
    slot: armed.method === "debug_register" ? armed.result.slot : null,
    threads_armed: armed.method === "debug_register" ? armed.result.armed_threads : null,
  } as WatchOutput);
};
