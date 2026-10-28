import type { z } from "zod";

import {
  GPRS,
  INSPECT_CAPS,
  type listThreadsInputSchema,
  type listThreadsOutputSchema,
} from "../../contracts/areas/inspect.js";
import type { Loc } from "../../domain/address/addressRef.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { ok, type Result } from "../../domain/result.js";
import type { AddressSpace } from "../../ports/address.js";
import type { ProcessInfo, ThreadInfo } from "../../shared/agentProtocol.js";
import { MASK64, type Hex } from "../../shared/hex.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";
import { clip, deliver, jsonInput, jsonResult, literalsOf, pageOf, recordLive, sliceOf } from "./common.js";

type Input = z.output<typeof listThreadsInputSchema>;
type Output = z.output<typeof listThreadsOutputSchema>;
type Row = Output["rows"][number];

/**
 * The main thread is the one whose start routine is the main module's entry point (Windows reports the image entry
 * as the main thread's Win32 start address; [ext-frida §3.13]: main = mainCRTStartup). Null when unknown.
 */
export const mainEntryOf = (info: ProcessInfo): bigint | null => {
  const entry = info.main_module.pe?.entry_rva;
  return entry === undefined ? null : (BigInt(info.main_module.base) + BigInt(entry)) & MASK64;
};

/** GPRs of a thread context, lowercase names only (QJS context objects need explicit names; S4 §8.5). */
export const gprsOf = (regs: Readonly<Record<string, Hex>> | null): Partial<Record<(typeof GPRS)[number], Hex>> => {
  const out: Partial<Record<(typeof GPRS)[number], Hex>> = {};
  if (regs === null) return out;
  for (const name of GPRS) {
    const value = regs[name] ?? regs[name.toUpperCase()];
    if (value !== undefined) out[name] = value;
  }
  return out;
};

const clipLoc = (loc: Loc): Loc => ({
  va: loc.va,
  at: loc.at === null ? null : clip(loc.at, INSPECT_CAPS.ref),
  static: loc.static === null ? null : clip(loc.static, INSPECT_CAPS.ref),
  func: loc.func === null ? null : clip(loc.func, INSPECT_CAPS.ref),
  sym: loc.sym === null ? null : clip(loc.sym, INSPECT_CAPS.ref),
});

export const listThreads = (
  app: BeaApplication,
  input: Input,
  ctx: HandlerContext,
): Promise<Result<Output, BeaError>> =>
  liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "agent" }, async (session, op) => {
    const literals = literalsOf(app);
    if (!literals.ok) return literals;
    // names: the agent reads each thread's GetThreadDescription (Chrome names CrGpuMain, VizCompositorThread, ...)
    const listed = await session.agent.call(
      "listThreads",
      { registers: input.registers ? "gpr" : "none", teb: false, names: true },
      { op },
    );
    if (!listed.ok) return listed;
    const capture = app.services.evidence.instances.capture(session.instanceId);
    const info = await session.agent.call("processInfo", {}, { op });
    if (!info.ok) return info;
    const mainEntry = mainEntryOf(info.value);
    const threads: ThreadInfo[] = listed.value.threads.filter((t) => t.bea_role === null);
    const page = sliceOf(threads, input.offset, input.limit);
    const space: AddressSpace = { kind: "live", session };
    const entries = page.flatMap((t) => (t.entry === null ? [] : [BigInt(t.entry)]));
    await app.services.address.prepare(space, entries, op);
    const rows: Row[] = [];
    for (const t of page) {
      const entry = t.entry === null ? null : clipLoc(await app.services.address.describeCode(space, BigInt(t.entry)));
      rows.push({
        tid: t.id,
        name: t.name === null || t.name === "" ? null : clip(t.name, INSPECT_CAPS.threadName),
        main: mainEntry !== null && t.entry !== null && BigInt(t.entry) === mainEntry,
        entry,
        ...(input.registers ? { registers: gprsOf(t.regs) } : {}),
      });
    }
    const limitations: string[] = [LIMITATIONS.AGENT_THREADS_CLOAKED];
    if (mainEntry === null || !threads.some((t) => t.entry !== null && BigInt(t.entry) === mainEntry))
      limitations.push(LIMITATIONS.MAIN_THREAD_UNKNOWN);
    const recorded = await recordLive({ app, ctx }, session, capture, {
      predicate: "bea.threads.list",
      input: jsonInput(input),
      result: jsonResult({ rows, page: pageOf(input.offset, input.limit, threads.length) }),
      limitations,
      literals: literals.value,
    });
    if (!recorded.ok) return recorded;
    return ok(deliver(recorded.value) as unknown as Output);
  });
