import type { z } from "zod";

import type { listModulesInputSchema, listModulesOutputSchema } from "../../contracts/areas/inspect.js";
import { INSPECT_CAPS } from "../../contracts/areas/inspect.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { COMPLETE } from "../../domain/evidence/coverage.js";
import { LIMITATIONS } from "../../domain/evidence/limitations.js";
import { pathKey } from "../../domain/process/instance.js";
import { ok, type Result } from "../../domain/result.js";
import type { EmuModuleView, EmuSessionHandle } from "../../ports/emu.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { ModuleInfo } from "../../shared/agentProtocol.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { anySessionOp } from "../sessionAccess.js";
import {
  clip,
  deliver,
  jsonInput,
  jsonResult,
  literalsOf,
  pageOf,
  recordLive,
  sliceOf,
  type InspectCall,
} from "./common.js";

type Input = z.output<typeof listModulesInputSchema>;
type Output = z.output<typeof listModulesOutputSchema>;
type Row = Output["rows"][number];

const SHA256_RE = /^[a-f0-9]{64}$/u;
const hostPlatform = (): "win32" | "linux" => (process.platform === "win32" ? "win32" : "linux");

/** Case-insensitive substring on the module name (S6 §4.8 `filter`). */
export const matchesFilter = (name: string, filter: string | undefined): boolean =>
  filter === undefined || name.toLowerCase().includes(filter.toLowerCase());

/** One live row: preferred base and (fallback) timestamp from the on-disk PE (the loader rewrites ImageBase). */
const liveRow = async (
  app: BeaApplication,
  m: ModuleInfo,
  want: { readonly hash: boolean; readonly mainKey: string; readonly signal: AbortSignal },
): Promise<{ readonly row: Row; readonly hashFailed: boolean }> => {
  const { hash, mainKey, signal } = want;
  const image = m.path.length > 0 ? await app.services.pe.images.open(m.path, signal) : null;
  const pe = image?.ok === true ? image.value : null;
  let sha256: string | null = null;
  let hashFailed = false;
  if (hash) {
    const digest = m.path.length > 0 ? await app.services.pe.hashes.sha256(m.path, signal) : null;
    if (digest?.ok === true && SHA256_RE.test(digest.value)) sha256 = digest.value;
    else hashFailed = true;
  }
  return {
    row: {
      name: clip(m.name, INSPECT_CAPS.moduleName),
      base: m.base,
      size: m.size,
      path: clip(m.path, INSPECT_CAPS.path),
      preferred_base: pe?.image_base ?? null,
      timestamp: m.pe?.time_date_stamp ?? pe?.time_date_stamp ?? null,
      sha256,
      main: m.path.length > 0 && pathKey(m.path, hostPlatform()) === mainKey,
    },
    hashFailed,
  };
};

const live = async (
  { app, ctx, input }: InspectCall & { readonly input: Input },
  session: LiveSession,
  op: OperationContext,
): Promise<Result<Output, BeaError>> => {
  const literals = literalsOf(app);
  if (!literals.ok) return literals;
  const reply = await session.agent.call("listModules", { with_pe: true }, { op });
  if (!reply.ok) return reply;
  const evidence = app.services.evidence;
  // the host mirrors the agent's epoch (never invents one), then anchors the observation on it
  evidence.modules.apply(session.instanceId, {
    op: "snapshot",
    epoch: reply.value.module_map_epoch,
    modules: reply.value.modules.map((m) => ({ name: m.name, base: m.base, size: m.size, path: m.path })),
  });
  const capture = evidence.instances.capture(session.instanceId);
  const filtered = reply.value.modules.filter((m) => matchesFilter(m.name, input.filter));
  const mainKey = pathKey(session.identity.image.path, hostPlatform());
  const built = await Promise.all(
    sliceOf(filtered, input.offset, input.limit).map((m) =>
      liveRow(app, m, { hash: input.hash, mainKey, signal: op.signal }),
    ),
  );
  const limitations: string[] = [LIMITATIONS.AGENT_CLOAKED];
  if (built.some((b) => b.hashFailed)) limitations.push(LIMITATIONS.IMAGE_HASH_UNAVAILABLE);
  const recorded = await recordLive({ app, ctx }, session, capture, {
    predicate: "bea.modules.list",
    input: jsonInput(input),
    result: jsonResult({
      epoch: reply.value.module_map_epoch,
      rows: built.map((b) => b.row),
      page: pageOf(input.offset, input.limit, filtered.length),
    }),
    limitations,
    literals: literals.value,
  });
  if (!recorded.ok) return recorded;
  return ok(deliver(recorded.value) as unknown as Output);
};

const emulationRow = (m: EmuModuleView, hash: boolean): Row => ({
  name: clip(m.name, INSPECT_CAPS.moduleName),
  base: m.base,
  size: m.size,
  path: m.path === null ? null : clip(m.path, INSPECT_CAPS.path),
  preferred_base: m.preferredBase,
  timestamp: null,
  sha256: hash && m.sha256 !== null && SHA256_RE.test(m.sha256) ? m.sha256 : null,
  main: m.primary,
});

/**
 * Emulation sessions answer from the session's cached module table (CI-B5, no bridge round trip). The predicate
 * bea.modules.list is live-only (src/domain/evidence/predicates.ts), so this branch is an unrecorded view of what
 * emu_open already recorded (change request: allow an emulation subject for bea.modules.list).
 */
const emulation = async (
  app: BeaApplication,
  input: Input,
  handle: EmuSessionHandle,
): Promise<Result<Output, BeaError>> => {
  const modules = app.services.emulator.modules(handle).filter((m) => matchesFilter(m.name, input.filter));
  return ok({
    epoch: handle.generation,
    rows: sliceOf(modules, input.offset, input.limit).map((m) => emulationRow(m, input.hash)),
    page: pageOf(input.offset, input.limit, modules.length),
    evidence_id: null,
    predicate_type: null,
    confidence: null,
    authority: null,
    coverage: COMPLETE,
    limitations: [LIMITATIONS.EMU_MODULES_UNRECORDED, LIMITATIONS.NOT_REAL_PROCESS],
  });
};

export const listModules = (
  app: BeaApplication,
  input: Input,
  ctx: HandlerContext,
): Promise<Result<Output, BeaError>> =>
  anySessionOp(
    app,
    ctx,
    input.session_id,
    { mode: "exclusive", need: "agent" },
    {
      live: (session, op) => live({ app, ctx, input }, session, op),
      emulation: (handle) => emulation(app, input, handle),
    },
  );
