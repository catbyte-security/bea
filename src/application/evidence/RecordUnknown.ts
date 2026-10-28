import type { z } from "zod";

import type { recordUnknownInputSchema, EVIDENCE_TOOLS } from "../../contracts/areas/evidence.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { referenceNotFound } from "../../domain/errors/constructors.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { EvId, UnkId } from "../../domain/ids.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { ResidualUnknown } from "../../domain/unknowns/unknown.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { anySessionOp } from "../sessionAccess.js";
import { recordedEnvelope } from "./envelope.js";

type Input = z.output<typeof recordUnknownInputSchema>;
type Output = z.output<(typeof EVIDENCE_TOOLS)[3]["outputSchema"]>;

/** Scope = the session's main image sha256 (live: identity / instance / hash; emulation: the primary module). */
const scopeImage = async (
  app: BeaApplication,
  ctx: HandlerContext,
  sessionId: string | undefined,
): Promise<Result<string | null, BeaError>> => {
  if (sessionId === undefined) return ok(null);
  return anySessionOp(
    app,
    ctx,
    sessionId,
    { mode: "concurrent", need: "host" },
    {
      live: async (session) => {
        const known =
          session.identity.image.sha256 ??
          app.services.evidence.instances.get(session.instanceId)?.image.sha256 ??
          null;
        if (known !== null) return ok(known);
        const hashed = await app.services.evidence.instances.hashImage(session.instanceId, ctx.signal);
        return hashed.ok ? ok(hashed.value) : ok(null);
      },
      emulation: async (handle) => ok(app.services.emulator.modules(handle).find((m) => m.primary)?.sha256 ?? null),
    },
  );
};

/**
 * record_unknown (DESIGN §6.2 #37, S2 §14): create (question) or CAS update (unknown_id + expected_revision). The
 * mutation is recorded as bea.unknown.mutation evidence before the revision line; the envelope is that record's.
 */
export const recordUnknown = async (
  app: BeaApplication,
  ctx: HandlerContext,
  input: Input,
): Promise<Result<Output, BeaError>> => {
  const scope = await scopeImage(app, ctx, input.session_id);
  if (!scope.ok) return scope;
  const evidence = app.services.evidence;
  let head: Partial<ResidualUnknown> = {};
  if (input.unknown_id !== undefined) {
    const read = await evidence.query.complete(input.unknown_id);
    if (!read.ok) return err(referenceNotFound(ctx.operation, "unknown", input.unknown_id));
    head = read.value["value"] as unknown as ResidualUnknown;
  }
  const status = input.status ?? head.status ?? "open";
  const result = await evidence.unknowns.upsert(
    {
      ...(input.unknown_id === undefined ? {} : { unknown_id: input.unknown_id as UnkId }),
      ...(input.expected_revision === undefined ? {} : { expected_revision: input.expected_revision }),
      ...(input.question === undefined ? {} : { question: input.question }),
      domain: input.domain,
      scope_image_sha256: scope.value,
      status,
      severity: input.severity ?? head.severity ?? "medium",
      supporting: (input.supporting ?? head.supporting_evidence_ids ?? []) as EvId[],
      contradicting: (input.contradicting ?? head.contradicting_evidence_ids ?? []) as EvId[],
      probes: input.probes ?? head.recommended_probes ?? [],
      resolution: status === "resolved" ? (input.resolution ?? head.resolution ?? null) : null,
    },
    ctx.operation,
  );
  if (!result.ok) return result;
  const record = await evidence.query.complete(result.value.evidence_id);
  if (!record.ok) return err(record.error);
  return ok({
    unknown_id: result.value.unknown_id,
    revision: result.value.revision,
    status: result.value.status as Output["status"],
    ...recordedEnvelope({ record: record.value["value"] as unknown as BeaEvidence }),
  } as Output);
};
