import type { z } from "zod";

import type { EVIDENCE_TOOLS, importEvidenceInputSchema } from "../../contracts/areas/evidence.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { checkLocalInputPath } from "../localPaths.js";
import { pollEnvelope } from "./envelope.js";

type Output = z.output<(typeof EVIDENCE_TOOLS)[2]["outputSchema"]>;
type Input = z.output<typeof importEvidenceInputSchema>;

/**
 * import_evidence (DESIGN §6.2 #36, S2 §13.4): validate everything (ids, digests, chains, layout, references,
 * conflicts, quota), then merge inside an import bracket unless validate_only. Data only: no target is touched.
 */
export const importEvidence = async (
  app: BeaApplication,
  ctx: HandlerContext,
  input: Input,
): Promise<Result<Output, BeaError>> => {
  // SEC-2: the input-path rule (drive-absolute, never a network location) before any filesystem access
  const local = await checkLocalInputPath(ctx.operation, "path", input.path, app.config.platform);
  if (!local.ok) return local;
  const imported = await app.services.evidence.bundles.import(
    { path: input.path, validate_only: input.validate_only },
    ctx.signal,
  );
  return imported.ok ? ok({ ...imported.value, ...pollEnvelope() } as unknown as Output) : imported;
};
