import type { EVIDENCE_TOOLS } from "../../contracts/areas/evidence.js";
import type { BeaApplication } from "../BeaApplication.js";
import { exportEvidence } from "../evidence/ExportEvidence.js";
import { getEvidence } from "../evidence/GetEvidence.js";
import { importEvidence } from "../evidence/ImportEvidence.js";
import { recordUnknown } from "../evidence/RecordUnknown.js";
import type { HandlersFor } from "../handlerContext.js";

/** Handlers for area evidence (WP-EVID): thin adapters over src/application/evidence/*. */
export const createEvidenceHandlers = (app: BeaApplication): HandlersFor<typeof EVIDENCE_TOOLS> => ({
  get_evidence: (input) => getEvidence(app.services.evidence, input),
  export_evidence: (input, ctx) => exportEvidence(app, ctx, input),
  import_evidence: (input, ctx) => importEvidence(app, ctx, input),
  record_unknown: (input, ctx) => recordUnknown(app, ctx, input),
});
