import { ledgerLineEnvelopeSchema as envelopeSchema } from "../../application/evidence/storeSchemas.js";
import { canonicalJson } from "../../domain/canonical.js";
import type { Effect, EffectTransition } from "../../domain/effects/effect.js";
import type { BeaErrorOf } from "../../domain/errors/beaError.js";
import {
  authenticateEffect,
  authenticateEvidence,
  authenticateTransition,
  evidenceIntegrity,
} from "../../domain/evidence/authenticate.js";
import type { BeaEvidence } from "../../domain/evidence/record.js";
import type { PiId, RunId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import { instanceIdOf, moduleMapIdOf, type ModuleMap, type ProcessIdentity } from "../../domain/process/instance.js";
import { err, ok, type Result } from "../../domain/result.js";
import { residualUnknownSchema, revisionDigestOf, type ResidualUnknown } from "../../domain/unknowns/unknown.js";

/**
 * Ledger lines (S2 §9.3): each line is canonicalJson(line) + "\n", at most 4 MiB. Reading a line authenticates every
 * self-identifying payload (pi/mm/fx/ev ids, unk revision digests). Display strings sit outside identities.
 */
export const MAX_LINE_BYTES = 4 * 1024 * 1024;

export interface PiLine {
  readonly t: "pi";
  readonly instance_id: PiId;
  readonly identity: ProcessIdentity;
  readonly ownership: "owned" | "attached";
  /** display only (redactable); excluded from the instance id */
  readonly display: { readonly image_name: string | null };
}
export interface ImportCounts {
  readonly instances: number;
  readonly module_maps: number;
  readonly effects: number;
  readonly effect_transitions: number;
  readonly unknown_revisions: number;
  readonly evidence: number;
}
export type LedgerLine =
  | { readonly t: "run"; readonly run_id: RunId; readonly bea_version: string; readonly started_wall: string }
  | PiLine
  | { readonly t: "mm"; readonly module_map: ModuleMap }
  | { readonly t: "fx"; readonly effect: Effect }
  | { readonly t: "fxt"; readonly transition: EffectTransition }
  | { readonly t: "ev"; readonly record: BeaEvidence }
  | { readonly t: "unk"; readonly revision: ResidualUnknown }
  | {
      readonly t: "import-begin";
      readonly import_id: string;
      readonly bundle_digest: string;
      readonly source_runs: readonly RunId[];
    }
  | { readonly t: "import-commit"; readonly import_id: string; readonly counts: ImportCounts }
  | { readonly t: "end"; readonly ended_wall: string; readonly counts: JsonObject };

export const encodeLine = (line: LedgerLine): string => `${canonicalJson(line as unknown as JsonValue)}\n`;

type Integrity = BeaErrorOf<"EvidenceIntegrity">;

/** Parse + authenticate one line (without its trailing newline). */
export const decodeLine = (text: string, operation = "ledger.read"): Result<LedgerLine, Integrity> => {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return err(evidenceIntegrity(operation, "non-canonical", { detail: "line is not JSON" }));
  }
  const parsed = envelopeSchema.safeParse(raw);
  if (!parsed.success) return err(evidenceIntegrity(operation, "schema", { detail: "unknown or malformed line" }));
  const line = parsed.data;
  switch (line.t) {
    case "pi":
      return instanceIdOf(line.identity as ProcessIdentity) === line.instance_id
        ? ok(line as PiLine)
        : err(evidenceIntegrity(operation, "id-mismatch", { instance_id: line.instance_id }));
    case "mm": {
      const { module_map_id, ...rest } = line.module_map;
      return moduleMapIdOf(rest as Omit<ModuleMap, "module_map_id">) === module_map_id
        ? ok({ t: "mm", module_map: line.module_map as ModuleMap })
        : err(evidenceIntegrity(operation, "id-mismatch", { module_map_id }));
    }
    case "fx": {
      const effect = authenticateEffect(line.effect, operation);
      return effect.ok ? ok({ t: "fx", effect: effect.value }) : effect;
    }
    case "fxt": {
      const transition = authenticateTransition(line.transition, operation);
      return transition.ok ? ok({ t: "fxt", transition: transition.value }) : transition;
    }
    case "ev": {
      const record = authenticateEvidence(line.record, operation);
      return record.ok ? ok({ t: "ev", record: record.value }) : record;
    }
    case "unk": {
      const revision = residualUnknownSchema.safeParse(line.revision);
      if (!revision.success) return err(evidenceIntegrity(operation, "schema", { detail: "unknown revision" }));
      return revisionDigestOf(revision.data) === revision.data.revision_digest
        ? ok({ t: "unk", revision: revision.data })
        : err(evidenceIntegrity(operation, "id-mismatch", { unknown_id: revision.data.unknown_id }));
    }
    default:
      return ok(line as LedgerLine);
  }
};

/** Bundle rule: a line must be byte-identical to its canonical re-serialization. */
export const isCanonicalLine = (text: string): boolean => {
  try {
    return canonicalJson(JSON.parse(text) as JsonValue) === text;
  } catch {
    return false;
  }
};
