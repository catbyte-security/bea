# REA Evidence model and error algebra, plus a proposed BEA Evidence/error model

Key: `rea-evidence`. REA clone: `<rea-checkout>` (read-only; nothing was edited, built or tested there).
Lab: `<scratch>/bea-lab/rea-evidence/`

Legend: **VERIFIED-READ** = I read the code at that path:line. **VERIFIED-RUN** = I ran it. **BELIEVED** = from docs or memory, not checked in code.

---

## 0. TL;DR

* REA has one Evidence envelope for every successful observation. Its ID is `ev_` + SHA-256 of an RFC 8785 canonical-JSON *semantic projection* of the record, so the ID is a content address. The projection leaves out the display path and name of the subject, so the same bytes at another path get the same ID. Every parse re-checks the ID (`parseEvidence` → `authenticatedEvidenceSchema`). A tampered record is rejected.
* Epistemic status is spread over several fields: `confidence` (`observed|derived|inferred`), `authority` (the kind of source: `shipped-artifact|controlled-replay|historical-reference|external-service|analyst-inference`), free-text `limitations[]`, a structured `relationship_coverage` (`complete|partial|unknown`), producer-specific coverage inside `normalized_result`, and a separate **ResidualUnknown** registry. That registry is an append-only revision chain of questions, linked to Evidence that supports, contradicts or mutates them.
* Evidence lives in a per-connection in-memory `EvidenceLedger` (Map by ID, idempotent, rejects conflicting records, imports are atomic, it is cleared by `close_binary`, and it has **no byte or record quota**). It is exported as a canonical *bundle* (sorted records + derived manifests + unknown revisions) and published atomically to disk. Snapshots are a separate replay cache keyed by `query_` digests.
* Tool success = the **complete Evidence record** in both `content[0].text` and `structuredContent`, plus an `evidence_reference` when it was retained. Tool failure = `isError: true` with a text-only `{error: AnalysisErrorProjection}`. The projection has a closed `code` (20 values), a `category` (10 values), `message`, `retryable`, `remediation.action`, an optional machine `recovery` and free `details`. Partial observations and cleanup uncertainty are carried inside the error.
* `Result<T,E>` is a 3-line discriminated union (`{ok:true,value}|{ok:false,error}`). Errors are **classes** that extend `AnalysisError extends Error`, each with a literal `readonly _tag`. A closed list of 27 tags is checked when errors are projected.
* Sensitive values are opt-in and explicit only. Callers declare literal `sensitive_values`. REA never guesses from names. The declarations are never persisted (only their count is), whole fields become `null` instead of carrying a marker, and errors are rebuilt with redacted text.
* For BEA: keep the content-addressed envelope, the observed/derived/inferred split, limitations, coverage, unknowns, tagged Result errors, the error-projection wire shape, and explicit-literal redaction. **Change**:
  1. The subject is a *process instance* plus a *module-map epoch*, not a file digest.
  2. Add a time and sequence anchor.
  3. Add first-class **Effect** records and a per-instance `perturbation` set.
  4. High-volume hook events go to on-disk hash-chained chunk files. A **stream-manifest Evidence** points at them; events are not inline Evidence.
  5. The ledger is append-only on disk with quotas.
  6. Replay snapshots apply only to deterministic lanes (emulation, static).

---

## 1. Files read (VERIFIED-READ)

| Concern | File |
|---|---|
| Result type | `src/domain/result.ts:1-10` |
| Evidence envelope + ID | `src/domain/evidence.ts` (478 lines) |
| Evidence bundle | `src/domain/evidenceBundle.ts` (590) |
| Evidence ref (retained-evidence) | `src/domain/evidenceReference.ts` (17) |
| Bundle summary/filters | `src/domain/evidenceRecordSummary.ts` (166) |
| Evidence errors | `src/domain/evidenceErrors.ts` (80) |
| Completion ledger (claims) | `src/domain/evidenceCompletionLedger.ts` (151) |
| Digests | `src/domain/digests.ts`, `src/domain/canonicalDigest.ts` |
| Immutable JSON sealing | `src/domain/immutableJson.ts` (282) |
| Error base / tags | `src/domain/analysisErrorBase.ts` (291) |
| Core error classes + partial-observation union | `src/domain/analysisErrorCore.ts` (258) |
| Error projection (wire) | `src/domain/analysisErrorProjection.ts` (660) |
| Error presentation (messages/remediation) | `src/domain/analysisErrorPresentation.ts` (535) |
| Recovery hints | `src/domain/analysisErrorRecovery.ts` |
| Cleanup composition | `src/domain/analysisErrorCleanup.ts` |
| Redaction | `src/domain/explicitSensitiveValues.ts`, `src/domain/explicitSensitiveFailure.ts` |
| Partial observations | `src/domain/artifactPartialObservation.ts` |
| Frida session status | `src/domain/fridaSessionStatus.ts` |
| Command observation | `src/domain/commandObservation.ts` |
| Analysis profile | `src/domain/analysisProfile.ts` |
| Relationship coverage | `src/domain/relationshipCoverage.ts` |
| Residual unknowns | `src/domain/residualUnknown.ts` (405) |
| Snapshots | `src/domain/analysisSnapshot.ts` (904) |
| Ledger | `src/application/investigation/EvidenceLedger.ts` (497) |
| Unknown mutation Evidence | `src/application/investigation/UnknownEvidence.ts`, `WorkflowUnknown.ts` |
| Ports | `src/application/investigation/InvestigationRecordPort.ts` |
| get_evidence_bundle core | `src/application/investigation/InspectEvidenceBundle.ts` |
| Bundle file IO | `src/application/EvidenceBundleFiles.ts`, `src/application/EvidenceBundleCommands.ts` |
| MCP delivery | `src/server/ToolResultDelivery.ts` (250) |
| Generic evidence tool registration | `src/server/registerEvidenceTools.ts` |
| Evidence closure / workflow unknowns | `src/server/registerInvestigationTools/helpers.ts`, `src/server/recordDerivedEvidence.ts` |
| Static-runtime correlation tool | `src/server/registerInvestigationTools.ts:197-273` |
| Frida Evidence | `src/application/frida/FridaInstrumentationService.ts:450-488`, `src/frida/fridaCaptureLimits.ts` |
| Process capture Evidence | `src/application/process/ProcessEvidence.ts` |
| Tool effects | `src/contracts/toolEffects.ts` |
| CLI envelope | `src/cli/cliResultOutput.ts:150-160, 329, 345-351` |
| Docs | `docs/mcp-contracts.md` §Tool results (14-300), §Retained Evidence inputs (302-490), §Request scope (762-812); `docs/cli.md` §Snapshots (237-275), §Import/export (276-298), §Output and exit status (473+); `docs/web-network-captures.md:262-295`; `docs/error-contract.schema.json`; `docs/user-visible-errors.csv` (117 rows) |

---

## 2. `Result<T, E>` and tagged errors

### 2.1 Result (VERIFIED-READ `src/domain/result.ts:1-10`)

```ts
/** A typed channel for expected success or failure. */
export type Result<T, E> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };
export const ok  = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
```

There are no `map`/`flatMap` helpers. Callers branch with `if (!r.ok) return r;`. That works because `Result<never,E>` is assignable to `Result<U,E>`. Exceptions are kept for programmer errors and schema failures inside domain code (`TypeError`, `ZodError`). Application boundaries catch those and wrap them in tagged errors. For example `EvidenceLedger.record` catches the parse failure and returns `err(new EvidenceIntegrityError("Evidence record validation failed", { cause }))` (`EvidenceLedger.ts:49-73`).

### 2.2 Tagged error base (VERIFIED-READ `src/domain/analysisErrorBase.ts`)

* `ANALYSIS_ERROR_TAGS` (line 4) is a closed tuple of 27 tags: `AnalysisProtocolError, AnalysisInputError, AnalysisAccessDeniedError, AnalysisArtifactChangedError, AnalysisOutputError, AnalysisCapabilityUnavailableError, AnalysisUnsupportedTargetError, AnalysisCancelledError, AnalysisTimeoutError, AnalysisResourceConstraintError, ProviderSelectionError, ProviderAdapterError, BrowserObservationError, ArtifactOperationError, ProcessCaptureError, EvidenceIntegrityError, EvidenceFileError, UnknownRegistryError, Hopper{Timeout,Cancelled,Protocol,Remote,Process,Start}Error, ConfigurationError, NoBinaryOpenError, BinaryTargetError`.
* `abstract class AnalysisError extends Error` (line 71):
  * `abstract readonly _tag: AnalysisErrorTag`
  * `userMessage?: string`, `userCategory?: "cancelled"`, `executionFailure?: string`
  * `diagnostics?: Record<string, JsonValue>`: producer-owned facts that are safe to show the caller. They are `structuredClone`d.
  * `capturedOutput?: { stdout, stderr, truncated, stdout_bytes?, stderr_bytes?, exit_code?, signal? }` (line 38)
  * `cleanup?: { reason, resources[] }` and `cleanupIncomplete: boolean`. There is a live graph of cleanup dependencies held through WeakRefs: `bindCleanupDependencies`, `resolveCleanup`, `cleanupResources` getter.
  * `cleanupPrimary?: AnalysisError`. When a cleanup failure wraps the original failure, the original stays here. `resolvedAnalysisError()` (line 211) unwraps it once cleanup is confirmed.
  * `secondaryFailures`: later failures kept without replacing the primary (`retainSecondaryFailure`).
  * `partialObservation?: AnalysisPartialObservation`: facts completed before the failure (`retainPartialObservation` keeps the first one: `??=`).
  * `cleanupReport` (process capture).
* Subclasses add their own typed fields. The pattern, from `analysisErrorCore.ts`:

```ts
export class AnalysisTimeoutError extends AnalysisError {
  readonly _tag = "AnalysisTimeoutError";
  override readonly userMessage: string | undefined;
  readonly remediationAction: string | undefined;
  constructor(readonly operation: string, readonly timeoutMs: number,
              options?: AnalysisErrorOptions & { userMessage?: string; remediationAction?: string }) {
    super(`Analysis operation timed out after ${String(timeoutMs)}ms: ${operation}`, options);
    this.userMessage = options?.userMessage;
    this.remediationAction = options?.remediationAction;
  }
}
```

* `AnalysisInputError(operation, options, issues: AnalysisInputIssue[])`. Each issue is `{ path, reason: unknown_argument|missing_argument|invalid_type|out_of_range|invalid_value|invalid_format, message?, expected?, minimum?, maximum? }`. The issues are secret-safe.
* `AnalysisResourceConstraintError(operation, resource: memory|cpu|file-size|transport|capacity, reason, reportedLimits, { remediationAction | fixedAllowance, retryable? })`. `transport` means the MCP frame overflowed.
* `AnalysisCapabilityUnavailableError(providerId, operation, reason, {retryable})`. `retryable` is forced to false while cleanup is incomplete.
* Evidence errors (`evidenceErrors.ts`):
  * `EvidenceIntegrityError` (has `userMessage`)
  * `AnalysisSnapshotMismatchError extends EvidenceIntegrityError`
  * `EvidenceReferenceError(evidenceId, reason: missing|wrong_operation|wrong_predicate|identity_mismatch, expected, actual)`
  * `EvidenceFileError(operation: read|write, reason: not-file|exists|wrong-kind|invalid-json|missing|io, {path, published?, contentIssues?})`. `published` is the receipt when the write committed but staging cleanup failed.
* `UnknownRegistryError(reason: not-found|already-exists|revision-conflict|invalid-transition|integrity|limit)`.
* Note: bundle-domain helpers also throw plain `TypeError` subclasses (`NonCanonicalEvidenceBundleError`, `DuplicateEvidenceRecordError`, `evidenceBundle.ts:57-70`). The application layer re-wraps them.

`AnalysisPartialObservation` (`analysisErrorCore.ts` top) is a union of about 30 typed partial shapes, `Evidence` among them. Example: `ArtifactInventoryPartialObservation { kind: "artifact-inventory", inventory }`.

### 2.3 Projection to the wire (VERIFIED-READ `analysisErrorProjection.ts`)

`projectAnalysisError(error): AnalysisErrorProjection` (line 52) is the **only** path from errors to the wire:

```ts
interface AnalysisErrorProjection {
  code: "invalid_request"|"access_denied"|"artifact_changed"|"unreadable_output"|"capability_unavailable"
      | "unsupported_target"|"provider_unavailable"|"provider_timeout"|"resource_constraint"|"cancelled"
      | "artifact_integrity_mismatch"|"artifact_operation_failed"|"evidence_integrity_mismatch"|"truncated"
      | "process_capture_failed"|"cleanup_incomplete"|"revision_conflict"|"configuration_invalid"
      | "target_unavailable"|"execution_failure";                    // 20 codes
  category: "invalid_input"|"unsupported_provider"|"unsupported_target"|"integrity_mismatch"|"truncated"
          | "cancelled"|"timeout"|"resource_constraint"|"unavailable"|"execution_failure";  // 10
  message: string;            // analysisErrorUserMessage(): curated, never raw provider text by default
  retryable: boolean;
  remediation: { action: string };   // analysisErrorRemediationAction()
  recovery?: { kind:"inspect_input_contract"; operation } | { kind:"inspect_timeout_state"; operation; timeout_ms };
  details?: Record<string, JsonValue>;
}
```

Rules (lines 61-130, 610-616):
* `code = cleanupIncomplete ? "cleanup_incomplete" : underlyingCode`. Unresolved cleanup **overrides** the code, and `details.execution_failure` keeps the underlying code.
* The tag-to-code mapping is a `STATIC_ERROR_CODES` table checked with `satisfies Record<Exclude<Tag, Specialized>, Code>` (line 252). Specialized tags compute the code from their `reason`. `staticErrorCode` throws on a specialized tag that fell through. The result is exhaustiveness at compile time and at run time.
* `RETRYABLE_CODES = {artifact_changed, provider_timeout, cancelled, revision_conflict, provider_unavailable}`. Also retryable: capability-unavailable with `retryable`, and resource_constraint with `retryable ?? resource==="capacity"`.
* `details` merges type-specific fields (`requestErrorDetails`, `artifactStateErrorDetails`, `providerErrorDetails`, `lifecycleErrorDetails`), `diagnostics`, `cleanup_history`, cleanup state (`cleanup:"incomplete", resources[], cleanup_reason`), `captured_output` and `partial_observation`. A partial observation is embedded *inline* (JSON-parsed), or as a `{kind:"retained-evidence", evidence_id}` ref via `toRecordedPartialErrorToolResult`.
* `docs/error-contract.schema.json` is a published JSON Schema `oneOf` per code. `docs/user-visible-errors.csv` is a 117-row audit of user-facing copy (harm rank, location, trigger, current copy, proposed replacement, status).

### 2.4 Presentation (VERIFIED-READ `analysisErrorPresentation.ts`)

* `analysisErrorUserMessage` prefers `error.userMessage`, then type-specific curated text, then the generic "Analysis could not complete. Run `rea doctor`, then try again." The design intent (from the CSV) is not to leak provider internals in `message`. Details carry the specifics.
* `analysisErrorRemediationAction` gives a concrete *next action*, for example "Correct the listed fields, then retry. Do not repeat the unchanged call." Transport overflow gets fixed constants: `MCP_TRANSPORT_EVIDENCE_DISCOVERY` says to use `get_evidence_bundle detail:summary` → `inspect_analysis_view` → `export_evidence_bundle`.
* Cleanup composition (`analysisErrorCleanup.ts`): `analysisErrorWithCleanupFailure(primary, cleanup)` → `ProviderAdapterError` with `cleanupPrimary: primary`, `cause: AggregateError([primary, cleanup])`, `userMessage` from the primary, remediation from the cleanup, and `diagnostics: {primary_error, cleanup_error}` (both projected).

### 2.5 Delivery (VERIFIED-READ `src/server/ToolResultDelivery.ts`)

* `toCallToolResult(result, contract)`: ok → `successResult` (session tools wrap as `{result}`); err → `toErrorToolResult`.
* `toEvidenceToolResult(evidence, contract, recorded)` (line 110). If the ledger write failed, the result is that error. Otherwise the result is a success with the Evidence as **both** `structuredContent` and JSON text. Recovery metadata `{ evidence_id, evidence_reference: {kind:"retained-evidence", evidence_id}, ...nativeContinuation }` is used only when the response overflows.
* Errors: `{ content:[{type:"text", text: JSON({error: projection})}], structuredContent: {error} /* stripped by transport */, isError:true, _meta? }`. The docs say failures omit `structuredContent` on the wire (`mcp-contracts.md` ~line 100).
* Response budget: 10 MiB stdio default minus 1024 bytes. If the payload is bigger, the tool returns `resource_constraint` with `details.resource:"transport"`, `reported_limits.{evidence_reference, continuation, response_bytes_at_least, …}` and a next step. Evidence stays complete in the session. A ready-to-call `inspect_analysis_view` continuation is attached for big function dossiers.
* Untrusted content marker: `_meta: { provenance: { untrusted_content: true, source: "analysis_target" } }` on every result (success **and** error) of tools whose `returnsTargetContent` is set. It is on by default. Only `export_evidence_bundle` and `record_unknown` are exempt (`mcp-contracts.md` §Untrusted target content).

### 2.6 CLI (VERIFIED-READ partial, `cliResultOutput.ts`, `docs/cli.md:473+`)

* Success prints the data. Failure prints the projection. `--full-output` prints the envelope `{ ok:false, error, meta:{command,duration} }`. Default format TOON, `--json` for JSON.
* Exit codes: `0` completed (may include partial evidence and unknowns), `1` could not complete, `128+N` signal (`130` SIGINT, `143` SIGTERM), `141` SIGPIPE.
* Commands with `--evidence_output` publish the bundle atomically before delivering. If cancellation loses the race to publication, the result keeps `details.diagnostics.evidence_bundle {path, bytes}`.

---

## 3. The Evidence record

### 3.1 Schema (VERIFIED-READ `src/domain/evidence.ts:132-151`)

```ts
const evidenceBaseSchema = z.object({
  evidence_id:        prefixedDigestSchema("ev"),           // ev_<64 hex>
  subject:            subjectSchema.nullable(),             // artifact identity or null
  provider:           { id, name, version: string|null },
  analysis_profile:   analysisProfileSchema.nullable(),     // {provider, parameters, digest}
  predicate_type:     z.string().min(1),                    // e.g. "rea.analysis", "rea.process-capture"
  operation:          z.string().min(1),                    // tool name, e.g. "analyze_function"
  parameters:         jsonObjectSchema,                     // caller args (identity-relevant only)
  raw_result:         jsonValueSchema.nullable(),           // provider-native representation, if distinct
  normalized_result:  jsonValueSchema,                      // the operation result (typed per operation)
  confidence:         z.enum(["observed","derived","inferred"]),
  authority:          evidenceAuthoritySchema,              // see below
  environment:        { id, platform, architecture, isolation: none|process|container|virtual-machine } | null,
  limitations:        z.array(z.string()),
  relationship_coverage: relationshipCoverageSchema.nullable(),
  locations:          z.array(evidenceLocationSchema),
  evidence_links:     z.array(prefixedDigestSchema("ev")),  // provenance edges to other Evidence
}).strict();
```

* `subject` (`evidence.ts:76-95`): `{ name, digest:{sha256}, local_path, format (≈30 formats: pe, elf, mach-o, raw-binary, zip, apk, …), architecture|null }`. The format decides which architectures are legal: raw-only architectures are allowed only for `raw-binary`.
* `authority` (`evidence.ts:117`): `shipped-artifact | controlled-replay | historical-reference | external-service | analyst-inference`. This is the **source class**, separate from `confidence`. Other strings like `packaged-process` that turn up in a grep belong to other, nested schemas, not the Evidence envelope.
* `locations` (`evidence.ts:97`): `address{address:string} | address-range{start,end} | artifact-path{path} | file-offset{offset} | file-offset-range{start,end}`. Addresses are strings, so canonical hex survives JSON.
* `analysis_profile` (`analysisProfile.ts`): `{ provider:{id,name,version}, parameters, digest }`, where `digest = sha256(canonical({provider, parameters}))`. It records every setting that affects analysis semantics. Its provider must equal the Evidence provider (`validateAnalysisProfileProvider`).
* `relationship_coverage` (`relationshipCoverage.ts`): `{status:"complete", diagnostics?} | {status:"partial", limitations[≥1], limited_directions?} | {status:"unknown", reason, limited_directions?}`. `limited_directions` is `["callers"]`, `["callees"]` or both. `relationshipCoverageLimitations(null)` → `["Provider did not report relationship coverage."]`. An absent report is treated as unknown, never as complete.
* `Evidence<Result extends JsonValue>` is the generic type, so each producer gets a typed `normalized_result`.

### 3.2 ID generation (VERIFIED-READ `evidence.ts:256-284`, `canonicalDigest.ts`)

```ts
const semanticProjection = (e) => ({
  subject: e.subject === null ? null : { digest: e.subject.digest, format: e.subject.format, architecture: e.subject.architecture },
  provider, analysis_profile, predicate_type, operation, parameters, raw_result, normalized_result,
  confidence, authority, environment, limitations, relationship_coverage, locations, evidence_links,
});
const computeEvidenceId = (e) => `ev_${digestCanonicalValue(semanticProjection(e), "Evidence")}`;
```

* `digestCanonicalValue` (`canonicalDigest.ts`) streams SHA-256 over RFC 8785 canonical JSON. Keys are sorted by UTF-16 code units, `undefined`/symbol keys are dropped, NaN/Infinity throw, and cycles throw. It batches 8 KiB writes.
* **Excluded from identity:** `subject.name` and `subject.local_path`. Rebinding a path (`rebindEvidenceToTargetPath`, line 304) keeps the ID. `EvidenceLedger.recordsAgree` compares canonical JSON with name and path masked (`EvidenceLedger.ts:483-497`).
* **Included:** everything else, including `raw_result`, `limitations` and `evidence_links`. So a different limitation string gives a different ID.
* Determinism has a consequence: two identical observations give the **same ID**, and the ledger treats the second as a `"duplicate"`. That is right for static facts. For dynamic facts it would merge two separate observations at different times. **This is the biggest semantic mismatch for BEA (see §9.2).**
* Other ID families in REA, all `<prefix>_<sha256>` and checked by `prefixedDigestSchema(prefix)` (`digests.ts`): `ev_` Evidence, `unk_` unknowns (digest of `{domain, normalized question, scope_digest[, comparison scope]}`), `query_` snapshot entries (digest of `{target, binding, operation, parameters}`), `ecl_` completion ledgers. A prefix makes an ID pasted from the wrong family fail validation.

### 3.3 Construction defaults (VERIFIED-READ `evidence.ts:356-478`)

`createEvidence(target | undefined, provider, observation, {immutable?})`:
* `predicate_type ?? "rea.analysis"`, `confidence ?? "observed"`, `authority ?? "shipped-artifact"`, `environment ?? null`, `raw_result ?? null`, `relationship_coverage ?? null`.
* If `target === undefined`, it **prepends a limitation**: `observation.subjectUnavailableReason ?? "Artifact identity is unavailable for this observation."`. A missing identity is always stated explicitly, and it is part of the ID.
* The record is parsed through zod with a placeholder ID (`ev_000…`), and then the real ID is computed over the parsed snapshot. This copies caller-owned mutable payloads before hashing.
* Immutability: `freezeOwnedJsonTreeSnapshot` + `WeakMap immutableEvidenceSnapshots`. A sealed record can be borrowed without re-authenticating or copying, which matters for 300 MB records. `createImmutableEvidenceSteps` is a generator that yields during validation and hashing so huge payloads do not block the event loop. This is cooperative scheduling.
* `parseEvidence(input)` authenticates (recomputes the ID) unless the object is a sealed snapshot it already knows. `immutableEvidence(input)` parses and then seals.

### 3.4 Concrete runtime Evidence producers in REA today (VERIFIED-READ)

* **Frida** (`FridaInstrumentationService.ts:450-488`):
  `createEvidence(undefined, {id:"frida",name:"Frida",version:null}, { predicateType:"rea.frida.instrumentation-observation", operation, parameters, result: {session_id, device_id, state, target, pid, mode, scripts[], messages[], messages_truncated, source_kind, source_path, source_sha256, cleanup_error}, rawResult?: {source_representation}, confidence:"observed", authority:"external-service", environment:null, limitations:["The target operating system and architecture were not reported by this observation.", ...fridaCaptureLimitations(result), …] })`.
  It has **no subject** (no image digest), no process start time and no module map. The messages are caller-defined opaque payloads (`fridaSessionStatus.ts`: `messages: z.array(z.unknown())`). Capture caps (`fridaCaptureLimits.ts`): 16 MiB per session, 32 KiB text fields, 250k JSON nodes, depth 64. Each cap that is hit becomes a fixed limitation sentence ending "This release has no runtime override." Truncation flags are read only from REA-owned fields, never from caller payloads (`collectOwnedCaps`).
* **Process capture** (`ProcessEvidence.ts`): `authority:"controlled-replay"`, `environment: {id:`${platform}-${arch}`, platform, architecture, isolation:"process"}`. Parameters are *secret-free by construction*: `executable_name` basename, `argument_count`, `event_count`, `filesystem_observation_path_count` and `normalization`. The arguments and environment values are **not** stored, only counts. `parseProcessCaptureEvidence` returns a `Result` with a *data* failure union (`invalid-evidence | wrong-workflow | unsupported-provider | invalid-capture`), not an error class. Domain-level failures are plain data, and adapters map them to errors.
* **Command observation** (`commandObservation.ts`): `{stdout, stderr, exit_code, signal, output_truncated, completion_status: complete|unknown, artifact_sha256_after, artifact_changed: boolean|null}`. **After a foreign command runs, the artifact is re-hashed and any mutation is reported.** This is the closest thing REA has to recording effects.
* **Static-runtime correlation** (`registerInvestigationTools.ts:197-273`): it takes caller-declared static and runtime comparison Evidence, computes an `evidenceClosure` (a transitive walk over `evidence_links` that fails on a dangling link), and emits `confidence:"inferred"`, `authority:"analyst-inference"`, `evidenceLinks: closure`. If the status is `unknown|truncated`, it also auto-records a residual unknown with recommended probes.

### 3.5 Observed / derived / inferred / unknown

| Layer | Where | Meaning |
|---|---|---|
| `confidence: "observed"` | envelope | Direct provider or runtime observation |
| `confidence: "derived"` | envelope | Deterministic computation over other Evidence (views, summaries, comparisons). Links to its parents in `evidence_links` |
| `confidence: "inferred"` | envelope | Heuristic or analyst interpretation (path templates, correlation hypotheses) |
| `authority` | envelope | Source class, ordered by trust in the resolution checks |
| `limitations[]` | envelope | Free text, part of identity |
| coverage | `relationship_coverage`, per-producer `coverage.{scope,status}`, `facet_availability{facet:{available:false, reason}}` | Was the *set* observed completely? Empty plus unknown coverage does **not** prove absence |
| completion ledger | `evidenceCompletionLedger.ts` | Per-claim `pass|fail|unsupported|truncated|unknown` with ≥1 evidence_ids, digest `ecl_`, `complete = (pass == total)` |
| ResidualUnknown | `residualUnknown.ts` | First-class open questions (below) |

Rules that recur in the docs: "gaps yield truncated or unknown, never equivalence"; "exhausting a page from a partial source does not establish that unreturned paths are absent"; "consumers use this producer-owned fact; limitations are explanatory and do not supply or infer coverage" (`mcp-contracts.md` §Tool results).

### 3.6 Residual unknowns (VERIFIED-READ `residualUnknown.ts`, `EvidenceLedger.ts`, `evidenceBundle.ts:300-560`)

Record fields:
* `unknown_id` (`unk_`), `revision` (≥1), `previous_revision_digest` (null only for revision 1), `revision_digest`, `scope_digest` (target sha256 or null)
* `question`, `status: open|investigating|blocked|contradicted|resolved`, `severity: low|medium|high|critical`, `domain`
* `supporting_evidence_ids[]`, `contradicting_evidence_ids[]`
* `required_authority|null`, `required_confidence`, `required_environment {id,platform,architecture,isolation}|null`
* `recommended_probes[{operation, rationale}]`, `relationships[{type: depends-on|related-to|contradicts, unknown_id}]`
* `resolution: {disposition:"verified", rationale, evidence_ids≥1} | {disposition: withdrawn|out-of-scope, rationale, evidence_ids}`
* `mutation_evidence_ids[≥1]`

Invariants:
* The ID matches the stable identity.
* `resolved ⇔ resolution != null`.
* `contradicted` needs contradicting evidence.
* No self-relations, no duplicate IDs, and no Evidence that both supports and contradicts.
* The revision chain is gap-free and linked by digests.
* There are no `depends-on` cycles.
* Every referenced Evidence exists in the bundle.
* A `verified` resolution needs at least one supporting, non-mutation Evidence that meets the required authority, confidence rank (`inferred 1 < derived 2 < observed 3`) and environment, and no contradicting evidence (`validateVerifiedResolution`).

Ownership and mutation: every mutation (`record_unknown`, `update_unknown`) creates **mutation Evidence**. Its predicate is `rea.residual-unknown-mutation`, its provider is `rea-unknown-registry`, and it has `confidence:"derived"`, `authority:"analyst-inference"`, `evidenceLinks` = the referenced IDs, and the limitation "Registry mutation evidence records analyst intent, not proof of the answer." (`UnknownEvidence.ts`). Updates are optimistic CAS: `expected_revision` must equal the current head, or the update fails with `revision-conflict` (retryable). Workflow tools auto-create unknowns whose question ends in `(Evidence ev_…)` (`WorkflowUnknown.ts`). `verifyUnknownResolution` → `{valid: status==="resolved", truthVerified: disposition==="verified"}`. "Withdrawn/out-of-scope are not truth claims."

---

## 4. Retention: EvidenceLedger (VERIFIED-READ `src/application/investigation/EvidenceLedger.ts`)

```ts
export class EvidenceLedger {
  readonly #records = new Map<string, Evidence>();
  readonly #unknownRevisions = new Map<string /*id:rev*/, ResidualUnknown>();
  readonly #unknownHeads = new Map<string, ResidualUnknown>();
  record(input: Evidence): Result<"added"|"duplicate", EvidenceIntegrityError>;         // :49
  import(input: unknown): Result<EvidenceImportDelta, EvidenceIntegrityError|AnalysisInputError>; // :75
  export(): EvidenceBundle;              // structuredClone(createEvidenceBundle(...)) :179
  forSerialization(): EvidenceBundle;    // sealed, zero-copy :189
  has(id); get(id) /*clone*/; forAnalysis(id) /*borrow*/;
  recordUnknown(input, mutationEvidence); recordWithUnknown(evidence, input, mutation); updateUnknown(...);
  listUnknowns(filters); listUnknownsPage({status,severity,domain,offset,limit}); verifyUnknownResolution(id);
  clear();                               // on close_binary
}
```

* `record` is idempotent. A record with the same ID and the same content (local path masked) returns `"duplicate"`. Same ID with different content returns an `EvidenceIntegrityError("Conflicting evidence record")`.
* `import` is **atomic**: the whole bundle is validated first, and on any conflict nothing changes. It reports `{recordsAdded, unknownsAdded, changed, metadataChanged}`. `metadataChanged` means the same semantic ID with different display metadata (path), which replaces the stored record.
* Scope: one ledger per MCP connection. Opening another target keeps the records. `close_binary` clears them. "A missing reference reports its exact ID and `details.reason: "missing"`; the server cannot infer whether it was never recorded, cleared, or retained by another connection" (`mcp-contracts.md` ~470).
* **No quota.** Tests: "retains more than ten thousand inline evidence records", "retains inline evidence larger than the former session byte quota" (`EvidenceLedger.test.ts:212,225`). Memory is the only limit. Heap headroom is checked before authenticating (`requireAuthenticationHeadroom`).
* Ports (`InvestigationRecordPort.ts`) split `EvidenceReader` (has/byId/forAnalysis/export), `EvidenceWriter.recordEvidence`, `EvidenceUnknownWriter`, and `UnknownRegistryPort`.

Recording discipline in tools (`registerEvidenceTools.ts`): execute → build Evidence → record source Evidence first (so links resolve) → optional projection (summary) → `recordEvidence` → `toEvidenceToolResult(evidence, contract, recorded)`. If recording fails, the tool returns the recording error even though the analysis succeeded. The success result is never shown without retention.

---

## 5. Bundles, summary, filters, export/import, snapshots

### 5.1 Bundle (VERIFIED-READ `evidenceBundle.ts:43-150`)

```ts
evidenceBundleSchema = z.strictObject({
  artifacts:    [{digest, format, architecture}],      // derived from record subjects (unique, sorted)
  providers:    [{id, name, version}],                 // derived
  environments: [{id, platform, architecture, isolation}], // derived
  scenarios:    [{evidence_id, operation, authority:"controlled-replay"}], // derived
  captures:     [{evidence_id, predicate_type}],       // derived: predicate rea.process-capture
  unknowns:     ResidualUnknown[],                     // sorted (unknown_id, revision)
  records:      Evidence[],                            // sorted by evidence_id
});
```

* The manifests are *derived* from the records. On parse, the bundle is rebuilt from its records and compared byte for byte (`equalJsonText(parsed, canonical)`). Any difference raises `NonCanonicalEvidenceBundleError`. Duplicate record IDs are rejected. Every record ID is re-authenticated, and the unknown graph is validated.
* `serializeEvidenceBundle` = `canonicalize(parseEvidenceBundle(b))`, giving byte-stable RFC 8785 output. Streaming writes use `canonicalJsonParts` → `writeTextParts` (atomic publish: write to staging, then rename; refuse an existing file unless `overwrite`).
* `evidenceBundleForTarget(bundle, sha256)` (line 153) projects a bundle onto one target. It keeps target records plus the complete unknown histories whose every referenced Evidence is on that target, or is mutation Evidence. Dependents of excluded unknowns are pruned transitively. Snapshots use this.
* `describeEvidenceBundleFailure` (line 238) tells "you gave me one Evidence record, not a bundle" apart from "invalid bundle" and gives tailored messages.

### 5.2 Summary and filters (VERIFIED-READ `evidenceRecordSummary.ts`, `InspectEvidenceBundle.ts`)

* `get_evidence_bundle { detail?: "complete"|"summary", filters? }`. Filters are **only** valid with `summary`; otherwise the call fails with `AnalysisInputError` (path `["filters"]`, `expected:"detail: summary"`).
* `EvidenceRecordFilters`: exact `evidence_id`, `operation`, `target_sha256`, `analysis_profile_digest`, `procedure_address`. Selection is exact and "never resolves a provider address".
* Summary: `{kind:"evidence-bundle-summary", filters, total_retained_records, matching_records, unknown_revisions, records:[{evidence_id, subject, provider, operation, confidence, authority, analysis_profile_digest, retention:"complete-record", limitation_count, native_dossier:{…value_flow truncation status…}}]}`. It reads only metadata and does not copy payloads.
* Producers that take `detail:"summary"` (`inspect_artifact`, `inspect_macho`, …) record the complete Evidence and return a *derived* summary Evidence whose `normalized_result.parent_evidence_id` and `evidence_links` point at the parent. "Delivery detail never reaches the provider and never changes the source Evidence ID" (`parametersForEvidence` strips delivery-only args from identity: `registerEvidenceTools.ts:34-38`).
* `inspect_analysis_view { source: {kind:"retained-evidence", evidence_id} | {kind:"inline", evidence} | {kind:"evidence-file", path}, view:{kind, offset, limit, fields?} }` pages through the retained Evidence without restarting providers. The result is derived Evidence with `coverage.next_offset`.

### 5.3 Export/import (VERIFIED-READ `EvidenceBundleCommands.ts`, `EvidenceBundleFiles.ts`, `registerSessionRecordTools.ts`)

* MCP `export_evidence_bundle {path, overwrite}` → `writeEvidenceBundle(ledger.forSerialization(), …)` → `{path, bytes, records}`. Cancellation removes the staging file, and the destination changes only on a complete atomic publish.
* MCP `import_evidence_bundle {path}` → read + authenticate + (process-capture payloads re-parsed) → `ledger.import` → `{imported, unknowns_added, total}`. "Imported content is data only and is never executed."
* CLI: `rea evidence-import BUNDLE`, `rea evidence-export SRC DST [--overwrite]`, `rea compare L R`, `rea inspect-evidence-bundle '{"path":…,"detail":"summary","filters":{…}}'`, `rea inspect-analysis-view REQ.json --evidence-bundle BUNDLE.json`. The last one resolves a `retained-evidence` ID from a bundle file, so the same view request works across MCP and CLI.

### 5.4 Snapshots (VERIFIED-READ `analysisSnapshot.ts:177-620`; `docs/cli.md:237-275`)

```ts
analysisSnapshotSchema = {
  target:  { sha256, kind, architecture, format [, entry_point for raw-binary] },  // path-free
  binding: { provider (committed, version required), analysis_profile },
  entries: [{ query_id, operation, parameters, execution:{result, raw_result, provider, limitations, relationship_coverage, locations, subject} }],
  workflow_entries: [... + execution.analysis_profile],
  evidence_bundle: EvidenceBundle,     // target-projected
};
query_id = "query_" + sha256(canonical({target, binding, operation, parameters}))   // :544
```

* A snapshot is a **replay cache**: an exact `(target bytes, provider+version, profile digest, operation, parameters)` match returns the stored Evidence without starting the provider (`snapshotEvidenceForQuery`, :445). The Evidence is rebound to the current path.
* Mutations and cursor-dependent calls are excluded. Any metadata write invalidates the session's snapshot cache "even if its reply fails: the provider may already have applied the write". Failed decompiler dossiers keep their Evidence but skip snapshot reuse, so a later recovery can be observed.
* Snapshot files are local with owner-only permissions. MCP `open_binary {snapshot_path}` imports and `close_binary {snapshot_path, overwrite}` saves. A failed save leaves the session open.

---

## 6. How tool results reference Evidence

1. **Inline**: every Evidence-producing tool returns the complete Evidence record. Callers read `structuredContent.normalized_result` and `structuredContent.evidence_id`.
2. **Retained reference** (`evidenceReference.ts`): `{kind:"retained-evidence", evidence_id:"ev_…"}`. `evidenceInputSchema = union(evidenceSchema, retainedEvidenceReferenceSchema)`, so tools that take Evidence inputs (compare_functions, trace_application_feature, …) accept either. Both forms "pass the same semantic, identity, authority, and provenance checks". Failures are `EvidenceReferenceError(missing|wrong_operation|wrong_predicate|identity_mismatch)`.
3. **Links**: derived Evidence lists its inputs in `evidence_links`. `evidenceClosure` gives the transitive set and fails on a dangling link (`EvidenceIntegrityError("Investigation input has a dangling Evidence link")`).
4. **Error references**: `details.partial_observation = {kind:"retained-evidence", evidence_id}` or inline. Transport overflow puts `details.reported_limits.evidence_reference` and an optional `continuation: {name, arguments}`.
5. **Unknowns** reference Evidence by ID in four lists (supporting, contradicting, mutation, resolution).

---

## 7. Sensitive-value redaction (VERIFIED-READ `explicitSensitiveValues.ts`, `explicitSensitiveFailure.ts`, `WebNetworkCaptureService.ts:150-240`, `webNetworkCapture.ts:64-90`; docs)

Principles:
* **Explicit literals only.** "Replace caller-declared literal text values without guessing sensitivity from names." "Unknown extension names and token-looking query parameters do not establish sensitivity." The only exceptions are structural: credential headers, cookies and URL userinfo are always excluded.
* Declarations (`sensitive_values: string[]`, CLI `--sensitive-value`) are **never persisted in Evidence parameters. Only `sensitive_value_count` is stored.**
* Payload fields that contain a declared literal are excluded **as a whole** (`null` plus a `redactions[]` entry), not rewritten with a marker. A marker could rebuild the literal at a boundary, and rewritten bytes would be fabricated. Redacted byte fields keep neither the bytes nor their digest.
* Paths and digests: if the artifact path contains a literal, the path is `""` and dropped from locations, with a limitation explaining it. If the **digest itself** matches, `subject = null` with `subjectUnavailableReason`. The other parameters (`format`, …) are dropped if they contain a literal.
* `redactExplicitText(value, literals)`:
  * Dedupe and drop empty literals.
  * Pick the first replacement among `"[REDACTED]"`, `"…"`, `""` that contains no literal.
  * Replace the longest literals first.
  * **If any literal still appears after replacement (because a replacement created a new match at a boundary), return `""`.**
* `redactExplicitFailure(error, literals)` rebuilds the typed error with redacted message, diagnostics (keys containing literals are dropped), captured stdout/stderr, cleanup reason/resources and input-issue paths. JSON-pointer paths are cut back to the last safe ancestor (`redactExplicitPointer`). Cleanup liveness is mirrored. The **tag and type are preserved** ("without changing error types").
* Process capture: parameters contain only counts and basenames. "Matching scenario commitments do not reveal whether redacted sensitive inputs were equal" (`process-capture.md:84`).
* Browser scenarios: secrets are declared as environment-backed references. "Durable results replace resolved secret values with their secret references." Undeclared secret references fail validation.
* Separate concern: **prompt-injection provenance marker** on target-derived content (§2.5).

---

## 8. Lab experiment (VERIFIED-RUN)

`bea-lab/rea-evidence/stream_digest_bench.mjs`, Node v24.18.0, 200,000 synthetic hook-hit events (`{seq, t_ns, tid, hook, pc, ret, args[3], retval}`):

```
per_event_hash_ms: 548   (2.74 µs/event: canonical JSON + SHA-256 per event)
hash_chained_chunks_ms: 435  (49 chunks of 4096, chained sha256(prev || jsonl))
canonical_jsonl_ms: 353
jsonl_mib: 29.0  (≈152 bytes/event)
```

Conclusions:
* Canonicalization dominates the cost. Hashing itself is cheap, so a per-event REA-style Evidence envelope is CPU-feasible at around 350k/s. **Size is the problem.** 200k events ≈ 29 MiB, about 3× the 10 MiB MCP frame, and REA's ledger has no quota.
* The design follows: events go to disk as canonical JSONL chunks, with one chunk digest each, chained (`sha256(prev_digest || chunk_bytes)`). The Evidence record carries a *manifest* (counts, drops, first/last seq, chunk digests, head digest). Queries over a stream produce derived Evidence that links to the manifest.

---

## 9. Critique: what fits a dynamic tool and what doesn't

### 9.1 Worth copying as-is
* Content-addressed `ev_` IDs, re-checked on every parse, plus prefixed ID families.
* Strict schemas (`z.strictObject`): unknown fields are rejected at the envelope. Open JSON is allowed only in `parameters`, `raw_result` and `normalized_result`.
* `confidence` × `authority` × `limitations` × `coverage` as separate axes. "Absent coverage = unknown."
* Missing identity is stated as a limitation and enters the ID.
* Delivery-only args (`detail`, paging) are stripped from Evidence identity.
* Record before deliver: a success is never shown without retention.
* Error projection wire shape `{code, category, message, retryable, remediation:{action}, recovery?, details?}` with an exhaustive tag→code table, plus the JSON-Schema contract file.
* Partial observations inside errors, and cleanup-incomplete overriding the code.
* Untrusted-content `_meta` marker, on by default.
* Explicit-literal redaction, never persisted, whole-field exclusion.
* Atomic bundle import and export, canonical bytes.
* The summary → view → export escape hatch for oversized results.

### 9.2 Mismatches for dynamic analysis
1. **Deterministic identity merges distinct observations.** Two `read_memory(0x1000, 16)` calls at different times with the same bytes give one `ev_`. In BEA, the observation's time anchor (`instance_id`, `module_map_id`, `seq`, and the effect epoch) must be inside the semantic projection. Then the ID still dedupes exact replays of a record but not separate observations.
2. **Subject = file digest.** For a live process, the subject is a *process instance*: device, pid, start time, image path and image sha256. Module bases are an *epoch* that changes on load and unload. REA's Frida Evidence has `subject:null`, `environment:null` and no start time, so pid reuse is undetectable (§3.4).
3. **No effect records.** REA records effects only as tool metadata (`toolEffects.ts`: `mutatesTarget`, `executesForeignCode`, …) and as `artifact_changed` after foreign commands. Nothing says "observation X was made while hook H (an effect) was active", but BEA tools write memory, install hooks, suspend threads and call functions in-process.
4. **Unbounded in-memory ledger.** That does not work for hook streams. BEA needs disk-backed retention and quotas.
5. **Replay snapshots** assume deterministic re-execution. A live process cannot be replayed. Only emulation (Unicorn), static lookups and pure dumps-at-rest are cacheable.
6. **Size and complexity.** The cleanup dependency graph with WeakRefs, sealed-snapshot borrowing, cooperative hashing generators, about 30 partial-observation types and 117 audited copy strings all grew to meet 300 MB static payloads and many providers. BEA v1 can do without most of it.
7. Errors as classes. This is fine in TS, but the error must be *projected* to cross a process boundary (Frida agent ↔ host). BEA's agent-side errors should be plain data tagged unions from the start.

---

## 10. Proposed BEA Evidence + error model

Goal: keep REA's guarantees (provenance, authenticated IDs, explicit uncertainty, honest coverage, redaction) but bind them to a process instance in time, record mutations as effects, and handle streams.

### 10.1 Result and errors

Keep REA's `Result` exactly, and add two helpers:

```ts
// src/domain/result.ts
export type Result<T, E> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: E };
export const ok  = <T>(value: T): Result<T, never> => ({ ok: true, value });
export const err = <E>(error: E): Result<never, E> => ({ ok: false, error });
export const tryResult = <T, E>(f: () => T, wrap: (cause: unknown) => E): Result<T, E> => {
  try { return ok(f()); } catch (cause) { return err(wrap(cause)); }
};
```

Errors are **plain-data** tagged unions. They serialize across the Frida RPC boundary with no extra step and can be checked exhaustively with `switch (e._tag)`:

```ts
// src/domain/beaError.ts
export type BeaErrorTag =
  | "InputError" | "CapabilityUnavailable" | "Unsupported" | "Timeout" | "Cancelled" | "ResourceLimit"
  | "TargetNotFound" | "TargetExited" | "InstanceMismatch" | "AccessDenied"         // process lifecycle
  | "AddressUnmapped" | "AccessViolation" | "ProtectionDenied"                       // memory
  | "HookConflict" | "HookInstallFailed" | "WatchpointUnavailable"                   // instrumentation
  | "CallFaulted" | "EmulationFault"                                                 // execution
  | "StaleReference" | "EvidenceIntegrity" | "EvidenceFile" | "UnknownRegistry"      // evidence
  | "EffectUnreverted" | "CleanupIncomplete" | "ProviderFailure" | "Internal";

interface BeaErrorBase<Tag extends BeaErrorTag> {
  readonly _tag: Tag;
  readonly operation: string;
  readonly message?: string;                    // curated, caller-safe
  readonly diagnostics?: Record<string, JsonValue>;
  readonly partial?: PartialRef;                // { kind:"retained-evidence", evidence_id } | inline Evidence
  readonly cleanup?: { status: "incomplete"; resources: string[]; reason: string };
  readonly effects?: readonly EffectRef[];      // effects applied before the failure (must not be lost!)
  readonly instance_id?: InstanceId;            // the process instance involved, if any
  readonly cause?: unknown;                     // never projected
}
export type BeaError =
  | (BeaErrorBase<"InputError"> & { issues: InputIssue[] })
  | (BeaErrorBase<"TargetExited"> & { exit: { code: number | null; signal?: string; observed_at: TimeAnchor } })
  | (BeaErrorBase<"AddressUnmapped"> & { address: Hex; module_map_id: string })
  | (BeaErrorBase<"AccessViolation"> & { address: Hex; access: "read" | "write" | "execute"; thread_id?: number })
  | (BeaErrorBase<"InstanceMismatch"> & { expected: InstanceId; actual: InstanceId | null })
  | (BeaErrorBase<"HookConflict"> & { address: Hex; existing_hook_id: string })
  | (BeaErrorBase<"CallFaulted"> & { address: Hex; exception: ExceptionRecord })
  | (BeaErrorBase<"Timeout"> & { timeout_ms: number })
  | (BeaErrorBase<"ResourceLimit"> & { resource: "memory" | "events" | "disk" | "transport" | "capacity"; limit: Record<string, JsonValue>; retryable: boolean })
  | (BeaErrorBase<"EffectUnreverted"> & { effect_ids: string[] })
  | BeaErrorBase<Exclude<BeaErrorTag, "InputError"|"TargetExited"|"AddressUnmapped"|"AccessViolation"|"InstanceMismatch"|"HookConflict"|"CallFaulted"|"Timeout"|"ResourceLimit"|"EffectUnreverted">>;
```

Wire projection: **keep REA's shape** so agents that know REA transfer directly:

```ts
interface BeaErrorProjection {
  code: BeaErrorCode;          // snake_case, closed, 1:1 or n:1 from tags via `satisfies Record<BeaErrorTag, BeaErrorCode>`
  category: "invalid_input"|"unsupported"|"target_state"|"integrity_mismatch"|"truncated"|"cancelled"
          | "timeout"|"resource_constraint"|"unavailable"|"execution_failure";
  message: string;
  retryable: boolean;
  remediation: { action: string };
  recovery?: { kind: "inspect_input_contract"; operation: string }
           | { kind: "reattach"; previous_instance_id: string }          // new: TargetExited / InstanceMismatch
           | { kind: "refresh_module_map"; instance_id: string }        // new: StaleReference / AddressUnmapped
           | { kind: "revert_effects"; effect_ids: string[] };          // new: EffectUnreverted
  details?: Record<string, JsonValue>;   // includes partial_observation, effects_applied, cleanup
}
```

Rules carried over from REA:
* `cleanup.status === "incomplete"` overrides the code to `cleanup_incomplete`, and `details.execution_failure` keeps the original code.
* `effects` applied before a failure are **always** projected (`details.effects_applied`). An agent must know the target was modified even when the call failed.
* `TargetExited` is not retryable for the same `instance_id`. The recovery says to spawn or attach again, which creates a new instance.
* Keep a static `docs/error-contract.schema.json` generated from the zod projection schema, and an exhaustive `tag→code` table with `satisfies`.

### 10.2 Process-instance identity (the subject)

```ts
type InstanceId = `pi_${string}`;
interface ProcessInstance {
  instance_id: InstanceId;           // sha256(canonical({device_id, pid, start_time, image}))
  device_id: string;                 // "local" | frida device id
  pid: number;
  start_time: { source: "os-creation-time" | "first-observed"; value: string };  // Win: FILETIME from GetProcessTimes (100ns, as decimal string)
  image: { path: string; sha256: string | null; size: number | null; format: "pe"|"elf"|"mach-o"|"unknown"; architecture: string };
  launched_by_bea: boolean;          // spawn vs attach; governs kill authority
  environment: { platform: "win32"|"linux"|"darwin"; os_version: string; architecture: string; isolation: "none"|"process"|"vm" };
}
```

* `start_time` together with `pid` stops pid reuse from aliasing two processes. If creation time is unavailable, use `source:"first-observed"` **and** add the limitation "Process start time not available; pid reuse cannot be excluded."
* `image.sha256` is computed on disk when attaching and checked again at detach. If it changed, add the limitation "image changed on disk during session" (like REA's `artifact_changed`). `null` means unknown, and its limitation enters the ID (REA's `subjectUnavailableReason` pattern).
* The display path is excluded from the instance ID the same way REA excludes `local_path`. **But** for a process, the path is part of identity (two copies of the same exe are different processes), so keep `image.path` in the ID. Only *user-facing aliases* are dropped.

**Module-map epochs.** Module bases are time-varying state, not identity:

```ts
interface ModuleMapEpoch {
  module_map_id: `mm_${string}`;     // sha256(canonical({instance_id, modules sorted by base}))
  instance_id: InstanceId;
  epoch: number;                     // monotone per instance; bumps on observed load/unload
  observed_at: TimeAnchor;
  modules: { name: string; path: string; base: Hex; size: number; sha256: string | null; timestamp_pe?: number }[];
  completeness: "complete" | "partial" | "unknown";  // e.g. enumerated vs inferred from a single address
}
```

Every observation that uses addresses carries a `module_map_id`. Locations are given in **both** forms so that ASLR rebasing to Ghidra/REA addresses is mechanical and checkable:

```ts
type BeaLocation =
  | { kind: "va"; address: Hex; module_map_id: string }
  | { kind: "module-offset"; module: string; module_sha256: string | null; rva: Hex }   // static-stable
  | { kind: "static-address"; image_sha256: string; preferred_base: Hex; address: Hex } // REA/Ghidra address space
  | { kind: "thread"; thread_id: number }
  | { kind: "range"; start: Hex; end: Hex; module_map_id: string };
```

Static↔runtime mapping is **derived** Evidence. Its `evidence_links` are [the module map Evidence, the static (REA) Evidence]. If `module.sha256 !== static.subject.digest.sha256`, the mapping is `inferred` with the limitation "runtime module bytes differ from static artifact". This is the bridge to REA: same digest = same address space.

### 10.3 Time anchor

```ts
interface TimeAnchor {
  instance_id: InstanceId;
  seq: number;              // session-global monotone sequence assigned by BEA host (total order of BEA operations)
  mono_ns: string;          // host monotonic clock (process.hrtime.bigint) as decimal string
  wall: string;             // ISO-8601 UTC, informational only
  effect_epoch: number;     // count of effects applied to this instance so far (see 10.5)
  module_map_epoch: number;
}
```

`seq` and `effect_epoch` are **part of the Evidence semantic projection**, so separate observations never merge. A *re-export* of the same record keeps its ID. `wall` is excluded from the ID because it is display data.

### 10.4 The BEA Evidence record

```ts
const beaEvidenceSchema = z.strictObject({
  schema: z.literal("bea.evidence/1"),
  evidence_id: prefixed("ev"),
  predicate_type: z.string(),          // "bea.memory.read" | "bea.hook.stream" | "bea.call.oracle" | "bea.emu.run" | "bea.map.static-runtime" | ...
  operation: z.string(),               // MCP tool name
  parameters: jsonObject,              // identity-relevant args only; secrets/delivery args stripped
  subject: z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("process-instance"), instance_id, module_map_id: z.string().nullable() }),
    z.strictObject({ kind: z.literal("artifact"), sha256, format, architecture }),        // static / dump-at-rest
    z.strictObject({ kind: z.literal("emulation"), image_sha256, function_rva, initial_state_digest }),
  ]).nullable(),
  observed_at: timeAnchorSchema.nullable(),     // null for timeless (static / emulation) Evidence
  provider: { id, name, version },               // e.g. { id:"frida", name:"Frida", version:"17.23.2" }
  agent: { script_sha256, bea_version } | null,  // the injected agent that produced the data
  confidence: z.enum(["observed","derived","inferred"]),
  authority: z.enum(["live-process","emulation","static-artifact","imported","analyst-inference"]),
  perturbation: z.strictObject({                 // what BEA had done to the target when this was observed
    active_effect_ids: z.array(prefixed("fx")),  // hooks/patches/breakpoints in force
    instrumentation: z.enum(["none","passive","intrusive"]),
  }),
  result: jsonValue,                             // normalized_result
  raw_result: jsonValue.nullable(),
  blobs: z.array(z.strictObject({ role: z.string(), sha256, bytes: z.number().int(), media_type: z.string(), path: z.string() })),
  coverage: z.discriminatedUnion("status", [
    z.strictObject({ status: z.literal("complete") }),
    z.strictObject({ status: z.literal("partial"), limitations: z.array(z.string()).min(1) }),
    z.strictObject({ status: z.literal("unknown"), reason: z.string() }),
  ]),
  truncation: z.strictObject({ truncated: z.boolean(), dropped: z.number().int().nonnegative().nullable(), reasons: z.array(z.string()) }),
  limitations: z.array(z.string()),
  locations: z.array(beaLocationSchema),
  evidence_links: z.array(prefixed("ev")),
  effects: z.array(prefixed("fx")),              // effects THIS operation applied (empty for pure reads)
});
```

ID rule: `ev_ = sha256(canonical(record minus {evidence_id, observed_at.wall, blobs[].path, subject display fields}))`. Blob **digests** are in the ID; blob **paths** are not, so bundles can be moved.

Large binary payloads (memory dumps, module dumps, coverage files) are always **blobs** (a content-addressed file in the session store), never base64 inside `result`. This keeps Evidence small and still authenticated.

### 10.5 Effects (target mutations)

Every tool that changes the target emits an Effect record. Effects are separate from Evidence because they have a lifecycle (applied → reverted | leaked):

```ts
const effectSchema = z.strictObject({
  effect_id: prefixed("fx"),            // sha256(canonical({instance_id, seq, kind, target, params}))
  instance_id,
  kind: z.enum([
    "process-spawned","process-attached","process-resumed","process-suspended","process-killed",
    "agent-injected","module-loaded","memory-written","protection-changed","memory-allocated",
    "hook-installed","breakpoint-set","watchpoint-set","thread-suspended","thread-context-set",
    "function-called","exception-handler-installed","stalker-followed",
  ]),
  target: z.strictObject({ address: hex.nullable(), size: z.number().int().nullable(), thread_id: z.number().int().nullable(), module_map_id: z.string().nullable() }),
  parameters: jsonObject,
  before: z.strictObject({ sha256: z.string().nullable(), blob: z.string().nullable() }).nullable(),  // e.g. original bytes for a patch
  after:  z.strictObject({ sha256: z.string().nullable() }).nullable(),
  applied_at: timeAnchorSchema,
  status: z.enum(["active","reverted","revert-failed","implicit-end"]),   // implicit-end: process exited
  reverted_at: timeAnchorSchema.nullable(),
  revert_evidence_id: prefixed("ev").nullable(),   // e.g. read-back proving original bytes restored
  reversible: z.boolean(),                         // function-called: false (side effects unknown)
  side_effects: z.enum(["none-known","unknown"]),  // honest: an in-process call may have arbitrary effects
});
```

* `effect_epoch` (in `TimeAnchor`) = the count of effects applied to the instance. Every Evidence carries `perturbation.active_effect_ids`, which lets an agent (or a verifier) tell "observed with no instrumentation" apart from "observed while hook fx_… was rewriting arg 2".
* An irreversible effect (`function-called`, `process-killed`, `memory-written` without a `before` blob) marks the instance **tainted**. Later observations get the limitation "Target state was modified by irreversible effect fx_…; observations may not reflect unperturbed behavior."
* Unresolved cleanup at detach → `EffectUnreverted` / `cleanup_incomplete` with the `effect_ids`. This uses REA's cleanup-incomplete semantics.
* Tool effect metadata (REA's `toolEffects.ts`): keep the static table (`mutatesTarget`, `executesForeignCode`, `launchesProcess`, `writesFilesystem`, `mutatesSession`, `idempotent`, `mayDiscardData`) and derive the MCP annotations from it. BEA adds `injectsCode` and `suspendsTarget`.
* Kill authority: `process-killed` is permitted only if `launched_by_bea` for that instance. Otherwise the tool returns `Unsupported` / `AccessDenied`. This enforces "never kill what you did not start" in the model itself.

### 10.6 High-volume streams (hooks, Stalker, watchpoints, exceptions)

Do **not** make one Evidence per hook hit. Use this pattern instead:

```
hook-installed Effect fx_H
   └── Stream (st_…): on-disk  session/streams/st_…/chunk-000000.jsonl, chunk-000001.jsonl, ...
         each chunk: canonical JSONL events; chunk_digest_i = sha256(chunk_digest_{i-1} || chunk_bytes)
   └── Stream-manifest Evidence (predicate "bea.stream.manifest"), emitted at close or on checkpoint:
         result = { stream_id, source: {kind:"hook"|"stalker"|"watchpoint"|"exception", effect_id},
                    first_seq, last_seq, events_recorded, events_dropped, drop_reasons:{buffer_full, rate_limit, payload_cap},
                    chunks:[{index, events, bytes, digest}], head_digest, schema:{event fields + arg decoders},
                    started_at, ended_at, end_reason:"stopped"|"process-exited"|"limit"|"detached" }
         coverage = complete iff events_dropped==0 && end_reason in {stopped, process-exited}
         truncation = { truncated: events_dropped>0, dropped: events_dropped, reasons:[...] }
```

* Event schema (agent → host): `{seq, mono_ns, tid, pc, return_address?, args:[hex|decoded], retval?, backtrace?: [module-offset], context_digest?}`. All integers are hex strings (avoids JS 2^53 loss).
* Queries (`query_stream {stream_id, filter, group_by, offset, limit}`) produce **derived** Evidence with `evidence_links:[manifest_ev]`, `parameters` = filter, and `result.coverage.next_offset`. Aggregations (per-caller counts, arg histograms, unique backtraces) are derived Evidence too.
* Checkpoints: a long-running stream can emit intermediate manifest Evidence (the same `stream_id`, with `last_seq` and `head_digest` advancing). Each is a separate ID because `observed_at.seq` differs. The ledger keeps all of them, and the latest supersedes for delivery.
* Live polling without Evidence: `stream_status` returns counts and is not recorded. This is the analogue of REA's session-status tools, so agents can poll cheaply.
* Budgets (fixed, reported like REA's Frida caps, with an exact sentence per cap): per-event payload bytes, agent→host batch size, per-stream disk bytes, per-session disk bytes. Agent-side ring-buffer overflow increments `events_dropped`. **Data is never dropped silently.**

### 10.7 Ledger, bundle, export

* `EvidenceStore` per BEA session directory (`%LOCALAPPDATA%/bea/sessions/<session_id>/`):
  * `ledger.jsonl`: append-only records (Evidence, Effect, Unknown revision, ProcessInstance, ModuleMapEpoch), each canonical and fsynced in batches. This makes it crash-safe. A target crash that takes down BEA's agent must not lose the host-side ledger.
  * `blobs/<sha256>`: content-addressed binary payloads.
  * `streams/<stream_id>/chunk-*.jsonl`.
  * In-memory index: Map id→offset, plus filters by `instance_id`, `predicate_type`, `operation`, `module_map_id`, `effect_id`.
* `record()` keeps REA's semantics: authenticate, return `"added"|"duplicate"`, and reject conflicting content with the same ID.
* Quotas (configurable, reported in `bea_session`): max ledger bytes, max blob bytes, max stream bytes. Hitting one returns `ResourceLimit{resource:"disk"}`, which is *retryable after export/prune*.
* Bundle = **directory or .zip** (not one JSON) with:
  * `manifest.json`: canonical; lists records, instances, module maps, effects, unknowns, blob digests, stream head digests, and a `bundle_digest`.
  * `records.jsonl`
  * `blobs/`
  * `streams/`
  REA's "derived manifests must equal recomputed" check carries over: on import, recompute and compare. `export_evidence_bundle {path, include: {blobs: bool, streams: "all"|"manifests-only"}, overwrite}` publishes atomically (stage, then rename). `import_evidence_bundle` validates everything, then merges atomically. Imported live-process Evidence is marked `authority:"imported"` **only in the importing session's view**. The ID does not change, so it can be cited but not re-observed.
* `get_evidence {detail:"summary"|"complete", filters}`: copy REA's rule that filters require summary. Summary rows: `{evidence_id, predicate_type, operation, instance_id, seq, confidence, authority, coverage.status, truncated, limitation_count, effect_count, blob_bytes}`.
* Snapshots: drop the general replay cache. Keep it only for **deterministic** lanes. Emulation Evidence is keyed by `query_ = sha256({image_sha256, function_rva, initial_state_digest, emulator:{unicorn, version}, hooks_digest})`. Static lookups are keyed by image digest. Live-process tools are never cached.

### 10.8 Unknowns (simplified)

Keep REA's ResidualUnknown, but drop the comparison-scope and environment-requirement complexity in v1:
`{unknown_id: unk_(question, domain, scope), revision, previous_revision_digest, question, status: open|investigating|blocked|contradicted|resolved, severity, supporting[], contradicting[], recommended_probes[{operation, rationale}], resolution|null, required_confidence, required_authority|null, mutation_evidence_ids[]}`

* Keep CAS updates (`expected_revision`).
* Keep "verified needs qualifying evidence", where `authority:"live-process"` + `observed` beats `emulation` beats `static-artifact` for runtime questions.
* `scope` = `image_sha256` (not the instance), so questions survive across process restarts of the same binary.
* Auto-unknowns: when a stream is truncated, when a call oracle faulted, or when an emulation diverged from the live oracle (the differential case), record an unknown with a probe suggestion. This is what REA's `recordWorkflowEvidence` does.

### 10.9 Differential / oracle Evidence (emulation vs live)

This is generic and inspired by how the user validated emulators against reference models:
* `bea.call.oracle`: the live in-process call. Effect `function-called` (irreversible, side_effects unknown). Result `{inputs (regs/memory blob digests), outputs, exception|null}`. `observed`, `live-process`.
* `bea.emu.run`: Unicorn. The subject is `emulation{image_sha256, function_rva, initial_state_digest}`. Result: the same output shape plus `{instructions_executed, unmapped_accesses[], stubbed_calls[]}`. `observed`, `authority:"emulation"`. Stubbed imports are **limitations**, and stubs make coverage `partial`.
* `bea.diff`: derived, linking both. Per-output `equal|differ|unknown`, with the overall result `equivalent-on-tested-inputs | differ | unknown`. It must never say "equivalent" in general. This is REA's "gaps yield unknown, never equivalence" rule.

### 10.10 Sensitive values and untrusted content

* Copy REA's `redactExplicitText` and `redactExplicitFailure` semantics verbatim (an explicit literal list, never persisted, count retained, whole-field exclusion, return "" on boundary re-formation).
* Dynamic-specific cases:
  * spawn `argv` and `env` are stored only as counts plus basenames (REA `ProcessEvidence.ts` pattern). Store `env_keys` digests, not values.
  * Memory read results matching a declared literal (UTF-8 or UTF-16LE) are excluded as a whole field with `redactions[]`. Check UTF-16LE spellings on Windows.
  * Hook argument decoders that produce strings go through the same filter before the chunk is written.
* Mark every tool result that carries target-derived content (strings, memory, hook args, exception text, module names) with `_meta.provenance.untrusted_content = true`, on by default.

### 10.11 MCP tool-result shape

Success: one compact envelope. Do not inline whole records unless asked (REA's default is the complete record inline; for BEA the common results are small, but streams and dumps are not):

```json
{
  "evidence_id": "ev_…",
  "predicate_type": "bea.memory.read",
  "instance_id": "pi_…",
  "observed_at": { "seq": 412, "effect_epoch": 3, "module_map_epoch": 2 },
  "confidence": "observed",
  "coverage": { "status": "complete" },
  "truncation": { "truncated": false, "dropped": 0, "reasons": [] },
  "perturbation": { "active_effect_ids": ["fx_…"], "instrumentation": "passive" },
  "effects_applied": [],
  "result": { "...": "operation-specific" },
  "limitations": [],
  "evidence_reference": { "kind": "retained-evidence", "evidence_id": "ev_…" }
}
```

* `detail: "complete"` returns the full record. Delivery args are excluded from identity.
* Response budget: the same 10 MiB guard. On overflow, return `resource_constraint/transport` with `evidence_reference` and a ready-to-call continuation (`query_stream` / `read_blob` page). This is copied from REA.

---

## 11. Minimal TS sketch of `createBeaEvidence` (proposal, not run)

```ts
import { createHash } from "node:crypto";
import canonicalize from "canonicalize"; // REA uses this dep for RFC 8785

const semantic = (e: Omit<BeaEvidence, "evidence_id">) => ({
  ...e,
  observed_at: e.observed_at && { ...e.observed_at, wall: undefined },   // wall clock is display-only
  blobs: e.blobs.map(({ path: _p, ...b }) => b),                          // paths are relocatable
});
export const evidenceId = (e: Omit<BeaEvidence, "evidence_id">) =>
  `ev_${createHash("sha256").update(canonicalize(semantic(e))!).digest("hex")}`;

export const createBeaEvidence = (input: Omit<BeaEvidence, "evidence_id" | "schema">): BeaEvidence => {
  const limitations = [...input.limitations];
  if (input.subject === null) limitations.unshift("Subject identity is unavailable for this observation.");
  if (input.subject?.kind === "process-instance" && input.subject.module_map_id === null && input.locations.some(l => l.kind === "va"))
    limitations.push("Virtual addresses are not bound to a module map; static mapping is unavailable.");
  const base = beaEvidenceSchema.omit({ evidence_id: true }).parse({ ...input, schema: "bea.evidence/1", limitations });
  return Object.freeze({ ...base, evidence_id: evidenceId(base) });
};
export const parseBeaEvidence = (x: unknown): Result<BeaEvidence, BeaError> => {
  const p = beaEvidenceSchema.safeParse(x);
  if (!p.success) return err({ _tag: "EvidenceIntegrity", operation: "parse_evidence", diagnostics: { issues: p.error.issues.length } });
  const { evidence_id, ...rest } = p.data;
  return evidenceId(rest) === evidence_id ? ok(p.data)
    : err({ _tag: "EvidenceIntegrity", operation: "parse_evidence", message: "Evidence semantic identifier does not match its record" });
};
```

---

## 12. Things to simplify or defer relative to REA (with reasons)

| REA mechanism | BEA v1 | Reason |
|---|---|---|
| Sealed immutable snapshot WeakMaps, borrow-without-copy (`immutableJson.ts`) | `Object.freeze` + parse once | BEA payloads are small. Large data lives in blobs and streams |
| Cooperative hashing generators (`createImmutableEvidenceSteps`) | Defer | Only needed for 100+ MB inline payloads |
| Cleanup dependency graph with WeakRefs (`bindCleanupDependencies`) | Plain `cleanup: {status, resources}` + effect status | Effects already model what needs undoing |
| 30-variant `AnalysisPartialObservation` union | `partial: retained-evidence ref | inline BeaEvidence` | One envelope covers all |
| Full analysis-profile commitments | `provider.version` + `agent.script_sha256` + a `settings` object in parameters | One provider (Frida) plus Unicorn |
| General replay snapshots | Emulation and static only | Live processes are not replayable |
| Unknown comparison scopes, environment requirements | Defer | Add when needed |
| Single-JSON canonical bundle | Directory/zip bundle with manifest + blobs + streams | Binary dumps and streams |
| Unbounded in-memory ledger | Disk-backed append-only ledger + quotas | Hook volumes (29 MiB per 200k events, measured) |
| 117-row error-copy audit CSV | Start with the curated `message` + `remediation` per tag; add the CSV later | Proportionality |

---

## 13. Open questions

1. Windows process start time: is it available through Frida (`Process` API) or only through a host-side `GetProcessTimes` (`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`)? This needs checking by the process/attach researcher. Without it, identity falls back to `first-observed`.
2. Image digest for packed or self-modifying targets: is the on-disk sha256 enough, or should BEA also digest the **in-memory** `.text` at attach (`module_sha256_runtime`) to detect unpacking or patching? (Proposal: both. The runtime digest is a separate field, and a mismatch is a limitation.)
3. Should hook-hit events go through Frida `send()` batches (JSON) or a binary ring buffer → `send(data, bytes)`? This affects the event canonical form and the per-event cost (the bench measured about 2.7 µs/event on the host for JSON canonicalization alone).
4. Ledger durability vs speed: fsync per record or per batch? What loss window is acceptable if BEA itself crashes?
5. Should `seq` be session-global (a total order across instances) or per instance? (Proposal: session-global host `seq` plus per-stream event `seq`.)
6. Interop with REA: should BEA export REA-compatible `ev_` records (REA `evidenceSchema`, `predicate_type:"bea.*"`, `subject` = image artifact) so `rea evidence-import` can ingest BEA findings? REA's schema is strict, so BEA-specific fields would have to go into `normalized_result` and `parameters`. That looks possible via a projection function and is worth a spike.
7. Should static↔runtime mapping Evidence accept REA Evidence inline (as REA's `evidenceInputSchema` does) and check `subject.digest.sha256` against the runtime module digest?
8. Redaction of memory reads: should declared literals also be searched in UTF-16LE and in the common XOR/obfuscated forms? (REA only does literal + URL/JSON spellings. Proposal: UTF-8 + UTF-16LE only. Anything else is guessing.)
