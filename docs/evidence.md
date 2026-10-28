# Evidence model and run store

BEA records what it observes as **evidence**: content-addressed records in an append-only ledger. Each record
says how the observation was made, what changed in the target while it was made, and what is known to be
missing. This page describes the model, the files on disk, and the four evidence tools. Contract details are
generated in [tools/evidence.md](tools/evidence.md). The normative design is DESIGN.md §5.4 and annex S2.

## Records

Each record has the schema `bea.evidence/1` and carries these fields:

- **identity**: `evidence_id = "ev_" + sha256(RFC 8785 canonical record minus evidence_id and observed_at.wall)`.
  Two live reads never merge, because the run id and the run-global `seq` are part of every anchor. Static facts
  and baseline emulation have no anchor, so repeating them deduplicates.
- **subject**: one of the following.
  - `process-instance`: `pi_` = digest of `{device_id, pid, start_time, image_path_sha256}`, plus the module map
    `mm_` in effect.
  - `image`: the image's sha256.
  - `emulation`: the image's sha256, the configuration digest and the state basis.
- **confidence** (`observed | derived | inferred`) and **authority**
  (`live-process | emulation | static-artifact | imported | analyst-inference`). A derived record takes the
  _weakest_ authority of the records it links. A diff of a live call against an emulator run is therefore
  `emulation`.
- **perturbation**: `{level, active_effect_ids, tainted_by}`. The level is one of `none`, `agent-only` (only the
  BEA agent is present), `passive` (hooks or watches are active) or `intrusive` (writes, overrides or calls, or a
  permanent taint). The session's own agent-injection effect is implied and not listed.
- **coverage**: `{status: complete|partial|unknown, truncated, dropped?, reasons[]}`.
  - Paging is not truncation: a paged result is still `complete`.
  - Absent knowledge is `unknown`, never `complete`.
  - Every reason maps to a fixed limitation sentence.
- **limitations**: BEA-authored sentences only, with numbers, hex values and ids as their only parameters. Text
  that comes from the target appears only inside `result`, and only when `untrusted: true`.

Tool results put the record's summary next to the result fields (the "envelope": `evidence_id`, `predicate_type`,
`confidence`, `authority`, `coverage`, `limitations` and optional keys). Polls carry `evidence_id: null`.
Handlers build the envelope with `recordedEnvelope()` / `pollEnvelope()` from `src/application/evidence/envelope.ts`.

## Writing evidence (for area work packages)

- `evidence.instances.capture(instance)` takes the anchor: `seq`, effect epoch, module-map epoch and perturbation.
  Call it inside the session's exclusive section, right after the agent RPC.
- `evidence.recorder.record(draft)` runs the pipeline. If the draft is malformed, it returns an `Internal` error.
  Every error carries the draft's `effects` in `effects_applied`. The steps are:
  1. registry check (closed predicate list, allowed subject, anchor rule);
  2. parameters: delivery and handle keys removed, `sensitive_values` turned into a count;
  3. module map materialized on first reference;
  4. perturbation and limitations;
  5. literal redaction;
  6. schema and invariant check;
  7. id;
  8. links checked to resolve;
  9. the `ev` line appended and awaited;
  10. index updated.
- `evidence.effects.apply(draft)` writes the effect line before anything references it, and each apply or transition
  bumps the instance's `effect_epoch`. The bytes an effect replaced (`before`) are kept in memory for
  `originalBytes()`, which disassembly and byte verification use. They are written to the ledger only when they
  hold no sensitive literal.
- `evidence.streams.open(spec)` gives a `StreamWriter`. `append()` is synchronous and never throws. Its outcomes
  are `accepted`, `redacted` (the batch held a literal), `queue-full`, `quota-exceeded` (the callback registered with
  `onQuota()` fires once) and `closed`.
  - `checkpoint()` first runs the agent flush barrier (`StreamSpec.flush`, CI-I13), then seals the chunk and records a
    `bea.stream.manifest`.
  - `end()` does the same, fsyncs the chunks, and is idempotent.
  - Host row streams (`emu-batch`, `emu-sweep`, `diff`; no instance) are sealed and hash-chained, but `end()` and
    `checkpoint()` answer `invalid_state` because `bea.stream.manifest` is defined only for process-instance
    subjects. Read them with `ndjsonRows()` (`src/application/evidence/ndjsonRows.ts`).
- Agent drop accounting is robust to either reporting style. The manifest counts the larger of two totals: the
  frame headers' `dropped_before`, or the drops reported per reason through `noteDropped(n, DropReason)`. A drop
  reported without a reason is counted as `agent_buffer_full`, and a limitation sentence says so.
- Unit tests of other areas use `tests/support/fakes/fakeEvidence.ts`. It is an in-memory runtime that uses the same
  build pipeline, with `addInstance()`, `records`, `frames()` and `failNextRecord()`.

## Storage (`BEA_HOME/runs/<run_id>/`)

```
run.json        bea.run/1: open | closed | crashed, quotas, final counts and the ledger digest
.lock           {pid, started_wall}; removed by a clean finalize
ledger.jsonl    canonical lines: run, pi, mm, fx, fxt, ev, unk, import-begin, import-commit, end (≤ 4 MiB each)
blobs/<sha256>  content-addressed bytes (dumps, retained tables as NDJSON, large effect bytes)
streams/<st_>/  descriptor.json, chunk-NNNNNN.bin (framed raw agent batches, sealed at 8 MiB), chain.jsonl
tmp/            staging for blobs, exports and imports
exports/        default output directory of every file-writing tool
```

- **Nothing is written until the first record.** A server that records nothing never creates a run directory.
- At start, sibling runs that are still `open` and whose lock process is dead are marked `crashed`.
- **fsync points:** stream end, export, import merge and run finalize. Lines are written without a per-line fsync.
  After a power loss a torn final line is detected and ignored, never repaired. `reloadLedger()` reports it as
  `tornBytes`.
- **Finalize** (lifecycle phase `finalize-evidence`):
  1. fence the ledger: appends from operations still running are rejected and counted as `late_appends`;
  2. end live streams with `server-shutdown`;
  3. end the remaining effects (`implicit-end`);
  4. append `{t:"end"}`;
  5. fsync;
  6. mark `run.json` closed;
  7. remove the lock.
- CLI runs are ordinary runs. Deleting an ephemeral CLI run (no `--keep-run`, no export) is the CLI runner's job,
  after `lifecycle.closeAll`.
- `openPersistedRun(config, runId)` (`src/providers/evidence/reloadRun.ts`) answers `get_evidence` reads over an
  older or crashed run without modifying it.

## Quotas

| Quota          | Default                                                                                                | Setting                                        |
| -------------- | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------- |
| Ledger per run | 512 MiB, with the last 8 MiB reserved for lifecycle lines (effect transitions, exits, final manifests) | `BEA_LEDGER_QUOTA_MB`, `BEA_LEDGER_RESERVE_MB` |
| Each stream    | 256 MiB                                                                                                | `BEA_STREAM_QUOTA_MB`                          |
| All streams    | 4 GiB                                                                                                  | `BEA_STREAM_TOTAL_QUOTA_MB`                    |
| Blobs          | 4 GiB                                                                                                  | `BEA_BLOB_QUOTA_MB`                            |

Reaching a quota is never silent. A full ledger or blob store is `resource_constraint{resource:"disk",
limits:{quota, limit_mib, knob}}`. A full stream drops the batch, counts it under `stream_quota`, calls `onQuota`, and
leaves the manifest `partial`. `bea_status.storage` reports usage.

## Redaction

- Literals come from two places: the per-call `sensitive_values` (at least 4 UTF-8 bytes each, at most 64 per
  call) and the server file `BEA_SENSITIVE_VALUES_FILE` (one literal per line, at most 256). Neither list is ever
  persisted; records keep only `sensitive_value_count`.
- Matching is by text and by UTF-8 and UTF-16LE bytes inside declared byte fields. There is no case folding and no
  other encoding.
- A field that matches is removed whole: a string becomes `null`, and a property whose name matches is dropped.
  The redaction is listed with its pointer and adds `explicit_sensitive_value`.
- A blob that matches is not stored (`{redacted:true}`).
- A stream batch that matches is replaced by a `redacted` frame. The batch is never partially rewritten.
- Effect bytes that match are kept only in memory.
- Identity digests (`image_path_sha256`, `path_sha256`) are not redacted. They are one-way, but a low-entropy path
  can be guessed.

## Tools

- **`get_evidence`** reads this run's ledger and records nothing (it is a poll). It has three modes:
  - `summary`: rows of evidence, effects, unknowns or instances, with exact filters (instance, predicate,
    operation, applied or active effect, stream, module map, links, seq window, confidence, authority, coverage,
    origin, `module` with an `rva` range, image digest, `va` range, and status/severity/domain for unknowns) and
    up to 500 rows per page.
  - `complete`: any ledger id (`ev_ fx_ unk_ pi_ mm_ st_`). Evidence is re-authenticated on read; a stored record
    that fails is `evidence_integrity_mismatch`.
  - `slice`: a page of an array (`/result/rows`) or a blob (`#blob:<role>`) of one record. NDJSON tables return
    15 rows per page; binary blobs return up to 64 KiB, as hex or base64.

  A missing id is `invalid_request` on `id`.

- **`export_evidence`** writes a bundle of the whole run, or of one session's closure (`session_id`).
  - The bundle is a directory or a zip containing `bundle.json` (`bea.bundle/1`), canonical `records.jsonl`, `blobs/`
    and `streams/` (descriptors and chains only, or every chunk with `streams:"all"`).
  - The default path is `<run>/exports/bundle-<seq>[.zip]`. Any other `out_path` must pass the output-path policy
    (`access_denied{policy}` otherwise).
  - The bundle is staged, fsynced and published without overwriting: an existing target is
    `file_operation_failed{exists}`.
  - Exporting the same selection twice gives byte-identical `records.jsonl` and the same `bundle_digest`.
- **`import_evidence`** validates everything before it merges anything.
  - **Zip guards:** traversal, absolute, drive and backslash names, duplicate entries, entries outside the layout,
    and a compression ratio above 200:1 for entries over 1 MiB.
  - **Integrity:** the manifest digest; each record line canonical, ordered and authenticated; blob digests; stream
    chains.
  - **Derived equality:** counts, blob list, stream list and source runs, recomputed from the records.
  - **References:** every reference resolves inside the bundle or this ledger.
  - **Conflicts with this run:** the same id with different bytes, or an unknown revision with a different digest
    (`revision_conflict`).
  - **Quota.**

  With `validate_only` nothing changes. Otherwise the new lines are appended between `import-begin` and
  `import-commit`, and only then indexed; a bracket without its commit is ignored on reload. Imported records keep
  their ids and authority and are shown as `origin: "imported"`. Imported effects never enter the live effect
  registry.

- **`record_unknown`** creates a residual unknown, or updates one with a compare-and-swap on `expected_revision`
  (a stale revision is `revision_conflict`, retryable).
  - An update keeps every field it omits.
  - Each mutation records `bea.unknown.mutation` evidence (analyst intent, linked to the cited ids), followed by a
    digest-linked revision line.
  - Resolving needs supporting, non-mutation evidence of an accepted authority with sufficient confidence and known
    coverage, and no contradicting evidence. A `runtime` question needs observed `live-process` evidence. Records
    imported from a bundle count as `imported` and cannot verify a live claim.
  - The scope is the session's main image digest when `session_id` is given, otherwise this run.

## Recordings

Each instrument is exactly one recording, `rec_xxxxxxxx` (`src/application/instruments/RecordingRegistry.ts`).

- **Duration clock.** The agent arms its own timers, including `clock:"resume"` timers for instruments installed
  on a paused target. The registry keeps `ends_in_ms` only for display, and starts counting at `resume_process`
  (`onResumed`).
- **Events.** `events()` decodes the stream through the kind's `RecordingKindSpec`. On a live recording it first
  runs the stream's flush barrier.
- **End.** `end()` computes the bounded summary in one pass over the stored batches and is idempotent.
