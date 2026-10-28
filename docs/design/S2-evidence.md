# BEA design S2: evidence, state and address model (v0.1)

> **Scope.** This file specifies BEA's Evidence record, the per-tool result envelope, process/module/effect
> state, the on-disk run store (ledger, blobs, streams), evidence queries, bundles, the unknown registry,
> redaction, and the address model with its on-disk PE reader. It is implementation-ready: file paths in the
> future repo `<repo>`, TypeScript types, zod 4.4.3 schemas, and algorithms.
>
> **Sources.** `bea-research/BRIEF.md` (cited `[BRIEF §x]`) and the nine notes (cited `[note §x]`). New lab
> runs for this design live in `bea-lab/design-S2-evidence/` and are cited `[S2-lab Ex]` (section 23).
>
> **Labels.** VERIFIED = a note or an S2 lab run established it on this host. **A#** = an assumption
> (BELIEVED, untested); the full list is in section 24. Everything else is a design decision of this file.
>
> **Fixed inputs honoured.** The orchestrator decisions: BEA_HOME/runs/<run_id>/, quotas 512 MiB ledger, 256 MiB
> per stream and 4 GiB blobs, no per-batch fsync, D5 readOnlyHint, MCP text = compact JSON equal to
> structuredContent, WoW64 unsupported, Linux best effort. BRIEF D1–D20 are the baseline.

---

## 0. Decisions at a glance

| # | Decision | Section |
|---|---|---|
| S2-1 | All IDs are `<prefix>_<64 lowercase hex>` = SHA-256 of an RFC 8785 canonical *projection*. Families: `ev_ pi_ mm_ fx_ st_ unk_` (+ reserved `query_`). Every projection carries a type tag (`schema` or `t`) for domain separation | 2.4 |
| S2-2 | BEA owns its canonicalizer (port of REA's streaming emitter), golden-tested against `canonicalize@3.0.0` (REA's pin; npm is now at 5.1.0 [S2-lab E6]) | 2.3 |
| S2-3 | TimeAnchor = `{run_id, seq, mono_ns, wall, effect_epoch, module_map_epoch}`. `run_id`+`seq` enter every live ID, so two live reads never merge, even across runs. Only `wall` is excluded | 3 |
| S2-4 | `pi_` identity = `{device_id, pid, start_time{source,value}, image_path_sha256}`. Image SHA-256 is an *attribute* (lazy, may be null). Start time comes from the OS creation FILETIME wherever possible | 4 |
| S2-5 | `mm_` identity = `{instance_id, completeness, modules[{base,size,path_sha256}]}` sorted by base. Module hashes are *not* in the map (lazy hashing of large game DLLs); they live in the PE hash cache and in AddressRefs | 5 |
| S2-6 | Identity lines carry digests; display strings (paths, names) sit in `display` sub-objects excluded from IDs, so they stay redactable without breaking authentication | 2.4, 15 |
| S2-7 | Effects are immutable creation records plus append-only transition lines. Status ∈ `active, revert-failed, reverted, expired, implicit-end, permanent`. Every create/transition bumps the instance `effect_epoch` | 6 |
| S2-8 | `perturbation = {level, active_effect_ids, tainted_by}` on every record. The session's own agent-injection effect is implied (authority `live-process` + `agent` field) and is not listed | 6.5 |
| S2-9 | Tool results are **spread envelopes**: `{...result, evidence_id, predicate_type, confidence, authority, coverage, limitations, instance_id?, module_map_id?, observed_at?, perturbation?, effects_applied?, redactions?, next?}`. Result schemas may not use reserved keys (contract test). Polls return `{...result, evidence_id:null, coverage, limitations, next?}` | 8 |
| S2-10 | Coverage = `{status: complete/partial/unknown, truncated, dropped?, reasons[]}`. **Paging is not truncation**; truncation means data was not *retained* | 7.5 |
| S2-11 | Record-before-deliver, plus record-before-reference: pi/mm/fx/blob/stream lines are on disk before the `ev` line that cites them, and that line is on disk before the reply | 9.5 |
| S2-12 | One run per server process: `BEA_HOME/runs/<run_id>/{run.json, .lock, ledger.jsonl, blobs/, streams/, tmp/}`. fsync only on stream finalize, `close_session`, export, and run finalize | 9 |
| S2-13 | Quotas per run: ledger 512 MiB (last 8 MiB reserved for lifecycle records), blobs 4 GiB, each stream 256 MiB, all streams 4 GiB (added). Hitting a quota is never silent | 9.7 |
| S2-14 | Streams store **raw agent batches** in framed chunk files (≤ 8 MiB), hash-chained from the descriptor digest. Checkpoint manifests are Evidence (`bea.stream.manifest`). Decoding happens only at query time | 10 |
| S2-15 | `get_evidence` is the single ledger read tool: `summary` (filters + paging), `complete` (any ledger ID), `slice` (page an array or blob of a retained record). It is a poll and records nothing | 12 |
| S2-16 | Bundles: a directory or zip with `bundle.json`, canonical `records.jsonl`, `blobs/` and `streams/`. Export is staged and then renamed. Import validates everything, then merges in an `import-begin … import-commit` bracket | 13 |
| S2-17 | Bundle-imported BEA records keep their authority. `origin: imported` is an index/view attribute. `authority: "imported"` is reserved for content BEA wraps from outside (Ghidra/REA symbol tables, external refs) | 7.4 |
| S2-18 | Unknowns: REA's revision chain, simplified, with `expected_revision` CAS. `accepted_authorities` is an explicit set, not an ordering. Scope is the image SHA-256 | 14 |
| S2-19 | Redaction: explicit literals only, each ≥ 4 UTF-8 bytes, scanned as text and as UTF-8 and UTF-16LE bytes. Matching fields are nulled whole; a matching stream batch is replaced by a `redacted` frame. Declarations are never persisted, only their count | 15 |
| S2-20 | Address input grammar: `0x<va>`, `<module>+0x<rva>`, `+0x<rva>` (main), `<module>!<export>[+0x<disp>]`, `<module>!#<ordinal>`, quoted modules/paths, `@0x<base>` qualifier. Separate `static_va` + optional `static_base` + optional `module` | 16 |
| S2-21 | AddressRef `{va, module, rva, static_va, static_base, static_base_source, module_map_id, image_sha256?, symbol?, section?}`. Bulk outputs use `AddressText` (`module+0xrva`) plus a `modules` legend; every AddressText parses back as input | 16.4–16.5 |
| S2-22 | BEA's own TS PE32+ reader (positioned reads, lazy tables, bounded loops) for headers, sections (long names), exports + forwarders, imports + IAT/delay-IAT slots, `.pdata` with unwind-chain resolution, relocations, CodeView, TLS. Parsed images are cached by `(path_key, size, mtime_ns, ctime_ns, ino, dev)` and SHA-256 results persist in `cache/file-sha256.jsonl`. Cross-checked against pefile [S2-lab E1] | 17 |
| S2-23 | Byte verification = live bytes vs **file bytes + base relocations**, with BEA's own patches restored from effect `before` bytes and loader-written bytes masked (IAT, delay-IAT, `fothk`, CFG pointers). VERIFIED exact on code [S2-lab E2]. Unexplained diffs → `mismatch` → confidence `inferred` | 18 |
| S2-24 | Symbolization: caller tables (Ghidra/REA, recorded as `bea.symbols.caller`) > exact or function-start exports > IAT slots > `.pdata` bounds (no fabricated names). `DebugSymbol` only as an opt-in hint | 19 |

---

## 1. Files in the future repo (this subsystem)

```
src/domain/json.ts                     JsonValue, JsonObject, jsonValueSchema
src/domain/hex.ts                      Hex type, parseHexInput, formatHex, hex schemas, bigint helpers
src/domain/canonical.ts                canonicalJson, sha256Hex, digestCanonical (streaming)
src/domain/ids.ts                      ID families, schemas, idOf(prefix, projection), RunId
src/domain/time.ts                     TimeAnchor, CompactAnchor, SeqClock, newRunId
src/domain/evidence/schema.ts          beaEvidenceSchema + invariants, BeaEvidence type
src/domain/evidence/subject.ts         Subject union
src/domain/evidence/predicates.ts      PREDICATES registry
src/domain/evidence/coverage.ts        Coverage schema, REASONS registry, combinators
src/domain/evidence/limitations.ts     LIMITATIONS catalog (fixed sentences/templates)
src/domain/evidence/location.ts        Location union, locationOf(AddressRef)
src/domain/evidence/perturbation.ts    Perturbation schema, level computation
src/domain/evidence/build.ts           buildEvidence (draft → validated record + id)
src/domain/evidence/authenticate.ts    authenticateEvidence(unknown) → Result
src/domain/evidence/envelope.ts        envelope shapes, recordedOutput/pollOutput, toEnvelope, NextStep
src/domain/process/instance.ts         ProcessIdentity, ProcessInstance, instanceIdOf, pathKey
src/domain/process/moduleMap.ts        ModuleEntry, ModuleMap, moduleMapIdOf, lookup
src/domain/effects/effect.ts           Effect, EffectKind table, EffectTransition, status machine
src/domain/unknowns/unknown.ts         ResidualUnknown, ids, revision digest, CAS update, verify rule
src/domain/redaction/literals.ts       SensitiveLiterals, spellings (UTF-8, UTF-16LE)
src/domain/redaction/redact.ts         redactExplicitText, redactJsonPayload, bytesContainLiteral
src/domain/address/grammar.ts          parseAddressString, parseModuleToken, AddressIssue
src/domain/address/addressRef.ts       AddressRef schema/type, AddressText, ModuleLegend
src/domain/address/rebase.ts           pure rebase arithmetic (bigint, range checks)
src/domain/address/verify.ts           byte-verification classifier (pure)
src/domain/address/symbolize.ts        symbol policy (pure, over PE tables + caller table)
src/pe/types.ts                        PeImage, PeSection, PeExport, PeImport, FunctionTable, PeError
src/pe/reader.ts                       parsePe(fileHandle) – headers, sections, directories
src/pe/tables.ts                       exports, imports (+delay), pdata+unwind, relocations, debug, tls, loadcfg
src/pe/imageBytes.ts                   readRva, imageBytes(rva,len,actualBase)
src/pe/PeImageCache.ts                 LRU of parsed images by FileKey
src/pe/FileHashCache.ts                persistent sha256 cache (BEA_HOME/cache/file-sha256.jsonl)
src/evidence/BeaHome.ts                BEA_HOME resolution, directory layout
src/evidence/RunStore.ts               run.json, .lock, finalize, crash marking, CLI ephemeral runs
src/evidence/Ledger.ts                 append queue, line codec, quotas, reload/recovery
src/evidence/LedgerIndex.ts            in-memory indexes and summary rows
src/evidence/BlobStore.ts              content-addressed blobs
src/evidence/StreamStore.ts            StreamWriter/StreamReader, frames, chain, checkpoints
src/evidence/Quotas.ts                 QuotaGuard
src/evidence/Recorder.ts               record pipeline (redact → build → reference closure → append → index)
src/evidence/InstanceRegistry.ts       live instances, anchors, liveness
src/evidence/ModuleMapTracker.ts       epochs, materialize-on-reference
src/evidence/EffectRegistry.ts         apply/transition/perturbation/taint
src/evidence/UnknownRegistry.ts        create/update(CAS)/list/verify
src/evidence/Bundle.ts                 export/import (directory), validation, closure
src/evidence/BundleZip.ts              zip wrapper (yazl/yauzl), traversal and bomb guards
src/evidence/FootprintScanner.ts       foreign/agent code-patch scan of a module
src/application/evidence/GetEvidence.ts      get_evidence service
src/application/evidence/ExportEvidence.ts   export_evidence service
src/application/evidence/ImportEvidence.ts   import_evidence service
src/application/evidence/RecordUnknown.ts    record_unknown service
src/application/address/MapAddress.ts        map_address service (live and pure-arithmetic)
src/application/address/AddressResolver.ts   resolve inputs for every address-taking tool
src/contracts/shared/evidenceSchemas.ts      zod fragments exported to all contracts
src/contracts/shared/addressSchemas.ts       address input shape + refine, AddressRef output schema
src/contracts/evidenceToolContracts.ts       get_evidence, export_evidence, import_evidence, record_unknown (proposal; S1 owns registry)
docs/evidence-model.md, docs/address-model.md
tests/unit/domain/{canonical,ids,evidence,coverage,effects,unknowns,redaction,address-grammar,rebase,verify,symbolize}.test.ts
tests/unit/pe/{reader,tables,imageBytes,caches}.test.ts
tests/integration/evidence/{ledger,streams,bundles,recorder,quotas}.test.ts
tests/acceptance/address/{map-address,verify-bytes,footprint}.test.ts  (real Frida, owned gcc fixture)
```

---

## 2. Primitives

### 2.1 JSON values (`src/domain/json.ts`)

```ts
import { z } from "zod";
export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [k: string]: JsonValue };
export type JsonObject = { readonly [k: string]: JsonValue };

// zod 4: z.number() already rejects NaN/±Infinity.
export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([z.null(), z.boolean(), z.number(), z.string(), z.array(jsonValueSchema), z.record(z.string(), jsonValueSchema)]),
);
export const jsonObjectSchema = z.record(z.string(), jsonValueSchema);
export const MAX_JSON_DEPTH = 64; // enforced by buildEvidence (walk), not by the schema
```

Value conventions inside records (copied from `bea-emu/0.1` [ext-backends §9.3]):
- Addresses and all 64-bit integers are canonical `Hex` strings. Integers above 2^53 never appear as numbers.
- Floats are `{type:"f32"|"f64", value: number | "NaN" | "Infinity" | "-Infinity", bits: Hex}`, and
  comparisons use `bits`.
- Times: `mono_ns` and FILETIME values are decimal strings; wall times are ISO-8601 UTC.

### 2.2 Hex (`src/domain/hex.ts`)

```ts
export type Hex = `0x${string}`;                       // canonical: lowercase, no leading zeros, "0x0" for zero
export const HEX_CANONICAL_RE = /^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/u;
export const HEX_INPUT_RE = /^0[xX][0-9a-fA-F]{1,16}$/u;  // inputs: any case, leading zeros ok
export const hexSchema = z.string().regex(HEX_CANONICAL_RE);        // records and outputs
export const hexInputSchema = z.string().regex(HEX_INPUT_RE);       // tool inputs (no transform: JSON-Schema safe)
export const formatHex = (v: bigint | number): Hex => `0x${BigInt(v).toString(16)}` as Hex;
export const parseHexInput = (s: string): bigint => BigInt(`0x${s.slice(2)}`); // after regex check
export const USER_VA_MAX = 0x7fff_ffff_ffffn;   // A13: Windows x64 user-mode ceiling (47-bit)
```

Input schemas never `.transform()`; handlers normalize. Transforms are not representable in the advertised
JSON Schema, and REA's pass-through validation pattern parses in the handler [rea-mcp §1.3].

### 2.3 Canonical JSON and digests (`src/domain/canonical.ts`)

```ts
export function canonicalJson(value: JsonValue): string;          // RFC 8785 (JCS)
export function sha256Hex(data: string | Uint8Array): string;     // lowercase hex
export function digestCanonical(value: JsonValue): string;        // streaming: never builds the whole string
```

- Semantics are exactly `canonicalize@3.0.0`, which REA pins (VERIFIED-READ REA `package.json:346`;
  `canonicalize.js` source read). Keys are sorted by UTF-16 code units, numbers use ES `Number::toString`,
  `undefined` keys are dropped, and NaN, Infinity and cycles throw.
- The implementation ports REA's `emitCanonical`/`digestCanonicalValue` streaming emitter, which flushes 8 KiB
  parts into the hash (VERIFIED-READ REA `src/domain/canonicalDigest.ts`).
- BEA does **not** depend on `canonicalize` at runtime. The npm `latest` is now 5.1.0 under a different
  license [S2-lab E6], and an ID algorithm must not drift with a dependency. `canonicalize@3.0.0` is a
  **devDependency oracle**: a property test compares both on 10,000 random JSON values, and there is a
  golden-vector test with RFC 8785 Appendix B numbers.

### 2.4 ID families (`src/domain/ids.ts`)

```ts
export const ID_PREFIXES = ["ev", "pi", "mm", "fx", "st", "unk", "query"] as const;
export type IdPrefix = (typeof ID_PREFIXES)[number];
export type EvId = `ev_${string}`; export type PiId = `pi_${string}`; export type MmId = `mm_${string}`;
export type FxId = `fx_${string}`; export type StId = `st_${string}`; export type UnkId = `unk_${string}`;
export const SHA256_RE = /^[a-f0-9]{64}$/u;
export const sha256Schema = z.string().regex(SHA256_RE);
export const idSchema = (p: IdPrefix) =>
  z.string().regex(new RegExp(`^${p}_[a-f0-9]{64}$`, "u"), `Expected a ${p}_ prefixed lowercase sha256`);
export const evIdSchema = idSchema("ev"), piIdSchema = idSchema("pi"), mmIdSchema = idSchema("mm"),
  fxIdSchema = idSchema("fx"), stIdSchema = idSchema("st"), unkIdSchema = idSchema("unk");
export const ANY_LEDGER_ID_RE = /^(ev|pi|mm|fx|st|unk)_[a-f0-9]{64}$/u;
export const idOf = <P extends IdPrefix>(p: P, projection: JsonValue): `${P}_${string}` =>
  `${p}_${digestCanonical(projection)}` as `${P}_${string}`;

export type RunId = `run_${string}`;
export const RUN_ID_RE = /^run_\d{8}T\d{6}Z_[0-9a-f]{16}$/u;          // run_20261028T014233Z_3f9a1c2e7b4d0a19
export const runIdSchema = z.string().regex(RUN_ID_RE);
```

| Family | Identifies | Projection hashed (everything else in the record is excluded) | Uniqueness comes from |
|---|---|---|---|
| `ev_` | Evidence record | the record minus `evidence_id` and minus `observed_at.wall` | content (+ `run_id`,`seq` for anchored records) |
| `pi_` | process instance | `{t:"bea.pi/1", device_id, pid, start_time:{source,value}, image_path_sha256}` | OS identity |
| `mm_` | module-map layout | `{t:"bea.mm/1", instance_id, completeness, modules:[{base,size,path_sha256}]}` (sorted by base) | content |
| `fx_` | Effect | the effect minus `effect_id`, `applied_at.wall` and `display` | `run_id`+`seq` |
| `st_` | event stream | `{t:"bea.st/1", run_id, seq, source}` | `run_id`+`seq` |
| `unk_` | residual unknown | `{t:"bea.unk/1", domain, question:normalize(q), scope_digest}` | content |
| `query_` | *reserved* (emulation/static replay cache, v0.2) | `{t:"bea.query/1", subject, operation, parameters}` | content |
| `run_` | server run | allocated: UTC second + 64 random bits | allocation |
| session/handle IDs | runtime handles (UUID v4) | never hashed into any ID, never in `parameters` | allocation |
| blob | bytes | bare sha256 of the bytes | content |
| bundle | bundle manifest | manifest minus `bundle_digest` and `created_wall` | content |

**Rule (S2-6).** Identity projections contain digests and numbers only. Any human-facing string derived from
the target (paths, module names) lives in a `display` sub-object or in the `result` of an observation record.
That keeps display strings redactable without changing IDs. This is REA's `local_path` exclusion
[rea-evidence §3.2], generalized.

### 2.5 Set-valued arrays are canonicalized

Arrays that are *sets* are sorted (UTF-16 code-unit order of their string or canonical JSON form) and
de-duplicated **before** hashing. Builders enforce this and the schema refinements reject unsorted input:
`limitations`, `evidence_links`, `effects`, `perturbation.active_effect_ids`, `perturbation.tainted_by`,
`coverage.reasons`, `locations`, `external_refs`, `blobs` (sorted by `role`, then `sha256`) and `redactions`
(sorted by `pointer`). Sequence arrays in `result` keep their order.

---

## 3. Runs, sequence clock and TimeAnchor (`src/domain/time.ts`)

```ts
export interface TimeAnchor {
  readonly run_id: RunId;
  readonly seq: number;                      // run-global, strictly increasing, starts at 1
  readonly mono_ns: string;                  // process.hrtime.bigint() at capture, decimal
  readonly wall: string;                     // ISO-8601 UTC; display only; excluded from every ID
  readonly effect_epoch: number | null;      // perturbation version of the subject instance (null: no live instance)
  readonly module_map_epoch: number | null;  // module-map epoch of the subject instance (null: no live instance)
}
export interface CompactAnchor { readonly seq: number; readonly effect_epoch: number | null; readonly module_map_epoch: number | null }

export const timeAnchorSchema = z.strictObject({
  run_id: runIdSchema,
  seq: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  mono_ns: z.string().regex(/^\d{1,20}$/u),
  wall: z.iso.datetime(),
  effect_epoch: z.number().int().min(0).max(2 ** 31).nullable(),
  module_map_epoch: z.number().int().min(0).max(2 ** 31).nullable(),
}).refine((a) => (a.effect_epoch === null) === (a.module_map_epoch === null), "epochs are both null or both set");

export class SeqClock { #n = 0; next(): number { return ++this.#n; } get current(): number { return this.#n; } }
export const newRunId = (now = new Date()): RunId =>
  `run_${now.toISOString().replace(/[-:]/gu, "").replace(/\.\d{3}Z$/u, "Z")}_${randomBytes(8).toString("hex")}` as RunId;
```

**Semantics**
- **One run = one server process** (stdio or `--http`) or one CLI invocation. `seq` totally orders every
  observation, effect transition and stream allocation in the run. This replaces the note's "session-global"
  `seq` [rea-evidence §13 Q5] because the orchestrator scoped storage per run.
- **Anchor capture.** `InstanceRegistry.capture(instance_id)` allocates `seq` and snapshots the epochs and the
  perturbation. The operation calls it while it still holds the per-instance operation lock (owned by S3; see
  21.2), right after the agent RPC resolved. Inside the lock the epochs cannot change, except for agent-side
  lifetime expiry, which makes `active_effect_ids` a conservative *superset* (documented).
- **Which records carry an anchor** is fixed per predicate (7.3):
  - Live observations always carry one.
  - Deterministic derivations do not: static PE facts, emulation from a baseline or snapshot, `map_address`
    without byte verification, and queries over sealed stream data. Their IDs therefore deduplicate, which is
    REA's semantics for static facts [rea-evidence §3.2].
  - Chained-state emulation carries an anchor with null epochs.

---

## 4. Process instances `pi_` (`src/domain/process/instance.ts`)

### 4.1 Identity

```ts
export type StartTimeSource = "os-creation-time" | "frida-started" | "first-observed";
export interface ProcessIdentity {
  readonly t: "bea.pi/1";
  readonly device_id: string;                                   // "local" in v0.1
  readonly pid: number;
  readonly start_time: { readonly source: StartTimeSource; readonly value: string };
  readonly image_path_sha256: string;                           // sha256(utf8(pathKey(main module path)))
}
export const processIdentitySchema = z.strictObject({
  t: z.literal("bea.pi/1"), device_id: z.string().min(1).max(128), pid: z.number().int().min(0).max(2 ** 32 - 1),
  start_time: z.strictObject({ source: z.enum(["os-creation-time", "frida-started", "first-observed"]),
                               value: z.string().min(1).max(64) }),
  image_path_sha256: sha256Schema,
});
export const instanceIdOf = (id: ProcessIdentity): PiId => idOf("pi", id);
```

`start_time.value`:
- `os-creation-time`: the FILETIME from `GetProcessTimes`, in 100 ns units, as a decimal string.
- `frida-started`: the ISO string exactly as Frida returned it.
- `first-observed`: the ISO time at which this run first saw the pid.

**Start-time acquisition, in order.** Stop at the first source that works and cross-check when two are
available.
1. Owned targets: jobhost `adopted.creationTime100ns` [rea-process §8.1] (VERIFIED helper protocol).
2. Any target with the agent loaded: the agent calls `kernel32!GetProcessTimes(GetCurrentProcess())`
   through `NativeFunction` and returns the creation FILETIME in its ready handshake (**A2**). For owned
   targets this must equal (1), otherwise the result is `instance_mismatch` and the spawn is aborted and
   killed.
3. Optional fallback: `bea-jobhost.exe observe <pid>`, a ~20-line C mode: OpenProcess(QUERY_LIMITED) +
   GetProcessTimes + QueryFullProcessImageNameW (requested from S-process; [rea-process §8.2] suggested it).
4. Frida `enumerateProcesses({scope:'metadata', pids:[pid]})` → `started` (ISO; precision UNVERIFIED, BRIEF L2)
   → source `frida-started` + limitation `PID_REUSE_UNEXCLUDED`.
5. `first-observed` + limitation `PID_REUSE_UNEXCLUDED`.

**Why the image digest is not in the identity.** The process is the same process whether or not BEA could hash
the file, and the file can be replaced on disk while the process runs. Hashing a 100 MB game executable is
also deferred until something needs it. `image_path_sha256` binds the identity to the main module's path
without storing the path, which stays redactable (15). Its caveat: a digest of a low-entropy path can be
guessed by dictionary, so it is not a secrecy mechanism.

**Path key** (Windows): strip `\\?\` (and turn `\\?\UNC\` into `\\`), turn `/` into `\`, apply
`path.win32.normalize`, then lowercase the whole string. Linux: `path.posix.normalize`, case preserved. Short 8.3
names are not expanded (A18).

### 4.2 Instance state (in memory; snapshot recorded as `bea.process.instance`)

```ts
export interface FileKey { readonly path_key: string; readonly size: string; readonly mtime_ns: string;
  readonly ctime_ns: string; readonly ino: string; readonly dev: string }        // fs.stat({bigint:true}) [S2-lab E4]
export interface AgentIdentity { readonly bundle_sha256: string; readonly bea_version: string; readonly runtime: "qjs" | "v8" }
export interface ProcessInstance {
  readonly instance_id: PiId;
  readonly identity: ProcessIdentity;
  readonly ownership: "owned" | "attached";                   // kill authority: owned only [rea-evidence §10.5]
  readonly image: {
    readonly display: { readonly path: string | null; readonly name: string | null };   // null when redacted
    readonly sha256: string | null;                             // lazily filled from FileHashCache; null = unknown
    readonly file: FileKey | null;
    readonly pe: { readonly machine: "x64" | "x86" | "arm64" | "unknown"; readonly image_base: Hex;
                   readonly size_of_image: number; readonly time_date_stamp: number;
                   readonly codeview: { guid: string; age: number } | null } | null;
  };
  readonly environment: { readonly platform: "win32" | "linux"; readonly os_version: string;
                          readonly arch: "x64"; readonly pointer_size: 8 };
  readonly agent: AgentIdentity;
  readonly launch: { readonly via: "frida-spawn+adopt" | "jobhost-run"; readonly argv_count: number;
                     readonly program_basename: string | null; readonly env_keys_count: number;
                     readonly env_keys_sha256: string | null; readonly argv_recorded: boolean } | null;  // owned only
  state: "suspended" | "running" | "exited" | "detached";
  exit: { code: number | null; code_hex: Hex | null; kind: "normal" | "ntstatus" | "bea-kill" | "unknown";
          name: string | null } | null;
}
```

Rules:
- `launch` stores counts and basenames only, as REA's `ProcessEvidence.ts` does [rea-evidence §3.4, §10.10].
  Verbatim argv is stored only when the spawn input opts in with `record_argv: true` (S3 contract), and then it
  passes through redaction.
- `bea.process.instance` Evidence (observed, live-process, anchored) is recorded at spawn/attach and on every
  state change. A crash conclusion is a separate derived record owned by S3 [BRIEF §3.1].
- Liveness comes only from detach events and jobhost status, never from the pid filter (VERIFIED zombie gotcha
  [ext-frida §1.3]).
- When the image file is hashed, BEA compares the file's `mtime_ns` and `ctime_ns` against the process
  creation time. Either one being later adds `IMAGE_CHANGED_ON_DISK` (cheap, conservative).

---

## 5. Module maps `mm_` and epochs (`src/domain/process/moduleMap.ts`, `src/evidence/ModuleMapTracker.ts`)

```ts
export interface ModuleEntry {
  readonly base: Hex; readonly size: number;                  // size == PE SizeOfImage (VERIFIED [S2-lab E2], 5/5 modules)
  readonly path_sha256: string;                               // sha256(utf8(pathKey(path)))
  readonly display: { readonly name: string | null; readonly path: string | null };
}
export interface ModuleMap {
  readonly module_map_id: MmId; readonly instance_id: PiId;
  readonly completeness: "complete" | "partial";              // partial: built from a single address lookup or a dump subset
  readonly modules: readonly ModuleEntry[];                   // sorted by base, non-overlapping (validated)
}
export const moduleMapIdOf = (m: Omit<ModuleMap, "module_map_id">): MmId => idOf("mm", {
  t: "bea.mm/1", instance_id: m.instance_id, completeness: m.completeness,
  modules: m.modules.map(({ base, size, path_sha256 }) => ({ base, size, path_sha256 })),
});
export function moduleAt(map: ModuleMap, va: bigint): ModuleEntry | null;   // binary search by base
```

**Epochs.**
- The agent owns the epoch counter. Its ready handshake sends `{module_epoch: 1, modules:[…]}`.
  `Process.attachModuleObserver` then sends `{bea:"mod", op:"load"|"unload", epoch, module:{name,base,size,path}}`.
  `onAdded` for loads is VERIFIED [ext-frida §3.13]; `onRemoved` for unloads is **A4**.
- The host mirrors the epoch and **never** invents one. `TimeAnchor.module_map_epoch` is the last epoch the host
  had applied when the anchor was captured.
- Every stream batch header carries the agent's current epoch (10.3), so events decode against the map of their
  own time.
- Startup loads ~150 DLLs in a game. Epochs are therefore cheap: a map is hashed only on demand (memoized per
  epoch).

**Materialize-on-reference.** A map line costs ~150 B per module, so only maps that something references are
written. On the first reference to an epoch's map (by an Evidence `subject.module_map_id`, an AddressRef, a
location or an effect target), `ModuleMapTracker.ensureRecorded(epoch)` writes:
1. the `{t:"mm", module_map}` line (idempotent by `mm_`);
2. a `bea.modules.map` Evidence (observed, live-process, anchored at materialization) with result
   `{epoch, module_count, loaded_since_previous_recorded:[name…], unloaded_since_previous_recorded:[name…]}`.

Derived records that rebase addresses link to that Evidence ID. That gives every static↔runtime mapping an
evidence chain [rea-evidence §10.2].

**Retention.** The tracker keeps every epoch referenced by a live stream or by Evidence in memory, plus the
current one, with at most 4,096 epochs per instance. Older unreferenced epochs are dropped.

**Agent cloaking.** `frida-agent.dll` is cloaked [ext-frida §3.1]. Maps are still `complete` with respect to the
target's modules, and the limitation `AGENT_CLOAKED` is attached to `bea.modules.map` and `bea.modules.list`.

---

## 6. Effects `fx_` (`src/domain/effects/effect.ts`, `src/evidence/EffectRegistry.ts`)

### 6.1 Kinds

| Kind | Class | Reversible | Taints when permanent | Notes |
|---|---|---|---|---|
| `process-spawned` | lifecycle | no (permanent) | no | owned instance creation |
| `process-suspended` | lifecycle | yes | — | active from spawn until resume |
| `process-resumed` | lifecycle | no | no | transitions the `process-suspended` effect to `reverted` |
| `process-killed` | lifecycle | no | no | permitted only when `ownership === "owned"` |
| `agent-injected` | lifecycle | yes (detach) | — | residue on end: "11 DLLs remain loaded" [ext-frida §4] |
| `hook-installed` | observe | yes | — | capture-only hooks; API-profile hooks = **one** effect per call |
| `watch-armed` | observe | yes | — | debug-register or page-guard |
| `trace-following` | observe | yes | — | Stalker |
| `override-installed` | modify | yes | — | argument/return rewrite or replacement |
| `memory-written` | modify | yes iff `before` retained in memory | yes when permanent | `write_memory` |
| `code-patched` | modify | yes iff `before` retained in memory | yes when permanent | patchCode |
| `protection-changed` | modify | yes | yes when permanent | |
| `memory-allocated` | modify | yes (freed at unload) | no | scratch for oracle calls |
| `thread-context-set` | modify | no | yes | |
| `function-called` | execute | no | **yes** | `call_function`, live leg of `diff_function`; side effects unknown |
| `script-run` | execute | no | **yes** | gated `run_script` |

`class` drives `perturbation.level`: lifecycle = `agent-only`, observe = `passive`, modify/execute = `intrusive`.

### 6.2 Records

```ts
export const EFFECT_KINDS = ["process-spawned","process-suspended","process-resumed","process-killed","agent-injected",
  "hook-installed","watch-armed","trace-following","override-installed","memory-written","code-patched",
  "protection-changed","memory-allocated","thread-context-set","function-called","script-run"] as const;
export type EffectKind = (typeof EFFECT_KINDS)[number];
export type EffectClass = "lifecycle" | "observe" | "modify" | "execute";
export type EffectStatus = "active" | "revert-failed" | "reverted" | "expired" | "implicit-end" | "permanent";

const byteStateSchema = z.strictObject({
  bytes: z.number().int().min(0).max(2 ** 32),
  sha256: sha256Schema.nullable(),              // null when redacted (15)
  hex: z.string().regex(/^(?:[0-9a-f]{2})*$/u).max(8192).nullable(),   // inline when ≤ 4096 bytes
  blob: sha256Schema.nullable(),                // blob when > 4096 bytes
  retained: z.boolean(),                         // false: not persisted (redacted); revert still uses the in-memory copy
});
const effectTargetSchema = z.strictObject({
  address: z.strictObject({ va: hexSchema, module_map_id: mmIdSchema.nullable(), module_key: z.string().max(260).nullable(),
                            rva: hexSchema.nullable() }).nullable(),
  size: z.number().int().min(0).max(2 ** 32).nullable(),
  threads: z.union([z.literal("all"), z.array(z.number().int().min(0)).max(4096)]).nullable(),
});
export const effectSchema = z.strictObject({
  schema: z.literal("bea.effect/1"),
  effect_id: fxIdSchema,
  instance_id: piIdSchema,
  kind: z.enum(EFFECT_KINDS),
  class: z.enum(["lifecycle", "observe", "modify", "execute"]),
  reversible: z.boolean(),
  target: effectTargetSchema,
  parameters: jsonObjectSchema,                 // sanitized: capture specs, lifetime bounds, gate used, ...
  before: byteStateSchema.nullable(),           // original bytes for code/data modifications; ≥32 B at hook sites (S3 req.)
  after: byteStateSchema.nullable(),
  lifetime: z.strictObject({ duration_ms: z.number().int().min(1).max(86_400_000).nullable(),
                             max_hits: z.number().int().min(1).max(1e9).nullable() }).nullable(),
  stream_ids: z.array(stIdSchema).max(16),
  applied_by: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u),      // tool name; NOT an evidence id (avoids a hash cycle)
  applied_at: timeAnchorSchema,                                  // its effect_epoch is the epoch AFTER this creation
  display: z.strictObject({ target_text: z.string().max(600).nullable() }),  // e.g. "kernel32.dll!CreateFileW"; excluded from id
});
export type Effect = z.infer<typeof effectSchema>;

export const effectTransitionSchema = z.strictObject({
  schema: z.literal("bea.effect-transition/1"),
  effect_id: fxIdSchema,
  from: z.enum(["active", "revert-failed"]),
  to: z.enum(["revert-failed", "reverted", "expired", "implicit-end"]),
  at: timeAnchorSchema,
  reason: z.enum(["stop-requested", "lifetime-duration", "lifetime-max-hits", "session-close", "process-exited",
                  "detached", "agent-unloaded", "resumed", "revert-error", "server-shutdown"]),
  verification: z.strictObject({ method: z.enum(["read-back", "agent-confirmed", "thread-context", "none"]),
                                 ok: z.boolean(), evidence_id: evIdSchema.nullable() }).nullable(),
  residue: z.array(z.string().max(300)).max(8),   // fixed sentences only (no target strings)
});
```

### 6.3 Lifecycle state machine

```
create(reversible)   ─► active
create(irreversible) ─► permanent                       (terminal; taints per 6.1)
active        ─► reverted        (explicit stop/close; verification recorded)
active        ─► expired         (agent removed it at duration/max_hits; agent-confirmed)
active        ─► revert-failed   (revert attempted; failed or unverifiable)
active        ─► implicit-end    (process exited, detached, agent unloaded)
revert-failed ─► reverted | implicit-end | revert-failed (a retry that failed again is still recorded)
terminal: reverted, expired, implicit-end, permanent
```

- Each transition is a `{t:"fxt"}` ledger line and **bumps the instance `effect_epoch`**. Creation bumps it
  too, so `effect_epoch` is a version number of the perturbation state: two observations with the same epoch
  were made under identical effect sets.
- Status is the fold of the creation record plus its transitions. A record never carries a mutable status
  field.
- `revert-failed` effects count as possibly still active. They stay in `active_effect_ids`, and a `modify`
  effect in that state taints the instance.
- Unresolved effects at session close produce `effect_unreverted` / `cleanup_incomplete` with the `fx_` IDs
  in `details.effects_applied` [BRIEF §1.6].
- Effects only ever exist on **live instances**. Emulation is sandboxed and has `perturbation.level:"none"`.

### 6.4 Registry API

```ts
export interface EffectDraft {
  instance_id: PiId; kind: EffectKind; target: z.input<typeof effectTargetSchema>; parameters: JsonObject;
  before?: Uint8Array; after?: Uint8Array; lifetime?: { duration_ms?: number; max_hits?: number };
  stream_ids?: readonly StId[]; applied_by: string; display_target?: string;
  literals: SensitiveLiterals;                  // decides whether before/after bytes can be persisted
}
export interface EffectState { readonly effect: Effect; readonly status: EffectStatus; readonly transitions: readonly EffectTransition[] }
export interface EffectRegistry {
  apply(draft: EffectDraft): Promise<Result<Effect, BeaError>>;          // seq + epoch++ + blob + fx line (record-before-reference)
  transition(id: FxId, to: EffectTransition["to"], detail: Pick<EffectTransition, "reason" | "verification" | "residue">)
    : Promise<Result<EffectState, BeaError>>;                            // validates the machine; writes fxt line; epoch++
  state(id: FxId): EffectState | undefined;
  active(instance: PiId): readonly EffectState[];                        // active ∪ revert-failed
  perturbation(instance: PiId): Perturbation;                            // see 6.5
  epoch(instance: PiId): number;
  originalBytes(instance: PiId, va: bigint, len: number): { ranges: { va: bigint; bytes: Uint8Array; fx: FxId }[] }; // for disassemble/verify
  endAll(instance: PiId, reason: "process-exited" | "detached" | "agent-unloaded" | "server-shutdown"): Promise<void>;
}
```

### 6.5 Perturbation and taint

```ts
export const perturbationSchema = z.strictObject({
  level: z.enum(["none", "agent-only", "passive", "intrusive"]),
  active_effect_ids: z.array(fxIdSchema).max(256),    // sorted; active ∪ revert-failed, excluding the session's agent-injected effect
  tainted_by: z.array(fxIdSchema).max(256),           // sorted; permanent taint effects + revert-failed modify effects
});
export type Perturbation = z.infer<typeof perturbationSchema>;
```

- `level`:
  - `none`: no live subject (image or emulation);
  - `agent-only`: only lifecycle-class effects are active;
  - `passive`: any observe-class effect is active;
  - `intrusive`: any modify- or execute-class effect is active, **or** `tainted_by` is non-empty.
- Derived records copy the union of their parents' perturbation, capped at 256 IDs plus the limitation
  `PERTURBATION_CAPPED`.
- A tainted instance adds `TAINTED(n, first3)` to every later record about it [rea-evidence §10.5].
- **The agent-injected effect is excluded from `active_effect_ids`** (S2-8). Agent presence is implied by
  authority `live-process`, the record's `agent` field and `level ≥ agent-only`. Listing it would cost ~67
  characters on every result without adding information.

---

## 7. The Evidence record

### 7.1 Schema (`src/domain/evidence/schema.ts`)

```ts
export const confidenceSchema = z.enum(["observed", "derived", "inferred"]);
export const authoritySchema = z.enum(["live-process", "emulation", "static-artifact", "imported", "analyst-inference"]);
export const CONFIDENCE_RANK = { inferred: 1, derived: 2, observed: 3 } as const;
export const AUTHORITY_TRUST = ["live-process", "emulation", "static-artifact", "imported", "analyst-inference"] as const; // strongest first

export const providerSchema = z.strictObject({
  id: z.enum(["frida", "unicorn", "bea-pe", "bea"]), name: z.string().min(1).max(64), version: z.string().max(64).nullable(),
});
export const agentSchema = z.strictObject({ bundle_sha256: sha256Schema, bea_version: z.string().max(32), runtime: z.enum(["qjs", "v8"]) });
export const blobRefSchema = z.strictObject({
  role: z.string().regex(/^[a-z][a-z0-9_.-]{0,63}$/u), sha256: sha256Schema,
  bytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER), media_type: z.string().min(1).max(100),
});
export const externalRefSchema = z.strictObject({
  system: z.enum(["rea", "ghidra", "ida", "binja", "other"]), id: z.string().min(1).max(256),   // opaque, e.g. "ev_…" from REA
  image_sha256: sha256Schema.nullable(),
});
export const redactionSchema = z.strictObject({
  pointer: z.string().max(512),                                   // RFC 6901 pointer into the record
  reason: z.literal("explicit-sensitive-value"),
  scope: z.enum(["value", "property-name", "blob", "batch", "parameter"]),
});

export const beaEvidenceSchema = z.strictObject({
  schema: z.literal("bea.evidence/1"),
  evidence_id: evIdSchema,
  predicate_type: z.string().regex(/^bea(?:\.[a-z][a-z0-9-]*){1,4}$/u).max(64),   // "bea.diff", "bea.memory.read", …
  operation: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u),        // MCP tool name that produced it
  parameters: jsonObjectSchema,                                   // identity-relevant, sanitized (7.9 step 2)
  subject: subjectSchema.nullable(),                              // 7.2
  observed_at: timeAnchorSchema.nullable(),                       // 3
  provider: providerSchema,
  agent: agentSchema.nullable(),                                  // the injected agent that produced live data
  confidence: confidenceSchema,
  authority: authoritySchema,
  perturbation: perturbationSchema,                               // 6.5
  result: jsonValueSchema,                                        // normalized result (typed per predicate)
  raw_result: jsonValueSchema.nullable(),                         // provider-native form, rarely used (REA parity)
  blobs: z.array(blobRefSchema).max(64),
  coverage: coverageSchema,                                       // 7.5
  limitations: z.array(z.string().min(1).max(1000)).max(64),
  locations: z.array(locationSchema).max(1024),                   // 7.7
  evidence_links: z.array(evIdSchema).max(4096),                  // provenance edges; must resolve in the ledger
  external_refs: z.array(externalRefSchema).max(64),              // opaque cross-tool refs (REA/Ghidra); never resolved
  effects: z.array(fxIdSchema).max(64),                           // effects THIS operation applied
  redactions: z.array(redactionSchema).max(1024),
  untrusted: z.boolean(),                                         // result holds target-derived content
}).superRefine(evidenceInvariants);
export type BeaEvidence<R extends JsonValue = JsonValue> = Omit<z.infer<typeof beaEvidenceSchema>, "result"> & { readonly result: R };
```

`evidenceInvariants(e, ctx)` (each is a unit test):
1. Every set-valued array is sorted and unique (2.5).
2. If `subject === null`: the predicate's registry entry allows `"none"`, or `limitations` contains
   `SUBJECT_UNAVAILABLE` (REA's rule [rea-evidence §3.3]).
3. If `subject.kind === "process-instance"` and `confidence === "observed"`: `observed_at` is non-null and its
   epochs are non-null.
4. If `observed_at` has non-null epochs: `subject.kind === "process-instance"`.
5. `authority === "live-process"` requires a process-instance subject (or one inherited by a derived record).
   `authority === "emulation"` requires an emulation subject.
6. `confidence ∈ {derived, inferred}` requires `evidence_links.length ≥ 1`, unless the predicate is marked
   `linkless` (`bea.symbols.caller`, `bea.unknown.mutation` with no references).
7. `perturbation.level === "none"` exactly when the subject is not a live process instance and there are no
   live parents.
8. Coverage invariants (7.5). `blobs` roles are unique per `(role, sha256)`.
9. The predicate's `anchor` rule (7.3) holds.

### 7.2 Subjects (`src/domain/evidence/subject.ts`)

```ts
export const subjectSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("process-instance"), instance_id: piIdSchema, module_map_id: mmIdSchema.nullable() }),
  z.strictObject({ kind: z.literal("image"), image_sha256: sha256Schema,
                   format: z.enum(["pe32+", "pe32", "elf64", "unknown"]), machine: z.enum(["x64", "x86", "arm64", "unknown"]) }),
  z.strictObject({ kind: z.literal("emulation"), image_sha256: sha256Schema,
                   config_digest: sha256Schema,           // digest of bridge protocol+versions, engines, session options (S4 supplies)
                   state: z.discriminatedUnion("basis", [
                     z.strictObject({ basis: z.literal("baseline") }),
                     z.strictObject({ basis: z.literal("snapshot"), snapshot_digest: sha256Schema }),
                     z.strictObject({ basis: z.literal("chained") }),        // order-dependent ⇒ anchored
                     z.strictObject({ basis: z.literal("dump"), dump_digest: sha256Schema }),
                   ]),
                   module_map_id: mmIdSchema.nullable() }),   // dump-backed: the live map the dump was taken under
]);
```

- `module_map_id` on a process subject is required (non-null) whenever the record has address locations or
  AddressRefs.
- `config_digest` is computed by S4 as `digestCanonical({protocol, bridge, engines, image_sha256, mapped_base,
  options})`, from `session.open` provenance [ext-backends §9.4, §9.7].

### 7.3 Predicate registry (`src/domain/evidence/predicates.ts`)

```ts
export interface PredicateSpec {
  readonly subjects: readonly ("process-instance" | "image" | "emulation" | "none")[];
  readonly confidence: Confidence | "per-call";                 // per-call: producer decides (documented below)
  readonly authority: Authority | "weakest-parent";             // weakest-parent: AUTHORITY_TRUST order, weakest wins
  readonly anchor: "required" | "none" | "per-call";
  readonly untrusted: boolean;
  readonly byteFields: readonly string[];                       // JSON-pointer patterns of hex/base64 byte fields (15.3)
  readonly linkless?: true;
  readonly owner: "S2" | "S3" | "S4" | "S5";
}
```

| Predicate | Produced by | Subjects | Confidence | Authority | Anchor | Owner |
|---|---|---|---|---|---|---|
| `bea.process.instance` | spawn_process, attach_process, state changes | process | observed | live-process | required | S2 shape / S3 |
| `bea.process.exit` | lifecycle | process | observed | live-process | required | S3 |
| `bea.modules.map` | Recorder (5, materialize) | process | observed | live-process | required | S2 |
| `bea.modules.list` | list_modules | process | observed | live-process | required | S3 |
| `bea.image.pe` | PE summary (disk mode) | image | observed | static-artifact | none | S2 |
| `bea.symbols.module` | list_module_symbols | image / process | observed (image) / derived (process) | static-artifact | none | S2 |
| `bea.symbols.caller` | map_address `symbols` input | image | inferred | imported / analyst-inference | none, linkless | S2 |
| `bea.address.map` | map_address | process / image | derived (inferred on mismatch) | weakest-parent | per-call (required iff bytes verified) | S2 |
| `bea.memory.ranges` / `bea.threads.list` | list_memory_ranges / list_threads | process | observed | live-process | required | S3 |
| `bea.memory.read` | read_memory | process | observed | live-process | required | S3 |
| `bea.memory.write` | write_memory | process | observed | live-process | required | S3 |
| `bea.code.disassembly` | disassemble | process / emulation / image | observed | per subject | per subject | S3 |
| `bea.memory.dump` | dump_memory | process | observed | live-process | required | S3 |
| `bea.scan.result` | scan_memory, scan_next | process | observed | live-process | required | S3 |
| `bea.instrument.install` / `.stop` | hook/watch/trace/override, stop_instrumentation | process | observed | live-process | required | S3 |
| `bea.stream.manifest` | StreamStore checkpoints (10.6) | process | observed | live-process | required | S2 |
| `bea.events.query` | query_events | process | derived | weakest-parent | none | S3 (S2 rules) |
| `bea.coverage.export` | export_coverage | process / emulation | derived | weakest-parent | none | S3 |
| `bea.call.oracle` | call_function, diff live leg | process | observed | live-process | required | S3 |
| `bea.script.run` | run_script | process | observed | live-process | required | S3 |
| `bea.emu.session` / `bea.emu.run` | emu_open / emu_call | emulation | observed | emulation | none, or required when `chained` | S4 |
| `bea.diff` | diff_function | process / emulation | derived | weakest-parent | none | S4 |
| `bea.session.status` | session_status `detail:"complete"` | process | observed | live-process | required | S3 |
| `bea.unknown.mutation` | record_unknown, auto-unknowns | none | derived | analyst-inference | none | S2 |

The emulation confidence is a deliberate resolution of a conflict between the notes. [rea-evidence §10.9] says
`observed`; [ext-backends §9.7] calls emulation a "derivation". BEA records the emulator's output as an
**observation of the emulator** (`confidence: observed`), and authority `emulation` carries the meaning "not
the real process". Rationale: the run is not computed from other Evidence, which is REA's definition of
`derived` [rea-evidence §3.5].

### 7.4 Confidence and authority rules

- `observed`: the producer directly observed it (agent RPC result, PE bytes read, emulator output).
- `derived`: a deterministic computation over other Evidence. It links its parents and must not add
  heuristics.
- `inferred`: heuristic or analyst interpretation, or a derivation whose inputs failed an identity check
  (image digest mismatch, byte mismatch).
- `weakest-parent`: a derived record takes the weakest authority among its parents under `AUTHORITY_TRUST`.
  A diff of a live oracle call and an emulator run is therefore `emulation`: a conclusion is only as strong as
  its weakest source.
- **Origin is not authority (S2-17).** A record imported from a BEA bundle keeps its authority and its ID. The
  index records `origin: {kind:"import", bundle_digest}` and summary rows show `origin:"imported"`. For
  unknown verification (14.3), imported-origin records count as authority `imported`: you can cite them, but
  they cannot verify a `live-process` claim in this run. `authority: "imported"` *inside* a record means BEA
  wrapped content supplied from outside: caller symbol tables from Ghidra/REA, or REA references.

### 7.5 Coverage and truncation (`src/domain/evidence/coverage.ts`)

```ts
export const reasonCodeSchema = z.string().regex(/^[a-z][a-z0-9_]{1,47}$/u);
export const coverageSchema = z.strictObject({
  status: z.enum(["complete", "partial", "unknown"]),
  truncated: z.boolean(),                        // some observed data was NOT retained (cap, drop, quota, redaction)
  dropped: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).exactOptional(),   // count when known (events, rows, bytes per reason doc)
  reasons: z.array(reasonCodeSchema).max(32),    // sorted unique; registry-checked by a contract test
}).superRefine((c, ctx) => {
  if (c.status === "complete" && (c.truncated || (c.dropped ?? 0) > 0)) ctx.addIssue({ code: "custom", message: "complete coverage cannot be truncated" });
  if (c.status !== "complete" && c.reasons.length === 0) ctx.addIssue({ code: "custom", message: "partial/unknown coverage needs a reason" });
  if (c.truncated && c.reasons.length === 0) ctx.addIssue({ code: "custom", message: "truncation needs a reason" });
});
export type Coverage = z.infer<typeof coverageSchema>;
export const COMPLETE: Coverage = { status: "complete", truncated: false, reasons: [] };
export function mergeCoverage(...cs: Coverage[]): Coverage;   // worst status wins (unknown > partial > complete); OR truncated; sum dropped; union reasons
```

Rules:
- Absent knowledge is `unknown`, never `complete` [rea-evidence §3.5].
- **Paging is not truncation.** A page with `next_offset` is complete if the underlying retained set is
  complete.
- Gaps yield `partial`/`unknown`, never equivalence. A diff verdict is only `equivalent-on-tested-inputs`,
  `differ` or `unknown` [rea-evidence §10.9].
- Each reason maps to a fixed limitation sentence, added **only when the reason actually occurred**
  [rea-runtime §5.3].

Reason registry (initial; the description is the doc string, the limitation key points into 7.6):

| Code | Meaning | Limitation |
|---|---|---|
| `unreadable_memory` | a read stopped or skipped an unreadable page | `UNREADABLE_MEMORY` |
| `unreadable_ranges` | a scan skipped unreadable ranges (count in `dropped` = bytes) | `UNREADABLE_RANGES` |
| `string_cap` / `frame_cap` / `value_cap` / `row_cap` | record-level caps on strings (64 KiB), backtrace frames (32), typed values (4096), table rows | `CAP(kind, n)` |
| `agent_buffer_full` / `agent_rate_limit` / `agent_payload_cap` | agent-side stream drops | `STREAM_DROPPED(n)` |
| `stream_quota` / `stream_total_quota` / `blob_quota` / `ledger_quota` | host quota reached | `QUOTA(kind, mib)` |
| `explicit_sensitive_value` | redaction removed a field, blob or batch | `REDACTED(n)` |
| `tail_unconfirmed` | stream ended without the agent's final-flush confirmation | `TAIL_UNCONFIRMED` |
| `process_exited` / `detached` / `cancelled` / `deadline` | the operation ended early | `ENDED_EARLY(reason)` |
| `malformed_pe_directory` / `pe_table_cap` | a PE table was unreadable or over its cap | `PE_TABLE(name)` |
| `module_map_partial` | the address space was only partly known | `MODULE_MAP_PARTIAL` |
| `hle_imports_used` / `emulation_deviation` / `isa_guard_stop` | emulation modeling | `EMU_*` (S4) |
| `entry_errors` | a batch had failed items (count in `dropped`) | `BATCH_ERRORS(n)` |
| `unknown_completeness` | the producer cannot assert completeness | `COMPLETENESS_UNKNOWN` |

### 7.6 Limitations catalog (`src/domain/evidence/limitations.ts`)

Limitations are fixed sentences or templates whose parameters are **BEA-controlled only**: numbers, hex, IDs and
enum codes. They never contain target-derived text such as module names or strings. The envelope outside
`result` therefore stays trustworthy prose, and target text appears only inside the untrusted `result`.

```ts
export const LIMITATIONS = {
  SUBJECT_UNAVAILABLE: "Subject identity is unavailable for this observation.",
  PID_REUSE_UNEXCLUDED: "Process start time is not the OS creation time; pid reuse cannot be fully excluded.",
  AGENT_CLOAKED: "The BEA agent module (frida-agent.dll) is cloaked and absent from module lists and range attribution.",
  AGENT_FOOTPRINT: "Attaching loaded frida-agent.dll and about 24 system DLLs, started 3 ntdll pool threads and patched a few system-DLL functions; 11 DLLs remain loaded after detach.",
  IMAGE_CHANGED_ON_DISK: "The module file changed on disk after the process started; the on-disk image may differ from the loaded image.",
  IMAGE_HASH_UNAVAILABLE: "The on-disk image could not be hashed; image identity is unverified.",
  STATIC_UNBOUND: "The static address was not bound to an image digest; pass expected_image_sha256 (Ghidra 'Executable SHA256' or the REA subject digest) to verify it refers to this build.",
  IMAGE_MISMATCH: "The supplied image digest differs from the loaded module's on-disk digest; the static address may belong to a different build.",
  CALLER_STATIC_BASE: (pe: Hex) => `The static base was supplied by the caller and differs from the PE preferred base ${pe}.`,
  PURE_ARITHMETIC: "No live module map was used; the runtime base was supplied by the caller.",
  BYTES_MISMATCH: "Live bytes differ from the on-disk image at the mapped address outside loader-written and BEA-patched ranges.",
  FOREIGN_PATCH: "Live code at the mapped address is patched by the BEA agent or another in-process component.",
  TAINTED: (n: number, ids: readonly FxId[]) => `Target state was modified by ${n} irreversible effect(s) (${ids.slice(0, 3).join(", ")}${n > 3 ? ", …" : ""}); observations may not reflect unperturbed behavior.`,
  STREAM_DROPPED: (n: number) => `${n} events were generated but not recorded; absence of an event in this stream is not evidence of absence.`,
  NOT_OBSERVED_WINDOW: "Only the recording window, threads and modules in scope were observed; other activity is unobserved, not absent.",
  TAIL_UNCONFIRMED: "The stream ended without a confirmed final flush; up to one agent batch (about 50 ms) may be missing.",
  QUOTA: (kind: string, mib: number) => `The run's ${kind} quota (${mib} MiB) was reached; later data was not retained. Set it before starting the server (BEA_*_QUOTA_MB or config.json).`,
  REDACTED: (n: number) => `${n} field(s), blob(s) or batch(es) were removed because they contained a caller-declared sensitive value.`,
  DEBUGSYMBOL_HINT: "Symbol hints from dbghelp are unverified for images without matching PDBs and may name the wrong function or module.",
  PERTURBATION_CAPPED: "More than 256 effects applied; the perturbation list is truncated.",
  MODULE_MAP_PARTIAL: "The module map was only partly known; addresses outside it could not be attributed.",
  COMPLETENESS_UNKNOWN: "The producer cannot assert that this set is complete.",
  // … full list maintained beside REASONS; a unit test pins every sentence.
} as const;
```

### 7.7 Locations, links and external references (`src/domain/evidence/location.ts`)

```ts
export const locationSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("address"), va: hexSchema, size: z.number().int().min(1).max(2 ** 32).nullable(),
                   module_map_id: mmIdSchema.nullable(), module_key: z.string().max(260).nullable(),   // lowercased basename
                   rva: hexSchema.nullable(), image_sha256: sha256Schema.nullable() }),
  z.strictObject({ kind: z.literal("thread"), thread_id: z.number().int().min(0).max(2 ** 32 - 1) }),
  z.strictObject({ kind: z.literal("file"), image_sha256: sha256Schema, offset: hexSchema, size: z.number().int().min(1).nullable() }),
]);
export const locationOf = (a: AddressRef, size?: number): Location => ({ kind: "address", va: a.va, size: size ?? null,
  module_map_id: a.module_map_id, module_key: a.module?.toLowerCase() ?? null, rva: a.rva, image_sha256: a.image_sha256 ?? null });
```

- Producers pass locations explicitly with `locationOf`. A contract test checks that every predicate whose
  result contains AddressRefs emits at least one location.
- The ledger index uses locations to answer queries such as "all evidence touching `game.exe+0x1a2b00
  .. +0x1a2c00`" across instances and runs, by `module_key`+`rva` or by `image_sha256`+`rva`.
- `evidence_links` must resolve in the ledger, or within the bundle on import. A dangling link is an integrity
  error [rea-evidence §6].
- `external_refs` are opaque and never resolved, e.g. `{system:"rea", id:"ev_…", image_sha256}`. They replace
  the BRIEF's `rea:`/`bea:` prefixing for cross-tool citations [BRIEF §1.7].

### 7.8 ID rule and authentication (`src/domain/evidence/authenticate.ts`)

```ts
export const evidenceProjection = (e: Omit<BeaEvidence, "evidence_id">): JsonValue => {
  const { observed_at, ...rest } = e;
  return { ...rest, observed_at: observed_at === null ? null : (({ wall: _w, ...a }) => a)(observed_at) };
};
export const evidenceIdOf = (e: Omit<BeaEvidence, "evidence_id">): EvId => idOf("ev", evidenceProjection(e));
export function authenticateEvidence(input: unknown): Result<BeaEvidence, BeaError> {
  const p = beaEvidenceSchema.safeParse(input);
  if (!p.success) return err(evidenceIntegrity("Evidence record does not match the bea.evidence/1 schema", { issues: p.error.issues.length }));
  const { evidence_id, ...rest } = p.data;
  return evidenceIdOf(rest) === evidence_id ? ok(Object.freeze(p.data))
    : err(evidenceIntegrity("Evidence identifier does not match its record"));
}
```

What enters the ID: everything except `evidence_id` and `observed_at.wall`. That includes `run_id`, `seq`,
`mono_ns`, the epochs, perturbation, limitations, redactions and `untrusted`. Blob paths are never stored, so
they need no exclusion. Records are frozen after parse; REA's sealed-snapshot machinery is not copied
[rea-evidence §12].

### 7.9 Building and recording (`src/domain/evidence/build.ts`, `src/evidence/Recorder.ts`)

```ts
export interface EvidenceDraft<R extends JsonValue> {
  predicate_type: PredicateType; operation: string;
  input: JsonObject;                                 // raw validated tool input
  identityExclude?: readonly string[];               // contract-declared delivery/handle keys (added to defaults)
  subject: { kind: "process-instance"; instance_id: PiId } | z.infer<typeof subjectSchema> | null;
  capture?: AnchorCapture;                           // from InstanceRegistry.capture() — required for anchored predicates
  provider: z.infer<typeof providerSchema>; agent?: AgentIdentity | null;
  confidence?: Confidence; authority?: Authority;    // when the registry says per-call
  result: R; raw_result?: JsonValue | null;
  blobs?: readonly BlobRef[]; coverage: Coverage; limitations?: readonly string[];
  locations?: readonly Location[]; evidence_links?: readonly EvId[]; external_refs?: readonly ExternalRef[];
  effects?: readonly FxId[]; literals: SensitiveLiterals;
}
export interface AnchorCapture { anchor: TimeAnchor; module_map_id: MmId; perturbation: Perturbation; tainted_count: number }
export interface RecordedEvidence<R extends JsonValue> { readonly record: BeaEvidence<R>; readonly outcome: "added" | "duplicate" }
export interface Recorder {
  record<R extends JsonValue>(draft: EvidenceDraft<R>, opts?: { lifecycle?: boolean }): Promise<Result<RecordedEvidence<R>, BeaError>>;
}
```

Pipeline. Each step is a separate, unit-tested pure function except the I/O steps 6–8.
1. **Registry check.** The predicate exists, the subject kind is allowed, and an anchor capture is present iff
   required.
2. **Parameters.** Start from `input` and delete the default delivery/handle keys plus any contract
   `identityExclude` keys.
   - Default keys: `session_id`, `detail`, `offset`, `limit`, `format`, `next`, `timeout_ms` (wait-style
     only), `overwrite`, `sensitive_values`.
   - Replace `sensitive_values` with `sensitive_value_count` (an integer, only when > 0)
     [rea-evidence §7].
   - Drop any parameter that contains a literal; that adds a redaction with scope `parameter`.
   - A delivery argument never reaches the provider and never changes the evidence identity
     [rea-evidence §5.2].
3. **Subject.** Fill `module_map_id` from the capture for process subjects. Call `ensureRecorded(epoch)` (5)
   and add the resulting `bea.modules.map` ID to `evidence_links` when the record rebases addresses.
4. **Perturbation and limitations.**
   - Copy perturbation from the capture; derived records take the union over parents.
   - Add `TAINTED` if `tainted_by` is non-empty.
   - Add the limitation for every coverage reason.
   - Add `SUBJECT_UNAVAILABLE` when the subject is null and the predicate is not subjectless.
   - Then sort and deduplicate.
5. **Redaction** (15): result payload and byte fields, then blobs (before they are stored), then `display`
   sub-objects of referenced lines.
6. **Validate** with `beaEvidenceSchema` (with a placeholder ID), compute the ID, then re-validate. A bound
   check walks the result: depth ≤ 64, the canonical record ≤ 4 MiB (`MAX_RECORD_BYTES`). Exceeding it is a
   programming error; the budget tests in 22 make it unreachable.
7. **Reference closure (record-before-reference).** Write any missing `pi`/`mm` lines and the materialized
   `bea.modules.map` Evidence. Effects, blobs and stream descriptors are already on disk because their
   producers wrote them first.
8. **Append** the `{t:"ev"}` line and await the write. **Index.** The outcome is `"added"`, or `"duplicate"`
   when the same ID already exists with identical canonical bytes. The same ID with different bytes gives
   `evidence_integrity_mismatch` [rea-evidence §4].
9. Return. The caller then builds the envelope (8) and delivers.

Measured cost: about **48 µs per 1.86 KB record** for double canonicalization, SHA-256, a synchronous append and
indexing [S2-lab E5]. That is negligible beside a ~1 ms agent RPC [ext-frida §1.7].

---

## 8. The compact result envelope (`src/domain/evidence/envelope.ts`)

### 8.1 Shape

Every tool's `structuredContent` is the envelope, and `content[0].text` is `JSON.stringify(envelope)`: the same
data, compact, REA-compatible [rea-mcp §1.6]. Result fields are **spread at the top level**, as in the
orchestrator's example. The envelope adds the reserved keys:

```ts
export const ENVELOPE_RESERVED_KEYS = ["evidence_id", "predicate_type", "confidence", "authority", "coverage", "limitations",
  "instance_id", "module_map_id", "observed_at", "perturbation", "effects_applied", "redactions", "next"] as const;

export const compactAnchorSchema = z.strictObject({ seq: z.number().int().min(1),
  effect_epoch: z.number().int().min(0).nullable(), module_map_epoch: z.number().int().min(0).nullable() });
export const nextStepSchema = z.strictObject({
  tool: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u),
  arguments: jsonObjectSchema,                 // must parse with the target tool's input schema (contract test)
  reason: z.string().min(1).max(200),          // BEA-authored, no target text
});
export const recordedEnvelopeShape = {
  evidence_id: evIdSchema,
  predicate_type: z.string().max(64),
  confidence: confidenceSchema,
  authority: authoritySchema,
  coverage: coverageSchema,
  limitations: z.array(z.string()).max(64),
  instance_id: piIdSchema.exactOptional(),                // live-process subjects
  module_map_id: mmIdSchema.exactOptional(),              // when addresses are involved
  observed_at: compactAnchorSchema.exactOptional(),       // anchored records
  perturbation: z.strictObject({ level: perturbationSchema.shape.level,
                                 active_effect_ids: z.array(fxIdSchema).max(256), tainted: z.boolean() }).exactOptional(),
  effects_applied: z.array(fxIdSchema).max(64).exactOptional(),     // present iff non-empty
  redactions: z.number().int().min(1).exactOptional(),              // count; present iff > 0
  next: z.array(nextStepSchema).max(3).exactOptional(),
} as const;
export const pollEnvelopeShape = {
  evidence_id: z.null(),                                  // not recorded (polls, ledger reads, exports)
  coverage: coverageSchema,
  limitations: z.array(z.string()).max(64),
  next: z.array(nextStepSchema).max(3).exactOptional(),
} as const;

export function recordedOutput<S extends z.ZodRawShape>(result: S) {
  assertNoReservedKeys(result);                           // throws at registry build time
  return z.strictObject({ ...result, ...recordedEnvelopeShape });
}
export function pollOutput<S extends z.ZodRawShape>(result: S) {
  assertNoReservedKeys(result);
  return z.strictObject({ ...result, ...pollEnvelopeShape });
}
export function toEnvelope<R extends JsonValue, P extends JsonObject>(
  rec: RecordedEvidence<R>, project: (result: R) => P, next?: readonly NextStep[]): P & RecordedEnvelope;
```

- Contracts declare `recording: "always" | "never"`, which chooses `recordedOutput` or `pollOutput` (S1's
  `ToolContract` gains that field).
- Polls: `bea_status`, `session_status` (except `detail:"complete"`), `wait`, `scan_results`, `get_evidence`,
  `export_evidence`, `import_evidence`.
- `scan_results` pages a retained scan; S3 decides whether the scan subsystem records evidence there.
- Errors never use the envelope. They use the error projection, which carries `details.effects_applied` and
  `details.partial_observation:{kind:"retained-evidence", evidence_id}` [BRIEF §1.6].
- Result schemas must not use reserved keys **at the top level**. Nested objects such as
  `AddressRef.module_map_id` are fine. A tool whose result "has an instance ID" (`spawn_process`) gets it
  through the envelope's `instance_id`. Paging metadata is `page:{offset, limit, total, next_offset}`, never
  `coverage`.

### 8.2 What goes inline and what is retained

| Data | Inline in the envelope | Retained (via `evidence_id`) |
|---|---|---|
| Operation result | the projection `project(record.result, delivery args)` | full normalized result |
| Memory bytes | ≤ 64 KiB, as hex or base64 per `format` (the record always stores hex) | > 64 KiB: blob + 256-byte preview inline |
| Typed values | ≤ 4,096 values | blob (NDJSON) beyond that; `value_cap` if not retained at all |
| Lists (modules, ranges, threads, symbols, events, scan hits) | one page (tool limit ≤ 500 rows, default 50–100) + `page` | full table retained (NDJSON blob, or a deterministic static recomputation); page again with `get_evidence detail:"slice"` |
| Target strings | ≤ 4,096 characters per field | record cap 64 KiB per string (`string_cap`) |
| Backtraces | ≤ 32 frames as AddressText + legend | same |
| Stream events | never inline in install tools; only `query_events` pages | raw chunks + manifests |
| Dumps, coverage files, exports | `{path?, bytes, sha256}` + bounded preview | blob, or the caller's file |
| Provider/agent versions, parameters, locations, links, blob refs, redaction pointers, full anchor (`run_id`, `mono_ns`, `wall`), stream chunk digests | no | yes |

Budget: the largest inline payload is about 128 KiB of hex plus envelope, far below the stdio budget (10 MiB −
1 KiB, counted about twice [rea-mcp §4.2]). A contract test computes each tool's **worst-case envelope bytes**
from schema bounds (max lengths × max item sizes) and fails above 2 MiB. If delivery still overflows, S1's
Delivery returns `resource_constraint{resource:"transport"}` with `details.evidence_reference` and a
continuation `{name:"get_evidence", arguments:{detail:"slice", id, pointer, offset:0, limit:100}}`. The data is
already retained (record-before-deliver).

### 8.3 Example (read_memory, live)

```json
{"address":{"va":"0x7ff7a8a11760","module":"fixture_gcc.exe","rva":"0x1760","static_va":"0x140001760","static_base":"0x140000000","static_base_source":"pe-header","module_map_id":"mm_…","image_sha256":"…","symbol":{"name":"physics_step","kind":"export","offset":"0x0","source":"pe-export"}},
 "requested_bytes":64,"returned_bytes":64,"complete":true,"format":"hex","data":"554889e5…",
 "evidence_id":"ev_…","predicate_type":"bea.memory.read","confidence":"observed","authority":"live-process",
 "coverage":{"status":"complete","truncated":false,"reasons":[]},"limitations":[],
 "instance_id":"pi_…","module_map_id":"mm_…","observed_at":{"seq":412,"effect_epoch":3,"module_map_epoch":2},
 "perturbation":{"level":"passive","active_effect_ids":["fx_…"],"tainted":false}}
```

CLI: the same envelope, rendered as TOON by default or `--json`.

---

## 9. Storage: BEA_HOME and runs

### 9.1 Layout (`src/evidence/BeaHome.ts`)

BEA_HOME is `BEA_HOME` env, else `%LOCALAPPDATA%\bea` (win32) or `${XDG_DATA_HOME:-~/.local/share}/bea` (linux).

```
BEA_HOME/
  config.json                               (owned by the config subsystem; quotas in 9.7)
  cache/file-sha256.jsonl                   FileHashCache (17.6)
  runs/<run_id>/
    run.json                                RunHeader (replaced atomically: tmp + rename)
    .lock                                   created with 'wx' at start; {pid, started_wall}; removed on clean finalize
    ledger.jsonl                            append-only canonical lines (9.3)
    blobs/<sha256>                          content-addressed bytes (flat directory)
    streams/<st_id>/descriptor.json         canonical StreamDescriptor
    streams/<st_id>/chunk-000000.bin …      framed raw agent batches (10.3)
    streams/<st_id>/chain.jsonl             one line per sealed chunk
    tmp/                                    staging: blob writes, imports, in-run export staging
  venv/                                     emulator venv (owned by S4)
```

### 9.2 Run lifecycle (`src/evidence/RunStore.ts`)

```ts
export const runHeaderSchema = z.strictObject({
  schema: z.literal("bea.run/1"), run_id: runIdSchema, kind: z.enum(["mcp-stdio", "mcp-http", "cli"]),
  bea_version: z.string(), node: z.string(), platform: z.enum(["win32", "linux"]), pid: z.number().int(),
  started_wall: z.iso.datetime(), ended_wall: z.iso.datetime().nullable(),
  status: z.enum(["open", "closed", "crashed"]),
  quotas: z.strictObject({ ledger_bytes: z.number().int(), ledger_reserve_bytes: z.number().int(), stream_bytes: z.number().int(),
                           stream_total_bytes: z.number().int(), blob_bytes: z.number().int() }),
  final: z.strictObject({ ledger_bytes: z.number().int(), ledger_sha256: sha256Schema, lines: z.number().int(),
                          evidence: z.number().int(), effects: z.number().int(), blobs: z.number().int(),
                          blob_bytes: z.number().int(), streams: z.number().int() }).nullable(),
});
```

- **Start.** Create the run directory, `.lock`, `run.json` (status `open`), and the first ledger line
  `{t:"run"}`. Then scan sibling runs: any `open` run whose lock pid is not alive becomes `crashed`
  (`run.json` only; no other change).
- **Finalize**, on clean shutdown, after S3 kills owned targets (BRIEF shutdown order):
  1. end open streams (`server-shutdown`) and record their final manifests;
  2. end remaining effects (`implicit-end`/`server-shutdown`);
  3. append `{t:"end"}`;
  4. fsync the ledger, the run's new blobs and its chunk files;
  5. write `run.json` with status `closed` and `final`;
  6. remove `.lock`.
- **Crashed runs are read-only.** Readers (CLI show/export) ignore a torn final ledger line (no `\n`) and report
  unsealed chunk bytes as `unsealed_bytes` without modifying the files.
- **CLI runs** (`kind:"cli"`) are regular runs that are deleted at exit unless `--keep-run` is given or
  `--evidence-out <bundle>` was exported first (REA parity: the CLI publishes bundles [rea-evidence §2.6]).
- **Multiple MCP clients** under `bea mcp --http` share the server's single run. One writer, serialized queues.

### 9.3 Ledger lines (`src/evidence/LedgerLines.ts`)

Each line is `canonicalJson(line) + "\n"`; the maximum line size is 4 MiB.

```ts
export type LedgerLine =
  | { t: "run"; run_id: RunId; bea_version: string; started_wall: string }
  | { t: "pi"; instance_id: PiId; identity: ProcessIdentity }
  | { t: "mm"; module_map: ModuleMap }
  | { t: "fx"; effect: Effect }
  | { t: "fxt"; transition: EffectTransition }
  | { t: "ev"; record: BeaEvidence }
  | { t: "unk"; revision: ResidualUnknown }
  | { t: "import-begin"; import_id: string; bundle_digest: string; source_runs: RunId[] }
  | { t: "import-commit"; import_id: string; counts: ImportCounts }
  | { t: "end"; ended_wall: string; counts: LedgerCounts };
```

Reading a line authenticates every self-identifying payload: `pi`/`mm`/`fx`/`ev` recompute their IDs and `unk`
recomputes `revision_digest`. Lines between an `import-begin` and its missing `import-commit` are ignored (an
uncommitted import).

### 9.4 Index (`src/evidence/LedgerIndex.ts`)

```ts
interface EvidenceIndexRow {                     // == get_evidence summary row (12.2) + offsets
  evidence_id: EvId; n: number /* ledger ordinal */; offset: number; length: number;
  predicate_type: string; operation: string; instance_id: PiId | null; module_map_id: MmId | null; seq: number | null;
  confidence: Confidence; authority: Authority; coverage_status: Coverage["status"]; truncated: boolean;
  limitation_count: number; effect_count: number; link_count: number; blob_bytes: number;
  origin: { kind: "local" } | { kind: "import"; bundle_digest: string };
  applied_effects: FxId[]; under_effects: FxId[]; stream_id: StId | null; links: EvId[];
}
```

Maps kept:
- `byId`
- `byInstance`, `byPredicate`, `byOperation`
- `byAppliedEffect`, `byUnderEffect` (perturbation)
- `byStream`
- `childrenOf` (reverse links)
- `bySeq` (sorted array)
- `byLocation`: per `module_key` and per `image_sha256`, a sorted `rva` array; per `module_map_id`, a sorted
  `va` array
- effects: `fxById` with the folded `EffectState`
- unknowns: heads and revisions
- `instances` (identity + last snapshot evidence)
- `mmById`

Full records are read on demand (`pread offset,length`) and authenticated, with an LRU cache of 2,048 parsed
records. Reloading an existing run costs ~23 µs/record with authentication [S2-lab E5], so a full 512 MiB ledger
(~290 k records) takes ~7 s. Only CLI/inspection of old runs does that; a live server never reloads.

### 9.5 Record-before-deliver and write ordering (`src/evidence/Ledger.ts`)

- A single **append queue** per run (a promise chain) does `FileHandle.write` on `ledger.jsonl` opened `'a'`.
  Writes never interleave. Seq allocation is synchronous and independent of the queue.
- **Order inside one operation:**
  1. the effect `fx` line(s) and their before/after blobs, when the effect is applied (record-before-reference);
  2. `pi`/`mm` + `bea.modules.map` lines when first referenced;
  3. stream descriptor files, before the effect that feeds the stream is reported;
  4. the `ev` line;
  5. the in-memory index update;
  6. the envelope is returned.
- **Failure handling:**

  | Where | Result |
  |---|---|
  | Validation (a bug) | `execution_failure` + `details.effects_applied` |
  | Disk or quota at step 1–4 | `resource_constraint{resource:"disk", quota}` or `file_operation_failed`, plus `details.effects_applied`. A success is never shown without retention [rea-evidence §4] |
  | Cancellation after the observation | still record (steps 1–5), then return `cancelled` with `details.partial_observation` (the SDK suppresses the reply, so the ledger is how it is found later [BRIEF §1.9]) |
  | Lifecycle writes (fxt, close, final manifests) | may use the reserve (9.7) and never block cleanup. If even the reserve is exhausted, cleanup still happens and the tool returns `resource_constraint` with `details.cleanup_completed:true` |

### 9.6 Durability

- No fsync per record or batch (orchestrator).
- fsync happens on:
  - stream finalize: the chunk files, then the ledger after the final manifest;
  - `close_session` (ledger);
  - export (ledger, before the snapshot read);
  - run finalize (ledger, new blobs, chunks).
- Directory fsync is best-effort; it is unsupported on win32, where errors are ignored (A7).
- **What is lost when.** If the BEA **process** crashes, completed `write()`s are in the OS cache and survive
  (A10). If the **OS** crashes or loses power, data after the last fsync may be lost or torn. The loss is
  detected (torn lines; blob or chunk digest mismatch on read, export or import) and never silently accepted.

### 9.7 Quotas (`src/evidence/Quotas.ts`)

| Quota | Default | Env | config.json key | Bounds | Behaviour at the limit |
|---|---|---|---|---|---|
| Ledger per run | 512 MiB | `BEA_LEDGER_QUOTA_MB` | `evidence.ledger_quota_mb` | 16–65,536 | Non-lifecycle records are refused once usage exceeds quota − reserve. `resource_constraint{resource:"disk", quota:"ledger"}`, not retryable in this run |
| Ledger lifecycle reserve | 8 MiB | `BEA_LEDGER_RESERVE_MB` | `evidence.ledger_reserve_mb` | 1–256 | Only fxt, close, process-exit and final-manifest records may use it |
| Blobs per run | 4,096 MiB | `BEA_BLOB_QUOTA_MB` | `evidence.blob_quota_mb` | 16–1,048,576 | The blob is not stored. The producing tool returns `resource_constraint{quota:"blobs"}`, or `blob:null` with `blob_quota` truncation when it has a degraded mode |
| Per stream | 256 MiB | `BEA_STREAM_QUOTA_MB` | `evidence.stream_quota_mb` | 1–65,536 | The stream ends with `end_reason:"quota"`. Host drops are counted as `stream_quota`, and the `onQuota` callback tells S3 to stop the instrument |
| All streams per run (added) | 4,096 MiB | `BEA_STREAM_TOTAL_QUOTA_MB` | `evidence.stream_total_quota_mb` | 16–1,048,576 | Same, reason `stream_total_quota` |

- Precedence: env > config.json > default. Values are read once at server start.
- An invalid value is `configuration_invalid`; the server refuses to start, except `bea doctor` [rea-cli §2].
- Every quota error and limitation names the knob, e.g. "Set BEA_STREAM_QUOTA_MB before starting the server".
- `ENOSPC` maps to `resource_constraint{resource:"disk", reason:"no_space"}`.
- `bea_status` shows usage against each quota (21.1, `EvidenceStatus`).

---

## 10. Streams (`src/evidence/StreamStore.ts`)

### 10.1 Purpose and rule

Hook calls, watch hits, Stalker events, first-chance exceptions, module load/unload, thread events and an owned
target's stdout/stderr are **streams**, never per-event Evidence [rea-evidence §10.6]. Throughput is the reason:
the agent delivers about 1.0–1.2 M events/s in batches [ext-frida §1.9], while per-event canonicalization costs
~2.74 µs (~365 k/s) [rea-evidence §8]. Raw batches are stored as they arrive, and decoding happens on query
[BRIEF §1.7].

### 10.2 Descriptor

The field layouts belong to S3; S2 defines the container.

```ts
export const streamDescriptorSchema = z.strictObject({
  schema: z.literal("bea.stream.descriptor/1"),
  stream_id: stIdSchema,
  source: z.strictObject({
    kind: z.enum(["hook", "api-profile", "watch", "trace", "exceptions", "modules", "threads", "stdout", "stderr", "call-coverage"]),
    instance_id: piIdSchema, effect_id: fxIdSchema.nullable(), channel: z.string().regex(/^[a-z][a-z0-9_-]{0,31}$/u),
  }),
  encoding: z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("fixed-records"), record_bytes: z.number().int().min(1).max(65536),
      fields: z.array(z.strictObject({ name: z.string().max(64), offset: z.number().int().min(0),
        type: z.enum(["u8", "u16", "u32", "u64", "i32", "i64", "f32", "f64", "ptr"]) })).max(256),
      var_tail: z.boolean() }),           // var_tail: a u32 length + UTF-8/UTF-16LE payload follows each record (decoded strings)
    z.strictObject({ kind: z.literal("ndjson") }),
    z.strictObject({ kind: z.literal("bytes") }),          // stdout/stderr
  ]),
  decoders: jsonValueSchema,                               // S3: typed arg specs, profile API table, string decoders
  seq: z.literal("implicit"),                              // record i of a frame has seq = first_seq + i
});
```

`st_ = idOf("st", {t:"bea.st/1", run_id, seq, source})`, where `seq` is allocated when the stream opens. The
descriptor is written canonically **before** the feeding effect's `fx` line, and `descriptor_sha256 =
sha256(file bytes)`.

### 10.3 Chunk files and frames

```
chunk-NNNNNN.bin := Frame*            (NNNNNN = zero-padded chunk index)
Frame            := header_len:u32le  header:UTF-8 canonical JSON  payload_len:u32le  payload:bytes
FrameHeader      := { k: "batch" | "redacted" | "gap",
                      first_seq: number, count: number,          // records in payload (batch) or covered (redacted/gap)
                      dropped_before: number,                    // agent drops immediately before first_seq
                      recv_mono_ns: string,                      // host receipt time
                      module_map_epoch: number | null,           // agent module epoch at flush (5)
                      final?: true,                              // agent confirmed final flush (process exit or stop)
                      layout_rev: 1 }
```

- The payload is the agent's `send(meta, ArrayBuffer)` data, unchanged ("raw batch chunks").
- **Sequence accounting** (a requirement on the S3 agent): the agent numbers every *generated* event, including
  dropped ones. A gap in `seq` between frames equals `dropped_before`, and `last_generated_seq` equals
  `records + dropped + redacted`. This makes drops detectable even if a header is wrong.
- **Sealing.** A chunk is sealed when it reaches 8 MiB, at a checkpoint, or when the stream ends.
  - `chunk_sha256 = sha256(file bytes)`
  - `chain_i = sha256_hex("bea.stream.chain/1\n" + chain_{i-1} + "\n" + chunk_sha256_i)`
  - `chain_{-1} = descriptor_sha256`
  - Each sealed chunk appends a line to `chain.jsonl`:
    `{index, file, sha256, bytes, frames, records, first_seq, last_seq, dropped, redacted, chain}`.
- The bench showed chained chunk hashing is cheap: 49 chunks in 435 ms including JSONL generation
  [rea-evidence §8]. Here hashing raw bytes is cheaper still.

### 10.4 Writer and reader API

```ts
export interface StreamWriter {
  readonly stream_id: StId; readonly descriptor_sha256: string;
  appendBatch(h: { first_seq: number; count: number; dropped_before: number; module_map_epoch: number | null; final?: boolean },
              payload: Uint8Array): void;                     // sync enqueue; quota + redaction scan; never throws on quota
  checkpoint(signal?: AbortSignal): Promise<Result<RecordedEvidence<StreamManifest>, BeaError>>;  // flush barrier + seal + manifest
  end(reason: StreamEndReason): Promise<Result<RecordedEvidence<StreamManifest>, BeaError>>;
  readonly counters: { records: number; dropped: number; redacted: number; bytes: number; state: "live" | "ended" };
  onQuota(cb: () => void): void;
}
export type StreamEndReason = "stopped" | "expired" | "process-exited" | "detached" | "quota" | "server-shutdown" | "agent-error";
export interface StreamReader {
  verify(): Promise<Result<{ head_chain: string; chunks: number }, BeaError>>;          // recompute digests + chain
  records(range: { from_seq?: number; to_seq?: number }, signal?: AbortSignal):
    AsyncIterable<{ seq: number; module_map_epoch: number | null; fields: JsonObject }>;   // decoded per descriptor
  gaps(range?: { from_seq?: number; to_seq?: number }): readonly { from_seq: number; to_seq: number; kind: "dropped" | "redacted" }[];
}
export interface StreamStore { open(d: Omit<StreamDescriptor, "stream_id" | "schema">): Promise<Result<StreamWriter, BeaError>>;
  reader(id: StId): StreamReader; }
```

**Checkpoint protocol** (live streams):
1. The host calls agent RPC `flush(stream)`, which returns `{last_generated_seq}`.
2. The host waits until it has appended frames up to that seq. Frida delivers the script's `send()` messages
   and the RPC reply on one ordered channel (**A5**).
3. Seal the open chunk.
4. Record the manifest.

`query_events` on a live stream always checkpoints first, so a query result links to a manifest that covers
exactly the queried range.

### 10.5 Redaction in streams

The writer scans each payload with `bytesContainLiteral` (UTF-8 and UTF-16LE spellings, 15.2). On a hit, the
frame is written as `k:"redacted"` with an empty payload and the same `first_seq`/`count`. Those records count as
`redacted`, and the reason `explicit_sensitive_value` is set. This deliberately over-redacts: a batch is never
partially rewritten, because rewritten bytes would be fabricated [rea-evidence §7]. The literal set is fixed when
the stream opens: the instrument call's `sensitive_values` plus the server-level list.

### 10.6 Manifest Evidence (`bea.stream.manifest`)

```ts
export const streamManifestSchema = z.strictObject({
  stream_id: stIdSchema,
  source: z.strictObject({ kind: streamDescriptorSchema.shape.source.shape.kind, channel: z.string(), effect_id: fxIdSchema.nullable() }),
  state: z.enum(["live", "ended"]),
  end_reason: z.enum(["stopped", "expired", "process-exited", "detached", "quota", "server-shutdown", "agent-error"]).nullable(),
  descriptor_sha256: sha256Schema,
  chunks: z.array(z.strictObject({ index: z.number().int(), sha256: sha256Schema, bytes: z.number().int(), records: z.number().int(),
                                   first_seq: z.number().int().nullable(), last_seq: z.number().int().nullable() })).max(4096),
  head_chain: sha256Schema,
  records: z.number().int(), dropped: z.number().int(), redacted: z.number().int(),
  drop_reasons: z.record(reasonCodeSchema, z.number().int().min(1)),
  first_seq: z.number().int().nullable(), last_seq: z.number().int().nullable(),
  started: compactAnchorSchema, checkpoint: compactAnchorSchema,
  concurrent_effect_ids: z.array(fxIdSchema).max(256),      // effects active at any time in the window, except the source
  tail_confirmed: z.boolean(),
  bytes: z.number().int(),
});
```

- Each checkpoint produces a new manifest record. The `stream_id` is the same and `seq` advances, so IDs differ.
  The newest manifest supersedes the others for delivery; the ledger keeps all of them [rea-evidence §10.6].
- **Coverage of a manifest** (for its window `[started, checkpoint]`):

  | Situation | Coverage |
  |---|---|
  | `dropped == 0 ∧ redacted == 0`, and either `state=="live"` with the checkpoint flush confirmed, or `end_reason ∈ {stopped, expired}`, or `end_reason == "process-exited" ∧ tail_confirmed` | `complete` |
  | otherwise | `partial`, with reasons from `drop_reasons`, `explicit_sensitive_value`, `tail_unconfirmed`, `stream_quota` … and `truncated: dropped+redacted > 0` |
  | the agent died without any final flush and the host cannot bound the loss | `unknown` (`tail_unconfirmed`) |

- Every manifest carries `NOT_OBSERVED_WINDOW`. Absence of an event is never evidence of absence.
- Queries and aggregations over a stream are **derived** Evidence (`bea.events.query`) with
  `evidence_links: [manifest ev_]` and `parameters` = filter. Their coverage is the manifest's coverage merged
  with the query's own, and they carry no anchor (deterministic over sealed data).

---

## 11. Blobs (`src/evidence/BlobStore.ts`)

```ts
export interface BlobStore {
  put(src: Uint8Array | AsyncIterable<Uint8Array>, meta: { role: string; media_type: string; literals: SensitiveLiterals },
      signal?: AbortSignal): Promise<Result<BlobRef | { redacted: true }, BeaError>>;
  has(sha256: string): boolean; size(sha256: string): number | undefined;
  open(sha256: string): Promise<Result<FileHandle, BeaError>>;
  read(sha256: string, offset: number, length: number): Promise<Result<Buffer, BeaError>>;
  verify(sha256: string, signal?: AbortSignal): Promise<Result<true, BeaError>>;   // rehash (export/import)
}
```

- **Write.** Stream into `tmp/blob-<16hex>` while hashing; check the quota against the declared size (or
  incrementally); scan for literals (15). Then rename to `blobs/<sha256>`. If that blob already exists, delete
  the temp file (dedup). No fsync until finalize (9.6).
- Media types:
  - `application/octet-stream`: raw memory or dumps;
  - `application/x-ndjson`: retained tables, one canonical JSON row per line, enabling slices;
  - `application/json`;
  - `application/x-drcov`.
- **NDJSON tables** support row slicing in `get_evidence`. Line offsets are computed on first access and cached
  per blob.
- A blob is never deleted during a run. The prune command deletes whole closed runs.

---

## 12. `get_evidence` (`src/application/evidence/GetEvidence.ts`)

### 12.1 Input (proposal for S1's registry; root flat with refinements [rea-mcp §3.1])

```ts
export const evidenceFiltersSchema = z.strictObject({
  evidence_id: evIdSchema.optional(),
  instance_id: piIdSchema.optional(),
  predicate_type: z.string().max(64).optional(),
  operation: z.string().max(64).optional(),
  applied_effect_id: fxIdSchema.optional(),          // records that applied this effect
  under_effect_id: fxIdSchema.optional(),            // records observed while it was active (perturbation)
  stream_id: stIdSchema.optional(),
  module_map_id: mmIdSchema.optional(),
  links_to: evIdSchema.optional(),                   // children: records whose evidence_links include it
  seq_from: z.number().int().min(1).optional(), seq_to: z.number().int().min(1).optional(),
  confidence: confidenceSchema.optional(), authority: authoritySchema.optional(),
  coverage_status: z.enum(["complete", "partial", "unknown"]).optional(),
  origin: z.enum(["local", "imported"]).optional(),
  module: z.string().min(1).max(260).optional(),     // location filter: basename (case-insensitive) …
  image_sha256: sha256Schema.optional(),             // … or image digest
  rva_from: hexInputSchema.optional(), rva_to: hexInputSchema.optional(),
  va_from: hexInputSchema.optional(), va_to: hexInputSchema.optional(),
  status: z.enum(["active", "revert-failed", "reverted", "expired", "implicit-end", "permanent",
                  "open", "investigating", "blocked", "contradicted", "resolved"]).optional(),   // effects / unknowns
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),                           // unknowns
  domain: z.string().max(64).optional(),                                                         // unknowns
});
export const getEvidenceInput = z.strictObject({
  detail: z.enum(["summary", "complete", "slice"]).default("summary"),
  entity: z.enum(["evidence", "effects", "unknowns", "instances"]).default("evidence"),   // summary only
  id: z.string().regex(ANY_LEDGER_ID_RE).optional(),                                     // complete: any ledger id; slice: ev_
  filters: evidenceFiltersSchema.optional(),                                             // summary only
  pointer: z.string().max(256).optional(),        // slice: "/result/…" (array) or "#blob:<role>" (NDJSON or binary blob)
  offset: z.number().int().min(0).max(1_000_000_000).default(0),
  limit: z.number().int().min(1).max(500).default(50),
  format: z.enum(["hex", "base64"]).default("hex"),   // slice of a binary blob (limit then counts KiB, max 64)
}).superRefine((v, ctx) => {
  if (v.detail !== "summary" && v.filters) ctx.addIssue({ code: "custom", path: ["filters"], message: "filters are valid only with detail: summary" });
  if (v.detail !== "summary" && v.entity !== "evidence") ctx.addIssue({ code: "custom", path: ["entity"], message: "entity is valid only with detail: summary" });
  if (v.detail !== "summary" && !v.id) ctx.addIssue({ code: "custom", path: ["id"], message: "id is required for complete and slice" });
  if (v.detail === "slice" && (!v.pointer || !v.id?.startsWith("ev_"))) ctx.addIssue({ code: "custom", path: ["pointer"], message: "slice needs an ev_ id and a pointer" });
  if (v.detail !== "slice" && v.pointer) ctx.addIssue({ code: "custom", path: ["pointer"], message: "pointer is valid only with detail: slice" });
});
```

Copied from REA: filters require `summary` [rea-evidence §5.2]. Selection is exact and never resolves an address:
a `module` filter matches `location.module_key` and never asks the target.

### 12.2 Output (poll envelope; a single object, no root union)

```ts
const summaryRowSchema = z.strictObject({
  kind: z.literal("evidence"), evidence_id: evIdSchema, n: z.number().int(), predicate_type: z.string(), operation: z.string(),
  instance_id: piIdSchema.nullable(), seq: z.number().int().nullable(), confidence: confidenceSchema, authority: authoritySchema,
  coverage_status: z.enum(["complete", "partial", "unknown"]), truncated: z.boolean(), limitation_count: z.number().int(),
  effect_count: z.number().int(), link_count: z.number().int(), blob_bytes: z.number().int(), origin: z.enum(["local", "imported"]),
});
const effectRowSchema = z.strictObject({ kind: z.literal("effect"), effect_id: fxIdSchema, effect_kind: z.enum(EFFECT_KINDS),
  class: z.string(), instance_id: piIdSchema, status: z.string(), applied_seq: z.number().int(), ended_seq: z.number().int().nullable(),
  target: z.string().nullable() /* AddressText */, stream_ids: z.array(stIdSchema) });
const unknownRowSchema = z.strictObject({ kind: z.literal("unknown"), unknown_id: unkIdSchema, revision: z.number().int(),
  status: z.string(), severity: z.string(), domain: z.string(), question: z.string().max(240), question_truncated: z.boolean(),
  supporting_count: z.number().int(), contradicting_count: z.number().int() });
const instanceRowSchema = z.strictObject({ kind: z.literal("instance"), instance_id: piIdSchema, pid: z.number().int(),
  ownership: z.enum(["owned", "attached"]), image_name: z.string().nullable(), state: z.string(), evidence_count: z.number().int() });

export const getEvidenceOutput = pollOutput({
  view: z.enum(["summary", "complete", "slice"]),
  summary: z.strictObject({ entity: z.string(), total: z.number().int(), matching: z.number().int(),
    rows: z.array(z.discriminatedUnion("kind", [summaryRowSchema, effectRowSchema, unknownRowSchema, instanceRowSchema])).max(500),
    page: pageSchema }).exactOptional(),
  record: z.strictObject({ record_kind: z.enum(["evidence", "effect", "unknown", "instance", "module_map", "stream"]),
    origin: z.enum(["local", "imported"]), value: jsonObjectSchema }).exactOptional(),   // effects include folded status + transitions
  slice: z.strictObject({ evidence_id: evIdSchema, pointer: z.string(), total: z.number().int(),
    items: z.array(jsonValueSchema).max(500).exactOptional(), data: z.string().exactOptional(), format: z.enum(["hex", "base64"]).exactOptional(),
    page: pageSchema }).exactOptional(),
});
export const pageSchema = z.strictObject({ offset: z.number().int(), limit: z.number().int(), total: z.number().int(),
  next_offset: z.number().int().nullable() });
```

`get_evidence` records nothing. It is a read of retained data, so its envelope is a poll with `evidence_id: null`,
and slices return the *source* ID in `slice.evidence_id`. It always carries the untrusted marker, because any
record or imported bundle may hold target content. A missing ID is `invalid_request` with
`details:{reason:"missing", id}`. The remediation says: "The ID is not in this run's ledger; list with
`get_evidence` summary, or import the bundle that holds it." This copies REA's message rule
[rea-evidence §4].

---

## 13. Bundles: export and import (`src/evidence/Bundle.ts`, `BundleZip.ts`)

### 13.1 Layout

```
<bundle>/ (or <bundle>.zip with the same entries)
  bundle.json                      BundleManifest (canonical)
  records.jsonl                    canonical lines: pi, mm, fx, fxt, unk, ev (no run/import/end lines)
  blobs/<sha256>                   referenced blobs (unless include_blobs:false)
  streams/<st_id>/descriptor.json, chunk-*.bin, chain.jsonl   (streams:"all"); descriptors + chain only for "manifests-only"
```

```ts
export const bundleManifestSchema = z.strictObject({
  schema: z.literal("bea.bundle/1"),
  bundle_digest: sha256Schema,                         // sha256(canonical(manifest − bundle_digest − created_wall))
  producer: z.strictObject({ name: z.literal("bea"), version: z.string() }),
  created_wall: z.iso.datetime(),
  source_runs: z.array(runIdSchema).min(1).max(1024),  // sorted
  selection: z.strictObject({ kind: z.enum(["run", "instance", "closure"]), instance_id: piIdSchema.nullable(),
                              roots: z.array(evIdSchema).max(1024) }),
  records: z.strictObject({ path: z.literal("records.jsonl"), sha256: sha256Schema, bytes: z.number().int(), lines: z.number().int() }),
  counts: z.strictObject({ instances: z.number().int(), module_maps: z.number().int(), effects: z.number().int(),
                           effect_transitions: z.number().int(), unknown_revisions: z.number().int(), evidence: z.number().int() }),
  blobs_included: z.boolean(),
  blobs: z.array(z.strictObject({ sha256: sha256Schema, bytes: z.number().int() })),      // sorted by sha256
  streams: z.array(z.strictObject({ stream_id: stIdSchema, descriptor_sha256: sha256Schema, head_chain: sha256Schema,
                                    chunks: z.number().int(), bytes: z.number().int(), included: z.enum(["all", "manifests-only"]) })),
});
```

**Canonical order of `records.jsonl`.** Lines are ordered by kind rank `pi < mm < fx < fxt < unk < ev`, then:
- `pi`, `mm`, `fx`, `ev` by ID;
- `fxt` by `(effect_id, at.run_id, at.seq)`;
- `unk` by `(unknown_id, revision)`.

Exporting the same selection twice therefore gives byte-identical `records.jsonl` and the same `bundle_digest`.

### 13.2 Selection closure

- `selection.kind` is `run` (everything), `instance` (records whose subject is the instance, plus their
  closure) or `closure` (given roots).
- The closure is the transitive set over:
  - `evidence_links`;
  - `subject.instance_id` → `pi`;
  - `module_map_id`s (subject, locations, effect targets) → `mm`;
  - `effects`, `perturbation.active_effect_ids` and `tainted_by` → `fx` + all of their `fxt`;
  - unknowns whose supporting/contradicting/mutation/resolution lists intersect the set (whole revision
    histories, pruned like REA's `evidenceBundleForTarget` [rea-evidence §5.1]);
  - blobs referenced by records or effect byte states;
  - streams referenced by manifests in the set.
- A bundle never contains a dangling reference, except blobs when `include_blobs:false`. The manifest then has
  `blobs_included:false`, the blob list still lists the digests, and the importer marks those blobs `absent`.

### 13.3 Export (atomic)

```ts
export const exportEvidenceInput = z.strictObject({
  path: z.string().min(1).max(1024),                      // absolute; ".zip" suffix ⇒ zip unless format given
  format: z.enum(["directory", "zip"]).optional(),
  overwrite: z.boolean().default(false),
  instance_id: piIdSchema.optional(),
  evidence_ids: z.array(evIdSchema).min(1).max(1024).optional(),
  streams: z.enum(["all", "manifests-only"]).default("all"),
  include_blobs: z.boolean().default(true),
}).refine((v) => !(v.instance_id && v.evidence_ids), { path: ["evidence_ids"], message: "choose instance_id or evidence_ids, not both" });
// output (poll): { path, format, bundle_digest, bytes, counts, selection } ; effects: WF + DD (when overwrite) [BRIEF §6.8]
```

Algorithm:
1. **Snapshot.** Take the ledger offset and the stream states under the append queue, so the export is
   consistent: records appended later are excluded. Live streams are checkpointed first.
2. Compute the closure. Read and **re-authenticate** every included line. Verify every included blob's digest
   and every stream chain. Fail on any mismatch (`evidence_integrity_mismatch`); a corrupted run is never
   exported silently.
3. Write to staging `<dest>.bea-staging-<16hex>`, a directory or zip in the destination's parent directory:
   - `records.jsonl` (hashing while writing);
   - blobs (copied);
   - stream files;
   - `bundle.json` last.
4. fsync the files. On zip, close and fsync the archive.
5. Publish.
   - `dest` absent: `rename(staging, dest)`.
   - `dest` present and `overwrite`: `rename(dest, dest.bea-old-<hex>)`, then `rename(staging, dest)`, then
     remove the old copy. If the second rename fails, rename the old copy back.
   - `dest` present without `overwrite`: `file_operation_failed{reason:"exists"}` before any staging.
   - Windows renames can fail transiently (EPERM/EBUSY from AV or Explorer handles): retry with 50/100/200/400
     ms backoff (≤ 2 s), then fail and clean up staging (A7).
6. On cancellation or failure, remove staging. The destination changes only on a complete publish
   [rea-evidence §5.3].

Zip specifics:
- Use `yazl@3.3.1` to write and `yauzl@3.4.0` to read (both MIT; metadata checked [S2-lab E6]), with ZIP64 for
  > 4 GiB or > 65,535 entries (A6).
- Entries have fixed mtime 1980-01-01 and sorted names.
- Deflate `.jsonl`/`.json`; store blobs and chunks.
- Exports are **not Evidence**. They are file-system results with a digest. Provenance lives in the bundle
  itself.

### 13.4 Import (validate all, then merge)

```ts
export const importEvidenceInput = z.strictObject({ path: z.string().min(1).max(1024) });
// output (poll): { bundle_digest, added: ImportCounts, duplicates: number, blobs_absent: number, total_after: LedgerCounts }
```

1. **Open.**
   - Directory: read `bundle.json`.
   - Zip: extract to `runs/<run>/tmp/import-<16hex>/` with guards:
     - reject names containing `..`, absolute paths, drive letters, backslashes, NUL, or duplicates;
     - ignore external attributes (no symlinks);
     - accept only names in the layout grammar;
     - cap per-entry uncompressed size at the manifest-declared size and in any case at the run's remaining
       quota;
     - stop on a compression ratio above 200:1 for any entry over 1 MiB (zip bomb).
2. **Manifest.** Parse with the schema and recompute `bundle_digest`.
3. **Records.** Stream `records.jsonl`:
   - check the sha256, byte count and line count;
   - check every line is canonical (re-serialize and compare bytes);
   - check canonical order and uniqueness;
   - authenticate every ID and revision digest.
4. **Blobs.** Every listed blob is present (if included) and hashes to its name. Unlisted files are an error.
5. **Streams.** Recompute chunk digests and the chain to `head_chain`, or check descriptors and chain lines
   only for `manifests-only`.
6. **Derived equality** (REA's rule [rea-evidence §5.1]). Recompute `counts`, `blobs`, `streams` and
   `source_runs` from the records and compare them byte-for-byte with the manifest.
7. **Referential integrity** inside the bundle ∪ the current ledger: links, instances, maps, effects and their
   transitions, unknown chains (gap-free, digest-linked, no `depends-on` cycles), blob references (or
   `blobs_included:false`).
8. **Conflicts with the current ledger.**
   - Same ID with different canonical bytes: reject the whole import (`evidence_integrity_mismatch`, listing up
     to 10 IDs).
   - Same `(unknown_id, revision)` with a different digest: reject.
   - An `fxt` for an effect that is *live* in this run: reject, because imported transitions cannot change live
     state.
9. **Quota.** Check the bytes to add against the remaining quota.
10. **Merge.**
    1. Copy blobs and stream directories (an existing identical `st_` is skipped; a different one is a
       conflict, though run-scoped IDs make this practically impossible).
    2. Append `import-begin`, the new lines (identical existing ones count as duplicates), then
       `import-commit`.
    3. Fsync the ledger.
    4. Update the index with `origin:{kind:"import", bundle_digest}`.

    A crash before `import-commit` leaves an ignored bracket (9.3). Copied blobs/streams without a committed
    import are inert: content-addressed, unreferenced.

Imported data is data only: nothing is executed, imported effects never enter the live EffectRegistry, and every
read of it carries the untrusted marker.

---

## 14. Unknown registry (`src/domain/unknowns/unknown.ts`, `src/evidence/UnknownRegistry.ts`)

### 14.1 Record

This is REA's model [rea-evidence §3.6] minus comparison scopes and environment requirements
[rea-evidence §10.8].

```ts
export const unknownScopeSchema = z.discriminatedUnion("kind", [
  z.strictObject({ kind: z.literal("image"), image_sha256: sha256Schema }),   // default: survives restarts of the same binary
  z.strictObject({ kind: z.literal("run"), run_id: runIdSchema }),
  z.strictObject({ kind: z.literal("global") }),
]);
export const unknownDomainSchema = z.enum(["runtime-behavior", "address-mapping", "struct-layout", "function-semantics",
  "emulation-fidelity", "coverage", "environment", "other"]);
const probeSchema = z.strictObject({ operation: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/u), rationale: z.string().min(1).max(500),
  arguments: jsonObjectSchema.nullable() });
const resolutionSchema = z.discriminatedUnion("disposition", [
  z.strictObject({ disposition: z.literal("verified"), rationale: z.string().min(1).max(2000), evidence_ids: z.array(evIdSchema).min(1).max(64) }),
  z.strictObject({ disposition: z.literal("withdrawn"), rationale: z.string().min(1).max(2000), evidence_ids: z.array(evIdSchema).max(64) }),
  z.strictObject({ disposition: z.literal("out-of-scope"), rationale: z.string().min(1).max(2000), evidence_ids: z.array(evIdSchema).max(64) }),
]);
export const residualUnknownSchema = z.strictObject({
  schema: z.literal("bea.unknown/1"),
  unknown_id: unkIdSchema, revision: z.number().int().min(1).max(10_000),
  previous_revision_digest: sha256Schema.nullable(), revision_digest: sha256Schema,
  scope: unknownScopeSchema, domain: unknownDomainSchema,
  question: z.string().min(1).max(2000),
  status: z.enum(["open", "investigating", "blocked", "contradicted", "resolved"]),
  severity: z.enum(["low", "medium", "high", "critical"]),
  supporting_evidence_ids: z.array(evIdSchema).max(256), contradicting_evidence_ids: z.array(evIdSchema).max(256),
  accepted_authorities: z.array(authoritySchema).min(1).max(5),        // explicit set (sorted)
  required_confidence: confidenceSchema,
  recommended_probes: z.array(probeSchema).max(16),
  resolution: resolutionSchema.nullable(),
  mutation_evidence_ids: z.array(evIdSchema).min(1).max(10_000),
}).superRefine(unknownInvariants);
export const unknownIdOf = (domain: string, question: string, scope: UnknownScope): UnkId =>
  idOf("unk", { t: "bea.unk/1", domain, question: question.replace(/\s+/gu, " ").trim(), scope_digest: digestCanonical(scope) });
export const revisionDigestOf = (r: Omit<ResidualUnknown, "revision_digest">) => digestCanonical(r);   // REA: digest of all other fields
```

Invariants, as in REA:
- `revision == 1 ⇔ previous_revision_digest === null`;
- `resolved ⇔ resolution !== null`;
- `contradicted ⇒ contradicting ≥ 1`;
- supporting ∩ contradicting = ∅;
- lists are sorted and unique.

Domain defaults for `accepted_authorities` and `required_confidence`:

| Domain | accepted_authorities | required_confidence |
|---|---|---|
| runtime-behavior, struct-layout | `["live-process"]` | `observed` |
| function-semantics | `["emulation", "live-process"]` | `observed` |
| address-mapping | `["live-process", "static-artifact"]` | `derived` |
| emulation-fidelity | `["emulation", "live-process"]` | `derived` |
| others | all five | `inferred` |

### 14.2 Mutations and CAS

- `create(input, literals)`: compute `unk_`. If the ID already exists → `invalid_request{reason:"already-exists",
  unknown_id, revision}`. Otherwise revision 1, status `contradicted` if contradicting is non-empty, else the
  given status.
- `update(unknown_id, expected_revision, patch)`:
  - `expected_revision !== head.revision` → `revision_conflict` (retryable) with
    `details:{unknown_id, expected_revision, current_revision}`.
  - Otherwise merge the patch onto the head. Provided lists replace wholesale; `question`, `domain` and `scope`
    are immutable. The result is revision + 1, with `previous_revision_digest = head.revision_digest`.
- Every mutation first records **mutation Evidence**:
  - `bea.unknown.mutation`, `confidence:"derived"`, `authority:"analyst-inference"`;
  - `evidence_links` = every referenced ID;
  - limitation "Registry mutation evidence records analyst intent, not proof of the answer." [rea-evidence §3.6];
  - result `{unknown_id, revision, status, change:[field…]}`.

  Then it appends the `unk` line, and the new revision's `mutation_evidence_ids` includes that ID.
- Proposed `record_unknown` input (S1 owns the contract): a flat strict object with `unknown_id?`,
  `expected_revision?`, `question?`, `domain?`, `scope_image_sha256?`, `status?`, `severity?`,
  `supporting_evidence_ids?`, `contradicting_evidence_ids?`, `accepted_authorities?`, `required_confidence?`,
  `recommended_probes?`, `resolution?`. The refine requires create = `question` + `domain` without
  `unknown_id`, and update = `unknown_id` + `expected_revision`. Listing goes through `get_evidence
  entity:"unknowns"`.

### 14.3 The verified-resolution rule

`disposition:"verified"` is accepted only if `resolution.evidence_ids` contains at least one non-mutation
Evidence that:
1. is in `supporting_evidence_ids`;
2. has an *effective* authority in `accepted_authorities` (bundle-imported records count as `imported`, 7.4);
3. has `CONFIDENCE_RANK ≥ rank(required_confidence)`;
4. has coverage that is not `unknown`;

and `contradicting_evidence_ids` is empty. Otherwise the result is `invalid_request{reason:"invalid-transition"}`
with the failing criterion. `withdrawn` and `out-of-scope` are not truth claims [rea-evidence §3.6].

### 14.4 Auto-unknowns

Created by producers through `UnknownRegistry.autoRecord(trigger)`. The question ends with `(Evidence ev_…)`,
the severity is `medium`, and the probes come from the table:

| Trigger | Domain | Probe |
|---|---|---|
| a stream manifest is `partial`/`unknown` with drops | coverage | `query_events` on the window, or re-record with a narrower filter |
| `call_function` returned a fault status | function-semantics | `emu_call` with `trace.memory`, `disassemble` |
| `diff_function` verdict `differ`/`unknown` | emulation-fidelity | `emu_call` with `trace.blocks` on the failing vectors |
| `map_address` image or byte mismatch | address-mapping | `disassemble` at the VA, `list_module_symbols` |

---

## 15. Redaction and untrusted content (`src/domain/redaction/*`)

### 15.1 Declarations

```ts
export interface SensitiveLiterals {
  readonly count: number;                       // persisted as sensitive_value_count (only when > 0)
  readonly texts: readonly string[];            // unique, longest first
  readonly spellings: readonly Buffer[];        // utf8(lit) and utf16le(lit) for each literal, unique, longest first
}
export function sensitiveLiterals(perCall: readonly string[] | undefined, serverLevel: readonly string[]): Result<SensitiveLiterals, InputIssue[]>;
export const sensitiveValuesInput = z.array(z.string().min(1).max(1024)).max(64);   // tool input fragment (per call)
```

Sources:
1. a per-call `sensitive_values` on every contract whose `returnsTargetContent` is true, plus `spawn_process`
   (argv/env) and `export_evidence` (paths);
2. the server-level `BEA_SENSITIVE_VALUES_FILE` / `evidence.sensitive_values_file`: UTF-8, one literal per
   line, at most 256, read once at start.

Neither is ever persisted [rea-evidence §7]. **BEA deviation:** literals shorter than 4 UTF-8 bytes are
`invalid_request`, because a one-character literal would erase everything (foot-gun prevention).

### 15.2 Algorithms

```ts
/** REA's exact text semantics (VERIFIED-READ REA src/domain/explicitSensitiveValues.ts). */
export const redactExplicitText = (value: string, lits: SensitiveLiterals): string => {
  const literals = lits.texts;
  const replacement = ["[REDACTED]", "…", ""].find((c) => literals.every((l) => !c.includes(l))) ?? "";
  let result = value;
  for (const l of literals) result = result.replaceAll(l, replacement);       // longest first
  return literals.some((l) => result.includes(l)) ? "" : result;              // boundary re-formation ⇒ ""
};
export const bytesContainLiteral = (b: Uint8Array, lits: SensitiveLiterals): boolean =>
  lits.spellings.some((s) => Buffer.from(b.buffer, b.byteOffset, b.byteLength).indexOf(s) !== -1);
export function redactJsonPayload(value: JsonValue, lits: SensitiveLiterals, at: string, byteFields: readonly string[])
  : { value: JsonValue; redactions: Redaction[] };
```

`redactJsonPayload` walks the value depth-first. Pointers are built per RFC 6901.
- **Object keys** containing a literal: the property is dropped; redaction scope `property-name`, pointer = the
  parent.
- **String values** containing a literal as text: the value becomes `null`, with scope `value`. Whole-field
  exclusion, never a marker [rea-evidence §7].
- **Byte fields** (the predicate's `byteFields` pointer patterns, e.g. `/data`, `/outputs/*/hex`,
  `/before/hex`): decode hex or base64 and check `bytesContainLiteral`. On a hit the value becomes `null` with
  scope `value`, and the field's digest is not kept either.
- **Blobs**: checked at `BlobStore.put`. On a hit the blob is not stored; the producer gets `{redacted:true}`
  and records `blob:null` + scope `blob` + `explicit_sensitive_value` truncation. A memory dump that contains a
  literal is therefore withheld whole; narrow the range.
- **Effects**: `before`/`after` bytes with a hit are kept **in memory only** (revert still works) and persisted
  as `{sha256:null, hex:null, blob:null, retained:false}`.
- **`display` sub-objects** (paths, names) are nulled on a hit.
- **Errors**: S1 applies `redactExplicitText` to `message`, diagnostics and captured output with REA's
  `redactExplicitFailure` semantics. Tags are preserved, and JSON pointers are cut back to a safe ancestor.

Spellings checked: the UTF-8 and UTF-16LE encodings only. No case folding, no XOR or obfuscated forms, no
UTF-16BE: anything else would be guessing [rea-evidence §13 Q8]. Identity digests (`image_path_sha256`,
`path_sha256`) are not redacted. They are one-way, but low-entropy inputs such as paths can be guessed, which is
documented in `docs/evidence-model.md`.

### 15.3 Untrusted content

- MCP: `_meta: {provenance: {untrusted_content: true, source: "analysis_target"}}` on success **and** error
  results of every contract with `returnsTargetContent` [rea-mcp §4.6]. For BEA that is every tool except
  `export_evidence`, `record_unknown` and `bea_status` (S1 owns the allow-list).
- Records: `untrusted` is true when `result` holds target-derived content: memory, strings, module names and
  paths, hook arguments, exception text, PE strings.
- Trusted envelope, untrusted payload:
  - Limitations, coverage reasons, `next.reason` and error messages are BEA-authored (7.6).
  - Target-derived text appears only in `result` fields: AddressRef `module`, `symbol.name`, PE names,
    memory-decoded strings.
  - The server instructions tell the agent to treat everything inside results as data [BRIEF §1.5].

---

## 16. Address model

### 16.1 Input grammar (`src/domain/address/grammar.ts`)

```
address      := va | modref
va           := "0x" HEX{1,16}                          ; case-insensitive, leading zeros allowed
modref       := module rvaSuffix                        ; module + RVA
              | "+" "0x" HEX{1,8}                       ; main module + RVA (leading "+" = main module)
              | module "!" exportRef                    ; export, optional displacement
module       := quoted | bare
bare         := 1*( any char except whitespace, '"', '+', '!' ) [ "@0x" HEX{1,16} ]   ; basename; optional base qualifier
quoted       := '"' JSON-string-body '"'                ; basename or full path (contains '\' or '/')
rvaSuffix    := "+" "0x" HEX{1,8}
exportRef    := ( "#" DEC{1,5} | exportName ) [ "+" "0x" HEX{1,8} ]
exportName   := quoted | 1*( any char except whitespace, '"', '+' )
```

Examples:
- `0x7ff7a8a11760`
- `game.exe+0x1a2b3c`
- `+0x1760`
- `kernel32.dll!Sleep`
- `kernel32.dll!Sleep+0x10`
- `ws2_32.dll!#115`
- `"notepad++.exe"+0x1000` (a `+` inside the name needs quotes)
- `"C:\\Games\\x\\msvcp140.dll"+0x10`
- `msvcp140.dll@0x7ffa10000000+0x1234` (two loaded modules share the basename)

Static form: separate fields `static_va` (hex input) + optional `static_base` (hex input) + optional `module`
(module token, without suffix).

The shared contract fragment and parser:

```ts
export const addressInputShape = {
  address: z.string().min(2).max(600).optional()
    .describe("Runtime VA 0x…, module+0xRVA, +0xRVA (main module), module!export[+0xN], module!#ordinal"),
  static_va: hexInputSchema.optional().describe("Address in the static (Ghidra/REA) image address space"),
  static_base: hexInputSchema.optional().describe("Image base of that static address space; default: PE preferred base from disk"),
  module: z.string().min(1).max(600).optional().describe("Module for static_va when ambiguous"),
} as const;
export const refineAddressInput = (v: { address?: string; static_va?: string; static_base?: string; module?: string }, ctx: z.RefinementCtx) => {
  if ((v.address === undefined) === (v.static_va === undefined))
    ctx.addIssue({ code: "custom", path: ["address"], message: "Give exactly one of address or static_va." });
  if (v.address !== undefined && (v.static_base !== undefined || v.module !== undefined))
    ctx.addIssue({ code: "custom", path: ["module"], message: "static_base and module are valid only with static_va." });
};

export type ModuleToken = { kind: "main" } | { kind: "name"; name: string; base: bigint | null } | { kind: "path"; path: string };
export type ParsedAddress =
  | { form: "va"; va: bigint }
  | { form: "module-rva"; module: ModuleToken; rva: number }
  | { form: "module-export"; module: Exclude<ModuleToken, { kind: "main" }>;
      export: { kind: "name"; name: string } | { kind: "ordinal"; ordinal: number }; displacement: number }
  | { form: "static"; static_va: bigint; static_base: bigint | null; module: Exclude<ModuleToken, { kind: "main" }> | null };
export interface AddressIssue { path: (string | number)[]; reason: "invalid_format" | "out_of_range" | "invalid_value";
  message: string; expected?: string }
export function parseAddressString(s: string, path?: (string | number)[]): Result<ParsedAddress, AddressIssue>;
export function parseAddressInput(v: { address?: string; static_va?: string; static_base?: string; module?: string },
  path?: (string | number)[]): Result<ParsedAddress, AddressIssue[]>;
```

`parseAddressString` algorithm:
1. `t = s.trim()`. Empty → `invalid_format`.
2. If `t` matches `^0[xX][0-9a-fA-F]{1,16}$`: `va = BigInt(t)`. If `va > USER_VA_MAX` → `out_of_range`
   ("non-canonical or kernel-space address; BEA is user-mode only"). Return the `va` form.
3. If `t` starts with `+`, the rest must match `^\+0[xX]([0-9a-fA-F]{1,8})$` → `{main}` + rva. Otherwise
   `invalid_format` ("the main-module shorthand requires +0x<rva>").
4. Read the module token. A quoted token is scanned to its matching unescaped quote and `JSON.parse`d. It is a
   `path` if it contains `\` or `/`, else a `name`. A bare token is everything up to the first `+`, `!`, `"` or
   whitespace, split by `^(.*)@0[xX]([0-9a-fA-F]{1,16})$` into name + base qualifier. An empty name is
   `invalid_format`.
5. Remainder:
   - `^\+0[xX]([0-9a-fA-F]{1,8})$` → module-rva;
   - `!#(\d{1,5})(?:\+0[xX]([0-9a-fA-F]{1,8}))?$` (ordinal ≤ 65535) → ordinal export;
   - `!` + quoted name + optional displacement, or `^!([^\s"+]+)(?:\+0[xX]([0-9a-fA-F]{1,8}))?$` → named export;
   - anything else → `invalid_format`, with `expected` set to the grammar's one-line summary.
6. Decimal-looking input (`^\d+$`) → `invalid_format` with the hint "addresses are hexadecimal with a 0x
   prefix".

### 16.2 Validation and resolution errors

| Stage | Condition | Wire error | Category | Details |
|---|---|---|---|---|
| parse | syntax | `invalid_request` (issue `invalid_format`) | invalid_input | `issues[{path, reason, message, expected}]`, recovery `inspect_input_contract` |
| parse | VA > 0x7fffffffffff, RVA > 32 bits, ordinal > 65535 | `invalid_request` (`out_of_range`) | invalid_input | same |
| parse | both or neither of address/static_va; static_base/module without static_va | `invalid_request` (`invalid_value`) | invalid_input | same |
| resolve | the module token matches no loaded module | `address_unmapped` | target_state | `{reason:"module_not_loaded", token, suggestions[≤5]}`, recovery `refresh_module_map` (the module may load later) |
| resolve | the basename matches > 1 module | `invalid_request` | invalid_input | `{reason:"module_ambiguous", candidates:[{name, path, base}]}` with remediation "Qualify with @0x<base> or quote the full path" |
| resolve | export not found | `invalid_request` | invalid_input | `{reason:"export_not_found", module, export, similar[≤5]}` |
| resolve | forwarder target module not loaded, or an API-set forwarder the agent cannot resolve | `address_unmapped` | target_state | `{reason:"forwarder_unresolved", forwarder}` |
| resolve | RVA ≥ SizeOfImage | `invalid_request` (`out_of_range`) | invalid_input | `{reason:"rva_out_of_image", size_of_image}` |
| resolve | static_va outside `[static_base, static_base+SizeOfImage)`, or no module's static range contains it | `invalid_request` | invalid_input | `{reason:"static_out_of_image"}` or `{reason:"static_module_ambiguous", candidates}` |
| resolve | module form used without a session | `invalid_request` | invalid_input | `{reason:"no_module_map"}` (use `image_path` + `runtime_base`) |
| resolve | the module's PE cannot be read | `unsupported_target` / `file_operation_failed` | — | `{reason: PeError.kind}`; PE32 (WoW64) is always `unsupported_target` |
| tools needing mapped memory | VA in no module and no committed range | `address_unmapped` | target_state | recovery `refresh_module_map` |

In batch `map_address`, per-item failures are **item results** (`status:"error"`, `issue`), the batch coverage
becomes `partial` (`entry_errors`), and the tool still succeeds.

### 16.3 Resolution (`src/application/address/AddressResolver.ts`)

```ts
export interface AddressContext {
  readonly instance: ProcessInstance | null;     // null: pure-arithmetic mode
  readonly map: ModuleMap | null;                // current epoch (materialized on reference)
  readonly pe: PeImageCache; readonly hashes: FileHashCache; readonly symbols: CallerSymbolTables;
  readonly agent: Pick<AgentRpc, "resolveExport" | "read"> | null;
}
export interface AddressResolver {
  resolve(ctx: AddressContext, p: ParsedAddress, opts: { expected_image_sha256?: string; signal?: AbortSignal })
    : Promise<Result<AddressRef, AddressResolutionError>>;
}
```

1. **Module selection.**
   - `main`: the map entry whose `path_sha256 == identity.image_path_sha256`.
   - `name`: case-insensitive basename match (case-sensitive on Linux). Exactly one match wins. With a `@base`
     qualifier, the base must equal it. With several matches and no qualifier → `module_ambiguous`. With none,
     and only if the token has no dot, try `token+".dll"` and then `token+".exe"`; a unique hit wins.
   - `path`: `pathKey` equality.
2. **Rva**:
   - module-rva: given;
   - export: `PeImage.exports()` by name or ordinal. Forwarders (export RVA inside the export directory) are
     followed up to 4 hops: `"NTDLL.RtlAllocateHeap"` → module `ntdll.dll` in the map → its export. API-set
     names (`api-ms-win-*`, `ext-ms-*`) go to agent RPC `resolveExport(declaring module, name)`, which returns
     the bound address (**A19**). The resulting AddressRef is in the *target* module and carries
     `symbol.forwarded_from`.
   - static: `rva = static_va − static_base`, where `static_base` is the caller's (`static_base_source:"caller"`),
     else the module's PE preferred base (`"pe-header"`), else the REA-supplied base (`"rea-evidence"`, when the
     input carried `external_ref.image_base`).
3. **Check** `0 ≤ rva < size_of_image`. Then `va = base + rva` and `static_va = static_base + rva` (bigint,
   with overflow checks). This is the ASLR formula VERIFIED in [ext-frida §3.14] and [S2-lab E2]
   (`0x140000000` → `0x7ff7a8a10000`).
4. **VA form**: `moduleAt(map, va)`. With no module, return `{va, module:null, rva:null, static_*:null}`; this
   is not an error for mapping.
5. **Image digest**: `FileHashCache.sha256(module path)` (lazy, persistent) → `image_sha256`, and
   `IMAGE_CHANGED_ON_DISK` when the file times post-date process start (4.2).
6. **Symbolize** (19). Return the AddressRef.

### 16.4 AddressRef (`src/domain/address/addressRef.ts`)

```ts
export const symbolSchema = z.strictObject({
  name: z.string().max(1024).nullable(),          // null for .pdata-only functions (no fabricated names)
  kind: z.enum(["export", "caller", "import-slot", "function", "debug-hint"]),
  offset: hexSchema,                              // address − symbol start
  source: z.enum(["pe-export", "pe-pdata", "pe-import", "caller-table", "dbghelp"]),
  function_start: hexSchema.exactOptional(),      // rva of the primary .pdata entry (unwind chains resolved)
  function_end: hexSchema.exactOptional(),        // end rva of the fragment containing the address
  fragment: z.boolean().exactOptional(),          // address lies in a chained (secondary) .pdata fragment
  forwarded_from: z.string().max(600).exactOptional(),
  evidence_id: evIdSchema.exactOptional(),        // caller-table names: the bea.symbols.caller record
});
export const addressRefSchema = z.strictObject({
  va: hexSchema,
  module: z.string().max(260).nullable(),         // display basename (loader casing); untrusted text
  rva: hexSchema.nullable(),
  static_va: hexSchema.nullable(),
  static_base: hexSchema.nullable(),
  static_base_source: z.enum(["pe-header", "caller", "rea-evidence"]).nullable(),
  module_map_id: mmIdSchema.nullable(),           // null: emulation (non-dump) or pure-arithmetic mode
  image_sha256: sha256Schema.nullable().exactOptional(),   // omitted when not computed; null = could not hash
  symbol: symbolSchema.exactOptional(),
  section: z.string().max(16).exactOptional(),    // e.g. ".text"; resolves gcc long names
});
export type AddressRef = z.infer<typeof addressRefSchema>;
```

Invariants:
- `module === null ⇒ rva === static_va === static_base === static_base_source === null`.
- `rva !== null ⇒ static_va === static_base + rva`, whenever `static_base` is non-null.
- Emulation AddressRefs come from the emulator's image: `module_map_id:null`, except for dump-backed sessions,
  which use the captured live map.

### 16.5 Bulk form: AddressText + module legend

For outputs with more than 8 addresses (backtraces, hit lists, scan pages, coverage summaries):

```ts
export type AddressText = string;   // "module+0xrva" (unique basename) | "module@0xbase+0xrva" (ambiguous) | "0x<va>" (non-module)
export const moduleLegendSchema = z.record(z.string().max(300), z.strictObject({
  base: hexSchema, size: z.number().int(), static_base: hexSchema, static_base_source: z.enum(["pe-header", "caller", "rea-evidence"]),
  image_sha256: sha256Schema.nullable().exactOptional(), module_map_id: mmIdSchema,
}));
// result fields: { frames: AddressText[], modules: ModuleLegend }
```

- **Round-trip property** (unit test): every AddressText is a valid `address` input that resolves to the same VA
  in the same map.
- `static_va = legend.static_base + rva` is mechanical. The "every address carries all forms" requirement
  [BRIEF §6.0] is met by the legend, at about a third of the tokens.

---

## 17. The on-disk PE reader (`src/pe/*`)

### 17.1 Types

```ts
export type PeErrorKind = "not_found" | "io" | "not_pe" | "unsupported_format" | "malformed";
export interface PeError { readonly kind: PeErrorKind; readonly detail: string; readonly field?: string }  // detail: curated, no raw bytes
export interface PeSection { readonly name: string; readonly short_name: string; readonly rva: number; readonly virtual_size: number;
  readonly raw_offset: number; readonly raw_size: number; readonly characteristics: number; readonly perms: `${"r"|"-"}${"w"|"-"}${"x"|"-"}` }
export interface PeExport { readonly ordinal: number; readonly name: string | null; readonly rva: number | null; readonly forwarder: string | null }
export interface PeImport { readonly dll: string; readonly name: string | null; readonly ordinal: number | null;
  readonly slot_rva: number; readonly delay: boolean }
export interface FunctionTable {
  readonly count: number; readonly chained: number;
  /** fragment containing rva, with its primary entry (unwind chains and RUNTIME_FUNCTION_INDIRECT followed, depth ≤ 32) */
  lookup(rva: number): { begin: number; end: number; primary_begin: number; fragment: boolean } | null;
  entries(): Iterable<{ begin: number; end: number; primary_begin: number }>;
}
export interface PeImage {
  readonly path_display: string; readonly file: FileKey;
  readonly format: "pe32+";                       // PE32 → PeError unsupported_format (WoW64 unsupported in v0.1)
  readonly machine: "x64" | "arm64" | "unknown";
  readonly time_date_stamp: number; readonly characteristics: number; readonly dll: boolean;
  readonly image_base: Hex;                       // PREFERRED base, from disk [ext-frida §3.14]
  readonly size_of_image: number; readonly size_of_headers: number; readonly entry_rva: number | null;
  readonly subsystem: number;
  readonly dll_characteristics: { dynamic_base: boolean; high_entropy_va: boolean; nx_compat: boolean; guard_cf: boolean };
  readonly sections: readonly PeSection[];
  readonly codeview: { guid: string; age: number; pdb_path: string } | null;
  readonly tls_callbacks: readonly number[];      // rvas
  readonly signed: boolean;                       // a security directory exists (not verified)
  readonly clr: boolean;                          // managed image (symbolization limited)
  readonly issues: readonly { table: string; reason: string }[];     // malformed or capped tables → coverage partial
  exports(): Promise<readonly PeExport[]>;
  imports(): Promise<readonly PeImport[]>;        // includes delay imports
  functions(): Promise<FunctionTable>;
  relocations(): Promise<Uint32Array>;            // DIR64 slot rvas, sorted
  loaderWritten(): Promise<readonly { rva: number; size: number; class: "iat" | "delay-iat" | "loader-thunk" | "loader-cfg" }[]>;
  readRva(rva: number, len: number): Promise<{ bytes: Buffer; backed: Uint8Array /* 1 = file-backed, 0 = zero-fill */ }>;
  imageBytes(rva: number, len: number, actualBase: bigint): Promise<Buffer>;   // file bytes + base relocations
  sectionOf(rva: number): PeSection | null;
}
```

### 17.2 Parsing algorithm (`src/pe/reader.ts`, `tables.ts`)

All reads are positioned (`FileHandle.read(buf, 0, len, off)`) on a short-lived handle. Opening, reading the
needed ranges and closing keeps game files unlocked. Every offset is bounds-checked against the file size, and
every RVA against `SizeOfImage`.

1. DOS header: `MZ`, `e_lfanew` at 0x3c → `PE\0\0` signature.
2. COFF header: Machine, NumberOfSections (≤ 96), TimeDateStamp, PointerToSymbolTable, NumberOfSymbols,
   SizeOfOptionalHeader, Characteristics.
3. Optional header. Magic `0x20b`; anything else → `unsupported_format`, and `0x10b` (PE32/WoW64) →
   `unsupported_target` upstream.
   - Fields: AddressOfEntryPoint (+16), ImageBase (u64 +24), SizeOfImage (+56), SizeOfHeaders (+60),
     Subsystem (+68), DllCharacteristics (+70: 0x20 high-entropy, 0x40 dynamic base, 0x100 NX, 0x4000
     guard CF), NumberOfRvaAndSizes (+108).
   - Data directories at +112: 0 export, 1 import, 3 exception, 4 security, 5 basereloc, 6 debug, 9 TLS,
     10 load config, 12 IAT, 13 delay import, 14 CLR.
4. Sections: 40-byte headers. A `/N` name resolves through the COFF string table at `PointerToSymbolTable +
   NumberOfSymbols×18 + N` (gcc long names; Frida shows them unresolved as `/4` [ext-frida §3.1]).
5. `rvaToOffset(rva)`: header bytes when `rva < SizeOfHeaders`; otherwise the section with `rva ∈ [VA,
   VA+max(VirtualSize, SizeOfRawData))`. The offset is `PointerToRawData + delta` when `delta < SizeOfRawData`,
   else `null` (zero-fill).
6. **Exports**: Base, NumberOfFunctions, NumberOfNames and the three arrays.
   - `ordinal = Base + i`.
   - An RVA inside `[exportDir, exportDir+size)` is a **forwarder** string.
   - Unnamed entries are NONAME ordinals (user32 has 160 [S2-lab E1]).
   - Zero RVAs are skipped.
   - Caps: 1,000,000 entries; names ≤ 4,096 bytes.
7. **Imports**: 20-byte descriptors until all-zero.
   - Thunks come from OriginalFirstThunk, or FirstThunk when OFT is 0. High bit 63 means an ordinal (low 16
     bits); otherwise the thunk is a hint/name RVA.
   - `slot_rva = FirstThunk + 8·i`.
   - **Delay imports**: 32-byte descriptors (Attributes, DllNameRVA, ModuleHandleRVA, IAT, INT, …). Attributes
     bit 0 = 0 means old-style VAs; subtract ImageBase.
   - Ordinal-only imports stay ordinal-only: BEA never invents names. pefile substitutes names from a built-in
     table, which was the only difference in E1.
8. **.pdata**: 12-byte RUNTIME_FUNCTION entries (Begin, End, UnwindData).
   - If `UnwindData & 1`, it is RUNTIME_FUNCTION_INDIRECT: follow `UnwindData − 1` to another entry (A8; 0
     seen in E1).
   - Else read UNWIND_INFO: byte 0 = version (bits 0–2) | flags (bits 3–7). If flags & 4 (UNW_FLAG_CHAININFO),
     the parent RUNTIME_FUNCTION is at `UnwindData + 4 + 2·((CountOfCodes+1) & ~1)`, with CountOfCodes =
     byte 2.
   - Follow chains (depth ≤ 32) to the primary entry; `primary_begin` is the **function start**.
   - VERIFIED against pefile: chained counts match exactly on kernel32 (43), KernelBase (1,675), ntdll (1,672),
     user32 (373) and d3d11 (497). All chains resolve to entries inside the table [S2-lab E1]. Chained
     fragments are 26–30% of entries in MSVC DLLs, which is why "function containing address" must follow
     chains.
   - The table is sorted by Begin for binary search. Caps: entries ≤ min(dir.size/12, 10,000,000).
9. **Relocations**: blocks of (PageRVA, BlockSize) + u16 entries; type 10 = DIR64 → `PageRVA + (e & 0xfff)`.
   Type 0 is padding. Other types are counted as `reloc_other` (expected 0 on x64; E1 found none). Sort into a
   `Uint32Array`. Cap: 20,000,000.
10. **Debug**: 28-byte entries. Type 2 (CodeView) with `RSDS` gives GUID (Data1 LE u32, Data2 LE u16, Data3 LE
    u16, 8 bytes; formatted upper-case 8-4-4-4-12), Age and the PDB path (≤ 1,024 bytes). VERIFIED equal to
    pefile on 4 system DLLs.
11. **TLS**: IMAGE_TLS_DIRECTORY64. `AddressOfCallBacks` (+24) is a VA; walk the u64 VAs until 0 (cap 256) →
    rvas. Fixtures have 2 and 3 callbacks [S2-lab E1].
12. **Load config** (dir 10, **A20**): GuardCFCheckFunctionPointer (+0x70) and GuardCFDispatchFunctionPointer
    (+0x78) are VAs of 8-byte slots the loader writes. They become `loader-cfg` ranges when non-zero and inside
    the image.
13. `loaderWritten()`, the bytes the Windows loader writes (VERIFIED classes [S2-lab E2]):

    | Class | Bytes covered |
    |---|---|
    | `iat` | every import `slot_rva` (8 B), plus the IAT directory (dir 12) range |
    | `delay-iat` | every delay-import `slot_rva` |
    | `loader-thunk` | sections named `fothk` (Windows 11 system-DLL forwarder thunks, `jmp rel32` patched at load: 3–9 bytes per DLL, even without Frida [S2-lab E2c]) |
    | `loader-cfg` | the CFG pointer slots (12) |

Malformed tables do not fail the whole image. The table becomes empty, `issues` gets `{table, reason}`, and
callers report coverage `partial` (`malformed_pe_directory`). Only an invalid header returns `PeError`.

### 17.3 imageBytes (`src/pe/imageBytes.ts`)

```ts
async imageBytes(rva, len, actualBase): Promise<Buffer> {
  const out = (await this.readRva(rva, len)).bytes;            // zero-fill where not file-backed
  const delta = BigInt.asUintN(64, actualBase - BigInt(this.image_base));
  if (delta === 0n) return out;
  const rel = await this.relocations();                        // sorted DIR64 slot rvas
  for (let i = lowerBound(rel, rva - 7); i < rel.length && rel[i] < rva + len; i++) {
    const slot = (await this.readRva(rel[i], 8)).bytes;        // full 8-byte slot even if it straddles the window
    slot.writeBigUInt64LE(BigInt.asUintN(64, slot.readBigUInt64LE(0) + delta));
    for (let k = 0; k < 8; k++) { const j = rel[i] + k - rva; if (j >= 0 && j < len) out[j] = slot[k]; }
  }
  return out;
}
```

VERIFIED [S2-lab E2]. In a Frida-attached owned gcc fixture, `imageBytes(.text)` equals live memory byte for
byte (37,776 B, 0 differences), and so do `.rdata`, `.pdata`, `.xdata`, `.edata`, `.rsrc` and `.reloc`. In a
Frida-free process, `.text` of ntdll (1.49 MB), kernel32 and KernelBase also match exactly; only `fothk` differs
[S2-lab E2c].

### 17.4 Limits and performance

The prototype parses fully in 1–31 ms for 113 KB–4.25 MB files, reading the whole file [S2-lab E1]. The real
reader reads only headers and the requested tables. For a 100 MB game executable, expect ≤ 50 ms for all tables
(**A16**). Hashing is a separate cost, cached across runs (17.6).

### 17.5 PeImageCache (`src/pe/PeImageCache.ts`)

```ts
export class PeImageCache {
  constructor(opts: { maxImages?: number /* 64 */ });
  open(path: string, signal?: AbortSignal): Promise<Result<PeImage, PeError>>;   // keyed by FileKey; stat on every open
}
```

`FileKey = (path_key, size, mtime_ns, ctime_ns, ino, dev)` from `fs.stat(p, {bigint:true})`. VERIFIED on NTFS:
rewriting content and then restoring mtime still changes `ctime_ns` (ChangeTime), and rename-replace changes
`ino`. `ino` values need bigint [S2-lab E4]. Parsed tables are cached, not file handles. `imageBytes`/`readRva`
re-stat before reading and re-parse when the key changed.

### 17.6 FileHashCache (`src/pe/FileHashCache.ts`)

```ts
export class FileHashCache {
  constructor(file: string /* BEA_HOME/cache/file-sha256.jsonl */);
  sha256(path: string, signal?: AbortSignal): Promise<Result<{ sha256: string; file: FileKey; cached: boolean }, PeError>>;
}
```

- Append-only NDJSON `{path_key, size, mtime_ns, ctime_ns, ino, dev, sha256}`, loaded at start (last write
  wins). Compacted when lines exceed 2× the unique keys. Corrupt lines are skipped: the cache is an
  optimization, never an authority.
- Concurrent servers each append single short lines with `O_APPEND`. A torn line is just a cache miss.
- Hashing is streaming SHA-256 with 1 MiB reads, cancellable through the signal.

---

## 18. `map_address` (`src/application/address/MapAddress.ts`)

### 18.1 Input (proposal; S1 owns the contract)

```ts
const mapItemSchema = z.strictObject({
  ...addressInputShape,
  expected_image_sha256: sha256Schema.optional(),        // Ghidra "Executable SHA256" / REA subject digest
}).superRefine(refineAddressInput);                       // per item: exactly one of address | static_va (nested, so no root anyOf)
export const mapAddressInput = z.strictObject({
  session_id: z.uuid().optional(),                        // absent ⇒ pure-arithmetic mode (CLI `bea rebase`)
  items: z.array(mapItemSchema).min(1).max(256),
  verify_bytes: z.number().int().min(0).max(256).default(16),   // live mode only
  image_path: z.string().min(1).max(1024).optional(),     // pure mode: the on-disk PE
  runtime_base: hexInputSchema.optional(),                // pure mode: the base to map to (or omit for static↔rva only)
  symbols: z.array(z.strictObject({ rva: hexInputSchema.optional(), static_va: hexInputSchema.optional(),
             name: z.string().min(1).max(1024), size: z.number().int().min(1).max(2 ** 32).optional() })).max(4096).optional(),
  symbols_module: z.string().max(600).optional(),         // module the symbols belong to (default: main)
  symbols_source: z.enum(["ghidra", "rea", "ida", "binja", "analyst", "other"]).optional(),
  external_ref: z.strictObject({ system: z.enum(["rea", "ghidra", "other"]), id: z.string().max(256),
                                 image_sha256: sha256Schema.optional(), image_base: hexInputSchema.optional() }).optional(),
  sensitive_values: sensitiveValuesInput.optional(),
}).superRefine((v, ctx) => {
  if (!v.session_id && !v.image_path) ctx.addIssue({ code: "custom", path: ["image_path"], message: "Without session_id, give image_path (pure arithmetic mode)." });
  if (v.session_id && (v.image_path || v.runtime_base)) ctx.addIssue({ code: "custom", path: ["image_path"], message: "image_path/runtime_base are only for mode without session_id." });
});
```

Output: `recordedOutput({ results: z.array(mapItemResultSchema).max(256), symbols_registered: z.number().int().exactOptional() })`.

```ts
export const mapItemResultSchema = z.strictObject({
  index: z.number().int(),
  status: z.enum(["mapped", "non-image", "error"]),
  address: addressRefSchema.exactOptional(),
  image_check: z.enum(["match", "mismatch", "unchecked"]).exactOptional(),
  verification: z.strictObject({
    status: z.enum(["match", "mismatch", "partial", "not-applicable", "skipped"]),
    compared: z.number().int(), equal: z.number().int(),
    excluded: z.strictObject({ iat: z.number().int(), delay_iat: z.number().int(), loader_thunk: z.number().int(),
                               loader_cfg: z.number().int(), zero_fill: z.number().int(), unreadable: z.number().int() }),
    own_effects_restored: z.number().int(),
    differences: z.array(z.strictObject({ rva: hexSchema, size: z.number().int(), class: z.enum(["unexplained", "foreign-or-agent-patch"]),
                                          live_hex: z.string().max(64), expected_hex: z.string().max(64) })).max(8),
    reason: z.enum(["writable_section", "no_session", "zero_bytes_requested", "unreadable"]).exactOptional(),
  }).exactOptional(),
  issue: z.strictObject({ code: z.string(), message: z.string(), details: jsonObjectSchema.exactOptional() }).exactOptional(),
});
```

### 18.2 Algorithm

```
mapAddresses(input):
  literals ← sensitiveLiterals(input.sensitive_values, server)
  if input.symbols: registerCallerSymbols(...)          // 19.3; records bea.symbols.caller first, links it
  ctx ← live (session's instance, current map epoch → ensureRecorded) | pure (PeImage(image_path), runtime_base?)
  if live: capture ← InstanceRegistry.capture(instance)   // only when verify_bytes > 0 (anchored record)
  for each item i:
    p ← parseAddressInput(item) ; on issue → results[i] = {status:"error", issue} ; continue
    ref ← AddressResolver.resolve(ctx, p, {expected_image_sha256})
         on error → results[i] = {status:"error", issue:{code, message, details}} ; continue
    if ref.module == null → results[i] = {status:"non-image", address: ref} ; continue
    image_check ← expected? (ref.image_sha256 == expected ? "match" : "mismatch") : "unchecked"
       (external_ref.image_sha256 counts as expected when the item has none)
    if live ∧ verify_bytes > 0: verification ← verifyBytes(ctx, ref, verify_bytes)   // 18.3
    results[i] = {status:"mapped", address: ref, image_check, verification?}
  coverage ← complete, or partial(entry_errors, dropped = #errors)
  confidence ← "derived"; downgrade to "inferred" if any item has image_check=="mismatch"
                or verification.status=="mismatch" with an "unexplained" difference
  limitations: STATIC_UNBOUND (any static item with image_check "unchecked"), IMAGE_MISMATCH, BYTES_MISMATCH,
               FOREIGN_PATCH, CALLER_STATIC_BASE(pe), PURE_ARITHMETIC (pure mode), IMAGE_CHANGED_ON_DISK
  record bea.address.map:
     subject: live → process-instance(+mm) | pure → image(sha256 of image_path)
     authority: weakest-parent(live-process via the bea.modules.map link | static-artifact)
     anchor: required iff any bytes were read (observation), else none (deterministic derivation dedups)
     evidence_links: [bea.modules.map ev_, bea.symbols.caller ev_ (if any)]
     external_refs: [input.external_ref] when given
     locations: locationOf(ref) for every mapped item
  auto-unknown (14.4) on any mismatch
  return envelope { results, symbols_registered? }
```

### 18.3 Byte verification (`src/domain/address/verify.ts`, pure; I/O in the service)

```
verifyBytes(ctx, ref, n):
  sec ← pe.sectionOf(rva)
  if sec.perms has "w"                    → {status:"not-applicable", reason:"writable_section"}   // .data/.bss change at runtime
  live ← agent.read(va, n)  (stops at the first unreadable page; unreadable tail → excluded.unreadable)
  live ← EffectRegistry.originalBytes(instance, va, n) applied over live   // BEA's own hooks/patches restored → own_effects_restored
  exp  ← pe.imageBytes(rva, n, module.base)                                 // file + base relocations
  mask ← pe.loaderWritten() ∩ window (iat, delay-iat, loader-thunk, loader-cfg) ∪ zero-fill bytes (readRva.backed==0)
  diff ← { j : ¬mask[j] ∧ live[j] ≠ exp[j] } coalesced into ranges (gap ≤ 4)
  class each range: "foreign-or-agent-patch" if it intersects FootprintScanner ranges of this module (18.4),
                    else "unexplained"
  status: compared==0 → "partial" (if unreadable) | "skipped";
          diff ∅ → (unreadable > 0 ? "partial" : "match");  diff ≠ ∅ → "mismatch"
```

VERIFIED basis [S2-lab E2/E2c]:
- **Code matches exactly after relocation.** Main-image `.text`: 0 of 37,776 bytes differ.
- **The loader writes** IAT slots (gcc `.idata`: 377 B, all IAT; kernel32 `.rdata`: 7,632 B, all IAT), `.didat`
  delay-IAT (KernelBase 355 B) and `fothk` thunks (3–9 B per system DLL, identical with and without Frida).
- **The Frida agent itself patches code** in the injected process: `ntdll!LdrLoadDll`, one unexported ntdll
  function (RVA 0x1f440 on build 26200) and `kernel32!FatalExit`. Comparing against a Frida-free process (0
  `.text` differences) proves these come from injection.
- **Writable sections always differ** at runtime: `.data`/`.bss`/`.mrdata` had 6–2,707 differing bytes.

### 18.4 FootprintScanner (`src/evidence/FootprintScanner.ts`)

```ts
export interface FootprintScanner {
  /** Executable, non-writable sections of one module: live vs imageBytes, excluding loader-written classes and BEA's own effects. */
  scan(instance: PiId, module: ModuleEntry, signal?: AbortSignal): Promise<Result<readonly { rva: number; size: number }[], BeaError>>;
}
```

- **When it runs.** Lazily, once per (instance, module base), the first time a verification in that module finds
  a difference. Recommended to S3 as well: run it at agent load for `ntdll.dll`, `kernel32.dll` and
  `kernelbase.dll`, and attach the ranges to the `bea.process.instance` record (`agent_footprint`, as
  AddressText + legend).
- **Cost.** About 3.7 MB of reads at 600 MB/s [ext-frida §1.9] plus a JS compare, in total ≈ 20–30 ms
  (estimated).
- **Classification.** The class is `foreign-or-agent-patch`. A scan cannot tell Frida's patches from overlay,
  EDR or AV hooks: BEA cannot read the target before injecting. The VERIFIED Frida sites above are documented,
  not hard-coded, because RVAs are build-specific.

---

## 19. Symbolization policy (`src/domain/address/symbolize.ts`)

### 19.1 Order, first hit wins

1. **Caller table** (19.3), keyed by `image_sha256`. An entry matches when:
   - `rva ≤ x < rva+size` (size given); or
   - `x == rva` exactly; or
   - the `.pdata` function containing `x` has `primary_begin == rva`.

   Result: `{name, kind:"caller", source:"caller-table", offset: x − rva, evidence_id}`.
2. **PE export.** Exact `x == export.rva` → offset 0. Or the `.pdata` function containing `x` has
   `primary_begin == export.rva` → offset `x − start`. **Never "nearest preceding export"**: dbghelp did exactly
   that and named a static function after the wrong export [ext-frida §3.12]. Data exports match exactly only.
3. **Import slot.** `x ∈ [slot_rva, slot_rva+8)` → `{name: "<dll>!<name>" or "<dll>!#<ord>", kind:"import-slot"}`.
4. **`.pdata` function**: `{name:null, kind:"function", source:"pe-pdata", function_start: primary_begin,
   function_end: fragment end, fragment, offset: x − primary_begin}`. Bounds only; no fabricated
   `sub_XXXX` names.
5. None: `symbol` omitted.

`DebugSymbol` (dbghelp) is **never** used by default. With an explicit `symbol_hints:true` on tools that support
it (owned by S3), a `{kind:"debug-hint", source:"dbghelp"}` entry is added **beside** the policy result and
`DEBUGSYMBOL_HINT` is attached. Its `moduleName` is ignored because it is wrong for system DLLs
[ext-frida §3.12]. PDB use is unverified (L5).

### 19.2 Why caller tables matter for the motivating workflow

MSVC game executables export almost nothing, so for such games the only names come from Ghidra/REA.
`.pdata` gives exact function bounds: Frida's `findFunctionRange` matched objdump [ext-frida §3.12], and the
chain resolution is VERIFIED against pefile.

### 19.3 Caller symbol tables

`map_address {symbols, symbols_module, symbols_source}` registers names for the module's `image_sha256`. It
records `bea.symbols.caller`:
- subject `image`, confidence `inferred`;
- authority `imported`, or `analyst-inference` when `symbols_source == "analyst"`;
- result: `{module_key, count, table: BlobRef(NDJSON {rva, name, size?}), source}`.

Static VAs are converted with the module's preferred base, or the given `static_base`. The table is kept in
memory per image digest for the run, so the names apply to every instance of that binary. Later registrations
override earlier entries at the same RVA, and each name carries its source `evidence_id`.

---

## 20. Errors raised by this subsystem

These map onto BRIEF §1.6 codes. The tag union, projection and messages belong to S1.

| Situation | Code | Retryable | Recovery | Details |
|---|---|---|---|---|
| address/filters/CAS input invalid | `invalid_request` | no | `inspect_input_contract` | `issues[]` with `path` |
| module not loaded, forwarder unresolved, VA unmapped | `address_unmapped` | after refresh | `refresh_module_map{instance_id}` | `reason`, `token`, `suggestions` |
| PE32/WoW64, non-PE image | `unsupported_target` | no | — | `reason` |
| record/bundle ID mismatch, conflicting record, corrupt blob/chunk | `evidence_integrity_mismatch` | no | — | `ids[≤10]`, `what` |
| unknown CAS lost | `revision_conflict` | yes | — | `unknown_id`, `expected_revision`, `current_revision` |
| quota reached / disk full | `resource_constraint` (`resource:"disk"`) | no in this run | — | `quota`, `limit_mib`, `knob`, `effects_applied` |
| response overflow | `resource_constraint` (`resource:"transport"`) | no | — | `evidence_reference`, `continuation` |
| export exists without overwrite; I/O; staging cleanup | `file_operation_failed` | no | — | `reason: exists/io/rename`, `path`, `published?` |
| unknown ID or evidence ID not in the ledger | `invalid_request` | no | — | `reason:"missing"`, `id` |
| pid identity disagreement at spawn/attach | `instance_mismatch` | no | `reattach` | `expected`, `actual` |
| internal invariant violated | `execution_failure` | no | — | `effects_applied` |

Every error raised after an effect was applied carries `details.effects_applied` [rea-evidence §10.1].

---

## 21. Interfaces

### 21.1 Provided (ports and services; all return `Result`)

```ts
// src/evidence/index.ts
export interface EvidenceRuntime {                    // one per run; constructed by the composition root
  readonly run: { id: RunId; dir: string; kind: RunHeader["kind"] };
  readonly clock: SeqClock;
  readonly recorder: Recorder;                        // 7.9
  readonly instances: InstanceRegistry;               // 4, 21.2 handshake inputs
  readonly modules: ModuleMapTracker;                 // 5
  readonly effects: EffectRegistry;                   // 6.4
  readonly streams: StreamStore;                      // 10.4
  readonly blobs: BlobStore;                          // 11
  readonly unknowns: UnknownRegistry;                 // 14
  readonly query: EvidenceQuery;                      // 12: summary/complete/slice
  readonly bundles: { export(i: ExportInput, s?: AbortSignal): Promise<Result<ExportOutput, BeaError>>;
                      import(i: ImportInput, s?: AbortSignal): Promise<Result<ImportOutput, BeaError>> };
  readonly address: { resolver: AddressResolver; map: MapAddressService; footprint: FootprintScanner };
  readonly pe: PeImageCache; readonly hashes: FileHashCache;
  status(): EvidenceStatus;                           // for bea_status
  finalize(reason: "shutdown" | "cli-exit"): Promise<Result<void, BeaError>>;
}
export interface EvidenceStatus { run_id: RunId; home: string;
  usage: { ledger: { bytes: number; quota: number; reserve: number }; blobs: { bytes: number; quota: number };
           streams: { bytes: number; quota_total: number; per_stream_quota: number; live: number } };
  counts: { evidence: number; effects_active: number; unknowns_open: number; instances: number } }

export interface InstanceRegistry {
  register(obs: InstanceObservation): Promise<Result<ProcessInstance, BeaError>>;   // computes pi_, writes pi line + bea.process.instance
  get(id: PiId): ProcessInstance | undefined;
  capture(id: PiId): AnchorCapture;                   // seq + epochs + perturbation (call inside the instance op lock)
  update(id: PiId, change: Partial<Pick<ProcessInstance, "state" | "exit">>): Promise<Result<void, BeaError>>;
  hashImage(id: PiId, signal?: AbortSignal): Promise<Result<string, BeaError>>;
}
export interface InstanceObservation {
  device_id: "local"; pid: number; ownership: "owned" | "attached";
  start_time: { source: StartTimeSource; value: string }; start_time_cross_check?: { source: StartTimeSource; value: string };
  main_module_path: string; agent: AgentIdentity; environment: ProcessInstance["environment"];
  initial_modules: { epoch: number; modules: { name: string; base: Hex; size: number; path: string }[] };
  launch?: ProcessInstance["launch"]; containment?: JsonObject; literals: SensitiveLiterals;
}
export interface ModuleMapTracker {
  apply(instance: PiId, ev: { op: "load" | "unload"; epoch: number; module: { name: string; base: Hex; size: number; path: string } }): void;
  current(instance: PiId): { epoch: number; map: () => ModuleMap };
  at(instance: PiId, epoch: number): ModuleMap | undefined;
  ensureRecorded(instance: PiId, epoch: number, operation: string): Promise<Result<{ module_map_id: MmId; evidence_id: EvId }, BeaError>>;
}
export interface EvidenceQuery {
  summary(i: z.infer<typeof getEvidenceInput>): Result<GetEvidenceSummary, BeaError>;
  complete(id: string): Promise<Result<GetEvidenceRecord, BeaError>>;
  slice(id: EvId, pointer: string, offset: number, limit: number, format: "hex" | "base64"): Promise<Result<GetEvidenceSlice, BeaError>>;
}
```

Zod fragments for S1 contracts: `addressInputShape`, `refineAddressInput`, `addressRefSchema`, `AddressText`,
`moduleLegendSchema`, `coverageSchema`, `pageSchema`, `recordedOutput`, `pollOutput`, `nextStepSchema`,
`sensitiveValuesInput`, `hexInputSchema`, the ID schemas, `getEvidenceInput/Output`,
`exportEvidenceInput`/`importEvidenceInput`, the `record_unknown` input and the `mapAddressInput`/output.

### 21.2 Required from other subsystems

| From | Need | Why |
|---|---|---|
| S1 (contracts/MCP) | `ToolContract.recording` (`always`/`never`), `identityExclude`, `returnsTargetContent`, `byteFields` passthrough; Delivery (spread envelope as structuredContent + identical compact JSON text, untrusted `_meta`, transport-budget continuation to `get_evidence`); error projection with `details.effects_applied`/`partial_observation`; pass-through validation turning zod issues into `InputIssue{path, reason}` | 7.9, 8, 20 |
| S3 (Frida sessions/agent) | **per-instance operation lock** for every target-touching op; agent handshake `{pid, creation_100ns (GetProcessTimes), main_module_path, module_epoch:1, modules[], platform, os_version, bundle_sha256, version, runtime}`; module observer events with agent epochs; `read(va, n)` chunked by page; `resolveExport(module, name)` (API sets); stream batch messages `{bea:"evt", st, first_seq, count, dropped_before, module_epoch, final?}` + ArrayBuffer with **seq consumed by dropped events**; `flush(stream)` returning `last_generated_seq`; ≥ 32 original bytes captured before every code-modifying instrument; effect confirmations (applied/expired) with agent timestamps; call `capture()` right after observations | 3, 5, 6, 10, 18 |
| Process subsystem | jobhost `adopted/started.creationTime100ns`; optional `observe <pid>` mode; exit code/NTSTATUS + `root-exit`/`settled`; ownership; liveness signals | 4 |
| S4 (emulation) | `config_digest` input from `session.open` provenance; isolation (`snapshot`/`chain`) per call; dump digests for dump-backed sessions; deviations → coverage reasons | 7.2, 7.3 |
| Config subsystem | BEA_HOME; quota values with bounds; `sensitive_values_file`; `configuration_invalid` handling | 9.7, 15 |
| S5 (CLI) | commands `bea evidence show/export/verify/prune`, `bea rebase` (pure map_address), `bea pe <path>` (list_module_symbols disk mode); `--keep-run`, `--evidence-out` | 9.2, 13 |

---

## 22. Tests this design requires (owned by S2)

- **canonical:**
  - RFC 8785 Appendix-B number vectors;
  - UTF-16 key order (supplementary-plane keys);
  - property test against `canonicalize@3.0.0` (devDep) on 10 k random values;
  - NaN/Infinity/cycles throw.
- **ids:** golden IDs for one fixture record per family. They pin projections, so a schema change that alters
  IDs must update goldens deliberately.
- **evidence:** each invariant in 7.1; authentication rejects a one-character change; `wall` changes do not
  change the ID; `seq` changes do.
- **envelope:** every contract's result shape has no reserved keys; `next.arguments` parse with the target
  tool's input schema; worst-case envelope bytes ≤ 2 MiB per tool (computed from bounds).
- **coverage:** registry completeness (every emitted reason registered, every reason has a limitation); merge
  algebra; "paging is not truncation".
- **effects:** state-machine table (all legal and illegal transitions); epoch increments; taint propagation;
  agent effect excluded from the list.
- **ledger:**
  - append/reload/authenticate;
  - torn-tail tolerance (E5 pattern);
  - duplicate vs conflict;
  - record-before-deliver with injected write failures (the error carries `effects_applied`);
  - reserve semantics;
  - an uncommitted import bracket is ignored.
- **streams:** frame codec; chain verification; seal-at-checkpoint; gap accounting with synthetic drops;
  quota stop and `onQuota`; redacted batch frames; decode round-trip per encoding.
- **bundles:**
  - dir and zip round-trip (byte-identical `records.jsonl`, the same `bundle_digest`);
  - tampered record, blob, chunk or manifest → rejected and the ledger unchanged;
  - traversal names and zip-bomb ratio rejected;
  - an overwrite rollback path;
  - an import conflict is atomic.
- **unknowns:** CAS conflict; revision chain; the verified rule with live, emulation and imported-origin
  support; auto-unknown templates.
- **redaction:** UTF-8 and UTF-16LE in hex fields; property-name redaction; boundary re-formation returns `""`;
  blob withholding; effect `before` not persisted but revert works; minimum length enforced.
- **address grammar:** table-driven valid/invalid cases (every form, quoting, `@0xbase`, ordinals, displacement,
  `+0x` main, 47-bit bound, decimal hint); AddressText round-trip.
- **PE reader** (gcc fixtures built in test setup + system DLLs):
  - section long names; exports with forwarders and NONAME; imports and delay imports with slot RVAs;
    `.pdata` chains; relocations; CodeView; TLS;
  - an optional cross-check against pefile (named skip if `py -I -c "import pefile"` fails) mirroring
    [S2-lab E1];
  - malformed-file fuzz (truncate or corrupt headers and directories → `PeError` or `issues`, never a throw or
    hang).
- **acceptance (real Frida, owned fixture):**
  - `+0x<rva of export>` equals `Module.findExportByName`;
  - static_va with the preferred base maps to the export;
  - `verify_bytes` gives `match` on `.text`;
  - after `write_memory` (own effect) still `match` with `own_effects_restored > 0`;
  - a footprint scan of ntdll finds ≥ 1 range;
  - `.data` gives `not-applicable`;
  - the owned-PID leak assertion [rea-testing §11.3].

---

## 23. Lab results for this design (`bea-lab/design-S2-evidence/`)

| ID | File | What | Result (VERIFIED on this host) |
|---|---|---|---|
| E1 | `pe.mjs`, `pefile_oracle.py`, `e1_compare.mjs` | PE reader prototype vs pefile 2024.8.26 on `fixture_gcc.exe`, `bea_fixture.dll`, kernel32, KernelBase, ntdll, user32, d3d11 | All fields equal (image base, size, entry, timestamp, section names, exports incl. forwarders, imports incl. delay with slot RVAs, `.pdata` count and chained count, DIR64 count, CodeView GUID/age/path, TLS callbacks). The single difference: pefile names KernelBase's ordinal-only delay import `oleaut32!#6` as `SysFreeString` from its built-in table. Chains: 43/1,675/1,672/373/497 chained entries, 100% resolving in-table; 0 INDIRECT entries. Parse 1–31 ms (full read) |
| E2 | `e2_verify_bytes.mjs` (owned `fixture_gcc.exe`, killed after; 0 processes left) | Live sections vs file + relocations, Frida-injected | Main `.text` 0/37,776 differ; differences only in IAT (`.idata` 377 B, kernel32 `.rdata` 7,632 B, KernelBase 4,488 B, msvcrt 927 B), `.didat` (355 B), `fothk` (3–9 B), writable sections, and **code patches at `ntdll!LdrLoadDll`, an unexported ntdll function (RVA 0x1f440) and `kernel32!FatalExit`**. Frida `module.size == SizeOfImage` for 5/5 modules |
| E2c | `e2c_nofrida.py` | The same comparison inside a Frida-free process (the Python interpreter's own ntdll/kernel32/KernelBase) | Executable sections: 0 differences except `fothk` (9/3/4 B). This proves the ntdll/kernel32 code patches in E2 come from Frida injection |
| E4 | `e4_filekey.mjs` | NTFS file-key stability | Rewriting content and restoring mtime still changed `ctimeNs`; rename-replace changed `ino`; `ino` needs bigint |
| E5 | `e5_ledger_bench.mjs` | Record pipeline cost | 20 k records, 1,855 B average: **48.5 µs/record** (canonicalize ×2 + SHA-256 + writeSync + index); fsync 21 ms; reload + re-authenticate **23.2 µs/record**; torn tail detected and truncated (42 B) |
| E6 | `npm view` (metadata only, no install) | Library versions | `yazl` 3.3.1 (MIT), `yauzl` 3.4.0 (MIT), `canonicalize` latest 5.1.0 (REA pins 3.0.0), `@toon-format/toon` 4.4.0 |
| E7 | `e7_zod_api.mjs` (REA's zod 4.4.3, read-only) | zod APIs used by these schemas | All 15 checks pass (see A14); `ZodRawShape` is in `v4/classic/compat.d.ts` as `core.$ZodShape` |

---

## 24. Assumptions and conflicts

### 24.1 Assumptions (BELIEVED; each needs a lab check or a fallback)

The numbering has gaps on purpose. A1 (Frida `module.size` = SizeOfImage), A9 (NTFS ChangeTime invalidates the
hash-cache key) and A17 (`ino` changes on rename-replace) were verified in the S2 lab (E2, E4), so they are no
longer assumptions. The remaining numbers stay stable so other designs can cite them.

| # | Assumption | Fallback if false |
|---|---|---|
| A2 | The agent can read its own creation FILETIME via `GetProcessTimes(GetCurrentProcess())` through `NativeFunction` | `jobhost observe <pid>` (A3/§4.1 step 3), then `frida-started` + limitation |
| A3 | Frida `started` precision is unknown (BRIEF L2); it is used only as a fallback | `first-observed` |
| A4 | `attachModuleObserver.onRemoved` fires on FreeLibrary | Re-enumerate modules on `list_modules` and on address-resolution misses, and bump the epoch on a diff |
| A5 | Frida delivers `send()` messages and the RPC reply of one script in order (checkpoint barrier) | The agent echoes `last_generated_seq` in a final batch header, and the host waits for it (with a timeout → `tail_unconfirmed`) |
| A6 | yazl 3.3.1 / yauzl 3.4.0 handle ZIP64 correctly | Directory bundles only, with zip limited to < 4 GiB and < 65,535 entries |
| A7 | NTFS directory rename is atomic for publishing; AV/Explorer may cause transient EPERM/EBUSY; directory fsync is unsupported on win32 | Retries; on failure keep the destination unchanged |
| A8 | `RUNTIME_FUNCTION_INDIRECT` (UnwindData bit 0) semantics. Chains were VERIFIED, but no indirect entry has been observed | Treat it as malformed: `issues` entry, fragment-only lookup |
| A10 | Completed `write()` calls survive a BEA process crash (OS page cache) | Documented loss window; detected on read |
| A11 | `fothk` thunk patching is specific to Windows 11 system DLLs; game binaries lack the section | Name-based mask only affects sections with that name |
| A12 | The Frida agent's code-patch sites (VERIFIED on 26200 / Frida 17.23.2) differ by build and version | Discovered dynamically by FootprintScanner, never hard-coded |
| A13 | Windows x64 user-mode VA ceiling is 0x7FFF'FFFF'FFFF | Raising the constant is a one-line change |
| A14 | **Mostly VERIFIED [S2-lab E7]:** `z.iso.datetime()`, `z.uuid()`, `.exactOptional()` (rejects an explicit `undefined`), `.shape` after `.refine`, nested discriminated unions, regex-keyed `z.record`, `z.number()` rejecting NaN/±Infinity, nested item refine paths (`["items",0,"address"]`), and `z.toJSONSchema` keeping a refined root as `type:"object", additionalProperties:false`. `ZodRawShape` exists only as a compat alias of `core.$ZodShape` | Type helpers against `z.core.$ZodShape` |
| A16 | Table parsing of a ~100 MB game executable is ≤ 50 ms and SHA-256 ≥ 1 GB/s | Tables are lazy; hashing is cached across runs |
| A18 | Loader paths are long names (no 8.3 forms) | `fs.realpathSync.native` before computing the path key |
| A19 | Frida resolves API-set forwarded exports via `Module.findExportByName` on the declaring module | Report `forwarder_unresolved` with the forwarder string |
| A20 | IMAGE_LOAD_CONFIG_DIRECTORY64 offsets 0x70/0x78 for the CFG check/dispatch pointers | Treat differences there as `unexplained` (conservative) |

### 24.2 Conflicts between notes and orchestrator decisions, and how they were resolved

1. **Storage root.** The note and BRIEF use `%LOCALAPPDATA%/bea/sessions/<session_id>/` [rea-evidence §10.7]; the
   orchestrator fixed `BEA_HOME/runs/<run_id>/`. **Followed the orchestrator.** The ledger is per run and shared
   by every session and HTTP client of the server process.
2. **Envelope shape.** BRIEF §1.5 nests `result`; the orchestrator's example spreads it. **Spread**, with
   reserved keys and a contract test.
3. **`imported` authority.** [rea-evidence §10.7] says to mark imported records `imported` "in the importing
   session's view", which conflicts with immutable IDs. **Resolved:** `origin` is a view and index attribute;
   `authority:"imported"` means content wrapped from outside BEA.
4. **`pi_` identity input.** The note's `{device_id, pid, start_time, image{path, sha256…}}` became
   `{device_id, pid, start_time, image_path_sha256}`. The image hash is a lazy attribute and the path is
   digested so it stays redactable.
5. **`mm_` identity.** The note includes module sha256 values; **excluded**, because hashing every DLL of a game
   at attach is too slow. Hashes live in the cache and in AddressRefs.
6. **Emulation confidence.** [rea-evidence §10.9] says `observed` and [ext-backends §9.7] says "derivation";
   **observed + authority emulation** (7.3).
7. **`seq` scope.** The note says session-global; changed to **run-global**, and `run_id` is part of the anchor,
   so IDs never merge across runs.
8. **Ledger fsync.** The note says "fsynced in batches"; the orchestrator says no per-batch fsync.
   **Followed the orchestrator** (fsync points in 9.6).
9. **Effect statuses.** Added `expired` and `permanent` to the note's set. Status is a fold over transition
   lines, never a mutable field.
10. **Per-tool `detail:"complete"`** [rea-evidence §10.11] was replaced by `get_evidence detail:"complete"`, so
    each tool has exactly one output shape.
11. **The agent-injection effect** is not listed in `active_effect_ids`; it is implied (S2-8).
12. **Sensitive literals** must be at least 4 UTF-8 bytes. REA has no minimum.
13. **Quotas.** "4 GiB blobs" is read as per run. Added a 4 GiB all-streams aggregate cap and an 8 MiB
    lifecycle reserve; both are configurable.
14. **Bulk addresses** use AddressText + legend instead of a full AddressRef per element. The BRIEF's
    "all forms on every address" is satisfied mechanically by the legend.
15. **Export/import** are not Evidence (no target subject). Imports leave bracketed ledger lines; exports carry
    their own digest.
16. **`query_` replay cache**: reserved, not built in v0.1. Emulation is fast enough, and dedup by
    deterministic IDs already covers repeated static and baseline-emulation queries.
17. **The REA-importable projection** [rea-evidence §13 Q6] stays out of scope. `external_refs` carries REA IDs
    opaquely.
