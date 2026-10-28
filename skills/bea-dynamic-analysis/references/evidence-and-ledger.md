# Evidence and the function ledger

Every recording BEA makes is an **evidence record** in the run's ledger under `BEA_HOME\runs\<run_id>\`. Its id
(`ev_` + 64 hex) is a content address: the same observation always has the same id, and the record cannot be edited
afterwards.

## The envelope

| Key               | Meaning                                                                                                                                                        |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `evidence_id`     | the record behind this result; `null` for polls (`bea_status`, `list_processes`, `wait`, `scan_results`, `get_evidence`, `export_evidence`, `import_evidence`) |
| `predicate_type`  | what kind of record (`bea.memory.read`, `bea.call.oracle`, `bea.diff`, …)                                                                                      |
| `confidence`      | `observed` (captured), `derived` (computed from observations), `inferred` (heuristic or a mismatch)                                                            |
| `authority`       | `live-process`, `emulation`, `static-artifact` (read from a file), `imported`, `analyst-inference`                                                             |
| `coverage`        | `{status: complete                                                                                                                                             | partial    | unknown, truncated, dropped, reasons[]}` |
| `limitations`     | fixed BEA sentences: what this result cannot show                                                                                                              |
| `instance_id`     | the process instance (`pi_…`): pid + start time + image identity                                                                                               |
| `perturbation`    | `{level: none                                                                                                                                                  | agent-only | passive                                  | intrusive, active_effect_ids, tainted}` |
| `effects_applied` | `fx_…` ids of target changes this call made (hooks, writes, calls)                                                                                             |
| `redactions`      | how many literals were redacted                                                                                                                                |
| `next`            | up to three suggested follow-up calls (BEA-authored)                                                                                                           |

`page{offset, limit, total, next_offset}` is paging, never coverage: page through with `offset` until `next_offset` is
null.

## Classifying statements

| Class       | Source                                                            | Example                                                                | How to write it                 |
| ----------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------- | ------------------------------- |
| observation | a BEA record, `authority:"live-process"`, `confidence:"observed"` | the hook saw `dt ∈ {0.016667, 0.008333}`                               | "observed (bea:ev_…): …"        |
| derivation  | computed from observations or static data                         | static VA of a writer; struct base from an operand; an emulated return | "derived from bea:ev_…: …"      |
| inference   | your interpretation                                               | "this is the tyre model"                                               | "I infer …, because …"          |
| unknown     | not established                                                   | "whether the value is clamped elsewhere"                               | `record_unknown` + "unknown: …" |

- Emulation results (`authority:"emulation"`) are derivations about the emulator, never observations of the
  process.
- Heuristics are inferences until confirmed: struct bases, `insn_confidence` other than `exact`, anti-cheat signals,
  caller-supplied symbol names.
- `confidence:"inferred"` on a BEA result (for example an image or byte mismatch in `map_address`) is a warning.

## Stating the window

Every runtime claim says:

- **which process**: pid, image sha256 prefix, start time (from `identity`), owned or attached;
- **which window**: `duration_ms`, number of events, threads, inputs;
- **how complete**: `coverage.status` with its reasons, `dropped`, and the relevant `limitations`.

"Not observed in this 2 s window on these threads" is the strongest negative statement BEA supports. Partial
coverage (drops, quota, an active recording read mid-way, a deadline) must be stated next to the claim it limits.

## Taint

`call_function`, `diff_function`'s live leg, `write_memory`, `override_function` and `run_script` change the
process. After them `perturbation.tainted` is true for every later result in that session. Cite later observations
as "after the oracle calls at …". Hooks and watches are perturbations too (`level:"passive"`/`"intrusive"`), but they
are reverted when stopped.

## Unknowns

`record_unknown {question, session_id?, severity, supporting:[ev_…], probes:["…next step…"]}` creates an open
question; update it with `{unknown_id, expected_revision, status, supporting|contradicting, resolution}`.

- Statuses: `open`, `investigating`, `blocked`, `contradicted`, `resolved`. `resolved` needs supporting evidence of
  sufficient authority (an emulation result cannot resolve a question about the live process).
- `revision_conflict` means someone updated it first: re-read with `get_evidence {entity:"unknowns"}` and retry.
- `diff_function` and `map_address` record unknowns automatically on non-equivalence or mismatch.

## Reading the ledger

- `get_evidence {detail:"summary", entity:"evidence", filters:{operation:"hook_function"}}` lists records (also
  `entity:"effects" | "unknowns" | "instances"`; filters by session instance, module, confidence, authority…).
- `get_evidence {detail:"complete", id:"ev_…"}` returns one record; `detail:"slice", pointer:"/result/…"` pages a
  large field or `#blob:<role>` a stored blob.
- After a client timeout or a cancellation, find what the call recorded with `filters:{operation:"<tool>"}`.

## Bundles

`export_evidence {format:"zip"}` writes a portable bundle (records, manifests, optionally all stream rows and blobs)
into the run's `exports\` directory; `session_id` limits it to one session. `import_evidence {path}` verifies and
imports a bundle (`validate_only:true` checks without importing); imported records keep their ids and authority with
origin `imported`. `sensitive_values` redact literals on export.

## The function ledger

Keep one row per function you touched, as TSV, and update it as evidence arrives:

```
static_va	module	rva	name	role	status	evidence	notes
0x140123460	game.exe	0x123460	(sub)	vehicle physics step	verified-on-tested-inputs	bea:ev_ab12…(diff), bea:ev_cd34…(hook)	dt∈{1/60,1/120}
0x14075b4a1	game.exe	0x75b4a1	(insn)	speed writer	observed	bea:ev_ef56…(watch)	movss [rbx+0x1c4], xmm6
```

| `status`                    | Meaning                                                    |
| --------------------------- | ---------------------------------------------------------- |
| `observed`                  | seen at runtime (hook, watch, trace)                       |
| `verified-on-tested-inputs` | a diff or oracle check passed on the listed vectors        |
| `inferred`                  | your interpretation, not yet tested                        |
| `unknown`                   | role not established (link the `unk_…` id in notes)        |
| `contradicted`              | evidence against an earlier claim; keep the row, cite both |

Cite with system prefixes so evidence from both tools stays unambiguous: `bea:ev_…` for BEA, `rea:ev_…` for REA. Use
the `static` form (`game.exe:0x…`) or `static_va` + `module` so the row lines up with Ghidra and REA.
