import { createHash, type Hash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { appendFile, mkdir, open, readdir, readFile, type FileHandle } from "node:fs/promises";
import { join } from "node:path";

import { canonicalJson, sha256Hex } from "../../domain/canonical.js";
import type { Clock, SequenceAllocator } from "../../domain/clock.js";
import { cancelled } from "../../domain/errors/constructors.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { Coverage } from "../../domain/evidence/coverage.js";
import { idOf, type FxId, type PiId, type RunId, type StId } from "../../domain/ids.js";
import type { JsonObject, JsonValue } from "../../domain/json.js";
import type { Logger } from "../../domain/logger.js";
import { NO_LITERALS } from "../../domain/redaction/literals.js";
import { bytesContainLiteral } from "../../domain/redaction/redact.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { CompactAnchor } from "../../domain/time.js";
import type {
  AppendOutcome,
  FrameBatchHeader,
  RecordedEvidence,
  StreamEndReason,
  StreamReader,
  StreamRecord,
  StreamSpec,
  StreamStore,
  StreamWriter,
} from "../../ports/evidence.js";
import { fileError, internalError, ioError } from "./errors.js";
import { fsyncPath, writeFileAtomic } from "./fsio.js";
import type { LedgerIndex, Origin } from "./LedgerIndex.js";
import type { QuotaGuard } from "./Quotas.js";
import { manifestCoverage, normalizeDropReason, type ManifestFacts } from "./streamManifest.js";
import {
  CHUNK_SEAL_BYTES,
  CHUNKS_ABSENT_MARKER,
  chunkFileName,
  decodeFrames,
  decodePayload,
  encodeFrame,
  nextChain,
  type ChainLine,
  type Frame,
  type FrameHeader,
} from "./streamFrames.js";

/** Streams (S2 §10): raw agent batches in framed, hash-chained chunk files; manifests are Evidence. */
const OPERATION = "evidence.streams";
/** Host-side write backlog per stream before appends answer "queue-full" (counted as host_queue_full drops). */
const MAX_PENDING_BYTES = 64 * 1024 * 1024;

export interface StreamDescriptor {
  readonly schema: "bea.stream.descriptor/1";
  readonly stream_id: StId;
  readonly source: StreamSpec["source"];
  readonly encoding: StreamSpec["encoding"];
  readonly decoders: JsonValue;
  readonly seq: "implicit";
  readonly opened: { readonly run_id: RunId; readonly seq: number };
}

export interface StreamHost {
  readonly runId: RunId;
  readonly streamsDir: string;
  readonly quotas: QuotaGuard;
  readonly index: LedgerIndex;
  readonly clock: Clock;
  readonly seq: SequenceAllocator;
  readonly logger: Logger;
  readonly ensureStarted: () => Promise<Result<void, BeaError>>;
  readonly epochs: (instance: PiId | null) => {
    readonly effect_epoch: number | null;
    readonly module_map_epoch: number | null;
  };
  /** effects of `instance` active at any time in [fromSeq, toSeq], except `exclude` and the agent-injected effect */
  readonly concurrentEffects: (instance: PiId, fromSeq: number, toSeq: number, exclude: FxId | null) => readonly FxId[];
  readonly recordManifest: (
    spec: StreamSpec,
    result: JsonObject,
    facts: { readonly coverage: Coverage; readonly limitations: readonly string[]; readonly lifecycle: boolean },
  ) => Promise<Result<RecordedEvidence<JsonObject>, BeaError>>;
  readonly syncLedger: () => Promise<void>;
}

interface OpenChunk {
  readonly index: number;
  readonly file: string;
  readonly handle: FileHandle;
  readonly hash: Hash;
  bytes: number;
  frames: number;
  records: number;
  first_seq: number | null;
  last_seq: number | null;
  dropped: number;
  redacted: number;
}

const descriptorText = (d: StreamDescriptor): string => canonicalJson(d as unknown as JsonValue);

export class FileStreamWriter implements StreamWriter {
  readonly stream_id: StId;
  readonly descriptor_sha256: string;
  readonly dir: string;
  readonly spec: StreamSpec;
  readonly #host: StreamHost;
  readonly #started: CompactAnchor;
  #state: "live" | "ended" = "live";
  #records = 0;
  #redacted = 0;
  #bytes = 0;
  #pending = 0;
  #agentHeaderDrops = 0;
  readonly #agentAttributed = new Map<string, number>();
  readonly #hostDrops = new Map<string, number>();
  #lastEnd = 0;
  #firstSeq: number | null = null;
  #finalSeen = false;
  #quotaHit: "stream" | "streams" | null = null;
  readonly #quotaCallbacks: (() => void)[] = [];
  readonly gapList: { from_seq: number; to_seq: number; kind: "dropped" | "redacted" }[] = [];
  #queue: Promise<void> = Promise.resolve();
  #writeError: unknown;
  #chunk: OpenChunk | undefined;
  #nextChunk = 0;
  #head: string;
  readonly sealed: ChainLine[] = [];
  readonly #unsynced: string[] = [];
  #final: Promise<Result<RecordedEvidence<JsonObject>, BeaError>> | undefined;

  constructor(
    host: StreamHost,
    descriptor: StreamDescriptor,
    descriptorSha: string,
    dir: string,
    spec: StreamSpec,
    started: CompactAnchor,
  ) {
    this.#host = host;
    this.stream_id = descriptor.stream_id;
    this.descriptor_sha256 = descriptorSha;
    this.#head = descriptorSha;
    this.dir = dir;
    this.spec = spec;
    this.#started = started;
  }

  get counters(): StreamWriter["counters"] {
    return {
      records: this.#records,
      dropped: this.droppedTotal,
      redacted: this.#redacted,
      bytes: this.#bytes,
      state: this.#state,
    };
  }

  get droppedTotal(): number {
    const attributed = [...this.#agentAttributed.values()].reduce((a, b) => a + b, 0);
    const host = [...this.#hostDrops.values()].reduce((a, b) => a + b, 0);
    return Math.max(this.#agentHeaderDrops, attributed) + host;
  }

  get headChain(): string {
    return this.#head;
  }

  get currentChunk(): { readonly file: string; readonly bytes: number } | null {
    return this.#chunk === undefined ? null : { file: this.#chunk.file, bytes: this.#chunk.bytes };
  }

  onQuota(callback: () => void): void {
    this.#quotaCallbacks.push(callback);
  }

  #countHostDrop(reason: string, n: number): void {
    if (n <= 0) return;
    this.#hostDrops.set(reason, (this.#hostDrops.get(reason) ?? 0) + n);
  }

  noteDropped(n: number, reason: string): void {
    if (!Number.isSafeInteger(n) || n <= 0) return;
    const code = normalizeDropReason(reason);
    if (code.agent) this.#agentAttributed.set(code.code, (this.#agentAttributed.get(code.code) ?? 0) + n);
    else this.#countHostDrop(code.code, n);
  }

  #fireQuota(): void {
    for (const callback of this.#quotaCallbacks.splice(0))
      queueMicrotask(() => {
        try {
          callback();
        } catch (cause) {
          this.#host.logger.warn("stream onQuota callback failed", {
            cause: cause instanceof Error ? cause : String(cause),
          });
        }
      });
  }

  /** SYNC enqueue: never blocks, never throws. */
  append(h: FrameBatchHeader, payload: Uint8Array): AppendOutcome {
    try {
      if (this.#state === "ended") return "closed";
      const count = Math.max(0, h.count);
      this.#agentHeaderDrops += Math.max(0, h.dropped_before);
      if (this.#quotaHit !== null) {
        this.#countHostDrop(this.#quotaHit === "stream" ? "stream_quota" : "stream_total_quota", count);
        return "quota-exceeded";
      }
      const redact = this.spec.literals.count > 0 && bytesContainLiteral(payload, this.spec.literals);
      const header: FrameHeader = {
        k: redact ? "redacted" : "batch",
        first_seq: h.first_seq,
        count,
        dropped_before: Math.max(0, h.dropped_before),
        recv_mono_ns: this.#host.clock.monoNs().toString(),
        module_map_epoch: h.module_map_epoch,
        ...(h.final === true ? { final: true as const } : {}),
        ...(h.bseq === undefined ? {} : { bseq: h.bseq }),
        ...(h.g0 === undefined ? {} : { g0: h.g0 }),
        ...(h.g1 === undefined ? {} : { g1: h.g1 }),
        layout_rev: 1,
      };
      const frame = encodeFrame(header, redact ? new Uint8Array(0) : payload);
      const quota = this.#host.quotas.reserveStream(this.#bytes, frame.length);
      if (quota !== "ok") {
        this.#quotaHit = quota;
        this.#countHostDrop(quota === "stream" ? "stream_quota" : "stream_total_quota", count);
        this.#fireQuota();
        return "quota-exceeded";
      }
      if (this.#pending + frame.length > MAX_PENDING_BYTES) {
        this.#host.quotas.releaseStream(frame.length);
        this.#countHostDrop("host_queue_full", count);
        return "queue-full";
      }
      this.#account(header);
      this.#bytes += frame.length;
      this.#pending += frame.length;
      this.#enqueue(() => this.#writeFrame(frame, header));
      return redact ? "redacted" : "accepted";
    } catch (cause) {
      this.#host.logger.warn("stream append failed", { cause: cause instanceof Error ? cause : String(cause) });
      return "closed";
    }
  }

  #account(h: FrameHeader): void {
    if (h.first_seq > this.#lastEnd + 1 && this.#lastEnd > 0)
      this.gapList.push({ from_seq: this.#lastEnd + 1, to_seq: h.first_seq - 1, kind: "dropped" });
    else if (this.#lastEnd === 0 && h.first_seq > 1)
      this.gapList.push({ from_seq: 1, to_seq: h.first_seq - 1, kind: "dropped" });
    if (h.k === "redacted" && h.count > 0)
      this.gapList.push({ from_seq: h.first_seq, to_seq: h.first_seq + h.count - 1, kind: "redacted" });
    if (h.k === "redacted") this.#redacted += h.count;
    else this.#records += h.count;
    this.#firstSeq ??= h.count > 0 ? h.first_seq : null;
    this.#lastEnd = Math.max(this.#lastEnd, h.first_seq + h.count - 1);
    if (h.final === true) this.#finalSeen = true;
  }

  #enqueue(task: () => Promise<void>): Promise<void> {
    const next = this.#queue.then(task).catch((cause: unknown) => {
      this.#writeError ??= cause;
      this.#host.logger.warn("stream write failed", {
        stream: this.stream_id,
        cause: cause instanceof Error ? cause : String(cause),
      });
    });
    this.#queue = next;
    return next;
  }

  async #openChunk(): Promise<OpenChunk> {
    const index = this.#nextChunk++;
    const file = chunkFileName(index);
    const handle = await open(join(this.dir, file), "wx");
    const chunk: OpenChunk = {
      index,
      file,
      handle,
      hash: createHash("sha256"),
      bytes: 0,
      frames: 0,
      records: 0,
      first_seq: null,
      last_seq: null,
      dropped: 0,
      redacted: 0,
    };
    this.#chunk = chunk;
    return chunk;
  }

  async #writeFrame(frame: Buffer, header: FrameHeader): Promise<void> {
    try {
      if (this.#writeError !== undefined) return;
      if (this.#chunk !== undefined && this.#chunk.frames > 0 && this.#chunk.bytes + frame.length > CHUNK_SEAL_BYTES)
        await this.#sealNow();
      const chunk = this.#chunk ?? (await this.#openChunk());
      let written = 0;
      while (written < frame.length) {
        const { bytesWritten } = await chunk.handle.write(frame, written, frame.length - written);
        written += bytesWritten;
      }
      chunk.hash.update(frame);
      chunk.bytes += frame.length;
      chunk.frames += 1;
      if (header.k === "redacted") chunk.redacted += header.count;
      else chunk.records += header.count;
      chunk.dropped += header.dropped_before;
      if (header.count > 0) {
        chunk.first_seq ??= header.first_seq;
        chunk.last_seq = header.first_seq + header.count - 1;
      }
    } finally {
      this.#pending -= frame.length;
    }
  }

  async #sealNow(): Promise<void> {
    const chunk = this.#chunk;
    if (chunk === undefined) return;
    this.#chunk = undefined;
    await chunk.handle.close();
    if (chunk.frames === 0) return;
    const sha256 = chunk.hash.digest("hex");
    this.#head = nextChain(this.#head, sha256);
    const line: ChainLine = {
      index: chunk.index,
      file: chunk.file,
      sha256,
      bytes: chunk.bytes,
      frames: chunk.frames,
      records: chunk.records,
      first_seq: chunk.first_seq,
      last_seq: chunk.last_seq,
      dropped: chunk.dropped,
      redacted: chunk.redacted,
      chain: this.#head,
    };
    await appendFile(join(this.dir, "chain.jsonl"), `${canonicalJson(line as unknown as JsonValue)}\n`);
    this.sealed.push(line);
    this.#unsynced.push(join(this.dir, chunk.file));
  }

  /** Resolves when every accepted frame is on disk. */
  async drained(): Promise<void> {
    await this.#queue;
  }

  #facts(endReason: StreamEndReason | null, tailConfirmed: boolean, checkpointSeq: number): ManifestFacts {
    const dropReasons: Record<string, number> = {};
    for (const [reason, n] of this.#agentAttributed) dropReasons[reason] = n;
    const attributed = [...this.#agentAttributed.values()].reduce((a, b) => a + b, 0);
    const unattributed = Math.max(0, this.#agentHeaderDrops - attributed);
    if (unattributed > 0) dropReasons["agent_buffer_full"] = (dropReasons["agent_buffer_full"] ?? 0) + unattributed;
    for (const [reason, n] of this.#hostDrops) dropReasons[reason] = (dropReasons[reason] ?? 0) + n;
    return {
      state: this.#state,
      endReason,
      tailConfirmed,
      dropped: this.droppedTotal,
      redacted: this.#redacted,
      dropReasons,
      unattributed,
      quotaMib:
        this.#quotaHit === null
          ? null
          : {
              kind: this.#quotaHit === "stream" ? "stream" : "all-streams",
              mib: Math.round(
                (this.#quotaHit === "stream"
                  ? this.#host.quotas.limits.streamBytes
                  : this.#host.quotas.limits.streamTotalBytes) /
                  (1024 * 1024),
              ),
            },
      checkpointSeq,
    };
  }

  #manifestResult(facts: ManifestFacts, checkpoint: CompactAnchor): JsonObject {
    const instance = this.spec.source.instance_id;
    return {
      stream_id: this.stream_id,
      source: { kind: this.spec.source.kind, channel: this.spec.source.channel, effect_id: this.spec.source.effect_id },
      state: facts.state,
      end_reason: facts.endReason,
      descriptor_sha256: this.descriptor_sha256,
      chunks: this.sealed.slice(0, 4096).map((c) => ({
        index: c.index,
        sha256: c.sha256,
        bytes: c.bytes,
        records: c.records,
        first_seq: c.first_seq,
        last_seq: c.last_seq,
      })),
      head_chain: this.#head,
      records: this.#records,
      dropped: facts.dropped,
      redacted: this.#redacted,
      drop_reasons: facts.dropReasons,
      first_seq: this.#firstSeq,
      last_seq: this.#lastEnd > 0 ? this.#lastEnd : null,
      started: { ...this.#started },
      checkpoint: { ...checkpoint },
      concurrent_effect_ids:
        instance === null
          ? []
          : [...this.#host.concurrentEffects(instance, this.#started.seq, checkpoint.seq, this.spec.source.effect_id)],
      tail_confirmed: facts.tailConfirmed,
      bytes: this.#bytes,
    };
  }

  async #record(
    endReason: StreamEndReason | null,
    tailConfirmed: boolean,
    lifecycle: boolean,
  ): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    if (this.#writeError !== undefined) return err(ioError(OPERATION, "write", this.dir, this.#writeError));
    const epochs = this.#host.epochs(this.spec.source.instance_id);
    const checkpoint: CompactAnchor = { seq: this.#host.seq.peek(), ...epochs };
    const facts = this.#facts(endReason, tailConfirmed, checkpoint.seq);
    const { coverage, limitations } = manifestCoverage(facts);
    return this.#host.recordManifest(this.spec, this.#manifestResult(facts, checkpoint), {
      coverage,
      limitations,
      lifecycle,
    });
  }

  async checkpoint(signal?: AbortSignal): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    if (this.#final !== undefined) return this.#final;
    let confirmed = true;
    if (this.spec.flush !== undefined) {
      try {
        await this.spec.flush(signal ?? new AbortController().signal);
      } catch {
        confirmed = false;
      }
    }
    if (signal?.aborted === true) return err(cancelled(OPERATION, "signal"));
    await this.#enqueue(() => this.#sealNow());
    return this.#record(null, confirmed || this.#finalSeen, false);
  }

  end(reason: StreamEndReason, deadlineMs?: number): Promise<Result<RecordedEvidence<JsonObject>, BeaError>> {
    this.#final ??= (async () => {
      this.#state = "ended";
      await this.#enqueue(() => this.#sealNow());
      const sync = Promise.allSettled(this.#unsynced.splice(0).map((path) => fsyncPath(path)));
      await (deadlineMs === undefined
        ? sync
        : Promise.race([sync, new Promise((r) => setTimeout(r, Math.max(0, deadlineMs)))]));
      const result = await this.#record(reason, this.#finalSeen, true);
      await this.#host.syncLedger().catch(() => undefined);
      return result;
    })();
    return this.#final;
  }
}

/** Reader over a stream directory: live (through its writer) or persisted/imported (files only). */
export class DirStreamReader implements StreamReader {
  #gaps: { from_seq: number; to_seq: number; kind: "dropped" | "redacted" }[] | undefined;

  constructor(
    readonly spec: StreamSpec,
    private readonly dir: string,
    private readonly descriptorSha: string,
    private readonly writer: FileStreamWriter | undefined,
  ) {}

  async #chunks(): Promise<{ readonly file: string; readonly limit: number | null }[]> {
    if (this.writer !== undefined) {
      await this.writer.drained();
      const current = this.writer.currentChunk;
      return [
        ...this.writer.sealed.map((c) => ({ file: c.file, limit: c.bytes })),
        ...(current === null ? [] : [{ file: current.file, limit: current.bytes }]),
      ];
    }
    const names = (await readdir(this.dir)).filter((n) => /^chunk-\d{6}\.bin$/u.test(n)).sort();
    return names.map((file) => ({ file, limit: null }));
  }

  async verify(
    signal?: AbortSignal,
  ): Promise<
    Result<
      { readonly head_chain: string; readonly chunks: number; readonly included?: "all" | "manifests-only" },
      BeaError
    >
  > {
    try {
      const descriptor = await readFile(join(this.dir, "descriptor.json"));
      if (sha256Hex(descriptor) !== this.descriptorSha)
        return err({
          _tag: "EvidenceIntegrity",
          operation: OPERATION,
          reason: "id-mismatch",
          diagnostics: { what: "descriptor" },
        });
      if (this.writer !== undefined) await this.writer.drained();
      const lines = await readChainLines(this.dir);
      // DATA-4: an imported manifests-only stream has no chunk files: its hash chain alone is verified
      const absent = this.writer === undefined && existsSync(join(this.dir, CHUNKS_ABSENT_MARKER));
      let head = this.descriptorSha;
      for (const line of lines) {
        if (signal?.aborted === true) return err(cancelled(OPERATION, "signal"));
        if (absent) {
          head = nextChain(head, line.sha256);
          if (head !== line.chain)
            return err({
              _tag: "EvidenceIntegrity",
              operation: OPERATION,
              reason: "id-mismatch",
              diagnostics: { what: "chain", index: line.index },
            });
          continue;
        }
        const bytes = await readFile(join(this.dir, line.file));
        if (sha256Hex(bytes) !== line.sha256 || bytes.length !== line.bytes)
          return err({
            _tag: "EvidenceIntegrity",
            operation: OPERATION,
            reason: "id-mismatch",
            diagnostics: { what: "chunk", index: line.index },
          });
        head = nextChain(head, line.sha256);
        if (head !== line.chain)
          return err({
            _tag: "EvidenceIntegrity",
            operation: OPERATION,
            reason: "id-mismatch",
            diagnostics: { what: "chain", index: line.index },
          });
      }
      return ok({ head_chain: head, chunks: lines.length, included: absent ? "manifests-only" : "all" });
    } catch (cause) {
      return err(fileError(OPERATION, "read", this.dir, cause));
    }
  }

  async *records(
    range: { readonly from_seq?: number; readonly to_seq?: number },
    signal?: AbortSignal,
  ): AsyncIterable<StreamRecord> {
    const from = range.from_seq ?? 1;
    const to = range.to_seq ?? Number.MAX_SAFE_INTEGER;
    for (const chunk of await this.#chunks()) {
      if (signal?.aborted === true) return;
      let bytes: Uint8Array = await readFile(join(this.dir, chunk.file));
      if (chunk.limit !== null) bytes = bytes.subarray(0, chunk.limit);
      for (const frame of decodeFrames(bytes).frames) {
        const h = frame.header;
        if (h.k !== "batch" || h.first_seq + h.count - 1 < from || h.first_seq > to) continue;
        for (const row of decodePayload(this.spec.encoding, frame)) {
          const seq = h.first_seq + row.index;
          if (seq >= from && seq <= to) yield { seq, module_map_epoch: h.module_map_epoch, fields: row.fields };
        }
      }
    }
  }

  gaps(range?: { readonly from_seq?: number; readonly to_seq?: number }): readonly {
    readonly from_seq: number;
    readonly to_seq: number;
    readonly kind: "dropped" | "redacted";
  }[] {
    const all = this.writer?.gapList ?? (this.#gaps ??= scanGaps(this.dir));
    const from = range?.from_seq ?? 1;
    const to = range?.to_seq ?? Number.MAX_SAFE_INTEGER;
    return all
      .filter((g) => g.to_seq >= from && g.from_seq <= to)
      .map((g) => ({ from_seq: Math.max(g.from_seq, from), to_seq: Math.min(g.to_seq, to), kind: g.kind }));
  }
}

export const readChainLines = async (dir: string): Promise<ChainLine[]> => {
  let text: string;
  try {
    text = await readFile(join(dir, "chain.jsonl"), "utf8");
  } catch {
    return [];
  }
  return text
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as ChainLine);
};

/** Sync gap scan of a persisted stream (gaps() is synchronous in the port). */
const scanGaps = (dir: string): { from_seq: number; to_seq: number; kind: "dropped" | "redacted" }[] => {
  const gaps: { from_seq: number; to_seq: number; kind: "dropped" | "redacted" }[] = [];
  let lastEnd = 0;
  let names: string[] = [];
  try {
    names = readdirNames(dir);
  } catch {
    return gaps;
  }
  for (const name of names) {
    const { frames } = decodeFrames(readFileSync(join(dir, name)));
    for (const frame of frames as Frame[]) {
      const h = frame.header;
      if (h.first_seq > lastEnd + 1) gaps.push({ from_seq: lastEnd + 1, to_seq: h.first_seq - 1, kind: "dropped" });
      if (h.k === "redacted" && h.count > 0)
        gaps.push({ from_seq: h.first_seq, to_seq: h.first_seq + h.count - 1, kind: "redacted" });
      lastEnd = Math.max(lastEnd, h.first_seq + h.count - 1);
    }
  }
  return gaps;
};

const readdirNames = (dir: string): string[] =>
  readdirSync(dir)
    .filter((n) => /^chunk-\d{6}\.bin$/u.test(n))
    .sort();

export class FileStreamStore implements StreamStore {
  readonly #writers = new Map<StId, FileStreamWriter>();

  constructor(private readonly host: StreamHost) {}

  /** Writers that have not ended (finalize ends them with server-shutdown; export checkpoints them). */
  live(): readonly FileStreamWriter[] {
    return [...this.#writers.values()].filter((w) => w.counters.state === "live");
  }

  all(): readonly FileStreamWriter[] {
    return [...this.#writers.values()];
  }

  dirOf(id: StId): string {
    return join(this.host.streamsDir, id);
  }

  async open(spec: StreamSpec): Promise<Result<StreamWriter, BeaError>> {
    const started = await this.host.ensureStarted();
    if (!started.ok) return started;
    const seq = this.host.seq.next();
    const stream_id = idOf("st", {
      t: "bea.st/1",
      run_id: this.host.runId,
      seq,
      source: spec.source as unknown as JsonValue,
    });
    const descriptor: StreamDescriptor = {
      schema: "bea.stream.descriptor/1",
      stream_id,
      source: spec.source,
      encoding: spec.encoding,
      decoders: spec.decoders,
      seq: "implicit",
      opened: { run_id: this.host.runId, seq },
    };
    const dir = this.dirOf(stream_id);
    let text: string;
    try {
      text = descriptorText(descriptor);
    } catch (cause) {
      return err(internalError(OPERATION, "stream descriptor is not canonical JSON", cause));
    }
    try {
      await mkdir(dir, { recursive: true });
      await writeFileAtomic(join(dir, "descriptor.json"), text);
    } catch (cause) {
      return err(ioError(OPERATION, "write", dir, cause));
    }
    const sha = sha256Hex(text);
    const writer = new FileStreamWriter(this.host, descriptor, sha, dir, spec, {
      seq,
      ...this.host.epochs(spec.source.instance_id),
    });
    this.#writers.set(stream_id, writer);
    this.host.index.addStream({
      stream_id,
      source_kind: spec.source.kind,
      instance_id: spec.source.instance_id,
      effect_id: spec.source.effect_id,
      descriptor_sha256: sha,
      origin: { kind: "local" },
      manifests: [],
    });
    return ok(writer);
  }

  writer(id: StId): FileStreamWriter | undefined {
    return this.#writers.get(id);
  }

  reader(id: StId): Result<StreamReader, BeaError> {
    const writer = this.#writers.get(id);
    if (writer !== undefined) return ok(new DirStreamReader(writer.spec, writer.dir, writer.descriptor_sha256, writer));
    const entry = this.host.index.streams.get(id);
    if (entry === undefined)
      return err({ _tag: "ReferenceNotFound", operation: OPERATION, reference: { kind: "stream", id } });
    const dir = this.dirOf(id);
    try {
      const descriptor = JSON.parse(readFileSync(join(dir, "descriptor.json"), "utf8")) as StreamDescriptor;
      const spec: StreamSpec = {
        source: descriptor.source,
        encoding: descriptor.encoding,
        decoders: descriptor.decoders,
        literals: NO_LITERALS,
      };
      return ok(new DirStreamReader(spec, dir, entry.descriptor_sha256, undefined));
    } catch (cause) {
      return err(fileError(OPERATION, "read", dir, cause));
    }
  }

  /** Register a stream directory that arrived with an import or a reopened run. */
  adopt(id: StId, descriptorSha: string, descriptor: StreamDescriptor, origin: Origin): void {
    this.host.index.addStream({
      stream_id: id,
      source_kind: descriptor.source.kind,
      instance_id: descriptor.source.instance_id,
      effect_id: descriptor.source.effect_id,
      descriptor_sha256: descriptorSha,
      origin,
      manifests: [],
    });
  }
}
