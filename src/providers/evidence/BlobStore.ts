import { createHash } from "node:crypto";
import { open, rm, stat, type FileHandle } from "node:fs/promises";
import { join } from "node:path";

import { cancelled } from "../../domain/errors/constructors.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { BlobRef } from "../../domain/evidence/record.js";
import { SHA256_RE } from "../../domain/ids.js";
import { bytesContainLiteral, literalOverlap } from "../../domain/redaction/redact.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BlobStore, SensitiveLiterals } from "../../ports/evidence.js";
import { fileError, internalError, ioError, isErrno, quotaError } from "./errors.js";
import { fsyncPath, pathExists, randomHex, renameWithRetry } from "./fsio.js";
import type { LedgerIndex } from "./LedgerIndex.js";
import { mibOf, type QuotaGuard } from "./Quotas.js";

const ROLE_RE = /^[a-z][a-z0-9_.-]{0,63}$/u;
const OPERATION = "evidence.blobs";

/**
 * Content-addressed blobs (S2 §11): streamed through tmp/ while hashing, quota-checked incrementally and scanned for
 * literals (a hit withholds the blob whole: {redacted:true}), then renamed to blobs/<sha256> (dedup when present).
 * Blobs are never deleted during a run; fsync happens at finalize (S2 §9.6).
 */
export class FileBlobStore implements BlobStore {
  readonly #fresh = new Set<string>();

  constructor(
    private readonly dirs: { readonly blobs: string; readonly tmp: string },
    private readonly index: LedgerIndex,
    private readonly quotas: QuotaGuard,
    private readonly ensureStarted: () => Promise<Result<void, BeaError>>,
  ) {}

  /** Blobs written in this run (fsynced at finalize). */
  get fresh(): readonly string[] {
    return [...this.#fresh];
  }

  pathOf(sha256: string): string {
    return join(this.dirs.blobs, sha256);
  }

  async put(
    src: Uint8Array | AsyncIterable<Uint8Array>,
    meta: { readonly role: string; readonly media_type: string; readonly literals: SensitiveLiterals },
    signal?: AbortSignal,
  ): Promise<Result<BlobRef | { readonly redacted: true }, BeaError>> {
    if (!ROLE_RE.test(meta.role)) return err(internalError(OPERATION, `invalid blob role ${meta.role.slice(0, 64)}`));
    const started = await this.ensureStarted();
    if (!started.ok) return started;
    const tmp = join(this.dirs.tmp, `blob-${randomHex()}`);
    const hash = createHash("sha256");
    const overlap = literalOverlap(meta.literals);
    let tail: Uint8Array = new Uint8Array(0);
    let reserved = 0;
    let redacted = false;
    let handle: FileHandle | undefined;
    const release = async (): Promise<void> => {
      this.quotas.releaseBlob(reserved);
      reserved = 0;
      await handle?.close().catch(() => undefined);
      handle = undefined;
      await rm(tmp, { force: true }).catch(() => undefined);
    };
    try {
      handle = await open(tmp, "wx");
      const chunks: AsyncIterable<Uint8Array> | Iterable<Uint8Array> = src instanceof Uint8Array ? [src] : src;
      for await (const chunk of chunks) {
        if (signal?.aborted === true) {
          await release();
          return err(cancelled(OPERATION, "signal"));
        }
        if (!this.quotas.reserveBlob(chunk.length)) {
          await release();
          return err(quotaError(OPERATION, "blobs", mibOf(this.quotas.limits.blobBytes)));
        }
        reserved += chunk.length;
        if (meta.literals.count > 0) {
          const window = new Uint8Array(tail.length + chunk.length);
          window.set(tail, 0);
          window.set(chunk, tail.length);
          if (bytesContainLiteral(window, meta.literals)) redacted = true;
          tail = window.subarray(Math.max(0, window.length - overlap));
        }
        if (redacted) break;
        hash.update(chunk);
        let written = 0;
        while (written < chunk.length) {
          const { bytesWritten } = await handle.write(chunk, written, chunk.length - written);
          written += bytesWritten;
        }
      }
      if (redacted) {
        await release();
        return ok({ redacted: true });
      }
      await handle.close();
      handle = undefined;
      const sha256 = hash.digest("hex");
      const bytes = reserved;
      const target = this.pathOf(sha256);
      if (this.index.blobs.has(sha256) || (await pathExists(target))) {
        this.quotas.releaseBlob(reserved); // dedup: the bytes are already accounted
        reserved = 0;
        await rm(tmp, { force: true });
      } else {
        await renameWithRetry(tmp, target);
        this.#fresh.add(sha256);
      }
      this.index.blobs.set(sha256, bytes);
      return ok({ role: meta.role, sha256, bytes, media_type: meta.media_type });
    } catch (cause) {
      await release();
      return err(ioError(OPERATION, "write", tmp, cause));
    }
  }

  has(sha256: string): boolean {
    return this.index.blobs.has(sha256);
  }

  size(sha256: string): number | undefined {
    return this.index.blobs.get(sha256);
  }

  async open(sha256: string): Promise<Result<FileHandle, BeaError>> {
    if (!SHA256_RE.test(sha256) || !this.index.blobs.has(sha256))
      return err({ _tag: "ReferenceNotFound", operation: OPERATION, reference: { kind: "blob", id: sha256 } });
    try {
      return ok(await open(this.pathOf(sha256), "r"));
    } catch (cause) {
      return err(fileError(OPERATION, "read", this.pathOf(sha256), cause));
    }
  }

  async read(sha256: string, offset: number, length: number): Promise<Result<Uint8Array, BeaError>> {
    const opened = await this.open(sha256);
    if (!opened.ok) return opened;
    try {
      const total = this.index.blobs.get(sha256) ?? 0;
      const want = Math.max(0, Math.min(length, total - offset));
      const buffer = Buffer.alloc(want);
      let got = 0;
      while (got < want) {
        const { bytesRead } = await opened.value.read(buffer, got, want - got, offset + got);
        if (bytesRead === 0) break;
        got += bytesRead;
      }
      return ok(new Uint8Array(buffer.buffer, buffer.byteOffset, got));
    } catch (cause) {
      return err(fileError(OPERATION, "read", this.pathOf(sha256), cause));
    } finally {
      await opened.value.close().catch(() => undefined);
    }
  }

  /** Rehash (export/import): integrity failure when the file no longer matches its name. */
  async verify(sha256: string, signal?: AbortSignal): Promise<Result<true, BeaError>> {
    const opened = await this.open(sha256);
    if (!opened.ok) return opened;
    try {
      const hash = createHash("sha256");
      for await (const chunk of opened.value.createReadStream({ autoClose: false })) {
        if (signal?.aborted === true) return err(cancelled(OPERATION, "signal"));
        hash.update(chunk as Buffer);
      }
      return hash.digest("hex") === sha256
        ? ok(true)
        : err({
            _tag: "EvidenceIntegrity",
            operation: OPERATION,
            reason: "id-mismatch",
            diagnostics: { blob: sha256 },
          });
    } catch (cause) {
      return err(fileError(OPERATION, "read", this.pathOf(sha256), cause));
    } finally {
      await opened.value.close().catch(() => undefined);
    }
  }

  /** Adopt a blob file that already sits in blobs/ (import merge). */
  async adopt(sha256: string): Promise<boolean> {
    try {
      const info = await stat(this.pathOf(sha256));
      this.index.blobs.set(sha256, info.size);
      return true;
    } catch (cause) {
      if (isErrno(cause, "ENOENT")) return false;
      throw cause;
    }
  }

  async syncFresh(): Promise<void> {
    await Promise.allSettled([...this.#fresh].map((sha) => fsyncPath(this.pathOf(sha))));
  }
}
