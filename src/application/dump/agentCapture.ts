import type { FileHandle } from "node:fs/promises";

import { mapAgentError } from "../../domain/errors/agentErrorMap.js";
import { isBeaError, type BeaError } from "../../domain/errors/beaError.js";
import { internalError } from "../../domain/errors/constructors.js";
import type { BlobRef } from "../../domain/evidence/record.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { AnchorCapture, EvidenceRuntime } from "../../ports/evidence.js";
import type { AgentJobOutcome, LiveSession, OperationContext } from "../../ports/sessions.js";
import type { DumpManifest, DumpRegion, DumpStartParams } from "../../shared/agentProtocol.js";

/**
 * One agent dump job end to end (S4 §15.1 over CI-B3): `dumpStart` → anchor capture → `LiveSession.jobs.await`
 * (AgentChannel stores every blob in EvidenceRuntime.blobs, sha256 recomputed, before resolving) → the bea-dump/1
 * manifest plus a reader for each region's bytes. Shared by dump_memory (pe/raw) and the bundle capture.
 */
export interface AgentDump {
  readonly manifest: DumpManifest;
  /** null when InstanceRegistry.capture is unavailable (anchor-less evidence is refused by the Recorder) */
  readonly anchor: AnchorCapture | null;
  readonly blobs: AgentJobOutcome["blobs"];
  /** stored blobs of the job, in region order (evidence references them) */
  readonly blobRefs: readonly BlobRef[];
  readonly plannedBytes: number;
}

/** A region's bytes: the stored blob, or `redacted` when a caller-declared sensitive value matched it. */
export type RegionBytes = { readonly kind: "bytes"; readonly bytes: Uint8Array } | { readonly kind: "redacted" };

/**
 * A port call as a Result even when the port throws (day-0 stubs throw capability_unavailable synchronously): the
 * optional steps of a dump (file digest, patch restore) degrade with a limitation instead of failing the dump.
 */
export const settle = async <T>(
  operation: string,
  call: () => Promise<Result<T, BeaError>>,
): Promise<Result<T, BeaError>> => {
  try {
    return await call();
  } catch (cause) {
    return err(isBeaError(cause) ? cause : internalError(operation, cause));
  }
};

const JOB_MARGIN_MS = 1500;
const MIN_JOB_TIMEOUT_MS = 1000;

const lostBlob = (operation: string, region: DumpRegion): BeaError => ({
  _tag: "ProviderFailure",
  operation,
  provider: "agent",
  message: "Dump data for a captured region was lost between the agent and the evidence store.",
  diagnostics: { region_base: region.base, region_size: region.size },
});

const isDumpManifest = (value: unknown): value is DumpManifest =>
  typeof value === "object" && value !== null && Reflect.get(value, "format") === "bea-dump/1";

export const runAgentDump = async (
  evidence: EvidenceRuntime,
  session: LiveSession,
  params: DumpStartParams,
  op: OperationContext,
): Promise<Result<AgentDump, BeaError>> => {
  const started = await session.agent.call("dumpStart", params, { op });
  if (!started.ok) return started;
  let anchor: AnchorCapture | null;
  try {
    anchor = evidence.instances.capture(session.instanceId);
  } catch {
    anchor = null;
  }
  op.progress?.(
    "dump",
    `${String(started.value.planned_blobs)} region(s), ${String(started.value.planned_bytes)} bytes planned`,
  );
  const timeoutMs = Math.max(MIN_JOB_TIMEOUT_MS, op.deadline.remaining() - JOB_MARGIN_MS);
  const outcome = await session.jobs.await(started.value.job_id, op, timeoutMs);
  if (!outcome.ok) return outcome;
  const { error, result, blobs } = outcome.value;
  if (error !== null) return err(mapAgentError(error, { operation: op.name, instance_id: session.instanceId }));
  if (!isDumpManifest(result))
    return err(internalError(op.name, new Error("dump job finished without a bea-dump/1 manifest")));
  const blobRefs: BlobRef[] = [];
  for (const region of result.regions) {
    const entry = blobs.get(region.blob);
    if (entry !== undefined && "sha256" in entry) blobRefs.push(entry);
  }
  return ok({ manifest: result, anchor, blobs, blobRefs, plannedBytes: started.value.planned_bytes });
};

const blobOf = (
  dump: AgentDump,
  region: DumpRegion,
  operation: string,
): Result<BlobRef | { readonly redacted: true }, BeaError> => {
  const entry = dump.blobs.get(region.blob);
  if (entry === undefined || "failed" in entry) return err(lostBlob(operation, region));
  return ok(entry);
};

/** Reads a whole region (module images, bundle regions). */
export const readRegion = async (
  evidence: EvidenceRuntime,
  dump: AgentDump,
  region: DumpRegion,
  operation: string,
): Promise<Result<RegionBytes, BeaError>> => {
  const blob = blobOf(dump, region, operation);
  if (!blob.ok) return blob;
  if ("redacted" in blob.value) return ok({ kind: "redacted" });
  if (blob.value.bytes !== region.size) return err(lostBlob(operation, region));
  if (region.size === 0) return ok({ kind: "bytes", bytes: new Uint8Array(0) });
  const read = await evidence.blobs.read(blob.value.sha256, 0, region.size);
  return read.ok ? ok({ kind: "bytes", bytes: read.value }) : read;
};

const CHUNK = 4 * 1024 * 1024;

async function* chunksOf(handle: FileHandle, size: number): AsyncIterable<Uint8Array> {
  try {
    for (let at = 0; at < size;) {
      const buffer = new Uint8Array(Math.min(CHUNK, size - at));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, at);
      if (bytesRead === 0) throw new Error("blob shorter than recorded");
      at += bytesRead;
      yield bytesRead === buffer.length ? buffer : buffer.subarray(0, bytesRead);
    }
  } finally {
    await handle.close();
  }
}

/** Streams a region (raw dumps up to 2 GiB) without holding it in memory. */
export const streamRegion = async (
  evidence: EvidenceRuntime,
  dump: AgentDump,
  region: DumpRegion,
  operation: string,
): Promise<Result<{ readonly kind: "stream"; readonly chunks: AsyncIterable<Uint8Array> } | RegionBytes, BeaError>> => {
  const blob = blobOf(dump, region, operation);
  if (!blob.ok) return blob;
  if ("redacted" in blob.value) return ok({ kind: "redacted" });
  if (blob.value.bytes !== region.size) return err(lostBlob(operation, region));
  const handle = await evidence.blobs.open(blob.value.sha256);
  return handle.ok ? ok({ kind: "stream", chunks: chunksOf(handle.value, region.size) }) : handle;
};

/** Holes of a region as absolute {va, size} gaps. */
export const gapsOf = (region: DumpRegion): { readonly va: bigint; readonly size: number }[] =>
  region.holes.map((h) => ({ va: BigInt(region.base) + BigInt(h.offset), size: h.size }));
