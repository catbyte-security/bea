import { readFile } from "node:fs/promises";
import { join } from "node:path";

import type { z } from "zod";

import type { DUMP_TOOLS, dumpInputSchema } from "../../contracts/areas/dump.js";
import { sha256Hex } from "../../domain/canonical.js";
import { DUMP_MANIFEST_FILE } from "../../domain/dumpBundle.js";
import { formatHex } from "../../domain/hex.js";
import type { JsonObject } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { BundleCaptureRequest, BundleCaptureResult } from "../../ports/dumps.js";
import type { LiveSession, OperationContext } from "../../ports/sessions.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { DetailedBundleCapture, DumpBundleRequest } from "../dump/captureBundle.js";
import { dumpModuleImage, dumpRawRange, MAX_GAPS, type DumpDeps, type DumpOutput } from "../dump/dumpMemory.js";
import { checkOutPath, outputPolicy } from "../dump/outputFiles.js";
import { verifyDumpBundle } from "../dump/verifyDumpBundle.js";
import type { HandlersFor } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";

/**
 * Handlers for area dump (WP13-DUMP): dump_memory. The out_path policy is checked before the target is touched;
 * pe/raw run application/dump/dumpMemory over app.services.{evidence,address,pe}; bundles go through
 * app.services.dumps (DumpCapturePort, shared with emu_open) inside one exclusive live operation.
 */
type DumpInput = z.output<typeof dumpInputSchema>;

const MiB = 1024 * 1024;

/** dump_memory's output from a bundle capture: the detailed result of WP-DUMP's service, or (any other port) the
 *  verified manifest plus a minimal envelope. */
const bundleOutput = async (
  app: BeaApplication,
  session: LiveSession,
  captured: BundleCaptureResult,
  operation: string,
): Promise<Result<DumpOutput, BeaError>> => {
  const detail = (captured as Partial<DetailedBundleCapture>).detail;
  const bundle = {
    bundle_id: captured.bundleId,
    regions: captured.regions,
    modules: captured.modules,
    threads: captured.threads,
  };
  if (detail !== undefined)
    return ok({
      path: captured.bundlePath,
      bytes: detail.bytes,
      sha256: detail.manifestSha256,
      format: "bundle",
      base: null,
      layout: null,
      image_base_in_file: null,
      module: null,
      gaps: detail.gaps,
      restored_patches: detail.restoredPatches,
      bundle,
      ...detail.envelope,
    });
  const verified = await verifyDumpBundle(captured.bundlePath, {
    maxTotalBytes: app.config.emu.dumpMaxMb.value * MiB,
    operation,
  });
  if (!verified.ok) return verified;
  const manifestBytes = await readFile(join(captured.bundlePath, DUMP_MANIFEST_FILE));
  const gaps = verified.value.manifest.regions.flatMap((r) =>
    r.unreadable_pages.map((page) => ({ va: formatHex(BigInt(page)), size: 4096 })),
  );
  return ok({
    path: captured.bundlePath,
    bytes: verified.value.totalBytes + manifestBytes.length,
    sha256: sha256Hex(manifestBytes),
    format: "bundle",
    base: null,
    layout: null,
    image_base_in_file: null,
    module: null,
    gaps: gaps.slice(0, MAX_GAPS),
    restored_patches: [],
    bundle,
    evidence_id: captured.evidenceId,
    predicate_type: "bea.dump.capture",
    confidence: "observed",
    authority: "live-process",
    coverage:
      gaps.length > 0
        ? { status: "partial", truncated: gaps.length > MAX_GAPS, reasons: ["unreadable_ranges"] }
        : { status: "complete", truncated: false, reasons: [] },
    limitations: captured.limitations.slice(0, 64),
    instance_id: session.instanceId,
  });
};

const runDump = (
  app: BeaApplication,
  deps: DumpDeps,
  session: LiveSession,
  input: DumpInput,
  op: OperationContext,
): Promise<Result<DumpOutput, BeaError>> => {
  const evidenceInput = JSON.parse(JSON.stringify(input)) as JsonObject;
  if (input.format === "pe")
    return dumpModuleImage(
      deps,
      session,
      {
        module: input.module ?? "$main",
        layout: input.layout,
        rebaseTo: input.rebase_to,
        liveBytes: input.live_bytes,
        ...(input.out_path !== undefined ? { outPath: input.out_path } : {}),
        input: evidenceInput,
      },
      op,
    );
  if (input.format === "raw")
    return dumpRawRange(
      deps,
      session,
      {
        address: input.address ?? "",
        size: input.size ?? 0,
        ...(input.out_path !== undefined ? { outPath: input.out_path } : {}),
        input: evidenceInput,
      },
      op,
    );
  const bundle = input.bundle ?? { modules: ["$main"], regions: [], mode: "running" as const };
  const req: DumpBundleRequest = {
    modules: bundle.modules,
    regions: bundle.regions,
    mode: bundle.mode,
    ...(bundle.thread_id !== undefined ? { threadId: bundle.thread_id } : {}),
    ...(input.out_path !== undefined ? { outDir: input.out_path } : {}),
    liveBytes: input.live_bytes,
  };
  const portRequest: BundleCaptureRequest = req;
  return app.services.dumps
    .captureBundle(session, portRequest, op)
    .then((captured) => (captured.ok ? bundleOutput(app, session, captured.value, op.name) : captured));
};

export const createDumpHandlers = (app: BeaApplication): HandlersFor<typeof DUMP_TOOLS> => ({
  dump_memory: async (input, ctx) => {
    const policy = outputPolicy(app.config, app.run.runId, process.env);
    if (input.out_path !== undefined) {
      const checked = checkOutPath(ctx.operation, input.out_path, policy);
      if (!checked.ok) return err(checked.error);
    }
    const deps: DumpDeps = {
      evidence: app.services.evidence,
      address: app.services.address,
      pe: app.services.pe,
      policy,
    };
    return liveOp(app, ctx, input.session_id, { mode: "exclusive", need: "agent" }, (session, op) =>
      runDump(app, deps, session, input, op),
    );
  },
});
