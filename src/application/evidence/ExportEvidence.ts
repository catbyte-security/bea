import { posix, win32 } from "node:path";

import type { z } from "zod";

import type { EVIDENCE_TOOLS, exportEvidenceInputSchema } from "../../contracts/areas/evidence.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { PiId } from "../../domain/ids.js";
import { checkOutputPath, type OutputPathPolicy } from "../../domain/outputPaths.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { BeaApplication } from "../BeaApplication.js";
import type { HandlerContext } from "../handlerContext.js";
import { liveOp } from "../sessionAccess.js";
import { pollEnvelope } from "./envelope.js";

type Output = z.output<(typeof EVIDENCE_TOOLS)[1]["outputSchema"]>;
type Input = z.output<typeof exportEvidenceInputSchema>;

/** CT-I8 / D-INT-42 output policy of this run (the same rules every file-writing tool applies). */
export const evidenceOutputPolicy = (app: BeaApplication): OutputPathPolicy => ({
  platform: app.config.platform,
  exportsDir: app.config.layout.exportsDir(app.run.runId),
  allowedRoots: app.config.exports.allowedRoots.value,
  systemRoots:
    app.config.platform === "win32"
      ? [process.env["SystemRoot"], process.env["windir"], "C:\\Windows"].filter(
          (root): root is string => root !== undefined && /^[A-Za-z]:[\\/]/u.test(root),
        )
      : ["/etc", "/usr", "/bin", "/sbin", "/lib"],
});

const resolveInstance = async (
  app: BeaApplication,
  ctx: HandlerContext,
  sessionId: string | undefined,
): Promise<Result<PiId | null, BeaError>> =>
  sessionId === undefined
    ? ok(null)
    : liveOp(app, ctx, sessionId, { mode: "concurrent", need: "host" }, async (session) => ok(session.instanceId));

/**
 * export_evidence (DESIGN §6.2 #35, S2 §13.3): resolve the selection (whole run or one session's closure), the
 * output path (default `<run>/exports/bundle-<seq>[.zip]`; any other path passes checkOutputPath, else
 * access_denied{policy}), then stage + publish through the evidence runtime. Never overwrites.
 */
export const exportEvidence = async (
  app: BeaApplication,
  ctx: HandlerContext,
  input: Input,
): Promise<Result<Output, BeaError>> => {
  const instance = await resolveInstance(app, ctx, input.session_id);
  if (!instance.ok) return instance;
  const policy = evidenceOutputPolicy(app);
  const api = policy.platform === "win32" ? win32 : posix;
  let outPath: string;
  if (input.out_path === undefined)
    outPath = api.join(policy.exportsDir, `bundle-${String(app.seq.next())}${input.format === "zip" ? ".zip" : ""}`);
  else {
    const checked = checkOutputPath(input.out_path, policy);
    if (!checked.ok)
      return err({
        _tag: "AccessDenied",
        operation: ctx.operation,
        reason: "policy",
        message: checked.message,
        diagnostics: { policy: checked.reason },
      });
    outPath = checked.path;
  }
  // parents are created only under this run's exports directory
  const parent = api.dirname(outPath);
  const under = (root: string): boolean => {
    const fold = (p: string): string =>
      policy.platform === "win32" ? api.normalize(p).toLowerCase() : api.normalize(p);
    const base = fold(root).replace(/[\\/]+$/u, "");
    return fold(parent) === base || fold(parent).startsWith(`${base}${api.sep}`);
  };
  const exported = await app.services.evidence.bundles.export(
    {
      out_path: outPath,
      // the run directory is created by the exporter's own start; parents only ever under <run>/exports
      create_parent: under(policy.exportsDir),
      format: input.format,
      streams: input.streams,
      blobs: input.blobs,
      ...(instance.value === null ? {} : { instance_id: instance.value }),
    },
    ctx.signal,
  );
  if (!exported.ok) return exported;
  return ok({ ...exported.value, ...pollEnvelope() } as unknown as Output);
};
