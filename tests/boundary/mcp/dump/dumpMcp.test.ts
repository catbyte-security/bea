import { existsSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createDumpService } from "../../../../src/application/dump/createDumpService.js";
import { verifyDumpBundle } from "../../../../src/application/dump/verifyDumpBundle.js";
import type { BeaServices } from "../../../../src/application/services/index.js";
import type { DumpCapturePort } from "../../../../src/ports/dumps.js";
import { DUMP_LIMITATIONS } from "../../../../src/domain/evidence/limitations/dump.js";
import { fakeServices } from "../../../support/fakes/fakeServices.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import {
  createEvidenceLog,
  disposeEvidenceLog,
  FakeTarget,
  fakeAddress,
  fakeEvidence,
  fakeLiveSession,
  fakePe,
  fakeSessions,
  GAME_BASE,
  LIVE_ID,
  type EvidenceLog,
} from "../../../unit/dump/dumpFakes.js";

/**
 * dump_memory through the production MCP server (in-memory transport, WP13 fakes behind the frozen ports, the real
 * DumpService for bundles): the output self-check of invokeTool validates every success against the advertised schema.
 */
let bea: InMemoryBea | undefined;
let log: EvidenceLog;
beforeEach(async () => {
  log = await createEvidenceLog();
});
afterEach(async () => {
  await bea?.close();
  bea = undefined;
  await disposeEvidenceLog(log);
});

const connect = async (options: { readonly withPe?: boolean; readonly portShapeOnly?: boolean } = {}) => {
  const target = new FakeTarget();
  target.hook(GAME_BASE + 0x1760n);
  const live = fakeLiveSession(target, log);
  const evidence = fakeEvidence(log);
  const address = fakeAddress(target, { patches: [] });
  const pe = fakePe(target);
  const withPe = options.withPe ?? true;
  bea = await connectInMemoryBea({
    services: async (core) => {
      // without pe: the day-0 stub PE ports, which throw capability_unavailable(not-implemented)
      const base = await fakeServices({
        sessions: fakeSessions(live.session),
        evidence,
        address,
        ...(withPe ? { pe } : {}),
      })(core);
      const service = createDumpService(core, { evidence, address, ...(withPe ? { pe } : {}) });
      // another DumpCapturePort implementation: only the port's result shape (no WP-DUMP detail)
      const portOnly: DumpCapturePort = {
        captureBundle: async (session, req, op) => {
          const res = await service.captureBundle(session, req, op);
          if (!res.ok) return res;
          const { detail, ...shape } = res.value;
          void detail;
          return { ok: true, value: shape };
        },
      };
      return { ...base, dumps: options.portShapeOnly === true ? portOnly : service } satisfies BeaServices;
    },
  });
  return { bea, live, target };
};

describe("dump_memory over MCP (S6 §10.8 row, fakes)", () => {
  it("is advertised as a filesystem writer (not read-only, not destructive, not idempotent) with the CLI positional module", async () => {
    const { bea: b } = await connect();
    const tool = (await b.client.listTools()).tools.find((t) => t.name === "dump_memory");
    expect(tool?.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    });
    expect(tool?.inputSchema.required).toEqual(["session_id"]);
  });

  it("dumps a realigned image under the run's exports directory with a recorded envelope", async () => {
    const { bea: b } = await connect();
    const out = expectToolSuccess(
      await b.client.callTool({ name: "dump_memory", arguments: { session_id: LIVE_ID, module: "game_sim.exe" } }),
    );
    expect(out).toMatchObject({
      format: "pe",
      layout: "pe_realigned",
      module: { name: "game_sim.exe", rebased_to: "runtime" },
      restored_patches: [{ rva: "0x1760", size: 5, source: "bea-original" }],
      predicate_type: "bea.memory.dump",
      confidence: "observed",
      authority: "live-process",
    });
    const exportsDir = b.app.config.layout.exportsDir(b.app.run.runId);
    expect(String(out["path"]).startsWith(exportsDir)).toBe(true);
    expect(existsSync(String(out["path"]))).toBe(true);
  });

  it("degrades without a working PE reader: mapped/runtime succeeds with BEA originals only and a limitation", async () => {
    const { bea: b } = await connect({ withPe: false });
    const out = expectToolSuccess(
      await b.client.callTool({
        name: "dump_memory",
        arguments: { session_id: LIVE_ID, module: "game_sim.exe", layout: "mapped" },
      }),
    );
    expect(out).toMatchObject({ module: { file_sha256: null }, restored_patches: [{ source: "bea-original" }] });
    expect(out["limitations"]).toContain(DUMP_LIMITATIONS.DUMP_FILE_IMAGE_UNAVAILABLE);
    const refused = parseToolError(
      await b.client.callTool({
        name: "dump_memory",
        arguments: { session_id: LIVE_ID, module: "game_sim.exe", rebase_to: "preferred" },
      }),
    );
    expect(refused.code).toBe("capability_unavailable");
  });

  it("refuses a Startup-folder or .cmd out_path with access_denied{policy} before touching the target", async () => {
    const { bea: b, live } = await connect();
    for (const out_path of [
      join(b.home.home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "x.bin"),
      join(b.app.config.layout.exportsDir(b.app.run.runId), "dump.cmd"),
    ]) {
      const error = parseToolError(
        await b.client.callTool({
          name: "dump_memory",
          arguments: { session_id: LIVE_ID, module: "game_sim.exe", out_path },
        }),
      );
      expect(error.code).toBe("access_denied");
      expect(error.details).toMatchObject({ reason: "policy" });
    }
    expect(live.agent.calls).toEqual([]);
  });

  it("rejects contradictory inputs with invalid_request and corrective messages", async () => {
    const { bea: b } = await connect();
    const cases: Record<string, unknown>[] = [
      { session_id: LIVE_ID },
      { session_id: LIVE_ID, format: "raw", address: "0x1000" },
      { session_id: LIVE_ID, module: "a.dll", bundle: {} },
      { session_id: LIVE_ID, format: "bundle", module: "a.dll" },
      { session_id: LIVE_ID, format: "raw", address: "0x1000", size: 2 ** 31 },
    ];
    for (const args of cases) {
      const error = parseToolError(await b.client.callTool({ name: "dump_memory", arguments: args }));
      expect(error.code, JSON.stringify(args)).toBe("invalid_request");
    }
  });

  it("an unknown session is session_not_found", async () => {
    const { bea: b } = await connect();
    const error = parseToolError(
      await b.client.callTool({
        name: "dump_memory",
        arguments: { session_id: "99999999-9999-4999-8999-999999999999", module: "x.dll" },
      }),
    );
    expect(error.code).toBe("session_not_found");
  });

  it("format bundle goes through DumpCapturePort and returns a verifiable bea.dump/1 directory", async () => {
    const { bea: b } = await connect();
    const out = expectToolSuccess(
      await b.client.callTool({
        name: "dump_memory",
        arguments: { session_id: LIVE_ID, format: "bundle", bundle: { mode: "suspended" } },
      }),
    );
    expect(out).toMatchObject({
      format: "bundle",
      base: null,
      layout: null,
      module: null,
      predicate_type: "bea.dump.capture",
    });
    const bundle = out["bundle"] as { bundle_id: string; threads: number };
    expect(bundle.threads).toBe(2);
    expect(String(out["path"]).endsWith(bundle.bundle_id)).toBe(true);
    const verified = await verifyDumpBundle(String(out["path"]), { maxTotalBytes: 1 << 30 });
    expect(verified.ok ? verified.value.manifest.bundle_id : verified.error).toBe(bundle.bundle_id);
  });

  it("format bundle through another DumpCapturePort: the handler verifies the bundle and builds the envelope itself", async () => {
    const { bea: b } = await connect({ portShapeOnly: true });
    const out = expectToolSuccess(
      await b.client.callTool({ name: "dump_memory", arguments: { session_id: LIVE_ID, format: "bundle" } }),
    );
    expect(out).toMatchObject({
      format: "bundle",
      predicate_type: "bea.dump.capture",
      confidence: "observed",
      restored_patches: [],
    });
    expect(String(out["sha256"])).toMatch(/^[0-9a-f]{64}$/u);
    expect(out["limitations"]).toContain(DUMP_LIMITATIONS.DUMP_RUNNING_TORN);
  });
});
