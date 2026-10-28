import { cp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { BeaCore } from "../../../src/application/BeaApplication.js";
import type { BeaServices } from "../../../src/application/services/index.js";
import { sha256Hex } from "../../../src/domain/canonical.js";
import { COMPLETE } from "../../../src/domain/evidence/coverage.js";
import type { PiId } from "../../../src/domain/ids.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import type { EvidenceRuntime } from "../../../src/ports/evidence.js";
import { createEvidenceRuntime } from "../../../src/providers/evidence/createEvidenceRuntime.js";
import { runHeaderSchema } from "../../../src/providers/evidence/RunStore.js";
import { fakeServices } from "../../support/fakes/fakeServices.js";
import { connectInMemoryBea, type InMemoryBea } from "../../support/mcp/inMemory.js";
import { expectToolSuccess, parseToolError } from "../../support/mcp/parseToolError.js";
import { observation, readDraft } from "../../unit/evidence/support.js";

/**
 * WP1 acceptance (DESIGN §9.3 WP1-EVID; wave rule CI-I1: records are written through the Recorder directly, the
 * tool-chained "after read and diff" versions belong to WP18). Real evidence runtime on a temp BEA_HOME behind the
 * production MCP server (in-process); no target process is involved.
 */
let bea: InMemoryBea | undefined;
afterEach(async () => {
  await bea?.close();
  bea = undefined;
});

const services = async (core: BeaCore): Promise<BeaServices> => {
  const evidence = createEvidenceRuntime(core, {});
  return fakeServices({ evidence })(core);
};

const start = async (
  env: Readonly<Record<string, string>> = {},
): Promise<{ evidence: EvidenceRuntime; instance: PiId }> => {
  bea = await connectInMemoryBea({ services, env });
  const evidence = bea.app.services.evidence;
  const registered = await evidence.instances.register(await observation(bea.home));
  if (!registered.ok) throw new Error(JSON.stringify(registered.error));
  return { evidence, instance: registered.value.instance.instance_id };
};

const call = async (name: string, args: Record<string, unknown>) => {
  if (bea === undefined) throw new Error("no server");
  return bea.client.callTool({ name, arguments: args });
};

describe("WP1 acceptance: evidence store", () => {
  it("export → import_evidence validate_only round trip with a stream; a tampered copy fails and the ledger is unchanged", async () => {
    const { evidence, instance } = await start();
    for (let i = 0; i < 10; i++)
      await evidence.recorder.record(readDraft(evidence as never, instance, `0${String(i)}`));
    const writer = await evidence.streams.open({
      source: { kind: "hook", instance_id: instance, effect_id: null, channel: "s1" },
      encoding: { kind: "json-rows", row_kind: "hook/1" },
      decoders: null,
      literals: NO_LITERALS,
    });
    if (!writer.ok) throw new Error("stream");
    for (let seq = 1; seq <= 100; seq += 10)
      writer.value.append(
        { first_seq: seq, count: 10, dropped_before: 0, module_map_epoch: 1 },
        new TextEncoder().encode(Array.from({ length: 10 }, (_, i) => `[${String(seq + i)}]\n`).join("")),
      );
    const manifest = await writer.value.checkpoint();
    expect(manifest.ok && manifest.value.record.coverage.status).toBe("complete");
    const exported = expectToolSuccess(await call("export_evidence", { format: "zip", streams: "all" }));
    expect(exported).toMatchObject({ streams: 1 });
    const verdict = expectToolSuccess(
      await call("import_evidence", { path: String(exported["path"]), validate_only: true }),
    );
    expect(verdict).toMatchObject({ valid: true, records: exported["records"] });

    const dir = expectToolSuccess(await call("export_evidence", { streams: "all" }));
    const copy = join(bea?.app.config.layout.exportsDir(bea.app.run.runId) ?? "", "tampered");
    await cp(String(dir["path"]), copy, { recursive: true });
    const records = join(copy, "records.jsonl");
    await writeFile(
      records,
      (await readFile(records, "utf8")).replace("554889e5", "554889e6").replace('"data":"00"', '"data":"01"'),
    );
    const ledger = join(evidence.run.dir, "ledger.jsonl");
    const before = (await stat(ledger)).size;
    const tampered = parseToolError(await call("import_evidence", { path: copy }));
    expect(tampered.code).toBe("evidence_integrity_mismatch");
    expect((await stat(ledger)).size).toBe(before);
  });

  it("a quota hit is resource_constraint (ledger) and a partial manifest (stream), and lifecycle lines still fit", async () => {
    const { evidence, instance } = await start({
      BEA_LEDGER_QUOTA_MB: "16",
      BEA_LEDGER_RESERVE_MB: "8",
      BEA_STREAM_QUOTA_MB: "1",
    });
    const writer = await evidence.streams.open({
      source: { kind: "hook", instance_id: instance, effect_id: null, channel: "s1" },
      encoding: { kind: "json-rows", row_kind: "hook/1" },
      decoders: null,
      literals: NO_LITERALS,
    });
    if (!writer.ok) throw new Error("stream");
    let quotaCalls = 0;
    writer.value.onQuota(() => (quotaCalls += 1));
    const big = new Uint8Array(700 * 1024).fill(0x30);
    writer.value.append({ first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: 1 }, big);
    expect(writer.value.append({ first_seq: 2, count: 4, dropped_before: 0, module_map_epoch: 1 }, big)).toBe(
      "quota-exceeded",
    );
    const padding = "a".repeat(64 * 1024);
    let refused = null;
    for (let i = 0; i < 400 && refused === null; i++) {
      const r = await evidence.recorder.record(
        readDraft(evidence as never, instance, "00", { result: { data: "00", note: `${padding}${String(i)}` } }),
      );
      if (!r.ok) refused = r.error;
    }
    expect(refused).toMatchObject({
      _tag: "ResourceConstraint",
      resource: "disk",
      limits: { quota: "ledger", knob: "BEA_LEDGER_QUOTA_MB" },
    });
    const ended = await writer.value.end("quota");
    if (!ended.ok) throw new Error(JSON.stringify(ended.error));
    expect(ended.value.record.coverage).toMatchObject({ status: "partial", dropped: 4, reasons: ["stream_quota"] });
    expect(quotaCalls).toBe(1);
  });

  it("finalize (lifecycle closeAll) fsyncs, writes the end line, closes run.json with the ledger digest and removes the lock", async () => {
    const { evidence, instance } = await start();
    await evidence.recorder.record(readDraft(evidence as never, instance));
    const dir = evidence.run.dir;
    await bea?.app.lifecycle.closeAll("test");
    const header = runHeaderSchema.parse(JSON.parse(await readFile(join(dir, "run.json"), "utf8")));
    expect(header.status).toBe("closed");
    expect(header.final?.ledger_sha256).toBe(sha256Hex(await readFile(join(dir, "ledger.jsonl"))));
    expect(await readdir(dir)).not.toContain(".lock");
    const last = (await readFile(join(dir, "ledger.jsonl"), "utf8")).trimEnd().split("\n").at(-1) ?? "";
    expect(JSON.parse(last)).toMatchObject({ t: "end" });
  });

  it("records 20k observations in at most 2 s (S2 E5: ~48 µs/record)", async () => {
    const { evidence, instance } = await start();
    const capture = evidence.instances.capture(instance);
    const started = performance.now();
    for (let i = 0; i < 20_000; i++) {
      const r = await evidence.recorder.record({
        predicate_type: "bea.memory.read",
        operation: "read_memory",
        input: { address: "0x140001000", size: 64 },
        subject: { kind: "process-instance", instance_id: instance },
        capture: { ...capture, anchor: { ...capture.anchor, seq: capture.anchor.seq + i + 1 } },
        provider: { id: "frida", name: "frida", version: "17.23.2" },
        result: { data: "55".repeat(64), note: "x".repeat(1500) },
        coverage: COMPLETE,
        literals: NO_LITERALS,
      });
      if (!r.ok) throw new Error(JSON.stringify(r.error));
    }
    const elapsed = performance.now() - started;
    expect(elapsed).toBeLessThanOrEqual(2000);
  });
});
