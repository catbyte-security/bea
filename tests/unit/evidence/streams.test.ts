import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { LIMITATIONS } from "../../../src/domain/evidence/limitations.js";
import type { PiId, StId } from "../../../src/domain/ids.js";
import type { JsonObject } from "../../../src/domain/json.js";
import { literalsOf, NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import type { StreamSpec, StreamWriter } from "../../../src/ports/evidence.js";
import { manifestCoverage, normalizeDropReason } from "../../../src/providers/evidence/streamManifest.js";
import { decodeFrames, encodeFrame, nextChain } from "../../../src/providers/evidence/streamFrames.js";
import { makeRuntime, observation, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
afterEach(async () => {
  await fx?.cleanup();
  fx = undefined;
});

const ndjson = (rows: readonly unknown[]): Uint8Array =>
  new TextEncoder().encode(rows.map((r) => `${JSON.stringify(r)}\n`).join(""));

const setup = async (
  overrides: Partial<StreamSpec> = {},
  env: Readonly<Record<string, string>> = {},
): Promise<{ fixture: RuntimeFixture; instance: PiId; writer: StreamWriter }> => {
  fx = await makeRuntime({ env });
  const r = await fx.runtime.instances.register(await observation(fx.home));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const instance = r.value.instance.instance_id;
  const opened = await fx.runtime.streams.open({
    source: { kind: "hook", instance_id: instance, effect_id: null, channel: "s1" },
    encoding: { kind: "json-rows", row_kind: "hook/1" },
    decoders: { capture: [] },
    literals: NO_LITERALS,
    ...overrides,
  });
  if (!opened.ok) throw new Error(JSON.stringify(opened.error));
  return { fixture: fx, instance, writer: opened.value };
};

describe("stream frames and chain (S2 §10.3)", () => {
  it("round-trips frames and stops at a torn tail", () => {
    const header = {
      k: "batch",
      first_seq: 1,
      count: 2,
      dropped_before: 0,
      recv_mono_ns: "1",
      module_map_epoch: 1,
      layout_rev: 1,
    } as const;
    const a = encodeFrame(header, new Uint8Array([1, 2, 3]));
    const b = encodeFrame({ ...header, first_seq: 3, count: 1 }, new Uint8Array([4]));
    const both = Buffer.concat([a, b]);
    const decoded = decodeFrames(both);
    expect(decoded.frames.map((f) => [f.header.first_seq, [...f.payload]])).toEqual([
      [1, [1, 2, 3]],
      [3, [4]],
    ]);
    const torn = decodeFrames(both.subarray(0, both.length - 1));
    expect(torn.torn).toBe(true);
    expect(torn.consumed).toBe(a.length);
  });

  it("chains chunk digests from the descriptor digest", () => {
    expect(nextChain("a".repeat(64), "b".repeat(64))).toMatch(/^[0-9a-f]{64}$/u);
    expect(nextChain("a".repeat(64), "b".repeat(64))).not.toBe(nextChain("a".repeat(64), "c".repeat(64)));
  });
});

describe("stream writer, reader and manifests (S2 §10)", () => {
  it("stores batches, decodes rows per seq, seals at checkpoint and verifies the chain", async () => {
    const { fixture, writer } = await setup();
    expect(
      writer.append(
        { first_seq: 1, count: 2, dropped_before: 0, module_map_epoch: 1 },
        ndjson([
          [1, 10],
          [2, 20],
        ]),
      ),
    ).toBe("accepted");
    expect(
      writer.append({ first_seq: 3, count: 1, dropped_before: 0, module_map_epoch: 1, final: true }, ndjson([[3, 30]])),
    ).toBe("accepted");
    const checkpoint = await writer.checkpoint();
    if (!checkpoint.ok) throw new Error(JSON.stringify(checkpoint.error));
    const manifest = checkpoint.value.record;
    expect(manifest.predicate_type).toBe("bea.stream.manifest");
    expect(manifest.coverage.status).toBe("complete");
    expect(manifest.limitations).toContain(LIMITATIONS.NOT_OBSERVED_WINDOW);
    expect(manifest.result).toMatchObject({
      records: 3,
      dropped: 0,
      state: "live",
      first_seq: 1,
      last_seq: 3,
      tail_confirmed: true,
    });
    const reader = fixture.runtime.streams.reader(writer.stream_id);
    if (!reader.ok) throw new Error("reader");
    const records = [];
    for await (const r of reader.value.records({ from_seq: 2 })) records.push([r.seq, r.fields]);
    expect(records).toEqual([
      [2, [2, 20]],
      [3, [3, 30]],
    ]);
    const verified = await reader.value.verify();
    expect(verified.ok && verified.value.chunks).toBe(1);
    expect(verified.ok && verified.value.head_chain).toBe((manifest.result as JsonObject)["head_chain"]);
  });

  it("accounts seq gaps and agent drops, reports gaps and a partial manifest", async () => {
    const { fixture, writer } = await setup();
    writer.append({ first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: 1 }, ndjson([[1]]));
    writer.append({ first_seq: 5, count: 1, dropped_before: 3, module_map_epoch: 1 }, ndjson([[5]]));
    writer.noteDropped(2, "buffer_full");
    expect(writer.counters).toMatchObject({ records: 2, dropped: 3 });
    const reader = fixture.runtime.streams.reader(writer.stream_id);
    if (!reader.ok) throw new Error("reader");
    expect(reader.value.gaps()).toEqual([{ from_seq: 2, to_seq: 4, kind: "dropped" }]);
    const ended = await writer.end("stopped");
    if (!ended.ok) throw new Error(JSON.stringify(ended.error));
    expect(ended.value.record.coverage).toMatchObject({
      status: "partial",
      truncated: true,
      dropped: 3,
      reasons: ["agent_buffer_full"],
    });
    expect(ended.value.record.limitations).toContain(LIMITATIONS.STREAM_DROPPED(3));
    expect(ended.value.record.limitations).toContain(LIMITATIONS.STREAM_DROPS_UNATTRIBUTED(1));
    expect(writer.append({ first_seq: 6, count: 1, dropped_before: 0, module_map_epoch: 1 }, ndjson([[6]]))).toBe(
      "closed",
    );
    const again = await writer.end("stopped");
    expect(again.ok && again.value.record.evidence_id).toBe(ended.value.record.evidence_id);
  });

  it("replaces a batch holding a literal (UTF-16LE too) with a redacted frame", async () => {
    const { fixture, writer } = await setup({ literals: literalsOf(["s3cr3t"]) });
    const utf16 = Buffer.from(JSON.stringify(["s3cr3t"]), "utf16le");
    expect(writer.append({ first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: 1 }, utf16)).toBe("redacted");
    expect(writer.append({ first_seq: 2, count: 1, dropped_before: 0, module_map_epoch: 1 }, ndjson([["fine"]]))).toBe(
      "accepted",
    );
    const ended = await writer.end("stopped");
    if (!ended.ok) throw new Error("end");
    expect(ended.value.record.coverage).toMatchObject({ status: "partial", reasons: ["explicit_sensitive_value"] });
    const reader = fixture.runtime.streams.reader(writer.stream_id);
    if (!reader.ok) throw new Error("reader");
    expect(reader.value.gaps()).toEqual([{ from_seq: 1, to_seq: 1, kind: "redacted" }]);
    const chunk = await readFile(join(fixture.runtime.streams.dirOf(writer.stream_id), "chunk-000000.bin"));
    expect(chunk.includes(Buffer.from("s3cr3t", "utf16le"))).toBe(false);
  });

  it("stops at the per-stream quota, counts the drops and calls onQuota once", async () => {
    const { writer } = await setup({}, { BEA_STREAM_QUOTA_MB: "1" });
    let calls = 0;
    writer.onQuota(() => {
      calls += 1;
    });
    const big = new Uint8Array(600 * 1024).fill(0x41);
    expect(writer.append({ first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: 1 }, big)).toBe("accepted");
    expect(writer.append({ first_seq: 2, count: 5, dropped_before: 0, module_map_epoch: 1 }, big)).toBe(
      "quota-exceeded",
    );
    expect(writer.append({ first_seq: 7, count: 1, dropped_before: 0, module_map_epoch: 1 }, new Uint8Array(1))).toBe(
      "quota-exceeded",
    );
    await Promise.resolve();
    expect(calls).toBe(1);
    const ended = await writer.end("quota");
    if (!ended.ok) throw new Error("end");
    expect(ended.value.record.coverage).toMatchObject({ status: "partial", dropped: 6, reasons: ["stream_quota"] });
    expect(ended.value.record.limitations).toContain(LIMITATIONS.QUOTA("stream", 1));
  });
});

describe("stream integrity, encodings and host streams (S2 §10)", () => {
  it("detects a tampered chunk on verify", async () => {
    const { fixture, writer } = await setup();
    writer.append({ first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: 1 }, ndjson([[1]]));
    await writer.end("stopped");
    const path = join(fixture.runtime.streams.dirOf(writer.stream_id), "chunk-000000.bin");
    const bytes = await readFile(path);
    bytes[bytes.length - 2] = 0x39;
    await writeFile(path, bytes);
    const reader = fixture.runtime.streams.reader(writer.stream_id);
    const verified = reader.ok ? await reader.value.verify() : null;
    expect(verified?.ok === false && verified.error._tag).toBe("EvidenceIntegrity");
  });

  it("decodes fixed-record and bytes encodings", async () => {
    const { fixture, instance } = await setup();
    const fixed = await fixture.runtime.streams.open({
      source: { kind: "trace", instance_id: instance, effect_id: null, channel: "t1" },
      encoding: {
        kind: "fixed-records",
        row_kind: "block-count/1",
        record_bytes: 12,
        fields: [
          { name: "start", offset: 0, type: "u64" },
          { name: "count", offset: 8, type: "u32" },
        ],
      },
      decoders: null,
      literals: NO_LITERALS,
    });
    if (!fixed.ok) throw new Error("open");
    const payload = Buffer.alloc(24);
    payload.writeBigUInt64LE(0x140001000n, 0);
    payload.writeUInt32LE(7, 8);
    payload.writeBigUInt64LE(0x140001100n, 12);
    payload.writeUInt32LE(9, 20);
    fixed.value.append({ first_seq: 1, count: 2, dropped_before: 0, module_map_epoch: 1 }, payload);
    const bytes = await fixture.runtime.streams.open({
      source: { kind: "stdout", instance_id: instance, effect_id: null, channel: "out" },
      encoding: { kind: "bytes" },
      decoders: null,
      literals: NO_LITERALS,
    });
    if (!bytes.ok) throw new Error("open");
    bytes.value.append({ first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: null }, Buffer.from("READY\n"));
    const read = async (id: StId) => {
      const reader = fixture.runtime.streams.reader(id);
      if (!reader.ok) throw new Error("reader");
      const out = [];
      for await (const r of reader.value.records({})) out.push(r.fields);
      return out;
    };
    expect(await read(fixed.value.stream_id)).toEqual([
      { start: "0x140001000", count: 7 },
      { start: "0x140001100", count: 9 },
    ]);
    expect(await read(bytes.value.stream_id)).toEqual([{ hex: Buffer.from("READY\n").toString("hex") }]);
  });

  it("host row streams (no instance) are sealed but have no manifest evidence", async () => {
    const { fixture } = await setup();
    const host = await fixture.runtime.streams.open({
      source: { kind: "emu-batch", instance_id: null, effect_id: null, channel: "emu" },
      encoding: { kind: "ndjson" },
      decoders: null,
      literals: NO_LITERALS,
    });
    if (!host.ok) throw new Error("open");
    host.value.append(
      { first_seq: 1, count: 2, dropped_before: 0, module_map_epoch: null },
      ndjson([{ a: 1 }, { a: 2 }]),
    );
    const ended = await host.value.end("stopped");
    expect(ended.ok || ended.error._tag).toBe("InvalidState");
    const reader = fixture.runtime.streams.reader(host.value.stream_id);
    const verified = reader.ok ? await reader.value.verify() : null;
    expect(verified?.ok && verified.value.chunks).toBe(1);
  });
});

describe("manifest coverage rules (S2 §10.6)", () => {
  const base = {
    state: "ended",
    endReason: "stopped",
    tailConfirmed: false,
    dropped: 0,
    redacted: 0,
    dropReasons: {},
    unattributed: 0,
    quotaMib: null,
    checkpointSeq: 9,
  } as const;
  it("is complete for a clean stop, partial for an unconfirmed exit, unknown for a seq gap or a lost agent", () => {
    expect(manifestCoverage(base).coverage.status).toBe("complete");
    expect(manifestCoverage({ ...base, endReason: "process-exited" }).coverage).toMatchObject({
      status: "partial",
      reasons: ["tail_unconfirmed"],
    });
    expect(manifestCoverage({ ...base, endReason: "process-exited", tailConfirmed: true }).coverage.status).toBe(
      "complete",
    );
    expect(manifestCoverage({ ...base, dropped: 2, dropReasons: { seq_gap: 2 } }).coverage.status).toBe("unknown");
    expect(manifestCoverage({ ...base, endReason: "agent-error" }).coverage.status).toBe("unknown");
    expect(manifestCoverage({ ...base, state: "live", endReason: null, tailConfirmed: true }).limitations).toContain(
      LIMITATIONS.RECORDING_ACTIVE,
    );
  });
  it("maps drop reasons to registered codes and tells agent attribution from host drops", () => {
    expect(normalizeDropReason("buffer_full")).toEqual({ code: "agent_buffer_full", agent: true });
    expect(normalizeDropReason("seq-gap")).toEqual({ code: "seq_gap", agent: false });
    expect(normalizeDropReason("host-queue-full")).toEqual({ code: "host_queue_full", agent: false });
    expect(normalizeDropReason("weird")).toEqual({ code: "decode_error", agent: true });
  });
});
