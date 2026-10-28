import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import { ZipFile } from "yazl";
import { createWriteStream } from "node:fs";
import { pipeline } from "node:stream/promises";

import { canonicalJson, sha256Hex } from "../../../src/domain/canonical.js";
import type { PiId } from "../../../src/domain/ids.js";
import { NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import { isUnsafeName } from "../../../src/providers/evidence/BundleZip.js";
import { bundleDigestOf } from "../../../src/providers/evidence/bundleFormat.js";
import { createTempHome, type TempHome } from "../../support/workspace/tempHome.js";
import { makeRuntime, observation, readDraft, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
let home: TempHome | undefined;
afterEach(async () => {
  await fx?.cleanup();
  await home?.cleanup();
  fx = undefined;
  home = undefined;
});

/** A run with an instance, records, an effect with a blob, a stream with a manifest and an unknown. */
const populated = async (): Promise<{ fixture: RuntimeFixture; instance: PiId }> => {
  home = await createTempHome("bundle");
  fx = await makeRuntime({ home });
  const runtime = fx.runtime;
  const r = await runtime.instances.register(await observation(home));
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  const instance = r.value.instance.instance_id;
  const effect = await runtime.effects.apply({
    instance_id: instance,
    kind: "memory-written",
    target: {
      address: { va: "0x140001000", module_map_id: null, module_key: "game_sim.exe", rva: "0x1000" },
      size: 5000,
      threads: null,
    },
    parameters: {},
    before: new Uint8Array(5000).fill(3),
    applied_by: "write_memory",
    literals: NO_LITERALS,
  });
  if (!effect.ok) throw new Error("effect");
  const blob = await runtime.blobs.put(new Uint8Array(100).fill(9), {
    role: "data",
    media_type: "application/octet-stream",
    literals: NO_LITERALS,
  });
  if (!blob.ok || "redacted" in blob.value) throw new Error("blob");
  const read = await runtime.recorder.record(
    readDraft(runtime, instance, "00", { blobs: [blob.value], effects: [effect.value.effect_id] }),
  );
  if (!read.ok) throw new Error(JSON.stringify(read.error));
  const stream = await runtime.streams.open({
    source: { kind: "hook", instance_id: instance, effect_id: null, channel: "s1" },
    encoding: { kind: "json-rows", row_kind: "hook/1" },
    decoders: null,
    literals: NO_LITERALS,
  });
  if (!stream.ok) throw new Error("stream");
  stream.value.append(
    { first_seq: 1, count: 1, dropped_before: 0, module_map_epoch: 1 },
    new TextEncoder().encode("[1]\n"),
  );
  await stream.value.end("stopped");
  const unknown = await runtime.unknowns.upsert(
    {
      question: "Is the hook complete?",
      domain: "runtime",
      scope_image_sha256: null,
      status: "open",
      severity: "low",
      supporting: [read.value.record.evidence_id],
      contradicting: [],
      probes: [],
      resolution: null,
    },
    "record_unknown",
  );
  if (!unknown.ok) throw new Error("unknown");
  return { fixture: fx, instance };
};

const exportTo = async (fixture: RuntimeFixture, name: string, extra: Record<string, unknown> = {}) => {
  const out = join(fixture.home.work, name);
  const result = await fixture.runtime.bundles.export({ out_path: out, ...extra } as never);
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return { out, value: result.value };
};

describe("bundles (S2 §13, §22 bundles)", () => {
  it("exports a directory twice with byte-identical records.jsonl and digest, then validates", async () => {
    const { fixture } = await populated();
    const a = await exportTo(fixture, "a", { streams: "all" });
    const b = await exportTo(fixture, "b", { streams: "all" });
    expect(a.value["bundle_digest"]).toBe(b.value["bundle_digest"]);
    expect(await readFile(join(a.out, "records.jsonl"))).toEqual(await readFile(join(b.out, "records.jsonl")));
    expect(a.value).toMatchObject({ blobs: 2, streams: 1 });
    expect((await readdir(join(a.out, "streams"))).length).toBe(1);
    const verdict = await fixture.runtime.bundles.import({ path: a.out, validate_only: true });
    expect(verdict.ok && verdict.value).toMatchObject({ valid: true, added: 0, records: a.value["records"] });
    expect(await readdir(fixture.home.work)).toEqual(["a", "b", "game_sim.exe"]);
  });

  it("round-trips a zip into a new run: added = records, a re-import is all duplicates, origin imported", async () => {
    const { fixture } = await populated();
    const zip = await exportTo(fixture, "bundle.zip", { format: "zip", streams: "all" });
    const target = fixture.another();
    const first = await target.bundles.import({ path: zip.out });
    if (!first.ok) throw new Error(JSON.stringify(first.error));
    expect(first.value).toMatchObject({ valid: true, added: zip.value["records"], duplicates: 0 });
    const second = await target.bundles.import({ path: zip.out });
    expect(second.ok && second.value).toMatchObject({ added: 0, duplicates: zip.value["records"] });
    const imported = target.query.summary({ filters: { origin: "imported" } });
    expect(imported.ok && imported.value["matching"]).toBe(fixture.runtime.index.rows.length);
    const stream = [...target.index.streams.values()][0];
    expect(stream?.origin.kind).toBe("import");
    const reader = stream === undefined ? null : target.streams.reader(stream.stream_id);
    expect(reader?.ok === true && (await reader.value.verify()).ok).toBe(true);
    const blob = fixture.runtime.index.rows.find((r) => r.blob_bytes > 0)?.blobs[0]?.sha256 ?? "";
    expect(target.blobs.has(blob)).toBe(true);
    // imported effects never enter the live registry
    expect(target.effects.instances()).toEqual([]);
  });
});

describe("bundles: manifests-only imports (review fixes DATA-4/5)", () => {
  it("a default (manifests-only) import charges no stream quota and the importing run still exports (DATA-4/5)", async () => {
    const { fixture } = await populated();
    const bundle = await exportTo(fixture, "manifests"); // default streams: "manifests"
    const target = fixture.another();
    const before = target.quotas.usage.streams;
    const imported = await target.bundles.import({ path: bundle.out });
    if (!imported.ok) throw new Error(JSON.stringify(imported.error));
    expect(target.quotas.usage.streams).toBe(before); // no chunk bytes arrived
    const stream = [...target.index.streams.values()][0];
    const reader = stream === undefined ? null : target.streams.reader(stream.stream_id);
    const verified = reader?.ok === true ? await reader.value.verify() : null;
    expect(verified?.ok === true && verified.value.included).toBe("manifests-only");
    // the whole importing run exports again, in both modes; the stream stays manifests-only
    for (const streams of ["manifests", "all"] as const) {
      const out = join(fixture.home.work, `re-${streams}`);
      const again = await target.bundles.export({ out_path: out, streams } as never);
      if (!again.ok) throw new Error(JSON.stringify(again.error));
      const manifest = JSON.parse(await readFile(join(out, "bundle.json"), "utf8")) as {
        streams: { included: string }[];
      };
      expect(manifest.streams.map((s) => s.included)).toEqual(["manifests-only"]);
    }
  });

  it("rejects a stream chain line whose file is not its chunk name, before using it as a path (DATA-4)", async () => {
    const { fixture } = await populated();
    const { out } = await exportTo(fixture, "chain-path", { streams: "all" });
    const st = (await readdir(join(out, "streams")))[0] ?? "";
    const chainPath = join(out, "streams", st, "chain.jsonl");
    const text = await readFile(chainPath, "utf8");
    await writeFile(chainPath, text.replace('"chunk-000000.bin"', '"..\\\\..\\\\records.jsonl"'));
    const result = await fixture.another().bundles.import({ path: out, validate_only: true });
    expect(!result.ok && result.error).toMatchObject({ _tag: "EvidenceIntegrity", reason: "schema" });
  });
});

describe("bundles: integrity and selection", () => {
  it("rejects a tampered record, blob or chunk and leaves the ledger unchanged", async () => {
    const { fixture } = await populated();
    const target = fixture.another();
    const before = target.index.rows.length;
    const tamper = async (name: string, edit: (dir: string) => Promise<void>) => {
      const { out } = await exportTo(fixture, name, { streams: "all" });
      await edit(out);
      const result = await target.bundles.import({ path: out });
      expect(result.ok || result.error._tag, name).toBe("EvidenceIntegrity");
    };
    await tamper("t-record", async (dir) => {
      const path = join(dir, "records.jsonl");
      await writeFile(path, (await readFile(path, "utf8")).replace('"read_memory"', '"read_memorz"'));
    });
    await tamper("t-blob", async (dir) => {
      const name = (await readdir(join(dir, "blobs")))[0] ?? "";
      await writeFile(join(dir, "blobs", name), "x");
    });
    await tamper("t-chunk", async (dir) => {
      const st = (await readdir(join(dir, "streams")))[0] ?? "";
      await writeFile(join(dir, "streams", st, "chunk-000000.bin"), "x");
    });
    await tamper("t-extra", async (dir) => {
      await writeFile(join(dir, "notes.txt"), "unexpected");
    });
    expect(target.index.rows.length).toBe(before);
    expect(target.ledger.started).toBe(true);
  });

  it("never overwrites: an existing out_path is file_operation_failed(exists) and no staging remains", async () => {
    const { fixture } = await populated();
    await mkdir(join(fixture.home.work, "taken"));
    const result = await fixture.runtime.bundles.export({ out_path: join(fixture.home.work, "taken") });
    expect(result.ok || result.error).toMatchObject({ _tag: "FileOperationFailed", reason: "exists" });
    expect((await readdir(fixture.home.work)).filter((n) => n.includes("staging"))).toEqual([]);
  });

  it("an instance selection carries its closure only", async () => {
    const { fixture, instance } = await populated();
    const second = await fixture.runtime.instances.register(await observation(fixture.home, 5555, "other.exe"));
    if (!second.ok) throw new Error("register");
    const all = await exportTo(fixture, "all");
    const one = await exportTo(fixture, "one", { instance_id: instance });
    expect(Number(one.value["records"])).toBeLessThan(Number(all.value["records"]));
    const text = await readFile(join(one.out, "records.jsonl"), "utf8");
    expect(text).not.toContain(second.value.instance.instance_id);
    const verdict = await fixture.another().bundles.import({ path: one.out, validate_only: true });
    expect(verdict.ok).toBe(true);
  });
});

describe("bundles: zip archives", () => {
  it("plans every entry against the manifest before extracting: unlisted side files and oversized chunks (SEC-5)", async () => {
    const { fixture } = await populated();
    const manifestOf = (streams: readonly Record<string, unknown>[]) =>
      Buffer.from(
        JSON.stringify({
          schema: "bea.bundle/1",
          bundle_digest: "a".repeat(64),
          producer: { name: "bea", version: "0.1.0" },
          created_wall: "2026-10-28T00:00:00.000Z",
          source_runs: ["run_20261028T000000Z_0123456789abcdef"],
          selection: { kind: "run", instance_id: null, roots: [] },
          records: { path: "records.jsonl", sha256: "b".repeat(64), bytes: 0, lines: 0 },
          counts: {
            instances: 0,
            module_maps: 0,
            effects: 0,
            effect_transitions: 0,
            unknown_revisions: 0,
            evidence: 0,
          },
          blobs_included: false,
          blobs: [],
          streams,
        }),
      );
    const zipWith = async (name: string, entries: readonly [string, Buffer][]) => {
      const zip = new ZipFile();
      for (const [entry, data] of entries) zip.addBuffer(data, entry, { compress: true });
      zip.end();
      const path = join(fixture.home.work, name);
      await pipeline(zip.outputStream, createWriteStream(path));
      return path;
    };
    const target = fixture.another();
    const sid = (n: number) => `st_${n.toString(16).padStart(64, "0")}`;
    // many 512 KiB unlisted descriptor/chain entries: each under the per-entry ratio threshold of old
    const unlisted = await zipWith("unlisted.zip", [
      ["bundle.json", manifestOf([])],
      ...Array.from({ length: 20 }, (_, i): [string, Buffer] => [
        `streams/${sid(i + 1)}/descriptor.json`,
        Buffer.alloc(512 * 1024, 0x41),
      ]),
    ]);
    const a = await target.bundles.import({ path: unlisted, validate_only: true });
    expect(!a.ok && a.error).toMatchObject({ _tag: "EvidenceIntegrity" });
    expect(JSON.stringify(!a.ok && a.error.diagnostics)).toMatch(/not referenced|ratio/u);
    // a listed manifests-only stream may not carry chunks; an "all" stream's chunks may not exceed its bytes
    const stream = (included: string) => ({
      stream_id: sid(7),
      descriptor_sha256: "c".repeat(64),
      head_chain: "d".repeat(64),
      chunks: 2,
      bytes: 100,
      included,
    });
    const chunky = await zipWith("chunky.zip", [
      ["bundle.json", manifestOf([stream("manifests-only")])],
      [`streams/${sid(7)}/chunk-000000.bin`, Buffer.alloc(50, 1)],
    ]);
    const b = await target.bundles.import({ path: chunky, validate_only: true });
    expect(JSON.stringify(!b.ok && b.error.diagnostics)).toContain("not referenced");
    const over = await zipWith("over.zip", [
      ["bundle.json", manifestOf([stream("all")])],
      [`streams/${sid(7)}/chunk-000000.bin`, Buffer.alloc(80, 1)],
      [`streams/${sid(7)}/chunk-000001.bin`, Buffer.alloc(80, 2)],
    ]);
    const c = await target.bundles.import({ path: over, validate_only: true });
    expect(JSON.stringify(!c.ok && c.error.diagnostics)).toContain("larger than declared");
  });

  it("rejects zips with traversal names, unknown entries or a bomb-like ratio", async () => {
    const { fixture } = await populated();
    const zipWith = async (name: string, entries: readonly [string, Buffer][]) => {
      const zip = new ZipFile();
      for (const [entry, data] of entries) zip.addBuffer(data, entry);
      zip.end();
      const path = join(fixture.home.work, name);
      await pipeline(zip.outputStream, createWriteStream(path));
      return path;
    };
    const target = fixture.another();
    const bomb = await zipWith("bomb.zip", [["records.jsonl", Buffer.alloc(8 * 1024 * 1024)]]);
    const extra = await zipWith("extra.zip", [
      ["bundle.json", Buffer.from("{}")],
      ["evil.exe", Buffer.from("MZ")],
    ]);
    for (const path of [bomb, extra]) {
      const result = await target.bundles.import({ path });
      expect(result.ok || result.error._tag, path).toBe("EvidenceIntegrity");
    }
    expect(isUnsafeName("../x")).toBe(true);
    expect(isUnsafeName("blobs\\x")).toBe(true);
    expect(isUnsafeName("C:/x")).toBe(true);
    expect(isUnsafeName("/abs")).toBe(true);
    expect(isUnsafeName("blobs/ok")).toBe(false);
    expect(await readdir(join(target.run.dir, "tmp"))).toEqual([]);
  });

  it("an import that conflicts with this run's ledger is rejected atomically", async () => {
    const { fixture } = await populated();
    const { out } = await exportTo(fixture, "c");
    // the wall clock is outside the ev_ identity: a re-sealed bundle can carry the same id with different bytes
    const path = join(out, "records.jsonl");
    const lines = (await readFile(path, "utf8")).split("\n").filter((l) => l.length > 0);
    const index = lines.findIndex((l) => l.startsWith('{"record":') && l.includes('"wall":"'));
    lines[index] = (lines[index] ?? "").replace(/"wall":"\d{4}/u, '"wall":"1999');
    const body = `${lines.join("\n")}\n`;
    await writeFile(path, body);
    const manifest = JSON.parse(await readFile(join(out, "bundle.json"), "utf8")) as Record<string, unknown>;
    manifest["records"] = {
      ...(manifest["records"] as object),
      sha256: sha256Hex(body),
      bytes: Buffer.byteLength(body),
    };
    manifest["bundle_digest"] = bundleDigestOf(manifest as never);
    await writeFile(join(out, "bundle.json"), `${canonicalJson(manifest as never)}\n`);
    const ledgerBefore = fixture.runtime.ledger.bytes;
    const rowsBefore = fixture.runtime.index.rows.length;
    const validated = await fixture.another().bundles.import({ path: out, validate_only: true });
    expect(validated.ok).toBe(true);
    const result = await fixture.runtime.bundles.import({ path: out });
    expect(result.ok || result.error).toMatchObject({ _tag: "EvidenceIntegrity", reason: "conflicting-record" });
    expect(fixture.runtime.ledger.bytes).toBe(ledgerBefore);
    expect(fixture.runtime.index.rows.length).toBe(rowsBefore);
  });
});
