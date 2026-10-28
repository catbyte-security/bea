import { createHash } from "node:crypto";
import { readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { literalsOf, NO_LITERALS } from "../../../src/domain/redaction/literals.js";
import { makeRuntime, type RuntimeFixture } from "./support.js";

let fx: RuntimeFixture | undefined;
afterEach(async () => {
  await fx?.cleanup();
  fx = undefined;
});

const chunks = async function* (parts: readonly string[]): AsyncIterable<Uint8Array> {
  for (const part of parts) yield new TextEncoder().encode(part);
};

describe("blobs (S2 §11)", () => {
  it("stores content-addressed, deduplicates, reads ranges and verifies", async () => {
    fx = await makeRuntime();
    const data = new TextEncoder().encode("hello blob world");
    const a = await fx.runtime.blobs.put(data, {
      role: "memory",
      media_type: "application/octet-stream",
      literals: NO_LITERALS,
    });
    const b = await fx.runtime.blobs.put(chunks(["hello ", "blob ", "world"]), {
      role: "copy",
      media_type: "application/octet-stream",
      literals: NO_LITERALS,
    });
    if (!a.ok || !b.ok || "redacted" in a.value || "redacted" in b.value) throw new Error("put");
    const sha = createHash("sha256").update(data).digest("hex");
    expect(a.value).toEqual({ role: "memory", sha256: sha, bytes: 16, media_type: "application/octet-stream" });
    expect(b.value.sha256).toBe(sha);
    expect(fx.runtime.blobs.size(sha)).toBe(16);
    expect(fx.runtime.quotas.usage.blobs).toBe(16);
    expect(await readdir(join(fx.runtime.run.dir, "blobs"))).toEqual([sha]);
    const range = await fx.runtime.blobs.read(sha, 6, 4);
    expect(range.ok && new TextDecoder().decode(range.value)).toBe("blob");
    expect((await fx.runtime.blobs.verify(sha)).ok).toBe(true);
    await writeFile(join(fx.runtime.run.dir, "blobs", sha), "tampered");
    const tampered = await fx.runtime.blobs.verify(sha);
    expect(tampered.ok || tampered.error._tag).toBe("EvidenceIntegrity");
  });

  it("withholds a blob containing a literal, even split across chunks", async () => {
    fx = await makeRuntime();
    const put = await fx.runtime.blobs.put(chunks(["xx sec", "ret yy"]), {
      role: "dump",
      media_type: "application/octet-stream",
      literals: literalsOf(["secret"]),
    });
    expect(put).toEqual({ ok: true, value: { redacted: true } });
    expect(await readdir(join(fx.runtime.run.dir, "blobs"))).toEqual([]);
    expect(await readdir(join(fx.runtime.run.dir, "tmp"))).toEqual([]);
    expect(fx.runtime.quotas.usage.blobs).toBe(0);
  });

  it("refuses a blob over the run's blob quota and names the knob", async () => {
    fx = await makeRuntime({ env: { BEA_BLOB_QUOTA_MB: "16" } });
    const put = await fx.runtime.blobs.put(new Uint8Array(17 * 1024 * 1024), {
      role: "dump",
      media_type: "application/octet-stream",
      literals: NO_LITERALS,
    });
    expect(put.ok).toBe(false);
    if (!put.ok)
      expect(put.error).toMatchObject({
        _tag: "ResourceConstraint",
        limits: { quota: "blobs", knob: "BEA_BLOB_QUOTA_MB" },
      });
    expect(await readdir(join(fx.runtime.run.dir, "tmp"))).toEqual([]);
  });

  it("rejects an invalid role and an unknown digest", async () => {
    fx = await makeRuntime();
    const bad = await fx.runtime.blobs.put(new Uint8Array(1), {
      role: "Bad Role",
      media_type: "x",
      literals: NO_LITERALS,
    });
    expect(bad.ok || bad.error._tag).toBe("Internal");
    const missing = await fx.runtime.blobs.read("0".repeat(64), 0, 1);
    expect(missing.ok || missing.error._tag).toBe("ReferenceNotFound");
  });
});
