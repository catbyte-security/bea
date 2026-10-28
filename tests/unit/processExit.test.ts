import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { afterAll, describe, expect, it } from "vitest";

/**
 * Review fix LIFE-2: the servers' hard exit must be REF'D and EXPLICIT. An unref'd timer never fires once the loop
 * drains into Node's natural-exit teardown (where frida-node's DeviceManager cleanup hook can block forever), so the
 * child below records whether process.exit was really called.
 */
const module = pathToFileURL(join(import.meta.dirname, "..", "..", "src", "main", "processShutdown.ts")).href;
const dir = mkdtempSync(join(tmpdir(), "bea-exit-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const runChild = (body: string): { readonly status: number | null; readonly stderr: string; readonly ms: number } => {
  const file = join(dir, `child-${String(Math.random()).slice(2)}.mjs`);
  writeFileSync(
    file,
    [
      `import { processExitAfterMs } from ${JSON.stringify(module)};`,
      "const realExit = process.exit.bind(process);",
      "process.exit = (code) => { process.stderr.write(`explicit:${String(code)}\\n`); return realExit(code); };",
      body,
    ].join("\n"),
  );
  const started = performance.now();
  const out = spawnSync(process.execPath, [file], { encoding: "utf8", timeout: 20_000 });
  return { status: out.status, stderr: out.stderr, ms: performance.now() - started };
};

describe("processExitAfterMs (LIFE-2)", () => {
  it("the hard-exit timer keeps the loop alive and exits explicitly with the code set so far", () => {
    const out = runChild("process.exitCode = 7; processExitAfterMs(null, 100);");
    expect(out.stderr).toContain("explicit:7");
    expect(out.status).toBe(7);
  });

  it("after cleanup it exits explicitly as soon as stdout drained, well before the cap", () => {
    const out = runChild('process.stdout.write("x".repeat(65536)); processExitAfterMs(3, 15_000);');
    expect(out.stderr).toContain("explicit:3");
    expect(out.status).toBe(3);
    expect(out.ms).toBeLessThan(10_000);
  });
});
