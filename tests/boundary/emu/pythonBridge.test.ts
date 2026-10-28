import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { emuSkip, gccSkip, loadFixtures, skipNote } from "../../support/acceptance/fixtures.js";
import { realPython } from "../../support/emu/python.js";

/**
 * The Python half of the S5 §14.1 `test:emu` lane: the bridge's own suite (bridge/emu/tests/run_tests.py, WP14) run
 * by `npm run test:emu`. It drives the REAL bridge on bea_emu_fixture.dll: every status (INT3 stop on the first VEX
 * instruction, x87 tag, unhandled CreateEventA with the caller RVA, budget, watchdog timeout, cancel latency, #DE,
 * syscall, terminated), the FP environment, struct buffers + ptr_to + codecs, hidden struct return, heap placement +
 * named state, the snapshot ordering suite (E8b + 200 random interleavings), map_zero in manual mode, the memory
 * limit, --probe/--selftest, the ISA cache, dump-backed sessions and the bridge build script. The interpreter is the
 * absolute one the emulation lanes use (BEA_PYTHON, else `python` on PATH, run with -I); the fixtures are this run's
 * gcc build (BEA_EMU_FIXTURE_DIR). The suite kills every bridge it started and fails on a leak.
 */
const skip = emuSkip() !== false ? emuSkip() : gccSkip();

const run = (command: string, args: readonly string[], env: NodeJS.ProcessEnv) =>
  new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve, reject) => {
    const child = spawn(command, args, { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, stdout, stderr }));
  });

describe.skipIf(skip !== false)(`bridge Python suite on bea_emu_fixture.dll (S5 §14.1)${skipNote(skip)}`, () => {
  it("passes with no leaked bridge process", { timeout: 600_000 }, async () => {
    const manifest = await loadFixtures();
    if ("unavailable" in manifest) throw new Error(manifest.unavailable);
    const python = realPython();
    if (python === null) throw new Error("no python resolved although EMU_SKIP is false");
    const runner = fileURLToPath(new URL("../../../bridge/emu/tests/run_tests.py", import.meta.url));
    const result = await run(python, ["-I", runner, "-q"], { ...process.env, BEA_EMU_FIXTURE_DIR: manifest.dir });
    const tail = result.stderr.slice(-6_000);
    expect(result.code, tail).toBe(0);
    const ran = Number(/^Ran (\d+) tests? in /mu.exec(result.stderr)?.[1] ?? 0);
    expect(ran, tail).toBeGreaterThanOrEqual(100);
    expect(result.stderr, tail).toMatch(/^OK\b/mu);
    expect(result.stderr, tail).toMatch(/bridge processes started: \d+, leaked: 0/u);
  });
});
