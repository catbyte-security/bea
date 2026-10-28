import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { fixtureToolchain } from "../../../../scripts/lib/fixtures.mjs";

/**
 * A target built by the test in a temp directory (DESIGN §8.1 "a test that needs a [special] target builds one in a
 * temp directory"; the `--ftz` flag for live_fixture is an open change request): its main thread runs with MXCSR
 * 0x9FC0 (FTZ | DAZ, all exceptions masked) and calls `ftz_tick` every 10 ms (a safe point for thread_at), and it
 * exports `four_floats` with the same source and flags as live_fixture's, so the S5 §9.6 denormal vector gives
 * 0x03480020 under round-to-nearest and 0x0 under FTZ/DAZ.
 */
const FTZ_TARGET_SOURCE = String.raw`
#include <windows.h>
#include <xmmintrin.h>

#define EXPORT __declspec(dllexport)
#define NOINLINE __attribute__((noinline))

EXPORT volatile unsigned g_ticks;

EXPORT NOINLINE float four_floats(float a, float b, float c, float d)
{
    return a * 1000.0f + b * 100.0f + c * 10.0f + d;
}

EXPORT NOINLINE unsigned ftz_tick(unsigned x)
{
    g_ticks = x;
    return x * 2654435761u;
}

int main(void)
{
    _mm_setcsr(0x9FC0);
    for (unsigned i = 0;; i++) {
        ftz_tick(i);
        Sleep(10);
    }
}
`;

export const FTZ_TARGET_EXE = "bea_ftz_target.exe";

export interface BuiltTarget {
  readonly path: string;
  readonly cleanup: () => Promise<void>;
}

const run = (command: string, args: readonly string[], cwd: string): Promise<{ code: number | null; out: string }> =>
  new Promise((resolve, reject) => {
    const child = spawn(command, [...args], { cwd, windowsHide: true });
    let out = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (out += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (out += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, out }));
  });

/** gcc -O2 (the fixtures' toolchain) into a fresh temp directory; cleanup removes it once the target has exited. */
export const buildFtzTarget = async (): Promise<BuiltTarget> => {
  const toolchain = fixtureToolchain();
  if ("unavailable" in toolchain) throw new Error(toolchain.unavailable);
  const dir = await mkdtemp(join(tmpdir(), "bea-wp11-ftz-"));
  const cleanup = (): Promise<void> => rm(dir, { recursive: true, force: true, maxRetries: 5 }).catch(() => undefined);
  try {
    await writeFile(join(dir, "bea_ftz_target.c"), FTZ_TARGET_SOURCE);
    const built = await run(
      toolchain.cc.path,
      ["-O2", "-Wall", "-Wl,--no-insert-timestamp", "-o", FTZ_TARGET_EXE, "bea_ftz_target.c"],
      dir,
    );
    if (built.code !== 0) throw new Error(`gcc failed (${String(built.code)}): ${built.out}`);
    return { path: join(dir, FTZ_TARGET_EXE), cleanup };
  } catch (cause) {
    await cleanup();
    throw cause;
  }
};
