import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  FRIDA_TEMP_OWNER,
  fridaTempFits,
  prepareFridaTemp,
  releaseFridaTemp,
  sweepFridaTemp,
  withTempDir,
  type FridaTempDeps,
} from "../../../src/providers/frida/fridaTemp.js";
import { directorySignals } from "../../../src/providers/frida/antiCheatSignals.js";
import { listImageNeighbourhood } from "../../../src/providers/frida/fileHash.js";
import { addForeign, createHarness, errTag } from "./support/harness.js";

/**
 * Review fix LIFE-3: Frida's ~45 MB agent extraction lands in a BEA-owned per-run directory (TEMP points there only
 * while device.attach runs) and preparing it reclaims the directories of dead owners (never a live one, never this
 * process's own, never the user's %TEMP%).
 */
let root: string | null = null;
afterEach(() => {
  if (root !== null) rmSync(root, { recursive: true, force: true });
  root = null;
});

const deps = (alive: ReadonlySet<number>, selfPid = 100): FridaTempDeps => ({
  pidAlive: (pid) => alive.has(pid),
  now: () => Date.now(),
  selfPid,
});

const ownedDir = (base: string, name: string, pid: number): string => {
  const dir = join(base, name);
  mkdirSync(join(dir, "frida-0123abcd"), { recursive: true });
  writeFileSync(join(dir, "frida-0123abcd", "frida-agent.dll"), "x".repeat(1024));
  writeFileSync(
    join(dir, FRIDA_TEMP_OWNER),
    JSON.stringify({ schema: "bea.frida-temp/1", pid, run_id: name, started_at: "2026-10-28T00:00:00.000Z" }),
  );
  return dir;
};

describe("anti-cheat neighbourhood (SEC-6)", () => {
  it("sees EasyAntiCheat and start_protected_game.exe in the root of an Unreal Engine layout", async () => {
    root = mkdtempSync(join(tmpdir(), "bea-ue-"));
    const win64 = join(root, "MyGame", "Binaries", "Win64");
    mkdirSync(win64, { recursive: true });
    mkdirSync(join(root, "EasyAntiCheat"));
    writeFileSync(join(root, "start_protected_game.exe"), "");
    writeFileSync(join(win64, "MyGame-Win64-Shipping.exe"), "");
    const names = await listImageNeighbourhood(join(win64, "MyGame-Win64-Shipping.exe"));
    expect(directorySignals(names)).toEqual(
      expect.arrayContaining(["dir:EasyAntiCheat", "dir:start_protected_game.exe"]),
    );
  });
});

describe("BEA-owned Frida temp directories (LIFE-3)", () => {
  it("prepares the run directory (TEMP untouched) and sweeps dead owners only", () => {
    root = mkdtempSync(join(tmpdir(), "bea-frida-temp-"));
    const dead = ownedDir(root, "run_dead", 4242);
    const alive = ownedDir(root, "run_alive", 5151);
    const youngUnowned = join(root, "run_young");
    mkdirSync(youngUnowned);
    const oldUnowned = join(root, "run_old");
    mkdirSync(oldUnowned);
    const old = new Date(Date.now() - 3_600_000);
    utimesSync(oldUnowned, old, old);
    const before = process.env["TEMP"];
    const dir = prepareFridaTemp(root, "run_self", deps(new Set([5151])));
    expect(dir).toBe(join(root, "run_self"));
    expect(process.env["TEMP"]).toBe(before);
    expect(JSON.parse(readFileSync(join(root, "run_self", FRIDA_TEMP_OWNER), "utf8"))).toMatchObject({
      pid: 100,
      run_id: "run_self",
    });
    expect(existsSync(dead)).toBe(false);
    expect(existsSync(oldUnowned)).toBe(false);
    expect(existsSync(alive)).toBe(true);
    expect(existsSync(youngUnowned)).toBe(true);
    // a later sweep from another process never removes the live owner's directory, nor its own
    expect(sweepFridaTemp(root, deps(new Set([100, 5151]), 7))).toEqual({ removed: 0, busy: 0 });
    expect(existsSync(join(root, "run_self"))).toBe(true);
    // once the owner is gone, the next process reclaims it
    expect(sweepFridaTemp(root, deps(new Set([5151]), 7)).removed).toBe(1);
    expect(existsSync(join(root, "run_self"))).toBe(false);
  });

  it("points TEMP/TMP at the directory only inside the window, restoring them (nested, thrown, unset)", async () => {
    const env: Record<string, string | undefined> = { TEMP: "/user-temp" };
    const seen: (string | undefined)[] = [];
    await withTempDir(
      "/bea/tmp/frida/run_1",
      async () => {
        seen.push(env["TEMP"], env["TMP"]);
        // a concurrent attach shares the window; the first to finish must not restore early
        await withTempDir("/bea/tmp/frida/run_1", async () => seen.push(env["TEMP"]), env);
        seen.push(env["TEMP"]);
      },
      env,
    );
    expect(seen).toEqual(Array(4).fill("/bea/tmp/frida/run_1"));
    expect(env).toEqual({ TEMP: "/user-temp" });
    await expect(
      withTempDir(
        "/d",
        async () => {
          throw new Error("attach failed");
        },
        env,
      ),
    ).rejects.toThrow("attach failed");
    expect(env).toEqual({ TEMP: "/user-temp" });
    expect(await withTempDir(null, async () => env["TEMP"], env)).toBe("/user-temp");
  });

  it("spawn and attach run device.attach inside the window; TEMP is restored afterwards", async () => {
    const dir = "/bea-home/tmp/frida/run_t";
    const before = process.env["TEMP"];
    const h = createHarness({ fridaTempDir: () => dir });
    expect(errTag(await h.spawn())).toBe("ok");
    addForeign(h, 7600);
    expect(errTag(await h.attach(7600))).toBe("ok");
    expect(h.fake.attachTemp).toEqual([dir, dir]);
    expect(process.env["TEMP"]).toBe(before);
    await h.closeAll();
  });

  it("release removes the run directory; a missing root is no error", () => {
    root = mkdtempSync(join(tmpdir(), "bea-frida-temp-"));
    const dir = ownedDir(root, "run_x", 1);
    releaseFridaTemp(dir);
    expect(existsSync(dir)).toBe(false);
    releaseFridaTemp(null);
    expect(sweepFridaTemp(join(root, "missing"), deps(new Set()))).toEqual({ removed: 0, busy: 0 });
  });

  it("leaves Frida in the user's TEMP when the run directory is too deep for its extraction path", () => {
    // Frida writes <dir>/frida-<32 hex>/x86_64/frida-agent.dll through MAX_PATH-limited calls: a deep BEA_HOME made
    // every injection fail ("Error opening file") before the guard (found by the final verification)
    root = mkdtempSync(join(tmpdir(), "bea-frida-temp-"));
    const deep = join(root, "d".repeat(Math.max(1, 200 - root.length)));
    expect(fridaTempFits(join(deep, "run_x"))).toBe(false);
    expect(prepareFridaTemp(deep, "run_x", deps(new Set()))).toBeNull();
    expect(existsSync(join(deep, "run_x"))).toBe(false);
    expect(fridaTempFits(join(root, "run_x"))).toBe(true);
    expect(fridaTempFits(`C:/${"a".repeat(194)}`)).toBe(true); // 197 characters + the 62-character suffix = 259
    expect(fridaTempFits(`C:/${"a".repeat(195)}`)).toBe(false);
  });
});
