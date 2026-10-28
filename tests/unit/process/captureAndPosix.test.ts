import { describe, expect, it } from "vitest";

import type { AppendOutcome, FrameBatchHeader, StreamWriter } from "../../../src/ports/evidence.js";
import {
  createOutputCapture,
  incompleteUtf8Tail,
  leadingContinuationBytes,
} from "../../../src/providers/process/BoundedCapture.js";
import {
  BestEffortOwnership,
  findDescendants,
  POSIX_BEST_EFFORT_LIMITATION,
  posixContainmentFacts,
  type PosixProcessApi,
} from "../../../src/providers/process/posix/BestEffortOwnership.js";
import {
  parseBootTime,
  parseProcStat,
  parseRealUid,
  startTicksToFiletime,
  type ProcFs,
} from "../../../src/providers/process/posix/procfs.js";
import { inspectLinux } from "../../../src/providers/process/ProcessInspector.js";

const fakeStream = (outcomes: AppendOutcome[] = []) => {
  const appended: { header: FrameBatchHeader; payload: Uint8Array }[] = [];
  const writer = {
    append: (header: FrameBatchHeader, payload: Uint8Array): AppendOutcome => {
      appended.push({ header, payload });
      return outcomes.shift() ?? "accepted";
    },
  } as unknown as StreamWriter;
  return { writer, appended };
};

describe("BoundedCapture (S3 §15)", () => {
  it("keeps head and tail, counts omitted bytes and records every chunk on the stdio stream", () => {
    const { writer, appended } = fakeStream();
    const capture = createOutputCapture({ pid: 1, headBytes: 4, tailBytes: 6, stream: writer });
    capture.onChunk(1, Buffer.from("abcdefgh"));
    capture.onChunk(1, Buffer.from("ijklmnop"));
    capture.onChunk(2, Buffer.from("err"));
    capture.onChunk(5, Buffer.from("xx"));
    const snap = capture.snapshot();
    expect(snap.stdout).toMatchObject({
      head: "abcd",
      tail: "klmnop",
      observedBytes: 16,
      retainedBytes: 10,
      omittedBytes: 6,
      truncated: true,
      invalidUtf8: false,
      eof: false,
    });
    expect(snap.stderr).toMatchObject({ head: "err", tail: "", truncated: false });
    expect(snap.otherFds).toEqual([{ fd: 5, bytes: 2 }]);
    expect(appended.map((a) => [a.header.first_seq, a.payload[0], a.payload.length])).toEqual([
      [1, 1, 9],
      [2, 1, 9],
      [3, 2, 4],
    ]);
    expect(capture.observedBytes).toEqual({ stdout: 16, stderr: 3 });
    expect(capture.truncated).toBe(true);
    expect(capture.tail(1, 3)).toBe("nop");
    expect(capture.contains("mno")).toBe(true);
    expect(capture.contains("efg")).toBe(false);
  });

  it("keeps draining after the stream refuses, and resolves ended on EOF of both fds", async () => {
    const { writer } = fakeStream(["accepted", "quota-exceeded"]);
    const capture = createOutputCapture({ pid: 1, stream: writer });
    capture.onChunk(1, Buffer.from("a"));
    capture.onChunk(1, Buffer.from("b"));
    capture.onChunk(1, Buffer.from("c"));
    expect(capture.stream).toEqual({ appended: 1, refused: 2 });
    expect(capture.snapshot().stdout.head).toBe("abc");
    capture.onChunk(1, Buffer.alloc(0));
    expect(capture.eof).toEqual({ stdout: true, stderr: false });
    capture.onChunk(2, Buffer.alloc(0));
    await capture.ended;
    capture.close();
    capture.onChunk(1, Buffer.from("late"));
    expect(capture.observedBytes.stdout).toBe(3);
  });

  it("never splits a code point between head, tail and the gap; flags invalid UTF-8", () => {
    expect(incompleteUtf8Tail(Buffer.from([0x61, 0xe2, 0x82]))).toBe(2);
    expect(incompleteUtf8Tail(Buffer.from("a€"))).toBe(0);
    expect(leadingContinuationBytes(Buffer.from([0x82, 0xac, 0x61]))).toBe(2);
    const contiguous = createOutputCapture({ pid: 1, headBytes: 2, tailBytes: 16, stream: null });
    contiguous.onChunk(1, Buffer.from("a€b"));
    expect(contiguous.snapshot().stdout).toMatchObject({ head: "a", tail: "€b", invalidUtf8: false, truncated: false });
    const gap = createOutputCapture({ pid: 1, headBytes: 2, tailBytes: 3, stream: null });
    gap.onChunk(1, Buffer.from("a€xx€"));
    expect(gap.snapshot().stdout).toMatchObject({ head: "a", tail: "€", truncated: true });
    const oem = createOutputCapture({ pid: 1, stream: null });
    oem.onChunk(1, Buffer.from([0x41, 0x81, 0x42]));
    expect(oem.snapshot().stdout.invalidUtf8).toBe(true);
  });
});

/** In-memory /proc: pid -> {stat, uid, exe}. */
const fakeProc = (procs: Record<number, { stat: string; uid?: number; exe?: string }>, btime = 1_700_000_000) => {
  const fs: ProcFs = {
    readText: async (path) => {
      if (path === "/proc/stat") return `cpu 1 2 3\nbtime ${String(btime)}\nprocesses 9\n`;
      const match = /^\/proc\/(\d+)\/(stat|status)$/u.exec(path);
      const proc = match === null ? undefined : procs[Number(match[1])];
      if (proc === undefined || match === null) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
      return match[2] === "stat" ? proc.stat : `Name:\tx\nUid:\t${String(proc.uid ?? 1000)}\t1000\t1000\t1000\n`;
    },
    readLink: async (path) => {
      const proc = procs[Number(/^\/proc\/(\d+)\/exe$/u.exec(path)?.[1])];
      if (proc?.exe === undefined) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
      return proc.exe;
    },
    list: async () => Object.keys(procs).concat(["self", "stat"]),
  };
  return fs;
};
const stat = (
  pid: number,
  f: {
    readonly ppid: number;
    readonly pgrp: number;
    readonly start: number;
    readonly state?: string;
    readonly comm?: string;
  },
) =>
  `${String(pid)} (${f.comm ?? "game"}) ${f.state ?? "S"} ${String(f.ppid)} ${String(f.pgrp)} ${String(f.pgrp)} 0 -1 4194304 1 0 0 0 0 0 0 0 20 0 1 0 ${String(f.start)} 1000 10`;

describe("Linux /proc (S3 §19; BELIEVED, exercised with an in-memory /proc)", () => {
  it("parses stat with awkward comm values, btime, Uid and FILETIME start times", () => {
    expect(parseProcStat(stat(5, { ppid: 1, pgrp: 5, start: 777, state: "R", comm: "a) (b" }))).toEqual({
      pid: 5,
      state: "R",
      ppid: 1,
      pgrp: 5,
      session: 5,
      startTicks: 777n,
    });
    expect(parseProcStat("garbage")).toBeNull();
    expect(parseBootTime("btime 12\n")).toBe(12n);
    expect(parseRealUid("Uid:\t0\t0\t0\t0\n")).toBe(0);
    expect(startTicksToFiletime(0n, 100n)).toBe(116_444_736_010_000_000n);
  });

  it("inspectLinux fills the portable facts and leaves Windows-only ones null", async () => {
    const fs = fakeProc({ 10: { stat: stat(10, { ppid: 1, pgrp: 10, start: 500 }), uid: 1000, exe: "/usr/bin/game" } });
    const result = await inspectLinux(10, fs, 1000);
    expect(result).toMatchObject({
      ok: true,
      value: {
        pid: 10,
        exited: false,
        parentPid: 1,
        imagePath: "/usr/bin/game",
        sameUser: true,
        elevated: false,
        wow64: null,
        critical: null,
      },
    });
    expect(result.ok && result.value.creationTime100ns).toBe(startTicksToFiletime(1_700_000_000n, 500n));
    expect(await inspectLinux(11, fs, 1000)).toMatchObject({ ok: false, error: { _tag: "InputError" } });
  });

  it("finds descendants started after the root by parent links", () => {
    const all = [
      { pid: 10, state: "S", ppid: 1, pgrp: 10, session: 10, startTicks: 500n },
      { pid: 11, state: "S", ppid: 10, pgrp: 10, session: 10, startTicks: 510n },
      { pid: 12, state: "S", ppid: 11, pgrp: 12, session: 12, startTicks: 520n },
      { pid: 13, state: "S", ppid: 10, pgrp: 13, session: 13, startTicks: 400n },
      { pid: 14, state: "S", ppid: 1, pgrp: 14, session: 14, startTicks: 600n },
    ];
    const root = all[0];
    if (root === undefined) throw new Error("fixture");
    expect(findDescendants(root, all).map((s) => s.pid)).toEqual([11, 12]);
  });

  it("BestEffortOwnership kills group, root and verified descendants, then polls until the root is gone", async () => {
    const procs: Record<number, { stat: string }> = {
      10: { stat: stat(10, { ppid: 1, pgrp: 10, start: 500 }) },
      11: { stat: stat(11, { ppid: 10, pgrp: 10, start: 510 }) },
      12: { stat: stat(12, { ppid: 11, pgrp: 12, start: 520 }) },
    };
    const signals: number[] = [];
    let t = 0;
    const api: PosixProcessApi = {
      fs: fakeProc(procs),
      kill: (pid) => {
        signals.push(pid);
        if (pid > 0) delete procs[pid];
        // pid 12 exits and is reused between the descendant snapshot and its own re-verification
        if (pid === 11) procs[12] = { stat: stat(12, { ppid: 1, pgrp: 12, start: 999 }) };
      },
      now: () => t,
      sleep: async (ms) => {
        t += ms;
      },
    };
    const captured = await BestEffortOwnership.capture(10, api);
    if (!captured.ok) throw new Error("capture failed");
    const report = await captured.value.kill();
    expect(signals).toEqual([-10, 10, 11]);
    expect(report).toMatchObject({
      rootVerified: true,
      groupKilled: true,
      killed: [10, 11],
      skipped: [12],
      rootGone: true,
    });
    expect(await captured.value.kill()).toBe(report);
    expect(posixContainmentFacts()).toMatchObject({ kind: "posix-best-effort", crashSafe: false, helperPid: null });
    expect(POSIX_BEST_EFFORT_LIMITATION).toContain("Daemonized descendants");
  });

  it("never signals a reused root pid", async () => {
    const procs: Record<number, { stat: string }> = { 10: { stat: stat(10, { ppid: 1, pgrp: 10, start: 500 }) } };
    const signals: number[] = [];
    const api: PosixProcessApi = {
      fs: fakeProc(procs),
      kill: (pid) => void signals.push(pid),
      now: () => 0,
      sleep: async () => {},
    };
    const captured = await BestEffortOwnership.capture(10, api);
    if (!captured.ok) throw new Error("capture failed");
    procs[10] = { stat: stat(10, { ppid: 1, pgrp: 10, start: 900 }) };
    expect(await captured.value.kill()).toMatchObject({ rootVerified: false, killed: [], rootGone: true });
    expect(signals).toEqual([]);
  });
});
