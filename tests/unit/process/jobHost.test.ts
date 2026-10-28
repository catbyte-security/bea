import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import type { BeaApplication } from "../../../src/application/BeaApplication.js";
import { Deadline } from "../../../src/domain/deadline.js";
import type { JobHostEvent } from "../../../src/domain/jobhostProtocol.js";
import type { AdoptRequest, JobHostPort } from "../../../src/ports/jobhost.js";
import { JobHostService } from "../../../src/providers/process/JobHostService.js";
import { testCore, writeFakeBinary } from "./support/core.js";
import { createFakeLauncher, POLICY, scriptAdopt, type FakeHelperChild } from "./support/fakeHelper.js";

let dir: string;
let binary: { exePath: string; manifestPath: string };
let core: BeaApplication;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "bea-wp2-jobhost-"));
  binary = await writeFakeBinary(dir);
  core = await testCore("win32");
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

const adoptReq = (over: Partial<AdoptRequest> = {}): AdoptRequest => ({
  pid: 1234,
  creationTime100ns: 133000000000000000n,
  tolerance100ns: 10n,
  expectImage: "C:\\t\\target.exe",
  expectParentPid: process.pid,
  deadline: Deadline.after(2000),
  ...over,
});

const service = (onLaunch: (child: FakeHelperChild) => void) => {
  const launcher = createFakeLauncher(onLaunch);
  return { launcher, jobhost: new JobHostService(core, { ...binary, launch: launcher.launch, platform: "win32" }) };
};

const adopted = async (onLaunch: (child: FakeHelperChild) => void = (c) => scriptAdopt(c)) => {
  const { launcher, jobhost } = service(onLaunch);
  const result = await jobhost.adopt(adoptReq());
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return { launcher, jobhost, handle: result.value, child: launcher.last() };
};

describe("JobHostPort over a fake helper (S3 §5.7)", () => {
  it("launches adopt with the S3 argv and stdio, and exposes the adopted facts", async () => {
    const { handle, child, jobhost } = await adopted();
    expect(child.args).toEqual([
      "adopt",
      "1234",
      "133000000000000000",
      "--tolerance-100ns",
      "10",
      "--expect-image",
      "C:\\t\\target.exe",
      "--expect-parent",
      String(process.pid),
    ]);
    expect(child.options).toMatchObject({
      stdio: ["pipe", "ignore", "pipe", "pipe"],
      detached: false,
      windowsHide: true,
      shell: false,
    });
    expect(Object.keys(child.options.env ?? {})).toEqual(["SystemRoot"]);
    expect(handle).toMatchObject({
      helperPid: child.pid,
      rootPid: 1234,
      wasInJob: true,
      state: "contained",
      lastActive: 1,
    });
    expect(handle.creationTime100ns).toBe(133000000000000000n);
    expect(handle.policy).toEqual(POLICY);
    expect(handle.stdin).toBeNull();
    expect(jobhost.live.owned).toBe(1);
    await handle.kill("close-session", 2000);
    expect(jobhost.live.owned).toBe(0);
  });

  it("kill() writes kill + EOF, settles from the helper's events and is memoized", async () => {
    const { handle, child } = await adopted();
    const seen: string[] = [];
    handle.on((e: JobHostEvent) => seen.push(e.event));
    const [a, b] = await Promise.all([handle.kill("close-session", 2000), handle.kill("server-shutdown", 10)]);
    expect(a).toBe(b);
    expect(child.control).toEqual(["kill", "<eof>"]);
    expect(child.killed).toBe(false);
    expect(a).toMatchObject({
      method: "control-kill",
      observation: "observed-zero-active",
      activeBefore: 2,
      active: 0,
      peakJobMemoryBytes: 4096,
      helperExitCode: 0xbea,
      outputComplete: true,
    });
    expect(seen).toEqual(["killed", "root-exit", "settled"]);
    expect(handle.state).toBe("settled");
    expect(handle.rootExit).toMatchObject({ code: 0xbea, byKill: true, activeAfterRoot: 0 });
    expect(await handle.settled).toBe(a);
    expect(await handle.kill("close-session", 1)).toBe(a);
  });

  it("escalates to TerminateProcess(helper) when the helper does not settle in time", async () => {
    const { handle, child } = await adopted((c) => scriptAdopt(c, { respond: false }));
    const settlement = await handle.kill("server-shutdown", 30);
    expect(child.killed).toBe(true);
    expect(settlement).toMatchObject({
      method: "helper-terminated",
      observation: "kernel-enforced-unobserved",
      active: null,
      helperExitCode: null,
    });
    expect(handle.state).toBe("settled");
  });

  it("escalateAfterMs 0 terminates the helper immediately", async () => {
    const { handle, child } = await adopted((c) => scriptAdopt(c, { respond: false }));
    const settlement = await handle.kill("startup-failed", 0);
    expect(child.killed).toBe(true);
    expect(settlement.method).toBe("helper-terminated");
  });

  it("synthesizes a settlement when even the terminated helper never reports its exit", async () => {
    const { handle, child } = await adopted((c) => {
      scriptAdopt(c, { respond: false });
      c.onKill = () => {};
    });
    const settlement = await handle.kill("server-shutdown", 1);
    expect(child.killed).toBe(true);
    expect(settlement).toMatchObject({ method: "helper-terminated", outputComplete: false, helperExitCode: null });
  });

  it("reports helper-lost when the helper exits without settling and without a kill", async () => {
    const { handle, child } = await adopted((c) => scriptAdopt(c, { respond: false }));
    child.exit(null, "SIGTERM");
    const settlement = await handle.settled;
    expect(handle.state).toBe("helper-lost");
    expect(settlement).toMatchObject({ method: "helper-terminated", observation: "kernel-enforced-unobserved" });
  });

  it("tracks a natural root exit, stragglers and status lines", async () => {
    const { handle, child } = await adopted((c) => scriptAdopt(c, { respond: false }));
    child.line({ event: "proc-start", pid: 99 });
    child.line({
      event: "root-exit",
      pid: 1234,
      code: 0xc0000005,
      codeHex: "0xC0000005",
      activeAfterRoot: 2,
      byKill: false,
    });
    await vi.waitFor(() => expect(handle.state).toBe("root-exited"), { interval: 5 });
    expect(handle.rootExit).toMatchObject({
      code: 0xc0000005,
      codeHex: "0xC0000005",
      byKill: false,
      activeAfterRoot: 2,
    });
    handle.requestStatus();
    await vi.waitFor(() => expect(child.control).toContain("status"), { interval: 5 });
    child.line({ event: "status", rootAlive: false, active: 1, elapsedMs: 50 });
    await vi.waitFor(() => expect(handle.lastActive).toBe(1), { interval: 5 });
    child.line({ event: "settled", active: 0, timedOut: false, peakJobMemoryBytes: 0, elapsedMs: 60 });
    child.exit(0xc0000005);
    expect(await handle.settled).toMatchObject({
      method: "natural",
      observation: "observed-zero-active",
      helperExitCode: 0xc0000005,
    });
  });

  it("terminates the helper on a protocol violation after start and reports failed", async () => {
    const { handle, child } = await adopted((c) => scriptAdopt(c, { respond: false }));
    child.line('{"event":"root-exit","pid":"nope"}');
    const settlement = await handle.settled;
    expect(child.killed).toBe(true);
    expect(handle.state).toBe("failed");
    expect(settlement.method).toBe("helper-terminated");
  });

  it("a throwing listener does not break event delivery", async () => {
    const { handle, child } = await adopted((c) => scriptAdopt(c, { respond: false }));
    const seen: string[] = [];
    handle.on(() => {
      throw new Error("bad listener");
    });
    const off = handle.on((e) => seen.push(e.event));
    child.line({ event: "proc-start", pid: 1 });
    await vi.waitFor(() => expect(seen).toEqual(["proc-start"]), { interval: 5 });
    off();
    child.line({ event: "proc-start", pid: 2 });
    await handle.kill("close-session", 5);
    expect(seen).toEqual(["proc-start"]);
  });
});

describe("start failures (S3 §5.7 error table)", () => {
  const failing = async (onLaunch: (child: FakeHelperChild) => void, req: Partial<AdoptRequest> = {}) => {
    const { jobhost, launcher } = service(onLaunch);
    const result = await jobhost.adopt(adoptReq(req));
    expect(result.ok).toBe(false);
    return { error: result.ok ? null : result.error, child: launcher.last(), jobhost };
  };

  it("identity refusal → instance_mismatch, the helper exits on its own", async () => {
    const { error, child, jobhost } = await failing((c) =>
      setImmediate(() => {
        c.hello();
        c.line({ event: "error", stage: "identity", win32: 0, detail: "creation-time", expected: "1", actual: "2" });
        c.exit(0xbea3);
      }),
    );
    expect(error).toMatchObject({ _tag: "InstanceMismatch", observed: { pid: 1234, start_time: "2" } });
    expect(child.killed).toBe(false);
    expect(jobhost.live.owned).toBe(0);
  });

  it("exit before the decisive event → execution_failure with the exit code", async () => {
    const { error } = await failing((c) =>
      setImmediate(() => {
        c.hello();
        c.exit(0xbea4);
      }),
    );
    expect(error).toMatchObject({
      _tag: "ProviderFailure",
      diagnostics: { reason: "helper-exited-early", helper_exit_code: 0xbea4 },
    });
  });

  it("deadline → provider_timeout and the helper is terminated (kernel kills anything adopted)", async () => {
    const { error, child } = await failing((c) => setImmediate(() => c.hello()), { deadline: Deadline.after(30) });
    expect(error).toMatchObject({ _tag: "ProviderTimeout", phase: "jobhost-adopt" });
    expect(child.killed).toBe(true);
  });

  it("caller abort → cancelled and the helper is terminated", async () => {
    const controller = new AbortController();
    const { error, child } = await failing(
      (c) =>
        setImmediate(() => {
          c.hello();
          controller.abort(new Error("caller"));
        }),
      { signal: controller.signal },
    );
    expect(error).toMatchObject({ _tag: "Cancelled", by: "signal" });
    expect(child.killed).toBe(true);
  });

  it("wrong hello mode, a foreign decisive event and protocol 2 are refused", async () => {
    const wrongMode = await failing((c) => setImmediate(() => c.hello("watch")));
    expect(wrongMode.error).toMatchObject({ _tag: "ProviderFailure", diagnostics: { reason: "protocol-violation" } });
    expect(wrongMode.child.killed).toBe(true);
    const foreign = await failing((c) =>
      setImmediate(() => {
        c.hello();
        c.line({ event: "watching", pid: 1, creationTime100ns: "1", imagePath: null });
      }),
    );
    expect(foreign.error).toMatchObject({ _tag: "ProviderFailure" });
    const v2 = await failing((c) =>
      setImmediate(() =>
        c.line({
          event: "hello",
          protocol: 2,
          version: "9",
          mode: "adopt",
          helperPid: c.pid,
          helperInJob: false,
          statusFd3: true,
        }),
      ),
    );
    expect(v2.error).toMatchObject({
      _tag: "CapabilityUnavailable",
      capability: "jobhost",
      reason: "protocol-mismatch",
    });
  });

  it("a launch failure (ENOENT) → capability_unavailable(binary-missing)", async () => {
    const svc = new JobHostService(core, {
      ...binary,
      platform: "win32",
      launch: () => {
        throw Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" });
      },
    });
    const result = await svc.adopt(adoptReq());
    expect(result).toMatchObject({ ok: false, error: { _tag: "CapabilityUnavailable", reason: "binary-missing" } });
  });

  it("invalid requests never launch a helper", async () => {
    const { jobhost, launcher } = service(() => {});
    const result = await jobhost.adopt(adoptReq({ pid: -5 }));
    expect(result).toMatchObject({ ok: false, error: { _tag: "InputError" } });
    expect(launcher.children).toHaveLength(0);
  });
});

describe("spawn mode and the watcher", () => {
  it("spawn passes target stdio through, resumes a suspended root and waits for output close", async () => {
    const { jobhost, launcher } = service((c) =>
      setImmediate(() => {
        c.hello();
        c.line({
          event: "started",
          pid: 77,
          tid: 78,
          creationTime100ns: "5",
          suspended: true,
          imagePath: "C:\\b\\py.exe",
          policy: { ...POLICY, memLimitBytes: 4096 },
        });
        c.onControl = (line) => {
          if (line === "resume") c.line({ event: "resumed", previousSuspendCount: 1 });
        };
      }),
    );
    const result = await jobhost.spawn({
      exe: "C:\\b\\py.exe",
      args: ["-I"],
      cwd: "C:\\w",
      env: { SystemRoot: "C:\\Windows", BEA_X: "1" },
      suspended: true,
      stdin: "pipe",
      killOnRootExit: true,
      memLimitBytes: 4096,
      deadline: Deadline.after(2000),
    });
    if (!result.ok) throw new Error(JSON.stringify(result.error));
    const handle: JobHostPort = result.value;
    const child = launcher.last();
    expect(child.options).toMatchObject({
      stdio: ["pipe", "pipe", "pipe", "pipe", "pipe"],
      cwd: "C:\\w",
      env: { SystemRoot: "C:\\Windows", BEA_X: "1" },
    });
    expect(handle.stdin).toBe(child.stdio[4]);
    expect(handle.stdout).toBe(child.stdio[1]);
    expect(handle.resume()).toEqual({ ok: true, value: undefined });
    await vi.waitFor(() => expect(handle.resume().ok).toBe(false), { interval: 5 });
    handle.stdout?.resume();
    handle.stderr?.resume();
    child.line({ event: "root-exit", pid: 77, code: 0, codeHex: "0x00000000", activeAfterRoot: 0, byKill: false });
    child.line({ event: "settled", active: 0, timedOut: false, peakJobMemoryBytes: 1, elapsedMs: 2 });
    child.exit(0);
    expect(await handle.settled).toMatchObject({ method: "natural", outputComplete: true, helperExitCode: 0 });
  });

  it("resume is refused outside spawn --suspended", async () => {
    const { handle } = await adopted();
    expect(handle.resume()).toMatchObject({ ok: false, error: { _tag: "InvalidState" } });
    await handle.kill("close-session", 100);
  });

  it("watch: stop() is EOF only; exited resolves with the root exit or null", async () => {
    const watchScript = (c: FakeHelperChild) =>
      setImmediate(() => {
        c.hello();
        c.line({ event: "watching", pid: 50, creationTime100ns: "9", imagePath: null });
        c.onControl = (line) => {
          if (line === "<eof>") {
            c.line({ event: "watch-ended", reason: "eof" });
            c.exit(0);
          }
        };
      });
    const { jobhost, launcher } = service(watchScript);
    const watched = await jobhost.watch({
      pid: 50,
      creationTime100ns: 9n,
      tolerance100ns: 0n,
      deadline: Deadline.after(2000),
    });
    if (!watched.ok) throw new Error(JSON.stringify(watched.error));
    expect(launcher.last().args).toEqual(["watch", "50", "9", "--tolerance-100ns", "0"]);
    expect(watched.value).toMatchObject({ pid: 50, creationTime100ns: 9n, imagePath: null });
    expect(jobhost.live.watchers).toBe(1);
    await watched.value.stop();
    expect(launcher.last().control).toEqual(["<eof>"]);
    expect(launcher.last().killed).toBe(false);
    expect(await watched.value.exited).toBeNull();
    expect(jobhost.live.watchers).toBe(0);

    const second = await jobhost.watch({
      pid: 50,
      creationTime100ns: 9n,
      tolerance100ns: 0n,
      deadline: Deadline.after(2000),
    });
    if (!second.ok) throw new Error("watch failed");
    launcher
      .last()
      .line({ event: "root-exit", pid: 50, code: 3, codeHex: "0x00000003", activeAfterRoot: null, byKill: false });
    launcher.last().exit(0);
    expect(await second.value.exited).toMatchObject({ code: 3, byKill: false, activeAfterRoot: null });
  });
});
