import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";

import type { SpawnOptions } from "node:child_process";

import type { HelperChild, LaunchHelper } from "../../../../src/providers/process/JobHostSession.js";

/**
 * Scriptable stand-in for a bea-jobhost child process (WP2 unit tests). Status lines go out on fd3, control lines
 * written by the wrapper are collected from fd0, `exit()` ends the channels the way Node reports a real exit.
 */
let nextPid = 40_000;

export class FakeHelperChild extends EventEmitter implements HelperChild {
  readonly pid: number | undefined;
  readonly stdio: (PassThrough | null)[];
  readonly control: string[] = [];
  readonly args: readonly string[];
  readonly options: SpawnOptions;
  killed = false;
  exited = false;
  /** Called for every complete control line; scripts react here. */
  onControl: ((line: string) => void) | null = null;
  /** What kill() does: by default the helper dies at once (TerminateProcess). */
  onKill: () => void = () => this.exit(null, "SIGTERM");
  #controlBuffer = "";

  constructor(args: readonly string[], options: SpawnOptions, pid: number | undefined = nextPid++) {
    super();
    this.pid = pid;
    this.args = args;
    this.options = options;
    const stdio = options.stdio as readonly string[];
    this.stdio = stdio.map((kind) => (kind === "pipe" ? new PassThrough() : null));
    this.stdio[0]?.on("data", (chunk: Buffer) => {
      this.#controlBuffer += chunk.toString("utf8");
      let nl = this.#controlBuffer.indexOf("\n");
      while (nl !== -1) {
        const line = this.#controlBuffer.slice(0, nl);
        this.#controlBuffer = this.#controlBuffer.slice(nl + 1);
        this.control.push(line);
        this.onControl?.(line);
        nl = this.#controlBuffer.indexOf("\n");
      }
    });
    this.stdio[0]?.on("end", () => {
      this.control.push("<eof>");
      this.onControl?.("<eof>");
    });
  }

  get mode(): string {
    return this.args[0] ?? "";
  }

  /** Write one status line (any value: tests also send invalid ones). */
  line(value: unknown): void {
    if (this.exited) return;
    this.stdio[3]?.write(`${typeof value === "string" ? value : JSON.stringify(value)}\n`);
  }

  raw(text: string): void {
    this.stdio[3]?.write(text);
  }

  hello(mode = this.mode): void {
    this.line({
      event: "hello",
      protocol: 1,
      version: "0.1.0",
      mode,
      helperPid: this.pid,
      helperInJob: true,
      statusFd3: true,
    });
  }

  /** The process exits: Node emits 'exit', then the pipes end. */
  exit(code: number | null, signal: NodeJS.Signals | null = null): void {
    if (this.exited) return;
    this.exited = true;
    queueMicrotask(() => {
      this.emit("exit", code, signal);
      for (const [fd, stream] of this.stdio.entries()) if (fd !== 0 && fd !== 4) stream?.end();
    });
  }

  kill(): boolean {
    this.killed = true;
    if (!this.exited) this.onKill();
    return true;
  }
}

export interface FakeLauncher {
  readonly launch: LaunchHelper;
  readonly children: FakeHelperChild[];
  /** Runs synchronously for each new child (before the wrapper subscribes; emit lines asynchronously). */
  onLaunch: (child: FakeHelperChild) => void;
  last(): FakeHelperChild;
}

export const createFakeLauncher = (onLaunch: (child: FakeHelperChild) => void = () => {}): FakeLauncher => {
  const fake: FakeLauncher = {
    children: [],
    onLaunch,
    launch: (_file, args, options) => {
      const child = new FakeHelperChild(args, options);
      fake.children.push(child);
      fake.onLaunch(child);
      return child;
    },
    last: () => {
      const child = fake.children.at(-1);
      if (child === undefined) throw new Error("no helper launched");
      return child;
    },
  };
  return fake;
};

export const POLICY = {
  killOnClose: true,
  dieOnUnhandledException: true,
  breakawayAllowed: false,
  memLimitBytes: null,
};

/** A helper that adopts like bea-jobhost: hello, adopted, then honours kill/EOF with killed → root-exit → settled. */
export const scriptAdopt = (
  child: FakeHelperChild,
  opts: { readonly pid?: number; readonly respond?: boolean } = {},
) => {
  const pid = opts.pid ?? 1234;
  setImmediate(() => {
    child.hello();
    child.line({
      event: "adopted",
      pid,
      creationTime100ns: "133000000000000000",
      wasInJob: true,
      imagePath: "C:\\t\\target.exe",
      active: 1,
      policy: POLICY,
    });
  });
  if (opts.respond === false) return;
  child.onControl = (line) => {
    if (line !== "kill" && line !== "<eof>") return;
    if (child.exited) return;
    const reason = line === "kill" ? "control" : "eof";
    child.line({ event: "killed", reason, activeBefore: 2, ok: true, win32: 0 });
    child.line({ event: "root-exit", pid, code: 0xbea, codeHex: "0x00000BEA", activeAfterRoot: 0, byKill: true });
    child.line({ event: "settled", active: 0, timedOut: false, peakJobMemoryBytes: 4096, elapsedMs: 10 });
    child.exit(0xbea);
  };
};
