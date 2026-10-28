import { spawn, type SpawnOptions } from "node:child_process";
import type { Readable, Writable } from "node:stream";

import { composeSignal } from "../../domain/abort.js";
import type { Deadline } from "../../domain/deadline.js";
import type { BeaError } from "../../domain/errors/beaError.js";
import type { JobHostEvent } from "../../domain/jobhostProtocol.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  helperExitedEarlyError,
  helperLaunchError,
  mapHelperError,
  protocolViolationError,
  startAbortedError,
  type HelperErrorEvent,
  type HelperRequestFacts,
} from "./jobhostErrors.js";
import { createStatusLineParser, type StatusLineParser, type StatusViolation } from "./statusLines.js";

/**
 * One bea-jobhost process and its protocol-1 conversation (S3 §5.2–§5.3, §5.7): launch, `hello` check, the mode's
 * decisive event, event fan-out, control lines and exit tracking. JobHostHandle (adopt/spawn), ProcessWatcher (watch)
 * and the one-shot modes (inspect, probe, version) are built on it.
 *
 * Launch rules (S3 §5.7, VERIFIED): never detached, so the helper stays in libuv's kill-on-close job (Node death →
 * helper death → the kernel closes the target job); never unref'd; status on fd3; stderr kept as a bounded
 * diagnostics tail outside spawn mode. Listeners run inline, O(1), and their exceptions are swallowed.
 */
export type HelperMode = "adopt" | "spawn" | "watch" | "inspect" | "probe" | "version";
type DecisiveEventName = "adopted" | "started" | "watching" | "inspect" | "probe" | "hello";
export type JobHostEventOf<N extends JobHostEvent["event"]> = Extract<JobHostEvent, { readonly event: N }>;

const DECISIVE_EVENT: { readonly [M in HelperMode]: DecisiveEventName } = {
  adopt: "adopted",
  spawn: "started",
  watch: "watching",
  inspect: "inspect",
  probe: "probe",
  version: "hello",
};
const DECISIVE_NAMES: ReadonlySet<string> = new Set(["adopted", "started", "watching", "inspect", "probe"]);

/** How long after the helper's exit the status channel and (spawn) target output may take to close. */
const CHANNEL_CLOSE_CAP_MS = 1000;
const STDERR_DIAGNOSTICS_BYTES = 4096;

/** The subset of ChildProcess the session uses (fakes implement it in unit tests). */
export interface HelperChild {
  readonly pid?: number | undefined;
  readonly stdio: readonly (Readable | Writable | null | undefined)[];
  kill(signal?: NodeJS.Signals | number): boolean;
  on(event: "exit", listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  on(event: "error", listener: (error: Error) => void): unknown;
}
export type LaunchHelper = (file: string, args: readonly string[], options: SpawnOptions) => HelperChild;

export const launchHelperProcess: LaunchHelper = (file, args, options) => spawn(file, [...args], options);

export interface SpawnModeStdio {
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly stdinPipe: boolean;
}

/** S3 §5.7 child options: identical for every mode apart from stdio, cwd and env. */
const helperSpawnOptions = (spawnMode: SpawnModeStdio | null, systemRoot: string): SpawnOptions =>
  spawnMode === null
    ? {
        stdio: ["pipe", "ignore", "pipe", "pipe"],
        detached: false,
        windowsHide: true,
        shell: false,
        env: { SystemRoot: systemRoot },
      }
    : {
        stdio: spawnMode.stdinPipe ? ["pipe", "pipe", "pipe", "pipe", "pipe"] : ["pipe", "pipe", "pipe", "pipe"],
        detached: false,
        windowsHide: true,
        shell: false,
        cwd: spawnMode.cwd,
        env: { ...spawnMode.env },
      };

export interface HelperExit {
  readonly code: number | null;
  readonly signal: string | null;
  /** false when the status channel had not ended CHANNEL_CLOSE_CAP_MS after the exit */
  readonly statusComplete: boolean;
}

type Decision =
  | { readonly kind: "decisive"; readonly event: JobHostEvent }
  | { readonly kind: "error"; readonly event: HelperErrorEvent }
  | { readonly kind: "violation"; readonly violation: StatusViolation }
  | { readonly kind: "exited" }
  | { readonly kind: "launch-error"; readonly cause: unknown };

const noop = (): void => {};

export interface HelperSessionOptions {
  readonly binaryPath: string;
  readonly mode: HelperMode;
  /** argv after the executable, starting with the mode word */
  readonly args: readonly string[];
  readonly spawnMode: SpawnModeStdio | null;
  readonly launch: LaunchHelper;
  readonly systemRoot: string;
}

export class HelperSession {
  readonly mode: HelperMode;
  readonly finished: Promise<HelperExit>;
  /** spawn mode: true when the target's stdout and stderr both closed in time; other modes: true */
  readonly outputClosed: Promise<boolean>;

  readonly #child: HelperChild | null;
  readonly #listeners = new Set<(event: JobHostEvent) => void>();
  readonly #violationListeners = new Set<(violation: StatusViolation) => void>();
  readonly #parser: StatusLineParser;
  #decide: (decision: Decision) => void = noop;
  readonly #decision: Promise<Decision>;
  #hello: JobHostEventOf<"hello"> | null = null;
  #decisive: JobHostEvent | null = null;
  #violation: StatusViolation | null = null;
  #exit: { code: number | null; signal: string | null } | null = null;
  #stderr = "";
  #terminated = false;

  constructor(options: HelperSessionOptions) {
    this.mode = options.mode;
    this.#decision = new Promise<Decision>((resolve) => {
      this.#decide = (decision) => {
        this.#decide = noop;
        resolve(decision);
      };
    });
    this.#parser = createStatusLineParser({
      onEvent: (event) => this.#onEvent(event),
      onViolation: (violation) => this.#onViolation(violation),
    });
    let child: HelperChild | null = null;
    let launchError: unknown = null;
    try {
      child = options.launch(
        options.binaryPath,
        options.args,
        helperSpawnOptions(options.spawnMode, options.systemRoot),
      );
    } catch (cause) {
      launchError = cause;
    }
    this.#child = child;
    let resolveFinished: (exit: HelperExit) => void = noop;
    this.finished = new Promise<HelperExit>((resolve) => {
      resolveFinished = resolve;
    });
    if (child === null) {
      this.#decide({ kind: "launch-error", cause: launchError });
      this.outputClosed = Promise.resolve(true);
      resolveFinished({ code: null, signal: null, statusComplete: true });
      return;
    }
    this.outputClosed = this.#wire(child, options.spawnMode !== null, resolveFinished);
  }

  get helperPid(): number {
    return this.#hello?.helperPid ?? this.#child?.pid ?? 0;
  }
  get hello(): JobHostEventOf<"hello"> | null {
    return this.#hello;
  }
  get exit(): { readonly code: number | null; readonly signal: string | null } | null {
    return this.#exit;
  }
  get violation(): StatusViolation | null {
    return this.#violation;
  }
  /** The helper was terminated by BEA (TerminateProcess), not by its own protocol. */
  get terminated(): boolean {
    return this.#terminated;
  }
  /** Bounded stderr text of non-spawn modes (diagnostics only; never shown verbatim to callers). */
  get stderrTail(): string {
    return this.#stderr;
  }
  stream(fd: number): Readable | Writable | null {
    return this.#child?.stdio[fd] ?? null;
  }

  /** Every validated status event, in order; returns the unsubscribe function. */
  subscribe(listener: (event: JobHostEvent) => void): () => void {
    this.#listeners.add(listener);
    return () => void this.#listeners.delete(listener);
  }
  onViolation(listener: (violation: StatusViolation) => void): () => void {
    this.#violationListeners.add(listener);
    return () => void this.#violationListeners.delete(listener);
  }

  /** Write one control line (`kill`, `resume`, `status`); false when the control pipe is gone. */
  sendControl(command: "kill" | "resume" | "status"): boolean {
    const control = this.#child?.stdio[0] as Writable | null | undefined;
    if (control === null || control === undefined || control.destroyed || control.writableEnded) return false;
    control.write(`${command}\n`);
    return true;
  }

  /** EOF on the control pipe: adopt/spawn kill the job ("eof"), watch stops watching. Idempotent. */
  endControl(): void {
    const control = this.#child?.stdio[0] as Writable | null | undefined;
    if (control !== null && control !== undefined && !control.destroyed && !control.writableEnded) control.end();
  }

  /** TerminateProcess on the helper. adopt/spawn: the kernel closes the last job handle and kills the tree. */
  terminate(): void {
    if (this.#exit !== null || this.#child === null) return;
    this.#terminated = true;
    try {
      this.#child.kill();
    } catch {
      // already gone
    }
  }

  /**
   * Resolve on the mode's decisive event; fail on an `error` line, a protocol violation, the helper's exit, the
   * deadline or an abort. On deadline/abort the helper is terminated: for adopt/spawn the kernel then kills whatever
   * was already contained, which is the correct cleanup of an owned startup (S3 §5.7).
   */
  async waitDecisive(
    operation: string,
    deadline: Deadline,
    signal: AbortSignal | undefined,
    facts: HelperRequestFacts,
  ): Promise<Result<JobHostEvent, BeaError>> {
    const composed = composeSignal(signal === undefined ? [deadline.signal()] : [deadline.signal(), signal]);
    try {
      const aborted = new Promise<{ readonly kind: "aborted"; readonly reason: unknown }>((resolve) => {
        if (composed.signal.aborted) resolve({ kind: "aborted", reason: composed.signal.reason });
        else
          composed.signal.addEventListener(
            "abort",
            () => resolve({ kind: "aborted", reason: composed.signal.reason }),
            {
              once: true,
            },
          );
      });
      const decision = await Promise.race([this.#decision, aborted]);
      switch (decision.kind) {
        case "decisive":
          return ok(decision.event);
        case "error":
          return err(mapHelperError(operation, decision.event, facts));
        case "violation":
          return err(protocolViolationError(operation, decision.violation));
        case "launch-error":
          return err(helperLaunchError(operation, decision.cause));
        case "exited":
          return err(
            helperExitedEarlyError(operation, {
              code: this.#exit?.code ?? null,
              signal: this.#exit?.signal ?? null,
              stderr: this.#stderr,
            }),
          );
        case "aborted":
          this.terminate();
          return err(startAbortedError(operation, decision.reason, deadline.budgetMs, `jobhost-${this.mode}`));
      }
    } finally {
      composed.dispose();
    }
  }

  #wire(child: HelperChild, spawnMode: boolean, resolveFinished: (exit: HelperExit) => void): Promise<boolean> {
    for (const stream of child.stdio) stream?.on("error", noop);
    const status = child.stdio[3] as Readable | null | undefined;
    let statusEnded = status === null || status === undefined;
    let exited = false;
    let capTimer: ReturnType<typeof setTimeout> | null = null;
    const tryFinish = (capped: boolean): void => {
      if (!exited || (!statusEnded && !capped)) return;
      if (capTimer !== null) clearTimeout(capTimer);
      capTimer = null;
      if (!this.#hasDecision()) this.#decide({ kind: "exited" });
      resolveFinished({ code: this.#exit?.code ?? null, signal: this.#exit?.signal ?? null, statusComplete: !capped });
    };
    if (status !== null && status !== undefined) {
      status.on("data", (chunk: Buffer) => {
        if (this.#violation === null) this.#parser.push(chunk);
      });
      const ended = (): void => {
        if (statusEnded) return;
        statusEnded = true;
        // A partial last line is a violation only while the helper runs its own protocol (not after TerminateProcess).
        if (this.#violation === null && !this.#terminated) this.#parser.end();
        tryFinish(false);
      };
      status.on("end", ended);
      status.on("close", ended);
    }
    if (!spawnMode) {
      const diagnostics = child.stdio[2] as Readable | null | undefined;
      diagnostics?.on("data", (chunk: Buffer) => {
        if (this.#stderr.length < STDERR_DIAGNOSTICS_BYTES)
          this.#stderr = (this.#stderr + chunk.toString("utf8")).slice(0, STDERR_DIAGNOSTICS_BYTES);
      });
    }
    child.on("error", (cause) => {
      if (child.pid === undefined && !exited) {
        exited = true;
        statusEnded = true;
        this.#decide({ kind: "launch-error", cause });
        tryFinish(false);
      }
    });
    child.on("exit", (code, signal) => {
      exited = true;
      this.#exit = { code, signal };
      capTimer = setTimeout(() => tryFinish(true), CHANNEL_CLOSE_CAP_MS);
      tryFinish(false);
    });
    return spawnMode ? this.#outputClosed(child) : Promise.resolve(true);
  }

  async #outputClosed(child: HelperChild): Promise<boolean> {
    const closed = (fd: 1 | 2): Promise<void> =>
      new Promise((resolve) => {
        const stream = child.stdio[fd];
        if (stream === null || stream === undefined || stream.closed) resolve();
        else stream.once("close", () => resolve());
      });
    const both = Promise.all([closed(1), closed(2)]).then(() => true);
    await this.finished;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const cap = new Promise<boolean>((resolve) => {
      timer = setTimeout(() => resolve(false), CHANNEL_CLOSE_CAP_MS);
    });
    const result = await Promise.race([both, cap]);
    if (timer !== null) clearTimeout(timer);
    return result;
  }

  #hasDecision(): boolean {
    return this.#decide === noop;
  }

  #onEvent(event: JobHostEvent): void {
    if (this.#violation !== null) return;
    if (this.#hello === null) {
      const pid = this.#child?.pid;
      if (event.event !== "hello" || event.mode !== this.mode || (pid !== undefined && event.helperPid !== pid)) {
        this.#onViolation({ kind: "schema", event: event.event });
        return;
      }
      this.#hello = event;
      if (this.mode === "version") {
        this.#decisive = event;
        this.#decide({ kind: "decisive", event });
      }
    } else if (event.event === "hello" || (DECISIVE_NAMES.has(event.event) && this.#decisive !== null)) {
      this.#onViolation({ kind: "schema", event: event.event });
      return;
    } else if (DECISIVE_NAMES.has(event.event)) {
      if (event.event !== DECISIVE_EVENT[this.mode]) {
        this.#onViolation({ kind: "schema", event: event.event });
        return;
      }
      this.#decisive = event;
      this.#decide({ kind: "decisive", event });
    } else if (event.event === "error" && this.#decisive === null) {
      this.#decide({ kind: "error", event });
    }
    for (const listener of this.#listeners) {
      try {
        listener(event);
      } catch {
        // listeners must not throw (S3 §16 rule 10); a faulty one cannot break the channel
      }
    }
  }

  #onViolation(violation: StatusViolation): void {
    if (this.#violation !== null || this.#exit !== null) return;
    this.#violation = violation;
    this.#decide({ kind: "violation", violation });
    this.terminate();
    for (const listener of this.#violationListeners) {
      try {
        listener(violation);
      } catch {
        // see #onEvent
      }
    }
  }
}
