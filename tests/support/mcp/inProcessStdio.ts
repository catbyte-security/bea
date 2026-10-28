import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";

import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";

import type { BeaCore } from "../../../src/application/BeaApplication.js";
import type { BeaServices } from "../../../src/application/services/index.js";
import { HARD_LIMITS } from "../../../src/domain/config.js";
import { runStdio, type StdioRuntimeDeps } from "../../../src/main/mcpStdio.js";
import { registerProcessShutdown, type ShutdownSignal } from "../../../src/main/processShutdown.js";
import { fakeServices } from "../fakes/fakeServices.js";
import { createTempHome, type TempHome } from "../workspace/tempHome.js";

/**
 * The production stdio entry (runStdio) in-process over PassThrough streams (rea-testing §4.4): the real
 * StdioServerTransport (maxBufferSize as in production), serveStdio, the lifecycle and the shutdown wiring, with the
 * process-level hooks (exit code, hard-exit timer, signals, stdin) observable instead of acting on the test process.
 */
export interface JsonRpcMessage {
  readonly jsonrpc: "2.0";
  readonly id?: number | string | null;
  readonly method?: string;
  readonly params?: unknown;
  readonly result?: Readonly<Record<string, unknown>>;
  readonly error?: { readonly code: number; readonly message: string; readonly data?: unknown };
}

export interface InProcessStdioOptions {
  readonly services?: Partial<BeaServices> | ((core: BeaCore) => Promise<BeaServices>);
  /** Server environment; BEA_HOME is a temp dir and BEA_LOG_LEVEL defaults to silent (logs go to process.stderr). */
  readonly env?: Readonly<Record<string, string>>;
  readonly maxBufferSize?: number;
}

export interface InProcessStdio {
  readonly home: TempHome;
  /** Writes one message as a JSON line. */
  readonly send: (message: Readonly<Record<string, unknown>>) => void;
  /** Writes raw text (a line must end with \n). */
  readonly sendRaw: (text: string) => void;
  /** Sends a request with the next id and resolves with its response. */
  readonly request: (
    method: string,
    params?: Readonly<Record<string, unknown>>,
    timeoutMs?: number,
  ) => Promise<JsonRpcMessage>;
  /** Allocates the id a hand-built request should use (keeps request() ids unique). */
  readonly nextId: () => number;
  /** Resolves with the response to `id`. */
  readonly response: (id: number, timeoutMs?: number) => Promise<JsonRpcMessage>;
  /** initialize + notifications/initialized. */
  readonly initialize: () => Promise<JsonRpcMessage>;
  /** Every parsed stdout message so far. */
  readonly messages: () => readonly JsonRpcMessage[];
  /** Every setExitCode call, in order (the first is the provisional code at the first shutdown trigger). */
  readonly exitCodes: () => readonly number[];
  /** Every forceExitAfterMs call (armed at the first trigger, then after cleanup). */
  readonly hardExits: () => readonly { readonly code: number | null; readonly ms: number }[];
  readonly stderr: () => string;
  readonly raiseSignal: (signal: ShutdownSignal) => void;
  /** Ends stdin (the stdio client went away) and waits for the shutdown to finish; returns the final exit code. */
  readonly endStdin: (timeoutMs?: number) => Promise<number | null>;
  /** Resolves with the final exit code once cleanup armed the 500 ms hard exit. */
  readonly shutdownDone: (timeoutMs?: number) => Promise<number | null>;
}

const withTimeout = <T>(promise: Promise<T>, ms: number, what: string): Promise<T> =>
  new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out after ${ms} ms waiting for ${what}`)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (cause: unknown) => {
        clearTimeout(timer);
        reject(cause);
      },
    );
  });

export const startInProcessStdio = async (options: InProcessStdioOptions = {}): Promise<InProcessStdio> => {
  const home = await createTempHome("stdio-inproc");
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const signals = new EventEmitter();
  const messages: JsonRpcMessage[] = [];
  const waiters = new Map<number | string, (message: JsonRpcMessage) => void>();
  const exitCodes: number[] = [];
  const hardExits: { code: number | null; ms: number }[] = [];
  let stderr = "";
  let finished: (code: number | null) => void = () => undefined;
  const done = new Promise<number | null>((resolve) => {
    finished = resolve;
  });

  let pending = "";
  stdout.setEncoding("utf8");
  stdout.on("data", (chunk: string) => {
    pending += chunk;
    for (let newline = pending.indexOf("\n"); newline >= 0; newline = pending.indexOf("\n")) {
      const line = pending.slice(0, newline).trim();
      pending = pending.slice(newline + 1);
      if (line === "") continue;
      const message = JSON.parse(line) as JsonRpcMessage;
      messages.push(message);
      if (message.id !== undefined && message.id !== null) waiters.get(message.id)?.(message);
    }
  });

  const deps: StdioRuntimeDeps = {
    env: { BEA_HOME: home.beaHome, BEA_LOG_LEVEL: "silent", ...options.env },
    serve: serveStdio,
    registerShutdown: (handler) => registerProcessShutdown(handler, { signals, stdin }),
    setExitCode: (code) => void exitCodes.push(code),
    transport: () =>
      new StdioServerTransport(stdin, stdout, {
        maxBufferSize: options.maxBufferSize ?? HARD_LIMITS.maxStdioRequestBytes,
      }),
    writeStderr: (text) => {
      stderr += text;
    },
    services: typeof options.services === "function" ? options.services : fakeServices(options.services ?? {}),
    forceExitAfterMs: (code, ms) => {
      hardExits.push({ code, ms });
      if (code !== null) finished(code);
    },
  };
  await runStdio(deps);

  let id = 0;
  const response = (target: number, timeoutMs = 10_000): Promise<JsonRpcMessage> => {
    const existing = messages.find((m) => m.id === target);
    if (existing !== undefined) return Promise.resolve(existing);
    return withTimeout(
      new Promise<JsonRpcMessage>((resolve) => {
        waiters.set(target, (message) => {
          waiters.delete(target);
          resolve(message);
        });
      }),
      timeoutMs,
      `the response to request ${target}`,
    );
  };
  const send = (message: Readonly<Record<string, unknown>>): void => void stdin.write(`${JSON.stringify(message)}\n`);
  const request = (
    method: string,
    params: Readonly<Record<string, unknown>> = {},
    timeoutMs = 10_000,
  ): Promise<JsonRpcMessage> => {
    id += 1;
    const current = id;
    send({ jsonrpc: "2.0", id: current, method, params });
    return response(current, timeoutMs);
  };
  const shutdownDone = (timeoutMs = 5_000): Promise<number | null> =>
    withTimeout(done, timeoutMs, "the stdio shutdown");
  return {
    home,
    send,
    sendRaw: (text) => void stdin.write(text),
    request,
    nextId: () => (id += 1),
    response,
    initialize: async () => {
      const result = await request("initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "bea-inproc-test", version: "1" },
      });
      send({ jsonrpc: "2.0", method: "notifications/initialized" });
      return result;
    },
    messages: () => messages,
    exitCodes: () => exitCodes,
    hardExits: () => hardExits,
    stderr: () => stderr,
    raiseSignal: (signal) => void signals.emit(signal),
    endStdin: async (timeoutMs = 5_000) => {
      stdin.end();
      try {
        return await shutdownDone(timeoutMs);
      } finally {
        await home.cleanup();
      }
    },
    shutdownDone,
  };
};
