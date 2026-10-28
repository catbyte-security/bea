import { describe, expect, it } from "vitest";

import type { HandlerContext } from "../../../src/application/handlerContext.js";
import { liveOp } from "../../../src/application/sessionAccess.js";
import { createApplication } from "../../../src/application/createApplication.js";
import { loadConfig } from "../../../src/domain/config.js";
import { silentLogger } from "../../../src/domain/logger.js";
import { ok } from "../../../src/domain/result.js";
import { FakeAgentRpc } from "../../support/fakes/fakeAgentRpc.js";
import { fakeServices } from "../../support/fakes/fakeServices.js";
import { FakeSessions } from "../../support/fakes/fakeSession.js";

/** The shared session fakes behave like the real port where other areas depend on it (sessionAccess.ts, agent errors). */
const ctx: HandlerContext = {
  operation: "read_memory",
  surface: "mcp",
  requestId: "1",
  signal: new AbortController().signal,
  abortCause: () => null,
  remainingMs: () => 5000,
  progress: { report: () => undefined },
  log: silentLogger,
  gates: { isEnabled: () => false, require: () => ok(undefined), requireUnlessOwned: () => ok(undefined) },
};

const appWith = async (sessions: FakeSessions) => {
  const loaded = await loadConfig({
    env: { BEA_HOME: "C:/bea-fake" },
    platform: "win32",
    accountHome: "C:/Users/t",
    readConfigFile: async () => null,
  });
  if (!loaded.ok) throw new Error("config");
  return createApplication({
    config: loaded.value,
    logger: silentLogger,
    transport: "cli",
    services: fakeServices({ sessions }),
  });
};

describe("shared session fakes", () => {
  it("FakeSessions + FakeAgentRpc through sessionAccess.liveOp: values, mapped agent errors, the state table", async () => {
    const sessions = new FakeSessions();
    const agent = new FakeAgentRpc({
      ping: () => ({ t: 1, g: 2, phase: "ready" }),
      readMemory: () => ({
        agentError: { _tag: "AccessViolation", message: "av", address: "0x10", operation: "read" },
      }),
    });
    const session = sessions.add({ agent, state: "running" });
    const app = await appWith(sessions);
    const ping = await liveOp(app, ctx, session.id, { mode: "exclusive", need: "agent" }, (s, op) =>
      s.agent.call("ping", {}, { op }),
    );
    expect(ping.ok && ping.value).toEqual({ t: 1, g: 2, phase: "ready" });
    const read = await liveOp(app, ctx, session.id, { mode: "exclusive", need: "agent" }, (s, op) =>
      s.agent.call("readMemory", { address: "0x10", size: 4 }, { op }),
    );
    expect(!read.ok && read.error._tag).toBe("MemoryAccessFailed");
    const unscripted = await liveOp(app, ctx, session.id, { mode: "exclusive", need: "agent" }, (s, op) =>
      s.agent.call("status", { detail: "summary" }, { op }),
    );
    expect(!unscripted.ok && unscripted.error._tag).toBe("UnsupportedTarget");
    expect(agent.callsOf("ping")).toHaveLength(1);
    session.exitWith({ code: 0xc0000005, code_hex: "0xc0000005", kind: "ntstatus", name: "STATUS_ACCESS_VIOLATION" });
    const exited = await liveOp(app, ctx, session.id, { mode: "exclusive", need: "agent" }, async () => ok("ran"));
    expect(!exited.ok && exited.error._tag).toBe("TargetExited");
    expect((await liveOp(app, ctx, "nope", { mode: "concurrent", need: "host" }, async () => ok(1))).ok).toBe(false);
  });

  it("waits wake on exit, stream ends and output; closed sessions keep a tombstone; onSessionEnded fires", async () => {
    const sessions = new FakeSessions();
    const session = sessions.add({ output: "READY\n" });
    const op = {
      opId: 1,
      name: "wait",
      signal: new AbortController().signal,
      deadline: { remaining: () => 1000 },
    } as never;
    expect((await session.waitFor({ kind: "output-contains", text: "READY" }, op, 10)).satisfied).toBe(true);
    const waiting = session.waitFor({ kind: "process-exit" }, op, 1000);
    session.exitWith({ code: 0, code_hex: "0x0", kind: "normal", name: null });
    expect((await waiting).satisfied).toBe(true);
    await session.streams.bind("s1", {
      source: { kind: "hook", instance_id: null, effect_id: null, channel: "s1" },
      encoding: { kind: "ndjson" },
      decoders: null,
      literals: { count: 0, texts: [], spellings: [] },
    });
    expect((await session.waitFor({ kind: "stream-end", agentStream: "s1" }, op, 5)).timedOut).toBe(true);
    session.streams.markEnded("s1");
    expect((await session.waitFor({ kind: "stream-end", agentStream: "s1" }, op, 5)).satisfied).toBe(true);
    const ended: string[] = [];
    sessions.onSessionEnded((e) => ended.push(e.reason));
    const closed = await sessions.close(session.id, { force: false }, op);
    expect(closed.ok).toBe(true);
    expect(sessions.kindOf(session.id)).toBe("closed");
    expect(ended).toEqual(["closed"]);
  });
});
