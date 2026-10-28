import { afterEach, describe, expect, it } from "vitest";

import { sessionsStatusContributor } from "../../../../src/providers/frida/statusAndDoctor.js";
import { expectToolSuccess, parseToolError } from "../../../support/mcp/parseToolError.js";
import { connectInMemoryBea, type InMemoryBea } from "../../../support/mcp/inMemory.js";
import { addForeign, createHarness, PROGRAM, settle, type Harness } from "../../../unit/sessions/support/harness.js";

/**
 * The seven sessions tools over the production MCP server (createMcpServer + invokeTool + Delivery), backed by the real
 * SessionManager over fake Frida, fake jobhost and local fake evidence/recordings (S3 §21 fast lane; DESIGN §6.2 A).
 */
let bea: InMemoryBea | undefined;
let h: Harness;

const connect = async (harness: Harness = createHarness()): Promise<InMemoryBea> => {
  h = harness;
  bea = await connectInMemoryBea({
    services: { sessions: h.manager, evidence: h.evidence, recordings: h.recordings },
  });
  return bea;
};

afterEach(async () => {
  await h.closeAll();
  await bea?.close();
  bea = undefined;
});

const call = async (name: string, args: Record<string, unknown>) =>
  (bea as InMemoryBea).client.callTool({ name, arguments: args });

describe("sessions tools over MCP: catalog, listing and startup", () => {
  it("advertises the seven tools with effect-derived hints", async () => {
    const { client } = await connect();
    const tools = (await client.listTools()).tools.filter((t) =>
      [
        "bea_status",
        "list_processes",
        "spawn_process",
        "attach_process",
        "resume_process",
        "session_status",
        "close_session",
      ].includes(t.name),
    );
    expect(tools).toHaveLength(7);
    const hints = Object.fromEntries(tools.map((t) => [t.name, t.annotations]));
    expect(hints["spawn_process"]).toMatchObject({ readOnlyHint: false, openWorldHint: true, idempotentHint: false });
    expect(hints["resume_process"]).toMatchObject({ destructiveHint: true, idempotentHint: false });
    expect(hints["close_session"]).toMatchObject({ destructiveHint: true, idempotentHint: true });
    expect(hints["session_status"]).toMatchObject({ readOnlyHint: true, idempotentHint: true });
    expect(hints["list_processes"]).toMatchObject({ readOnlyHint: true });
  });

  it("list_processes pages a sorted listing and marks BEA's sessions", async () => {
    const harness = createHarness();
    addForeign(harness, 300, "zeta.exe");
    addForeign(harness, 200, "Alpha.exe");
    addForeign(harness, 100, "alpha.exe");
    await connect(harness);
    const spawned = expectToolSuccess(await call("spawn_process", { program: PROGRAM }));
    const page = expectToolSuccess(await call("list_processes", { limit: 2 }));
    expect((page["rows"] as { pid: number }[]).map((r) => r.pid)).toEqual([100, 200]);
    expect(page["page"]).toEqual({ offset: 0, limit: 2, total: 4, next_offset: 2 });
    expect(page["evidence_id"]).toBeNull();
    const mine = expectToolSuccess(await call("list_processes", { filter: "GAME_SIM" }));
    const rows = mine["rows"] as { pid: number; bea_session: string | null }[];
    expect(rows).toHaveLength(1);
    expect(rows[0]?.bea_session).toBe(spawned["session_id"]);
  });

  it("spawn_process returns the paused session, its identity, recordings and lifecycle effects, recorded as evidence", async () => {
    await connect();
    const result = expectToolSuccess(
      await call("spawn_process", { program: PROGRAM, args: ["--frames", "60"], env: ["MODE=1", "BEA_X=1"] }),
    );
    expect(result).toMatchObject({
      state: "paused",
      identity: { ownership: "owned", start_time: { source: "os-creation-time" }, image: { path: PROGRAM } },
      main_module: { base: "0x7ff6a0000000", preferred_base: "0x140000000" },
      containment: {
        kind: "win32-job",
        kill_on_close: true,
        breakaway: false,
        assigned_before_first_instruction: true,
        watch_helper_pid: null,
      },
      agent: { runtime: "qjs", version: "0.1.0" },
      environment: { mode: "allowlist", allowlist_version: 1, caller_keys: 1 },
      predicate_type: "bea.process.instance",
    });
    expect(result["evidence_id"]).toMatch(/^ev_[0-9a-f]{64}$/u);
    expect((result["recordings"] as { kind: string }[]).map((r) => r.kind).sort()).toEqual([
      "exceptions",
      "modules",
      "output",
    ]);
    expect((result["effects_applied"] as string[]).length).toBe(3);
    const draft = h.evidence.drafts.find((d) => d.operation === "spawn_process");
    expect(JSON.stringify(draft?.input)).not.toContain("MODE=1");
    expect(draft?.input).toMatchObject({ args_count: 2, env_keys_count: 2 });
  });

  it("spawn_process refusals come back as the canonical error projection", async () => {
    await connect();
    const relative = parseToolError(await call("spawn_process", { program: "game.exe" }));
    expect(relative.code).toBe("invalid_request");
    const shell = parseToolError(await call("spawn_process", { program: "C:\\Windows\\System32\\cmd.exe" }));
    expect(shell).toMatchObject({ code: "access_denied", details: { reason: "policy" } });
    expect(shell.remediation.action).toContain("spawn.allow_interpreters");
    const mismatch = parseToolError(await call("spawn_process", { program: PROGRAM, expect_sha256: "cd".repeat(32) }));
    expect(mismatch.code).toBe("instance_mismatch");
    const literals = parseToolError(await call("spawn_process", { program: PROGRAM, redact_literals: ["abc"] }));
    expect(literals.code).toBe("invalid_request");
  });

  it("attach_process by name refuses ambiguity with candidates; exactly one of pid or name", async () => {
    const harness = createHarness();
    addForeign(harness, 501, "twin.exe");
    addForeign(harness, 502, "twin.exe");
    addForeign(harness, 503, "solo.exe");
    await connect(harness);
    const both = parseToolError(await call("attach_process", { pid: 503, name: "solo.exe" }));
    expect(both.code).toBe("invalid_request");
    const ambiguous = parseToolError(await call("attach_process", { name: "TWIN.exe" }));
    expect(ambiguous).toMatchObject({ code: "invalid_request", details: { diagnostics: { candidates: [501, 502] } } });
    const attached = expectToolSuccess(await call("attach_process", { name: "solo.exe" }));
    expect(attached).toMatchObject({
      state: "running",
      identity: { ownership: "attached", pid: 503 },
      containment: { kind: "none", kill_on_close: false },
      environment: null,
    });
    const resume = parseToolError(await call("resume_process", { session_id: attached["session_id"] }));
    expect(resume.code).toBe("invalid_state");
  });
});

describe("sessions tools over MCP: resume, status and close", () => {
  it("resume_process waits for the exit and returns the exit code and the derived crash", async () => {
    await connect();
    const spawned = expectToolSuccess(await call("spawn_process", { program: PROGRAM }));
    const id = spawned["session_id"] as string;
    const pid = (spawned["identity"] as { pid: number }).pid;
    const resuming = call("resume_process", { session_id: id, wait_ms: 5000, until: "exit" });
    await settle();
    await settle();
    h.jobhost.hostOf(pid)?.exitRoot(0xc0000005);
    const result = expectToolSuccess(await resuming);
    expect(result).toMatchObject({
      state: "exited",
      exit: { code: 0xc0000005, code_hex: "0xc0000005", kind: "ntstatus", name: "STATUS_ACCESS_VIOLATION" },
      crash: { type: "access-violation", pc: null, ntstatus: "STATUS_ACCESS_VIOLATION" },
      predicate_type: "bea.process.instance",
    });
    expect(result["effects_applied"]).toHaveLength(1);
    expect(result["waited_ms"]).toBeGreaterThanOrEqual(0);
    const again = parseToolError(await call("resume_process", { session_id: id }));
    expect(again.code).toBe("target_exited");
  });

  it("session_status: summary is a poll, complete records evidence, a closed session answers from its tombstone", async () => {
    await connect();
    const spawned = expectToolSuccess(await call("spawn_process", { program: PROGRAM }));
    const id = spawned["session_id"] as string;
    const summary = expectToolSuccess(await call("session_status", { session_id: id }));
    expect(summary).toMatchObject({
      kind: "live",
      state: "paused",
      evidence_id: null,
      exit: null,
      crash: null,
      emulation: null,
      module_map_epoch: 1,
      containment: { kind: "win32-job" },
    });
    expect((summary["instruments"] as unknown[]).length).toBe(3);
    expect((summary["effects"] as { kind: string }[]).map((e) => e.kind).sort()).toEqual([
      "agent-injected",
      "process-spawned",
      "process-suspended",
    ]);
    const complete = expectToolSuccess(await call("session_status", { session_id: id, detail: "complete" }));
    expect(complete["predicate_type"]).toBe("bea.session.status");
    expect(complete["evidence_id"]).toMatch(/^ev_/u);
    expectToolSuccess(await call("close_session", { session_id: id }));
    const closed = expectToolSuccess(await call("session_status", { session_id: id }));
    expect(closed).toMatchObject({ state: "closed", kind: "live" });
    const unknown = parseToolError(
      await call("session_status", { session_id: "00000000-0000-4000-8000-00000000abcd" }),
    );
    expect(unknown.code).toBe("session_not_found");
  });

  it("close_session kills an owned target, reports manifests, records bea.process.exit and is idempotent", async () => {
    await connect();
    const spawned = expectToolSuccess(await call("spawn_process", { program: PROGRAM }));
    const id = spawned["session_id"] as string;
    const pid = (spawned["identity"] as { pid: number }).pid;
    const closed = expectToolSuccess(await call("close_session", { session_id: id }));
    expect(closed).toMatchObject({
      already_closed: false,
      target_state: "killed",
      predicate_type: "bea.process.exit",
      exit: { kind: "bea-kill" },
    });
    expect((closed["manifests"] as string[]).length).toBe(4);
    expect(
      (closed["reverted"] as { kind: string; status: string }[]).map((r) => `${r.kind}:${r.status}`).sort(),
    ).toEqual(["agent-injected:implicit-end", "process-suspended:implicit-end"]);
    expect(closed["effects_applied"]).toHaveLength(1);
    expect(h.fake.process(pid)?.alive).toBe(false);
    const again = expectToolSuccess(await call("close_session", { session_id: id }));
    expect(again).toMatchObject({ already_closed: true, target_state: "killed", evidence_id: null });
  });

  it("close_session keeps an attached session whose effects cannot be reverted; force detaches and leaves it running", async () => {
    const harness = createHarness();
    addForeign(harness, 600);
    harness.fake.behaviors.set(600, {
      rpc: {
        shutdown: () => ({
          ok: true,
          value: {
            stopped: [],
            unreverted: [{ id: "h1", detail: "x" }],
            scans_freed: 0,
            jobs_cancelled: 0,
            final_batches: 0,
          },
        }),
      },
    });
    await connect(harness);
    const attached = expectToolSuccess(await call("attach_process", { pid: 600 }));
    const id = attached["session_id"] as string;
    const refused = parseToolError(await call("close_session", { session_id: id }));
    expect(refused).toMatchObject({ code: "effect_unreverted", retryable: true });
    const status = expectToolSuccess(await call("session_status", { session_id: id }));
    expect(status["state"]).toBe("cleanup_pending");
    const forced = expectToolSuccess(await call("close_session", { session_id: id, force: true }));
    expect(forced).toMatchObject({ target_state: "detached-running", already_closed: false });
    expect(h.fake.process(600)?.alive).toBe(true);
  });
});

describe("bea_status over MCP", () => {
  it("bea_status shows the sessions contributor: frida/agent backends, open sessions and the machine-wide anti-cheat note", async () => {
    const harness = createHarness();
    harness.fake.addProcess({ pid: 42, name: "vgc.exe", path: "C:\\Program Files\\Riot Vanguard\\vgc.exe" });
    const { app } = await connect(harness);
    app.status.add(sessionsStatusContributor(harness.host, harness.manager));
    const before = expectToolSuccess(await call("bea_status", {}));
    expect(before["backends"]).toContainEqual({
      id: "frida",
      state: "not-loaded",
      version: null,
      detail: "loads on first use (frida 17.23.2)",
    });
    expect(before["notes"]).toEqual([]);
    expectToolSuccess(await call("spawn_process", { program: PROGRAM }));
    const status = expectToolSuccess(await call("bea_status", {}));
    expect(status["evidence_id"]).toBeNull();
    expect(
      (status["sessions"] as { state: string; ownership: string }[]).map((s) => `${s.ownership}:${s.state}`),
    ).toEqual(["owned:paused"]);
    expect(
      (status["backends"] as { id: string; state: string }[])
        .filter((b) => b.id === "frida" || b.id === "agent")
        .map((b) => `${b.id}:${b.state}`),
    ).toEqual(["frida:available", "agent:available"]);
    expect(status["notes"]).toEqual([
      "A machine-wide anti-cheat service is running (vgc.exe); BEA refuses only targets that show anti-cheat signals themselves.",
    ]);
  });
});
