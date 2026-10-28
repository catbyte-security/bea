// =================================================================================================
// src/agent/fingerprint.ts — WP3-AGENT instrumentation fingerprint (S4 §16, `run_script` interference detection).
// The host calls fingerprint() before and after a user script: patch heads must equal the heads recorded right after
// BEA patched them (`originals.markPatched`), sampled threads' DR7 must carry the bits BEA's armed slots need (WP9
// supplies the expectation), BEA guard pages must still be guarded (or legitimately mid-trap / suspended), and the
// followed-thread set is reported. Any mismatch sends one NoticeMessage{instrument-interference}.
// =================================================================================================
import type { Fingerprint } from "../shared/agentProtocol.js";
import { env } from "./env.js";
import { hex } from "./encode.js";
import { bytesHex, hexOfBigint } from "./pure/coreHex.js";
import { CONTEXT_FLAGS } from "./pure/coreWin64.js";
import type { AgentCore } from "./state.js";

export const fingerprint = (c: AgentCore): Fingerprint => {
  const patches = c.originals.list().map((rec) => {
    const { expected, actual } = c.originals.check(rec);
    const actualHex = actual === null ? "" : bytesHex(actual);
    const expectedHex = bytesHex(expected);
    return {
      owner: [...rec.owners.keys()].join(","),
      address: hex(rec.site),
      expected_head: expectedHex,
      actual_head: actualHex,
      ok: actual !== null && actualHex === expectedHex,
    };
  });
  const expectedDr7 = c.hooks.expectedDr7?.() ?? null;
  const debugRegisters: Fingerprint["debug_registers"] = [];
  for (const t of c.threads.enumerate().slice(0, c.limits.hwbp_verify_threads)) {
    const ctx = c.threads.context(t.id, CONTEXT_FLAGS.debugRegisters);
    if (ctx === null) continue;
    debugRegisters.push({
      tid: t.id,
      dr7: hexOfBigint(ctx.dr7),
      ok: expectedDr7 === null || (ctx.dr7 & expectedDr7) === expectedDr7,
    });
  }
  const guardPages = c.guards.entries().map((e) => {
    const guarded = c.guards.isGuardedNow(e);
    return { page: hex(e.base), guarded, ok: guarded || !e.desired || e.suspended > 0 };
  });
  const result: Fingerprint = {
    t: c.native.nowUs(),
    patches,
    debug_registers: debugRegisters,
    guard_pages: guardPages,
    stalker_threads: c.stalkerCo.threads(),
  };
  const bad = {
    patches: patches.filter((p) => !p.ok).length,
    debug_registers: debugRegisters.filter((d) => !d.ok).length,
    guard_pages: guardPages.filter((g) => !g.ok).length,
  };
  if (bad.patches + bad.debug_registers + bad.guard_pages > 0)
    env.send({ bea: "notice", code: "instrument-interference", detail: bad });
  return result;
};
