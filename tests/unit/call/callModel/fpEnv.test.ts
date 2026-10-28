import { describe, expect, it } from "vitest";

import { fpThreadToRead, resolveFpEnv } from "../../../../src/domain/callModel/fpEnv.js";

describe("fpEnv (CT-I9, D-INT-43)", () => {
  it("auto with a known thread uses that thread's environment with MXCSR status bits cleared", () => {
    expect(fpThreadToRead(undefined, 4242)).toBe(4242);
    const r = resolveFpEnv(undefined, { threadId: 4242, env: { mxcsr: 0x9fe3, fpcw: 0x37f } });
    expect(r.ok && r.value).toEqual({ mxcsr: 0x9fc0, fpcw: 0x37f, source: "thread", threadId: 4242, limitations: [] });
  });

  it("auto without a known thread is the Windows default and carries CALL_FP_DEFAULT", () => {
    expect(fpThreadToRead({ source: "auto" }, null)).toBeNull();
    const r = resolveFpEnv({ source: "auto" }, { threadId: null, env: null });
    expect(r.ok && r.value).toEqual({
      mxcsr: 0x1f80,
      fpcw: 0x27f,
      source: "windows-default",
      threadId: null,
      limitations: ["CALL_FP_DEFAULT"],
    });
  });

  it("auto falls back to the dump's primary thread for dump-backed sessions", () => {
    const r = resolveFpEnv(
      { source: "auto" },
      { threadId: null, env: null, dumpThread: { mxcsr: 0x1fa0, fpcw: 0x27f } },
    );
    expect(r.ok && r.value).toMatchObject({ mxcsr: 0x1f80, source: "dump-thread", limitations: [] });
  });

  it("explicit mxcsr/fpcw override field by field; both explicit is source explicit and needs no thread", () => {
    expect(fpThreadToRead({ source: "thread", mxcsr: "0x9fc0", fpcw: "0x37f" }, 7)).toBeNull();
    const both = resolveFpEnv({ source: "thread", mxcsr: "0x9FC0", fpcw: "0x37f" }, { threadId: null, env: null });
    expect(both.ok && both.value).toEqual({
      mxcsr: 0x9fc0,
      fpcw: 0x37f,
      source: "explicit",
      threadId: null,
      limitations: [],
    });
    const partial = resolveFpEnv({ source: "auto", mxcsr: "0x7f80" }, { threadId: null, env: null });
    expect(partial.ok && partial.value).toMatchObject({
      mxcsr: 0x7f80,
      fpcw: 0x27f,
      source: "windows-default",
      limitations: [],
    });
  });

  it('source "thread" without a readable thread is invalid_request; windows-default ignores threads', () => {
    const none = resolveFpEnv({ source: "thread" }, { threadId: null, env: null });
    expect(!none.ok && none.error).toMatchObject({ path: "fp.source", reason: "invalid_value" });
    const unread = resolveFpEnv({ source: "thread", thread_id: 9 }, { threadId: 9, env: null });
    expect(!unread.ok && unread.error.message).toMatch(/could not be read/u);
    expect(fpThreadToRead({ source: "windows-default" }, 9)).toBeNull();
    const win = resolveFpEnv({ source: "windows-default" }, { threadId: 9, env: { mxcsr: 0x9fc0, fpcw: 0x37f } });
    expect(win.ok && win.value.source).toBe("windows-default");
  });

  it("fp.thread_id takes precedence over the call's thread", () => {
    expect(fpThreadToRead({ source: "auto", thread_id: 11 }, 22)).toBe(11);
  });
});
