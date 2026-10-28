import { describe, expect, it } from "vitest";

import type { BeaError } from "../../../src/domain/errors/beaError.js";
import { projectBeaError } from "../../../src/domain/errors/projection.js";
import type { ProcessMitigations } from "../../../src/domain/jobhostProtocol.js";
import { NO_LITERALS, type SensitiveLiterals } from "../../../src/domain/redaction/literals.js";
import type { InstanceObservation } from "../../../src/ports/evidence.js";
import type { ProcessInspection } from "../../../src/ports/jobhost.js";
import { evaluateAttachPolicy, type AttachSelfFacts } from "../../../src/providers/frida/attachPolicy.js";
import { decodeMitigations } from "../../../src/providers/process/ProcessInspector.js";
import { FRIDA_MESSAGE_MAX_CHARS, fridaMessageOf, withFridaMessage } from "../../../src/providers/frida/rpcErrors.js";
import { addForeign, createHarness, errTag } from "./support/harness.js";

/**
 * BEA-FEEDBACK item 1: attach refuses processes whose mitigations make the injection impossible (rule 13 Code
 * Integrity Guard, rule 14 Arbitrary Code Guard) before anything is injected, and a failed injection keeps Frida's own
 * text (sanitized, bounded) instead of only a generic execution_failure.
 */
const FRIDA_REFUSED = "Process with pid 7400 either refused to load frida-agent, or terminated during injection";

const mitigations = (flags: {
  readonly signature?: number | null;
  readonly dynamicCode?: number | null;
  readonly userShadowStack?: number | null;
  readonly imageLoad?: number | null;
}): ProcessMitigations => {
  const read = (value: number | null | undefined) =>
    value === null ? { flags: null, win32: 5 } : { flags: value ?? 0, win32: 0 };
  return decodeMitigations({
    access: "limited",
    signature: read(flags.signature),
    dynamicCode: read(flags.dynamicCode),
    userShadowStack: read(flags.userShadowStack),
    imageLoad: read(flags.imageLoad),
  });
};

const inspection = (over: Partial<ProcessInspection> = {}): ProcessInspection => ({
  pid: 5000,
  access: "limited+synchronize",
  exited: false,
  exitCode: null,
  creationTime100ns: 1n,
  imagePath: "C:\\chrome\\chrome.exe",
  parentPid: 100,
  osSessionId: 1,
  critical: false,
  protectionLevel: 0xfffffffe,
  protected: false,
  wow64: false,
  processMachine: 0,
  nativeMachine: 0x8664,
  inJob: true,
  elevated: false,
  integrityRid: 0x1000,
  sameUser: true,
  ...over,
});
const self: AttachSelfFacts = {
  pid: 10,
  ppid: 11,
  helperPids: [12],
  sessionPids: new Map(),
  elevated: false,
  integrityRid: 0x2000,
  systemRoot: "C:\\Windows",
};
const config = { allowSession0: false, extraDenylist: [], allowAntiCheat: false, allowAntiCheatImages: [] };
const decide = (
  over: Partial<ProcessInspection>,
  options: { signals?: readonly string[]; allowAntiCheat?: boolean } = {},
) =>
  evaluateAttachPolicy({
    pid: 5000,
    inspection: inspection(over),
    self,
    config: { ...config, allowAntiCheat: options.allowAntiCheat ?? false },
    antiCheatSignals: options.signals ?? [],
    imageSha256: null,
  }).refusal;
const reasonOf = (refusal: BeaError | null): string | null =>
  refusal === null ? null : `${refusal._tag}:${(refusal as { readonly reason?: string }).reason ?? ""}`;

describe("attach rules 13–14: mitigations under which the injection cannot work", () => {
  it.each([
    [
      "MicrosoftSignedOnly (Chrome's sandboxed GPU process)",
      { signature: 0x5 },
      "AccessDenied:code-integrity-guard",
      "ProcessSignaturePolicy.MicrosoftSignedOnly",
      "only Microsoft-signed DLLs",
    ],
    [
      "StoreSignedOnly",
      { signature: 0x2 },
      "AccessDenied:code-integrity-guard",
      "ProcessSignaturePolicy.StoreSignedOnly",
      "only Microsoft Store-signed DLLs",
    ],
    [
      "ProhibitDynamicCode",
      { dynamicCode: 0x1 },
      "AccessDenied:arbitrary-code-guard",
      "ProcessDynamicCodePolicy.ProhibitDynamicCode",
      "would crash it",
    ],
    [
      "ProhibitDynamicCode with thread opt-out and remote downgrade",
      { dynamicCode: 0x7 },
      "AccessDenied:arbitrary-code-guard",
      "ProcessDynamicCodePolicy.ProhibitDynamicCode",
      "executable memory",
    ],
  ] as const)("%s refuses", (_name, flags, expected, mitigation, effect) => {
    const refusal = decide({ mitigations: mitigations(flags) });
    expect(reasonOf(refusal)).toBe(expected);
    expect(refusal?.diagnostics?.["mitigation"]).toBe(mitigation);
    expect(refusal?.message).toContain(`(${mitigation}): `);
    expect(refusal?.message).toContain(effect);
    expect(refusal?.operation).toBe("attach_process");
  });

  it.each([
    ["no mitigation", {}],
    ["MitigationOptIn alone (does not block unsigned images, lab)", { signature: 0x4 }],
    ["audit-only signature and dynamic-code bits", { signature: 0x18, dynamicCode: 0x8 }],
    ["user shadow stacks, compat mode (Chrome with --disable-gpu-sandbox)", { userShadowStack: 0x101 }],
    ["user shadow stacks, strict mode and non-CET binaries blocked (information only)", { userShadowStack: 0x31 }],
    ["image-load restrictions", { imageLoad: 0x7 }],
  ] as const)("%s does not refuse", (_name, flags) => {
    expect(decide({ mitigations: mitigations(flags) })).toBeNull();
  });

  it("unknown policies never refuse: a failed read, an older helper (absent) or Linux (null)", () => {
    expect(decide({ mitigations: mitigations({ signature: null, dynamicCode: null }) })).toBeNull();
    expect(decide({})).toBeNull();
    expect(decide({ mitigations: null })).toBeNull();
  });

  it("CIG and ACG together: the CIG refusal names both; earlier rules and anti-cheat still win", () => {
    const both = mitigations({ signature: 0x1, dynamicCode: 0x1 });
    const refusal = decide({ mitigations: both });
    expect(reasonOf(refusal)).toBe("AccessDenied:code-integrity-guard");
    expect(refusal?.diagnostics).toEqual({
      mitigation: "ProcessSignaturePolicy.MicrosoftSignedOnly",
      blocking: ["ProcessSignaturePolicy.MicrosoftSignedOnly", "ProcessDynamicCodePolicy.ProhibitDynamicCode"],
      signature_policy_flags: 1,
      dynamic_code_policy_flags: 1,
      user_shadow_stack_policy_flags: 0,
    });
    expect(reasonOf(decide({ mitigations: both, protected: true }))).toBe("AccessDenied:protected-process");
    expect(reasonOf(decide({ mitigations: both, wow64: true }))).toBe("UnsupportedTarget:wow64");
    expect(reasonOf(decide({ mitigations: both }, { signals: ["dir:BattlEye"] }))).toBe(
      "AccessDenied:anti-cheat-detected",
    );
    // the user's anti-cheat override cannot lift a mitigation
    expect(reasonOf(decide({ mitigations: both }, { signals: ["dir:BattlEye"], allowAntiCheat: true }))).toBe(
      "AccessDenied:code-integrity-guard",
    );
  });

  it("the projected error is access_denied with the reason, a curated message naming the mitigation and research-only remediation", () => {
    const cig = decide({ mitigations: mitigations({ signature: 0x5 }) });
    const acg = decide({ mitigations: mitigations({ dynamicCode: 0x1 }) });
    if (cig === null || acg === null) throw new Error("expected refusals");
    const p = projectBeaError(cig);
    expect(p).toMatchObject({
      code: "access_denied",
      category: "unavailable",
      retryable: false,
      details: {
        reason: "code-integrity-guard",
        diagnostics: { mitigation: "ProcessSignaturePolicy.MicrosoftSignedOnly" },
      },
    });
    expect(p.message).toContain("Code Integrity Guard (ProcessSignaturePolicy.MicrosoftSignedOnly)");
    expect(p.message).toContain("Nothing was injected");
    expect(p.remediation.action).toContain("cannot inject");
    expect(p.remediation.action).toContain("--disable-gpu-sandbox");
    expect(p.remediation.action).toContain("research only");
    const q = projectBeaError(acg);
    expect(q.details["reason"]).toBe("arbitrary-code-guard");
    expect(q.message).toContain("Arbitrary Code Guard (ProcessDynamicCodePolicy.ProhibitDynamicCode)");
    expect(q.message).toContain("would crash it");
  });
});

describe("Frida's own text in attach errors (BEA-FEEDBACK item 1c)", () => {
  const literals = (texts: readonly string[]): SensitiveLiterals => ({ count: texts.length, texts, spellings: [] });

  it("fridaMessageOf: control, format and separator characters become spaces; bounded without splitting a pair", () => {
    expect(fridaMessageOf(new Error(FRIDA_REFUSED))).toBe(FRIDA_REFUSED);
    expect(fridaMessageOf(new Error("line one\r\n\tline\u0000two \u202Eevil\u2028x  "))).toBe(
      "line one line two evil x",
    );
    expect(fridaMessageOf("plain string cause")).toBe("plain string cause");
    expect(fridaMessageOf({ message: "not an Error" })).toBeNull();
    expect(fridaMessageOf(new Error(" \u0001 "))).toBeNull();
    const long = fridaMessageOf(new Error("x".repeat(1000)));
    expect(long?.length).toBe(FRIDA_MESSAGE_MAX_CHARS);
    expect(long?.endsWith("…")).toBe(true);
    // a surrogate pair straddling the cut is dropped whole, never split
    const pair = fridaMessageOf(new Error(`${"y".repeat(FRIDA_MESSAGE_MAX_CHARS - 2)}\u{1F9F5}tail`));
    expect(pair).toBe(`${"y".repeat(FRIDA_MESSAGE_MAX_CHARS - 2)}…`);
  });

  it("withFridaMessage adds diagnostics.frida_message to Frida's failures only, and withholds a sensitive literal", () => {
    const failure: BeaError = {
      _tag: "ProviderFailure",
      operation: "attach_process",
      provider: "frida",
      diagnostics: { phase: "attach" },
    };
    expect(withFridaMessage(failure, new Error(FRIDA_REFUSED), NO_LITERALS).diagnostics).toEqual({
      phase: "attach",
      frida_message: FRIDA_REFUSED,
    });
    expect(withFridaMessage(failure, new Error(FRIDA_REFUSED), null).diagnostics?.["frida_message"]).toBe(
      FRIDA_REFUSED,
    );
    expect(
      withFridaMessage(failure, new Error("C:\\secret-project\\app.exe denied"), literals(["secret-project"]))
        .diagnostics,
    ).toEqual({
      phase: "attach",
      frida_message_withheld: true,
    });
    const denied: BeaError = {
      _tag: "AccessDenied",
      operation: "attach_process",
      reason: "os-denied",
      diagnostics: { phase: "attach" },
    };
    expect(withFridaMessage(denied, new Error("Access is denied"), null).diagnostics?.["frida_message"]).toBe(
      "Access is denied",
    );
    const timeout: BeaError = {
      _tag: "ProviderTimeout",
      operation: "attach_process",
      timeout_ms: 10_000,
      phase: "attach",
    };
    expect(withFridaMessage(timeout, new Error("Operation was cancelled"), null)).toBe(timeout);
    const cancelled: BeaError = { _tag: "Cancelled", operation: "attach_process", by: "client" };
    expect(withFridaMessage(cancelled, new Error("Operation was cancelled"), null)).toBe(cancelled);
    // curated message and remediation are untouched: Frida text is data, never prose
    const projected = projectBeaError(withFridaMessage(failure, new Error(FRIDA_REFUSED), null));
    expect(projected.message).toBe("The frida backend failed during attach_process.");
    expect(projected.details["diagnostics"]).toMatchObject({ frida_message: FRIDA_REFUSED });
  });
});

describe("attach path over the fake binding (refusal before injection, Frida text, injection that ends the target)", () => {
  it("a CIG target is refused after inspect: no watcher, no device.attach, nothing injected", async () => {
    const h = createHarness();
    addForeign(h, 7400, "chrome.exe");
    h.jobhost.inspections.set(7400, { mitigations: mitigations({ signature: 0x5 }) });
    const result = await h.attach(7400);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(projectBeaError(result.error).details["reason"]).toBe("code-integrity-guard");
    expect(h.fake.log).toContain("inspect:7400");
    expect(h.fake.log.some((l) => l.startsWith("attach:") || l.startsWith("watch:"))).toBe(false);
    expect(h.fake.sessionsOf(7400)).toHaveLength(0);
    expect(h.fake.process(7400)?.alive).toBe(true);
  });

  it("an ACG target is refused the same way (Frida's injection would crash it)", async () => {
    const h = createHarness();
    addForeign(h, 7401, "chrome.exe");
    h.jobhost.inspections.set(7401, { mitigations: mitigations({ dynamicCode: 0x1 }) });
    const result = await h.attach(7401);
    if (result.ok) throw new Error("expected a refusal");
    expect(result.error).toMatchObject({ _tag: "AccessDenied", reason: "arbitrary-code-guard" });
    expect(h.fake.log.some((l) => l.startsWith("attach:"))).toBe(false);
  });

  it("a failed injection keeps Frida's text in details.diagnostics; the target is never killed", async () => {
    const h = createHarness();
    addForeign(h, 7402);
    h.fake.fail("attach", new Error(`${FRIDA_REFUSED}\n`));
    const result = await h.attach(7402);
    expect(errTag(result)).toBe("ProviderFailure");
    if (result.ok) return;
    const projected = projectBeaError(result.error);
    expect(projected.code).toBe("execution_failure");
    expect(projected.details["diagnostics"]).toEqual({ phase: "attach", frida_message: FRIDA_REFUSED });
    expect(h.fake.process(7402)?.alive).toBe(true);
    expect(h.fake.log.some((l) => l.startsWith("frida.kill") || l.startsWith("jobhost.kill"))).toBe(false);
    expect(h.jobhost.watcherOf(7402)?.stopped).toBe(true);
  });

  it("an injection that ends the target is target_exited with its exit status and Frida's text", async () => {
    const h = createHarness();
    addForeign(h, 7403);
    const gate = h.fake.hold("attach");
    h.fake.fail("attach", new Error(FRIDA_REFUSED));
    const attaching = h.attach(7403);
    await gate.entered;
    h.jobhost.watcherOf(7403)?.exitRoot(0xc0000005);
    gate.release();
    const result = await attaching;
    if (result.ok) throw new Error("expected a failure");
    const projected = projectBeaError(result.error);
    expect(projected).toMatchObject({
      code: "target_exited",
      details: {
        exit: { code: 0xc0000005, code_hex: "0xc0000005", kind: "ntstatus", name: "STATUS_ACCESS_VIOLATION" },
        diagnostics: { phase: "attach", during: "injection", frida_message: FRIDA_REFUSED },
      },
    });
    expect(projected.message).toContain("while BEA was injecting its agent");
    expect(projected.remediation.action).toContain("BEA did not end the process");
  });

  it("a successful attach records the target's mitigations with the instance evidence", async () => {
    const h = createHarness();
    addForeign(h, 7404);
    h.jobhost.inspections.set(7404, { mitigations: mitigations({ userShadowStack: 0x101 }) });
    const observed: InstanceObservation[] = [];
    const register = h.evidence.instances.register.bind(h.evidence.instances);
    h.evidence.instances.register = async (obs) => {
      observed.push(obs);
      return register(obs);
    };
    expect(errTag(await h.attach(7404))).toBe("ok");
    expect(observed[0]?.containment?.["target_mitigations"]).toEqual({
      access: "limited",
      signature: { flags: 0, microsoft_signed_only: false, store_signed_only: false, mitigation_opt_in: false },
      dynamic_code: {
        flags: 0,
        prohibit_dynamic_code: false,
        allow_thread_opt_out: false,
        allow_remote_downgrade: false,
      },
      user_shadow_stack: { flags: 0x101, enabled: true, strict_mode: false, block_non_cet_binaries: false },
      image_load: { flags: 0, no_remote_images: false, no_low_mandatory_label_images: false },
      unreadable: [],
    });
    await h.closeAll();
  });
});
