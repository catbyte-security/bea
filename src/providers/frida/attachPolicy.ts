import type { BeaError } from "../../domain/errors/beaError.js";
import type { JsonObject } from "../../domain/json.js";
import type { ProcessInspection } from "../../ports/jobhost.js";
import { antiCheatVerdict, basenameOf, type AntiCheatVerdict } from "./antiCheatSignals.js";

/**
 * Attach refusal policy (S3 §5.8 rules 1–11 + D-INT-1 rule 12; pure). Rules run in order and the first hit refuses,
 * before any injection. `null` (unknown) facts never refuse on their own. Rule 12 needs the target-scoped anti-cheat
 * signals the caller gathered (directory, on-disk imports, ancestry).
 */
export interface AttachSelfFacts {
  readonly pid: number;
  readonly ppid: number | null;
  /** jobhost/watch helpers and other BEA processes */
  readonly helperPids: readonly number[];
  /** pid → session id of every live BEA session */
  readonly sessionPids: ReadonlyMap<number, string>;
  readonly elevated: boolean | null;
  readonly integrityRid: number | null;
  readonly systemRoot: string;
}

export interface AttachPolicyConfig {
  readonly allowSession0: boolean;
  readonly extraDenylist: readonly string[];
  readonly allowAntiCheat: boolean;
  readonly allowAntiCheatImages: readonly string[];
}

/** S3 §5.8 rule 9 (image under %SystemRoot%) */
const SYSTEM_DENYLIST: readonly string[] = [
  "csrss.exe",
  "smss.exe",
  "wininit.exe",
  "winlogon.exe",
  "lsass.exe",
  "lsaiso.exe",
  "services.exe",
  "svchost.exe",
  "dwm.exe",
  "fontdrvhost.exe",
  "spoolsv.exe",
  "MsMpEng.exe",
  "NisSrv.exe",
  "MpDefenderCoreService.exe",
  "SecurityHealthService.exe",
];

const denied = (
  reason: Extract<BeaError, { _tag: "AccessDenied" }>["reason"],
  message: string,
  diagnostics?: JsonObject,
): BeaError => ({
  _tag: "AccessDenied",
  operation: "attach_process",
  reason,
  message,
  ...(diagnostics === undefined ? {} : { diagnostics }),
});

const isUnder = (path: string, root: string): boolean => {
  const p = path.replaceAll("/", "\\").toLowerCase();
  const r = root.replaceAll("/", "\\").toLowerCase().replace(/\\+$/u, "");
  return r.length > 0 && p.startsWith(`${r}\\`);
};

export interface AttachDecision {
  readonly refusal: BeaError | null;
  readonly antiCheat: AntiCheatVerdict;
  /** "Protection or critical status could not be read" */
  readonly protectionUnknown: boolean;
}

export const evaluateAttachPolicy = (input: {
  readonly pid: number;
  readonly inspection: ProcessInspection;
  readonly self: AttachSelfFacts;
  readonly config: AttachPolicyConfig;
  readonly antiCheatSignals: readonly string[];
  readonly imageSha256: string | null;
}): AttachDecision => {
  const { pid, inspection: i, self, config } = input;
  const antiCheat = antiCheatVerdict({
    signals: input.antiCheatSignals,
    allowGlobal: config.allowAntiCheat,
    allowedImages: config.allowAntiCheatImages,
    imageSha256: input.imageSha256,
  });
  const protectionUnknown = i.protected === null || i.critical === null;
  const decide = (refusal: BeaError | null): AttachDecision => ({ refusal, antiCheat, protectionUnknown });
  if (pid <= 4) return decide(denied("system-process", "The System Idle and System processes cannot be attached."));
  if (pid === self.pid || (self.ppid !== null && pid === self.ppid) || self.helperPids.includes(pid))
    return decide(
      denied("bea-process-tree", "BEA does not attach to its own process tree (server, client or helpers)."),
    );
  const existing = self.sessionPids.get(pid);
  if (existing !== undefined)
    return decide({
      _tag: "InputError",
      operation: "attach_process",
      issues: [
        {
          path: "pid",
          reason: "invalid_value",
          message: `Process ${String(pid)} already has BEA session ${existing}; use that session_id.`,
        },
      ],
    });
  if (i.exited === true)
    return decide({
      _tag: "InputError",
      operation: "attach_process",
      issues: [{ path: "pid", reason: "invalid_value", message: `Process ${String(pid)} has exited.` }],
    });
  if (i.protected === true)
    return decide(
      denied("protected-process", "The process is protected (PPL); BEA cannot inject into it.", {
        protection_level: i.protectionLevel ?? -1,
      }),
    );
  if (i.critical === true)
    return decide(denied("critical-process", "The process is critical; a fault in it would stop Windows."));
  if (i.osSessionId === 0 && !config.allowSession0)
    return decide(
      denied("session-0", "Session-0 (service) processes are refused unless config attach.allow_session0 is set."),
    );
  if (i.wow64 === true || (i.processMachine !== null && i.processMachine !== 0))
    return decide({
      _tag: "UnsupportedTarget",
      operation: "attach_process",
      reason: "wow64",
      message: "32-bit (WoW64) targets are unsupported in BEA v0.1.",
    });
  const image = i.imagePath ?? "";
  const base = basenameOf(image).toLowerCase();
  const systemImage = image.length > 0 && isUnder(image, self.systemRoot);
  if (
    (systemImage && SYSTEM_DENYLIST.some((name) => name.toLowerCase() === base)) ||
    (base.length > 0 && config.extraDenylist.some((name) => name.toLowerCase() === base))
  )
    return decide(denied("system-process", "System processes on BEA's denylist are never attached."));
  if (i.sameUser === false) return decide(denied("other-user", "The process belongs to another user."));
  const higher =
    (i.elevated === true && self.elevated === false) ||
    (i.integrityRid !== null && self.integrityRid !== null && i.integrityRid > self.integrityRid);
  if (higher)
    return decide(denied("higher-integrity", "The process runs at a higher integrity level; BEA never elevates."));
  if (antiCheat.kind === "refuse")
    return decide(
      denied(
        "anti-cheat-detected",
        "Anti-cheat signals were found for this target; BEA refuses to inject by default.",
        {
          signals: [...antiCheat.signals],
        },
      ),
    );
  return decide(null);
};
