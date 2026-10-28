import { access, stat } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname } from "node:path";

import type { DoctorCheckResult } from "../../application/doctor.js";
import type { BeaConfig } from "../../domain/config.js";
import type { BeaErrorOf } from "../../domain/errors/beaError.js";
import type { Result } from "../../domain/result.js";
import { CLIENTS } from "../setup/clients.js";
import type { ClientInspection } from "../setup/registration.js";
import type { SkillInspection } from "../setup/skill.js";

/** package.json engines: ^24.11.0 (S1 A-5). */
export const nodeCheck = (version: string): DoctorCheckResult => {
  const [major, minor] = version.split(".").map(Number);
  const ok = major === 24 && (minor ?? 0) >= 11;
  return {
    name: "node",
    ok,
    classification: ok ? "healthy" : "unsupported_host",
    detail: `node ${version}`,
    ...(ok ? {} : { remediation: "Install Node.js 24.11 or newer within 24.x." }),
  };
};

export const platformCheck = (platform: string, arch: string): DoctorCheckResult => {
  if (platform === "win32" && arch === "x64")
    return { name: "platform", ok: true, classification: "healthy", detail: "win32-x64" };
  if (platform === "linux" && arch === "x64")
    return {
      name: "platform",
      ok: true,
      classification: "healthy",
      detail:
        "linux-x64: best-effort containment (no job object); spawn_process reports capability_unavailable(jobhost).",
    };
  return {
    name: "platform",
    ok: false,
    classification: "unsupported_host",
    detail: `${platform}-${arch}`,
    remediation: "BEA v0.1 analyses Windows x64 user-mode programs on a Windows x64 host.",
  };
};

/** loadConfig issues; constraint texts never echo secret values (config.ts guarantees it for BEA_HTTP_TOKEN). */
export const configCheck = (loaded: Result<BeaConfig, BeaErrorOf<"ConfigurationError">>): DoctorCheckResult =>
  loaded.ok
    ? {
        name: "config",
        ok: true,
        classification: "healthy",
        detail: `BEA_HOME ${loaded.value.home.value} (${loaded.value.home.source})`,
      }
    : {
        name: "config",
        ok: false,
        classification: "configuration_invalid",
        detail: loaded.error.settings
          .map((s) => `${s.setting}: ${s.constraint}`)
          .join(" | ")
          .slice(0, 2000),
        remediation: "Fix the listed settings (environment variables or BEA_HOME/config.json).",
      };

export const unknownEnvCheck = (config: BeaConfig | null): DoctorCheckResult => {
  const unknown = config?.unknownEnv ?? [];
  return {
    name: "config:unknown-env",
    ok: unknown.length === 0,
    classification: unknown.length === 0 ? "healthy" : "config_drift",
    ...(unknown.length === 0
      ? {}
      : {
          detail: `Unknown BEA_* variables (likely typos): ${unknown.join(", ")}`,
          remediation: "Remove or correct them; BEA ignores unknown variables.",
        }),
  };
};

const errorCode = (cause: unknown): string | undefined =>
  typeof cause === "object" && cause !== null ? (Reflect.get(cause, "code") as string | undefined) : undefined;

/** BEA_HOME exists (a writable directory), or its nearest existing ancestor is writable. Never creates anything. */
export const homeCheck = async (home: string | null): Promise<DoctorCheckResult> => {
  if (home === null)
    return {
      name: "home",
      ok: false,
      classification: "configuration_invalid",
      detail: "BEA_HOME could not be resolved (see config).",
    };
  let probe = home;
  for (;;) {
    try {
      const info = await stat(probe);
      if (!info.isDirectory())
        return {
          name: "home",
          ok: false,
          classification: "configuration_invalid",
          detail: `${probe} exists and is not a directory.`,
          remediation: "Point BEA_HOME at a directory.",
        };
      await access(probe, constants.W_OK);
      return {
        name: "home",
        ok: true,
        classification: "healthy",
        detail:
          probe === home
            ? `${home} exists and is writable.`
            : `${home} does not exist yet; ${probe} is writable (created on first use).`,
      };
    } catch (cause: unknown) {
      if (errorCode(cause) !== "ENOENT") {
        return {
          name: "home",
          ok: false,
          classification: "runtime_failure",
          detail: `${probe} is not writable (${errorCode(cause) ?? "error"}).`,
          remediation: "Fix the permissions or set BEA_HOME to a writable directory.",
        };
      }
      const parent = dirname(probe);
      if (parent === probe)
        return {
          name: "home",
          ok: false,
          classification: "configuration_invalid",
          detail: `No ancestor of ${home} exists.`,
        };
      probe = parent;
    }
  }
};

/** registration:<client> from the setup inspection (S1 §7.9.2 states). */
export const registrationCheck = (inspection: ClientInspection): DoctorCheckResult => {
  const name = `registration:${inspection.client}`;
  const label = CLIENTS[inspection.client].label;
  const repair = `bea setup --client ${inspection.client} --dry-run, then --yes; restart ${label}.`;
  switch (inspection.state) {
    case "aligned":
      return {
        name,
        ok: true,
        classification: "healthy",
        detail: `${inspection.path}: aligned. Restart ${label} if its tools are missing.`,
      };
    case "missing":
      return {
        name,
        ok: false,
        classification: "missing_dependency",
        detail: `${inspection.path}: no bea entry${inspection.detected ? "" : ` (${label} not detected)`}.`,
        remediation: repair,
      };
    case "stale":
      return {
        name,
        ok: false,
        classification: "config_drift",
        detail: `${inspection.path}: BEA's entry is out of date.`,
        remediation: repair,
      };
    default:
      return {
        name,
        ok: false,
        classification: "configuration_invalid",
        detail: `${inspection.path}: ${inspection.state}. ${inspection.reason ?? ""}`.trim(),
        remediation: "Needs a human: setup will not edit this file. Fix it by hand, then rerun setup.",
      };
  }
};

/** skill: name, metadata.version and tool_count vs the bundled copy (S1 §7.8). */
export const skillCheck = (inspection: SkillInspection): DoctorCheckResult => {
  const installed = inspection.installed;
  switch (inspection.state) {
    case "aligned":
      return {
        name: "skill",
        ok: true,
        classification: "healthy",
        detail: `${inspection.path}: version ${installed?.version ?? "?"}, ${String(installed?.tool_count ?? "?")} tools.`,
      };
    case "missing":
      return {
        name: "skill",
        ok: false,
        classification: "missing_dependency",
        detail: `${inspection.path} is not installed.`,
        remediation: "bea setup --skill --yes",
      };
    case "stale":
      return {
        name: "skill",
        ok: false,
        classification: "config_drift",
        detail: `${inspection.path}: installed version ${installed?.version ?? "?"} / ${String(installed?.tool_count ?? "?")} tools; bundled ${inspection.expected?.version ?? "?"} / ${String(inspection.expected?.tool_count ?? "?")}.`,
        remediation: "bea setup --skill --yes",
      };
    case "unavailable":
      return {
        name: "skill",
        ok: false,
        classification: "missing_dependency",
        detail: inspection.reason ?? "",
        remediation: "npm run build",
      };
    default:
      return {
        name: "skill",
        ok: false,
        classification: "configuration_invalid",
        detail: inspection.reason ?? inspection.state,
        remediation: "Move the directory aside, then rerun bea setup --skill.",
      };
  }
};
