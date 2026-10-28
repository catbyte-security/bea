import { randomBytes } from "node:crypto";
import { cp, lstat, mkdir, readdir, readFile, rename, rm } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";

import type { DistLayout } from "../../application/distLayout.js";
import { PRODUCT_IDENTITY } from "../../identity.js";
import { claudeConfigDir, type ClientContext } from "./clients.js";

export const SKILL_NAME = PRODUCT_IDENTITY.skillName;
/** Ownership marker (S1 §7.9.6, [rea-cli §5.7]). */
const OWNER_MARKER = `---\nname: ${SKILL_NAME}\n`;

export const skillDestination = (ctx: ClientContext): string => join(claudeConfigDir(ctx), "skills", SKILL_NAME);
export const bundledSkillDir = (layout: DistLayout): string => join(layout.skillsDir, SKILL_NAME);

export interface SkillIdentity {
  readonly name: string | null;
  readonly version: string | null;
  readonly tool_count: number | null;
  readonly bea_version: string | null;
}

const unquote = (value: string): string => value.trim().replace(/^(["'])(.*)\1$/u, "$2");

/** The few frontmatter keys BEA reads: `name` and `metadata.{version, tool_count, bea_version}` (a YAML subset). */
export const parseSkillFrontmatter = (text: string): SkillIdentity => {
  const lines = text.replace(/^﻿/u, "").split(/\r?\n/u);
  const out = {
    name: null as string | null,
    version: null as string | null,
    tool_count: null as number | null,
    bea_version: null as string | null,
  };
  if (lines[0] !== "---") return out;
  let inMetadata = false;
  for (const line of lines.slice(1)) {
    if (line === "---") break;
    const top = /^([A-Za-z_][\w-]*):\s*(.*)$/u.exec(line);
    if (top !== null) {
      inMetadata = top[1] === "metadata" && (top[2] ?? "").trim() === "";
      if (top[1] === "name") out.name = unquote(top[2] ?? "");
      continue;
    }
    const nested = /^\s+([A-Za-z_][\w-]*):\s*(.*)$/u.exec(line);
    if (!inMetadata || nested === null) continue;
    const value = unquote(nested[2] ?? "");
    if (nested[1] === "version") out.version = value;
    else if (nested[1] === "bea_version") out.bea_version = value;
    else if (nested[1] === "tool_count" && /^\d+$/u.test(value)) out.tool_count = Number(value);
  }
  return out;
};

export type SkillState = "missing" | "aligned" | "stale" | "unmanaged" | "symlink" | "unavailable";

export interface SkillInspection {
  readonly path: string;
  readonly bundled: string;
  readonly state: SkillState;
  readonly installed: SkillIdentity | null;
  readonly expected: SkillIdentity | null;
  /** What install would do: unchanged when every bundled file is byte-identical; null when it cannot install. */
  readonly operation: "create" | "update" | "unchanged" | null;
  /** Bundled files, relative, forward slashes. */
  readonly files: readonly string[];
  readonly reason: string | null;
}

const isSymlink = async (path: string): Promise<boolean | null> => {
  try {
    return (await lstat(path)).isSymbolicLink();
  } catch {
    return null; // absent
  }
};

const listFiles = async (root: string): Promise<string[]> => {
  const entries = await readdir(root, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => relative(root, join(entry.parentPath, entry.name)).split(sep).join("/"))
    .sort();
};

const readOptional = async (path: string): Promise<Buffer | null> => {
  try {
    return await readFile(path);
  } catch {
    return null;
  }
};

const sameFiles = async (from: string, to: string, files: readonly string[]): Promise<boolean> => {
  for (const file of files) {
    const [a, b] = await Promise.all([readOptional(join(from, file)), readOptional(join(to, file))]);
    if (a === null || b === null || !a.equals(b)) return false;
  }
  return true;
};

const identityMatches = (a: SkillIdentity, b: SkillIdentity): boolean =>
  a.name === b.name && a.version === b.version && a.tool_count === b.tool_count;

/** Read-only view of the installed skill against the bundled build output (doctor `skill`, setup plan). */
export const inspectSkill = async (ctx: ClientContext, layout: DistLayout): Promise<SkillInspection> => {
  const path = skillDestination(ctx);
  const bundled = bundledSkillDir(layout);
  const base = { path, bundled };
  const bundledText = await readOptional(join(bundled, "SKILL.md"));
  const expected = bundledText === null ? null : parseSkillFrontmatter(bundledText.toString("utf8"));
  const files = bundledText === null ? [] : await listFiles(bundled);
  const destLink = await isSymlink(path);
  const referencesLink = await isSymlink(join(path, "references"));
  if (destLink === true || referencesLink === true)
    return {
      ...base,
      state: "symlink",
      installed: null,
      expected,
      operation: null,
      files,
      reason: "The skill directory (or its references/) is a symbolic link; BEA will not replace it.",
    };
  const installedText = destLink === null ? null : await readOptional(join(path, "SKILL.md"));
  if (
    destLink !== null &&
    (installedText === null || !installedText.toString("utf8").replace(/\r\n/gu, "\n").startsWith(OWNER_MARKER))
  )
    return {
      ...base,
      state: "unmanaged",
      installed: installedText === null ? null : parseSkillFrontmatter(installedText.toString("utf8")),
      expected,
      operation: null,
      files,
      reason: `${path} exists but is not BEA's skill (its SKILL.md does not start with name: ${SKILL_NAME}); move it aside first.`,
    };
  const installed = installedText === null ? null : parseSkillFrontmatter(installedText.toString("utf8"));
  if (expected === null)
    return {
      ...base,
      state: "unavailable",
      installed,
      expected,
      operation: null,
      files,
      reason: `The bundled skill ${bundled} is missing; run \`npm run build\` (build:skill).`,
    };
  if (installed === null)
    return { ...base, state: "missing", installed, expected, operation: "create", files, reason: null };
  const unchanged = await sameFiles(bundled, path, files);
  return {
    ...base,
    state: identityMatches(installed, expected) ? "aligned" : "stale",
    installed,
    expected,
    operation: unchanged ? "unchanged" : "update",
    files,
    reason: null,
  };
};

const rand = (): string => randomBytes(4).toString("hex");

/**
 * S1 §7.9.6: copy into `<parent>/.bea-skill-<rand>/`, then rename into place; an owned existing directory is first
 * renamed to `<dest>.bea-old-<rand>` and removed after the new one is in place (renamed back on failure).
 */
export const installSkill = async (inspection: SkillInspection): Promise<void> => {
  const parent = dirname(inspection.path);
  await mkdir(parent, { recursive: true });
  const staging = join(parent, `.bea-skill-${rand()}`);
  try {
    await cp(inspection.bundled, staging, { recursive: true, errorOnExist: true, force: false });
    if (inspection.state === "missing") {
      await rename(staging, inspection.path);
      return;
    }
    const old = `${inspection.path}.bea-old-${rand()}`;
    await rename(inspection.path, old);
    try {
      await rename(staging, inspection.path);
    } catch (cause: unknown) {
      await rename(old, inspection.path);
      throw cause;
    }
    await rm(old, { recursive: true, force: true });
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
};

/** Uninstall: rename aside, then delete (only ever called on an owned, non-symlink directory). */
export const removeSkill = async (inspection: SkillInspection): Promise<void> => {
  const old = `${inspection.path}.bea-old-${rand()}`;
  await rename(inspection.path, old);
  await rm(old, { recursive: true, force: true });
};
