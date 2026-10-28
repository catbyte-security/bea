import { randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { dirname, join, posix, win32 } from "node:path";

import { z } from "zod";

import type { HostPlatform } from "../../domain/paths.js";

export const HTTP_CONNECTION_SCHEMA = "bea.http-connection/1";

export const httpConnectionSchema = z.strictObject({
  schema: z.literal(HTTP_CONNECTION_SCHEMA),
  url: z.string(),
  token: z.string(),
  pid: z.number().int().min(1).max(4_294_967_295),
  run_id: z.string(),
  started_at: z.string(),
  version: z.string(),
});
export type HttpConnection = z.infer<typeof httpConnectionSchema>;

/** Atomic publish (temp in the same dir + rename); directory 0700 and file 0600 on POSIX (Windows ignores modes). */
export const writeConnectionFile = async (path: string, connection: HttpConnection): Promise<void> => {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temp = join(dirname(path), `.bea-connection-${randomBytes(6).toString("hex")}.tmp`);
  try {
    const handle = await open(temp, "wx", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(connection, null, 2)}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temp, path);
  } catch (cause: unknown) {
    await rm(temp, { force: true }).catch(() => undefined);
    throw cause;
  }
};

/** The parsed connection file, or null when it is missing, unreadable or not a `bea.http-connection/1` document. */
export const readConnectionFile = async (path: string): Promise<HttpConnection | null> => {
  try {
    const parsed = httpConnectionSchema.safeParse(JSON.parse(await readFile(path, "utf8")));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
};

/** Remove only our own file (same run_id): a newer server may have replaced it. */
export const removeConnectionFile = async (path: string, runId: string): Promise<boolean> => {
  const current = await readConnectionFile(path);
  if (current?.run_id !== runId) return false;
  await rm(path, { force: true });
  return true;
};

/** True when `child` is `parent` or below it (case-insensitive on Windows; never via `..`). */
export const isWithinDirectory = (child: string, parent: string, platform: HostPlatform): boolean => {
  const api = platform === "win32" ? win32 : posix;
  const fold = (value: string): string =>
    platform === "win32" ? api.resolve(value).toLowerCase() : api.resolve(value);
  const rel = api.relative(fold(parent), fold(child));
  return rel === "" || (!rel.startsWith("..") && !api.isAbsolute(rel));
};

export type ConnectionLocationCheck = { readonly ok: true } | { readonly ok: false; readonly message: string };

/**
 * CT-M7 / §5.9: the connection file holds the bearer token. Inside the user profile its directory inherits the
 * profile's owner-only DACL; elsewhere (`BEA_HOME=D:\bea`, a shared `--connection-file`) the inherited DACL may let
 * other users read it. The design allows "set an owner-only DACL or refuse"; setting a DACL needs a child process
 * (icacls), which the module-boundary rules do not allow in the server layer yet (change request filed), so v0.1
 * refuses on Windows. POSIX relies on the 0700/0600 modes.
 */
export const checkConnectionLocation = (
  connectionFile: string,
  platform: HostPlatform,
  profileDir: string,
): ConnectionLocationCheck => {
  if (platform !== "win32") return { ok: true };
  const dir = win32.dirname(win32.resolve(connectionFile));
  if (isWithinDirectory(dir, profileDir, platform)) return { ok: true };
  return {
    ok: false,
    message:
      `the connection file directory ${dir} is outside your user profile (${profileDir}), so other accounts may be ` +
      "able to read the bearer token. Use a BEA_HOME (or --connection-file) inside your profile, e.g. the default " +
      "%LOCALAPPDATA%\\bea.",
  };
};
