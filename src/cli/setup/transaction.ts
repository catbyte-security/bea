import { createHash, randomBytes } from "node:crypto";
import { link, lstat, open, readFile, rename, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

export type PublishFailure = "symlink" | "target_changed" | "backup" | "write" | "readback" | "rollback";

export interface FileSnapshot {
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly mode: number;
}

export interface PublishResult {
  readonly ok: boolean;
  readonly failure?: PublishFailure;
  readonly backupPath: string | null;
  readonly recoveryPath: string | null;
}

const sha256 = (bytes: Buffer | string): string => createHash("sha256").update(bytes).digest("hex");

const code = (cause: unknown): string | undefined =>
  typeof cause === "object" && cause !== null ? (Reflect.get(cause, "code") as string | undefined) : undefined;

/** Read the current file (null when absent). Refuses symlinks: BEA never edits through a link. */
export const snapshotFile = async (path: string): Promise<FileSnapshot | null | "symlink"> => {
  try {
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) return "symlink";
    const bytes = await readFile(path);
    return { bytes, sha256: sha256(bytes), mode: stat.mode & 0o777 };
  } catch (cause: unknown) {
    if (code(cause) === "ENOENT") return null;
    throw cause;
  }
};

const writeExclusive = async (path: string, data: Buffer | string, mode: number): Promise<void> => {
  const handle = await open(path, "wx", mode);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
};

/**
 * One client file transaction (REA ClientConfigurationPublication, simplified):
 * re-check the planned snapshot -> one-time `<file>.bea.backup` (never replaced;
 * a differing one gets a content-addressed `.recovery` copy) -> temp in the same
 * directory (O_EXCL) + fsync -> rename (update) or link (create; cannot clobber a
 * concurrently created file) -> read back and verify -> roll back on mismatch.
 */
export const publishConfigFile = async (
  path: string,
  planned: FileSnapshot | null,
  next: string,
  verify: (text: string) => boolean,
): Promise<PublishResult> => {
  const current = await snapshotFile(path);
  if (current === "symlink") return { ok: false, failure: "symlink", backupPath: null, recoveryPath: null };
  if ((current?.sha256 ?? null) !== (planned?.sha256 ?? null))
    return { ok: false, failure: "target_changed", backupPath: null, recoveryPath: null };

  let backupPath: string | null = null;
  let recoveryPath: string | null = null;
  if (current !== null) {
    backupPath = `${path}.bea.backup`;
    try {
      await writeExclusive(backupPath, current.bytes, current.mode);
    } catch (cause: unknown) {
      if (code(cause) !== "EEXIST") return { ok: false, failure: "backup", backupPath: null, recoveryPath: null };
      const existing = await readFile(backupPath);
      if (sha256(existing) !== current.sha256) {
        recoveryPath = `${path}.bea.backup.${current.sha256.slice(0, 12)}.recovery`;
        try {
          await writeExclusive(recoveryPath, current.bytes, current.mode);
        } catch (inner: unknown) {
          if (code(inner) !== "EEXIST") return { ok: false, failure: "backup", backupPath, recoveryPath: null };
        }
      }
    }
  }

  const temp = join(dirname(path), `.bea-config-${randomBytes(6).toString("hex")}.tmp`);
  try {
    await writeExclusive(temp, next, current?.mode ?? 0o600);
    if (current !== null) await rename(temp, path);
    else {
      await link(temp, path);
      await unlink(temp);
    }
  } catch {
    await unlink(temp).catch(() => undefined);
    return { ok: false, failure: "write", backupPath, recoveryPath };
  }

  const written = await readFile(path, "utf8").catch(() => null);
  if (written !== null && sha256(written) === sha256(next) && verify(written))
    return { ok: true, backupPath, recoveryPath };

  // Roll back: restore the snapshot bytes, or remove a file we created (only if it is still ours).
  try {
    if (current !== null) {
      const restore = join(dirname(path), `.bea-restore-${basename(path)}-${randomBytes(4).toString("hex")}.tmp`);
      await writeExclusive(restore, current.bytes, current.mode);
      await rename(restore, path);
    } else if (written !== null && sha256(written) === sha256(next)) {
      await unlink(path);
    }
  } catch {
    return { ok: false, failure: "rollback", backupPath, recoveryPath };
  }
  return { ok: false, failure: "readback", backupPath, recoveryPath };
};
