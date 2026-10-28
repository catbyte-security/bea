import { open, stat, type FileHandle } from "node:fs/promises";

import type { HostPlatform } from "../../domain/paths.js";
import { pathKey, type FileKey } from "../../domain/process/instance.js";
import { fsErrorKind, peFailure } from "./errors.js";

/**
 * Positioned reads on short-lived handles (S2 §17.2): open, read the needed ranges, close — game files stay
 * unlocked between calls. FileKey = (path_key, size, mtime_ns, ctime_ns, ino, dev) from a bigint stat; on NTFS a
 * content rewrite changes ctime_ns even when mtime is restored, and rename-replace changes ino [S2-lab E4].
 */
const keyPlatform = (platform: HostPlatform): "win32" | "linux" => (platform === "win32" ? "win32" : "linux");

const fileKeyOf = (
  path: string,
  st: { size: bigint; mtimeNs: bigint; ctimeNs: bigint; ino: bigint; dev: bigint },
  platform: HostPlatform,
): FileKey => ({
  path_key: pathKey(path, keyPlatform(platform)),
  size: String(st.size),
  mtime_ns: String(st.mtimeNs),
  ctime_ns: String(st.ctimeNs),
  ino: String(st.ino),
  dev: String(st.dev),
});

export const fileKeyString = (key: FileKey): string =>
  `${key.path_key}|${key.size}|${key.mtime_ns}|${key.ctime_ns}|${key.ino}|${key.dev}`;

export const sameFileKey = (a: FileKey, b: FileKey): boolean => fileKeyString(a) === fileKeyString(b);

/** stat → FileKey; a missing file or a directory is a PeFailure. */
export const statFileKey = async (path: string, platform: HostPlatform): Promise<FileKey> => {
  let st;
  try {
    st = await stat(path, { bigint: true });
  } catch (cause) {
    throw peFailure(fsErrorKind(cause), "The file could not be read.");
  }
  if (!st.isFile()) throw peFailure("not_found", "The path is not a regular file.");
  return fileKeyOf(path, st, platform);
};

/** An open handle with exact positioned reads. */
export interface FileReader {
  readonly size: number;
  /** exactly len bytes from offset (short reads are retried; past EOF is an io failure) */
  readAt(offset: number, len: number): Promise<Buffer>;
}

const checkAbort = (signal: AbortSignal | undefined): void => {
  if (signal?.aborted === true) throw peFailure("io", "The read was cancelled.");
};

/**
 * Open, verify the FileKey still matches `expected` (null: no check), run fn, close. A changed file is an io
 * failure ("changed on disk"): PeImageCache.open() re-parses on the next call.
 */
export const withFile = async <T>(
  path: string,
  platform: HostPlatform,
  expected: FileKey | null,
  fn: (reader: FileReader) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> => {
  checkAbort(signal);
  let handle: FileHandle;
  try {
    handle = await open(path, "r");
  } catch (cause) {
    throw peFailure(fsErrorKind(cause), "The file could not be opened.");
  }
  try {
    let st;
    try {
      st = await handle.stat({ bigint: true });
    } catch (cause) {
      throw peFailure(fsErrorKind(cause), "The file could not be read.");
    }
    if (expected !== null && !sameFileKey(fileKeyOf(path, st, platform), expected))
      throw peFailure("io", "The file changed on disk since it was parsed; retry the call.");
    const size = Number(st.size);
    const reader: FileReader = {
      size,
      readAt: async (offset, len) => {
        checkAbort(signal);
        if (offset < 0 || len < 0 || offset + len > size)
          throw peFailure("malformed", "A read ran past the end of the file.");
        const out = Buffer.alloc(len);
        let done = 0;
        while (done < len) {
          let n: number;
          try {
            ({ bytesRead: n } = await handle.read(out, done, len - done, offset + done));
          } catch (cause) {
            throw peFailure(fsErrorKind(cause), "The file could not be read.");
          }
          if (n === 0) throw peFailure("io", "The file shrank while it was read.");
          done += n;
        }
        return out;
      },
    };
    return await fn(reader);
  } finally {
    await handle.close().catch(() => undefined);
  }
};
