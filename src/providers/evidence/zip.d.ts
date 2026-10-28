/**
 * Minimal type declarations for yazl 3.3.1 and yauzl 3.4.0 (neither ships types; only the API BundleZip uses).
 * Owned by WP-EVID (src/providers/evidence/**); verify against node_modules/{yazl,yauzl}/README.md when bumping.
 */
declare module "yazl" {
  import type { Readable } from "node:stream";

  export interface EntryOptions {
    readonly mtime?: Date;
    readonly mode?: number;
    readonly compress?: boolean;
    readonly compressionLevel?: number;
    readonly forceZip64Format?: boolean;
    readonly forceDosTimestamp?: boolean;
  }
  export class ZipFile {
    constructor();
    addFile(realPath: string, metadataPath: string, options?: EntryOptions | null): void;
    addBuffer(buffer: Buffer, metadataPath: string, options?: EntryOptions | null): void;
    addReadStream(readStream: Readable, metadataPath: string, options?: EntryOptions | null): void;
    end(
      options?: { readonly forceZip64Format?: boolean } | null,
      calculatedTotalSizeCallback?: (size: number) => void,
    ): void;
    readonly outputStream: Readable;
  }
}

declare module "yauzl" {
  import type { EventEmitter } from "node:events";
  import type { Readable } from "node:stream";

  export interface OpenOptions {
    readonly autoClose?: boolean;
    readonly lazyEntries?: boolean;
    readonly decodeStrings?: boolean;
    readonly validateEntrySizes?: boolean;
    readonly strictFileNames?: boolean;
  }
  export class Entry {
    readonly fileName: string;
    readonly compressedSize: number;
    readonly uncompressedSize: number;
    readonly compressionMethod: number;
    readonly externalFileAttributes: number;
    isEncrypted(): boolean;
    isCompressed(): boolean;
  }
  export class ZipFile extends EventEmitter {
    readonly entryCount: number;
    /** total size of the archive file in bytes */
    readonly fileSize: number;
    readonly isOpen: boolean;
    eachEntry(): AsyncIterableIterator<Entry>;
    openReadStreamPromise(entry: Entry, options?: { readonly decompress?: boolean | null }): Promise<Readable>;
    close(): void;
  }
  export function openPromise(path: string, options?: OpenOptions): Promise<ZipFile>;
  export function validateFileName(fileName: string): string | null;
}
