// Types for scripts/lib/atomic.mjs.

export declare function makeStagingDir(label: string, root?: string): Promise<string>;
export declare function removeStagingDir(dir: string): Promise<void>;
export declare function publishFile(staged: string, dest: string): Promise<void>;
export declare function publishDir(staged: string, dest: string): Promise<void>;
export declare function writeFileAtomic(path: string, data: string | Uint8Array): Promise<void>;
