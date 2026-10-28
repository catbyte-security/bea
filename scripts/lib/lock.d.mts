// Types for scripts/lib/lock.mjs.

export interface HeldLock {
  readonly name: string;
  readonly token: string;
  /** True when this process (or the parent build that spawned it) already held the lock. */
  readonly reentrant: boolean;
  readonly release: () => void;
}

export interface LockOptions {
  /** Repository root whose build/.locks/ holds the lock (default: this checkout). */
  readonly root?: string;
  readonly timeoutMs?: number;
  readonly log?: (line: string) => void;
  /** Shown to waiters (default: this process's command line). */
  readonly command?: string;
}

export declare const REPO_ROOT: string;
export declare const lockTokenEnv: (name: string) => string;
export declare function acquireLock(name: string, options?: LockOptions): Promise<HeldLock>;
export declare function withLock<T>(
  name: string,
  fn: (lock: HeldLock) => Promise<T> | T,
  options?: LockOptions,
): Promise<T>;
export declare const withBuildLock: <T>(fn: (lock: HeldLock) => Promise<T> | T, options?: LockOptions) => Promise<T>;
