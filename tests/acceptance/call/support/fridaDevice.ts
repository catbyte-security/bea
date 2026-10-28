import { pidStatus } from "../../../support/process/ownedPidLedger.js";

/**
 * The local Frida device through a DeviceManager the test file OWNS (core acceptance change request: never
 * frida.getLocalDevice(), whose shared manager is never closed). Frida copies its agent DLLs (~45 MB) into
 * %TEMP%\frida-<id> and deletes them only at DeviceManager.close(), and only once no process still maps them: close
 * the manager after every target this file spawned has fully terminated (`waitGone`).
 */
export interface RawDevice {
  spawn(argv: string[], options: Record<string, unknown>): Promise<number>;
  attach(pid: number): Promise<RawSession>;
  resume(pid: number): Promise<void>;
  kill(pid: number): Promise<void>;
}
export interface RawSession {
  createScript(source: string, options: Record<string, unknown>): Promise<RawScript>;
  detach(): Promise<void>;
}
export interface RawScript {
  readonly message: {
    connect(handler: (message: { type: string; payload?: unknown; description?: string }) => void): void;
  };
  readonly exports: Record<string, (...args: unknown[]) => Promise<unknown>>;
  load(): Promise<void>;
  unload(): Promise<void>;
}
interface DeviceManager {
  getDeviceById(id: string, timeout: number): Promise<RawDevice>;
  close(): Promise<void>;
}

export interface OwnedDevice {
  readonly device: RawDevice;
  /** Close the manager; call after `waitGone` of every spawned target. */
  close(): Promise<void>;
}

export const openLocalDevice = async (): Promise<OwnedDevice> => {
  const mod = (await import("frida")) as unknown as { default?: unknown };
  const frida = (mod.default ?? mod) as { DeviceManager: new () => DeviceManager };
  const dm = new frida.DeviceManager();
  try {
    return { device: await dm.getDeviceById("local", 5000), close: () => dm.close() };
  } catch (cause) {
    await dm.close();
    throw cause;
  }
};

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Polls (25 ms) until the process object of `pid` is signaled (pidcheck `alive:false`; process.kill(pid, 0) reports
 * ESRCH about 10 ms too early) or `timeoutMs` passes. Returns whether it is gone.
 */
export const waitGone = async (pidcheck: string | null, pid: number, timeoutMs: number): Promise<boolean> => {
  const deadline = performance.now() + timeoutMs;
  for (;;) {
    let alive = true;
    try {
      alive = pidStatus(pidcheck, pid).alive;
    } catch {
      alive = true;
    }
    if (!alive) return true;
    if (performance.now() > deadline) return false;
    await sleep(25);
  }
};
