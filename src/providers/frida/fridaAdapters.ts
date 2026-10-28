import type * as Frida from "frida";

import type {
  CancellableLike,
  FridaDeviceLike,
  FridaDeviceManagerLike,
  FridaModuleLike,
  FridaProcessLike,
  FridaScriptLike,
  FridaSessionLike,
} from "./fridaPorts.js";

/**
 * Vendor → port adapters (S3 §4.1). TypeScript string enums (Stdio, ScriptRuntime, Scope, MessageType, LogLevel,
 * SessionDetachReason) block structural assignment of the vendor classes to the ports; every cast lives here and the
 * enum values come from the loaded module (never a runtime import of frida outside fridaLoader.ts). Cancellables are
 * the binding's own class: frida.js pops a trailing argument only when it is `instanceof Cancellable`.
 */
type FridaNamespace = typeof Frida;

const asVendorCancellable = (token: CancellableLike | null | undefined): Frida.Cancellable | null =>
  (token ?? null) as Frida.Cancellable | null;

const adaptScript = (script: Frida.Script): FridaScriptLike => script as unknown as FridaScriptLike;

const adaptSession = (frida: FridaNamespace, session: Frida.Session): FridaSessionLike => ({
  get pid() {
    return session.pid;
  },
  isDetached: () => session.isDetached(),
  detach: (cancellable) => session.detach(asVendorCancellable(cancellable)),
  createScript: async (source, options, cancellable) =>
    adaptScript(
      await session.createScript(
        source,
        {
          name: options.name,
          runtime: options.runtime === "v8" ? frida.ScriptRuntime.V8 : frida.ScriptRuntime.QJS,
        },
        asVendorCancellable(cancellable),
      ),
    ),
  detached: session.detached as unknown as FridaSessionLike["detached"],
});

const adaptProcess = (process: Frida.Process): FridaProcessLike => ({
  pid: process.pid,
  name: process.name,
  parameters: process.parameters as Readonly<Record<string, unknown>>,
});

const adaptDevice = (frida: FridaNamespace, vendor: Frida.Device): FridaDeviceLike => ({
  id: vendor.id,
  spawn: (argv, options) =>
    vendor.spawn([...argv], {
      envp: { ...options.envp },
      cwd: options.cwd,
      stdio: options.stdio === "pipe" ? frida.Stdio.Pipe : frida.Stdio.Inherit,
    }),
  resume: (pid) => vendor.resume(pid),
  kill: (pid) => vendor.kill(pid),
  attach: async (pid, cancellable) =>
    adaptSession(frida, await vendor.attach(pid, {}, asVendorCancellable(cancellable))),
  enumerateProcesses: async (options, cancellable) =>
    (
      await vendor.enumerateProcesses(
        { scope: options.scope === "metadata" ? frida.Scope.Metadata : frida.Scope.Minimal },
        asVendorCancellable(cancellable),
      )
    ).map(adaptProcess),
  querySystemParameters: async (cancellable) =>
    (await vendor.querySystemParameters(asVendorCancellable(cancellable))) as Readonly<Record<string, unknown>>,
  output: vendor.output as unknown as FridaDeviceLike["output"],
});

const adaptDeviceManager = (frida: FridaNamespace, manager: Frida.DeviceManager): FridaDeviceManagerLike => ({
  getDeviceById: async (id, timeoutMs, cancellable) =>
    adaptDevice(frida, await manager.getDeviceById(id, timeoutMs, asVendorCancellable(cancellable))),
  close: (cancellable) => manager.close(asVendorCancellable(cancellable)),
});

/** The loaded binding as the provider sees it (fridaLoader.ts is the only caller). */
export const adaptFridaModule = (frida: FridaNamespace, version: string): FridaModuleLike => ({
  version,
  createDeviceManager: () => adaptDeviceManager(frida, new frida.DeviceManager()),
  createCancellable: () => new frida.Cancellable(),
});
