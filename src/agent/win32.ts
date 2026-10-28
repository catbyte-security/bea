// =================================================================================================
// src/agent/win32.ts — WP3-AGENT native bindings (S4 §5.5): created lazily, cached, with EXPLICIT scheduling.
// Thread-control and memory-protection calls are `exclusive` (a cooperative SuspendThread/GetThreadContext deadlocked
// a run [ext-frida §3.7, a6d/a6e]); WaitForSingleObject is `cooperative` so the JS thread can run the ack receiver
// while a crashing or exiting thread waits (F12). Every handle opened here is closed in `finally` by the callers.
// =================================================================================================

type Scheduling = "exclusive" | "cooperative";
type AnyNative = (...args: never[]) => unknown;

const resolveExport = (module: string, name: string): NativePointer => {
  const m = Process.findModuleByName(module);
  const p = m?.findExportByName(name) ?? null;
  if (p === null) throw new Error(`unable to find export '${module}!${name}'`);
  return p;
};

export class Win32 {
  readonly #cache = new Map<string, unknown>();

  /** A cached NativeFunction for `module!name` (generic; features may bind more APIs through it). */
  bind<F extends AnyNative>(
    module: string,
    name: string,
    ret: NativeFunctionReturnType,
    args: NativeFunctionArgumentType[],
    scheduling: Scheduling = "exclusive",
  ): F {
    const key = `${module}!${name}/${scheduling}`;
    let fn = this.#cache.get(key);
    if (fn === undefined) {
      fn = new NativeFunction(resolveExport(module, name), ret, args, { scheduling });
      this.#cache.set(key, fn);
    }
    return fn as F;
  }

  /** The address of an export (no binding). */
  address(module: string, name: string): NativePointer | null {
    return Process.findModuleByName(module)?.findExportByName(name) ?? null;
  }

  get CreateEventW(): (attrs: NativePointer, manual: number, initial: number, name: NativePointer) => NativePointer {
    return this.bind("kernelbase.dll", "CreateEventW", "pointer", ["pointer", "int", "int", "pointer"]);
  }

  get SetEvent(): (h: NativePointer) => number {
    return this.bind("kernelbase.dll", "SetEvent", "int", ["pointer"]);
  }

  get CloseHandle(): (h: NativePointer) => number {
    return this.bind("kernelbase.dll", "CloseHandle", "int", ["pointer"]);
  }

  /** Cooperative: releases the JS lock while waiting (F12). */
  get WaitForSingleObject(): (h: NativePointer, ms: number) => number {
    return this.bind("kernelbase.dll", "WaitForSingleObject", "uint32", ["pointer", "uint32"], "cooperative");
  }

  get OpenThread(): (access: number, inherit: number, tid: number) => NativePointer {
    return this.bind("kernelbase.dll", "OpenThread", "pointer", ["uint32", "int", "uint32"]);
  }

  get SuspendThread(): (h: NativePointer) => number {
    return this.bind("kernelbase.dll", "SuspendThread", "uint32", ["pointer"]);
  }

  get ResumeThread(): (h: NativePointer) => number {
    return this.bind("kernelbase.dll", "ResumeThread", "uint32", ["pointer"]);
  }

  get GetThreadContext(): (h: NativePointer, ctx: NativePointer) => number {
    return this.bind("kernelbase.dll", "GetThreadContext", "int", ["pointer", "pointer"]);
  }

  get NtQueryInformationThread(): (
    h: NativePointer,
    cls: number,
    buf: NativePointer,
    len: number,
    ret: NativePointer,
  ) => number {
    return this.bind("ntdll.dll", "NtQueryInformationThread", "uint32", [
      "pointer",
      "uint32",
      "pointer",
      "uint32",
      "pointer",
    ]);
  }

  get GetThreadDescription(): (h: NativePointer, out: NativePointer) => number {
    return this.bind("kernelbase.dll", "GetThreadDescription", "int32", ["pointer", "pointer"]);
  }

  get LocalFree(): (p: NativePointer) => NativePointer {
    return this.bind("kernelbase.dll", "LocalFree", "pointer", ["pointer"]);
  }

  get VirtualQuery(): (addr: NativePointer, mbi: NativePointer, len: number) => UInt64 {
    return this.bind("kernelbase.dll", "VirtualQuery", "size_t", ["pointer", "pointer", "size_t"]);
  }

  get VirtualProtect(): (addr: NativePointer, size: number, prot: number, old: NativePointer) => number {
    return this.bind("kernelbase.dll", "VirtualProtect", "int", ["pointer", "size_t", "uint32", "pointer"]);
  }

  get VirtualAlloc(): (addr: NativePointer, size: number, type: number, prot: number) => NativePointer {
    return this.bind("kernelbase.dll", "VirtualAlloc", "pointer", ["pointer", "size_t", "uint32", "uint32"]);
  }

  get VirtualFree(): (addr: NativePointer, size: number, type: number) => number {
    return this.bind("kernelbase.dll", "VirtualFree", "int", ["pointer", "size_t", "uint32"]);
  }

  get NtQueryKey(): (h: NativePointer, cls: number, buf: NativePointer, len: number, ret: NativePointer) => number {
    return this.bind("ntdll.dll", "NtQueryKey", "uint32", ["pointer", "uint32", "pointer", "uint32", "pointer"]);
  }

  get GetLastError(): () => number {
    return this.bind("kernelbase.dll", "GetLastError", "uint32", []);
  }
}
