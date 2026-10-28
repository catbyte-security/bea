import type { ExceptionType } from "../shared/agentProtocol.js";
import { hexToByteArray, SEH_PAGE, SEH_PAGE_HEX } from "./pure/callBlock.js";

/**
 * The oracle thunk as a REGISTERED SEH FRAME (DESIGN §5.3.1, CT-B1/B2; VERIFIED [REV-lab R1]). The verified page is
 * written once at feature init, its handler's imm64 patched with ntdll!RtlUnwindEx, and its two RUNTIME_FUNCTIONs
 * registered with RtlAddFunctionTable (BaseAddress = page). Calls go through NativeFunction(page, "void",
 * ["pointer"], {exceptions: "propagate"}) with cooperative scheduling: the callee's own SEH/C++ handlers run first,
 * BEA's DR/guard traps reach the single dispatcher, and only an exception nobody handles unwinds to the thunk's
 * recovery label (CallBlock status 2). If registration fails the thunk falls back to exceptions:"steal"
 * (exception_model "steal", limitation CALL_SEH_UNAVAILABLE).
 *
 * The page comes from VirtualAlloc, not Memory.alloc: Frida frees its heap on unload, and a registered function
 * table over freed memory would hand garbage unwind data to the OS dispatcher. With VirtualAlloc a missed dispose
 * leaves a valid (leaked, 4 KiB) frame; disposeThunk() deletes the table and frees the page when the core calls it.
 */
type ExceptionModel = "seh-frame" | "steal";

export interface Thunk {
  readonly model: ExceptionModel;
  readonly page: NativePointer;
  /** void thunk(CallBlock*) */
  readonly call: NativeFunction<void, [NativePointerValue]>;
  /** the same entry with traps:"all" (per-call Stalker coverage, S4 §13.5) */
  readonly callTraced: NativeFunction<void, [NativePointerValue]>;
  /** S5 FP-env restore stub (belt and braces after a stolen fault in the steal fallback) */
  readonly restoreEnv: NativeFunction<void, [NativePointerValue]>;
  /** S5 FP-env read stub: stmxcsr [rcx]; fnstcw [rcx+4] (the calling thread's environment) */
  readonly readEnv: NativeFunction<void, [NativePointerValue]>;
}

const MEM_COMMIT_RESERVE = 0x3000;
const MEM_RELEASE = 0x8000;
const PAGE_EXECUTE_READWRITE = 0x40;

/** Module scope keeps every native allocation reachable (QJS freed a local code page: VERIFIED). */
let installed: Thunk | null = null;
let tableRegistered = false;

const exportOf = (module: string, name: string): NativePointer => Process.getModuleByName(module).getExportByName(name);

export function installThunk(): Thunk {
  if (installed !== null) return installed;
  const virtualAlloc = new NativeFunction(
    exportOf("kernel32.dll", "VirtualAlloc"),
    "pointer",
    ["pointer", "size_t", "uint32", "uint32"],
    {
      scheduling: "exclusive",
    },
  );
  const page = virtualAlloc(NULL, Process.pageSize, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
  if (page.isNull()) throw new Error("VirtualAlloc failed for the oracle thunk page");
  page.writeByteArray(hexToByteArray(SEH_PAGE_HEX));
  page.add(SEH_PAGE.rtlUnwindExImm).writePointer(exportOf("ntdll.dll", "RtlUnwindEx"));
  let model: ExceptionModel = "steal";
  try {
    const rtlAddFunctionTable = new NativeFunction(
      exportOf("ntdll.dll", "RtlAddFunctionTable"),
      "uint8",
      ["pointer", "uint32", "pointer"],
      {
        scheduling: "exclusive",
      },
    );
    tableRegistered = rtlAddFunctionTable(page.add(SEH_PAGE.table), SEH_PAGE.tableEntries, page) !== 0;
    model = tableRegistered ? "seh-frame" : "steal";
  } catch {
    model = "steal";
  }
  const exceptions = model === "seh-frame" ? "propagate" : "steal";
  installed = {
    model,
    page,
    call: new NativeFunction(page, "void", ["pointer"], { exceptions }),
    callTraced: new NativeFunction(page, "void", ["pointer"], { exceptions, traps: "all" }),
    restoreEnv: new NativeFunction(page.add(SEH_PAGE.restoreStub), "void", ["pointer"], { exceptions: "steal" }),
    readEnv: new NativeFunction(page.add(SEH_PAGE.readStub), "void", ["pointer"], { exceptions: "steal" }),
  };
  return installed;
}

/** RtlDeleteFunctionTable + VirtualFree (agent dispose); safe to call twice. */
export function disposeThunk(): void {
  if (installed === null) return;
  const page = installed.page;
  installed = null;
  try {
    if (tableRegistered)
      new NativeFunction(exportOf("ntdll.dll", "RtlDeleteFunctionTable"), "uint8", ["pointer"], {
        scheduling: "exclusive",
      })(page.add(SEH_PAGE.table));
    tableRegistered = false;
    new NativeFunction(exportOf("kernel32.dll", "VirtualFree"), "int", ["pointer", "size_t", "uint32"], {
      scheduling: "exclusive",
    })(page, 0, MEM_RELEASE);
  } catch {
    // unload path: never throw out of dispose
  }
}

/** NTSTATUS of a Frida exception type (steal fallback: the JS error carries the type, not the code). */
export const CODE_OF_TYPE: Readonly<Partial<Record<ExceptionType, number>>> = {
  "access-violation": 0xc0000005,
  "guard-page": 0x80000001,
  "illegal-instruction": 0xc000001d,
  "stack-overflow": 0xc00000fd,
  arithmetic: 0xc0000094,
  breakpoint: 0x80000003,
  "single-step": 0x80000004,
  abort: 0xc0000409,
};
