// =================================================================================================
// src/shared/apiProfiles.ts — API behavior profile catalog (S4 §10.5 + S6 §6). WP-BEHAVIOR owns this file.
// Staged into the agent build (frida.Compiler) and imported by the host decoders; no imports beyond the protocol.
// The wire carries `ApiRow.api` = ApiSpec.id: ids are stable and never reused (sparse by family, S4 §10.5).
// =================================================================================================
import type { ApiProfileName } from "./agentProtocol.js";
import type { Hex } from "./hex.js";

export type ApiModule = "ntdll.dll" | "kernelbase.dll" | "ws2_32.dll" | "dnsapi.dll" | "winhttp.dll" | "wininet.dll";
/** Handle-cache kinds (S4 §10.6). */
export type HandleKind = "file" | "key" | "socket" | "process" | "thread" | "section" | "inet" | "module";

/**
 * How the agent decodes one argument (S4 §10.5). Every decoder writes FLAT keys into ApiRow.args (ValueCell values
 * only, never nested objects); the key names per decoder are fixed by `decoderKeys` below so host and agent agree.
 */
export type ArgDecoder =
  | { readonly k: "u32" }
  | { readonly k: "i32" }
  | { readonly k: "u64" }
  | { readonly k: "ptr" }
  | { readonly k: "bool" }
  | { readonly k: "handle"; readonly kind: HandleKind } // value + `<name>_name` from the handle cache
  | { readonly k: "out_handle"; readonly kind: HandleKind } // PHANDLE read at leave (success); cache insert
  | { readonly k: "wstr"; readonly max: number }
  | { readonly k: "astr"; readonly max: number }
  | { readonly k: "ustr"; readonly max: number } // PUNICODE_STRING (nullable)
  | { readonly k: "oa"; readonly kind: "file" | "key" } // POBJECT_ATTRIBUTES → path (root joined), `_root`, `_attr`
  | { readonly k: "iosb" } // PIO_STATUS_BLOCK → Information at leave
  | { readonly k: "inout_ptr" } // PVOID*: value at enter, `<name>_out` at leave
  | { readonly k: "inout_size" } // PSIZE_T: value at enter, `<name>_out` at leave
  | { readonly k: "out_u32" } // PULONG at leave
  | { readonly k: "out_ptr" } // PVOID* at leave
  | { readonly k: "i64ptr" } // PLARGE_INTEGER at enter (value or null)
  | { readonly k: "client_id" } // PCLIENT_ID → `_pid`, `_tid`
  | { readonly k: "proc_params" } // PRTL_USER_PROCESS_PARAMETERS → `_image`, `_cmdline`, `_cwd`
  | { readonly k: "proc_info_out" } // LPPROCESS_INFORMATION at leave → `_pid`, `_tid`
  | { readonly k: "loadpath" } // LdrLoadDll arg0: odd → `_flags`; else PWSTR search path
  | { readonly k: "procname" } // PANSI_STRING name, or null → `_ordinal` from ProcedureNumber
  | { readonly k: "sockaddr"; readonly len_arg: number } // `_family`, `_addr`, `_port`
  | { readonly k: "out_sockaddr" } // same keys, at leave
  | { readonly k: "wsabufs"; readonly count_arg: number; readonly when: "enter" | "leave" } // `_len` total bytes
  | {
      readonly k: "buf";
      readonly len_arg: number;
      readonly when: "enter" | "leave";
      readonly len_from: "arg" | "ret" | "iosb" | "out_arg";
      readonly out_arg?: number;
    } // `_len` bytes (payload hex only when capture bytes > 0)
  | { readonly k: "fileinfo"; readonly class_arg: number; readonly len_arg: number } // by class (see decoderKeys)
  | { readonly k: "regdata"; readonly type_arg: number; readonly size_arg: number } // `_type`, `_size`
  | { readonly k: "kvinfo"; readonly class_arg: number } // NtQueryValueKey output at leave → `_type`, `_size`
  | { readonly k: "addrinfo_out"; readonly ex: boolean } // `_count`, `_addr0..7` at leave (rc == 0)
  | { readonly k: "dnsreq" }; // PDNS_QUERY_REQUEST → `_name`, `_type`

export interface ApiArgSpec {
  /** Win64 positional slot (0-based). */
  readonly slot: number;
  /** Base key in ApiRow.args. */
  readonly name: string;
  readonly d: ArgDecoder;
}

export type ApiSub =
  | "core"
  | "io"
  | "track_handles"
  | "enumerate"
  | "query_key"
  | "resolve_procedures"
  | "frees"
  | "sections"
  | "dns"
  | "http"
  | "cross_process_memory"
  | "apc_and_context";
export type ApiRet = "ntstatus" | "bool32" | "handle" | "ptr" | "i32" | "u32" | "socket" | "void";

export interface ApiSpec {
  /** Stable wire id carried in ApiRow.api (never reused). */
  readonly id: number;
  readonly profile: ApiProfileName;
  readonly sub: ApiSub;
  readonly module: ApiModule;
  readonly export: string;
  /** Normalized operation (S6 §6); the host may refine it (create/open from IoStatus, rename/delete by class). */
  readonly op: string;
  readonly args: readonly ApiArgSpec[];
  readonly ret: ApiRet;
  readonly volume: "low" | "medium" | "high";
  /** Selected when the sub-option is unset (S4 §10.6 step 1). */
  readonly default_on: boolean;
  /** Emit only when the argument compares as given (e.g. remote-process filters). */
  readonly emit_when?: { readonly arg: string; readonly op: "eq" | "ne"; readonly value: Hex };
  /** Self-terminate style calls: emit at enter (ret null). */
  readonly noreturn_when?: { readonly arg: string; readonly op: "eq"; readonly value: Hex };
  /** false = cache maintenance only (NtClose). */
  readonly rows: boolean;
  /** Missing module → pending (installed from the module observer) instead of failed. */
  readonly lazy_module: boolean;
  /** S4 lab status: hooked+decoded, hooked only, or believed (argument layout from SDK headers, lab check A-21). */
  readonly verified: "hooked+decoded" | "hooked" | "believed";
}

/** Bump on any additive change to API_CATALOG; the host records it in stream descriptors. */
export const API_CATALOG_MINOR = 0 as const;

// ---------------------------------------------------------------------------------------------- builders
const a = (slot: number, name: string, d: ArgDecoder): ApiArgSpec => ({ slot, name, d });
const u32 = { k: "u32" } as const;
const i32 = { k: "i32" } as const;
const u64 = { k: "u64" } as const;
const ptrD = { k: "ptr" } as const;
const boolD = { k: "bool" } as const;
const h = (kind: HandleKind): ArgDecoder => ({ k: "handle", kind });
const outH = (kind: HandleKind): ArgDecoder => ({ k: "out_handle", kind });
const ustr: ArgDecoder = { k: "ustr", max: 1024 };
const wstr = (max = 1024): ArgDecoder => ({ k: "wstr", max });
type SpecInit = Omit<ApiSpec, "rows" | "lazy_module" | "default_on" | "volume"> &
  Partial<Pick<ApiSpec, "rows" | "lazy_module" | "default_on" | "volume">>;
const spec = (s: SpecInit): ApiSpec => ({
  rows: true,
  lazy_module: s.module !== "ntdll.dll" && s.module !== "kernelbase.dll",
  default_on: s.sub === "core" || s.sub === "track_handles" || s.sub === "dns",
  volume: "medium",
  ...s,
});

const SELF_PROCESS: Hex = "0xffffffffffffffff";

/** The v0.1 catalog (S4 §10.5 table; ids are wire ids). */
export const API_CATALOG: readonly ApiSpec[] = [
  // ------------------------------------------------------------------ file
  spec({
    id: 1,
    profile: "file",
    sub: "core",
    module: "ntdll.dll",
    export: "NtCreateFile",
    op: "create",
    args: [
      a(0, "handle", outH("file")),
      a(1, "access", u32),
      a(2, "path", { k: "oa", kind: "file" }),
      a(3, "iosb", { k: "iosb" }),
      a(5, "attributes", u32),
      a(6, "share", u32),
      a(7, "disposition", u32),
      a(8, "options", u32),
    ],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 2,
    profile: "file",
    sub: "core",
    module: "ntdll.dll",
    export: "NtOpenFile",
    op: "open",
    args: [
      a(0, "handle", outH("file")),
      a(1, "access", u32),
      a(2, "path", { k: "oa", kind: "file" }),
      a(3, "iosb", { k: "iosb" }),
      a(4, "share", u32),
      a(5, "options", u32),
    ],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 3,
    profile: "file",
    sub: "core",
    module: "ntdll.dll",
    export: "NtQueryAttributesFile",
    op: "stat",
    args: [a(0, "path", { k: "oa", kind: "file" })],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 4,
    profile: "file",
    sub: "core",
    module: "ntdll.dll",
    export: "NtQueryFullAttributesFile",
    op: "stat",
    args: [a(0, "path", { k: "oa", kind: "file" })],
    ret: "ntstatus",
    verified: "hooked",
  }),
  spec({
    id: 5,
    profile: "file",
    sub: "core",
    module: "ntdll.dll",
    export: "NtSetInformationFile",
    op: "set_info",
    args: [
      a(0, "handle", h("file")),
      a(2, "info", { k: "fileinfo", class_arg: 4, len_arg: 3 }),
      a(3, "length", u32),
      a(4, "class", u32),
    ],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 6,
    profile: "file",
    sub: "core",
    module: "ntdll.dll",
    export: "NtQueryDirectoryFileEx",
    op: "list",
    args: [
      a(0, "handle", h("file")),
      a(6, "length", u32),
      a(7, "class", u32),
      a(8, "flags", u32),
      a(9, "pattern", ustr),
    ],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 7,
    profile: "file",
    sub: "core",
    module: "ntdll.dll",
    export: "NtQueryDirectoryFile",
    op: "list",
    args: [
      a(0, "handle", h("file")),
      a(6, "length", u32),
      a(7, "class", u32),
      a(8, "single", boolD),
      a(9, "pattern", ustr),
      a(10, "restart", boolD),
    ],
    ret: "ntstatus",
    verified: "hooked",
  }),
  spec({
    id: 8,
    profile: "file",
    sub: "core",
    module: "ntdll.dll",
    export: "NtDeleteFile",
    op: "delete",
    args: [a(0, "path", { k: "oa", kind: "file" })],
    ret: "ntstatus",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 9,
    profile: "file",
    sub: "io",
    module: "ntdll.dll",
    export: "NtReadFile",
    op: "read",
    args: [
      a(0, "handle", h("file")),
      a(4, "iosb", { k: "iosb" }),
      a(5, "buffer", { k: "buf", len_arg: 6, when: "leave", len_from: "iosb" }),
      a(6, "length", u32),
      a(7, "offset", { k: "i64ptr" }),
    ],
    ret: "ntstatus",
    volume: "high",
    verified: "hooked+decoded",
  }),
  spec({
    id: 10,
    profile: "file",
    sub: "io",
    module: "ntdll.dll",
    export: "NtWriteFile",
    op: "write",
    args: [
      a(0, "handle", h("file")),
      a(4, "iosb", { k: "iosb" }),
      a(5, "buffer", { k: "buf", len_arg: 6, when: "enter", len_from: "arg" }),
      a(6, "length", u32),
      a(7, "offset", { k: "i64ptr" }),
    ],
    ret: "ntstatus",
    volume: "high",
    verified: "hooked+decoded",
  }),
  spec({
    id: 11,
    profile: "file",
    sub: "track_handles",
    module: "ntdll.dll",
    export: "NtClose",
    op: "close",
    args: [a(0, "handle", ptrD)],
    ret: "ntstatus",
    volume: "high",
    rows: false,
    verified: "hooked",
  }),
  // ------------------------------------------------------------------ registry
  spec({
    id: 20,
    profile: "registry",
    sub: "core",
    module: "ntdll.dll",
    export: "NtOpenKey",
    op: "open",
    args: [a(0, "handle", outH("key")), a(1, "access", u32), a(2, "key", { k: "oa", kind: "key" })],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 21,
    profile: "registry",
    sub: "core",
    module: "ntdll.dll",
    export: "NtOpenKeyEx",
    op: "open",
    args: [
      a(0, "handle", outH("key")),
      a(1, "access", u32),
      a(2, "key", { k: "oa", kind: "key" }),
      a(3, "options", u32),
    ],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 22,
    profile: "registry",
    sub: "core",
    module: "ntdll.dll",
    export: "NtCreateKey",
    op: "create",
    args: [
      a(0, "handle", outH("key")),
      a(1, "access", u32),
      a(2, "key", { k: "oa", kind: "key" }),
      a(5, "options", u32),
      a(6, "disposition", { k: "out_u32" }),
    ],
    ret: "ntstatus",
    volume: "low",
    verified: "hooked",
  }),
  spec({
    id: 23,
    profile: "registry",
    sub: "core",
    module: "ntdll.dll",
    export: "NtQueryValueKey",
    op: "query_value",
    args: [
      a(0, "handle", h("key")),
      a(1, "value", ustr),
      a(2, "class", u32),
      a(3, "info", { k: "kvinfo", class_arg: 2 }),
      a(4, "length", u32),
    ],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 24,
    profile: "registry",
    sub: "core",
    module: "ntdll.dll",
    export: "NtSetValueKey",
    op: "set_value",
    args: [
      a(0, "handle", h("key")),
      a(1, "value", ustr),
      a(3, "type", u32),
      a(4, "data", { k: "regdata", type_arg: 3, size_arg: 5 }),
      a(5, "size", u32),
    ],
    ret: "ntstatus",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 25,
    profile: "registry",
    sub: "core",
    module: "ntdll.dll",
    export: "NtDeleteKey",
    op: "delete_key",
    args: [a(0, "handle", h("key"))],
    ret: "ntstatus",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 26,
    profile: "registry",
    sub: "core",
    module: "ntdll.dll",
    export: "NtDeleteValueKey",
    op: "delete_value",
    args: [a(0, "handle", h("key")), a(1, "value", ustr)],
    ret: "ntstatus",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 27,
    profile: "registry",
    sub: "core",
    module: "ntdll.dll",
    export: "NtRenameKey",
    op: "rename_key",
    args: [a(0, "handle", h("key")), a(1, "new_name", ustr)],
    ret: "ntstatus",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 28,
    profile: "registry",
    sub: "enumerate",
    module: "ntdll.dll",
    export: "NtEnumerateKey",
    op: "enum",
    args: [a(0, "handle", h("key")), a(1, "index", u32), a(2, "class", u32), a(4, "length", u32)],
    ret: "ntstatus",
    verified: "believed",
  }),
  spec({
    id: 29,
    profile: "registry",
    sub: "enumerate",
    module: "ntdll.dll",
    export: "NtEnumerateValueKey",
    op: "enum_values",
    args: [a(0, "handle", h("key")), a(1, "index", u32), a(2, "class", u32), a(4, "length", u32)],
    ret: "ntstatus",
    verified: "believed",
  }),
  spec({
    id: 30,
    profile: "registry",
    sub: "query_key",
    module: "ntdll.dll",
    export: "NtQueryKey",
    op: "query_key",
    args: [a(0, "handle", h("key")), a(1, "class", u32), a(3, "length", u32)],
    ret: "ntstatus",
    volume: "high",
    verified: "hooked+decoded",
  }),
  // ------------------------------------------------------------------ module_load
  spec({
    id: 40,
    profile: "module_load",
    sub: "core",
    module: "ntdll.dll",
    export: "LdrLoadDll",
    op: "load_request",
    args: [a(0, "search", { k: "loadpath" }), a(2, "name", ustr), a(3, "base", { k: "out_ptr" })],
    ret: "ntstatus",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 41,
    profile: "module_load",
    sub: "core",
    module: "ntdll.dll",
    export: "LdrUnloadDll",
    op: "unload_request",
    args: [a(0, "module", h("module"))],
    ret: "ntstatus",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 42,
    profile: "module_load",
    sub: "resolve_procedures",
    module: "ntdll.dll",
    export: "LdrGetProcedureAddressForCaller",
    op: "resolve",
    args: [
      a(0, "module", h("module")),
      a(1, "name", { k: "procname" }),
      a(2, "ordinal", u32),
      a(3, "address", { k: "out_ptr" }),
      a(4, "flags", u32),
    ],
    ret: "ntstatus",
    default_on: true,
    verified: "hooked+decoded",
  }),
  // ------------------------------------------------------------------ memory_protection
  spec({
    id: 50,
    profile: "memory_protection",
    sub: "core",
    module: "ntdll.dll",
    export: "NtProtectVirtualMemory",
    op: "protect",
    args: [
      a(0, "process", h("process")),
      a(1, "base", { k: "inout_ptr" }),
      a(2, "size", { k: "inout_size" }),
      a(3, "new", u32),
      a(4, "old", { k: "out_u32" }),
    ],
    ret: "ntstatus",
    verified: "hooked+decoded",
  }),
  spec({
    id: 51,
    profile: "memory_protection",
    sub: "core",
    module: "ntdll.dll",
    export: "NtAllocateVirtualMemoryEx",
    op: "alloc",
    args: [
      a(0, "process", h("process")),
      a(1, "base", { k: "inout_ptr" }),
      a(2, "size", { k: "inout_size" }),
      a(3, "type", u32),
      a(4, "protect", u32),
    ],
    ret: "ntstatus",
    verified: "hooked",
  }),
  spec({
    id: 52,
    profile: "memory_protection",
    sub: "core",
    module: "kernelbase.dll",
    export: "VirtualAllocEx",
    op: "alloc",
    args: [
      a(0, "process", h("process")),
      a(1, "base", ptrD),
      a(2, "size", u64),
      a(3, "type", u32),
      a(4, "protect", u32),
    ],
    ret: "ptr",
    verified: "hooked",
  }),
  spec({
    id: 53,
    profile: "memory_protection",
    sub: "core",
    module: "kernelbase.dll",
    export: "VirtualAlloc2",
    op: "alloc",
    args: [
      a(0, "process", h("process")),
      a(1, "base", ptrD),
      a(2, "size", u64),
      a(3, "type", u32),
      a(4, "protect", u32),
    ],
    ret: "ptr",
    verified: "hooked",
  }),
  spec({
    id: 54,
    profile: "memory_protection",
    sub: "frees",
    module: "ntdll.dll",
    export: "NtFreeVirtualMemory",
    op: "free",
    args: [
      a(0, "process", h("process")),
      a(1, "base", { k: "inout_ptr" }),
      a(2, "size", { k: "inout_size" }),
      a(3, "type", u32),
    ],
    ret: "ntstatus",
    volume: "high",
    verified: "hooked+decoded",
  }),
  spec({
    id: 55,
    profile: "memory_protection",
    sub: "sections",
    module: "ntdll.dll",
    export: "NtMapViewOfSection",
    op: "map_view",
    args: [
      a(0, "section", h("section")),
      a(1, "process", h("process")),
      a(2, "base", { k: "inout_ptr" }),
      a(4, "commit", u64),
      a(5, "offset", { k: "i64ptr" }),
      a(6, "size", { k: "inout_size" }),
      a(7, "inherit", u32),
      a(8, "type", u32),
      a(9, "protect", u32),
    ],
    ret: "ntstatus",
    verified: "believed",
  }),
  spec({
    id: 56,
    profile: "memory_protection",
    sub: "sections",
    module: "ntdll.dll",
    export: "NtUnmapViewOfSection",
    op: "unmap_view",
    args: [a(0, "process", h("process")), a(1, "base", ptrD)],
    ret: "ntstatus",
    verified: "believed",
  }),
  // ------------------------------------------------------------------ network
  spec({
    id: 60,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "WSASocketW",
    op: "socket",
    args: [a(0, "af", i32), a(1, "type", i32), a(2, "protocol", i32), a(4, "group", u32), a(5, "flags", u32)],
    ret: "socket",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 61,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "WSASocketA",
    op: "socket",
    args: [a(0, "af", i32), a(1, "type", i32), a(2, "protocol", i32), a(4, "group", u32), a(5, "flags", u32)],
    ret: "socket",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 62,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "bind",
    op: "bind",
    args: [a(0, "socket", h("socket")), a(1, "local", { k: "sockaddr", len_arg: 2 }), a(2, "namelen", i32)],
    ret: "i32",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 63,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "listen",
    op: "listen",
    args: [a(0, "socket", h("socket")), a(1, "backlog", i32)],
    ret: "i32",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 64,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "connect",
    op: "connect",
    args: [a(0, "socket", h("socket")), a(1, "remote", { k: "sockaddr", len_arg: 2 }), a(2, "namelen", i32)],
    ret: "i32",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 65,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "WSAConnect",
    op: "connect",
    args: [a(0, "socket", h("socket")), a(1, "remote", { k: "sockaddr", len_arg: 2 }), a(2, "namelen", i32)],
    ret: "i32",
    volume: "low",
    verified: "hooked",
  }),
  spec({
    id: 66,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "accept",
    op: "accept",
    args: [a(0, "socket", h("socket")), a(1, "peer", { k: "out_sockaddr" })],
    ret: "socket",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 67,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "WSAAccept",
    op: "accept",
    args: [a(0, "socket", h("socket")), a(1, "peer", { k: "out_sockaddr" })],
    ret: "socket",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 68,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "send",
    op: "send",
    args: [
      a(0, "socket", h("socket")),
      a(1, "buffer", { k: "buf", len_arg: 2, when: "enter", len_from: "arg" }),
      a(2, "length", i32),
      a(3, "flags", i32),
    ],
    ret: "i32",
    verified: "hooked+decoded",
  }),
  spec({
    id: 69,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "WSASend",
    op: "send",
    args: [
      a(0, "socket", h("socket")),
      a(1, "buffers", { k: "wsabufs", count_arg: 2, when: "enter" }),
      a(2, "count", u32),
      a(3, "sent", { k: "out_u32" }),
      a(4, "flags", u32),
      a(5, "overlapped", ptrD),
    ],
    ret: "i32",
    verified: "hooked+decoded",
  }),
  spec({
    id: 70,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "sendto",
    op: "sendto",
    args: [
      a(0, "socket", h("socket")),
      a(1, "buffer", { k: "buf", len_arg: 2, when: "enter", len_from: "arg" }),
      a(2, "length", i32),
      a(3, "flags", i32),
      a(4, "remote", { k: "sockaddr", len_arg: 5 }),
      a(5, "tolen", i32),
    ],
    ret: "i32",
    verified: "hooked+decoded",
  }),
  spec({
    id: 71,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "WSASendTo",
    op: "sendto",
    args: [
      a(0, "socket", h("socket")),
      a(1, "buffers", { k: "wsabufs", count_arg: 2, when: "enter" }),
      a(2, "count", u32),
      a(3, "sent", { k: "out_u32" }),
      a(4, "flags", u32),
      a(5, "remote", { k: "sockaddr", len_arg: 6 }),
      a(6, "tolen", i32),
      a(7, "overlapped", ptrD),
    ],
    ret: "i32",
    verified: "hooked",
  }),
  spec({
    id: 72,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "recv",
    op: "recv",
    args: [
      a(0, "socket", h("socket")),
      a(1, "buffer", { k: "buf", len_arg: 2, when: "leave", len_from: "ret" }),
      a(2, "length", i32),
      a(3, "flags", i32),
    ],
    ret: "i32",
    verified: "hooked+decoded",
  }),
  spec({
    id: 73,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "WSARecv",
    op: "recv",
    args: [
      a(0, "socket", h("socket")),
      a(1, "buffers", { k: "wsabufs", count_arg: 2, when: "leave" }),
      a(2, "count", u32),
      a(3, "received", { k: "out_u32" }),
      a(5, "overlapped", ptrD),
    ],
    ret: "i32",
    verified: "hooked",
  }),
  spec({
    id: 74,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "recvfrom",
    op: "recvfrom",
    args: [
      a(0, "socket", h("socket")),
      a(1, "buffer", { k: "buf", len_arg: 2, when: "leave", len_from: "ret" }),
      a(2, "length", i32),
      a(3, "flags", i32),
      a(4, "remote", { k: "out_sockaddr" }),
    ],
    ret: "i32",
    verified: "hooked+decoded",
  }),
  spec({
    id: 75,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "WSARecvFrom",
    op: "recvfrom",
    args: [
      a(0, "socket", h("socket")),
      a(1, "buffers", { k: "wsabufs", count_arg: 2, when: "leave" }),
      a(2, "count", u32),
      a(3, "received", { k: "out_u32" }),
      a(5, "remote", { k: "out_sockaddr" }),
      a(7, "overlapped", ptrD),
    ],
    ret: "i32",
    verified: "believed",
  }),
  spec({
    id: 76,
    profile: "network",
    sub: "core",
    module: "ws2_32.dll",
    export: "closesocket",
    op: "close",
    args: [a(0, "socket", h("socket"))],
    ret: "i32",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 77,
    profile: "network",
    sub: "dns",
    module: "ws2_32.dll",
    export: "GetAddrInfoW",
    op: "dns",
    args: [a(0, "node", wstr(256)), a(1, "service", wstr(64)), a(3, "result", { k: "addrinfo_out", ex: false })],
    ret: "i32",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 78,
    profile: "network",
    sub: "dns",
    module: "ws2_32.dll",
    export: "GetAddrInfoExW",
    op: "dns",
    args: [
      a(0, "node", wstr(256)),
      a(1, "service", wstr(64)),
      a(2, "namespace", u32),
      a(5, "result", { k: "addrinfo_out", ex: true }),
      a(7, "overlapped", ptrD),
    ],
    ret: "i32",
    volume: "low",
    verified: "hooked",
  }),
  spec({
    id: 79,
    profile: "network",
    sub: "dns",
    module: "ws2_32.dll",
    export: "gethostbyname",
    op: "dns",
    args: [a(0, "node", { k: "astr", max: 256 })],
    ret: "ptr",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 80,
    profile: "network",
    sub: "dns",
    module: "dnsapi.dll",
    export: "DnsQueryEx",
    op: "dns",
    args: [a(0, "request", { k: "dnsreq" })],
    ret: "i32",
    volume: "low",
    verified: "hooked",
  }),
  spec({
    id: 81,
    profile: "network",
    sub: "dns",
    module: "dnsapi.dll",
    export: "DnsQuery_W",
    op: "dns",
    args: [a(0, "node", wstr(256)), a(1, "qtype", u32), a(2, "options", u32)],
    ret: "i32",
    volume: "low",
    verified: "hooked",
  }),
  spec({
    id: 82,
    profile: "network",
    sub: "http",
    module: "winhttp.dll",
    export: "WinHttpConnect",
    op: "http_connect",
    args: [a(0, "session", h("inet")), a(1, "server", wstr(256)), a(2, "port", u32)],
    ret: "handle",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 83,
    profile: "network",
    sub: "http",
    module: "winhttp.dll",
    export: "WinHttpOpenRequest",
    op: "http_request",
    args: [
      a(0, "connection", h("inet")),
      a(1, "verb", wstr(32)),
      a(2, "object", wstr(2048)),
      a(3, "version", wstr(32)),
      a(6, "flags", u32),
    ],
    ret: "handle",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 84,
    profile: "network",
    sub: "http",
    module: "winhttp.dll",
    export: "WinHttpSendRequest",
    op: "http_send",
    args: [
      a(0, "request", h("inet")),
      a(3, "optional", { k: "buf", len_arg: 4, when: "enter", len_from: "arg" }),
      a(4, "optional_length", u32),
      a(5, "total_length", u32),
    ],
    ret: "bool32",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 85,
    profile: "network",
    sub: "http",
    module: "wininet.dll",
    // slot 4 (lpszPassword) and slot 3 (lpszUserName) are never read (S6 §6.1 redaction rule)
    export: "InternetConnectW",
    op: "http_connect",
    args: [
      a(0, "session", h("inet")),
      a(1, "server", wstr(256)),
      a(2, "port", u32),
      a(5, "service", u32),
      a(6, "flags", u32),
    ],
    ret: "handle",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 86,
    profile: "network",
    sub: "http",
    module: "wininet.dll",
    export: "HttpOpenRequestW",
    op: "http_request",
    args: [
      a(0, "connection", h("inet")),
      a(1, "verb", wstr(32)),
      a(2, "object", wstr(2048)),
      a(3, "version", wstr(32)),
      a(6, "flags", u32),
    ],
    ret: "handle",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 87,
    profile: "network",
    sub: "http",
    module: "wininet.dll",
    export: "InternetOpenUrlW",
    op: "http_request",
    args: [a(0, "session", h("inet")), a(1, "url", wstr(2048)), a(3, "headers_length", u32), a(4, "flags", u32)],
    ret: "handle",
    volume: "low",
    verified: "believed",
  }),
  // ------------------------------------------------------------------ process
  spec({
    id: 100,
    profile: "process",
    sub: "core",
    module: "kernelbase.dll",
    export: "CreateProcessInternalW",
    op: "spawn",
    args: [
      a(1, "image", wstr(1024)),
      a(2, "cmdline", wstr(4096)),
      a(5, "inherit", boolD),
      a(6, "flags", u32),
      a(8, "cwd", wstr(1024)),
      a(10, "info", { k: "proc_info_out" }),
    ],
    ret: "bool32",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 101,
    profile: "process",
    sub: "core",
    module: "ntdll.dll",
    export: "NtCreateUserProcess",
    op: "spawn",
    args: [
      a(0, "process", outH("process")),
      a(1, "thread", outH("thread")),
      a(2, "process_access", u32),
      a(3, "thread_access", u32),
      a(6, "process_flags", u32),
      a(7, "thread_flags", u32),
      a(8, "params", { k: "proc_params" }),
    ],
    ret: "ntstatus",
    volume: "low",
    verified: "hooked",
  }),
  spec({
    id: 102,
    profile: "process",
    sub: "core",
    module: "ntdll.dll",
    export: "NtOpenProcess",
    op: "open_process",
    args: [a(0, "handle", outH("process")), a(1, "access", u32), a(3, "client", { k: "client_id" })],
    ret: "ntstatus",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 103,
    profile: "process",
    sub: "core",
    module: "ntdll.dll",
    export: "NtTerminateProcess",
    op: "terminate",
    args: [a(0, "process", h("process")), a(1, "status", u32)],
    ret: "ntstatus",
    volume: "low",
    emit_when: { arg: "process", op: "ne", value: "0x0" },
    noreturn_when: { arg: "process", op: "eq", value: SELF_PROCESS },
    verified: "believed",
  }),
  spec({
    id: 104,
    profile: "process",
    sub: "core",
    module: "ntdll.dll",
    export: "NtCreateThreadEx",
    op: "create_thread",
    args: [
      a(0, "handle", outH("thread")),
      a(1, "access", u32),
      a(3, "process", h("process")),
      a(4, "start", ptrD),
      a(5, "argument", ptrD),
      a(6, "flags", u32),
      a(8, "stack", u64),
      a(9, "max_stack", u64),
    ],
    ret: "ntstatus",
    volume: "low",
    verified: "hooked+decoded",
  }),
  spec({
    id: 105,
    profile: "process",
    sub: "cross_process_memory",
    module: "ntdll.dll",
    export: "NtWriteVirtualMemory",
    op: "write_process_memory",
    args: [a(0, "process", h("process")), a(1, "base", ptrD), a(3, "size", u64)],
    ret: "ntstatus",
    emit_when: { arg: "process", op: "ne", value: SELF_PROCESS },
    verified: "believed",
  }),
  spec({
    id: 106,
    profile: "process",
    sub: "cross_process_memory",
    module: "ntdll.dll",
    export: "NtReadVirtualMemory",
    op: "read_process_memory",
    args: [a(0, "process", h("process")), a(1, "base", ptrD), a(3, "size", u64)],
    ret: "ntstatus",
    emit_when: { arg: "process", op: "ne", value: SELF_PROCESS },
    verified: "believed",
  }),
  spec({
    id: 107,
    profile: "process",
    sub: "apc_and_context",
    module: "ntdll.dll",
    export: "NtQueueApcThread",
    op: "queue_apc",
    args: [
      a(0, "thread", h("thread")),
      a(1, "routine", ptrD),
      a(2, "arg1", ptrD),
      a(3, "arg2", ptrD),
      a(4, "arg3", ptrD),
    ],
    ret: "ntstatus",
    volume: "low",
    verified: "believed",
  }),
  spec({
    id: 108,
    profile: "process",
    sub: "apc_and_context",
    module: "ntdll.dll",
    export: "NtSetContextThread",
    op: "set_context",
    args: [a(0, "thread", h("thread"))],
    ret: "ntstatus",
    volume: "low",
    verified: "believed",
  }),
];

/**
 * Pseudo APIs: rows the agent produces from its own observers, multiplexed on the profile's api/1 stream so one
 * recording carries everything (WP-BEHAVIOR decision; see profiles.ts). Ids never collide with catalog ids.
 *  - MEMMAP (200): the memory-map watcher (S4 §10.7) and the free-time executable-region probe. args: ev
 *    ("new-exec" | "new-rwx" | "gone" | "prot-change"), base, size, protection, module, seen ("scan" | "free").
 *  - MODULES (201): module observer loads/unloads for module_load (S6 §6.6). args: ev ("L" | "U"), name, path,
 *    base, size.
 */
export const PSEUDO_API = {
  MEMMAP: { id: 200, profile: "memory_protection", name: "bea!memmap" },
  MODULES: { id: 201, profile: "module_load", name: "bea!modules" },
} as const satisfies Record<string, { id: number; profile: ApiProfileName; name: string }>;

/** VERIFIED deadlock at the next CreateThread (S4 F8): never hooked by profiles or hook_function. */
export const HOOK_DENY_LIST: readonly { readonly api: string; readonly reason: "deadlock-risk" | "agent-critical" }[] =
  [
    { api: "ntdll.dll!NtAllocateVirtualMemory", reason: "deadlock-risk" },
    { api: "kernelbase.dll!VirtualAlloc", reason: "deadlock-risk" },
  ];

/**
 * Untested hook sites that need force_caution (S4 §10.8, BELIEVED risky, A-24): heap, locks, waits, exception
 * dispatch, thread start and the agent's own guard checks. Profiles never select them.
 */
export const HOOK_CAUTION_LIST: readonly string[] = [
  "ntdll.dll!RtlAllocateHeap",
  "ntdll.dll!RtlFreeHeap",
  "ntdll.dll!RtlReAllocateHeap",
  "ntdll.dll!RtlSizeHeap",
  "ntdll.dll!RtlEnterCriticalSection",
  "ntdll.dll!RtlLeaveCriticalSection",
  "ntdll.dll!RtlTryEnterCriticalSection",
  "ntdll.dll!RtlAcquireSRWLockExclusive",
  "ntdll.dll!RtlReleaseSRWLockExclusive",
  "ntdll.dll!RtlAcquireSRWLockShared",
  "ntdll.dll!RtlReleaseSRWLockShared",
  "ntdll.dll!NtWaitForSingleObject",
  "ntdll.dll!NtWaitForMultipleObjects",
  "ntdll.dll!NtSetEvent",
  "ntdll.dll!NtResetEvent",
  "ntdll.dll!NtReleaseSemaphore",
  "ntdll.dll!NtDelayExecution",
  "ntdll.dll!NtYieldExecution",
  "ntdll.dll!NtContinue",
  "ntdll.dll!NtRaiseException",
  "ntdll.dll!RtlRaiseException",
  "ntdll.dll!KiUserExceptionDispatcher",
  "ntdll.dll!RtlDispatchException",
  "ntdll.dll!RtlUnwindEx",
  "ntdll.dll!RtlVirtualUnwind",
  "ntdll.dll!RtlLookupFunctionEntry",
  "ntdll.dll!LdrInitializeThunk",
  "ntdll.dll!RtlUserThreadStart",
  "kernelbase.dll!BaseThreadInitThunk",
  "ntdll.dll!RtlExitUserThread",
  "ntdll.dll!NtQueryVirtualMemory",
  "kernelbase.dll!VirtualQuery",
];

/** "ntdll.dll!NtCreateFile" style name of a catalog entry. */
export const apiName = (s: Pick<ApiSpec, "module" | "export">): string => `${s.module}!${s.export}`;

const BY_ID: ReadonlyMap<number, ApiSpec> = new Map(API_CATALOG.map((s) => [s.id, s]));
export const apiById = (id: number): ApiSpec | undefined => BY_ID.get(id);

/** Sub-option of each profile (ProfileOptions keys) → the catalog subs it controls. */
export const PROFILE_SUB_OPTIONS: { readonly [P in ApiProfileName]: readonly ApiSub[] } = {
  file: ["io", "track_handles"],
  registry: ["query_key", "enumerate"],
  network: ["dns", "http"],
  process: ["cross_process_memory", "apc_and_context"],
  module_load: ["resolve_procedures"],
  memory_protection: ["frees", "sections"],
};
