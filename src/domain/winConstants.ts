/**
 * Windows constant tables for decoding api/1 rows on the host (S4 §3 "winConstants.ts"; A15: the agent ships raw
 * numbers, the host names them). Pure data + small helpers; HOST ONLY (never staged into the agent).
 * WP-BEHAVIOR owns this file.
 */

// ------------------------------------------------------------------------------------------------ NTSTATUS
/** Statuses that profile rows commonly carry (u32 bit pattern → name). Unknown codes render as 0x… hex. */
export const NTSTATUS_NAMES: ReadonlyMap<number, string> = new Map<number, string>([
  [0x00000000, "STATUS_SUCCESS"],
  [0x00000102, "STATUS_TIMEOUT"],
  [0x00000103, "STATUS_PENDING"],
  [0x00000104, "STATUS_REPARSE"],
  [0x00000105, "STATUS_MORE_ENTRIES"],
  [0x40000000, "STATUS_OBJECT_NAME_EXISTS"],
  [0x40000003, "STATUS_IMAGE_NOT_AT_BASE"],
  [0x4000000e, "STATUS_IMAGE_MACHINE_TYPE_MISMATCH"],
  [0x80000005, "STATUS_BUFFER_OVERFLOW"],
  [0x80000006, "STATUS_NO_MORE_FILES"],
  [0x8000001a, "STATUS_NO_MORE_ENTRIES"],
  [0xc0000001, "STATUS_UNSUCCESSFUL"],
  [0xc0000002, "STATUS_NOT_IMPLEMENTED"],
  [0xc0000004, "STATUS_INFO_LENGTH_MISMATCH"],
  [0xc0000005, "STATUS_ACCESS_VIOLATION"],
  [0xc0000008, "STATUS_INVALID_HANDLE"],
  [0xc000000b, "STATUS_INVALID_CID"],
  [0xc000000d, "STATUS_INVALID_PARAMETER"],
  [0xc000000f, "STATUS_NO_SUCH_FILE"],
  [0xc0000010, "STATUS_INVALID_DEVICE_REQUEST"],
  [0xc0000011, "STATUS_END_OF_FILE"],
  [0xc0000017, "STATUS_NO_MEMORY"],
  [0xc0000018, "STATUS_CONFLICTING_ADDRESSES"],
  [0xc0000022, "STATUS_ACCESS_DENIED"],
  [0xc0000023, "STATUS_BUFFER_TOO_SMALL"],
  [0xc0000024, "STATUS_OBJECT_TYPE_MISMATCH"],
  [0xc000002d, "STATUS_NOT_COMMITTED"],
  [0xc0000033, "STATUS_OBJECT_NAME_INVALID"],
  [0xc0000034, "STATUS_OBJECT_NAME_NOT_FOUND"],
  [0xc0000035, "STATUS_OBJECT_NAME_COLLISION"],
  [0xc000003a, "STATUS_OBJECT_PATH_NOT_FOUND"],
  [0xc0000043, "STATUS_SHARING_VIOLATION"],
  [0xc0000045, "STATUS_INVALID_PAGE_PROTECTION"],
  [0xc0000056, "STATUS_DELETE_PENDING"],
  [0xc0000061, "STATUS_PRIVILEGE_NOT_HELD"],
  [0xc000007a, "STATUS_PROCEDURE_NOT_FOUND"],
  [0xc000007b, "STATUS_INVALID_IMAGE_FORMAT"],
  [0xc00000a0, "STATUS_MEMORY_NOT_ALLOCATED"],
  [0xc00000ac, "STATUS_PIPE_NOT_AVAILABLE"],
  [0xc00000ae, "STATUS_PIPE_BUSY"],
  [0xc00000ba, "STATUS_FILE_IS_A_DIRECTORY"],
  [0xc00000bb, "STATUS_NOT_SUPPORTED"],
  [0xc00000be, "STATUS_BAD_NETWORK_PATH"],
  [0xc00000cc, "STATUS_BAD_NETWORK_NAME"],
  [0xc0000101, "STATUS_DIRECTORY_NOT_EMPTY"],
  [0xc0000103, "STATUS_NOT_A_DIRECTORY"],
  [0xc0000106, "STATUS_NAME_TOO_LONG"],
  [0xc000010a, "STATUS_PROCESS_IS_TERMINATING"],
  [0xc0000121, "STATUS_CANNOT_DELETE"],
  [0xc0000135, "STATUS_DLL_NOT_FOUND"],
  [0xc0000138, "STATUS_ORDINAL_NOT_FOUND"],
  [0xc0000139, "STATUS_ENTRYPOINT_NOT_FOUND"],
  [0xc000017c, "STATUS_KEY_DELETED"],
  [0xc0000225, "STATUS_NOT_FOUND"],
]);

/** NT_SUCCESS: the status, read as a signed 32-bit value, is ≥ 0 (success and informational). */
export const ntSuccess = (code: number): boolean => (code | 0) >= 0;

/** Name of an NTSTATUS, else its canonical 8-digit hex form ("0xc0001234"). */
export const ntstatusName = (code: number): string =>
  NTSTATUS_NAMES.get(code >>> 0) ?? `0x${(code >>> 0).toString(16).padStart(8, "0")}`;

// ------------------------------------------------------------------------------------------------ Winsock
/** @public */
export const SOCKET_ERROR = -1;
export const WSA_ERROR_NAMES: ReadonlyMap<number, string> = new Map<number, string>([
  [10004, "WSAEINTR"],
  [10013, "WSAEACCES"],
  [10014, "WSAEFAULT"],
  [10022, "WSAEINVAL"],
  [10024, "WSAEMFILE"],
  [10035, "WSAEWOULDBLOCK"],
  [10036, "WSAEINPROGRESS"],
  [10038, "WSAENOTSOCK"],
  [10047, "WSAEAFNOSUPPORT"],
  [10048, "WSAEADDRINUSE"],
  [10049, "WSAEADDRNOTAVAIL"],
  [10051, "WSAENETUNREACH"],
  [10054, "WSAECONNRESET"],
  [10056, "WSAEISCONN"],
  [10057, "WSAENOTCONN"],
  [10060, "WSAETIMEDOUT"],
  [10061, "WSAECONNREFUSED"],
  [10065, "WSAEHOSTUNREACH"],
  [10093, "WSANOTINITIALISED"],
  [10109, "WSATYPE_NOT_FOUND"],
  [11001, "WSAHOST_NOT_FOUND"],
  [11002, "WSATRY_AGAIN"],
  [11003, "WSANO_RECOVERY"],
  [11004, "WSANO_DATA"],
  [997, "WSA_IO_PENDING"],
]);
export const wsaErrorName = (code: number): string => WSA_ERROR_NAMES.get(code) ?? `WSA_ERROR_${String(code)}`;

/** @public */
export const ADDRESS_FAMILIES: ReadonlyMap<number, string> = new Map([
  [0, "AF_UNSPEC"],
  [1, "AF_UNIX"],
  [2, "AF_INET"],
  [23, "AF_INET6"],
]);
/** @public */
export const SOCKET_TYPES: ReadonlyMap<number, "tcp" | "udp" | "raw"> = new Map([
  [1, "tcp"],
  [2, "udp"],
  [3, "raw"],
]);
export const DNS_TYPES: ReadonlyMap<number, string> = new Map([
  [1, "A"],
  [5, "CNAME"],
  [12, "PTR"],
  [15, "MX"],
  [16, "TXT"],
  [28, "AAAA"],
  [33, "SRV"],
]);

// ------------------------------------------------------------------------------------------------ flags
export type FlagTable = readonly (readonly [mask: number, name: string])[];

/** Names of the set bits listed in `table`, in table order (unlisted bits are ignored). */
export const decodeFlags = (value: number, table: FlagTable): string[] =>
  table.filter(([mask]) => (value & mask) === mask && mask !== 0).map(([, name]) => name);

/** File/directory DesiredAccess → coarse rights (S6 §6.2 "access decoded to read/write/delete/execute"). */
const FILE_ACCESS_GROUPS: readonly (readonly [number, string])[] = [
  [0x80000000 | 0x10000000 | 0x0001 | 0x0008 | 0x0080, "read"], // GENERIC_READ|ALL, READ_DATA, READ_EA, READ_ATTRIBUTES
  [0x40000000 | 0x10000000 | 0x0002 | 0x0004 | 0x0010 | 0x0100, "write"], // GENERIC_WRITE|ALL, WRITE/APPEND, EA, ATTRS
  [0x00010000 | 0x10000000, "delete"], // DELETE, GENERIC_ALL
  [0x20000000 | 0x10000000 | 0x0020, "execute"], // GENERIC_EXECUTE|ALL, FILE_EXECUTE
];
export const fileAccess = (mask: number): string[] =>
  FILE_ACCESS_GROUPS.filter(([bits]) => ((mask >>> 0) & bits) !== 0).map(([, name]) => name);

/** NtCreateFile CreateDisposition. */
export const CREATE_DISPOSITIONS = ["supersede", "open", "create", "open_if", "overwrite", "overwrite_if"] as const;
/** IO_STATUS_BLOCK.Information after NtCreateFile/NtOpenFile. */
export const CREATE_RESULTS = ["superseded", "opened", "created", "overwritten", "exists", "does_not_exist"] as const;

export const FILE_DIRECTORY_FILE = 0x1;
/** @public */
export const FILE_NON_DIRECTORY_FILE = 0x40;
/** @public */
export const FILE_DELETE_ON_CLOSE = 0x1000;

/** FILE_INFORMATION_CLASS values that NtSetInformationFile rows refine (S4 §10.5 fileinfo). */
export const FILE_INFO_CLASS = {
  basic: 4,
  rename: 10,
  link: 11,
  disposition: 13,
  position: 14,
  allocation: 19,
  end_of_file: 20,
  disposition_ex: 64,
  rename_ex: 65,
} as const;

/** Registry DesiredAccess → coarse rights. */
export const KEY_ACCESS: FlagTable = [
  [0x0001, "query"],
  [0x0002, "set"],
  [0x0004, "create_sub_key"],
  [0x0008, "enumerate"],
  [0x0010, "notify"],
  [0x0020, "create_link"],
  [0x10000, "delete"],
  [0x80000000, "generic_read"],
  [0x40000000, "generic_write"],
  [0x10000000, "generic_all"],
  [0x02000000, "maximum_allowed"],
];
export const REG_CREATED_NEW_KEY = 1;
/** @public */
export const REG_OPENED_EXISTING_KEY = 2;
export const REG_TYPES: ReadonlyMap<number, string> = new Map([
  [0, "REG_NONE"],
  [1, "REG_SZ"],
  [2, "REG_EXPAND_SZ"],
  [3, "REG_BINARY"],
  [4, "REG_DWORD"],
  [5, "REG_DWORD_BIG_ENDIAN"],
  [6, "REG_LINK"],
  [7, "REG_MULTI_SZ"],
  [8, "REG_RESOURCE_LIST"],
  [11, "REG_QWORD"],
]);
export const regTypeName = (t: number): string => REG_TYPES.get(t) ?? `REG_TYPE_${String(t)}`;

/** Process DesiredAccess (S6 §6.5: VM_WRITE, VM_OPERATION and CREATE_THREAD are flagged). */
export const PROCESS_ACCESS: FlagTable = [
  [0x0001, "terminate"],
  [0x0002, "create_thread"],
  [0x0008, "vm_operation"],
  [0x0010, "vm_read"],
  [0x0020, "vm_write"],
  [0x0040, "dup_handle"],
  [0x0080, "create_process"],
  [0x0200, "set_information"],
  [0x0400, "query_information"],
  [0x0800, "suspend_resume"],
  [0x1000, "query_limited_information"],
  [0x100000, "synchronize"],
  [0x02000000, "maximum_allowed"],
];
export const PROCESS_ALL_ACCESS = 0x1fffff;
export const SUSPICIOUS_PROCESS_ACCESS = ["vm_operation", "vm_write", "create_thread"] as const;
export const processAccess = (mask: number): string[] =>
  (mask & PROCESS_ALL_ACCESS) === PROCESS_ALL_ACCESS ? ["all_access"] : decodeFlags(mask >>> 0, PROCESS_ACCESS);

/** CreateProcess dwCreationFlags (S6 §6.5 flags). */
export const CREATION_FLAGS: FlagTable = [
  [0x00000001, "debug"],
  [0x00000002, "debug_only_this_process"],
  [0x00000004, "suspended"],
  [0x00000008, "detached"],
  [0x00000010, "new_console"],
  [0x00000200, "new_process_group"],
  [0x00000400, "unicode_environment"],
  [0x00080000, "extended_startupinfo"],
  [0x01000000, "breakaway_from_job"],
  [0x08000000, "no_window"],
];

// ------------------------------------------------------------------------------------------------ memory
export const MEM_TYPES: FlagTable = [
  [0x00001000, "commit"],
  [0x00002000, "reserve"],
  [0x00004000, "decommit"],
  [0x00008000, "release"],
  [0x00080000, "reset"],
  [0x00100000, "top_down"],
  [0x00400000, "physical"],
  [0x20000000, "large_pages"],
];
/** @public */
export const MEM_RELEASE = 0x8000;

const PAGE_BASE: ReadonlyMap<number, string> = new Map([
  [0x01, "---"],
  [0x02, "r--"],
  [0x04, "rw-"],
  [0x08, "rw-"], // WRITECOPY
  [0x10, "--x"],
  [0x20, "r-x"],
  [0x40, "rwx"],
  [0x80, "rwx"], // EXECUTE_WRITECOPY
]);
const PAGE_MODIFIERS: FlagTable = [
  [0x100, "guard"],
  [0x200, "nocache"],
  [0x400, "writecombine"],
];

/** PAGE_* protection → "rwx"-style text plus modifiers ("rw-+guard"); unknown bases render as hex. */
export const protectionText = (value: number): string => {
  const base = PAGE_BASE.get(value & 0xff) ?? `0x${(value & 0xff).toString(16)}`;
  const mods = decodeFlags(value >>> 0, PAGE_MODIFIERS);
  return mods.length === 0 ? base : `${base}+${mods.join("+")}`;
};
export const isExecutable = (value: number): boolean => (value & 0xf0) !== 0;
export const isWritable = (value: number): boolean => (value & 0xcc) !== 0;

/** WinHTTP WINHTTP_FLAG_SECURE / WinINet INTERNET_FLAG_SECURE (both 0x00800000). */
export const HTTP_FLAG_SECURE = 0x00800000;
