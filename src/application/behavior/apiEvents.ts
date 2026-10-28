import type { JsonObject, JsonValue } from "../../domain/json.js";
import {
  CREATE_DISPOSITIONS,
  CREATE_RESULTS,
  CREATION_FLAGS,
  DNS_TYPES,
  FILE_DIRECTORY_FILE,
  FILE_INFO_CLASS,
  HTTP_FLAG_SECURE,
  KEY_ACCESS,
  MEM_TYPES,
  REG_CREATED_NEW_KEY,
  SUSPICIOUS_PROCESS_ACCESS,
  decodeFlags,
  fileAccess,
  isExecutable,
  isWritable,
  ntstatusName,
  ntSuccess,
  processAccess,
  protectionText,
  regTypeName,
  wsaErrorName,
} from "../../domain/winConstants.js";
import type { EventField, EventRecord } from "../../ports/recordings.js";
import { PSEUDO_API, apiById, type ApiSpec } from "../../shared/apiProfiles.js";
import { normalizeKey, normalizeNtPath, stripQuery, type PathKind } from "./normalize.js";

/**
 * api/1 row → event (S6 §5.4 api field dictionary). Rows come from the target process (untrusted shape): every
 * accessor tolerates missing or mistyped cells, and a row that is not an ApiRow tuple decodes to null.
 * Cell key conventions: src/agent/pure/profileDecode.ts.
 */

/** Recording decoders for kind "api" (RecordingCreate.decoders / DecodeContext.decoders). */
export interface ApiDecoders {
  readonly catalog_minor: number;
  readonly include_failed: boolean;
  readonly caller: boolean;
  /** current user SID for HKCU normalization; null = heuristic (normalize.ts) */
  readonly user_sid: string | null;
}
export const DEFAULT_API_DECODERS: ApiDecoders = {
  catalog_minor: 0,
  include_failed: true,
  caller: true,
  user_sid: null,
};

export const parseApiDecoders = (value: JsonValue): ApiDecoders => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return DEFAULT_API_DECODERS;
  const o = value as JsonObject;
  return {
    catalog_minor: typeof o.catalog_minor === "number" ? o.catalog_minor : 0,
    include_failed: o.include_failed !== false,
    caller: o.caller !== false,
    user_sid: typeof o.user_sid === "string" ? o.user_sid : null,
  };
};

export const API_EVENT_FIELDS: readonly EventField[] = [
  { name: "seq", type: "int" },
  { name: "t_ms", type: "float" },
  { name: "tid", type: "int" },
  { name: "g", type: "int" },
  { name: "parent", type: "int" },
  { name: "profile", type: "string" },
  { name: "op", type: "string" },
  { name: "api", type: "string" },
  { name: "target", type: "string" },
  { name: "kind", type: "string" },
  { name: "status", type: "string" },
  { name: "ok", type: "bool" },
  { name: "bytes", type: "int" },
  { name: "handle", type: "address" },
  { name: "caller", type: "address" },
  { name: "detail", type: "object" },
];

type Cells = Readonly<Record<string, JsonValue>>;

const text = (cells: Cells, key: string): string | null => {
  const c = cells[key];
  return typeof c === "object" && c !== null && !Array.isArray(c) && typeof (c as JsonObject).s === "string"
    ? ((c as JsonObject).s as string)
    : null;
};
const num = (cells: Cells, key: string): number | null => {
  const c = cells[key];
  return typeof c === "number" && Number.isFinite(c) ? c : null;
};
const hex = (cells: Cells, key: string): string | null => {
  const c = cells[key];
  return typeof c === "string" && /^0x[0-9a-f]{1,16}$/u.test(c) ? c : null;
};
const hexNum = (cells: Cells, key: string): number | null => {
  const h = hex(cells, key);
  if (h === null) return null;
  const v = Number.parseInt(h.slice(2), 16);
  return Number.isSafeInteger(v) ? v : null;
};

const SELF = "0xffffffffffffffff";

/** The "ntdll!NtCreateFile" display name (S6 §5.4 `api`). */
const displayApi = (spec: Pick<ApiSpec, "module" | "export">): string =>
  `${spec.module.replace(/\.dll$/u, "")}!${spec.export}`;

interface Decoded {
  op: string;
  target: string;
  kind: string;
  bytes: number | null;
  handle: string | null;
  detail: Record<string, JsonValue>;
}

const socketTarget = (cells: Cells, arg: string): string => {
  const name = text(cells, `${arg}_name`);
  const proto = text(cells, `${arg}_proto`) ?? "tcp";
  return name === null ? `<socket ${hex(cells, arg) ?? "?"}>` : `${name}/${proto}`;
};

const endpoint = (cells: Cells, arg: string, proto: string): string | null => {
  const addr = text(cells, `${arg}_addr`);
  const port = num(cells, `${arg}_port`);
  if (addr === null || port === null) return null;
  return num(cells, `${arg}_family`) === 23 ? `[${addr}]:${String(port)}/${proto}` : `${addr}:${String(port)}/${proto}`;
};

const pathOf = (cells: Cells, key: string): { path: string; kind: PathKind } =>
  normalizeNtPath(text(cells, key) ?? text(cells, `${key}_name`) ?? `<handle ${hex(cells, key) ?? "?"}>`);

const handleTarget = (cells: Cells, arg: string): { path: string; kind: PathKind } => {
  const name = text(cells, `${arg}_name`);
  return name === null ? { path: `<handle ${hex(cells, arg) ?? "?"}>`, kind: "unknown" } : normalizeNtPath(name);
};

const fileEvent = (spec: ApiSpec, c: Cells, ok: boolean): Decoded => {
  const d: Record<string, JsonValue> = {};
  switch (spec.op) {
    case "create":
    case "open": {
      const p = pathOf(c, "path");
      const options = num(c, "options") ?? 0;
      const access = num(c, "access");
      if (access !== null) d.access = fileAccess(access);
      const disposition = num(c, "disposition");
      const info = hexNum(c, "iosb");
      let op: string = spec.op;
      if (spec.id === 1) {
        if (disposition !== null) d.disposition = CREATE_DISPOSITIONS[disposition] ?? disposition;
        if (ok && info !== null) {
          d.result = CREATE_RESULTS[info] ?? info;
          op = info === 2 ? "create" : info === 1 ? "open" : "overwrite";
        } else op = disposition === 1 || disposition === 3 ? "open" : disposition === 2 ? "create" : "overwrite";
      }
      const kind = p.kind === "file" && (options & FILE_DIRECTORY_FILE) !== 0 ? "dir" : p.kind;
      return { op, target: p.path, kind, bytes: null, handle: hex(c, "handle"), detail: d };
    }
    case "stat":
    case "delete": {
      const p = pathOf(c, "path");
      return { op: spec.op, target: p.path, kind: p.kind, bytes: null, handle: null, detail: d };
    }
    case "set_info": {
      const p = handleTarget(c, "handle");
      const cls = num(c, "class") ?? num(c, "info_class") ?? -1;
      d.class = cls;
      let op = "set_info";
      if (cls === FILE_INFO_CLASS.rename || cls === FILE_INFO_CLASS.rename_ex) {
        op = "rename";
        const to = text(c, "info_target");
        if (to !== null) d.to = normalizeNtPath(to).path;
      } else if (cls === FILE_INFO_CLASS.disposition || cls === FILE_INFO_CLASS.disposition_ex)
        op = num(c, "info_delete") === 0 ? "undelete" : "delete";
      else if (cls === FILE_INFO_CLASS.end_of_file) op = "truncate";
      return { op, target: p.path, kind: p.kind, bytes: null, handle: hex(c, "handle"), detail: d };
    }
    case "list": {
      const p = handleTarget(c, "handle");
      const pattern = text(c, "pattern");
      if (pattern !== null) d.pattern = pattern;
      return {
        op: "list",
        target: p.path,
        kind: p.kind === "file" ? "dir" : p.kind,
        bytes: null,
        handle: hex(c, "handle"),
        detail: d,
      };
    }
    case "read":
    case "write": {
      const p = handleTarget(c, "handle");
      const info = hexNum(c, "iosb");
      const bytes = ok ? (info ?? num(c, "buffer_len")) : null;
      if (ok && info === null) d.bytes_unknown = true; // STATUS_PENDING: async I/O (limitation)
      return { op: spec.op, target: p.path, kind: p.kind, bytes, handle: hex(c, "handle"), detail: d };
    }
    default:
      return {
        op: spec.op,
        target: handleTarget(c, "handle").path,
        kind: "unknown",
        bytes: null,
        handle: null,
        detail: d,
      };
  }
};

const registryEvent = (spec: ApiSpec, c: Cells, ok: boolean, userSid: string | null): Decoded => {
  const d: Record<string, JsonValue> = {};
  const keyName = (k: string): string => normalizeKey(text(c, k) ?? `<handle ${hex(c, "handle") ?? "?"}>`, userSid);
  if (spec.op === "open" || spec.op === "create") {
    const nt = text(c, "key");
    const access = num(c, "access");
    if (access !== null) d.access = decodeFlags(access >>> 0, KEY_ACCESS);
    if (nt !== null && !nt.startsWith("<")) d.nt = nt;
    let op = spec.op;
    if (spec.id === 22 && ok) op = num(c, "disposition") === REG_CREATED_NEW_KEY ? "create" : "open";
    return { op, target: keyName("key"), kind: "key", bytes: null, handle: hex(c, "handle"), detail: d };
  }
  const value = text(c, "value");
  if (value !== null) d.value = value;
  const type = num(c, "type") ?? num(c, "data_type") ?? num(c, "info_type");
  if (type !== null) d.type = regTypeName(type);
  const size = num(c, "size") ?? num(c, "info_size");
  if (size !== null && spec.op !== "rename_key") d.size = size;
  const newName = text(c, "new_name");
  if (newName !== null) d.new_name = newName;
  return { op: spec.op, target: keyName("handle_name"), kind: "key", bytes: null, handle: hex(c, "handle"), detail: d };
};

const networkEvent = (spec: ApiSpec, c: Cells, ok: boolean): Decoded => {
  const d: Record<string, JsonValue> = {};
  const proto = text(c, "socket_proto") ?? (spec.op === "sendto" || spec.op === "recvfrom" ? "udp" : "tcp");
  const sock = hex(c, "socket");
  switch (spec.op) {
    case "socket": {
      const type = num(c, "type");
      const p = type === 1 ? "tcp" : type === 2 ? "udp" : type === 3 ? "raw" : "unknown";
      d.af = num(c, "af") ?? 0;
      return { op: "socket", target: p, kind: "socket", bytes: null, handle: null, detail: d };
    }
    case "bind": {
      const bound = text(c, "local_bound");
      const target = bound !== null ? `${bound}/${proto}` : (endpoint(c, "local", proto) ?? socketTarget(c, "socket"));
      return { op: "bind", target, kind: "socket", bytes: null, handle: sock, detail: d };
    }
    case "connect": {
      const target = endpoint(c, "remote", proto) ?? socketTarget(c, "socket");
      return { op: "connect", target, kind: "socket", bytes: null, handle: sock, detail: d };
    }
    case "listen":
    case "accept":
    case "close": {
      const peer = endpoint(c, "peer", proto);
      if (peer !== null) d.peer = peer;
      return { op: spec.op, target: socketTarget(c, "socket"), kind: "socket", bytes: null, handle: sock, detail: d };
    }
    case "send":
    case "recv": {
      const bytes = !ok
        ? null
        : spec.export === "WSASend" || spec.export === "WSARecv"
          ? (num(c, spec.op === "send" ? "sent" : "received") ?? num(c, "buffers_len"))
          : (num(c, "buffer_len") ?? 0);
      return { op: spec.op, target: socketTarget(c, "socket"), kind: "socket", bytes, handle: sock, detail: d };
    }
    case "sendto":
    case "recvfrom": {
      const target = endpoint(c, "remote", proto) ?? socketTarget(c, "socket");
      const bytes = !ok
        ? null
        : spec.export === "WSASendTo" || spec.export === "WSARecvFrom"
          ? (num(c, spec.op === "sendto" ? "sent" : "received") ?? num(c, "buffers_len"))
          : (num(c, "buffer_len") ?? 0);
      return { op: spec.op, target, kind: "socket", bytes, handle: sock, detail: d };
    }
    case "dns": {
      const name = text(c, "node") ?? text(c, "request_name") ?? "";
      const addrs: string[] = [];
      for (let i = 0; i < 8; i++) {
        const a = text(c, `result_addr${String(i)}`);
        if (a !== null && !addrs.includes(a)) addrs.push(a);
      }
      if (addrs.length > 0) d.addresses = addrs;
      const qtype = num(c, "qtype") ?? num(c, "request_type");
      if (qtype !== null) d.type = DNS_TYPES.get(qtype) ?? qtype;
      return { op: "dns", target: name, kind: "dns", bytes: null, handle: null, detail: d };
    }
    case "http_connect": {
      const server = text(c, "server") ?? "";
      return {
        op: "http_connect",
        target: `${server}:${String(num(c, "port") ?? 0)}`,
        kind: "http",
        bytes: null,
        handle: null,
        detail: d,
      };
    }
    case "http_request": {
      const verb = text(c, "verb");
      if (verb !== null) d.method = verb;
      const flags = num(c, "flags");
      if (flags !== null) d.secure = (flags & HTTP_FLAG_SECURE) !== 0;
      const raw = text(c, "url") ?? `${text(c, "connection_name") ?? ""}${text(c, "object") ?? ""}`;
      const s = stripQuery(raw);
      if (s.stripped) d.query_stripped = true;
      return { op: "http_request", target: s.text, kind: "http", bytes: null, handle: null, detail: d };
    }
    default:
      return {
        op: spec.op,
        target: text(c, "request_name") ?? socketTarget(c, "socket"),
        kind: "http",
        bytes: num(c, "optional_len"),
        handle: null,
        detail: d,
      };
  }
};

const processEvent = (spec: ApiSpec, c: Cells): Decoded => {
  const d: Record<string, JsonValue> = {};
  const self = (arg: string): string => {
    const h = hex(c, arg);
    return h === null || h === SELF || h === "0x0" ? "self" : (text(c, `${arg}_name`) ?? `<handle ${h}>`);
  };
  switch (spec.op) {
    case "spawn": {
      const cmd = spec.id === 100 ? text(c, "cmdline") : text(c, "params_cmdline");
      const image = spec.id === 100 ? text(c, "image") : text(c, "params_image");
      if (cmd !== null) d.cmdline = cmd.length > 1024 ? `${cmd.slice(0, 1024)}…` : cmd;
      const flags = num(c, "flags");
      if (flags !== null) d.flags = decodeFlags(flags >>> 0, CREATION_FLAGS);
      const pid = num(c, "info_pid");
      if (pid !== null) d.pid = pid;
      const target =
        image ??
        (cmd === null
          ? ""
          : (/^"([^"]*)"|^(\S+)/u
              .exec(cmd)
              ?.slice(1)
              .find((x) => x !== undefined) ?? cmd));
      return {
        op: "spawn",
        target: normalizeNtPath(target).path,
        kind: "process",
        bytes: null,
        handle: null,
        detail: d,
      };
    }
    case "open_process": {
      const access = num(c, "access") ?? 0;
      const rights = processAccess(access);
      d.access = rights;
      const flagged = rights.filter(
        (r) => (SUSPICIOUS_PROCESS_ACCESS as readonly string[]).includes(r) || r === "all_access",
      );
      if (flagged.length > 0) d.flagged = flagged;
      const pid = num(c, "client_pid");
      return {
        op: "open_process",
        target: pid === null ? "" : `pid:${String(pid)}`,
        kind: "process",
        bytes: null,
        handle: hex(c, "handle"),
        detail: d,
      };
    }
    case "terminate": {
      d.exit_status = num(c, "status") ?? 0;
      return { op: "terminate", target: self("process"), kind: "process", bytes: null, handle: null, detail: d };
    }
    case "create_thread": {
      const start = hex(c, "start");
      if (start !== null) d.start = start;
      const target = self("process");
      d.remote = target !== "self";
      return { op: "create_thread", target, kind: "thread", bytes: null, handle: hex(c, "handle"), detail: d };
    }
    default: {
      const size = hexNum(c, "size");
      if (size !== null) d.size = size;
      const base = hex(c, "base");
      if (base !== null) d.base = base;
      return {
        op: spec.op,
        target: self(spec.op === "queue_apc" || spec.op === "set_context" ? "thread" : "process"),
        kind: "process",
        bytes: null,
        handle: null,
        detail: d,
      };
    }
  }
};

const moduleEvent = (spec: ApiSpec, c: Cells, frame: (va: string) => string | null): Decoded => {
  const d: Record<string, JsonValue> = {};
  if (spec.op === "load_request") {
    const base = hex(c, "base");
    if (base !== null) d.base = base;
    return { op: "load_request", target: text(c, "name") ?? "", kind: "module", bytes: null, handle: null, detail: d };
  }
  if (spec.op === "resolve") {
    const mod = hex(c, "module");
    const modName = text(c, "module_name") ?? (mod === null ? null : (frame(mod)?.split("+")[0] ?? null));
    const proc = text(c, "name") ?? `#${String(num(c, "name_ordinal") ?? num(c, "ordinal") ?? 0)}`;
    return {
      op: "resolve",
      target: `${modName ?? mod ?? "?"}!${proc}`,
      kind: "procedure",
      bytes: null,
      handle: null,
      detail: d,
    };
  }
  const base = hex(c, "module");
  const named = text(c, "module_name");
  const target = named ?? (base === null ? "" : (frame(base)?.split("+")[0] ?? base));
  return { op: spec.op, target, kind: "module", bytes: null, handle: null, detail: d };
};

const memoryEvent = (spec: ApiSpec, c: Cells, ret: JsonValue, ok: boolean): Decoded => {
  const d: Record<string, JsonValue> = {};
  const proc = hex(c, "process");
  const remote = proc !== null && proc !== SELF && proc !== "0x0";
  const flags: string[] = [];
  if (remote) flags.push("remote");
  const returned = spec.ret === "ptr" && ok && typeof ret === "string" ? ret : null;
  const base = returned ?? hex(c, "base_out") ?? hex(c, "base") ?? "0x0";
  const size = hexNum(c, "size_out") ?? hexNum(c, "size");
  if (size !== null) d.size = size;
  if (spec.op === "protect") {
    const to = num(c, "new");
    const from = num(c, "old");
    if (to !== null) d.to = protectionText(to);
    if (from !== null) d.from = protectionText(from);
    if (to !== null && isExecutable(to) && isWritable(to)) flags.push("wx");
    if (to !== null && isExecutable(to) && from !== null && !isExecutable(from)) flags.push("x_added");
  } else if (spec.op === "alloc" || spec.op === "map_view") {
    const prot = num(c, "protect");
    if (prot !== null) {
      d.to = protectionText(prot);
      if (isExecutable(prot) && isWritable(prot)) flags.push("wx");
      else if (isExecutable(prot)) flags.push("x");
    }
    const type = num(c, "type");
    if (type !== null) d.type = decodeFlags(type >>> 0, MEM_TYPES);
  } else if (spec.op === "free") {
    const type = num(c, "type");
    if (type !== null) d.type = decodeFlags(type >>> 0, MEM_TYPES);
  }
  d.flags = flags;
  return { op: spec.op, target: base, kind: "memory", bytes: null, handle: null, detail: d };
};

/** Pseudo rows (PSEUDO_API): memmap watcher and module observer. */
const pseudoEvent = (apiId: number, c: Cells): { profile: string; api: string; decoded: Decoded } | null => {
  if (apiId === PSEUDO_API.MEMMAP.id) {
    const ev = text(c, "ev") ?? "new-exec";
    const protection = text(c, "protection") ?? "";
    const flags: string[] = [];
    if (protection.includes("x") && protection.includes("w")) flags.push("wx");
    const seen = text(c, "seen");
    if (seen === "free") flags.push("seen_at_free");
    else flags.push("sampled");
    const op = ev === "gone" ? "free" : ev === "prot-change" ? "protect" : "alloc";
    const detail: Record<string, JsonValue> = { ev, to: protection, size: num(c, "size") ?? 0, flags };
    const mod = text(c, "module");
    if (mod !== null) detail.module = mod;
    return {
      profile: PSEUDO_API.MEMMAP.profile,
      api: PSEUDO_API.MEMMAP.name,
      decoded: { op, target: hex(c, "base") ?? "0x0", kind: "memory", bytes: null, handle: null, detail },
    };
  }
  if (apiId === PSEUDO_API.MODULES.id) {
    const ev = text(c, "ev");
    const detail: Record<string, JsonValue> = { base: hex(c, "base") ?? "0x0", size: num(c, "size") ?? 0 };
    const name = text(c, "name");
    if (name !== null) detail.name = name;
    return {
      profile: PSEUDO_API.MODULES.profile,
      api: PSEUDO_API.MODULES.name,
      decoded: {
        op: ev === "U" ? "unloaded" : "loaded",
        target: text(c, "path") ?? name ?? "",
        kind: "module",
        bytes: null,
        handle: null,
        detail,
      },
    };
  }
  return null;
};

const statusOf = (spec: ApiSpec, ret: JsonValue, cells: Cells): { status: string; ok: boolean } => {
  if (ret === null && spec.noreturn_when !== undefined) return { status: "no_return", ok: true }; // emitted at enter
  if (spec.ret === "ntstatus") {
    const code = typeof ret === "string" && /^0x[0-9a-f]{1,8}$/u.test(ret) ? Number.parseInt(ret.slice(2), 16) : null;
    if (code === null) return { status: "unknown", ok: false };
    return { status: ntstatusName(code), ok: ntSuccess(code) };
  }
  const lastError = num(cells, "last_error");
  if (spec.op === "dns") {
    const rc = typeof ret === "number" ? ret : null;
    return rc === 0 ? { status: "ok", ok: true } : { status: rc === null ? "unknown" : wsaErrorName(rc), ok: false };
  }
  let ok: boolean;
  switch (spec.ret) {
    case "bool32":
    case "u32":
      ok = typeof ret === "number" && ret !== 0;
      break;
    case "i32":
      ok = typeof ret === "number" && ret >= 0;
      break;
    case "socket":
      ok = typeof ret === "string" && ret !== SELF;
      break;
    case "handle":
    case "ptr":
      ok = typeof ret === "string" && ret !== "0x0";
      break;
    case "void":
      ok = true;
      break;
  }
  if (ok) return { status: "ok", ok };
  return {
    status:
      lastError === null
        ? "failed"
        : spec.profile === "network"
          ? wsaErrorName(lastError)
          : `WIN32_ERROR_${String(lastError)}`,
    ok,
  };
};

export interface ApiRowContext {
  readonly seq: number;
  readonly startedAtUs: number;
  readonly decoders: ApiDecoders;
  /** VA text → compact `module+0xrva` text (DecodeContext.frame(...).at) */
  readonly frame: (va: string) => string | null;
}

/** Decode one ApiRow tuple; null for malformed rows, unknown ids, or failed calls when include_failed is false. */
export const decodeApiRow = (row: JsonValue, ctx: ApiRowContext): EventRecord | null => {
  if (!Array.isArray(row) || row.length < 9) return null;
  const [g, t, tid, , parent, apiId, rawCells, ret, caller] = row as readonly JsonValue[];
  if (typeof apiId !== "number" || typeof g !== "number" || typeof t !== "number") return null;
  const cells: Cells =
    typeof rawCells === "object" && rawCells !== null && !Array.isArray(rawCells) ? (rawCells as Cells) : {};
  let profile: string;
  let api: string;
  let decoded: Decoded;
  let status: { status: string; ok: boolean };
  const pseudo = pseudoEvent(apiId, cells);
  if (pseudo !== null) {
    ({ profile, api, decoded } = pseudo);
    status = { status: "ok", ok: true };
  } else {
    const spec = apiById(apiId);
    if (spec === undefined) return null;
    status = statusOf(spec, ret ?? null, cells);
    profile = spec.profile;
    api = displayApi(spec);
    switch (spec.profile) {
      case "file":
        decoded = fileEvent(spec, cells, status.ok);
        break;
      case "registry":
        decoded = registryEvent(spec, cells, status.ok, ctx.decoders.user_sid);
        break;
      case "network":
        decoded = networkEvent(spec, cells, status.ok);
        break;
      case "process":
        decoded = processEvent(spec, cells);
        break;
      case "module_load":
        decoded = moduleEvent(spec, cells, ctx.frame);
        break;
      case "memory_protection":
        decoded = memoryEvent(spec, cells, ret ?? null, status.ok);
        break;
    }
  }
  if (!status.ok && !ctx.decoders.include_failed) return null;
  const callerText =
    ctx.decoders.caller && typeof caller === "string" && caller !== "0x0" ? (ctx.frame(caller) ?? caller) : null;
  return {
    seq: ctx.seq,
    t_ms: Math.max(0, Math.round((t - ctx.startedAtUs) / 10) / 100),
    tid: typeof tid === "number" ? tid : 0,
    g,
    parent: typeof parent === "number" ? parent : 0,
    profile,
    op: decoded.op,
    api,
    target: decoded.target,
    kind: decoded.kind,
    status: status.status,
    ok: status.ok,
    bytes: decoded.bytes,
    handle: decoded.handle,
    caller: callerText,
    detail: decoded.detail,
  };
};
