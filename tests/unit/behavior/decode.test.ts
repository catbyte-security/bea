import { describe, expect, it } from "vitest";

import { decodeEnter, decodeLeave, readSockaddr, type DecodeEnv } from "../../../src/agent/pure/profileDecode.js";
import { HandleCache } from "../../../src/agent/pure/profileHandles.js";
import type { ApiSpec } from "../../../src/shared/apiProfiles.js";
import { specOf } from "./support/agentSim.js";
import { FakeMem } from "./support/fakeMem.js";

const envOf = (mem: FakeMem, caps = { fileBytes: 0, netBytes: 0, valueBytes: 0 }): DecodeEnv<bigint> => ({
  mem,
  cache: new HandleCache(64),
  caps,
  keyName: () => null,
});

const raw = (args: readonly bigint[]): bigint[] => [...args, ...Array<bigint>(12).fill(0n)].slice(0, 12);

/** Decoder layouts of S4 §10.5 over FakeMem (offsets VERIFIED F9 unless the catalog marks them believed). */
describe("profile decoders", () => {
  it("OBJECT_ATTRIBUTES: a relative open joins the cached root name; an unknown root uses the S6 placeholder", () => {
    const mem = new FakeMem();
    const env = envOf(mem);
    env.cache.set("0x40", { kind: "file", name: "\\??\\C:\\dir" });
    const spec = specOf("NtOpenFile");
    const known = decodeEnter(env, spec, raw([mem.slot(), 1n, mem.oa("a.txt", 0x40n), mem.iosb(), 7n, 0x60n]));
    expect(known).toMatchObject({
      path: { s: "\\??\\C:\\dir\\a.txt" },
      path_root: "0x40",
      path_attr: 0x40,
      access: 1,
      options: 0x60,
    });
    const unknown = decodeEnter(env, spec, raw([mem.slot(), 1n, mem.oa("b.txt", 0x99n), mem.iosb(), 7n, 0x60n]));
    expect(unknown.path).toEqual({ s: "<handle 0x99>\\b.txt" });
  });

  it("registry roots missing from the cache are resolved once through keyName (F10) and cached", () => {
    const mem = new FakeMem();
    const calls: bigint[] = [];
    const env: DecodeEnv<bigint> = { ...envOf(mem), keyName: (h) => (calls.push(h), "\\REGISTRY\\MACHINE") };
    const spec = specOf("NtOpenKeyEx");
    decodeEnter(env, spec, raw([mem.slot(), 0x20019n, mem.oa("SOFTWARE\\X", 0x14cn), 0n]));
    const second = decodeEnter(env, spec, raw([mem.slot(), 0x20019n, mem.oa("SOFTWARE\\Y", 0x14cn), 0n]));
    expect(second.key).toEqual({ s: "\\REGISTRY\\MACHINE\\SOFTWARE\\Y" });
    expect(calls).toEqual([0x14cn]);
  });

  it("UNICODE_STRING is read by Length (not NUL-terminated) and capped with trunc", () => {
    const mem = new FakeMem();
    const spec: ApiSpec = {
      ...specOf("NtDeleteValueKey"),
      args: [{ slot: 1, name: "value", d: { k: "ustr", max: 3 } }],
    };
    expect(decodeEnter(envOf(mem), spec, raw([0n, mem.ustr("Answer")]))).toEqual({ value: { s: "Ans", trunc: true } });
    expect(decodeEnter(envOf(mem), spec, raw([0n, 0n]))).toEqual({ value: null });
  });

  it("unreadable memory marks <name>_err and keeps the other arguments", () => {
    const mem = new FakeMem();
    const cells = decodeEnter(
      envOf(mem),
      specOf("NtCreateFile"),
      raw([mem.slot(), 0x80n, 0xdead_0000n, mem.iosb(), 0n, 0x80n, 0n, 1n, 0x60n]),
    );
    expect(cells.path_err).toBe(1);
    expect(cells.disposition).toBe(1);
  });

  it("sockaddr: AF_INET big-endian port, AF_INET6 groups, other families keep only the family", () => {
    const mem = new FakeMem();
    expect(readSockaddr(mem, mem.sockaddrIn("10.1.2.3", 443))).toEqual({ family: 2, addr: "10.1.2.3", port: 443 });
    const v6 = mem.alloc(28);
    mem.writeUInt(v6, 23, 2);
    mem.writeUInt(v6 + 2n, 0x5000, 2); // port 80 big-endian
    mem.writeUInt(v6 + 22n, 0x0100, 2); // ::1 (last group, big-endian bytes 00 01)
    expect(readSockaddr(mem, v6)).toEqual({ family: 23, addr: "0:0:0:0:0:0:0:1", port: 80 });
    const unix = mem.alloc(16);
    mem.writeUInt(unix, 1, 2);
    expect(readSockaddr(mem, unix)).toEqual({ family: 1, addr: "", port: 0 });
  });
});

describe("profile decoders: payload structures", () => {
  it("fileinfo by class: rename target, disposition, disposition-ex, end-of-file, basic attributes", () => {
    const mem = new FakeMem();
    const env = envOf(mem);
    const spec = specOf("NtSetInformationFile");
    const name = "\\??\\C:\\x\\new.txt";
    const ren = mem.alloc(0x14 + name.length * 2);
    mem.writeUInt(ren + 0x10n, name.length * 2, 4);
    for (let i = 0; i < name.length; i++) mem.writeUInt(ren + 0x14n + BigInt(2 * i), name.charCodeAt(i), 2);
    expect(decodeEnter(env, spec, raw([0x10n, 0n, ren, BigInt(0x14 + name.length * 2), 10n]))).toMatchObject({
      info_class: 10,
      info_target: { s: name },
      info_flags: 0,
    });
    const disp = mem.writeUInt(mem.alloc(1), 1, 1);
    expect(decodeEnter(env, spec, raw([0x10n, 0n, disp, 1n, 13n])).info_delete).toBe(1);
    const dispEx = mem.writeUInt(mem.alloc(4), 0x12, 4);
    expect(decodeEnter(env, spec, raw([0x10n, 0n, dispEx, 4n, 64n]))).toMatchObject({
      info_flags: 0x12,
      info_delete: 0,
    });
    const eof = mem.writeUInt(mem.alloc(8), 1234, 8);
    expect(decodeEnter(env, spec, raw([0x10n, 0n, eof, 8n, 20n])).info_eof).toBe("0x4d2");
    const basic = mem.alloc(0x28);
    mem.writeUInt(basic + 0x20n, 0x80, 4);
    expect(decodeEnter(env, spec, raw([0x10n, 0n, basic, 0x28n, 4n])).info_attributes).toBe(0x80);
    expect(decodeEnter(env, spec, raw([0x10n, 0n, basic, 0x28n, 99n]))).toMatchObject({ info_class: 99 });
  });

  it("KEY_VALUE information at leave: partial (class 2) and full (class 1); value preview only with capture_value_bytes", () => {
    const mem = new FakeMem();
    const spec = specOf("NtQueryValueKey");
    const partial = mem.alloc(0x10);
    mem.writeUInt(partial + 4n, 4, 4);
    mem.writeUInt(partial + 8n, 4, 4);
    mem.writeUInt(partial + 0xcn, 42, 4);
    const args = raw([0x10n, mem.ustr("Answer"), 2n, partial, 16n, mem.alloc(4)]);
    const cells = decodeEnter(envOf(mem), spec, args);
    decodeLeave(envOf(mem), spec, args, 0n, true, cells);
    expect(cells).toMatchObject({ info_type: 4, info_size: 4 });
    expect(cells.info_preview).toBeUndefined();
    const withPreview = envOf(mem, { fileBytes: 0, netBytes: 0, valueBytes: 64 });
    decodeLeave(withPreview, spec, args, 0n, true, cells);
    expect(cells.info_preview).toBe(42);
    const full = mem.alloc(0x30);
    mem.writeUInt(full + 4n, 1, 4); // REG_SZ
    mem.writeUInt(full + 8n, 0x20, 4); // DataOffset
    mem.writeUInt(full + 0xcn, 8, 4);
    mem.write(full + 0x20n, new Uint8Array([0x62, 0, 0x65, 0, 0x61, 0, 0, 0]));
    const fargs = raw([0x10n, mem.ustr("Name"), 1n, full, 48n, mem.alloc(4)]);
    const fc = decodeEnter(withPreview, spec, fargs);
    decodeLeave(withPreview, spec, fargs, 0n, true, fc);
    expect(fc).toMatchObject({ info_type: 1, info_size: 8, info_preview: { s: "bea" } });
  });

  it("NtSetValueKey data: type and size always, payload never by default (S4 Payloads)", () => {
    const mem = new FakeMem();
    const cells = decodeEnter(
      envOf(mem),
      specOf("NtSetValueKey"),
      raw([0x10n, mem.ustr("Name"), 0n, 1n, mem.wstr("bea"), 8n]),
    );
    expect(cells).toMatchObject({ value: { s: "Name" }, type: 1, data_type: 1, data_size: 8, size: 8 });
    expect(cells.data_preview).toBeUndefined();
  });

  it("buffers: write length at enter, read length from IoStatus at leave, payload hex only with capture bytes", () => {
    const mem = new FakeMem();
    const buf = mem.write(mem.alloc(4), new Uint8Array([1, 2, 3, 4]));
    const iosb = mem.iosb();
    const args = raw([0x10n, 0n, 0n, 0n, iosb, buf, 4n, 0n]);
    const capped = envOf(mem, { fileBytes: 2, netBytes: 0, valueBytes: 0 });
    expect(decodeEnter(capped, specOf("NtWriteFile"), args)).toMatchObject({
      buffer_len: 4,
      buffer_hex: { s: "0102" },
      offset: null,
    });
    const read = decodeEnter(envOf(mem), specOf("NtReadFile"), args);
    mem.setIosb(iosb, 3);
    decodeLeave(envOf(mem), specOf("NtReadFile"), args, 0n, true, read);
    expect(read).toMatchObject({ buffer_len: 3, iosb: "0x3" });
    const failed = decodeEnter(envOf(mem), specOf("NtReadFile"), args);
    decodeLeave(envOf(mem), specOf("NtReadFile"), args, 0xc000_0011n, false, failed);
    expect(failed).toMatchObject({ buffer_len: null, iosb: null });
  });

  it("WSABUF totals, recv length from the return value", () => {
    const mem = new FakeMem();
    const bufs = mem.alloc(32);
    mem.writeUInt(bufs, 10, 4);
    mem.writeUInt(bufs + 16n, 6, 4);
    expect(decodeEnter(envOf(mem), specOf("WSASend"), raw([0x300n, bufs, 2n, mem.alloc(4), 0n, 0n])).buffers_len).toBe(
      16,
    );
    const args = raw([0x300n, mem.alloc(16), 16n, 0n]);
    const cells = decodeEnter(envOf(mem), specOf("recv"), args);
    decodeLeave(envOf(mem), specOf("recv"), args, 12n, true, cells);
    expect(cells.buffer_len).toBe(12);
  });
});

describe("profile decoders: DNS, process and loader structures", () => {
  it("GetAddrInfoW result list (≤ 8, only on rc 0) and DNS_QUERY_REQUEST", () => {
    const mem = new FakeMem();
    const pp = mem.slot();
    const second = mem.alloc(48);
    mem.writeUInt(second + 32n, mem.sockaddrIn("10.0.0.2", 0), 8);
    const first = mem.alloc(48);
    mem.writeUInt(first + 32n, mem.sockaddrIn("10.0.0.1", 0), 8);
    mem.writeUInt(first + 40n, second, 8);
    mem.writeUInt(pp, first, 8);
    const spec = specOf("GetAddrInfoW");
    const args = raw([mem.wstr("example.test"), 0n, 0n, pp]);
    const cells = decodeEnter(envOf(mem), spec, args);
    decodeLeave(envOf(mem), spec, args, 0n, true, cells);
    expect(cells).toMatchObject({
      node: { s: "example.test" },
      result_count: 2,
      result_addr0: { s: "10.0.0.1" },
      result_addr1: { s: "10.0.0.2" },
    });
    const req = mem.alloc(24);
    mem.writeUInt(req + 8n, mem.wstr("example.test"), 8);
    mem.writeUInt(req + 16n, 28, 2);
    expect(decodeEnter(envOf(mem), specOf("DnsQueryEx"), raw([req]))).toEqual({
      request_name: { s: "example.test" },
      request_type: 28,
    });
  });

  it("process structures: CLIENT_ID, PROCESS_INFORMATION at leave, RTL_USER_PROCESS_PARAMETERS (normalized and offset form)", () => {
    const mem = new FakeMem();
    const cid = mem.alloc(16);
    mem.writeUInt(cid, 77, 8);
    mem.writeUInt(cid + 8n, 78, 8);
    expect(decodeEnter(envOf(mem), specOf("NtOpenProcess"), raw([mem.slot(), 0x1000n, 0n, cid]))).toMatchObject({
      client_pid: 77,
      client_tid: 78,
      access: 0x1000,
    });
    const pi = mem.alloc(24);
    mem.writeUInt(pi + 0x10n, 1234, 4);
    mem.writeUInt(pi + 0x14n, 1235, 4);
    const spawnArgs = raw([0n, mem.wstr("C:\\a.exe"), mem.wstr("a.exe -x"), 0n, 0n, 0n, 4n, 0n, 0n, 0n, pi]);
    const spawn = decodeEnter(envOf(mem), specOf("CreateProcessInternalW"), spawnArgs);
    decodeLeave(envOf(mem), specOf("CreateProcessInternalW"), spawnArgs, 1n, true, spawn);
    expect(spawn).toMatchObject({
      image: { s: "C:\\a.exe" },
      cmdline: { s: "a.exe -x" },
      flags: 4,
      info_pid: 1234,
      info_tid: 1235,
    });
    // non-normalized block: Buffer fields are offsets from the block (Flags +8 bit 0 clear)
    const block = mem.alloc(0x100);
    const text = "C:\\b.exe";
    for (let i = 0; i < text.length; i++) mem.writeUInt(block + 0xc0n + BigInt(2 * i), text.charCodeAt(i), 2);
    mem.writeUInt(block + 0x60n, text.length * 2, 2);
    mem.writeUInt(block + 0x68n, 0xc0, 8);
    mem.writeUInt(block + 0x70n, 0, 2);
    mem.writeUInt(block + 0x38n, 0, 2);
    const params = decodeEnter(
      envOf(mem),
      specOf("NtCreateUserProcess"),
      raw([mem.slot(), mem.slot(), 0n, 0n, 0n, 0n, 0n, 0n, block]),
    );
    expect(params).toMatchObject({ params_image: { s: text }, params_cmdline: { s: "" } });
  });

  it("LdrLoadDll search path: odd values are flags; LdrGetProcedureAddressForCaller ordinal when the name is null", () => {
    const mem = new FakeMem();
    expect(decodeEnter(envOf(mem), specOf("LdrLoadDll"), raw([1n, 0n, mem.ustr("x.dll"), mem.slot()]))).toMatchObject({
      search_flags: 1,
      name: { s: "x.dll" },
    });
    expect(
      decodeEnter(envOf(mem), specOf("LdrLoadDll"), raw([mem.wstr("C:\\p"), 0n, mem.ustr("x.dll"), mem.slot()])).search,
    ).toEqual({ s: "C:\\p" });
    expect(
      decodeEnter(envOf(mem), specOf("LdrGetProcedureAddressForCaller"), raw([0x7000n, 0n, 12n, mem.slot(), 0n])),
    ).toMatchObject({ name: null, name_ordinal: 12 });
  });

  it("module handles of modules loaded before tracing are named through moduleName and cached", () => {
    const mem = new FakeMem();
    const env: DecodeEnv<bigint> = { ...envOf(mem), moduleName: (b) => (b === 0x7000n ? "kernel32.dll" : null) };
    const cells = decodeEnter(
      env,
      specOf("LdrGetProcedureAddressForCaller"),
      raw([0x7000n, mem.anstr("Sleep"), 0n, mem.slot(), 0n]),
    );
    expect(cells).toMatchObject({ module: "0x7000", module_name: { s: "kernel32.dll" }, name: { s: "Sleep" } });
    expect(env.cache.get("0x7000")).toEqual({ kind: "module", name: "kernel32.dll" });
  });
});
