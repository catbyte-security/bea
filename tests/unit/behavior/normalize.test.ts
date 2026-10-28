import { describe, expect, it } from "vitest";

import { normalizeKey, normalizeNtPath, stripQuery } from "../../../src/application/behavior/normalize.js";
import {
  decodeFlags,
  fileAccess,
  isExecutable,
  isWritable,
  KEY_ACCESS,
  ntstatusName,
  ntSuccess,
  processAccess,
  protectionText,
  regTypeName,
  wsaErrorName,
} from "../../../src/domain/winConstants.js";

describe("NT path normalization (S6 §6.2)", () => {
  it.each([
    ["\\??\\C:\\dir\\a.txt", "C:\\dir\\a.txt", "file"],
    ["\\??\\C:\\dir\\", "C:\\dir", "file"],
    ["\\??\\C:\\", "C:\\", "file"],
    ["\\??\\UNC\\srv\\share\\x", "\\\\srv\\share\\x", "file"],
    ["\\DosDevices\\D:\\y", "D:\\y", "file"],
    ["\\??\\pipe\\foo", "pipe\\foo", "pipe"],
    ["\\Device\\NamedPipe\\bar", "\\Device\\NamedPipe\\bar", "pipe"],
    ["\\Device\\ConDrv\\Connect", "\\Device\\ConDrv\\Connect", "console"],
    ["CONOUT$", "CONOUT$", "console"],
    ["\\Device\\Afd\\Endpoint", "\\Device\\Afd\\Endpoint", "afd"],
    ["\\Device\\RasAcd", "\\Device\\RasAcd", "device"],
    ["\\Device\\HarddiskVolume3\\x", "\\Device\\HarddiskVolume3\\x", "file"],
    ["<handle 0x1a4>", "<handle 0x1a4>", "unknown"],
  ])("%s → %s (%s)", (nt, path, kind) => {
    expect(normalizeNtPath(nt)).toEqual({ path, kind });
  });
});

describe("registry key normalization (S6 §6.3)", () => {
  const sid = "S-1-5-21-1-2-3-1001";
  it("maps machine, current user, classes and other users", () => {
    expect(normalizeKey("\\REGISTRY\\MACHINE\\SOFTWARE\\X", sid)).toBe("HKLM\\SOFTWARE\\X");
    expect(normalizeKey(`\\REGISTRY\\USER\\${sid}\\Software\\Y`, sid)).toBe("HKCU\\Software\\Y");
    expect(normalizeKey(`\\REGISTRY\\USER\\${sid}`, sid)).toBe("HKCU");
    expect(normalizeKey(`\\REGISTRY\\USER\\${sid}_Classes\\.txt`, sid)).toBe("HKCU\\Software\\Classes\\.txt");
    expect(normalizeKey("\\REGISTRY\\USER\\S-1-5-18\\Software", sid)).toBe("HKU\\S-1-5-18\\Software");
    expect(normalizeKey("\\REGISTRY\\USER\\S-1-5-21-9-9-9-500\\Software", sid)).toBe(
      "HKU\\S-1-5-21-9-9-9-500\\Software",
    );
  });
  it("without a known SID, user-account SIDs are taken as HKCU and service SIDs stay HKU", () => {
    expect(normalizeKey(`\\REGISTRY\\USER\\${sid}\\Software`, null)).toBe("HKCU\\Software");
    expect(normalizeKey("\\REGISTRY\\USER\\S-1-12-1-5-6-7-8\\X", null)).toBe("HKCU\\X");
    expect(normalizeKey("\\REGISTRY\\USER\\.DEFAULT\\X", null)).toBe("HKU\\.DEFAULT\\X");
    expect(normalizeKey("\\registry\\machine\\system", null)).toBe("HKLM\\system");
    expect(normalizeKey("<handle 0x10>\\Sub", null)).toBe("<handle 0x10>\\Sub");
  });
});

describe("URL query stripping (S6 §6.1)", () => {
  it("strips query strings and fragments", () => {
    expect(stripQuery("https://h/p?token=1#x")).toEqual({ text: "https://h/p", stripped: true });
    expect(stripQuery("/p")).toEqual({ text: "/p", stripped: false });
  });
});

describe("winConstants", () => {
  it("NTSTATUS names and NT_SUCCESS", () => {
    expect(ntstatusName(0)).toBe("STATUS_SUCCESS");
    expect(ntstatusName(0xc0000034)).toBe("STATUS_OBJECT_NAME_NOT_FOUND");
    expect(ntstatusName(0xc0000135)).toBe("STATUS_DLL_NOT_FOUND");
    expect(ntstatusName(0xc0001234)).toBe("0xc0001234");
    expect(ntSuccess(0x103)).toBe(true);
    expect(ntSuccess(0x80000006)).toBe(false);
    expect(ntSuccess(0xc0000022)).toBe(false);
  });
  it("PAGE_* protections, access masks, registry types and Winsock errors", () => {
    expect(protectionText(0x04)).toBe("rw-");
    expect(protectionText(0x20)).toBe("r-x");
    expect(protectionText(0x40)).toBe("rwx");
    expect(protectionText(0x104)).toBe("rw-+guard");
    expect(protectionText(0x03)).toBe("0x3");
    expect([isExecutable(0x40), isWritable(0x40), isExecutable(0x04), isWritable(0x20)]).toEqual([
      true,
      true,
      false,
      false,
    ]);
    expect(fileAccess(0x80100080)).toEqual(["read"]);
    expect(fileAccess(0x40100080)).toEqual(["read", "write"]);
    expect(fileAccess(0x00110080)).toEqual(["read", "delete"]);
    expect(processAccess(0x1fffff)).toEqual(["all_access"]);
    expect(processAccess(0x1000)).toEqual(["query_limited_information"]);
    expect(processAccess(0x28)).toEqual(["vm_operation", "vm_write"]);
    expect(decodeFlags(0x20019, KEY_ACCESS)).toEqual(["query", "enumerate", "notify"]);
    expect(regTypeName(4)).toBe("REG_DWORD");
    expect(regTypeName(99)).toBe("REG_TYPE_99");
    expect(wsaErrorName(10061)).toBe("WSAECONNREFUSED");
    expect(wsaErrorName(1)).toBe("WSA_ERROR_1");
  });
});
