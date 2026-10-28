import { PSEUDO_API } from "../../../../src/shared/apiProfiles.js";
import type { AgentSim } from "./agentSim.js";
import { MINUS_ONE } from "./fakeMem.js";

/**
 * behavior.exe's steps (fixtures/native/behavior.c, S6 §10.1 table) replayed at the NT/Winsock level the profiles hook,
 * in the shapes the S4 lab recorded (F6, F9, F10, F16). Used by the pipeline unit test (agent engine → api/1 rows →
 * host events → ApiSummary); the real-Frida acceptance test asserts the same expectations on the live fixture.
 */
export const SCENARIO = {
  dir: "C:\\T\\out",
  sid: "S-1-5-21-111-222-333-1001",
  regKey: "run-42",
  port: 50_123,
  childPid: 4242,
  mathlibBase: 0x7ff6_0000_0000n,
  rwBase: 0x0200_0000n,
  rwxBase: 0x0300_0000n,
} as const;

const S_OK = 0n;
const NAME_NOT_FOUND = 0xc000_0034n;
const DLL_NOT_FOUND = 0xc000_0135n;

interface Ctx {
  readonly sim: AgentSim;
  readonly m: AgentSim["mem"];
  readonly nt: (leaf: string) => string;
  readonly open: (
    exportName: "NtCreateFile" | "NtOpenFile",
    path: string,
    access: number,
    disposition: number,
    options: number,
    info: number,
  ) => bigint;
  readonly close: (h: bigint) => void;
  readonly io: (exportName: "NtReadFile" | "NtWriteFile", h: bigint, n: number) => void;
  readonly setInfo: (h: bigint, cls: number, info: bigint, len: number) => void;
}

const context = (sim: AgentSim): Ctx => {
  const m = sim.mem;
  const nt = (leaf: string) => `\\??\\${SCENARIO.dir}\\${leaf}`;
  let nextHandle = 0x100n;
  const open = (
    exportName: "NtCreateFile" | "NtOpenFile",
    path: string,
    access: number,
    disposition: number,
    options: number,
    info: number,
  ) => {
    const ph = m.slot();
    const iosb = m.iosb();
    const h = (nextHandle += 4n);
    const args =
      exportName === "NtCreateFile"
        ? [ph, BigInt(access), m.oa(path), iosb, 0n, 0x80n, 0n, BigInt(disposition), BigInt(options), 0n, 0n]
        : [ph, BigInt(access), m.oa(path), iosb, 7n, BigInt(options)];
    sim.call(exportName, args, S_OK, {
      kernel: () => {
        m.writeUInt(ph, h, 8);
        m.setIosb(iosb, info);
      },
    });
    return h;
  };
  const close = (h: bigint) => sim.call("NtClose", [h], S_OK);
  const io = (exportName: "NtReadFile" | "NtWriteFile", h: bigint, n: number) => {
    const iosb = m.iosb();
    sim.call(exportName, [h, 0n, 0n, 0n, iosb, m.alloc(16), BigInt(n), 0n, 0n], S_OK, {
      kernel: () => m.setIosb(iosb, n),
    });
  };
  const setInfo = (h: bigint, cls: number, info: bigint, len: number) =>
    sim.call("NtSetInformationFile", [h, m.iosb(), info, BigInt(len), BigInt(cls)], S_OK);
  return { sim, m, nt, open, close, io, setInfo };
};

const fileStep = ({ sim, m, nt, open, close, io, setInfo }: Ctx): void => {
  // ------------------------------------------------------------------ file
  let h = open("NtCreateFile", nt("bea_behavior_a.txt"), 0x4010_0080, 5, 0x60, 2);
  io("NtWriteFile", h, 5);
  close(h);
  h = open("NtCreateFile", nt("bea_behavior_a.txt"), 0x8010_0080, 1, 0x60, 1);
  io("NtReadFile", h, 5);
  close(h);
  h = open("NtOpenFile", nt("bea_behavior_a.txt"), 0x0011_0080, 0, 0x4060, 1);
  const target = nt("bea_behavior_b.txt");
  const rename = m.alloc(0x14 + target.length * 2);
  m.writeUInt(rename, 1, 1);
  m.writeUInt(rename + 0x10n, target.length * 2, 4);
  for (let i = 0; i < target.length; i++) m.writeUInt(rename + 0x14n + BigInt(2 * i), target.charCodeAt(i), 2);
  setInfo(h, 10, rename, 0x14 + target.length * 2);
  close(h);
  sim.call("NtQueryAttributesFile", [m.oa(nt("does_not_exist.txt")), m.alloc(64)], NAME_NOT_FOUND);
  h = open("NtOpenFile", nt("bea_behavior_b.txt"), 0x0011_0080, 0, 0x4060, 1);
  const dispEx = m.alloc(4);
  m.writeUInt(dispEx, 0x3, 4);
  setInfo(h, 64, dispEx, 4);
  close(h);
  h = open("NtCreateFile", nt("sub"), 0x0010_0001, 2, 0x21, 2);
  close(h);
  h = open("NtOpenFile", `\\??\\${SCENARIO.dir}`, 0x0010_0001, 0, 0x4021, 1);
  sim.call("NtQueryDirectoryFileEx", [h, 0n, 0n, 0n, m.iosb(), m.alloc(64), 0x268n, 3n, 1n, m.ustr("*")], S_OK);
  close(h);
  h = open("NtOpenFile", nt("sub"), 0x0011_0080, 0, 0x4021, 1);
  setInfo(h, 64, dispEx, 4);
  close(h);
};

const registryStep = ({ sim, m, close }: Ctx): void => {
  // ------------------------------------------------------------------ registry (F10: HKCU via \REGISTRY\USER\<SID>)
  const hkcu = m.slot();
  sim.call("NtOpenKey", [hkcu, 0x0200_0000n, m.oa(`\\REGISTRY\\USER\\${SCENARIO.sid}`)], S_OK, {
    kernel: () => m.writeUInt(hkcu, 0x200n, 8),
  });
  const keyPath = `Software\\BEA-Fixture\\${SCENARIO.regKey}`;
  const created = m.slot();
  const disposition = m.alloc(4);
  sim.call("NtCreateKey", [created, 0xf003fn, m.oa(keyPath, 0x200n), 0n, 0n, 0n, disposition], S_OK, {
    kernel: () => {
      m.writeUInt(created, 0x204n, 8);
      m.writeUInt(disposition, 1, 4);
    },
  });
  sim.call("NtSetValueKey", [0x204n, m.ustr("Answer"), 0n, 4n, m.writeUInt(m.alloc(4), 42, 4), 4n], S_OK);
  sim.call("NtSetValueKey", [0x204n, m.ustr("Name"), 0n, 1n, m.wstr("bea"), 8n], S_OK);
  const kv = m.alloc(32);
  sim.call("NtQueryValueKey", [0x204n, m.ustr("Answer"), 2n, kv, 32n, m.alloc(4)], S_OK, {
    kernel: () => {
      m.writeUInt(kv + 4n, 4, 4);
      m.writeUInt(kv + 8n, 4, 4);
    },
  });
  sim.call("NtDeleteValueKey", [0x204n, m.ustr("Name")], S_OK);
  close(0x204n);
  const del = m.slot();
  sim.call("NtOpenKeyEx", [del, 0x10000n, m.oa(keyPath, 0x200n), 0n], S_OK, {
    kernel: () => m.writeUInt(del, 0x208n, 8),
  });
  sim.call("NtDeleteKey", [0x208n], S_OK);
  close(0x208n);
  sim.keyRoots.set(0x14cn, "\\REGISTRY\\MACHINE"); // HKLM root opened before tracing: resolved by NtQueryKey (F10)
  const ro = m.slot();
  sim.call("NtOpenKeyEx", [ro, 0x20019n, m.oa("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0x14cn), 0n], S_OK, {
    kernel: () => m.writeUInt(ro, 0x20cn, 8),
  });
  sim.call("NtQueryValueKey", [0x20cn, m.ustr("ProductName"), 2n, m.alloc(256), 256n, m.alloc(4)], S_OK, {
    kernel: () => undefined,
  });
  close(0x20cn);
  close(0x200n);
};

const networkStep = ({ sim, m }: Ctx): void => {
  // ------------------------------------------------------------------ network
  const ppResult = m.slot();
  const ai = m.alloc(48);
  m.writeUInt(ai + 4n, 2, 4);
  m.writeUInt(ai + 32n, m.sockaddrIn("127.0.0.1", 0), 8);
  m.writeUInt(ai + 40n, 0n, 8);
  sim.call("GetAddrInfoW", [m.wstr("localhost"), 0n, 0n, ppResult], 0n, { kernel: () => m.writeUInt(ppResult, ai, 8) });
  const sock = (s: bigint, type: number) =>
    sim.call("WSASocketW", [2n, BigInt(type), type === 1 ? 6n : 17n, 0n, 0n, 0x81n], s);
  sock(0x300n, 1);
  sock(0x304n, 1);
  sim.endpoints.set(0x300n, { family: 2, addr: "127.0.0.1", port: SCENARIO.port });
  sim.call("bind", [0x300n, m.sockaddrIn("127.0.0.1", 0), 16n], 0n);
  sim.call("listen", [0x300n, 1n], 0n);
  sim.call("connect", [0x304n, m.sockaddrIn("127.0.0.1", SCENARIO.port), 16n], 0n);
  sim.call("accept", [0x300n, 0n, 0n], 0x308n);
  sim.call("send", [0x304n, m.alloc(16), 16n, 0n], 16n);
  sim.call("recv", [0x308n, m.alloc(16), 16n, 8n], 16n);
  sock(0x30cn, 2);
  sim.call("sendto", [0x30cn, m.alloc(16), 16n, 0n, m.sockaddrIn("127.0.0.1", SCENARIO.port), 16n], 16n);
  for (const s of [0x30cn, 0x308n, 0x304n, 0x300n]) sim.call("closesocket", [s], 0n);
};

const processStep = ({ sim, m }: Ctx): void => {
  // ------------------------------------------------------------------ process (CreateProcessW → CreateProcessInternalW)
  const pi = m.alloc(24);
  const image = "C:\\T\\behavior.exe";
  const spawn = sim.begin("CreateProcessInternalW", [
    0n,
    m.wstr(image),
    m.wstr(`"${image}" --child --hold-ms 0`),
    0n,
    0n,
    0n,
    0n,
    0n,
    0n,
    m.alloc(104),
    pi,
    0n,
  ]);
  const ph = m.slot();
  const th = m.slot();
  const params = m.alloc(0x80);
  m.writeUInt(params + 8n, 1, 4); // normalized
  const writeUs = (at: bigint, s: string) => {
    const us = m.ustr(s);
    m.writeUInt(at, m.readU16(us), 2);
    m.writeUInt(at + 8n, m.readPointer(us + 8n), 8);
  };
  writeUs(params + 0x60n, `\\??\\${image}`);
  writeUs(params + 0x70n, `"${image}" --child --hold-ms 0`);
  writeUs(params + 0x38n, "C:\\T\\");
  sim.call("NtCreateUserProcess", [ph, th, 0x2000000n, 0x2000000n, 0n, 0n, 0n, 0n, params, 0n, 0n], S_OK, {
    depth: 1,
    kernel: () => {
      m.writeUInt(ph, 0x400n, 8);
      m.writeUInt(th, 0x404n, 8);
    },
  });
  m.writeUInt(pi + 0x10n, SCENARIO.childPid, 4);
  m.writeUInt(pi + 0x14n, SCENARIO.childPid + 1, 4);
  sim.end(spawn, 1n);
  const cid = m.alloc(16);
  m.writeUInt(cid, SCENARIO.childPid, 8);
  const hp = m.slot();
  sim.call("NtOpenProcess", [hp, 0x1000n, m.oa(""), cid], S_OK, { kernel: () => m.writeUInt(hp, 0x408n, 8) });
};

const moduleStep = ({ sim, m }: Ctx): void => {
  // ------------------------------------------------------------------ module
  const base = m.slot();
  sim.call("LdrLoadDll", [1n, 0n, m.ustr("mathlib.dll"), base], S_OK, {
    kernel: () => m.writeUInt(base, SCENARIO.mathlibBase, 8),
  });
  sim.pseudo(PSEUDO_API.MODULES.id, {
    ev: { s: "L" },
    name: { s: "mathlib.dll" },
    path: { s: "C:\\T\\mathlib.dll" },
    base: `0x${SCENARIO.mathlibBase.toString(16)}`,
    size: 0x9000,
  });
  sim.call(
    "LdrGetProcedureAddressForCaller",
    [SCENARIO.mathlibBase, m.anstr("mf_lerp"), 0n, m.slot(), 0n, 0x401000n],
    S_OK,
  );
  sim.call("LdrUnloadDll", [SCENARIO.mathlibBase], S_OK);
  const missing = sim.begin("LdrLoadDll", [1n, 0n, m.ustr("bea_missing_dll.dll"), m.slot()]);
  for (const dir of ["C:\\T", "C:\\Windows\\system32"])
    sim.call("NtQueryAttributesFile", [m.oa(`\\??\\${dir}\\bea_missing_dll.dll`), m.alloc(64)], NAME_NOT_FOUND, {
      depth: 1,
    });
  sim.end(missing, DLL_NOT_FOUND);
};

const memoryStep = ({ sim, m }: Ctx): void => {
  // ------------------------------------------------------------------ memory (RW → RX → RW, then an RWX alloc)
  const protect = (from: number, to: number) => {
    const pb = m.slot(SCENARIO.rwBase);
    const ps = m.slot(4096);
    const old = m.alloc(4);
    sim.call("NtProtectVirtualMemory", [MINUS_ONE, pb, ps, BigInt(to), old], S_OK, {
      kernel: () => m.writeUInt(old, from, 4),
    });
  };
  protect(0x04, 0x20);
  protect(0x20, 0x04);
  sim.call("NtFreeVirtualMemory", [MINUS_ONE, m.slot(SCENARIO.rwBase), m.slot(0), 0x8000n], S_OK);
  sim.pseudo(PSEUDO_API.MEMMAP.id, {
    ev: { s: "new-rwx" },
    base: `0x${SCENARIO.rwxBase.toString(16)}`,
    size: 4096,
    protection: { s: "rwx" },
    module: null,
    seen: { s: "free" },
  });
  sim.call("NtFreeVirtualMemory", [MINUS_ONE, m.slot(SCENARIO.rwxBase), m.slot(0), 0x8000n], S_OK);
};

export const runBehaviorScenario = (sim: AgentSim): void => {
  const ctx = context(sim);
  for (const step of [fileStep, registryStep, networkStep, processStep, moduleStep, memoryStep]) step(ctx);
};
