import { describe, expect, it } from "vitest";

import { ModuleTable, isUnder } from "../../../src/agent/pure/profileModules.js";

/** The observer-fed module table that replaces ModuleMap.update() while hooks are active (deadlock avoidance). */
describe("ModuleTable", () => {
  const table = (): ModuleTable => {
    const t = new ModuleTable();
    t.add({ name: "b.dll", path: "C:\\Windows\\System32\\b.dll", base: 0x7ff0_2000_0000n, size: 0x1000 });
    t.add({ name: "a.exe", path: "C:\\app\\a.exe", base: 0x1_4000_0000n, size: 0x8000 });
    t.add({ name: "ntdll.dll", path: "C:\\WINDOWS\\SYSTEM32\\ntdll.dll", base: 0x7ff0_1000_0000n, size: 0x20_0000 });
    return t;
  };

  it("finds the containing module by address (binary search over sorted bases)", () => {
    const t = table();
    expect(t.find(0x1_4000_0000n)?.name).toBe("a.exe");
    expect(t.find(0x1_4000_7fffn)?.name).toBe("a.exe");
    expect(t.find(0x1_4000_8000n)).toBeNull();
    expect(t.find(0x7ff0_1010_0000n)?.name).toBe("ntdll.dll");
    expect(t.find(0x7ff0_2000_0fffn)?.name).toBe("b.dll");
    expect(t.find(0n)).toBeNull();
  });

  it("names module handles only by exact base; by-name lookup is case-insensitive", () => {
    const t = table();
    expect(t.nameAt(0x7ff0_2000_0000n)).toBe("b.dll");
    expect(t.nameAt(0x7ff0_2000_0010n)).toBeNull();
    expect(t.findByName("NTDLL.DLL")?.base).toBe(0x7ff0_1000_0000n);
  });

  it("re-adding a base replaces the entry; remove drops it", () => {
    const t = table();
    t.add({ name: "c.dll", path: "C:\\c.dll", base: 0x7ff0_2000_0000n, size: 0x2000 });
    expect(t.size).toBe(3);
    expect(t.find(0x7ff0_2000_1fffn)?.name).toBe("c.dll");
    t.remove(0x7ff0_2000_0000n);
    expect(t.find(0x7ff0_2000_0000n)).toBeNull();
    expect(t.size).toBe(2);
  });

  it("isUnder compares the system root case-insensitively", () => {
    expect(isUnder("C:\\WINDOWS\\System32\\x.dll", "c:\\windows\\")).toBe(true);
    expect(isUnder("C:\\app\\x.dll", "c:\\windows\\")).toBe(false);
  });
});
