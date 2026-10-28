import { describe, expect, it } from "vitest";

import { checkLocalInputPath, isNetworkPath } from "../../src/application/localPaths.js";
import { localPathSchema } from "../../src/contracts/schemas/primitives.js";

/**
 * Review fix SEC-2: caller-supplied input paths (pe_path, image_path, dump_path, import_evidence path, spawn cwd) are
 * local files only. Opening \\host\share\x authenticates to that host with the user's NTLM credentials.
 */
describe("input path rule (SEC-2)", () => {
  const remote = [
    "\\\\host\\share\\x.dll",
    "//host/share/x.dll",
    "\\\\?\\UNC\\host\\share\\x",
    "\\\\.\\pipe\\x",
    "/\\host\\x",
  ];

  it("the contract refuses UNC, device and long-path forms; drive- and POSIX-absolute paths pass", () => {
    for (const path of remote) expect(localPathSchema.safeParse(path).success, path).toBe(false);
    for (const path of ["C:\\games\\x.exe", "c:/games/x.exe", "/opt/x"])
      expect(localPathSchema.safeParse(path).success, path).toBe(true);
    for (const path of ["games\\x.exe", "C:x.exe", "\\x.exe", ""])
      expect(localPathSchema.safeParse(path).success, path).toBe(false);
  });

  it("the handler check refuses non-drive-absolute text on Windows before any filesystem access", async () => {
    const touched: string[] = [];
    const resolve = async (path: string) => {
      touched.push(path);
      return path;
    };
    for (const path of [...remote, "relative\\x", "C:x", "\\rooted\\x"]) {
      const checked = await checkLocalInputPath("import_evidence", "path", path, "win32", resolve);
      expect(!checked.ok && checked.error._tag, path).toBe("InputError");
    }
    expect(touched).toEqual([]);
  });

  it("refuses a drive path whose final path is a network location (mapped drive, junction to a share)", async () => {
    const mapped = await checkLocalInputPath(
      "emu_open",
      "dump_path",
      "Z:\\bundle",
      "win32",
      async () => "\\\\srv\\share\\bundle",
    );
    expect(!mapped.ok && mapped.error).toMatchObject({ _tag: "AccessDenied", reason: "policy" });
    const local = await checkLocalInputPath("emu_open", "dump_path", "C:\\bundle", "win32", async () => "C:\\bundle");
    expect(local.ok).toBe(true);
    const missing = await checkLocalInputPath("emu_open", "dump_path", "C:\\nope", "win32", async () => null);
    expect(missing.ok).toBe(true); // the open reports the missing file itself
    expect(isNetworkPath("\\\\?\\UNC\\srv\\share\\x")).toBe(true);
    expect(isNetworkPath("\\\\?\\C:\\long\\path")).toBe(false);
    expect(isNetworkPath("C:\\x")).toBe(false);
  });
});
