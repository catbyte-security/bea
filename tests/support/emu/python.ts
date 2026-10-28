import { spawnSync } from "node:child_process";

/**
 * The absolute interpreter the emulation lanes pass as BEA_PYTHON to a server started with a minimal environment
 * (temp HOME/LOCALAPPDATA can break PATH launchers such as the WindowsApps aliases). BEA_PYTHON wins; else the
 * `python` on PATH reports its own sys.executable (run isolated, -I). null when there is none.
 */
let cached: { readonly value: string | null } | undefined;
export const realPython = (): string | null => {
  cached ??= (() => {
    const command = process.env["BEA_PYTHON"] ?? "python";
    const probe = spawnSync(command, ["-I", "-c", "import sys; print(sys.executable)"], {
      encoding: "utf8",
      windowsHide: true,
      timeout: 30_000,
    });
    const value = probe.status === 0 ? probe.stdout.trim() : "";
    return { value: value.length > 0 ? value : null };
  })();
  return cached.value;
};
