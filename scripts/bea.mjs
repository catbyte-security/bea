#!/usr/bin/env node
import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { default: pkg } = await import("../package.json", { with: { type: "json" } });
process.env.BEA_PACKAGE_VERSION = pkg.version;
// Windows: an empty USERPROFILE makes os.homedir() throw inside dependencies at import time.
if (process.platform === "win32" && process.env.USERPROFILE === "") delete process.env.USERPROFILE;

const SIGPIPE_EXIT = 141;
let stdoutClosed = false;
const route =
  args[0] === "mcp"
    ? args[1] === "doctor"
      ? "mcp-doctor"
      : args.length === 1
        ? "mcp-stdio"
        : // REA's rule: only flags may follow `mcp`, so `--port 0` stays valid (the value is not a flag).
          (args[1]?.startsWith("-") ?? false) && args.slice(1).includes("--http")
          ? "mcp-http"
          : "mcp-usage"
    : ["--version", "-v", "version"].includes(args[0] ?? "")
      ? "version"
      : "cli";
const RUNTIME = {
  "mcp-stdio": "dist/main/mcp.js",
  "mcp-http": "dist/main/mcp.js",
  "mcp-doctor": "dist/main/mcpDoctor.js",
  cli: "dist/main/cli.js",
};

if (route === "version") process.stdout.write(`${pkg.version}\n`);
else if (route === "mcp-usage") {
  process.stderr.write(
    "Usage: bea mcp | bea mcp --http [--port N] [--json-response] [--connection-file PATH] | bea mcp doctor [--json]\n",
  );
  process.exitCode = 1;
} else if (!(await exists(RUNTIME[route]))) {
  process.stderr.write(
    `BEA's compiled runtime is missing. Run \`npm ci && npm run build\` in ${packageRoot}, then retry.\n`,
  );
  process.exitCode = 1;
} else if (route === "mcp-stdio") await (await import("../dist/main/mcp.js")).runStdioMain();
else if (route === "mcp-http") await (await import("../dist/main/mcp.js")).runHttpMain(args.slice(1));
else {
  guardClosedStdout();
  const io = {
    stdout: (text) => {
      if (!stdoutClosed) process.stdout.write(text);
    },
    stdoutIsTty: process.stdout.isTTY === true,
  };
  const code =
    route === "mcp-doctor"
      ? await (
          await import("../dist/main/mcpDoctor.js")
        ).runMcpDoctorMain(args.slice(2), { dispatcherPath: fileURLToPath(import.meta.url), io })
      : await (await import("../dist/main/cli.js")).runCliMain(args, io);
  process.exitCode = stdoutClosed ? SIGPIPE_EXIT : code;
  // Review fix LIFE-2: never rely on a natural exit once the CLI may have loaded Frida (its DeviceManager env-cleanup
  // hook blocks forever on a wedged frida-core); exit explicitly once stdout and stderr drained.
  exitWhenFlushed(process.exitCode);
}

function exitWhenFlushed(code) {
  let pending = 2;
  const exit = () => process.exit(code);
  const done = () => {
    pending -= 1;
    if (pending === 0) exit();
  };
  setTimeout(exit, 2000); // ref'd backstop for a reader that stopped reading
  for (const stream of [process.stdout, process.stderr]) {
    if (stream.destroyed || (stream === process.stdout && stdoutClosed)) done();
    else stream.write("", done);
  }
}

function guardClosedStdout() {
  process.stdout.on("error", (cause) => {
    if (cause?.code === "EPIPE") {
      stdoutClosed = true;
      process.exitCode = SIGPIPE_EXIT;
      return;
    }
    throw cause;
  });
}
async function exists(rel) {
  try {
    await access(resolve(packageRoot, rel));
    return true;
  } catch (c) {
    if (c?.code === "ENOENT") return false;
    throw c;
  }
}
