#!/usr/bin/env node
// scripts/smoke-stdio.mjs (WP0; DESIGN §10.1 step 3). Run after `npm run build`: spawns `bea mcp` over stdio, lists
// tools, calls bea_status (valid and invalid input), closes the client and checks a clean exit inside the 2 s budget.
// WP0 shared-tree amendments: the server runs from BEA_DIST_DIR when set (a snapshot from scripts/snapshot-dist.mjs;
// its dispatcher is <dist>/../scripts/bea.mjs) with a fresh temp BEA_HOME (removed afterwards), and the smoke also
// checks that the server process is gone after close.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const distDir = process.env.BEA_DIST_DIR;
const dispatcher =
  distDir !== undefined && distDir !== ""
    ? resolve(distDir, "..", "scripts", "bea.mjs")
    : fileURLToPath(new URL("./bea.mjs", import.meta.url));
const home = await mkdtemp(join(tmpdir(), "bea-smoke-"));
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [dispatcher, "mcp"],
  stderr: "pipe",
  env: {
    PATH: process.env.PATH ?? "",
    SystemRoot: process.env.SystemRoot ?? "",
    BEA_HOME: home,
    BEA_LOG_LEVEL: "info",
  },
});
let stderr = "";
transport.stderr?.on("data", (chunk) => (stderr += chunk));
const client = new Client({ name: "bea-smoke", version: "1" });
await client.connect(transport);
const serverPid = transport.pid;
const tools = await client.listTools();
const status = await client.callTool({ name: "bea_status", arguments: {} });
const bad = await client.callTool({ name: "bea_status", arguments: { bogus: 1 } });
const closeStart = performance.now();
await client.close();
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    return cause?.code === "EPERM";
  }
};
const out = {
  dispatcher,
  tools: tools.tools.length,
  tool_names: tools.tools.map((t) => t.name),
  status_ok: status.isError !== true,
  envelope: {
    evidence_id: status.structuredContent?.evidence_id,
    coverage: status.structuredContent?.coverage?.status,
  },
  text_equals_structured: status.content?.[0]?.text === JSON.stringify(status.structuredContent),
  untrusted: status._meta?.provenance?.untrusted_content === true,
  bad: JSON.parse(bad.content?.[0]?.text ?? "{}").error?.code ?? null,
  close_ms: Math.round(performance.now() - closeStart),
  server_exited: serverPid === null ? null : !alive(serverPid),
  stderr_tail: stderr.split("\n").filter(Boolean).slice(-2),
};
await rm(home, { recursive: true, force: true, maxRetries: 5 }).catch(() => undefined);
process.stdout.write(`${JSON.stringify(out, null, 1)}\n`);
const ok =
  out.status_ok &&
  out.envelope.evidence_id === null &&
  out.text_equals_structured &&
  out.untrusted &&
  out.bad === "invalid_request" &&
  out.close_ms < 2000 &&
  out.server_exited !== false;
process.exitCode = ok ? 0 : 1;
