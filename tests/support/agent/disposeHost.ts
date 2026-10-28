// =================================================================================================
// tests/support/agent/disposeHost.ts — a minimal stand-alone "host" process for the WP3 dispose acceptance test
// (S4 §18, A-36, [CT-lab E4]). Run as `node disposeHost.ts <pid> <bundle.js> <module> <export>`: it attaches to a
// process the TEST started, loads the test agent, says hello (attached session), resolves `module!export` and arms
// the core's BEA guard on that page (the target keeps touching it, so a guard left armed after unload kills it), then
// prints one `READY {json}` line and idles until it is killed (the test uses taskkill /F: no JS cleanup runs here,
// so only the agent's rpc.exports.dispose can disarm). Self-contained: node builtins + frida only.
// =================================================================================================
import { readFileSync } from "node:fs";

type Exports = Record<string, (params: unknown) => Promise<unknown>>;
interface Script {
  load(): Promise<void>;
  post(message: unknown): void;
  logHandler: (level: string, text: string) => void;
  readonly message: { connect(h: (m: { type: string; payload?: Record<string, unknown> }) => void): void };
  readonly exports: Exports;
}

const [pidText, bundlePath, moduleName, exportName] = process.argv.slice(2);
const mod = (await import("frida")) as unknown as { default?: unknown };
const frida = (mod.default ?? mod) as {
  DeviceManager: new () => {
    getDeviceById(
      id: string,
      timeout: number,
    ): Promise<{ attach(pid: number): Promise<{ createScript(s: string, o: object): Promise<Script> }> }>;
  };
};
const dm = new frida.DeviceManager();
const device = await dm.getDeviceById("local", 2000);
const session = await device.attach(Number(pidText));
const script = await session.createScript(readFileSync(String(bundlePath), "utf8"), {
  name: "bea-agent",
  runtime: "qjs",
});
script.logHandler = () => undefined;
let ready = false;
script.message.connect((m) => {
  if (m.type !== "send" || m.payload === undefined) return;
  if (m.payload["bea"] === "ready") ready = true;
  if (m.payload["bea"] === "crash" || m.payload["bea"] === "exit")
    script.post({ type: "ack", token: m.payload["ack"] });
});
await script.load();
for (let i = 0; i < 200 && !ready; i++) await new Promise((r) => setTimeout(r, 25));
const call = (name: string, params: unknown): Promise<unknown> => script.exports[name]!(params);
await call("hello", {
  protocol: "bea-agent/1",
  min_minor: 0,
  host: { name: "bea", version: "0.1.0-test" },
  session: { session_id: "00000000-0000-4000-8000-0000000000d1", instance_id: "pi_dispose", owned: false },
  gates: { write_memory: false, override_function: false, call_function: false },
  crash: {
    first_chance_rows: true,
    first_chance_blocking: false,
    crash_class: ["access-violation"],
    ack_timeout_ms: 1000,
    last_chance_ack_timeout_ms: 2000,
    max_blocking_per_10s: 8,
    rows_per_sec: 1000,
    stack_bytes: 256,
    backtrace_depth: 16,
    include_xmm: false,
  },
  streams: { flush_ms: 50, exceptions: true, threads: false },
  flow: { high_water_bytes: 33554432, low_water_bytes: 8388608 },
});
const resolved = (await call("resolveTargets", { targets: [{ module: moduleName, export: exportName }] })) as {
  value: { results: { ok: boolean; target?: { va: string } }[] };
};
const va = resolved.value.results[0]?.target?.va;
const armed = (await call("testGuardAddress", { address: va })) as { page: string };
await new Promise((r) => setTimeout(r, 300));
const state = await call("testGuardState", { page: armed.page });
process.stdout.write(`READY ${JSON.stringify({ va, armed, state })}\n`);
setInterval(() => undefined, 1000);
