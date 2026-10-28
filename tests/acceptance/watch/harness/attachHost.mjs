// WP9 safety-net lab host (DESIGN §5.3, CT-I4; started and later killed with `taskkill /F` by
// tests/acceptance/watch/agentEngines.test.ts). Attaches to the test-owned fixture <pid>, loads the harness bundle,
// arms a hot debug-register write watch on g_hot_sink, prints READY once hits arrive, ARMED, then LIVE (the traps
// BEA's dispatcher counted over 500 ms and the safety net's DR count, which must stay 0 while the agent is loaded).
// On the hard kill Frida unloads the script and calls rpc.exports.dispose (the engines' synchronous disarm, as WP3's
// core does); traps already in flight then meet no BEA dispatcher, and only the leaked native safety net stands
// between them and the target. dispose "0" skips the disarm (worst case: the watch stays armed through the unload).
// argv: <pid> <bundle.js> <attached:"1"|"0"> [dispose:"1"|"0"]
import { readFileSync } from "node:fs";

const [pidText, bundlePath, attachedText, disposeText] = process.argv.slice(2);
const mod = await import("frida");
const frida = mod.default ?? mod;
const device = await frida.getLocalDevice();
const session = await device.attach(Number(pidText));
const script = await session.createScript(readFileSync(bundlePath, "utf8"), { runtime: "qjs" });
script.logHandler = () => {};
let hits = 0;
let announced = false;
script.message.connect((m) => {
  if (m.type === "send" && m.payload?.type === "rows") {
    hits += m.payload.rows.length;
    if (hits >= 50 && !announced) {
      announced = true;
      process.stdout.write(`READY hits=${hits}\n`);
    }
  } else if (m.type === "send" && (m.payload?.type === "unclaimed" || m.payload?.type === "fault"))
    process.stdout.write(`AGENT-${String(m.payload.type).toUpperCase()} ${JSON.stringify(m.payload)}\n`);
  else if (m.type === "error") process.stdout.write(`AGENT-ERROR ${m.description}\n`);
});
await script.load();
await script.exports.configure({ attached: attachedText === "1", dispose: disposeText !== "0" });
const layout = await script.exports.layout();
const armed = await script.exports.watchInstall({
  method: "debug-register",
  address: `0x${BigInt(layout.hotSink).toString(16)}`,
  size: 8,
  access: "write",
  threads: "all",
  capture: { registers: "none", backtrace: 0, values: true },
  lifetime: { duration_ms: 600_000, max_hits: 1_000_000_000 },
});
const status = await script.exports.status();
process.stdout.write(`ARMED ok=${String(armed.ok)} net=${String(status.netInstalled)}\n`);
// while the agent is loaded every trap is BEA's dispatcher's: the net (registered last) must not have seen one
await new Promise((resolve) => setTimeout(resolve, 500));
const live = await script.exports.status();
process.stdout.write(
  `LIVE traps0=${String(status.traps)} traps=${String(live.traps)} netdr=${String(live.safetyNet?.dr ?? "none")}\n`,
);
setInterval(() => {}, 1000);
