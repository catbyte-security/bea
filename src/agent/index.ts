import {
  AGENT_PROTOCOL,
  AGENT_PROTOCOL_MINOR,
  type AgentRpcImpl,
  type AgentRpcMethods,
} from "../shared/agentProtocol.js";
import { AGENT_BUILD_ID, AGENT_VERSION } from "./buildInfo.js";
import * as core from "./coreRpc.js";
import * as jobs from "./jobs.js";
import * as instruments from "./instruments.js";
import * as inspect from "./inspect.js";
import * as memory from "./memory.js";
import * as code from "./code.js";
import * as memwrite from "./memwrite.js";
import * as scan from "./scan.js";
import * as hooks from "./hooks.js";
import * as profiles from "./profiles.js";
import * as watch from "./watch.js";
import * as trace from "./trace.js";
import * as override from "./override.js";
import * as call from "./call.js";
import * as dump from "./dump.js";
import { mapThrown } from "./errors.js";
import { wrapAll } from "./rpc.js";
import { createCore } from "./state.js";

/**
 * PRE-WIRED agent entry (WP0; never edited later). Boot order (S4 §3.2): core CModule → single exception dispatcher
 * (FIRST, once) → exit/UEF hooks → events → modules/threads → features → rpc.exports → ready. WP-AGENT fills the
 * core services behind `core.init`; feature WPs fill their own files. A missing RPC method is a compile error
 * (satisfies AgentRpcImpl) and an extra one too (_noExtra).
 */
const c = createCore();
try {
  core.init(c);
  jobs.init(c);
  instruments.init(c);
  inspect.init(c);
  memory.init(c);
  code.init(c);
  memwrite.init(c);
  scan.init(c);
  hooks.init(c);
  profiles.init(c);
  watch.init(c);
  trace.init(c);
  override.init(c);
  call.init(c);
  dump.init(c);
  const impl = {
    ...core.rpc,
    ...jobs.rpc,
    ...instruments.rpc,
    ...inspect.rpc,
    ...memory.rpc,
    ...code.rpc,
    ...memwrite.rpc,
    ...scan.rpc,
    ...hooks.rpc,
    ...profiles.rpc,
    ...watch.rpc,
    ...trace.rpc,
    ...override.rpc,
    ...call.rpc,
    ...dump.rpc,
  } satisfies AgentRpcImpl;
  type Extra = Exclude<keyof typeof impl, keyof AgentRpcMethods>;
  const _noExtra: [Extra] extends [never] ? true : never = true;
  void _noExtra;
  rpc.exports = wrapAll(c, impl);
  send({
    bea: "ready",
    protocol: AGENT_PROTOCOL,
    protocol_minor: AGENT_PROTOCOL_MINOR,
    agent_version: AGENT_VERSION,
    build_id: AGENT_BUILD_ID,
    frida_version: Frida.version,
    runtime: Script.runtime === "V8" ? "V8" : "QJS",
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    js_thread_id: c.jsTid,
    t0_wall_ms: c.t0Wall,
    features: c.features,
    early: c.early,
  });
} catch (e) {
  send({ bea: "fatal", stage: c.bootStage, error: mapThrown(e, "boot") });
}
