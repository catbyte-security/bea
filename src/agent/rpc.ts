// =================================================================================================
// src/agent/rpc.ts — WP3-AGENT the wrapper every RPC passes through (S4 §5.2, §18; DESIGN §5.3).
//  - admission: shutting-down → only status/ping; before hello → only PRE_HELLO_METHODS; gates re-checked from
//    hello.gates (defense in depth; the host enforces first);
//  - conversion: thrown errors → AgentResult via mapThrown (the host only sees transport throws); a guard-page error on
//    a BEA page re-arms that page (stolen guard, CT-I5);
//  - the announcement scope: streams and jobs created inside the call are announced once its reply was produced;
//  - timing: calls counted, slices over rpc_slice_ms listed in status().rpc.slow (last 16);
//  - rpc.exports.dispose (not an AgentRpcMethods method): Frida calls it on script unload — also when the host is
//    killed with taskkill /F (A-36, VERIFIED [CT-lab E4]) — and it synchronously disarms everything BEA armed.
// =================================================================================================
import { GATED_METHODS, PRE_HELLO_METHODS, type AgentMethodName, type AgentRpcImpl } from "../shared/agentProtocol.js";
import { fail, mapThrown } from "./errors.js";
import type { AgentCore } from "./state.js";

const SLOW_KEEP = 16;

const noteTiming = (c: AgentCore, name: string, t0: number): void => {
  const us = c.native.nowUs() - t0;
  if (us <= c.limits.rpc_slice_ms * 1000) return;
  c.counters.slow.push({ method: name, us: Math.round(us) });
  if (c.counters.slow.length > SLOW_KEEP) c.counters.slow.shift();
};

const failThrown = (c: AgentCore, e: unknown, name: string) => {
  c.guards.noteThrown(e);
  const error = mapThrown(e, name);
  if (error._tag === "GuardPage" && c.guards.ownsPage(BigInt(error.address))) return fail({ ...error, owner: "bea" });
  return fail(error);
};

const wrapOne = (c: AgentCore, name: AgentMethodName, fn: (p: unknown) => unknown) => {
  const gate = GATED_METHODS[name];
  return (params: unknown): unknown => {
    c.counters.rpcCalls++;
    if (c.phase === "shutting-down" && name !== "status" && name !== "ping")
      return fail({ _tag: "ShuttingDown", message: "agent is shutting down" });
    if (c.phase === "loaded" && !PRE_HELLO_METHODS.includes(name))
      return fail({ _tag: "NotReady", message: "hello() must be called first" });
    if (gate !== undefined && !c.gates[gate])
      return fail({ _tag: "GateClosed", message: `gate ${gate} is closed for this session`, gate });
    const t0 = c.native.nowUs();
    c.scope.begin();
    c.streams.beginScope();
    const end = (): void => {
      c.streams.endScope();
      c.scope.end();
      noteTiming(c, name, t0);
    };
    try {
      const r = fn(params ?? {});
      if (r instanceof Promise)
        return r.then(
          (v: unknown) => {
            end();
            return v;
          },
          (e: unknown) => {
            end();
            return failThrown(c, e, name);
          },
        );
      end();
      return r;
    } catch (e) {
      end();
      return failThrown(c, e, name);
    }
  };
};

/** Synchronous teardown on script unload: never throws, never waits, never needs the host. */
export const disposeAll = (c: AgentCore): void => {
  for (const hook of [...c.hooks.onDispose].reverse()) {
    try {
      hook();
    } catch {
      // keep disarming the rest
    }
  }
  try {
    c.guards.disarmAll();
  } catch {
    // best effort
  }
  try {
    c.calls.drain();
    c.events.stop();
    c.threads.dispose();
    c.modules.dispose();
  } catch {
    // best effort
  }
};

/** Every RPC method wrapped, plus `dispose` for Frida's unload (index.ts assigns the result to rpc.exports). */
export function wrapAll(c: AgentCore, impl: AgentRpcImpl): Record<string, (p: unknown) => unknown> {
  c.bootStage = "rpc";
  const out: Record<string, (p: unknown) => unknown> = {};
  for (const name of Object.keys(impl) as AgentMethodName[])
    out[name] = wrapOne(c, name, impl[name] as (p: unknown) => unknown);
  out["dispose"] = () => {
    disposeAll(c);
    return undefined;
  };
  return out;
}
