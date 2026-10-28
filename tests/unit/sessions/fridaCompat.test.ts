import type * as Frida from "frida";
import { describe, expectTypeOf, it } from "vitest";

import type {
  CancellableLike,
  FridaProcessLike,
  FridaScriptLike,
  FridaSessionLike,
  OutputHandler,
} from "../../../src/providers/frida/fridaPorts.js";

/**
 * Compile-time "vendor fits port" assertions (S3 §4.1, rea-testing §6.1): `npm run typecheck` fails when a frida
 * upgrade changes a member the provider relies on. Members whose vendor types carry string enums are bridged in
 * src/providers/frida/fridaAdapters.ts; their runtime values are asserted here through the enums' string literal types.
 */
type DetachReasonOfPort = Parameters<FridaSessionLike["detached"]["connect"]>[0] extends (
  reason: infer R,
  crash: unknown,
) => void
  ? R
  : never;

describe("frida 17.23.2 fits the provider's narrow ports", () => {
  it("Cancellable, Script, Session, Process and the output handler", () => {
    expectTypeOf<Frida.Cancellable>().toExtend<CancellableLike>();
    expectTypeOf<Frida.Script["isDestroyed"]>().toExtend<FridaScriptLike["isDestroyed"]>();
    expectTypeOf<Frida.Script["exports"]>().toExtend<FridaScriptLike["exports"]>();
    expectTypeOf<Frida.Script["post"]>().toExtend<FridaScriptLike["post"]>();
    expectTypeOf<Frida.Script["destroyed"]>().toExtend<FridaScriptLike["destroyed"]>();
    expectTypeOf<Frida.Session["pid"]>().toExtend<FridaSessionLike["pid"]>();
    expectTypeOf<Pick<Frida.Process, "pid" | "name">>().toExtend<Pick<FridaProcessLike, "pid" | "name">>();
    expectTypeOf<OutputHandler>().toExtend<Frida.OutputHandler>();
  });

  it("the enum values the adapters pass are the string literals the ports use", () => {
    expectTypeOf<`${Frida.Stdio}`>().toExtend<"pipe" | "inherit">();
    expectTypeOf<"qjs" | "v8">().toExtend<`${Frida.ScriptRuntime}`>();
    expectTypeOf<"minimal" | "metadata">().toExtend<`${Frida.Scope}`>();
    expectTypeOf<`${Frida.SessionDetachReason}`>().toExtend<DetachReasonOfPort>();
    expectTypeOf<`${Frida.MessageType}`>().toExtend<"send" | "error">();
    expectTypeOf<`${Frida.LogLevel}`>().toExtend<"info" | "warning" | "error">();
  });
});
