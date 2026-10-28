import type { BeaConfig } from "../domain/config.js";
import { gateDisabled } from "../domain/errors/constructors.js";
import { err, ok } from "../domain/result.js";
import type { GateEvaluator } from "./handlerContext.js";

/** Gates are fixed for the life of the process (config is parsed once at startup). */
export const createGateEvaluator = (config: BeaConfig): GateEvaluator => {
  const isEnabled = (gate: keyof BeaConfig["gates"]): boolean => config.gates[gate].value;
  return {
    isEnabled,
    require: (gate, operation) => (isEnabled(gate) ? ok(undefined) : err(gateDisabled(operation, gate))),
    requireUnlessOwned: (gate, operation, ownership) =>
      ownership === "owned" || isEnabled(gate) ? ok(undefined) : err(gateDisabled(operation, gate)),
  };
};
