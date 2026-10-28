import type { EMULATION_TOOLS } from "../../contracts/areas/emulation.js";
import type { BeaApplication } from "../BeaApplication.js";
import { DiffService } from "../diff/DiffService.js";
import { EmulationService } from "../emu/EmulationService.js";
import type { HandlersFor } from "../handlerContext.js";

/**
 * Handlers for area emulation (WP14-EMU): emu_open, emu_call and diff_function. The services are built lazily on the
 * first call, so constructing the handler table never touches a service slot (every area's boundary tests build it
 * over fakeServices). One EmulationService per application holds the emulation state lineage the frozen EmuPort does
 * not carry; DiffService runs its emulation leg through the same service.
 */
export const createEmulationHandlers = (app: BeaApplication): HandlersFor<typeof EMULATION_TOOLS> => {
  let built: { readonly emulation: EmulationService; readonly diff: DiffService } | null = null;
  const services = (): { readonly emulation: EmulationService; readonly diff: DiffService } => {
    if (built === null) {
      const emulation = new EmulationService(app);
      built = { emulation, diff: new DiffService(app, emulation) };
    }
    return built;
  };
  return {
    emu_open: (input, ctx) => services().emulation.open(input, ctx),
    emu_call: (input, ctx) => services().emulation.call(input, ctx),
    diff_function: (input, ctx) => services().diff.run(input, ctx),
  };
};
