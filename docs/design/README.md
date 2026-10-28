# BEA design record (2026-10-28)

These files are the design record BEA v0.1 was built from. They are archived as written and are not kept in sync with
the code; where they disagree with the source or with `docs/decisions.md`, the source and `docs/decisions.md` win.

| File | What it is |
|---|---|
| `DESIGN.md` | The authoritative integrated design, revision 2: decisions, file tree, the verbatim shared core (§4), subsystem designs, the 37-tool catalog, the test plan, the work packages, risks, and appendices (conflict register, critique dispositions). |
| `S1-core.md` … `S6-catalog.md` | The six specialist designs (core/MCP/CLI, evidence and addresses, Frida host and jobhost, in-target agent, emulator, catalog/skill/tests). `DESIGN.md` cites them as normative annexes, as amended by its Appendix A. |
| `CRITIC-technical.md`, `CRITIC-integration.md` | The two adversarial reviews of the integrated design. Their dispositions are in `DESIGN.md` Appendix C. |
| `final-wps.json` | The work-package list (owned paths, dependencies, acceptance) used to drive implementation. |

The research that fed the design is in `../research/`: `BRIEF.md` is the consolidated brief, and the other notes cover
REA's patterns (`rea-*.md`), Frida 17.23.2 on Windows (`ext-frida.md`), emulation and debugger backends
(`ext-backends.md`), and other dynamic-analysis MCP servers (`ext-landscape.md`).

Citations such as `[INT-lab]`, `[REV-lab]` or paths under `bea-lab/` point to experiment directories from the build
session's scratch space. Those directories were not preserved; the documents quote the results that mattered.
