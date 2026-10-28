import { describe, expect, it } from "vitest";

import { injectSkillMetadata, pinPackageVersion, SkillMetadataError } from "../../../src/cli/setup/skillMetadata.js";
import { parseSkillFrontmatter } from "../../../src/cli/setup/skill.js";

const authored =
  '---\nname: bea-dynamic-analysis\ndescription: >\n  Dynamic analysis.\nmetadata:\n  version: "1"\n  author: bea\n---\n\n# BEA\nRun `npx -y bea-agents@latest doctor`.\n';

describe("build-skill transforms (DESIGN §7)", () => {
  it("injects tool_count and bea_version into the metadata block; doctor reads them back", () => {
    const built = injectSkillMetadata(authored, { toolCount: 37, beaVersion: "0.1.0" });
    expect(built).toContain('metadata:\n  version: "1"\n  author: bea\n  tool_count: 37\n  bea_version: "0.1.0"\n---');
    expect(parseSkillFrontmatter(built)).toEqual({
      name: "bea-dynamic-analysis",
      version: "1",
      tool_count: 37,
      bea_version: "0.1.0",
    });
    expect(built.startsWith("---\nname: bea-dynamic-analysis\n")).toBe(true);
  });
  it("adds a metadata block when there is none; keeps CRLF", () => {
    const crlf = "---\r\nname: bea-dynamic-analysis\r\n---\r\nbody\r\n";
    expect(injectSkillMetadata(crlf, { toolCount: 2, beaVersion: "9.9.9" })).toBe(
      '---\r\nname: bea-dynamic-analysis\r\nmetadata:\r\n  tool_count: 2\r\n  bea_version: "9.9.9"\r\n---\r\nbody\r\n',
    );
  });
  it("refuses sources that already carry generated metadata or no frontmatter", () => {
    expect(() =>
      injectSkillMetadata(authored.replace("author: bea", "tool_count: 3"), { toolCount: 1, beaVersion: "1" }),
    ).toThrow(SkillMetadataError);
    expect(() => injectSkillMetadata("# no frontmatter", { toolCount: 1, beaVersion: "1" })).toThrow(
      SkillMetadataError,
    );
  });
  it("pins bea-agents@latest to the package version", () => {
    expect(pinPackageVersion(authored, "bea-agents", "0.1.0")).toContain("npx -y bea-agents@0.1.0 doctor");
  });
});
