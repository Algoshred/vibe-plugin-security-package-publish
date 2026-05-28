import { describe, expect, test } from "bun:test";

import { CosignSlsaProvider } from "../src/provider.js";
import { COSIGN_VERSION, SLSA_GENERATOR_VERSION } from "../src/tools-manifest.js";

const baseInput = (workdir: string, config: Record<string, unknown> = {}) => ({
  runId: "pkg-pub-1",
  vibeId: "v1",
  workspaceId: "w1",
  repoUrl: "x",
  repoLocalPath: "/tmp",
  commit: "c",
  stage: "package.publish" as const,
  profile: { kind: "backend", languages: ["ts"], runtimes: ["bun"] },
  policyLevel: "advisory" as const,
  config,
  workdir,
});

describe("CosignSlsaProvider", () => {
  test("provider name + stage are immutable identifiers", () => {
    const p = new CosignSlsaProvider();
    expect(p.name).toBe("cosign-slsa");
    expect(p.stage).toBe("package.publish");
  });

  test("toolVersion encodes both Cosign + SLSA generator versions", () => {
    const p = new CosignSlsaProvider();
    expect(p.toolVersion).toContain(COSIGN_VERSION);
    expect(p.toolVersion).toContain(SLSA_GENERATOR_VERSION);
  });

  test("metadata advertises supply-chain-relevant profiles", () => {
    const m = new CosignSlsaProvider().metadata();
    expect(m.supportedProfiles).toContain("backend");
    expect(m.supportedProfiles).toContain("container");
    expect(m.supportedProfiles).toContain("iac");
    expect(m.stage).toBe("package.publish");
  });

  test("run() returns a single info finding describing the stub", async () => {
    const p = new CosignSlsaProvider();
    const result = await p.run(baseInput("/tmp", {}));
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].category).toBe("supplychain");
    expect(result.summary.info).toBe(1);
    expect(result.evidence).toEqual([]);
  });

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new CosignSlsaProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });
});
