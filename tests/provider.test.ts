import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { CosignSlsaProvider } from "../src/provider.js";
import { COSIGN_VERSION, SLSA_GENERATOR_VERSION } from "../src/tools-manifest.js";

interface TestEnv {
  workdir: string;
  artifactPath: string;
  artifactDigest: string;
  cosignStubKey: string; // a fake cosign stub that succeeds with --key
  cosignStubNoKey: string; // a fake cosign stub that fails without --key
}

let env: TestEnv;

beforeAll(async () => {
  const root = await fs.mkdtemp(path.join(tmpdir(), "vibe-pkg-pub-test-"));
  const workdir = path.join(root, "workdir");
  await fs.mkdir(workdir, { recursive: true });

  const artifactPath = path.join(root, "demo-artifact.tar.gz");
  const artifactBytes = Buffer.from("hello-artifact-bytes\n");
  await fs.writeFile(artifactPath, artifactBytes);
  const artifactDigest = createHash("sha256").update(artifactBytes).digest("hex");

  // Stub cosign — succeeds when --key is present, writes empty .sig + .cert.
  const stubWithKey = path.join(root, "cosign-with-key.sh");
  await fs.writeFile(
    stubWithKey,
    `#!/usr/bin/env bash
# Locate --output-signature and --output-certificate args, write 0-byte files.
SIG=""
CERT=""
HAS_KEY=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-signature) SIG="$2"; shift 2 ;;
    --output-certificate) CERT="$2"; shift 2 ;;
    --key) HAS_KEY=1; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$HAS_KEY" = "1" ]; then
  echo -n "stub-signature-bytes" > "$SIG"
  echo -n "stub-cert-pem" > "$CERT"
  exit 0
fi
echo "Error: no OIDC token available" >&2
exit 1
`,
    { mode: 0o755 },
  );

  const stubNoKey = path.join(root, "cosign-no-key.sh");
  await fs.writeFile(
    stubNoKey,
    `#!/usr/bin/env bash
echo "Error: unauthenticated" >&2
exit 1
`,
    { mode: 0o755 },
  );

  env = {
    workdir,
    artifactPath,
    artifactDigest,
    cosignStubKey: stubWithKey,
    cosignStubNoKey: stubNoKey,
  };
});

afterAll(async () => {
  try {
    await fs.rm(path.dirname(env.workdir), { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
});

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

describe("CosignSlsaProvider metadata", () => {
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

  test("cancel() on an unknown run is a no-op", async () => {
    const p = new CosignSlsaProvider();
    await expect(p.cancel("nonexistent")).resolves.toBeUndefined();
  });
});

describe("CosignSlsaProvider run() — skip paths", () => {
  test("skips with reason artifact-path-missing when no artifactPath", async () => {
    const p = new CosignSlsaProvider();
    const result = await p.run(baseInput(env.workdir, {}));
    expect(result.status).toBe("succeeded");
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].ruleId).toBe("signing.cosign.skipped");
    expect(result.findings[0].description).toMatch(/artifact-path-missing/);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].category).toBe("supplychain");
    expect(result.evidence).toEqual([]);
  });

  test("skips with reason artifact-path-unreachable when artifact missing", async () => {
    const p = new CosignSlsaProvider();
    const result = await p.run(
      baseInput(env.workdir, { artifactPath: "/nonexistent/path/foo.tgz" }),
    );
    expect(result.status).toBe("succeeded");
    expect(result.findings[0].ruleId).toBe("signing.cosign.skipped");
    expect(result.findings[0].description).toMatch(/artifact-path-unreachable/);
  });

  test("skips cosign step with keyless-oidc-unavailable but still emits provenance", async () => {
    // No SIGSTORE_OIDC_TOKEN / GITHUB_ACTIONS in test env, no cosignKey →
    // the provider must report keyless-oidc-unavailable but still generate
    // a provenance file.
    const oldGh = process.env.GITHUB_ACTIONS;
    const oldOidc = process.env.SIGSTORE_OIDC_TOKEN;
    const oldAct = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    delete process.env.GITHUB_ACTIONS;
    delete process.env.SIGSTORE_OIDC_TOKEN;
    delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    try {
      const p = new CosignSlsaProvider();
      const result = await p.run(
        baseInput(env.workdir, {
          artifactPath: env.artifactPath,
          cosignBinaryOverride: env.cosignStubNoKey,
        }),
      );
      expect(result.status).toBe("succeeded");
      const skip = result.findings.find((f) => f.ruleId === "signing.cosign.skipped");
      expect(skip).toBeDefined();
      expect(skip?.description).toMatch(/keyless-oidc-unavailable/);
      const prov = result.findings.find((f) => f.ruleId === "provenance.slsa.generated");
      expect(prov).toBeDefined();
      const provEvidence = result.evidence.find((e) => e.type === "provenance");
      expect(provEvidence).toBeDefined();
    } finally {
      if (oldGh) process.env.GITHUB_ACTIONS = oldGh;
      if (oldOidc) process.env.SIGSTORE_OIDC_TOKEN = oldOidc;
      if (oldAct) process.env.ACTIONS_ID_TOKEN_REQUEST_URL = oldAct;
    }
  });
});

describe("CosignSlsaProvider run() — happy path", () => {
  test("signs artifact + emits cosign-bundle + provenance evidence", async () => {
    const p = new CosignSlsaProvider();
    const result = await p.run(
      baseInput(env.workdir, {
        artifactPath: env.artifactPath,
        cosignKey: "/path/to/fake-cosign.key",
        cosignKeyPassword: "secret",
        cosignBinaryOverride: env.cosignStubKey,
      }),
    );
    expect(result.status).toBe("succeeded");
    const signed = result.findings.find((f) => f.ruleId === "signing.cosign.signed");
    expect(signed).toBeDefined();
    expect(signed?.title).toMatch(/key-based/);
    const prov = result.findings.find((f) => f.ruleId === "provenance.slsa.generated");
    expect(prov).toBeDefined();
    expect(prov?.description).toMatch(new RegExp(env.artifactDigest));

    // Evidence: cosign-bundle + provenance.
    const bundle = result.evidence.find((e) => e.type === "cosign-bundle");
    expect(bundle).toBeDefined();
    const provE = result.evidence.find((e) => e.type === "provenance");
    expect(provE).toBeDefined();

    // Provenance file should exist with the right digest.
    const provRaw = await fs.readFile(provE!.localPath, "utf-8");
    expect(provRaw).toContain(env.artifactDigest);
    expect(provRaw).toContain("https://slsa.dev/provenance/v1");
    expect(provRaw).toContain(
      "https://vibecontrols.com/builder/vibe-plugin-security-package-publish",
    );

    // Bundle file should contain the artifact name + base64 sig + cert.
    const bundleRaw = JSON.parse(await fs.readFile(bundle!.localPath, "utf-8"));
    expect(bundleRaw.artifact.name).toBe(path.basename(env.artifactPath));
    expect(bundleRaw.artifact.digest.sha256).toBe(env.artifactDigest);
    expect(bundleRaw.keyless).toBe(false);
    expect(typeof bundleRaw.signature).toBe("string");
    expect(typeof bundleRaw.certificate).toBe("string");
  });

  test("respects slsaPredicateType override", async () => {
    const p = new CosignSlsaProvider();
    const result = await p.run(
      baseInput(env.workdir, {
        artifactPath: env.artifactPath,
        cosignKey: "/fake.key",
        cosignBinaryOverride: env.cosignStubKey,
        slsaPredicateType: "https://slsa.dev/provenance/v0.2",
      }),
    );
    const provE = result.evidence.find((e) => e.type === "provenance");
    expect(provE).toBeDefined();
    const raw = await fs.readFile(provE!.localPath, "utf-8");
    expect(raw).toContain("https://slsa.dev/provenance/v0.2");
  });
});
