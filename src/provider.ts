/**
 * CosignSlsaProvider — implements SecurityProvider for stage `package.publish`.
 *
 * Wave 2 scaffold. The real implementation will:
 *  - Sign the published artifact with Cosign:
 *      * keyless via Fulcio OIDC when GITHUB_ACTIONS / SIGSTORE_OIDC is set, OR
 *      * key-based with input.config.cosignKey (private-key + password).
 *  - Generate a SLSA v1.0 provenance document (intoto+json) describing the
 *    builder, build invocation, materials, and the signed digest.
 *  - Emit both the cosign bundle and the provenance file as evidence.
 *
 * TODO: replace the stub `run()` body with the real cosign + slsa-generator
 * subprocess pipeline. The `ensureToolInstalled()` machinery is already wired
 * to resolve the pinned `cosign` binary from TOOLS_MANIFEST.
 */
import type { ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import { resolveToolPath } from "@vibecontrols/vibe-plugin-security/tool-installer";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

import { COSIGN_VERSION, SLSA_GENERATOR_VERSION, TOOLS_MANIFEST } from "./tools-manifest.js";

interface CosignSlsaConfig {
  artifactPath?: string;
  artifactDigest?: string; // sha256:<hex>
  cosignKey?: string; // path to cosign.key for key-based signing
  cosignPassword?: string;
  fulcioUrl?: string;
  rekorUrl?: string;
  extraCosignArgs?: string[];
  extraSlsaArgs?: string[];
}

export class CosignSlsaProvider implements SecurityProvider {
  readonly name = "cosign-slsa";
  readonly stage: SecurityStage = "package.publish";
  readonly toolVersion = `cosign@${COSIGN_VERSION}+slsa-generator@${SLSA_GENERATOR_VERSION}`;

  private host?: HostServices;
  private cosignPath?: string;
  private active = new Map<string, ChildProcess>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    const dataDir =
      this.host?.getDataDir?.() ?? path.join(process.env.HOME ?? ".", ".boff/vibecontrols");
    this.cosignPath = await resolveToolPath(
      {
        dataDir,
        log: {
          info: (m) => this.host?.logger?.info?.("cosign-slsa-provider", m),
          warn: (m) => this.host?.logger?.warn?.("cosign-slsa-provider", m),
          error: (m) => this.host?.logger?.error?.("cosign-slsa-provider", m),
        },
      },
      "cosign",
      TOOLS_MANIFEST.cosign,
    );
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    const cfg = (input.config as CosignSlsaConfig) ?? {};

    input.onProgress?.({ pct: 10, message: "package.publish scaffold — emitting stub finding" });

    // TODO(wave-2): replace this stub body with the real cosign + slsa-generator
    // pipeline. Keep the result shape identical so the meta plugin's
    // dispatcher does not need to change.
    const fingerprint = createHash("sha256")
      .update(`${this.name}:${input.runId}:${cfg.artifactDigest ?? "no-artifact"}`)
      .digest("hex");

    const findings: NormalizedFinding[] = [
      {
        fingerprint,
        ruleId: `${this.name}.stub`,
        title: "package.publish: cosign-slsa scaffolded — real signer integration pending",
        severity: "info",
        category: "supplychain",
        description:
          "Wave 2 scaffold for the package.publish lifecycle stage. The real provider will sign the published artifact via Cosign (keyless Fulcio OIDC or key-based with input.config.cosignKey) and emit a SLSA v1.0 intoto+json provenance document. Today this stub records that the stage ran so the dispatcher can chain the next stage.",
        remediation:
          "Wire the real cosign sign + slsa-generator provenance generation; emit a cosign-bundle + provenance evidence pair.",
      },
    ];

    const evidence: ScanEvidenceArtifact[] = [];
    const summary: SecurityScanSummary = summarize(findings);

    input.onProgress?.({ pct: 100, message: "Scaffold run complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary,
    };
  }

  async cancel(runId: string): Promise<void> {
    const child = this.active.get(runId);
    if (!child) return;
    try {
      child.kill("SIGTERM");
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }, 5000);
    } finally {
      this.active.delete(runId);
    }
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: ["backend", "frontend", "cli", "sdk", "mcp", "container", "iac"],
      toolVersion: this.toolVersion,
      description:
        "Cosign signing + SLSA provenance for package.publish (Wave 2 scaffold; real integration pending).",
    };
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}
