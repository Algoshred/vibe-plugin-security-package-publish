/**
 * CosignSlsaProvider — implements SecurityProvider for stage `package.publish`.
 *
 * Real implementation:
 *  - Signs the published artifact with Cosign:
 *      * key-based when `input.config.cosignKey` (+ optional `cosignKeyPassword`) is set, OR
 *      * keyless via Fulcio OIDC otherwise. If keyless signing fails because no
 *        OIDC identity token can be acquired (typical on dev boxes outside CI),
 *        the cosign step is skipped with reason `keyless-oidc-unavailable` and
 *        the run still emits provenance.
 *  - Generates a SLSA v1.0 (default) provenance document (`intoto+json`)
 *    describing the builder, build invocation, the artifact's sha256 digest,
 *    and run metadata. Written to `<workdir>/provenance.intoto.jsonl`.
 *  - Emits a `cosign-bundle` evidence artifact (a JSON manifest packaging the
 *    .sig + .cert next to a small index) when signing succeeds, plus a
 *    `provenance` evidence artifact for the intoto statement.
 *
 * If `input.config.artifactPath` is missing, the provider concludes `skipped`
 * (status `succeeded` with one info finding `signing.cosign.skipped` + reason
 * `artifact-path-missing`) — the manager's deriveConclusion turns "no critical
 * /high" into `pass` for advisory policy or `skipped` for stricter levels.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as os from "node:os";
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
  cosignKey?: string;
  cosignKeyPassword?: string;
  fulcioUrl?: string;
  rekorUrl?: string;
  slsaPredicateType?: string;
  extraCosignArgs?: string[];
  /** Override the cosign binary path (testing). */
  cosignBinaryOverride?: string;
}

const DEFAULT_SLSA_PREDICATE = "https://slsa.dev/provenance/v1";

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
      this.host?.getDataDir?.() ?? path.join(os.homedir(), ".boff/vibecontrols");
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

    // ── 1. Validate inputs ──────────────────────────────────────────────
    if (!cfg.artifactPath) {
      return this.skipResult(
        input,
        startedAt,
        "artifact-path-missing",
        "signing.cosign.skipped",
        "package.publish: cosign+SLSA skipped — no input.config.artifactPath provided.",
      );
    }

    let artifactStat;
    try {
      artifactStat = await fs.stat(cfg.artifactPath);
      if (!artifactStat.isFile()) {
        return this.skipResult(
          input,
          startedAt,
          "artifact-not-a-file",
          "signing.cosign.skipped",
          `package.publish: cosign+SLSA skipped — artifactPath ${cfg.artifactPath} is not a regular file.`,
        );
      }
    } catch {
      return this.skipResult(
        input,
        startedAt,
        "artifact-path-unreachable",
        "signing.cosign.skipped",
        `package.publish: cosign+SLSA skipped — artifactPath ${cfg.artifactPath} could not be read.`,
      );
    }

    input.onProgress?.({ pct: 10, message: "Computing artifact digest" });

    // Compute artifact sha256 once — used by both cosign signing
    // and provenance subject.
    const artifactBuf = await fs.readFile(cfg.artifactPath);
    const artifactDigest = createHash("sha256").update(artifactBuf).digest("hex");
    const artifactBase = path.basename(cfg.artifactPath);

    const findings: NormalizedFinding[] = [];
    const evidence: ScanEvidenceArtifact[] = [];

    // ── 2. Cosign signing (optional, may skip cleanly) ──────────────────
    input.onProgress?.({ pct: 30, message: "Signing artifact with cosign" });

    let cosignSigned = false;
    let cosignSkipReason: string | undefined;

    if (!this.cosignPath && !cfg.cosignBinaryOverride) {
      try {
        await this.ensureToolInstalled();
      } catch (err) {
        cosignSkipReason = `cosign-install-failed:${String(err).slice(0, 100)}`;
      }
    }

    const cosignBinary = cfg.cosignBinaryOverride ?? this.cosignPath;

    if (cosignBinary && !cosignSkipReason) {
      const sigPath = path.join(input.workdir, `${artifactBase}.sig`);
      const certPath = path.join(input.workdir, `${artifactBase}.cert`);

      const cosignArgs: string[] = [
        "sign-blob",
        "--yes",
        "--output-signature",
        sigPath,
        "--output-certificate",
        certPath,
      ];
      if (cfg.cosignKey) {
        cosignArgs.push("--key", cfg.cosignKey);
      }
      if (cfg.fulcioUrl) {
        cosignArgs.push("--fulcio-url", cfg.fulcioUrl);
      }
      if (cfg.rekorUrl) {
        cosignArgs.push("--rekor-url", cfg.rekorUrl);
      }
      if (cfg.extraCosignArgs) {
        cosignArgs.push(...cfg.extraCosignArgs);
      }
      cosignArgs.push(cfg.artifactPath);

      const env: NodeJS.ProcessEnv = { ...process.env };
      if (cfg.cosignKeyPassword !== undefined) {
        env.COSIGN_PASSWORD = cfg.cosignKeyPassword;
      }
      // For keyless mode we need a non-interactive flow; cosign respects
      // SIGSTORE_OIDC_TOKEN / GITHUB_ACTIONS env to drive that. If
      // neither is set and there's no --key, sign-blob will block on TTY
      // — we surface that as a clean skip rather than hang.
      const keyless = !cfg.cosignKey;
      const oidcAvailable =
        !!env.SIGSTORE_OIDC_TOKEN || !!env.GITHUB_ACTIONS || !!env.ACTIONS_ID_TOKEN_REQUEST_URL;
      if (keyless && !oidcAvailable) {
        cosignSkipReason = "keyless-oidc-unavailable";
      } else {
        const cosignResult = await this.spawnAndWait(
          cosignBinary,
          input.runId,
          cosignArgs,
          env,
          120_000,
        );
        if (cosignResult.code === 0) {
          cosignSigned = true;
          // Bundle .sig + .cert into a single evidence file.
          const sig = await safeRead(sigPath);
          const cert = await safeRead(certPath);
          const bundle = {
            kind: "cosign-bundle",
            cosignVersion: COSIGN_VERSION,
            artifact: {
              name: artifactBase,
              digest: { sha256: artifactDigest },
              sizeBytes: artifactStat.size,
            },
            keyless,
            signature: sig?.toString("base64"),
            certificate: cert?.toString("utf-8"),
            rekorUrl: cfg.rekorUrl,
            fulcioUrl: cfg.fulcioUrl,
            createdAt: new Date().toISOString(),
          };
          const bundlePath = path.join(input.workdir, `${artifactBase}.cosign-bundle.json`);
          const bundleRaw = JSON.stringify(bundle, null, 2);
          await fs.writeFile(bundlePath, bundleRaw, "utf-8");
          const bundleSha = createHash("sha256").update(bundleRaw).digest("hex");
          evidence.push({
            type: "cosign-bundle",
            localPath: bundlePath,
            sha256: bundleSha,
            sizeBytes: Buffer.byteLength(bundleRaw),
          });
          findings.push({
            fingerprint: createHash("sha256")
              .update(`${this.name}:signed:${artifactDigest}`)
              .digest("hex"),
            ruleId: "signing.cosign.signed",
            title: `Artifact ${artifactBase} signed with cosign (${keyless ? "keyless" : "key-based"})`,
            severity: "info",
            category: "supplychain",
            description: `Cosign sign-blob produced a signature + certificate for ${artifactBase}. Bundle path: ${path.basename(bundlePath)}.`,
            remediation: undefined,
          });
        } else {
          // Spawn ran but exited non-zero.
          cosignSkipReason = `cosign-exit-${cosignResult.code}`;
          const stderrRedacted = redactStderr(cosignResult.stderr).slice(0, 240);
          findings.push({
            fingerprint: createHash("sha256")
              .update(`${this.name}:cosign-fail:${input.runId}`)
              .digest("hex"),
            ruleId: "signing.cosign.skipped",
            title: `Artifact ${artifactBase} not signed — cosign returned ${cosignResult.code}`,
            severity: "info",
            category: "supplychain",
            description: `Cosign sign-blob failed: ${stderrRedacted}. Skip reason: ${cosignSkipReason}.`,
            remediation:
              "Provide input.config.cosignKey (+ cosignKeyPassword) for key-based signing, or run inside an OIDC-capable environment (e.g. GitHub Actions) for keyless Fulcio signing.",
          });
        }
      }
    }

    if (!cosignSigned && cosignSkipReason) {
      // Emit a clear skip finding when we never even spawned cosign.
      if (!findings.find((f) => f.ruleId === "signing.cosign.skipped")) {
        findings.push({
          fingerprint: createHash("sha256")
            .update(`${this.name}:cosign-skip:${input.runId}`)
            .digest("hex"),
          ruleId: "signing.cosign.skipped",
          title: `Artifact ${artifactBase} not signed (cosign skipped)`,
          severity: "info",
          category: "supplychain",
          description: `Cosign step skipped — reason: ${cosignSkipReason}. Provenance generation continues independently.`,
          remediation:
            "Set input.config.cosignKey for key-based signing or run in an OIDC-capable environment for keyless signing.",
        });
      }
    }

    // ── 3. SLSA provenance (always runs) ────────────────────────────────
    input.onProgress?.({ pct: 75, message: "Generating SLSA provenance" });

    const predicateType = cfg.slsaPredicateType ?? DEFAULT_SLSA_PREDICATE;
    const now = new Date().toISOString();
    const statement = {
      _type: "https://in-toto.io/Statement/v1",
      predicateType,
      subject: [
        {
          name: artifactBase,
          digest: { sha256: artifactDigest },
        },
      ],
      predicate: {
        buildDefinition: {
          buildType: "https://vibecontrols.com/build/v1",
          externalParameters: {
            vibeId: input.vibeId,
            stage: "package.publish",
            policyLevel: input.policyLevel,
          },
          internalParameters: {
            commit: input.commit,
          },
          resolvedDependencies: [],
        },
        runDetails: {
          builder: {
            id: "https://vibecontrols.com/builder/vibe-plugin-security-package-publish",
            version: { "cosign-slsa": SLSA_GENERATOR_VERSION },
          },
          metadata: {
            invocationId: input.runId,
            startedOn: new Date(startedAt).toISOString(),
            finishedOn: now,
          },
        },
      },
    };

    const provenancePath = path.join(input.workdir, "provenance.intoto.jsonl");
    const provenanceRaw = JSON.stringify(statement);
    await fs.writeFile(provenancePath, provenanceRaw + "\n", "utf-8");
    const provenanceSha = createHash("sha256").update(provenanceRaw).digest("hex");

    evidence.push({
      type: "provenance",
      localPath: provenancePath,
      sha256: provenanceSha,
      sizeBytes: Buffer.byteLength(provenanceRaw + "\n"),
    });

    findings.push({
      fingerprint: createHash("sha256")
        .update(`${this.name}:provenance:${artifactDigest}`)
        .digest("hex"),
      ruleId: "provenance.slsa.generated",
      title: `SLSA provenance generated for ${artifactBase}`,
      severity: "info",
      category: "supplychain",
      description: `SLSA v1 in-toto statement written to ${path.basename(provenancePath)}. predicateType=${predicateType}, subjectDigest=sha256:${artifactDigest}.`,
      remediation: undefined,
    });

    input.onProgress?.({ pct: 100, message: "Scan complete" });

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary: summarize(findings),
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
        "Cosign sign-blob (key or keyless Fulcio OIDC) + SLSA v1 in-toto provenance for the package.publish stage.",
    };
  }

  private spawnAndWait(
    bin: string,
    runId: string,
    args: string[],
    env: NodeJS.ProcessEnv,
    timeoutMs: number,
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const child = spawn(bin, args, {
        stdio: ["ignore", "pipe", "pipe"],
        env,
      });
      this.active.set(runId, child);
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }, timeoutMs);
      child.stdout?.on("data", (b: Buffer) => (stdout += b.toString()));
      child.stderr?.on("data", (b: Buffer) => (stderr += b.toString()));
      child.on("close", (code) => {
        clearTimeout(timer);
        this.active.delete(runId);
        resolve({ code, stdout, stderr });
      });
      child.on("error", (err) => {
        clearTimeout(timer);
        this.active.delete(runId);
        resolve({ code: -1, stdout, stderr: err.message });
      });
    });
  }

  private skipResult(
    input: SecurityScanInput,
    startedAt: number,
    reason: string,
    ruleId: string,
    title: string,
  ): SecurityScanResult {
    const findings: NormalizedFinding[] = [
      {
        fingerprint: createHash("sha256")
          .update(`${this.name}:${reason}:${input.runId}`)
          .digest("hex"),
        ruleId,
        title,
        severity: "info",
        category: "supplychain",
        description: `package.publish skipped — reason: ${reason}. No signing or provenance was produced.`,
        remediation:
          "Wire an artifactPath in the plugin's per-vibe config so cosign + SLSA provenance can run against it.",
      },
    ];
    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence: [],
      durationMs: Date.now() - startedAt,
      summary: summarize(findings),
    };
  }
}

function summarize(findings: NormalizedFinding[]): SecurityScanSummary {
  const s: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}

async function safeRead(p: string): Promise<Buffer | undefined> {
  try {
    return await fs.readFile(p);
  } catch {
    return undefined;
  }
}

/**
 * Defensive scrub of cosign stderr before it lands in a finding description.
 * Cosign output is generally safe but we strip anything that looks like a
 * key block, OIDC token, or base64 blob > 40 chars to avoid surfacing
 * sensitive material in a finding.
 */
function redactStderr(s: string): string {
  return s
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[REDACTED-PEM-BLOCK]")
    .replace(/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, "[REDACTED-JWT]")
    .replace(/[A-Za-z0-9+/]{60,}={0,2}/g, "[REDACTED-BASE64]");
}
