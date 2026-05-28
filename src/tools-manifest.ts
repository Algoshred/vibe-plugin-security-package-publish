/**
 * Cosign + SLSA generator binary manifest.
 *
 * Versions pinned per CalVer release. sha256 values below are placeholders
 * (zeros) — TODO(wave-2): pin to upstream checksums sourced from
 *   https://github.com/sigstore/cosign/releases/download/v<VER>/cosign_checksums.txt
 *   https://github.com/slsa-framework/slsa-github-generator/releases/tag/v<VER>
 * before enabling real downloads in production.
 *
 * Updating the version is a deliberate, audited operation: bump the
 * version + sha256 here, re-run sanity, publish a new CalVer release.
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const COSIGN_VERSION = "2.4.1";
export const SLSA_GENERATOR_VERSION = "1.10.0";
const PLACEHOLDER_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000";

export const TOOLS_MANIFEST: ToolManifest = {
  cosign: {
    version: COSIGN_VERSION,
    binaryName: "cosign",
    versionMatcher: COSIGN_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64`,
        sha256: PLACEHOLDER_SHA256,
        archive: "raw",
      },
      "linux-arm64": {
        url: `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-arm64`,
        sha256: PLACEHOLDER_SHA256,
        archive: "raw",
      },
      "darwin-x64": {
        url: `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-darwin-amd64`,
        sha256: PLACEHOLDER_SHA256,
        archive: "raw",
      },
      "darwin-arm64": {
        url: `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-darwin-arm64`,
        sha256: PLACEHOLDER_SHA256,
        archive: "raw",
      },
    },
  },
};
