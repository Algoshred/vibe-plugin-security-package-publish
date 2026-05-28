/**
 * Cosign + SLSA generator binary manifest.
 *
 * cosign sha256 values pinned from
 *   https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign_checksums.txt
 *
 * SLSA_GENERATOR_VERSION is retained as a pinned identifier for audit
 * logs even though slsa-github-generator runs as a reusable GitHub
 * Actions workflow rather than a downloadable host binary, so there is
 * no entry in the downloads map for it.
 *
 * Updating the version is a deliberate, audited operation: bump the
 * version + sha256 here, re-run sanity, publish a new CalVer release.
 */
import type { ToolManifest } from "@vibecontrols/vibe-plugin-security/tool-installer";

export const COSIGN_VERSION = "2.4.1";
export const SLSA_GENERATOR_VERSION = "1.10.0";

export const TOOLS_MANIFEST: ToolManifest = {
  cosign: {
    version: COSIGN_VERSION,
    binaryName: "cosign",
    versionMatcher: COSIGN_VERSION.replace(/\./g, "\\."),
    downloads: {
      "linux-x64": {
        url: `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64`,
        sha256: "8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b",
        archive: "raw",
      },
      "linux-arm64": {
        url: `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-arm64`,
        sha256: "3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a",
        archive: "raw",
      },
      "darwin-x64": {
        url: `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-darwin-amd64`,
        sha256: "666032ca283da92b6f7953965688fd51200fdc891a86c19e05c98b898ea0af4e",
        archive: "raw",
      },
      "darwin-arm64": {
        url: `https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-darwin-arm64`,
        sha256: "13343856b69f70388c4fe0b986a31dde5958e444b41be22d785d3dc5e1a9cc62",
        archive: "raw",
      },
    },
  },
};
