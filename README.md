## @vibecontrols/vibe-plugin-security-package-publish

Cosign signing + SLSA provenance provider for the `package.publish` lifecycle stage in [VibeControls](https://vibecontrols.com). Provider name: `cosign-slsa`. Wraps the pinned `cosign` binary and the SLSA generator workflow. **Wave 2 scaffold — real tool integration pending; see `src/provider.ts` TODO.**

Registers itself with [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) under the per-stage provider type `security.sbom` (per `PROVIDER_TYPE_FOR_STAGE("package.publish")`). When the user picks "cosign-slsa" as their default provider for `package.publish`, the security meta plugin dispatches scan runs here.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-package-publish
vibe security providers set-default --stage package.publish --provider cosign-slsa
```

On first real run the plugin downloads the Cosign binary (sha256-verified per platform) into `~/.boff/vibecontrols/agents/<profile>/tools/cosign/`. SLSA provenance generation is invoked via the slsa-github-generator workflow output.

## Behavior (planned)

- Signs the published artifact:
  - Keyless via Fulcio OIDC when `GITHUB_ACTIONS` or `SIGSTORE_OIDC` is present.
  - Key-based when `input.config.cosignKey` (+ optional `cosignPassword`) is provided.
- Emits a SLSA v1.0 provenance document (`intoto+json`) describing the builder, build invocation, materials, and the signed digest.
- Evidence pair: `cosign-bundle` + `provenance` (`SecurityEvidenceType`).

## Configuration

Per-vibe config (stored in `RepositorySecurityConfig.pluginAssignments["package.publish"].config`):

```yaml
provider: cosign-slsa
config:
  artifactPath: ./dist/<artifact>
  artifactDigest: "sha256:<hex>"
  cosignKey: /path/to/cosign.key # optional; omit for keyless
  cosignPassword: "<password>" # optional
  fulcioUrl: https://fulcio.sigstore.dev
  rekorUrl: https://rekor.sigstore.dev
  extraCosignArgs: []
  extraSlsaArgs: []
```

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
