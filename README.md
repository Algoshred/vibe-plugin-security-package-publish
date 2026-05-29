## @vibecontrols/vibe-plugin-security-package-publish

Cosign signing + SLSA provenance provider for the `package.publish` lifecycle stage in [VibeControls](https://vibecontrols.com). Provider name: `cosign-slsa`. Wraps the pinned `cosign` binary and emits a SLSA v1 in-toto provenance statement next to a cosign signature/certificate bundle.

Registers itself with [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) under the per-stage provider type `security.sbom` (per `PROVIDER_TYPE_FOR_STAGE("package.publish")`). When the user picks "cosign-slsa" as their default provider for `package.publish`, the security meta plugin dispatches scan runs here.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-package-publish
vibe security providers set-default --stage package.publish --provider cosign-slsa
```

On first run the plugin auto-installs the pinned Cosign binary (sha256-verified per platform — linux-x64, linux-arm64, darwin-x64, darwin-arm64) into `~/.boff/vibecontrols/agents/<profile>/tools/cosign/`. If `cosign` is already on `PATH` and reports the expected version, that binary is used as-is.

## Behavior

- Validates `input.config.artifactPath`; concludes `skipped` (one info finding `signing.cosign.skipped`) if missing or unreadable.
- Computes the sha256 of the artifact (used both for signing and the provenance subject digest).
- **Cosign signing:**
  - Key-based when `cosignKey` is provided (`COSIGN_PASSWORD` is taken from `cosignKeyPassword`).
  - Keyless via Fulcio OIDC otherwise — requires `SIGSTORE_OIDC_TOKEN`, `GITHUB_ACTIONS`, or `ACTIONS_ID_TOKEN_REQUEST_URL` in the environment. If absent, the cosign step is skipped with reason `keyless-oidc-unavailable` (provenance still runs).
  - On success, emits a `cosign-bundle` evidence artifact bundling the signature, certificate, artifact digest, and metadata.
- **SLSA provenance:**
  - Always runs (even when cosign is skipped) since the build identity + digest is independent of signing.
  - Writes a `provenance.intoto.jsonl` (in-toto Statement v1, default `predicateType = https://slsa.dev/provenance/v1`).
  - Subject: `{ name: <basename>, digest: { sha256: <computed> } }`.
  - Predicate: `buildDefinition.buildType = https://vibecontrols.com/build/v1`, builder id `https://vibecontrols.com/builder/vibe-plugin-security-package-publish`, run metadata (invocationId, startedOn, finishedOn).
  - Emits `provenance` evidence artifact.

## Configuration

Per-vibe config (stored in `RepositorySecurityConfig.pluginAssignments["package.publish"].config`):

```yaml
provider: cosign-slsa
config:
  artifactPath: ./dist/app-v1.2.3.tar.gz # required
  cosignKey: /path/to/cosign.key # optional; omit for keyless
  cosignKeyPassword: "<password>" # optional; sets COSIGN_PASSWORD
  fulcioUrl: https://fulcio.sigstore.dev # optional override
  rekorUrl: https://rekor.sigstore.dev # optional override
  slsaPredicateType: https://slsa.dev/provenance/v1 # optional
  extraCosignArgs: [] # extra flags appended before the artifact arg
```

<!-- VIBECONTROLS_OSS_FOOTER_START -->

---

## About VibeControls

**VibeControls** is the agentic engineering mission control for AI-native teams. Vibe-plugins extend the VibeControls agent with new providers, tools, sessions, tunnels, storage backends, and security stages.

- Website: <https://vibecontrols.com>
- Documentation: <https://docs.vibecontrols.com>
- Plugin SDK: <https://github.com/algoshred/vibecontrols-plugin-sdk>
- All plugins: <https://github.com/algoshred?q=vibe-plugin-&type=all>

## Credits

This plugin builds on the following upstream open-source projects. All trademarks and copyrights remain with their respective owners.

- **Sigstore Cosign** — <https://github.com/sigstore/cosign>
- **SLSA** — <https://slsa.dev/>

## License

Released under the [MIT License](./LICENSE).

Copyright (c) 2026 Burdenoff Consultancy Services Private Limited, Algoshred Technologies Private Limited, and all its sister companies.

Maintainer: **Vignesh T.V** — <https://github.com/tvvignesh>

**Note**: this plugin is open source under MIT. The `@vibecontrols/agent` runtime that loads and orchestrates plugins is **closed source** and proprietary to Burdenoff Consultancy Services Pvt. Ltd. If you want a fully self-hostable agent, please open an issue or contact the maintainer.

<!-- VIBECONTROLS_OSS_FOOTER_END -->
