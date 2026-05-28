/**
 * @vibecontrols/vibe-plugin-security-package-publish
 *
 * Cosign signing + SLSA provenance provider for the `package.publish`
 * lifecycle stage. Registers as a `security.sbom` provider (per
 * PROVIDER_TYPE_FOR_STAGE) with @vibecontrols/vibe-plugin-security on
 * the host's ServiceRegistry.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { CosignSlsaProvider } from "./provider.js";

const PLUGIN_NAME = "security-package-publish";
const PLUGIN_VERSION = "2026.528.4";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new CosignSlsaProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.package-publish.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      const registry = new ProviderRegistry(host);
      registry.registerProvider("security.sbom", "cosign-slsa", provider);
      telemetry.emit("security.package-publish.registered", {
        provider: "cosign-slsa",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description:
      "Cosign sign-blob (key-based or keyless via Fulcio OIDC) + SLSA v1 provenance for the package.publish lifecycle stage.",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      subprocess: true,
      audit: true,
      telemetry: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { CosignSlsaProvider } from "./provider.js";
