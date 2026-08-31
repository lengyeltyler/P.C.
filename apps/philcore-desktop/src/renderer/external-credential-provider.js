(function exposeExternalCredentialProvider(root) {
  const worldId = Object.freeze({
    providerId: "world-id",
    displayName: "World ID",
    status: "preview",
    capabilities: Object.freeze([
      "proof-of-personhood",
      "optional-identity-creation-credential",
      "optional-trust-signal"
    ]),
    identityRootAuthority: false,
    remoteSdkLoaded: false,
    networkRequestsEnabled: false,
    biometricDataRequestedByPhilCore: false,
    biometricDataStoredByPhilCore: false
  });

  root.PhilCoreExternalCredentialProviders = Object.freeze({
    getById: (providerId) => providerId === worldId.providerId ? worldId : undefined,
    providers: Object.freeze([worldId]),
    identityRootProvider: "philcore"
  });
  if (typeof module !== "undefined" && module.exports) module.exports = root.PhilCoreExternalCredentialProviders;
}(globalThis));
