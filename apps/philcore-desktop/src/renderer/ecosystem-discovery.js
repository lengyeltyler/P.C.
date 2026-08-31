(function exposeEcosystemDiscovery(root) {
  const items = Object.freeze([
    Object.freeze({
      id: "collectible-gallery",
      name: "Collectible Gallery",
      chainId: "ethereum",
      chainName: "Ethereum",
      iconText: "CG",
      status: "Demo",
      description: "A generic local collectible-gallery example for ecosystem discovery."
    }),
    Object.freeze({
      id: "identity-community",
      name: "Identity Community",
      chainId: "ethereum",
      chainName: "Ethereum",
      iconText: "IC",
      status: "Preview",
      description: "A generic local preview of identity-aware ecosystem discovery."
    })
  ]);

  root.PhilCoreEcosystemDiscovery = Object.freeze({
    source: "bundled-alpha-examples",
    liveTrending: false,
    remoteAccessEnabled: false,
    items,
    getById: (id) => items.find((item) => item.id === id)
  });
  if (typeof module !== "undefined" && module.exports) module.exports = root.PhilCoreEcosystemDiscovery;
}(globalThis));
