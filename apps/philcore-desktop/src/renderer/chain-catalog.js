(function exposePhilCoreChainCatalog(root) {
  const definitions = [
    ["ethereum", "Ethereum", "ETH", "View the completed Controlled Sepolia Beta and run a separate local authorization demonstration.", "Sepolia Beta", "controlled_beta_read_only", "deployed-testnet", ["controlled_beta_status", "local_protected_action_demonstration"], ["new_public_execution", "transfers", "tokens"], ["Controlled Sepolia Beta", "Local protected-action demonstration"], ["smart contracts", "apps", "local demo", "sepolia beta"]],
    ["bitcoin", "Bitcoin", "BTC", "Bitcoin support is planned but is not active in this Beta.", "Preview", "not_implemented", "unavailable", [], ["accounts", "payments", "transfers"], [], ["payments"]],
    ["solana", "Solana", "SOL", "Solana support is planned but is not active in this Beta.", "Preview", "not_implemented", "unavailable", [], ["accounts", "applications", "transfers"], [], ["apps"]],
    ["base", "Base", "BASE", "Base is part of PhilCore's future execution direction, but public access is off.", "Preview", "preparation_boundaries_only", "prepared", [], ["public_execution", "account_deployment", "transfers"], [], ["ethereum layer 2", "l2"]],
    ["polygon", "Polygon", "POL", "Polygon support is planned but is not active in this Beta.", "Preview", "not_implemented", "unavailable", [], ["accounts", "applications", "transfers"], [], ["matic", "ethereum layer 2"]],
    ["cardano", "Cardano", "ADA", "Cardano support is planned but is not active in this Beta.", "Preview", "not_implemented", "unavailable", [], ["accounts", "applications", "transfers"], [], ["staking"]],
    ["arbitrum", "Arbitrum", "ARB", "Arbitrum support is planned but is not active in this Beta.", "Preview", "not_implemented", "unavailable", [], ["accounts", "applications", "transfers"], [], ["ethereum layer 2", "l2"]],
    ["optimism", "Optimism", "OP", "Optimism support is planned but is not active in this Beta.", "Preview", "not_implemented", "unavailable", [], ["accounts", "applications", "transfers"], [], ["ethereum layer 2", "l2"]]
  ];
  const chains = definitions.map(([id, name, symbol, description, status, adapterStatus, accountStatus, supportedActions, disabledActions, applications, extraKeywords]) => Object.freeze({
    id,
    name,
    symbol,
    iconText: symbol,
    description,
    status,
    favorite: true,
    adapterStatus,
    publicNetworkEnabled: false,
    accountStatus,
    supportedActions: Object.freeze(supportedActions),
    disabledActions: Object.freeze(disabledActions),
    applications: Object.freeze(applications),
    keywords: Object.freeze([id, name, symbol, ...extraKeywords])
  }));
  function getById(id) {
    return chains.find((chain) => chain.id === id);
  }
  function search(query) {
    const normalized = String(query || "").trim().toLowerCase();
    if (!normalized) return chains;
    return chains.filter((chain) => [
      chain.name,
      chain.symbol,
      chain.description,
      ...chain.keywords,
      ...chain.applications
    ].some((value) => String(value).toLowerCase().includes(normalized)));
  }
  const catalog = Object.freeze({
    chains: Object.freeze(chains),
    favorites: Object.freeze(chains.filter((chain) => chain.favorite)),
    getById,
    search,
    accountStatuses: Object.freeze(["none", "local-test", "prepared", "deployed-testnet", "deployed-mainnet", "unavailable"]),
    source: "bundled_controlled_beta_catalog",
    remoteSearchEnabled: false
  });
  root.PhilCoreChainCatalog = catalog;
  if (typeof module !== "undefined" && module.exports) module.exports = catalog;
}(globalThis));
