const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const CANONICAL_BASE_CROSS_DOMAIN_MESSENGER = "0x4200000000000000000000000000000000000007";
const DEFAULT_ADAPTER_MIN_GAS_LIMIT = 200_000;

const BASE_MESSENGER_NETWORK_CONFIG = Object.freeze({
  base: Object.freeze({
    chainId: 8453,
    canonicalBaseMessengerAddress: CANONICAL_BASE_CROSS_DOMAIN_MESSENGER,
    adapterMinGasLimit: DEFAULT_ADAPTER_MIN_GAS_LIMIT
  }),
  baseSepolia: Object.freeze({
    chainId: 84532,
    canonicalBaseMessengerAddress: CANONICAL_BASE_CROSS_DOMAIN_MESSENGER,
    adapterMinGasLimit: DEFAULT_ADAPTER_MIN_GAS_LIMIT
  }),
  hardhat: Object.freeze({
    chainId: 31337,
    canonicalBaseMessengerAddress: ZERO_ADDRESS,
    adapterMinGasLimit: DEFAULT_ADAPTER_MIN_GAS_LIMIT
  }),
  localhost: Object.freeze({
    chainId: 31337,
    canonicalBaseMessengerAddress: ZERO_ADDRESS,
    adapterMinGasLimit: DEFAULT_ADAPTER_MIN_GAS_LIMIT
  })
});

function normalizeAddress(value) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) {
    throw new Error(`Invalid configured messenger address: ${text || "<empty>"}`);
  }
  return text;
}

function resolveBaseMessengerConfig(networkName, overrides = {}) {
  const baseConfig = BASE_MESSENGER_NETWORK_CONFIG[networkName];
  if (!baseConfig) {
    throw new Error(`Unsupported Base messenger network config: ${networkName}`);
  }

  const canonicalBaseMessengerAddress = normalizeAddress(
    overrides.canonicalBaseMessengerAddress ?? baseConfig.canonicalBaseMessengerAddress
  );
  const adapterMinGasLimit = Number(overrides.adapterMinGasLimit ?? baseConfig.adapterMinGasLimit);

  if (!Number.isInteger(adapterMinGasLimit) || adapterMinGasLimit < 0) {
    throw new Error(`Invalid adapter minGasLimit: ${adapterMinGasLimit}`);
  }

  return {
    networkName,
    chainId: baseConfig.chainId,
    canonicalBaseMessengerAddress,
    adapterMinGasLimit
  };
}

function adapterConstructorArgs(networkName, overrides = {}) {
  const config = resolveBaseMessengerConfig(networkName, overrides);
  return [config.canonicalBaseMessengerAddress, config.adapterMinGasLimit];
}

function mirrorConstructorArgs(networkName, authorizedL1Messenger, overrides = {}) {
  const config = resolveBaseMessengerConfig(networkName, overrides);
  return [config.canonicalBaseMessengerAddress, authorizedL1Messenger];
}

module.exports = {
  BASE_MESSENGER_NETWORK_CONFIG,
  CANONICAL_BASE_CROSS_DOMAIN_MESSENGER,
  DEFAULT_ADAPTER_MIN_GAS_LIMIT,
  resolveBaseMessengerConfig,
  adapterConstructorArgs,
  mirrorConstructorArgs
};
