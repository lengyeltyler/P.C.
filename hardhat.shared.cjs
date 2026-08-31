require("tsx/cjs");

const { subtask } = require("hardhat/config");
const {
  TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD
} = require("hardhat/builtin-tasks/task-names");

const TEST_MNEMONIC = "test test test test test test test test test test test junk";
const TEST_ACCOUNT_COUNT = 40;
const FROZEN_O37_7_SOLC_VERSION = "0.8.27";
const O37_7_INTERFACE_SOURCE =
  "contracts/base/erc4337/v2/IPhilCoreV2StaticAuthorityVerifier.sol";
const O37_7_VERIFIER_SOURCE =
  "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol";
const O37_10_INTERFACE_SOURCE =
  "contracts/base/erc4337/v2/IPhilCoreV2MinimalAccountV2.sol";
const O37_10_ACCOUNT_SOURCE =
  "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol";
const O37_10_FACTORY_SOURCE =
  "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol";

subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD).setAction(
  async ({ solcVersion }, _environment, runSuper) => {
    if (solcVersion !== FROZEN_O37_7_SOLC_VERSION) {
      return runSuper();
    }
    const solc = require("solc");
    const longVersion = solc.version();
    if (!longVersion.startsWith(`${FROZEN_O37_7_SOLC_VERSION}+`)) {
      throw new Error(`O37_7_SOLC_VERSION_MISMATCH:${longVersion}`);
    }
    return {
      compilerPath: require.resolve("solc/soljson.js"),
      isSolcJs: true,
      version: FROZEN_O37_7_SOLC_VERSION,
      longVersion
    };
  }
);

function createO377SoliditySettings() {
  return {
    optimizer: {
      enabled: true,
      runs: 200
    },
    viaIR: true,
    evmVersion: "cancun",
    metadata: {
      appendCBOR: true,
      bytecodeHash: "ipfs",
      useLiteralContent: true
    },
    outputSelection: {
      "*": {
        "*": [
          "abi",
          "evm.bytecode",
          "evm.deployedBytecode",
          "metadata",
          "storageLayout"
        ],
        "": ["ast"]
      }
    }
  };
}

function readEnv(name) {
  return String(process.env[name] || "").trim();
}

function normalizePrivateKey(rawValue) {
  if (!rawValue) {
    return "";
  }

  const trimmed = rawValue.trim();
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(trimmed)) {
    throw new Error("Configured deployer private key must be 32 bytes of hex");
  }

  return trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
}

function resolveDeployerPrivateKey() {
  return normalizePrivateKey(readEnv("DEPLOYER_PRIVATE_KEY") || readEnv("PRIVATE_KEY"));
}

function buildNetworks({ hardhatChainId, localhostUrl, includeEnvNetworks, hardhatAccounts }) {
  const networks = {
    hardhat: {
      chainId: hardhatChainId,
      gas: 8000000,
      blockGasLimit: 0x1fffffffffffff,
      accounts: hardhatAccounts || {
        mnemonic: TEST_MNEMONIC,
        count: TEST_ACCOUNT_COUNT
      }
    },
    localhost: {
      url: localhostUrl
    }
  };

  if (!includeEnvNetworks) {
    return networks;
  }

  const deployerPrivateKey = resolveDeployerPrivateKey();
  const baseRpcUrl = readEnv("BASE_RPC_URL");

  if (baseRpcUrl) {
    networks.base = {
      url: baseRpcUrl,
      accounts: deployerPrivateKey ? [deployerPrivateKey] : []
    };
  }

  return networks;
}

function createConfig({
  hardhatChainId = 31337,
  localhostUrl = "http://127.0.0.1:8545",
  includeEnvNetworks = true,
  hardhatAccounts
} = {}) {
  return {
    solidity: {
      compilers: [
        {
          version: FROZEN_O37_7_SOLC_VERSION,
          settings: {
            optimizer: {
              enabled: true,
              runs: 200
            },
            viaIR: true,
            evmVersion: "cancun"
          }
        },
      ],
      overrides: {
        [O37_7_INTERFACE_SOURCE]: {
          version: FROZEN_O37_7_SOLC_VERSION,
          settings: createO377SoliditySettings()
        },
        [O37_7_VERIFIER_SOURCE]: {
          version: FROZEN_O37_7_SOLC_VERSION,
          settings: createO377SoliditySettings()
        },
        [O37_10_INTERFACE_SOURCE]: {
          version: FROZEN_O37_7_SOLC_VERSION,
          settings: createO377SoliditySettings()
        },
        [O37_10_ACCOUNT_SOURCE]: {
          version: FROZEN_O37_7_SOLC_VERSION,
          settings: createO377SoliditySettings()
        },
        [O37_10_FACTORY_SOURCE]: {
          version: FROZEN_O37_7_SOLC_VERSION,
          settings: createO377SoliditySettings()
        }
      }
    },
    paths: {
      sources: "./contracts",
      tests: "./test",
      artifacts: "./artifacts",
      cache: "./cache"
    },
    networks: buildNetworks({
      hardhatChainId,
      localhostUrl,
      includeEnvNetworks,
      hardhatAccounts
    }),
    mocha: {
      timeout: 60000
    }
  };
}

module.exports = {
  TEST_MNEMONIC,
  TEST_ACCOUNT_COUNT,
  FROZEN_O37_7_SOLC_VERSION,
  createO377SoliditySettings,
  createConfig
};
