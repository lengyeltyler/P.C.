require("@nomicfoundation/hardhat-ethers");

const {
  FROZEN_O37_7_SOLC_VERSION,
  createO377SoliditySettings
} = require("./hardhat.shared.cjs");

module.exports = {
  solidity: {
    version: FROZEN_O37_7_SOLC_VERSION,
    settings: createO377SoliditySettings()
  },
  paths: {
    sources: "./contracts/base/erc4337/v2",
    tests: "./test",
    artifacts: "./artifacts/o37-7",
    cache: "./cache/o37-7"
  },
  networks: {
    hardhat: {
      chainId: 31337,
      gas: 30000000,
      blockGasLimit: 0x1fffffffffffff
    }
  },
  mocha: {
    timeout: 120000
  }
};
