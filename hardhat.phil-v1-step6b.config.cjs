require("@nomicfoundation/hardhat-ethers");

const { createConfig } = require("./hardhat.shared.cjs");

// Local-only Base-mainnet-shaped chain for the Step 6B enforcement gate.
module.exports = createConfig({
  hardhatChainId: 8453,
  localhostUrl: "http://127.0.0.1:8545",
  includeEnvNetworks: false
});
