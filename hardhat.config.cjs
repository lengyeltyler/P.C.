require("dotenv").config();
require("@nomicfoundation/hardhat-ethers");

const { createConfig } = require("./hardhat.shared.cjs");

// Base-first config used by compile, tests, and the default local node.
module.exports = createConfig({
  hardhatChainId: 31337,
  localhostUrl: "http://127.0.0.1:8545",
  includeEnvNetworks: true
});
