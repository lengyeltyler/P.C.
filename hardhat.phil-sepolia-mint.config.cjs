require("@nomicfoundation/hardhat-ethers");

const { createConfig } = require("./hardhat.shared.cjs");

module.exports = createConfig({
  hardhatChainId: 11155111,
  localhostUrl: "http://127.0.0.1:8545",
  includeEnvNetworks: false
});
