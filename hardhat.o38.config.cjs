require("@nomicfoundation/hardhat-ethers");

const { createConfig } = require("./hardhat.shared.cjs");

// O.38 is intentionally local-only: do not load dotenv or expose environment
// networks while exercising the deployment-readiness gate.
module.exports = createConfig({
  hardhatChainId: 31337,
  localhostUrl: "http://127.0.0.1:8545",
  includeEnvNetworks: false
});
