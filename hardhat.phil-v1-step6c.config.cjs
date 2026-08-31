require("@nomicfoundation/hardhat-ethers");

const { createConfig } = require("./hardhat.shared.cjs");

// Isolated in-process chain only. No environment-provided network is admitted.
const config = createConfig({
  hardhatChainId: 31337,
  localhostUrl: "http://127.0.0.1:8545",
  includeEnvNetworks: false
});

// Fix the in-process genesis identity so deterministic evidence can retain
// actual captured block hashes across fresh verifier processes.
config.networks.hardhat.initialDate = "2027-01-15T07:00:00.000Z";

module.exports = config;
