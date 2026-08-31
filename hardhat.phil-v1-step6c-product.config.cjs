require("@nomicfoundation/hardhat-ethers");

const { Wallet, parseEther } = require("ethers");
const { createConfig } = require("./hardhat.shared.cjs");

// Product-owned in-process chain only. The one framework account is generated
// afresh for each process and is never used as Phil authorization authority.
const config = createConfig({
  hardhatChainId: 31337,
  localhostUrl: "http://127.0.0.1:8545",
  includeEnvNetworks: false,
  hardhatAccounts: [{
    privateKey: Wallet.createRandom().privateKey,
    balance: parseEther("1").toString()
  }]
});
config.networks.hardhat.allowBlocksWithSameTimestamp = true;
module.exports = config;
