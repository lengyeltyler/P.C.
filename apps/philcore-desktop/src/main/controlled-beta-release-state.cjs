"use strict";

// Frozen, public, read-only release facts for the completed Controlled Sepolia
// Beta. The renderer receives this through the existing Runtime snapshot. It
// never reads ceremony files, RPC configuration, or private evidence roots.
const CONTROLLED_BETA_RELEASE_STATE = {
  format: "philcore-controlled-sepolia-beta-public-state-v1",
  releaseId: "controlled-sepolia-beta-2026-08-29",
  productStage: "Controlled Sepolia Beta",
  shortStage: "Sepolia Beta",
  status: "completed",
  completed: true,
  environment: {
    network: "Ethereum Sepolia",
    chainId: "11155111",
    testOnly: true,
    mainnet: false,
    meaningfulAssetsAllowed: false,
    productionCustody: false,
    postQuantumSecure: false
  },
  recovery: {
    status: "deferred",
    availableInBeta: false,
    summary: "Recovery is intentionally unavailable in this Controlled Sepolia Beta."
  },
  account: {
    present: true,
    status: "verified",
    ownerState: "unchanged_and_reconciled",
    finalNonce: "3",
    nativeBalanceWei: "0",
    nativeBalanceEth: "0",
    entryPointDepositWei: "1297280743685756",
    entryPointDepositEth: "0.001297280743685756",
    passBalance: "2"
  },
  milestones: [
    {
      id: "P2",
      status: "completed",
      title: "First controlled Beta action",
      summary: "The first Sepolia test pass was issued and independently reconciled."
    },
    {
      id: "P3",
      status: "completed",
      title: "Full controlled authorization",
      summary: "A local privacy proof, enrolled iPhone approval, protected signing, and restricted Sepolia execution completed successfully."
    },
    {
      id: "P5",
      status: "completed",
      title: "Test-fund cleanup",
      summary: "Test funds were cleaned up with one submission, no retry, and no new funding."
    }
  ],
  reconciliation: {
    status: "successful",
    summary: "The bundler, primary Sepolia provider, and independent provider agreed on the final result."
  },
  evidence: {
    sourceCommit: "3ff6541fa5ec8798cf8a45bef9e96ccb38c897a3",
    sourceTree: "9c729274b020485040c517726df6f35afa13bf94",
    smartAccountAddress: "0xb72053013089F089502B075009c0BD807349eCC6",
    ownerAddress: "0xCCFdf0a8172A8B10529a48F77F75941A1FB7aA81",
    entryPointAddress: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
    entryPointVersion: "0.7",
    P2: {
      userOperationHash: "0x0d96fa9ff4fd9a0fe3717b217b3151fbfeda51d682bf9d071b350086e251b670",
      transactionHash: "0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934",
      blockNumber: "11573471"
    },
    P3: {
      userOperationHash: "0x7cecc29755c1420f5844047b5c9f22d0f02adcb030db2157fb95bb74979def0d",
      transactionHash: "0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0",
      blockNumber: "11579252"
    },
    P5: {
      lineage: "p5-attempt-0002",
      userOperationHash: "0xe3f05bbe887dd752f5bd51e0ee36c5048e9975c73c8dd3a5f0880fc9625917c0",
      transactionHash: "0xceb00a759a8347aa7d70299afb46f7fd18e2f0ba4b3e41ea379b15bca21f5c2d",
      submissions: 1,
      retries: 0,
      additionalFundingWei: "0"
    }
  }
};

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

deepFreeze(CONTROLLED_BETA_RELEASE_STATE);

function controlledBetaReleaseState() {
  return CONTROLLED_BETA_RELEASE_STATE;
}

module.exports = Object.freeze({
  CONTROLLED_BETA_RELEASE_STATE,
  controlledBetaReleaseState
});
