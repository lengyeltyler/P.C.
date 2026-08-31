const {
  createFixtureEthereumL1MessageAvailabilityReader,
  createFixtureL1FactAnchorDeploymentReader,
  createFixtureL1FeeDataReader,
  createFixtureL1GasEstimator,
  createFixtureL1NonceReader,
  createL1FactAnchorFixtureConfiguration,
  createStarknetL2ToL1MessageIdentity,
  deriveCanonicalStarknetL2ToL1MessageHash,
  prepareL1FactAnchorTransaction,
  requestL1MessageAvailability
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const SOURCE_L2_VERIFIER = "0x5048494c";
const ANCHOR_ADDRESS = "0x1111111111111111111111111111111111111111";
const MESSAGING_CORE_ADDRESS = "0x2222222222222222222222222222222222222222";
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";

function hasArg(name) {
  return process.argv.includes(name);
}

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function fixtureReceiptArtifact() {
  const messageHash = deriveCanonicalStarknetL2ToL1MessageHash({
    fromAddress: SOURCE_L2_VERIFIER,
    toAddress: ANCHOR_ADDRESS,
    payload: [FACT_HIGH, FACT_LOW]
  });
  return {
    receiptArtifactId: "diagnostic-l1-anchor-receipt",
    submissionId: "diagnostic-starknet-submission",
    transactionHash: "0xabc123",
    networkProfileId: "local_devnet",
    chainId: "SN_LOCAL",
    publicationContract: SOURCE_L2_VERIFIER,
    senderAccount: "0x12345",
    proofInputHash: PROOF_INPUT_HASH,
    factHigh: FACT_HIGH,
    factLow: FACT_LOW,
    l1Recipient: ANCHOR_ADDRESS,
    transactionStatus: "transaction_accepted_on_l2",
    blockNumber: 1,
    blockHash: "0xbeef",
    l2ToL1Message: {
      senderContract: SOURCE_L2_VERIFIER,
      l1Recipient: ANCHOR_ADDRESS,
      payloadLength: 2,
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      transactionHash: "0xabc123",
      blockNumber: 1,
      blockHash: "0xbeef",
      messageHash
    },
    observedAt: now(),
    auditCorrelationId: "diagnostic-l1-anchor",
    limitations: [],
    transactionAcceptedOnL2: true,
    verificationEventObserved: true,
    l2ToL1MessageObserved: true,
    l1MessageAvailabilityConfirmed: false,
    l1MessageConsumed: false,
    l1FactAnchored: false,
    baseFactMirrored: false,
    nullifierConsumed: false
  };
}

async function main() {
  const receiptArtifact = fixtureReceiptArtifact();
  const identity = createStarknetL2ToL1MessageIdentity({
    receiptArtifact,
    evidenceClass: "fixture_receipt",
    expectedL2Sender: SOURCE_L2_VERIFIER,
    expectedL1Recipient: ANCHOR_ADDRESS,
    expectedProofInputHash: PROOF_INPUT_HASH
  });
  const config = createL1FactAnchorFixtureConfiguration({
    anchorAddress: ANCHOR_ADDRESS,
    messagingCoreAddress: MESSAGING_CORE_ADDRESS,
    sourceL2Verifier: SOURCE_L2_VERIFIER
  });
  const availabilityReader = createFixtureEthereumL1MessageAvailabilityReader({
    available: !hasArg("--message-unavailable")
  });
  const availability = await requestL1MessageAvailability({
    requestId: "diagnostic-l1-message-availability",
    messageIdentity: identity,
    ethereumNetworkProfileId: "hardhat",
    ethereumChainId: 31337,
    messagingCoreAddress: MESSAGING_CORE_ADDRESS,
    anchorAddress: ANCHOR_ADDRESS,
    issueTime: now(),
    expiresAt: futureDate(),
    freshnessMs: 60_000
  }, availabilityReader);
  const preparation = await prepareL1FactAnchorTransaction({
    requestId: "diagnostic-l1-anchor-preparation",
    messageIdentity: identity,
    availabilityReader,
    deploymentReader: createFixtureL1FactAnchorDeploymentReader({
      anchorAddress: ANCHOR_ADDRESS,
      messagingCoreAddress: MESSAGING_CORE_ADDRESS,
      sourceL2Verifier: SOURCE_L2_VERIFIER
    }),
    configuration: config,
    value: "0",
    gasEstimator: createFixtureL1GasEstimator("300000"),
    nonceReader: createFixtureL1NonceReader("7"),
    feeDataReader: createFixtureL1FeeDataReader(),
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-l1-anchor"
  });
  const summary = {
    phase: "M.6B",
    evidenceClass: identity.source.evidenceClass,
    liveMessageEvidence: identity.liveMessageEvidence,
    productionSignable: preparation.status === "approved" ? preparation.value.productionSignable : false,
    starknetTransactionHash: identity.source.starknetTransactionHash,
    l2Sender: identity.binding.l2Sender,
    l1Recipient: identity.binding.l1Recipient,
    proofInputHash: identity.binding.proofInputHash,
    factHigh: identity.binding.payload.factHigh,
    factLow: identity.binding.payload.factLow,
    messageHash: identity.binding.messageHash.value,
    availabilityStatus: availability.status === "approved" ? availability.value.status : availability.error.details?.outcome,
    ethereumNetwork: "hardhat",
    anchorAddress: ANCHOR_ADDRESS,
    methodSelector: preparation.status === "approved" ? preparation.value.methodSelector : null,
    calldataHash: preparation.status === "approved" ? preparation.value.calldataHash : null,
    gasStatus: preparation.status === "approved" ? preparation.value.gas.status : "unavailable",
    nonceStatus: preparation.status === "approved" ? preparation.value.nonce.status : "unavailable",
    feeStatus: preparation.status === "approved" ? preparation.value.fee.status : "unavailable",
    transactionPrepared: preparation.status === "approved",
    transactionSigned: false,
    transactionSubmitted: false,
    l2ToL1MessageConsumed: false,
    l1FactAnchored: false,
    l1ToBaseRelayPrepared: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    chainStateMutated: false
  };
  if (hasArg("--json")) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log("Ethereum L1 fact-anchor preparation diagnostic");
  for (const [key, value] of Object.entries(summary)) {
    console.log(`${key}: ${value}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
