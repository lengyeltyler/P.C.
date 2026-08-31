const {
  createFixtureL1AnchoredFactStateReader,
  createFixtureL1ToBaseRelayDeploymentReader,
  createFixtureL1ToBaseRelayFeeQuoter,
  createFixtureL1ToBaseRelayGasEstimator,
  createFixtureL1ToBaseRelayNonceReader,
  createL1AnchoredFactEvidence,
  createL1ToBaseRelayFixtureConfiguration,
  deriveCanonicalStarknetL2ToL1MessageHash,
  prepareL1ToBaseFactRelayTransaction,
  requestL1AnchoredFactVerification
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const SOURCE_L2_VERIFIER = "0x5048494c";
const ANCHOR_ADDRESS = "0x1111111111111111111111111111111111111111";
const L1_RELAY_ADDRESS = "0x3333333333333333333333333333333333333333";
const L1_MESSENGER_ADDRESS = "0x4444444444444444444444444444444444444444";
const BASE_MESSENGER_ADDRESS = "0x5555555555555555555555555555555555555555";
const BASE_MIRROR_ADDRESS = "0x6666666666666666666666666666666666666666";
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

function fixtureReceipt() {
  const messageHash = deriveCanonicalStarknetL2ToL1MessageHash({
    fromAddress: SOURCE_L2_VERIFIER,
    toAddress: ANCHOR_ADDRESS,
    payload: [FACT_HIGH, FACT_LOW]
  });
  return {
    l1FactAnchorReceiptId: "diagnostic-l1-anchor-receipt",
    transactionHash: `0x${"ab".repeat(32)}`,
    chainId: 31337,
    anchorAddress: ANCHOR_ADDRESS,
    relayerAccount: "0x7777777777777777777777777777777777777777",
    messageHash,
    proofInputHash: PROOF_INPUT_HASH,
    factHigh: FACT_HIGH,
    factLow: FACT_LOW,
    event: {
      contractAddress: ANCHOR_ADDRESS,
      sourceL2Verifier: SOURCE_L2_VERIFIER,
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      transactionHash: `0x${"ab".repeat(32)}`,
      blockNumber: 1,
      blockHash: `0x${"12".repeat(32)}`
    },
    blockNumber: 1,
    blockHash: `0x${"12".repeat(32)}`,
    gasUsed: "100000",
    confirmations: 1,
    observedAt: now(),
    transactionConfirmed: true,
    l2ToL1MessageConsumed: true,
    l1FactAnchored: true,
    l1ToBaseRelayPrepared: false,
    l1ToBaseRelaySubmitted: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    consumerExecuted: false
  };
}

async function main() {
  const evidence = createL1AnchoredFactEvidence({
    receipt: fixtureReceipt(),
    source: "fixture_receipt",
    expectedAnchorContract: ANCHOR_ADDRESS,
    expectedFactHigh: FACT_HIGH,
    expectedFactLow: FACT_LOW,
    expectedProofInputHash: PROOF_INPUT_HASH,
    expectedStarknetSender: SOURCE_L2_VERIFIER,
    expectedEthereumChainId: 31337
  });
  const stateReader = createFixtureL1AnchoredFactStateReader(
    hasArg("--fact-not-anchored") ? "fact_not_anchored" : "fact_anchored"
  );
  const config = createL1ToBaseRelayFixtureConfiguration({
    l1AnchorAddress: ANCHOR_ADDRESS,
    l1RelayAddress: L1_RELAY_ADDRESS,
    l1MessengerAddress: L1_MESSENGER_ADDRESS,
    baseMessengerAddress: BASE_MESSENGER_ADDRESS,
    baseMirrorAddress: BASE_MIRROR_ADDRESS,
    authorizedL1RemoteSender: L1_MESSENGER_ADDRESS
  });
  const verification = await requestL1AnchoredFactVerification({
    requestId: "diagnostic-l1-anchored-fact",
    evidence,
    stateReader,
    issueTime: now(),
    expiresAt: futureDate(),
    freshnessMs: 60_000
  });
  const relay = await prepareL1ToBaseFactRelayTransaction({
    requestId: "diagnostic-l1-to-base-relay-preparation",
    anchoredFactEvidence: evidence,
    stateReader,
    deploymentReader: createFixtureL1ToBaseRelayDeploymentReader({
      l1RelayAddress: L1_RELAY_ADDRESS,
      l1AnchorAddress: ANCHOR_ADDRESS,
      l1MessengerAddress: L1_MESSENGER_ADDRESS,
      baseMirrorAddress: BASE_MIRROR_ADDRESS,
      baseMessengerAddress: BASE_MESSENGER_ADDRESS,
      authorizedL1RemoteSender: L1_MESSENGER_ADDRESS
    }),
    configuration: config,
    value: hasArg("--invalid-value") ? "1" : "0",
    feeQuoter: createFixtureL1ToBaseRelayFeeQuoter("0"),
    gasEstimator: createFixtureL1ToBaseRelayGasEstimator("350000"),
    nonceReader: createFixtureL1ToBaseRelayNonceReader("8"),
    issueTime: now(),
    expiresAt: futureDate(),
    freshnessMs: 60_000,
    auditCorrelationId: "diagnostic-l1-to-base-relay"
  });
  const draft = relay.status === "approved" ? relay.value : undefined;
  const summary = {
    phase: "M.6D",
    evidenceClass: evidence.source,
    liveAnchoredFactEvidence: evidence.liveAnchoredFactEvidence,
    productionSignable: draft?.productionSignable ?? false,
    l1AnchorTransaction: evidence.binding.l1AnchorTransactionHash,
    factAnchoredStatus: verification.status === "approved" ? verification.value.outcome : verification.error.details?.outcome,
    proofInputHash: evidence.binding.proofInputHash,
    factHigh: evidence.binding.factHigh,
    factLow: evidence.binding.factLow,
    l1RelayContract: L1_RELAY_ADDRESS,
    l1Messenger: L1_MESSENGER_ADDRESS,
    baseMessenger: BASE_MESSENGER_ADDRESS,
    baseMirror: BASE_MIRROR_ADDRESS,
    authorizedL1RemoteSender: L1_MESSENGER_ADDRESS,
    methodSelector: draft?.methodSelector ?? null,
    calldataHash: draft?.calldataHash ?? null,
    transactionValue: draft?.value ?? null,
    remoteGasLimit: draft?.remoteGasLimit ?? null,
    nonceStatus: draft?.nonce.status ?? "unavailable",
    gasStatus: draft?.gas.status ?? "unavailable",
    feeStatus: relay.status === "approved" ? "resolved" : "unavailable",
    relayPrepared: relay.status === "approved",
    transactionSigned: false,
    transactionSubmitted: false,
    crossDomainMessageSent: false,
    baseMirrorCalled: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    chainStateMutated: false
  };
  if (hasArg("--json")) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log("Ethereum L1-to-Base fact relay preparation diagnostic");
  for (const [key, value] of Object.entries(summary)) {
    console.log(`${key}: ${value}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
