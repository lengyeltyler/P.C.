const {
  createFixtureBaseFactMirrorStateReader,
  createFixtureEthereumRelayTransactionSubmitter,
  createFixtureL1AnchoredFactStateReader,
  createFixtureL1ToBaseMessageMonitor,
  createFixtureL1ToBaseRelayDeploymentReader,
  createFixtureL1ToBaseRelayFeeDataReader,
  createFixtureL1ToBaseRelayFeeQuoter,
  createFixtureL1ToBaseRelayGasEstimator,
  createFixtureL1ToBaseRelayNonceReader,
  createFixtureL1ToBaseRelayReceiptReader,
  createFixtureL1ToBaseRelaySigner,
  createL1AnchoredFactEvidence,
  createL1ToBaseRelayFixtureConfiguration,
  createL1ToBaseRelaySigningPresentation,
  createL1ToBaseRelaySubmissionApproval,
  deriveCanonicalStarknetL2ToL1MessageHash,
  prepareL1ToBaseFactRelayTransaction,
  requestBaseFactMirrorVerification,
  requestL1ToBaseRelayMonitoring,
  requestL1ToBaseRelaySigning,
  requestL1ToBaseRelaySubmission
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");
const { Interface, Wallet } = require("ethers");

const SOURCE_L2_VERIFIER = "0x5048494c";
const ANCHOR_ADDRESS = "0x1111111111111111111111111111111111111111";
const L1_RELAY_ADDRESS = "0x3333333333333333333333333333333333333333";
const L1_MESSENGER_ADDRESS = "0x4444444444444444444444444444444444444444";
const BASE_MESSENGER_ADDRESS = "0x5555555555555555555555555555555555555555";
const BASE_MIRROR_ADDRESS = "0x6666666666666666666666666666666666666666";
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";
const RELAYER_PRIVATE_KEY = `0x${"11".repeat(32)}`;
const RELAY_INTERFACE = new Interface([
  "event ProofInputHashFactRelayedToBase(address indexed baseMirror,uint256 indexed factHigh,uint256 indexed factLow)"
]);

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

async function buildSignedFixture() {
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
    baseMirrorAddress: hasArg("--mirror-mismatch")
      ? "0x9999999999999999999999999999999999999999"
      : BASE_MIRROR_ADDRESS,
    authorizedL1RemoteSender: L1_MESSENGER_ADDRESS
  });
  const deploymentReader = createFixtureL1ToBaseRelayDeploymentReader({
    l1RelayAddress: L1_RELAY_ADDRESS,
    l1AnchorAddress: ANCHOR_ADDRESS,
    l1MessengerAddress: L1_MESSENGER_ADDRESS,
    baseMirrorAddress: config.baseMirror.address,
    baseMessengerAddress: BASE_MESSENGER_ADDRESS,
    authorizedL1RemoteSender: L1_MESSENGER_ADDRESS
  });
  const prepared = await prepareL1ToBaseFactRelayTransaction({
    requestId: "diagnostic-l1-to-base-relay-preparation",
    anchoredFactEvidence: evidence,
    stateReader,
    deploymentReader,
    configuration: config,
    value: "0",
    feeQuoter: createFixtureL1ToBaseRelayFeeQuoter("0"),
    gasEstimator: createFixtureL1ToBaseRelayGasEstimator("350000"),
    nonceReader: createFixtureL1ToBaseRelayNonceReader("8"),
    issueTime: now(),
    expiresAt: futureDate(),
    freshnessMs: 60_000,
    auditCorrelationId: "diagnostic-l1-to-base-relay"
  });
  if (prepared.status !== "approved") return { prepared, evidence };

  const draft = prepared.value;
  const wallet = new Wallet(RELAYER_PRIVATE_KEY);
  const feeDataReader = createFixtureL1ToBaseRelayFeeDataReader();
  const fee = await feeDataReader.readFeeData({});
  const presentation = createL1ToBaseRelaySigningPresentation({
    draft,
    relayer: wallet.address,
    fee,
    auditCorrelationId: "diagnostic-l1-to-base-relay"
  });
  const signed = await requestL1ToBaseRelaySigning({
    requestId: "diagnostic-l1-to-base-relay-signing",
    draft,
    mirrorBinding: {
      baseChainId: draft.binding.baseChainId,
      baseMirrorAddress: draft.binding.baseMirrorAddress,
      messengerAddress: draft.binding.baseMessengerAddress,
      authorizedL1RemoteSender: draft.binding.authorizedL1RemoteSender,
      deploymentReference: "fixture-base-mirror",
      approvalStatus: "approved",
      configurationVersion: "fixture-v1",
      fixtureOnly: true
    },
    mirrorPolicy: {
      allowedBaseChainIds: [draft.binding.baseChainId],
      approvedMirrorAddresses: [draft.binding.baseMirrorAddress],
      approvedMessengerAddresses: [draft.binding.baseMessengerAddress],
      approvedAuthorizedL1RemoteSenders: [draft.binding.authorizedL1RemoteSender],
      allowMainnet: false,
      requireLiveDeployment: false
    },
    relayerIdentity: {
      relayerId: "diagnostic-fixture-relayer",
      mode: "developer_fixture",
      address: wallet.address,
      displayName: "Fixture relay operator",
      approved: true,
      productionSuitable: false
    },
    policy: {
      allowedModes: ["developer_fixture"],
      allowedL1ChainIds: [draft.binding.l1ChainId],
      allowedBaseChainIds: [draft.binding.baseChainId],
      allowedRelayContracts: [draft.binding.l1RelayAddress],
      allowMainnet: false,
      requireLiveAnchoredFactEvidence: hasArg("--require-live"),
      requireApprovedMirrorBinding: true,
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "200000000",
      maxGasLimit: "500000",
      minBalanceWei: "1",
      allowedApprovalSources: ["developer_fixture_approval"]
    },
    approval: {
      approvalId: "diagnostic-signing-approval",
      source: "developer_fixture_approval",
      presentationDigest: presentation.digest,
      approved: true,
      approvedAt: now(),
      expiresAt: futureDate()
    },
    signer: createFixtureL1ToBaseRelaySigner({ privateKey: RELAYER_PRIVATE_KEY }),
    anchoredFactStateReader: stateReader,
    deploymentReader,
    gasEstimator: createFixtureL1ToBaseRelayGasEstimator("350000"),
    nonceReader: createFixtureL1ToBaseRelayNonceReader("8"),
    feeDataReader,
    fundingStatus: { status: "sufficient", balanceWei: "1000000000000000000", checkedAt: now() },
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-l1-to-base-relay"
  });
  return { evidence, prepared, signed, stateReader, deploymentReader, feeDataReader };
}

async function main() {
  const built = await buildSignedFixture();
  const draft = built.prepared.status === "approved" ? built.prepared.value : undefined;
  const signed = built.signed?.status === "approved" ? built.signed.value : undefined;
  let submission;
  if (signed && hasArg("--submit") && hasArg("--fixture-submit")) {
    const approval = createL1ToBaseRelaySubmissionApproval({
      signedTransaction: signed,
      source: "developer_fixture_approval"
    });
    submission = await requestL1ToBaseRelaySubmission({
      requestId: "diagnostic-l1-to-base-relay-submission",
      signedTransaction: signed,
      submissionApproval: approval,
      anchoredFactStateReader: built.stateReader,
      deploymentReader: built.deploymentReader,
      gasEstimator: createFixtureL1ToBaseRelayGasEstimator("350000"),
      nonceReader: createFixtureL1ToBaseRelayNonceReader("8"),
      feeDataReader: built.feeDataReader,
      submitter: createFixtureEthereumRelayTransactionSubmitter(),
      issueTime: now(),
      expiresAt: futureDate()
    });
  }

  let monitor;
  let baseMirrorVerification;
  if (signed && (hasArg("--monitor") || hasArg("--verify-base-mirror"))) {
    const event = RELAY_INTERFACE.encodeEventLog(RELAY_INTERFACE.getEvent("ProofInputHashFactRelayedToBase"), [
      signed.binding.approvedBaseMirror,
      BigInt(signed.binding.factHigh),
      BigInt(signed.binding.factLow)
    ]);
    const receipt = {
      transactionHash: signed.transactionHashBinding.transactionHash,
      status: "confirmed",
      blockNumber: 1,
      blockHash: `0x${"34".repeat(32)}`,
      confirmations: 1,
      logs: [{
        address: signed.binding.l1RelayContract,
        topics: event.topics,
        data: event.data
      }]
    };
    const messageMonitor = createFixtureL1ToBaseMessageMonitor(
      hasArg("--message-pending") ? "message_pending" : "message_relayed_on_base"
    );
    const mirrorReader = createFixtureBaseFactMirrorStateReader(
      hasArg("--base-not-mirrored") ? "fact_not_mirrored" : "fact_mirrored"
    );
    if (hasArg("--verify-base-mirror")) {
      const messageEvidence = await messageMonitor.readMessageStatus({ signedTransaction: signed, l1Receipt: receipt });
      baseMirrorVerification = await requestBaseFactMirrorVerification({
        signedTransaction: signed,
        messageEvidence
      }, mirrorReader);
    } else {
      monitor = await requestL1ToBaseRelayMonitoring({
        requestId: "diagnostic-l1-to-base-relay-monitor",
        signedTransaction: signed,
        receiptReader: createFixtureL1ToBaseRelayReceiptReader(receipt),
        messageMonitor,
        baseMirrorStateReader: mirrorReader,
        minConfirmations: 1,
        maxAttempts: 1
      });
    }
  }

  const summary = {
    phase: "M.6E",
    evidenceClass: built.evidence?.source,
    liveAnchoredFactEvidence: built.evidence?.liveAnchoredFactEvidence ?? false,
    productionSignable: draft?.productionSignable ?? false,
    l1ChainId: draft?.binding.l1ChainId ?? null,
    baseChainId: draft?.binding.baseChainId ?? null,
    l1RelayContract: draft?.binding.l1RelayAddress ?? null,
    l1Messenger: draft?.binding.l1MessengerAddress ?? null,
    baseMessenger: draft?.binding.baseMessengerAddress ?? null,
    approvedBaseMirror: draft?.binding.baseMirrorAddress ?? null,
    authorizedL1RemoteSender: draft?.binding.authorizedL1RemoteSender ?? null,
    factHigh: draft?.binding.factHigh ?? null,
    factLow: draft?.binding.factLow ?? null,
    proofInputHash: draft?.binding.proofInputHash ?? null,
    calldataHash: draft?.calldataHash ?? null,
    relayPrepared: built.prepared.status === "approved",
    relaySigned: built.signed?.status === "approved",
    signingOutcome: built.signed?.status === "approved" ? built.signed.value.outcome : built.signed?.error?.details?.outcome,
    transactionHash: signed?.transactionHashBinding.transactionHash ?? null,
    transactionSubmitted: submission?.status === "approved" ? submission.value.transactionSubmitted : false,
    submissionOutcome: submission?.status === "approved"
      ? submission.value.outcome
      : submission?.error?.details?.outcome ?? (hasArg("--submit") ? "blocked_missing_live_prerequisites" : null),
    crossDomainMessageSent: false,
    crossDomainMessageRelayed: monitor?.status === "approved" ? monitor.value.crossDomainMessageRelayed : false,
    baseFactMirrored: monitor?.status === "approved"
      ? monitor.value.baseFactMirrored
      : baseMirrorVerification?.status === "approved"
        ? baseMirrorVerification.value.baseFactMirrored
        : false,
    baseAuthorizationExecutionPrepared: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    live_relay_submission_performed: false,
    reason: "missing confirmed live L1 anchor evidence, accepted Sepolia/Base Sepolia deployments, approved protected relayer custody, and explicit live submission approval"
  };
  if (hasArg("--json")) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log("Ethereum L1-to-Base relay signing/submission/monitoring diagnostic");
  for (const [key, value] of Object.entries(summary)) {
    console.log(`${key}: ${value}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
