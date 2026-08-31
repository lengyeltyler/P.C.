const {
  createFixtureEthereumL1MessageAvailabilityReader,
  createFixtureEthereumTransactionSubmitter,
  createFixtureL1FactAnchorDeploymentReader,
  createFixtureL1FactAnchorSigner,
  createFixtureL1FeeDataReader,
  createFixtureL1GasEstimator,
  createFixtureL1NonceReader,
  createInMemoryL1FactAnchorSubmittedTransactionStore,
  createL1FactAnchorFixtureConfiguration,
  createL1FactAnchorSigningPresentation,
  createL1FactAnchorSubmissionApproval,
  createStarknetL2ToL1MessageIdentity,
  deriveCanonicalStarknetL2ToL1MessageHash,
  prepareL1FactAnchorTransaction,
  requestL1FactAnchorSubmission,
  requestL1FactAnchorTransactionSigning
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const SOURCE_L2_VERIFIER = "0x5048494c";
const ANCHOR_ADDRESS = "0x1111111111111111111111111111111111111111";
const MESSAGING_CORE_ADDRESS = "0x2222222222222222222222222222222222222222";
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";
const FIXTURE_PRIVATE_KEY = `0x${"11".repeat(32)}`;

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
    receiptArtifactId: "diagnostic-l1-anchor-signing-receipt",
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
    auditCorrelationId: "diagnostic-l1-anchor-signing",
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
    auditCorrelationId: "diagnostic-l1-anchor-signing"
  });

  let signing;
  let submission;
  if (preparation.status === "approved") {
    const signer = createFixtureL1FactAnchorSigner({ privateKey: FIXTURE_PRIVATE_KEY });
    const relayer = signer.describeSigner().relayerAddress;
    const presentation = createL1FactAnchorSigningPresentation({
      draft: preparation.value,
      relayer
    });
    signing = await requestL1FactAnchorTransactionSigning({
      requestId: "diagnostic-l1-anchor-signing",
      draft: preparation.value,
      relayerIdentity: {
        relayerId: "diagnostic-fixture-relayer",
        mode: "developer_fixture",
        address: relayer,
        displayName: "Diagnostic fixture relayer",
        approved: true,
        productionSuitable: false
      },
      policy: {
        allowedModes: ["developer_fixture"],
        allowedChainIds: [31337],
        allowedAnchorAddresses: [ANCHOR_ADDRESS],
        allowMainnet: false,
        requireLiveMessageEvidence: false,
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
      signer,
      availabilityReader,
      deploymentReader: createFixtureL1FactAnchorDeploymentReader({
        anchorAddress: ANCHOR_ADDRESS,
        messagingCoreAddress: MESSAGING_CORE_ADDRESS,
        sourceL2Verifier: SOURCE_L2_VERIFIER
      }),
      gasEstimator: createFixtureL1GasEstimator("300000"),
      nonceReader: createFixtureL1NonceReader("7"),
      feeDataReader: createFixtureL1FeeDataReader(),
      fundingStatus: {
        status: "sufficient",
        balanceWei: "1000000000000000000",
        checkedAt: now()
      },
      issueTime: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "diagnostic-l1-anchor-signing"
    });

    if (hasArg("--fixture-submit") && signing.status === "approved") {
      submission = await requestL1FactAnchorSubmission({
        requestId: "diagnostic-l1-anchor-fixture-submission",
        signedTransaction: signing.value,
        submissionApproval: createL1FactAnchorSubmissionApproval({
          signedTransaction: signing.value,
          source: "developer_fixture_approval"
        }),
        availabilityReader,
        deploymentReader: createFixtureL1FactAnchorDeploymentReader({
          anchorAddress: ANCHOR_ADDRESS,
          messagingCoreAddress: MESSAGING_CORE_ADDRESS,
          sourceL2Verifier: SOURCE_L2_VERIFIER
        }),
        nonceReader: createFixtureL1NonceReader("7"),
        gasEstimator: createFixtureL1GasEstimator("300000"),
        feeDataReader: createFixtureL1FeeDataReader(),
        submitter: createFixtureEthereumTransactionSubmitter(),
        submittedTransactionStore: createInMemoryL1FactAnchorSubmittedTransactionStore(),
        issueTime: now(),
        expiresAt: futureDate()
      });
    }
  }

  const signed = signing?.status === "approved" ? signing.value : undefined;
  const submitted = submission?.status === "approved" ? submission.value : undefined;
  const submitRequested = hasArg("--submit");
  const monitorRequested = hasArg("--monitor");
  const summary = {
    phase: "M.6C",
    commandMode: submitRequested ? "submit" : monitorRequested ? "monitor" : "diagnose",
    evidenceClass: identity.source.evidenceClass,
    liveMessageEvidence: identity.liveMessageEvidence,
    productionSignable: preparation.status === "approved" ? preparation.value.productionSignable : false,
    ethereumNetwork: "hardhat_fixture",
    ethereumSepoliaOnlyLiveRule: true,
    anchorAddress: ANCHOR_ADDRESS,
    messagingCoreAddress: MESSAGING_CORE_ADDRESS,
    expectedStarknetSender: SOURCE_L2_VERIFIER,
    messageHash: identity.binding.messageHash.value,
    proofInputHash: identity.binding.proofInputHash,
    factHigh: identity.binding.payload.factHigh,
    factLow: identity.binding.payload.factLow,
    relayerMode: "developer_fixture",
    relayerAddress: signed?.binding.relayerAccount ?? null,
    transactionHash: signed?.transactionHashBinding.transactionHash ?? null,
    maximumFee: signed
      ? (BigInt(signed.binding.maxFeePerGas) * BigInt(signed.binding.gasLimit)).toString()
      : null,
    transactionPrepared: preparation.status === "approved",
    transactionSigned: Boolean(signed),
    transactionSubmitted: Boolean(submitted),
    live_l1_submission_performed: false,
    reason: submitRequested
      ? "missing independently validated live Starknet Sepolia message evidence, accepted Sepolia anchor deployment, approved protected relayer, and explicit live submission approval"
      : "diagnostic mode is non-mutating",
    l2ToL1MessageConsumed: false,
    l1FactAnchored: false,
    l1ToBaseRelayPrepared: false,
    l1ToBaseRelaySubmitted: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    chainStateMutated: false
  };

  if (hasArg("--json")) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log("Ethereum L1 fact-anchor signing diagnostic");
  for (const [key, value] of Object.entries(summary)) {
    console.log(`${key}: ${value}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
