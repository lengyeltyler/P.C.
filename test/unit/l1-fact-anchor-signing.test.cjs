const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const hre = require("hardhat");
const { ethers } = hre;
const { describe, it } = require("mocha");
const { deployContract } = require("../helpers/context.cjs");

const {
  createFixtureEthereumL1MessageAvailabilityReader,
  createFixtureEthereumReceiptReader,
  createFixtureEthereumTransactionSubmitter,
  createFixtureL1FactAnchorDeploymentReader,
  createFixtureL1FactAnchorSigner,
  createFixtureL1FactAnchorStateReader,
  createFixtureL1FeeDataReader,
  createFixtureL1GasEstimator,
  createFixtureL1NonceReader,
  createInMemoryAuditDraftCollector,
  createInMemoryL1FactAnchorSubmittedTransactionStore,
  createL1FactAnchorFixtureConfiguration,
  createL1FactAnchorSigningPresentation,
  createL1FactAnchorSubmissionApproval,
  createStarknetL2ToL1MessageIdentity,
  createUnavailableEthereumTransactionSubmitter,
  deriveCanonicalStarknetL2ToL1MessageHash,
  prepareL1FactAnchorTransaction,
  requestL1FactAnchorReceiptMonitoring,
  requestL1FactAnchorSubmission,
  requestL1FactAnchorTransactionSigning,
  verifyL1FactAnchoredEvent
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const SOURCE_L2_VERIFIER = "0x5048494c";
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";
const FIXTURE_PRIVATE_KEY = `0x${"11".repeat(32)}`;

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function receiptArtifact(anchorAddress, overrides = {}) {
  const messageHash = deriveCanonicalStarknetL2ToL1MessageHash({
    fromAddress: SOURCE_L2_VERIFIER,
    toAddress: anchorAddress,
    payload: [FACT_HIGH, FACT_LOW]
  });
  return {
    receiptArtifactId: "receipt-artifact-signing-1",
    submissionId: "submission-signing-1",
    transactionHash: "0xabc123",
    networkProfileId: "local_devnet",
    chainId: "SN_LOCAL",
    publicationContract: SOURCE_L2_VERIFIER,
    senderAccount: "0x12345",
    proofInputHash: PROOF_INPUT_HASH,
    factHigh: FACT_HIGH,
    factLow: FACT_LOW,
    l1Recipient: anchorAddress,
    transactionStatus: "transaction_accepted_on_l2",
    blockNumber: 9,
    blockHash: "0xbeef",
    event: {
      contractAddress: SOURCE_L2_VERIFIER,
      transactionHash: "0xabc123",
      eventSelector: "0x1",
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      blockNumber: 9,
      blockHash: "0xbeef"
    },
    l2ToL1Message: {
      senderContract: SOURCE_L2_VERIFIER,
      l1Recipient: anchorAddress,
      payloadLength: 2,
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      transactionHash: "0xabc123",
      blockNumber: 9,
      blockHash: "0xbeef",
      messageHash
    },
    observedAt: now(),
    auditCorrelationId: "audit-l1-anchor-signing",
    limitations: [],
    transactionAcceptedOnL2: true,
    verificationEventObserved: true,
    l2ToL1MessageObserved: true,
    l1MessageAvailabilityConfirmed: false,
    l1MessageConsumed: false,
    l1FactAnchored: false,
    baseFactMirrored: false,
    nullifierConsumed: false,
    ...overrides
  };
}

async function deployedFixture() {
  const [deployer] = await ethers.getSigners();
  const messaging = await deployContract(deployer, "MockStarknetMessaging");
  const anchor = await deployContract(deployer, "PhilL1ProofInputHashAnchor", [
    await messaging.getAddress(),
    BigInt(SOURCE_L2_VERIFIER)
  ]);
  const anchorAddress = await anchor.getAddress();
  const messagingAddress = await messaging.getAddress();
  const artifact = receiptArtifact(anchorAddress);
  const identity = createStarknetL2ToL1MessageIdentity({
    receiptArtifact: artifact,
    evidenceClass: "local_devnet_receipt",
    expectedL2Sender: SOURCE_L2_VERIFIER,
    expectedL1Recipient: anchorAddress,
    expectedProofInputHash: PROOF_INPUT_HASH
  });
  const config = createL1FactAnchorFixtureConfiguration({
    anchorAddress,
    messagingCoreAddress: messagingAddress,
    sourceL2Verifier: SOURCE_L2_VERIFIER
  });
  return { deployer, messaging, anchor, anchorAddress, messagingAddress, artifact, identity, config };
}

async function preparedDraft(fixture, overrides = {}) {
  const result = await prepareL1FactAnchorTransaction({
    requestId: "l1-anchor-prep-signing-1",
    messageIdentity: fixture.identity,
    availabilityReader: createFixtureEthereumL1MessageAvailabilityReader({ available: true }),
    deploymentReader: createFixtureL1FactAnchorDeploymentReader({
      anchorAddress: fixture.anchorAddress,
      messagingCoreAddress: fixture.messagingAddress,
      sourceL2Verifier: SOURCE_L2_VERIFIER
    }),
    configuration: fixture.config,
    senderAccount: fixture.anchorAddress,
    value: "0",
    gasEstimator: createFixtureL1GasEstimator("300000"),
    nonceReader: createFixtureL1NonceReader("7"),
    feeDataReader: createFixtureL1FeeDataReader(),
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "audit-l1-anchor-signing",
    ...overrides
  });
  assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
  return result.value;
}

function relayerIdentity(address, overrides = {}) {
  return {
    relayerId: "fixture-relayer",
    mode: "developer_fixture",
    address,
    displayName: "Fixture relayer",
    approved: true,
    productionSuitable: false,
    expectedSignerAddress: address,
    ...overrides
  };
}

function relayerPolicy(draft, overrides = {}) {
  return {
    allowedModes: ["developer_fixture"],
    allowedChainIds: [draft.binding.ethereumChainId],
    allowedAnchorAddresses: [draft.binding.anchorAddress],
    allowMainnet: false,
    requireLiveMessageEvidence: false,
    maxFeePerGas: "2000000000",
    maxPriorityFeePerGas: "200000000",
    maxGasLimit: "500000",
    minBalanceWei: "1",
    allowedApprovalSources: ["developer_fixture_approval"],
    ...overrides
  };
}

function signingApproval(draft, relayer, overrides = {}) {
  const presentation = createL1FactAnchorSigningPresentation({ draft, relayer });
  return {
    approvalId: "fixture-signing-approval",
    source: "developer_fixture_approval",
    presentationDigest: presentation.digest,
    approved: true,
    approvedAt: now(),
    expiresAt: futureDate(),
    ...overrides
  };
}

async function signedFixture(overrides = {}) {
  const fixture = await deployedFixture();
  const draft = await preparedDraft(fixture);
  const signer = createFixtureL1FactAnchorSigner({ privateKey: FIXTURE_PRIVATE_KEY });
  const relayer = signer.describeSigner().relayerAddress;
  const result = await requestL1FactAnchorTransactionSigning({
    requestId: "l1-anchor-signing-1",
    draft,
    relayerIdentity: relayerIdentity(relayer, overrides.relayerIdentity),
    policy: relayerPolicy(draft, overrides.policy),
    approval: signingApproval(draft, relayer, overrides.approval),
    signer: overrides.signer ?? signer,
    availabilityReader: overrides.availabilityReader ?? createFixtureEthereumL1MessageAvailabilityReader({ available: true }),
    deploymentReader: overrides.deploymentReader ?? createFixtureL1FactAnchorDeploymentReader({
      anchorAddress: fixture.anchorAddress,
      messagingCoreAddress: fixture.messagingAddress,
      sourceL2Verifier: SOURCE_L2_VERIFIER
    }),
    gasEstimator: overrides.gasEstimator ?? createFixtureL1GasEstimator("300000"),
    nonceReader: overrides.nonceReader ?? createFixtureL1NonceReader("7"),
    feeDataReader: overrides.feeDataReader ?? createFixtureL1FeeDataReader(),
    fundingStatus: overrides.fundingStatus ?? {
      status: "sufficient",
      balanceWei: "1000000000000000000",
      checkedAt: now()
    },
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "audit-l1-anchor-signing"
  });
  return { fixture, draft, relayer, signer, result };
}

function confirmedReceipt(signed, fixture, overrides = {}) {
  const encoded = fixture.anchor.interface.encodeEventLog(
    fixture.anchor.interface.getEvent("ProofInputHashFactAnchored"),
    [BigInt(SOURCE_L2_VERIFIER), BigInt(FACT_HIGH), BigInt(FACT_LOW)]
  );
  return {
    transactionHash: signed.transactionHashBinding.transactionHash,
    status: "confirmed",
    blockNumber: 42,
    blockHash: `0x${"42".repeat(32)}`,
    gasUsed: "123456",
    effectiveGasPrice: "1000000000",
    confirmations: 2,
    logs: [{
      address: fixture.anchorAddress,
      topics: encoded.topics,
      data: encoded.data
    }],
    ...overrides
  };
}

describe("Ethereum L1 fact-anchor signing, submission, and monitoring boundary", function () {
  this.timeout(180_000);

  it("signs the exact immutable fixture L1 anchor transaction without submission or anchoring", async function () {
    const { result } = await signedFixture();
    assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
    const signed = result.value;
    assert.equal(signed.transactionSigned, true);
    assert.equal(signed.transactionSubmitted, false);
    assert.equal(signed.messageConsumed, false);
    assert.equal(signed.factAnchored, false);
    assert.equal(signed.l1ToBaseRelayPrepared, false);
    assert.equal(signed.baseStateChanged, false);
    assert.equal(signed.nullifierConsumed, false);
    assert.equal(signed.transaction.type, 2);
    assert.equal(signed.transaction.value, 0n);
    assert.equal(signed.binding.factHigh, FACT_HIGH);
    assert.equal(signed.binding.factLow, FACT_LOW);
    assert.ok(signed.limitations.includes("fixture_not_live_submission"));
  });

  it("rejects fixture evidence when live message evidence is required", async function () {
    const { result } = await signedFixture({ policy: { requireLiveMessageEvidence: true } });
    assert.equal(result.status, "denied");
    assert.equal(result.error.details.outcome, "fixture_evidence_rejected");
  });

  it("rejects unauthorized relayers, stale nonce, gas cap, fee cap, insufficient funds, and approval mismatches", async function () {
    for (const [overrides, expected] of [
      [{ relayerIdentity: { approved: false } }, "relayer_unapproved"],
      [{ nonceReader: createFixtureL1NonceReader("8") }, "nonce_unresolved"],
      [{ policy: { maxGasLimit: "1" } }, "gas_limit_exceeded"],
      [{ policy: { maxFeePerGas: "1" } }, "fee_cap_exceeded"],
      [{ fundingStatus: { status: "insufficient", balanceWei: "0", checkedAt: now() } }, "funding_insufficient"],
      [{ approval: { presentationDigest: "wrong" } }, "presentation_digest_mismatch"]
    ]) {
      const { result } = await signedFixture(overrides);
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, expected);
    }
  });

  it("rejects wrong signer and signer unavailability", async function () {
    const wrongSigner = createFixtureL1FactAnchorSigner({ privateKey: `0x${"22".repeat(32)}` });
    const { result: wrong } = await signedFixture({ signer: wrongSigner });
    assert.equal(wrong.status, "denied");
    assert.equal(wrong.error.details.outcome, "wrong_signer");

    const unavailableSigner = createFixtureL1FactAnchorSigner({ privateKey: FIXTURE_PRIVATE_KEY });
    unavailableSigner.invalidateSigningSession();
    const { result: unavailable } = await signedFixture({ signer: unavailableSigner });
    assert.equal(unavailable.status, "denied");
    assert.equal(unavailable.error.details.outcome, "signer_unavailable");
  });

  it("blocks submission without exact approval, with duplicate guard, stale nonce, fee changes, and consumed message state", async function () {
    const { fixture, result } = await signedFixture();
    const signed = result.value;
    const store = createInMemoryL1FactAnchorSubmittedTransactionStore();
    store.addTransaction(signed.transactionHashBinding.transactionHash);
    for (const [overrides, expected] of [
      [{ submissionApproval: undefined }, "approval_missing"],
      [{ submittedTransactionStore: store }, "duplicate_submission"],
      [{ nonceReader: createFixtureL1NonceReader("8") }, "nonce_changed"],
      [{ feeDataReader: { readFeeData: async () => ({ status: "resolved", maxFeePerGas: "2", maxPriorityFeePerGas: "1", checkedAt: now(), source: "fixture" }) } }, "fee_changed"],
      [{ availabilityReader: createFixtureEthereumL1MessageAvailabilityReader({ alreadyConsumed: true }) }, "message_already_consumed"]
    ]) {
      const submission = await requestL1FactAnchorSubmission({
        requestId: "l1-anchor-submit-negative",
        signedTransaction: signed,
        submissionApproval: createL1FactAnchorSubmissionApproval({
          signedTransaction: signed,
          source: "developer_fixture_approval"
        }),
        availabilityReader: createFixtureEthereumL1MessageAvailabilityReader({ available: true }),
        deploymentReader: createFixtureL1FactAnchorDeploymentReader({
          anchorAddress: fixture.anchorAddress,
          messagingCoreAddress: fixture.messagingAddress,
          sourceL2Verifier: SOURCE_L2_VERIFIER
        }),
        nonceReader: createFixtureL1NonceReader("7"),
        gasEstimator: createFixtureL1GasEstimator("300000"),
        feeDataReader: createFixtureL1FeeDataReader(),
        submitter: createFixtureEthereumTransactionSubmitter(),
        issueTime: now(),
        expiresAt: futureDate(),
        ...overrides
      });
      assert.equal(submission.status, "denied");
      assert.equal(submission.error.details.outcome, expected);
    }
  });

  it("submits only the exact signed fixture artifact and still does not confirm, relay, mirror, or consume nullifiers", async function () {
    const { fixture, result } = await signedFixture();
    const signed = result.value;
    const submission = await requestL1FactAnchorSubmission({
      requestId: "l1-anchor-submit-1",
      signedTransaction: signed,
      submissionApproval: createL1FactAnchorSubmissionApproval({
        signedTransaction: signed,
        source: "developer_fixture_approval"
      }),
      availabilityReader: createFixtureEthereumL1MessageAvailabilityReader({ available: true }),
      deploymentReader: createFixtureL1FactAnchorDeploymentReader({
        anchorAddress: fixture.anchorAddress,
        messagingCoreAddress: fixture.messagingAddress,
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
    assert.equal(submission.status, "approved", JSON.stringify(submission.error, null, 2));
    assert.equal(submission.value.transactionSubmitted, true);
    assert.equal(submission.value.transactionConfirmed, false);
    assert.equal(submission.value.l1FactAnchored, false);
    assert.equal(submission.value.l1ToBaseRelayPrepared, false);
    assert.equal(submission.value.baseFactMirrored, false);
    assert.equal(submission.value.nullifierConsumed, false);
  });

  it("handles unavailable submitter without claiming submission", async function () {
    const { fixture, result } = await signedFixture();
    const signed = result.value;
    const submission = await requestL1FactAnchorSubmission({
      requestId: "l1-anchor-submit-unavailable",
      signedTransaction: signed,
      submissionApproval: createL1FactAnchorSubmissionApproval({
        signedTransaction: signed,
        source: "developer_fixture_approval"
      }),
      availabilityReader: createFixtureEthereumL1MessageAvailabilityReader({ available: true }),
      deploymentReader: createFixtureL1FactAnchorDeploymentReader({
        anchorAddress: fixture.anchorAddress,
        messagingCoreAddress: fixture.messagingAddress,
        sourceL2Verifier: SOURCE_L2_VERIFIER
      }),
      nonceReader: createFixtureL1NonceReader("7"),
      gasEstimator: createFixtureL1GasEstimator("300000"),
      feeDataReader: createFixtureL1FeeDataReader(),
      submitter: createUnavailableEthereumTransactionSubmitter(),
      issueTime: now(),
      expiresAt: futureDate()
    });
    assert.equal(submission.status, "denied");
    assert.equal(submission.error.details.outcome, "rpc_unavailable");
  });

  it("validates anchor receipt events and state without relaying to Base", async function () {
    const { fixture, result } = await signedFixture();
    const signed = result.value;
    const receipt = confirmedReceipt(signed, fixture);
    const event = verifyL1FactAnchoredEvent(receipt, signed);
    assert.equal(event.status, "approved");

    const monitoring = await requestL1FactAnchorReceiptMonitoring({
      requestId: "l1-anchor-monitor-1",
      signedTransaction: signed,
      receiptReader: createFixtureEthereumReceiptReader(receipt),
      stateReader: createFixtureL1FactAnchorStateReader("anchored"),
      minConfirmations: 1,
      maxAttempts: 1
    });
    assert.equal(monitoring.status, "approved", JSON.stringify(monitoring.error, null, 2));
    assert.equal(monitoring.value.transactionConfirmed, true);
    assert.equal(monitoring.value.l2ToL1MessageConsumed, true);
    assert.equal(monitoring.value.l1FactAnchored, true);
    assert.equal(monitoring.value.l1ToBaseRelayPrepared, false);
    assert.equal(monitoring.value.l1ToBaseRelaySubmitted, false);
    assert.equal(monitoring.value.baseFactMirrored, false);
    assert.equal(monitoring.value.nullifierConsumed, false);
    assert.equal(monitoring.value.consumerExecuted, false);
  });

  it("rejects pending, reverted, wrong-event, and failed-state receipt outcomes", async function () {
    const { fixture, result } = await signedFixture();
    const signed = result.value;
    for (const [receipt, stateReader, code] of [
      [{ ...confirmedReceipt(signed, fixture), status: "pending" }, undefined, "L1_FACT_ANCHOR_RECEIPT_TIMEOUT"],
      [{ ...confirmedReceipt(signed, fixture), status: "reverted" }, undefined, "L1_FACT_ANCHOR_RECEIPT_NOT_CONFIRMED"],
      [{ ...confirmedReceipt(signed, fixture), logs: [] }, undefined, "L1_FACT_ANCHOR_EVENT_INVALID"],
      [confirmedReceipt(signed, fixture), createFixtureL1FactAnchorStateReader("not_anchored"), "L1_FACT_ANCHOR_STATE_INVALID"]
    ]) {
      const monitoring = await requestL1FactAnchorReceiptMonitoring({
        requestId: "l1-anchor-monitor-negative",
        signedTransaction: signed,
        receiptReader: createFixtureEthereumReceiptReader(receipt),
        stateReader,
        minConfirmations: 1,
        maxAttempts: 1,
        timeoutMs: 1
      });
      assert.equal(monitoring.status, "denied");
      assert.equal(monitoring.error.code, code);
    }
  });

  it("does not leak secrets in audit drafts", async function () {
    const fixture = await deployedFixture();
    const draft = await preparedDraft(fixture);
    const signer = createFixtureL1FactAnchorSigner({ privateKey: FIXTURE_PRIVATE_KEY });
    const relayer = signer.describeSigner().relayerAddress;
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const result = await requestL1FactAnchorTransactionSigning({
      requestId: "l1-anchor-signing-audit",
      draft,
      relayerIdentity: relayerIdentity(relayer),
      policy: relayerPolicy(draft),
      approval: signingApproval(draft, relayer),
      signer,
      availabilityReader: createFixtureEthereumL1MessageAvailabilityReader({ available: true }),
      deploymentReader: createFixtureL1FactAnchorDeploymentReader({
        anchorAddress: fixture.anchorAddress,
        messagingCoreAddress: fixture.messagingAddress,
        sourceL2Verifier: SOURCE_L2_VERIFIER
      }),
      gasEstimator: createFixtureL1GasEstimator("300000"),
      nonceReader: createFixtureL1NonceReader("7"),
      feeDataReader: createFixtureL1FeeDataReader(),
      fundingStatus: { status: "sufficient", balanceWei: "1000000000000000000", checkedAt: now() },
      issueTime: now(),
      expiresAt: futureDate(),
      auditDraftCollector
    });
    assert.equal(result.status, "approved");
    const serialized = JSON.stringify(auditDraftCollector.getAll());
    assert.doesNotMatch(serialized, /privateKey|seedPhrase|mnemonic|phil_secret|nullifierSeed|witness|biometric/i);
  });

  it("runs M.6C diagnostics without live submission", function () {
    const run = spawnSync("npm", [
      "run",
      "diagnose:l1-fact-anchor-signing",
      "--",
      "--json"
    ], { cwd: pathRoot(), encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /"transactionSigned": true/);
    assert.match(run.stdout, /"transactionSubmitted": false/);
    assert.match(run.stdout, /"live_l1_submission_performed": false/);
    assert.match(run.stdout, /"l1ToBaseRelayPrepared": false/);
    assert.match(run.stdout, /"nullifierConsumed": false/);
  });
});

function pathRoot() {
  return require("node:path").resolve(__dirname, "../..");
}
