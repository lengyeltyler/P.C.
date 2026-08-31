const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const hre = require("hardhat");
const { ethers } = hre;
const { describe, it } = require("mocha");
const { deployContract } = require("../helpers/context.cjs");

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
  createInMemoryAuditDraftCollector,
  createInMemoryL1ToBaseRelaySubmittedTransactionStore,
  createL1AnchoredFactEvidence,
  createL1ToBaseRelayFixtureConfiguration,
  createL1ToBaseRelaySigningPresentation,
  createL1ToBaseRelaySubmissionApproval,
  createUnavailableEthereumRelayTransactionSubmitter,
  deriveCanonicalStarknetL2ToL1MessageHash,
  prepareL1ToBaseFactRelayTransaction,
  requestBaseFactMirrorVerification,
  requestL1ToBaseRelayMonitoring,
  requestL1ToBaseRelaySigning,
  requestL1ToBaseRelaySubmission,
  validateApprovedBaseFactMirrorTarget
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const SOURCE_L2_VERIFIER = "0x5048494c";
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";
const RELAYER_PRIVATE_KEY = `0x${"11".repeat(32)}`;

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function rootPath() {
  return path.resolve(__dirname, "../..");
}

async function deployedFixture() {
  const [deployer] = await ethers.getSigners();
  const messaging = await deployContract(deployer, "MockStarknetMessaging");
  const anchor = await deployContract(deployer, "PhilL1ProofInputHashAnchor", [
    await messaging.getAddress(),
    BigInt(SOURCE_L2_VERIFIER)
  ]);
  const anchorAddress = await anchor.getAddress();
  await (await messaging.registerMessageFromL2(BigInt(SOURCE_L2_VERIFIER), anchorAddress, [
    BigInt(FACT_HIGH),
    BigInt(FACT_LOW)
  ])).wait();
  const anchorTx = await anchor.consumeProofInputHashFactFromL2(BigInt(FACT_HIGH), BigInt(FACT_LOW));
  const anchorReceipt = await anchorTx.wait();
  const messageHash = deriveCanonicalStarknetL2ToL1MessageHash({
    fromAddress: SOURCE_L2_VERIFIER,
    toAddress: anchorAddress,
    payload: [FACT_HIGH, FACT_LOW]
  });

  const baseMessenger = await deployContract(deployer, "MockBaseCrossDomainMessenger");
  const adapter = await deployContract(deployer, "PhilBaseCrossDomainMessengerAdapter", [
    await baseMessenger.getAddress(),
    200000
  ]);
  const baseMirror = await deployContract(deployer, "PhilBaseProofInputHashMirror", [
    await baseMessenger.getAddress(),
    await adapter.getAddress()
  ]);
  const relay = await deployContract(deployer, "PhilL1ToBaseProofInputHashMessenger", [
    anchorAddress,
    await adapter.getAddress()
  ]);

  const l1FactAnchorReceipt = {
    l1FactAnchorReceiptId: "fixture-l1-anchor-receipt",
    transactionHash: anchorReceipt.hash,
    chainId: 31337,
    anchorAddress,
    relayerAccount: await deployer.getAddress(),
    messageHash,
    proofInputHash: PROOF_INPUT_HASH,
    factHigh: FACT_HIGH,
    factLow: FACT_LOW,
    event: {
      contractAddress: anchorAddress,
      sourceL2Verifier: SOURCE_L2_VERIFIER,
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      transactionHash: anchorReceipt.hash,
      blockNumber: anchorReceipt.blockNumber,
      blockHash: anchorReceipt.blockHash
    },
    blockNumber: anchorReceipt.blockNumber,
    blockHash: anchorReceipt.blockHash,
    gasUsed: anchorReceipt.gasUsed.toString(),
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
  const evidence = createL1AnchoredFactEvidence({
    receipt: l1FactAnchorReceipt,
    source: "local_hardhat_receipt",
    expectedAnchorContract: anchorAddress,
    expectedFactHigh: FACT_HIGH,
    expectedFactLow: FACT_LOW,
    expectedProofInputHash: PROOF_INPUT_HASH,
    expectedStarknetMessageHash: messageHash,
    expectedStarknetSender: SOURCE_L2_VERIFIER,
    expectedEthereumChainId: 31337
  });
  const config = createL1ToBaseRelayFixtureConfiguration({
    l1AnchorAddress: anchorAddress,
    l1RelayAddress: await relay.getAddress(),
    l1MessengerAddress: await adapter.getAddress(),
    baseMessengerAddress: await baseMessenger.getAddress(),
    baseMirrorAddress: await baseMirror.getAddress(),
    authorizedL1RemoteSender: await adapter.getAddress()
  });
  const deploymentReader = createFixtureL1ToBaseRelayDeploymentReader({
    l1RelayAddress: await relay.getAddress(),
    l1AnchorAddress: anchorAddress,
    l1MessengerAddress: await adapter.getAddress(),
    baseMirrorAddress: await baseMirror.getAddress(),
    baseMessengerAddress: await baseMessenger.getAddress(),
    authorizedL1RemoteSender: await adapter.getAddress()
  });
  const stateReader = {
    async readAnchoredFact() {
      const anchored = await anchor.anchoredProofInputHashFact(BigInt(FACT_HIGH), BigInt(FACT_LOW));
      return {
        status: anchored ? "fact_anchored" : "fact_not_anchored",
        checkedAt: now(),
        blockNumber: anchorReceipt.blockNumber,
        blockHash: anchorReceipt.blockHash,
        readerSource: "rpc_view"
      };
    }
  };
  return {
    deployer,
    anchor,
    baseMessenger,
    adapter,
    baseMirror,
    relay,
    l1FactAnchorReceipt,
    evidence,
    config,
    deploymentReader,
    stateReader
  };
}

function prepRequest(fixture, overrides = {}) {
  return {
    requestId: "m6e-relay-prep",
    anchoredFactEvidence: fixture.evidence,
    stateReader: fixture.stateReader,
    deploymentReader: fixture.deploymentReader,
    configuration: fixture.config,
    relayerAccount: fixture.deployer.address,
    value: "0",
    feeQuoter: createFixtureL1ToBaseRelayFeeQuoter("0"),
    gasEstimator: createFixtureL1ToBaseRelayGasEstimator("350000"),
    nonceReader: createFixtureL1ToBaseRelayNonceReader("8"),
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "audit-m6e-relay",
    ...overrides
  };
}

async function signedFixture(overrides = {}) {
  const fixture = await deployedFixture();
  const prepared = await prepareL1ToBaseFactRelayTransaction(prepRequest(fixture, overrides.prep ?? {}));
  assert.equal(prepared.status, "approved", JSON.stringify(prepared.error, null, 2));
  const draft = prepared.value;
  const relayerWallet = new ethers.Wallet(RELAYER_PRIVATE_KEY);
  const fee = createFixtureL1ToBaseRelayFeeDataReader();
  const feeData = await fee.readFeeData({});
  const presentation = createL1ToBaseRelaySigningPresentation({
    draft,
    relayer: relayerWallet.address,
    fee: feeData,
    auditCorrelationId: "audit-m6e-relay"
  });
  const mirrorBinding = {
    baseChainId: draft.binding.baseChainId,
    baseMirrorAddress: draft.binding.baseMirrorAddress,
    messengerAddress: draft.binding.baseMessengerAddress,
    authorizedL1RemoteSender: draft.binding.authorizedL1RemoteSender,
    deploymentReference: "fixture-base-mirror",
    approvalStatus: "approved",
    configurationVersion: "fixture-v1",
    fixtureOnly: true
  };
  const mirrorPolicy = {
    allowedBaseChainIds: [draft.binding.baseChainId],
    approvedMirrorAddresses: [draft.binding.baseMirrorAddress],
    approvedMessengerAddresses: [draft.binding.baseMessengerAddress],
    approvedAuthorizedL1RemoteSenders: [draft.binding.authorizedL1RemoteSender],
    allowMainnet: false,
    requireLiveDeployment: false
  };
  const relayerIdentity = {
    relayerId: "fixture-relayer",
    mode: "developer_fixture",
    address: relayerWallet.address,
    displayName: "Fixture relay operator",
    approved: true,
    productionSuitable: false
  };
  const policy = {
    allowedModes: ["developer_fixture"],
    allowedL1ChainIds: [draft.binding.l1ChainId],
    allowedBaseChainIds: [draft.binding.baseChainId],
    allowedRelayContracts: [draft.binding.l1RelayAddress],
    allowMainnet: false,
    requireLiveAnchoredFactEvidence: false,
    requireApprovedMirrorBinding: true,
    maxFeePerGas: "2000000000",
    maxPriorityFeePerGas: "200000000",
    maxGasLimit: "500000",
    minBalanceWei: "1",
    allowedApprovalSources: ["developer_fixture_approval"]
  };
  const request = {
    requestId: "m6e-relay-signing",
    draft,
    mirrorBinding,
    mirrorPolicy,
    relayerIdentity,
    policy,
    approval: {
      approvalId: "fixture-signing-approval",
      source: "developer_fixture_approval",
      presentationDigest: presentation.digest,
      approved: true,
      approvedAt: now(),
      expiresAt: futureDate()
    },
    signer: createFixtureL1ToBaseRelaySigner({ privateKey: RELAYER_PRIVATE_KEY }),
    anchoredFactStateReader: fixture.stateReader,
    deploymentReader: fixture.deploymentReader,
    gasEstimator: createFixtureL1ToBaseRelayGasEstimator("350000"),
    nonceReader: createFixtureL1ToBaseRelayNonceReader("8"),
    feeDataReader: fee,
    fundingStatus: { status: "sufficient", balanceWei: "1000000000000000000", checkedAt: now() },
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "audit-m6e-relay",
    ...(overrides.signing ?? {})
  };
  const signed = await requestL1ToBaseRelaySigning(request);
  return { fixture, draft, request, signed, presentation, relayerWallet };
}

describe("Ethereum L1-to-Base relay signing, submission, and monitoring boundary", function () {
  this.timeout(180_000);

  it("validates approved Base mirror binding and rejects mirror substitution", async function () {
    const { draft, request } = await signedFixture();
    const accepted = validateApprovedBaseFactMirrorTarget(request.mirrorBinding, request.mirrorPolicy);
    assert.equal(accepted.status, "approved");

    const randomMirror = ethers.Wallet.createRandom().address;
    const rejected = validateApprovedBaseFactMirrorTarget({
      ...request.mirrorBinding,
      baseMirrorAddress: randomMirror
    }, request.mirrorPolicy);
    assert.equal(rejected.status, "rejected");

    const signing = await requestL1ToBaseRelaySigning({
      ...request,
      mirrorBinding: { ...request.mirrorBinding, baseMirrorAddress: randomMirror }
    });
    assert.equal(signing.status, "denied");
    assert.equal(signing.error.details.outcome, "mirror_target_rejected");
    assert.equal(draft.transactionSigned, false);
  });

  it("signs the exact immutable relay transaction without submission, Base mirroring, or nullifier consumption", async function () {
    const { signed, draft, relayerWallet } = await signedFixture();
    assert.equal(signed.status, "approved", JSON.stringify(signed.error, null, 2));
    assert.equal(signed.value.status, "relay_transaction_signed");
    assert.equal(signed.value.binding.approvedBaseMirror, draft.binding.baseMirrorAddress);
    assert.equal(signed.value.signatureArtifact.signerAccountAddress, relayerWallet.address);
    assert.equal(signed.value.signatureArtifact.privateKeyExposed, false);
    assert.equal(signed.value.transactionSigned, true);
    assert.equal(signed.value.transactionSubmitted, false);
    assert.equal(signed.value.crossDomainMessageSent, false);
    assert.equal(signed.value.baseMirrorCalled, false);
    assert.equal(signed.value.baseFactMirrored, false);
    assert.equal(signed.value.baseExecutionPrepared, false);
    assert.equal(signed.value.nullifierConsumed, false);
    assert.equal(signed.value.consumerExecuted, false);
    assert.ok(signed.value.limitations.includes("fixture_not_live_submission"));
  });

  it("blocks fixture anchoring evidence when live evidence is required for production signing", async function () {
    const { request } = await signedFixture();
    const result = await requestL1ToBaseRelaySigning({
      ...request,
      policy: { ...request.policy, requireLiveAnchoredFactEvidence: true }
    });
    assert.equal(result.status, "denied");
    assert.equal(result.error.details.outcome, "fixture_evidence_rejected");
  });

  it("rejects unauthorized relayer, stale nonce, gas/fee policy changes, insufficient balance, and bad signing approval", async function () {
    const { request } = await signedFixture();
    for (const [patch, expected] of [
      [{ relayerIdentity: { ...request.relayerIdentity, approved: false } }, "relayer_unapproved"],
      [{ nonceReader: createFixtureL1ToBaseRelayNonceReader("9") }, "nonce_unresolved"],
      [{ gasEstimator: createFixtureL1ToBaseRelayGasEstimator("700000") }, "gas_limit_exceeded"],
      [{ feeDataReader: { readFeeData: async () => ({ status: "resolved", maxFeePerGas: "3000000000", maxPriorityFeePerGas: "100000000", checkedAt: now(), source: "fixture" }) } }, "fee_cap_exceeded"],
      [{ fundingStatus: { status: "insufficient", balanceWei: "0", checkedAt: now() } }, "funding_insufficient"],
      [{ approval: { ...request.approval, presentationDigest: "wrong" } }, "presentation_digest_mismatch"],
      [{ approval: undefined }, "approval_missing"]
    ]) {
      const result = await requestL1ToBaseRelaySigning({ ...request, ...patch });
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, expected);
    }
  });

  it("submits only with explicit approval and keeps delivery, mirroring, and execution separate", async function () {
    const { signed, request } = await signedFixture();
    assert.equal(signed.status, "approved");
    const missing = await requestL1ToBaseRelaySubmission({
      requestId: "m6e-submit-missing-approval",
      signedTransaction: signed.value,
      anchoredFactStateReader: request.anchoredFactStateReader,
      deploymentReader: request.deploymentReader,
      gasEstimator: request.gasEstimator,
      nonceReader: request.nonceReader,
      feeDataReader: request.feeDataReader,
      submitter: createFixtureEthereumRelayTransactionSubmitter(),
      issueTime: now(),
      expiresAt: futureDate()
    });
    assert.equal(missing.status, "denied");
    assert.equal(missing.error.details.outcome, "approval_missing");

    const approval = createL1ToBaseRelaySubmissionApproval({
      signedTransaction: signed.value,
      source: "developer_fixture_approval"
    });
    const submitted = await requestL1ToBaseRelaySubmission({
      requestId: "m6e-submit",
      signedTransaction: signed.value,
      submissionApproval: approval,
      anchoredFactStateReader: request.anchoredFactStateReader,
      deploymentReader: request.deploymentReader,
      gasEstimator: request.gasEstimator,
      nonceReader: request.nonceReader,
      feeDataReader: request.feeDataReader,
      submitter: createFixtureEthereumRelayTransactionSubmitter(),
      issueTime: now(),
      expiresAt: futureDate()
    });
    assert.equal(submitted.status, "approved", JSON.stringify(submitted.error, null, 2));
    assert.equal(submitted.value.transactionSubmitted, true);
    assert.equal(submitted.value.l1RelayConfirmed, false);
    assert.equal(submitted.value.crossDomainMessageSent, false);
    assert.equal(submitted.value.crossDomainMessageRelayed, false);
    assert.equal(submitted.value.baseFactMirrored, false);
    assert.equal(submitted.value.nullifierConsumed, false);
    assert.equal(submitted.value.consumerExecuted, false);
  });

  it("blocks duplicate submission, changed nonce or fee, unavailable RPC, and unanchored fact", async function () {
    const { signed, request } = await signedFixture();
    assert.equal(signed.status, "approved");
    const approval = createL1ToBaseRelaySubmissionApproval({
      signedTransaction: signed.value,
      source: "developer_fixture_approval"
    });
    const store = createInMemoryL1ToBaseRelaySubmittedTransactionStore();
    store.addTransaction(signed.value.transactionHashBinding.transactionHash);
    for (const [patch, expected] of [
      [{ submittedTransactionStore: store }, "duplicate_submission"],
      [{ nonceReader: createFixtureL1ToBaseRelayNonceReader("9") }, "nonce_changed"],
      [{ feeDataReader: { readFeeData: async () => ({ status: "resolved", maxFeePerGas: "1000000001", maxPriorityFeePerGas: "100000000", checkedAt: now(), source: "fixture" }) } }, "fee_changed"],
      [{ anchoredFactStateReader: createFixtureL1AnchoredFactStateReader("fact_not_anchored") }, "fact_not_anchored"]
    ]) {
      const result = await requestL1ToBaseRelaySubmission({
        requestId: `m6e-submit-${expected}`,
        signedTransaction: signed.value,
        submissionApproval: approval,
        anchoredFactStateReader: request.anchoredFactStateReader,
        deploymentReader: request.deploymentReader,
        gasEstimator: request.gasEstimator,
        nonceReader: request.nonceReader,
        feeDataReader: request.feeDataReader,
        submitter: createFixtureEthereumRelayTransactionSubmitter(),
        issueTime: now(),
        expiresAt: futureDate(),
        ...patch
      });
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, expected);
    }

    const unavailable = await requestL1ToBaseRelaySubmission({
      requestId: "m6e-submit-rpc-unavailable",
      signedTransaction: signed.value,
      submissionApproval: approval,
      anchoredFactStateReader: request.anchoredFactStateReader,
      deploymentReader: request.deploymentReader,
      gasEstimator: request.gasEstimator,
      nonceReader: request.nonceReader,
      feeDataReader: request.feeDataReader,
      submitter: createUnavailableEthereumRelayTransactionSubmitter(),
      issueTime: now(),
      expiresAt: futureDate()
    });
    assert.equal(unavailable.status, "denied");
    assert.equal(unavailable.error.details.outcome, "rpc_unavailable");
  });

  it("monitors L1 receipt, cross-domain message delivery, and Base mirror verification without Base execution", async function () {
    const { signed, fixture } = await signedFixture();
    assert.equal(signed.status, "approved");
    const tx = await fixture.relay.relayProofInputHashFactToBase(
      await fixture.baseMirror.getAddress(),
      BigInt(FACT_HIGH),
      BigInt(FACT_LOW)
    );
    const receipt = await tx.wait();
    const relayReceipt = {
      transactionHash: signed.value.transactionHashBinding.transactionHash,
      status: "confirmed",
      blockNumber: receipt.blockNumber,
      blockHash: receipt.blockHash,
      gasUsed: receipt.gasUsed.toString(),
      effectiveGasPrice: receipt.gasPrice?.toString(),
      confirmations: 1,
      logs: receipt.logs.map((log) => ({
        address: log.address,
        topics: Array.from(log.topics),
        data: log.data
      }))
    };
    const monitored = await requestL1ToBaseRelayMonitoring({
      requestId: "m6e-monitor",
      signedTransaction: signed.value,
      receiptReader: createFixtureL1ToBaseRelayReceiptReader(relayReceipt),
      messageMonitor: createFixtureL1ToBaseMessageMonitor("message_relayed_on_base"),
      baseMirrorStateReader: createFixtureBaseFactMirrorStateReader("fact_mirrored"),
      minConfirmations: 1,
      maxAttempts: 1
    });
    assert.equal(monitored.status, "approved", JSON.stringify(monitored.error, null, 2));
    assert.equal(monitored.value.l1RelayConfirmed, true);
    assert.equal(monitored.value.crossDomainMessageRelayed, true);
    assert.equal(monitored.value.baseFactMirrored, true);
    assert.equal(monitored.value.baseAuthorizationExecutionPrepared, false);
    assert.equal(monitored.value.baseAuthorizationExecutionSubmitted, false);
    assert.equal(monitored.value.nullifierConsumed, false);
    assert.equal(monitored.value.consumerExecuted, false);
  });

  it("blocks pending/reverted receipts, wrong event, undelivered message, and missing Base mirror state", async function () {
    const { signed } = await signedFixture();
    assert.equal(signed.status, "approved");
    const baseReceipt = {
      transactionHash: signed.value.transactionHashBinding.transactionHash,
      status: "confirmed",
      blockNumber: 1,
      blockHash: `0x${"12".repeat(32)}`,
      confirmations: 1,
      logs: []
    };
    for (const [receipt, monitor, mirrorReader, expectedCode] of [
      [{ ...baseReceipt, status: "pending" }, createFixtureL1ToBaseMessageMonitor(), createFixtureBaseFactMirrorStateReader(), "L1_TO_BASE_RELAY_MONITORING_TIMEOUT"],
      [{ ...baseReceipt, status: "reverted" }, createFixtureL1ToBaseMessageMonitor(), createFixtureBaseFactMirrorStateReader(), "L1_TO_BASE_RELAY_RECEIPT_NOT_CONFIRMED"],
      [baseReceipt, createFixtureL1ToBaseMessageMonitor(), createFixtureBaseFactMirrorStateReader(), "L1_TO_BASE_RELAY_EVENT_INVALID"]
    ]) {
      const result = await requestL1ToBaseRelayMonitoring({
        requestId: `m6e-monitor-${expectedCode}`,
        signedTransaction: signed.value,
        receiptReader: createFixtureL1ToBaseRelayReceiptReader(receipt),
        messageMonitor: monitor,
        baseMirrorStateReader: mirrorReader,
        minConfirmations: 1,
        maxAttempts: 1,
        timeoutMs: 1
      });
      assert.equal(result.status, "denied");
      assert.equal(result.error.code, expectedCode);
    }
  });

  it("verifies Base mirror read-only state and rejects mismatched mirrored facts", async function () {
    const { signed } = await signedFixture();
    assert.equal(signed.status, "approved");
    const ok = await requestBaseFactMirrorVerification({
      signedTransaction: signed.value,
      messageEvidence: await createFixtureL1ToBaseMessageMonitor().readMessageStatus({
        signedTransaction: signed.value,
        l1Receipt: { transactionHash: signed.value.transactionHashBinding.transactionHash, status: "confirmed", logs: [] }
      })
    }, createFixtureBaseFactMirrorStateReader("fact_mirrored"));
    assert.equal(ok.status, "approved");
    assert.equal(ok.value.baseFactMirrored, true);
    assert.equal(ok.value.nullifierConsumed, false);

    const bad = await requestBaseFactMirrorVerification({
      signedTransaction: signed.value,
      messageEvidence: ok.value
    }, {
      async readBaseFactMirrorState(request) {
        const signedTx = request.signedTransaction;
        return {
          status: "fact_mirrored",
          baseMirror: signedTx.binding.approvedBaseMirror,
          baseMessenger: signedTx.binding.baseMessenger,
          authorizedL1RemoteSender: signedTx.binding.authorizedL1RemoteSender,
          factHigh: FACT_LOW,
          factLow: FACT_HIGH,
          checkedAt: now()
        };
      }
    });
    assert.equal(bad.status, "denied");
    assert.equal(bad.error.code, "BASE_FACT_MIRROR_MISMATCH");
  });

  it("preserves messenger authorization invariants on the Base mirror contract", async function () {
    const fixture = await deployedFixture();
    await assert.rejects(
      fixture.baseMirror.mirrorProofInputHashFact(BigInt(FACT_HIGH), BigInt(FACT_LOW)),
      /OnlyCrossDomainMessenger/
    );
    await assert.rejects(
      fixture.baseMessenger.sendMessage(
        await fixture.baseMirror.getAddress(),
        fixture.baseMirror.interface.encodeFunctionData("mirrorProofInputHashFact", [
          BigInt(FACT_HIGH),
          BigInt(FACT_LOW)
        ]),
        200000
      ),
      /TargetCallFailed/
    );
  });

  it("redacts audit details and never exposes private keys or unrestricted authority", async function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const { request } = await signedFixture({ signing: { auditDraftCollector } });
    const signed = await requestL1ToBaseRelaySigning({ ...request, auditDraftCollector });
    assert.equal(signed.status, "approved");
    const serialized = JSON.stringify(auditDraftCollector.getAll());
    assert.doesNotMatch(serialized, /privateKey|mnemonic|seedPhrase|phil_secret|nullifierSeed|witness|unrestricted/i);
  });

  it("runs M.6E diagnostics without live relay submission or Base authorization execution", function () {
    const run = spawnSync("npm", [
      "run",
      "diagnose:l1-to-base-relay-signing",
      "--",
      "--json"
    ], { cwd: rootPath(), encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /"relaySigned": true/);
    assert.match(run.stdout, /"live_relay_submission_performed": false/);
    assert.match(run.stdout, /"transactionSubmitted": false/);
    assert.match(run.stdout, /"crossDomainMessageSent": false/);
    assert.match(run.stdout, /"baseFactMirrored": false/);
    assert.match(run.stdout, /"nullifierConsumed": false/);
  });
});
