const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const hre = require("hardhat");
const { ethers } = hre;
const { describe, it } = require("mocha");
const { deployContract } = require("../helpers/context.cjs");

const {
  L1_FACT_ANCHOR_METHOD_SELECTOR,
  createFixtureEthereumL1MessageAvailabilityReader,
  createFixtureL1FactAnchorDeploymentReader,
  createFixtureL1FeeDataReader,
  createFixtureL1GasEstimator,
  createFixtureL1NonceReader,
  createL1FactAnchorFixtureConfiguration,
  createStarknetL2ToL1MessageIdentity,
  deriveCanonicalStarknetL2ToL1MessageHash,
  encodeL1FactAnchorCalldata,
  prepareL1FactAnchorTransaction,
  requestL1MessageAvailability,
  requestL1FactAnchorTransactionPreparation,
  validateL1FactAnchorTransactionDraft,
  validateStarknetL2ToL1MessageIdentity
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const SOURCE_L2_VERIFIER = "0x5048494c";
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function receiptArtifact(anchorAddress, overrides = {}) {
  const messageHash = deriveCanonicalStarknetL2ToL1MessageHash({
    fromAddress: SOURCE_L2_VERIFIER,
    toAddress: anchorAddress,
    payload: [FACT_HIGH, FACT_LOW]
  });
  return {
    receiptArtifactId: "receipt-artifact-1",
    submissionId: "submission-1",
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
    auditCorrelationId: "audit-l1-anchor",
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

function prepRequest(fixture, overrides = {}) {
  return {
    requestId: "l1-anchor-prep-1",
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
    auditCorrelationId: "audit-l1-anchor-prep",
    ...overrides
  };
}

describe("Ethereum L1 message availability and fact-anchor preparation boundary", function () {
  this.timeout(180_000);

  it("derives the same L2-to-L1 message hash as the actual mock messaging contract", async function () {
    const fixture = await deployedFixture();
    const payload = [BigInt(FACT_HIGH), BigInt(FACT_LOW)];
    const contractHash = await fixture.messaging.l2ToL1MessageHash(
      BigInt(SOURCE_L2_VERIFIER),
      fixture.anchorAddress,
      payload
    );
    const helperHash = deriveCanonicalStarknetL2ToL1MessageHash({
      fromAddress: SOURCE_L2_VERIFIER,
      toAddress: fixture.anchorAddress,
      payload: [FACT_HIGH, FACT_LOW]
    });
    assert.equal(helperHash, contractHash);
  });

  it("creates valid live-shaped and fixture-classified message identities without promoting fixtures to production signable", async function () {
    const fixture = await deployedFixture();
    const fixtureIdentity = createStarknetL2ToL1MessageIdentity({
      receiptArtifact: fixture.artifact,
      evidenceClass: "fixture_receipt"
    });
    assert.equal(fixtureIdentity.status, "message_identity_valid");
    assert.equal(fixtureIdentity.liveMessageEvidence, false);
    assert.equal(fixtureIdentity.productionSignable, false);

    const liveIdentity = createStarknetL2ToL1MessageIdentity({
      receiptArtifact: { ...fixture.artifact, networkProfileId: "starknet_sepolia" },
      evidenceClass: "live_starknet_receipt",
      expectedStarknetNetworkProfileId: "starknet_sepolia"
    });
    assert.equal(liveIdentity.status, "message_identity_valid");
    assert.equal(liveIdentity.liveMessageEvidence, true);
    assert.equal(liveIdentity.productionSignable, true);
  });

  it("rejects wrong sender, wrong recipient, high/low reversal, wrong payload length, and proofInputHash mismatch", async function () {
    const fixture = await deployedFixture();
    const cases = [
      { l2ToL1Message: { ...fixture.artifact.l2ToL1Message, senderContract: "0x999" } },
      { l2ToL1Message: { ...fixture.artifact.l2ToL1Message, l1Recipient: ethers.Wallet.createRandom().address } },
      { l2ToL1Message: { ...fixture.artifact.l2ToL1Message, factHigh: FACT_LOW, factLow: FACT_HIGH } },
      { l2ToL1Message: { ...fixture.artifact.l2ToL1Message, payloadLength: 3 } },
      { proofInputHash: `0x${"11".repeat(32)}` }
    ];
    for (const item of cases) {
      const identity = createStarknetL2ToL1MessageIdentity({
        receiptArtifact: receiptArtifact(fixture.anchorAddress, item),
        evidenceClass: "local_devnet_receipt",
        expectedL2Sender: SOURCE_L2_VERIFIER,
        expectedL1Recipient: fixture.anchorAddress,
        expectedProofInputHash: PROOF_INPUT_HASH
      });
      assert.notEqual(validateStarknetL2ToL1MessageIdentity(identity).valid, true);
    }
  });

  it("checks message availability read-only and preserves race limitations", async function () {
    const fixture = await deployedFixture();
    const result = await requestL1MessageAvailability({
      requestId: "availability-1",
      messageIdentity: fixture.identity,
      ethereumNetworkProfileId: "hardhat",
      ethereumChainId: 31337,
      messagingCoreAddress: fixture.messagingAddress,
      anchorAddress: fixture.anchorAddress,
      issueTime: now(),
      expiresAt: futureDate(),
      freshnessMs: 60_000
    }, createFixtureEthereumL1MessageAvailabilityReader({ available: true, blockNumber: 5 }));
    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "message_available");
    assert.equal(result.value.l2ToL1MessageConsumed, false);
    assert.equal(result.value.l1FactAnchored, false);
    assert.match(result.value.raceWarning, /snapshot/i);
  });

  it("handles unavailable, consumed, unknown, stale, and mismatched availability states without consumption", async function () {
    const fixture = await deployedFixture();
    for (const [reader, outcome] of [
      [createFixtureEthereumL1MessageAvailabilityReader({ available: false }), "message_not_available"],
      [createFixtureEthereumL1MessageAvailabilityReader({ alreadyConsumed: true }), "message_already_consumed"],
      [createFixtureEthereumL1MessageAvailabilityReader({ unavailable: true }), "messaging_core_unavailable"],
      [{
        readMessageAvailability: async (request) => ({
          status: "message_state_unknown",
          messageHash: request.messageIdentity.binding.messageHash.value,
          checkedAt: now(),
          readerSource: "manual"
        })
      }, "message_state_unknown"],
      [{
        readMessageAvailability: async (request) => ({
          status: "message_available",
          messageHash: request.messageIdentity.binding.messageHash.value,
          messageCount: "1",
          checkedAt: pastDate(),
          readerSource: "fixture"
        })
      }, "stale_read"]
    ]) {
      const result = await requestL1MessageAvailability({
        requestId: "availability-negative",
        messageIdentity: fixture.identity,
        ethereumNetworkProfileId: "hardhat",
        ethereumChainId: 31337,
        messagingCoreAddress: fixture.messagingAddress,
        anchorAddress: fixture.anchorAddress,
        issueTime: now(),
        expiresAt: futureDate(),
        freshnessMs: 1
      }, reader);
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, outcome);
    }
  });

  it("prepares exact unsigned nonpayable anchor calldata without consuming the message", async function () {
    const fixture = await deployedFixture();
    const result = await prepareL1FactAnchorTransaction(prepRequest(fixture));
    assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
    const draft = result.value;
    assert.equal(draft.methodName, "consumeProofInputHashFactFromL2");
    assert.equal(draft.methodSelector, L1_FACT_ANCHOR_METHOD_SELECTOR);
    assert.equal(draft.value, "0");
    assert.equal(draft.calldata, encodeL1FactAnchorCalldata({ factHigh: FACT_HIGH, factLow: FACT_LOW }));
    assert.equal(draft.calldata, fixture.anchor.interface.encodeFunctionData("consumeProofInputHashFactFromL2", [
      BigInt(FACT_HIGH),
      BigInt(FACT_LOW)
    ]));
    assert.equal(draft.transactionPrepared, true);
    assert.equal(draft.transactionSigned, false);
    assert.equal(draft.transactionSubmitted, false);
    assert.equal(draft.l2ToL1MessageConsumed, false);
    assert.equal(draft.l1FactAnchored, false);
    assert.equal(draft.l1ToBaseRelayPrepared, false);
    assert.equal(draft.baseFactMirrored, false);
    assert.equal(draft.nullifierConsumed, false);
    assert.equal(draft.chainStateMutated, false);
    assert.equal(validateL1FactAnchorTransactionDraft(draft).valid, true);
  });

  it("keeps fixture-derived drafts non-production-signable", async function () {
    const fixture = await deployedFixture();
    const fixtureIdentity = createStarknetL2ToL1MessageIdentity({
      receiptArtifact: fixture.artifact,
      evidenceClass: "fixture_receipt"
    });
    const result = await prepareL1FactAnchorTransaction(prepRequest({ ...fixture, identity: fixtureIdentity }));
    assert.equal(result.status, "approved");
    assert.equal(result.value.liveMessageEvidence, false);
    assert.equal(result.value.productionSignable, false);
    assert.ok(result.value.limitations.includes("fixture_not_production_signable"));
  });

  it("rejects anchor deployment/configuration mismatch, network mismatch, selector mismatch, nonzero value, and missing message", async function () {
    const fixture = await deployedFixture();
    for (const [overrides, outcome] of [
      [{ deploymentReader: createFixtureL1FactAnchorDeploymentReader({ anchorAddress: fixture.anchorAddress, messagingCoreAddress: ethers.Wallet.createRandom().address, sourceL2Verifier: SOURCE_L2_VERIFIER }) }, "anchor_deployment_invalid"],
      [{ configuration: createL1FactAnchorFixtureConfiguration({ anchorAddress: fixture.anchorAddress, messagingCoreAddress: fixture.messagingAddress, sourceL2Verifier: "0x999" }) }, "wrong_sender"],
      [{
        configuration: {
          ...fixture.config,
          anchorDeployment: { ...fixture.config.anchorDeployment, methodSelector: "0x12345678" }
        }
      }, "anchor_configuration_invalid"],
      [{ value: "1" }, "malformed"],
      [{ availabilityReader: createFixtureEthereumL1MessageAvailabilityReader({ available: false }) }, "message_not_available"]
    ]) {
      const result = await prepareL1FactAnchorTransaction(prepRequest(fixture, overrides));
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, outcome);
    }
  });

  it("keeps unresolved gas, nonce, and fee explicit and non-signable", async function () {
    const fixture = await deployedFixture();
    const result = await requestL1FactAnchorTransactionPreparation(prepRequest(fixture, {
      gasEstimator: undefined,
      nonceReader: undefined,
      feeDataReader: undefined
    }));
    assert.equal(result.status, "approved");
    assert.equal(result.value.gas.status, "unresolved");
    assert.equal(result.value.nonce.status, "unresolved");
    assert.equal(result.value.fee.status, "unresolved");
    assert.equal(result.value.productionSignable, false);
  });

  it("does not leak secrets in audit drafts", async function () {
    const fixture = await deployedFixture();
    const { createInMemoryAuditDraftCollector } = require("../../apps/phil-device-sdk/src/runtime/index.ts");
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const result = await prepareL1FactAnchorTransaction(prepRequest(fixture, { auditDraftCollector }));
    assert.equal(result.status, "approved");
    const serialized = JSON.stringify(auditDraftCollector.getAll());
    assert.doesNotMatch(serialized, /privateKey|seedPhrase|mnemonic|phil_secret|nullifierSeed|witness|signature/i);
  });

  it("runs L1 diagnostics without signing, submitting, consuming, anchoring, relaying, or touching Base", function () {
    const result = spawnSync("npm", [
      "run",
      "diagnose:l1-fact-anchor-preparation",
      "--",
      "--json"
    ], { cwd: pathRoot(), encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /"transactionSigned": false/);
    assert.match(result.stdout, /"l2ToL1MessageConsumed": false/);
    assert.match(result.stdout, /"l1FactAnchored": false/);
    assert.match(result.stdout, /"baseFactMirrored": false/);
  });
});

function pathRoot() {
  return require("node:path").resolve(__dirname, "../..");
}
