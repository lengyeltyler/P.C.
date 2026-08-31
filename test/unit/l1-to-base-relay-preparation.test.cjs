const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const hre = require("hardhat");
const { ethers } = hre;
const { describe, it } = require("mocha");
const { deployContract } = require("../helpers/context.cjs");

const {
  BASE_FACT_MIRROR_METHOD_SELECTOR,
  L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR,
  createFixtureL1AnchoredFactStateReader,
  createFixtureL1ToBaseRelayDeploymentReader,
  createFixtureL1ToBaseRelayFeeQuoter,
  createFixtureL1ToBaseRelayGasEstimator,
  createFixtureL1ToBaseRelayNonceReader,
  createInMemoryAuditDraftCollector,
  createL1AnchoredFactEvidence,
  createL1ToBaseRelayFixtureConfiguration,
  deriveCanonicalStarknetL2ToL1MessageHash,
  encodeBaseFactMirrorCalldata,
  encodeL1ToBaseFactRelayCalldata,
  prepareL1ToBaseFactRelayTransaction,
  requestL1AnchoredFactVerification,
  requestL1ToBaseFactRelayPreparation,
  validateL1ToBaseFactRelayTransactionDraft
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
    messaging,
    anchor,
    anchorAddress,
    baseMessenger,
    adapter,
    baseMirror,
    relay,
    l1FactAnchorReceipt,
    evidence,
    config,
    deploymentReader,
    stateReader,
    messageHash
  };
}

function prepRequest(fixture, overrides = {}) {
  return {
    requestId: "l1-to-base-relay-prep-1",
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
    auditCorrelationId: "audit-l1-to-base-relay",
    ...overrides
  };
}

describe("Ethereum L1-to-Base fact relay preparation boundary", function () {
  this.timeout(180_000);

  it("creates valid anchored fact evidence but does not promote fixture/local evidence to production signable", async function () {
    const fixture = await deployedFixture();
    assert.equal(fixture.evidence.status, "anchored_fact_evidence_valid");
    assert.equal(fixture.evidence.liveAnchoredFactEvidence, false);
    assert.equal(fixture.evidence.productionSignable, false);
    assert.equal(fixture.evidence.binding.factHigh, FACT_HIGH);
    assert.equal(fixture.evidence.binding.factLow, FACT_LOW);
  });

  it("verifies anchored fact state read-only and preserves race limitations", async function () {
    const fixture = await deployedFixture();
    const result = await requestL1AnchoredFactVerification({
      requestId: "verify-anchored-fact",
      evidence: fixture.evidence,
      stateReader: fixture.stateReader,
      issueTime: now(),
      expiresAt: futureDate(),
      freshnessMs: 60_000
    });
    assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
    assert.equal(result.value.outcome, "fact_anchored");
    assert.equal(result.value.l1FactAnchored, true);
    assert.equal(result.value.l1ToBaseRelayPrepared, false);
    assert.equal(result.value.baseFactMirrored, false);
    assert.equal(result.value.chainStateMutated, false);
    assert.match(result.value.raceWarning, /snapshot/i);
  });

  it("prepares exact unsigned relay calldata and exact Base mirror payload without sending a message", async function () {
    const fixture = await deployedFixture();
    const result = await prepareL1ToBaseFactRelayTransaction(prepRequest(fixture));
    assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
    const draft = result.value;
    assert.equal(draft.methodName, "relayProofInputHashFactToBase");
    assert.equal(draft.methodSelector, L1_TO_BASE_FACT_RELAY_METHOD_SELECTOR);
    assert.equal(draft.baseMirrorCallPreview.selector, BASE_FACT_MIRROR_METHOD_SELECTOR);
    assert.equal(draft.baseMirrorCallPreview.calldata, encodeBaseFactMirrorCalldata({
      factHigh: FACT_HIGH,
      factLow: FACT_LOW
    }));
    assert.equal(draft.calldata, encodeL1ToBaseFactRelayCalldata({
      baseMirror: await fixture.baseMirror.getAddress(),
      factHigh: FACT_HIGH,
      factLow: FACT_LOW
    }));
    assert.equal(draft.calldata, fixture.relay.interface.encodeFunctionData("relayProofInputHashFactToBase", [
      await fixture.baseMirror.getAddress(),
      BigInt(FACT_HIGH),
      BigInt(FACT_LOW)
    ]));
    assert.equal(draft.value, "0");
    assert.equal(draft.transactionPrepared, true);
    assert.equal(draft.transactionSigned, false);
    assert.equal(draft.transactionSubmitted, false);
    assert.equal(draft.crossDomainMessageSent, false);
    assert.equal(draft.baseMirrorCalled, false);
    assert.equal(draft.baseFactMirrored, false);
    assert.equal(draft.nullifierConsumed, false);
    assert.equal(validateL1ToBaseFactRelayTransactionDraft(draft).valid, true);
  });

  it("rejects fact-not-anchored, wrong receipt, wrong event, high/low reversal, and proofInputHash mismatch", async function () {
    const fixture = await deployedFixture();
    for (const [override, expected] of [
      [{ stateReader: createFixtureL1AnchoredFactStateReader("fact_not_anchored") }, "fact_not_anchored"],
      [{ anchoredFactEvidence: createL1AnchoredFactEvidence({ receipt: { ...fixture.l1FactAnchorReceipt, transactionConfirmed: false }, source: "fixture_receipt" }) }, "anchored_fact_evidence_ineligible"],
      [{ anchoredFactEvidence: createL1AnchoredFactEvidence({ receipt: { ...fixture.l1FactAnchorReceipt, event: { ...fixture.l1FactAnchorReceipt.event, sourceL2Verifier: "0x999" } }, source: "fixture_receipt", expectedStarknetSender: SOURCE_L2_VERIFIER }) }, "anchored_fact_evidence_ineligible"],
      [{ anchoredFactEvidence: createL1AnchoredFactEvidence({ receipt: { ...fixture.l1FactAnchorReceipt, factHigh: FACT_LOW, factLow: FACT_HIGH }, source: "fixture_receipt" }) }, "anchored_fact_evidence_ineligible"],
      [{ anchoredFactEvidence: createL1AnchoredFactEvidence({ receipt: { ...fixture.l1FactAnchorReceipt, proofInputHash: `0x${"11".repeat(32)}` }, source: "fixture_receipt" }) }, "anchored_fact_evidence_ineligible"]
    ]) {
      const result = await prepareL1ToBaseFactRelayTransaction(prepRequest(fixture, override));
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, expected);
    }
  });

  it("rejects relay, messenger, mirror, remote-sender, chain, fee, value, gas, and nonce mismatches", async function () {
    const fixture = await deployedFixture();
    const random = ethers.Wallet.createRandom().address;
    for (const [override, expected] of [
      [{ deploymentReader: createFixtureL1ToBaseRelayDeploymentReader({ l1RelayAddress: random, l1AnchorAddress: fixture.anchorAddress, l1MessengerAddress: await fixture.adapter.getAddress(), baseMirrorAddress: await fixture.baseMirror.getAddress(), baseMessengerAddress: await fixture.baseMessenger.getAddress(), authorizedL1RemoteSender: await fixture.adapter.getAddress() }) }, "relay_deployment_invalid"],
      [{ deploymentReader: createFixtureL1ToBaseRelayDeploymentReader({ l1RelayAddress: await fixture.relay.getAddress(), l1AnchorAddress: fixture.anchorAddress, l1MessengerAddress: random, baseMirrorAddress: await fixture.baseMirror.getAddress(), baseMessengerAddress: await fixture.baseMessenger.getAddress(), authorizedL1RemoteSender: await fixture.adapter.getAddress() }) }, "messenger_pair_invalid"],
      [{ deploymentReader: createFixtureL1ToBaseRelayDeploymentReader({ l1RelayAddress: await fixture.relay.getAddress(), l1AnchorAddress: fixture.anchorAddress, l1MessengerAddress: await fixture.adapter.getAddress(), baseMirrorAddress: random, baseMessengerAddress: await fixture.baseMessenger.getAddress(), authorizedL1RemoteSender: await fixture.adapter.getAddress() }) }, "mirror_deployment_invalid"],
      [{ deploymentReader: createFixtureL1ToBaseRelayDeploymentReader({ l1RelayAddress: await fixture.relay.getAddress(), l1AnchorAddress: fixture.anchorAddress, l1MessengerAddress: await fixture.adapter.getAddress(), baseMirrorAddress: await fixture.baseMirror.getAddress(), baseMessengerAddress: await fixture.baseMessenger.getAddress(), authorizedL1RemoteSender: random }) }, "messenger_pair_invalid"],
      [{ configuration: createL1ToBaseRelayFixtureConfiguration({ l1AnchorAddress: fixture.anchorAddress, l1RelayAddress: await fixture.relay.getAddress(), l1MessengerAddress: await fixture.adapter.getAddress(), baseMessengerAddress: await fixture.baseMessenger.getAddress(), baseMirrorAddress: await fixture.baseMirror.getAddress(), authorizedL1RemoteSender: await fixture.adapter.getAddress(), l1ChainId: 11155111 }) }, "network_mismatch"],
      [{ feeQuoter: { quoteRelayFee: async () => ({ status: "unresolved", checkedAt: now(), source: "unavailable" }) } }, "fee_unresolved"],
      [{ value: "1" }, "fee_policy_violation"],
      [{ configuration: createL1ToBaseRelayFixtureConfiguration({ l1AnchorAddress: fixture.anchorAddress, l1RelayAddress: await fixture.relay.getAddress(), l1MessengerAddress: await fixture.adapter.getAddress(), baseMessengerAddress: await fixture.baseMessenger.getAddress(), baseMirrorAddress: await fixture.baseMirror.getAddress(), authorizedL1RemoteSender: await fixture.adapter.getAddress(), minGasLimit: "2000000" }) }, "gas_limit_unresolved"],
      [{ nonceReader: undefined }, "nonce_unresolved"],
      [{ gasEstimator: undefined }, "gas_limit_unresolved"]
    ]) {
      const result = await prepareL1ToBaseFactRelayTransaction(prepRequest(fixture, override));
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, expected);
    }
  });

  it("does not leak secrets in audit drafts", async function () {
    const fixture = await deployedFixture();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const result = await requestL1ToBaseFactRelayPreparation(prepRequest(fixture, { auditDraftCollector }));
    assert.equal(result.status, "approved");
    const serialized = JSON.stringify(auditDraftCollector.getAll());
    assert.doesNotMatch(serialized, /privateKey|seedPhrase|mnemonic|phil_secret|nullifierSeed|witness|signature/i);
  });

  it("runs M.6D diagnostics without signing, submitting, sending messages, touching Base, or consuming nullifiers", function () {
    const run = spawnSync("npm", [
      "run",
      "diagnose:l1-to-base-relay-preparation",
      "--",
      "--json"
    ], { cwd: pathRoot(), encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    assert.match(run.stdout, /"relayPrepared": true/);
    assert.match(run.stdout, /"transactionSigned": false/);
    assert.match(run.stdout, /"transactionSubmitted": false/);
    assert.match(run.stdout, /"crossDomainMessageSent": false/);
    assert.match(run.stdout, /"baseFactMirrored": false/);
    assert.match(run.stdout, /"nullifierConsumed": false/);
  });
});

function pathRoot() {
  return require("node:path").resolve(__dirname, "../..");
}
