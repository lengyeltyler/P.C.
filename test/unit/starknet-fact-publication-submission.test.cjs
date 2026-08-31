const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { describe, it } = require("mocha");
const { hash: starknetHash } = require("starknet");

const {
  createFixtureStarknetNonceReader,
  createFixtureStarknetPublicationDeploymentReader,
  createFixtureStarknetPublisherSigner,
  createFixtureStarknetReceiptReader,
  createFixtureStarknetTransactionFeeEstimator,
  createFixtureStarknetTransactionSubmitter,
  createInMemoryAuditDraftCollector,
  createInMemoryStarknetSubmittedTransactionStore,
  createStarknetPublicationSigningPresentation,
  createStarknetPublicationSubmissionApproval,
  createUnavailableStarknetPublicationDeploymentReader,
  createUnavailableStarknetTransactionSubmitter,
  monitorStarknetFactPublicationReceipt,
  prepareStarknetFactPublicationTransaction,
  requestStarknetFactPublicationReceiptMonitoring,
  requestStarknetFactPublicationSubmission,
  signStarknetFactPublicationTransaction,
  submitStarknetFactPublicationTransaction,
  validateSigningFeeFreshness,
  validateStarknetPublicationPreflight,
  verifyExistingStarknetPublicationDeployment,
  verifyStarknetFactVerificationEvent,
  verifyStarknetL2ToL1MessageEvidence
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const root = path.resolve(__dirname, "../..");
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";
const PUBLICATION_CONTRACT = "0x5048494c";
const L1_RECIPIENT = "0x4c315f54525553545f414e43484f52";
const PUBLISHER_ACCOUNT = "0x12345";
const CLASS_HASH = "0x123456789abcdef";
const COMPILED_CLASS_HASH = "0xabcdef123456789";
const PRIVATE_KEY = "0x1";

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function finalizedPackage(overrides = {}) {
  return {
    finalizedAuthorizationPackageId: "finalized-starknet-package-1",
    status: "authorization_package_finalized",
    outcome: "authorization_package_finalized",
    binding: {
      authorizationPackageDraftId: "draft-1",
      proofGenerationArtifactId: "proof-generation-1",
      proofVerificationResultId: "proof-verification-1",
      sessionId: "session-1",
      applicationId: "ethereum-net",
      intentId: "intent-1",
      capabilityName: "request_transaction_submission",
      ownerCommitment: "0xeabc46426af38005e06573556996c697727a37a4dee2facade7ee6b21f34f7f6",
      proofInputHash: PROOF_INPUT_HASH,
      auditCorrelationId: "audit-starknet-package"
    },
    actionUnlockAuthorization: {
      version: "v1",
      proofType: "stwo-unlock-keccak-v1",
      ownerCommitment: "0xeabc46426af38005e06573556996c697727a37a4dee2facade7ee6b21f34f7f6",
      actionHash: "0xd5d0b728949459873e285251af92184e4697ce9fef42838314e021c76837981c",
      policyHash: "0xc427bdc4dc8a7e133577265d90328a2a3678cd85d354d9f49acf2ec72d893476",
      nullifier: "0x98babeb39173de519d32e7f5c9f9212cc992b4ce34c28f85978ba0af093a4f06",
      consumerDataHash: "0x2083576b1bd13af43e74b048befa382eb9b540dcc1bb952b4c0b3133aebd10e1",
      expiry: "1900000000",
      proofInputHash: PROOF_INPUT_HASH,
      factShapeReference: "[fact_high, fact_low]"
    },
    proofArtifact: {
      proofArtifactId: "proof-artifact-1",
      proofGenerationArtifactId: "proof-generation-1",
      proofVerificationResultId: "proof-verification-1",
      proofType: "stwo-unlock-keccak-v1",
      proofDigest: "0x1111111111111111111111111111111111111111111111111111111111111111",
      proofByteLength: 482389,
      proofInputHash: PROOF_INPUT_HASH,
      proofBlobIncluded: false,
      proofBytesLogged: false,
      nonSecretProofArtifact: true,
      containsWitnessOpenings: false,
      safeForExternalVerifierTransmission: true,
      executableByAdapters: false
    },
    evidence: {
      proofGenerated: true,
      proofVerifiedLocally: true,
      proofTypeMatched: true,
      publicInputsMatched: true,
      proofInputHashMatched: true,
      factShapeValidated: true
    },
    factShapePreview: {
      proofInputHash: PROOF_INPUT_HASH,
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      factShapeReference: "[fact_high, fact_low]"
    },
    validity: {
      issuedAt: now(),
      expiresAt: futureDate(),
      expired: false
    },
    limitations: ["verified_fact_not_published"],
    authorizationPackageFinalized: true,
    proofGenerated: true,
    proofVerifiedLocally: true,
    verifiedFactPublished: false,
    onChainVerificationPerformed: false,
    nullifierConsumed: false,
    adapterExecutionAllowed: false,
    contractExecutionAllowed: false,
    transactionSubmitted: false,
    executableByApplications: false,
    witnessMaterialExposed: false,
    persisted: false,
    ...overrides
  };
}

function resolvedConfig(overrides = {}) {
  const config = readJson("config/starknet-publication-config.local.json");
  config.configurationApprovalStatus = "accepted";
  config.artifactBinding.starknetClassHash = CLASS_HASH;
  config.artifactBinding.compiledClassHash = COMPILED_CLASS_HASH;
  config.l1RecipientBinding.configuredL1RecipientAddress = L1_RECIPIENT;
  config.expectedL2SenderBinding.status = "resolved";
  config.expectedL2SenderBinding.publicationContractAddress = PUBLICATION_CONTRACT;
  config.expectedL2SenderBinding.expectedL1AnchorSenderReference = PUBLICATION_CONTRACT;
  config.accountCallerModel.status = "resolved";
  config.accountCallerModel.accountAddress = PUBLISHER_ACCOUNT;
  config.networkProfiles.local_devnet.usableForTransactionPreparation = true;
  config.networkProfiles.local_devnet.publicationContractDeploymentStatus = "deployed";
  config.networkProfiles.local_devnet.l1AnchorAddressStatus = "configured";
  return Object.assign(config, overrides);
}

function resourceBounds(overrides = {}) {
  return {
    l1_gas: { max_amount: "0x1", max_price_per_unit: "0x2", ...(overrides.l1_gas || {}) },
    l2_gas: { max_amount: "0x3", max_price_per_unit: "0x4", ...(overrides.l2_gas || {}) },
    l1_data_gas: { max_amount: "0x2", max_price_per_unit: "0x1", ...(overrides.l1_data_gas || {}) }
  };
}

function policy(draft, overrides = {}) {
  return {
    allowedModes: ["developer_fixture", "infrastructure_operator"],
    allowedNetworkProfileIds: ["local_devnet"],
    allowedPublicationContractAddresses: [draft.call.contractAddress],
    allowedFeeToken: "STRK",
    maxOverallFee: "0x100",
    maxResourceBounds: resourceBounds({
      l1_gas: { max_amount: "0x10", max_price_per_unit: "0x10" },
      l2_gas: { max_amount: "0x10", max_price_per_unit: "0x10" },
      l1_data_gas: { max_amount: "0x10", max_price_per_unit: "0x10" }
    }),
    allowMainnet: false,
    allowedApprovalSources: ["developer_fixture_approval"],
    requireFreshNonce: true,
    requireFreshFee: true,
    ...overrides
  };
}

function preparationDraft() {
  const result = prepareStarknetFactPublicationTransaction({
    requestId: "starknet-prep-1",
    finalizedAuthorizationPackage: finalizedPackage(),
    publicationConfig: resolvedConfig(),
    readinessManifest: readJson("config/starknet-publication-readiness.json"),
    proofInputHashSliceArgs: readJson("proving/out/cairo_air_adapter_spike/proof_input_hash_slice_verify_args.json"),
    proofInputHashSliceSummary: readJson("proving/out/cairo_air_adapter_spike/summary.json"),
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "audit-starknet-prep-1",
    feeEstimator: createFixtureStarknetTransactionFeeEstimator({
      feeToken: "STRK",
      estimatedFee: "0x20",
      l1Gas: "0x1",
      l1DataGas: "0x2",
      l2Gas: "0x3",
      freshUntil: futureDate()
    }),
    nonceReader: createFixtureStarknetNonceReader("0x7", futureDate())
  }, root);
  assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
  return result.value;
}

function baseSigningParts(overrides = {}) {
  const draft = overrides.draft || preparationDraft();
  const signer = overrides.signer || createFixtureStarknetPublisherSigner({
    privateKey: PRIVATE_KEY,
    accountAddress: PUBLISHER_ACCOUNT
  });
  const identity = {
    publisherId: "fixture-publisher",
    mode: "developer_fixture",
    displayName: "Fixture Publisher",
    expectedSignerPublicKey: signer.describeSigner().publicKey,
    productionSuitable: false
  };
  const accountBinding = {
    accountAddress: PUBLISHER_ACCOUNT,
    networkProfileId: "local_devnet",
    chainId: "SN_LOCAL",
    publicationContractAddress: draft.call.contractAddress,
    entrypoint: "verify_proof_input_hash_slice_and_send_to_l1",
    calldataHash: draft.call.calldataHash
  };
  const policyValue = policy(draft);
  const feeInput = {
    feeToken: "STRK",
    estimatedFee: "0x20",
    freshUntil: futureDate(),
    resourceBounds: resourceBounds(),
    ...(overrides.feeValidation || {})
  };
  const feeResult = validateSigningFeeFreshness({
    draft,
    policy: policyValue,
    feeToken: feeInput.feeToken,
    estimatedFee: feeInput.estimatedFee,
    freshUntil: feeInput.freshUntil,
    resourceBounds: feeInput.resourceBounds
  });
  const presentation = createStarknetPublicationSigningPresentation({
    transactionDraft: draft,
    accountBinding,
    feeValidation: feeResult,
    auditCorrelationId: "audit-starknet-signing"
  });
  const approval = {
    source: "developer_fixture_approval",
    presentationDigest: presentation.digest,
    approved: true,
    approvedAt: now(),
    expiresAt: futureDate(),
    approvalId: "fixture-approval-1"
  };
  return {
    request: {
      requestId: "starknet-signing-1",
      transactionDraft: draft,
      publisherIdentity: identity,
      accountBinding,
      policy: policyValue,
      approval,
      signer,
      nonceReader: createFixtureStarknetNonceReader("0x7", futureDate()),
      feeValidation: feeInput,
      issueTime: now(),
      expiresAt: futureDate(),
      auditCorrelationId: "audit-starknet-signing",
      ...(overrides.request || {})
    },
    draft,
    feeResult
  };
}

function hashInputFor(draft, feeValidation = resourceBounds()) {
  return {
    calls: [{
      contractAddress: draft.call.contractAddress,
      entrypoint: draft.call.entrypoint,
      calldata: [...draft.call.calldata]
    }],
    signerDetails: {
      walletAddress: PUBLISHER_ACCOUNT,
      chainId: "SN_LOCAL",
      cairoVersion: "1",
      version: "0x3",
      nonce: "0x7",
      resourceBounds: feeValidation,
      tip: "0x0",
      paymasterData: [],
      accountDeploymentData: [],
      nonceDataAvailabilityMode: "L1",
      feeDataAvailabilityMode: "L1"
    }
  };
}

async function signedFixture(overrides = {}) {
  const parts = baseSigningParts(overrides);
  const result = await signStarknetFactPublicationTransaction(parts.request);
  assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
  return {
    draft: parts.draft,
    signed: result.value,
    feeResult: validateSigningFeeFreshness({
      draft: parts.draft,
      policy: parts.request.policy,
      feeToken: parts.request.feeValidation.feeToken,
      estimatedFee: parts.request.feeValidation.estimatedFee,
      freshUntil: parts.request.feeValidation.freshUntil,
      resourceBounds: parts.request.feeValidation.resourceBounds
    }),
    hashInput: hashInputFor(parts.draft, parts.request.feeValidation.resourceBounds)
  };
}

function deploymentRecord(overrides = {}) {
  return {
    deploymentId: "deployment-1",
    networkProfileId: "local_devnet",
    chainId: "SN_LOCAL",
    contractAddress: PUBLICATION_CONTRACT,
    classHash: CLASS_HASH,
    compiledClassHash: COMPILED_CLASS_HASH,
    abiSha256: resolvedConfig().artifactBinding.abiSha256,
    deploymentStatus: "configured",
    approved: true,
    ...overrides
  };
}

async function verifiedDeployment(overrides = {}) {
  const request = {
    requestId: "deployment-verification-1",
    publicationConfig: resolvedConfig(overrides.config || {}),
    readinessManifest: readJson("config/starknet-publication-readiness.json"),
    deployment: deploymentRecord(overrides.deployment || {}),
    deploymentReader: overrides.deploymentReader || createFixtureStarknetPublicationDeploymentReader(
      (overrides.deployment && overrides.deployment.classHash) || CLASS_HASH
    ),
    deploymentApproval: {
      approvalId: "deployment-approval-1",
      approved: true,
      source: "testnet_deployment_policy",
      approvedAt: now(),
      expiresAt: futureDate(),
      ...(overrides.deploymentApproval || {})
    },
    issueTime: now(),
    expiresAt: futureDate()
  };
  return verifyExistingStarknetPublicationDeployment(request);
}

function publisherAuthorization(overrides = {}) {
  const defaultPublisherAccount = {
    accountAddress: PUBLISHER_ACCOUNT,
    networkProfileId: "local_devnet",
    approved: true,
    custody: {
      custodyId: "fixture-custody",
      model: "developer_fixture",
      approvedForPublicTestnet: false,
      plaintextKeyInRepository: false,
      commandLineSecretAllowed: false
    }
  };
  const defaultFundingStatus = {
    status: "sufficient",
    feeToken: "STRK",
    checkedAt: now(),
    balance: "0x100",
    requiredMaximumFee: "0x20"
  };
  return {
    publisherAccount: {
      ...defaultPublisherAccount,
      ...(overrides.publisherAccount || {}),
      custody: {
        ...defaultPublisherAccount.custody,
        ...(overrides.publisherAccount?.custody || {})
      }
    },
    fundingStatus: {
      ...defaultFundingStatus,
      ...(overrides.fundingStatus || {})
    },
    approved: true,
    ...overrides
  };
}

async function submissionRequest(overrides = {}) {
  const { signed, draft, feeResult, hashInput } = await signedFixture(overrides.signing || {});
  const deployment = overrides.deploymentResult || await verifiedDeployment();
  assert.equal(deployment.status, "approved", JSON.stringify(deployment.error, null, 2));
  return {
    requestId: "submission-1",
    signedTransaction: overrides.signedTransaction || signed,
    deploymentResult: overrides.deploymentResultValue || deployment.value,
    publisherAuthorization: overrides.publisherAuthorization || publisherAuthorization(),
    submissionApproval: overrides.submissionApproval === null
      ? undefined
      : (overrides.submissionApproval || createStarknetPublicationSubmissionApproval({
        signedTransaction: overrides.signedTransaction || signed,
        source: "fixture_submission_policy",
        expiresAt: futureDate()
      })),
    nonceReader: overrides.nonceReader || createFixtureStarknetNonceReader("0x7", futureDate()),
    feeValidation: overrides.feeValidation || feeResult,
    hashInput: overrides.hashInput || hashInput,
    submitter: overrides.submitter || createFixtureStarknetTransactionSubmitter(),
    submittedTransactionStore: overrides.submittedTransactionStore,
    issueTime: now(),
    expiresAt: overrides.expiresAt || futureDate(),
    auditCorrelationId: "audit-submission-1",
    auditDraftCollector: overrides.auditDraftCollector,
    draft
  };
}

function acceptedReceipt(signed, overrides = {}) {
  return {
    transactionHash: signed.transactionHash,
    finalityStatus: "ACCEPTED_ON_L2",
    executionStatus: "SUCCEEDED",
    blockNumber: 42,
    blockHash: "0xabc",
    events: [{
      fromAddress: signed.binding.publicationContractAddress,
      keys: [starknetHash.getSelectorFromName("ProofInputHashFactVerified")],
      data: [signed.binding.factHigh, signed.binding.factLow]
    }],
    messagesSent: [{
      fromAddress: signed.binding.publicationContractAddress,
      toAddress: signed.binding.l1Recipient,
      payload: [signed.binding.factHigh, signed.binding.factLow],
      messageHash: "0xfeed"
    }],
    ...overrides
  };
}

describe("Starknet fact-publication submission and receipt boundary", function () {
  this.timeout(240_000);

  it("keeps the default repository config blocked before submission", function () {
    const config = readJson("config/starknet-publication-config.local.json");
    const result = validateStarknetPublicationPreflight(config);
    assert.equal(result.valid, false);
    assert.match(result.errors.join(" | "), /configuration approval missing|accepted deployment address missing/);
  });

  it("verifies an existing deployment with exact class, compiled class, ABI, network, and L1 recipient bindings", async function () {
    const result = await verifiedDeployment();
    assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
    assert.equal(result.value.outcome, "existing_deployment_verified");
    assert.equal(result.value.binding.contractAddress, PUBLICATION_CONTRACT.toLowerCase());
    assert.equal(result.value.binding.l1Recipient, L1_RECIPIENT.toLowerCase());
  });

  it("rejects deployment class, compiled class, ABI, network, address, approval, and RPC mismatches", async function () {
    const cases = [
      { deployment: { classHash: "0x999" }, outcome: "class_hash_mismatch" },
      { deployment: { compiledClassHash: "0x999" }, outcome: "compiled_class_hash_mismatch" },
      { deployment: { abiSha256: "bad" }, outcome: "abi_hash_mismatch" },
      { deployment: { networkProfileId: "starknet_sepolia" }, outcome: "malformed" },
      { deployment: { contractAddress: "0x999" }, outcome: "deployment_address_mismatch" },
      { deploymentApproval: { approved: false }, outcome: "approval_missing" },
      { deploymentReader: createUnavailableStarknetPublicationDeploymentReader(), outcome: "rpc_unavailable" }
    ];
    for (const item of cases) {
      const result = await verifiedDeployment(item);
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, item.outcome);
    }
  });

  it("submits only an exact approved signed publication transaction through a fixture submitter", async function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const store = createInMemoryStarknetSubmittedTransactionStore();
    const request = await submissionRequest({ auditDraftCollector, submittedTransactionStore: store });
    const result = await submitStarknetFactPublicationTransaction(request);
    assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
    assert.equal(result.value.outcome, "transaction_submitted");
    assert.equal(result.value.transactionSubmitted, true);
    assert.equal(result.value.transactionAcceptedOnL2, false);
    assert.equal(result.value.l1MessageAvailabilityConfirmed, false);
    assert.equal(result.value.l1MessageConsumed, false);
    assert.equal(result.value.baseFactMirrored, false);
    assert.equal(result.value.nullifierConsumed, false);
    assert.equal(store.hasTransaction(request.signedTransaction.transactionHash), true);
    assert.equal(auditDraftCollector.count(), 1);
  });

  it("blocks missing approval, unapproved publisher, insufficient funding, stale nonce, fee change, expired artifact, duplicate submission, and RPC unavailable", async function () {
    const base = await submissionRequest();
    const cases = [
      { submissionApproval: null, outcome: "approval_missing" },
      { publisherAuthorization: publisherAuthorization({ approved: false }), outcome: "submission_blocked" },
      { publisherAuthorization: publisherAuthorization({ publisherAccount: { approved: false } }), outcome: "submission_blocked" },
      { publisherAuthorization: publisherAuthorization({ fundingStatus: { status: "insufficient" } }), outcome: "submission_blocked" },
      { nonceReader: createFixtureStarknetNonceReader("0x8", futureDate()), outcome: "nonce_changed" },
      { feeValidation: { ...base.feeValidation, status: "fee_stale" }, outcome: "fee_changed" },
      { signedTransaction: { ...base.signedTransaction, expiresAt: pastDate() }, outcome: "malformed" },
      {
        submittedTransactionStore: (() => {
          const store = createInMemoryStarknetSubmittedTransactionStore();
          store.addTransaction(base.signedTransaction.transactionHash);
          return store;
        })(),
        outcome: "duplicate_submission"
      },
      { submitter: createUnavailableStarknetTransactionSubmitter(), approvedButFails: true, outcome: "rpc_unavailable" }
    ];
    for (const item of cases) {
      const { outcome, approvedButFails, ...overrides } = item;
      const request = {
        ...base,
        ...overrides,
        submissionApproval: item.submissionApproval === null
          ? undefined
          : (item.submissionApproval || base.submissionApproval)
      };
      const result = await submitStarknetFactPublicationTransaction(request);
      assert.equal(result.status, "denied");
      assert.equal(result.error.details.outcome, outcome);
    }
  });

  it("detects transaction hash/signature binding mutation", async function () {
    const request = await submissionRequest();
    const mutatedHashInput = {
      ...request.hashInput,
      signerDetails: {
        ...request.hashInput.signerDetails,
        tip: "0x1"
      }
    };
    const result = await submitStarknetFactPublicationTransaction({
      ...request,
      hashInput: mutatedHashInput
    });
    assert.equal(result.status, "denied");
    assert.equal(result.error.details.outcome, "signature_invalid");
  });

  it("verifies accepted-on-L2 receipts, the expected event, and the exact two-felt L2-to-L1 message", async function () {
    const submission = await submitStarknetFactPublicationTransaction(await submissionRequest());
    assert.equal(submission.status, "approved");
    const signed = (await submissionRequest()).signedTransaction;
    const receipt = acceptedReceipt(signed, { transactionHash: submission.value.transactionHash });
    const event = verifyStarknetFactVerificationEvent(receipt, signed);
    const message = verifyStarknetL2ToL1MessageEvidence(receipt, signed);
    assert.equal(event.status, "observed");
    assert.equal(message.status, "observed");

    const monitored = await monitorStarknetFactPublicationReceipt({
      requestId: "monitor-1",
      submission: submission.value,
      signedTransaction: signed,
      receiptReader: createFixtureStarknetReceiptReader(receipt),
      maxAttempts: 1,
      timeoutMs: 1000,
      auditCorrelationId: "audit-monitor-1"
    });
    assert.equal(monitored.status, "approved", JSON.stringify(monitored.error, null, 2));
    assert.equal(monitored.value.transactionAcceptedOnL2, true);
    assert.equal(monitored.value.verificationEventObserved, true);
    assert.equal(monitored.value.l2ToL1MessageObserved, true);
    assert.equal(monitored.value.l1MessageAvailabilityConfirmed, false);
    assert.equal(monitored.value.l1MessageConsumed, false);
    assert.equal(monitored.value.baseFactMirrored, false);
    assert.equal(monitored.value.nullifierConsumed, false);
  });

  it("rejects wrong event contract, wrong event payload, wrong recipient, high/low reversal, missing message, rejected, reverted, and timeout receipts", async function () {
    const request = await submissionRequest();
    const submission = await submitStarknetFactPublicationTransaction(request);
    assert.equal(submission.status, "approved");
    const signed = request.signedTransaction;
    const wrongContract = verifyStarknetFactVerificationEvent(
      acceptedReceipt(signed, { events: [{ fromAddress: "0x999", keys: [starknetHash.getSelectorFromName("ProofInputHashFactVerified")], data: [FACT_HIGH, FACT_LOW] }] }),
      signed
    );
    assert.equal(wrongContract.status, "missing");
    const wrongPayload = verifyStarknetFactVerificationEvent(
      acceptedReceipt(signed, { events: [{ fromAddress: PUBLICATION_CONTRACT, keys: [starknetHash.getSelectorFromName("ProofInputHashFactVerified")], data: [FACT_LOW, FACT_HIGH] }] }),
      signed
    );
    assert.equal(wrongPayload.status, "mismatch");
    const wrongRecipient = verifyStarknetL2ToL1MessageEvidence(
      acceptedReceipt(signed, { messagesSent: [{ fromAddress: PUBLICATION_CONTRACT, toAddress: "0x999", payload: [FACT_HIGH, FACT_LOW] }] }),
      signed
    );
    assert.equal(wrongRecipient.status, "missing");
    const reversed = verifyStarknetL2ToL1MessageEvidence(
      acceptedReceipt(signed, { messagesSent: [{ fromAddress: PUBLICATION_CONTRACT, toAddress: L1_RECIPIENT, payload: [FACT_LOW, FACT_HIGH] }] }),
      signed
    );
    assert.equal(reversed.status, "mismatch");
    const missing = verifyStarknetL2ToL1MessageEvidence(
      acceptedReceipt(signed, { messagesSent: [] }),
      signed
    );
    assert.equal(missing.status, "missing");

    for (const receipt of [
      acceptedReceipt(signed, { finalityStatus: "REJECTED", executionStatus: "REJECTED" }),
      acceptedReceipt(signed, { finalityStatus: "ACCEPTED_ON_L2", executionStatus: "REVERTED" })
    ]) {
      const result = await monitorStarknetFactPublicationReceipt({
        requestId: "monitor-blocked",
        submission: submission.value,
        signedTransaction: signed,
        receiptReader: createFixtureStarknetReceiptReader(receipt),
        maxAttempts: 1,
        timeoutMs: 1000
      });
      assert.equal(result.status, "denied");
    }

    const timeout = await monitorStarknetFactPublicationReceipt({
      requestId: "monitor-timeout",
      submission: submission.value,
      signedTransaction: signed,
      receiptReader: createFixtureStarknetReceiptReader({
        transactionHash: signed.transactionHash,
        finalityStatus: "NOT_RECEIVED",
        events: [],
        messagesSent: []
      }),
      maxAttempts: 1,
      timeoutMs: 1
    });
    assert.equal(timeout.status, "denied");
    assert.equal(timeout.error.details.outcome, "submission_timeout");
  });

  it("does not leak secrets, signatures, proof calldata, or witness material into audit drafts", async function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const result = await submitStarknetFactPublicationTransaction(await submissionRequest({ auditDraftCollector }));
    assert.equal(result.status, "approved");
    const serialized = JSON.stringify(auditDraftCollector.getAll());
    assert.doesNotMatch(serialized, /privateKey|seedPhrase|mnemonic|phil_secret|nullifierSeed|witness/i);
    assert.doesNotMatch(serialized, /StarkProofMirror|ProofInputHashSliceClaim/);
    assert.doesNotMatch(serialized, /signatureArtifact|signature/i);
  });

  it("exposes bounded request aliases without granting arbitrary RPC authority", async function () {
    const request = await submissionRequest();
    const submitted = await requestStarknetFactPublicationSubmission(request);
    assert.equal(submitted.status, "approved");
    const monitored = await requestStarknetFactPublicationReceiptMonitoring({
      requestId: "alias-monitor",
      submission: submitted.value,
      signedTransaction: request.signedTransaction,
      receiptReader: createFixtureStarknetReceiptReader(acceptedReceipt(request.signedTransaction)),
      maxAttempts: 1,
      timeoutMs: 1000
    });
    assert.equal(monitored.status, "approved");
  });

  it("runs submission diagnostics without live submission by default", function () {
    const result = spawnSync("npm", [
      "run",
      "diagnose:starknet-fact-publication-submission",
      "--",
      "--json"
    ], { cwd: root, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /"live_submission_performed": false/);
  });
});
