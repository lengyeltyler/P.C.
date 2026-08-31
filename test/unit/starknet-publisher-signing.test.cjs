const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { describe, it } = require("mocha");
const { hash: starknetHash, transaction: starknetTransaction } = require("starknet");

const {
  computeUnsignedStarknetInvokeV3Hash,
  createFixtureStarknetNonceReader,
  createFixtureStarknetPublisherSigner,
  createFixtureStarknetTransactionFeeEstimator,
  createInMemoryAuditDraftCollector,
  createInMemorySignedStarknetPublicationTransactionStore,
  createStarknetPublicationSigningPresentation,
  prepareStarknetFactPublicationTransaction,
  requestStarknetFactPublicationTransactionSigning,
  signStarknetFactPublicationTransaction,
  starknetChainIdToFelt,
  validateSigningFeeFreshness
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

function futureDate(ms = 60_000) {
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

function resolvedConfig() {
  const config = readJson("config/starknet-publication-config.local.json");
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
  return config;
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
    productionSuitable: false,
    ...(overrides.publisherIdentity || {})
  };
  const accountBinding = {
    accountAddress: PUBLISHER_ACCOUNT,
    networkProfileId: "local_devnet",
    chainId: "SN_LOCAL",
    publicationContractAddress: draft.call.contractAddress,
    entrypoint: "verify_proof_input_hash_slice_and_send_to_l1",
    calldataHash: draft.call.calldataHash,
    ...(overrides.accountBinding || {})
  };
  const policyValue = policy(draft, overrides.policy || {});
  const feeValidation = {
    feeToken: "STRK",
    estimatedFee: "0x20",
    freshUntil: futureDate(),
    resourceBounds: resourceBounds(),
    ...(overrides.feeValidation || {})
  };
  const feeResult = validateSigningFeeFreshness({
    draft,
    policy: policyValue,
    feeToken: feeValidation.feeToken,
    estimatedFee: feeValidation.estimatedFee,
    freshUntil: feeValidation.freshUntil,
    resourceBounds: feeValidation.resourceBounds
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
    approvalId: "fixture-approval-1",
    ...(overrides.approval || {})
  };
  return {
    requestId: "starknet-signing-1",
    transactionDraft: draft,
    publisherIdentity: identity,
    accountBinding,
    policy: policyValue,
    approval,
    signer,
    nonceReader: overrides.nonceReader || createFixtureStarknetNonceReader("0x7", futureDate()),
    feeValidation,
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "audit-starknet-signing",
    ...(overrides.request || {})
  };
}

describe("Starknet publisher authorization and signing boundary", function () {
  it("creates a signed but unsubmitted fixture artifact", async function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const signedTransactionStore = createInMemorySignedStarknetPublicationTransactionStore();
    const result = await signStarknetFactPublicationTransaction(baseSigningParts({
      request: { auditDraftCollector, signedTransactionStore }
    }));
    assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
    const artifact = result.value;
    assert.equal(artifact.transactionSigned, true);
    assert.equal(artifact.transactionSubmitted, false);
    assert.equal(artifact.l2ToL1MessageEmitted, false);
    assert.equal(artifact.l1MessageConsumed, false);
    assert.equal(artifact.chainStateMutated, false);
    assert.equal(artifact.submissionAllowedByApplications, false);
    assert.equal(artifact.signatureArtifact.privateKeyExposed, false);
    assert.match(artifact.signatureArtifact.signature.r, /^0x[0-9a-f]+$/);
    assert.match(artifact.signatureArtifact.signature.s, /^0x[0-9a-f]+$/);
    assert.equal(signedTransactionStore.count(), 1);
    assert.equal(auditDraftCollector.count(), 1);
  });

  it("computes the Starknet.js INVOKE v3 hash for the exact account execute calldata", function () {
    const draft = preparationDraft();
    const request = baseSigningParts({ draft });
    const calls = [{
      contractAddress: draft.call.contractAddress,
      entrypoint: draft.call.entrypoint,
      calldata: [...draft.call.calldata]
    }];
    const signerDetails = {
      walletAddress: PUBLISHER_ACCOUNT,
      chainId: "SN_LOCAL",
      cairoVersion: "1",
      version: "0x3",
      nonce: "0x7",
      resourceBounds: request.feeValidation.resourceBounds,
      tip: "0x0",
      paymasterData: [],
      accountDeploymentData: [],
      nonceDataAvailabilityMode: "L1",
      feeDataAvailabilityMode: "L1"
    };
    const helperHash = computeUnsignedStarknetInvokeV3Hash({ calls, signerDetails });
    const directHash = starknetHash.calculateInvokeTransactionHash({
      senderAddress: PUBLISHER_ACCOUNT,
      version: "0x3",
      compiledCalldata: starknetTransaction.getExecuteCalldata(calls, "1"),
      chainId: starknetChainIdToFelt("SN_LOCAL"),
      nonce: "0x7",
      accountDeploymentData: [],
      nonceDataAvailabilityMode: 0,
      feeDataAvailabilityMode: 0,
      resourceBounds: {
        l1_gas: { max_amount: 1n, max_price_per_unit: 2n },
        l2_gas: { max_amount: 3n, max_price_per_unit: 4n },
        l1_data_gas: { max_amount: 2n, max_price_per_unit: 1n }
      },
      tip: "0x0",
      paymasterData: []
    });
    assert.equal(helperHash, directHash);
  });

  it("rejects unauthorized publisher policy and wrong account/network/contract bindings", async function () {
    for (const overrides of [
      { publisherIdentity: { mode: "unsupported" }, policy: { allowedModes: ["developer_fixture"] } },
      { accountBinding: { accountAddress: "0x999" } },
      { accountBinding: { networkProfileId: "starknet_sepolia" } },
      { accountBinding: { publicationContractAddress: "0x999" } }
    ]) {
      const result = await signStarknetFactPublicationTransaction(baseSigningParts(overrides));
      assert.equal(result.status, "denied");
    }
  });

  it("rejects stale draft, stale nonce, unresolved nonce, and unavailable nonce reader", async function () {
    const staleDraft = {
      ...preparationDraft(),
      expiresAt: pastDate()
    };
    const staleDraftResult = await signStarknetFactPublicationTransaction(baseSigningParts({
      draft: staleDraft
    }));
    assert.equal(staleDraftResult.status, "denied");

    const staleNonceResult = await signStarknetFactPublicationTransaction(baseSigningParts({
      nonceReader: createFixtureStarknetNonceReader("0x8", futureDate())
    }));
    assert.equal(staleNonceResult.status, "denied");
    assert.equal(staleNonceResult.error.details.outcome, "nonce_stale");

    const unresolvedDraft = {
      ...preparationDraft(),
      unsignedInvokeTransaction: {
        ...preparationDraft().unsignedInvokeTransaction,
        nonce: {
          status: "unresolved",
          source: "none",
          reservationCreated: false,
          revalidateBeforeSigning: true
        }
      }
    };
    const unresolvedResult = await signStarknetFactPublicationTransaction(baseSigningParts({
      draft: unresolvedDraft
    }));
    assert.equal(unresolvedResult.status, "denied");

    const unavailableResult = await signStarknetFactPublicationTransaction(baseSigningParts({
      nonceReader: { readNonce: () => ({ status: "failed", source: "none", error: "unavailable" }) }
    }));
    assert.equal(unavailableResult.status, "denied");
  });

  it("rejects stale fee, fee limit excess, token mismatch, and widened resource bounds", async function () {
    for (const overrides of [
      { feeValidation: { freshUntil: pastDate() } },
      { feeValidation: { resourceBounds: resourceBounds({ l1_gas: { max_amount: "0x100" } }) } },
      { feeValidation: { feeToken: "ETH" } },
      { policy: { maxOverallFee: "0x1" } }
    ]) {
      const result = await signStarknetFactPublicationTransaction(baseSigningParts(overrides));
      assert.equal(result.status, "denied");
    }
  });

  it("rejects presentation digest mismatch and transaction mutation", async function () {
    const badDigest = await signStarknetFactPublicationTransaction(baseSigningParts({
      approval: { presentationDigest: "bad" }
    }));
    assert.equal(badDigest.status, "denied");
    assert.equal(badDigest.error.details.outcome, "presentation_digest_mismatch");

    const draft = preparationDraft();
    const mutatedDraft = {
      ...draft,
      call: {
        ...draft.call,
        calldataHash: "mutated"
      }
    };
    const mutationResult = await signStarknetFactPublicationTransaction(baseSigningParts({
      draft: mutatedDraft
    }));
    assert.equal(mutationResult.status, "denied");
  });

  it("rejects signer unavailable, malformed signature, wrong hash, and wrong signer", async function () {
    const unavailableSigner = createFixtureStarknetPublisherSigner({
      privateKey: PRIVATE_KEY,
      accountAddress: PUBLISHER_ACCOUNT
    });
    unavailableSigner.invalidateSigningSession();
    const unavailable = await signStarknetFactPublicationTransaction(baseSigningParts({
      signer: unavailableSigner
    }));
    assert.equal(unavailable.status, "denied");

    const malformedSigner = {
      describeSigner: () => createFixtureStarknetPublisherSigner({
        privateKey: PRIVATE_KEY,
        accountAddress: PUBLISHER_ACCOUNT
      }).describeSigner(),
      checkAvailability: () => ({ available: true }),
      getAccountReference: () => ({ accountAddress: PUBLISHER_ACCOUNT }),
      signPublicationTransaction: async (request) => ({
        status: "signed",
        transactionHash: request.transactionHash,
        signature: { r: "not-a-felt", s: "0x2", felts: ["not-a-felt", "0x2"] },
        signerDescriptor: createFixtureStarknetPublisherSigner({
          privateKey: PRIVATE_KEY,
          accountAddress: PUBLISHER_ACCOUNT
        }).describeSigner()
      }),
      invalidateSigningSession: () => {}
    };
    const malformed = await signStarknetFactPublicationTransaction(baseSigningParts({
      signer: malformedSigner
    }));
    assert.equal(malformed.status, "denied");
    assert.equal(malformed.error.details.outcome, "malformed_signature");

    const wrongHashSigner = {
      ...malformedSigner,
      signPublicationTransaction: async () => ({
        status: "signed",
        transactionHash: "0x123",
        signature: { r: "0x1", s: "0x2", felts: ["0x1", "0x2"] },
        signerDescriptor: malformedSigner.describeSigner()
      })
    };
    const wrongHash = await signStarknetFactPublicationTransaction(baseSigningParts({
      signer: wrongHashSigner
    }));
    assert.equal(wrongHash.status, "denied");
    assert.equal(wrongHash.error.details.outcome, "transaction_hash_mismatch");

    const wrongSigner = createFixtureStarknetPublisherSigner({
      privateKey: "0x2",
      accountAddress: PUBLISHER_ACCOUNT
    });
    const expectedSigner = createFixtureStarknetPublisherSigner({
      privateKey: PRIVATE_KEY,
      accountAddress: PUBLISHER_ACCOUNT
    });
    const wrong = await signStarknetFactPublicationTransaction(baseSigningParts({
      signer: wrongSigner,
      publisherIdentity: {
        expectedSignerPublicKey: expectedSigner.describeSigner().publicKey
      }
    }));
    assert.equal(wrong.status, "denied");
    assert.equal(wrong.error.details.outcome, "wrong_signer");
  });

  it("fixture signer cannot sign mainnet profiles", async function () {
    const result = await signStarknetFactPublicationTransaction(baseSigningParts({
      accountBinding: { networkProfileId: "starknet_mainnet", chainId: "SN_MAIN" },
      policy: {
        allowedNetworkProfileIds: ["starknet_mainnet"],
        allowMainnet: true
      },
      signer: createFixtureStarknetPublisherSigner({
        privateKey: PRIVATE_KEY,
        accountAddress: PUBLISHER_ACCOUNT,
        allowedNetworkProfileIds: ["starknet_mainnet"]
      })
    }));
    assert.equal(result.status, "denied");
  });

  it("signed artifact store is bounded, duplicate-protected, and immutable to callers", async function () {
    const store = createInMemorySignedStarknetPublicationTransactionStore({ maxArtifactCount: 1 });
    const first = await signStarknetFactPublicationTransaction(baseSigningParts({
      request: { signedTransactionStore: store }
    }));
    assert.equal(first.status, "approved");
    assert.equal(store.count(), 1);
    const duplicate = store.addArtifact(first.value);
    assert.equal(duplicate.status, "rejected_duplicate");
    const stored = store.getById(first.value.signedStarknetFactPublicationTransactionId);
    assert.ok(stored);
    stored.transactionSubmitted = true;
    assert.equal(stored.transactionSubmitted, false);
    store.clear();
    assert.equal(store.count(), 0);
  });

  it("does not leak secrets or proof calldata in audit details", async function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const result = await signStarknetFactPublicationTransaction(baseSigningParts({
      request: { auditDraftCollector }
    }));
    assert.equal(result.status, "approved");
    const audit = auditDraftCollector.getAll()[0];
    const serialized = JSON.stringify(audit);
    assert.doesNotMatch(serialized, /privateKey|seedPhrase|mnemonic|phil_secret|nullifierSeed/i);
    assert.doesNotMatch(serialized, /StarkProofMirror|ProofInputHashSliceClaim/);
  });

  it("runtime facade alias signs the same bounded artifact", async function () {
    const result = await requestStarknetFactPublicationTransactionSigning(baseSigningParts());
    assert.equal(result.status, "approved");
    assert.equal(result.value.transactionSigned, true);
    assert.equal(result.value.transactionSubmitted, false);
  });

  it("runs signing text and JSON diagnostics without submitting", function () {
    const json = spawnSync("npm", [
      "run",
      "diagnose:starknet-fact-publication-signing",
      "--",
      "--fixture-resolved",
      "--json"
    ], { cwd: root, encoding: "utf8" });
    assert.equal(json.status, 0, json.stderr);
    assert.match(json.stdout, /"transactionSigned": true/);
    assert.match(json.stdout, /"transactionSubmitted": false/);

    const text = spawnSync("npm", [
      "run",
      "diagnose:starknet-fact-publication-signing",
      "--",
      "--fixture-resolved"
    ], { cwd: root, encoding: "utf8" });
    assert.equal(text.status, 0, text.stderr);
    assert.match(text.stdout, /transactionSigned: true/);
    assert.match(text.stdout, /chainStateMutated: false/);
  });
});
