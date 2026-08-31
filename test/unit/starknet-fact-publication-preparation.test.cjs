const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { describe, it } = require("mocha");

const {
  createFixtureStarknetNonceReader,
  createFixtureStarknetTransactionFeeEstimator,
  createInMemoryAuditDraftCollector,
  createInMemoryStarknetFactPublicationTransactionDraftStore,
  deriveStarknetSelector,
  encodeStarknetFactPublicationCalldata,
  prepareStarknetFactPublicationTransaction,
  validateStarknetFactPublicationTransactionDraft
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

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function now() {
  return new Date().toISOString();
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

function request(overrides = {}) {
  return {
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
      estimatedFee: "0x100",
      l1Gas: "0x1",
      l1DataGas: "0x2",
      l2Gas: "0x3",
      freshUntil: futureDate()
    }),
    nonceReader: createFixtureStarknetNonceReader("0x7", futureDate()),
    ...overrides
  };
}

describe("Starknet fact-publication transaction preparation boundary", function () {
  it("rejects a secret-bearing proof package before publication preparation", function () {
    const unsafe = finalizedPackage();
    unsafe.proofArtifact = {
      ...unsafe.proofArtifact,
      nonSecretProofArtifact: false,
      containsWitnessOpenings: true,
      safeForExternalVerifierTransmission: false
    };
    const result = prepareStarknetFactPublicationTransaction(request({
      finalizedAuthorizationPackage: unsafe
    }), root);
    assert.equal(result.status, "denied");
    assert.match(result.error.details.errors.join("\n"), /witness-hiding proof reference/);
  });

  it("rejects the draft local config because deployment address and account model are unresolved", function () {
    const result = prepareStarknetFactPublicationTransaction(request({
      publicationConfig: readJson("config/starknet-publication-config.local.json")
    }), root);
    assert.equal(result.status, "denied");
    assert.equal(result.error.details.outcome, "deployment_address_missing");
  });

  it("prepares an unsigned, unsubmitted draft from exact resolved fixture config", function () {
    const store = createInMemoryStarknetFactPublicationTransactionDraftStore();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const result = prepareStarknetFactPublicationTransaction(request({
      draftStore: store,
      auditDraftCollector
    }), root);
    assert.equal(result.status, "approved", JSON.stringify(result.error, null, 2));
    const draft = result.value;
    assert.equal(validateStarknetFactPublicationTransactionDraft(draft).valid, true);
    assert.equal(draft.transactionPrepared, true);
    assert.equal(draft.transactionSigned, false);
    assert.equal(draft.transactionSubmitted, false);
    assert.equal(draft.l2ToL1MessageEmitted, false);
    assert.equal(draft.l1MessageConsumed, false);
    assert.equal(draft.chainStateMutated, false);
    assert.equal(draft.applicationExecutionAllowed, false);
    assert.deepEqual(draft.unsignedInvokeTransaction.signature, []);
    assert.equal(store.count(), 1);
    assert.equal(auditDraftCollector.count(), 1);
  });

  it("uses the actual Starknet selector and Rust-generated Cairo argument fixture", function () {
    const proofArgs = readJson("proving/out/cairo_air_adapter_spike/proof_input_hash_slice_verify_args.json");
    const calldata = encodeStarknetFactPublicationCalldata(L1_RECIPIENT, proofArgs);
    assert.equal(calldata[0], L1_RECIPIENT.toLowerCase());
    assert.deepEqual(calldata.slice(1), proofArgs.map((arg) => arg.toLowerCase()));
    const result = prepareStarknetFactPublicationTransaction(request(), root);
    assert.equal(result.status, "approved");
    assert.equal(
      result.value.call.selector,
      deriveStarknetSelector("verify_proof_input_hash_slice_and_send_to_l1")
    );
    assert.deepEqual(result.value.call.calldata, calldata);
    assert.match(result.value.call.calldataHash, /^[0-9a-f]{64}$/);
  });

  it("changes calldata hash when the recipient changes", function () {
    const first = prepareStarknetFactPublicationTransaction(request(), root);
    const second = prepareStarknetFactPublicationTransaction(request({
      l1Recipient: "0x4c315f54525553545f414e43484f53"
    }), root);
    assert.equal(first.status, "approved");
    assert.equal(second.status, "approved");
    assert.notEqual(first.value.call.calldataHash, second.value.call.calldataHash);
  });

  it("rejects artifact, ABI, entrypoint, selector, proof, and claim mismatches", function () {
    for (const mutate of [
      (input) => { input.publicationConfig.artifactBinding.compiledClassSha256 = "bad"; },
      (input) => { input.publicationConfig.artifactBinding.abiSha256 = "bad"; },
      (input) => { input.publicationConfig.artifactBinding.entrypoint = "wrong"; },
      (input) => { input.publicationConfig.artifactBinding.entrypointSelector = "0x1234"; },
      (input) => { input.finalizedAuthorizationPackage = finalizedPackage({
        actionUnlockAuthorization: {
          ...finalizedPackage().actionUnlockAuthorization,
          proofInputHash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      }); },
      (input) => { input.proofInputHashSliceSummary.expectedFactPayload = [FACT_LOW, FACT_HIGH]; },
      (input) => { input.proofInputHashSliceArgs = [...input.proofInputHashSliceArgs, "0x1"]; }
    ]) {
      const input = request();
      mutate(input);
      const result = prepareStarknetFactPublicationTransaction(input, root);
      assert.equal(result.status, "denied");
    }
  });

  it("rejects invalid L1 recipient, missing account, wrong network, and felt range violations", function () {
    for (const mutate of [
      (input) => { input.l1Recipient = "0x0"; },
      (input) => { input.publicationConfig.accountCallerModel.accountAddress = undefined; },
      (input) => { input.publicationConfig.networkProfiles.local_devnet.enabled = false; },
      (input) => { input.proofInputHashSliceArgs = ["0x1" + "0".repeat(64)]; }
    ]) {
      const input = request();
      mutate(input);
      const result = prepareStarknetFactPublicationTransaction(input, root);
      assert.equal(result.status, "denied");
    }
  });

  it("keeps nonce and fee limitations explicit", function () {
    const result = prepareStarknetFactPublicationTransaction(request({
      feeEstimator: undefined,
      nonceReader: undefined
    }), root);
    assert.equal(result.status, "approved");
    assert.equal(result.value.unsignedInvokeTransaction.nonce.status, "unresolved");
    assert.equal(result.value.unsignedInvokeTransaction.fee.status, "unresolved");
    assert.equal(result.value.unsignedInvokeTransaction.signable, false);
    assert.equal(result.value.unsignedInvokeTransaction.submittable, false);
  });

  it("protects the optional in-memory draft store from duplicates and mutation", function () {
    const store = createInMemoryStarknetFactPublicationTransactionDraftStore({ maxDraftCount: 1 });
    const first = prepareStarknetFactPublicationTransaction(request({ draftStore: store }), root);
    const duplicate = store.addDraft(first.value);
    assert.equal(duplicate.status, "rejected_duplicate");
    assert.throws(() => {
      store.getAll()[0].call.calldata.push("0x1");
    }, /object is not extensible|read only|Cannot add property/);
  });

  it("does not include full proof calldata in audit details", function () {
    const result = prepareStarknetFactPublicationTransaction(request({
      auditDraftCollector: createInMemoryAuditDraftCollector()
    }), root);
    assert.equal(result.status, "approved");
    const details = JSON.stringify(result.value.auditEventDraft.redactedDetails);
    assert.doesNotMatch(details, /59bf4006/);
    assert.match(details, /calldataHash/);
  });

  it("runs text and JSON diagnostics without signing or submitting", function () {
    const json = spawnSync(
      "npm",
      ["run", "diagnose:starknet-fact-publication-preparation", "--", "--fixture-resolved", "--json"],
      { cwd: root, encoding: "utf8" }
    );
    assert.equal(json.status, 0, json.stderr);
    const parsed = JSON.parse(json.stdout.slice(json.stdout.indexOf("{")));
    assert.equal(parsed.transactionPrepared, true);
    assert.equal(parsed.transactionSigned, false);
    assert.equal(parsed.transactionSubmitted, false);
    assert.equal(parsed.messageEmitted, false);
    assert.equal(parsed.l1AnchorCalled, false);
    assert.equal(parsed.baseCalled, false);

    const text = spawnSync(
      "npm",
      ["run", "diagnose:starknet-fact-publication-preparation", "--", "--fixture-resolved"],
      { cwd: root, encoding: "utf8" }
    );
    assert.equal(text.status, 0, text.stderr);
    assert.match(text.stdout, /PhilCore Alpha 0 Starknet fact-publication preparation diagnostic/);
    assert.match(text.stdout, /transactionSigned: false/);
    assert.match(text.stdout, /messageEmitted: false/);
  });
});
