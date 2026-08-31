require("tsx/cjs");

const assert = require("node:assert/strict");
const {
  Wallet,
  keccak256,
  toUtf8Bytes
} = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID,
  computeLocalProofGatedRuntimeAuthorizationDigest,
  createLocalProofGatedFirstUserOperationProposal,
  createLocalProofGatedSigningRequestFromUnsignedArtifact,
  createLocalProofGatedUnsignedPreparationArtifact,
  validateLocalProofGatedSigningAuthorization,
  validateLocalProofGatedUnsignedPreparationArtifact
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const H = (value) => keccak256(toUtf8Bytes(value));
const IDENTITY_ID = "identity_aaaaaaaaaaaa_00000000";
const OWNER = Wallet.createRandom().address;
const ACCOUNT = "0x1000000000000000000000000000000000000001";
const FACTORY = "0x2000000000000000000000000000000000000002";
const TARGET = "0x3000000000000000000000000000000000000003";
const OWNER_COMMITMENT = H("owner-commitment");
const VALIDATOR_KEY_ID = H("validator-key");
const VALIDATOR_KEY_REFERENCE = "validator_key_aaaaaaaaaaaaaaaa";

function fixture() {
  const nowSeconds = 2_000_000_000;
  const expiry = String(nowSeconds + 300);
  const actionId = H("canonical-action");
  const proofInputHash = H("proof-input");
  const proofArtifactDigest = H("proof-artifact");
  const presentationDigest = H("approval");
  const identityReference = H("identity-reference");
  const publicNullifier = H("public-nullifier");
  const sessionId = "session_o21_1";
  const auditCorrelationId = "audit_o21_1";
  const authorizationDigest = computeLocalProofGatedRuntimeAuthorizationDigest({
    identityReference,
    ownerCommitment: OWNER_COMMITMENT,
    actionId,
    canonicalActionDigest: actionId,
    proofInputHash,
    proofArtifactDigest,
    nullifier: publicNullifier,
    approvalPresentationDigest: presentationDigest,
    targetAddress: TARGET,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    sessionId,
    auditCorrelationId,
    expiry
  });
  const proposal = createLocalProofGatedFirstUserOperationProposal({
    sender: ACCOUNT,
    factoryAddress: FACTORY,
    ownerAddress: OWNER,
    ownerCommitment: OWNER_COMMITMENT,
    validatorKeyId: VALIDATOR_KEY_ID,
    accountSalt: "0",
    actionId,
    authorizationDigest,
    expiry,
    nonce: "0",
    verificationGasLimit: "1000000",
    callGasLimit: "250000",
    preVerificationGas: "150000",
    maxFeePerGas: "2000000000",
    maxPriorityFeePerGas: "1000000000",
    nowSeconds
  });
  const approvedAt = new Date((nowSeconds - 5) * 1000).toISOString();
  const generatedAt = new Date((nowSeconds - 3) * 1000).toISOString();
  const verifiedAt = new Date((nowSeconds - 2) * 1000).toISOString();
  const preparedAt = new Date((nowSeconds - 1) * 1000).toISOString();
  const request = {
    identityId: IDENTITY_ID,
    identityReference,
    ownerCommitment: OWNER_COMMITMENT,
    validatorAddress: OWNER,
    validatorKeyReferenceId: VALIDATOR_KEY_REFERENCE,
    validatorKeyId: VALIDATOR_KEY_ID,
    identityUnlocked: true,
    expectedIdentityId: IDENTITY_ID,
    expectedOwnerCommitment: OWNER_COMMITMENT,
    expectedValidatorAddress: OWNER,
    expectedValidatorKeyReferenceId: VALIDATOR_KEY_REFERENCE,
    expectedValidatorKeyId: VALIDATOR_KEY_ID,
    smartAccountAddress: ACCOUNT,
    factoryAddress: FACTORY,
    targetAddress: TARGET,
    expectedTargetAddress: TARGET,
    actionId,
    canonicalActionDigest: actionId,
    runtimeAuthorizationDigest: authorizationDigest,
    expiry,
    proof: {
      status: "generated",
      proofType: "stwo-unlock-keccak-v1",
      proofArtifactDigest,
      proofInputHash,
      actionId,
      canonicalActionDigest: actionId,
      generatedAt
    },
    verification: {
      status: "verified",
      valid: true,
      proofType: "stwo-unlock-keccak-v1",
      proofArtifactDigest,
      proofInputHash,
      actionId,
      canonicalActionDigest: actionId,
      verifiedAt
    },
    publicNullifier,
    proofPreviouslyUsed: false,
    nullifierPreviouslyUsed: false,
    runtimeApprovalEvidence: {
      status: "approved",
      approvalArtifactId: "approval_artifact_o21_1",
      platformUserApprovalDecisionId: "platform_approval_o21_1",
      authoritativePolicyDecisionId: "policy_o21_1",
      authoritativeCapabilityGrantId: "grant_o21_1",
      presentationDigest,
      approvedAt,
      expiresAt: new Date((nowSeconds + 120) * 1000).toISOString(),
      sessionId,
      auditCorrelationId,
      oneTime: true,
      consumedForPreparation: true,
      authorizesSigning: false,
      authorizesSubmission: false
    },
    userOperation: proposal.userOperation,
    userOperationHash: proposal.userOperationHash,
    preparedAt,
    nowSeconds
  };
  return { request, nowSeconds };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function validate(artifact, nowSeconds) {
  return validateLocalProofGatedUnsignedPreparationArtifact(artifact, {
    identityId: IDENTITY_ID,
    identityReference: fixture().request.identityReference,
    ownerCommitment: OWNER_COMMITMENT,
    validatorAddress: OWNER,
    validatorKeyReferenceId: VALIDATOR_KEY_REFERENCE,
    validatorKeyId: VALIDATOR_KEY_ID,
    smartAccountAddress: ACCOUNT,
    factoryAddress: FACTORY,
    targetAddress: TARGET,
    nowSeconds
  });
}

function signingRequestFor(artifact, nowSeconds) {
  const signingApproval = {
    status: "approved",
    actionId: artifact.actionId,
    canonicalActionDigest: artifact.canonicalActionDigest,
    presentationDigest: H("o21-2-signing-presentation"),
    approvedAt: new Date((nowSeconds - 1) * 1000).toISOString(),
    expiresAt: new Date((nowSeconds + 120) * 1000).toISOString(),
    oneTime: true,
    consumed: false
  };
  const userPresence = {
    status: "verified",
    actionId: artifact.actionId,
    canonicalActionDigest: artifact.canonicalActionDigest,
    evidenceDigest: H("o21-2-fresh-presence"),
    verifiedAt: new Date(nowSeconds * 1000).toISOString(),
    expiresAt: new Date((nowSeconds + 60) * 1000).toISOString()
  };
  return createLocalProofGatedSigningRequestFromUnsignedArtifact({
    artifact,
    signingApproval,
    userPresence,
    signingPolicy: {
      maxVerificationGasLimit: "1000000",
      maxCallGasLimit: "250000",
      maxPreVerificationGas: "150000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
      maxTotalFeeWei: "2800000000000000"
    },
    expectedFactoryAddress: FACTORY,
    expectedOwnerAddress: OWNER,
    validatorKeyId: VALIDATOR_KEY_ID,
    nowSeconds
  });
}

describe("O.21.1 Runtime-connected unsigned UserOperation boundary", function () {
  it("creates a verified unsigned preparation artifact and no mutation authority", function () {
    const { request } = fixture();
    const result = createLocalProofGatedUnsignedPreparationArtifact(request);
    assert.equal(result.status, "prepared_unsigned");
    assert.equal(result.value.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(result.value.entryPointAddress, ERC4337_V07_CANONICAL_ENTRYPOINT);
    assert.equal(result.value.userOperation.signature, "0x");
    assert.equal(result.value.userOperationSigned, false);
    assert.equal(result.value.userOperationSubmitted, false);
    assert.equal(result.value.publicMutationOccurred, false);
    assert.equal(result.value.ethereumVerifiedProof, false);
    assert.equal(result.value.starkVerificationLocation, "local");
    assert.equal(result.value.proofBytesIncluded, false);
    assert.equal(result.value.witnessMaterialIncluded, false);
    assert.equal(result.value.secretMaterialIncluded, false);
  });

  it("rejects locked, incorrect, stale, failed, and reused evidence", function () {
    const cases = [
      ["locked", { identityUnlocked: false }, "identity_locked"],
      ["incorrect identity", { identityId: "identity_bbbbbbbbbbbb_00000000" }, "incorrect_identity"],
      ["failed proof", { verification: { ...fixture().request.verification, valid: false } }, "proof_not_verified"],
      ["wrong validator", { validatorKeyId: H("wrong-validator") }, "validator_key_id_mismatch"],
      ["reused proof", { proofPreviouslyUsed: true }, "proof_reuse_rejected"],
      ["reused nullifier", { nullifierPreviouslyUsed: true }, "nullifier_reuse_rejected"],
      ["expired", { expiry: String(fixture().nowSeconds - 1) }, "authorization_expired"]
    ];
    for (const [label, overrides, expected] of cases) {
      const { request } = fixture();
      const result = createLocalProofGatedUnsignedPreparationArtifact({
        ...request,
        ...overrides
      });
      assert.equal(result.status, "rejected", label);
      assert.ok(result.errors.includes(expected), `${label}: ${result.errors.join(",")}`);
    }
  });

  it("rejects modified target, chain, calldata, hash, expiry, and signature", function () {
    const { request, nowSeconds } = fixture();
    const created = createLocalProofGatedUnsignedPreparationArtifact(request);
    assert.equal(created.status, "prepared_unsigned");
    const cases = [
      ["target", (value) => { value.targetAddress = Wallet.createRandom().address; }, "target_address_mismatch"],
      ["chain", (value) => { value.chainId = 1; }, "chain_id_mismatch"],
      ["calldata", (value) => { value.userOperation.callData = "0x1234"; }, "user_operation_calldata_mismatch"],
      ["hash", (value) => { value.userOperationHash = H("modified"); }, "user_operation_hash_mismatch"],
      ["authorization digest", (value) => { value.authorizationDigest = H("modified"); }, "runtime_authorization_digest_mismatch"],
      ["artifact id", (value) => { value.artifactId = "unsigned_user_operation_modified"; }, "artifact_id_mismatch"],
      ["identity reference", (value) => { value.identityBinding.identityReference = H("modified"); }, "identity_reference_mismatch"],
      ["expiry", (value) => { value.expiry = String(nowSeconds - 1); }, "authorization_expired"],
      ["signature", (value) => { value.userOperation.signature = "0x1234"; }, "signature_present"]
    ];
    for (const [label, mutate, expected] of cases) {
      const artifact = clone(created.value);
      mutate(artifact);
      const result = validate(artifact, nowSeconds);
      assert.equal(result.valid, false, label);
      assert.ok(result.errors.includes(expected), `${label}: ${result.errors.join(",")}`);
    }
  });

  it("changes the Runtime digest when proof, approval, or target binding changes", function () {
    const { request } = fixture();
    const base = request.runtimeAuthorizationDigest;
    const common = {
      identityReference: request.identityReference,
      ownerCommitment: request.ownerCommitment,
      actionId: request.actionId,
      canonicalActionDigest: request.canonicalActionDigest,
      proofInputHash: request.proof.proofInputHash,
      proofArtifactDigest: request.proof.proofArtifactDigest,
      nullifier: request.publicNullifier,
      approvalPresentationDigest: request.runtimeApprovalEvidence.presentationDigest,
      targetAddress: request.targetAddress,
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      sessionId: request.runtimeApprovalEvidence.sessionId,
      auditCorrelationId: request.runtimeApprovalEvidence.auditCorrelationId,
      expiry: request.expiry
    };
    assert.notEqual(computeLocalProofGatedRuntimeAuthorizationDigest({
      ...common,
      proofArtifactDigest: H("other-proof")
    }), base);
    assert.notEqual(computeLocalProofGatedRuntimeAuthorizationDigest({
      ...common,
      approvalPresentationDigest: H("other-approval")
    }), base);
    assert.notEqual(computeLocalProofGatedRuntimeAuthorizationDigest({
      ...common,
      targetAddress: Wallet.createRandom().address
    }), base);
  });

  it("rejects malformed artifact JSON without throwing", function () {
    const result = validate({ schemaVersion: "invalid" }, fixture().nowSeconds);
    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ["unsigned_preparation_malformed"]);
  });

  it("does not authorize signing without separate fresh user-presence evidence", function () {
    const result = validateLocalProofGatedSigningAuthorization({
      proof: {},
      verification: {},
      approval: {}
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.includes("user_presence_missing"));
  });

  it("binds post-verification approval and presence to the unchanged unsigned operation", function () {
    const { request, nowSeconds } = fixture();
    const created = createLocalProofGatedUnsignedPreparationArtifact(request);
    assert.equal(created.status, "prepared_unsigned");
    const signingRequest = signingRequestFor(created.value, nowSeconds);
    const valid = validateLocalProofGatedSigningAuthorization(signingRequest);
    assert.equal(valid.valid, true, valid.errors.join(","));

    const mutations = [
      ["modified operation", {
        ...signingRequest,
        userOperation: {
          ...signingRequest.userOperation,
          nonce: "1"
        }
      }],
      ["wrong chain", {
        ...signingRequest,
        envelope: { ...signingRequest.envelope, chainId: 1 }
      }],
      ["wrong validator", {
        ...signingRequest,
        validatorKeyId: H("wrong-validator")
      }],
      ["expired authorization", {
        ...signingRequest,
        nowSeconds: Number(created.value.expiry) + 1
      }],
      ["missing presence", {
        ...signingRequest,
        userPresence: undefined
      }],
      ["replayed approval", {
        ...signingRequest,
        approval: { ...signingRequest.approval, consumed: true }
      }]
    ];
    for (const [label, candidate] of mutations) {
      const result = validateLocalProofGatedSigningAuthorization(candidate);
      assert.equal(result.valid, false, label);
    }
  });
});
