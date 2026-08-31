const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  keccak256,
  toUtf8Bytes
} = require("ethers");

const runtime = require("../../../phil-device-sdk/src/runtime/index.ts");

const {
  ETHEREUM_SEPOLIA_CHAIN_ID,
  LOCAL_PROOF_GATED_SEPOLIA_SIGNING_PURPOSE,
  createDeviceVaultEcdsaProtectedSigningSession,
  createDeviceVaultEcdsaValidatorSigner,
  createLocalProofGatedSignedUserOperationArtifact,
  createLocalProofGatedSigningRequestFromUnsignedArtifact,
  createRestrictedSepoliaReadOnlyClient,
  runLocalProofGatedPreparationPreflight,
  signLocalProofGatedUserOperation,
  unpackPhilCore4337Uints,
  validateLocalProofGatedSignedUserOperationArtifact,
  validateLocalProofGatedUnsignedPreparationArtifact,
  verifyGeneratedActionUnlockProof
} = runtime;

const WORKFLOW_VERSION =
  "philcore-desktop-device-vault-sepolia-signing-o21-2-v1";
const SIGNING_TTL_MS = 2 * 60_000;

function nowIso() {
  return new Date().toISOString();
}

function stableJson(value) {
  return JSON.stringify(value, (_key, candidate) => {
    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      return Object.fromEntries(
        Object.entries(candidate).sort(([left], [right]) =>
          left.localeCompare(right)
        )
      );
    }
    return candidate;
  });
}

function freeze(value) {
  return Object.freeze(JSON.parse(JSON.stringify(value)));
}

function atomicWriteJson(location, value) {
  fs.mkdirSync(path.dirname(location), { recursive: true, mode: 0o700 });
  const temporary = `${location}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
    flag: "wx"
  });
  fs.renameSync(temporary, location);
  fs.chmodSync(location, 0o600);
}

function signedArtifactLocation(storageRoot, artifactId) {
  return path.join(
    storageRoot,
    "ethereum-sepolia",
    "signed-user-operations",
    `${artifactId}.json`
  );
}

function signingPolicyFor(artifact) {
  const gasLimits = unpackPhilCore4337Uints(artifact.userOperation.accountGasLimits);
  const gasFees = unpackPhilCore4337Uints(artifact.userOperation.gasFees);
  const totalGas =
    BigInt(gasLimits.high128)
    + BigInt(gasLimits.low128)
    + BigInt(artifact.userOperation.preVerificationGas);
  return freeze({
    maxVerificationGasLimit: gasLimits.high128,
    maxCallGasLimit: gasLimits.low128,
    maxPreVerificationGas: artifact.userOperation.preVerificationGas,
    maxFeePerGas: gasFees.low128,
    maxPriorityFeePerGas: gasFees.high128,
    maxTotalFeeWei: (totalGas * BigInt(gasFees.low128)).toString()
  });
}

function expectedUnsignedBinding(artifact) {
  return {
    identityId: artifact.identityBinding.identityId,
    identityReference: artifact.identityBinding.identityReference,
    ownerCommitment: artifact.identityBinding.ownerCommitment,
    validatorAddress: artifact.identityBinding.validatorAddress,
    validatorKeyReferenceId: artifact.identityBinding.validatorKeyReferenceId,
    validatorKeyId: artifact.identityBinding.validatorKeyId,
    smartAccountAddress: artifact.smartAccountAddress,
    factoryAddress: artifact.factoryAddress,
    targetAddress: artifact.targetAddress
  };
}

async function freshReadOnlyPreflight(configuration, dependencies) {
  if (dependencies.signingReadOnlyPreflightResult) {
    return freeze(dependencies.signingReadOnlyPreflightResult);
  }
  if (dependencies.readOnlyPreflightResult) {
    return freeze(dependencies.readOnlyPreflightResult);
  }
  const client = dependencies.readOnlyClient || createRestrictedSepoliaReadOnlyClient({
    url: configuration.rpcUrl
  });
  return runLocalProofGatedPreparationPreflight({
    client,
    deployer: {
      address: configuration.proposal.deployerAddress,
      configuredPendingNonce: configuration.proposal.deployerNonce
    },
    validatorAddress: configuration.identity.validatorAddress,
    proposedAddresses: {
      confirmationTarget: configuration.proposal.targetAddress,
      accountFactory: configuration.proposal.factoryAddress,
      firstAccount: configuration.proposal.accountAddress
    }
  });
}

function validateFreshPreflight(preflight, artifact) {
  const errors = [];
  if (preflight.status !== "READ_ONLY_PREFLIGHT_PASSED") {
    errors.push(...(preflight.errors || ["sepolia_read_only_preflight_failed"]));
  }
  if (preflight.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    errors.push("chain_id_mismatch");
  }
  if (!preflight.entryPoint?.codePresent) errors.push("entry_point_code_missing");
  for (const name of ["confirmationTarget", "accountFactory", "firstAccount"]) {
    if (preflight.proposedAddresses?.[name]?.codeStatus !== "empty") {
      errors.push(`${name}_address_changed`);
    }
  }
  const observedGasPrice = BigInt(preflight.feeData?.gasPriceWei || "0");
  const gasFees = unpackPhilCore4337Uints(artifact.userOperation.gasFees);
  if (observedGasPrice <= 0n) errors.push("fee_data_unresolved");
  if (observedGasPrice > BigInt(gasFees.low128)) errors.push("fee_cap_no_longer_sufficient");
  if (artifact.userOperation.nonce !== "0") errors.push("counterfactual_nonce_changed");
  if (preflight.mutationAttempted || preflight.publicMutationOccurred) {
    errors.push("read_only_boundary_violated");
  }
  return freeze({ valid: errors.length === 0, errors });
}

function presenceDigest(evidence) {
  return keccak256(toUtf8Bytes(stableJson({
    evidenceId: evidence.evidenceId,
    purpose: evidence.purpose,
    identityId: evidence.identityId,
    sessionId: evidence.sessionId,
    presentationDigest: evidence.presentationDigest,
    issuedAt: evidence.issuedAt,
    expiresAt: evidence.expiresAt,
    userPresenceGuaranteed: evidence.userPresenceGuaranteed
  })));
}

async function completeDesktopSepoliaUserOperationSigning(input) {
  const dependencies = input.dependencies || {};
  const capability = input.workflow.privateState;
  if (!capability || capability.kind !== "philcore-desktop-sepolia-signing-capability-v1") {
    throw new Error("process_local_signing_capability_unavailable");
  }
  if (capability.consumptionState?.consumed) {
    throw new Error("signing_capability_already_consumed");
  }
  if (capability.createdForSessionId !== input.sessionId) {
    throw new Error("signing_session_mismatch");
  }
  if (capability.createdForVaultHandleId !== input.vaultHandleId) {
    throw new Error("vault_handle_mismatch");
  }
  const artifact = capability.unsignedArtifact;
  const material = input.signingIdentityMaterial;
  if (!material) throw new Error("identity_locked");
  const signingAuthority = input.deviceVaultSigningAuthority;
  if (!signingAuthority) throw new Error("device_vault_signing_authority_unavailable");
  const freshEvidence = input.freshAuthenticationEvidence;
  if (
    freshEvidence.status !== "fresh_authentication_satisfied"
    || freshEvidence.purpose
      !== "ethereum_sepolia_local_proof_gated_v1_signing"
    || freshEvidence.presentationDigest
      !== input.signingApproval.presentationDigest
    || freshEvidence.identityId !== material.identityId
    || freshEvidence.sessionId !== input.sessionId
    || Date.parse(freshEvidence.expiresAt) <= Date.now()
  ) {
    throw new Error("fresh_user_presence_binding_invalid");
  }
  const fixturePresence = freshEvidence.method === "developer_fixture";
  if (!freshEvidence.userPresenceGuaranteed && !fixturePresence) {
    throw new Error("fresh_user_presence_not_guaranteed");
  }
  const unsignedValidation = validateLocalProofGatedUnsignedPreparationArtifact(
    artifact,
    expectedUnsignedBinding(artifact)
  );
  if (!unsignedValidation.valid) {
    throw new Error(unsignedValidation.errors.join(","));
  }
  if (
    material.identityId !== artifact.identityBinding.identityId
    || material.ownerCommitment.toLowerCase()
      !== artifact.identityBinding.ownerCommitment.toLowerCase()
    || material.validator.keyReferenceId
      !== artifact.identityBinding.validatorKeyReferenceId
    || material.validator.publicOwnerAddress.toLowerCase()
      !== artifact.identityBinding.validatorAddress.toLowerCase()
  ) {
    throw new Error("device_vault_identity_or_validator_mismatch");
  }

  const preflight = await freshReadOnlyPreflight(
    capability.configuration,
    dependencies
  );
  const preflightValidation = validateFreshPreflight(preflight, artifact);
  if (!preflightValidation.valid) {
    throw new Error(preflightValidation.errors.join(","));
  }

  const verifyProof = dependencies.verifyGeneratedActionUnlockProof
    || verifyGeneratedActionUnlockProof;
  const proofRevalidation = await verifyProof({
    requestId: `${input.workflow.workflowId}:o21-2-proof-revalidation`,
    authorizationPackageDraft: capability.authorizationPackageDraft,
    proofGenerationArtifact: capability.proofGenerationArtifact,
    issuedAt: nowIso(),
    expiresAt: new Date(Date.now() + SIGNING_TTL_MS).toISOString(),
    auditCorrelationId: input.workflow.correlation.auditCorrelationId,
    timeoutMs: input.proofTimeoutMs || 120_000,
    expectedProofInputHash: artifact.proofInputHash,
    expectedProofType: "stwo-unlock-keccak-v1",
    expectedFactShapeReference: "[fact_high, fact_low]"
  });
  if (
    proofRevalidation.status !== "approved"
    || !proofRevalidation.value
    || proofRevalidation.value.proofVerifiedLocally !== true
    || proofRevalidation.value.proofInputHash.toLowerCase()
      !== artifact.proofInputHash.toLowerCase()
  ) {
    throw new Error("local_proof_revalidation_failed");
  }

  const approvalEvidence = freeze({
    status: "approved",
    actionId: artifact.actionId,
    canonicalActionDigest: artifact.canonicalActionDigest,
    presentationDigest: input.signingApproval.presentationDigest,
    approvedAt: input.signingApproval.issuedAt,
    expiresAt: input.signingApproval.expiresAt,
    oneTime: true,
    consumed: false
  });
  const userPresenceEvidenceDigest = presenceDigest(freshEvidence);
  const userPresence = freeze({
    status: "verified",
    actionId: artifact.actionId,
    canonicalActionDigest: artifact.canonicalActionDigest,
    evidenceDigest: userPresenceEvidenceDigest,
    verifiedAt: freshEvidence.issuedAt,
    expiresAt: freshEvidence.expiresAt
  });
  const signingRequest = createLocalProofGatedSigningRequestFromUnsignedArtifact({
    artifact,
    signingApproval: approvalEvidence,
    userPresence,
    signingPolicy: signingPolicyFor(artifact),
    expectedFactoryAddress: artifact.factoryAddress,
    expectedOwnerAddress: artifact.identityBinding.validatorAddress,
    validatorKeyId: artifact.identityBinding.validatorKeyId
  });
  const signingValidation = runtime.validateLocalProofGatedSigningAuthorization(
    signingRequest
  );
  if (!signingValidation.valid || !signingValidation.authorization) {
    throw new Error(signingValidation.errors.join(","));
  }

  const sessionResult = await createDeviceVaultEcdsaProtectedSigningSession({
    requestId: `${input.workflow.workflowId}:o21-2-device-vault-signing`,
    identityUnlocked: input.identityUnlocked,
    activeSession: input.activeSession,
    recentUserPresence: true,
    currentApproval: true,
    keyReferenceId: material.validator.keyReferenceId,
    recordId: material.validator.recordId,
    ownerCommitment: material.ownerCommitment,
    ownerAddress: material.validator.publicOwnerAddress,
    sessionId: input.sessionId,
    vaultHandleId: input.vaultHandleId,
    smartAccountAddress: artifact.smartAccountAddress,
    entryPointAddress: artifact.entryPointAddress,
    chainId: artifact.chainId,
    userOperationHash: artifact.userOperationHash,
    signingDigest: signingValidation.authorization.accountSignatureDigest,
    presentationDigest: approvalEvidence.presentationDigest,
    callDataHash: keccak256(artifact.userOperation.callData),
    signingPurpose: LOCAL_PROOF_GATED_SEPOLIA_SIGNING_PURPOSE,
    expiresAt: input.signingApproval.expiresAt,
    auditCorrelationId: input.workflow.correlation.auditCorrelationId,
    checkAuthorityAvailable: () =>
      signingAuthority.checkAuthorityAvailable({
        keyReferenceId: material.validator.keyReferenceId,
        ownerAddress: material.validator.publicOwnerAddress,
        signingPurpose: LOCAL_PROOF_GATED_SEPOLIA_SIGNING_PURPOSE
      }),
    signBoundDigest: (digest) => signingAuthority.signBoundDigest({
      digest,
      signingPurpose: LOCAL_PROOF_GATED_SEPOLIA_SIGNING_PURPOSE
    })
  });
  if (sessionResult.status !== "approved" || !sessionResult.value) {
    throw new Error(
      sessionResult.error?.details?.errors?.join(",")
      || "device_vault_signing_session_rejected"
    );
  }
  const signer = createDeviceVaultEcdsaValidatorSigner(
    sessionResult.value.signingSession
  );
  let signed;
  try {
    signed = await signLocalProofGatedUserOperation({
      request: signingRequest,
      signer
    });
  } finally {
    sessionResult.value.signingSession.invalidate("o21-2-signing-complete");
  }
  if (signed.status !== "signed") {
    throw new Error(signed.errors.join(","));
  }
  const signedArtifact = createLocalProofGatedSignedUserOperationArtifact({
    unsignedArtifact: artifact,
    signedUserOperation: signed.value,
    signingApprovalPresentationDigest: approvalEvidence.presentationDigest,
    userPresenceEvidenceDigest,
    validatorPublicAddress: material.validator.publicOwnerAddress
  });
  const validation = validateLocalProofGatedSignedUserOperationArtifact(
    signedArtifact,
    {
      unsignedArtifact: artifact,
      validatorPublicAddress: material.validator.publicOwnerAddress
    }
  );
  if (!validation.valid) throw new Error(validation.errors.join(","));
  const location = signedArtifactLocation(input.storageRoot, signedArtifact.artifactId);
  atomicWriteJson(location, signedArtifact);
  capability.consumptionState.consumed = true;
  return {
    signedArtifact,
    artifactLocation: location,
    preflight,
    proofRevalidation: proofRevalidation.value,
    signingSession: sessionResult.value.snapshot
  };
}

module.exports = {
  WORKFLOW_VERSION,
  completeDesktopSepoliaUserOperationSigning,
  signedArtifactLocation,
  signingPolicyFor,
  validateFreshPreflight
};
