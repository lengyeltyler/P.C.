const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("hardhat");

const runtime = require("../../../phil-device-sdk/src/runtime/index.ts");
const hashes = require("../../../phil-device-sdk/src/hashes.ts");
const {
  createDesktopRuntimeAuthorizationArtifacts
} = require("./real-local-authorization-workflow.cjs");
const {
  loadSepoliaLocalEnvironment
} = require("../../../../scripts/ethereum-sepolia/local-environment.cjs");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID,
  calculateLocalProofGatedProposedAddresses,
  computeLocalProofGatedRuntimeAuthorizationDigest,
  createLocalProofGatedFirstUserOperationProposal,
  createLocalProofGatedUnsignedPreparationArtifact,
  createRestrictedSepoliaReadOnlyClient,
  createStaticActionUnlockProtectedWitnessProvider,
  deriveCanonicalAuthorizationActionHash,
  deriveLocalProofGatedValidatorKeyIdBinding,
  finalizeAuthorizationPackage,
  generateActionUnlockProof,
  runLocalProofGatedPreparationPreflight,
  validateLocalProofGatedUnsignedPreparationArtifact,
  verifyGeneratedActionUnlockProof
} = runtime;
const {
  UNLOCK_PROOF_TYPE,
  dataHash,
  nullifier,
  policyHash
} = hashes;

const ROOT = path.resolve(__dirname, "../../../..");
const WORKFLOW_VERSION =
  "philcore-desktop-runtime-connected-sepolia-userop-o21-1-v1";
const APPLICATION_ID = "ethereum-net";
const APPLICATION_NAME = "Ethereum Net";
const HYPOTHETICAL_STACK_CLASSIFICATION =
  "HYPOTHETICAL_WITNESS_HIDING_TEST_STACK_NOT_AN_IMPLEMENTATION";
const PREPARATION_TTL_MS = 5 * 60_000;
const ACCOUNT_ARTIFACT_PATH = path.join(
  ROOT,
  "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol/PhilCore4337LocalProofAccountV1.json"
);

function nowIso() {
  return new Date().toISOString();
}

function freeze(value) {
  return Object.freeze(JSON.parse(JSON.stringify(value)));
}

function shortRef(value) {
  const text = String(value || "");
  if (text.length <= 18) return text;
  return `${text.slice(0, 10)}...${text.slice(-6)}`;
}

function stage(id, label, evidenceClass, status, details = {}) {
  return freeze({ id, label, evidenceClass, status, at: nowIso(), details });
}

function assertApproved(result, label) {
  if (result?.status !== "approved" || !result.value) {
    const reason = result?.error?.details?.errors?.join("; ")
      || result?.error?.message
      || result?.status
      || "unknown failure";
    throw new Error(`${label}: ${reason}`);
  }
  return result.value;
}

function identityReference(identityId) {
  return ethers.keccak256(ethers.toUtf8Bytes(
    `PHILCORE_DESKTOP_IDENTITY_REFERENCE_V1:${identityId}`
  ));
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

function loadDesktopSepoliaPreparationConfiguration(options = {}) {
  const root = options.root || ROOT;
  const environment = {};
  const loaded = loadSepoliaLocalEnvironment({
    root,
    indexPath: options.indexPath,
    environment
  });
  const accountArtifactPath = options.accountArtifactPath || ACCOUNT_ARTIFACT_PATH;
  const accountArtifact = JSON.parse(fs.readFileSync(accountArtifactPath, "utf8"));
  const validatorKeyId = deriveLocalProofGatedValidatorKeyIdBinding(
    loaded.values.PHILCORE_SEPOLIA_VALIDATOR_KEY_ID
  );
  const proposedAddresses = calculateLocalProofGatedProposedAddresses({
    deployerAddress: loaded.values.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS,
    deployerNonce: loaded.values.PHILCORE_SEPOLIA_DEPLOYER_NONCE,
    ownerAddress: loaded.values.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS,
    ownerCommitment: loaded.values.PHILCORE_SEPOLIA_OWNER_COMMITMENT,
    validatorKeyId,
    accountSalt: loaded.values.PHILCORE_SEPOLIA_ACCOUNT_SALT,
    accountCreationBytecode: accountArtifact.bytecode
  });
  if (proposedAddresses.status !== "calculated") {
    throw new Error(proposedAddresses.errors.join(",") || "sepolia_address_calculation_failed");
  }
  return freeze({
    schemaVersion: "philcore-desktop-sepolia-preparation-configuration-v1",
    identity: {
      identityId: loaded.identity.identityId,
      ownerCommitment: loaded.identity.ownerCommitment,
      validatorAddress: loaded.identity.validatorAddress,
      validatorKeyReferenceId: loaded.identity.validatorKeyId,
      validatorKeyId
    },
    network: {
      profileId: "ethereum_sepolia",
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT
    },
    proposal: {
      deployerAddress: loaded.values.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS,
      deployerNonce: loaded.values.PHILCORE_SEPOLIA_DEPLOYER_NONCE,
      accountSalt: loaded.values.PHILCORE_SEPOLIA_ACCOUNT_SALT,
      targetAddress: proposedAddresses.targetAddress,
      factoryAddress: proposedAddresses.factoryAddress,
      accountAddress: proposedAddresses.accountAddress
    },
    gasPolicy: {
      verificationGasLimit: "1000000",
      callGasLimit: "250000",
      preVerificationGas: "150000",
      maxPriorityFeePerGas: "1000000000"
    },
    rpcUrl: loaded.values.PHILCORE_SEPOLIA_RPC_URL,
    publicMutationAllowed: false,
    signingAllowed: false,
    submissionAllowed: false
  });
}

function validateConfigurationBinding(configuration, material) {
  const errors = [];
  if (configuration.network.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    errors.push("chain_id_mismatch");
  }
  if (
    configuration.network.entryPointAddress.toLowerCase()
      !== ERC4337_V07_CANONICAL_ENTRYPOINT.toLowerCase()
  ) {
    errors.push("entry_point_mismatch");
  }
  if (configuration.identity.identityId !== material.identityId) {
    errors.push("incorrect_identity");
  }
  if (
    configuration.identity.ownerCommitment.toLowerCase()
      !== material.ownerCommitment.toLowerCase()
  ) {
    errors.push("owner_commitment_mismatch");
  }
  if (
    configuration.identity.validatorAddress.toLowerCase()
      !== material.validator.publicOwnerAddress.toLowerCase()
  ) {
    errors.push("validator_address_mismatch");
  }
  if (
    configuration.identity.validatorKeyReferenceId
      !== material.validator.keyReferenceId
  ) {
    errors.push("validator_key_reference_mismatch");
  }
  if (
    configuration.identity.validatorKeyId.toLowerCase()
      !== deriveLocalProofGatedValidatorKeyIdBinding(
        material.validator.keyReferenceId
      ).toLowerCase()
  ) {
    errors.push("validator_key_id_mismatch");
  }
  if (
    configuration.publicMutationAllowed
    || configuration.signingAllowed
    || configuration.submissionAllowed
  ) {
    errors.push("unsafe_preparation_configuration");
  }
  return freeze({ valid: errors.length === 0, errors });
}

async function readOnlyPreflight(configuration, dependencies) {
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

function assertPreflight(preflight) {
  if (preflight.status !== "READ_ONLY_PREFLIGHT_PASSED") {
    throw new Error(preflight.errors?.join(",") || "sepolia_read_only_preflight_failed");
  }
  if (preflight.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("sepolia_read_only_chain_mismatch");
  }
  if (
    preflight.mutationMethodsExposed !== false
    || preflight.mutationAttempted !== false
    || preflight.publicMutationOccurred !== false
  ) {
    throw new Error("sepolia_rpc_mutation_boundary_violated");
  }
  for (const observation of Object.values(preflight.proposedAddresses || {})) {
    if (observation.codeStatus && observation.codeStatus !== "empty") {
      throw new Error("proposed_address_no_longer_empty");
    }
  }
}

function gasPriceForPreparation(preflight) {
  const observed = BigInt(preflight.feeData?.gasPriceWei || "0");
  if (observed <= 0n) throw new Error("sepolia_fee_data_unresolved");
  const doubled = observed * 2n;
  const maximum = 100_000_000_000n;
  return (doubled > maximum ? maximum : doubled).toString();
}

function artifactLocation(storageRoot, artifactId) {
  return path.join(
    storageRoot,
    "ethereum-sepolia",
    "unsigned-user-operations",
    `${artifactId}.json`
  );
}

async function startDesktopSepoliaUserOperationPreparation(input) {
  const dependencies = input.dependencies || {};
  const generateProof = dependencies.generateActionUnlockProof
    || generateActionUnlockProof;
  const verifyProof = dependencies.verifyGeneratedActionUnlockProof
    || verifyGeneratedActionUnlockProof;
  const finalizePackage = dependencies.finalizeAuthorizationPackage
    || finalizeAuthorizationPackage;
  const proofEvidenceClass = dependencies.classification === HYPOTHETICAL_STACK_CLASSIFICATION
    ? "hypothetical_witness_hiding_test_fixture"
    : "unavailable_secret_bearing_proof_quarantined";
  const stages = [];
  const timings = {};
  const startedAt = Date.now();
  const mark = (id, label, evidenceClass, status, details = {}) => {
    const item = stage(id, label, evidenceClass, status, details);
    stages.push(item);
    return item;
  };

  try {
    const material = input.protectedMaterial;
    if (!material) throw new Error("identity_locked");
    const configurationValidation = validateConfigurationBinding(
      input.configuration,
      material
    );
    if (!configurationValidation.valid) {
      throw new Error(configurationValidation.errors.join(","));
    }
    mark("identity_unlocked", "Identity unlocked", "real_local", "completed", {
      identityId: material.identityId,
      validator: shortRef(material.validator.publicOwnerAddress)
    });
    mark("intent_created", "Intent created", "real_local", "completed", {
      application: APPLICATION_NAME,
      action: "Create Ethereum Test Account Action",
      network: "Ethereum Sepolia",
      publicMutation: false
    });

    const preflight = await readOnlyPreflight(input.configuration, dependencies);
    assertPreflight(preflight);
    const expiresAt = new Date(Date.now() + PREPARATION_TTL_MS).toISOString();
    const expiry = BigInt(Math.floor(Date.parse(expiresAt) / 1000));
    const target = input.configuration.proposal.targetAddress;
    const account = input.configuration.proposal.accountAddress;
    const nullifierSeed = ethers.hexlify(ethers.randomBytes(32));
    const canonical = deriveCanonicalAuthorizationActionHash({
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      consumer: target,
      account,
      target,
      value: 0,
      callData: "0x"
    });
    const effectivePolicyHash = policyHash({
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      consumer: target,
      target,
      expiry,
      policyDataHash: dataHash("0x")
    });
    const publicNullifier = nullifier({
      ownerCommitment: material.ownerCommitment,
      actionHash: canonical.actionHash,
      policyHash: effectivePolicyHash,
      nullifierSeed
    });
    if (input.usedNullifiers?.has(publicNullifier.toLowerCase())) {
      throw new Error("nullifier_reuse_rejected");
    }

    const baseInput = {
      workflowId: input.workflowId,
      sessionId: input.sessionId,
      ownerCommitment: material.ownerCommitment,
      validator: material.validator,
      auditCorrelationId: input.auditCorrelationId,
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      network: "ethereum-sepolia",
      authenticationPurpose: "sepolia_unsigned_user_operation_preparation",
      approvalRiskSummary:
        "This prepares an unsigned Ethereum Sepolia test action. Nothing is signed or submitted.",
      workflowExpiresAt: expiresAt,
      desktopApproval: input.desktopApproval,
      action: {
        consumer: target,
        account,
        target,
        callData: "0x",
        expiresAt,
        publicNullifier,
        consumerDataReference: "philcore-local-proof-confirmation-target-v1"
      }
    };
    const authority = createDesktopRuntimeAuthorizationArtifacts(baseInput);
    mark("trust_evaluated", "Trust checked", "real_local", "completed", {
      outcome: authority.trust.outcome,
      evidence: "desktop_local_alpha"
    });
    mark("policy_decided", "Policy checked", "real_local", "completed", {
      outcome: authority.policy.outcome,
      target: shortRef(target),
      value: "0"
    });
    mark("approval_completed", "Protected action approved", "real_local", "completed", {
      approvalArtifactId: shortRef(input.desktopApproval.approvalArtifactId),
      oneTime: true,
      signingAuthorized: false,
      submissionAuthorized: false
    });
    mark("capability_activated", "Capability activated", "real_local", "completed", {
      capability: authority.grant.scope.capabilityName,
      expiresAt: authority.grant.validity.expiresAt
    });
    mark("authorization_candidate_created", "Authorization candidate created", "real_local", "completed", {
      candidateId: shortRef(authority.candidate.authorizationDecisionCandidateId)
    });
    mark("package_draft_created", "Authorization package created", "real_local", "completed", {
      proofInputHash: shortRef(authority.draft.hashSummary.proofInputHash),
      publicNullifier: shortRef(publicNullifier)
    });

    const proofGeneratedAt = nowIso();
    const proofStart = Date.now();
    mark("proof_generating", "Generating local proof", proofEvidenceClass, "running", {
      proofType: UNLOCK_PROOF_TYPE
    });
    const witnessProvider = createStaticActionUnlockProtectedWitnessProvider({
      providerId: `${input.workflowId}:desktop-sepolia-protected-witness`,
      providerKind: "local_device_vault",
      displayName: "Desktop Device Vault protected witness",
      philSecret: material.philSecret,
      nullifierSeed
    });
    const proofArtifact = assertApproved(await generateProof({
      requestId: `${input.workflowId}:sepolia-proof-generation`,
      authorizationPackageDraft: authority.draft,
      witnessProvider,
      issuedAt: proofGeneratedAt,
      expiresAt,
      auditCorrelationId: input.auditCorrelationId,
      timeoutMs: input.proofTimeoutMs || 120_000,
      includeProofBlob: true,
      expectedProofInputHash: authority.draft.hashSummary.proofInputHash,
      expectedProofType: UNLOCK_PROOF_TYPE
    }), "proof generation");
    timings.proofGenerationMs = Date.now() - proofStart;
    if (input.usedProofDigests?.has(
      proofArtifact.proofArtifact.proofDigest.toLowerCase()
    )) {
      throw new Error("proof_reuse_rejected");
    }
    mark("proof_generated", "Proof fixture generated locally", proofEvidenceClass, "completed", {
      proofDigest: shortRef(proofArtifact.proofArtifact.proofDigest),
      proofInputHash: shortRef(proofArtifact.proofInputHash),
      proofBytesDisplayed: false,
      witnessPersisted: false
    });

    const proofVerifiedAt = nowIso();
    const verifyStart = Date.now();
    const verification = assertApproved(await verifyProof({
      requestId: `${input.workflowId}:sepolia-proof-verification`,
      authorizationPackageDraft: authority.draft,
      proofGenerationArtifact: proofArtifact,
      issuedAt: proofVerifiedAt,
      expiresAt,
      auditCorrelationId: input.auditCorrelationId,
      timeoutMs: input.proofTimeoutMs || 120_000,
      expectedProofInputHash: authority.draft.hashSummary.proofInputHash,
      expectedProofType: UNLOCK_PROOF_TYPE,
      expectedFactShapeReference: "[fact_high, fact_low]"
    }), "proof verification");
    timings.proofVerificationMs = Date.now() - verifyStart;
    mark("proof_verified", "Proof fixture verified locally", proofEvidenceClass, "completed", {
      proofInputHash: shortRef(verification.proofInputHash),
      ethereumVerifiedProof: false
    });
    const finalized = assertApproved(await finalizePackage({
      requestId: `${input.workflowId}:sepolia-package-finalization`,
      authorizationPackageDraft: authority.draft,
      proofGenerationArtifact: proofArtifact,
      proofVerificationResult: verification,
      issuedAt: nowIso(),
      expiresAt,
      auditCorrelationId: input.auditCorrelationId
    }), "package finalization");

    const actionId = authority.draft.hashSummary.actionHash;
    const canonicalActionDigest = authority.draft.hashSummary.actionHash;
    const identityRef = identityReference(material.identityId);
    const runtimeAuthorizationDigest =
      computeLocalProofGatedRuntimeAuthorizationDigest({
        identityReference: identityRef,
        ownerCommitment: material.ownerCommitment,
        actionId,
        canonicalActionDigest,
        proofInputHash: finalized.actionUnlockAuthorization.proofInputHash,
        proofArtifactDigest: proofArtifact.proofArtifact.proofDigest,
        nullifier: publicNullifier,
        approvalPresentationDigest: input.desktopApproval.presentationDigest,
        targetAddress: target,
        chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
        sessionId: input.sessionId,
        auditCorrelationId: input.auditCorrelationId,
        expiry: expiry.toString()
      });
    mark("authorization_created", "Authorization created", "real_local", "completed", {
      authorizationDigest: shortRef(runtimeAuthorizationDigest),
      signingAuthorized: false,
      submissionAuthorized: false
    });

    const maxFeePerGas = gasPriceForPreparation(preflight);
    const proposal = createLocalProofGatedFirstUserOperationProposal({
      sender: account,
      factoryAddress: input.configuration.proposal.factoryAddress,
      ownerAddress: material.validator.publicOwnerAddress,
      ownerCommitment: material.ownerCommitment,
      validatorKeyId: input.configuration.identity.validatorKeyId,
      accountSalt: input.configuration.proposal.accountSalt,
      actionId,
      authorizationDigest: runtimeAuthorizationDigest,
      expiry: expiry.toString(),
      nonce: "0",
      verificationGasLimit: input.configuration.gasPolicy.verificationGasLimit,
      callGasLimit: input.configuration.gasPolicy.callGasLimit,
      preVerificationGas: input.configuration.gasPolicy.preVerificationGas,
      maxFeePerGas,
      maxPriorityFeePerGas:
        input.configuration.gasPolicy.maxPriorityFeePerGas
    });
    const preparedAt = nowIso();
    const preparation = createLocalProofGatedUnsignedPreparationArtifact({
      identityId: material.identityId,
      identityReference: identityRef,
      ownerCommitment: material.ownerCommitment,
      validatorAddress: material.validator.publicOwnerAddress,
      validatorKeyReferenceId: material.validator.keyReferenceId,
      validatorKeyId: input.configuration.identity.validatorKeyId,
      identityUnlocked: true,
      expectedIdentityId: input.configuration.identity.identityId,
      expectedOwnerCommitment: input.configuration.identity.ownerCommitment,
      expectedValidatorAddress: input.configuration.identity.validatorAddress,
      expectedValidatorKeyReferenceId:
        input.configuration.identity.validatorKeyReferenceId,
      expectedValidatorKeyId: input.configuration.identity.validatorKeyId,
      smartAccountAddress: account,
      factoryAddress: input.configuration.proposal.factoryAddress,
      targetAddress: target,
      expectedTargetAddress: target,
      actionId,
      canonicalActionDigest,
      runtimeAuthorizationDigest,
      expiry: expiry.toString(),
      proof: {
        status: "generated",
        proofType: UNLOCK_PROOF_TYPE,
        proofArtifactDigest: proofArtifact.proofArtifact.proofDigest,
        proofInputHash: proofArtifact.proofInputHash,
        actionId,
        canonicalActionDigest,
        generatedAt: proofGeneratedAt
      },
      verification: {
        status: "verified",
        valid: true,
        proofType: UNLOCK_PROOF_TYPE,
        proofArtifactDigest: proofArtifact.proofArtifact.proofDigest,
        proofInputHash: verification.proofInputHash,
        actionId,
        canonicalActionDigest,
        verifiedAt: proofVerifiedAt
      },
      publicNullifier,
      proofPreviouslyUsed: false,
      nullifierPreviouslyUsed: false,
      runtimeApprovalEvidence: {
        status: "approved",
        approvalArtifactId: input.desktopApproval.approvalArtifactId,
        platformUserApprovalDecisionId:
          authority.approval.platformUserApprovalDecisionId,
        authoritativePolicyDecisionId:
          authority.policy.authoritativePolicyDecisionId,
        authoritativeCapabilityGrantId:
          authority.grant.authoritativeCapabilityGrantId,
        presentationDigest: input.desktopApproval.presentationDigest,
        approvedAt: input.desktopApproval.decidedAt,
        expiresAt: input.desktopApproval.expiresAt,
        sessionId: input.sessionId,
        auditCorrelationId: input.auditCorrelationId,
        oneTime: true,
        consumedForPreparation: true,
        authorizesSigning: false,
        authorizesSubmission: false
      },
      userOperation: proposal.userOperation,
      userOperationHash: proposal.userOperationHash,
      preparedAt
    });
    if (preparation.status !== "prepared_unsigned") {
      throw new Error(preparation.errors.join(","));
    }
    const artifact = preparation.value;
    const artifactValidation = validateLocalProofGatedUnsignedPreparationArtifact(
      artifact,
      {
        identityId: material.identityId,
        identityReference: identityRef,
        ownerCommitment: material.ownerCommitment,
        validatorAddress: material.validator.publicOwnerAddress,
        validatorKeyReferenceId: material.validator.keyReferenceId,
        validatorKeyId: input.configuration.identity.validatorKeyId,
        smartAccountAddress: account,
        factoryAddress: input.configuration.proposal.factoryAddress,
        targetAddress: target
      }
    );
    if (!artifactValidation.valid) {
      throw new Error(artifactValidation.errors.join(","));
    }
    const location = artifactLocation(input.storageRoot, artifact.artifactId);
    atomicWriteJson(location, artifact);
    input.usedProofDigests?.add(proofArtifact.proofArtifact.proofDigest.toLowerCase());
    input.usedNullifiers?.add(publicNullifier.toLowerCase());
    mark("user_operation_prepared", "Unsigned UserOperation prepared", "real_local", "completed", {
      userOperationHash: shortRef(artifact.userOperationHash),
      signaturePresent: false,
      publicMutationOccurred: false
    });
    mark("ready_for_review", "Ready for review", "real_local", "completed", {
      message: "Prepared locally. Nothing has been sent to Ethereum.",
      artifactId: artifact.artifactId
    });
    timings.totalMachineProcessingMs = Date.now() - startedAt;
    return {
      workflowId: input.workflowId,
      workflowKind: "ethereum_sepolia_unsigned_preparation",
      version: WORKFLOW_VERSION,
      status: "prepared_unsigned",
      startedAt: new Date(startedAt).toISOString(),
      updatedAt: nowIso(),
      stages,
      timings,
      correlation: {
        identityId: material.identityId,
        ownerCommitment: material.ownerCommitment,
        applicationId: APPLICATION_ID,
        sessionId: input.sessionId,
        auditCorrelationId: input.auditCorrelationId,
        capabilityGrantId: authority.grant.authoritativeCapabilityGrantId,
        authorizationPackageDraftId: authority.draft.authorizationPackageDraftId,
        finalizedAuthorizationPackageId:
          finalized.finalizedAuthorizationPackageId,
        proofInputHash: finalized.actionUnlockAuthorization.proofInputHash,
        publicNullifier,
        smartAccount: account,
        entryPoint: ERC4337_V07_CANONICAL_ENTRYPOINT,
        userOperationHash: artifact.userOperationHash
      },
      preparation: {
        artifactId: artifact.artifactId,
        artifactLocation: location,
        chainId: artifact.chainId,
        entryPointAddress: artifact.entryPointAddress,
        smartAccountAddress: artifact.smartAccountAddress,
        targetAddress: artifact.targetAddress,
        authorizationDigest: artifact.authorizationDigest,
        actionId: artifact.actionId,
        expiry: artifact.expiry,
        userOperationHash: artifact.userOperationHash,
        proofVerifiedLocally: true,
        ethereumVerifiedProof: false,
        starkVerificationLocation: "local",
        signaturePresent: false,
        publicMutationOccurred: false,
        statusMessage: "Prepared locally. Nothing has been sent to Ethereum."
      },
      proof: {
        proofType: UNLOCK_PROOF_TYPE,
        proofDigest: proofArtifact.proofArtifact.proofDigest,
        proofByteLength: proofArtifact.proofArtifact.proofByteLength,
        proofInputHash: verification.proofInputHash,
        generationDurationMs: proofArtifact.summary.durationMs,
        verificationDurationMs: verification.summary.durationMs,
        proofBytesDisplayed: false,
        witnessExposed: false
      },
      evidenceLabels: {
        identity: "real_local",
        runtimeAuthorization: "real_local",
        proofGeneration: proofEvidenceClass,
        proofVerification: proofEvidenceClass,
        ethereumVerification: "not_executed",
        signing: "not_executed",
        submission: "not_executed"
      },
      privateState: Object.freeze({
        kind: "philcore-desktop-sepolia-signing-capability-v1",
        unsignedArtifact: artifact,
        authorizationPackageDraft: authority.draft,
        proofGenerationArtifact: proofArtifact,
        proofVerificationResult: verification,
        finalizedAuthorizationPackage: finalized,
        configuration: input.configuration,
        createdForSessionId: input.sessionId,
        createdForVaultHandleId: input.vaultHandleId,
        consumptionState: { consumed: false },
        toJSON() {
          throw new Error(
            "Sepolia signing capabilities are process-local and non-serializable"
          );
        }
      }),
      includesSecrets: false,
      proofWitnessExposed: false,
      proofBytesExposed: false,
      rawUserOperationExposed: false,
      transactionSigned: false,
      userOperationSigned: false,
      userOperationSubmitted: false,
      publicNetworkMutation: false,
      productionApprovalGranted: false
    };
  } catch (error) {
    mark("failed", "Preparation failed", "real_local", "failed", {
      reason: error instanceof Error ? error.message : "unknown_error"
    });
    return {
      workflowId: input.workflowId,
      workflowKind: "ethereum_sepolia_unsigned_preparation",
      version: WORKFLOW_VERSION,
      status: "failed",
      startedAt: new Date(startedAt).toISOString(),
      updatedAt: nowIso(),
      stages,
      timings,
      error: error instanceof Error ? error.message : "unknown_error",
      publicNetworkMutation: false,
      transactionSigned: false,
      userOperationSigned: false,
      userOperationSubmitted: false
    };
  }
}

module.exports = {
  WORKFLOW_VERSION,
  artifactLocation,
  loadDesktopSepoliaPreparationConfiguration,
  startDesktopSepoliaUserOperationPreparation,
  validateConfigurationBinding
};
