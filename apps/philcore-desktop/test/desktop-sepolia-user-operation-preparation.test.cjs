require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Wallet, id } = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID,
  calculateLocalProofGatedProposedAddresses,
  deriveLocalProofGatedValidatorKeyIdBinding,
  validateLocalProofGatedSignedUserOperationArtifact,
  validateLocalProofGatedUnsignedPreparationArtifact
} = require("../../phil-device-sdk/src/runtime/index.ts");
const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");
const {
  createHypotheticalWitnessHidingProofStack
} = require("./helpers/hypothetical-witness-hiding-proof-stack.cjs");

const PASSPHRASE = "O21-runtime-connected-passphrase!1";
const ACCOUNT_ARTIFACT = path.resolve(
  "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol/PhilCore4337LocalProofAccountV1.json"
);

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

function preflight(proposedAddresses) {
  return {
    schemaVersion: "philcore-local-proof-gated-preparation-v1",
    status: "READ_ONLY_PREFLIGHT_PASSED",
    checkedAt: new Date().toISOString(),
    rpcClassification: "fixture://read-only",
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    blockNumber: "1",
    entryPoint: {
      address: ERC4337_V07_CANONICAL_ENTRYPOINT,
      codePresent: true,
      getNonceCallSupported: true
    },
    proposedAddresses: {
      confirmationTarget: {
        address: proposedAddresses.targetAddress,
        codeStatus: "empty",
        balanceWei: "0"
      },
      accountFactory: {
        address: proposedAddresses.factoryAddress,
        codeStatus: "empty",
        balanceWei: "0"
      },
      firstAccount: {
        address: proposedAddresses.accountAddress,
        codeStatus: "empty",
        balanceWei: "0"
      }
    },
    feeData: { gasPriceWei: "1000000000", source: "rpc" },
    mutationMethodsExposed: false,
    mutationAttempted: false,
    publicMutationOccurred: false,
    errors: []
  };
}

function configurationFor(identity) {
  const accountArtifact = JSON.parse(fs.readFileSync(ACCOUNT_ARTIFACT, "utf8"));
  const deployer = Wallet.createRandom().address;
  const accountSalt = id(`o21:${identity.identityId}`);
  const validatorKeyId = deriveLocalProofGatedValidatorKeyIdBinding(
    identity.validatorKeyReferenceId
  );
  const proposed = calculateLocalProofGatedProposedAddresses({
    deployerAddress: deployer,
    deployerNonce: "0",
    ownerAddress: identity.validatorPublicAddress,
    ownerCommitment: identity.ownerCommitment,
    validatorKeyId,
    accountSalt,
    accountCreationBytecode: accountArtifact.bytecode
  });
  assert.equal(proposed.status, "calculated", proposed.errors?.join(","));
  return {
    schemaVersion: "philcore-desktop-sepolia-preparation-configuration-v1",
    identity: {
      identityId: identity.identityId,
      ownerCommitment: identity.ownerCommitment,
      validatorAddress: identity.validatorPublicAddress,
      validatorKeyReferenceId: identity.validatorKeyReferenceId,
      validatorKeyId
    },
    network: {
      profileId: "ethereum_sepolia",
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT
    },
    proposal: {
      deployerAddress: deployer,
      deployerNonce: "0",
      accountSalt,
      targetAddress: proposed.targetAddress,
      factoryAddress: proposed.factoryAddress,
      accountAddress: proposed.accountAddress
    },
    gasPolicy: {
      verificationGasLimit: "1000000",
      callGasLimit: "250000",
      preVerificationGas: "150000",
      maxPriorityFeePerGas: "1000000000"
    },
    rpcUrl: "fixture://read-only",
    publicMutationAllowed: false,
    signingAllowed: false,
    submissionAllowed: false,
    fixturePreflight: preflight(proposed)
  };
}

function createHost(options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o21-1-"));
  const hostOptions = {
    preferencesPath: path.join(dir, "prefs.json"),
    identityStorageRoot: path.join(dir, "identities"),
    platformKeyAdapter: createFixturePlatformKeyAdapter(),
    sessionTtlMs: 600_000,
    ...options
  };
  const host = createDesktopRuntimeHost(hostOptions);
  return { dir, host, hostOptions };
}

function createAndUnlock(host) {
  const created = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "O.21 Runtime Identity",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: false
  });
  const identity = {
    identityId: created.identity.identityId,
    ownerCommitment: created.identity.ownerCommitment,
    validatorPublicAddress: created.ethereum.validator.publicOwnerAddress,
    validatorKeyReferenceId: created.ethereum.validator.keyReferenceId
  };
  assert.equal(
    host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase: PASSPHRASE }).status,
    "authenticated"
  );
  assert.equal(host.invoke(CHANNELS.UNLOCK_VAULT, {}).status, "unlocked");
  const enrollment = approveKind(host, "platform_unlock_enrollment");
  const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
    passphrase: PASSPHRASE,
    approvalArtifactId: enrollment.approvalArtifactId
  });
  assert.equal(enrolled.status, "enrolled");
  return identity;
}

function approveKind(host, kind) {
  const created = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, {
    kind
  });
  assert.equal(created.status, "presentation_created");
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: created.presentation.presentationId,
    decision: "approve"
  });
  assert.equal(approved.status, "approved");
  return approved.approvalArtifact;
}

function approve(host) {
  return approveKind(host, "ethereum_sepolia_unsigned_preparation");
}

test("locked identity cannot prepare the Sepolia action", async () => {
  const { host, hostOptions } = createHost();
  const created = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Locked O.21",
    passphrase: PASSPHRASE,
    createRecoveryAuthority: false
  });
  const identity = {
    identityId: created.identity.identityId,
    ownerCommitment: created.identity.ownerCommitment,
    validatorPublicAddress: created.ethereum.validator.publicOwnerAddress,
    validatorKeyReferenceId: created.ethereum.validator.keyReferenceId
  };
  const configuration = configurationFor(identity);
  hostOptions.sepoliaPreparationConfiguration = configuration;
  hostOptions.sepoliaPreparationDependencies = {
    readOnlyPreflightResult: configuration.fixturePreflight
  };
  const result = await host.invoke(
    CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION,
    { approvalArtifactId: "missing" }
  );
  assert.equal(result.status, "blocked");
  assert.equal(result.reason, "identity_locked");
});

test("incorrect identity binding fails closed", async () => {
  const { host, hostOptions } = createHost();
  const identity = createAndUnlock(host);
  const configuration = configurationFor(identity);
  configuration.identity.identityId = "identity_bbbbbbbbbbbb_00000000";
  hostOptions.sepoliaPreparationConfiguration = configuration;
  hostOptions.sepoliaPreparationDependencies = {
    readOnlyPreflightResult: configuration.fixturePreflight
  };
  const preflightResult = host.invoke(
    CHANNELS.PREFLIGHT_SEPOLIA_USER_OPERATION_PREPARATION,
    {}
  );
  assert.equal(preflightResult.status, "blocked");
  assert.equal(preflightResult.reason, "incorrect_identity");
});

test("default Sepolia preparation fails closed on the secret-bearing proof path", async () => {
  const { dir, host, hostOptions } = createHost();
  const identity = createAndUnlock(host);
  const configuration = configurationFor(identity);
  hostOptions.sepoliaPreparationConfiguration = configuration;
  hostOptions.sepoliaPreparationDependencies = {
    readOnlyPreflightResult: configuration.fixturePreflight
  };
  const approval = approve(host);
  const result = await host.invoke(
    CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION,
    { approvalArtifactId: approval.approvalArtifactId, proofTimeoutMs: 120_000 }
  );
  assert.equal(result.status, "failed");
  assert.match(result.workflow.error, /secret-bearing proof research|experimental secret-bearing proof gate/u);
  assert.equal(result.workflow.publicNetworkMutation, false);
  assert.equal(fs.existsSync(path.join(
    dir,
    "identities",
    "ethereum-sepolia",
    "unsigned-user-operations"
  )), false);
});

test("hypothetical witness-hiding fixture exports one verified unsigned artifact and stops", async () => {
  const { dir, host, hostOptions } = createHost();
  const identity = createAndUnlock(host);
  const configuration = configurationFor(identity);
  hostOptions.sepoliaPreparationConfiguration = configuration;
  hostOptions.sepoliaPreparationDependencies = {
    readOnlyPreflightResult: configuration.fixturePreflight,
    ...createHypotheticalWitnessHidingProofStack()
  };
  const approval = approve(host);
  const result = await host.invoke(
    CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION,
    {
      approvalArtifactId: approval.approvalArtifactId,
      proofTimeoutMs: 120_000
    }
  );
  assert.equal(result.status, "prepared_unsigned", result.workflow?.error);
  assert.equal(result.workflow.workflowKind, "ethereum_sepolia_unsigned_preparation");
  assert.equal(
    result.workflow.preparation.statusMessage,
    "Prepared locally. Nothing has been sent to Ethereum."
  );
  assert.equal(result.workflow.preparation.signaturePresent, false);
  assert.equal(result.workflow.preparation.publicMutationOccurred, false);
  assert.equal(result.workflow.preparation.ethereumVerifiedProof, false);
  assert.equal(result.workflow.preparation.starkVerificationLocation, "local");
  const location = result.workflow.preparation.artifactLocation;
  assert.ok(location.startsWith(dir));
  assert.ok(fs.existsSync(location));
  assert.equal(fs.statSync(location).mode & 0o777, 0o600);
  const artifact = JSON.parse(fs.readFileSync(location, "utf8"));
  const validation = validateLocalProofGatedUnsignedPreparationArtifact(artifact, {
    identityId: identity.identityId,
    identityReference: id(
      `PHILCORE_DESKTOP_IDENTITY_REFERENCE_V1:${identity.identityId}`
    ),
    ownerCommitment: identity.ownerCommitment,
    validatorAddress: identity.validatorPublicAddress,
    validatorKeyReferenceId: identity.validatorKeyReferenceId,
    validatorKeyId: configuration.identity.validatorKeyId,
    smartAccountAddress: configuration.proposal.accountAddress,
    factoryAddress: configuration.proposal.factoryAddress,
    targetAddress: configuration.proposal.targetAddress
  });
  assert.equal(validation.valid, true, validation.errors.join(","));
  assert.equal(artifact.userOperation.signature, "0x");
  assert.equal(artifact.transactionSigned, false);
  assert.equal(artifact.userOperationSubmitted, false);
  assert.equal(artifact.publicMutationOccurred, false);
  const serialized = JSON.stringify({ artifact, workflow: result.workflow });
  for (const forbidden of [
    "phil_secret",
    "\"privateKey\":",
    "nullifierSeed",
    "\"vaultKey\":",
    "\"wrappingKey\":",
    "proofBlob"
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  const actions = result.snapshot.audit.history.map((event) => event.action);
  for (const action of [
    "protected_action_requested",
    "action_approved",
    "local_security_proof_generated",
    "local_security_proof_verified",
    "runtime_authorization_created",
    "unsigned_user_operation_prepared"
  ]) {
    assert.ok(actions.includes(action), action);
  }
  const replay = await host.invoke(
    CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION,
    {
      approvalArtifactId: approval.approvalArtifactId,
      proofTimeoutMs: 120_000
    }
  );
  assert.equal(replay.status, "approval_required");
  assert.equal(replay.reason, "approval_not_found_or_consumed");
});

test("separate fresh approval creates one validated signed and unsubmitted artifact", async () => {
  const { dir, host, hostOptions } = createHost();
  const identity = createAndUnlock(host);
  const configuration = configurationFor(identity);
  hostOptions.sepoliaPreparationConfiguration = configuration;
  hostOptions.sepoliaPreparationDependencies = {
    readOnlyPreflightResult: configuration.fixturePreflight,
    signingReadOnlyPreflightResult: configuration.fixturePreflight,
    ...createHypotheticalWitnessHidingProofStack()
  };
  const preparationApproval = approve(host);
  const prepared = await host.invoke(
    CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION,
    {
      approvalArtifactId: preparationApproval.approvalArtifactId,
      proofTimeoutMs: 120_000
    }
  );
  assert.equal(prepared.status, "prepared_unsigned", prepared.workflow?.error);

  const signingPresentation = host.invoke(
    CHANNELS.CREATE_APPROVAL_PRESENTATION,
    { kind: "ethereum_sepolia_user_operation_signing" }
  );
  assert.equal(signingPresentation.status, "presentation_created");
  assert.equal(
    signingPresentation.presentation.fields.some(
      (field) =>
        field.label === "Action"
        && field.value === "Create Ethereum test account"
    ),
    true
  );
  assert.equal(
    signingPresentation.presentation.fields.some(
      (field) =>
        field.label === "Network"
        && field.value === "Ethereum Sepolia"
    ),
    true
  );
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: signingPresentation.presentation.presentationId,
    decision: "approve"
  });
  assert.equal(approved.status, "approved");
  const missingPresence = await host.invoke(
    CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT,
    {
      workflowId: prepared.workflow.workflowId,
      approvalArtifactId: approved.approvalArtifact.approvalArtifactId,
      presentationDigest: approved.presentation.digest,
      freshAuthenticationEvidenceId: ""
    }
  );
  assert.equal(missingPresence.status, "approval_required");
  assert.equal(missingPresence.reason, "fresh_authentication_required");

  const fresh = host.invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
    purpose: "ethereum_sepolia_local_proof_gated_v1_signing",
    presentationId: approved.presentation.presentationId,
    presentationDigest: approved.presentation.digest
  });
  assert.equal(fresh.status, "authenticated");
  const signed = await host.invoke(
    CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT,
    {
      workflowId: prepared.workflow.workflowId,
      approvalArtifactId: approved.approvalArtifact.approvalArtifactId,
      presentationDigest: approved.presentation.digest,
      freshAuthenticationEvidenceId: fresh.evidence.evidenceId,
      proofTimeoutMs: 120_000
    }
  );
  assert.equal(signed.status, "signed_unsubmitted", signed.workflow?.error);
  assert.equal(signed.workflow.signing.signaturePresent, true);
  assert.equal(signed.workflow.signing.ethereumVerifiedProof, false);
  assert.equal(signed.workflow.signing.starkVerificationLocation, "local");
  assert.equal(signed.workflow.signing.publicMutationOccurred, false);
  assert.equal(signed.workflow.signing.userOperationSubmitted, false);
  const signedLocation = signed.workflow.signing.artifactLocation;
  assert.ok(signedLocation.startsWith(dir));
  assert.ok(fs.existsSync(signedLocation));
  assert.equal(fs.statSync(signedLocation).mode & 0o777, 0o600);
  const signedArtifact = JSON.parse(fs.readFileSync(signedLocation, "utf8"));
  const unsignedArtifact = JSON.parse(
    fs.readFileSync(prepared.workflow.preparation.artifactLocation, "utf8")
  );
  const validation = validateLocalProofGatedSignedUserOperationArtifact(
    signedArtifact,
    {
      unsignedArtifact,
      validatorPublicAddress: identity.validatorPublicAddress
    }
  );
  assert.equal(validation.valid, true, validation.errors.join(","));
  assert.equal(signedArtifact.userOperationSubmitted, false);
  assert.equal(signedArtifact.publicMutationOccurred, false);
  assert.equal(signedArtifact.ethereumVerifiedProof, false);
  assert.equal(signedArtifact.starkVerificationLocation, "local");
  assert.equal(signedArtifact.signedUserOperation.signature !== "0x", true);
  const serialized = JSON.stringify({ signedArtifact, workflow: signed.workflow });
  for (const forbidden of [
    "phil_secret",
    "\"privateKey\":",
    "nullifierSeed",
    "\"vaultKey\":",
    "\"wrappingKey\":",
    "proofBlob"
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  const replay = await host.invoke(
    CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT,
    {
      workflowId: prepared.workflow.workflowId,
      approvalArtifactId: approved.approvalArtifact.approvalArtifactId,
      presentationDigest: approved.presentation.digest,
      freshAuthenticationEvidenceId: fresh.evidence.evidenceId
    }
  );
  assert.equal(replay.status, "blocked");
});

test("failed proof generation creates no artifact and records no mutation", async () => {
  const { dir, host, hostOptions } = createHost();
  const identity = createAndUnlock(host);
  const configuration = configurationFor(identity);
  hostOptions.sepoliaPreparationConfiguration = configuration;
  hostOptions.sepoliaPreparationDependencies = {
    readOnlyPreflightResult: configuration.fixturePreflight,
    async generateActionUnlockProof() {
      return {
        status: "denied",
        error: { message: "injected proof failure" }
      };
    }
  };
  const approval = approve(host);
  const result = await host.invoke(
    CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION,
    { approvalArtifactId: approval.approvalArtifactId }
  );
  assert.equal(result.status, "failed");
  assert.match(result.workflow.error, /proof generation/);
  assert.equal(result.workflow.publicNetworkMutation, false);
  const exportRoot = path.join(
    dir,
    "identities",
    "ethereum-sepolia",
    "unsigned-user-operations"
  );
  assert.equal(fs.existsSync(exportRoot), false);
});

test("local Alpha renderer and preload omit the legacy Sepolia journey", () => {
  const renderer = fs.readFileSync(
    path.resolve("apps/philcore-desktop/src/renderer/app.js"),
    "utf8"
  );
  const preload = fs.readFileSync(
    path.resolve("apps/philcore-desktop/src/preload/preload.cjs"),
    "utf8"
  );
  for (const text of [
    "Create Ethereum Test Account Action",
    "You are approving a local Ethereum action",
    "Your device will authorize this action. Nothing has been sent to Ethereum.",
    "Signed locally. Nothing has been sent to Ethereum."
  ]) {
    assert.equal(renderer.includes(text), false, text);
  }
  for (const forbidden of [
    "preflightSepoliaUserOperationPreparation",
    "startSepoliaUserOperationPreparation",
    "getSepoliaUserOperationPreparation",
    "finalizeSepoliaSignedArtifact",
    "signSepoliaPreparation",
    "submitSepoliaPreparation",
    "SIGN_SEPOLIA_USER_OPERATION",
    "SUBMIT_SEPOLIA_USER_OPERATION",
    "signBoundDigest",
    "signUserOperationHash",
    "eth_sendUserOperation"
  ]) {
    assert.equal(renderer.includes(forbidden), false, forbidden);
    assert.equal(preload.includes(forbidden), false, forbidden);
  }
  assert.equal(renderer.includes("privateKey"), false);
  assert.equal(preload.includes("privateKey"), false);
});

process.nextTick(async () => {
  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`ok - ${name}`);
    } catch (error) {
      console.error(`not ok - ${name}`);
      console.error(error);
      process.exitCode = 1;
    }
  }
});
