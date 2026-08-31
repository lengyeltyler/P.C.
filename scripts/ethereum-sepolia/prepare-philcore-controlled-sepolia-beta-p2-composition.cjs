"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { ethers } = require("ethers");
require("tsx/cjs");

const common = require("./philcore-controlled-sepolia-beta-p2-common.cjs");
const workflow = require("../../apps/philcore-desktop/src/main/sepolia-mint-composed-workflow.cjs");
const { createRoutineAuthorizationProtectedStores } = require(
  "../../apps/philcore-desktop/src/main/routine-authorization-storage.cjs"
);
const { createRoutineDeviceEnrollmentHost } = require(
  "../../apps/philcore-desktop/src/main/routine-device-enrollment-host.cjs"
);
const {
  createControlledSepoliaBetaCeremonyLifecycle,
  classifyExistingCeremony,
  classifyAuthorizationStore,
  archiveInvalidatedCeremony,
  physicalEnrollmentLifecycle,
  sanitizedCode
} = require("../../apps/philcore-desktop/src/main/controlled-sepolia-beta-ceremony-lifecycle.cjs");
const { createSepoliaMintCeremonyStore } = require(
  "../../apps/philcore-desktop/src/main/sepolia-mint-ceremony-store.cjs"
);
const { createSepoliaMintDeviceAuthorizationHost } = require(
  "../../apps/philcore-desktop/src/main/sepolia-mint-device-authorization-host.cjs"
);
const { createSepoliaMintReplayStore } = require(
  "../../apps/philcore-desktop/src/main/sepolia-mint-replay-store.cjs"
);
const { createQrDataUrl } = require(
  "../../apps/philcore-desktop/src/main/native-qr-code.cjs"
);
const { selectIPhonePrivateInterface } = require(
  "../../apps/philcore-desktop/src/main/native-iphone-pairing-host.cjs"
);
const {
  createPhilDeviceEnrollmentRecordV1
} = require("../../apps/phil-device-sdk/src/deviceApprovalV1.ts");
const {
  PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE
} = require("../../apps/phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const {
  deriveOwnerCommitmentFromPhilSecret,
  derivePhilIdentityRoot
} = require("../../apps/phil-device-sdk/src/identity.ts");
const {
  bindDeviceVaultEcdsaValidatorAccountReference,
  createDeviceVaultEcdsaSigningSession,
  createDeviceVaultEcdsaValidatorSigner,
  createUserSessionLifecycleSnapshot
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");
const {
  createFileDeviceIdentityRegistryStorageBackend,
  createInjectedRawKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");

let activeEnrollmentHost = null;
let activeAuthorizationHost = null;
let activeVaultKey = null;
let activeIdentity = null;
let activeCeremonyLifecycle = null;

const P3_COMPANION_IDENTITY = Object.freeze({
  expectedAppVersion: "0.1.0",
  expectedAppBuild: "56",
  expectedBundleIdentifier: "com.philcore.ios.companion.localalpha"
});

function acceptedReview(source, mode) {
  const prefix = mode === "p3"
    ? "PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW"
    : mode === "final"
    ? "PHILCORE_CONTROLLED_BETA_P2_FINAL_RUNNER_REVIEW"
    : mode === "recovery"
      ? "PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW"
      : "PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW";
  const review = {
    reviewedCommit: common.required(`${prefix}_COMMIT`),
    reviewedTree: common.required(`${prefix}_TREE`),
    reportSha256: common.required(`${prefix}_SHA256`).toLowerCase(),
    disposition: common.required(`${prefix}_DISPOSITION`)
  };
  if (review.reviewedCommit !== source.commit || review.reviewedTree !== source.tree
    || !/^0x[0-9a-f]{64}$/u.test(review.reportSha256)
    || review.disposition !== "ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH") {
    common.fail(mode === "p3"
      ? "PHILCORE_CONTROLLED_BETA_P3_RUNNER_REVIEW_INVALID"
      : mode === "final"
      ? "PHILCORE_CONTROLLED_BETA_P2_FINAL_RUNNER_REVIEW_INVALID"
      : mode === "recovery"
        ? "PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RUNNER_REVIEW_INVALID"
        : "PHILCORE_CONTROLLED_BETA_P2_RUNNER_REVIEW_INVALID");
  }
  return review;
}

function readVaultKey(service) {
  let encoded;
  try {
    encoded = execFileSync("security", ["find-generic-password", "-s", service, "-w"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_VAULT_KEY_UNAVAILABLE");
  }
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32 || key.toString("base64") !== encoded) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_VAULT_KEY_INVALID");
  }
  return key;
}

function decryptIdentity(location, key, expectedOwnerCommitment) {
  const value = common.readJson(location);
  if (value?.format !== "philcore-controlled-sepolia-beta-encrypted-identity-v1"
    || value.version !== 1 || value.encryption?.algorithm !== "aes-256-gcm"
    || value.associatedData?.ownerCommitment?.toLowerCase()
      !== expectedOwnerCommitment.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_IDENTITY_RECORD_INVALID");
  }
  let parsed;
  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm", key, Buffer.from(value.encryption.iv, "base64")
    );
    decipher.setAAD(Buffer.from(JSON.stringify(value.associatedData), "utf8"));
    decipher.setAuthTag(Buffer.from(value.encryption.tag, "base64"));
    parsed = JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(value.ciphertext, "base64")),
      decipher.final()
    ]).toString("utf8"));
  } catch {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_IDENTITY_DECRYPTION_FAILED");
  }
  if (!/^0x[0-9a-f]{64}$/u.test(parsed?.philSecret || "")
    || derivePhilIdentityRoot(parsed.philSecret).toLowerCase()
      !== String(parsed.identityRoot).toLowerCase()
    || deriveOwnerCommitmentFromPhilSecret(parsed.philSecret).toLowerCase()
      !== expectedOwnerCommitment.toLowerCase()) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_IDENTITY_BINDING_INVALID");
  }
  return parsed;
}

function encryptionAdapter(key) {
  return Object.freeze({
    isAvailable: () => true,
    encrypt(value) {
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
      const ciphertext = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
      return Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]);
    },
    decrypt(value) {
      const bytes = Buffer.from(value);
      if (bytes.length < 29) common.fail("PHILCORE_CONTROLLED_BETA_P2_PROTECTED_RECORD_INVALID");
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
      decipher.setAuthTag(bytes.subarray(12, 28));
      return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString("utf8");
    }
  });
}

function qrImage(qrPayload, outputPath) {
  const dataUrl = createQrDataUrl(qrPayload, { appRoot: common.ROOT });
  const match = /^data:image\/png;base64,(.+)$/u.exec(dataUrl);
  if (!match) common.fail("PHILCORE_CONTROLLED_BETA_P2_QR_INVALID");
  fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(outputPath, Buffer.from(match[1], "base64"), { mode: 0o600 });
  fs.chmodSync(outputPath, 0o600);
  return outputPath;
}

function announce(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function waitForEnrollment(host, requestId) {
  while (true) {
    const value = host.status(requestId);
    if (value.state === "completed") return;
    if (["expired", "cancelled", "failed"].includes(value.state)) {
      common.fail(`PHILCORE_CONTROLLED_BETA_P2_ENROLLMENT_${value.state.toUpperCase()}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

async function physicalEnrollment(input) {
  try {
    return await input.host.activeEnrollment();
  } catch (error) {
    if (error?.code !== "ROUTINE_ENROLLMENT_NOT_FOUND") throw error;
  }
  await input.host.start();
  const started = await input.host.beginEnrollment();
  const imagePath = qrImage(
    started.qrPayload,
    path.join(input.outputRoot, `p2-enrollment-${started.requestId.slice(2, 14)}.png`)
  );
  announce({
    status: "PHONE_ENROLLMENT_SCAN_REQUIRED",
    requestId: started.requestId,
    expiresAt: started.expiresAt,
    comparisonFingerprint: started.comparisonFingerprint,
    qrImagePath: imagePath,
    publicMutationOccurred: false
  });
  await waitForEnrollment(input.host, started.requestId);
  await input.host.stop();
  announce({ status: "PHONE_ENROLLMENT_CONFIRMED", publicMutationOccurred: false });
  return input.host.activeEnrollment();
}

function p3LifecycleOptions(outputRoot, source) {
  return Object.freeze({
    storageRoot: outputRoot,
    sourceCommit: source.commit,
    sourceTree: source.tree,
    ...P3_COMPANION_IDENTITY,
    now: () => BigInt(Math.floor(Date.now() / 1000))
  });
}

function reconcileP3SupportRoot(outputRoot, source) {
  if (!fs.existsSync(outputRoot)) return null;
  const options = p3LifecycleOptions(outputRoot, source);
  const classified = classifyExistingCeremony(options);
  if (classified.action === "resume") return classified.manager;
  if (!["invalidate", "fresh"].includes(classified.action)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P3_LOCAL_STATE_ALREADY_EXISTS_REQUIRES_ARCHIVE");
  }
  const reason = classified.reason || "P3_CEREMONY_TERMINAL_STATE_ARCHIVED";
  const archived = archiveInvalidatedCeremony(options, reason);
  announce({
    status: archived.record.invalidated
      ? "PRIOR_REQUEST_INVALIDATED_AFTER_RESTART"
      : "PRIOR_TERMINAL_CEREMONY_ARCHIVED",
    priorPhase: archived.record.previousPhase,
    diagnosticCode: archived.record.diagnosticCode,
    incidentArchivePath: archived.destination,
    publicMutationOccurred: false
  });
  return null;
}

function adaptEnrollment(stored, phoneAssurance) {
  const record = stored.record;
  if (stored.evidenceClass !== "physical_device_unverified"
    || record.secureEnclaveBacked !== true || record.userPresenceRequired !== true) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_PHYSICAL_DEVICE_REQUIRED");
  }
  return createPhilDeviceEnrollmentRecordV1({
    deviceId: record.deviceId,
    deviceKeyId: record.deviceKeyId,
    signatureSuiteId: PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
    publicKey: record.publicKeyX963,
    deviceEpoch: record.generation,
    enrolledAt: "1",
    assuranceClass: 3,
    attestationEvidenceHash: ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify({
      evidenceClass: stored.evidenceClass,
      generation: record.generation,
      publicKeyFingerprint: record.publicKeyFingerprint,
      secureEnclaveBacked: true,
      userPresenceRequired: true,
      remoteHardwareAttestationEstablished: false,
      assuranceClass: phoneAssurance.assuranceClass
    }))),
    policyHash: ethers.id("PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_DEVICE_POLICY_V1")
  });
}

async function bindInitialValidator(input) {
  const serialized = await input.storageBackend.read();
  const collection = JSON.parse(serialized);
  const record = collection.records.find((candidate) => (
    common.sameAddress(candidate.metadata.ownerAddress, input.config.account.initialExecutionValidator)
    && candidate.metadata.purpose === "erc4337_owner_validator_base_sepolia_beta"
    && candidate.metadata.status === "active"
  ));
  if (!record) common.fail("PHILCORE_CONTROLLED_BETA_P2_INITIAL_VALIDATOR_NOT_FOUND");
  if (record.metadata.accountAddress
    && common.sameAddress(record.metadata.accountAddress, input.config.account.predictedAddress)
    && record.metadata.chainId === common.CHAIN_ID) return record.keyReference;
  const bound = await bindDeviceVaultEcdsaValidatorAccountReference({
    storageBackend: input.storageBackend,
    keyProvider: input.keyProvider,
    keyReference: record.keyReference,
    accountAddress: input.config.account.predictedAddress,
    chainId: common.CHAIN_ID
  });
  if (bound.status !== "account_reference_bound" || !bound.record?.keyReference) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_INITIAL_VALIDATOR_BINDING_FAILED");
  }
  return bound.record.keyReference;
}

async function main() {
  const p3Mode = process.argv.includes("--p3");
  const finalMode = process.argv.includes("--final");
  const recoveryMode = process.argv.includes("--recovery");
  if ([p3Mode, finalMode, recoveryMode].filter(Boolean).length > 1) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_MODE_INVALID");
  }
  const mode = p3Mode ? "p3" : finalMode ? "final" : recoveryMode ? "recovery" : "initial";
  const source = common.sourceIdentity();
  acceptedReview(source, mode);
  const signedArtifactPath = p3Mode
    ? common.DEFAULT_P3_SIGNED_ARTIFACT_PATH
    : finalMode
    ? common.DEFAULT_FINAL_SIGNED_ARTIFACT_PATH
    : recoveryMode ? common.DEFAULT_RECOVERY_SIGNED_ARTIFACT_PATH : common.DEFAULT_SIGNED_ARTIFACT_PATH;
  if (fs.existsSync(signedArtifactPath)) {
    common.fail(p3Mode
      ? "PHILCORE_CONTROLLED_BETA_P3_SIGNED_ARTIFACT_ALREADY_EXISTS"
      : finalMode
      ? "PHILCORE_CONTROLLED_BETA_P2_FINAL_SIGNED_ARTIFACT_ALREADY_EXISTS"
      : recoveryMode
        ? "PHILCORE_CONTROLLED_BETA_P2_RECOVERY_SIGNED_ARTIFACT_ALREADY_EXISTS"
        : "PHILCORE_CONTROLLED_BETA_P2_SIGNED_ARTIFACT_ALREADY_EXISTS");
  }
  const config = common.loadConfiguration();
  const metadataPath = common.required("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_PATH");
  const metadataDocument = common.readJson(metadataPath);
  const metadata = common.normalizePublicMetadata(metadataDocument);
  const outputRoot = path.join(
    metadataDocument.paths.supportDir,
    p3Mode
      ? "p3-composed-authorization-v1"
      : finalMode
      ? "p2-final-composed-authorization-v1"
      : recoveryMode ? "p2-recovery-composed-authorization-v1" : "p2-composed-authorization-v1"
  );
  let p3Lifecycle = null;
  const guardedPaths = p3Mode
    ? [
        common.DEFAULT_P3_PLAN_PATH,
        common.DEFAULT_P3_RECEIPT_PATH,
        common.DEFAULT_P3_EXECUTION_LOCK_PATH
      ]
    : finalMode
    ? [
        common.DEFAULT_FINAL_PLAN_PATH,
        common.DEFAULT_FINAL_RECEIPT_PATH,
        common.DEFAULT_FINAL_EXECUTION_LOCK_PATH,
        outputRoot
      ]
    : recoveryMode
    ? [
        common.DEFAULT_RECOVERY_PLAN_PATH,
        common.DEFAULT_RECOVERY_RECEIPT_PATH,
        common.DEFAULT_RECOVERY_EXECUTION_LOCK_PATH,
        outputRoot
      ]
    : [
        common.DEFAULT_PLAN_PATH,
        common.DEFAULT_RECEIPT_PATH,
        common.DEFAULT_EXECUTION_LOCK_PATH,
        outputRoot
      ];
  if (guardedPaths.some((location) => fs.existsSync(location))) {
    common.fail(p3Mode
      ? "PHILCORE_CONTROLLED_BETA_P3_LOCAL_STATE_ALREADY_EXISTS_REQUIRES_ARCHIVE"
      : finalMode
      ? "PHILCORE_CONTROLLED_BETA_P2_FINAL_LOCAL_STATE_ALREADY_EXISTS_REQUIRES_ARCHIVE"
      : recoveryMode
        ? "PHILCORE_CONTROLLED_BETA_P2_RECOVERY_LOCAL_STATE_ALREADY_EXISTS_REQUIRES_ARCHIVE"
        : "PHILCORE_CONTROLLED_BETA_P2_LOCAL_STATE_ALREADY_EXISTS_REQUIRES_ARCHIVE");
  }
  if (p3Mode) p3Lifecycle = reconcileP3SupportRoot(outputRoot, source);
  common.assertConfigurationMetadata(config, metadata);
  const primaryUrl = common.required("PHILCORE_BETA_SEPOLIA_PRIMARY_RPC_URL");
  const reconciliationUrl = common.required("PHILCORE_BETA_SEPOLIA_RECONCILIATION_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_BETA_SEPOLIA_BUNDLER_URL");
  if (common.endpointDigest(primaryUrl) === common.endpointDigest(reconciliationUrl)) {
    common.fail("PHILCORE_CONTROLLED_BETA_PROVIDERS_NOT_INDEPENDENT");
  }
  const primary = new ethers.JsonRpcProvider(primaryUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const reconciliation = new ethers.JsonRpcProvider(reconciliationUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, common.PROVIDER_OPTIONS);
  const placeholder = Object.freeze({
    authorizationEnvelopeDigest: ethers.id("PHILCORE_P2_PREFLIGHT_ENVELOPE_PLACEHOLDER"),
    rootProofNullifier: ethers.id("PHILCORE_P2_PREFLIGHT_NULLIFIER_PLACEHOLDER"),
    deviceApprovalNonce: ethers.id("PHILCORE_P2_PREFLIGHT_DEVICE_PLACEHOLDER")
  });
  const state = await common.assertProviderPair(
    primary,
    reconciliation,
    config,
    placeholder,
    {
      expectUnfunded: !recoveryMode && !finalMode && !p3Mode,
      expectDeployed: finalMode || p3Mode,
      expectedNonce: p3Mode ? 1 : 0,
      expectedNextTokenId: p3Mode ? 2 : 1,
      expectedEntryPointDepositWei: p3Mode
        ? common.P2_FINAL_ORIGIN.entryPointDepositWei
        : "0"
    }
  );
  if (p3Mode) {
    const receiptBytes = fs.readFileSync(common.DEFAULT_FINAL_RECEIPT_PATH);
    const receipt = common.assertP2FinalReceipt(JSON.parse(receiptBytes), receiptBytes, config);
    const p2Plan = common.assertP2FinalPlan(
      common.readJson(common.DEFAULT_FINAL_PLAN_PATH), config
    );
    if (state.accountBalanceWei !== receipt.finalState.nativeBalanceWei
      || state.accountCodeHash?.toLowerCase() !== receipt.finalState.accountCodeHash.toLowerCase()
      || state.accountCodeHash?.toLowerCase() !== p2Plan.runtimeCodeHashes.account.toLowerCase()
      || state.accountImmutableMaskedRuntimeCodeHash?.toLowerCase()
        !== p2Plan.runtimeCodeHashes.accountImmutableMasked.toLowerCase()) {
      common.fail("PHILCORE_CONTROLLED_BETA_P3_P2_FINAL_BALANCE_CHANGED");
    }
    await common.assertP2FinalOriginLive(primary, reconciliation, bundler, config);
  } else if (finalMode) {
    const deploymentReceipt = common.readJson(common.DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH);
    if (deploymentReceipt?.format
        !== "philcore-controlled-sepolia-beta-p2-account-deployment-receipt-v1"
      || deploymentReceipt.status !== "P2_ACCOUNT_DEPLOYMENT_CONFIRMED"
      || deploymentReceipt.publicMutationOccurred !== true
      || deploymentReceipt.automaticRetryOccurred !== false
      || !common.sameAddress(deploymentReceipt.finalState?.smartAccount, config.account.predictedAddress)
      || state.accountBalanceWei !== deploymentReceipt.finalState.nativeBalanceWei) {
      common.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_ACCOUNT_DEPLOYMENT_EVIDENCE_INVALID");
    }
  } else if (recoveryMode) {
    const [nonceLeft, nonceRight] = await Promise.all([
      primary.getTransactionCount(config.deployer, "pending"),
      reconciliation.getTransactionCount(config.deployer, "pending")
    ]);
    if (state.accountBalanceWei !== common.P2_RECOVERY_ORIGIN.confirmedFundingValueWei
      || nonceLeft !== 4 || nonceRight !== 4) {
      common.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_RECONCILIATION_INVALID");
    }
    await common.assertP2RecoveryOriginLive(primary, reconciliation, bundler, config);
  }
  const feeData = await primary.getFeeData();
  if (!feeData.maxFeePerGas || !feeData.maxPriorityFeePerGas
    || feeData.maxFeePerGas > BigInt(config.gasPolicy.maxFeePerGas)
    || feeData.maxPriorityFeePerGas > BigInt(config.gasPolicy.maxPriorityFeePerGas)) {
    common.fail("PHILCORE_CONTROLLED_BETA_P2_CONFIGURED_FEE_CAP_STALE");
  }
  const selectedInterface = selectIPhonePrivateInterface();
  if (!selectedInterface) common.fail("PHILCORE_CONTROLLED_BETA_P2_PRIVATE_INTERFACE_UNAVAILABLE");
  const vaultKey = readVaultKey(metadata.keychainServices.vault);
  activeVaultKey = vaultKey;
  const identity = decryptIdentity(metadataDocument.paths.encryptedIdentity, vaultKey, metadata.ownerCommitment);
  activeIdentity = identity;
  const adapter = encryptionAdapter(vaultKey);
  const stores = createRoutineAuthorizationProtectedStores({
    storageRoot: path.join(outputRoot, "routine-device"),
    encryptionAdapter: adapter
  });
  const profileId = ethers.id(p3Mode
    ? "PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_DEVICE_PROFILE_V1"
    : "PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_DEVICE_PROFILE_V1");
  const enrollmentHost = createRoutineDeviceEnrollmentHost({
    disposableProfileId: profileId,
    ipv4: selectedInterface.address,
    enrollmentStore: stores.enrollmentStore,
    now: () => BigInt(Math.floor(Date.now() / 1000)),
    allowSynthetic: false
  });
  activeEnrollmentHost = enrollmentHost;
  if (p3Mode && !p3Lifecycle) {
    p3Lifecycle = createControlledSepoliaBetaCeremonyLifecycle(p3LifecycleOptions(outputRoot, source));
  }
  activeCeremonyLifecycle = p3Lifecycle;
  const storedEnrollment = p3Mode
    ? await physicalEnrollmentLifecycle({
        host: enrollmentHost,
        lifecycle: p3Lifecycle,
        createQrImage: (started) => qrImage(
          started.qrPayload,
          path.join(outputRoot, `p3-enrollment-${started.requestId.slice(2, 14)}.png`)
        ),
        announce,
        sleep: () => new Promise((resolve) => setTimeout(resolve, 500))
      })
    : await physicalEnrollment({ host: enrollmentHost, outputRoot });
  const enrollment = adaptEnrollment(storedEnrollment, config.phoneAssurance);
  const authorityStorage = createFileDeviceIdentityRegistryStorageBackend({
    filePath: metadataDocument.paths.encryptedAuthorities
  });
  const keyProvider = createInjectedRawKeyProvider({ key: vaultKey });
  const keyReference = await bindInitialValidator({
    storageBackend: authorityStorage,
    keyProvider,
    config
  });

  const now = BigInt(Math.floor(Date.now() / 1000));
  const validUntil = now + BigInt(config.authorizationWindowSeconds);
  const bindingsInput = Object.freeze({
    factory: config.infrastructure.factory,
    smartAccount: config.account.predictedAddress,
    actionGate: config.infrastructure.actionGate,
    mintConsumer: config.infrastructure.mintConsumer,
    mintRecipient: config.account.initialExecutionValidator,
    accountNonce: p3Mode ? "1" : "0",
    validAfter: now.toString(),
    validUntil: validUntil.toString(),
    maximumTotalFeeWei: config.maximumTotalFeeWei
  });
  announce({ status: "GENERATING_REAL_NOIR_PROOF", publicMutationOccurred: false });
  const prepared = await workflow.preparePhilSepoliaMintComposedWorkflow({
    repositoryRoot: common.ROOT,
    protectedMaterial: { philSecret: identity.philSecret },
    bindingsInput,
    epochs: {
      scopeEpoch: "1",
      deviceEpoch: enrollment.deviceEpoch,
      recoveryEpoch: "1",
      validatorEpoch: "1"
    },
    enrollment,
    executionOwner: config.account.initialExecutionValidator,
    ownerCommitment: config.account.ownerCommitment,
    accountSalt: BigInt(config.account.salt).toString(),
    accountDeployed: finalMode || p3Mode,
    gas: finalMode ? common.p2FinalGasPolicy(config.gasPolicy)
      : p3Mode ? common.p3GasPolicy(config.gasPolicy) : config.gasPolicy,
    proofTimeoutMs: 120_000
  });
  const replayStore = createSepoliaMintReplayStore({
    ledgerPath: path.join(outputRoot, "replay-v1.json"),
    now: () => new Date().toISOString()
  });
  const ceremonyStore = createSepoliaMintCeremonyStore({
    storageRoot: path.join(outputRoot, "ceremonies"),
    encryptionAdapter: adapter
  });
  const authorizationStoreDecision = p3Mode
    ? classifyAuthorizationStore(p3Lifecycle.snapshot(), ceremonyStore)
    : null;
  if (p3Mode && authorizationStoreDecision.action === "invalidate") {
    archiveInvalidatedCeremony(
      p3LifecycleOptions(outputRoot, source),
      "P3_CEREMONY_AUTHORIZATION_STORE_INCONSISTENT"
    );
    common.fail("PHILCORE_CONTROLLED_BETA_P3_AUTHORIZATION_STATE_INVALIDATED");
  }
  let completedArtifact = null;
  const authorizationHost = createSepoliaMintDeviceAuthorizationHost({
    ceremonyStore,
    enrollment,
    ipv4: selectedInterface.address,
    now: () => BigInt(Math.floor(Date.now() / 1000)),
    requestFactory: prepared.createDeviceRequest,
    onApproved: async ({ request, response, context }) => {
      if (p3Mode && p3Lifecycle.snapshot().phase === "authorization_request_created") {
        p3Lifecycle.transition("authorization_response_observed", {
          requestType: "exact_authorization", authorizationRequestId: request.requestId,
          diagnosticStage: "authorization_response", diagnosticCode: null
        });
        p3Lifecycle.transition("approved_authorization_persisted", {
          requestType: "exact_authorization", diagnosticStage: "authorization_persistence",
          diagnosticCode: null, persistenceSucceeded: true
        });
        announce({ status: "APPROVED_AUTHORIZATION_PERSISTED", publicMutationOccurred: false });
      }
      const liveNonce = await new ethers.Contract(
        config.entryPoint, common.entryPointInterface, primary
      ).getNonce(config.account.predictedAddress, 0);
      const signed = await workflow.completePhilSepoliaMintComposedWorkflow({
        repositoryRoot: common.ROOT,
        context,
        request,
        response,
        enrollment,
        replayStore,
        trustedState: {
          now: String(Math.floor(Date.now() / 1000)),
          scopeEpoch: "1",
          deviceEpoch: enrollment.deviceEpoch,
          recoveryEpoch: "1",
          validatorEpoch: "1",
          accountNonce: liveNonce.toString(),
          valueWei: "0",
          maximumTotalFeeWei: config.maximumTotalFeeWei,
          emergencyStop: false,
          scopeActive: true,
          policyActive: true,
          proofDescriptorActive: true,
          deviceActive: true,
          recoveryStateCurrent: true,
          validatorActive: true,
          cancelled: false,
          denied: false
        },
        createDeviceVaultSigner: async ({ prepared: operation }) => {
          const sessionId = `${p3Mode ? "p3" : finalMode ? "p2f" : recoveryMode ? "p2r" : "p2"}-${request.requestId.slice(2, 18)}`;
          const lifecycleSnapshot = createUserSessionLifecycleSnapshot({
            sessionId,
            state: "unlocked",
            metadata: { deviceVaultUnlocked: true, protectedStateAvailable: true }
          });
          const expiresAt = new Date(Number(request.approvalExpiresAt) * 1000).toISOString();
          const unlockedVaultHandle = Object.freeze({
            handleId: `p2-vault-${request.requestId.slice(2, 18)}`,
            sessionId,
            ownerCommitment: config.account.ownerCommitment,
            envelopeId: p3Mode
              ? "controlled-sepolia-beta-p3"
              : finalMode
              ? "controlled-sepolia-beta-p2-final"
              : recoveryMode
                ? "controlled-sepolia-beta-p2-recovery"
                : "controlled-sepolia-beta-p2",
            unlockResultId: p3Mode
              ? "controlled-sepolia-beta-p3-composed-release"
              : finalMode
              ? "controlled-sepolia-beta-p2-final-composed-release"
              : recoveryMode
                ? "controlled-sepolia-beta-p2-recovery-composed-release"
                : "controlled-sepolia-beta-p2-composed-release",
            unlockedAt: new Date().toISOString(),
            expiresAt,
            processLocal: true,
            serializable: false,
            exportable: false,
            containsPlaintext: false,
            containsRawVaultKey: false,
            containsPhilSecret: false,
            applicationAccessible: false
          });
          const session = await createDeviceVaultEcdsaSigningSession({
            requestId: `${request.requestId}:device-vault-signing`,
            lifecycleSnapshot,
            unlockedVaultHandle,
            storageBackend: authorityStorage,
            keyProvider,
            keyReference,
            ownerCommitment: config.account.ownerCommitment,
            smartAccountAddress: operation.smartAccount,
            entryPointAddress: config.entryPoint,
            chainId: common.CHAIN_ID,
            userOperationHash: operation.userOperationHash,
            signingDigest: operation.userOperationHash,
            presentationDigest: context.authorization.bindings.humanPresentationHash,
            callDataHash: ethers.keccak256(operation.userOperation.callData),
            purpose: "erc4337_owner_validator_base_sepolia_beta",
            expiresAt,
            auditCorrelationId: context.authorization.authorizationEnvelopeDigest
          });
          if (session.status !== "approved" || !session.value?.signingSession) {
            common.fail("PHILCORE_CONTROLLED_BETA_P2_DEVICE_VAULT_RELEASE_FAILED");
          }
          return createDeviceVaultEcdsaValidatorSigner(session.value.signingSession);
        }
      });
      const signedWithBoundedPhoneAssurance = Object.freeze({
        ...signed,
        phoneAssurance: config.phoneAssurance
      });
      common.parseSignedArtifact(
        signedWithBoundedPhoneAssurance,
        config,
        common.artifacts(),
        { accountDeployed: finalMode || p3Mode, expectedNonce: p3Mode ? 1 : 0 }
      );
      common.atomicCreateJson(signedArtifactPath, signedWithBoundedPhoneAssurance);
      replayStore.markConsumed(signed);
      completedArtifact = signedWithBoundedPhoneAssurance;
      return signedWithBoundedPhoneAssurance;
    }
  });
  activeAuthorizationHost = authorizationHost;
  await authorizationHost.startListener();
  let authorization = null;
  if (p3Mode && authorizationStoreDecision.action === "resume") {
    p3Lifecycle.markResumed();
    const restored = await authorizationHost.restoreApproved();
    if (restored.length !== 1 || !completedArtifact) {
      common.fail("PHILCORE_CONTROLLED_BETA_P3_APPROVED_AUTHORIZATION_RESUME_INVALID");
    }
    announce({ status: "APPROVED_AUTHORIZATION_SAFELY_RESUMED", publicMutationOccurred: false });
  } else {
    authorization = await authorizationHost.begin();
    if (p3Mode) {
      p3Lifecycle.transition("authorization_request_created", {
        requestType: "exact_authorization", authorizationRequestId: authorization.requestId,
        expiresAt: authorization.expiresAt, diagnosticStage: "authorization_create", diagnosticCode: null
      });
    }
    const authorizationImage = qrImage(
      authorization.qrPayload,
      path.join(outputRoot, `${p3Mode ? "p3" : "p2"}-authorization-${authorization.requestId.slice(2, 14)}.png`)
    );
    announce({
      status: "PHONE_AUTHORIZATION_SCAN_REQUIRED",
      requestId: authorization.requestId,
      expiresAt: authorization.expiresAt,
      presentation: authorization.presentation,
      qrImagePath: authorizationImage,
      publicMutationOccurred: false
    });
    const completionDeadlineMs = Number(authorization.expiresAt) * 1000 + 30_000;
    while (!completedArtifact) {
      const status = authorizationHost.getStatus(authorization.requestId);
      if (["expired", "cancelled", "failed"].includes(status.state)) {
        if (p3Mode && ["expired", "cancelled"].includes(status.state)) {
          p3Lifecycle.transition(status.state, {
            requestType: "exact_authorization",
            diagnosticStage: "authorization_response",
            diagnosticCode: `SEPOLIA_MINT_AUTHORIZATION_${status.state.toUpperCase()}`,
            cancellationOccurred: status.state === "cancelled",
            expiryOccurred: status.state === "expired"
          });
        }
        common.fail(`PHILCORE_CONTROLLED_BETA_P2_AUTHORIZATION_${status.state.toUpperCase()}`);
      }
      if (Date.now() > completionDeadlineMs) {
        common.fail("PHILCORE_CONTROLLED_BETA_P2_AUTHORIZATION_COMPLETION_AMBIGUOUS");
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  await authorizationHost.stopListener();
  activeAuthorizationHost = null;
  identity.philSecret = null;
  activeIdentity = null;
  vaultKey.fill(0);
  activeVaultKey = null;
  if (p3Mode) {
    p3Lifecycle.transition("completed_cleaned", {
      requestType: "exact_authorization", diagnosticStage: "cleanup", diagnosticCode: null,
      completedAndCleaned: true, deviceVaultReleaseOccurred: true, persistenceSucceeded: true
    });
  }
  announce({
    status: p3Mode
      ? "P3_SIGNED_UNSUBMITTED_ARTIFACT_READY"
      : recoveryMode
      ? "P2_RECOVERY_SIGNED_UNSUBMITTED_ARTIFACT_READY"
      : finalMode
        ? "P2_FINAL_SIGNED_UNSUBMITTED_ARTIFACT_READY"
        : "P2_SIGNED_UNSUBMITTED_ARTIFACT_READY",
    userOperationHash: completedArtifact.userOperationHash,
    authorizationEnvelopeDigest: completedArtifact.authorizationEnvelopeDigest,
    validUntil: bindingsInput.validUntil,
    outputPath: signedArtifactPath,
    signed: true,
    submitted: false,
    publicMutationOccurred: false
  });
}

main().catch(async (error) => {
  const lifecycleSnapshot = activeCeremonyLifecycle?.snapshot();
  const phase = lifecycleSnapshot?.phase;
  try {
    if (lifecycleSnapshot?.enrollmentRequestId && ["enrollment_request_created", "waiting_for_enrollment_contact", "enrollment_preflight_observed"].includes(phase)) {
      activeEnrollmentHost?.cancel(lifecycleSnapshot.enrollmentRequestId);
      activeCeremonyLifecycle.transition("cancelled", {
        requestType: "enrollment", cancellationOccurred: true,
        diagnosticStage: "enrollment_wait", diagnosticCode: sanitizedCode(error?.code)
      });
    } else if (lifecycleSnapshot?.authorizationRequestId && phase === "authorization_request_created") {
      await activeAuthorizationHost?.cancel(lifecycleSnapshot.authorizationRequestId);
      activeCeremonyLifecycle.transition("cancelled", {
        requestType: "exact_authorization", cancellationOccurred: true,
        diagnosticStage: "authorization_response", diagnosticCode: sanitizedCode(error?.code)
      });
    }
  } catch {}
  try { await activeAuthorizationHost?.stopListener(); } catch {}
  try { await activeEnrollmentHost?.stop(); } catch {}
  if (activeIdentity) activeIdentity.philSecret = null;
  activeVaultKey?.fill(0);
  process.stderr.write(`${error?.code || error?.message || String(error)}\n`);
  process.exitCode = 1;
});
