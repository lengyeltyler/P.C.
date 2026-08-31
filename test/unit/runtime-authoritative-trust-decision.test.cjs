const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { ethers } = require("hardhat");

const {
  arrayBufferToBase64Url
} = require("../../apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts");
const {
  createPhilCredentialRegistry
} = require("../../apps/phil-device-sdk/src/deviceIdentityLifecycle.ts");
const {
  createEncryptedDeviceIdentityRegistryStore,
  createInMemoryDeviceIdentityRegistryStorageBackend,
  createLocalDevPassphraseKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");
const {
  createPhilIdentityPrivate,
  derivePhilIdentityPublic
} = require("../../apps/phil-device-sdk/src/identity.ts");
const {
  createAuthoritativeTrustDecision,
  createBoundedTrustDecisionCandidate,
  createEphemeralTrustDecisionEvidenceConsumptionStore,
  createEphemeralTrustManagerVerificationConsumptionStore,
  createEphemeralUserSessionLifecycleStore,
  createEphemeralVaultUnlockConsumptionStore,
  createInMemoryAuthoritativeTrustDecisionStore,
  createInMemoryAuditDraftCollector,
  createProductionAuthenticationRequest,
  createTrustManagerVerificationInput,
  createValidationOnlyRuntimeApi,
  persistVerifiedCredentialCounter,
  requestPublicCredentialDirectory,
  requestSelectedCredentialPublicMaterial,
  resolveCounterPersistenceRequirement,
  runAlpha0Shell,
  transitionUserSessionWithVerifiedVaultUnlock,
  validateAuthoritativeTrustDecisionShape,
  verifyDeviceVaultUnlock,
  verifyTrustManagerProductionAssertion
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function generateP256CredentialKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  return {
    publicKey,
    privateKey,
    publicKeyHex: ethers.hexlify(publicKey.export({ type: "spki", format: "der" }))
  };
}

function sha256(value) {
  return crypto.createHash("sha256").update(Buffer.from(value)).digest();
}

function hashSerialized(value) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function buildAuthenticatorData({ rpId, flags = 0x05, signCount = 1 }) {
  const out = Buffer.alloc(37);
  sha256(Buffer.from(rpId, "utf8")).copy(out, 0);
  out[32] = flags;
  out.writeUInt32BE(signCount >>> 0, 33);
  return out;
}

function buildAssertion({
  credentialId = "cred-active",
  privateKey,
  rpId = "philcore.local",
  origin = "https://philcore.local",
  challenge = "challenge-ref-1",
  flags = 0x05,
  signCount = 8
}) {
  const authenticatorData = buildAuthenticatorData({ rpId, flags, signCount });
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin
  }));
  const signedBytes = Buffer.concat([authenticatorData, sha256(clientDataJSON)]);
  const signer = crypto.createSign("SHA256");
  signer.update(signedBytes);
  signer.end();
  return {
    id: credentialId,
    rawId: credentialId,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      authenticatorData: arrayBufferToBase64Url(authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(clientDataJSON),
      signature: arrayBufferToBase64Url(Buffer.from(signer.sign(privateKey))),
      userHandle: null
    },
    clientExtensionResults: {}
  };
}

function keyProvider() {
  return createLocalDevPassphraseKeyProvider({
    passphrase: "authoritative trust decision passphrase",
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
}

function partialSnapshot(sessionId) {
  const store = createEphemeralUserSessionLifecycleStore();
  store.initialize({ sessionId, transitionRequestId: `${sessionId}:initialize` });
  store.requestTransition({
    transitionRequestId: `${sessionId}:request-unlock`,
    event: "request_unlock"
  });
  const snapshot = store.getSnapshot();
  const now = new Date().toISOString();
  return Object.freeze({
    ...snapshot,
    state: "partially_unlocked",
    sequence: snapshot.sequence + 1,
    version: snapshot.version + 1,
    updatedAt: now,
    metadata: Object.freeze({
      ...snapshot.metadata,
      lifecycleAuthenticationFactorVerified: true,
      deviceVaultUnlocked: false,
      protectedStateAvailable: false,
      activeCapabilitiesAvailable: false,
      authorizationAvailable: false,
      persisted: false
    }),
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: false,
    grantsAuthority: false
  });
}

async function fixture(options = {}) {
  const storedCounter = options.storedCounter ?? 7;
  const returnedCounter = options.returnedCounter ?? 8;
  const credentialStatus = options.credentialStatus ?? "active";
  const registryCredentialStatus = options.registryCredentialStatus ?? credentialStatus;
  const purpose = options.purpose ?? "high_risk_action";
  const keyPair = generateP256CredentialKeyPair();
  const identity = derivePhilIdentityPublic(createPhilIdentityPrivate());
  const provider = keyProvider();
  const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
  const registryStore = createEncryptedDeviceIdentityRegistryStore({ backend, keyProvider: provider });
  const registry = createPhilCredentialRegistry({
    philIdentity: identity,
    credentials: [
      Object.freeze({
        credentialId: "cred-active",
        providerKind: "webauthn_passkey",
        algorithm: "ES256",
        label: "Primary passkey",
        createdAt: new Date().toISOString(),
        status: registryCredentialStatus,
        signCount: storedCounter,
        deviceType: "platform",
        transport: Object.freeze({
          transports: Object.freeze(["internal"]),
          authenticatorAttachment: "platform"
        }),
        priority: 1,
        deviceKeyId: "device-active",
        publicKey: keyPair.publicKeyHex,
        publicKeyHash: ethers.keccak256(keyPair.publicKeyHex)
      })
    ]
  }).getSnapshot();
  await registryStore.saveRegistry(registry);
  const encryptedBlob = await backend.read();
  const sessionId = "authoritative-trust-session-1";
  const materialAuditCorrelationId = `${sessionId}:selected-material`;
  const partial = partialSnapshot(sessionId);
  const unlock = await verifyDeviceVaultUnlock({
    requestId: "authoritative-trust-vault-unlock",
    lifecycleSnapshot: partial,
    identity,
    envelope: {
      envelopeId: "authoritative-trust-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "authoritative-trust-unlock-material",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    correlation: {
      sessionId,
      ownerCommitment: identity.ownerCommitment,
      lifecycleTransitionRequestId: `${sessionId}:vault-unlock-succeeded`,
      applicationId: "ethereum-net",
      auditCorrelationId: materialAuditCorrelationId
    },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    expectedAuditCorrelationId: materialAuditCorrelationId,
    auditCorrelationId: materialAuditCorrelationId
  });
  assert.equal(unlock.status, "approved", unlock.error?.details?.errors?.join("\n"));
  const transition = transitionUserSessionWithVerifiedVaultUnlock({
    requestId: "authoritative-trust-session-unlock",
    lifecycleSnapshot: partial,
    transitionRequest: {
      transitionRequestId: `${sessionId}:vault-unlock-succeeded`,
      event: "unlock_succeeded"
    },
    vaultUnlockResult: unlock.value,
    consumptionStore: createEphemeralVaultUnlockConsumptionStore(),
    auditCorrelationId: materialAuditCorrelationId
  });
  assert.equal(transition.status, "approved", transition.error?.details?.errors?.join("\n"));
  const directory = await requestPublicCredentialDirectory({
    requestId: "authoritative-trust-directory",
    operation: "list_credentials",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    identity,
    envelope: {
      envelopeId: "authoritative-trust-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "authoritative-trust-directory-material",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    query: { limit: 10 },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    auditCorrelationId: materialAuditCorrelationId
  });
  assert.equal(directory.status, "approved", directory.error?.details?.errors?.join("\n"));
  const material = await requestSelectedCredentialPublicMaterial({
    requestId: "authoritative-trust-selected-material",
    operation: "materialize_selected_credential_public_data",
    credentialId: "cred-active",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    publicCredentialDirectory: directory.value,
    identity,
    envelope: {
      envelopeId: "authoritative-trust-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "authoritative-trust-selected-material-key",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    auditCorrelationId: materialAuditCorrelationId
  });
  assert.equal(material.status, "approved", material.error?.details?.errors?.join("\n"));
  const auditCorrelationId = `${sessionId}:trust-manager-input`;
  const authRequest = createProductionAuthenticationRequest({
    requestId: "authoritative-trust-auth-request",
    purpose,
    providerId: "webauthn-provider-1",
    providerKind: "webauthn_passkey",
    requirement: {
      purpose,
      provider: {
        providerKind: "webauthn_passkey",
        providerId: "webauthn-provider-1",
        minimumAssurance: ["user_presence", "user_verification", "phishing_resistant"],
        userPresenceRequired: true,
        userVerificationRequired: true,
        phishingResistantRequired: true
      },
      challengeReference: {
        challengeReferenceId: "challenge-ref-1",
        challengeBindingHash: "challenge-binding-1",
        createdAt: new Date().toISOString(),
        expiresAt: futureDate(),
        generatedChallenge: false
      },
      correlation: {
        sessionId,
        ownerCommitment: identity.ownerCommitment,
        applicationId: "ethereum-net",
        credentialId: "cred-active",
        providerId: "webauthn-provider-1",
        auditCorrelationId
      },
      expiresAt: futureDate(),
      requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"]
    },
    metadata: { rpId: "philcore.local", origin: "https://philcore.local" }
  });
  assert.equal(authRequest.status, "approved", authRequest.error?.details?.errors?.join("\n"));
  const verificationInput = createTrustManagerVerificationInput({
    requestId: "authoritative-trust-verification-input",
    selectedCredentialVerificationProfile: material.value.verificationProfile,
    selectedCredentialVerificationHandle: material.value.verificationHandle,
    productionAuthenticationRequest: authRequest.value,
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    userSessionContext: {
      sessionId,
      ownerCommitment: identity.ownerCommitment,
      status: "unlocked",
      activeApplicationId: "ethereum-net",
      activeCapabilityIds: [],
      pendingIntentIds: [],
      policyMode: "default",
      metadata: { deviceVaultUnlocked: true, protectedStateAvailable: true }
    },
    applicationId: "ethereum-net",
    sessionId,
    ownerCommitment: identity.ownerCommitment,
    credentialId: "cred-active",
    providerId: "webauthn-provider-1",
    authenticationPurpose: purpose,
    challengeReferenceId: "challenge-ref-1",
    requiredAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    auditCorrelationId
  });
  assert.equal(verificationInput.status, "approved", verificationInput.error?.details?.errors?.join("\n"));
  const verification = await verifyTrustManagerProductionAssertion({
    requestId: "authoritative-trust-assertion-verification",
    verificationInput: verificationInput.value.verificationInput,
    assertion: buildAssertion({
      privateKey: keyPair.privateKey,
      signCount: returnedCounter
    }),
    expectedChallenge: "challenge-ref-1",
    expectedOrigin: "https://philcore.local",
    expectedRpId: "philcore.local",
    previousSignCounter: storedCounter,
    expectedSessionId: sessionId,
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedApplicationId: "ethereum-net",
    expectedAuthenticationPurpose: purpose,
    expectedProviderId: "webauthn-provider-1",
    expectedAuditCorrelationId: auditCorrelationId,
    collectedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId
  }, createEphemeralTrustManagerVerificationConsumptionStore());
  assert.equal(verification.status, "approved", verification.error?.details?.errors?.join("\n"));
  const candidate = createBoundedTrustDecisionCandidate({
    requestId: "authoritative-trust-candidate",
    productionVerificationResult: verification.value,
    credentialLifecycleStatus: credentialStatus,
    credentialId: "cred-active",
    providerKind: "webauthn_passkey",
    ownerCommitment: identity.ownerCommitment,
    sessionId,
    lifecycleState: "unlocked",
    applicationId: "ethereum-net",
    authenticationPurpose: purpose,
    requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    verificationTimestamp: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId,
    recoveryContext: options.recoveryContext,
    canonicalPhilActivationContext: options.canonicalPhilActivationContext
  });
  assert.equal(candidate.status, "approved", candidate.error?.details?.errors?.join("\n"));
  const persistence = await persistVerifiedCredentialCounter({
    operationId: `authoritative-trust-counter-persistence-${Math.random()}`,
    requestId: "authoritative-trust-counter-persistence",
    identity,
    storageBackend: backend,
    unlockMaterial: {
      materialId: "authoritative-trust-counter-material",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    productionVerificationResult: verification.value,
    boundedTrustDecisionCandidate: candidate.value,
    credentialId: "cred-active",
    ownerCommitment: identity.ownerCommitment,
    sessionId,
    applicationId: "ethereum-net",
    previousVerificationCounter: storedCounter,
    verifiedReturnedCounter: returnedCounter,
    expectedStoredCounter: storedCounter,
    expectedEncryptedRegistryHash: hashSerialized(encryptedBlob),
    expectedRegistryVersion: "phil-device-credential-registry-v1",
    expectedStorageVersion: 1,
    auditCorrelationId,
    requestedAt: new Date().toISOString(),
    expiresAt: futureDate()
  });
  assert.equal(persistence.status, "approved", persistence.error?.details?.errors?.join("\n"));
  const resolution = resolveCounterPersistenceRequirement({
    boundedTrustDecisionCandidate: candidate.value,
    receipt: persistence.value
  });
  const baseDecisionRequest = {
    requestId: "authoritative-trust-decision-request",
    productionVerificationResult: verification.value,
    boundedTrustDecisionCandidate: candidate.value,
    counterPersistenceReceipt: persistence.value,
    counterResolution: resolution,
    credentialLifecycleStatus: credentialStatus,
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    credentialId: "cred-active",
    providerKind: "webauthn_passkey",
    ownerCommitment: identity.ownerCommitment,
    sessionId,
    applicationId: "ethereum-net",
    authenticationPurpose: purpose,
    requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId,
    recoveryContext: options.recoveryContext,
    canonicalPhilActivationContext: options.canonicalPhilActivationContext
  };
  return {
    baseDecisionRequest,
    verification,
    candidate,
    persistence,
    resolution,
    transition,
    identity
  };
}

describe("PhilCore authoritative Trust Decision boundary", function () {
  it("creates a bounded Trust Manager decision from a full production evidence chain", async function () {
    const f = await fixture();
    const result = createAuthoritativeTrustDecision(f.baseDecisionRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.trustDecisionCreated, true);
    assert.equal(result.value.scope.sessionId, f.baseDecisionRequest.sessionId);
    assert.equal(result.value.scope.authenticationPurpose, "high_risk_action");
    assert.equal(result.value.credentialCounterCommitted, true);
    assert.equal(result.value.capabilityGranted, false);
    assert.equal(result.value.policyApproved, false);
    assert.equal(result.value.userApprovalCollected, false);
    assert.equal(result.value.authorizationCreated, false);
    assert.equal(result.value.sessionKeyCreated, false);
    assert.equal(result.value.executionAllowed, false);
    assert.equal(result.value.worldIdVerified, false);
    assert.equal(result.value.vaultMaterialExposed, false);
    assert.equal(result.value.persistedAsAuthority, false);
    assert.equal(validateAuthoritativeTrustDecisionShape(result.value).valid, true);
    assert.equal(JSON.stringify(result.value).includes("clientDataJSON"), false);
    assert.equal(JSON.stringify(result.value).includes("authenticatorData"), false);
  });

  it("rejects ineligible verification, mismatched receipt, expired evidence, and replay", async function () {
    const f = await fixture();
    const failedVerification = createAuthoritativeTrustDecision({
      ...f.baseDecisionRequest,
      productionVerificationResult: {
        ...f.baseDecisionRequest.productionVerificationResult,
        status: "verification_rejected"
      }
    });
    const receiptMismatch = createAuthoritativeTrustDecision({
      ...f.baseDecisionRequest,
      counterPersistenceReceipt: {
        ...f.baseDecisionRequest.counterPersistenceReceipt,
        correlation: {
          ...f.baseDecisionRequest.counterPersistenceReceipt.correlation,
          credentialId: "other"
        }
      }
    });
    const expired = createAuthoritativeTrustDecision({
      ...f.baseDecisionRequest,
      expiresAt: pastDate()
    });
    const store = createEphemeralTrustDecisionEvidenceConsumptionStore();
    const first = createAuthoritativeTrustDecision(f.baseDecisionRequest, store);
    const replay = createAuthoritativeTrustDecision(f.baseDecisionRequest, store);

    assert.equal(failedVerification.status, "denied");
    assert.equal(receiptMismatch.status, "denied");
    assert.equal(expired.status, "denied");
    assert.equal(first.status, "approved");
    assert.equal(replay.status, "denied");
    assert.match(replay.error.message, /rejected/i);
  });

  it("accepts zero-counter semantics without creating application authority", async function () {
    const f = await fixture({ storedCounter: 0, returnedCounter: 0 });
    const result = createAuthoritativeTrustDecision(f.baseDecisionRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.credentialCounterCommitted, false);
    assert.equal(result.value.acceptedZeroCounterSemantics, true);
    assert.equal(result.value.capabilityGranted, false);
  });

  it("rejects ineligible lifecycle contexts and keeps recovery-only bounded to recovery purpose", async function () {
    const ordinaryRecoveryOnly = await fixture();
    const recoveryPurpose = await fixture({
      credentialStatus: "recovery-only",
      registryCredentialStatus: "active",
      purpose: "recovery_approval",
      recoveryContext: true
    });
    const locked = createAuthoritativeTrustDecision({
      ...recoveryPurpose.baseDecisionRequest,
      lifecycleSnapshot: {
        ...recoveryPurpose.baseDecisionRequest.lifecycleSnapshot,
        state: "locked"
      }
    });
    const ordinaryRejected = createAuthoritativeTrustDecision({
      ...ordinaryRecoveryOnly.baseDecisionRequest,
      credentialLifecycleStatus: "recovery-only"
    });
    const recoveryAccepted =
      createAuthoritativeTrustDecision(recoveryPurpose.baseDecisionRequest);

    assert.equal(ordinaryRejected.status, "denied");
    assert.equal(locked.status, "denied");
    assert.equal(recoveryAccepted.status, "approved", recoveryAccepted.error?.details?.errors?.join("\n"));
    assert.equal(recoveryAccepted.value.scope.authenticationPurpose, "recovery_approval");
  });

  it("preserves World ID as canonical activation specific and does not require it ordinarily", async function () {
    const ordinary = await fixture();
    const canonical = await fixture({
      purpose: "canonical_phil_activation",
      canonicalPhilActivationContext: true
    });
    const ordinaryResult = createAuthoritativeTrustDecision(ordinary.baseDecisionRequest);
    const canonicalResult = createAuthoritativeTrustDecision(canonical.baseDecisionRequest);

    assert.equal(ordinaryResult.status, "approved");
    assert.equal(ordinaryResult.value.worldIdVerified, false);
    assert.equal(canonicalResult.status, "denied");
  });

  it("integrates with facade, audit drafts, and optional process-local store without session authority mutation", async function () {
    const f = await fixture();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const decisionStore = createInMemoryAuthoritativeTrustDecisionStore({ maxDecisionCount: 1 });
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      authoritativeTrustDecisionStore: decisionStore,
      trustDecisionEvidenceConsumptionStore:
        createEphemeralTrustDecisionEvidenceConsumptionStore()
    });
    const result = api.requestAuthoritativeTrustDecision(f.baseDecisionRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.authoritativeTrustDecision.trustDecisionCreated, true);
    assert.equal(result.value.authoritativeTrustDecisionCollectionResult.status, "collected");
    assert.equal(decisionStore.count(), 1);
    assert.equal(result.value.authoritativeTrustDecision.capabilityGranted, false);
    assert.equal(result.value.authoritativeTrustDecision.authorizationCreated, false);
    assert.equal(result.value.auditEventDraft.redactedDetails.authoritativeTrustDecisionTrustDecisionCreated, true);
    assert.equal(JSON.stringify(result.value.auditEventDraft).includes("phil_secret"), false);
  });

  it("runs Alpha 0 authoritative Trust Decision diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_authoritative_trust_decision"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_authoritative_trust_decision", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Authoritative bounded Trust Decision:/i);
    assert.match(textOutput, /Trust Decision created: yes, Trust Manager authority only/i);
    assert.match(textOutput, /capability grant created: no/i);
    assert.match(textOutput, /Authorization Package created: no/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.authoritativeTrustDecision.outcome, "trust_decision_created");
    assert.equal(parsed.authoritativeTrustDecision.capabilityGranted, false);
    assert.equal(parsed.authoritativeTrustDecision.authorizationCreated, false);
    assert.equal(parsed.authoritativeTrustDecision.executionAllowed, false);
  });
});
