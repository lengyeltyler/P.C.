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
  createBoundedTrustDecisionCandidate,
  createEphemeralCredentialCounterPersistenceReplayStore,
  createEphemeralTrustManagerVerificationConsumptionStore,
  createEphemeralUserSessionLifecycleStore,
  createEphemeralVaultUnlockConsumptionStore,
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
  verifyDeviceVaultUnlock,
  verifyPersistedCredentialCounter,
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
  const signature = Buffer.from(signer.sign(privateKey));
  return {
    id: credentialId,
    rawId: credentialId,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      authenticatorData: arrayBufferToBase64Url(authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(clientDataJSON),
      signature: arrayBufferToBase64Url(signature),
      userHandle: null
    },
    clientExtensionResults: {}
  };
}

function keyProvider() {
  return createLocalDevPassphraseKeyProvider({
    passphrase: "credential counter persistence passphrase",
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
}

function partialSnapshot(sessionId) {
  const store = createEphemeralUserSessionLifecycleStore();
  store.initialize({ sessionId, transitionRequestId: `${sessionId}:initialize` });
  store.requestTransition({ transitionRequestId: `${sessionId}:request-unlock`, event: "request_unlock" });
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

async function fixture() {
  const keyPair = generateP256CredentialKeyPair();
  const identity = derivePhilIdentityPublic(createPhilIdentityPrivate());
  const provider = keyProvider();
  const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
  const registryStore = createEncryptedDeviceIdentityRegistryStore({ backend, keyProvider: provider });
  const secondKeyPair = generateP256CredentialKeyPair();
  const registry = createPhilCredentialRegistry({
    philIdentity: identity,
    credentials: [
      Object.freeze({
        credentialId: "cred-active",
        providerKind: "webauthn_passkey",
        algorithm: "ES256",
        label: "Primary passkey",
        createdAt: new Date().toISOString(),
        status: "active",
        signCount: 7,
        deviceType: "platform",
        transport: Object.freeze({
          transports: Object.freeze(["internal"]),
          authenticatorAttachment: "platform"
        }),
        priority: 1,
        deviceKeyId: "device-active",
        publicKey: keyPair.publicKeyHex,
        publicKeyHash: ethers.keccak256(keyPair.publicKeyHex)
      }),
      Object.freeze({
        credentialId: "cred-other",
        providerKind: "webauthn_passkey",
        algorithm: "ES256",
        label: "Secondary passkey",
        createdAt: new Date().toISOString(),
        status: "active",
        signCount: 3,
        deviceType: "platform",
        transport: Object.freeze({
          transports: Object.freeze(["internal"]),
          authenticatorAttachment: "platform"
        }),
        priority: 2,
        deviceKeyId: "device-other",
        publicKey: secondKeyPair.publicKeyHex,
        publicKeyHash: ethers.keccak256(secondKeyPair.publicKeyHex)
      })
    ]
  }).getSnapshot();
  await registryStore.saveRegistry(registry);
  const initialEncryptedBlob = await backend.read();
  const expectedEncryptedRegistryHash = hashSerialized(initialEncryptedBlob);
  const sessionId = "counter-persistence-session-1";
  const materialAuditCorrelationId = `${sessionId}:selected-material`;
  const partial = partialSnapshot(sessionId);
  const unlock = await verifyDeviceVaultUnlock({
    requestId: "counter-persistence-vault-unlock",
    lifecycleSnapshot: partial,
    identity,
    envelope: {
      envelopeId: "counter-persistence-envelope",
      encryptedBlob: initialEncryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "counter-persistence-unlock-material",
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
    requestId: "counter-persistence-session-unlock",
    lifecycleSnapshot: partial,
    transitionRequest: { transitionRequestId: `${sessionId}:vault-unlock-succeeded`, event: "unlock_succeeded" },
    vaultUnlockResult: unlock.value,
    consumptionStore: createEphemeralVaultUnlockConsumptionStore(),
    auditCorrelationId: materialAuditCorrelationId
  });
  assert.equal(transition.status, "approved", transition.error?.details?.errors?.join("\n"));
  const directory = await requestPublicCredentialDirectory({
    requestId: "counter-persistence-directory",
    operation: "list_credentials",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    identity,
    envelope: {
      envelopeId: "counter-persistence-envelope",
      encryptedBlob: initialEncryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "counter-persistence-directory-material",
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
    requestId: "counter-persistence-selected-material",
    operation: "materialize_selected_credential_public_data",
    credentialId: "cred-active",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    publicCredentialDirectory: directory.value,
    identity,
    envelope: {
      envelopeId: "counter-persistence-envelope",
      encryptedBlob: initialEncryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "counter-persistence-selected-material-key",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    auditCorrelationId: materialAuditCorrelationId
  });
  assert.equal(material.status, "approved", material.error?.details?.errors?.join("\n"));
  const verificationAuditCorrelationId = `${sessionId}:trust-manager-input`;
  const authRequest = createProductionAuthenticationRequest({
    requestId: "counter-persistence-auth-request",
    purpose: "high_risk_action",
    providerId: "webauthn-provider-1",
    providerKind: "webauthn_passkey",
    requirement: {
      purpose: "high_risk_action",
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
        auditCorrelationId: verificationAuditCorrelationId
      },
      expiresAt: futureDate(),
      requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"]
    },
    metadata: { rpId: "philcore.local", origin: "https://philcore.local" }
  });
  assert.equal(authRequest.status, "approved", authRequest.error?.details?.errors?.join("\n"));
  const verificationInput = createTrustManagerVerificationInput({
    requestId: "counter-persistence-verification-input",
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
    authenticationPurpose: "high_risk_action",
    challengeReferenceId: "challenge-ref-1",
    requiredAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    auditCorrelationId: verificationAuditCorrelationId
  });
  assert.equal(verificationInput.status, "approved", verificationInput.error?.details?.errors?.join("\n"));
  const verification = await verifyTrustManagerProductionAssertion({
    requestId: "counter-persistence-assertion-verification",
    verificationInput: verificationInput.value.verificationInput,
    assertion: buildAssertion({ privateKey: keyPair.privateKey }),
    expectedChallenge: "challenge-ref-1",
    expectedOrigin: "https://philcore.local",
    expectedRpId: "philcore.local",
    previousSignCounter: 7,
    expectedSessionId: sessionId,
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedApplicationId: "ethereum-net",
    expectedAuthenticationPurpose: "high_risk_action",
    expectedProviderId: "webauthn-provider-1",
    expectedAuditCorrelationId: verificationAuditCorrelationId,
    collectedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: verificationAuditCorrelationId
  }, createEphemeralTrustManagerVerificationConsumptionStore());
  assert.equal(verification.status, "approved", verification.error?.details?.errors?.join("\n"));
  const candidate = createBoundedTrustDecisionCandidate({
    requestId: "counter-persistence-candidate",
    productionVerificationResult: verification.value,
    credentialLifecycleStatus: "active",
    credentialId: "cred-active",
    providerKind: "webauthn_passkey",
    ownerCommitment: identity.ownerCommitment,
    sessionId,
    lifecycleState: "unlocked",
    applicationId: "ethereum-net",
    authenticationPurpose: "high_risk_action",
    requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    verificationTimestamp: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: verificationAuditCorrelationId
  });
  assert.equal(candidate.status, "approved", candidate.error?.details?.errors?.join("\n"));
  const baseRequest = {
    operationId: "counter-persistence-operation",
    requestId: "counter-persistence-request",
    identity,
    storageBackend: backend,
    unlockMaterial: {
      materialId: "counter-persistence-material",
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
    previousVerificationCounter: 7,
    verifiedReturnedCounter: 8,
    expectedStoredCounter: 7,
    expectedEncryptedRegistryHash,
    expectedRegistryVersion: "phil-device-credential-registry-v1",
    expectedStorageVersion: 1,
    auditCorrelationId: verificationAuditCorrelationId,
    requestedAt: new Date().toISOString(),
    expiresAt: futureDate()
  };
  return {
    baseRequest,
    registryStore,
    backend,
    provider,
    identity,
    beforeSnapshot: registry,
    verification,
    candidate
  };
}

async function credentialSnapshot(f, credentialId = "cred-active") {
  const snapshot = await f.registryStore.loadRegistry(f.identity);
  return snapshot.credentials.find((credential) => credential.credentialId === credentialId);
}

describe("PhilCore credential counter persistence boundary", function () {
  it("persists a valid advanced counter and mutates only the selected counter field", async function () {
    const f = await fixture();
    const beforeTarget = await credentialSnapshot(f);
    const beforeOther = await credentialSnapshot(f, "cred-other");
    const result = await persistVerifiedCredentialCounter(f.baseRequest);
    const afterTarget = await credentialSnapshot(f);
    const afterOther = await credentialSnapshot(f, "cred-other");
    const verify = await verifyPersistedCredentialCounter(f.baseRequest, result.value);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.outcome, "counter_persisted");
    assert.equal(result.value.counterPersisted, true);
    assert.equal(afterTarget.signCount, 8);
    assert.equal(beforeTarget.status, afterTarget.status);
    assert.equal(beforeTarget.label, afterTarget.label);
    assert.equal(JSON.stringify(beforeOther), JSON.stringify(afterOther));
    assert.equal(result.value.trustDecisionCreated, false);
    assert.equal(result.value.capabilityGranted, false);
    assert.equal(result.value.authorizationCreated, false);
    assert.equal(result.value.registryPlaintextExposed, false);
    assert.equal(verify.valid, true, verify.errors.join("\n"));
  });

  it("rejects stale counters, stale registry hashes, rollback, clone risk, ineligible credentials, and bad correlations", async function () {
    const cases = [
      ["stored counter mismatch", { expectedStoredCounter: 6 }, "stored_counter_mismatch"],
      ["previous counter mismatch", { previousVerificationCounter: 6 }, "stored_counter_mismatch"],
      ["stale hash", { expectedEncryptedRegistryHash: "0xdead" }, "stored_counter_mismatch"],
      ["rollback", {
        verifiedReturnedCounter: 6,
        productionVerificationResult: (base) => ({
          ...base.productionVerificationResult,
          counterAssessment: {
            ...base.productionVerificationResult.counterAssessment,
            counterStatus: "rollback",
            rollbackDetected: true,
            futurePersistenceRequired: false
          }
        })
      }, "counter_rollback_detected"],
      ["clone", {
        verifiedReturnedCounter: 7,
        productionVerificationResult: (base) => ({
          ...base.productionVerificationResult,
          counterAssessment: {
            ...base.productionVerificationResult.counterAssessment,
            counterStatus: "clone-suspected",
            cloneSuspected: true,
            futurePersistenceRequired: false
          }
        })
      }, "counter_clone_risk_detected"],
      ["session mismatch", { sessionId: "wrong-session" }, "session_mismatch"],
      ["owner mismatch", { ownerCommitment: "0xdead" }, "owner_mismatch"],
      ["application mismatch", { applicationId: "nft-manager" }, "application_mismatch"],
      ["audit mismatch", { auditCorrelationId: "wrong-audit" }, "audit_correlation_mismatch"],
      ["expired", { expiresAt: pastDate() }, "expired"],
      ["invalid lifecycle", { lifecycleSnapshot: (base) => ({ ...base.lifecycleSnapshot, state: "locked" }) }, "session_mismatch"]
    ];

    for (const [name, patch, outcome] of cases) {
      const f = await fixture();
      const expanded = { ...patch };
      for (const [key, value] of Object.entries(patch)) {
        if (typeof value === "function") expanded[key] = value(f.baseRequest);
      }
      const result = await persistVerifiedCredentialCounter({
        ...f.baseRequest,
        operationId: `counter-persistence-${name}`,
        ...expanded
      });
      assert.equal(result.status, "denied", name);
      assert.equal(result.error.details.errors.length > 0, true, name);
    }
    const missing = await fixture();
    const missingSnapshot = await missing.registryStore.loadRegistry(missing.identity);
    await missing.registryStore.saveRegistry({
      ...missingSnapshot,
      credentials: Object.freeze(missingSnapshot.credentials.filter((credential) =>
        credential.credentialId !== "cred-active"
      ))
    });
    const missingResult = await persistVerifiedCredentialCounter({
      ...missing.baseRequest,
      operationId: "counter-persistence-credential-not-found",
      expectedEncryptedRegistryHash: undefined
    });
    assert.equal(missingResult.status, "denied");
    assert.match(missingResult.error.details.errors.join(" "), /not found/i);
  });

  it("rejects revoked, archived, and rotated credentials from the current registry", async function () {
    for (const status of ["revoked", "archived", "rotated"]) {
      const f = await fixture();
      const snapshot = await f.registryStore.loadRegistry(f.identity);
      await f.registryStore.saveRegistry({
        ...snapshot,
        credentials: Object.freeze(snapshot.credentials.map((credential) =>
          credential.credentialId === "cred-active"
            ? Object.freeze({ ...credential, status })
            : credential
        ))
      });
      const result = await persistVerifiedCredentialCounter({
        ...f.baseRequest,
        operationId: `counter-persistence-${status}`,
        expectedEncryptedRegistryHash: undefined
      });
      assert.equal(result.status, "denied");
      assert.match(result.error.details.errors.join(" "), /not eligible/i);
    }
  });

  it("accepts unchanged zero-counter semantics without mutating and rejects unsupported counters explicitly", async function () {
    const zero = await fixture();
    const zeroSnapshot = await zero.registryStore.loadRegistry(zero.identity);
    await zero.registryStore.saveRegistry({
      ...zeroSnapshot,
      credentials: Object.freeze(zeroSnapshot.credentials.map((credential) =>
        credential.credentialId === "cred-active"
          ? Object.freeze({ ...credential, signCount: 0 })
          : credential
      ))
    });
    const zeroResult = await persistVerifiedCredentialCounter({
      ...zero.baseRequest,
      operationId: "counter-persistence-zero",
      previousVerificationCounter: 0,
      verifiedReturnedCounter: 0,
      expectedStoredCounter: 0,
      expectedEncryptedRegistryHash: undefined,
      productionVerificationResult: {
        ...zero.baseRequest.productionVerificationResult,
        counterAssessment: {
          ...zero.baseRequest.productionVerificationResult.counterAssessment,
          previousCounter: 0,
          returnedCounter: 0,
          counterStatus: "unchanged-zero",
          counterAdvanced: false,
          counterUnchanged: true,
          futurePersistenceRequired: false
        }
      }
    });
    const unsupported = await fixture();
    const unsupportedResult = await persistVerifiedCredentialCounter({
      ...unsupported.baseRequest,
      operationId: "counter-persistence-unsupported",
      productionVerificationResult: {
        ...unsupported.baseRequest.productionVerificationResult,
        counterAssessment: {
          ...unsupported.baseRequest.productionVerificationResult.counterAssessment,
          counterStatus: "unsupported",
          counterAdvanced: false,
          futurePersistenceRequired: false
        }
      }
    });

    assert.equal(zeroResult.status, "approved", zeroResult.error?.details?.errors?.join("\n"));
    assert.equal(zeroResult.value.outcome, "counter_unchanged_accepted");
    assert.equal(zeroResult.value.counterPersisted, false);
    assert.equal(unsupportedResult.status, "denied");
    assert.match(unsupportedResult.error.details.errors.join(" "), /unsupported counter/i);
  });

  it("handles replay rejection, facade integration, audit redaction, and candidate counter resolution", async function () {
    const f = await fixture();
    const store = createEphemeralCredentialCounterPersistenceReplayStore();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const result = await persistVerifiedCredentialCounter(
      f.baseRequest,
      store,
      auditDraftCollector
    );
    const replay = await persistVerifiedCredentialCounter(
      {
        ...f.baseRequest,
        expectedEncryptedRegistryHash: undefined,
        expectedStoredCounter: 8,
        previousVerificationCounter: 8,
        verifiedReturnedCounter: 9
      },
      store,
      auditDraftCollector
    );
    const resolution = resolveCounterPersistenceRequirement({
      boundedTrustDecisionCandidate: f.baseRequest.boundedTrustDecisionCandidate,
      receipt: result.value
    });
    const apiFixture = await fixture();
    const api = createValidationOnlyRuntimeApi({
      credentialCounterPersistenceReplayStore: createEphemeralCredentialCounterPersistenceReplayStore(),
      auditDraftCollector
    });
    const viaFacade = await api.requestCredentialCounterPersistence(apiFixture.baseRequest);
    const auditJson = JSON.stringify(result.value.auditEventDraft);

    assert.equal(result.status, "approved");
    assert.equal(replay.status, "denied");
    assert.equal(resolution.counterRequirementSatisfied, true);
    assert.equal(resolution.activeTrustDecisionCreated, false);
    assert.equal(viaFacade.status, "approved", viaFacade.error?.details?.errors?.join("\n"));
    assert.equal(viaFacade.value.credentialCounterPersistenceReceipt.trustDecisionCreated, false);
    assert.equal(viaFacade.value.trustDecisionCandidateCounterResolution.counterRequirementSatisfied, true);
    assert.equal(auditDraftCollector.count() >= 1, true);
    assert.equal(auditJson.includes("phil_secret"), false);
    assert.equal(auditJson.includes("privateKey"), false);
    assert.equal(auditJson.includes("clientDataJSON"), false);
  });

  it("rejects invalid vault handle, registry integrity failure, and write failure", async function () {
    const invalidHandle = await fixture();
    const handleResult = await persistVerifiedCredentialCounter({
      ...invalidHandle.baseRequest,
      unlockedVaultHandle: {
        ...invalidHandle.baseRequest.unlockedVaultHandle,
        sessionId: "wrong-session"
      }
    });
    const integrity = await fixture();
    await integrity.backend.write("{bad-json");
    const integrityResult = await persistVerifiedCredentialCounter({
      ...integrity.baseRequest,
      expectedEncryptedRegistryHash: undefined
    });
    const writeFailure = await fixture();
    const failingBackend = {
      exists: () => writeFailure.backend.exists(),
      read: () => writeFailure.backend.read(),
      write: async () => { throw new Error("write failed"); }
    };
    const writeResult = await persistVerifiedCredentialCounter({
      ...writeFailure.baseRequest,
      storageBackend: failingBackend
    });

    assert.equal(handleResult.status, "denied");
    assert.equal(integrityResult.status, "denied");
    assert.equal(writeResult.status, "denied");
  });

  it("runs Alpha 0 credential counter persistence diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_credential_counter_persistence"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_credential_counter_persistence", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Credential counter persistence:/i);
    assert.match(textOutput, /persisted counter: 8/i);
    assert.match(textOutput, /only selected counter field changed: yes/i);
    assert.match(textOutput, /active Trust Decision created: no/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.credentialCounterPersistenceReceipt.outcome, "counter_persisted");
    assert.equal(parsed.credentialCounterPersistenceReceipt.persistedCounter, 8);
    assert.equal(parsed.credentialCounterPersistenceReceipt.trustDecisionCreated, false);
    assert.equal(parsed.trustDecisionCandidateCounterResolution.counterRequirementSatisfied, true);
  });
});
