const assert = require("node:assert/strict");
const crypto = require("node:crypto");

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
  createEphemeralUserSessionLifecycleStore,
  createEphemeralVaultUnlockConsumptionStore,
  createFixtureTrustManagerVerificationInputConsumer,
  createInMemoryAuditDraftCollector,
  createProductionAuthenticationRequest,
  createTrustManagerVerificationInput,
  createValidationOnlyRuntimeApi,
  requestPublicCredentialDirectory,
  requestSelectedCredentialPublicMaterial,
  runAlpha0Shell,
  transitionUserSessionWithVerifiedVaultUnlock,
  verifyDeviceVaultUnlock
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function publicKeyHex() {
  const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return `0x${Buffer.from(publicKey.export({ type: "spki", format: "der" })).toString("hex")}`;
}

function publicKeyHash(publicKey) {
  return `0x${crypto.createHash("sha256").update(Buffer.from(publicKey.slice(2), "hex")).digest("hex")}`;
}

function keyProvider(passphrase = "trust manager verification input passphrase") {
  return createLocalDevPassphraseKeyProvider({
    passphrase,
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
}

function partialSnapshot(sessionId = "trust-manager-input-session-1") {
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
    lastTransition: {
      event: "unlock_succeeded",
      previousState: "unlocking",
      nextState: "partially_unlocked",
      reason: "production-authentication-verified",
      transitionedAt: now,
      transitionRequestId: `${sessionId}:partial-unlock`
    },
    metadata: Object.freeze({
      ...snapshot.metadata,
      lifecycleAuthenticationFactorVerified: true,
      deviceVaultUnlocked: false,
      protectedStateAvailable: false,
      activeCapabilitiesAvailable: false,
      authorizationAvailable: false,
      strongerVaultUnlockRequired: true,
      persisted: false
    }),
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: false,
    grantsAuthority: false
  });
}

function credential(overrides = {}) {
  const key = overrides.publicKey ?? publicKeyHex();
  return Object.freeze({
    credentialId: overrides.credentialId ?? "cred-active",
    providerKind: overrides.providerKind ?? "webauthn_passkey",
    algorithm: overrides.algorithm ?? "ES256",
    label: overrides.label ?? "Primary passkey",
    createdAt: new Date().toISOString(),
    status: overrides.status ?? "active",
    signCount: 8,
    deviceType: "platform",
    transport: Object.freeze({
      transports: Object.freeze(["internal"]),
      authenticatorAttachment: "platform"
    }),
    priority: 1,
    deviceKeyId: "device-active",
    publicKey: key,
    publicKeyHash: publicKeyHash(key)
  });
}

function authRequest(input) {
  const result = createProductionAuthenticationRequest({
    requestId: input.requestId ?? "trust-manager-auth-request",
    purpose: input.purpose ?? "high_risk_action",
    providerId: input.providerId ?? "webauthn-provider-1",
    providerKind: input.providerKind ?? "webauthn_passkey",
    requirement: {
      purpose: input.requirementPurpose ?? input.purpose ?? "high_risk_action",
      provider: {
        providerKind: input.providerKind ?? "webauthn_passkey",
        providerId: input.providerId ?? "webauthn-provider-1",
        minimumAssurance: input.requiredAssurance ?? ["user_presence", "user_verification", "phishing_resistant"],
        userPresenceRequired: true,
        userVerificationRequired: true,
        phishingResistantRequired: true
      },
      challengeReference: {
        challengeReferenceId: input.challengeReferenceId ?? "challenge-ref-1",
        challengeBindingHash: "challenge-binding-1",
        createdAt: new Date().toISOString(),
        expiresAt: input.challengeExpiresAt ?? futureDate(),
        generatedChallenge: false
      },
      correlation: {
        sessionId: input.sessionId ?? "trust-manager-input-session-1",
        ownerCommitment: input.ownerCommitment,
        applicationId: input.applicationId ?? "ethereum-net",
        credentialId: input.credentialId ?? "cred-active",
        providerId: input.providerId ?? "webauthn-provider-1",
        auditCorrelationId: input.auditCorrelationId ?? "trust-manager-input-session-1:trust-manager-input"
      },
      expiresAt: input.expiresAt ?? futureDate(),
      requestedAssurance: input.requiredAssurance ?? ["user_presence", "user_verification", "phishing_resistant"]
    },
    expiresAt: input.expiresAt,
    metadata: {
      rpId: "philcore.local",
      origin: "https://philcore.local"
    }
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

async function fixture(overrides = {}) {
  const identity = derivePhilIdentityPublic(createPhilIdentityPrivate());
  const provider = keyProvider();
  const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
  const registryStore = createEncryptedDeviceIdentityRegistryStore({ backend, keyProvider: provider });
  const registry = createPhilCredentialRegistry({
    philIdentity: identity,
    credentials: [credential({
      status: overrides.credentialStatus,
      providerKind: overrides.credentialProviderKind,
      algorithm: overrides.credentialAlgorithm
    })]
  }).getSnapshot();
  await registryStore.saveRegistry(registry);
  const encryptedBlob = await backend.read();
  const sessionId = "trust-manager-input-session-1";
  const auditCorrelationId = `${sessionId}:selected-material`;
  const partial = partialSnapshot(sessionId);
  const unlock = await verifyDeviceVaultUnlock({
    requestId: "trust-manager-input-vault-unlock",
    lifecycleSnapshot: partial,
    identity,
    envelope: {
      envelopeId: "trust-manager-input-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "trust-manager-input-unlock-material",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    correlation: {
      sessionId,
      ownerCommitment: identity.ownerCommitment,
      lifecycleTransitionRequestId: `${sessionId}:vault-unlock-succeeded`,
      applicationId: "ethereum-net",
      auditCorrelationId
    },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    expectedAuditCorrelationId: auditCorrelationId,
    auditCorrelationId
  });
  assert.equal(unlock.status, "approved", unlock.error?.details?.errors?.join("\n"));
  const transition = transitionUserSessionWithVerifiedVaultUnlock({
    requestId: "trust-manager-input-vault-session-unlock",
    lifecycleSnapshot: partial,
    transitionRequest: {
      transitionRequestId: `${sessionId}:vault-unlock-succeeded`,
      event: "unlock_succeeded"
    },
    vaultUnlockResult: unlock.value,
    consumptionStore: createEphemeralVaultUnlockConsumptionStore(),
    auditCorrelationId
  });
  assert.equal(transition.status, "approved", transition.error?.details?.errors?.join("\n"));
  const directory = await requestPublicCredentialDirectory({
    requestId: "trust-manager-input-directory",
    operation: "list_credentials",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    identity,
    envelope: {
      envelopeId: "trust-manager-input-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "trust-manager-input-directory-material",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    query: { limit: 10 },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    auditCorrelationId
  });
  assert.equal(directory.status, "approved", directory.error?.details?.errors?.join("\n"));
  const material = await requestSelectedCredentialPublicMaterial({
    requestId: "trust-manager-input-selected-material",
    operation: "materialize_selected_credential_public_data",
    credentialId: "cred-active",
    verificationContext: overrides.credentialStatus === "recovery-only" ? "recovery" : undefined,
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    publicCredentialDirectory: directory.value,
    identity,
    envelope: {
      envelopeId: "trust-manager-input-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "trust-manager-input-selected-material-key",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    auditCorrelationId
  });
  assert.equal(material.status, "approved", material.error?.details?.errors?.join("\n"));
  const tmAuditCorrelationId = `${sessionId}:trust-manager-input`;
  const baseAuthRequest = authRequest({
    ownerCommitment: identity.ownerCommitment,
    auditCorrelationId: tmAuditCorrelationId
  });
  const userSessionContext = {
    sessionId,
    ownerCommitment: identity.ownerCommitment,
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: [],
    pendingIntentIds: [],
    policyMode: "default",
    metadata: {
      deviceVaultUnlocked: true,
      protectedStateAvailable: true
    }
  };
  const baseRequest = {
    requestId: "trust-manager-verification-input-request",
    selectedCredentialVerificationProfile: material.value.verificationProfile,
    selectedCredentialVerificationHandle: material.value.verificationHandle,
    productionAuthenticationRequest: baseAuthRequest,
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    userSessionContext,
    applicationId: "ethereum-net",
    sessionId,
    ownerCommitment: identity.ownerCommitment,
    credentialId: "cred-active",
    providerId: "webauthn-provider-1",
    authenticationPurpose: "high_risk_action",
    challengeReferenceId: "challenge-ref-1",
    requiredAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    auditCorrelationId: tmAuditCorrelationId
  };
  return {
    identity,
    partial,
    unlockedSnapshot: transition.value.transitionResult.snapshot,
    material: material.value,
    authRequest: baseAuthRequest,
    userSessionContext,
    baseRequest
  };
}

function assertNoAuthority(value) {
  assert.equal(value.verificationPerformed, false);
  assert.equal(value.trustDecisionCreated, false);
  assert.equal(value.authenticationPerformed, false);
  assert.equal(value.grantsAuthority, false);
  assert.equal(value.vaultHandleExposed, false);
  assert.equal(value.registryAccessProvided, false);
  assert.equal(value.privateMaterialIncluded, false);
  assert.equal(value.persisted, false);
}

describe("PhilCore Trust Manager verification input bridge", function () {
  it("creates a bounded verification input from selected public material and an explicit auth request", async function () {
    const f = await fixture();
    const result = createTrustManagerVerificationInput(f.baseRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.outcome, "verification_input_created");
    assert.equal(result.value.verificationInput.credentialSafeReference, f.material.summary.credentialSafeReference);
    assert.equal(result.value.verificationInput.providerKind, "webauthn_passkey");
    assert.equal(result.value.verificationInput.publicKeyAlgorithm, "ES256");
    assert.equal(result.value.verificationInput.authenticationPurpose, "high_risk_action");
    assert.equal(result.value.verificationInput.challengeBinding.challengeReferenceId, "challenge-ref-1");
    assert.equal(result.value.verificationInput.assuranceRequirement.sufficient, true);
    assertNoAuthority(result.value);
    assertNoAuthority(result.value.verificationInput);
    assert.equal(Object.isFrozen(result.value), true);
    assert.equal(Object.isFrozen(result.value.verificationInput), true);
  });

  it("rejects credential/profile, provider, algorithm, session, owner, application, challenge, and purpose mismatches", async function () {
    const f = await fixture();
    const cases = [
      ["credential", { credentialId: "wrong-credential" }],
      ["provider", { providerId: "wrong-provider" }],
      ["algorithm", {
        selectedCredentialVerificationProfile: {
          ...f.baseRequest.selectedCredentialVerificationProfile,
          publicKeyAlgorithm: "RS256"
        }
      }],
      ["session", { sessionId: "wrong-session" }],
      ["owner", { ownerCommitment: "0xdead" }],
      ["application", { applicationId: "nft-manager" }],
      ["challenge", { challengeReferenceId: "wrong-challenge" }],
      ["purpose", { authenticationPurpose: "backup_export" }]
    ];

    for (const [name, patch] of cases) {
      const result = createTrustManagerVerificationInput({
        ...f.baseRequest,
        requestId: `trust-manager-input-${name}-mismatch`,
        ...patch
      });
      assert.equal(result.status, "denied", name);
    }
  });

  it("rejects expired handle, expired auth request, ineligible lifecycle, vault metadata, and recovery-only ordinary use", async function () {
    const f = await fixture();
    const expiredHandle = createTrustManagerVerificationInput({
      ...f.baseRequest,
      selectedCredentialVerificationHandle: {
        ...f.baseRequest.selectedCredentialVerificationHandle,
        expiresAt: pastDate()
      }
    });
    const expiredAuth = createTrustManagerVerificationInput({
      ...f.baseRequest,
      productionAuthenticationRequest: authRequest({
        ownerCommitment: f.identity.ownerCommitment,
        auditCorrelationId: f.baseRequest.auditCorrelationId,
        expiresAt: pastDate()
      })
    });
    const partial = createTrustManagerVerificationInput({
      ...f.baseRequest,
      lifecycleSnapshot: f.partial
    });
    const vaultNotUnlocked = createTrustManagerVerificationInput({
      ...f.baseRequest,
      lifecycleSnapshot: {
        ...f.baseRequest.lifecycleSnapshot,
        metadata: {
          ...f.baseRequest.lifecycleSnapshot.metadata,
          deviceVaultUnlocked: false
        }
      }
    });
    const recovery = await fixture({ credentialStatus: "recovery-only" });
    const recoveryOrdinary = createTrustManagerVerificationInput(recovery.baseRequest);
    const recoveryExplicit = createTrustManagerVerificationInput({
      ...recovery.baseRequest,
      productionAuthenticationRequest: authRequest({
        ownerCommitment: recovery.identity.ownerCommitment,
        auditCorrelationId: recovery.baseRequest.auditCorrelationId,
        purpose: "recovery_approval",
        requirementPurpose: "recovery_approval"
      }),
      authenticationPurpose: "recovery_approval"
    });

    assert.equal(expiredHandle.status, "denied");
    assert.equal(expiredAuth.status, "denied");
    assert.equal(partial.status, "denied");
    assert.equal(vaultNotUnlocked.status, "denied");
    assert.equal(recoveryOrdinary.status, "denied");
    assert.equal(recoveryExplicit.status, "approved", recoveryExplicit.error?.details?.errors?.join("\n"));
  });

  it("rejects unsupported assurance and keeps audit output redacted", async function () {
    const f = await fixture();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const insufficient = createTrustManagerVerificationInput({
      ...f.baseRequest,
      requiredAssurance: ["hardware_backed"]
    }, auditDraftCollector);
    const valid = createTrustManagerVerificationInput({
      ...f.baseRequest,
      requestId: "trust-manager-verification-input-valid-after-insufficient"
    }, auditDraftCollector);
    const json = JSON.stringify(valid.value);
    const auditJson = JSON.stringify(valid.value.auditEventDraft);

    assert.equal(insufficient.status, "denied");
    assert.equal(valid.status, "approved");
    assert.equal(auditJson.includes(valid.value.verificationInput.verificationKey.publicKey), false);
    assert.equal(json.includes("unlockedVaultHandle"), false);
    assert.equal(json.includes("rawVault"), false);
    assert.equal(json.includes("privateKey"), false);
    assert.equal(json.includes("credentialRecordContents"), false);
    assert.equal(json.includes("authenticatorData"), false);
    assert.equal(json.includes("clientDataJSON"), false);
    assert.equal(json.includes("rawSignature"), false);
    assert.equal(auditDraftCollector.count() >= 1, true);
  });

  it("exposes a fixture consumer that accepts shape only without vault access, enumeration, or authority", async function () {
    const f = await fixture();
    const result = createTrustManagerVerificationInput(f.baseRequest);
    const consumer = createFixtureTrustManagerVerificationInputConsumer();
    const accepted = consumer.acceptVerificationInput(result.value.verificationInput);

    assert.equal(accepted.status, "accepted");
    assert.equal(accepted.trustDecisionCreated, false);
    assert.equal(accepted.authenticationPerformed, false);
    assert.equal(accepted.grantsAuthority, false);
    assert.equal(accepted.vaultHandleAccessed, false);
    assert.equal(accepted.registryEnumerated, false);
    assert.equal(accepted.persisted, false);
  });

  it("integrates through the Runtime facade without executing auth, trust, proof, adapter, or authority", async function () {
    const f = await fixture();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({ auditDraftCollector });
    const viaFacade = api.requestTrustManagerVerificationInput(f.baseRequest);

    assert.equal(viaFacade.status, "approved", viaFacade.error?.details?.errors?.join("\n"));
    assert.equal(viaFacade.value.trustManagerVerificationInput.outcome, "verification_input_created");
    assertNoAuthority(viaFacade.value.trustManagerVerificationInput);
    assert.equal(auditDraftCollector.count() >= 2, true);
  });

  it("runs Alpha 0 Trust Manager verification input diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_trust_manager_verification_input"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_trust_manager_verification_input", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Trust Manager verification input:/i);
    assert.match(textOutput, /challenge correlation: matched/i);
    assert.match(textOutput, /authentication performed: no/i);
    assert.match(textOutput, /Trust Decision made: no/i);
    assert.match(textOutput, /vault access granted to Trust Manager: no/i);
    assert.match(textOutput, /authority granted: no/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.finalState, "unlocked");
    assert.equal(parsed.trustManagerVerificationInput.status, "verification_input_created");
    assert.equal(parsed.trustManagerVerificationInput.challengeCorrelationStatus, "matched");
    assert.equal(parsed.trustManagerVerificationInput.authenticationPerformed, false);
    assert.equal(parsed.trustManagerVerificationInput.trustDecisionCreated, false);
    assert.equal(parsed.trustManagerVerificationInput.vaultHandleExposed, false);
    assert.equal(parsed.trustManagerVerificationInput.grantsAuthority, false);
  });
});
