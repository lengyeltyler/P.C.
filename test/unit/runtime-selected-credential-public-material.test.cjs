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
  createInMemoryAuditDraftCollector,
  createValidationOnlyRuntimeApi,
  requestPublicCredentialDirectory,
  requestSelectedCredentialPublicMaterial,
  runAlpha0Shell,
  sanitizeCredentialRecordToVerificationProfile,
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
  const spki = publicKey.export({ type: "spki", format: "der" });
  return `0x${Buffer.from(spki).toString("hex")}`;
}

function publicKeyHash(publicKey) {
  return `0x${crypto.createHash("sha256").update(Buffer.from(publicKey.slice(2), "hex")).digest("hex")}`;
}

function keyProvider(passphrase = "selected credential public material passphrase") {
  return createLocalDevPassphraseKeyProvider({
    passphrase,
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
}

function partialSnapshot(sessionId = "selected-material-session-1") {
  const store = createEphemeralUserSessionLifecycleStore();
  store.initialize({
    sessionId,
    transitionRequestId: `${sessionId}:initialize`
  });
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

function credential(input) {
  const key = input.publicKey ?? publicKeyHex();
  const base = {
    credentialId: input.credentialId,
    providerKind: input.providerKind ?? "webauthn_passkey",
    algorithm: input.algorithm ?? "ES256",
    label: input.label,
    createdAt: input.createdAt ?? new Date().toISOString(),
    lastUsedAt: input.lastUsedAt,
    status: input.status,
    signCount: input.signCount ?? 1,
    deviceType: input.deviceType ?? "platform",
    transport: Object.freeze({
      transports: Object.freeze(input.transports ?? ["internal"]),
      authenticatorAttachment: input.authenticatorAttachment ?? "platform"
    }),
    priority: input.priority ?? 1,
    deviceKeyId: input.deviceKeyId,
    publicKey: key,
    publicKeyHash: input.publicKeyHash ?? publicKeyHash(key)
  };
  return Object.freeze(input.includeSecretShapedFields ? {
    ...base,
    privateKey: "must-not-leak",
    clientDataJSON: "must-not-leak",
    authenticatorData: "must-not-leak",
    assertionSignature: "must-not-leak",
    encryptedCredentialBlob: "must-not-leak",
    recoverySecret: "must-not-leak",
    arbitraryMetadata: { secret: "must-not-leak" }
  } : base);
}

function credentials(overrides = {}) {
  return [
    credential({
      credentialId: "cred-active",
      label: "Primary passkey",
      status: overrides.activeStatus ?? "active",
      providerKind: overrides.activeProviderKind,
      algorithm: overrides.activeAlgorithm,
      publicKey: overrides.activePublicKey,
      deviceKeyId: "device-active",
      includeSecretShapedFields: overrides.includeSecretShapedFields
    }),
    credential({
      credentialId: "cred-recovery",
      label: "Recovery passkey",
      status: "recovery-only",
      deviceKeyId: "device-recovery"
    }),
    credential({
      credentialId: "cred-revoked",
      label: "Revoked passkey",
      status: "revoked",
      deviceKeyId: "device-revoked"
    }),
    credential({
      credentialId: "cred-archived",
      label: "Archived passkey",
      status: "archived",
      deviceKeyId: "device-archived"
    })
  ];
}

async function fixture(overrides = {}) {
  const identity = overrides.identity
    ?? derivePhilIdentityPublic(createPhilIdentityPrivate());
  const provider = overrides.provider ?? keyProvider();
  const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
  const registryStore = createEncryptedDeviceIdentityRegistryStore({
    backend,
    keyProvider: provider
  });
  const registry = createPhilCredentialRegistry({
    philIdentity: identity,
    credentials: overrides.credentials ?? credentials(overrides)
  }).getSnapshot();
  await registryStore.saveRegistry(registry);
  const encryptedBlob = await backend.read();
  const sessionId = overrides.sessionId ?? "selected-material-session-1";
  const auditCorrelationId = overrides.auditCorrelationId ?? `${sessionId}:selected-material`;
  const partial = partialSnapshot(sessionId);
  const unlock = await verifyDeviceVaultUnlock({
    requestId: "selected-material-vault-unlock",
    lifecycleSnapshot: partial,
    identity,
    envelope: {
      envelopeId: "selected-material-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment,
      expiresAt: overrides.handleExpiresAt
    },
    unlockMaterial: {
      materialId: "selected-material-unlock-material",
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
    expiresAt: overrides.handleExpiresAt,
    auditCorrelationId
  });
  assert.equal(unlock.status, "approved", unlock.error?.details?.errors?.join("\n"));
  const transition = transitionUserSessionWithVerifiedVaultUnlock({
    requestId: "selected-material-vault-session-unlock",
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

  const baseDirectoryRequest = {
    requestId: "selected-material-directory-request",
    operation: "list_credentials",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    identity,
    envelope: {
      envelopeId: "selected-material-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "selected-material-directory-material",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    query: {
      limit: 10
    },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    auditCorrelationId
  };
  const directory = await requestPublicCredentialDirectory(baseDirectoryRequest);
  assert.equal(directory.status, "approved", directory.error?.details?.errors?.join("\n"));

  const baseRequest = {
    requestId: "selected-material-request-1",
    operation: "materialize_selected_credential_public_data",
    credentialId: overrides.credentialId ?? "cred-active",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    publicCredentialDirectory: directory.value,
    identity,
    envelope: {
      envelopeId: "selected-material-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment
    },
    unlockMaterial: {
      materialId: "selected-material-material",
      keyProvider: provider,
      providerKind: provider.providerKind,
      unsafeForProduction: provider.unsafeForProduction
    },
    expectedOwnerCommitment: identity.ownerCommitment,
    expectedSessionId: sessionId,
    auditCorrelationId
  };

  return {
    identity,
    provider,
    encryptedBlob,
    partial,
    unlockedSnapshot: transition.value.transitionResult.snapshot,
    handle: unlock.value.unlockedVaultHandle,
    directory: directory.value,
    baseRequest
  };
}

function assertNonAuthority(value) {
  assert.equal(value.containsPrivateMaterial, false);
  assert.equal(value.containsVaultKey, false);
  assert.equal(value.containsPhilSecret, false);
  assert.equal(value.containsRawAssertionPayload, false);
  assert.equal(value.containsRawRegistrationPayload, false);
  assert.equal(value.containsAuthorization, false);
  assert.equal(value.grantsAuthority, false);
  assert.equal(value.verificationPerformed, false);
  assert.equal(value.authenticationPerformed, false);
  assert.equal(value.webAuthnInvoked, false);
  assert.equal(value.signatureVerified, false);
  assert.equal(value.credentialCounterMutated, false);
  assert.equal(value.trustDecisionCreated, false);
  assert.equal(value.activeCapabilityCreated, false);
  assert.equal(value.sessionKeyCreated, false);
  assert.equal(value.authorizationCreated, false);
  assert.equal(value.persisted, false);
}

describe("PhilCore selected credential public material boundary", function () {
  it("materializes one allowlisted verification-ready public profile", async function () {
    const f = await fixture();
    const result = await requestSelectedCredentialPublicMaterial(f.baseRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.operation, "materialize_selected_credential_public_data");
    assert.equal(result.value.verificationProfile.credentialId, "cred-active");
    assert.equal(result.value.verificationProfile.providerKind, "webauthn_passkey");
    assert.equal(result.value.verificationProfile.publicKeyAlgorithm, "ES256");
    assert.equal(result.value.verificationProfile.supportedVerificationMethods[0], "webauthn_assertion");
    assert.equal(result.value.verificationHandle.singleCredentialOnly, true);
    assert.equal(result.value.evidence.registryRecordReturned, false);
    assert.equal(result.value.evidence.verifierReadyPublicKeyIncluded, true);
    assertNonAuthority(result.value);
    assert.equal(Object.isFrozen(result.value), true);
    assert.equal(Object.isFrozen(result.value.verificationProfile), true);
  });

  it("rejects missing, multiple, wildcard, and not-found selectors", async function () {
    const f = await fixture();
    const missing = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      requestId: "selected-material-missing-selector",
      credentialId: undefined
    });
    const multiple = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      requestId: "selected-material-multiple-selector",
      credentialIds: ["cred-active", "cred-recovery"]
    });
    const wildcard = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      requestId: "selected-material-wildcard-selector",
      wildcardSelector: true
    });
    const notFound = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      requestId: "selected-material-not-found",
      credentialId: "cred-missing"
    });

    assert.equal(missing.status, "denied");
    assert.equal(multiple.status, "denied");
    assert.equal(wildcard.status, "denied");
    assert.equal(notFound.status, "denied");
  });

  it("rejects locked or partial sessions, expired handles, and owner/session/audit mismatches", async function () {
    const f = await fixture();
    const partial = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      lifecycleSnapshot: f.partial
    });
    const expired = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      unlockedVaultHandle: {
        ...f.baseRequest.unlockedVaultHandle,
        expiresAt: pastDate()
      }
    });
    const ownerMismatch = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      expectedOwnerCommitment: "0xdead"
    });
    const sessionMismatch = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      expectedSessionId: "wrong-session"
    });
    const auditMismatch = await requestSelectedCredentialPublicMaterial({
      ...f.baseRequest,
      expectedAuditCorrelationId: "wrong-audit"
    });

    assert.equal(partial.status, "denied");
    assert.equal(expired.status, "denied");
    assert.equal(ownerMismatch.status, "denied");
    assert.equal(sessionMismatch.status, "denied");
    assert.equal(auditMismatch.status, "denied");
  });

  it("enforces lifecycle, provider, algorithm, and public verification material boundaries", async function () {
    const revoked = await fixture({ credentialId: "cred-revoked" });
    const archived = await fixture({ credentialId: "cred-archived" });
    const recoveryOrdinary = await fixture({ credentialId: "cred-recovery" });
    const unsupportedProvider = await fixture({ activeProviderKind: "hardware_key" });
    const unsupportedAlgorithm = await fixture({ activeAlgorithm: "RS256" });
    const malformedPublicKey = await fixture({ activePublicKey: "0x1234" });

    const revokedResult = await requestSelectedCredentialPublicMaterial(revoked.baseRequest);
    const archivedResult = await requestSelectedCredentialPublicMaterial(archived.baseRequest);
    const recoveryOrdinaryResult = await requestSelectedCredentialPublicMaterial(recoveryOrdinary.baseRequest);
    const recoveryExplicitResult = await requestSelectedCredentialPublicMaterial({
      ...recoveryOrdinary.baseRequest,
      requestId: "selected-material-recovery-context",
      verificationContext: "recovery"
    });
    const providerResult = await requestSelectedCredentialPublicMaterial(unsupportedProvider.baseRequest);
    const algorithmResult = await requestSelectedCredentialPublicMaterial(unsupportedAlgorithm.baseRequest);
    const malformedPublicKeyResult = await requestSelectedCredentialPublicMaterial(malformedPublicKey.baseRequest);

    assert.equal(revokedResult.status, "denied");
    assert.equal(archivedResult.status, "denied");
    assert.equal(recoveryOrdinaryResult.status, "denied");
    assert.equal(recoveryExplicitResult.status, "approved", recoveryExplicitResult.error?.details?.errors?.join("\n"));
    assert.equal(providerResult.status, "denied");
    assert.equal(algorithmResult.status, "denied");
    assert.equal(malformedPublicKeyResult.status, "denied");
  });

  it("uses an explicit allowlist and does not leak private, encrypted, raw WebAuthn, or arbitrary metadata fields", async function () {
    const f = await fixture();
    const result = await requestSelectedCredentialPublicMaterial(f.baseRequest);
    const json = JSON.stringify(result.value);
    const directProfile = sanitizeCredentialRecordToVerificationProfile({
      credential: credential({
        credentialId: "cred-secret-source",
        label: "Secret source",
        status: "active",
        includeSecretShapedFields: true
      }),
      ownerCommitment: f.identity.ownerCommitment
    });

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(Object.keys(directProfile).includes("privateKey"), false);
    assert.equal(Object.keys(directProfile).includes("encryptedCredentialBlob"), false);
    assert.equal(Object.keys(directProfile).includes("clientDataJSON"), false);
    assert.equal(Object.keys(directProfile).includes("authenticatorData"), false);
    assert.equal(Object.keys(directProfile).includes("assertionSignature"), false);
    assert.equal(Object.keys(directProfile).includes("arbitraryMetadata"), false);
    assert.equal(json.includes("must-not-leak"), false);
    assert.equal(json.includes("privateKey"), false);
    assert.equal(json.includes("encryptedCredentialBlob"), false);
    assert.equal(json.includes("clientDataJSON"), false);
    assert.equal(json.includes("authenticatorData"), false);
    assert.equal(json.includes("assertionSignature"), false);
    assert.equal(result.value.auditEventDraft.redactedDetails.containsPublicKeyBytes, false);
  });

  it("integrates through the Runtime facade and audit draft collector without creating authority", async function () {
    const f = await fixture();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({ auditDraftCollector });
    const viaFacade = await api.requestSelectedCredentialPublicMaterial(f.baseRequest);

    assert.equal(viaFacade.status, "approved", viaFacade.error?.details?.errors?.join("\n"));
    assert.equal(viaFacade.value.selectedCredentialPublicMaterial.verificationProfile.credentialId, "cred-active");
    assert.equal(auditDraftCollector.count() >= 2, true);
    assertNonAuthority(viaFacade.value.selectedCredentialPublicMaterial);
  });

  it("runs Alpha 0 selected credential public material diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_selected_credential_public_material"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_selected_credential_public_material", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Selected credential public material:/i);
    assert.match(textOutput, /verification handle created: yes/i);
    assert.match(textOutput, /raw public key bytes: not printed/i);
    assert.match(textOutput, /private credential material: no/i);
    assert.match(textOutput, /authentication performed: no/i);
    assert.match(textOutput, /Trust Decision made: no/i);
    assert.match(textOutput, /authority granted: no/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.finalState, "unlocked");
    assert.equal(parsed.selectedCredentialPublicMaterial.status, "material_created");
    assert.equal(parsed.selectedCredentialPublicMaterial.verificationHandleCreated, true);
    assert.equal(parsed.selectedCredentialPublicMaterial.containsPrivateMaterial, false);
    assert.equal(parsed.selectedCredentialPublicMaterial.containsRawAssertionPayload, false);
    assert.equal(parsed.selectedCredentialPublicMaterial.trustDecisionCreated, false);
    assert.equal(parsed.selectedCredentialPublicMaterial.grantsAuthority, false);
    assert.equal(JSON.stringify(parsed).includes("webauthn_spki_public_key_hex"), false);
  });
});
