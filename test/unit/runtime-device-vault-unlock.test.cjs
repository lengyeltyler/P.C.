const assert = require("node:assert/strict");

const {
  createEncryptedDeviceIdentityRegistryStore,
  createInMemoryDeviceIdentityRegistryStorageBackend,
  createLocalDevPassphraseKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");
const {
  PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_VERSION,
  DEFAULT_PHIL_DEVICE_IDENTITY_ROTATION_POLICY
} = require("../../apps/phil-device-sdk/src/deviceIdentityKeyLifecycle.ts");
const {
  createPhilIdentityPrivate,
  derivePhilIdentityPublic
} = require("../../apps/phil-device-sdk/src/identity.ts");
const {
  createEphemeralUserSessionLifecycleStore,
  createEphemeralVaultUnlockConsumptionStore,
  createInMemoryAuditDraftCollector,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  deriveUserSessionContextFromVerifiedVaultUnlock,
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

function keyProvider(passphrase = "correct test passphrase") {
  return createLocalDevPassphraseKeyProvider({
    passphrase,
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
}

function partialSnapshot(sessionId = "vault-session-1") {
  const store = createEphemeralUserSessionLifecycleStore();
  const initialized = store.initialize({
    sessionId,
    transitionRequestId: `${sessionId}:initialize`
  });
  assert.equal(initialized.status, "initialized");
  const unlocking = store.requestTransition({
    transitionRequestId: `${sessionId}:request-unlock`,
    event: "request_unlock"
  });
  assert.equal(unlocking.status, "transitioned");
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

function lockedSnapshot(sessionId = "vault-session-1") {
  const store = createEphemeralUserSessionLifecycleStore();
  store.initialize({
    sessionId,
    transitionRequestId: `${sessionId}:initialize`
  });
  return store.getSnapshot();
}

async function vaultFixture(overrides = {}) {
  const identity = overrides.identity
    ?? derivePhilIdentityPublic(createPhilIdentityPrivate());
  const provider = overrides.provider ?? keyProvider();
  const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
  const store = createEncryptedDeviceIdentityRegistryStore({
    backend,
    keyProvider: provider
  });
  const registry = await store.createNewRegistry(identity);
  await store.saveRegistry(registry);
  const encryptedBlob = await backend.read();
  const sessionId = overrides.sessionId ?? "vault-session-1";
  const auditCorrelationId = overrides.auditCorrelationId ?? `${sessionId}:vault-unlock`;
  const snapshot = overrides.lifecycleSnapshot ?? partialSnapshot(sessionId);
  return {
    identity,
    provider,
    encryptedBlob,
    snapshot,
    request: {
      requestId: overrides.requestId ?? "vault-unlock-request-1",
      lifecycleSnapshot: snapshot,
      identity,
      envelope: {
        envelopeId: overrides.envelopeId ?? "vault-envelope-1",
        encryptedBlob: overrides.encryptedBlob ?? encryptedBlob,
        ownerCommitment: overrides.envelopeOwnerCommitment ?? identity.ownerCommitment,
        keyVersion: overrides.keyVersion,
        integrityHash: overrides.integrityHash,
        expiresAt: overrides.envelopeExpiresAt
      },
      unlockMaterial: {
        materialId: "vault-unlock-material-1",
        keyProvider: overrides.unlockProvider ?? provider,
        keyVersion: overrides.keyVersion,
        providerKind: (overrides.unlockProvider ?? provider).providerKind,
        unsafeForProduction: (overrides.unlockProvider ?? provider).unsafeForProduction,
        expiresAt: overrides.unlockMaterialExpiresAt
      },
      correlation: {
        sessionId: overrides.correlationSessionId ?? sessionId,
        ownerCommitment: overrides.correlationOwnerCommitment ?? identity.ownerCommitment,
        lifecycleTransitionRequestId: overrides.transitionRequestId ?? `${sessionId}:vault-unlock-succeeded`,
        applicationId: "ethereum-net",
        auditCorrelationId
      },
      keyLifecycle: overrides.keyLifecycle,
      expectedOwnerCommitment: overrides.expectedOwnerCommitment ?? identity.ownerCommitment,
      expectedSessionId: overrides.expectedSessionId ?? sessionId,
      expectedAuditCorrelationId: overrides.expectedAuditCorrelationId ?? auditCorrelationId,
      expectedIntegrityHash: overrides.expectedIntegrityHash,
      expiresAt: overrides.expiresAt,
      auditCorrelationId,
      metadata: overrides.metadata
    }
  };
}

function lifecycle(status = "active") {
  return {
    version: PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_VERSION,
    storageKeys: [{
      keyVersion: 1,
      createdAt: new Date().toISOString(),
      status,
      providerType: "local-dev-passphrase-scrypt-device-registry-key-test-only-v1",
      algorithm: "aes-256-gcm",
      registryVersion: 1
    }],
    backupKeys: [],
    policy: DEFAULT_PHIL_DEVICE_IDENTITY_ROTATION_POLICY,
    migrationVersion: 1
  };
}

async function successfulUnlock(overrides = {}) {
  const fixture = await vaultFixture(overrides);
  const result = await verifyDeviceVaultUnlock(fixture.request);
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return {
    ...fixture,
    result
  };
}

function assertNoAuthority(value) {
  assert.equal(value.philSecretExposed, false);
  assert.equal(value.rawVaultKeyExposed, false);
  assert.equal(value.applicationCredentialsLoaded, false);
  assert.equal(value.activeCapabilityCreated, false);
  assert.equal(value.sessionKeyCreated, false);
  assert.equal(value.authorizationCreated, false);
  assert.equal(value.persistedRuntimeState, false);
}

describe("PhilCore controlled Device Vault unlock boundary", function () {
  it("verifies an explicit in-memory vault envelope with existing registry validation", async function () {
    const { result } = await successfulUnlock();

    assert.equal(result.value.status, "vault_unlock_verified");
    assert.equal(result.value.outcome, "vault_unlock_verified");
    assert.equal(result.value.deviceVaultUnlocked, true);
    assert.equal(result.value.protectedStateAvailable, true);
    assert.equal(result.value.unlockedVaultHandle.processLocal, true);
    assert.equal(result.value.unlockedVaultHandle.serializable, false);
    assert.equal(result.value.unlockedVaultHandle.applicationAccessible, false);
    assert.equal(result.value.evidenceSummary.registryAuthenticated, true);
    assert.equal(result.value.evidenceSummary.plaintextReturned, false);
    assertNoAuthority(result.value);
  });

  it("rejects malformed, unsupported, mismatched, incorrect, expired, and inactive-key inputs", async function () {
    const base = await vaultFixture();
    const malformed = await verifyDeviceVaultUnlock({
      ...base.request,
      envelope: { ...base.request.envelope, encryptedBlob: "{bad json" }
    });
    const unsupported = await verifyDeviceVaultUnlock({
      ...base.request,
      envelope: {
        ...base.request.envelope,
        encryptedBlob: JSON.stringify({
          ...JSON.parse(base.encryptedBlob),
          version: 999
        })
      }
    });
    const wrongOwner = await verifyDeviceVaultUnlock({
      ...base.request,
      expectedOwnerCommitment: "0xdead"
    });
    const wrongSession = await verifyDeviceVaultUnlock({
      ...base.request,
      expectedSessionId: "wrong-session"
    });
    const wrongAudit = await verifyDeviceVaultUnlock({
      ...base.request,
      expectedAuditCorrelationId: "wrong-audit"
    });
    const wrongIntegrity = await verifyDeviceVaultUnlock({
      ...base.request,
      expectedIntegrityHash: "0xdead"
    });
    const wrongMaterial = await verifyDeviceVaultUnlock({
      ...base.request,
      unlockMaterial: {
        ...base.request.unlockMaterial,
        keyProvider: keyProvider("wrong passphrase")
      }
    });
    const expired = await verifyDeviceVaultUnlock({
      ...base.request,
      expiresAt: pastDate()
    });
    const revoked = await verifyDeviceVaultUnlock({
      ...base.request,
      keyLifecycle: lifecycle("revoked"),
      envelope: { ...base.request.envelope, keyVersion: 1 },
      unlockMaterial: { ...base.request.unlockMaterial, keyVersion: 1 }
    });

    for (const entry of [
      malformed,
      unsupported,
      wrongOwner,
      wrongSession,
      wrongAudit,
      wrongIntegrity,
      wrongMaterial,
      expired,
      revoked
    ]) {
      assert.equal(entry.status, "denied");
      assert.equal(entry.value, undefined);
    }
  });

  it("requires a partially_unlocked lifecycle snapshot", async function () {
    const fixture = await vaultFixture({
      lifecycleSnapshot: lockedSnapshot("vault-session-1")
    });
    const result = await verifyDeviceVaultUnlock(fixture.request);

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some((error) => error.includes("partially_unlocked")));
  });

  it("transitions only from partially_unlocked to unlocked after verified vault unlock", async function () {
    const { snapshot, result } = await successfulUnlock();
    const transitioned = transitionUserSessionWithVerifiedVaultUnlock({
      requestId: "verified-vault-session-unlock-1",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "vault-session-1:vault-unlock-succeeded",
        event: "unlock_succeeded"
      },
      vaultUnlockResult: result.value,
      consumptionStore: createEphemeralVaultUnlockConsumptionStore()
    });

    assert.equal(transitioned.status, "approved", transitioned.error?.details?.errors?.join("\n"));
    assert.equal(transitioned.value.transitionResult.previousState, "partially_unlocked");
    assert.equal(transitioned.value.transitionResult.nextState, "unlocked");
    assert.equal(transitioned.value.transitionResult.snapshot.state, "unlocked");
    assert.equal(transitioned.value.transitionResult.snapshot.unlocksVault, true);
    assert.equal(transitioned.value.transitionResult.snapshot.grantsAuthority, false);
    assert.equal(transitioned.value.transitionResult.snapshot.metadata.deviceVaultUnlocked, true);
    assert.equal(transitioned.value.transitionResult.snapshot.metadata.protectedStateAvailable, true);
    assert.equal(transitioned.value.transitionResult.snapshot.metadata.activeCapabilitiesAvailable, false);
    assert.equal(transitioned.value.transitionResult.snapshot.metadata.authorizationAvailable, false);
    assertNoAuthority(transitioned.value);
  });

  it("rejects replayed and expired vault unlock results", async function () {
    const { snapshot, result } = await successfulUnlock({ expiresAt: futureDate() });
    const store = createEphemeralVaultUnlockConsumptionStore();
    const request = {
      requestId: "verified-vault-session-unlock-1",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "vault-session-1:vault-unlock-succeeded",
        event: "unlock_succeeded"
      },
      vaultUnlockResult: result.value,
      consumptionStore: store
    };
    const first = transitionUserSessionWithVerifiedVaultUnlock(request);
    const second = transitionUserSessionWithVerifiedVaultUnlock(request);
    const expired = transitionUserSessionWithVerifiedVaultUnlock({
      ...request,
      vaultUnlockResult: {
        ...result.value,
        vaultUnlockResultId: "expired-result",
        expiresAt: pastDate()
      },
      consumptionStore: createEphemeralVaultUnlockConsumptionStore()
    });

    assert.equal(first.status, "approved");
    assert.equal(second.status, "denied");
    assert.ok(second.error.details.errors.some((error) => error.includes("replayed")));
    assert.equal(expired.status, "denied");
    assert.ok(expired.error.details.errors.some((error) => error.includes("expired")));
  });

  it("derives unlocked User Session context without mutating capabilities", async function () {
    const { snapshot, result } = await successfulUnlock();
    const transitioned = transitionUserSessionWithVerifiedVaultUnlock({
      requestId: "verified-vault-session-unlock-1",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "vault-session-1:vault-unlock-succeeded",
        event: "unlock_succeeded"
      },
      vaultUnlockResult: result.value
    });
    const baseContext = createUserSessionContext({
      sessionId: snapshot.sessionId,
      ownerCommitment: result.value.correlation.ownerCommitment,
      status: "partially-unlocked",
      activeCapabilityIds: [],
      pendingIntentIds: [],
      policyMode: "default"
    }).context;
    const derived = deriveUserSessionContextFromVerifiedVaultUnlock({
      userSessionContext: baseContext,
      lifecycleSnapshot: transitioned.value.transitionResult.snapshot,
      vaultUnlockResult: result.value
    });

    assert.equal(derived.status, "approved");
    assert.equal(derived.context.status, "unlocked");
    assert.deepEqual(derived.context.activeCapabilityIds, []);
    assert.equal(baseContext.status, "partially-unlocked");
    assert.equal(derived.context.metadata.deviceVaultUnlocked, true);
    assert.equal(derived.context.metadata.authorizationAvailable, false);
  });

  it("creates sanitized audit drafts and exposes facade methods without authority", async function () {
    const fixture = await vaultFixture();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const consumptionStore = createEphemeralVaultUnlockConsumptionStore();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      vaultUnlockConsumptionStore: consumptionStore
    });
    const unlockResult = await api.requestDeviceVaultUnlockVerification(fixture.request);
    const transitionResult = api.requestVerifiedVaultSessionUnlock({
      requestId: "facade-vault-session-unlock-1",
      lifecycleSnapshot: fixture.snapshot,
      transitionRequest: {
        transitionRequestId: "vault-session-1:vault-unlock-succeeded",
        event: "unlock_succeeded"
      },
      vaultUnlockResult: unlockResult.value.deviceVaultUnlockResult
    });
    const auditJson = JSON.stringify({
      unlock: unlockResult.value.auditEventDraft,
      transition: transitionResult.value.auditEventDraft
    });

    assert.equal(unlockResult.status, "approved");
    assert.equal(transitionResult.status, "approved", transitionResult.error?.details?.errors?.join("\n"));
    assert.equal(transitionResult.value.verifiedVaultSessionUnlock.transitionResult.nextState, "unlocked");
    assert.equal(consumptionStore.getAll().length, 1);
    assert.equal(auditDraftCollector.count() >= 3, true);
    assert.equal(auditJson.includes("phil_secret"), false);
    assert.equal(auditJson.includes("privateKey"), false);
    assert.equal(auditJson.includes("seedPhrase"), false);
    assertNoAuthority(unlockResult.value.deviceVaultUnlockResult);
    assertNoAuthority(transitionResult.value.verifiedVaultSessionUnlock);
  });

  it("does not include vault plaintext, phil_secret, raw vault keys, or executable authority in result JSON", async function () {
    const { result } = await successfulUnlock({
      metadata: {
        note: "safe"
      }
    });
    const json = JSON.stringify(result.value);

    assert.equal(json.includes("phil_secret"), false);
    assert.equal(json.includes("correct test passphrase"), false);
    assert.equal(json.includes("mnemonic"), false);
    assert.equal(json.includes("seedPhrase"), false);
    assert.equal(json.includes("authorityToken"), false);
    assert.equal(json.includes("privateKey"), false);
  });

  it("does not retain deep request metadata in the vault-unlock audit draft", async function () {
    const fixture = await vaultFixture({
      metadata: {
        a: [{ b: [{ c: { password: "VAULT-DEPTH-CANARY" } }] }]
      }
    });
    const api = createValidationOnlyRuntimeApi();
    const result = await api.requestDeviceVaultUnlockVerification(fixture.request);
    const json = JSON.stringify(result.value);

    assert.equal(result.status, "denied");
    assert.ok(result.error.details.errors.some(
      (error) => error.includes("a[0].b[0].c")
    ));
    assert.equal(json.includes("VAULT-DEPTH-CANARY"), false);
  });

  it("runs Alpha 0 production WebAuthn vault unlock diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_webauthn_vault_unlock"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_webauthn_vault_unlock", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Device Vault unlock performed against explicit in-memory test envelope/i);
    assert.match(textOutput, /phil_secret exposed: no/i);
    assert.match(textOutput, /raw vault key exposed: no/i);
    assert.match(textOutput, /application credentials loaded: no/i);
    assert.match(textOutput, /Final lifecycle state: unlocked/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.finalState, "unlocked");
    assert.equal(parsed.nonAuthority.productionAuthenticationPerformed, true);
    assert.equal(parsed.nonAuthority.vaultUnlocked, true);
    assert.equal(parsed.deviceVaultUnlockResult.deviceVaultUnlocked, true);
    assert.equal(parsed.deviceVaultUnlockResult.philSecretExposed, false);
    assert.equal(parsed.verifiedVaultSessionUnlock.nextState, "unlocked");
    assert.equal(parsed.verifiedVaultSessionUnlock.authorizationCreated, false);
  });
});
