const assert = require("node:assert/strict");

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
  createEphemeralProtectedStateViewReplayStore,
  createEphemeralUserSessionLifecycleStore,
  createEphemeralVaultUnlockConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryProtectedStateViewCollector,
  createProtectedStateView,
  createValidationOnlyRuntimeApi,
  getExpiredProtectedStateViews,
  groupProtectedStateViewsByOutcome,
  groupProtectedStateViewsByOwner,
  groupProtectedStateViewsBySession,
  groupProtectedStateViewsByView,
  runAlpha0Shell,
  summarizeProtectedStateViews,
  transitionUserSessionWithVerifiedVaultUnlock,
  verifyDeviceVaultUnlock
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function keyProvider(passphrase = "protected state test passphrase") {
  return createLocalDevPassphraseKeyProvider({
    passphrase,
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
}

function partialSnapshot(sessionId = "protected-state-session-1") {
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

function credentialRecord() {
  return Object.freeze({
    credentialId: "credential-secretish-id-should-not-leak",
    providerKind: "webauthn_passkey",
    algorithm: "ES256",
    label: "Primary passkey",
    createdAt: new Date().toISOString(),
    status: "active",
    signCount: 4,
    deviceType: "platform",
    transport: Object.freeze({
      transports: Object.freeze(["internal"]),
      authenticatorAttachment: "platform"
    }),
    priority: 1,
    publicKey: "0xabcdef",
    publicKeyHash: "0x123456"
  });
}

async function protectedStateFixture(overrides = {}) {
  const identity = overrides.identity
    ?? derivePhilIdentityPublic(createPhilIdentityPrivate());
  const provider = overrides.provider ?? keyProvider();
  const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
  const store = createEncryptedDeviceIdentityRegistryStore({
    backend,
    keyProvider: provider
  });
  const registry = createPhilCredentialRegistry({
    philIdentity: identity,
    credentials: overrides.credentials ?? [credentialRecord()]
  }).getSnapshot();
  await store.saveRegistry(registry);
  const encryptedBlob = await backend.read();
  const sessionId = overrides.sessionId ?? "protected-state-session-1";
  const auditCorrelationId = overrides.auditCorrelationId ?? `${sessionId}:vault-unlock`;
  const partial = partialSnapshot(sessionId);
  const unlock = await verifyDeviceVaultUnlock({
    requestId: "protected-state-vault-unlock",
    lifecycleSnapshot: partial,
    identity,
    envelope: {
      envelopeId: "protected-state-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment,
      expiresAt: overrides.handleExpiresAt
    },
    unlockMaterial: {
      materialId: "protected-state-unlock-material",
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
    requestId: "protected-state-vault-session-unlock",
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
  return {
    identity,
    provider,
    encryptedBlob,
    unlockedSnapshot: transition.value.transitionResult.snapshot,
    handle: unlock.value.unlockedVaultHandle,
    baseRequest: {
      requestId: "protected-state-view-1",
      viewType: "identity_summary",
      lifecycleSnapshot: transition.value.transitionResult.snapshot,
      unlockedVaultHandle: unlock.value.unlockedVaultHandle,
      identity,
      envelope: {
        envelopeId: "protected-state-envelope",
        encryptedBlob,
        ownerCommitment: identity.ownerCommitment
      },
      unlockMaterial: {
        materialId: "protected-state-view-material",
        keyProvider: provider,
        providerKind: provider.providerKind,
        unsafeForProduction: provider.unsafeForProduction
      },
      expectedOwnerCommitment: identity.ownerCommitment,
      expectedSessionId: sessionId,
      auditCorrelationId: `${sessionId}:protected-state-view`
    }
  };
}

function assertNoAuthorityOrSecrets(view) {
  assert.equal(view.containsSecrets, false);
  assert.equal(view.containsCredentials, false);
  assert.equal(view.containsPrivateKeys, false);
  assert.equal(view.containsAuthorization, false);
  assert.equal(view.containsSessionKeys, false);
  assert.equal(view.activeCapabilityCreated, false);
  assert.equal(view.sessionKeyCreated, false);
  assert.equal(view.authorizationCreated, false);
  assert.equal(view.persisted, false);
}

describe("PhilCore protected state view boundary", function () {
  it("returns a valid identity summary without exposing secrets or credentials", async function () {
    const fixture = await protectedStateFixture();
    const result = await createProtectedStateView(fixture.baseRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.viewType, "identity_summary");
    assert.equal(result.value.summary.ownerCommitment, fixture.identity.ownerCommitment);
    assert.equal(result.value.summary.identityRootAvailable, true);
    assert.equal(result.value.summary.credentialCount, 1);
    assert.equal(result.value.evidence.plaintextReturned, false);
    assert.equal(result.value.evidence.credentialRecordsReturned, false);
    assertNoAuthorityOrSecrets(result.value);
  });

  it("returns credential, audit, registry, device, recovery, key lifecycle, and runtime summaries only", async function () {
    const fixture = await protectedStateFixture();
    const views = {};
    for (const viewType of [
      "credential_summary",
      "audit_summary",
      "registry_summary",
      "device_summary",
      "recovery_summary",
      "key_lifecycle_summary",
      "runtime_summary"
    ]) {
      const result = await createProtectedStateView({
        ...fixture.baseRequest,
        requestId: `protected-state-view-${viewType}`,
        viewType,
        keyLifecycle: {
          version: "phil-device-identity-key-lifecycle-v1",
          storageKeys: [{
            keyVersion: 1,
            createdAt: new Date().toISOString(),
            status: "active",
            providerType: "local-dev-passphrase-scrypt-device-registry-key-test-only-v1",
            algorithm: "aes-256-gcm",
            registryVersion: 1
          }],
          backupKeys: [],
          policy: {
            recommendedRotationIntervalDays: 90,
            maxKeyAgeDays: 365,
            requireBackupBeforeRotation: true,
            requireAuditEvent: true,
            allowEmergencyRotation: true
          },
          migrationVersion: 1
        }
      });
      assert.equal(result.status, "approved", viewType);
      views[viewType] = result.value;
      assertNoAuthorityOrSecrets(result.value);
    }

    assert.equal(views.credential_summary.summary.totalCredentials, 1);
    assert.equal(views.credential_summary.summary.credentialsByStatus.active, 1);
    assert.equal(views.audit_summary.summary.auditEventCount >= 1, true);
    assert.equal(views.registry_summary.summary.credentialCount, 1);
    assert.equal(views.device_summary.summary.devicesByType.platform, 1);
    assert.equal(views.recovery_summary.summary.recoveryState, "normal");
    assert.equal(views.key_lifecycle_summary.summary.activeStorageKeyCount, 1);
    assert.equal(views.runtime_summary.summary.lifecycleState, "unlocked");
  });

  it("rejects unsupported views, expired handles, owner mismatch, session mismatch, and replayed handles", async function () {
    const fixture = await protectedStateFixture();
    const unsupported = await createProtectedStateView({
      ...fixture.baseRequest,
      viewType: "raw_registry"
    });
    const expired = await createProtectedStateView({
      ...fixture.baseRequest,
      unlockedVaultHandle: {
        ...fixture.baseRequest.unlockedVaultHandle,
        expiresAt: pastDate()
      }
    });
    const ownerMismatch = await createProtectedStateView({
      ...fixture.baseRequest,
      expectedOwnerCommitment: "0xdead"
    });
    const sessionMismatch = await createProtectedStateView({
      ...fixture.baseRequest,
      expectedSessionId: "wrong-session"
    });
    const replayStore = createEphemeralProtectedStateViewReplayStore();
    const firstReplay = await createProtectedStateView({
      ...fixture.baseRequest,
      replayStore
    });
    const secondReplay = await createProtectedStateView({
      ...fixture.baseRequest,
      requestId: "protected-state-view-replay-2",
      replayStore
    });

    assert.equal(unsupported.status, "denied");
    assert.equal(expired.status, "denied");
    assert.equal(ownerMismatch.status, "denied");
    assert.equal(sessionMismatch.status, "denied");
    assert.equal(firstReplay.status, "approved");
    assert.equal(secondReplay.status, "denied");
    assert.ok(secondReplay.error.details.errors.some((error) => error.includes("replayed")));
  });

  it("returns immutable values and never leaks credential identifiers, public keys, or raw vault data", async function () {
    const fixture = await protectedStateFixture();
    const result = await createProtectedStateView({
      ...fixture.baseRequest,
      viewType: "credential_summary"
    });
    const json = JSON.stringify(result.value);

    assert.equal(Object.isFrozen(result.value), true);
    assert.equal(Object.isFrozen(result.value.summary), true);
    assert.equal(json.includes("credential-secretish-id-should-not-leak"), false);
    assert.equal(json.includes("0xabcdef"), false);
    assert.equal(json.includes("protected state test passphrase"), false);
    assert.equal(json.includes("phil_secret"), false);
    assert.equal(json.includes("privateKey"), false);
    assertNoAuthorityOrSecrets(result.value);
  });

  it("collects views process-locally and supports read-only review helpers", async function () {
    const fixture = await protectedStateFixture();
    const collector = createInMemoryProtectedStateViewCollector({ maxViewCount: 2 });
    const first = await createProtectedStateView({
      ...fixture.baseRequest,
      requestId: "protected-state-view-identity"
    }, collector);
    const second = await createProtectedStateView({
      ...fixture.baseRequest,
      requestId: "protected-state-view-audit",
      viewType: "audit_summary"
    }, collector);
    const third = await createProtectedStateView({
      ...fixture.baseRequest,
      requestId: "protected-state-view-runtime",
      viewType: "runtime_summary"
    });
    const expiredCollectionResult = collector.addView(Object.freeze({
      ...third.value,
      protectedStateViewId: `${third.value.protectedStateViewId}:expired-review-copy`,
      expiresAt: pastDate()
    }));
    const all = collector.getAll();
    const summary = summarizeProtectedStateViews(all);

    assert.equal(first.status, "approved");
    assert.equal(second.status, "approved");
    assert.equal(third.status, "approved");
    assert.equal(expiredCollectionResult.status, "evicted_oldest");
    assert.equal(collector.count(), 2);
    assert.equal(all.some((view) => view.protectedStateViewId === first.value.protectedStateViewId), false);
    assert.equal(groupProtectedStateViewsByView(all).audit_summary.length, 1);
    assert.equal(groupProtectedStateViewsBySession(all)[fixture.unlockedSnapshot.sessionId].length, 2);
    assert.equal(groupProtectedStateViewsByOutcome(all).view_created.length, 2);
    assert.equal(groupProtectedStateViewsByOwner(all)[fixture.identity.ownerCommitment].length, 2);
    assert.equal(getExpiredProtectedStateViews(all).length, 1);
    assert.equal(summary.totalViewCount, 2);
    assert.equal(summary.expiredViewCount, 1);
  });

  it("exposes protected state view through the Runtime facade and audit collectors", async function () {
    const fixture = await protectedStateFixture();
    const protectedStateViewCollector = createInMemoryProtectedStateViewCollector();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      protectedStateViewCollector,
      auditDraftCollector
    });
    const result = await api.requestProtectedStateView(fixture.baseRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.protectedStateView.viewType, "identity_summary");
    assert.equal(protectedStateViewCollector.count(), 1);
    assert.equal(auditDraftCollector.count() >= 2, true);
    assertNoAuthorityOrSecrets(result.value.protectedStateView);
  });

  it("runs Alpha 0 protected state view diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_protected_state_view"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_protected_state_view", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Protected state view:/i);
    assert.match(textOutput, /identity summary returned: yes/i);
    assert.match(textOutput, /Secrets remain protected: yes/i);
    assert.match(textOutput, /credentials loaded into applications: no/i);
    assert.match(textOutput, /Applications still have no authority/i);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(json.exitCode, 0, errorOutput);
    assert.equal(parsed.finalState, "unlocked");
    assert.equal(parsed.protectedStateView.viewType, "identity_summary");
    assert.equal(parsed.protectedStateView.containsSecrets, false);
    assert.equal(parsed.protectedStateView.containsCredentials, false);
    assert.equal(parsed.protectedStateView.containsAuthorization, false);
  });
});
