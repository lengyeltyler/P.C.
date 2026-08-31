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
  createEphemeralUserSessionLifecycleStore,
  createEphemeralVaultUnlockConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryPublicCredentialDirectoryResultCollector,
  createValidationOnlyRuntimeApi,
  requestPublicCredentialDirectory,
  runAlpha0Shell,
  sanitizeCredentialRecordToPublicDescriptor,
  transitionUserSessionWithVerifiedVaultUnlock,
  verifyDeviceVaultUnlock
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function keyProvider(passphrase = "public credential directory passphrase") {
  return createLocalDevPassphraseKeyProvider({
    passphrase,
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
}

function partialSnapshot(sessionId = "public-directory-session-1") {
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
    publicKey: input.publicKey ?? "0xabcdef",
    publicKeyHash: input.publicKeyHash
  };
  return Object.freeze(input.includeSecretShapedFields ? {
    ...base,
    privateKey: "must-not-leak",
    clientDataJSON: "must-not-leak",
    authenticatorData: "must-not-leak",
    assertionSignature: "must-not-leak",
    encryptedCredentialBlob: "must-not-leak",
    recoverySecret: "must-not-leak"
  } : base);
}

function credentials() {
  return [
    credential({
      credentialId: "cred-active",
      label: "Primary passkey",
      status: "active",
      deviceKeyId: "device-active",
      publicKeyHash: "0x1111",
      signCount: 8
    }),
    credential({
      credentialId: "cred-recovery",
      label: "Recovery key",
      status: "recovery-only",
      providerKind: "hardware_key",
      deviceType: "hardware-security-key",
      deviceKeyId: "device-recovery",
      publicKeyHash: "0x2222"
    }),
    credential({
      credentialId: "cred-revoked",
      label: "Old revoked passkey",
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

async function directoryFixture(overrides = {}) {
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
    credentials: overrides.credentials ?? credentials()
  }).getSnapshot();
  await registryStore.saveRegistry(registry);
  const encryptedBlob = await backend.read();
  const sessionId = overrides.sessionId ?? "public-directory-session-1";
  const auditCorrelationId = overrides.auditCorrelationId ?? `${sessionId}:vault-unlock`;
  const partial = partialSnapshot(sessionId);
  const unlock = await verifyDeviceVaultUnlock({
    requestId: "public-directory-vault-unlock",
    lifecycleSnapshot: partial,
    identity,
    envelope: {
      envelopeId: "public-directory-envelope",
      encryptedBlob,
      ownerCommitment: identity.ownerCommitment,
      expiresAt: overrides.handleExpiresAt
    },
    unlockMaterial: {
      materialId: "public-directory-unlock-material",
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
    requestId: "public-directory-vault-session-unlock",
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
    partial,
    unlockedSnapshot: transition.value.transitionResult.snapshot,
    handle: unlock.value.unlockedVaultHandle,
    baseRequest: {
      requestId: "public-directory-request-1",
      operation: "list_credentials",
      lifecycleSnapshot: transition.value.transitionResult.snapshot,
      unlockedVaultHandle: unlock.value.unlockedVaultHandle,
      identity,
      envelope: {
        envelopeId: "public-directory-envelope",
        encryptedBlob,
        ownerCommitment: identity.ownerCommitment
      },
      unlockMaterial: {
        materialId: "public-directory-material",
        keyProvider: provider,
        providerKind: provider.providerKind,
        unsafeForProduction: provider.unsafeForProduction
      },
      query: {
        limit: 10
      },
      expectedOwnerCommitment: identity.ownerCommitment,
      expectedSessionId: sessionId,
      auditCorrelationId: `${sessionId}:public-directory`
    }
  };
}

function assertNoAuthorityOrPrivateMaterial(value) {
  assert.equal(value.containsPrivateMaterial, false);
  assert.equal(value.containsRawAssertionData, false);
  assert.equal(value.containsVaultKeys, false);
  assert.equal(value.containsPhilSecret, false);
  assert.equal(value.providesTrustDecision, false);
  assert.equal(value.grantsAuthority, false);
}

describe("PhilCore public credential directory boundary", function () {
  it("lists public credential descriptors from a valid unlocked vault", async function () {
    const fixture = await directoryFixture();
    const result = await requestPublicCredentialDirectory(fixture.baseRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.operation, "list_credentials");
    assert.equal(result.value.descriptors.length, 4);
    assert.equal(result.value.summary.totalCredentialCount, 4);
    assert.equal(result.value.summary.providerKinds.includes("webauthn_passkey"), true);
    assert.equal(result.value.summary.lifecycleStatuses.active, 1);
    assert.equal(result.value.summary.lifecycleStatuses.revoked, 1);
    assert.equal(result.value.summary.lifecycleStatuses.archived, 1);
    assert.equal(result.value.summary.lifecycleStatuses["recovery-only"], 1);
    assert.equal(result.value.summary.recoveryOnlyCount, 1);
    assert.equal(result.value.summary.ordinaryUseEligibleCount, 1);
    assertNoAuthorityOrPrivateMaterial(result.value);
    for (const descriptor of result.value.descriptors) {
      assertNoAuthorityOrPrivateMaterial(descriptor);
    }
  });

  it("retrieves one descriptor and supports summary-only requests", async function () {
    const fixture = await directoryFixture();
    const one = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      requestId: "public-directory-get-one",
      operation: "get_credential_descriptor",
      query: {
        credentialId: "cred-active",
        limit: 10
      }
    });
    const summary = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      requestId: "public-directory-summary",
      operation: "summarize_credentials"
    });

    assert.equal(one.status, "approved");
    assert.equal(one.value.descriptors.length, 1);
    assert.equal(one.value.descriptors[0].credentialId, "cred-active");
    assert.equal(summary.status, "approved");
    assert.equal(summary.value.descriptors.length, 0);
    assert.equal(summary.value.summary.returnedCredentialCount, 4);
    assert.equal(summary.value.summary.totalCredentialCount, 4);
  });

  it("filters by provider, status, device, recovery-only, and ordinary-use eligibility", async function () {
    const fixture = await directoryFixture();
    const cases = [
      [{ providerKind: "hardware_key" }, ["cred-recovery"]],
      [{ lifecycleStatus: "revoked" }, ["cred-revoked"]],
      [{ deviceId: "device-active" }, ["cred-active"]],
      [{ recoveryOnly: true }, ["cred-recovery"]],
      [{ ordinaryUseEligible: true }, ["cred-active"]]
    ];

    for (const [filter, expectedIds] of cases) {
      const result = await requestPublicCredentialDirectory({
        ...fixture.baseRequest,
        requestId: `public-directory-filter-${Object.keys(filter)[0]}`,
        query: {
          filter,
          limit: 10
        }
      });
      assert.equal(result.status, "approved");
      assert.deepEqual(result.value.descriptors.map((descriptor) => descriptor.credentialId), expectedIds);
    }
  });

  it("enforces bounded result limits and rejects malformed filters or unsupported operations", async function () {
    const fixture = await directoryFixture();
    const limited = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      requestId: "public-directory-limited",
      query: {
        limit: 2
      }
    });
    const overLimit = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      requestId: "public-directory-over-limit",
      query: {
        limit: 99
      }
    });
    const malformedFilter = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      requestId: "public-directory-malformed-filter",
      query: {
        filter: {
          recoveryOnly: "yes"
        },
        limit: 10
      }
    });
    const unsupported = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      requestId: "public-directory-raw",
      operation: "read_registry"
    });

    assert.equal(limited.status, "approved");
    assert.equal(limited.value.descriptors.length, 2);
    assert.equal(limited.value.summary.truncated, true);
    assert.equal(overLimit.status, "denied");
    assert.equal(malformedFilter.status, "denied");
    assert.equal(unsupported.status, "denied");
  });

  it("rejects invalid session state, expired handles, and owner/session mismatches", async function () {
    const fixture = await directoryFixture();
    const partial = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      lifecycleSnapshot: fixture.partial
    });
    const expired = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      unlockedVaultHandle: {
        ...fixture.baseRequest.unlockedVaultHandle,
        expiresAt: pastDate()
      }
    });
    const ownerMismatch = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      expectedOwnerCommitment: "0xdead"
    });
    const sessionMismatch = await requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      expectedSessionId: "wrong-session"
    });

    assert.equal(partial.status, "denied");
    assert.equal(expired.status, "denied");
    assert.equal(ownerMismatch.status, "denied");
    assert.equal(sessionMismatch.status, "denied");
  });

  it("uses explicit allowlist construction and omits private/raw WebAuthn fields and raw public keys", async function () {
    const descriptor = sanitizeCredentialRecordToPublicDescriptor(credential({
      credentialId: "cred-secret-shaped-source",
      label: "Secret shaped source",
      status: "active",
      includeSecretShapedFields: true
    }));
    const fixture = await directoryFixture();
    const result = await requestPublicCredentialDirectory(fixture.baseRequest);
    const json = JSON.stringify(result.value);

    assert.equal(Object.keys(descriptor).includes("privateKey"), false);
    assert.equal(Object.keys(descriptor).includes("clientDataJSON"), false);
    assert.equal(Object.keys(descriptor).includes("authenticatorData"), false);
    assert.equal(Object.keys(descriptor).includes("assertionSignature"), false);
    assert.equal(Object.keys(descriptor).includes("encryptedCredentialBlob"), false);
    assert.equal(Object.keys(descriptor).includes("publicKey"), false);
    assert.equal(json.includes("must-not-leak"), false);
    assert.equal(json.includes("0xabcdef"), false);
    assert.equal(json.includes("privateKey"), false);
    assert.equal(json.includes("clientDataJSON"), false);
    assert.equal(json.includes("authenticatorData"), false);
    assert.equal(json.includes("assertionSignature"), false);
    assert.equal(json.includes("encryptedCredentialBlob"), false);
  });

  it("returns frozen results, collects process-locally, and integrates through the Runtime facade", async function () {
    const fixture = await directoryFixture();
    const collector = createInMemoryPublicCredentialDirectoryResultCollector({ maxResultCount: 1 });
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const direct = await requestPublicCredentialDirectory(
      fixture.baseRequest,
      collector,
      auditDraftCollector
    );
    const api = createValidationOnlyRuntimeApi({
      publicCredentialDirectoryResultCollector: collector,
      auditDraftCollector
    });
    const viaFacade = await api.requestPublicCredentialDirectory({
      ...fixture.baseRequest,
      requestId: "public-directory-facade"
    });

    assert.equal(direct.status, "approved");
    assert.equal(Object.isFrozen(direct.value), true);
    assert.equal(Object.isFrozen(direct.value.descriptors), true);
    assert.equal(viaFacade.status, "approved", viaFacade.error?.details?.errors?.join("\n"));
    assert.equal(viaFacade.value.publicCredentialDirectory.descriptors.length, 4);
    assert.equal(collector.count(), 1);
    assert.equal(auditDraftCollector.count() >= 2, true);
    assertNoAuthorityOrPrivateMaterial(viaFacade.value.publicCredentialDirectory);
  });

  it("runs Alpha 0 public credential directory diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_public_credential_directory"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_public_credential_directory", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Public credential directory:/i);
    assert.match(textOutput, /credential count: 1/i);
    assert.match(textOutput, /provider kinds: webauthn_passkey/i);
    assert.match(textOutput, /no private credential material loaded/i);
    assert.match(textOutput, /no assertion executed/i);
    assert.match(textOutput, /no Trust Decision made/i);
    assert.match(textOutput, /no capability or authorization created/i);
    assert.match(textOutput, /no persistence/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.finalState, "unlocked");
    assert.equal(parsed.publicCredentialDirectory.credentialCount, 1);
    assert.equal(parsed.publicCredentialDirectory.containsPrivateMaterial, false);
    assert.equal(parsed.publicCredentialDirectory.containsRawAssertionData, false);
    assert.equal(parsed.publicCredentialDirectory.providesTrustDecision, false);
    assert.equal(parsed.publicCredentialDirectory.grantsAuthority, false);
  });
});
