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
  createEphemeralTrustManagerVerificationConsumptionStore,
  createEphemeralUserSessionLifecycleStore,
  createEphemeralVaultUnlockConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryTrustManagerProductionVerificationResultCollector,
  createProductionAuthenticationRequest,
  createTrustManagerVerificationInput,
  createValidationOnlyRuntimeApi,
  requestPublicCredentialDirectory,
  requestSelectedCredentialPublicMaterial,
  runAlpha0Shell,
  transitionUserSessionWithVerifiedVaultUnlock,
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
  signCount = 8,
  invalidSignature = false
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
  if (invalidSignature) signature[signature.length - 1] ^= 0x01;
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
    passphrase: "trust manager production verification passphrase",
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
  const registry = createPhilCredentialRegistry({
    philIdentity: identity,
    credentials: [Object.freeze({
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
    })]
  }).getSnapshot();
  await registryStore.saveRegistry(registry);
  const encryptedBlob = await backend.read();
  const sessionId = "trust-manager-production-session-1";
  const materialAuditCorrelationId = `${sessionId}:selected-material`;
  const partial = partialSnapshot(sessionId);
  const unlock = await verifyDeviceVaultUnlock({
    requestId: "trust-manager-prod-vault-unlock",
    lifecycleSnapshot: partial,
    identity,
    envelope: { envelopeId: "trust-manager-prod-envelope", encryptedBlob, ownerCommitment: identity.ownerCommitment },
    unlockMaterial: {
      materialId: "trust-manager-prod-unlock-material",
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
    requestId: "trust-manager-prod-session-unlock",
    lifecycleSnapshot: partial,
    transitionRequest: { transitionRequestId: `${sessionId}:vault-unlock-succeeded`, event: "unlock_succeeded" },
    vaultUnlockResult: unlock.value,
    consumptionStore: createEphemeralVaultUnlockConsumptionStore(),
    auditCorrelationId: materialAuditCorrelationId
  });
  assert.equal(transition.status, "approved", transition.error?.details?.errors?.join("\n"));
  const directory = await requestPublicCredentialDirectory({
    requestId: "trust-manager-prod-directory",
    operation: "list_credentials",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    identity,
    envelope: { envelopeId: "trust-manager-prod-envelope", encryptedBlob, ownerCommitment: identity.ownerCommitment },
    unlockMaterial: {
      materialId: "trust-manager-prod-directory-material",
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
    requestId: "trust-manager-prod-selected-material",
    operation: "materialize_selected_credential_public_data",
    credentialId: "cred-active",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    publicCredentialDirectory: directory.value,
    identity,
    envelope: { envelopeId: "trust-manager-prod-envelope", encryptedBlob, ownerCommitment: identity.ownerCommitment },
    unlockMaterial: {
      materialId: "trust-manager-prod-selected-material-key",
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
    requestId: "trust-manager-prod-auth-request",
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
    requestId: "trust-manager-prod-verification-input",
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
  const baseRequest = {
    requestId: "trust-manager-prod-assertion-verification",
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
  };
  return { keyPair, baseRequest, verificationInput: verificationInput.value };
}

function assertNoAuthority(value) {
  assert.equal(value.trustDecisionCreated, false);
  assert.equal(value.capabilityGranted, false);
  assert.equal(value.authorizationCreated, false);
  assert.equal(value.deviceVaultAccessed, false);
  assert.equal(value.credentialLoadedFromVault, false);
  assert.equal(value.counterPersisted, false);
  assert.equal(value.persisted, false);
}

describe("PhilCore Trust Manager production verification bridge", function () {
  it("verifies a valid explicit WebAuthn assertion with the existing verifier", async function () {
    const f = await fixture();
    const result = await verifyTrustManagerProductionAssertion(f.baseRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.outcome, "assertion_verified");
    assert.equal(result.value.assertionCryptographicallyVerified, true);
    assert.equal(result.value.challengeBindingVerified, true);
    assert.equal(result.value.originVerified, true);
    assert.equal(result.value.rpIdHashVerified, true);
    assert.equal(result.value.signatureVerified, true);
    assert.equal(result.value.counterAssessment.counterStatus, "advanced");
    assert.equal(result.value.productionVerifierUsed, true);
    assert.equal(result.value.verifiedEvidenceReference.isTrustDecision, false);
    assertNoAuthority(result.value);
  });

  it("rejects invalid signature, challenge, origin, RP ID, credential, provider, presence, verification, and counters", async function () {
    const f = await fixture();
    const cases = [
      ["signature", { assertion: buildAssertion({ privateKey: f.keyPair.privateKey, invalidSignature: true }) }],
      ["challenge", { assertion: buildAssertion({ privateKey: f.keyPair.privateKey, challenge: "wrong-challenge" }) }],
      ["origin", { assertion: buildAssertion({ privateKey: f.keyPair.privateKey, origin: "https://evil.local" }) }],
      ["rp", { assertion: buildAssertion({ privateKey: f.keyPair.privateKey, rpId: "evil.local" }) }],
      ["credential", { assertion: buildAssertion({ credentialId: "wrong-credential", privateKey: f.keyPair.privateKey }) }],
      ["provider", { expectedProviderId: "wrong-provider" }],
      ["presence", { assertion: buildAssertion({ privateKey: f.keyPair.privateKey, flags: 0x04 }) }],
      ["verification", { assertion: buildAssertion({ privateKey: f.keyPair.privateKey, flags: 0x01 }) }],
      ["rollback", { assertion: buildAssertion({ privateKey: f.keyPair.privateKey, signCount: 6 }) }],
      ["clone", { assertion: buildAssertion({ privateKey: f.keyPair.privateKey, signCount: 7 }) }]
    ];
    for (const [name, patch] of cases) {
      const result = await verifyTrustManagerProductionAssertion({
        ...f.baseRequest,
        requestId: `trust-manager-prod-${name}`,
        ...patch
      });
      assert.equal(result.status, "denied", name);
      assertNoAuthority(result.value ?? {
        trustDecisionCreated: false,
        capabilityGranted: false,
        authorizationCreated: false,
        deviceVaultAccessed: false,
        credentialLoadedFromVault: false,
        counterPersisted: false,
        persisted: false
      });
    }
  });

  it("rejects expired input, expired assertion evidence, malformed assertion, replay, and correlation mismatches", async function () {
    const f = await fixture();
    const store = createEphemeralTrustManagerVerificationConsumptionStore();
    const first = await verifyTrustManagerProductionAssertion(f.baseRequest, store);
    const replay = await verifyTrustManagerProductionAssertion({
      ...f.baseRequest,
      requestId: "trust-manager-prod-replay"
    }, store);
    const expiredInput = await verifyTrustManagerProductionAssertion({
      ...f.baseRequest,
      verificationInput: {
        ...f.baseRequest.verificationInput,
        expiresAt: pastDate()
      }
    });
    const expiredEvidence = await verifyTrustManagerProductionAssertion({
      ...f.baseRequest,
      expiresAt: pastDate()
    });
    const malformed = await verifyTrustManagerProductionAssertion({
      ...f.baseRequest,
      assertion: { rawId: "cred-active" }
    });
    const sessionMismatch = await verifyTrustManagerProductionAssertion({
      ...f.baseRequest,
      expectedSessionId: "wrong-session"
    });
    const ownerMismatch = await verifyTrustManagerProductionAssertion({
      ...f.baseRequest,
      expectedOwnerCommitment: "0xdead"
    });
    const appMismatch = await verifyTrustManagerProductionAssertion({
      ...f.baseRequest,
      expectedApplicationId: "nft-manager"
    });
    const purposeMismatch = await verifyTrustManagerProductionAssertion({
      ...f.baseRequest,
      expectedAuthenticationPurpose: "backup_export"
    });

    assert.equal(first.status, "approved");
    assert.equal(replay.status, "denied");
    assert.equal(expiredInput.status, "denied");
    assert.equal(expiredEvidence.status, "denied");
    assert.equal(malformed.status, "denied");
    assert.equal(sessionMismatch.status, "denied");
    assert.equal(ownerMismatch.status, "denied");
    assert.equal(appMismatch.status, "denied");
    assert.equal(purposeMismatch.status, "denied");
  });

  it("collects results, redacts audit output, and integrates through the Runtime facade", async function () {
    const f = await fixture();
    const collector = createInMemoryTrustManagerProductionVerificationResultCollector({ maxResultCount: 1 });
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const store = createEphemeralTrustManagerVerificationConsumptionStore();
    const direct = await verifyTrustManagerProductionAssertion(
      f.baseRequest,
      store,
      collector,
      auditDraftCollector
    );
    const api = createValidationOnlyRuntimeApi({
      trustManagerProductionVerificationCollector: collector,
      trustManagerVerificationConsumptionStore: createEphemeralTrustManagerVerificationConsumptionStore(),
      auditDraftCollector
    });
    const viaFacade = await api.requestTrustManagerProductionVerification({
      ...f.baseRequest,
      requestId: "trust-manager-prod-facade"
    });
    const auditJson = JSON.stringify(direct.value.auditEventDraft);

    assert.equal(direct.status, "approved", direct.error?.details?.errors?.join("\n"));
    assert.equal(viaFacade.status, "approved", viaFacade.error?.details?.errors?.join("\n"));
    assert.equal(collector.count(), 1);
    assert.equal(auditDraftCollector.count() >= 1, true);
    assert.equal(auditJson.includes(f.baseRequest.assertion.response.signature), false);
    assert.equal(auditJson.includes(f.baseRequest.assertion.response.authenticatorData), false);
    assert.equal(auditJson.includes(f.baseRequest.assertion.response.clientDataJSON), false);
    assertNoAuthority(viaFacade.value.trustManagerProductionVerification);
  });

  it("runs Alpha 0 Trust Manager production assertion diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_trust_manager_assertion_verification"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_trust_manager_assertion_verification", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Trust Manager production assertion verification:/i);
    assert.match(textOutput, /challenge verified: yes/i);
    assert.match(textOutput, /signature verified: yes/i);
    assert.match(textOutput, /Trust Decision made: no/i);
    assert.match(textOutput, /capability grant created: no/i);
    assert.match(textOutput, /vault access by Trust Manager: no/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.finalState, "unlocked");
    assert.equal(parsed.trustManagerProductionVerification.status, "verification_succeeded");
    assert.equal(parsed.trustManagerProductionVerification.outcome, "assertion_verified");
    assert.equal(parsed.trustManagerProductionVerification.signatureVerified, true);
    assert.equal(parsed.trustManagerProductionVerification.trustDecisionCreated, false);
    assert.equal(parsed.trustManagerProductionVerification.capabilityGranted, false);
    assert.equal(parsed.trustManagerProductionVerification.deviceVaultAccessed, false);
  });
});
