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
  createEphemeralTrustManagerVerificationConsumptionStore,
  createEphemeralUserSessionLifecycleStore,
  createEphemeralVaultUnlockConsumptionStore,
  createInMemoryAuditDraftCollector,
  createInMemoryBoundedTrustDecisionCandidateCollector,
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
    passphrase: "bounded trust decision candidate passphrase",
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
  const sessionId = "bounded-trust-decision-session-1";
  const materialAuditCorrelationId = `${sessionId}:selected-material`;
  const partial = partialSnapshot(sessionId);
  const unlock = await verifyDeviceVaultUnlock({
    requestId: "bounded-candidate-vault-unlock",
    lifecycleSnapshot: partial,
    identity,
    envelope: { envelopeId: "bounded-candidate-envelope", encryptedBlob, ownerCommitment: identity.ownerCommitment },
    unlockMaterial: {
      materialId: "bounded-candidate-unlock-material",
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
    requestId: "bounded-candidate-session-unlock",
    lifecycleSnapshot: partial,
    transitionRequest: { transitionRequestId: `${sessionId}:vault-unlock-succeeded`, event: "unlock_succeeded" },
    vaultUnlockResult: unlock.value,
    consumptionStore: createEphemeralVaultUnlockConsumptionStore(),
    auditCorrelationId: materialAuditCorrelationId
  });
  assert.equal(transition.status, "approved", transition.error?.details?.errors?.join("\n"));
  const directory = await requestPublicCredentialDirectory({
    requestId: "bounded-candidate-directory",
    operation: "list_credentials",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    identity,
    envelope: { envelopeId: "bounded-candidate-envelope", encryptedBlob, ownerCommitment: identity.ownerCommitment },
    unlockMaterial: {
      materialId: "bounded-candidate-directory-material",
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
    requestId: "bounded-candidate-selected-material",
    operation: "materialize_selected_credential_public_data",
    credentialId: "cred-active",
    lifecycleSnapshot: transition.value.transitionResult.snapshot,
    unlockedVaultHandle: unlock.value.unlockedVaultHandle,
    publicCredentialDirectory: directory.value,
    identity,
    envelope: { envelopeId: "bounded-candidate-envelope", encryptedBlob, ownerCommitment: identity.ownerCommitment },
    unlockMaterial: {
      materialId: "bounded-candidate-selected-material-key",
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
    requestId: "bounded-candidate-auth-request",
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
    requestId: "bounded-candidate-verification-input",
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
    requestId: "bounded-candidate-assertion-verification",
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
  });
  assert.equal(verification.status, "approved", verification.error?.details?.errors?.join("\n"));
  const baseRequest = {
    requestId: "bounded-candidate-request",
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
  };
  return { baseRequest, verification, keyPair };
}

function assertNoAuthority(candidate) {
  assert.equal(candidate.activeTrustDecisionCreated, false);
  assert.equal(candidate.capabilityGranted, false);
  assert.equal(candidate.sessionKeyCreated, false);
  assert.equal(candidate.authorizationCreated, false);
  assert.equal(candidate.vaultAccessGranted, false);
  assert.equal(candidate.persisted, false);
  assert.equal(candidate.worldIdVerified, false);
  assert.equal(candidate.proofExecuted, false);
  assert.equal(candidate.adapterExecuted, false);
}

describe("PhilCore bounded Trust Decision candidate", function () {
  it("creates a bounded candidate from successful production verification and active lifecycle data", async function () {
    const f = await fixture();
    const result = createBoundedTrustDecisionCandidate(f.baseRequest);

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.status, "candidate_created");
    assert.equal(result.value.outcome, "counter_persistence_required");
    assert.equal(result.value.productionAssertionVerified, true);
    assert.equal(result.value.evidence.productionVerifierUsed, true);
    assert.equal(result.value.lifecycleAssessment.credentialLifecycleStatus, "active");
    assert.equal(result.value.assurance.sufficient, true);
    assert.equal(result.value.requiresCounterPersistence, true);
    assert.equal(result.value.eligibleForAuthoritativeTrustDecision, false);
    assertNoAuthority(result.value);
  });

  it("classifies lifecycle, recovery, session, correlation, assurance, expiry, replay, and counter constraints", async function () {
    const f = await fixture();
    const cases = [
      ["revoked", { credentialLifecycleStatus: "revoked" }, "credential_lifecycle_ineligible"],
      ["archived", { credentialLifecycleStatus: "archived" }, "credential_lifecycle_ineligible"],
      ["rotated", { credentialLifecycleStatus: "rotated" }, "credential_lifecycle_ineligible"],
      ["pending", { credentialLifecycleStatus: "pending" }, "unsupported"],
      ["recovery-only ordinary", { credentialLifecycleStatus: "recovery-only" }, "credential_lifecycle_ineligible"],
      ["recovery-only recovery", {
        credentialLifecycleStatus: "recovery-only",
        authenticationPurpose: "recovery_approval",
        recoveryContext: true,
        productionVerificationResult: {
          ...f.baseRequest.productionVerificationResult,
          correlation: {
            ...f.baseRequest.productionVerificationResult.correlation,
            authenticationPurpose: "recovery_approval"
          }
        }
      }, "counter_persistence_required"],
      ["session", { lifecycleState: "locked" }, "session_state_ineligible"],
      ["owner", { ownerCommitment: "0xdead" }, "correlation_mismatch"],
      ["application", { applicationId: "nft-manager" }, "correlation_mismatch"],
      ["purpose", { authenticationPurpose: "backup_export" }, "correlation_mismatch"],
      ["assurance", { requestedAssurance: ["user_presence", "user_verification", "hardware_backed"] }, "assurance_insufficient"],
      ["expired", { expiresAt: pastDate() }, "evidence_expired"],
      ["replayed", {
        productionVerificationResult: {
          ...f.baseRequest.productionVerificationResult,
          status: "verification_replayed",
          outcome: "evidence_replayed"
        }
      }, "evidence_replayed"],
      ["rollback", {
        productionVerificationResult: {
          ...f.baseRequest.productionVerificationResult,
          counterAssessment: {
            ...f.baseRequest.productionVerificationResult.counterAssessment,
            counterStatus: "rollback",
            rollbackDetected: true,
            futurePersistenceRequired: false
          }
        }
      }, "verification_ineligible"],
      ["presence", {
        productionVerificationResult: {
          ...f.baseRequest.productionVerificationResult,
          evidenceSummary: {
            ...f.baseRequest.productionVerificationResult.evidenceSummary,
            userPresenceVerified: false
          }
        }
      }, "assurance_insufficient"],
      ["verification", {
        productionVerificationResult: {
          ...f.baseRequest.productionVerificationResult,
          evidenceSummary: {
            ...f.baseRequest.productionVerificationResult.evidenceSummary,
            userVerificationVerified: false
          }
        }
      }, "assurance_insufficient"]
    ];
    for (const [name, patch, outcome] of cases) {
      const result = createBoundedTrustDecisionCandidate({
        ...f.baseRequest,
        requestId: `bounded-candidate-${name}`,
        ...patch
      });
      assert.equal(result.status, "approved", name);
      assert.equal(result.value.outcome, outcome, name);
      assertNoAuthority(result.value);
    }
  });

  it("rejects malformed, fixture-only, and secret-shaped requests without authority", async function () {
    const f = await fixture();
    const failedVerification = createBoundedTrustDecisionCandidate({
      ...f.baseRequest,
      productionVerificationResult: {
        ...f.baseRequest.productionVerificationResult,
        status: "verification_rejected",
        outcome: "signature_invalid",
        assertionCryptographicallyVerified: false
      }
    });
    const fixtureOnly = createBoundedTrustDecisionCandidate({
      ...f.baseRequest,
      productionVerificationResult: {
        ...f.baseRequest.productionVerificationResult,
        evidenceSummary: {
          ...f.baseRequest.productionVerificationResult.evidenceSummary,
          verifierKind: "fixture-webauthn"
        }
      }
    });
    const secret = createBoundedTrustDecisionCandidate({
      ...f.baseRequest,
      metadata: { phil_secret: "do-not-accept" }
    });

    assert.equal(failedVerification.status, "approved");
    assert.equal(failedVerification.value.outcome, "verification_ineligible");
    assert.equal(fixtureOnly.status, "approved");
    assert.equal(fixtureOnly.value.outcome, "verification_ineligible");
    assert.equal(secret.status, "denied");
  });

  it("preserves canonical Phil activation World ID requirement without verifying World ID", async function () {
    const f = await fixture();
    const result = createBoundedTrustDecisionCandidate({
      ...f.baseRequest,
      authenticationPurpose: "canonical_phil_activation",
      canonicalPhilActivationContext: true,
      productionVerificationResult: {
        ...f.baseRequest.productionVerificationResult,
        correlation: {
          ...f.baseRequest.productionVerificationResult.correlation,
          authenticationPurpose: "canonical_phil_activation"
        }
      }
    });

    assert.equal(result.status, "approved");
    assert.equal(result.value.requiresWorldIdEnrollment, true);
    assert.equal(result.value.worldIdVerified, false);
    assert.ok(result.value.requirements.includes("world_id_enrollment"));
    assertNoAuthority(result.value);
  });

  it("collects candidates, integrates through the facade, and keeps audit output sanitized", async function () {
    const f = await fixture();
    const collector = createInMemoryBoundedTrustDecisionCandidateCollector({ maxCandidateCount: 1 });
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const direct = createBoundedTrustDecisionCandidate(f.baseRequest, collector, auditDraftCollector);
    const duplicate = collector.addCandidate(direct.value);
    const second = createBoundedTrustDecisionCandidate({
      ...f.baseRequest,
      requestId: "bounded-candidate-second",
      auditCorrelationId: `${f.baseRequest.auditCorrelationId}:second`,
      productionVerificationResult: {
        ...f.baseRequest.productionVerificationResult,
        auditCorrelationId: `${f.baseRequest.auditCorrelationId}:second`,
        correlation: {
          ...f.baseRequest.productionVerificationResult.correlation,
          auditCorrelationId: `${f.baseRequest.auditCorrelationId}:second`
        }
      }
    }, collector);
    const api = createValidationOnlyRuntimeApi({
      boundedTrustDecisionCandidateCollector: collector,
      auditDraftCollector
    });
    const viaFacade = api.requestBoundedTrustDecisionCandidate({
      ...f.baseRequest,
      requestId: "bounded-candidate-facade"
    });
    const auditJson = JSON.stringify(direct.value.auditEventDraft);

    assert.equal(direct.status, "approved");
    assert.equal(duplicate.status, "rejected_duplicate");
    assert.equal(second.status, "approved");
    assert.equal(collector.count(), 1);
    assert.equal(viaFacade.status, "approved");
    assert.equal(viaFacade.value.boundedTrustDecisionCandidate.activeTrustDecisionCreated, false);
    assert.equal(auditDraftCollector.count() >= 1, true);
    assert.equal(auditJson.includes("clientDataJSON"), false);
    assert.equal(auditJson.includes("authenticatorData"), false);
    assert.equal(auditJson.includes("signatureBytes"), false);
    assertNoAuthority(viaFacade.value.boundedTrustDecisionCandidate);
  });

  it("runs Alpha 0 bounded Trust Decision candidate diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_trust_decision_candidate"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_trust_decision_candidate", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /Bounded Trust Decision candidate:/i);
    assert.match(textOutput, /counter persistence required: yes/i);
    assert.match(textOutput, /authoritative Trust Decision created: no/i);
    assert.match(textOutput, /capability grant created: no/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.finalState, "unlocked");
    assert.equal(parsed.boundedTrustDecisionCandidate.status, "candidate_created");
    assert.equal(parsed.boundedTrustDecisionCandidate.outcome, "counter_persistence_required");
    assert.equal(parsed.boundedTrustDecisionCandidate.activeTrustDecisionCreated, false);
    assert.equal(parsed.boundedTrustDecisionCandidate.capabilityGranted, false);
    assert.equal(parsed.boundedTrustDecisionCandidate.authorizationCreated, false);
    assert.equal(parsed.boundedTrustDecisionCandidate.persisted, false);
  });
});
