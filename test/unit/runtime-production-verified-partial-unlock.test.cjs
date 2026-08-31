const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");

const {
  arrayBufferToBase64Url
} = require("../../apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts");
const {
  createEphemeralProductionVerificationConsumptionStore,
  createEphemeralUserSessionLifecycleStore,
  createInMemoryAuditDraftCollector,
  createLifecycleTransitionCandidate,
  createValidationOnlyRuntimeApi,
  createUserSessionContext,
  deriveUserSessionContextFromProductionVerifiedPartialUnlock,
  runAlpha0Shell,
  transitionUserSessionWithProductionVerification,
  verifyProductionWebAuthnAuthentication
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function generateP256CredentialKeyPair() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const publicKeySpki = publicKey.export({
    type: "spki",
    format: "der"
  });

  return {
    privateKey,
    publicKeyHex: `0x${Buffer.from(publicKeySpki).toString("hex")}`
  };
}

function sha256(value) {
  return nodeCrypto.createHash("sha256").update(Buffer.from(value)).digest();
}

function buildAuthenticatorData({ rpId, flags = 0x05, signCount = 1 }) {
  const out = Buffer.alloc(37);
  sha256(Buffer.from(rpId, "utf8")).copy(out, 0);
  out[32] = flags;
  out.writeUInt32BE(signCount >>> 0, 33);
  return out;
}

function buildAssertion({
  credentialId,
  privateKey,
  rpId,
  origin,
  challenge,
  flags = 0x05,
  signCount = 7,
  invalidSignature = false
}) {
  const authenticatorData = buildAuthenticatorData({ rpId, flags, signCount });
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin
  }));
  const signer = nodeCrypto.createSign("SHA256");
  signer.update(Buffer.concat([authenticatorData, sha256(clientDataJSON)]));
  signer.end();
  const signature = Buffer.from(signer.sign(privateKey));
  if (invalidSignature) {
    signature[signature.length - 1] ^= 0x01;
  }

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

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function pastDate(ms = 60_000) {
  return new Date(Date.now() - ms).toISOString();
}

function unlockingSnapshot(sessionId = "session-1") {
  const store = createEphemeralUserSessionLifecycleStore();
  const init = store.initialize({
    sessionId,
    transitionRequestId: `${sessionId}:initialize`
  });
  assert.equal(init.status, "initialized");
  const unlock = store.requestTransition({
    transitionRequestId: `${sessionId}:request-unlock`,
    event: "request_unlock"
  });
  assert.equal(unlock.status, "transitioned");
  assert.equal(store.getSnapshot().state, "unlocking");
  return store.getSnapshot();
}

function lockedSnapshot(sessionId = "session-1") {
  const store = createEphemeralUserSessionLifecycleStore();
  const init = store.initialize({
    sessionId,
    transitionRequestId: `${sessionId}:initialize`
  });
  assert.equal(init.status, "initialized");
  return store.getSnapshot();
}

function verificationRequest(overrides = {}) {
  const keyPair = overrides.keyPair ?? generateP256CredentialKeyPair();
  const sessionId = overrides.sessionId ?? "session-1";
  const transitionRequestId = overrides.transitionRequestId ?? "unlock-transition-1";
  const credentialId = overrides.credentialId ?? "credential-1";
  const providerId = overrides.providerId ?? "webauthn-provider-1";
  const challenge = overrides.challenge ?? "production-challenge-1";
  const challengeReferenceId = overrides.challengeReferenceId ?? "challenge-reference-1";
  const origin = overrides.origin ?? "https://philcore.local";
  const rpId = overrides.rpId ?? "philcore.local";

  return {
    requestId: overrides.requestId ?? "production-auth-verification-1",
    providerKind: "webauthn_passkey",
    providerId,
    assertion: buildAssertion({
      credentialId,
      privateKey: keyPair.privateKey,
      rpId: overrides.assertionRpId ?? rpId,
      origin: overrides.assertionOrigin ?? origin,
      challenge: overrides.assertionChallenge ?? challenge,
      flags: overrides.flags ?? 0x05,
      signCount: overrides.signCount ?? 7,
      invalidSignature: overrides.invalidSignature ?? false
    }),
    credential: {
      credentialId,
      credentialIdHash: "0xcredential",
      rawId: credentialId,
      publicKey: keyPair.publicKeyHex,
      publicKeyAlgorithm: -7,
      signCount: overrides.previousSignCount ?? 6
    },
    expectedChallenge: overrides.expectedChallenge ?? challenge,
    expectedRpId: overrides.expectedRpId ?? rpId,
    expectedOrigin: overrides.expectedOrigin ?? origin,
    expectedUserVerification: overrides.expectedUserVerification ?? "required",
    storedSignCount: overrides.storedSignCount ?? overrides.previousSignCount ?? 6,
    correlation: {
      sessionId,
      lifecycleTransitionRequestId: transitionRequestId,
      lifecycleEvent: "unlock_succeeded",
      ownerCommitment: overrides.ownerCommitment ?? "0x1234",
      applicationId: "ethereum-net",
      credentialId,
      deviceId: "device-1",
      providerId,
      challengeReferenceId,
      auditCorrelationId: overrides.auditCorrelationId ?? "session-1:production-unlock"
    },
    requestedAssurance: overrides.requestedAssurance ?? [
      "user_presence",
      "user_verification",
      "phishing_resistant"
    ],
    freshness: overrides.freshness ?? {
      collectedAt: new Date().toISOString(),
      expiresAt: futureDate()
    },
    auditCorrelationId: overrides.auditCorrelationId ?? "session-1:production-unlock"
  };
}

async function verifiedCandidate(overrides = {}) {
  const snapshot = overrides.snapshot ?? unlockingSnapshot(overrides.sessionId ?? "session-1");
  const request = verificationRequest({
    ...overrides,
    sessionId: snapshot.sessionId
  });
  const verification = await verifyProductionWebAuthnAuthentication(request);
  const candidate = createLifecycleTransitionCandidate({
    requestId: overrides.candidateRequestId ?? "candidate-1",
    productionAuthenticationVerification: verification.value,
    lifecycleEligibility: verification.value?.lifecycleEligibility,
    lifecycleSnapshot: snapshot,
    transitionRequest: {
      transitionRequestId: overrides.candidateTransitionRequestId
        ?? overrides.transitionRequestId
        ?? "unlock-transition-1",
      event: overrides.transitionEvent ?? "unlock_succeeded"
    },
    expectedSessionId: overrides.expectedSessionId ?? snapshot.sessionId,
    expectedOwnerCommitment: overrides.expectedOwnerCommitment ?? "0x1234",
    expectedCredentialId: overrides.expectedCredentialId ?? "credential-1",
    expectedProviderId: overrides.expectedProviderId ?? "webauthn-provider-1",
    expectedChallengeReferenceId: overrides.expectedChallengeReferenceId ?? "challenge-reference-1",
    requestedAssurance: overrides.candidateRequestedAssurance ?? [
      "user_presence",
      "user_verification",
      "phishing_resistant"
    ],
    auditCorrelationId: overrides.auditCorrelationId ?? "session-1:production-unlock"
  });
  return {
    snapshot,
    verification,
    candidate
  };
}

function assertNoAuthority(value) {
  assert.equal(value.deviceVaultUnlocked, false);
  assert.equal(value.activeCapabilityCreated, false);
  assert.equal(value.authorizationCreated, false);
  assert.equal(value.persisted, false);
}

describe("PhilCore production-verified partial session unlock", function () {
  it("creates a lifecycle candidate from a valid real WebAuthn verification", async function () {
    const { verification, candidate } = await verifiedCandidate();

    assert.equal(verification.status, "approved");
    assert.equal(verification.value.outcome, "webauthn_assertion_verified");
    assert.equal(candidate.status, "approved", candidate.error?.details?.errors?.join("\n"));
    assert.equal(candidate.value.outcome, "candidate_created");
    assert.equal(candidate.value.targetState, "partially_unlocked");
    assert.equal(candidate.value.productionWebAuthnVerificationPerformed, true);
    assert.equal(candidate.value.browserWebAuthnInvocationPerformed, false);
    assert.equal(candidate.value.credentialLoadedFromVault, false);
    assertNoAuthority(candidate.value);
  });

  it("rejects invalid signature, challenge, origin, RP, user-presence, user-verification, expired, and replayed verification results", async function () {
    const cases = [
      { name: "signature", input: { invalidSignature: true } },
      { name: "challenge", input: { expectedChallenge: "wrong-challenge" } },
      { name: "origin", input: { expectedOrigin: "https://evil.example" } },
      { name: "rp", input: { expectedRpId: "wrong.example" } },
      { name: "presence", input: { flags: 0x04 } },
      { name: "verification", input: { flags: 0x01 } },
      {
        name: "expired",
        input: { freshness: { collectedAt: pastDate(120_000), expiresAt: pastDate(1_000) } }
      },
      { name: "replay", input: { signCount: 6, previousSignCount: 6, storedSignCount: 6 } }
    ];

    for (const entry of cases) {
      const result = await verifiedCandidate(entry.input);
      assert.equal(result.candidate.status, "denied", entry.name);
      assert.equal(result.candidate.value, undefined, entry.name);
    }
  });

  it("rejects correlation and lifecycle mismatches", async function () {
    assert.equal((await verifiedCandidate({ expectedSessionId: "wrong-session" })).candidate.status, "denied");
    assert.equal((await verifiedCandidate({ expectedOwnerCommitment: "0xwrong" })).candidate.status, "denied");
    assert.equal((await verifiedCandidate({ expectedCredentialId: "wrong-credential" })).candidate.status, "denied");
    assert.equal((await verifiedCandidate({ expectedProviderId: "wrong-provider" })).candidate.status, "denied");
    assert.equal((await verifiedCandidate({ expectedChallengeReferenceId: "wrong-challenge-ref" })).candidate.status, "denied");
    assert.equal((await verifiedCandidate({ candidateTransitionRequestId: "wrong-transition" })).candidate.status, "denied");
    assert.equal((await verifiedCandidate({ snapshot: lockedSnapshot("session-1") })).candidate.status, "denied");
    assert.equal((await verifiedCandidate({ transitionEvent: "request_recovery" })).candidate.status, "denied");
  });

  it("performs only the controlled unlocking to partially_unlocked transition", async function () {
    const { snapshot, candidate } = await verifiedCandidate();
    const store = createEphemeralProductionVerificationConsumptionStore();
    const result = transitionUserSessionWithProductionVerification({
      requestId: "partial-unlock-1",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-transition-1",
        event: "unlock_succeeded"
      },
      candidate: candidate.value,
      consumptionStore: store
    });

    assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
    assert.equal(result.value.transitionResult.previousState, "unlocking");
    assert.equal(result.value.transitionResult.nextState, "partially_unlocked");
    assert.equal(result.value.transitionResult.snapshot.state, "partially_unlocked");
    assert.notEqual(result.value.transitionResult.snapshot.state, "unlocked");
    assert.equal(result.value.transitionResult.snapshot.unlocksVault, false);
    assert.equal(result.value.transitionResult.snapshot.grantsAuthority, false);
    assert.equal(result.value.transitionResult.snapshot.metadata.lifecycleAuthenticationFactorVerified, true);
    assert.equal(result.value.transitionResult.snapshot.metadata.deviceVaultUnlocked, false);
    assert.equal(result.value.transitionResult.snapshot.metadata.protectedStateAvailable, false);
    assert.equal(result.value.transitionResult.snapshot.metadata.activeCapabilitiesAvailable, false);
    assert.equal(result.value.transitionResult.snapshot.metadata.authorizationAvailable, false);
    assert.equal(result.value.transitionResult.snapshot.metadata.strongerVaultUnlockRequired, true);
    assert.equal(result.value.sessionKeysCreated, false);
    assertNoAuthority(result.value);
  });

  it("rejects replayed consumption and never reaches full unlocked", async function () {
    const { snapshot, candidate } = await verifiedCandidate();
    const store = createEphemeralProductionVerificationConsumptionStore();
    const request = {
      requestId: "partial-unlock-1",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-transition-1",
        event: "unlock_succeeded"
      },
      candidate: candidate.value,
      consumptionStore: store
    };

    const first = transitionUserSessionWithProductionVerification(request);
    const second = transitionUserSessionWithProductionVerification(request);

    assert.equal(first.status, "approved");
    assert.equal(first.value.transitionResult.nextState, "partially_unlocked");
    assert.equal(second.status, "denied");
    assert.ok(second.error.details.errors.some((error) => error.includes("replayed")));
    assert.equal(store.getAll().length, 1);
  });

  it("derives User Session context copy without capabilities, vault access, or full unlock claim", async function () {
    const { snapshot, candidate } = await verifiedCandidate();
    const partial = transitionUserSessionWithProductionVerification({
      requestId: "partial-unlock-1",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-transition-1",
        event: "unlock_succeeded"
      },
      candidate: candidate.value
    });
    const baseContext = createUserSessionContext({
      sessionId: snapshot.sessionId,
      ownerCommitment: "0x1234",
      status: "locked",
      activeCapabilityIds: [],
      pendingIntentIds: [],
      policyMode: "default"
    }).context;
    const derived = deriveUserSessionContextFromProductionVerifiedPartialUnlock({
      userSessionContext: baseContext,
      lifecycleSnapshot: partial.value.transitionResult.snapshot,
      candidate: candidate.value
    });

    assert.equal(derived.status, "approved");
    assert.equal(derived.context.status, "partially-unlocked");
    assert.deepEqual(derived.context.activeCapabilityIds, []);
    assert.equal(baseContext.status, "locked");
    assert.equal(derived.context.metadata.deviceVaultUnlocked, false);
    assert.equal(derived.context.metadata.protectedStateAvailable, false);
    assert.equal(derived.context.metadata.authorizationAvailable, false);
  });

  it("creates sanitized audit drafts without raw WebAuthn payloads", async function () {
    const { snapshot, candidate } = await verifiedCandidate();
    const result = transitionUserSessionWithProductionVerification({
      requestId: "partial-unlock-1",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-transition-1",
        event: "unlock_succeeded"
      },
      candidate: candidate.value
    });
    const auditJson = JSON.stringify(result.value.auditEventDraft);

    assert.equal(result.value.auditEventDraft.persisted, false);
    assert.equal(auditJson.includes("clientDataJSON"), false);
    assert.equal(auditJson.includes("authenticatorData"), false);
    assert.equal(auditJson.includes("signature"), false);
    assert.equal(auditJson.includes("publicKey"), false);
    assert.equal(auditJson.includes("privateKey"), false);
  });

  it("exposes candidate and partial unlock through the validation-only Runtime API facade", async function () {
    const { snapshot, verification } = await verifiedCandidate();
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const consumptionStore = createEphemeralProductionVerificationConsumptionStore();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      productionVerificationConsumptionStore: consumptionStore
    });
    const candidateResult = api.requestLifecycleTransitionCandidate({
      requestId: "facade-candidate-1",
      productionAuthenticationVerification: verification.value,
      lifecycleEligibility: verification.value.lifecycleEligibility,
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-transition-1",
        event: "unlock_succeeded"
      },
      expectedSessionId: snapshot.sessionId,
      expectedOwnerCommitment: "0x1234",
      expectedCredentialId: "credential-1",
      expectedProviderId: "webauthn-provider-1",
      expectedChallengeReferenceId: "challenge-reference-1",
      requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"]
    });
    const partialResult = api.requestProductionVerifiedPartialUnlock({
      requestId: "facade-partial-unlock-1",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "unlock-transition-1",
        event: "unlock_succeeded"
      },
      candidate: candidateResult.value.lifecycleTransitionCandidate
    });

    assert.equal(candidateResult.status, "approved");
    assert.equal(candidateResult.value.lifecycleTransitionCandidate.outcome, "candidate_created");
    assert.equal(partialResult.status, "approved", partialResult.error?.details?.errors?.join("\n"));
    assert.equal(partialResult.value.productionVerifiedPartialUnlock.transitionResult.nextState, "partially_unlocked");
    assert.equal(partialResult.value.productionVerifiedPartialUnlock.deviceVaultUnlocked, false);
    assert.equal(partialResult.value.productionVerifiedPartialUnlock.authorizationCreated, false);
    assert.equal(consumptionStore.getAll().length, 1);
    assert.equal(auditDraftCollector.count() >= 2, true);
  });

  it("runs Alpha 0 production WebAuthn partial unlock diagnostic in text and JSON modes", async function () {
    let textOutput = "";
    let jsonOutput = "";
    let errorOutput = "";
    const text = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_webauthn_partial_unlock"],
      output: { write(chunk) { textOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });
    const json = await runAlpha0Shell({
      argv: ["--lifecycle", "--lifecycle-sequence", "production_webauthn_partial_unlock", "--json"],
      output: { write(chunk) { jsonOutput += chunk; return true; } },
      errorOutput: { write(chunk) { errorOutput += chunk; return true; } }
    });

    assert.equal(text.exitCode, 0, errorOutput);
    assert.match(textOutput, /production WebAuthn assertion verified from explicit in-memory inputs/i);
    assert.match(textOutput, /browser WebAuthn prompt.*not invoked/i);
    assert.match(textOutput, /Device Vault unlock: not performed/i);
    assert.match(textOutput, /Final lifecycle state: partially_unlocked/i);
    assert.equal(json.exitCode, 0, errorOutput);
    const parsed = JSON.parse(jsonOutput);
    assert.equal(parsed.finalState, "partially_unlocked");
    assert.equal(parsed.nonAuthority.productionAuthenticationPerformed, true);
    assert.equal(parsed.nonAuthority.vaultUnlocked, false);
    assert.equal(parsed.productionVerifiedPartialUnlock.nextState, "partially_unlocked");
  });
});
