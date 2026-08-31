const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");
const { ethers } = require("hardhat");

const {
  arrayBufferToBase64Url
} = require("../../apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts");
const {
  createInMemoryAuditDraftCollector,
  createInMemoryProductionAuthenticationVerificationCollector,
  createValidationOnlyRuntimeApi,
  getExpiredVerifications,
  getReplayFailures,
  getSuccessfulVerifications,
  groupByCredential,
  groupByOutcome,
  groupByProvider,
  groupBySession,
  summarizeProductionAuthenticationVerifications,
  validateProductionAuthenticationVerificationCorrelation,
  validateProductionAuthenticationVerificationRequest,
  validateProductionAuthenticationVerificationResult,
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
    publicKey,
    privateKey,
    publicKeyHex: ethers.hexlify(publicKeySpki)
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

function signWebAuthnAssertion({
  privateKey,
  rpId,
  origin,
  challenge,
  flags = 0x05,
  signCount = 1,
  invalidSignature = false
}) {
  const authenticatorData = buildAuthenticatorData({ rpId, flags, signCount });
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin
  }));
  const signedBytes = Buffer.concat([
    authenticatorData,
    sha256(clientDataJSON)
  ]);
  const signer = nodeCrypto.createSign("SHA256");
  signer.update(signedBytes);
  signer.end();
  const signature = Buffer.from(signer.sign(privateKey));
  if (invalidSignature) {
    signature[signature.length - 1] ^= 0x01;
  }

  return {
    authenticatorData,
    clientDataJSON,
    signature
  };
}

function buildAssertion({
  credentialId = "credential-1",
  privateKey,
  rpId,
  origin,
  challenge,
  flags = 0x05,
  signCount = 1,
  invalidSignature = false
}) {
  const signed = signWebAuthnAssertion({
    privateKey,
    rpId,
    origin,
    challenge,
    flags,
    signCount,
    invalidSignature
  });

  return {
    id: credentialId,
    rawId: credentialId,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      authenticatorData: arrayBufferToBase64Url(signed.authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(signed.clientDataJSON),
      signature: arrayBufferToBase64Url(signed.signature),
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

function verificationRequest(overrides = {}) {
  const keyPair = overrides.keyPair ?? generateP256CredentialKeyPair();
  const challenge = overrides.challenge ?? "production-challenge-1";
  const origin = overrides.origin ?? "https://philcore.local";
  const rpId = overrides.rpId ?? "philcore.local";
  const credentialId = overrides.credentialId ?? "credential-1";

  return {
    requestId: overrides.requestId ?? "production-auth-verification-1",
    providerKind: overrides.providerKind ?? "webauthn_passkey",
    providerId: overrides.providerId ?? "webauthn-provider-1",
    assertion: overrides.assertion ?? buildAssertion({
      credentialId: overrides.assertionCredentialId ?? credentialId,
      privateKey: keyPair.privateKey,
      rpId: overrides.assertionRpId ?? rpId,
      origin: overrides.assertionOrigin ?? origin,
      challenge: overrides.assertionChallenge ?? challenge,
      flags: overrides.flags ?? 0x05,
      signCount: overrides.signCount ?? 7,
      invalidSignature: overrides.invalidSignature ?? false
    }),
    credential: overrides.credential ?? {
      credentialId,
      credentialIdHash: ethers.id("credential-id-hash"),
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
    correlation: overrides.correlation ?? {
      sessionId: "session-1",
      lifecycleTransitionRequestId: "unlock-transition-1",
      lifecycleEvent: "unlock_succeeded",
      ownerCommitment: "0x1234",
      applicationId: "ethereum-net",
      credentialId,
      deviceId: "device-1",
      providerId: overrides.providerId ?? "webauthn-provider-1",
      auditCorrelationId: overrides.auditCorrelationId ?? "session-1:unlock-transition-1:prod-auth"
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
    requestedAt: overrides.requestedAt,
    auditCorrelationId: overrides.auditCorrelationId,
    metadata: overrides.metadata
  };
}

function assertNoAuthority(result) {
  assert.equal(result.authenticatesRuntime, false);
  assert.equal(result.productionAuthenticationPerformed, false);
  assert.equal(result.browserCredentialPrompted, false);
  assert.equal(result.vaultUnlocked, false);
  assert.equal(result.counterPersisted, false);
  assert.equal(result.grantsCapability, false);
  assert.equal(result.createsAuthorizationPackage, false);
  assert.equal(result.performsTrustDecision, false);
  assert.equal(result.performsPolicyDecision, false);
  assert.equal(result.executesAdapter, false);
  assert.equal(result.persisted, false);
}

describe("PhilCore production authentication verification boundary", function () {
  it("uses the existing WebAuthn verifier for a valid assertion and creates lifecycle eligibility only", async function () {
    const request = verificationRequest();
    const validation = validateProductionAuthenticationVerificationRequest(request);
    assert.equal(validation.valid, true, validation.errors.join("\n"));

    const result = await verifyProductionWebAuthnAuthentication(request);

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "webauthn_assertion_verified");
    assert.equal(result.value.status, "verification_succeeded");
    assert.equal(result.value.evidenceSummary.productionVerified, true);
    assert.equal(result.value.evidenceSummary.signatureVerified, true);
    assert.equal(result.value.evidenceSummary.counterStatus, "advanced");
    assert.equal(result.value.lifecycleEligibility.eligibleForFutureLifecycleTransition, true);
    assert.equal(result.value.lifecycleEligibility.performsTransitionNow, false);
    assert.equal(result.value.lifecycleEligibility.unlocksVault, false);
    assert.equal(result.value.lifecycleEligibility.authenticatesRuntime, false);
    assert.equal(validateProductionAuthenticationVerificationResult(result.value).valid, true);
    assert.equal(validateProductionAuthenticationVerificationCorrelation(request, result.value).valid, true);
    assertNoAuthority(result.value);
  });

  it("rejects invalid signatures without lifecycle eligibility", async function () {
    const result = await verifyProductionWebAuthnAuthentication(verificationRequest({
      invalidSignature: true
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "invalid_signature");
    assert.equal(result.value.evidenceSummary.signatureVerified, false);
    assert.equal(result.value.lifecycleEligibility, undefined);
    assertNoAuthority(result.value);
  });

  it("reports RP ID mismatch", async function () {
    const result = await verifyProductionWebAuthnAuthentication(verificationRequest({
      expectedRpId: "wrong.philcore.local"
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "rp_mismatch");
    assert.equal(result.value.evidenceSummary.rpIdHashMatched, false);
    assert.equal(result.value.lifecycleEligibility, undefined);
  });

  it("reports challenge mismatch", async function () {
    const result = await verifyProductionWebAuthnAuthentication(verificationRequest({
      expectedChallenge: "wrong-challenge"
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "challenge_mismatch");
    assert.equal(result.value.evidenceSummary.challengeMatched, false);
    assert.equal(result.value.lifecycleEligibility, undefined);
  });

  it("reports origin mismatch", async function () {
    const result = await verifyProductionWebAuthnAuthentication(verificationRequest({
      expectedOrigin: "https://evil.example"
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "origin_mismatch");
    assert.equal(result.value.evidenceSummary.originMatched, false);
    assert.equal(result.value.lifecycleEligibility, undefined);
  });

  it("reports stale assertions", async function () {
    const result = await verifyProductionWebAuthnAuthentication(verificationRequest({
      freshness: {
        collectedAt: pastDate(120_000),
        staleAfter: pastDate(1_000),
        expiresAt: futureDate()
      }
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "stale_assertion");
    assert.equal(result.value.status, "verification_expired");
    assert.equal(result.value.lifecycleEligibility, undefined);
  });

  it("reports replay detection from counter rollback or clone suspicion", async function () {
    const result = await verifyProductionWebAuthnAuthentication(verificationRequest({
      signCount: 6,
      previousSignCount: 6,
      storedSignCount: 6
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "replay_detected");
    assert.equal(result.value.status, "verification_replayed");
    assert.equal(result.value.evidenceSummary.counterStatus, "clone-suspected");
    assert.equal(result.value.lifecycleEligibility, undefined);
  });

  it("reports unsupported providers without invoking browser UI or creating authority", async function () {
    const result = await verifyProductionWebAuthnAuthentication(verificationRequest({
      providerKind: "developer_fixture"
    }));

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "unsupported_provider");
    assert.equal(result.value.status, "verification_unsupported");
    assert.equal(result.value.lifecycleEligibility, undefined);
    assert.equal(result.value.evidenceSummary.productionVerified, false);
    assertNoAuthority(result.value);
  });

  it("rejects malformed payloads before verification", async function () {
    const result = await verifyProductionWebAuthnAuthentication({
      ...verificationRequest(),
      assertion: null
    });

    assert.equal(result.status, "denied");
    assert.equal(result.error.code, "PRODUCTION_AUTHENTICATION_VERIFICATION_INVALID");
    assert.ok(result.error.details.errors.some((error) => error.includes("assertion")));
  });

  it("collects production verification results in process-local memory", async function () {
    const collector = createInMemoryProductionAuthenticationVerificationCollector({
      maxResultCount: 2
    });
    const first = (await verifyProductionWebAuthnAuthentication(verificationRequest({
      requestId: "prod-auth-1",
      auditCorrelationId: "prod-auth-1"
    }))).value;
    const second = (await verifyProductionWebAuthnAuthentication(verificationRequest({
      requestId: "prod-auth-2",
      auditCorrelationId: "prod-auth-2"
    }))).value;
    const third = (await verifyProductionWebAuthnAuthentication(verificationRequest({
      requestId: "prod-auth-3",
      auditCorrelationId: "prod-auth-3"
    }))).value;

    assert.equal(collector.count(), 0);
    assert.equal(collector.addResult(first).status, "collected");
    assert.equal(collector.addResult(first).status, "rejected_duplicate");
    assert.equal(collector.addResult(second).status, "collected");
    const evicted = collector.addResult(third);
    assert.equal(evicted.status, "evicted_oldest");
    assert.equal(evicted.evictedResults[0].verificationId, first.verificationId);
    assert.equal(collector.count(), 2);
    assert.equal(collector.getById(second.verificationId).requestId, "prod-auth-2");
    assert.equal(collector.filter({ requestId: "prod-auth-3" }).length, 1);
    assert.equal(collector.query({ limit: 1 }).length, 1);
    assert.equal(collector.removeResult(second.verificationId).status, "removed");
    assert.equal(collector.clear().status, "cleared");
    assert.equal(collector.count(), 0);
  });

  it("summarizes and groups verification results read-only", async function () {
    const success = (await verifyProductionWebAuthnAuthentication(verificationRequest({
      requestId: "prod-auth-success",
      auditCorrelationId: "prod-auth-success"
    }))).value;
    const expired = (await verifyProductionWebAuthnAuthentication(verificationRequest({
      requestId: "prod-auth-expired",
      auditCorrelationId: "prod-auth-expired",
      freshness: {
        collectedAt: pastDate(120_000),
        staleAfter: pastDate(1_000),
        expiresAt: futureDate()
      }
    }))).value;
    const replay = (await verifyProductionWebAuthnAuthentication(verificationRequest({
      requestId: "prod-auth-replay",
      auditCorrelationId: "prod-auth-replay",
      signCount: 6,
      previousSignCount: 6,
      storedSignCount: 6
    }))).value;
    const results = Object.freeze([success, expired, replay]);

    assert.equal(groupByProvider(results)["webauthn-provider-1"].length, 3);
    assert.equal(groupByOutcome(results).stale_assertion.length, 1);
    assert.equal(groupBySession(results)["session-1"].length, 3);
    assert.equal(groupByCredential(results)["credential-1"].length, 3);
    assert.equal(getSuccessfulVerifications(results).length, 1);
    assert.equal(getExpiredVerifications(results).length, 1);
    assert.equal(getReplayFailures(results).length, 1);

    const summary = summarizeProductionAuthenticationVerifications(results);
    assert.equal(summary.totalResultCount, 3);
    assert.equal(summary.resultsByOutcome.webauthn_assertion_verified, 1);
    assert.equal(summary.resultsByOutcome.stale_assertion, 1);
    assert.equal(summary.resultsByOutcome.replay_detected, 1);
    assert.equal(summary.grantsAuthority, false);
    assert.equal(summary.persisted, false);
    assert.equal(Object.isFrozen(summary), true);
  });

  it("integrates with the validation-only Runtime API facade and audit drafts", async function () {
    const auditCollector = createInMemoryAuditDraftCollector();
    const verificationCollector = createInMemoryProductionAuthenticationVerificationCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector: auditCollector,
      productionAuthenticationVerificationCollector: verificationCollector
    });

    const result = await api.requestProductionAuthenticationVerification(verificationRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.productionAuthenticationVerification.outcome, "webauthn_assertion_verified");
    assert.equal(result.value.productionAuthenticationVerification.lifecycleEligibility.performsTransitionNow, false);
    assert.equal(result.value.productionAuthenticationVerificationCollectionResult.status, "collected");
    assert.equal(result.value.auditEventDraft.category, "runtime");
    assert.equal(result.value.auditEventDraft.persisted, false);
    assert.equal(verificationCollector.count(), 1);
    assert.equal(auditCollector.count(), 1);
    assertNoAuthority(result.value.productionAuthenticationVerification);
  });
});
