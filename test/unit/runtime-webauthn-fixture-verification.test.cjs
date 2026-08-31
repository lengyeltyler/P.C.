const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");
const { ethers } = require("hardhat");

const {
  arrayBufferToBase64Url
} = require("../../apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts");
const {
  createCapabilityGrantDraft,
  createCapabilityRequestDraft,
  createEphemeralUserSessionStore,
  createInMemoryAuditDraftCollector,
  createPossessionVerificationRequestDraft,
  createTrustEvaluationDraft,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  evaluatePublicTrustMetadata,
  verifyPossessionDraftWithWebAuthnFixture
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

function capabilityDraft(id = "capability-1") {
  const result = createCapabilityGrantDraft({
    capabilityRequest: createCapabilityRequestDraft({
      requestId: id,
      applicationId: "ethereum-net",
      capability: "request_message_signature",
      sensitivity: "sensitive",
      requestedAt: "2026-07-10T00:00:00.000Z"
    }),
    sessionId: "session-1",
    auditCorrelationId: `${id}:capability-draft`,
    createdAt: "2026-07-10T00:00:00.000Z"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function trustDraft(id = "trust-draft-1") {
  const result = createTrustEvaluationDraft({
    requestId: id,
    capabilityGrantDraft: capabilityDraft(`${id}:capability`),
    credentialReference: {
      credentialId: "credential-1",
      credentialKind: "webauthn",
      providerKind: "webauthn-passkey-device-identity-v1",
      credentialStatusReference: "active"
    },
    deviceReference: {
      deviceId: "device-1",
      providerKind: "webauthn-passkey-device-identity-v1"
    },
    ownerCommitment: "0x1234",
    auditCorrelationId: id,
    createdAt: "2026-07-10T00:00:00.000Z"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function publicDeviceMetadata() {
  return {
    version: "phil-device-identity-v1",
    providerKind: "webauthn-passkey-device-identity-v1",
    deviceIdentityId: "0xdevice",
    deviceKeyId: "0xdevicekey",
    credentialId: "credential-1",
    credentialPublicKey: "0xcredentialpublic",
    philIdentity: {
      version: "phil-identity-v1",
      ownerCommitment: "0x1234"
    },
    productionSafe: true,
    privateMaterialExportable: false,
    hardwareBacked: true,
    createdAt: "2026-07-10T00:00:00.000Z"
  };
}

function publicMetadataEvaluation() {
  const result = evaluatePublicTrustMetadata({
    requestId: "public-trust-evaluation-1",
    trustEvaluationDraft: trustDraft(),
    credential: {
      credentialId: "credential-1",
      credentialKind: "webauthn",
      providerKind: "webauthn-passkey-device-identity-v1",
      lifecycleStatus: "active",
      ownerCommitment: "0x1234"
    },
    device: {
      deviceId: "device-1",
      providerKind: "webauthn-passkey-device-identity-v1",
      lifecycleStatus: "active",
      ownerCommitment: "0x1234",
      publicMetadata: publicDeviceMetadata()
    },
    ownerCommitment: "0x1234",
    auditCorrelationId: "public-trust-evaluation-1"
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function possessionDraft(overrides = {}) {
  const result = createPossessionVerificationRequestDraft({
    requestId: "possession-draft-1",
    publicTrustMetadataEvaluation: publicMetadataEvaluation(),
    auditCorrelationId: "possession-draft-1",
    ...overrides
  });
  assert.equal(result.status, "approved");
  return result.value;
}

function fixtureRequest(overrides = {}) {
  const keyPair = overrides.keyPair ?? generateP256CredentialKeyPair();
  const draft = overrides.draft ?? possessionDraft(overrides.draftInput ?? {});
  const challenge = overrides.challenge ?? "fixture-challenge-1";
  const origin = overrides.origin ?? "http://localhost";
  const rpId = overrides.rpId ?? "localhost";
  const credentialId = overrides.credentialId ?? "credential-1";

  return {
    requestId: overrides.requestId ?? "webauthn-fixture-request-1",
    possessionVerificationRequestDraft: draft,
    fixture: {
      assertion: buildAssertion({
        credentialId: overrides.assertionCredentialId ?? credentialId,
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
        credentialIdHash: ethers.id("credential-id-hash"),
        rawId: credentialId,
        publicKey: keyPair.publicKeyHex,
        publicKeyAlgorithm: -7,
        signCount: overrides.previousSignCount ?? 6
      },
      descriptor: {
        fixtureId: overrides.fixtureId ?? "fixture-1",
        challengeBindingReference: overrides.challengeBindingReference
          ?? draft.challengeDescriptor.challengeReference,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
        expectedUserVerification: overrides.expectedUserVerification ?? "required",
        previousSignCount: overrides.previousSignCount ?? 6,
        metadata: overrides.descriptorMetadata
      }
    },
    metadata: overrides.metadata,
    auditCorrelationId: overrides.auditCorrelationId
  };
}

function userSession(activeCapabilities = []) {
  const result = createUserSessionContext({
    sessionId: "session-1",
    ownerCommitment: "0x1234",
    status: "unlocked",
    activeApplicationId: "ethereum-net",
    activeCapabilityIds: activeCapabilities,
    pendingIntentIds: [],
    policyMode: "default"
  });
  assert.equal(result.status, "approved");
  return result.context;
}

function assertFixtureOnly(value) {
  const text = JSON.stringify(value).toLowerCase();
  assert.equal(text.includes("trusted\":true"), false);
  assert.equal(text.includes("authenticated\":true"), false);
  assert.equal(text.includes("approved\":true"), false);
  assert.equal(text.includes("authorizationpackage"), false);
  assert.equal(value.fixtureOnly, true);
  assert.equal(value.productionAuthentication, false);
  assert.equal(value.authenticatesUser, false);
  assert.equal(value.verifiesProductionPossession, false);
  assert.equal(value.providesTrustDecision, false);
  assert.equal(value.grantsAuthority, false);
  assert.equal(value.persisted, false);
}

describe("PhilCore WebAuthn fixture possession verification bridge", function () {
  it("valid WebAuthn fixture produces fixture_verified", async function () {
    const result = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "fixture_verified");
    assert.equal(result.value.signatureVerified, true);
    assert.equal(result.value.challengeMatched, true);
    assert.equal(result.value.originMatched, true);
    assert.equal(result.value.rpIdHashMatched, true);
    assert.equal(result.value.counterStatus, "advanced");
    assert.equal(result.value.counterPersisted, false);
    assertFixtureOnly(result.value);
  });

  it("rejects malformed fixture requests", async function () {
    const result = await verifyPossessionDraftWithWebAuthnFixture({
      requestId: "",
      possessionVerificationRequestDraft: possessionDraft()
    });

    assert.equal(result.status, "denied");
    assert.equal(result.value, undefined);
    assert.ok(result.error.details.errors.includes("fixture is required"));
  });

  it("reports invalid signature, challenge mismatch, origin mismatch, and RP ID hash mismatch", async function () {
    const invalidSignature = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      invalidSignature: true
    }));
    const challengeMismatch = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      assertionChallenge: "wrong-challenge"
    }));
    const originMismatch = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      assertionOrigin: "https://evil.example"
    }));
    const rpMismatch = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      assertionRpId: "evil.example"
    }));

    assert.equal(invalidSignature.value.outcome, "signature_invalid");
    assert.equal(challengeMismatch.value.outcome, "challenge_mismatch");
    assert.equal(originMismatch.value.outcome, "origin_mismatch");
    assert.equal(rpMismatch.value.outcome, "rp_id_hash_mismatch");
  });

  it("reports missing user presence and missing required user verification", async function () {
    const missingPresence = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      flags: 0x04
    }));
    const missingVerification = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      flags: 0x01
    }));

    assert.equal(missingPresence.value.outcome, "user_presence_missing");
    assert.equal(missingPresence.value.userPresent, false);
    assert.equal(missingVerification.value.outcome, "user_verification_missing");
    assert.equal(missingVerification.value.userVerified, false);
  });

  it("reports rolled-back or cloned counter behavior without persistence", async function () {
    const rollback = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      signCount: 4,
      previousSignCount: 5
    }));
    const cloneSuspected = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      signCount: 5,
      previousSignCount: 5
    }));

    assert.equal(rollback.value.outcome, "counter_invalid");
    assert.equal(rollback.value.counterStatus, "rollback");
    assert.equal(rollback.value.counterPersisted, false);
    assert.equal(cloneSuspected.value.counterStatus, "clone-suspected");
    assert.equal(cloneSuspected.value.counterPersisted, false);
  });

  it("reports unsupported provider or method and expired draft", async function () {
    const unsupported = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      draftInput: {
        verificationMethod: "device_signature"
      }
    }));
    const expired = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      draftInput: {
        expiresAt: new Date(Date.now() - 60_000).toISOString()
      }
    }));

    assert.equal(unsupported.value.outcome, "fixture_unsupported");
    assert.equal(expired.value.outcome, "fixture_rejected");
  });

  it("reports challenge binding and credential correlation mismatch", async function () {
    const bindingMismatch = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      challengeBindingReference: "wrong-binding-reference"
    }));
    const credentialMismatch = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      credentialId: "credential-2"
    }));

    assert.equal(bindingMismatch.value.outcome, "challenge_mismatch");
    assert.equal(credentialMismatch.value.outcome, "fixture_rejected");
  });

  it("rejects secret-shaped metadata without echoing secret values", async function () {
    const result = await verifyPossessionDraftWithWebAuthnFixture(fixtureRequest({
      metadata: {
        privateKey: "must-not-enter"
      }
    }));

    assert.equal(result.status, "denied");
    assert.equal(JSON.stringify(result).includes("must-not-enter"), false);
  });

  it("facade creates an audit event draft for fixture verification", async function () {
    const auditDraftCollector = createInMemoryAuditDraftCollector();
    const api = createValidationOnlyRuntimeApi({
      auditDraftCollector,
      userSessionContext: userSession()
    });

    const result = await api.requestWebAuthnFixturePossessionVerification(fixtureRequest());

    assert.equal(result.status, "approved");
    assert.equal(result.value.webAuthnFixtureVerificationArtifact.outcome, "fixture_verified");
    assert.equal(result.value.auditEventDraft.category, "trust");
    assert.equal(result.value.auditDraftCollectionResult.status, "collected");
    assert.equal(auditDraftCollector.count(), 1);
    assertFixtureOnly(result.value.webAuthnFixtureVerificationArtifact);
  });

  it("does not call browser WebAuthn, Device Vault, storage, credential loading, session mutation, capability grants, policy, authorization, proof, or adapter hooks", async function () {
    const hooks = {
      browserWebAuthnCalls: 0,
      deviceVaultCalls: 0,
      storageCalls: 0,
      credentialLoadCalls: 0,
      counterPersistenceCalls: 0,
      sessionMutationCalls: 0,
      capabilityGrantCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const store = createEphemeralUserSessionStore();
    store.setSessionContext(userSession(["existing-capability"]));
    const api = createValidationOnlyRuntimeApi({
      userSessionStore: store
    });

    const result = await api.requestWebAuthnFixturePossessionVerification(fixtureRequest({
      metadata: {
        hooks
      }
    }));

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      browserWebAuthnCalls: 0,
      deviceVaultCalls: 0,
      storageCalls: 0,
      credentialLoadCalls: 0,
      counterPersistenceCalls: 0,
      sessionMutationCalls: 0,
      capabilityGrantCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.deepEqual(store.getSessionContext().activeCapabilityIds, ["existing-capability"]);
    assertFixtureOnly(result.value.webAuthnFixtureVerificationArtifact);
  });
});
