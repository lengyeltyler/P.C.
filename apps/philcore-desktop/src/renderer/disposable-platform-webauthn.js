(function exposeDisposablePlatformWebAuthn(root) {
  const TEST_LABEL = "O42_1_DISPOSABLE_PLATFORM_WEBAUTHN_TEST_ONLY";
  const CANONICAL_RP_ID = "recovery.philcore.localhost";
  const CANONICAL_ORIGIN = "https://recovery.philcore.localhost:18443";

  function flags(authenticatorData) {
    const bytes = new Uint8Array(authenticatorData);
    if (bytes.length < 37) throw new Error("disposable_authenticator_data_truncated");
    const value = bytes[32];
    return Object.freeze({
      userPresent: Boolean(value & 0x01),
      userVerified: Boolean(value & 0x04),
      backupEligible: Boolean(value & 0x08),
      backupState: Boolean(value & 0x10)
    });
  }

  function bytesToBase64Url(value) {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  }

  function base64UrlToBytes(value) {
    const padded = `${String(value).replaceAll("-", "+").replaceAll("_", "/")}${"=".repeat((4 - String(value).length % 4) % 4)}`;
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function assertCanonicalContext(rpId) {
    if (rpId !== CANONICAL_RP_ID) {
      throw new Error("disposable_rp_id_rejected");
    }
    if (root.location?.origin !== CANONICAL_ORIGIN) {
      throw new Error("disposable_origin_rejected");
    }
    if (
      !root.isSecureContext
      || !root.PublicKeyCredential
      || !root.navigator?.credentials
    ) throw new Error("disposable_platform_webauthn_unavailable");
  }

  function serializeRegistration(credential) {
    return Object.freeze({
      id: credential.id,
      rawId: bytesToBase64Url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || null,
      response: Object.freeze({
        clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
        attestationObject: bytesToBase64Url(credential.response.attestationObject),
        transports: typeof credential.response.getTransports === "function"
          ? credential.response.getTransports()
          : ["internal"],
        publicKey: typeof credential.response.getPublicKey === "function"
          && credential.response.getPublicKey()
          ? bytesToBase64Url(credential.response.getPublicKey())
          : undefined,
        publicKeyAlgorithm: typeof credential.response.getPublicKeyAlgorithm === "function"
          ? credential.response.getPublicKeyAlgorithm()
          : -7
      }),
      clientExtensionResults: Object.freeze({})
    });
  }

  function serializeAssertion(assertion) {
    return Object.freeze({
      id: assertion.id,
      rawId: bytesToBase64Url(assertion.rawId),
      type: assertion.type,
      authenticatorAttachment: assertion.authenticatorAttachment || null,
      response: Object.freeze({
        authenticatorData: bytesToBase64Url(assertion.response.authenticatorData),
        clientDataJSON: bytesToBase64Url(assertion.response.clientDataJSON),
        signature: bytesToBase64Url(assertion.response.signature),
        userHandle: assertion.response.userHandle
          ? bytesToBase64Url(assertion.response.userHandle)
          : null
      }),
      clientExtensionResults: Object.freeze({})
    });
  }

  async function createWithChallenge({
    challenge,
    rpId,
    rpName,
    timeoutMs = 60_000
  }) {
    assertCanonicalContext(rpId);
    if (typeof challenge !== "string" || challenge.length < 16) {
      throw new Error("disposable_main_challenge_required");
    }
    const userId = crypto.getRandomValues(new Uint8Array(32));
    const credential = await root.navigator.credentials.create({
      publicKey: {
        challenge: base64UrlToBytes(challenge),
        rp: { id: rpId, name: rpName },
        user: { id: userId, name: TEST_LABEL, displayName: TEST_LABEL },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required"
        },
        attestation: "none",
        timeout: timeoutMs
      }
    });
    if (!credential) throw new Error("disposable_credential_not_created");
    return credential;
  }

  async function getWithChallenge({
    challenge,
    rpId,
    credentialRawId,
    timeoutMs = 60_000
  }) {
    assertCanonicalContext(rpId);
    if (typeof challenge !== "string" || challenge.length < 16) {
      throw new Error("disposable_main_challenge_required");
    }
    const assertion = await root.navigator.credentials.get({
      publicKey: {
        challenge: base64UrlToBytes(challenge),
        rpId,
        allowCredentials: [{ type: "public-key", id: credentialRawId }],
        userVerification: "required",
        timeout: timeoutMs
      }
    });
    if (!assertion) throw new Error("disposable_assertion_not_created");
    return assertion;
  }

  async function run({
    begin,
    verifyRegistration,
    verifyAssertion,
    rpId,
    rpName,
    timeoutMs = 60_000
  }) {
    assertCanonicalContext(rpId);
    if (
      typeof begin !== "function"
      || typeof verifyRegistration !== "function"
      || typeof verifyAssertion !== "function"
    ) {
      throw new Error("disposable_main_orchestration_required");
    }
    const beginResult = await begin();
    if (beginResult?.status === "failed") {
      throw new Error(beginResult.reason || "disposable_begin_failed");
    }
    if (typeof beginResult?.challenge !== "string") {
      throw new Error("disposable_main_challenge_required");
    }
    const credential = await createWithChallenge({
      challenge: beginResult.challenge,
      rpId,
      rpName: rpName || beginResult.rp?.name || "PhilCore Recovery Disposable Test",
      timeoutMs
    });
    const registration = serializeRegistration(credential);
    const registrationResult = await verifyRegistration(registration);
    if (registrationResult?.status === "failed" || registrationResult?.verified !== true) {
      throw new Error(
        registrationResult?.reason
        || registrationResult?.errorCode
        || "disposable_registration_verify_failed"
      );
    }
    if (typeof registrationResult.assertionChallenge !== "string") {
      throw new Error("disposable_assertion_challenge_required");
    }
    const assertion = await getWithChallenge({
      challenge: registrationResult.assertionChallenge,
      rpId,
      credentialRawId: credential.rawId,
      timeoutMs
    });
    const assertionPayload = serializeAssertion(assertion);
    const assertionResult = await verifyAssertion(assertionPayload);
    if (assertionResult?.status === "failed" || assertionResult?.verified !== true) {
      throw new Error(
        assertionResult?.reason
        || assertionResult?.errorCode
        || "disposable_assertion_verify_failed"
      );
    }
    // Renderer policyAccepted alone has no authority; success is main verify result.
    return Object.freeze({
      label: TEST_LABEL,
      created: true,
      asserted: true,
      verified: true,
      disposableCreationAssertion: assertionResult.disposableCreationAssertion === true,
      productionAuthorityCreated: false,
      rawCredentialIdReturned: false,
      cleanup:
        assertionResult.cleanup
        || "OS_CREDENTIAL_DELETION_API_UNAVAILABLE_PRODUCTION_UNREFERENCED"
    });
  }

  root.PhilCoreDisposablePlatformWebAuthn = Object.freeze({
    CANONICAL_ORIGIN,
    CANONICAL_RP_ID,
    TEST_LABEL,
    flags,
    bytesToBase64Url,
    base64UrlToBytes,
    serializeRegistration,
    serializeAssertion,
    createWithChallenge,
    getWithChallenge,
    run
  });
  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.PhilCoreDisposablePlatformWebAuthn;
  }
}(globalThis));
