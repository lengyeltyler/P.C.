const APP_MODE = Object.freeze({
  LOCAL_ALPHA: "local_alpha",
  LOCAL_FIXTURE_BETA: "local_fixture_beta",
  PUBLIC_TESTNET_DISABLED: "public_testnet_disabled",
  MAINNET_DISABLED: "mainnet_disabled"
});

const CHANNELS = Object.freeze({
  GET_SNAPSHOT: "philcore:state:getSnapshot",
  LIST_LOCAL_IDENTITIES: "philcore:identity:listLocal",
  CREATE_LOCAL_IDENTITY: "philcore:identity:createLocal",
  OPEN_LOCAL_IDENTITY: "philcore:identity:openLocal",
  RENAME_LOCAL_IDENTITY: "philcore:identity:renameLocal",
  GET_LOCKED_SUMMARY: "philcore:identity:getLockedSummary",
  GET_PLATFORM_AUTH_AVAILABILITY: "philcore:platformAuth:getAvailability",
  GET_PLATFORM_AUTH_STATUS: "philcore:platformAuth:getStatus",
  GET_PLATFORM_AUTH_POLICY: "philcore:platformAuth:getPolicy",
  ENROLL_PLATFORM_AUTH: "philcore:platformAuth:enroll",
  PLATFORM_UNLOCK: "philcore:platformAuth:unlock",
  DISABLE_PLATFORM_AUTH: "philcore:platformAuth:disable",
  REQUIRE_FRESH_PLATFORM_AUTH: "philcore:platformAuth:requireFreshAuthentication",
  CREATE_APPROVAL_PRESENTATION: "philcore:approval:createPresentation",
  GET_APPROVAL_PRESENTATION: "philcore:approval:getPresentation",
  RESPOND_APPROVAL: "philcore:approval:respond",
  CANCEL_APPROVAL: "philcore:approval:cancel",
  GET_APPROVAL_STATUS: "philcore:approval:getStatus",
  CONSUME_APPROVAL: "philcore:approval:consume",
  LIST_APPROVAL_HISTORY: "philcore:approval:listHistory",
  AUTHENTICATE_LOCAL: "philcore:session:authenticateLocal",
  UNLOCK_VAULT: "philcore:session:unlockVault",
  AUTHENTICATE_LOCAL_FIXTURE: "philcore:session:authenticateLocalFixture",
  LOCK_SESSION: "philcore:session:lock",
  GET_SESSION_STATE: "philcore:session:getState",
  GET_VAULT_STATUS: "philcore:vault:getStatus",
  GET_PROTECTED_VIEW: "philcore:vault:getProtectedView",
  LIST_PUBLIC_CREDENTIALS: "philcore:credentials:listPublic",
  GET_VALIDATOR_STATUS: "philcore:validator:getPublicStatus",
  GET_RECOVERY_STATUS: "philcore:recovery:getPublicStatus",
  RESET_LOCAL_IDENTITY: "philcore:identity:resetLocal",
  RUN_LOCAL_AUTHORIZATION_DEMO: "philcore:demo:runLocalAuthorization",
  START_REAL_LOCAL_AUTHORIZATION_WORKFLOW: "philcore:authorization:startLocalWorkflow",
  PREFLIGHT_REAL_LOCAL_AUTHORIZATION_WORKFLOW: "philcore:authorization:preflightLocalWorkflow",
  GET_REAL_LOCAL_AUTHORIZATION_WORKFLOW: "philcore:authorization:getWorkflow",
  REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH: "philcore:authorization:requestFreshAuth",
  RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL: "philcore:authorization:respondToApproval",
  CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW: "philcore:authorization:cancelWorkflow",
  GET_REAL_LOCAL_AUTHORIZATION_RESULT: "philcore:authorization:getResult",
  PREFLIGHT_SEPOLIA_USER_OPERATION_PREPARATION:
    "philcore:authorization:preflightSepoliaUserOperationPreparation",
  START_SEPOLIA_USER_OPERATION_PREPARATION:
    "philcore:authorization:startSepoliaUserOperationPreparation",
  GET_SEPOLIA_USER_OPERATION_PREPARATION:
    "philcore:authorization:getSepoliaUserOperationPreparation",
  FINALIZE_SEPOLIA_SIGNED_ARTIFACT:
    "philcore:authorization:finalizeSepoliaSignedArtifact",
  RUN_RECOVERY_DEMO: "philcore:recovery:runLocalDemo",
  RECOVERY_ENROLLMENT_PREFLIGHT: "philcore:recoveryEnrollment:preflight",
  RECOVERY_ENROLLMENT_STATUS: "philcore:recoveryEnrollment:status",
  RECOVERY_ENROLLMENT_BEGIN_CREDENTIAL: "philcore:recoveryEnrollment:beginCredential",
  RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC:
    "philcore:recoveryEnrollment:beginDisposableDiagnostic",
  RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC:
    "philcore:recoveryEnrollment:cancelDisposableDiagnostic",
  RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION:
    "philcore:recoveryEnrollment:verifyDisposableRegistration",
  RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION:
    "philcore:recoveryEnrollment:verifyDisposableAssertion",
  RECOVERY_ENROLLMENT_BEGIN_HARDWARE_FALLBACK: "philcore:recoveryEnrollment:beginHardwareFallback",
  RECOVERY_ENROLLMENT_STORE_CREDENTIAL: "philcore:recoveryEnrollment:storeCredential",
  RECOVERY_ENROLLMENT_BEGIN_PAIRING: "philcore:recoveryEnrollment:beginPairing",
  RECOVERY_ENROLLMENT_BEGIN_IPHONE_PAIRING:
    "philcore:recoveryEnrollment:beginIPhonePairing",
  RECOVERY_ENROLLMENT_IPHONE_PAIRING_STATUS:
    "philcore:recoveryEnrollment:iPhonePairingStatus",
  RECOVERY_ENROLLMENT_CANCEL_IPHONE_PAIRING:
    "philcore:recoveryEnrollment:cancelIPhonePairing",
  RECOVERY_ENROLLMENT_ACCEPT_PAIRING: "philcore:recoveryEnrollment:acceptPairing",
  RECOVERY_ENROLLMENT_COMPLETE_PAIRING: "philcore:recoveryEnrollment:completePairing",
  RECOVERY_ENROLLMENT_GENERATE_OFFLINE: "philcore:recoveryEnrollment:generateOffline",
  RECOVERY_ENROLLMENT_REVEAL_OFFLINE: "philcore:recoveryEnrollment:revealOffline",
  RECOVERY_ENROLLMENT_CONFIRM_OFFLINE_EXPORT: "philcore:recoveryEnrollment:confirmOfflineExport",
  RECOVERY_ENROLLMENT_RESTORE_OFFLINE: "philcore:recoveryEnrollment:restoreOffline",
  RECOVERY_ENROLLMENT_REVIEW_INDEPENDENCE: "philcore:recoveryEnrollment:reviewIndependence",
  RECOVERY_ENROLLMENT_COMPLETE: "philcore:recoveryEnrollment:complete",
  RECOVERY_ENROLLMENT_CANCEL: "philcore:recoveryEnrollment:cancel",
  RECOVERY_ENROLLMENT_LIST_PUBLIC_FACTORS: "philcore:recoveryEnrollment:listPublicFactors",
  RECOVERY_ENROLLMENT_DELETE_FACTOR: "philcore:recoveryEnrollment:deleteFactor",
  RECOVERY_ENROLLMENT_ROTATE_FACTOR: "philcore:recoveryEnrollment:rotateFactor",
  RECOVERY_TRANSPORT_BEGIN: "philcore:recoveryTransport:begin",
  RECOVERY_TRANSPORT_STATUS: "philcore:recoveryTransport:status",
  RECOVERY_TRANSPORT_BEGIN_ROLE0_ASSERTION:
    "philcore:recoveryTransport:beginRole0Assertion",
  RECOVERY_TRANSPORT_SUBMIT_ROLE0_ASSERTION:
    "philcore:recoveryTransport:submitRole0Assertion",
  RECOVERY_TRANSPORT_CANCEL: "philcore:recoveryTransport:cancel",
  ROUTINE_AUTHORIZATION_BEGIN: "philcore:routineAuthorization:begin",
  ROUTINE_AUTHORIZATION_BASELINE: "philcore:routineAuthorization:baseline",
  ROUTINE_AUTHORIZATION_STATUS: "philcore:routineAuthorization:status",
  ROUTINE_AUTHORIZATION_CANCEL: "philcore:routineAuthorization:cancel",
  ROUTINE_AUTHORIZATION_DELETE_DISPOSABLE_PROFILE:
    "philcore:routineAuthorization:deleteDisposableProfile",
  SEPOLIA_MINT_BEGIN: "philcore:sepoliaMint:begin",
  SEPOLIA_MINT_STATUS: "philcore:sepoliaMint:status",
  SEPOLIA_MINT_CANCEL: "philcore:sepoliaMint:cancel",
  LIST_AUDIT_EVENTS: "philcore:audit:list",
  GET_SETTINGS: "philcore:settings:get",
  UPDATE_SETTINGS: "philcore:settings:update",
  EXPORT_SANITIZED_DIAGNOSTICS: "philcore:diagnostics:exportSanitized",
  DIAGNOSE_STORAGE: "philcore:diagnostics:storage",
  DIAGNOSE_IDENTITY: "philcore:diagnostics:identity",
  DIAGNOSE_VAULT: "philcore:diagnostics:vault",
  DIAGNOSE_PLATFORM_AUTH: "philcore:diagnostics:platformAuth",
  DIAGNOSE_KEYCHAIN: "philcore:diagnostics:keychain",
  DIAGNOSE_FRESH_AUTH: "philcore:diagnostics:freshAuth"
});

const ALLOWED_CHANNELS = Object.freeze(Object.values(CHANNELS));
const SEPOLIA_MINT_CHANNELS = Object.freeze([
  CHANNELS.SEPOLIA_MINT_BEGIN,
  CHANNELS.SEPOLIA_MINT_STATUS,
  CHANNELS.SEPOLIA_MINT_CANCEL
]);
const RECOVERY_ENROLLMENT_CHANNELS = Object.freeze([
  CHANNELS.RECOVERY_ENROLLMENT_PREFLIGHT,
  CHANNELS.RECOVERY_ENROLLMENT_STATUS,
  CHANNELS.RECOVERY_ENROLLMENT_BEGIN_CREDENTIAL,
  CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC,
  CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC,
  CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION,
  CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION,
  CHANNELS.RECOVERY_ENROLLMENT_BEGIN_HARDWARE_FALLBACK,
  CHANNELS.RECOVERY_ENROLLMENT_STORE_CREDENTIAL,
  CHANNELS.RECOVERY_ENROLLMENT_BEGIN_PAIRING,
  CHANNELS.RECOVERY_ENROLLMENT_BEGIN_IPHONE_PAIRING,
  CHANNELS.RECOVERY_ENROLLMENT_IPHONE_PAIRING_STATUS,
  CHANNELS.RECOVERY_ENROLLMENT_CANCEL_IPHONE_PAIRING,
  CHANNELS.RECOVERY_ENROLLMENT_ACCEPT_PAIRING,
  CHANNELS.RECOVERY_ENROLLMENT_COMPLETE_PAIRING,
  CHANNELS.RECOVERY_ENROLLMENT_GENERATE_OFFLINE,
  CHANNELS.RECOVERY_ENROLLMENT_REVEAL_OFFLINE,
  CHANNELS.RECOVERY_ENROLLMENT_CONFIRM_OFFLINE_EXPORT,
  CHANNELS.RECOVERY_ENROLLMENT_RESTORE_OFFLINE,
  CHANNELS.RECOVERY_ENROLLMENT_REVIEW_INDEPENDENCE,
  CHANNELS.RECOVERY_ENROLLMENT_COMPLETE,
  CHANNELS.RECOVERY_ENROLLMENT_CANCEL,
  CHANNELS.RECOVERY_ENROLLMENT_LIST_PUBLIC_FACTORS,
  CHANNELS.RECOVERY_ENROLLMENT_DELETE_FACTOR,
  CHANNELS.RECOVERY_ENROLLMENT_ROTATE_FACTOR
]);
const RECOVERY_TRANSPORT_CHANNELS = Object.freeze([
  CHANNELS.RECOVERY_TRANSPORT_BEGIN,
  CHANNELS.RECOVERY_TRANSPORT_STATUS,
  CHANNELS.RECOVERY_TRANSPORT_BEGIN_ROLE0_ASSERTION,
  CHANNELS.RECOVERY_TRANSPORT_SUBMIT_ROLE0_ASSERTION,
  CHANNELS.RECOVERY_TRANSPORT_CANCEL
]);
const ROUTINE_AUTHORIZATION_CHANNELS = Object.freeze([
  CHANNELS.ROUTINE_AUTHORIZATION_BEGIN,
  CHANNELS.ROUTINE_AUTHORIZATION_BASELINE,
  CHANNELS.ROUTINE_AUTHORIZATION_STATUS,
  CHANNELS.ROUTINE_AUTHORIZATION_CANCEL,
  CHANNELS.ROUTINE_AUTHORIZATION_DELETE_DISPOSABLE_PROFILE
]);

const FORBIDDEN_RENDERER_TOKENS = Object.freeze([
  "phil_secret",
  "privateKey",
  "private_key",
  "seedPhrase",
  "mnemonic",
  "vaultKey",
  "rawVaultKey",
  "wrappingKey",
  "rawWrappingKey",
  "recoverySecret",
  "signingKey",
  "nullifierSeed"
]);

const APPROVAL_KINDS = Object.freeze([
  "local_authorization_execution",
  "ethereum_sepolia_unsigned_preparation",
  "ethereum_sepolia_user_operation_signing",
  "user_operation_signing",
  "recovery_request",
  "recovery_cancel",
  "recovery_complete",
  "execution_owner_rotation",
  "recovery_authority_rotation",
  "validator_signing_session",
  "recovery_signing_session",
  "platform_unlock_enrollment",
  "platform_unlock_disablement",
  "local_identity_reset"
]);

const APPROVAL_DECISIONS = Object.freeze(["approve", "deny", "cancel", "expired"]);
const NEW_IDENTITY_PASSPHRASE_POLICY = Object.freeze({
  minLength: 12,
  requirements: Object.freeze([
    Object.freeze({ id: "min_length", label: "At least 12 characters" }),
    Object.freeze({ id: "lowercase", label: "One lowercase letter" }),
    Object.freeze({ id: "uppercase", label: "One uppercase letter" }),
    Object.freeze({ id: "number", label: "One number" }),
    Object.freeze({ id: "special", label: "One special character" })
  ])
});

function isAllowedChannel(channel) {
  return ALLOWED_CHANNELS.includes(channel);
}

function assertAllowedChannel(channel) {
  if (!isAllowedChannel(channel)) {
    throw new Error(`Unsupported PhilCore desktop bridge channel: ${channel}`);
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sanitizeText(value) {
  if (value === null || value === undefined) return "";
  return String(value).slice(0, 240);
}

function sanitizePassphrase(value) {
  if (typeof value !== "string") return "";
  return value.slice(0, 1024);
}

function validateNewIdentityPassphrase(passphrase) {
  const value = typeof passphrase === "string" ? passphrase : "";
  const checks = {
    min_length: value.length >= NEW_IDENTITY_PASSPHRASE_POLICY.minLength,
    lowercase: /[a-z]/u.test(value),
    uppercase: /[A-Z]/u.test(value),
    number: /[0-9]/u.test(value),
    special: /[^a-zA-Z0-9]/u.test(value)
  };
  const missing = NEW_IDENTITY_PASSPHRASE_POLICY.requirements
    .filter((requirement) => !checks[requirement.id])
    .map((requirement) => requirement.id);
  return {
    ok: missing.length === 0,
    missing,
    checks,
    policy: NEW_IDENTITY_PASSPHRASE_POLICY
  };
}

function sanitizeId(value) {
  return sanitizeText(value).replace(/[^a-zA-Z0-9_:-]/g, "").slice(0, 160);
}

function hasOnlyKeys(payload, keys) {
  return Object.keys(payload || {}).every((key) => keys.includes(key));
}

function validateRecoveryRegistration(registration) {
  if (
    !isPlainObject(registration)
    || !hasOnlyKeys(registration, [
      "id", "rawId", "type", "authenticatorAttachment", "response",
      "clientExtensionResults"
    ])
    || registration.type !== "public-key"
    || typeof registration.id !== "string"
    || registration.id.length > 2048
    || !/^[a-zA-Z0-9_-]{16,2048}$/u.test(registration.rawId || "")
    || !isPlainObject(registration.response)
    || !hasOnlyKeys(registration.response, [
      "attestationObject", "clientDataJSON", "transports", "publicKey",
      "publicKeyAlgorithm"
    ])
    || !/^[a-zA-Z0-9_-]{16,131072}$/u.test(registration.response.attestationObject || "")
    || !/^[a-zA-Z0-9_-]{16,16384}$/u.test(registration.response.clientDataJSON || "")
    || (registration.response.publicKey !== undefined
      && !/^[a-zA-Z0-9_-]{16,4096}$/u.test(registration.response.publicKey))
    || registration.response.publicKeyAlgorithm !== -7
    || !Array.isArray(registration.response.transports)
    || registration.response.transports.some((transport) =>
      !["internal", "hybrid", "usb", "nfc", "ble"].includes(transport))
  ) return false;
  return true;
}

function validateRecoveryAssertion(assertion) {
  if (
    !isPlainObject(assertion)
    || !hasOnlyKeys(assertion, [
      "id", "rawId", "type", "authenticatorAttachment", "response",
      "clientExtensionResults"
    ])
    || assertion.type !== "public-key"
    || typeof assertion.id !== "string"
    || assertion.id.length > 2048
    || !/^[a-zA-Z0-9_-]{16,2048}$/u.test(assertion.rawId || "")
    || !isPlainObject(assertion.response)
    || !hasOnlyKeys(assertion.response, [
      "authenticatorData", "clientDataJSON", "signature", "userHandle"
    ])
    || !/^[a-zA-Z0-9_-]{16,16384}$/u.test(assertion.response.authenticatorData || "")
    || !/^[a-zA-Z0-9_-]{16,16384}$/u.test(assertion.response.clientDataJSON || "")
    || !/^[a-zA-Z0-9_-]{16,8192}$/u.test(assertion.response.signature || "")
    || (
      assertion.response.userHandle !== null
      && assertion.response.userHandle !== undefined
      && !/^[a-zA-Z0-9_-]{0,2048}$/u.test(assertion.response.userHandle)
    )
  ) return false;
  return true;
}

function validatePhilPreview(value) {
  const philenatorTraitKeys = [
    "bgColor", "bgNebula", "bgStars", "bgSpiral", "bgDust", "bgOverlay",
    "bodyBase", "body", "spikes", "teeth", "jawNose", "eyes", "top"
  ];
  const philenatorRevision = "f174dedda16a354c592e3252d9b0b5805bab59c4";
  if (value === undefined) {
    return {
      ok: true,
      value: {
        selectionId: "local-philenator-00",
        sequence: 0,
        traits: Object.fromEntries(philenatorTraitKeys.map((key) => [key, `${key}-pending`.slice(0, 32)])),
        source: "philenator-local",
        artworkSource: "philenator-local",
        generatorRevision: philenatorRevision,
        mintStatus: "not-minted",
        publicToken: null
      }
    };
  }
  if (!isPlainObject(value)) return { ok: false, reason: "phil_preview_must_be_object" };
  if (!hasOnlyKeys(value, [
    "selectionId", "sequence", "traits", "source", "artworkSource",
    "generatorRevision", "mintStatus", "publicToken"
  ])) {
    return { ok: false, reason: "unexpected_phil_preview_field" };
  }
  if (!/^local-philenator-[0-9]{2}$/u.test(value.selectionId || "")) {
    return { ok: false, reason: "invalid_phil_preview_selection" };
  }
  if (!Number.isInteger(value.sequence) || value.sequence < 0 || value.sequence > 999) {
    return { ok: false, reason: "invalid_phil_preview_sequence" };
  }
  if (!isPlainObject(value.traits)
    || !hasOnlyKeys(value.traits, philenatorTraitKeys)
    || !philenatorTraitKeys.every((key) => typeof value.traits[key] === "string" && value.traits[key].length <= 32)) {
    return { ok: false, reason: "invalid_phil_preview_traits" };
  }
  if (value.source !== "philenator-local" || value.artworkSource !== "philenator-local") {
    return { ok: false, reason: "unsupported_phil_artwork_source" };
  }
  if (value.generatorRevision !== philenatorRevision) {
    return { ok: false, reason: "unsupported_philenator_revision" };
  }
  if (value.mintStatus !== "not-minted" || value.publicToken !== null) {
    return { ok: false, reason: "invalid_local_phil_mint_status" };
  }
  return {
    ok: true,
    value: {
      selectionId: value.selectionId,
      sequence: value.sequence,
      traits: Object.fromEntries(philenatorTraitKeys.map((key) => [key, sanitizeId(value.traits[key])])),
      source: "philenator-local",
      artworkSource: "philenator-local",
      generatorRevision: philenatorRevision,
      mintStatus: "not-minted",
      publicToken: null
    }
  };
}

function validateBridgePayload(channel, payload = {}) {
  assertAllowedChannel(channel);
  if (payload !== undefined && !isPlainObject(payload)) {
    return { ok: false, reason: "payload_must_be_object" };
  }

  switch (channel) {
    case CHANNELS.SEPOLIA_MINT_BEGIN:
      if (!hasOnlyKeys(payload, [])) {
        return { ok: false, reason: "unexpected_sepolia_mint_begin_field" };
      }
      return { ok: true, value: {} };
    case CHANNELS.SEPOLIA_MINT_STATUS:
    case CHANNELS.SEPOLIA_MINT_CANCEL:
      if (!hasOnlyKeys(payload, ["requestId"])
        || !/^0x[0-9a-f]{64}$/u.test(payload.requestId || "")) {
        return { ok: false, reason: "invalid_sepolia_mint_request_id" };
      }
      return { ok: true, value: { requestId: payload.requestId } };
    case CHANNELS.ROUTINE_AUTHORIZATION_BEGIN:
      if (!hasOnlyKeys(payload, ["typedApplicationIntent"])
        || !isPlainObject(payload.typedApplicationIntent)
        || !hasOnlyKeys(payload.typedApplicationIntent, ["action"])
        || !["record_harmless_value","replace_routine_device"].includes(payload.typedApplicationIntent.action)) {
        return { ok: false, reason: "invalid_routine_authorization_intent" };
      }
      return { ok: true, value: { typedApplicationIntent: { action: payload.typedApplicationIntent.action } } };
    case CHANNELS.ROUTINE_AUTHORIZATION_BASELINE:
      return hasOnlyKeys(payload,[]) ? {ok:true,value:{}} : {ok:false,reason:"invalid_routine_baseline_payload"};
    case CHANNELS.ROUTINE_AUTHORIZATION_STATUS:
    case CHANNELS.ROUTINE_AUTHORIZATION_CANCEL:
      if (!hasOnlyKeys(payload, ["requestId"])
        || !/^0x[0-9a-f]{64}$/u.test(payload.requestId || "")) {
        return { ok: false, reason: "invalid_routine_authorization_request_id" };
      }
      return { ok: true, value: { requestId: payload.requestId } };
    case CHANNELS.ROUTINE_AUTHORIZATION_DELETE_DISPOSABLE_PROFILE:
      if (!hasOnlyKeys(payload, ["confirmation"])
        || payload.confirmation !== "DELETE DISPOSABLE ROUTINE PROFILE") {
        return { ok: false, reason: "invalid_routine_profile_deletion_confirmation" };
      }
      return { ok: true, value: { confirmation: payload.confirmation } };
    case CHANNELS.RECOVERY_ENROLLMENT_PREFLIGHT:
      if (!hasOnlyKeys(payload, [
        "profile",
        "webAuthnApiAvailable",
        "platformAuthenticatorAvailable",
        "packagedEnvironmentReady",
        "dependencyAdvisoryGateReady"
      ])) return { ok: false, reason: "unexpected_recovery_preflight_field" };
      if (!["STANDARD", "ENHANCED"].includes(payload.profile)) {
        return { ok: false, reason: "invalid_recovery_profile" };
      }
      return {
        ok: true,
        value: {
          profile: payload.profile,
          webAuthnApiAvailable: payload.webAuthnApiAvailable === true,
          platformAuthenticatorAvailable: payload.platformAuthenticatorAvailable === true,
          packagedEnvironmentReady: payload.packagedEnvironmentReady !== false,
          dependencyAdvisoryGateReady: payload.dependencyAdvisoryGateReady !== false
        }
      };
    case CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION:
      if (!hasOnlyKeys(payload, ["registration"])) {
        return { ok: false, reason: "unexpected_disposable_registration_field" };
      }
      if (!validateRecoveryRegistration(payload.registration)) {
        return { ok: false, reason: "invalid_disposable_registration_material" };
      }
      return { ok: true, value: payload };
    case CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION:
      if (!hasOnlyKeys(payload, ["assertion"])) {
        return { ok: false, reason: "unexpected_disposable_assertion_field" };
      }
      if (!validateRecoveryAssertion(payload.assertion)) {
        return { ok: false, reason: "invalid_disposable_assertion_material" };
      }
      return { ok: true, value: payload };
    case CHANNELS.RECOVERY_ENROLLMENT_STORE_CREDENTIAL:
      if (!hasOnlyKeys(payload, [
        "role", "registration", "descriptorMetadata", "generation",
        "custodyDomainCommitment"
      ])) return { ok: false, reason: "unexpected_recovery_credential_field" };
      if (![0, 1].includes(payload.role)) return { ok: false, reason: "invalid_recovery_role" };
      if (
        !validateRecoveryRegistration(payload.registration)
        || !Number.isSafeInteger(payload.generation)
        || payload.generation < 1
        || !/^0x[a-fA-F0-9]{64}$/u.test(payload.custodyDomainCommitment || "")
        || !isPlainObject(payload.descriptorMetadata)
      ) {
        return { ok: false, reason: "invalid_recovery_credential_material" };
      }
      return { ok: true, value: payload };
    case CHANNELS.RECOVERY_ENROLLMENT_ACCEPT_PAIRING:
      if (!hasOnlyKeys(payload, ["encodedRequest", "credential"])) {
        return { ok: false, reason: "unexpected_pairing_accept_field" };
      }
      if (
        typeof payload.encodedRequest !== "string"
        || payload.encodedRequest.length > 24_000
        || !isPlainObject(payload.credential)
        || !hasOnlyKeys(payload.credential, [
          "challenge", "registration", "descriptorMetadata", "generation",
          "custodyDomainCommitment"
        ])
        || typeof payload.credential.challenge !== "string"
        || payload.credential.challenge.length > 128
        || !validateRecoveryRegistration(payload.credential.registration)
        || !isPlainObject(payload.credential.descriptorMetadata)
        || !Number.isSafeInteger(payload.credential.generation)
        || payload.credential.generation < 1
        || !/^0x[a-fA-F0-9]{64}$/u.test(payload.credential.custodyDomainCommitment || "")
      ) {
        return { ok: false, reason: "invalid_pairing_accept_payload" };
      }
      return { ok: true, value: payload };
    case CHANNELS.RECOVERY_ENROLLMENT_COMPLETE_PAIRING:
      if (!hasOnlyKeys(payload, ["encodedResponse", "custodyDomainCommitment"])) {
        return { ok: false, reason: "unexpected_pairing_complete_field" };
      }
      if (
        typeof payload.encodedResponse !== "string"
        || payload.encodedResponse.length > 24_000
        || typeof payload.custodyDomainCommitment !== "string"
        || payload.custodyDomainCommitment.length > 128
      ) return { ok: false, reason: "invalid_pairing_complete_payload" };
      return { ok: true, value: payload };
    case CHANNELS.RECOVERY_ENROLLMENT_RESTORE_OFFLINE:
      if (!hasOnlyKeys(payload, ["restorationInput"]) || typeof payload.restorationInput !== "string" || payload.restorationInput.length > 256) {
        return { ok: false, reason: "invalid_offline_restoration_input" };
      }
      return { ok: true, value: payload };
    case CHANNELS.RECOVERY_ENROLLMENT_REVIEW_INDEPENDENCE:
      if (!hasOnlyKeys(payload, ["acknowledged", "primaryAndSecondaryIndependent"])) {
        return { ok: false, reason: "unexpected_independence_review_field" };
      }
      return {
        ok: true,
        value: {
          acknowledged: payload.acknowledged === true,
          primaryAndSecondaryIndependent: payload.primaryAndSecondaryIndependent === true
        }
      };
    case CHANNELS.RECOVERY_ENROLLMENT_DELETE_FACTOR:
      if (!hasOnlyKeys(payload, ["reference"]) || !/^recovery_credential_[a-f0-9]{32}$/u.test(payload.reference || "")) {
        return { ok: false, reason: "invalid_recovery_credential_reference" };
      }
      return { ok: true, value: { reference: payload.reference } };
    case CHANNELS.RECOVERY_ENROLLMENT_ROTATE_FACTOR:
      if (!hasOnlyKeys(payload, ["reference", "replacement"]) || !/^recovery_credential_[a-f0-9]{32}$/u.test(payload.reference || "") || !isPlainObject(payload.replacement)) {
        return { ok: false, reason: "invalid_recovery_rotation_payload" };
      }
      return { ok: true, value: payload };
    case CHANNELS.RECOVERY_ENROLLMENT_STATUS:
    case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_CREDENTIAL:
    case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC:
    case CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC:
    case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_HARDWARE_FALLBACK:
    case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_PAIRING:
    case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_IPHONE_PAIRING:
    case CHANNELS.RECOVERY_ENROLLMENT_IPHONE_PAIRING_STATUS:
    case CHANNELS.RECOVERY_ENROLLMENT_CANCEL_IPHONE_PAIRING:
    case CHANNELS.RECOVERY_ENROLLMENT_GENERATE_OFFLINE:
    case CHANNELS.RECOVERY_ENROLLMENT_REVEAL_OFFLINE:
    case CHANNELS.RECOVERY_ENROLLMENT_CONFIRM_OFFLINE_EXPORT:
    case CHANNELS.RECOVERY_ENROLLMENT_COMPLETE:
    case CHANNELS.RECOVERY_ENROLLMENT_CANCEL:
    case CHANNELS.RECOVERY_ENROLLMENT_LIST_PUBLIC_FACTORS:
      if (!hasOnlyKeys(payload, [])) return { ok: false, reason: "unexpected_recovery_enrollment_field" };
      return { ok: true, value: {} };
    case CHANNELS.RECOVERY_TRANSPORT_BEGIN:
      if (!hasOnlyKeys(payload, ["bitmap"])) {
        return { ok: false, reason: "unexpected_recovery_transport_field" };
      }
      if (![3, 5, 6].includes(Number(payload.bitmap))) {
        return { ok: false, reason: "invalid_recovery_transport_bitmap" };
      }
      return { ok: true, value: { bitmap: Number(payload.bitmap) } };
    case CHANNELS.RECOVERY_TRANSPORT_SUBMIT_ROLE0_ASSERTION:
      if (!hasOnlyKeys(payload, ["assertion"])) {
        return { ok: false, reason: "unexpected_recovery_transport_field" };
      }
      if (!validateRecoveryAssertion(payload.assertion)) {
        return { ok: false, reason: "invalid_recovery_transport_assertion_material" };
      }
      return { ok: true, value: { assertion: payload.assertion } };
    case CHANNELS.RECOVERY_TRANSPORT_STATUS:
    case CHANNELS.RECOVERY_TRANSPORT_BEGIN_ROLE0_ASSERTION:
    case CHANNELS.RECOVERY_TRANSPORT_CANCEL:
      if (!hasOnlyKeys(payload, [])) {
        return { ok: false, reason: "unexpected_recovery_transport_field" };
      }
      return { ok: true, value: {} };
    case CHANNELS.CREATE_LOCAL_IDENTITY:
      if (!hasOnlyKeys(payload, ["label", "passphrase", "createRecoveryAuthority", "philPreview"])) {
        return { ok: false, reason: "unexpected_identity_creation_field" };
      }
      if (payload.label !== undefined && typeof payload.label !== "string") {
        return { ok: false, reason: "label_must_be_string" };
      }
      if (!validateNewIdentityPassphrase(payload.passphrase).ok) {
        return { ok: false, reason: "new_identity_passphrase_requirements_not_met" };
      }
      {
        const preview = validatePhilPreview(payload.philPreview);
        if (!preview.ok) return preview;
        return {
          ok: true,
          value: {
            label: sanitizeText(payload.label || "Local Phil Identity"),
            passphrase: sanitizePassphrase(payload.passphrase),
            createRecoveryAuthority: Boolean(payload.createRecoveryAuthority),
            philPreview: preview.value
          }
        };
      }
    case CHANNELS.OPEN_LOCAL_IDENTITY:
      if (typeof payload.identityId !== "string" || payload.identityId.length === 0) {
        return { ok: false, reason: "identity_id_must_be_string" };
      }
      return { ok: true, value: { identityId: sanitizeText(payload.identityId) } };
    case CHANNELS.RENAME_LOCAL_IDENTITY: {
      if (!hasOnlyKeys(payload, ["label"])) return { ok: false, reason: "unexpected_identity_rename_field" };
      const label = typeof payload.label === "string" ? payload.label.trim() : "";
      if (!label || label.length > 64) return { ok: false, reason: "invalid_identity_label" };
      return { ok: true, value: { label: sanitizeText(label) } };
    }
    case CHANNELS.AUTHENTICATE_LOCAL:
    case CHANNELS.ENROLL_PLATFORM_AUTH:
    case CHANNELS.DISABLE_PLATFORM_AUTH:
      if (typeof payload.passphrase !== "string" || payload.passphrase.length < 8) {
        return { ok: false, reason: "local_alpha_passphrase_required" };
      }
      return {
        ok: true,
        value: {
          passphrase: sanitizePassphrase(payload.passphrase),
          approvalArtifactId: sanitizeId(payload.approvalArtifactId || ""),
          freshAuthenticationEvidenceId: sanitizeId(payload.freshAuthenticationEvidenceId || "")
        }
      };
    case CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH:
      if (payload.purpose !== undefined && typeof payload.purpose !== "string") {
        return { ok: false, reason: "purpose_must_be_string" };
      }
      return {
        ok: true,
        value: {
          purpose: sanitizeText(payload.purpose || "sensitive_action"),
          presentationId: sanitizeId(payload.presentationId || ""),
          presentationDigest: sanitizeText(payload.presentationDigest || "")
        }
      };
    case CHANNELS.CREATE_APPROVAL_PRESENTATION:
      if (!hasOnlyKeys(payload, ["kind", "scenario", "confirmationTarget"])) {
        return { ok: false, reason: "unexpected_approval_field" };
      }
      if (!APPROVAL_KINDS.includes(payload.kind)) return { ok: false, reason: "unsupported_approval_kind" };
      return {
        ok: true,
        value: {
          kind: payload.kind,
          scenario: sanitizeText(payload.scenario || ""),
          confirmationTarget: sanitizeText(payload.confirmationTarget || "")
        }
      };
    case CHANNELS.GET_APPROVAL_PRESENTATION:
    case CHANNELS.CANCEL_APPROVAL:
      if (typeof payload.presentationId !== "string" || payload.presentationId.length === 0) {
        return { ok: false, reason: "presentation_id_required" };
      }
      return { ok: true, value: { presentationId: sanitizeId(payload.presentationId) } };
    case CHANNELS.RESPOND_APPROVAL:
      if (!hasOnlyKeys(payload, ["presentationId", "decision", "typedConfirmation"])) {
        return { ok: false, reason: "unexpected_approval_response_field" };
      }
      if (typeof payload.presentationId !== "string" || payload.presentationId.length === 0) {
        return { ok: false, reason: "presentation_id_required" };
      }
      if (!APPROVAL_DECISIONS.includes(payload.decision)) return { ok: false, reason: "unsupported_approval_decision" };
      return {
        ok: true,
        value: {
          presentationId: sanitizeId(payload.presentationId),
          decision: payload.decision,
          typedConfirmation: sanitizeText(payload.typedConfirmation || "")
        }
      };
    case CHANNELS.CONSUME_APPROVAL:
      if (typeof payload.approvalArtifactId !== "string" || payload.approvalArtifactId.length === 0) {
        return { ok: false, reason: "approval_artifact_id_required" };
      }
      return {
        ok: true,
        value: {
          approvalArtifactId: sanitizeId(payload.approvalArtifactId),
          kind: APPROVAL_KINDS.includes(payload.kind) ? payload.kind : "",
          presentationDigest: sanitizeText(payload.presentationDigest || ""),
          freshAuthenticationEvidenceId: sanitizeId(payload.freshAuthenticationEvidenceId || "")
        }
      };
    case CHANNELS.GET_PROTECTED_VIEW:
      if (payload.viewType !== undefined && typeof payload.viewType !== "string") {
        return { ok: false, reason: "view_type_must_be_string" };
      }
      return { ok: true, value: { viewType: sanitizeText(payload.viewType || "runtime_summary") } };
    case CHANNELS.RESET_LOCAL_IDENTITY:
      if (typeof payload.confirmation !== "string") {
        return { ok: false, reason: "reset_confirmation_required" };
      }
      return {
        ok: true,
        value: {
          confirmation: sanitizeText(payload.confirmation),
          approvalArtifactId: sanitizeId(payload.approvalArtifactId || ""),
          freshAuthenticationEvidenceId: sanitizeId(payload.freshAuthenticationEvidenceId || ""),
          passphrase: sanitizePassphrase(payload.passphrase || "")
        }
      };
    case CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO:
      return {
        ok: true,
        value: {
          approvalArtifactId: sanitizeId(payload.approvalArtifactId || ""),
          signingApprovalArtifactId: sanitizeId(payload.signingApprovalArtifactId || ""),
          freshAuthenticationEvidenceId: sanitizeId(payload.freshAuthenticationEvidenceId || "")
        }
      };
    case CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW:
    case CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION:
      if (!hasOnlyKeys(payload, ["approvalArtifactId", "proofTimeoutMs", "clientActionId"])) {
        return { ok: false, reason: "unexpected_workflow_start_field" };
      }
      return {
        ok: true,
        value: {
          approvalArtifactId: sanitizeId(payload.approvalArtifactId || ""),
          clientActionId: sanitizeId(payload.clientActionId || ""),
          proofTimeoutMs: Number.isInteger(payload.proofTimeoutMs) ? Math.max(10_000, Math.min(payload.proofTimeoutMs, 300_000)) : undefined
        }
      };
    case CHANNELS.PREFLIGHT_REAL_LOCAL_AUTHORIZATION_WORKFLOW:
    case CHANNELS.PREFLIGHT_SEPOLIA_USER_OPERATION_PREPARATION:
      return { ok: true, value: {} };
    case CHANNELS.GET_REAL_LOCAL_AUTHORIZATION_WORKFLOW:
    case CHANNELS.GET_SEPOLIA_USER_OPERATION_PREPARATION:
    case CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH:
    case CHANNELS.GET_REAL_LOCAL_AUTHORIZATION_RESULT:
      return { ok: true, value: { workflowId: sanitizeId(payload.workflowId || "") } };
    case CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT:
      if (!hasOnlyKeys(payload, [
        "workflowId",
        "approvalArtifactId",
        "presentationDigest",
        "freshAuthenticationEvidenceId",
        "proofTimeoutMs"
      ])) {
        return { ok: false, reason: "unexpected_sepolia_signing_field" };
      }
      return {
        ok: true,
        value: {
          workflowId: sanitizeId(payload.workflowId || ""),
          approvalArtifactId: sanitizeId(payload.approvalArtifactId || ""),
          presentationDigest: sanitizeText(payload.presentationDigest || ""),
          freshAuthenticationEvidenceId: sanitizeId(
            payload.freshAuthenticationEvidenceId || ""
          ),
          proofTimeoutMs: Number.isInteger(payload.proofTimeoutMs)
            ? Math.max(10_000, Math.min(payload.proofTimeoutMs, 300_000))
            : undefined
        }
      };
    case CHANNELS.CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW:
      if (!hasOnlyKeys(payload, ["workflowId", "terminalStatus", "reason"])) {
        return { ok: false, reason: "unexpected_workflow_cancel_field" };
      }
      if (payload.terminalStatus && !["cancelled", "failed", "timed_out", "interrupted"].includes(payload.terminalStatus)) {
        return { ok: false, reason: "unsupported_workflow_terminal_status" };
      }
      return {
        ok: true,
        value: {
          workflowId: sanitizeId(payload.workflowId || ""),
          terminalStatus: payload.terminalStatus || "cancelled",
          reason: sanitizeId(payload.reason || "user_cancelled")
        }
      };
    case CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL:
      if (!hasOnlyKeys(payload, ["workflowId", "decision", "presentationDigest", "freshAuthenticationEvidenceId"])) {
        return { ok: false, reason: "unexpected_workflow_approval_field" };
      }
      if (!["approve", "deny", "cancel"].includes(payload.decision)) {
        return { ok: false, reason: "unsupported_workflow_decision" };
      }
      return {
        ok: true,
        value: {
          workflowId: sanitizeId(payload.workflowId || ""),
          decision: payload.decision,
          presentationDigest: sanitizeText(payload.presentationDigest || ""),
          freshAuthenticationEvidenceId: sanitizeId(payload.freshAuthenticationEvidenceId || "")
        }
      };
    case CHANNELS.RUN_RECOVERY_DEMO:
      if (!["owner_rotation", "request", "cancel", "complete", "authority_rotation_request", "authority_rotation_cancel", "authority_rotation_complete"].includes(payload.scenario)) {
        return { ok: false, reason: "unsupported_recovery_scenario" };
      }
      return {
        ok: true,
        value: {
          scenario: payload.scenario,
          approvalArtifactId: sanitizeId(payload.approvalArtifactId || ""),
          freshAuthenticationEvidenceId: sanitizeId(payload.freshAuthenticationEvidenceId || "")
        }
      };
    case CHANNELS.UPDATE_SETTINGS:
      return validateSettingsPayload(payload);
    default:
      return { ok: true, value: payload };
  }
}

function validateSettingsPayload(payload) {
  const next = {};
  if (payload.sessionTimeoutMinutes !== undefined) {
    const timeout = Number(payload.sessionTimeoutMinutes);
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 120) {
      return { ok: false, reason: "invalid_session_timeout" };
    }
    next.sessionTimeoutMinutes = timeout;
  }
  if (payload.autoLockEnabled !== undefined) next.autoLockEnabled = Boolean(payload.autoLockEnabled);
  if (payload.developerModeVisible !== undefined) next.developerModeVisible = Boolean(payload.developerModeVisible);
  if (payload.introCompleted !== undefined) next.introCompleted = Boolean(payload.introCompleted);
  if (payload.presentationMode !== undefined) {
    if (!["user", "technical"].includes(payload.presentationMode)) {
      return { ok: false, reason: "invalid_presentation_mode" };
    }
    next.presentationMode = payload.presentationMode;
  }
  if (payload.auditDetailLevel !== undefined) {
    if (!["summary", "standard", "developer"].includes(payload.auditDetailLevel)) {
      return { ok: false, reason: "invalid_audit_detail_level" };
    }
    next.auditDetailLevel = payload.auditDetailLevel;
  }
  if (payload.appearance !== undefined) {
    if (!["system", "light", "dark"].includes(payload.appearance)) {
      return { ok: false, reason: "invalid_appearance" };
    }
    next.appearance = payload.appearance;
  }
  return { ok: true, value: next };
}

function containsForbiddenKey(value) {
  if (!value || typeof value !== "object") return false;
  for (const [key, nested] of Object.entries(value)) {
    if (FORBIDDEN_RENDERER_TOKENS.some((token) => key.toLowerCase().includes(token.toLowerCase()))) {
      return true;
    }
    if (nested && typeof nested === "object" && containsForbiddenKey(nested)) return true;
  }
  return false;
}

module.exports = {
  APP_MODE,
  CHANNELS,
  ALLOWED_CHANNELS,
  RECOVERY_ENROLLMENT_CHANNELS,
  RECOVERY_TRANSPORT_CHANNELS,
  ROUTINE_AUTHORIZATION_CHANNELS,
  SEPOLIA_MINT_CHANNELS,
  FORBIDDEN_RENDERER_TOKENS,
  NEW_IDENTITY_PASSPHRASE_POLICY,
  assertAllowedChannel,
  isAllowedChannel,
  validateBridgePayload,
  validateRecoveryAssertion,
  validateRecoveryRegistration,
  validateNewIdentityPassphrase,
  containsForbiddenKey
};
