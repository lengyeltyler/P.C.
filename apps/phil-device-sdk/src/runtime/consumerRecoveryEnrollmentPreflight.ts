export const PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS = Object.freeze({
  READY: "READY",
  READY_WITH_USER_WARNINGS: "READY_WITH_USER_WARNINGS",
  BLOCKED: "BLOCKED"
} as const);

export type PhilCoreConsumerRecoveryPreflightStatus =
  typeof PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS[
    keyof typeof PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS
  ];

export type PhilCoreConsumerRecoveryRole1Class =
  | "STANDARD_SECONDARY_DEVICE"
  | "ENHANCED_HARDWARE_KEY";

export interface PhilCoreConsumerRecoveryEnrollmentEnvironment {
  readonly rpId?: string;
  readonly origin?: string;
  readonly localApplicationOrigin?: string;
  readonly secureContext: boolean;
  readonly stableApplicationOrigin: boolean;
  readonly webAuthnApiAvailable: boolean;
  readonly platformAuthenticatorAvailable: boolean;
  readonly secureCredentialStorageAdapterAvailable: boolean;
  readonly credentialStorageEncrypted: boolean;
  readonly opaqueCredentialReferencesOnly: boolean;
  readonly rawCredentialIdsLogged: boolean;
  readonly privateKeysLogged: boolean;
  readonly terminalOutputSecretSafe: boolean;
  readonly clipboardUsedForSecrets: boolean;
  readonly crashLogsMayCaptureSecrets: boolean;
  readonly localEnrollmentRecordsIgnored: boolean;
  readonly localDirectoryMode: number | null;
  readonly localFileMode: number | null;
  readonly backupBehaviorUnderstood: boolean;
  readonly directAttestationTrustValidationAvailable: boolean;
  readonly offlineSecureDisplayAvailable: boolean;
  readonly offlineSecureRestoreInputAvailable: boolean;
  readonly role1Class: PhilCoreConsumerRecoveryRole1Class;
  readonly secondaryDeviceHandoffAvailable: boolean;
  readonly hardwareKeyCeremonyAvailable: boolean;
  readonly custodyLimitationsAcknowledged: boolean;
}

export interface PhilCoreConsumerRecoveryPreflightCheck {
  readonly id: string;
  readonly passed: boolean;
  readonly detail: string;
}

export interface PhilCoreConsumerRecoveryEnrollmentPreflight {
  readonly status: PhilCoreConsumerRecoveryPreflightStatus;
  readonly role1Class: PhilCoreConsumerRecoveryRole1Class;
  readonly checks: readonly PhilCoreConsumerRecoveryPreflightCheck[];
  readonly blockerIds: readonly string[];
  readonly warnings: readonly string[];
  readonly productionCredentialCreationPermitted: boolean;
}

function validRpOriginBinding(rpId: string | undefined, origin: string | undefined): boolean {
  if (!rpId || !origin) return false;
  try {
    const parsed = new URL(origin);
    const normalizedRpId = rpId.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();
    return parsed.protocol === "https:"
      && (hostname === normalizedRpId || hostname.endsWith(`.${normalizedRpId}`))
      && parsed.username === ""
      && parsed.password === "";
  } catch {
    return false;
  }
}

function check(
  id: string,
  passed: boolean,
  passedDetail: string,
  failedDetail: string
): PhilCoreConsumerRecoveryPreflightCheck {
  return Object.freeze({
    id,
    passed,
    detail: passed ? passedDetail : failedDetail
  });
}

export function evaluateConsumerRecoveryEnrollmentPreflight(
  input: PhilCoreConsumerRecoveryEnrollmentEnvironment
): PhilCoreConsumerRecoveryEnrollmentPreflight {
  const rpOriginBound = validRpOriginBinding(input.rpId, input.origin);
  const originMatchesApplication =
    Boolean(input.origin)
    && input.origin === input.localApplicationOrigin;
  const role1CeremonyAvailable =
    input.role1Class === "STANDARD_SECONDARY_DEVICE"
      ? input.secondaryDeviceHandoffAvailable
      : input.hardwareKeyCeremonyAvailable;

  const checks = Object.freeze([
    check(
      "canonical_https_rp_origin",
      rpOriginBound,
      "RP ID is bound to a canonical HTTPS origin.",
      "A canonical HTTPS RP ID/origin binding is not configured."
    ),
    check(
      "application_origin_binding",
      originMatchesApplication && input.stableApplicationOrigin,
      "The application runs at the stable enrolled origin.",
      "The application does not run at the stable enrolled origin."
    ),
    check(
      "secure_context",
      input.secureContext,
      "The ceremony executes in a secure context.",
      "The ceremony secure-context requirement is not established."
    ),
    check(
      "webauthn_api",
      input.webAuthnApiAvailable,
      "The WebAuthn API is available.",
      "The WebAuthn API is unavailable or has not been safely probed."
    ),
    check(
      "platform_authenticator",
      input.platformAuthenticatorAvailable,
      "A user-verifying platform authenticator is available.",
      "A user-verifying platform authenticator is unavailable or unverified."
    ),
    check(
      "direct_attestation_trust",
      input.directAttestationTrustValidationAvailable,
      "Direct attestation trust validation is available.",
      "O.39 requires verified direct attestation, but trust-root validation is unavailable."
    ),
    check(
      "credential_storage_adapter",
      input.secureCredentialStorageAdapterAvailable
        && input.credentialStorageEncrypted
        && input.opaqueCredentialReferencesOnly,
      "Credential identifiers are encrypted and exposed only by opaque reference.",
      "No integrated encrypted recovery-credential adapter with opaque references is available."
    ),
    check(
      "logging_boundary",
      !input.rawCredentialIdsLogged
        && !input.privateKeysLogged
        && input.terminalOutputSecretSafe
        && !input.crashLogsMayCaptureSecrets,
      "Raw credential identifiers and private material are excluded from logs and terminal output.",
      "End-to-end log, crash-log, and terminal exclusion is not established."
    ),
    check(
      "clipboard_boundary",
      !input.clipboardUsedForSecrets,
      "The ceremony does not place secrets on the clipboard.",
      "The ceremony would place a secret on the clipboard."
    ),
    check(
      "local_record_boundary",
      input.localEnrollmentRecordsIgnored
        && input.localDirectoryMode === 0o700
        && input.localFileMode === 0o600,
      "Local enrollment records are ignored and use 0700/0600 permissions.",
      "Ignored-path and restrictive-permission handling is not established for enrollment records."
    ),
    check(
      "backup_policy",
      input.backupBehaviorUnderstood,
      "BE/BS behavior is captured and the device-bound policy is understood.",
      "Authenticator backup behavior is not understood."
    ),
    check(
      "role1_ceremony",
      role1CeremonyAvailable,
      input.role1Class === "STANDARD_SECONDARY_DEVICE"
        ? "A request-bound, expiring secondary-device handoff is available."
        : "A reviewed external hardware-key ceremony is available.",
      input.role1Class === "STANDARD_SECONDARY_DEVICE"
        ? "No request-bound, expiring secondary-device handoff is implemented."
        : "No reviewed external hardware-key ceremony is integrated."
    ),
    check(
      "offline_secure_display",
      input.offlineSecureDisplayAvailable,
      "A dedicated no-log offline-factor display is available.",
      "No dedicated no-log offline-factor reveal interface is available."
    ),
    check(
      "offline_secure_restore",
      input.offlineSecureRestoreInputAvailable,
      "A dedicated no-log offline restoration input is available.",
      "No dedicated no-log offline restoration input is available."
    )
  ]);

  const blockerIds = Object.freeze(
    checks.filter((entry) => !entry.passed).map((entry) => entry.id)
  );
  const warnings = input.custodyLimitationsAcknowledged
    ? Object.freeze([] as string[])
    : Object.freeze([
      "Separate Apple, Google, password-manager, and backup custody cannot be proven cryptographically and requires explicit user review."
    ]);
  const status = blockerIds.length > 0
    ? PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.BLOCKED
    : warnings.length > 0
      ? PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.READY_WITH_USER_WARNINGS
      : PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.READY;

  return Object.freeze({
    status,
    role1Class: input.role1Class,
    checks,
    blockerIds,
    warnings,
    productionCredentialCreationPermitted:
      status !== PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.BLOCKED
  });
}

export const PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_V2_PROFILE = Object.freeze({
  STANDARD: "STANDARD",
  ENHANCED: "ENHANCED"
} as const);

export interface PhilCoreConsumerRecoveryEnrollmentEnvironmentV2 {
  readonly secureOriginReady: boolean;
  readonly rpIdReady: boolean;
  readonly consumerPlatformPolicyV1Ready: boolean;
  readonly encryptedStorageReady: boolean;
  readonly role0PathReady: boolean;
  readonly standardRole1HandoffReady: boolean;
  readonly externalHardwareTrustRootsReady: boolean;
  readonly externalHardwareChainValidationReady: boolean;
  readonly offlineRevealRestoreReady: boolean;
  readonly loggingCrashExclusionReady: boolean;
  readonly dependencyAdvisoryGateReady: boolean;
  readonly packagedEnvironmentReady: boolean;
  readonly interactivePhysicalDeviceValidationComplete: boolean;
}

export interface PhilCoreConsumerRecoveryEnrollmentPreflightV2 {
  readonly version: 2;
  readonly standard: PhilCoreConsumerRecoveryPreflightStatus;
  readonly enhanced: PhilCoreConsumerRecoveryPreflightStatus;
  readonly standardBlockers: readonly string[];
  readonly enhancedBlockers: readonly string[];
  readonly warnings: readonly string[];
  readonly ceremonyReady: boolean;
  readonly productionCredentialCreated: false;
}

export function evaluateConsumerRecoveryEnrollmentPreflightV2(
  input: PhilCoreConsumerRecoveryEnrollmentEnvironmentV2
): PhilCoreConsumerRecoveryEnrollmentPreflightV2 {
  const common = Object.freeze([
    ["secure_origin", input.secureOriginReady],
    ["rp_id", input.rpIdReady],
    ["consumer_platform_policy_v1", input.consumerPlatformPolicyV1Ready],
    ["encrypted_storage", input.encryptedStorageReady],
    ["role_0_path", input.role0PathReady],
    ["offline_reveal_restore", input.offlineRevealRestoreReady],
    ["logging_crash_exclusion", input.loggingCrashExclusionReady],
    ["dependency_advisory_gate", input.dependencyAdvisoryGateReady],
    ["packaged_environment", input.packagedEnvironmentReady]
  ] as const);
  const standardBlockers = Object.freeze([
    ...common.filter(([, ready]) => !ready).map(([id]) => id),
    ...(input.standardRole1HandoffReady ? [] : ["standard_role_1_handoff"])
  ]);
  const enhancedBlockers = Object.freeze([
    ...common.filter(([, ready]) => !ready).map(([id]) => id),
    ...(input.externalHardwareTrustRootsReady ? [] : ["hardware_trust_roots"]),
    ...(input.externalHardwareChainValidationReady ? [] : ["hardware_chain_validation"])
  ]);
  const warnings = Object.freeze([
    ...(!input.interactivePhysicalDeviceValidationComplete
      ? ["A later interactive ceremony must validate the actual primary and secondary devices."]
      : []),
    "Custody-domain independence remains an explicit user-reviewed property."
  ]);
  const classify = (blockers: readonly string[]): PhilCoreConsumerRecoveryPreflightStatus =>
    blockers.length > 0
      ? PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.BLOCKED
      : warnings.length > 0
        ? PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.READY_WITH_USER_WARNINGS
        : PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.READY;
  const standard = classify(standardBlockers);
  const enhanced = classify(enhancedBlockers);
  return Object.freeze({
    version: 2,
    standard,
    enhanced,
    standardBlockers,
    enhancedBlockers,
    warnings,
    ceremonyReady:
      standard !== PHILCORE_CONSUMER_RECOVERY_PREFLIGHT_STATUS.BLOCKED,
    productionCredentialCreated: false
  });
}
