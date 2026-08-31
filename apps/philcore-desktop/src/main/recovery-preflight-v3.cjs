const PREFLIGHT_STATUS = Object.freeze({
  READY: "READY",
  READY_WITH_WARNINGS: "READY_WITH_WARNINGS",
  BLOCKED: "BLOCKED"
});

const REQUIRED_PRIMARY_CHECKS = Object.freeze([
  "electronRuntimeCapability",
  "startupWebAuthnConfiguration",
  "bundleIdentity",
  "keychainAccessGroup",
  "secureOrigin",
  "certificatePersistence",
  "safeStoragePersistence",
  "platformAuthenticator",
  "disposableCreationAssertion",
  "packagedBuild",
  "loggingCrashExclusion",
  "noStaleCeremonyState",
  "noProductionSecretContamination"
]);

const REQUIRED_IPHONE_CHECKS = Object.freeze([
  "iphoneCompanionConnectivity",
  "iphoneRole1CredentialPolicy"
]);

function classify(checks, required, warningIds = []) {
  const blockers = required.filter((id) => checks[id] !== true);
  if (blockers.length) return { status: PREFLIGHT_STATUS.BLOCKED, blockers, warnings: [] };
  const warnings = warningIds.filter((id) => checks[id] !== true);
  return {
    status: warnings.length ? PREFLIGHT_STATUS.READY_WITH_WARNINGS : PREFLIGHT_STATUS.READY,
    blockers,
    warnings
  };
}

function evaluateRecoveryPreflightV3(input = {}) {
  const checks = Object.freeze({
    electronRuntimeCapability: input.electronRuntimeCapability === true,
    startupWebAuthnConfiguration: input.startupWebAuthnConfiguration === true,
    bundleIdentity: input.bundleIdentity === true,
    keychainAccessGroup: input.keychainAccessGroup === true,
    secureOrigin: input.secureOrigin === true,
    certificatePersistence: input.certificatePersistence === true,
    safeStoragePersistence: input.safeStoragePersistence === true,
    platformAuthenticator: input.platformAuthenticator === true,
    disposableCreationAssertion: input.disposableCreationAssertion === true,
    packagedBuild: input.packagedBuild === true,
    iphoneCompanionConnectivity: input.iphoneCompanionConnectivity === true,
    iphoneRole1CredentialPolicy: input.iphoneRole1CredentialPolicy === true,
    loggingCrashExclusion: input.loggingCrashExclusion === true,
    noStaleCeremonyState: input.noStaleCeremonyState === true,
    noProductionSecretContamination: input.noProductionSecretContamination === true
  });
  const primaryMacRole0 = classify(checks, REQUIRED_PRIMARY_CHECKS);
  const iphoneRole1 = classify(checks, REQUIRED_IPHONE_CHECKS, ["iphonePhysicalProbe"]);
  const completeBlockers = [
    ...primaryMacRole0.blockers,
    ...iphoneRole1.blockers
  ];
  const completeStandardCeremony = {
    status: completeBlockers.length
      ? PREFLIGHT_STATUS.BLOCKED
      : [...primaryMacRole0.warnings, ...iphoneRole1.warnings].length
        ? PREFLIGHT_STATUS.READY_WITH_WARNINGS
        : PREFLIGHT_STATUS.READY,
    blockers: [...new Set(completeBlockers)],
    warnings: [...new Set([...primaryMacRole0.warnings, ...iphoneRole1.warnings])]
  };
  return Object.freeze({
    schemaVersion: 3,
    checks,
    primaryMacRole0: Object.freeze(primaryMacRole0),
    iphoneRole1: Object.freeze(iphoneRole1),
    completeStandardCeremony: Object.freeze(completeStandardCeremony)
  });
}

module.exports = {
  PREFLIGHT_STATUS,
  REQUIRED_IPHONE_CHECKS,
  REQUIRED_PRIMARY_CHECKS,
  evaluateRecoveryPreflightV3
};
