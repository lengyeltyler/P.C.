const { id } = require("ethers");
const {
  RECOVERY_ORIGIN,
  RECOVERY_RP_ID
} = require("./recovery-secure-origin.cjs");

const CONSUMER_PLATFORM_POLICY_V1 = Object.freeze({
  id: "PHILCORE_CONSUMER_PLATFORM_POLICY_V1",
  version: 1,
  rpId: RECOVERY_RP_ID,
  origin: RECOVERY_ORIGIN,
  publicKeyAlgorithm: "ES256",
  userVerification: "required",
  attestation: "none",
  requireAttestedCredentialData: true,
  backupEligibility: false,
  backupState: false,
  manufacturerProvenanceClaimed: false,
  acceptedRoles: Object.freeze([0, 1]),
  policyCommitment: id(
    `PHILCORE_CONSUMER_PLATFORM_POLICY_V1|${RECOVERY_RP_ID}|${RECOVERY_ORIGIN}|ES256|UV|AT|BE0|BS0|NONE`
  )
});

const EXTERNAL_HARDWARE_POLICY_V1 = Object.freeze({
  id: "PHILCORE_EXTERNAL_HARDWARE_POLICY_V1",
  version: 1,
  rpId: RECOVERY_RP_ID,
  origin: RECOVERY_ORIGIN,
  publicKeyAlgorithm: "ES256",
  userVerification: "required",
  attestation: "direct",
  trustRootBundleVersion: null,
  trustRootBundleIntegrityHash: null,
  supportedAttestationFormats: Object.freeze([]),
  readiness: "BLOCKED",
  blocker: "DIRECT_ATTESTATION_TRUST_ROOT_VALIDATION_NOT_IMPLEMENTED",
  manufacturerProvenanceClaimed: false,
  fallbackPolicyId: CONSUMER_PLATFORM_POLICY_V1.id,
  policyCommitment: id(
    `PHILCORE_EXTERNAL_HARDWARE_POLICY_V1|${RECOVERY_RP_ID}|${RECOVERY_ORIGIN}|DIRECT|BLOCKED`
  )
});

function classifyRegistrationPolicy(input) {
  if (input?.requestedProfile === "ENHANCED_HARDWARE") {
    return Object.freeze({
      accepted: false,
      classification: "UNVERIFIED_HARDWARE_REJECTED",
      policy: EXTERNAL_HARDWARE_POLICY_V1,
      safeFallbackAvailable: Boolean(input.allowConsumerPlatformFallback),
      fallbackClassification: input.allowConsumerPlatformFallback
        ? "CONSUMER_PLATFORM_NO_HARDWARE_ATTESTATION"
        : null
    });
  }
  if (
    input?.attestationConveyance !== "none"
    || input?.algorithm !== "ES256"
    || input?.userVerified !== true
    || input?.attestedCredentialDataPresent !== true
    || input?.backupEligible !== false
    || input?.backupState !== false
  ) {
    return Object.freeze({
      accepted: false,
      classification: "CONSUMER_PLATFORM_POLICY_REJECTED",
      policy: CONSUMER_PLATFORM_POLICY_V1
    });
  }
  return Object.freeze({
    accepted: true,
    classification: "CONSUMER_PLATFORM_NO_HARDWARE_ATTESTATION",
    policy: CONSUMER_PLATFORM_POLICY_V1
  });
}

module.exports = {
  CONSUMER_PLATFORM_POLICY_V1,
  EXTERNAL_HARDWARE_POLICY_V1,
  classifyRegistrationPolicy
};
