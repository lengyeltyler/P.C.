import type {
  HumanUniquenessBinding,
  HumanUniquenessEnrollmentDraft,
  HumanUniquenessProofReference,
  HumanUniquenessReplayProtectionReference,
  HumanUniquenessRegistryReference,
  WorldIdSessionReference,
  WorldIdUniquenessProofReference
} from "../../apps/phil-device-sdk/src/runtime/index.ts";

const proofReference: WorldIdUniquenessProofReference = {
  providerKind: "world_id",
  proofReferenceId: "world-id-proof-reference-1",
  proofVersion: "world-id-vNext",
  proofBindingHash: "0xproofbinding",
  verifiedByAdapterBoundary: false,
  integrationVersion: "world-id-integration-vNext",
  relyingParty: {
    relyingPartyReferenceId: "phil-canonical-activation-rp",
    applicationId: "recovery",
    purpose: "canonical_phil_activation"
  },
  action: {
    actionReferenceId: "phil-canonical-activation-action",
    action: "phil_canonical_activation",
    ownerCommitmentBound: true,
    canonicalPhilActivationAction: true
  },
  signalBindingHash: "0xsignalbinding",
  ownerCommitment: "0xownercommitment",
  rawWorldIdProofModeled: false
};

const registryReference: HumanUniquenessRegistryReference = {
  registryReferenceId: "phil-uniqueness-registry-reference-1",
  providerKind: "world_id",
  environment: "production",
  registrationStatus: "pending_registration"
};

const replayProtectionReference: HumanUniquenessReplayProtectionReference = {
  replayProtectionReferenceId: "world-id-replay-protection-1",
  providerKind: "world_id",
  uniquenessRegistryReference: registryReference,
  returningUserContinuityReference: "world-id-returning-user-session-reference-1",
  replayProtectionIsReturningUserContinuity: false
};

const binding: HumanUniquenessBinding = {
  bindingId: "human-uniqueness-binding-1",
  providerKind: "world_id",
  ownerCommitment: "0xownercommitment",
  philIdentityRootReference: "identityRoot-reference-only",
  applicationId: "recovery",
  uniquenessProofReference: proofReference,
  replayProtectionReference,
  registryReference,
  activatesCanonicalPhilIdentity: false,
  rawProviderSecretModeled: false
};

export const productionEnrollmentDraft: HumanUniquenessEnrollmentDraft = {
  enrollmentDraftId: "human-uniqueness-enrollment-draft-1",
  providerKind: "world_id",
  ownerCommitment: "0xownercommitment",
  applicationId: "recovery",
  status: "pending_registration",
  proofReference,
  binding,
  registryReference,
  replayProtectionReference,
  developmentFixture: false,
  productionCanonicalActivation: true,
  rawWorldIdSecretModeled: false,
  replacesPhilIdentityRoot: false,
  replacesDeviceCredential: false,
  grantsWalletAuthority: false
};

export const developmentFixtureProofReference: HumanUniquenessProofReference = {
  providerKind: "development_fixture",
  proofReferenceId: "development-fixture-proof-reference-1",
  verifiedByAdapterBoundary: false
};

export const developmentEnrollmentDraft: HumanUniquenessEnrollmentDraft = {
  enrollmentDraftId: "development-human-uniqueness-enrollment-draft-1",
  providerKind: "development_fixture",
  ownerCommitment: "0xownercommitment",
  applicationId: "recovery",
  status: "draft",
  proofReference: developmentFixtureProofReference,
  developmentFixture: true,
  productionCanonicalActivation: false,
  rawWorldIdSecretModeled: false,
  replacesPhilIdentityRoot: false,
  replacesDeviceCredential: false,
  grantsWalletAuthority: false
};

export const returningUserSessionReference: WorldIdSessionReference = {
  sessionReferenceId: "world-id-returning-user-session-reference-1",
  providerKind: "world_id",
  continuityPurpose: "returning_user",
  uniquenessReplayProtectionReference: replayProtectionReference,
  grantsPhilIdentityContinuity: false
};

// @ts-expect-error ownerCommitment is required for enrollment binding.
export const missingOwnerCommitmentEnrollment: HumanUniquenessEnrollmentDraft = {
  enrollmentDraftId: "invalid-human-uniqueness-enrollment-draft",
  providerKind: "world_id",
  applicationId: "recovery",
  status: "draft",
  developmentFixture: false,
  productionCanonicalActivation: true,
  rawWorldIdSecretModeled: false,
  replacesPhilIdentityRoot: false,
  replacesDeviceCredential: false,
  grantsWalletAuthority: false
};

export const replayProtectionCannotBeContinuity: HumanUniquenessReplayProtectionReference = {
  replayProtectionReferenceId: "invalid-replay-protection-reference",
  providerKind: "world_id",
  // @ts-expect-error uniqueness replay protection and returning-user continuity are separate.
  replayProtectionIsReturningUserContinuity: true
};
