import type { Hex } from "../hashes.ts";
import type {
  ApplicationId,
  RuntimeEnvironment
} from "./types.ts";

export type HumanUniquenessProviderKind =
  | "world_id"
  | "development_fixture"
  | "unsupported";

export type HumanUniquenessRegistrationStatus =
  | "draft"
  | "pending_proof"
  | "pending_verification"
  | "pending_registration"
  | "registered"
  | "rejected"
  | "revoked"
  | "recovery_rebind_pending";

export type WorldIdIntegrationVersion = string;

export interface HumanUniquenessProofReference {
  readonly providerKind: HumanUniquenessProviderKind;
  readonly proofReferenceId: string;
  readonly proofVersion?: string;
  readonly proofBindingHash?: Hex;
  readonly verifiedByAdapterBoundary: false;
}

export interface HumanUniquenessRegistryReference {
  readonly registryReferenceId: string;
  readonly providerKind: HumanUniquenessProviderKind;
  readonly environment: RuntimeEnvironment;
  readonly registrationStatus: HumanUniquenessRegistrationStatus;
}

export interface HumanUniquenessReplayProtectionReference {
  readonly replayProtectionReferenceId: string;
  readonly providerKind: HumanUniquenessProviderKind;
  readonly registrationAttemptId?: string;
  readonly uniquenessRegistryReference?: HumanUniquenessRegistryReference;
  readonly returningUserContinuityReference?: string;
  readonly replayProtectionIsReturningUserContinuity: false;
}

export interface HumanUniquenessBinding {
  readonly bindingId: string;
  readonly providerKind: HumanUniquenessProviderKind;
  readonly ownerCommitment: Hex;
  readonly philIdentityRootReference?: string;
  readonly applicationId: ApplicationId;
  readonly uniquenessProofReference: HumanUniquenessProofReference;
  readonly replayProtectionReference?: HumanUniquenessReplayProtectionReference;
  readonly registryReference?: HumanUniquenessRegistryReference;
  readonly boundAt?: string;
  readonly activatesCanonicalPhilIdentity: boolean;
  readonly rawProviderSecretModeled: false;
}

export interface HumanUniquenessEnrollmentDraft {
  readonly enrollmentDraftId: string;
  readonly providerKind: HumanUniquenessProviderKind;
  readonly ownerCommitment: Hex;
  readonly applicationId: ApplicationId;
  readonly status: HumanUniquenessRegistrationStatus;
  readonly proofReference?: HumanUniquenessProofReference;
  readonly binding?: HumanUniquenessBinding;
  readonly registryReference?: HumanUniquenessRegistryReference;
  readonly replayProtectionReference?: HumanUniquenessReplayProtectionReference;
  readonly developmentFixture: boolean;
  readonly productionCanonicalActivation: boolean;
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly rawWorldIdSecretModeled: false;
  readonly replacesPhilIdentityRoot: false;
  readonly replacesDeviceCredential: false;
  readonly grantsWalletAuthority: false;
}

export interface HumanUniquenessEnrollmentRequest {
  readonly requestId: string;
  readonly providerKind: HumanUniquenessProviderKind;
  readonly ownerCommitment: Hex;
  readonly applicationId: ApplicationId;
  readonly enrollmentDraft?: HumanUniquenessEnrollmentDraft;
  readonly requestedAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface WorldIdRelyingPartyReference {
  readonly relyingPartyReferenceId: string;
  readonly applicationId: ApplicationId;
  readonly purpose: "canonical_phil_activation" | "recovery_rebind" | "development_fixture";
}

export interface WorldIdActionReference {
  readonly actionReferenceId: string;
  readonly action: string;
  readonly ownerCommitmentBound: true;
  readonly canonicalPhilActivationAction: boolean;
}

export interface WorldIdUniquenessProofReference extends HumanUniquenessProofReference {
  readonly providerKind: "world_id";
  readonly integrationVersion: WorldIdIntegrationVersion;
  readonly relyingParty: WorldIdRelyingPartyReference;
  readonly action: WorldIdActionReference;
  readonly signalBindingHash: Hex;
  readonly ownerCommitment: Hex;
  readonly rawWorldIdProofModeled: false;
}

export interface WorldIdSessionReference {
  readonly sessionReferenceId: string;
  readonly providerKind: "world_id";
  readonly continuityPurpose: "returning_user" | "recovery_rebind";
  readonly uniquenessReplayProtectionReference?: HumanUniquenessReplayProtectionReference;
  readonly grantsPhilIdentityContinuity: false;
}
