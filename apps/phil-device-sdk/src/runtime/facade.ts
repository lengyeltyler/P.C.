import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  evaluateAuthoritativeCapabilityActivation,
  type ActiveCapabilityGrantInspectionRequest,
  type ActiveCapabilityGrantInspectionResultValue,
  type AuthoritativeCapabilityActivationRequest,
  type AuthoritativeCapabilityActivationResult,
  type AuthoritativeCapabilityGrant,
  type AuthoritativeCapabilityGrantStore,
  type CapabilityGrantRevocationRequest,
  type EphemeralCapabilityActivationEvidenceConsumptionStore,
  type UserSessionCapabilityMutationResult
} from "./authoritativeCapabilityGrant.ts";
import {
  evaluateAuthorizationDecisionCandidate,
  type AuthorizationDecisionCandidate,
  type AuthorizationDecisionCandidateCollectionResult,
  type AuthorizationDecisionCandidateRequest,
  type AuthorizationDecisionCandidateStore,
  type EphemeralAuthorizationCandidateConsumptionStore
} from "./authorizationDecisionCandidate.ts";
import {
  createAuthorizationPackageDraft,
  type AuthorizationPackageDraft,
  type AuthorizationPackageDraftCollectionResult,
  type AuthorizationPackageDraftRequest,
  type AuthorizationPackageDraftStore,
  type EphemeralAuthorizationPackageDraftConsumptionStore
} from "./authorizationPackageDraft.ts";
import {
  generateActionUnlockProof,
  type ActionUnlockProofGenerationArtifact,
  type ActionUnlockProofGenerationArtifactStore,
  type ActionUnlockProofGenerationCollectionResult,
  type ActionUnlockProofGenerationRequest,
  type EphemeralActionUnlockProofGenerationConsumptionStore
} from "./actionUnlockProofGeneration.ts";
import {
  finalizeAuthorizationPackage,
  verifyGeneratedActionUnlockProof,
  type ActionUnlockProofVerificationCollectionResult,
  type ActionUnlockProofVerificationRequest,
  type ActionUnlockProofVerificationResultStore,
  type ActionUnlockProofVerificationResultValue,
  type EphemeralActionUnlockProofVerificationConsumptionStore,
  type EphemeralFinalizedAuthorizationPackageConsumptionStore,
  type FinalizedAuthorizationPackage,
  type FinalizedAuthorizationPackageCollectionResult,
  type FinalizedAuthorizationPackageRequest,
  type FinalizedAuthorizationPackageStore
} from "./actionUnlockProofFinalization.ts";
import {
  createVerifiedFactPublicationRequestDraft,
  evaluateAuthorizationExecutionReadiness,
  type AuthorizationExecutionReadinessRequest,
  type AuthorizationExecutionReadinessResultCollectionResult,
  type AuthorizationExecutionReadinessResultStore,
  type AuthorizationExecutionReadinessResultValue,
  type VerifiedFactPublicationRequest,
  type VerifiedFactPublicationRequestDraft,
  type VerifiedFactPublicationRequestDraftCollectionResult,
  type VerifiedFactPublicationRequestDraftStore
} from "./authorizationExecutionReadiness.ts";
import {
  evaluateAuthoritativeSecurityPolicy,
  type AuthoritativePolicyDecision,
  type AuthoritativePolicyDecisionCollectionResult,
  type AuthoritativePolicyDecisionRequest,
  type AuthoritativePolicyDecisionStore,
  type EphemeralPolicyDecisionEvidenceConsumptionStore
} from "./authoritativePolicyDecision.ts";
import {
  evaluatePlatformUserApprovalDecision,
  type EphemeralUserApprovalArtifactConsumptionStore,
  type PlatformUserApprovalDecision,
  type PlatformUserApprovalDecisionCollectionResult,
  type PlatformUserApprovalDecisionRequest,
  type PlatformUserApprovalDecisionStore
} from "./platformUserApprovalDecision.ts";
import {
  evaluateAuthoritativeTrustDecision,
  type AuthoritativeTrustDecision,
  type AuthoritativeTrustDecisionCollectionResult,
  type AuthoritativeTrustDecisionRequest,
  type AuthoritativeTrustDecisionStore,
  type EphemeralTrustDecisionEvidenceConsumptionStore
} from "./authoritativeTrustDecision.ts";
import {
  evaluateBoundedRuntimePolicy,
  type BoundedPolicyEvaluationCollectionResult,
  type BoundedPolicyEvaluationRequest,
  type BoundedPolicyEvaluationResult,
  type BoundedPolicyEvaluationResultCollector,
  type BoundedPolicyEvaluationRuntimeResult
} from "./boundedPolicyEvaluation.ts";
import {
  evaluateBoundedTrustDecisionCandidate,
  type BoundedTrustDecisionCandidate,
  type BoundedTrustDecisionCandidateCollectionResult,
  type BoundedTrustDecisionCandidateCollector,
  type BoundedTrustDecisionCandidateRequest,
  type BoundedTrustDecisionCandidateResult
} from "./boundedTrustDecisionCandidate.ts";
import {
  evaluateBoundedTrustEvidence,
  type BoundedTrustEvaluationCollectionResult,
  type BoundedTrustEvaluationRequest,
  type BoundedTrustEvaluationResult,
  type BoundedTrustEvaluationResultCollector,
  type BoundedTrustEvaluationRuntimeResult
} from "./boundedTrustEvaluation.ts";
import {
  createCapabilityActivationCandidate,
  type CapabilityActivationCandidate,
  type CapabilityActivationCandidateCollectionResult,
  type CapabilityActivationCandidateCollector,
  type CapabilityActivationCandidateRequest,
  type CapabilityActivationCandidateResult
} from "./capabilityActivationCandidates.ts";
import {
  createCapabilityGrantDraft,
  type CapabilityGrantDraft,
  type CapabilityGrantDraftCollectionResult,
  type CapabilityGrantDraftCollector
} from "./capabilityDrafts.ts";
import {
  persistVerifiedCredentialCounter,
  resolveCounterPersistenceRequirement,
  type CredentialCounterPersistenceReceipt,
  type CredentialCounterPersistenceRequest,
  type CredentialCounterPersistenceResult,
  type EphemeralCredentialCounterPersistenceReplayStore,
  type TrustDecisionCandidateCounterResolution
} from "./credentialCounterPersistence.ts";
import {
  transitionUserSessionWithVerifiedVaultUnlock,
  verifyDeviceVaultUnlock,
  type DeviceVaultUnlockRequest,
  type DeviceVaultUnlockResult,
  type DeviceVaultUnlockResultValue,
  type EphemeralVaultUnlockConsumptionStore,
  type VerifiedVaultSessionUnlockRequest,
  type VerifiedVaultSessionUnlockResult,
  type VerifiedVaultSessionUnlockResultValue
} from "./deviceVaultUnlock.ts";
import {
  createProtectedStateView,
  type EphemeralProtectedStateViewReplayStore,
  type ProtectedStateViewCollector,
  type ProtectedStateViewCollectionResult,
  type ProtectedStateViewRequest,
  type ProtectedStateViewResult,
  type ProtectedStateViewResultValue
} from "./protectedStateView.ts";
import {
  requestPublicCredentialDirectory as createPublicCredentialDirectoryResult,
  type PublicCredentialDirectoryRequest,
  type PublicCredentialDirectoryResult,
  type PublicCredentialDirectoryResultCollector,
  type PublicCredentialDirectoryResultValue
} from "./publicCredentialDirectory.ts";
import {
  requestSelectedCredentialPublicMaterial as createSelectedCredentialPublicMaterialResult,
  type SelectedCredentialPublicMaterialRequest,
  type SelectedCredentialPublicMaterialResult,
  type SelectedCredentialPublicMaterialResultValue
} from "./selectedCredentialPublicMaterial.ts";
import {
  createTrustManagerVerificationInput,
  type TrustManagerVerificationInputRequest,
  type TrustManagerVerificationInputResult,
  type TrustManagerVerificationInputResultValue
} from "./trustManagerVerificationInput.ts";
import {
  verifyTrustManagerProductionAssertion,
  type EphemeralTrustManagerVerificationConsumptionStore,
  type TrustManagerProductionVerificationCollectionResult,
  type TrustManagerProductionVerificationRequest,
  type TrustManagerProductionVerificationResult,
  type TrustManagerProductionVerificationResultCollector,
  type TrustManagerProductionVerificationResultValue
} from "./trustManagerProductionVerification.ts";
import { bindSessionContextToRuntimeRequest, runtimeFailed } from "./helpers.ts";
import { runtimeDenied, runtimeOk } from "./helpers.ts";
import {
  createPossessionVerificationRequestDraft,
  type PossessionVerificationRequestDraft,
  type PossessionVerificationRequestDraftInput,
  type PossessionVerificationRequestDraftResult
} from "./possessionVerification.ts";
import {
  createPossessionEvaluationResultFromWebAuthnFixture,
  type PossessionEvaluationCollectionResult,
  type PossessionEvaluationRequest,
  type PossessionEvaluationResult,
  type PossessionEvaluationResultCollector,
  type PossessionEvaluationRuntimeResult
} from "./possessionEvaluation.ts";
import {
  evaluatePublicTrustMetadata,
  type PublicTrustMetadataEvaluationCollectionResult,
  type PublicTrustMetadataEvaluationCollector,
  type PublicTrustMetadataEvaluationRequest,
  type PublicTrustMetadataEvaluationResult,
  type PublicTrustMetadataEvaluationRuntimeResult
} from "./publicTrustMetadata.ts";
import {
  verifyProductionWebAuthnAuthentication,
  type ProductionAuthenticationVerificationCollectionResult,
  type ProductionAuthenticationVerificationRequest,
  type ProductionAuthenticationVerificationResult,
  type ProductionAuthenticationVerificationResultCollector,
  type ProductionAuthenticationVerificationResultValue
} from "./productionAuthenticationVerification.ts";
import {
  createLifecycleTransitionCandidate,
  transitionUserSessionWithProductionVerification,
  type EphemeralProductionVerificationConsumptionStore,
  type LifecycleTransitionCandidate,
  type LifecycleTransitionCandidateRequest,
  type LifecycleTransitionCandidateResult,
  type ProductionVerifiedPartialUnlockRequest,
  type ProductionVerifiedPartialUnlockResult,
  type ProductionVerifiedPartialUnlockResultValue
} from "./productionVerifiedPartialUnlock.ts";
import { redactRuntimeMetadata } from "./redaction.ts";
import {
  createTrustEvaluationDraft,
  type TrustEvaluationDraft,
  type TrustEvaluationDraftCollectionResult,
  type TrustEvaluationDraftCollector,
  type TrustEvaluationDraftInput,
  type TrustEvaluationDraftResult
} from "./trustDrafts.ts";
import {
  validateCapabilityRequestIntake,
  validateIntentRequestIntake,
  validateRuntimeRequestIntake,
  type RuntimeIntakeResult,
  type RuntimeRequestEnvelope
} from "./intake.ts";
import {
  createUserApprovalRequestDraft,
  type UserApprovalRequestDraft,
  type UserApprovalRequestDraftCollectionResult,
  type UserApprovalRequestDraftCollector,
  type UserApprovalRequestDraftInput,
  type UserApprovalRequestDraftResult
} from "./userApprovalDrafts.ts";
import {
  createUserDecisionFixtureArtifact,
  type UserDecisionFixtureArtifact,
  type UserDecisionFixtureArtifactCollectionResult,
  type UserDecisionFixtureArtifactCollector,
  type UserDecisionFixtureRequest,
  type UserDecisionFixtureResult
} from "./userDecisionFixtures.ts";
import {
  verifyPossessionDraftWithWebAuthnFixture,
  type WebAuthnFixtureVerificationArtifact,
  type WebAuthnFixtureVerificationRequest,
  type WebAuthnFixtureVerificationResult
} from "./webauthnFixtureVerification.ts";
import type { EphemeralUserSessionStore } from "./sessionStore.ts";
import type {
  CapabilityRequest,
  Intent,
  RequestAuditReviewRequest,
  RequestAuthorizationRequest,
  RequestContractCallRequest,
  RequestCredentialRevocationRequest,
  RequestCredentialRotationRequest,
  RequestEncryptedBackupExportRequest,
  RequestIntentRequest,
  RequestMessageSignatureRequest,
  RequestRecoveryApprovalRequest,
  RequestRecoveryStartRequest,
  RequestScopedAgentPermissionRequest,
  RequestSessionKeyManagementRequest,
  RequestSmartAccountDeploymentRequest,
  RequestTransactionPreparationRequest,
  RequestTransactionSubmissionRequest,
  RuntimeErrorDescriptor,
  RuntimeRequestContext,
  RuntimeResult,
  UserSessionContext
} from "./types.ts";

export interface ValidationOnlyRuntimeApiResultValue {
  readonly intake: RuntimeIntakeResult;
  readonly capabilityGrantDraft?: CapabilityGrantDraft;
  readonly capabilityGrantDraftCollectionResult?: CapabilityGrantDraftCollectionResult;
  readonly trustEvaluationDraft?: TrustEvaluationDraft;
  readonly trustEvaluationDraftCollectionResult?: TrustEvaluationDraftCollectionResult;
  readonly publicTrustMetadataEvaluation?: PublicTrustMetadataEvaluationResult;
  readonly publicTrustMetadataEvaluationCollectionResult?:
    PublicTrustMetadataEvaluationCollectionResult;
  readonly possessionVerificationRequestDraft?: PossessionVerificationRequestDraft;
  readonly webAuthnFixtureVerificationArtifact?: WebAuthnFixtureVerificationArtifact;
  readonly possessionEvaluationResult?: PossessionEvaluationResult;
  readonly possessionEvaluationCollectionResult?: PossessionEvaluationCollectionResult;
  readonly boundedTrustEvaluationResult?: BoundedTrustEvaluationResult;
  readonly boundedTrustEvaluationCollectionResult?: BoundedTrustEvaluationCollectionResult;
  readonly boundedPolicyEvaluationResult?: BoundedPolicyEvaluationResult;
  readonly boundedPolicyEvaluationCollectionResult?: BoundedPolicyEvaluationCollectionResult;
  readonly userApprovalRequestDraft?: UserApprovalRequestDraft;
  readonly userApprovalRequestDraftCollectionResult?: UserApprovalRequestDraftCollectionResult;
  readonly userDecisionFixtureArtifact?: UserDecisionFixtureArtifact;
  readonly userDecisionFixtureArtifactCollectionResult?: UserDecisionFixtureArtifactCollectionResult;
  readonly capabilityActivationCandidate?: CapabilityActivationCandidate;
  readonly capabilityActivationCandidateCollectionResult?:
    CapabilityActivationCandidateCollectionResult;
  readonly productionAuthenticationVerification?: ProductionAuthenticationVerificationResultValue;
  readonly productionAuthenticationVerificationCollectionResult?:
    ProductionAuthenticationVerificationCollectionResult;
  readonly lifecycleTransitionCandidate?: LifecycleTransitionCandidate;
  readonly productionVerifiedPartialUnlock?: ProductionVerifiedPartialUnlockResultValue;
  readonly deviceVaultUnlockResult?: DeviceVaultUnlockResultValue;
  readonly verifiedVaultSessionUnlock?: VerifiedVaultSessionUnlockResultValue;
  readonly protectedStateView?: ProtectedStateViewResultValue;
  readonly protectedStateViewCollectionResult?: ProtectedStateViewCollectionResult;
  readonly publicCredentialDirectory?: PublicCredentialDirectoryResultValue;
  readonly selectedCredentialPublicMaterial?: SelectedCredentialPublicMaterialResultValue;
  readonly trustManagerVerificationInput?: TrustManagerVerificationInputResultValue;
  readonly trustManagerProductionVerification?: TrustManagerProductionVerificationResultValue;
  readonly trustManagerProductionVerificationCollectionResult?:
    TrustManagerProductionVerificationCollectionResult;
  readonly boundedTrustDecisionCandidate?: BoundedTrustDecisionCandidate;
  readonly boundedTrustDecisionCandidateCollectionResult?:
    BoundedTrustDecisionCandidateCollectionResult;
  readonly credentialCounterPersistenceReceipt?: CredentialCounterPersistenceReceipt;
  readonly trustDecisionCandidateCounterResolution?:
    TrustDecisionCandidateCounterResolution;
  readonly authoritativeTrustDecision?: AuthoritativeTrustDecision;
  readonly authoritativeTrustDecisionCollectionResult?:
    AuthoritativeTrustDecisionCollectionResult;
  readonly authoritativePolicyDecision?: AuthoritativePolicyDecision;
  readonly authoritativePolicyDecisionCollectionResult?:
    AuthoritativePolicyDecisionCollectionResult;
  readonly platformUserApprovalDecision?: PlatformUserApprovalDecision;
  readonly platformUserApprovalDecisionCollectionResult?:
    PlatformUserApprovalDecisionCollectionResult;
  readonly authoritativeCapabilityGrant?: AuthoritativeCapabilityGrant;
  readonly userSessionCapabilityMutationResult?: UserSessionCapabilityMutationResult;
  readonly activeCapabilityGrantInspection?: ActiveCapabilityGrantInspectionResultValue;
  readonly authorizationDecisionCandidate?: AuthorizationDecisionCandidate;
  readonly authorizationDecisionCandidateCollectionResult?:
    AuthorizationDecisionCandidateCollectionResult;
  readonly authorizationPackageDraft?: AuthorizationPackageDraft;
  readonly authorizationPackageDraftCollectionResult?: AuthorizationPackageDraftCollectionResult;
  readonly actionUnlockProofGenerationArtifact?: ActionUnlockProofGenerationArtifact;
  readonly actionUnlockProofGenerationCollectionResult?:
    ActionUnlockProofGenerationCollectionResult;
  readonly actionUnlockProofVerification?: ActionUnlockProofVerificationResultValue;
  readonly actionUnlockProofVerificationCollectionResult?:
    ActionUnlockProofVerificationCollectionResult;
  readonly finalizedAuthorizationPackage?: FinalizedAuthorizationPackage;
  readonly finalizedAuthorizationPackageCollectionResult?:
    FinalizedAuthorizationPackageCollectionResult;
  readonly verifiedFactPublicationRequestDraft?: VerifiedFactPublicationRequestDraft;
  readonly verifiedFactPublicationRequestDraftCollectionResult?:
    VerifiedFactPublicationRequestDraftCollectionResult;
  readonly authorizationExecutionReadiness?: AuthorizationExecutionReadinessResultValue;
  readonly authorizationExecutionReadinessCollectionResult?:
    AuthorizationExecutionReadinessResultCollectionResult;
  readonly auditEventDraft: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly sessionId?: string;
}

export type ValidationOnlyRuntimeApiResult = RuntimeResult<ValidationOnlyRuntimeApiResultValue>;

export interface ValidationOnlyRuntimeApiOptions {
  readonly auditDraftCollector?: AuditDraftCollector;
  readonly capabilityGrantDraftCollector?: CapabilityGrantDraftCollector;
  readonly trustEvaluationDraftCollector?: TrustEvaluationDraftCollector;
  readonly publicTrustMetadataEvaluationCollector?: PublicTrustMetadataEvaluationCollector;
  readonly possessionEvaluationResultCollector?: PossessionEvaluationResultCollector;
  readonly boundedTrustEvaluationResultCollector?: BoundedTrustEvaluationResultCollector;
  readonly boundedPolicyEvaluationResultCollector?: BoundedPolicyEvaluationResultCollector;
  readonly userApprovalRequestDraftCollector?: UserApprovalRequestDraftCollector;
  readonly userDecisionFixtureArtifactCollector?: UserDecisionFixtureArtifactCollector;
  readonly capabilityActivationCandidateCollector?: CapabilityActivationCandidateCollector;
  readonly productionAuthenticationVerificationCollector?:
    ProductionAuthenticationVerificationResultCollector;
  readonly productionVerificationConsumptionStore?: EphemeralProductionVerificationConsumptionStore;
  readonly vaultUnlockConsumptionStore?: EphemeralVaultUnlockConsumptionStore;
  readonly protectedStateViewCollector?: ProtectedStateViewCollector;
  readonly protectedStateViewReplayStore?: EphemeralProtectedStateViewReplayStore;
  readonly publicCredentialDirectoryResultCollector?: PublicCredentialDirectoryResultCollector;
  readonly trustManagerProductionVerificationCollector?:
    TrustManagerProductionVerificationResultCollector;
  readonly trustManagerVerificationConsumptionStore?:
    EphemeralTrustManagerVerificationConsumptionStore;
  readonly boundedTrustDecisionCandidateCollector?: BoundedTrustDecisionCandidateCollector;
  readonly credentialCounterPersistenceReplayStore?:
    EphemeralCredentialCounterPersistenceReplayStore;
  readonly trustDecisionEvidenceConsumptionStore?:
    EphemeralTrustDecisionEvidenceConsumptionStore;
  readonly authoritativeTrustDecisionStore?: AuthoritativeTrustDecisionStore;
  readonly policyDecisionEvidenceConsumptionStore?:
    EphemeralPolicyDecisionEvidenceConsumptionStore;
  readonly authoritativePolicyDecisionStore?: AuthoritativePolicyDecisionStore;
  readonly userApprovalArtifactConsumptionStore?:
    EphemeralUserApprovalArtifactConsumptionStore;
  readonly platformUserApprovalDecisionStore?: PlatformUserApprovalDecisionStore;
  readonly capabilityActivationEvidenceConsumptionStore?:
    EphemeralCapabilityActivationEvidenceConsumptionStore;
  readonly authoritativeCapabilityGrantStore?: AuthoritativeCapabilityGrantStore;
  readonly authorizationCandidateConsumptionStore?:
    EphemeralAuthorizationCandidateConsumptionStore;
  readonly authorizationDecisionCandidateStore?: AuthorizationDecisionCandidateStore;
  readonly authorizationPackageDraftConsumptionStore?:
    EphemeralAuthorizationPackageDraftConsumptionStore;
  readonly authorizationPackageDraftStore?: AuthorizationPackageDraftStore;
  readonly actionUnlockProofGenerationConsumptionStore?:
    EphemeralActionUnlockProofGenerationConsumptionStore;
  readonly actionUnlockProofGenerationArtifactStore?: ActionUnlockProofGenerationArtifactStore;
  readonly actionUnlockProofVerificationConsumptionStore?:
    EphemeralActionUnlockProofVerificationConsumptionStore;
  readonly actionUnlockProofVerificationResultStore?: ActionUnlockProofVerificationResultStore;
  readonly finalizedAuthorizationPackageConsumptionStore?:
    EphemeralFinalizedAuthorizationPackageConsumptionStore;
  readonly finalizedAuthorizationPackageStore?: FinalizedAuthorizationPackageStore;
  readonly verifiedFactPublicationRequestDraftStore?:
    VerifiedFactPublicationRequestDraftStore;
  readonly authorizationExecutionReadinessResultStore?:
    AuthorizationExecutionReadinessResultStore;
  readonly userSessionContext?: UserSessionContext;
  readonly userSessionStore?: EphemeralUserSessionStore;
}

export interface ValidationOnlyRuntimeApi {
  requestCapability(request: CapabilityRequest): ValidationOnlyRuntimeApiResult;
  requestTrustEvaluationDraft(request: TrustEvaluationDraftInput): ValidationOnlyRuntimeApiResult;
  requestPublicTrustMetadataEvaluation(
    request: PublicTrustMetadataEvaluationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestPossessionVerificationDraft(
    request: PossessionVerificationRequestDraftInput
  ): ValidationOnlyRuntimeApiResult;
  requestWebAuthnFixturePossessionVerification(
    request: WebAuthnFixtureVerificationRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestFixturePossessionEvaluation(
    request: PossessionEvaluationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestBoundedTrustEvaluation(
    request: BoundedTrustEvaluationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestBoundedPolicyEvaluation(
    request: BoundedPolicyEvaluationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestUserApprovalDraft(request: UserApprovalRequestDraftInput): ValidationOnlyRuntimeApiResult;
  requestUserDecisionFixture(request: UserDecisionFixtureRequest): ValidationOnlyRuntimeApiResult;
  requestCapabilityActivationCandidate(
    request: CapabilityActivationCandidateRequest
  ): ValidationOnlyRuntimeApiResult;
  requestProductionAuthenticationVerification(
    request: ProductionAuthenticationVerificationRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestLifecycleTransitionCandidate(
    request: LifecycleTransitionCandidateRequest
  ): ValidationOnlyRuntimeApiResult;
  requestProductionVerifiedPartialUnlock(
    request: ProductionVerifiedPartialUnlockRequest
  ): ValidationOnlyRuntimeApiResult;
  requestDeviceVaultUnlockVerification(
    request: DeviceVaultUnlockRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestVerifiedVaultSessionUnlock(
    request: VerifiedVaultSessionUnlockRequest
  ): ValidationOnlyRuntimeApiResult;
  requestProtectedStateView(
    request: ProtectedStateViewRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestPublicCredentialDirectory(
    request: PublicCredentialDirectoryRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestSelectedCredentialPublicMaterial(
    request: SelectedCredentialPublicMaterialRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestTrustManagerVerificationInput(
    request: TrustManagerVerificationInputRequest
  ): ValidationOnlyRuntimeApiResult;
  requestTrustManagerProductionVerification(
    request: TrustManagerProductionVerificationRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestBoundedTrustDecisionCandidate(
    request: BoundedTrustDecisionCandidateRequest
  ): ValidationOnlyRuntimeApiResult;
  requestCredentialCounterPersistence(
    request: CredentialCounterPersistenceRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestAuthoritativeTrustDecision(
    request: AuthoritativeTrustDecisionRequest
  ): ValidationOnlyRuntimeApiResult;
  requestAuthoritativePolicyDecision(
    request: AuthoritativePolicyDecisionRequest
  ): ValidationOnlyRuntimeApiResult;
  requestPlatformUserApprovalDecision(
    request: PlatformUserApprovalDecisionRequest
  ): ValidationOnlyRuntimeApiResult;
  requestAuthoritativeCapabilityActivation(
    request: AuthoritativeCapabilityActivationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestCapabilityGrantRevocation(
    request: CapabilityGrantRevocationRequest
  ): ValidationOnlyRuntimeApiResult;
  inspectActiveCapabilityGrants(
    request: ActiveCapabilityGrantInspectionRequest
  ): ValidationOnlyRuntimeApiResult;
  requestAuthorizationDecisionCandidate(
    request: AuthorizationDecisionCandidateRequest
  ): ValidationOnlyRuntimeApiResult;
  requestAuthorizationPackageDraft(
    request: AuthorizationPackageDraftRequest
  ): ValidationOnlyRuntimeApiResult;
  requestActionUnlockProofGeneration(
    request: ActionUnlockProofGenerationRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestActionUnlockProofVerification(
    request: ActionUnlockProofVerificationRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestFinalizedAuthorizationPackage(
    request: FinalizedAuthorizationPackageRequest
  ): ValidationOnlyRuntimeApiResult;
  requestVerifiedFactPublicationDraft(
    request: VerifiedFactPublicationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestAuthorizationExecutionReadiness(
    request: AuthorizationExecutionReadinessRequest
  ): Promise<ValidationOnlyRuntimeApiResult>;
  requestIntent(request: RequestIntentRequest): ValidationOnlyRuntimeApiResult;
  requestAuthorization(request: RequestAuthorizationRequest): ValidationOnlyRuntimeApiResult;
  requestMessageSignature(request: RequestMessageSignatureRequest): ValidationOnlyRuntimeApiResult;
  requestTransactionPreparation(
    request: RequestTransactionPreparationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestTransactionSubmission(
    request: RequestTransactionSubmissionRequest
  ): ValidationOnlyRuntimeApiResult;
  requestContractCall(request: RequestContractCallRequest): ValidationOnlyRuntimeApiResult;
  requestSmartAccountDeployment(
    request: RequestSmartAccountDeploymentRequest
  ): ValidationOnlyRuntimeApiResult;
  requestSessionKeyManagement(
    request: RequestSessionKeyManagementRequest
  ): ValidationOnlyRuntimeApiResult;
  requestCredentialRotation(
    request: RequestCredentialRotationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestCredentialRevocation(
    request: RequestCredentialRevocationRequest
  ): ValidationOnlyRuntimeApiResult;
  requestEncryptedBackupExport(
    request: RequestEncryptedBackupExportRequest
  ): ValidationOnlyRuntimeApiResult;
  requestRecoveryStart(request: RequestRecoveryStartRequest): ValidationOnlyRuntimeApiResult;
  requestRecoveryApproval(request: RequestRecoveryApprovalRequest): ValidationOnlyRuntimeApiResult;
  requestAuditReview(request: RequestAuditReviewRequest): ValidationOnlyRuntimeApiResult;
  requestScopedAgentPermission(
    request: RequestScopedAgentPermissionRequest
  ): ValidationOnlyRuntimeApiResult;
}

function bindOptionalSessionContext<TContext extends RuntimeRequestContext>(
  context: TContext,
  userSessionContext?: UserSessionContext
): TContext {
  if (!userSessionContext) {
    return context;
  }
  return bindSessionContextToRuntimeRequest(context, userSessionContext);
}

function userSessionContextFromOptions(
  options: ValidationOnlyRuntimeApiOptions
): UserSessionContext | undefined {
  return options.userSessionContext ?? options.userSessionStore?.getSessionContext();
}

function contextFromRequest(
  request: RuntimeRequestContext,
  userSessionContext?: UserSessionContext
): RuntimeRequestContext {
  const metadata = request.metadata
    ? redactRuntimeMetadata(request.metadata).value as Readonly<Record<string, unknown>>
    : undefined;

  return bindOptionalSessionContext({
    requestId: request.requestId,
    sessionId: request.sessionId,
    applicationId: request.applicationId,
    requestedAt: request.requestedAt,
    metadata
  }, userSessionContext);
}

function contextFromCapabilityRequest(
  request: CapabilityRequest,
  userSessionContext?: UserSessionContext
): RuntimeRequestContext {
  return bindOptionalSessionContext({
    requestId: request.requestId,
    applicationId: request.applicationId,
    requestedAt: request.requestedAt
  }, userSessionContext);
}

function intentEnvelope<TPayload>(
  request: RuntimeRequestContext & { readonly intent: Intent<TPayload> },
  userSessionContext?: UserSessionContext
): RuntimeRequestEnvelope {
  return {
    kind: "intent",
    context: contextFromRequest(request, userSessionContext),
    intent: request.intent
  };
}

function unsupportedFutureScopedAgentPermission(): RuntimeIntakeResult {
  const error: RuntimeErrorDescriptor = {
    category: "unsupported_operation",
    code: "RUNTIME_FACADE_UNSUPPORTED_FUTURE_AGENT_PERMISSION",
    message: "Future scoped agent permissions are validation-only and not supported by this facade.",
    boundary: "runtime-api",
    recoverable: true
  };

  return runtimeFailed(error);
}

function outcomeFromIntake(intake: RuntimeIntakeResult) {
  if (intake.status === "approved") {
    return "validation_succeeded" as const;
  }
  if (intake.status === "failed") {
    return "malformed" as const;
  }
  return "validation_failed" as const;
}

function intakeFromTrustEvaluationDraftResult(
  result: TrustEvaluationDraftResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "TRUST_EVALUATION_DRAFT_INVALID",
    message: "trust evaluation draft request failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromPublicTrustMetadataEvaluationResult(
  result: PublicTrustMetadataEvaluationRuntimeResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "PUBLIC_TRUST_METADATA_EVALUATION_INVALID",
    message: "public Trust metadata evaluation request failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromPossessionVerificationRequestDraftResult(
  result: PossessionVerificationRequestDraftResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "POSSESSION_VERIFICATION_REQUEST_DRAFT_INVALID",
    message: "possession verification request draft failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromWebAuthnFixtureVerificationResult(
  result: WebAuthnFixtureVerificationResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "WEBAUTHN_FIXTURE_VERIFICATION_INVALID",
    message: "WebAuthn fixture verification request failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromPossessionEvaluationResult(
  result: PossessionEvaluationRuntimeResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "POSSESSION_EVALUATION_INVALID",
    message: "possession evaluation request failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromBoundedTrustEvaluationResult(
  result: BoundedTrustEvaluationRuntimeResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "BOUNDED_TRUST_EVALUATION_INVALID",
    message: "bounded Trust evaluation request failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromBoundedPolicyEvaluationResult(
  result: BoundedPolicyEvaluationRuntimeResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "BOUNDED_POLICY_EVALUATION_INVALID",
    message: "bounded policy evaluation request failed validation",
    boundary: "security-policy-engine",
    recoverable: true
  });
}

function intakeFromUserApprovalRequestDraftResult(
  result: UserApprovalRequestDraftResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "USER_APPROVAL_REQUEST_DRAFT_INVALID",
    message: "user approval request draft failed validation",
    boundary: "security-policy-engine",
    recoverable: true
  });
}

function intakeFromUserDecisionFixtureResult(
  result: UserDecisionFixtureResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "USER_DECISION_FIXTURE_ARTIFACT_INVALID",
    message: "user decision fixture request failed validation",
    boundary: "runtime-api",
    recoverable: true
  });
}

function intakeFromCapabilityActivationCandidateResult(
  result: CapabilityActivationCandidateResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "CAPABILITY_ACTIVATION_CANDIDATE_INVALID",
    message: "capability activation candidate request failed validation",
    boundary: "runtime-api",
    recoverable: true
  });
}

function intakeFromProductionAuthenticationVerificationResult(
  result: ProductionAuthenticationVerificationResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "PRODUCTION_AUTHENTICATION_VERIFICATION_INVALID",
    message: "production authentication verification request failed validation",
    boundary: "user-session",
    recoverable: true
  });
}

function intakeFromLifecycleTransitionCandidateResult(
  result: LifecycleTransitionCandidateResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "LIFECYCLE_TRANSITION_CANDIDATE_INVALID",
    message: "lifecycle transition candidate request failed validation",
    boundary: "user-session",
    recoverable: true
  });
}

function intakeFromProductionVerifiedPartialUnlockResult(
  result: ProductionVerifiedPartialUnlockResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "PRODUCTION_VERIFIED_PARTIAL_UNLOCK_INVALID",
    message: "production-verified partial unlock request failed validation",
    boundary: "user-session",
    recoverable: true
  });
}

function intakeFromDeviceVaultUnlockResult(
  result: DeviceVaultUnlockResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "vault_unavailable",
    code: "DEVICE_VAULT_UNLOCK_INVALID",
    message: "Device Vault unlock request failed validation",
    boundary: "device-vault",
    recoverable: true
  });
}

function intakeFromVerifiedVaultSessionUnlockResult(
  result: VerifiedVaultSessionUnlockResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "vault_unavailable",
    code: "VERIFIED_VAULT_SESSION_UNLOCK_INVALID",
    message: "verified Device Vault session unlock request failed validation",
    boundary: "user-session",
    recoverable: true
  });
}

function intakeFromProtectedStateViewResult(
  result: ProtectedStateViewResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "vault_unavailable",
    code: "PROTECTED_STATE_VIEW_INVALID",
    message: "protected state view request failed validation",
    boundary: "device-vault",
    recoverable: true
  });
}

function intakeFromPublicCredentialDirectoryResult(
  result: PublicCredentialDirectoryResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "vault_unavailable",
    code: "PUBLIC_CREDENTIAL_DIRECTORY_INVALID",
    message: "public credential directory request failed validation",
    boundary: "device-vault",
    recoverable: true
  });
}

function intakeFromSelectedCredentialPublicMaterialResult(
  result: SelectedCredentialPublicMaterialResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "vault_unavailable",
    code: "SELECTED_CREDENTIAL_PUBLIC_MATERIAL_INVALID",
    message: "selected credential public material request failed validation",
    boundary: "device-vault",
    recoverable: true
  });
}

function intakeFromTrustManagerVerificationInputResult(
  result: TrustManagerVerificationInputResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "TRUST_MANAGER_VERIFICATION_INPUT_INVALID",
    message: "Trust Manager verification input request failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromTrustManagerProductionVerificationResult(
  result: TrustManagerProductionVerificationResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "TRUST_MANAGER_PRODUCTION_VERIFICATION_INVALID",
    message: "Trust Manager production verification request failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromBoundedTrustDecisionCandidateResult(
  result: BoundedTrustDecisionCandidateResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_intent",
    code: "BOUNDED_TRUST_DECISION_CANDIDATE_INVALID",
    message: "bounded Trust Decision candidate request failed validation",
    boundary: "trust-manager",
    recoverable: true
  });
}

function intakeFromCredentialCounterPersistenceResult(
  result: CredentialCounterPersistenceResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "vault_unavailable",
    code: "CREDENTIAL_COUNTER_PERSISTENCE_INVALID",
    message: "credential counter persistence request failed validation",
    boundary: "device-vault",
    recoverable: true
  });
}

function intakeFromAuthoritativeCapabilityActivationResult(
  result: AuthoritativeCapabilityActivationResult
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "capability_denied",
    code: "AUTHORITATIVE_CAPABILITY_ACTIVATION_REJECTED",
    message: "authoritative capability activation request was rejected",
    boundary: "runtime-api",
    recoverable: true
  });
}

function intakeFromAuthorizationDecisionCandidateResult(
  result: RuntimeResult<AuthorizationDecisionCandidate>
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_authorization_package",
    code: "AUTHORIZATION_DECISION_CANDIDATE_REJECTED",
    message: "authorization decision candidate request was rejected",
    boundary: "authorization-engine",
    recoverable: true
  });
}

function intakeFromAuthorizationPackageDraftResult(
  result: RuntimeResult<AuthorizationPackageDraft>
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_authorization_package",
    code: "AUTHORIZATION_PACKAGE_DRAFT_REJECTED",
    message: "authorization package draft request was rejected",
    boundary: "authorization-engine",
    recoverable: true
  });
}

function intakeFromActionUnlockProofGenerationResult(
  result: RuntimeResult<ActionUnlockProofGenerationArtifact>
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  const fallback = {
    category: "proof_failed" as const,
    code: "ACTION_UNLOCK_PROOF_GENERATION_REJECTED",
    message: "ACTION_UNLOCK proof generation request was rejected",
    boundary: "proof-system" as const,
    recoverable: true
  };
  return result.status === "failed"
    ? runtimeFailed(result.error ?? fallback)
    : runtimeDenied(result.error ?? fallback);
}

function intakeFromActionUnlockProofVerificationResult(
  result: RuntimeResult<ActionUnlockProofVerificationResultValue>
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  const fallback = {
    category: "proof_failed" as const,
    code: "ACTION_UNLOCK_PROOF_VERIFICATION_REJECTED",
    message: "ACTION_UNLOCK proof verification request was rejected",
    boundary: "proof-system" as const,
    recoverable: true
  };
  return result.status === "failed"
    ? runtimeFailed(result.error ?? fallback)
    : runtimeDenied(result.error ?? fallback);
}

function intakeFromFinalizedAuthorizationPackageResult(
  result: RuntimeResult<FinalizedAuthorizationPackage>
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_authorization_package",
    code: "FINALIZED_AUTHORIZATION_PACKAGE_REJECTED",
    message: "finalized authorization package request was rejected",
    boundary: "authorization-engine",
    recoverable: true
  });
}

function intakeFromVerifiedFactPublicationRequestResult(
  result: RuntimeResult<VerifiedFactPublicationRequestDraft>
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "invalid_authorization_package",
    code: "VERIFIED_FACT_PUBLICATION_REQUEST_REJECTED",
    message: "verified fact publication request was rejected",
    boundary: "authorization-engine",
    recoverable: true
  });
}

function intakeFromAuthorizationExecutionReadinessResult(
  result: RuntimeResult<AuthorizationExecutionReadinessResultValue>
): RuntimeIntakeResult {
  if (result.status === "approved") {
    return runtimeOk({
      valid: true,
      issues: []
    });
  }

  return runtimeDenied(result.error ?? {
    category: "unsupported_operation",
    code: "AUTHORIZATION_EXECUTION_READINESS_BLOCKED",
    message: "authorization execution readiness request was blocked",
    boundary: "authorization-engine",
    recoverable: true
  });
}

function wrapIntakeWithAuditDraft(input: {
  intake: RuntimeIntakeResult;
  envelope: RuntimeRequestEnvelope;
  category: AuditEventDraft["category"];
  summary: string;
  outcome?: AuditEventDraft["outcome"];
  auditDraftCollector?: AuditDraftCollector;
  capabilityGrantDraft?: CapabilityGrantDraft;
  capabilityGrantDraftCollectionResult?: CapabilityGrantDraftCollectionResult;
  trustEvaluationDraft?: TrustEvaluationDraft;
  trustEvaluationDraftCollectionResult?: TrustEvaluationDraftCollectionResult;
  publicTrustMetadataEvaluation?: PublicTrustMetadataEvaluationResult;
  publicTrustMetadataEvaluationCollectionResult?: PublicTrustMetadataEvaluationCollectionResult;
  possessionVerificationRequestDraft?: PossessionVerificationRequestDraft;
  webAuthnFixtureVerificationArtifact?: WebAuthnFixtureVerificationArtifact;
  possessionEvaluationResult?: PossessionEvaluationResult;
  possessionEvaluationCollectionResult?: PossessionEvaluationCollectionResult;
  boundedTrustEvaluationResult?: BoundedTrustEvaluationResult;
  boundedTrustEvaluationCollectionResult?: BoundedTrustEvaluationCollectionResult;
  boundedPolicyEvaluationResult?: BoundedPolicyEvaluationResult;
  boundedPolicyEvaluationCollectionResult?: BoundedPolicyEvaluationCollectionResult;
  userApprovalRequestDraft?: UserApprovalRequestDraft;
  userApprovalRequestDraftCollectionResult?: UserApprovalRequestDraftCollectionResult;
  userDecisionFixtureArtifact?: UserDecisionFixtureArtifact;
  userDecisionFixtureArtifactCollectionResult?: UserDecisionFixtureArtifactCollectionResult;
  capabilityActivationCandidate?: CapabilityActivationCandidate;
  capabilityActivationCandidateCollectionResult?: CapabilityActivationCandidateCollectionResult;
  productionAuthenticationVerification?: ProductionAuthenticationVerificationResultValue;
  productionAuthenticationVerificationCollectionResult?: ProductionAuthenticationVerificationCollectionResult;
  lifecycleTransitionCandidate?: LifecycleTransitionCandidate;
  productionVerifiedPartialUnlock?: ProductionVerifiedPartialUnlockResultValue;
  deviceVaultUnlockResult?: DeviceVaultUnlockResultValue;
  verifiedVaultSessionUnlock?: VerifiedVaultSessionUnlockResultValue;
  protectedStateView?: ProtectedStateViewResultValue;
  protectedStateViewCollectionResult?: ProtectedStateViewCollectionResult;
  publicCredentialDirectory?: PublicCredentialDirectoryResultValue;
  selectedCredentialPublicMaterial?: SelectedCredentialPublicMaterialResultValue;
  trustManagerVerificationInput?: TrustManagerVerificationInputResultValue;
  trustManagerProductionVerification?: TrustManagerProductionVerificationResultValue;
  trustManagerProductionVerificationCollectionResult?:
    TrustManagerProductionVerificationCollectionResult;
  boundedTrustDecisionCandidate?: BoundedTrustDecisionCandidate;
  boundedTrustDecisionCandidateCollectionResult?:
    BoundedTrustDecisionCandidateCollectionResult;
  credentialCounterPersistenceReceipt?: CredentialCounterPersistenceReceipt;
  trustDecisionCandidateCounterResolution?: TrustDecisionCandidateCounterResolution;
  authoritativeTrustDecision?: AuthoritativeTrustDecision;
  authoritativeTrustDecisionCollectionResult?: AuthoritativeTrustDecisionCollectionResult;
  authoritativePolicyDecision?: AuthoritativePolicyDecision;
  authoritativePolicyDecisionCollectionResult?: AuthoritativePolicyDecisionCollectionResult;
  platformUserApprovalDecision?: PlatformUserApprovalDecision;
  platformUserApprovalDecisionCollectionResult?: PlatformUserApprovalDecisionCollectionResult;
  authoritativeCapabilityGrant?: AuthoritativeCapabilityGrant;
  userSessionCapabilityMutationResult?: UserSessionCapabilityMutationResult;
  activeCapabilityGrantInspection?: ActiveCapabilityGrantInspectionResultValue;
  authorizationDecisionCandidate?: AuthorizationDecisionCandidate;
  authorizationDecisionCandidateCollectionResult?: AuthorizationDecisionCandidateCollectionResult;
  authorizationPackageDraft?: AuthorizationPackageDraft;
  authorizationPackageDraftCollectionResult?: AuthorizationPackageDraftCollectionResult;
  actionUnlockProofGenerationArtifact?: ActionUnlockProofGenerationArtifact;
  actionUnlockProofGenerationCollectionResult?: ActionUnlockProofGenerationCollectionResult;
  actionUnlockProofVerification?: ActionUnlockProofVerificationResultValue;
  actionUnlockProofVerificationCollectionResult?: ActionUnlockProofVerificationCollectionResult;
  finalizedAuthorizationPackage?: FinalizedAuthorizationPackage;
  finalizedAuthorizationPackageCollectionResult?: FinalizedAuthorizationPackageCollectionResult;
  verifiedFactPublicationRequestDraft?: VerifiedFactPublicationRequestDraft;
  verifiedFactPublicationRequestDraftCollectionResult?: VerifiedFactPublicationRequestDraftCollectionResult;
  authorizationExecutionReadiness?: AuthorizationExecutionReadinessResultValue;
  authorizationExecutionReadinessCollectionResult?: AuthorizationExecutionReadinessResultCollectionResult;
}): ValidationOnlyRuntimeApiResult {
  const outcome = input.outcome ?? outcomeFromIntake(input.intake);
  const auditEventDraft = createAuditEventDraft({
    category: input.category,
    outcome,
    requestKind: input.envelope.kind,
    sessionId: input.envelope.context?.sessionId,
    applicationId: input.envelope.context?.applicationId
      ?? input.envelope.intent?.applicationId
      ?? input.envelope.capabilityRequest?.applicationId,
    intentId: input.envelope.intent?.intentId,
    capabilityId: input.envelope.context?.requestId
      ?? input.envelope.capabilityRequest?.requestId,
    capability: input.envelope.capabilityRequest?.capability,
    adapterId: input.envelope.adapterManifest?.adapterId,
    summary: input.summary,
    redactedDetails: {
      validationStatus: input.intake.status,
      issueCodes: input.intake.error?.details?.issueCodes ?? [],
      sessionId: input.envelope.context?.sessionId,
      capabilityGrantDraftId: input.capabilityGrantDraft?.capabilityGrantDraftId,
      capabilityGrantDraftStatus: input.capabilityGrantDraft?.status,
      trustEvaluationDraftId: input.trustEvaluationDraft?.trustEvaluationDraftId,
      trustEvaluationDraftStatus: input.trustEvaluationDraft?.status,
      publicTrustMetadataEvaluationId: input.publicTrustMetadataEvaluation?.evaluationId,
      publicTrustMetadataEvaluationOutcome: input.publicTrustMetadataEvaluation?.outcome,
      publicTrustMetadataEvaluationProvidesTrustDecision:
        input.publicTrustMetadataEvaluation?.providesTrustDecision,
      possessionVerificationRequestDraftId:
        input.possessionVerificationRequestDraft?.possessionVerificationRequestDraftId,
      possessionVerificationRequestDraftStatus: input.possessionVerificationRequestDraft?.status,
      possessionVerificationMethod:
        input.possessionVerificationRequestDraft?.verificationMethod,
      webAuthnFixtureVerificationArtifactId:
        input.webAuthnFixtureVerificationArtifact?.artifactId,
      webAuthnFixtureVerificationOutcome:
        input.webAuthnFixtureVerificationArtifact?.outcome,
      webAuthnFixtureVerificationFixtureOnly:
        input.webAuthnFixtureVerificationArtifact?.fixtureOnly,
      possessionEvaluationResultId:
        input.possessionEvaluationResult?.possessionEvaluationResultId,
      possessionEvaluationOutcome: input.possessionEvaluationResult?.outcome,
      possessionEvaluationFixtureOnly: input.possessionEvaluationResult?.fixtureOnly,
      possessionEvaluationProvidesTrustDecision:
        input.possessionEvaluationResult?.providesTrustDecision,
      boundedTrustEvaluationResultId:
        input.boundedTrustEvaluationResult?.boundedTrustEvaluationResultId,
      boundedTrustEvaluationOutcome: input.boundedTrustEvaluationResult?.outcome,
      boundedTrustEvaluationEligibleForPolicyReview:
        input.boundedTrustEvaluationResult?.eligibleForPolicyReview,
      boundedTrustEvaluationProvidesTrustDecision:
        input.boundedTrustEvaluationResult?.providesTrustDecision,
      boundedTrustEvaluationWorldIdEnrollmentVerified:
        input.boundedTrustEvaluationResult?.worldIdEnrollmentVerified,
      boundedPolicyEvaluationResultId:
        input.boundedPolicyEvaluationResult?.boundedPolicyEvaluationResultId,
      boundedPolicyEvaluationOutcome: input.boundedPolicyEvaluationResult?.outcome,
      boundedPolicyEvaluationEligibleForUserApproval:
        input.boundedPolicyEvaluationResult?.eligibleForUserApproval,
      boundedPolicyEvaluationProvidesPolicyDecision:
        input.boundedPolicyEvaluationResult?.providesPolicyDecision,
      boundedPolicyEvaluationGrantsAuthority:
        input.boundedPolicyEvaluationResult?.grantsAuthority,
      userApprovalRequestDraftId:
        input.userApprovalRequestDraft?.userApprovalRequestDraftId,
      userApprovalRequestDraftStatus: input.userApprovalRequestDraft?.status,
      userApprovalRequestDraftCollectsUserDecision:
        input.userApprovalRequestDraft?.collectsUserDecision,
      userApprovalRequestDraftGrantsAuthority:
        input.userApprovalRequestDraft?.grantsAuthority,
      userDecisionFixtureArtifactId:
        input.userDecisionFixtureArtifact?.userDecisionFixtureArtifactId,
      userDecisionFixtureOutcome: input.userDecisionFixtureArtifact?.outcome,
      userDecisionFixtureSource: input.userDecisionFixtureArtifact?.source,
      userDecisionFixtureOnly: input.userDecisionFixtureArtifact?.fixtureOnly,
      userDecisionFixtureProductionUserConsentCollected:
        input.userDecisionFixtureArtifact?.productionUserConsentCollected,
      userDecisionFixtureGrantsAuthority:
        input.userDecisionFixtureArtifact?.grantsAuthority,
      userDecisionFixtureCreatesAuthorization:
        input.userDecisionFixtureArtifact?.createsAuthorization,
      capabilityActivationCandidateId:
        input.capabilityActivationCandidate?.capabilityActivationCandidateId,
      capabilityActivationCandidateStatus:
        input.capabilityActivationCandidate?.status,
      capabilityActivationCandidateFixtureOnlyUserDecision:
        input.capabilityActivationCandidate?.fixtureOnlyUserDecision,
      capabilityActivationCandidateProductionUserConsentCollected:
        input.capabilityActivationCandidate?.productionUserConsentCollected,
      capabilityActivationCandidateGrantsAuthority:
        input.capabilityActivationCandidate?.grantsAuthority,
      capabilityActivationCandidateActiveCapabilityCreated:
        input.capabilityActivationCandidate?.activeCapabilityCreated,
      productionAuthenticationVerificationId:
        input.productionAuthenticationVerification?.verificationId,
      productionAuthenticationVerificationStatus:
        input.productionAuthenticationVerification?.status,
      productionAuthenticationVerificationOutcome:
        input.productionAuthenticationVerification?.outcome,
      productionAuthenticationVerificationLifecycleEligibilityCreated:
        input.productionAuthenticationVerification?.lifecycleEligibility !== undefined,
      productionAuthenticationVerificationAuthenticatesRuntime:
        input.productionAuthenticationVerification?.authenticatesRuntime,
      productionAuthenticationVerificationProductionAuthenticationPerformed:
        input.productionAuthenticationVerification?.productionAuthenticationPerformed,
      productionAuthenticationVerificationBrowserCredentialPrompted:
        input.productionAuthenticationVerification?.browserCredentialPrompted,
      productionAuthenticationVerificationVaultUnlocked:
        input.productionAuthenticationVerification?.vaultUnlocked,
      productionAuthenticationVerificationCounterPersisted:
        input.productionAuthenticationVerification?.counterPersisted,
      productionAuthenticationVerificationGrantsCapability:
        input.productionAuthenticationVerification?.grantsCapability,
      productionAuthenticationVerificationCreatesAuthorizationPackage:
        input.productionAuthenticationVerification?.createsAuthorizationPackage,
      productionAuthenticationVerificationPerformsTrustDecision:
        input.productionAuthenticationVerification?.performsTrustDecision,
      productionAuthenticationVerificationPerformsPolicyDecision:
        input.productionAuthenticationVerification?.performsPolicyDecision,
      productionAuthenticationVerificationExecutesAdapter:
        input.productionAuthenticationVerification?.executesAdapter,
      productionAuthenticationVerificationPersisted:
        input.productionAuthenticationVerification?.persisted,
      lifecycleTransitionCandidateId:
        input.lifecycleTransitionCandidate?.lifecycleTransitionCandidateId,
      lifecycleTransitionCandidateOutcome:
        input.lifecycleTransitionCandidate?.outcome,
      lifecycleTransitionCandidateTargetState:
        input.lifecycleTransitionCandidate?.targetState,
      lifecycleTransitionCandidateDeviceVaultUnlocked:
        input.lifecycleTransitionCandidate?.deviceVaultUnlocked,
      lifecycleTransitionCandidateActiveCapabilityCreated:
        input.lifecycleTransitionCandidate?.activeCapabilityCreated,
      lifecycleTransitionCandidateAuthorizationCreated:
        input.lifecycleTransitionCandidate?.authorizationCreated,
      productionVerifiedPartialUnlockNextState:
        input.productionVerifiedPartialUnlock?.transitionResult.nextState,
      productionVerifiedPartialUnlockDeviceVaultUnlocked:
        input.productionVerifiedPartialUnlock?.deviceVaultUnlocked,
      productionVerifiedPartialUnlockProtectedIdentityStateAvailable:
        input.productionVerifiedPartialUnlock?.protectedIdentityStateAvailable,
      productionVerifiedPartialUnlockActiveCapabilitiesAvailable:
        input.productionVerifiedPartialUnlock?.activeCapabilitiesAvailable,
      productionVerifiedPartialUnlockSessionKeysCreated:
        input.productionVerifiedPartialUnlock?.sessionKeysCreated,
      productionVerifiedPartialUnlockAuthorizationCreated:
        input.productionVerifiedPartialUnlock?.authorizationCreated,
      deviceVaultUnlockResultId:
        input.deviceVaultUnlockResult?.vaultUnlockResultId,
      deviceVaultUnlockOutcome:
        input.deviceVaultUnlockResult?.outcome,
      deviceVaultUnlocked:
        input.deviceVaultUnlockResult?.deviceVaultUnlocked
        ?? input.verifiedVaultSessionUnlock?.deviceVaultUnlocked,
      protectedStateAvailable:
        input.deviceVaultUnlockResult?.protectedStateAvailable
        ?? input.verifiedVaultSessionUnlock?.protectedStateAvailable,
      deviceVaultUnlockPhilSecretExposed:
        input.deviceVaultUnlockResult?.philSecretExposed
        ?? input.verifiedVaultSessionUnlock?.philSecretExposed,
      deviceVaultUnlockRawVaultKeyExposed:
        input.deviceVaultUnlockResult?.rawVaultKeyExposed
        ?? input.verifiedVaultSessionUnlock?.rawVaultKeyExposed,
      deviceVaultUnlockApplicationCredentialsLoaded:
        input.deviceVaultUnlockResult?.applicationCredentialsLoaded
        ?? input.verifiedVaultSessionUnlock?.applicationCredentialsLoaded,
      deviceVaultUnlockActiveCapabilityCreated:
        input.deviceVaultUnlockResult?.activeCapabilityCreated
        ?? input.verifiedVaultSessionUnlock?.activeCapabilityCreated,
      deviceVaultUnlockSessionKeyCreated:
        input.deviceVaultUnlockResult?.sessionKeyCreated
        ?? input.verifiedVaultSessionUnlock?.sessionKeyCreated,
      deviceVaultUnlockAuthorizationCreated:
        input.deviceVaultUnlockResult?.authorizationCreated
        ?? input.verifiedVaultSessionUnlock?.authorizationCreated,
      deviceVaultUnlockPersistedRuntimeState:
        input.deviceVaultUnlockResult?.persistedRuntimeState
        ?? input.verifiedVaultSessionUnlock?.persistedRuntimeState,
      deviceVaultUnlockHandleId:
        input.deviceVaultUnlockResult?.unlockedVaultHandle?.handleId
        ?? input.verifiedVaultSessionUnlock?.vaultUnlockResult.unlockedVaultHandle?.handleId,
      verifiedVaultSessionUnlockNextState:
        input.verifiedVaultSessionUnlock?.transitionResult.nextState,
      protectedStateViewId:
        input.protectedStateView?.protectedStateViewId,
      protectedStateViewType:
        input.protectedStateView?.viewType,
      protectedStateViewOutcome:
        input.protectedStateView?.outcome,
      protectedStateViewContainsSecrets:
        input.protectedStateView?.containsSecrets,
      protectedStateViewContainsCredentials:
        input.protectedStateView?.containsCredentials,
      protectedStateViewContainsPrivateKeys:
        input.protectedStateView?.containsPrivateKeys,
      protectedStateViewContainsAuthorization:
        input.protectedStateView?.containsAuthorization,
      protectedStateViewContainsSessionKeys:
        input.protectedStateView?.containsSessionKeys,
      protectedStateViewActiveCapabilityCreated:
        input.protectedStateView?.activeCapabilityCreated,
      protectedStateViewSessionKeyCreated:
        input.protectedStateView?.sessionKeyCreated,
      protectedStateViewAuthorizationCreated:
        input.protectedStateView?.authorizationCreated,
      publicCredentialDirectoryResultId:
        input.publicCredentialDirectory?.publicCredentialDirectoryResultId,
      publicCredentialDirectoryOperation:
        input.publicCredentialDirectory?.operation,
      publicCredentialDirectoryDescriptorCount:
        input.publicCredentialDirectory?.descriptors.length,
      publicCredentialDirectoryContainsPrivateMaterial:
        input.publicCredentialDirectory?.containsPrivateMaterial,
      publicCredentialDirectoryContainsRawAssertionData:
        input.publicCredentialDirectory?.containsRawAssertionData,
      publicCredentialDirectoryContainsVaultKeys:
        input.publicCredentialDirectory?.containsVaultKeys,
      publicCredentialDirectoryContainsPhilSecret:
        input.publicCredentialDirectory?.containsPhilSecret,
      publicCredentialDirectoryProvidesTrustDecision:
        input.publicCredentialDirectory?.providesTrustDecision,
      publicCredentialDirectoryGrantsAuthority:
        input.publicCredentialDirectory?.grantsAuthority,
      selectedCredentialPublicMaterialResultId:
        input.selectedCredentialPublicMaterial?.selectedCredentialPublicMaterialResultId,
      selectedCredentialPublicMaterialOutcome:
        input.selectedCredentialPublicMaterial?.outcome,
      selectedCredentialPublicMaterialCredentialSafeReference:
        input.selectedCredentialPublicMaterial?.summary.credentialSafeReference,
      selectedCredentialPublicMaterialProviderKind:
        input.selectedCredentialPublicMaterial?.summary.providerKind,
      selectedCredentialPublicMaterialLifecycleStatus:
        input.selectedCredentialPublicMaterial?.summary.lifecycleStatus,
      selectedCredentialPublicMaterialVerificationHandleCreated:
        input.selectedCredentialPublicMaterial?.summary.verificationHandleCreated,
      selectedCredentialPublicMaterialContainsPrivateMaterial:
        input.selectedCredentialPublicMaterial?.containsPrivateMaterial,
      selectedCredentialPublicMaterialContainsVaultKey:
        input.selectedCredentialPublicMaterial?.containsVaultKey,
      selectedCredentialPublicMaterialContainsPhilSecret:
        input.selectedCredentialPublicMaterial?.containsPhilSecret,
      selectedCredentialPublicMaterialContainsRawAssertionPayload:
        input.selectedCredentialPublicMaterial?.containsRawAssertionPayload,
      selectedCredentialPublicMaterialContainsRawRegistrationPayload:
        input.selectedCredentialPublicMaterial?.containsRawRegistrationPayload,
      selectedCredentialPublicMaterialVerificationPerformed:
        input.selectedCredentialPublicMaterial?.verificationPerformed,
      selectedCredentialPublicMaterialTrustDecisionCreated:
        input.selectedCredentialPublicMaterial?.trustDecisionCreated,
      selectedCredentialPublicMaterialGrantsAuthority:
        input.selectedCredentialPublicMaterial?.grantsAuthority,
      trustManagerVerificationInputId:
        input.trustManagerVerificationInput?.verificationInput.trustManagerVerificationInputId,
      trustManagerVerificationInputOutcome:
        input.trustManagerVerificationInput?.outcome,
      trustManagerVerificationInputCredentialSafeReference:
        input.trustManagerVerificationInput?.verificationInput.credentialSafeReference,
      trustManagerVerificationInputAuthenticationPurpose:
        input.trustManagerVerificationInput?.verificationInput.authenticationPurpose,
      trustManagerVerificationInputChallengeReferenceId:
        input.trustManagerVerificationInput?.verificationInput.challengeBinding.challengeReferenceId,
      trustManagerVerificationInputVerificationPerformed:
        input.trustManagerVerificationInput?.verificationPerformed,
      trustManagerVerificationInputTrustDecisionCreated:
        input.trustManagerVerificationInput?.trustDecisionCreated,
      trustManagerVerificationInputAuthenticationPerformed:
        input.trustManagerVerificationInput?.authenticationPerformed,
      trustManagerVerificationInputVaultHandleExposed:
        input.trustManagerVerificationInput?.vaultHandleExposed,
      trustManagerVerificationInputRegistryAccessProvided:
        input.trustManagerVerificationInput?.registryAccessProvided,
      trustManagerVerificationInputPrivateMaterialIncluded:
        input.trustManagerVerificationInput?.privateMaterialIncluded,
      trustManagerVerificationInputGrantsAuthority:
        input.trustManagerVerificationInput?.grantsAuthority,
      trustManagerProductionVerificationResultId:
        input.trustManagerProductionVerification?.trustManagerProductionVerificationResultId,
      trustManagerProductionVerificationOutcome:
        input.trustManagerProductionVerification?.outcome,
      trustManagerProductionVerificationCounterStatus:
        input.trustManagerProductionVerification?.counterAssessment.counterStatus,
      trustManagerProductionVerificationSignatureVerified:
        input.trustManagerProductionVerification?.signatureVerified,
      trustManagerProductionVerificationChallengeVerified:
        input.trustManagerProductionVerification?.challengeBindingVerified,
      trustManagerProductionVerificationOriginVerified:
        input.trustManagerProductionVerification?.originVerified,
      trustManagerProductionVerificationRpIdHashVerified:
        input.trustManagerProductionVerification?.rpIdHashVerified,
      trustManagerProductionVerificationTrustDecisionCreated:
        input.trustManagerProductionVerification?.trustDecisionCreated,
      trustManagerProductionVerificationCapabilityGranted:
        input.trustManagerProductionVerification?.capabilityGranted,
      trustManagerProductionVerificationAuthorizationCreated:
        input.trustManagerProductionVerification?.authorizationCreated,
      trustManagerProductionVerificationDeviceVaultAccessed:
        input.trustManagerProductionVerification?.deviceVaultAccessed,
      trustManagerProductionVerificationCounterPersisted:
        input.trustManagerProductionVerification?.counterPersisted,
      boundedTrustDecisionCandidateId:
        input.boundedTrustDecisionCandidate?.boundedTrustDecisionCandidateId,
      boundedTrustDecisionCandidateOutcome:
        input.boundedTrustDecisionCandidate?.outcome,
      boundedTrustDecisionCandidateCredentialLifecycleStatus:
        input.boundedTrustDecisionCandidate?.lifecycleAssessment.credentialLifecycleStatus,
      boundedTrustDecisionCandidateRequiresCounterPersistence:
        input.boundedTrustDecisionCandidate?.requiresCounterPersistence,
      boundedTrustDecisionCandidateRequiresWorldIdEnrollment:
        input.boundedTrustDecisionCandidate?.requiresWorldIdEnrollment,
      boundedTrustDecisionCandidateEligibleForAuthoritativeTrustDecision:
        input.boundedTrustDecisionCandidate?.eligibleForAuthoritativeTrustDecision,
      boundedTrustDecisionCandidateActiveTrustDecisionCreated:
        input.boundedTrustDecisionCandidate?.activeTrustDecisionCreated,
      boundedTrustDecisionCandidateCapabilityGranted:
        input.boundedTrustDecisionCandidate?.capabilityGranted,
      boundedTrustDecisionCandidateAuthorizationCreated:
        input.boundedTrustDecisionCandidate?.authorizationCreated,
      boundedTrustDecisionCandidateVaultAccessGranted:
        input.boundedTrustDecisionCandidate?.vaultAccessGranted,
      boundedTrustDecisionCandidatePersisted:
        input.boundedTrustDecisionCandidate?.persisted,
      credentialCounterPersistenceReceiptId:
        input.credentialCounterPersistenceReceipt?.credentialCounterPersistenceReceiptId,
      credentialCounterPersistenceOutcome:
        input.credentialCounterPersistenceReceipt?.outcome,
      credentialCounterPersistencePreviousStoredCounter:
        input.credentialCounterPersistenceReceipt?.mutationSummary.previousStoredCounter,
      credentialCounterPersistencePersistedCounter:
        input.credentialCounterPersistenceReceipt?.mutationSummary.persistedCounter,
      credentialCounterPersistenceOnlyCounterFieldChanged:
        input.credentialCounterPersistenceReceipt?.mutationSummary.onlyCounterFieldChanged,
      credentialCounterPersistenceCounterPersisted:
        input.credentialCounterPersistenceReceipt?.counterPersisted,
      credentialCounterPersistenceTrustDecisionCreated:
        input.credentialCounterPersistenceReceipt?.trustDecisionCreated,
      credentialCounterPersistenceCapabilityGranted:
        input.credentialCounterPersistenceReceipt?.capabilityGranted,
      credentialCounterPersistenceAuthorizationCreated:
        input.credentialCounterPersistenceReceipt?.authorizationCreated,
      credentialCounterPersistenceRegistryPlaintextExposed:
        input.credentialCounterPersistenceReceipt?.registryPlaintextExposed,
      trustDecisionCandidateCounterResolutionId:
        input.trustDecisionCandidateCounterResolution?.resolutionId,
      trustDecisionCandidateCounterRequirementSatisfied:
        input.trustDecisionCandidateCounterResolution?.counterRequirementSatisfied,
      trustDecisionCandidateCounterResolutionActiveTrustDecisionCreated:
        input.trustDecisionCandidateCounterResolution?.activeTrustDecisionCreated,
      authoritativeTrustDecisionId:
        input.authoritativeTrustDecision?.authoritativeTrustDecisionId,
      authoritativeTrustDecisionOutcome:
        input.authoritativeTrustDecision?.outcome,
      authoritativeTrustDecisionCredentialSafeReference:
        input.authoritativeTrustDecision?.scope.credentialSafeReference,
      authoritativeTrustDecisionPurpose:
        input.authoritativeTrustDecision?.scope.authenticationPurpose,
      authoritativeTrustDecisionSessionId:
        input.authoritativeTrustDecision?.scope.sessionId,
      authoritativeTrustDecisionExpiresAt:
        input.authoritativeTrustDecision?.validity.expiresAt,
      authoritativeTrustDecisionTrustDecisionCreated:
        input.authoritativeTrustDecision?.trustDecisionCreated,
      authoritativeTrustDecisionCapabilityGranted:
        input.authoritativeTrustDecision?.capabilityGranted,
      authoritativeTrustDecisionPolicyApproved:
        input.authoritativeTrustDecision?.policyApproved,
      authoritativeTrustDecisionUserApprovalCollected:
        input.authoritativeTrustDecision?.userApprovalCollected,
      authoritativeTrustDecisionAuthorizationCreated:
        input.authoritativeTrustDecision?.authorizationCreated,
      authoritativeTrustDecisionExecutionAllowed:
        input.authoritativeTrustDecision?.executionAllowed,
      authoritativeTrustDecisionWorldIdVerified:
        input.authoritativeTrustDecision?.worldIdVerified,
      authoritativeTrustDecisionPersistedAsAuthority:
        input.authoritativeTrustDecision?.persistedAsAuthority,
      authoritativePolicyDecisionId:
        input.authoritativePolicyDecision?.authoritativePolicyDecisionId,
      authoritativePolicyDecisionOutcome:
        input.authoritativePolicyDecision?.outcome,
      authoritativePolicyDecisionPolicySetId:
        input.authoritativePolicyDecision?.binding.policySetId,
      authoritativePolicyDecisionCapabilityName:
        input.authoritativePolicyDecision?.scope.capabilityName,
      authoritativePolicyDecisionActionType:
        input.authoritativePolicyDecision?.scope.actionType,
      authoritativePolicyDecisionTargetReference:
        input.authoritativePolicyDecision?.scope.targetReference,
      authoritativePolicyDecisionRequiresUserApproval:
        input.authoritativePolicyDecision?.requiresUserApproval,
      authoritativePolicyDecisionEligibleForCapabilityActivationReview:
        input.authoritativePolicyDecision?.eligibleForCapabilityActivationReview,
      authoritativePolicyDecisionCapabilityGranted:
        input.authoritativePolicyDecision?.capabilityGranted,
      authoritativePolicyDecisionUserApprovalCollected:
        input.authoritativePolicyDecision?.userApprovalCollected,
      authoritativePolicyDecisionAuthorizationCreated:
        input.authoritativePolicyDecision?.authorizationCreated,
      authoritativePolicyDecisionExecutionAllowed:
        input.authoritativePolicyDecision?.executionAllowed,
      authoritativePolicyDecisionProofExecuted:
        input.authoritativePolicyDecision?.proofExecuted,
      authoritativePolicyDecisionAdapterExecuted:
        input.authoritativePolicyDecision?.adapterExecuted,
      authoritativePolicyDecisionPersistedAsAuthority:
        input.authoritativePolicyDecision?.persistedAsAuthority,
      platformUserApprovalDecisionId:
        input.platformUserApprovalDecision?.platformUserApprovalDecisionId,
      platformUserApprovalDecisionOutcome:
        input.platformUserApprovalDecision?.outcome,
      platformUserApprovalDecisionSurface:
        input.platformUserApprovalDecision?.evidence.approvalSurface,
      platformUserApprovalDecisionUserApproved:
        input.platformUserApprovalDecision?.userApproved,
      platformUserApprovalDecisionUserDenied:
        input.platformUserApprovalDecision?.userDenied,
      platformUserApprovalDecisionUserCancelled:
        input.platformUserApprovalDecision?.userCancelled,
      platformUserApprovalDecisionApprovalExpired:
        input.platformUserApprovalDecision?.approvalExpired,
      platformUserApprovalDecisionPresentationDigestMatched:
        input.platformUserApprovalDecision?.presentationDigestMatched,
      platformUserApprovalDecisionEligibleForCapabilityActivationReview:
        input.platformUserApprovalDecision?.eligibleForCapabilityActivationReview,
      platformUserApprovalDecisionCapabilityGranted:
        input.platformUserApprovalDecision?.capabilityGranted,
      platformUserApprovalDecisionAuthorizationCreated:
        input.platformUserApprovalDecision?.authorizationCreated,
      platformUserApprovalDecisionSessionKeyCreated:
        input.platformUserApprovalDecision?.sessionKeyCreated,
      platformUserApprovalDecisionExecutionAllowed:
        input.platformUserApprovalDecision?.executionAllowed,
      platformUserApprovalDecisionProofExecuted:
        input.platformUserApprovalDecision?.proofExecuted,
      platformUserApprovalDecisionAdapterExecuted:
        input.platformUserApprovalDecision?.adapterExecuted,
      platformUserApprovalDecisionTransactionSubmitted:
        input.platformUserApprovalDecision?.transactionSubmitted,
      platformUserApprovalDecisionBiometricTemplateStored:
        input.platformUserApprovalDecision?.biometricTemplateStored,
      platformUserApprovalDecisionRawPlatformSecretIncluded:
        input.platformUserApprovalDecision?.rawPlatformSecretIncluded,
      platformUserApprovalDecisionPersistedAsAuthority:
        input.platformUserApprovalDecision?.persistedAsAuthority,
      authoritativeCapabilityGrantId:
        input.authoritativeCapabilityGrant?.authoritativeCapabilityGrantId,
      authoritativeCapabilityGrantStatus:
        input.authoritativeCapabilityGrant?.status,
      authoritativeCapabilityGrantCapability:
        input.authoritativeCapabilityGrant?.scope.capabilityName,
      authoritativeCapabilityGrantSessionId:
        input.authoritativeCapabilityGrant?.binding.sessionId,
      authoritativeCapabilityGrantApplicationId:
        input.authoritativeCapabilityGrant?.binding.applicationId,
      authoritativeCapabilityGrantExpiresAt:
        input.authoritativeCapabilityGrant?.validity.expiresAt,
      authoritativeCapabilityGrantActiveCapabilityCreated:
        input.authoritativeCapabilityGrant?.activeCapabilityCreated,
      authoritativeCapabilityGrantActionAuthorized:
        input.authoritativeCapabilityGrant?.actionAuthorized,
      authoritativeCapabilityGrantAuthorizationCreated:
        input.authoritativeCapabilityGrant?.authorizationCreated,
      authoritativeCapabilityGrantAuthorizationPackageCreated:
        input.authoritativeCapabilityGrant?.authorizationPackageCreated,
      authoritativeCapabilityGrantSessionKeyCreated:
        input.authoritativeCapabilityGrant?.sessionKeyCreated,
      authoritativeCapabilityGrantExecutionAllowed:
        input.authoritativeCapabilityGrant?.executionAllowed,
      authoritativeCapabilityGrantProofExecuted:
        input.authoritativeCapabilityGrant?.proofExecuted,
      authoritativeCapabilityGrantAdapterExecuted:
        input.authoritativeCapabilityGrant?.adapterExecuted,
      authoritativeCapabilityGrantTransactionSubmitted:
        input.authoritativeCapabilityGrant?.transactionSubmitted,
      authoritativeCapabilityGrantVaultAccessed:
        input.authoritativeCapabilityGrant?.vaultAccessed,
      authoritativeCapabilityGrantWorldIdVerified:
        input.authoritativeCapabilityGrant?.worldIdVerified,
      authoritativeCapabilityGrantPersistedAsAuthority:
        input.authoritativeCapabilityGrant?.persistedAsAuthority,
      userSessionCapabilityMutationStatus:
        input.userSessionCapabilityMutationResult?.status,
      userSessionCapabilityMutationActiveCapabilityCreated:
        input.userSessionCapabilityMutationResult?.activeCapabilityCreated,
      userSessionCapabilityMutationAuthorizationCreated:
        input.userSessionCapabilityMutationResult?.authorizationCreated,
      userSessionCapabilityMutationSessionKeyCreated:
        input.userSessionCapabilityMutationResult?.sessionKeyCreated,
      userSessionCapabilityMutationExecutionAllowed:
        input.userSessionCapabilityMutationResult?.executionAllowed,
      userSessionCapabilityMutationPersisted:
        input.userSessionCapabilityMutationResult?.persisted,
      activeCapabilityGrantInspectionCount:
        input.activeCapabilityGrantInspection?.count,
      activeCapabilityGrantInspectionAuthorizationCreated:
        input.activeCapabilityGrantInspection?.authorizationCreated,
      activeCapabilityGrantInspectionExecutionAllowed:
        input.activeCapabilityGrantInspection?.executionAllowed,
      activeCapabilityGrantInspectionPersisted:
        input.activeCapabilityGrantInspection?.persisted,
      authorizationDecisionCandidateId:
        input.authorizationDecisionCandidate?.authorizationDecisionCandidateId,
      authorizationDecisionCandidateOutcome:
        input.authorizationDecisionCandidate?.outcome,
      authorizationDecisionCandidateActionType:
        input.authorizationDecisionCandidate?.actionSummary.actionType,
      authorizationDecisionCandidateRequiredCapability:
        input.authorizationDecisionCandidate?.actionSummary.requiredCapability,
      authorizationDecisionCandidateTarget:
        input.authorizationDecisionCandidate?.actionSummary.target,
      authorizationDecisionCandidateMethod:
        input.authorizationDecisionCandidate?.actionSummary.method,
      authorizationDecisionCandidateValue:
        input.authorizationDecisionCandidate?.actionSummary.value,
      authorizationDecisionCandidateActionDigestPreview:
        input.authorizationDecisionCandidate?.evidence.actionDigestPreview.digestPreview,
      authorizationDecisionCandidateProofRequirement:
        input.authorizationDecisionCandidate?.proofRequirement,
      authorizationDecisionCandidatePackageCreated:
        input.authorizationDecisionCandidate?.authorizationPackageCreated,
      authorizationDecisionCandidateActionAuthorized:
        input.authorizationDecisionCandidate?.actionAuthorized,
      authorizationDecisionCandidateProofInputHashCreated:
        input.authorizationDecisionCandidate?.proofInputHashCreated,
      authorizationDecisionCandidateProofExecuted:
        input.authorizationDecisionCandidate?.proofExecuted,
      authorizationDecisionCandidateSignatureCreated:
        input.authorizationDecisionCandidate?.signatureCreated,
      authorizationDecisionCandidateSessionKeyCreated:
        input.authorizationDecisionCandidate?.sessionKeyCreated,
      authorizationDecisionCandidateAdapterExecutionAllowed:
        input.authorizationDecisionCandidate?.adapterExecutionAllowed,
      authorizationDecisionCandidateTransactionSubmitted:
        input.authorizationDecisionCandidate?.transactionSubmitted,
      authorizationDecisionCandidateVaultAccessed:
        input.authorizationDecisionCandidate?.vaultAccessed,
      authorizationDecisionCandidatePersistedAsAuthority:
        input.authorizationDecisionCandidate?.persistedAsAuthority,
      authorizationPackageDraftId:
        input.authorizationPackageDraft?.authorizationPackageDraftId,
      authorizationPackageDraftActionHash:
        input.authorizationPackageDraft?.hashSummary.actionHash,
      authorizationPackageDraftPolicyHash:
        input.authorizationPackageDraft?.hashSummary.policyHash,
      authorizationPackageDraftConsumerDataHash:
        input.authorizationPackageDraft?.hashSummary.consumerDataHash,
      authorizationPackageDraftProofInputHash:
        input.authorizationPackageDraft?.hashSummary.proofInputHash,
      authorizationPackageDraftProofType:
        input.authorizationPackageDraft?.actionUnlockPublicInputDraft.proofType,
      authorizationPackageDraftFactShapeReference:
        input.authorizationPackageDraft?.actionUnlockPublicInputDraft.factShapeReference,
      authorizationPackageDraftCreated:
        input.authorizationPackageDraft?.authorizationPackageDraftCreated,
      authorizationPackageDraftExecutable:
        input.authorizationPackageDraft?.authorizationPackageExecutable,
      authorizationPackageDraftActionAuthorized:
        input.authorizationPackageDraft?.actionAuthorized,
      authorizationPackageDraftProofGenerated:
        input.authorizationPackageDraft?.proofGenerated,
      authorizationPackageDraftProofVerified:
        input.authorizationPackageDraft?.proofVerified,
      authorizationPackageDraftVerifiedFactAvailable:
        input.authorizationPackageDraft?.verifiedFactAvailable,
      authorizationPackageDraftNullifierConsumed:
        input.authorizationPackageDraft?.nullifierConsumed,
      authorizationPackageDraftAdapterExecutionAllowed:
        input.authorizationPackageDraft?.adapterExecutionAllowed,
      authorizationPackageDraftTransactionSubmitted:
        input.authorizationPackageDraft?.transactionSubmitted,
      actionUnlockProofGenerationArtifactId:
        input.actionUnlockProofGenerationArtifact?.proofGenerationArtifactId,
      actionUnlockProofGenerationProofType:
        input.actionUnlockProofGenerationArtifact?.proofType,
      actionUnlockProofGenerationProofInputHash:
        input.actionUnlockProofGenerationArtifact?.proofInputHash,
      actionUnlockProofGenerationProofDigest:
        input.actionUnlockProofGenerationArtifact?.proofArtifact.proofDigest,
      actionUnlockProofGenerationProofByteLength:
        input.actionUnlockProofGenerationArtifact?.proofArtifact.proofByteLength,
      actionUnlockProofGenerationPublicInputsMatched:
        input.actionUnlockProofGenerationArtifact?.summary.publicInputsMatched,
      actionUnlockProofGenerationProofInputHashMatched:
        input.actionUnlockProofGenerationArtifact?.summary.proofInputHashMatched,
      actionUnlockProofGenerationWitnessMaterialExposed:
        input.actionUnlockProofGenerationArtifact?.witnessMaterialExposed,
      actionUnlockProofGenerationProofVerifiedByRuntime:
        input.actionUnlockProofGenerationArtifact?.proofVerifiedByRuntime,
      actionUnlockProofGenerationVerifiedFactPublished:
        input.actionUnlockProofGenerationArtifact?.verifiedFactPublished,
      actionUnlockProofGenerationNullifierConsumed:
        input.actionUnlockProofGenerationArtifact?.nullifierConsumed,
      actionUnlockProofGenerationPackageFinalized:
        input.actionUnlockProofGenerationArtifact?.authorizationPackageFinalized,
      actionUnlockProofGenerationAdapterExecutionAllowed:
        input.actionUnlockProofGenerationArtifact?.adapterExecutionAllowed,
      actionUnlockProofGenerationTransactionSubmitted:
        input.actionUnlockProofGenerationArtifact?.transactionSubmitted,
      actionUnlockProofVerificationResultId:
        input.actionUnlockProofVerification?.proofVerificationResultId,
      actionUnlockProofVerificationProofVerifiedLocally:
        input.actionUnlockProofVerification?.proofVerifiedLocally,
      actionUnlockProofVerificationProofInputHash:
        input.actionUnlockProofVerification?.proofInputHash,
      actionUnlockProofVerificationProofDigest:
        input.actionUnlockProofVerification?.verifiedProofReference.proofDigest,
      actionUnlockProofVerificationFactShapeReference:
        input.actionUnlockProofVerification?.factShapePreview.factShapeReference,
      actionUnlockProofVerificationFactHigh:
        input.actionUnlockProofVerification?.factShapePreview.factHigh,
      actionUnlockProofVerificationFactLow:
        input.actionUnlockProofVerification?.factShapePreview.factLow,
      actionUnlockProofVerificationVerifiedFactPublished:
        input.actionUnlockProofVerification?.verifiedFactPublished,
      actionUnlockProofVerificationOnChainVerificationPerformed:
        input.actionUnlockProofVerification?.onChainVerificationPerformed,
      actionUnlockProofVerificationNullifierConsumed:
        input.actionUnlockProofVerification?.nullifierConsumed,
      actionUnlockProofVerificationAdapterExecutionAllowed:
        input.actionUnlockProofVerification?.adapterExecutionAllowed,
      actionUnlockProofVerificationTransactionSubmitted:
        input.actionUnlockProofVerification?.transactionSubmitted,
      actionUnlockProofVerificationProofBytesExposedToAudit:
        input.actionUnlockProofVerification?.proofBytesExposedToAudit,
      finalizedAuthorizationPackageId:
        input.finalizedAuthorizationPackage?.finalizedAuthorizationPackageId,
      finalizedAuthorizationPackageProofInputHash:
        input.finalizedAuthorizationPackage?.actionUnlockAuthorization.proofInputHash,
      finalizedAuthorizationPackageProofDigest:
        input.finalizedAuthorizationPackage?.proofArtifact.proofDigest,
      finalizedAuthorizationPackageFactShapeReference:
        input.finalizedAuthorizationPackage?.factShapePreview.factShapeReference,
      finalizedAuthorizationPackageFinalized:
        input.finalizedAuthorizationPackage?.authorizationPackageFinalized,
      finalizedAuthorizationPackageVerifiedFactPublished:
        input.finalizedAuthorizationPackage?.verifiedFactPublished,
      finalizedAuthorizationPackageOnChainVerificationPerformed:
        input.finalizedAuthorizationPackage?.onChainVerificationPerformed,
      finalizedAuthorizationPackageNullifierConsumed:
        input.finalizedAuthorizationPackage?.nullifierConsumed,
      finalizedAuthorizationPackageAdapterExecutionAllowed:
        input.finalizedAuthorizationPackage?.adapterExecutionAllowed,
      finalizedAuthorizationPackageContractExecutionAllowed:
        input.finalizedAuthorizationPackage?.contractExecutionAllowed,
      finalizedAuthorizationPackageTransactionSubmitted:
        input.finalizedAuthorizationPackage?.transactionSubmitted,
      finalizedAuthorizationPackageExecutableByApplications:
        input.finalizedAuthorizationPackage?.executableByApplications,
      verifiedFactPublicationRequestDraftId:
        input.verifiedFactPublicationRequestDraft?.verifiedFactPublicationRequestDraftId,
      verifiedFactPublicationRequestProofInputHash:
        input.verifiedFactPublicationRequestDraft?.binding.proofInputHash,
      verifiedFactPublicationRequestProofDigest:
        input.verifiedFactPublicationRequestDraft?.binding.proofDigest,
      verifiedFactPublicationRequestFactHigh:
        input.verifiedFactPublicationRequestDraft?.binding.factHigh,
      verifiedFactPublicationRequestFactLow:
        input.verifiedFactPublicationRequestDraft?.binding.factLow,
      verifiedFactPublicationRequestPublicNullifier:
        input.verifiedFactPublicationRequestDraft?.binding.nullifier,
      verifiedFactPublicationRequestChainId:
        input.verifiedFactPublicationRequestDraft?.target.chainProfile.chainId,
      verifiedFactPublicationRequestNetwork:
        input.verifiedFactPublicationRequestDraft?.target.chainProfile.network,
      verifiedFactPublicationRequestVerifierReference:
        input.verifiedFactPublicationRequestDraft?.target.verifier.verifierReference,
      verifiedFactPublicationRequestRegistryReference:
        input.verifiedFactPublicationRequestDraft?.target.registry.registryReference,
      verifiedFactPublicationRequestConsumerReference:
        input.verifiedFactPublicationRequestDraft?.target.consumer.consumerReference,
      verifiedFactPublicationRequestFactPublished:
        input.verifiedFactPublicationRequestDraft?.factPublished,
      verifiedFactPublicationRequestNullifierConsumed:
        input.verifiedFactPublicationRequestDraft?.nullifierConsumed,
      verifiedFactPublicationRequestContractCalled:
        input.verifiedFactPublicationRequestDraft?.contractCalled,
      verifiedFactPublicationRequestUserOperationCreated:
        input.verifiedFactPublicationRequestDraft?.userOperationCreated,
      verifiedFactPublicationRequestTransactionSubmitted:
        input.verifiedFactPublicationRequestDraft?.transactionSubmitted,
      verifiedFactPublicationRequestAdapterExecuted:
        input.verifiedFactPublicationRequestDraft?.adapterExecuted,
      authorizationExecutionReadinessResultId:
        input.authorizationExecutionReadiness?.authorizationExecutionReadinessResultId,
      authorizationExecutionReadinessOutcome:
        input.authorizationExecutionReadiness?.outcome,
      authorizationExecutionReadinessFactState:
        input.authorizationExecutionReadiness?.summary.factState,
      authorizationExecutionReadinessNullifierState:
        input.authorizationExecutionReadiness?.summary.nullifierState,
      authorizationExecutionReadinessRaceConditionWarning:
        input.authorizationExecutionReadiness?.summary.raceConditionWarning,
      authorizationExecutionReadinessRevalidationRequired:
        input.authorizationExecutionReadiness?.summary.revalidationRequiredBeforeTransaction,
      authorizationExecutionReadinessFactPublished:
        input.authorizationExecutionReadiness?.factPublished,
      authorizationExecutionReadinessNullifierConsumed:
        input.authorizationExecutionReadiness?.nullifierConsumed,
      authorizationExecutionReadinessContractCalled:
        input.authorizationExecutionReadiness?.contractCalled,
      authorizationExecutionReadinessUserOperationCreated:
        input.authorizationExecutionReadiness?.userOperationCreated,
      authorizationExecutionReadinessTransactionSigned:
        input.authorizationExecutionReadiness?.transactionSigned,
      authorizationExecutionReadinessTransactionSubmitted:
        input.authorizationExecutionReadiness?.transactionSubmitted,
      authorizationExecutionReadinessAdapterExecuted:
        input.authorizationExecutionReadiness?.adapterExecuted,
      authorizationExecutionReadinessChainStateMutated:
        input.authorizationExecutionReadiness?.chainStateMutated,
      requestMetadata: input.envelope.context?.metadata,
      persisted: false
    }
  });

  const auditDraftCollectionResult = input.auditDraftCollector?.addDraft(auditEventDraft);

  return {
    status: input.intake.status,
    value: {
      intake: input.intake,
      capabilityGrantDraft: input.capabilityGrantDraft,
      capabilityGrantDraftCollectionResult: input.capabilityGrantDraftCollectionResult,
      trustEvaluationDraft: input.trustEvaluationDraft,
      trustEvaluationDraftCollectionResult: input.trustEvaluationDraftCollectionResult,
      publicTrustMetadataEvaluation: input.publicTrustMetadataEvaluation,
      publicTrustMetadataEvaluationCollectionResult:
        input.publicTrustMetadataEvaluationCollectionResult,
      possessionVerificationRequestDraft: input.possessionVerificationRequestDraft,
      webAuthnFixtureVerificationArtifact: input.webAuthnFixtureVerificationArtifact,
      possessionEvaluationResult: input.possessionEvaluationResult,
      possessionEvaluationCollectionResult: input.possessionEvaluationCollectionResult,
      boundedTrustEvaluationResult: input.boundedTrustEvaluationResult,
      boundedTrustEvaluationCollectionResult: input.boundedTrustEvaluationCollectionResult,
      boundedPolicyEvaluationResult: input.boundedPolicyEvaluationResult,
      boundedPolicyEvaluationCollectionResult: input.boundedPolicyEvaluationCollectionResult,
      userApprovalRequestDraft: input.userApprovalRequestDraft,
      userApprovalRequestDraftCollectionResult: input.userApprovalRequestDraftCollectionResult,
      userDecisionFixtureArtifact: input.userDecisionFixtureArtifact,
      userDecisionFixtureArtifactCollectionResult:
        input.userDecisionFixtureArtifactCollectionResult,
      capabilityActivationCandidate: input.capabilityActivationCandidate,
      capabilityActivationCandidateCollectionResult:
        input.capabilityActivationCandidateCollectionResult,
      productionAuthenticationVerification: input.productionAuthenticationVerification,
      productionAuthenticationVerificationCollectionResult:
        input.productionAuthenticationVerificationCollectionResult,
      lifecycleTransitionCandidate: input.lifecycleTransitionCandidate,
      productionVerifiedPartialUnlock: input.productionVerifiedPartialUnlock,
      deviceVaultUnlockResult: input.deviceVaultUnlockResult,
      verifiedVaultSessionUnlock: input.verifiedVaultSessionUnlock,
      protectedStateView: input.protectedStateView,
      protectedStateViewCollectionResult: input.protectedStateViewCollectionResult,
      publicCredentialDirectory: input.publicCredentialDirectory,
      selectedCredentialPublicMaterial: input.selectedCredentialPublicMaterial,
      trustManagerVerificationInput: input.trustManagerVerificationInput,
      trustManagerProductionVerification: input.trustManagerProductionVerification,
      trustManagerProductionVerificationCollectionResult:
        input.trustManagerProductionVerificationCollectionResult,
      boundedTrustDecisionCandidate: input.boundedTrustDecisionCandidate,
      boundedTrustDecisionCandidateCollectionResult:
        input.boundedTrustDecisionCandidateCollectionResult,
      credentialCounterPersistenceReceipt: input.credentialCounterPersistenceReceipt,
      trustDecisionCandidateCounterResolution:
        input.trustDecisionCandidateCounterResolution,
      authoritativeTrustDecision: input.authoritativeTrustDecision,
      authoritativeTrustDecisionCollectionResult:
        input.authoritativeTrustDecisionCollectionResult,
      authoritativePolicyDecision: input.authoritativePolicyDecision,
      authoritativePolicyDecisionCollectionResult:
        input.authoritativePolicyDecisionCollectionResult,
      platformUserApprovalDecision: input.platformUserApprovalDecision,
      platformUserApprovalDecisionCollectionResult:
        input.platformUserApprovalDecisionCollectionResult,
      authoritativeCapabilityGrant: input.authoritativeCapabilityGrant,
      userSessionCapabilityMutationResult:
        input.userSessionCapabilityMutationResult,
      activeCapabilityGrantInspection:
        input.activeCapabilityGrantInspection,
      authorizationDecisionCandidate: input.authorizationDecisionCandidate,
      authorizationDecisionCandidateCollectionResult:
        input.authorizationDecisionCandidateCollectionResult,
      authorizationPackageDraft: input.authorizationPackageDraft,
      authorizationPackageDraftCollectionResult:
        input.authorizationPackageDraftCollectionResult,
      actionUnlockProofGenerationArtifact:
        input.actionUnlockProofGenerationArtifact,
      actionUnlockProofGenerationCollectionResult:
        input.actionUnlockProofGenerationCollectionResult,
      actionUnlockProofVerification:
        input.actionUnlockProofVerification,
      actionUnlockProofVerificationCollectionResult:
        input.actionUnlockProofVerificationCollectionResult,
      finalizedAuthorizationPackage:
        input.finalizedAuthorizationPackage,
      finalizedAuthorizationPackageCollectionResult:
        input.finalizedAuthorizationPackageCollectionResult,
      verifiedFactPublicationRequestDraft:
        input.verifiedFactPublicationRequestDraft,
      verifiedFactPublicationRequestDraftCollectionResult:
        input.verifiedFactPublicationRequestDraftCollectionResult,
      authorizationExecutionReadiness:
        input.authorizationExecutionReadiness,
      authorizationExecutionReadinessCollectionResult:
        input.authorizationExecutionReadinessCollectionResult,
      auditEventDraft,
      auditDraftCollectionResult,
      sessionId: input.envelope.context?.sessionId
    },
    error: input.intake.error,
    auditEventId: auditEventDraft.eventDraftId,
    pendingApprovalId: input.intake.pendingApprovalId
  };
}

export function createValidationOnlyRuntimeApi(
  options: ValidationOnlyRuntimeApiOptions = {}
): ValidationOnlyRuntimeApi {
  return {
    requestCapability(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const envelope: RuntimeRequestEnvelope = {
        context: contextFromCapabilityRequest(request, userSessionContext),
        capabilityRequest: request
      };
      const intake = validateCapabilityRequestIntake(envelope);
      const capabilityGrantDraft = intake.status === "approved"
        ? createCapabilityGrantDraft({
          capabilityRequest: request,
          sessionId: envelope.context?.sessionId
        }).value
        : undefined;
      const capabilityGrantDraftCollectionResult = capabilityGrantDraft
        ? options.capabilityGrantDraftCollector?.addDraft(capabilityGrantDraft)
        : undefined;

      return wrapIntakeWithAuditDraft({
        intake,
        envelope: {
          ...envelope,
          kind: "capability"
        },
        category: "capability",
        summary: "Capability request shape validation completed.",
        auditDraftCollector: options.auditDraftCollector,
        capabilityGrantDraft,
        capabilityGrantDraftCollectionResult
      });
    },
    requestTrustEvaluationDraft(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const trustEvaluationDraftResult = createTrustEvaluationDraft({
        ...request,
        userSessionContext: request.userSessionContext ?? userSessionContext
      });
      const trustEvaluationDraft = trustEvaluationDraftResult.value;
      const trustEvaluationDraftCollectionResult = trustEvaluationDraft
        ? options.trustEvaluationDraftCollector?.addDraft(trustEvaluationDraft)
        : undefined;
      const intake = intakeFromTrustEvaluationDraftResult(trustEvaluationDraftResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: trustEvaluationDraft?.sessionId
          ?? request.sessionId
          ?? userSessionContext?.sessionId
          ?? request.capabilityGrantDraft?.sessionId,
        applicationId: trustEvaluationDraft?.applicationId
          ?? request.capabilityGrantDraft?.applicationId,
        requestedAt: request.createdAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: trustEvaluationDraft
          ? "Trust evaluation draft shape validation completed; no trust decision was made."
          : "Trust evaluation draft shape validation failed; no trust decision was made.",
        auditDraftCollector: options.auditDraftCollector,
        capabilityGrantDraft: request.capabilityGrantDraft,
        trustEvaluationDraft,
        trustEvaluationDraftCollectionResult
      });
    },
    requestPublicTrustMetadataEvaluation(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const evaluationResult = evaluatePublicTrustMetadata(request);
      const publicTrustMetadataEvaluation = evaluationResult.value;
      const publicTrustMetadataEvaluationCollectionResult = publicTrustMetadataEvaluation
        ? options.publicTrustMetadataEvaluationCollector?.addResult(publicTrustMetadataEvaluation)
        : undefined;
      const intake = intakeFromPublicTrustMetadataEvaluationResult(evaluationResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.trustEvaluationDraft?.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.trustEvaluationDraft?.applicationId,
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: publicTrustMetadataEvaluation
          ? "Public Trust metadata evaluation completed; no authentication or trust decision was made."
          : "Public Trust metadata evaluation failed request validation; no authentication or trust decision was made.",
        auditDraftCollector: options.auditDraftCollector,
        trustEvaluationDraft: request.trustEvaluationDraft,
        publicTrustMetadataEvaluation,
        publicTrustMetadataEvaluationCollectionResult
      });
    },
    requestPossessionVerificationDraft(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const draftResult = createPossessionVerificationRequestDraft({
        ...request,
        userSessionContext: request.userSessionContext ?? userSessionContext
      });
      const possessionVerificationRequestDraft = draftResult.value;
      const intake = intakeFromPossessionVerificationRequestDraftResult(draftResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: possessionVerificationRequestDraft?.sessionId
          ?? request.publicTrustMetadataEvaluation?.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: possessionVerificationRequestDraft?.applicationId
          ?? request.publicTrustMetadataEvaluation?.applicationId,
        requestedAt: request.createdAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: possessionVerificationRequestDraft
          ? "Possession verification request draft created; no verification was executed."
          : "Possession verification request draft validation failed; no verification was executed.",
        auditDraftCollector: options.auditDraftCollector,
        publicTrustMetadataEvaluation: request.publicTrustMetadataEvaluation,
        possessionVerificationRequestDraft
      });
    },
    async requestWebAuthnFixturePossessionVerification(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const verificationResult = await verifyPossessionDraftWithWebAuthnFixture(request);
      const webAuthnFixtureVerificationArtifact = verificationResult.value;
      const intake = intakeFromWebAuthnFixtureVerificationResult(verificationResult);
      const draft = request.possessionVerificationRequestDraft;
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: draft?.sessionId ?? userSessionContext?.sessionId,
        applicationId: draft?.applicationId,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: webAuthnFixtureVerificationArtifact
          ? "WebAuthn fixture possession verification completed; no production authentication or trust decision was made."
          : "WebAuthn fixture possession verification request failed validation; no production authentication or trust decision was made.",
        auditDraftCollector: options.auditDraftCollector,
        possessionVerificationRequestDraft: request.possessionVerificationRequestDraft,
        webAuthnFixtureVerificationArtifact
      });
    },
    requestFixturePossessionEvaluation(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const possessionEvaluationRuntimeResult =
        createPossessionEvaluationResultFromWebAuthnFixture(request);
      const possessionEvaluationResult = possessionEvaluationRuntimeResult.value;
      const possessionEvaluationCollectionResult = possessionEvaluationResult
        ? options.possessionEvaluationResultCollector?.addResult(possessionEvaluationResult)
        : undefined;
      const intake = intakeFromPossessionEvaluationResult(possessionEvaluationRuntimeResult);
      const draft = request.possessionVerificationRequestDraft;
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: draft?.sessionId ?? userSessionContext?.sessionId,
        applicationId: draft?.applicationId,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: possessionEvaluationResult
          ? "Fixture-only possession evaluation completed; no production authentication or trust decision was made."
          : "Fixture-only possession evaluation request failed validation; no production authentication or trust decision was made.",
        auditDraftCollector: options.auditDraftCollector,
        possessionVerificationRequestDraft: request.possessionVerificationRequestDraft,
        webAuthnFixtureVerificationArtifact: request.webAuthnFixtureVerificationArtifact,
        possessionEvaluationResult,
        possessionEvaluationCollectionResult
      });
    },
    requestBoundedTrustEvaluation(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const boundedTrustEvaluationRuntimeResult = evaluateBoundedTrustEvidence(request);
      const boundedTrustEvaluationResult = boundedTrustEvaluationRuntimeResult.value;
      const boundedTrustEvaluationCollectionResult = boundedTrustEvaluationResult
        ? options.boundedTrustEvaluationResultCollector?.addResult(boundedTrustEvaluationResult)
        : undefined;
      const intake = intakeFromBoundedTrustEvaluationResult(boundedTrustEvaluationRuntimeResult);
      const draft = request.trustEvaluationDraft;
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? draft?.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId ?? draft?.applicationId,
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: boundedTrustEvaluationResult
          ? "Bounded Trust evaluation completed; no trust decision, policy decision, or authority was created."
          : "Bounded Trust evaluation failed validation; no trust decision, policy decision, or authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        trustEvaluationDraft: request.trustEvaluationDraft,
        publicTrustMetadataEvaluation: request.publicTrustMetadataEvaluation,
        possessionEvaluationResult: request.possessionEvaluationResult,
        boundedTrustEvaluationResult,
        boundedTrustEvaluationCollectionResult
      });
    },
    requestBoundedPolicyEvaluation(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const boundedPolicyEvaluationRuntimeResult = evaluateBoundedRuntimePolicy(request);
      const boundedPolicyEvaluationResult = boundedPolicyEvaluationRuntimeResult.value;
      const boundedPolicyEvaluationCollectionResult = boundedPolicyEvaluationResult
        ? options.boundedPolicyEvaluationResultCollector?.addResult(boundedPolicyEvaluationResult)
        : undefined;
      const intake = intakeFromBoundedPolicyEvaluationResult(boundedPolicyEvaluationRuntimeResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? request.context?.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId ?? request.context?.applicationId,
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: boundedPolicyEvaluationResult
          ? "Bounded policy evaluation completed; no user approval, authorization, or authority was created."
          : "Bounded policy evaluation failed validation; no user approval, authorization, or authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        capabilityGrantDraft: request.capabilityGrantDraft,
        boundedTrustEvaluationResult: request.boundedTrustEvaluationResult,
        boundedPolicyEvaluationResult,
        boundedPolicyEvaluationCollectionResult
      });
    },
    requestUserApprovalDraft(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const draftResult = createUserApprovalRequestDraft(request);
      const userApprovalRequestDraft = draftResult.value;
      const userApprovalRequestDraftCollectionResult = userApprovalRequestDraft
        ? options.userApprovalRequestDraftCollector?.addDraft(userApprovalRequestDraft)
        : undefined;
      const intake = intakeFromUserApprovalRequestDraftResult(draftResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId
          ?? request.boundedPolicyEvaluationResult?.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.applicationId
          ?? request.boundedPolicyEvaluationResult?.applicationId,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: userApprovalRequestDraft
          ? "User approval request draft created; no user decision, authorization, or authority was created."
          : "User approval request draft validation failed; no user decision, authorization, or authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        capabilityGrantDraft: request.capabilityGrantDraft,
        boundedTrustEvaluationResult: request.boundedTrustEvaluationResult,
        boundedPolicyEvaluationResult: request.boundedPolicyEvaluationResult,
        userApprovalRequestDraft,
        userApprovalRequestDraftCollectionResult
      });
    },
    requestUserDecisionFixture(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const fixtureResult = createUserDecisionFixtureArtifact(request);
      const userDecisionFixtureArtifact = fixtureResult.value;
      const userDecisionFixtureArtifactCollectionResult = userDecisionFixtureArtifact
        ? options.userDecisionFixtureArtifactCollector?.addArtifact(userDecisionFixtureArtifact)
        : undefined;
      const intake = intakeFromUserDecisionFixtureResult(fixtureResult);
      const approval = request.userApprovalRequestDraft;
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId
          ?? approval?.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.applicationId
          ?? approval?.applicationId,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: userDecisionFixtureArtifact
          ? "User decision fixture artifact recorded; no production consent, authorization, or authority was created."
          : "User decision fixture artifact validation failed; no production consent, authorization, or authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        capabilityGrantDraft: request.capabilityGrantDraft,
        boundedTrustEvaluationResult: request.boundedTrustEvaluationResult,
        boundedPolicyEvaluationResult: request.boundedPolicyEvaluationResult,
        userApprovalRequestDraft: request.userApprovalRequestDraft,
        userDecisionFixtureArtifact,
        userDecisionFixtureArtifactCollectionResult
      });
    },
    requestCapabilityActivationCandidate(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const candidateResult = createCapabilityActivationCandidate(request);
      const capabilityActivationCandidate = candidateResult.value;
      const capabilityActivationCandidateCollectionResult = capabilityActivationCandidate
        ? options.capabilityActivationCandidateCollector?.addCandidate(capabilityActivationCandidate)
        : undefined;
      const intake = intakeFromCapabilityActivationCandidateResult(candidateResult);
      const approval = request.userApprovalRequestDraft;
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId
          ?? approval?.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.applicationId
          ?? approval?.applicationId,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: capabilityActivationCandidate
          ? "Capability activation candidate created; no active capability, authorization, or authority was created."
          : "Capability activation candidate validation failed; no active capability, authorization, or authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        capabilityGrantDraft: request.capabilityGrantDraft,
        boundedTrustEvaluationResult: request.boundedTrustEvaluationResult,
        boundedPolicyEvaluationResult: request.boundedPolicyEvaluationResult,
        userApprovalRequestDraft: request.userApprovalRequestDraft,
        userDecisionFixtureArtifact: request.userDecisionFixtureArtifact,
        capabilityActivationCandidate,
        capabilityActivationCandidateCollectionResult
      });
    },
    async requestProductionAuthenticationVerification(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const verificationResult = await verifyProductionWebAuthnAuthentication(request);
      const productionAuthenticationVerification = verificationResult.value;
      const productionAuthenticationVerificationCollectionResult =
        productionAuthenticationVerification
          ? options.productionAuthenticationVerificationCollector?.addResult(
            productionAuthenticationVerification
          )
          : undefined;
      const intake = intakeFromProductionAuthenticationVerificationResult(verificationResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.correlation?.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.correlation?.applicationId ?? "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: productionAuthenticationVerification
          ? "Production WebAuthn verification completed; lifecycle eligibility only, no runtime authentication or vault unlock occurred."
          : "Production WebAuthn verification request failed validation; no runtime authentication or vault unlock occurred.",
        auditDraftCollector: options.auditDraftCollector,
        productionAuthenticationVerification,
        productionAuthenticationVerificationCollectionResult
      });
    },
    requestLifecycleTransitionCandidate(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const candidateResult = createLifecycleTransitionCandidate(request);
      const lifecycleTransitionCandidate = candidateResult.value;
      const intake = intakeFromLifecycleTransitionCandidateResult(candidateResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.lifecycleSnapshot?.sessionId
          ?? request.productionAuthenticationVerification?.correlation.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.applicationId
          ?? request.productionAuthenticationVerification?.correlation.applicationId
          ?? "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: lifecycleTransitionCandidate
          ? "Lifecycle transition candidate created for production-verified partial unlock; no session transition occurred."
          : "Lifecycle transition candidate request failed; no session transition occurred.",
        auditDraftCollector: options.auditDraftCollector,
        productionAuthenticationVerification: request.productionAuthenticationVerification,
        lifecycleTransitionCandidate
      });
    },
    requestProductionVerifiedPartialUnlock(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const partialUnlockResult = transitionUserSessionWithProductionVerification({
        ...request,
        consumptionStore: request.consumptionStore ?? options.productionVerificationConsumptionStore,
        auditDraftCollector: request.auditDraftCollector ?? options.auditDraftCollector
      });
      const productionVerifiedPartialUnlock = partialUnlockResult.value;
      const intake = intakeFromProductionVerifiedPartialUnlockResult(partialUnlockResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.lifecycleSnapshot.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.candidate.applicationId ?? "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: productionVerifiedPartialUnlock
          ? "Production-verified partial unlock completed; Device Vault remains locked and no authority was created."
          : "Production-verified partial unlock failed validation; Device Vault remains locked and no authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        lifecycleTransitionCandidate: request.candidate,
        productionVerifiedPartialUnlock
      });
    },
    async requestDeviceVaultUnlockVerification(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const vaultUnlockResult = await verifyDeviceVaultUnlock(request);
      const deviceVaultUnlockResult = vaultUnlockResult.value;
      const intake = intakeFromDeviceVaultUnlockResult(vaultUnlockResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.correlation?.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.correlation?.applicationId ?? "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, request.userSessionContext ?? userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: deviceVaultUnlockResult
          ? "Device Vault unlock verification completed against explicit in-memory material; no capability or authorization was created."
          : "Device Vault unlock verification failed; no capability or authorization was created.",
        auditDraftCollector: options.auditDraftCollector,
        deviceVaultUnlockResult
      });
    },
    requestVerifiedVaultSessionUnlock(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const verifiedVaultSessionUnlockResult = transitionUserSessionWithVerifiedVaultUnlock({
        ...request,
        consumptionStore: request.consumptionStore ?? options.vaultUnlockConsumptionStore,
        auditDraftCollector: request.auditDraftCollector ?? options.auditDraftCollector
      });
      const verifiedVaultSessionUnlock = verifiedVaultSessionUnlockResult.value;
      const intake = intakeFromVerifiedVaultSessionUnlockResult(verifiedVaultSessionUnlockResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.lifecycleSnapshot.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.vaultUnlockResult.correlation.applicationId ?? "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: verifiedVaultSessionUnlock
          ? "Verified Device Vault session unlock completed; no active capability, authorization, proof, adapter call, or persistence occurred."
          : "Verified Device Vault session unlock failed validation; no active capability, authorization, proof, adapter call, or persistence occurred.",
        auditDraftCollector: options.auditDraftCollector,
        deviceVaultUnlockResult: request.vaultUnlockResult,
        verifiedVaultSessionUnlock
      });
    },
    async requestProtectedStateView(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const viewResult = await createProtectedStateView({
        ...request,
        replayStore: request.replayStore ?? options.protectedStateViewReplayStore
      }, options.protectedStateViewCollector, options.auditDraftCollector);
      const protectedStateView = viewResult.value;
      const intake = intakeFromProtectedStateViewResult(viewResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.lifecycleSnapshot.sessionId ?? userSessionContext?.sessionId,
        applicationId: "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: protectedStateView
          ? "Protected state view request completed; only explicit non-secret summary metadata was returned."
          : "Protected state view request failed; no raw vault contents were returned.",
        auditDraftCollector: options.auditDraftCollector,
        protectedStateView,
        protectedStateViewCollectionResult: protectedStateView?.protectedStateViewCollectionResult
      });
    },
    async requestPublicCredentialDirectory(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const directoryResult = await createPublicCredentialDirectoryResult(
        request,
        options.publicCredentialDirectoryResultCollector,
        options.auditDraftCollector
      );
      const publicCredentialDirectory = directoryResult.value;
      const intake = intakeFromPublicCredentialDirectoryResult(directoryResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.lifecycleSnapshot.sessionId ?? userSessionContext?.sessionId,
        applicationId: "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: publicCredentialDirectory
          ? "Public credential directory returned allowlisted public descriptors; no trust decision or authority was created."
          : "Public credential directory request failed; no credential private material was returned.",
        auditDraftCollector: options.auditDraftCollector,
        publicCredentialDirectory
      });
    },
    async requestSelectedCredentialPublicMaterial(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const selectedMaterialResult = await createSelectedCredentialPublicMaterialResult(
        request,
        options.auditDraftCollector
      );
      const selectedCredentialPublicMaterial = selectedMaterialResult.value;
      const intake = intakeFromSelectedCredentialPublicMaterialResult(selectedMaterialResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.lifecycleSnapshot.sessionId ?? userSessionContext?.sessionId,
        applicationId: "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: selectedCredentialPublicMaterial
          ? "Selected credential public material was materialized for future verification; no authentication, Trust Decision, or authority was created."
          : "Selected credential public material request failed; no private credential material, assertion payload, or authority was returned.",
        auditDraftCollector: options.auditDraftCollector,
        selectedCredentialPublicMaterial
      });
    },
    requestTrustManagerVerificationInput(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const trustManagerVerificationInputResult = createTrustManagerVerificationInput(
        request,
        options.auditDraftCollector
      );
      const trustManagerVerificationInput = trustManagerVerificationInputResult.value;
      const intake = intakeFromTrustManagerVerificationInputResult(
        trustManagerVerificationInputResult
      );
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId,
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: trustManagerVerificationInput
          ? "Trust Manager verification input was constructed from bounded public material; no verification, Trust Decision, or authority was created."
          : "Trust Manager verification input request failed; no authentication, Trust Decision, or authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        trustManagerVerificationInput
      });
    },
    async requestTrustManagerProductionVerification(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const verificationResult = await verifyTrustManagerProductionAssertion(
        request,
        options.trustManagerVerificationConsumptionStore,
        options.trustManagerProductionVerificationCollector,
        options.auditDraftCollector
      );
      const trustManagerProductionVerification = verificationResult.value;
      const intake = intakeFromTrustManagerProductionVerificationResult(verificationResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.verificationInput.correlation.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.verificationInput.correlation.applicationId,
        requestedAt: request.collectedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "runtime",
        summary: trustManagerProductionVerification
          ? "Trust Manager production assertion verification completed as bounded evidence only; no Trust Decision or authority was created."
          : "Trust Manager production assertion verification failed; no Trust Decision or authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        trustManagerProductionVerification,
        trustManagerProductionVerificationCollectionResult:
          trustManagerProductionVerification?.collectionResult
      });
    },
    requestBoundedTrustDecisionCandidate(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const candidateResult = evaluateBoundedTrustDecisionCandidate(
        request,
        options.boundedTrustDecisionCandidateCollector,
        options.auditDraftCollector
      );
      const boundedTrustDecisionCandidate = candidateResult.value;
      const intake = intakeFromBoundedTrustDecisionCandidateResult(candidateResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId,
        requestedAt: request.verificationTimestamp,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: boundedTrustDecisionCandidate
          ? "Bounded Trust Decision candidate evaluated; no authoritative Trust Decision or authority was created."
          : "Bounded Trust Decision candidate request failed; no authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        trustManagerProductionVerification: request.productionVerificationResult,
        boundedTrustDecisionCandidate,
        boundedTrustDecisionCandidateCollectionResult:
          boundedTrustDecisionCandidate?.collectionResult
      });
    },
    async requestCredentialCounterPersistence(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const persistenceResult = await persistVerifiedCredentialCounter(
        request,
        options.credentialCounterPersistenceReplayStore,
        options.auditDraftCollector
      );
      const credentialCounterPersistenceReceipt = persistenceResult.value;
      const trustDecisionCandidateCounterResolution =
        credentialCounterPersistenceReceipt
          ? resolveCounterPersistenceRequirement({
            boundedTrustDecisionCandidate: request.boundedTrustDecisionCandidate,
            receipt: credentialCounterPersistenceReceipt
          })
          : undefined;
      const intake = intakeFromCredentialCounterPersistenceResult(persistenceResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId,
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: credentialCounterPersistenceReceipt
          ? "Credential counter persistence completed for one credential counter field; no Trust Decision or authority was created."
          : "Credential counter persistence failed or was rejected; no Trust Decision or authority was created.",
        auditDraftCollector: options.auditDraftCollector,
        trustManagerProductionVerification: request.productionVerificationResult,
        boundedTrustDecisionCandidate: request.boundedTrustDecisionCandidate,
        credentialCounterPersistenceReceipt,
        trustDecisionCandidateCounterResolution
      });
    },
    requestAuthoritativeTrustDecision(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const trustDecisionResult = evaluateAuthoritativeTrustDecision(
        request,
        options.trustDecisionEvidenceConsumptionStore,
        options.authoritativeTrustDecisionStore,
        options.auditDraftCollector
      );
      const authoritativeTrustDecision = trustDecisionResult.value;
      const intake = trustDecisionResult.status === "approved"
        ? runtimeOk({ valid: true, issues: [] })
        : runtimeDenied(trustDecisionResult.error ?? {
          category: "trust_denied",
          code: "AUTHORITATIVE_TRUST_DECISION_REJECTED",
          message: "authoritative Trust Decision request was rejected",
          boundary: "trust-manager",
          recoverable: true
        });
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId,
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "trust",
        summary: authoritativeTrustDecision
          ? "Authoritative Trust Manager decision created for one bounded evidence chain; no capability, policy approval, authorization, or execution was created."
          : "Authoritative Trust Manager decision request rejected; no capability, policy approval, authorization, or execution was created.",
        auditDraftCollector: options.auditDraftCollector,
        trustManagerProductionVerification: request.productionVerificationResult,
        boundedTrustDecisionCandidate: request.boundedTrustDecisionCandidate,
        credentialCounterPersistenceReceipt: request.counterPersistenceReceipt,
        trustDecisionCandidateCounterResolution: request.counterResolution,
        authoritativeTrustDecision,
        authoritativeTrustDecisionCollectionResult:
          authoritativeTrustDecision?.collectionResult
      });
    },
    requestAuthoritativePolicyDecision(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const policyDecisionResult = evaluateAuthoritativeSecurityPolicy(
        request,
        options.policyDecisionEvidenceConsumptionStore,
        options.authoritativePolicyDecisionStore,
        options.auditDraftCollector
      );
      const authoritativePolicyDecision = policyDecisionResult.value;
      const intake = policyDecisionResult.status === "approved"
        ? runtimeOk({ valid: true, issues: [] })
        : runtimeDenied(policyDecisionResult.error ?? {
          category: "policy_denied",
          code: "AUTHORITATIVE_POLICY_DECISION_REJECTED",
          message: "authoritative Security Policy Decision request was rejected",
          boundary: "security-policy-engine",
          recoverable: true
        });
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId,
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: authoritativePolicyDecision
          ? "Authoritative Security Policy Decision created for one bounded request; no capability, user approval, authorization, proof, or execution was created."
          : "Authoritative Security Policy Decision request rejected; no capability, user approval, authorization, proof, or execution was created.",
        auditDraftCollector: options.auditDraftCollector,
        authoritativeTrustDecision: request.authoritativeTrustDecision,
        authoritativePolicyDecision,
        authoritativePolicyDecisionCollectionResult:
          authoritativePolicyDecision?.collectionResult
      });
    },
    requestPlatformUserApprovalDecision(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const approvalDecisionResult = evaluatePlatformUserApprovalDecision(
        request,
        options.userApprovalArtifactConsumptionStore,
        options.platformUserApprovalDecisionStore,
        options.auditDraftCollector
      );
      const platformUserApprovalDecision = approvalDecisionResult.value;
      const intake = approvalDecisionResult.status === "approved"
        ? runtimeOk({ valid: true, issues: [] })
        : runtimeDenied(approvalDecisionResult.error ?? {
          category: "user_cancelled",
          code: "PLATFORM_USER_APPROVAL_DECISION_REJECTED",
          message: "platform User Approval Decision request was rejected",
          boundary: "runtime-api",
          recoverable: true
        });
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.actionRequest.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.actionRequest.applicationId,
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: platformUserApprovalDecision
          ? "Platform User Approval Decision accepted for one exact request; no capability, authorization, proof, or execution was created."
          : "Platform User Approval Decision request rejected; no capability, authorization, proof, or execution was created.",
        auditDraftCollector: options.auditDraftCollector,
        authoritativeTrustDecision: request.authoritativeTrustDecision,
        authoritativePolicyDecision: request.authoritativePolicyDecision,
        platformUserApprovalDecision,
        platformUserApprovalDecisionCollectionResult:
          platformUserApprovalDecision?.collectionResult
      });
    },
    requestAuthoritativeCapabilityActivation(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const activationResult = evaluateAuthoritativeCapabilityActivation(
        request,
        options.capabilityActivationEvidenceConsumptionStore,
        options.auditDraftCollector
      );
      const draftGrant = activationResult.value;
      const userSessionCapabilityMutationResult = draftGrant
        ? options.authoritativeCapabilityGrantStore?.activate(draftGrant)
        : undefined;
      const authoritativeCapabilityGrant =
        userSessionCapabilityMutationResult?.grant ?? draftGrant;
      const intake = intakeFromAuthoritativeCapabilityActivationResult(activationResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId,
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "capability",
        summary: authoritativeCapabilityGrant
          ? "Authoritative scoped capability grant created for one session; no action authorization, proof, adapter call, or execution occurred."
          : "Authoritative capability activation request rejected; no active capability, authorization, proof, adapter call, or execution occurred.",
        auditDraftCollector: options.auditDraftCollector,
        authoritativeTrustDecision: request.authoritativeTrustDecision,
        authoritativePolicyDecision: request.authoritativePolicyDecision,
        platformUserApprovalDecision: request.platformUserApprovalDecision,
        authoritativeCapabilityGrant,
        userSessionCapabilityMutationResult
      });
    },
    requestCapabilityGrantRevocation(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const mutation = options.authoritativeCapabilityGrantStore?.revoke(
        request.grantId,
        request.reason,
        request.requestedAt
      );
      const intake = mutation?.status === "revoked"
        ? runtimeOk({ valid: true, issues: [] })
        : runtimeDenied({
          category: "capability_denied",
          code: mutation ? "CAPABILITY_GRANT_REVOCATION_NOT_FOUND" : "CAPABILITY_GRANT_STORE_UNAVAILABLE",
          message: mutation
            ? "capability grant revocation request did not match an active grant"
            : "capability grant revocation requires an explicit process-local grant store",
          boundary: "runtime-api",
          recoverable: true,
          details: { mutationStatus: mutation?.status, reason: mutation?.reason }
        });
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId ?? "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "capability",
        summary: mutation?.status === "revoked"
          ? "Process-local capability grant revoked; no authorization, proof, adapter call, or execution occurred."
          : "Capability grant revocation request failed; no authorization, proof, adapter call, or execution occurred.",
        auditDraftCollector: options.auditDraftCollector,
        authoritativeCapabilityGrant: mutation?.grant,
        userSessionCapabilityMutationResult: mutation
      });
    },
    inspectActiveCapabilityGrants(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const all = options.authoritativeCapabilityGrantStore?.getAll() ?? [];
      const grants = all.filter((grant) =>
        (request.sessionId === undefined || grant.binding.sessionId === request.sessionId)
        && (request.applicationId === undefined
          || grant.binding.applicationId === request.applicationId)
        && (request.capabilityName === undefined
          || grant.binding.capabilityName === request.capabilityName)
        && (request.ownerCommitment === undefined
          || grant.binding.ownerCommitment === request.ownerCommitment)
      );
      const activeCapabilityGrantInspection = Object.freeze({
        status: "inspected" as const,
        sessionId: request.sessionId,
        applicationId: request.applicationId,
        capabilityName: request.capabilityName,
        count: grants.length,
        grants: Object.freeze([...grants]),
        authorizationCreated: false as const,
        executionAllowed: false as const,
        persisted: false as const
      });
      const intake = options.authoritativeCapabilityGrantStore
        ? runtimeOk({ valid: true, issues: [] })
        : runtimeDenied({
          category: "capability_denied",
          code: "CAPABILITY_GRANT_STORE_UNAVAILABLE",
          message: "active capability grant inspection requires an explicit process-local grant store",
          boundary: "runtime-api",
          recoverable: true
        });
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId ?? "ethereum-net",
        requestedAt: request.requestedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "capability",
        summary: "Process-local active capability grants inspected; no authorization, proof, adapter call, or execution occurred.",
        auditDraftCollector: options.auditDraftCollector,
        activeCapabilityGrantInspection
      });
    },
    requestAuthorizationDecisionCandidate(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const candidateResult = evaluateAuthorizationDecisionCandidate(
        request,
        options.authorizationCandidateConsumptionStore,
        options.authorizationDecisionCandidateStore,
        options.auditDraftCollector
      );
      const authorizationDecisionCandidate = candidateResult.value;
      const intake = intakeFromAuthorizationDecisionCandidateResult(candidateResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.sessionId ?? userSessionContext?.sessionId,
        applicationId: request.applicationId,
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: authorizationDecisionCandidate
          ? "Authorization Decision Candidate created; no Authorization Package, proof, signature, adapter call, or execution occurred."
          : "Authorization Decision Candidate request rejected; no Authorization Package, proof, signature, adapter call, or execution occurred.",
        auditDraftCollector: options.auditDraftCollector,
        authoritativeCapabilityGrant: request.activeCapabilityGrant,
        authorizationDecisionCandidate,
        authorizationDecisionCandidateCollectionResult:
          authorizationDecisionCandidate?.collectionResult
      });
    },
    requestAuthorizationPackageDraft(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const draftResult = createAuthorizationPackageDraft(
        request,
        options.authorizationPackageDraftConsumptionStore,
        options.authorizationPackageDraftStore,
        options.auditDraftCollector
      );
      const authorizationPackageDraft = draftResult.value;
      const intake = intakeFromAuthorizationPackageDraftResult(draftResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.authorizationDecisionCandidate?.binding.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.authorizationDecisionCandidate?.binding.applicationId
          ?? "ethereum-net",
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: authorizationPackageDraft
          ? "Authorization Package Draft created; proof, fact publication, nullifier consumption, adapter call, and execution did not occur."
          : "Authorization Package Draft request rejected; proof, fact publication, nullifier consumption, adapter call, and execution did not occur.",
        auditDraftCollector: options.auditDraftCollector,
        authoritativeCapabilityGrant: request.activeCapabilityGrant,
        authorizationDecisionCandidate: request.authorizationDecisionCandidate,
        authorizationPackageDraft,
        authorizationPackageDraftCollectionResult:
          authorizationPackageDraft?.collectionResult
      });
    },
    async requestActionUnlockProofGeneration(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const proofResult = await generateActionUnlockProof(
        request,
        options.actionUnlockProofGenerationConsumptionStore,
        options.actionUnlockProofGenerationArtifactStore,
        options.auditDraftCollector
      );
      const actionUnlockProofGenerationArtifact = proofResult.value;
      const intake = intakeFromActionUnlockProofGenerationResult(proofResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.authorizationPackageDraft?.binding.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.authorizationPackageDraft?.binding.applicationId
          ?? "ethereum-net",
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: actionUnlockProofGenerationArtifact
          ? "ACTION_UNLOCK proof artifact generated; no fact publication, nullifier consumption, package finalization, adapter call, or execution occurred."
          : "ACTION_UNLOCK proof generation rejected or failed; no fact publication, nullifier consumption, package finalization, adapter call, or execution occurred.",
        auditDraftCollector: options.auditDraftCollector,
        authorizationPackageDraft: request.authorizationPackageDraft,
        actionUnlockProofGenerationArtifact,
        actionUnlockProofGenerationCollectionResult:
          actionUnlockProofGenerationArtifact?.collectionResult
      });
    },
    async requestActionUnlockProofVerification(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const verificationResult = await verifyGeneratedActionUnlockProof(
        request,
        options.actionUnlockProofVerificationConsumptionStore,
        options.actionUnlockProofVerificationResultStore,
        options.auditDraftCollector
      );
      const actionUnlockProofVerification = verificationResult.value;
      const intake = intakeFromActionUnlockProofVerificationResult(verificationResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.authorizationPackageDraft?.binding.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.authorizationPackageDraft?.binding.applicationId
          ?? "ethereum-net",
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: actionUnlockProofVerification
          ? "ACTION_UNLOCK proof verified locally; no fact publication, nullifier consumption, package execution, adapter call, or transaction occurred."
          : "ACTION_UNLOCK proof verification rejected or failed; no fact publication, nullifier consumption, package execution, adapter call, or transaction occurred.",
        auditDraftCollector: options.auditDraftCollector,
        authorizationPackageDraft: request.authorizationPackageDraft,
        actionUnlockProofGenerationArtifact: request.proofGenerationArtifact,
        actionUnlockProofVerification,
        actionUnlockProofVerificationCollectionResult:
          actionUnlockProofVerification?.collectionResult
      });
    },
    requestFinalizedAuthorizationPackage(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const finalizationResult = finalizeAuthorizationPackage(
        request,
        options.finalizedAuthorizationPackageConsumptionStore,
        options.finalizedAuthorizationPackageStore,
        options.auditDraftCollector
      );
      const finalizedAuthorizationPackage = finalizationResult.value;
      const intake = intakeFromFinalizedAuthorizationPackageResult(finalizationResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.authorizationPackageDraft?.binding.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.authorizationPackageDraft?.binding.applicationId
          ?? "ethereum-net",
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: finalizedAuthorizationPackage
          ? "Finalized non-executing ACTION_UNLOCK Authorization Package created; no fact publication, nullifier consumption, contract call, adapter call, or transaction occurred."
          : "Finalized Authorization Package request rejected; no fact publication, nullifier consumption, contract call, adapter call, or transaction occurred.",
        auditDraftCollector: options.auditDraftCollector,
        authorizationPackageDraft: request.authorizationPackageDraft,
        actionUnlockProofGenerationArtifact: request.proofGenerationArtifact,
        actionUnlockProofVerification: request.proofVerificationResult,
        finalizedAuthorizationPackage,
        finalizedAuthorizationPackageCollectionResult:
          finalizedAuthorizationPackage?.collectionResult
      });
    },
    requestVerifiedFactPublicationDraft(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const publicationResult = createVerifiedFactPublicationRequestDraft(
        request,
        options.verifiedFactPublicationRequestDraftStore,
        options.auditDraftCollector
      );
      const verifiedFactPublicationRequestDraft = publicationResult.value;
      const intake = intakeFromVerifiedFactPublicationRequestResult(publicationResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.finalizedAuthorizationPackage?.binding.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.finalizedAuthorizationPackage?.binding.applicationId
          ?? "ethereum-net",
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: verifiedFactPublicationRequestDraft
          ? "Verified-fact publication request draft created; no contract call, fact publication, nullifier consumption, adapter call, or transaction occurred."
          : "Verified-fact publication request rejected; no contract call, fact publication, nullifier consumption, adapter call, or transaction occurred.",
        auditDraftCollector: options.auditDraftCollector,
        finalizedAuthorizationPackage: request.finalizedAuthorizationPackage,
        verifiedFactPublicationRequestDraft,
        verifiedFactPublicationRequestDraftCollectionResult:
          verifiedFactPublicationRequestDraft?.collectionResult
      });
    },
    async requestAuthorizationExecutionReadiness(request) {
      const userSessionContext = userSessionContextFromOptions(options);
      const readinessResult = await evaluateAuthorizationExecutionReadiness(
        request,
        options.authorizationExecutionReadinessResultStore,
        options.auditDraftCollector
      );
      const authorizationExecutionReadiness = readinessResult.value;
      const intake = intakeFromAuthorizationExecutionReadinessResult(readinessResult);
      const context = contextFromRequest({
        requestId: request.requestId,
        sessionId: request.publicationRequestDraft?.binding.sessionId
          ?? userSessionContext?.sessionId,
        applicationId: request.publicationRequestDraft?.binding.applicationId
          ?? "ethereum-net",
        requestedAt: request.issuedAt,
        metadata: request.metadata
      }, userSessionContext);
      const envelope: RuntimeRequestEnvelope = {
        kind: "generic",
        context
      };

      return wrapIntakeWithAuditDraft({
        intake,
        envelope,
        category: "authorization_request",
        summary: authorizationExecutionReadiness
          ? "Authorization execution readiness snapshot created; no fact publication, nullifier consumption, contract call, UserOperation, adapter call, or transaction occurred."
          : "Authorization execution readiness blocked; no fact publication, nullifier consumption, contract call, UserOperation, adapter call, or transaction occurred.",
        auditDraftCollector: options.auditDraftCollector,
        verifiedFactPublicationRequestDraft: request.publicationRequestDraft,
        authorizationExecutionReadiness,
        authorizationExecutionReadinessCollectionResult:
          authorizationExecutionReadiness?.collectionResult
      });
    },
    requestIntent(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Intent request shape validation completed.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestAuthorization(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "authorization_request",
        summary: "Authorization request shape validation completed; no authorization was created.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestMessageSignature(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Message signature request shape validation completed; nothing was signed.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestTransactionPreparation(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Transaction preparation request shape validation completed.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestTransactionSubmission(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Transaction submission request shape validation completed; nothing was submitted.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestContractCall(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Contract call request shape validation completed; no adapter was called.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestSmartAccountDeployment(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Smart Account deployment request shape validation completed; nothing was deployed.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestSessionKeyManagement(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Session key management request shape validation completed.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestCredentialRotation(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Credential rotation request shape validation completed; no credential changed.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestCredentialRevocation(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Credential revocation request shape validation completed; no credential changed.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestEncryptedBackupExport(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Encrypted backup export request shape validation completed; no backup was exported.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestRecoveryStart(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Recovery start request shape validation completed; recovery did not start.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestRecoveryApproval(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "intent",
        summary: "Recovery approval request shape validation completed; recovery was not approved.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestAuditReview(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: validateIntentRequestIntake(envelope),
        envelope,
        category: "runtime",
        summary: "Audit review request shape validation completed; no audit data was read.",
        auditDraftCollector: options.auditDraftCollector
      });
    },
    requestScopedAgentPermission(request) {
      const envelope = intentEnvelope(request, userSessionContextFromOptions(options));
      return wrapIntakeWithAuditDraft({
        intake: unsupportedFutureScopedAgentPermission(),
        envelope,
        category: "future_ai",
        outcome: "unsupported",
        summary: "Future scoped agent permission request is unsupported by the validation facade.",
        auditDraftCollector: options.auditDraftCollector
      });
    }
  };
}

export function validateRuntimeApiFacadeEnvelope(
  envelope: RuntimeRequestEnvelope,
  options: ValidationOnlyRuntimeApiOptions = {}
): ValidationOnlyRuntimeApiResult {
  const userSessionContext = userSessionContextFromOptions(options);
  const sessionBoundEnvelope: RuntimeRequestEnvelope = userSessionContext
    ? {
      ...envelope,
      context: envelope.context
        ? bindOptionalSessionContext(envelope.context, userSessionContext)
        : envelope.context
    }
    : envelope;

  return wrapIntakeWithAuditDraft({
    intake: validateRuntimeRequestIntake(sessionBoundEnvelope),
    envelope: sessionBoundEnvelope,
    category: "runtime",
    summary: "Runtime request envelope shape validation completed.",
    auditDraftCollector: options.auditDraftCollector
  });
}
