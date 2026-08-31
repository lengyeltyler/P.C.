import type { BigNumberish } from "ethers";

import type {
  BaseActionAuthorization,
  Hex,
  UnlockProofPackage,
  UnlockProofPublicInputs,
  UnlockRequest
} from "../hashes.ts";
import type {
  ResolvedOwnerCommitment,
  UnlockAuthorizationAssembly
} from "../authorization.ts";
import type {
  PhilDeviceIdentityProviderKind,
  PhilDevicePublicMetadata
} from "../deviceIdentity.ts";
import type { PhilIdentityPublic } from "../identity.ts";

export type RuntimeLayer = "identity" | "decision" | "execution";

export type RuntimeBoundary =
  | "identity-root"
  | "device-vault"
  | "trust-manager"
  | "authorization-engine"
  | "security-policy-engine"
  | "proof-system"
  | "recovery-manager"
  | "audit-log"
  | "user-session"
  | "runtime-api"
  | "applications-layer"
  | "adapter-layer";

export type ApplicationId =
  | "ethereum-net"
  | "nft-manager"
  | "recovery"
  | "audit-log"
  | "future-ai-permissions"
  | (string & {});

export type AdapterId =
  | "ethereum"
  | "ethereum-base-profile"
  | "future-ai-agent-execution"
  | (string & {});

export type RuntimePlatform =
  | "native-ios"
  | "native-android"
  | "desktop"
  | "browser-extension"
  | "pwa-candidate"
  | "local-dev";

export type RuntimeEnvironment = "local-dev" | "test" | "staging" | "production";

export type RuntimeVersion = string;
export type SdkVersion = string;
export type MinimumRuntimeVersion = RuntimeVersion;
export type DeprecatedSince = RuntimeVersion;
export type ExperimentalSince = RuntimeVersion;

export interface CompatibilityRange {
  readonly minimumRuntimeVersion?: MinimumRuntimeVersion;
  readonly maximumRuntimeVersion?: RuntimeVersion;
  readonly minimumSdkVersion?: SdkVersion;
  readonly maximumSdkVersion?: SdkVersion;
  readonly deprecatedSince?: DeprecatedSince;
  readonly experimentalSince?: ExperimentalSince;
}

export interface RuntimeCompatibility {
  readonly runtimeVersion?: RuntimeVersion;
  readonly sdkVersion?: SdkVersion;
  readonly range?: CompatibilityRange;
  readonly compatible: boolean;
  readonly reason?: string;
}

export type CapabilityName =
  | EthereumNetCapability
  | NftManagerCapability
  | RecoveryAppCapability
  | AuditLogAppCapability
  | FutureAiPermissionsCapability
  | (string & {});

export type EthereumNetCapability =
  | "read_balance"
  | "view_transactions"
  | "view_nfts"
  | "request_message_signature"
  | "prepare_transaction"
  | "request_transaction_submission"
  | "request_contract_call"
  | "request_smart_account_deployment"
  | "manage_session_keys";

export type NftManagerCapability =
  | "view_nfts"
  | "read_metadata"
  | "prepare_mint"
  | "request_mint_submission"
  | "prepare_transfer"
  | "request_transfer_submission";

export type RecoveryAppCapability =
  | "view_recovery_state"
  | "start_recovery"
  | "approve_recovery"
  | "complete_recovery"
  | "rotate_trust_credential"
  | "revoke_trust_credential";

export type AuditLogAppCapability =
  | "view_audit_events"
  | "export_encrypted_audit_bundle"
  | "verify_audit_integrity";

export type FutureAiPermissionsCapability =
  | "request_scoped_permission"
  | "draft_action"
  | "request_user_approval"
  | "execute_limited_action"
  | "revoke_agent_permission";

export type CapabilityDecision =
  | "granted"
  | "denied"
  | "scoped"
  | "expired"
  | "revoked"
  | "pending";

export type CapabilitySensitivity = "read" | "sensitive" | "privileged";

export interface CapabilityScope {
  readonly applicationId?: ApplicationId;
  readonly adapterId?: AdapterId;
  readonly resource?: string;
  readonly action?: string;
  readonly chainId?: BigNumberish;
  readonly account?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface CapabilityRequest {
  readonly requestId: string;
  readonly applicationId: ApplicationId;
  readonly capability: CapabilityName;
  readonly sensitivity: CapabilitySensitivity;
  readonly scope?: CapabilityScope;
  readonly reason?: string;
  readonly requestedAt?: string;
}

export interface CapabilityGrant {
  readonly grantId: string;
  readonly requestId: string;
  readonly applicationId: ApplicationId;
  readonly capability: CapabilityName;
  readonly decision: CapabilityDecision;
  readonly scope?: CapabilityScope;
  readonly grantedAt?: string;
  readonly expiresAt?: string;
  readonly revokedAt?: string;
  readonly auditEventId?: string;
}

export type ApplicationVersion = string;
export type AdapterVersion = string;

export type ApplicationTrustLevel =
  | "system"
  | "verified"
  | "community"
  | "developer"
  | "experimental";

export type AdapterTrustLevel = "core" | "verified" | "experimental";

export type ApplicationStatus =
  | "available"
  | "installed"
  | "disabled"
  | "suspended"
  | "deprecated"
  | "experimental";

export type ApplicationVisibility = "system" | "visible" | "hidden" | "developer";

export type ApplicationCategory =
  | "wallet"
  | "nft"
  | "recovery"
  | "audit"
  | "security"
  | "future-ai-permissions"
  | "developer"
  | (string & {});

export type ApplicationInstallState =
  | "not-installed"
  | "installing"
  | "installed"
  | "updating"
  | "removed";

export type ApplicationOrigin =
  | "philcore-system"
  | "local-development"
  | "verified-publisher"
  | "community"
  | "developer"
  | "experimental"
  | (string & {});

export interface ApplicationIdentity {
  readonly applicationId: ApplicationId;
  readonly origin: ApplicationOrigin;
  readonly publisher?: string;
  readonly publisherId?: string;
}

export interface ApplicationMetadata {
  readonly displayName: string;
  readonly description?: string;
  readonly category: ApplicationCategory;
  readonly visibility: ApplicationVisibility;
  readonly trustLevel: ApplicationTrustLevel;
  readonly homepageUrl?: string;
  readonly supportUrl?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ApplicationCapabilityDeclaration {
  readonly capability: CapabilityName;
  readonly sensitivity: CapabilitySensitivity;
  readonly required: boolean;
  readonly defaultScope?: CapabilityScope;
  readonly reason?: string;
}

export interface ApplicationPermissionDescriptor {
  readonly permissionId: string;
  readonly capability: CapabilityName;
  readonly scope?: CapabilityScope;
  readonly sensitivity: CapabilitySensitivity;
  readonly requiresUserApproval: boolean;
  readonly requiresTrust?: boolean;
  readonly requiresProof?: ProofRequirement;
}

export interface ApplicationPermissionRequest {
  readonly requestId: string;
  readonly applicationId: ApplicationId;
  readonly permissions: readonly ApplicationPermissionDescriptor[];
  readonly requestedAt?: string;
  readonly reason?: string;
}

export interface ApplicationCompatibility {
  readonly runtime: RuntimeCompatibility;
  readonly platforms?: readonly RuntimePlatform[];
  readonly adapters?: readonly AdapterId[];
}

export interface ApplicationRegistration {
  readonly identity: ApplicationIdentity;
  readonly metadata: ApplicationMetadata;
  readonly version: ApplicationVersion;
  readonly compatibility: ApplicationCompatibility;
  readonly capabilities: readonly ApplicationCapabilityDeclaration[];
  readonly installState?: ApplicationInstallState;
  readonly status?: ApplicationStatus;
  readonly manifest?: ApplicationManifest;
}

export type RuntimeResultStatus = "approved" | "denied" | "pending" | "failed";

export interface RuntimeRequestContext {
  readonly requestId: string;
  readonly sessionId?: string;
  readonly applicationId: ApplicationId;
  readonly requestedAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface RuntimeResult<TValue = unknown> {
  readonly status: RuntimeResultStatus;
  readonly value?: TValue;
  readonly error?: RuntimeErrorDescriptor;
  readonly auditEventId?: string;
  readonly pendingApprovalId?: string;
}

export type IntentKind =
  | "read"
  | "authorize"
  | "sign"
  | "prepare-transaction"
  | "submit-transaction"
  | "call-contract"
  | "deploy-smart-account"
  | "credential-rotation"
  | "credential-revocation"
  | "encrypted-backup-export"
  | "recovery-start"
  | "recovery-approval"
  | "audit-review"
  | "scoped-agent-permission";

export type IntentStatus =
  | "created"
  | "evaluating"
  | "approved"
  | "denied"
  | "expired"
  | "cancelled"
  | "executed"
  | "failed";

export interface Intent<TPayload = unknown> {
  readonly intentId: string;
  readonly kind: IntentKind;
  readonly applicationId: ApplicationId;
  readonly requestedCapabilities: readonly CapabilityName[];
  readonly payload: TPayload;
  readonly status?: IntentStatus;
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface EthereumTransactionIntentPayload {
  readonly chainId: BigNumberish;
  readonly account?: string;
  readonly target: string;
  readonly value?: BigNumberish;
  readonly callData?: Hex;
}

export interface EthereumContractCallIntentPayload {
  readonly chainId: BigNumberish;
  readonly account?: string;
  readonly target: string;
  readonly callData: Hex;
  readonly value?: BigNumberish;
}

export interface EthereumMessageSignatureIntentPayload {
  readonly chainId?: BigNumberish;
  readonly account?: string;
  readonly messageHash?: Hex;
  readonly message?: string;
}

export interface EthereumSmartAccountDeploymentIntentPayload {
  readonly chainId: BigNumberish;
  readonly ownerCommitment?: Hex;
  readonly entryPoint?: string;
  readonly factory?: string;
  readonly salt?: Hex;
}

export interface SessionKeyManagementIntentPayload {
  readonly chainId: BigNumberish;
  readonly smartAccount?: string;
  readonly action: "create" | "rotate" | "revoke" | "list";
  readonly sessionKeyId?: string;
  readonly capabilities?: readonly CapabilityName[];
  readonly expiresAt?: string;
}

export interface TrustCredentialRotationIntentPayload {
  readonly credentialId: string;
  readonly replacementCredentialId?: string;
  readonly credentialKind?: TrustCredentialSummary["credentialKind"];
  readonly reason?: string;
}

export interface TrustCredentialRevocationIntentPayload {
  readonly credentialId: string;
  readonly credentialKind?: TrustCredentialSummary["credentialKind"];
  readonly reason?: string;
  readonly recoveryRequired?: boolean;
}

export interface EncryptedBackupExportIntentPayload {
  readonly includeAuditEvents?: boolean;
  readonly includeRecoveryState?: boolean;
  readonly destinationHint?: string;
  readonly encryptionProfile?: string;
}

export interface RecoveryStartIntentPayload {
  readonly recoveryReason: "lost-device" | "credential-compromise" | "user-request" | (string & {});
  readonly recoveryCredentialId?: string;
  readonly targetOwnerCommitment?: Hex;
}

export interface RecoveryApprovalIntentPayload {
  readonly recoverySessionId: string;
  readonly approvingCredentialId?: string;
  readonly approvalScope?: CapabilityScope;
}

export interface AuditReviewIntentPayload {
  readonly from?: string;
  readonly to?: string;
  readonly kinds?: readonly AuditEventKind[];
  readonly includeEncryptedExport?: boolean;
}

export interface FutureScopedAgentPermissionIntentPayload {
  readonly agentId: string;
  readonly requestedCapabilities: readonly CapabilityName[];
  readonly scope: CapabilityScope;
  readonly expiresAt?: string;
  readonly humanApprovalRequired: true;
}

export interface UserSessionState {
  readonly sessionId: string;
  readonly activeIdentity?: PhilIdentityPublic;
  readonly ownerCommitment?: Hex;
  readonly vaultUnlockState: "locked" | "unlocking" | "unlocked" | "suspended";
  readonly trustState: "unknown" | "loading" | "trusted" | "restricted" | "recovery-only";
  readonly policyMode: "default" | "strict" | "recovery" | "local-dev";
  readonly activeApplications: readonly ApplicationId[];
  readonly activeCapabilities: readonly CapabilityGrant[];
  readonly pendingApprovals: readonly string[];
  readonly activeAuthorizationSessions: readonly string[];
  readonly lockTimeoutAt?: string;
  readonly suspendedAt?: string;
}

export type UserSessionContextStatus =
  | "locked"
  | "partially-unlocked"
  | "unlocked"
  | "recovery"
  | "suspended";

export interface UserSessionMetadata {
  readonly createdAt?: string;
  readonly updatedAt?: string;
  readonly expiresAt?: string;
  readonly lockTimeoutAt?: string;
  readonly suspendedAt?: string;
  readonly lifecycleState?: string;
  readonly lifecycleTransitionSequence?: number;
  readonly lastLifecycleTransitionAt?: string;
  readonly authenticationEvidenceReferenceId?: string;
  readonly deviceVaultUnlocked?: boolean;
  readonly protectedStateAvailable?: boolean;
  readonly activeCapabilitiesAvailable?: false;
  readonly authorizationAvailable?: false;
  readonly vaultHandleId?: string;
  readonly vaultUnlockedAt?: string;
  readonly strongerVaultUnlockRequired?: boolean;
  readonly requestMetadata?: Readonly<Record<string, unknown>>;
}

// Ephemeral, non-secret runtime session context. This object must not own or expose
// phil_secret, raw vault keys, private keys, unrestricted signing authority, or vault access.
export interface UserSessionContext {
  readonly sessionId: string;
  readonly ownerCommitment?: Hex;
  readonly status: UserSessionContextStatus;
  readonly activeApplicationId?: ApplicationId;
  readonly activeCapabilityIds: readonly string[];
  readonly pendingIntentIds: readonly string[];
  readonly policyMode: UserSessionState["policyMode"];
  readonly recoveryState?: "inactive" | "available" | "pending" | "active" | "completed";
  readonly timeout?: {
    readonly lockTimeoutAt?: string;
    readonly suspendedAt?: string;
  };
  readonly metadata?: UserSessionMetadata;
}

export interface UserSessionSnapshot {
  readonly context: UserSessionContext;
  readonly capturedAt: string;
}

export interface UserSessionContextInput {
  readonly sessionId: string;
  readonly ownerCommitment?: Hex;
  readonly status: UserSessionContextStatus;
  readonly activeApplicationId?: ApplicationId;
  readonly activeCapabilityIds?: readonly string[];
  readonly pendingIntentIds?: readonly string[];
  readonly policyMode?: UserSessionState["policyMode"];
  readonly recoveryState?: UserSessionContext["recoveryState"];
  readonly timeout?: UserSessionContext["timeout"];
  readonly metadata?: UserSessionMetadata;
}

export interface UserSessionContextResult {
  readonly status: RuntimeResultStatus;
  readonly context?: UserSessionContext;
  readonly snapshot?: UserSessionSnapshot;
  readonly errors?: readonly string[];
}

export interface SessionBoundRuntimeRequestContext extends RuntimeRequestContext {
  readonly sessionId: string;
  readonly userSession: UserSessionContext;
}

export interface TrustCredentialSummary {
  readonly credentialId: string;
  readonly credentialKind:
    | "device"
    | "passkey"
    | "webauthn"
    | "recovery"
    | "local-dev"
    | (string & {});
  readonly providerKind?: PhilDeviceIdentityProviderKind;
  readonly state: "active" | "rotated" | "revoked" | "recovery-only" | "unknown";
  readonly device?: PhilDevicePublicMetadata;
  readonly createdAt?: string;
  readonly updatedAt?: string;
}

export type TrustDecision = "trusted" | "denied" | "requires-escalation" | "recovery-only";

export type TrustDecisionReason =
  | "active-trusted-credential"
  | "credential-revoked"
  | "credential-rotated"
  | "credential-missing"
  | "device-untrusted"
  | "recovery-only-credential"
  | "hardware-backed-required"
  | "passkey-required"
  | "manual-review-required"
  | (string & {});

export type TrustRequirementLevel =
  | "none"
  | "trusted-device"
  | "trusted-passkey"
  | "hardware-backed"
  | "recovery-only"
  | "multiple-credentials";

export interface TrustCredentialRequirement {
  readonly credentialKind?: TrustCredentialSummary["credentialKind"];
  readonly providerKind?: PhilDeviceIdentityProviderKind;
  readonly credentialId?: string;
  readonly hardwareBacked?: boolean;
  readonly productionSafe?: boolean;
  readonly state?: TrustCredentialSummary["state"];
}

export interface TrustEscalationRequirement {
  readonly level: TrustRequirementLevel;
  readonly reason: TrustDecisionReason;
  readonly acceptableCredentials?: readonly TrustCredentialRequirement[];
  readonly userApprovalRequired?: boolean;
  readonly recoveryRequired?: boolean;
}

export interface TrustRequirement {
  readonly level: TrustRequirementLevel;
  readonly credentials?: readonly TrustCredentialRequirement[];
  readonly escalation?: TrustEscalationRequirement;
}

export interface TrustEvaluationRequest {
  readonly requestId: string;
  readonly session: UserSessionState;
  readonly intent: Intent;
  readonly capabilityGrants?: readonly CapabilityGrant[];
  readonly availableCredentials?: readonly TrustCredentialSummary[];
  readonly requirement?: TrustRequirement;
}

export interface TrustEvaluationResult {
  readonly evaluationId: string;
  readonly decision: TrustDecision;
  readonly reasons?: readonly TrustDecisionReason[];
  readonly satisfiedRequirements?: readonly TrustRequirement[];
  readonly missingRequirements?: readonly TrustRequirement[];
  readonly escalation?: TrustEscalationRequirement;
  readonly credential?: TrustCredentialSummary;
  readonly auditEventId?: string;
}

export interface ApplicationManifest {
  readonly applicationId: ApplicationId;
  readonly displayName: string;
  readonly version: string;
  readonly requestedCapabilities: readonly CapabilityName[];
  readonly optionalCapabilities?: readonly CapabilityName[];
  readonly supportedPlatforms?: readonly RuntimePlatform[];
  readonly adapterDependencies?: readonly AdapterId[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type AdapterExecutionEnvironment =
  | "ethereum"
  | "base-profile"
  | "local-dev"
  | "future-experimental"
  | (string & {});

export type AdapterStatus =
  | "available"
  | "unavailable"
  | "disabled"
  | "deprecated"
  | "experimental";

export type AdapterAvailability =
  | "online"
  | "offline"
  | "degraded"
  | "unknown"
  | "not-configured";

export interface AdapterIdentity {
  readonly adapterId: AdapterId;
  readonly executionEnvironment: AdapterExecutionEnvironment;
  readonly profile?: AdapterProfile;
}

export interface AdapterProfile {
  readonly profileId: string;
  readonly displayName: string;
  readonly chainId?: BigNumberish;
  readonly networkName?: string;
  readonly environment?: RuntimeEnvironment;
}

export interface AdapterMetadata {
  readonly displayName: string;
  readonly description?: string;
  readonly trustLevel: AdapterTrustLevel;
  readonly maintainer?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface AdapterCapabilities {
  readonly providedCapabilities: readonly CapabilityName[];
  readonly requiredCapabilities?: readonly CapabilityName[];
  readonly supportsAuthorizationPackages: boolean;
  readonly supportsProofBackedAuthorization?: boolean;
}

export interface AdapterCompatibility {
  readonly runtime: RuntimeCompatibility;
  readonly applications?: readonly ApplicationId[];
  readonly platforms?: readonly RuntimePlatform[];
}

export interface AdapterHealth {
  readonly availability: AdapterAvailability;
  readonly checkedAt?: string;
  readonly reason?: string;
}

export interface AdapterConfigurationReference {
  readonly configurationId: string;
  readonly profileId?: string;
  readonly description?: string;
  readonly secretFree: true;
}

export interface AdapterRegistration {
  readonly identity: AdapterIdentity;
  readonly metadata: AdapterMetadata;
  readonly version: AdapterVersion;
  readonly compatibility: AdapterCompatibility;
  readonly capabilities: AdapterCapabilities;
  readonly configuration?: AdapterConfigurationReference;
  readonly status?: AdapterStatus;
  readonly health?: AdapterHealth;
  readonly manifest?: AdapterManifest;
}

export interface AdapterExecutionResult<TResult = unknown> {
  readonly status: RuntimeResultStatus;
  readonly adapterId: AdapterId;
  readonly authorizationPackageId?: string;
  readonly result?: TResult;
  readonly error?: RuntimeErrorDescriptor;
  readonly auditEventId?: string;
}

export interface AdapterManifest {
  readonly adapterId: AdapterId;
  readonly displayName: string;
  readonly version: string;
  readonly executionEnvironment: AdapterExecutionEnvironment;
  readonly providedCapabilities: readonly CapabilityName[];
  readonly supportedApplications?: readonly ApplicationId[];
  readonly requiresAuthorizationPackage: boolean;
  readonly requiresProof?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type AuthorizationDecision = "approved" | "denied" | "requires-proof" | "requires-review";

export type PolicyMode = UserSessionState["policyMode"];

export type PolicyDecision =
  | "allow"
  | "deny"
  | "requires-user-approval"
  | "requires-proof"
  | "requires-trust-escalation"
  | "requires-recovery";

export type PolicyDecisionReason =
  | "capability-allowed"
  | "capability-denied"
  | "trust-insufficient"
  | "proof-required"
  | "user-approval-required"
  | "risk-too-high"
  | "runtime-locked"
  | "recovery-required"
  | "experimental-feature-disabled"
  | (string & {});

export type PolicyRiskLevel = "low" | "medium" | "high" | "critical";

export interface PolicyConstraint {
  readonly constraintId: string;
  readonly boundary?: RuntimeBoundary;
  readonly description?: string;
  readonly riskLevel?: PolicyRiskLevel;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface PolicyEscalationRequirement {
  readonly reason: PolicyDecisionReason;
  readonly requiredTrust?: TrustRequirement;
  readonly requiredApproval?: UserApprovalRequirement;
  readonly requiredProof?: ProofRequirement;
}

export interface PolicyRequirement {
  readonly requirementId: string;
  readonly capabilities?: readonly CapabilityName[];
  readonly constraints?: readonly PolicyConstraint[];
  readonly trust?: TrustRequirement;
  readonly proof?: ProofRequirement;
  readonly userApproval?: UserApprovalRequirement;
}

export interface PolicyEvaluationRequest {
  readonly requestId: string;
  readonly session: UserSessionState;
  readonly intent: Intent;
  readonly capabilityGrants: readonly CapabilityGrant[];
  readonly trust?: TrustEvaluationResult;
  readonly policyMode: PolicyMode;
}

export interface PolicyEvaluationResult {
  readonly policyEvaluationId: string;
  readonly decision: PolicyDecision;
  readonly mode: PolicyMode;
  readonly riskLevel?: PolicyRiskLevel;
  readonly reasons?: readonly PolicyDecisionReason[];
  readonly requirements?: readonly PolicyRequirement[];
  readonly constraints?: readonly PolicyConstraint[];
  readonly escalation?: PolicyEscalationRequirement;
  readonly auditEventId?: string;
}

export interface PolicyEvaluation {
  readonly policyEvaluationId: string;
  readonly decision: AuthorizationDecision;
  readonly policyMode: PolicyMode;
  readonly reasons?: readonly string[];
  readonly requiredCapabilities?: readonly CapabilityName[];
  readonly requiredProof?: ProofRequirement;
}

export type ProofRequirement =
  | "not-required"
  | "optional"
  | "required"
  | "not-production-ready";

export interface ProofBackedAuthorizationBoundary {
  readonly proofRequirement: ProofRequirement;
  readonly proofPackage?: UnlockProofPackage;
  readonly publicInputs?: UnlockProofPublicInputs;
}

export type RequestCapabilityRequest = CapabilityRequest;
export type RequestCapabilityResponse = RuntimeResult<CapabilityGrant>;

export interface RequestIntentRequest<TIntent extends Intent = Intent> extends RuntimeRequestContext {
  readonly intent: TIntent;
}

export type RequestIntentResponse<TIntent extends Intent = Intent> = RuntimeResult<TIntent>;

export interface RequestAuthorizationRequest<TPayload = unknown> extends RuntimeRequestContext {
  readonly intent: Intent<TPayload>;
}

export type RequestAuthorizationResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestMessageSignatureRequest extends RuntimeRequestContext {
  readonly intent: Intent<EthereumMessageSignatureIntentPayload>;
}

export type RequestMessageSignatureResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestTransactionPreparationRequest extends RuntimeRequestContext {
  readonly intent: Intent<EthereumTransactionIntentPayload>;
}

export type RequestTransactionPreparationResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestTransactionSubmissionRequest extends RuntimeRequestContext {
  readonly intent: Intent<EthereumTransactionIntentPayload>;
}

export type RequestTransactionSubmissionResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestContractCallRequest extends RuntimeRequestContext {
  readonly intent: Intent<EthereumContractCallIntentPayload>;
}

export type RequestContractCallResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestSmartAccountDeploymentRequest extends RuntimeRequestContext {
  readonly intent: Intent<EthereumSmartAccountDeploymentIntentPayload>;
}

export type RequestSmartAccountDeploymentResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestSessionKeyManagementRequest extends RuntimeRequestContext {
  readonly intent: Intent<SessionKeyManagementIntentPayload>;
}

export type RequestSessionKeyManagementResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestCredentialRotationRequest extends RuntimeRequestContext {
  readonly intent: Intent<TrustCredentialRotationIntentPayload>;
}

export type RequestCredentialRotationResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestCredentialRevocationRequest extends RuntimeRequestContext {
  readonly intent: Intent<TrustCredentialRevocationIntentPayload>;
}

export type RequestCredentialRevocationResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestEncryptedBackupExportRequest extends RuntimeRequestContext {
  readonly intent: Intent<EncryptedBackupExportIntentPayload>;
}

export type RequestEncryptedBackupExportResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestRecoveryStartRequest extends RuntimeRequestContext {
  readonly intent: Intent<RecoveryStartIntentPayload>;
}

export type RequestRecoveryStartResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestRecoveryApprovalRequest extends RuntimeRequestContext {
  readonly intent: Intent<RecoveryApprovalIntentPayload>;
}

export type RequestRecoveryApprovalResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestAuditReviewRequest extends RuntimeRequestContext {
  readonly intent: Intent<AuditReviewIntentPayload>;
}

export type RequestAuditReviewResponse = RuntimeResult<AuthorizationPackageBoundary>;

export interface RequestScopedAgentPermissionRequest extends RuntimeRequestContext {
  readonly intent: Intent<FutureScopedAgentPermissionIntentPayload>;
  readonly futureOnly: true;
}

export type RequestScopedAgentPermissionResponse = RuntimeResult<AuthorizationPackageBoundary>;

export type UserApprovalDecision = "approved" | "denied" | "cancelled" | "expired";

export type UserApprovalSurface =
  | "native-ios"
  | "native-android"
  | "desktop"
  | "browser-extension"
  | "cli"
  | "local-dev"
  | (string & {});

export interface UserApprovalRiskDisclosure {
  readonly riskLevel: PolicyRiskLevel;
  readonly summary: string;
  readonly details?: readonly string[];
}

export interface UserApprovalSummary {
  readonly title: string;
  readonly description?: string;
  readonly applicationId: ApplicationId;
  readonly requestedCapabilities: readonly CapabilityName[];
  readonly adapterId?: AdapterId;
  readonly risk?: UserApprovalRiskDisclosure;
}

export interface UserApprovalRequirement {
  readonly required: boolean;
  readonly surface?: UserApprovalSurface;
  readonly reason?: PolicyDecisionReason | TrustDecisionReason;
  readonly riskDisclosure?: UserApprovalRiskDisclosure;
}

export interface UserApprovalRequest {
  readonly approvalRequestId: string;
  readonly sessionId: string;
  readonly intent: Intent;
  readonly summary: UserApprovalSummary;
  readonly requirement: UserApprovalRequirement;
  readonly expiresAt?: string;
}

export interface UserApprovalResult {
  readonly approvalRequestId: string;
  readonly decision: UserApprovalDecision;
  readonly decidedAt?: string;
  readonly surface?: UserApprovalSurface;
  readonly auditEventId?: string;
}

export type AuthorizationDecisionReason =
  | "trust-approved"
  | "trust-denied"
  | "policy-approved"
  | "policy-denied"
  | "user-approved"
  | "user-denied"
  | "proof-required"
  | "proof-attached"
  | "adapter-ready"
  | "invalid-authorization-package"
  | (string & {});

export interface AuthorizationDecisionTrace {
  readonly traceId: string;
  readonly intentId: string;
  readonly capabilityIds?: readonly string[];
  readonly trust?: TrustEvaluationResult;
  readonly policy?: PolicyEvaluationResult;
  readonly userApproval?: UserApprovalResult;
  readonly proofRequirement?: ProofRequirement;
  readonly reasons?: readonly AuthorizationDecisionReason[];
}

export interface AuthorizationDecisionRequest {
  readonly requestId: string;
  readonly session: UserSessionState;
  readonly intent: Intent;
  readonly capabilityGrants: readonly CapabilityGrant[];
  readonly trust: TrustEvaluationResult;
  readonly policy: PolicyEvaluationResult;
  readonly userApproval?: UserApprovalResult;
}

export interface AuthorizationDecisionResult {
  readonly decision: AuthorizationDecision;
  readonly reasons?: readonly AuthorizationDecisionReason[];
  readonly trace: AuthorizationDecisionTrace;
  readonly error?: RuntimeErrorDescriptor;
  readonly auditEventId?: string;
}

export interface AuthorizationPackageRequest<TAdapterPayload = unknown> {
  readonly requestId: string;
  readonly decision: AuthorizationDecisionResult;
  readonly adapterId: AdapterId;
  readonly adapterPayload: TAdapterPayload;
  readonly proof?: ProofBackedAuthorizationBoundary;
}

export type AuthorizationPackageResult<TAdapterPayload = unknown> =
  RuntimeResult<AuthorizationPackageBoundary<TAdapterPayload>>;

export interface AuthorizationPackageBoundary<TAdapterPayload = unknown> {
  readonly authorizationPackageId: string;
  readonly intentId: string;
  readonly applicationId: ApplicationId;
  readonly adapterId: AdapterId;
  readonly ownerCommitment: ResolvedOwnerCommitment;
  readonly decision: "approved";
  readonly capabilities: readonly CapabilityGrant[];
  readonly policyEvaluation: PolicyEvaluation;
  readonly adapterPayload: TAdapterPayload;
  readonly proof?: ProofBackedAuthorizationBoundary;
  readonly auditEventId?: string;
  readonly createdAt?: string;
  readonly expiresAt?: string;
}

export interface UnlockAuthorizationPackageBoundary
  extends AuthorizationPackageBoundary<UnlockRequest> {
  readonly action: "ACTION_UNLOCK";
  readonly baseAuthorization: BaseActionAuthorization;
  readonly unlockAssembly?: UnlockAuthorizationAssembly;
  readonly proof: ProofBackedAuthorizationBoundary & {
    readonly proofPackage: UnlockProofPackage;
    readonly publicInputs: UnlockProofPublicInputs;
  };
}

export type AuditEventKind =
  | "runtime.boot"
  | "runtime.lock"
  | "runtime.suspend"
  | "vault.unlock.requested"
  | "vault.unlock.completed"
  | "trust.credential.loaded"
  | "trust.credential.rotated"
  | "trust.credential.revoked"
  | "application.registered"
  | "capability.requested"
  | "capability.granted"
  | "capability.denied"
  | "intent.created"
  | "authorization.requested"
  | "authorization.approved"
  | "authorization.denied"
  | "proof.requested"
  | "proof.attached"
  | "adapter.invoked"
  | "adapter.completed"
  | "recovery.started"
  | "recovery.approved"
  | "audit.export.requested";

export interface AuditEvent<TDetails = unknown> {
  readonly auditEventId: string;
  readonly kind: AuditEventKind;
  readonly occurredAt: string;
  readonly sessionId?: string;
  readonly applicationId?: ApplicationId;
  readonly adapterId?: AdapterId;
  readonly intentId?: string;
  readonly authorizationPackageId?: string;
  readonly capability?: CapabilityName;
  readonly boundary?: RuntimeBoundary;
  readonly details?: TDetails;
  readonly encryptedByDefault: true;
}

export type RuntimeErrorCategory =
  | "runtime_locked"
  | "session_expired"
  | "capability_denied"
  | "policy_denied"
  | "trust_denied"
  | "user_cancelled"
  | "proof_required"
  | "proof_failed"
  | "adapter_unavailable"
  | "network_unavailable"
  | "bundler_unavailable"
  | "vault_unavailable"
  | "recovery_required"
  | "invalid_intent"
  | "invalid_authorization_package"
  | "unsupported_operation"
  | "experimental_feature_disabled";

export interface RuntimeErrorDescriptor {
  readonly category: RuntimeErrorCategory;
  readonly code: string;
  readonly message: string;
  readonly boundary?: RuntimeBoundary;
  readonly intentId?: string;
  readonly capability?: CapabilityName;
  readonly recoverable: boolean;
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface RuntimeEventMap {
  readonly "runtime:booted": { readonly session: UserSessionState };
  readonly "runtime:locked": { readonly sessionId: string };
  readonly "runtime:suspended": { readonly sessionId: string };
  readonly "session:updated": { readonly session: UserSessionState };
  readonly "application:registered": { readonly manifest: ApplicationManifest };
  readonly "adapter:registered": { readonly manifest: AdapterManifest };
  readonly "capability:requested": { readonly request: CapabilityRequest };
  readonly "capability:decided": { readonly grant: CapabilityGrant };
  readonly "intent:created": { readonly intent: Intent };
  readonly "authorization:requested": { readonly intent: Intent };
  readonly "authorization:approved": { readonly package: AuthorizationPackageBoundary };
  readonly "authorization:denied": { readonly intentId: string; readonly error: RuntimeErrorDescriptor };
  readonly "proof:requested": { readonly intentId: string; readonly requirement: ProofRequirement };
  readonly "adapter:invoked": { readonly package: AuthorizationPackageBoundary };
  readonly "audit:recorded": { readonly event: AuditEvent };
  readonly "runtime:error": { readonly error: RuntimeErrorDescriptor };
}

export type RuntimeEventName = keyof RuntimeEventMap;

export interface RuntimeEventBus {
  publish<TName extends RuntimeEventName>(
    name: TName,
    event: RuntimeEventMap[TName]
  ): void | Promise<void>;
  subscribe<TName extends RuntimeEventName>(
    name: TName,
    handler: (event: RuntimeEventMap[TName]) => void | Promise<void>
  ): void | (() => void);
}

export type AdapterExecutionDecision = "execute" | "deny" | "defer" | "unavailable";

export type AdapterExecutionStatus =
  | "not-started"
  | "prepared"
  | "submitted"
  | "confirmed"
  | "failed"
  | "cancelled";

export interface AdapterExecutionFailure {
  readonly category: RuntimeErrorCategory;
  readonly message: string;
  readonly retryable?: boolean;
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface AdapterExecutionPlan {
  readonly executionPlanId: string;
  readonly adapterId: AdapterId;
  readonly manifest?: AdapterManifest;
  readonly authorizationPackageId: string;
  readonly requiredCapabilities?: readonly CapabilityName[];
  readonly proofRequirement?: ProofRequirement;
  readonly steps?: readonly string[];
}

export interface AdapterExecutionRequest<TAdapterPayload = unknown> {
  readonly requestId: string;
  readonly plan: AdapterExecutionPlan;
  readonly authorizationPackage: AuthorizationPackageBoundary<TAdapterPayload>;
}

export interface AdapterExecutionReceipt<TResult = unknown> {
  readonly receiptId: string;
  readonly adapterId: AdapterId;
  readonly status: AdapterExecutionStatus;
  readonly result?: TResult;
  readonly failure?: AdapterExecutionFailure;
  readonly submittedAt?: string;
  readonly completedAt?: string;
  readonly auditEventId?: string;
}

export interface AdapterExecutionDecisionResult<TResult = unknown> {
  readonly decision: AdapterExecutionDecision;
  readonly plan?: AdapterExecutionPlan;
  readonly receipt?: AdapterExecutionReceipt<TResult>;
  readonly executionResult?: AdapterExecutionResult<TResult>;
  readonly error?: RuntimeErrorDescriptor;
}

export interface RuntimeDecisionTrace<TAdapterPayload = unknown, TAdapterResult = unknown> {
  readonly traceId: string;
  readonly intentId: string;
  readonly capabilityId?: string;
  readonly sessionId?: string;
  readonly applicationId: ApplicationId;
  readonly adapterId?: AdapterId;
  readonly trustDecision?: TrustEvaluationResult;
  readonly policyDecision?: PolicyEvaluationResult;
  readonly userApprovalDecision?: UserApprovalResult;
  readonly proofRequirement?: ProofRequirement;
  readonly authorizationDecision?: AuthorizationDecisionResult;
  readonly authorizationPackage?: AuthorizationPackageBoundary<TAdapterPayload>;
  readonly adapterExecutionStatus?: AdapterExecutionStatus;
  readonly adapterExecutionReceipt?: AdapterExecutionReceipt<TAdapterResult>;
  readonly auditCorrelationId?: string;
}

export interface ApplicationFilter {
  readonly applicationIds?: readonly ApplicationId[];
  readonly categories?: readonly ApplicationCategory[];
  readonly trustLevels?: readonly ApplicationTrustLevel[];
  readonly statuses?: readonly ApplicationStatus[];
  readonly visibility?: readonly ApplicationVisibility[];
  readonly installStates?: readonly ApplicationInstallState[];
  readonly capabilities?: readonly CapabilityName[];
  readonly platform?: RuntimePlatform;
}

export interface AdapterFilter {
  readonly adapterIds?: readonly AdapterId[];
  readonly trustLevels?: readonly AdapterTrustLevel[];
  readonly statuses?: readonly AdapterStatus[];
  readonly availability?: readonly AdapterAvailability[];
  readonly executionEnvironments?: readonly AdapterExecutionEnvironment[];
  readonly capabilities?: readonly CapabilityName[];
  readonly applicationId?: ApplicationId;
}

export interface CapabilityFilter {
  readonly capabilities?: readonly CapabilityName[];
  readonly sensitivity?: readonly CapabilitySensitivity[];
  readonly applicationId?: ApplicationId;
  readonly adapterId?: AdapterId;
}

export interface ApplicationQuery {
  readonly text?: string;
  readonly filter?: ApplicationFilter;
  readonly limit?: number;
  readonly cursor?: string;
}

export interface AdapterQuery {
  readonly text?: string;
  readonly filter?: AdapterFilter;
  readonly limit?: number;
  readonly cursor?: string;
}

export interface CapabilityQuery {
  readonly text?: string;
  readonly filter?: CapabilityFilter;
  readonly limit?: number;
  readonly cursor?: string;
}

export interface SearchResult<TItem = unknown> {
  readonly item: TItem;
  readonly score?: number;
  readonly matchedFields?: readonly string[];
}

export interface DiscoveryResult<TItem = unknown> {
  readonly items: readonly TItem[];
  readonly nextCursor?: string;
  readonly totalCount?: number;
}

export interface ApplicationRegistry {
  registerApplication(registration: ApplicationRegistration): Promise<ApplicationRegistration>;
  getApplication(applicationId: ApplicationId): Promise<ApplicationRegistration | undefined>;
  listApplications(filter?: ApplicationFilter): Promise<readonly ApplicationRegistration[]>;
  queryApplications(query: ApplicationQuery): Promise<DiscoveryResult<ApplicationRegistration>>;
}

export interface AdapterRegistry {
  registerAdapter(registration: AdapterRegistration): Promise<AdapterRegistration>;
  getAdapter(adapterId: AdapterId): Promise<AdapterRegistration | undefined>;
  listAdapters(filter?: AdapterFilter): Promise<readonly AdapterRegistration[]>;
  queryAdapters(query: AdapterQuery): Promise<DiscoveryResult<AdapterRegistration>>;
}

export interface RuntimeLookup {
  resolveApplication(applicationId: ApplicationId): Promise<ApplicationRegistration | undefined>;
  resolveAdapter(adapterId: AdapterId): Promise<AdapterRegistration | undefined>;
  resolveCapability(
    capability: CapabilityName,
    filter?: CapabilityFilter
  ): Promise<DiscoveryResult<ApplicationRegistration | AdapterRegistration>>;
}

export interface RuntimeDiscovery {
  applications(query?: ApplicationQuery): Promise<DiscoveryResult<ApplicationRegistration>>;
  adapters(query?: AdapterQuery): Promise<DiscoveryResult<AdapterRegistration>>;
  capabilities(query?: CapabilityQuery): Promise<DiscoveryResult<CapabilityName>>;
}

export interface RuntimeApi {
  requestCapability(request: RequestCapabilityRequest): Promise<RequestCapabilityResponse>;
  requestIntent(request: RequestIntentRequest): Promise<RequestIntentResponse>;
  requestAuthorization(request: RequestAuthorizationRequest): Promise<RequestAuthorizationResponse>;
  requestMessageSignature(
    request: RequestMessageSignatureRequest
  ): Promise<RequestMessageSignatureResponse>;
  requestTransactionPreparation(
    request: RequestTransactionPreparationRequest
  ): Promise<RequestTransactionPreparationResponse>;
  requestTransactionSubmission(
    request: RequestTransactionSubmissionRequest
  ): Promise<RequestTransactionSubmissionResponse>;
  requestContractCall(request: RequestContractCallRequest): Promise<RequestContractCallResponse>;
  requestSmartAccountDeployment(
    request: RequestSmartAccountDeploymentRequest
  ): Promise<RequestSmartAccountDeploymentResponse>;
  requestSessionKeyManagement(
    request: RequestSessionKeyManagementRequest
  ): Promise<RequestSessionKeyManagementResponse>;
  requestCredentialRotation(
    request: RequestCredentialRotationRequest
  ): Promise<RequestCredentialRotationResponse>;
  requestCredentialRevocation(
    request: RequestCredentialRevocationRequest
  ): Promise<RequestCredentialRevocationResponse>;
  requestEncryptedBackupExport(
    request: RequestEncryptedBackupExportRequest
  ): Promise<RequestEncryptedBackupExportResponse>;
  requestRecoveryStart(request: RequestRecoveryStartRequest): Promise<RequestRecoveryStartResponse>;
  requestRecoveryApproval(
    request: RequestRecoveryApprovalRequest
  ): Promise<RequestRecoveryApprovalResponse>;
  requestAuditReview(request: RequestAuditReviewRequest): Promise<RequestAuditReviewResponse>;
  requestScopedAgentPermission(
    request: RequestScopedAgentPermissionRequest
  ): Promise<RequestScopedAgentPermissionResponse>;
}
