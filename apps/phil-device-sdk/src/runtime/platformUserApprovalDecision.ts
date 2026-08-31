import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type { AuthoritativePolicyDecision } from "./authoritativePolicyDecision.ts";
import { validateAuthoritativePolicyDecisionShape } from "./authoritativePolicyDecision.ts";
import type { AuthoritativeTrustDecision } from "./authoritativeTrustDecision.ts";
import { validateAuthoritativeTrustDecisionShape } from "./authoritativeTrustDecision.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  UserSessionLifecycleSnapshot,
  UserSessionLifecycleState
} from "./sessionLifecycle.ts";
import { validateUserSessionLifecycleSnapshotShape } from "./sessionLifecycle.ts";
import type {
  ApplicationId,
  CapabilityName,
  CapabilityScope,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type PlatformUserApprovalSurface =
  | "desktop_native"
  | "mobile_native"
  | "browser_extension"
  | "hardware_confirmation"
  | "recovery_surface"
  | "developer_fixture"
  | "unsupported";

export type PlatformUserApprovalArtifactOutcome =
  | "approved"
  | "denied"
  | "cancelled"
  | "expired";

export type PlatformUserApprovalDecisionStatus =
  | "approval_decision_created"
  | "approval_decision_rejected"
  | "approval_decision_malformed"
  | "approval_decision_replayed"
  | "approval_decision_expired"
  | "approval_decision_unsupported";

export type PlatformUserApprovalDecisionOutcome =
  | "approval_decision_created"
  | "user_approved"
  | "user_denied"
  | "user_cancelled"
  | "approval_expired"
  | "approval_artifact_invalid"
  | "policy_decision_ineligible"
  | "trust_decision_ineligible"
  | "surface_unsupported"
  | "correlation_mismatch"
  | "presentation_digest_mismatch"
  | "evidence_replayed"
  | "malformed"
  | "unsupported";

export type PlatformUserApprovalDecisionReason =
  | "authoritative-trust-decision-valid"
  | "authoritative-policy-decision-valid"
  | "policy-requires-user-approval"
  | "platform-approval-request-valid"
  | "platform-approval-artifact-valid"
  | "presentation-digest-matched"
  | "exact-action-bound"
  | "process-local-consumption"
  | "production-bound-platform-artifact"
  | "fixture-artifact-rejected-for-production"
  | "user-approved"
  | "user-denied"
  | "user-cancelled"
  | "approval-expired"
  | "user-approval-decision-only"
  | "no-capability-grant"
  | "no-authorization"
  | "no-execution"
  | (string & {});

export type PlatformUserApprovalRequirement =
  | "authoritative_trust_decision"
  | "authoritative_policy_decision_requiring_approval"
  | "exact_action_binding"
  | "presentation_digest_binding"
  | "explicit_platform_artifact"
  | "non_fixture_production_surface"
  | "bounded_validity_window"
  | "process_local_replay_check";

export type PlatformUserApprovalLimitation =
  | "user_approval_decision_only"
  | "process_local_replay_protection_only"
  | "process_local_store_only"
  | "explicit_platform_artifact_only"
  | "no_native_ui_invocation"
  | "request_bound"
  | "session_bound"
  | "application_bound"
  | "capability_bound"
  | "action_bound"
  | "target_bound"
  | "presentation_bound"
  | "no_capability_grant"
  | "no_authorization_package"
  | "no_session_key"
  | "no_execution"
  | "no_proof_execution"
  | "no_adapter_execution"
  | "no_transaction_submission"
  | "no_world_id_verification"
  | "no_vault_access"
  | "no_biometric_template_storage"
  | "no_durable_approval_database";

export interface PlatformUserApprovalRestrictionSummary {
  readonly effectiveScope?: CapabilityScope;
  readonly effectiveDurationSeconds?: number;
  readonly effectiveValueLimit?: string;
  readonly effectiveTargetRestrictions?: readonly string[];
  readonly policyRestrictions?: readonly string[];
}

export interface PlatformUserApprovalRiskDisclosure {
  readonly disclosureId: string;
  readonly summary: string;
  readonly severity?: "info" | "low" | "medium" | "high";
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface UserApprovalPresentationSummary {
  readonly applicationId: ApplicationId;
  readonly applicationName?: string;
  readonly capabilityName: CapabilityName;
  readonly actionType: string;
  readonly targetReference?: string;
  readonly requestedValue?: string;
  readonly effectiveScope?: CapabilityScope;
  readonly effectiveDurationSeconds?: number;
  readonly chainId?: string | number;
  readonly network?: string;
  readonly trustLimitations?: readonly string[];
  readonly policyRestrictions?: PlatformUserApprovalRestrictionSummary;
  readonly riskDisclosures?: readonly PlatformUserApprovalRiskDisclosure[];
  readonly expiresAt: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface UserApprovalPresentationDigest {
  readonly digest: string;
  readonly digestAlgorithm: "philcore-presentation-digest-v1";
  readonly summaryVersion: "philcore-user-approval-summary-v1";
}

export interface PlatformUserApprovalActionRequest {
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly capabilityName: CapabilityName;
  readonly actionType: string;
  readonly targetReference?: string;
  readonly requestedValue?: string;
  readonly effectiveScope?: CapabilityScope;
  readonly effectiveDurationSeconds?: number;
  readonly chainId?: string | number;
  readonly network?: string;
  readonly auditCorrelationId: string;
}

export interface PlatformUserApprovalBinding {
  readonly authoritativeTrustDecisionId: string;
  readonly authoritativePolicyDecisionId: string;
  readonly approvalRequestId: string;
  readonly approvalChallengeReference: string;
  readonly presentationDigest: UserApprovalPresentationDigest;
  readonly sessionLifecycleId: string;
  readonly sessionLifecycleState: UserSessionLifecycleState;
  readonly validityWindowId: string;
  readonly reusableAcrossTrustDecisions: false;
  readonly reusableAcrossPolicyDecisions: false;
  readonly reusableAcrossSessions: false;
  readonly reusableAcrossApplications: false;
  readonly reusableAcrossCapabilities: false;
  readonly reusableAcrossActions: false;
  readonly reusableAcrossTargets: false;
  readonly reusableAcrossValues: false;
  readonly reusableAcrossPresentationDigests: false;
  readonly reusableAcrossTimeWindows: false;
}

export interface PlatformUserApprovalRequest {
  readonly platformUserApprovalRequestId: string;
  readonly requestId: string;
  readonly authoritativeTrustDecisionId: string;
  readonly authoritativePolicyDecisionId: string;
  readonly actionRequest: PlatformUserApprovalActionRequest;
  readonly approvalSurface: PlatformUserApprovalSurface;
  readonly approvalChallengeReference: string;
  readonly presentationSummary: UserApprovalPresentationSummary;
  readonly presentationDigest: UserApprovalPresentationDigest;
  readonly requestedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly humanReadableSummary: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly invokesNativeUi: false;
  readonly invokesBiometrics: false;
  readonly invokesWebAuthn: false;
  readonly grantsAuthority: false;
  readonly createsCapabilityGrant: false;
  readonly createsAuthorizationPackage: false;
  readonly allowsExecution: false;
  readonly persisted: false;
}

export interface PlatformUserApprovalArtifact {
  readonly platformUserApprovalArtifactId: string;
  readonly platformUserApprovalRequestId: string;
  readonly approvalSurface: PlatformUserApprovalSurface;
  readonly outcome: PlatformUserApprovalArtifactOutcome;
  readonly decidedAt: string;
  readonly presentationDigest: UserApprovalPresentationDigest;
  readonly approvalChallengeReference: string;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly deviceReference?: string;
  readonly platformProviderReference?: string;
  readonly userPresenceIndicated: boolean;
  readonly userVerificationIndicated?: boolean;
  readonly productionBound: boolean;
  readonly fixtureOnly: boolean;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly biometricTemplateIncluded: false;
  readonly rawPlatformSecretIncluded: false;
  readonly rawPrivateKeyIncluded: false;
  readonly rawWebAuthnPrivateMaterialIncluded: false;
  readonly vaultMaterialIncluded: false;
  readonly credentialRecordIncluded: false;
  readonly authorizationPackageIncluded: false;
  readonly adapterPayloadIncluded: false;
}

export interface PlatformUserApprovalEvidence {
  readonly platformArtifactAccepted: true;
  readonly productionBoundArtifact: boolean;
  readonly fixtureOnlyArtifact: boolean;
  readonly approvalSurface: PlatformUserApprovalSurface;
  readonly userPresenceIndicated: boolean;
  readonly userVerificationIndicated?: boolean;
  readonly presentationDigestMatched: true;
  readonly rawPlatformPayloadIncluded: false;
  readonly biometricTemplateIncluded: false;
  readonly credentialRecordIncluded: false;
  readonly vaultMaterialIncluded: false;
  readonly authorizationPackageIncluded: false;
  readonly adapterPayloadIncluded: false;
}

export interface PlatformUserApprovalValidity {
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly expired: boolean;
  readonly invalidatedBySessionLock: true;
  readonly invalidatedBySessionClose: true;
  readonly invalidatedByTrustDecisionExpiry: true;
  readonly invalidatedByPolicyDecisionExpiry: true;
  readonly invalidatedByActionMutation: true;
  readonly invalidatedByApprovalCancellation: true;
}

export interface PlatformUserApprovalDecision {
  readonly platformUserApprovalDecisionId: string;
  readonly requestId: string;
  readonly status: "approval_decision_created";
  readonly outcome: PlatformUserApprovalDecisionOutcome;
  readonly actionRequest: PlatformUserApprovalActionRequest;
  readonly binding: PlatformUserApprovalBinding;
  readonly evidence: PlatformUserApprovalEvidence;
  readonly validity: PlatformUserApprovalValidity;
  readonly requirements: readonly PlatformUserApprovalRequirement[];
  readonly limitations: readonly PlatformUserApprovalLimitation[];
  readonly reasons: readonly PlatformUserApprovalDecisionReason[];
  readonly userApprovalDecisionCreated: true;
  readonly userApproved: boolean;
  readonly userDenied: boolean;
  readonly userCancelled: boolean;
  readonly approvalExpired: boolean;
  readonly trustDecisionAccepted: true;
  readonly policyDecisionAccepted: true;
  readonly presentationDigestMatched: true;
  readonly validForExactRequestOnly: true;
  readonly eligibleForCapabilityActivationReview: boolean;
  readonly productionBound: boolean;
  readonly fixtureOnly: boolean;
  readonly capabilityGranted: false;
  readonly authorizationCreated: false;
  readonly sessionKeyCreated: false;
  readonly executionAllowed: false;
  readonly proofExecuted: false;
  readonly adapterExecuted: false;
  readonly transactionSubmitted: false;
  readonly vaultAccessed: false;
  readonly worldIdVerified: false;
  readonly biometricTemplateStored: false;
  readonly rawPlatformSecretIncluded: false;
  readonly persistedAsAuthority: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: PlatformUserApprovalDecisionCollectionResult;
}

export interface PlatformUserApprovalRequestInput {
  readonly requestId: string;
  readonly authoritativeTrustDecision: AuthoritativeTrustDecision;
  readonly authoritativePolicyDecision: AuthoritativePolicyDecision;
  readonly actionRequest: PlatformUserApprovalActionRequest;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly approvalSurface: PlatformUserApprovalSurface;
  readonly approvalChallengeReference: string;
  readonly presentationSummary: UserApprovalPresentationSummary;
  readonly requestedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly humanReadableSummary?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface PlatformUserApprovalDecisionRequest {
  readonly requestId: string;
  readonly authoritativeTrustDecision: AuthoritativeTrustDecision;
  readonly authoritativePolicyDecision: AuthoritativePolicyDecision;
  readonly actionRequest: PlatformUserApprovalActionRequest;
  readonly platformApprovalRequest: PlatformUserApprovalRequest;
  readonly platformApprovalArtifact: PlatformUserApprovalArtifact;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type PlatformUserApprovalDecisionResult =
  RuntimeResult<PlatformUserApprovalDecision>;

export interface PlatformUserApprovalArtifactConsumptionRecord {
  readonly approvalArtifactEvidenceChainId: string;
  readonly platformUserApprovalDecisionId?: string;
  readonly platformUserApprovalArtifactId: string;
  readonly platformUserApprovalRequestId: string;
  readonly authoritativeTrustDecisionId: string;
  readonly authoritativePolicyDecisionId: string;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly capabilityName: CapabilityName;
  readonly actionType: string;
  readonly targetReference?: string;
  readonly requestedValue?: string;
  readonly presentationDigest: string;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export type PlatformUserApprovalArtifactConsumptionStatus =
  | "consumed"
  | "replayed"
  | "cleared";

export interface PlatformUserApprovalArtifactConsumptionResult {
  readonly status: PlatformUserApprovalArtifactConsumptionStatus;
  readonly record?: PlatformUserApprovalArtifactConsumptionRecord;
  readonly records: readonly PlatformUserApprovalArtifactConsumptionRecord[];
  readonly reason?: string;
}

export interface EphemeralUserApprovalArtifactConsumptionStore {
  consume(record: PlatformUserApprovalArtifactConsumptionRecord):
    PlatformUserApprovalArtifactConsumptionResult;
  has(approvalArtifactEvidenceChainId: string): boolean;
  clear(): PlatformUserApprovalArtifactConsumptionResult;
  getAll(): readonly PlatformUserApprovalArtifactConsumptionRecord[];
}

export type PlatformUserApprovalDecisionCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface PlatformUserApprovalDecisionCollection {
  readonly decisions: readonly PlatformUserApprovalDecision[];
  readonly count: number;
  readonly maxDecisionCount: number;
}

export interface PlatformUserApprovalDecisionCollectionResult {
  readonly status: PlatformUserApprovalDecisionCollectionStatus;
  readonly decision?: PlatformUserApprovalDecision;
  readonly removedDecision?: PlatformUserApprovalDecision;
  readonly evictedDecisions?: readonly PlatformUserApprovalDecision[];
  readonly collection: PlatformUserApprovalDecisionCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface PlatformUserApprovalDecisionStore {
  addDecision(decision: PlatformUserApprovalDecision):
    PlatformUserApprovalDecisionCollectionResult;
  removeDecision(decisionId: string): PlatformUserApprovalDecisionCollectionResult;
  clear(): PlatformUserApprovalDecisionCollectionResult;
  count(): number;
  getById(decisionId: string): PlatformUserApprovalDecision | undefined;
  getAll(): readonly PlatformUserApprovalDecision[];
  getUnexpired(now?: string): readonly PlatformUserApprovalDecision[];
}

export interface InMemoryPlatformUserApprovalDecisionStoreOptions {
  readonly maxDecisionCount?: number;
}

export interface UserApprovalDecisionConsumerRequest {
  readonly consumerId: string;
  readonly platformUserApprovalDecision: PlatformUserApprovalDecision;
  readonly requestedAt: string;
}

export interface UserApprovalDecisionConsumerResult {
  readonly status: "accepted_shape" | "rejected_shape";
  readonly platformUserApprovalDecisionId?: string;
  readonly errors: readonly string[];
  readonly capabilityGranted: false;
  readonly authorizationCreated: false;
}

export interface UserApprovalDecisionConsumer {
  acceptUserApprovalDecisionShape(request: UserApprovalDecisionConsumerRequest):
    UserApprovalDecisionConsumerResult;
}

export interface CapabilityActivationApprovalInput {
  readonly platformUserApprovalDecisionId: string;
  readonly userApproved: boolean;
  readonly eligibleForCapabilityActivationReview: boolean;
  readonly grantsCapability: false;
  readonly createsAuthorization: false;
}

const SURFACES = new Set<PlatformUserApprovalSurface>([
  "desktop_native",
  "mobile_native",
  "browser_extension",
  "hardware_confirmation",
  "recovery_surface",
  "developer_fixture",
  "unsupported"
]);

const PRODUCTION_SURFACES = new Set<PlatformUserApprovalSurface>([
  "desktop_native",
  "mobile_native",
  "browser_extension",
  "hardware_confirmation",
  "recovery_surface"
]);

const ARTIFACT_OUTCOMES = new Set<PlatformUserApprovalArtifactOutcome>([
  "approved",
  "denied",
  "cancelled",
  "expired"
]);

const STATUSES = new Set<PlatformUserApprovalDecisionStatus>([
  "approval_decision_created",
  "approval_decision_rejected",
  "approval_decision_malformed",
  "approval_decision_replayed",
  "approval_decision_expired",
  "approval_decision_unsupported"
]);

const OUTCOMES = new Set<PlatformUserApprovalDecisionOutcome>([
  "approval_decision_created",
  "user_approved",
  "user_denied",
  "user_cancelled",
  "approval_expired",
  "approval_artifact_invalid",
  "policy_decision_ineligible",
  "trust_decision_ineligible",
  "surface_unsupported",
  "correlation_mismatch",
  "presentation_digest_mismatch",
  "evidence_replayed",
  "malformed",
  "unsupported"
]);

const LIMITATIONS: readonly PlatformUserApprovalLimitation[] = Object.freeze([
  "user_approval_decision_only",
  "process_local_replay_protection_only",
  "process_local_store_only",
  "explicit_platform_artifact_only",
  "no_native_ui_invocation",
  "request_bound",
  "session_bound",
  "application_bound",
  "capability_bound",
  "action_bound",
  "target_bound",
  "presentation_bound",
  "no_capability_grant",
  "no_authorization_package",
  "no_session_key",
  "no_execution",
  "no_proof_execution",
  "no_adapter_execution",
  "no_transaction_submission",
  "no_world_id_verification",
  "no_vault_access",
  "no_biometric_template_storage",
  "no_durable_approval_database"
]);

const PRIVATE_OR_AUTHORITY_FIELDS = new Set([
  "philsecret",
  "privatekey",
  "signingkey",
  "vaultkey",
  "rawvaultkey",
  "seed",
  "seedphrase",
  "mnemonic",
  "password",
  "passphrase",
  "recoverysecret",
  "biometrictemplate",
  "rawbiometricdata",
  "rawplatformsecret",
  "webauthnprivate",
  "credentialrecord",
  "authorizationpackage",
  "adapterpayload",
  "capabilitygrant",
  "sessionkey",
  "authoritytoken",
  "transactionpayload"
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasValidDateShape(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function expired(value: string | undefined, now = Date.now()): boolean {
  return value !== undefined && Date.parse(value) <= now;
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as TValue;
  if (isRecord(value)) {
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, freezeRecord(entry)]))
    ) as TValue;
  }
  return value;
}

function validation(errors: string[]): RuntimeValidationResult {
  return { valid: errors.length === 0, errors };
}

function normalizeFieldName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function findBlockedFields(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findBlockedFields(entry, `${path}[${index}]`));
  }
  if (!isRecord(value)) return [];
  const findings: string[] = [];
  for (const [key, entry] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (PRIVATE_OR_AUTHORITY_FIELDS.has(normalizeFieldName(key)) && entry !== false) {
      findings.push(childPath);
    }
    findings.push(...findBlockedFields(entry, childPath));
  }
  return findings;
}

function secretValidationErrors(input: unknown): readonly string[] {
  return validateNoSensitiveMetadataKeys(input).errors.map(
    (error) => `secret-shaped metadata is not allowed: ${error}`
  );
}

function approvalError(code: string, errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "user_cancelled",
    code,
    message: "platform User Approval Decision request was rejected",
    boundary: "runtime-api",
    recoverable: true,
    details: { errors }
  };
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function createUserApprovalPresentationDigest(
  summary: UserApprovalPresentationSummary
): UserApprovalPresentationDigest {
  return freezeRecord({
    digest: createAuditCorrelationId([
      "philcore-user-approval-summary-v1",
      stableJson(summary)
    ]),
    digestAlgorithm: "philcore-presentation-digest-v1" as const,
    summaryVersion: "philcore-user-approval-summary-v1" as const
  });
}

function requirements(): readonly PlatformUserApprovalRequirement[] {
  return Object.freeze([
    "authoritative_trust_decision",
    "authoritative_policy_decision_requiring_approval",
    "exact_action_binding",
    "presentation_digest_binding",
    "explicit_platform_artifact",
    "non_fixture_production_surface",
    "bounded_validity_window",
    "process_local_replay_check"
  ]);
}

function actionRequestMatchesPresentation(
  action: PlatformUserApprovalActionRequest,
  summary: UserApprovalPresentationSummary
): readonly string[] {
  const errors: string[] = [];
  if (summary.applicationId !== action.applicationId) errors.push("presentation application mismatch");
  if (summary.capabilityName !== action.capabilityName) errors.push("presentation capability mismatch");
  if (summary.actionType !== action.actionType) errors.push("presentation action mismatch");
  if ((summary.targetReference ?? "") !== (action.targetReference ?? "")) {
    errors.push("presentation target mismatch");
  }
  if ((summary.requestedValue ?? "") !== (action.requestedValue ?? "")) {
    errors.push("presentation value mismatch");
  }
  if ((summary.effectiveDurationSeconds ?? -1) !== (action.effectiveDurationSeconds ?? -1)) {
    errors.push("presentation duration mismatch");
  }
  if (stableJson(summary.effectiveScope) !== stableJson(action.effectiveScope)) {
    errors.push("presentation scope mismatch");
  }
  if ((summary.chainId ?? "") !== (action.chainId ?? "")) errors.push("presentation chain mismatch");
  if ((summary.network ?? "") !== (action.network ?? "")) errors.push("presentation network mismatch");
  return Object.freeze(errors);
}

function actionRequestMatchesPolicy(
  action: PlatformUserApprovalActionRequest,
  policy: AuthoritativePolicyDecision
): readonly string[] {
  const errors: string[] = [];
  if (policy.scope.sessionId !== action.sessionId) errors.push("policy session mismatch");
  if (policy.scope.applicationId !== action.applicationId) errors.push("policy application mismatch");
  if (policy.scope.ownerCommitment !== action.ownerCommitment) errors.push("policy owner mismatch");
  if (policy.scope.capabilityName !== action.capabilityName) errors.push("policy capability mismatch");
  if (policy.scope.actionType !== action.actionType) errors.push("policy action mismatch");
  if ((policy.scope.targetReference ?? "") !== (action.targetReference ?? "")) {
    errors.push("policy target mismatch");
  }
  if ((policy.scope.requestedValue ?? "") !== (action.requestedValue ?? "")) {
    errors.push("policy value mismatch");
  }
  if ((policy.effectiveDurationSeconds ?? policy.scope.requestedDurationSeconds ?? -1)
    !== (action.effectiveDurationSeconds ?? -1)) {
    errors.push("policy duration mismatch");
  }
  if (stableJson(policy.effectiveScope ?? policy.scope.requestedScope)
    !== stableJson(action.effectiveScope)) {
    errors.push("policy scope mismatch");
  }
  if ((policy.scope.auditCorrelationId ?? "") !== action.auditCorrelationId) {
    errors.push("policy audit mismatch");
  }
  return Object.freeze(errors);
}

function trustMatchesPolicy(
  trust: AuthoritativeTrustDecision,
  policy: AuthoritativePolicyDecision
): readonly string[] {
  const errors: string[] = [];
  if (policy.binding.authoritativeTrustDecisionId !== trust.authoritativeTrustDecisionId) {
    errors.push("policy Trust Decision mismatch");
  }
  if (policy.scope.sessionId !== trust.scope.sessionId) errors.push("Trust Decision session mismatch");
  if (policy.scope.applicationId !== trust.scope.applicationId) {
    errors.push("Trust Decision application mismatch");
  }
  if (policy.scope.ownerCommitment !== trust.scope.ownerCommitment) {
    errors.push("Trust Decision owner mismatch");
  }
  if (policy.scope.authenticationPurpose !== trust.scope.authenticationPurpose) {
    errors.push("Trust Decision purpose mismatch");
  }
  if (policy.scope.auditCorrelationId !== trust.scope.auditCorrelationId) {
    errors.push("Trust Decision audit mismatch");
  }
  return Object.freeze(errors);
}

function policyEligibilityErrors(policy: AuthoritativePolicyDecision): readonly string[] {
  if (
    policy.requiresUserApproval
    || policy.outcome === "requires_user_approval"
    || policy.outcome === "allowed_for_user_approval"
  ) {
    return Object.freeze([]);
  }
  return Object.freeze([
    `authoritative policy decision outcome ${policy.outcome} is not eligible for platform user approval`
  ]);
}

export function isPlatformUserApprovalDecisionStatus(
  value: unknown
): value is PlatformUserApprovalDecisionStatus {
  return STATUSES.has(value as PlatformUserApprovalDecisionStatus);
}

export function isPlatformUserApprovalDecisionOutcome(
  value: unknown
): value is PlatformUserApprovalDecisionOutcome {
  return OUTCOMES.has(value as PlatformUserApprovalDecisionOutcome);
}

export function validatePlatformUserApprovalRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["platform user approval request must be an object"]);
  for (const field of [
    "platformUserApprovalRequestId",
    "requestId",
    "authoritativeTrustDecisionId",
    "authoritativePolicyDecisionId",
    "approvalChallengeReference",
    "requestedAt",
    "expiresAt",
    "auditCorrelationId",
    "humanReadableSummary"
  ] as const) {
    if (!isNonEmptyString(request[field])) errors.push(`${field} is required`);
  }
  if (!SURFACES.has(request.approvalSurface as PlatformUserApprovalSurface)) {
    errors.push("approvalSurface is invalid");
  }
  if (!isRecord(request.actionRequest)) errors.push("actionRequest is required");
  if (!isRecord(request.presentationSummary)) errors.push("presentationSummary is required");
  if (!isRecord(request.presentationDigest)) errors.push("presentationDigest is required");
  if (hasValidDateShape(request.requestedAt) && hasValidDateShape(request.expiresAt)) {
    if (Date.parse(request.expiresAt) <= Date.parse(request.requestedAt)) {
      errors.push("expiresAt must be after requestedAt");
    }
  } else {
    if (!hasValidDateShape(request.requestedAt)) errors.push("requestedAt must be a parseable date string");
    if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  }
  for (const [field, expected] of [
    ["invokesNativeUi", false],
    ["invokesBiometrics", false],
    ["invokesWebAuthn", false],
    ["grantsAuthority", false],
    ["createsCapabilityGrant", false],
    ["createsAuthorizationPackage", false],
    ["allowsExecution", false],
    ["persisted", false]
  ] as const) {
    if (request[field] !== expected) errors.push(`${field} must be false`);
  }
  if (isRecord(request.presentationSummary) && isRecord(request.presentationDigest)) {
    const expected = createUserApprovalPresentationDigest(
      request.presentationSummary as unknown as UserApprovalPresentationSummary
    );
    if ((request.presentationDigest as { digest?: unknown }).digest !== expected.digest) {
      errors.push("presentationDigest must match presentationSummary");
    }
    if (isRecord(request.actionRequest)) {
      errors.push(...actionRequestMatchesPresentation(
        request.actionRequest as unknown as PlatformUserApprovalActionRequest,
        request.presentationSummary as unknown as UserApprovalPresentationSummary
      ));
    }
  }
  errors.push(...secretValidationErrors(request.metadata));
  errors.push(...secretValidationErrors(request.presentationSummary));
  const blockedFields = findBlockedFields(request);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  return validation([...new Set(errors)]);
}

export function validatePlatformUserApprovalArtifact(
  artifact: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(artifact)) return validation(["platform user approval artifact must be an object"]);
  for (const field of [
    "platformUserApprovalArtifactId",
    "platformUserApprovalRequestId",
    "decidedAt",
    "approvalChallengeReference",
    "sessionId",
    "applicationId",
    "ownerCommitment",
    "expiresAt",
    "auditCorrelationId"
  ] as const) {
    if (!isNonEmptyString(artifact[field])) errors.push(`${field} is required`);
  }
  if (!SURFACES.has(artifact.approvalSurface as PlatformUserApprovalSurface)) {
    errors.push("approvalSurface is invalid");
  }
  if (!ARTIFACT_OUTCOMES.has(artifact.outcome as PlatformUserApprovalArtifactOutcome)) {
    errors.push("outcome is invalid");
  }
  if (!isRecord(artifact.presentationDigest)) errors.push("presentationDigest is required");
  if (!hasValidDateShape(artifact.decidedAt)) errors.push("decidedAt must be a parseable date string");
  if (!hasValidDateShape(artifact.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (typeof artifact.userPresenceIndicated !== "boolean") {
    errors.push("userPresenceIndicated must be a boolean");
  }
  if (
    artifact.userVerificationIndicated !== undefined
    && typeof artifact.userVerificationIndicated !== "boolean"
  ) {
    errors.push("userVerificationIndicated must be a boolean when provided");
  }
  if (typeof artifact.productionBound !== "boolean") errors.push("productionBound must be a boolean");
  if (typeof artifact.fixtureOnly !== "boolean") errors.push("fixtureOnly must be a boolean");
  for (const [field, expected] of [
    ["biometricTemplateIncluded", false],
    ["rawPlatformSecretIncluded", false],
    ["rawPrivateKeyIncluded", false],
    ["rawWebAuthnPrivateMaterialIncluded", false],
    ["vaultMaterialIncluded", false],
    ["credentialRecordIncluded", false],
    ["authorizationPackageIncluded", false],
    ["adapterPayloadIncluded", false]
  ] as const) {
    if (artifact[field] !== expected) errors.push(`${field} must be false`);
  }
  errors.push(...secretValidationErrors(artifact.metadata));
  const blockedFields = findBlockedFields(artifact);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  return validation([...new Set(errors)]);
}

export function createPlatformUserApprovalRequest(
  input: PlatformUserApprovalRequestInput
): RuntimeResult<PlatformUserApprovalRequest> {
  const errors: string[] = [];
  const trustValidation = validateAuthoritativeTrustDecisionShape(input.authoritativeTrustDecision);
  errors.push(...trustValidation.errors.map((error) => `authoritativeTrustDecision.${error}`));
  const policyValidation = validateAuthoritativePolicyDecisionShape(input.authoritativePolicyDecision);
  errors.push(...policyValidation.errors.map((error) => `authoritativePolicyDecision.${error}`));
  const lifecycleValidation = validateUserSessionLifecycleSnapshotShape(input.lifecycleSnapshot);
  errors.push(...lifecycleValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  if (!SURFACES.has(input.approvalSurface)) errors.push("approvalSurface is invalid");
  if (input.approvalSurface === "unsupported") errors.push("approvalSurface is unsupported");
  if (!isNonEmptyString(input.approvalChallengeReference)) {
    errors.push("approvalChallengeReference is required");
  }
  if (!hasValidDateShape(input.requestedAt)) errors.push("requestedAt must be a parseable date string");
  if (!hasValidDateShape(input.expiresAt)) errors.push("expiresAt must be a parseable date string");
  errors.push(...trustMatchesPolicy(input.authoritativeTrustDecision, input.authoritativePolicyDecision));
  errors.push(...policyEligibilityErrors(input.authoritativePolicyDecision));
  errors.push(...actionRequestMatchesPolicy(input.actionRequest, input.authoritativePolicyDecision));
  errors.push(...actionRequestMatchesPresentation(input.actionRequest, input.presentationSummary));
  if (input.actionRequest.auditCorrelationId !== input.auditCorrelationId) {
    errors.push("actionRequest auditCorrelationId must match request auditCorrelationId");
  }
  errors.push(...secretValidationErrors(input.metadata));
  errors.push(...secretValidationErrors(input.presentationSummary));
  const blockedFields = findBlockedFields(input);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  if (errors.length > 0) {
    return runtimeDenied(approvalError(
      "PLATFORM_USER_APPROVAL_REQUEST_MALFORMED",
      [...new Set(errors)]
    ));
  }

  const metadata = input.metadata
    ? redactRuntimeMetadata(input.metadata).value as Readonly<Record<string, unknown>>
    : undefined;
  const presentationSummary = freezeRecord(input.presentationSummary);
  const presentationDigest = createUserApprovalPresentationDigest(presentationSummary);
  const approvalRequest: PlatformUserApprovalRequest = freezeRecord({
    platformUserApprovalRequestId: createAuditCorrelationId([
      input.requestId,
      input.authoritativePolicyDecision.authoritativePolicyDecisionId,
      input.approvalChallengeReference,
      presentationDigest.digest,
      "platform-user-approval-request"
    ]),
    requestId: input.requestId,
    authoritativeTrustDecisionId: input.authoritativeTrustDecision.authoritativeTrustDecisionId,
    authoritativePolicyDecisionId: input.authoritativePolicyDecision.authoritativePolicyDecisionId,
    actionRequest: freezeRecord(input.actionRequest),
    approvalSurface: input.approvalSurface,
    approvalChallengeReference: input.approvalChallengeReference,
    presentationSummary,
    presentationDigest,
    requestedAt: input.requestedAt,
    expiresAt: input.expiresAt,
    auditCorrelationId: input.auditCorrelationId,
    humanReadableSummary: input.humanReadableSummary
      ?? `Request platform user approval for ${input.actionRequest.capabilityName} ${input.actionRequest.actionType}; no capability or authorization is created.`,
    metadata,
    invokesNativeUi: false as const,
    invokesBiometrics: false as const,
    invokesWebAuthn: false as const,
    grantsAuthority: false as const,
    createsCapabilityGrant: false as const,
    createsAuthorizationPackage: false as const,
    allowsExecution: false as const,
    persisted: false as const
  });
  const shape = validatePlatformUserApprovalRequest(approvalRequest);
  if (!shape.valid) {
    return runtimeDenied(approvalError("PLATFORM_USER_APPROVAL_REQUEST_SHAPE_INVALID", shape.errors));
  }
  return runtimeOk(approvalRequest);
}

export function validatePlatformUserApprovalDecisionShape(
  decision: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(decision)) return validation(["platform user approval decision must be an object"]);
  if (!isNonEmptyString(decision.platformUserApprovalDecisionId)) {
    errors.push("platformUserApprovalDecisionId is required");
  }
  if (decision.status !== "approval_decision_created") {
    errors.push("status must be approval_decision_created");
  }
  if (!isPlatformUserApprovalDecisionOutcome(decision.outcome)) errors.push("outcome is invalid");
  if (!isRecord(decision.actionRequest)) errors.push("actionRequest is required");
  if (!isRecord(decision.binding)) errors.push("binding is required");
  if (!isRecord(decision.evidence)) errors.push("evidence is required");
  if (!Array.isArray(decision.requirements)) errors.push("requirements must be an array");
  if (!Array.isArray(decision.limitations)) errors.push("limitations must be an array");
  if (!Array.isArray(decision.reasons)) errors.push("reasons must be an array");
  for (const field of [
    "userApprovalDecisionCreated",
    "trustDecisionAccepted",
    "policyDecisionAccepted",
    "presentationDigestMatched",
    "validForExactRequestOnly"
  ]) {
    if (decision[field] !== true) errors.push(`${field} must be true`);
  }
  for (const field of [
    "capabilityGranted",
    "authorizationCreated",
    "sessionKeyCreated",
    "executionAllowed",
    "proofExecuted",
    "adapterExecuted",
    "transactionSubmitted",
    "vaultAccessed",
    "worldIdVerified",
    "biometricTemplateStored",
    "rawPlatformSecretIncluded",
    "persistedAsAuthority",
    "persisted"
  ]) {
    if (decision[field] !== false) errors.push(`${field} must be false`);
  }
  if (decision.userApproved === true && decision.outcome !== "user_approved") {
    errors.push("userApproved may only be true for user_approved");
  }
  if (decision.eligibleForCapabilityActivationReview === true && decision.outcome !== "user_approved") {
    errors.push("only user_approved decisions may be eligible for capability activation review");
  }
  return validation(errors);
}

function auditDraftForApproval(input: {
  readonly request: PlatformUserApprovalDecisionRequest;
  readonly outcome: PlatformUserApprovalDecisionOutcome;
  readonly decision?: PlatformUserApprovalDecision;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.decision ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: input.request.actionRequest.sessionId,
    applicationId: input.request.actionRequest.applicationId,
    capability: input.request.actionRequest.capabilityName,
    summary: input.decision
      ? "Platform User Approval Decision accepted for one exact request; no capability, authorization, or execution was created."
      : "Platform User Approval Decision request rejected; no capability, authorization, or execution was created.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      platformUserApprovalDecisionId: input.decision?.platformUserApprovalDecisionId,
      platformUserApprovalRequestId:
        input.request.platformApprovalRequest?.platformUserApprovalRequestId,
      platformUserApprovalArtifactId:
        input.request.platformApprovalArtifact?.platformUserApprovalArtifactId,
      authoritativeTrustDecisionId:
        input.request.authoritativeTrustDecision?.authoritativeTrustDecisionId,
      authoritativePolicyDecisionId:
        input.request.authoritativePolicyDecision?.authoritativePolicyDecisionId,
      applicationId: input.request.actionRequest.applicationId,
      sessionId: input.request.actionRequest.sessionId,
      ownerCommitment: input.request.actionRequest.ownerCommitment,
      capabilityName: input.request.actionRequest.capabilityName,
      actionType: input.request.actionRequest.actionType,
      targetReference: input.request.actionRequest.targetReference,
      requestedValue: input.request.actionRequest.requestedValue,
      effectiveDurationSeconds: input.request.actionRequest.effectiveDurationSeconds,
      approvalSurface: input.request.platformApprovalArtifact?.approvalSurface,
      artifactOutcome: input.request.platformApprovalArtifact?.outcome,
      outcome: input.outcome,
      presentationDigest: input.request.platformApprovalRequest?.presentationDigest?.digest,
      userApproved: input.decision?.userApproved ?? false,
      userDenied: input.decision?.userDenied ?? false,
      userCancelled: input.decision?.userCancelled ?? false,
      approvalExpired: input.decision?.approvalExpired ?? false,
      eligibleForCapabilityActivationReview:
        input.decision?.eligibleForCapabilityActivationReview ?? false,
      capabilityGranted: false,
      authorizationCreated: false,
      sessionKeyCreated: false,
      executionAllowed: false,
      proofExecuted: false,
      adapterExecuted: false,
      transactionSubmitted: false,
      biometricTemplateStored: false,
      rawPlatformSecretIncluded: false,
      vaultAccessed: false,
      persistedAsAuthority: false,
      errors: input.errors ?? []
    }
  });
}

function validateDecisionRequestShape(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["platform user approval decision request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  const trustValidation = validateAuthoritativeTrustDecisionShape(request.authoritativeTrustDecision);
  errors.push(...trustValidation.errors.map((error) => `authoritativeTrustDecision.${error}`));
  const policyValidation = validateAuthoritativePolicyDecisionShape(request.authoritativePolicyDecision);
  errors.push(...policyValidation.errors.map((error) => `authoritativePolicyDecision.${error}`));
  const approvalRequestValidation =
    validatePlatformUserApprovalRequest(request.platformApprovalRequest);
  errors.push(...approvalRequestValidation.errors.map((error) => `platformApprovalRequest.${error}`));
  const artifactValidation = validatePlatformUserApprovalArtifact(request.platformApprovalArtifact);
  errors.push(...artifactValidation.errors.map((error) => `platformApprovalArtifact.${error}`));
  const lifecycleValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  errors.push(...lifecycleValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  if (!isRecord(request.actionRequest)) errors.push("actionRequest is required");
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a parseable date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  errors.push(...secretValidationErrors(request.metadata));
  const blockedFields = findBlockedFields(request);
  if (blockedFields.length > 0) {
    errors.push(`private material or active authority fields are not allowed: ${blockedFields.join(", ")}`);
  }
  return validation([...new Set(errors)]);
}

function correlationErrors(request: PlatformUserApprovalDecisionRequest): readonly string[] {
  const errors: string[] = [];
  const { authoritativeTrustDecision: trust, authoritativePolicyDecision: policy } = request;
  const approvalRequest = request.platformApprovalRequest;
  const artifact = request.platformApprovalArtifact;
  errors.push(...trustMatchesPolicy(trust, policy));
  errors.push(...actionRequestMatchesPolicy(request.actionRequest, policy));
  errors.push(...actionRequestMatchesPresentation(
    request.actionRequest,
    approvalRequest.presentationSummary
  ));
  if (approvalRequest.authoritativeTrustDecisionId !== trust.authoritativeTrustDecisionId) {
    errors.push("approval request Trust Decision mismatch");
  }
  if (approvalRequest.authoritativePolicyDecisionId !== policy.authoritativePolicyDecisionId) {
    errors.push("approval request Policy Decision mismatch");
  }
  if (approvalRequest.platformUserApprovalRequestId !== artifact.platformUserApprovalRequestId) {
    errors.push("approval artifact request mismatch");
  }
  if (approvalRequest.approvalSurface !== artifact.approvalSurface) {
    errors.push("approval artifact surface mismatch");
  }
  if (approvalRequest.approvalChallengeReference !== artifact.approvalChallengeReference) {
    errors.push("approval artifact challenge mismatch");
  }
  if (approvalRequest.presentationDigest.digest !== artifact.presentationDigest.digest) {
    errors.push("presentation digest mismatch");
  }
  if (approvalRequest.actionRequest.sessionId !== artifact.sessionId) {
    errors.push("approval artifact session mismatch");
  }
  if (approvalRequest.actionRequest.applicationId !== artifact.applicationId) {
    errors.push("approval artifact application mismatch");
  }
  if (approvalRequest.actionRequest.ownerCommitment !== artifact.ownerCommitment) {
    errors.push("approval artifact owner mismatch");
  }
  if (request.lifecycleSnapshot.sessionId !== request.actionRequest.sessionId) {
    errors.push("lifecycle session mismatch");
  }
  if (approvalRequest.auditCorrelationId !== request.auditCorrelationId) {
    errors.push("approval request audit mismatch");
  }
  if (artifact.auditCorrelationId !== request.auditCorrelationId) {
    errors.push("approval artifact audit mismatch");
  }
  return Object.freeze([...new Set(errors)]);
}

function preflightErrors(request: PlatformUserApprovalDecisionRequest): readonly string[] {
  const errors: string[] = [];
  const { authoritativeTrustDecision: trust, authoritativePolicyDecision: policy } = request;
  const artifact = request.platformApprovalArtifact;
  if (trust.status !== "trust_decision_created" || trust.outcome !== "trust_decision_created") {
    errors.push("trust decision ineligible");
  }
  if (policy.status !== "policy_decision_created" || !policy.policyDecisionCreated) {
    errors.push("policy decision ineligible");
  }
  errors.push(...policyEligibilityErrors(policy));
  if (expired(trust.validity.expiresAt)) errors.push("trust decision expired");
  if (expired(policy.validity.expiresAt)) errors.push("policy decision expired");
  if (expired(request.platformApprovalRequest.expiresAt)) errors.push("approval request expired");
  if (expired(request.expiresAt)) errors.push("approval decision request expired");
  if (!PRODUCTION_SURFACES.has(artifact.approvalSurface)) {
    errors.push("approval surface unsupported for production decision");
  }
  if (artifact.fixtureOnly || !artifact.productionBound || artifact.approvalSurface === "developer_fixture") {
    errors.push("fixture artifact cannot create production approval decision");
  }
  if (artifact.outcome === "approved" && artifact.userPresenceIndicated !== true) {
    errors.push("approved artifact requires user presence indication");
  }
  if (Date.parse(request.expiresAt) <= Date.parse(request.issuedAt)) {
    errors.push("decision expiresAt must be after issuedAt");
  }
  return Object.freeze([...new Set(errors)]);
}

function outcomeForArtifact(
  artifact: PlatformUserApprovalArtifact,
  decisionIssuedAt: string
): PlatformUserApprovalDecisionOutcome {
  if (artifact.outcome === "expired" || Date.parse(artifact.expiresAt) <= Date.parse(decisionIssuedAt)) {
    return "approval_expired";
  }
  if (artifact.outcome === "approved") return "user_approved";
  if (artifact.outcome === "denied") return "user_denied";
  if (artifact.outcome === "cancelled") return "user_cancelled";
  return "approval_artifact_invalid";
}

function outcomeForErrors(errors: readonly string[]): PlatformUserApprovalDecisionOutcome {
  if (errors.some((error) => error.includes("replay") || error.includes("consumed"))) {
    return "evidence_replayed";
  }
  if (errors.some((error) => error.includes("Trust Decision") || error.includes("trust decision"))) {
    return "trust_decision_ineligible";
  }
  if (errors.some((error) => error.includes("policy") || error.includes("Policy Decision"))) {
    return "policy_decision_ineligible";
  }
  if (errors.some((error) => error.includes("surface") || error.includes("fixture"))) {
    return "surface_unsupported";
  }
  if (errors.some((error) => error.includes("digest") || error.includes("presentation"))) {
    return "presentation_digest_mismatch";
  }
  if (errors.some((error) => error.includes("mismatch"))) return "correlation_mismatch";
  if (errors.some((error) => error.includes("expired"))) return "approval_expired";
  return "malformed";
}

export function evaluatePlatformUserApprovalDecision(
  request: PlatformUserApprovalDecisionRequest,
  consumptionStore?: EphemeralUserApprovalArtifactConsumptionStore,
  decisionStore?: PlatformUserApprovalDecisionStore,
  auditDraftCollector?: AuditDraftCollector
): PlatformUserApprovalDecisionResult {
  const requestValidation = validateDecisionRequestShape(request);
  if (!requestValidation.valid) {
    const auditEventDraft = auditDraftForApproval({
      request,
      outcome: "malformed",
      errors: requestValidation.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(approvalError(
      "PLATFORM_USER_APPROVAL_DECISION_MALFORMED",
      requestValidation.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const correlation = correlationErrors(request);
  if (correlation.length > 0) {
    const outcome = outcomeForErrors(correlation);
    const auditEventDraft = auditDraftForApproval({ request, outcome, errors: correlation });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(approvalError(
      outcome === "presentation_digest_mismatch"
        ? "PLATFORM_USER_APPROVAL_PRESENTATION_DIGEST_MISMATCH"
        : "PLATFORM_USER_APPROVAL_CORRELATION_MISMATCH",
      correlation
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const preflight = preflightErrors(request);
  if (preflight.length > 0) {
    const outcome = outcomeForErrors(preflight);
    const auditEventDraft = auditDraftForApproval({ request, outcome, errors: preflight });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(approvalError(
      outcome === "surface_unsupported"
        ? "PLATFORM_USER_APPROVAL_SURFACE_UNSUPPORTED"
        : "PLATFORM_USER_APPROVAL_DECISION_REJECTED",
      preflight
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const approvalArtifactEvidenceChainId = createAuditCorrelationId([
    request.platformApprovalArtifact.platformUserApprovalArtifactId,
    "one-platform-user-approval-decision-per-artifact",
    "platform-user-approval-artifact-evidence-chain"
  ]);
  if (consumptionStore?.has(approvalArtifactEvidenceChainId)) {
    const auditEventDraft = auditDraftForApproval({
      request,
      outcome: "evidence_replayed",
      errors: ["approval artifact evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(approvalError(
      "PLATFORM_USER_APPROVAL_ARTIFACT_REPLAYED",
      ["approval artifact evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const outcome = outcomeForArtifact(request.platformApprovalArtifact, request.issuedAt);
  const userApproved = outcome === "user_approved";
  const userDenied = outcome === "user_denied";
  const userCancelled = outcome === "user_cancelled";
  const approvalExpired = outcome === "approval_expired";
  const reasons: PlatformUserApprovalDecisionReason[] = [
    "authoritative-trust-decision-valid",
    "authoritative-policy-decision-valid",
    "policy-requires-user-approval",
    "platform-approval-request-valid",
    "platform-approval-artifact-valid",
    "presentation-digest-matched",
    "exact-action-bound",
    "production-bound-platform-artifact",
    "user-approval-decision-only",
    "no-capability-grant",
    "no-authorization",
    "no-execution"
  ];
  if (userApproved) reasons.push("user-approved");
  if (userDenied) reasons.push("user-denied");
  if (userCancelled) reasons.push("user-cancelled");
  if (approvalExpired) reasons.push("approval-expired");
  const decisionId = createAuditCorrelationId([
    approvalArtifactEvidenceChainId,
    request.issuedAt,
    request.expiresAt,
    outcome,
    "platform-user-approval-decision"
  ]);
  const decisionBase = {
    platformUserApprovalDecisionId: decisionId,
    requestId: request.requestId,
    status: "approval_decision_created" as const,
    outcome,
    actionRequest: freezeRecord(request.actionRequest),
    binding: {
      authoritativeTrustDecisionId: request.authoritativeTrustDecision.authoritativeTrustDecisionId,
      authoritativePolicyDecisionId: request.authoritativePolicyDecision.authoritativePolicyDecisionId,
      approvalRequestId: request.platformApprovalRequest.platformUserApprovalRequestId,
      approvalChallengeReference: request.platformApprovalRequest.approvalChallengeReference,
      presentationDigest: request.platformApprovalRequest.presentationDigest,
      sessionLifecycleId: request.lifecycleSnapshot.lifecycleId,
      sessionLifecycleState: request.lifecycleSnapshot.state,
      validityWindowId: createAuditCorrelationId([
        request.actionRequest.sessionId,
        request.actionRequest.capabilityName,
        request.actionRequest.actionType,
        request.platformApprovalRequest.presentationDigest.digest,
        request.issuedAt,
        request.expiresAt,
        "platform-user-approval-validity-window"
      ]),
      reusableAcrossTrustDecisions: false as const,
      reusableAcrossPolicyDecisions: false as const,
      reusableAcrossSessions: false as const,
      reusableAcrossApplications: false as const,
      reusableAcrossCapabilities: false as const,
      reusableAcrossActions: false as const,
      reusableAcrossTargets: false as const,
      reusableAcrossValues: false as const,
      reusableAcrossPresentationDigests: false as const,
      reusableAcrossTimeWindows: false as const
    },
    evidence: {
      platformArtifactAccepted: true as const,
      productionBoundArtifact: request.platformApprovalArtifact.productionBound,
      fixtureOnlyArtifact: request.platformApprovalArtifact.fixtureOnly,
      approvalSurface: request.platformApprovalArtifact.approvalSurface,
      userPresenceIndicated: request.platformApprovalArtifact.userPresenceIndicated,
      userVerificationIndicated: request.platformApprovalArtifact.userVerificationIndicated,
      presentationDigestMatched: true as const,
      rawPlatformPayloadIncluded: false as const,
      biometricTemplateIncluded: false as const,
      credentialRecordIncluded: false as const,
      vaultMaterialIncluded: false as const,
      authorizationPackageIncluded: false as const,
      adapterPayloadIncluded: false as const
    },
    validity: {
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      expired: approvalExpired,
      invalidatedBySessionLock: true as const,
      invalidatedBySessionClose: true as const,
      invalidatedByTrustDecisionExpiry: true as const,
      invalidatedByPolicyDecisionExpiry: true as const,
      invalidatedByActionMutation: true as const,
      invalidatedByApprovalCancellation: true as const
    },
    requirements: requirements(),
    limitations: LIMITATIONS,
    reasons: Object.freeze(reasons),
    userApprovalDecisionCreated: true as const,
    userApproved,
    userDenied,
    userCancelled,
    approvalExpired,
    trustDecisionAccepted: true as const,
    policyDecisionAccepted: true as const,
    presentationDigestMatched: true as const,
    validForExactRequestOnly: true as const,
    eligibleForCapabilityActivationReview: userApproved,
    productionBound: request.platformApprovalArtifact.productionBound,
    fixtureOnly: request.platformApprovalArtifact.fixtureOnly,
    capabilityGranted: false as const,
    authorizationCreated: false as const,
    sessionKeyCreated: false as const,
    executionAllowed: false as const,
    proofExecuted: false as const,
    adapterExecuted: false as const,
    transactionSubmitted: false as const,
    vaultAccessed: false as const,
    worldIdVerified: false as const,
    biometricTemplateStored: false as const,
    rawPlatformSecretIncluded: false as const,
    persistedAsAuthority: false as const,
    persisted: false as const
  };
  const decisionWithoutAudit = freezeRecord(decisionBase) as PlatformUserApprovalDecision;
  const shape = validatePlatformUserApprovalDecisionShape(decisionWithoutAudit);
  if (!shape.valid) {
    const auditEventDraft = auditDraftForApproval({
      request,
      outcome: "malformed",
      errors: shape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(approvalError(
      "PLATFORM_USER_APPROVAL_DECISION_SHAPE_INVALID",
      shape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const consumed = consumptionStore?.consume({
    approvalArtifactEvidenceChainId,
    platformUserApprovalDecisionId: decisionId,
    platformUserApprovalArtifactId:
      request.platformApprovalArtifact.platformUserApprovalArtifactId,
    platformUserApprovalRequestId:
      request.platformApprovalRequest.platformUserApprovalRequestId,
    authoritativeTrustDecisionId:
      request.authoritativeTrustDecision.authoritativeTrustDecisionId,
    authoritativePolicyDecisionId:
      request.authoritativePolicyDecision.authoritativePolicyDecisionId,
    sessionId: request.actionRequest.sessionId,
    applicationId: request.actionRequest.applicationId,
    capabilityName: request.actionRequest.capabilityName,
    actionType: request.actionRequest.actionType,
    targetReference: request.actionRequest.targetReference,
    requestedValue: request.actionRequest.requestedValue,
    presentationDigest: request.platformApprovalRequest.presentationDigest.digest,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const auditEventDraft = auditDraftForApproval({
      request,
      outcome: "evidence_replayed",
      errors: ["approval artifact evidence chain was already consumed"]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(approvalError(
      "PLATFORM_USER_APPROVAL_ARTIFACT_REPLAYED",
      ["approval artifact evidence chain was already consumed"]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const auditEventDraft = auditDraftForApproval({ request, outcome, decision: decisionWithoutAudit });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const decisionWithAudit = freezeRecord({
    ...decisionBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as PlatformUserApprovalDecision;
  const collectionResult = decisionStore?.addDecision(decisionWithAudit);
  return runtimeOk(freezeRecord({
    ...decisionWithAudit,
    collectionResult
  }) as PlatformUserApprovalDecision);
}

export function createPlatformUserApprovalDecision(
  request: PlatformUserApprovalDecisionRequest,
  consumptionStore?: EphemeralUserApprovalArtifactConsumptionStore,
  decisionStore?: PlatformUserApprovalDecisionStore,
  auditDraftCollector?: AuditDraftCollector
): PlatformUserApprovalDecisionResult {
  return evaluatePlatformUserApprovalDecision(
    request,
    consumptionStore,
    decisionStore,
    auditDraftCollector
  );
}

export function createEphemeralUserApprovalArtifactConsumptionStore():
  EphemeralUserApprovalArtifactConsumptionStore {
  const records = new Map<string, PlatformUserApprovalArtifactConsumptionRecord>();
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(record) {
      if (records.has(record.approvalArtifactEvidenceChainId)) {
        return freezeRecord({
          status: "replayed" as const,
          record: records.get(record.approvalArtifactEvidenceChainId),
          records: all(),
          reason: "platform user approval artifact evidence chain was already consumed"
        });
      }
      const frozen = freezeRecord(record);
      records.set(record.approvalArtifactEvidenceChainId, frozen);
      return freezeRecord({ status: "consumed" as const, record: frozen, records: all() });
    },
    has(approvalArtifactEvidenceChainId) {
      return records.has(approvalArtifactEvidenceChainId);
    },
    clear() {
      records.clear();
      return freezeRecord({ status: "cleared" as const, records: all() });
    },
    getAll: all
  };
}

function collectionSnapshot(
  decisions: Map<string, PlatformUserApprovalDecision>,
  maxDecisionCount: number
): PlatformUserApprovalDecisionCollection {
  return freezeRecord({
    decisions: Array.from(decisions.values()),
    count: decisions.size,
    maxDecisionCount
  });
}

export function createInMemoryPlatformUserApprovalDecisionStore(
  options: InMemoryPlatformUserApprovalDecisionStoreOptions = {}
): PlatformUserApprovalDecisionStore {
  const maxDecisionCount = Math.max(1, Math.floor(options.maxDecisionCount ?? 100));
  const decisions = new Map<string, PlatformUserApprovalDecision>();
  const result = (
    status: PlatformUserApprovalDecisionCollectionStatus,
    extra: Omit<PlatformUserApprovalDecisionCollectionResult, "status" | "collection"> = {}
  ): PlatformUserApprovalDecisionCollectionResult => freezeRecord({
    status,
    collection: collectionSnapshot(decisions, maxDecisionCount),
    ...extra
  });
  return {
    addDecision(decision) {
      const shape = validatePlatformUserApprovalDecisionShape(decision);
      if (!shape.valid) return result("rejected_invalid", { errors: shape.errors });
      if (decisions.has(decision.platformUserApprovalDecisionId)) {
        return result("rejected_duplicate", {
          decision,
          reason: "platform user approval decision ID already exists"
        });
      }
      let evictedDecisions: PlatformUserApprovalDecision[] = [];
      if (decisions.size >= maxDecisionCount) {
        const oldestKey = decisions.keys().next().value;
        if (typeof oldestKey === "string") {
          const evicted = decisions.get(oldestKey);
          decisions.delete(oldestKey);
          if (evicted) evictedDecisions = [evicted];
        }
      }
      const frozen = freezeRecord(decision);
      decisions.set(frozen.platformUserApprovalDecisionId, frozen);
      return result(evictedDecisions.length > 0 ? "evicted_oldest" : "collected", {
        decision: frozen,
        evictedDecisions: evictedDecisions.length > 0
          ? Object.freeze(evictedDecisions)
          : undefined
      });
    },
    removeDecision(decisionId) {
      const removedDecision = decisions.get(decisionId);
      if (!removedDecision) return result("not_found");
      decisions.delete(decisionId);
      return result("removed", { removedDecision });
    },
    clear() {
      decisions.clear();
      return result("cleared");
    },
    count() {
      return decisions.size;
    },
    getById(decisionId) {
      return decisions.get(decisionId);
    },
    getAll() {
      return Object.freeze(Array.from(decisions.values()));
    },
    getUnexpired(now = new Date().toISOString()) {
      return Object.freeze(Array.from(decisions.values()).filter(
        (decision) => Date.parse(decision.validity.expiresAt) > Date.parse(now)
      ));
    }
  };
}

export function createFixtureUserApprovalDecisionConsumer(): UserApprovalDecisionConsumer {
  return {
    acceptUserApprovalDecisionShape(request) {
      const validationResult =
        validatePlatformUserApprovalDecisionShape(request.platformUserApprovalDecision);
      if (!validationResult.valid) {
        return freezeRecord({
          status: "rejected_shape" as const,
          errors: validationResult.errors,
          capabilityGranted: false as const,
          authorizationCreated: false as const
        });
      }
      return freezeRecord({
        status: "accepted_shape" as const,
        platformUserApprovalDecisionId:
          request.platformUserApprovalDecision.platformUserApprovalDecisionId,
        errors: [],
        capabilityGranted: false as const,
        authorizationCreated: false as const
      });
    }
  };
}
