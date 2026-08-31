import type { BigNumberish, BytesLike } from "ethers";

import {
  computeUnlockActionHashFromConsumerData,
  encodeUnlockConsumerData
} from "../authorization.ts";
import {
  UNLOCK_PROOF_SCHEMA_VERSION,
  UNLOCK_PROOF_TYPE,
  authorizationDigest,
  dataHash,
  normalizeBaseActionAuthorization,
  policyHash as derivePolicyHash,
  type BaseActionAuthorization,
  type Hex,
  type UnlockProofPackage,
  type UnlockProofPublicInputs
} from "../hashes.ts";
import { buildUnlockProofPackageFromAuthorization } from "../proof/publicInputs.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type { AuthoritativeCapabilityGrant } from "./authoritativeCapabilityGrant.ts";
import { validateAuthoritativeCapabilityGrantShape } from "./authoritativeCapabilityGrant.ts";
import type { AuthoritativePolicyDecision } from "./authoritativePolicyDecision.ts";
import { validateAuthoritativePolicyDecisionShape } from "./authoritativePolicyDecision.ts";
import type { AuthoritativeTrustDecision } from "./authoritativeTrustDecision.ts";
import { validateAuthoritativeTrustDecisionShape } from "./authoritativeTrustDecision.ts";
import type { AuthorizationDecisionCandidate } from "./authorizationDecisionCandidate.ts";
import { validateAuthorizationDecisionCandidateShape } from "./authorizationDecisionCandidate.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import type { PlatformUserApprovalDecision } from "./platformUserApprovalDecision.ts";
import { validatePlatformUserApprovalDecisionShape } from "./platformUserApprovalDecision.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  ApplicationId,
  CapabilityName,
  CapabilityScope,
  Intent,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type AuthorizationPackageDraftStatus =
  | "package_draft_created"
  | "package_draft_rejected"
  | "package_draft_malformed"
  | "package_draft_replayed"
  | "package_draft_expired"
  | "package_draft_unsupported";

export type AuthorizationPackageDraftOutcome =
  | "authorization_package_draft_created"
  | "candidate_ineligible"
  | "capability_grant_ineligible"
  | "trust_decision_ineligible"
  | "policy_decision_ineligible"
  | "approval_decision_ineligible"
  | "action_correlation_mismatch"
  | "action_hash_mismatch"
  | "policy_hash_mismatch"
  | "consumer_data_hash_mismatch"
  | "nullifier_invalid"
  | "expiry_invalid"
  | "proof_input_hash_mismatch"
  | "proof_required"
  | "additional_user_approval_required"
  | "evidence_expired"
  | "evidence_replayed"
  | "malformed"
  | "unsupported";

export type AuthorizationPackageDraftReason =
  | "active-capability-grant-valid"
  | "authorization-decision-candidate-valid"
  | "trust-policy-approval-chain-correlated"
  | "canonical-action-hash-derived"
  | "canonical-policy-hash-derived"
  | "consumer-data-hash-derived"
  | "public-nullifier-accepted"
  | "canonical-proof-input-hash-derived"
  | "authorization-package-draft-only"
  | "no-proof-generation"
  | "no-nullifier-consumption"
  | "no-execution"
  | (string & {});

export type AuthorizationPackageDraftRequirement =
  | "active_authoritative_capability_grant"
  | "valid_authorization_decision_candidate"
  | "authoritative_trust_decision"
  | "authoritative_policy_decision"
  | "approved_platform_user_approval_decision"
  | "exact_action_intent"
  | "canonical_action_unlock_public_tuple"
  | "public_nullifier_reference"
  | "bounded_validity_window";

export type AuthorizationPackageDraftLimitation =
  | "authorization_package_draft_only"
  | "process_local_replay_protection_only"
  | "process_local_store_only"
  | "no_phil_secret"
  | "no_nullifier_seed"
  | "no_witness_material"
  | "no_proof_generation"
  | "no_proof_verification"
  | "no_verified_fact"
  | "no_nullifier_consumption"
  | "no_signature"
  | "no_session_key"
  | "no_adapter_execution"
  | "no_transaction_submission"
  | "no_durable_draft_persistence";

export interface ActionUnlockPublicInputDraft {
  readonly version: typeof UNLOCK_PROOF_SCHEMA_VERSION;
  readonly proofType: typeof UNLOCK_PROOF_TYPE;
  readonly tupleFieldOrder: readonly [
    "ownerCommitment",
    "actionHash",
    "policyHash",
    "nullifier",
    "consumerDataHash",
    "expiry"
  ];
  readonly publicInputs: UnlockProofPublicInputs;
  readonly proofInputHash: Hex;
  readonly proofPackageDraft: UnlockProofPackage;
  readonly factShapeReference: "[fact_high, fact_low]";
  readonly proofBlobIncluded: false;
  readonly proofGenerated: false;
  readonly proofVerified: false;
  readonly verifiedFactAvailable: false;
}

export interface AuthorizationHashSummary {
  readonly actionHash: Hex;
  readonly policyHash: Hex;
  readonly consumerDataHash: Hex;
  readonly proofInputHash: Hex;
  readonly authorizationDigest: Hex;
  readonly m1ActionDigestPreview?: string;
  readonly m1PreviewIsCanonicalActionHash: false;
}

export interface AuthorizationNullifierPublicReference {
  readonly nullifier: Hex;
  readonly source: "explicit_public_nullifier" | "protected_derivation_reference";
  readonly safeReference?: string;
  readonly nullifierSeedIncluded: false;
  readonly nullifierConsumed: false;
  readonly durableReplayProtectionClaimed: false;
}

export interface AuthorizationConsumerDataBinding {
  readonly consumer: string;
  readonly account: string;
  readonly target: string;
  readonly value: string;
  readonly callDataHash: Hex;
  readonly consumerDataHash: Hex;
  readonly rawConsumerDataIncluded: false;
  readonly executableUserOperationIncluded: false;
  readonly adapterPayloadIncluded: false;
}

export interface AuthorizationPackageDraftBinding {
  readonly authoritativeCapabilityGrantId: string;
  readonly authorizationDecisionCandidateId: string;
  readonly authoritativeTrustDecisionId: string;
  readonly authoritativePolicyDecisionId: string;
  readonly platformUserApprovalDecisionId: string;
  readonly intentId: string;
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly capabilityName: CapabilityName;
  readonly actionType: string;
  readonly auditCorrelationId: string;
}

export interface AuthorizationPackageDraftEvidence {
  readonly activeCapabilityGrantAccepted: true;
  readonly authorizationDecisionCandidateAccepted: true;
  readonly trustDecisionAccepted: true;
  readonly policyDecisionAccepted: true;
  readonly platformUserApprovalAccepted: true;
  readonly canonicalActionHashDerived: true;
  readonly canonicalPolicyHashDerived: true;
  readonly consumerDataHashDerived: true;
  readonly publicNullifierAccepted: true;
  readonly proofInputHashDerived: true;
  readonly rawTrustEvidenceIncluded: false;
  readonly rawApprovalArtifactIncluded: false;
  readonly credentialRecordIncluded: false;
  readonly vaultHandleIncluded: false;
  readonly privateMaterialIncluded: false;
  readonly nullifierSeedIncluded: false;
  readonly proofBytesIncluded: false;
  readonly verifiedFactIncluded: false;
  readonly signatureIncluded: false;
  readonly adapterPayloadIncluded: false;
  readonly executableTransactionIncluded: false;
}

export interface AuthorizationPackageDraftValidity {
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly expiry: bigint;
  readonly expired: boolean;
  readonly invalidatedByCapabilityGrantExpiry: true;
  readonly invalidatedByCandidateExpiry: true;
  readonly invalidatedByTrustDecisionExpiry: true;
  readonly invalidatedByPolicyDecisionExpiry: true;
  readonly invalidatedByApprovalDecisionExpiry: true;
  readonly invalidatedBySessionLock: true;
  readonly invalidatedByNullifierConsumption: true;
}

export interface AuthorizationPackageDraft {
  readonly authorizationPackageDraftId: string;
  readonly requestId: string;
  readonly status: "package_draft_created";
  readonly outcome: "authorization_package_draft_created";
  readonly binding: AuthorizationPackageDraftBinding;
  readonly actionUnlockPublicInputDraft: ActionUnlockPublicInputDraft;
  readonly baseActionAuthorization: BaseActionAuthorization;
  readonly hashSummary: AuthorizationHashSummary;
  readonly nullifierReference: AuthorizationNullifierPublicReference;
  readonly consumerDataBinding: AuthorizationConsumerDataBinding;
  readonly requirements: readonly AuthorizationPackageDraftRequirement[];
  readonly limitations: readonly AuthorizationPackageDraftLimitation[];
  readonly reasons: readonly AuthorizationPackageDraftReason[];
  readonly validity: AuthorizationPackageDraftValidity;
  readonly proofRequirement: string;
  readonly authorizationPackageDraftCreated: true;
  readonly authorizationPackageExecutable: false;
  readonly actionAuthorized: false;
  readonly proofGenerated: false;
  readonly proofVerified: false;
  readonly verifiedFactAvailable: false;
  readonly nullifierConsumed: false;
  readonly adapterExecutionAllowed: false;
  readonly transactionSubmitted: false;
  readonly signatureCreated: false;
  readonly sessionKeyCreated: false;
  readonly vaultAccessed: false;
  readonly persisted: false;
  readonly persistedAsAuthority: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: AuthorizationPackageDraftCollectionResult;
}

export interface AuthorizationPackageDraftRequest {
  readonly requestId: string;
  readonly activeCapabilityGrant: AuthoritativeCapabilityGrant;
  readonly authorizationDecisionCandidate: AuthorizationDecisionCandidate;
  readonly authoritativeTrustDecision: AuthoritativeTrustDecision;
  readonly authoritativePolicyDecision: AuthoritativePolicyDecision;
  readonly platformUserApprovalDecision: PlatformUserApprovalDecision;
  readonly intent: Intent;
  readonly chainId: BigNumberish;
  readonly consumer: string;
  readonly account: string;
  readonly target: string;
  readonly method?: string;
  readonly value?: BigNumberish;
  readonly callData?: BytesLike;
  readonly policyData?: BytesLike;
  readonly policyTarget?: string;
  readonly nullifier: Hex;
  readonly nullifierSafeReference?: string;
  readonly expectedActionHash?: Hex;
  readonly expectedPolicyHash?: Hex;
  readonly expectedConsumerDataHash?: Hex;
  readonly expectedProofInputHash?: Hex;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type AuthorizationPackageDraftResult = RuntimeResult<AuthorizationPackageDraft>;

export interface AuthorizationPackageDraftConsumptionRecord {
  readonly packageDraftEvidenceChainId: string;
  readonly authorizationPackageDraftId?: string;
  readonly nullifier: Hex;
  readonly authorizationDecisionCandidateId: string;
  readonly authoritativeCapabilityGrantId: string;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export interface EphemeralAuthorizationPackageDraftConsumptionStore {
  consume(record: AuthorizationPackageDraftConsumptionRecord): {
    readonly status: "consumed" | "replayed" | "cleared";
    readonly record?: AuthorizationPackageDraftConsumptionRecord;
    readonly records: readonly AuthorizationPackageDraftConsumptionRecord[];
    readonly reason?: string;
  };
  has(packageDraftEvidenceChainId: string): boolean;
  hasNullifier(nullifier: Hex): boolean;
  clear(): {
    readonly status: "cleared";
    readonly records: readonly AuthorizationPackageDraftConsumptionRecord[];
  };
  getAll(): readonly AuthorizationPackageDraftConsumptionRecord[];
}

export type AuthorizationPackageDraftCollectionStatus =
  | "collected"
  | "duplicate_rejected"
  | "cleared";

export interface AuthorizationPackageDraftCollectionResult {
  readonly status: AuthorizationPackageDraftCollectionStatus;
  readonly draft?: AuthorizationPackageDraft;
  readonly drafts: readonly AuthorizationPackageDraft[];
  readonly count: number;
  readonly persisted: false;
  readonly reason?: string;
}

export interface AuthorizationPackageDraftStore {
  addDraft(draft: AuthorizationPackageDraft): AuthorizationPackageDraftCollectionResult;
  getById(draftId: string): AuthorizationPackageDraft | undefined;
  listForSession(sessionId: string): readonly AuthorizationPackageDraft[];
  listForNullifier(nullifier: Hex): readonly AuthorizationPackageDraft[];
  getAll(): readonly AuthorizationPackageDraft[];
  count(): number;
  clear(): AuthorizationPackageDraftCollectionResult;
}

export interface InMemoryAuthorizationPackageDraftStoreOptions {
  readonly maxDraftCount?: number;
}

export interface ProofGenerationAuthorizationInput {
  readonly draft: AuthorizationPackageDraft;
  readonly proofPublicInputs: UnlockProofPublicInputs;
  readonly witnessRequired: true;
  readonly philSecretIncluded: false;
  readonly nullifierSeedIncluded: false;
}

export interface AuthorizationPackageDraftWitnessRequestBoundary {
  readonly draftId: string;
  readonly ownerCommitment: Hex;
  readonly actionHash: Hex;
  readonly policyHash: Hex;
  readonly nullifier: Hex;
  readonly consumerDataHash: Hex;
  readonly expiry: BigNumberish;
  readonly protectedWitnessRequired: true;
  readonly philSecretIncluded: false;
  readonly nullifierSeedIncluded: false;
}

export interface VerifiedAuthorizationFactInput {
  readonly draftId: string;
  readonly factShapeReference: "[fact_high, fact_low]";
  readonly proofVerifiedElsewhere: true;
  readonly verifiedFactPublished: false;
}

export interface AuthorizationPackageFinalizationInput {
  readonly draft: AuthorizationPackageDraft;
  readonly proofGenerationInput?: ProofGenerationAuthorizationInput;
  readonly verifiedFactInput?: VerifiedAuthorizationFactInput;
  readonly finalPackageCreated: false;
  readonly adapterExecutionAllowed: false;
}

const PACKAGE_STATUSES = new Set<AuthorizationPackageDraftStatus>([
  "package_draft_created",
  "package_draft_rejected",
  "package_draft_malformed",
  "package_draft_replayed",
  "package_draft_expired",
  "package_draft_unsupported"
]);

const PACKAGE_OUTCOMES = new Set<AuthorizationPackageDraftOutcome>([
  "authorization_package_draft_created",
  "candidate_ineligible",
  "capability_grant_ineligible",
  "trust_decision_ineligible",
  "policy_decision_ineligible",
  "approval_decision_ineligible",
  "action_correlation_mismatch",
  "action_hash_mismatch",
  "policy_hash_mismatch",
  "consumer_data_hash_mismatch",
  "nullifier_invalid",
  "expiry_invalid",
  "proof_input_hash_mismatch",
  "proof_required",
  "additional_user_approval_required",
  "evidence_expired",
  "evidence_replayed",
  "malformed",
  "unsupported"
]);

const TUPLE_FIELD_ORDER = Object.freeze([
  "ownerCommitment",
  "actionHash",
  "policyHash",
  "nullifier",
  "consumerDataHash",
  "expiry"
] as const);

const LIMITATIONS: readonly AuthorizationPackageDraftLimitation[] = Object.freeze([
  "authorization_package_draft_only",
  "process_local_replay_protection_only",
  "process_local_store_only",
  "no_phil_secret",
  "no_nullifier_seed",
  "no_witness_material",
  "no_proof_generation",
  "no_proof_verification",
  "no_verified_fact",
  "no_nullifier_consumption",
  "no_signature",
  "no_session_key",
  "no_adapter_execution",
  "no_transaction_submission",
  "no_durable_draft_persistence"
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isHex32(value: unknown): value is Hex {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isAddressLike(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function hasValidDateShape(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function expired(value: string | undefined, now = Date.now()): boolean {
  return value !== undefined && Date.parse(value) <= now;
}

function isIntegerLike(value: unknown): value is string | number | bigint {
  if (typeof value === "bigint") return true;
  if (typeof value === "number") return Number.isInteger(value);
  return typeof value === "string" && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value);
}

function integerString(value: string | number | bigint): string {
  return BigInt(value).toString();
}

function expirySeconds(expiresAt: string): bigint {
  return BigInt(Math.floor(Date.parse(expiresAt) / 1000));
}

function stableJson(value: unknown): string {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
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
  return { valid: errors.length === 0, errors: Object.freeze([...new Set(errors)]) };
}

function requirements(): readonly AuthorizationPackageDraftRequirement[] {
  return Object.freeze([
    "active_authoritative_capability_grant",
    "valid_authorization_decision_candidate",
    "authoritative_trust_decision",
    "authoritative_policy_decision",
    "approved_platform_user_approval_decision",
    "exact_action_intent",
    "canonical_action_unlock_public_tuple",
    "public_nullifier_reference",
    "bounded_validity_window"
  ]);
}

function packageError(
  code: string,
  outcome: AuthorizationPackageDraftOutcome,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "invalid_authorization_package",
    code,
    message: "authorization package draft request was rejected",
    boundary: "authorization-engine",
    recoverable: true,
    details: { outcome, errors }
  };
}

function outcomeForErrors(errors: readonly string[]): AuthorizationPackageDraftOutcome {
  if (errors.some((error) => error.includes("replay") || error.includes("duplicate"))) {
    return "evidence_replayed";
  }
  if (errors.some((error) => error.includes("nullifier"))) return "nullifier_invalid";
  if (errors.some((error) => error.includes("proofInputHash"))) return "proof_input_hash_mismatch";
  if (errors.some((error) => error.includes("actionHash"))) return "action_hash_mismatch";
  if (errors.some((error) => error.includes("policyHash"))) return "policy_hash_mismatch";
  if (errors.some((error) => error.includes("consumerDataHash"))) return "consumer_data_hash_mismatch";
  if (errors.some((error) => error.includes("expiry") || error.includes("expired"))) {
    return "evidence_expired";
  }
  if (errors.some((error) => error.includes("candidate"))) return "candidate_ineligible";
  if (errors.some((error) => error.includes("capability grant") || error.includes("grant"))) {
    return "capability_grant_ineligible";
  }
  if (errors.some((error) => error.includes("Trust Decision"))) return "trust_decision_ineligible";
  if (errors.some((error) => error.includes("Policy Decision"))) return "policy_decision_ineligible";
  if (errors.some((error) => error.includes("Approval Decision") || error.includes("approval"))) {
    return "approval_decision_ineligible";
  }
  if (errors.some((error) => error.includes("mutation") || error.includes("mismatch"))) {
    return "action_correlation_mismatch";
  }
  return "malformed";
}

export function isAuthorizationPackageDraftStatus(
  value: unknown
): value is AuthorizationPackageDraftStatus {
  return PACKAGE_STATUSES.has(value as AuthorizationPackageDraftStatus);
}

export function isAuthorizationPackageDraftOutcome(
  value: unknown
): value is AuthorizationPackageDraftOutcome {
  return PACKAGE_OUTCOMES.has(value as AuthorizationPackageDraftOutcome);
}

export function validateAuthorizationNullifierInput(input: unknown): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) return validation(["nullifier input must be an object"]);
  if (Object.prototype.hasOwnProperty.call(input, "nullifierSeed")) {
    errors.push("nullifierSeed is forbidden in Authorization Package Draft requests");
  }
  if (!isHex32(input.nullifier)) errors.push("nullifier must be a bytes32 hex string");
  if (input.nullifier === "0x0000000000000000000000000000000000000000000000000000000000000000") {
    errors.push("nullifier must be non-zero");
  }
  return validation(errors);
}

export function validateAuthorizationPackageDraftRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["authorization package draft request must be an object"]);
  for (const field of [
    "requestId",
    "consumer",
    "account",
    "target",
    "nullifier",
    "issuedAt",
    "expiresAt",
    "auditCorrelationId"
  ] as const) {
    if (!isNonEmptyString(request[field])) errors.push(`${field} is required`);
  }
  if (!isRecord(request.activeCapabilityGrant)) errors.push("activeCapabilityGrant is required");
  if (!isRecord(request.authorizationDecisionCandidate)) {
    errors.push("authorizationDecisionCandidate is required");
  }
  if (!isRecord(request.authoritativeTrustDecision)) errors.push("authoritativeTrustDecision is required");
  if (!isRecord(request.authoritativePolicyDecision)) errors.push("authoritativePolicyDecision is required");
  if (!isRecord(request.platformUserApprovalDecision)) {
    errors.push("platformUserApprovalDecision is required");
  }
  if (!isRecord(request.intent)) {
    errors.push("intent is required");
  } else {
    if (!isNonEmptyString(request.intent.intentId)) errors.push("intent.intentId is required");
    if (!isNonEmptyString(request.intent.applicationId)) errors.push("intent.applicationId is required");
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a parseable date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (request.callData !== undefined && typeof request.callData !== "string") {
    errors.push("callData must be a hex string when supplied");
  }
  if (request.policyData !== undefined && typeof request.policyData !== "string") {
    errors.push("policyData must be a hex string when supplied");
  }
  errors.push(...validateAuthorizationNullifierInput(request).errors);
  errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  return validation(errors);
}

export function deriveCanonicalAuthorizationActionHash(input: {
  readonly chainId: BigNumberish;
  readonly consumer: string;
  readonly account: string;
  readonly target: string;
  readonly value?: BigNumberish;
  readonly callData?: BytesLike;
}): {
  readonly consumerData: Hex;
  readonly consumerDataHash: Hex;
  readonly actionHash: Hex;
  readonly callDataHash: Hex;
  readonly normalizedRequest: {
    readonly account: string;
    readonly target: string;
    readonly value: bigint;
    readonly callData: Hex;
  };
} {
  const consumerData = encodeUnlockConsumerData({
    account: input.account,
    target: input.target,
    value: input.value ?? 0,
    callData: input.callData ?? "0x"
  });
  const action = computeUnlockActionHashFromConsumerData({
    chainId: input.chainId,
    consumer: input.consumer,
    consumerData
  });
  return freezeRecord({
    consumerData,
    consumerDataHash: dataHash(consumerData),
    actionHash: action.actionHash,
    callDataHash: dataHash(action.request.callData),
    normalizedRequest: action.request
  });
}

export function assembleActionUnlockPublicInputDraft(input: {
  readonly authorization: BaseActionAuthorization;
}): ActionUnlockPublicInputDraft {
  const proofPackage = buildUnlockProofPackageFromAuthorization(input.authorization);
  return freezeRecord({
    version: UNLOCK_PROOF_SCHEMA_VERSION,
    proofType: UNLOCK_PROOF_TYPE,
    tupleFieldOrder: TUPLE_FIELD_ORDER,
    publicInputs: proofPackage.publicInputs,
    proofInputHash: proofPackage.proofInputHash,
    proofPackageDraft: proofPackage,
    factShapeReference: "[fact_high, fact_low]" as const,
    proofBlobIncluded: false as const,
    proofGenerated: false as const,
    proofVerified: false as const,
    verifiedFactAvailable: false as const
  });
}

export function validateActionUnlockPublicInputDraft(
  draft: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(draft)) return validation(["ACTION_UNLOCK public input draft must be an object"]);
  if (draft.version !== UNLOCK_PROOF_SCHEMA_VERSION) errors.push("version must remain v1");
  if (draft.proofType !== UNLOCK_PROOF_TYPE) {
    errors.push("proofType must remain stwo-unlock-keccak-v1");
  }
  if (!isRecord(draft.publicInputs)) errors.push("publicInputs is required");
  if (!isHex32(draft.proofInputHash)) errors.push("proofInputHash must be bytes32");
  if (!Array.isArray(draft.tupleFieldOrder)
    || stableJson(draft.tupleFieldOrder) !== stableJson(TUPLE_FIELD_ORDER)) {
    errors.push("tuple field order changed");
  }
  if (draft.factShapeReference !== "[fact_high, fact_low]") {
    errors.push("fact shape reference changed");
  }
  for (const field of ["proofBlobIncluded", "proofGenerated", "proofVerified", "verifiedFactAvailable"]) {
    if (draft[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

function correlationErrors(request: AuthorizationPackageDraftRequest): readonly string[] {
  const errors: string[] = [];
  const grant = request.activeCapabilityGrant;
  const candidate = request.authorizationDecisionCandidate;
  const trust = request.authoritativeTrustDecision;
  const policy = request.authoritativePolicyDecision;
  const approval = request.platformUserApprovalDecision;
  const intent = request.intent;

  errors.push(...validateAuthoritativeCapabilityGrantShape(grant).errors.map((error) => `grant.${error}`));
  errors.push(...validateAuthorizationDecisionCandidateShape(candidate).errors.map((error) => `candidate.${error}`));
  errors.push(...validateAuthoritativeTrustDecisionShape(trust).errors.map((error) => `Trust Decision.${error}`));
  errors.push(...validateAuthoritativePolicyDecisionShape(policy).errors.map((error) => `Policy Decision.${error}`));
  errors.push(...validatePlatformUserApprovalDecisionShape(approval).errors.map((error) => `Approval Decision.${error}`));

  if (grant.status !== "active") errors.push("capability grant is not active");
  if (grant.revocation.revoked) errors.push("capability grant revoked");
  if (expired(grant.validity.expiresAt)) errors.push("capability grant expired");
  if (expired(candidate.validity.expiresAt)) errors.push("candidate expired");
  if (expired(trust.validity.expiresAt)) errors.push("Trust Decision expired");
  if (expired(policy.validity.expiresAt)) errors.push("Policy Decision expired");
  if (expired(approval.validity.expiresAt)) errors.push("Approval Decision expired");
  if (expired(request.expiresAt)) errors.push("package draft request expired");
  if (Date.parse(request.expiresAt) > Date.parse(grant.validity.expiresAt)) {
    errors.push("expiry extends beyond capability grant");
  }
  if (Date.parse(request.expiresAt) > Date.parse(candidate.validity.expiresAt)) {
    errors.push("expiry extends beyond candidate");
  }
  if (Date.parse(candidate.validity.expiresAt) > Date.parse(grant.validity.expiresAt)) {
    errors.push("candidate expiry extends beyond capability grant");
  }

  if (candidate.binding.authoritativeCapabilityGrantId !== grant.authoritativeCapabilityGrantId) {
    errors.push("candidate and capability grant mismatch");
  }
  if (candidate.binding.authoritativeTrustDecisionId !== trust.authoritativeTrustDecisionId) {
    errors.push("candidate and Trust Decision mismatch");
  }
  if (candidate.binding.authoritativePolicyDecisionId !== policy.authoritativePolicyDecisionId) {
    errors.push("candidate and Policy Decision mismatch");
  }
  if (candidate.binding.platformUserApprovalDecisionId
    !== approval.platformUserApprovalDecisionId) {
    errors.push("candidate and Approval Decision mismatch");
  }
  if (grant.binding.authoritativeTrustDecisionId !== trust.authoritativeTrustDecisionId) {
    errors.push("grant and Trust Decision mismatch");
  }
  if (grant.binding.authoritativePolicyDecisionId !== policy.authoritativePolicyDecisionId) {
    errors.push("grant and Policy Decision mismatch");
  }
  if (grant.binding.platformUserApprovalDecisionId !== approval.platformUserApprovalDecisionId) {
    errors.push("grant and Approval Decision mismatch");
  }
  if (policy.binding.authoritativeTrustDecisionId !== trust.authoritativeTrustDecisionId) {
    errors.push("Policy Decision Trust Decision mismatch");
  }
  if (approval.binding.authoritativeTrustDecisionId !== trust.authoritativeTrustDecisionId) {
    errors.push("Approval Decision Trust Decision mismatch");
  }
  if (approval.binding.authoritativePolicyDecisionId !== policy.authoritativePolicyDecisionId) {
    errors.push("Approval Decision Policy Decision mismatch");
  }

  for (const [label, expected, actual] of [
    ["owner", grant.binding.ownerCommitment, candidate.binding.ownerCommitment],
    ["session", grant.binding.sessionId, candidate.binding.sessionId],
    ["application", grant.binding.applicationId, candidate.binding.applicationId],
    ["capability", grant.binding.capabilityName, candidate.binding.requiredCapability],
    ["audit", grant.binding.auditCorrelationId, candidate.binding.auditCorrelationId],
    ["intent", candidate.binding.intentId, intent.intentId],
    ["intent application", candidate.binding.applicationId, intent.applicationId],
    ["trust owner", trust.scope.ownerCommitment, candidate.binding.ownerCommitment],
    ["trust session", trust.scope.sessionId, candidate.binding.sessionId],
    ["trust application", trust.scope.applicationId, candidate.binding.applicationId],
    ["trust audit", trust.scope.auditCorrelationId, candidate.binding.auditCorrelationId],
    ["policy owner", policy.scope.ownerCommitment, candidate.binding.ownerCommitment],
    ["policy session", policy.scope.sessionId, candidate.binding.sessionId],
    ["policy application", policy.scope.applicationId, candidate.binding.applicationId],
    ["policy capability", policy.scope.capabilityName, candidate.binding.requiredCapability],
    ["policy action", policy.scope.actionType, grant.scope.actionTypes[0]],
    ["policy audit", policy.scope.auditCorrelationId, candidate.binding.auditCorrelationId],
    ["approval owner", approval.actionRequest.ownerCommitment, candidate.binding.ownerCommitment],
    ["approval session", approval.actionRequest.sessionId, candidate.binding.sessionId],
    ["approval application", approval.actionRequest.applicationId, candidate.binding.applicationId],
    ["approval capability", approval.actionRequest.capabilityName, candidate.binding.requiredCapability],
    ["approval audit", approval.actionRequest.auditCorrelationId, candidate.binding.auditCorrelationId],
    ["request audit", request.auditCorrelationId, candidate.binding.auditCorrelationId]
  ] as const) {
    if (expected !== actual) errors.push(`${label} mismatch`);
  }
  if (!intent.requestedCapabilities.includes(candidate.binding.requiredCapability)) {
    errors.push("intent missing capability");
  }
  if (approval.userApproved !== true || approval.outcome !== "user_approved") {
    errors.push("Approval Decision not approved");
  }
  if (candidate.additionalUserApprovalRequired !== false) {
    errors.push("additional user approval required");
  }
  if (candidate.actionSummary.target !== undefined
    && grant.scope.allowedTargets.length > 0
    && !grant.scope.allowedTargets.includes(candidate.actionSummary.target)) {
    errors.push("target mutation detected");
  }
  if (isAddressLike(candidate.actionSummary.target)
    && request.target.toLowerCase() !== candidate.actionSummary.target.toLowerCase()) {
    errors.push("target mutation detected");
  }
  if (candidate.actionSummary.method !== undefined
    && request.method !== undefined
    && request.method !== candidate.actionSummary.method) {
    errors.push("method mutation detected");
  }
  if (candidate.actionSummary.value !== undefined
    && grant.scope.valueLimit !== undefined
    && candidate.actionSummary.value !== grant.scope.valueLimit) {
    errors.push("value mutation detected");
  }
  if (candidate.actionSummary.value !== undefined
    && request.value !== undefined
    && isIntegerLike(candidate.actionSummary.value)
    && isIntegerLike(request.value)
    && integerString(candidate.actionSummary.value) !== integerString(request.value)) {
    errors.push("value mutation detected");
  }
  if (candidate.actionSummary.scope !== undefined
    && grant.scope.effectiveScope !== undefined
    && stableJson(candidate.actionSummary.scope) !== stableJson(grant.scope.effectiveScope)) {
    errors.push("scope mutation detected");
  }
  if (candidate.actionSummary.requestedDurationSeconds !== undefined
    && grant.scope.effectiveDurationSeconds !== undefined
    && candidate.actionSummary.requestedDurationSeconds > grant.scope.effectiveDurationSeconds) {
    errors.push("duration mutation detected");
  }
  if (candidate.actionSummary.network !== undefined
    && grant.scope.network !== undefined
    && candidate.actionSummary.network !== grant.scope.network) {
    errors.push("network mutation detected");
  }
  if (candidate.actionSummary.chainId !== undefined
    && grant.scope.chainId !== undefined
    && String(candidate.actionSummary.chainId) !== String(grant.scope.chainId)) {
    errors.push("chain mutation detected");
  }
  return Object.freeze([...new Set(errors)]);
}

function auditDraftForPackage(input: {
  readonly request: AuthorizationPackageDraftRequest;
  readonly outcome: AuthorizationPackageDraftOutcome;
  readonly draft?: AuthorizationPackageDraft;
  readonly errors?: readonly string[];
  readonly hashes?: AuthorizationHashSummary;
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.draft ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: input.request.authorizationDecisionCandidate?.binding.sessionId,
    applicationId: input.request.authorizationDecisionCandidate?.binding.applicationId,
    intentId: input.request.intent?.intentId,
    capability: input.request.authorizationDecisionCandidate?.binding.requiredCapability,
    summary: input.draft
      ? "Authorization Package Draft created; proof, fact publication, nullifier consumption, adapter call, and execution did not occur."
      : "Authorization Package Draft request rejected; proof, fact publication, nullifier consumption, adapter call, and execution did not occur.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authorizationPackageDraftId: input.draft?.authorizationPackageDraftId,
      authorizationDecisionCandidateId:
        input.request.authorizationDecisionCandidate?.authorizationDecisionCandidateId,
      authoritativeCapabilityGrantId:
        input.request.activeCapabilityGrant?.authoritativeCapabilityGrantId,
      actionType: input.request.authorizationDecisionCandidate?.binding.actionType,
      targetReference: input.request.authorizationDecisionCandidate?.actionSummary.target,
      value: input.request.authorizationDecisionCandidate?.actionSummary.value,
      actionHash: input.hashes?.actionHash ?? input.draft?.hashSummary.actionHash,
      policyHash: input.hashes?.policyHash ?? input.draft?.hashSummary.policyHash,
      consumerDataHash:
        input.hashes?.consumerDataHash ?? input.draft?.hashSummary.consumerDataHash,
      proofInputHash: input.hashes?.proofInputHash ?? input.draft?.hashSummary.proofInputHash,
      nullifier: input.request.nullifier,
      proofType: UNLOCK_PROOF_TYPE,
      factShapeReference: "[fact_high, fact_low]",
      outcome: input.outcome,
      authorizationPackageDraftCreated: Boolean(input.draft),
      authorizationPackageExecutable: false,
      actionAuthorized: false,
      proofGenerated: false,
      proofVerified: false,
      verifiedFactAvailable: false,
      nullifierConsumed: false,
      adapterExecutionAllowed: false,
      transactionSubmitted: false,
      errors: input.errors ?? []
    }
  });
}

export function createAuthorizationPackageDraft(
  request: AuthorizationPackageDraftRequest,
  consumptionStore?: EphemeralAuthorizationPackageDraftConsumptionStore,
  draftStore?: AuthorizationPackageDraftStore,
  auditDraftCollector?: AuditDraftCollector
): AuthorizationPackageDraftResult {
  const requestShape = validateAuthorizationPackageDraftRequest(request);
  if (!requestShape.valid) {
    const outcome = outcomeForErrors(requestShape.errors);
    const auditEventDraft = auditDraftForPackage({
      request,
      outcome,
      errors: requestShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(packageError(
      "AUTHORIZATION_PACKAGE_DRAFT_MALFORMED",
      outcome,
      requestShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const correlation = correlationErrors(request);
  if (correlation.length > 0) {
    const outcome = outcomeForErrors(correlation);
    const auditEventDraft = auditDraftForPackage({
      request,
      outcome,
      errors: correlation
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(packageError(
      "AUTHORIZATION_PACKAGE_DRAFT_REJECTED",
      outcome,
      correlation
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  let canonicalAction: ReturnType<typeof deriveCanonicalAuthorizationActionHash>;
  let policyHashValue: Hex;
  let authorization: BaseActionAuthorization;
  let publicInputDraft: ActionUnlockPublicInputDraft;
  try {
    canonicalAction = deriveCanonicalAuthorizationActionHash({
      chainId: request.chainId,
      consumer: request.consumer,
      account: request.account,
      target: request.target,
      value: request.value ?? 0,
      callData: request.callData ?? "0x"
    });
    policyHashValue = derivePolicyHash({
      chainId: request.chainId,
      consumer: request.consumer,
      target: request.policyTarget ?? request.target,
      expiry: expirySeconds(request.expiresAt),
      policyDataHash: dataHash(request.policyData ?? "0x")
    });
    authorization = normalizeBaseActionAuthorization({
      consumer: request.consumer,
      ownerCommitment: request.authorizationDecisionCandidate.binding.ownerCommitment,
      actionHash: canonicalAction.actionHash,
      policyHash: policyHashValue,
      nullifier: request.nullifier,
      consumerDataHash: canonicalAction.consumerDataHash,
      expiry: expirySeconds(request.expiresAt)
    });
    publicInputDraft = assembleActionUnlockPublicInputDraft({ authorization });
  } catch (error) {
    const errors = [error instanceof Error ? error.message : "canonical hash derivation failed"];
    const outcome = outcomeForErrors(errors);
    const auditEventDraft = auditDraftForPackage({ request, outcome, errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(packageError(
      "AUTHORIZATION_PACKAGE_DRAFT_HASH_DERIVATION_FAILED",
      outcome,
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const hashSummary = freezeRecord({
    actionHash: canonicalAction.actionHash,
    policyHash: policyHashValue,
    consumerDataHash: canonicalAction.consumerDataHash,
    proofInputHash: publicInputDraft.proofInputHash,
    authorizationDigest: authorizationDigest(authorization),
    m1ActionDigestPreview:
      request.authorizationDecisionCandidate.evidence.actionDigestPreview.digestPreview,
    m1PreviewIsCanonicalActionHash: false as const
  });

  const hashErrors: string[] = [];
  if (request.expectedActionHash !== undefined
    && request.expectedActionHash !== hashSummary.actionHash) {
    hashErrors.push("actionHash mismatch");
  }
  if (request.expectedPolicyHash !== undefined
    && request.expectedPolicyHash !== hashSummary.policyHash) {
    hashErrors.push("policyHash mismatch");
  }
  if (request.expectedConsumerDataHash !== undefined
    && request.expectedConsumerDataHash !== hashSummary.consumerDataHash) {
    hashErrors.push("consumerDataHash mismatch");
  }
  if (request.expectedProofInputHash !== undefined
    && request.expectedProofInputHash !== hashSummary.proofInputHash) {
    hashErrors.push("proofInputHash mismatch");
  }
  const publicDraftShape = validateActionUnlockPublicInputDraft(publicInputDraft);
  hashErrors.push(...publicDraftShape.errors);
  if (hashErrors.length > 0) {
    const outcome = outcomeForErrors(hashErrors);
    const auditEventDraft = auditDraftForPackage({
      request,
      outcome,
      errors: hashErrors,
      hashes: hashSummary
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(packageError(
      "AUTHORIZATION_PACKAGE_DRAFT_HASH_MISMATCH",
      outcome,
      hashErrors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const packageDraftEvidenceChainId = createAuditCorrelationId([
    request.activeCapabilityGrant.authoritativeCapabilityGrantId,
    request.authorizationDecisionCandidate.authorizationDecisionCandidateId,
    hashSummary.actionHash,
    hashSummary.policyHash,
    hashSummary.consumerDataHash,
    request.nullifier,
    hashSummary.proofInputHash,
    request.auditCorrelationId,
    "authorization-package-draft-evidence-chain"
  ]);
  if (consumptionStore?.has(packageDraftEvidenceChainId)
    || consumptionStore?.hasNullifier(request.nullifier)) {
    const errors = ["authorization package draft evidence or nullifier was already used locally"];
    const outcome = "evidence_replayed";
    const auditEventDraft = auditDraftForPackage({
      request,
      outcome,
      errors,
      hashes: hashSummary
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(packageError(
      "AUTHORIZATION_PACKAGE_DRAFT_REPLAYED",
      outcome,
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const draftId = createAuditCorrelationId([
    packageDraftEvidenceChainId,
    request.issuedAt,
    request.expiresAt,
    "authorization-package-draft"
  ]);
  const draftBase = {
    authorizationPackageDraftId: draftId,
    requestId: request.requestId,
    status: "package_draft_created" as const,
    outcome: "authorization_package_draft_created" as const,
    binding: {
      authoritativeCapabilityGrantId:
        request.activeCapabilityGrant.authoritativeCapabilityGrantId,
      authorizationDecisionCandidateId:
        request.authorizationDecisionCandidate.authorizationDecisionCandidateId,
      authoritativeTrustDecisionId:
        request.authoritativeTrustDecision.authoritativeTrustDecisionId,
      authoritativePolicyDecisionId:
        request.authoritativePolicyDecision.authoritativePolicyDecisionId,
      platformUserApprovalDecisionId:
        request.platformUserApprovalDecision.platformUserApprovalDecisionId,
      intentId: request.intent.intentId,
      ownerCommitment: request.authorizationDecisionCandidate.binding.ownerCommitment,
      sessionId: request.authorizationDecisionCandidate.binding.sessionId,
      applicationId: request.authorizationDecisionCandidate.binding.applicationId,
      capabilityName: request.authorizationDecisionCandidate.binding.requiredCapability,
      actionType: request.authorizationDecisionCandidate.binding.actionType,
      auditCorrelationId: request.auditCorrelationId
    },
    actionUnlockPublicInputDraft: publicInputDraft,
    baseActionAuthorization: authorization,
    hashSummary,
    nullifierReference: {
      nullifier: request.nullifier,
      source: "explicit_public_nullifier" as const,
      safeReference: request.nullifierSafeReference,
      nullifierSeedIncluded: false as const,
      nullifierConsumed: false as const,
      durableReplayProtectionClaimed: false as const
    },
    consumerDataBinding: {
      consumer: authorization.consumer,
      account: canonicalAction.normalizedRequest.account,
      target: canonicalAction.normalizedRequest.target,
      value: canonicalAction.normalizedRequest.value.toString(),
      callDataHash: canonicalAction.callDataHash,
      consumerDataHash: canonicalAction.consumerDataHash,
      rawConsumerDataIncluded: false as const,
      executableUserOperationIncluded: false as const,
      adapterPayloadIncluded: false as const
    },
    requirements: requirements(),
    limitations: LIMITATIONS,
    reasons: Object.freeze([
      "active-capability-grant-valid",
      "authorization-decision-candidate-valid",
      "trust-policy-approval-chain-correlated",
      "canonical-action-hash-derived",
      "canonical-policy-hash-derived",
      "consumer-data-hash-derived",
      "public-nullifier-accepted",
      "canonical-proof-input-hash-derived",
      "authorization-package-draft-only",
      "no-proof-generation",
      "no-nullifier-consumption",
      "no-execution"
    ]),
    validity: {
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      expiry: expirySeconds(request.expiresAt),
      expired: false,
      invalidatedByCapabilityGrantExpiry: true as const,
      invalidatedByCandidateExpiry: true as const,
      invalidatedByTrustDecisionExpiry: true as const,
      invalidatedByPolicyDecisionExpiry: true as const,
      invalidatedByApprovalDecisionExpiry: true as const,
      invalidatedBySessionLock: true as const,
      invalidatedByNullifierConsumption: true as const
    },
    proofRequirement: request.authorizationDecisionCandidate.proofRequirement,
    authorizationPackageDraftCreated: true as const,
    authorizationPackageExecutable: false as const,
    actionAuthorized: false as const,
    proofGenerated: false as const,
    proofVerified: false as const,
    verifiedFactAvailable: false as const,
    nullifierConsumed: false as const,
    adapterExecutionAllowed: false as const,
    transactionSubmitted: false as const,
    signatureCreated: false as const,
    sessionKeyCreated: false as const,
    vaultAccessed: false as const,
    persisted: false as const,
    persistedAsAuthority: false as const
  };
  const draft = freezeRecord(draftBase) as AuthorizationPackageDraft;
  const draftShape = validateAuthorizationPackageDraftShape(draft);
  if (!draftShape.valid) {
    const outcome = "malformed";
    const auditEventDraft = auditDraftForPackage({
      request,
      outcome,
      draft,
      errors: draftShape.errors,
      hashes: hashSummary
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(packageError(
      "AUTHORIZATION_PACKAGE_DRAFT_SHAPE_INVALID",
      outcome,
      draftShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const consumed = consumptionStore?.consume({
    packageDraftEvidenceChainId,
    authorizationPackageDraftId: draft.authorizationPackageDraftId,
    nullifier: request.nullifier,
    authorizationDecisionCandidateId:
      request.authorizationDecisionCandidate.authorizationDecisionCandidateId,
    authoritativeCapabilityGrantId:
      request.activeCapabilityGrant.authoritativeCapabilityGrantId,
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const errors = ["authorization package draft evidence or nullifier was already used locally"];
    const outcome = "evidence_replayed";
    const auditEventDraft = auditDraftForPackage({
      request,
      outcome,
      errors,
      hashes: hashSummary
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(packageError(
      "AUTHORIZATION_PACKAGE_DRAFT_REPLAYED",
      outcome,
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const auditEventDraft = auditDraftForPackage({
    request,
    outcome: "authorization_package_draft_created",
    draft,
    hashes: hashSummary
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const collectionResult = draftStore?.addDraft(draft);

  return runtimeOk(freezeRecord({
    ...draftBase,
    auditEventDraft,
    auditDraftCollectionResult,
    collectionResult
  }) as AuthorizationPackageDraft);
}

export function validateAuthorizationPackageDraftShape(
  draft: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(draft)) return validation(["authorization package draft must be an object"]);
  if (!isNonEmptyString(draft.authorizationPackageDraftId)) {
    errors.push("authorizationPackageDraftId is required");
  }
  if (draft.status !== "package_draft_created") errors.push("status must be package_draft_created");
  if (draft.outcome !== "authorization_package_draft_created") {
    errors.push("outcome must be authorization_package_draft_created");
  }
  if (!isRecord(draft.binding)) errors.push("binding is required");
  if (!isRecord(draft.actionUnlockPublicInputDraft)) {
    errors.push("actionUnlockPublicInputDraft is required");
  } else {
    errors.push(...validateActionUnlockPublicInputDraft(draft.actionUnlockPublicInputDraft).errors);
  }
  if (!isRecord(draft.baseActionAuthorization)) errors.push("baseActionAuthorization is required");
  if (!isRecord(draft.hashSummary)) errors.push("hashSummary is required");
  if (!isRecord(draft.nullifierReference)) errors.push("nullifierReference is required");
  if (!isRecord(draft.consumerDataBinding)) errors.push("consumerDataBinding is required");
  for (const field of [
    "authorizationPackageDraftCreated"
  ]) {
    if (draft[field] !== true) errors.push(`${field} must be true`);
  }
  for (const field of [
    "authorizationPackageExecutable",
    "actionAuthorized",
    "proofGenerated",
    "proofVerified",
    "verifiedFactAvailable",
    "nullifierConsumed",
    "adapterExecutionAllowed",
    "transactionSubmitted",
    "signatureCreated",
    "sessionKeyCreated",
    "vaultAccessed",
    "persisted",
    "persistedAsAuthority"
  ]) {
    if (draft[field] !== false) errors.push(`${field} must be false`);
  }
  const nullifierReference = isRecord(draft.nullifierReference)
    ? draft.nullifierReference
    : undefined;
  if (nullifierReference?.nullifierSeedIncluded !== false) {
    errors.push("nullifierSeedIncluded must be false");
  }
  return validation(errors);
}

export function createEphemeralAuthorizationPackageDraftConsumptionStore():
  EphemeralAuthorizationPackageDraftConsumptionStore {
  const records = new Map<string, AuthorizationPackageDraftConsumptionRecord>();
  const nullifiers = new Set<Hex>();
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(record) {
      if (records.has(record.packageDraftEvidenceChainId) || nullifiers.has(record.nullifier)) {
        return freezeRecord({
          status: "replayed" as const,
          record: records.get(record.packageDraftEvidenceChainId),
          records: all(),
          reason: "authorization package draft evidence or nullifier already used locally"
        });
      }
      const frozen = freezeRecord(record);
      records.set(record.packageDraftEvidenceChainId, frozen);
      nullifiers.add(record.nullifier);
      return freezeRecord({ status: "consumed" as const, record: frozen, records: all() });
    },
    has(packageDraftEvidenceChainId) {
      return records.has(packageDraftEvidenceChainId);
    },
    hasNullifier(nullifierValue) {
      return nullifiers.has(nullifierValue);
    },
    clear() {
      records.clear();
      nullifiers.clear();
      return freezeRecord({ status: "cleared" as const, records: all() });
    },
    getAll: all
  };
}

export function createInMemoryAuthorizationPackageDraftStore(
  options: InMemoryAuthorizationPackageDraftStoreOptions = {}
): AuthorizationPackageDraftStore {
  const maxDraftCount = Math.max(1, Math.floor(options.maxDraftCount ?? 100));
  const drafts = new Map<string, AuthorizationPackageDraft>();
  function all() {
    return Object.freeze(Array.from(drafts.values()).map(freezeRecord));
  }
  function collectionResult(input: {
    readonly status: AuthorizationPackageDraftCollectionStatus;
    readonly draft?: AuthorizationPackageDraft;
    readonly reason?: string;
  }): AuthorizationPackageDraftCollectionResult {
    return freezeRecord({
      status: input.status,
      draft: input.draft,
      drafts: all(),
      count: drafts.size,
      persisted: false as const,
      reason: input.reason
    });
  }
  return {
    addDraft(draft) {
      if (drafts.has(draft.authorizationPackageDraftId)) {
        return collectionResult({
          status: "duplicate_rejected",
          draft,
          reason: "authorization package draft ID already exists"
        });
      }
      if (drafts.size >= maxDraftCount) {
        const oldest = drafts.keys().next().value as string | undefined;
        if (oldest) drafts.delete(oldest);
      }
      const frozen = freezeRecord(draft);
      drafts.set(draft.authorizationPackageDraftId, frozen);
      return collectionResult({ status: "collected", draft: frozen });
    },
    getById(draftId) {
      return drafts.get(draftId);
    },
    listForSession(sessionId) {
      return Object.freeze(all().filter((draft) => draft.binding.sessionId === sessionId));
    },
    listForNullifier(nullifierValue) {
      return Object.freeze(all().filter(
        (draft) => draft.nullifierReference.nullifier === nullifierValue
      ));
    },
    getAll: all,
    count() {
      return drafts.size;
    },
    clear() {
      drafts.clear();
      return collectionResult({ status: "cleared" });
    }
  };
}
