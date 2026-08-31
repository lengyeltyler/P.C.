import { keccak256, toUtf8Bytes } from "ethers";

import {
  PHIL_DEVICE_CREDENTIAL_REGISTRY_VERSION,
  type PhilCredentialRecord
} from "../deviceIdentityLifecycle.ts";
import {
  PHIL_DEVICE_IDENTITY_STORAGE_VERSION,
  createEncryptedDeviceIdentityRegistryStore,
  type PhilDeviceIdentityRegistryKeyProvider,
  type PhilDeviceIdentityRegistryStorageBackend
} from "../deviceIdentityStorage.ts";
import type { Hex } from "../hashes.ts";
import type { PhilIdentityPublic } from "../identity.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type { BoundedTrustDecisionCandidate } from "./boundedTrustDecisionCandidate.ts";
import { validateBoundedTrustDecisionCandidateShape } from "./boundedTrustDecisionCandidate.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  UserSessionLifecycleSnapshot
} from "./sessionLifecycle.ts";
import { validateUserSessionLifecycleSnapshotShape } from "./sessionLifecycle.ts";
import type {
  TrustManagerProductionVerificationResultValue
} from "./trustManagerProductionVerification.ts";
import { validateTrustManagerProductionVerificationResultShape } from "./trustManagerProductionVerification.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";
import type { UnlockedDeviceVaultHandleMetadata } from "./deviceVaultUnlock.ts";

export type CredentialCounterPersistenceStatus =
  | "persistence_succeeded"
  | "persistence_rejected"
  | "persistence_malformed"
  | "persistence_replayed"
  | "persistence_failed"
  | "persistence_unsupported";

export type CredentialCounterPersistenceOutcome =
  | "counter_persisted"
  | "counter_unchanged_accepted"
  | "counter_unsupported"
  | "stored_counter_mismatch"
  | "counter_rollback_detected"
  | "counter_clone_risk_detected"
  | "credential_not_found"
  | "credential_ineligible"
  | "verification_result_ineligible"
  | "candidate_ineligible"
  | "owner_mismatch"
  | "session_mismatch"
  | "application_mismatch"
  | "audit_correlation_mismatch"
  | "vault_handle_invalid"
  | "registry_integrity_failed"
  | "write_failed"
  | "verification_failed"
  | "expired"
  | "replayed"
  | "malformed"
  | "unsupported";

export type CredentialCounterPersistenceReason =
  | "production-verification-result-required"
  | "bounded-trust-decision-candidate-required"
  | "unlocked-vault-handle-required"
  | "existing-encrypted-registry-storage-reused"
  | "single-credential-target"
  | "expected-counter-matched"
  | "counter-advanced"
  | "counter-unchanged-zero"
  | "counter-unsupported"
  | "counter-rollback-rejected"
  | "counter-clone-risk-rejected"
  | "stale-write-rejected"
  | "counter-field-only"
  | "receipt-only-no-trust-decision"
  | "no-authority"
  | (string & {});

export type CredentialCounterPersistenceRequirement =
  | "successful_production_verification"
  | "bounded_candidate"
  | "unlocked_lifecycle"
  | "valid_vault_handle"
  | "owner_session_application_audit_correlation"
  | "current_counter_match"
  | "registry_integrity"
  | "counter_update_verification";

export type CredentialCounterPersistenceLimitation =
  | "single_counter_field_only"
  | "no_compare_and_swap_available"
  | "best_effort_stale_hash_guard"
  | "no_trust_decision"
  | "no_capability_grant"
  | "no_authorization"
  | "no_registry_plaintext_export"
  | "no_vault_material_export";

export interface CredentialCounterPersistenceCorrelation {
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly credentialId: string;
  readonly credentialSafeReference: Hex;
  readonly auditCorrelationId: string;
}

export interface CredentialCounterState {
  readonly expectedStoredCounter: number;
  readonly currentStoredCounter: number;
  readonly previousVerificationCounter: number;
  readonly verifiedReturnedCounter: number;
  readonly counterStatus: string;
  readonly counterAdvanced: boolean;
  readonly counterUnchangedZero: boolean;
  readonly counterUnsupported: boolean;
  readonly rollbackDetected: boolean;
  readonly cloneSuspected: boolean;
}

export interface CredentialCounterMutationSummary {
  readonly credentialId: string;
  readonly previousStoredCounter: number;
  readonly persistedCounter: number;
  readonly mutationPerformed: boolean;
  readonly onlyCounterFieldChanged: boolean;
  readonly lifecycleStatusChanged: false;
  readonly otherCredentialChanged: false;
  readonly registryAuditEventCountBefore: number;
  readonly registryAuditEventCountAfter: number;
  readonly registryHashBefore: Hex;
  readonly registryHashAfter?: Hex;
  readonly storageBackendKind: string;
}

export interface CredentialCounterPersistenceReceipt {
  readonly credentialCounterPersistenceReceiptId: string;
  readonly operationId: string;
  readonly status: CredentialCounterPersistenceStatus;
  readonly outcome: CredentialCounterPersistenceOutcome;
  readonly correlation: CredentialCounterPersistenceCorrelation;
  readonly counterState: CredentialCounterState;
  readonly mutationSummary: CredentialCounterMutationSummary;
  readonly requirements: readonly CredentialCounterPersistenceRequirement[];
  readonly limitations: readonly CredentialCounterPersistenceLimitation[];
  readonly reasons: readonly CredentialCounterPersistenceReason[];
  readonly persistedAt: string;
  readonly auditCorrelationId: string;
  readonly registryIntegrityVerified: boolean;
  readonly writeVerified: boolean;
  readonly counterPersisted: boolean;
  readonly trustDecisionCreated: false;
  readonly capabilityGranted: false;
  readonly sessionKeyCreated: false;
  readonly authorizationCreated: false;
  readonly privateMaterialExposed: false;
  readonly registryPlaintextExposed: false;
  readonly vaultMaterialExposed: false;
  readonly credentialRecordExposed: false;
  readonly rawAssertionMaterialIncluded: false;
  readonly publicKeyBytesIncluded: false;
  readonly persisted: boolean;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export interface DeviceVaultCounterPersistenceMaterial {
  readonly materialId: string;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly providerKind?: string;
  readonly unsafeForProduction?: boolean;
}

export interface CredentialCounterPersistenceRequest {
  readonly operationId: string;
  readonly requestId: string;
  readonly identity: PhilIdentityPublic;
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly unlockMaterial: DeviceVaultCounterPersistenceMaterial;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly productionVerificationResult: TrustManagerProductionVerificationResultValue;
  readonly boundedTrustDecisionCandidate: BoundedTrustDecisionCandidate;
  readonly credentialId: string;
  readonly ownerCommitment: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly previousVerificationCounter: number;
  readonly verifiedReturnedCounter: number;
  readonly expectedStoredCounter: number;
  readonly expectedEncryptedRegistryHash?: Hex;
  readonly expectedRegistryVersion?: typeof PHIL_DEVICE_CREDENTIAL_REGISTRY_VERSION;
  readonly expectedStorageVersion?: typeof PHIL_DEVICE_IDENTITY_STORAGE_VERSION;
  readonly auditCorrelationId: string;
  readonly requestedAt?: string;
  readonly expiresAt: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type CredentialCounterPersistenceResult =
  RuntimeResult<CredentialCounterPersistenceReceipt>;

export interface CredentialCounterPersistenceConsumptionRecord {
  readonly operationId: string;
  readonly credentialId: string;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export type CredentialCounterPersistenceConsumptionStatus =
  | "consumed"
  | "replayed"
  | "cleared";

export interface CredentialCounterPersistenceConsumptionResult {
  readonly status: CredentialCounterPersistenceConsumptionStatus;
  readonly record?: CredentialCounterPersistenceConsumptionRecord;
  readonly records: readonly CredentialCounterPersistenceConsumptionRecord[];
  readonly reason?: string;
}

export interface EphemeralCredentialCounterPersistenceReplayStore {
  consume(
    operationId: string,
    credentialId: string,
    auditCorrelationId: string
  ): CredentialCounterPersistenceConsumptionResult;
  has(operationId: string): boolean;
  clear(): CredentialCounterPersistenceConsumptionResult;
  getAll(): readonly CredentialCounterPersistenceConsumptionRecord[];
}

export interface TrustDecisionCandidateCounterResolution {
  readonly resolutionId: string;
  readonly boundedTrustDecisionCandidateId: string;
  readonly credentialCounterPersistenceReceiptId: string;
  readonly counterRequirementSatisfied: boolean;
  readonly persistenceReceiptReferenceAttached: true;
  readonly activeTrustDecisionCreated: false;
  readonly capabilityGranted: false;
  readonly authorizationCreated: false;
  readonly persisted: false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasValidDateShape(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function expired(value: string | undefined): boolean {
  return value !== undefined && Date.parse(value) <= Date.now();
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

function hashSerialized(serialized: string): Hex {
  return keccak256(toUtf8Bytes(serialized)) as Hex;
}

function persistenceError(
  code: string,
  message: string,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    category: "vault_unavailable",
    code,
    message,
    boundary: "device-vault",
    recoverable: true,
    details: { errors }
  };
}

function nonNegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

export function validateCredentialCounterPersistenceRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["credential counter persistence request must be an object"]);
  if (!isNonEmptyString(request.operationId)) errors.push("operationId is required");
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.identity)) errors.push("identity is required");
  if (!isRecord(request.storageBackend)) errors.push("storageBackend is required");
  if (!isRecord(request.unlockMaterial) || !isRecord(request.unlockMaterial.keyProvider)) {
    errors.push("unlockMaterial.keyProvider is required");
  }
  if (!isRecord(request.unlockedVaultHandle)) errors.push("unlockedVaultHandle is required");
  const lifecycleValidation = validateUserSessionLifecycleSnapshotShape(request.lifecycleSnapshot);
  if (!lifecycleValidation.valid) {
    errors.push(...lifecycleValidation.errors.map((error) => `lifecycleSnapshot.${error}`));
  }
  if (!isRecord(request.productionVerificationResult)) {
    errors.push("productionVerificationResult is required");
  } else {
    const resultValidation =
      validateTrustManagerProductionVerificationResultShape(request.productionVerificationResult);
    if (!resultValidation.valid) {
      errors.push(...resultValidation.errors.map((error) => `productionVerificationResult.${error}`));
    }
  }
  if (!isRecord(request.boundedTrustDecisionCandidate)) {
    errors.push("boundedTrustDecisionCandidate is required");
  } else {
    const candidateValidation =
      validateBoundedTrustDecisionCandidateShape(request.boundedTrustDecisionCandidate);
    if (!candidateValidation.valid) {
      errors.push(...candidateValidation.errors.map((error) => `boundedTrustDecisionCandidate.${error}`));
    }
  }
  if (!isNonEmptyString(request.credentialId)) errors.push("credentialId is required");
  if (!isNonEmptyString(request.ownerCommitment)) errors.push("ownerCommitment is required");
  if (!isNonEmptyString(request.sessionId)) errors.push("sessionId is required");
  if (!isNonEmptyString(request.applicationId)) errors.push("applicationId is required");
  if (!nonNegativeNumber(request.previousVerificationCounter)) {
    errors.push("previousVerificationCounter must be a non-negative integer");
  }
  if (!nonNegativeNumber(request.verifiedReturnedCounter)) {
    errors.push("verifiedReturnedCounter must be a non-negative integer");
  }
  if (!nonNegativeNumber(request.expectedStoredCounter)) {
    errors.push("expectedStoredCounter must be a non-negative integer");
  }
  if (request.expectedEncryptedRegistryHash !== undefined
    && !isNonEmptyString(request.expectedEncryptedRegistryHash)) {
    errors.push("expectedEncryptedRegistryHash must be non-empty when provided");
  }
  if (request.expectedRegistryVersion !== undefined
    && request.expectedRegistryVersion !== PHIL_DEVICE_CREDENTIAL_REGISTRY_VERSION) {
    errors.push("expectedRegistryVersion is unsupported");
  }
  if (request.expectedStorageVersion !== undefined
    && request.expectedStorageVersion !== PHIL_DEVICE_IDENTITY_STORAGE_VERSION) {
    errors.push("expectedStorageVersion is unsupported");
  }
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (request.requestedAt !== undefined && !hasValidDateShape(request.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a parseable date string");
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  }
  return validation(errors);
}

function correlationErrors(request: CredentialCounterPersistenceRequest): readonly string[] {
  const errors: string[] = [];
  const verification = request.productionVerificationResult;
  const candidate = request.boundedTrustDecisionCandidate;
  if (request.identity.ownerCommitment !== request.ownerCommitment) errors.push("owner mismatch");
  if (request.unlockedVaultHandle.ownerCommitment !== request.ownerCommitment) errors.push("owner mismatch");
  if (request.unlockedVaultHandle.sessionId !== request.sessionId) errors.push("session mismatch");
  if (request.lifecycleSnapshot.sessionId !== request.sessionId) errors.push("session mismatch");
  if (verification.correlation.ownerCommitment !== request.ownerCommitment) errors.push("owner mismatch");
  if (verification.correlation.sessionId !== request.sessionId) errors.push("session mismatch");
  if (verification.correlation.applicationId !== request.applicationId) errors.push("application mismatch");
  if (verification.correlation.credentialId !== request.credentialId) errors.push("credential mismatch");
  if (verification.auditCorrelationId !== request.auditCorrelationId) {
    errors.push("audit correlation mismatch");
  }
  if (candidate.correlation.ownerCommitment !== request.ownerCommitment) errors.push("owner mismatch");
  if (candidate.correlation.sessionId !== request.sessionId) errors.push("session mismatch");
  if (candidate.correlation.applicationId !== request.applicationId) errors.push("application mismatch");
  if (candidate.correlation.credentialId !== request.credentialId) errors.push("credential mismatch");
  if (candidate.auditCorrelationId !== request.auditCorrelationId) {
    errors.push("audit correlation mismatch");
  }
  return Object.freeze([...new Set(errors)]);
}

function preflightOutcome(errors: readonly string[]): CredentialCounterPersistenceOutcome {
  if (errors.some((error) => error.includes("owner"))) return "owner_mismatch";
  if (errors.some((error) => error.includes("session"))) return "session_mismatch";
  if (errors.some((error) => error.includes("application"))) return "application_mismatch";
  if (errors.some((error) => error.includes("audit"))) return "audit_correlation_mismatch";
  if (errors.some((error) => error.includes("vault"))) return "vault_handle_invalid";
  if (errors.some((error) => error.includes("expired"))) return "expired";
  if (errors.some((error) => error.includes("candidate"))) return "candidate_ineligible";
  if (errors.some((error) => error.includes("verification"))) return "verification_result_ineligible";
  return "malformed";
}

function statusForOutcome(
  outcome: CredentialCounterPersistenceOutcome
): CredentialCounterPersistenceStatus {
  if (outcome === "counter_persisted" || outcome === "counter_unchanged_accepted") {
    return "persistence_succeeded";
  }
  if (outcome === "replayed") return "persistence_replayed";
  if (outcome === "malformed") return "persistence_malformed";
  if (outcome === "unsupported" || outcome === "counter_unsupported") {
    return "persistence_unsupported";
  }
  if (outcome === "write_failed" || outcome === "verification_failed") return "persistence_failed";
  return "persistence_rejected";
}

function limitations(): readonly CredentialCounterPersistenceLimitation[] {
  return Object.freeze([
    "single_counter_field_only",
    "no_compare_and_swap_available",
    "best_effort_stale_hash_guard",
    "no_trust_decision",
    "no_capability_grant",
    "no_authorization",
    "no_registry_plaintext_export",
    "no_vault_material_export"
  ]);
}

function requirements(): readonly CredentialCounterPersistenceRequirement[] {
  return Object.freeze([
    "successful_production_verification",
    "bounded_candidate",
    "unlocked_lifecycle",
    "valid_vault_handle",
    "owner_session_application_audit_correlation",
    "current_counter_match",
    "registry_integrity",
    "counter_update_verification"
  ]);
}

function counterState(input: {
  request: CredentialCounterPersistenceRequest;
  currentStoredCounter: number;
}): CredentialCounterState {
  const status = input.request.productionVerificationResult.counterAssessment.counterStatus;
  return freezeRecord({
    expectedStoredCounter: input.request.expectedStoredCounter,
    currentStoredCounter: input.currentStoredCounter,
    previousVerificationCounter: input.request.previousVerificationCounter,
    verifiedReturnedCounter: input.request.verifiedReturnedCounter,
    counterStatus: status,
    counterAdvanced: status === "advanced",
    counterUnchangedZero: status === "unchanged-zero",
    counterUnsupported: status === "unsupported",
    rollbackDetected: input.request.productionVerificationResult.counterAssessment.rollbackDetected,
    cloneSuspected: input.request.productionVerificationResult.counterAssessment.cloneSuspected
  });
}

function auditDraftForCounterPersistence(input: {
  readonly request: CredentialCounterPersistenceRequest;
  readonly outcome: CredentialCounterPersistenceOutcome;
  readonly receipt?: CredentialCounterPersistenceReceipt;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "trust",
    outcome: input.outcome === "counter_persisted" || input.outcome === "counter_unchanged_accepted"
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: "generic",
    sessionId: input.request.sessionId,
    applicationId: input.request.applicationId,
    summary: input.receipt
      ? "Credential counter persistence boundary completed; no Trust Decision or authority was created."
      : "Credential counter persistence boundary rejected the request; no authority was created.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      operationId: input.request.operationId,
      credentialId: input.request.credentialId,
      credentialSafeReference:
        input.request.productionVerificationResult?.correlation.credentialSafeReference,
      outcome: input.outcome,
      previousVerificationCounter: input.request.previousVerificationCounter,
      verifiedReturnedCounter: input.request.verifiedReturnedCounter,
      expectedStoredCounter: input.request.expectedStoredCounter,
      persistedCounter: input.receipt?.mutationSummary.persistedCounter,
      registryIntegrityVerified: input.receipt?.registryIntegrityVerified,
      counterPersisted: input.receipt?.counterPersisted ?? false,
      trustDecisionCreated: false,
      capabilityGranted: false,
      authorizationCreated: false,
      registryPlaintextExposed: false,
      vaultMaterialExposed: false,
      privateMaterialExposed: false,
      errors: input.errors ?? []
    }
  });
}

function receiptFor(input: {
  readonly request: CredentialCounterPersistenceRequest;
  readonly outcome: CredentialCounterPersistenceOutcome;
  readonly currentStoredCounter: number;
  readonly persistedCounter: number;
  readonly mutationPerformed: boolean;
  readonly auditBefore: number;
  readonly auditAfter: number;
  readonly registryHashBefore: Hex;
  readonly registryHashAfter?: Hex;
  readonly persistedAt: string;
}): CredentialCounterPersistenceReceipt {
  const state = counterState({
    request: input.request,
    currentStoredCounter: input.currentStoredCounter
  });
  return freezeRecord({
    credentialCounterPersistenceReceiptId: createAuditCorrelationId([
      input.request.operationId,
      input.request.credentialId,
      input.request.auditCorrelationId,
      "credential-counter-persistence-receipt"
    ]),
    operationId: input.request.operationId,
    status: statusForOutcome(input.outcome),
    outcome: input.outcome,
    correlation: {
      sessionId: input.request.sessionId,
      applicationId: input.request.applicationId,
      ownerCommitment: input.request.ownerCommitment,
      credentialId: input.request.credentialId,
      credentialSafeReference:
        input.request.productionVerificationResult.correlation.credentialSafeReference,
      auditCorrelationId: input.request.auditCorrelationId
    },
    counterState: state,
    mutationSummary: {
      credentialId: input.request.credentialId,
      previousStoredCounter: input.currentStoredCounter,
      persistedCounter: input.persistedCounter,
      mutationPerformed: input.mutationPerformed,
      onlyCounterFieldChanged: true,
      lifecycleStatusChanged: false,
      otherCredentialChanged: false,
      registryAuditEventCountBefore: input.auditBefore,
      registryAuditEventCountAfter: input.auditAfter,
      registryHashBefore: input.registryHashBefore,
      registryHashAfter: input.registryHashAfter,
      storageBackendKind: "encrypted-device-identity-registry-store"
    },
    requirements: requirements(),
    limitations: limitations(),
    reasons: Object.freeze([
      "production-verification-result-required",
      "bounded-trust-decision-candidate-required",
      "unlocked-vault-handle-required",
      "existing-encrypted-registry-storage-reused",
      "single-credential-target",
      input.mutationPerformed ? "counter-advanced" : "counter-unchanged-zero",
      "counter-field-only",
      "receipt-only-no-trust-decision",
      "no-authority"
    ]),
    persistedAt: input.persistedAt,
    auditCorrelationId: input.request.auditCorrelationId,
    registryIntegrityVerified: true,
    writeVerified: true,
    counterPersisted: input.mutationPerformed,
    trustDecisionCreated: false,
    capabilityGranted: false,
    sessionKeyCreated: false,
    authorizationCreated: false,
    privateMaterialExposed: false,
    registryPlaintextExposed: false,
    vaultMaterialExposed: false,
    credentialRecordExposed: false,
    rawAssertionMaterialIncluded: false,
    publicKeyBytesIncluded: false,
    persisted: input.mutationPerformed
  });
}

function credentialEligible(credential: PhilCredentialRecord): boolean {
  return credential.status === "active" || credential.status === "recovery-only";
}

function cloneCredentialWithCounter(
  credential: PhilCredentialRecord,
  signCount: number
): PhilCredentialRecord {
  return Object.freeze({
    ...credential,
    signCount,
    transport: Object.freeze({
      transports: Object.freeze([...credential.transport.transports]),
      authenticatorAttachment: credential.transport.authenticatorAttachment
    })
  });
}

function receiptValidationErrors(receipt: CredentialCounterPersistenceReceipt): readonly string[] {
  const errors: string[] = [];
  if (!isNonEmptyString(receipt.credentialCounterPersistenceReceiptId)) {
    errors.push("credentialCounterPersistenceReceiptId is required");
  }
  if (receipt.trustDecisionCreated !== false) errors.push("trustDecisionCreated must be false");
  if (receipt.capabilityGranted !== false) errors.push("capabilityGranted must be false");
  if (receipt.authorizationCreated !== false) errors.push("authorizationCreated must be false");
  if (receipt.privateMaterialExposed !== false) errors.push("privateMaterialExposed must be false");
  if (receipt.registryPlaintextExposed !== false) errors.push("registryPlaintextExposed must be false");
  if (receipt.vaultMaterialExposed !== false) errors.push("vaultMaterialExposed must be false");
  if (receipt.credentialRecordExposed !== false) errors.push("credentialRecordExposed must be false");
  return Object.freeze(errors);
}

export function validateCredentialCounterPersistenceReceipt(
  receipt: unknown
): RuntimeValidationResult {
  if (!isRecord(receipt)) return validation(["receipt must be an object"]);
  return validation([
    ...receiptValidationErrors(receipt as unknown as CredentialCounterPersistenceReceipt)
  ]);
}

function deniedResult(
  request: CredentialCounterPersistenceRequest,
  outcome: CredentialCounterPersistenceOutcome,
  errors: readonly string[],
  auditDraftCollector?: AuditDraftCollector
): CredentialCounterPersistenceResult {
  const auditEventDraft = auditDraftForCounterPersistence({ request, outcome, errors });
  auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeDenied(persistenceError(
    "CREDENTIAL_COUNTER_PERSISTENCE_REJECTED",
    "credential counter persistence request was rejected",
    errors
  ), { auditEventId: auditEventDraft.eventDraftId });
}

export async function persistVerifiedCredentialCounter(
  request: CredentialCounterPersistenceRequest,
  replayStore?: EphemeralCredentialCounterPersistenceReplayStore,
  auditDraftCollector?: AuditDraftCollector
): Promise<CredentialCounterPersistenceResult> {
  const validationResult = validateCredentialCounterPersistenceRequest(request);
  if (!validationResult.valid) {
    return deniedResult(request, "malformed", validationResult.errors, auditDraftCollector);
  }
  if (replayStore?.has(request.operationId)) {
    return deniedResult(request, "replayed", ["operation was already consumed"], auditDraftCollector);
  }
  const preflightErrors = [
    ...correlationErrors(request),
    ...(expired(request.expiresAt) || expired(request.productionVerificationResult.expiresAt)
      ? ["expired"]
      : []),
    ...(request.unlockedVaultHandle.processLocal !== true
      || request.unlockedVaultHandle.containsPlaintext !== false
      || request.unlockedVaultHandle.containsRawVaultKey !== false
      || request.unlockedVaultHandle.containsPhilSecret !== false
      || expired(request.unlockedVaultHandle.expiresAt)
      ? ["vault handle invalid"]
      : []),
    ...(request.lifecycleSnapshot.state !== "unlocked" ? ["session lifecycle not unlocked"] : []),
    ...(request.productionVerificationResult.status !== "verification_succeeded"
      || request.productionVerificationResult.outcome !== "assertion_verified"
      ? ["verification result ineligible"]
      : []),
    ...(request.boundedTrustDecisionCandidate.status !== "candidate_created"
      || request.boundedTrustDecisionCandidate.productionAssertionVerified !== true
      ? ["candidate ineligible"]
      : [])
  ];
  if (preflightErrors.length > 0) {
    return deniedResult(request, preflightOutcome(preflightErrors), preflightErrors, auditDraftCollector);
  }

  const consumed = replayStore?.consume(
    request.operationId,
    request.credentialId,
    request.auditCorrelationId
  );
  if (consumed?.status === "replayed") {
    return deniedResult(request, "replayed", ["operation was already consumed"], auditDraftCollector);
  }

  const counter = request.productionVerificationResult.counterAssessment;
  if (counter.rollbackDetected || counter.counterStatus === "rollback") {
    return deniedResult(request, "counter_rollback_detected", ["counter rollback detected"], auditDraftCollector);
  }
  if (counter.cloneSuspected || counter.counterStatus === "clone-suspected") {
    return deniedResult(request, "counter_clone_risk_detected", ["counter clone risk detected"], auditDraftCollector);
  }
  if (request.previousVerificationCounter !== request.expectedStoredCounter) {
    return deniedResult(request, "stored_counter_mismatch", [
      "previous verification counter must match expected stored counter"
    ], auditDraftCollector);
  }

  const serializedBefore = await request.storageBackend.read();
  if (serializedBefore === null) {
    return deniedResult(request, "registry_integrity_failed", ["encrypted registry missing"], auditDraftCollector);
  }
  const registryHashBefore = hashSerialized(serializedBefore);
  if (
    request.expectedEncryptedRegistryHash !== undefined
    && request.expectedEncryptedRegistryHash !== registryHashBefore
  ) {
    return deniedResult(request, "stored_counter_mismatch", [
      "encrypted registry hash changed before counter persistence"
    ], auditDraftCollector);
  }

  const store = createEncryptedDeviceIdentityRegistryStore({
    backend: request.storageBackend,
    keyProvider: request.unlockMaterial.keyProvider
  });
  let snapshot;
  try {
    snapshot = await store.loadRegistry(request.identity);
  } catch {
    return deniedResult(request, "registry_integrity_failed", [
      "encrypted registry integrity validation failed"
    ], auditDraftCollector);
  }
  const credential = snapshot.credentials.find((entry) => entry.credentialId === request.credentialId);
  if (!credential) {
    return deniedResult(request, "credential_not_found", ["selected credential not found"], auditDraftCollector);
  }
  if (!credentialEligible(credential)) {
    return deniedResult(request, "credential_ineligible", [
      `credential status ${credential.status} is not eligible for counter persistence`
    ], auditDraftCollector);
  }
  const currentStoredCounter = credential.signCount ?? 0;
  if (currentStoredCounter !== request.expectedStoredCounter) {
    return deniedResult(request, "stored_counter_mismatch", [
      "current stored counter does not match expected stored counter"
    ], auditDraftCollector);
  }
  if (request.verifiedReturnedCounter < currentStoredCounter) {
    return deniedResult(request, "counter_rollback_detected", [
      "verified returned counter is lower than current stored counter"
    ], auditDraftCollector);
  }

  const unchangedZero = counter.counterStatus === "unchanged-zero"
    && currentStoredCounter === 0
    && request.verifiedReturnedCounter === 0;
  const unsupported = counter.counterStatus === "unsupported";
  if (unsupported) {
    return deniedResult(request, "counter_unsupported", [
      "unsupported counter behavior is represented explicitly and not persisted in K.8"
    ], auditDraftCollector);
  }
  if (request.verifiedReturnedCounter === currentStoredCounter && !unchangedZero) {
    return deniedResult(request, "stored_counter_mismatch", [
      "verified returned counter did not advance and is not an accepted zero-counter case"
    ], auditDraftCollector);
  }

  const auditBefore = snapshot.auditTrail.length;
  const persistedCounter = unchangedZero ? currentStoredCounter : request.verifiedReturnedCounter;
  if (!unchangedZero) {
    const updatedCredentials = snapshot.credentials.map((entry) =>
      entry.credentialId === request.credentialId
        ? cloneCredentialWithCounter(entry, persistedCounter)
        : entry
    );
    const beforeOtherCredentials = JSON.stringify(
      snapshot.credentials.filter((entry) => entry.credentialId !== request.credentialId)
    );
    const afterOtherCredentials = JSON.stringify(
      updatedCredentials.filter((entry) => entry.credentialId !== request.credentialId)
    );
    if (beforeOtherCredentials !== afterOtherCredentials) {
      return deniedResult(request, "verification_failed", [
        "non-target credential mutation detected before write"
      ], auditDraftCollector);
    }
    try {
      await store.saveRegistry({
        ...snapshot,
        credentials: Object.freeze(updatedCredentials)
      });
    } catch {
      return deniedResult(request, "write_failed", ["encrypted registry write failed"], auditDraftCollector);
    }
  }

  const serializedAfter = await request.storageBackend.read();
  if (serializedAfter === null) {
    return deniedResult(request, "verification_failed", ["encrypted registry missing after write"], auditDraftCollector);
  }
  let verifiedSnapshot;
  try {
    verifiedSnapshot = await store.loadRegistry(request.identity);
  } catch {
    return deniedResult(request, "verification_failed", ["written registry failed integrity validation"], auditDraftCollector);
  }
  const verifiedCredential = verifiedSnapshot.credentials.find((entry) =>
    entry.credentialId === request.credentialId
  );
  if (!verifiedCredential || (verifiedCredential.signCount ?? 0) !== persistedCounter) {
    return deniedResult(request, "verification_failed", [
      "persisted credential counter could not be verified after reload"
    ], auditDraftCollector);
  }
  const receipt = receiptFor({
    request,
    outcome: unchangedZero ? "counter_unchanged_accepted" : "counter_persisted",
    currentStoredCounter,
    persistedCounter,
    mutationPerformed: !unchangedZero,
    auditBefore,
    auditAfter: verifiedSnapshot.auditTrail.length,
    registryHashBefore,
    registryHashAfter: hashSerialized(serializedAfter),
    persistedAt: new Date().toISOString()
  });
  const receiptValidation = validateCredentialCounterPersistenceReceipt(receipt);
  if (!receiptValidation.valid) {
    return deniedResult(request, "verification_failed", receiptValidation.errors, auditDraftCollector);
  }
  const auditEventDraft = auditDraftForCounterPersistence({
    request,
    outcome: receipt.outcome,
    receipt
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    ...receipt,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export async function verifyPersistedCredentialCounter(
  request: CredentialCounterPersistenceRequest,
  receipt: CredentialCounterPersistenceReceipt
): Promise<RuntimeValidationResult> {
  const errors: string[] = [];
  const store = createEncryptedDeviceIdentityRegistryStore({
    backend: request.storageBackend,
    keyProvider: request.unlockMaterial.keyProvider
  });
  try {
    const snapshot = await store.loadRegistry(request.identity);
    const credential = snapshot.credentials.find((entry) =>
      entry.credentialId === request.credentialId
    );
    if (!credential) errors.push("credential not found");
    if ((credential?.signCount ?? 0) !== receipt.mutationSummary.persistedCounter) {
      errors.push("persisted counter does not match receipt");
    }
  } catch {
    errors.push("registry integrity validation failed");
  }
  return validation(errors);
}

export function resolveCounterPersistenceRequirement(input: {
  readonly boundedTrustDecisionCandidate: BoundedTrustDecisionCandidate;
  readonly receipt: CredentialCounterPersistenceReceipt;
}): TrustDecisionCandidateCounterResolution {
  return freezeRecord({
    resolutionId: createAuditCorrelationId([
      input.boundedTrustDecisionCandidate.boundedTrustDecisionCandidateId,
      input.receipt.credentialCounterPersistenceReceiptId,
      "counter-resolution"
    ]),
    boundedTrustDecisionCandidateId:
      input.boundedTrustDecisionCandidate.boundedTrustDecisionCandidateId,
    credentialCounterPersistenceReceiptId:
      input.receipt.credentialCounterPersistenceReceiptId,
    counterRequirementSatisfied:
      input.receipt.outcome === "counter_persisted"
      || input.receipt.outcome === "counter_unchanged_accepted",
    persistenceReceiptReferenceAttached: true,
    activeTrustDecisionCreated: false,
    capabilityGranted: false,
    authorizationCreated: false,
    persisted: false
  });
}

export function createEphemeralCredentialCounterPersistenceReplayStore():
  EphemeralCredentialCounterPersistenceReplayStore {
  const records = new Map<string, CredentialCounterPersistenceConsumptionRecord>();
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(operationId, credentialId, auditCorrelationId) {
      if (records.has(operationId)) {
        return freezeRecord({
          status: "replayed" as const,
          record: records.get(operationId),
          records: all(),
          reason: "credential counter persistence operation was already consumed"
        });
      }
      const record = freezeRecord({
        operationId,
        credentialId,
        auditCorrelationId,
        consumedAt: new Date().toISOString()
      });
      records.set(operationId, record);
      return freezeRecord({ status: "consumed" as const, record, records: all() });
    },
    has(operationId) {
      return records.has(operationId);
    },
    clear() {
      records.clear();
      return freezeRecord({ status: "cleared" as const, records: all() });
    },
    getAll: all
  };
}
