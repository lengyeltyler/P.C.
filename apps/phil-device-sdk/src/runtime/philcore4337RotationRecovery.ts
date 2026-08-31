import { Interface, getAddress, isHexString, keccak256, toUtf8Bytes } from "ethers";

import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type { DeviceVaultEcdsaValidatorKeyReference } from "./deviceVaultEcdsaCustody.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import type { Hex } from "../hashes.ts";
import type { RuntimeResult } from "./types.ts";

export type PhilCore4337OwnerRotationStatus =
  | "rotation_candidate_created"
  | "rotation_rejected";

export type PhilCore4337OwnerRotationReason =
  | "current-owner-rotation"
  | "device-vault-pending-rotation"
  | "owner-commitment-continuity"
  | "no-public-submission"
  | "invalid-account"
  | "invalid-owner"
  | "binding-mismatch";

export type PhilCore4337RecoveryState =
  | "none"
  | "recovery_requested"
  | "recovery_challenge_period"
  | "recovery_ready"
  | "recovery_cancelled"
  | "recovery_completed"
  | "recovery_expired";

export type PhilCore4337RecoveryAction =
  | "request_recovery"
  | "cancel_recovery"
  | "complete_recovery";

export type PhilCore4337RecoveryAuthorityRotationAction =
  | "request_recovery_authority_rotation"
  | "cancel_recovery_authority_rotation"
  | "complete_recovery_authority_rotation";

export type PhilCore4337RecoveryAuthorityRotationState =
  | "recovery_authority_rotation_none"
  | "recovery_authority_rotation_requested"
  | "recovery_authority_rotation_challenge"
  | "recovery_authority_rotation_ready"
  | "recovery_authority_rotation_cancelled"
  | "recovery_authority_rotation_completed"
  | "recovery_authority_rotation_expired";

export interface PhilCore4337OwnerRotationRequest {
  readonly requestId: string;
  readonly accountAddress: string;
  readonly currentOwner: string;
  readonly newOwner: string;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly currentValidatorKeyReference?: DeviceVaultEcdsaValidatorKeyReference;
  readonly newValidatorKeyReference?: DeviceVaultEcdsaValidatorKeyReference;
  readonly issuedAt?: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId?: string;
}

export interface PhilCore4337OwnerRotationCandidate {
  readonly rotationCandidateId: string;
  readonly status: "rotation_candidate_created";
  readonly accountAddress: string;
  readonly currentOwner: string;
  readonly newOwner: string;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly maintenanceSelector: string;
  readonly maintenanceCallData: Hex;
  readonly maintenanceCallDataHash: Hex;
  readonly issuedAt: string;
  readonly expiresAt?: string;
  readonly reasons: readonly PhilCore4337OwnerRotationReason[];
  readonly limitations: readonly PhilCore4337RecoveryLimitation[];
  readonly privateKeyExposed: false;
  readonly publicUserOperationSubmitted: false;
  readonly ownerCommitmentChanged: false;
  readonly actionGateChanged: false;
  readonly entryPointChanged: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type PhilCore4337OwnerRotationResult =
  RuntimeResult<PhilCore4337OwnerRotationCandidate>;

export interface PhilCore4337RecoveryRequest {
  readonly requestId: string;
  readonly action: PhilCore4337RecoveryAction;
  readonly accountAddress: string;
  readonly recoveryAuthority: string;
  readonly currentOwner: string;
  readonly pendingOwner?: string;
  readonly recoveryRequestId?: Hex;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly issuedAt?: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId?: string;
}

export interface PhilCore4337RecoveryCandidate {
  readonly recoveryCandidateId: string;
  readonly action: PhilCore4337RecoveryAction;
  readonly state: PhilCore4337RecoveryState;
  readonly accountAddress: string;
  readonly recoveryAuthority: string;
  readonly currentOwner: string;
  readonly pendingOwner?: string;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly maintenanceSelector: string;
  readonly maintenanceCallData: Hex;
  readonly maintenanceCallDataHash: Hex;
  readonly issuedAt: string;
  readonly expiresAt?: string;
  readonly limitations: readonly PhilCore4337RecoveryLimitation[];
  readonly recoveryAuthorityCanExecuteOrdinaryActions: false;
  readonly recoveryAuthorityCanTransferAssets: false;
  readonly ownerCommitmentChanged: false;
  readonly actionGateChanged: false;
  readonly entryPointChanged: false;
  readonly publicUserOperationSubmitted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type PhilCore4337RecoveryResult =
  RuntimeResult<PhilCore4337RecoveryCandidate>;

export interface PhilCore4337RecoveryAuthorityRotationRequest {
  readonly requestId: string;
  readonly action: PhilCore4337RecoveryAuthorityRotationAction;
  readonly accountAddress: string;
  readonly currentOwner: string;
  readonly currentRecoveryAuthority: string;
  readonly pendingRecoveryAuthority?: string;
  readonly proposer?: string;
  readonly canceller?: string;
  readonly recoveryAuthorityRotationRequestId?: Hex;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly pendingRecoveryKeyReference?: DeviceVaultEcdsaValidatorKeyReference;
  readonly currentRecoveryKeyReference?: DeviceVaultEcdsaValidatorKeyReference;
  readonly issuedAt?: string;
  readonly expiresAt?: string;
  readonly auditCorrelationId?: string;
}

export interface PhilCore4337RecoveryAuthorityRotationCandidate {
  readonly recoveryAuthorityRotationCandidateId: string;
  readonly action: PhilCore4337RecoveryAuthorityRotationAction;
  readonly state: PhilCore4337RecoveryAuthorityRotationState;
  readonly accountAddress: string;
  readonly currentOwner: string;
  readonly currentRecoveryAuthority: string;
  readonly pendingRecoveryAuthority?: string;
  readonly proposer?: string;
  readonly canceller?: string;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly maintenanceSelector: string;
  readonly maintenanceCallData: Hex;
  readonly maintenanceCallDataHash: Hex;
  readonly issuedAt: string;
  readonly expiresAt?: string;
  readonly limitations: readonly PhilCore4337RecoveryLimitation[];
  readonly exactlyOneActiveRecoveryAuthority: true;
  readonly pendingAuthorityActiveBeforeCompletion: false;
  readonly executionOwnerChanged: false;
  readonly ownerCommitmentChanged: false;
  readonly actionGateChanged: false;
  readonly entryPointChanged: false;
  readonly accountAddressChanged: false;
  readonly arbitraryExternalCallAllowed: false;
  readonly valueTransferAllowed: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly newLocalRecoveryKeyActivated: false;
  readonly oldLocalRecoveryKeyRevoked: false;
  readonly publicUserOperationSubmitted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export type PhilCore4337RecoveryAuthorityRotationResult =
  RuntimeResult<PhilCore4337RecoveryAuthorityRotationCandidate>;

export interface PhilCore4337RecoveryLimitation {
  readonly limitationId: string;
  readonly description: string;
}

const maintenanceInterface = new Interface([
  "function rotateExecutionOwner(address newOwner)",
  "function requestRecovery(address pendingOwner)",
  "function cancelRecovery(bytes32 requestId)",
  "function completeRecovery(bytes32 requestId,address expectedPendingOwner)",
  "function requestRecoveryAuthorityRotation(address pendingRecoveryAuthority,address expectedProposer)",
  "function cancelRecoveryAuthorityRotation(bytes32 requestId,address expectedCanceller)",
  "function completeRecoveryAuthorityRotation(bytes32 requestId,address expectedPendingRecoveryAuthority)"
]);

function selectorFor(name: string): string {
  const fragment = maintenanceInterface.getFunction(name);
  if (!fragment) throw new Error(`missing maintenance ABI fragment ${name}`);
  return fragment.selector;
}

const DEFAULT_LIMITATIONS: readonly PhilCore4337RecoveryLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "no-public-submission",
    description: "The runtime boundary prepares exact maintenance calldata only; it does not sign or submit a UserOperation."
  }),
  Object.freeze({
    limitationId: "no-secret-access",
    description: "No validator private key, recovery secret, phil_secret, or vault key is accessed or exposed."
  }),
  Object.freeze({
    limitationId: "no-ordinary-recovery-execution",
    description: "Recovery authority is modeled only for explicit recovery selectors and cannot execute ordinary ActionGate calls."
  })
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as TValue;
  if (isRecord(value)) {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, freezeRecord(entry)])
    )) as TValue;
  }
  return value;
}

function nowIso(): string {
  return new Date().toISOString();
}

function validAddress(value: string): boolean {
  try {
    getAddress(value);
    return true;
  } catch {
    return false;
  }
}

function validateCommon(input: {
  readonly accountAddress?: string;
  readonly currentOwner?: string;
  readonly ownerCommitment?: string;
  readonly chainId?: number;
}): string[] {
  const errors: string[] = [];
  if (!input.accountAddress || !validAddress(input.accountAddress)) errors.push("account address is invalid");
  if (!input.currentOwner || !validAddress(input.currentOwner)) errors.push("current owner is invalid");
  if (!input.ownerCommitment || !isHexString(input.ownerCommitment, 32)) errors.push("ownerCommitment must be bytes32");
  if (!Number.isInteger(input.chainId) || Number(input.chainId) <= 0) errors.push("chainId must be a positive integer");
  return errors;
}

function error(code: string, errors: readonly string[]) {
  return {
    code,
    category: "invalid_authorization_package" as const,
    message: "PhilCore ERC-4337 rotation/recovery request was rejected.",
    recoverable: true,
    details: { errors }
  };
}

function audit(input: {
  readonly outcome: string;
  readonly summary: string;
  readonly auditCorrelationId?: string;
  readonly details?: Readonly<Record<string, unknown>>;
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.outcome.includes("created") ? "validation_succeeded" : "validation_failed",
    requestKind: "requestPhilCore4337RotationRecovery",
    summary: input.summary,
    auditCorrelationId: input.auditCorrelationId,
    redactedDetails: {
      ...(input.details ?? {}),
      privateKeyExposed: false,
      recoverySecretExposed: false,
      publicUserOperationSubmitted: false
    }
  });
}

export function validatePhilCore4337OwnerRotationRequest(
  request: unknown
): RuntimeValidationResult {
  if (!isRecord(request)) return { valid: false, errors: ["request must be an object"] };
  const errors = validateCommon(request);
  if (typeof request.requestId !== "string" || request.requestId.length === 0) errors.push("requestId is required");
  if (typeof request.newOwner !== "string" || !validAddress(request.newOwner)) errors.push("new owner is invalid");
  if (
    typeof request.currentOwner === "string"
    && typeof request.newOwner === "string"
    && validAddress(request.currentOwner)
    && validAddress(request.newOwner)
    && getAddress(request.currentOwner) === getAddress(request.newOwner)
  ) {
    errors.push("new owner must differ from current owner");
  }
  return { valid: errors.length === 0, errors };
}

export function createPhilCore4337OwnerRotationCandidate(
  request: PhilCore4337OwnerRotationRequest,
  auditDraftCollector?: AuditDraftCollector
): PhilCore4337OwnerRotationResult {
  const validation = validatePhilCore4337OwnerRotationRequest(request);
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.accountAddress,
    "philcore-4337-owner-rotation"
  ]);
  if (!validation.valid) {
    const auditEventDraft = audit({
      outcome: "rotation_rejected",
      summary: "PhilCore ERC-4337 owner rotation candidate was rejected.",
      auditCorrelationId,
      details: { errors: validation.errors }
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(error("PHILCORE_4337_OWNER_ROTATION_INVALID", validation.errors), {
      auditEventId: auditEventDraft.eventDraftId
    });
  }
  const issuedAt = request.issuedAt ?? nowIso();
  const maintenanceCallData = maintenanceInterface.encodeFunctionData("rotateExecutionOwner", [
    request.newOwner
  ]) as Hex;
  const auditEventDraft = audit({
    outcome: "rotation_candidate_created",
    summary: "PhilCore ERC-4337 owner rotation maintenance calldata was prepared.",
    auditCorrelationId,
    details: {
      accountAddress: request.accountAddress,
      currentOwner: request.currentOwner,
      newOwner: request.newOwner,
      ownerCommitment: request.ownerCommitment,
      chainId: request.chainId,
      maintenanceCallDataHash: keccak256(maintenanceCallData)
    }
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    rotationCandidateId: createAuditCorrelationId([
      request.requestId,
      request.accountAddress,
      request.newOwner,
      "philcore-4337-owner-rotation-candidate"
    ]),
    status: "rotation_candidate_created",
    accountAddress: getAddress(request.accountAddress),
    currentOwner: getAddress(request.currentOwner),
    newOwner: getAddress(request.newOwner),
    ownerCommitment: request.ownerCommitment,
    chainId: request.chainId,
    maintenanceSelector: selectorFor("rotateExecutionOwner"),
    maintenanceCallData,
    maintenanceCallDataHash: keccak256(maintenanceCallData) as Hex,
    issuedAt,
    expiresAt: request.expiresAt,
    reasons: Object.freeze([
      "current-owner-rotation",
      "device-vault-pending-rotation",
      "owner-commitment-continuity",
      "no-public-submission"
    ]),
    limitations: DEFAULT_LIMITATIONS,
    privateKeyExposed: false,
    publicUserOperationSubmitted: false,
    ownerCommitmentChanged: false,
    actionGateChanged: false,
    entryPointChanged: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export function validatePhilCore4337RecoveryRequest(
  request: unknown
): RuntimeValidationResult {
  if (!isRecord(request)) return { valid: false, errors: ["request must be an object"] };
  const errors = validateCommon(request);
  if (typeof request.requestId !== "string" || request.requestId.length === 0) errors.push("requestId is required");
  if (typeof request.recoveryAuthority !== "string" || !validAddress(request.recoveryAuthority)) errors.push("recovery authority is invalid");
  if (request.action === "request_recovery" || request.action === "complete_recovery") {
    if (typeof request.pendingOwner !== "string" || !validAddress(request.pendingOwner)) errors.push("pending owner is invalid");
  }
  if (request.action === "cancel_recovery" || request.action === "complete_recovery") {
    if (typeof request.recoveryRequestId !== "string" || !isHexString(request.recoveryRequestId, 32)) {
      errors.push("recoveryRequestId must be bytes32");
    }
  }
  if (!["request_recovery", "cancel_recovery", "complete_recovery"].includes(String(request.action))) {
    errors.push("unsupported recovery action");
  }
  return { valid: errors.length === 0, errors };
}

export function createPhilCore4337RecoveryCandidate(
  request: PhilCore4337RecoveryRequest,
  auditDraftCollector?: AuditDraftCollector
): PhilCore4337RecoveryResult {
  const validation = validatePhilCore4337RecoveryRequest(request);
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.accountAddress,
    String(request.action),
    "philcore-4337-recovery"
  ]);
  if (!validation.valid) {
    const auditEventDraft = audit({
      outcome: "recovery_rejected",
      summary: "PhilCore ERC-4337 recovery candidate was rejected.",
      auditCorrelationId,
      details: { errors: validation.errors }
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(error("PHILCORE_4337_RECOVERY_INVALID", validation.errors), {
      auditEventId: auditEventDraft.eventDraftId
    });
  }
  const issuedAt = request.issuedAt ?? nowIso();
  let maintenanceCallData: Hex;
  let selector: string;
  let state: PhilCore4337RecoveryState;
  if (request.action === "request_recovery") {
    maintenanceCallData = maintenanceInterface.encodeFunctionData("requestRecovery", [
      request.pendingOwner
    ]) as Hex;
    selector = selectorFor("requestRecovery");
    state = "recovery_requested";
  } else if (request.action === "cancel_recovery") {
    maintenanceCallData = maintenanceInterface.encodeFunctionData("cancelRecovery", [
      request.recoveryRequestId
    ]) as Hex;
    selector = selectorFor("cancelRecovery");
    state = "recovery_cancelled";
  } else {
    maintenanceCallData = maintenanceInterface.encodeFunctionData("completeRecovery", [
      request.recoveryRequestId,
      request.pendingOwner
    ]) as Hex;
    selector = selectorFor("completeRecovery");
    state = "recovery_completed";
  }
  const auditEventDraft = audit({
    outcome: "recovery_candidate_created",
    summary: "PhilCore ERC-4337 recovery maintenance calldata was prepared.",
    auditCorrelationId,
    details: {
      accountAddress: request.accountAddress,
      recoveryAuthority: request.recoveryAuthority,
      currentOwner: request.currentOwner,
      pendingOwner: request.pendingOwner,
      ownerCommitment: request.ownerCommitment,
      chainId: request.chainId,
      action: request.action,
      maintenanceCallDataHash: keccak256(maintenanceCallData)
    }
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    recoveryCandidateId: createAuditCorrelationId([
      request.requestId,
      request.accountAddress,
      request.action,
      "philcore-4337-recovery-candidate"
    ]),
    action: request.action,
    state,
    accountAddress: getAddress(request.accountAddress),
    recoveryAuthority: getAddress(request.recoveryAuthority),
    currentOwner: getAddress(request.currentOwner),
    pendingOwner: request.pendingOwner ? getAddress(request.pendingOwner) : undefined,
    ownerCommitment: request.ownerCommitment,
    chainId: request.chainId,
    maintenanceSelector: selector,
    maintenanceCallData,
    maintenanceCallDataHash: keccak256(maintenanceCallData) as Hex,
    issuedAt,
    expiresAt: request.expiresAt,
    limitations: DEFAULT_LIMITATIONS,
    recoveryAuthorityCanExecuteOrdinaryActions: false,
    recoveryAuthorityCanTransferAssets: false,
    ownerCommitmentChanged: false,
    actionGateChanged: false,
    entryPointChanged: false,
    publicUserOperationSubmitted: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}

export function validatePhilCore4337RecoveryAuthorityRotationRequest(
  request: unknown
): RuntimeValidationResult {
  if (!isRecord(request)) return { valid: false, errors: ["request must be an object"] };
  const errors = validateCommon(request);
  if (typeof request.requestId !== "string" || request.requestId.length === 0) errors.push("requestId is required");
  if (typeof request.currentRecoveryAuthority !== "string" || !validAddress(request.currentRecoveryAuthority)) {
    errors.push("current recovery authority is invalid");
  }
  if (![
    "request_recovery_authority_rotation",
    "cancel_recovery_authority_rotation",
    "complete_recovery_authority_rotation"
  ].includes(String(request.action))) {
    errors.push("unsupported recovery authority rotation action");
  }
  if (
    request.action === "request_recovery_authority_rotation"
      || request.action === "complete_recovery_authority_rotation"
  ) {
    if (typeof request.pendingRecoveryAuthority !== "string" || !validAddress(request.pendingRecoveryAuthority)) {
      errors.push("pending recovery authority is invalid");
    }
  }
  if (request.action === "request_recovery_authority_rotation") {
    if (typeof request.proposer !== "string" || !validAddress(request.proposer)) errors.push("proposer is invalid");
  }
  if (request.action === "cancel_recovery_authority_rotation") {
    if (typeof request.canceller !== "string" || !validAddress(request.canceller)) errors.push("canceller is invalid");
  }
  if (
    request.action === "cancel_recovery_authority_rotation"
      || request.action === "complete_recovery_authority_rotation"
  ) {
    if (
      typeof request.recoveryAuthorityRotationRequestId !== "string"
        || !isHexString(request.recoveryAuthorityRotationRequestId, 32)
    ) {
      errors.push("recoveryAuthorityRotationRequestId must be bytes32");
    }
  }
  if (
    typeof request.pendingRecoveryAuthority === "string"
      && validAddress(request.pendingRecoveryAuthority)
      && typeof request.currentRecoveryAuthority === "string"
      && validAddress(request.currentRecoveryAuthority)
      && getAddress(request.pendingRecoveryAuthority) === getAddress(request.currentRecoveryAuthority)
  ) {
    errors.push("pending recovery authority must differ from current recovery authority");
  }
  if (
    typeof request.pendingRecoveryAuthority === "string"
      && validAddress(request.pendingRecoveryAuthority)
      && typeof request.currentOwner === "string"
      && validAddress(request.currentOwner)
      && getAddress(request.pendingRecoveryAuthority) === getAddress(request.currentOwner)
  ) {
    errors.push("pending recovery authority must differ from current owner");
  }
  return { valid: errors.length === 0, errors };
}

export function createPhilCore4337RecoveryAuthorityRotationCandidate(
  request: PhilCore4337RecoveryAuthorityRotationRequest,
  auditDraftCollector?: AuditDraftCollector
): PhilCore4337RecoveryAuthorityRotationResult {
  const validation = validatePhilCore4337RecoveryAuthorityRotationRequest(request);
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.accountAddress,
    String(request.action),
    "philcore-4337-recovery-authority-rotation"
  ]);
  if (!validation.valid) {
    const auditEventDraft = audit({
      outcome: "recovery_authority_rotation_rejected",
      summary: "PhilCore ERC-4337 recovery authority rotation candidate was rejected.",
      auditCorrelationId,
      details: { errors: validation.errors }
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(error("PHILCORE_4337_RECOVERY_AUTHORITY_ROTATION_INVALID", validation.errors), {
      auditEventId: auditEventDraft.eventDraftId
    });
  }
  const issuedAt = request.issuedAt ?? nowIso();
  let maintenanceCallData: Hex;
  let selector: string;
  let state: PhilCore4337RecoveryAuthorityRotationState;
  if (request.action === "request_recovery_authority_rotation") {
    maintenanceCallData = maintenanceInterface.encodeFunctionData("requestRecoveryAuthorityRotation", [
      request.pendingRecoveryAuthority,
      request.proposer
    ]) as Hex;
    selector = selectorFor("requestRecoveryAuthorityRotation");
    state = "recovery_authority_rotation_requested";
  } else if (request.action === "cancel_recovery_authority_rotation") {
    maintenanceCallData = maintenanceInterface.encodeFunctionData("cancelRecoveryAuthorityRotation", [
      request.recoveryAuthorityRotationRequestId,
      request.canceller
    ]) as Hex;
    selector = selectorFor("cancelRecoveryAuthorityRotation");
    state = "recovery_authority_rotation_cancelled";
  } else {
    maintenanceCallData = maintenanceInterface.encodeFunctionData("completeRecoveryAuthorityRotation", [
      request.recoveryAuthorityRotationRequestId,
      request.pendingRecoveryAuthority
    ]) as Hex;
    selector = selectorFor("completeRecoveryAuthorityRotation");
    state = "recovery_authority_rotation_completed";
  }
  const auditEventDraft = audit({
    outcome: "recovery_authority_rotation_candidate_created",
    summary: "PhilCore ERC-4337 recovery authority rotation maintenance calldata was prepared.",
    auditCorrelationId,
    details: {
      accountAddress: request.accountAddress,
      currentOwner: request.currentOwner,
      currentRecoveryAuthority: request.currentRecoveryAuthority,
      pendingRecoveryAuthority: request.pendingRecoveryAuthority,
      proposer: request.proposer,
      canceller: request.canceller,
      ownerCommitment: request.ownerCommitment,
      chainId: request.chainId,
      action: request.action,
      maintenanceCallDataHash: keccak256(maintenanceCallData),
      newLocalRecoveryKeyActivated: false,
      oldLocalRecoveryKeyRevoked: false
    }
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    recoveryAuthorityRotationCandidateId: createAuditCorrelationId([
      request.requestId,
      request.accountAddress,
      request.action,
      "philcore-4337-recovery-authority-rotation-candidate"
    ]),
    action: request.action,
    state,
    accountAddress: getAddress(request.accountAddress),
    currentOwner: getAddress(request.currentOwner),
    currentRecoveryAuthority: getAddress(request.currentRecoveryAuthority),
    pendingRecoveryAuthority: request.pendingRecoveryAuthority ? getAddress(request.pendingRecoveryAuthority) : undefined,
    proposer: request.proposer ? getAddress(request.proposer) : undefined,
    canceller: request.canceller ? getAddress(request.canceller) : undefined,
    ownerCommitment: request.ownerCommitment,
    chainId: request.chainId,
    maintenanceSelector: selector,
    maintenanceCallData,
    maintenanceCallDataHash: keccak256(maintenanceCallData) as Hex,
    issuedAt,
    expiresAt: request.expiresAt,
    limitations: DEFAULT_LIMITATIONS,
    exactlyOneActiveRecoveryAuthority: true,
    pendingAuthorityActiveBeforeCompletion: false,
    executionOwnerChanged: false,
    ownerCommitmentChanged: false,
    actionGateChanged: false,
    entryPointChanged: false,
    accountAddressChanged: false,
    arbitraryExternalCallAllowed: false,
    valueTransferAllowed: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    newLocalRecoveryKeyActivated: false,
    oldLocalRecoveryKeyRevoked: false,
    publicUserOperationSubmitted: false,
    auditEventDraft,
    auditDraftCollectionResult
  }));
}
