import {
  Interface,
  getAddress,
  hexlify,
  isHexString,
  keccak256,
  toUtf8Bytes
} from "ethers";

import type { Hex } from "../hashes.ts";
import type {
  PhilDeviceIdentityRegistryKeyProvider,
  PhilDeviceIdentityRegistryStorageBackend
} from "../deviceIdentityStorage.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import type { UnlockedDeviceVaultHandleMetadata } from "./deviceVaultUnlock.ts";
import {
  bindDeviceVaultEcdsaValidatorAccountReference,
  createDeviceVaultEcdsaSigningSession,
  createDeviceVaultEcdsaValidatorSigner,
  generateDeviceVaultEcdsaValidator,
  type DeviceVaultEcdsaKeyGenerationResultValue,
  type DeviceVaultEcdsaSigningSession,
  type DeviceVaultEcdsaValidatorKeyReference,
  type DeviceVaultEcdsaValidatorPurpose,
  type DeviceVaultEcdsaValidatorRecord
} from "./deviceVaultEcdsaCustody.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk
} from "./helpers.ts";
import {
  PHILCORE_4337_EMPTY_BYTES,
  computePhilCore4337UserOperationHash,
  packPhilCore4337AccountGasLimits,
  packPhilCore4337GasFees,
  type PhilCorePackedUserOperation
} from "./philcore4337UserOperationPreparation.ts";
import type {
  PhilCore4337SigningResult,
  PhilCore4337ValidatorSignerDescriptor
} from "./philcore4337UserOperationSigning.ts";
import type {
  PhilCore4337RecoveryAction,
  PhilCore4337RecoveryCandidate
} from "./philcore4337RotationRecovery.ts";
import { redactRuntimeMetadata, validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type { UserSessionLifecycleSnapshot } from "./sessionLifecycle.ts";
import type { RuntimeResult } from "./types.ts";

const recoveryInterface = new Interface([
  "function requestRecovery(address pendingOwner)",
  "function cancelRecovery(bytes32 requestId)",
  "function completeRecovery(bytes32 requestId,address expectedPendingOwner)",
  "function execute(address target,uint256 value,bytes data)"
]);

export const PHILCORE_4337_REQUEST_RECOVERY_SELECTOR =
  recoveryInterface.getFunction("requestRecovery")?.selector as "0xc47abf7d";
export const PHILCORE_4337_CANCEL_RECOVERY_SELECTOR =
  recoveryInterface.getFunction("cancelRecovery")?.selector as "0x8d7d0d1e";
export const PHILCORE_4337_COMPLETE_RECOVERY_SELECTOR =
  recoveryInterface.getFunction("completeRecovery")?.selector as "0x7f3f9f43";
export const PHILCORE_4337_EXECUTE_SELECTOR_FORBIDDEN_TO_RECOVERY =
  recoveryInterface.getFunction("execute")?.selector as "0xb61d27f6";

export type RecoveryAuthorityCustodyType =
  | "device_vault_separate_ecdsa_key"
  | "second_trusted_device"
  | "hardware_security_key"
  | "threshold_authority"
  | "managed_testnet_operator"
  | "external_registered_address"
  | "unsupported";

export type RecoveryAuthorityLifecycleState =
  | "active"
  | "suspended"
  | "pending_rotation"
  | "rotated"
  | "revoked"
  | "lost"
  | "compromised"
  | "archived";

export type RecoveryAuthorityPurpose =
  | "local_alpha_recovery_authority"
  | "base_sepolia_beta_recovery_authority"
  | "production_recovery_authority";

export interface RecoveryAuthorityMetadata {
  readonly authorityId: string;
  readonly publicRecoveryAddress: string;
  readonly accountAddress?: string;
  readonly ownerCommitment: Hex;
  readonly custodyType: RecoveryAuthorityCustodyType;
  readonly purpose: RecoveryAuthorityPurpose;
  readonly lifecycleState: RecoveryAuthorityLifecycleState;
  readonly rotationVersion: number;
  readonly chainId: number;
  readonly networkProfile: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly auditCorrelationId: string;
  readonly privateKeyReturned: false;
  readonly storedEncrypted: boolean;
  readonly separateFromExecutionKey: boolean;
  readonly ordinaryExecutionAuthority: false;
  readonly publicSubmissionEnabled: false;
}

export interface RecoveryAuthorityRecord {
  readonly recordId: string;
  readonly metadata: RecoveryAuthorityMetadata;
  readonly keyReference?: DeviceVaultEcdsaValidatorKeyReference;
  readonly deviceVaultRecord?: DeviceVaultEcdsaValidatorRecord;
  readonly externalSignerReference?: string;
}

export interface RecoveryAuthorityGenerationRequest {
  readonly requestId: string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly accountAddress?: string;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly networkProfile: string;
  readonly purpose: Exclude<RecoveryAuthorityPurpose, "production_recovery_authority">;
  readonly executionOwnerAddress: string;
  readonly issuedAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly auditCorrelationId?: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface RecoveryAuthorityRegistrationRequest {
  readonly requestId: string;
  readonly accountAddress: string;
  readonly ownerCommitment: Hex;
  readonly chainId: number;
  readonly networkProfile: string;
  readonly publicRecoveryAddress: string;
  readonly custodyType: Exclude<RecoveryAuthorityCustodyType, "device_vault_separate_ecdsa_key">;
  readonly purpose: RecoveryAuthorityPurpose;
  readonly executionOwnerAddress?: string;
  readonly externalSignerReference?: string;
  readonly issuedAt?: string;
  readonly auditCorrelationId?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface RecoveryAuthorityAccountBindingRequest {
  readonly requestId: string;
  readonly recoveryRecord: RecoveryAuthorityRecord;
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly accountAddress: string;
  readonly chainId: number;
  readonly auditCorrelationId?: string;
}

export type RecoveryAuthorityRecordResult = RuntimeResult<{
  readonly status: "recovery_authority_record_created";
  readonly record: RecoveryAuthorityRecord;
  readonly privateKeyReturned: false;
  readonly storedEncrypted: boolean;
  readonly separateFromExecutionKey: boolean;
  readonly ordinaryExecutionAuthority: false;
  readonly publicSubmissionEnabled: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}>;

export type PhilCoreRecoveryActionPresentationKind =
  | "recovery_request"
  | "recovery_completion"
  | "recovery_cancellation";

export interface PhilCoreRecoveryUserOperationDraft {
  readonly recoveryUserOperationDraftId: string;
  readonly status: "recovery_user_operation_draft_created";
  readonly action: PhilCore4337RecoveryAction;
  readonly accountAddress: string;
  readonly recoveryAuthority: string;
  readonly currentOwner: string;
  readonly pendingOwner?: string;
  readonly ownerCommitment: Hex;
  readonly entryPointAddress: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly callData: Hex;
  readonly callDataHash: Hex;
  readonly maintenanceSelector: string;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly userOperationHash: Hex;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly recoveryAuthorityCanExecuteOrdinaryActions: false;
  readonly recoveryAuthorityCanTransferAssets: false;
  readonly publicUserOperationSubmitted: false;
  readonly paymasterInvoked: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly ownerCommitmentChanged: false;
  readonly actionGateChanged: false;
  readonly entryPointChanged: false;
}

export interface PhilCoreRecoveryUserOperationPreparationRequest {
  readonly requestId: string;
  readonly candidate: PhilCore4337RecoveryCandidate;
  readonly entryPointAddress: string;
  readonly nonce: string | bigint | number;
  readonly chainId: number;
  readonly expiresAt: string;
  readonly callGasLimit?: string | bigint | number;
  readonly verificationGasLimit?: string | bigint | number;
  readonly preVerificationGas?: string | bigint | number;
  readonly maxPriorityFeePerGas?: string | bigint | number;
  readonly maxFeePerGas?: string | bigint | number;
}

export interface PhilCoreRecoveryActionPresentation {
  readonly presentationId: string;
  readonly kind: PhilCoreRecoveryActionPresentationKind;
  readonly action: PhilCore4337RecoveryAction;
  readonly accountAddress: string;
  readonly ownerCommitment: Hex;
  readonly currentOwner: string;
  readonly proposedNewOwner?: string;
  readonly recoveryAuthority: string;
  readonly recoveryRequestId?: Hex;
  readonly network: { readonly chainId: number; readonly entryPointAddress: string };
  readonly maintenanceSelector: string;
  readonly callDataHash: Hex;
  readonly userOperationHash: Hex;
  readonly nonce: string;
  readonly gasSummary: {
    readonly accountGasLimits: Hex;
    readonly preVerificationGas: string;
    readonly gasFees: Hex;
    readonly paymasterDisabled: true;
  };
  readonly freezeBehavior: "request_freezes_account" | "completion_unfreezes_account" | "cancellation_unfreezes_account";
  readonly exactActionOnly: true;
  readonly ordinaryExecutionAuthority: false;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
}

export interface PhilCoreRecoveryActionPresentationResult {
  readonly presentation: PhilCoreRecoveryActionPresentation;
  readonly presentationDigest: Hex;
}

export type PhilCoreRecoveryApprovalSource =
  | "authenticated_recovery_device_user"
  | "trusted_secondary_device"
  | "hardware_key_confirmation"
  | "approved_testnet_operator"
  | "developer_fixture";

export interface PhilCoreRecoveryActionApprovalRequest {
  readonly approvalId: string;
  readonly presentationDigest: Hex;
  readonly source: PhilCoreRecoveryApprovalSource;
  readonly approved: boolean;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly oneTime: true;
  readonly publicNetworkAllowed: boolean;
}

export interface PhilCoreRecoveryActionApprovalArtifact extends PhilCoreRecoveryActionApprovalRequest {
  readonly approvalArtifactId: string;
}

export interface PhilCoreRecoveryApprovalStore {
  consumeApproval(approval: PhilCoreRecoveryActionApprovalArtifact): {
    readonly status: "approval_accepted" | "approval_rejected" | "approval_replayed" | "approval_expired";
    readonly errors: readonly string[];
  };
}

export interface PhilCoreRecoverySigningSession {
  readonly signingSessionId: string;
  inspect(): {
    readonly signingSessionId: string;
    readonly recoveryAuthority: string;
    readonly status: "active" | "used" | "invalidated" | "expired";
    readonly oneTime: true;
    readonly privateKeyReturned: false;
    readonly arbitraryMessageSigning: false;
    readonly arbitraryTransactionSigning: false;
  };
  signRecoveryUserOperationHash(request: PhilCoreRecoverySigningRequest): Promise<PhilCoreRecoverySigningResult>;
  invalidate(reason?: string): void;
  toJSON(): never;
}

export interface PhilCoreRecoverySigningRequest {
  readonly userOperationHash: Hex;
  readonly presentationDigest: Hex;
  readonly expectedRecoveryAuthority: string;
  readonly entryPointAddress: string;
  readonly accountAddress: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly callDataHash: Hex;
  readonly maintenanceSelector: string;
  readonly auditCorrelationId: string;
}

export interface PhilCoreRecoverySigningResult {
  readonly status: "signed" | "rejected" | "signer_unavailable";
  readonly signature?: Hex;
  readonly signerDescriptor: PhilCore4337ValidatorSignerDescriptor;
  readonly signedAt: string;
  readonly errors?: readonly string[];
}

export interface SignedPhilCoreRecoveryUserOperation {
  readonly signedRecoveryUserOperationId: string;
  readonly status: "recovery_user_operation_signed";
  readonly draft: PhilCoreRecoveryUserOperationDraft;
  readonly presentation: PhilCoreRecoveryActionPresentation;
  readonly presentationDigest: Hex;
  readonly approval: PhilCoreRecoveryActionApprovalArtifact;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly signature: Hex;
  readonly signedAt: string;
  readonly transactionSubmitted: false;
  readonly publicUserOperationSubmitted: false;
  readonly recoveryStateMutatedBySigning: false;
  readonly privateKeyExposed: false;
}

export interface PhilCoreRecoverySigningSessionRequest {
  readonly requestId: string;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
  readonly unlockedVaultHandle: UnlockedDeviceVaultHandleMetadata;
  readonly storageBackend: PhilDeviceIdentityRegistryStorageBackend;
  readonly keyProvider: PhilDeviceIdentityRegistryKeyProvider;
  readonly recoveryRecord: RecoveryAuthorityRecord;
  readonly draft: PhilCoreRecoveryUserOperationDraft;
  readonly presentationDigest: Hex;
  readonly issuedAt?: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
}

export interface PhilCoreRecoveryUserOperationSigningRequest {
  readonly requestId: string;
  readonly draft: PhilCoreRecoveryUserOperationDraft;
  readonly presentation: PhilCoreRecoveryActionPresentation;
  readonly presentationDigest: Hex;
  readonly approval: PhilCoreRecoveryActionApprovalArtifact;
  readonly signer: PhilCoreRecoverySigningSession;
  readonly approvalStore?: PhilCoreRecoveryApprovalStore;
  readonly auditDraftCollector?: AuditDraftCollector;
}

function nowIso(): string {
  return new Date().toISOString();
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as TValue;
  if (value && typeof value === "object") {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, freezeRecord(entry)])
    )) as TValue;
  }
  return value;
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function normalizeHex(value: string, bytes?: number): Hex {
  if (!isHexString(value, bytes)) throw new Error("invalid hex");
  return hexlify(value).toLowerCase() as Hex;
}

function recoveryPurposeToVaultPurpose(purpose: Exclude<RecoveryAuthorityPurpose, "production_recovery_authority">): DeviceVaultEcdsaValidatorPurpose {
  return purpose === "base_sepolia_beta_recovery_authority"
    ? "erc4337_recovery_authority_base_sepolia_beta"
    : "erc4337_recovery_authority_local_alpha";
}

function runtimeError(code: string, errors: readonly string[]) {
  return {
    code,
    category: "vault_unavailable" as const,
    message: "PhilCore recovery authority custody request was rejected.",
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
    outcome: input.outcome.includes("created")
      || input.outcome.includes("signed")
      || input.outcome.includes("registered")
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: "requestPhilCoreRecoveryAuthorityCustody",
    summary: input.summary,
    auditCorrelationId: input.auditCorrelationId,
    redactedDetails: {
      ...(input.details ? redactRuntimeMetadata(input.details).value : {}),
      privateKeyReturned: false,
      rawPrivateKeyIncluded: false,
      philSecretExposed: false,
      vaultKeyExposed: false,
      ordinaryExecutionAuthority: false
    }
  });
}

function validateCommon(input: {
  readonly accountAddress?: string;
  readonly ownerCommitment?: string;
  readonly chainId?: number;
  readonly networkProfile?: string;
}): string[] {
  const errors: string[] = [];
  try {
    if (input.accountAddress !== undefined) normalizeAddress(input.accountAddress);
  } catch {
    errors.push("accountAddress must be a valid address");
  }
  if (!input.ownerCommitment || !isHexString(input.ownerCommitment, 32)) errors.push("ownerCommitment must be bytes32");
  if (!Number.isInteger(input.chainId) || Number(input.chainId) <= 0) errors.push("chainId must be positive");
  if (!input.networkProfile || input.networkProfile.length === 0) errors.push("networkProfile is required");
  return errors;
}

function metadataErrors(metadata?: Readonly<Record<string, unknown>>): readonly string[] {
  return metadata ? validateNoSensitiveMetadataKeys(metadata).errors : Object.freeze([]);
}

export async function generatePhilCoreRecoveryAuthority(
  request: RecoveryAuthorityGenerationRequest
): Promise<RecoveryAuthorityRecordResult> {
  const errors = [
    ...validateCommon(request),
    ...metadataErrors(request.metadata)
  ];
  let executionOwner = "";
  try {
    executionOwner = normalizeAddress(request.executionOwnerAddress);
  } catch {
    errors.push("executionOwnerAddress must be valid");
  }
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.accountAddress ?? "account-unbound",
    "philcore-recovery-authority-generation"
  ]);
  if (errors.length > 0) {
    const auditEventDraft = audit({
      outcome: "recovery_authority_generation_rejected",
      summary: "Recovery authority generation was rejected.",
      auditCorrelationId,
      details: { errors }
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError("PHILCORE_RECOVERY_AUTHORITY_GENERATION_REJECTED", errors), {
      auditEventId: auditEventDraft.eventDraftId
    });
  }

  const generated = await generateDeviceVaultEcdsaValidator({
    requestId: request.requestId,
    lifecycleSnapshot: request.lifecycleSnapshot,
    unlockedVaultHandle: request.unlockedVaultHandle,
    storageBackend: request.storageBackend,
    keyProvider: request.keyProvider,
    ownerCommitment: request.ownerCommitment,
    purpose: recoveryPurposeToVaultPurpose(request.purpose),
    accountAddress: request.accountAddress,
    chainId: request.chainId,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    metadata: request.metadata,
    auditCorrelationId,
    auditDraftCollector: request.auditDraftCollector
  });
  if (generated.status !== "approved" || !generated.value) {
    return runtimeDenied(generated.error ?? runtimeError("PHILCORE_RECOVERY_AUTHORITY_GENERATION_FAILED", ["vault generation failed"]));
  }
  const value = generated.value as DeviceVaultEcdsaKeyGenerationResultValue;
  if (normalizeAddress(value.ownerAddress) === executionOwner) {
    return runtimeDenied(runtimeError("PHILCORE_RECOVERY_AUTHORITY_NOT_SEPARATE", ["recovery authority matches execution owner"]));
  }
  const createdAt = value.generatedAt;
  const recordId = createAuditCorrelationId([
    value.keyReference.keyReferenceId,
    request.accountAddress ?? "account-unbound",
    "philcore-recovery-authority-record"
  ]);
  const record: RecoveryAuthorityRecord = freezeRecord({
    recordId,
    metadata: {
      authorityId: createAuditCorrelationId([recordId, "authority-id"]),
      publicRecoveryAddress: normalizeAddress(value.ownerAddress),
      accountAddress: request.accountAddress ? normalizeAddress(request.accountAddress) : undefined,
      ownerCommitment: normalizeHex(request.ownerCommitment, 32),
      custodyType: "device_vault_separate_ecdsa_key",
      purpose: request.purpose,
      lifecycleState: "active",
      rotationVersion: 1,
      chainId: request.chainId,
      networkProfile: request.networkProfile,
      createdAt,
      updatedAt: createdAt,
      auditCorrelationId,
      privateKeyReturned: false,
      storedEncrypted: true,
      separateFromExecutionKey: true,
      ordinaryExecutionAuthority: false,
      publicSubmissionEnabled: false
    },
    keyReference: value.keyReference,
    deviceVaultRecord: value.record
  });
  const auditEventDraft = audit({
    outcome: "recovery_authority_record_created",
    summary: "Recovery authority key was generated as a separate encrypted Device Vault record.",
    auditCorrelationId,
    details: {
      authorityId: record.metadata.authorityId,
      accountAddress: record.metadata.accountAddress,
      publicRecoveryAddress: record.metadata.publicRecoveryAddress,
      ownerCommitment: record.metadata.ownerCommitment,
      custodyType: record.metadata.custodyType,
      privateKeyReturned: false,
      storedEncrypted: true,
      separateFromExecutionKey: true,
      ordinaryExecutionAuthority: false,
      publicSubmissionEnabled: false
    }
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    status: "recovery_authority_record_created",
    record,
    privateKeyReturned: false,
    storedEncrypted: true,
    separateFromExecutionKey: true,
    ordinaryExecutionAuthority: false,
    publicSubmissionEnabled: false,
    auditEventDraft,
    auditDraftCollectionResult
  }), { auditEventId: auditEventDraft.eventDraftId });
}

export async function bindPhilCoreRecoveryAuthorityAccountReference(
  request: RecoveryAuthorityAccountBindingRequest
): Promise<RecoveryAuthorityRecordResult> {
  if (!request.recoveryRecord.keyReference) {
    return runtimeDenied(runtimeError("PHILCORE_RECOVERY_AUTHORITY_BINDING_REJECTED", ["recovery record has no Device Vault key reference"]));
  }
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.accountAddress,
    "philcore-recovery-authority-account-binding"
  ]);
  const bound = await bindDeviceVaultEcdsaValidatorAccountReference({
    storageBackend: request.storageBackend,
    keyProvider: request.keyProvider,
    keyReference: request.recoveryRecord.keyReference,
    accountAddress: request.accountAddress,
    chainId: request.chainId
  });
  if (bound.status !== "account_reference_bound" || !bound.record) {
    return runtimeDenied(runtimeError("PHILCORE_RECOVERY_AUTHORITY_BINDING_REJECTED", [bound.reason ?? "account binding failed"]));
  }
  const updated: RecoveryAuthorityRecord = freezeRecord({
    ...request.recoveryRecord,
    metadata: {
      ...request.recoveryRecord.metadata,
      accountAddress: normalizeAddress(request.accountAddress),
      chainId: request.chainId,
      updatedAt: nowIso(),
      auditCorrelationId
    },
    keyReference: bound.record.keyReference,
    deviceVaultRecord: bound.record
  });
  const auditEventDraft = audit({
    outcome: "recovery_authority_record_created",
    summary: "Recovery authority record was bound to the PhilCore account address.",
    auditCorrelationId,
    details: {
      authorityId: updated.metadata.authorityId,
      accountAddress: updated.metadata.accountAddress,
      publicRecoveryAddress: updated.metadata.publicRecoveryAddress,
      chainId: updated.metadata.chainId
    }
  });
  return runtimeOk(freezeRecord({
    status: "recovery_authority_record_created",
    record: updated,
    privateKeyReturned: false,
    storedEncrypted: true,
    separateFromExecutionKey: true,
    ordinaryExecutionAuthority: false,
    publicSubmissionEnabled: false,
    auditEventDraft
  }), { auditEventId: auditEventDraft.eventDraftId });
}

export function registerExternalPhilCoreRecoveryAuthority(
  request: RecoveryAuthorityRegistrationRequest
): RecoveryAuthorityRecordResult {
  const errors = [
    ...validateCommon(request),
    ...metadataErrors(request.metadata)
  ];
  try {
    const recovery = normalizeAddress(request.publicRecoveryAddress);
    if (request.executionOwnerAddress && recovery === normalizeAddress(request.executionOwnerAddress)) {
      errors.push("recovery authority matches execution owner");
    }
  } catch {
    errors.push("publicRecoveryAddress must be valid");
  }
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    request.requestId,
    request.publicRecoveryAddress,
    "philcore-external-recovery-authority"
  ]);
  if (errors.length > 0) return runtimeDenied(runtimeError("PHILCORE_RECOVERY_AUTHORITY_REGISTRATION_REJECTED", errors));
  const issuedAt = request.issuedAt ?? nowIso();
  const recordId = createAuditCorrelationId([
    request.requestId,
    request.publicRecoveryAddress,
    "philcore-recovery-authority-record"
  ]);
  const record: RecoveryAuthorityRecord = freezeRecord({
    recordId,
    metadata: {
      authorityId: createAuditCorrelationId([recordId, "authority-id"]),
      publicRecoveryAddress: normalizeAddress(request.publicRecoveryAddress),
      accountAddress: normalizeAddress(request.accountAddress),
      ownerCommitment: normalizeHex(request.ownerCommitment, 32),
      custodyType: request.custodyType,
      purpose: request.purpose,
      lifecycleState: "active",
      rotationVersion: 1,
      chainId: request.chainId,
      networkProfile: request.networkProfile,
      createdAt: issuedAt,
      updatedAt: issuedAt,
      auditCorrelationId,
      privateKeyReturned: false,
      storedEncrypted: false,
      separateFromExecutionKey: true,
      ordinaryExecutionAuthority: false,
      publicSubmissionEnabled: false
    },
    externalSignerReference: request.externalSignerReference
  });
  const auditEventDraft = audit({
    outcome: "recovery_authority_registered",
    summary: "External recovery authority public address was registered.",
    auditCorrelationId,
    details: { ...record.metadata }
  });
  return runtimeOk(freezeRecord({
    status: "recovery_authority_record_created",
    record,
    privateKeyReturned: false,
    storedEncrypted: false,
    separateFromExecutionKey: true,
    ordinaryExecutionAuthority: false,
    publicSubmissionEnabled: false,
    auditEventDraft
  }), { auditEventId: auditEventDraft.eventDraftId });
}

export function preparePhilCoreRecoveryUserOperation(
  request: PhilCoreRecoveryUserOperationPreparationRequest
): RuntimeResult<PhilCoreRecoveryUserOperationDraft> {
  const errors: string[] = [];
  if (!["request_recovery", "complete_recovery"].includes(request.candidate.action)) {
    errors.push("recovery authority may only prepare request or completion actions");
  }
  if (
    request.candidate.maintenanceSelector !== PHILCORE_4337_REQUEST_RECOVERY_SELECTOR
    && request.candidate.maintenanceSelector !== PHILCORE_4337_COMPLETE_RECOVERY_SELECTOR
  ) {
    errors.push("unsupported recovery maintenance selector");
  }
  if (request.candidate.maintenanceCallData.startsWith(PHILCORE_4337_EXECUTE_SELECTOR_FORBIDDEN_TO_RECOVERY)) {
    errors.push("recovery authority cannot sign execute");
  }
  if (request.chainId !== request.candidate.chainId) errors.push("chain id mismatch");
  if (Date.parse(request.expiresAt) <= Date.now()) errors.push("draft expiry is in the past");
  if (errors.length > 0) return runtimeDenied(runtimeError("PHILCORE_RECOVERY_USER_OPERATION_REJECTED", errors));

  const userOperation: PhilCorePackedUserOperation = freezeRecord({
    sender: normalizeAddress(request.candidate.accountAddress),
    nonce: BigInt(request.nonce).toString(),
    initCode: PHILCORE_4337_EMPTY_BYTES,
    callData: request.candidate.maintenanceCallData,
    accountGasLimits: packPhilCore4337AccountGasLimits({
      verificationGasLimit: request.verificationGasLimit ?? 300_000n,
      callGasLimit: request.callGasLimit ?? 300_000n
    }),
    preVerificationGas: BigInt(request.preVerificationGas ?? 75_000n).toString(),
    gasFees: packPhilCore4337GasFees({
      maxPriorityFeePerGas: request.maxPriorityFeePerGas ?? 1_000_000_000n,
      maxFeePerGas: request.maxFeePerGas ?? 30_000_000_000n
    }),
    paymasterAndData: PHILCORE_4337_EMPTY_BYTES,
    signature: PHILCORE_4337_EMPTY_BYTES
  });
  const userOperationHash = computePhilCore4337UserOperationHash({
    userOperation,
    entryPointAddress: request.entryPointAddress,
    chainId: request.chainId
  });
  return runtimeOk(freezeRecord({
    recoveryUserOperationDraftId: createAuditCorrelationId([
      request.requestId,
      userOperationHash,
      "philcore-recovery-user-operation-draft"
    ]),
    status: "recovery_user_operation_draft_created",
    action: request.candidate.action,
    accountAddress: normalizeAddress(request.candidate.accountAddress),
    recoveryAuthority: normalizeAddress(request.candidate.recoveryAuthority),
    currentOwner: normalizeAddress(request.candidate.currentOwner),
    pendingOwner: request.candidate.pendingOwner ? normalizeAddress(request.candidate.pendingOwner) : undefined,
    ownerCommitment: request.candidate.ownerCommitment,
    entryPointAddress: normalizeAddress(request.entryPointAddress),
    chainId: request.chainId,
    nonce: userOperation.nonce,
    callData: userOperation.callData,
    callDataHash: keccak256(userOperation.callData) as Hex,
    maintenanceSelector: request.candidate.maintenanceSelector,
    userOperation,
    userOperationHash,
    issuedAt: request.candidate.issuedAt,
    expiresAt: request.expiresAt,
    recoveryAuthorityCanExecuteOrdinaryActions: false,
    recoveryAuthorityCanTransferAssets: false,
    publicUserOperationSubmitted: false,
    paymasterInvoked: false,
    nullifierConsumed: false,
    consumerExecuted: false,
    ownerCommitmentChanged: false,
    actionGateChanged: false,
    entryPointChanged: false
  }));
}

export function createPhilCoreRecoveryActionPresentation(
  draft: PhilCoreRecoveryUserOperationDraft,
  auditCorrelationId = createAuditCorrelationId([draft.recoveryUserOperationDraftId, "recovery-presentation"])
): PhilCoreRecoveryActionPresentationResult {
  const kind: PhilCoreRecoveryActionPresentationKind = draft.action === "request_recovery"
    ? "recovery_request"
    : "recovery_completion";
  const presentation: PhilCoreRecoveryActionPresentation = freezeRecord({
    presentationId: createAuditCorrelationId([draft.recoveryUserOperationDraftId, draft.userOperationHash, "presentation"]),
    kind,
    action: draft.action,
    accountAddress: draft.accountAddress,
    ownerCommitment: draft.ownerCommitment,
    currentOwner: draft.currentOwner,
    proposedNewOwner: draft.pendingOwner,
    recoveryAuthority: draft.recoveryAuthority,
    network: {
      chainId: draft.chainId,
      entryPointAddress: draft.entryPointAddress
    },
    maintenanceSelector: draft.maintenanceSelector,
    callDataHash: draft.callDataHash,
    userOperationHash: draft.userOperationHash,
    nonce: draft.nonce,
    gasSummary: {
      accountGasLimits: draft.userOperation.accountGasLimits,
      preVerificationGas: draft.userOperation.preVerificationGas,
      gasFees: draft.userOperation.gasFees,
      paymasterDisabled: true
    },
    freezeBehavior: draft.action === "request_recovery"
      ? "request_freezes_account"
      : "completion_unfreezes_account",
    exactActionOnly: true,
    ordinaryExecutionAuthority: false,
    expiresAt: draft.expiresAt,
    auditCorrelationId
  });
  const presentationDigest = keccak256(toUtf8Bytes(JSON.stringify({
    accountAddress: presentation.accountAddress,
    ownerCommitment: presentation.ownerCommitment,
    recoveryAuthority: presentation.recoveryAuthority,
    proposedNewOwner: presentation.proposedNewOwner,
    selector: presentation.maintenanceSelector,
    callDataHash: presentation.callDataHash,
    userOperationHash: presentation.userOperationHash,
    nonce: presentation.nonce,
    chainId: presentation.network.chainId,
    expiresAt: presentation.expiresAt
  }))) as Hex;
  return freezeRecord({ presentation, presentationDigest });
}

export function createPhilCoreRecoveryActionApprovalArtifact(
  input: PhilCoreRecoveryActionApprovalRequest
): PhilCoreRecoveryActionApprovalArtifact {
  return freezeRecord({
    ...input,
    approvalArtifactId: createAuditCorrelationId([
      input.approvalId,
      input.presentationDigest,
      input.source,
      "philcore-recovery-approval"
    ])
  });
}

export function createInMemoryPhilCoreRecoveryApprovalStore(): PhilCoreRecoveryApprovalStore {
  const consumed = new Set<string>();
  return Object.freeze({
    consumeApproval(approval: PhilCoreRecoveryActionApprovalArtifact) {
      if (consumed.has(approval.approvalId)) {
        return freezeRecord({ status: "approval_replayed" as const, errors: Object.freeze(["approval already consumed"]) });
      }
      if (Date.parse(approval.expiresAt) <= Date.now()) {
        return freezeRecord({ status: "approval_expired" as const, errors: Object.freeze(["approval expired"]) });
      }
      if (!approval.approved) {
        return freezeRecord({ status: "approval_rejected" as const, errors: Object.freeze(["approval rejected"]) });
      }
      consumed.add(approval.approvalId);
      return freezeRecord({ status: "approval_accepted" as const, errors: Object.freeze([]) });
    }
  });
}

export async function createPhilCoreRecoveryAuthoritySigningSession(
  request: PhilCoreRecoverySigningSessionRequest
): Promise<RuntimeResult<{
  readonly status: "recovery_signing_session_created";
  readonly signingSession: PhilCoreRecoverySigningSession;
  readonly auditEventDraft?: AuditEventDraft;
}>> {
  if (!request.recoveryRecord.keyReference) {
    return runtimeDenied(runtimeError("PHILCORE_RECOVERY_SIGNER_UNAVAILABLE", ["recovery record has no Device Vault key reference"]));
  }
  const underlying = await createDeviceVaultEcdsaSigningSession({
    requestId: request.requestId,
    lifecycleSnapshot: request.lifecycleSnapshot,
    unlockedVaultHandle: request.unlockedVaultHandle,
    storageBackend: request.storageBackend,
    keyProvider: request.keyProvider,
    keyReference: request.recoveryRecord.keyReference,
    ownerCommitment: request.recoveryRecord.metadata.ownerCommitment,
    smartAccountAddress: request.draft.accountAddress,
    entryPointAddress: request.draft.entryPointAddress,
    chainId: request.draft.chainId,
    userOperationHash: request.draft.userOperationHash,
    presentationDigest: request.presentationDigest,
    callDataHash: request.draft.callDataHash,
    purpose: recoveryPurposeToVaultPurpose(
      request.recoveryRecord.metadata.purpose === "base_sepolia_beta_recovery_authority"
        ? "base_sepolia_beta_recovery_authority"
        : "local_alpha_recovery_authority"
    ),
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId
  });
  if (underlying.status !== "approved" || !underlying.value) {
    return runtimeDenied(underlying.error ?? runtimeError("PHILCORE_RECOVERY_SIGNING_SESSION_REJECTED", ["underlying signing session failed"]));
  }
  const baseSession: DeviceVaultEcdsaSigningSession = underlying.value.signingSession;
  const baseSigner = createDeviceVaultEcdsaValidatorSigner(baseSession);
  const signingSessionId = `philcore-recovery:${baseSession.signingSessionId}`;
  const session: PhilCoreRecoverySigningSession = Object.freeze({
    signingSessionId,
    inspect() {
      const snapshot = baseSession.inspect();
      return freezeRecord({
        signingSessionId,
        recoveryAuthority: snapshot.binding.ownerAddress,
        status: snapshot.status,
        oneTime: true as const,
        privateKeyReturned: false as const,
        arbitraryMessageSigning: false as const,
        arbitraryTransactionSigning: false as const
      });
    },
    async signRecoveryUserOperationHash(signingRequest: PhilCoreRecoverySigningRequest): Promise<PhilCoreRecoverySigningResult> {
      const errors: string[] = [];
      if (
        signingRequest.maintenanceSelector !== PHILCORE_4337_REQUEST_RECOVERY_SELECTOR
        && signingRequest.maintenanceSelector !== PHILCORE_4337_COMPLETE_RECOVERY_SELECTOR
      ) {
        errors.push("recovery signer may only sign requestRecovery or completeRecovery");
      }
      if (signingRequest.maintenanceSelector === PHILCORE_4337_EXECUTE_SELECTOR_FORBIDDEN_TO_RECOVERY) {
        errors.push("recovery signer cannot sign execute");
      }
      if (normalizeAddress(signingRequest.expectedRecoveryAuthority) !== normalizeAddress(request.recoveryRecord.metadata.publicRecoveryAddress)) {
        errors.push("recovery authority mismatch");
      }
      if (errors.length > 0) {
        return freezeRecord({
          status: "rejected",
          signerDescriptor: await baseSigner.describeSigner(),
          signedAt: nowIso(),
          errors: Object.freeze(errors)
        });
      }
      return baseSession.signUserOperationHash({
        userOperationHash: signingRequest.userOperationHash,
        presentationDigest: signingRequest.presentationDigest,
        expectedOwner: signingRequest.expectedRecoveryAuthority,
        chainId: signingRequest.chainId,
        entryPointAddress: signingRequest.entryPointAddress,
        smartAccountAddress: signingRequest.accountAddress,
        nonce: signingRequest.nonce,
        callDataHash: signingRequest.callDataHash,
        auditCorrelationId: signingRequest.auditCorrelationId
      }) as Promise<PhilCoreRecoverySigningResult>;
    },
    invalidate(reason?: string) {
      baseSession.invalidate(reason);
    },
    toJSON(): never {
      throw new Error("PhilCore recovery signing sessions are process-local and non-serializable");
    }
  });
  const auditEventDraft = audit({
    outcome: "recovery_signing_session_created",
    summary: "Recovery authority signing session was created for one exact recovery UserOperation.",
    auditCorrelationId: request.auditCorrelationId,
    details: {
      signingSessionId,
      recoveryAuthority: request.recoveryRecord.metadata.publicRecoveryAddress,
      accountAddress: request.draft.accountAddress,
      selector: request.draft.maintenanceSelector,
      userOperationHash: request.draft.userOperationHash,
      arbitraryMessageSigning: false,
      arbitraryTransactionSigning: false
    }
  });
  return runtimeOk(freezeRecord({
    status: "recovery_signing_session_created",
    signingSession: session,
    auditEventDraft
  }), { auditEventId: auditEventDraft.eventDraftId });
}

export async function signPhilCoreRecoveryUserOperation(
  request: PhilCoreRecoveryUserOperationSigningRequest
): Promise<RuntimeResult<SignedPhilCoreRecoveryUserOperation>> {
  const errors: string[] = [];
  if (request.presentationDigest.toLowerCase() !== request.approval.presentationDigest.toLowerCase()) {
    errors.push("presentation digest mismatch");
  }
  if (request.presentation.userOperationHash.toLowerCase() !== request.draft.userOperationHash.toLowerCase()) {
    errors.push("presentation does not match draft");
  }
  if (request.draft.action === "cancel_recovery") {
    errors.push("recovery authority signer cannot sign cancellation");
  }
  const approvalResult = request.approvalStore
    ? request.approvalStore.consumeApproval(request.approval)
    : { status: request.approval.approved ? "approval_accepted" : "approval_rejected", errors: request.approval.approved ? [] : ["approval rejected"] };
  if (approvalResult.status !== "approval_accepted") errors.push(...approvalResult.errors);
  if (errors.length > 0) return runtimeDenied(runtimeError("PHILCORE_RECOVERY_SIGNING_REJECTED", errors));

  const signed = await request.signer.signRecoveryUserOperationHash({
    userOperationHash: request.draft.userOperationHash,
    presentationDigest: request.presentationDigest,
    expectedRecoveryAuthority: request.draft.recoveryAuthority,
    entryPointAddress: request.draft.entryPointAddress,
    accountAddress: request.draft.accountAddress,
    chainId: request.draft.chainId,
    nonce: request.draft.nonce,
    callDataHash: request.draft.callDataHash,
    maintenanceSelector: request.draft.maintenanceSelector,
    auditCorrelationId: request.presentation.auditCorrelationId
  });
  if (signed.status !== "signed" || !signed.signature) {
    return runtimeDenied(runtimeError("PHILCORE_RECOVERY_SIGNER_REJECTED", signed.errors ?? ["signer rejected recovery UserOperation"]));
  }
  const userOperation: PhilCorePackedUserOperation = freezeRecord({
    ...request.draft.userOperation,
    signature: signed.signature
  });
  const auditEventDraft = audit({
    outcome: "recovery_user_operation_signed",
    summary: "Recovery authority signed one exact recovery maintenance UserOperation.",
    auditCorrelationId: request.presentation.auditCorrelationId,
    details: {
      accountAddress: request.draft.accountAddress,
      recoveryAuthority: request.draft.recoveryAuthority,
      selector: request.draft.maintenanceSelector,
      userOperationHash: request.draft.userOperationHash,
      signature: "present_redacted",
      publicUserOperationSubmitted: false
    }
  });
  request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({
    signedRecoveryUserOperationId: createAuditCorrelationId([
      request.requestId,
      request.draft.userOperationHash,
      "signed-recovery-user-operation"
    ]),
    status: "recovery_user_operation_signed",
    draft: request.draft,
    presentation: request.presentation,
    presentationDigest: request.presentationDigest,
    approval: request.approval,
    userOperation,
    signature: signed.signature,
    signedAt: signed.signedAt,
    transactionSubmitted: false,
    publicUserOperationSubmitted: false,
    recoveryStateMutatedBySigning: false,
    privateKeyExposed: false
  }), { auditEventId: auditEventDraft.eventDraftId });
}
