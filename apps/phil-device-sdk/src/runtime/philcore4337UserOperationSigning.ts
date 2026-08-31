import {
  AbiCoder,
  Signature,
  dataLength,
  getAddress,
  getBytes,
  hexlify,
  isHexString,
  keccak256,
  verifyMessage,
  zeroPadValue
} from "ethers";

import type { Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  PHILCORE_4337_EMPTY_BYTES,
  PHILCORE_4337_ENTRYPOINT_VERSION,
  computePhilCore4337UserOperationHash,
  unpackPhilCore4337Uints,
  validatePhilCore4337UserOperationDraft,
  verifyPhilCore4337Account,
  type PhilCore4337AccountStateReader,
  type PhilCore4337FoundationConfiguration,
  type PhilCore4337NonceReader,
  type PhilCore4337PrefundReader,
  type PhilCore4337PrefundRequirement,
  type PhilCoreBundlerGasEstimator,
  type PhilCorePackedUserOperation,
  type PhilCorePackedUserOperationDraft,
  type PhilCoreUserOperationGasEstimateResult
} from "./philcore4337UserOperationPreparation.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk
} from "./helpers.ts";
import type { RuntimeResult } from "./types.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const SECP256K1_N_DIV_2 = BigInt("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

export type PhilCore4337ValidatorMode =
  | "device_vault_beta_ecdsa"
  | "external_protected_signer"
  | "operator_fixture"
  | "developer_fixture"
  | "future_webauthn_validator"
  | "unsupported";

export interface PhilCore4337ValidatorKeyReference {
  readonly keyReferenceId: string;
  readonly mode: PhilCore4337ValidatorMode;
  readonly custody: "device_vault_encrypted" | "device_vault_future" | "external" | "operator" | "developer_fixture" | "unsupported";
  readonly privateKeyExportable: false;
  readonly derivedFromPhilSecret: false;
}

export interface PhilCore4337ValidatorSignerDescriptor {
  readonly signerId: string;
  readonly mode: PhilCore4337ValidatorMode;
  readonly ownerAddress: string;
  readonly keyReference: PhilCore4337ValidatorKeyReference;
  readonly available: boolean;
  readonly productionApproved: boolean;
  readonly arbitraryMessageSigning: false;
  readonly arbitraryTransactionSigning: false;
}

export interface PhilCore4337SigningRequest {
  readonly userOperationHash: Hex;
  /** Optional purpose-bound digest. When absent, the canonical UserOperation hash is signed. */
  readonly signingDigest?: Hex;
  readonly presentationDigest: Hex;
  readonly expectedOwner: string;
  readonly chainId: number;
  readonly entryPointAddress: string;
  readonly smartAccountAddress: string;
  readonly nonce: string;
  readonly callDataHash: Hex;
  readonly auditCorrelationId: string;
}

export interface PhilCore4337SigningResult {
  readonly status: "signed" | "rejected" | "signer_unavailable";
  readonly signature?: Hex;
  readonly signerDescriptor: PhilCore4337ValidatorSignerDescriptor;
  readonly signedAt: string;
  readonly errors?: readonly string[];
}

export interface PhilCore4337ValidatorSigner {
  describeSigner(): Promise<PhilCore4337ValidatorSignerDescriptor>;
  checkAvailability(): Promise<PhilCore4337ValidatorSignerDescriptor>;
  getOwnerAddress(): Promise<string>;
  signUserOperationHash(request: PhilCore4337SigningRequest): Promise<PhilCore4337SigningResult>;
  invalidateSigningSession?(reason?: string): Promise<void>;
}

export interface PhilCore4337SigningRuntimeAuthoritySnapshot {
  readonly capabilityGrantStatus: "active" | "inactive" | "revoked" | "expired" | "exhausted";
  readonly sessionStatus: "eligible" | "locked" | "suspended" | "expired" | "closing" | "closed";
  readonly platformApprovalStatus: "valid" | "missing" | "rejected" | "expired";
  readonly baseExecutionApprovalStatus: "valid" | "missing" | "rejected" | "expired";
  readonly finalizedPackageStatus: "valid" | "expired" | "invalid";
  readonly mirroredFactStatus: "present" | "missing" | "mismatch" | "unknown";
  readonly nullifierStatus: "available" | "consumed" | "unknown";
}

export type PhilCore4337SigningAuthorizationStatus =
  | "signing_authorized"
  | "signing_not_authorized";

export type PhilCore4337SigningAuthorizationOutcome =
  | "signing_authorized"
  | "signing_not_authorized"
  | "runtime_authority_ineligible"
  | "capability_ineligible"
  | "session_ineligible"
  | "package_ineligible"
  | "mirrored_fact_ineligible"
  | "nullifier_unavailable"
  | "account_binding_mismatch"
  | "owner_mismatch"
  | "owner_commitment_mismatch"
  | "entry_point_mismatch"
  | "nonce_changed"
  | "gas_changed"
  | "fee_changed"
  | "prefund_insufficient"
  | "presentation_approval_required"
  | "presentation_approval_rejected"
  | "signer_unavailable"
  | "expired"
  | "malformed"
  | "unsupported";

export type PhilCore4337SigningAuthorizationReason =
  | "runtime_authority_revalidated"
  | "account_binding_revalidated"
  | "nonce_revalidated"
  | "gas_and_fee_revalidated"
  | "prefund_revalidated"
  | "presentation_approved"
  | "signer_bound_to_owner"
  | "no_bundler_submission";

export type PhilCore4337SigningLimitation =
  | "acp_0002_proposed"
  | "developer_fixture_only"
  | "device_vault_custody_not_implemented"
  | "signed_but_unsubmitted"
  | "paymaster_disabled"
  | "session_keys_disabled"
  | "requires_future_bundler_boundary";

export interface PhilCore4337SigningAuthorizationBinding {
  readonly draftId: string;
  readonly userOperationHash: Hex;
  readonly smartAccountAddress: string;
  readonly owner: string;
  readonly ownerCommitment: Hex;
  readonly entryPointAddress: string;
  readonly entryPointVersion: typeof PHILCORE_4337_ENTRYPOINT_VERSION;
  readonly factoryAddress?: string;
  readonly actionGateAddress: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly callDataHash: Hex;
  readonly innerCalldataHash: Hex;
  readonly accountGasLimits: Hex;
  readonly gasFees: Hex;
  readonly capabilityGrantId: string;
  readonly sessionId: string;
  readonly finalizedAuthorizationPackageId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
}

export interface PhilCore4337SigningPresentation {
  readonly presentationId: string;
  readonly entryPointVersion: typeof PHILCORE_4337_ENTRYPOINT_VERSION;
  readonly entryPointAddress: string;
  readonly chainId: number;
  readonly smartAccountAddress: string;
  readonly accountState: "deployed" | "counterfactual";
  readonly factoryAddress?: string;
  readonly owner: string;
  readonly ownerCommitment: Hex;
  readonly actionGateAddress: string;
  readonly innerCalldataHash: Hex;
  readonly proofInputHash: Hex;
  readonly nullifier: Hex;
  readonly capabilityGrantId: string;
  readonly sessionId: string;
  readonly applicationId: string;
  readonly value: string;
  readonly userOperationHash: Hex;
  readonly nonce: string;
  readonly verificationGasLimit: string;
  readonly callGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly maxFeePerGas: string;
  readonly prefundStatus: string;
  readonly paymasterDisabled: true;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
}

export interface PhilCore4337SigningPresentationResult {
  readonly presentation: PhilCore4337SigningPresentation;
  readonly presentationDigest: Hex;
}

export type PhilCore4337SigningApprovalSource =
  | "authenticated_platform_user"
  | "approved_runtime_policy"
  | "operator_testnet_approval"
  | "developer_fixture";

export interface PhilCore4337SigningApprovalRequest {
  readonly approvalId: string;
  readonly presentationDigest: Hex;
  readonly source: PhilCore4337SigningApprovalSource;
  readonly approved: boolean;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly oneTime: true;
  readonly publicNetworkAllowed: boolean;
  readonly consumed?: boolean;
}

export interface PhilCore4337SigningApprovalArtifact extends PhilCore4337SigningApprovalRequest {
  readonly approvalArtifactId: string;
}

export interface PhilCore4337SigningApprovalResult {
  readonly status: "approval_accepted" | "approval_rejected" | "approval_replayed" | "approval_expired";
  readonly approval?: PhilCore4337SigningApprovalArtifact;
  readonly errors: readonly string[];
}

export interface PhilCore4337SigningApprovalStore {
  consumeApproval(approval: PhilCore4337SigningApprovalArtifact): PhilCore4337SigningApprovalResult;
  hasConsumed(approvalId: string): boolean;
  clear(): void;
}

export interface PhilCore4337SignatureArtifact {
  readonly signatureArtifactId: string;
  readonly signature: Hex;
  readonly signatureFormat: "eth_sign_entrypoint_userop_hash_eip191";
  readonly userOperationHash: Hex;
  readonly recoveredOwner: string;
  readonly expectedOwner: string;
  readonly v: number;
  readonly r: Hex;
  readonly s: Hex;
  readonly lowS: boolean;
  readonly byteLength: number;
  readonly privateKeyExposed: false;
}

export interface PhilCore4337SigningAuthorizationResultValue {
  readonly status: "signing_authorized";
  readonly outcome: "signing_authorized";
  readonly binding: PhilCore4337SigningAuthorizationBinding;
  readonly presentation: PhilCore4337SigningPresentation;
  readonly presentationDigest: Hex;
  readonly approval: PhilCore4337SigningApprovalArtifact;
  readonly signerDescriptor: PhilCore4337ValidatorSignerDescriptor;
  readonly reasons: readonly PhilCore4337SigningAuthorizationReason[];
  readonly limitations: readonly PhilCore4337SigningLimitation[];
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
}

export interface PhilCore4337SigningAuthorizationRequest {
  readonly requestId: string;
  readonly draft: PhilCorePackedUserOperationDraft;
  readonly foundation: PhilCore4337FoundationConfiguration;
  readonly runtimeAuthority: PhilCore4337SigningRuntimeAuthoritySnapshot;
  readonly approval: PhilCore4337SigningApprovalArtifact;
  readonly signer: PhilCore4337ValidatorSigner;
  readonly nonceReader: PhilCore4337NonceReader;
  readonly gasEstimator?: PhilCoreBundlerGasEstimator;
  readonly prefundReader?: PhilCore4337PrefundReader;
  readonly accountStateReader?: PhilCore4337AccountStateReader;
  readonly approvalStore?: PhilCore4337SigningApprovalStore;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type PhilCore4337SigningAuthorizationRuntimeResult =
  RuntimeResult<PhilCore4337SigningAuthorizationResultValue>;

export type SignedPhilCore4337UserOperationStatus =
  | "user_operation_signed"
  | "user_operation_signing_rejected";

export type SignedPhilCore4337UserOperationOutcome =
  | "user_operation_signed"
  | "signing_rejected"
  | "signature_invalid"
  | "signer_unavailable"
  | "expired"
  | "malformed";

export interface SignedPhilCore4337UserOperationBinding extends PhilCore4337SigningAuthorizationBinding {
  readonly presentationDigest: Hex;
  readonly approvalId: string;
  readonly signerId: string;
  readonly signatureArtifactId: string;
}

export interface SignedPhilCore4337UserOperation {
  readonly signedPhilCore4337UserOperationId: string;
  readonly status: "user_operation_signed";
  readonly outcome: "user_operation_signed";
  readonly binding: SignedPhilCore4337UserOperationBinding;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly signatureArtifact: PhilCore4337SignatureArtifact;
  readonly signerDescriptor: PhilCore4337ValidatorSignerDescriptor;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly limitations: readonly PhilCore4337SigningLimitation[];
  readonly userOperationSigned: true;
  readonly userOperationSubmitted: false;
  readonly bundlerSubmissionPerformed: false;
  readonly paymasterInvoked: false;
  readonly smartAccountDeploymentPerformed: false;
  readonly nullifierConsumed: false;
  readonly consumerExecuted: false;
  readonly baseStateMutated: false;
  readonly applicationCanSubmitDirectly: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: SignedPhilCore4337UserOperationCollectionResult;
}

export interface PhilCore4337UserOperationSigningRequest extends PhilCore4337SigningAuthorizationRequest {
  readonly signedOperationStore?: SignedPhilCore4337UserOperationStore;
}

export type SignedPhilCore4337UserOperationResult =
  RuntimeResult<SignedPhilCore4337UserOperation>;

export type SignedPhilCore4337UserOperationCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "removed"
  | "not_found"
  | "cleared";

export interface SignedPhilCore4337UserOperationCollection {
  readonly signedOperations: readonly SignedPhilCore4337UserOperation[];
  readonly count: number;
  readonly maxSignedOperationCount: number;
}

export interface SignedPhilCore4337UserOperationCollectionResult {
  readonly status: SignedPhilCore4337UserOperationCollectionStatus;
  readonly signedOperation?: SignedPhilCore4337UserOperation;
  readonly removedSignedOperation?: SignedPhilCore4337UserOperation;
  readonly evictedSignedOperations?: readonly SignedPhilCore4337UserOperation[];
  readonly collection: SignedPhilCore4337UserOperationCollection;
  readonly reason?: string;
}

export interface SignedPhilCore4337UserOperationStore {
  addSignedOperation(signedOperation: SignedPhilCore4337UserOperation): SignedPhilCore4337UserOperationCollectionResult;
  removeSignedOperation(id: string): SignedPhilCore4337UserOperationCollectionResult;
  clear(): SignedPhilCore4337UserOperationCollectionResult;
  count(): number;
  getById(id: string): SignedPhilCore4337UserOperation | undefined;
  getAll(): readonly SignedPhilCore4337UserOperation[];
}

function nowIso(): string {
  return new Date().toISOString();
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as TValue;
  if (value && typeof value === "object") {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, freezeRecord(nested)])
    )) as TValue;
  }
  return value;
}

function normalizeAddress(value: string): string {
  return getAddress(value);
}

function normalizeHex(value: string, bytes?: number): Hex {
  if (!isHexString(value)) throw new Error("invalid hex");
  const padded = bytes === undefined ? hexlify(value) : zeroPadValue(value, bytes);
  return padded.toLowerCase() as Hex;
}

function operationHash(draft: PhilCorePackedUserOperationDraft): Hex {
  return computePhilCore4337UserOperationHash({
    userOperation: draft.userOperation,
    entryPointAddress: draft.binding.entryPointAddress,
    chainId: draft.binding.chainId
  });
}

function signingError(
  outcome: PhilCore4337SigningAuthorizationOutcome | SignedPhilCore4337UserOperationOutcome,
  errors: readonly string[],
  request: PhilCore4337SigningAuthorizationRequest
): RuntimeResult<never> {
  const auditEventDraft = createSigningAuditDraft({
    outcome,
    summary: "PhilCore ERC-4337 UserOperation signing was rejected.",
    request,
    errors
  });
  request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeDenied({
    code: `PHILCORE_4337_SIGNING_${String(outcome).toUpperCase()}`,
    category: String(outcome).includes("approval")
      ? "user_cancelled"
      : String(outcome).includes("session")
        ? "session_expired"
        : String(outcome).includes("capability")
          ? "capability_denied"
          : "invalid_authorization_package",
    message: "PhilCore ERC-4337 UserOperation signing was rejected.",
    recoverable: true,
    details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
  }, { auditEventId: auditEventDraft.eventDraftId });
}

function createSigningAuditDraft(input: {
  readonly outcome: string;
  readonly summary: string;
  readonly request?: PhilCore4337SigningAuthorizationRequest;
  readonly authorization?: PhilCore4337SigningAuthorizationResultValue;
  readonly signed?: SignedPhilCore4337UserOperation;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  const draft = input.request?.draft ?? input.signed;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.outcome === "signing_authorized" || input.outcome === "user_operation_signed"
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: "requestPhilCore4337UserOperationSigning",
    summary: input.summary,
    auditCorrelationId: input.request?.auditCorrelationId
      ?? input.authorization?.binding.auditCorrelationId
      ?? input.signed?.binding.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      account: input.request?.draft.binding.smartAccountAddress ?? input.signed?.binding.smartAccountAddress,
      entryPoint: input.request?.draft.binding.entryPointAddress ?? input.signed?.binding.entryPointAddress,
      owner: input.request?.draft.binding.owner ?? input.signed?.binding.owner,
      ownerCommitment: input.request?.draft.binding.ownerCommitment ?? input.signed?.binding.ownerCommitment,
      userOperationHash: input.request?.draft.binding.userOperationHash ?? input.signed?.binding.userOperationHash,
      innerCalldataHash: input.request?.draft.binding.innerCalldataHash ?? input.signed?.binding.innerCalldataHash,
      nonce: input.request?.draft.userOperation.nonce ?? input.signed?.userOperation.nonce,
      approvalSource: input.request?.approval.source,
      signature: input.signed ? "present_redacted" : "not_present",
      paymaster: "disabled",
      submitted: false,
      bundlerSubmissionPerformed: false,
      nullifierConsumed: false,
      consumerExecuted: false,
      baseStateMutated: false,
      draftId: "philCorePackedUserOperationDraftId" in (draft ?? {})
        ? (draft as PhilCorePackedUserOperationDraft).philCorePackedUserOperationDraftId
        : undefined
    }
  });
}

export function createPhilCore4337SigningPresentation(
  draft: PhilCorePackedUserOperationDraft
): PhilCore4337SigningPresentationResult {
  const gasLimits = unpackPhilCore4337Uints(draft.userOperation.accountGasLimits);
  const gasFees = unpackPhilCore4337Uints(draft.userOperation.gasFees);
  const presentation: PhilCore4337SigningPresentation = freezeRecord({
    presentationId: createAuditCorrelationId([
      draft.philCorePackedUserOperationDraftId,
      draft.binding.userOperationHash,
      "signing-presentation"
    ]),
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    entryPointAddress: draft.binding.entryPointAddress,
    chainId: draft.binding.chainId,
    smartAccountAddress: draft.binding.smartAccountAddress,
    accountState: draft.accountState,
    factoryAddress: draft.binding.factoryAddress,
    owner: draft.binding.owner,
    ownerCommitment: draft.binding.ownerCommitment,
    actionGateAddress: draft.binding.actionGateAddress,
    innerCalldataHash: draft.binding.innerCalldataHash,
    proofInputHash: draft.binding.proofInputHash,
    nullifier: draft.binding.nullifier,
    capabilityGrantId: draft.binding.authoritativeCapabilityGrantId,
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    value: draft.executionCall.value,
    userOperationHash: draft.binding.userOperationHash,
    nonce: draft.userOperation.nonce,
    verificationGasLimit: gasLimits.high128,
    callGasLimit: gasLimits.low128,
    preVerificationGas: draft.userOperation.preVerificationGas,
    maxPriorityFeePerGas: gasFees.high128,
    maxFeePerGas: gasFees.low128,
    prefundStatus: draft.prefund.status,
    paymasterDisabled: true as const,
    expiresAt: draft.expiresAt,
    auditCorrelationId: draft.binding.auditCorrelationId
  });
  const presentationDigest = keccak256(abiCoder.encode(
    [
      "string",
      "address",
      "uint256",
      "address",
      "address",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint256",
      "bytes32",
      "uint256",
      "bytes32",
      "bytes32"
    ],
    [
      PHILCORE_4337_ENTRYPOINT_VERSION,
      presentation.entryPointAddress,
      presentation.chainId,
      presentation.smartAccountAddress,
      presentation.owner,
      presentation.ownerCommitment,
      presentation.innerCalldataHash,
      presentation.proofInputHash,
      presentation.nullifier,
      BigInt(presentation.nonce),
      presentation.userOperationHash,
      BigInt(presentation.value),
      draft.userOperation.accountGasLimits,
      draft.userOperation.gasFees
    ]
  )) as Hex;
  return freezeRecord({ presentation, presentationDigest });
}

export function createPhilCore4337SigningApprovalArtifact(input: PhilCore4337SigningApprovalRequest): PhilCore4337SigningApprovalArtifact {
  return freezeRecord({
    ...input,
    approvalArtifactId: createAuditCorrelationId([
      input.approvalId,
      input.presentationDigest,
      input.source,
      "philcore-4337-signing-approval"
    ])
  });
}

export function createInMemoryPhilCore4337SigningApprovalStore(): PhilCore4337SigningApprovalStore {
  const consumed = new Set<string>();
  return {
    consumeApproval(approval) {
      const errors: string[] = [];
      if (consumed.has(approval.approvalId) || approval.consumed) {
        return freezeRecord({
          status: "approval_replayed" as const,
          errors: Object.freeze(["approval already consumed"])
        });
      }
      if (new Date(approval.expiresAt).getTime() <= Date.now()) {
        return freezeRecord({
          status: "approval_expired" as const,
          errors: Object.freeze(["approval expired"])
        });
      }
      if (!approval.approved) errors.push("approval rejected");
      if (errors.length > 0) {
        return freezeRecord({
          status: "approval_rejected" as const,
          errors: Object.freeze(errors)
        });
      }
      consumed.add(approval.approvalId);
      return freezeRecord({
        status: "approval_accepted" as const,
        approval,
        errors: Object.freeze([])
      });
    },
    hasConsumed(approvalId) {
      return consumed.has(approvalId);
    },
    clear() {
      consumed.clear();
    }
  };
}

export function validatePhilCore4337SignatureArtifact(
  artifact: PhilCore4337SignatureArtifact
): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = [];
  if (artifact.byteLength !== 65 || dataLength(artifact.signature) !== 65) errors.push("signature must be 65 bytes");
  if (!artifact.lowS) errors.push("signature must be low-s");
  if (![27, 28].includes(artifact.v)) errors.push("signature v must be 27 or 28");
  if (normalizeAddress(artifact.recoveredOwner) !== normalizeAddress(artifact.expectedOwner)) errors.push("recovered owner mismatch");
  if (artifact.privateKeyExposed !== false) errors.push("private key must not be exposed");
  return freezeRecord({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

export function verifyPhilCore4337SignerBinding(input: {
  readonly signature: Hex;
  readonly userOperationHash: Hex;
  readonly expectedOwner: string;
}): PhilCore4337SignatureArtifact {
  const signature = Signature.from(input.signature);
  const rawS = ((signature as unknown as { readonly _s?: string })._s ?? signature.s);
  let recoveredOwner = "0x0000000000000000000000000000000000000000";
  try {
    recoveredOwner = verifyMessage(getBytes(input.userOperationHash), input.signature);
  } catch {
    recoveredOwner = "0x0000000000000000000000000000000000000000";
  }
  const lowS = BigInt(rawS) <= SECP256K1_N_DIV_2;
  return freezeRecord({
    signatureArtifactId: createAuditCorrelationId([
      input.userOperationHash,
      recoveredOwner,
      "philcore-4337-signature"
    ]),
    signature: input.signature,
    signatureFormat: "eth_sign_entrypoint_userop_hash_eip191" as const,
    userOperationHash: input.userOperationHash,
    recoveredOwner: normalizeAddress(recoveredOwner),
    expectedOwner: normalizeAddress(input.expectedOwner),
    v: signature.v,
    r: normalizeHex(signature.r, 32),
    s: normalizeHex(rawS, 32),
    lowS,
    byteLength: dataLength(input.signature),
    privateKeyExposed: false as const
  });
}

export async function requestPhilCore4337SigningAuthorization(
  request: PhilCore4337SigningAuthorizationRequest
): Promise<PhilCore4337SigningAuthorizationRuntimeResult> {
  const errors = await validateSigningRequest(request);
  if (errors.length > 0) return signingError(outcomeForErrors(errors), errors, request);

  const presentationResult = createPhilCore4337SigningPresentation(request.draft);
  if (presentationResult.presentationDigest.toLowerCase() !== request.approval.presentationDigest.toLowerCase()) {
    return signingError("presentation_approval_rejected", ["presentation digest mismatch"], request);
  }
  const approvalResult = request.approvalStore
    ? request.approvalStore.consumeApproval(request.approval)
    : validateApproval(request.approval);
  if (approvalResult.status !== "approval_accepted" || !approvalResult.approval) {
    return signingError(
      approvalResult.status === "approval_replayed"
        ? "presentation_approval_rejected"
        : "presentation_approval_required",
      approvalResult.errors,
      request
    );
  }
  const signerDescriptor = await request.signer.checkAvailability();
  if (!signerDescriptor.available) return signingError("signer_unavailable", ["signer unavailable"], request);
  if (normalizeAddress(signerDescriptor.ownerAddress) !== normalizeAddress(request.draft.binding.owner)) {
    return signingError("owner_mismatch", ["signer owner mismatch"], request);
  }

  const binding = createSigningBinding(request);
  const value: PhilCore4337SigningAuthorizationResultValue = freezeRecord({
    status: "signing_authorized" as const,
    outcome: "signing_authorized" as const,
    binding,
    presentation: presentationResult.presentation,
    presentationDigest: presentationResult.presentationDigest,
    approval: approvalResult.approval,
    signerDescriptor,
    reasons: Object.freeze([
      "runtime_authority_revalidated",
      "account_binding_revalidated",
      "nonce_revalidated",
      "gas_and_fee_revalidated",
      "prefund_revalidated",
      "presentation_approved",
      "signer_bound_to_owner",
      "no_bundler_submission"
    ] satisfies PhilCore4337SigningAuthorizationReason[]),
    limitations: signingLimitations(signerDescriptor)
  });
  const auditEventDraft = createSigningAuditDraft({
    outcome: "signing_authorized",
    summary: "PhilCore ERC-4337 UserOperation signing authorization was created.",
    request,
    authorization: value
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeOk(freezeRecord({ ...value, auditEventDraft, auditDraftCollectionResult }), {
    auditEventId: auditEventDraft.eventDraftId
  });
}

export async function signPhilCore4337UserOperation(
  request: PhilCore4337UserOperationSigningRequest
): Promise<SignedPhilCore4337UserOperationResult> {
  const authorizationResult = await requestPhilCore4337SigningAuthorization(request);
  if (authorizationResult.status !== "approved" || !authorizationResult.value) {
    return runtimeDenied(authorizationResult.error ?? {
      code: "PHILCORE_4337_SIGNING_SIGNING_REJECTED",
      category: "invalid_authorization_package",
      message: "PhilCore ERC-4337 signing authorization was rejected.",
      recoverable: true
    });
  }
  const authorization = authorizationResult.value;
  const signingResult = await request.signer.signUserOperationHash({
    userOperationHash: authorization.binding.userOperationHash,
    presentationDigest: authorization.presentationDigest,
    expectedOwner: authorization.binding.owner,
    chainId: authorization.binding.chainId,
    entryPointAddress: authorization.binding.entryPointAddress,
    smartAccountAddress: authorization.binding.smartAccountAddress,
    nonce: authorization.binding.nonce,
    callDataHash: authorization.binding.callDataHash,
    auditCorrelationId: authorization.binding.auditCorrelationId
  });
  if (signingResult.status !== "signed" || !signingResult.signature) {
    return signingError("signer_unavailable", signingResult.errors ?? ["signer did not produce a signature"], request);
  }
  const signatureArtifact = verifyPhilCore4337SignerBinding({
    signature: signingResult.signature,
    userOperationHash: authorization.binding.userOperationHash,
    expectedOwner: authorization.binding.owner
  });
  const signatureValidation = validatePhilCore4337SignatureArtifact(signatureArtifact);
  if (!signatureValidation.valid) return signingError("signature_invalid", signatureValidation.errors, request);

  const userOperation: PhilCorePackedUserOperation = freezeRecord({
    ...request.draft.userOperation,
    signature: signingResult.signature
  });
  const signedBase = {
    signedPhilCore4337UserOperationId: createAuditCorrelationId([
      request.draft.philCorePackedUserOperationDraftId,
      authorization.binding.userOperationHash,
      "signed"
    ]),
    status: "user_operation_signed" as const,
    outcome: "user_operation_signed" as const,
    binding: {
      ...authorization.binding,
      presentationDigest: authorization.presentationDigest,
      approvalId: authorization.approval.approvalId,
      signerId: authorization.signerDescriptor.signerId,
      signatureArtifactId: signatureArtifact.signatureArtifactId
    },
    userOperation,
    signatureArtifact,
    signerDescriptor: authorization.signerDescriptor,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    limitations: authorization.limitations,
    userOperationSigned: true as const,
    userOperationSubmitted: false as const,
    bundlerSubmissionPerformed: false as const,
    paymasterInvoked: false as const,
    smartAccountDeploymentPerformed: false as const,
    nullifierConsumed: false as const,
    consumerExecuted: false as const,
    baseStateMutated: false as const,
    applicationCanSubmitDirectly: false as const
  };
  const auditEventDraft = createSigningAuditDraft({
    outcome: "user_operation_signed",
    summary: "PhilCore ERC-4337 UserOperation was signed; it remains unsubmitted.",
    request,
    signed: signedBase as SignedPhilCore4337UserOperation
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const signed = freezeRecord({
    ...signedBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as SignedPhilCore4337UserOperation;
  const collectionResult = request.signedOperationStore?.addSignedOperation(signed);
  return runtimeOk(collectionResult
    ? freezeRecord({ ...signed, collectionResult }) as SignedPhilCore4337UserOperation
    : signed, { auditEventId: auditEventDraft.eventDraftId });
}

export const requestPhilCore4337UserOperationSigning = signPhilCore4337UserOperation;

export function inspectSignedPhilCore4337UserOperation(
  signed: SignedPhilCore4337UserOperation
): Readonly<Record<string, unknown>> {
  return freezeRecord({
    signedPhilCore4337UserOperationId: signed.signedPhilCore4337UserOperationId,
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    sender: signed.userOperation.sender,
    nonce: signed.userOperation.nonce,
    userOperationHash: signed.binding.userOperationHash,
    signaturePresent: signed.userOperation.signature !== PHILCORE_4337_EMPTY_BYTES,
    recoveredOwner: signed.signatureArtifact.recoveredOwner,
    userOperationSigned: signed.userOperationSigned,
    userOperationSubmitted: signed.userOperationSubmitted,
    bundlerSubmissionPerformed: signed.bundlerSubmissionPerformed,
    paymasterInvoked: signed.paymasterInvoked,
    nullifierConsumed: signed.nullifierConsumed,
    consumerExecuted: signed.consumerExecuted,
    baseStateMutated: signed.baseStateMutated,
    applicationCanSubmitDirectly: signed.applicationCanSubmitDirectly
  });
}

async function validateSigningRequest(
  request: PhilCore4337SigningAuthorizationRequest
): Promise<readonly string[]> {
  const errors: string[] = [];
  const draftValidation = validatePhilCore4337UserOperationDraft(request.draft);
  if (!draftValidation.valid) errors.push(...draftValidation.errors);
  if (new Date(request.expiresAt).getTime() <= Date.now()) errors.push("signing request expired");
  if (new Date(request.draft.expiresAt).getTime() <= Date.now()) errors.push("UserOperation draft expired");
  if (request.foundation.acpStatus !== "Proposed") errors.push("ACP-0002 must remain proposed");
  if (request.foundation.entryPoint.version !== PHILCORE_4337_ENTRYPOINT_VERSION) errors.push("EntryPoint version mismatch");
  if (normalizeAddress(request.foundation.entryPoint.address) !== normalizeAddress(request.draft.binding.entryPointAddress)) errors.push("EntryPoint mismatch");
  if (normalizeAddress(request.foundation.validator.owner) !== normalizeAddress(request.draft.binding.owner)) errors.push("owner mismatch");
  if (request.foundation.validator.ownerCommitment.toLowerCase() !== request.draft.binding.ownerCommitment.toLowerCase()) errors.push("ownerCommitment mismatch");
  if (request.draft.userOperation.paymasterAndData !== PHILCORE_4337_EMPTY_BYTES) errors.push("paymaster data not allowed");
  if (request.draft.userOperation.signature !== PHILCORE_4337_EMPTY_BYTES) errors.push("draft signature must be empty");
  const computedHash = operationHash(request.draft);
  if (computedHash.toLowerCase() !== request.draft.binding.userOperationHash.toLowerCase()) errors.push("UserOperation hash mismatch");

  validateAuthority(request.runtimeAuthority, errors);
  const nonce = await request.nonceReader.readNonce({
    entryPointAddress: request.draft.binding.entryPointAddress,
    accountAddress: request.draft.binding.smartAccountAddress,
    nonceKey: "0",
    chainId: request.draft.binding.chainId
  });
  if (nonce.status !== "resolved" || nonce.nonce !== request.draft.userOperation.nonce) errors.push("nonce changed");
  if (request.gasEstimator) {
    const gas = await request.gasEstimator.estimateUserOperationGas({
      userOperation: request.draft.userOperation,
      entryPointAddress: request.draft.binding.entryPointAddress,
      chainId: request.draft.binding.chainId
    });
    compareGas(gas, request.draft.gas, errors);
  }
  if (request.prefundReader) {
    const prefund = await request.prefundReader.readPrefundRequirement({
      userOperation: request.draft.userOperation,
      entryPointAddress: request.draft.binding.entryPointAddress,
      chainId: request.draft.binding.chainId
    });
    comparePrefund(prefund, request.draft.prefund, errors);
  }
  if (request.accountStateReader && request.draft.accountState === "deployed") {
    const verification = await verifyPhilCore4337Account({
      request: {
        accountAddress: request.draft.binding.smartAccountAddress,
        expectedEntryPoint: request.draft.binding.entryPointAddress,
        expectedOwner: request.draft.binding.owner,
        expectedOwnerCommitment: request.draft.binding.ownerCommitment,
        expectedApprovedActionGate: request.draft.binding.actionGateAddress,
        expectedChainId: request.draft.binding.chainId,
        configurationApproved: request.foundation.status === "local_fixture" || request.foundation.status === "approved"
      },
      reader: request.accountStateReader
    });
    if (verification.outcome !== "account_verified") errors.push(...verification.errors);
  }
  return Object.freeze(errors);
}

function validateAuthority(
  authority: PhilCore4337SigningRuntimeAuthoritySnapshot,
  errors: string[]
): void {
  if (authority.capabilityGrantStatus !== "active") errors.push("capability ineligible");
  if (authority.sessionStatus !== "eligible") errors.push("session ineligible");
  if (authority.platformApprovalStatus !== "valid") errors.push("platform approval ineligible");
  if (authority.baseExecutionApprovalStatus !== "valid") errors.push("base execution approval ineligible");
  if (authority.finalizedPackageStatus !== "valid") errors.push("package ineligible");
  if (authority.mirroredFactStatus !== "present") errors.push("mirrored fact ineligible");
  if (authority.nullifierStatus !== "available") errors.push("nullifier unavailable");
}

function compareGas(
  fresh: PhilCoreUserOperationGasEstimateResult,
  draftGas: PhilCoreUserOperationGasEstimateResult,
  errors: string[]
): void {
  if (fresh.status === "failed") errors.push("gas estimation failed");
  if (fresh.callGasLimit && draftGas.callGasLimit && fresh.callGasLimit !== draftGas.callGasLimit) errors.push("gas changed");
  if (fresh.verificationGasLimit && draftGas.verificationGasLimit && fresh.verificationGasLimit !== draftGas.verificationGasLimit) errors.push("gas changed");
  if (fresh.preVerificationGas && draftGas.preVerificationGas && fresh.preVerificationGas !== draftGas.preVerificationGas) errors.push("gas changed");
  if (fresh.maxFeePerGas && draftGas.maxFeePerGas && fresh.maxFeePerGas !== draftGas.maxFeePerGas) errors.push("fee changed");
  if (fresh.maxPriorityFeePerGas && draftGas.maxPriorityFeePerGas && fresh.maxPriorityFeePerGas !== draftGas.maxPriorityFeePerGas) errors.push("fee changed");
}

function comparePrefund(
  fresh: PhilCore4337PrefundRequirement,
  draftPrefund: PhilCore4337PrefundRequirement,
  errors: string[]
): void {
  if (fresh.status === "prefund_insufficient") errors.push("prefund insufficient");
  if (fresh.requiredPrefund !== draftPrefund.requiredPrefund) errors.push("prefund changed");
}

function validateApproval(approval: PhilCore4337SigningApprovalArtifact): PhilCore4337SigningApprovalResult {
  if (new Date(approval.expiresAt).getTime() <= Date.now()) {
    return freezeRecord({ status: "approval_expired" as const, errors: Object.freeze(["approval expired"]) });
  }
  if (!approval.approved || approval.consumed) {
    return freezeRecord({ status: approval.consumed ? "approval_replayed" as const : "approval_rejected" as const, errors: Object.freeze(["approval rejected"]) });
  }
  return freezeRecord({ status: "approval_accepted" as const, approval, errors: Object.freeze([]) });
}

function createSigningBinding(request: PhilCore4337SigningAuthorizationRequest): PhilCore4337SigningAuthorizationBinding {
  return freezeRecord({
    draftId: request.draft.philCorePackedUserOperationDraftId,
    userOperationHash: request.draft.binding.userOperationHash,
    smartAccountAddress: request.draft.binding.smartAccountAddress,
    owner: request.draft.binding.owner,
    ownerCommitment: request.draft.binding.ownerCommitment,
    entryPointAddress: request.draft.binding.entryPointAddress,
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    factoryAddress: request.draft.binding.factoryAddress,
    actionGateAddress: request.draft.binding.actionGateAddress,
    chainId: request.draft.binding.chainId,
    nonce: request.draft.userOperation.nonce,
    callDataHash: keccak256(request.draft.userOperation.callData) as Hex,
    innerCalldataHash: request.draft.binding.innerCalldataHash,
    accountGasLimits: request.draft.userOperation.accountGasLimits,
    gasFees: request.draft.userOperation.gasFees,
    capabilityGrantId: request.draft.binding.authoritativeCapabilityGrantId,
    sessionId: request.draft.binding.sessionId,
    finalizedAuthorizationPackageId: request.draft.binding.finalizedAuthorizationPackageId,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId
  });
}

function signingLimitations(
  descriptor: PhilCore4337ValidatorSignerDescriptor
): readonly PhilCore4337SigningLimitation[] {
  const limitations: PhilCore4337SigningLimitation[] = [
    "acp_0002_proposed",
    "signed_but_unsubmitted",
    "paymaster_disabled",
    "session_keys_disabled",
    "requires_future_bundler_boundary"
  ];
  if (descriptor.mode !== "device_vault_beta_ecdsa") limitations.push("device_vault_custody_not_implemented");
  if (descriptor.mode === "developer_fixture" || descriptor.mode === "operator_fixture") limitations.push("developer_fixture_only");
  return Object.freeze(limitations);
}

function outcomeForErrors(errors: readonly string[]): PhilCore4337SigningAuthorizationOutcome {
  const joined = errors.join(" ").toLowerCase();
  if (joined.includes("capability")) return "capability_ineligible";
  if (joined.includes("session")) return "session_ineligible";
  if (joined.includes("package")) return "package_ineligible";
  if (joined.includes("mirrored fact")) return "mirrored_fact_ineligible";
  if (joined.includes("nullifier")) return "nullifier_unavailable";
  if (joined.includes("ownercommitment")) return "owner_commitment_mismatch";
  if (joined.includes("owner")) return "owner_mismatch";
  if (joined.includes("entrypoint")) return "entry_point_mismatch";
  if (joined.includes("nonce")) return "nonce_changed";
  if (joined.includes("gas")) return "gas_changed";
  if (joined.includes("fee")) return "fee_changed";
  if (joined.includes("prefund")) return "prefund_insufficient";
  if (joined.includes("approval")) return "presentation_approval_required";
  if (joined.includes("expired")) return "expired";
  return "runtime_authority_ineligible";
}

export function createInMemorySignedPhilCore4337UserOperationStore(
  options: { readonly maxSignedOperationCount?: number } = {}
): SignedPhilCore4337UserOperationStore {
  const maxSignedOperationCount = Math.max(1, Math.floor(options.maxSignedOperationCount ?? 25));
  const signedOperations = new Map<string, SignedPhilCore4337UserOperation>();
  const all = () => Object.freeze(Array.from(signedOperations.values()));
  const collection = (): SignedPhilCore4337UserOperationCollection => Object.freeze({
    signedOperations: all(),
    count: signedOperations.size,
    maxSignedOperationCount
  });
  return {
    addSignedOperation(signedOperation) {
      if (signedOperations.has(signedOperation.signedPhilCore4337UserOperationId)) {
        return freezeRecord({
          status: "rejected_duplicate" as const,
          signedOperation: signedOperations.get(signedOperation.signedPhilCore4337UserOperationId),
          collection: collection(),
          reason: "duplicate signed UserOperation id"
        });
      }
      const evictedSignedOperations: SignedPhilCore4337UserOperation[] = [];
      while (signedOperations.size >= maxSignedOperationCount) {
        const oldest = signedOperations.keys().next().value as string | undefined;
        if (!oldest) break;
        const evicted = signedOperations.get(oldest);
        signedOperations.delete(oldest);
        if (evicted) evictedSignedOperations.push(evicted);
      }
      const stored = freezeRecord(signedOperation);
      signedOperations.set(stored.signedPhilCore4337UserOperationId, stored);
      return freezeRecord({
        status: evictedSignedOperations.length > 0 ? "evicted_oldest" as const : "collected" as const,
        signedOperation: stored,
        evictedSignedOperations: Object.freeze(evictedSignedOperations),
        collection: collection()
      });
    },
    removeSignedOperation(id) {
      const removedSignedOperation = signedOperations.get(id);
      if (!removedSignedOperation) {
        return freezeRecord({ status: "not_found" as const, collection: collection(), reason: "signed operation not found" });
      }
      signedOperations.delete(id);
      return freezeRecord({ status: "removed" as const, removedSignedOperation, collection: collection() });
    },
    clear() {
      signedOperations.clear();
      return freezeRecord({ status: "cleared" as const, collection: collection() });
    },
    count() {
      return signedOperations.size;
    },
    getById(id) {
      return signedOperations.get(id);
    },
    getAll() {
      return all();
    }
  };
}
