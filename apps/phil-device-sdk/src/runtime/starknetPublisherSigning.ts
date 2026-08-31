import { createHash } from "node:crypto";
import {
  EDataAvailabilityMode,
  ETransactionVersion3,
  Signer,
  constants,
  ec,
  hash as starknetHash,
  shortString,
  transaction as starknetTransaction
} from "starknet";
import type { Call, Signature } from "starknet";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import {
  type StarknetFactPublicationTransactionDraft,
  type StarknetNonceReader,
  validateStarknetFactPublicationTransactionDraft
} from "./starknetFactPublicationPreparation.ts";
import type { RuntimeResult } from "./types.ts";

const ENTRYPOINT = "verify_proof_input_hash_slice_and_send_to_l1";
const FELT_MAX = (1n << 252n) - 1n;

export type StarknetPublisherMode =
  | "infrastructure_operator"
  | "permissionless_external_publisher"
  | "user_controlled_starknet_account"
  | "sponsored_publisher"
  | "developer_fixture"
  | "unsupported";

export interface StarknetPublisherModeProfile {
  readonly mode: StarknetPublisherMode;
  readonly accountOwner: string;
  readonly signerOwner: string;
  readonly feePayer: string;
  readonly submissionActor: string;
  readonly availabilityExpectation: string;
  readonly censorshipExposure: string;
  readonly userConsentRequirement: string;
  readonly runtimeControlsSigner: boolean;
  readonly productionSuitability:
    | "recommended_initial_beta"
    | "candidate"
    | "development_only"
    | "not_recommended"
    | "unsupported";
}

export const STARKNET_PUBLISHER_MODE_PROFILES: readonly StarknetPublisherModeProfile[] = Object.freeze([
  Object.freeze({
    mode: "infrastructure_operator",
    accountOwner: "PhilCore-operated or delegated proof-publication infrastructure",
    signerOwner: "isolated publisher signer boundary",
    feePayer: "infrastructure operator",
    submissionActor: "future Starknet publication adapter or operator service",
    availabilityExpectation: "high availability once testnet operations exist",
    censorshipExposure: "operator availability and policy censorship risk",
    userConsentRequirement: "bounded infrastructure policy approval for proof-fact publication",
    runtimeControlsSigner: false,
    productionSuitability: "recommended_initial_beta"
  }),
  Object.freeze({
    mode: "permissionless_external_publisher",
    accountOwner: "external publisher",
    signerOwner: "external publisher",
    feePayer: "external publisher",
    submissionActor: "external publisher",
    availabilityExpectation: "best effort",
    censorshipExposure: "external publisher availability risk",
    userConsentRequirement: "policy-bound authorization to publish this exact fact",
    runtimeControlsSigner: false,
    productionSuitability: "candidate"
  }),
  Object.freeze({
    mode: "user_controlled_starknet_account",
    accountOwner: "user",
    signerOwner: "user wallet or external signer",
    feePayer: "user",
    submissionActor: "future user Starknet wallet path",
    availabilityExpectation: "depends on user wallet",
    censorshipExposure: "wallet availability and user fee funding",
    userConsentRequirement: "explicit user approval for Starknet fee spend",
    runtimeControlsSigner: false,
    productionSuitability: "not_recommended"
  }),
  Object.freeze({
    mode: "sponsored_publisher",
    accountOwner: "sponsor or paymaster-like infrastructure",
    signerOwner: "sponsor signer boundary",
    feePayer: "sponsor",
    submissionActor: "future sponsored publisher",
    availabilityExpectation: "depends on sponsor policy",
    censorshipExposure: "sponsor policy risk",
    userConsentRequirement: "bounded publisher policy approval",
    runtimeControlsSigner: false,
    productionSuitability: "candidate"
  }),
  Object.freeze({
    mode: "developer_fixture",
    accountOwner: "local deterministic fixture",
    signerOwner: "local deterministic fixture key",
    feePayer: "fixture",
    submissionActor: "none in M.6A.4",
    availabilityExpectation: "tests and diagnostics only",
    censorshipExposure: "not applicable",
    userConsentRequirement: "developer fixture approval only",
    runtimeControlsSigner: false,
    productionSuitability: "development_only"
  }),
  Object.freeze({
    mode: "unsupported",
    accountOwner: "unresolved",
    signerOwner: "unresolved",
    feePayer: "unresolved",
    submissionActor: "unresolved",
    availabilityExpectation: "none",
    censorshipExposure: "unbounded",
    userConsentRequirement: "unsupported",
    runtimeControlsSigner: false,
    productionSuitability: "unsupported"
  })
]);

export type StarknetPublisherAuthorizationStatus =
  | "publisher_authorized"
  | "publisher_rejected"
  | "publisher_malformed";

export type StarknetPublisherAuthorizationOutcome =
  | "publisher_authorized"
  | "publisher_not_authorized"
  | "account_mismatch"
  | "network_mismatch"
  | "publication_contract_mismatch"
  | "transaction_draft_ineligible"
  | "fee_policy_violation"
  | "nonce_policy_violation"
  | "approval_required"
  | "approval_rejected"
  | "signer_unavailable"
  | "expired"
  | "malformed"
  | "unsupported";

export type StarknetPublisherAuthorizationReason =
  | "exact_publication_transaction_authorized"
  | "draft_or_binding_rejected"
  | "approval_missing_or_rejected"
  | "publisher_policy_rejected"
  | "freshness_rejected";

export interface StarknetPublisherIdentity {
  readonly publisherId: string;
  readonly mode: StarknetPublisherMode;
  readonly displayName: string;
  readonly expectedSignerPublicKey?: string;
  readonly productionSuitable: boolean;
}

export interface StarknetPublisherAccountBinding {
  readonly accountAddress: string;
  readonly networkProfileId: string;
  readonly chainId: string;
  readonly publicationContractAddress: string;
  readonly entrypoint: typeof ENTRYPOINT;
  readonly calldataHash: string;
}

export interface StarknetV3ResourceBound {
  readonly max_amount: string;
  readonly max_price_per_unit: string;
}

export interface StarknetInvokeV3ResourceBounds {
  readonly l1_gas: StarknetV3ResourceBound;
  readonly l2_gas: StarknetV3ResourceBound;
  readonly l1_data_gas: StarknetV3ResourceBound;
}

export interface StarknetPublisherPolicy {
  readonly allowedModes: readonly StarknetPublisherMode[];
  readonly allowedNetworkProfileIds: readonly string[];
  readonly allowedPublicationContractAddresses: readonly string[];
  readonly allowedFeeToken: string;
  readonly maxOverallFee: string;
  readonly maxResourceBounds: StarknetInvokeV3ResourceBounds;
  readonly allowMainnet: boolean;
  readonly allowedApprovalSources: readonly StarknetPublicationSigningApprovalSource[];
  readonly requireFreshNonce: true;
  readonly requireFreshFee: true;
}

export type StarknetPublicationSigningApprovalSource =
  | "automated_infrastructure_policy"
  | "operator_approval"
  | "publisher_service_authorization"
  | "developer_fixture_approval";

export interface StarknetPublisherApprovalRequirement {
  readonly source: StarknetPublicationSigningApprovalSource;
  readonly presentationDigest: string;
  readonly approved: boolean;
  readonly approvedAt: string;
  readonly expiresAt: string;
  readonly approvalId: string;
}

export type StarknetPublisherAuthorizationLimitation =
  | "publisher_authorization_only"
  | "no_submission_authority"
  | "nonce_not_reserved"
  | "fee_revalidation_required_before_submission"
  | "not_application_signing_authority";

export interface StarknetPublisherAuthorizationRequest {
  readonly transactionDraft: StarknetFactPublicationTransactionDraft;
  readonly publisherIdentity: StarknetPublisherIdentity;
  readonly accountBinding: StarknetPublisherAccountBinding;
  readonly policy: StarknetPublisherPolicy;
  readonly approval?: StarknetPublisherApprovalRequirement;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
}

export interface StarknetPublisherAuthorizationResult {
  readonly status: StarknetPublisherAuthorizationStatus;
  readonly outcome: StarknetPublisherAuthorizationOutcome;
  readonly reason: StarknetPublisherAuthorizationReason;
  readonly publisherIdentity: StarknetPublisherIdentity;
  readonly accountBinding: StarknetPublisherAccountBinding;
  readonly limitations: readonly StarknetPublisherAuthorizationLimitation[];
  readonly auditCorrelationId: string;
  readonly errors: readonly string[];
}

export interface StarknetPublisherSignerDescriptor {
  readonly signerId: string;
  readonly signerKind:
    | "local_encrypted_operator_key"
    | "hardware_or_os_key"
    | "remote_hsm"
    | "developer_fixture";
  readonly mode: StarknetPublisherMode;
  readonly accountAddress: string;
  readonly publicKey?: string;
  readonly productionSuitable: boolean;
  readonly arbitrarySigningSupported: false;
  readonly submissionSupported: false;
}

export interface StarknetPublisherSignerAvailability {
  readonly available: boolean;
  readonly reason?: string;
}

export interface StarknetPublisherAccountReference {
  readonly accountAddress: string;
  readonly publicKey?: string;
}

export interface StarknetPublisherSigningRequest {
  readonly transactionDraft: StarknetFactPublicationTransactionDraft;
  readonly transactionHash: string;
  readonly signingPresentationDigest: string;
  readonly accountBinding: StarknetPublisherAccountBinding;
  readonly calls: readonly Call[];
  readonly signerDetails: StarknetInvokeV3SignerDetails;
  readonly approval: StarknetPublisherApprovalRequirement;
}

export type StarknetPublisherSigningStatus =
  | "signed"
  | "rejected"
  | "failed";

export interface StarknetPublisherSigningResult {
  readonly status: StarknetPublisherSigningStatus;
  readonly transactionHash: string;
  readonly signature?: StarknetTransactionSignature;
  readonly signerDescriptor?: StarknetPublisherSignerDescriptor;
  readonly signerPublicKey?: string;
  readonly error?: string;
}

export interface StarknetTransactionSignature {
  readonly r: string;
  readonly s: string;
  readonly recovery?: number;
  readonly felts: readonly [string, string];
}

export interface StarknetPublisherSignatureArtifact {
  readonly transactionHash: string;
  readonly signature: StarknetTransactionSignature;
  readonly signerId: string;
  readonly signerPublicKey?: string;
  readonly signerAccountAddress: string;
  readonly exactHashSigned: true;
  readonly privateKeyExposed: false;
}

export interface StarknetPublisherSigner {
  describeSigner(): StarknetPublisherSignerDescriptor;
  checkAvailability(): StarknetPublisherSignerAvailability;
  getAccountReference(): StarknetPublisherAccountReference;
  signPublicationTransaction(
    request: StarknetPublisherSigningRequest
  ): Promise<StarknetPublisherSigningResult>;
  invalidateSigningSession(): void;
}

export type StarknetSigningNonceStatus =
  | "nonce_fresh"
  | "nonce_stale"
  | "nonce_unresolved"
  | "nonce_reader_unavailable";

export interface StarknetSigningNonceValidation {
  readonly status: StarknetSigningNonceStatus;
  readonly draftNonce?: string;
  readonly freshNonce?: string;
  readonly readAt: string;
  readonly blockReference?: string;
  readonly revalidateBeforeSubmission: true;
}

export type StarknetSigningFeeStatus =
  | "fee_fresh"
  | "fee_stale"
  | "fee_limit_exceeded"
  | "fee_token_rejected"
  | "resource_bounds_widened"
  | "fee_unresolved";

export interface StarknetSigningFeeValidation {
  readonly status: StarknetSigningFeeStatus;
  readonly feeToken: string;
  readonly estimatedFee: string;
  readonly maxOverallFee: string;
  readonly resourceBounds: StarknetInvokeV3ResourceBounds;
  readonly checkedAt: string;
  readonly freshUntil?: string;
  readonly revalidateBeforeSubmission: true;
}

export interface StarknetPublicationSigningPresentation {
  readonly networkProfileId: string;
  readonly chainId: string;
  readonly publisherAccount: string;
  readonly publicationContract: string;
  readonly entrypoint: typeof ENTRYPOINT;
  readonly calldataHash: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly l1Recipient: string;
  readonly nonce: string;
  readonly feeToken: string;
  readonly maxOverallFee: string;
  readonly resourceBounds: StarknetInvokeV3ResourceBounds;
  readonly transactionExpiresAt: string;
  readonly auditCorrelationId: string;
}

export interface StarknetPublicationSigningPresentationDigest {
  readonly digest: string;
  readonly algorithm: "sha256-json-v1";
  readonly presentation: StarknetPublicationSigningPresentation;
}

export interface StarknetInvokeV3SignerDetails {
  readonly walletAddress: string;
  readonly chainId: string;
  readonly cairoVersion: "1";
  readonly version: "0x3";
  readonly nonce: string;
  readonly resourceBounds: StarknetInvokeV3ResourceBounds;
  readonly tip: string;
  readonly paymasterData: readonly string[];
  readonly accountDeploymentData: readonly string[];
  readonly nonceDataAvailabilityMode: "L1" | "L2";
  readonly feeDataAvailabilityMode: "L1" | "L2";
}

export interface StarknetInvokeV3HashInput {
  readonly calls: readonly Call[];
  readonly signerDetails: StarknetInvokeV3SignerDetails;
}

export interface StarknetSignedTransactionBinding {
  readonly transactionDraftId: string;
  readonly publisherId: string;
  readonly accountAddress: string;
  readonly networkProfileId: string;
  readonly chainId: string;
  readonly publicationContractAddress: string;
  readonly entrypoint: typeof ENTRYPOINT;
  readonly calldataHash: string;
  readonly proofInputHash: string;
  readonly factHigh: string;
  readonly factLow: string;
  readonly l1Recipient: string;
  readonly nonce: string;
  readonly resourceBounds: StarknetInvokeV3ResourceBounds;
  readonly approvalId: string;
  readonly signingPresentationDigest: string;
  readonly auditCorrelationId: string;
}

export type SignedStarknetFactPublicationStatus =
  | "transaction_signed"
  | "transaction_signing_rejected"
  | "transaction_signing_malformed";

export type SignedStarknetFactPublicationOutcome =
  | "transaction_signed"
  | StarknetPublisherAuthorizationOutcome
  | "nonce_stale"
  | "nonce_unresolved"
  | "fee_stale"
  | "fee_limit_exceeded"
  | "resource_bounds_widened"
  | "presentation_digest_mismatch"
  | "transaction_mutation_detected"
  | "transaction_hash_mismatch"
  | "malformed_signature"
  | "wrong_signer";

export type StarknetSignedTransactionLimitation =
  | "signed_but_unsubmitted"
  | "not_submittable_by_applications"
  | "nonce_must_be_revalidated_before_submission"
  | "fee_must_be_revalidated_before_submission"
  | "message_not_emitted"
  | "no_l1_or_base_behavior";

export interface SignedStarknetFactPublicationTransaction {
  readonly signedStarknetFactPublicationTransactionId: string;
  readonly status: "transaction_signed";
  readonly outcome: "transaction_signed";
  readonly binding: StarknetSignedTransactionBinding;
  readonly transactionHash: string;
  readonly signatureArtifact: StarknetPublisherSignatureArtifact;
  readonly signerDescriptor: StarknetPublisherSignerDescriptor;
  readonly signedAt: string;
  readonly expiresAt: string;
  readonly limitations: readonly StarknetSignedTransactionLimitation[];
  readonly transactionSigned: true;
  readonly transactionSubmitted: false;
  readonly factVerifiedOnStarknet: false;
  readonly l2ToL1MessageEmitted: false;
  readonly l1MessageConsumed: false;
  readonly chainStateMutated: false;
  readonly submissionAllowedByApplications: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: SignedStarknetPublicationTransactionCollectionResult;
}

export type SignedStarknetFactPublicationResult =
  RuntimeResult<SignedStarknetFactPublicationTransaction>;

export interface StarknetFactPublicationSigningRequest {
  readonly requestId: string;
  readonly transactionDraft: StarknetFactPublicationTransactionDraft;
  readonly publisherIdentity: StarknetPublisherIdentity;
  readonly accountBinding: StarknetPublisherAccountBinding;
  readonly policy: StarknetPublisherPolicy;
  readonly approval?: StarknetPublisherApprovalRequirement;
  readonly signer: StarknetPublisherSigner;
  readonly nonceReader: StarknetNonceReader;
  readonly feeValidation: {
    readonly feeToken: string;
    readonly estimatedFee: string;
    readonly freshUntil: string;
    readonly resourceBounds: StarknetInvokeV3ResourceBounds;
  };
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly signedTransactionStore?: SignedStarknetPublicationTransactionStore;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type SignedStarknetPublicationTransactionCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "removed"
  | "not_found"
  | "cleared";

export interface SignedStarknetPublicationTransactionCollectionResult {
  readonly status: SignedStarknetPublicationTransactionCollectionStatus;
  readonly artifact?: SignedStarknetFactPublicationTransaction;
  readonly removedArtifact?: SignedStarknetFactPublicationTransaction;
  readonly evictedArtifacts?: readonly SignedStarknetFactPublicationTransaction[];
  readonly collection: {
    readonly artifacts: readonly SignedStarknetFactPublicationTransaction[];
    readonly count: number;
    readonly maxArtifactCount: number;
  };
}

export interface SignedStarknetPublicationTransactionStore {
  addArtifact(
    artifact: SignedStarknetFactPublicationTransaction
  ): SignedStarknetPublicationTransactionCollectionResult;
  removeArtifact(
    artifactId: string
  ): SignedStarknetPublicationTransactionCollectionResult;
  clear(): SignedStarknetPublicationTransactionCollectionResult;
  count(): number;
  getById(artifactId: string): SignedStarknetFactPublicationTransaction | undefined;
  getAll(): readonly SignedStarknetFactPublicationTransaction[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function validation(errors: string[]): RuntimeValidationResult {
  return { valid: errors.length === 0, errors };
}

function normalizeHex(value: string): string {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  const normalized = raw.replace(/^0+/, "") || "0";
  return `0x${normalized.toLowerCase()}`;
}

function isFelt(value: unknown): value is string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) return false;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && parsed <= FELT_MAX;
  } catch {
    return false;
  }
}

function isNonZeroFelt(value: unknown): value is string {
  return isFelt(value) && BigInt(value) !== 0n;
}

function nowIso(): string {
  return new Date().toISOString();
}

function sha256Json(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function toBigInt(value: string): bigint {
  return BigInt(value);
}

function compareBigNumberish(a: string, b: string): number {
  const left = toBigInt(a);
  const right = toBigInt(b);
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function multiplyHex(a: string, b: string): bigint {
  return toBigInt(a) * toBigInt(b);
}

function totalFee(resourceBounds: StarknetInvokeV3ResourceBounds): bigint {
  return multiplyHex(resourceBounds.l1_gas.max_amount, resourceBounds.l1_gas.max_price_per_unit)
    + multiplyHex(resourceBounds.l1_data_gas.max_amount, resourceBounds.l1_data_gas.max_price_per_unit)
    + multiplyHex(resourceBounds.l2_gas.max_amount, resourceBounds.l2_gas.max_price_per_unit);
}

function resourceBoundsWithin(
  actual: StarknetInvokeV3ResourceBounds,
  allowed: StarknetInvokeV3ResourceBounds
): boolean {
  for (const key of ["l1_gas", "l2_gas", "l1_data_gas"] as const) {
    if (compareBigNumberish(actual[key].max_amount, allowed[key].max_amount) > 0) return false;
    if (compareBigNumberish(actual[key].max_price_per_unit, allowed[key].max_price_per_unit) > 0) {
      return false;
    }
  }
  return true;
}

function validateResourceBounds(resourceBounds: StarknetInvokeV3ResourceBounds): string[] {
  const errors: string[] = [];
  for (const key of ["l1_gas", "l2_gas", "l1_data_gas"] as const) {
    if (!isFelt(resourceBounds[key]?.max_amount)) errors.push(`${key}.max_amount invalid`);
    if (!isFelt(resourceBounds[key]?.max_price_per_unit)) {
      errors.push(`${key}.max_price_per_unit invalid`);
    }
  }
  return errors;
}

function daModeToStarknet(mode: "L1" | "L2"): EDataAvailabilityMode {
  return mode === "L1" ? EDataAvailabilityMode.L1 : EDataAvailabilityMode.L2;
}

function daModeToHashNumber(mode: "L1" | "L2"): 0 | 1 {
  return mode === "L1" ? 0 : 1;
}

export function starknetChainIdToFelt(chainId: string): string {
  if (chainId === "SN_MAIN") return constants.StarknetChainId.SN_MAIN;
  if (chainId === "SN_SEPOLIA") return constants.StarknetChainId.SN_SEPOLIA;
  if (chainId.startsWith("0x")) return normalizeHex(chainId);
  return shortString.encodeShortString(chainId);
}

function toStarknetResourceBounds(resourceBounds: StarknetInvokeV3ResourceBounds) {
  return {
    l1_gas: {
      max_amount: toBigInt(resourceBounds.l1_gas.max_amount),
      max_price_per_unit: toBigInt(resourceBounds.l1_gas.max_price_per_unit)
    },
    l2_gas: {
      max_amount: toBigInt(resourceBounds.l2_gas.max_amount),
      max_price_per_unit: toBigInt(resourceBounds.l2_gas.max_price_per_unit)
    },
    l1_data_gas: {
      max_amount: toBigInt(resourceBounds.l1_data_gas.max_amount),
      max_price_per_unit: toBigInt(resourceBounds.l1_data_gas.max_price_per_unit)
    }
  };
}

export function validateStarknetInvokeV3HashInput(
  input: StarknetInvokeV3HashInput
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!Array.isArray(input.calls) || input.calls.length !== 1) {
    errors.push("exactly one call is required");
  }
  const call = input.calls[0];
  if (!call?.contractAddress || !isNonZeroFelt(call.contractAddress)) {
    errors.push("call contract address invalid");
  }
  if (call?.entrypoint !== ENTRYPOINT) errors.push("call entrypoint mismatch");
  const calldata = call?.calldata;
  if (!Array.isArray(calldata) || calldata.length === 0) errors.push("call calldata missing");
  if (Array.isArray(calldata) && !calldata.every(isFelt)) errors.push("call calldata contains non-felt");
  const details = input.signerDetails;
  if (!isNonZeroFelt(details.walletAddress)) errors.push("wallet address invalid");
  if (!isFelt(starknetChainIdToFelt(details.chainId))) errors.push("chain id invalid");
  if (details.version !== ETransactionVersion3.V3) errors.push("version must be 0x3");
  if (!isFelt(details.nonce)) errors.push("nonce invalid");
  errors.push(...validateResourceBounds(details.resourceBounds));
  if (!["L1", "L2"].includes(details.nonceDataAvailabilityMode)) {
    errors.push("nonce DA mode invalid");
  }
  if (!["L1", "L2"].includes(details.feeDataAvailabilityMode)) {
    errors.push("fee DA mode invalid");
  }
  if (!isFelt(details.tip)) errors.push("tip invalid");
  if (!details.paymasterData.every(isFelt)) errors.push("paymaster data invalid");
  if (!details.accountDeploymentData.every(isFelt)) errors.push("account deployment data invalid");
  return validation(errors);
}

export function computeUnsignedStarknetInvokeV3Hash(
  input: StarknetInvokeV3HashInput
): string {
  const validationResult = validateStarknetInvokeV3HashInput(input);
  if (!validationResult.valid) {
    throw new Error(`Invalid Starknet invoke v3 hash input: ${validationResult.errors.join("; ")}`);
  }
  const compiledCalldata = starknetTransaction.getExecuteCalldata(
    [...input.calls],
    input.signerDetails.cairoVersion
  );
  return starknetHash.calculateInvokeTransactionHash({
    senderAddress: input.signerDetails.walletAddress,
    version: input.signerDetails.version,
    compiledCalldata,
    chainId: starknetChainIdToFelt(input.signerDetails.chainId) as never,
    nonce: input.signerDetails.nonce,
    accountDeploymentData: [...input.signerDetails.accountDeploymentData],
    nonceDataAvailabilityMode: daModeToHashNumber(input.signerDetails.nonceDataAvailabilityMode),
    feeDataAvailabilityMode: daModeToHashNumber(input.signerDetails.feeDataAvailabilityMode),
    resourceBounds: toStarknetResourceBounds(input.signerDetails.resourceBounds),
    tip: input.signerDetails.tip,
    paymasterData: [...input.signerDetails.paymasterData]
  });
}

export function validateStarknetTransactionHashBinding(
  input: StarknetInvokeV3HashInput,
  expectedHash: string
): RuntimeValidationResult {
  const errors: string[] = [];
  let actualHash: string | undefined;
  try {
    actualHash = computeUnsignedStarknetInvokeV3Hash(input);
  } catch (error) {
    errors.push(error instanceof Error ? error.message : "hash computation failed");
  }
  if (actualHash && normalizeHex(actualHash) !== normalizeHex(expectedHash)) {
    errors.push("transaction hash mismatch");
  }
  return validation(errors);
}

export function createStarknetPublicationSigningPresentation(
  input: {
    readonly transactionDraft: StarknetFactPublicationTransactionDraft;
    readonly accountBinding: StarknetPublisherAccountBinding;
    readonly feeValidation: StarknetSigningFeeValidation;
    readonly auditCorrelationId: string;
  }
): StarknetPublicationSigningPresentationDigest {
  const draft = input.transactionDraft;
  const presentation: StarknetPublicationSigningPresentation = Object.freeze({
    networkProfileId: input.accountBinding.networkProfileId,
    chainId: input.accountBinding.chainId,
    publisherAccount: normalizeHex(input.accountBinding.accountAddress),
    publicationContract: normalizeHex(input.accountBinding.publicationContractAddress),
    entrypoint: ENTRYPOINT,
    calldataHash: draft.call.calldataHash,
    proofInputHash: draft.binding.proofInputHash,
    factHigh: draft.binding.factHigh,
    factLow: draft.binding.factLow,
    l1Recipient: draft.messagePreview.destinationL1Address,
    nonce: draft.unsignedInvokeTransaction.nonce.nonce ?? "unresolved",
    feeToken: input.feeValidation.feeToken,
    maxOverallFee: input.feeValidation.maxOverallFee,
    resourceBounds: input.feeValidation.resourceBounds,
    transactionExpiresAt: draft.expiresAt,
    auditCorrelationId: input.auditCorrelationId
  });
  return Object.freeze({
    digest: sha256Json(presentation),
    algorithm: "sha256-json-v1",
    presentation
  });
}

export function validateStarknetPublisherAuthorizationRequest(
  request: StarknetPublisherAuthorizationRequest
): RuntimeValidationResult {
  const errors: string[] = [];
  const draftValidation = validateStarknetFactPublicationTransactionDraft(request.transactionDraft);
  errors.push(...draftValidation.errors);
  if (request.transactionDraft.transactionSigned !== false) errors.push("draft already signed");
  if (sha256Json(request.transactionDraft.call.calldata) !== request.transactionDraft.call.calldataHash) {
    errors.push("transaction mutation detected");
  }
  if (Date.now() > Date.parse(request.transactionDraft.expiresAt)) errors.push("transaction draft expired");
  if (Number.isNaN(Date.parse(request.issueTime))) errors.push("issueTime must be a date");
  if (Number.isNaN(Date.parse(request.expiresAt))) errors.push("expiresAt must be a date");
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("publisher authorization request expired");
  if (!request.publisherIdentity.publisherId) errors.push("publisherId is required");
  if (!request.policy.allowedModes.includes(request.publisherIdentity.mode)) {
    errors.push("publisher mode not allowed");
  }
  if (request.publisherIdentity.mode === "unsupported") errors.push("publisher mode unsupported");
  if (
    request.accountBinding.accountAddress
    && request.transactionDraft.account.accountAddress
    && normalizeHex(request.accountBinding.accountAddress) !== normalizeHex(request.transactionDraft.account.accountAddress)
  ) {
    errors.push("publisher account mismatch");
  }
  if (request.accountBinding.networkProfileId !== request.transactionDraft.binding.configProfileId) {
    errors.push("network mismatch");
  }
  if (!request.policy.allowedNetworkProfileIds.includes(request.accountBinding.networkProfileId)) {
    errors.push("network not allowed by policy");
  }
  if (
    request.accountBinding.networkProfileId.includes("mainnet")
    && request.policy.allowMainnet !== true
  ) {
    errors.push("mainnet signing not allowed by policy");
  }
  if (normalizeHex(request.accountBinding.publicationContractAddress) !== normalizeHex(request.transactionDraft.call.contractAddress)) {
    errors.push("publication contract mismatch");
  }
  if (
    !request.policy.allowedPublicationContractAddresses
      .map(normalizeHex)
      .includes(normalizeHex(request.accountBinding.publicationContractAddress))
  ) {
    errors.push("publication contract not allowed by policy");
  }
  if (request.accountBinding.entrypoint !== ENTRYPOINT) errors.push("entrypoint mismatch");
  if (request.accountBinding.calldataHash !== request.transactionDraft.call.calldataHash) {
    errors.push("calldata hash mismatch");
  }
  if (!request.approval) {
    errors.push("signing approval required");
  } else {
    if (!request.approval.approved) errors.push("signing approval rejected");
    if (!request.policy.allowedApprovalSources.includes(request.approval.source)) {
      errors.push("approval source not allowed");
    }
    if (Date.now() > Date.parse(request.approval.expiresAt)) errors.push("signing approval expired");
    if (Number.isNaN(Date.parse(request.approval.approvedAt))) {
      errors.push("approval timestamp invalid");
    }
  }
  return validation(errors);
}

function authorizationOutcomeForErrors(
  errors: readonly string[]
): StarknetPublisherAuthorizationOutcome {
  const joined = errors.join(" | ");
  if (joined.includes("account")) return "account_mismatch";
  if (joined.includes("network") || joined.includes("mainnet")) return "network_mismatch";
  if (joined.includes("publication contract")) return "publication_contract_mismatch";
  if (joined.includes("draft")) return "transaction_draft_ineligible";
  if (joined.includes("approval required")) return "approval_required";
  if (joined.includes("approval rejected")) return "approval_rejected";
  if (joined.includes("approval")) return "approval_rejected";
  if (joined.includes("expired")) return "expired";
  if (joined.includes("unsupported") || joined.includes("mode")) return "unsupported";
  return "malformed";
}

export function authorizeStarknetPublisher(
  request: StarknetPublisherAuthorizationRequest
): StarknetPublisherAuthorizationResult {
  const auditCorrelationId = request.auditCorrelationId
    ?? createAuditCorrelationId([
      request.transactionDraft.starknetFactPublicationTransactionDraftId,
      request.publisherIdentity.publisherId,
      "starknet-publisher-authorization"
    ]);
  const validationResult = validateStarknetPublisherAuthorizationRequest(request);
  if (!validationResult.valid) {
    return Object.freeze({
      status: "publisher_rejected",
      outcome: authorizationOutcomeForErrors(validationResult.errors),
      reason: "draft_or_binding_rejected",
      publisherIdentity: request.publisherIdentity,
      accountBinding: request.accountBinding,
      limitations: Object.freeze([
        "publisher_authorization_only",
        "no_submission_authority",
        "not_application_signing_authority"
      ] satisfies readonly StarknetPublisherAuthorizationLimitation[]),
      auditCorrelationId,
      errors: Object.freeze(validationResult.errors)
    });
  }
  return Object.freeze({
    status: "publisher_authorized",
    outcome: "publisher_authorized",
    reason: "exact_publication_transaction_authorized",
    publisherIdentity: request.publisherIdentity,
    accountBinding: request.accountBinding,
    limitations: Object.freeze([
      "publisher_authorization_only",
      "no_submission_authority",
      "nonce_not_reserved",
      "fee_revalidation_required_before_submission",
      "not_application_signing_authority"
    ] satisfies readonly StarknetPublisherAuthorizationLimitation[]),
    auditCorrelationId,
    errors: Object.freeze([])
  });
}

export function validateSigningNonceFreshness(
  draft: StarknetFactPublicationTransactionDraft,
  nonceReader: StarknetNonceReader
): StarknetSigningNonceValidation {
  const readAt = nowIso();
  const accountAddress = draft.account.accountAddress;
  if (!accountAddress || draft.unsignedInvokeTransaction.nonce.status !== "resolved") {
    return Object.freeze({
      status: "nonce_unresolved",
      draftNonce: draft.unsignedInvokeTransaction.nonce.nonce,
      readAt,
      revalidateBeforeSubmission: true
    });
  }
  const readResult = nonceReader.readNonce({
    accountAddress,
    networkProfileId: draft.binding.configProfileId
  });
  if (readResult.status !== "resolved" || !readResult.nonce) {
    return Object.freeze({
      status: "nonce_reader_unavailable",
      draftNonce: draft.unsignedInvokeTransaction.nonce.nonce,
      readAt,
      revalidateBeforeSubmission: true
    });
  }
  if (readResult.freshUntil && Date.now() > Date.parse(readResult.freshUntil)) {
    return Object.freeze({
      status: "nonce_stale",
      draftNonce: draft.unsignedInvokeTransaction.nonce.nonce,
      freshNonce: readResult.nonce,
      readAt,
      revalidateBeforeSubmission: true
    });
  }
  return Object.freeze({
    status: normalizeHex(readResult.nonce) === normalizeHex(draft.unsignedInvokeTransaction.nonce.nonce ?? "")
      ? "nonce_fresh"
      : "nonce_stale",
    draftNonce: draft.unsignedInvokeTransaction.nonce.nonce,
    freshNonce: normalizeHex(readResult.nonce),
    readAt,
    revalidateBeforeSubmission: true
  });
}

export function validateSigningFeeFreshness(
  input: {
    readonly draft: StarknetFactPublicationTransactionDraft;
    readonly policy: StarknetPublisherPolicy;
    readonly feeToken: string;
    readonly estimatedFee: string;
    readonly freshUntil: string;
    readonly resourceBounds: StarknetInvokeV3ResourceBounds;
  }
): StarknetSigningFeeValidation {
  const checkedAt = nowIso();
  const base = {
    feeToken: input.feeToken,
    estimatedFee: input.estimatedFee,
    maxOverallFee: input.policy.maxOverallFee,
    resourceBounds: input.resourceBounds,
    checkedAt,
    freshUntil: input.freshUntil,
    revalidateBeforeSubmission: true as const
  };
  if (input.feeToken !== input.policy.allowedFeeToken) {
    return Object.freeze({ ...base, status: "fee_token_rejected" });
  }
  if (Date.now() > Date.parse(input.freshUntil)) {
    return Object.freeze({ ...base, status: "fee_stale" });
  }
  if (input.draft.unsignedInvokeTransaction.fee.status !== "estimated") {
    return Object.freeze({ ...base, status: "fee_unresolved" });
  }
  if (input.draft.unsignedInvokeTransaction.fee.estimatedFee !== input.estimatedFee) {
    return Object.freeze({ ...base, status: "fee_stale" });
  }
  if (!resourceBoundsWithin(input.resourceBounds, input.policy.maxResourceBounds)) {
    return Object.freeze({ ...base, status: "resource_bounds_widened" });
  }
  if (totalFee(input.resourceBounds) > toBigInt(input.policy.maxOverallFee)) {
    return Object.freeze({ ...base, status: "fee_limit_exceeded" });
  }
  return Object.freeze({ ...base, status: "fee_fresh" });
}

function signingOutcomeFor(
  input: {
    readonly authorization?: StarknetPublisherAuthorizationResult;
    readonly nonce?: StarknetSigningNonceValidation;
    readonly fee?: StarknetSigningFeeValidation;
    readonly signerAvailability?: StarknetPublisherSignerAvailability;
    readonly errors?: readonly string[];
  }
): SignedStarknetFactPublicationOutcome {
  if (input.authorization && input.authorization.status !== "publisher_authorized") {
    return input.authorization.outcome;
  }
  if (input.nonce?.status === "nonce_stale") return "nonce_stale";
  if (input.nonce?.status === "nonce_unresolved") return "nonce_unresolved";
  if (input.nonce?.status === "nonce_reader_unavailable") return "nonce_unresolved";
  if (input.fee?.status === "fee_stale") return "fee_stale";
  if (input.fee?.status === "fee_limit_exceeded") return "fee_limit_exceeded";
  if (input.fee?.status === "resource_bounds_widened") return "resource_bounds_widened";
  if (input.fee && input.fee.status !== "fee_fresh") return "fee_policy_violation";
  if (input.signerAvailability && !input.signerAvailability.available) return "signer_unavailable";
  const joined = input.errors?.join(" | ") ?? "";
  if (joined.includes("presentation")) return "presentation_digest_mismatch";
  if (joined.includes("hash")) return "transaction_hash_mismatch";
  if (joined.includes("signature")) return "malformed_signature";
  if (joined.includes("signer")) return "wrong_signer";
  if (joined.includes("mutation")) return "transaction_mutation_detected";
  return "malformed";
}

function createSigningAuditDraft(
  input: {
    readonly request: StarknetFactPublicationSigningRequest;
    readonly outcome: SignedStarknetFactPublicationOutcome;
    readonly transactionHash?: string;
    readonly errors?: readonly string[];
  }
): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.outcome === "transaction_signed" ? "validation_succeeded" : "validation_failed",
    requestKind: "requestStarknetFactPublicationTransactionSigning",
    applicationId: "proof-publication",
    sessionId: input.request.transactionDraft.binding.finalizedAuthorizationPackageId,
    summary: input.outcome === "transaction_signed"
      ? "Signed but unsubmitted Starknet fact-publication transaction artifact created."
      : "Starknet fact-publication transaction signing rejected.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      publisherAccount: input.request.accountBinding.accountAddress,
      network: input.request.accountBinding.networkProfileId,
      publicationContract: input.request.accountBinding.publicationContractAddress,
      entrypoint: ENTRYPOINT,
      calldataHash: input.request.transactionDraft.call.calldataHash,
      transactionHash: input.transactionHash,
      proofInputHash: input.request.transactionDraft.binding.proofInputHash,
      nonce: input.request.transactionDraft.unsignedInvokeTransaction.nonce.nonce,
      feeToken: input.request.feeValidation.feeToken,
      estimatedFee: input.request.feeValidation.estimatedFee
    }
  });
}

function callsFromDraft(draft: StarknetFactPublicationTransactionDraft): readonly Call[] {
  return Object.freeze([
    {
      contractAddress: draft.call.contractAddress,
      entrypoint: draft.call.entrypoint,
      calldata: [...draft.call.calldata]
    }
  ]);
}

function signerDetailsFromRequest(
  request: StarknetFactPublicationSigningRequest
): StarknetInvokeV3SignerDetails {
  return Object.freeze({
    walletAddress: normalizeHex(request.accountBinding.accountAddress),
    chainId: request.accountBinding.chainId,
    cairoVersion: "1",
    version: ETransactionVersion3.V3,
    nonce: normalizeHex(request.transactionDraft.unsignedInvokeTransaction.nonce.nonce ?? "0x0"),
    resourceBounds: request.feeValidation.resourceBounds,
    tip: "0x0",
    paymasterData: Object.freeze([]),
    accountDeploymentData: Object.freeze([]),
    nonceDataAvailabilityMode: "L1",
    feeDataAvailabilityMode: "L1"
  });
}

function signatureToArtifact(
  signature: StarknetTransactionSignature,
  result: StarknetPublisherSigningResult
): StarknetPublisherSignatureArtifact | undefined {
  if (!result.signerDescriptor) return undefined;
  return Object.freeze({
    transactionHash: result.transactionHash,
    signature,
    signerId: result.signerDescriptor.signerId,
    signerPublicKey: result.signerPublicKey,
    signerAccountAddress: result.signerDescriptor.accountAddress,
    exactHashSigned: true,
    privateKeyExposed: false
  });
}

export async function signStarknetFactPublicationTransaction(
  request: StarknetFactPublicationSigningRequest
): Promise<SignedStarknetFactPublicationResult> {
  const errors: string[] = [];
  if (!request.requestId) errors.push("requestId is required");
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("signing request expired");
  const auditCorrelationId = request.auditCorrelationId
    ?? createAuditCorrelationId([
      request.transactionDraft.starknetFactPublicationTransactionDraftId,
      "starknet-publication-signing"
    ]);

  if (errors.length > 0) {
    const auditEventDraft = createSigningAuditDraft({
      request,
      outcome: "expired",
      errors
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SIGNING_REJECTED",
      category: "unsupported_operation",
      message: "Starknet fact-publication transaction signing was rejected.",
      recoverable: true,
      details: { outcome: "expired", errors, auditEventId: auditEventDraft.eventDraftId }
    });
  }

  const nonceValidation = validateSigningNonceFreshness(
    request.transactionDraft,
    request.nonceReader
  );
  const feeValidation = validateSigningFeeFreshness({
    draft: request.transactionDraft,
    policy: request.policy,
    feeToken: request.feeValidation.feeToken,
    estimatedFee: request.feeValidation.estimatedFee,
    freshUntil: request.feeValidation.freshUntil,
    resourceBounds: request.feeValidation.resourceBounds
  });

  const presentation = createStarknetPublicationSigningPresentation({
    transactionDraft: request.transactionDraft,
    accountBinding: request.accountBinding,
    feeValidation,
    auditCorrelationId
  });

  const authorization = authorizeStarknetPublisher({
    transactionDraft: request.transactionDraft,
    publisherIdentity: request.publisherIdentity,
    accountBinding: request.accountBinding,
    policy: request.policy,
    approval: request.approval,
    issueTime: request.issueTime,
    expiresAt: request.expiresAt,
    auditCorrelationId
  });
  if (
    authorization.status !== "publisher_authorized"
    || nonceValidation.status !== "nonce_fresh"
    || feeValidation.status !== "fee_fresh"
  ) {
    const outcome = signingOutcomeFor({ authorization, nonce: nonceValidation, fee: feeValidation });
    const rejectionErrors = [
      ...authorization.errors,
      nonceValidation.status,
      feeValidation.status
    ].filter((item) => item !== "nonce_fresh" && item !== "fee_fresh");
    const auditEventDraft = createSigningAuditDraft({
      request: { ...request, auditCorrelationId },
      outcome,
      errors: rejectionErrors
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SIGNING_REJECTED",
      category: "unsupported_operation",
      message: "Starknet fact-publication transaction signing was rejected.",
      recoverable: true,
      details: { outcome, errors: rejectionErrors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  if (!request.approval || request.approval.presentationDigest !== presentation.digest) {
    const outcome = "presentation_digest_mismatch";
    const auditEventDraft = createSigningAuditDraft({
      request: { ...request, auditCorrelationId },
      outcome,
      errors: ["signing approval presentation digest mismatch"]
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SIGNING_REJECTED",
      category: "policy_denied",
      message: "Signing approval did not match the immutable transaction presentation.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }

  const calls = callsFromDraft(request.transactionDraft);
  const signerDetails = signerDetailsFromRequest(request);
  const transactionHash = computeUnsignedStarknetInvokeV3Hash({ calls, signerDetails });
  const signerAvailability = request.signer.checkAvailability();
  if (!signerAvailability.available) {
    const outcome = signingOutcomeFor({ signerAvailability });
    const auditEventDraft = createSigningAuditDraft({
      request: { ...request, auditCorrelationId },
      outcome,
      transactionHash,
      errors: [signerAvailability.reason ?? "signer unavailable"]
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SIGNING_REJECTED",
      category: "adapter_unavailable",
      message: "Publisher signer is unavailable.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }

  const signerDescriptor = request.signer.describeSigner();
  const signerAccount = request.signer.getAccountReference();
  const signerErrors: string[] = [];
  if (normalizeHex(signerDescriptor.accountAddress) !== normalizeHex(request.accountBinding.accountAddress)) {
    signerErrors.push("signer account mismatch");
  }
  if (normalizeHex(signerAccount.accountAddress) !== normalizeHex(request.accountBinding.accountAddress)) {
    signerErrors.push("signer account reference mismatch");
  }
  if (
    request.publisherIdentity.expectedSignerPublicKey
    && signerDescriptor.publicKey
    && normalizeHex(request.publisherIdentity.expectedSignerPublicKey) !== normalizeHex(signerDescriptor.publicKey)
  ) {
    signerErrors.push("signer public key mismatch");
  }
  if (signerDescriptor.submissionSupported !== false || signerDescriptor.arbitrarySigningSupported !== false) {
    signerErrors.push("signer exposes unsupported authority");
  }
  if (signerErrors.length > 0) {
    const outcome = "wrong_signer";
    const auditEventDraft = createSigningAuditDraft({
      request: { ...request, auditCorrelationId },
      outcome,
      transactionHash,
      errors: signerErrors
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SIGNING_REJECTED",
      category: "trust_denied",
      message: "Publisher signer binding was rejected.",
      recoverable: true,
      details: { outcome, errors: signerErrors, auditEventId: auditEventDraft.eventDraftId }
    });
  }

  const signingResult = await request.signer.signPublicationTransaction({
    transactionDraft: request.transactionDraft,
    transactionHash,
    signingPresentationDigest: presentation.digest,
    accountBinding: request.accountBinding,
    calls,
    signerDetails,
    approval: request.approval
  });
  if (
    signingResult.status !== "signed"
    || !signingResult.signature
    || normalizeHex(signingResult.transactionHash) !== normalizeHex(transactionHash)
  ) {
    const signingErrors = [
      signingResult.error ?? "signing rejected",
      normalizeHex(signingResult.transactionHash) !== normalizeHex(transactionHash)
        ? "signed hash mismatch"
        : undefined
    ].filter((item): item is string => Boolean(item));
    const outcome = signingOutcomeFor({ errors: signingErrors });
    const auditEventDraft = createSigningAuditDraft({
      request: { ...request, auditCorrelationId },
      outcome,
      transactionHash,
      errors: signingErrors
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SIGNING_REJECTED",
      category: "proof_failed",
      message: "Publisher signer did not produce a valid bounded signature artifact.",
      recoverable: true,
      details: { outcome, errors: signingErrors, auditEventId: auditEventDraft.eventDraftId }
    });
  }
  if (!isFelt(signingResult.signature.r) || !isFelt(signingResult.signature.s)) {
    const outcome = "malformed_signature";
    const auditEventDraft = createSigningAuditDraft({
      request: { ...request, auditCorrelationId },
      outcome,
      transactionHash,
      errors: ["signature felts invalid"]
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SIGNING_REJECTED",
      category: "proof_failed",
      message: "Publisher signer produced a malformed signature.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }

  const signatureArtifact = signatureToArtifact(signingResult.signature, signingResult);
  if (!signatureArtifact) {
    const outcome = "wrong_signer";
    const auditEventDraft = createSigningAuditDraft({
      request: { ...request, auditCorrelationId },
      outcome,
      transactionHash,
      errors: ["signer descriptor missing from signing result"]
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_SIGNING_REJECTED",
      category: "trust_denied",
      message: "Publisher signer descriptor was missing.",
      recoverable: true,
      details: { outcome, auditEventId: auditEventDraft.eventDraftId }
    });
  }

  const signedAt = nowIso();
  const auditEventDraft = createSigningAuditDraft({
    request: { ...request, auditCorrelationId },
    outcome: "transaction_signed",
    transactionHash
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const artifactBase: SignedStarknetFactPublicationTransaction = Object.freeze({
    signedStarknetFactPublicationTransactionId: createAuditCorrelationId([
      request.transactionDraft.starknetFactPublicationTransactionDraftId,
      transactionHash,
      "signed-starknet-publication"
    ]),
    status: "transaction_signed",
    outcome: "transaction_signed",
    binding: Object.freeze({
      transactionDraftId: request.transactionDraft.starknetFactPublicationTransactionDraftId,
      publisherId: request.publisherIdentity.publisherId,
      accountAddress: normalizeHex(request.accountBinding.accountAddress),
      networkProfileId: request.accountBinding.networkProfileId,
      chainId: request.accountBinding.chainId,
      publicationContractAddress: normalizeHex(request.accountBinding.publicationContractAddress),
      entrypoint: ENTRYPOINT,
      calldataHash: request.transactionDraft.call.calldataHash,
      proofInputHash: request.transactionDraft.binding.proofInputHash,
      factHigh: request.transactionDraft.binding.factHigh,
      factLow: request.transactionDraft.binding.factLow,
      l1Recipient: request.transactionDraft.messagePreview.destinationL1Address,
      nonce: request.transactionDraft.unsignedInvokeTransaction.nonce.nonce ?? "unresolved",
      resourceBounds: feeValidation.resourceBounds,
      approvalId: request.approval.approvalId,
      signingPresentationDigest: presentation.digest,
      auditCorrelationId
    }),
    transactionHash,
    signatureArtifact,
    signerDescriptor,
    signedAt,
    expiresAt: request.expiresAt,
    limitations: Object.freeze([
      "signed_but_unsubmitted",
      "not_submittable_by_applications",
      "nonce_must_be_revalidated_before_submission",
      "fee_must_be_revalidated_before_submission",
      "message_not_emitted",
      "no_l1_or_base_behavior"
    ] satisfies readonly StarknetSignedTransactionLimitation[]),
    transactionSigned: true,
    transactionSubmitted: false,
    factVerifiedOnStarknet: false,
    l2ToL1MessageEmitted: false,
    l1MessageConsumed: false,
    chainStateMutated: false,
    submissionAllowedByApplications: false,
    auditEventDraft,
    auditDraftCollectionResult
  });
  const collectionResult = request.signedTransactionStore?.addArtifact(artifactBase);
  return runtimeOk(Object.freeze({
    ...artifactBase,
    collectionResult
  }));
}

export const requestStarknetFactPublicationTransactionSigning =
  signStarknetFactPublicationTransaction;

function toSignatureArtifact(signature: Signature): StarknetTransactionSignature {
  const sig = signature as Signature & { r?: bigint; s?: bigint; recovery?: number };
  if (sig.r === undefined || sig.s === undefined) {
    throw new Error("Unsupported Starknet signature shape");
  }
  const r = normalizeHex(`0x${sig.r.toString(16)}`);
  const s = normalizeHex(`0x${sig.s.toString(16)}`);
  return Object.freeze({
    r,
    s,
    recovery: typeof sig.recovery === "number" ? sig.recovery : undefined,
    felts: Object.freeze([r, s]) as readonly [string, string]
  });
}

export function createFixtureStarknetPublisherSigner(
  input: {
    readonly privateKey: string;
    readonly accountAddress: string;
    readonly signerId?: string;
    readonly allowedNetworkProfileIds?: readonly string[];
  }
): StarknetPublisherSigner {
  const signer = new Signer(input.privateKey);
  const publicKey = normalizeHex(ec.starkCurve.getStarkKey(input.privateKey));
  const allowedNetworkProfileIds = input.allowedNetworkProfileIds ?? ["local_devnet"];
  let invalidated = false;
  return {
    describeSigner() {
      return Object.freeze({
        signerId: input.signerId ?? "developer-fixture-starknet-publisher-signer",
        signerKind: "developer_fixture",
        mode: "developer_fixture",
        accountAddress: normalizeHex(input.accountAddress),
        publicKey,
        productionSuitable: false,
        arbitrarySigningSupported: false,
        submissionSupported: false
      });
    },
    checkAvailability() {
      return Object.freeze({
        available: !invalidated,
        reason: invalidated ? "fixture signing session invalidated" : undefined
      });
    },
    getAccountReference() {
      return Object.freeze({
        accountAddress: normalizeHex(input.accountAddress),
        publicKey
      });
    },
    async signPublicationTransaction(request) {
      if (invalidated) {
        return Object.freeze({
          status: "failed",
          transactionHash: request.transactionHash,
          error: "fixture signing session invalidated"
        });
      }
      if (!allowedNetworkProfileIds.includes(request.accountBinding.networkProfileId)) {
        return Object.freeze({
          status: "rejected",
          transactionHash: request.transactionHash,
          signerDescriptor: this.describeSigner(),
          signerPublicKey: publicKey,
          error: "fixture signer cannot sign this network profile"
        });
      }
      if (request.accountBinding.networkProfileId.includes("mainnet")) {
        return Object.freeze({
          status: "rejected",
          transactionHash: request.transactionHash,
          signerDescriptor: this.describeSigner(),
          signerPublicKey: publicKey,
          error: "fixture signer cannot sign mainnet profiles"
        });
      }
      const signature = await signer.signTransaction([...request.calls], {
        walletAddress: normalizeHex(input.accountAddress),
        chainId: starknetChainIdToFelt(request.signerDetails.chainId) as never,
        cairoVersion: request.signerDetails.cairoVersion,
        version: request.signerDetails.version,
        nonce: request.signerDetails.nonce,
        resourceBounds: toStarknetResourceBounds(request.signerDetails.resourceBounds),
        tip: request.signerDetails.tip,
        paymasterData: [...request.signerDetails.paymasterData],
        accountDeploymentData: [...request.signerDetails.accountDeploymentData],
        nonceDataAvailabilityMode: daModeToStarknet(request.signerDetails.nonceDataAvailabilityMode),
        feeDataAvailabilityMode: daModeToStarknet(request.signerDetails.feeDataAvailabilityMode)
      });
      return Object.freeze({
        status: "signed",
        transactionHash: request.transactionHash,
        signature: toSignatureArtifact(signature),
        signerDescriptor: this.describeSigner(),
        signerPublicKey: publicKey
      });
    },
    invalidateSigningSession() {
      invalidated = true;
    }
  };
}

function freezeSignedArtifact(
  artifact: SignedStarknetFactPublicationTransaction
): SignedStarknetFactPublicationTransaction {
  return Object.freeze({
    ...artifact,
    binding: Object.freeze({ ...artifact.binding }),
    signatureArtifact: Object.freeze({
      ...artifact.signatureArtifact,
      signature: Object.freeze({
        ...artifact.signatureArtifact.signature,
        felts: Object.freeze([...artifact.signatureArtifact.signature.felts]) as readonly [string, string]
      })
    }),
    limitations: Object.freeze([...artifact.limitations])
  });
}

export function createInMemorySignedStarknetPublicationTransactionStore(
  options: { readonly maxArtifactCount?: number } = {}
): SignedStarknetPublicationTransactionStore {
  const maxArtifactCount = Math.max(1, Math.floor(options.maxArtifactCount ?? 25));
  const artifacts = new Map<string, SignedStarknetFactPublicationTransaction>();
  function collection() {
    return Object.freeze({
      artifacts: Object.freeze(Array.from(artifacts.values()).map(freezeSignedArtifact)),
      count: artifacts.size,
      maxArtifactCount
    });
  }
  return {
    addArtifact(artifact) {
      if (artifacts.has(artifact.signedStarknetFactPublicationTransactionId)) {
        return {
          status: "rejected_duplicate",
          artifact: freezeSignedArtifact(artifact),
          collection: collection()
        };
      }
      const evictedArtifacts: SignedStarknetFactPublicationTransaction[] = [];
      while (artifacts.size >= maxArtifactCount) {
        const firstKey = artifacts.keys().next().value as string | undefined;
        if (!firstKey) break;
        const evicted = artifacts.get(firstKey);
        artifacts.delete(firstKey);
        if (evicted) evictedArtifacts.push(evicted);
      }
      artifacts.set(artifact.signedStarknetFactPublicationTransactionId, freezeSignedArtifact(artifact));
      return {
        status: evictedArtifacts.length > 0 ? "evicted_oldest" : "collected",
        artifact: freezeSignedArtifact(artifact),
        evictedArtifacts: Object.freeze(evictedArtifacts.map(freezeSignedArtifact)),
        collection: collection()
      };
    },
    removeArtifact(artifactId) {
      const removedArtifact = artifacts.get(artifactId);
      artifacts.delete(artifactId);
      return {
        status: removedArtifact ? "removed" : "not_found",
        removedArtifact: removedArtifact ? freezeSignedArtifact(removedArtifact) : undefined,
        collection: collection()
      };
    },
    clear() {
      artifacts.clear();
      return { status: "cleared", collection: collection() };
    },
    count() {
      return artifacts.size;
    },
    getById(artifactId) {
      const artifact = artifacts.get(artifactId);
      return artifact ? freezeSignedArtifact(artifact) : undefined;
    },
    getAll() {
      return collection().artifacts;
    }
  };
}
