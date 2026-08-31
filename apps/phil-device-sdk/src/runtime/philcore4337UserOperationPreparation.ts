import {
  AbiCoder,
  Interface,
  concat,
  dataLength,
  getAddress,
  hexlify,
  isHexString,
  keccak256,
  toBeHex,
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
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  type BaseAuthorizationExecutionTransactionDraft
} from "./baseAuthorizationExecutionPreparation.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk
} from "./helpers.ts";
import type { RuntimeResult } from "./types.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const accountInterface = new Interface([
  "function execute(address target,uint256 value,bytes data)",
  "function entryPoint() view returns (address)",
  "function owner() view returns (address)",
  "function ownerCommitment() view returns (bytes32)",
  "function approvedActionGate() view returns (address)"
]);
const factoryInterface = new Interface([
  "function createAccount(address owner,bytes32 ownerCommitment,uint256 salt) returns (address)",
  "function getAddress(address owner,bytes32 ownerCommitment,uint256 salt) view returns (address)"
]);

export const PHILCORE_4337_ENTRYPOINT_VERSION = "0.7" as const;
export const PHILCORE_4337_EXECUTE_SELECTOR =
  accountInterface.getFunction("execute")?.selector as "0xb61d27f6";
export const PHILCORE_4337_FACTORY_CREATE_ACCOUNT_SELECTOR =
  factoryInterface.getFunction("createAccount")?.selector as "0x5fbfb9cf";
export const PHILCORE_4337_EMPTY_BYTES = "0x" as Hex;

export type PhilCore4337FoundationStatus =
  | "proposed"
  | "local_fixture"
  | "predeployment"
  | "approved"
  | "disabled";

export interface PhilCore4337NetworkProfile {
  readonly profileId: string;
  readonly chainId: number;
  readonly networkName: string;
  readonly liveNetwork: boolean;
  readonly productionApproved: boolean;
}

export interface PhilCore4337EntryPointConfiguration {
  readonly version: typeof PHILCORE_4337_ENTRYPOINT_VERSION;
  readonly address: string;
  readonly packageName: "@account-abstraction/contracts";
  readonly packageVersion: "0.7.0";
}

export interface PhilCore4337AccountConfiguration {
  readonly contractName: "PhilCore4337Account";
  readonly executeSelector: typeof PHILCORE_4337_EXECUTE_SELECTOR;
  readonly directOwnerExecuteAllowed: false;
  readonly entryPointExecuteAllowed: true;
  readonly selfExecuteAllowed: false;
  readonly approvedActionGate: string;
  readonly allowedTarget: "approved_action_gate";
  readonly allowedSelector: typeof BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR;
  readonly batchExecution: false;
}

export interface PhilCore4337FactoryConfiguration {
  readonly contractName: "PhilCore4337AccountFactory";
  readonly address: string;
  readonly createAccountSelector: typeof PHILCORE_4337_FACTORY_CREATE_ACCOUNT_SELECTOR;
  readonly deploymentModel: "create2";
  readonly approvedActionGate: string;
}

export interface PhilCore4337ValidatorConfiguration {
  readonly model: "ecdsa_owner";
  readonly signatureFormat: "eth_sign_entrypoint_userop_hash_eip191";
  readonly owner: string;
  readonly ownerCommitment: Hex;
  readonly paymaster: "disabled";
  readonly sessionKeys: "disabled";
}

export interface PhilCore4337FoundationConfiguration {
  readonly status: PhilCore4337FoundationStatus;
  readonly acpId: "ACP-0002";
  readonly acpStatus: "Proposed";
  readonly network: PhilCore4337NetworkProfile;
  readonly entryPoint: PhilCore4337EntryPointConfiguration;
  readonly account: PhilCore4337AccountConfiguration;
  readonly factory: PhilCore4337FactoryConfiguration;
  readonly validator: PhilCore4337ValidatorConfiguration;
}

export type PhilCore4337AccountVerificationOutcome =
  | "account_verified"
  | "account_not_deployed"
  | "entry_point_mismatch"
  | "owner_mismatch"
  | "owner_commitment_mismatch"
  | "implementation_mismatch"
  | "network_mismatch"
  | "configuration_unapproved"
  | "malformed"
  | "unsupported";

export interface PhilCore4337AccountState {
  readonly accountAddress: string;
  readonly chainId: number;
  readonly codeExists: boolean;
  readonly codeHash?: Hex;
  readonly entryPoint?: string;
  readonly owner?: string;
  readonly ownerCommitment?: Hex;
  readonly approvedActionGate?: string;
  readonly checkedAt: string;
  readonly blockNumber?: number;
}

export interface PhilCore4337AccountStateReader {
  readAccountState(request: PhilCore4337AccountVerificationRequest): Promise<PhilCore4337AccountState>;
}

export interface PhilCore4337AccountVerificationRequest {
  readonly accountAddress: string;
  readonly expectedEntryPoint: string;
  readonly expectedOwner: string;
  readonly expectedOwnerCommitment: Hex;
  readonly expectedApprovedActionGate: string;
  readonly expectedChainId: number;
  readonly expectedCodeHash?: Hex;
  readonly configurationApproved: boolean;
}

export interface PhilCore4337AccountVerificationResult {
  readonly outcome: PhilCore4337AccountVerificationOutcome;
  readonly accountAddress: string;
  readonly chainId: number;
  readonly codeExists: boolean;
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly errors: readonly string[];
}

export interface PhilCoreCounterfactualAccountRequest {
  readonly factoryAddress: string;
  readonly owner: string;
  readonly ownerCommitment: Hex;
  readonly salt: string | bigint | number;
  readonly expectedChainId: number;
  readonly predictedAddress?: string;
}

export interface PhilCore4337FactoryData {
  readonly factoryAddress: string;
  readonly createAccountCalldata: Hex;
  readonly initCode: Hex;
  readonly createAccountSelector: typeof PHILCORE_4337_FACTORY_CREATE_ACCOUNT_SELECTOR;
}

export interface PhilCore4337CounterfactualBinding {
  readonly factoryAddress: string;
  readonly owner: string;
  readonly ownerCommitment: Hex;
  readonly salt: string;
  readonly predictedAddress: string;
  readonly chainId: number;
  readonly factoryData: PhilCore4337FactoryData;
  readonly accountDeploymentPerformed: false;
}

export interface PhilCoreCounterfactualAccountResult {
  readonly outcome: "counterfactual_resolved" | "counterfactual_resolution_failed";
  readonly binding?: PhilCore4337CounterfactualBinding;
  readonly errors: readonly string[];
}

export interface PhilCore4337ExecutionCallBinding {
  readonly actionGateAddress: string;
  readonly baseExecutionDraftId: string;
  readonly finalizedAuthorizationPackageId: string;
  readonly authoritativeCapabilityGrantId: string;
  readonly sessionId: string;
  readonly applicationId: string;
  readonly ownerCommitment: Hex;
  readonly proofInputHash: Hex;
  readonly nullifier: Hex;
  readonly innerCalldataHash: Hex;
  readonly accountExecuteCalldataHash: Hex;
}

export interface PhilCore4337ExecutionCall {
  readonly target: string;
  readonly value: string;
  readonly innerCalldata: Hex;
  readonly innerCalldataHash: Hex;
  readonly executeCalldata: Hex;
  readonly executeCalldataHash: Hex;
  readonly binding: PhilCore4337ExecutionCallBinding;
}

export interface PhilCorePackedUserOperation {
  readonly sender: string;
  readonly nonce: string;
  readonly initCode: Hex;
  readonly callData: Hex;
  readonly accountGasLimits: Hex;
  readonly preVerificationGas: string;
  readonly gasFees: Hex;
  readonly paymasterAndData: Hex;
  readonly signature: Hex;
}

export interface PhilCore4337NonceReadRequest {
  readonly entryPointAddress: string;
  readonly accountAddress: string;
  readonly nonceKey: string;
  readonly chainId: number;
}

export interface PhilCore4337NonceReadResult {
  readonly status: "resolved" | "unresolved" | "reader_unavailable";
  readonly nonce?: string;
  readonly nonceKey: string;
  readonly source: "entrypoint_get_nonce" | "fixture" | "none";
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly errors?: readonly string[];
}

export interface PhilCore4337NonceReader {
  readNonce(request: PhilCore4337NonceReadRequest): Promise<PhilCore4337NonceReadResult>;
}

export interface PhilCoreUserOperationGasEstimateRequest {
  readonly userOperation: PhilCorePackedUserOperation;
  readonly entryPointAddress: string;
  readonly chainId: number;
}

export interface PhilCoreUserOperationGasEstimateResult {
  readonly status: "estimated" | "failed" | "unavailable";
  readonly callGasLimit?: string;
  readonly verificationGasLimit?: string;
  readonly preVerificationGas?: string;
  readonly maxFeePerGas?: string;
  readonly maxPriorityFeePerGas?: string;
  readonly source: "fixture" | "eth_estimateUserOperationGas" | "entrypoint_simulation" | "none";
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly error?: string;
}

export interface PhilCoreBundlerGasEstimator {
  estimateUserOperationGas(
    request: PhilCoreUserOperationGasEstimateRequest
  ): Promise<PhilCoreUserOperationGasEstimateResult>;
}

export type PhilCore4337FundingStatus =
  | "prefund_sufficient"
  | "prefund_insufficient"
  | "funding_state_unknown"
  | "deposit_reader_unavailable";

export interface PhilCore4337PrefundRequirement {
  readonly status: PhilCore4337FundingStatus;
  readonly requiredPrefund: string;
  readonly entryPointDeposit?: string;
  readonly accountBalance?: string;
  readonly missingPrefund?: string;
  readonly checkedAt: string;
  readonly source: "fixture" | "entrypoint_balance" | "none";
  readonly blockNumber?: number;
}

export interface PhilCore4337PrefundReader {
  readPrefundRequirement(
    request: PhilCoreUserOperationGasEstimateRequest
  ): Promise<PhilCore4337PrefundRequirement>;
}

export interface PhilCoreEntryPointSimulationRequest {
  readonly userOperation: PhilCorePackedUserOperation;
  readonly userOperationHash: Hex;
  readonly entryPointAddress: string;
  readonly chainId: number;
}

export interface PhilCoreEntryPointSimulationResult {
  readonly status:
    | "simulation_succeeded"
    | "validation_failed"
    | "signature_required"
    | "nonce_invalid"
    | "factory_failed"
    | "account_deployment_failed"
    | "prefund_insufficient"
    | "inner_execution_reverted"
    | "unknown_failure";
  readonly fixtureOnly: boolean;
  readonly simulationOnlySignatureUsed: boolean;
  readonly checkedAt: string;
  readonly blockNumber?: number;
  readonly error?: string;
}

export interface PhilCoreEntryPointSimulator {
  simulateUserOperation(
    request: PhilCoreEntryPointSimulationRequest
  ): Promise<PhilCoreEntryPointSimulationResult>;
}

export type PhilCoreUserOperationStatus =
  | "user_operation_draft_created"
  | "user_operation_rejected";

export type PhilCoreUserOperationOutcome =
  | "user_operation_draft_created"
  | "foundation_configuration_invalid"
  | "account_verification_failed"
  | "counterfactual_resolution_failed"
  | "entry_point_mismatch"
  | "owner_binding_mismatch"
  | "owner_commitment_mismatch"
  | "execution_call_mismatch"
  | "nonce_unresolved"
  | "gas_estimation_failed"
  | "prefund_insufficient"
  | "fee_policy_violation"
  | "paymaster_not_allowed"
  | "signature_must_be_empty"
  | "expired"
  | "malformed"
  | "unsupported";

export type PhilCoreUserOperationReason =
  | "uses_entrypoint_v0_7_packed_user_operation"
  | "wraps_exact_base_action_gate_call"
  | "paymaster_disabled"
  | "signature_unresolved"
  | "requires_revalidation_before_signing"
  | "requires_revalidation_before_submission"
  | "no_bundler_submission"
  | "no_live_account_deployment"
  | "no_base_state_mutation";

export type PhilCoreUserOperationLimitation =
  | "acp_0002_proposed"
  | "beta_ecdsa_validator_not_final"
  | "unsigned_preparation_only"
  | "paymaster_disabled"
  | "session_keys_disabled"
  | "batch_execution_disabled"
  | "requires_future_signing_boundary"
  | "requires_future_bundler_boundary";

export interface PhilCoreUserOperationBinding {
  readonly baseExecutionDraftId: string;
  readonly finalizedAuthorizationPackageId: string;
  readonly authoritativeCapabilityGrantId: string;
  readonly sessionId: string;
  readonly applicationId: string;
  readonly owner: string;
  readonly ownerCommitment: Hex;
  readonly entryPointAddress: string;
  readonly entryPointVersion: typeof PHILCORE_4337_ENTRYPOINT_VERSION;
  readonly factoryAddress?: string;
  readonly smartAccountAddress: string;
  readonly actionGateAddress: string;
  readonly proofInputHash: Hex;
  readonly nullifier: Hex;
  readonly innerCalldataHash: Hex;
  readonly executeCalldataHash: Hex;
  readonly userOperationHash: Hex;
  readonly chainId: number;
  readonly auditCorrelationId: string;
}

export interface PhilCorePackedUserOperationDraft {
  readonly philCorePackedUserOperationDraftId: string;
  readonly status: "user_operation_draft_created";
  readonly outcome: "user_operation_draft_created";
  readonly binding: PhilCoreUserOperationBinding;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly accountState: "deployed" | "counterfactual";
  readonly accountVerification?: PhilCore4337AccountVerificationResult;
  readonly counterfactual?: PhilCore4337CounterfactualBinding;
  readonly executionCall: PhilCore4337ExecutionCall;
  readonly nonce: PhilCore4337NonceReadResult;
  readonly gas: PhilCoreUserOperationGasEstimateResult;
  readonly prefund: PhilCore4337PrefundRequirement;
  readonly simulation?: PhilCoreEntryPointSimulationResult;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly reasons: readonly PhilCoreUserOperationReason[];
  readonly limitations: readonly PhilCoreUserOperationLimitation[];
  readonly entryPointVersion: typeof PHILCORE_4337_ENTRYPOINT_VERSION;
  readonly userOperationPrepared: true;
  readonly userOperationSigned: false;
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
  readonly collectionResult?: PhilCore4337UserOperationDraftCollectionResult;
}

export interface PhilCoreUserOperationPreparationRequest {
  readonly requestId: string;
  readonly baseExecutionDraft: BaseAuthorizationExecutionTransactionDraft;
  readonly foundation: PhilCore4337FoundationConfiguration;
  readonly accountMode: "deployed" | "counterfactual";
  readonly accountAddress?: string;
  readonly accountStateReader?: PhilCore4337AccountStateReader;
  readonly counterfactual?: PhilCoreCounterfactualAccountRequest;
  readonly counterfactualResolver?: PhilCoreCounterfactualAccountResolver;
  readonly nonceReader: PhilCore4337NonceReader;
  readonly gasEstimator?: PhilCoreBundlerGasEstimator;
  readonly prefundReader?: PhilCore4337PrefundReader;
  readonly simulator?: PhilCoreEntryPointSimulator;
  readonly callGasLimit?: string | bigint | number;
  readonly verificationGasLimit?: string | bigint | number;
  readonly preVerificationGas?: string | bigint | number;
  readonly maxFeePerGas?: string | bigint | number;
  readonly maxPriorityFeePerGas?: string | bigint | number;
  readonly paymasterAndData?: Hex;
  readonly signature?: Hex;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly auditDraftCollector?: AuditDraftCollector;
  readonly draftStore?: PhilCore4337UserOperationDraftStore;
}

export type PhilCoreUserOperationPreparationResult =
  RuntimeResult<PhilCorePackedUserOperationDraft>;

export interface PhilCoreCounterfactualAccountResolver {
  resolveCounterfactualAccount(
    request: PhilCoreCounterfactualAccountRequest
  ): Promise<PhilCoreCounterfactualAccountResult>;
}

export type PhilCore4337DraftCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "removed"
  | "not_found"
  | "cleared";

export interface PhilCore4337UserOperationDraftCollection {
  readonly drafts: readonly PhilCorePackedUserOperationDraft[];
  readonly count: number;
  readonly maxDraftCount: number;
}

export interface PhilCore4337UserOperationDraftCollectionResult {
  readonly status: PhilCore4337DraftCollectionStatus;
  readonly draft?: PhilCorePackedUserOperationDraft;
  readonly removedDraft?: PhilCorePackedUserOperationDraft;
  readonly evictedDrafts?: readonly PhilCorePackedUserOperationDraft[];
  readonly collection: PhilCore4337UserOperationDraftCollection;
  readonly reason?: string;
}

export interface PhilCore4337UserOperationDraftStore {
  addDraft(draft: PhilCorePackedUserOperationDraft): PhilCore4337UserOperationDraftCollectionResult;
  removeDraft(draftId: string): PhilCore4337UserOperationDraftCollectionResult;
  clear(): PhilCore4337UserOperationDraftCollectionResult;
  count(): number;
  getById(draftId: string): PhilCorePackedUserOperationDraft | undefined;
  getAll(): readonly PhilCorePackedUserOperationDraft[];
}

const USER_OPERATION_OUTCOMES = new Set<PhilCoreUserOperationOutcome>([
  "user_operation_draft_created",
  "foundation_configuration_invalid",
  "account_verification_failed",
  "counterfactual_resolution_failed",
  "entry_point_mismatch",
  "owner_binding_mismatch",
  "owner_commitment_mismatch",
  "execution_call_mismatch",
  "nonce_unresolved",
  "gas_estimation_failed",
  "prefund_insufficient",
  "fee_policy_violation",
  "paymaster_not_allowed",
  "signature_must_be_empty",
  "expired",
  "malformed",
  "unsupported"
]);

const USER_OPERATION_STATUSES = new Set<PhilCoreUserOperationStatus>([
  "user_operation_draft_created",
  "user_operation_rejected"
]);

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

function uintString(value: string | bigint | number | undefined, fallback: bigint): string {
  if (value === undefined) return fallback.toString();
  return BigInt(value).toString();
}

function uintHex(value: string | bigint | number): Hex {
  return toBeHex(BigInt(value)) as Hex;
}

function requestError(
  outcome: PhilCoreUserOperationOutcome,
  errors: readonly string[],
  request: PhilCoreUserOperationPreparationRequest
): RuntimeResult<never> {
  const auditEventDraft = createUserOperationAuditDraft({
    outcome,
    summary: "PhilCore ERC-4337 UserOperation preparation was rejected; no UserOperation was signed or submitted.",
    request,
    errors
  });
  request.auditDraftCollector?.addDraft(auditEventDraft);
  return runtimeDenied({
    code: `PHILCORE_4337_USER_OPERATION_${outcome.toUpperCase()}`,
    category: outcome.includes("nonce") || outcome.includes("expired")
      ? "invalid_authorization_package"
      : outcome.includes("paymaster") || outcome.includes("unsupported")
        ? "unsupported_operation"
        : "invalid_authorization_package",
    message: "PhilCore ERC-4337 UserOperation preparation was rejected.",
    recoverable: true,
    details: { outcome, errors, auditEventId: auditEventDraft.eventDraftId }
  }, { auditEventId: auditEventDraft.eventDraftId });
}

function createUserOperationAuditDraft(input: {
  readonly outcome: PhilCoreUserOperationOutcome;
  readonly summary: string;
  readonly request?: PhilCoreUserOperationPreparationRequest;
  readonly draft?: PhilCorePackedUserOperationDraft;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.outcome === "user_operation_draft_created"
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: "requestPhilCore4337UserOperationPreparation",
    summary: input.summary,
    auditCorrelationId: input.request?.auditCorrelationId ?? input.draft?.binding.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      entryPoint: input.request?.foundation.entryPoint.address ?? input.draft?.binding.entryPointAddress,
      entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
      factory: input.request?.foundation.factory.address ?? input.draft?.binding.factoryAddress,
      account: input.request?.accountAddress ?? input.draft?.binding.smartAccountAddress,
      owner: input.request?.foundation.validator.owner ?? input.draft?.binding.owner,
      ownerCommitment: input.request?.foundation.validator.ownerCommitment ?? input.draft?.binding.ownerCommitment,
      actionGate: input.request?.baseExecutionDraft.to ?? input.draft?.binding.actionGateAddress,
      innerCalldataHash: input.request?.baseExecutionDraft.calldataHash ?? input.draft?.binding.innerCalldataHash,
      userOperationHash: input.draft?.binding.userOperationHash,
      nonce: input.draft?.nonce.status,
      gas: input.draft?.gas.status,
      prefund: input.draft?.prefund.status,
      paymaster: "disabled",
      signature: "unresolved"
    }
  });
}

export function isPhilCoreUserOperationStatus(
  value: unknown
): value is PhilCoreUserOperationStatus {
  return USER_OPERATION_STATUSES.has(value as PhilCoreUserOperationStatus);
}

export function isPhilCoreUserOperationOutcome(
  value: unknown
): value is PhilCoreUserOperationOutcome {
  return USER_OPERATION_OUTCOMES.has(value as PhilCoreUserOperationOutcome);
}

export function packPhilCore4337Uints(
  high128: string | bigint | number,
  low128: string | bigint | number
): Hex {
  const high = BigInt(high128);
  const low = BigInt(low128);
  const max = (1n << 128n) - 1n;
  if (high < 0n || low < 0n || high > max || low > max) {
    throw new Error("ERC-4337 packed uint128 fields overflow");
  }
  return toBeHex((high << 128n) + low, 32).toLowerCase() as Hex;
}

export function unpackPhilCore4337Uints(
  packed: Hex
): { readonly high128: string; readonly low128: string } {
  const value = BigInt(packed);
  const low = value & ((1n << 128n) - 1n);
  const high = value >> 128n;
  return Object.freeze({ high128: high.toString(), low128: low.toString() });
}

export function packPhilCore4337AccountGasLimits(input: {
  readonly verificationGasLimit: string | bigint | number;
  readonly callGasLimit: string | bigint | number;
}): Hex {
  return packPhilCore4337Uints(input.verificationGasLimit, input.callGasLimit);
}

export function packPhilCore4337GasFees(input: {
  readonly maxPriorityFeePerGas: string | bigint | number;
  readonly maxFeePerGas: string | bigint | number;
}): Hex {
  return packPhilCore4337Uints(input.maxPriorityFeePerGas, input.maxFeePerGas);
}

export function computePhilCore4337UserOperationHash(input: {
  readonly userOperation: PhilCorePackedUserOperation;
  readonly entryPointAddress: string;
  readonly chainId: number;
}): Hex {
  const op = input.userOperation;
  const packHash = keccak256(abiCoder.encode(
    [
      "address",
      "uint256",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint256",
      "bytes32",
      "bytes32"
    ],
    [
      normalizeAddress(op.sender),
      BigInt(op.nonce),
      keccak256(op.initCode),
      keccak256(op.callData),
      normalizeHex(op.accountGasLimits, 32),
      BigInt(op.preVerificationGas),
      normalizeHex(op.gasFees, 32),
      keccak256(op.paymasterAndData)
    ]
  ));
  return keccak256(abiCoder.encode(
    ["bytes32", "address", "uint256"],
    [packHash, normalizeAddress(input.entryPointAddress), BigInt(input.chainId)]
  )) as Hex;
}

export function validatePhilCore4337UserOperationHashBinding(input: {
  readonly userOperation: PhilCorePackedUserOperation;
  readonly entryPointAddress: string;
  readonly chainId: number;
  readonly expectedUserOperationHash: Hex;
}): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = [];
  const computed = computePhilCore4337UserOperationHash(input);
  if (computed.toLowerCase() !== input.expectedUserOperationHash.toLowerCase()) {
    errors.push("UserOperation hash mismatch");
  }
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

export function verifyPhilCore4337Foundation(
  foundation: PhilCore4337FoundationConfiguration
): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = [];
  try {
    normalizeAddress(foundation.entryPoint.address);
    normalizeAddress(foundation.factory.address);
    normalizeAddress(foundation.validator.owner);
    normalizeHex(foundation.validator.ownerCommitment, 32);
  } catch {
    errors.push("foundation addresses or ownerCommitment malformed");
  }
  if (foundation.entryPoint.version !== PHILCORE_4337_ENTRYPOINT_VERSION) errors.push("EntryPoint version must be 0.7");
  if (foundation.entryPoint.packageVersion !== "0.7.0") errors.push("EntryPoint package must be 0.7.0");
  if (foundation.account.executeSelector !== PHILCORE_4337_EXECUTE_SELECTOR) errors.push("account execute selector mismatch");
  if (foundation.account.selfExecuteAllowed !== false) errors.push("account self execute must be disabled");
  if (foundation.account.allowedTarget !== "approved_action_gate") errors.push("account target must be ActionGate restricted");
  if (foundation.account.allowedSelector !== BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR) {
    errors.push("account ActionGate selector mismatch");
  }
  if (foundation.factory.createAccountSelector !== PHILCORE_4337_FACTORY_CREATE_ACCOUNT_SELECTOR) {
    errors.push("factory createAccount selector mismatch");
  }
  try {
    if (normalizeAddress(foundation.account.approvedActionGate) !== normalizeAddress(foundation.factory.approvedActionGate)) {
      errors.push("factory/account ActionGate mismatch");
    }
  } catch {
    errors.push("approved ActionGate malformed");
  }
  if (foundation.validator.paymaster !== "disabled") errors.push("paymaster must be disabled");
  if (foundation.validator.sessionKeys !== "disabled") errors.push("session keys must be disabled");
  if (foundation.acpId !== "ACP-0002" || foundation.acpStatus !== "Proposed") errors.push("ACP-0002 must remain Proposed");
  if (foundation.network.chainId <= 0) errors.push("chainId invalid");
  if (foundation.network.productionApproved && foundation.status !== "approved") {
    errors.push("production approval requires approved status");
  }
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

export async function resolvePhilCore4337Account(input: {
  readonly request: PhilCoreUserOperationPreparationRequest;
}): Promise<{
  readonly accountAddress?: string;
  readonly accountState?: "deployed" | "counterfactual";
  readonly accountVerification?: PhilCore4337AccountVerificationResult;
  readonly counterfactual?: PhilCore4337CounterfactualBinding;
  readonly errors: readonly string[];
}> {
  const { request } = input;
  const errors: string[] = [];
  if (request.accountMode === "deployed") {
    if (!request.accountAddress) {
      return Object.freeze({ errors: Object.freeze(["deployed account address required"]) });
    }
    if (!request.accountStateReader) {
      return Object.freeze({ errors: Object.freeze(["account state reader required"]) });
    }
    const accountAddress = normalizeAddress(request.accountAddress);
    const verification = await verifyPhilCore4337Account({
      request: {
        accountAddress,
        expectedEntryPoint: request.foundation.entryPoint.address,
        expectedOwner: request.foundation.validator.owner,
        expectedOwnerCommitment: request.foundation.validator.ownerCommitment,
        expectedApprovedActionGate: request.foundation.account.approvedActionGate,
        expectedChainId: request.foundation.network.chainId,
        configurationApproved: request.foundation.status === "approved" || request.foundation.status === "local_fixture"
      },
      reader: request.accountStateReader
    });
    if (verification.outcome !== "account_verified") errors.push(...verification.errors);
    return Object.freeze({
      accountAddress,
      accountState: "deployed" as const,
      accountVerification: verification,
      errors: Object.freeze(errors)
    });
  }
  if (!request.counterfactual) {
    return Object.freeze({ errors: Object.freeze(["counterfactual request required"]) });
  }
  const resolver = request.counterfactualResolver ?? createDeterministicCounterfactualResolver();
  const result = await resolver.resolveCounterfactualAccount(request.counterfactual);
  if (result.outcome !== "counterfactual_resolved" || !result.binding) {
    errors.push(...result.errors);
    return Object.freeze({ errors: Object.freeze(errors) });
  }
  return Object.freeze({
    accountAddress: result.binding.predictedAddress,
    accountState: "counterfactual" as const,
    counterfactual: result.binding,
    errors: Object.freeze(errors)
  });
}

export async function verifyPhilCore4337Account(input: {
  readonly request: PhilCore4337AccountVerificationRequest;
  readonly reader: PhilCore4337AccountStateReader;
}): Promise<PhilCore4337AccountVerificationResult> {
  const state = await input.reader.readAccountState(input.request);
  const errors: string[] = [];
  let outcome: PhilCore4337AccountVerificationOutcome = "account_verified";
  if (state.chainId !== input.request.expectedChainId) {
    outcome = "network_mismatch";
    errors.push("network mismatch");
  }
  if (!state.codeExists) {
    outcome = "account_not_deployed";
    errors.push("account not deployed");
  }
  if (input.request.expectedCodeHash && state.codeHash?.toLowerCase() !== input.request.expectedCodeHash.toLowerCase()) {
    outcome = "implementation_mismatch";
    errors.push("account code hash mismatch");
  }
  if (state.entryPoint && normalizeAddress(state.entryPoint) !== normalizeAddress(input.request.expectedEntryPoint)) {
    outcome = "entry_point_mismatch";
    errors.push("EntryPoint mismatch");
  }
  if (state.owner && normalizeAddress(state.owner) !== normalizeAddress(input.request.expectedOwner)) {
    outcome = "owner_mismatch";
    errors.push("owner mismatch");
  }
  if (
    state.ownerCommitment
    && state.ownerCommitment.toLowerCase() !== input.request.expectedOwnerCommitment.toLowerCase()
  ) {
    outcome = "owner_commitment_mismatch";
    errors.push("ownerCommitment mismatch");
  }
  if (
    state.approvedActionGate
    && normalizeAddress(state.approvedActionGate) !== normalizeAddress(input.request.expectedApprovedActionGate)
  ) {
    outcome = "implementation_mismatch";
    errors.push("approved ActionGate mismatch");
  }
  if (!input.request.configurationApproved) {
    outcome = "configuration_unapproved";
    errors.push("configuration not approved for profile");
  }
  return freezeRecord({
    outcome,
    accountAddress: normalizeAddress(input.request.accountAddress),
    chainId: state.chainId,
    codeExists: state.codeExists,
    checkedAt: state.checkedAt,
    blockNumber: state.blockNumber,
    errors: Object.freeze(errors)
  });
}

export function createDeterministicCounterfactualResolver(): PhilCoreCounterfactualAccountResolver {
  return {
    async resolveCounterfactualAccount(request) {
      const errors: string[] = [];
      try {
        const owner = normalizeAddress(request.owner);
        const ownerCommitment = normalizeHex(request.ownerCommitment, 32);
        const factoryAddress = normalizeAddress(request.factoryAddress);
        const salt = BigInt(request.salt);
        const createAccountCalldata = factoryInterface.encodeFunctionData("createAccount", [
          owner,
          ownerCommitment,
          salt
        ]) as Hex;
        const predictedAddress = request.predictedAddress
          ? normalizeAddress(request.predictedAddress)
          : undefined;
        if (!predictedAddress) errors.push("predicted address required without live factory helper");
        const initCode = predictedAddress
          ? concat([factoryAddress, createAccountCalldata]).toLowerCase() as Hex
          : PHILCORE_4337_EMPTY_BYTES;
        return freezeRecord({
          outcome: errors.length > 0
            ? "counterfactual_resolution_failed" as const
            : "counterfactual_resolved" as const,
          binding: predictedAddress
            ? {
              factoryAddress,
              owner,
              ownerCommitment,
              salt: salt.toString(),
              predictedAddress,
              chainId: request.expectedChainId,
              factoryData: {
                factoryAddress,
                createAccountCalldata,
                initCode,
                createAccountSelector: PHILCORE_4337_FACTORY_CREATE_ACCOUNT_SELECTOR
              },
              accountDeploymentPerformed: false as const
            }
            : undefined,
          errors: Object.freeze(errors)
        });
      } catch (error) {
        return freezeRecord({
          outcome: "counterfactual_resolution_failed" as const,
          errors: Object.freeze([error instanceof Error ? error.message : "counterfactual malformed"])
        });
      }
    }
  };
}

export function encodePhilCore4337ExecuteCall(input: {
  readonly baseExecutionDraft: BaseAuthorizationExecutionTransactionDraft;
}): PhilCore4337ExecutionCall {
  const draft = input.baseExecutionDraft;
  if (draft.methodSelector !== BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR) {
    throw new Error("Base execution draft must call verifyAndConsume");
  }
  if (!draft.calldata.startsWith(BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR)) {
    throw new Error("Base execution calldata selector mismatch");
  }
  if (draft.calldataHash.toLowerCase() !== keccak256(draft.calldata).toLowerCase()) {
    throw new Error("Base execution calldata hash mismatch");
  }
  const executeCalldata = accountInterface.encodeFunctionData("execute", [
    normalizeAddress(draft.to),
    BigInt(draft.value),
    draft.calldata
  ]) as Hex;
  const executeCalldataHash = keccak256(executeCalldata) as Hex;
  return freezeRecord({
    target: normalizeAddress(draft.to),
    value: BigInt(draft.value).toString(),
    innerCalldata: draft.calldata,
    innerCalldataHash: draft.calldataHash,
    executeCalldata,
    executeCalldataHash,
    binding: {
      actionGateAddress: normalizeAddress(draft.to),
      baseExecutionDraftId: draft.baseAuthorizationExecutionTransactionDraftId,
      finalizedAuthorizationPackageId: draft.binding.finalizedAuthorizationPackageId,
      authoritativeCapabilityGrantId: draft.binding.authoritativeCapabilityGrantId,
      sessionId: draft.binding.sessionId,
      applicationId: draft.binding.applicationId,
      ownerCommitment: draft.binding.ownerCommitment,
      proofInputHash: draft.binding.proofInputHash,
      nullifier: draft.binding.nullifier,
      innerCalldataHash: draft.calldataHash,
      accountExecuteCalldataHash: executeCalldataHash
    }
  });
}

export function validatePhilCore4337UserOperationDraft(
  draft: PhilCorePackedUserOperationDraft
): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = [];
  if (draft.status !== "user_operation_draft_created") errors.push("status invalid");
  if (draft.entryPointVersion !== PHILCORE_4337_ENTRYPOINT_VERSION) errors.push("EntryPoint version invalid");
  if (draft.userOperation.signature !== PHILCORE_4337_EMPTY_BYTES) errors.push("signature must be empty");
  if (draft.userOperation.paymasterAndData !== PHILCORE_4337_EMPTY_BYTES) errors.push("paymasterAndData must be empty");
  if (!draft.userOperation.callData.startsWith(PHILCORE_4337_EXECUTE_SELECTOR)) errors.push("callData must wrap account execute");
  if (draft.userOperationPrepared !== true || draft.userOperationSigned !== false || draft.userOperationSubmitted !== false) {
    errors.push("draft must be prepared, unsigned, and unsubmitted");
  }
  if (
    draft.bundlerSubmissionPerformed
    || draft.paymasterInvoked
    || draft.smartAccountDeploymentPerformed
    || draft.nullifierConsumed
    || draft.consumerExecuted
    || draft.baseStateMutated
    || draft.applicationCanSubmitDirectly
  ) {
    errors.push("draft must not claim execution authority");
  }
  const computedHash = computePhilCore4337UserOperationHash({
    userOperation: draft.userOperation,
    entryPointAddress: draft.binding.entryPointAddress,
    chainId: draft.binding.chainId
  });
  if (computedHash.toLowerCase() !== draft.binding.userOperationHash.toLowerCase()) {
    errors.push("UserOperation hash binding invalid");
  }
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

export async function preparePhilCore4337UserOperation(
  request: PhilCoreUserOperationPreparationRequest
): Promise<PhilCoreUserOperationPreparationResult> {
  const errors: string[] = [];
  const foundation = verifyPhilCore4337Foundation(request.foundation);
  if (!foundation.valid) errors.push(...foundation.errors);
  if (request.signature && request.signature !== PHILCORE_4337_EMPTY_BYTES) errors.push("signature must be empty");
  if (request.paymasterAndData && request.paymasterAndData !== PHILCORE_4337_EMPTY_BYTES) errors.push("paymaster not allowed");
  if (new Date(request.expiresAt).getTime() <= Date.now()) errors.push("request expired");
  const baseDraftValidation = validateBaseDraftForUserOperation(request.baseExecutionDraft);
  if (!baseDraftValidation.valid) errors.push(...baseDraftValidation.errors);
  if (errors.length > 0) {
    return requestError(outcomeForErrors(errors), errors, request);
  }

  const resolved = await resolvePhilCore4337Account({ request });
  if (resolved.errors.length > 0 || !resolved.accountAddress || !resolved.accountState) {
    return requestError(
      request.accountMode === "counterfactual"
        ? "counterfactual_resolution_failed"
        : "account_verification_failed",
      resolved.errors,
      request
    );
  }

  const executeCall = encodePhilCore4337ExecuteCall({ baseExecutionDraft: request.baseExecutionDraft });
  const nonce = await request.nonceReader.readNonce({
    entryPointAddress: request.foundation.entryPoint.address,
    accountAddress: resolved.accountAddress,
    nonceKey: "0",
    chainId: request.foundation.network.chainId
  });
  if (nonce.status !== "resolved" || nonce.nonce === undefined) {
    return requestError("nonce_unresolved", nonce.errors ?? ["EntryPoint nonce unresolved"], request);
  }

  const accountGasLimits = packPhilCore4337AccountGasLimits({
    verificationGasLimit: uintString(request.verificationGasLimit, 900_000n),
    callGasLimit: uintString(request.callGasLimit, 900_000n)
  });
  const gasFees = packPhilCore4337GasFees({
    maxPriorityFeePerGas: uintString(request.maxPriorityFeePerGas, 1_000_000_000n),
    maxFeePerGas: uintString(request.maxFeePerGas, 30_000_000_000n)
  });
  const userOperation: PhilCorePackedUserOperation = freezeRecord({
    sender: normalizeAddress(resolved.accountAddress),
    nonce: BigInt(nonce.nonce).toString(),
    initCode: resolved.counterfactual?.factoryData.initCode ?? PHILCORE_4337_EMPTY_BYTES,
    callData: executeCall.executeCalldata,
    accountGasLimits,
    preVerificationGas: uintString(request.preVerificationGas, 120_000n),
    gasFees,
    paymasterAndData: PHILCORE_4337_EMPTY_BYTES,
    signature: PHILCORE_4337_EMPTY_BYTES
  });

  const estimateRequest = {
    userOperation,
    entryPointAddress: request.foundation.entryPoint.address,
    chainId: request.foundation.network.chainId
  };
  const gas = request.gasEstimator
    ? await request.gasEstimator.estimateUserOperationGas(estimateRequest)
    : freezeRecord({
      status: "unavailable" as const,
      source: "none" as const,
      checkedAt: nowIso()
    });
  if (gas.status === "failed") {
    return requestError("gas_estimation_failed", [gas.error ?? "UserOperation gas estimation failed"], request);
  }

  const prefund = request.prefundReader
    ? await request.prefundReader.readPrefundRequirement(estimateRequest)
    : freezeRecord({
      status: "deposit_reader_unavailable" as const,
      requiredPrefund: "0",
      checkedAt: nowIso(),
      source: "none" as const
    });
  if (prefund.status === "prefund_insufficient") {
    return requestError("prefund_insufficient", [`missing prefund ${prefund.missingPrefund ?? "unknown"}`], request);
  }

  const userOperationHash = computePhilCore4337UserOperationHash({
    userOperation,
    entryPointAddress: request.foundation.entryPoint.address,
    chainId: request.foundation.network.chainId
  });
  const simulation = request.simulator
    ? await request.simulator.simulateUserOperation({
      userOperation,
      userOperationHash,
      entryPointAddress: request.foundation.entryPoint.address,
      chainId: request.foundation.network.chainId
    })
    : undefined;
  if (
    simulation
    && !["simulation_succeeded", "signature_required"].includes(simulation.status)
  ) {
    return requestError("unsupported", [simulation.error ?? `simulation ${simulation.status}`], request);
  }

  const draftBase = {
    philCorePackedUserOperationDraftId: createAuditCorrelationId([
      request.baseExecutionDraft.baseAuthorizationExecutionTransactionDraftId,
      userOperationHash,
      "philcore-4337-user-operation-draft"
    ]),
    status: "user_operation_draft_created" as const,
    outcome: "user_operation_draft_created" as const,
    binding: {
      baseExecutionDraftId: request.baseExecutionDraft.baseAuthorizationExecutionTransactionDraftId,
      finalizedAuthorizationPackageId: request.baseExecutionDraft.binding.finalizedAuthorizationPackageId,
      authoritativeCapabilityGrantId: request.baseExecutionDraft.binding.authoritativeCapabilityGrantId,
      sessionId: request.baseExecutionDraft.binding.sessionId,
      applicationId: request.baseExecutionDraft.binding.applicationId,
      owner: normalizeAddress(request.foundation.validator.owner),
      ownerCommitment: request.foundation.validator.ownerCommitment,
      entryPointAddress: normalizeAddress(request.foundation.entryPoint.address),
      entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
      factoryAddress: normalizeAddress(request.foundation.factory.address),
      smartAccountAddress: normalizeAddress(resolved.accountAddress),
      actionGateAddress: normalizeAddress(request.baseExecutionDraft.to),
      proofInputHash: request.baseExecutionDraft.binding.proofInputHash,
      nullifier: request.baseExecutionDraft.binding.nullifier,
      innerCalldataHash: executeCall.innerCalldataHash,
      executeCalldataHash: executeCall.executeCalldataHash,
      userOperationHash,
      chainId: request.foundation.network.chainId,
      auditCorrelationId: request.auditCorrelationId
    },
    userOperation,
    accountState: resolved.accountState,
    accountVerification: resolved.accountVerification,
    counterfactual: resolved.counterfactual,
    executionCall: executeCall,
    nonce,
    gas,
    prefund,
    simulation,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    reasons: Object.freeze([
      "uses_entrypoint_v0_7_packed_user_operation",
      "wraps_exact_base_action_gate_call",
      "paymaster_disabled",
      "signature_unresolved",
      "requires_revalidation_before_signing",
      "requires_revalidation_before_submission",
      "no_bundler_submission",
      "no_live_account_deployment",
      "no_base_state_mutation"
    ] satisfies PhilCoreUserOperationReason[]),
    limitations: Object.freeze([
      "acp_0002_proposed",
      "beta_ecdsa_validator_not_final",
      "unsigned_preparation_only",
      "paymaster_disabled",
      "session_keys_disabled",
      "batch_execution_disabled",
      "requires_future_signing_boundary",
      "requires_future_bundler_boundary"
    ] satisfies PhilCoreUserOperationLimitation[]),
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    userOperationPrepared: true as const,
    userOperationSigned: false as const,
    userOperationSubmitted: false as const,
    bundlerSubmissionPerformed: false as const,
    paymasterInvoked: false as const,
    smartAccountDeploymentPerformed: false as const,
    nullifierConsumed: false as const,
    consumerExecuted: false as const,
    baseStateMutated: false as const,
    applicationCanSubmitDirectly: false as const
  };
  const auditEventDraft = createUserOperationAuditDraft({
    outcome: "user_operation_draft_created",
    summary: "PhilCore ERC-4337 UserOperation draft was prepared; it remains unsigned and unsubmitted.",
    request,
    draft: draftBase as PhilCorePackedUserOperationDraft
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const draft = freezeRecord({
    ...draftBase,
    auditEventDraft,
    auditDraftCollectionResult
  }) as PhilCorePackedUserOperationDraft;
  const collectionResult = request.draftStore?.addDraft(draft);
  const value = collectionResult
    ? freezeRecord({ ...draft, collectionResult }) as PhilCorePackedUserOperationDraft
    : draft;
  return runtimeOk(value, { auditEventId: auditEventDraft.eventDraftId });
}

export const requestPhilCore4337UserOperationPreparation =
  preparePhilCore4337UserOperation;

export const requestPhilCore4337AccountVerification =
  verifyPhilCore4337Account;

export function requestPhilCore4337UserOperationSimulation(
  simulator: PhilCoreEntryPointSimulator,
  request: PhilCoreEntryPointSimulationRequest
): Promise<PhilCoreEntryPointSimulationResult> {
  return simulator.simulateUserOperation(request);
}

function validateBaseDraftForUserOperation(
  draft: BaseAuthorizationExecutionTransactionDraft
): { readonly valid: boolean; readonly errors: readonly string[] } {
  const errors: string[] = [];
  if (draft.status !== "execution_transaction_draft_created") errors.push("Base execution draft status invalid");
  if (draft.methodSelector !== BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR) errors.push("Base execution selector invalid");
  if (draft.calldataHash.toLowerCase() !== keccak256(draft.calldata).toLowerCase()) errors.push("Base execution calldata hash mismatch");
  if (draft.transactionSigned || draft.transactionSubmitted) errors.push("Base execution draft must be unsigned and unsubmitted");
  if (draft.userOperationCreated) errors.push("Base execution draft must not already contain a UserOperation");
  if (draft.nullifierConsumed || draft.consumerExecuted || draft.baseStateMutated) errors.push("Base execution state must not be mutated");
  if (new Date(draft.expiresAt).getTime() <= Date.now()) errors.push("Base execution draft expired");
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

function outcomeForErrors(errors: readonly string[]): PhilCoreUserOperationOutcome {
  const joined = errors.join(" ").toLowerCase();
  if (joined.includes("paymaster")) return "paymaster_not_allowed";
  if (joined.includes("signature")) return "signature_must_be_empty";
  if (joined.includes("entrypoint")) return "entry_point_mismatch";
  if (joined.includes("ownercommitment")) return "owner_commitment_mismatch";
  if (joined.includes("owner")) return "owner_binding_mismatch";
  if (joined.includes("nonce")) return "nonce_unresolved";
  if (joined.includes("gas")) return "gas_estimation_failed";
  if (joined.includes("prefund")) return "prefund_insufficient";
  if (joined.includes("expired")) return "expired";
  if (joined.includes("base execution")) return "execution_call_mismatch";
  return "foundation_configuration_invalid";
}

export function createFixturePhilCore4337NonceReader(
  nonce: string | bigint | number,
  source: PhilCore4337NonceReadResult["source"] = "fixture"
): PhilCore4337NonceReader {
  return {
    async readNonce(request) {
      return freezeRecord({
        status: "resolved" as const,
        nonce: BigInt(nonce).toString(),
        nonceKey: request.nonceKey,
        source,
        checkedAt: nowIso()
      });
    }
  };
}

export function createFixturePhilCore4337GasEstimator(
  overrides: Partial<PhilCoreUserOperationGasEstimateResult> = {}
): PhilCoreBundlerGasEstimator {
  return {
    async estimateUserOperationGas() {
      return freezeRecord({
        status: "estimated" as const,
        callGasLimit: "900000",
        verificationGasLimit: "900000",
        preVerificationGas: "120000",
        maxFeePerGas: "30000000000",
        maxPriorityFeePerGas: "1000000000",
        source: "fixture" as const,
        checkedAt: nowIso(),
        ...overrides
      });
    }
  };
}

export function createFixturePhilCore4337PrefundReader(
  overrides: Partial<PhilCore4337PrefundRequirement> = {}
): PhilCore4337PrefundReader {
  return {
    async readPrefundRequirement() {
      return freezeRecord({
        status: "prefund_sufficient" as const,
        requiredPrefund: "0",
        entryPointDeposit: "0",
        accountBalance: "0",
        checkedAt: nowIso(),
        source: "fixture" as const,
        ...overrides
      });
    }
  };
}

export function createFixturePhilCore4337AccountStateReader(
  state: Omit<PhilCore4337AccountState, "checkedAt">
): PhilCore4337AccountStateReader {
  return {
    async readAccountState() {
      return freezeRecord({
        ...state,
        checkedAt: nowIso()
      });
    }
  };
}

export function createFixturePhilCore4337EntryPointSimulator(
  status: PhilCoreEntryPointSimulationResult["status"] = "signature_required"
): PhilCoreEntryPointSimulator {
  return {
    async simulateUserOperation() {
      return freezeRecord({
        status,
        fixtureOnly: true,
        simulationOnlySignatureUsed: false,
        checkedAt: nowIso()
      });
    }
  };
}

export function createInMemoryPhilCore4337UserOperationDraftStore(
  options: { readonly maxDraftCount?: number } = {}
): PhilCore4337UserOperationDraftStore {
  const maxDraftCount = Math.max(1, Math.floor(options.maxDraftCount ?? 25));
  const drafts = new Map<string, PhilCorePackedUserOperationDraft>();
  const all = () => Object.freeze(Array.from(drafts.values()));
  const collection = (): PhilCore4337UserOperationDraftCollection => Object.freeze({
    drafts: all(),
    count: drafts.size,
    maxDraftCount
  });

  return {
    addDraft(draft) {
      if (drafts.has(draft.philCorePackedUserOperationDraftId)) {
        return freezeRecord({
          status: "rejected_duplicate" as const,
          draft: drafts.get(draft.philCorePackedUserOperationDraftId),
          collection: collection(),
          reason: "duplicate UserOperation draft id"
        });
      }
      const evictedDrafts: PhilCorePackedUserOperationDraft[] = [];
      while (drafts.size >= maxDraftCount) {
        const oldest = drafts.keys().next().value as string | undefined;
        if (!oldest) break;
        const evicted = drafts.get(oldest);
        drafts.delete(oldest);
        if (evicted) evictedDrafts.push(evicted);
      }
      const stored = freezeRecord(draft);
      drafts.set(stored.philCorePackedUserOperationDraftId, stored);
      return freezeRecord({
        status: evictedDrafts.length > 0 ? "evicted_oldest" as const : "collected" as const,
        draft: stored,
        evictedDrafts: Object.freeze(evictedDrafts),
        collection: collection()
      });
    },
    removeDraft(draftId) {
      const removedDraft = drafts.get(draftId);
      if (!removedDraft) {
        return freezeRecord({
          status: "not_found" as const,
          collection: collection(),
          reason: "draft not found"
        });
      }
      drafts.delete(draftId);
      return freezeRecord({
        status: "removed" as const,
        removedDraft,
        collection: collection()
      });
    },
    clear() {
      drafts.clear();
      return freezeRecord({
        status: "cleared" as const,
        collection: collection()
      });
    },
    count() {
      return drafts.size;
    },
    getById(draftId) {
      return drafts.get(draftId);
    },
    getAll() {
      return all();
    }
  };
}

export function createPhilCore4337LocalFoundationConfiguration(input: {
  readonly chainId: number;
  readonly entryPointAddress: string;
  readonly factoryAddress: string;
  readonly approvedActionGateAddress: string;
  readonly owner: string;
  readonly ownerCommitment: Hex;
  readonly profileId?: string;
}): PhilCore4337FoundationConfiguration {
  return freezeRecord({
    status: "local_fixture" as const,
    acpId: "ACP-0002" as const,
    acpStatus: "Proposed" as const,
    network: {
      profileId: input.profileId ?? "local-hardhat",
      chainId: input.chainId,
      networkName: input.profileId ?? "local-hardhat",
      liveNetwork: false,
      productionApproved: false
    },
    entryPoint: {
      version: PHILCORE_4337_ENTRYPOINT_VERSION,
      address: normalizeAddress(input.entryPointAddress),
      packageName: "@account-abstraction/contracts" as const,
      packageVersion: "0.7.0" as const
    },
    account: {
      contractName: "PhilCore4337Account" as const,
      executeSelector: PHILCORE_4337_EXECUTE_SELECTOR,
      directOwnerExecuteAllowed: false as const,
      entryPointExecuteAllowed: true as const,
      selfExecuteAllowed: false as const,
      approvedActionGate: normalizeAddress(input.approvedActionGateAddress),
      allowedTarget: "approved_action_gate" as const,
      allowedSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
      batchExecution: false as const
    },
    factory: {
      contractName: "PhilCore4337AccountFactory" as const,
      address: normalizeAddress(input.factoryAddress),
      createAccountSelector: PHILCORE_4337_FACTORY_CREATE_ACCOUNT_SELECTOR,
      deploymentModel: "create2" as const,
      approvedActionGate: normalizeAddress(input.approvedActionGateAddress)
    },
    validator: {
      model: "ecdsa_owner" as const,
      signatureFormat: "eth_sign_entrypoint_userop_hash_eip191" as const,
      owner: normalizeAddress(input.owner),
      ownerCommitment: normalizeHex(input.ownerCommitment, 32),
      paymaster: "disabled" as const,
      sessionKeys: "disabled" as const
    }
  });
}

export function createBaseExecutionDraftFixture(input: {
  readonly draftId?: string;
  readonly actionGateAddress: string;
  readonly senderAccount: string;
  readonly ownerCommitment: Hex;
  readonly proofInputHash: Hex;
  readonly nullifier: Hex;
  readonly calldata: Hex;
  readonly chainId: number;
  readonly value?: string | bigint | number;
  readonly issuedAt?: string;
  readonly expiresAt?: string;
}): BaseAuthorizationExecutionTransactionDraft {
  const calldataHash = keccak256(input.calldata) as Hex;
  const value = BigInt(input.value ?? 0n).toString();
  const issuedAt = input.issuedAt ?? nowIso();
  const expiresAt = input.expiresAt ?? new Date(Date.now() + 300_000).toISOString();
  return freezeRecord({
    baseAuthorizationExecutionTransactionDraftId: input.draftId ?? createAuditCorrelationId([
      calldataHash,
      "fixture-base-execution-draft"
    ]),
    status: "execution_transaction_draft_created" as const,
    outcome: "execution_transaction_draft_created" as const,
    binding: {
      finalizedAuthorizationPackageId: "fixture-finalized-package",
      authoritativeCapabilityGrantId: "fixture-capability-grant",
      sessionId: "fixture-session",
      applicationId: "ethereum-net",
      ownerCommitment: input.ownerCommitment,
      actionHash: normalizeHex(`0x${"a1".repeat(32)}`, 32),
      policyHash: normalizeHex(`0x${"b2".repeat(32)}`, 32),
      nullifier: input.nullifier,
      proofInputHash: input.proofInputHash,
      factHigh: normalizeHex(`0x${input.proofInputHash.slice(2).padStart(64, "0").slice(0, 32)}`, 16),
      factLow: normalizeHex(`0x${input.proofInputHash.slice(2).padStart(64, "0").slice(32)}`, 16),
      actionGateAddress: normalizeAddress(input.actionGateAddress),
      verifierAddress: normalizeAddress("0x0000000000000000000000000000000000000001"),
      baseMirrorAddress: normalizeAddress("0x0000000000000000000000000000000000000002"),
      consumerAddress: normalizeAddress("0x0000000000000000000000000000000000000003"),
      senderAccount: normalizeAddress(input.senderAccount),
      value,
      calldataHash,
      consumerDataHash: normalizeHex(`0x${"c3".repeat(32)}`, 32),
      auditCorrelationId: "fixture-audit"
    },
    to: normalizeAddress(input.actionGateAddress),
    from: normalizeAddress(input.senderAccount),
    chainId: input.chainId,
    methodName: "verifyAndConsume" as const,
    methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    calldata: input.calldata,
    calldataHash,
    value,
    consumerCallPreview: {
      account: normalizeAddress(input.senderAccount),
      target: normalizeAddress(input.actionGateAddress),
      value,
      callData: input.calldata,
      callDataHash: calldataHash,
      consumerData: input.calldata,
      consumerDataHash: calldataHash,
      actionHash: normalizeHex(`0x${"a1".repeat(32)}`, 32)
    },
    nullifierState: {
      status: "nullifier_available" as const,
      actionGateAddress: normalizeAddress(input.actionGateAddress),
      nullifier: input.nullifier,
      checkedAt: nowIso(),
      nullifierConsumed: false,
      nullifierReserved: false,
      baseStateMutated: false
    },
    gas: {
      status: "estimated" as const,
      gasLimit: "900000",
      source: "fixture" as const,
      checkedAt: nowIso()
    },
    nonce: {
      status: "resolved" as const,
      nonce: "0",
      source: "fixture" as const,
      checkedAt: nowIso()
    },
    fee: {
      status: "resolved" as const,
      maxFeePerGas: "30000000000",
      maxPriorityFeePerGas: "1000000000",
      source: "fixture" as const,
      checkedAt: nowIso()
    },
    issuedAt,
    expiresAt,
    transactionPrepared: true as const,
    transactionSigned: false as const,
    transactionSubmitted: false as const,
    simulationPerformed: false,
    simulationSucceeded: false,
    nullifierConsumed: false as const,
    consumerExecuted: false as const,
    baseStateMutated: false as const,
    userOperationCreated: false as const,
    applicationCanSubmitDirectly: false as const,
    liveMirroredFactEvidence: false,
    productionSignable: false
  }) as BaseAuthorizationExecutionTransactionDraft;
}

export function summarizePhilCore4337UserOperationDraft(
  draft: PhilCorePackedUserOperationDraft
): Readonly<Record<string, unknown>> {
  const gasLimits = unpackPhilCore4337Uints(draft.userOperation.accountGasLimits);
  const gasFees = unpackPhilCore4337Uints(draft.userOperation.gasFees);
  return freezeRecord({
    entryPointVersion: draft.entryPointVersion,
    sender: draft.userOperation.sender,
    nonce: draft.userOperation.nonce,
    accountState: draft.accountState,
    initCodeBytes: dataLength(draft.userOperation.initCode),
    callDataHash: keccak256(draft.userOperation.callData),
    userOperationHash: draft.binding.userOperationHash,
    verificationGasLimit: gasLimits.high128,
    callGasLimit: gasLimits.low128,
    maxPriorityFeePerGas: gasFees.high128,
    maxFeePerGas: gasFees.low128,
    preVerificationGas: draft.userOperation.preVerificationGas,
    paymasterDisabled: draft.userOperation.paymasterAndData === PHILCORE_4337_EMPTY_BYTES,
    signatureUnresolved: draft.userOperation.signature === PHILCORE_4337_EMPTY_BYTES,
    userOperationPrepared: draft.userOperationPrepared,
    userOperationSigned: draft.userOperationSigned,
    userOperationSubmitted: draft.userOperationSubmitted,
    bundlerSubmissionPerformed: draft.bundlerSubmissionPerformed,
    nullifierConsumed: draft.nullifierConsumed,
    consumerExecuted: draft.consumerExecuted,
    baseStateMutated: draft.baseStateMutated
  });
}
