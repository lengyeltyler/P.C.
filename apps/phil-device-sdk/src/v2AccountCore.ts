import {
  getAddress,
  isHexString,
  keccak256,
  toUtf8Bytes,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION,
  PHILCORE_V2_RECOVERY_THRESHOLD,
  PHILCORE_V2_VALIDATOR_VERIFIER_KIND,
  computePhilCoreV2RecoveryConfigurationHash,
  computePhilCoreV2ValidatorCommitment
} from "./v2Authorization.ts";
import {
  PHILCORE_V2_ACCOUNT_VERSION_ID,
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_NONCE_KEY,
  PHILCORE_V2_SECURITY_MODEL_ID,
  computePhilCoreV2FundLifecycleDigest,
  decomposePhilCoreV2Nonce,
  encodePhilCoreV2Intent,
  type PhilCoreV2ActionPayloadInput,
  type PhilCoreV2FundLifecycleInput
} from "./v2Intent.ts";
import {
  verifyPhilCoreV2Authorization,
  type PhilCoreV2AuthorizationPackage,
  type PhilCoreV2AuthorizationVerificationResult
} from "./v2AuthorizationEngine.ts";
import {
  beginPhilCoreV2Recovery,
  cancelPhilCoreV2Recovery,
  consumePhilCoreV2AuthorizationLocally,
  createPhilCoreV2ValidatorState,
  rotatePhilCoreV2ValidatorState,
  type PhilCoreV2AuthorityVerifier,
  type PhilCoreV2ValidatorState,
  type PhilCoreV2ValidatorStateInput
} from "./v2Validator.ts";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const MAX_UINT64 = (1n << 64n) - 1n;
const issuedValidationContexts = new WeakSet<object>();
const consumedValidationContexts = new WeakSet<object>();

export const PHILCORE_V2_ACCOUNT_CORE_FORMAT =
  "philcore-v2-account-core-local-prototype-v1" as const;
export const PHILCORE_V2_ACCOUNT_VALIDATION_CONTEXT_FORMAT =
  "philcore-v2-account-validation-context-local-v1" as const;
export const PHILCORE_V2_RECOVERY_DELAY_SECONDS = 172800n;
export const PHILCORE_V2_RECOVERY_EXPIRY_SECONDS = 604800n;

export type PhilCoreV2AccountRecoveryLifecycle =
  | "NORMAL"
  | "RECOVERY_ACTIVE"
  | "RECOVERY_COMPLETED"
  | "RECOVERY_CANCELLED";

export interface PhilCoreV2AccountImmutableInput {
  readonly chainId: BigNumberish;
  readonly entryPoint: string;
  readonly account: string;
  readonly ownerCommitment: Hex;
  readonly factoryBinding: string;
  readonly accountVersionId: Hex;
  readonly securityModelId: Hex;
  readonly confirmationTarget: string;
  readonly recoveryDelaySeconds: BigNumberish;
  readonly recoveryExpirySeconds: BigNumberish;
}

export interface PhilCoreV2AccountImmutable {
  readonly chainId: bigint;
  readonly entryPoint: string;
  readonly account: string;
  readonly ownerCommitment: Hex;
  readonly factoryBinding: string;
  readonly accountVersionId: Hex;
  readonly securityModelId: Hex;
  readonly confirmationTarget: string;
  readonly recoveryDelaySeconds: bigint;
  readonly recoveryExpirySeconds: bigint;
  readonly upgradeable: false;
  readonly administrator: null;
  readonly upgradeKey: null;
  readonly arbitraryExecutionEnabled: false;
  readonly delegatecallEnabled: false;
  readonly modulesEnabled: false;
  readonly sessionKeysEnabled: false;
  readonly paymastersEnabled: false;
}

export interface PhilCoreV2NonceSequencesInput {
  readonly ordinary: BigNumberish;
  readonly maintenance: BigNumberish;
  readonly recovery: BigNumberish;
}

export interface PhilCoreV2NonceSequences {
  readonly ordinary: bigint;
  readonly maintenance: bigint;
  readonly recovery: bigint;
}

export interface PhilCoreV2PendingRecovery {
  readonly requestId: Hex;
  readonly proposedValidator: string;
  readonly proposedValidatorKeyIdBinding: Hex;
  readonly proposedValidatorEpoch: bigint;
  readonly sourceValidatorEpoch: bigint;
  readonly sourceRecoveryEpoch: bigint;
  readonly requestedAt: bigint;
  readonly executableAfter: bigint;
  readonly expiresAt: bigint;
  readonly authorizationEvidenceCommitment: Hex;
}

export interface PhilCoreV2AccountStateInput {
  readonly immutable: PhilCoreV2AccountImmutableInput;
  readonly validatorState: PhilCoreV2ValidatorStateInput;
  readonly nonceSequences: PhilCoreV2NonceSequencesInput;
  readonly validatorCommitment: Hex;
  readonly securityConfigurationHash: Hex;
  readonly primaryDeviceFactorCommitment: Hex;
  readonly hardwareSecurityKeyCommitment: Hex;
  readonly recoveryFactorCommitment: Hex;
  readonly executionLocked?: boolean;
  readonly recoveryLifecycle?: PhilCoreV2AccountRecoveryLifecycle;
  readonly pendingRecovery?: PhilCoreV2PendingRecovery | null;
}

export interface PhilCoreV2AccountState {
  readonly format: typeof PHILCORE_V2_ACCOUNT_CORE_FORMAT;
  readonly immutable: PhilCoreV2AccountImmutable;
  readonly validatorState: PhilCoreV2ValidatorState;
  readonly nonceSequences: PhilCoreV2NonceSequences;
  readonly validatorCommitment: Hex;
  readonly securityConfigurationHash: Hex;
  readonly primaryDeviceFactorCommitment: Hex;
  readonly hardwareSecurityKeyCommitment: Hex;
  readonly recoveryFactorCommitment: Hex;
  readonly executionLocked: boolean;
  readonly recoveryLifecycle: PhilCoreV2AccountRecoveryLifecycle;
  readonly pendingRecovery: PhilCoreV2PendingRecovery | null;
  readonly publicMutationCount: 0;
}

export interface PhilCoreV2FundLifecycleGate {
  readonly lifecycle: PhilCoreV2FundLifecycleInput;
  readonly releasePathVerified: true;
  readonly residualHandlingBound: true;
  readonly finalStateVerificationRequired: true;
  readonly separateReleaseAuthorizationRequired: true;
}

export interface PhilCoreV2AccountValidationRequest {
  readonly state: PhilCoreV2AccountState;
  readonly caller: string;
  readonly keyedNonce: BigNumberish;
  readonly userOperationHashBinding: Hex;
  readonly authorizationPackage: PhilCoreV2AuthorizationPackage;
  readonly currentTime: BigNumberish;
  readonly authorityVerifier: PhilCoreV2AuthorityVerifier;
  readonly fundLifecycleGate?: PhilCoreV2FundLifecycleGate;
  readonly paymasterPresent?: boolean;
  readonly arbitraryTarget?: never;
  readonly arbitraryCalldata?: never;
  readonly delegatecall?: never;
  readonly module?: never;
  readonly sessionKey?: never;
}

export const PHILCORE_V2_ACCOUNT_FAILURE_CODES = Object.freeze([
  "ACCOUNT_STATE_INVALID",
  "CALLER_NOT_ENTRYPOINT",
  "EXECUTION_LOCKED",
  "UNRESTRICTED_EXECUTION_PROHIBITED",
  "USER_OPERATION_BINDING_MISMATCH",
  "NONCE_KEY_UNSUPPORTED",
  "NONCE_STALE",
  "NONCE_FUTURE",
  "NONCE_ENVELOPE_MISMATCH",
  "ACTION_NOT_IMPLEMENTED",
  "CONFIRMATION_TARGET_MISMATCH",
  "PAYMASTER_PROHIBITED",
  "FUND_LIFECYCLE_REQUIRED",
  "FUND_LIFECYCLE_INVALID",
  "FUND_LIFECYCLE_MISMATCH",
  "RELEASE_PATH_UNVERIFIED",
  "AUTHORIZATION_REJECTED"
] as const);

export type PhilCoreV2AccountFailureCode =
  typeof PHILCORE_V2_ACCOUNT_FAILURE_CODES[number];

export type PhilCoreV2TypedExecutionDraft =
  | Readonly<{
      kind: "CONFIRM";
      target: string;
      confirmationDigest: Hex;
      valueWei: 0n;
      calldataMode: "fixed_confirmation_selector";
    }>
  | Readonly<{
      kind: "NATIVE_TRANSFER";
      recipient: string;
      amountWei: bigint;
      calldata: "0x";
    }>
  | Readonly<{
      kind: "ERC20_TRANSFER";
      token: string;
      recipient: string;
      amount: bigint;
      selector: "transfer(address,uint256)";
    }>
  | Readonly<{
      kind: "ERC721_SAFE_TRANSFER";
      token: string;
      recipient: string;
      tokenId: bigint;
      receiverDataHash: Hex;
      selector: "safeTransferFrom(address,address,uint256,bytes)";
    }>
  | Readonly<{
      kind: "ERC1155_SAFE_TRANSFER";
      token: string;
      recipient: string;
      tokenId: bigint;
      amount: bigint;
      receiverDataHash: Hex;
      selector: "safeTransferFrom(address,address,uint256,uint256,bytes)";
    }>
  | Readonly<{
      kind: "VALIDATOR_ROTATION";
      proposedValidator: string;
      proposedValidatorKeyIdBinding: Hex;
      proposedValidatorEpoch: bigint;
    }>
  | Readonly<{
      kind: "RECOVERY_REQUEST";
      requestId: Hex;
      proposedValidator: string;
      proposedValidatorKeyIdBinding: Hex;
      proposedValidatorEpoch: bigint;
    }>
  | Readonly<{
      kind: "RECOVERY_CANCEL";
      requestId: Hex;
    }>;

export type PhilCoreV2AccountValidationResult =
  | Readonly<{
      accepted: true;
      status: "accepted";
      classification: "LOCAL_ACCOUNT_VALIDATION_ACCEPTED_NON_EXECUTABLE";
      format: typeof PHILCORE_V2_ACCOUNT_VALIDATION_CONTEXT_FORMAT;
      authorization: Extract<
        PhilCoreV2AuthorizationVerificationResult,
        { accepted: true }
      >;
      action: PhilCoreV2TypedExecutionDraft;
      nonceKey: bigint;
      nonceSequence: bigint;
      validatedStateBinding: Hex;
      fundLifecycleEnforced: boolean;
      executionPerformed: false;
      externalCallPerformed: false;
      fundsMoved: false;
      userOperationCreated: false;
      signatureProduced: false;
      publicMutationCount: 0;
    }>
  | Readonly<{
      accepted: false;
      status: "rejected";
      code: PhilCoreV2AccountFailureCode;
      authorizationFailureCode?: string;
      executionPerformed: false;
      externalCallPerformed: false;
      fundsMoved: false;
      userOperationCreated: false;
      signatureProduced: false;
      publicMutationCount: 0;
    }>;

export interface PhilCoreV2LocalTransitionResult {
  readonly state: PhilCoreV2AccountState;
  readonly action: PhilCoreV2TypedExecutionDraft;
  readonly stateTransitionAppliedLocally: true;
  readonly executionPerformed: false;
  readonly externalCallPerformed: false;
  readonly fundsMoved: false;
  readonly userOperationCreated: false;
  readonly signatureProduced: false;
  readonly publicMutationCount: 0;
}

function uint(value: BigNumberish, bits: number, label: string): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  return parsed;
}

function bytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  if (value === `0x${"00".repeat(32)}`) {
    throw new Error(`${label}_must_be_nonzero`);
  }
  return value.toLowerCase() as Hex;
}

function address(value: string, label: string, allowZero = false): string {
  let normalized: string;
  try {
    normalized = getAddress(value);
  } catch {
    throw new Error(`${label}_must_be_address`);
  }
  if (!allowZero && normalized === ZERO_ADDRESS) {
    throw new Error(`${label}_must_be_nonzero`);
  }
  return normalized;
}

function sameAddress(left: string, right: string): boolean {
  try {
    return getAddress(left) === getAddress(right);
  } catch {
    return false;
  }
}

function nonceSequences(
  input: PhilCoreV2NonceSequencesInput
): PhilCoreV2NonceSequences {
  return Object.freeze({
    ordinary: uint(input.ordinary, 64, "ordinaryNonceSequence"),
    maintenance: uint(input.maintenance, 64, "maintenanceNonceSequence"),
    recovery: uint(input.recovery, 64, "recoveryNonceSequence")
  });
}

function expectedSequence(
  sequences: PhilCoreV2NonceSequences,
  key: bigint
): bigint | undefined {
  if (key === PHILCORE_V2_NONCE_KEY.ORDINARY) return sequences.ordinary;
  if (key === PHILCORE_V2_NONCE_KEY.MAINTENANCE) {
    return sequences.maintenance;
  }
  if (key === PHILCORE_V2_NONCE_KEY.RECOVERY) return sequences.recovery;
  return undefined;
}

function incrementSequence(
  sequences: PhilCoreV2NonceSequences,
  key: bigint
): PhilCoreV2NonceSequences {
  const current = expectedSequence(sequences, key);
  if (current === undefined) throw new Error("nonce_key_unsupported");
  if (current === MAX_UINT64) throw new Error("nonce_sequence_exhausted");
  return Object.freeze({
    ordinary: key === 0n ? current + 1n : sequences.ordinary,
    maintenance: key === 1n ? current + 1n : sequences.maintenance,
    recovery: key === 2n ? current + 1n : sequences.recovery
  });
}

function normalizePendingRecovery(
  pending: PhilCoreV2PendingRecovery | null | undefined
): PhilCoreV2PendingRecovery | null {
  if (!pending) return null;
  const requestedAt = uint(pending.requestedAt, 48, "requestedAt");
  const executableAfter = uint(
    pending.executableAfter,
    48,
    "executableAfter"
  );
  const expiresAt = uint(pending.expiresAt, 48, "expiresAt");
  if (!(requestedAt < executableAfter && executableAfter < expiresAt)) {
    throw new Error("pendingRecovery_timing_invalid");
  }
  return Object.freeze({
    requestId: bytes32(pending.requestId, "recoveryRequestId"),
    proposedValidator: address(
      pending.proposedValidator,
      "proposedValidator"
    ),
    proposedValidatorKeyIdBinding: bytes32(
      pending.proposedValidatorKeyIdBinding,
      "proposedValidatorKeyIdBinding"
    ),
    proposedValidatorEpoch: uint(
      pending.proposedValidatorEpoch,
      64,
      "proposedValidatorEpoch"
    ),
    sourceValidatorEpoch: uint(
      pending.sourceValidatorEpoch,
      64,
      "sourceValidatorEpoch"
    ),
    sourceRecoveryEpoch: uint(
      pending.sourceRecoveryEpoch,
      64,
      "sourceRecoveryEpoch"
    ),
    requestedAt,
    executableAfter,
    expiresAt,
    authorizationEvidenceCommitment: bytes32(
      pending.authorizationEvidenceCommitment,
      "authorizationEvidenceCommitment"
    )
  });
}

export function createPhilCoreV2AccountState(
  input: PhilCoreV2AccountStateInput
): PhilCoreV2AccountState {
  const immutable = Object.freeze({
    chainId: uint(input.immutable.chainId, 256, "chainId"),
    entryPoint: address(input.immutable.entryPoint, "entryPoint"),
    account: address(input.immutable.account, "account"),
    ownerCommitment: bytes32(
      input.immutable.ownerCommitment,
      "ownerCommitment"
    ),
    factoryBinding: address(
      input.immutable.factoryBinding,
      "factoryBinding"
    ),
    accountVersionId: bytes32(
      input.immutable.accountVersionId,
      "accountVersionId"
    ),
    securityModelId: bytes32(
      input.immutable.securityModelId,
      "securityModelId"
    ),
    confirmationTarget: address(
      input.immutable.confirmationTarget,
      "confirmationTarget"
    ),
    recoveryDelaySeconds: uint(
      input.immutable.recoveryDelaySeconds,
      48,
      "recoveryDelaySeconds"
    ),
    recoveryExpirySeconds: uint(
      input.immutable.recoveryExpirySeconds,
      48,
      "recoveryExpirySeconds"
    ),
    upgradeable: false,
    administrator: null,
    upgradeKey: null,
    arbitraryExecutionEnabled: false,
    delegatecallEnabled: false,
    modulesEnabled: false,
    sessionKeysEnabled: false,
    paymastersEnabled: false
  } satisfies PhilCoreV2AccountImmutable);
  if (immutable.chainId === 0n) throw new Error("chainId_must_be_nonzero");
  if (immutable.accountVersionId !== PHILCORE_V2_ACCOUNT_VERSION_ID) {
    throw new Error("accountVersionId_unsupported");
  }
  if (immutable.securityModelId !== PHILCORE_V2_SECURITY_MODEL_ID) {
    throw new Error("securityModelId_unsupported");
  }
  if (
    immutable.recoveryDelaySeconds !== PHILCORE_V2_RECOVERY_DELAY_SECONDS
    || immutable.recoveryExpirySeconds
      !== PHILCORE_V2_RECOVERY_EXPIRY_SECONDS
  ) {
    throw new Error("recovery_timing_not_canonical");
  }
  const validatorState = createPhilCoreV2ValidatorState(
    input.validatorState
  );
  if (
    validatorState.chainId !== immutable.chainId
    || validatorState.entryPoint !== immutable.entryPoint
    || validatorState.account !== immutable.account
    || validatorState.ownerCommitment !== immutable.ownerCommitment
  ) {
    throw new Error("validatorState_immutable_binding_mismatch");
  }
  const validatorCommitment = bytes32(
    input.validatorCommitment,
    "validatorCommitment"
  );
  if (
    validatorCommitment !== computePhilCoreV2ValidatorCommitment({
      verifierKind: PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
      validator: validatorState.validator,
      validatorKeyIdBinding: validatorState.validatorKeyIdBinding
    })
  ) {
    throw new Error("validatorCommitment_state_mismatch");
  }
  const securityConfigurationHash = bytes32(
    input.securityConfigurationHash,
    "securityConfigurationHash"
  );
  const primaryDeviceFactorCommitment = bytes32(
    input.primaryDeviceFactorCommitment,
    "primaryDeviceFactorCommitment"
  );
  const hardwareSecurityKeyCommitment = bytes32(
    input.hardwareSecurityKeyCommitment,
    "hardwareSecurityKeyCommitment"
  );
  const recoveryFactorCommitment = bytes32(
    input.recoveryFactorCommitment,
    "recoveryFactorCommitment"
  );
  if (
    securityConfigurationHash !== validatorState.recoveryConfigHash
    || securityConfigurationHash
      !== computePhilCoreV2RecoveryConfigurationHash({
        configurationVersion: PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION,
        threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
        primaryDeviceCommitment: primaryDeviceFactorCommitment,
        hardwareSecurityKeyCommitment: hardwareSecurityKeyCommitment,
        recoveryFactorCommitment
      })
  ) {
    throw new Error("securityConfigurationHash_state_mismatch");
  }
  const recoveryLifecycle = input.recoveryLifecycle ?? "NORMAL";
  if (
    recoveryLifecycle !== "NORMAL"
    && recoveryLifecycle !== "RECOVERY_ACTIVE"
    && recoveryLifecycle !== "RECOVERY_COMPLETED"
    && recoveryLifecycle !== "RECOVERY_CANCELLED"
  ) {
    throw new Error("recoveryLifecycle_unsupported");
  }
  const pendingRecovery = normalizePendingRecovery(input.pendingRecovery);
  if (
    (recoveryLifecycle === "RECOVERY_ACTIVE")
      !== (pendingRecovery !== null)
    || (recoveryLifecycle === "RECOVERY_ACTIVE")
      !== (validatorState.recoveryState === "recovery_active")
  ) {
    throw new Error("recoveryLifecycle_state_mismatch");
  }
  if (
    recoveryLifecycle !== "RECOVERY_ACTIVE"
    && validatorState.recoveryState === "recovery_active"
  ) {
    throw new Error("recoveryLifecycle_state_mismatch");
  }
  return Object.freeze({
    format: PHILCORE_V2_ACCOUNT_CORE_FORMAT,
    immutable,
    validatorState,
    nonceSequences: nonceSequences(input.nonceSequences),
    validatorCommitment,
    securityConfigurationHash,
    primaryDeviceFactorCommitment,
    hardwareSecurityKeyCommitment,
    recoveryFactorCommitment,
    executionLocked: input.executionLocked === true,
    recoveryLifecycle,
    pendingRecovery,
    publicMutationCount: 0
  });
}

function rejected(
  code: PhilCoreV2AccountFailureCode,
  authorizationFailureCode?: string
): PhilCoreV2AccountValidationResult {
  return Object.freeze({
    accepted: false,
    status: "rejected",
    code,
    ...(authorizationFailureCode === undefined
      ? {}
      : { authorizationFailureCode }),
    executionPerformed: false,
    externalCallPerformed: false,
    fundsMoved: false,
    userOperationCreated: false,
    signatureProduced: false,
    publicMutationCount: 0
  });
}

function accountStateBinding(state: PhilCoreV2AccountState): Hex {
  const serialized = JSON.stringify(state, (_key, value) =>
    typeof value === "bigint" ? value.toString(10) : value
  );
  return keccak256(toUtf8Bytes(serialized)) as Hex;
}

function isValueMoving(payload: PhilCoreV2ActionPayloadInput): boolean {
  return payload.kind === "NATIVE_TRANSFER"
    || payload.kind === "ERC20_TRANSFER"
    || payload.kind === "ERC721_SAFE_TRANSFER"
    || payload.kind === "ERC1155_SAFE_TRANSFER";
}

function validateFundLifecycle(input: {
  readonly state: PhilCoreV2AccountState;
  readonly payload: PhilCoreV2ActionPayloadInput;
  readonly expectedDigest: Hex;
  readonly gate?: PhilCoreV2FundLifecycleGate;
}): PhilCoreV2AccountFailureCode | undefined {
  if (!isValueMoving(input.payload)) return undefined;
  if (!input.gate) return "FUND_LIFECYCLE_REQUIRED";
  if (
    input.gate.releasePathVerified !== true
    || input.gate.residualHandlingBound !== true
    || input.gate.finalStateVerificationRequired !== true
    || input.gate.separateReleaseAuthorizationRequired !== true
  ) {
    return "RELEASE_PATH_UNVERIFIED";
  }
  let digest: Hex;
  try {
    digest = computePhilCoreV2FundLifecycleDigest(input.gate.lifecycle);
  } catch {
    return "FUND_LIFECYCLE_INVALID";
  }
  if (
    digest !== input.expectedDigest.toLowerCase()
    || !sameAddress(
      input.gate.lifecycle.account,
      input.state.immutable.account
    )
    || sameAddress(input.gate.lifecycle.residualRecipient, ZERO_ADDRESS)
  ) {
    return "FUND_LIFECYCLE_MISMATCH";
  }
  const payload = input.payload;
  let expectedAsset: string;
  switch (payload.kind) {
    case "NATIVE_TRANSFER":
      expectedAsset = ZERO_ADDRESS;
      break;
    case "ERC20_TRANSFER":
    case "ERC721_SAFE_TRANSFER":
    case "ERC1155_SAFE_TRANSFER":
      expectedAsset = payload.token;
      break;
    default:
      return "FUND_LIFECYCLE_INVALID";
  }
  const expectedTokenId =
    payload.kind === "ERC721_SAFE_TRANSFER"
    || payload.kind === "ERC1155_SAFE_TRANSFER"
      ? BigInt(payload.tokenId)
      : 0n;
  if (
    !sameAddress(input.gate.lifecycle.asset, expectedAsset)
    || BigInt(input.gate.lifecycle.tokenId) !== expectedTokenId
    || BigInt(input.gate.lifecycle.expectedFinalBalance)
      > BigInt(input.gate.lifecycle.maximumStranded)
  ) {
    return "FUND_LIFECYCLE_MISMATCH";
  }
  const authorizedAmount =
    payload.kind === "NATIVE_TRANSFER"
    || payload.kind === "ERC20_TRANSFER"
    || payload.kind === "ERC1155_SAFE_TRANSFER"
      ? BigInt(
        payload.kind === "NATIVE_TRANSFER"
          ? payload.amountWei
          : payload.amount
      )
      : 1n;
  if (
    authorizedAmount
      > BigInt(input.gate.lifecycle.maximumFundingOrHolding)
  ) {
    return "FUND_LIFECYCLE_MISMATCH";
  }
  return undefined;
}

function typedAction(
  payload: PhilCoreV2ActionPayloadInput,
  authorizedIntentHash: Hex
): PhilCoreV2TypedExecutionDraft | undefined {
  switch (payload.kind) {
    case "CONFIRM":
      return Object.freeze({
        kind: payload.kind,
        target: getAddress(payload.confirmationTarget),
        confirmationDigest: payload.confirmationDigest.toLowerCase() as Hex,
        valueWei: 0n,
        calldataMode: "fixed_confirmation_selector"
      });
    case "NATIVE_TRANSFER":
      return Object.freeze({
        kind: payload.kind,
        recipient: getAddress(payload.recipient),
        amountWei: BigInt(payload.amountWei),
        calldata: "0x"
      });
    case "ERC20_TRANSFER":
      return Object.freeze({
        kind: payload.kind,
        token: getAddress(payload.token),
        recipient: getAddress(payload.recipient),
        amount: BigInt(payload.amount),
        selector: "transfer(address,uint256)"
      });
    case "ERC721_SAFE_TRANSFER":
      return Object.freeze({
        kind: payload.kind,
        token: getAddress(payload.token),
        recipient: getAddress(payload.recipient),
        tokenId: BigInt(payload.tokenId),
        receiverDataHash: payload.receiverDataHash.toLowerCase() as Hex,
        selector: "safeTransferFrom(address,address,uint256,bytes)"
      });
    case "ERC1155_SAFE_TRANSFER":
      return Object.freeze({
        kind: payload.kind,
        token: getAddress(payload.token),
        recipient: getAddress(payload.recipient),
        tokenId: BigInt(payload.tokenId),
        amount: BigInt(payload.amount),
        receiverDataHash: payload.receiverDataHash.toLowerCase() as Hex,
        selector: "safeTransferFrom(address,address,uint256,uint256,bytes)"
      });
    case "VALIDATOR_ROTATION":
      return Object.freeze({
        kind: payload.kind,
        proposedValidator: getAddress(payload.proposedValidator),
        proposedValidatorKeyIdBinding:
          payload.proposedValidatorKeyIdBinding.toLowerCase() as Hex,
        proposedValidatorEpoch: BigInt(payload.proposedValidatorEpoch)
      });
    case "RECOVERY_REQUEST":
      return Object.freeze({
        kind: payload.kind,
        requestId: authorizedIntentHash,
        proposedValidator: getAddress(payload.proposedValidator),
        proposedValidatorKeyIdBinding:
          payload.proposedValidatorKeyIdBinding.toLowerCase() as Hex,
        proposedValidatorEpoch: BigInt(payload.proposedValidatorEpoch)
      });
    case "RECOVERY_CANCEL":
      return Object.freeze({
        kind: payload.kind,
        requestId: payload.recoveryRequestId.toLowerCase() as Hex
      });
    default:
      return undefined;
  }
}

export async function validatePhilCoreV2AccountOperation(
  request: PhilCoreV2AccountValidationRequest
): Promise<PhilCoreV2AccountValidationResult> {
  let state: PhilCoreV2AccountState;
  try {
    state = createPhilCoreV2AccountState(request.state);
  } catch {
    return rejected("ACCOUNT_STATE_INVALID");
  }
  if (!sameAddress(request.caller, state.immutable.entryPoint)) {
    return rejected("CALLER_NOT_ENTRYPOINT");
  }
  if (state.executionLocked) return rejected("EXECUTION_LOCKED");
  if (
    Object.hasOwn(request, "arbitraryTarget")
    || Object.hasOwn(request, "arbitraryCalldata")
    || Object.hasOwn(request, "delegatecall")
    || Object.hasOwn(request, "module")
    || Object.hasOwn(request, "sessionKey")
  ) {
    return rejected("UNRESTRICTED_EXECUTION_PROHIBITED");
  }
  if (request.paymasterPresent === true) {
    return rejected("PAYMASTER_PROHIBITED");
  }
  let nonce: ReturnType<typeof decomposePhilCoreV2Nonce>;
  let encoded: ReturnType<typeof encodePhilCoreV2Intent>;
  try {
    nonce = decomposePhilCoreV2Nonce(request.keyedNonce);
  } catch {
    return rejected("NONCE_ENVELOPE_MISMATCH");
  }
  try {
    encoded = encodePhilCoreV2Intent(request.authorizationPackage.intent);
  } catch {
    return rejected("AUTHORIZATION_REJECTED", "INTENT_INVALID");
  }
  const expected = expectedSequence(state.nonceSequences, nonce.key);
  if (expected === undefined) return rejected("NONCE_KEY_UNSUPPORTED");
  if (nonce.sequence < expected) return rejected("NONCE_STALE");
  if (nonce.sequence > expected) return rejected("NONCE_FUTURE");
  if (
    nonce.key !== encoded.header.nonceKey
    || nonce.sequence !== encoded.header.nonceSequence
  ) {
    return rejected("NONCE_ENVELOPE_MISMATCH");
  }
  const userOperationHash = request.userOperationHashBinding?.toLowerCase();
  if (
    typeof userOperationHash !== "string"
    || !isHexString(userOperationHash, 32)
    || userOperationHash
      !== request.authorizationPackage.userOperationHashBinding.toLowerCase()
  ) {
    return rejected("USER_OPERATION_BINDING_MISMATCH");
  }
  const action = typedAction(
    request.authorizationPackage.intent.payload,
    request.authorizationPackage.declaredAuthorizedIntentHash
      .toLowerCase() as Hex
  );
  if (!action) return rejected("ACTION_NOT_IMPLEMENTED");
  if (
    action.kind === "CONFIRM"
    && action.target !== state.immutable.confirmationTarget
  ) {
    return rejected("CONFIRMATION_TARGET_MISMATCH");
  }
  const fundFailure = validateFundLifecycle({
    state,
    payload: request.authorizationPackage.intent.payload,
    expectedDigest: encoded.header.fundLifecycleDigest,
    gate: request.fundLifecycleGate
  });
  if (fundFailure) return rejected(fundFailure);
  const authorization = await verifyPhilCoreV2Authorization({
    state: state.validatorState,
    authorizationPackage: request.authorizationPackage,
    currentTime: request.currentTime,
    authorityVerifier: request.authorityVerifier
  });
  if (!authorization.accepted) {
    return rejected("AUTHORIZATION_REJECTED", authorization.code);
  }
  const expectsNoStateTransition =
    action.kind === "CONFIRM"
    || action.kind === "NATIVE_TRANSFER"
    || action.kind === "ERC20_TRANSFER"
    || action.kind === "ERC721_SAFE_TRANSFER"
    || action.kind === "ERC1155_SAFE_TRANSFER";
  if (
    authorization.keyedNonce !== BigInt(request.keyedNonce)
    || (authorization.authorizedStateTransition === "none")
      !== expectsNoStateTransition
  ) {
    return rejected("NONCE_ENVELOPE_MISMATCH");
  }
  const accepted = Object.freeze({
    accepted: true,
    status: "accepted",
    classification: "LOCAL_ACCOUNT_VALIDATION_ACCEPTED_NON_EXECUTABLE",
    format: PHILCORE_V2_ACCOUNT_VALIDATION_CONTEXT_FORMAT,
    authorization,
    action,
    nonceKey: nonce.key,
    nonceSequence: nonce.sequence,
    validatedStateBinding: accountStateBinding(state),
    fundLifecycleEnforced: isValueMoving(
      request.authorizationPackage.intent.payload
    ),
    executionPerformed: false,
    externalCallPerformed: false,
    fundsMoved: false,
    userOperationCreated: false,
    signatureProduced: false,
    publicMutationCount: 0
  });
  issuedValidationContexts.add(accepted);
  return accepted;
}

function nextState(
  state: PhilCoreV2AccountState,
  changes: Partial<PhilCoreV2AccountStateInput>
): PhilCoreV2AccountState {
  return createPhilCoreV2AccountState({
    immutable: state.immutable,
    validatorState: state.validatorState,
    nonceSequences: state.nonceSequences,
    validatorCommitment: state.validatorCommitment,
    securityConfigurationHash: state.securityConfigurationHash,
    primaryDeviceFactorCommitment:
      state.primaryDeviceFactorCommitment,
    hardwareSecurityKeyCommitment:
      state.hardwareSecurityKeyCommitment,
    recoveryFactorCommitment: state.recoveryFactorCommitment,
    executionLocked: state.executionLocked,
    recoveryLifecycle: state.recoveryLifecycle,
    pendingRecovery: state.pendingRecovery,
    ...changes
  });
}

export function applyPhilCoreV2AccountTransitionLocally(input: {
  readonly state: PhilCoreV2AccountState;
  readonly validation: Extract<
    PhilCoreV2AccountValidationResult,
    { accepted: true }
  >;
  readonly currentTime: BigNumberish;
}): PhilCoreV2LocalTransitionResult {
  const state = createPhilCoreV2AccountState(input.state);
  const now = uint(input.currentTime, 48, "currentTime");
  if (
    !issuedValidationContexts.has(input.validation)
    || consumedValidationContexts.has(input.validation)
    || input.validation.format
      !== PHILCORE_V2_ACCOUNT_VALIDATION_CONTEXT_FORMAT
    || input.validation.publicMutationCount !== 0
    || input.validation.validatedStateBinding
      !== accountStateBinding(state)
    || expectedSequence(
      state.nonceSequences,
      input.validation.nonceKey
    ) !== input.validation.nonceSequence
  ) {
    throw new Error("validation_context_invalid");
  }
  consumedValidationContexts.add(input.validation);
  let validatorState = consumePhilCoreV2AuthorizationLocally({
    state: state.validatorState,
    authorizationDigest: input.validation.authorization.authorityDigest,
    nonceKey: input.validation.nonceKey,
    nonceSequence: input.validation.nonceSequence
  });
  let updated: PhilCoreV2AccountState;
  switch (input.validation.action.kind) {
    case "VALIDATOR_ROTATION":
      validatorState = rotatePhilCoreV2ValidatorState({
        state: validatorState,
        proposedValidator: input.validation.action.proposedValidator,
        proposedValidatorKeyIdBinding:
          input.validation.action.proposedValidatorKeyIdBinding,
        proposedValidatorEpoch:
          input.validation.action.proposedValidatorEpoch,
        mode: "normal_rotation"
      });
      updated = nextState(state, {
        validatorState,
        validatorCommitment: computePhilCoreV2ValidatorCommitment({
          verifierKind:
            PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
          validator: validatorState.validator,
          validatorKeyIdBinding: validatorState.validatorKeyIdBinding
        }),
        nonceSequences: incrementSequence(
          state.nonceSequences,
          input.validation.nonceKey
        )
      });
      break;
    case "RECOVERY_REQUEST": {
      validatorState = beginPhilCoreV2Recovery(validatorState);
      const pendingRecovery = Object.freeze({
        requestId: input.validation.action.requestId,
        proposedValidator: input.validation.action.proposedValidator,
        proposedValidatorKeyIdBinding:
          input.validation.action.proposedValidatorKeyIdBinding,
        proposedValidatorEpoch:
          input.validation.action.proposedValidatorEpoch,
        sourceValidatorEpoch: state.validatorState.validatorEpoch,
        sourceRecoveryEpoch: state.validatorState.recoveryEpoch,
        requestedAt: now,
        executableAfter:
          now + state.immutable.recoveryDelaySeconds,
        expiresAt: now + state.immutable.recoveryExpirySeconds,
        authorizationEvidenceCommitment:
          input.validation.authorization.authorityDigest
      });
      updated = nextState(state, {
        validatorState,
        nonceSequences: incrementSequence(
          state.nonceSequences,
          input.validation.nonceKey
        ),
        recoveryLifecycle: "RECOVERY_ACTIVE",
        pendingRecovery
      });
      break;
    }
    case "RECOVERY_CANCEL":
      if (
        !state.pendingRecovery
        || state.pendingRecovery.requestId
          !== input.validation.action.requestId
      ) {
        throw new Error("recovery_request_id_mismatch");
      }
      validatorState = cancelPhilCoreV2Recovery(validatorState);
      updated = nextState(state, {
        validatorState,
        nonceSequences: incrementSequence(
          state.nonceSequences,
          input.validation.nonceKey
        ),
        recoveryLifecycle: "RECOVERY_CANCELLED",
        pendingRecovery: null
      });
      break;
    default:
      updated = nextState(state, {
        validatorState,
        nonceSequences: incrementSequence(
          state.nonceSequences,
          input.validation.nonceKey
        )
      });
  }
  return Object.freeze({
    state: updated,
    action: input.validation.action,
    stateTransitionAppliedLocally: true,
    executionPerformed: false,
    externalCallPerformed: false,
    fundsMoved: false,
    userOperationCreated: false,
    signatureProduced: false,
    publicMutationCount: 0
  });
}

export function completePhilCoreV2RecoveryLocally(input: {
  readonly state: PhilCoreV2AccountState;
  readonly recoveryRequestId: Hex;
  readonly currentTime: BigNumberish;
}): PhilCoreV2AccountState {
  const state = createPhilCoreV2AccountState(input.state);
  const pending = state.pendingRecovery;
  const now = uint(input.currentTime, 48, "currentTime");
  if (
    state.recoveryLifecycle !== "RECOVERY_ACTIVE"
    || !pending
    || pending.requestId !== bytes32(
      input.recoveryRequestId,
      "recoveryRequestId"
    )
  ) {
    throw new Error("recovery_request_not_active");
  }
  if (now < pending.executableAfter) {
    throw new Error("recovery_delay_not_elapsed");
  }
  if (now >= pending.expiresAt) throw new Error("recovery_request_expired");
  if (
    pending.sourceValidatorEpoch !== state.validatorState.validatorEpoch
    || pending.sourceRecoveryEpoch !== state.validatorState.recoveryEpoch
  ) {
    throw new Error("recovery_source_epoch_changed");
  }
  const validatorState = rotatePhilCoreV2ValidatorState({
    state: state.validatorState,
    proposedValidator: pending.proposedValidator,
    proposedValidatorKeyIdBinding:
      pending.proposedValidatorKeyIdBinding,
    proposedValidatorEpoch: pending.proposedValidatorEpoch,
    proposedRecoveryEpoch: state.validatorState.recoveryEpoch + 1n,
    mode: "recovery_completion"
  });
  return nextState(state, {
    validatorState,
    validatorCommitment: computePhilCoreV2ValidatorCommitment({
      verifierKind:
        PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
      validator: validatorState.validator,
      validatorKeyIdBinding: validatorState.validatorKeyIdBinding
    }),
    recoveryLifecycle: "RECOVERY_COMPLETED",
    pendingRecovery: null
  });
}
