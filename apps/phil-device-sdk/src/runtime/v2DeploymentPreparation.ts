import {
  AbiCoder,
  Interface,
  concat,
  getAddress,
  getCreate2Address,
  isHexString,
  keccak256,
  type BigNumberish
} from "ethers";

import type { Hex } from "../hashes.ts";
import {
  PHILCORE_ENTRY_POINT_V07_ADDRESS,
  PHILCORE_V2_CREATE2_SALT_DOMAIN,
  PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
  PHILCORE_V2_SECURITY_MODEL_ID,
  PHILCORE_V2_SEPOLIA_CHAIN_ID
} from "../v2DeployableIdentity.ts";
import {
  PHILCORE_V2_VALIDATOR_VERIFIER_KIND,
  computePhilCoreV2ValidatorCommitment
} from "../v2Authorization.ts";
import { computePhilCoreV2ConsumerRecoveryConfigurationHash } from "../v2ConsumerRecovery.ts";
import {
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
  PHILCORE_V2_NONCE_KEY,
  PHILCORE_V2_PURPOSE,
  composePhilCoreV2Nonce,
  encodePhilCoreV2Intent
} from "../v2Intent.ts";
import {
  PHILCORE_4337_EMPTY_BYTES,
  computePhilCore4337UserOperationHash,
  packPhilCore4337AccountGasLimits,
  packPhilCore4337GasFees,
  type PhilCorePackedUserOperation
} from "./philcore4337UserOperationPreparation.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

const INITIALIZATION_TUPLE_COMPONENTS =
  "address entryPoint, uint256 deploymentChainId, bytes32 ownerCommitment, " +
  "bytes32 identityBindingCommitment, address factoryBinding, bytes32 accountVersionId, " +
  "bytes32 securityModelId, address confirmationTarget, address initialValidator, " +
  "uint8 validatorVerifierKind, bytes32 validatorKeyIdBinding, bytes32 validatorCommitment, " +
  "uint64 validatorEpoch, bytes32 primaryDeviceRecoveryCommitment, " +
  "bytes32 hardwareSecurityKeyCommitment, bytes32 independentRecoveryFactorCommitment, " +
  "bytes32 recoveryConfigurationHash, uint64 recoveryEpoch, uint64 recoveryDelaySeconds, " +
  "uint64 recoveryExpirySeconds";

const INTENT_CORE_HEADER_TUPLE_COMPONENTS =
  "uint8 specificationVersion, bytes32 securityModelId, uint8 actionType, bytes32 actionId, " +
  "bytes32 purpose, bytes32 ownerCommitment, uint256 chainId, address entryPoint, " +
  "address account, uint192 nonceKey, uint64 nonceSequence, uint64 validatorEpoch, " +
  "uint64 recoveryEpoch, bytes32 applicationContextHash, bytes32 fundLifecycleDigest, " +
  "uint256 maxTotalFeeWei, uint48 validAfter, uint48 validUntil";

const factoryInterface = new Interface([
  `function createAccount(tuple(${INITIALIZATION_TUPLE_COMPONENTS}) initialization, bytes32 userSalt) returns (address account)`,
  `function getAddress(tuple(${INITIALIZATION_TUPLE_COMPONENTS}) initialization, bytes32 userSalt) view returns (address)`
]);

const accountInterface = new Interface([
  `function confirmIntent(tuple(tuple(${INTENT_CORE_HEADER_TUPLE_COMPONENTS}) core, bytes32 runtimeAuthorizationDigest) intent, bytes32 confirmationDigest)`
]);

export const PHILCORE_V2_FACTORY_CREATE_ACCOUNT_SELECTOR =
  factoryInterface.getFunction("createAccount")?.selector as "0x10652e82";
export const PHILCORE_V2_FACTORY_GET_ADDRESS_SELECTOR =
  factoryInterface.getFunction("getAddress")?.selector as "0x135a58fd";
export const PHILCORE_V2_CONFIRM_INTENT_SELECTOR =
  accountInterface.getFunction("confirmIntent")?.selector as "0x2a44a457";

/**
 * Domain constants baked into `PhilCoreV2MinimalAccountV2` /
 * `PhilCoreV2MinimalAccountFactoryV2` for identity-binding, validator, and
 * recovery-configuration commitments. These are immutable, audited values;
 * they are not derived from labels and must not be changed independently of
 * the on-chain contracts.
 */
const IDENTITY_BINDING_TYPEHASH =
  "0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8" as Hex;
const OWNER_COMMITMENT_SCHEME_ID =
  "0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e" as Hex;

const PHILCORE_V2_INITIAL_VALIDATOR_EPOCH = 1n;
const PHILCORE_V2_INITIAL_RECOVERY_EPOCH = 1n;
const PHILCORE_V2_RECOVERY_DELAY_SECONDS = 172_800n;
const PHILCORE_V2_RECOVERY_EXPIRY_SECONDS = 604_800n;
const PHILCORE_V2_CONFIRM_MAX_VALIDITY_LIFETIME_SECONDS = 600n;

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_SCHEMA =
  "philcore-v2-sepolia-demo-preparation-v1" as const;

export const PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_ERROR_CODE = Object.freeze({
  FACTORY_ADDRESS_INVALID: "FACTORY_ADDRESS_INVALID",
  VERIFIER_ADDRESS_INVALID: "VERIFIER_ADDRESS_INVALID",
  CONFIRMATION_TARGET_ADDRESS_INVALID: "CONFIRMATION_TARGET_ADDRESS_INVALID",
  VALIDATOR_ADDRESS_INVALID: "VALIDATOR_ADDRESS_INVALID",
  VERIFIER_RUNTIME_CODE_HASH_INVALID: "VERIFIER_RUNTIME_CODE_HASH_INVALID",
  ENTRY_POINT_UNSUPPORTED: "ENTRY_POINT_UNSUPPORTED",
  CHAIN_ID_UNSUPPORTED: "CHAIN_ID_UNSUPPORTED",
  ACCOUNT_VERSION_UNSUPPORTED: "ACCOUNT_VERSION_UNSUPPORTED",
  SECURITY_MODEL_UNSUPPORTED: "SECURITY_MODEL_UNSUPPORTED",
  OWNER_COMMITMENT_INVALID: "OWNER_COMMITMENT_INVALID",
  IDENTITY_BINDING_COMMITMENT_MISMATCH: "IDENTITY_BINDING_COMMITMENT_MISMATCH",
  VALIDATOR_KEY_ID_BINDING_INVALID: "VALIDATOR_KEY_ID_BINDING_INVALID",
  VALIDATOR_COMMITMENT_MISMATCH: "VALIDATOR_COMMITMENT_MISMATCH",
  VALIDATOR_EPOCH_INVALID: "VALIDATOR_EPOCH_INVALID",
  RECOVERY_EPOCH_INVALID: "RECOVERY_EPOCH_INVALID",
  RECOVERY_COMMITMENT_INVALID: "RECOVERY_COMMITMENT_INVALID",
  RECOVERY_COMMITMENTS_NOT_DISTINCT: "RECOVERY_COMMITMENTS_NOT_DISTINCT",
  RECOVERY_CONFIGURATION_HASH_MISMATCH: "RECOVERY_CONFIGURATION_HASH_MISMATCH",
  RECOVERY_DELAY_SECONDS_INVALID: "RECOVERY_DELAY_SECONDS_INVALID",
  RECOVERY_EXPIRY_SECONDS_INVALID: "RECOVERY_EXPIRY_SECONDS_INVALID",
  USER_SALT_INVALID: "USER_SALT_INVALID",
  ACCOUNT_CREATION_BYTECODE_INVALID: "ACCOUNT_CREATION_BYTECODE_INVALID",
  ACTION_ID_INVALID: "ACTION_ID_INVALID",
  CONFIRMATION_DIGEST_INVALID: "CONFIRMATION_DIGEST_INVALID",
  RUNTIME_AUTHORIZATION_DIGEST_INVALID: "RUNTIME_AUTHORIZATION_DIGEST_INVALID",
  APPLICATION_CONTEXT_HASH_INVALID: "APPLICATION_CONTEXT_HASH_INVALID",
  FUND_LIFECYCLE_DIGEST_INVALID: "FUND_LIFECYCLE_DIGEST_INVALID",
  MAX_TOTAL_FEE_WEI_INVALID: "MAX_TOTAL_FEE_WEI_INVALID",
  VALIDITY_WINDOW_INVALID: "VALIDITY_WINDOW_INVALID",
  NONCE_SEQUENCE_INVALID: "NONCE_SEQUENCE_INVALID",
  GAS_FIELD_INVALID: "GAS_FIELD_INVALID"
} as const);

export type PhilCoreV2SepoliaDemoPreparationErrorCode =
  typeof PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_ERROR_CODE[
    keyof typeof PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_ERROR_CODE
  ];

export class PhilCoreV2SepoliaDemoPreparationError extends Error {
  readonly code: PhilCoreV2SepoliaDemoPreparationErrorCode;

  constructor(code: PhilCoreV2SepoliaDemoPreparationErrorCode, message?: string) {
    super(message ?? code);
    this.name = "PhilCoreV2SepoliaDemoPreparationError";
    this.code = code;
  }
}

function fail(
  code: PhilCoreV2SepoliaDemoPreparationErrorCode,
  message?: string
): never {
  throw new PhilCoreV2SepoliaDemoPreparationError(code, message);
}

function requiredBytes32(
  value: unknown,
  label: string,
  code: PhilCoreV2SepoliaDemoPreparationErrorCode
): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    fail(code, `${label} must be a 32-byte hex string`);
  }
  return (value as string).toLowerCase() as Hex;
}

function nonzeroBytes32(
  value: unknown,
  label: string,
  code: PhilCoreV2SepoliaDemoPreparationErrorCode
): Hex {
  const normalized = requiredBytes32(value, label, code);
  if (normalized === ZERO_BYTES32) fail(code, `${label} must be nonzero`);
  return normalized;
}

function requiredAddress(
  value: unknown,
  label: string,
  code: PhilCoreV2SepoliaDemoPreparationErrorCode
): string {
  if (typeof value !== "string") fail(code, `${label} must be an address`);
  let normalized: string;
  try {
    normalized = getAddress(value as string);
  } catch {
    return fail(code, `${label} must be a valid address`);
  }
  if (normalized === ZERO_ADDRESS) fail(code, `${label} must be nonzero`);
  return normalized;
}

function requiredUint(
  value: unknown,
  bits: number,
  label: string,
  code: PhilCoreV2SepoliaDemoPreparationErrorCode
): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value as BigNumberish);
  } catch {
    return fail(code, `${label} must be a uint${bits}`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    fail(code, `${label} must be a uint${bits}`);
  }
  return parsed;
}

function freezeRecord<T>(value: T): T {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as T;
  if (value && typeof value === "object") {
    return Object.freeze(Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, freezeRecord(entry)])
    )) as T;
  }
  return value;
}

/**
 * `PhilCoreV2MinimalAccountFactoryV2._identityBinding` / `PhilCoreV2MinimalAccountV2._identityBinding`.
 */
export function computePhilCoreV2IdentityBindingCommitment(ownerCommitment: Hex): Hex {
  const normalizedOwnerCommitment = nonzeroBytes32(
    ownerCommitment,
    "ownerCommitment",
    PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_ERROR_CODE.OWNER_COMMITMENT_INVALID
  );
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "bytes32", "bytes32"],
    [IDENTITY_BINDING_TYPEHASH, 1, normalizedOwnerCommitment, OWNER_COMMITMENT_SCHEME_ID]
  )) as Hex;
}

export interface PhilCoreV2AccountInitializationV1 {
  readonly entryPoint: string;
  readonly deploymentChainId: bigint;
  readonly ownerCommitment: Hex;
  readonly identityBindingCommitment: Hex;
  readonly factoryBinding: string;
  readonly accountVersionId: Hex;
  readonly securityModelId: Hex;
  readonly confirmationTarget: string;
  readonly initialValidator: string;
  readonly validatorVerifierKind: bigint;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorCommitment: Hex;
  readonly validatorEpoch: bigint;
  readonly primaryDeviceRecoveryCommitment: Hex;
  readonly hardwareSecurityKeyCommitment: Hex;
  readonly independentRecoveryFactorCommitment: Hex;
  readonly recoveryConfigurationHash: Hex;
  readonly recoveryEpoch: bigint;
  readonly recoveryDelaySeconds: bigint;
  readonly recoveryExpirySeconds: bigint;
}

export type PhilCoreV2AccountInitializationV1Tuple = readonly [
  string, // entryPoint
  bigint, // deploymentChainId
  Hex, // ownerCommitment
  Hex, // identityBindingCommitment
  string, // factoryBinding
  Hex, // accountVersionId
  Hex, // securityModelId
  string, // confirmationTarget
  string, // initialValidator
  bigint, // validatorVerifierKind
  Hex, // validatorKeyIdBinding
  Hex, // validatorCommitment
  bigint, // validatorEpoch
  Hex, // primaryDeviceRecoveryCommitment
  Hex, // hardwareSecurityKeyCommitment
  Hex, // independentRecoveryFactorCommitment
  Hex, // recoveryConfigurationHash
  bigint, // recoveryEpoch
  bigint, // recoveryDelaySeconds
  bigint // recoveryExpirySeconds
];

export function toPhilCoreV2AccountInitializationV1Tuple(
  initialization: PhilCoreV2AccountInitializationV1
): PhilCoreV2AccountInitializationV1Tuple {
  return [
    initialization.entryPoint,
    initialization.deploymentChainId,
    initialization.ownerCommitment,
    initialization.identityBindingCommitment,
    initialization.factoryBinding,
    initialization.accountVersionId,
    initialization.securityModelId,
    initialization.confirmationTarget,
    initialization.initialValidator,
    initialization.validatorVerifierKind,
    initialization.validatorKeyIdBinding,
    initialization.validatorCommitment,
    initialization.validatorEpoch,
    initialization.primaryDeviceRecoveryCommitment,
    initialization.hardwareSecurityKeyCommitment,
    initialization.independentRecoveryFactorCommitment,
    initialization.recoveryConfigurationHash,
    initialization.recoveryEpoch,
    initialization.recoveryDelaySeconds,
    initialization.recoveryExpirySeconds
  ];
}

/**
 * `PhilCoreV2MinimalAccountFactoryV2.deploymentSalt`.
 */
export function computeDeploymentSalt(input: {
  readonly deploymentChainId: BigNumberish;
  readonly ownerCommitment: Hex;
  readonly identityBindingCommitment: Hex;
  readonly userSalt: Hex;
}): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_CREATE2_SALT_DOMAIN,
      BigInt(input.deploymentChainId),
      PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
      PHILCORE_V2_SECURITY_MODEL_ID,
      input.ownerCommitment,
      input.identityBindingCommitment,
      input.userSalt
    ]
  )) as Hex;
}

/**
 * `PhilCoreV2MinimalAccountFactoryV2.accountCreationCodeHash`:
 * `keccak256(creationCode ‖ abi.encode(initialization))`.
 */
export function computeAccountCreationCodeHash(input: {
  readonly accountCreationBytecode: Hex;
  readonly initialization: PhilCoreV2AccountInitializationV1;
}): Hex {
  const encodedInitialization = abiCoder.encode(
    [`tuple(${INITIALIZATION_TUPLE_COMPONENTS})`],
    [toPhilCoreV2AccountInitializationV1Tuple(input.initialization)]
  );
  return keccak256(concat([input.accountCreationBytecode, encodedInitialization])) as Hex;
}

/**
 * `PhilCoreV2MinimalAccountFactoryV2.getAddress`:
 * `CREATE2(factory, deploymentSalt, accountCreationCodeHash)`.
 */
export function predictCreate2Address(input: {
  readonly factory: string;
  readonly deploymentSalt: Hex;
  readonly accountCreationCodeHash: Hex;
}): string {
  return getCreate2Address(
    getAddress(input.factory),
    input.deploymentSalt,
    input.accountCreationCodeHash
  );
}

/** `PhilCoreV2MinimalAccountFactoryV2.createAccount` calldata. */
export function encodeCreateAccountCalldata(input: {
  readonly initialization: PhilCoreV2AccountInitializationV1;
  readonly userSalt: Hex;
}): Hex {
  return factoryInterface.encodeFunctionData("createAccount", [
    toPhilCoreV2AccountInitializationV1Tuple(input.initialization),
    input.userSalt
  ]) as Hex;
}

/** Offline review-only encoding of the factory constructor arguments. */
export function encodeFactoryConstructorArgs(input: {
  readonly entryPoint: string;
  readonly deploymentChainId: BigNumberish;
  readonly confirmationTarget: string;
  readonly verifier: string;
  readonly verifierRuntimeCodeHash: Hex;
}): Hex {
  return abiCoder.encode(
    ["address", "uint256", "address", "address", "bytes32"],
    [
      getAddress(input.entryPoint),
      BigInt(input.deploymentChainId),
      getAddress(input.confirmationTarget),
      getAddress(input.verifier),
      input.verifierRuntimeCodeHash
    ]
  ) as Hex;
}

export interface PhilCoreV2ConfirmIntentInput {
  readonly account: string;
  readonly chainId: BigNumberish;
  readonly entryPoint: string;
  readonly confirmationTarget: string;
  readonly ownerCommitment: Hex;
  readonly actionId: Hex;
  readonly confirmationDigest: Hex;
  readonly runtimeAuthorizationDigest: Hex;
  readonly applicationContextHash: Hex;
  readonly fundLifecycleDigest: Hex;
  readonly maxTotalFeeWei: BigNumberish;
  readonly validAfter: BigNumberish;
  readonly validUntil: BigNumberish;
  readonly validatorEpoch: BigNumberish;
  readonly recoveryEpoch: BigNumberish;
  readonly nonceSequence?: BigNumberish;
}

export interface PhilCoreV2ConfirmIntentEncoding {
  readonly coreHeaderHash: Hex;
  readonly intentCoreHash: Hex;
  readonly calldata: Hex;
}

/**
 * Builds the `confirmIntent(PhilCoreV2AuthorizedIntentV1,bytes32)` calldata
 * for the first (deployment-confirming) UserOperation. Uses `v2Intent.ts`'s
 * `encodePhilCoreV2Intent` so the header/action encoding is byte-identical to
 * what the deployed account will reconstruct on-chain.
 */
export function encodeConfirmIntentCalldata(
  input: PhilCoreV2ConfirmIntentInput
): PhilCoreV2ConfirmIntentEncoding {
  const nonceSequence = input.nonceSequence ?? 0n;
  const encoding = encodePhilCoreV2Intent({
    header: {
      specificationVersion: PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
      securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
      actionType: PHILCORE_V2_ACTION_TYPE.CONFIRM,
      actionId: input.actionId,
      purpose: PHILCORE_V2_PURPOSE.CONFIRM_ACTION,
      ownerCommitment: input.ownerCommitment,
      chainId: input.chainId,
      entryPoint: input.entryPoint,
      account: input.account,
      nonceKey: PHILCORE_V2_NONCE_KEY.ORDINARY,
      nonceSequence,
      validatorEpoch: input.validatorEpoch,
      recoveryEpoch: input.recoveryEpoch,
      applicationContextHash: input.applicationContextHash,
      fundLifecycleDigest: input.fundLifecycleDigest,
      maxTotalFeeWei: input.maxTotalFeeWei,
      validAfter: input.validAfter,
      validUntil: input.validUntil
    },
    payload: {
      kind: "CONFIRM",
      confirmationTarget: input.confirmationTarget,
      confirmationDigest: input.confirmationDigest
    }
  });
  const header = encoding.header;
  const calldata = accountInterface.encodeFunctionData("confirmIntent", [
    [
      [
        header.specificationVersion,
        header.securityModelId,
        header.actionType,
        header.actionId,
        header.purpose,
        header.ownerCommitment,
        header.chainId,
        header.entryPoint,
        header.account,
        header.nonceKey,
        header.nonceSequence,
        header.validatorEpoch,
        header.recoveryEpoch,
        header.applicationContextHash,
        header.fundLifecycleDigest,
        header.maxTotalFeeWei,
        header.validAfter,
        header.validUntil
      ],
      input.runtimeAuthorizationDigest
    ],
    input.confirmationDigest
  ]) as Hex;
  return freezeRecord({
    coreHeaderHash: encoding.coreHeaderHash,
    intentCoreHash: encoding.intentCoreHash,
    calldata
  });
}

export interface PhilCoreV2SepoliaDemoDeploymentInput {
  readonly factory: string;
  readonly verifier: string;
  readonly verifierRuntimeCodeHash: Hex;
  readonly confirmationTarget: string;
  readonly entryPoint: string;
  readonly validator: string;
  readonly chainId: BigNumberish;
  readonly ownerCommitment: Hex;
  readonly identityBindingCommitment: Hex;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorCommitment: Hex;
  readonly primaryDeviceRecoveryCommitment: Hex;
  readonly hardwareSecurityKeyCommitment: Hex;
  readonly independentRecoveryFactorCommitment: Hex;
  readonly recoveryConfigurationHash: Hex;
  readonly validatorEpoch: BigNumberish;
  readonly recoveryEpoch: BigNumberish;
  readonly recoveryDelaySeconds: BigNumberish;
  readonly recoveryExpirySeconds: BigNumberish;
  readonly userSalt: Hex;
  readonly accountCreationBytecode: Hex;
  /** Overrides for negative-path testing only; must equal the current constants. */
  readonly accountVersionId?: Hex;
  readonly securityModelId?: Hex;
  readonly actionId: Hex;
  readonly confirmationDigest: Hex;
  readonly runtimeAuthorizationDigest: Hex;
  readonly applicationContextHash: Hex;
  readonly fundLifecycleDigest: Hex;
  readonly maxTotalFeeWei: BigNumberish;
  readonly validAfter: BigNumberish;
  readonly validUntil: BigNumberish;
  readonly nonceSequence?: BigNumberish;
  readonly verificationGasLimit: BigNumberish;
  readonly callGasLimit: BigNumberish;
  readonly preVerificationGas: BigNumberish;
  readonly maxFeePerGas: BigNumberish;
  readonly maxPriorityFeePerGas: BigNumberish;
}

export interface PhilCoreV2SepoliaDemoDeploymentProposal {
  readonly schemaVersion: typeof PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_SCHEMA;
  readonly chainId: bigint;
  readonly entryPoint: string;
  readonly factory: string;
  readonly initialization: PhilCoreV2AccountInitializationV1;
  readonly initializationTuple: PhilCoreV2AccountInitializationV1Tuple;
  readonly factoryConstructorArgs: Hex;
  readonly createAccountCalldata: Hex;
  readonly initCode: Hex;
  readonly deploymentSalt: Hex;
  readonly accountCreationCodeHash: Hex;
  readonly counterfactualAccount: string;
  readonly confirmIntent: PhilCoreV2ConfirmIntentEncoding;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly userOperationHash: Hex;
  readonly hashes: Readonly<{
    readonly identityBindingCommitment: Hex;
    readonly validatorCommitment: Hex;
    readonly recoveryConfigurationHash: Hex;
    readonly deploymentSalt: Hex;
    readonly accountCreationCodeHash: Hex;
    readonly coreHeaderHash: Hex;
    readonly intentCoreHash: Hex;
    readonly userOperationHash: Hex;
  }>;
  readonly status: "proposed_unsigned";
  readonly signed: false;
  readonly submitted: false;
  readonly incompleteUntilDeviceApproval: true;
}

/**
 * Pure, offline preparation of a PhilCore V2 Sepolia demo account deployment.
 *
 * Performs no network I/O, reads no environment variables, files, providers,
 * or signers, and generates no recovery commitments or default policy: every
 * commitment must be supplied explicitly and is independently re-verified
 * against its canonical on-chain formula before being accepted. The returned
 * proposal is unsigned and unsubmitted; it does not expose any
 * submit/deploy/fund/sign/retry capability.
 */
export function preparePhilCoreV2SepoliaDemoDeployment(
  input: PhilCoreV2SepoliaDemoDeploymentInput
): PhilCoreV2SepoliaDemoDeploymentProposal {
  const CODE = PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_ERROR_CODE;

  const factory = requiredAddress(input.factory, "factory", CODE.FACTORY_ADDRESS_INVALID);
  const verifier = requiredAddress(input.verifier, "verifier", CODE.VERIFIER_ADDRESS_INVALID);
  const confirmationTarget = requiredAddress(
    input.confirmationTarget,
    "confirmationTarget",
    CODE.CONFIRMATION_TARGET_ADDRESS_INVALID
  );
  const entryPoint = requiredAddress(input.entryPoint, "entryPoint", CODE.ENTRY_POINT_UNSUPPORTED);
  const validator = requiredAddress(input.validator, "validator", CODE.VALIDATOR_ADDRESS_INVALID);
  const verifierRuntimeCodeHash = nonzeroBytes32(
    input.verifierRuntimeCodeHash,
    "verifierRuntimeCodeHash",
    CODE.VERIFIER_RUNTIME_CODE_HASH_INVALID
  );

  if (getAddress(entryPoint) !== getAddress(PHILCORE_ENTRY_POINT_V07_ADDRESS)) {
    fail(CODE.ENTRY_POINT_UNSUPPORTED, "only the canonical ERC-4337 v0.7 EntryPoint is supported");
  }

  const chainId = requiredUint(input.chainId, 256, "chainId", CODE.CHAIN_ID_UNSUPPORTED);
  if (chainId !== BigInt(PHILCORE_V2_SEPOLIA_CHAIN_ID)) {
    fail(CODE.CHAIN_ID_UNSUPPORTED, "only Ethereum Sepolia (11155111) is supported");
  }

  const accountVersionId = requiredBytes32(
    input.accountVersionId ?? PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
    "accountVersionId",
    CODE.ACCOUNT_VERSION_UNSUPPORTED
  );
  if (accountVersionId !== PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID.toLowerCase()) {
    fail(CODE.ACCOUNT_VERSION_UNSUPPORTED, "only the current deployable account version is supported");
  }

  const securityModelId = requiredBytes32(
    input.securityModelId ?? PHILCORE_V2_SECURITY_MODEL_ID,
    "securityModelId",
    CODE.SECURITY_MODEL_UNSUPPORTED
  );
  if (securityModelId !== PHILCORE_V2_SECURITY_MODEL_ID.toLowerCase()) {
    fail(CODE.SECURITY_MODEL_UNSUPPORTED, "only the current security model is supported");
  }

  const ownerCommitment = nonzeroBytes32(
    input.ownerCommitment,
    "ownerCommitment",
    CODE.OWNER_COMMITMENT_INVALID
  );
  const expectedIdentityBindingCommitment = computePhilCoreV2IdentityBindingCommitment(ownerCommitment);
  const identityBindingCommitment = nonzeroBytes32(
    input.identityBindingCommitment,
    "identityBindingCommitment",
    CODE.IDENTITY_BINDING_COMMITMENT_MISMATCH
  );
  if (identityBindingCommitment !== expectedIdentityBindingCommitment) {
    fail(
      CODE.IDENTITY_BINDING_COMMITMENT_MISMATCH,
      "identityBindingCommitment does not match the recomputed formula"
    );
  }

  const validatorKeyIdBinding = nonzeroBytes32(
    input.validatorKeyIdBinding,
    "validatorKeyIdBinding",
    CODE.VALIDATOR_KEY_ID_BINDING_INVALID
  );
  let expectedValidatorCommitment: Hex;
  try {
    expectedValidatorCommitment = computePhilCoreV2ValidatorCommitment({
      verifierKind: PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
      validator,
      validatorKeyIdBinding
    });
  } catch (error) {
    return fail(
      CODE.VALIDATOR_COMMITMENT_MISMATCH,
      error instanceof Error ? error.message : "validatorCommitment could not be recomputed"
    );
  }
  const validatorCommitment = nonzeroBytes32(
    input.validatorCommitment,
    "validatorCommitment",
    CODE.VALIDATOR_COMMITMENT_MISMATCH
  );
  if (validatorCommitment !== expectedValidatorCommitment.toLowerCase()) {
    fail(CODE.VALIDATOR_COMMITMENT_MISMATCH, "validatorCommitment does not match the recomputed formula");
  }

  const validatorEpoch = requiredUint(
    input.validatorEpoch,
    64,
    "validatorEpoch",
    CODE.VALIDATOR_EPOCH_INVALID
  );
  if (validatorEpoch !== PHILCORE_V2_INITIAL_VALIDATOR_EPOCH) {
    fail(CODE.VALIDATOR_EPOCH_INVALID, "validatorEpoch must be 1 for initial deployment");
  }
  const recoveryEpoch = requiredUint(
    input.recoveryEpoch,
    64,
    "recoveryEpoch",
    CODE.RECOVERY_EPOCH_INVALID
  );
  if (recoveryEpoch !== PHILCORE_V2_INITIAL_RECOVERY_EPOCH) {
    fail(CODE.RECOVERY_EPOCH_INVALID, "recoveryEpoch must be 1 for initial deployment");
  }

  const primaryDeviceRecoveryCommitment = nonzeroBytes32(
    input.primaryDeviceRecoveryCommitment,
    "primaryDeviceRecoveryCommitment",
    CODE.RECOVERY_COMMITMENT_INVALID
  );
  const hardwareSecurityKeyCommitment = nonzeroBytes32(
    input.hardwareSecurityKeyCommitment,
    "hardwareSecurityKeyCommitment",
    CODE.RECOVERY_COMMITMENT_INVALID
  );
  const independentRecoveryFactorCommitment = nonzeroBytes32(
    input.independentRecoveryFactorCommitment,
    "independentRecoveryFactorCommitment",
    CODE.RECOVERY_COMMITMENT_INVALID
  );
  const recoveryCommitments = [
    primaryDeviceRecoveryCommitment,
    hardwareSecurityKeyCommitment,
    independentRecoveryFactorCommitment
  ] as const;
  if (new Set(recoveryCommitments).size !== 3) {
    fail(
      CODE.RECOVERY_COMMITMENTS_NOT_DISTINCT,
      "primaryDevice, hardwareSecurityKey, and independentRecoveryFactor commitments must be pairwise distinct"
    );
  }
  let expectedRecoveryConfigurationHash: Hex;
  try {
    expectedRecoveryConfigurationHash = computePhilCoreV2ConsumerRecoveryConfigurationHash(
      recoveryCommitments
    );
  } catch (error) {
    return fail(
      CODE.RECOVERY_CONFIGURATION_HASH_MISMATCH,
      error instanceof Error ? error.message : "recoveryConfigurationHash could not be recomputed"
    );
  }
  const recoveryConfigurationHash = nonzeroBytes32(
    input.recoveryConfigurationHash,
    "recoveryConfigurationHash",
    CODE.RECOVERY_CONFIGURATION_HASH_MISMATCH
  );
  if (recoveryConfigurationHash !== expectedRecoveryConfigurationHash.toLowerCase()) {
    fail(
      CODE.RECOVERY_CONFIGURATION_HASH_MISMATCH,
      "recoveryConfigurationHash does not match the recomputed formula"
    );
  }

  const recoveryDelaySeconds = requiredUint(
    input.recoveryDelaySeconds,
    64,
    "recoveryDelaySeconds",
    CODE.RECOVERY_DELAY_SECONDS_INVALID
  );
  if (recoveryDelaySeconds !== PHILCORE_V2_RECOVERY_DELAY_SECONDS) {
    fail(CODE.RECOVERY_DELAY_SECONDS_INVALID, "recoveryDelaySeconds must be exactly 172800");
  }
  const recoveryExpirySeconds = requiredUint(
    input.recoveryExpirySeconds,
    64,
    "recoveryExpirySeconds",
    CODE.RECOVERY_EXPIRY_SECONDS_INVALID
  );
  if (recoveryExpirySeconds !== PHILCORE_V2_RECOVERY_EXPIRY_SECONDS) {
    fail(CODE.RECOVERY_EXPIRY_SECONDS_INVALID, "recoveryExpirySeconds must be exactly 604800");
  }

  const userSalt = nonzeroBytes32(input.userSalt, "userSalt", CODE.USER_SALT_INVALID);

  if (!isHexString(input.accountCreationBytecode) || input.accountCreationBytecode.length <= 2) {
    fail(CODE.ACCOUNT_CREATION_BYTECODE_INVALID, "accountCreationBytecode must be nonempty hex");
  }

  const initialization: PhilCoreV2AccountInitializationV1 = freezeRecord({
    entryPoint,
    deploymentChainId: chainId,
    ownerCommitment,
    identityBindingCommitment,
    factoryBinding: factory,
    accountVersionId: PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    confirmationTarget,
    initialValidator: validator,
    validatorVerifierKind: BigInt(PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA),
    validatorKeyIdBinding,
    validatorCommitment,
    validatorEpoch,
    primaryDeviceRecoveryCommitment,
    hardwareSecurityKeyCommitment,
    independentRecoveryFactorCommitment,
    recoveryConfigurationHash,
    recoveryEpoch,
    recoveryDelaySeconds,
    recoveryExpirySeconds
  });
  const initializationTuple = toPhilCoreV2AccountInitializationV1Tuple(initialization);

  const factoryConstructorArgs = encodeFactoryConstructorArgs({
    entryPoint,
    deploymentChainId: chainId,
    confirmationTarget,
    verifier,
    verifierRuntimeCodeHash
  });
  const createAccountCalldata = encodeCreateAccountCalldata({ initialization, userSalt });
  const initCode = concat([factory, createAccountCalldata]) as Hex;
  const deploymentSalt = computeDeploymentSalt({
    deploymentChainId: chainId,
    ownerCommitment,
    identityBindingCommitment,
    userSalt
  });
  const accountCreationCodeHash = computeAccountCreationCodeHash({
    accountCreationBytecode: input.accountCreationBytecode,
    initialization
  });
  const counterfactualAccount = predictCreate2Address({
    factory,
    deploymentSalt,
    accountCreationCodeHash
  });

  const actionId = nonzeroBytes32(input.actionId, "actionId", CODE.ACTION_ID_INVALID);
  const confirmationDigest = nonzeroBytes32(
    input.confirmationDigest,
    "confirmationDigest",
    CODE.CONFIRMATION_DIGEST_INVALID
  );
  const runtimeAuthorizationDigest = nonzeroBytes32(
    input.runtimeAuthorizationDigest,
    "runtimeAuthorizationDigest",
    CODE.RUNTIME_AUTHORIZATION_DIGEST_INVALID
  );
  const applicationContextHash = nonzeroBytes32(
    input.applicationContextHash,
    "applicationContextHash",
    CODE.APPLICATION_CONTEXT_HASH_INVALID
  );
  const fundLifecycleDigest = nonzeroBytes32(
    input.fundLifecycleDigest,
    "fundLifecycleDigest",
    CODE.FUND_LIFECYCLE_DIGEST_INVALID
  );
  const maxTotalFeeWei = requiredUint(
    input.maxTotalFeeWei,
    256,
    "maxTotalFeeWei",
    CODE.MAX_TOTAL_FEE_WEI_INVALID
  );
  if (maxTotalFeeWei === 0n) fail(CODE.MAX_TOTAL_FEE_WEI_INVALID, "maxTotalFeeWei must be nonzero");
  const validAfter = requiredUint(input.validAfter, 48, "validAfter", CODE.VALIDITY_WINDOW_INVALID);
  const validUntil = requiredUint(input.validUntil, 48, "validUntil", CODE.VALIDITY_WINDOW_INVALID);
  if (validUntil <= validAfter) {
    fail(CODE.VALIDITY_WINDOW_INVALID, "validUntil must be greater than validAfter");
  }
  if (validUntil - validAfter > PHILCORE_V2_CONFIRM_MAX_VALIDITY_LIFETIME_SECONDS) {
    fail(CODE.VALIDITY_WINDOW_INVALID, "CONFIRM validity window must not exceed 600 seconds");
  }
  const nonceSequence = requiredUint(
    input.nonceSequence ?? 0,
    64,
    "nonceSequence",
    CODE.NONCE_SEQUENCE_INVALID
  );

  let confirmIntent: PhilCoreV2ConfirmIntentEncoding;
  try {
    confirmIntent = encodeConfirmIntentCalldata({
      account: counterfactualAccount,
      chainId,
      entryPoint,
      confirmationTarget,
      ownerCommitment,
      actionId,
      confirmationDigest,
      runtimeAuthorizationDigest,
      applicationContextHash,
      fundLifecycleDigest,
      maxTotalFeeWei,
      validAfter,
      validUntil,
      validatorEpoch,
      recoveryEpoch,
      nonceSequence
    });
  } catch (error) {
    return fail(
      CODE.VALIDITY_WINDOW_INVALID,
      error instanceof Error ? error.message : "confirmIntent could not be encoded"
    );
  }

  const verificationGasLimit = requiredUint(
    input.verificationGasLimit,
    128,
    "verificationGasLimit",
    CODE.GAS_FIELD_INVALID
  );
  const callGasLimit = requiredUint(input.callGasLimit, 128, "callGasLimit", CODE.GAS_FIELD_INVALID);
  const preVerificationGas = requiredUint(
    input.preVerificationGas,
    256,
    "preVerificationGas",
    CODE.GAS_FIELD_INVALID
  );
  const maxFeePerGas = requiredUint(input.maxFeePerGas, 128, "maxFeePerGas", CODE.GAS_FIELD_INVALID);
  const maxPriorityFeePerGas = requiredUint(
    input.maxPriorityFeePerGas,
    128,
    "maxPriorityFeePerGas",
    CODE.GAS_FIELD_INVALID
  );

  const userOperation: PhilCorePackedUserOperation = freezeRecord({
    sender: counterfactualAccount,
    nonce: composePhilCoreV2Nonce({ key: PHILCORE_V2_NONCE_KEY.ORDINARY, sequence: nonceSequence }).toString(),
    initCode,
    callData: confirmIntent.calldata,
    accountGasLimits: packPhilCore4337AccountGasLimits({
      verificationGasLimit: verificationGasLimit.toString(),
      callGasLimit: callGasLimit.toString()
    }),
    preVerificationGas: preVerificationGas.toString(),
    gasFees: packPhilCore4337GasFees({
      maxPriorityFeePerGas: maxPriorityFeePerGas.toString(),
      maxFeePerGas: maxFeePerGas.toString()
    }),
    paymasterAndData: PHILCORE_4337_EMPTY_BYTES,
    signature: PHILCORE_4337_EMPTY_BYTES
  });
  const userOperationHash = computePhilCore4337UserOperationHash({
    userOperation,
    entryPointAddress: entryPoint,
    chainId: Number(chainId)
  });

  return freezeRecord({
    schemaVersion: PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_SCHEMA,
    chainId,
    entryPoint,
    factory,
    initialization,
    initializationTuple,
    factoryConstructorArgs,
    createAccountCalldata,
    initCode,
    deploymentSalt,
    accountCreationCodeHash,
    counterfactualAccount,
    confirmIntent,
    userOperation,
    userOperationHash,
    hashes: {
      identityBindingCommitment,
      validatorCommitment,
      recoveryConfigurationHash,
      deploymentSalt,
      accountCreationCodeHash,
      coreHeaderHash: confirmIntent.coreHeaderHash,
      intentCoreHash: confirmIntent.intentCoreHash,
      userOperationHash
    },
    status: "proposed_unsigned" as const,
    signed: false as const,
    submitted: false as const,
    incompleteUntilDeviceApproval: true as const
  });
}
