import {
  AbiCoder,
  concat,
  getAddress,
  isHexString,
  keccak256,
  toUtf8Bytes,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const PHILCORE_V2_INTENT_SPECIFICATION_VERSION = 1 as const;
export const PHILCORE_V2_EIP712_NAME = "PhilCore V2 Account" as const;
export const PHILCORE_V2_EIP712_VERSION = "1" as const;
export const PHILCORE_V2_SECURITY_MODEL =
  "philcore-v2-typed-intent-local-proof-gated-v1" as const;
export const PHILCORE_V2_SECURITY_MODEL_ID =
  keccak256(toUtf8Bytes(PHILCORE_V2_SECURITY_MODEL)) as Hex;
export const PHILCORE_V2_ACCOUNT_VERSION =
  "philcore-v2-account-v1" as const;
export const PHILCORE_V2_ACCOUNT_VERSION_ID =
  keccak256(toUtf8Bytes(PHILCORE_V2_ACCOUNT_VERSION)) as Hex;

export const PHILCORE_V2_ACTION_TYPE = Object.freeze({
  CONFIRM: 1,
  NATIVE_TRANSFER: 2,
  ERC20_TRANSFER: 3,
  ERC721_SAFE_TRANSFER: 4,
  ERC1155_SAFE_TRANSFER: 5,
  ENTRYPOINT_DEPOSIT_WITHDRAWAL: 6,
  VALIDATOR_ROTATION: 7,
  RECOVERY_REQUEST: 8,
  RECOVERY_CANCEL: 9,
  RECOVERY_CONFIG_ROTATION_REQUEST: 10,
  RECOVERY_CONFIG_ROTATION_CANCEL: 11
} as const);

export type PhilCoreV2ActionType =
  typeof PHILCORE_V2_ACTION_TYPE[keyof typeof PHILCORE_V2_ACTION_TYPE];

export const PHILCORE_V2_NONCE_KEY = Object.freeze({
  ORDINARY: 0n,
  MAINTENANCE: 1n,
  RECOVERY: 2n
} as const);

export const PHILCORE_V2_PURPOSE_LABEL = Object.freeze({
  CONFIRM_ACTION: "PHILCORE_V2_PURPOSE_CONFIRM_ACTION",
  TRANSFER_ASSET: "PHILCORE_V2_PURPOSE_TRANSFER_ASSET",
  RELEASE_RESIDUAL: "PHILCORE_V2_PURPOSE_RELEASE_RESIDUAL",
  MIGRATE_ASSET: "PHILCORE_V2_PURPOSE_MIGRATE_ASSET",
  WITHDRAW_DEPOSIT: "PHILCORE_V2_PURPOSE_WITHDRAW_DEPOSIT",
  ROTATE_VALIDATOR: "PHILCORE_V2_PURPOSE_ROTATE_VALIDATOR",
  REQUEST_RECOVERY: "PHILCORE_V2_PURPOSE_REQUEST_RECOVERY",
  CANCEL_RECOVERY: "PHILCORE_V2_PURPOSE_CANCEL_RECOVERY",
  ROTATE_RECOVERY_CONFIG: "PHILCORE_V2_PURPOSE_ROTATE_RECOVERY_CONFIG",
  CANCEL_RECOVERY_CONFIG_ROTATION:
    "PHILCORE_V2_PURPOSE_CANCEL_RECOVERY_CONFIG_ROTATION"
} as const);

export const PHILCORE_V2_PURPOSE = Object.freeze(
  Object.fromEntries(
    Object.entries(PHILCORE_V2_PURPOSE_LABEL).map(([key, value]) => [
      key,
      keccak256(toUtf8Bytes(value))
    ])
  ) as Record<keyof typeof PHILCORE_V2_PURPOSE_LABEL, Hex>
);

export const PHILCORE_V2_TYPE = Object.freeze({
  EIP712_DOMAIN:
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
  INTENT_CORE_HEADER:
    "PhilCoreV2IntentCoreHeader(uint8 specificationVersion,bytes32 securityModelId,uint8 actionType,bytes32 actionId,bytes32 purpose,bytes32 ownerCommitment,uint256 chainId,address entryPoint,address account,uint192 nonceKey,uint64 nonceSequence,uint64 validatorEpoch,uint64 recoveryEpoch,bytes32 applicationContextHash,bytes32 fundLifecycleDigest,uint256 maxTotalFeeWei,uint48 validAfter,uint48 validUntil)",
  APPLICATION_CONTEXT:
    "PhilCoreV2ApplicationContext(bytes32 applicationIdHash,bytes32 originHash,bytes32 sessionIdHash,bytes32 capabilityGrantIdHash,bytes32 policyDecisionIdHash)",
  FUND_LIFECYCLE:
    "PhilCoreV2FundLifecycle(bytes32 lifecycleSchemaHash,address account,address asset,uint256 tokenId,uint256 maximumFundingOrHolding,uint256 maximumStranded,address residualRecipient,uint256 expectedPostOperationBalance,uint256 expectedFinalBalance,bytes32 releaseRouteHash,bytes32 simulationEvidenceHash)",
  CONFIRM:
    "PhilCoreV2ConfirmIntent(bytes32 coreHeaderHash,address confirmationTarget,bytes32 confirmationDigest)",
  NATIVE_TRANSFER:
    "PhilCoreV2NativeTransferIntent(bytes32 coreHeaderHash,address recipient,uint256 amountWei)",
  ERC20_TRANSFER:
    "PhilCoreV2ERC20TransferIntent(bytes32 coreHeaderHash,address token,address recipient,uint256 amount)",
  ERC721_SAFE_TRANSFER:
    "PhilCoreV2ERC721SafeTransferIntent(bytes32 coreHeaderHash,address token,address recipient,uint256 tokenId,bytes32 receiverDataHash)",
  ERC1155_SAFE_TRANSFER:
    "PhilCoreV2ERC1155SafeTransferIntent(bytes32 coreHeaderHash,address token,address recipient,uint256 tokenId,uint256 amount,bytes32 receiverDataHash)",
  ENTRYPOINT_DEPOSIT_WITHDRAWAL:
    "PhilCoreV2EntryPointDepositWithdrawalIntent(bytes32 coreHeaderHash,address recipient,uint256 amountWei)",
  VALIDATOR_ROTATION:
    "PhilCoreV2ValidatorRotationIntent(bytes32 coreHeaderHash,address proposedValidator,bytes32 proposedValidatorKeyIdBinding,uint64 proposedValidatorEpoch)",
  RECOVERY_REQUEST:
    "PhilCoreV2RecoveryRequestIntent(bytes32 coreHeaderHash,address proposedValidator,bytes32 proposedValidatorKeyIdBinding,uint64 proposedValidatorEpoch,bytes32 recoveryRequestSalt)",
  RECOVERY_CANCEL:
    "PhilCoreV2RecoveryCancelIntent(bytes32 coreHeaderHash,bytes32 recoveryRequestId)",
  RECOVERY_CONFIG_ROTATION_REQUEST:
    "PhilCoreV2RecoveryConfigRotationRequestIntent(bytes32 coreHeaderHash,bytes32 proposedRecoveryConfigHash,bytes32 proposedPrimaryDeviceCommitment,bytes32 proposedHardwareSecurityKeyCommitment,bytes32 proposedRecoveryFactorCommitment,uint64 proposedRecoveryEpoch)",
  RECOVERY_CONFIG_ROTATION_CANCEL:
    "PhilCoreV2RecoveryConfigRotationCancelIntent(bytes32 coreHeaderHash,bytes32 recoveryConfigRotationRequestId)"
} as const);

export const PHILCORE_V2_TYPEHASH = Object.freeze(
  Object.fromEntries(
    Object.entries(PHILCORE_V2_TYPE).map(([key, value]) => [
      key,
      keccak256(toUtf8Bytes(value))
    ])
  ) as Record<keyof typeof PHILCORE_V2_TYPE, Hex>
);

const ACTION_NONCE_KEYS: Readonly<Record<PhilCoreV2ActionType, bigint>> =
  Object.freeze({
    [PHILCORE_V2_ACTION_TYPE.CONFIRM]: PHILCORE_V2_NONCE_KEY.ORDINARY,
    [PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER]: PHILCORE_V2_NONCE_KEY.ORDINARY,
    [PHILCORE_V2_ACTION_TYPE.ERC20_TRANSFER]: PHILCORE_V2_NONCE_KEY.ORDINARY,
    [PHILCORE_V2_ACTION_TYPE.ERC721_SAFE_TRANSFER]:
      PHILCORE_V2_NONCE_KEY.ORDINARY,
    [PHILCORE_V2_ACTION_TYPE.ERC1155_SAFE_TRANSFER]:
      PHILCORE_V2_NONCE_KEY.ORDINARY,
    [PHILCORE_V2_ACTION_TYPE.ENTRYPOINT_DEPOSIT_WITHDRAWAL]:
      PHILCORE_V2_NONCE_KEY.ORDINARY,
    [PHILCORE_V2_ACTION_TYPE.VALIDATOR_ROTATION]:
      PHILCORE_V2_NONCE_KEY.MAINTENANCE,
    [PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST]:
      PHILCORE_V2_NONCE_KEY.RECOVERY,
    [PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL]:
      PHILCORE_V2_NONCE_KEY.RECOVERY,
    [PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST]:
      PHILCORE_V2_NONCE_KEY.RECOVERY,
    [PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL]:
      PHILCORE_V2_NONCE_KEY.RECOVERY
  });

const ACTION_PURPOSES: Readonly<Record<PhilCoreV2ActionType, readonly Hex[]>> =
  Object.freeze({
    [PHILCORE_V2_ACTION_TYPE.CONFIRM]: [
      PHILCORE_V2_PURPOSE.CONFIRM_ACTION
    ],
    [PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER]: [
      PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
      PHILCORE_V2_PURPOSE.RELEASE_RESIDUAL,
      PHILCORE_V2_PURPOSE.MIGRATE_ASSET
    ],
    [PHILCORE_V2_ACTION_TYPE.ERC20_TRANSFER]: [
      PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
      PHILCORE_V2_PURPOSE.RELEASE_RESIDUAL,
      PHILCORE_V2_PURPOSE.MIGRATE_ASSET
    ],
    [PHILCORE_V2_ACTION_TYPE.ERC721_SAFE_TRANSFER]: [
      PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
      PHILCORE_V2_PURPOSE.RELEASE_RESIDUAL,
      PHILCORE_V2_PURPOSE.MIGRATE_ASSET
    ],
    [PHILCORE_V2_ACTION_TYPE.ERC1155_SAFE_TRANSFER]: [
      PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
      PHILCORE_V2_PURPOSE.RELEASE_RESIDUAL,
      PHILCORE_V2_PURPOSE.MIGRATE_ASSET
    ],
    [PHILCORE_V2_ACTION_TYPE.ENTRYPOINT_DEPOSIT_WITHDRAWAL]: [
      PHILCORE_V2_PURPOSE.WITHDRAW_DEPOSIT,
      PHILCORE_V2_PURPOSE.RELEASE_RESIDUAL,
      PHILCORE_V2_PURPOSE.MIGRATE_ASSET
    ],
    [PHILCORE_V2_ACTION_TYPE.VALIDATOR_ROTATION]: [
      PHILCORE_V2_PURPOSE.ROTATE_VALIDATOR
    ],
    [PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST]: [
      PHILCORE_V2_PURPOSE.REQUEST_RECOVERY
    ],
    [PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL]: [
      PHILCORE_V2_PURPOSE.CANCEL_RECOVERY
    ],
    [PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST]: [
      PHILCORE_V2_PURPOSE.ROTATE_RECOVERY_CONFIG
    ],
    [PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL]: [
      PHILCORE_V2_PURPOSE.CANCEL_RECOVERY_CONFIG_ROTATION
    ]
  });

export interface PhilCoreV2IntentCoreHeaderInput {
  readonly specificationVersion: BigNumberish;
  readonly securityModelId: Hex;
  readonly actionType: BigNumberish;
  readonly actionId: Hex;
  readonly purpose: Hex;
  readonly ownerCommitment: Hex;
  readonly chainId: BigNumberish;
  readonly entryPoint: string;
  readonly account: string;
  readonly nonceKey: BigNumberish;
  readonly nonceSequence: BigNumberish;
  readonly validatorEpoch: BigNumberish;
  readonly recoveryEpoch: BigNumberish;
  readonly applicationContextHash: Hex;
  readonly fundLifecycleDigest: Hex;
  readonly maxTotalFeeWei: BigNumberish;
  readonly validAfter: BigNumberish;
  readonly validUntil: BigNumberish;
}

export interface PhilCoreV2IntentCoreHeader {
  readonly specificationVersion: bigint;
  readonly securityModelId: Hex;
  readonly actionType: PhilCoreV2ActionType;
  readonly actionId: Hex;
  readonly purpose: Hex;
  readonly ownerCommitment: Hex;
  readonly chainId: bigint;
  readonly entryPoint: string;
  readonly account: string;
  readonly nonceKey: bigint;
  readonly nonceSequence: bigint;
  readonly validatorEpoch: bigint;
  readonly recoveryEpoch: bigint;
  readonly applicationContextHash: Hex;
  readonly fundLifecycleDigest: Hex;
  readonly maxTotalFeeWei: bigint;
  readonly validAfter: bigint;
  readonly validUntil: bigint;
}

export interface PhilCoreV2ApplicationContextInput {
  readonly applicationIdHash: Hex;
  readonly originHash: Hex;
  readonly sessionIdHash: Hex;
  readonly capabilityGrantIdHash: Hex;
  readonly policyDecisionIdHash: Hex;
}

export interface PhilCoreV2FundLifecycleInput {
  readonly lifecycleSchemaHash: Hex;
  readonly account: string;
  readonly asset: string;
  readonly tokenId: BigNumberish;
  readonly maximumFundingOrHolding: BigNumberish;
  readonly maximumStranded: BigNumberish;
  readonly residualRecipient: string;
  readonly expectedPostOperationBalance: BigNumberish;
  readonly expectedFinalBalance: BigNumberish;
  readonly releaseRouteHash: Hex;
  readonly simulationEvidenceHash: Hex;
}

export type PhilCoreV2ActionPayloadInput =
  | {
      readonly kind: "CONFIRM";
      readonly confirmationTarget: string;
      readonly confirmationDigest: Hex;
    }
  | {
      readonly kind: "NATIVE_TRANSFER";
      readonly recipient: string;
      readonly amountWei: BigNumberish;
    }
  | {
      readonly kind: "ERC20_TRANSFER";
      readonly token: string;
      readonly recipient: string;
      readonly amount: BigNumberish;
    }
  | {
      readonly kind: "ERC721_SAFE_TRANSFER";
      readonly token: string;
      readonly recipient: string;
      readonly tokenId: BigNumberish;
      readonly receiverDataHash: Hex;
    }
  | {
      readonly kind: "ERC1155_SAFE_TRANSFER";
      readonly token: string;
      readonly recipient: string;
      readonly tokenId: BigNumberish;
      readonly amount: BigNumberish;
      readonly receiverDataHash: Hex;
    }
  | {
      readonly kind: "ENTRYPOINT_DEPOSIT_WITHDRAWAL";
      readonly recipient: string;
      readonly amountWei: BigNumberish;
    }
  | {
      readonly kind: "VALIDATOR_ROTATION";
      readonly proposedValidator: string;
      readonly proposedValidatorKeyIdBinding: Hex;
      readonly proposedValidatorEpoch: BigNumberish;
    }
  | {
      readonly kind: "RECOVERY_REQUEST";
      readonly proposedValidator: string;
      readonly proposedValidatorKeyIdBinding: Hex;
      readonly proposedValidatorEpoch: BigNumberish;
      readonly recoveryRequestSalt: Hex;
    }
  | {
      readonly kind: "RECOVERY_CANCEL";
      readonly recoveryRequestId: Hex;
    }
  | {
      readonly kind: "RECOVERY_CONFIG_ROTATION_REQUEST";
      readonly proposedRecoveryConfigHash: Hex;
      readonly proposedPrimaryDeviceCommitment: Hex;
      readonly proposedHardwareSecurityKeyCommitment: Hex;
      readonly proposedRecoveryFactorCommitment: Hex;
      readonly proposedRecoveryEpoch: BigNumberish;
    }
  | {
      readonly kind: "RECOVERY_CONFIG_ROTATION_CANCEL";
      readonly recoveryConfigRotationRequestId: Hex;
    };

export interface PhilCoreV2IntentInput {
  readonly header: PhilCoreV2IntentCoreHeaderInput;
  readonly payload: PhilCoreV2ActionPayloadInput;
}

export interface PhilCoreV2IntentEncoding {
  readonly header: PhilCoreV2IntentCoreHeader;
  readonly coreHeaderEncoding: Hex;
  readonly coreHeaderHash: Hex;
  readonly actionEncoding: Hex;
  readonly intentCoreHash: Hex;
}

function bytes32(value: unknown, label: string, allowZero = false): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (!allowZero && normalized === ZERO_BYTES32) {
    throw new Error(`${label}_must_be_nonzero`);
  }
  return normalized;
}

function uint(
  value: BigNumberish,
  bits: number,
  label: string,
  options: { readonly nonzero?: boolean } = {}
): bigint {
  let parsed: bigint;
  try {
    parsed = BigInt(value);
  } catch {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  if (parsed < 0n || parsed >= (1n << BigInt(bits))) {
    throw new Error(`${label}_must_be_uint${bits}`);
  }
  if (options.nonzero === true && parsed === 0n) {
    throw new Error(`${label}_must_be_nonzero`);
  }
  return parsed;
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

function actionType(value: BigNumberish): PhilCoreV2ActionType {
  const parsed = uint(value, 8, "actionType", { nonzero: true });
  if (!Object.values(PHILCORE_V2_ACTION_TYPE).includes(Number(parsed) as PhilCoreV2ActionType)) {
    throw new Error("actionType_unsupported");
  }
  return Number(parsed) as PhilCoreV2ActionType;
}

function payloadActionType(payload: PhilCoreV2ActionPayloadInput): PhilCoreV2ActionType {
  return PHILCORE_V2_ACTION_TYPE[payload.kind];
}

function assertPurpose(action: PhilCoreV2ActionType, purpose: Hex): void {
  if (!ACTION_PURPOSES[action].includes(purpose)) {
    throw new Error("purpose_not_allowed_for_action");
  }
}

function assertDistinctFromAccount(
  candidate: string,
  account: string,
  label: string
): void {
  if (candidate === account) throw new Error(`${label}_cannot_equal_account`);
}

export function normalizePhilCoreV2IntentCoreHeader(
  input: PhilCoreV2IntentCoreHeaderInput
): PhilCoreV2IntentCoreHeader {
  const normalizedActionType = actionType(input.actionType);
  const normalizedPurpose = bytes32(input.purpose, "purpose");
  const normalizedNonceKey = uint(input.nonceKey, 192, "nonceKey");
  const validAfter = uint(input.validAfter, 48, "validAfter");
  const validUntil = uint(input.validUntil, 48, "validUntil");
  const expectedLifetime = normalizedActionType >= PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST
    ? 3600n
    : 600n;

  if (uint(input.specificationVersion, 8, "specificationVersion")
      !== BigInt(PHILCORE_V2_INTENT_SPECIFICATION_VERSION)) {
    throw new Error("specificationVersion_unsupported");
  }
  if (bytes32(input.securityModelId, "securityModelId")
      !== PHILCORE_V2_SECURITY_MODEL_ID.toLowerCase()) {
    throw new Error("securityModelId_unsupported");
  }
  if (normalizedNonceKey !== ACTION_NONCE_KEYS[normalizedActionType]) {
    throw new Error("nonceKey_not_allowed_for_action");
  }
  assertPurpose(normalizedActionType, normalizedPurpose);
  if (validUntil <= validAfter) throw new Error("validity_range_invalid");
  if (validUntil - validAfter > expectedLifetime) {
    throw new Error("validity_lifetime_exceeded");
  }

  return Object.freeze({
    specificationVersion: BigInt(PHILCORE_V2_INTENT_SPECIFICATION_VERSION),
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID.toLowerCase() as Hex,
    actionType: normalizedActionType,
    actionId: bytes32(input.actionId, "actionId"),
    purpose: normalizedPurpose,
    ownerCommitment: bytes32(input.ownerCommitment, "ownerCommitment"),
    chainId: uint(input.chainId, 256, "chainId", { nonzero: true }),
    entryPoint: address(input.entryPoint, "entryPoint"),
    account: address(input.account, "account"),
    nonceKey: normalizedNonceKey,
    nonceSequence: uint(input.nonceSequence, 64, "nonceSequence"),
    validatorEpoch: uint(input.validatorEpoch, 64, "validatorEpoch", {
      nonzero: true
    }),
    recoveryEpoch: uint(input.recoveryEpoch, 64, "recoveryEpoch", {
      nonzero: true
    }),
    applicationContextHash: bytes32(
      input.applicationContextHash,
      "applicationContextHash"
    ),
    fundLifecycleDigest: bytes32(
      input.fundLifecycleDigest,
      "fundLifecycleDigest"
    ),
    maxTotalFeeWei: uint(input.maxTotalFeeWei, 256, "maxTotalFeeWei", {
      nonzero: true
    }),
    validAfter,
    validUntil
  });
}

export function computePhilCoreV2ApplicationContextHash(
  input: PhilCoreV2ApplicationContextInput
): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      PHILCORE_V2_TYPEHASH.APPLICATION_CONTEXT,
      bytes32(input.applicationIdHash, "applicationIdHash"),
      bytes32(input.originHash, "originHash"),
      bytes32(input.sessionIdHash, "sessionIdHash"),
      bytes32(input.capabilityGrantIdHash, "capabilityGrantIdHash"),
      bytes32(input.policyDecisionIdHash, "policyDecisionIdHash")
    ]
  )) as Hex;
}

export function computePhilCoreV2FundLifecycleDigest(
  input: PhilCoreV2FundLifecycleInput
): Hex {
  const maximumFundingOrHolding = uint(
    input.maximumFundingOrHolding,
    256,
    "maximumFundingOrHolding"
  );
  const maximumStranded = uint(input.maximumStranded, 256, "maximumStranded");
  if (maximumStranded > maximumFundingOrHolding) {
    throw new Error("maximumStranded_exceeds_maximumFundingOrHolding");
  }
  return keccak256(abiCoder.encode(
    [
      "bytes32",
      "bytes32",
      "address",
      "address",
      "uint256",
      "uint256",
      "uint256",
      "address",
      "uint256",
      "uint256",
      "bytes32",
      "bytes32"
    ],
    [
      PHILCORE_V2_TYPEHASH.FUND_LIFECYCLE,
      bytes32(input.lifecycleSchemaHash, "lifecycleSchemaHash"),
      address(input.account, "fundLifecycle.account"),
      address(input.asset, "fundLifecycle.asset", true),
      uint(input.tokenId, 256, "tokenId"),
      maximumFundingOrHolding,
      maximumStranded,
      address(input.residualRecipient, "residualRecipient", true),
      uint(input.expectedPostOperationBalance, 256, "expectedPostOperationBalance"),
      uint(input.expectedFinalBalance, 256, "expectedFinalBalance"),
      bytes32(input.releaseRouteHash, "releaseRouteHash"),
      bytes32(input.simulationEvidenceHash, "simulationEvidenceHash")
    ]
  )) as Hex;
}

export function encodePhilCoreV2IntentCoreHeader(
  input: PhilCoreV2IntentCoreHeaderInput | PhilCoreV2IntentCoreHeader
): Hex {
  const header = normalizePhilCoreV2IntentCoreHeader(input);
  return abiCoder.encode(
    [
      "bytes32",
      "uint8",
      "bytes32",
      "uint8",
      "bytes32",
      "bytes32",
      "bytes32",
      "uint256",
      "address",
      "address",
      "uint192",
      "uint64",
      "uint64",
      "uint64",
      "bytes32",
      "bytes32",
      "uint256",
      "uint48",
      "uint48"
    ],
    [
      PHILCORE_V2_TYPEHASH.INTENT_CORE_HEADER,
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
    ]
  ) as Hex;
}

export function computePhilCoreV2IntentCoreHeaderHash(
  input: PhilCoreV2IntentCoreHeaderInput | PhilCoreV2IntentCoreHeader
): Hex {
  return keccak256(encodePhilCoreV2IntentCoreHeader(input)) as Hex;
}

function encodeAction(
  header: PhilCoreV2IntentCoreHeader,
  coreHeaderHash: Hex,
  payload: PhilCoreV2ActionPayloadInput
): Hex {
  const expectedActionType = payloadActionType(payload);
  if (header.actionType !== expectedActionType) {
    throw new Error("payload_actionType_mismatch");
  }

  switch (payload.kind) {
    case "CONFIRM":
      return abiCoder.encode(
        ["bytes32", "bytes32", "address", "bytes32"],
        [
          PHILCORE_V2_TYPEHASH.CONFIRM,
          coreHeaderHash,
          address(payload.confirmationTarget, "confirmationTarget"),
          bytes32(payload.confirmationDigest, "confirmationDigest")
        ]
      ) as Hex;
    case "NATIVE_TRANSFER": {
      const recipient = address(payload.recipient, "recipient");
      assertDistinctFromAccount(recipient, header.account, "recipient");
      return abiCoder.encode(
        ["bytes32", "bytes32", "address", "uint256"],
        [
          PHILCORE_V2_TYPEHASH.NATIVE_TRANSFER,
          coreHeaderHash,
          recipient,
          uint(payload.amountWei, 256, "amountWei", { nonzero: true })
        ]
      ) as Hex;
    }
    case "ERC20_TRANSFER": {
      const token = address(payload.token, "token");
      const recipient = address(payload.recipient, "recipient");
      assertDistinctFromAccount(recipient, header.account, "recipient");
      return abiCoder.encode(
        ["bytes32", "bytes32", "address", "address", "uint256"],
        [
          PHILCORE_V2_TYPEHASH.ERC20_TRANSFER,
          coreHeaderHash,
          token,
          recipient,
          uint(payload.amount, 256, "amount", { nonzero: true })
        ]
      ) as Hex;
    }
    case "ERC721_SAFE_TRANSFER": {
      const recipient = address(payload.recipient, "recipient");
      assertDistinctFromAccount(recipient, header.account, "recipient");
      return abiCoder.encode(
        ["bytes32", "bytes32", "address", "address", "uint256", "bytes32"],
        [
          PHILCORE_V2_TYPEHASH.ERC721_SAFE_TRANSFER,
          coreHeaderHash,
          address(payload.token, "token"),
          recipient,
          uint(payload.tokenId, 256, "tokenId"),
          bytes32(payload.receiverDataHash, "receiverDataHash")
        ]
      ) as Hex;
    }
    case "ERC1155_SAFE_TRANSFER": {
      const recipient = address(payload.recipient, "recipient");
      assertDistinctFromAccount(recipient, header.account, "recipient");
      return abiCoder.encode(
        [
          "bytes32",
          "bytes32",
          "address",
          "address",
          "uint256",
          "uint256",
          "bytes32"
        ],
        [
          PHILCORE_V2_TYPEHASH.ERC1155_SAFE_TRANSFER,
          coreHeaderHash,
          address(payload.token, "token"),
          recipient,
          uint(payload.tokenId, 256, "tokenId"),
          uint(payload.amount, 256, "amount", { nonzero: true }),
          bytes32(payload.receiverDataHash, "receiverDataHash")
        ]
      ) as Hex;
    }
    case "ENTRYPOINT_DEPOSIT_WITHDRAWAL": {
      const recipient = address(payload.recipient, "recipient");
      assertDistinctFromAccount(recipient, header.account, "recipient");
      return abiCoder.encode(
        ["bytes32", "bytes32", "address", "uint256"],
        [
          PHILCORE_V2_TYPEHASH.ENTRYPOINT_DEPOSIT_WITHDRAWAL,
          coreHeaderHash,
          recipient,
          uint(payload.amountWei, 256, "amountWei", { nonzero: true })
        ]
      ) as Hex;
    }
    case "VALIDATOR_ROTATION":
      if (
        uint(
          payload.proposedValidatorEpoch,
          64,
          "proposedValidatorEpoch",
          { nonzero: true }
        ) !== header.validatorEpoch + 1n
      ) {
        throw new Error(
          "proposedValidatorEpoch_must_equal_current_plus_one"
        );
      }
      return abiCoder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "uint64"],
        [
          PHILCORE_V2_TYPEHASH.VALIDATOR_ROTATION,
          coreHeaderHash,
          address(payload.proposedValidator, "proposedValidator"),
          bytes32(
            payload.proposedValidatorKeyIdBinding,
            "proposedValidatorKeyIdBinding"
          ),
          uint(
            payload.proposedValidatorEpoch,
            64,
            "proposedValidatorEpoch",
            { nonzero: true }
          )
        ]
      ) as Hex;
    case "RECOVERY_REQUEST":
      if (
        uint(
          payload.proposedValidatorEpoch,
          64,
          "proposedValidatorEpoch",
          { nonzero: true }
        ) !== header.validatorEpoch + 1n
      ) {
        throw new Error(
          "proposedValidatorEpoch_must_equal_current_plus_one"
        );
      }
      return abiCoder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "uint64", "bytes32"],
        [
          PHILCORE_V2_TYPEHASH.RECOVERY_REQUEST,
          coreHeaderHash,
          address(payload.proposedValidator, "proposedValidator"),
          bytes32(
            payload.proposedValidatorKeyIdBinding,
            "proposedValidatorKeyIdBinding"
          ),
          uint(
            payload.proposedValidatorEpoch,
            64,
            "proposedValidatorEpoch",
            { nonzero: true }
          ),
          bytes32(payload.recoveryRequestSalt, "recoveryRequestSalt")
        ]
      ) as Hex;
    case "RECOVERY_CANCEL":
      return abiCoder.encode(
        ["bytes32", "bytes32", "bytes32"],
        [
          PHILCORE_V2_TYPEHASH.RECOVERY_CANCEL,
          coreHeaderHash,
          bytes32(payload.recoveryRequestId, "recoveryRequestId")
        ]
      ) as Hex;
    case "RECOVERY_CONFIG_ROTATION_REQUEST": {
      if (
        uint(
          payload.proposedRecoveryEpoch,
          64,
          "proposedRecoveryEpoch",
          { nonzero: true }
        ) !== header.recoveryEpoch + 1n
      ) {
        throw new Error(
          "proposedRecoveryEpoch_must_equal_current_plus_one"
        );
      }
      const commitments = [
        bytes32(
          payload.proposedPrimaryDeviceCommitment,
          "proposedPrimaryDeviceCommitment"
        ),
        bytes32(
          payload.proposedHardwareSecurityKeyCommitment,
          "proposedHardwareSecurityKeyCommitment"
        ),
        bytes32(
          payload.proposedRecoveryFactorCommitment,
          "proposedRecoveryFactorCommitment"
        )
      ] as const;
      if (new Set(commitments).size !== commitments.length) {
        throw new Error("proposed_factor_commitments_must_be_unique");
      }
      return abiCoder.encode(
        [
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "uint64"
        ],
        [
          PHILCORE_V2_TYPEHASH.RECOVERY_CONFIG_ROTATION_REQUEST,
          coreHeaderHash,
          bytes32(
            payload.proposedRecoveryConfigHash,
            "proposedRecoveryConfigHash"
          ),
          ...commitments,
          uint(
            payload.proposedRecoveryEpoch,
            64,
            "proposedRecoveryEpoch",
            { nonzero: true }
          )
        ]
      ) as Hex;
    }
    case "RECOVERY_CONFIG_ROTATION_CANCEL":
      return abiCoder.encode(
        ["bytes32", "bytes32", "bytes32"],
        [
          PHILCORE_V2_TYPEHASH.RECOVERY_CONFIG_ROTATION_CANCEL,
          coreHeaderHash,
          bytes32(
            payload.recoveryConfigRotationRequestId,
            "recoveryConfigRotationRequestId"
          )
        ]
      ) as Hex;
  }
}

export function encodePhilCoreV2Intent(
  input: PhilCoreV2IntentInput
): PhilCoreV2IntentEncoding {
  const header = normalizePhilCoreV2IntentCoreHeader(input.header);
  const coreHeaderEncoding = encodePhilCoreV2IntentCoreHeader(header);
  const coreHeaderHash = keccak256(coreHeaderEncoding) as Hex;
  const actionEncoding = encodeAction(header, coreHeaderHash, input.payload);
  return Object.freeze({
    header,
    coreHeaderEncoding,
    coreHeaderHash,
    actionEncoding,
    intentCoreHash: keccak256(actionEncoding) as Hex
  });
}

export function computePhilCoreV2IntentCoreHash(
  input: PhilCoreV2IntentInput
): Hex {
  return encodePhilCoreV2Intent(input).intentCoreHash;
}

export function computePhilCoreV2DomainSeparator(input: {
  readonly chainId: BigNumberish;
  readonly account: string;
}): Hex {
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "uint256", "address"],
    [
      PHILCORE_V2_TYPEHASH.EIP712_DOMAIN,
      keccak256(toUtf8Bytes(PHILCORE_V2_EIP712_NAME)),
      keccak256(toUtf8Bytes(PHILCORE_V2_EIP712_VERSION)),
      uint(input.chainId, 256, "chainId", { nonzero: true }),
      address(input.account, "account")
    ]
  )) as Hex;
}

export function computePhilCoreV2TypedDataDigest(input: {
  readonly domainSeparator: Hex;
  readonly structHash: Hex;
}): Hex {
  return keccak256(concat([
    "0x1901",
    bytes32(input.domainSeparator, "domainSeparator"),
    bytes32(input.structHash, "structHash")
  ])) as Hex;
}

export function composePhilCoreV2Nonce(input: {
  readonly key: BigNumberish;
  readonly sequence: BigNumberish;
}): bigint {
  const key = uint(input.key, 192, "nonceKey");
  const sequence = uint(input.sequence, 64, "nonceSequence");
  return (key << 64n) | sequence;
}

export function decomposePhilCoreV2Nonce(nonce: BigNumberish): Readonly<{
  key: bigint;
  sequence: bigint;
}> {
  const value = uint(nonce, 256, "nonce");
  return Object.freeze({
    key: value >> 64n,
    sequence: value & ((1n << 64n) - 1n)
  });
}

export function expectedPhilCoreV2NonceKey(
  action: PhilCoreV2ActionType
): bigint {
  if (!ACTION_NONCE_KEYS[action]) {
    if (ACTION_NONCE_KEYS[action] !== 0n) throw new Error("actionType_unsupported");
  }
  return ACTION_NONCE_KEYS[action];
}
