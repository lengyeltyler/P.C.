import {
  getAddress,
  isHexString,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_NONCE_KEY,
  composePhilCoreV2Nonce,
  encodePhilCoreV2Intent,
  type PhilCoreV2IntentInput
} from "./v2Intent.ts";
import {
  computePhilCoreV2AuthorizedIntentHash,
  computePhilCoreV2CombinedCancellationDigest,
  computePhilCoreV2ConfigRotationDigest,
  computePhilCoreV2RecoveryFactorDigest,
  computePhilCoreV2RuntimeAuthorizationDigest,
  computePhilCoreV2ValidatorDigest,
  type PhilCoreV2RuntimeAuthorizationInput
} from "./v2Authorization.ts";
import {
  PHILCORE_V2_AUTHORITY_EVIDENCE_FORMAT,
  PHILCORE_V2_RECOVERY_AUTHORITY_FORMAT,
  PHILCORE_V2_VALIDATOR_SIGNATURE_FORMAT,
  createPhilCoreV2ValidatorState,
  type PhilCoreV2AuthorityEvidenceReference,
  type PhilCoreV2AuthorityKind,
  type PhilCoreV2AuthorityVerifier,
  type PhilCoreV2ValidatorState
} from "./v2Validator.ts";

const RECOVERY_FACTOR_BITMAPS = Object.freeze([0b011, 0b101, 0b110]);

export const PHILCORE_V2_AUTHORIZATION_FAILURE_CODES = Object.freeze([
  "STATE_INVALID",
  "INTENT_INVALID",
  "CHAIN_MISMATCH",
  "ENTRYPOINT_MISMATCH",
  "ACCOUNT_MISMATCH",
  "OWNER_COMMITMENT_MISMATCH",
  "AUTHORIZATION_NOT_YET_VALID",
  "AUTHORIZATION_EXPIRED",
  "VALIDATOR_REVOKED",
  "VALIDATOR_MISMATCH",
  "VALIDATOR_KEY_ID_MISMATCH",
  "VALIDATOR_EPOCH_STALE",
  "VALIDATOR_EPOCH_FUTURE",
  "RECOVERY_EPOCH_STALE",
  "RECOVERY_EPOCH_FUTURE",
  "RECOVERY_CONFIG_MISMATCH",
  "ORDINARY_EXECUTION_FROZEN",
  "MAINTENANCE_FROZEN",
  "RECOVERY_ACTION_INVALID_FOR_STATE",
  "INTENT_HASH_MISMATCH",
  "RUNTIME_INTENT_HASH_MISMATCH",
  "RUNTIME_AUTHORIZATION_DIGEST_MISMATCH",
  "AUTHORIZED_INTENT_HASH_MISMATCH",
  "AUTHORITY_MISSING",
  "AUTHORITY_KIND_MISMATCH",
  "RECOVERY_THRESHOLD_NOT_MET",
  "RECOVERY_FACTOR_BITMAP_INVALID",
  "AUTHORITY_DIGEST_INVALID",
  "AUTHORITY_DIGEST_MISMATCH",
  "AUTHORITY_EVIDENCE_MALFORMED",
  "AUTHORITY_VERIFIER_UNSAFE",
  "SIGNATURE_INVALID",
  "AUTHORIZATION_REPLAY",
  "NONCE_REPLAY"
] as const);

export type PhilCoreV2AuthorizationFailureCode =
  typeof PHILCORE_V2_AUTHORIZATION_FAILURE_CODES[number];

export type PhilCoreV2AuthorizationFailureStage =
  | "state"
  | "intent"
  | "runtime"
  | "authority"
  | "recovery"
  | "replay";

export interface PhilCoreV2ValidatorAuthorityInput {
  readonly authorityKind: PhilCoreV2AuthorityKind;
  readonly validator: string;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorEpoch: BigNumberish;
  readonly recoveryEpoch: BigNumberish;
  readonly recoveryConfigHash: Hex;
  readonly factorBitmap?: number;
  readonly evidence: PhilCoreV2AuthorityEvidenceReference;
  readonly declaredAuthorityDigest: Hex;
}

export interface PhilCoreV2AuthorizationPackage {
  readonly intent: PhilCoreV2IntentInput;
  readonly declaredIntentCoreHash: Hex;
  readonly runtimeAuthorization: PhilCoreV2RuntimeAuthorizationInput;
  readonly declaredRuntimeAuthorizationDigest: Hex;
  readonly declaredAuthorizedIntentHash: Hex;
  readonly userOperationHashBinding: Hex;
  readonly authority?: PhilCoreV2ValidatorAuthorityInput;
}

export interface PhilCoreV2AuthorizationVerificationRequest {
  readonly state: PhilCoreV2ValidatorState;
  readonly authorizationPackage: PhilCoreV2AuthorizationPackage;
  readonly currentTime: BigNumberish;
  readonly authorityVerifier: PhilCoreV2AuthorityVerifier;
}

export type PhilCoreV2AuthorizedStateTransition =
  | "none"
  | "rotate_validator"
  | "begin_recovery"
  | "cancel_recovery"
  | "begin_recovery_config_rotation"
  | "cancel_recovery_config_rotation";

export type PhilCoreV2AuthorizationVerificationResult =
  | Readonly<{
      accepted: true;
      status: "accepted";
      classification: "LOCAL_AUTHORIZATION_ACCEPTED_NON_EXECUTABLE";
      intentCoreHash: Hex;
      runtimeAuthorizationDigest: Hex;
      authorizedIntentHash: Hex;
      authorityDigest: Hex;
      keyedNonce: bigint;
      authorityKind: PhilCoreV2AuthorityKind;
      verifierId: string;
      authorizedStateTransition: PhilCoreV2AuthorizedStateTransition;
      executionPerformed: false;
      signatureProduced: false;
      userOperationCreated: false;
      publicMutationCount: 0;
    }>
  | Readonly<{
      accepted: false;
      status: "rejected";
      code: PhilCoreV2AuthorizationFailureCode;
      stage: PhilCoreV2AuthorizationFailureStage;
      executionPerformed: false;
      signatureProduced: false;
      userOperationCreated: false;
      publicMutationCount: 0;
    }>;

function rejected(
  code: PhilCoreV2AuthorizationFailureCode,
  stage: PhilCoreV2AuthorizationFailureStage
): PhilCoreV2AuthorizationVerificationResult {
  return Object.freeze({
    accepted: false,
    status: "rejected",
    code,
    stage,
    executionPerformed: false,
    signatureProduced: false,
    userOperationCreated: false,
    publicMutationCount: 0
  });
}

function bytes32(value: unknown): Hex | undefined {
  if (typeof value !== "string" || !isHexString(value, 32)) return undefined;
  if (value === `0x${"00".repeat(32)}`) return undefined;
  return value.toLowerCase() as Hex;
}

function bigint(value: BigNumberish): bigint | undefined {
  try {
    const parsed = BigInt(value);
    return parsed >= 0n ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function address(value: string): string | undefined {
  try {
    return getAddress(value);
  } catch {
    return undefined;
  }
}

function requiredAuthorityKinds(
  actionType: number
): readonly PhilCoreV2AuthorityKind[] {
  switch (actionType) {
    case PHILCORE_V2_ACTION_TYPE.CONFIRM:
    case PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER:
    case PHILCORE_V2_ACTION_TYPE.ERC20_TRANSFER:
    case PHILCORE_V2_ACTION_TYPE.ERC721_SAFE_TRANSFER:
    case PHILCORE_V2_ACTION_TYPE.ERC1155_SAFE_TRANSFER:
    case PHILCORE_V2_ACTION_TYPE.ENTRYPOINT_DEPOSIT_WITHDRAWAL:
    case PHILCORE_V2_ACTION_TYPE.VALIDATOR_ROTATION:
      return ["validator_signature"];
    case PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST:
      return ["recovery_threshold"];
    case PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL:
    case PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL:
      return ["recovery_threshold"];
    case PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST:
      return ["recovery_config_rotation"];
    default:
      return [];
  }
}

function expectedStateTransition(
  actionType: number
): PhilCoreV2AuthorizedStateTransition {
  switch (actionType) {
    case PHILCORE_V2_ACTION_TYPE.VALIDATOR_ROTATION:
      return "rotate_validator";
    case PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST:
      return "begin_recovery";
    case PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL:
      return "cancel_recovery";
    case PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST:
      return "begin_recovery_config_rotation";
    case PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL:
      return "cancel_recovery_config_rotation";
    default:
      return "none";
  }
}

function recoveryStateFailure(
  state: PhilCoreV2ValidatorState,
  actionType: number,
  nonceKey: bigint
): PhilCoreV2AuthorizationVerificationResult | undefined {
  if (state.recoveryState === "recovery_active") {
    if (nonceKey === PHILCORE_V2_NONCE_KEY.ORDINARY) {
      return rejected("ORDINARY_EXECUTION_FROZEN", "recovery");
    }
    if (nonceKey === PHILCORE_V2_NONCE_KEY.MAINTENANCE) {
      return rejected("MAINTENANCE_FROZEN", "recovery");
    }
    if (actionType !== PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL) {
      return rejected("RECOVERY_ACTION_INVALID_FOR_STATE", "recovery");
    }
    return undefined;
  }
  if (state.recoveryState === "recovery_config_rotation_active") {
    if (nonceKey === PHILCORE_V2_NONCE_KEY.MAINTENANCE) {
      return rejected("MAINTENANCE_FROZEN", "recovery");
    }
    if (
      nonceKey === PHILCORE_V2_NONCE_KEY.RECOVERY
      && actionType
        !== PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL
    ) {
      return rejected("RECOVERY_ACTION_INVALID_FOR_STATE", "recovery");
    }
    return undefined;
  }
  if (
    actionType === PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL
    || actionType
      === PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL
  ) {
    return rejected("RECOVERY_ACTION_INVALID_FOR_STATE", "recovery");
  }
  return undefined;
}

function factorBitmapFailure(
  value: number | undefined
): PhilCoreV2AuthorizationVerificationResult | undefined {
  if (value === undefined || !Number.isInteger(value) || value < 0) {
    return rejected("RECOVERY_FACTOR_BITMAP_INVALID", "authority");
  }
  if (value === 1 || value === 2 || value === 4) {
    return rejected("RECOVERY_THRESHOLD_NOT_MET", "authority");
  }
  if (!RECOVERY_FACTOR_BITMAPS.includes(value)) {
    return rejected("RECOVERY_FACTOR_BITMAP_INVALID", "authority");
  }
  return undefined;
}

function computeAuthorityDigest(input: {
  readonly state: PhilCoreV2ValidatorState;
  readonly authorizationPackage: PhilCoreV2AuthorizationPackage;
  readonly authorizedIntentHash: Hex;
  readonly authority: PhilCoreV2ValidatorAuthorityInput;
}): Hex {
  const domain = {
    chainId: input.state.chainId,
    account: input.state.account
  };
  const common = {
    authorizedIntentHash: input.authorizedIntentHash,
    userOperationHash: input.authorizationPackage.userOperationHashBinding,
    recoveryConfigHash: input.authority.recoveryConfigHash,
    recoveryEpoch: input.authority.recoveryEpoch,
    factorBitmap: input.authority.factorBitmap ?? 0
  };
  switch (input.authority.authorityKind) {
    case "validator_signature":
      return computePhilCoreV2ValidatorDigest(domain, {
        authorizedIntentHash: input.authorizedIntentHash,
        userOperationHash:
          input.authorizationPackage.userOperationHashBinding,
        validator: input.authority.validator,
        validatorKeyIdBinding: input.authority.validatorKeyIdBinding,
        validatorEpoch: input.authority.validatorEpoch,
        recoveryEpoch: input.authority.recoveryEpoch
      }).digest;
    case "recovery_threshold":
      return computePhilCoreV2RecoveryFactorDigest(domain, common).digest;
    case "combined_validator_recovery":
      return computePhilCoreV2CombinedCancellationDigest(domain, {
        ...common,
        validator: input.authority.validator,
        validatorEpoch: input.authority.validatorEpoch
      }).digest;
    case "recovery_config_rotation": {
      const payload = input.authorizationPackage.intent.payload;
      if (payload.kind !== "RECOVERY_CONFIG_ROTATION_REQUEST") {
        throw new Error("recovery_config_rotation_payload_required");
      }
      return computePhilCoreV2ConfigRotationDigest(domain, {
        ...common,
        validator: input.authority.validator,
        validatorEpoch: input.authority.validatorEpoch,
        proposedRecoveryConfigHash: payload.proposedRecoveryConfigHash,
        proposedRecoveryEpoch: payload.proposedRecoveryEpoch
      }).digest;
    }
  }
}

export async function verifyPhilCoreV2Authorization(
  request: PhilCoreV2AuthorizationVerificationRequest
): Promise<PhilCoreV2AuthorizationVerificationResult> {
  let state: PhilCoreV2ValidatorState;
  try {
    state = createPhilCoreV2ValidatorState(request.state);
  } catch {
    return rejected("STATE_INVALID", "state");
  }

  const packageValue = request.authorizationPackage;
  const rawHeader = packageValue?.intent?.header;
  const chainId = rawHeader ? bigint(rawHeader.chainId) : undefined;
  const entryPoint = rawHeader ? address(rawHeader.entryPoint) : undefined;
  const account = rawHeader ? address(rawHeader.account) : undefined;
  const ownerCommitment = rawHeader
    ? bytes32(rawHeader.ownerCommitment)
    : undefined;
  if (
    chainId === undefined
    || entryPoint === undefined
    || account === undefined
    || ownerCommitment === undefined
  ) {
    return rejected("INTENT_INVALID", "intent");
  }
  if (chainId !== state.chainId) return rejected("CHAIN_MISMATCH", "intent");
  if (entryPoint !== state.entryPoint) {
    return rejected("ENTRYPOINT_MISMATCH", "intent");
  }
  if (account !== state.account) return rejected("ACCOUNT_MISMATCH", "intent");
  if (ownerCommitment !== state.ownerCommitment) {
    return rejected("OWNER_COMMITMENT_MISMATCH", "intent");
  }

  let encoded: ReturnType<typeof encodePhilCoreV2Intent>;
  try {
    encoded = encodePhilCoreV2Intent(packageValue.intent);
  } catch {
    return rejected("INTENT_INVALID", "intent");
  }
  const now = bigint(request.currentTime);
  if (now === undefined) return rejected("INTENT_INVALID", "intent");
  if (now < encoded.header.validAfter) {
    return rejected("AUTHORIZATION_NOT_YET_VALID", "intent");
  }
  if (now > encoded.header.validUntil) {
    return rejected("AUTHORIZATION_EXPIRED", "intent");
  }
  if (encoded.header.validatorEpoch < state.validatorEpoch) {
    return rejected("VALIDATOR_EPOCH_STALE", "intent");
  }
  if (encoded.header.validatorEpoch > state.validatorEpoch) {
    return rejected("VALIDATOR_EPOCH_FUTURE", "intent");
  }
  if (encoded.header.recoveryEpoch < state.recoveryEpoch) {
    return rejected("RECOVERY_EPOCH_STALE", "intent");
  }
  if (encoded.header.recoveryEpoch > state.recoveryEpoch) {
    return rejected("RECOVERY_EPOCH_FUTURE", "intent");
  }

  const recoveryFailure = recoveryStateFailure(
    state,
    encoded.header.actionType,
    encoded.header.nonceKey
  );
  if (recoveryFailure) return recoveryFailure;

  const declaredIntentCoreHash = bytes32(packageValue.declaredIntentCoreHash);
  if (
    declaredIntentCoreHash === undefined
    || declaredIntentCoreHash !== encoded.intentCoreHash
  ) {
    return rejected("INTENT_HASH_MISMATCH", "intent");
  }

  if (
    bytes32(packageValue.runtimeAuthorization.intentCoreHash)
      !== encoded.intentCoreHash
  ) {
    return rejected("RUNTIME_INTENT_HASH_MISMATCH", "runtime");
  }
  let runtimeAuthorizationDigest: Hex;
  try {
    runtimeAuthorizationDigest =
      computePhilCoreV2RuntimeAuthorizationDigest(
        packageValue.runtimeAuthorization
      );
  } catch {
    return rejected("RUNTIME_AUTHORIZATION_DIGEST_MISMATCH", "runtime");
  }
  if (
    bytes32(packageValue.declaredRuntimeAuthorizationDigest)
      !== runtimeAuthorizationDigest
  ) {
    return rejected(
      "RUNTIME_AUTHORIZATION_DIGEST_MISMATCH",
      "runtime"
    );
  }
  const authorizedIntentHash = computePhilCoreV2AuthorizedIntentHash({
    intentCoreHash: encoded.intentCoreHash,
    runtimeAuthorizationDigest
  });
  if (
    bytes32(packageValue.declaredAuthorizedIntentHash)
      !== authorizedIntentHash
  ) {
    return rejected("AUTHORIZED_INTENT_HASH_MISMATCH", "runtime");
  }

  const keyedNonce = composePhilCoreV2Nonce({
    key: encoded.header.nonceKey,
    sequence: encoded.header.nonceSequence
  });
  if (state.consumedNonces.includes(keyedNonce)) {
    return rejected("NONCE_REPLAY", "replay");
  }

  const authority = packageValue.authority;
  if (!authority) return rejected("AUTHORITY_MISSING", "authority");
  const requiredKinds = requiredAuthorityKinds(encoded.header.actionType);
  if (!requiredKinds.includes(authority.authorityKind)) {
    return rejected("AUTHORITY_KIND_MISMATCH", "authority");
  }
  if (
    authority.authorityKind !== "validator_signature"
  ) {
    const bitmapFailure = factorBitmapFailure(authority.factorBitmap);
    if (bitmapFailure) return bitmapFailure;
  }

  const authorityValidator = address(authority.validator);
  if (authorityValidator !== state.validator) {
    return rejected("VALIDATOR_MISMATCH", "authority");
  }
  if (
    bytes32(authority.validatorKeyIdBinding)
      !== state.validatorKeyIdBinding
  ) {
    return rejected("VALIDATOR_KEY_ID_MISMATCH", "authority");
  }
  const validatorEpoch = bigint(authority.validatorEpoch);
  if (validatorEpoch === undefined) {
    return rejected("VALIDATOR_EPOCH_FUTURE", "authority");
  }
  if (validatorEpoch < state.validatorEpoch) {
    return rejected("VALIDATOR_EPOCH_STALE", "authority");
  }
  if (validatorEpoch > state.validatorEpoch) {
    return rejected("VALIDATOR_EPOCH_FUTURE", "authority");
  }
  const recoveryEpoch = bigint(authority.recoveryEpoch);
  if (recoveryEpoch === undefined) {
    return rejected("RECOVERY_EPOCH_FUTURE", "authority");
  }
  if (recoveryEpoch < state.recoveryEpoch) {
    return rejected("RECOVERY_EPOCH_STALE", "authority");
  }
  if (recoveryEpoch > state.recoveryEpoch) {
    return rejected("RECOVERY_EPOCH_FUTURE", "authority");
  }
  if (
    bytes32(authority.recoveryConfigHash) !== state.recoveryConfigHash
  ) {
    return rejected("RECOVERY_CONFIG_MISMATCH", "authority");
  }
  if (
    authority.authorityKind === "validator_signature"
    && state.validatorStatus !== "active"
  ) {
    return rejected("VALIDATOR_REVOKED", "authority");
  }

  let authorityDigest: Hex;
  try {
    authorityDigest = computeAuthorityDigest({
      state,
      authorizationPackage: packageValue,
      authorizedIntentHash,
      authority
    });
  } catch {
    return rejected("AUTHORITY_DIGEST_INVALID", "authority");
  }
  if (
    bytes32(authority.declaredAuthorityDigest) !== authorityDigest
  ) {
    return rejected("AUTHORITY_DIGEST_MISMATCH", "authority");
  }
  if (state.consumedAuthorizationDigests.includes(authorityDigest)) {
    return rejected("AUTHORIZATION_REPLAY", "replay");
  }

  const userOperationHashBinding = bytes32(
    packageValue.userOperationHashBinding
  );
  if (userOperationHashBinding === undefined) {
    return rejected("AUTHORITY_DIGEST_INVALID", "authority");
  }
  const expectedEvidenceVerificationFormat =
    authority.authorityKind === "validator_signature"
      ? PHILCORE_V2_VALIDATOR_SIGNATURE_FORMAT
      : PHILCORE_V2_RECOVERY_AUTHORITY_FORMAT;
  if (
    authority.evidence?.format !== PHILCORE_V2_AUTHORITY_EVIDENCE_FORMAT
    || authority.evidence.authorityKind !== authority.authorityKind
    || authority.evidence.verificationFormat
      !== expectedEvidenceVerificationFormat
    || authority.evidence.signatureBytesPresentToEngine !== false
    || bytes32(authority.evidence.evidenceReferenceHash) === undefined
  ) {
    return rejected("AUTHORITY_EVIDENCE_MALFORMED", "authority");
  }
  const verifierDescriptor = request.authorityVerifier?.descriptor;
  if (
    verifierDescriptor?.acceptsGenericMessages !== false
    || verifierDescriptor.createsSignatures !== false
    || verifierDescriptor.requiresIntentBoundDigest !== true
    || typeof verifierDescriptor.verifierId !== "string"
    || !/^[a-z0-9][a-z0-9._-]{2,80}$/.test(verifierDescriptor.verifierId)
  ) {
    return rejected("AUTHORITY_VERIFIER_UNSAFE", "authority");
  }
  let verification;
  try {
    verification = await request.authorityVerifier.verify({
      authorityKind: authority.authorityKind,
      digest: authorityDigest,
      evidence: authority.evidence,
      chainId: state.chainId,
      account: state.account,
      validator: state.validator,
      validatorKeyIdBinding: state.validatorKeyIdBinding,
      validatorEpoch: state.validatorEpoch,
      recoveryEpoch: state.recoveryEpoch,
      recoveryConfigHash: state.recoveryConfigHash,
      ...(authority.factorBitmap === undefined
        ? {}
        : { factorBitmap: authority.factorBitmap })
    });
  } catch {
    return rejected("SIGNATURE_INVALID", "authority");
  }
  if (!verification.verified) {
    if (verification.failure === "AUTHORITY_EVIDENCE_MALFORMED") {
      return rejected("AUTHORITY_EVIDENCE_MALFORMED", "authority");
    }
    return rejected("SIGNATURE_INVALID", "authority");
  }
  if (
    verification.signatureProduced !== false
    || verification.verifierId !== verifierDescriptor.verifierId
  ) {
    return rejected("AUTHORITY_VERIFIER_UNSAFE", "authority");
  }

  return Object.freeze({
    accepted: true,
    status: "accepted",
    classification: "LOCAL_AUTHORIZATION_ACCEPTED_NON_EXECUTABLE",
    intentCoreHash: encoded.intentCoreHash,
    runtimeAuthorizationDigest,
    authorizedIntentHash,
    authorityDigest,
    keyedNonce,
    authorityKind: authority.authorityKind,
    verifierId: verification.verifierId,
    authorizedStateTransition:
      expectedStateTransition(encoded.header.actionType),
    executionPerformed: false,
    signatureProduced: false,
    userOperationCreated: false,
    publicMutationCount: 0
  });
}
