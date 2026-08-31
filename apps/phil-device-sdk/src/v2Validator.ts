import {
  getAddress,
  isHexString,
  type BigNumberish
} from "ethers";

import type { Hex } from "./hashes.ts";
import { composePhilCoreV2Nonce } from "./v2Intent.ts";

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const PHILCORE_V2_AUTHORITY_EVIDENCE_FORMAT =
  "philcore-v2-authority-evidence-reference-v1" as const;

export const PHILCORE_V2_VALIDATOR_SIGNATURE_FORMAT =
  "secp256k1-rsv-65-low-s-v1" as const;

export const PHILCORE_V2_RECOVERY_AUTHORITY_FORMAT =
  "role-bound-factor-bundle-v1" as const;

export type PhilCoreV2AuthorityKind =
  | "validator_signature"
  | "recovery_threshold"
  | "combined_validator_recovery"
  | "recovery_config_rotation";

export type PhilCoreV2RecoveryState =
  | "normal"
  | "recovery_active"
  | "recovery_config_rotation_active";

export type PhilCoreV2ValidatorStatus = "active" | "revoked";

export interface PhilCoreV2AuthorityEvidenceReference {
  readonly format: typeof PHILCORE_V2_AUTHORITY_EVIDENCE_FORMAT;
  readonly authorityKind: PhilCoreV2AuthorityKind;
  readonly verificationFormat:
    | typeof PHILCORE_V2_VALIDATOR_SIGNATURE_FORMAT
    | typeof PHILCORE_V2_RECOVERY_AUTHORITY_FORMAT;
  readonly evidenceReferenceHash: Hex;
  readonly signatureBytesPresentToEngine: false;
  readonly fixtureOnly: boolean;
}

export interface PhilCoreV2ValidatorStateInput {
  readonly chainId: BigNumberish;
  readonly entryPoint: string;
  readonly account: string;
  readonly ownerCommitment: Hex;
  readonly validator: string;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorEpoch: BigNumberish;
  readonly validatorStatus?: PhilCoreV2ValidatorStatus;
  readonly recoveryEpoch: BigNumberish;
  readonly recoveryConfigHash: Hex;
  readonly recoveryState?: PhilCoreV2RecoveryState;
  readonly consumedAuthorizationDigests?: readonly Hex[];
  readonly consumedNonces?: readonly BigNumberish[];
}

export interface PhilCoreV2ValidatorState {
  readonly chainId: bigint;
  readonly entryPoint: string;
  readonly account: string;
  readonly ownerCommitment: Hex;
  readonly validator: string;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorEpoch: bigint;
  readonly validatorStatus: PhilCoreV2ValidatorStatus;
  readonly recoveryEpoch: bigint;
  readonly recoveryConfigHash: Hex;
  readonly recoveryState: PhilCoreV2RecoveryState;
  readonly consumedAuthorizationDigests: readonly Hex[];
  readonly consumedNonces: readonly bigint[];
}

export type PhilCoreV2AuthorityVerificationFailure =
  | "AUTHORITY_EVIDENCE_MALFORMED"
  | "AUTHORITY_KIND_UNSUPPORTED"
  | "AUTHORITY_DIGEST_NOT_ALLOWLISTED"
  | "AUTHORITY_BINDING_MISMATCH";

export type PhilCoreV2AuthorityVerificationResult =
  | Readonly<{
      verified: true;
      classification: "fixture_authority_verified" | "signature_verified";
      verifierId: string;
      signatureProduced: false;
    }>
  | Readonly<{
      verified: false;
      failure: PhilCoreV2AuthorityVerificationFailure;
      verifierId: string;
      signatureProduced: false;
    }>;

export interface PhilCoreV2AuthorityVerificationRequest {
  readonly authorityKind: PhilCoreV2AuthorityKind;
  readonly digest: Hex;
  readonly evidence: PhilCoreV2AuthorityEvidenceReference;
  readonly chainId: bigint;
  readonly account: string;
  readonly validator: string;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorEpoch: bigint;
  readonly recoveryEpoch: bigint;
  readonly recoveryConfigHash: Hex;
  readonly factorBitmap?: number;
}

export interface PhilCoreV2AuthorityVerifier {
  readonly descriptor: Readonly<{
    verifierId: string;
    fixtureOnly: boolean;
    acceptsGenericMessages: false;
    createsSignatures: false;
    requiresIntentBoundDigest: true;
  }>;
  verify(
    request: PhilCoreV2AuthorityVerificationRequest
  ): Promise<PhilCoreV2AuthorityVerificationResult>;
}

export interface PhilCoreV2FixtureAuthorityExpectation {
  readonly authorityKind: PhilCoreV2AuthorityKind;
  readonly digest: Hex;
  readonly evidenceReferenceHash: Hex;
  readonly chainId: BigNumberish;
  readonly account: string;
  readonly validator: string;
  readonly validatorKeyIdBinding: Hex;
  readonly validatorEpoch: BigNumberish;
  readonly recoveryEpoch: BigNumberish;
  readonly recoveryConfigHash: Hex;
  readonly factorBitmap?: number;
}

function uint(
  value: BigNumberish,
  bits: number,
  label: string,
  nonzero = false
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
  if (nonzero && parsed === 0n) throw new Error(`${label}_must_be_nonzero`);
  return parsed;
}

function bytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHexString(value, 32)) {
    throw new Error(`${label}_must_be_bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (normalized === ZERO_BYTES32) throw new Error(`${label}_must_be_nonzero`);
  return normalized;
}

function address(value: string, label: string): string {
  let normalized: string;
  try {
    normalized = getAddress(value);
  } catch {
    throw new Error(`${label}_must_be_address`);
  }
  if (normalized === ZERO_ADDRESS) throw new Error(`${label}_must_be_nonzero`);
  return normalized;
}

function authorityKind(value: unknown): PhilCoreV2AuthorityKind {
  if (
    value !== "validator_signature"
    && value !== "recovery_threshold"
    && value !== "combined_validator_recovery"
    && value !== "recovery_config_rotation"
  ) {
    throw new Error("authorityKind_unsupported");
  }
  return value;
}

function recoveryState(value: unknown): PhilCoreV2RecoveryState {
  if (
    value !== "normal"
    && value !== "recovery_active"
    && value !== "recovery_config_rotation_active"
  ) {
    throw new Error("recoveryState_unsupported");
  }
  return value;
}

function validatorStatus(value: unknown): PhilCoreV2ValidatorStatus {
  if (value !== "active" && value !== "revoked") {
    throw new Error("validatorStatus_unsupported");
  }
  return value;
}

function uniqueHex(values: readonly Hex[], label: string): readonly Hex[] {
  const normalized = values.map((value, index) =>
    bytes32(value, `${label}[${index}]`)
  );
  if (new Set(normalized).size !== normalized.length) {
    throw new Error(`${label}_must_be_unique`);
  }
  return Object.freeze(normalized);
}

function uniqueNonces(
  values: readonly BigNumberish[],
  label: string
): readonly bigint[] {
  const normalized = values.map((value, index) =>
    uint(value, 256, `${label}[${index}]`)
  );
  if (new Set(normalized.map(String)).size !== normalized.length) {
    throw new Error(`${label}_must_be_unique`);
  }
  return Object.freeze(normalized);
}

export function createPhilCoreV2ValidatorState(
  input: PhilCoreV2ValidatorStateInput
): PhilCoreV2ValidatorState {
  return Object.freeze({
    chainId: uint(input.chainId, 256, "chainId", true),
    entryPoint: address(input.entryPoint, "entryPoint"),
    account: address(input.account, "account"),
    ownerCommitment: bytes32(input.ownerCommitment, "ownerCommitment"),
    validator: address(input.validator, "validator"),
    validatorKeyIdBinding: bytes32(
      input.validatorKeyIdBinding,
      "validatorKeyIdBinding"
    ),
    validatorEpoch: uint(input.validatorEpoch, 64, "validatorEpoch", true),
    validatorStatus: validatorStatus(input.validatorStatus ?? "active"),
    recoveryEpoch: uint(input.recoveryEpoch, 64, "recoveryEpoch", true),
    recoveryConfigHash: bytes32(
      input.recoveryConfigHash,
      "recoveryConfigHash"
    ),
    recoveryState: recoveryState(input.recoveryState ?? "normal"),
    consumedAuthorizationDigests: uniqueHex(
      input.consumedAuthorizationDigests ?? [],
      "consumedAuthorizationDigests"
    ),
    consumedNonces: uniqueNonces(
      input.consumedNonces ?? [],
      "consumedNonces"
    )
  });
}

export function createPhilCoreV2AuthorityEvidenceReference(input: {
  readonly authorityKind: PhilCoreV2AuthorityKind;
  readonly evidenceReferenceHash: Hex;
  readonly fixtureOnly: boolean;
}): PhilCoreV2AuthorityEvidenceReference {
  const kind = authorityKind(input.authorityKind);
  return Object.freeze({
    format: PHILCORE_V2_AUTHORITY_EVIDENCE_FORMAT,
    authorityKind: kind,
    verificationFormat: kind === "validator_signature"
      ? PHILCORE_V2_VALIDATOR_SIGNATURE_FORMAT
      : PHILCORE_V2_RECOVERY_AUTHORITY_FORMAT,
    evidenceReferenceHash: bytes32(
      input.evidenceReferenceHash,
      "evidenceReferenceHash"
    ),
    signatureBytesPresentToEngine: false,
    fixtureOnly: input.fixtureOnly === true
  });
}

export function consumePhilCoreV2AuthorizationLocally(input: {
  readonly state: PhilCoreV2ValidatorState;
  readonly authorizationDigest: Hex;
  readonly nonceKey: BigNumberish;
  readonly nonceSequence: BigNumberish;
}): PhilCoreV2ValidatorState {
  const state = createPhilCoreV2ValidatorState(input.state);
  const digest = bytes32(input.authorizationDigest, "authorizationDigest");
  const nonce = composePhilCoreV2Nonce({
    key: input.nonceKey,
    sequence: input.nonceSequence
  });
  if (state.consumedAuthorizationDigests.includes(digest)) {
    throw new Error("authorization_replay");
  }
  if (state.consumedNonces.includes(nonce)) throw new Error("nonce_replay");
  return createPhilCoreV2ValidatorState({
    ...state,
    consumedAuthorizationDigests: [
      ...state.consumedAuthorizationDigests,
      digest
    ],
    consumedNonces: [...state.consumedNonces, nonce]
  });
}

export function beginPhilCoreV2Recovery(
  stateInput: PhilCoreV2ValidatorState
): PhilCoreV2ValidatorState {
  const state = createPhilCoreV2ValidatorState(stateInput);
  if (state.recoveryState !== "normal") {
    throw new Error("recovery_state_not_normal");
  }
  return createPhilCoreV2ValidatorState({
    ...state,
    recoveryState: "recovery_active"
  });
}

export function cancelPhilCoreV2Recovery(
  stateInput: PhilCoreV2ValidatorState
): PhilCoreV2ValidatorState {
  const state = createPhilCoreV2ValidatorState(stateInput);
  if (state.recoveryState !== "recovery_active") {
    throw new Error("recovery_not_active");
  }
  return createPhilCoreV2ValidatorState({
    ...state,
    recoveryState: "normal"
  });
}

export function beginPhilCoreV2RecoveryConfigRotation(
  stateInput: PhilCoreV2ValidatorState
): PhilCoreV2ValidatorState {
  const state = createPhilCoreV2ValidatorState(stateInput);
  if (state.recoveryState !== "normal") {
    throw new Error("recovery_state_not_normal");
  }
  return createPhilCoreV2ValidatorState({
    ...state,
    recoveryState: "recovery_config_rotation_active"
  });
}

export function cancelPhilCoreV2RecoveryConfigRotation(
  stateInput: PhilCoreV2ValidatorState
): PhilCoreV2ValidatorState {
  const state = createPhilCoreV2ValidatorState(stateInput);
  if (state.recoveryState !== "recovery_config_rotation_active") {
    throw new Error("recovery_config_rotation_not_active");
  }
  return createPhilCoreV2ValidatorState({
    ...state,
    recoveryState: "normal"
  });
}

export function rotatePhilCoreV2ValidatorState(input: {
  readonly state: PhilCoreV2ValidatorState;
  readonly proposedValidator: string;
  readonly proposedValidatorKeyIdBinding: Hex;
  readonly proposedValidatorEpoch: BigNumberish;
  readonly mode: "normal_rotation" | "recovery_completion";
  readonly proposedRecoveryEpoch?: BigNumberish;
}): PhilCoreV2ValidatorState {
  const state = createPhilCoreV2ValidatorState(input.state);
  const proposedValidatorEpoch = uint(
    input.proposedValidatorEpoch,
    64,
    "proposedValidatorEpoch",
    true
  );
  if (proposedValidatorEpoch !== state.validatorEpoch + 1n) {
    throw new Error("proposedValidatorEpoch_must_equal_current_plus_one");
  }
  if (input.mode === "normal_rotation") {
    if (state.recoveryState !== "normal") {
      throw new Error("validator_rotation_blocked_by_recovery_state");
    }
    if (state.validatorStatus !== "active") {
      throw new Error("validator_rotation_requires_active_validator");
    }
    return createPhilCoreV2ValidatorState({
      ...state,
      validator: input.proposedValidator,
      validatorKeyIdBinding: input.proposedValidatorKeyIdBinding,
      validatorEpoch: proposedValidatorEpoch,
      validatorStatus: "active"
    });
  }
  if (state.recoveryState !== "recovery_active") {
    throw new Error("recovery_completion_requires_active_recovery");
  }
  const proposedRecoveryEpoch = uint(
    input.proposedRecoveryEpoch ?? 0,
    64,
    "proposedRecoveryEpoch",
    true
  );
  if (proposedRecoveryEpoch !== state.recoveryEpoch + 1n) {
    throw new Error("proposedRecoveryEpoch_must_equal_current_plus_one");
  }
  return createPhilCoreV2ValidatorState({
    ...state,
    validator: input.proposedValidator,
    validatorKeyIdBinding: input.proposedValidatorKeyIdBinding,
    validatorEpoch: proposedValidatorEpoch,
    validatorStatus: "active",
    recoveryEpoch: proposedRecoveryEpoch,
    recoveryState: "normal"
  });
}

export function revokePhilCoreV2ValidatorLocally(
  stateInput: PhilCoreV2ValidatorState
): PhilCoreV2ValidatorState {
  const state = createPhilCoreV2ValidatorState(stateInput);
  if (state.validatorStatus !== "active") {
    throw new Error("validator_already_revoked");
  }
  return createPhilCoreV2ValidatorState({
    ...state,
    validatorStatus: "revoked"
  });
}

function normalizeFixtureExpectation(
  input: PhilCoreV2FixtureAuthorityExpectation
): Readonly<{
  authorityKind: PhilCoreV2AuthorityKind;
  digest: Hex;
  evidenceReferenceHash: Hex;
  chainId: bigint;
  account: string;
  validator: string;
  validatorKeyIdBinding: Hex;
  validatorEpoch: bigint;
  recoveryEpoch: bigint;
  recoveryConfigHash: Hex;
  factorBitmap?: number;
}> {
  const normalizedFactorBitmap = input.factorBitmap;
  if (
    normalizedFactorBitmap !== undefined
    && !Number.isInteger(normalizedFactorBitmap)
  ) {
    throw new Error("factorBitmap_must_be_integer");
  }
  return Object.freeze({
    authorityKind: authorityKind(input.authorityKind),
    digest: bytes32(input.digest, "digest"),
    evidenceReferenceHash: bytes32(
      input.evidenceReferenceHash,
      "evidenceReferenceHash"
    ),
    chainId: uint(input.chainId, 256, "chainId", true),
    account: address(input.account, "account"),
    validator: address(input.validator, "validator"),
    validatorKeyIdBinding: bytes32(
      input.validatorKeyIdBinding,
      "validatorKeyIdBinding"
    ),
    validatorEpoch: uint(input.validatorEpoch, 64, "validatorEpoch", true),
    recoveryEpoch: uint(input.recoveryEpoch, 64, "recoveryEpoch", true),
    recoveryConfigHash: bytes32(
      input.recoveryConfigHash,
      "recoveryConfigHash"
    ),
    ...(normalizedFactorBitmap === undefined
      ? {}
      : { factorBitmap: normalizedFactorBitmap })
  });
}

export function createPhilCoreV2FixtureAuthorityVerifier(input: {
  readonly verifierId: string;
  readonly expectations: readonly PhilCoreV2FixtureAuthorityExpectation[];
}): PhilCoreV2AuthorityVerifier {
  if (!/^[a-z0-9][a-z0-9._-]{2,80}$/.test(input.verifierId)) {
    throw new Error("verifierId_invalid");
  }
  const expectations = input.expectations.map(normalizeFixtureExpectation);
  return Object.freeze({
    descriptor: Object.freeze({
      verifierId: input.verifierId,
      fixtureOnly: true,
      acceptsGenericMessages: false,
      createsSignatures: false,
      requiresIntentBoundDigest: true
    }),
    async verify(
      request: PhilCoreV2AuthorityVerificationRequest
    ): Promise<PhilCoreV2AuthorityVerificationResult> {
      let evidence: PhilCoreV2AuthorityEvidenceReference;
      try {
        const expectedVerificationFormat =
          request.evidence.authorityKind === "validator_signature"
            ? PHILCORE_V2_VALIDATOR_SIGNATURE_FORMAT
            : PHILCORE_V2_RECOVERY_AUTHORITY_FORMAT;
        if (
          request.evidence.format !== PHILCORE_V2_AUTHORITY_EVIDENCE_FORMAT
          || request.evidence.verificationFormat !== expectedVerificationFormat
          || request.evidence.signatureBytesPresentToEngine !== false
          || request.evidence.fixtureOnly !== true
        ) {
          throw new Error("fixture_evidence_boundary_invalid");
        }
        evidence = createPhilCoreV2AuthorityEvidenceReference(
          request.evidence
        );
      } catch {
        return Object.freeze({
          verified: false,
          failure: "AUTHORITY_EVIDENCE_MALFORMED",
          verifierId: input.verifierId,
          signatureProduced: false
        });
      }
      if (evidence.authorityKind !== request.authorityKind) {
        return Object.freeze({
          verified: false,
          failure: "AUTHORITY_KIND_UNSUPPORTED",
          verifierId: input.verifierId,
          signatureProduced: false
        });
      }
      const digest = bytes32(request.digest, "digest");
      const match = expectations.find((expectation) =>
        expectation.authorityKind === request.authorityKind
        && expectation.digest === digest
        && expectation.evidenceReferenceHash
          === evidence.evidenceReferenceHash
      );
      if (!match) {
        return Object.freeze({
          verified: false,
          failure: "AUTHORITY_DIGEST_NOT_ALLOWLISTED",
          verifierId: input.verifierId,
          signatureProduced: false
        });
      }
      const bindingMatches =
        match.chainId === request.chainId
        && match.account === getAddress(request.account)
        && match.validator === getAddress(request.validator)
        && match.validatorKeyIdBinding
          === request.validatorKeyIdBinding.toLowerCase()
        && match.validatorEpoch === request.validatorEpoch
        && match.recoveryEpoch === request.recoveryEpoch
        && match.recoveryConfigHash
          === request.recoveryConfigHash.toLowerCase()
        && match.factorBitmap === request.factorBitmap;
      if (!bindingMatches) {
        return Object.freeze({
          verified: false,
          failure: "AUTHORITY_BINDING_MISMATCH",
          verifierId: input.verifierId,
          signatureProduced: false
        });
      }
      return Object.freeze({
        verified: true,
        classification: "fixture_authority_verified",
        verifierId: input.verifierId,
        signatureProduced: false
      });
    }
  });
}
