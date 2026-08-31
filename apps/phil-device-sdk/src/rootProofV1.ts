import {
  AbiCoder,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import { derivePhilIdentityRoot } from "./identity.ts";
import type { Hex } from "./hashes.ts";
import {
  derivePhilScopedOwnerCommitmentV1,
  normalizePhilUInt64,
  requirePhilNonZeroBytes32
} from "./secureIdentityV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_ROOT_PROOF_NULLIFIER_V1_LABEL =
  "PHIL_ROOT_PROOF_NULLIFIER_V1" as const;
export const PHIL_PROOF_DESCRIPTOR_V1_LABEL = "PHIL_PROOF_DESCRIPTOR_V1" as const;
export const PHIL_VERIFIER_BINDING_V1_LABEL = "PHIL_VERIFIER_BINDING_V1" as const;
export const PHIL_ROOT_PROOF_PUBLIC_INPUTS_U128X2_V1_LABEL =
  "PHIL_ROOT_PROOF_PUBLIC_INPUTS_U128X2_V1" as const;
export const PHIL_GARAGA_ULTRA_KECCAK_ZK_HONK_CALLDATA_V1_LABEL =
  "PHIL_GARAGA_ULTRA_KECCAK_ZK_HONK_CALLDATA_V1" as const;

export const PHIL_ROOT_PROOF_NULLIFIER_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_ROOT_PROOF_NULLIFIER_V1_LABEL)
) as Hex;
export const PHIL_PROOF_DESCRIPTOR_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_PROOF_DESCRIPTOR_V1_LABEL)
) as Hex;
export const PHIL_VERIFIER_BINDING_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_VERIFIER_BINDING_V1_LABEL)
) as Hex;
export const PHIL_ROOT_PROOF_PUBLIC_INPUTS_U128X2_V1_ID = keccak256(
  toUtf8Bytes(PHIL_ROOT_PROOF_PUBLIC_INPUTS_U128X2_V1_LABEL)
) as Hex;
export const PHIL_GARAGA_ULTRA_KECCAK_ZK_HONK_CALLDATA_V1_ID = keccak256(
  toUtf8Bytes(PHIL_GARAGA_ULTRA_KECCAK_ZK_HONK_CALLDATA_V1_LABEL)
) as Hex;

export interface PhilProofDescriptorV1 {
  readonly descriptorVersionHash: Hex;
  readonly proofSuiteId: Hex;
  readonly proofSystemVersionHash: Hex;
  readonly circuitOrProgramId: Hex;
  readonly publicInputSchemaId: Hex;
  readonly verificationKeyHash: Hex;
  readonly verifierCodeHash: Hex;
  readonly verifierBindingHash: Hex;
  readonly codecId: Hex;
}

export interface PhilRootProofPublicInputsV1 {
  readonly scopedOwnerCommitment: Hex;
  readonly scopeId: Hex;
  readonly scopeInstance: Hex;
  readonly scopeEpoch: string;
  readonly authorizationEnvelopeDigest: Hex;
  readonly rootProofNullifier: Hex;
  readonly proofDescriptorHash: Hex;
}

export interface PhilPackedRootProofPublicInputsV1 {
  readonly codec: "phil-root-proof-public-inputs-u128x2-v1";
  readonly felts: readonly string[];
}

export interface PhilExpectedRootProofBindingV1 {
  readonly scopedOwnerCommitment: BytesLike;
  readonly scopeId: BytesLike;
  readonly scopeInstance: BytesLike;
  readonly scopeEpoch: string | number | bigint;
  readonly authorizationEnvelopeDigest: BytesLike;
  readonly rootProofNullifier: BytesLike;
  readonly proofDescriptorHash: BytesLike;
}

export class PhilRootProofV1Error extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilRootProofV1Error";
    this.code = code;
  }
}

function normalizeBytes32(value: BytesLike, label: string): Hex {
  try {
    const normalized = hexlify(value).toLowerCase() as Hex;
    if (getBytes(normalized).length !== 32) throw new Error("length");
    return normalized;
  } catch {
    throw new PhilRootProofV1Error(
      "PHIL_ROOT_PROOF_INVALID_BYTES32",
      `${label} must be bytes32`
    );
  }
}

function normalizeDescriptor(input: PhilProofDescriptorV1): PhilProofDescriptorV1 {
  const descriptorVersionHash = normalizeBytes32(
    input.descriptorVersionHash,
    "descriptorVersionHash"
  );
  if (descriptorVersionHash !== PHIL_PROOF_DESCRIPTOR_V1_HASH) {
    throw new PhilRootProofV1Error(
      "PHIL_ROOT_PROOF_DESCRIPTOR_VERSION_UNSUPPORTED",
      "descriptorVersionHash is unsupported"
    );
  }
  const descriptor = {
    descriptorVersionHash,
    proofSuiteId: requirePhilNonZeroBytes32(input.proofSuiteId, "proofSuiteId"),
    proofSystemVersionHash: requirePhilNonZeroBytes32(
      input.proofSystemVersionHash,
      "proofSystemVersionHash"
    ),
    circuitOrProgramId: requirePhilNonZeroBytes32(
      input.circuitOrProgramId,
      "circuitOrProgramId"
    ),
    publicInputSchemaId: requirePhilNonZeroBytes32(
      input.publicInputSchemaId,
      "publicInputSchemaId"
    ),
    verificationKeyHash: requirePhilNonZeroBytes32(
      input.verificationKeyHash,
      "verificationKeyHash"
    ),
    verifierCodeHash: requirePhilNonZeroBytes32(
      input.verifierCodeHash,
      "verifierCodeHash"
    ),
    verifierBindingHash: requirePhilNonZeroBytes32(
      input.verifierBindingHash,
      "verifierBindingHash"
    ),
    codecId: requirePhilNonZeroBytes32(input.codecId, "codecId")
  } satisfies PhilProofDescriptorV1;
  const expectedVerifierBindingHash = derivePhilVerifierBindingHashV1(descriptor);
  if (descriptor.verifierBindingHash !== expectedVerifierBindingHash) {
    throw new PhilRootProofV1Error(
      "PHIL_ROOT_PROOF_VERIFIER_BINDING_MISMATCH",
      "verifierBindingHash does not bind the exact proof suite, circuit, key, verifier, schema, and codec"
    );
  }
  return Object.freeze(descriptor);
}

export function derivePhilVerifierBindingHashV1(input: Omit<
  PhilProofDescriptorV1,
  "descriptorVersionHash" | "verifierBindingHash"
>): Hex {
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        PHIL_VERIFIER_BINDING_V1_HASH,
        requirePhilNonZeroBytes32(input.proofSuiteId, "proofSuiteId"),
        requirePhilNonZeroBytes32(
          input.proofSystemVersionHash,
          "proofSystemVersionHash"
        ),
        requirePhilNonZeroBytes32(input.circuitOrProgramId, "circuitOrProgramId"),
        requirePhilNonZeroBytes32(input.publicInputSchemaId, "publicInputSchemaId"),
        requirePhilNonZeroBytes32(input.verificationKeyHash, "verificationKeyHash"),
        requirePhilNonZeroBytes32(input.verifierCodeHash, "verifierCodeHash"),
        requirePhilNonZeroBytes32(input.codecId, "codecId")
      ]
    )
  ) as Hex;
}

export function derivePhilProofDescriptorHashV1(input: PhilProofDescriptorV1): Hex {
  const descriptor = normalizeDescriptor(input);
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        PHIL_PROOF_DESCRIPTOR_V1_HASH,
        descriptor.proofSuiteId,
        descriptor.proofSystemVersionHash,
        descriptor.circuitOrProgramId,
        descriptor.publicInputSchemaId,
        descriptor.verificationKeyHash,
        descriptor.verifierCodeHash,
        descriptor.verifierBindingHash,
        descriptor.codecId
      ]
    )
  ) as Hex;
}

export function derivePhilRootProofNullifierV1(input: {
  readonly scopedOwnerCommitment: BytesLike;
  readonly authorizationEnvelopeDigest: BytesLike;
  readonly nullifierSeed: BytesLike;
}): Hex {
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [
        PHIL_ROOT_PROOF_NULLIFIER_V1_HASH,
        requirePhilNonZeroBytes32(
          input.scopedOwnerCommitment,
          "scopedOwnerCommitment"
        ),
        requirePhilNonZeroBytes32(
          input.authorizationEnvelopeDigest,
          "authorizationEnvelopeDigest"
        ),
        requirePhilNonZeroBytes32(input.nullifierSeed, "nullifierSeed")
      ]
    )
  ) as Hex;
}

export function createPhilRootProofPublicInputsV1(input: {
  readonly philSecret: BytesLike;
  readonly nullifierSeed: BytesLike;
  readonly scopeId: BytesLike;
  readonly scopeInstance: BytesLike;
  readonly scopeEpoch: string | number | bigint;
  readonly authorizationEnvelopeDigest: BytesLike;
  readonly proofDescriptorHash: BytesLike;
}): PhilRootProofPublicInputsV1 {
  const scopeId = requirePhilNonZeroBytes32(input.scopeId, "scopeId");
  const scopeInstance = requirePhilNonZeroBytes32(input.scopeInstance, "scopeInstance");
  const scopeEpoch = normalizePhilUInt64(input.scopeEpoch, "scopeEpoch");
  if (scopeEpoch === "0") {
    throw new PhilRootProofV1Error(
      "PHIL_ROOT_PROOF_SCOPE_EPOCH_ZERO",
      "scopeEpoch must be non-zero"
    );
  }
  const authorizationEnvelopeDigest = requirePhilNonZeroBytes32(
    input.authorizationEnvelopeDigest,
    "authorizationEnvelopeDigest"
  );
  const proofDescriptorHash = requirePhilNonZeroBytes32(
    input.proofDescriptorHash,
    "proofDescriptorHash"
  );
  const scopedOwnerCommitment = derivePhilScopedOwnerCommitmentV1({
    identityRoot: derivePhilIdentityRoot(input.philSecret),
    scopeId,
    scopeInstance,
    scopeEpoch
  });
  return Object.freeze({
    scopedOwnerCommitment,
    scopeId,
    scopeInstance,
    scopeEpoch,
    authorizationEnvelopeDigest,
    rootProofNullifier: derivePhilRootProofNullifierV1({
      scopedOwnerCommitment,
      authorizationEnvelopeDigest,
      nullifierSeed: input.nullifierSeed
    }),
    proofDescriptorHash
  });
}

function normalizePublicInputs(
  input: PhilExpectedRootProofBindingV1
): PhilRootProofPublicInputsV1 {
  const scopeEpoch = normalizePhilUInt64(input.scopeEpoch, "scopeEpoch");
  if (scopeEpoch === "0") {
    throw new PhilRootProofV1Error(
      "PHIL_ROOT_PROOF_SCOPE_EPOCH_ZERO",
      "scopeEpoch must be non-zero"
    );
  }
  return Object.freeze({
    scopedOwnerCommitment: requirePhilNonZeroBytes32(
      input.scopedOwnerCommitment,
      "scopedOwnerCommitment"
    ),
    scopeId: requirePhilNonZeroBytes32(input.scopeId, "scopeId"),
    scopeInstance: requirePhilNonZeroBytes32(input.scopeInstance, "scopeInstance"),
    scopeEpoch,
    authorizationEnvelopeDigest: requirePhilNonZeroBytes32(
      input.authorizationEnvelopeDigest,
      "authorizationEnvelopeDigest"
    ),
    rootProofNullifier: requirePhilNonZeroBytes32(
      input.rootProofNullifier,
      "rootProofNullifier"
    ),
    proofDescriptorHash: requirePhilNonZeroBytes32(
      input.proofDescriptorHash,
      "proofDescriptorHash"
    )
  });
}

export function assertPhilRootProofPublicInputsBindingV1(input: {
  readonly publicInputs: PhilRootProofPublicInputsV1;
  readonly expected: PhilExpectedRootProofBindingV1;
}): PhilRootProofPublicInputsV1 {
  const actual = normalizePublicInputs(input.publicInputs);
  const expected = normalizePublicInputs(input.expected);
  for (const field of [
    "scopedOwnerCommitment",
    "scopeId",
    "scopeInstance",
    "scopeEpoch",
    "authorizationEnvelopeDigest",
    "rootProofNullifier",
    "proofDescriptorHash"
  ] as const) {
    if (actual[field] !== expected[field]) {
      throw new PhilRootProofV1Error(
        "PHIL_ROOT_PROOF_PUBLIC_INPUT_BINDING_MISMATCH",
        `${field} does not match the accepted authorization and verifier binding`
      );
    }
  }
  return actual;
}

function bytes32ToU128Pair(value: BytesLike): readonly [string, string] {
  const normalized = normalizeBytes32(value, "packed bytes32");
  return Object.freeze([
    BigInt(`0x${normalized.slice(2, 34)}`).toString(10),
    BigInt(`0x${normalized.slice(34)}`).toString(10)
  ]);
}

export function packPhilRootProofPublicInputsV1(
  input: PhilRootProofPublicInputsV1
): PhilPackedRootProofPublicInputsV1 {
  const normalized = normalizePublicInputs(input);
  const values = [
    normalized.scopedOwnerCommitment,
    normalized.scopeId,
    normalized.scopeInstance
  ] as const;
  const tail = [
    normalized.authorizationEnvelopeDigest,
    normalized.rootProofNullifier,
    normalized.proofDescriptorHash
  ] as const;
  const felts = [
    ...values.flatMap((value) => bytes32ToU128Pair(value)),
    normalized.scopeEpoch,
    ...tail.flatMap((value) => bytes32ToU128Pair(value))
  ];
  if (felts.length !== 13) {
    throw new PhilRootProofV1Error(
      "PHIL_ROOT_PROOF_PUBLIC_INPUT_COUNT_INVALID",
      "packed public inputs must contain exactly 13 felts"
    );
  }
  return Object.freeze({
    codec: "phil-root-proof-public-inputs-u128x2-v1",
    felts: Object.freeze(felts)
  });
}
