import {
  AbiCoder,
  keccak256,
  toUtf8Bytes,
  type BytesLike
} from "ethers";

import type { Hex } from "./hashes.ts";
import {
  normalizePhilUInt64,
  requirePhilNonZeroBytes32
} from "./secureIdentityV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_STEP4_REFERENCE_RECEIPT_V1_LABEL =
  "PHIL_STEP4_REFERENCE_RECEIPT_V1" as const;
export const PHIL_STEP4_REFERENCE_RECEIPT_V1_HASH = keccak256(
  toUtf8Bytes(PHIL_STEP4_REFERENCE_RECEIPT_V1_LABEL)
) as Hex;

export interface PhilStep4ReferenceReceiptV1 {
  readonly authorizationEnvelopeDigest: Hex;
  readonly rootProofNullifier: Hex;
  readonly deviceApprovalDigest: Hex;
  readonly accountNonce: string;
  readonly receiptSequence: string;
  readonly receiptDigest: Hex;
  readonly productionAuthority: false;
  readonly networkActivity: false;
}

function canonicalPositiveUInt64(
  value: string | number | bigint,
  label: string
): string {
  const normalized = normalizePhilUInt64(value, label);
  if (normalized === "0") throw new Error(`${label}_must_be_non_zero`);
  return normalized;
}

export function derivePhilStep4ReferenceReceiptDigestV1(input: {
  readonly authorizationEnvelopeDigest: BytesLike;
  readonly rootProofNullifier: BytesLike;
  readonly deviceApprovalDigest: BytesLike;
  readonly accountNonce: string | number | bigint;
  readonly receiptSequence: string | number | bigint;
}): Hex {
  const accountNonce = normalizePhilUInt64(input.accountNonce, "accountNonce");
  const receiptSequence = canonicalPositiveUInt64(
    input.receiptSequence,
    "receiptSequence"
  );
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "uint64", "uint64"],
      [
        PHIL_STEP4_REFERENCE_RECEIPT_V1_HASH,
        requirePhilNonZeroBytes32(
          input.authorizationEnvelopeDigest,
          "authorizationEnvelopeDigest"
        ),
        requirePhilNonZeroBytes32(
          input.rootProofNullifier,
          "rootProofNullifier"
        ),
        requirePhilNonZeroBytes32(
          input.deviceApprovalDigest,
          "deviceApprovalDigest"
        ),
        BigInt(accountNonce),
        BigInt(receiptSequence)
      ]
    )
  ) as Hex;
}

export function createPhilStep4ReferenceReceiptV1(input: {
  readonly authorizationEnvelopeDigest: BytesLike;
  readonly rootProofNullifier: BytesLike;
  readonly deviceApprovalDigest: BytesLike;
  readonly accountNonce: string | number | bigint;
  readonly receiptSequence: string | number | bigint;
}): PhilStep4ReferenceReceiptV1 {
  const authorizationEnvelopeDigest = requirePhilNonZeroBytes32(
    input.authorizationEnvelopeDigest,
    "authorizationEnvelopeDigest"
  );
  const rootProofNullifier = requirePhilNonZeroBytes32(
    input.rootProofNullifier,
    "rootProofNullifier"
  );
  const deviceApprovalDigest = requirePhilNonZeroBytes32(
    input.deviceApprovalDigest,
    "deviceApprovalDigest"
  );
  const accountNonce = normalizePhilUInt64(input.accountNonce, "accountNonce");
  const receiptSequence = canonicalPositiveUInt64(
    input.receiptSequence,
    "receiptSequence"
  );
  return Object.freeze({
    authorizationEnvelopeDigest,
    rootProofNullifier,
    deviceApprovalDigest,
    accountNonce,
    receiptSequence,
    receiptDigest: derivePhilStep4ReferenceReceiptDigestV1({
      authorizationEnvelopeDigest,
      rootProofNullifier,
      deviceApprovalDigest,
      accountNonce,
      receiptSequence
    }),
    productionAuthority: false as const,
    networkActivity: false as const
  });
}
