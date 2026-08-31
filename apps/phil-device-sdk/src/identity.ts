import {
  getBytes,
  hexlify,
  randomBytes,
  toBeHex,
  zeroPadValue,
  type BytesLike
} from "ethers";

import {
  canonicalOwnerCommitmentFromIdentityRoot,
  identityRootFromPhilSecret,
  type Hex
} from "./hashes.ts";

export const PHIL_SECRET_FORMAT = "PHIL_SECRET_V1" as const;
export const PHIL_SECRET_MAX_BITS = 251n;
export const PHIL_SECRET_FIELD_MASK = (1n << PHIL_SECRET_MAX_BITS) - 1n;

export type PhilSecret = Hex;

export interface PhilIdentityPublic {
  identityRoot: Hex;
  ownerCommitment: Hex;
}

export interface PhilIdentityPrivate {
  philSecret: PhilSecret;
  identityRoot: Hex;
  ownerCommitment: Hex;
}

/**
 * @deprecated Use PhilIdentityPublic.
 */
export type PhilIdentityPublicRecord = PhilIdentityPublic;

/**
 * @deprecated Use PhilIdentityPrivate.
 */
export type PhilIdentityMaterial = PhilIdentityPrivate;

function bytesToBigInt(value: BytesLike): bigint {
  return BigInt(hexlify(value));
}

function normalizeBytes32(value: BytesLike): Hex {
  return zeroPadValue(hexlify(value), 32) as Hex;
}

export function philSecretToBigInt(philSecret: BytesLike): bigint {
  const normalized = normalizePhilSecret(philSecret);
  return bytesToBigInt(normalized);
}

export function isValidPhilSecret(philSecret: BytesLike): boolean {
  try {
    void normalizePhilSecret(philSecret);
    return true;
  } catch {
    return false;
  }
}

export function normalizePhilSecret(philSecret: BytesLike): PhilSecret {
  const normalized = zeroPadValue(hexlify(philSecret), 32) as PhilSecret;
  const numeric = bytesToBigInt(normalized);

  if (numeric === 0n) {
    throw new Error("phil_secret must be non-zero");
  }
  if (numeric > PHIL_SECRET_FIELD_MASK) {
    throw new Error("phil_secret must fit within the 251-bit Stark-friendly private root range");
  }

  return normalized;
}

export function generatePhilSecret(): PhilSecret {
  for (;;) {
    const entropy = getBytes(randomBytes(32));
    const numeric = bytesToBigInt(entropy) & PHIL_SECRET_FIELD_MASK;
    if (numeric === 0n) {
      continue;
    }

    return zeroPadValue(toBeHex(numeric), 32) as PhilSecret;
  }
}

export function derivePhilIdentityRoot(philSecret: BytesLike): Hex {
  return identityRootFromPhilSecret(normalizePhilSecret(philSecret));
}

export function deriveOwnerCommitmentFromPhilSecret(philSecret: BytesLike): Hex {
  return canonicalOwnerCommitmentFromIdentityRoot(derivePhilIdentityRoot(philSecret));
}

export function createPhilIdentityPrivate(
  input: { philSecret?: BytesLike } = {}
): PhilIdentityPrivate {
  const philSecret = input.philSecret === undefined
    ? generatePhilSecret()
    : normalizePhilSecret(input.philSecret);

  const identityRoot = derivePhilIdentityRoot(philSecret);
  const ownerCommitment = deriveOwnerCommitmentFromPhilSecret(philSecret);

  return {
    philSecret,
    identityRoot,
    ownerCommitment
  };
}

export function derivePhilIdentityPublic(
  privateIdentity: PhilIdentityPrivate
): PhilIdentityPublic {
  const philSecret = normalizePhilSecret(privateIdentity.philSecret);
  const expectedIdentityRoot = derivePhilIdentityRoot(philSecret);
  const expectedOwnerCommitment = deriveOwnerCommitmentFromPhilSecret(philSecret);
  const providedIdentityRoot = normalizeBytes32(privateIdentity.identityRoot);
  const providedOwnerCommitment = normalizeBytes32(privateIdentity.ownerCommitment);

  if (providedIdentityRoot !== expectedIdentityRoot) {
    throw new Error("PhilIdentityPrivate.identityRoot does not match philSecret");
  }
  if (providedOwnerCommitment !== expectedOwnerCommitment) {
    throw new Error("PhilIdentityPrivate.ownerCommitment does not match philSecret");
  }

  return {
    identityRoot: expectedIdentityRoot,
    ownerCommitment: expectedOwnerCommitment
  };
}

/**
 * @deprecated Returns only the public identity. Use createPhilIdentityPrivate()
 * when explicit secret access is required.
 */
export function buildPhilIdentity(input: { philSecret?: BytesLike } = {}): PhilIdentityPublic {
  return derivePhilIdentityPublic(createPhilIdentityPrivate(input));
}

/**
 * @deprecated Use derivePhilIdentityPublic(createPhilIdentityPrivate(...)).
 */
export function buildPhilIdentityPublicRecord(
  input: { philSecret: BytesLike }
): PhilIdentityPublic {
  return derivePhilIdentityPublic(createPhilIdentityPrivate(input));
}
