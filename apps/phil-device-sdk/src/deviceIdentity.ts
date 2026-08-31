import {
  AbiCoder,
  Signature,
  SigningKey,
  computeAddress,
  getAddress,
  hexlify,
  keccak256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue,
  type BytesLike
} from "ethers";

import {
  createPhilIdentityPrivate,
  derivePhilIdentityPublic,
  PHIL_SECRET_FIELD_MASK,
  type PhilIdentityPrivate,
  type PhilIdentityPublic
} from "./identity.ts";
import type { Hex } from "./hashes.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_DEVICE_IDENTITY_VERSION = "phil-device-identity-v1" as const;
export const PHIL_DEVICE_IDENTITY_DOMAIN_LABEL = "PHIL_DEVICE_IDENTITY_V1" as const;
export const PHIL_DEVICE_IDENTITY_DOMAIN_HASH = keccak256(
  toUtf8Bytes(PHIL_DEVICE_IDENTITY_DOMAIN_LABEL)
) as Hex;
export const PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND =
  "local-dev-deterministic-device-identity-test-only-v1" as const;
export const PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND =
  "webauthn-passkey-device-identity-v1" as const;
export const PHIL_SECURE_ENCLAVE_DEVICE_IDENTITY_PROVIDER_KIND =
  "secure-enclave-platform-device-identity-scaffold-v1" as const;
export const PHIL_MOBILE_SECURE_HARDWARE_DEVICE_IDENTITY_PROVIDER_KIND =
  "mobile-secure-hardware-device-identity-scaffold-v1" as const;
export const PHIL_DEVICE_IDENTITY_UNSUPPORTED_PLATFORM_ERROR =
  "PHIL_DEVICE_IDENTITY_UNSUPPORTED_PLATFORM" as const;
export const PHIL_DEVICE_IDENTITY_PRIVATE_MATERIAL_EXPORT_ERROR =
  "PHIL_DEVICE_IDENTITY_PRIVATE_MATERIAL_NOT_EXPORTABLE" as const;
export const LOCAL_DEV_DEVICE_IDENTITY_PRODUCTION_SAFE = false as const;

export type PhilDeviceIdentityProviderKind =
  | typeof PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND
  | typeof PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND
  | typeof PHIL_SECURE_ENCLAVE_DEVICE_IDENTITY_PROVIDER_KIND
  | typeof PHIL_MOBILE_SECURE_HARDWARE_DEVICE_IDENTITY_PROVIDER_KIND;

export interface PhilAuthorizationDigestPayload {
  signatureRequestId?: Hex;
  signerPayloadHash?: Hex;
  signatureRequestHash?: Hex;
  signableDigest: Hex;
  digestEncoding: string;
  signatureTarget?: Record<string, unknown>;
}

export interface PhilDevicePublicMetadata {
  version: typeof PHIL_DEVICE_IDENTITY_VERSION;
  providerKind: PhilDeviceIdentityProviderKind;
  deviceIdentityId: Hex;
  deviceKeyId: Hex;
  publicKey?: Hex;
  publicKeyHash?: Hex;
  signerAddress?: string;
  credentialId?: string;
  credentialPublicKey?: Hex;
  authenticatorAttachment?: string;
  transports?: readonly string[];
  philIdentity: PhilIdentityPublic;
  productionSafe: boolean;
  privateMaterialExportable: false;
  hardwareBacked: boolean;
  createdAt?: string;
}

export interface PhilDeviceAuthorizationSignature {
  version: typeof PHIL_DEVICE_IDENTITY_VERSION;
  providerKind: PhilDeviceIdentityProviderKind;
  deviceIdentityId: Hex;
  deviceKeyId: Hex;
  signatureKind: string;
  signableDigest: Hex;
  digestEncoding: string;
  signature: Hex;
  signatureHash: Hex;
  recoveredAddress?: string;
  signedAt?: string;
}

export interface PhilDeviceIdentityProvider {
  readonly providerKind: PhilDeviceIdentityProviderKind;
  readonly productionSafe: boolean;
  readonly hardwareBacked: boolean;
  getPublicMetadata(): PhilDevicePublicMetadata;
  authorizeDigest(
    payload: PhilAuthorizationDigestPayload
  ): PhilDeviceAuthorizationSignature | Promise<PhilDeviceAuthorizationSignature>;
  exportPrivateMaterial(): never;
}

export interface LocalDevDeviceIdentityOptions {
  philIdentityPrivate?: PhilIdentityPrivate;
  philSecret?: BytesLike;
  devPrivateKey?: BytesLike;
  devKeyLabel?: string;
  keySource?: string;
  keySourcePath?: string | null;
  createdAt?: string;
}

export interface UnsupportedHardwareProviderOptions {
  philIdentityPublic?: PhilIdentityPublic;
  credentialId?: string;
  createdAt?: string;
}

export class PhilDeviceIdentityUnsupportedPlatformError extends Error {
  readonly code = PHIL_DEVICE_IDENTITY_UNSUPPORTED_PLATFORM_ERROR;
  readonly providerKind: PhilDeviceIdentityProviderKind;

  constructor(providerKind: PhilDeviceIdentityProviderKind, message?: string) {
    super(message ?? `${providerKind} is not available in this local scaffold`);
    this.name = "PhilDeviceIdentityUnsupportedPlatformError";
    this.providerKind = providerKind;
  }
}

export class PhilDeviceIdentityPrivateMaterialError extends Error {
  readonly code = PHIL_DEVICE_IDENTITY_PRIVATE_MATERIAL_EXPORT_ERROR;

  constructor() {
    super("Phil Device Identity v1 does not export phil_secret or private key material");
    this.name = "PhilDeviceIdentityPrivateMaterialError";
  }
}

function normalizeBytes(value: BytesLike, label: string): Hex {
  try {
    return hexlify(value).toLowerCase() as Hex;
  } catch {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
}

function normalizeHex32(value: BytesLike, label: string): Hex {
  const normalized = zeroPadValue(hexlify(value), 32).toLowerCase() as Hex;
  if (normalized.length !== 66) {
    throw new Error(`Invalid ${label}: ${normalized}`);
  }
  return normalized;
}

function normalizePrivateKey(value: BytesLike, label: string): Hex {
  const normalized = normalizeHex32(value, label);
  if (BigInt(normalized) === 0n) {
    throw new Error(`${label} must not be zero`);
  }
  try {
    new SigningKey(normalized);
  } catch {
    throw new Error(`Invalid ${label}: signing key rejected`);
  }
  return normalized;
}

function normalizeAddress(value: string, label: string): string {
  try {
    return getAddress(value);
  } catch {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
}

function deriveDefaultPhilIdentityPrivate(): PhilIdentityPrivate {
  const raw = BigInt(
    keccak256(
      abiCoder.encode(
        ["bytes32", "string"],
        [PHIL_DEVICE_IDENTITY_DOMAIN_HASH, "phil-local-dev-device-identity-phil-secret-v1"]
      )
    )
  );
  const reduced = raw & PHIL_SECRET_FIELD_MASK;

  return createPhilIdentityPrivate({
    philSecret: zeroPadValue(toBeHex(reduced), 32)
  });
}

export function deriveLocalDevDevicePrivateKey(devKeyLabel: string): Hex {
  return normalizePrivateKey(
    keccak256(
      abiCoder.encode(
        ["bytes32", "string"],
        [PHIL_DEVICE_IDENTITY_DOMAIN_HASH, devKeyLabel]
      )
    ),
    "deterministicLocalDevDevicePrivateKey"
  );
}

export function createLocalDevDeviceIdentityProvider(
  options: LocalDevDeviceIdentityOptions = {}
): PhilDeviceIdentityProvider {
  const privateIdentity = options.philIdentityPrivate
    ?? createPhilIdentityPrivate({
      philSecret: options.philSecret ?? deriveDefaultPhilIdentityPrivate().philSecret
    });
  const philIdentity = derivePhilIdentityPublic(privateIdentity);
  const privateKey = normalizePrivateKey(
    options.devPrivateKey
      ?? deriveLocalDevDevicePrivateKey(
        options.devKeyLabel ?? "phil-local-device-signing-dev-key-phase0-v1"
      ),
    "localDevDevicePrivateKey"
  );
  const signingKey = new SigningKey(privateKey);
  const publicKey = normalizeBytes(signingKey.publicKey, "publicKey");
  const publicKeyHash = keccak256(publicKey) as Hex;
  const signerAddress = normalizeAddress(computeAddress(signingKey.publicKey), "signerAddress");
  const deviceKeyId = keccak256(
    abiCoder.encode(
      ["bytes32", "address", "bytes32"],
      [PHIL_DEVICE_IDENTITY_DOMAIN_HASH, signerAddress, publicKeyHash]
    )
  ) as Hex;
  const deviceIdentityId = keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32"],
      [PHIL_DEVICE_IDENTITY_DOMAIN_HASH, philIdentity.ownerCommitment, deviceKeyId]
    )
  ) as Hex;

  const metadata: PhilDevicePublicMetadata = Object.freeze({
    version: PHIL_DEVICE_IDENTITY_VERSION,
    providerKind: PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
    deviceIdentityId,
    deviceKeyId,
    publicKey,
    publicKeyHash,
    signerAddress,
    philIdentity,
    productionSafe: LOCAL_DEV_DEVICE_IDENTITY_PRODUCTION_SAFE,
    privateMaterialExportable: false,
    hardwareBacked: false,
    createdAt: options.createdAt
  });

  return Object.freeze({
    providerKind: PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
    productionSafe: LOCAL_DEV_DEVICE_IDENTITY_PRODUCTION_SAFE,
    hardwareBacked: false,
    getPublicMetadata() {
      return metadata;
    },
    authorizeDigest(payload: PhilAuthorizationDigestPayload) {
      const signableDigest = normalizeHex32(payload.signableDigest, "signableDigest");
      const signature = Signature.from(signingKey.sign(signableDigest)).serialized.toLowerCase() as Hex;
      const recoveredAddress = normalizeAddress(
        computeAddress(SigningKey.recoverPublicKey(signableDigest, signature)),
        "recoveredAddress"
      );

      return {
        version: PHIL_DEVICE_IDENTITY_VERSION,
        providerKind: PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
        deviceIdentityId,
        deviceKeyId,
        signatureKind: "local-dev-secp256k1-userop-hash-signature-test-only-v1",
        signableDigest,
        digestEncoding: String(payload.digestEncoding || ""),
        signature,
        signatureHash: keccak256(signature) as Hex,
        recoveredAddress,
        signedAt: options.createdAt
      };
    },
    exportPrivateMaterial(): never {
      throw new PhilDeviceIdentityPrivateMaterialError();
    }
  });
}

function createUnsupportedHardwareProvider(
  providerKind: PhilDeviceIdentityProviderKind,
  options: UnsupportedHardwareProviderOptions = {}
): PhilDeviceIdentityProvider {
  const philIdentity = options.philIdentityPublic
    ?? derivePhilIdentityPublic(deriveDefaultPhilIdentityPrivate());
  const credentialId = options.credentialId ?? `${providerKind}:unregistered`;
  const deviceKeyId = keccak256(
    abiCoder.encode(
      ["bytes32", "string", "bytes32"],
      [PHIL_DEVICE_IDENTITY_DOMAIN_HASH, credentialId, philIdentity.ownerCommitment]
    )
  ) as Hex;
  const deviceIdentityId = keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32"],
      [PHIL_DEVICE_IDENTITY_DOMAIN_HASH, philIdentity.ownerCommitment, deviceKeyId]
    )
  ) as Hex;
  const metadata: PhilDevicePublicMetadata = Object.freeze({
    version: PHIL_DEVICE_IDENTITY_VERSION,
    providerKind,
    deviceIdentityId,
    deviceKeyId,
    credentialId,
    philIdentity,
    productionSafe: false,
    privateMaterialExportable: false,
    hardwareBacked: true,
    createdAt: options.createdAt
  });

  return Object.freeze({
    providerKind,
    productionSafe: false,
    hardwareBacked: true,
    getPublicMetadata() {
      return metadata;
    },
    authorizeDigest(): PhilDeviceAuthorizationSignature {
      throw new PhilDeviceIdentityUnsupportedPlatformError(
        providerKind,
        `${providerKind} requires OS/browser hardware integration and is scaffolded only`
      );
    },
    exportPrivateMaterial(): never {
      throw new PhilDeviceIdentityPrivateMaterialError();
    }
  });
}

export function createWebAuthnDeviceIdentityProvider(
  options: UnsupportedHardwareProviderOptions = {}
): PhilDeviceIdentityProvider {
  if (options.credentialId !== undefined) {
    return createUnsupportedHardwareProvider(
      PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
      options
    );
  }

  return createUnsupportedHardwareProvider(
    PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
    options
  );
}

export function createSecureEnclaveDeviceIdentityProvider(
  options: UnsupportedHardwareProviderOptions = {}
): PhilDeviceIdentityProvider {
  return createUnsupportedHardwareProvider(
    PHIL_SECURE_ENCLAVE_DEVICE_IDENTITY_PROVIDER_KIND,
    options
  );
}

export function createMobileSecureHardwareDeviceIdentityProvider(
  options: UnsupportedHardwareProviderOptions = {}
): PhilDeviceIdentityProvider {
  return createUnsupportedHardwareProvider(
    PHIL_MOBILE_SECURE_HARDWARE_DEVICE_IDENTITY_PROVIDER_KIND,
    options
  );
}
