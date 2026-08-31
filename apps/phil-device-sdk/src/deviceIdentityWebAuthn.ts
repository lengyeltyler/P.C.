import {
  AbiCoder,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes,
  zeroPadValue,
  type BytesLike
} from "ethers";

import {
  derivePhilIdentityPublic,
  type PhilIdentityPrivate,
  type PhilIdentityPublic
} from "./identity.ts";
import {
  PHIL_DEVICE_IDENTITY_PRIVATE_MATERIAL_EXPORT_ERROR,
  PHIL_DEVICE_IDENTITY_UNSUPPORTED_PLATFORM_ERROR,
  PHIL_DEVICE_IDENTITY_VERSION,
  PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
  PhilDeviceIdentityPrivateMaterialError,
  PhilDeviceIdentityUnsupportedPlatformError,
  type PhilAuthorizationDigestPayload,
  type PhilDeviceAuthorizationSignature,
  type PhilDeviceIdentityProvider,
  type PhilDevicePublicMetadata
} from "./deviceIdentity.ts";
import type { Hex } from "./hashes.ts";

export { PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND } from "./deviceIdentity.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const WEBAUTHN_DEFAULT_TIMEOUT_MS = 60_000;

export type WebAuthnUserVerification = "required" | "preferred" | "discouraged";
export type WebAuthnResidentKeyRequirement =
  | "discouraged"
  | "preferred"
  | "required";
export type WebAuthnAuthenticatorAttachment = "platform" | "cross-platform";

export interface PhilWebAuthnRelyingPartyConfig {
  rpId: string;
  rpName: string;
  origin: string;
  userDisplayName: string;
  userName: string;
  userId: BytesLike | string;
  userVerification?: WebAuthnUserVerification;
  residentKey?: WebAuthnResidentKeyRequirement;
  authenticatorAttachment?: WebAuthnAuthenticatorAttachment;
  timeout?: number;
  label?: string;
}

export interface PhilWebAuthnCredentialMetadata {
  credentialId: string;
  credentialIdHash: Hex;
  rawId: string;
  publicKey?: Hex;
  publicKeyAlgorithm?: number;
  signCount?: number;
  transports?: readonly string[];
  authenticatorAttachment?: string;
  createdAt?: string;
  label?: string;
}

export interface PhilWebAuthnPublicMetadata extends PhilDevicePublicMetadata {
  rpId: string;
  rpName: string;
  origin: string;
  credentialIdHash: Hex;
  userVerification: WebAuthnUserVerification;
  residentKey: WebAuthnResidentKeyRequirement;
  label?: string;
}

export interface PhilWebAuthnAssertion {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string | null;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string | null;
  };
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

export interface PhilWebAuthnAuthorizationSignature
  extends PhilDeviceAuthorizationSignature {
  assertion: PhilWebAuthnAssertion;
  verification: PhilWebAuthnVerificationResult;
}

export interface PhilWebAuthnProvider extends PhilDeviceIdentityProvider {
  getPublicMetadata(): PhilWebAuthnPublicMetadata;
  authorizeDigest(
    payload: PhilAuthorizationDigestPayload
  ): Promise<PhilWebAuthnAuthorizationSignature>;
  buildAssertionOptions(
    payload: PhilAuthorizationDigestPayload
  ): PublicKeyCredentialRequestOptions;
}

export interface PhilWebAuthnRegistrationResult {
  provider: PhilWebAuthnProvider;
  metadata: PhilWebAuthnPublicMetadata;
  credential: {
    id: string;
    rawId: string;
    type: string;
    authenticatorAttachment?: string | null;
    response: {
      attestationObject: string;
      clientDataJSON: string;
      publicKey?: string | null;
      publicKeyAlgorithm?: number;
      transports?: readonly string[];
    };
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
  };
  creationOptions: PublicKeyCredentialCreationOptions;
  verification: PhilWebAuthnRegistrationVerificationResult;
}

export interface PhilWebAuthnProviderOptions {
  rp: PhilWebAuthnRelyingPartyConfig;
  philIdentityPublic?: PhilIdentityPublic;
  philIdentityPrivate?: PhilIdentityPrivate;
  credential?: PhilWebAuthnCredentialMetadata;
  navigatorLike?: Pick<Navigator, "credentials"> & {
    PublicKeyCredential?: typeof PublicKeyCredential;
  };
  verifier?: PhilWebAuthnVerifier;
  now?: () => string;
}

export interface PhilWebAuthnRegistrationOptions extends PhilWebAuthnProviderOptions {
  attestation?: AttestationConveyancePreference;
  attestationPolicy?: PhilWebAuthnAttestationPolicyConfig;
  expectedAlgorithms?: readonly number[];
  allowCrossOriginRegistration?: boolean;
}

export type PhilWebAuthnAttestationPolicyMode = "none" | "permissive" | "direct";

export interface PhilWebAuthnAttestationPolicyConfig {
  mode: PhilWebAuthnAttestationPolicyMode;
  allowCrossOrigin?: boolean;
}

export interface PhilWebAuthnRegistrationCredential {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment?: string | null;
  response: {
    attestationObject: string;
    clientDataJSON: string;
    publicKey?: string | null;
    publicKeyAlgorithm?: number;
    transports?: readonly string[];
  };
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
}

export interface PhilWebAuthnRegistrationVerificationInput {
  registration: PhilWebAuthnRegistrationCredential;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRpId: string;
  expectedUserVerification: WebAuthnUserVerification;
  expectedAlgorithms?: readonly number[];
  attestationPolicy?: PhilWebAuthnAttestationPolicyConfig;
  allowCrossOrigin?: boolean;
}

export interface PhilWebAuthnRegistrationVerificationResult {
  verified: boolean;
  verifierKind: string;
  productionVerified: boolean;
  reason: string;
  credentialId: string;
  credentialPublicKey?: Hex;
  algorithm?: number;
  signCount: number;
  originMatched: boolean;
  challengeMatched: boolean;
  rpIdHashMatched: boolean;
  userPresent: boolean;
  userVerified: boolean;
  backupEligible: boolean;
  backupState: boolean;
  attestedCredentialDataIncluded: boolean;
  attestationType: string;
  attestationPolicyMode: PhilWebAuthnAttestationPolicyMode;
  transports: readonly string[];
  warnings: readonly string[];
  errors: readonly string[];
}

export interface PhilWebAuthnVerificationInput {
  assertion: PhilWebAuthnAssertion;
  credential: PhilWebAuthnCredentialMetadata;
  expectedChallenge: string;
  expectedOrigin: string;
  expectedRpId: string;
  expectedUserVerification: WebAuthnUserVerification;
  storedSignCount: number;
}

export type PhilWebAuthnCounterStatus =
  | "advanced"
  | "unsupported"
  | "unchanged-zero"
  | "rollback"
  | "clone-suspected";

export interface PhilWebAuthnVerificationResult {
  verified: boolean;
  verifierKind: string;
  productionVerified: boolean;
  reason: string;
  credentialId: string;
  newSignCount: number;
  userPresent: boolean;
  userVerified: boolean;
  rpIdHashMatched: boolean;
  challengeMatched: boolean;
  originMatched: boolean;
  signatureVerified: boolean;
  counterStatus: PhilWebAuthnCounterStatus;
  warnings: readonly string[];
  errors: readonly string[];
}

export interface PhilWebAuthnVerifier {
  verifyAssertion(
    input: PhilWebAuthnVerificationInput
  ): PhilWebAuthnVerificationResult | Promise<PhilWebAuthnVerificationResult>;
}

export const PHIL_WEBAUTHN_LOCAL_STUB_VERIFIER_KIND =
  "webauthn-local-structure-only-verifier-v1" as const;

export const philWebAuthnLocalStubVerifier: PhilWebAuthnVerifier = Object.freeze({
  verifyAssertion(input: PhilWebAuthnVerificationInput): PhilWebAuthnVerificationResult {
    const parsed = parseWebAuthnClientDataJSON(input.assertion.response.clientDataJSON);
    const credentialId = input.assertion.rawId;
    if (parsed.challenge !== input.expectedChallenge) {
      return {
        verified: false,
        verifierKind: PHIL_WEBAUTHN_LOCAL_STUB_VERIFIER_KIND,
        productionVerified: false,
        reason: "clientDataJSON challenge mismatch",
        credentialId,
        newSignCount: input.storedSignCount,
        userPresent: false,
        userVerified: false,
        rpIdHashMatched: false,
        challengeMatched: false,
        originMatched: parsed.origin === input.expectedOrigin,
        signatureVerified: false,
        counterStatus: "unsupported",
        warnings: [],
        errors: ["clientDataJSON challenge mismatch"]
      };
    }
    if (parsed.origin !== input.expectedOrigin) {
      return {
        verified: false,
        verifierKind: PHIL_WEBAUTHN_LOCAL_STUB_VERIFIER_KIND,
        productionVerified: false,
        reason: "clientDataJSON origin mismatch",
        credentialId,
        newSignCount: input.storedSignCount,
        userPresent: false,
        userVerified: false,
        rpIdHashMatched: false,
        challengeMatched: true,
        originMatched: false,
        signatureVerified: false,
        counterStatus: "unsupported",
        warnings: [],
        errors: ["clientDataJSON origin mismatch"]
      };
    }

    return {
      verified: true,
      verifierKind: PHIL_WEBAUTHN_LOCAL_STUB_VERIFIER_KIND,
      productionVerified: false,
      reason:
        "structure-only local verifier; signature, rpIdHash, counter, and UV flags are not production-verified",
      credentialId,
      newSignCount: input.storedSignCount,
      userPresent: true,
      userVerified: input.expectedUserVerification !== "required",
      rpIdHashMatched: false,
      challengeMatched: true,
      originMatched: true,
      signatureVerified: false,
      counterStatus: "unsupported",
      warnings: [
        "structure-only local verifier does not production-verify signature, rpIdHash, counter, or UV flags"
      ],
      errors: []
    };
  }
});

function normalizeHex32(value: BytesLike, label: string): Hex {
  const normalized = zeroPadValue(hexlify(value), 32).toLowerCase() as Hex;
  if (normalized.length !== 66) {
    throw new Error(`Invalid ${label}: ${normalized}`);
  }
  return normalized;
}

function getGlobalNavigator(): (Navigator & { PublicKeyCredential?: typeof PublicKeyCredential }) | undefined {
  if (typeof globalThis.navigator === "undefined") {
    return undefined;
  }
  return globalThis.navigator as Navigator & {
    PublicKeyCredential?: typeof PublicKeyCredential;
  };
}

function getCredentials(options: PhilWebAuthnProviderOptions): CredentialsContainer {
  const nav = options.navigatorLike ?? getGlobalNavigator();
  if (!nav || !nav.credentials) {
    throw new PhilDeviceIdentityUnsupportedPlatformError(
      PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
      "WebAuthn requires browser navigator.credentials. Run this provider in a WebAuthn-capable browser or inject a mock for tests."
    );
  }
  return nav.credentials;
}

export function isWebAuthnPlatformSupported(
  navigatorLike?: Pick<Navigator, "credentials">
): boolean {
  const nav = navigatorLike ?? getGlobalNavigator();
  return Boolean(nav && nav.credentials && typeof nav.credentials.create === "function" && typeof nav.credentials.get === "function");
}

export function arrayBufferToBase64Url(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  const base64 = typeof btoa === "function"
    ? btoa(binary)
    : Buffer.from(bytes).toString("base64");

  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToArrayBuffer(value: string): ArrayBuffer {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = typeof atob === "function"
    ? atob(padded)
    : Buffer.from(padded, "base64").toString("binary");
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes.buffer;
}

function bytesToOwnedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function bufferSourceToUint8Array(value: BufferSource): Uint8Array {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}

export function bytesLikeToArrayBuffer(value: BytesLike | string): ArrayBuffer {
  if (typeof value === "string" && !value.startsWith("0x")) {
    return bytesToOwnedArrayBuffer(new TextEncoder().encode(value));
  }
  return bytesToOwnedArrayBuffer(getBytes(value as BytesLike));
}

export function authorizationDigestToWebAuthnChallenge(signableDigest: BytesLike): ArrayBuffer {
  return bytesToOwnedArrayBuffer(getBytes(normalizeHex32(signableDigest, "signableDigest")));
}

export function authorizationDigestToWebAuthnChallengeBase64Url(
  signableDigest: BytesLike
): string {
  return arrayBufferToBase64Url(
    authorizationDigestToWebAuthnChallenge(signableDigest)
  );
}

export function credentialIdToBase64Url(rawId: ArrayBuffer): string {
  return arrayBufferToBase64Url(rawId);
}

export function credentialIdFromBase64Url(credentialId: string): ArrayBuffer {
  return base64UrlToArrayBuffer(credentialId);
}

export function serializeWebAuthnCredential(
  credential: PublicKeyCredential
): PhilWebAuthnRegistrationResult["credential"] {
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports = typeof response.getTransports === "function"
    ? response.getTransports()
    : undefined;
  const publicKey = typeof response.getPublicKey === "function"
    ? response.getPublicKey()
    : undefined;

  return {
    id: credential.id,
    rawId: credentialIdToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      attestationObject: arrayBufferToBase64Url(response.attestationObject),
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      publicKey: publicKey ? arrayBufferToBase64Url(publicKey) : null,
      publicKeyAlgorithm: typeof response.getPublicKeyAlgorithm === "function"
        ? response.getPublicKeyAlgorithm()
        : undefined,
      transports
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}

export function serializeWebAuthnAssertion(
  credential: PublicKeyCredential
): PhilWebAuthnAssertion {
  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: credentialIdToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      authenticatorData: arrayBufferToBase64Url(response.authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      signature: arrayBufferToBase64Url(response.signature),
      userHandle: response.userHandle
        ? arrayBufferToBase64Url(response.userHandle)
        : null
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}

export function parseWebAuthnClientDataJSON(clientDataJSON: string): {
  type: string;
  challenge: string;
  origin: string;
  crossOrigin?: boolean;
} {
  const bytes = new Uint8Array(base64UrlToArrayBuffer(clientDataJSON));
  return JSON.parse(new TextDecoder().decode(bytes));
}

function base64UrlToBytes(value: string): Uint8Array {
  return new Uint8Array(base64UrlToArrayBuffer(value));
}

async function sha256Bytes(value: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    bytesToOwnedArrayBuffer(bytes)
  );
  return new Uint8Array(digest);
}

function concatBytes(...chunks: readonly Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < a.byteLength; index += 1) {
    diff |= a[index] ^ b[index];
  }
  return diff === 0;
}

export interface ParsedWebAuthnAuthenticatorData {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  userPresent: boolean;
  userVerified: boolean;
  backupEligible: boolean;
  backupState: boolean;
  attestedCredentialDataIncluded: boolean;
  extensionDataIncluded: boolean;
}

export function parseWebAuthnAuthenticatorData(
  authenticatorData: string
): ParsedWebAuthnAuthenticatorData {
  const bytes = base64UrlToBytes(authenticatorData);
  if (bytes.byteLength < 37) {
    throw new Error("authenticatorData must be at least 37 bytes");
  }

  const flags = bytes[32];
  const signCount =
    (bytes[33] << 24) | (bytes[34] << 16) | (bytes[35] << 8) | bytes[36];

  return {
    rpIdHash: bytes.slice(0, 32),
    flags,
    signCount: signCount >>> 0,
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    backupEligible: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0,
    attestedCredentialDataIncluded: (flags & 0x40) !== 0,
    extensionDataIncluded: (flags & 0x80) !== 0
  };
}

interface CborReadResult {
  value: unknown;
  offset: number;
}

interface CborByteString {
  readonly cborType: "bytes";
  readonly bytes: Uint8Array;
}

function readCborLength(bytes: Uint8Array, offset: number, additional: number): {
  length: number;
  offset: number;
} {
  if (additional < 24) {
    return { length: additional, offset };
  }
  if (additional === 24) {
    return { length: bytes[offset], offset: offset + 1 };
  }
  if (additional === 25) {
    return {
      length: (bytes[offset] << 8) | bytes[offset + 1],
      offset: offset + 2
    };
  }
  if (additional === 26) {
    return {
      length:
        ((bytes[offset] << 24) >>> 0)
        + (bytes[offset + 1] << 16)
        + (bytes[offset + 2] << 8)
        + bytes[offset + 3],
      offset: offset + 4
    };
  }
  throw new Error("Unsupported CBOR length encoding");
}

function cborMapKeyToString(key: unknown): string {
  if (typeof key === "number" || typeof key === "string") {
    return String(key);
  }
  throw new Error("Unsupported CBOR map key");
}

function decodeCbor(bytes: Uint8Array, offset = 0): CborReadResult {
  if (offset >= bytes.byteLength) {
    throw new Error("Unexpected end of CBOR data");
  }
  const initial = bytes[offset];
  const major = initial >> 5;
  const additional = initial & 0x1f;
  const lengthInfo = readCborLength(bytes, offset + 1, additional);

  if (major === 0) {
    return { value: lengthInfo.length, offset: lengthInfo.offset };
  }
  if (major === 1) {
    return { value: -1 - lengthInfo.length, offset: lengthInfo.offset };
  }
  if (major === 2) {
    return {
      value: {
        cborType: "bytes",
        bytes: bytes.slice(lengthInfo.offset, lengthInfo.offset + lengthInfo.length)
      } satisfies CborByteString,
      offset: lengthInfo.offset + lengthInfo.length
    };
  }
  if (major === 3) {
    return {
      value: new TextDecoder().decode(
        bytes.slice(lengthInfo.offset, lengthInfo.offset + lengthInfo.length)
      ),
      offset: lengthInfo.offset + lengthInfo.length
    };
  }
  if (major === 4) {
    const out: unknown[] = [];
    let nextOffset = lengthInfo.offset;
    for (let index = 0; index < lengthInfo.length; index += 1) {
      const decoded = decodeCbor(bytes, nextOffset);
      out.push(decoded.value);
      nextOffset = decoded.offset;
    }
    return { value: out, offset: nextOffset };
  }
  if (major === 5) {
    const out: Record<string, unknown> = {};
    let nextOffset = lengthInfo.offset;
    for (let index = 0; index < lengthInfo.length; index += 1) {
      const key = decodeCbor(bytes, nextOffset);
      const value = decodeCbor(bytes, key.offset);
      out[cborMapKeyToString(key.value)] = value.value;
      nextOffset = value.offset;
    }
    return { value: out, offset: nextOffset };
  }
  if (major === 7) {
    if (additional === 20) {
      return { value: false, offset: offset + 1 };
    }
    if (additional === 21) {
      return { value: true, offset: offset + 1 };
    }
    if (additional === 22) {
      return { value: null, offset: offset + 1 };
    }
  }
  throw new Error("Unsupported CBOR value");
}

function cborBytes(value: unknown, label: string): Uint8Array {
  if (
    Boolean(value)
    && typeof value === "object"
    && (value as { cborType?: unknown }).cborType === "bytes"
    && (value as { bytes?: unknown }).bytes instanceof Uint8Array
  ) {
    return (value as CborByteString).bytes;
  }
  throw new Error(`Expected CBOR byte string for ${label}`);
}

function cborMap(value: unknown, label: string): Record<string, unknown> {
  if (Boolean(value) && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error(`Expected CBOR map for ${label}`);
}

function coseP256PublicKeyToSpki(coseKey: Record<string, unknown>): {
  algorithm: number;
  publicKey: Hex;
} {
  const kty = coseKey["1"];
  const algorithm = coseKey["3"];
  const curve = coseKey["-1"];
  if (kty !== 2 || algorithm !== -7 || curve !== 1) {
    throw new Error("Only COSE EC2 ES256/P-256 credential public keys are supported");
  }
  const x = cborBytes(coseKey["-2"], "COSE x coordinate");
  const y = cborBytes(coseKey["-3"], "COSE y coordinate");
  if (x.byteLength !== 32 || y.byteLength !== 32) {
    throw new Error("COSE P-256 coordinates must be 32 bytes");
  }
  const spkiPrefix = getBytes(
    "0x3059301306072a8648ce3d020106082a8648ce3d03010703420004"
  );
  return {
    algorithm,
    publicKey: hexlify(concatBytes(spkiPrefix, x, y)) as Hex
  };
}

interface ParsedWebAuthnRegistrationAuthenticatorData
  extends ParsedWebAuthnAuthenticatorData {
  credentialId?: string;
  credentialPublicKey?: Hex;
  credentialPublicKeyAlgorithm?: number;
  aaguid?: Hex;
}

function parseRegistrationAuthenticatorData(
  authenticatorData: Uint8Array
): ParsedWebAuthnRegistrationAuthenticatorData {
  if (authenticatorData.byteLength < 37) {
    throw new Error("authenticatorData must be at least 37 bytes");
  }
  const flags = authenticatorData[32];
  const signCount =
    (authenticatorData[33] << 24)
    | (authenticatorData[34] << 16)
    | (authenticatorData[35] << 8)
    | authenticatorData[36];
  const parsed: ParsedWebAuthnRegistrationAuthenticatorData = {
    rpIdHash: authenticatorData.slice(0, 32),
    flags,
    signCount: signCount >>> 0,
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    backupEligible: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0,
    attestedCredentialDataIncluded: (flags & 0x40) !== 0,
    extensionDataIncluded: (flags & 0x80) !== 0
  };

  if (!parsed.attestedCredentialDataIncluded) {
    return parsed;
  }
  if (authenticatorData.byteLength < 55) {
    throw new Error("attested credential data is truncated");
  }
  const aaguid = authenticatorData.slice(37, 53);
  const credentialIdLength = (authenticatorData[53] << 8) | authenticatorData[54];
  const credentialIdStart = 55;
  const credentialIdEnd = credentialIdStart + credentialIdLength;
  if (authenticatorData.byteLength <= credentialIdEnd) {
    throw new Error("credential public key is missing from attested credential data");
  }
  const credentialId = authenticatorData.slice(credentialIdStart, credentialIdEnd);
  const cose = decodeCbor(authenticatorData, credentialIdEnd);
  const publicKey = coseP256PublicKeyToSpki(cborMap(cose.value, "COSE credential public key"));

  return {
    ...parsed,
    credentialId: arrayBufferToBase64Url(credentialId),
    credentialPublicKey: publicKey.publicKey,
    credentialPublicKeyAlgorithm: publicKey.algorithm,
    aaguid: hexlify(aaguid) as Hex
  };
}

export const PHIL_WEBAUTHN_REGISTRATION_VERIFIER_KIND =
  "webauthn-es256-cose-registration-verifier-v1" as const;

export async function verifyWebAuthnRegistration(
  input: PhilWebAuthnRegistrationVerificationInput
): Promise<PhilWebAuthnRegistrationVerificationResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const attestationPolicy = input.attestationPolicy ?? { mode: "none" as const };
  const expectedAlgorithms = input.expectedAlgorithms ?? [-7];
  const credentialId = input.registration.rawId;
  let parsedClientData: ReturnType<typeof parseWebAuthnClientDataJSON> | null = null;
  let attestationType = "unparsed";
  let authenticatorData: ParsedWebAuthnRegistrationAuthenticatorData | null = null;
  let rpIdHashMatched = false;
  let algorithm = input.registration.response.publicKeyAlgorithm;
  let credentialPublicKey = input.registration.response.publicKey
    ? hexlify(new Uint8Array(base64UrlToArrayBuffer(input.registration.response.publicKey))) as Hex
    : undefined;

  try {
    parsedClientData = parseWebAuthnClientDataJSON(input.registration.response.clientDataJSON);
  } catch (error) {
    errors.push(`Invalid clientDataJSON: ${String(error && typeof error === "object" && "message" in error ? error.message : error)}`);
  }

  const challengeMatched = parsedClientData?.challenge === input.expectedChallenge;
  const originMatched = parsedClientData?.origin === input.expectedOrigin;
  if (parsedClientData?.type !== "webauthn.create") {
    errors.push("clientDataJSON type must be webauthn.create");
  }
  if (!challengeMatched) {
    errors.push("clientDataJSON challenge mismatch");
  }
  if (!originMatched) {
    errors.push("clientDataJSON origin mismatch");
  }
  if (
    parsedClientData?.crossOrigin === true
    && input.allowCrossOrigin !== true
    && attestationPolicy.allowCrossOrigin !== true
  ) {
    errors.push("crossOrigin WebAuthn registrations are not accepted");
  }

  try {
    const decoded = decodeCbor(base64UrlToBytes(input.registration.response.attestationObject));
    const attestationObject = cborMap(decoded.value, "attestationObject");
    attestationType = typeof attestationObject.fmt === "string"
      ? attestationObject.fmt
      : "unknown";
    const authDataBytes = cborBytes(attestationObject.authData, "attestationObject.authData");
    authenticatorData = parseRegistrationAuthenticatorData(authDataBytes);
    const expectedRpIdHash = await sha256Bytes(input.expectedRpId);
    rpIdHashMatched = bytesEqual(authenticatorData.rpIdHash, expectedRpIdHash);
    if (!rpIdHashMatched) {
      errors.push("authenticatorData rpIdHash mismatch");
    }
    if (!authenticatorData.userPresent) {
      errors.push("authenticatorData user presence flag is not set");
    }
    if (
      input.expectedUserVerification === "required"
      && !authenticatorData.userVerified
    ) {
      errors.push("authenticatorData user verification flag is not set");
    }
    if (!authenticatorData.attestedCredentialDataIncluded) {
      errors.push("authenticatorData attested credential data is missing");
    }
    if (authenticatorData.extensionDataIncluded) {
      warnings.push("authenticatorData extension data is present and ignored after flag parsing");
    }
    if (authenticatorData.credentialId && authenticatorData.credentialId !== credentialId) {
      errors.push("registration rawId does not match attested credential ID");
    }
    credentialPublicKey = authenticatorData.credentialPublicKey ?? credentialPublicKey;
    algorithm = authenticatorData.credentialPublicKeyAlgorithm ?? algorithm;
  } catch (error) {
    errors.push(`Invalid attestationObject: ${String(error && typeof error === "object" && "message" in error ? error.message : error)}`);
  }

  if (algorithm === undefined) {
    errors.push("Credential public-key algorithm is missing");
  } else if (!expectedAlgorithms.includes(algorithm)) {
    errors.push("Credential public-key algorithm is not allowed");
  }
  if (algorithm !== undefined && algorithm !== -7) {
    errors.push("Only ES256/P-256 WebAuthn registration verification is currently supported");
  }
  if (!credentialPublicKey) {
    errors.push("Credential public key is missing");
  }
  if (attestationPolicy.mode === "none") {
    if (attestationType !== "none") {
      warnings.push("Attestation object was parsed, but attestation trust chain validation is disabled by policy");
    }
  } else if (attestationPolicy.mode === "permissive") {
    warnings.push("Permissive attestation parses metadata but does not validate trusted attestation roots");
  } else if (attestationPolicy.mode === "direct") {
    errors.push("Direct attestation trust root validation is not implemented");
  } else {
    errors.push("Unsupported attestation policy mode");
  }

  const verified = errors.length === 0;
  return {
    verified,
    verifierKind: PHIL_WEBAUTHN_REGISTRATION_VERIFIER_KIND,
    productionVerified: verified,
    reason: verified
      ? "WebAuthn registration verified with ES256/P-256 credential extraction and local attestation policy"
      : "WebAuthn registration verification failed",
    credentialId,
    credentialPublicKey,
    algorithm,
    signCount: authenticatorData?.signCount ?? 0,
    originMatched,
    challengeMatched,
    rpIdHashMatched,
    userPresent: authenticatorData?.userPresent ?? false,
    userVerified: authenticatorData?.userVerified ?? false,
    backupEligible: authenticatorData?.backupEligible ?? false,
    backupState: authenticatorData?.backupState ?? false,
    attestedCredentialDataIncluded: authenticatorData?.attestedCredentialDataIncluded ?? false,
    attestationType,
    attestationPolicyMode: attestationPolicy.mode,
    transports: Object.freeze([...(input.registration.response.transports ?? [])]),
    warnings,
    errors
  };
}

function readDerLength(bytes: Uint8Array, offset: number): { length: number; offset: number } {
  const first = bytes[offset];
  if (first < 0x80) {
    return { length: first, offset: offset + 1 };
  }
  const byteCount = first & 0x7f;
  if (byteCount === 0 || byteCount > 2) {
    throw new Error("Unsupported DER ECDSA signature length");
  }
  let length = 0;
  for (let index = 0; index < byteCount; index += 1) {
    length = (length << 8) | bytes[offset + 1 + index];
  }
  return { length, offset: offset + 1 + byteCount };
}

function readDerInteger(bytes: Uint8Array, offset: number): { value: Uint8Array; offset: number } {
  if (bytes[offset] !== 0x02) {
    throw new Error("Invalid DER ECDSA signature integer");
  }
  const lengthInfo = readDerLength(bytes, offset + 1);
  const raw = bytes.slice(lengthInfo.offset, lengthInfo.offset + lengthInfo.length);
  return {
    value: raw,
    offset: lengthInfo.offset + lengthInfo.length
  };
}

function derIntegerToFixed32(value: Uint8Array): Uint8Array {
  let normalized = value;
  while (normalized.byteLength > 0 && normalized[0] === 0) {
    normalized = normalized.slice(1);
  }
  if (normalized.byteLength > 32) {
    throw new Error("DER ECDSA integer is too large for P-256");
  }
  const out = new Uint8Array(32);
  out.set(normalized, 32 - normalized.byteLength);
  return out;
}

export function derEcdsaSignatureToRawP256(signature: Uint8Array): Uint8Array {
  if (signature[0] !== 0x30) {
    throw new Error("Invalid DER ECDSA signature sequence");
  }
  const sequenceLength = readDerLength(signature, 1);
  const sequenceEnd = sequenceLength.offset + sequenceLength.length;
  const r = readDerInteger(signature, sequenceLength.offset);
  const s = readDerInteger(signature, r.offset);
  if (s.offset !== sequenceEnd) {
    throw new Error("Invalid trailing bytes in DER ECDSA signature");
  }
  return concatBytes(derIntegerToFixed32(r.value), derIntegerToFixed32(s.value));
}

async function verifyP256SpkiSignature(input: {
  publicKey: Hex;
  signature: string;
  authenticatorData: string;
  clientDataJSON: string;
}): Promise<boolean> {
  const publicKeyBytes = getBytes(input.publicKey);
  const signatureBytes = base64UrlToBytes(input.signature);
  const rawSignature = derEcdsaSignatureToRawP256(signatureBytes);
  const authenticatorData = base64UrlToBytes(input.authenticatorData);
  const clientDataJSON = base64UrlToBytes(input.clientDataJSON);
  const clientDataHash = await sha256Bytes(clientDataJSON);
  const signedBytes = concatBytes(authenticatorData, clientDataHash);
  const key = await globalThis.crypto.subtle.importKey(
    "spki",
    bytesToOwnedArrayBuffer(publicKeyBytes),
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    false,
    ["verify"]
  );

  return globalThis.crypto.subtle.verify(
    {
      name: "ECDSA",
      hash: "SHA-256"
    },
    key,
    bytesToOwnedArrayBuffer(rawSignature),
    bytesToOwnedArrayBuffer(signedBytes)
  );
}

function evaluateCounter(input: {
  storedSignCount: number;
  returnedSignCount: number;
}): {
  counterStatus: PhilWebAuthnCounterStatus;
  accepted: boolean;
  newSignCount: number;
  warning?: string;
  error?: string;
} {
  const stored = input.storedSignCount;
  const returned = input.returnedSignCount;

  if (stored === 0 && returned === 0) {
    return {
      counterStatus: "unchanged-zero",
      accepted: true,
      newSignCount: 0,
      warning: "Authenticator sign counter is zero; this authenticator may not support counters"
    };
  }
  if (returned === 0) {
    return {
      counterStatus: "unsupported",
      accepted: true,
      newSignCount: stored,
      warning: "Authenticator returned zero sign counter; replay detection is limited"
    };
  }
  if (returned > stored) {
    return {
      counterStatus: "advanced",
      accepted: true,
      newSignCount: returned
    };
  }
  if (returned < stored) {
    return {
      counterStatus: "rollback",
      accepted: false,
      newSignCount: stored,
      error: "Authenticator sign counter rolled back"
    };
  }

  return {
    counterStatus: "clone-suspected",
    accepted: false,
    newSignCount: stored,
    error: "Authenticator sign counter did not advance"
  };
}

export const PHIL_WEBAUTHN_ASSERTION_VERIFIER_KIND =
  "webauthn-es256-spki-assertion-verifier-v1" as const;

export function createWebAuthnAssertionVerifier(): PhilWebAuthnVerifier {
  return Object.freeze({
    async verifyAssertion(
      input: PhilWebAuthnVerificationInput
    ): Promise<PhilWebAuthnVerificationResult> {
      const errors: string[] = [];
      const warnings: string[] = [];
      const credentialId = input.assertion.rawId;
      let parsedClientData: ReturnType<typeof parseWebAuthnClientDataJSON> | null = null;
      let authenticatorData: ParsedWebAuthnAuthenticatorData | null = null;
      let rpIdHashMatched = false;
      let signatureVerified = false;
      let counterStatus: PhilWebAuthnCounterStatus = "unsupported";
      let newSignCount = input.storedSignCount;

      if (credentialId !== input.credential.credentialId) {
        errors.push("Credential ID mismatch");
      }

      try {
        parsedClientData = parseWebAuthnClientDataJSON(
          input.assertion.response.clientDataJSON
        );
      } catch (error) {
        errors.push(`Invalid clientDataJSON: ${String(error && typeof error === "object" && "message" in error ? error.message : error)}`);
      }

      const challengeMatched = parsedClientData?.challenge === input.expectedChallenge;
      const originMatched = parsedClientData?.origin === input.expectedOrigin;
      if (parsedClientData?.type !== "webauthn.get") {
        errors.push("clientDataJSON type must be webauthn.get");
      }
      if (!challengeMatched) {
        errors.push("clientDataJSON challenge mismatch");
      }
      if (!originMatched) {
        errors.push("clientDataJSON origin mismatch");
      }
      if (parsedClientData?.crossOrigin === true) {
        errors.push("crossOrigin WebAuthn assertions are not accepted");
      }

      try {
        authenticatorData = parseWebAuthnAuthenticatorData(
          input.assertion.response.authenticatorData
        );
        const expectedRpIdHash = await sha256Bytes(input.expectedRpId);
        rpIdHashMatched = bytesEqual(authenticatorData.rpIdHash, expectedRpIdHash);
        if (!rpIdHashMatched) {
          errors.push("authenticatorData rpIdHash mismatch");
        }
        if (!authenticatorData.userPresent) {
          errors.push("authenticatorData user presence flag is not set");
        }
        if (
          input.expectedUserVerification === "required"
          && !authenticatorData.userVerified
        ) {
          errors.push("authenticatorData user verification flag is not set");
        }
        if (authenticatorData.attestedCredentialDataIncluded) {
          errors.push("authenticatorData unexpectedly includes attested credential data");
        }
        if (authenticatorData.extensionDataIncluded) {
          warnings.push("authenticatorData extension data is present and ignored after flag parsing");
        }

        const counter = evaluateCounter({
          storedSignCount: input.storedSignCount,
          returnedSignCount: authenticatorData.signCount
        });
        counterStatus = counter.counterStatus;
        newSignCount = counter.newSignCount;
        if (counter.warning) {
          warnings.push(counter.warning);
        }
        if (!counter.accepted && counter.error) {
          errors.push(counter.error);
        }
      } catch (error) {
        errors.push(`Invalid authenticatorData: ${String(error && typeof error === "object" && "message" in error ? error.message : error)}`);
      }

      if (input.credential.publicKeyAlgorithm !== undefined && input.credential.publicKeyAlgorithm !== -7) {
        errors.push("Only ES256/P-256 WebAuthn assertion verification is currently supported");
      }
      if (!input.credential.publicKey) {
        errors.push("Stored SPKI public key is required for signature verification");
      }

      if (input.credential.publicKey && errors.length === 0) {
        try {
          signatureVerified = await verifyP256SpkiSignature({
            publicKey: input.credential.publicKey,
            signature: input.assertion.response.signature,
            authenticatorData: input.assertion.response.authenticatorData,
            clientDataJSON: input.assertion.response.clientDataJSON
          });
          if (!signatureVerified) {
            errors.push("WebAuthn assertion signature verification failed");
          }
        } catch (error) {
          errors.push(`WebAuthn assertion signature verification failed: ${String(error && typeof error === "object" && "message" in error ? error.message : error)}`);
        }
      }

      const verified = errors.length === 0;
      return {
        verified,
        verifierKind: PHIL_WEBAUTHN_ASSERTION_VERIFIER_KIND,
        productionVerified: verified,
        reason: verified
          ? "WebAuthn assertion verified with ES256/P-256 SPKI public key"
          : "WebAuthn assertion verification failed",
        credentialId,
        newSignCount,
        userPresent: authenticatorData?.userPresent ?? false,
        userVerified: authenticatorData?.userVerified ?? false,
        rpIdHashMatched,
        challengeMatched,
        originMatched,
        signatureVerified,
        counterStatus,
        warnings,
        errors
      };
    }
  });
}

function resolvePhilIdentity(options: PhilWebAuthnProviderOptions): PhilIdentityPublic {
  if (options.philIdentityPrivate !== undefined) {
    return derivePhilIdentityPublic(options.philIdentityPrivate);
  }
  if (options.philIdentityPublic !== undefined) {
    return options.philIdentityPublic;
  }
  throw new Error("Phil identity public metadata is required for WebAuthn provider setup");
}

function normalizeRpConfig(rp: PhilWebAuthnRelyingPartyConfig): Required<PhilWebAuthnRelyingPartyConfig> {
  return {
    rpId: String(rp.rpId || "").trim(),
    rpName: String(rp.rpName || "").trim(),
    origin: String(rp.origin || "").trim(),
    userDisplayName: String(rp.userDisplayName || "").trim(),
    userName: String(rp.userName || "").trim(),
    userId: rp.userId,
    userVerification: rp.userVerification ?? "preferred",
    residentKey: rp.residentKey ?? "preferred",
    authenticatorAttachment: rp.authenticatorAttachment ?? "platform",
    timeout: rp.timeout ?? WEBAUTHN_DEFAULT_TIMEOUT_MS,
    label: rp.label ?? "Phil passkey"
  };
}

function assertRpConfig(rp: Required<PhilWebAuthnRelyingPartyConfig>) {
  for (const key of ["rpId", "rpName", "origin", "userDisplayName", "userName"] as const) {
    if (!rp[key]) {
      throw new Error(`WebAuthn RP config ${key} is required`);
    }
  }
}

function deviceIds(input: {
  ownerCommitment: Hex;
  rpId: string;
  credentialId: string;
}) {
  const credentialIdHash = keccak256(toUtf8Bytes(input.credentialId)) as Hex;
  const deviceKeyId = keccak256(
    abiCoder.encode(
      ["bytes32", "string", "bytes32"],
      [credentialIdHash, input.rpId, input.ownerCommitment]
    )
  ) as Hex;
  const deviceIdentityId = keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "bytes32"],
      [keccak256(toUtf8Bytes("PHIL_WEBAUTHN_DEVICE_IDENTITY_V1")), input.ownerCommitment, deviceKeyId]
    )
  ) as Hex;

  return { credentialIdHash, deviceKeyId, deviceIdentityId };
}

export function buildWebAuthnRegistrationOptions(input: {
  rp: PhilWebAuthnRelyingPartyConfig;
  philIdentity: PhilIdentityPublic;
  challenge?: BytesLike;
  attestation?: AttestationConveyancePreference;
}): PublicKeyCredentialCreationOptions {
  const rp = normalizeRpConfig(input.rp);
  assertRpConfig(rp);

  const challenge = input.challenge === undefined
    ? authorizationDigestToWebAuthnChallenge(input.philIdentity.ownerCommitment)
    : authorizationDigestToWebAuthnChallenge(input.challenge);

  return {
    rp: {
      id: rp.rpId,
      name: rp.rpName
    },
    user: {
      id: bytesLikeToArrayBuffer(rp.userId),
      name: rp.userName,
      displayName: rp.userDisplayName
    },
    challenge,
    pubKeyCredParams: [
      { type: "public-key", alg: -7 }
    ],
    timeout: rp.timeout,
    attestation: input.attestation ?? "none",
    authenticatorSelection: {
      authenticatorAttachment: rp.authenticatorAttachment,
      residentKey: rp.residentKey,
      requireResidentKey: rp.residentKey === "required",
      userVerification: rp.userVerification
    }
  };
}

export function buildWebAuthnAssertionOptions(input: {
  rp: PhilWebAuthnRelyingPartyConfig;
  credential: PhilWebAuthnCredentialMetadata;
  signableDigest: BytesLike;
}): PublicKeyCredentialRequestOptions {
  const rp = normalizeRpConfig(input.rp);
  assertRpConfig(rp);

  return {
    challenge: authorizationDigestToWebAuthnChallenge(input.signableDigest),
    timeout: rp.timeout,
    rpId: rp.rpId,
    allowCredentials: [
      {
        id: credentialIdFromBase64Url(input.credential.credentialId),
        type: "public-key",
        transports: input.credential.transports as AuthenticatorTransport[] | undefined
      }
    ],
    userVerification: rp.userVerification
  };
}

export async function registerWebAuthnDeviceIdentity(
  options: PhilWebAuthnRegistrationOptions
): Promise<PhilWebAuthnRegistrationResult> {
  const credentials = getCredentials(options);
  const philIdentity = resolvePhilIdentity(options);
  const rp = normalizeRpConfig(options.rp);
  const creationOptions = buildWebAuthnRegistrationOptions({
    rp: options.rp,
    philIdentity,
    attestation: options.attestation
  });
  const created = await credentials.create({
    publicKey: creationOptions
  });

  if (!created || created.type !== "public-key") {
    throw new Error("WebAuthn registration did not return a public-key credential");
  }

  const publicKeyCredential = created as PublicKeyCredential;
  const serialized = serializeWebAuthnCredential(publicKeyCredential);
  const expectedChallenge = arrayBufferToBase64Url(
    bufferSourceToUint8Array(creationOptions.challenge)
  );
  const verification = await verifyWebAuthnRegistration({
    registration: serialized,
    expectedChallenge,
    expectedOrigin: rp.origin,
    expectedRpId: rp.rpId,
    expectedUserVerification: rp.userVerification,
    expectedAlgorithms: options.expectedAlgorithms,
    attestationPolicy: options.attestationPolicy ?? {
      mode: options.attestation === "direct" ? "direct" : "none"
    },
    allowCrossOrigin: options.allowCrossOriginRegistration
  });
  if (!verification.verified) {
    throw new Error(
      `WebAuthn registration verification failed: ${verification.errors.join("; ")}`
    );
  }
  const credentialMetadata: PhilWebAuthnCredentialMetadata = {
    credentialId: serialized.rawId,
    credentialIdHash: keccak256(toUtf8Bytes(serialized.rawId)) as Hex,
    rawId: serialized.rawId,
    publicKey: verification.credentialPublicKey,
    publicKeyAlgorithm: verification.algorithm,
    signCount: verification.signCount,
    transports: verification.transports,
    authenticatorAttachment: serialized.authenticatorAttachment ?? undefined,
    createdAt: options.now?.(),
    label: rp.label
  };
  const provider = createWebAuthnPasskeyDeviceIdentityProvider({
    ...options,
    philIdentityPublic: philIdentity,
    credential: credentialMetadata
  });

  return {
    provider,
    metadata: provider.getPublicMetadata(),
    credential: serialized,
    creationOptions,
    verification
  };
}

export function createWebAuthnPasskeyDeviceIdentityProvider(
  options: PhilWebAuthnProviderOptions
): PhilWebAuthnProvider {
  const rp = normalizeRpConfig(options.rp);
  assertRpConfig(rp);
  const philIdentity = resolvePhilIdentity(options);
  if (!options.credential) {
    throw new Error("WebAuthn credential metadata is required; call registerWebAuthnDeviceIdentity first or load an existing credential");
  }
  const credentialMetadata = options.credential;

  const ids = deviceIds({
    ownerCommitment: philIdentity.ownerCommitment,
    rpId: rp.rpId,
    credentialId: credentialMetadata.credentialId
  });
  const metadata: PhilWebAuthnPublicMetadata = Object.freeze({
    version: PHIL_DEVICE_IDENTITY_VERSION,
    providerKind: PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
    deviceIdentityId: ids.deviceIdentityId,
    deviceKeyId: ids.deviceKeyId,
    credentialId: credentialMetadata.credentialId,
    credentialIdHash: ids.credentialIdHash,
    credentialPublicKey: credentialMetadata.publicKey,
    publicKey: credentialMetadata.publicKey,
    publicKeyHash: credentialMetadata.publicKey
      ? keccak256(credentialMetadata.publicKey) as Hex
      : undefined,
    authenticatorAttachment: credentialMetadata.authenticatorAttachment,
    transports: credentialMetadata.transports,
    philIdentity,
    rpId: rp.rpId,
    rpName: rp.rpName,
    origin: rp.origin,
    userVerification: rp.userVerification,
    residentKey: rp.residentKey,
    label: credentialMetadata.label ?? rp.label,
    productionSafe: false,
    privateMaterialExportable: false,
    hardwareBacked: true,
    createdAt: credentialMetadata.createdAt
  });
  const verifier = options.verifier ?? createWebAuthnAssertionVerifier();

  return Object.freeze({
    providerKind: PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
    productionSafe: false,
    hardwareBacked: true,
    getPublicMetadata() {
      return metadata;
    },
    buildAssertionOptions(payload: PhilAuthorizationDigestPayload) {
      return buildWebAuthnAssertionOptions({
        rp,
        credential: credentialMetadata,
        signableDigest: payload.signableDigest
      });
    },
    async authorizeDigest(
      payload: PhilAuthorizationDigestPayload
    ): Promise<PhilWebAuthnAuthorizationSignature> {
      const signableDigest = normalizeHex32(payload.signableDigest, "signableDigest");
      const credentials = getCredentials(options);
      const requestOptions = buildWebAuthnAssertionOptions({
        rp,
        credential: credentialMetadata,
        signableDigest
      });
      const credential = await credentials.get({
        publicKey: requestOptions
      });

      if (!credential || credential.type !== "public-key") {
        throw new Error("WebAuthn authentication did not return a public-key assertion");
      }

      const assertion = serializeWebAuthnAssertion(credential as PublicKeyCredential);
      const expectedChallenge = authorizationDigestToWebAuthnChallengeBase64Url(signableDigest);
      const verification = await verifier.verifyAssertion({
        assertion,
        credential: credentialMetadata,
        expectedChallenge,
        expectedOrigin: rp.origin,
        expectedRpId: rp.rpId,
        expectedUserVerification: rp.userVerification,
        storedSignCount: credentialMetadata.signCount ?? 0
      });

      return {
        version: PHIL_DEVICE_IDENTITY_VERSION,
        providerKind: PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
        deviceIdentityId: ids.deviceIdentityId,
        deviceKeyId: ids.deviceKeyId,
        signatureKind: "webauthn-passkey-assertion-over-phil-digest-v1",
        signableDigest,
        digestEncoding: String(payload.digestEncoding || ""),
        signature: hexlify(new Uint8Array(base64UrlToArrayBuffer(assertion.response.signature))) as Hex,
        signatureHash: keccak256(
          new Uint8Array(base64UrlToArrayBuffer(assertion.response.signature))
        ) as Hex,
        signedAt: options.now?.(),
        assertion,
        verification
      };
    },
    exportPrivateMaterial(): never {
      throw new PhilDeviceIdentityPrivateMaterialError();
    }
  });
}

export function assertWebAuthnPrivateMaterialError(error: unknown): boolean {
  return (
    Boolean(error)
    && typeof error === "object"
    && (error as { code?: unknown }).code
      === PHIL_DEVICE_IDENTITY_PRIVATE_MATERIAL_EXPORT_ERROR
  );
}

export function assertWebAuthnUnsupportedPlatformError(error: unknown): boolean {
  return (
    Boolean(error)
    && typeof error === "object"
    && (error as { code?: unknown }).code
      === PHIL_DEVICE_IDENTITY_UNSUPPORTED_PLATFORM_ERROR
  );
}
