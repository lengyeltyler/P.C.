import { AbiCoder, getBytes, hexlify, keccak256, toUtf8Bytes, type BytesLike } from "ethers";

import type { Hex } from "./hashes.ts";
import {
  derivePhilCryptoSchemeRegistryHashV1,
  validatePhilCryptoSchemeRegistryV1
} from "./postQuantumMigrationV1.ts";
import {
  PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
  PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
  PHIL_ROUTINE_WIRE_ENCODING_V2_ID
} from "./p256SignatureWireV2.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
export const PHIL_ROUTINE_SIGNATURE_REGISTRY_V2_LABEL = "PHIL_ROUTINE_SIGNATURE_REGISTRY_V2" as const;
export const PHIL_ROUTINE_SIGNATURE_REGISTRY_V2_HASH = keccak256(
  toUtf8Bytes(PHIL_ROUTINE_SIGNATURE_REGISTRY_V2_LABEL)
) as Hex;
export const PHIL_ROUTINE_INHERITED_REGISTRY_V1_HASH = derivePhilCryptoSchemeRegistryHashV1(1);

export interface PhilRoutineSignatureRegistryV2 {
  readonly formatVersionHash: Hex;
  readonly registryEpoch: string;
  readonly inheritedRegistryEpoch: string;
  readonly inheritedRegistryHash: Hex;
  readonly routineDeviceSignatureSuiteId: Hex;
  readonly providerProfileId: Hex;
  readonly wireEncodingId: Hex;
  readonly status: 1;
  readonly externalNetwork: false;
  readonly postQuantum: false;
  readonly registryHash: Hex;
}

export class PhilRoutineSignatureRegistryV2Error extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilRoutineSignatureRegistryV2Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilRoutineSignatureRegistryV2Error(code, message);
}

function bytes32(value: BytesLike, label: string): Hex {
  let normalized: Hex;
  try { normalized = hexlify(value).toLowerCase() as Hex; }
  catch { return fail("PHIL_ROUTINE_REGISTRY_BYTES32_INVALID", `${label} must be bytes32`); }
  if (getBytes(normalized).length !== 32) fail("PHIL_ROUTINE_REGISTRY_BYTES32_INVALID", `${label} must be bytes32`);
  return normalized;
}

export function createPhilRoutineSignatureRegistryV2(): PhilRoutineSignatureRegistryV2 {
  const inherited = validatePhilCryptoSchemeRegistryV1();
  if (inherited.registryEpoch !== "1" || inherited.registryHash !== PHIL_ROUTINE_INHERITED_REGISTRY_V1_HASH) {
    fail("PHIL_ROUTINE_REGISTRY_INHERITANCE_MISMATCH", "accepted Step 5 epoch-1 registry changed");
  }
  const normalized = {
    formatVersionHash: PHIL_ROUTINE_SIGNATURE_REGISTRY_V2_HASH,
    registryEpoch: "2",
    inheritedRegistryEpoch: "1",
    inheritedRegistryHash: PHIL_ROUTINE_INHERITED_REGISTRY_V1_HASH,
    routineDeviceSignatureSuiteId: PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
    providerProfileId: PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
    wireEncodingId: PHIL_ROUTINE_WIRE_ENCODING_V2_ID,
    status: 1 as const,
    externalNetwork: false as const,
    postQuantum: false as const
  };
  const registryHash = keccak256(abiCoder.encode(
    ["bytes32","uint64","uint64","bytes32","bytes32","bytes32","bytes32","uint8","bool","bool"],
    [normalized.formatVersionHash,2n,1n,normalized.inheritedRegistryHash,
      normalized.routineDeviceSignatureSuiteId,normalized.providerProfileId,
      normalized.wireEncodingId,1,false,false]
  )) as Hex;
  return Object.freeze({ ...normalized, registryHash });
}

export function validatePhilRoutineSignatureRegistryV2(
  registry: PhilRoutineSignatureRegistryV2
): PhilRoutineSignatureRegistryV2 {
  const expected = createPhilRoutineSignatureRegistryV2();
  for (const key of Object.keys(expected) as (keyof PhilRoutineSignatureRegistryV2)[]) {
    const actual = key.endsWith("Hash") || key.endsWith("Id")
      ? bytes32(registry[key] as BytesLike, key)
      : registry[key];
    if (actual !== expected[key]) fail("PHIL_ROUTINE_REGISTRY_MISMATCH", `${key} does not match the admitted local V2 profile`);
  }
  return expected;
}
