import {
  AbiCoder,
  hexlify,
  type BigNumberish,
  type BytesLike
} from "ethers";

import {
  buildLegacyOwnerCommitmentFromAddressSalt,
  buildUnlockPolicy,
  type LegacyOwnerCommitment
} from "./commitments.ts";
import {
  createPhilIdentityPrivate,
  derivePhilIdentityPublic,
  type PhilIdentityPrivate,
  type PhilIdentityPublic
} from "./identity.ts";
import {
  authorizationDigest,
  dataHash,
  normalizeBaseActionAuthorization,
  normalizeUnlockRequest,
  unlockActionHash,
  type BaseActionAuthorization,
  type UnlockProofPackage,
  type UnlockRequest
} from "./hashes.ts";
import { buildNullifier } from "./nullifier.ts";
import { buildUnlockProofPackageFromAuthorization } from "./proof/publicInputs.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export interface UnlockAuthorizationAssemblyInput {
  chainId: BigNumberish;
  consumer: string;
  philSecret?: BytesLike;
  philIdentityPrivate?: PhilIdentityPrivate;
  // LEGACY ONLY / TEST ONLY. Disabled unless explicitly enabled.
  allowLegacyOwnerCommitment?: true;
  legacyOwner?: string;
  legacyOwnerSalt?: BytesLike;
  account: string;
  target: string;
  value?: BigNumberish;
  callData?: BytesLike;
  expiry?: BigNumberish;
  policyData?: BytesLike;
  policyTarget?: string;
  nullifierSeed: BytesLike;
}

export interface ResolvedOwnerCommitment {
  ownerCommitment: `0x${string}`;
  mode: "phil-secret" | LegacyOwnerCommitment["mode"];
  philIdentity?: PhilIdentityPublic;
  legacyOwner?: string;
  legacyOwnerSalt?: `0x${string}`;
}

interface ResolvedOwnerCommitmentInternal extends ResolvedOwnerCommitment {
  philIdentityPrivate?: PhilIdentityPrivate;
}

export interface UnlockAuthorizationAssembly {
  ownerCommitment: ResolvedOwnerCommitment;
  unlockRequest: ReturnType<typeof normalizeUnlockRequest>;
  consumerData: `0x${string}`;
  consumerDataHash: `0x${string}`;
  policy: ReturnType<typeof buildUnlockPolicy>;
  actionHash: `0x${string}`;
  nullifier: ReturnType<typeof buildNullifier>;
  authorization: BaseActionAuthorization;
  proofPackage: UnlockProofPackage;
  digest: `0x${string}`;
}

export function encodeUnlockConsumerData(request: UnlockRequest): `0x${string}` {
  const normalized = normalizeUnlockRequest(request);
  return abiCoder.encode(
    ["tuple(address account,address target,uint256 value,bytes callData)"],
    [normalized]
  ) as `0x${string}`;
}

export function decodeUnlockConsumerData(consumerData: BytesLike) {
  const [decoded] = abiCoder.decode(
    ["tuple(address account,address target,uint256 value,bytes callData)"],
    consumerData
  );

  return normalizeUnlockRequest(decoded);
}

export function computeUnlockActionHashFromConsumerData(input: {
  chainId: BigNumberish;
  consumer: string;
  consumerData: BytesLike;
}) {
  const request = decodeUnlockConsumerData(input.consumerData);
  return {
    request,
    actionHash: unlockActionHash({
      chainId: input.chainId,
      consumer: input.consumer,
      account: request.account,
      target: request.target,
      value: request.value,
      callDataHash: dataHash(request.callData)
    })
  };
}

function resolveOwnerCommitment(
  input: UnlockAuthorizationAssemblyInput
): ResolvedOwnerCommitmentInternal {
  const hasPhilSecret = input.philSecret !== undefined;
  const hasPhilIdentityPrivate = input.philIdentityPrivate !== undefined;
  const hasOwnerCommitmentInjection =
    Object.prototype.hasOwnProperty.call(input, "ownerCommitment")
    && (input as { ownerCommitment?: unknown }).ownerCommitment !== undefined;
  const hasLegacyInputs =
    input.legacyOwner !== undefined || input.legacyOwnerSalt !== undefined;

  if (hasOwnerCommitmentInjection) {
    throw new Error(
      "ownerCommitment injection is disabled; provide philSecret or philIdentityPrivate"
    );
  }

  if (hasPhilSecret && hasPhilIdentityPrivate) {
    throw new Error("Provide either philSecret or philIdentityPrivate, not both");
  }

  if (hasLegacyInputs) {
    if (hasPhilSecret || hasPhilIdentityPrivate) {
      throw new Error(
        "LEGACY ONLY / TEST ONLY: do not combine legacy owner inputs with philSecret or philIdentityPrivate"
      );
    }
    if (input.allowLegacyOwnerCommitment !== true) {
      throw new Error(
        "LEGACY ONLY / TEST ONLY: legacyOwnerCommitment requires allowLegacyOwnerCommitment: true"
      );
    }
    if (input.legacyOwner === undefined || input.legacyOwnerSalt === undefined) {
      throw new Error(
        "LEGACY ONLY / TEST ONLY: legacyOwner and legacyOwnerSalt are both required"
      );
    }

    const legacy = buildLegacyOwnerCommitmentFromAddressSalt({
      legacyOwner: input.legacyOwner,
      legacyOwnerSalt: input.legacyOwnerSalt
    });

    return {
      ownerCommitment: legacy.ownerCommitment,
      mode: legacy.mode,
      legacyOwner: legacy.legacyOwner,
      legacyOwnerSalt: legacy.legacyOwnerSalt
    };
  }

  if (input.philSecret !== undefined) {
    const philIdentityPrivate = createPhilIdentityPrivate({ philSecret: input.philSecret });
    const philIdentity = derivePhilIdentityPublic(philIdentityPrivate);
    return {
      ownerCommitment: philIdentity.ownerCommitment,
      mode: "phil-secret",
      philIdentity,
      philIdentityPrivate
    };
  }

  if (input.philIdentityPrivate !== undefined) {
    const philIdentity = derivePhilIdentityPublic(input.philIdentityPrivate);
    return {
      ownerCommitment: philIdentity.ownerCommitment,
      mode: "phil-secret",
      philIdentity,
      philIdentityPrivate: input.philIdentityPrivate
    };
  }

  throw new Error("Canonical identity required: provide philSecret or philIdentityPrivate");
}

export function assembleUnlockAuthorizationPayload(
  input: UnlockAuthorizationAssemblyInput
): UnlockAuthorizationAssembly {
  const resolvedOwnerCommitment = resolveOwnerCommitment(input);
  const publicOwnerCommitment: ResolvedOwnerCommitment = {
    ownerCommitment: resolvedOwnerCommitment.ownerCommitment,
    mode: resolvedOwnerCommitment.mode,
    philIdentity: resolvedOwnerCommitment.philIdentity,
    legacyOwner: resolvedOwnerCommitment.legacyOwner,
    legacyOwnerSalt: resolvedOwnerCommitment.legacyOwnerSalt
  };

  const unlockRequest = normalizeUnlockRequest({
    account: input.account,
    target: input.target,
    value: input.value ?? 0,
    callData: input.callData ?? "0x"
  });

  const consumerData = encodeUnlockConsumerData(unlockRequest);
  const consumerDataHash = dataHash(consumerData);

  const actionHash = unlockActionHash({
    chainId: input.chainId,
    consumer: input.consumer,
    account: unlockRequest.account,
    target: unlockRequest.target,
    value: unlockRequest.value,
    callDataHash: dataHash(unlockRequest.callData)
  });

  const policy = buildUnlockPolicy({
    chainId: input.chainId,
    consumer: input.consumer,
    target: input.policyTarget ?? unlockRequest.target,
    expiry: input.expiry ?? 0,
    policyData: input.policyData ?? "0x"
  });

  const nullifierData = buildNullifier({
    ownerCommitment: resolvedOwnerCommitment.ownerCommitment,
    actionHash,
    policyHash: policy.policyHash,
    nullifierSeed: input.nullifierSeed
  });

  const authorization = normalizeBaseActionAuthorization({
    consumer: input.consumer,
    ownerCommitment: resolvedOwnerCommitment.ownerCommitment,
    actionHash,
    policyHash: policy.policyHash,
    nullifier: nullifierData.nullifier,
    consumerDataHash,
    expiry: BigInt(input.expiry ?? 0)
  });

  const proofPackage = buildUnlockProofPackageFromAuthorization(authorization);

  return {
    ownerCommitment: publicOwnerCommitment,
    unlockRequest,
    consumerData,
    consumerDataHash,
    policy,
    actionHash,
    nullifier: nullifierData,
    authorization,
    proofPackage,
    digest: authorizationDigest(authorization)
  };
}

export function encodeAuthorizationForContract(
  authorization: BaseActionAuthorization
): readonly unknown[] {
  const normalized = normalizeBaseActionAuthorization(authorization);
  return [
    normalized.consumer,
    normalized.ownerCommitment,
    normalized.actionHash,
    normalized.policyHash,
    normalized.nullifier,
    normalized.consumerDataHash,
    normalized.expiry
  ] as const;
}

export function overrideActionHash(
  assembly: UnlockAuthorizationAssembly,
  actionHashOverride: BytesLike
): UnlockAuthorizationAssembly {
  const authorization = normalizeBaseActionAuthorization({
    ...assembly.authorization,
    actionHash: hexlify(actionHashOverride) as `0x${string}`
  });
  const proofPackage = buildUnlockProofPackageFromAuthorization(authorization, {
    version: assembly.proofPackage.version,
    proofType: assembly.proofPackage.proofType,
    proofBlob: assembly.proofPackage.proofBlob
  });

  return {
    ...assembly,
    actionHash: authorization.actionHash,
    authorization,
    proofPackage,
    digest: authorizationDigest(authorization)
  };
}
