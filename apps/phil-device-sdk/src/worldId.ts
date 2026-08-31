import { hexlify, zeroPadValue, type BytesLike } from "ethers";

import {
  worldSignal,
  worldIdBindingHash,
  type Hex
} from "./hashes.ts";

export const WORLD_ID_PROVIDER = "world-id" as const;
export const PHIL_WORLD_ID_ONBOARDING_ACTION = "phil-human-onboarding-v1" as const;

export type WorldIdVerificationMode =
  | "backend-verified"
  | "offchain-verified"
  | "contract-verified";

export type WorldIdVerificationLevel =
  | "orb"
  | "device";

export interface WorldIdVerificationReceipt {
  provider: typeof WORLD_ID_PROVIDER;
  verificationMode: WorldIdVerificationMode;
  appId: string;
  action: string;
  verificationLevel: WorldIdVerificationLevel;
  signal: Hex;
  nullifierHash: Hex;
  merkleRoot?: Hex;
  proof?: string;
  verifiedAt: number;
  rawPayload?: unknown;
}

export interface PhilHumanVerificationSignal {
  provider: typeof WORLD_ID_PROVIDER;
  storageModel: "offchain";
  status: "verified";
  ownerCommitment: Hex;
  bindingHash: Hex;
  worldId: Omit<WorldIdVerificationReceipt, "rawPayload">;
}

function normalizeBytes32(value: BytesLike): Hex {
  return zeroPadValue(hexlify(value), 32) as Hex;
}

export function buildContextBoundWorldIdSignal(input: {
  ownerCommitment: BytesLike;
  appId: string;
  action?: string;
}): Hex {
  const ownerCommitment = normalizeBytes32(input.ownerCommitment);
  const appId = String(input.appId).trim();
  const action = String(input.action ?? PHIL_WORLD_ID_ONBOARDING_ACTION).trim();

  if (!appId) {
    throw new Error("appId is required");
  }
  if (!action) {
    throw new Error("action is required");
  }

  return worldSignal({
    ownerCommitment,
    appId,
    action
  });
}

export function createWorldIdVerificationReceipt(input: {
  verificationMode?: WorldIdVerificationMode;
  appId: string;
  action?: string;
  verificationLevel?: WorldIdVerificationLevel;
  signal: BytesLike;
  nullifierHash: BytesLike;
  merkleRoot?: BytesLike;
  proof?: string;
  verifiedAt?: number;
  rawPayload?: unknown;
}): WorldIdVerificationReceipt {
  const appId = String(input.appId).trim();
  const action = String(input.action ?? PHIL_WORLD_ID_ONBOARDING_ACTION).trim();
  const signal = normalizeBytes32(input.signal);

  if (!appId) {
    throw new Error("appId is required");
  }
  if (!action) {
    throw new Error("action is required");
  }

  return {
    provider: WORLD_ID_PROVIDER,
    verificationMode: input.verificationMode ?? "backend-verified",
    appId,
    action,
    verificationLevel: input.verificationLevel ?? "orb",
    signal,
    nullifierHash: normalizeBytes32(input.nullifierHash),
    merkleRoot: input.merkleRoot === undefined ? undefined : normalizeBytes32(input.merkleRoot),
    proof: input.proof === undefined ? undefined : String(input.proof),
    verifiedAt: Math.trunc(input.verifiedAt ?? Date.now() / 1000),
    rawPayload: input.rawPayload
  };
}

export function bindWorldIdVerificationToPhilIdentity(input: {
  ownerCommitment: BytesLike;
  receipt: WorldIdVerificationReceipt;
}): PhilHumanVerificationSignal {
  const ownerCommitment = normalizeBytes32(input.ownerCommitment);
  const expectedSignal = buildContextBoundWorldIdSignal({
    ownerCommitment,
    appId: input.receipt.appId,
    action: input.receipt.action
  });

  if (input.receipt.signal !== expectedSignal) {
    throw new Error("World ID signal does not match the ownerCommitment-bound onboarding signal");
  }

  const bindingHash = worldIdBindingHash({
    ownerCommitment,
    signal: input.receipt.signal,
    nullifierHash: input.receipt.nullifierHash,
    appId: input.receipt.appId,
    action: input.receipt.action,
    verificationLevel: input.receipt.verificationLevel
  });

  return {
    provider: WORLD_ID_PROVIDER,
    storageModel: "offchain",
    status: "verified",
    ownerCommitment,
    bindingHash,
    worldId: {
      provider: input.receipt.provider,
      verificationMode: input.receipt.verificationMode,
      appId: input.receipt.appId,
      action: input.receipt.action,
      verificationLevel: input.receipt.verificationLevel,
      signal: input.receipt.signal,
      nullifierHash: input.receipt.nullifierHash,
      merkleRoot: input.receipt.merkleRoot,
      proof: input.receipt.proof,
      verifiedAt: input.receipt.verifiedAt
    }
  };
}

export function buildWorldIdOnboardingRequest(input: {
  ownerCommitment: BytesLike;
  appId: string;
  action?: string;
}) {
  const ownerCommitment = normalizeBytes32(input.ownerCommitment);
  const action = String(input.action ?? PHIL_WORLD_ID_ONBOARDING_ACTION).trim();
  const appId = String(input.appId).trim();

  if (!appId) {
    throw new Error("appId is required");
  }
  if (!action) {
    throw new Error("action is required");
  }

  return {
    provider: WORLD_ID_PROVIDER,
    action,
    appId,
    signal: buildContextBoundWorldIdSignal({
      ownerCommitment,
      appId,
      action
    }),
    ownerCommitment
  };
}
