import type { Hex } from "./hashes.ts";
import {
  assertPhilRootProofPublicInputsBindingV1,
  type PhilRootProofPublicInputsV1
} from "./rootProofV1.ts";
import {
  verifyPhilDeviceApprovalEvidenceV1,
  type PhilDeviceApprovalEvidenceV1,
  type PhilDeviceApprovalSignatureVerifierV1,
  type PhilDeviceEnrollmentRecordV1
} from "./deviceApprovalV1.ts";
import {
  createPhilSepoliaMintAuthorizationV1,
  derivePhilSepoliaMintBindingsV1,
  type PhilSepoliaMintAuthorizationV1
} from "./sepoliaMintAuthorizationV1.ts";

export interface PhilSepoliaMintProofVerifierV1 {
  readonly verifierId: string;
  verify(input: {
    readonly proofArtifact: unknown;
    readonly publicInputs: PhilRootProofPublicInputsV1;
  }): boolean | Promise<boolean>;
}

export interface PhilSepoliaMintReplayStoreV1 {
  hasEnvelopeDigest(value: Hex): boolean | Promise<boolean>;
  hasRootNullifier(value: Hex): boolean | Promise<boolean>;
  hasDeviceApprovalNonce(value: Hex): boolean | Promise<boolean>;
  hasAccountNonce(value: string): boolean | Promise<boolean>;
  reserve(input: {
    readonly authorizationEnvelopeDigest: Hex;
    readonly rootProofNullifier: Hex;
    readonly deviceApprovalNonce: Hex;
    readonly accountNonce: string;
  }): void | Promise<void>;
  hasExactReservation?(input: {
    readonly authorizationEnvelopeDigest: Hex;
    readonly rootProofNullifier: Hex;
    readonly deviceApprovalNonce: Hex;
    readonly accountNonce: string;
  }): boolean | Promise<boolean>;
}

export interface PhilSepoliaMintComposedAuthorizationReleaseV1 {
  readonly authorizationEnvelopeDigest: Hex;
  readonly rootProofNullifier: Hex;
  readonly deviceApprovalNonce: Hex;
  readonly deviceApprovalDigest: Hex;
  readonly accountNonce: string;
  readonly smartAccount: string;
  readonly actionGate: string;
  readonly mintConsumer: string;
  readonly mintRecipient: string;
  readonly validUntil: string;
  readonly maximumTotalFeeWei: string;
  readonly proofVerifierId: string;
  readonly deviceVerifierId: string;
  readonly executionSigningAuthorized: true;
  readonly ethereumVerificationBoundary:
    "restricted_execution_signature_after_local_composed_authorization";
  readonly ethereumVerifiesNoirProof: false;
  readonly ethereumVerifiesP256Approval: false;
}

function fail(code: string): never {
  const error = new Error(code);
  error.name = "PhilSepoliaMintComposedAuthorizationV1Error";
  Object.assign(error, { code });
  throw error;
}

function same(actual: unknown, expected: unknown, code: string): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(code);
}

export async function authorizePhilSepoliaMintCompositionV1(input: {
  readonly authorization: PhilSepoliaMintAuthorizationV1;
  readonly expectedBindings: Parameters<typeof derivePhilSepoliaMintBindingsV1>[0];
  readonly proofPublicInputs: PhilRootProofPublicInputsV1;
  readonly proofArtifact: unknown;
  readonly proofVerifier: PhilSepoliaMintProofVerifierV1;
  readonly deviceApproval: PhilDeviceApprovalEvidenceV1;
  readonly deviceEnrollment: PhilDeviceEnrollmentRecordV1;
  readonly deviceVerifier: PhilDeviceApprovalSignatureVerifierV1;
  readonly replayStore: PhilSepoliaMintReplayStoreV1;
  readonly trustedState: {
    readonly now: string | number | bigint;
    readonly scopeEpoch: string | number | bigint;
    readonly deviceEpoch: string | number | bigint;
    readonly recoveryEpoch: string | number | bigint;
    readonly validatorEpoch: string | number | bigint;
    readonly accountNonce: string | number | bigint;
    readonly valueWei: string | number | bigint;
    readonly maximumTotalFeeWei: string | number | bigint;
    readonly emergencyStop: boolean;
    readonly scopeActive: boolean;
    readonly policyActive: boolean;
    readonly proofDescriptorActive: boolean;
    readonly deviceActive: boolean;
    readonly recoveryStateCurrent: boolean;
    readonly validatorActive: boolean;
    readonly cancelled: boolean;
    readonly denied: boolean;
  };
}): Promise<PhilSepoliaMintComposedAuthorizationReleaseV1> {
  const state = input.trustedState;
  if (
    state.emergencyStop || !state.scopeActive || !state.policyActive
      || !state.proofDescriptorActive || !state.deviceActive
      || !state.recoveryStateCurrent || !state.validatorActive
      || state.cancelled || state.denied
  ) fail("PHIL_SEPOLIA_MINT_AUTHORITY_INACTIVE");

  const expectedBindings = derivePhilSepoliaMintBindingsV1(input.expectedBindings);
  same(input.authorization.bindings, expectedBindings, "PHIL_SEPOLIA_MINT_BINDING_MISMATCH");
  const envelope = input.authorization.authorizationEnvelope;
  const reservation = {
    authorizationEnvelopeDigest: input.authorization.authorizationEnvelopeDigest,
    rootProofNullifier: envelope.rootProofNullifier,
    deviceApprovalNonce: input.deviceApproval.approvalNonce,
    accountNonce: envelope.nonce
  };
  const resumingExactReservation = Boolean(
    input.replayStore.hasExactReservation
      && await input.replayStore.hasExactReservation(reservation)
  );
  const rebuilt = createPhilSepoliaMintAuthorizationV1({
    scopedOwnerCommitment: envelope.scopedOwnerCommitment,
    proofDescriptorHash: envelope.proofDescriptorHash,
    rootProofNullifier: envelope.rootProofNullifier,
    scopeEpoch: state.scopeEpoch,
    deviceEpoch: state.deviceEpoch,
    recoveryEpoch: state.recoveryEpoch,
    validatorEpoch: state.validatorEpoch,
    bindings: expectedBindings
  });
  same(input.authorization, rebuilt, "PHIL_SEPOLIA_MINT_ENVELOPE_MISMATCH");

  const now = BigInt(state.now);
  if (now < BigInt(envelope.validAfter) || now > BigInt(envelope.validUntil)) {
    fail("PHIL_SEPOLIA_MINT_AUTHORIZATION_EXPIRED");
  }
  if (BigInt(state.valueWei) !== 0n || envelope.valueLimit !== "0") {
    fail("PHIL_SEPOLIA_MINT_NONZERO_VALUE_FORBIDDEN");
  }
  if (
    BigInt(state.maximumTotalFeeWei) > BigInt(envelope.feeLimit)
      || BigInt(state.maximumTotalFeeWei) > BigInt(expectedBindings.maximumTotalFeeWei)
  ) fail("PHIL_SEPOLIA_MINT_FEE_LIMIT_EXCEEDED");
  if (BigInt(state.accountNonce).toString() !== envelope.nonce) {
    fail("PHIL_SEPOLIA_MINT_ACCOUNT_NONCE_MISMATCH");
  }

  assertPhilRootProofPublicInputsBindingV1({
    publicInputs: input.proofPublicInputs,
    expected: {
      scopedOwnerCommitment: envelope.scopedOwnerCommitment,
      scopeId: envelope.scopeId,
      scopeInstance: envelope.scopeInstance,
      scopeEpoch: envelope.scopeEpoch,
      authorizationEnvelopeDigest: input.authorization.authorizationEnvelopeDigest,
      rootProofNullifier: envelope.rootProofNullifier,
      proofDescriptorHash: envelope.proofDescriptorHash
    }
  });
  if (!await input.proofVerifier.verify({
    proofArtifact: input.proofArtifact,
    publicInputs: input.proofPublicInputs
  })) fail("PHIL_SEPOLIA_MINT_ROOT_PROOF_INVALID");

  const consumedApprovalNonces = new Set<Hex>();
  if (!resumingExactReservation
      && await input.replayStore.hasDeviceApprovalNonce(input.deviceApproval.approvalNonce)) {
    consumedApprovalNonces.add(input.deviceApproval.approvalNonce);
  }
  const deviceResult = await verifyPhilDeviceApprovalEvidenceV1({
    evidence: input.deviceApproval,
    enrollment: input.deviceEnrollment,
    verifier: input.deviceVerifier,
    expectedAuthorizationEnvelopeDigest: input.authorization.authorizationEnvelopeDigest,
    expectedHumanPresentationHash: envelope.humanPresentationHash,
    currentDeviceEpoch: state.deviceEpoch,
    now: state.now,
    consumedApprovalNonces
  });

  if (!resumingExactReservation
      && await input.replayStore.hasEnvelopeDigest(input.authorization.authorizationEnvelopeDigest)) {
    fail("PHIL_SEPOLIA_MINT_ENVELOPE_REPLAY");
  }
  if (!resumingExactReservation
      && await input.replayStore.hasRootNullifier(envelope.rootProofNullifier)) {
    fail("PHIL_SEPOLIA_MINT_ROOT_NULLIFIER_REPLAY");
  }
  if (!resumingExactReservation
      && await input.replayStore.hasAccountNonce(envelope.nonce)) {
    fail("PHIL_SEPOLIA_MINT_ACCOUNT_NONCE_REPLAY");
  }

  if (!resumingExactReservation) await input.replayStore.reserve(reservation);

  return Object.freeze({
    authorizationEnvelopeDigest: input.authorization.authorizationEnvelopeDigest,
    rootProofNullifier: envelope.rootProofNullifier,
    deviceApprovalNonce: input.deviceApproval.approvalNonce,
    deviceApprovalDigest: deviceResult.deviceApprovalDigest,
    accountNonce: envelope.nonce,
    smartAccount: expectedBindings.smartAccount,
    actionGate: expectedBindings.actionGate,
    mintConsumer: expectedBindings.mintConsumer,
    mintRecipient: expectedBindings.mintRecipient,
    validUntil: envelope.validUntil,
    maximumTotalFeeWei: envelope.feeLimit,
    proofVerifierId: input.proofVerifier.verifierId,
    deviceVerifierId: deviceResult.verifierId,
    executionSigningAuthorized: true as const,
    ethereumVerificationBoundary:
      "restricted_execution_signature_after_local_composed_authorization" as const,
    ethereumVerifiesNoirProof: false as const,
    ethereumVerifiesP256Approval: false as const
  });
}
