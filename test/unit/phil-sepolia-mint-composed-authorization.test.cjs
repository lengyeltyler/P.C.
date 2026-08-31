"use strict";

const assert = require("node:assert/strict");
const { ethers } = require("hardhat");
const { p256 } = require("@noble/curves/p256");
require("tsx/cjs");

const mint = require("../../apps/phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const composed = require("../../apps/phil-device-sdk/src/sepoliaMintComposedAuthorizationV1.ts");
const device = require("../../apps/phil-device-sdk/src/deviceApprovalV1.ts");
const wire = require("../../apps/phil-device-sdk/src/p256SignatureWireV2.ts");

const privateKey = Buffer.from("41".repeat(32), "hex");
const publicKey = Buffer.from(p256.getPublicKey(privateKey, false));
const bindingsInput = Object.freeze({
  factory: "0x1000000000000000000000000000000000000001",
  smartAccount: "0x2000000000000000000000000000000000000002",
  actionGate: "0x3000000000000000000000000000000000000003",
  mintConsumer: "0x4000000000000000000000000000000000000004",
  mintRecipient: "0x5000000000000000000000000000000000000005",
  accountNonce: "7",
  validAfter: "1800000000",
  validUntil: "1800000120",
  maximumTotalFeeWei: "2500000000000000"
});

function rawSignature(signature) {
  return ethers.concat([
    ethers.toBeHex(signature.r, 32),
    ethers.toBeHex(signature.s, 32)
  ]);
}

function replayStore() {
  const envelopes = new Set(), nullifiers = new Set(), approvals = new Set(), nonces = new Set();
  return {
    hasEnvelopeDigest: (value) => envelopes.has(value),
    hasRootNullifier: (value) => nullifiers.has(value),
    hasDeviceApprovalNonce: (value) => approvals.has(value),
    hasAccountNonce: (value) => nonces.has(value),
    reserve(value) {
      if (envelopes.has(value.authorizationEnvelopeDigest)
        || nullifiers.has(value.rootProofNullifier)
        || approvals.has(value.deviceApprovalNonce)
        || nonces.has(value.accountNonce)) throw new Error("REPLAY_STORE_CAS_CONFLICT");
      envelopes.add(value.authorizationEnvelopeDigest);
      nullifiers.add(value.rootProofNullifier);
      approvals.add(value.deviceApprovalNonce);
      nonces.add(value.accountNonce);
    }
  };
}

function build() {
  const bindings = mint.derivePhilSepoliaMintBindingsV1(bindingsInput);
  const rootNullifier = ethers.id("root-nullifier");
  const authorization = mint.createPhilSepoliaMintAuthorizationV1({
    scopedOwnerCommitment: ethers.id("scoped-owner"),
    proofDescriptorHash: ethers.id("noir-descriptor"),
    rootProofNullifier: rootNullifier,
    scopeEpoch: "2",
    deviceEpoch: "3",
    recoveryEpoch: "4",
    validatorEpoch: "5",
    bindings
  });
  const enrollment = device.createPhilDeviceEnrollmentRecordV1({
    deviceId: ethers.id("device"),
    deviceKeyId: ethers.id("device-key"),
    signatureSuiteId: mint.PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
    publicKey,
    deviceEpoch: "3",
    enrolledAt: "1799999000",
    assuranceClass: 3,
    policyHash: authorization.authorizationEnvelope.policyHash
  });
  const approvalNonce = ethers.id("approval-nonce");
  const approvalDigest = mint.derivePhilSepoliaMintDeviceApprovalDigestV1({
    authorizationEnvelopeDigest: authorization.authorizationEnvelopeDigest,
    deviceId: enrollment.deviceId,
    deviceKeyId: enrollment.deviceKeyId,
    deviceEpoch: enrollment.deviceEpoch,
    approvalNonce,
    approvedAt: "1800000005",
    approvalExpiresAt: "1800000100"
  });
  const signature = p256.sign(approvalDigest.slice(2), privateKey, { lowS: true, prehash: false });
  const approval = device.createPhilDeviceApprovalEvidenceV1({
    authorizationEnvelopeDigest: authorization.authorizationEnvelopeDigest,
    enrollment,
    approvalNonce,
    approvedAt: "1800000005",
    approvalExpiresAt: "1800000100",
    humanPresentationHash: bindings.humanPresentationHash,
    signature: rawSignature(signature)
  });
  const proofPublicInputs = {
    scopedOwnerCommitment: authorization.authorizationEnvelope.scopedOwnerCommitment,
    scopeId: authorization.authorizationEnvelope.scopeId,
    scopeInstance: authorization.authorizationEnvelope.scopeInstance,
    scopeEpoch: authorization.authorizationEnvelope.scopeEpoch,
    authorizationEnvelopeDigest: authorization.authorizationEnvelopeDigest,
    rootProofNullifier: rootNullifier,
    proofDescriptorHash: authorization.authorizationEnvelope.proofDescriptorHash
  };
  const proofVerifier = {
    verifierId: "noir-native-test-verifier",
    verify: ({ proofArtifact }) => proofArtifact === "valid-noir-proof"
  };
  const deviceVerifier = {
    verifierId: "p256-low-s-test-verifier",
    verify({ digest, signature: inputSignature, publicKey: inputPublicKey }) {
      try {
        wire.decodePhilP256RawSignatureV2(inputSignature);
        return p256.verify(inputSignature.slice(2), digest.slice(2), inputPublicKey.slice(2), {
          lowS: true,
          prehash: false
        });
      } catch {
        return false;
      }
    }
  };
  const trustedState = {
    now: "1800000010",
    scopeEpoch: "2",
    deviceEpoch: "3",
    recoveryEpoch: "4",
    validatorEpoch: "5",
    accountNonce: "7",
    valueWei: "0",
    maximumTotalFeeWei: bindings.maximumTotalFeeWei,
    emergencyStop: false,
    scopeActive: true,
    policyActive: true,
    proofDescriptorActive: true,
    deviceActive: true,
    recoveryStateCurrent: true,
    validatorActive: true,
    cancelled: false,
    denied: false
  };
  return {
    authorization,
    expectedBindings: bindingsInput,
    proofPublicInputs,
    proofArtifact: "valid-noir-proof",
    proofVerifier,
    deviceApproval: approval,
    deviceEnrollment: enrollment,
    deviceVerifier,
    replayStore: replayStore(),
    trustedState
  };
}

describe("Phil Sepolia mint local composed authorization", function () {
  it("releases execution signing only after proof, device, policy, and replay checks pass", async function () {
    const input = build();
    const release = await composed.authorizePhilSepoliaMintCompositionV1(input);
    assert.equal(release.executionSigningAuthorized, true);
    assert.equal(release.authorizationEnvelopeDigest, input.authorization.authorizationEnvelopeDigest);
    assert.equal(release.rootProofNullifier, input.proofPublicInputs.rootProofNullifier);
    assert.equal(release.deviceApprovalNonce, input.deviceApproval.approvalNonce);
    assert.equal(release.ethereumVerifiesNoirProof, false);
    assert.equal(release.ethereumVerifiesP256Approval, false);
    assert.equal(
      release.ethereumVerificationBoundary,
      "restricted_execution_signature_after_local_composed_authorization"
    );
    await assert.rejects(
      composed.authorizePhilSepoliaMintCompositionV1(input),
      (error) => error.code === "PHIL_DEVICE_APPROVAL_REPLAY"
    );
  });

  it("fails closed for proof, device, key, binding, time, fee, value, epoch, policy, and nonce mutations", async function () {
    const cases = [
      ["wrong proof", (value) => { value.proofArtifact = "wrong-proof"; }],
      ["proof digest", (value) => { value.proofPublicInputs = { ...value.proofPublicInputs, authorizationEnvelopeDigest: ethers.id("wrong") }; }],
      ["root nullifier", (value) => { value.proofPublicInputs = { ...value.proofPublicInputs, rootProofNullifier: ethers.id("wrong-nullifier") }; }],
      ["recipient", (value) => { value.expectedBindings = { ...value.expectedBindings, mintRecipient: "0x5000000000000000000000000000000000000006" }; }],
      ["account", (value) => { value.expectedBindings = { ...value.expectedBindings, smartAccount: "0x2000000000000000000000000000000000000006" }; }],
      ["expired", (value) => { value.trustedState = { ...value.trustedState, now: "1800000121" }; }],
      ["fee", (value) => { value.trustedState = { ...value.trustedState, maximumTotalFeeWei: "2500000000000001" }; }],
      ["value", (value) => { value.trustedState = { ...value.trustedState, valueWei: "1" }; }],
      ["nonce", (value) => { value.trustedState = { ...value.trustedState, accountNonce: "8" }; }],
      ["device epoch", (value) => { value.trustedState = { ...value.trustedState, deviceEpoch: "4" }; }],
      ["recovery epoch", (value) => { value.trustedState = { ...value.trustedState, recoveryEpoch: "5" }; }],
      ["validator epoch", (value) => { value.trustedState = { ...value.trustedState, validatorEpoch: "6" }; }],
      ["emergency", (value) => { value.trustedState = { ...value.trustedState, emergencyStop: true }; }],
      ["cancelled", (value) => { value.trustedState = { ...value.trustedState, cancelled: true }; }],
      ["denied", (value) => { value.trustedState = { ...value.trustedState, denied: true }; }],
      ["wrong key", (value) => {
        const otherKey = Buffer.from("42".repeat(32), "hex");
        value.deviceEnrollment = { ...value.deviceEnrollment, publicKey: ethers.hexlify(p256.getPublicKey(otherKey, false)) };
      }]
    ];
    for (const [label, mutate] of cases) {
      const input = build();
      mutate(input);
      await assert.rejects(
        composed.authorizePhilSepoliaMintCompositionV1(input),
        undefined,
        label
      );
    }
  });

  it("rejects a high-S P-256 approval", async function () {
    const input = build();
    const low = wire.decodePhilP256RawSignatureV2(input.deviceApproval.signature);
    const highS = p256.CURVE.n - BigInt(low.s);
    input.deviceApproval = {
      ...input.deviceApproval,
      signature: ethers.concat([low.r, ethers.toBeHex(highS, 32)])
    };
    await assert.rejects(
      composed.authorizePhilSepoliaMintCompositionV1(input),
      (error) => error.code === "PHIL_DEVICE_APPROVAL_SIGNATURE_INVALID"
    );
  });
});
