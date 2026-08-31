"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const { ethers } = require("ethers");
require("tsx/cjs");

const { derivePhilIdentityRoot } = require("../../phil-device-sdk/src/identity.ts");
const { derivePhilScopedOwnerCommitmentV1 } = require("../../phil-device-sdk/src/secureIdentityV1.ts");
const { createPhilRootProofPublicInputsV1 } = require("../../phil-device-sdk/src/rootProofV1.ts");
const mint = require("../../phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const composed = require("../../phil-device-sdk/src/sepoliaMintComposedAuthorizationV1.ts");
const device = require("../../phil-device-sdk/src/deviceApprovalV1.ts");
const wire = require("../../phil-device-sdk/src/p256SignatureWireV2.ts");
const {
  proveNoirRootProofV1,
  resolveNoirRootProofPaths,
  validateNoirRootProofPaths,
  verifyNoirRootProofV1
} = require("../src/main/noir-root-proof-stack.cjs");

function rawSignature(signature) {
  return ethers.concat([ethers.toBeHex(signature.r, 32), ethers.toBeHex(signature.s, 32)]);
}

async function main() {
  const repositoryRoot = path.resolve(__dirname, "../../..");
  const paths = resolveNoirRootProofPaths(repositoryRoot);
  const descriptor = validateNoirRootProofPaths(paths).descriptorDocument.proofDescriptorHash;
  const bindingsInput = {
    factory: "0x1000000000000000000000000000000000000001",
    smartAccount: "0x2000000000000000000000000000000000000002",
    actionGate: "0x3000000000000000000000000000000000000003",
    mintConsumer: "0x4000000000000000000000000000000000000004",
    mintRecipient: "0x5000000000000000000000000000000000000005",
    accountNonce: "0",
    validAfter: "1800000000",
    validUntil: "1800000120",
    maximumTotalFeeWei: "2500000000000000"
  };
  const bindings = mint.derivePhilSepoliaMintBindingsV1(bindingsInput);
  const philSecret = `0x${"07".repeat(32)}`;
  const nullifierSeed = `0x${"08".repeat(32)}`;
  const scopedOwnerCommitment = derivePhilScopedOwnerCommitmentV1({
    identityRoot: derivePhilIdentityRoot(philSecret),
    scopeId: mint.PHIL_SEPOLIA_MINT_SCOPE_ID,
    scopeInstance: bindings.scopeInstance,
    scopeEpoch: "1"
  });
  const authorizationEnvelopeDigest = mint.derivePhilSepoliaMintAuthorizationEnvelopeDigestV1({
    scopedOwnerCommitment,
    proofDescriptorHash: descriptor,
    scopeEpoch: "1",
    deviceEpoch: "1",
    recoveryEpoch: "1",
    validatorEpoch: "1",
    bindings
  });
  const proofPublicInputs = createPhilRootProofPublicInputsV1({
    philSecret,
    nullifierSeed,
    scopeId: mint.PHIL_SEPOLIA_MINT_SCOPE_ID,
    scopeInstance: bindings.scopeInstance,
    scopeEpoch: "1",
    authorizationEnvelopeDigest,
    proofDescriptorHash: descriptor
  });
  assert.equal(proofPublicInputs.scopedOwnerCommitment, scopedOwnerCommitment);
  const proofArtifact = await proveNoirRootProofV1({
    paths,
    philSecret,
    nullifierSeed,
    publicInputs: proofPublicInputs,
    timeoutMs: 120_000
  });
  const native = verifyNoirRootProofV1({
    paths,
    proof: proofArtifact.proof,
    publicInputBytes: proofArtifact.publicInputBytes,
    publicInputs: proofPublicInputs,
    timeoutMs: 120_000
  });
  assert.equal(native.verified, true);

  const authorization = mint.createPhilSepoliaMintAuthorizationV1({
    scopedOwnerCommitment,
    proofDescriptorHash: descriptor,
    rootProofNullifier: proofPublicInputs.rootProofNullifier,
    scopeEpoch: "1",
    deviceEpoch: "1",
    recoveryEpoch: "1",
    validatorEpoch: "1",
    bindings
  });
  assert.equal(authorization.authorizationEnvelopeDigest, authorizationEnvelopeDigest);

  const devicePrivateKey = Buffer.from("43".repeat(32), "hex");
  const devicePublicKey = Buffer.from(p256.getPublicKey(devicePrivateKey, false));
  const enrollment = device.createPhilDeviceEnrollmentRecordV1({
    deviceId: ethers.id("sepolia-noir-composition-device"),
    deviceKeyId: ethers.id("sepolia-noir-composition-device-key"),
    signatureSuiteId: mint.PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
    publicKey: devicePublicKey,
    deviceEpoch: "1",
    enrolledAt: "1799999000",
    assuranceClass: 3,
    policyHash: authorization.authorizationEnvelope.policyHash
  });
  const approvalNonce = ethers.id("sepolia-noir-composition-approval-nonce");
  const approvalDigest = mint.derivePhilSepoliaMintDeviceApprovalDigestV1({
    authorizationEnvelopeDigest,
    deviceId: enrollment.deviceId,
    deviceKeyId: enrollment.deviceKeyId,
    deviceEpoch: enrollment.deviceEpoch,
    approvalNonce,
    approvedAt: "1800000005",
    approvalExpiresAt: "1800000100"
  });
  const approvalSignature = p256.sign(approvalDigest.slice(2), devicePrivateKey, {
    lowS: true,
    prehash: false
  });
  const deviceApproval = device.createPhilDeviceApprovalEvidenceV1({
    authorizationEnvelopeDigest,
    enrollment,
    approvalNonce,
    approvedAt: "1800000005",
    approvalExpiresAt: "1800000100",
    humanPresentationHash: bindings.humanPresentationHash,
    signature: rawSignature(approvalSignature)
  });
  const replay = { envelopes: new Set(), nullifiers: new Set(), approvals: new Set(), nonces: new Set() };
  const release = await composed.authorizePhilSepoliaMintCompositionV1({
    authorization,
    expectedBindings: bindingsInput,
    proofPublicInputs,
    proofArtifact,
    proofVerifier: {
      verifierId: "native-barretenberg-ultra-keccak-zk-honk",
      verify({ proofArtifact: artifact, publicInputs }) {
        return verifyNoirRootProofV1({
          paths,
          proof: artifact.proof,
          publicInputBytes: artifact.publicInputBytes,
          publicInputs,
          timeoutMs: 120_000
        }).verified;
      }
    },
    deviceApproval,
    deviceEnrollment: enrollment,
    deviceVerifier: {
      verifierId: "p256-low-s-native",
      verify({ digest, signature, publicKey }) {
        try {
          wire.decodePhilP256RawSignatureV2(signature);
          return p256.verify(signature.slice(2), digest.slice(2), publicKey.slice(2), {
            lowS: true,
            prehash: false
          });
        } catch { return false; }
      }
    },
    replayStore: {
      hasEnvelopeDigest: (value) => replay.envelopes.has(value),
      hasRootNullifier: (value) => replay.nullifiers.has(value),
      hasDeviceApprovalNonce: (value) => replay.approvals.has(value),
      hasAccountNonce: (value) => replay.nonces.has(value),
      reserve(value) {
        replay.envelopes.add(value.authorizationEnvelopeDigest);
        replay.nullifiers.add(value.rootProofNullifier);
        replay.approvals.add(value.deviceApprovalNonce);
        replay.nonces.add(value.accountNonce);
      }
    },
    trustedState: {
      now: "1800000010",
      scopeEpoch: "1",
      deviceEpoch: "1",
      recoveryEpoch: "1",
      validatorEpoch: "1",
      accountNonce: "0",
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
    }
  });
  assert.equal(release.executionSigningAuthorized, true);
  assert.equal(release.authorizationEnvelopeDigest, authorizationEnvelopeDigest);
  assert.equal(release.rootProofNullifier, proofPublicInputs.rootProofNullifier);
  console.log("ok - Noir proof and P-256 approval compose against one Sepolia mint envelope digest");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
