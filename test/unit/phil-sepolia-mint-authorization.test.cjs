"use strict";

const assert = require("node:assert/strict");
const { ethers } = require("hardhat");
require("tsx/cjs");

const mint = require("../../apps/phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");

const addresses = {
  factory: "0x1000000000000000000000000000000000000001",
  smartAccount: "0x2000000000000000000000000000000000000002",
  actionGate: "0x3000000000000000000000000000000000000003",
  mintConsumer: "0x4000000000000000000000000000000000000004",
  mintRecipient: "0x5000000000000000000000000000000000000005"
};

function bindingInput(overrides = {}) {
  return {
    ...addresses,
    accountNonce: "0",
    validAfter: "1800000000",
    validUntil: "1800000120",
    maximumTotalFeeWei: "2500000000000000",
    ...overrides
  };
}

function envelopeInput(bindings, overrides = {}) {
  return {
    scopedOwnerCommitment: ethers.id("scoped-owner"),
    proofDescriptorHash: ethers.id("noir-proof-descriptor"),
    scopeEpoch: "1",
    deviceEpoch: "3",
    recoveryEpoch: "4",
    validatorEpoch: "5",
    bindings,
    ...overrides
  };
}

describe("canonical Phil Sepolia mint authorization", function () {
  it("binds every displayed mint field to one exceptional envelope digest", function () {
    const bindings = mint.derivePhilSepoliaMintBindingsV1(bindingInput());
    const baseline = mint.derivePhilSepoliaMintAuthorizationEnvelopeDigestV1(
      envelopeInput(bindings)
    );
    assert.match(baseline, /^0x[0-9a-f]{64}$/u);
    assert.equal(bindings.chainId, "11155111");
    assert.equal(bindings.entryPoint, mint.PHIL_ETHEREUM_ENTRYPOINT_V07);

    const mutations = [
      { factory: "0x1000000000000000000000000000000000000009" },
      { smartAccount: "0x2000000000000000000000000000000000000009" },
      { actionGate: "0x3000000000000000000000000000000000000009" },
      { mintConsumer: "0x4000000000000000000000000000000000000009" },
      { mintRecipient: "0x5000000000000000000000000000000000000009" },
      { accountNonce: "1" },
      { validAfter: "1800000001" },
      { validUntil: "1800000119" },
      { maximumTotalFeeWei: "2499999999999999" }
    ];
    for (const mutation of mutations) {
      const changedBindings = mint.derivePhilSepoliaMintBindingsV1(
        bindingInput(mutation)
      );
      const changed = mint.derivePhilSepoliaMintAuthorizationEnvelopeDigestV1(
        envelopeInput(changedBindings)
      );
      assert.notEqual(changed, baseline, JSON.stringify(mutation));
    }

    for (const mutation of [
      { scopedOwnerCommitment: ethers.id("other-owner") },
      { proofDescriptorHash: ethers.id("other-descriptor") },
      { scopeEpoch: "2" },
      { deviceEpoch: "4" },
      { recoveryEpoch: "5" },
      { validatorEpoch: "6" }
    ]) {
      const changed = mint.derivePhilSepoliaMintAuthorizationEnvelopeDigestV1(
        envelopeInput(bindings, mutation)
      );
      assert.notEqual(changed, baseline, JSON.stringify(mutation));
    }
  });

  it("finalizes the proof nullifier without changing the pre-proof digest", function () {
    const bindings = mint.derivePhilSepoliaMintBindingsV1(bindingInput());
    const pending = mint.derivePhilSepoliaMintAuthorizationEnvelopeDigestV1(
      envelopeInput(bindings)
    );
    const first = mint.createPhilSepoliaMintAuthorizationV1({
      ...envelopeInput(bindings),
      rootProofNullifier: ethers.id("root-nullifier-one")
    });
    const second = mint.createPhilSepoliaMintAuthorizationV1({
      ...envelopeInput(bindings),
      rootProofNullifier: ethers.id("root-nullifier-two")
    });
    assert.equal(first.authorizationEnvelopeDigest, pending);
    assert.equal(second.authorizationEnvelopeDigest, pending);
    assert.notEqual(
      first.authorizationEnvelope.rootProofNullifier,
      second.authorizationEnvelope.rootProofNullifier
    );
  });

  it("binds device identity, epoch, nonce, and time to the same envelope", function () {
    const bindings = mint.derivePhilSepoliaMintBindingsV1(bindingInput());
    const authorizationEnvelopeDigest = mint.derivePhilSepoliaMintAuthorizationEnvelopeDigestV1(
      envelopeInput(bindings)
    );
    const input = {
      authorizationEnvelopeDigest,
      deviceId: ethers.id("device"),
      deviceKeyId: ethers.id("device-key"),
      deviceEpoch: "3",
      approvalNonce: ethers.id("approval-nonce"),
      approvedAt: "1800000001",
      approvalExpiresAt: "1800000100"
    };
    const baseline = mint.derivePhilSepoliaMintDeviceApprovalDigestV1(input);
    for (const mutation of [
      { authorizationEnvelopeDigest: ethers.id("other-envelope") },
      { deviceId: ethers.id("other-device") },
      { deviceKeyId: ethers.id("other-key") },
      { deviceEpoch: "4" },
      { approvalNonce: ethers.id("other-approval") },
      { approvedAt: "1800000002" },
      { approvalExpiresAt: "1800000099" }
    ]) {
      assert.notEqual(
        mint.derivePhilSepoliaMintDeviceApprovalDigestV1({ ...input, ...mutation }),
        baseline,
        JSON.stringify(mutation)
      );
    }
  });
});
