"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ethers } = require("hardhat");
require("tsx/cjs");

const mint = require("../../apps/phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const operation = require("../../apps/phil-device-sdk/src/sepoliaMintUserOperationV1.ts");
const { createSepoliaMintReplayStore } = require(
  "../../apps/philcore-desktop/src/main/sepolia-mint-replay-store.cjs"
);

const owner = new ethers.Wallet(`0x${"61".repeat(32)}`);
const ownerCommitment = ethers.id("sepolia-mint-owner-commitment");
const bindings = mint.derivePhilSepoliaMintBindingsV1({
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
const authorization = mint.createPhilSepoliaMintAuthorizationV1({
  scopedOwnerCommitment: ownerCommitment,
  proofDescriptorHash: ethers.id("noir-proof-descriptor"),
  rootProofNullifier: ethers.id("root-nullifier"),
  scopeEpoch: "2",
  deviceEpoch: "3",
  recoveryEpoch: "4",
  validatorEpoch: "5",
  bindings
});
const release = Object.freeze({
  authorizationEnvelopeDigest: authorization.authorizationEnvelopeDigest,
  rootProofNullifier: authorization.authorizationEnvelope.rootProofNullifier,
  deviceApprovalNonce: ethers.id("device-approval-nonce"),
  deviceApprovalDigest: ethers.id("device-approval-digest"),
  accountNonce: bindings.accountNonce,
  smartAccount: bindings.smartAccount,
  actionGate: bindings.actionGate,
  mintConsumer: bindings.mintConsumer,
  mintRecipient: bindings.mintRecipient,
  validUntil: bindings.validUntil,
  maximumTotalFeeWei: bindings.maximumTotalFeeWei,
  proofVerifierId: "noir-native-test-verifier",
  deviceVerifierId: "p256-low-s-test-verifier",
  executionSigningAuthorized: true,
  ethereumVerificationBoundary: "restricted_execution_signature_after_local_composed_authorization",
  ethereumVerifiesNoirProof: false,
  ethereumVerifiesP256Approval: false
});
const gas = Object.freeze({
  callGasLimit: "180000",
  verificationGasLimit: "500000",
  preVerificationGas: "90000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000"
});

function signer(callCounter) {
  const descriptor = Object.freeze({
    signerId: "device-vault-sepolia-mint-test",
    mode: "device_vault_beta_ecdsa",
    ownerAddress: owner.address,
    keyReference: Object.freeze({
      keyReferenceId: "encrypted-test-key-reference",
      mode: "device_vault_beta_ecdsa",
      custody: "device_vault_encrypted",
      privateKeyExportable: false,
      derivedFromPhilSecret: false
    }),
    available: true,
    productionApproved: false,
    arbitraryMessageSigning: false,
    arbitraryTransactionSigning: false
  });
  return {
    describeSigner: async () => descriptor,
    checkAvailability: async () => descriptor,
    getOwnerAddress: async () => owner.address,
    async signUserOperationHash(request) {
      callCounter.count += 1;
      return {
        status: "signed",
        signature: await owner.signMessage(ethers.getBytes(request.userOperationHash)),
        signerDescriptor: descriptor,
        signedAt: "2026-08-24T22:00:00.000Z"
      };
    }
  };
}

function prepared(overrides = {}) {
  return operation.preparePhilSepoliaMintUserOperationV1({
    authorization,
    release,
    executionOwner: owner.address,
    ownerCommitment,
    accountSalt: "9",
    accountDeployed: false,
    gas,
    ...overrides
  });
}

describe("Phil Sepolia mint UserOperation release and Device Vault signing", function () {
  it("builds the exact zero-value v0.7 operation and signs only after durable reservation read-back", async function () {
    const draft = prepared();
    assert.equal(draft.userOperation.sender, bindings.smartAccount);
    assert.equal(draft.userOperation.nonce, bindings.accountNonce);
    assert.equal(draft.userOperation.paymasterAndData, "0x");
    assert.equal(draft.userOperation.signature, "0x");
    assert.equal(draft.userOperation.initCode.slice(0, 42), bindings.factory);
    assert.ok(BigInt(draft.maximumTotalFeeWei) <= BigInt(bindings.maximumTotalFeeWei));

    const root = fs.mkdtempSync(path.join(os.tmpdir(), "phil-sepolia-signing-release-"));
    try {
      const replayStore = createSepoliaMintReplayStore({
        ledgerPath: path.join(root, "replay.json"),
        now: () => "2026-08-24T22:00:00.000Z"
      });
      const calls = { count: 0 };
      await assert.rejects(
        operation.signPhilSepoliaMintUserOperationV1({
          authorization, release, prepared: draft, replayStore, signer: signer(calls)
        }),
        (error) => error.code === "PHIL_SEPOLIA_MINT_DURABLE_RESERVATION_REQUIRED"
      );
      assert.equal(calls.count, 0, "Device Vault must not be called before durable reserve");

      replayStore.reserve({
        authorizationEnvelopeDigest: release.authorizationEnvelopeDigest,
        rootProofNullifier: release.rootProofNullifier,
        deviceApprovalNonce: release.deviceApprovalNonce,
        accountNonce: release.accountNonce
      });
      const signed = await operation.signPhilSepoliaMintUserOperationV1({
        authorization, release, prepared: draft, replayStore, signer: signer(calls)
      });
      assert.equal(calls.count, 1);
      assert.equal(signed.signed, true);
      assert.equal(signed.submitted, false);
      assert.equal(
        ethers.verifyMessage(ethers.getBytes(signed.userOperationHash), signed.userOperation.signature),
        owner.address
      );
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects fee overflow and every post-release operation mutation before signing", async function () {
    assert.throws(
      () => prepared({ gas: { ...gas, maxFeePerGas: bindings.maximumTotalFeeWei } }),
      (error) => error.code === "PHIL_SEPOLIA_MINT_USER_OPERATION_FEE_LIMIT_EXCEEDED"
    );
    const draft = prepared();
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "phil-sepolia-signing-mutation-"));
    try {
      const replayStore = createSepoliaMintReplayStore({
        ledgerPath: path.join(root, "replay.json"),
        now: () => "2026-08-24T22:00:00.000Z"
      });
      replayStore.reserve({
        authorizationEnvelopeDigest: release.authorizationEnvelopeDigest,
        rootProofNullifier: release.rootProofNullifier,
        deviceApprovalNonce: release.deviceApprovalNonce,
        accountNonce: release.accountNonce
      });
      for (const [label, mutated] of [
        ["nonce", { ...draft, userOperation: { ...draft.userOperation, nonce: "8" } }],
        ["call data", { ...draft, userOperation: { ...draft.userOperation, callData: "0x12345678" } }],
        ["factory", { ...draft, userOperation: { ...draft.userOperation, initCode: "0x" } }],
        ["gas", { ...draft, userOperation: { ...draft.userOperation, preVerificationGas: "90001" } }]
      ]) {
        const calls = { count: 0 };
        await assert.rejects(
          operation.signPhilSepoliaMintUserOperationV1({
            authorization, release, prepared: mutated, replayStore, signer: signer(calls)
          }),
          (error) => error.code === "PHIL_SEPOLIA_MINT_USER_OPERATION_HASH_MISMATCH",
          label
        );
        assert.equal(calls.count, 0, label);
      }
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});
