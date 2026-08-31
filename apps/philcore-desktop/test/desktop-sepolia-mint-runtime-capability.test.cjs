"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const { ethers } = require("ethers");
require("tsx/cjs");

const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");
const { createSepoliaMintReplayStore } = require("../src/main/sepolia-mint-replay-store.cjs");
const mint = require("../../phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const device = require("../../phil-device-sdk/src/deviceApprovalV1.ts");
const requestApi = require("../../phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts");

async function main() {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "phil-sepolia-runtime-capability-"));
  try {
    const host = createDesktopRuntimeHost({
      preferencesPath: path.join(temporary, "preferences.json"),
      identityStorageRoot: path.join(temporary, "identities"),
      platformKeyAdapter: createFixturePlatformKeyAdapter()
    });
    await assert.rejects(
      host._createSepoliaMintComposedCapability({}),
      /capability_input_invalid/u
    );
    const passphrase = "Sepolia-runtime-capability!123";
    host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
      label: "Sepolia capability test",
      passphrase,
      createRecoveryAuthority: true
    });
    host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase });
    assert.equal(host.invoke(CHANNELS.UNLOCK_VAULT, {}).status, "unlocked");
    const snapshot = host.snapshot();
    const devicePrivateKey = Buffer.from("43".repeat(32), "hex");
    const enrollment = device.createPhilDeviceEnrollmentRecordV1({
      deviceId: ethers.id("runtime-capability-device"),
      deviceKeyId: ethers.id("runtime-capability-device-key"),
      signatureSuiteId: mint.PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
      publicKey: p256.getPublicKey(devicePrivateKey, false),
      deviceEpoch: "1",
      enrolledAt: "1",
      assuranceClass: 3,
      policyHash: ethers.id("runtime-capability-device-policy")
    });
    const bindingsInput = {
      factory: "0x1000000000000000000000000000000000000001",
      smartAccount: "0x2000000000000000000000000000000000000002",
      actionGate: "0x3000000000000000000000000000000000000003",
      mintConsumer: "0x4000000000000000000000000000000000000004",
      mintRecipient: "0x2000000000000000000000000000000000000002",
      accountNonce: "0",
      validAfter: "1800000000",
      validUntil: "1800000900",
      maximumTotalFeeWei: "2500000000000000"
    };
    const replayStore = createSepoliaMintReplayStore({
      ledgerPath: path.join(temporary, "replay.json"),
      now: () => "2026-08-24T23:00:00.000Z"
    });
    const capability = await host._createSepoliaMintComposedCapability({
      repositoryRoot: path.resolve(__dirname, "../../.."),
      bindingsInput,
      epochs: { scopeEpoch: "1", deviceEpoch: "1", recoveryEpoch: "1", validatorEpoch: "1" },
      enrollment,
      accountSalt: "9",
      accountDeployed: false,
      gas: {
        callGasLimit: "180000",
        verificationGasLimit: "500000",
        preVerificationGas: "90000",
        maxFeePerGas: "2000000000",
        maxPriorityFeePerGas: "1000000000"
      },
      replayStore,
      trustedStateFactory: async () => ({
        now: "1800000010",
        scopeEpoch: "1",
        deviceEpoch: "1",
        recoveryEpoch: "1",
        validatorEpoch: "1",
        accountNonce: "0",
        valueWei: "0",
        maximumTotalFeeWei: bindingsInput.maximumTotalFeeWei,
        emergencyStop: false,
        scopeActive: true,
        policyActive: true,
        proofDescriptorActive: true,
        deviceActive: true,
        recoveryStateCurrent: true,
        validatorActive: true,
        cancelled: false,
        denied: false
      }),
      dependencies: {
        randomBytes: () => Buffer.from("08".repeat(32), "hex"),
        proveNoirRootProofV1: async () => ({ proof: "0x1234", publicInputBytes: "0x5678" }),
        verifyNoirRootProofV1: () => ({ verified: true })
      }
    });
    assert.equal(capability.executionOwner, snapshot.ethereum.executionOwnerAddress);
    assert.equal(capability.ownerCommitment, snapshot.identity.ownerCommitment);
    assert.equal(capability.publicNetworkMutation, false);
    const ceremony = capability.requestFactory({
      sessionId: ethers.id("runtime-capability-session"),
      approvalNonce: ethers.id("runtime-capability-approval"),
      now: "1800000005"
    });
    const approval = p256.sign(
      ceremony.request.deviceApprovalDigest.slice(2),
      devicePrivateKey,
      { lowS: true, prehash: false }
    );
    const response = requestApi.createPhilSepoliaMintDeviceResponseV1({
      request: ceremony.request,
      enrollment,
      signature: ethers.concat([
        ethers.toBeHex(approval.r, 32),
        ethers.toBeHex(approval.s, 32)
      ])
    });
    const signed = await capability.onApproved({
      request: ceremony.request,
      response,
      context: ceremony.context
    });
    assert.equal(signed.signed, true);
    assert.equal(signed.submitted, false);
    assert.equal(
      ethers.verifyMessage(ethers.getBytes(signed.userOperationHash), signed.userOperation.signature),
      snapshot.ethereum.executionOwnerAddress
    );
    assert.equal(replayStore.snapshot().count, 1);
    const resumed = await capability.onApproved({
      request: ceremony.request,
      response,
      context: ceremony.context
    });
    assert.equal(resumed.userOperationHash, signed.userOperationHash);
    assert.deepEqual(resumed.userOperation, signed.userOperation);
    replayStore.markConsumed(signed);
    await assert.rejects(
      capability.onApproved({ request: ceremony.request, response, context: ceremony.context }),
      (error) => ["PHIL_DEVICE_APPROVAL_REPLAY", "PHIL_SEPOLIA_MINT_ENVELOPE_REPLAY"]
        .includes(error.code)
    );
    host.invoke(CHANNELS.LOCK_SESSION, {});
    await assert.rejects(
      capability.onApproved({ request: ceremony.request, response, context: ceremony.context }),
      /signing_authority_invalidated/u
    );
    process.stdout.write("ok - Desktop runtime keeps Phil and Device Vault authority process-local through composed Sepolia signing\n");
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exitCode = 1;
});
