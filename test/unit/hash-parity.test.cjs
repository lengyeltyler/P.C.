const assert = require("node:assert/strict");

const { ethers } = require("hardhat");

const { dataHash } = require("../../apps/phil-device-sdk/src/hashes.ts");
const {
  buildLegacyOwnerCommitmentFromAddressSalt
} = require("../../apps/phil-device-sdk/src/commitments.ts");
const {
  generatePhilSecret,
  deriveOwnerCommitmentFromPhilSecret,
  derivePhilIdentityRoot
} = require("../../apps/phil-device-sdk/src/identity.ts");
const {
  assembleUnlockAuthorizationPayload
} = require("../../apps/phil-device-sdk/src/authorization.ts");
const { deployContract } = require("../helpers/context.cjs");

describe("Hash parity", function () {
  it("matches between the TypeScript SDK and Solidity helpers for the Base-native path", async function () {
    const [deployer, user] = await ethers.getSigners();
    const { chainId } = await ethers.provider.getNetwork();

    const gate = await deployContract(deployer, "PhilBaseActionGate", [ethers.ZeroAddress]);
    const consumer = await deployContract(deployer, "PhilUnlockConsumer", [await gate.getAddress()]);
    const harness = await deployContract(deployer, "PhilHashHarness");

    const callData = "0x11223344";
    const philSecret = generatePhilSecret();
    const ownerSalt = ethers.id("parity-owner-salt");
    const nullifierSeed = ethers.id("parity-nullifier-seed");
    const policyData = "0x5566";

    const assembly = assembleUnlockAuthorizationPayload({
      chainId,
      consumer: await consumer.getAddress(),
      philSecret,
      account: user.address,
      target: ethers.Wallet.createRandom().address,
      callData,
      policyData,
      nullifierSeed
    });

    assert.equal(
      await harness.computeLegacyOwnerCommitment(user.address, ownerSalt),
      buildLegacyOwnerCommitmentFromAddressSalt({
        legacyOwner: user.address,
        legacyOwnerSalt: ownerSalt
      }).ownerCommitment
    );
    assert.equal(await harness.computeIdentityRoot(philSecret), derivePhilIdentityRoot(philSecret));
    assert.equal(
      await harness.computeCanonicalOwnerCommitment(derivePhilIdentityRoot(philSecret)),
      deriveOwnerCommitmentFromPhilSecret(philSecret)
    );
    assert.equal(
      await harness.computeUnlockActionHash(
        chainId,
        await consumer.getAddress(),
        user.address,
        assembly.unlockRequest.target,
        0n,
        dataHash(callData)
      ),
      assembly.actionHash
    );
    assert.equal(
      await harness.computePolicyHash(
        chainId,
        await consumer.getAddress(),
        assembly.policy.target,
        0n,
        dataHash(policyData)
      ),
      assembly.policy.policyHash
    );
    assert.equal(
      await harness.computeNullifier(
        assembly.ownerCommitment.ownerCommitment,
        assembly.actionHash,
        assembly.policy.policyHash,
        nullifierSeed
      ),
      assembly.nullifier.nullifier
    );
    assert.equal(
      await harness.computeAuthorizationDigest(assembly.authorization),
      assembly.digest
    );
    assert.equal(
      await gate.computeAuthorizationDigest(assembly.authorization),
      assembly.digest
    );
    assert.equal(
      await harness.computeUnlockProofInputHash(assembly.proofPackage),
      assembly.proofPackage.proofInputHash
    );
    assert.equal(
      await gate.computeProofInputHash(assembly.proofPackage),
      assembly.proofPackage.proofInputHash
    );
  });
});
