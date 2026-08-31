const assert = require("node:assert/strict");

const { ethers } = require("hardhat");

const {
  buildUnlockKeccakFixtureVector,
  encodeIdentityRootPreimage,
  encodeNullifierPreimage,
  encodeOwnerCommitmentPreimage,
  encodeUnlockProofInputPreimage
} = require("../../apps/phil-device-sdk/src/proof/stwo/abi.ts");
const {
  STWO_UNLOCK_ARTIFACT_VERSION,
  STWO_UNLOCK_PROOF_TYPE,
  STWO_UNLOCK_PROOF_VERSION,
  STWO_UNLOCK_VERIFIER_KEY_ID
} = require("../../apps/phil-device-sdk/src/proof/stwo/constants.ts");
const { DOMAIN_HASHES, proofInputHash } = require("../../apps/phil-device-sdk/src/hashes.ts");
const { deployContract } = require("../helpers/context.cjs");

const GOLDEN_VECTOR = {
  version: "v1",
  proofType: "stwo-unlock-keccak-v1",
  philSecret: "0x0000000000000000000000000000000000000000000000000000000000123456",
  actionHash: ethers.id("phase3.4-action"),
  policyHash: ethers.id("phase3.4-policy"),
  nullifierSeed: "0x0000000000000000000000000000000000000000000000000000000000abcdef",
  consumerDataHash: ethers.id("phase3.4-consumer-data"),
  expiry: 1900000000n,
  identityRootPreimage: "0xadf25d12ac1774736834c011d2ffda2f32944194f2e18f5ec760c9b4b4ea693e0000000000000000000000000000000000000000000000000000000000123456",
  identityRootHash: "0xb94cc4af433e43dcb42f177387a71c630d51f656b44d3e162ad4984fb7d25894",
  ownerCommitmentPreimage: "0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4eb94cc4af433e43dcb42f177387a71c630d51f656b44d3e162ad4984fb7d25894",
  ownerCommitmentHash: "0xeabc46426af38005e06573556996c697727a37a4dee2facade7ee6b21f34f7f6",
  nullifierPreimage: "0xa00fb767a066eaea6c0b7b3ef589b5ed73640b96a6530130e6fe85cafc53f391eabc46426af38005e06573556996c697727a37a4dee2facade7ee6b21f34f7f6d5d0b728949459873e285251af92184e4697ce9fef42838314e021c76837981cc427bdc4dc8a7e133577265d90328a2a3678cd85d354d9f49acf2ec72d8934760000000000000000000000000000000000000000000000000000000000abcdef",
  nullifierHash: "0x98babeb39173de519d32e7f5c9f9212cc992b4ce34c28f85978ba0af093a4f06",
  proofInputHashPreimage: "0xca19fffd16bff6d359d87d9658fa988e1ecca206885433cc3bb57113222e820c00000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000160eabc46426af38005e06573556996c697727a37a4dee2facade7ee6b21f34f7f6d5d0b728949459873e285251af92184e4697ce9fef42838314e021c76837981cc427bdc4dc8a7e133577265d90328a2a3678cd85d354d9f49acf2ec72d89347698babeb39173de519d32e7f5c9f9212cc992b4ce34c28f85978ba0af093a4f062083576b1bd13af43e74b048befa382eb9b540dcc1bb952b4c0b3133aebd10e100000000000000000000000000000000000000000000000000000000713fb3000000000000000000000000000000000000000000000000000000000000000002763100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000157374776f2d756e6c6f636b2d6b656363616b2d76310000000000000000000000",
  proofInputHashValue: "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2"
};

describe("Phase 3.4 S-two ABI fixtures", function () {
  it("locks the proof constants and envelope metadata", function () {
    assert.equal(STWO_UNLOCK_PROOF_VERSION, "v1");
    assert.equal(STWO_UNLOCK_PROOF_TYPE, "stwo-unlock-keccak-v1");
    assert.equal(STWO_UNLOCK_ARTIFACT_VERSION, "phil-s2-proof-envelope-v1");
    assert.match(STWO_UNLOCK_VERIFIER_KEY_ID, /^0x[0-9a-f]{64}$/);
  });

  it("produces the exact ABI preimages and golden hashes", function () {
    const vector = buildUnlockKeccakFixtureVector({
      philSecret: GOLDEN_VECTOR.philSecret,
      actionHash: GOLDEN_VECTOR.actionHash,
      policyHash: GOLDEN_VECTOR.policyHash,
      nullifierSeed: GOLDEN_VECTOR.nullifierSeed,
      consumerDataHash: GOLDEN_VECTOR.consumerDataHash,
      expiry: GOLDEN_VECTOR.expiry,
      version: GOLDEN_VECTOR.version,
      proofType: GOLDEN_VECTOR.proofType
    });

    assert.equal(encodeIdentityRootPreimage(GOLDEN_VECTOR.philSecret), GOLDEN_VECTOR.identityRootPreimage);
    assert.equal(encodeOwnerCommitmentPreimage(GOLDEN_VECTOR.identityRootHash), GOLDEN_VECTOR.ownerCommitmentPreimage);
    assert.equal(
      encodeNullifierPreimage({
        ownerCommitment: GOLDEN_VECTOR.ownerCommitmentHash,
        actionHash: GOLDEN_VECTOR.actionHash,
        policyHash: GOLDEN_VECTOR.policyHash,
        nullifierSeed: GOLDEN_VECTOR.nullifierSeed
      }),
      GOLDEN_VECTOR.nullifierPreimage
    );
    assert.equal(
      encodeUnlockProofInputPreimage({
        version: GOLDEN_VECTOR.version,
        proofType: GOLDEN_VECTOR.proofType,
        publicInputs: vector.publicInputs
      }),
      GOLDEN_VECTOR.proofInputHashPreimage
    );

    assert.equal(vector.identityRootHash, GOLDEN_VECTOR.identityRootHash);
    assert.equal(vector.ownerCommitmentHash, GOLDEN_VECTOR.ownerCommitmentHash);
    assert.equal(vector.nullifierHash, GOLDEN_VECTOR.nullifierHash);
    assert.equal(vector.proofInputHashValue, GOLDEN_VECTOR.proofInputHashValue);
    assert.equal(
      proofInputHash({
        version: GOLDEN_VECTOR.version,
        proofType: GOLDEN_VECTOR.proofType,
        publicInputs: vector.publicInputs
      }),
      GOLDEN_VECTOR.proofInputHashValue
    );
  });

  it("matches Solidity for the derived hashes built from the canonical ABI fixtures", async function () {
    const [deployer] = await ethers.getSigners();
    const harness = await deployContract(deployer, "PhilHashHarness");
    const vector = buildUnlockKeccakFixtureVector({
      philSecret: GOLDEN_VECTOR.philSecret,
      actionHash: GOLDEN_VECTOR.actionHash,
      policyHash: GOLDEN_VECTOR.policyHash,
      nullifierSeed: GOLDEN_VECTOR.nullifierSeed,
      consumerDataHash: GOLDEN_VECTOR.consumerDataHash,
      expiry: GOLDEN_VECTOR.expiry
    });

    assert.equal(await harness.computeIdentityRoot(GOLDEN_VECTOR.philSecret), vector.identityRootHash);
    assert.equal(
      await harness.computeCanonicalOwnerCommitment(vector.identityRootHash),
      vector.ownerCommitmentHash
    );
    assert.equal(
      await harness.computeNullifier(
        vector.ownerCommitmentHash,
        vector.publicInputs.actionHash,
        vector.publicInputs.policyHash,
        GOLDEN_VECTOR.nullifierSeed
      ),
      vector.nullifierHash
    );
    assert.equal(
      await harness.computeUnlockProofInputHash({
        version: STWO_UNLOCK_PROOF_VERSION,
        proofType: STWO_UNLOCK_PROOF_TYPE,
        publicInputs: vector.publicInputs,
        proofInputHash: vector.proofInputHashValue,
        proofBlob: "0x"
      }),
      vector.proofInputHashValue
    );
  });

  it("uses exact Solidity abi.encode layout for the dynamic proof tuple preimage", function () {
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const vector = buildUnlockKeccakFixtureVector({
      philSecret: GOLDEN_VECTOR.philSecret,
      actionHash: GOLDEN_VECTOR.actionHash,
      policyHash: GOLDEN_VECTOR.policyHash,
      nullifierSeed: GOLDEN_VECTOR.nullifierSeed,
      consumerDataHash: GOLDEN_VECTOR.consumerDataHash,
      expiry: GOLDEN_VECTOR.expiry
    });

    const manual = abiCoder.encode(
      ["bytes32", "string", "string", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint64"],
      [
        DOMAIN_HASHES.unlockProofInputs,
        STWO_UNLOCK_PROOF_VERSION,
        STWO_UNLOCK_PROOF_TYPE,
        vector.publicInputs.ownerCommitment,
        vector.publicInputs.actionHash,
        vector.publicInputs.policyHash,
        vector.publicInputs.nullifier,
        vector.publicInputs.consumerDataHash,
        GOLDEN_VECTOR.expiry
      ]
    );

    assert.equal(manual, GOLDEN_VECTOR.proofInputHashPreimage);
  });
});
