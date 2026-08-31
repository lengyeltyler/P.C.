const assert = require("node:assert/strict");
const hre = require("hardhat");
const { ethers } = hre;

const { deployContract, expectRevert } = require("../helpers/context.cjs");

describe("PhilCoreAuthorizationConfirmationTarget", function () {
  async function fixture() {
    const [deployer, account] = await ethers.getSigners();
    const gate = await deployContract(deployer, "PhilBaseActionGate", [ethers.ZeroAddress]);
    const unlockConsumer = await deployContract(deployer, "PhilUnlockConsumer", [await gate.getAddress()]);
    const target = await deployContract(deployer, "PhilCoreAuthorizationConfirmationTarget", [
      await unlockConsumer.getAddress()
    ]);
    return { account, gate, target, unlockConsumer };
  }

  function buildPackage(input) {
    return {
      version: "v1",
      proofType: "s-two",
      publicInputs: {
        ownerCommitment: input.ownerCommitment,
        actionHash: input.actionHash,
        policyHash: input.policyHash,
        nullifier: input.nullifier,
        consumerDataHash: input.consumerDataHash,
        expiry: 0
      },
      proofInputHash: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "bytes32",
          "string",
          "string",
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "uint64"
        ],
        [
          ethers.keccak256(ethers.toUtf8Bytes("PHIL_UNLOCK_PROOF_INPUTS_V1")),
          "v1",
          "s-two",
          input.ownerCommitment,
          input.actionHash,
          input.policyHash,
          input.nullifier,
          input.consumerDataHash,
          0
        ]
      )),
      proofBlob: "0x"
    };
  }

  it("records one zero-value confirmation only through the reviewed ActionGate path", async function () {
    const { account, gate, target, unlockConsumer } = await fixture();
    const actionId = ethers.keccak256(ethers.toUtf8Bytes("o17-first-action"));
    const terminalCallData = ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [actionId]);
    const unlockRequest = {
      account: account.address,
      target: await target.getAddress(),
      value: 0,
      callData: terminalCallData
    };
    const consumerData = ethers.AbiCoder.defaultAbiCoder().encode(
      ["tuple(address account,address target,uint256 value,bytes callData)"],
      [unlockRequest]
    );
    const actionHash = await unlockConsumer.computeUnlockActionHash(unlockRequest);
    const ownerCommitment = ethers.keccak256(ethers.toUtf8Bytes("owner"));
    const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
    const nullifier = ethers.keccak256(ethers.toUtf8Bytes("nullifier"));
    const consumerDataHash = ethers.keccak256(consumerData);
    const authorization = {
      consumer: await unlockConsumer.getAddress(),
      ownerCommitment,
      actionHash,
      policyHash,
      nullifier,
      consumerDataHash,
      expiry: 0
    };
    const proofPackage = buildPackage({
      ownerCommitment,
      actionHash,
      policyHash,
      nullifier,
      consumerDataHash
    });

    await (await gate.verifyAndConsume(authorization, proofPackage, consumerData)).wait();

    assert.equal(await target.confirmedAction(actionId), true);
    assert.equal(await target.lastActionId(), actionId);
    assert.equal(await target.lastNullifier(), nullifier);
    assert.equal(await target.lastAccount(), account.address);
    assert.equal(await target.confirmationCount(), 1n);
    assert.equal(await ethers.provider.getBalance(await target.getAddress()), 0n);

    await expectRevert(
      () => gate.verifyAndConsume(authorization, proofPackage, consumerData),
      "duplicate nullifier should fail"
    );
  });

  it("rejects direct calls, zero action IDs, duplicate action IDs, and ETH value", async function () {
    const { account, gate, target, unlockConsumer } = await fixture();
    const actionId = ethers.keccak256(ethers.toUtf8Bytes("o17-duplicate-action"));
    const callData = ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [actionId]);

    await expectRevert(
      () => target.onPhilUnlock(account.address, ethers.ZeroHash, callData),
      "direct target call should fail"
    );

    const makeAttempt = async (nullifier, terminalCallData, value = 0n) => {
      const request = {
        account: account.address,
        target: await target.getAddress(),
        value,
        callData: terminalCallData
      };
      const consumerData = ethers.AbiCoder.defaultAbiCoder().encode(
        ["tuple(address account,address target,uint256 value,bytes callData)"],
        [request]
      );
      const actionHash = await unlockConsumer.computeUnlockActionHash(request);
      const ownerCommitment = ethers.keccak256(ethers.toUtf8Bytes("owner"));
      const policyHash = ethers.keccak256(ethers.toUtf8Bytes("policy"));
      const consumerDataHash = ethers.keccak256(consumerData);
      const authorization = {
        consumer: await unlockConsumer.getAddress(),
        ownerCommitment,
        actionHash,
        policyHash,
        nullifier,
        consumerDataHash,
        expiry: 0
      };
      const proofPackage = buildPackage({
        ownerCommitment,
        actionHash,
        policyHash,
        nullifier,
        consumerDataHash
      });
      return gate.verifyAndConsume(authorization, proofPackage, consumerData, { value });
    };

    await expectRevert(
      () => makeAttempt(
        ethers.keccak256(ethers.toUtf8Bytes("zero-action-nullifier")),
        ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [ethers.ZeroHash])
      ),
      "zero action ID should fail"
    );

    await (await makeAttempt(ethers.keccak256(ethers.toUtf8Bytes("first")), callData)).wait();
    await expectRevert(
      () => makeAttempt(ethers.keccak256(ethers.toUtf8Bytes("second")), callData),
      "duplicate action ID should fail"
    );
    await expectRevert(
      () => makeAttempt(
        ethers.keccak256(ethers.toUtf8Bytes("value")),
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32"],
          [ethers.keccak256(ethers.toUtf8Bytes("value-action"))]
        ),
        1n
      ),
      "nonzero value should fail"
    );
  });
});
