"use strict";

const assert = require("node:assert/strict");
const { ethers } = require("hardhat");
const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

function packed128(high, low) {
  return ethers.toBeHex((BigInt(high) << 128n) | BigInt(low), 32);
}

async function deployEntryPoint(deployer) {
  const implementation = await new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
  await implementation.waitForDeployment();
  return implementation;
}

async function fixture() {
  const [deployer, beneficiary, mismatchedRecipient, recovery, outsider] = await ethers.getSigners();
  const executionOwner = ethers.Wallet.createRandom().connect(ethers.provider);
  const entryPoint = await deployEntryPoint(deployer);
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const nonce = await ethers.provider.getTransactionCount(deployer.address);
  const predictedFactory = ethers.getCreateAddress({ from: deployer.address, nonce });
  const predictedGate = ethers.getCreateAddress({ from: deployer.address, nonce: nonce + 1 });
  const predictedConsumer = ethers.getCreateAddress({ from: deployer.address, nonce: nonce + 2 });

  const Factory = await ethers.getContractFactory("PhilCore4337AccountFactory", deployer);
  const factory = await Factory.deploy(
    await entryPoint.getAddress(),
    predictedGate,
    recovery.address,
    60,
    3600
  );
  await factory.waitForDeployment();
  assert.equal((await factory.getAddress()).toLowerCase(), predictedFactory.toLowerCase());

  const ownerCommitment = ethers.id("phil-beta-reusable-owner-commitment");
  const salt = BigInt(ethers.id("phil-beta-reusable-account-salt"));
  const accountAddress = await factory.getFunction("getAddress").staticCall(
    executionOwner.address,
    ownerCommitment,
    salt
  );

  const Gate = await ethers.getContractFactory("PhilSepoliaLocalComposedActionGateV1", deployer);
  const gate = await Gate.deploy(chainId, predictedFactory, predictedConsumer, accountAddress);
  await gate.waitForDeployment();
  assert.equal((await gate.getAddress()).toLowerCase(), predictedGate.toLowerCase());

  const Consumer = await ethers.getContractFactory("PhilSepoliaMintPassConsumerV1", deployer);
  const consumer = await Consumer.deploy(predictedGate);
  await consumer.waitForDeployment();
  assert.equal((await consumer.getAddress()).toLowerCase(), predictedConsumer.toLowerCase());

  await deployer.sendTransaction({ to: accountAddress, value: ethers.parseEther("0.05") });
  const accountInterface = (await ethers.getContractFactory("PhilCore4337Account")).interface;
  return {
    deployer,
    beneficiary,
    recipient: executionOwner,
    mismatchedRecipient,
    recovery,
    outsider,
    executionOwner,
    entryPoint,
    chainId,
    factory,
    gate,
    consumer,
    ownerCommitment,
    salt,
    accountAddress,
    accountInterface
  };
}

async function signedOperation(env, {
  sequence,
  counterfactual,
  tag,
  value = 0n,
  executionOwner = env.executionOwner,
  ownerCommitment = env.ownerCommitment,
  salt = env.salt,
  accountAddress = env.accountAddress,
  recipient = executionOwner.address,
  envelopeDigest = ethers.id(`${tag}-envelope`),
  rootNullifier = ethers.id(`${tag}-root-nullifier`),
  approvalNonce = ethers.id(`${tag}-device-approval`),
  validUntil
}) {
  const latest = await ethers.provider.getBlock("latest");
  const effectiveValidUntil = validUntil ?? BigInt(latest.timestamp) + 300n;
  const gateData = env.gate.interface.encodeFunctionData("verifyAndConsume", [
    envelopeDigest,
    rootNullifier,
    approvalNonce,
    effectiveValidUntil,
    recipient
  ]);
  const callData = env.accountInterface.encodeFunctionData("execute", [
    await env.gate.getAddress(),
    value,
    gateData
  ]);
  const factoryData = env.factory.interface.encodeFunctionData("createAccount", [
    executionOwner.address,
    ownerCommitment,
    salt
  ]);
  const operation = {
    sender: accountAddress,
    nonce: BigInt(sequence),
    initCode: counterfactual
      ? ethers.concat([await env.factory.getAddress(), factoryData])
      : "0x",
    callData,
    accountGasLimits: packed128(1_800_000n, 300_000n),
    preVerificationGas: 100_000n,
    gasFees: packed128(1n, 2n),
    paymasterAndData: "0x",
    signature: "0x"
  };
  const userOperationHash = await env.entryPoint.getUserOpHash(operation);
  operation.signature = await executionOwner.signMessage(ethers.getBytes(userOperationHash));
  return { operation, envelopeDigest, rootNullifier, approvalNonce, validUntil: effectiveValidUntil };
}

describe("Phil controlled Sepolia Beta reusable composed contracts", function () {
  it("counterfactually deploys once, then executes a second fresh authorization with empty initCode", async function () {
    const env = await fixture();
    const first = await signedOperation(env, {
      sequence: 0,
      counterfactual: true,
      tag: "beta-first"
    });
    await (await env.entryPoint.handleOps([first.operation], env.beneficiary.address)).wait();

    assert.equal(await env.factory.isPhilSepoliaMintAccount(env.accountAddress), true);
    assert.notEqual(await ethers.provider.getCode(env.accountAddress), "0x");
    assert.equal(await env.consumer.tokenIdByEnvelopeDigest(first.envelopeDigest), 1n);
    assert.equal(await env.entryPoint.getNonce(env.accountAddress, 0), 1n);

    const second = await signedOperation(env, {
      sequence: 1,
      counterfactual: false,
      tag: "beta-second"
    });
    assert.equal(second.operation.initCode, "0x");
    await (await env.entryPoint.handleOps([second.operation], env.beneficiary.address)).wait();

    assert.equal(await env.consumer.tokenIdByEnvelopeDigest(second.envelopeDigest), 2n);
    assert.equal(await env.consumer.balanceOf(env.recipient.address), 2n);
    assert.equal(await env.entryPoint.getNonce(env.accountAddress, 0), 2n);
  });

  it("rejects stale nonce replay and forbids non-zero composed execution", async function () {
    const env = await fixture();
    const first = await signedOperation(env, {
      sequence: 0,
      counterfactual: true,
      tag: "beta-replay"
    });
    await (await env.entryPoint.handleOps([first.operation], env.beneficiary.address)).wait();
    await assert.rejects(
      env.entryPoint.handleOps([first.operation], env.beneficiary.address),
      /AA25 invalid account nonce|unrecognized custom error/u
    );

    const nonZero = await signedOperation(env, {
      sequence: 1,
      counterfactual: false,
      tag: "beta-non-zero",
      value: 1n
    });
    await (await env.entryPoint.handleOps([nonZero.operation], env.beneficiary.address)).wait();
    assert.equal(await env.consumer.tokenIdByEnvelopeDigest(nonZero.envelopeDigest), 0n);
    assert.equal(await env.entryPoint.getNonce(env.accountAddress, 0), 2n);
  });

  it("rejects copied one-time authorization fields from another registered account", async function () {
    const env = await fixture();
    const legitimate = await signedOperation(env, {
      sequence: 0,
      counterfactual: true,
      tag: "beta-account-bound-legitimate"
    });
    const attackerOwner = ethers.Wallet.createRandom().connect(ethers.provider);
    const attackerCommitment = ethers.id("beta-account-bound-attacker-commitment");
    const attackerSalt = BigInt(ethers.id("beta-account-bound-attacker-salt"));
    const attackerAccountAddress = await env.factory.getFunction("getAddress").staticCall(
      attackerOwner.address,
      attackerCommitment,
      attackerSalt
    );
    await env.deployer.sendTransaction({ to: attackerAccountAddress, value: ethers.parseEther("1") });
    const copied = await signedOperation(env, {
      sequence: 0,
      counterfactual: true,
      tag: "beta-account-bound-attacker",
      executionOwner: attackerOwner,
      ownerCommitment: attackerCommitment,
      salt: attackerSalt,
      accountAddress: attackerAccountAddress,
      recipient: attackerOwner.address,
      envelopeDigest: legitimate.envelopeDigest,
      rootNullifier: legitimate.rootNullifier,
      approvalNonce: legitimate.approvalNonce,
      validUntil: legitimate.validUntil
    });
    await (await env.entryPoint.handleOps([copied.operation], env.beneficiary.address)).wait();
    assert.equal(await env.factory.isPhilSepoliaMintAccount(attackerAccountAddress), true);
    assert.equal(await env.gate.consumedEnvelopeDigest(legitimate.envelopeDigest), false);
    assert.equal(await env.consumer.tokenIdByEnvelopeDigest(legitimate.envelopeDigest), 0n);
    await (await env.entryPoint.handleOps([legitimate.operation], env.beneficiary.address)).wait();
    assert.equal(await env.consumer.tokenIdByEnvelopeDigest(legitimate.envelopeDigest), 1n);
  });

  it("enforces the current execution owner as the mint recipient", async function () {
    const env = await fixture();
    await env.factory.createAccount(env.executionOwner.address, env.ownerCommitment, env.salt);
    await ethers.provider.send("hardhat_impersonateAccount", [env.accountAddress]);
    await env.deployer.sendTransaction({ to: env.accountAddress, value: ethers.parseEther("1") });
    const latest = await ethers.provider.getBlock("latest");
    try {
      await assert.rejects(
        env.gate.connect(await ethers.getSigner(env.accountAddress)).verifyAndConsume(
          ethers.id("wrong-recipient-envelope"),
          ethers.id("wrong-recipient-nullifier"),
          ethers.id("wrong-recipient-device-approval"),
          BigInt(latest.timestamp) + 300n,
          env.mismatchedRecipient.address
        ),
        /MintRecipientNotCurrentOwner/u
      );
    } finally {
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [env.accountAddress]);
    }
  });

  it("freezes ordinary composed execution throughout delayed recovery", async function () {
    const env = await fixture();
    await env.factory.createAccount(env.executionOwner.address, env.ownerCommitment, env.salt);
    const account = await ethers.getContractAt("PhilCore4337Account", env.accountAddress);
    const pendingOwner = env.outsider.address;
    await account.connect(env.recovery).requestRecovery(pendingOwner);
    assert.equal(await account.frozen(), true);

    const frozen = await signedOperation(env, {
      sequence: 0,
      counterfactual: false,
      tag: "beta-frozen"
    });
    await assert.rejects(
      env.entryPoint.handleOps([frozen.operation], env.beneficiary.address),
      /AA24 signature error|unrecognized custom error/u
    );
    assert.equal(await env.consumer.tokenIdByEnvelopeDigest(frozen.envelopeDigest), 0n);
  });
});
