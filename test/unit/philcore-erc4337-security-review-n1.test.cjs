const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const {
  PHILCORE_4337_EMPTY_BYTES,
  computePhilCore4337UserOperationHash,
  packPhilCore4337AccountGasLimits,
  packPhilCore4337GasFees
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const OWNER_COMMITMENT = ethers.id("philcore-n1-owner-commitment");
const POLICY_HASH = ethers.id("philcore-n1-policy");

function packUints(high128, low128) {
  return ethers.toBeHex((BigInt(high128) << 128n) + BigInt(low128), 32);
}

function userOpDefaults({ sender, nonce, callData, initCode = PHILCORE_4337_EMPTY_BYTES, overrides = {} }) {
  return {
    sender,
    nonce,
    initCode,
    callData,
    accountGasLimits: packUints(900_000n, 900_000n),
    preVerificationGas: 120_000n,
    gasFees: packUints(1_000_000_000n, 30_000_000_000n),
    paymasterAndData: PHILCORE_4337_EMPTY_BYTES,
    signature: PHILCORE_4337_EMPTY_BYTES,
    ...overrides
  };
}

async function deployEntryPoint() {
  const [deployer] = await ethers.getSigners();
  return new ethers.ContractFactory(EntryPointArtifact.abi, EntryPointArtifact.bytecode, deployer).deploy();
}

async function fixture() {
  const [deployer, owner, other, beneficiary, attacker, recovery] = await ethers.getSigners();
  const entryPoint = await deployEntryPoint();
  const ActionGate = await ethers.getContractFactory("PhilBaseActionGate");
  const actionGate = await ActionGate.deploy(ethers.ZeroAddress);
  const AccountFactory = await ethers.getContractFactory("PhilCore4337AccountFactory");
  const accountFactory = await AccountFactory.deploy(await entryPoint.getAddress(), await actionGate.getAddress(), recovery.address, 60, 3600);
  const Target = await ethers.getContractFactory("PhilSmartAccountExecutionTarget");
  const target = await Target.deploy();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  return { deployer, owner, other, beneficiary, attacker, entryPoint, actionGate, accountFactory, target, chainId };
}

async function createAccount({ accountFactory, owner, ownerCommitment = OWNER_COMMITMENT, salt = 1n }) {
  const predicted = await accountFactory
    .getFunction("getAddress")
    .staticCall(owner.address, ownerCommitment, salt);
  await (await accountFactory.createAccount(owner.address, ownerCommitment, salt)).wait();
  const account = await ethers.getContractAt("PhilCore4337Account", predicted);
  return { account, accountAddress: predicted };
}

async function signUserOp({ entryPoint, userOp, signer, chainId }) {
  const userOperationHash = await entryPoint.getUserOpHash(userOp);
  const localHash = computePhilCore4337UserOperationHash({
    userOperation: normalizeRuntimeUserOp(userOp),
    entryPointAddress: await entryPoint.getAddress(),
    chainId
  });
  assert.equal(localHash, userOperationHash);
  return {
    userOperationHash,
    signedUserOp: {
      ...userOp,
      signature: await signer.signMessage(ethers.getBytes(userOperationHash))
    }
  };
}

function normalizeRuntimeUserOp(userOp) {
  return {
    sender: userOp.sender,
    nonce: userOp.nonce.toString(),
    initCode: userOp.initCode,
    callData: userOp.callData,
    accountGasLimits: userOp.accountGasLimits,
    preVerificationGas: userOp.preVerificationGas.toString(),
    gasFees: userOp.gasFees,
    paymasterAndData: userOp.paymasterAndData,
    signature: userOp.signature
  };
}

async function executeUserOp({ entryPoint, beneficiary, userOp }) {
  return entryPoint.handleOps([userOp], beneficiary.address, { gasLimit: 7_000_000 });
}

async function buildActionGateFixture() {
  const [deployer, account, target] = await ethers.getSigners();
  const ActionGate = await ethers.getContractFactory("PhilBaseActionGate");
  const gate = await ActionGate.deploy(ethers.ZeroAddress);
  const Consumer = await ethers.getContractFactory("PhilAdversarialAuthorizationConsumer");
  const consumer = await Consumer.deploy(await gate.getAddress());
  return { deployer, account, target, gate, consumer };
}

async function authorizationFor({ gate, consumer, consumerData, nullifier = ethers.id("n1-nullifier") }) {
  const authorization = {
    consumer: await consumer.getAddress(),
    ownerCommitment: OWNER_COMMITMENT,
    actionHash: ethers.id("n1-action"),
    policyHash: POLICY_HASH,
    nullifier,
    consumerDataHash: ethers.keccak256(consumerData),
    expiry: Math.floor(Date.now() / 1000) + 3600
  };
  const proofPackage = {
    version: "v1",
    proofType: "s-two",
    publicInputs: {
      ownerCommitment: authorization.ownerCommitment,
      actionHash: authorization.actionHash,
      policyHash: authorization.policyHash,
      nullifier: authorization.nullifier,
      consumerDataHash: authorization.consumerDataHash,
      expiry: authorization.expiry
    },
    proofInputHash: ethers.ZeroHash,
    proofBlob: "0x"
  };
  proofPackage.proofInputHash = await gate.computeProofInputHash(proofPackage);
  return { authorization, proofPackage };
}

async function approvedActionGateCall({ gate, accountAddress, tag }) {
  const Consumer = await ethers.getContractFactory("PhilAuthorizationConsumerMock");
  const consumer = await Consumer.deploy();
  const consumerData = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "bytes32"],
    [accountAddress, ethers.id(tag)]
  );
  const { authorization, proofPackage } = await authorizationFor({
    gate,
    consumer,
    consumerData,
    nullifier: ethers.id(`${tag}-nullifier`)
  });
  return {
    consumer,
    callData: gate.interface.encodeFunctionData("verifyAndConsume", [
      authorization,
      proofPackage,
      consumerData
    ])
  };
}

describe("Phase N.1/N.2 adversarial ERC-4337 security review tests", function () {
  it("proves direct owner calls and owner-signed arbitrary EntryPoint executions are blocked", async function () {
    const { owner, beneficiary, entryPoint, accountFactory, target, chainId } = await fixture();
    const { account, accountAddress } = await createAccount({ accountFactory, owner });
    await owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });

    const arbitraryValue = ethers.id("arbitrary-entrypoint-call");
    const arbitraryTargetCall = target.interface.encodeFunctionData("ping", [arbitraryValue]);

    await assert.rejects(
      account.connect(owner).execute(await target.getAddress(), 0, arbitraryTargetCall),
      /UnauthorizedExecuteCaller/
    );

    const accountCallData = account.interface.encodeFunctionData("execute", [
      await target.getAddress(),
      0,
      arbitraryTargetCall
    ]);
    const unsigned = userOpDefaults({
      sender: accountAddress,
      nonce: await entryPoint.getNonce(accountAddress, 0),
      callData: accountCallData
    });
    const { signedUserOp } = await signUserOp({ entryPoint, userOp: unsigned, signer: owner, chainId });
    const tx = await executeUserOp({ entryPoint, beneficiary, userOp: signedUserOp });
    const receipt = await tx.wait();

    assert.equal(receipt.status, 1);
    assert.equal(await target.lastValue(), ethers.ZeroHash);
    assert.equal(await target.calls(), 0n);
  });

  it("rejects wrong selectors and account-self nesting through owner-signed EntryPoint calls", async function () {
    const { owner, beneficiary, entryPoint, actionGate, accountFactory, chainId } = await fixture();
    const { account, accountAddress } = await createAccount({ accountFactory, owner });
    await owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });

    const wrongSelectorCall = account.interface.encodeFunctionData("execute", [
      await actionGate.getAddress(),
      0,
      "0x12345678"
    ]);
    const wrongSelectorOp = userOpDefaults({
      sender: accountAddress,
      nonce: await entryPoint.getNonce(accountAddress, 0),
      callData: wrongSelectorCall
    });
    const { signedUserOp: signedWrongSelector } = await signUserOp({
      entryPoint,
      userOp: wrongSelectorOp,
      signer: owner,
      chainId
    });
    await (await executeUserOp({ entryPoint, beneficiary, userOp: signedWrongSelector })).wait();

    const { consumer, callData: validGateCall } = await approvedActionGateCall({
      gate: actionGate,
      accountAddress,
      tag: "self-nested"
    });
    const nestedExecute = account.interface.encodeFunctionData("execute", [
      await actionGate.getAddress(),
      0,
      validGateCall
    ]);
    const selfTargetCall = account.interface.encodeFunctionData("execute", [
      accountAddress,
      0,
      nestedExecute
    ]);
    const selfTargetOp = userOpDefaults({
      sender: accountAddress,
      nonce: await entryPoint.getNonce(accountAddress, 0),
      callData: selfTargetCall
    });
    const { signedUserOp: signedSelfTarget } = await signUserOp({
      entryPoint,
      userOp: selfTargetOp,
      signer: owner,
      chainId
    });
    await (await executeUserOp({ entryPoint, beneficiary, userOp: signedSelfTarget })).wait();

    assert.equal(await consumer.consumeCount(), 0n);
  });

  it("invalidates signatures when any signed UserOperation field is mutated", async function () {
    const { owner, beneficiary, entryPoint, accountFactory, target, chainId } = await fixture();
    const { account, accountAddress } = await createAccount({ accountFactory, owner });
    await owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });
    const targetCall = target.interface.encodeFunctionData("ping", [ethers.id("signed-field")]);
    const accountCallData = account.interface.encodeFunctionData("execute", [await target.getAddress(), 0, targetCall]);
    const unsigned = userOpDefaults({
      sender: accountAddress,
      nonce: await entryPoint.getNonce(accountAddress, 0),
      callData: accountCallData
    });
    const { signedUserOp } = await signUserOp({ entryPoint, userOp: unsigned, signer: owner, chainId });

    for (const mutated of [
      { ...signedUserOp, callData: `${signedUserOp.callData}00` },
      { ...signedUserOp, accountGasLimits: packUints(900_001n, 900_000n) },
      { ...signedUserOp, gasFees: packUints(1_000_000_001n, 30_000_000_000n) },
      { ...signedUserOp, paymasterAndData: "0x01" }
    ]) {
      await assert.rejects(
        executeUserOp({ entryPoint, beneficiary, userOp: mutated }),
        /reverted/
      );
    }
  });

  it("keeps CREATE2 addresses deterministic and prevents altered initialization at the same predicted address", async function () {
    const { owner, other, accountFactory } = await fixture();
    for (let i = 0; i < 16; i += 1) {
      const ownerCommitment = ethers.hexlify(randomBytes(32));
      const salt = BigInt(`0x${randomBytes(8).toString("hex")}`);
      const predicted = await accountFactory
        .getFunction("getAddress")
        .staticCall(owner.address, ownerCommitment, salt);
      const wrongOwner = await accountFactory
        .getFunction("getAddress")
        .staticCall(other.address, ownerCommitment, salt);
      const wrongCommitment = await accountFactory
        .getFunction("getAddress")
        .staticCall(owner.address, ethers.hexlify(randomBytes(32)), salt);
      assert.notEqual(predicted, wrongOwner);
      assert.notEqual(predicted, wrongCommitment);

      const deployed = await accountFactory.createAccount.staticCall(owner.address, ownerCommitment, salt);
      assert.equal(deployed, predicted);
      await (await accountFactory.createAccount(owner.address, ownerCommitment, salt)).wait();
      const duplicate = await accountFactory.createAccount.staticCall(other.address, ownerCommitment, salt);
      assert.notEqual(duplicate, predicted);
    }
  });

  it("rejects gas and fee packing overflows through runtime helpers", function () {
    assert.equal(
      packPhilCore4337AccountGasLimits({ verificationGasLimit: 1n, callGasLimit: 2n }),
      packUints(1n, 2n)
    );
    assert.equal(
      packPhilCore4337GasFees({ maxPriorityFeePerGas: 3n, maxFeePerGas: 4n }),
      packUints(3n, 4n)
    );
    assert.throws(() => packPhilCore4337AccountGasLimits({
      verificationGasLimit: 1n << 128n,
      callGasLimit: 1n
    }));
    assert.throws(() => packPhilCore4337GasFees({
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 1n << 128n
    }));
  });

  it("preserves ActionGate nullifier atomicity when a malicious consumer reenters with the same nullifier", async function () {
    const { gate, consumer } = await buildActionGateFixture();
    await consumer.setMode(1);
    const consumerData = ethers.hexlify(ethers.toUtf8Bytes("reenter"));
    const { authorization, proofPackage } = await authorizationFor({ gate, consumer, consumerData });

    await (await gate.verifyAndConsume(authorization, proofPackage, consumerData)).wait();

    assert.equal(await consumer.consumeCount(), 1n);
    assert.equal(await consumer.reentryAttempted(), true);
    assert.equal(await consumer.reentryFailed(), true);
    assert.equal(await gate.consumedNullifier(authorization.nullifier), true);
    await assert.rejects(
      gate.verifyAndConsume(authorization, proofPackage, consumerData),
      /NullifierAlreadyConsumed/
    );
  });

  it("rolls back nullifier state when a malicious consumer reverts after ActionGate marks consumption", async function () {
    const { gate, consumer } = await buildActionGateFixture();
    await consumer.setMode(3);
    const consumerData = ethers.hexlify(ethers.toUtf8Bytes("revert-after-observe"));
    const { authorization, proofPackage } = await authorizationFor({ gate, consumer, consumerData });

    await assert.rejects(
      gate.verifyAndConsume(authorization, proofPackage, consumerData),
      /ForcedAdversarialRevert|DownstreamCallFailed|reverted/
    );
    assert.equal(await gate.consumedNullifier(authorization.nullifier), false);
  });

  it("blocks a malicious consumer from calling account.execute directly", async function () {
    const { owner, entryPoint, accountFactory, target } = await fixture();
    const { account, accountAddress } = await createAccount({ accountFactory, owner });
    const { gate, consumer } = await buildActionGateFixture();
    await consumer.setMode(2);
    const attemptedCall = target.interface.encodeFunctionData("ping", [ethers.id("consumer-account-execute")]);
    const consumerData = ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "address", "bytes"],
      [accountAddress, await target.getAddress(), attemptedCall]
    );
    const { authorization, proofPackage } = await authorizationFor({ gate, consumer, consumerData });

    await (await gate.verifyAndConsume(authorization, proofPackage, consumerData)).wait();

    assert.equal(await consumer.accountExecuteAttempted(), true);
    assert.equal(await consumer.accountExecuteFailed(), true);
    assert.equal(await target.calls(), 0n);
    assert.equal(await account.entryPoint(), await entryPoint.getAddress());
  });

  it("blocks unauthorized direct Base mirror injection and wrong remote senders", async function () {
    const { deployer, attacker } = await fixture();
    const Messenger = await ethers.getContractFactory("MockBaseCrossDomainMessenger");
    const messenger = await Messenger.deploy();
    const Mirror = await ethers.getContractFactory("PhilBaseProofInputHashMirror");
    const authorizedL1 = deployer.address;
    const mirror = await Mirror.deploy(await messenger.getAddress(), authorizedL1);

    await assert.rejects(
      mirror.connect(attacker).mirrorProofInputHashFact(1, 2),
      /OnlyCrossDomainMessenger/
    );
    await assert.rejects(
      messenger.connect(attacker).sendMessage(
        await mirror.getAddress(),
        mirror.interface.encodeFunctionData("mirrorProofInputHashFact", [1, 2]),
        200000
      ),
      /TargetCallFailed|InvalidCrossDomainSender/
    );
    await (await messenger.connect(deployer).sendMessage(
      await mirror.getAddress(),
      mirror.interface.encodeFunctionData("mirrorProofInputHashFact", [1, 2]),
      200000
    )).wait();
    assert.equal(await mirror.mirroredProofInputHashFact(1, 2), true);
    void deployer;
  });
});
