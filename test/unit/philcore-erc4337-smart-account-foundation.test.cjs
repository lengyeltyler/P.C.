const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const OWNER_COMMITMENT = ethers.id("philcore-m9a-owner-commitment");
const ZERO_BYTES = "0x";

function packUints(high128, low128) {
  return ethers.toBeHex((BigInt(high128) << 128n) + BigInt(low128), 32);
}

function packAccountGasLimits({ verificationGasLimit, callGasLimit }) {
  return packUints(verificationGasLimit, callGasLimit);
}

function packGasFees({ maxPriorityFeePerGas, maxFeePerGas }) {
  return packUints(maxPriorityFeePerGas, maxFeePerGas);
}

function userOpDefaults({ sender, nonce, callData, initCode = ZERO_BYTES, overrides = {} }) {
  return {
    sender,
    nonce,
    initCode,
    callData,
    accountGasLimits: packAccountGasLimits({
      verificationGasLimit: 900_000n,
      callGasLimit: 900_000n
    }),
    preVerificationGas: 120_000n,
    gasFees: packGasFees({
      maxPriorityFeePerGas: ethers.parseUnits("1", "gwei"),
      maxFeePerGas: ethers.parseUnits("30", "gwei")
    }),
    paymasterAndData: ZERO_BYTES,
    signature: ZERO_BYTES,
    ...overrides
  };
}

async function deployEntryPoint() {
  const [deployer] = await ethers.getSigners();
  const factory = new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  );
  return factory.deploy();
}

async function signUserOp({ entryPoint, userOp, signer, chainId }) {
  const userOpHash = await entryPoint.getUserOpHash(userOp);
  const signature = await signer.signMessage(ethers.getBytes(userOpHash));
  const localHash = computeUserOpHash({
    userOp,
    entryPointAddress: await entryPoint.getAddress(),
    chainId
  });
  assert.equal(localHash, userOpHash);
  return {
    userOpHash,
    signedUserOp: {
      ...userOp,
      signature
    }
  };
}

function computeUserOpHash({ userOp, entryPointAddress, chainId }) {
  const packHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "address",
        "uint256",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint256",
        "bytes32",
        "bytes32"
      ],
      [
        userOp.sender,
        userOp.nonce,
        ethers.keccak256(userOp.initCode),
        ethers.keccak256(userOp.callData),
        userOp.accountGasLimits,
        userOp.preVerificationGas,
        userOp.gasFees,
        ethers.keccak256(userOp.paymasterAndData)
      ]
    )
  );
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "uint256"],
      [packHash, entryPointAddress, chainId]
    )
  );
}

async function fixture() {
  const [deployer, owner, other, beneficiary, recovery] = await ethers.getSigners();
  const entryPoint = await deployEntryPoint();
  const ActionGate = await ethers.getContractFactory("PhilBaseActionGate");
  const actionGate = await ActionGate.deploy(ethers.ZeroAddress);
  const AccountFactory = await ethers.getContractFactory("PhilCore4337AccountFactory");
  const accountFactory = await AccountFactory.deploy(await entryPoint.getAddress(), await actionGate.getAddress(), recovery.address, 60, 3600);
  const Target = await ethers.getContractFactory("PhilSmartAccountExecutionTarget");
  const target = await Target.deploy();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  return {
    deployer,
    owner,
    other,
    beneficiary,
    entryPoint,
    actionGate,
    accountFactory,
    target,
    chainId
  };
}

async function createAccount({ accountFactory, owner, ownerCommitment = OWNER_COMMITMENT, salt = 1n }) {
  const predicted = await accountFactory
    .getFunction("getAddress")
    .staticCall(owner.address, ownerCommitment, salt);
  const tx = await accountFactory.createAccount(owner.address, ownerCommitment, salt);
  await tx.wait();
  const account = await ethers.getContractAt("PhilCore4337Account", predicted);
  return { account, predicted };
}

async function executeUserOp({ entryPoint, beneficiary, userOp }) {
  return entryPoint.handleOps([userOp], beneficiary.address, { gasLimit: 6_000_000 });
}

async function buildActionGateCall({ actionGate, accountAddress, tag, ownerCommitment = OWNER_COMMITMENT }) {
  const Consumer = await ethers.getContractFactory("PhilAuthorizationConsumerMock");
  const consumer = await Consumer.deploy();
  const consumerData = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "bytes32"],
    [accountAddress, ethers.id(tag)]
  );
  const authorization = {
    consumer: await consumer.getAddress(),
    ownerCommitment,
    actionHash: ethers.id(`${tag}-action`),
    policyHash: ethers.id(`${tag}-policy`),
    nullifier: ethers.id(`${tag}-nullifier`),
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
  proofPackage.proofInputHash = await actionGate.computeProofInputHash(proofPackage);
  return {
    consumer,
    callData: actionGate.interface.encodeFunctionData("verifyAndConsume", [
      authorization,
      proofPackage,
      consumerData
    ])
  };
}

describe("PhilCore ERC-4337 smart account foundation", function () {
  it("selects the actual EntryPoint v0.7 schema and computes canonical UserOperation hashes", async function () {
    const { entryPoint, accountFactory, owner, target, chainId } = await fixture();
    const { account } = await createAccount({ accountFactory, owner });
    const accountAddress = await account.getAddress();
    const data = target.interface.encodeFunctionData("ping", [ethers.id("hash-parity")]);
    const callData = account.interface.encodeFunctionData("execute", [
      await target.getAddress(),
      0,
      data
    ]);
    const nonce = await entryPoint.getNonce(accountAddress, 0);
    const userOp = userOpDefaults({ sender: accountAddress, nonce, callData });
    const entryPointHash = await entryPoint.getUserOpHash(userOp);
    const localHash = computeUserOpHash({
      userOp,
      entryPointAddress: await entryPoint.getAddress(),
      chainId
    });

    assert.equal(localHash, entryPointHash);
    assert.equal(userOp.signature, ZERO_BYTES);
    assert.equal(userOp.paymasterAndData, ZERO_BYTES);
  });

  it("deploys deterministic accounts and rejects direct execute bypasses", async function () {
    const { accountFactory, owner, other, target } = await fixture();
    const salt = 123n;
    const predicted = await accountFactory
      .getFunction("getAddress")
      .staticCall(owner.address, OWNER_COMMITMENT, salt);
    const changedOwner = await accountFactory
      .getFunction("getAddress")
      .staticCall(other.address, OWNER_COMMITMENT, salt);
    const changedSalt = await accountFactory
      .getFunction("getAddress")
      .staticCall(owner.address, OWNER_COMMITMENT, salt + 1n);

    assert.notEqual(predicted, changedOwner);
    assert.notEqual(predicted, changedSalt);

    const { account } = await createAccount({ accountFactory, owner, salt });
    assert.equal(await account.getAddress(), predicted);
    assert.equal(await account.owner(), owner.address);
    assert.equal(await account.ownerCommitment(), OWNER_COMMITMENT);
    assert.equal(await account.approvedActionGate(), await accountFactory.approvedActionGate());

    const duplicate = await accountFactory.createAccount.staticCall(
      owner.address,
      OWNER_COMMITMENT,
      salt
    );
    assert.equal(duplicate, predicted);

    const data = target.interface.encodeFunctionData("ping", [ethers.id("direct-bypass")]);
    await assert.rejects(
      account.connect(owner).execute(await target.getAddress(), 0, data),
      /UnauthorizedExecuteCaller/
    );
    await assert.rejects(
      accountFactory.createAccount(ethers.ZeroAddress, OWNER_COMMITMENT, 999n),
      /InvalidOwner/
    );
  });

  it("executes a valid ActionGate UserOperation through the actual local EntryPoint and blocks replay", async function () {
    const { entryPoint, accountFactory, owner, beneficiary, actionGate, chainId } = await fixture();
    const { account } = await createAccount({ accountFactory, owner });
    const accountAddress = await account.getAddress();
    await owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });

    const { consumer, callData: targetCall } = await buildActionGateCall({
      actionGate,
      accountAddress,
      tag: "entrypoint-execution"
    });
    const callData = account.interface.encodeFunctionData("execute", [
      await actionGate.getAddress(),
      0,
      targetCall
    ]);
    const nonce = await entryPoint.getNonce(accountAddress, 0);
    const unsigned = userOpDefaults({ sender: accountAddress, nonce, callData });
    const { signedUserOp } = await signUserOp({
      entryPoint,
      userOp: unsigned,
      signer: owner,
      chainId
    });

    const tx = await executeUserOp({ entryPoint, beneficiary, userOp: signedUserOp });
    const receipt = await tx.wait();

    assert.equal(receipt.status, 1);
    assert.equal(await consumer.consumeCount(), 1n);

    await assert.rejects(
      executeUserOp({ entryPoint, beneficiary, userOp: signedUserOp }),
      /reverted/
    );
  });

  it("rejects invalid signatures, wrong domain signatures, mutated calldata, and mutated gas fields", async function () {
    const { entryPoint, accountFactory, owner, other, beneficiary, actionGate, chainId } = await fixture();
    const { account } = await createAccount({ accountFactory, owner });
    const accountAddress = await account.getAddress();
    await owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });

    const { callData: targetCall } = await buildActionGateCall({
      actionGate,
      accountAddress,
      tag: "valid"
    });
    const callData = account.interface.encodeFunctionData("execute", [
      await actionGate.getAddress(),
      0,
      targetCall
    ]);
    const nonce = await entryPoint.getNonce(accountAddress, 0);
    const unsigned = userOpDefaults({ sender: accountAddress, nonce, callData });

    const wrongSigner = await signUserOp({ entryPoint, userOp: unsigned, signer: other, chainId });
    await assert.rejects(
      executeUserOp({ entryPoint, beneficiary, userOp: wrongSigner.signedUserOp }),
      /reverted/
    );

    const wrongDomainHash = computeUserOpHash({
      userOp: unsigned,
      entryPointAddress: await entryPoint.getAddress(),
      chainId: chainId + 1
    });
    const wrongDomain = {
      ...unsigned,
      signature: await owner.signMessage(ethers.getBytes(wrongDomainHash))
    };
    await assert.rejects(
      executeUserOp({ entryPoint, beneficiary, userOp: wrongDomain }),
      /reverted/
    );

    const signed = await signUserOp({ entryPoint, userOp: unsigned, signer: owner, chainId });
    const mutatedTargetCall = `${targetCall}00`;
    const mutatedCallData = account.interface.encodeFunctionData("execute", [
      await actionGate.getAddress(),
      0,
      mutatedTargetCall
    ]);
    await assert.rejects(
      executeUserOp({
        entryPoint,
        beneficiary,
        userOp: { ...signed.signedUserOp, callData: mutatedCallData }
      }),
      /reverted/
    );

    await assert.rejects(
      executeUserOp({
        entryPoint,
        beneficiary,
        userOp: {
          ...signed.signedUserOp,
          accountGasLimits: packAccountGasLimits({
            verificationGasLimit: 900_001n,
            callGasLimit: 900_000n
          })
        }
      }),
      /reverted/
    );
  });

  it("supports counterfactual deployment through EntryPoint initCode", async function () {
    const { entryPoint, accountFactory, owner, beneficiary, actionGate, chainId } = await fixture();
    const salt = 456n;
    const predicted = await accountFactory
      .getFunction("getAddress")
      .staticCall(owner.address, OWNER_COMMITMENT, salt);
    assert.equal(await ethers.provider.getCode(predicted), "0x");

    await entryPoint.depositTo(predicted, { value: ethers.parseEther("1") });

    const factoryCall = accountFactory.interface.encodeFunctionData("createAccount", [
      owner.address,
      OWNER_COMMITMENT,
      salt
    ]);
    const initCode = ethers.concat([await accountFactory.getAddress(), factoryCall]);
    const account = await ethers.getContractAt("PhilCore4337Account", predicted);
    const { consumer, callData: targetCall } = await buildActionGateCall({
      actionGate,
      accountAddress: predicted,
      tag: "counterfactual"
    });
    const callData = account.interface.encodeFunctionData("execute", [
      await actionGate.getAddress(),
      0,
      targetCall
    ]);
    const unsigned = userOpDefaults({
      sender: predicted,
      nonce: 0n,
      initCode,
      callData,
      overrides: {
        accountGasLimits: packAccountGasLimits({
          verificationGasLimit: 4_000_000n,
          callGasLimit: 900_000n
        })
      }
    });
    const { signedUserOp } = await signUserOp({
      entryPoint,
      userOp: unsigned,
      signer: owner,
      chainId
    });

    const tx = await executeUserOp({ entryPoint, beneficiary, userOp: signedUserOp });
    const receipt = await tx.wait();

    assert.equal(receipt.status, 1);
    assert.notEqual(await ethers.provider.getCode(predicted), "0x");
    assert.equal(await consumer.consumeCount(), 1n);
  });

  it("wraps the exact ActionGate verifyAndConsume call through the smart account", async function () {
    const { entryPoint, accountFactory, owner, beneficiary, actionGate, chainId } = await fixture();
    const { account } = await createAccount({ accountFactory, owner });
    const accountAddress = await account.getAddress();
    await owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });

    const Consumer = await ethers.getContractFactory("PhilAuthorizationConsumerMock");
    const consumer = await Consumer.deploy();

    const consumerData = ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes32"],
      [accountAddress, ethers.id("m9a-consumer-data")]
    );
    const authorization = {
      consumer: await consumer.getAddress(),
      ownerCommitment: OWNER_COMMITMENT,
      actionHash: ethers.id("m9a-action"),
      policyHash: ethers.id("m9a-policy"),
      nullifier: ethers.id("m9a-nullifier"),
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
    proofPackage.proofInputHash = await actionGate.computeProofInputHash(proofPackage);

    const actionGateCall = actionGate.interface.encodeFunctionData("verifyAndConsume", [
      authorization,
      proofPackage,
      consumerData
    ]);
    assert.equal(actionGateCall.slice(0, 10), "0xb1952061");

    const accountCallData = account.interface.encodeFunctionData("execute", [
      await actionGate.getAddress(),
      0,
      actionGateCall
    ]);
    const unsigned = userOpDefaults({
      sender: accountAddress,
      nonce: await entryPoint.getNonce(accountAddress, 0),
      callData: accountCallData,
      overrides: {
        accountGasLimits: packAccountGasLimits({
          verificationGasLimit: 900_000n,
          callGasLimit: 1_500_000n
        })
      }
    });
    const { signedUserOp } = await signUserOp({
      entryPoint,
      userOp: unsigned,
      signer: owner,
      chainId
    });

    const tx = await executeUserOp({ entryPoint, beneficiary, userOp: signedUserOp });
    const receipt = await tx.wait();

    assert.equal(receipt.status, 1);
    assert.equal(await actionGate.consumedNullifier(authorization.nullifier), true);
    assert.equal(await consumer.consumeCount(), 1n);

    await assert.rejects(
      executeUserOp({ entryPoint, beneficiary, userOp: signedUserOp }),
      /reverted/
    );
  });
});
