const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const {
  PHILCORE_4337_EMPTY_BYTES,
  computePhilCore4337UserOperationHash,
  createPhilCore4337OwnerRotationCandidate,
  createPhilCore4337RecoveryAuthorityRotationCandidate,
  createPhilCore4337RecoveryCandidate,
  createUserSessionLifecycleSnapshot,
  generateDeviceVaultEcdsaValidator,
  bindDeviceVaultEcdsaValidatorAccountReference,
  markDeviceVaultEcdsaValidatorPendingRotation,
  revokeDeviceVaultEcdsaValidator
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const {
  createInMemoryDeviceIdentityRegistryStorageBackend,
  createLocalDevPassphraseKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");

const OWNER_COMMITMENT = ethers.id("philcore-n4-owner-commitment");
const POLICY_HASH = ethers.id("philcore-n4-policy");

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

async function fixture({ recoveryDelay = 60, recoveryExpiry = 3600 } = {}) {
  const [deployer, owner, newOwner, recovery, other, beneficiary, attacker] = await ethers.getSigners();
  const entryPoint = await deployEntryPoint();
  const ActionGate = await ethers.getContractFactory("PhilBaseActionGate");
  const actionGate = await ActionGate.deploy(ethers.ZeroAddress);
  const AccountFactory = await ethers.getContractFactory("PhilCore4337AccountFactory");
  const accountFactory = await AccountFactory.deploy(
    await entryPoint.getAddress(),
    await actionGate.getAddress(),
    recovery.address,
    recoveryDelay,
    recoveryExpiry
  );
  const Target = await ethers.getContractFactory("PhilSmartAccountExecutionTarget");
  const target = await Target.deploy();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  return { deployer, owner, newOwner, recovery, other, beneficiary, attacker, entryPoint, actionGate, accountFactory, target, chainId };
}

async function createAccount({ accountFactory, owner, ownerCommitment = OWNER_COMMITMENT, salt = 1n }) {
  const predicted = await accountFactory.getFunction("getAddress").staticCall(owner.address, ownerCommitment, salt);
  await (await accountFactory.createAccount(owner.address, ownerCommitment, salt)).wait();
  const account = await ethers.getContractAt("PhilCore4337Account", predicted);
  return { account, accountAddress: predicted };
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

async function executeUserOp({ entryPoint, beneficiary, userOp }) {
  return entryPoint.handleOps([userOp], beneficiary.address, { gasLimit: 7_000_000 });
}

function userOperationEvent(entryPoint, receipt) {
  return receipt.logs
    .map((log) => {
      try { return entryPoint.interface.parseLog(log); } catch { return null; }
    })
    .find((event) => event?.name === "UserOperationEvent");
}

async function actionGateCall({ actionGate, accountAddress, tag }) {
  const Consumer = await ethers.getContractFactory("PhilAuthorizationConsumerMock");
  const consumer = await Consumer.deploy();
  const consumerData = ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [accountAddress, ethers.id(tag)]);
  const authorization = {
    consumer: await consumer.getAddress(),
    ownerCommitment: OWNER_COMMITMENT,
    actionHash: ethers.id(`${tag}-action`),
    policyHash: POLICY_HASH,
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
    callData: actionGate.interface.encodeFunctionData("verifyAndConsume", [authorization, proofPackage, consumerData])
  };
}

async function signActionGateUserOp(env, signer, tag) {
  const { consumer, callData } = await actionGateCall({
    actionGate: env.actionGate,
    accountAddress: env.accountAddress,
    tag
  });
  const accountCallData = env.account.interface.encodeFunctionData("execute", [
    await env.actionGate.getAddress(),
    0,
    callData
  ]);
  const unsigned = userOpDefaults({
    sender: env.accountAddress,
    nonce: await env.entryPoint.getNonce(env.accountAddress, 0),
    callData: accountCallData
  });
  const { signedUserOp } = await signUserOp({
    entryPoint: env.entryPoint,
    userOp: unsigned,
    signer,
    chainId: env.chainId
  });
  return { consumer, signedUserOp };
}

async function latestRecoveryRequest(account) {
  const pending = await account.recoveryRequest();
  return {
    pendingOwner: pending[0],
    requestedAt: pending[1],
    executableAfter: pending[2],
    expiresAt: pending[3],
    requestId: pending[4],
    active: pending[5]
  };
}

async function latestRecoveryAuthorityRotationRequest(account) {
  const pending = await account.recoveryAuthorityRotationRequest();
  return {
    pendingRecoveryAuthority: pending[0],
    proposer: pending[1],
    requestedAt: pending[2],
    executableAfter: pending[3],
    expiresAt: pending[4],
    requestId: pending[5],
    active: pending[6]
  };
}

async function increase(seconds) {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}

function custodyEnv() {
  const lifecycleSnapshot = createUserSessionLifecycleSnapshot({
    sessionId: "n4-session",
    state: "unlocked",
    metadata: { deviceVaultUnlocked: true, protectedStateAvailable: true }
  });
  return {
    lifecycleSnapshot,
    unlockedVaultHandle: {
      handleId: "n4-vault-handle",
      sessionId: lifecycleSnapshot.sessionId,
      ownerCommitment: OWNER_COMMITMENT,
      envelopeId: "n4-envelope",
      unlockResultId: "n4-unlock",
      unlockedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
      processLocal: true,
      serializable: false,
      exportable: false,
      containsPlaintext: false,
      containsRawVaultKey: false,
      containsPhilSecret: false,
      applicationAccessible: false
    },
    storageBackend: createInMemoryDeviceIdentityRegistryStorageBackend(),
    keyProvider: createLocalDevPassphraseKeyProvider({
      passphrase: "n4-device-vault-rotation",
      scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
    })
  };
}

describe("PhilCore ERC-4337 restricted validator rotation and recovery", function () {
  it("executes two fresh authorizations on one deployed account without replaying initCode", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    await env.owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });

    const first = await signActionGateUserOp(
      { ...env, account, accountAddress },
      env.owner,
      "reusable-account-first"
    );
    assert.equal(first.signedUserOp.nonce, 0n);
    assert.equal(first.signedUserOp.initCode, "0x");
    await (await executeUserOp({
      entryPoint: env.entryPoint,
      beneficiary: env.beneficiary,
      userOp: first.signedUserOp
    })).wait();
    assert.equal(await first.consumer.consumeCount(), 1n);

    const second = await signActionGateUserOp(
      { ...env, account, accountAddress },
      env.owner,
      "reusable-account-second"
    );
    assert.equal(second.signedUserOp.nonce, 1n);
    assert.equal(second.signedUserOp.initCode, "0x");
    await (await executeUserOp({
      entryPoint: env.entryPoint,
      beneficiary: env.beneficiary,
      userOp: second.signedUserOp
    })).wait();
    assert.equal(await second.consumer.consumeCount(), 1n);
    assert.equal(await env.entryPoint.getNonce(accountAddress, 0), 2n);

    await assert.rejects(
      executeUserOp({
        entryPoint: env.entryPoint,
        beneficiary: env.beneficiary,
        userOp: first.signedUserOp
      }),
      /AA25 invalid account nonce|unrecognized custom error/
    );
  });

  it("rotates the execution owner without changing account address, ActionGate, EntryPoint, or ownerCommitment", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    await env.owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });
    const oldAddress = await account.getAddress();
    const actionGate = await account.approvedActionGate();
    const entryPoint = await account.entryPoint();
    const ownerCommitment = await account.ownerCommitment();

    await assert.rejects(account.connect(env.other).rotateExecutionOwner(env.newOwner.address), /UnauthorizedMaintenanceCaller/);
    await assert.rejects(account.connect(env.owner).rotateExecutionOwner(ethers.ZeroAddress), /InvalidOwner/);
    await assert.rejects(account.connect(env.owner).rotateExecutionOwner(env.owner.address), /InvalidOwner/);
    await (await account.connect(env.owner).rotateExecutionOwner(env.newOwner.address)).wait();

    assert.equal(await account.owner(), env.newOwner.address);
    assert.equal(await account.getAddress(), oldAddress);
    assert.equal(await account.approvedActionGate(), actionGate);
    assert.equal(await account.entryPoint(), entryPoint);
    assert.equal(await account.ownerCommitment(), ownerCommitment);

    const oldSigned = await signActionGateUserOp({ ...env, account, accountAddress }, env.owner, "old-owner");
    await assert.rejects(
      executeUserOp({ entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: oldSigned.signedUserOp }),
      /AA24 signature error|unrecognized custom error/
    );
    assert.equal(await oldSigned.consumer.consumeCount(), 0n);

    const newSigned = await signActionGateUserOp({ ...env, account, accountAddress }, env.newOwner, "new-owner");
    await (await executeUserOp({ entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: newSigned.signedUserOp })).wait();
    assert.equal(await newSigned.consumer.consumeCount(), 1n);
  });

  it("supports owner-signed EntryPoint rotation through the explicit maintenance selector only", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    await env.owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });
    const callData = account.interface.encodeFunctionData("rotateExecutionOwner", [env.newOwner.address]);
    const unsigned = userOpDefaults({
      sender: accountAddress,
      nonce: await env.entryPoint.getNonce(accountAddress, 0),
      callData
    });
    const { signedUserOp } = await signUserOp({ entryPoint: env.entryPoint, userOp: unsigned, signer: env.owner, chainId: env.chainId });
    await (await executeUserOp({ entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: signedUserOp })).wait();
    assert.equal(await account.owner(), env.newOwner.address);
  });

  it("releases only bounded disposable native balance and EntryPoint deposit to the current owner", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    const nativeAmount = ethers.parseEther("0.01");
    const depositBalance = ethers.parseEther("0.10");
    const depositAmount = ethers.parseEther("0.02");
    await env.deployer.sendTransaction({ to: accountAddress, value: nativeAmount });
    await env.entryPoint.depositTo(accountAddress, { value: depositBalance });

    const ownerBalanceBefore = await ethers.provider.getBalance(env.owner.address);
    const callData = account.interface.encodeFunctionData("releaseTestFunds", [
      nativeAmount,
      depositAmount
    ]);
    const unsigned = userOpDefaults({
      sender: accountAddress,
      nonce: await env.entryPoint.getNonce(accountAddress, 0),
      callData
    });
    const { signedUserOp } = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: unsigned,
      signer: env.owner,
      chainId: env.chainId
    });
    const receipt = await (await executeUserOp({
      entryPoint: env.entryPoint,
      beneficiary: env.beneficiary,
      userOp: signedUserOp
    })).wait();
    const operationEvent = userOperationEvent(env.entryPoint, receipt);
    assert.ok(operationEvent);

    assert.equal(await ethers.provider.getBalance(accountAddress), 0n);
    assert.equal(
      await env.entryPoint.balanceOf(accountAddress),
      depositBalance - depositAmount - operationEvent.args.actualGasCost
    );
    assert.equal(
      await ethers.provider.getBalance(env.owner.address),
      ownerBalanceBefore + nativeAmount + depositAmount
    );

    const replay = { ...signedUserOp, nonce: 0n };
    await assert.rejects(
      executeUserOp({ entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: replay }),
      /AA25 invalid account nonce|unrecognized custom error/
    );
  });

  it("supports a successful native-only test-fund release", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    const nativeAmount = ethers.parseEther("0.01");
    const depositBalance = ethers.parseEther("0.10");
    await env.deployer.sendTransaction({ to: accountAddress, value: nativeAmount });
    await env.entryPoint.depositTo(accountAddress, { value: depositBalance });
    const callData = account.interface.encodeFunctionData("releaseTestFunds", [nativeAmount, 0n]);
    const signed = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: userOpDefaults({ sender: accountAddress, nonce: 0n, callData }),
      signer: env.owner,
      chainId: env.chainId
    });
    const receipt = await (await executeUserOp({
      entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: signed.signedUserOp
    })).wait();
    const operationEvent = userOperationEvent(env.entryPoint, receipt);
    assert.equal(operationEvent.args.success, true);
    assert.equal(await ethers.provider.getBalance(accountAddress), 0n);
    assert.equal(
      await env.entryPoint.balanceOf(accountAddress),
      depositBalance - operationEvent.args.actualGasCost
    );
  });

  it("supports a successful EntryPoint-deposit-only test-fund release", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    const depositBalance = ethers.parseEther("0.10");
    const depositAmount = ethers.parseEther("0.02");
    await env.entryPoint.depositTo(accountAddress, { value: depositBalance });
    const ownerBefore = await ethers.provider.getBalance(env.owner.address);
    const callData = account.interface.encodeFunctionData("releaseTestFunds", [0n, depositAmount]);
    const signed = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: userOpDefaults({ sender: accountAddress, nonce: 0n, callData }),
      signer: env.owner,
      chainId: env.chainId
    });
    const receipt = await (await executeUserOp({
      entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: signed.signedUserOp
    })).wait();
    const operationEvent = userOperationEvent(env.entryPoint, receipt);
    assert.equal(operationEvent.args.success, true);
    assert.equal(await ethers.provider.getBalance(env.owner.address), ownerBefore + depositAmount);
    assert.equal(
      await env.entryPoint.balanceOf(accountAddress),
      depositBalance - depositAmount - operationEvent.args.actualGasCost
    );
  });

  it("includes but marks over-bound release amounts failed without transferring funds", async function () {
    for (const amounts of [[4n, 0n], [0n, ethers.parseEther("0.10")]]) {
      const env = await fixture();
      const { account, accountAddress } = await createAccount(env);
      await env.deployer.sendTransaction({ to: accountAddress, value: 3n });
      const depositBalance = ethers.parseEther("0.10");
      await env.entryPoint.depositTo(accountAddress, { value: depositBalance });
      const callData = account.interface.encodeFunctionData("releaseTestFunds", amounts);
      const signed = await signUserOp({
        entryPoint: env.entryPoint,
        userOp: userOpDefaults({ sender: accountAddress, nonce: 0n, callData }),
        signer: env.owner,
        chainId: env.chainId
      });
      const receipt = await (await executeUserOp({
        entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: signed.signedUserOp
      })).wait();
      const operationEvent = userOperationEvent(env.entryPoint, receipt);
      assert.equal(operationEvent.args.success, false);
      assert.equal(await env.entryPoint.getNonce(accountAddress, 0), 1n);
      assert.equal(await ethers.provider.getBalance(accountAddress), 3n);
      assert.equal(
        await env.entryPoint.balanceOf(accountAddress),
        depositBalance - operationEvent.args.actualGasCost
      );
    }
  });

  it("detects EntryPoint deposit withdrawal failure and rolls back the release", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    const depositBalance = ethers.parseEther("0.10");
    const depositAmount = ethers.parseEther("0.02");
    await env.entryPoint.depositTo(accountAddress, { value: depositBalance });
    await ethers.provider.send("hardhat_setCode", [env.owner.address, "0x60006000fd"]);
    const callData = account.interface.encodeFunctionData("releaseTestFunds", [0n, depositAmount]);
    const signed = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: userOpDefaults({ sender: accountAddress, nonce: 0n, callData }),
      signer: env.owner,
      chainId: env.chainId
    });
    const receipt = await (await executeUserOp({
      entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: signed.signedUserOp
    })).wait();
    const operationEvent = userOperationEvent(env.entryPoint, receipt);
    assert.equal(operationEvent.args.success, false);
    assert.equal(
      await env.entryPoint.balanceOf(accountAddress),
      depositBalance - operationEvent.args.actualGasCost
    );
  });

  it("detects native transfer failure and preserves the account native balance", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    const nativeAmount = ethers.parseEther("0.01");
    await env.deployer.sendTransaction({ to: accountAddress, value: nativeAmount });
    await env.entryPoint.depositTo(accountAddress, { value: ethers.parseEther("0.10") });
    await ethers.provider.send("hardhat_setCode", [env.owner.address, "0x60006000fd"]);
    const callData = account.interface.encodeFunctionData("releaseTestFunds", [nativeAmount, 0n]);
    const signed = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: userOpDefaults({ sender: accountAddress, nonce: 0n, callData }),
      signer: env.owner,
      chainId: env.chainId
    });
    const receipt = await (await executeUserOp({
      entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: signed.signedUserOp
    })).wait();
    assert.equal(userOperationEvent(env.entryPoint, receipt).args.success, false);
    assert.equal(await ethers.provider.getBalance(accountAddress), nativeAmount);
  });

  it("rejects recovery-authority fund release, zero release, and release while recovery is frozen", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    await env.deployer.sendTransaction({ to: accountAddress, value: 3n });

    const releaseCall = account.interface.encodeFunctionData("releaseTestFunds", [1n, 0n]);
    const recoverySigned = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: userOpDefaults({ sender: accountAddress, nonce: 0n, callData: releaseCall }),
      signer: env.recovery,
      chainId: env.chainId
    });
    await assert.rejects(
      executeUserOp({
        entryPoint: env.entryPoint,
        beneficiary: env.beneficiary,
        userOp: recoverySigned.signedUserOp
      }),
      /AA24 signature error|unrecognized custom error/
    );

    const zeroCall = account.interface.encodeFunctionData("releaseTestFunds", [0n, 0n]);
    const zeroSigned = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: userOpDefaults({ sender: accountAddress, nonce: 0n, callData: zeroCall }),
      signer: env.owner,
      chainId: env.chainId
    });
    await assert.rejects(
      executeUserOp({
        entryPoint: env.entryPoint,
        beneficiary: env.beneficiary,
        userOp: zeroSigned.signedUserOp
      }),
      /unrecognized custom error|FailedOp/
    );

    await account.connect(env.recovery).requestRecovery(env.newOwner.address);
    const frozenSigned = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: userOpDefaults({ sender: accountAddress, nonce: 0n, callData: releaseCall }),
      signer: env.owner,
      chainId: env.chainId
    });
    await assert.rejects(
      executeUserOp({
        entryPoint: env.entryPoint,
        beneficiary: env.beneficiary,
        userOp: frozenSigned.signedUserOp
      }),
      /AA24 signature error|unrecognized custom error/
    );
  });

  it("rejects a freshly owner-signed paymaster operation on chain", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    await env.deployer.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });
    const { callData } = await actionGateCall({
      actionGate: env.actionGate,
      accountAddress,
      tag: "paymaster-forbidden"
    });
    const accountCallData = account.interface.encodeFunctionData("execute", [
      await env.actionGate.getAddress(),
      0,
      callData
    ]);
    const paymasterAndData = ethers.concat([
      env.other.address,
      ethers.zeroPadValue("0x01", 16),
      ethers.zeroPadValue("0x01", 16)
    ]);
    const unsigned = userOpDefaults({
      sender: accountAddress,
      nonce: await env.entryPoint.getNonce(accountAddress, 0),
      callData: accountCallData,
      overrides: { paymasterAndData }
    });
    const { signedUserOp } = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: unsigned,
      signer: env.owner,
      chainId: env.chainId
    });
    await assert.rejects(
      executeUserOp({
        entryPoint: env.entryPoint,
        beneficiary: env.beneficiary,
        userOp: signedUserOp
      }),
      /AA23 reverted|unrecognized custom error/
    );
  });

  it("runs delayed recovery with freeze, owner cancellation, and no ordinary recovery-authority execution", async function () {
    const env = await fixture({ recoveryDelay: 120, recoveryExpiry: 600 });
    const { account, accountAddress } = await createAccount(env);
    await env.owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });

    await assert.rejects(account.connect(env.recovery).execute(await env.actionGate.getAddress(), 0, "0x12345678"), /UnauthorizedExecuteCaller/);
    await assert.rejects(account.connect(env.recovery).rotateExecutionOwner(env.newOwner.address), /UnauthorizedMaintenanceCaller/);
    await assert.rejects(account.connect(env.other).requestRecovery(env.newOwner.address), /UnauthorizedMaintenanceCaller/);

    await (await account.connect(env.recovery).requestRecovery(env.newOwner.address)).wait();
    assert.equal(await account.frozen(), true);
    const pending = await latestRecoveryRequest(account);
    assert.equal(pending.active, true);
    assert.equal(pending.pendingOwner, env.newOwner.address);

    const frozenSigned = await signActionGateUserOp({ ...env, account, accountAddress }, env.owner, "frozen-normal");
    await assert.rejects(
      executeUserOp({ entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: frozenSigned.signedUserOp }),
      /AA24 signature error|unrecognized custom error/
    );
    assert.equal(await frozenSigned.consumer.consumeCount(), 0n);

    await assert.rejects(account.connect(env.recovery).completeRecovery(pending.requestId, env.newOwner.address), /RecoveryDelayNotElapsed/);
    await (await account.connect(env.owner).cancelRecovery(pending.requestId)).wait();
    assert.equal(await account.frozen(), false);
    assert.equal((await latestRecoveryRequest(account)).active, false);

    await (await account.connect(env.recovery).requestRecovery(env.newOwner.address)).wait();
    const second = await latestRecoveryRequest(account);
    await increase(121);
    await (await account.connect(env.recovery).completeRecovery(second.requestId, env.newOwner.address)).wait();
    assert.equal(await account.owner(), env.newOwner.address);
    assert.equal(await account.frozen(), false);
    assert.equal((await latestRecoveryRequest(account)).active, false);
  });

  it("rejects expired, replayed, replacement, and wrong-pending-owner recovery attempts while allowing expired cancellation", async function () {
    const env = await fixture({ recoveryDelay: 10, recoveryExpiry: 30 });
    const { account } = await createAccount(env);
    await (await account.connect(env.recovery).requestRecovery(env.newOwner.address)).wait();
    await assert.rejects(account.connect(env.recovery).requestRecovery(env.other.address), /RecoveryAlreadyActive/);
    const pending = await latestRecoveryRequest(account);
    await increase(31);
    await assert.rejects(account.connect(env.recovery).completeRecovery(pending.requestId, env.newOwner.address), /RecoveryExpired/);
    await (await account.connect(env.owner).cancelRecovery(pending.requestId)).wait();
    assert.equal(await account.frozen(), false);

    await (await account.connect(env.recovery).requestRecovery(env.newOwner.address)).wait();
    const next = await latestRecoveryRequest(account);
    await increase(11);
    await assert.rejects(account.connect(env.recovery).completeRecovery(next.requestId, env.other.address), /RecoveryPendingOwnerMismatch/);
    await (await account.connect(env.recovery).completeRecovery(next.requestId, env.newOwner.address)).wait();
    await assert.rejects(account.connect(env.recovery).completeRecovery(next.requestId, env.newOwner.address), /RecoveryNotActive/);
  });

  it("keeps the factory address deterministic and stable after owner rotation", async function () {
    const env = await fixture();
    const salt = 99n;
    const predicted = await env.accountFactory.getFunction("getAddress").staticCall(env.owner.address, OWNER_COMMITMENT, salt);
    const changedOwner = await env.accountFactory.getFunction("getAddress").staticCall(env.newOwner.address, OWNER_COMMITMENT, salt);
    const OtherFactory = await ethers.getContractFactory("PhilCore4337AccountFactory");
    const otherFactory = await OtherFactory.deploy(
      await env.entryPoint.getAddress(),
      await env.actionGate.getAddress(),
      env.other.address,
      60,
      3600
    );
    const changedRecovery = await otherFactory.getFunction("getAddress").staticCall(env.owner.address, OWNER_COMMITMENT, salt);
    assert.notEqual(predicted, changedOwner);
    assert.notEqual(predicted, changedRecovery);

    await (await env.accountFactory.createAccount(env.owner.address, OWNER_COMMITMENT, salt)).wait();
    const account = await ethers.getContractAt("PhilCore4337Account", predicted);
    await (await account.connect(env.owner).rotateExecutionOwner(env.newOwner.address)).wait();
    assert.equal(await account.getAddress(), predicted);
  });

  it("rotates recovery authority through a delayed challenge without changing account identity", async function () {
    const env = await fixture({ recoveryDelay: 20, recoveryExpiry: 90 });
    const { account, accountAddress } = await createAccount(env);
    const originalEntryPoint = await account.entryPoint();
    const originalActionGate = await account.approvedActionGate();
    const originalOwnerCommitment = await account.ownerCommitment();
    const originalOwner = await account.owner();

    await assert.rejects(
      account.connect(env.owner).requestRecoveryAuthorityRotation(ethers.ZeroAddress, env.owner.address),
      /InvalidRecoveryAuthority/
    );
    await assert.rejects(
      account.connect(env.owner).requestRecoveryAuthorityRotation(env.recovery.address, env.owner.address),
      /InvalidRecoveryAuthority/
    );
    await assert.rejects(
      account.connect(env.owner).requestRecoveryAuthorityRotation(env.owner.address, env.owner.address),
      /InvalidRecoveryAuthority/
    );
    await assert.rejects(
      account.connect(env.attacker).requestRecoveryAuthorityRotation(env.other.address, env.attacker.address),
      /UnauthorizedMaintenanceCaller/
    );

    await (await account.connect(env.owner).requestRecoveryAuthorityRotation(env.other.address, env.owner.address)).wait();
    const pending = await latestRecoveryAuthorityRotationRequest(account);
    assert.equal(pending.active, true);
    assert.equal(pending.pendingRecoveryAuthority, env.other.address);
    assert.equal(pending.proposer, env.owner.address);
    assert.equal(await account.recoveryAuthority(), env.recovery.address);
    await assert.rejects(
      account.connect(env.owner).cancelRecoveryAuthorityRotation(pending.requestId, env.owner.address),
      /RecoveryAuthorityRotationUnauthorizedCanceller/
    );
    await assert.rejects(
      account.connect(env.attacker).completeRecoveryAuthorityRotation(pending.requestId, env.other.address),
      /RecoveryAuthorityRotationDelayNotElapsed/
    );
    await (await account.connect(env.recovery).cancelRecoveryAuthorityRotation(pending.requestId, env.recovery.address)).wait();
    assert.equal((await latestRecoveryAuthorityRotationRequest(account)).active, false);
    assert.equal(await account.recoveryAuthority(), env.recovery.address);

    await (await account.connect(env.recovery).requestRecoveryAuthorityRotation(env.other.address, env.recovery.address)).wait();
    const second = await latestRecoveryAuthorityRotationRequest(account);
    await assert.rejects(
      account.connect(env.recovery).cancelRecoveryAuthorityRotation(second.requestId, env.recovery.address),
      /RecoveryAuthorityRotationUnauthorizedCanceller/
    );
    await increase(21);
    await (await account.connect(env.attacker).completeRecoveryAuthorityRotation(second.requestId, env.other.address)).wait();
    assert.equal(await account.recoveryAuthority(), env.other.address);
    assert.equal((await latestRecoveryAuthorityRotationRequest(account)).active, false);
    assert.equal(await account.owner(), originalOwner);
    assert.equal(await account.ownerCommitment(), originalOwnerCommitment);
    assert.equal(await account.approvedActionGate(), originalActionGate);
    assert.equal(await account.entryPoint(), originalEntryPoint);
    assert.equal(await account.getAddress(), accountAddress);

    await assert.rejects(account.connect(env.recovery).requestRecovery(env.newOwner.address), /UnauthorizedMaintenanceCaller/);
    await (await account.connect(env.other).requestRecovery(env.newOwner.address)).wait();
    const recovery = await latestRecoveryRequest(account);
    assert.equal(recovery.active, true);
    assert.equal(recovery.pendingOwner, env.newOwner.address);
  });

  it("supports owner-signed EntryPoint recovery-authority rotation request and preserves old authority until completion", async function () {
    const env = await fixture({ recoveryDelay: 10, recoveryExpiry: 60 });
    const { account, accountAddress } = await createAccount(env);
    await env.owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });
    const callData = account.interface.encodeFunctionData("requestRecoveryAuthorityRotation", [
      env.other.address,
      env.owner.address
    ]);
    const unsigned = userOpDefaults({
      sender: accountAddress,
      nonce: await env.entryPoint.getNonce(accountAddress, 0),
      callData
    });
    const { signedUserOp } = await signUserOp({
      entryPoint: env.entryPoint,
      userOp: unsigned,
      signer: env.owner,
      chainId: env.chainId
    });
    await (await executeUserOp({ entryPoint: env.entryPoint, beneficiary: env.beneficiary, userOp: signedUserOp })).wait();
    const pending = await latestRecoveryAuthorityRotationRequest(account);
    assert.equal(pending.active, true);
    assert.equal(pending.proposer, env.owner.address);
    assert.equal(pending.pendingRecoveryAuthority, env.other.address);
    assert.equal(await account.recoveryAuthority(), env.recovery.address);

    await assert.rejects(
      account.connect(env.attacker).completeRecoveryAuthorityRotation(pending.requestId, env.other.address),
      /RecoveryAuthorityRotationDelayNotElapsed/
    );
    await increase(11);
    await (await account.connect(env.attacker).completeRecoveryAuthorityRotation(pending.requestId, env.other.address)).wait();
    assert.equal(await account.recoveryAuthority(), env.other.address);
  });

  it("rejects cancelled, expired, replayed, and mismatched recovery-authority rotation completion", async function () {
    const env = await fixture({ recoveryDelay: 10, recoveryExpiry: 20 });
    const { account } = await createAccount(env);
    await (await account.connect(env.owner).requestRecoveryAuthorityRotation(env.other.address, env.owner.address)).wait();
    await assert.rejects(
      account.connect(env.owner).requestRecoveryAuthorityRotation(env.attacker.address, env.owner.address),
      /RecoveryAuthorityRotationAlreadyActive/
    );
    const first = await latestRecoveryAuthorityRotationRequest(account);
    await assert.rejects(
      account.connect(env.attacker).completeRecoveryAuthorityRotation(first.requestId, env.attacker.address),
      /RecoveryAuthorityRotationPendingAuthorityMismatch/
    );
    await (await account.connect(env.recovery).cancelRecoveryAuthorityRotation(first.requestId, env.recovery.address)).wait();
    await assert.rejects(
      account.connect(env.attacker).completeRecoveryAuthorityRotation(first.requestId, env.other.address),
      /RecoveryAuthorityRotationNotActive/
    );

    await (await account.connect(env.owner).requestRecoveryAuthorityRotation(env.other.address, env.owner.address)).wait();
    const second = await latestRecoveryAuthorityRotationRequest(account);
    await increase(21);
    await assert.rejects(
      account.connect(env.attacker).completeRecoveryAuthorityRotation(second.requestId, env.other.address),
      /RecoveryAuthorityRotationExpired/
    );
    assert.equal(await account.recoveryAuthority(), env.recovery.address);
  });

  it("prepares runtime rotation/recovery candidates without signing or submitting", async function () {
    const env = await fixture();
    const { account, accountAddress } = await createAccount(env);
    const rotation = createPhilCore4337OwnerRotationCandidate({
      requestId: "n4-rotation",
      accountAddress,
      currentOwner: env.owner.address,
      newOwner: env.newOwner.address,
      ownerCommitment: OWNER_COMMITMENT,
      chainId: env.chainId
    });
    assert.equal(rotation.status, "approved");
    assert.equal(rotation.value.maintenanceSelector, account.interface.getFunction("rotateExecutionOwner").selector);
    assert.equal(rotation.value.privateKeyExposed, false);
    assert.equal(rotation.value.publicUserOperationSubmitted, false);
    assert.equal(rotation.value.ownerCommitmentChanged, false);

    const recovery = createPhilCore4337RecoveryCandidate({
      requestId: "n4-recovery",
      action: "request_recovery",
      accountAddress,
      recoveryAuthority: env.recovery.address,
      currentOwner: env.owner.address,
      pendingOwner: env.newOwner.address,
      ownerCommitment: OWNER_COMMITMENT,
      chainId: env.chainId
    });
    assert.equal(recovery.status, "approved");
    assert.equal(recovery.value.maintenanceSelector, account.interface.getFunction("requestRecovery").selector);
    assert.equal(recovery.value.recoveryAuthorityCanExecuteOrdinaryActions, false);
    assert.equal(recovery.value.recoveryAuthorityCanTransferAssets, false);

    const recoveryAuthorityRotation = createPhilCore4337RecoveryAuthorityRotationCandidate({
      requestId: "n8-recovery-authority-rotation",
      action: "request_recovery_authority_rotation",
      accountAddress,
      currentOwner: env.owner.address,
      currentRecoveryAuthority: env.recovery.address,
      pendingRecoveryAuthority: env.other.address,
      proposer: env.owner.address,
      ownerCommitment: OWNER_COMMITMENT,
      chainId: env.chainId
    });
    assert.equal(recoveryAuthorityRotation.status, "approved");
    assert.equal(
      recoveryAuthorityRotation.value.maintenanceSelector,
      account.interface.getFunction("requestRecoveryAuthorityRotation").selector
    );
    assert.equal(recoveryAuthorityRotation.value.pendingAuthorityActiveBeforeCompletion, false);
    assert.equal(recoveryAuthorityRotation.value.executionOwnerChanged, false);
    assert.equal(recoveryAuthorityRotation.value.accountAddressChanged, false);
    assert.equal(recoveryAuthorityRotation.value.publicUserOperationSubmitted, false);
  });

  it("coordinates Device Vault pending rotation without revoking old local key before on-chain success", async function () {
    const env = custodyEnv();
    const oldKey = await generateDeviceVaultEcdsaValidator({
      requestId: "n4-old-key",
      lifecycleSnapshot: env.lifecycleSnapshot,
      unlockedVaultHandle: env.unlockedVaultHandle,
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      ownerCommitment: OWNER_COMMITMENT,
      purpose: "erc4337_owner_validator_local_alpha",
      expiresAt: new Date(Date.now() + 300_000).toISOString()
    });
    const newKey = await generateDeviceVaultEcdsaValidator({
      requestId: "n4-new-key",
      lifecycleSnapshot: env.lifecycleSnapshot,
      unlockedVaultHandle: env.unlockedVaultHandle,
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      ownerCommitment: OWNER_COMMITMENT,
      purpose: "erc4337_owner_validator_local_alpha",
      expiresAt: new Date(Date.now() + 300_000).toISOString()
    });
    assert.equal(oldKey.status, "approved");
    assert.equal(newKey.status, "approved");
    const pending = await markDeviceVaultEcdsaValidatorPendingRotation({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: oldKey.value.keyReference
    });
    assert.equal(pending.status, "rotation_marked_pending");
    assert.equal(pending.onChainOwnerChanged, false);

    const bound = await bindDeviceVaultEcdsaValidatorAccountReference({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: newKey.value.keyReference,
      accountAddress: ethers.Wallet.createRandom().address,
      chainId: 31337
    });
    assert.equal(bound.status, "account_reference_bound");
    const revoked = await revokeDeviceVaultEcdsaValidator({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: oldKey.value.keyReference
    });
    assert.equal(revoked.status, "revoked");
    assert.equal(revoked.onChainOwnerChanged, false);
  });
});
