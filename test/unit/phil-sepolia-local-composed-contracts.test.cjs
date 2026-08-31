"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ethers } = require("hardhat");
const { p256 } = require("@noble/curves/p256");
const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");
require("tsx/cjs");
const mint = require("../../apps/phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const device = require("../../apps/phil-device-sdk/src/deviceApprovalV1.ts");
const deviceRequest = require("../../apps/phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts");
const workflow = require("../../apps/philcore-desktop/src/main/sepolia-mint-composed-workflow.cjs");
const { createSepoliaMintReplayStore } = require("../../apps/philcore-desktop/src/main/sepolia-mint-replay-store.cjs");

function packed128(high, low) {
  return ethers.toBeHex((BigInt(high) << 128n) | BigInt(low), 32);
}

async function deployEntryPoint(deployer) {
  const factory = new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  );
  const implementation = await factory.deploy();
  await implementation.waitForDeployment();
  const canonical = mint.PHIL_ETHEREUM_ENTRYPOINT_V07;
  const runtimeCode = await ethers.provider.getCode(await implementation.getAddress());
  await ethers.provider.send("hardhat_setCode", [canonical, runtimeCode]);
  return new ethers.Contract(canonical, EntryPointArtifact.abi, deployer);
}

async function deployFixture() {
  const [deployer, beneficiary, mismatchedRecipient, outsider] = await ethers.getSigners();
  const executionOwner = ethers.Wallet.createRandom().connect(ethers.provider);
  const entryPoint = await deployEntryPoint(deployer);
  const deployerNonce = await ethers.provider.getTransactionCount(deployer.address);
  const predictedFactory = ethers.getCreateAddress({ from: deployer.address, nonce: deployerNonce });
  const predictedGate = ethers.getCreateAddress({ from: deployer.address, nonce: deployerNonce + 1 });
  const predictedConsumer = ethers.getCreateAddress({ from: deployer.address, nonce: deployerNonce + 2 });

  const Factory = await ethers.getContractFactory("PhilSepoliaMintAccountFactoryV1", deployer);
  const factory = await Factory.deploy(await entryPoint.getAddress(), predictedGate);
  await factory.waitForDeployment();
  assert.equal((await factory.getAddress()).toLowerCase(), predictedFactory.toLowerCase());

  const ownerCommitment = ethers.id("phil-sepolia-local-composed-owner");
  const salt = BigInt(ethers.id("phil-sepolia-local-composed-salt"));
  const accountAddress = await factory.getFunction("getAddress").staticCall(
    executionOwner.address,
    ownerCommitment,
    salt
  );

  const Gate = await ethers.getContractFactory("PhilSepoliaLocalComposedActionGateV1", deployer);
  const gate = await Gate.deploy(11155111, predictedFactory, predictedConsumer, accountAddress);
  await gate.waitForDeployment();
  assert.equal((await gate.getAddress()).toLowerCase(), predictedGate.toLowerCase());

  const Consumer = await ethers.getContractFactory("PhilSepoliaMintPassConsumerV1", deployer);
  const consumer = await Consumer.deploy(predictedGate);
  await consumer.waitForDeployment();
  assert.equal((await consumer.getAddress()).toLowerCase(), predictedConsumer.toLowerCase());

  await deployer.sendTransaction({ to: accountAddress, value: ethers.parseEther("0.05") });
  return {
    deployer,
    beneficiary,
    recipient: executionOwner,
    mismatchedRecipient,
    outsider,
    executionOwner,
    entryPoint,
    factory,
    gate,
    consumer,
    ownerCommitment,
    salt,
    accountAddress
  };
}

async function buildSignedUserOperation(fixture, overrides = {}) {
  const now = BigInt((await ethers.provider.getBlock("latest")).timestamp);
  const envelopeDigest = overrides.envelopeDigest || ethers.id("mint-envelope-1");
  const rootNullifier = overrides.rootNullifier || ethers.id("root-nullifier-1");
  const approvalNonce = overrides.approvalNonce || ethers.id("approval-nonce-1");
  const validUntil = overrides.validUntil || now + 120n;
  const recipient = overrides.recipient || fixture.recipient.address;
  const gateData = fixture.gate.interface.encodeFunctionData("verifyAndConsume", [
    envelopeDigest,
    rootNullifier,
    approvalNonce,
    validUntil,
    recipient
  ]);
  const accountInterface = (await ethers.getContractFactory("PhilSepoliaMintAccountV1")).interface;
  const callData = accountInterface.encodeFunctionData("execute", [
    overrides.target || await fixture.gate.getAddress(),
    overrides.value || 0,
    gateData
  ]);
  const factoryData = fixture.factory.interface.encodeFunctionData("createAccount", [
    fixture.executionOwner.address,
    fixture.ownerCommitment,
    fixture.salt
  ]);
  const initCode = overrides.initCode === undefined
    ? ethers.concat([await fixture.factory.getAddress(), factoryData])
    : overrides.initCode;
  const operation = {
    sender: fixture.accountAddress,
    nonce: overrides.nonce || 0,
    initCode,
    callData,
    accountGasLimits: packed128(1_500_000, 500_000),
    preVerificationGas: 150_000,
    gasFees: packed128(1, 2),
    paymasterAndData: "0x",
    signature: "0x"
  };
  const userOperationHash = await fixture.entryPoint.getUserOpHash(operation);
  operation.signature = await fixture.executionOwner.signMessage(ethers.getBytes(userOperationHash));
  return { operation, userOperationHash, envelopeDigest, rootNullifier, approvalNonce, validUntil, recipient };
}

describe("Phil Sepolia local-composed ERC-4337 contracts", function () {
  it("executes the exact real-Noir, device-approved, Device-Vault-signed product operation", async function () {
    const f = await deployFixture();
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "phil-sepolia-contract-product-"));
    try {
      const devicePrivate = Buffer.from("43".repeat(32), "hex");
      const enrollment = device.createPhilDeviceEnrollmentRecordV1({
        deviceId: ethers.id("contract-product-device"),
        deviceKeyId: ethers.id("contract-product-device-key"),
        signatureSuiteId: mint.PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
        publicKey: p256.getPublicKey(devicePrivate, false),
        deviceEpoch: "1",
        enrolledAt: "1799999000",
        assuranceClass: 3,
        policyHash: ethers.id("contract-product-device-policy")
      });
      const block = await ethers.provider.getBlock("latest");
      const validAfter = BigInt(block.timestamp);
      const validUntil = validAfter + 300n;
      const bindingsInput = {
        factory: await f.factory.getAddress(),
        smartAccount: f.accountAddress,
        actionGate: await f.gate.getAddress(),
        mintConsumer: await f.consumer.getAddress(),
        mintRecipient: f.recipient.address,
        accountNonce: "0",
        validAfter: validAfter.toString(),
        validUntil: validUntil.toString(),
        maximumTotalFeeWei: "2500000000000000"
      };
      const prepared = await workflow.preparePhilSepoliaMintComposedWorkflow({
        repositoryRoot: path.resolve(__dirname, "../.."),
        protectedMaterial: { philSecret: `0x${"07".repeat(32)}` },
        bindingsInput,
        epochs: { scopeEpoch: "1", deviceEpoch: "1", recoveryEpoch: "1", validatorEpoch: "1" },
        enrollment,
        executionOwner: f.executionOwner.address,
        ownerCommitment: f.ownerCommitment,
        accountSalt: f.salt.toString(),
        accountDeployed: false,
        gas: { callGasLimit: "500000", verificationGasLimit: "1500000", preVerificationGas: "150000", maxFeePerGas: "2", maxPriorityFeePerGas: "1" },
        dependencies: { randomBytes: () => Buffer.from("08".repeat(32), "hex") }
      });
      const ceremony = prepared.createDeviceRequest({
        sessionId: ethers.id("contract-product-session"),
        approvalNonce: ethers.id("contract-product-approval-nonce"),
        now: validAfter.toString()
      });
      const p256Signature = p256.sign(ceremony.request.deviceApprovalDigest.slice(2), devicePrivate, { lowS: true, prehash: false });
      const response = deviceRequest.createPhilSepoliaMintDeviceResponseV1({
        request: ceremony.request,
        enrollment,
        signature: ethers.concat([ethers.toBeHex(p256Signature.r, 32), ethers.toBeHex(p256Signature.s, 32)])
      });
      const replayStore = createSepoliaMintReplayStore({
        ledgerPath: path.join(temporary, "replay.json"),
        now: () => "2026-08-24T22:00:00.000Z"
      });
      const descriptor = {
        signerId: "device-vault-contract-product",
        mode: "device_vault_beta_ecdsa",
        ownerAddress: f.executionOwner.address,
        keyReference: { keyReferenceId: "encrypted-contract-product-key", mode: "device_vault_beta_ecdsa", custody: "device_vault_encrypted", privateKeyExportable: false, derivedFromPhilSecret: false },
        available: true,
        productionApproved: false,
        arbitraryMessageSigning: false,
        arbitraryTransactionSigning: false
      };
      const signed = await workflow.completePhilSepoliaMintComposedWorkflow({
        repositoryRoot: path.resolve(__dirname, "../.."),
        context: ceremony.context,
        request: ceremony.request,
        response,
        enrollment,
        replayStore,
        trustedState: { now: validAfter.toString(), scopeEpoch: "1", deviceEpoch: "1", recoveryEpoch: "1", validatorEpoch: "1", accountNonce: "0", valueWei: "0", maximumTotalFeeWei: bindingsInput.maximumTotalFeeWei, emergencyStop: false, scopeActive: true, policyActive: true, proofDescriptorActive: true, deviceActive: true, recoveryStateCurrent: true, validatorActive: true, cancelled: false, denied: false },
        createDeviceVaultSigner: async () => ({
          describeSigner: async () => descriptor,
          checkAvailability: async () => descriptor,
          getOwnerAddress: async () => f.executionOwner.address,
          signUserOperationHash: async (request) => ({ status: "signed", signature: await f.executionOwner.signMessage(ethers.getBytes(request.userOperationHash)), signerDescriptor: descriptor, signedAt: "2026-08-24T22:00:00.000Z" }),
          invalidateSigningSession: async () => {}
        })
      });
      assert.equal(signed.userOperationHash, await f.entryPoint.getUserOpHash(signed.userOperation));
      await (await f.entryPoint.handleOps([signed.userOperation], f.beneficiary.address)).wait();
      assert.equal(await f.consumer.tokenIdByEnvelopeDigest(signed.authorizationEnvelopeDigest), 1n);
      assert.equal(await f.consumer.ownerOf(1), f.recipient.address);
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  });

  it("counterfactually deploys and mints exactly one zero-value pass through the restricted gate", async function () {
    const f = await deployFixture();
    const built = await buildSignedUserOperation(f);
    await (await f.entryPoint.handleOps([built.operation], f.beneficiary.address)).wait();

    assert.equal(await f.factory.isPhilSepoliaMintAccount(f.accountAddress), true);
    assert.equal(await f.gate.consumedEnvelopeDigest(built.envelopeDigest), true);
    assert.equal(await f.gate.consumedRootNullifier(built.rootNullifier), true);
    assert.equal(await f.gate.consumedDeviceApprovalNonce(built.approvalNonce), true);
    assert.equal(await f.consumer.tokenIdByEnvelopeDigest(built.envelopeDigest), 1n);
    assert.equal(await f.consumer.ownerOf(1), built.recipient);
    assert.equal(await f.consumer.balanceOf(built.recipient), 1n);
  });

  it("rejects unregistered callers, wrong signatures, post-approval mutation, replay, expiry, target, and value", async function () {
    const f = await deployFixture();
    const first = await buildSignedUserOperation(f);
    await assert.rejects(
      f.gate.connect(f.outsider).verifyAndConsume(
        first.envelopeDigest,
        first.rootNullifier,
        first.approvalNonce,
        first.validUntil,
        first.recipient
      ),
      /UnauthorizedAccount/u
    );

    const wrongSigner = await buildSignedUserOperation(f);
    wrongSigner.operation.signature = await f.outsider.signMessage(
      ethers.getBytes(wrongSigner.userOperationHash)
    );
    await assert.rejects(
      f.entryPoint.handleOps([wrongSigner.operation], f.beneficiary.address),
      /AA24|signature error|220266b6|41413234/u
    );

    const mutated = await buildSignedUserOperation(f);
    mutated.operation.callData = `${mutated.operation.callData.slice(0, -40)}${f.outsider.address.slice(2)}`;
    await assert.rejects(
      f.entryPoint.handleOps([mutated.operation], f.beneficiary.address),
      /AA24|signature error|220266b6|41413234/u
    );

    await (await f.entryPoint.handleOps([first.operation], f.beneficiary.address)).wait();
    const replay = await buildSignedUserOperation(f, { initCode: "0x", nonce: 1 });
    await (await f.entryPoint.handleOps([replay.operation], f.beneficiary.address)).wait();
    assert.equal(await f.consumer.nextTokenId(), 2n);

    const expired = await buildSignedUserOperation(f, {
      initCode: "0x",
      nonce: 2,
      envelopeDigest: ethers.id("expired-envelope"),
      rootNullifier: ethers.id("expired-nullifier"),
      approvalNonce: ethers.id("expired-approval"),
      validUntil: 1n
    });
    await (await f.entryPoint.handleOps([expired.operation], f.beneficiary.address)).wait();
    assert.equal(await f.consumer.nextTokenId(), 2n);

    const wrongTarget = await buildSignedUserOperation(f, {
      initCode: "0x",
      nonce: 3,
      target: await f.consumer.getAddress(),
      envelopeDigest: ethers.id("wrong-target-envelope"),
      rootNullifier: ethers.id("wrong-target-nullifier"),
      approvalNonce: ethers.id("wrong-target-approval")
    });
    await (await f.entryPoint.handleOps([wrongTarget.operation], f.beneficiary.address)).wait();
    assert.equal(await f.consumer.nextTokenId(), 2n);

    const nonZero = await buildSignedUserOperation(f, {
      initCode: "0x",
      nonce: 4,
      value: 1,
      envelopeDigest: ethers.id("value-envelope"),
      rootNullifier: ethers.id("value-nullifier"),
      approvalNonce: ethers.id("value-approval")
    });
    await (await f.entryPoint.handleOps([nonZero.operation], f.beneficiary.address)).wait();
    assert.equal(await f.consumer.nextTokenId(), 2n);
  });

  it("fuzzes signed-operation mutation and gate replay invariants", async function () {
    const f = await deployFixture();
    for (let index = 0; index < 48; index += 1) {
      const built = await buildSignedUserOperation(f);
      const field = ["callData", "accountGasLimits", "preVerificationGas", "gasFees"][index % 4];
      if (field === "preVerificationGas") {
        built.operation[field] = BigInt(built.operation[field]) + BigInt(index + 1);
      } else {
        const bytes = ethers.getBytes(built.operation[field]);
        const offset = index % bytes.length;
        bytes[offset] ^= 1 << (index % 8);
        built.operation[field] = ethers.hexlify(bytes);
      }
      await assert.rejects(
        f.entryPoint.handleOps([built.operation], f.beneficiary.address),
        /AA24|signature error|220266b6|41413234/u
      );
    }

    for (const malformedLength of [1, 31, 63, 64, 66, 96]) {
      const built = await buildSignedUserOperation(f);
      built.operation.signature = `0x${"11".repeat(malformedLength)}`;
      await assert.rejects(
        f.entryPoint.handleOps([built.operation], f.beneficiary.address),
        /AA24|signature error|220266b6|41413234/u
      );
    }

    await f.factory.createAccount(f.executionOwner.address, f.ownerCommitment, f.salt);
    await ethers.provider.send("hardhat_impersonateAccount", [f.accountAddress]);
    await f.deployer.sendTransaction({ to: f.accountAddress, value: ethers.parseEther("1") });
    const accountCaller = await ethers.getSigner(f.accountAddress);
    const latest = await ethers.provider.getBlock("latest");
    try {
      for (let index = 0; index < 32; index += 1) {
        const envelope = ethers.keccak256(ethers.solidityPacked(["string", "uint256"], ["fuzz-envelope", index]));
        const nullifier = ethers.keccak256(ethers.solidityPacked(["string", "uint256"], ["fuzz-nullifier", index]));
        const approval = ethers.keccak256(ethers.solidityPacked(["string", "uint256"], ["fuzz-approval", index]));
        await f.gate.connect(accountCaller).verifyAndConsume(
          envelope,
          nullifier,
          approval,
          BigInt(latest.timestamp) + 3600n,
          f.recipient.address
        );
        const tokenId = BigInt(index + 1);
        assert.equal(await f.consumer.tokenIdByEnvelopeDigest(envelope), tokenId);
        assert.equal(await f.consumer.tokenIdByRootNullifier(nullifier), tokenId);
        await assert.rejects(
          f.gate.connect(accountCaller).verifyAndConsume(
            envelope,
            ethers.id(`alternate-nullifier-${index}`),
            ethers.id(`alternate-approval-${index}`),
            BigInt(latest.timestamp) + 3600n,
            f.recipient.address
          ),
          /EnvelopeAlreadyConsumed/u
        );
      }
      assert.equal(await f.consumer.nextTokenId(), 33n);
      assert.equal(await f.consumer.balanceOf(f.recipient.address), 32n);
    } finally {
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [f.accountAddress]);
    }
  });
});
