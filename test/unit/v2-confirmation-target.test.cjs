const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const CONTRACT_NAME = "PhilCoreV2ConfirmationTargetV1";

const ACCOUNT_VERSION_ID =
  "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f";
const SECURITY_MODEL_ID = ethers.id(
  "philcore-v2-typed-intent-local-proof-gated-v1"
);
const WRONG_ACCOUNT_VERSION_ID = ethers.id("wrong-account-version");
const WRONG_SECURITY_MODEL_ID = ethers.id("wrong-security-model");
const IDENTITY_BINDING_TYPEHASH =
  "0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8";
const OWNER_COMMITMENT_SCHEME_ID =
  "0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e";
const VALIDATOR_COMMITMENT_TYPEHASH = ethers.id(
  "PhilCoreV2ValidatorCommitment(uint8 verifierKind,address validator,bytes32 validatorKeyIdBinding)"
);
const RECOVERY_CONFIGURATION_TYPEHASH = ethers.id(
  "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"
);
const INTENT_CORE_HEADER_TYPEHASH = ethers.id(
  "PhilCoreV2IntentCoreHeader(uint8 specificationVersion,bytes32 securityModelId,uint8 actionType,bytes32 actionId,bytes32 purpose,bytes32 ownerCommitment,uint256 chainId,address entryPoint,address account,uint192 nonceKey,uint64 nonceSequence,uint64 validatorEpoch,uint64 recoveryEpoch,bytes32 applicationContextHash,bytes32 fundLifecycleDigest,uint256 maxTotalFeeWei,uint48 validAfter,uint48 validUntil)"
);
const AUTHORIZED_INTENT_TYPEHASH = ethers.id(
  "PhilCoreV2AuthorizedIntent(bytes32 intentCoreHash,bytes32 runtimeAuthorizationDigest)"
);
const CONFIRM_TYPEHASH = ethers.id(
  "PhilCoreV2ConfirmIntent(bytes32 coreHeaderHash,address confirmationTarget,bytes32 confirmationDigest)"
);
const ACTION_CONFIRM = 1;
const PURPOSE_CONFIRM = ethers.id("PHILCORE_V2_PURPOSE_CONFIRM_ACTION");

const abi = ethers.AbiCoder.defaultAbiCoder();

function packUints(high128, low128) {
  return ethers.toBeHex((BigInt(high128) << 128n) | BigInt(low128), 32);
}

function identityBinding(ownerCommitment) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "uint8", "bytes32", "bytes32"],
      [
        IDENTITY_BINDING_TYPEHASH,
        1,
        ownerCommitment,
        OWNER_COMMITMENT_SCHEME_ID
      ]
    )
  );
}

function validatorCommitment(validator, keyBinding) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "uint8", "address", "bytes32"],
      [VALIDATOR_COMMITMENT_TYPEHASH, 1, validator, keyBinding]
    )
  );
}

function recoveryConfigHash(primary, hardware, independent) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
      [RECOVERY_CONFIGURATION_TYPEHASH, 3, 2, primary, hardware, independent]
    )
  );
}

function headerHash(core) {
  return ethers.keccak256(
    abi.encode(
      [
        "bytes32",
        "uint8",
        "bytes32",
        "uint8",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint256",
        "address",
        "address",
        "uint192",
        "uint64",
        "uint64",
        "uint64",
        "bytes32",
        "bytes32",
        "uint256",
        "uint48",
        "uint48"
      ],
      [
        INTENT_CORE_HEADER_TYPEHASH,
        core.specificationVersion,
        core.securityModelId,
        core.actionType,
        core.actionId,
        core.purpose,
        core.ownerCommitment,
        core.chainId,
        core.entryPoint,
        core.account,
        core.nonceKey,
        core.nonceSequence,
        core.validatorEpoch,
        core.recoveryEpoch,
        core.applicationContextHash,
        core.fundLifecycleDigest,
        core.maxTotalFeeWei,
        core.validAfter,
        core.validUntil
      ]
    )
  );
}

function confirmCoreHash(core, digest, confirmationTargetAddress) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "address", "bytes32"],
      [CONFIRM_TYPEHASH, headerHash(core), confirmationTargetAddress, digest]
    )
  );
}

function authorizedIntentHash(intent, intentCoreHash) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32"],
      [
        AUTHORIZED_INTENT_TYPEHASH,
        intentCoreHash,
        intent.runtimeAuthorizationDigest
      ]
    )
  );
}

function initialization({
  entryPoint,
  chainId,
  ownerCommitment,
  factory,
  confirmationTarget,
  validator,
  validatorKey,
  primary,
  hardware,
  independent
}) {
  return {
    entryPoint,
    deploymentChainId: chainId,
    ownerCommitment,
    identityBindingCommitment: identityBinding(ownerCommitment),
    factoryBinding: factory,
    accountVersionId: ACCOUNT_VERSION_ID,
    securityModelId: SECURITY_MODEL_ID,
    confirmationTarget,
    initialValidator: validator,
    validatorVerifierKind: 1,
    validatorKeyIdBinding: validatorKey,
    validatorCommitment: validatorCommitment(validator, validatorKey),
    validatorEpoch: 1,
    primaryDeviceRecoveryCommitment: primary,
    hardwareSecurityKeyCommitment: hardware,
    independentRecoveryFactorCommitment: independent,
    recoveryConfigurationHash: recoveryConfigHash(primary, hardware, independent),
    recoveryEpoch: 1,
    recoveryDelaySeconds: 172800,
    recoveryExpirySeconds: 604800
  };
}

async function deployEntryPoint(deployer) {
  return new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
}

async function deployTarget() {
  const Target = await ethers.getContractFactory(CONTRACT_NAME);
  return Target.deploy();
}

async function deployConfigMock(
  target,
  {
    entryPoint = ethers.ZeroAddress,
    deploymentChainId,
    ownerCommitment = ethers.id("mock-owner"),
    identityBindingCommitmentValue,
    factoryBinding = ethers.ZeroAddress,
    accountVersionId = ACCOUNT_VERSION_ID,
    securityModelId = SECURITY_MODEL_ID,
    confirmationTarget
  } = {}
) {
  const chainId = deploymentChainId ?? (await ethers.provider.getNetwork()).chainId;
  const targetAddress = confirmationTarget ?? (await target.getAddress());
  const identityBindingCommitmentResolved =
    identityBindingCommitmentValue ?? identityBinding(ownerCommitment);
  const Mock = await ethers.getContractFactory(
    "PhilCoreV2ConfirmationTargetConfigMock"
  );
  return Mock.deploy(
    entryPoint,
    chainId,
    ownerCommitment,
    identityBindingCommitmentResolved,
    factoryBinding,
    accountVersionId,
    securityModelId,
    targetAddress
  );
}

async function fixture() {
  const [deployer, other, attacker] = await ethers.getSigners();
  const target = await deployTarget();
  const goodCaller = await deployConfigMock(target);
  return { deployer, other, attacker, target, goodCaller };
}

describe("PhilCoreV2ConfirmationTargetV1", function () {
  it("rejects direct EOA calls before any external read", async function () {
    const { target, deployer } = await fixture();
    await assert.rejects(
      target.connect(deployer).confirmPhilCoreAction(
        ethers.id("eoa-action"),
        ethers.id("eoa-digest")
      ),
      /CallerIsNotContract/
    );
  });

  it("rejects when the caller's accountConfiguration() call reverts", async function () {
    const { target } = await fixture();
    const Reverting = await ethers.getContractFactory(
      "PhilCoreV2ConfirmationTargetRevertingConfigMock"
    );
    const caller = await Reverting.deploy();
    await assert.rejects(
      caller.confirm(
        await target.getAddress(),
        ethers.id("reverting-config-action"),
        ethers.id("reverting-config-digest")
      )
    );
  });

  it("rejects when the caller has no accountConfiguration() function at all", async function () {
    const { target } = await fixture();
    const NoConfig = await ethers.getContractFactory(
      "PhilCoreV2ConfirmationTargetNoConfigMock"
    );
    const caller = await NoConfig.deploy();
    await assert.rejects(
      caller.confirm(
        await target.getAddress(),
        ethers.id("missing-config-action"),
        ethers.id("missing-config-digest")
      )
    );
  });

  it("rejects when the caller's accountConfiguration() returns a malformed/wrong-shaped tuple", async function () {
    const { target } = await fixture();
    const Malformed = await ethers.getContractFactory(
      "PhilCoreV2ConfirmationTargetMalformedConfigMock"
    );
    const caller = await Malformed.deploy();
    await assert.rejects(
      caller.confirm(
        await target.getAddress(),
        ethers.id("malformed-config-action"),
        ethers.id("malformed-config-digest")
      )
    );
  });

  it("rejects a wrong deploymentChainId (chain binding mismatch)", async function () {
    const { target } = await fixture();
    const chainId = (await ethers.provider.getNetwork()).chainId;
    const caller = await deployConfigMock(target, {
      deploymentChainId: chainId + 1n
    });
    await assert.rejects(
      caller.confirm(
        await target.getAddress(),
        ethers.id("wrong-chain-action"),
        ethers.id("wrong-chain-digest")
      ),
      /ChainBindingMismatch/
    );
  });

  it("rejects a wrong confirmationTarget (target binding mismatch)", async function () {
    const { target, other } = await fixture();
    const caller = await deployConfigMock(target, {
      confirmationTarget: other.address
    });
    await assert.rejects(
      caller.confirm(
        await target.getAddress(),
        ethers.id("wrong-target-action"),
        ethers.id("wrong-target-digest")
      ),
      /TargetBindingMismatch/
    );
  });

  it("rejects a wrong accountVersionId", async function () {
    const { target } = await fixture();
    const caller = await deployConfigMock(target, {
      accountVersionId: WRONG_ACCOUNT_VERSION_ID
    });
    await assert.rejects(
      caller.confirm(
        await target.getAddress(),
        ethers.id("wrong-version-action"),
        ethers.id("wrong-version-digest")
      ),
      /UnsupportedAccountVersion/
    );
  });

  it("rejects a wrong securityModelId", async function () {
    const { target } = await fixture();
    const caller = await deployConfigMock(target, {
      securityModelId: WRONG_SECURITY_MODEL_ID
    });
    await assert.rejects(
      caller.confirm(
        await target.getAddress(),
        ethers.id("wrong-security-action"),
        ethers.id("wrong-security-digest")
      ),
      /UnsupportedSecurityModel/
    );
  });

  it("rejects a zero actionId", async function () {
    const { target, goodCaller } = await fixture();
    await assert.rejects(
      goodCaller.confirm(
        await target.getAddress(),
        ethers.ZeroHash,
        ethers.id("zero-action-digest")
      ),
      /InvalidActionId/
    );
  });

  it("rejects a zero authorizationDigest", async function () {
    const { target, goodCaller } = await fixture();
    await assert.rejects(
      goodCaller.confirm(
        await target.getAddress(),
        ethers.id("zero-digest-action"),
        ethers.ZeroHash
      ),
      /InvalidAuthorizationDigest/
    );
  });

  it("rejects a duplicate confirmation of the same actionId from the same caller", async function () {
    const { target, goodCaller } = await fixture();
    const actionId = ethers.id("duplicate-action");
    await (
      await goodCaller.confirm(
        await target.getAddress(),
        actionId,
        ethers.id("duplicate-digest-1")
      )
    ).wait();
    await assert.rejects(
      goodCaller.confirm(
        await target.getAddress(),
        actionId,
        ethers.id("duplicate-digest-2")
      ),
      /ActionAlreadyConfirmed/
    );
  });

  it("records the exact state and emits the exact event on a valid confirmation", async function () {
    const { target, goodCaller } = await fixture();
    const targetAddress = await target.getAddress();
    const callerAddress = await goodCaller.getAddress();
    const actionId = ethers.id("exact-event-action");
    const digest = ethers.id("exact-event-digest");

    assert.equal(await target.confirmedAction(callerAddress, actionId), false);

    const tx = await goodCaller.confirm(targetAddress, actionId, digest);
    const receipt = await tx.wait();

    assert.equal(await target.confirmedAction(callerAddress, actionId), true);

    const parsedLogs = receipt.logs
      .map((log) => {
        try {
          return target.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .filter((parsed) => parsed && parsed.name === "PhilCoreV2ActionConfirmed");
    assert.equal(parsedLogs.length, 1);
    const event = parsedLogs[0];
    assert.equal(event.args.account, callerAddress);
    assert.equal(event.args.actionId, actionId);
    assert.equal(event.args.authorizationDigest, digest);
  });

  it("scopes the same actionId independently across distinct callers", async function () {
    const { target } = await fixture();
    const targetAddress = await target.getAddress();
    const callerA = await deployConfigMock(target);
    const callerB = await deployConfigMock(target, {
      ownerCommitment: ethers.id("mock-owner-b")
    });
    const actionId = ethers.id("shared-action-id");

    await (
      await callerA.confirm(targetAddress, actionId, ethers.id("digest-a"))
    ).wait();
    await (
      await callerB.confirm(targetAddress, actionId, ethers.id("digest-b"))
    ).wait();

    assert.equal(
      await target.confirmedAction(await callerA.getAddress(), actionId),
      true
    );
    assert.equal(
      await target.confirmedAction(await callerB.getAddress(), actionId),
      true
    );
    await assert.rejects(
      callerA.confirm(targetAddress, actionId, ethers.id("digest-a-2")),
      /ActionAlreadyConfirmed/
    );
    await assert.rejects(
      callerB.confirm(targetAddress, actionId, ethers.id("digest-b-2")),
      /ActionAlreadyConfirmed/
    );
  });

  it("has no payable surface: no receive, no fallback, and confirmPhilCoreAction is not payable", async function () {
    const { target, deployer } = await fixture();
    const targetAddress = await target.getAddress();

    await assert.rejects(
      deployer.sendTransaction({ to: targetAddress, value: 1n })
    );

    const fragment = target.interface.getFunction("confirmPhilCoreAction");
    assert.equal(fragment.payable, false);
    assert.equal(fragment.stateMutability, "nonpayable");

    await assert.rejects(
      target.confirmPhilCoreAction(
        ethers.id("payable-probe-action"),
        ethers.id("payable-probe-digest"),
        { value: 1n }
      )
    );

    assert.equal(await ethers.provider.getBalance(targetAddress), 0n);
  });

  it("exposes only the narrow expected ABI surface", async function () {
    const { target } = await fixture();
    const functions = target.interface.fragments.filter(
      (fragment) => fragment.type === "function"
    );
    const names = functions.map((fragment) => fragment.name).sort();
    assert.deepEqual(names, [
      "ACCOUNT_VERSION_ID",
      "SECURITY_MODEL_ID",
      "confirmPhilCoreAction",
      "confirmedAction"
    ]);

    for (const forbidden of [
      "owner",
      "admin",
      "upgradeTo",
      "setAdmin",
      "execute",
      "executeBatch",
      "transfer",
      "transferOwnership",
      "receive",
      "fallback",
      "lastAccount",
      "lastActionId",
      "lastAuthorizationDigest",
      "confirmationCount"
    ]) {
      assert(!names.includes(forbidden), `unexpected surface: ${forbidden}`);
    }

    assert.equal(await target.ACCOUNT_VERSION_ID(), ACCOUNT_VERSION_ID);
    assert.equal(await target.SECURITY_MODEL_ID(), SECURITY_MODEL_ID);
  });

  describe("integration with PhilCoreV2MinimalAccountV2", function () {
    async function integrationFixture() {
      const [deployer, validator, recipient, beneficiary, attacker] =
        await ethers.getSigners();
      const chainId = (await ethers.provider.getNetwork()).chainId;
      const entryPoint = await deployEntryPoint(deployer);
      const target = await deployTarget();
      const Verifier = await ethers.getContractFactory(
        "PhilCoreV2AuthorityVerifierMock"
      );
      const verifier = await Verifier.deploy("0x15c57f54", false);
      const verifierAddress = await verifier.getAddress();
      const verifierCodeHash = ethers.keccak256(
        await ethers.provider.getCode(verifierAddress)
      );
      const Factory = await ethers.getContractFactory(
        "PhilCoreV2MinimalAccountFactoryV2"
      );
      const factory = await Factory.deploy(
        await entryPoint.getAddress(),
        chainId,
        await target.getAddress(),
        verifierAddress,
        verifierCodeHash
      );
      const values = {
        ownerCommitment: ethers.id("v2-confirmation-target-owner"),
        validatorKey: ethers.id("v2-confirmation-target-validator-key"),
        primary: ethers.id("v2-confirmation-target-primary"),
        hardware: ethers.id("v2-confirmation-target-hardware"),
        independent: ethers.id("v2-confirmation-target-independent"),
        userSalt: ethers.id("v2-confirmation-target-user-salt")
      };
      const init = initialization({
        entryPoint: await entryPoint.getAddress(),
        chainId,
        ownerCommitment: values.ownerCommitment,
        factory: await factory.getAddress(),
        confirmationTarget: await target.getAddress(),
        validator: validator.address,
        validatorKey: values.validatorKey,
        primary: values.primary,
        hardware: values.hardware,
        independent: values.independent
      });
      const predicted = await factory
        .getFunction("getAddress")
        .staticCall(init, values.userSalt);
      await (await factory.createAccount(init, values.userSalt)).wait();
      const account = await ethers.getContractAt(
        "PhilCoreV2MinimalAccountV2",
        predicted
      );
      await (
        await entryPoint.depositTo(predicted, { value: ethers.parseEther("2") })
      ).wait();
      return {
        deployer,
        validator,
        recipient,
        beneficiary,
        attacker,
        chainId,
        entryPoint,
        target,
        factory,
        init,
        account,
        accountAddress: predicted,
        ...values
      };
    }

    async function buildConfirmOperation(env, { digest, signer = env.validator }) {
      const latest = await ethers.provider.getBlock("latest");
      const nonce = await env.entryPoint.getNonce(env.accountAddress, 0);
      const actionId = ethers.id(`v2-confirmation-target-action-${nonce}`);
      const core = {
        specificationVersion: 1,
        securityModelId: SECURITY_MODEL_ID,
        actionType: ACTION_CONFIRM,
        actionId,
        purpose: PURPOSE_CONFIRM,
        ownerCommitment: env.ownerCommitment,
        chainId: env.chainId,
        entryPoint: await env.entryPoint.getAddress(),
        account: env.accountAddress,
        nonceKey: 0n,
        nonceSequence: BigInt(nonce) & ((1n << 64n) - 1n),
        validatorEpoch: 1n,
        recoveryEpoch: 1n,
        applicationContextHash: ethers.id("v2-confirmation-target-context"),
        fundLifecycleDigest: ethers.id("v2-confirmation-target-fund-lifecycle"),
        maxTotalFeeWei: ethers.parseEther("1"),
        validAfter: BigInt(latest.timestamp - 1),
        validUntil: BigInt(latest.timestamp + 500)
      };
      const intent = {
        core,
        runtimeAuthorizationDigest: ethers.id(
          `v2-confirmation-target-runtime-${nonce}`
        )
      };
      const callData = env.account.interface.encodeFunctionData(
        "confirmIntent",
        [intent, digest]
      );
      const userOp = {
        sender: env.accountAddress,
        nonce,
        initCode: "0x",
        callData,
        accountGasLimits: packUints(3_000_000n, 1_000_000n),
        preVerificationGas: 200_000n,
        gasFees: packUints(1_000_000_000n, 30_000_000_000n),
        paymasterAndData: "0x",
        signature: "0x"
      };
      const userOpHash = await env.entryPoint.getUserOpHash(userOp);
      const coreHash = confirmCoreHash(core, digest, await env.target.getAddress());
      const authHash = authorizedIntentHash(intent, coreHash);
      const raw = await signer.signTypedData(
        {
          name: "PhilCore V2 Account",
          version: "1",
          chainId: env.chainId,
          verifyingContract: env.accountAddress
        },
        {
          PhilCoreV2Authorization: [
            { name: "authorizedIntentHash", type: "bytes32" },
            { name: "userOpHash", type: "bytes32" },
            { name: "validator", type: "address" },
            { name: "validatorKeyIdBinding", type: "bytes32" },
            { name: "validatorEpoch", type: "uint64" },
            { name: "recoveryEpoch", type: "uint64" }
          ]
        },
        {
          authorizedIntentHash: authHash,
          userOpHash,
          validator: env.validator.address,
          validatorKeyIdBinding: env.validatorKey,
          validatorEpoch: 1n,
          recoveryEpoch: 1n
        }
      );
      const parsed = ethers.Signature.from(raw);
      const signature = abi.encode(
        [
          "uint8",
          "uint8",
          "uint8",
          "address",
          "bytes32",
          "uint64",
          "uint64",
          "bytes32",
          "bytes32",
          "uint8"
        ],
        [
          1,
          1,
          1,
          env.validator.address,
          env.validatorKey,
          1,
          1,
          parsed.r,
          parsed.s,
          parsed.v
        ]
      );
      return { ...userOp, signature, actionId };
    }

    it("records a confirmation reached through a real deployed V2 account's confirmIntent path", async function () {
      const env = await integrationFixture();
      const digest = ethers.id("v2-confirmation-target-integration-digest");
      const op = await buildConfirmOperation(env, { digest });
      const receipt = await (
        await env.entryPoint.handleOps([op], env.beneficiary.address, {
          gasLimit: 12_000_000
        })
      ).wait();

      assert.equal(
        await env.target.confirmedAction(env.accountAddress, op.actionId),
        true
      );

      const targetInterface = env.target.interface;
      const parsedLogs = receipt.logs
        .map((log) => {
          try {
            return targetInterface.parseLog(log);
          } catch {
            return null;
          }
        })
        .filter(
          (parsed) => parsed && parsed.name === "PhilCoreV2ActionConfirmed"
        );
      assert.equal(parsedLogs.length, 1);
      assert.equal(parsedLogs[0].args.account, env.accountAddress);
      assert.equal(parsedLogs[0].args.actionId, op.actionId);
      assert.equal(parsedLogs[0].args.authorizationDigest, digest);

      const config = await env.account.accountConfiguration();
      assert.equal(config[5], ACCOUNT_VERSION_ID);
      assert.equal(config[6], SECURITY_MODEL_ID);
      assert.equal(config[7], await env.target.getAddress());
    });

    it("rejects a direct (non-EntryPoint) call to the real account's confirmIntent", async function () {
      const env = await integrationFixture();
      const digest = ethers.id("v2-confirmation-target-direct-call-digest");
      const op = await buildConfirmOperation(env, { digest });
      await assert.rejects(
        env.attacker.sendTransaction({
          to: env.accountAddress,
          data: op.callData
        }),
        /UnauthorizedEntryPoint/
      );
      assert.equal(
        await env.target.confirmedAction(env.accountAddress, op.actionId),
        false
      );
    });
  });
});
