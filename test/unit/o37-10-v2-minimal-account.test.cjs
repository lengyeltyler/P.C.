const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const ACCOUNT_VERSION_ID =
  "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f";
const FACTORY_VERSION_ID =
  "0x66e130d6512db6801362a672a59d58b9b6c16bb2ba76172808d6b5c21814d671";
const SECURITY_MODEL_ID = ethers.id(
  "philcore-v2-typed-intent-local-proof-gated-v1"
);
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

const ACTION = {
  CONFIRM: 1,
  TRANSFER: 2,
  WITHDRAW: 6,
  ROTATE: 7,
  RECOVERY_REQUEST: 8,
  RECOVERY_CANCEL: 9,
  CONFIG_REQUEST: 10,
  CONFIG_CANCEL: 11
};

const PURPOSE = {
  [ACTION.CONFIRM]: ethers.id("PHILCORE_V2_PURPOSE_CONFIRM_ACTION"),
  [ACTION.TRANSFER]: ethers.id("PHILCORE_V2_PURPOSE_TRANSFER_ASSET"),
  [ACTION.WITHDRAW]: ethers.id("PHILCORE_V2_PURPOSE_WITHDRAW_DEPOSIT"),
  [ACTION.ROTATE]: ethers.id("PHILCORE_V2_PURPOSE_ROTATE_VALIDATOR"),
  [ACTION.RECOVERY_REQUEST]: ethers.id(
    "PHILCORE_V2_PURPOSE_REQUEST_RECOVERY"
  ),
  [ACTION.RECOVERY_CANCEL]: ethers.id(
    "PHILCORE_V2_PURPOSE_CANCEL_RECOVERY"
  ),
  [ACTION.CONFIG_REQUEST]: ethers.id(
    "PHILCORE_V2_PURPOSE_ROTATE_RECOVERY_CONFIG"
  ),
  [ACTION.CONFIG_CANCEL]: ethers.id(
    "PHILCORE_V2_PURPOSE_CANCEL_RECOVERY_CONFIG_ROTATION"
  )
};

const ACTION_TYPE = {
  [ACTION.CONFIRM]: ethers.id(
    "PhilCoreV2ConfirmIntent(bytes32 coreHeaderHash,address confirmationTarget,bytes32 confirmationDigest)"
  ),
  [ACTION.TRANSFER]: ethers.id(
    "PhilCoreV2NativeTransferIntent(bytes32 coreHeaderHash,address recipient,uint256 amountWei)"
  ),
  [ACTION.WITHDRAW]: ethers.id(
    "PhilCoreV2EntryPointDepositWithdrawalIntent(bytes32 coreHeaderHash,address recipient,uint256 amountWei)"
  ),
  [ACTION.ROTATE]: ethers.id(
    "PhilCoreV2ValidatorRotationIntent(bytes32 coreHeaderHash,address proposedValidator,bytes32 proposedValidatorKeyIdBinding,uint64 proposedValidatorEpoch)"
  ),
  [ACTION.RECOVERY_REQUEST]: ethers.id(
    "PhilCoreV2RecoveryRequestIntent(bytes32 coreHeaderHash,address proposedValidator,bytes32 proposedValidatorKeyIdBinding,uint64 proposedValidatorEpoch,bytes32 recoveryRequestSalt)"
  ),
  [ACTION.RECOVERY_CANCEL]: ethers.id(
    "PhilCoreV2RecoveryCancelIntent(bytes32 coreHeaderHash,bytes32 recoveryRequestId)"
  ),
  [ACTION.CONFIG_REQUEST]: ethers.id(
    "PhilCoreV2RecoveryConfigRotationRequestIntent(bytes32 coreHeaderHash,bytes32 proposedRecoveryConfigHash,bytes32 proposedPrimaryDeviceCommitment,bytes32 proposedHardwareSecurityKeyCommitment,bytes32 proposedRecoveryFactorCommitment,uint64 proposedRecoveryEpoch)"
  ),
  [ACTION.CONFIG_CANCEL]: ethers.id(
    "PhilCoreV2RecoveryConfigRotationCancelIntent(bytes32 coreHeaderHash,bytes32 recoveryConfigRotationRequestId)"
  )
};

const abi = ethers.AbiCoder.defaultAbiCoder();

function packUints(high128, low128) {
  return ethers.toBeHex((BigInt(high128) << 128n) | BigInt(low128), 32);
}

function replaceCallDataWord(callData, index, value) {
  const body = callData.slice(2);
  const start = 8 + index * 64;
  const word = ethers.zeroPadValue(value, 32).slice(2);
  return `0x${body.slice(0, start)}${word}${body.slice(start + 64)}`;
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
      [
        RECOVERY_CONFIGURATION_TYPEHASH,
        3,
        2,
        primary,
        hardware,
        independent
      ]
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

function actionCoreHash(action, core, args, confirmationTarget) {
  const head = headerHash(core);
  if (action === ACTION.CONFIRM) {
    return ethers.keccak256(
      abi.encode(
        ["bytes32", "bytes32", "address", "bytes32"],
        [ACTION_TYPE[action], head, confirmationTarget, args[0]]
      )
    );
  }
  if (action === ACTION.TRANSFER || action === ACTION.WITHDRAW) {
    return ethers.keccak256(
      abi.encode(
        ["bytes32", "bytes32", "address", "uint256"],
        [ACTION_TYPE[action], head, args[0], args[1]]
      )
    );
  }
  if (action === ACTION.ROTATE) {
    return ethers.keccak256(
      abi.encode(
        ["bytes32", "bytes32", "address", "bytes32", "uint64"],
        [ACTION_TYPE[action], head, ...args]
      )
    );
  }
  if (action === ACTION.RECOVERY_REQUEST) {
    return ethers.keccak256(
      abi.encode(
        [
          "bytes32",
          "bytes32",
          "address",
          "bytes32",
          "uint64",
          "bytes32"
        ],
        [ACTION_TYPE[action], head, ...args]
      )
    );
  }
  if (action === ACTION.RECOVERY_CANCEL) {
    return ethers.keccak256(
      abi.encode(
        ["bytes32", "bytes32", "bytes32"],
        [ACTION_TYPE[action], head, args[0]]
      )
    );
  }
  if (action === ACTION.CONFIG_REQUEST) {
    const proposedHash = recoveryConfigHash(args[0], args[1], args[2]);
    return ethers.keccak256(
      abi.encode(
        [
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "bytes32",
          "uint64"
        ],
        [ACTION_TYPE[action], head, proposedHash, ...args]
      )
    );
  }
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32"],
      [ACTION_TYPE[action], head, args[0]]
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
    recoveryConfigurationHash: recoveryConfigHash(
      primary,
      hardware,
      independent
    ),
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

async function fixture({ realVerifier = true } = {}) {
  const signers = await ethers.getSigners();
  const [
    deployer,
    validator,
    nextValidator,
    recipient,
    beneficiary,
    attacker
  ] = signers;
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const entryPoint = await deployEntryPoint(deployer);
  const Confirmation = await ethers.getContractFactory(
    "PhilCoreV2ConfirmationTargetMock"
  );
  const confirmation = await Confirmation.deploy();
  let verifier;
  if (realVerifier) {
    const Verifier = await ethers.getContractFactory(
      "PhilCoreV2StaticAuthorityVerifier"
    );
    verifier = await Verifier.deploy();
  } else {
    const Verifier = await ethers.getContractFactory(
      "PhilCoreV2AuthorityVerifierMock"
    );
    verifier = await Verifier.deploy("0x15c57f54", false);
  }
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
    await confirmation.getAddress(),
    verifierAddress,
    verifierCodeHash
  );
  const values = {
    ownerCommitment: ethers.id("o37-10-owner"),
    validatorKey: ethers.id("o37-10-validator-key"),
    primary: ethers.id("o37-10-primary"),
    hardware: ethers.id("o37-10-hardware"),
    independent: ethers.id("o37-10-independent"),
    userSalt: ethers.id("o37-10-user-salt")
  };
  const init = initialization({
    entryPoint: await entryPoint.getAddress(),
    chainId,
    ownerCommitment: values.ownerCommitment,
    factory: await factory.getAddress(),
    confirmationTarget: await confirmation.getAddress(),
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
    await entryPoint.depositTo(predicted, { value: ethers.parseEther("4") })
  ).wait();
  return {
    signers,
    deployer,
    validator,
    nextValidator,
    recipient,
    beneficiary,
    attacker,
    chainId,
    entryPoint,
    confirmation,
    verifier,
    verifierCodeHash,
    factory,
    init,
    account,
    accountAddress: predicted,
    ...values
  };
}

async function securityState(env) {
  const state = await env.account.accountSecurityState();
  return {
    validator: state[0],
    validatorCommitment: state[1],
    validatorKey: state[2],
    validatorEpoch: state[3],
    verifierKind: state[4],
    recoveryState: state[5],
    recoveryEpoch: state[6],
    recoveryConfigHash: state[7],
    primary: state[8],
    hardware: state[9],
    independent: state[10],
    locked: state[11]
  };
}

async function buildOperation(
  env,
  {
    action,
    args,
    lane,
    signer = env.validator,
    signatureOverride,
    mutateCore,
    mutateOperation
  }
) {
  const state = await securityState(env);
  const latest = await ethers.provider.getBlock("latest");
  const nonce = await env.entryPoint.getNonce(env.accountAddress, lane);
  const core = {
    specificationVersion: 1,
    securityModelId: SECURITY_MODEL_ID,
    actionType: action,
    actionId: ethers.id(`o37-10-action-${action}-${nonce}`),
    purpose: PURPOSE[action],
    ownerCommitment: env.ownerCommitment,
    chainId: env.chainId,
    entryPoint: await env.entryPoint.getAddress(),
    account: env.accountAddress,
    nonceKey: BigInt(lane),
    nonceSequence: BigInt(nonce) & ((1n << 64n) - 1n),
    validatorEpoch: state.validatorEpoch,
    recoveryEpoch: state.recoveryEpoch,
    applicationContextHash: ethers.id("o37-10-application-context"),
    fundLifecycleDigest: ethers.id("o37-10-fund-lifecycle"),
    maxTotalFeeWei: ethers.parseEther("1"),
    validAfter: BigInt(latest.timestamp - 1),
    validUntil: BigInt(latest.timestamp + (action >= 8 ? 3500 : 500))
  };
  if (mutateCore) mutateCore(core);
  const intent = {
    core,
    runtimeAuthorizationDigest: ethers.id(
      `o37-10-runtime-${action}-${nonce}`
    )
  };
  const functionName = {
    [ACTION.CONFIRM]: "confirmIntent",
    [ACTION.TRANSFER]: "transferNative",
    [ACTION.WITHDRAW]: "withdrawEntryPointDeposit",
    [ACTION.ROTATE]: "rotateValidator",
    [ACTION.RECOVERY_REQUEST]: "requestRecovery",
    [ACTION.RECOVERY_CANCEL]: "cancelRecovery",
    [ACTION.CONFIG_REQUEST]: "requestRecoveryConfigRotation",
    [ACTION.CONFIG_CANCEL]: "cancelRecoveryConfigRotation"
  }[action];
  const callData = env.account.interface.encodeFunctionData(functionName, [
    intent,
    ...args
  ]);
  let userOp = {
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
  if (mutateOperation) userOp = mutateOperation(userOp);
  const userOpHash = await env.entryPoint.getUserOpHash(userOp);
  let signature = signatureOverride;
  if (signature === undefined) {
    const coreHash = actionCoreHash(
      action,
      core,
      args,
      await env.confirmation.getAddress()
    );
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
        validator: state.validator,
        validatorKeyIdBinding: state.validatorKey,
        validatorEpoch: state.validatorEpoch,
        recoveryEpoch: state.recoveryEpoch
      }
    );
    const parsed = ethers.Signature.from(raw);
    signature = abi.encode(
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
        state.validator,
        state.validatorKey,
        state.validatorEpoch,
        state.recoveryEpoch,
        parsed.r,
        parsed.s,
        parsed.v
      ]
    );
  }
  return { ...userOp, signature };
}

async function execute(env, userOp) {
  return env.entryPoint.handleOps([userOp], env.beneficiary.address, {
    gasLimit: 12_000_000
  });
}

async function increaseTime(seconds) {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}

describe("O.37.10 V2 minimal account, factory, and local lifecycle", function () {
  it("deploys the exact CREATE2 account, verifies initialization, and rejects duplicate and direct construction", async function () {
    const env = await fixture();
    assert.notEqual(await ethers.provider.getCode(env.accountAddress), "0x");
    const config = await env.account.accountConfiguration();
    assert.equal(config[0], await env.entryPoint.getAddress());
    assert.equal(config[1], env.chainId);
    assert.equal(config[2], env.ownerCommitment);
    assert.equal(config[3], identityBinding(env.ownerCommitment));
    assert.equal(config[4], await env.factory.getAddress());
    assert.equal(config[5], ACCOUNT_VERSION_ID);
    assert.equal(config[6], SECURITY_MODEL_ID);
    assert.equal(config[7], await env.confirmation.getAddress());
    await assert.rejects(
      env.factory.createAccount(env.init, env.userSalt),
      /AccountAlreadyDeployed/
    );

    const Account = await ethers.getContractFactory(
      "PhilCoreV2MinimalAccountV2"
    );
    const direct = { ...env.init, factoryBinding: env.deployer.address };
    await assert.rejects(Account.deploy(direct), /InvalidInitialization/);
  });

  it("reproduces CREATE2 addresses and salts independently across deterministic vectors", async function () {
    const env = await fixture();
    const factoryAddress = await env.factory.getAddress();
    for (let index = 1; index <= 12; index += 1) {
      const salt = ethers.id(`o37-10-vector-${index}`);
      const deploymentSalt = await env.factory.deploymentSalt(env.init, salt);
      const expectedSalt = ethers.keccak256(
        abi.encode(
          [
            "bytes32",
            "uint256",
            "bytes32",
            "bytes32",
            "bytes32",
            "bytes32",
            "bytes32"
          ],
          [
            ethers.id("PHILCORE_V2_CREATE2_SALT_V1"),
            env.chainId,
            ACCOUNT_VERSION_ID,
            SECURITY_MODEL_ID,
            env.ownerCommitment,
            identityBinding(env.ownerCommitment),
            salt
          ]
        )
      );
      assert.equal(deploymentSalt, expectedSalt);
      const initCodeHash =
        await env.factory.accountCreationCodeHash(env.init);
      assert.equal(
        await env.factory
          .getFunction("getAddress")
          .staticCall(env.init, salt),
        ethers.getCreate2Address(factoryAddress, expectedSalt, initCodeHash)
      );
    }
  });

  it("independently validates the committed O.37.10 CREATE2 evidence against the current V3 recovery configuration semantics", async function () {
    const env = await fixture();
    const evidencePath = path.join(
      __dirname,
      "../../config/solidity/O37_10_CREATE2_VECTORS.json"
    );
    const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
    const inputs = evidence.syntheticVectorInputs;

    // Independently compute the current recovery configuration hash using
    // PhilCoreV2RecoveryConfigurationV3 (configurationVersion=3, threshold=2),
    // the same formula the live account/factory contracts use, reusing this
    // file's own contract-aligned helper rather than the evidence generator.
    const computedRecoveryConfigurationHash = recoveryConfigHash(
      inputs.primaryDeviceRecoveryCommitment,
      inputs.hardwareSecurityKeyCommitment,
      inputs.independentRecoveryFactorCommitment
    );
    assert.equal(
      computedRecoveryConfigurationHash,
      inputs.recoveryConfigurationHash,
      "O.37.10 CREATE2 evidence recoveryConfigurationHash does not match the " +
        "current PhilCoreV2RecoveryConfigurationV3 formula"
    );

    // Reconstruct the recorded 20-field initialization tuple from
    // syntheticVectorInputs, using the independently computed recovery hash
    // rather than trusting the recorded field.
    const initStruct = {
      entryPoint: inputs.entryPoint,
      deploymentChainId: inputs.deploymentChainId,
      ownerCommitment: inputs.ownerCommitment,
      identityBindingCommitment: inputs.identityBindingCommitment,
      factoryBinding: inputs.factoryBinding,
      accountVersionId: inputs.accountVersionId,
      securityModelId: inputs.securityModelId,
      confirmationTarget: inputs.confirmationTarget,
      initialValidator: inputs.initialValidator,
      validatorVerifierKind: inputs.validatorVerifierKind,
      validatorKeyIdBinding: inputs.validatorKeyIdBinding,
      validatorCommitment: inputs.validatorCommitment,
      validatorEpoch: inputs.validatorEpoch,
      primaryDeviceRecoveryCommitment: inputs.primaryDeviceRecoveryCommitment,
      hardwareSecurityKeyCommitment: inputs.hardwareSecurityKeyCommitment,
      independentRecoveryFactorCommitment:
        inputs.independentRecoveryFactorCommitment,
      recoveryConfigurationHash: computedRecoveryConfigurationHash,
      recoveryEpoch: inputs.recoveryEpoch,
      recoveryDelaySeconds: inputs.recoveryDelaySeconds,
      recoveryExpirySeconds: inputs.recoveryExpirySeconds
    };

    // Independently recompute the exact init-code hash through the real
    // deployed factory's own pure accountCreationCodeHash function (a
    // function of the account creation code and abi-encoded initialization
    // only -- independent of the factory's own address).
    const computedInitCodeHash =
      await env.factory.accountCreationCodeHash(initStruct);
    assert.equal(computedInitCodeHash, evidence.accountCreationCodeHash);

    // Independently recompute every deployment salt and predicted address
    // through the real deployed factory's own pure deploymentSalt function,
    // combined with the evidence's fixed synthetic factory address.
    for (const vector of evidence.vectors) {
      const computedSalt = await env.factory.deploymentSalt(
        initStruct,
        vector.userSalt
      );
      assert.equal(computedSalt, vector.deploymentSalt, `${vector.label} deploymentSalt`);
      const computedAddress = ethers.getCreate2Address(
        vector.syntheticFactoryAddress,
        computedSalt,
        computedInitCodeHash
      );
      assert.equal(
        computedAddress.toLowerCase(),
        vector.predictedAddress.toLowerCase(),
        `${vector.label} predictedAddress`
      );
    }
  });

  it("executes a real-verifier native transfer and rejects EntryPoint replay", async function () {
    const env = await fixture();
    await env.deployer.sendTransaction({
      to: env.accountAddress,
      value: ethers.parseEther("2")
    });
    const amount = ethers.parseEther("0.25");
    const before = await ethers.provider.getBalance(env.recipient.address);
    const op = await buildOperation(env, {
      action: ACTION.TRANSFER,
      args: [env.recipient.address, amount],
      lane: 0
    });
    await (await execute(env, op)).wait();
    assert.equal(
      await ethers.provider.getBalance(env.recipient.address),
      before + amount
    );
    await assert.rejects(execute(env, op));
  });

  it("rejects wrong signer, modified digest, chain, account, epoch, lane, paymaster, truncation, and extension", async function () {
    const env = await fixture();
    const base = {
      action: ACTION.CONFIRM,
      args: [ethers.id("o37-10-confirmation")],
      lane: 0
    };
    const invalid = [
      await buildOperation(env, { ...base, signer: env.attacker }),
      await buildOperation(env, {
        ...base,
        mutateCore: (core) => {
          core.runtimeAuthorizationDigest = ethers.id("unused");
          core.chainId += 1n;
        }
      }),
      await buildOperation(env, {
        ...base,
        mutateCore: (core) => {
          core.account = env.attacker.address;
        }
      }),
      await buildOperation(env, {
        ...base,
        mutateCore: (core) => {
          core.validatorEpoch += 1n;
        }
      }),
      await buildOperation(env, {
        ...base,
        mutateCore: (core) => {
          core.nonceKey = 1n;
        }
      }),
      await buildOperation(env, {
        ...base,
        mutateOperation: (op) => ({
          ...op,
          paymasterAndData: ethers.concat([
            env.attacker.address,
            ethers.toBeHex(0, 32),
            ethers.toBeHex(0, 32)
          ])
        })
      }),
      await buildOperation(env, {
        ...base,
        mutateOperation: (op) => ({
          ...op,
          gasFees: packUints(31_000_000_000n, 30_000_000_000n)
        })
      })
    ];
    const valid = await buildOperation(env, base);
    invalid.push({
      ...valid,
      callData: replaceCallDataWord(
        valid.callData,
        18,
        ethers.id("modified-runtime-authorization-digest")
      )
    });
    invalid.push({ ...valid, callData: valid.callData.slice(0, -2) });
    invalid.push({ ...valid, callData: `${valid.callData}00` });
    for (const op of invalid) {
      await assert.rejects(execute(env, op));
    }
  });

  it("confirms only through the immutable target and rejects direct calls", async function () {
    const env = await fixture();
    const digest = ethers.id("o37-10-confirmation-digest");
    const op = await buildOperation(env, {
      action: ACTION.CONFIRM,
      args: [digest],
      lane: 0
    });
    await (await execute(env, op)).wait();
    assert.equal(await env.confirmation.confirmationCount(), 1n);
    assert.equal(await env.confirmation.lastAuthorizationDigest(), digest);
    await assert.rejects(
      env.attacker.sendTransaction({
        to: env.accountAddress,
        data: op.callData
      }),
      /UnauthorizedEntryPoint/
    );
    assert.equal(
      env.account.interface.getFunction("confirmIntent").inputs.length,
      2
    );
  });

  it("rotates the validator and makes stale validator authority unusable", async function () {
    const env = await fixture();
    const nextKey = ethers.id("o37-10-next-validator-key");
    const rotate = await buildOperation(env, {
      action: ACTION.ROTATE,
      args: [env.nextValidator.address, nextKey, 2],
      lane: 1
    });
    await (await execute(env, rotate)).wait();
    const state = await securityState(env);
    assert.equal(state.validator, env.nextValidator.address);
    assert.equal(state.validatorKey, nextKey);
    assert.equal(state.validatorEpoch, 2n);
    const stale = await buildOperation(env, {
      action: ACTION.CONFIRM,
      args: [ethers.id("stale-validator")],
      lane: 0,
      signer: env.validator
    });
    await assert.rejects(execute(env, stale));
    const fresh = await buildOperation(env, {
      action: ACTION.CONFIRM,
      args: [ethers.id("fresh-validator")],
      lane: 0,
      signer: env.nextValidator
    });
    await (await execute(env, fresh)).wait();
  });

  it("prevents authority-class substitution, action confusion, and invalid native payloads", async function () {
    const env = await fixture();
    const validatorOnlyRecovery = await buildOperation(env, {
      action: ACTION.RECOVERY_REQUEST,
      args: [
        env.nextValidator.address,
        ethers.id("validator-only-recovery-key"),
        2,
        ethers.id("validator-only-recovery-salt")
      ],
      lane: 2
    });
    await assert.rejects(execute(env, validatorOnlyRecovery));

    const vectors = JSON.parse(
      fs.readFileSync(
        path.join(
          process.cwd(),
          "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json"
        ),
        "utf8"
      )
    );
    const recoveryOnOrdinary = await buildOperation(env, {
      action: ACTION.CONFIRM,
      args: [ethers.id("recovery-on-ordinary")],
      lane: 0,
      signatureOverride:
        vectors.valid.validatorPlusPrimaryAndHardwareConfigRotation
          .recoveryEvidence.encodedRecoveryEnvelope
    });
    await assert.rejects(execute(env, recoveryOnOrdinary));

    const confused = await buildOperation(env, {
      action: ACTION.CONFIRM,
      args: [ethers.id("action-confusion")],
      lane: 0,
      mutateCore: (core) => {
        core.actionType = ACTION.TRANSFER;
        core.purpose = PURPOSE[ACTION.TRANSFER];
      }
    });
    await assert.rejects(execute(env, confused));

    for (const args of [
      [ethers.ZeroAddress, 1n],
      [env.recipient.address, 0n]
    ]) {
      const invalidTransfer = await buildOperation(env, {
        action: ACTION.TRANSFER,
        args,
        lane: 0
      });
      await assert.rejects(execute(env, invalidTransfer));
    }
  });

  it("enforces recovery request freeze, cancellation, delay, completion, and expiry deterministically", async function () {
    const env = await fixture({ realVerifier: false });
    const requestArgs = [
      env.nextValidator.address,
      ethers.id("o37-10-recovered-key"),
      2,
      ethers.id("o37-10-recovery-salt")
    ];
    const request = await buildOperation(env, {
      action: ACTION.RECOVERY_REQUEST,
      args: requestArgs,
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, request)).wait();
    const pending = await env.account.pendingRecovery();
    assert.notEqual(pending[0], ethers.ZeroHash);
    await assert.rejects(env.account.settleRecovery(pending[0]));
    const frozen = await buildOperation(env, {
      action: ACTION.CONFIRM,
      args: [ethers.id("frozen")],
      lane: 0,
      signatureOverride: "0x01"
    });
    await assert.rejects(execute(env, frozen));
    const cancel = await buildOperation(env, {
      action: ACTION.RECOVERY_CANCEL,
      args: [pending[0]],
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, cancel)).wait();
    assert.equal((await env.account.pendingRecovery())[0], ethers.ZeroHash);
    assert.equal((await securityState(env)).recoveryState, 3n);

    const second = await buildOperation(env, {
      action: ACTION.RECOVERY_REQUEST,
      args: [
        env.nextValidator.address,
        ethers.id("o37-10-recovered-key-2"),
        2,
        ethers.id("o37-10-recovery-salt-2")
      ],
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, second)).wait();
    const secondId = (await env.account.pendingRecovery())[0];
    await increaseTime(172800);
    await (await env.account.settleRecovery(secondId)).wait();
    let state = await securityState(env);
    assert.equal(state.validator, env.nextValidator.address);
    assert.equal(state.validatorEpoch, 2n);
    assert.equal(state.recoveryEpoch, 2n);
    assert.equal(state.recoveryState, 2n);

    const thirdValidator = env.signers[8];
    const third = await buildOperation(env, {
      action: ACTION.RECOVERY_REQUEST,
      args: [
        thirdValidator.address,
        ethers.id("o37-10-recovered-key-3"),
        3,
        ethers.id("o37-10-recovery-salt-3")
      ],
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, third)).wait();
    const thirdId = (await env.account.pendingRecovery())[0];
    await increaseTime(604800);
    await (await env.account.settleRecovery(thirdId)).wait();
    state = await securityState(env);
    assert.equal(state.validator, env.nextValidator.address);
    assert.equal(state.validatorEpoch, 2n);
    assert.equal((await env.account.pendingRecovery())[0], ethers.ZeroHash);
  });

  it("rotates exactly one recovery factor with cancellation, completion, and epoch transition", async function () {
    const env = await fixture({ realVerifier: false });
    const replacement = ethers.id("o37-10-primary-replacement");
    const args = [replacement, env.hardware, env.independent, 2];
    const request = await buildOperation(env, {
      action: ACTION.CONFIG_REQUEST,
      args,
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, request)).wait();
    let pending = await env.account.pendingRecoveryConfigRotation();
    assert.equal(pending[1], recoveryConfigHash(...args.slice(0, 3)));
    const cancel = await buildOperation(env, {
      action: ACTION.CONFIG_CANCEL,
      args: [pending[0]],
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, cancel)).wait();
    assert.equal(
      (await env.account.pendingRecoveryConfigRotation())[0],
      ethers.ZeroHash
    );

    const request2 = await buildOperation(env, {
      action: ACTION.CONFIG_REQUEST,
      args,
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, request2)).wait();
    pending = await env.account.pendingRecoveryConfigRotation();
    await increaseTime(172800);
    await (await env.account.settleRecoveryConfigRotation(pending[0])).wait();
    const state = await securityState(env);
    assert.equal(state.primary, replacement);
    assert.equal(state.recoveryEpoch, 2n);
    assert.equal(
      state.recoveryConfigHash,
      recoveryConfigHash(replacement, env.hardware, env.independent)
    );
  });

  it("blocks permissionless settlement reentrancy during an authorized external call", async function () {
    const env = await fixture({ realVerifier: false });
    const replacement = ethers.id("o37-10-reentrancy-factor");
    const request = await buildOperation(env, {
      action: ACTION.CONFIG_REQUEST,
      args: [replacement, env.hardware, env.independent, 2],
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, request)).wait();
    const requestId = (await env.account.pendingRecoveryConfigRotation())[0];
    await increaseTime(172800);

    const Recipient = await ethers.getContractFactory(
      "PhilCoreV2ReentrantRecipientMock"
    );
    const recipient = await Recipient.deploy();
    await recipient.configure(
      env.accountAddress,
      env.account.interface.encodeFunctionData(
        "settleRecoveryConfigRotation",
        [requestId]
      )
    );
    await env.deployer.sendTransaction({
      to: env.accountAddress,
      value: ethers.parseEther("1")
    });
    const transfer = await buildOperation(env, {
      action: ACTION.TRANSFER,
      args: [await recipient.getAddress(), ethers.parseEther("0.1")],
      lane: 0,
      signatureOverride: "0x01"
    });
    await (await execute(env, transfer)).wait();
    assert.equal(await recipient.attempted(), true);
    assert.equal(await recipient.succeeded(), false);
    assert.equal(
      (await env.account.pendingRecoveryConfigRotation())[0],
      requestId
    );
    await (await env.account.settleRecoveryConfigRotation(requestId)).wait();
    assert.equal((await securityState(env)).recoveryEpoch, 2n);
  });

  it("releases an exact EntryPoint deposit amount and reconciles the residual", async function () {
    const env = await fixture();
    const amount = ethers.parseEther("0.1");
    const beforeRecipient = await ethers.provider.getBalance(
      env.recipient.address
    );
    const beforeDeposit = await env.entryPoint.balanceOf(env.accountAddress);
    const op = await buildOperation(env, {
      action: ACTION.WITHDRAW,
      args: [env.recipient.address, amount],
      lane: 0
    });
    const receipt = await (await execute(env, op)).wait();
    const afterDeposit = await env.entryPoint.balanceOf(env.accountAddress);
    const afterRecipient = await ethers.provider.getBalance(
      env.recipient.address
    );
    assert.equal(afterRecipient - beforeRecipient, amount);
    assert(afterDeposit < beforeDeposit - amount);
    assert.equal(receipt.status, 1);
  });

  it("fails closed for short, extended, wrong-code-hash, reverting, and wrong-magic verifier bindings", async function () {
    const base = await fixture({ realVerifier: false });
    const Mock = await ethers.getContractFactory(
      "PhilCoreV2AuthorityVerifierMock"
    );
    const wrongMagic = await Mock.deploy("0xdeadbeef", false);
    const reverting = await Mock.deploy("0x15c57f54", true);
    const cases = [
      {
        verifier: await base.verifier.getAddress(),
        hash: base.verifierCodeHash,
        mode: 1
      },
      {
        verifier: await base.verifier.getAddress(),
        hash: base.verifierCodeHash,
        mode: 2
      },
      {
        verifier: await base.verifier.getAddress(),
        hash: ethers.id("wrong-code-hash"),
        mode: 0
      },
      {
        verifier: await reverting.getAddress(),
        hash: ethers.keccak256(
          await ethers.provider.getCode(await reverting.getAddress())
        ),
        mode: 0
      },
      {
        verifier: await wrongMagic.getAddress(),
        hash: ethers.keccak256(
          await ethers.provider.getCode(await wrongMagic.getAddress())
        ),
        mode: 0
      }
    ];
    for (const [index, item] of cases.entries()) {
      const Harness = await ethers.getContractFactory(
        "PhilCoreV2BindingHarness"
      );
      const harness = await Harness.deploy(item.verifier, item.hash, item.mode);
      const init = {
        ...base.init,
        factoryBinding: await harness.getAddress()
      };
      const accountAddress = await harness.getFunction("deploy").staticCall(init);
      await (await harness.deploy(init)).wait();
      const account = await ethers.getContractAt(
        "PhilCoreV2MinimalAccountV2",
        accountAddress
      );
      const env = { ...base, init, account, accountAddress };
      await (
        await base.entryPoint.depositTo(accountAddress, {
          value: ethers.parseEther("0.5")
        })
      ).wait();
      const op = await buildOperation(env, {
        action: ACTION.CONFIRM,
        args: [ethers.id(`binding-failure-${index}`)],
        lane: 0,
        signatureOverride: "0x01"
      });
      await assert.rejects(execute(env, op));
    }
  });

  it("preserves the frozen transport fixture and tests the superseding O.43 verifier", async function () {
    const fixturePath = path.join(
      process.cwd(),
      "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json"
    );
    const vectors = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
    assert.equal(vectors.phase, "O.37.4");
    assert.equal(
      vectors.authorityTransportFreeze.actionDispatch.recoveryOnly.join(","),
      "8,9,11"
    );
    assert.equal(
      vectors.authorityTransportFreeze.actionDispatch.validatorAndRecovery[0],
      10
    );
    assert.equal(
      vectors.valid.normalValidatorExecution.encodedSignature.length,
      642
    );
    const verifierSource = fs.readFileSync(
      path.join(
        process.cwd(),
        "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol"
      ),
      "utf8"
    );
    assert.equal(
      ethers.sha256(ethers.toUtf8Bytes(verifierSource)),
      "0x410638b556e08ed98deebb00b7375798ad3a3f13230230fbd93884232e7a23d8"
    );
  });

  it("has the exact reduced ABI and frozen 15-slot storage with no forbidden surfaces", async function () {
    const artifact = await ethers.getContractFactory(
      "PhilCoreV2MinimalAccountV2"
    );
    const functions = artifact.interface.fragments.filter(
      (fragment) => fragment.type === "function"
    );
    assert.equal(functions.length, 15);
    const names = functions.map((fragment) => fragment.name);
    for (const forbidden of [
      "execute",
      "executeBatch",
      "delegatecall",
      "approve",
      "upgradeTo",
      "setAdmin",
      "setVerifier",
      "installModule",
      "onERC721Received",
      "onERC1155Received"
    ]) {
      assert(!names.includes(forbidden));
    }
    const buildInfoDirectory = path.join(process.cwd(), "artifacts/build-info");
    const layouts = fs
      .readdirSync(buildInfoDirectory)
      .map((name) =>
        JSON.parse(
          fs.readFileSync(path.join(buildInfoDirectory, name), "utf8")
        )
      )
      .map(
        (info) =>
          info.output.contracts?.[
            "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol"
          ]?.PhilCoreV2MinimalAccountV2?.storageLayout?.storage
      )
      .filter(Boolean);
    assert(layouts.length > 0);
    const layout = layouts.at(-1);
    assert.equal(Math.max(...layout.map((item) => Number(item.slot))), 14);
    assert.equal(layout[0].slot, "0");
    assert.equal(layout[0].offset, 0);
    assert.equal(layout[1].offset, 20);
    assert.equal(layout[2].offset, 28);
    assert.equal(layout[3].offset, 29);
    assert.equal(layout[4].offset, 30);
    assert(
      !layout.some((item) =>
        /nonce|admin|owner|verifier(address|hash|registry)|module/i.test(
          item.label
        )
      )
    );

    const factoryArtifact = await ethers.getContractFactory(
      "PhilCoreV2MinimalAccountFactoryV2"
    );
    const factoryNames = factoryArtifact.interface.fragments
      .filter((fragment) => fragment.type === "function")
      .map((fragment) => fragment.name);
    assert.deepEqual(factoryNames.sort(), [
      "accountCreationCodeHash",
      "createAccount",
      "deploymentSalt",
      "getAddress",
      "verifierBinding"
    ]);
    assert.equal(ethers.id("philcore-v2-minimal-factory-v2"), FACTORY_VERSION_ID);
  });
});
