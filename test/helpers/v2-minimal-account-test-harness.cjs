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
    ownerCommitment: ethers.id("o37-10-fsm-owner"),
    validatorKey: ethers.id("o37-10-fsm-validator-key"),
    primary: ethers.id("o37-10-fsm-primary"),
    hardware: ethers.id("o37-10-fsm-hardware"),
    independent: ethers.id("o37-10-fsm-independent"),
    userSalt: ethers.id("o37-10-fsm-user-salt")
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
    actionId: ethers.id(`o37-10-fsm-action-${action}-${nonce}`),
    purpose: PURPOSE[action],
    ownerCommitment: env.ownerCommitment,
    chainId: env.chainId,
    entryPoint: await env.entryPoint.getAddress(),
    account: env.accountAddress,
    nonceKey: BigInt(lane),
    nonceSequence: BigInt(nonce) & ((1n << 64n) - 1n),
    validatorEpoch: state.validatorEpoch,
    recoveryEpoch: state.recoveryEpoch,
    applicationContextHash: ethers.id("o37-10-fsm-application-context"),
    fundLifecycleDigest: ethers.id("o37-10-fsm-fund-lifecycle"),
    maxTotalFeeWei: ethers.parseEther("1"),
    validAfter: BigInt(latest.timestamp - 1),
    validUntil: BigInt(latest.timestamp + (action >= 8 ? 3500 : 500))
  };
  if (mutateCore) mutateCore(core);
  const intent = {
    core,
    runtimeAuthorizationDigest: ethers.id(
      `o37-10-fsm-runtime-${action}-${nonce}`
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

module.exports = {
  ACTION,
  PURPOSE,
  ACCOUNT_VERSION_ID,
  SECURITY_MODEL_ID,
  identityBinding,
  validatorCommitment,
  recoveryConfigHash,
  fixture,
  securityState,
  buildOperation,
  execute,
  increaseTime
};
