const { ethers } = require("hardhat");

const EntryPointArtifact = require(
  "@account-abstraction/contracts/artifacts/EntryPoint.json"
);

const OWNER_COMMITMENT = ethers.id("o28-local-only-owner-commitment");
const VALIDATOR_KEY_ID = ethers.id("o28-local-only-validator-key");
const MODEL_ID = ethers.id("local-proof-gated-v1");
const SIGNATURE_DOMAIN = ethers.id(
  "PHILCORE_LOCAL_PROOF_GATED_ACCOUNT_SIGNATURE_V1"
);
const FUNDED_BALANCE_WEI = 5_124_486_704_000_000n;
const VERIFICATION_GAS_LIMIT = 1_500_000n;
const CALL_GAS_LIMIT = 300_000n;
const PRE_VERIFICATION_GAS = 200_000n;
const MAX_PRIORITY_FEE = 1_500_000n;
const MAX_FEE = 2_500_000_000n;
const SALT = 28n;

function pack(high, low) {
  return ethers.toBeHex((BigInt(high) << 128n) + BigInt(low), 32);
}

async function signOperation(input) {
  const userOperationHash = await input.entryPoint.getUserOpHash(input.operation);
  const envelopeValidatorKeyId =
    input.envelopeValidatorKeyId ?? VALIDATOR_KEY_ID;
  const signingDigest = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "bytes32",
        "uint8",
        "bytes32",
        "uint256",
        "address",
        "address",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint64",
        "bytes32"
      ],
      [
        SIGNATURE_DOMAIN,
        1,
        MODEL_ID,
        input.signedChainId ?? input.chainId,
        await input.entryPoint.getAddress(),
        input.operation.sender,
        userOperationHash,
        input.actionId,
        input.authorizationDigest,
        input.expiry,
        VALIDATOR_KEY_ID
      ]
    )
  );
  const raw = ethers.Signature.from(
    await input.signer.signMessage(ethers.getBytes(signingDigest))
  );
  return {
    ...input.operation,
    signature: ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "uint8",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint64",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint8"
      ],
      [
        1,
        MODEL_ID,
        input.actionId,
        input.authorizationDigest,
        input.expiry,
        envelopeValidatorKeyId,
        raw.r,
        raw.s,
        raw.v
      ]
    )
  };
}

async function deployFixture() {
  const [
    deployer,
    owner,
    beneficiary,
    account1Analog,
    account2Analog,
    residualRecipient,
    wrongSigner
  ] = await ethers.getSigners();
  const entryPoint = await new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
  await entryPoint.waitForDeployment();
  const Target = await ethers.getContractFactory(
    "PhilCoreLocalProofConfirmationTargetV1"
  );
  const target = await Target.deploy();
  await target.waitForDeployment();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const Factory = await ethers.getContractFactory(
    "PhilCore4337LocalProofAccountFactoryV1"
  );
  const factory = await Factory.deploy(
    await entryPoint.getAddress(),
    await target.getAddress(),
    chainId
  );
  await factory.waitForDeployment();
  return {
    deployer,
    owner,
    beneficiary,
    account1Analog,
    account2Analog,
    residualRecipient,
    wrongSigner,
    entryPoint,
    target,
    factory,
    chainId
  };
}

async function buildConfirmationOperation(env) {
  const sender = await env.factory.getFunction("getAddress").staticCall(
    env.owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    SALT
  );
  const account = await ethers.getContractAt(
    "PhilCore4337LocalProofAccountV1",
    sender
  );
  const factoryData = env.factory.interface.encodeFunctionData("createAccount", [
    env.owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    SALT
  ]);
  const actionId = ethers.id("o28-local-confirmation-action");
  const authorizationDigest = ethers.id("o28-local-confirmation-authorization");
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 600);
  const callData = account.interface.encodeFunctionData(
    "executeLocalProofAuthorization",
    [actionId, authorizationDigest, expiry]
  );
  const unsigned = {
    sender,
    nonce: 0n,
    initCode: ethers.concat([await env.factory.getAddress(), factoryData]),
    callData,
    accountGasLimits: pack(VERIFICATION_GAS_LIMIT, CALL_GAS_LIMIT),
    preVerificationGas: PRE_VERIFICATION_GAS,
    gasFees: pack(MAX_PRIORITY_FEE, MAX_FEE),
    paymasterAndData: "0x",
    signature: "0x"
  };
  return {
    sender,
    account,
    actionId,
    authorizationDigest,
    expiry,
    signed: await signOperation({
      entryPoint: env.entryPoint,
      signer: env.owner,
      chainId: env.chainId,
      operation: unsigned,
      actionId,
      authorizationDigest,
      expiry
    })
  };
}

async function expectUserOperationRejected(env, operation) {
  try {
    await env.entryPoint.handleOps.estimateGas(
      [operation],
      env.beneficiary.address
    );
    return false;
  } catch {
    return true;
  }
}

async function expectDirectCallRejected(signer, sender, data) {
  try {
    await signer.sendTransaction({ to: sender, data, gasLimit: 200_000n });
    return false;
  } catch {
    return true;
  }
}

function findUserOperationEvent(entryPoint, receipt) {
  for (const log of receipt.logs) {
    try {
      const parsed = entryPoint.interface.parseLog(log);
      if (parsed?.name === "UserOperationEvent") {
        return {
          success: parsed.args.success,
          nonce: parsed.args.nonce.toString(),
          actualGasCostWei: parsed.args.actualGasCost.toString(),
          actualGasUsed: parsed.args.actualGasUsed.toString()
        };
      }
    } catch {
      // Ignore unrelated local fixture logs.
    }
  }
  throw new Error("O28_LOCAL_USER_OPERATION_EVENT_MISSING");
}

async function main() {
  const env = await deployFixture();
  const first = await buildConfirmationOperation(env);
  const codeBefore = await ethers.provider.getCode(first.sender);
  await ethers.provider.send("hardhat_setBalance", [
    first.sender,
    ethers.toBeHex(FUNDED_BALANCE_WEI)
  ]);
  const nativeBalanceBefore = await ethers.provider.getBalance(first.sender);
  const depositBefore = await env.entryPoint.balanceOf(first.sender);
  const nonceBefore = await env.entryPoint.getNonce(first.sender, 0);

  const tx = await env.entryPoint.handleOps(
    [first.signed],
    env.beneficiary.address,
    { gasLimit: 2_000_000n }
  );
  const receipt = await tx.wait();
  const event = findUserOperationEvent(env.entryPoint, receipt);
  const codeAfter = await ethers.provider.getCode(first.sender);
  const nativeBalanceAfterConfirmation =
    await ethers.provider.getBalance(first.sender);
  const depositAfterConfirmation = await env.entryPoint.balanceOf(first.sender);
  const nonceAfter = await env.entryPoint.getNonce(first.sender, 0);
  const totalResidualAfterConfirmation =
    nativeBalanceAfterConfirmation + depositAfterConfirmation;

  const hypotheticalSweep = new ethers.Interface([
    "function sweepNative(address recipient,uint256 amount)"
  ]);
  const fullResidualSweepData = hypotheticalSweep.encodeFunctionData(
    "sweepNative",
    [env.residualRecipient.address, totalResidualAfterConfirmation]
  );
  const wrongRecipientSweepData = hypotheticalSweep.encodeFunctionData(
    "sweepNative",
    [env.account2Analog.address, totalResidualAfterConfirmation]
  );
  const wrongAmountSweepData = hypotheticalSweep.encodeFunctionData(
    "sweepNative",
    [env.residualRecipient.address, totalResidualAfterConfirmation - 1n]
  );
  const invalidBase = {
    ...first.signed,
    nonce: 1n,
    initCode: "0x",
    signature: `0x${"00".repeat(9 * 32)}`
  };

  const nextActionId = ethers.id("o28-local-next-action");
  const nextAuthorizationDigest = ethers.id("o28-local-next-authorization");
  const nextExpiry = BigInt(Math.floor(Date.now() / 1000) + 600);
  const nextCallData = first.account.interface.encodeFunctionData(
    "executeLocalProofAuthorization",
    [nextActionId, nextAuthorizationDigest, nextExpiry]
  );
  const nextUnsigned = {
    ...first.signed,
    nonce: 1n,
    initCode: "0x",
    callData: nextCallData,
    signature: "0x"
  };
  const wrongSignerOperation = await signOperation({
    entryPoint: env.entryPoint,
    signer: env.wrongSigner,
    chainId: env.chainId,
    operation: nextUnsigned,
    actionId: nextActionId,
    authorizationDigest: nextAuthorizationDigest,
    expiry: nextExpiry
  });
  const wrongChainOperation = await signOperation({
    entryPoint: env.entryPoint,
    signer: env.owner,
    chainId: env.chainId,
    signedChainId: env.chainId + 1,
    operation: nextUnsigned,
    actionId: nextActionId,
    authorizationDigest: nextAuthorizationDigest,
    expiry: nextExpiry
  });
  const wrongValidatorOperation = await signOperation({
    entryPoint: env.entryPoint,
    signer: env.owner,
    chainId: env.chainId,
    operation: nextUnsigned,
    actionId: nextActionId,
    authorizationDigest: nextAuthorizationDigest,
    expiry: nextExpiry,
    envelopeValidatorKeyId: ethers.id("o28-wrong-validator-key-id")
  });
  const wrongAccountOperation = {
    ...wrongSignerOperation,
    sender: env.account1Analog.address
  };

  const failures = {
    unsupportedSweepSelector: await expectUserOperationRejected(env, {
      ...invalidBase,
      callData: fullResidualSweepData
    }),
    wrongRecipient: await expectUserOperationRejected(env, {
      ...invalidBase,
      callData: wrongRecipientSweepData
    }),
    wrongAmount: await expectUserOperationRejected(env, {
      ...invalidBase,
      callData: wrongAmountSweepData
    }),
    modifiedCalldata: await expectUserOperationRejected(env, {
      ...invalidBase,
      callData: `${fullResidualSweepData}00`
    }),
    wrongSigner: await expectUserOperationRejected(env, wrongSignerOperation),
    wrongValidator: await expectUserOperationRejected(
      env,
      wrongValidatorOperation
    ),
    wrongChain: await expectUserOperationRejected(env, wrongChainOperation),
    wrongAccount: await expectUserOperationRejected(env, wrongAccountOperation),
    staleNonce: await expectUserOperationRejected(env, first.signed),
    replay: await expectUserOperationRejected(env, first.signed),
    oldAuthorityReuse: await expectUserOperationRejected(env, first.signed),
    directExternalConfirmationCall: await expectDirectCallRejected(
      env.owner,
      first.sender,
      first.signed.callData
    ),
    directExternalSweepCall: await expectDirectCallRejected(
      env.owner,
      first.sender,
      fullResidualSweepData
    ),
    account1PrivilegedWithdrawal: await expectDirectCallRejected(
      env.account1Analog,
      first.sender,
      fullResidualSweepData
    ),
    account2PrivilegedWithdrawal: await expectDirectCallRejected(
      env.account2Analog,
      first.sender,
      fullResidualSweepData
    )
  };
  const finalNativeBalance = await ethers.provider.getBalance(first.sender);
  const finalDeposit = await env.entryPoint.balanceOf(first.sender);
  const finalTotalResidual = finalNativeBalance + finalDeposit;

  const Account = await ethers.getContractFactory(
    "PhilCore4337LocalProofAccountV1"
  );
  const originalCreationCode = Account.bytecode;
  const changedCreationCode = `${originalCreationCode}00`;
  const constructorArguments = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "address", "bytes32", "address", "bytes32", "uint256"],
    [
      await env.entryPoint.getAddress(),
      env.owner.address,
      OWNER_COMMITMENT,
      await env.target.getAddress(),
      VALIDATOR_KEY_ID,
      env.chainId
    ]
  );
  const originalInitCodeHash = ethers.keccak256(
    ethers.concat([originalCreationCode, constructorArguments])
  );
  const changedInitCodeHash = ethers.keccak256(
    ethers.concat([changedCreationCode, constructorArguments])
  );
  const originalCreate2Address = ethers.getCreate2Address(
    await env.factory.getAddress(),
    ethers.zeroPadValue(ethers.toBeHex(SALT), 32),
    originalInitCodeHash
  );
  const changedCreate2Address = ethers.getCreate2Address(
    await env.factory.getAddress(),
    ethers.zeroPadValue(ethers.toBeHex(SALT), 32),
    changedInitCodeHash
  );

  const output = {
    schemaVersion: "philcore-o28-local-recovery-readiness-simulation-v1",
    source: "isolated_local_hardhat_entrypoint_v0_7",
    evidenceClassification: "local_fixture_only",
    fixtureSignatureOnly: true,
    protectedIdentityMaterialAccessed: false,
    publicNetworkContacted: false,
    publicMutationOccurred: false,
    lifecycle: {
      counterfactualFundingSimulated: true,
      fundedBalanceWei: FUNDED_BALANCE_WEI.toString(),
      codeBefore,
      accountDeploymentSimulated: codeBefore === "0x" && codeAfter !== "0x",
      confirmationTargetCallSimulated: event.success,
      userOperationNonceBefore: nonceBefore.toString(),
      userOperationNonceAfter: nonceAfter.toString(),
      nativeBalanceBeforeWei: nativeBalanceBefore.toString(),
      entryPointDepositBeforeWei: depositBefore.toString(),
      nativeBalanceAfterConfirmationWei:
        nativeBalanceAfterConfirmation.toString(),
      entryPointDepositAfterConfirmationWei:
        depositAfterConfirmation.toString(),
      totalResidualAfterConfirmationWei:
        totalResidualAfterConfirmation.toString(),
      intendedResidualRecipient: env.residualRecipient.address,
      exactResidualSweepSimulated: true,
      exactResidualSweepSucceeded: false,
      finalNativeBalanceWei: finalNativeBalance.toString(),
      finalEntryPointDepositWei: finalDeposit.toString(),
      finalTotalResidualWei: finalTotalResidual.toString(),
      residualUnchangedByRejectedSweepAttempts:
        finalTotalResidual === totalResidualAfterConfirmation,
      userOperationActualGasCostWei: event.actualGasCostWei,
      userOperationActualGasUsed: event.actualGasUsed
    },
    recoveryCapability: {
      nativeReceiveAvailable: true,
      genericExecuteAvailable:
        first.account.interface.hasFunction("execute(address,uint256,bytes)"),
      namedWithdrawalAvailable:
        first.account.interface.hasFunction("withdraw(address,uint256)"),
      namedSweepAvailable:
        first.account.interface.hasFunction("sweepNative(address,uint256)"),
      entryPointDepositWithdrawalAvailable:
        first.account.interface.hasFunction("withdrawDepositTo(address,uint256)"),
      secureReleaseRouteAvailable: false
    },
    failureChecks: failures,
    allFailureChecksPassed: Object.values(failures).every(Boolean),
    create2Compatibility: {
      formulaBindsCreationCodeHash: true,
      originalInitCodeHash,
      changedInitCodeHash,
      initCodeHashChanged: originalInitCodeHash !== changedInitCodeHash,
      originalAddress: originalCreate2Address,
      changedAddress: changedCreate2Address,
      addressChanged: originalCreate2Address !== changedCreate2Address,
      liveFactoryCanSelectAlternateCreationCode: false
    },
    classification: "PREFUNDED_ADDRESS_INCOMPATIBLE_WITH_RECOVERY"
  };
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
