const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const OWNER_COMMITMENT = ethers.id("o25-local-only-owner-commitment");
const VALIDATOR_KEY_ID = ethers.id("o25-local-only-validator-key");
const MODEL_ID = ethers.id("local-proof-gated-v1");
const SIGNATURE_DOMAIN = ethers.id("PHILCORE_LOCAL_PROOF_GATED_ACCOUNT_SIGNATURE_V1");
const VERIFICATION_GAS_LIMIT = 1_500_000n;
const CALL_GAS_LIMIT = 300_000n;
const PRE_VERIFICATION_GAS = 200_000n;
const MAX_PRIORITY_FEE = 1_500_000n;
const MAX_FEE = 2_500_000_000n;

function pack(high, low) {
  return ethers.toBeHex((BigInt(high) << 128n) + BigInt(low), 32);
}

async function signFixtureOperation(input) {
  const userOperationHash = await input.entryPoint.getUserOpHash(input.operation);
  const signingDigest = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    [
      "bytes32", "uint8", "bytes32", "uint256", "address", "address",
      "bytes32", "bytes32", "bytes32", "uint64", "bytes32"
    ],
    [
      SIGNATURE_DOMAIN,
      1,
      MODEL_ID,
      input.chainId,
      await input.entryPoint.getAddress(),
      input.operation.sender,
      userOperationHash,
      input.actionId,
      input.authorizationDigest,
      input.expiry,
      VALIDATOR_KEY_ID
    ]
  ));
  const raw = ethers.Signature.from(
    await input.owner.signMessage(ethers.getBytes(signingDigest))
  );
  return {
    ...input.operation,
    signature: ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "uint8", "bytes32", "bytes32", "bytes32", "uint64",
        "bytes32", "bytes32", "bytes32", "uint8"
      ],
      [
        1,
        MODEL_ID,
        input.actionId,
        input.authorizationDigest,
        input.expiry,
        VALIDATOR_KEY_ID,
        raw.r,
        raw.s,
        raw.v
      ]
    )
  };
}

function findUserOperationEvent(entryPoint, receipt) {
  for (const log of receipt.logs) {
    try {
      const parsed = entryPoint.interface.parseLog(log);
      if (parsed?.name === "UserOperationEvent") {
        return {
          userOperationHash: parsed.args.userOpHash,
          sender: parsed.args.sender,
          nonce: parsed.args.nonce.toString(),
          success: parsed.args.success,
          actualGasCostWei: parsed.args.actualGasCost.toString(),
          actualGasUsed: parsed.args.actualGasUsed.toString()
        };
      }
    } catch {
      // Ignore unrelated fixture logs.
    }
  }
  throw new Error("o25_local_user_operation_event_missing");
}

async function deployFixture() {
  const [deployer, owner, beneficiary] = await ethers.getSigners();
  const entryPoint = await new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
  await entryPoint.waitForDeployment();
  const Target = await ethers.getContractFactory("PhilCoreLocalProofConfirmationTargetV1");
  const target = await Target.deploy();
  await target.waitForDeployment();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const Factory = await ethers.getContractFactory("PhilCore4337LocalProofAccountFactoryV1");
  const factory = await Factory.deploy(
    await entryPoint.getAddress(),
    await target.getAddress(),
    chainId
  );
  await factory.waitForDeployment();
  return { deployer, owner, beneficiary, entryPoint, target, factory, chainId };
}

async function buildOperation(env, salt, label, overrides = {}) {
  const sender = await env.factory.getFunction("getAddress").staticCall(
    env.owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    salt
  );
  const account = await ethers.getContractAt("PhilCore4337LocalProofAccountV1", sender);
  const factoryData = env.factory.interface.encodeFunctionData("createAccount", [
    env.owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    salt
  ]);
  const actionId = ethers.id(`${label}:action`);
  const authorizationDigest = ethers.id(`${label}:authorization`);
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
    signature: "0x",
    ...overrides
  };
  return {
    sender,
    account,
    factoryData,
    actionId,
    authorizationDigest,
    expiry,
    signed: await signFixtureOperation({
      entryPoint: env.entryPoint,
      owner: env.owner,
      chainId: env.chainId,
      operation: unsigned,
      actionId,
      authorizationDigest,
      expiry
    })
  };
}

async function expectRejected(operation, env) {
  try {
    await env.entryPoint.handleOps.estimateGas([operation], env.beneficiary.address);
    return false;
  } catch {
    return true;
  }
}

async function main() {
  const env = await deployFixture();
  const first = await buildOperation(env, 77n, "o25-counterfactual");
  const requiredGas = VERIFICATION_GAS_LIMIT + CALL_GAS_LIMIT + PRE_VERIFICATION_GAS;
  const requiredPrefund = requiredGas * MAX_FEE;

  await ethers.provider.send("hardhat_setBalance", [
    first.sender,
    ethers.toBeHex(requiredPrefund)
  ]);
  const nonceBefore = await env.entryPoint.getNonce(first.sender, 0);
  const depositBefore = await env.entryPoint.balanceOf(first.sender);
  const txEstimate = await env.entryPoint.handleOps.estimateGas(
    [first.signed],
    env.beneficiary.address
  );
  const tx = await env.entryPoint.handleOps(
    [first.signed],
    env.beneficiary.address,
    { gasLimit: txEstimate * 2n }
  );
  const receipt = await tx.wait();
  const event = findUserOperationEvent(env.entryPoint, receipt);
  const nonceAfter = await env.entryPoint.getNonce(first.sender, 0);
  const depositAfter = await env.entryPoint.balanceOf(first.sender);
  const codeAfter = await ethers.provider.getCode(first.sender);

  const deployedSalt = 78n;
  const deployed = await buildOperation(env, deployedSalt, "o25-deployed");
  const deployTx = await env.factory.createAccount(
    env.owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    deployedSalt
  );
  const deployReceipt = await deployTx.wait();
  await ethers.provider.send("hardhat_setBalance", [
    deployed.sender,
    ethers.toBeHex(requiredPrefund)
  ]);
  const deployedOperation = { ...deployed.signed, initCode: "0x" };
  const resignedDeployed = await signFixtureOperation({
    entryPoint: env.entryPoint,
    owner: env.owner,
    chainId: env.chainId,
    operation: deployedOperation,
    actionId: deployed.actionId,
    authorizationDigest: deployed.authorizationDigest,
    expiry: deployed.expiry
  });
  const deployedTx = await env.entryPoint.handleOps(
    [resignedDeployed],
    env.beneficiary.address,
    { gasLimit: 2_000_000 }
  );
  const deployedReceipt = await deployedTx.wait();
  const deployedEvent = findUserOperationEvent(env.entryPoint, deployedReceipt);
  const componentActionId = ethers.id("o25-component-estimate:action");
  const componentAuthorizationDigest = ethers.id(
    "o25-component-estimate:authorization"
  );
  const componentExpiry = BigInt(Math.floor(Date.now() / 1000) + 600);
  const componentCallData = deployed.account.interface.encodeFunctionData(
    "executeLocalProofAuthorization",
    [componentActionId, componentAuthorizationDigest, componentExpiry]
  );
  const componentUnsigned = {
    ...resignedDeployed,
    nonce: 1n,
    callData: componentCallData,
    signature: "0x"
  };
  const componentSigned = await signFixtureOperation({
    entryPoint: env.entryPoint,
    owner: env.owner,
    chainId: env.chainId,
    operation: componentUnsigned,
    actionId: componentActionId,
    authorizationDigest: componentAuthorizationDigest,
    expiry: componentExpiry
  });
  const componentUserOpHash = await env.entryPoint.getUserOpHash(componentSigned);
  const executionTransactionGas = await ethers.provider.estimateGas({
    from: await env.entryPoint.getAddress(),
    to: deployed.sender,
    data: componentCallData
  });
  const validationTransactionGas = await ethers.provider.estimateGas({
    from: await env.entryPoint.getAddress(),
    to: deployed.sender,
    data: deployed.account.interface.encodeFunctionData("validateUserOp", [
      componentSigned,
      componentUserOpHash,
      0n
    ])
  });

  const failed = {};
  const insufficient = await buildOperation(env, 80n, "o25-insufficient");
  failed.insufficientPrefund = await expectRejected(insufficient.signed, env);
  failed.modifiedFactoryData = await expectRejected({
    ...insufficient.signed,
    initCode: ethers.concat([
      await env.factory.getAddress(),
      `${insufficient.factoryData.slice(0, -2)}00`
    ])
  }, env);
  const wrongSalt = await buildOperation(env, 81n, "o25-wrong-salt");
  failed.wrongAccountSalt = await expectRejected({
    ...wrongSalt.signed,
    sender: insufficient.sender
  }, env);
  failed.wrongValidator = await expectRejected({
    ...insufficient.signed,
    signature: `0x${"00".repeat(9 * 32)}`
  }, env);
  failed.wrongTargetOrCall = await expectRejected({
    ...insufficient.signed,
    callData: "0x12345678"
  }, env);
  failed.nonzeroValueUnavailable = !insufficient.account.interface.hasFunction(
    "execute(address,uint256,bytes)"
  );
  const expired = await buildOperation(env, 82n, "o25-expired");
  const expiredCall = expired.account.interface.encodeFunctionData(
    "executeLocalProofAuthorization",
    [expired.actionId, expired.authorizationDigest, BigInt(Math.floor(Date.now() / 1000) - 1)]
  );
  failed.staleExpiry = await expectRejected({ ...expired.signed, callData: expiredCall }, env);
  failed.invalidPlaceholderSignature = await expectRejected({
    ...insufficient.signed,
    signature: `0x${"00".repeat(9 * 32)}`
  }, env);
  failed.paymasterIntroduction = await expectRejected({
    ...insufficient.signed,
    paymasterAndData: `0x${"11".repeat(52)}`
  }, env);
  const overCeiling = {
    ...insufficient.signed,
    accountGasLimits: pack(1_500_001n, CALL_GAS_LIMIT)
  };
  failed.gasCeilingViolationRejectedByO25Validator =
    BigInt(overCeiling.accountGasLimits) >> 128n > VERIFICATION_GAS_LIMIT;

  const counterfactualGas = BigInt(event.actualGasUsed);
  const deployedGas = BigInt(deployedEvent.actualGasUsed);
  const deploymentComponent = counterfactualGas > deployedGas
    ? counterfactualGas - deployedGas
    : 0n;
  const transactionIntrinsicGas = 21_000n;
  const executionEstimate = executionTransactionGas - transactionIntrinsicGas;
  const validationEstimate = validationTransactionGas - transactionIntrinsicGas;

  const output = {
    schemaVersion: "philcore-o25-local-entrypoint-simulation-v1",
    source: "isolated_local_hardhat_entrypoint_v0_7",
    evidenceClassification: "local_fixture",
    fixtureSignatureOnly: true,
    realUserSignatureGenerated: false,
    protectedIdentityMaterialAccessed: false,
    publicNetworkContacted: false,
    fixtureMutationOnly: true,
    transactionSubmittedToPublicNetwork: false,
    accountCreation: {
      atomicWithFirstOperation: true,
      codeBefore: "0x",
      codeAfterPresent: codeAfter !== "0x",
      directFactoryCreationGasUsed: deployReceipt.gasUsed.toString(),
      approximateFirstOperationCreationGasComponent: deploymentComponent.toString()
    },
    operation: {
      declaredVerificationGasLimit: VERIFICATION_GAS_LIMIT.toString(),
      declaredCallGasLimit: CALL_GAS_LIMIT.toString(),
      declaredPreVerificationGas: PRE_VERIFICATION_GAS.toString(),
      declaredTotalGas: requiredGas.toString(),
      maxFeePerGasWei: MAX_FEE.toString(),
      exactRequiredPrefundWei: requiredPrefund.toString(),
      handleOpsTransactionEstimate: txEstimate.toString(),
      handleOpsTransactionGasUsed: receipt.gasUsed.toString(),
      userOperationActualGasUsed: event.actualGasUsed,
      userOperationActualGasCostWei: event.actualGasCostWei,
      validationGasEstimate: validationEstimate.toString(),
      executionGasEstimate: executionEstimate.toString(),
      componentEstimationMethod:
        "isolated eth_estimateGas calls from the local EntryPoint address with 21000 transaction intrinsic gas removed",
      decompositionLimitation:
        "The component estimates isolate account validation and execution but do not apportion EntryPoint orchestration overhead; the EntryPoint event reports only aggregate actualGasUsed."
    },
    state: {
      nonceBefore: nonceBefore.toString(),
      nonceAfter: nonceAfter.toString(),
      depositBeforeWei: depositBefore.toString(),
      depositAfterWei: depositAfter.toString(),
      targetConfirmationCount: (await env.target.confirmationCount()).toString(),
      confirmationSucceeded: event.success
    },
    rollbackAndFailureChecks: failed,
    allFailureChecksPassed: Object.values(failed).every(Boolean)
  };
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
