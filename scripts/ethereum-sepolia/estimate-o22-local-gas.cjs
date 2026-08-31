const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const OWNER_COMMITMENT = ethers.id("o22-local-gas-owner-commitment");
const VALIDATOR_KEY_ID = ethers.id("o22-local-gas-validator-key");
const MODEL_ID = ethers.id("local-proof-gated-v1");
const SIGNATURE_DOMAIN = ethers.id("PHILCORE_LOCAL_PROOF_GATED_ACCOUNT_SIGNATURE_V1");

function pack(high, low) {
  return ethers.toBeHex((BigInt(high) << 128n) + BigInt(low), 32);
}

async function signOperation(input) {
  const userOperationHash = await input.entryPoint.getUserOpHash(input.operation);
  const digest = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
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
    await input.owner.signMessage(ethers.getBytes(digest))
  );
  const signature = ethers.AbiCoder.defaultAbiCoder().encode(
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
  );
  return { ...input.operation, signature };
}

function userOperationEvent(entryPoint, receipt) {
  for (const log of receipt.logs) {
    try {
      const parsed = entryPoint.interface.parseLog(log);
      if (parsed?.name === "UserOperationEvent") {
        return {
          actualGasCostWei: parsed.args.actualGasCost.toString(),
          actualGasUsed: parsed.args.actualGasUsed.toString(),
          success: parsed.args.success
        };
      }
    } catch {
      // Ignore unrelated fixture logs.
    }
  }
  throw new Error("local_user_operation_event_missing");
}

async function executeFixture(input) {
  const account = await ethers.getContractAt(
    "PhilCore4337LocalProofAccountV1",
    input.accountAddress
  );
  const actionId = ethers.id(input.actionLabel);
  const authorizationDigest = ethers.id(`${input.actionLabel}:authorization`);
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const callData = account.interface.encodeFunctionData(
    "executeLocalProofAuthorization",
    [actionId, authorizationDigest, expiry]
  );
  const operation = {
    sender: input.accountAddress,
    nonce: 0n,
    initCode: input.initCode,
    callData,
    accountGasLimits: pack(1_500_000n, 300_000n),
    preVerificationGas: 200_000n,
    gasFees: pack(1_000_000_000n, 2_000_000_000n),
    paymasterAndData: "0x",
    signature: "0x"
  };
  const signed = await signOperation({
    entryPoint: input.entryPoint,
    owner: input.owner,
    chainId: input.chainId,
    operation,
    actionId,
    authorizationDigest,
    expiry
  });
  const gasEstimate = await input.entryPoint.handleOps.estimateGas(
    [signed],
    input.beneficiary.address
  );
  const transaction = await input.entryPoint.handleOps(
    [signed],
    input.beneficiary.address,
    { gasLimit: gasEstimate * 2n }
  );
  const receipt = await transaction.wait();
  return {
    transactionGasEstimate: gasEstimate.toString(),
    transactionGasUsed: receipt.gasUsed.toString(),
    userOperation: userOperationEvent(input.entryPoint, receipt)
  };
}

async function main() {
  const [deployer, owner, beneficiary] = await ethers.getSigners();
  const entryPoint = await new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
  await entryPoint.waitForDeployment();
  const Target = await ethers.getContractFactory(
    "PhilCoreLocalProofConfirmationTargetV1",
    deployer
  );
  const target = await Target.deploy();
  const targetReceipt = await target.deploymentTransaction().wait();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const Factory = await ethers.getContractFactory(
    "PhilCore4337LocalProofAccountFactoryV1",
    deployer
  );
  const factory = await Factory.deploy(
    await entryPoint.getAddress(),
    await target.getAddress(),
    chainId
  );
  const factoryReceipt = await factory.deploymentTransaction().wait();

  const counterfactualSalt = 77n;
  const counterfactualAddress = await factory.getFunction("getAddress").staticCall(
    owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    counterfactualSalt
  );
  await entryPoint.depositTo(counterfactualAddress, {
    value: ethers.parseEther("1")
  });
  const createCalldata = factory.interface.encodeFunctionData("createAccount", [
    owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    counterfactualSalt
  ]);
  const counterfactual = await executeFixture({
    entryPoint,
    owner,
    beneficiary,
    chainId,
    accountAddress: counterfactualAddress,
    initCode: ethers.concat([await factory.getAddress(), createCalldata]),
    actionLabel: "o22-counterfactual"
  });

  const deployedSalt = 78n;
  const deployedAddress = await factory.getFunction("getAddress").staticCall(
    owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    deployedSalt
  );
  const createTransaction = await factory.createAccount(
    owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    deployedSalt
  );
  const createReceipt = await createTransaction.wait();
  await entryPoint.depositTo(deployedAddress, {
    value: ethers.parseEther("1")
  });
  const deployed = await executeFixture({
    entryPoint,
    owner,
    beneficiary,
    chainId,
    accountAddress: deployedAddress,
    initCode: "0x",
    actionLabel: "o22-deployed"
  });
  const counterfactualGas = BigInt(counterfactual.userOperation.actualGasUsed);
  const deployedGas = BigInt(deployed.userOperation.actualGasUsed);

  process.stdout.write(`${JSON.stringify({
    schemaVersion: "philcore-o22-local-gas-estimate-v1",
    source: "isolated_local_hardhat_entrypoint_v0_7",
    publicNetworkContacted: false,
    fixtureMutationOnly: true,
    targetDeploymentGasUsed: targetReceipt.gasUsed.toString(),
    factoryDeploymentGasUsed: factoryReceipt.gasUsed.toString(),
    directFactoryAccountCreationGasUsed: createReceipt.gasUsed.toString(),
    deployedAccountConfirmationUserOperation: deployed,
    counterfactualFirstUserOperation: counterfactual,
    approximateCounterfactualDeploymentComponentGas:
      (counterfactualGas > deployedGas ? counterfactualGas - deployedGas : 0n).toString(),
    exactBundlerComponentEstimateAvailable: false
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
