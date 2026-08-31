require("tsx/cjs");

const {
  JsonRpcProvider,
  formatEther,
  getAddress,
  keccak256
} = require("ethers");

const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  EXPECTED_VALIDATOR,
  MAX_PRIORITY_FEE_PER_GAS,
  ROOT,
  artifactBindings,
  compilerBinding,
  requireCleanRepository,
  sourceBinding,
  verifyConfiguredKeyPairs
} = require("./o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET,
  FACTORY_DEPLOYMENT_NONCE,
  O23R_RECEIPT_PATH,
  O24_PROPOSAL_PATH,
  assertFreshO24ReceiptPath,
  buildFactoryDeploymentData,
  calculateO24Addresses,
  canonicalDigest,
  ensureNoSecrets,
  expectedFactoryRuntimeBinding,
  factoryConstructorBinding,
  readJson,
  validateReviewedFactoryArtifacts,
  writeJson
} = require("./o24-factory-common.cjs");
const {
  selectApprovedMaxFee
} = require("./generate-o23r-readiness.cjs");
const {
  loadSepoliaLocalEnvironment
} = require("./local-environment.cjs");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");

const BUFFER_BASIS_POINTS = 2500n;
const APPROVAL_LIFETIME_MS = 2 * 60 * 60 * 1000;

function withBuffer(value) {
  return value * (10_000n + BUFFER_BASIS_POINTS) / 10_000n;
}

async function observe(provider, address) {
  const [latestNonce, pendingNonce, balance, code] = await Promise.all([
    provider.getTransactionCount(address, "latest"),
    provider.getTransactionCount(address, "pending"),
    provider.getBalance(address),
    provider.getCode(address)
  ]);
  return {
    address: getAddress(address),
    latestNonce: String(latestNonce),
    pendingNonce: String(pendingNonce),
    balanceWei: balance.toString(),
    codeStatus: code === "0x" ? "empty" : "present",
    codeHash: code === "0x" ? null : keccak256(code)
  };
}

function requireEmpty(name, state) {
  if (
    state.codeStatus !== "empty"
    || BigInt(state.balanceWei) !== 0n
    || state.latestNonce !== "0"
    || state.pendingNonce !== "0"
  ) {
    throw new Error(name === "factory"
      ? "FACTORY_ADDRESS_NO_LONGER_EMPTY"
      : "COUNTERFACTUAL_ACCOUNT_STATE_CHANGED");
  }
}

async function main() {
  requireCleanRepository();
  assertFreshO24ReceiptPath();
  const environment = loadSepoliaLocalEnvironment({
    root: ROOT,
    includeO23rSensitiveSelectors: true
  });
  const keys = verifyConfiguredKeyPairs();
  const o23r = readJson(O23R_RECEIPT_PATH);
  if (
    o23r.receiptStatus !== "success"
    || o23r.actualTarget !== EXPECTED_TARGET
    || !o23r.runtimeCodeVerification?.matched
  ) {
    throw new Error("O23R_TARGET_EVIDENCE_INVALID");
  }
  const compiler = compilerBinding();
  const artifacts = validateReviewedFactoryArtifacts();
  const sources = sourceBinding();
  const constructor = factoryConstructorBinding();
  const deployment = buildFactoryDeploymentData();
  const runtime = expectedFactoryRuntimeBinding();
  const runtimeEvidence = {
    bytecodeHash: runtime.bytecodeHash,
    immutableReferences: runtime.immutableReferences
  };
  const addresses = calculateO24Addresses(
    environment.identity,
    process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
  );
  const provider = new JsonRpcProvider(
    process.env.PHILCORE_SEPOLIA_RPC_URL,
    ETHEREUM_SEPOLIA_CHAIN_ID,
    { staticNetwork: true }
  );
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("WRONG_ETHEREUM_CHAIN");
  }
  const states = {
    account1: await observe(provider, EXPECTED_DEPLOYER),
    account2: await observe(provider, EXPECTED_FUNDING),
    validator: await observe(provider, EXPECTED_VALIDATOR),
    entryPoint: await observe(provider, ERC4337_V07_CANONICAL_ENTRYPOINT),
    target: await observe(provider, EXPECTED_TARGET),
    factory: await observe(provider, EXPECTED_FACTORY),
    smartAccount: await observe(provider, EXPECTED_ACCOUNT)
  };
  if (
    states.account1.latestNonce !== FACTORY_DEPLOYMENT_NONCE
    || states.account1.pendingNonce !== FACTORY_DEPLOYMENT_NONCE
  ) {
    throw new Error("FACTORY_DEPLOYMENT_NONCE_CHANGED");
  }
  if (states.entryPoint.codeStatus !== "present") {
    throw new Error("entry_point_verification_failed");
  }
  if (
    states.target.codeStatus !== "present"
    || states.target.codeHash !== o23r.runtimeCodeVerification.actualHash
  ) {
    throw new Error("confirmation_target_verification_failed");
  }
  requireEmpty("factory", states.factory);
  requireEmpty("smartAccount", states.smartAccount);
  const estimate = await provider.estimateGas({
    from: EXPECTED_DEPLOYER,
    data: deployment.data,
    value: 0n
  });
  const gasLimit = withBuffer(estimate);
  const fees = await provider.getFeeData();
  const approvedMaxFee = selectApprovedMaxFee(
    fees.maxFeePerGas ?? fees.gasPrice ?? 0n
  );
  const currentPriorityFee = fees.maxPriorityFeePerGas ?? 1_000_000_000n;
  const approvedPriorityFee = currentPriorityFee > MAX_PRIORITY_FEE_PER_GAS
    ? MAX_PRIORITY_FEE_PER_GAS
    : currentPriorityFee;
  const maximumCost = gasLimit * approvedMaxFee;
  if (BigInt(states.account1.balanceWei) < maximumCost) {
    throw new Error("factory_deployer_balance_insufficient");
  }
  const block = await provider.getBlock("latest");
  if (!block) throw new Error("latest_block_unavailable");
  const issuedAt = new Date();
  const approvalBinding = {
    schemaVersion: "philcore-o24-factory-only-approval-v1",
    approvalSource: "explicit_o24_user_instruction",
    oneTime: true,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    signer: EXPECTED_DEPLOYER,
    nonce: FACTORY_DEPLOYMENT_NONCE,
    predictedFactory: EXPECTED_FACTORY,
    factorySourceSha256:
      artifacts.find((item) => item.id === "accountFactory").sourceSha256,
    creationBytecodeHash: deployment.creationBytecodeHash,
    artifactRuntimeBytecodeHash:
      artifacts.find((item) => item.id === "accountFactory").deployedBytecodeHash,
    expectedImmutableRuntimeBytecodeHash: runtime.bytecodeHash,
    constructorDataHash: deployment.constructorDataHash,
    deploymentDataHash: deployment.dataHash,
    valueWei: "0",
    gasEstimate: estimate.toString(),
    gasLimit: gasLimit.toString(),
    maxFeePerGasWei: approvedMaxFee.toString(),
    maxPriorityFeePerGasWei: approvedPriorityFee.toString(),
    maximumTransactionCostWei: maximumCost.toString(),
    latestBlockNumber: String(block.number),
    latestBlockHash: block.hash,
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + APPROVAL_LIFETIME_MS).toISOString(),
    approvedScope: "factory-deployment-only",
    fundingWalletUseApproved: false,
    smartAccountDeploymentApproved: false,
    smartAccountFundingApproved: false,
    deviceVaultSigningApproved: false,
    bundlerContactApproved: false,
    userOperationSubmissionApproved: false
  };
  const approval = {
    ...approvalBinding,
    approvalDigest: canonicalDigest(approvalBinding),
    approved: true,
    consumed: false
  };
  const proposal = {
    schemaVersion: "philcore-o24-factory-deployment-proposal-v1",
    phase: "O.24",
    status: "proposed",
    accepted: false,
    sourceBinding: sources,
    compiler,
    artifacts,
    canonicalIdentityBinding: {
      identityId: environment.identity.identityId,
      ownerCommitment: environment.identity.ownerCommitment,
      validatorAddress: environment.identity.validatorAddress,
      validatorKeyReferenceId: environment.identity.validatorKeyId,
      preservedUnchanged: true
    },
    keyPairVerification: {
      account1: keys.deployer,
      account2: keys.funding
    },
    network: {
      profileId: "ethereum_sepolia",
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      latestBlockNumber: String(block.number),
      latestBlockHash: block.hash,
      checkedAt: issuedAt.toISOString()
    },
    preflight: states,
    confirmationTargetEvidence: {
      address: EXPECTED_TARGET,
      deploymentTransactionHash: o23r.transactionHash,
      expectedRuntimeCodeHash: o23r.runtimeCodeVerification.actualHash,
      liveRuntimeCodeHash: states.target.codeHash,
      unchanged: true
    },
    factory: {
      address: EXPECTED_FACTORY,
      deploymentNonce: FACTORY_DEPLOYMENT_NONCE,
      constructor,
      deployment,
      expectedRuntime: runtimeEvidence,
      embedsAccountCreationBytecode: true,
      usesCreate2Directly: true,
      standaloneImplementationRequired: false
    },
    counterfactualAccount: {
      address: addresses.account,
      factory: addresses.factory,
      accountSaltDecimal: addresses.accountSaltDecimal,
      accountSaltBytes32: addresses.accountSaltBytes32,
      validatorAddress: environment.identity.validatorAddress,
      ownerCommitment: environment.identity.ownerCommitment,
      validatorKeyIdBinding: addresses.validatorKeyIdBinding,
      accountCreationBytecodeHash: addresses.accountCreationBytecodeHash,
      accountConstructorDataHash: addresses.accountConstructorDataHash,
      accountInitCodeHash: addresses.accountInitCodeHash,
      codeStatus: states.smartAccount.codeStatus,
      balanceWei: states.smartAccount.balanceWei,
      deployed: false,
      funded: false
    },
    gasAndFee: {
      estimateWei: estimate.toString(),
      gasLimit: gasLimit.toString(),
      maxFeePerGasWei: approvedMaxFee.toString(),
      maxPriorityFeePerGasWei: approvedPriorityFee.toString(),
      maximumTransactionCostWei: maximumCost.toString(),
      maximumTransactionCostEth: formatEther(maximumCost),
      safetyBufferBasisPoints: Number(BUFFER_BASIS_POINTS)
    },
    factoryOnlyApproval: approval,
    mutationState: {
      transactionSigned: false,
      transactionBroadcast: false,
      factoryDeployed: false,
      fundingWalletUsed: false,
      smartAccountDeployed: false,
      smartAccountFunded: false,
      deviceVaultSignatureGenerated: false,
      bundlerContacted: false,
      userOperationSubmitted: false,
      publicMutationOccurred: false
    },
    acp0002Status: "Proposed",
    betaApproved: false,
    productionApproved: false
  };
  ensureNoSecrets(proposal);
  writeJson(O24_PROPOSAL_PATH, proposal);
  process.stdout.write(`${JSON.stringify({
    status: "O24_FACTORY_READINESS_CREATED",
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    account1Nonce: states.account1.pendingNonce,
    targetVerified: true,
    factory: EXPECTED_FACTORY,
    smartAccount: EXPECTED_ACCOUNT,
    factoryEmpty: true,
    smartAccountEmptyAndUnfunded: true,
    gasEstimate: estimate.toString(),
    gasLimit: gasLimit.toString(),
    maximumCostWei: maximumCost.toString(),
    approvalDigest: approval.approvalDigest,
    approvalExpiresAt: approval.expiresAt,
    publicMutationOccurred: false,
    proposalFile: O24_PROPOSAL_PATH.replace(`${ROOT}/`, "")
  }, null, 2)}\n`);
}

module.exports = { observe, requireEmpty };

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
