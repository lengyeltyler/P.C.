require("tsx/cjs");

const { spawnSync } = require("node:child_process");
const {
  JsonRpcProvider,
  formatEther,
  formatUnits,
  getAddress,
  keccak256
} = require("ethers");

const {
  APPROVAL_LIFETIME_MS,
  ARTIFACTS,
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  EXPECTED_VALIDATOR,
  MAX_FEE_PER_GAS,
  MAX_PRIORITY_FEE_PER_GAS,
  O23R_FUNDING_PATH,
  O23R_PROPOSAL_PATH,
  OLD_ADDRESSES,
  ROOT,
  artifactBindings,
  calculateAddresses,
  canonicalDigest,
  compilerBinding,
  ensureNoSecrets,
  initializationBinding,
  readJson,
  requireCleanRepository,
  sourceBinding,
  verifyConfiguredKeyPairs,
  writeJson
} = require("./o23r-common.cjs");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  loadSepoliaLocalEnvironment
} = require("./local-environment.cjs");

const BUFFER_BASIS_POINTS = 2500n;

function amount(value) {
  return {
    wei: value.toString(),
    gwei: formatUnits(value, "gwei"),
    eth: formatEther(value)
  };
}

function withBuffer(value) {
  return value * (10_000n + BUFFER_BASIS_POINTS) / 10_000n;
}

function selectApprovedMaxFee(candidateMaxFee) {
  const boundedDriftAllowance = candidateMaxFee * 4n > 10_000_000_000n
    ? candidateMaxFee * 4n
    : 10_000_000_000n;
  return boundedDriftAllowance > MAX_FEE_PER_GAS
    ? MAX_FEE_PER_GAS
    : boundedDriftAllowance;
}

async function observeAddress(provider, address) {
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

function assertEmptyProposalAddress(name, observation) {
  if (
    observation.codeStatus !== "empty"
    || BigInt(observation.balanceWei) !== 0n
    || observation.latestNonce !== "0"
    || observation.pendingNonce !== "0"
  ) {
    throw new Error(`NEW_DEPLOYER_PROPOSED_ADDRESS_COLLISION:${name}`);
  }
}

function runLocalGasEstimate() {
  const result = spawnSync(
    process.execPath,
    ["scripts/ethereum-sepolia/estimate-o22-local-gas.cjs"],
    { cwd: ROOT, encoding: "utf8", env: { ...process.env } }
  );
  if (result.status !== 0) {
    throw new Error(`local_gas_estimation_failed:${result.stderr.trim()}`);
  }
  return JSON.parse(result.stdout);
}

async function main() {
  requireCleanRepository();
  const environment = loadSepoliaLocalEnvironment({
    root: ROOT,
    includeO23rSensitiveSelectors: true
  });
  const keyPairs = verifyConfiguredKeyPairs();
  const compiler = compilerBinding();
  const artifacts = artifactBindings();
  const sources = sourceBinding();
  const provider = new JsonRpcProvider(
    process.env.PHILCORE_SEPOLIA_RPC_URL,
    ETHEREUM_SEPOLIA_CHAIN_ID,
    { staticNetwork: true }
  );
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("WRONG_ETHEREUM_CHAIN");
  }

  const account1 = await observeAddress(provider, EXPECTED_DEPLOYER);
  const account2 = await observeAddress(provider, EXPECTED_FUNDING);
  const validator = await observeAddress(provider, EXPECTED_VALIDATOR);
  const entryPoint = await observeAddress(provider, ERC4337_V07_CANONICAL_ENTRYPOINT);
  if (entryPoint.codeStatus !== "present") throw new Error("entry_point_verification_failed");
  if (account1.codeStatus !== "empty" || account2.codeStatus !== "empty") {
    throw new Error("disposable_account_is_not_eoa");
  }
  if (process.env.PHILCORE_SEPOLIA_DEPLOYER_NONCE !== account1.pendingNonce) {
    throw new Error("configured_deployer_nonce_stale");
  }

  const addresses = calculateAddresses(environment.identity, account1.pendingNonce);
  const proposed = {
    target: await observeAddress(provider, addresses.targetAddress),
    factory: await observeAddress(provider, addresses.factoryAddress),
    account: await observeAddress(provider, addresses.accountAddress)
  };
  for (const [name, observation] of Object.entries(proposed)) {
    assertEmptyProposalAddress(name, observation);
  }

  const targetArtifact = readJson(`${ROOT}/${ARTIFACTS.target}`);
  const factoryArtifact = readJson(`${ROOT}/${ARTIFACTS.factory}`);
  const initialization = initializationBinding(addresses, environment.identity);
  const targetGasEstimate = await provider.estimateGas({
    from: EXPECTED_DEPLOYER,
    data: targetArtifact.bytecode,
    value: 0n
  });
  const factoryGasEstimate = await provider.estimateGas({
    from: EXPECTED_DEPLOYER,
    data: `${factoryArtifact.bytecode}${initialization.factoryConstructorData.slice(2)}`,
    value: 0n
  });
  const localGas = runLocalGasEstimate();
  const feeData = await provider.getFeeData();
  const gasPrice = feeData.gasPrice ?? 0n;
  const currentPriorityFee = feeData.maxPriorityFeePerGas ?? 1_000_000_000n;
  const approvedPriorityFee = currentPriorityFee > MAX_PRIORITY_FEE_PER_GAS
    ? MAX_PRIORITY_FEE_PER_GAS
    : currentPriorityFee;
  const candidateMaxFee = feeData.maxFeePerGas ?? gasPrice * 2n;
  const approvedMaxFee = selectApprovedMaxFee(candidateMaxFee);
  if (approvedMaxFee <= 0n || approvedPriorityFee <= 0n) {
    throw new Error("fee_data_unresolved");
  }
  const targetGasLimit = withBuffer(targetGasEstimate);
  const latestBlock = await provider.getBlock("latest");
  if (!latestBlock) throw new Error("latest_block_unavailable");
  const issuedAt = new Date();
  const approvalBinding = {
    schemaVersion: "philcore-o23r-target-only-approval-v1",
    approvalSource: "explicit_o23r_user_instruction",
    oneTime: true,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    signer: EXPECTED_DEPLOYER,
    nonce: account1.pendingNonce,
    expectedTargetAddress: addresses.targetAddress,
    sourceSha256: artifacts.find((item) => item.id === "confirmationTarget").sourceSha256,
    creationBytecodeHash:
      artifacts.find((item) => item.id === "confirmationTarget").creationBytecodeHash,
    constructorHash: initialization.targetConstructorHash,
    valueWei: "0",
    gasLimit: targetGasLimit.toString(),
    maxFeePerGasWei: approvedMaxFee.toString(),
    maxPriorityFeePerGasWei: approvedPriorityFee.toString(),
    latestBlockNumber: String(latestBlock.number),
    latestBlockHash: latestBlock.hash,
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + APPROVAL_LIFETIME_MS).toISOString(),
    approvedScope: "new-deployer-confirmation-target-only",
    factoryDeploymentApproved: false,
    fundingWalletUseApproved: false,
    smartAccountFundingApproved: false,
    deviceVaultSigningApproved: false,
    bundlerContactApproved: false,
    userOperationSubmissionApproved: false
  };
  const targetOnlyApproval = {
    ...approvalBinding,
    approvalDigest: canonicalDigest(approvalBinding),
    approved: true,
    consumed: false
  };

  const deployerDeploymentGas = targetGasEstimate + factoryGasEstimate;
  const bufferedDeployerGas = withBuffer(deployerDeploymentGas);
  const accountOperationGas = BigInt(
    localGas.counterfactualFirstUserOperation.userOperation.actualGasUsed
  );
  const funding = {
    schemaVersion: "philcore-o23r-new-deployer-funding-readiness-v1",
    phase: "O.23R",
    status: "proposed_estimates_only",
    accepted: false,
    fundingApproved: false,
    fundingPerformed: false,
    gasReference: {
      gasPrice: amount(gasPrice),
      approvedTargetMaxFeePerGas: amount(approvedMaxFee),
      approvedTargetMaxPriorityFeePerGas: amount(approvedPriorityFee),
      safetyBufferBasisPoints: Number(BUFFER_BASIS_POINTS)
    },
    deploymentWallet: {
      address: EXPECTED_DEPLOYER,
      purpose: "target deployment now; factory only after separate approval",
      balance: amount(BigInt(account1.balanceWei)),
      targetEstimatedGas: targetGasEstimate.toString(),
      factoryEstimatedGas: factoryGasEstimate.toString(),
      combinedEstimatedGas: deployerDeploymentGas.toString(),
      combinedBufferedGas: bufferedDeployerGas.toString(),
      estimatedMinimum: amount(deployerDeploymentGas * gasPrice),
      recommendedTestAmount: amount(bufferedDeployerGas * approvedMaxFee),
      targetMaximumApprovedCost: amount(targetGasLimit * approvedMaxFee)
    },
    futurePrefundingWallet: {
      address: EXPECTED_FUNDING,
      purpose: "future counterfactual account funding only",
      balance: amount(BigInt(account2.balanceWei)),
      useApprovedInO23R: false,
      transactionSigningApprovedInO23R: false
    },
    counterfactualSmartAccount: {
      address: addresses.accountAddress,
      currentBalance: amount(BigInt(proposed.account.balanceWei)),
      estimatedMinimum: amount(accountOperationGas * gasPrice),
      fundingApproved: false,
      fundingPerformed: false
    },
    publicMutationOccurred: false
  };

  const proposal = {
    schemaVersion: "philcore-o23r-new-deployer-deployment-proposal-v1",
    phase: "O.23R",
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
      preservedUnchanged: true,
      privateMaterialAccessed: false
    },
    keyPairVerification: {
      account1: keyPairs.deployer,
      account2: keyPairs.funding
    },
    network: {
      profileId: "ethereum_sepolia",
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
      entryPointCodeStatus: entryPoint.codeStatus,
      entryPointCodeHash: entryPoint.codeHash,
      latestBlockNumber: String(latestBlock.number),
      latestBlockHash: latestBlock.hash,
      checkedAt: issuedAt.toISOString()
    },
    accountObservations: {
      deploymentWallet: account1,
      futurePrefundingWallet: account2,
      canonicalValidator: validator
    },
    oldAddressInvalidation: {
      ...OLD_ADDRESSES,
      status: "stale_historical_proposals_not_reused"
    },
    addressSequence: {
      targetDeploymentNonce: addresses.targetDeploymentNonce,
      targetAddress: addresses.targetAddress,
      factoryDeploymentNonce: addresses.factoryDeploymentNonce,
      factoryAddress: addresses.factoryAddress,
      accountSalt: addresses.inputs.accountSalt,
      counterfactualAccountAddress: addresses.accountAddress,
      proposedAddressObservations: proposed,
      unexpectedCollision: false
    },
    initialization,
    gasEstimates: {
      liveReadOnly: {
        targetDeploymentGas: targetGasEstimate.toString(),
        factoryDeploymentGas: factoryGasEstimate.toString()
      },
      localDeterministic: localGas,
      bundler: {
        status: "NOT_CONFIGURED_OR_CONTACTED",
        contacted: false
      }
    },
    fundingReference: "config/ethereum-sepolia/O23R_NEW_DEPLOYER_FUNDING_READINESS.json",
    targetOnlyApproval,
    approvals: {
      targetDeploymentApproved: true,
      factoryDeploymentApproved: false,
      smartAccountFundingApproved: false,
      fundingWalletUseApproved: false,
      deviceVaultSigningApproved: false,
      bundlerContactApproved: false,
      userOperationSubmissionApproved: false
    },
    mutationState: {
      transactionSigned: false,
      transactionBroadcast: false,
      targetDeployed: false,
      factoryDeployed: false,
      smartAccountFunded: false,
      fundingWalletUsed: false,
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
  ensureNoSecrets(funding);
  writeJson(O23R_PROPOSAL_PATH, proposal);
  writeJson(O23R_FUNDING_PATH, funding);
  process.stdout.write(`${JSON.stringify({
    status: "O23R_NEW_DEPLOYER_READINESS_CREATED",
    account1: keyPairs.deployer,
    account2: keyPairs.funding,
    canonicalValidatorPreserved: keyPairs.validator.preserved,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    latestNonce: account1.latestNonce,
    pendingNonce: account1.pendingNonce,
    addresses: {
      target: addresses.targetAddress,
      factory: addresses.factoryAddress,
      account: addresses.accountAddress
    },
    collisions: false,
    targetOnlyApprovalDigest: targetOnlyApproval.approvalDigest,
    targetOnlyApprovalExpiresAt: targetOnlyApproval.expiresAt,
    publicMutationOccurred: false,
    files: [
      O23R_PROPOSAL_PATH.replace(`${ROOT}/`, ""),
      O23R_FUNDING_PATH.replace(`${ROOT}/`, "")
    ]
  }, null, 2)}\n`);
}

module.exports = {
  assertEmptyProposalAddress,
  observeAddress,
  selectApprovedMaxFee
};

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
