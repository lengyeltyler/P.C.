require("tsx/cjs");

const fs = require("node:fs");
const {
  Contract,
  JsonRpcProvider,
  Wallet,
  formatEther,
  getAddress,
  getCreateAddress,
  keccak256
} = require("ethers");

const {
  ARTIFACTS,
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  MAX_FEE_PER_GAS,
  MAX_PRIORITY_FEE_PER_GAS,
  ROOT,
  artifactBindings,
  compilerBinding,
  normalizePrivateKey,
  requireCleanRepository,
  runGit,
  sha256File,
  verifyConfiguredKeyPairs
} = require("./o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET,
  FACTORY_DEPLOYMENT_NONCE,
  O24_PROPOSAL_PATH,
  O24_RECEIPT_PATH,
  assertFreshO24ReceiptPath,
  buildFactoryDeploymentData,
  buildFactoryDeploymentTransaction,
  calculateO24Addresses,
  canonicalDigest,
  ensureNoSecrets,
  expectedFactoryRuntimeBinding,
  factoryConstructorBinding,
  readJson,
  validateReviewedFactoryArtifacts,
  verifySignedFactoryDeployment,
  writeJson
} = require("./o24-factory-common.cjs");
const {
  loadSepoliaLocalEnvironment
} = require("./local-environment.cjs");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");

const TARGET_CONFIRMATIONS = 2;
const WAIT_TIMEOUT_MS = 10 * 60 * 1000;

async function state(provider, address) {
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

function validateProposal(proposal, environment) {
  if (
    proposal.phase !== "O.24"
    || proposal.status !== "proposed"
    || proposal.accepted !== false
  ) {
    throw new Error("o24_proposal_status_invalid");
  }
  const stored = proposal.factoryOnlyApproval;
  if (!stored?.approved || stored.consumed) throw new Error("factory_approval_invalid");
  const binding = { ...stored };
  delete binding.approvalDigest;
  delete binding.approved;
  delete binding.consumed;
  if (canonicalDigest(binding) !== stored.approvalDigest) {
    throw new Error("factory_approval_digest_mismatch");
  }
  if (Date.parse(stored.expiresAt) <= Date.now()) {
    throw new Error("factory_approval_expired");
  }
  if (
    stored.fundingWalletUseApproved
    || stored.smartAccountDeploymentApproved
    || stored.smartAccountFundingApproved
    || stored.deviceVaultSigningApproved
    || stored.bundlerContactApproved
    || stored.userOperationSubmissionApproved
  ) {
    throw new Error("factory_approval_scope_expanded");
  }
  if (
    proposal.canonicalIdentityBinding.ownerCommitment !== environment.identity.ownerCommitment
    || proposal.canonicalIdentityBinding.validatorAddress
      !== environment.identity.validatorAddress
    || proposal.canonicalIdentityBinding.validatorKeyReferenceId
      !== environment.identity.validatorKeyId
  ) {
    throw new Error("canonical_identity_binding_changed");
  }
  if (
    runGit(["merge-base", "--is-ancestor",
      proposal.sourceBinding.sourceCommitAtGeneration, "HEAD"]) !== ""
  ) {
    throw new Error("proposal_source_commit_not_ancestor");
  }
  for (const source of proposal.sourceBinding.sources) {
    if (sha256File(source.path) !== source.sha256) {
      throw new Error("FACTORY_SOURCE_BINDING_STALE");
    }
  }
  if (JSON.stringify(artifactBindings()) !== JSON.stringify(proposal.artifacts)) {
    throw new Error("FACTORY_SOURCE_BINDING_STALE");
  }
  const compiler = compilerBinding();
  for (const key of ["version", "optimizerEnabled", "optimizerRuns", "viaIR", "evmVersion"]) {
    if (compiler[key] !== proposal.compiler[key]) {
      throw new Error("FACTORY_SOURCE_BINDING_STALE");
    }
  }
}

async function main() {
  if (!process.argv.includes("--broadcast-factory")) {
    throw new Error("explicit_factory_broadcast_flag_required");
  }
  requireCleanRepository();
  assertFreshO24ReceiptPath();
  const environment = loadSepoliaLocalEnvironment({
    root: ROOT,
    includeO23rSensitiveSelectors: true
  });
  const keys = verifyConfiguredKeyPairs();
  const proposal = readJson(O24_PROPOSAL_PATH);
  validateProposal(proposal, environment);
  validateReviewedFactoryArtifacts();
  const constructor = factoryConstructorBinding();
  const deployment = buildFactoryDeploymentData();
  const expectedRuntime = expectedFactoryRuntimeBinding();
  const expectedRuntimeEvidence = {
    bytecodeHash: expectedRuntime.bytecodeHash,
    immutableReferences: expectedRuntime.immutableReferences
  };
  const addresses = calculateO24Addresses(
    environment.identity,
    process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
  );
  if (
    deployment.creationBytecodeHash
      !== proposal.factory.deployment.creationBytecodeHash
    || deployment.constructorDataHash
      !== proposal.factory.deployment.constructorDataHash
    || deployment.dataHash !== proposal.factory.deployment.dataHash
    || expectedRuntime.bytecodeHash
      !== proposal.factory.expectedRuntime.bytecodeHash
  ) {
    throw new Error("FACTORY_SOURCE_BINDING_STALE");
  }
  const provider = new JsonRpcProvider(
    process.env.PHILCORE_SEPOLIA_RPC_URL,
    ETHEREUM_SEPOLIA_CHAIN_ID,
    { staticNetwork: true }
  );
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("WRONG_ETHEREUM_CHAIN");
  }
  const before = {
    account1: await state(provider, EXPECTED_DEPLOYER),
    account2: await state(provider, EXPECTED_FUNDING),
    entryPoint: await state(provider, ERC4337_V07_CANONICAL_ENTRYPOINT),
    target: await state(provider, EXPECTED_TARGET),
    factory: await state(provider, EXPECTED_FACTORY),
    smartAccount: await state(provider, EXPECTED_ACCOUNT)
  };
  if (
    before.account1.latestNonce !== FACTORY_DEPLOYMENT_NONCE
    || before.account1.pendingNonce !== FACTORY_DEPLOYMENT_NONCE
  ) {
    throw new Error("FACTORY_DEPLOYMENT_NONCE_CHANGED");
  }
  if (
    before.entryPoint.codeHash !== proposal.preflight.entryPoint.codeHash
    || before.target.codeHash !== proposal.preflight.target.codeHash
  ) {
    throw new Error("entrypoint_or_target_binding_changed");
  }
  if (
    before.factory.codeStatus !== "empty"
    || BigInt(before.factory.balanceWei) !== 0n
    || before.factory.latestNonce !== "0"
  ) {
    throw new Error("FACTORY_ADDRESS_NO_LONGER_EMPTY");
  }
  if (
    before.smartAccount.codeStatus !== "empty"
    || BigInt(before.smartAccount.balanceWei) !== 0n
  ) {
    throw new Error("COUNTERFACTUAL_ACCOUNT_STATE_CHANGED");
  }
  if (
    getCreateAddress({
      from: EXPECTED_DEPLOYER,
      nonce: BigInt(FACTORY_DEPLOYMENT_NONCE)
    }) !== EXPECTED_FACTORY
    || addresses.account !== EXPECTED_ACCOUNT
  ) {
    throw new Error("FACTORY_OR_ACCOUNT_PREDICTION_CHANGED");
  }
  const estimate = await provider.estimateGas({
    from: EXPECTED_DEPLOYER,
    data: deployment.data,
    value: 0n
  });
  const approval = proposal.factoryOnlyApproval;
  const gasLimit = BigInt(approval.gasLimit);
  const maxFeePerGas = BigInt(approval.maxFeePerGasWei);
  const maxPriorityFeePerGas = BigInt(approval.maxPriorityFeePerGasWei);
  if (estimate > gasLimit) throw new Error("factory_gas_limit_stale");
  if (
    maxFeePerGas > MAX_FEE_PER_GAS
    || maxPriorityFeePerGas > MAX_PRIORITY_FEE_PER_GAS
  ) {
    throw new Error("factory_fee_ceiling_exceeded");
  }
  const feeData = await provider.getFeeData();
  if ((feeData.maxFeePerGas ?? feeData.gasPrice ?? 0n) > maxFeePerGas) {
    throw new Error("factory_fee_evidence_stale");
  }
  const maximumCost = gasLimit * maxFeePerGas;
  if (BigInt(before.account1.balanceWei) < maximumCost) {
    throw new Error("factory_deployer_balance_insufficient");
  }
  const block = await provider.getBlock("latest");
  if (!block) throw new Error("latest_block_unavailable");
  const transactionRequest = buildFactoryDeploymentTransaction({
    data: deployment.data,
    dataHash: deployment.dataHash,
    gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas
  });
  const preSigning = {
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    signer: EXPECTED_DEPLOYER,
    signerDerivationMatched: keys.deployer.addressMatch,
    nonce: FACTORY_DEPLOYMENT_NONCE,
    predictedFactory: EXPECTED_FACTORY,
    sourceSha256: approval.factorySourceSha256,
    creationBytecodeHash: deployment.creationBytecodeHash,
    artifactRuntimeBytecodeHash: approval.artifactRuntimeBytecodeHash,
    expectedImmutableRuntimeBytecodeHash: expectedRuntime.bytecodeHash,
    constructorDataHash: deployment.constructorDataHash,
    deploymentDataHash: deployment.dataHash,
    valueWei: "0",
    freshGasEstimate: estimate.toString(),
    gasLimit: gasLimit.toString(),
    maxFeePerGasWei: maxFeePerGas.toString(),
    maxPriorityFeePerGasWei: maxPriorityFeePerGas.toString(),
    maximumTransactionCostWei: maximumCost.toString(),
    latestBlockNumber: String(block.number),
    latestBlockHash: block.hash,
    approvalDigest: approval.approvalDigest,
    approvalExpiresAt: approval.expiresAt
  };
  ensureNoSecrets(preSigning);
  process.stdout.write(`${JSON.stringify({
    status: "O24_FINAL_PRE_SIGNING_CHECK_PASSED",
    ...preSigning
  }, null, 2)}\n`);

  const wallet = new Wallet(normalizePrivateKey(
    process.env.PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY
  ));
  const raw = await wallet.signTransaction(transactionRequest);
  const transactionHash = keccak256(raw);
  const parsed = verifySignedFactoryDeployment(raw, {
    ...transactionRequest,
    signer: EXPECTED_DEPLOYER,
    transactionHash,
    dataHash: deployment.dataHash,
    creationBytecodeLength: deployment.creationBytecodeLength,
    creationBytecodeHash: deployment.creationBytecodeHash,
    constructorDataHash: deployment.constructorDataHash
  });
  let broadcast;
  try {
    broadcast = await provider.broadcastTransaction(raw);
  } catch (error) {
    const reconciled = await provider.getTransaction(transactionHash);
    if (!reconciled) throw error;
    broadcast = reconciled;
  }
  if (broadcast.hash !== transactionHash) throw new Error("factory_broadcast_hash_mismatch");
  const receipt = await provider.waitForTransaction(
    transactionHash,
    TARGET_CONFIRMATIONS,
    WAIT_TIMEOUT_MS
  );
  if (!receipt) throw new Error("factory_receipt_timeout");
  if (receipt.status !== 1) throw new Error("factory_deployment_reverted");
  if (getAddress(receipt.contractAddress) !== EXPECTED_FACTORY) {
    throw new Error("factory_deployed_address_mismatch");
  }
  const transaction = await provider.getTransaction(transactionHash);
  if (
    !transaction
    || getAddress(transaction.from) !== EXPECTED_DEPLOYER
    || transaction.to !== null
    || transaction.nonce !== Number(FACTORY_DEPLOYMENT_NONCE)
    || transaction.value !== 0n
    || keccak256(transaction.data) !== deployment.dataHash
  ) {
    throw new Error("factory_mined_transaction_mismatch");
  }
  if (receipt.logs.length !== 0) throw new Error("unexpected_factory_deployment_logs");
  const deployedCode = await provider.getCode(EXPECTED_FACTORY);
  if (keccak256(deployedCode) !== expectedRuntime.bytecodeHash) {
    throw new Error("factory_runtime_bytecode_mismatch");
  }
  const artifact = readJson(`${ROOT}/${ARTIFACTS.factory}`);
  const factory = new Contract(EXPECTED_FACTORY, artifact.abi, provider);
  const [entryPoint, target, expectedChainId, predictedAccount] = await Promise.all([
    factory.entryPoint(),
    factory.approvedConfirmationTarget(),
    factory.expectedChainId(),
    factory["getAddress(address,bytes32,bytes32,uint256)"](
      environment.identity.validatorAddress,
      environment.identity.ownerCommitment,
      addresses.validatorKeyIdBinding,
      BigInt(process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT)
    )
  ]);
  if (
    getAddress(entryPoint) !== ERC4337_V07_CANONICAL_ENTRYPOINT
    || getAddress(target) !== EXPECTED_TARGET
    || Number(expectedChainId) !== ETHEREUM_SEPOLIA_CHAIN_ID
    || getAddress(predictedAccount) !== EXPECTED_ACCOUNT
  ) {
    throw new Error("factory_constructor_or_account_binding_mismatch");
  }
  const entryPointContract = new Contract(
    ERC4337_V07_CANONICAL_ENTRYPOINT,
    ["function balanceOf(address) view returns (uint256)"],
    provider
  );
  const entryPointDeposit = await entryPointContract.balanceOf(EXPECTED_ACCOUNT);
  if (entryPointDeposit !== 0n) throw new Error("unexpected_entrypoint_deposit");
  const after = {
    account1: await state(provider, EXPECTED_DEPLOYER),
    account2: await state(provider, EXPECTED_FUNDING),
    entryPoint: await state(provider, ERC4337_V07_CANONICAL_ENTRYPOINT),
    target: await state(provider, EXPECTED_TARGET),
    factory: await state(provider, EXPECTED_FACTORY),
    smartAccount: await state(provider, EXPECTED_ACCOUNT)
  };
  if (
    after.account2.latestNonce !== before.account2.latestNonce
    || after.account2.pendingNonce !== before.account2.pendingNonce
    || after.account2.balanceWei !== before.account2.balanceWei
    || after.account2.codeHash !== before.account2.codeHash
  ) {
    throw new Error("funding_wallet_changed_during_o24");
  }
  if (
    after.target.codeHash !== before.target.codeHash
    || after.smartAccount.codeStatus !== "empty"
    || BigInt(after.smartAccount.balanceWei) !== 0n
    || after.account1.latestNonce !== "3"
    || after.account1.pendingNonce !== "3"
  ) {
    throw new Error("o24_post_deployment_state_mismatch");
  }
  const gasUsed = receipt.gasUsed;
  const effectiveGasPrice = receipt.gasPrice;
  const exactCost = gasUsed * effectiveGasPrice;
  const evidence = {
    schemaVersion: "philcore-o24-factory-deployment-receipt-v1",
    phase: "O.24",
    status: "factory_deployed_and_verified",
    sourceHead: proposal.sourceBinding.sourceCommitAtGeneration,
    evidenceRecordedFromHead: runGit(["rev-parse", "HEAD"]),
    compiler: proposal.compiler,
    sourceBinding: proposal.sourceBinding,
    factoryArtifact: proposal.artifacts.find((item) => item.id === "accountFactory"),
    accountArtifact: proposal.artifacts.find((item) => item.id === "account"),
    constructorBinding: constructor,
    expectedImmutableRuntime: expectedRuntimeEvidence,
    entryPointBinding: {
      expected: ERC4337_V07_CANONICAL_ENTRYPOINT,
      actual: getAddress(entryPoint),
      matched: true
    },
    confirmationTargetBinding: {
      expected: EXPECTED_TARGET,
      actual: getAddress(target),
      codeHashBefore: before.target.codeHash,
      codeHashAfter: after.target.codeHash,
      changed: false
    },
    signerPublicAddress: EXPECTED_DEPLOYER,
    signerRecovered: parsed.from,
    nonce: FACTORY_DEPLOYMENT_NONCE,
    predictedFactory: EXPECTED_FACTORY,
    actualFactory: getAddress(receipt.contractAddress),
    transactionHash,
    receiptStatus: "success",
    confirmationsRequired: TARGET_CONFIRMATIONS,
    blockNumber: String(receipt.blockNumber),
    blockHash: receipt.blockHash,
    gasUsed: gasUsed.toString(),
    effectiveGasPriceWei: effectiveGasPrice.toString(),
    exactTransactionCostWei: exactCost.toString(),
    exactTransactionCostEth: formatEther(exactCost),
    runtimeCodeVerification: {
      expectedHash: expectedRuntime.bytecodeHash,
      actualHash: keccak256(deployedCode),
      matched: true
    },
    constructorStateVerification: {
      entryPoint: getAddress(entryPoint),
      approvedConfirmationTarget: getAddress(target),
      expectedChainId: Number(expectedChainId),
      matched: true
    },
    counterfactualAccount: {
      expected: EXPECTED_ACCOUNT,
      recalculatedLocally: addresses.account,
      returnedByFactory: getAddress(predictedAccount),
      accountInitCodeHash: addresses.accountInitCodeHash,
      codeStatus: after.smartAccount.codeStatus,
      balanceWei: after.smartAccount.balanceWei,
      entryPointDepositWei: entryPointDeposit.toString(),
      deployed: false,
      funded: false
    },
    preSigning,
    stateBefore: before,
    stateAfter: after,
    publicMutationOccurred: true,
    publicMutationScope: "factory-deployment-only",
    confirmationTargetChanged: false,
    fundingWalletUsed: false,
    smartAccountDeployed: false,
    smartAccountFunded: false,
    factoryAccountCreationCalled: false,
    entryPointDepositCreated: false,
    deviceVaultSignatureGenerated: false,
    bundlerContacted: false,
    userOperationSubmitted: false,
    acp0002Status: "Proposed",
    betaApproved: false,
    productionApproved: false
  };
  writeJson(O24_RECEIPT_PATH, evidence);
  process.stdout.write(`${JSON.stringify({
    status: "O24_FACTORY_DEPLOYED_AND_VERIFIED",
    transactionHash,
    receiptStatus: "success",
    blockNumber: evidence.blockNumber,
    blockHash: evidence.blockHash,
    actualFactory: evidence.actualFactory,
    runtimeBytecodeMatched: true,
    constructorStateMatched: true,
    entryPointMatched: true,
    counterfactualAccount: EXPECTED_ACCOUNT,
    smartAccountDeployed: false,
    smartAccountFunded: false,
    gasUsed: evidence.gasUsed,
    effectiveGasPriceWei: evidence.effectiveGasPriceWei,
    exactTransactionCostWei: evidence.exactTransactionCostWei,
    account1BalanceAfterWei: after.account1.balanceWei,
    account2Unchanged: true,
    bundlerContacted: false,
    userOperationSubmitted: false,
    publicMutationScope: evidence.publicMutationScope,
    receiptFile: O24_RECEIPT_PATH.replace(`${ROOT}/`, "")
  }, null, 2)}\n`);
}

module.exports = { state, validateProposal };

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
