require("tsx/cjs");

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
  O23R_PROPOSAL_PATH,
  O23R_RECEIPT_PATH,
  ROOT,
  TARGET_CONFIRMATIONS,
  artifactBindings,
  buildTargetDeploymentTransaction,
  calculateAddresses,
  canonicalDigest,
  compilerBinding,
  ensureNoSecrets,
  initializationBinding,
  normalizePrivateKey,
  readJson,
  requireCleanRepository,
  runGit,
  sha256File,
  verifyConfiguredKeyPairs,
  verifySignedTargetDeployment,
  writeJson
} = require("./o23r-common.cjs");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  loadSepoliaLocalEnvironment
} = require("./local-environment.cjs");

const SECURITY_MODEL_ID =
  "0x23dfc212b869b8ab99a124b1577adcd22a72f948ffc53efe44b5b37ae5647c4c";
const WAIT_TIMEOUT_MS = 10 * 60 * 1000;

async function readState(provider, address) {
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

function verifyProposalBindings(proposal, environment) {
  if (proposal.phase !== "O.23R" || proposal.status !== "proposed") {
    throw new Error("o23r_proposal_status_invalid");
  }
  if (proposal.accepted !== false) throw new Error("proposal_acceptance_must_remain_false");
  if (!proposal.targetOnlyApproval?.approved || proposal.targetOnlyApproval?.consumed) {
    throw new Error("target_only_approval_invalid");
  }
  const approval = { ...proposal.targetOnlyApproval };
  delete approval.approvalDigest;
  delete approval.approved;
  delete approval.consumed;
  if (canonicalDigest(approval) !== proposal.targetOnlyApproval.approvalDigest) {
    throw new Error("target_only_approval_digest_mismatch");
  }
  if (Date.parse(proposal.targetOnlyApproval.expiresAt) <= Date.now()) {
    throw new Error("target_only_approval_expired");
  }
  if (
    proposal.approvals.factoryDeploymentApproved
    || proposal.approvals.smartAccountFundingApproved
    || proposal.approvals.fundingWalletUseApproved
    || proposal.approvals.deviceVaultSigningApproved
    || proposal.approvals.bundlerContactApproved
    || proposal.approvals.userOperationSubmissionApproved
  ) {
    throw new Error("o23r_scope_expanded");
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
    if (sha256File(source.path) !== source.sha256) throw new Error("source_binding_changed");
  }
  if (JSON.stringify(artifactBindings()) !== JSON.stringify(proposal.artifacts)) {
    throw new Error("CURRENT_SOURCE_BYTECODE_CHANGED");
  }
  const compiler = compilerBinding();
  for (const field of [
    "version",
    "optimizerEnabled",
    "optimizerRuns",
    "viaIR",
    "evmVersion"
  ]) {
    if (compiler[field] !== proposal.compiler[field]) {
      throw new Error("compiler_configuration_mismatch");
    }
  }
}

async function main() {
  if (!process.argv.includes("--broadcast-target")) {
    throw new Error("explicit_target_broadcast_flag_required");
  }
  requireCleanRepository();
  const environment = loadSepoliaLocalEnvironment({
    root: ROOT,
    includeO23rSensitiveSelectors: true
  });
  const keyPairs = verifyConfiguredKeyPairs();
  const proposal = readJson(O23R_PROPOSAL_PATH);
  verifyProposalBindings(proposal, environment);

  const provider = new JsonRpcProvider(
    process.env.PHILCORE_SEPOLIA_RPC_URL,
    ETHEREUM_SEPOLIA_CHAIN_ID,
    { staticNetwork: true }
  );
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("WRONG_ETHEREUM_CHAIN");
  }
  const [account1Before, account2Before, entryPointBefore] = await Promise.all([
    readState(provider, EXPECTED_DEPLOYER),
    readState(provider, EXPECTED_FUNDING),
    readState(provider, ERC4337_V07_CANONICAL_ENTRYPOINT)
  ]);
  if (entryPointBefore.codeStatus !== "present") {
    throw new Error("entry_point_verification_failed");
  }
  if (
    account1Before.latestNonce !== proposal.targetOnlyApproval.nonce
    || account1Before.pendingNonce !== proposal.targetOnlyApproval.nonce
  ) {
    throw new Error("NEW_DEPLOYER_NONCE_CHANGED");
  }
  if (account2Before.latestNonce !== "0" || account2Before.pendingNonce !== "0") {
    throw new Error("funding_wallet_state_changed_before_o23r");
  }
  const addresses = calculateAddresses(environment.identity, account1Before.pendingNonce);
  if (
    addresses.targetAddress !== proposal.addressSequence.targetAddress
    || addresses.factoryAddress !== proposal.addressSequence.factoryAddress
    || addresses.accountAddress !== proposal.addressSequence.counterfactualAccountAddress
  ) {
    throw new Error("target_or_downstream_address_changed_after_approval");
  }
  const targetBefore = await readState(provider, addresses.targetAddress);
  if (
    targetBefore.codeStatus !== "empty"
    || BigInt(targetBefore.balanceWei) !== 0n
    || targetBefore.latestNonce !== "0"
  ) {
    throw new Error("NEW_DEPLOYER_PROPOSED_ADDRESS_COLLISION");
  }

  const artifact = readJson(`${ROOT}/${ARTIFACTS.target}`);
  const targetBinding = proposal.artifacts.find(
    (item) => item.id === "confirmationTarget"
  );
  const initialization = initializationBinding(addresses, environment.identity);
  if (
    keccak256(artifact.bytecode) !== targetBinding.creationBytecodeHash
    || initialization.targetConstructorHash !== proposal.targetOnlyApproval.constructorHash
  ) {
    throw new Error("CURRENT_SOURCE_BYTECODE_CHANGED");
  }
  const estimatedGas = await provider.estimateGas({
    from: EXPECTED_DEPLOYER,
    data: artifact.bytecode,
    value: 0n
  });
  const gasLimit = BigInt(proposal.targetOnlyApproval.gasLimit);
  if (estimatedGas > gasLimit) throw new Error("approved_gas_limit_below_fresh_estimate");
  const maxFeePerGas = BigInt(proposal.targetOnlyApproval.maxFeePerGasWei);
  const maxPriorityFeePerGas = BigInt(
    proposal.targetOnlyApproval.maxPriorityFeePerGasWei
  );
  if (
    maxFeePerGas > MAX_FEE_PER_GAS
    || maxPriorityFeePerGas > MAX_PRIORITY_FEE_PER_GAS
  ) {
    throw new Error("approved_fee_ceiling_exceeded");
  }
  const feeData = await provider.getFeeData();
  if ((feeData.maxFeePerGas ?? feeData.gasPrice ?? 0n) > maxFeePerGas) {
    throw new Error("approved_max_fee_below_current_network_requirement");
  }
  const maxTransactionCost = gasLimit * maxFeePerGas;
  if (BigInt(account1Before.balanceWei) < maxTransactionCost) {
    throw new Error("insufficient_deployment_wallet_balance");
  }
  const latestBlock = await provider.getBlock("latest");
  if (!latestBlock) throw new Error("latest_block_unavailable");
  const transactionRequest = buildTargetDeploymentTransaction({
    nonce: proposal.targetOnlyApproval.nonce,
    creationBytecode: artifact.bytecode,
    creationBytecodeHash: targetBinding.creationBytecodeHash,
    gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas
  });
  const predictedTarget = getCreateAddress({
    from: EXPECTED_DEPLOYER,
    nonce: BigInt(transactionRequest.nonce)
  });
  if (predictedTarget !== addresses.targetAddress) {
    throw new Error("target_prediction_mismatch");
  }
  const preSigning = {
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    signer: EXPECTED_DEPLOYER,
    signerDerivationMatched: keyPairs.deployer.addressMatch,
    nonce: String(transactionRequest.nonce),
    expectedTargetAddress: addresses.targetAddress,
    sourceSha256: targetBinding.sourceSha256,
    creationBytecodeHash: targetBinding.creationBytecodeHash,
    constructorHash: initialization.targetConstructorHash,
    valueWei: "0",
    freshGasEstimate: estimatedGas.toString(),
    gasLimit: gasLimit.toString(),
    maxFeePerGasWei: maxFeePerGas.toString(),
    maxPriorityFeePerGasWei: maxPriorityFeePerGas.toString(),
    maximumTransactionCostWei: maxTransactionCost.toString(),
    latestBlockNumber: String(latestBlock.number),
    latestBlockHash: latestBlock.hash,
    approvalDigest: proposal.targetOnlyApproval.approvalDigest,
    approvalExpiresAt: proposal.targetOnlyApproval.expiresAt
  };
  ensureNoSecrets(preSigning);
  process.stdout.write(`${JSON.stringify({
    status: "O23R_FINAL_PRE_SIGNING_CHECK_PASSED",
    ...preSigning
  }, null, 2)}\n`);

  const wallet = new Wallet(
    normalizePrivateKey(process.env.PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY)
  );
  const rawSignedTransaction = await wallet.signTransaction(transactionRequest);
  const transactionHash = keccak256(rawSignedTransaction);
  const parsed = verifySignedTargetDeployment(rawSignedTransaction, {
    ...transactionRequest,
    signer: EXPECTED_DEPLOYER,
    nonce: String(transactionRequest.nonce),
    creationBytecodeHash: targetBinding.creationBytecodeHash,
    transactionHash
  });
  if (parsed.from !== EXPECTED_DEPLOYER) throw new Error("signer_recovery_failed");

  let broadcast;
  try {
    broadcast = await provider.broadcastTransaction(rawSignedTransaction);
  } catch (error) {
    const reconciled = await provider.getTransaction(transactionHash);
    if (!reconciled) throw error;
    broadcast = reconciled;
  }
  if (broadcast.hash !== transactionHash) throw new Error("broadcast_hash_mismatch");
  const receipt = await provider.waitForTransaction(
    transactionHash,
    TARGET_CONFIRMATIONS,
    WAIT_TIMEOUT_MS
  );
  if (!receipt) throw new Error("target_deployment_receipt_timeout");
  if (receipt.status !== 1) throw new Error("target_deployment_reverted");
  if (!receipt.contractAddress) throw new Error("target_contract_address_missing");
  if (getAddress(receipt.contractAddress) !== addresses.targetAddress) {
    throw new Error("deployed_target_address_mismatch");
  }
  const transaction = await provider.getTransaction(transactionHash);
  if (!transaction) throw new Error("deployed_transaction_unavailable");
  if (
    getAddress(transaction.from) !== EXPECTED_DEPLOYER
    || transaction.to !== null
    || transaction.nonce !== Number(proposal.targetOnlyApproval.nonce)
    || transaction.value !== 0n
    || keccak256(transaction.data) !== targetBinding.creationBytecodeHash
  ) {
    throw new Error("mined_transaction_binding_mismatch");
  }
  if (receipt.logs.length !== 0) throw new Error("unexpected_target_deployment_logs");

  const deployedCode = await provider.getCode(addresses.targetAddress);
  if (keccak256(deployedCode) !== targetBinding.deployedBytecodeHash) {
    throw new Error("deployed_runtime_bytecode_mismatch");
  }
  const target = new Contract(
    addresses.targetAddress,
    artifact.abi,
    provider
  );
  const securityModelId = await target.SECURITY_MODEL_ID();
  if (securityModelId !== SECURITY_MODEL_ID) {
    throw new Error("target_security_model_state_mismatch");
  }
  const postBlock = await provider.getBlock("latest");
  const [
    account1After,
    account2After,
    targetAfter,
    factoryAfter,
    smartAccountAfter
  ] = await Promise.all([
    readState(provider, EXPECTED_DEPLOYER),
    readState(provider, EXPECTED_FUNDING),
    readState(provider, addresses.targetAddress),
    readState(provider, addresses.factoryAddress),
    readState(provider, addresses.accountAddress)
  ]);
  if (
    account2After.latestNonce !== account2Before.latestNonce
    || account2After.pendingNonce !== account2Before.pendingNonce
    || account2After.balanceWei !== account2Before.balanceWei
    || account2After.codeHash !== account2Before.codeHash
  ) {
    throw new Error("funding_wallet_changed_during_o23r");
  }
  for (const [name, state] of Object.entries({
    factory: factoryAfter,
    smartAccount: smartAccountAfter
  })) {
    if (state.codeStatus !== "empty" || BigInt(state.balanceWei) !== 0n) {
      throw new Error(`unexpected_downstream_mutation:${name}`);
    }
  }
  const gasUsed = receipt.gasUsed;
  const effectiveGasPrice = receipt.gasPrice;
  const exactCost = gasUsed * effectiveGasPrice;
  const receiptEvidence = {
    schemaVersion: "philcore-o23r-confirmation-target-deployment-receipt-v1",
    phase: "O.23R",
    sourceHead: proposal.sourceBinding.sourceCommitAtGeneration,
    evidenceRecordedFromHead: runGit(["rev-parse", "HEAD"]),
    sourceBinding: proposal.sourceBinding,
    compiler: proposal.compiler,
    targetArtifact: targetBinding,
    signerPublicAddress: EXPECTED_DEPLOYER,
    signerRecovered: parsed.from,
    nonce: String(transaction.nonce),
    predictedTarget: addresses.targetAddress,
    actualTarget: getAddress(receipt.contractAddress),
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
      expectedHash: targetBinding.deployedBytecodeHash,
      actualHash: keccak256(deployedCode),
      matched: true
    },
    constructorStateVerification: {
      constructorArguments: [],
      constructorHash: initialization.targetConstructorHash,
      securityModelId,
      matched: true
    },
    preSigning,
    stateBefore: {
      deploymentWallet: account1Before,
      futurePrefundingWallet: account2Before,
      target: targetBefore
    },
    stateAfter: {
      observedAtBlockNumber: postBlock ? String(postBlock.number) : null,
      observedAtBlockHash: postBlock?.hash ?? null,
      deploymentWallet: account1After,
      futurePrefundingWallet: account2After,
      target: targetAfter,
      factory: factoryAfter,
      smartAccount: smartAccountAfter
    },
    publicMutationOccurred: true,
    publicMutationScope: "new-deployer-confirmation-target-only",
    factoryDeployed: false,
    smartAccountFunded: false,
    fundingWalletUsed: false,
    deviceVaultSignatureGenerated: false,
    bundlerContacted: false,
    userOperationSubmitted: false,
    acp0002Status: "Proposed",
    betaApproved: false,
    productionApproved: false
  };
  writeJson(O23R_RECEIPT_PATH, receiptEvidence);
  process.stdout.write(`${JSON.stringify({
    status: "O23R_CONFIRMATION_TARGET_DEPLOYED",
    transactionHash,
    receiptStatus: receiptEvidence.receiptStatus,
    blockNumber: receiptEvidence.blockNumber,
    blockHash: receiptEvidence.blockHash,
    targetAddress: receiptEvidence.actualTarget,
    runtimeBytecodeMatched: true,
    constructorStateMatched: true,
    gasUsed: receiptEvidence.gasUsed,
    effectiveGasPriceWei: receiptEvidence.effectiveGasPriceWei,
    exactTransactionCostWei: receiptEvidence.exactTransactionCostWei,
    account1BalanceAfterWei: account1After.balanceWei,
    account2Unchanged: true,
    factoryDeployed: false,
    smartAccountFunded: false,
    bundlerContacted: false,
    userOperationSubmitted: false,
    publicMutationScope: receiptEvidence.publicMutationScope,
    receiptFile: O23R_RECEIPT_PATH.replace(`${ROOT}/`, "")
  }, null, 2)}\n`);
}

module.exports = { readState, verifyProposalBindings };

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
