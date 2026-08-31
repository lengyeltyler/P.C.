require("tsx/cjs");

const {
  Contract,
  JsonRpcProvider,
  formatEther,
  getAddress,
  keccak256
} = require("ethers");

const {
  ARTIFACTS,
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  ROOT,
  compilerBinding,
  requireCleanRepository,
  runGit,
  sha256File
} = require("./o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET,
  FACTORY_DEPLOYMENT_NONCE,
  O24_PROPOSAL_PATH,
  O24_RECEIPT_PATH,
  assertFreshO24ReceiptPath,
  calculateO24Addresses,
  ensureNoSecrets,
  expectedFactoryRuntimeBinding,
  factoryConstructorBinding,
  readJson,
  validateReviewedFactoryArtifacts,
  writeJson
} = require("./o24-factory-common.cjs");
const {
  loadSepoliaLocalEnvironment
} = require("./local-environment.cjs");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");

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

function transactionHashArgument() {
  const index = process.argv.indexOf("--transaction-hash");
  const value = index >= 0 ? process.argv[index + 1] : undefined;
  if (!/^0x[0-9a-fA-F]{64}$/.test(value ?? "")) {
    throw new Error("o24_transaction_hash_required");
  }
  return value.toLowerCase();
}

async function main() {
  requireCleanRepository();
  assertFreshO24ReceiptPath();
  const transactionHash = transactionHashArgument();
  const environment = loadSepoliaLocalEnvironment({ root: ROOT });
  const proposal = readJson(O24_PROPOSAL_PATH);
  validateReviewedFactoryArtifacts();
  const compiler = compilerBinding();
  for (const key of ["version", "optimizerEnabled", "optimizerRuns", "viaIR", "evmVersion"]) {
    if (compiler[key] !== proposal.compiler[key]) {
      throw new Error("FACTORY_SOURCE_BINDING_STALE");
    }
  }
  for (const source of proposal.sourceBinding.sources) {
    if (sha256File(source.path) !== source.sha256) {
      throw new Error("FACTORY_SOURCE_BINDING_STALE");
    }
  }
  const addresses = calculateO24Addresses(
    environment.identity,
    process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
  );
  const expectedRuntime = expectedFactoryRuntimeBinding();
  const expectedRuntimeEvidence = {
    bytecodeHash: expectedRuntime.bytecodeHash,
    immutableReferences: expectedRuntime.immutableReferences
  };
  const constructor = factoryConstructorBinding();
  const provider = new JsonRpcProvider(
    process.env.PHILCORE_SEPOLIA_RPC_URL,
    ETHEREUM_SEPOLIA_CHAIN_ID,
    { staticNetwork: true }
  );
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("WRONG_ETHEREUM_CHAIN");
  }
  const [transaction, receipt] = await Promise.all([
    provider.getTransaction(transactionHash),
    provider.getTransactionReceipt(transactionHash)
  ]);
  if (!transaction || !receipt) throw new Error("o24_transaction_or_receipt_missing");
  if (
    receipt.status !== 1
    || getAddress(transaction.from) !== EXPECTED_DEPLOYER
    || transaction.to !== null
    || transaction.nonce !== Number(FACTORY_DEPLOYMENT_NONCE)
    || transaction.value !== 0n
    || keccak256(transaction.data) !== proposal.factory.deployment.dataHash
    || getAddress(receipt.contractAddress) !== EXPECTED_FACTORY
    || receipt.logs.length !== 0
  ) {
    throw new Error("o24_mined_transaction_binding_mismatch");
  }
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
  const before = proposal.preflight;
  if (
    after.account1.latestNonce !== "3"
    || after.account1.pendingNonce !== "3"
    || JSON.stringify(after.account2) !== JSON.stringify(before.account2)
    || after.target.codeHash !== before.target.codeHash
    || after.smartAccount.codeStatus !== "empty"
    || BigInt(after.smartAccount.balanceWei) !== 0n
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
    signerRecovered: getAddress(transaction.from),
    nonce: FACTORY_DEPLOYMENT_NONCE,
    predictedFactory: EXPECTED_FACTORY,
    actualFactory: getAddress(receipt.contractAddress),
    transactionHash,
    receiptStatus: "success",
    confirmationsRequired: 2,
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
    preSigning: {
      ...proposal.factoryOnlyApproval,
      approved: undefined,
      consumed: undefined
    },
    reconciliation: {
      mode: "read_only_after_post_deployment_verifier_name_collision",
      additionalTransactionSigned: false,
      additionalTransactionBroadcast: false
    },
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
  ensureNoSecrets(evidence);
  writeJson(O24_RECEIPT_PATH, evidence);
  process.stdout.write(`${JSON.stringify({
    status: "O24_FACTORY_RECONCILED_AND_VERIFIED",
    transactionHash,
    receiptStatus: "success",
    blockNumber: evidence.blockNumber,
    blockHash: evidence.blockHash,
    factory: evidence.actualFactory,
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
    additionalTransactionSigned: false,
    additionalTransactionBroadcast: false,
    publicMutationScope: evidence.publicMutationScope,
    receiptFile: O24_RECEIPT_PATH.replace(`${ROOT}/`, "")
  }, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
