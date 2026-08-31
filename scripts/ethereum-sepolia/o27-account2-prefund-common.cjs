require("tsx/cjs");

const path = require("node:path");
const {
  Interface,
  Transaction,
  formatEther,
  getAddress,
  keccak256
} = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  MAX_FEE_PER_GAS,
  MAX_PRIORITY_FEE_PER_GAS,
  ROOT,
  canonicalDigest,
  ensureNoSecrets,
  readJson
} = require("./o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET
} = require("./o24-factory-common.cjs");

const O27_PROPOSAL_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O27_ACCOUNT2_DIRECT_PREFUND_PROPOSAL.json"
);
const O27_RECEIPT_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O27_ACCOUNT2_DIRECT_PREFUND_RECEIPT.json"
);
const O23R_RECEIPT_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O23R_CONFIRMATION_TARGET_DEPLOYMENT_RECEIPT.json"
);
const O24_RECEIPT_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O24_FACTORY_DEPLOYMENT_RECEIPT.json"
);
const O26_1_COMPATIBILITY_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_1_LIVE_BUNDLER_COMPATIBILITY_REPORT.json"
);
const O26_1_ESTIMATE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_1_REMOTE_USEROP_GAS_ESTIMATE.json"
);
const O26_1_PREFUND_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_1_REFRESHED_PREFUND_PROPOSAL.json"
);
const DIRECT_TRANSFER_GAS_LIMIT = 21_000n;
const PROPOSAL_FRESHNESS_SECONDS = 15 * 60;
const EXPECTED_TARGET_RUNTIME_HASH =
  "0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad";
const EXPECTED_FACTORY_RUNTIME_HASH =
  "0x8a356af155426d2de17da0762d29c4c0a7956e3bc4e4b6811d1b819da789722f";
const EXPECTED_ENTRYPOINT_RUNTIME_HASH =
  "0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58";
const EXPECTED_SECURITY_MODEL_ID =
  "0x23dfc212b869b8ab99a124b1577adcd22a72f948ffc53efe44b5b37ae5647c4c";

const factoryInterface = new Interface([
  "function entryPoint() view returns (address)",
  "function approvedConfirmationTarget() view returns (address)",
  "function expectedChainId() view returns (uint256)",
  "function getAddress(address,bytes32,bytes32,uint256) view returns (address)"
]);
const entryPointInterface = new Interface([
  "function getNonce(address,uint192) view returns (uint256)",
  "function balanceOf(address) view returns (uint256)"
]);
const targetInterface = new Interface([
  "function SECURITY_MODEL_ID() view returns (bytes32)"
]);

function amount(value) {
  const parsed = BigInt(value);
  return Object.freeze({
    wei: parsed.toString(),
    eth: formatEther(parsed)
  });
}

function sanitizeRpcError(error) {
  const raw = error instanceof Error ? error.message : String(error);
  return new Error(
    raw
      .replace(/https?:\/\/[^\s"']+/gi, "<redacted-endpoint>")
      .replace(/[A-Za-z0-9_-]{24,}/g, "<redacted>")
  );
}

function createJsonRpcTransport(url) {
  let requestId = 0;
  return Object.freeze({
    async request(method, params) {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: ++requestId,
          method,
          params
        })
      });
      const body = await response.json();
      if (!response.ok || body.error) {
        const error = new Error(body.error?.message ?? `rpc_http_${response.status}`);
        error.code = body.error?.code ?? response.status;
        throw error;
      }
      return body.result;
    }
  });
}

function createO27ReadOnlyClient(input) {
  const internal = input.transport ?? createJsonRpcTransport(input.url);
  return Object.freeze({
    auditClassification: "ethereum_sepolia_o27_read_only",
    mutationMethodsExposed: false,
    async getChainId() {
      return internal.request("eth_chainId", []);
    },
    async getLatestBlock() {
      return internal.request("eth_getBlockByNumber", ["latest", false]);
    },
    async getCode(address, block = "latest") {
      return internal.request("eth_getCode", [address, block]);
    },
    async getBalance(address, block = "latest") {
      return internal.request("eth_getBalance", [address, block]);
    },
    async getTransactionCount(address, block = "latest") {
      return internal.request("eth_getTransactionCount", [address, block]);
    },
    async call(to, data, block = "latest") {
      return internal.request("eth_call", [{ to, data }, block]);
    },
    async getTransactionReceipt(hash) {
      return internal.request("eth_getTransactionReceipt", [hash]);
    },
    async getTransaction(hash) {
      return internal.request("eth_getTransactionByHash", [hash]);
    }
  });
}

function createO27OneShotBroadcastClient(input) {
  const internal = input.transport ?? createJsonRpcTransport(input.url);
  let broadcastCount = 0;
  return Object.freeze({
    auditClassification: "ethereum_sepolia_o27_single_raw_transaction_broadcast",
    automaticRetryEnabled: false,
    get broadcastCount() {
      return broadcastCount;
    },
    async broadcastOnce(rawSignedTransaction) {
      if (broadcastCount !== 0) throw new Error("O27_BROADCAST_ALREADY_ATTEMPTED");
      broadcastCount += 1;
      return internal.request("eth_sendRawTransaction", [rawSignedTransaction]);
    }
  });
}

function decodeCallResult(iface, functionName, encoded) {
  return iface.decodeFunctionResult(functionName, encoded)[0];
}

async function readO27State(client, identity, derivation) {
  const chainId = Number(BigInt(await client.getChainId()));
  if (chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) throw new Error("WRONG_ETHEREUM_CHAIN");
  const latestBlock = await client.getLatestBlock();
  if (!latestBlock?.hash || !latestBlock?.number || !latestBlock?.timestamp) {
    throw new Error("O27_LATEST_BLOCK_UNAVAILABLE");
  }
  const [
    targetCode,
    factoryCode,
    entryPointCode,
    accountCode,
    accountBalance,
    accountLatestNonce,
    accountPendingNonce,
    account1LatestNonce,
    account1PendingNonce,
    account1Balance,
    account2LatestNonce,
    account2PendingNonce,
    account2Balance,
    factoryEntryPointRaw,
    factoryTargetRaw,
    factoryChainRaw,
    factoryAccountRaw,
    targetSecurityModelRaw,
    entryPointNonceRaw,
    entryPointDepositRaw,
    targetReceipt,
    factoryReceipt
  ] = await Promise.all([
    client.getCode(EXPECTED_TARGET),
    client.getCode(EXPECTED_FACTORY),
    client.getCode(ERC4337_V07_CANONICAL_ENTRYPOINT),
    client.getCode(EXPECTED_ACCOUNT),
    client.getBalance(EXPECTED_ACCOUNT),
    client.getTransactionCount(EXPECTED_ACCOUNT, "latest"),
    client.getTransactionCount(EXPECTED_ACCOUNT, "pending"),
    client.getTransactionCount(EXPECTED_DEPLOYER, "latest"),
    client.getTransactionCount(EXPECTED_DEPLOYER, "pending"),
    client.getBalance(EXPECTED_DEPLOYER),
    client.getTransactionCount(EXPECTED_FUNDING, "latest"),
    client.getTransactionCount(EXPECTED_FUNDING, "pending"),
    client.getBalance(EXPECTED_FUNDING),
    client.call(EXPECTED_FACTORY, factoryInterface.encodeFunctionData("entryPoint")),
    client.call(
      EXPECTED_FACTORY,
      factoryInterface.encodeFunctionData("approvedConfirmationTarget")
    ),
    client.call(EXPECTED_FACTORY, factoryInterface.encodeFunctionData("expectedChainId")),
    client.call(
      EXPECTED_FACTORY,
      factoryInterface.encodeFunctionData(
        "getAddress(address,bytes32,bytes32,uint256)",
        [
          identity.validatorAddress,
          identity.ownerCommitment,
          derivation.validatorKeyIdBinding,
          BigInt(derivation.accountSaltDecimal)
        ]
      )
    ),
    client.call(EXPECTED_TARGET, targetInterface.encodeFunctionData("SECURITY_MODEL_ID")),
    client.call(
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      entryPointInterface.encodeFunctionData("getNonce", [EXPECTED_ACCOUNT, 0])
    ),
    client.call(
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      entryPointInterface.encodeFunctionData("balanceOf", [EXPECTED_ACCOUNT])
    ),
    client.getTransactionReceipt(readJson(O23R_RECEIPT_PATH).transactionHash),
    client.getTransactionReceipt(readJson(O24_RECEIPT_PATH).transactionHash)
  ]);

  const infrastructure = {
    chainId,
    entryPoint: {
      address: ERC4337_V07_CANONICAL_ENTRYPOINT,
      codeHash: keccak256(entryPointCode)
    },
    target: {
      address: EXPECTED_TARGET,
      codeHash: keccak256(targetCode),
      securityModelId: decodeCallResult(
        targetInterface,
        "SECURITY_MODEL_ID",
        targetSecurityModelRaw
      ),
      deploymentTransactionHash: readJson(O23R_RECEIPT_PATH).transactionHash,
      deploymentBlockNumber: String(BigInt(targetReceipt?.blockNumber ?? "0x0")),
      deploymentBlockHash: targetReceipt?.blockHash ?? null,
      deployedContractAddress: targetReceipt?.contractAddress
        ? getAddress(targetReceipt.contractAddress)
        : null,
      deploymentStatus: Number(BigInt(targetReceipt?.status ?? "0x0"))
    },
    factory: {
      address: EXPECTED_FACTORY,
      codeHash: keccak256(factoryCode),
      entryPoint: getAddress(decodeCallResult(
        factoryInterface,
        "entryPoint",
        factoryEntryPointRaw
      )),
      target: getAddress(decodeCallResult(
        factoryInterface,
        "approvedConfirmationTarget",
        factoryTargetRaw
      )),
      expectedChainId: Number(decodeCallResult(
        factoryInterface,
        "expectedChainId",
        factoryChainRaw
      )),
      deploymentTransactionHash: readJson(O24_RECEIPT_PATH).transactionHash,
      deploymentBlockNumber: String(BigInt(factoryReceipt?.blockNumber ?? "0x0")),
      deploymentBlockHash: factoryReceipt?.blockHash ?? null,
      deployedContractAddress: factoryReceipt?.contractAddress
        ? getAddress(factoryReceipt.contractAddress)
        : null,
      deploymentStatus: Number(BigInt(factoryReceipt?.status ?? "0x0"))
    }
  };
  const targetReceiptEvidence = readJson(O23R_RECEIPT_PATH);
  const factoryReceiptEvidence = readJson(O24_RECEIPT_PATH);
  if (
    infrastructure.entryPoint.codeHash !== EXPECTED_ENTRYPOINT_RUNTIME_HASH
    || infrastructure.target.codeHash !== EXPECTED_TARGET_RUNTIME_HASH
    || infrastructure.target.securityModelId !== EXPECTED_SECURITY_MODEL_ID
    || infrastructure.target.deploymentStatus !== 1
    || infrastructure.target.deploymentBlockNumber !== targetReceiptEvidence.blockNumber
    || infrastructure.target.deploymentBlockHash !== targetReceiptEvidence.blockHash
    || infrastructure.target.deployedContractAddress !== EXPECTED_TARGET
    || infrastructure.factory.codeHash !== EXPECTED_FACTORY_RUNTIME_HASH
    || infrastructure.factory.entryPoint !== ERC4337_V07_CANONICAL_ENTRYPOINT
    || infrastructure.factory.target !== EXPECTED_TARGET
    || infrastructure.factory.expectedChainId !== ETHEREUM_SEPOLIA_CHAIN_ID
    || infrastructure.factory.deploymentStatus !== 1
    || infrastructure.factory.deploymentBlockNumber !== factoryReceiptEvidence.blockNumber
    || infrastructure.factory.deploymentBlockHash !== factoryReceiptEvidence.blockHash
    || infrastructure.factory.deployedContractAddress !== EXPECTED_FACTORY
  ) {
    throw new Error("O27_INFRASTRUCTURE_BINDING_MISMATCH");
  }

  const factoryAccount = getAddress(decodeCallResult(
    factoryInterface,
    "getAddress(address,bytes32,bytes32,uint256)",
    factoryAccountRaw
  ));
  const entryPointNonce = BigInt(decodeCallResult(
    entryPointInterface,
    "getNonce",
    entryPointNonceRaw
  ));
  const entryPointDeposit = BigInt(decodeCallResult(
    entryPointInterface,
    "balanceOf",
    entryPointDepositRaw
  ));
  const account = {
    address: EXPECTED_ACCOUNT,
    locallyDerivedAddress: derivation.account,
    factoryDerivedAddress: factoryAccount,
    codeStatus: accountCode === "0x" ? "empty" : "present",
    codeHash: accountCode === "0x" ? null : keccak256(accountCode),
    balanceWei: BigInt(accountBalance).toString(),
    latestTransactionCount: BigInt(accountLatestNonce).toString(),
    pendingTransactionCount: BigInt(accountPendingNonce).toString(),
    entryPointNonce: entryPointNonce.toString(),
    entryPointDepositWei: entryPointDeposit.toString()
  };
  if (
    account.locallyDerivedAddress !== EXPECTED_ACCOUNT
    || account.factoryDerivedAddress !== EXPECTED_ACCOUNT
    || account.codeStatus !== "empty"
    || account.latestTransactionCount !== "0"
    || account.pendingTransactionCount !== "0"
    || account.entryPointNonce !== "0"
    || account.entryPointDepositWei !== "0"
  ) {
    throw new Error("O27_COUNTERFACTUAL_ACCOUNT_STATE_CHANGED");
  }
  const accounts = {
    account1: {
      address: EXPECTED_DEPLOYER,
      latestNonce: BigInt(account1LatestNonce).toString(),
      pendingNonce: BigInt(account1PendingNonce).toString(),
      balanceWei: BigInt(account1Balance).toString()
    },
    account2: {
      address: EXPECTED_FUNDING,
      latestNonce: BigInt(account2LatestNonce).toString(),
      pendingNonce: BigInt(account2PendingNonce).toString(),
      balanceWei: BigInt(account2Balance).toString()
    }
  };
  if (
    accounts.account1.latestNonce !== "3"
    || accounts.account1.pendingNonce !== "3"
    || accounts.account2.latestNonce !== accounts.account2.pendingNonce
    || !["0", "1"].includes(accounts.account2.latestNonce)
  ) {
    throw new Error("O27_DISPOSABLE_WALLET_HISTORY_CHANGED");
  }
  infrastructure.bindingDigest = canonicalDigest(infrastructure);
  return Object.freeze({
    block: Object.freeze({
      number: BigInt(latestBlock.number).toString(),
      hash: latestBlock.hash,
      timestamp: Number(BigInt(latestBlock.timestamp))
    }),
    infrastructure: Object.freeze(infrastructure),
    account: Object.freeze(account),
    accounts: Object.freeze(accounts)
  });
}

function buildO27Proposal(input) {
  const value = BigInt(input.valueWei);
  const gasLimit = DIRECT_TRANSFER_GAS_LIMIT;
  const maxFeePerGas = BigInt(input.maxFeePerGasWei);
  const maxPriorityFeePerGas = BigInt(input.maxPriorityFeePerGasWei);
  const maximumTransactionFee = gasLimit * maxFeePerGas;
  const maximumTotalDebit = value + maximumTransactionFee;
  const proposal = {
    schemaVersion: "philcore-o27-account2-direct-prefund-proposal-v1",
    phase: "O.27",
    canonicalPhaseName: "O.27 Account 2 Direct Prefunding",
    status: "AWAITING_EXPLICIT_APPROVAL",
    generatedAt: input.generatedAt,
    expiresAt: input.expiresAt,
    sourceHead: input.sourceHead,
    branch: input.branch,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    transactionType: 2,
    sender: EXPECTED_FUNDING,
    verifiedDerivedSender: EXPECTED_FUNDING,
    senderNonce: String(input.senderNonce),
    recipient: EXPECTED_ACCOUNT,
    recipientBalanceBefore: amount(input.recipientBalanceWei),
    recipientCodeStatusBefore: input.recipientCodeStatus,
    calldata: "0x",
    gasLimit: gasLimit.toString(),
    maxFeePerGas: amount(maxFeePerGas),
    maxPriorityFeePerGas: amount(maxPriorityFeePerGas),
    transferValue: amount(value),
    maximumTransactionFee: amount(maximumTransactionFee),
    maximumTotalAccount2Debit: amount(maximumTotalDebit),
    account2BalanceBefore: amount(input.account2BalanceWei),
    expectedRecipientBalanceAfter: amount(
      BigInt(input.recipientBalanceWei) + value
    ),
    expectedFutureOperationCost: amount(input.expectedOperationCostWei),
    expectedResidualAfterSuccessfulOperation: amount(input.expectedResidualWei),
    residualRiskClassification:
      "RESIDUAL_FUNDS_NONRECOVERABLE_BY_CURRENT_ACCOUNT",
    strandedFundsWarning:
      "ETH sent to this counterfactual address can become permanently stranded if the account is never successfully deployed or cannot execute an approved recovery path.",
    prefundRationale: {
      o261CompatibilityBinding: input.o261CompatibilityBinding,
      o261GasEstimateBinding: input.o261GasEstimateBinding,
      remoteDeclaredGas: input.remoteDeclaredGas,
      estimatedMinimumPrefundWei: String(input.estimatedMinimumPrefundWei),
      recommendedDisposablePrefundWei: value.toString(),
      selectedRecommendationMargin: "canonical_o26_1_current_fee_plus_25_percent",
      paymasterRequired: false
    },
    snapshot: {
      blockNumber: input.state.block.number,
      blockHash: input.state.block.hash,
      infrastructureBinding: input.state.infrastructure.bindingDigest,
      account: input.state.account,
      account1: input.state.accounts.account1,
      account2: input.state.accounts.account2
    },
    approval: {
      approved: false,
      approvalReceived: false,
      reusableApprovalArtifact: false,
      exactYesOrNoRequired: true,
      approvalInvalidatedByStateChange: true
    },
    authority: {
      account1UseAuthorized: false,
      account2DirectEthTransferAuthorized: false,
      factoryCallAuthorized: false,
      accountDeploymentAuthorized: false,
      entryPointDepositAuthorized: false,
      protectedRuntimeAuthorized: false,
      proofGenerationAuthorized: false,
      deviceVaultSigningAuthorized: false,
      userOperationSubmissionAuthorized: false,
      bundlerSubmissionAuthorized: false,
      paymasterAuthorized: false,
      tokenMovementAuthorized: false,
      secondTransactionAuthorized: false
    },
    signed: false,
    broadcast: false,
    publicMutationOccurred: false
  };
  if (BigInt(input.account2BalanceWei) < maximumTotalDebit) {
    throw new Error("O27_ACCOUNT2_BALANCE_INSUFFICIENT");
  }
  validateO27Transaction(buildO27Transaction(proposal), proposal);
  proposal.proposalDigest = canonicalDigest(proposal);
  ensureNoSecrets(proposal);
  return Object.freeze(proposal);
}

function validateO27Proposal(proposal, options = {}) {
  if (
    proposal.phase !== "O.27"
    || proposal.canonicalPhaseName !== "O.27 Account 2 Direct Prefunding"
    || proposal.status !== "AWAITING_EXPLICIT_APPROVAL"
    || proposal.approval?.approved !== false
    || proposal.approval?.reusableApprovalArtifact !== false
    || proposal.signed !== false
    || proposal.broadcast !== false
  ) {
    throw new Error("O27_PROPOSAL_STATUS_INVALID");
  }
  const digestInput = { ...proposal };
  delete digestInput.proposalDigest;
  if (canonicalDigest(digestInput) !== proposal.proposalDigest) {
    throw new Error("O27_PROPOSAL_DIGEST_MISMATCH");
  }
  if (options.now !== undefined && Date.parse(proposal.expiresAt) <= options.now) {
    throw new Error("O27_PROPOSAL_EXPIRED");
  }
  validateO27Transaction(buildO27Transaction(proposal), proposal);
  return true;
}

function buildO27Transaction(proposal) {
  return Object.freeze({
    type: 2,
    chainId: Number(proposal.chainId),
    nonce: Number(proposal.senderNonce),
    to: proposal.recipient,
    value: BigInt(proposal.transferValue.wei),
    data: proposal.calldata,
    gasLimit: BigInt(proposal.gasLimit),
    maxFeePerGas: BigInt(proposal.maxFeePerGas.wei),
    maxPriorityFeePerGas: BigInt(proposal.maxPriorityFeePerGas.wei)
  });
}

function validateO27Transaction(transaction, proposal) {
  if (Number(transaction.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("O27_WRONG_CHAIN");
  }
  if (String(transaction.nonce) !== String(proposal.senderNonce)) {
    throw new Error("O27_NONCE_MISMATCH");
  }
  if (getAddress(transaction.to) !== EXPECTED_ACCOUNT) {
    throw new Error("O27_RECIPIENT_MISMATCH");
  }
  if (transaction.data !== "0x") throw new Error("O27_CALLDATA_MUST_BE_EMPTY");
  if (BigInt(transaction.gasLimit) !== DIRECT_TRANSFER_GAS_LIMIT) {
    throw new Error("O27_GAS_LIMIT_MISMATCH");
  }
  if (BigInt(transaction.value) !== BigInt(proposal.transferValue.wei)) {
    throw new Error("O27_TRANSFER_VALUE_MISMATCH");
  }
  if (
    BigInt(transaction.maxFeePerGas) !== BigInt(proposal.maxFeePerGas.wei)
    || BigInt(transaction.maxPriorityFeePerGas)
      !== BigInt(proposal.maxPriorityFeePerGas.wei)
  ) {
    throw new Error("O27_FEE_ENVELOPE_MISMATCH");
  }
  if (
    BigInt(transaction.maxFeePerGas) > MAX_FEE_PER_GAS
    || BigInt(transaction.maxPriorityFeePerGas) > MAX_PRIORITY_FEE_PER_GAS
  ) {
    throw new Error("O27_FEE_CEILING_EXCEEDED");
  }
  return true;
}

function verifySignedO27Transaction(
  rawSignedTransaction,
  proposal,
  expectedSigner = EXPECTED_FUNDING
) {
  const parsed = Transaction.from(rawSignedTransaction);
  validateO27Transaction(parsed, proposal);
  if (getAddress(parsed.from) !== getAddress(expectedSigner)) {
    throw new Error("O27_SIGNER_RECOVERY_FAILED");
  }
  if (parsed.hash !== keccak256(rawSignedTransaction)) {
    throw new Error("O27_TRANSACTION_HASH_MISMATCH");
  }
  return parsed;
}

function assertO27ApprovalBoundState(proposal, state) {
  if (state.infrastructure.bindingDigest !== proposal.snapshot.infrastructureBinding) {
    throw new Error("O27_APPROVAL_INVALIDATED_INFRASTRUCTURE");
  }
  if (
    state.account.address !== proposal.recipient
    || state.account.codeStatus !== proposal.recipientCodeStatusBefore
    || state.account.balanceWei !== proposal.recipientBalanceBefore.wei
    || state.account.entryPointNonce !== "0"
    || state.account.entryPointDepositWei !== "0"
  ) {
    throw new Error("O27_APPROVAL_INVALIDATED_RECIPIENT_STATE");
  }
  if (
    state.accounts.account1.latestNonce !== proposal.snapshot.account1.latestNonce
    || state.accounts.account1.pendingNonce !== proposal.snapshot.account1.pendingNonce
    || state.accounts.account1.balanceWei !== proposal.snapshot.account1.balanceWei
  ) {
    throw new Error("O27_ACCOUNT1_STATE_CHANGED");
  }
  if (
    state.accounts.account2.latestNonce !== proposal.senderNonce
    || state.accounts.account2.pendingNonce !== proposal.senderNonce
  ) {
    throw new Error("O27_APPROVAL_INVALIDATED_ACCOUNT2_NONCE");
  }
  if (
    BigInt(state.accounts.account2.balanceWei)
      < BigInt(proposal.maximumTotalAccount2Debit.wei)
  ) {
    throw new Error("O27_APPROVAL_INVALIDATED_ACCOUNT2_BALANCE");
  }
  return true;
}

module.exports = {
  DIRECT_TRANSFER_GAS_LIMIT,
  EXPECTED_ACCOUNT,
  EXPECTED_DEPLOYER,
  EXPECTED_ENTRYPOINT_RUNTIME_HASH,
  EXPECTED_FACTORY,
  EXPECTED_FACTORY_RUNTIME_HASH,
  EXPECTED_FUNDING,
  EXPECTED_SECURITY_MODEL_ID,
  EXPECTED_TARGET,
  EXPECTED_TARGET_RUNTIME_HASH,
  O23R_RECEIPT_PATH,
  O24_RECEIPT_PATH,
  O26_1_COMPATIBILITY_PATH,
  O26_1_ESTIMATE_PATH,
  O26_1_PREFUND_PATH,
  O27_PROPOSAL_PATH,
  O27_RECEIPT_PATH,
  PROPOSAL_FRESHNESS_SECONDS,
  amount,
  assertO27ApprovalBoundState,
  buildO27Proposal,
  buildO27Transaction,
  createO27OneShotBroadcastClient,
  createO27ReadOnlyClient,
  readO27State,
  sanitizeRpcError,
  validateO27Proposal,
  validateO27Transaction,
  verifySignedO27Transaction
};
