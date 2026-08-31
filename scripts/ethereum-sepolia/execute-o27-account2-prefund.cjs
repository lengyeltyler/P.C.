require("tsx/cjs");

const fs = require("node:fs");
const {
  Transaction,
  Wallet,
  getAddress,
  keccak256
} = require("ethers");

const {
  ROOT,
  ensureNoSecrets,
  normalizePrivateKey,
  readJson,
  requireCleanRepository,
  runGit,
  verifyConfiguredKeyPairs,
  writeJson
} = require("./o23r-common.cjs");
const {
  calculateO24Addresses
} = require("./o24-factory-common.cjs");
const {
  loadSepoliaLocalEnvironment
} = require("./local-environment.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_DEPLOYER,
  EXPECTED_FACTORY,
  EXPECTED_FUNDING,
  EXPECTED_TARGET,
  O27_PROPOSAL_PATH,
  O27_RECEIPT_PATH,
  amount,
  assertO27ApprovalBoundState,
  buildO27Transaction,
  createO27OneShotBroadcastClient,
  createO27ReadOnlyClient,
  readO27State,
  sanitizeRpcError,
  validateO27Proposal,
  verifySignedO27Transaction
} = require("./o27-account2-prefund-common.cjs");

const RECEIPT_TIMEOUT_MS = 10 * 60 * 1000;
const POLL_INTERVAL_MS = 5_000;
const REQUIRED_CONFIRMATIONS = 2n;

function approvalDigestArgument(argv = process.argv.slice(2)) {
  const prefix = "--approved-proposal-digest=";
  const value = argv.find((argument) => argument.startsWith(prefix));
  return value ? value.slice(prefix.length) : null;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForReceipt(client, hash, initialBroadcastError = null) {
  const deadline = Date.now() + RECEIPT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const receipt = await client.getTransactionReceipt(hash);
    if (receipt) {
      const latestBlock = await client.getLatestBlock();
      const confirmations =
        BigInt(latestBlock.number) - BigInt(receipt.blockNumber) + 1n;
      if (confirmations >= REQUIRED_CONFIRMATIONS) return receipt;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  if (initialBroadcastError) {
    throw new Error("O27_AMBIGUOUS_BROADCAST_INCLUSION_NOT_ESTABLISHED");
  }
  throw new Error("O27_RECEIPT_TIMEOUT");
}

function validateMinedTransaction(transaction, proposal, transactionHash) {
  if (!transaction) throw new Error("O27_MINED_TRANSACTION_MISSING");
  const normalized = {
    type: Number(BigInt(transaction.type)),
    chainId: Number(BigInt(transaction.chainId)),
    nonce: Number(BigInt(transaction.nonce)),
    to: transaction.to,
    value: BigInt(transaction.value),
    data: transaction.input,
    gasLimit: BigInt(transaction.gas),
    maxFeePerGas: BigInt(transaction.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(transaction.maxPriorityFeePerGas)
  };
  const expected = buildO27Transaction(proposal);
  for (const field of [
    "type",
    "chainId",
    "nonce",
    "to",
    "value",
    "data",
    "gasLimit",
    "maxFeePerGas",
    "maxPriorityFeePerGas"
  ]) {
    const actualValue = field === "to"
      ? getAddress(normalized[field])
      : normalized[field];
    const expectedValue = field === "to"
      ? getAddress(expected[field])
      : expected[field];
    if (actualValue !== expectedValue) {
      throw new Error(`O27_MINED_TRANSACTION_${field.toUpperCase()}_MISMATCH`);
    }
  }
  if (
    getAddress(transaction.from) !== EXPECTED_FUNDING
    || transaction.hash !== transactionHash
  ) {
    throw new Error("O27_MINED_TRANSACTION_SENDER_OR_HASH_MISMATCH");
  }
  return true;
}

async function main() {
  if (!process.argv.includes("--broadcast-account2-direct-prefund")) {
    throw new Error("O27_EXPLICIT_BROADCAST_FLAG_REQUIRED");
  }
  const approvedProposalDigest = approvalDigestArgument();
  if (!approvedProposalDigest) throw new Error("O27_EXACT_APPROVAL_DIGEST_REQUIRED");
  if (fs.existsSync(O27_RECEIPT_PATH)) throw new Error("O27_ALREADY_COMPLETED");
  requireCleanRepository();

  const environment = loadSepoliaLocalEnvironment({
    root: ROOT,
    includeO23rSensitiveSelectors: true
  });
  const keyBindings = verifyConfiguredKeyPairs(process.env);
  const proposal = readJson(O27_PROPOSAL_PATH);
  validateO27Proposal(proposal, { now: Date.now() });
  if (proposal.proposalDigest !== approvedProposalDigest) {
    throw new Error("O27_EXACT_APPROVAL_DIGEST_MISMATCH");
  }
  if (
    runGit(["merge-base", "--is-ancestor", proposal.sourceHead, "HEAD"]) !== ""
    || runGit(["branch", "--show-current"]) !== proposal.branch
  ) {
    throw new Error("O27_APPROVED_SOURCE_OR_BRANCH_CHANGED");
  }
  if (
    keyBindings.deployer.addressMatch !== true
    || keyBindings.funding.addressMatch !== true
  ) {
    throw new Error("O27_WALLET_KEY_BINDING_MISMATCH");
  }

  const derivation = calculateO24Addresses(
    environment.identity,
    process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
  );
  const readClient = createO27ReadOnlyClient({
    url: process.env.PHILCORE_SEPOLIA_RPC_URL
  });
  const beforeSigning = await readO27State(
    readClient,
    environment.identity,
    derivation
  );
  assertO27ApprovalBoundState(proposal, beforeSigning);
  if (beforeSigning.accounts.account2.pendingNonce !== "0") {
    throw new Error("O27_ACCOUNT2_ONE_TRANSACTION_HISTORY_VIOLATION");
  }

  const transactionRequest = buildO27Transaction(proposal);
  const wallet = new Wallet(normalizePrivateKey(
    process.env.PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY
  ));
  if (wallet.address !== EXPECTED_FUNDING) throw new Error("O27_ACCOUNT2_KEY_MISMATCH");
  const rawSignedTransaction = await wallet.signTransaction(transactionRequest);
  const transactionHash = keccak256(rawSignedTransaction);
  const parsed = verifySignedO27Transaction(rawSignedTransaction, proposal);
  const decoded = Transaction.from(rawSignedTransaction);
  if (decoded.hash !== transactionHash || parsed.from !== EXPECTED_FUNDING) {
    throw new Error("O27_SIGNED_TRANSACTION_VERIFICATION_FAILED");
  }

  const beforeBroadcast = await readO27State(
    readClient,
    environment.identity,
    derivation
  );
  assertO27ApprovalBoundState(proposal, beforeBroadcast);
  if (
    beforeBroadcast.accounts.account2.pendingNonce
      !== beforeSigning.accounts.account2.pendingNonce
    || beforeBroadcast.accounts.account2.balanceWei
      !== beforeSigning.accounts.account2.balanceWei
  ) {
    throw new Error("O27_ACCOUNT2_STATE_CHANGED_AFTER_SIGNING");
  }

  const broadcastClient = createO27OneShotBroadcastClient({
    url: process.env.PHILCORE_SEPOLIA_RPC_URL
  });
  let returnedHash = null;
  let broadcastError = null;
  try {
    returnedHash = await broadcastClient.broadcastOnce(rawSignedTransaction);
  } catch (error) {
    broadcastError = sanitizeRpcError(error);
  }
  if (broadcastClient.broadcastCount !== 1) {
    throw new Error("O27_BROADCAST_COUNT_INVALID");
  }
  if (returnedHash && returnedHash !== transactionHash) {
    throw new Error("O27_BROADCAST_HASH_MISMATCH");
  }
  if (broadcastError) {
    const [knownTransaction, knownReceipt] = await Promise.all([
      readClient.getTransaction(transactionHash),
      readClient.getTransactionReceipt(transactionHash)
    ]);
    if (!knownTransaction && !knownReceipt) {
      throw new Error("O27_AMBIGUOUS_BROADCAST_HASH_NOT_FOUND_NO_REBROADCAST");
    }
  }
  const receipt = await waitForReceipt(readClient, transactionHash, broadcastError);
  if (Number(BigInt(receipt.status)) !== 1) throw new Error("O27_TRANSFER_REVERTED");
  const transaction = await readClient.getTransaction(transactionHash);
  validateMinedTransaction(transaction, proposal, transactionHash);
  if (
    getAddress(receipt.from) !== EXPECTED_FUNDING
    || getAddress(receipt.to) !== EXPECTED_ACCOUNT
    || receipt.transactionHash !== transactionHash
  ) {
    throw new Error("O27_RECEIPT_ENVELOPE_MISMATCH");
  }
  if (!Array.isArray(receipt.logs) || receipt.logs.length !== 0) {
    throw new Error("O27_UNEXPECTED_RECEIPT_LOGS");
  }
  const gasUsed = BigInt(receipt.gasUsed);
  const effectiveGasPrice = BigInt(receipt.effectiveGasPrice);
  const exactTransactionFee = gasUsed * effectiveGasPrice;
  const exactTotalDebit = BigInt(proposal.transferValue.wei) + exactTransactionFee;

  const after = await readO27State(readClient, environment.identity, derivation);
  if (
    after.accounts.account1.latestNonce
      !== beforeSigning.accounts.account1.latestNonce
    || after.accounts.account1.pendingNonce
      !== beforeSigning.accounts.account1.pendingNonce
    || after.accounts.account1.balanceWei
      !== beforeSigning.accounts.account1.balanceWei
  ) {
    throw new Error("O27_ACCOUNT1_CHANGED");
  }
  if (
    after.accounts.account2.latestNonce !== "1"
    || after.accounts.account2.pendingNonce !== "1"
    || BigInt(after.accounts.account2.balanceWei)
      !== BigInt(beforeSigning.accounts.account2.balanceWei) - exactTotalDebit
  ) {
    throw new Error("O27_ACCOUNT2_POST_TRANSFER_ACCOUNTING_MISMATCH");
  }
  if (
    BigInt(after.account.balanceWei)
      !== BigInt(beforeSigning.account.balanceWei) + BigInt(proposal.transferValue.wei)
    || after.account.codeStatus !== "empty"
    || after.account.entryPointNonce !== "0"
    || after.account.entryPointDepositWei !== "0"
  ) {
    throw new Error("O27_COUNTERFACTUAL_ACCOUNT_POST_TRANSFER_STATE_MISMATCH");
  }
  if (
    after.infrastructure.bindingDigest !== beforeSigning.infrastructure.bindingDigest
    || after.infrastructure.target.codeHash !== beforeSigning.infrastructure.target.codeHash
    || after.infrastructure.factory.codeHash !== beforeSigning.infrastructure.factory.codeHash
  ) {
    throw new Error("O27_INFRASTRUCTURE_CHANGED");
  }

  const evidence = {
    schemaVersion: "philcore-o27-account2-direct-prefund-receipt-v1",
    phase: "O.27",
    canonicalPhaseName: proposal.canonicalPhaseName,
    status: "COMPLETE",
    proposalDigest: proposal.proposalDigest,
    sourceHead: proposal.sourceHead,
    evidenceRecordedFromHead: runGit(["rev-parse", "HEAD"]),
    chainId: proposal.chainId,
    transaction: {
      hash: transactionHash,
      type: 2,
      sender: EXPECTED_FUNDING,
      recoveredSigner: parsed.from,
      recipient: EXPECTED_ACCOUNT,
      nonce: proposal.senderNonce,
      value: proposal.transferValue,
      calldata: "0x",
      gasLimit: proposal.gasLimit,
      maxFeePerGas: proposal.maxFeePerGas,
      maxPriorityFeePerGas: proposal.maxPriorityFeePerGas,
      signedOnlyByAccount2: true,
      decodedAndMatchedApproval: true
    },
    receipt: {
      found: true,
      status: "success",
      logCount: 0,
      blockNumber: BigInt(receipt.blockNumber).toString(),
      blockHash: receipt.blockHash,
      gasUsed: gasUsed.toString(),
      effectiveGasPrice: amount(effectiveGasPrice),
      exactTransactionFee: amount(exactTransactionFee),
      exactTotalAccount2Debit: amount(exactTotalDebit)
    },
    stateBefore: beforeSigning,
    stateImmediatelyBeforeBroadcast: beforeBroadcast,
    stateAfter: after,
    controls: {
      exactApprovalDigestMatched: true,
      approvalBoundStateRecheckedBeforeSigning: true,
      approvalBoundStateRecheckedBeforeBroadcast: true,
      account1Signed: false,
      account2Signed: true,
      broadcastCount: broadcastClient.broadcastCount,
      automaticRetryPerformed: false,
      replacementPerformed: false,
      speedUpPerformed: false,
      cancellationPerformed: false,
      fallbackProviderBroadcastPerformed: false,
      secondTransactionPerformed: false,
      factoryCallPerformed: false,
      entryPointDepositPerformed: false,
      proofGenerated: false,
      runtimeAuthorizationPerformed: false,
      userPresenceEventPerformed: false,
      deviceVaultSigningPerformed: false,
      userOperationSubmitted: false,
      bundlerSubmissionPerformed: false,
      paymasterUsed: false,
      tokenMovementPerformed: false
    },
    infrastructure: {
      targetUnchanged: true,
      factoryUnchanged: true,
      accountRemainsUndeployed: true,
      accountRemainsCodeFree: true,
      entryPointNonceRemainsZero: true,
      entryPointDepositRemainsZero: true
    },
    publicMutationScope: "one-direct-native-eth-transfer-account2-to-counterfactual-account",
    exactPublicMutationCount: 1
  };
  ensureNoSecrets(evidence);
  writeJson(O27_RECEIPT_PATH, evidence);
  process.stdout.write(`${JSON.stringify({
    phase: evidence.phase,
    status: evidence.status,
    transactionHash,
    receipt: evidence.receipt,
    account1Unchanged: true,
    account2NonceAfter: after.accounts.account2.latestNonce,
    account2BalanceAfterWei: after.accounts.account2.balanceWei,
    counterfactualBalanceBeforeWei: beforeSigning.account.balanceWei,
    counterfactualBalanceAfterWei: after.account.balanceWei,
    counterfactualCodeStatus: after.account.codeStatus,
    entryPointNonce: after.account.entryPointNonce,
    entryPointDepositWei: after.account.entryPointDepositWei,
    exactPublicMutationCount: 1
  }, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${sanitizeRpcError(error).message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  approvalDigestArgument,
  validateMinedTransaction,
  waitForReceipt
};
