require("tsx/cjs");

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const {
  ROOT,
  ensureNoSecrets,
  readJson,
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
  O26_1_COMPATIBILITY_PATH,
  O26_1_ESTIMATE_PATH,
  O26_1_PREFUND_PATH,
  O27_PROPOSAL_PATH,
  PROPOSAL_FRESHNESS_SECONDS,
  buildO27Proposal,
  createO27ReadOnlyClient,
  readO27State,
  sanitizeRpcError
} = require("./o27-account2-prefund-common.cjs");

const O261_GENERATOR = path.join(
  ROOT,
  "scripts/ethereum-sepolia/generate-o26-1-live-bundler-readiness.cjs"
);
const MUTATION_APPROVALS = Object.freeze([
  "PHILCORE_PUBLIC_NETWORK_APPROVED",
  "PHILCORE_ETHEREUM_SEPOLIA_APPROVED",
  "PHILCORE_ETHEREUM_SEPOLIA_DEPLOYMENT_APPROVED",
  "PHILCORE_USEROP_SUBMISSION_APPROVED"
]);

function refreshO261Evidence() {
  const result = spawnSync(process.execPath, [O261_GENERATOR], {
    cwd: ROOT,
    encoding: "utf8",
    env: process.env
  });
  if (result.status !== 0) {
    throw sanitizeRpcError(new Error(result.stderr || "O26_1_REFRESH_FAILED"));
  }
}

async function main() {
  if (MUTATION_APPROVALS.some((name) => process.env[name] === "1")) {
    throw new Error("O27_MUTATION_APPROVAL_ENVIRONMENT_PRESENT");
  }
  const environment = loadSepoliaLocalEnvironment({
    root: ROOT,
    includeO23rSensitiveSelectors: true
  });
  const keyBindings = verifyConfiguredKeyPairs(process.env);
  refreshO261Evidence();

  const compatibility = readJson(O26_1_COMPATIBILITY_PATH);
  const estimate = readJson(O26_1_ESTIMATE_PATH);
  const prefund = readJson(O26_1_PREFUND_PATH);
  const sourceHead = runGit(["rev-parse", "HEAD"]);
  const branch = runGit(["branch", "--show-current"]);
  if (
    compatibility.sourceHead !== sourceHead
    || estimate.sourceHead !== sourceHead
    || prefund.sourceHead !== sourceHead
    || compatibility.status !== "BUNDLER_ESTIMATION_SUCCEEDED"
    || prefund.status !== "FUNDING_READY_FOR_SEPARATE_APPROVAL"
    || compatibility.clientIsolation?.submissionMethodExposed !== false
    || compatibility.clientIsolation?.genericRequestExposed !== false
    || compatibility.canonicalEntryPointV07Supported !== true
    || compatibility.paymasterRequired !== false
  ) {
    throw new Error("O27_O26_1_EVIDENCE_NOT_CURRENT_OR_COMPATIBLE");
  }

  const derivation = calculateO24Addresses(
    environment.identity,
    process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
  );
  const client = createO27ReadOnlyClient({
    url: process.env.PHILCORE_SEPOLIA_RPC_URL
  });
  const state = await readO27State(client, environment.identity, derivation);
  if (
    state.account.balanceWei !== "0"
    || state.accounts.account2.latestNonce !== "0"
    || state.accounts.account2.pendingNonce !== "0"
  ) {
    throw new Error("O27_RECIPIENT_PRETRANSFER_BALANCE_CHANGED");
  }
  const observedAt = new Date(state.block.timestamp * 1000).toISOString();
  const expiresAt = new Date(
    (state.block.timestamp + PROPOSAL_FRESHNESS_SECONDS) * 1000
  ).toISOString();
  const proposal = buildO27Proposal({
    generatedAt: observedAt,
    expiresAt,
    sourceHead,
    branch,
    senderNonce: state.accounts.account2.pendingNonce,
    recipientBalanceWei: state.account.balanceWei,
    recipientCodeStatus: state.account.codeStatus,
    account2BalanceWei: state.accounts.account2.balanceWei,
    valueWei: prefund.prefund.recommendedDisposableTestPrefund.wei,
    maxFeePerGasWei:
      prefund.feeEvidence.scenarios.recommended.maxFeePerGas.wei,
    maxPriorityFeePerGasWei:
      prefund.feeEvidence.scenarios.recommended.maxPriorityFeePerGas.wei,
    expectedOperationCostWei: prefund.prefund.expectedActualCost.wei,
    expectedResidualWei: prefund.prefund.expectedResidualAfterSuccess.wei,
    estimatedMinimumPrefundWei: prefund.prefund.estimatedMinimum.wei,
    remoteDeclaredGas: prefund.selectedGas,
    o261CompatibilityBinding: compatibility.provider.endpointBindingSha256,
    o261GasEstimateBinding: estimate.response.digest,
    state
  });
  if (
    keyBindings.funding.addressMatch !== true
    || keyBindings.deployer.addressMatch !== true
  ) {
    throw new Error("O27_WALLET_KEY_BINDING_MISMATCH");
  }
  ensureNoSecrets(proposal);
  writeJson(O27_PROPOSAL_PATH, proposal);
  process.stdout.write(`${JSON.stringify({
    phase: proposal.phase,
    canonicalPhaseName: proposal.canonicalPhaseName,
    status: proposal.status,
    chainId: proposal.chainId,
    sender: proposal.sender,
    verifiedDerivedSender: proposal.verifiedDerivedSender,
    senderNonce: proposal.senderNonce,
    recipient: proposal.recipient,
    recipientBalanceBefore: proposal.recipientBalanceBefore,
    recipientCodeStatusBefore: proposal.recipientCodeStatusBefore,
    calldata: proposal.calldata,
    gasLimit: proposal.gasLimit,
    maxFeePerGas: proposal.maxFeePerGas,
    maxPriorityFeePerGas: proposal.maxPriorityFeePerGas,
    transferValue: proposal.transferValue,
    maximumTransactionFee: proposal.maximumTransactionFee,
    maximumTotalAccount2Debit: proposal.maximumTotalAccount2Debit,
    account2BalanceBefore: proposal.account2BalanceBefore,
    expectedRecipientBalanceAfter: proposal.expectedRecipientBalanceAfter,
    estimatedMinimumPrefundWei:
      proposal.prefundRationale.estimatedMinimumPrefundWei,
    expectedFutureOperationCost: proposal.expectedFutureOperationCost,
    expectedResidualAfterSuccessfulOperation:
      proposal.expectedResidualAfterSuccessfulOperation,
    residualRiskClassification: proposal.residualRiskClassification,
    strandedFundsWarning: proposal.strandedFundsWarning,
    snapshot: {
      blockNumber: proposal.snapshot.blockNumber,
      blockHash: proposal.snapshot.blockHash,
      infrastructureBinding: proposal.snapshot.infrastructureBinding
    },
    expiresAt: proposal.expiresAt,
    proposalDigest: proposal.proposalDigest,
    approved: false,
    signed: false,
    broadcast: false,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${sanitizeRpcError(error).message}\n`);
    process.exitCode = 1;
  });
}
