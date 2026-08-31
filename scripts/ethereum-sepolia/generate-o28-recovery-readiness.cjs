require("tsx/cjs");

const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { Interface, getAddress } = require("ethers");

const {
  ARTIFACTS,
  ROOT,
  artifactBindings,
  ensureNoSecrets,
  readJson,
  runGit,
  verifyConfiguredKeyPairs,
  writeJson
} = require("./o23r-common.cjs");
const {
  calculateO24Addresses,
  expectedFactoryRuntimeBinding
} = require("./o24-factory-common.cjs");
const {
  loadSepoliaLocalEnvironment
} = require("./local-environment.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  O27_RECEIPT_PATH,
  createO27ReadOnlyClient,
  readO27State,
  sanitizeRpcError
} = require("./o27-account2-prefund-common.cjs");
const {
  validateTestFundReleasePlan
} = require("./test-fund-release-policy.cjs");

const O28_EVIDENCE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O28_RECOVERY_AWARE_READINESS.json"
);
const O28_SIMULATION_SCRIPT = path.join(
  ROOT,
  "scripts/ethereum-sepolia/simulate-o28-recovery-readiness.cjs"
);
const ACCOUNT_SOURCE_PATH = path.join(
  ROOT,
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol"
);
const FACTORY_SOURCE_PATH = path.join(
  ROOT,
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol"
);
const O21_3_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O21_3_FIRST_SEPOLIA_EXECUTION_PROPOSAL.json"
);

function runLocalSimulation() {
  const output = execFileSync(
    "npx",
    ["hardhat", "run", O28_SIMULATION_SCRIPT],
    { cwd: ROOT, encoding: "utf8", maxBuffer: 10 * 1024 * 1024 }
  );
  const result = JSON.parse(output);
  if (
    result.classification
      !== "PREFUNDED_ADDRESS_INCOMPATIBLE_WITH_RECOVERY"
    || result.publicMutationOccurred !== false
    || result.lifecycle.accountDeploymentSimulated !== true
    || result.lifecycle.confirmationTargetCallSimulated !== true
    || result.lifecycle.exactResidualSweepSucceeded !== false
    || result.recoveryCapability.secureReleaseRouteAvailable !== false
    || result.allFailureChecksPassed !== true
    || result.create2Compatibility.addressChanged !== true
  ) {
    throw new Error("O28_LOCAL_SIMULATION_RESULT_INVALID");
  }
  return result;
}

function inspectCurrentRecoverySurface() {
  const accountArtifact = readJson(path.join(ROOT, ARTIFACTS.account));
  const accountInterface = new Interface(accountArtifact.abi);
  const accountSource = fs.readFileSync(ACCOUNT_SOURCE_PATH, "utf8");
  const factorySource = fs.readFileSync(FACTORY_SOURCE_PATH, "utf8");
  const nativeValuePaths = [
    {
      path: "receive()",
      direction: "inbound_only",
      authorization: "unrestricted_receive",
      canReleaseFunds: false
    },
    {
      path: "BaseAccount._payPrefund(missingAccountFunds)",
      direction: "account_to_entrypoint_only",
      authorization: "during_entrypoint_validation",
      canReleaseFundsToApprovedRecipient: false
    },
    {
      path: "executeLocalProofAuthorization(...)",
      direction: "zero_value_fixed_target_call",
      authorization: "entrypoint_and_canonical_validator",
      canReleaseFunds: false
    }
  ];
  const surface = {
    receiveAvailable: /\breceive\(\)\s+external\s+payable/.test(accountSource),
    genericExecuteAvailable:
      accountInterface.hasFunction("execute(address,uint256,bytes)"),
    nativeSweepAvailable:
      accountInterface.hasFunction("sweepNative(address,uint256)"),
    nativeWithdrawalAvailable:
      accountInterface.hasFunction("withdraw(address,uint256)"),
    entryPointDepositWithdrawalAvailable:
      accountInterface.hasFunction("withdrawDepositTo(address,uint256)"),
    tokenTransferRouteAvailable:
      accountInterface.hasFunction("executeTokenTransfer(address,address,uint256)"),
    upgradeAvailable: /\bupgradeTo\b|\bupgradeToAndCall\b/.test(accountSource),
    delegatecallAvailable: /\bdelegatecall\b/.test(accountSource),
    selfdestructAvailable: /\bselfdestruct\b/.test(accountSource),
    onlyExecutionSelector:
      accountInterface.getFunction("executeLocalProofAuthorization").selector,
    executionRequiresEntryPoint:
      /function executeLocalProofAuthorization[\s\S]*?_requireFromEntryPoint\(\)/.test(
        accountSource
      ),
    validationRequiresExactSelector:
      /executeLocalProofAuthorization\.selector/.test(accountSource),
    validationRequiresCanonicalOwner:
      /recovered != owner/.test(accountSource),
    chainBound: /block\.chainid/.test(accountSource),
    accountBound: /address\(this\)/.test(accountSource),
    replayProtectedByEntryPointNonce: true,
    liveFactoryEmbedsExactCreationCode:
      /type\(PhilCore4337LocalProofAccountV1\)\.creationCode/.test(factorySource),
    liveFactoryAllowsAlternateCreationCode: false,
    nativeValuePaths
  };
  if (
    !surface.receiveAvailable
    || surface.genericExecuteAvailable
    || surface.nativeSweepAvailable
    || surface.nativeWithdrawalAvailable
    || surface.entryPointDepositWithdrawalAvailable
    || surface.tokenTransferRouteAvailable
    || surface.upgradeAvailable
    || surface.delegatecallAvailable
    || surface.selfdestructAvailable
    || !surface.executionRequiresEntryPoint
    || !surface.validationRequiresExactSelector
    || !surface.validationRequiresCanonicalOwner
    || !surface.liveFactoryEmbedsExactCreationCode
  ) {
    throw new Error("O28_ACCOUNT_RECOVERY_SURFACE_UNEXPECTED");
  }
  return Object.freeze(surface);
}

async function main() {
  const environment = loadSepoliaLocalEnvironment({
    root: ROOT,
    includeO23rSensitiveSelectors: true
  });
  const keyBindings = verifyConfiguredKeyPairs(process.env);
  const derivation = calculateO24Addresses(
    environment.identity,
    process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
  );
  const client = createO27ReadOnlyClient({
    url: process.env.PHILCORE_SEPOLIA_RPC_URL
  });
  const state = await readO27State(client, environment.identity, derivation);
  const o27 = readJson(O27_RECEIPT_PATH);
  const [transaction, receipt] = await Promise.all([
    client.getTransaction(o27.transaction.hash),
    client.getTransactionReceipt(o27.transaction.hash)
  ]);
  if (
    state.account.address !== EXPECTED_ACCOUNT
    || state.account.codeStatus !== "empty"
    || state.account.balanceWei !== "5124486704000000"
    || state.account.entryPointNonce !== "0"
    || state.account.entryPointDepositWei !== "0"
    || state.accounts.account1.latestNonce !== "3"
    || state.accounts.account2.latestNonce !== "1"
    || transaction?.hash !== o27.transaction.hash
    || BigInt(transaction?.value ?? 0).toString() !== "5124486704000000"
    || transaction?.input !== "0x"
    || Number(BigInt(receipt?.status ?? "0x0")) !== 1
  ) {
    throw new Error("O28_POST_O27_LIVE_STATE_MISMATCH");
  }
  const currentArtifacts = artifactBindings();
  const expectedFactoryRuntime = expectedFactoryRuntimeBinding();
  if (
    expectedFactoryRuntime.bytecodeHash !== state.infrastructure.factory.codeHash
  ) {
    throw new Error("O28_LIVE_FACTORY_NOT_CURRENT_VERIFIED_SOURCE");
  }
  const recoverySurface = inspectCurrentRecoverySurface();
  const localSimulation = runLocalSimulation();
  const oldO21 = readJson(O21_3_PATH);
  const oldAuthority = {
    artifactPhase: oldO21.phase,
    eligibleForReuse: false,
    repositoryVerdict: oldO21.verdict,
    rejectionReasons: [
      "O.21.3 explicitly denies public submission authority",
      "the artifact predates live target, factory, account, fee, and prefund state",
      "its proof, approval, presence, Runtime authorization, and signature are one-time",
      "it contains no recovery-specific recipient or amount binding"
    ]
  };
  const currentO27Plan = {
    policyVersion: "philcore-test-fund-release-v1",
    assetKind: "smart_account_balance",
    maximumFundingWei: "5124486704000000",
    maximumResidualWei: "5124486704000000",
    fundingAmountIsMinimumPlusBoundedMargin: true,
    balancesBeforeAndAfterRecorded: true,
    routeTestedBeforeFundingWhenPossible: false,
    releaseRoute: { status: "absent" }
  };
  let currentO27PassesNewPolicy = true;
  let currentO27PolicyRejection = null;
  try {
    validateTestFundReleasePlan(currentO27Plan);
  } catch (error) {
    currentO27PassesNewPolicy = false;
    currentO27PolicyRejection = error.message;
  }
  if (currentO27PassesNewPolicy) {
    throw new Error("O28_NEW_POLICY_FAILED_TO_REJECT_UNRECOVERABLE_PREFUND");
  }
  const futureVerifiedRouteGuard = validateTestFundReleasePlan({
    policyVersion: "philcore-test-fund-release-v1",
    assetKind: "smart_account_balance",
    maximumFundingWei: "1000000",
    maximumResidualWei: "1000000",
    fundingAmountIsMinimumPlusBoundedMargin: true,
    balancesBeforeAndAfterRecorded: true,
    routeTestedBeforeFundingWhenPossible: true,
    releaseRoute: {
      status: "verified",
      canonicalAuthorizationRequired: true,
      freshApprovalRequired: true,
      freshUserPresenceRequired: true,
      freshDeviceVaultSignatureRequired: true,
      chainBound: true,
      accountBound: true,
      recipientBound: true,
      amountBound: true,
      nonceBound: true,
      purposeBound: true,
      replayProtected: true,
      eventEmitted: true,
      localSimulationPassed: true,
      intendedResidualRecipient: getAddress(
        "0x1111111111111111111111111111111111111111"
      ),
      publicReleaseRequiresSeparateExactApproval: true
    }
  });
  const sourceHead = runGit(["rev-parse", "HEAD"]);
  const evidence = {
    schemaVersion: "philcore-o28-recovery-aware-readiness-v1",
    phase: "O.28",
    canonicalPhaseName: "O.28 Recovery-Aware Live-Operation Readiness",
    classification: "PREFUNDED_ADDRESS_INCOMPATIBLE_WITH_RECOVERY",
    generatedAt: new Date().toISOString(),
    sourceHead,
    branch: runGit(["branch", "--show-current"]),
    canonicalIdentity: {
      identityId: environment.identity.identityId,
      label: environment.identity.label,
      ownerCommitment: environment.identity.ownerCommitment,
      validatorAddress: environment.identity.validatorAddress,
      validatorKeyId: environment.identity.validatorKeyId,
      validatorKeyIdBinding: derivation.validatorKeyIdBinding,
      coherent: true
    },
    keyBindings: {
      account1: keyBindings.deployer.addressMatch,
      account2: keyBindings.funding.addressMatch,
      canonicalValidatorPreserved: true
    },
    liveState: {
      snapshotBlock: state.block,
      infrastructure: state.infrastructure,
      counterfactualAccount: state.account,
      account1: state.accounts.account1,
      account2: state.accounts.account2,
      o27Transaction: {
        hash: transaction.hash,
        from: transaction.from,
        to: transaction.to,
        nonce: BigInt(transaction.nonce).toString(),
        valueWei: BigInt(transaction.value).toString(),
        calldata: transaction.input,
        receiptStatus: Number(BigInt(receipt.status)),
        receiptBlockNumber: BigInt(receipt.blockNumber).toString(),
        receiptBlockHash: receipt.blockHash
      }
    },
    sourceAndDeploymentBinding: {
      artifacts: currentArtifacts,
      currentFactoryImmutableRuntimeHash: expectedFactoryRuntime.bytecodeHash,
      liveFactoryRuntimeHash: state.infrastructure.factory.codeHash,
      matched: true,
      factoryEmbedsV1CreationCode: true,
      alternateAccountImplementationSelectable: false
    },
    currentRecoverySurface: recoverySurface,
    localSimulation,
    oldAuthority: oldAuthority,
    testFundReleasePolicy: {
      policyVersion: "philcore-test-fund-release-v1",
      active: true,
      coveredAssetKinds: [
        "native currency",
        "tokens",
        "EntryPoint deposits",
        "paymaster deposits",
        "escrow and contract balances"
      ],
      currentO27WouldPassNewPolicy: currentO27PassesNewPolicy,
      currentO27PolicyRejection,
      futureVerifiedRouteGuard,
      disposableStatusAloneAccepted: false
    },
    fundsAtRisk: {
      currentBalanceWei: state.account.balanceWei,
      securelyRecoverableThroughCurrentImplementation: false,
      maximumAmountThatCouldRemainStrandedWei: state.account.balanceWei,
      deployingOriginalV1CreatesReleaseRoute: false,
      originalV1MayConsumeSomeBalanceAsAuthorizedOperationGas: true,
      gasConsumptionIsFundRecovery: false,
      entryPointDepositWouldBeWithdrawableThroughV1: false
    },
    compatibilityDecision: {
      addingSecureReleaseChangesAccountCreationCode: true,
      create2InitCodeHashWouldChange: true,
      counterfactualAddressWouldChange: true,
      liveFactoryCanDeployChangedAccountCode: false,
      newFactoryRequired: true,
      newCounterfactualAccountRequired: true,
      currentPrefundMovesAutomaticallyToNewAddress: false,
      currentInfrastructureBindingWouldChange: true
    },
    correctiveOptions: [
      {
        id: "abandon-current-v1-prefund",
        safeForCurrentInfrastructure: true,
        recoversCurrentFunds: false,
        consequence:
          "Leave the undeployed V1 address untouched and treat the full balance as stranded."
      },
      {
        id: "deploy-current-v1-and-run-confirmation",
        safeForRecoveryObjective: false,
        recoversCurrentFunds: false,
        consequence:
          "Consumes some ETH as operation gas but leaves native balance and/or EntryPoint deposit without a release route."
      },
      {
        id: "design-v2-recovery-account-and-new-factory",
        recommendedForFutureTesting: true,
        recoversCurrentFunds: false,
        consequence:
          "Requires local design, audit, fork simulation, a new factory deployment, a new counterfactual address, and new funding approval."
      }
    ],
    recommendedNextAction:
      "Stop before deployment. Obtain a user decision on accepting the current full-balance loss versus designing a recovery-capable V2/new factory for future testing.",
    securityBoundary: {
      smartAccountDeployed: false,
      factoryCalled: false,
      proofGenerated: false,
      runtimeAuthorizationGenerated: false,
      userPresenceRequested: false,
      deviceVaultSigningUsed: false,
      userOperationConstructedForSubmission: false,
      userOperationSubmitted: false,
      entryPointDepositCreated: false,
      paymasterUsed: false,
      tokenMovementOccurred: false,
      nativeValueMoved: false,
      account1TransactionSent: false,
      account2TransactionSent: false,
      publicMutationOccurred: false
    }
  };
  ensureNoSecrets(evidence);
  writeJson(O28_EVIDENCE_PATH, evidence);
  process.stdout.write(`${JSON.stringify({
    phase: evidence.phase,
    canonicalPhaseName: evidence.canonicalPhaseName,
    classification: evidence.classification,
    snapshotBlock: evidence.liveState.snapshotBlock,
    currentBalanceWei: evidence.fundsAtRisk.currentBalanceWei,
    secureReleaseRouteAvailable:
      evidence.currentRecoverySurface.nativeSweepAvailable,
    deployingOriginalV1CreatesReleaseRoute:
      evidence.fundsAtRisk.deployingOriginalV1CreatesReleaseRoute,
    addingRecoveryChangesAddress:
      evidence.compatibilityDecision.counterfactualAddressWouldChange,
    newFactoryRequired: evidence.compatibilityDecision.newFactoryRequired,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${sanitizeRpcError(error).message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  O28_EVIDENCE_PATH,
  inspectCurrentRecoverySurface,
  runLocalSimulation
};
