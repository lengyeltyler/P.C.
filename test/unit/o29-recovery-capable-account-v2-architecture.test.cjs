require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  ROOT,
  ensureNoSecrets,
  readJson
} = require("../../scripts/ethereum-sepolia/o23r-common.cjs");
const {
  validateTestFundLifecyclePlan
} = require("../../scripts/ethereum-sepolia/test-fund-release-policy.cjs");

const ARCHITECTURE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O29_RECOVERY_CAPABLE_ACCOUNT_V2_ARCHITECTURE.json"
);
const ACCOUNT_PATH =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const FACTORY_PATH =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";

function sha256File(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

function git(args) {
  const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function verifiedReleasePlan() {
  return {
    policyVersion: "philcore-test-fund-release-v1",
    assetKind: "smart_account_balance",
    maximumFundingWei: "1000000",
    maximumResidualWei: "250000",
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
      intendedResidualRecipient:
        "0x1111111111111111111111111111111111111111",
      publicReleaseRequiresSeparateExactApproval: true
    }
  };
}

function completeLifecyclePlan(overrides = {}) {
  return {
    schemaVersion: "philcore-test-fund-lifecycle-v1",
    maximumFundingWei: "1000000",
    maximumStrandedWei: "1000000",
    accountBinding: {
      implementationVerified: true,
      factoryVerified: true,
      derivationVerified: true,
      chainBound: true
    },
    releasePlan: verifiedReleasePlan(),
    simulation: {
      createSimulated: true,
      fundSimulated: true,
      executeSimulated: true,
      releaseSimulated: true,
      finalStateVerified: true,
      localSimulationPassed: true,
      forkSimulationPassed: true,
      forkSimulationUnavailabilityReason: null
    },
    authority: {
      freshProofRequired: true,
      freshApprovalRequired: true,
      freshUserPresenceRequired: true,
      freshDeviceVaultSignatureRequired: true,
      oneTimeAuthorityRequired: true,
      separateReleaseApprovalRequired: true
    },
    expectedFinalState: {
      nativeBalanceWei: "0",
      entryPointDepositWei: "0",
      tokenBalancesReconciled: true,
      dustJustification: null,
      dustExplicitlyApprovedBeforeFunding: false
    },
    ...overrides
  };
}

describe("O.29 recovery-capable account V2 architecture", function () {
  const architecture = readJson(ARCHITECTURE_PATH);

  it("records the exact local-only phase and baseline without authority", function () {
    assert.equal(architecture.phase, "O.29");
    assert.equal(
      architecture.canonicalPhaseName,
      "O.29 Recovery-Capable Account V2 Architecture Design"
    );
    assert.equal(
      architecture.classification,
      "ARCHITECTURE_DESIGN_COMPLETE_LOCAL_ONLY"
    );
    assert.equal(
      architecture.sourceHeadAtPhaseStart,
      "a7edd2eca1bd987dfcd993e58c485dce90e467d2"
    );
    assert.equal(
      git(["merge-base", "--is-ancestor", architecture.sourceHeadAtPhaseStart, "HEAD"]),
      ""
    );
    assert.equal(architecture.publicMutationCount, 0);
  });

  it("freezes V1 source and rejects retrofitting the prefunded address", function () {
    assert.equal(
      sha256File(ACCOUNT_PATH),
      architecture.v1Freeze.accountSourceSha256
    );
    assert.equal(
      sha256File(FACTORY_PATH),
      architecture.v1Freeze.factorySourceSha256
    );
    assert.equal(architecture.v1Freeze.deployedContractsModified, false);
    assert.equal(architecture.v1Freeze.prefundRecoveryAttempted, false);
    assert.equal(
      architecture.v1Freeze.existingCounterfactualAddressReusableForV2,
      false
    );
  });

  it("preserves canonical identity independently from chain execution", function () {
    const identity = architecture.canonicalIdentity;
    assert.equal(identity.identityId, "identity_abab9766da60_24afd015");
    assert.equal(
      identity.validatorAddress,
      "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa"
    );
    assert.equal(identity.validatorKeyId, "validator_key_3c5b2ebebc4f3f3b");
    assert.equal(identity.identityRemainsSeparateFromExecution, true);
  });

  it("selects a non-upgradeable typed account rather than a generic wallet", function () {
    const model = architecture.selectedAccountModel;
    assert.equal(model.versionedNonUpgradeableImplementation, true);
    assert.equal(model.entryPointOnlyExecution, true);
    assert.equal(model.directEoaExecution, false);
    assert.equal(model.genericArbitraryCall, false);
    assert.equal(model.delegatecall, false);
    assert.equal(model.selfdestruct, false);
    assert.equal(model.upgradeKey, false);
    assert.equal(model.hiddenAdministrator, false);
    assert.equal(model.typedIntentSelectors, true);
  });

  it("binds every action to exact Runtime, account, asset, fee, and replay fields", function () {
    const bindings = new Set(architecture.intentAuthorization.requiredBindings);
    for (const required of [
      "action type",
      "purpose",
      "chain id",
      "EntryPoint",
      "account",
      "complete PackedUserOperation hash",
      "EntryPoint nonce key and sequence",
      "validator configuration epoch",
      "recipient or target",
      "native value",
      "token contract",
      "token identifier",
      "token amount",
      "calldata hash",
      "maximum total fee",
      "expiry"
    ]) {
      assert.equal(bindings.has(required), true, required);
    }
    assert.equal(architecture.intentAuthorization.freshApprovalRequired, true);
    assert.equal(
      architecture.intentAuthorization.freshUserPresenceRequired,
      true
    );
    assert.equal(
      architecture.intentAuthorization.freshDeviceVaultSignatureRequired,
      true
    );
    assert.equal(architecture.intentAuthorization.reusableAuthorityAllowed, false);
  });

  it("selects required transfers while keeping risky capabilities disabled", function () {
    const capabilities = architecture.capabilities;
    for (const capability of [
      "fixedConfirmation",
      "nativeTransfer",
      "erc20Transfer",
      "erc721Transfer",
      "erc1155Transfer",
      "entryPointDepositWithdrawal"
    ]) {
      assert.equal(capabilities[capability].status, "required", capability);
    }
    assert.equal(capabilities.contractCall.status, "adapter_gated");
    assert.equal(capabilities.batch.status, "deferred");
    assert.equal(capabilities.paymaster.status, "disabled_by_default");
  });

  it("keeps account, Runtime, validator, adapter, and application roles separate", function () {
    const split = architecture.responsibilitySplit;
    for (const role of [
      "account",
      "runtime",
      "validator",
      "chainAdapter",
      "application"
    ]) {
      assert.ok(Array.isArray(split[role]) && split[role].length > 0, role);
    }
    assert.match(split.application.join(" "), /intent only/);
    assert.match(split.validator.join(" "), /one exact purpose-bound digest/);
    assert.match(split.chainAdapter.join(" "), /method allowlists/);
  });

  it("uses delayed threshold authority recovery with no asset privilege", function () {
    const recovery = architecture.recovery;
    assert.equal(recovery.normalFundReleaseUsesOrdinaryIntentAuthorization, true);
    assert.equal(recovery.authorityRecoveryMovesAssets, false);
    assert.equal(recovery.authorityRecoveryRotatesValidatorOnly, true);
    assert.equal(recovery.singleRecoveryEoaAcceptedForProduction, false);
    assert.ok(recovery.recommendedThreshold.minimumApprovals >= 2);
    assert.ok(
      recovery.recommendedThreshold.minimumRegisteredFactors
        > recovery.recommendedThreshold.minimumApprovals
    );
    assert.equal(
      recovery.recommendedThreshold.factorsDerivedFromPhilSecret,
      false
    );
    assert.equal(
      recovery.recommendedThreshold.factorsDerivedFromExecutionValidator,
      false
    );
    assert.equal(recovery.delayedFlow.accountFreezesOrdinaryExecution, true);
    assert.equal(recovery.delayedFlow.challengeDelayRequired, true);
    assert.equal(recovery.delayedFlow.cancellationWindowRequired, true);
    assert.equal(recovery.delayedFlow.expiryRequired, true);
    assert.equal(recovery.delayedFlow.completionTransfersValue, false);
    assert.equal(
      recovery.delayedFlow.postRecoveryFundReleaseRequiresSeparateFreshIntent,
      true
    );
  });

  it("defines separated ERC-4337 nonce lanes and fail-closed optional features", function () {
    const erc4337 = architecture.erc4337;
    assert.equal(architecture.selectedAccountModel.entryPointVersion, "0.7");
    assert.equal(erc4337.packedUserOperation, true);
    assert.equal(erc4337.entryPointNonceReplayProtection, true);
    assert.equal(erc4337.nonceLanes.ordinary, "key 0");
    assert.notEqual(erc4337.nonceLanes.ordinary, erc4337.nonceLanes.recovery);
    assert.notEqual(erc4337.nonceLanes.maintenance, erc4337.nonceLanes.recovery);
    assert.equal(erc4337.recoveryFreezeBlocksOrdinaryLane, true);
    assert.equal(erc4337.paymasterDataRejectedWhenPolicyDisabled, true);
    assert.equal(erc4337.depositReleaseRequiresTypedAuthorization, true);
    assert.equal(erc4337.bundlerTrustedForAuthorization, false);
    assert.equal(erc4337.rpcTrustedForAuthorization, false);
  });

  it("selects identity and adapter migration without claiming V1 recovery", function () {
    const migration = architecture.migration;
    assert.equal(
      migration.selectedModel,
      "identity_and_chain_adapter_version_migration"
    );
    assert.equal(migration.proxyUpgradeSelected, false);
    assert.equal(migration.v1AccountMutated, false);
    assert.equal(migration.v1AssetsRecoverableByV2, false);
    assert.equal(migration.newFactoryRequired, true);
    assert.equal(migration.newCounterfactualAddressRequired, true);
    assert.equal(migration.ownerCommitmentContinuityRequired, true);
  });

  it("enforces a complete create-through-release lifecycle before funding", function () {
    const accepted = validateTestFundLifecyclePlan(completeLifecyclePlan());
    assert.equal(accepted.mode, "complete_test_fund_lifecycle");
    assert.equal(accepted.zeroFinalNativeAndDepositBalance, true);
    assert.equal(accepted.approvedForFundingProposal, true);

    assert.throws(
      () => validateTestFundLifecyclePlan(completeLifecyclePlan({
        simulation: {
          ...completeLifecyclePlan().simulation,
          releaseSimulated: false
        }
      })),
      /complete_test_fund_lifecycle_simulation_required/
    );
    assert.throws(
      () => validateTestFundLifecyclePlan(completeLifecyclePlan({
        simulation: {
          ...completeLifecyclePlan().simulation,
          forkSimulationPassed: false,
          forkSimulationUnavailabilityReason: null
        }
      })),
      /fork_test_fund_lifecycle_simulation_or_reason_required/
    );
    assert.throws(
      () => validateTestFundLifecyclePlan(completeLifecyclePlan({
        maximumStrandedWei: "1000001"
      })),
      /maximum_stranded_wei_cannot_exceed/
    );
    assert.throws(
      () => validateTestFundLifecyclePlan(completeLifecyclePlan({
        expectedFinalState: {
          ...completeLifecyclePlan().expectedFinalState,
          nativeBalanceWei: "1"
        }
      })),
      /nonzero_final_test_balance_requires_exact_dust_approval/
    );
  });

  it("documents all required threats, lifecycle rules, and capability decisions", function () {
    const architectureDoc = fs.readFileSync(path.join(
      ROOT,
      "docs/reference/O29_RECOVERY_CAPABLE_ACCOUNT_V2_ARCHITECTURE.md"
    ), "utf8");
    const matrix = fs.readFileSync(path.join(
      ROOT,
      "docs/reference/O29_V2_ACCOUNT_CAPABILITY_MATRIX.md"
    ), "utf8");
    const threatModel = fs.readFileSync(path.join(
      ROOT,
      "docs/security/O29_RECOVERY_CAPABLE_ACCOUNT_V2_THREAT_MODEL.md"
    ), "utf8");
    const releasePolicy = fs.readFileSync(path.join(
      ROOT,
      "docs/security/PHILCORE_TEST_FUND_RELEASE_POLICY.md"
    ), "utf8");
    for (const threat of [
      "Stolen device",
      "Compromised validator",
      "Malicious application",
      "Malicious bundler",
      "Malicious recovery attempt",
      "Replay",
      "Social engineering",
      "Chain replay"
    ]) {
      assert.match(threatModel, new RegExp(threat, "i"), threat);
    }
    assert.match(architectureDoc, /Responsibility Boundaries/);
    assert.match(architectureDoc, /Lost-Validator Recovery/);
    assert.match(architectureDoc, /Migration Model/);
    assert.match(matrix, /Native ETH transfer/);
    assert.match(matrix, /ERC-20 transfer/);
    assert.match(matrix, /ERC-721 transfer/);
    assert.match(matrix, /ERC-1155 transfer/);
    assert.match(matrix, /Batch operations/);
    assert.match(releasePolicy, /Mandatory Lifecycle Gate/);
    assert.match(releasePolicy, /maximum amount that could remain stranded/);
  });

  it("contains no secrets, executable authority, implementation, or public mutation", function () {
    ensureNoSecrets(architecture);
    for (const [key, value] of Object.entries(architecture.securityBoundary)) {
      assert.equal(value, false, key);
    }
    const serialized = JSON.stringify(architecture);
    assert.doesNotMatch(serialized, /https?:\/\//);
    assert.doesNotMatch(serialized, /rawSignedTransaction|privateKey|phil_secret/);
    assert.equal(architecture.securityBoundary.contractImplementationAdded, false);
    assert.equal(architecture.securityBoundary.publicMutationOccurred, false);
  });
});
