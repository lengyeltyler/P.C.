require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  ROOT,
  ensureNoSecrets,
  readJson
} = require("../../scripts/ethereum-sepolia/o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET
} = require("../../scripts/ethereum-sepolia/o24-factory-common.cjs");
const {
  O28_EVIDENCE_PATH,
  inspectCurrentRecoverySurface
} = require("../../scripts/ethereum-sepolia/generate-o28-recovery-readiness.cjs");
const {
  COVERED_ASSET_KINDS,
  validateTestFundReleasePlan
} = require("../../scripts/ethereum-sepolia/test-fund-release-policy.cjs");

function verifiedPlan(overrides = {}) {
  return {
    policyVersion: "philcore-test-fund-release-v1",
    assetKind: "smart_account_balance",
    maximumFundingWei: "1000000",
    maximumResidualWei: "500000",
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
    },
    ...overrides
  };
}

describe("O.28 recovery-aware live-operation readiness", function () {
  const evidence = readJson(O28_EVIDENCE_PATH);

  it("establishes one canonical policy across every test-fund holding class", function () {
    for (const kind of [
      "native_currency",
      "token",
      "entrypoint_deposit",
      "paymaster_deposit",
      "escrow",
      "contract_balance",
      "smart_account_balance"
    ]) {
      assert.ok(COVERED_ASSET_KINDS.includes(kind));
    }
    const policy = fs.readFileSync(path.join(
      ROOT,
      "docs/security/PHILCORE_TEST_FUND_RELEASE_POLICY.md"
    ), "utf8");
    assert.match(policy, /Every testing flow/);
    assert.match(policy, /Disposable status alone|Calling funds disposable/);
    assert.match(policy, /EntryPoint deposits/);
    assert.match(policy, /paymaster deposits/);
    assert.match(policy, /exact residual recipient/i);
    assert.match(policy, /separate exact approval/i);
    assert.match(policy, /balances before and after/i);
  });

  it("rejects funding without a pretested verified release route", function () {
    assert.throws(
      () => validateTestFundReleasePlan({
        ...verifiedPlan(),
        routeTestedBeforeFundingWhenPossible: false,
        releaseRoute: { status: "absent" }
      }),
      /release_route_pretest/
    );
    assert.throws(
      () => validateTestFundReleasePlan({
        ...verifiedPlan(),
        releaseRoute: {
          ...verifiedPlan().releaseRoute,
          recipientBound: false
        }
      }),
      /security_requirements_incomplete/
    );
  });

  it("requires a non-disposable residual recipient and separate exact release approval", function () {
    for (const recipient of [
      EXPECTED_DEPLOYER,
      EXPECTED_FUNDING,
      "0x0000000000000000000000000000000000000000"
    ]) {
      assert.throws(
        () => validateTestFundReleasePlan({
          ...verifiedPlan(),
          releaseRoute: {
            ...verifiedPlan().releaseRoute,
            intendedResidualRecipient: recipient
          }
        }),
        /cannot_be_disposable_wallet|cannot_be_zero_address/
      );
    }
    assert.throws(
      () => validateTestFundReleasePlan({
        ...verifiedPlan(),
        releaseRoute: {
          ...verifiedPlan().releaseRoute,
          publicReleaseRequiresSeparateExactApproval: false
        }
      }),
      /separate_exact_release_approval/
    );
    assert.throws(
      () => validateTestFundReleasePlan({
        ...verifiedPlan(),
        maximumResidualWei: "1000001"
      }),
      /maximum_residual_wei_cannot_exceed/
    );
  });

  it("accepts only a complete verified route or complete unavoidable-lock exception", function () {
    const route = validateTestFundReleasePlan(verifiedPlan());
    assert.equal(route.mode, "verified_release_route");
    const exception = validateTestFundReleasePlan({
      policyVersion: "philcore-test-fund-release-v1",
      assetKind: "other_test_asset",
      maximumFundingWei: "1000",
      maximumResidualWei: "1000",
      fundingAmountIsMinimumPlusBoundedMargin: true,
      balancesBeforeAndAfterRecorded: true,
      routeTestedBeforeFundingWhenPossible: true,
      releaseRoute: { status: "technically_impossible" },
      unavoidableLock: {
        unavoidablePropertyOfExactProductionDesign: true,
        amountExplicitlyExpendable: true,
        clearExactLossWarningShown: true,
        explicitExactLossApprovalReceived: true,
        noSaferRouteTechnicallyPossible: true,
        exactMaximumLossWei: "1000",
        technicalImpossibilityEvidence:
          "The exact immutable fixture deliberately models an unrecoverable production lock."
      }
    });
    assert.equal(exception.mode, "unavoidable_lock_exception");
    assert.throws(
      () => validateTestFundReleasePlan({
        ...verifiedPlan(),
        releaseRoute: { status: "absent" },
        unavoidableLock: {
          unavoidablePropertyOfExactProductionDesign: true,
          amountExplicitlyExpendable: true
        }
      }),
      /exact_maximum_loss_wei|unavoidable_test_fund_lock_exception_incomplete/
    );
  });

  it("proves the current V1 account has inbound value but no release surface", function () {
    const surface = inspectCurrentRecoverySurface();
    assert.equal(surface.receiveAvailable, true);
    assert.equal(surface.genericExecuteAvailable, false);
    assert.equal(surface.nativeSweepAvailable, false);
    assert.equal(surface.nativeWithdrawalAvailable, false);
    assert.equal(surface.entryPointDepositWithdrawalAvailable, false);
    assert.equal(surface.tokenTransferRouteAvailable, false);
    assert.equal(surface.upgradeAvailable, false);
    assert.equal(surface.delegatecallAvailable, false);
    assert.equal(surface.selfdestructAvailable, false);
    assert.equal(surface.executionRequiresEntryPoint, true);
    assert.equal(surface.validationRequiresExactSelector, true);
    assert.equal(surface.validationRequiresCanonicalOwner, true);
    assert.equal(surface.chainBound, true);
    assert.equal(surface.accountBound, true);
    assert.equal(surface.replayProtectedByEntryPointNonce, true);
    assert.equal(surface.liveFactoryEmbedsExactCreationCode, true);
    assert.equal(surface.liveFactoryAllowsAlternateCreationCode, false);
  });

  it("binds the decision to current live infrastructure and post-O.27 state", function () {
    assert.equal(evidence.phase, "O.28");
    assert.equal(
      evidence.classification,
      "PREFUNDED_ADDRESS_INCOMPATIBLE_WITH_RECOVERY"
    );
    assert.equal(evidence.liveState.infrastructure.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(
      evidence.liveState.infrastructure.entryPoint.address,
      ERC4337_V07_CANONICAL_ENTRYPOINT
    );
    assert.equal(evidence.liveState.infrastructure.target.address, EXPECTED_TARGET);
    assert.equal(evidence.liveState.infrastructure.factory.address, EXPECTED_FACTORY);
    assert.equal(
      evidence.liveState.counterfactualAccount.address,
      EXPECTED_ACCOUNT
    );
    assert.equal(evidence.liveState.counterfactualAccount.codeStatus, "empty");
    assert.equal(
      evidence.liveState.counterfactualAccount.balanceWei,
      "5124486704000000"
    );
    assert.equal(evidence.liveState.counterfactualAccount.entryPointNonce, "0");
    assert.equal(
      evidence.liveState.counterfactualAccount.entryPointDepositWei,
      "0"
    );
    assert.equal(evidence.liveState.account1.latestNonce, "3");
    assert.equal(evidence.liveState.account2.latestNonce, "1");
    assert.equal(evidence.sourceAndDeploymentBinding.matched, true);
  });

  it("simulates funding, deployment, confirmation, and the unavailable residual sweep", function () {
    const lifecycle = evidence.localSimulation.lifecycle;
    assert.equal(lifecycle.counterfactualFundingSimulated, true);
    assert.equal(lifecycle.fundedBalanceWei, "5124486704000000");
    assert.equal(lifecycle.accountDeploymentSimulated, true);
    assert.equal(lifecycle.confirmationTargetCallSimulated, true);
    assert.ok(BigInt(lifecycle.totalResidualAfterConfirmationWei) > 0n);
    assert.equal(lifecycle.exactResidualSweepSimulated, true);
    assert.equal(lifecycle.exactResidualSweepSucceeded, false);
    assert.equal(
      lifecycle.finalTotalResidualWei,
      lifecycle.totalResidualAfterConfirmationWei
    );
    assert.equal(lifecycle.residualUnchangedByRejectedSweepAttempts, true);
  });

  it("rejects every required unauthorized or mutated recovery attempt", function () {
    const failures = evidence.localSimulation.failureChecks;
    for (const name of [
      "unsupportedSweepSelector",
      "wrongRecipient",
      "wrongAmount",
      "modifiedCalldata",
      "wrongSigner",
      "wrongValidator",
      "wrongChain",
      "wrongAccount",
      "staleNonce",
      "replay",
      "oldAuthorityReuse",
      "directExternalConfirmationCall",
      "directExternalSweepCall",
      "account1PrivilegedWithdrawal",
      "account2PrivilegedWithdrawal"
    ]) {
      assert.equal(failures[name], true, name);
    }
    assert.equal(evidence.localSimulation.allFailureChecksPassed, true);
    assert.equal(evidence.oldAuthority.eligibleForReuse, false);
  });

  it("proves any recovery-capable creation-code change changes CREATE2 identity", function () {
    const compatibility = evidence.localSimulation.create2Compatibility;
    assert.equal(compatibility.formulaBindsCreationCodeHash, true);
    assert.equal(compatibility.initCodeHashChanged, true);
    assert.equal(compatibility.addressChanged, true);
    assert.notEqual(compatibility.originalAddress, compatibility.changedAddress);
    assert.equal(compatibility.liveFactoryCanSelectAlternateCreationCode, false);
    assert.equal(
      evidence.compatibilityDecision.counterfactualAddressWouldChange,
      true
    );
    assert.equal(evidence.compatibilityDecision.newFactoryRequired, true);
    assert.equal(evidence.compatibilityDecision.newCounterfactualAccountRequired, true);
    assert.equal(
      evidence.compatibilityDecision.currentPrefundMovesAutomaticallyToNewAddress,
      false
    );
  });

  it("records the full live balance as maximum stranded exposure", function () {
    assert.equal(evidence.fundsAtRisk.currentBalanceWei, "5124486704000000");
    assert.equal(
      evidence.fundsAtRisk.maximumAmountThatCouldRemainStrandedWei,
      "5124486704000000"
    );
    assert.equal(
      evidence.fundsAtRisk.securelyRecoverableThroughCurrentImplementation,
      false
    );
    assert.equal(
      evidence.fundsAtRisk.deployingOriginalV1CreatesReleaseRoute,
      false
    );
    assert.equal(
      evidence.fundsAtRisk.entryPointDepositWouldBeWithdrawableThroughV1,
      false
    );
  });

  it("reruns the complete local fixture without public contact", function () {
    const result = spawnSync(
      "npx",
      [
        "hardhat",
        "run",
        "scripts/ethereum-sepolia/simulate-o28-recovery-readiness.cjs"
      ],
      { cwd: ROOT, encoding: "utf8" }
    );
    assert.equal(result.status, 0, result.stderr);
    const simulation = JSON.parse(result.stdout);
    assert.equal(simulation.publicNetworkContacted, false);
    assert.equal(simulation.publicMutationOccurred, false);
    assert.equal(simulation.allFailureChecksPassed, true);
    assert.equal(
      simulation.classification,
      "PREFUNDED_ADDRESS_INCOMPATIBLE_WITH_RECOVERY"
    );
  });

  it("keeps O.28 sanitized, authority-free, and public-mutation-free", function () {
    assert.equal(evidence.securityBoundary.smartAccountDeployed, false);
    assert.equal(evidence.securityBoundary.factoryCalled, false);
    assert.equal(evidence.securityBoundary.proofGenerated, false);
    assert.equal(evidence.securityBoundary.runtimeAuthorizationGenerated, false);
    assert.equal(evidence.securityBoundary.userPresenceRequested, false);
    assert.equal(evidence.securityBoundary.deviceVaultSigningUsed, false);
    assert.equal(evidence.securityBoundary.userOperationSubmitted, false);
    assert.equal(evidence.securityBoundary.entryPointDepositCreated, false);
    assert.equal(evidence.securityBoundary.paymasterUsed, false);
    assert.equal(evidence.securityBoundary.tokenMovementOccurred, false);
    assert.equal(evidence.securityBoundary.nativeValueMoved, false);
    assert.equal(evidence.securityBoundary.account1TransactionSent, false);
    assert.equal(evidence.securityBoundary.account2TransactionSent, false);
    assert.equal(evidence.securityBoundary.publicMutationOccurred, false);
    assert.equal(evidence.testFundReleasePolicy.disposableStatusAloneAccepted, false);
    assert.equal(evidence.testFundReleasePolicy.currentO27WouldPassNewPolicy, false);
    ensureNoSecrets(evidence);
    assert.doesNotMatch(
      fs.readFileSync(O28_EVIDENCE_PATH, "utf8"),
      /rawSignedTransaction|rawTransaction|https:\/\/[^ <"]+\/v2\/[A-Za-z0-9_-]+/
    );
  });
});
