const { getAddress } = require("ethers");

const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING
} = require("./o23r-common.cjs");

const COVERED_ASSET_KINDS = Object.freeze([
  "native_currency",
  "token",
  "entrypoint_deposit",
  "paymaster_deposit",
  "escrow",
  "contract_balance",
  "smart_account_balance",
  "other_test_asset"
]);

function requireNonnegativeInteger(value, label) {
  if (!/^(0|[1-9][0-9]*)$/.test(String(value ?? ""))) {
    throw new Error(`${label}_must_be_nonnegative_integer`);
  }
  return BigInt(value);
}

function assertNotDisposableWalletRecipient(recipient) {
  const normalized = getAddress(recipient);
  if (normalized === "0x0000000000000000000000000000000000000000") {
    throw new Error("test_fund_release_recipient_cannot_be_zero_address");
  }
  if (
    normalized === getAddress(EXPECTED_DEPLOYER)
    || normalized === getAddress(EXPECTED_FUNDING)
  ) {
    throw new Error("test_fund_release_recipient_cannot_be_disposable_wallet");
  }
  return normalized;
}

function validateVerifiedReleaseRoute(plan) {
  const route = plan.releaseRoute;
  if (!route || route.status !== "verified") {
    throw new Error("verified_test_fund_release_route_required");
  }
  if (
    route.canonicalAuthorizationRequired !== true
    || route.freshApprovalRequired !== true
    || route.freshUserPresenceRequired !== true
    || route.freshDeviceVaultSignatureRequired !== true
    || route.chainBound !== true
    || route.accountBound !== true
    || route.recipientBound !== true
    || route.amountBound !== true
    || route.nonceBound !== true
    || route.purposeBound !== true
    || route.replayProtected !== true
    || route.eventEmitted !== true
    || route.localSimulationPassed !== true
  ) {
    throw new Error("test_fund_release_route_security_requirements_incomplete");
  }
  const recipient = assertNotDisposableWalletRecipient(route.intendedResidualRecipient);
  const maximumFunding = requireNonnegativeInteger(
    plan.maximumFundingWei,
    "maximum_funding_wei"
  );
  const maximumResidual = requireNonnegativeInteger(
    plan.maximumResidualWei,
    "maximum_residual_wei"
  );
  if (maximumResidual > maximumFunding) {
    throw new Error("maximum_residual_wei_cannot_exceed_maximum_funding_wei");
  }
  if (route.publicReleaseRequiresSeparateExactApproval !== true) {
    throw new Error("separate_exact_release_approval_required");
  }
  return Object.freeze({
    mode: "verified_release_route",
    intendedResidualRecipient: recipient,
    maximumFundingWei: maximumFunding.toString(),
    maximumResidualWei: maximumResidual.toString(),
    approvedForFunding: true
  });
}

function validateUnavoidableLockException(plan) {
  const lock = plan.unavoidableLock;
  const maximumFunding = requireNonnegativeInteger(
    plan.maximumFundingWei,
    "maximum_funding_wei"
  );
  const maximumLoss = requireNonnegativeInteger(
    lock?.exactMaximumLossWei,
    "exact_maximum_loss_wei"
  );
  if (
    !lock
    || lock.unavoidablePropertyOfExactProductionDesign !== true
    || lock.amountExplicitlyExpendable !== true
    || lock.clearExactLossWarningShown !== true
    || lock.explicitExactLossApprovalReceived !== true
    || lock.noSaferRouteTechnicallyPossible !== true
    || typeof lock.technicalImpossibilityEvidence !== "string"
    || lock.technicalImpossibilityEvidence.length < 20
    || maximumLoss !== maximumFunding
  ) {
    throw new Error("unavoidable_test_fund_lock_exception_incomplete");
  }
  return Object.freeze({
    mode: "unavoidable_lock_exception",
    exactMaximumLossWei: maximumLoss.toString(),
    approvedForFunding: true
  });
}

function validateTestFundReleasePlan(plan) {
  if (!plan || plan.policyVersion !== "philcore-test-fund-release-v1") {
    throw new Error("test_fund_release_policy_version_invalid");
  }
  if (!COVERED_ASSET_KINDS.includes(plan.assetKind)) {
    throw new Error("test_fund_asset_kind_not_covered");
  }
  if (plan.fundingAmountIsMinimumPlusBoundedMargin !== true) {
    throw new Error("minimum_bounded_test_funding_required");
  }
  if (plan.balancesBeforeAndAfterRecorded !== true) {
    throw new Error("test_fund_balance_accounting_required");
  }
  if (plan.routeTestedBeforeFundingWhenPossible !== true) {
    throw new Error("test_fund_release_route_pretest_required");
  }
  if (plan.releaseRoute?.status === "verified") {
    return validateVerifiedReleaseRoute(plan);
  }
  return validateUnavoidableLockException(plan);
}

function validateTestFundLifecyclePlan(plan) {
  if (!plan || plan.schemaVersion !== "philcore-test-fund-lifecycle-v1") {
    throw new Error("test_fund_lifecycle_schema_invalid");
  }
  const maximumFunding = requireNonnegativeInteger(
    plan.maximumFundingWei,
    "maximum_funding_wei"
  );
  const maximumStranded = requireNonnegativeInteger(
    plan.maximumStrandedWei,
    "maximum_stranded_wei"
  );
  if (maximumStranded > maximumFunding) {
    throw new Error("maximum_stranded_wei_cannot_exceed_maximum_funding_wei");
  }
  if (
    plan.accountBinding?.implementationVerified !== true
    || plan.accountBinding?.factoryVerified !== true
    || plan.accountBinding?.derivationVerified !== true
    || plan.accountBinding?.chainBound !== true
  ) {
    throw new Error("test_fund_account_binding_incomplete");
  }
  const releaseGuard = validateTestFundReleasePlan(plan.releasePlan);
  const simulation = plan.simulation;
  if (
    !simulation
    || simulation.createSimulated !== true
    || simulation.fundSimulated !== true
    || simulation.executeSimulated !== true
    || simulation.releaseSimulated !== true
    || simulation.finalStateVerified !== true
    || simulation.localSimulationPassed !== true
  ) {
    throw new Error("complete_test_fund_lifecycle_simulation_required");
  }
  if (
    simulation.forkSimulationPassed !== true
    && (
      typeof simulation.forkSimulationUnavailabilityReason !== "string"
      || simulation.forkSimulationUnavailabilityReason.length < 20
    )
  ) {
    throw new Error("fork_test_fund_lifecycle_simulation_or_reason_required");
  }
  if (
    plan.authority?.freshProofRequired !== true
    || plan.authority?.freshApprovalRequired !== true
    || plan.authority?.freshUserPresenceRequired !== true
    || plan.authority?.freshDeviceVaultSignatureRequired !== true
    || plan.authority?.oneTimeAuthorityRequired !== true
    || plan.authority?.separateReleaseApprovalRequired !== true
  ) {
    throw new Error("test_fund_lifecycle_authority_requirements_incomplete");
  }
  const expectedNativeBalance = requireNonnegativeInteger(
    plan.expectedFinalState?.nativeBalanceWei,
    "expected_final_native_balance_wei"
  );
  const expectedDeposit = requireNonnegativeInteger(
    plan.expectedFinalState?.entryPointDepositWei,
    "expected_final_entrypoint_deposit_wei"
  );
  if (plan.expectedFinalState?.tokenBalancesReconciled !== true) {
    throw new Error("expected_final_token_balances_must_be_reconciled");
  }
  const nonzeroFinalBalance =
    expectedNativeBalance > 0n || expectedDeposit > 0n;
  if (
    nonzeroFinalBalance
    && (
      typeof plan.expectedFinalState?.dustJustification !== "string"
      || plan.expectedFinalState.dustJustification.length < 20
      || plan.expectedFinalState.dustExplicitlyApprovedBeforeFunding !== true
    )
  ) {
    throw new Error("nonzero_final_test_balance_requires_exact_dust_approval");
  }
  return Object.freeze({
    mode: "complete_test_fund_lifecycle",
    maximumFundingWei: maximumFunding.toString(),
    maximumStrandedWei: maximumStranded.toString(),
    intendedResidualRecipient: releaseGuard.intendedResidualRecipient ?? null,
    expectedFinalNativeBalanceWei: expectedNativeBalance.toString(),
    expectedFinalEntryPointDepositWei: expectedDeposit.toString(),
    zeroFinalNativeAndDepositBalance: !nonzeroFinalBalance,
    approvedForFundingProposal: true
  });
}

module.exports = {
  COVERED_ASSET_KINDS,
  assertNotDisposableWalletRecipient,
  validateTestFundLifecyclePlan,
  validateTestFundReleasePlan
};
