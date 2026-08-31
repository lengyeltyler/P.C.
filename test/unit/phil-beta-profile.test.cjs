"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { id } = require("ethers");

const root = path.resolve(__dirname, "../..");
const profile = JSON.parse(
  fs.readFileSync(path.join(root, "config/controlled-sepolia-beta-v1.json"), "utf8")
);
const mutationPlanTemplate = JSON.parse(
  fs.readFileSync(
    path.join(
      root,
      "config/ethereum-sepolia/PHILCORE_CONTROLLED_SEPOLIA_BETA_MUTATION_PLAN_TEMPLATE.json"
    ),
    "utf8"
  )
);
const accountSource = fs.readFileSync(
  path.join(root, "contracts/base/erc4337/PhilCore4337Account.sol"),
  "utf8"
);
const gateSource = fs.readFileSync(
  path.join(root, "contracts/base/PhilSepoliaLocalComposedActionGateV1.sol"),
  "utf8"
);

test("freezes the controlled Sepolia Beta network and action surface", () => {
  assert.equal(profile.network.chainId, 11155111);
  assert.equal(
    profile.network.entryPoint,
    "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
  );
  assert.equal(profile.ordinaryAction.accountSelector, id("execute(address,uint256,bytes)").slice(0, 10));
  assert.equal(
    profile.ordinaryAction.gateSelector,
    id("verifyAndConsume(bytes32,bytes32,bytes32,uint64,address)").slice(0, 10)
  );
  assert.equal(profile.ordinaryAction.maximumValueWei, "0");
  assert.equal(profile.account.paymasterAllowed, false);
  assert.equal(profile.account.batchAllowed, false);
  assert.equal(profile.account.delegatecallAllowed, false);
  assert.equal(profile.account.genericCallAllowed, false);
  assert.equal(profile.account.singleAuthorizedAccount, true);
  assert.equal(profile.ordinaryAction.mintRecipientPolicy, "current_execution_owner_enforced_on_chain");
  assert.equal(profile.ordinaryAction.automaticRetry, false);
  assert.equal(profile.release.mainnetAllowed, false);
});

test("binds the composed gate to one account and its current execution owner", () => {
  for (const fragment of [
    "address public immutable authorizedAccount",
    "msg.sender != authorizedAccount",
    "revert UnauthorizedAccountBinding()",
    "mintRecipient != _currentExecutionOwner(msg.sender)",
    "revert MintRecipientNotCurrentOwner()"
  ]) {
    assert.equal(gateSource.includes(fragment), true, fragment);
  }
});

test("freezes recovery timing and disposable-fund ceilings", () => {
  assert.equal(profile.recovery.delaySeconds, "172800");
  assert.equal(profile.recovery.expirySeconds, "604800");
  assert.equal(profile.recovery.ordinaryActionAuthority, false);
  assert.equal(profile.recovery.accountFrozenWhilePending, true);
  assert.equal(profile.funding.maximumOperatorExposureWei, "50000000000000000");
  assert.equal(profile.funding.maximumAccountNativeBalanceWei, "10000000000000000");
  assert.equal(profile.funding.maximumEntryPointDepositWei, "10000000000000000");
  assert.equal(profile.funding.legacyDisclosedAlphaSourceAllowedForCappedFundingOnly, true);
  assert.equal(profile.funding.legacyDisclosedAlphaSourceMayHoldBetaAuthority, false);
  assert.equal(profile.funding.fundOnlyBalanceBearingRoles, true);
  assert.equal(profile.funding.releaseRecipient, "current_execution_owner_only");
  assert.equal(profile.funding.meaningfulAssetsAllowed, false);
});

test("binds the profile to source-enforced paymaster, value, gate, and release restrictions", () => {
  for (const fragment of [
    "userOp.paymasterAndData.length != 0",
    "revert PaymasterForbidden()",
    "revert NonZeroActionValueForbidden()",
    "target != approvedActionGate",
    "COMPOSED_VERIFY_AND_CONSUME_SELECTOR = 0xfa724deb",
    "address payable recipient = payable(_owner)",
    "entryPoint().withdrawTo(recipient"
  ]) {
    assert.equal(accountSource.includes(fragment), true, fragment);
  }
});

test("keeps the staged Beta mutation-plan template fail closed", () => {
  assert.equal(mutationPlanTemplate.status, "TEMPLATE_NOT_APPROVABLE");
  assert.equal(mutationPlanTemplate.approvable, false);
  assert.equal(mutationPlanTemplate.publicMutationAuthorized, false);
  assert.equal(mutationPlanTemplate.betaReady, false);
  assert.equal(mutationPlanTemplate.approval.templateApprovalAuthorizesMutation, false);
  assert.equal(mutationPlanTemplate.approval.priorAlphaApprovalAuthorizesMutation, false);
  assert.equal(mutationPlanTemplate.approval.oneStageApprovalAuthorizesAnotherStage, false);
  assert.equal(mutationPlanTemplate.addresses.minimumForDeploymentAndFirstAction, 3);
  assert.equal(mutationPlanTemplate.addresses.requiredForFullLifecycleMatrix, 5);
  assert.equal(mutationPlanTemplate.addresses.allFiveMustBeDistinct, true);
  assert.equal(mutationPlanTemplate.addresses.disclosedAlphaAddressOrKeyReuseAllowed, false);
  assert.equal(
    mutationPlanTemplate.contracts.PhilSepoliaLocalComposedActionGateV1.authorizedAccount,
    null
  );
  assert.equal(
    mutationPlanTemplate.fundingSource.policy,
    "LEGACY_DISCLOSED_ALPHA_SOURCE_CAPPED_FUNDING_ONLY"
  );
  assert.equal(mutationPlanTemplate.fundingSource.mayHoldAnyBetaAuthority, false);
  assert.equal(mutationPlanTemplate.fundingSource.permittedDirectTarget, "BETA_DEPLOYER_ONLY");
  assert.equal(mutationPlanTemplate.fundingSource.authorityAddressesMustRemainUnfunded, true);
  assert.equal(mutationPlanTemplate.fundingSource.exactTransactionRequiresStageApproval, true);
});

test("binds staged plan limits and mutation counts to the controlled Beta profile", () => {
  assert.equal(
    mutationPlanTemplate.network.entryPoint,
    profile.network.entryPoint
  );
  assert.equal(
    mutationPlanTemplate.limits.maximumOperatorExposureWei,
    profile.funding.maximumOperatorExposureWei
  );
  assert.equal(
    mutationPlanTemplate.limits.maximumAccountNativeBalanceWei,
    profile.funding.maximumAccountNativeBalanceWei
  );
  assert.equal(
    mutationPlanTemplate.limits.maximumEntryPointDepositWei,
    profile.funding.maximumEntryPointDepositWei
  );
  assert.equal(
    mutationPlanTemplate.limits.maximumOperationFeeWei,
    profile.ordinaryAction.maximumTotalFeeWei
  );
  assert.deepEqual(
    mutationPlanTemplate.stages.map(({ stageId, expectedPublicMutationCount }) => [
      stageId,
      expectedPublicMutationCount
    ]),
    [
      ["P0", 0],
      ["P1", 4],
      ["P2", 2],
      ["P3", 1],
      ["P4", null],
      ["P5", 1]
    ]
  );
  assert.equal(mutationPlanTemplate.stages[0].approvalRequired, false);
  assert.equal(
    mutationPlanTemplate.stages.slice(1).every(
      (stage) => stage.approvalRequired === true || stage.approvalRequiredPerSubplan === true
    ),
    true
  );
});
