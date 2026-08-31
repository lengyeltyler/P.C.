require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  ROOT,
  ensureNoSecrets,
  readJson
} = require("../../scripts/ethereum-sepolia/o23r-common.cjs");

const ARCHITECTURE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O35_V2_FACTORY_ACCOUNT_LIFECYCLE_ARCHITECTURE.json"
);
const V1_ACCOUNT_PATH =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const V1_FACTORY_PATH =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function sha256File(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

function solidityFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name);
    if (entry.isDirectory()) return solidityFiles(resolved);
    return entry.name.endsWith(".sol") ? [resolved] : [];
  });
}

describe("O.35 V2 factory architecture and account lifecycle design", function () {
  const architecture = readJson(ARCHITECTURE_PATH);

  it("records the exact local-only phase and baseline", function () {
    assert.equal(architecture.schemaVersion, 1);
    assert.equal(architecture.phase, "O.35");
    assert.equal(
      architecture.canonicalPhaseName,
      "O.35 V2 Factory Architecture and Account Lifecycle Design"
    );
    assert.equal(
      architecture.classification,
      "LOCAL_FACTORY_ACCOUNT_LIFECYCLE_DESIGN_ONLY"
    );
    assert.equal(
      architecture.sourceHeadAtPhaseStart,
      "9c139d94b1dcad14314484283a4b02532d32a2fa"
    );
    assert.equal(architecture.publicMutationCount, 0);
  });

  it("preserves the canonical identity without making it a wallet", function () {
    const identity = architecture.identityBoundary;
    assert.equal(identity.identityId, "identity_abab9766da60_24afd015");
    assert.equal(identity.label, "My Phil");
    assert.equal(
      identity.validatorAddressAtBaseline,
      "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa"
    );
    assert.equal(
      identity.validatorKeyIdAtBaseline,
      "validator_key_3c5b2ebebc4f3f3b"
    );
    assert.equal(
      identity.validatorKeyIdBindingAtBaseline,
      "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809"
    );
    assert.equal(identity.identityIsChainIndependent, true);
    assert.equal(identity.accountIsVersionedChainAdapter, true);
    assert.equal(identity.identityIdStoredOnchain, false);
    assert.equal(
      identity.privateIdentitySourceMaterialStoredOrDerivedByFactory,
      false
    );
  });

  it("freezes V1 and excludes the O.27 prefund from migration", function () {
    assert.equal(
      sha256File(V1_ACCOUNT_PATH),
      architecture.v1Boundary.accountSourceSha256
    );
    assert.equal(
      sha256File(V1_FACTORY_PATH),
      architecture.v1Boundary.factorySourceSha256
    );
    assert.equal(architecture.v1Boundary.sourceFrozen, true);
    assert.equal(architecture.v1Boundary.proxyUpgradeAllowed, false);
    assert.equal(architecture.v1Boundary.retrofitAllowed, false);
    assert.equal(architecture.v1Boundary.v1PrefundIsMigrationSource, false);
  });

  it("selects one immutable factory per reviewed account version", function () {
    const factory = architecture.factoryModel;
    assert.equal(
      factory.selectedModel,
      "one_non_upgradeable_factory_per_reviewed_account_version"
    );
    assert.equal(
      factory.implementationSelection,
      "external_manifest_selects_version_specific_factory"
    );
    for (const field of [
      "mutableImplementationRegistryAllowed",
      "factoryProxyAllowed",
      "accountProxyAllowed",
      "postDeploymentInitializerAllowed",
      "callerSpecificAuthorityAllowed",
      "factoryReceivesValue",
      "factoryCustodiesFunds",
      "factoryAdministrativeAuthority",
      "factoryRecoveryAuthority",
      "factoryExecutionAuthority",
      "factoryPostDeploymentAccountAuthority"
    ]) {
      assert.equal(factory[field], false, field);
    }
    assert.equal(factory.constructorOnlyAtomicInitialization, true);
    assert.equal(factory.permissionlessExactCreationAllowed, true);
  });

  it("limits the factory to deterministic complete account creation", function () {
    const responsibilities = architecture.factoryResponsibilities;
    for (const required of [
      "validate a complete canonical initialization tuple",
      "derive the domain-separated CREATE2 salt",
      "predict the counterfactual address",
      "deploy the exact version-bound account creation code"
    ]) {
      assert.equal(responsibilities.allowed.includes(required), true, required);
    }
    for (const forbidden of [
      "select a mutable implementation",
      "upgrade or replace an account",
      "initialize an already deployed account",
      "rotate a validator",
      "execute an account action",
      "hold or route native currency or tokens",
      "bypass Runtime O.32 O.33 or O.34 enforcement"
    ]) {
      assert.equal(
        responsibilities.forbidden.includes(forbidden),
        true,
        forbidden
      );
    }
  });

  it("binds every security field into CREATE2 derivation", function () {
    const create2 = architecture.create2Model;
    assert.match(create2.formula, /0xff/);
    assert.match(create2.formula, /factoryAddress/);
    assert.match(create2.formula, /deploymentSalt/);
    assert.match(create2.formula, /accountCreationCode/);
    assert.match(create2.saltFormula, /deploymentChainId/);
    assert.match(create2.saltFormula, /accountVersionId/);
    assert.match(create2.saltFormula, /ownerCommitment/);
    assert.match(create2.saltFormula, /identityBindingCommitment/);
    assert.match(create2.saltFormula, /userSalt/);
    assert.equal(create2.initializationTupleInOrder.length, 20);
    assert.equal(create2.initialValidatorEpoch, 1);
    assert.equal(create2.initialRecoveryEpoch, 1);
    assert.equal(create2.allSecurityInputsBoundIntoCreationCodeHash, true);
    assert.equal(create2.derivationVectorDeferredUntilCreationBytecodeExists, true);
  });

  it("changes address for creation inputs but not authorized later state", function () {
    const rules = architecture.addressChangeRules;
    for (const field of [
      "differentIdentityOrOwnerCommitment",
      "differentIdentityBindingCommitment",
      "differentFactory",
      "differentAccountVersion",
      "differentSecurityModel",
      "differentEntryPoint",
      "differentChain",
      "differentUserSalt",
      "differentInitialValidator",
      "differentInitialValidatorKeyBinding",
      "differentInitialRecoveryConfiguration"
    ]) {
      assert.equal(rules[field], true, field);
    }
    for (const field of [
      "postActivationValidatorRotation",
      "postActivationRecoveryConfigurationRotation",
      "postActivationRecoveryCompletion"
    ]) {
      assert.equal(rules[field], false, field);
    }
  });

  it("requires atomic complete initialization and independent activation", function () {
    const initialization = architecture.initializationModel;
    assert.equal(initialization.predeploymentStateOnchain, "none");
    assert.equal(initialization.constructorValidatesCompleteTuple, true);
    assert.equal(initialization.constructorMakesExternalCalls, false);
    assert.equal(initialization.constructorAcceptsNativeValue, false);
    assert.equal(initialization.partialOnchainInitializationAllowed, false);
    assert.equal(initialization.duplicateInitializationImpossible, true);
    assert.equal(
      initialization.successfulDeploymentState,
      "INITIALIZED_ACTIVE_PENDING_INDEPENDENT_VERIFICATION"
    );
    assert.equal(
      initialization.activationRequiresIndependentPostDeploymentVerification,
      true
    );
  });

  it("requires exact validator and three-domain recovery initialization", function () {
    assert.equal(architecture.validatorInitialization.addressRequired, true);
    assert.equal(
      architecture.validatorInitialization.keyIdBindingRequired,
      true
    );
    assert.equal(
      architecture.validatorInitialization.validatorEpochStartsAtOne,
      true
    );
    assert.equal(
      architecture.validatorInitialization.factoryCanSignOrRotate,
      false
    );
    assert.deepEqual(architecture.recoveryInitialization.roles, [
      "PRIMARY_DEVICE",
      "HARDWARE_SECURITY_KEY",
      "RECOVERY_FACTOR"
    ]);
    assert.equal(architecture.recoveryInitialization.threshold, 2);
    assert.equal(
      architecture.recoveryInitialization
        .allThreeRoleCommitmentsRequiredBeforeDerivationAcceptance,
      true
    );
    assert.equal(
      architecture.recoveryInitialization.recoveryEpochStartsAtOne,
      true
    );
    assert.equal(
      architecture.recoveryInitialization
        .postActivationRotationOnlyThroughAccountRecoveryRules,
      true
    );
  });

  it("defines an ordered lifecycle that blocks counterfactual funding", function () {
    assert.deepEqual(architecture.accountLifecycle.states, [
      "LOCAL_IDENTITY_READY",
      "LOCAL_CONFIGURATION_COMPLETE",
      "COUNTERFACTUAL_DERIVATION_VERIFIED",
      "DEPLOYMENT_ELIGIBLE_UNFUNDED",
      "DEPLOYED_PENDING_VERIFICATION",
      "ACTIVE_UNFUNDED",
      "ACTIVE_FUNDED",
      "MIGRATION_PENDING",
      "RETIREMENT_PENDING",
      "RETIRED"
    ]);
    assert.equal(
      architecture.counterfactualModel
        .counterfactualBalanceMustBeZeroForLifecycleAcceptance,
      true
    );
    assert.equal(
      architecture.counterfactualModel
        .unexpectedBalanceCodeNonceOrDepositFailsLifecycleAcceptance,
      true
    );
    assert.equal(
      architecture.accountLifecycle.fundingBeforeActiveUnfundedProhibited,
      true
    );
  });

  it("uses explicit version and migration instead of proxy upgrade", function () {
    const versioning = architecture.versioning;
    assert.equal(versioning.newReviewedFactoryPerVersion, true);
    assert.equal(versioning.newCreationCodePerVersion, true);
    assert.equal(versioning.newCounterfactualAddressPerVersion, true);
    assert.equal(versioning.proxyUpgrade, false);
    assert.equal(versioning.identityContinuityUsesOwnerAndIdentityCommitments, true);

    const migration = architecture.migration;
    assert.equal(migration.destinationActiveBeforeAssetMovement, true);
    assert.equal(migration.freshIntentPerAssetMovement, true);
    assert.equal(migration.freshApprovalAndPresencePerPublicAction, true);
    assert.equal(migration.freshValidatorAuthorizationPerAction, true);
    assert.equal(migration.automaticAssetMovement, false);
    assert.equal(migration.factoryAssetSeizureOrSweep, false);
    assert.equal(migration.v1CanMoveAssetsToV2, false);
    assert.equal(migration.v2CanClaimV1Prefund, false);
  });

  it("preserves O.28 release and final-state gates", function () {
    const fund = architecture.fundLifecycle;
    for (const field of [
      "lifecycleCompletionRequiredBeforeFunding",
      "validatorInitializationRequiredBeforeFunding",
      "recoveryInitializationRequiredBeforeFunding",
      "independentDeploymentVerificationRequiredBeforeFunding",
      "verifiedReleasePathRequiredBeforeFunding",
      "localLifecycleSimulationRequired",
      "forkLifecycleSimulationOrTechnicalReasonRequired",
      "maximumLossRequired",
      "residualRecipientRequired",
      "separateFundingOperationAndReleaseApprovals",
      "finalStateReconciliationRequired",
      "zeroFinalBalancePreferred",
      "factoryIsNeverReleasePath"
    ]) {
      assert.equal(fund[field], true, field);
    }
  });

  it("indexes every required O.35 deliverable", function () {
    const docs = {
      factory: read("docs/reference/O35_V2_FACTORY_ARCHITECTURE.md"),
      lifecycle: read("docs/reference/O35_V2_ACCOUNT_LIFECYCLE.md"),
      migration: read("docs/reference/O35_V2_MIGRATION_DESIGN.md"),
      security: read(
        "docs/security/O35_V2_FACTORY_LIFECYCLE_SECURITY_ANALYSIS.md"
      ),
      tests: read(
        "docs/reference/O35_V2_FACTORY_LIFECYCLE_TEST_PLAN.md"
      )
    };
    assert.match(docs.factory, /one non-upgradeable factory per reviewed/);
    assert.match(docs.lifecycle, /COUNTERFACTUAL_DERIVATION_VERIFIED/);
    assert.match(docs.migration, /V1 cannot execute a V2 migration intent/);
    assert.match(docs.security, /Factory Compromise Analysis/);
    assert.match(docs.tests, /Future Creation Tests/);
    const index = read("docs/CANONICAL_DOCS.md");
    for (const filename of [
      "O35_V2_FACTORY_ARCHITECTURE.md",
      "O35_V2_ACCOUNT_LIFECYCLE.md",
      "O35_V2_MIGRATION_DESIGN.md",
      "O35_V2_FACTORY_LIFECYCLE_SECURITY_ANALYSIS.md",
      "O35_V2_FACTORY_LIFECYCLE_TEST_PLAN.md"
    ]) {
      assert.equal(index.includes(filename), true, filename);
    }
  });

  it("contains no V2 Solidity factory/account implementation", function () {
    const sources = solidityFiles(path.join(ROOT, "contracts"));
    for (const sourcePath of sources) {
      const source = fs.readFileSync(sourcePath, "utf8");
      assert.doesNotMatch(source, /contract\s+PhilCoreV2Account(?:Factory)?\b/);
    }
  });

  it("contains no secrets, authority, deployment, or public mutation", function () {
    ensureNoSecrets(architecture);
    assert.deepEqual(
      Object.values(architecture.securityBoundary),
      Object.values(architecture.securityBoundary).map(() => false)
    );
    const serialized = JSON.stringify(architecture);
    for (const prohibited of [
      "\"signature\":\"0x",
      "\"privateKey\":\"",
      "\"rawTransaction\":\"",
      "http://",
      "https://",
      "/v2/"
    ]) {
      assert.equal(serialized.includes(prohibited), false, prohibited);
    }
  });
});
