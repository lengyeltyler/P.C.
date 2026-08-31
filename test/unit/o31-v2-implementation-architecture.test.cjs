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

const ARCHITECTURE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O31_V2_IMPLEMENTATION_ARCHITECTURE.json"
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

function git(args) {
  const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

describe("O.31 V2 implementation architecture and module design", function () {
  const architecture = readJson(ARCHITECTURE_PATH);

  it("records the exact local-only phase and verified starting baseline", function () {
    assert.equal(architecture.phase, "O.31");
    assert.equal(
      architecture.canonicalPhaseName,
      "O.31 V2 Account Implementation Architecture and Module Design"
    );
    assert.equal(
      architecture.classification,
      "IMPLEMENTATION_ARCHITECTURE_COMPLETE_LOCAL_ONLY"
    );
    assert.equal(
      architecture.sourceHeadAtPhaseStart,
      "978e6d1169d536d7b0a014338799d8abb2b43630"
    );
    assert.equal(
      git(["merge-base", "--is-ancestor", architecture.sourceHeadAtPhaseStart, "HEAD"]),
      ""
    );
    assert.equal(architecture.scope, "local_implementation_architecture_only");
    assert.equal(architecture.publicMutationCount, 0);
    assert.equal(architecture.baseline.repositoryRoot, ROOT);
    assert.equal(architecture.baseline.branch, "codex/device-identity-v1");
    assert.equal(architecture.baseline.worktreeCleanAtStart, true);
    assert.deepEqual(architecture.baseline.completedPhasesReviewed, [
      "O.20",
      "O.21.1",
      "O.21.2",
      "O.21.3",
      "O.22",
      "O.23R",
      "O.24",
      "O.25",
      "O.26",
      "O.26.1",
      "O.27",
      "O.28",
      "O.29",
      "O.30"
    ]);
    assert.equal(architecture.baseline.discrepancies.length, 1);
    assert.equal(
      architecture.baseline.discrepancies[0].id,
      "O22_GUARDED_SOURCE_BINDING_HISTORICAL_AFTER_O26_1"
    );
    assert.equal(architecture.baseline.discrepancies[0].securityRelevant, true);
    assert.equal(architecture.baseline.discrepancies[0].continuationSafe, true);
    assert.match(
      architecture.baseline.discrepancies[0].effect,
      /fails closed/
    );
  });

  it("preserves canonical identity, Runtime, WebAuthn, and frozen V1 bindings", function () {
    const identity = architecture.baseline.canonicalIdentity;
    const bindings = architecture.baseline.sourceBindings;
    assert.equal(identity.identityId, "identity_abab9766da60_24afd015");
    assert.equal(identity.label, "My Phil");
    assert.equal(
      identity.validatorAddress,
      "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa"
    );
    assert.equal(identity.validatorKeyId, "validator_key_3c5b2ebebc4f3f3b");
    assert.equal(
      identity.validatorKeyIdBinding,
      "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809"
    );
    assert.equal(sha256File(V1_ACCOUNT_PATH), bindings.v1AccountSourceSha256);
    assert.equal(sha256File(V1_FACTORY_PATH), bindings.v1FactorySourceSha256);
    assert.equal(
      sha256File("docs/PHILCORE_CORE_BOUNDARY.md"),
      bindings.coreBoundarySha256
    );
    assert.equal(
      sha256File("docs/PHILCORE_RUNTIME_LIFECYCLE.md"),
      bindings.runtimeLifecycleSha256
    );
    assert.equal(
      sha256File("apps/phil-device-sdk/src/runtime/localProofGatedAccount.ts"),
      bindings.runtimeLocalProofAccountSha256
    );
    assert.equal(
      sha256File("apps/phil-device-sdk/src/runtime/deviceVaultEcdsaCustody.ts"),
      bindings.deviceVaultCustodySha256
    );
    assert.equal(
      sha256File("apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts"),
      bindings.webauthnProviderSha256
    );
    assert.equal(
      sha256File("config/ethereum-sepolia/O30_V2_ACCOUNT_SPECIFICATION.json"),
      bindings.o30SpecificationSha256
    );
  });

  it("uses fixed compiled-in modules without plugin, proxy, or administrator paths", function () {
    const modules = architecture.modules;
    assert.equal(modules.account.stateOwner, true);
    assert.equal(modules.account.nonUpgradeable, true);
    assert.equal(modules.account.entryPointOnlyActions, true);
    assert.equal(modules.intentValidation.runtimeInstallable, false);
    assert.equal(modules.validatorVerification.runtimeInstallable, false);
    assert.equal(
      modules.validatorVerification.calldataSelectedVerifierAllowed,
      false
    );
    assert.equal(modules.validatorVerification.delegatecallAllowed, false);
    assert.equal(modules.recoveryStateMachine.externalCalls, false);
    assert.equal(modules.recoveryStateMachine.valueMovement, false);
    assert.equal(modules.typedExecution.genericTargetValueDataPrimitive, false);
    assert.equal(modules.factory.postDeploymentAuthority, false);
  });

  it("fixes exact independent primary, hardware, and recovery roles at 2-of-3", function () {
    const recovery = architecture.recoveryModel;
    assert.equal(recovery.threshold, 2);
    assert.equal(recovery.registeredRoleCount, 3);
    assert.deepEqual(
      recovery.roles.map((role) => role.id),
      ["PRIMARY_DEVICE", "HARDWARE_SECURITY_KEY", "RECOVERY_FACTOR"]
    );
    assert.equal(new Set(recovery.roles.map((role) => role.domain)).size, 3);
    assert.equal(recovery.roles[0].dailyExecutionValidatorKeyMayBeReused, false);
    assert.equal(recovery.roles[0].independentPurposeBoundCredentialRequired, true);
    assert.equal(
      recovery.roles[1].synchronizedPasskeyAcceptedAsIndependentHardware,
      false
    );
    assert.equal(recovery.roles[2].directAssetMovementAuthority, false);
    assert.equal(recovery.anySingleRoleSufficient, false);
    assert.equal(recovery.dailyValidatorCountsAsRecoveryRole, false);
    assert.equal(recovery.requestMovesAssets, false);
    assert.equal(recovery.completionMovesAssets, false);
    assert.equal(
      recovery.postRecoveryAssetMovementRequiresFreshOrdinaryAuthorization,
      true
    );
  });

  it("selects commitment storage and fail-closed independent hardware integration", function () {
    const recovery = architecture.recoveryModel;
    const hardware = architecture.hardwareIntegration;
    assert.equal(recovery.factorCommitmentsStoredOnchain, true);
    assert.equal(recovery.rawPrivateMaterialStoredOnchain, false);
    assert.equal(recovery.publicWitnessMayBecomeVisibleOnUse, true);
    assert.equal(
      hardware.preferredExternalFactor,
      "cross_platform_FIDO2_WebAuthn_security_key"
    );
    assert.equal(
      hardware.evaluation.syncedPasskey,
      "not accepted as the independent hardware role"
    );
    assert.equal(hardware.onchainP256VerificationMustBeAcceptedBeforeImplementation, true);
    assert.equal(hardware.fallbackToSameDeviceSoftwareKeyAllowed, false);
    assert.equal(hardware.registration.explicitTrustedRuntimeCeremony, true);
    assert.equal(hardware.registration.attestationEvidenceStoredLocallyOnly, true);
  });

  it("declares immutable and mutable storage without capability mappings", function () {
    const storage = architecture.storage;
    for (const required of [
      "EntryPoint",
      "deployment chain ID",
      "owner commitment",
      "factory binding",
      "account version ID",
      "security model ID"
    ]) {
      assert.equal(storage.immutable.includes(required), true, required);
    }
    assert.equal(storage.mappingsAllowed, false);
    assert.equal(storage.moduleRegistryAllowed, false);
    assert.equal(storage.proxyStorageSlotsAllowed, false);
    assert.ok(storage.mutableInOrder.length >= 16);
    assert.match(storage.mutableInOrder[4], /primary-device/);
    assert.match(storage.mutableInOrder[5], /hardware-security-key/);
    assert.match(storage.mutableInOrder[6], /recovery-factor/);
  });

  it("separates nonce lanes and invalidates old authority through epochs", function () {
    const nonce = architecture.nonceModel;
    assert.deepEqual(nonce.lanes, {
      "0": "ordinary typed execution",
      "1": "validator maintenance",
      "2": "recovery and recovery-configuration maintenance"
    });
    assert.equal(nonce.entryPointOwnsSequence, true);
    assert.deepEqual(nonce.activeRecoveryFreezes, [0, 1]);
    assert.equal(nonce.validatorEpochBoundToAllSignedActions, true);
    assert.equal(nonce.recoveryEpochBoundToAllSignedActions, true);
    assert.equal(nonce.recoveryCompletionIncrementsValidatorEpoch, true);
    assert.equal(nonce.recoveryCompletionIncrementsRecoveryEpoch, true);
    assert.equal(nonce.configCompletionIncrementsRecoveryEpoch, true);
    assert.equal(nonce.cancellationOrExpiryIncrementsEpoch, false);
  });

  it("defines only typed interfaces and explicitly prohibits wallet backdoors", function () {
    const surface = architecture.conceptualInterfaces;
    for (const required of [
      "validateUserOperation",
      "validateIntent",
      "validateAuthorityEpoch"
    ]) {
      assert.equal(surface.validation.includes(required), true);
    }
    for (const required of [
      "transferNative",
      "transferERC20",
      "safeTransferERC721",
      "safeTransferERC1155",
      "withdrawEntryPointDeposit"
    ]) {
      assert.equal(surface.execution.includes(required), true);
    }
    for (const required of [
      "requestRecovery",
      "cancelRecovery",
      "finalizeRecovery",
      "expireRecovery"
    ]) {
      assert.equal(surface.recovery.includes(required), true);
    }
    for (const prohibited of [
      "execute",
      "executeBatch",
      "delegatecall",
      "upgradeTo",
      "installModule",
      "setAdmin",
      "sweep",
      "withdrawAll",
      "approveToken"
    ]) {
      assert.equal(surface.prohibited.includes(prohibited), true, prohibited);
    }
  });

  it("requires unit, security, and complete create-through-release lifecycle tests", function () {
    const testing = architecture.testingArchitecture;
    assert.ok(testing.unit.length >= 8);
    for (const threat of [
      "stolen primary device",
      "stolen hardware key",
      "stolen recovery factor",
      "malicious application",
      "malicious bundler relayer and RPC",
      "replay stale signature and wrong epoch"
    ]) {
      assert.equal(testing.security.includes(threat), true, threat);
    }
    assert.deepEqual(testing.fullLifecycleInOrder, [
      "Create Account",
      "Register Device",
      "Register Hardware Key",
      "Register Recovery Factor",
      "Fund Account",
      "Execute Operation",
      "Recover Authority",
      "Release Residual Funds",
      "Verify Final State"
    ]);
    assert.equal(testing.localLifecycleRequiredBeforeFunding, true);
    assert.equal(testing.forkLifecycleRequiredBeforeFunding, true);
    assert.equal(testing.factorLossPermutationsRequired, true);
  });

  it("documents implementation, recovery, interface, roadmap, and canonical index", function () {
    const architectureDoc = read(
      "docs/reference/O31_V2_IMPLEMENTATION_ARCHITECTURE_AND_MODULE_DESIGN.md"
    );
    const recoveryDoc = read(
      "docs/reference/O31_V2_RECOVERY_ARCHITECTURE.md"
    );
    const interfaceDoc = read(
      "docs/reference/O31_V2_INTERFACE_SPECIFICATION.md"
    );
    const roadmap = read("docs/reference/O31_V2_IMPLEMENTATION_ROADMAP.md");
    const index = read("docs/CANONICAL_DOCS.md");

    for (const heading of [
      "Component Model",
      "Contract Composition",
      "Off-Chain Components",
      "Trust Boundaries",
      "Storage Architecture",
      "Nonce And Epoch Architecture",
      "Migration Requirements"
    ]) {
      assert.match(architectureDoc, new RegExp(heading));
    }
    for (const required of [
      "Primary device",
      "Hardware security key",
      "Recovery factor",
      "Recovery State Machine",
      "Factor Commitments And Privacy",
      "Loss And Compromise Procedures",
      "Recovery-Configuration Rotation"
    ]) {
      assert.match(recoveryDoc, new RegExp(required, "i"));
    }
    assert.match(interfaceDoc, /Validation Interfaces/);
    assert.match(interfaceDoc, /EntryPoint-Only Typed Execution/);
    assert.match(interfaceDoc, /Prohibited Interface/);
    assert.match(roadmap, /Contract Implementation Order/);
    assert.match(roadmap, /Testing Order/);
    assert.match(roadmap, /Audit Preparation/);
    assert.match(roadmap, /Deployment Preparation/);
    assert.match(index, /O\.31 V2 Account Implementation Architecture/);
    assert.match(index, /O\.31 V2 Three-Domain Recovery Architecture/);
  });

  it("keeps every mutation and authority boundary false with no secrets or URLs", function () {
    ensureNoSecrets(architecture);
    for (const [key, value] of Object.entries(architecture.securityBoundary)) {
      assert.equal(value, false, key);
    }
    assert.doesNotMatch(JSON.stringify(architecture), /https?:\/\//);
    assert.equal(architecture.principles.hiddenAdministrator, false);
    assert.equal(architecture.principles.upgradeKey, false);
    assert.equal(architecture.principles.arbitraryExecution, false);
    assert.equal(architecture.principles.delegatecall, false);
    assert.equal(architecture.principles.unrestrictedWithdrawal, false);
    assert.equal(architecture.principles.singleFactorRecovery, false);
  });
});
