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

const SPEC_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O30_V2_ACCOUNT_SPECIFICATION.json"
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

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

describe("O.30 V2 account specification and threat-model refinement", function () {
  const spec = readJson(SPEC_PATH);

  it("records the exact local-only phase and starting baseline", function () {
    assert.equal(spec.phase, "O.30");
    assert.equal(
      spec.canonicalPhaseName,
      "O.30 V2 Account Specification and Threat Model Refinement"
    );
    assert.equal(spec.classification, "V2_SPECIFICATION_COMPLETE_LOCAL_ONLY");
    assert.equal(
      spec.sourceHeadAtPhaseStart,
      "907cd616ad47c13c818cf81348003c9da47bf320"
    );
    assert.match(spec.sourceHeadAtPhaseStart, /^[0-9a-f]{40}$/u);
    assert.equal(spec.scope, "architecture_specification_only");
    assert.equal(spec.publicMutationCount, 0);
  });

  it("preserves the canonical identity boundary and frozen V1 hashes", function () {
    assert.equal(spec.identityBoundary.identityId, "identity_abab9766da60_24afd015");
    assert.equal(spec.identityBoundary.identityRemainsChainIndependent, true);
    assert.equal(spec.identityBoundary.accountIsChainAdapterState, true);
    assert.equal(sha256File(ACCOUNT_PATH), spec.v1Freeze.accountSourceSha256);
    assert.equal(sha256File(FACTORY_PATH), spec.v1Freeze.factorySourceSha256);
    assert.equal(spec.v1Freeze.modifyV1, false);
    assert.equal(spec.v1Freeze.recoverO27Prefund, false);
    assert.equal(spec.v1Freeze.reuseV1AddressForV2, false);
  });

  it("defines one noncircular canonical EIP-712 intent construction", function () {
    const intent = spec.intent;
    assert.equal(intent.canonicalSerialization.includes("EIP-712"), true);
    assert.equal(intent.packedEncodingAllowed, false);
    assert.deepEqual(intent.domain.fields, ["chainId", "verifyingContract"]);
    assert.deepEqual(intent.authorizedIntentFieldsInOrder, [
      "bytes32 intentCoreHash",
      "bytes32 runtimeAuthorizationDigest"
    ]);
    assert.equal(
      intent.coreHeaderFieldsInOrder.includes("bytes32 runtimeAuthorizationDigest"),
      false
    );
    assert.equal(intent.authorizedIntentRules.circularHashDependencyAllowed, false);
    assert.match(intent.hashes.intentCoreHash, /coreHeaderHash/);
    assert.match(intent.hashes.authorizedIntentHash, /runtimeAuthorizationDigest/);
    assert.match(intent.hashes.authorizationStructHash, /userOpHash/);
    assert.match(intent.hashes.validatorDigest, /0x1901/);
    assert.match(intent.hashes.recoveryFactorDigest, /0x1901/);
    assert.match(intent.hashes.configRotationDigest, /0x1901/);
  });

  it("fixes every core field, context, lifecycle, fee, and validity binding", function () {
    const fields = new Set(spec.intent.coreHeaderFieldsInOrder);
    for (const field of [
      "bytes32 securityModelId",
      "uint8 actionType",
      "bytes32 actionId",
      "bytes32 purpose",
      "bytes32 ownerCommitment",
      "uint256 chainId",
      "address entryPoint",
      "address account",
      "uint192 nonceKey",
      "uint64 nonceSequence",
      "uint64 validatorEpoch",
      "uint64 recoveryEpoch",
      "bytes32 applicationContextHash",
      "bytes32 fundLifecycleDigest",
      "uint256 maxTotalFeeWei",
      "uint48 validAfter",
      "uint48 validUntil"
    ]) {
      assert.equal(fields.has(field), true, field);
    }
    assert.equal(spec.intent.optionalFieldsAllowed, false);
    assert.equal(spec.intent.unusedFieldsZeroFilled, false);
    assert.equal(spec.intent.headerRules.fundLifecycleDigestRequiredForAllActions, true);
    assert.equal(spec.intent.headerRules.nonAssetLifecycleMustCommitNoAssetEffect, true);
    assert.equal(
      spec.intent.headerRules.ordinaryAndMaintenanceMaximumLifetimeSeconds,
      600
    );
    assert.equal(
      spec.intent.headerRules.recoverySubmissionMaximumLifetimeSeconds,
      3600
    );
    assert.equal(spec.intent.applicationContext.fieldsInOrder.length, 5);
    assert.equal(spec.intent.fundLifecycle.fieldsInOrder.length, 11);
    assert.equal(
      spec.feeRule.requiredComparison,
      "feeUpperBoundWei <= intentCore.maxTotalFeeWei"
    );
    assert.equal(spec.feeRule.integerArithmeticOnly, true);
  });

  it("assigns unique action IDs, exact nonce lanes, and allowed purposes", function () {
    const ids = spec.actionTypes.map((action) => action.id);
    const names = spec.actionTypes.map((action) => action.name);
    assert.equal(new Set(ids).size, ids.length);
    assert.equal(new Set(names).size, names.length);
    assert.deepEqual(ids, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    for (const action of spec.actionTypes) {
      assert.ok([0, 1, 2].includes(action.nonceKey), action.name);
      assert.ok(action.payload.length > 0, action.name);
      assert.ok(action.allowedPurposes.length > 0, action.name);
      for (const purpose of action.allowedPurposes) {
        assert.equal(
          spec.canonicalPurposes.values.includes(purpose),
          true,
          `${action.name}:${purpose}`
        );
      }
    }
    assert.equal(
      spec.actionTypes.find((action) => action.name === "VALIDATOR_ROTATION").nonceKey,
      1
    );
    for (const action of spec.actionTypes.filter(
      (candidate) => candidate.name.startsWith("RECOVERY")
    )) {
      assert.equal(action.nonceKey, 2, action.name);
      assert.equal(action.valueMovement, false, action.name);
    }
  });

  it("closes V2.0 capabilities instead of retaining dormant generic behavior", function () {
    const policy = spec.capabilityPolicy;
    for (const included of [
      "typed native transfer",
      "typed ERC-20 transfer with exact balance-delta checks",
      "typed ERC-721 safe transfer",
      "typed ERC-1155 safe transfer",
      "typed EntryPoint deposit withdrawal",
      "delayed threshold recovery"
    ]) {
      assert.equal(policy.includedInV2_0.includes(included), true, included);
    }
    for (const deferred of [
      "ERC-20 approvals and allowance changes",
      "contract capability adapters",
      "arbitrary contract calls",
      "batching",
      "paymasters",
      "session keys"
    ]) {
      assert.equal(policy.deferredToNewAccountVersion.includes(deferred), true);
    }
    for (const prohibited of [
      "generic execute",
      "delegatecall",
      "proxy upgrade",
      "public sweep",
      "Account 1 privilege",
      "Account 2 privilege",
      "tx.origin authorization"
    ]) {
      assert.equal(policy.prohibited.includes(prohibited), true, prohibited);
    }
  });

  it("defines validator creation, rotation, revocation, and compromise response", function () {
    const lifecycle = spec.validatorLifecycle;
    assert.equal(lifecycle.activeExecutionValidators, 1);
    assert.equal(
      lifecycle.productionMeaningfulAssetsRequireStrongerValidatorComposition,
      true
    );
    assert.equal(lifecycle.creation.randomKeyGeneratedInsideDeviceVault, true);
    assert.equal(lifecycle.creation.derivedFromIdentitySecret, false);
    assert.equal(lifecycle.creation.initialEpoch, 1);
    assert.equal(lifecycle.rotation.nonceKey, 1);
    assert.equal(lifecycle.rotation.proposedEpochMustEqualCurrentPlusOne, true);
    assert.equal(lifecycle.rotation.blockedWhileRecoveryActive, true);
    assert.equal(lifecycle.rotation.transfersValue, false);
    assert.equal(lifecycle.revocation.zeroValidatorStateAllowed, false);
    assert.ok(lifecycle.compromiseResponse.length >= 4);
  });

  it("defines exact two-of-three delayed recovery and safe expiry cleanup", function () {
    const recovery = spec.recovery;
    assert.equal(recovery.factorCount, 3);
    assert.equal(recovery.threshold, 2);
    assert.equal(recovery.delaySeconds, 172800);
    assert.equal(recovery.expirySecondsAfterRequest, 604800);
    assert.equal(recovery.factorRequirements.sortedStrictlyIncreasingAddresses, true);
    assert.equal(recovery.factorRequirements.executionValidatorExcluded, true);
    assert.equal(recovery.request.twoOfThreeFactorSignaturesRequired, true);
    assert.equal(
      recovery.request.freezesOrdinaryAndMaintenanceLanesImmediately,
      true
    );
    assert.equal(recovery.cancellation.currentValidatorAloneAccepted, false);
    assert.deepEqual(recovery.cancellation.acceptedAuthorizationCombinations, [
      "two of three recovery factors",
      "current validator plus one recovery factor"
    ]);
    assert.equal(recovery.completion.permissionlessDirectCall, true);
    assert.equal(recovery.completion.externalCalls, false);
    assert.equal(recovery.completion.transfersValue, false);
    assert.equal(recovery.expiryCleanup.permissionlessDirectCall, true);
    assert.equal(recovery.expiryCleanup.installsProposedValidator, false);
    assert.equal(recovery.expiryCleanup.unfreezesAccount, true);
    assert.equal(recovery.postRecoveryAssetMovementRequiresFreshOrdinaryIntent, true);
  });

  it("separates nonce namespaces and binds replay to both epochs", function () {
    assert.deepEqual(spec.nonceModel.lanes, {
      "0": "ordinary action intents",
      "1": "validator maintenance",
      "2": "recovery and recovery-configuration maintenance"
    });
    assert.equal(spec.nonceModel.exactKeyRequiredPerAction, true);
    assert.equal(spec.nonceModel.sequenceReadFromEntryPoint, true);
    assert.equal(spec.nonceModel.actionIdMappingStoredOnchain, false);
    assert.equal(spec.nonceModel.validatorEpochBound, true);
    assert.equal(spec.nonceModel.recoveryEpochBound, true);
    assert.deepEqual(spec.nonceModel.recoveryFreezeBlocksKeys, [0, 1]);
  });

  it("defines a fixed non-upgradeable storage model without capability mappings", function () {
    const storage = spec.storageModel;
    assert.equal(storage.nonUpgradeable, true);
    for (const immutable of [
      "EntryPoint",
      "deployment chain ID",
      "owner commitment",
      "factory binding",
      "account version ID",
      "security model ID",
      "recovery delay",
      "recovery expiry"
    ]) {
      assert.equal(storage.immutable.includes(immutable), true, immutable);
    }
    assert.equal(storage.mappingsAllowed, false);
    assert.equal(storage.arbitraryCapabilityStorageAllowed, false);
    assert.equal(storage.zeroOrReservedFieldsMustRemainZero, true);
    assert.ok(storage.mutableLayoutInOrder.length >= 12);
  });

  it("specifies a narrow conceptual interface and prohibited ABI names", function () {
    const surface = spec.conceptualInterface;
    for (const required of [
      "transferNative",
      "transferERC20",
      "safeTransferERC721",
      "safeTransferERC1155",
      "withdrawEntryPointDeposit",
      "rotateValidator",
      "requestRecovery",
      "cancelRecovery"
    ]) {
      assert.equal(surface.entryPointOnly.includes(required), true, required);
    }
    for (const transition of [
      "completeRecovery",
      "completeRecoveryConfigRotation",
      "expireRecovery",
      "expireRecoveryConfigRotation"
    ]) {
      assert.equal(
        surface.permissionlessStateTransitions.includes(transition),
        true,
        transition
      );
    }
    for (const prohibited of [
      "execute",
      "executeBatch",
      "delegate",
      "upgradeTo",
      "sweep",
      "approveToken",
      "setOwner",
      "setAdmin"
    ]) {
      assert.equal(surface.prohibitedNames.includes(prohibited), true);
    }
  });

  it("defines exact token, external-call, and fund-lifecycle behavior", function () {
    const rules = spec.executionRules;
    assert.equal(rules.nativeTransferUsesEmptyCalldata, true);
    assert.equal(rules.erc20RequiresExactSenderDecreaseAndRecipientIncrease, true);
    assert.equal(rules.feeOnTransferTokensRejected, true);
    assert.equal(rules.erc20FalseOrMalformedReturnRejected, true);
    assert.equal(rules.erc721UsesSafeTransferFrom, true);
    assert.equal(rules.erc1155UsesSafeTransferFrom, true);
    assert.equal(rules.receiverDataHashMustMatchCalldata, true);
    assert.equal(rules.executionLockRequiredAroundExternalCalls, true);
    assert.equal(spec.fundLifecycle.releasePathRequiredBeforeFunding, true);
    assert.equal(spec.fundLifecycle.fullLocalLifecycleRequired, true);
    assert.equal(spec.fundLifecycle.forkLifecycleRequiredOrTechnicalReason, true);
    assert.equal(spec.fundLifecycle.separateReleaseApprovalRequired, true);
  });

  it("selects version migration while preserving identity and rejecting V1 recovery", function () {
    const migration = spec.migration;
    assert.equal(migration.proxyUpgrade, false);
    assert.equal(migration.newImplementationFactoryAndAddressPerVersion, true);
    assert.equal(migration.ownerCommitmentContinuity, true);
    assert.equal(migration.V1AssetMigrationPossible, false);
    assert.equal(migration.futureAssetMigrationUsesTypedOrdinaryIntents, true);
    assert.equal(
      migration.canonicalAdapterSwitchAfterOldAndNewStateVerification,
      true
    );
  });

  it("documents the complete attacker set, trusted presentation, and residual risks", function () {
    const threatModel = read("docs/security/O30_V2_FORMAL_THREAT_MODEL.md");
    for (const required of [
      "Stolen locked device",
      "Stolen unlocked device",
      "Validator key compromise",
      "Malicious application",
      "Malicious bundler",
      "Malicious RPC",
      "Two recovery factors compromised",
      "User deception",
      "Chain replay",
      "Stranded funds",
      "Denial of service"
    ]) {
      assert.match(threatModel, new RegExp(required, "i"), required);
    }
    assert.match(threatModel, /Trusted Presentation Requirements/);
    assert.match(threatModel, /Security Invariants/);
    assert.match(threatModel, /Unresolved Production Risks/);
  });

  it("documents the implementation-ready account, capability, and acceptance surfaces", function () {
    const phaseDoc = read(
      "docs/reference/O30_V2_ACCOUNT_SPECIFICATION_AND_THREAT_MODEL_REFINEMENT.md"
    );
    const interfaceDoc = read(
      "docs/reference/O30_V2_ACCOUNT_INTERFACE_SPECIFICATION.md"
    );
    const matrix = read("docs/reference/O30_V2_CAPABILITY_MATRIX.md");
    assert.match(phaseDoc, /Canonical Intent Model/);
    assert.match(phaseDoc, /Authorization Flow/);
    assert.match(phaseDoc, /Validator Lifecycle/);
    assert.match(phaseDoc, /Recovery Lifecycle/);
    assert.match(phaseDoc, /Nonce Model/);
    assert.match(phaseDoc, /Storage And Upgrade Policy/);
    assert.match(phaseDoc, /Migration/);
    assert.match(phaseDoc, /Implementation Acceptance/);
    assert.match(interfaceDoc, /EntryPoint-Only Action Surface/);
    assert.match(interfaceDoc, /Signature Envelopes/);
    assert.match(interfaceDoc, /Prohibited Surface/);
    assert.match(matrix, /Capability Closure/);
    assert.ok(spec.implementationAcceptanceTests.length >= 15);
  });

  it("promotes the current narrow V2 model through every canonical entry point", function () {
    for (const rel of [
      "README.md",
      "ARCHITECTURE.md",
      "STATUS.md",
      "docs/PHILCORE_CORE_BOUNDARY.md",
      "docs/CANONICAL_DOCS.md"
    ]) {
      const text = read(rel);
      assert.match(text, /PhilCoreV2MinimalAccountV2/);
      assert.match(text, /exact 2-of-3/i);
      assert.match(
        text,
        /validator (?:is not a\s+recovery factor|never counts toward the recovery threshold)/i
      );
      assert.match(text, /cannot\s+veto/i);
      assert.match(text, /independent(?:ly)?\s+(?:custodied|custody)/i);
      assert.match(text, /generic(?: wallet)?\s+execution/i);
      assert.match(text, /O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_REPORT\.md/);
    }
  });

  it("contains no secret material, executable authority, Solidity, or public mutation", function () {
    ensureNoSecrets(spec);
    for (const [key, value] of Object.entries(spec.securityBoundary)) {
      assert.equal(value, false, key);
    }
    assert.doesNotMatch(JSON.stringify(spec), /https?:\/\//);
    assert.equal(spec.securityBoundary.solidityImplemented, false);
    assert.equal(spec.securityBoundary.userOperationCreated, false);
    assert.equal(spec.securityBoundary.publicMutationOccurred, false);
  });
});
