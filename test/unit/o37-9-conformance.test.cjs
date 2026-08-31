const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const MODEL_PATH = path.join(
  ROOT,
  "config/solidity/O37_9_SIZE_BUDGET_MODEL.json"
);
const MODEL = JSON.parse(fs.readFileSync(MODEL_PATH));

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function sha256(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

describe("O.37.9 compression and verifier-binding conformance", function () {
  it("records the exact baseline and preserves frozen sources", function () {
    assert.equal(
      MODEL.sourceHeadAtPhaseStart,
      "73eecd93e98c4b9c954e034aaae5fe15473b7ce0"
    );
    const bindings = [
      [
        "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol",
        "v1AccountSourceSha256"
      ],
      [
        "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol",
        "v1FactorySourceSha256"
      ],
      ["docs/reference/O37_4_ABI_FREEZE.md", "o37_4AbiFreezeSha256"],
      [
        "docs/reference/O37_4_AUTHORITY_TRANSPORT_SPECIFICATION.md",
        "o37_4AuthorityTransportSha256"
      ],
      [
        "docs/reference/O37_6_MINIMAL_ACCOUNT_ARCHITECTURE.md",
        "o37_6MinimalArchitectureSha256"
      ],
      [
        "docs/reference/O37_6_FACTORY_SIZE_STRATEGY.md",
        "o37_6FactoryStrategySha256"
      ],
      [
        "config/solidity/O37_7_STATIC_VERIFIER_IMPLEMENTATION_EVIDENCE.json",
        "o37_7VerifierEvidenceSha256"
      ],
      [
        "config/solidity/O37_8_MINIMAL_ACCOUNT_IMPLEMENTATION_CONFLICT_EVIDENCE.json",
        "o37_8ConflictEvidenceSha256"
      ],
      [
        "docs/reference/O37_8_MINIMAL_ACCOUNT_IMPLEMENTATION_CONFLICT_REVIEW.md",
        "o37_8ConflictReviewSha256"
      ]
    ];
    for (const [file, field] of bindings) {
      assert.equal(sha256(file), MODEL.baseline[field], file);
    }
    assert.notEqual(
      sha256(
        "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol"
      ),
      MODEL.baseline.o37_7VerifierSourceSha256,
      "O.39 must supersede, not silently masquerade as, the O.37.7 verifier"
    );
    assert.equal(
      JSON.parse(read(
        "config/solidity/O39_CONSUMER_RECOVERY_IMPLEMENTATION_EVIDENCE.json"
      )).phase,
      "O.39"
    );
  });

  it("reconciles current attribution and minimum reductions exactly", function () {
    const attributed = MODEL.forensicAttribution.categories.reduce(
      (sum, category) => sum + category.bytes,
      0
    );
    assert.equal(attributed, MODEL.forensicAttribution.sumBytes);
    assert.equal(attributed, MODEL.o37_8BestCandidate.runtimeBytes);
    assert.equal(
      MODEL.o37_8BestCandidate.runtimeBytes
        - MODEL.hardBudgets.runtimeBytes,
      MODEL.o37_8BestCandidate.minimumRuntimeReductionBytes
    );
    assert.equal(
      MODEL.o37_8BestCandidate.creationBytes
        - MODEL.hardBudgets.creationBytes,
      MODEL.o37_8BestCandidate.minimumCreationReductionBytes
    );
  });

  it("allocates a projected result below both hard budgets", function () {
    const gross = MODEL.plannedRuntimeReduction.items.reduce(
      (sum, item) => sum + item.plannedReductionBytes,
      0
    );
    assert.equal(gross, MODEL.plannedRuntimeReduction.grossReductionBytes);
    assert.equal(
      gross - MODEL.plannedRuntimeReduction.factoryBindingLookupOverheadBytes,
      MODEL.plannedRuntimeReduction.netReductionBytes
    );
    assert.equal(
      MODEL.o37_8BestCandidate.runtimeBytes
        - MODEL.plannedRuntimeReduction.netReductionBytes,
      MODEL.projectedAccount.runtimeBytes
    );
    assert.equal(
      MODEL.hardBudgets.runtimeBytes - MODEL.projectedAccount.runtimeBytes,
      MODEL.projectedAccount.runtimeReserveBytes
    );
    assert.equal(
      MODEL.hardBudgets.creationBytes - MODEL.projectedAccount.creationBytes,
      MODEL.projectedAccount.creationReserveBytes
    );
    assert.ok(MODEL.projectedAccount.runtimeReserveBytes > 0);
    assert.ok(MODEL.projectedAccount.creationReserveBytes > 0);
    assert.equal(MODEL.projectedAccount.classification.includes("NOT"), true);
  });

  it("fixes one factory-owned verifier binding with no account authority", function () {
    assert.equal(MODEL.verifierBinding.source, "VERSION_SPECIFIC_FACTORY_IMMUTABLES");
    assert.equal(MODEL.verifierBinding.factoryGetter, "verifierBinding()");
    assert.equal(MODEL.verifierBinding.factoryGetterSelector, "0xa7d16353");
    assert.equal(MODEL.verifierBinding.accountConstructorFieldCount, 20);
    assert.equal(MODEL.verifierBinding.accountVerifierConstructorArguments, 0);
    assert.equal(MODEL.verifierBinding.accountVerifierStorageSlots, 0);
    assert.equal(MODEL.verifierBinding.lookupOpcode, "STATICCALL");
    assert.equal(MODEL.verifierBinding.verifierCallOpcode, "STATICCALL");
    assert.equal(MODEL.verifierBinding.exactFactoryReturnBytes, 64);
    assert.equal(MODEL.verifierBinding.accountChecksExtCodeHash, true);
    assert.equal(MODEL.verifierBinding.mutableRegistry, false);
    assert.equal(MODEL.verifierBinding.callerSelectedVerifier, false);

    const bindingDoc = read(
      "docs/reference/O37_9_VERIFIER_BINDING_RESOLUTION.md"
    );
    for (const forbidden of [
      "no retry",
      "no verifier setter",
      "No helper deployer",
      "msg.sender == initialization.factoryBinding"
    ]) {
      assert.ok(bindingDoc.includes(forbidden), forbidden);
    }
  });

  it("freezes compact storage without nonce, admin, upgrade, or verifier slots", function () {
    assert.equal(MODEL.proposedAccount.mutableStorageHighestSlot, 14);
    for (const field of [
      "duplicateNonceStorage",
      "replayMapping",
      "admin",
      "proxy",
      "mutableVerifier",
      "sessionKeys",
      "modules",
      "paymasters"
    ]) {
      assert.equal(MODEL.proposedAccount[field], false, field);
    }
    const storageDoc = read("docs/reference/O37_9_STORAGE_BOUNDARY.md");
    for (let slot = 0; slot <= 14; slot += 1) {
      assert.ok(storageDoc.includes(`| \`${slot}\` |`), `slot ${slot}`);
    }
    for (const required of [
      "validator commitment",
      "recovery-configuration hash",
      "EntryPoint remains the sole nonce-sequence owner"
    ]) {
      assert.ok(storageDoc.includes(required), required);
    }
  });

  it("freezes exactly 15 functions and the minimal action set", function () {
    assert.equal(MODEL.proposedAccount.externalFunctionCount, 15);
    assert.deepEqual(
      MODEL.proposedAccount.supportedActions,
      [1, 2, 6, 7, 8, 9, 10, 11]
    );
    assert.deepEqual(MODEL.proposedAccount.validRecoveryBitmaps, [3, 5, 6]);
    assert.equal(MODEL.proposedAccount.recoveryThreshold, 2);
    assert.equal(MODEL.proposedAccount.entryPointOwnsNonceSequences, true);

    const abiDoc = read("docs/reference/O37_9_ABI_REDUCTION_PLAN.md");
    const selectorRows = abiDoc.match(/\| `0x[0-9a-f]{8}` \|/g) || [];
    assert.equal(selectorRows.length, 14);
    assert.ok(abiDoc.includes("0x19822f7c"));
    assert.ok(abiDoc.includes("exactly 15 functions"));
    for (const forbidden of [
      "executeBatch",
      "delegatecall",
      "setVerifier",
      "transferERC20",
      "safeTransferERC721",
      "safeTransferERC1155"
    ]) {
      assert.ok(abiDoc.includes(forbidden), forbidden);
    }
  });

  it("retains no O.37.9 Solidity, bytecode, factory, or deployment artifact", function () {
    for (const [field, value] of Object.entries(MODEL.retainedState)) {
      assert.equal(value, false, field);
    }
    for (const [field, value] of Object.entries(MODEL.phaseBoundary)) {
      assert.equal(value, false, field);
    }
    const tracked = require("node:child_process")
      .execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" })
      .trim()
      .split("\\n");
    assert.equal(
      tracked.some((file) =>
        file.endsWith(".sol") && file.toLowerCase().includes("o37_9")
      ),
      false
    );
    assert.equal(
      tracked.some((file) =>
        /(^|\/)(artifacts|cache)\/.*o37-9/i.test(file)
      ),
      false
    );
  });

  it("indexes every O.37.9 deliverable", function () {
    const index = read("docs/CANONICAL_DOCS.md");
    for (const file of [
      "O37_9_MINIMAL_ACCOUNT_COMPRESSION_REVIEW.md",
      "O37_9_VERIFIER_BINDING_RESOLUTION.md",
      "O37_9_STORAGE_BOUNDARY.md",
      "O37_9_ABI_REDUCTION_PLAN.md"
    ]) {
      assert.ok(index.includes(file), file);
    }
  });
});
