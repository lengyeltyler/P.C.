const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const EVIDENCE_PATH = path.join(
  ROOT,
  "config/solidity/O37_8_MINIMAL_ACCOUNT_IMPLEMENTATION_CONFLICT_EVIDENCE.json"
);
const EVIDENCE = JSON.parse(fs.readFileSync(EVIDENCE_PATH));

function sha256(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

describe("O.37.8 minimal-account implementation conflict", function () {
  it("records the exact baseline and preserves V1", function () {
    assert.equal(
      EVIDENCE.sourceHeadAtPhaseStart,
      "21ca442c881198351b111c5f146e0d20cb1cef07"
    );
    assert.equal(
      sha256("contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol"),
      EVIDENCE.baseline.v1AccountSourceSha256
    );
    assert.equal(
      sha256(
        "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol"
      ),
      EVIDENCE.baseline.v1FactorySourceSha256
    );
  });

  it("binds the unchanged O.37.4, O.37.6, and O.37.7 evidence", function () {
    const bindings = [
      ["docs/reference/O37_4_ABI_FREEZE.md", "o37_4AbiFreezeSha256"],
      [
        "docs/reference/O37_4_AUTHORITY_TRANSPORT_SPECIFICATION.md",
        "o37_4AuthorityTransportSha256"
      ],
      [
        "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json",
        "o37_4FixtureSha256"
      ],
      [
        "config/solidity/O37_6_V2_CODE_SIZE_ARCHITECTURE.json",
        "o37_6ArchitectureEvidenceSha256"
      ],
      [
        "config/solidity/O37_7_STATIC_VERIFIER_IMPLEMENTATION_EVIDENCE.json",
        "o37_7VerifierEvidenceSha256"
      ]
    ];
    for (const [file, field] of bindings) {
      assert.equal(sha256(file), EVIDENCE.baseline[field], file);
    }
  });

  it("fails both frozen account size gates", function () {
    const best = EVIDENCE.measuredCandidates.find(
      (candidate) => candidate.name === "BEST_SECURITY_PRESERVING_DEDUPLICATION"
    );
    assert.ok(best.runtimeBytes > EVIDENCE.sizeGate.accountRuntimeMaximumBytes);
    assert.ok(best.creationBytes > EVIDENCE.sizeGate.accountCreationMaximumBytes);
    assert.equal(
      best.runtimeBytes - EVIDENCE.sizeGate.accountRuntimeMaximumBytes,
      best.runtimeBudgetExcessBytes
    );
    assert.equal(
      best.creationBytes - EVIDENCE.sizeGate.accountCreationMaximumBytes,
      best.creationBudgetExcessBytes
    );
    assert.ok(best.runtimeBytes < EVIDENCE.sizeGate.eip170MaximumRuntimeBytes);
  });

  it("retains no partial account, factory, or deployment implementation", function () {
    for (const relativePath of [
      "contracts/base/erc4337/v2/IPhilCoreV2MinimalAccount.sol",
      "contracts/base/erc4337/v2/PhilCoreV2MinimalAccount.sol",
      "hardhat.o37-8.config.cjs"
    ]) {
      assert.equal(fs.existsSync(path.join(ROOT, relativePath)), false);
    }
    assert.equal(EVIDENCE.retainedState.v2AccountContract, false);
    assert.equal(EVIDENCE.retainedState.partialOversizedImplementation, false);
    assert.equal(EVIDENCE.retainedState.factoryContract, false);
    assert.equal(EVIDENCE.phaseBoundary.deploymentPerformed, false);
    assert.equal(EVIDENCE.phaseBoundary.blockchainInteractionPerformed, false);
    assert.equal(EVIDENCE.phaseBoundary.fundsMoved, false);
    assert.equal(EVIDENCE.phaseBoundary.signatureCreated, false);
    assert.equal(EVIDENCE.phaseBoundary.userOperationCreated, false);
    assert.equal(EVIDENCE.phaseBoundary.userOperationSubmitted, false);
    assert.equal(EVIDENCE.publicMutationCount, 0);
  });

  it("records the unresolved verifier-binding architecture discrepancy", function () {
    assert.equal(EVIDENCE.architectureDiscrepancy.present, true);
    assert.equal(
      EVIDENCE.architectureDiscrepancy.resolution,
      "NO_ARCHITECTURE_CHANGE_RETAINED"
    );
    assert.equal(EVIDENCE.architectureDiscrepancy.securityEffect, "FAIL_CLOSED");
  });
});
