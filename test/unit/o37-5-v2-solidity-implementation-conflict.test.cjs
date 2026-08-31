const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const EVIDENCE_PATH =
  "config/solidity/O37_5_V2_IMPLEMENTATION_CONFLICT_EVIDENCE.json";
const REVIEW_PATH =
  "docs/reference/O37_5_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md";
const V1_ACCOUNT =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const V1_FACTORY =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function sha256(relativePath) {
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

describe("O.37.5 V2 Solidity implementation code-size conflict", function () {
  const evidence = readJson(EVIDENCE_PATH);

  it("records the exact fail-closed baseline and preserves V1", function () {
    assert.equal(evidence.phase, "O.37.5");
    assert.equal(
      evidence.sourceHeadAtPhaseStart,
      "910b5f6f3be1637d1b05ad04ae209e5f232ca3aa"
    );
    assert.equal(
      evidence.result,
      "STOPPED_FAIL_CLOSED_BEFORE_SOLIDITY_RETENTION"
    );
    assert.equal(sha256(V1_ACCOUNT), evidence.baseline.v1AccountSourceSha256);
    assert.equal(sha256(V1_FACTORY), evidence.baseline.v1FactorySourceSha256);
  });

  it("records the exact frozen toolchain used by the rejected compile", function () {
    assert.match(evidence.frozenBuild.solidity, /^0\.8\.27\+/);
    assert.equal(evidence.frozenBuild.evmVersion, "cancun");
    assert.equal(evidence.frozenBuild.optimizerEnabled, true);
    assert.equal(evidence.frozenBuild.optimizerRuns, 200);
    assert.equal(evidence.frozenBuild.viaIR, true);
    assert.equal(evidence.frozenBuild.openZeppelinContracts, "5.6.1");
    assert.equal(evidence.frozenBuild.accountAbstractionContracts, "0.7.0");
  });

  it("fails both frozen account and factory against EIP-170", function () {
    const limit = evidence.eip170.maximumRuntimeBytes;
    const attempt = evidence.eip170.frozenDirectOpenZeppelinAttempt;
    assert.equal(limit, 24576);
    assert.ok(attempt.accountRuntimeBytes > limit);
    assert.ok(attempt.factoryRuntimeBytes > limit);
    assert.equal(
      attempt.accountRuntimeBytes - limit,
      attempt.accountExcessBytes
    );
    assert.equal(
      attempt.factoryRuntimeBytes - limit,
      attempt.factoryExcessBytes
    );
    assert.equal(attempt.accepted, false);
  });

  it("rejects native P256 as both unfrozen and still oversized", function () {
    const attempt = evidence.eip170.rejectedNativeP256Exploration;
    assert.match(attempt.reason, /UNFROZEN_NATIVE_PRECOMPILE/);
    assert.ok(attempt.accountRuntimeBytes > 24576);
    assert.ok(attempt.factoryRuntimeBytes > 24576);
    assert.match(attempt.accountRuntimeKeccak256, /^0x[0-9a-f]{64}$/);
    assert.match(attempt.factoryRuntimeKeccak256, /^0x[0-9a-f]{64}$/);
    assert.equal(attempt.accepted, false);
  });

  it("retains no rejected implementation and allows only reviewed later V2 sources", function () {
    const v2Solidity = solidityFiles(path.join(ROOT, "contracts"))
      .filter((file) => /philcore.*v2/i.test(path.basename(file)));
    assert.deepEqual(
      v2Solidity.map((file) => path.relative(ROOT, file)).sort(),
      [
        "contracts/base/erc4337/v2/IPhilCoreV2MinimalAccountV2.sol",
        "contracts/base/erc4337/v2/IPhilCoreV2StaticAuthorityVerifier.sol",
        "contracts/base/erc4337/v2/PhilCoreV2ConfirmationTargetV1.sol",
        "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol",
        "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol",
        "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol",
        "contracts/test/PhilCoreV2ConfirmationTargetTestMocks.sol",
        "contracts/test/PhilCoreV2MinimalAccountTestMocks.sol"
      ]
    );
    for (const value of Object.values(evidence.retainedState)) {
      assert.equal(value, false);
    }
  });

  it("documents every architecture-changing alternative as blocked", function () {
    for (const alternative of [
      "external_authority_verifier",
      "linked_delegatecall_library",
      "proxy_or_minimal_proxy",
      "reduced_or_changed_frozen_abi",
      "alternate_factory_creation_path"
    ]) {
      assert.equal(evidence.blockedAlternatives.includes(alternative), true);
    }
    const review = read(REVIEW_PATH);
    assert.match(review, /separately approved architecture phase/);
    assert.match(review, /No contract was deployed/);
  });

  it("records the absolute zero-mutation stop boundary", function () {
    assert.equal(evidence.publicMutationCount, 0);
    for (const [field, value] of Object.entries(evidence.securityBoundary)) {
      assert.equal(value, false, field);
    }
  });

  it("indexes the O.37.5 review as canonical evidence", function () {
    assert.match(
      read("docs/CANONICAL_DOCS.md"),
      /O37_5_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW\.md/
    );
  });
});
