const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const FREEZE_PATH =
  "config/cryptography/O36_1_V2_SECURITY_INTERFACE_FREEZE.json";
const FIXTURE_PATH =
  "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json";
const REVIEW_PATH =
  "docs/reference/O37_3_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md";
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

describe("O.37.3 V2 Solidity implementation conflict gate", function () {
  const freeze = readJson(FREEZE_PATH);
  const fixtures = readJson(FIXTURE_PATH);
  const review = read(REVIEW_PATH);

  it("records the exact fail-closed baseline and preserves V1", function () {
    assert.match(review,
      /2d271b824ba22b234b65b7950de3c6c88b3033ea/);
    assert.match(review, /STOPPED_FAIL_CLOSED_BEFORE_SOLIDITY/);
    assert.match(review, /Public mutations are zero/);
    assert.equal(
      sha256(V1_ACCOUNT),
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a"
    );
    assert.equal(
      sha256(V1_FACTORY),
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    );
  });

  it("requires validator plus exact two factors for config rotation", function () {
    assert.equal(
      freeze.recovery.configRotationRequestAuthority,
      "CURRENT_VALIDATOR_AND_EXACT_TWO_CURRENT_RECOVERY_FACTORS"
    );
    assert.equal(freeze.recovery.threshold, 2);
    assert.equal(freeze.recovery.validatorCountsAsFactor, false);
    assert.equal(freeze.recovery.combinedValidatorOneFactorAccepted, false);
  });

  it("has separate validator and recovery envelopes but no combined envelope", function () {
    assert.equal(freeze.validatorEnvelope.exactBytes, 320);
    assert.deepEqual(freeze.validatorEnvelope.fields, [
      "uint8 envelopeVersion",
      "uint8 authorityKind",
      "uint8 verifierKind",
      "address validator",
      "bytes32 validatorKeyIdBinding",
      "uint64 validatorEpoch",
      "uint64 recoveryEpoch",
      "bytes32 r",
      "bytes32 s",
      "uint8 v"
    ]);
    assert.equal(Object.hasOwn(freeze, "combinedAuthorityEnvelope"), false);
    assert.equal(Object.hasOwn(freeze, "configRotationEnvelope"), false);
    assert.match(
      read("docs/reference/O37_1_RECOVERY_EVIDENCE_SPECIFICATION.md"),
      /RecoveryEvidenceContextV2 context\n  bytes firstFactorEvidence\n  bytes secondFactorEvidence/
    );
  });

  it("finds no accepted O.37.2 config-rotation authority fixture", function () {
    assert.equal(
      fixtures.recoveryAuthorizationFixtures.intent.header.actionType,
      8
    );
    assert.equal(
      Object.hasOwn(
        fixtures.recoveryAuthorizationFixtures,
        "recoveryConfigRotation"
      ),
      false
    );
    const serialized = JSON.stringify(fixtures);
    assert.equal(
      serialized.includes("combinedAuthorityEnvelope"),
      false
    );
    assert.equal(
      serialized.includes("configRotationValidatorSignature"),
      false
    );
  });

  it("records the fixture deployment/state integration mismatch", function () {
    assert.equal(
      fixtures.fixtureDomain.account,
      "0x00000000000000000000000000000000000F3702"
    );
    assert.equal(
      fixtures.fixtureDomain.entryPoint,
      "0x00000000000000000000000000000000000F4337"
    );
    assert.equal(
      fixtures.validAuthorizationFixture.intent.header.validatorEpoch,
      "3"
    );
    assert.equal(
      fixtures.validAuthorizationFixture.intent.header.recoveryEpoch,
      "2"
    );
    assert.match(
      read("docs/reference/O36_1_SOLIDITY_IMPLEMENTATION_FREEZE.md"),
      /validator epoch, exactly `1`/
    );
    assert.match(
      read("docs/reference/O36_1_SOLIDITY_IMPLEMENTATION_FREEZE.md"),
      /recovery epoch, exactly `1`/
    );
  });

  it("keeps EntryPoint nonce ownership and constructor-only commitments explicit", function () {
    assert.equal(freeze.storage.entryPointOwnsNonceSequences, true);
    assert.equal(freeze.storage.duplicateNonceMappingAllowed, false);
    assert.equal(freeze.abi.accountInitializationFieldCount, 20);
    assert.equal(freeze.abi.constructorOnlyInitialization, true);
  });

  it("recognizes the later authorized frozen compiler and verifier override", function () {
    const packageJson = readJson("package.json");
    const hardhat = read("hardhat.shared.cjs");
    assert.equal(
      packageJson.devDependencies["@openzeppelin/contracts"],
      "5.6.1"
    );
    assert.equal(
      packageJson.devDependencies["@account-abstraction/contracts"],
      "0.7.0"
    );
    assert.equal(packageJson.devDependencies.solc, "0.8.27");
    assert.match(hardhat, /FROZEN_O37_7_SOLC_VERSION = "0\.8\.27"/);
    assert.match(hardhat, /O37_7_VERIFIER_SOURCE/);
  });

  it("preserves the conflict boundary and allows only reviewed later V2 sources", function () {
    const v2 = solidityFiles(path.join(ROOT, "contracts"))
      .filter((file) => /philcore.*v2/i.test(path.basename(file)));
    assert.deepEqual(
      v2.map((file) => path.relative(ROOT, file)).sort(),
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
    for (const forbidden of [
      "combined validator and one factor",
      "validator-only config rotation",
      "storage injection is accepted",
      "temporary administrator"
    ]) {
      assert.equal(review.toLowerCase().includes(forbidden), false);
    }
  });

  it("indexes the fail-closed review as canonical evidence", function () {
    assert.match(
      read("docs/CANONICAL_DOCS.md"),
      /O\.37\.3 V2 Solidity Implementation Conflict Review/
    );
    assert.match(
      read("docs/reference/LOCAL_PROOF_GATED_ACCOUNT_MODEL.md"),
      /O\.37\.3 Combined-Authority Implementation Conflict/
    );
  });
});
