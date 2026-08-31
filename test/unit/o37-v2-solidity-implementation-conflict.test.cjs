const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const REVIEW_PATH =
  "docs/reference/O37_V2_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md";
const HARDWARE_SPEC_PATH =
  "docs/reference/O36_1_HARDWARE_RECOVERY_SPECIFICATION.md";
const V1_ACCOUNT_PATH =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const V1_FACTORY_PATH =
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

function frozenStruct(source, name) {
  const match = source.match(new RegExp(`${name} \\{([\\s\\S]*?)\\n\\}`));
  assert.ok(match, `missing frozen ${name}`);
  return match[1];
}

function frozenType(source, name) {
  const match = source.match(new RegExp(`${name}\\(([\\s\\S]*?)\\n\\)`));
  assert.ok(match, `missing frozen ${name}`);
  return match[1];
}

describe("O.37 V2 Solidity implementation conflict gate", function () {
  const review = read(REVIEW_PATH);
  const hardwareSpec = read(HARDWARE_SPEC_PATH);

  it("records the exact fail-closed baseline and zero mutation result", function () {
    assert.match(review, /STOPPED_FAIL_CLOSED_BEFORE_SOLIDITY/);
    assert.match(
      review,
      /55babe3bd1da67c89c4eb7606ca1c8507acd0a10/
    );
    assert.match(review, /Public mutations are zero/);
    assert.match(review, /No RPC or live-chain interaction occurred/);
  });

  it("detects committed descriptor fields missing from both evidence ABIs", function () {
    const commitment = frozenType(hardwareSpec, "PhilCoreV2RecoveryFactor");
    const webAuthnEvidence =
      frozenStruct(hardwareSpec, "WebAuthnFactorEvidenceV1");
    const secp256k1Evidence =
      frozenStruct(hardwareSpec, "Secp256k1FactorEvidenceV1");

    assert.match(commitment, /bytes32 originPolicyHash/);
    assert.match(commitment, /uint64 credentialGeneration/);
    assert.doesNotMatch(webAuthnEvidence, /originPolicyHash/);
    assert.doesNotMatch(webAuthnEvidence, /credentialGeneration/);
    assert.doesNotMatch(secp256k1Evidence, /credentialGeneration/);
    assert.match(
      hardwareSpec,
      /reconstructs each public-material hash and factor commitment/
    );
    assert.match(hardwareSpec, /compares each commitment with the stored role commitment/);
  });

  it("confirms accepted vectors cannot supply valid Solidity signatures", function () {
    const o32 = readJson(
      "config/cryptography/O32_V2_CRYPTOGRAPHIC_TEST_VECTORS.json"
    );
    const o33 = readJson(
      "config/cryptography/O33_V2_VALIDATOR_AUTHORIZATION_TEST_VECTORS.json"
    );

    assert.equal(o32.securityBoundary.signatureCreated, false);
    assert.equal(o32.securityBoundary.userOperationCreated, false);
    assert.equal(o33.securityBoundary.signatureCreated, false);
    assert.equal(o33.securityBoundary.signatureBytesStored, false);
    assert.equal(o33.securityBoundary.userOperationCreated, false);
    assert.equal(
      o33.validAuthorization.authorizationPackage.authority.evidence
        .signatureBytesPresentToEngine,
      false
    );
  });

  it("preserves the frozen V1 account and factory", function () {
    assert.equal(
      sha256(V1_ACCOUNT_PATH),
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a"
    );
    assert.equal(
      sha256(V1_FACTORY_PATH),
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    );
  });

  it("retains no V2 account/factory and recognizes the later authorized verifier toolchain", function () {
    for (const sourcePath of solidityFiles(path.join(ROOT, "contracts"))) {
      const source = fs.readFileSync(sourcePath, "utf8");
      assert.doesNotMatch(
        source,
        /contract\s+PhilCoreV2(?:Account|AccountFactory)\b/
      );
    }

    const packageJson = readJson("package.json");
    const packageLock = readJson("package-lock.json");
    assert.equal(
      packageJson.devDependencies["@openzeppelin/contracts"],
      "5.6.1"
    );
    assert.equal(
      packageJson.devDependencies["@account-abstraction/contracts"],
      "0.7.0"
    );
    assert.equal(
      packageJson.devDependencies.solc,
      "0.8.27"
    );
    assert.equal(
      packageLock.packages["node_modules/@openzeppelin/contracts"].version,
      "5.6.1"
    );
    assert.equal(
      packageLock.packages["node_modules/@account-abstraction/contracts"]
        .version,
      "0.7.0"
    );
  });

  it("indexes the conflict as canonical current evidence", function () {
    const canonical = read("docs/CANONICAL_DOCS.md");
    const model = read("docs/reference/LOCAL_PROOF_GATED_ACCOUNT_MODEL.md");
    assert.equal(
      canonical.includes("O37_V2_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md"),
      true
    );
    assert.equal(
      model.includes("O37_V2_SOLIDITY_IMPLEMENTATION_CONFLICT_REVIEW.md"),
      true
    );
  });
});
