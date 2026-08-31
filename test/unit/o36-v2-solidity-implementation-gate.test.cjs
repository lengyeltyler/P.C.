const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const REVIEW_PATH =
  "docs/reference/O36_V2_SOLIDITY_IMPLEMENTATION_GATE_REVIEW.md";
const V1_ACCOUNT_PATH =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const V1_FACTORY_PATH =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
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

describe("O.36 V2 Solidity implementation gate", function () {
  const review = read(REVIEW_PATH);

  it("records the fail-closed phase result and exact starting baseline", function () {
    assert.match(review, /STOPPED_FAIL_CLOSED_BEFORE_SOLIDITY/);
    assert.match(
      review,
      /7fed6ee96805fd8adf0453ab0067fc23f6b2450d/
    );
    assert.match(review, /Public mutations are zero/);
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

  it("keeps every unresolved security gate explicit", function () {
    for (const gate of [
      "Recovery-factor verifier gate",
      "Production authority-verifier gate",
      "Identity-binding commitment gate",
      "Recovery-cancellation representation mismatch",
      "ABI and verifier-dependency freeze"
    ]) {
      assert.equal(review.includes(gate), true, gate);
    }
  });

  it("does not permit a placeholder V2 account or factory", function () {
    for (const sourcePath of solidityFiles(path.join(ROOT, "contracts"))) {
      const source = fs.readFileSync(sourcePath, "utf8");
      assert.doesNotMatch(
        source,
        /contract\s+PhilCoreV2(?:Account|AccountFactory)\b/
      );
    }
    assert.match(review, /No V2 account, V2 factory, mock substitute/);
    assert.match(review, /no signature was\s+produced/i);
    assert.match(review, /no UserOperation was created/i);
  });

  it("is indexed as canonical current evidence", function () {
    const canonical = read("docs/CANONICAL_DOCS.md");
    const model = read("docs/reference/LOCAL_PROOF_GATED_ACCOUNT_MODEL.md");
    assert.equal(
      canonical.includes("O36_V2_SOLIDITY_IMPLEMENTATION_GATE_REVIEW.md"),
      true
    );
    assert.equal(
      model.includes("O36_V2_SOLIDITY_IMPLEMENTATION_GATE_REVIEW.md"),
      true
    );
  });
});
