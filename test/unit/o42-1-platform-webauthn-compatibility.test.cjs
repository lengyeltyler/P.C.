const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  OUTPUT,
  buildEvidence,
  serialized
} = require(
  "../../scripts/cryptography/generate-o42-1-platform-webauthn-evidence.cjs"
);

const ROOT = path.resolve(__dirname, "../..");

function sha256(relative) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relative)))
    .digest("hex");
}

describe("O.42.1 platform WebAuthn compatibility", function () {
  it("records the runtime fix and exact remaining provisioning blocker", function () {
    const evidence = buildEvidence();
    assert.equal(evidence.rootCause.priorElectron, "39.8.10");
    assert.equal(evidence.rootCause.selectedElectron, "41.10.3");
    assert.equal(evidence.rootCause.configureBeforeReady, true);
    assert.equal(evidence.rootCause.userDenialOccurred, false);
    assert.equal(
      evidence.rootCause.remainingBlocker,
      "EXACT_DEVELOPER_ID_PROVISIONING_PROFILE_NOT_INSTALLED"
    );
  });

  it("keeps all recovery and iPhone policies fail closed", function () {
    const evidence = buildEvidence();
    assert.equal(evidence.preflightV3.primaryMacRole0, "BLOCKED");
    assert.equal(evidence.preflightV3.iphoneRole1, "BLOCKED");
    assert.equal(evidence.preflightV3.completeStandardCeremony, "BLOCKED");
    assert.equal(evidence.iphone.requiredBackupFlags.backupEligible, false);
    assert.equal(evidence.iphone.requiredBackupFlags.backupState, false);
    assert.equal(evidence.ceremony.productionRole0Created, false);
  });

  it("preserves the frozen Solidity package", function () {
    const evidence = buildEvidence();
    assert.equal(
      sha256("contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol"),
      evidence.frozenHashes.v1AccountSourceSha256
    );
    assert.equal(
      sha256("contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol"),
      evidence.frozenHashes.v1FactorySourceSha256
    );
    assert.equal(
      evidence.frozenHashes.v2RuntimeKeccak256.verifier,
      "0x665910b9989f3b83c3f025314fb127755d5abfc46e66ee386fbcbbfefc864dd7"
    );
    assert.equal(
      evidence.frozenHashes.v2RuntimeKeccak256.account,
      "0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519"
    );
    assert.equal(
      evidence.frozenHashes.v2RuntimeKeccak256.factory,
      "0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95"
    );
  });

  it("keeps deterministic evidence secret-free", function () {
    assert.equal(fs.readFileSync(OUTPUT, "utf8"), serialized());
    assert.doesNotMatch(serialized(), /BEGIN (?:EC |RSA )?PRIVATE KEY/u);
    assert.doesNotMatch(
      serialized(),
      /PHIL39-V1-(?:[A-Z2-7]{4}-){8,}[A-Z2-7]{4,}/u
    );
    assert.doesNotMatch(
      serialized(),
      /"(?:rawCredentialId|privateKey|pairingSecret)"\s*:/u
    );
    assert.equal(buildEvidence().security.productionSecretCommitted, false);
  });

  it("preserves the zero-public-mutation boundary", function () {
    const evidence = buildEvidence();
    assert.equal(evidence.publicMutationCount, 0);
    assert.ok(
      Object.values(evidence.stopBoundary).every((value) => value === false)
    );
  });
});
