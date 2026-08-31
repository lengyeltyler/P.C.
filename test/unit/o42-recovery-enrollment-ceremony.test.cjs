const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  buildEvidence
} = require(
  "../../scripts/cryptography/generate-o42-recovery-enrollment-evidence.cjs"
);

const ROOT = path.resolve(__dirname, "../..");

function sha256(relative) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relative)))
    .digest("hex");
}

describe("O.42 real Standard recovery enrollment ceremony", function () {
  it("records the exact physical-device blocker and fails before Role 0", function () {
    const evidence = buildEvidence();
    assert.equal(evidence.readiness, "A_ENROLLMENT_CEREMONY_BLOCKED");
    assert.equal(evidence.livePhysicalPreflight.standardResult, "BLOCKED");
    assert.deepEqual(
      evidence.livePhysicalPreflight.blockerIds,
      ["platformAuthenticator"]
    );
    assert.equal(
      evidence.livePhysicalPreflight.userVerifyingPlatformAuthenticatorAvailable,
      false
    );
    assert.equal(evidence.ceremony.role0Created, false);
    assert.equal(evidence.ceremony.webAuthnCreationPromptShown, false);
  });

  it("proves that no partial production enrollment or initialization exists", function () {
    const evidence = buildEvidence();
    assert.equal(evidence.protectedLocalState.credentialRecordCountAfter, 0);
    assert.equal(evidence.protectedLocalState.offlinePublicMetadataCountAfter, 0);
    assert.equal(evidence.protectedLocalState.temporaryArtifactCountAfter, 0);
    assert.equal(evidence.ceremony.sessionCreated, false);
    assert.equal(evidence.ceremony.pairingSessionCreated, false);
    assert.equal(evidence.ceremony.offlineFactorGenerated, false);
    assert.equal(evidence.initialization.productionUserSaltGenerated, false);
    assert.equal(
      evidence.initialization.protectedInitializationPackageCreated,
      false
    );
    assert.equal(
      evidence.initialization.publicInitializationManifestCreated,
      false
    );
  });

  it("preserves the frozen V1 and V2 Solidity package", function () {
    const evidence = buildEvidence();
    assert.equal(
      sha256("contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol"),
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a"
    );
    assert.equal(
      sha256("contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol"),
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    );
    assert.equal(
      evidence.baseline.v2RuntimeKeccak256.verifier,
      "0x665910b9989f3b83c3f025314fb127755d5abfc46e66ee386fbcbbfefc864dd7"
    );
    assert.equal(
      evidence.baseline.v2RuntimeKeccak256.account,
      "0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519"
    );
    assert.equal(
      evidence.baseline.v2RuntimeKeccak256.factory,
      "0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95"
    );
  });

  it("keeps the machine evidence deterministic and secret-free", function () {
    const evidencePath = path.join(
      ROOT,
      "config/solidity/O42_RECOVERY_ENROLLMENT_CEREMONY_EVIDENCE.json"
    );
    const serialized = `${JSON.stringify(buildEvidence(), null, 2)}\n`;
    assert.equal(fs.readFileSync(evidencePath, "utf8"), serialized);
    assert.doesNotMatch(
      serialized,
      /PHIL39-V1-(?:[A-Z2-7]{4}-){8,}[A-Z2-7]{4,}/u
    );
    assert.doesNotMatch(serialized, /BEGIN (?:EC |RSA )?PRIVATE KEY/u);
    assert.doesNotMatch(serialized, /"(?:rawCredentialId|privateKey|pairingSecret)"\s*:/u);
    assert.equal(buildEvidence().security.productionSecretCommitted, false);
  });

  it("preserves the zero-public-mutation stop boundary", function () {
    const evidence = buildEvidence();
    assert.equal(evidence.publicMutationCount, 0);
    assert.equal(evidence.rpcAccessed, false);
    assert.equal(evidence.sepoliaAccessed, false);
    assert.equal(evidence.externalNetworkAccessed, false);
    assert.ok(
      Object.values(evidence.stopBoundary).every((value) => value === false)
    );
  });
});
