const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  DEMO_FORBIDDEN_OUTPUT_PATTERNS,
  PHIL_DEVICE_IDENTITY_DEMO_KIND,
  assertDemoOutputSafe,
  runPhilDeviceIdentityDemo
} = require("../../scripts/base/run-phil-device-identity-demo.cjs");

describe("Phil Device Identity local demo", function () {
  this.timeout(30_000);

  it("runs the v1.8 end-to-end mocked WebAuthn, encrypted registry, and session matrix flow", async function () {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phil-device-demo-"));
    const outPath = path.join(tempRoot, "phil_device_identity_demo_result.json");
    const registryPath = path.join(tempRoot, "phil_device_identity_demo_registry.enc.json");
    const sessionOutDir = path.join(tempRoot, "session_matrix");
    const artifact = await runPhilDeviceIdentityDemo({
      outPath,
      registryPath,
      sessionOutDir
    });
    const persistedArtifact = JSON.parse(fs.readFileSync(outPath, "utf8"));
    const encryptedRegistry = fs.readFileSync(registryPath, "utf8");
    const serializedArtifact = JSON.stringify(persistedArtifact);

    assert.deepEqual(persistedArtifact, artifact);
    assert.equal(artifact.demoKind, PHIL_DEVICE_IDENTITY_DEMO_KIND);
    assert.match(artifact.identity.identityRootHash, /^0x[0-9a-f]{64}$/);
    assert.match(artifact.identity.ownerCommitment, /^0x[0-9a-f]{64}$/);
    assert.equal(Object.prototype.hasOwnProperty.call(artifact.identity, "philSecret"), false);
    assert.equal(artifact.credential.count, 1);
    assert.equal(artifact.credential.providerKind, "webauthn-passkey-device-identity-v1");
    assert.equal(artifact.registry.persisted, true);
    assert.equal(artifact.registry.reloaded, true);
    assert.equal(artifact.registry.encryptedAtRest, true);
    assert.equal(artifact.registry.auditEventTypes.includes("registry-created"), true);
    assert.equal(artifact.registry.auditEventTypes.includes("credential-added"), true);
    assert.equal(artifact.registry.auditEventTypes.includes("registry-saved"), true);
    assert.equal(artifact.registry.auditEventTypes.includes("registry-loaded"), true);
    assert.equal(artifact.webAuthn.mocked, true);
    assert.equal(artifact.webAuthn.registrationVerified, true);
    assert.equal(artifact.webAuthn.assertionVerified, true);
    assert.equal(artifact.webAuthn.challengeBindingPreserved, true);
    assert.equal(artifact.webAuthn.signatureVerified, true);
    assert.equal(artifact.webAuthn.counterStatus, "advanced");
    assert.equal(artifact.webAuthn.browserCreateCalls, 1);
    assert.equal(artifact.webAuthn.browserGetCalls, 1);
    assert.equal(artifact.authorization.digestAuthorized, true);
    assert.match(artifact.authorization.signableDigest, /^0x[0-9a-f]{64}$/);
    assert.equal(artifact.sessionMatrix.ready, true);
    assert.equal(artifact.sessionMatrix.proofType, "stwo-unlock-keccak-v1");
    assert.equal(artifact.sessionMatrix.payloadShape, "[fact_high, fact_low]");
    assert.equal(artifact.sessionMatrix.lockedBaseTupleSemanticsUnchanged, true);
    assert.equal(artifact.sessionMatrix.exactTwoFeltFactShapePreserved, true);
    assert.equal(artifact.safety.publicArtifactOnly, true);
    assert.equal(artifact.safety.secretScanPassed, true);
    assertDemoOutputSafe(artifact);

    for (const pattern of DEMO_FORBIDDEN_OUTPUT_PATTERNS) {
      assert.equal(pattern.test(serializedArtifact), false);
    }
    assert.equal(encryptedRegistry.includes("Phil demo passkey"), false);
    assert.equal(encryptedRegistry.includes("phil_secret"), false);
  });
});
