"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "../..");
const productPaths = [
  "apps/phil-device-sdk/src/sepoliaMintAuthorizationV1.ts",
  "apps/phil-device-sdk/src/sepoliaMintComposedAuthorizationV1.ts",
  "apps/phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts",
  "apps/phil-device-sdk/src/sepoliaMintUserOperationV1.ts",
  "apps/philcore-desktop/src/main/sepolia-mint-ceremony-store.cjs",
  "apps/philcore-desktop/src/main/sepolia-mint-composed-workflow.cjs",
  "apps/philcore-desktop/src/main/sepolia-mint-device-authorization-host.cjs",
  "apps/philcore-desktop/src/main/sepolia-mint-replay-store.cjs",
  "contracts/base/PhilSepoliaLocalComposedActionGateV1.sol",
  "contracts/base/PhilSepoliaMintPassConsumerV1.sol",
  "contracts/base/erc4337/PhilSepoliaMintAccountFactoryV1.sol",
  "contracts/base/erc4337/PhilSepoliaMintAccountV1.sol"
];

test("Sepolia mint product graph cannot reach STWO, synthetic secrets, or public submission", () => {
  const combined = productPaths.map((relative) => {
    const source = fs.readFileSync(path.join(root, relative), "utf8");
    assert.doesNotMatch(source, /STWO|stwo|hypotheticalWitness|synthetic[_ -]secret|fixture[_ -]secret/iu, relative);
    assert.doesNotMatch(source, /eth_sendUserOperation|sendTransaction\s*\(|sendRawTransaction/iu, relative);
    return source;
  }).join("\n");
  assert.match(combined, /proveNoirRootProofV1/u);
  assert.match(combined, /verifyNoirRootProofV1/u);
  assert.match(combined, /p256\.verify/u);
  assert.match(combined, /executionSigningAuthorized/u);

  const main = fs.readFileSync(
    path.join(root, "apps/philcore-desktop/src/main/main.cjs"),
    "utf8"
  );
  const start = main.indexOf("function loadSepoliaMintDemoConfiguration");
  const end = main.indexOf("function createRecoveryEncryptionAdapter", start);
  assert.ok(start > 0 && end > start);
  const mintMainBoundary = main.slice(start, end);
  assert.doesNotMatch(mintMainBoundary, /STWO|stwo|eth_sendUserOperation|sendTransaction\s*\(/u);
  assert.match(mintMainBoundary, /submissionEnabled:\s*false/u);
  assert.match(mintMainBoundary, /publicMutationOccurred:\s*false/u);

  const bridge = fs.readFileSync(
    path.join(root, "apps/philcore-desktop/src/shared/bridge-contract.cjs"),
    "utf8"
  );
  const channels = [...bridge.matchAll(/SEPOLIA_MINT_[A-Z_]+:\s*"([^"]+)"/gu)]
    .map((match) => match[1]);
  assert.deepEqual(channels, [
    "philcore:sepoliaMint:begin",
    "philcore:sepoliaMint:status",
    "philcore:sepoliaMint:cancel"
  ]);

  const configuration = JSON.parse(fs.readFileSync(
    path.join(root, "config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_V1.json"),
    "utf8"
  ));
  assert.equal(configuration.publicMutationEnabled, false);
  assert.equal(configuration.submissionEnabled, false);
});

test("packaging retains production sources and excludes test-only Sepolia secrets", () => {
  const packaging = fs.readFileSync(
    path.join(root, "apps/philcore-desktop/scripts/package-local.cjs"),
    "utf8"
  );
  const policy = fs.readFileSync(
    path.join(root, "apps/philcore-desktop/scripts/package-composition-policy.cjs"),
    "utf8"
  );
  assert.match(packaging, /PHIL_SEPOLIA_MINT_DEMO_V1\.json/u);
  assert.match(policy, /part === "test" \|\| part === "tests"/u);
});
