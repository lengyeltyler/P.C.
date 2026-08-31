const assert = require("node:assert/strict");

const {
  EXCLUDED_EDR_PLATFORM_PACKAGES,
  SOLIDITY_ANALYZER_PACKAGES,
  nodeModulePackageName,
  shouldCopyContractArtifact,
  shouldCopyContractSource,
  shouldCopyNodeModuleEntry
} = require("../scripts/package-composition-policy.cjs");

assert.equal(nodeModulePackageName("@nomicfoundation/edr-darwin-arm64/edr.darwin-arm64.node"), "@nomicfoundation/edr-darwin-arm64");
assert.equal(nodeModulePackageName("typescript/lib/typescript.js"), "typescript");
assert.equal(nodeModulePackageName("@esbuild/darwin-arm64/bin/esbuild"), "@esbuild/darwin-arm64");

for (const packageName of EXCLUDED_EDR_PLATFORM_PACKAGES) {
  assert.equal(shouldCopyNodeModuleEntry("", `${packageName}/package.json`), false, `${packageName} should be pruned`);
}

assert.equal(
  shouldCopyNodeModuleEntry("", "@nomicfoundation/edr-darwin-arm64/edr.darwin-arm64.node"),
  true,
  "Darwin arm64 EDR must remain packaged"
);

for (const packageName of SOLIDITY_ANALYZER_PACKAGES) {
  assert.equal(shouldCopyNodeModuleEntry("", `${packageName}/package.json`), false, `${packageName} should be pruned`);
}

assert.equal(shouldCopyNodeModuleEntry("", "typescript/lib/typescript.js"), false);
assert.equal(shouldCopyNodeModuleEntry("", "solc/index.js"), false);
assert.equal(shouldCopyNodeModuleEntry("", "esbuild/lib/main.js"), true);
assert.equal(shouldCopyNodeModuleEntry("", "@esbuild/darwin-arm64/bin/esbuild"), true);
assert.equal(shouldCopyNodeModuleEntry("", "esbuild/bin/esbuild"), false);
assert.equal(shouldCopyNodeModuleEntry("", "esbuild/install.js"), false);
assert.equal(shouldCopyNodeModuleEntry("", "hardhat/internal/lib/hardhat-lib.js"), true);
assert.equal(shouldCopyNodeModuleEntry("", "hardhat/internal/lib/hardhat-lib.d.ts"), false);

assert.equal(shouldCopyContractArtifact("", "contracts/base/PhilBaseActionGate.sol/PhilBaseActionGate.json"), true);
assert.equal(shouldCopyContractArtifact("", "contracts/base/PhilBaseActionGate.sol/PhilBaseActionGate.dbg.json"), false);
assert.equal(shouldCopyContractArtifact("", "contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol/PhilV1Step6CHarmlessTarget.json"), true);
assert.equal(shouldCopyContractArtifact("", "contracts/base/erc4337/test/Fixture.sol/Fixture.json"), false);
assert.equal(shouldCopyContractArtifact("", "build-info/abc.json"), false);
assert.equal(shouldCopyContractSource("", "base/PhilBaseActionGate.sol"), true);
assert.equal(shouldCopyContractSource("", "base/erc4337/PhilV1Step6CHarmlessTarget.sol"), true);
assert.equal(shouldCopyContractSource("", "base/erc4337/test/Fixture.sol"), false);

console.log(JSON.stringify({
  status: "passed",
  policy: "desktop_package_pruning",
  publicNetworkMutation: false
}, null, 2));
