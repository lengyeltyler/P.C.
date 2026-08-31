#!/usr/bin/env node
const { spawnSync } = require("node:child_process");

const expectedSlitherVersion = "0.10.4";
const targets = [
  "contracts/base/erc4337/PhilCore4337Account.sol",
  "contracts/base/erc4337/PhilCore4337AccountFactory.sol",
  "contracts/base/PhilBaseActionGate.sol",
  "contracts/base/PhilUnlockConsumer.sol",
  "contracts/base/erc4337/PhilSepoliaMintAccountV1.sol",
  "contracts/base/erc4337/PhilSepoliaMintAccountFactoryV1.sol",
  "contracts/base/PhilSepoliaLocalComposedActionGateV1.sol",
  "contracts/base/PhilSepoliaMintPassConsumerV1.sol"
];

function run(command, args) {
  return spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
}

const version = run("slither", ["--version"]);
if (version.error || version.status !== 0) {
  console.error(JSON.stringify({
    status: "blocked",
    tool: "slither",
    expectedVersion: expectedSlitherVersion,
    reason: "slither_unavailable",
    guidance: "Install the pinned Slither version in an isolated Python environment before running public-network security gates.",
    targets
  }, null, 2));
  process.exit(1);
}

const installedVersion = `${version.stdout}${version.stderr}`.trim();
if (!installedVersion.includes(expectedSlitherVersion)) {
  console.error(JSON.stringify({
    status: "blocked",
    tool: "slither",
    expectedVersion: expectedSlitherVersion,
    installedVersion,
    reason: "slither_version_mismatch",
    targets
  }, null, 2));
  process.exit(1);
}

const analysis = run("slither", [
  ".",
  "--filter-paths",
  "node_modules|artifacts|cache|proving|docs|starknet_integration|starknet_spike|cairo_air_adapter_spike"
]);

if (analysis.status !== 0) {
  console.error(analysis.stdout);
  console.error(analysis.stderr);
  process.exit(analysis.status ?? 1);
}

process.stdout.write(JSON.stringify({
  status: "passed",
  tool: "slither",
  expectedVersion: expectedSlitherVersion,
  installedVersion,
  targets
}, null, 2));
process.stdout.write("\n");
