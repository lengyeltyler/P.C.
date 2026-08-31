require("tsx/cjs");

const fs = require("node:fs");
const path = require("node:path");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID,
  createEthereumSepoliaDryRunReport,
  evaluateEthereumSepoliaMutationGuard,
  validateEthereumSepoliaManifestStatus
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");

const ROOT = path.resolve(__dirname, "../..");
const MANIFEST_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/ETHEREUM_SEPOLIA_DEPLOYMENT_MANIFEST_PROPOSED.json"
);

function loadManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
}

function summary(manifest) {
  return {
    status: manifest.status,
    chainId: manifest.network.chainId,
    entryPointAddress: manifest.entryPoint.address,
    deploymentApproved: manifest.approval.deploymentApproved,
    userOperationSubmissionApproved: manifest.approval.userOperationSubmissionApproved,
    productionApproved: manifest.approval.productionApproved,
    acceptedAddressesPresent: manifest.approval.acceptedAddressesPresent
  };
}

function parseStage() {
  const stageIndex = process.argv.indexOf("--stage");
  return stageIndex >= 0 ? process.argv[stageIndex + 1] : "inspect-config";
}

function main() {
  const stage = parseStage();
  const manifest = loadManifest();
  const manifestSummary = summary(manifest);
  const validation = validateEthereumSepoliaManifestStatus(manifestSummary);
  const dryRun = createEthereumSepoliaDryRunReport(manifest.status);

  if (stage === "inspect-config" || stage === "read-only-preflight") {
    process.stdout.write(JSON.stringify({
      stage,
      manifestValidation: validation,
      dryRun,
      rpcContacted: false,
      publicMutationPerformed: false
    }, null, 2) + "\n");
    if (!validation.valid) process.exitCode = 1;
    return;
  }

  const operation = stage === "submit-first-userop"
    ? "submit_first_user_operation"
    : stage === "deploy-test-target"
      ? "deploy_test_target"
      : undefined;
  if (!operation) {
    throw new Error(`Unsupported stage: ${stage}`);
  }

  const guard = evaluateEthereumSepoliaMutationGuard({
    operation,
    manifest: manifestSummary,
    environment: process.env,
    chainId: Number(process.env.PHILCORE_SEPOLIA_EXPECTED_CHAIN_ID || ETHEREUM_SEPOLIA_CHAIN_ID),
    entryPointAddress: process.env.PHILCORE_SEPOLIA_ENTRYPOINT || ERC4337_V07_CANONICAL_ENTRYPOINT,
    targetAddress: process.env.PHILCORE_SEPOLIA_TEST_TARGET,
    allowlistedTargetAddress: process.env.PHILCORE_SEPOLIA_TEST_TARGET,
    valueWei: "0",
    paymasterAndData: "0x",
    repositoryClean: false
  });
  process.stdout.write(JSON.stringify({
    stage,
    guard,
    transportImplemented: false,
    rpcContacted: false,
    publicMutationPerformed: false
  }, null, 2) + "\n");

  // O.17 deliberately has no mutation transport. A later approved phase must add it.
  process.exitCode = 2;
}

main();
