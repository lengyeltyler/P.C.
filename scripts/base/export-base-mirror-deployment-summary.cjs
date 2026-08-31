const fs = require("node:fs");
const path = require("node:path");

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch`);
  }
}

function buildBaseMirrorDeploymentSummary({ deploymentBundle }) {
  if (!deploymentBundle || typeof deploymentBundle !== "object") {
    throw new Error("deploymentBundle is required");
  }

  const manifest = deploymentBundle.deploymentManifest;
  const runnerOutput = deploymentBundle.runnerOutput;
  const deploymentReceipt = deploymentBundle.deploymentReceipt;
  const deploymentVerification = deploymentBundle.deploymentVerification;

  if (!manifest || typeof manifest !== "object") {
    throw new Error("deploymentBundle.deploymentManifest is required");
  }
  if (!runnerOutput || typeof runnerOutput !== "object") {
    throw new Error("deploymentBundle.runnerOutput is required");
  }
  if (!deploymentReceipt || typeof deploymentReceipt !== "object") {
    throw new Error("deploymentBundle.deploymentReceipt is required");
  }
  if (!deploymentVerification || typeof deploymentVerification !== "object") {
    throw new Error("deploymentBundle.deploymentVerification is required");
  }

  assertEqual(
    deploymentBundle.payloadShape,
    "[fact_high, fact_low]",
    "bundle payloadShape"
  );
  assertEqual(
    deploymentBundle.networkName,
    manifest.networkName,
    "bundle/manifest networkName"
  );
  assertEqual(
    runnerOutput.adapter.address,
    deploymentReceipt.deploymentReceipts.adapter.address,
    "runner/receipt adapter address"
  );
  assertEqual(
    runnerOutput.mirror.address,
    deploymentReceipt.deploymentReceipts.mirror.address,
    "runner/receipt mirror address"
  );
  assertEqual(
    deploymentVerification.deploymentVerification.adapter.transactionHash,
    deploymentReceipt.deploymentReceipts.adapter.transactionHash,
    "verification/receipt adapter transactionHash"
  );
  assertEqual(
    deploymentVerification.deploymentVerification.mirror.blockNumber,
    deploymentReceipt.deploymentReceipts.mirror.blockNumber,
    "verification/receipt mirror blockNumber"
  );

  return {
    version: 1,
    path: "base-proof-input-hash-mirror-deployment-summary",
    networkName: deploymentBundle.networkName,
    chainId: manifest.chainId,
    summarySource: "scripts/base/export-base-mirror-deployment-summary.cjs",
    bundleSource: deploymentBundle.packageSource,
    configSource: deploymentBundle.configSource,
    payloadShape: deploymentBundle.payloadShape,
    mirrorWriteShape: deploymentBundle.mirrorWriteShape,
    deploymentPlan: {
      canonicalBaseMessengerAddress: manifest.deploymentPlan.canonicalBaseMessengerAddress,
      adapterMinGasLimit: manifest.deploymentPlan.adapterMinGasLimit,
      authorizedL1Messenger: manifest.deploymentPlan.authorizedL1Messenger
    },
    deployedContracts: {
      baseCrossDomainMessenger: {
        address: runnerOutput.baseCrossDomainMessenger.address,
        transactionHash: runnerOutput.baseCrossDomainMessenger.transactionHash,
        blockNumber: runnerOutput.baseCrossDomainMessenger.blockNumber
      },
      adapter: {
        address: runnerOutput.adapter.address,
        transactionHash: runnerOutput.adapter.transactionHash,
        blockNumber: runnerOutput.adapter.blockNumber
      },
      mirror: {
        address: runnerOutput.mirror.address,
        transactionHash: runnerOutput.mirror.transactionHash,
        blockNumber: runnerOutput.mirror.blockNumber
      }
    },
    runtimeVerification: {
      baseCrossDomainMessenger: {
        runtimeBytecodeMatch:
          deploymentVerification.deploymentVerification.baseCrossDomainMessenger.runtimeBytecodeMatch,
        expectedRuntimeHash:
          deploymentVerification.deploymentVerification.baseCrossDomainMessenger.expectedRuntimeHash
      },
      adapter: {
        runtimeBytecodeMatch:
          deploymentVerification.deploymentVerification.adapter.runtimeBytecodeMatch,
        expectedRuntimeHash:
          deploymentVerification.deploymentVerification.adapter.expectedRuntimeHash
      },
      mirror: {
        runtimeBytecodeMatch:
          deploymentVerification.deploymentVerification.mirror.runtimeBytecodeMatch,
        expectedRuntimeHash:
          deploymentVerification.deploymentVerification.mirror.expectedRuntimeHash
      }
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--bundle") {
      parsed.bundlePath = argv[i + 1];
      i += 1;
    } else if (arg === "--help") {
      parsed.help = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return parsed;
}

function printUsage() {
  console.log(
    [
      "Usage:",
      "  node scripts/base/export-base-mirror-deployment-summary.cjs --bundle <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.bundlePath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const summary = buildBaseMirrorDeploymentSummary({
      deploymentBundle: loadJson(path.resolve(parsed.bundlePath))
    });
    console.log(JSON.stringify(summary, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildBaseMirrorDeploymentSummary
};
