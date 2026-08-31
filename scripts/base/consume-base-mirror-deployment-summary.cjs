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

function normalizeAddress(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function normalizeHash(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function normalizePositiveInteger(value, label) {
  const integerValue = Number(value);
  if (!Number.isInteger(integerValue) || integerValue <= 0) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return integerValue;
}

function assertRuntimeVerification(entry, label) {
  if (!entry || typeof entry !== "object") {
    throw new Error(`${label} runtime verification entry is required`);
  }

  assertEqual(entry.runtimeBytecodeMatch, true, `${label} runtimeBytecodeMatch`);
  normalizeHash(entry.expectedRuntimeHash, `${label} expectedRuntimeHash`);
}

function buildBaseMirrorDeploymentConsumption({ deploymentSummary }) {
  if (!deploymentSummary || typeof deploymentSummary !== "object") {
    throw new Error("deploymentSummary is required");
  }

  assertEqual(
    deploymentSummary.path,
    "base-proof-input-hash-mirror-deployment-summary",
    "deploymentSummary.path"
  );
  assertEqual(
    deploymentSummary.payloadShape,
    "[fact_high, fact_low]",
    "deploymentSummary.payloadShape"
  );

  const baseCrossDomainMessenger = deploymentSummary.deployedContracts?.baseCrossDomainMessenger;
  const adapter = deploymentSummary.deployedContracts?.adapter;
  const mirror = deploymentSummary.deployedContracts?.mirror;

  normalizeAddress(
    deploymentSummary.deploymentPlan?.canonicalBaseMessengerAddress,
    "deploymentPlan.canonicalBaseMessengerAddress"
  );
  normalizeAddress(
    deploymentSummary.deploymentPlan?.authorizedL1Messenger,
    "deploymentPlan.authorizedL1Messenger"
  );
  normalizePositiveInteger(
    deploymentSummary.deploymentPlan?.adapterMinGasLimit,
    "deploymentPlan.adapterMinGasLimit"
  );

  normalizeAddress(baseCrossDomainMessenger?.address, "baseCrossDomainMessenger.address");
  normalizeHash(
    baseCrossDomainMessenger?.transactionHash,
    "baseCrossDomainMessenger.transactionHash"
  );
  normalizePositiveInteger(
    baseCrossDomainMessenger?.blockNumber,
    "baseCrossDomainMessenger.blockNumber"
  );

  normalizeAddress(adapter?.address, "adapter.address");
  normalizeHash(adapter?.transactionHash, "adapter.transactionHash");
  normalizePositiveInteger(adapter?.blockNumber, "adapter.blockNumber");

  normalizeAddress(mirror?.address, "mirror.address");
  normalizeHash(mirror?.transactionHash, "mirror.transactionHash");
  normalizePositiveInteger(mirror?.blockNumber, "mirror.blockNumber");

  assertRuntimeVerification(
    deploymentSummary.runtimeVerification?.baseCrossDomainMessenger,
    "baseCrossDomainMessenger"
  );
  assertRuntimeVerification(deploymentSummary.runtimeVerification?.adapter, "adapter");
  assertRuntimeVerification(deploymentSummary.runtimeVerification?.mirror, "mirror");

  assertEqual(
    baseCrossDomainMessenger.address,
    deploymentSummary.deploymentPlan.canonicalBaseMessengerAddress,
    "canonical base messenger address"
  );
  assertEqual(
    adapter.address,
    deploymentSummary.deploymentPlan.authorizedL1Messenger,
    "authorizedL1Messenger / adapter address"
  );

  return {
    version: 1,
    path: "base-proof-input-hash-mirror-deployment-consumption",
    consumptionSource: "scripts/base/consume-base-mirror-deployment-summary.cjs",
    summarySource: deploymentSummary.summarySource,
    consumedSummaryPath: deploymentSummary.path,
    networkName: deploymentSummary.networkName,
    chainId: deploymentSummary.chainId,
    configSource: deploymentSummary.configSource,
    payloadMarker: deploymentSummary.payloadShape,
    mirrorWriteShape: deploymentSummary.mirrorWriteShape,
    validationChecks: {
      summaryPathValid: true,
      canonicalMessengerAligned: true,
      authorizedMessengerAligned: true,
      runtimeVerificationAllPassed: true
    },
    operatorReadModel: {
      canonicalBaseMessengerAddress:
        deploymentSummary.deploymentPlan.canonicalBaseMessengerAddress,
      adapterAddress: adapter.address,
      mirrorAddress: mirror.address,
      adapterMinGasLimit: deploymentSummary.deploymentPlan.adapterMinGasLimit,
      deploymentTransactions: {
        baseCrossDomainMessenger: baseCrossDomainMessenger.transactionHash,
        adapter: adapter.transactionHash,
        mirror: mirror.transactionHash
      },
      deploymentBlocks: {
        baseCrossDomainMessenger: baseCrossDomainMessenger.blockNumber,
        adapter: adapter.blockNumber,
        mirror: mirror.blockNumber
      }
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--summary") {
      parsed.summaryPath = argv[i + 1];
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
      "  node scripts/base/consume-base-mirror-deployment-summary.cjs --summary <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.summaryPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const consumption = buildBaseMirrorDeploymentConsumption({
      deploymentSummary: loadJson(path.resolve(parsed.summaryPath))
    });
    console.log(JSON.stringify(consumption, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildBaseMirrorDeploymentConsumption
};
