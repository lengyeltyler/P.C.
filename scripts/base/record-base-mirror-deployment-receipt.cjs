const fs = require("node:fs");
const path = require("node:path");

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function normalizeAddress(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function normalizeTransactionHash(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function normalizeBlockNumber(value, label) {
  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized <= 0) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return normalized;
}

function normalizeDeploymentRecord(value, label) {
  if (!value || typeof value !== "object") {
    throw new Error(`Missing ${label}`);
  }

  return {
    contract: String(value.contract || "").trim(),
    address: normalizeAddress(value.address, `${label} address`),
    transactionHash: normalizeTransactionHash(
      value.transactionHash,
      `${label} transaction hash`
    ),
    blockNumber: normalizeBlockNumber(value.blockNumber, `${label} block number`)
  };
}

function buildBaseMirrorDeploymentReceipt({ runnerOutput }) {
  if (!runnerOutput || typeof runnerOutput !== "object") {
    throw new Error("runnerOutput is required");
  }

  if (!runnerOutput.deploymentManifest || typeof runnerOutput.deploymentManifest !== "object") {
    throw new Error("runnerOutput.deploymentManifest is required");
  }

  return {
    version: 1,
    path: "base-proof-input-hash-mirror-deployment-receipt",
    networkName: String(runnerOutput.networkName || "").trim(),
    runnerSource: "scripts/base/run-local-base-mirror-deployment.cjs",
    manifestSource: "scripts/base/record-base-mirror-deployment-manifest.cjs",
    configSource:
      runnerOutput.deploymentManifest.configSource || "config/base-messenger-config.cjs",
    payloadShape:
      runnerOutput.deploymentManifest.payloadShape || "[fact_high, fact_low]",
    mirrorWriteShape: runnerOutput.deploymentManifest.mirrorWriteShape,
    deploymentManifest: runnerOutput.deploymentManifest,
    deploymentReceipts: {
      baseCrossDomainMessenger: normalizeDeploymentRecord(
        runnerOutput.baseCrossDomainMessenger,
        "baseCrossDomainMessenger"
      ),
      adapter: normalizeDeploymentRecord(runnerOutput.adapter, "adapter"),
      mirror: normalizeDeploymentRecord(runnerOutput.mirror, "mirror")
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--runner-output") {
      parsed.runnerOutputPath = argv[i + 1];
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
      "  node scripts/base/record-base-mirror-deployment-receipt.cjs --runner-output <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.runnerOutputPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const runnerOutput = loadJson(path.resolve(parsed.runnerOutputPath));
    const receipt = buildBaseMirrorDeploymentReceipt({ runnerOutput });
    console.log(JSON.stringify(receipt, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildBaseMirrorDeploymentReceipt
};
