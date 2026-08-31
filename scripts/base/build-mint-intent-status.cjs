const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch`);
  }
}

function assertTrue(value, label) {
  if (value !== true) {
    throw new Error(`${label} must be true`);
  }
}

function normalizeBytes(value, label) {
  try {
    return ethers.hexlify(ethers.getBytes(value)).toLowerCase();
  } catch {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
}

function normalizeHex32(value, label) {
  const normalized = normalizeBytes(value, label);
  if (normalized.length !== 66) {
    throw new Error(`Invalid ${label}: ${normalized}`);
  }
  return normalized;
}

function normalizeAddress(value, label) {
  try {
    return ethers.getAddress(value);
  } catch {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
}

function buildMintIntentStatus({ mintIntentConsumption }) {
  if (!mintIntentConsumption || typeof mintIntentConsumption !== "object") {
    throw new Error("mintIntentConsumption is required");
  }

  assertEqual(
    mintIntentConsumption.path,
    "phil-mint-intent-consumption",
    "mintIntentConsumption.path"
  );
  assertEqual(
    mintIntentConsumption.payloadShape,
    "[fact_high, fact_low]",
    "mintIntentConsumption.payloadShape"
  );

  if (
    !mintIntentConsumption.validationChecks ||
    typeof mintIntentConsumption.validationChecks !== "object"
  ) {
    throw new Error("mintIntentConsumption.validationChecks is required");
  }
  if (
    !mintIntentConsumption.appReadModel ||
    typeof mintIntentConsumption.appReadModel !== "object"
  ) {
    throw new Error("mintIntentConsumption.appReadModel is required");
  }

  assertTrue(
    mintIntentConsumption.validationChecks.intentPathValid,
    "mintIntentConsumption.validationChecks.intentPathValid"
  );
  assertTrue(
    mintIntentConsumption.validationChecks.payloadShapeValid,
    "mintIntentConsumption.validationChecks.payloadShapeValid"
  );
  assertTrue(
    mintIntentConsumption.validationChecks.intentFieldsValid,
    "mintIntentConsumption.validationChecks.intentFieldsValid"
  );
  assertTrue(
    mintIntentConsumption.validationChecks.recipientConsistencyValid,
    "mintIntentConsumption.validationChecks.recipientConsistencyValid"
  );

  const appReadModel = {
    ownerCommitment: normalizeHex32(
      mintIntentConsumption.appReadModel.ownerCommitment,
      "appReadModel.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      mintIntentConsumption.appReadModel.consumerDataHash,
      "appReadModel.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      mintIntentConsumption.appReadModel.canonicalRecipient,
      "appReadModel.canonicalRecipient"
    ),
    ready: mintIntentConsumption.appReadModel.ready === true,
    status: String(mintIntentConsumption.appReadModel.status || ""),
    parityProven: mintIntentConsumption.appReadModel.parityProven === true
  };

  assertTrue(appReadModel.ready, "appReadModel.ready");
  assertEqual(appReadModel.status, "ready-to-mint", "appReadModel.status");
  assertTrue(appReadModel.parityProven, "appReadModel.parityProven");

  return {
    version: 1,
    path: "phil-mint-intent-status",
    statusSource: "scripts/base/build-mint-intent-status.cjs",
    consumptionSource: mintIntentConsumption.consumptionSource,
    consumedPath: mintIntentConsumption.path,
    proofType: mintIntentConsumption.proofType,
    payloadShape: mintIntentConsumption.payloadShape,
    validationChecks: {
      consumptionPathValid: true,
      payloadShapeValid: true,
      upstreamValidationPassed: true,
      intentFieldConsistencyValid: true
    },
    readinessSummary: {
      ready: true,
      status: "ready",
      reason: "validated-mint-intent-consumption",
      parityProven: true
    },
    appReadiness: {
      ownerCommitment: appReadModel.ownerCommitment,
      consumerDataHash: appReadModel.consumerDataHash,
      canonicalRecipient: appReadModel.canonicalRecipient,
      ready: true,
      status: "ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mint-intent-consumption") {
      parsed.mintIntentConsumptionPath = argv[i + 1];
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
      "  node scripts/base/build-mint-intent-status.cjs --mint-intent-consumption <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.mintIntentConsumptionPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const status = buildMintIntentStatus({
      mintIntentConsumption: loadJson(path.resolve(parsed.mintIntentConsumptionPath))
    });
    console.log(JSON.stringify(status, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildMintIntentStatus
};
