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

function buildMintIntentConsumption({ mintIntent }) {
  if (!mintIntent || typeof mintIntent !== "object") {
    throw new Error("mintIntent is required");
  }

  assertEqual(mintIntent.path, "phil-mint-intent", "mintIntent.path");
  assertEqual(mintIntent.payloadShape, "[fact_high, fact_low]", "mintIntent.payloadShape");

  if (!mintIntent.validationChecks || typeof mintIntent.validationChecks !== "object") {
    throw new Error("mintIntent.validationChecks is required");
  }
  if (!mintIntent.intentSummary || typeof mintIntent.intentSummary !== "object") {
    throw new Error("mintIntent.intentSummary is required");
  }
  if (!mintIntent.deviceMintIntent || typeof mintIntent.deviceMintIntent !== "object") {
    throw new Error("mintIntent.deviceMintIntent is required");
  }
  if (!mintIntent.appIntent || typeof mintIntent.appIntent !== "object") {
    throw new Error("mintIntent.appIntent is required");
  }

  assertTrue(mintIntent.validationChecks.readinessPathValid, "validationChecks.readinessPathValid");
  assertTrue(mintIntent.validationChecks.payloadShapeValid, "validationChecks.payloadShapeValid");
  assertTrue(mintIntent.validationChecks.readinessValid, "validationChecks.readinessValid");
  assertTrue(
    mintIntent.validationChecks.recipientBindingValid,
    "validationChecks.recipientBindingValid"
  );

  assertTrue(mintIntent.intentSummary.ready, "intentSummary.ready");
  assertEqual(mintIntent.intentSummary.status, "ready-to-mint", "intentSummary.status");
  assertTrue(mintIntent.intentSummary.parityProven, "intentSummary.parityProven");

  const deviceMintIntent = {
    ownerCommitment: normalizeHex32(
      mintIntent.deviceMintIntent.ownerCommitment,
      "deviceMintIntent.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      mintIntent.deviceMintIntent.consumerDataHash,
      "deviceMintIntent.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      mintIntent.deviceMintIntent.canonicalRecipient,
      "deviceMintIntent.canonicalRecipient"
    )
  };

  const appIntent = {
    recipient: normalizeAddress(mintIntent.appIntent.recipient, "appIntent.recipient"),
    ready: mintIntent.appIntent.ready === true,
    status: String(mintIntent.appIntent.status || ""),
    parityProven: mintIntent.appIntent.parityProven === true
  };

  assertTrue(appIntent.ready, "appIntent.ready");
  assertEqual(appIntent.status, "ready-to-mint", "appIntent.status");
  assertTrue(appIntent.parityProven, "appIntent.parityProven");
  assertEqual(
    appIntent.recipient.toLowerCase(),
    deviceMintIntent.canonicalRecipient.toLowerCase(),
    "appIntent.recipient/deviceMintIntent.canonicalRecipient"
  );

  return {
    version: 1,
    path: "phil-mint-intent-consumption",
    consumptionSource: "scripts/base/consume-mint-intent.cjs",
    intentSource: mintIntent.intentSource,
    consumedIntentPath: mintIntent.path,
    proofType: mintIntent.proofType,
    payloadShape: mintIntent.payloadShape,
    validationChecks: {
      intentPathValid: true,
      payloadShapeValid: true,
      intentFieldsValid: true,
      recipientConsistencyValid: true
    },
    appReadModel: {
      ownerCommitment: deviceMintIntent.ownerCommitment,
      consumerDataHash: deviceMintIntent.consumerDataHash,
      canonicalRecipient: deviceMintIntent.canonicalRecipient,
      ready: true,
      status: "ready-to-mint",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mint-intent") {
      parsed.mintIntentPath = argv[i + 1];
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
      "  node scripts/base/consume-mint-intent.cjs --mint-intent <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.mintIntentPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const mintIntentConsumption = buildMintIntentConsumption({
      mintIntent: loadJson(path.resolve(parsed.mintIntentPath))
    });
    console.log(JSON.stringify(mintIntentConsumption, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildMintIntentConsumption
};
