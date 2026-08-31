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

function buildWalletInput({ mintIntentStatus }) {
  if (!mintIntentStatus || typeof mintIntentStatus !== "object") {
    throw new Error("mintIntentStatus is required");
  }

  assertEqual(mintIntentStatus.path, "phil-mint-intent-status", "mintIntentStatus.path");
  assertEqual(
    mintIntentStatus.payloadShape,
    "[fact_high, fact_low]",
    "mintIntentStatus.payloadShape"
  );

  if (!mintIntentStatus.validationChecks || typeof mintIntentStatus.validationChecks !== "object") {
    throw new Error("mintIntentStatus.validationChecks is required");
  }
  if (!mintIntentStatus.readinessSummary || typeof mintIntentStatus.readinessSummary !== "object") {
    throw new Error("mintIntentStatus.readinessSummary is required");
  }
  if (!mintIntentStatus.appReadiness || typeof mintIntentStatus.appReadiness !== "object") {
    throw new Error("mintIntentStatus.appReadiness is required");
  }

  assertTrue(
    mintIntentStatus.validationChecks.consumptionPathValid,
    "validationChecks.consumptionPathValid"
  );
  assertTrue(
    mintIntentStatus.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    mintIntentStatus.validationChecks.upstreamValidationPassed,
    "validationChecks.upstreamValidationPassed"
  );
  assertTrue(
    mintIntentStatus.validationChecks.intentFieldConsistencyValid,
    "validationChecks.intentFieldConsistencyValid"
  );
  assertTrue(mintIntentStatus.readinessSummary.ready, "readinessSummary.ready");
  assertEqual(mintIntentStatus.readinessSummary.status, "ready", "readinessSummary.status");
  assertTrue(mintIntentStatus.readinessSummary.parityProven, "readinessSummary.parityProven");

  const appReadiness = {
    ownerCommitment: normalizeHex32(
      mintIntentStatus.appReadiness.ownerCommitment,
      "appReadiness.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      mintIntentStatus.appReadiness.consumerDataHash,
      "appReadiness.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      mintIntentStatus.appReadiness.canonicalRecipient,
      "appReadiness.canonicalRecipient"
    ),
    ready: mintIntentStatus.appReadiness.ready === true,
    status: String(mintIntentStatus.appReadiness.status || ""),
    parityProven: mintIntentStatus.appReadiness.parityProven === true
  };

  assertTrue(appReadiness.ready, "appReadiness.ready");
  assertEqual(appReadiness.status, "ready", "appReadiness.status");
  assertTrue(appReadiness.parityProven, "appReadiness.parityProven");

  return {
    version: 1,
    path: "phil-wallet-input",
    walletInputSource: "scripts/base/build-wallet-input.cjs",
    statusSource: mintIntentStatus.statusSource,
    consumedPath: mintIntentStatus.path,
    proofType: mintIntentStatus.proofType,
    payloadShape: mintIntentStatus.payloadShape,
    validationChecks: {
      statusPathValid: true,
      payloadShapeValid: true,
      upstreamStatusValid: true,
      walletInputFieldsValid: true
    },
    walletInputSummary: {
      ready: true,
      status: "wallet-input-ready",
      reason: "validated-mint-intent-status",
      parityProven: true
    },
    deviceWalletInput: {
      ownerCommitment: appReadiness.ownerCommitment,
      consumerDataHash: appReadiness.consumerDataHash,
      canonicalRecipient: appReadiness.canonicalRecipient
    },
    appWalletInput: {
      recipient: appReadiness.canonicalRecipient,
      ready: true,
      status: "wallet-input-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mint-intent-status") {
      parsed.mintIntentStatusPath = argv[i + 1];
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
      "  node scripts/base/build-wallet-input.cjs --mint-intent-status <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.mintIntentStatusPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const walletInput = buildWalletInput({
      mintIntentStatus: loadJson(path.resolve(parsed.mintIntentStatusPath))
    });
    console.log(JSON.stringify(walletInput, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildWalletInput
};
