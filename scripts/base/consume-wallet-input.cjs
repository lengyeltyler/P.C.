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

function buildWalletInputConsumption({ walletInput }) {
  if (!walletInput || typeof walletInput !== "object") {
    throw new Error("walletInput is required");
  }

  assertEqual(walletInput.path, "phil-wallet-input", "walletInput.path");
  assertEqual(walletInput.payloadShape, "[fact_high, fact_low]", "walletInput.payloadShape");

  if (!walletInput.validationChecks || typeof walletInput.validationChecks !== "object") {
    throw new Error("walletInput.validationChecks is required");
  }
  if (!walletInput.walletInputSummary || typeof walletInput.walletInputSummary !== "object") {
    throw new Error("walletInput.walletInputSummary is required");
  }
  if (!walletInput.deviceWalletInput || typeof walletInput.deviceWalletInput !== "object") {
    throw new Error("walletInput.deviceWalletInput is required");
  }
  if (!walletInput.appWalletInput || typeof walletInput.appWalletInput !== "object") {
    throw new Error("walletInput.appWalletInput is required");
  }

  assertTrue(walletInput.validationChecks.statusPathValid, "validationChecks.statusPathValid");
  assertTrue(walletInput.validationChecks.payloadShapeValid, "validationChecks.payloadShapeValid");
  assertTrue(
    walletInput.validationChecks.upstreamStatusValid,
    "validationChecks.upstreamStatusValid"
  );
  assertTrue(
    walletInput.validationChecks.walletInputFieldsValid,
    "validationChecks.walletInputFieldsValid"
  );

  assertTrue(walletInput.walletInputSummary.ready, "walletInputSummary.ready");
  assertEqual(
    walletInput.walletInputSummary.status,
    "wallet-input-ready",
    "walletInputSummary.status"
  );
  assertTrue(walletInput.walletInputSummary.parityProven, "walletInputSummary.parityProven");

  const deviceWalletInput = {
    ownerCommitment: normalizeHex32(
      walletInput.deviceWalletInput.ownerCommitment,
      "deviceWalletInput.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      walletInput.deviceWalletInput.consumerDataHash,
      "deviceWalletInput.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      walletInput.deviceWalletInput.canonicalRecipient,
      "deviceWalletInput.canonicalRecipient"
    )
  };

  const appWalletInput = {
    recipient: normalizeAddress(walletInput.appWalletInput.recipient, "appWalletInput.recipient"),
    ready: walletInput.appWalletInput.ready === true,
    status: String(walletInput.appWalletInput.status || ""),
    parityProven: walletInput.appWalletInput.parityProven === true
  };

  assertTrue(appWalletInput.ready, "appWalletInput.ready");
  assertEqual(appWalletInput.status, "wallet-input-ready", "appWalletInput.status");
  assertTrue(appWalletInput.parityProven, "appWalletInput.parityProven");
  assertEqual(
    appWalletInput.recipient.toLowerCase(),
    deviceWalletInput.canonicalRecipient.toLowerCase(),
    "appWalletInput.recipient/deviceWalletInput.canonicalRecipient"
  );

  return {
    version: 1,
    path: "phil-wallet-input-consumption",
    consumptionSource: "scripts/base/consume-wallet-input.cjs",
    walletInputSource: walletInput.walletInputSource,
    consumedWalletInputPath: walletInput.path,
    proofType: walletInput.proofType,
    payloadShape: walletInput.payloadShape,
    validationChecks: {
      walletInputPathValid: true,
      payloadShapeValid: true,
      walletInputFieldsValid: true,
      recipientConsistencyValid: true
    },
    appReadModel: {
      ownerCommitment: deviceWalletInput.ownerCommitment,
      consumerDataHash: deviceWalletInput.consumerDataHash,
      canonicalRecipient: deviceWalletInput.canonicalRecipient,
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
    if (arg === "--wallet-input") {
      parsed.walletInputPath = argv[i + 1];
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
      "  node scripts/base/consume-wallet-input.cjs --wallet-input <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.walletInputPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const walletInputConsumption = buildWalletInputConsumption({
      walletInput: loadJson(path.resolve(parsed.walletInputPath))
    });
    console.log(JSON.stringify(walletInputConsumption, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildWalletInputConsumption
};
