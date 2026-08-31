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

function buildMintIntent({ onboardingReadiness }) {
  if (!onboardingReadiness || typeof onboardingReadiness !== "object") {
    throw new Error("onboardingReadiness is required");
  }

  assertEqual(onboardingReadiness.path, "phil-mint-onboarding-readiness", "onboardingReadiness.path");
  assertEqual(
    onboardingReadiness.payloadShape,
    "[fact_high, fact_low]",
    "onboardingReadiness.payloadShape"
  );

  if (!onboardingReadiness.validationChecks || typeof onboardingReadiness.validationChecks !== "object") {
    throw new Error("onboardingReadiness.validationChecks is required");
  }
  if (!onboardingReadiness.readinessSummary || typeof onboardingReadiness.readinessSummary !== "object") {
    throw new Error("onboardingReadiness.readinessSummary is required");
  }
  if (!onboardingReadiness.appReadiness || typeof onboardingReadiness.appReadiness !== "object") {
    throw new Error("onboardingReadiness.appReadiness is required");
  }

  assertTrue(
    onboardingReadiness.validationChecks.consumptionPathValid,
    "validationChecks.consumptionPathValid"
  );
  assertTrue(
    onboardingReadiness.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    onboardingReadiness.validationChecks.onboardingFieldsValid,
    "validationChecks.onboardingFieldsValid"
  );
  assertTrue(
    onboardingReadiness.validationChecks.recipientParityValid,
    "validationChecks.recipientParityValid"
  );
  assertTrue(onboardingReadiness.readinessSummary.ready, "readinessSummary.ready");
  assertEqual(onboardingReadiness.readinessSummary.status, "ready", "readinessSummary.status");
  assertTrue(
    onboardingReadiness.readinessSummary.parityProven,
    "readinessSummary.parityProven"
  );

  const appReadiness = {
    ownerCommitment: normalizeHex32(
      onboardingReadiness.appReadiness.ownerCommitment,
      "appReadiness.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      onboardingReadiness.appReadiness.consumerDataHash,
      "appReadiness.consumerDataHash"
    ),
    derivedRecipient: normalizeAddress(
      onboardingReadiness.appReadiness.derivedRecipient,
      "appReadiness.derivedRecipient"
    ),
    expectedBaseRecipient: normalizeAddress(
      onboardingReadiness.appReadiness.expectedBaseRecipient,
      "appReadiness.expectedBaseRecipient"
    ),
    parityProven: onboardingReadiness.appReadiness.parityProven === true
  };

  assertTrue(appReadiness.parityProven, "appReadiness.parityProven");
  assertEqual(
    appReadiness.derivedRecipient.toLowerCase(),
    appReadiness.expectedBaseRecipient.toLowerCase(),
    "appReadiness.derivedRecipient/appReadiness.expectedBaseRecipient"
  );

  return {
    version: 1,
    path: "phil-mint-intent",
    intentSource: "scripts/base/build-mint-intent.cjs",
    readinessSource: onboardingReadiness.readinessSource,
    consumedPath: onboardingReadiness.path,
    proofType: onboardingReadiness.proofType,
    payloadShape: onboardingReadiness.payloadShape,
    validationChecks: {
      readinessPathValid: true,
      payloadShapeValid: true,
      readinessValid: true,
      recipientBindingValid: true
    },
    intentSummary: {
      ready: true,
      status: "ready-to-mint",
      reason: "validated-onboarding-readiness",
      parityProven: true
    },
    deviceMintIntent: {
      ownerCommitment: appReadiness.ownerCommitment,
      consumerDataHash: appReadiness.consumerDataHash,
      canonicalRecipient: appReadiness.derivedRecipient
    },
    appIntent: {
      recipient: appReadiness.derivedRecipient,
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
    if (arg === "--onboarding-readiness") {
      parsed.onboardingReadinessPath = argv[i + 1];
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
      "  node scripts/base/build-mint-intent.cjs --onboarding-readiness <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.onboardingReadinessPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const mintIntent = buildMintIntent({
      onboardingReadiness: loadJson(path.resolve(parsed.onboardingReadinessPath))
    });
    console.log(JSON.stringify(mintIntent, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildMintIntent
};
