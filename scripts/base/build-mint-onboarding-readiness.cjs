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

function buildMintOnboardingReadiness({ onboardingBundleConsumption }) {
  if (!onboardingBundleConsumption || typeof onboardingBundleConsumption !== "object") {
    throw new Error("onboardingBundleConsumption is required");
  }

  assertEqual(
    onboardingBundleConsumption.path,
    "phil-mint-onboarding-bundle-consumption",
    "onboardingBundleConsumption.path"
  );
  assertEqual(
    onboardingBundleConsumption.payloadShape,
    "[fact_high, fact_low]",
    "onboardingBundleConsumption.payloadShape"
  );

  if (
    !onboardingBundleConsumption.validationChecks ||
    typeof onboardingBundleConsumption.validationChecks !== "object"
  ) {
    throw new Error("onboardingBundleConsumption.validationChecks is required");
  }
  if (
    !onboardingBundleConsumption.appReadModel ||
    typeof onboardingBundleConsumption.appReadModel !== "object"
  ) {
    throw new Error("onboardingBundleConsumption.appReadModel is required");
  }

  assertTrue(
    onboardingBundleConsumption.validationChecks.bundlePathValid,
    "validationChecks.bundlePathValid"
  );
  assertTrue(
    onboardingBundleConsumption.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    onboardingBundleConsumption.validationChecks.bindingDomainValid,
    "validationChecks.bindingDomainValid"
  );
  assertTrue(
    onboardingBundleConsumption.validationChecks.preimageValid,
    "validationChecks.preimageValid"
  );
  assertTrue(
    onboardingBundleConsumption.validationChecks.recipientDerivationValid,
    "validationChecks.recipientDerivationValid"
  );
  assertTrue(
    onboardingBundleConsumption.validationChecks.parityValid,
    "validationChecks.parityValid"
  );

  const appReadModel = {
    ownerCommitment: normalizeHex32(
      onboardingBundleConsumption.appReadModel.ownerCommitment,
      "appReadModel.ownerCommitment"
    ),
    consumerData: normalizeBytes(
      onboardingBundleConsumption.appReadModel.consumerData,
      "appReadModel.consumerData"
    ),
    consumerDataHash: normalizeHex32(
      onboardingBundleConsumption.appReadModel.consumerDataHash,
      "appReadModel.consumerDataHash"
    ),
    derivedRecipient: normalizeAddress(
      onboardingBundleConsumption.appReadModel.derivedRecipient,
      "appReadModel.derivedRecipient"
    ),
    expectedBaseRecipient: normalizeAddress(
      onboardingBundleConsumption.appReadModel.expectedBaseRecipient,
      "appReadModel.expectedBaseRecipient"
    ),
    parityProven: onboardingBundleConsumption.appReadModel.parityProven === true
  };

  assertTrue(appReadModel.parityProven, "appReadModel.parityProven");
  assertEqual(
    appReadModel.derivedRecipient.toLowerCase(),
    appReadModel.expectedBaseRecipient.toLowerCase(),
    "appReadModel.derivedRecipient/appReadModel.expectedBaseRecipient"
  );

  return {
    version: 1,
    path: "phil-mint-onboarding-readiness",
    readinessSource: "scripts/base/build-mint-onboarding-readiness.cjs",
    consumptionSource: onboardingBundleConsumption.consumptionSource,
    consumedPath: onboardingBundleConsumption.path,
    proofType: onboardingBundleConsumption.proofType,
    payloadShape: onboardingBundleConsumption.payloadShape,
    validationChecks: {
      consumptionPathValid: true,
      payloadShapeValid: true,
      onboardingFieldsValid: true,
      recipientParityValid: true
    },
    readinessSummary: {
      ready: true,
      status: "ready",
      reason: "validated-onboarding-bundle-consumption",
      parityProven: true
    },
    appReadiness: {
      ownerCommitment: appReadModel.ownerCommitment,
      consumerDataHash: appReadModel.consumerDataHash,
      derivedRecipient: appReadModel.derivedRecipient,
      expectedBaseRecipient: appReadModel.expectedBaseRecipient,
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--onboarding-bundle-consumption") {
      parsed.onboardingBundleConsumptionPath = argv[i + 1];
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
      "  node scripts/base/build-mint-onboarding-readiness.cjs --onboarding-bundle-consumption <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.onboardingBundleConsumptionPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const readiness = buildMintOnboardingReadiness({
      onboardingBundleConsumption: loadJson(path.resolve(parsed.onboardingBundleConsumptionPath))
    });
    console.log(JSON.stringify(readiness, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildMintOnboardingReadiness
};
