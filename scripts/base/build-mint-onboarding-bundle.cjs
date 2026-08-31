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

function buildMintOnboardingBundle({ onboardingRecipient }) {
  if (!onboardingRecipient || typeof onboardingRecipient !== "object") {
    throw new Error("onboardingRecipient is required");
  }

  assertEqual(
    onboardingRecipient.path,
    "phil-mint-recipient-onboarding",
    "onboardingRecipient.path"
  );
  assertEqual(
    onboardingRecipient.payloadShape,
    "[fact_high, fact_low]",
    "onboardingRecipient.payloadShape"
  );

  if (!onboardingRecipient.bindingDomain || typeof onboardingRecipient.bindingDomain !== "object") {
    throw new Error("onboardingRecipient.bindingDomain is required");
  }
  if (!onboardingRecipient.deviceMintInputs || typeof onboardingRecipient.deviceMintInputs !== "object") {
    throw new Error("onboardingRecipient.deviceMintInputs is required");
  }
  if (!onboardingRecipient.parityCheck || typeof onboardingRecipient.parityCheck !== "object") {
    throw new Error("onboardingRecipient.parityCheck is required");
  }
  if (!onboardingRecipient.appReadModel || typeof onboardingRecipient.appReadModel !== "object") {
    throw new Error("onboardingRecipient.appReadModel is required");
  }

  const mintInputPreimage = {
    ownerCommitment: normalizeHex32(
      onboardingRecipient.deviceMintInputs.ownerCommitment,
      "deviceMintInputs.ownerCommitment"
    ),
    consumerData: normalizeBytes(
      onboardingRecipient.deviceMintInputs.consumerData,
      "deviceMintInputs.consumerData"
    ),
    consumerDataHash: normalizeHex32(
      onboardingRecipient.deviceMintInputs.consumerDataHash,
      "deviceMintInputs.consumerDataHash"
    )
  };

  const derivedRecipient = normalizeAddress(
    onboardingRecipient.derivedRecipient,
    "onboardingRecipient.derivedRecipient"
  );

  const expectedBaseRecipient =
    onboardingRecipient.parityCheck.expectedBaseRecipient === null
      ? null
      : normalizeAddress(
          onboardingRecipient.parityCheck.expectedBaseRecipient,
          "parityCheck.expectedBaseRecipient"
        );

  if (expectedBaseRecipient !== null) {
    assertTrue(
      onboardingRecipient.parityCheck.matchesBaseRecipient,
      "parityCheck.matchesBaseRecipient"
    );
    assertEqual(
      derivedRecipient.toLowerCase(),
      expectedBaseRecipient.toLowerCase(),
      "derivedRecipient/expectedBaseRecipient"
    );
  }

  assertEqual(
    onboardingRecipient.appReadModel.derivedRecipient,
    derivedRecipient,
    "appReadModel.derivedRecipient"
  );
  assertEqual(
    normalizeHex32(
      onboardingRecipient.appReadModel.consumerDataHash,
      "appReadModel.consumerDataHash"
    ),
    mintInputPreimage.consumerDataHash,
    "appReadModel.consumerDataHash/deviceMintInputs.consumerDataHash"
  );

  return {
    version: 1,
    path: "phil-mint-onboarding-bundle",
    bundleSource: "scripts/base/build-mint-onboarding-bundle.cjs",
    onboardingSource: onboardingRecipient.onboardingSource,
    proofType: onboardingRecipient.proofType,
    payloadShape: onboardingRecipient.payloadShape,
    bindingDomain: {
      label: String(onboardingRecipient.bindingDomain.label || ""),
      hash: normalizeHex32(onboardingRecipient.bindingDomain.hash, "bindingDomain.hash")
    },
    mintInputPreimage,
    recipientBinding: {
      derivedRecipient,
      expectedBaseRecipient,
      parityProven:
        expectedBaseRecipient === null
          ? false
          : derivedRecipient.toLowerCase() === expectedBaseRecipient.toLowerCase()
    },
    appBundle: {
      derivedRecipient,
      consumerDataHash: mintInputPreimage.consumerDataHash,
      parityProven:
        expectedBaseRecipient === null
          ? false
          : derivedRecipient.toLowerCase() === expectedBaseRecipient.toLowerCase()
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--onboarding-recipient") {
      parsed.onboardingRecipientPath = argv[i + 1];
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
      "  node scripts/base/build-mint-onboarding-bundle.cjs --onboarding-recipient <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.onboardingRecipientPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const bundle = buildMintOnboardingBundle({
      onboardingRecipient: loadJson(path.resolve(parsed.onboardingRecipientPath))
    });
    console.log(JSON.stringify(bundle, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildMintOnboardingBundle
};
