const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");
const {
  MINT_RECIPIENT_BINDING_DOMAIN_LABEL,
  MINT_RECIPIENT_BINDING_DOMAIN_HASH,
  deriveCanonicalMintRecipient
} = require("./build-mint-recipient-onboarding.cjs");

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

function consumeMintOnboardingBundle({ onboardingBundle }) {
  if (!onboardingBundle || typeof onboardingBundle !== "object") {
    throw new Error("onboardingBundle is required");
  }

  assertEqual(onboardingBundle.path, "phil-mint-onboarding-bundle", "onboardingBundle.path");
  assertEqual(
    onboardingBundle.payloadShape,
    "[fact_high, fact_low]",
    "onboardingBundle.payloadShape"
  );

  if (!onboardingBundle.bindingDomain || typeof onboardingBundle.bindingDomain !== "object") {
    throw new Error("onboardingBundle.bindingDomain is required");
  }
  if (!onboardingBundle.mintInputPreimage || typeof onboardingBundle.mintInputPreimage !== "object") {
    throw new Error("onboardingBundle.mintInputPreimage is required");
  }
  if (!onboardingBundle.recipientBinding || typeof onboardingBundle.recipientBinding !== "object") {
    throw new Error("onboardingBundle.recipientBinding is required");
  }
  if (!onboardingBundle.appBundle || typeof onboardingBundle.appBundle !== "object") {
    throw new Error("onboardingBundle.appBundle is required");
  }

  assertEqual(
    String(onboardingBundle.bindingDomain.label || ""),
    MINT_RECIPIENT_BINDING_DOMAIN_LABEL,
    "bindingDomain.label"
  );
  assertEqual(
    normalizeHex32(onboardingBundle.bindingDomain.hash, "bindingDomain.hash"),
    MINT_RECIPIENT_BINDING_DOMAIN_HASH,
    "bindingDomain.hash"
  );

  const mintInputPreimage = {
    ownerCommitment: normalizeHex32(
      onboardingBundle.mintInputPreimage.ownerCommitment,
      "mintInputPreimage.ownerCommitment"
    ),
    consumerData: normalizeBytes(
      onboardingBundle.mintInputPreimage.consumerData,
      "mintInputPreimage.consumerData"
    ),
    consumerDataHash: normalizeHex32(
      onboardingBundle.mintInputPreimage.consumerDataHash,
      "mintInputPreimage.consumerDataHash"
    )
  };

  const recomputed = deriveCanonicalMintRecipient({
    ownerCommitment: mintInputPreimage.ownerCommitment,
    consumerData: mintInputPreimage.consumerData
  });

  assertEqual(
    recomputed.consumerDataHash,
    mintInputPreimage.consumerDataHash,
    "recomputed.consumerDataHash/mintInputPreimage.consumerDataHash"
  );

  const derivedRecipient = normalizeAddress(
    onboardingBundle.recipientBinding.derivedRecipient,
    "recipientBinding.derivedRecipient"
  );
  assertEqual(
    recomputed.recipient.toLowerCase(),
    derivedRecipient.toLowerCase(),
    "recomputed.recipient/recipientBinding.derivedRecipient"
  );

  const expectedBaseRecipient =
    onboardingBundle.recipientBinding.expectedBaseRecipient === null
      ? null
      : normalizeAddress(
          onboardingBundle.recipientBinding.expectedBaseRecipient,
          "recipientBinding.expectedBaseRecipient"
        );

  if (expectedBaseRecipient === null) {
    assertEqual(
      onboardingBundle.recipientBinding.parityProven,
      false,
      "recipientBinding.parityProven"
    );
  } else {
    assertTrue(onboardingBundle.recipientBinding.parityProven, "recipientBinding.parityProven");
    assertEqual(
      derivedRecipient.toLowerCase(),
      expectedBaseRecipient.toLowerCase(),
      "derivedRecipient/expectedBaseRecipient"
    );
  }

  assertEqual(
    normalizeAddress(onboardingBundle.appBundle.derivedRecipient, "appBundle.derivedRecipient"),
    derivedRecipient,
    "appBundle.derivedRecipient"
  );
  assertEqual(
    normalizeHex32(onboardingBundle.appBundle.consumerDataHash, "appBundle.consumerDataHash"),
    mintInputPreimage.consumerDataHash,
    "appBundle.consumerDataHash"
  );
  assertEqual(
    onboardingBundle.appBundle.parityProven,
    expectedBaseRecipient === null ? false : true,
    "appBundle.parityProven"
  );

  return {
    version: 1,
    path: "phil-mint-onboarding-bundle-consumption",
    consumptionSource: "scripts/base/consume-mint-onboarding-bundle.cjs",
    bundleSource: onboardingBundle.bundleSource,
    consumedPath: onboardingBundle.path,
    proofType: onboardingBundle.proofType,
    payloadShape: onboardingBundle.payloadShape,
    validationChecks: {
      bundlePathValid: true,
      payloadShapeValid: true,
      bindingDomainValid: true,
      preimageValid: true,
      recipientDerivationValid: true,
      parityValid: expectedBaseRecipient === null ? false : true
    },
    appReadModel: {
      ownerCommitment: mintInputPreimage.ownerCommitment,
      consumerData: mintInputPreimage.consumerData,
      consumerDataHash: mintInputPreimage.consumerDataHash,
      derivedRecipient,
      expectedBaseRecipient,
      parityProven: expectedBaseRecipient === null ? false : true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--onboarding-bundle") {
      parsed.onboardingBundlePath = argv[i + 1];
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
      "  node scripts/base/consume-mint-onboarding-bundle.cjs --onboarding-bundle <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.onboardingBundlePath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const consumption = consumeMintOnboardingBundle({
      onboardingBundle: loadJson(path.resolve(parsed.onboardingBundlePath))
    });
    console.log(JSON.stringify(consumption, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  consumeMintOnboardingBundle
};
