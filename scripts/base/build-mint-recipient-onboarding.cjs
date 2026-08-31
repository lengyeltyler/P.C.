const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const MINT_RECIPIENT_BINDING_DOMAIN_LABEL = "PHIL_MINT_RECIPIENT_BINDING_V1";
const MINT_RECIPIENT_BINDING_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(MINT_RECIPIENT_BINDING_DOMAIN_LABEL)
);

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

function deriveCanonicalMintRecipient({ ownerCommitment, consumerData }) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerData = normalizeBytes(consumerData, "consumerData");
  const consumerDataHash = ethers.keccak256(normalizedConsumerData);
  const recipientHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes"],
      [MINT_RECIPIENT_BINDING_DOMAIN_HASH, normalizedOwnerCommitment, normalizedConsumerData]
    )
  );
  const recipient = ethers.getAddress(`0x${recipientHash.slice(-40)}`);

  if (recipient === ethers.ZeroAddress) {
    throw new Error("Derived recipient is zero address");
  }

  return {
    ownerCommitment: normalizedOwnerCommitment,
    consumerData: normalizedConsumerData,
    consumerDataHash,
    recipient
  };
}

function buildMintRecipientOnboarding({
  ownerCommitment,
  consumerData,
  expectedBaseRecipient
}) {
  const derived = deriveCanonicalMintRecipient({
    ownerCommitment,
    consumerData
  });

  const normalizedExpectedBaseRecipient =
    expectedBaseRecipient === undefined || expectedBaseRecipient === null
      ? null
      : normalizeAddress(expectedBaseRecipient, "expectedBaseRecipient");

  return {
    version: 1,
    path: "phil-mint-recipient-onboarding",
    onboardingSource: "scripts/base/build-mint-recipient-onboarding.cjs",
    proofType: "stwo-unlock-keccak-v1",
    payloadShape: "[fact_high, fact_low]",
    bindingDomain: {
      label: MINT_RECIPIENT_BINDING_DOMAIN_LABEL,
      hash: MINT_RECIPIENT_BINDING_DOMAIN_HASH
    },
    deviceMintInputs: {
      ownerCommitment: derived.ownerCommitment,
      consumerData: derived.consumerData,
      consumerDataHash: derived.consumerDataHash
    },
    derivedRecipient: derived.recipient,
    parityCheck: {
      expectedBaseRecipient: normalizedExpectedBaseRecipient,
      matchesBaseRecipient:
        normalizedExpectedBaseRecipient === null
          ? null
          : derived.recipient.toLowerCase() === normalizedExpectedBaseRecipient.toLowerCase()
    },
    appReadModel: {
      derivedRecipient: derived.recipient,
      consumerDataHash: derived.consumerDataHash,
      parityProven:
        normalizedExpectedBaseRecipient === null
          ? false
          : derived.recipient.toLowerCase() === normalizedExpectedBaseRecipient.toLowerCase()
    }
  };
}

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--owner-commitment") {
      parsed.ownerCommitment = argv[i + 1];
      i += 1;
    } else if (arg === "--consumer-data") {
      parsed.consumerData = argv[i + 1];
      i += 1;
    } else if (arg === "--expected-base-recipient") {
      parsed.expectedBaseRecipient = argv[i + 1];
      i += 1;
    } else if (arg === "--from-json") {
      parsed.fromJson = argv[i + 1];
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
      "  node scripts/base/build-mint-recipient-onboarding.cjs --owner-commitment <hex32> --consumer-data <hex> [--expected-base-recipient <address>]",
      "  node scripts/base/build-mint-recipient-onboarding.cjs --from-json <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help) {
      printUsage();
      process.exit(0);
    }

    let onboarding;
    if (parsed.fromJson) {
      const input = loadJson(path.resolve(parsed.fromJson));
      onboarding = buildMintRecipientOnboarding(input);
    } else {
      if (!parsed.ownerCommitment || !parsed.consumerData) {
        printUsage();
        process.exit(1);
      }
      onboarding = buildMintRecipientOnboarding({
        ownerCommitment: parsed.ownerCommitment,
        consumerData: parsed.consumerData,
        expectedBaseRecipient: parsed.expectedBaseRecipient
      });
    }

    console.log(JSON.stringify(onboarding, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  MINT_RECIPIENT_BINDING_DOMAIN_LABEL,
  MINT_RECIPIENT_BINDING_DOMAIN_HASH,
  deriveCanonicalMintRecipient,
  buildMintRecipientOnboarding
};
