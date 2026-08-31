const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const WALLET_ARTIFACT_DOMAIN_LABEL = "PHIL_DETERMINISTIC_WALLET_V1";
const WALLET_ARTIFACT_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(WALLET_ARTIFACT_DOMAIN_LABEL)
);

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

function deriveDeterministicWallet({ ownerCommitment, consumerDataHash, canonicalRecipient }) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");

  const walletId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "address"],
      [
        WALLET_ARTIFACT_DOMAIN_HASH,
        normalizedOwnerCommitment,
        normalizedConsumerDataHash,
        normalizedCanonicalRecipient
      ]
    )
  );

  const walletSalt = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [WALLET_ARTIFACT_DOMAIN_HASH, walletId]
    )
  );

  return {
    ownerCommitment: normalizedOwnerCommitment,
    consumerDataHash: normalizedConsumerDataHash,
    canonicalRecipient: normalizedCanonicalRecipient,
    walletId,
    walletSalt
  };
}

function buildWalletArtifact({ walletInputConsumption }) {
  if (!walletInputConsumption || typeof walletInputConsumption !== "object") {
    throw new Error("walletInputConsumption is required");
  }

  assertEqual(
    walletInputConsumption.path,
    "phil-wallet-input-consumption",
    "walletInputConsumption.path"
  );
  assertEqual(
    walletInputConsumption.payloadShape,
    "[fact_high, fact_low]",
    "walletInputConsumption.payloadShape"
  );

  if (
    !walletInputConsumption.validationChecks ||
    typeof walletInputConsumption.validationChecks !== "object"
  ) {
    throw new Error("walletInputConsumption.validationChecks is required");
  }
  if (
    !walletInputConsumption.appReadModel ||
    typeof walletInputConsumption.appReadModel !== "object"
  ) {
    throw new Error("walletInputConsumption.appReadModel is required");
  }

  assertTrue(
    walletInputConsumption.validationChecks.walletInputPathValid,
    "validationChecks.walletInputPathValid"
  );
  assertTrue(
    walletInputConsumption.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    walletInputConsumption.validationChecks.walletInputFieldsValid,
    "validationChecks.walletInputFieldsValid"
  );
  assertTrue(
    walletInputConsumption.validationChecks.recipientConsistencyValid,
    "validationChecks.recipientConsistencyValid"
  );

  const appReadModel = {
    ownerCommitment: normalizeHex32(
      walletInputConsumption.appReadModel.ownerCommitment,
      "appReadModel.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      walletInputConsumption.appReadModel.consumerDataHash,
      "appReadModel.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      walletInputConsumption.appReadModel.canonicalRecipient,
      "appReadModel.canonicalRecipient"
    ),
    ready: walletInputConsumption.appReadModel.ready === true,
    status: String(walletInputConsumption.appReadModel.status || ""),
    parityProven: walletInputConsumption.appReadModel.parityProven === true
  };

  assertTrue(appReadModel.ready, "appReadModel.ready");
  assertEqual(appReadModel.status, "wallet-input-ready", "appReadModel.status");
  assertTrue(appReadModel.parityProven, "appReadModel.parityProven");

  const deterministicWallet = deriveDeterministicWallet({
    ownerCommitment: appReadModel.ownerCommitment,
    consumerDataHash: appReadModel.consumerDataHash,
    canonicalRecipient: appReadModel.canonicalRecipient
  });

  return {
    version: 1,
    path: "phil-wallet-artifact",
    walletArtifactSource: "scripts/base/build-wallet-artifact.cjs",
    walletInputConsumptionSource: walletInputConsumption.consumptionSource,
    consumedPath: walletInputConsumption.path,
    proofType: walletInputConsumption.proofType,
    payloadShape: walletInputConsumption.payloadShape,
    walletGenerationDomain: {
      label: WALLET_ARTIFACT_DOMAIN_LABEL,
      hash: WALLET_ARTIFACT_DOMAIN_HASH
    },
    validationChecks: {
      walletInputConsumptionPathValid: true,
      payloadShapeValid: true,
      upstreamWalletInputValid: true,
      deterministicWalletDerived: true
    },
    deterministicWalletSummary: {
      ready: true,
      status: "wallet-artifact-ready",
      reason: "validated-wallet-input-consumption",
      parityProven: true
    },
    deterministicWallet: {
      ownerCommitment: deterministicWallet.ownerCommitment,
      consumerDataHash: deterministicWallet.consumerDataHash,
      canonicalRecipient: deterministicWallet.canonicalRecipient,
      walletId: deterministicWallet.walletId,
      walletSalt: deterministicWallet.walletSalt
    },
    appWalletArtifact: {
      recipient: deterministicWallet.canonicalRecipient,
      walletId: deterministicWallet.walletId,
      walletSalt: deterministicWallet.walletSalt,
      ready: true,
      status: "wallet-artifact-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--wallet-input-consumption") {
      parsed.walletInputConsumptionPath = argv[i + 1];
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
      "  node scripts/base/build-wallet-artifact.cjs --wallet-input-consumption <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.walletInputConsumptionPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const walletArtifact = buildWalletArtifact({
      walletInputConsumption: loadJson(path.resolve(parsed.walletInputConsumptionPath))
    });
    console.log(JSON.stringify(walletArtifact, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  WALLET_ARTIFACT_DOMAIN_LABEL,
  WALLET_ARTIFACT_DOMAIN_HASH,
  deriveDeterministicWallet,
  buildWalletArtifact
};
