const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_TARGET_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_TARGET_V1";
const SMART_ACCOUNT_TARGET_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_TARGET_DOMAIN_LABEL)
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

function deriveDeterministicSmartAccountTarget({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  walletSalt
}) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedWalletSalt = normalizeHex32(walletSalt, "walletSalt");

  const targetId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "address"],
      [
        SMART_ACCOUNT_TARGET_DOMAIN_HASH,
        normalizedOwnerCommitment,
        normalizedConsumerDataHash,
        normalizedWalletId,
        normalizedCanonicalRecipient
      ]
    )
  );

  const targetSalt = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32"],
      [SMART_ACCOUNT_TARGET_DOMAIN_HASH, normalizedWalletSalt, targetId]
    )
  );

  const targetAddress = ethers.getAddress(`0x${targetId.slice(-40)}`);
  if (targetAddress === ethers.ZeroAddress) {
    throw new Error("Derived smart account target address is zero");
  }

  return {
    ownerCommitment: normalizedOwnerCommitment,
    consumerDataHash: normalizedConsumerDataHash,
    canonicalRecipient: normalizedCanonicalRecipient,
    walletId: normalizedWalletId,
    walletSalt: normalizedWalletSalt,
    targetId,
    targetSalt,
    targetAddress
  };
}

function buildSmartAccountTarget({ walletArtifact }) {
  if (!walletArtifact || typeof walletArtifact !== "object") {
    throw new Error("walletArtifact is required");
  }

  assertEqual(walletArtifact.path, "phil-wallet-artifact", "walletArtifact.path");
  assertEqual(walletArtifact.payloadShape, "[fact_high, fact_low]", "walletArtifact.payloadShape");

  if (!walletArtifact.validationChecks || typeof walletArtifact.validationChecks !== "object") {
    throw new Error("walletArtifact.validationChecks is required");
  }
  if (
    !walletArtifact.deterministicWalletSummary ||
    typeof walletArtifact.deterministicWalletSummary !== "object"
  ) {
    throw new Error("walletArtifact.deterministicWalletSummary is required");
  }
  if (
    !walletArtifact.deterministicWallet ||
    typeof walletArtifact.deterministicWallet !== "object"
  ) {
    throw new Error("walletArtifact.deterministicWallet is required");
  }
  if (!walletArtifact.appWalletArtifact || typeof walletArtifact.appWalletArtifact !== "object") {
    throw new Error("walletArtifact.appWalletArtifact is required");
  }

  assertTrue(
    walletArtifact.validationChecks.walletInputConsumptionPathValid,
    "validationChecks.walletInputConsumptionPathValid"
  );
  assertTrue(
    walletArtifact.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    walletArtifact.validationChecks.upstreamWalletInputValid,
    "validationChecks.upstreamWalletInputValid"
  );
  assertTrue(
    walletArtifact.validationChecks.deterministicWalletDerived,
    "validationChecks.deterministicWalletDerived"
  );
  assertTrue(walletArtifact.deterministicWalletSummary.ready, "deterministicWalletSummary.ready");
  assertEqual(
    walletArtifact.deterministicWalletSummary.status,
    "wallet-artifact-ready",
    "deterministicWalletSummary.status"
  );
  assertTrue(
    walletArtifact.deterministicWalletSummary.parityProven,
    "deterministicWalletSummary.parityProven"
  );

  const deterministicWallet = {
    ownerCommitment: normalizeHex32(
      walletArtifact.deterministicWallet.ownerCommitment,
      "deterministicWallet.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      walletArtifact.deterministicWallet.consumerDataHash,
      "deterministicWallet.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      walletArtifact.deterministicWallet.canonicalRecipient,
      "deterministicWallet.canonicalRecipient"
    ),
    walletId: normalizeHex32(walletArtifact.deterministicWallet.walletId, "deterministicWallet.walletId"),
    walletSalt: normalizeHex32(
      walletArtifact.deterministicWallet.walletSalt,
      "deterministicWallet.walletSalt"
    )
  };

  const appWalletArtifact = {
    recipient: normalizeAddress(walletArtifact.appWalletArtifact.recipient, "appWalletArtifact.recipient"),
    walletId: normalizeHex32(walletArtifact.appWalletArtifact.walletId, "appWalletArtifact.walletId"),
    walletSalt: normalizeHex32(
      walletArtifact.appWalletArtifact.walletSalt,
      "appWalletArtifact.walletSalt"
    ),
    ready: walletArtifact.appWalletArtifact.ready === true,
    status: String(walletArtifact.appWalletArtifact.status || ""),
    parityProven: walletArtifact.appWalletArtifact.parityProven === true
  };

  assertTrue(appWalletArtifact.ready, "appWalletArtifact.ready");
  assertEqual(appWalletArtifact.status, "wallet-artifact-ready", "appWalletArtifact.status");
  assertTrue(appWalletArtifact.parityProven, "appWalletArtifact.parityProven");
  assertEqual(
    appWalletArtifact.recipient.toLowerCase(),
    deterministicWallet.canonicalRecipient.toLowerCase(),
    "appWalletArtifact.recipient/deterministicWallet.canonicalRecipient"
  );
  assertEqual(
    appWalletArtifact.walletId,
    deterministicWallet.walletId,
    "appWalletArtifact.walletId/deterministicWallet.walletId"
  );
  assertEqual(
    appWalletArtifact.walletSalt,
    deterministicWallet.walletSalt,
    "appWalletArtifact.walletSalt/deterministicWallet.walletSalt"
  );

  const smartAccountTarget = deriveDeterministicSmartAccountTarget({
    ownerCommitment: deterministicWallet.ownerCommitment,
    consumerDataHash: deterministicWallet.consumerDataHash,
    canonicalRecipient: deterministicWallet.canonicalRecipient,
    walletId: deterministicWallet.walletId,
    walletSalt: deterministicWallet.walletSalt
  });

  return {
    version: 1,
    path: "phil-smart-account-target",
    smartAccountTargetSource: "scripts/base/build-smart-account-target.cjs",
    walletArtifactSource: walletArtifact.walletArtifactSource,
    consumedPath: walletArtifact.path,
    proofType: walletArtifact.proofType,
    payloadShape: walletArtifact.payloadShape,
    smartAccountTargetDomain: {
      label: SMART_ACCOUNT_TARGET_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_TARGET_DOMAIN_HASH
    },
    validationChecks: {
      walletArtifactPathValid: true,
      payloadShapeValid: true,
      upstreamWalletArtifactValid: true,
      deterministicSmartAccountTargetDerived: true
    },
    smartAccountTargetSummary: {
      ready: true,
      status: "smart-account-target-ready",
      reason: "validated-wallet-artifact",
      parityProven: true
    },
    smartAccountTarget: {
      ownerCommitment: smartAccountTarget.ownerCommitment,
      consumerDataHash: smartAccountTarget.consumerDataHash,
      canonicalRecipient: smartAccountTarget.canonicalRecipient,
      walletId: smartAccountTarget.walletId,
      targetId: smartAccountTarget.targetId,
      targetSalt: smartAccountTarget.targetSalt,
      targetAddress: smartAccountTarget.targetAddress
    },
    appSmartAccountTarget: {
      recipient: smartAccountTarget.canonicalRecipient,
      targetId: smartAccountTarget.targetId,
      targetAddress: smartAccountTarget.targetAddress,
      ready: true,
      status: "smart-account-target-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--wallet-artifact") {
      parsed.walletArtifactPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-target.cjs --wallet-artifact <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.walletArtifactPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountTarget = buildSmartAccountTarget({
      walletArtifact: loadJson(path.resolve(parsed.walletArtifactPath))
    });
    console.log(JSON.stringify(smartAccountTarget, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_TARGET_DOMAIN_LABEL,
  SMART_ACCOUNT_TARGET_DOMAIN_HASH,
  deriveDeterministicSmartAccountTarget,
  buildSmartAccountTarget
};
