const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_INIT_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_INIT_V1";
const SMART_ACCOUNT_INIT_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_INIT_DOMAIN_LABEL)
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

function deriveDeterministicSmartAccountInit({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetSalt,
  targetAddress
}) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetSalt = normalizeHex32(targetSalt, "targetSalt");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");

  const initPayloadHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "address", "bytes32", "bytes32", "address"],
      [
        SMART_ACCOUNT_INIT_DOMAIN_HASH,
        normalizedOwnerCommitment,
        normalizedConsumerDataHash,
        normalizedCanonicalRecipient,
        normalizedTargetId,
        normalizedTargetSalt,
        normalizedTargetAddress
      ]
    )
  );

  const initCommitment = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_INIT_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        initPayloadHash
      ]
    )
  );

  return {
    ownerCommitment: normalizedOwnerCommitment,
    consumerDataHash: normalizedConsumerDataHash,
    canonicalRecipient: normalizedCanonicalRecipient,
    walletId: normalizedWalletId,
    targetId: normalizedTargetId,
    targetSalt: normalizedTargetSalt,
    targetAddress: normalizedTargetAddress,
    initPayloadHash,
    initCommitment
  };
}

function buildSmartAccountInit({ smartAccountTarget }) {
  if (!smartAccountTarget || typeof smartAccountTarget !== "object") {
    throw new Error("smartAccountTarget is required");
  }

  assertEqual(smartAccountTarget.path, "phil-smart-account-target", "smartAccountTarget.path");
  assertEqual(
    smartAccountTarget.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountTarget.payloadShape"
  );

  if (!smartAccountTarget.validationChecks || typeof smartAccountTarget.validationChecks !== "object") {
    throw new Error("smartAccountTarget.validationChecks is required");
  }
  if (
    !smartAccountTarget.smartAccountTargetSummary ||
    typeof smartAccountTarget.smartAccountTargetSummary !== "object"
  ) {
    throw new Error("smartAccountTarget.smartAccountTargetSummary is required");
  }
  if (
    !smartAccountTarget.smartAccountTarget ||
    typeof smartAccountTarget.smartAccountTarget !== "object"
  ) {
    throw new Error("smartAccountTarget.smartAccountTarget is required");
  }
  if (
    !smartAccountTarget.appSmartAccountTarget ||
    typeof smartAccountTarget.appSmartAccountTarget !== "object"
  ) {
    throw new Error("smartAccountTarget.appSmartAccountTarget is required");
  }

  assertTrue(
    smartAccountTarget.validationChecks.walletArtifactPathValid,
    "validationChecks.walletArtifactPathValid"
  );
  assertTrue(
    smartAccountTarget.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountTarget.validationChecks.upstreamWalletArtifactValid,
    "validationChecks.upstreamWalletArtifactValid"
  );
  assertTrue(
    smartAccountTarget.validationChecks.deterministicSmartAccountTargetDerived,
    "validationChecks.deterministicSmartAccountTargetDerived"
  );
  assertTrue(
    smartAccountTarget.smartAccountTargetSummary.ready,
    "smartAccountTargetSummary.ready"
  );
  assertEqual(
    smartAccountTarget.smartAccountTargetSummary.status,
    "smart-account-target-ready",
    "smartAccountTargetSummary.status"
  );
  assertTrue(
    smartAccountTarget.smartAccountTargetSummary.parityProven,
    "smartAccountTargetSummary.parityProven"
  );

  const deterministicSmartAccountTarget = {
    ownerCommitment: normalizeHex32(
      smartAccountTarget.smartAccountTarget.ownerCommitment,
      "smartAccountTarget.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountTarget.smartAccountTarget.consumerDataHash,
      "smartAccountTarget.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountTarget.smartAccountTarget.canonicalRecipient,
      "smartAccountTarget.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountTarget.smartAccountTarget.walletId,
      "smartAccountTarget.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountTarget.smartAccountTarget.targetId,
      "smartAccountTarget.targetId"
    ),
    targetSalt: normalizeHex32(
      smartAccountTarget.smartAccountTarget.targetSalt,
      "smartAccountTarget.targetSalt"
    ),
    targetAddress: normalizeAddress(
      smartAccountTarget.smartAccountTarget.targetAddress,
      "smartAccountTarget.targetAddress"
    )
  };

  const appSmartAccountTarget = {
    recipient: normalizeAddress(
      smartAccountTarget.appSmartAccountTarget.recipient,
      "appSmartAccountTarget.recipient"
    ),
    targetId: normalizeHex32(
      smartAccountTarget.appSmartAccountTarget.targetId,
      "appSmartAccountTarget.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountTarget.appSmartAccountTarget.targetAddress,
      "appSmartAccountTarget.targetAddress"
    ),
    ready: smartAccountTarget.appSmartAccountTarget.ready === true,
    status: String(smartAccountTarget.appSmartAccountTarget.status || ""),
    parityProven: smartAccountTarget.appSmartAccountTarget.parityProven === true
  };

  assertTrue(appSmartAccountTarget.ready, "appSmartAccountTarget.ready");
  assertEqual(
    appSmartAccountTarget.status,
    "smart-account-target-ready",
    "appSmartAccountTarget.status"
  );
  assertTrue(
    appSmartAccountTarget.parityProven,
    "appSmartAccountTarget.parityProven"
  );
  assertEqual(
    appSmartAccountTarget.recipient.toLowerCase(),
    deterministicSmartAccountTarget.canonicalRecipient.toLowerCase(),
    "appSmartAccountTarget.recipient/smartAccountTarget.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountTarget.targetId,
    deterministicSmartAccountTarget.targetId,
    "appSmartAccountTarget.targetId/smartAccountTarget.targetId"
  );
  assertEqual(
    appSmartAccountTarget.targetAddress.toLowerCase(),
    deterministicSmartAccountTarget.targetAddress.toLowerCase(),
    "appSmartAccountTarget.targetAddress/smartAccountTarget.targetAddress"
  );

  const smartAccountInit = deriveDeterministicSmartAccountInit({
    ownerCommitment: deterministicSmartAccountTarget.ownerCommitment,
    consumerDataHash: deterministicSmartAccountTarget.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountTarget.canonicalRecipient,
    walletId: deterministicSmartAccountTarget.walletId,
    targetId: deterministicSmartAccountTarget.targetId,
    targetSalt: deterministicSmartAccountTarget.targetSalt,
    targetAddress: deterministicSmartAccountTarget.targetAddress
  });

  return {
    version: 1,
    path: "phil-smart-account-init",
    smartAccountInitSource: "scripts/base/build-smart-account-init.cjs",
    smartAccountTargetSource: smartAccountTarget.smartAccountTargetSource,
    consumedPath: smartAccountTarget.path,
    proofType: smartAccountTarget.proofType,
    payloadShape: smartAccountTarget.payloadShape,
    smartAccountInitDomain: {
      label: SMART_ACCOUNT_INIT_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_INIT_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountTargetPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountTargetValid: true,
      deterministicSmartAccountInitDerived: true
    },
    smartAccountInitSummary: {
      ready: true,
      status: "smart-account-init-ready",
      reason: "validated-smart-account-target",
      parityProven: true
    },
    smartAccountInit: {
      ownerCommitment: smartAccountInit.ownerCommitment,
      consumerDataHash: smartAccountInit.consumerDataHash,
      canonicalRecipient: smartAccountInit.canonicalRecipient,
      walletId: smartAccountInit.walletId,
      targetId: smartAccountInit.targetId,
      targetSalt: smartAccountInit.targetSalt,
      targetAddress: smartAccountInit.targetAddress,
      initPayloadHash: smartAccountInit.initPayloadHash,
      initCommitment: smartAccountInit.initCommitment
    },
    appSmartAccountInit: {
      recipient: smartAccountInit.canonicalRecipient,
      targetId: smartAccountInit.targetId,
      targetAddress: smartAccountInit.targetAddress,
      initPayloadHash: smartAccountInit.initPayloadHash,
      initCommitment: smartAccountInit.initCommitment,
      ready: true,
      status: "smart-account-init-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-target") {
      parsed.smartAccountTargetPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-init.cjs --smart-account-target <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountTargetPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountInit = buildSmartAccountInit({
      smartAccountTarget: loadJson(path.resolve(parsed.smartAccountTargetPath))
    });
    console.log(JSON.stringify(smartAccountInit, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_INIT_DOMAIN_LABEL,
  SMART_ACCOUNT_INIT_DOMAIN_HASH,
  deriveDeterministicSmartAccountInit,
  buildSmartAccountInit
};
