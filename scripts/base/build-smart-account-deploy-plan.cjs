const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_DEPLOY_PLAN_V1";
const SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_LABEL)
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

function deriveDeterministicSmartAccountDeployPlan({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetSalt,
  targetAddress,
  initPayloadHash,
  initCommitment
}) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetSalt = normalizeHex32(targetSalt, "targetSalt");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedInitPayloadHash = normalizeHex32(initPayloadHash, "initPayloadHash");
  const normalizedInitCommitment = normalizeHex32(initCommitment, "initCommitment");

  const deploymentEnvelopeHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "address", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_HASH,
        normalizedTargetId,
        normalizedTargetAddress,
        normalizedTargetSalt,
        normalizedInitPayloadHash,
        normalizedInitCommitment
      ]
    )
  );

  const deploymentPlanId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "address"],
      [
        SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_HASH,
        normalizedWalletId,
        normalizedOwnerCommitment,
        deploymentEnvelopeHash,
        normalizedCanonicalRecipient
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
    initPayloadHash: normalizedInitPayloadHash,
    initCommitment: normalizedInitCommitment,
    deploymentMode: "deterministic-smart-account-init",
    deploymentEnvelopeHash,
    deploymentPlanId
  };
}

function buildSmartAccountDeployPlan({ smartAccountInit }) {
  if (!smartAccountInit || typeof smartAccountInit !== "object") {
    throw new Error("smartAccountInit is required");
  }

  assertEqual(smartAccountInit.path, "phil-smart-account-init", "smartAccountInit.path");
  assertEqual(smartAccountInit.payloadShape, "[fact_high, fact_low]", "smartAccountInit.payloadShape");

  if (!smartAccountInit.validationChecks || typeof smartAccountInit.validationChecks !== "object") {
    throw new Error("smartAccountInit.validationChecks is required");
  }
  if (
    !smartAccountInit.smartAccountInitSummary ||
    typeof smartAccountInit.smartAccountInitSummary !== "object"
  ) {
    throw new Error("smartAccountInit.smartAccountInitSummary is required");
  }
  if (!smartAccountInit.smartAccountInit || typeof smartAccountInit.smartAccountInit !== "object") {
    throw new Error("smartAccountInit.smartAccountInit is required");
  }
  if (
    !smartAccountInit.appSmartAccountInit ||
    typeof smartAccountInit.appSmartAccountInit !== "object"
  ) {
    throw new Error("smartAccountInit.appSmartAccountInit is required");
  }

  assertTrue(
    smartAccountInit.validationChecks.smartAccountTargetPathValid,
    "validationChecks.smartAccountTargetPathValid"
  );
  assertTrue(
    smartAccountInit.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountInit.validationChecks.upstreamSmartAccountTargetValid,
    "validationChecks.upstreamSmartAccountTargetValid"
  );
  assertTrue(
    smartAccountInit.validationChecks.deterministicSmartAccountInitDerived,
    "validationChecks.deterministicSmartAccountInitDerived"
  );
  assertTrue(smartAccountInit.smartAccountInitSummary.ready, "smartAccountInitSummary.ready");
  assertEqual(
    smartAccountInit.smartAccountInitSummary.status,
    "smart-account-init-ready",
    "smartAccountInitSummary.status"
  );
  assertTrue(
    smartAccountInit.smartAccountInitSummary.parityProven,
    "smartAccountInitSummary.parityProven"
  );

  const deterministicSmartAccountInit = {
    ownerCommitment: normalizeHex32(
      smartAccountInit.smartAccountInit.ownerCommitment,
      "smartAccountInit.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountInit.smartAccountInit.consumerDataHash,
      "smartAccountInit.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountInit.smartAccountInit.canonicalRecipient,
      "smartAccountInit.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountInit.smartAccountInit.walletId,
      "smartAccountInit.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountInit.smartAccountInit.targetId,
      "smartAccountInit.targetId"
    ),
    targetSalt: normalizeHex32(
      smartAccountInit.smartAccountInit.targetSalt,
      "smartAccountInit.targetSalt"
    ),
    targetAddress: normalizeAddress(
      smartAccountInit.smartAccountInit.targetAddress,
      "smartAccountInit.targetAddress"
    ),
    initPayloadHash: normalizeHex32(
      smartAccountInit.smartAccountInit.initPayloadHash,
      "smartAccountInit.initPayloadHash"
    ),
    initCommitment: normalizeHex32(
      smartAccountInit.smartAccountInit.initCommitment,
      "smartAccountInit.initCommitment"
    )
  };

  const appSmartAccountInit = {
    recipient: normalizeAddress(
      smartAccountInit.appSmartAccountInit.recipient,
      "appSmartAccountInit.recipient"
    ),
    targetId: normalizeHex32(
      smartAccountInit.appSmartAccountInit.targetId,
      "appSmartAccountInit.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountInit.appSmartAccountInit.targetAddress,
      "appSmartAccountInit.targetAddress"
    ),
    initPayloadHash: normalizeHex32(
      smartAccountInit.appSmartAccountInit.initPayloadHash,
      "appSmartAccountInit.initPayloadHash"
    ),
    initCommitment: normalizeHex32(
      smartAccountInit.appSmartAccountInit.initCommitment,
      "appSmartAccountInit.initCommitment"
    ),
    ready: smartAccountInit.appSmartAccountInit.ready === true,
    status: String(smartAccountInit.appSmartAccountInit.status || ""),
    parityProven: smartAccountInit.appSmartAccountInit.parityProven === true
  };

  assertTrue(appSmartAccountInit.ready, "appSmartAccountInit.ready");
  assertEqual(
    appSmartAccountInit.status,
    "smart-account-init-ready",
    "appSmartAccountInit.status"
  );
  assertTrue(appSmartAccountInit.parityProven, "appSmartAccountInit.parityProven");
  assertEqual(
    appSmartAccountInit.recipient.toLowerCase(),
    deterministicSmartAccountInit.canonicalRecipient.toLowerCase(),
    "appSmartAccountInit.recipient/smartAccountInit.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountInit.targetId,
    deterministicSmartAccountInit.targetId,
    "appSmartAccountInit.targetId/smartAccountInit.targetId"
  );
  assertEqual(
    appSmartAccountInit.targetAddress.toLowerCase(),
    deterministicSmartAccountInit.targetAddress.toLowerCase(),
    "appSmartAccountInit.targetAddress/smartAccountInit.targetAddress"
  );
  assertEqual(
    appSmartAccountInit.initPayloadHash,
    deterministicSmartAccountInit.initPayloadHash,
    "appSmartAccountInit.initPayloadHash/smartAccountInit.initPayloadHash"
  );
  assertEqual(
    appSmartAccountInit.initCommitment,
    deterministicSmartAccountInit.initCommitment,
    "appSmartAccountInit.initCommitment/smartAccountInit.initCommitment"
  );

  const smartAccountDeployPlan = deriveDeterministicSmartAccountDeployPlan({
    ownerCommitment: deterministicSmartAccountInit.ownerCommitment,
    consumerDataHash: deterministicSmartAccountInit.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountInit.canonicalRecipient,
    walletId: deterministicSmartAccountInit.walletId,
    targetId: deterministicSmartAccountInit.targetId,
    targetSalt: deterministicSmartAccountInit.targetSalt,
    targetAddress: deterministicSmartAccountInit.targetAddress,
    initPayloadHash: deterministicSmartAccountInit.initPayloadHash,
    initCommitment: deterministicSmartAccountInit.initCommitment
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-plan",
    smartAccountDeployPlanSource: "scripts/base/build-smart-account-deploy-plan.cjs",
    smartAccountInitSource: smartAccountInit.smartAccountInitSource,
    consumedPath: smartAccountInit.path,
    proofType: smartAccountInit.proofType,
    payloadShape: smartAccountInit.payloadShape,
    smartAccountDeployPlanDomain: {
      label: SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountInitPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountInitValid: true,
      deterministicSmartAccountDeployPlanDerived: true
    },
    smartAccountDeployPlanSummary: {
      ready: true,
      status: "smart-account-deploy-plan-ready",
      reason: "validated-smart-account-init",
      parityProven: true
    },
    smartAccountDeployPlan: {
      ownerCommitment: smartAccountDeployPlan.ownerCommitment,
      consumerDataHash: smartAccountDeployPlan.consumerDataHash,
      canonicalRecipient: smartAccountDeployPlan.canonicalRecipient,
      walletId: smartAccountDeployPlan.walletId,
      targetId: smartAccountDeployPlan.targetId,
      targetSalt: smartAccountDeployPlan.targetSalt,
      targetAddress: smartAccountDeployPlan.targetAddress,
      initPayloadHash: smartAccountDeployPlan.initPayloadHash,
      initCommitment: smartAccountDeployPlan.initCommitment,
      deploymentMode: smartAccountDeployPlan.deploymentMode,
      deploymentEnvelopeHash: smartAccountDeployPlan.deploymentEnvelopeHash,
      deploymentPlanId: smartAccountDeployPlan.deploymentPlanId
    },
    appSmartAccountDeployPlan: {
      recipient: smartAccountDeployPlan.canonicalRecipient,
      targetAddress: smartAccountDeployPlan.targetAddress,
      deploymentMode: smartAccountDeployPlan.deploymentMode,
      deploymentEnvelopeHash: smartAccountDeployPlan.deploymentEnvelopeHash,
      deploymentPlanId: smartAccountDeployPlan.deploymentPlanId,
      ready: true,
      status: "smart-account-deploy-plan-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-init") {
      parsed.smartAccountInitPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-plan.cjs --smart-account-init <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountInitPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployPlan = buildSmartAccountDeployPlan({
      smartAccountInit: loadJson(path.resolve(parsed.smartAccountInitPath))
    });
    console.log(JSON.stringify(smartAccountDeployPlan, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_HASH,
  deriveDeterministicSmartAccountDeployPlan,
  buildSmartAccountDeployPlan
};
