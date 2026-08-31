const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_DEPLOY_REQUEST_V1";
const SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_LABEL)
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

function deriveDeterministicSmartAccountDeployRequest({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  deploymentMode,
  deploymentEnvelopeHash,
  deploymentPlanId
}) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedDeploymentEnvelopeHash = normalizeHex32(
    deploymentEnvelopeHash,
    "deploymentEnvelopeHash"
  );
  const normalizedDeploymentPlanId = normalizeHex32(deploymentPlanId, "deploymentPlanId");
  const normalizedDeploymentMode = String(deploymentMode || "").trim();

  if (normalizedDeploymentMode !== "deterministic-smart-account-init") {
    throw new Error(`Invalid deploymentMode: ${normalizedDeploymentMode || "<empty>"}`);
  }

  const requestPayloadHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "address", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_HASH,
        normalizedTargetId,
        normalizedTargetAddress,
        normalizedDeploymentEnvelopeHash,
        normalizedDeploymentPlanId
      ]
    )
  );

  const requestId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "address", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_HASH,
        normalizedWalletId,
        normalizedOwnerCommitment,
        normalizedCanonicalRecipient,
        requestPayloadHash
      ]
    )
  );

  return {
    ownerCommitment: normalizedOwnerCommitment,
    consumerDataHash: normalizedConsumerDataHash,
    canonicalRecipient: normalizedCanonicalRecipient,
    walletId: normalizedWalletId,
    targetId: normalizedTargetId,
    targetAddress: normalizedTargetAddress,
    deploymentMode: normalizedDeploymentMode,
    deploymentEnvelopeHash: normalizedDeploymentEnvelopeHash,
    deploymentPlanId: normalizedDeploymentPlanId,
    requestKind: "smart-account-deploy",
    requestPayloadHash,
    requestId
  };
}

function buildSmartAccountDeployRequest({ smartAccountDeployPlan }) {
  if (!smartAccountDeployPlan || typeof smartAccountDeployPlan !== "object") {
    throw new Error("smartAccountDeployPlan is required");
  }

  assertEqual(
    smartAccountDeployPlan.path,
    "phil-smart-account-deploy-plan",
    "smartAccountDeployPlan.path"
  );
  assertEqual(
    smartAccountDeployPlan.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployPlan.payloadShape"
  );

  if (
    !smartAccountDeployPlan.validationChecks ||
    typeof smartAccountDeployPlan.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployPlan.validationChecks is required");
  }
  if (
    !smartAccountDeployPlan.smartAccountDeployPlanSummary ||
    typeof smartAccountDeployPlan.smartAccountDeployPlanSummary !== "object"
  ) {
    throw new Error("smartAccountDeployPlan.smartAccountDeployPlanSummary is required");
  }
  if (
    !smartAccountDeployPlan.smartAccountDeployPlan ||
    typeof smartAccountDeployPlan.smartAccountDeployPlan !== "object"
  ) {
    throw new Error("smartAccountDeployPlan.smartAccountDeployPlan is required");
  }
  if (
    !smartAccountDeployPlan.appSmartAccountDeployPlan ||
    typeof smartAccountDeployPlan.appSmartAccountDeployPlan !== "object"
  ) {
    throw new Error("smartAccountDeployPlan.appSmartAccountDeployPlan is required");
  }

  assertTrue(
    smartAccountDeployPlan.validationChecks.smartAccountInitPathValid,
    "validationChecks.smartAccountInitPathValid"
  );
  assertTrue(
    smartAccountDeployPlan.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployPlan.validationChecks.upstreamSmartAccountInitValid,
    "validationChecks.upstreamSmartAccountInitValid"
  );
  assertTrue(
    smartAccountDeployPlan.validationChecks.deterministicSmartAccountDeployPlanDerived,
    "validationChecks.deterministicSmartAccountDeployPlanDerived"
  );
  assertTrue(
    smartAccountDeployPlan.smartAccountDeployPlanSummary.ready,
    "smartAccountDeployPlanSummary.ready"
  );
  assertEqual(
    smartAccountDeployPlan.smartAccountDeployPlanSummary.status,
    "smart-account-deploy-plan-ready",
    "smartAccountDeployPlanSummary.status"
  );
  assertTrue(
    smartAccountDeployPlan.smartAccountDeployPlanSummary.parityProven,
    "smartAccountDeployPlanSummary.parityProven"
  );

  const deterministicSmartAccountDeployPlan = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployPlan.smartAccountDeployPlan.ownerCommitment,
      "smartAccountDeployPlan.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployPlan.smartAccountDeployPlan.consumerDataHash,
      "smartAccountDeployPlan.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployPlan.smartAccountDeployPlan.canonicalRecipient,
      "smartAccountDeployPlan.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployPlan.smartAccountDeployPlan.walletId,
      "smartAccountDeployPlan.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployPlan.smartAccountDeployPlan.targetId,
      "smartAccountDeployPlan.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployPlan.smartAccountDeployPlan.targetAddress,
      "smartAccountDeployPlan.targetAddress"
    ),
    deploymentMode: String(
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentMode || ""
    ).trim(),
    deploymentEnvelopeHash: normalizeHex32(
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentEnvelopeHash,
      "smartAccountDeployPlan.deploymentEnvelopeHash"
    ),
    deploymentPlanId: normalizeHex32(
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentPlanId,
      "smartAccountDeployPlan.deploymentPlanId"
    )
  };

  const appSmartAccountDeployPlan = {
    recipient: normalizeAddress(
      smartAccountDeployPlan.appSmartAccountDeployPlan.recipient,
      "appSmartAccountDeployPlan.recipient"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployPlan.appSmartAccountDeployPlan.targetAddress,
      "appSmartAccountDeployPlan.targetAddress"
    ),
    deploymentMode: String(
      smartAccountDeployPlan.appSmartAccountDeployPlan.deploymentMode || ""
    ).trim(),
    deploymentEnvelopeHash: normalizeHex32(
      smartAccountDeployPlan.appSmartAccountDeployPlan.deploymentEnvelopeHash,
      "appSmartAccountDeployPlan.deploymentEnvelopeHash"
    ),
    deploymentPlanId: normalizeHex32(
      smartAccountDeployPlan.appSmartAccountDeployPlan.deploymentPlanId,
      "appSmartAccountDeployPlan.deploymentPlanId"
    ),
    ready: smartAccountDeployPlan.appSmartAccountDeployPlan.ready === true,
    status: String(smartAccountDeployPlan.appSmartAccountDeployPlan.status || ""),
    parityProven: smartAccountDeployPlan.appSmartAccountDeployPlan.parityProven === true
  };

  assertTrue(appSmartAccountDeployPlan.ready, "appSmartAccountDeployPlan.ready");
  assertEqual(
    appSmartAccountDeployPlan.status,
    "smart-account-deploy-plan-ready",
    "appSmartAccountDeployPlan.status"
  );
  assertTrue(
    appSmartAccountDeployPlan.parityProven,
    "appSmartAccountDeployPlan.parityProven"
  );
  assertEqual(
    appSmartAccountDeployPlan.recipient.toLowerCase(),
    deterministicSmartAccountDeployPlan.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployPlan.recipient/smartAccountDeployPlan.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployPlan.targetAddress.toLowerCase(),
    deterministicSmartAccountDeployPlan.targetAddress.toLowerCase(),
    "appSmartAccountDeployPlan.targetAddress/smartAccountDeployPlan.targetAddress"
  );
  assertEqual(
    appSmartAccountDeployPlan.deploymentMode,
    deterministicSmartAccountDeployPlan.deploymentMode,
    "appSmartAccountDeployPlan.deploymentMode/smartAccountDeployPlan.deploymentMode"
  );
  assertEqual(
    appSmartAccountDeployPlan.deploymentEnvelopeHash,
    deterministicSmartAccountDeployPlan.deploymentEnvelopeHash,
    "appSmartAccountDeployPlan.deploymentEnvelopeHash/smartAccountDeployPlan.deploymentEnvelopeHash"
  );
  assertEqual(
    appSmartAccountDeployPlan.deploymentPlanId,
    deterministicSmartAccountDeployPlan.deploymentPlanId,
    "appSmartAccountDeployPlan.deploymentPlanId/smartAccountDeployPlan.deploymentPlanId"
  );

  const smartAccountDeployRequest = deriveDeterministicSmartAccountDeployRequest({
    ownerCommitment: deterministicSmartAccountDeployPlan.ownerCommitment,
    consumerDataHash: deterministicSmartAccountDeployPlan.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountDeployPlan.canonicalRecipient,
    walletId: deterministicSmartAccountDeployPlan.walletId,
    targetId: deterministicSmartAccountDeployPlan.targetId,
    targetAddress: deterministicSmartAccountDeployPlan.targetAddress,
    deploymentMode: deterministicSmartAccountDeployPlan.deploymentMode,
    deploymentEnvelopeHash: deterministicSmartAccountDeployPlan.deploymentEnvelopeHash,
    deploymentPlanId: deterministicSmartAccountDeployPlan.deploymentPlanId
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-request",
    smartAccountDeployRequestSource: "scripts/base/build-smart-account-deploy-request.cjs",
    smartAccountDeployPlanSource: smartAccountDeployPlan.smartAccountDeployPlanSource,
    consumedPath: smartAccountDeployPlan.path,
    proofType: smartAccountDeployPlan.proofType,
    payloadShape: smartAccountDeployPlan.payloadShape,
    smartAccountDeployRequestDomain: {
      label: SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployPlanPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployPlanValid: true,
      deterministicSmartAccountDeployRequestDerived: true
    },
    smartAccountDeployRequestSummary: {
      ready: true,
      status: "smart-account-deploy-request-ready",
      reason: "validated-smart-account-deploy-plan",
      parityProven: true
    },
    smartAccountDeployRequest: {
      ownerCommitment: smartAccountDeployRequest.ownerCommitment,
      consumerDataHash: smartAccountDeployRequest.consumerDataHash,
      canonicalRecipient: smartAccountDeployRequest.canonicalRecipient,
      walletId: smartAccountDeployRequest.walletId,
      targetId: smartAccountDeployRequest.targetId,
      targetAddress: smartAccountDeployRequest.targetAddress,
      deploymentMode: smartAccountDeployRequest.deploymentMode,
      deploymentEnvelopeHash: smartAccountDeployRequest.deploymentEnvelopeHash,
      deploymentPlanId: smartAccountDeployRequest.deploymentPlanId,
      requestKind: smartAccountDeployRequest.requestKind,
      requestPayloadHash: smartAccountDeployRequest.requestPayloadHash,
      requestId: smartAccountDeployRequest.requestId
    },
    appSmartAccountDeployRequest: {
      recipient: smartAccountDeployRequest.canonicalRecipient,
      targetAddress: smartAccountDeployRequest.targetAddress,
      requestKind: smartAccountDeployRequest.requestKind,
      requestPayloadHash: smartAccountDeployRequest.requestPayloadHash,
      requestId: smartAccountDeployRequest.requestId,
      ready: true,
      status: "smart-account-deploy-request-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-plan") {
      parsed.smartAccountDeployPlanPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-request.cjs --smart-account-deploy-plan <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployPlanPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployRequest = buildSmartAccountDeployRequest({
      smartAccountDeployPlan: loadJson(path.resolve(parsed.smartAccountDeployPlanPath))
    });
    console.log(JSON.stringify(smartAccountDeployRequest, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_HASH,
  deriveDeterministicSmartAccountDeployRequest,
  buildSmartAccountDeployRequest
};
