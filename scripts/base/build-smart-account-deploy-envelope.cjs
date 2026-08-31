const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_DEPLOY_ENVELOPE_V1";
const SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_LABEL)
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

function deriveDeterministicSmartAccountDeployEnvelope({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  requestKind,
  requestPayloadHash,
  requestId
}) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedRequestPayloadHash = normalizeHex32(requestPayloadHash, "requestPayloadHash");
  const normalizedRequestId = normalizeHex32(requestId, "requestId");
  const normalizedRequestKind = String(requestKind || "").trim();

  if (normalizedRequestKind !== "smart-account-deploy") {
    throw new Error(`Invalid requestKind: ${normalizedRequestKind || "<empty>"}`);
  }

  const envelopePayloadHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "address", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_HASH,
        normalizedTargetId,
        normalizedTargetAddress,
        normalizedRequestPayloadHash,
        normalizedRequestId
      ]
    )
  );

  const envelopeId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "address", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_HASH,
        normalizedWalletId,
        normalizedOwnerCommitment,
        normalizedCanonicalRecipient,
        envelopePayloadHash
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
    requestKind: normalizedRequestKind,
    requestPayloadHash: normalizedRequestPayloadHash,
    requestId: normalizedRequestId,
    envelopeKind: "smart-account-deploy-envelope",
    envelopePayloadHash,
    envelopeId
  };
}

function buildSmartAccountDeployEnvelope({ smartAccountDeployRequest }) {
  if (!smartAccountDeployRequest || typeof smartAccountDeployRequest !== "object") {
    throw new Error("smartAccountDeployRequest is required");
  }

  assertEqual(
    smartAccountDeployRequest.path,
    "phil-smart-account-deploy-request",
    "smartAccountDeployRequest.path"
  );
  assertEqual(
    smartAccountDeployRequest.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployRequest.payloadShape"
  );

  if (
    !smartAccountDeployRequest.validationChecks ||
    typeof smartAccountDeployRequest.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployRequest.validationChecks is required");
  }
  if (
    !smartAccountDeployRequest.smartAccountDeployRequestSummary ||
    typeof smartAccountDeployRequest.smartAccountDeployRequestSummary !== "object"
  ) {
    throw new Error("smartAccountDeployRequest.smartAccountDeployRequestSummary is required");
  }
  if (
    !smartAccountDeployRequest.smartAccountDeployRequest ||
    typeof smartAccountDeployRequest.smartAccountDeployRequest !== "object"
  ) {
    throw new Error("smartAccountDeployRequest.smartAccountDeployRequest is required");
  }
  if (
    !smartAccountDeployRequest.appSmartAccountDeployRequest ||
    typeof smartAccountDeployRequest.appSmartAccountDeployRequest !== "object"
  ) {
    throw new Error("smartAccountDeployRequest.appSmartAccountDeployRequest is required");
  }

  assertTrue(
    smartAccountDeployRequest.validationChecks.smartAccountDeployPlanPathValid,
    "validationChecks.smartAccountDeployPlanPathValid"
  );
  assertTrue(
    smartAccountDeployRequest.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployRequest.validationChecks.upstreamSmartAccountDeployPlanValid,
    "validationChecks.upstreamSmartAccountDeployPlanValid"
  );
  assertTrue(
    smartAccountDeployRequest.validationChecks.deterministicSmartAccountDeployRequestDerived,
    "validationChecks.deterministicSmartAccountDeployRequestDerived"
  );
  assertTrue(
    smartAccountDeployRequest.smartAccountDeployRequestSummary.ready,
    "smartAccountDeployRequestSummary.ready"
  );
  assertEqual(
    smartAccountDeployRequest.smartAccountDeployRequestSummary.status,
    "smart-account-deploy-request-ready",
    "smartAccountDeployRequestSummary.status"
  );
  assertTrue(
    smartAccountDeployRequest.smartAccountDeployRequestSummary.parityProven,
    "smartAccountDeployRequestSummary.parityProven"
  );

  const deterministicSmartAccountDeployRequest = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployRequest.smartAccountDeployRequest.ownerCommitment,
      "smartAccountDeployRequest.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployRequest.smartAccountDeployRequest.consumerDataHash,
      "smartAccountDeployRequest.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployRequest.smartAccountDeployRequest.canonicalRecipient,
      "smartAccountDeployRequest.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployRequest.smartAccountDeployRequest.walletId,
      "smartAccountDeployRequest.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployRequest.smartAccountDeployRequest.targetId,
      "smartAccountDeployRequest.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployRequest.smartAccountDeployRequest.targetAddress,
      "smartAccountDeployRequest.targetAddress"
    ),
    requestKind: String(
      smartAccountDeployRequest.smartAccountDeployRequest.requestKind || ""
    ).trim(),
    requestPayloadHash: normalizeHex32(
      smartAccountDeployRequest.smartAccountDeployRequest.requestPayloadHash,
      "smartAccountDeployRequest.requestPayloadHash"
    ),
    requestId: normalizeHex32(
      smartAccountDeployRequest.smartAccountDeployRequest.requestId,
      "smartAccountDeployRequest.requestId"
    )
  };

  const appSmartAccountDeployRequest = {
    recipient: normalizeAddress(
      smartAccountDeployRequest.appSmartAccountDeployRequest.recipient,
      "appSmartAccountDeployRequest.recipient"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployRequest.appSmartAccountDeployRequest.targetAddress,
      "appSmartAccountDeployRequest.targetAddress"
    ),
    requestKind: String(
      smartAccountDeployRequest.appSmartAccountDeployRequest.requestKind || ""
    ).trim(),
    requestPayloadHash: normalizeHex32(
      smartAccountDeployRequest.appSmartAccountDeployRequest.requestPayloadHash,
      "appSmartAccountDeployRequest.requestPayloadHash"
    ),
    requestId: normalizeHex32(
      smartAccountDeployRequest.appSmartAccountDeployRequest.requestId,
      "appSmartAccountDeployRequest.requestId"
    ),
    ready: smartAccountDeployRequest.appSmartAccountDeployRequest.ready === true,
    status: String(smartAccountDeployRequest.appSmartAccountDeployRequest.status || ""),
    parityProven: smartAccountDeployRequest.appSmartAccountDeployRequest.parityProven === true
  };

  assertTrue(appSmartAccountDeployRequest.ready, "appSmartAccountDeployRequest.ready");
  assertEqual(
    appSmartAccountDeployRequest.status,
    "smart-account-deploy-request-ready",
    "appSmartAccountDeployRequest.status"
  );
  assertTrue(
    appSmartAccountDeployRequest.parityProven,
    "appSmartAccountDeployRequest.parityProven"
  );
  assertEqual(
    appSmartAccountDeployRequest.recipient.toLowerCase(),
    deterministicSmartAccountDeployRequest.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployRequest.recipient/smartAccountDeployRequest.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployRequest.targetAddress.toLowerCase(),
    deterministicSmartAccountDeployRequest.targetAddress.toLowerCase(),
    "appSmartAccountDeployRequest.targetAddress/smartAccountDeployRequest.targetAddress"
  );
  assertEqual(
    appSmartAccountDeployRequest.requestKind,
    deterministicSmartAccountDeployRequest.requestKind,
    "appSmartAccountDeployRequest.requestKind/smartAccountDeployRequest.requestKind"
  );
  assertEqual(
    appSmartAccountDeployRequest.requestPayloadHash,
    deterministicSmartAccountDeployRequest.requestPayloadHash,
    "appSmartAccountDeployRequest.requestPayloadHash/smartAccountDeployRequest.requestPayloadHash"
  );
  assertEqual(
    appSmartAccountDeployRequest.requestId,
    deterministicSmartAccountDeployRequest.requestId,
    "appSmartAccountDeployRequest.requestId/smartAccountDeployRequest.requestId"
  );

  const smartAccountDeployEnvelope = deriveDeterministicSmartAccountDeployEnvelope({
    ownerCommitment: deterministicSmartAccountDeployRequest.ownerCommitment,
    consumerDataHash: deterministicSmartAccountDeployRequest.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountDeployRequest.canonicalRecipient,
    walletId: deterministicSmartAccountDeployRequest.walletId,
    targetId: deterministicSmartAccountDeployRequest.targetId,
    targetAddress: deterministicSmartAccountDeployRequest.targetAddress,
    requestKind: deterministicSmartAccountDeployRequest.requestKind,
    requestPayloadHash: deterministicSmartAccountDeployRequest.requestPayloadHash,
    requestId: deterministicSmartAccountDeployRequest.requestId
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-envelope",
    smartAccountDeployEnvelopeSource: "scripts/base/build-smart-account-deploy-envelope.cjs",
    smartAccountDeployRequestSource: smartAccountDeployRequest.smartAccountDeployRequestSource,
    consumedPath: smartAccountDeployRequest.path,
    proofType: smartAccountDeployRequest.proofType,
    payloadShape: smartAccountDeployRequest.payloadShape,
    smartAccountDeployEnvelopeDomain: {
      label: SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployRequestPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployRequestValid: true,
      deterministicSmartAccountDeployEnvelopeDerived: true
    },
    smartAccountDeployEnvelopeSummary: {
      ready: true,
      status: "smart-account-deploy-envelope-ready",
      reason: "validated-smart-account-deploy-request",
      parityProven: true
    },
    smartAccountDeployEnvelope: {
      ownerCommitment: smartAccountDeployEnvelope.ownerCommitment,
      consumerDataHash: smartAccountDeployEnvelope.consumerDataHash,
      canonicalRecipient: smartAccountDeployEnvelope.canonicalRecipient,
      walletId: smartAccountDeployEnvelope.walletId,
      targetId: smartAccountDeployEnvelope.targetId,
      targetAddress: smartAccountDeployEnvelope.targetAddress,
      requestKind: smartAccountDeployEnvelope.requestKind,
      requestPayloadHash: smartAccountDeployEnvelope.requestPayloadHash,
      requestId: smartAccountDeployEnvelope.requestId,
      envelopeKind: smartAccountDeployEnvelope.envelopeKind,
      envelopePayloadHash: smartAccountDeployEnvelope.envelopePayloadHash,
      envelopeId: smartAccountDeployEnvelope.envelopeId
    },
    appSmartAccountDeployEnvelope: {
      recipient: smartAccountDeployEnvelope.canonicalRecipient,
      targetAddress: smartAccountDeployEnvelope.targetAddress,
      envelopeKind: smartAccountDeployEnvelope.envelopeKind,
      envelopePayloadHash: smartAccountDeployEnvelope.envelopePayloadHash,
      envelopeId: smartAccountDeployEnvelope.envelopeId,
      ready: true,
      status: "smart-account-deploy-envelope-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-request") {
      parsed.smartAccountDeployRequestPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-envelope.cjs --smart-account-deploy-request <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployRequestPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployEnvelope = buildSmartAccountDeployEnvelope({
      smartAccountDeployRequest: loadJson(path.resolve(parsed.smartAccountDeployRequestPath))
    });
    console.log(JSON.stringify(smartAccountDeployEnvelope, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_HASH,
  deriveDeterministicSmartAccountDeployEnvelope,
  buildSmartAccountDeployEnvelope
};
