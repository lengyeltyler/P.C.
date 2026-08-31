const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_DEPLOY_PAYLOAD_V1";
const SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_PAYLOAD_ENCODING = "abi-v1";
const SMART_ACCOUNT_DEPLOY_EXECUTION_VALUE = "0";

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

function deriveDeterministicSmartAccountDeployPayload({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  requestKind,
  requestPayloadHash,
  requestId,
  envelopeKind,
  envelopePayloadHash,
  envelopeId
}) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedRequestPayloadHash = normalizeHex32(requestPayloadHash, "requestPayloadHash");
  const normalizedRequestId = normalizeHex32(requestId, "requestId");
  const normalizedEnvelopePayloadHash = normalizeHex32(
    envelopePayloadHash,
    "envelopePayloadHash"
  );
  const normalizedEnvelopeId = normalizeHex32(envelopeId, "envelopeId");
  const normalizedRequestKind = String(requestKind || "").trim();
  const normalizedEnvelopeKind = String(envelopeKind || "").trim();

  if (normalizedRequestKind !== "smart-account-deploy") {
    throw new Error(`Invalid requestKind: ${normalizedRequestKind || "<empty>"}`);
  }
  if (normalizedEnvelopeKind !== "smart-account-deploy-envelope") {
    throw new Error(`Invalid envelopeKind: ${normalizedEnvelopeKind || "<empty>"}`);
  }

  const deployCalldata = ethers.AbiCoder.defaultAbiCoder().encode(
    [
      "bytes32",
      "bytes32",
      "bytes32",
      "address",
      "bytes32",
      "bytes32",
      "address",
      "bytes32",
      "bytes32",
      "bytes32",
      "bytes32"
    ],
    [
      SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_HASH,
      normalizedOwnerCommitment,
      normalizedConsumerDataHash,
      normalizedCanonicalRecipient,
      normalizedWalletId,
      normalizedTargetId,
      normalizedTargetAddress,
      normalizedRequestPayloadHash,
      normalizedRequestId,
      normalizedEnvelopePayloadHash,
      normalizedEnvelopeId
    ]
  );

  const deployCalldataHash = ethers.keccak256(deployCalldata);
  const deployPayloadHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "uint256", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_HASH,
        normalizedTargetAddress,
        BigInt(SMART_ACCOUNT_DEPLOY_EXECUTION_VALUE),
        deployCalldataHash,
        normalizedEnvelopeId
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
    envelopeKind: normalizedEnvelopeKind,
    envelopePayloadHash: normalizedEnvelopePayloadHash,
    envelopeId: normalizedEnvelopeId,
    executionValue: SMART_ACCOUNT_DEPLOY_EXECUTION_VALUE,
    payloadEncoding: SMART_ACCOUNT_DEPLOY_PAYLOAD_ENCODING,
    deployCalldata,
    deployCalldataHash,
    deployPayloadHash
  };
}

function buildSmartAccountDeployPayload({ smartAccountDeployEnvelope }) {
  if (!smartAccountDeployEnvelope || typeof smartAccountDeployEnvelope !== "object") {
    throw new Error("smartAccountDeployEnvelope is required");
  }

  assertEqual(
    smartAccountDeployEnvelope.path,
    "phil-smart-account-deploy-envelope",
    "smartAccountDeployEnvelope.path"
  );
  assertEqual(
    smartAccountDeployEnvelope.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployEnvelope.payloadShape"
  );

  if (
    !smartAccountDeployEnvelope.validationChecks ||
    typeof smartAccountDeployEnvelope.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployEnvelope.validationChecks is required");
  }
  if (
    !smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary ||
    typeof smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary !== "object"
  ) {
    throw new Error("smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary is required");
  }
  if (
    !smartAccountDeployEnvelope.smartAccountDeployEnvelope ||
    typeof smartAccountDeployEnvelope.smartAccountDeployEnvelope !== "object"
  ) {
    throw new Error("smartAccountDeployEnvelope.smartAccountDeployEnvelope is required");
  }
  if (
    !smartAccountDeployEnvelope.appSmartAccountDeployEnvelope ||
    typeof smartAccountDeployEnvelope.appSmartAccountDeployEnvelope !== "object"
  ) {
    throw new Error("smartAccountDeployEnvelope.appSmartAccountDeployEnvelope is required");
  }

  assertTrue(
    smartAccountDeployEnvelope.validationChecks.smartAccountDeployRequestPathValid,
    "validationChecks.smartAccountDeployRequestPathValid"
  );
  assertTrue(
    smartAccountDeployEnvelope.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployEnvelope.validationChecks.upstreamSmartAccountDeployRequestValid,
    "validationChecks.upstreamSmartAccountDeployRequestValid"
  );
  assertTrue(
    smartAccountDeployEnvelope.validationChecks.deterministicSmartAccountDeployEnvelopeDerived,
    "validationChecks.deterministicSmartAccountDeployEnvelopeDerived"
  );
  assertTrue(
    smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary.ready,
    "smartAccountDeployEnvelopeSummary.ready"
  );
  assertEqual(
    smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary.status,
    "smart-account-deploy-envelope-ready",
    "smartAccountDeployEnvelopeSummary.status"
  );
  assertTrue(
    smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary.parityProven,
    "smartAccountDeployEnvelopeSummary.parityProven"
  );

  const deterministicSmartAccountDeployEnvelope = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.ownerCommitment,
      "smartAccountDeployEnvelope.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.consumerDataHash,
      "smartAccountDeployEnvelope.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.canonicalRecipient,
      "smartAccountDeployEnvelope.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.walletId,
      "smartAccountDeployEnvelope.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.targetId,
      "smartAccountDeployEnvelope.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.targetAddress,
      "smartAccountDeployEnvelope.targetAddress"
    ),
    requestKind: String(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.requestKind || ""
    ).trim(),
    requestPayloadHash: normalizeHex32(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.requestPayloadHash,
      "smartAccountDeployEnvelope.requestPayloadHash"
    ),
    requestId: normalizeHex32(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.requestId,
      "smartAccountDeployEnvelope.requestId"
    ),
    envelopeKind: String(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopeKind || ""
    ).trim(),
    envelopePayloadHash: normalizeHex32(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopePayloadHash,
      "smartAccountDeployEnvelope.envelopePayloadHash"
    ),
    envelopeId: normalizeHex32(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopeId,
      "smartAccountDeployEnvelope.envelopeId"
    )
  };

  const appSmartAccountDeployEnvelope = {
    recipient: normalizeAddress(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.recipient,
      "appSmartAccountDeployEnvelope.recipient"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.targetAddress,
      "appSmartAccountDeployEnvelope.targetAddress"
    ),
    envelopeKind: String(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.envelopeKind || ""
    ).trim(),
    envelopePayloadHash: normalizeHex32(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.envelopePayloadHash,
      "appSmartAccountDeployEnvelope.envelopePayloadHash"
    ),
    envelopeId: normalizeHex32(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.envelopeId,
      "appSmartAccountDeployEnvelope.envelopeId"
    ),
    ready: smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.ready === true,
    status: String(smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.status || ""),
    parityProven: smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.parityProven === true
  };

  assertTrue(appSmartAccountDeployEnvelope.ready, "appSmartAccountDeployEnvelope.ready");
  assertEqual(
    appSmartAccountDeployEnvelope.status,
    "smart-account-deploy-envelope-ready",
    "appSmartAccountDeployEnvelope.status"
  );
  assertTrue(
    appSmartAccountDeployEnvelope.parityProven,
    "appSmartAccountDeployEnvelope.parityProven"
  );
  assertEqual(
    appSmartAccountDeployEnvelope.recipient.toLowerCase(),
    deterministicSmartAccountDeployEnvelope.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployEnvelope.recipient/smartAccountDeployEnvelope.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployEnvelope.targetAddress.toLowerCase(),
    deterministicSmartAccountDeployEnvelope.targetAddress.toLowerCase(),
    "appSmartAccountDeployEnvelope.targetAddress/smartAccountDeployEnvelope.targetAddress"
  );
  assertEqual(
    appSmartAccountDeployEnvelope.envelopeKind,
    deterministicSmartAccountDeployEnvelope.envelopeKind,
    "appSmartAccountDeployEnvelope.envelopeKind/smartAccountDeployEnvelope.envelopeKind"
  );
  assertEqual(
    appSmartAccountDeployEnvelope.envelopePayloadHash,
    deterministicSmartAccountDeployEnvelope.envelopePayloadHash,
    "appSmartAccountDeployEnvelope.envelopePayloadHash/smartAccountDeployEnvelope.envelopePayloadHash"
  );
  assertEqual(
    appSmartAccountDeployEnvelope.envelopeId,
    deterministicSmartAccountDeployEnvelope.envelopeId,
    "appSmartAccountDeployEnvelope.envelopeId/smartAccountDeployEnvelope.envelopeId"
  );

  const smartAccountDeployPayload = deriveDeterministicSmartAccountDeployPayload({
    ownerCommitment: deterministicSmartAccountDeployEnvelope.ownerCommitment,
    consumerDataHash: deterministicSmartAccountDeployEnvelope.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountDeployEnvelope.canonicalRecipient,
    walletId: deterministicSmartAccountDeployEnvelope.walletId,
    targetId: deterministicSmartAccountDeployEnvelope.targetId,
    targetAddress: deterministicSmartAccountDeployEnvelope.targetAddress,
    requestKind: deterministicSmartAccountDeployEnvelope.requestKind,
    requestPayloadHash: deterministicSmartAccountDeployEnvelope.requestPayloadHash,
    requestId: deterministicSmartAccountDeployEnvelope.requestId,
    envelopeKind: deterministicSmartAccountDeployEnvelope.envelopeKind,
    envelopePayloadHash: deterministicSmartAccountDeployEnvelope.envelopePayloadHash,
    envelopeId: deterministicSmartAccountDeployEnvelope.envelopeId
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-payload",
    smartAccountDeployPayloadSource: "scripts/base/build-smart-account-deploy-payload.cjs",
    smartAccountDeployEnvelopeSource: smartAccountDeployEnvelope.smartAccountDeployEnvelopeSource,
    consumedPath: smartAccountDeployEnvelope.path,
    proofType: smartAccountDeployEnvelope.proofType,
    payloadShape: smartAccountDeployEnvelope.payloadShape,
    smartAccountDeployPayloadDomain: {
      label: SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployEnvelopePathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployEnvelopeValid: true,
      executionReadySmartAccountDeployPayloadDerived: true
    },
    smartAccountDeployPayloadSummary: {
      ready: true,
      status: "smart-account-deploy-payload-ready",
      reason: "validated-smart-account-deploy-envelope",
      parityProven: true
    },
    smartAccountDeployPayload: {
      ownerCommitment: smartAccountDeployPayload.ownerCommitment,
      consumerDataHash: smartAccountDeployPayload.consumerDataHash,
      canonicalRecipient: smartAccountDeployPayload.canonicalRecipient,
      walletId: smartAccountDeployPayload.walletId,
      targetId: smartAccountDeployPayload.targetId,
      targetAddress: smartAccountDeployPayload.targetAddress,
      requestKind: smartAccountDeployPayload.requestKind,
      requestPayloadHash: smartAccountDeployPayload.requestPayloadHash,
      requestId: smartAccountDeployPayload.requestId,
      envelopeKind: smartAccountDeployPayload.envelopeKind,
      envelopePayloadHash: smartAccountDeployPayload.envelopePayloadHash,
      envelopeId: smartAccountDeployPayload.envelopeId,
      executionValue: smartAccountDeployPayload.executionValue,
      payloadEncoding: smartAccountDeployPayload.payloadEncoding,
      deployCalldata: smartAccountDeployPayload.deployCalldata,
      deployCalldataHash: smartAccountDeployPayload.deployCalldataHash,
      deployPayloadHash: smartAccountDeployPayload.deployPayloadHash
    },
    appSmartAccountDeployPayload: {
      recipient: smartAccountDeployPayload.canonicalRecipient,
      expectedDeployedAddress: smartAccountDeployPayload.targetAddress,
      executionValue: smartAccountDeployPayload.executionValue,
      payloadEncoding: smartAccountDeployPayload.payloadEncoding,
      deployCalldata: smartAccountDeployPayload.deployCalldata,
      deployPayloadHash: smartAccountDeployPayload.deployPayloadHash,
      ready: true,
      status: "smart-account-deploy-payload-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-envelope") {
      parsed.smartAccountDeployEnvelopePath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-payload.cjs --smart-account-deploy-envelope <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployEnvelopePath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployPayload = buildSmartAccountDeployPayload({
      smartAccountDeployEnvelope: loadJson(path.resolve(parsed.smartAccountDeployEnvelopePath))
    });
    console.log(JSON.stringify(smartAccountDeployPayload, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_PAYLOAD_ENCODING,
  SMART_ACCOUNT_DEPLOY_EXECUTION_VALUE,
  deriveDeterministicSmartAccountDeployPayload,
  buildSmartAccountDeployPayload
};
