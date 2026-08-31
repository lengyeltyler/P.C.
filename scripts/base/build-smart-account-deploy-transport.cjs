const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_DEPLOY_TRANSPORT_V1";
const SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_TRANSPORT_KIND = "smart-account-deploy-relay-http-v1";
const SMART_ACCOUNT_DEPLOY_TRANSPORT_CONTENT_TYPE = "application/json";
const SMART_ACCOUNT_DEPLOY_TRANSPORT_METHOD = "POST";
const SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH = "/v1/smart-accounts/deploy";

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

function deriveDeterministicSmartAccountDeployTransport({
  proofType,
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  executionValue,
  payloadEncoding,
  deployCalldata,
  deployPayloadHash
}) {
  const normalizedProofType = String(proofType || "").trim();
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedExecutionValue = String(executionValue || "").trim();
  const normalizedPayloadEncoding = String(payloadEncoding || "").trim();
  const normalizedDeployCalldata = normalizeBytes(deployCalldata, "deployCalldata");
  const normalizedDeployPayloadHash = normalizeHex32(deployPayloadHash, "deployPayloadHash");

  const transportBodyObject = {
    version: 1,
    requestType: "smart-account-deploy",
    proofType: normalizedProofType,
    ownerCommitment: normalizedOwnerCommitment,
    consumerDataHash: normalizedConsumerDataHash,
    canonicalRecipient: normalizedCanonicalRecipient,
    expectedDeployedAddress: normalizedTargetAddress,
    executionValue: normalizedExecutionValue,
    payloadEncoding: normalizedPayloadEncoding,
    deployCalldata: normalizedDeployCalldata,
    deployPayloadHash: normalizedDeployPayloadHash
  };

  const transportBody = JSON.stringify(transportBodyObject);
  const transportBodyBytes = ethers.hexlify(ethers.toUtf8Bytes(transportBody));
  const transportBodyHash = ethers.keccak256(ethers.toUtf8Bytes(transportBody));
  const transportRequestId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        transportBodyHash
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
    executionValue: normalizedExecutionValue,
    payloadEncoding: normalizedPayloadEncoding,
    deployCalldata: normalizedDeployCalldata,
    deployPayloadHash: normalizedDeployPayloadHash,
    transportKind: SMART_ACCOUNT_DEPLOY_TRANSPORT_KIND,
    contentType: SMART_ACCOUNT_DEPLOY_TRANSPORT_CONTENT_TYPE,
    method: SMART_ACCOUNT_DEPLOY_TRANSPORT_METHOD,
    path: SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH,
    transportBody,
    transportBodyBytes,
    transportBodyHash,
    transportRequestId
  };
}

function buildSmartAccountDeployTransport({ smartAccountDeployPayload }) {
  if (!smartAccountDeployPayload || typeof smartAccountDeployPayload !== "object") {
    throw new Error("smartAccountDeployPayload is required");
  }

  assertEqual(
    smartAccountDeployPayload.path,
    "phil-smart-account-deploy-payload",
    "smartAccountDeployPayload.path"
  );
  assertEqual(
    smartAccountDeployPayload.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployPayload.payloadShape"
  );

  if (
    !smartAccountDeployPayload.validationChecks ||
    typeof smartAccountDeployPayload.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployPayload.validationChecks is required");
  }
  if (
    !smartAccountDeployPayload.smartAccountDeployPayloadSummary ||
    typeof smartAccountDeployPayload.smartAccountDeployPayloadSummary !== "object"
  ) {
    throw new Error("smartAccountDeployPayload.smartAccountDeployPayloadSummary is required");
  }
  if (
    !smartAccountDeployPayload.smartAccountDeployPayload ||
    typeof smartAccountDeployPayload.smartAccountDeployPayload !== "object"
  ) {
    throw new Error("smartAccountDeployPayload.smartAccountDeployPayload is required");
  }
  if (
    !smartAccountDeployPayload.appSmartAccountDeployPayload ||
    typeof smartAccountDeployPayload.appSmartAccountDeployPayload !== "object"
  ) {
    throw new Error("smartAccountDeployPayload.appSmartAccountDeployPayload is required");
  }

  assertTrue(
    smartAccountDeployPayload.validationChecks.smartAccountDeployEnvelopePathValid,
    "validationChecks.smartAccountDeployEnvelopePathValid"
  );
  assertTrue(
    smartAccountDeployPayload.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployPayload.validationChecks.upstreamSmartAccountDeployEnvelopeValid,
    "validationChecks.upstreamSmartAccountDeployEnvelopeValid"
  );
  assertTrue(
    smartAccountDeployPayload.validationChecks.executionReadySmartAccountDeployPayloadDerived,
    "validationChecks.executionReadySmartAccountDeployPayloadDerived"
  );
  assertTrue(
    smartAccountDeployPayload.smartAccountDeployPayloadSummary.ready,
    "smartAccountDeployPayloadSummary.ready"
  );
  assertEqual(
    smartAccountDeployPayload.smartAccountDeployPayloadSummary.status,
    "smart-account-deploy-payload-ready",
    "smartAccountDeployPayloadSummary.status"
  );
  assertTrue(
    smartAccountDeployPayload.smartAccountDeployPayloadSummary.parityProven,
    "smartAccountDeployPayloadSummary.parityProven"
  );

  const deterministicSmartAccountDeployPayload = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployPayload.smartAccountDeployPayload.ownerCommitment,
      "smartAccountDeployPayload.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployPayload.smartAccountDeployPayload.consumerDataHash,
      "smartAccountDeployPayload.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployPayload.smartAccountDeployPayload.canonicalRecipient,
      "smartAccountDeployPayload.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployPayload.smartAccountDeployPayload.walletId,
      "smartAccountDeployPayload.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployPayload.smartAccountDeployPayload.targetId,
      "smartAccountDeployPayload.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployPayload.smartAccountDeployPayload.targetAddress,
      "smartAccountDeployPayload.targetAddress"
    ),
    executionValue: String(
      smartAccountDeployPayload.smartAccountDeployPayload.executionValue || ""
    ).trim(),
    payloadEncoding: String(
      smartAccountDeployPayload.smartAccountDeployPayload.payloadEncoding || ""
    ).trim(),
    deployCalldata: normalizeBytes(
      smartAccountDeployPayload.smartAccountDeployPayload.deployCalldata,
      "smartAccountDeployPayload.deployCalldata"
    ),
    deployPayloadHash: normalizeHex32(
      smartAccountDeployPayload.smartAccountDeployPayload.deployPayloadHash,
      "smartAccountDeployPayload.deployPayloadHash"
    )
  };

  const appSmartAccountDeployPayload = {
    recipient: normalizeAddress(
      smartAccountDeployPayload.appSmartAccountDeployPayload.recipient,
      "appSmartAccountDeployPayload.recipient"
    ),
    expectedDeployedAddress: normalizeAddress(
      smartAccountDeployPayload.appSmartAccountDeployPayload.expectedDeployedAddress,
      "appSmartAccountDeployPayload.expectedDeployedAddress"
    ),
    executionValue: String(
      smartAccountDeployPayload.appSmartAccountDeployPayload.executionValue || ""
    ).trim(),
    payloadEncoding: String(
      smartAccountDeployPayload.appSmartAccountDeployPayload.payloadEncoding || ""
    ).trim(),
    deployCalldata: normalizeBytes(
      smartAccountDeployPayload.appSmartAccountDeployPayload.deployCalldata,
      "appSmartAccountDeployPayload.deployCalldata"
    ),
    deployPayloadHash: normalizeHex32(
      smartAccountDeployPayload.appSmartAccountDeployPayload.deployPayloadHash,
      "appSmartAccountDeployPayload.deployPayloadHash"
    ),
    ready: smartAccountDeployPayload.appSmartAccountDeployPayload.ready === true,
    status: String(smartAccountDeployPayload.appSmartAccountDeployPayload.status || ""),
    parityProven: smartAccountDeployPayload.appSmartAccountDeployPayload.parityProven === true
  };

  assertTrue(appSmartAccountDeployPayload.ready, "appSmartAccountDeployPayload.ready");
  assertEqual(
    appSmartAccountDeployPayload.status,
    "smart-account-deploy-payload-ready",
    "appSmartAccountDeployPayload.status"
  );
  assertTrue(
    appSmartAccountDeployPayload.parityProven,
    "appSmartAccountDeployPayload.parityProven"
  );
  assertEqual(
    appSmartAccountDeployPayload.recipient.toLowerCase(),
    deterministicSmartAccountDeployPayload.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployPayload.recipient/smartAccountDeployPayload.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployPayload.expectedDeployedAddress.toLowerCase(),
    deterministicSmartAccountDeployPayload.targetAddress.toLowerCase(),
    "appSmartAccountDeployPayload.expectedDeployedAddress/smartAccountDeployPayload.targetAddress"
  );
  assertEqual(
    appSmartAccountDeployPayload.executionValue,
    deterministicSmartAccountDeployPayload.executionValue,
    "appSmartAccountDeployPayload.executionValue/smartAccountDeployPayload.executionValue"
  );
  assertEqual(
    appSmartAccountDeployPayload.payloadEncoding,
    deterministicSmartAccountDeployPayload.payloadEncoding,
    "appSmartAccountDeployPayload.payloadEncoding/smartAccountDeployPayload.payloadEncoding"
  );
  assertEqual(
    appSmartAccountDeployPayload.deployCalldata,
    deterministicSmartAccountDeployPayload.deployCalldata,
    "appSmartAccountDeployPayload.deployCalldata/smartAccountDeployPayload.deployCalldata"
  );
  assertEqual(
    appSmartAccountDeployPayload.deployPayloadHash,
    deterministicSmartAccountDeployPayload.deployPayloadHash,
    "appSmartAccountDeployPayload.deployPayloadHash/smartAccountDeployPayload.deployPayloadHash"
  );

  const smartAccountDeployTransport = deriveDeterministicSmartAccountDeployTransport({
    proofType: smartAccountDeployPayload.proofType,
    ownerCommitment: deterministicSmartAccountDeployPayload.ownerCommitment,
    consumerDataHash: deterministicSmartAccountDeployPayload.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountDeployPayload.canonicalRecipient,
    walletId: deterministicSmartAccountDeployPayload.walletId,
    targetId: deterministicSmartAccountDeployPayload.targetId,
    targetAddress: deterministicSmartAccountDeployPayload.targetAddress,
    executionValue: deterministicSmartAccountDeployPayload.executionValue,
    payloadEncoding: deterministicSmartAccountDeployPayload.payloadEncoding,
    deployCalldata: deterministicSmartAccountDeployPayload.deployCalldata,
    deployPayloadHash: deterministicSmartAccountDeployPayload.deployPayloadHash
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-transport",
    smartAccountDeployTransportSource: "scripts/base/build-smart-account-deploy-transport.cjs",
    smartAccountDeployPayloadSource: smartAccountDeployPayload.smartAccountDeployPayloadSource,
    consumedPath: smartAccountDeployPayload.path,
    proofType: smartAccountDeployPayload.proofType,
    payloadShape: smartAccountDeployPayload.payloadShape,
    smartAccountDeployTransportDomain: {
      label: SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployPayloadPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployPayloadValid: true,
      deterministicSmartAccountDeployTransportDerived: true
    },
    smartAccountDeployTransportSummary: {
      ready: true,
      status: "smart-account-deploy-transport-ready",
      reason: "validated-smart-account-deploy-payload",
      parityProven: true
    },
    smartAccountDeployTransport: {
      ownerCommitment: smartAccountDeployTransport.ownerCommitment,
      consumerDataHash: smartAccountDeployTransport.consumerDataHash,
      canonicalRecipient: smartAccountDeployTransport.canonicalRecipient,
      walletId: smartAccountDeployTransport.walletId,
      targetId: smartAccountDeployTransport.targetId,
      targetAddress: smartAccountDeployTransport.targetAddress,
      executionValue: smartAccountDeployTransport.executionValue,
      payloadEncoding: smartAccountDeployTransport.payloadEncoding,
      deployCalldata: smartAccountDeployTransport.deployCalldata,
      deployPayloadHash: smartAccountDeployTransport.deployPayloadHash,
      transportKind: smartAccountDeployTransport.transportKind,
      contentType: smartAccountDeployTransport.contentType,
      method: smartAccountDeployTransport.method,
      path: smartAccountDeployTransport.path,
      transportBody: smartAccountDeployTransport.transportBody,
      transportBodyBytes: smartAccountDeployTransport.transportBodyBytes,
      transportBodyHash: smartAccountDeployTransport.transportBodyHash,
      transportRequestId: smartAccountDeployTransport.transportRequestId
    },
    appSmartAccountDeployTransport: {
      recipient: smartAccountDeployTransport.canonicalRecipient,
      expectedDeployedAddress: smartAccountDeployTransport.targetAddress,
      contentType: smartAccountDeployTransport.contentType,
      method: smartAccountDeployTransport.method,
      path: smartAccountDeployTransport.path,
      transportBody: smartAccountDeployTransport.transportBody,
      transportRequestId: smartAccountDeployTransport.transportRequestId,
      ready: true,
      status: "smart-account-deploy-transport-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-payload") {
      parsed.smartAccountDeployPayloadPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-transport.cjs --smart-account-deploy-payload <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployPayloadPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployTransport = buildSmartAccountDeployTransport({
      smartAccountDeployPayload: loadJson(path.resolve(parsed.smartAccountDeployPayloadPath))
    });
    console.log(JSON.stringify(smartAccountDeployTransport, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_KIND,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_CONTENT_TYPE,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_METHOD,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH,
  deriveDeterministicSmartAccountDeployTransport,
  buildSmartAccountDeployTransport
};
