const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_DEPLOY_SUBMIT_V1";
const SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_SUBMIT_KIND = "smart-account-deploy-submit-relay-http-v1";
const SMART_ACCOUNT_DEPLOY_SUBMIT_ACCEPT = "application/json";

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

function normalizeString(value, label) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    throw new Error(`Invalid ${label}: <empty>`);
  }
  return normalized;
}

function deriveDeterministicSmartAccountDeploySubmit({
  proofType,
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  deployPayloadHash,
  transportKind,
  contentType,
  method,
  path: requestPath,
  transportBody,
  transportBodyBytes,
  transportBodyHash,
  transportRequestId
}) {
  const normalizedProofType = normalizeString(proofType, "proofType");
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedDeployPayloadHash = normalizeHex32(deployPayloadHash, "deployPayloadHash");
  const normalizedTransportKind = normalizeString(transportKind, "transportKind");
  const normalizedContentType = normalizeString(contentType, "contentType");
  const normalizedMethod = normalizeString(method, "method");
  const normalizedPath = normalizeString(requestPath, "path");
  const normalizedTransportBody = normalizeString(transportBody, "transportBody");
  const normalizedTransportBodyBytes = normalizeBytes(transportBodyBytes, "transportBodyBytes");
  const normalizedTransportBodyHash = normalizeHex32(transportBodyHash, "transportBodyHash");
  const normalizedTransportRequestId = normalizeHex32(transportRequestId, "transportRequestId");

  const recomputedTransportBodyBytes = ethers.hexlify(
    ethers.toUtf8Bytes(normalizedTransportBody)
  ).toLowerCase();
  const recomputedTransportBodyHash = ethers.keccak256(
    ethers.toUtf8Bytes(normalizedTransportBody)
  );

  assertEqual(
    recomputedTransportBodyBytes,
    normalizedTransportBodyBytes,
    "transportBodyBytes/transportBody"
  );
  assertEqual(
    recomputedTransportBodyHash,
    normalizedTransportBodyHash,
    "transportBodyHash/transportBody"
  );

  const submitIdempotencyKey = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_HASH,
        normalizedTransportRequestId,
        normalizedDeployPayloadHash,
        normalizedTargetId
      ]
    )
  );

  const submitHeaders = {
    accept: SMART_ACCOUNT_DEPLOY_SUBMIT_ACCEPT,
    "content-type": normalizedContentType,
    "idempotency-key": submitIdempotencyKey,
    "x-phil-deploy-payload-hash": normalizedDeployPayloadHash,
    "x-phil-proof-type": normalizedProofType,
    "x-phil-target-address": normalizedTargetAddress,
    "x-phil-transport-kind": normalizedTransportKind,
    "x-phil-transport-request-id": normalizedTransportRequestId
  };

  const submitHeadersJson = JSON.stringify(submitHeaders);
  const submitHeadersHash = ethers.keccak256(ethers.toUtf8Bytes(submitHeadersJson));

  const submitRequest = {
    method: normalizedMethod,
    path: normalizedPath,
    headers: submitHeaders,
    body: normalizedTransportBody
  };

  const submitRequestJson = JSON.stringify(submitRequest);
  const submitRequestBytes = ethers.hexlify(ethers.toUtf8Bytes(submitRequestJson));
  const submitRequestHash = ethers.keccak256(ethers.toUtf8Bytes(submitRequestJson));
  const submitRequestLengthBytes = String(ethers.getBytes(submitRequestBytes).length);

  const submitId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedTransportRequestId,
        submitRequestHash
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
    deployPayloadHash: normalizedDeployPayloadHash,
    transportKind: normalizedTransportKind,
    transportRequestId: normalizedTransportRequestId,
    submissionKind: SMART_ACCOUNT_DEPLOY_SUBMIT_KIND,
    submitHeaders,
    submitHeadersHash,
    submitIdempotencyKey,
    submitRequest,
    submitRequestJson,
    submitRequestBytes,
    submitRequestHash,
    submitRequestLengthBytes,
    submitId
  };
}

function buildSmartAccountDeploySubmit({ smartAccountDeployTransport }) {
  if (!smartAccountDeployTransport || typeof smartAccountDeployTransport !== "object") {
    throw new Error("smartAccountDeployTransport is required");
  }

  assertEqual(
    smartAccountDeployTransport.path,
    "phil-smart-account-deploy-transport",
    "smartAccountDeployTransport.path"
  );
  assertEqual(
    smartAccountDeployTransport.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployTransport.payloadShape"
  );

  if (
    !smartAccountDeployTransport.validationChecks ||
    typeof smartAccountDeployTransport.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployTransport.validationChecks is required");
  }
  if (
    !smartAccountDeployTransport.smartAccountDeployTransportSummary ||
    typeof smartAccountDeployTransport.smartAccountDeployTransportSummary !== "object"
  ) {
    throw new Error("smartAccountDeployTransport.smartAccountDeployTransportSummary is required");
  }
  if (
    !smartAccountDeployTransport.smartAccountDeployTransport ||
    typeof smartAccountDeployTransport.smartAccountDeployTransport !== "object"
  ) {
    throw new Error("smartAccountDeployTransport.smartAccountDeployTransport is required");
  }
  if (
    !smartAccountDeployTransport.appSmartAccountDeployTransport ||
    typeof smartAccountDeployTransport.appSmartAccountDeployTransport !== "object"
  ) {
    throw new Error("smartAccountDeployTransport.appSmartAccountDeployTransport is required");
  }

  assertTrue(
    smartAccountDeployTransport.validationChecks.smartAccountDeployPayloadPathValid,
    "validationChecks.smartAccountDeployPayloadPathValid"
  );
  assertTrue(
    smartAccountDeployTransport.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployTransport.validationChecks.upstreamSmartAccountDeployPayloadValid,
    "validationChecks.upstreamSmartAccountDeployPayloadValid"
  );
  assertTrue(
    smartAccountDeployTransport.validationChecks.deterministicSmartAccountDeployTransportDerived,
    "validationChecks.deterministicSmartAccountDeployTransportDerived"
  );
  assertTrue(
    smartAccountDeployTransport.smartAccountDeployTransportSummary.ready,
    "smartAccountDeployTransportSummary.ready"
  );
  assertEqual(
    smartAccountDeployTransport.smartAccountDeployTransportSummary.status,
    "smart-account-deploy-transport-ready",
    "smartAccountDeployTransportSummary.status"
  );
  assertTrue(
    smartAccountDeployTransport.smartAccountDeployTransportSummary.parityProven,
    "smartAccountDeployTransportSummary.parityProven"
  );

  const deterministicSmartAccountDeployTransport = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployTransport.smartAccountDeployTransport.ownerCommitment,
      "smartAccountDeployTransport.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployTransport.smartAccountDeployTransport.consumerDataHash,
      "smartAccountDeployTransport.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployTransport.smartAccountDeployTransport.canonicalRecipient,
      "smartAccountDeployTransport.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployTransport.smartAccountDeployTransport.walletId,
      "smartAccountDeployTransport.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployTransport.smartAccountDeployTransport.targetId,
      "smartAccountDeployTransport.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployTransport.smartAccountDeployTransport.targetAddress,
      "smartAccountDeployTransport.targetAddress"
    ),
    deployPayloadHash: normalizeHex32(
      smartAccountDeployTransport.smartAccountDeployTransport.deployPayloadHash,
      "smartAccountDeployTransport.deployPayloadHash"
    ),
    transportKind: normalizeString(
      smartAccountDeployTransport.smartAccountDeployTransport.transportKind,
      "smartAccountDeployTransport.transportKind"
    ),
    contentType: normalizeString(
      smartAccountDeployTransport.smartAccountDeployTransport.contentType,
      "smartAccountDeployTransport.contentType"
    ),
    method: normalizeString(
      smartAccountDeployTransport.smartAccountDeployTransport.method,
      "smartAccountDeployTransport.method"
    ),
    path: normalizeString(
      smartAccountDeployTransport.smartAccountDeployTransport.path,
      "smartAccountDeployTransport.path"
    ),
    transportBody: normalizeString(
      smartAccountDeployTransport.smartAccountDeployTransport.transportBody,
      "smartAccountDeployTransport.transportBody"
    ),
    transportBodyBytes: normalizeBytes(
      smartAccountDeployTransport.smartAccountDeployTransport.transportBodyBytes,
      "smartAccountDeployTransport.transportBodyBytes"
    ),
    transportBodyHash: normalizeHex32(
      smartAccountDeployTransport.smartAccountDeployTransport.transportBodyHash,
      "smartAccountDeployTransport.transportBodyHash"
    ),
    transportRequestId: normalizeHex32(
      smartAccountDeployTransport.smartAccountDeployTransport.transportRequestId,
      "smartAccountDeployTransport.transportRequestId"
    )
  };

  const appSmartAccountDeployTransport = {
    recipient: normalizeAddress(
      smartAccountDeployTransport.appSmartAccountDeployTransport.recipient,
      "appSmartAccountDeployTransport.recipient"
    ),
    expectedDeployedAddress: normalizeAddress(
      smartAccountDeployTransport.appSmartAccountDeployTransport.expectedDeployedAddress,
      "appSmartAccountDeployTransport.expectedDeployedAddress"
    ),
    contentType: normalizeString(
      smartAccountDeployTransport.appSmartAccountDeployTransport.contentType,
      "appSmartAccountDeployTransport.contentType"
    ),
    method: normalizeString(
      smartAccountDeployTransport.appSmartAccountDeployTransport.method,
      "appSmartAccountDeployTransport.method"
    ),
    path: normalizeString(
      smartAccountDeployTransport.appSmartAccountDeployTransport.path,
      "appSmartAccountDeployTransport.path"
    ),
    transportBody: normalizeString(
      smartAccountDeployTransport.appSmartAccountDeployTransport.transportBody,
      "appSmartAccountDeployTransport.transportBody"
    ),
    transportRequestId: normalizeHex32(
      smartAccountDeployTransport.appSmartAccountDeployTransport.transportRequestId,
      "appSmartAccountDeployTransport.transportRequestId"
    ),
    ready: smartAccountDeployTransport.appSmartAccountDeployTransport.ready === true,
    status: String(smartAccountDeployTransport.appSmartAccountDeployTransport.status || ""),
    parityProven:
      smartAccountDeployTransport.appSmartAccountDeployTransport.parityProven === true
  };

  assertTrue(appSmartAccountDeployTransport.ready, "appSmartAccountDeployTransport.ready");
  assertEqual(
    appSmartAccountDeployTransport.status,
    "smart-account-deploy-transport-ready",
    "appSmartAccountDeployTransport.status"
  );
  assertTrue(
    appSmartAccountDeployTransport.parityProven,
    "appSmartAccountDeployTransport.parityProven"
  );
  assertEqual(
    appSmartAccountDeployTransport.recipient.toLowerCase(),
    deterministicSmartAccountDeployTransport.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployTransport.recipient/smartAccountDeployTransport.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployTransport.expectedDeployedAddress.toLowerCase(),
    deterministicSmartAccountDeployTransport.targetAddress.toLowerCase(),
    "appSmartAccountDeployTransport.expectedDeployedAddress/smartAccountDeployTransport.targetAddress"
  );
  assertEqual(
    appSmartAccountDeployTransport.contentType,
    deterministicSmartAccountDeployTransport.contentType,
    "appSmartAccountDeployTransport.contentType/smartAccountDeployTransport.contentType"
  );
  assertEqual(
    appSmartAccountDeployTransport.method,
    deterministicSmartAccountDeployTransport.method,
    "appSmartAccountDeployTransport.method/smartAccountDeployTransport.method"
  );
  assertEqual(
    appSmartAccountDeployTransport.path,
    deterministicSmartAccountDeployTransport.path,
    "appSmartAccountDeployTransport.path/smartAccountDeployTransport.path"
  );
  assertEqual(
    appSmartAccountDeployTransport.transportBody,
    deterministicSmartAccountDeployTransport.transportBody,
    "appSmartAccountDeployTransport.transportBody/smartAccountDeployTransport.transportBody"
  );
  assertEqual(
    appSmartAccountDeployTransport.transportRequestId,
    deterministicSmartAccountDeployTransport.transportRequestId,
    "appSmartAccountDeployTransport.transportRequestId/smartAccountDeployTransport.transportRequestId"
  );

  const smartAccountDeploySubmit = deriveDeterministicSmartAccountDeploySubmit({
    proofType: smartAccountDeployTransport.proofType,
    ownerCommitment: deterministicSmartAccountDeployTransport.ownerCommitment,
    consumerDataHash: deterministicSmartAccountDeployTransport.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountDeployTransport.canonicalRecipient,
    walletId: deterministicSmartAccountDeployTransport.walletId,
    targetId: deterministicSmartAccountDeployTransport.targetId,
    targetAddress: deterministicSmartAccountDeployTransport.targetAddress,
    deployPayloadHash: deterministicSmartAccountDeployTransport.deployPayloadHash,
    transportKind: deterministicSmartAccountDeployTransport.transportKind,
    contentType: deterministicSmartAccountDeployTransport.contentType,
    method: deterministicSmartAccountDeployTransport.method,
    path: deterministicSmartAccountDeployTransport.path,
    transportBody: deterministicSmartAccountDeployTransport.transportBody,
    transportBodyBytes: deterministicSmartAccountDeployTransport.transportBodyBytes,
    transportBodyHash: deterministicSmartAccountDeployTransport.transportBodyHash,
    transportRequestId: deterministicSmartAccountDeployTransport.transportRequestId
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-submit",
    smartAccountDeploySubmitSource: "scripts/base/build-smart-account-deploy-submit.cjs",
    smartAccountDeployTransportSource: smartAccountDeployTransport.smartAccountDeployTransportSource,
    consumedPath: smartAccountDeployTransport.path,
    proofType: smartAccountDeployTransport.proofType,
    payloadShape: smartAccountDeployTransport.payloadShape,
    smartAccountDeploySubmitDomain: {
      label: SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployTransportPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployTransportValid: true,
      deterministicSmartAccountDeploySubmitDerived: true
    },
    smartAccountDeploySubmitSummary: {
      ready: true,
      status: "smart-account-deploy-submit-ready",
      reason: "validated-smart-account-deploy-transport",
      parityProven: true
    },
    smartAccountDeploySubmit: {
      ownerCommitment: smartAccountDeploySubmit.ownerCommitment,
      consumerDataHash: smartAccountDeploySubmit.consumerDataHash,
      canonicalRecipient: smartAccountDeploySubmit.canonicalRecipient,
      walletId: smartAccountDeploySubmit.walletId,
      targetId: smartAccountDeploySubmit.targetId,
      targetAddress: smartAccountDeploySubmit.targetAddress,
      deployPayloadHash: smartAccountDeploySubmit.deployPayloadHash,
      transportKind: smartAccountDeploySubmit.transportKind,
      transportRequestId: smartAccountDeploySubmit.transportRequestId,
      submissionKind: smartAccountDeploySubmit.submissionKind,
      submitHeaders: smartAccountDeploySubmit.submitHeaders,
      submitHeadersHash: smartAccountDeploySubmit.submitHeadersHash,
      submitIdempotencyKey: smartAccountDeploySubmit.submitIdempotencyKey,
      submitRequest: smartAccountDeploySubmit.submitRequest,
      submitRequestJson: smartAccountDeploySubmit.submitRequestJson,
      submitRequestBytes: smartAccountDeploySubmit.submitRequestBytes,
      submitRequestHash: smartAccountDeploySubmit.submitRequestHash,
      submitRequestLengthBytes: smartAccountDeploySubmit.submitRequestLengthBytes,
      submitId: smartAccountDeploySubmit.submitId
    },
    appSmartAccountDeploySubmit: {
      recipient: smartAccountDeploySubmit.canonicalRecipient,
      expectedDeployedAddress: smartAccountDeploySubmit.targetAddress,
      headers: smartAccountDeploySubmit.submitHeaders,
      request: smartAccountDeploySubmit.submitRequest,
      idempotencyKey: smartAccountDeploySubmit.submitIdempotencyKey,
      submitId: smartAccountDeploySubmit.submitId,
      ready: true,
      status: "smart-account-deploy-submit-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-transport") {
      parsed.smartAccountDeployTransportPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-submit.cjs --smart-account-deploy-transport <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployTransportPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeploySubmit = buildSmartAccountDeploySubmit({
      smartAccountDeployTransport: loadJson(path.resolve(parsed.smartAccountDeployTransportPath))
    });
    console.log(JSON.stringify(smartAccountDeploySubmit, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_SUBMIT_KIND,
  SMART_ACCOUNT_DEPLOY_SUBMIT_ACCEPT,
  deriveDeterministicSmartAccountDeploySubmit,
  buildSmartAccountDeploySubmit
};
