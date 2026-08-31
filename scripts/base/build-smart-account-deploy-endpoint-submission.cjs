const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_TRANSPORT_KIND,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_CONTENT_TYPE,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_ACCEPT
} = require("./build-smart-account-deploy-bundler-submission.cjs");

const SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_V1";
const SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND =
  "erc4337-smart-account-deploy-endpoint-submission-v1";
const SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL =
  "base-8453-bundler-no-send-v1";
const SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL =
  "https://base-8453-bundler.phil.invalid/rpc";

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

function normalizeUintString(value, label) {
  const normalized = String(value || "").trim();
  if (!/^[0-9]+$/.test(normalized)) {
    throw new Error(`Invalid ${label}: ${normalized || "<empty>"}`);
  }
  return normalized;
}

function normalizeBundlerSubmissionTarget(bundlerSubmissionTarget) {
  if (!bundlerSubmissionTarget || typeof bundlerSubmissionTarget !== "object") {
    throw new Error("bundlerSubmissionTarget is required");
  }

  return {
    transportKind: normalizeString(
      bundlerSubmissionTarget.transportKind,
      "bundlerSubmissionTarget.transportKind"
    ),
    rpcMethod: normalizeString(
      bundlerSubmissionTarget.rpcMethod,
      "bundlerSubmissionTarget.rpcMethod"
    ),
    entryPointAddress: normalizeAddress(
      bundlerSubmissionTarget.entryPointAddress,
      "bundlerSubmissionTarget.entryPointAddress"
    ),
    chainId: normalizeUintString(
      bundlerSubmissionTarget.chainId,
      "bundlerSubmissionTarget.chainId"
    )
  };
}

function normalizeSignedBundlerRequest(signedBundlerRequest) {
  if (!signedBundlerRequest || typeof signedBundlerRequest !== "object") {
    throw new Error("bundlerSubmissionBody is required");
  }
  if (!Array.isArray(signedBundlerRequest.params) || signedBundlerRequest.params.length !== 2) {
    throw new Error("bundlerSubmissionBody.params must contain [signedUserOperation, entryPoint]");
  }

  return {
    jsonrpc: normalizeString(signedBundlerRequest.jsonrpc, "bundlerSubmissionBody.jsonrpc"),
    method: normalizeString(signedBundlerRequest.method, "bundlerSubmissionBody.method"),
    params: [
      signedBundlerRequest.params[0],
      normalizeAddress(
        signedBundlerRequest.params[1],
        "bundlerSubmissionBody.params[1]"
      )
    ]
  };
}

function normalizeHeaders(headers, label) {
  if (!headers || typeof headers !== "object") {
    throw new Error(`${label} is required`);
  }

  const normalized = {};
  for (const [key, value] of Object.entries(headers)) {
    normalized[String(key)] = normalizeString(value, `${label}.${String(key)}`);
  }
  return normalized;
}

function normalizeBundlerSubmissionRequest(bundlerSubmissionRequest) {
  if (!bundlerSubmissionRequest || typeof bundlerSubmissionRequest !== "object") {
    throw new Error("bundlerSubmissionRequest is required");
  }

  return {
    method: normalizeString(
      bundlerSubmissionRequest.method,
      "bundlerSubmissionRequest.method"
    ),
    headers: normalizeHeaders(
      bundlerSubmissionRequest.headers,
      "bundlerSubmissionRequest.headers"
    ),
    body: normalizeSignedBundlerRequest(bundlerSubmissionRequest.body)
  };
}

function deriveDeterministicSmartAccountDeployEndpointSubmission({
  proofType,
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  entryPointAddress,
  chainId,
  userOpHash,
  signedUserOpId,
  bundlerSubmissionKind,
  bundlerSubmissionId,
  bundlerSubmissionTarget,
  bundlerSubmissionBody,
  bundlerSubmissionBodyJson,
  bundlerSubmissionBodyBytes,
  bundlerSubmissionBodyHash,
  bundlerSubmissionHeaders,
  bundlerSubmissionRequest,
  bundlerSubmissionRequestHash
}) {
  const normalizedProofType = normalizeString(proofType, "proofType");
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedEntryPointAddress = normalizeAddress(
    entryPointAddress,
    "entryPointAddress"
  );
  const normalizedChainId = normalizeUintString(chainId, "chainId");
  const normalizedUserOpHash = normalizeHex32(userOpHash, "userOpHash");
  const normalizedSignedUserOpId = normalizeHex32(signedUserOpId, "signedUserOpId");
  const normalizedBundlerSubmissionKind = normalizeString(
    bundlerSubmissionKind,
    "bundlerSubmissionKind"
  );
  const normalizedBundlerSubmissionId = normalizeHex32(
    bundlerSubmissionId,
    "bundlerSubmissionId"
  );
  const normalizedBundlerSubmissionTarget = normalizeBundlerSubmissionTarget(
    bundlerSubmissionTarget
  );
  const normalizedBundlerSubmissionBody = normalizeSignedBundlerRequest(
    bundlerSubmissionBody
  );
  const normalizedBundlerSubmissionBodyJson = normalizeString(
    bundlerSubmissionBodyJson,
    "bundlerSubmissionBodyJson"
  );
  const normalizedBundlerSubmissionBodyBytes = normalizeBytes(
    bundlerSubmissionBodyBytes,
    "bundlerSubmissionBodyBytes"
  );
  const normalizedBundlerSubmissionBodyHash = normalizeHex32(
    bundlerSubmissionBodyHash,
    "bundlerSubmissionBodyHash"
  );
  const normalizedBundlerSubmissionHeaders = normalizeHeaders(
    bundlerSubmissionHeaders,
    "bundlerSubmissionHeaders"
  );
  const normalizedBundlerSubmissionRequest = normalizeBundlerSubmissionRequest(
    bundlerSubmissionRequest
  );
  const normalizedBundlerSubmissionRequestHash = normalizeHex32(
    bundlerSubmissionRequestHash,
    "bundlerSubmissionRequestHash"
  );

  assertEqual(
    normalizedBundlerSubmissionKind,
    SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND,
    "bundlerSubmissionKind"
  );
  assertEqual(
    normalizedBundlerSubmissionTarget.transportKind,
    SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_TRANSPORT_KIND,
    "bundlerSubmissionTarget.transportKind"
  );
  assertEqual(
    normalizedBundlerSubmissionRequest.method,
    SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
    "bundlerSubmissionRequest.method"
  );
  assertEqual(
    normalizedBundlerSubmissionHeaders.accept,
    SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_ACCEPT,
    "bundlerSubmissionHeaders.accept"
  );
  assertEqual(
    normalizedBundlerSubmissionHeaders["content-type"],
    SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_CONTENT_TYPE,
    "bundlerSubmissionHeaders.content-type"
  );
  assertEqual(
    normalizedBundlerSubmissionTarget.entryPointAddress.toLowerCase(),
    normalizedEntryPointAddress.toLowerCase(),
    "bundlerSubmissionTarget.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    normalizedBundlerSubmissionTarget.chainId,
    normalizedChainId,
    "bundlerSubmissionTarget.chainId/chainId"
  );
  assertEqual(
    normalizedBundlerSubmissionHeaders["x-phil-chain-id"],
    normalizedChainId,
    "bundlerSubmissionHeaders.x-phil-chain-id/chainId"
  );
  assertEqual(
    normalizedBundlerSubmissionHeaders["x-phil-entry-point-address"].toLowerCase(),
    normalizedEntryPointAddress.toLowerCase(),
    "bundlerSubmissionHeaders.x-phil-entry-point-address/entryPointAddress"
  );
  assertEqual(
    normalizedBundlerSubmissionHeaders["x-phil-target-address"].toLowerCase(),
    normalizedTargetAddress.toLowerCase(),
    "bundlerSubmissionHeaders.x-phil-target-address/targetAddress"
  );
  assertEqual(
    normalizedBundlerSubmissionHeaders["x-phil-userop-hash"],
    normalizedUserOpHash,
    "bundlerSubmissionHeaders.x-phil-userop-hash/userOpHash"
  );
  assertEqual(
    normalizedBundlerSubmissionHeaders["x-phil-proof-type"],
    normalizedProofType,
    "bundlerSubmissionHeaders.x-phil-proof-type/proofType"
  );
  assertEqual(
    normalizedBundlerSubmissionHeaders["x-phil-signed-userop-id"],
    normalizedSignedUserOpId,
    "bundlerSubmissionHeaders.x-phil-signed-userop-id/signedUserOpId"
  );
  assertEqual(
    JSON.stringify(normalizedBundlerSubmissionRequest.headers),
    JSON.stringify(normalizedBundlerSubmissionHeaders),
    "bundlerSubmissionRequest.headers/bundlerSubmissionHeaders"
  );
  assertEqual(
    JSON.stringify(normalizedBundlerSubmissionRequest.body),
    JSON.stringify(normalizedBundlerSubmissionBody),
    "bundlerSubmissionRequest.body/bundlerSubmissionBody"
  );

  const recomputedBundlerSubmissionBodyJson = JSON.stringify(normalizedBundlerSubmissionBody);
  const recomputedBundlerSubmissionBodyBytes = ethers.hexlify(
    ethers.toUtf8Bytes(recomputedBundlerSubmissionBodyJson)
  );
  const recomputedBundlerSubmissionBodyHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedBundlerSubmissionBodyJson)
  );
  assertEqual(
    recomputedBundlerSubmissionBodyJson,
    normalizedBundlerSubmissionBodyJson,
    "bundlerSubmissionBodyJson"
  );
  assertEqual(
    recomputedBundlerSubmissionBodyBytes,
    normalizedBundlerSubmissionBodyBytes,
    "bundlerSubmissionBodyBytes"
  );
  assertEqual(
    recomputedBundlerSubmissionBodyHash,
    normalizedBundlerSubmissionBodyHash,
    "bundlerSubmissionBodyHash"
  );

  const recomputedBundlerSubmissionRequestJson = JSON.stringify(
    normalizedBundlerSubmissionRequest
  );
  const recomputedBundlerSubmissionRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedBundlerSubmissionRequestJson)
  );
  assertEqual(
    recomputedBundlerSubmissionRequestHash,
    normalizedBundlerSubmissionRequestHash,
    "bundlerSubmissionRequestHash"
  );

  const endpointUrl = new URL(SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL);
  const endpointUrlString = endpointUrl.toString();
  const endpointOrigin = endpointUrl.origin;
  const endpointProtocol = endpointUrl.protocol;
  const endpointHostname = endpointUrl.hostname;
  const endpointHost = endpointUrl.host;
  const endpointPathname = endpointUrl.pathname;
  const endpointUrlHash = ethers.keccak256(ethers.toUtf8Bytes(endpointUrlString));

  const endpointBinding = {
    endpointLabel: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL,
    endpointUrl: endpointUrlString,
    endpointOrigin,
    endpointProtocol,
    endpointHost,
    endpointHostname,
    endpointPathname
  };

  const endpointHeaders = {
    ...normalizedBundlerSubmissionHeaders,
    host: endpointHost,
    origin: endpointOrigin,
    "x-phil-endpoint-label": SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL,
    "x-phil-endpoint-url-hash": endpointUrlHash
  };
  const endpointHeadersJson = JSON.stringify(endpointHeaders);
  const endpointHeadersHash = ethers.keccak256(ethers.toUtf8Bytes(endpointHeadersJson));

  const endpointRequest = {
    url: endpointUrlString,
    method: normalizedBundlerSubmissionRequest.method,
    headers: endpointHeaders,
    body: normalizedBundlerSubmissionRequest.body
  };
  const endpointRequestJson = JSON.stringify(endpointRequest);
  const endpointRequestBytes = ethers.hexlify(ethers.toUtf8Bytes(endpointRequestJson));
  const endpointRequestHash = ethers.keccak256(ethers.toUtf8Bytes(endpointRequestJson));

  const endpointSubmissionId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedBundlerSubmissionId,
        endpointRequestHash
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
    entryPointAddress: normalizedEntryPointAddress,
    chainId: normalizedChainId,
    userOpHash: normalizedUserOpHash,
    signedUserOpId: normalizedSignedUserOpId,
    bundlerSubmissionKind: normalizedBundlerSubmissionKind,
    bundlerSubmissionId: normalizedBundlerSubmissionId,
    bundlerSubmissionRequestHash: normalizedBundlerSubmissionRequestHash,
    endpointSubmissionKind: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND,
    endpointBinding,
    endpointUrlHash,
    endpointHeaders,
    endpointHeadersJson,
    endpointHeadersHash,
    endpointRequest,
    endpointRequestJson,
    endpointRequestBytes,
    endpointRequestHash,
    endpointSubmissionId
  };
}

function buildSmartAccountDeployEndpointSubmission({ smartAccountDeployBundlerSubmission }) {
  if (
    !smartAccountDeployBundlerSubmission ||
    typeof smartAccountDeployBundlerSubmission !== "object"
  ) {
    throw new Error("smartAccountDeployBundlerSubmission is required");
  }

  assertEqual(
    smartAccountDeployBundlerSubmission.path,
    "phil-smart-account-deploy-bundler-submission",
    "smartAccountDeployBundlerSubmission.path"
  );
  assertEqual(
    smartAccountDeployBundlerSubmission.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployBundlerSubmission.payloadShape"
  );

  if (
    !smartAccountDeployBundlerSubmission.validationChecks ||
    typeof smartAccountDeployBundlerSubmission.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployBundlerSubmission.validationChecks is required");
  }
  if (
    !smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary ||
    typeof smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary is required"
    );
  }
  if (
    !smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission ||
    typeof smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission is required"
    );
  }
  if (
    !smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission ||
    typeof smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission is required"
    );
  }

  assertTrue(
    smartAccountDeployBundlerSubmission.validationChecks
      .smartAccountDeploySignedUserOpPathValid,
    "validationChecks.smartAccountDeploySignedUserOpPathValid"
  );
  assertTrue(
    smartAccountDeployBundlerSubmission.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployBundlerSubmission.validationChecks
      .upstreamSmartAccountDeploySignedUserOpValid,
    "validationChecks.upstreamSmartAccountDeploySignedUserOpValid"
  );
  assertTrue(
    smartAccountDeployBundlerSubmission.validationChecks
      .deterministicSmartAccountDeployBundlerSubmissionDerived,
    "validationChecks.deterministicSmartAccountDeployBundlerSubmissionDerived"
  );
  assertTrue(
    smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary.ready,
    "smartAccountDeployBundlerSubmissionSummary.ready"
  );
  assertEqual(
    smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary.status,
    "smart-account-deploy-bundler-submission-ready",
    "smartAccountDeployBundlerSubmissionSummary.status"
  );
  assertTrue(
    smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary
      .parityProven,
    "smartAccountDeployBundlerSubmissionSummary.parityProven"
  );

  const deterministicSmartAccountDeployBundlerSubmission = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .ownerCommitment,
      "smartAccountDeployBundlerSubmission.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .consumerDataHash,
      "smartAccountDeployBundlerSubmission.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .canonicalRecipient,
      "smartAccountDeployBundlerSubmission.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.walletId,
      "smartAccountDeployBundlerSubmission.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.targetId,
      "smartAccountDeployBundlerSubmission.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .targetAddress,
      "smartAccountDeployBundlerSubmission.targetAddress"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .entryPointAddress,
      "smartAccountDeployBundlerSubmission.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.chainId,
      "smartAccountDeployBundlerSubmission.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.userOpHash,
      "smartAccountDeployBundlerSubmission.userOpHash"
    ),
    signedUserOpId: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .signedUserOpId,
      "smartAccountDeployBundlerSubmission.signedUserOpId"
    ),
    bundlerSubmissionKind: normalizeString(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionKind,
      "smartAccountDeployBundlerSubmission.bundlerSubmissionKind"
    ),
    bundlerSubmissionId: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionId,
      "smartAccountDeployBundlerSubmission.bundlerSubmissionId"
    ),
    bundlerSubmissionTarget: normalizeBundlerSubmissionTarget(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionTarget
    ),
    bundlerSubmissionBody: normalizeSignedBundlerRequest(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBody
    ),
    bundlerSubmissionBodyJson: normalizeString(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBodyJson,
      "smartAccountDeployBundlerSubmission.bundlerSubmissionBodyJson"
    ),
    bundlerSubmissionBodyBytes: normalizeBytes(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBodyBytes,
      "smartAccountDeployBundlerSubmission.bundlerSubmissionBodyBytes"
    ),
    bundlerSubmissionBodyHash: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBodyHash,
      "smartAccountDeployBundlerSubmission.bundlerSubmissionBodyHash"
    ),
    bundlerSubmissionHeaders: normalizeHeaders(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders,
      "smartAccountDeployBundlerSubmission.bundlerSubmissionHeaders"
    ),
    bundlerSubmissionRequest: normalizeBundlerSubmissionRequest(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionRequest
    ),
    bundlerSubmissionRequestHash: normalizeHex32(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionRequestHash,
      "smartAccountDeployBundlerSubmission.bundlerSubmissionRequestHash"
    )
  };

  const appSmartAccountDeployBundlerSubmission = {
    recipient: normalizeAddress(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .recipient,
      "appSmartAccountDeployBundlerSubmission.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission.sender,
      "appSmartAccountDeployBundlerSubmission.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .entryPointAddress,
      "appSmartAccountDeployBundlerSubmission.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .chainId,
      "appSmartAccountDeployBundlerSubmission.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .userOpHash,
      "appSmartAccountDeployBundlerSubmission.userOpHash"
    ),
    signedUserOpId: normalizeHex32(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .signedUserOpId,
      "appSmartAccountDeployBundlerSubmission.signedUserOpId"
    ),
    bundlerSubmissionKind: normalizeString(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .bundlerSubmissionKind,
      "appSmartAccountDeployBundlerSubmission.bundlerSubmissionKind"
    ),
    bundlerSubmissionId: normalizeHex32(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .bundlerSubmissionId,
      "appSmartAccountDeployBundlerSubmission.bundlerSubmissionId"
    ),
    bundlerSubmissionRequestHash: normalizeHex32(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .bundlerSubmissionRequestHash,
      "appSmartAccountDeployBundlerSubmission.bundlerSubmissionRequestHash"
    ),
    ready:
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission.ready ===
      true,
    status: normalizeString(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .status,
      "appSmartAccountDeployBundlerSubmission.status"
    ),
    parityProven:
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .parityProven === true
  };

  assertTrue(
    appSmartAccountDeployBundlerSubmission.ready,
    "appSmartAccountDeployBundlerSubmission.ready"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.status,
    "smart-account-deploy-bundler-submission-ready",
    "appSmartAccountDeployBundlerSubmission.status"
  );
  assertTrue(
    appSmartAccountDeployBundlerSubmission.parityProven,
    "appSmartAccountDeployBundlerSubmission.parityProven"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.recipient.toLowerCase(),
    deterministicSmartAccountDeployBundlerSubmission.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployBundlerSubmission.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.sender.toLowerCase(),
    deterministicSmartAccountDeployBundlerSubmission.targetAddress.toLowerCase(),
    "appSmartAccountDeployBundlerSubmission.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeployBundlerSubmission.entryPointAddress.toLowerCase(),
    "appSmartAccountDeployBundlerSubmission.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.chainId,
    deterministicSmartAccountDeployBundlerSubmission.chainId,
    "appSmartAccountDeployBundlerSubmission.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.userOpHash,
    deterministicSmartAccountDeployBundlerSubmission.userOpHash,
    "appSmartAccountDeployBundlerSubmission.userOpHash/userOpHash"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.signedUserOpId,
    deterministicSmartAccountDeployBundlerSubmission.signedUserOpId,
    "appSmartAccountDeployBundlerSubmission.signedUserOpId/signedUserOpId"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.bundlerSubmissionKind,
    deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionKind,
    "appSmartAccountDeployBundlerSubmission.bundlerSubmissionKind/bundlerSubmissionKind"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.bundlerSubmissionId,
    deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionId,
    "appSmartAccountDeployBundlerSubmission.bundlerSubmissionId/bundlerSubmissionId"
  );
  assertEqual(
    appSmartAccountDeployBundlerSubmission.bundlerSubmissionRequestHash,
    deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionRequestHash,
    "appSmartAccountDeployBundlerSubmission.bundlerSubmissionRequestHash/bundlerSubmissionRequestHash"
  );

  const smartAccountDeployEndpointSubmission =
    deriveDeterministicSmartAccountDeployEndpointSubmission({
      proofType: smartAccountDeployBundlerSubmission.proofType,
      ownerCommitment:
        deterministicSmartAccountDeployBundlerSubmission.ownerCommitment,
      consumerDataHash:
        deterministicSmartAccountDeployBundlerSubmission.consumerDataHash,
      canonicalRecipient:
        deterministicSmartAccountDeployBundlerSubmission.canonicalRecipient,
      walletId: deterministicSmartAccountDeployBundlerSubmission.walletId,
      targetId: deterministicSmartAccountDeployBundlerSubmission.targetId,
      targetAddress:
        deterministicSmartAccountDeployBundlerSubmission.targetAddress,
      entryPointAddress:
        deterministicSmartAccountDeployBundlerSubmission.entryPointAddress,
      chainId: deterministicSmartAccountDeployBundlerSubmission.chainId,
      userOpHash: deterministicSmartAccountDeployBundlerSubmission.userOpHash,
      signedUserOpId:
        deterministicSmartAccountDeployBundlerSubmission.signedUserOpId,
      bundlerSubmissionKind:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionKind,
      bundlerSubmissionId:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionId,
      bundlerSubmissionTarget:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionTarget,
      bundlerSubmissionBody:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionBody,
      bundlerSubmissionBodyJson:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionBodyJson,
      bundlerSubmissionBodyBytes:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionBodyBytes,
      bundlerSubmissionBodyHash:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionBodyHash,
      bundlerSubmissionHeaders:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionHeaders,
      bundlerSubmissionRequest:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionRequest,
      bundlerSubmissionRequestHash:
        deterministicSmartAccountDeployBundlerSubmission.bundlerSubmissionRequestHash
    });

  return {
    version: 1,
    path: "phil-smart-account-deploy-endpoint-submission",
    smartAccountDeployEndpointSubmissionSource:
      "scripts/base/build-smart-account-deploy-endpoint-submission.cjs",
    smartAccountDeployBundlerSubmissionSource:
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSource,
    consumedPath: smartAccountDeployBundlerSubmission.path,
    proofType: smartAccountDeployBundlerSubmission.proofType,
    payloadShape: smartAccountDeployBundlerSubmission.payloadShape,
    smartAccountDeployEndpointSubmissionDomain: {
      label: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployBundlerSubmissionPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployBundlerSubmissionValid: true,
      deterministicSmartAccountDeployEndpointSubmissionDerived: true
    },
    smartAccountDeployEndpointSubmissionSummary: {
      ready: true,
      status: "smart-account-deploy-endpoint-submission-ready",
      reason: "validated-smart-account-deploy-bundler-submission",
      parityProven: true
    },
    smartAccountDeployEndpointSubmission: {
      ownerCommitment: smartAccountDeployEndpointSubmission.ownerCommitment,
      consumerDataHash: smartAccountDeployEndpointSubmission.consumerDataHash,
      canonicalRecipient: smartAccountDeployEndpointSubmission.canonicalRecipient,
      walletId: smartAccountDeployEndpointSubmission.walletId,
      targetId: smartAccountDeployEndpointSubmission.targetId,
      targetAddress: smartAccountDeployEndpointSubmission.targetAddress,
      entryPointAddress: smartAccountDeployEndpointSubmission.entryPointAddress,
      chainId: smartAccountDeployEndpointSubmission.chainId,
      userOpHash: smartAccountDeployEndpointSubmission.userOpHash,
      signedUserOpId: smartAccountDeployEndpointSubmission.signedUserOpId,
      bundlerSubmissionKind:
        smartAccountDeployEndpointSubmission.bundlerSubmissionKind,
      bundlerSubmissionId:
        smartAccountDeployEndpointSubmission.bundlerSubmissionId,
      bundlerSubmissionRequestHash:
        smartAccountDeployEndpointSubmission.bundlerSubmissionRequestHash,
      endpointSubmissionKind:
        smartAccountDeployEndpointSubmission.endpointSubmissionKind,
      endpointBinding: smartAccountDeployEndpointSubmission.endpointBinding,
      endpointUrlHash: smartAccountDeployEndpointSubmission.endpointUrlHash,
      endpointHeaders: smartAccountDeployEndpointSubmission.endpointHeaders,
      endpointHeadersJson: smartAccountDeployEndpointSubmission.endpointHeadersJson,
      endpointHeadersHash: smartAccountDeployEndpointSubmission.endpointHeadersHash,
      endpointRequest: smartAccountDeployEndpointSubmission.endpointRequest,
      endpointRequestJson: smartAccountDeployEndpointSubmission.endpointRequestJson,
      endpointRequestBytes:
        smartAccountDeployEndpointSubmission.endpointRequestBytes,
      endpointRequestHash: smartAccountDeployEndpointSubmission.endpointRequestHash,
      endpointSubmissionId:
        smartAccountDeployEndpointSubmission.endpointSubmissionId
    },
    appSmartAccountDeployEndpointSubmission: {
      recipient: smartAccountDeployEndpointSubmission.canonicalRecipient,
      sender: smartAccountDeployEndpointSubmission.targetAddress,
      entryPointAddress: smartAccountDeployEndpointSubmission.entryPointAddress,
      chainId: smartAccountDeployEndpointSubmission.chainId,
      endpointUrl:
        smartAccountDeployEndpointSubmission.endpointBinding.endpointUrl,
      bundlerSubmissionId:
        smartAccountDeployEndpointSubmission.bundlerSubmissionId,
      endpointSubmissionKind:
        smartAccountDeployEndpointSubmission.endpointSubmissionKind,
      endpointSubmissionId:
        smartAccountDeployEndpointSubmission.endpointSubmissionId,
      endpointRequestHash:
        smartAccountDeployEndpointSubmission.endpointRequestHash,
      ready: true,
      status: "smart-account-deploy-endpoint-submission-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-bundler-submission") {
      parsed.smartAccountDeployBundlerSubmissionPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-endpoint-submission.cjs --smart-account-deploy-bundler-submission <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployBundlerSubmissionPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployEndpointSubmission =
      buildSmartAccountDeployEndpointSubmission({
        smartAccountDeployBundlerSubmission: loadJson(
          path.resolve(parsed.smartAccountDeployBundlerSubmissionPath)
        )
      });
    console.log(JSON.stringify(smartAccountDeployEndpointSubmission, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
  deriveDeterministicSmartAccountDeployEndpointSubmission,
  buildSmartAccountDeployEndpointSubmission
};
