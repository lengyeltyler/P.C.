const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL
} = require("./build-smart-account-deploy-endpoint-submission.cjs");

const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_V1";
const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND =
  "erc4337-smart-account-deploy-client-session-v1";
const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_LABEL =
  "base-8453-device-no-send-session-v1";
const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_CHANNEL =
  "device-app-submission-loop-v1";
const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE = "prepared-no-send";
const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_NEXT_ACTION =
  "await-explicit-dispatch";
const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DISPATCH_MODE = "manual-no-send";
const SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_ATTEMPT_COUNT = "0";

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

function normalizeBoolean(value, label) {
  if (value !== true && value !== false) {
    throw new Error(`Invalid ${label}: ${String(value)}`);
  }
  return value;
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

function normalizeEndpointBinding(endpointBinding) {
  if (!endpointBinding || typeof endpointBinding !== "object") {
    throw new Error("endpointBinding is required");
  }

  return {
    endpointLabel: normalizeString(endpointBinding.endpointLabel, "endpointBinding.endpointLabel"),
    endpointUrl: normalizeString(endpointBinding.endpointUrl, "endpointBinding.endpointUrl"),
    endpointOrigin: normalizeString(
      endpointBinding.endpointOrigin,
      "endpointBinding.endpointOrigin"
    ),
    endpointProtocol: normalizeString(
      endpointBinding.endpointProtocol,
      "endpointBinding.endpointProtocol"
    ),
    endpointHost: normalizeString(endpointBinding.endpointHost, "endpointBinding.endpointHost"),
    endpointHostname: normalizeString(
      endpointBinding.endpointHostname,
      "endpointBinding.endpointHostname"
    ),
    endpointPathname: normalizeString(
      endpointBinding.endpointPathname,
      "endpointBinding.endpointPathname"
    )
  };
}

function normalizeEndpointBody(endpointBody) {
  if (!endpointBody || typeof endpointBody !== "object") {
    throw new Error("endpointRequest.body is required");
  }
  if (!Array.isArray(endpointBody.params) || endpointBody.params.length !== 2) {
    throw new Error("endpointRequest.body.params must contain [signedUserOperation, entryPoint]");
  }

  return {
    jsonrpc: normalizeString(endpointBody.jsonrpc, "endpointRequest.body.jsonrpc"),
    method: normalizeString(endpointBody.method, "endpointRequest.body.method"),
    params: [endpointBody.params[0], normalizeAddress(endpointBody.params[1], "endpointRequest.body.params[1]")]
  };
}

function normalizeEndpointRequest(endpointRequest) {
  if (!endpointRequest || typeof endpointRequest !== "object") {
    throw new Error("endpointRequest is required");
  }

  return {
    url: normalizeString(endpointRequest.url, "endpointRequest.url"),
    method: normalizeString(endpointRequest.method, "endpointRequest.method"),
    headers: normalizeHeaders(endpointRequest.headers, "endpointRequest.headers"),
    body: normalizeEndpointBody(endpointRequest.body)
  };
}

function deriveDeterministicSmartAccountDeployClientSession({
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
  bundlerSubmissionId,
  endpointSubmissionKind,
  endpointSubmissionId,
  endpointBinding,
  endpointUrlHash,
  endpointHeaders,
  endpointRequest,
  endpointRequestHash
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
  const normalizedBundlerSubmissionId = normalizeHex32(
    bundlerSubmissionId,
    "bundlerSubmissionId"
  );
  const normalizedEndpointSubmissionKind = normalizeString(
    endpointSubmissionKind,
    "endpointSubmissionKind"
  );
  const normalizedEndpointSubmissionId = normalizeHex32(
    endpointSubmissionId,
    "endpointSubmissionId"
  );
  const normalizedEndpointBinding = normalizeEndpointBinding(endpointBinding);
  const normalizedEndpointUrlHash = normalizeHex32(endpointUrlHash, "endpointUrlHash");
  const normalizedEndpointHeaders = normalizeHeaders(endpointHeaders, "endpointHeaders");
  const normalizedEndpointRequest = normalizeEndpointRequest(endpointRequest);
  const normalizedEndpointRequestHash = normalizeHex32(
    endpointRequestHash,
    "endpointRequestHash"
  );

  assertEqual(
    normalizedEndpointSubmissionKind,
    SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND,
    "endpointSubmissionKind"
  );
  assertEqual(
    normalizedEndpointBinding.endpointLabel,
    SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL,
    "endpointBinding.endpointLabel"
  );
  assertEqual(
    normalizedEndpointBinding.endpointUrl,
    SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
    "endpointBinding.endpointUrl"
  );
  assertEqual(
    normalizedEndpointRequest.url,
    normalizedEndpointBinding.endpointUrl,
    "endpointRequest.url/endpointBinding.endpointUrl"
  );
  assertEqual(
    normalizeAddress(
      normalizedEndpointHeaders["x-phil-entry-point-address"],
      "endpointHeaders.x-phil-entry-point-address"
    ).toLowerCase(),
    normalizedEntryPointAddress.toLowerCase(),
    "endpointHeaders.x-phil-entry-point-address/entryPointAddress"
  );
  assertEqual(
    normalizedEndpointHeaders["x-phil-chain-id"],
    normalizedChainId,
    "endpointHeaders.x-phil-chain-id/chainId"
  );
  assertEqual(
    normalizeAddress(
      normalizedEndpointHeaders["x-phil-target-address"],
      "endpointHeaders.x-phil-target-address"
    ).toLowerCase(),
    normalizedTargetAddress.toLowerCase(),
    "endpointHeaders.x-phil-target-address/targetAddress"
  );
  assertEqual(
    normalizedEndpointHeaders["x-phil-userop-hash"],
    normalizedUserOpHash,
    "endpointHeaders.x-phil-userop-hash/userOpHash"
  );
  assertEqual(
    normalizedEndpointHeaders["x-phil-proof-type"],
    normalizedProofType,
    "endpointHeaders.x-phil-proof-type/proofType"
  );
  assertEqual(
    normalizedEndpointHeaders["x-phil-endpoint-label"],
    normalizedEndpointBinding.endpointLabel,
    "endpointHeaders.x-phil-endpoint-label/endpointBinding.endpointLabel"
  );
  assertEqual(
    normalizedEndpointHeaders["x-phil-endpoint-url-hash"],
    normalizedEndpointUrlHash,
    "endpointHeaders.x-phil-endpoint-url-hash/endpointUrlHash"
  );
  assertEqual(
    JSON.stringify(normalizedEndpointRequest.headers),
    JSON.stringify(normalizedEndpointHeaders),
    "endpointRequest.headers/endpointHeaders"
  );

  const recomputedEndpointRequestJson = JSON.stringify(normalizedEndpointRequest);
  const recomputedEndpointRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedEndpointRequestJson)
  );
  assertEqual(
    recomputedEndpointRequestHash,
    normalizedEndpointRequestHash,
    "endpointRequestHash"
  );

  const clientSessionContext = {
    sessionLabel: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_LABEL,
    sessionChannel: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_CHANNEL,
    sessionStage: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE,
    dispatchMode: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DISPATCH_MODE,
    nextAction: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_NEXT_ACTION,
    attemptCount: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_ATTEMPT_COUNT,
    networkSubmissionPerformed: false,
    responseObserved: false,
    pollingEnabled: false,
    readyToDispatch: true,
    endpointLabel: normalizedEndpointBinding.endpointLabel,
    endpointUrl: normalizedEndpointBinding.endpointUrl,
    requestMethod: normalizedEndpointRequest.method,
    requestHash: normalizedEndpointRequestHash
  };
  const clientSessionContextJson = JSON.stringify(clientSessionContext);
  const clientSessionContextHash = ethers.keccak256(
    ethers.toUtf8Bytes(clientSessionContextJson)
  );

  const clientSessionId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedEndpointSubmissionId,
        clientSessionContextHash
      ]
    )
  );

  const clientSessionHandoff = {
    sessionId: clientSessionId,
    session: clientSessionContext,
    endpointRequest: normalizedEndpointRequest
  };
  const clientSessionHandoffJson = JSON.stringify(clientSessionHandoff);
  const clientSessionHandoffBytes = ethers.hexlify(
    ethers.toUtf8Bytes(clientSessionHandoffJson)
  );
  const clientSessionHandoffHash = ethers.keccak256(
    ethers.toUtf8Bytes(clientSessionHandoffJson)
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
    bundlerSubmissionId: normalizedBundlerSubmissionId,
    endpointSubmissionKind: normalizedEndpointSubmissionKind,
    endpointSubmissionId: normalizedEndpointSubmissionId,
    endpointRequestHash: normalizedEndpointRequestHash,
    clientSessionKind: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND,
    clientSessionContext,
    clientSessionContextJson,
    clientSessionContextHash,
    clientSessionId,
    clientSessionHandoff,
    clientSessionHandoffJson,
    clientSessionHandoffBytes,
    clientSessionHandoffHash
  };
}

function buildSmartAccountDeployClientSession({ smartAccountDeployEndpointSubmission }) {
  if (
    !smartAccountDeployEndpointSubmission ||
    typeof smartAccountDeployEndpointSubmission !== "object"
  ) {
    throw new Error("smartAccountDeployEndpointSubmission is required");
  }

  assertEqual(
    smartAccountDeployEndpointSubmission.path,
    "phil-smart-account-deploy-endpoint-submission",
    "smartAccountDeployEndpointSubmission.path"
  );
  assertEqual(
    smartAccountDeployEndpointSubmission.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployEndpointSubmission.payloadShape"
  );

  if (
    !smartAccountDeployEndpointSubmission.validationChecks ||
    typeof smartAccountDeployEndpointSubmission.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployEndpointSubmission.validationChecks is required");
  }
  if (
    !smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary ||
    typeof smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary is required"
    );
  }
  if (
    !smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission ||
    typeof smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission is required"
    );
  }
  if (
    !smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission ||
    typeof smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission is required"
    );
  }

  assertTrue(
    smartAccountDeployEndpointSubmission.validationChecks
      .smartAccountDeployBundlerSubmissionPathValid,
    "validationChecks.smartAccountDeployBundlerSubmissionPathValid"
  );
  assertTrue(
    smartAccountDeployEndpointSubmission.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployEndpointSubmission.validationChecks
      .upstreamSmartAccountDeployBundlerSubmissionValid,
    "validationChecks.upstreamSmartAccountDeployBundlerSubmissionValid"
  );
  assertTrue(
    smartAccountDeployEndpointSubmission.validationChecks
      .deterministicSmartAccountDeployEndpointSubmissionDerived,
    "validationChecks.deterministicSmartAccountDeployEndpointSubmissionDerived"
  );
  assertTrue(
    smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary
      .ready,
    "smartAccountDeployEndpointSubmissionSummary.ready"
  );
  assertEqual(
    smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary
      .status,
    "smart-account-deploy-endpoint-submission-ready",
    "smartAccountDeployEndpointSubmissionSummary.status"
  );
  assertTrue(
    smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary
      .parityProven,
    "smartAccountDeployEndpointSubmissionSummary.parityProven"
  );

  const deterministicSmartAccountDeployEndpointSubmission = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .ownerCommitment,
      "smartAccountDeployEndpointSubmission.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .consumerDataHash,
      "smartAccountDeployEndpointSubmission.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .canonicalRecipient,
      "smartAccountDeployEndpointSubmission.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission.walletId,
      "smartAccountDeployEndpointSubmission.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission.targetId,
      "smartAccountDeployEndpointSubmission.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .targetAddress,
      "smartAccountDeployEndpointSubmission.targetAddress"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .entryPointAddress,
      "smartAccountDeployEndpointSubmission.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission.chainId,
      "smartAccountDeployEndpointSubmission.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .userOpHash,
      "smartAccountDeployEndpointSubmission.userOpHash"
    ),
    bundlerSubmissionId: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .bundlerSubmissionId,
      "smartAccountDeployEndpointSubmission.bundlerSubmissionId"
    ),
    endpointSubmissionKind: normalizeString(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointSubmissionKind,
      "smartAccountDeployEndpointSubmission.endpointSubmissionKind"
    ),
    endpointSubmissionId: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointSubmissionId,
      "smartAccountDeployEndpointSubmission.endpointSubmissionId"
    ),
    endpointBinding: normalizeEndpointBinding(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointBinding
    ),
    endpointUrlHash: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointUrlHash,
      "smartAccountDeployEndpointSubmission.endpointUrlHash"
    ),
    endpointHeaders: normalizeHeaders(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders,
      "smartAccountDeployEndpointSubmission.endpointHeaders"
    ),
    endpointRequest: normalizeEndpointRequest(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequest
    ),
    endpointRequestHash: normalizeHex32(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequestHash,
      "smartAccountDeployEndpointSubmission.endpointRequestHash"
    )
  };

  const appSmartAccountDeployEndpointSubmission = {
    recipient: normalizeAddress(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .recipient,
      "appSmartAccountDeployEndpointSubmission.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .sender,
      "appSmartAccountDeployEndpointSubmission.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .entryPointAddress,
      "appSmartAccountDeployEndpointSubmission.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .chainId,
      "appSmartAccountDeployEndpointSubmission.chainId"
    ),
    endpointUrl: normalizeString(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .endpointUrl,
      "appSmartAccountDeployEndpointSubmission.endpointUrl"
    ),
    bundlerSubmissionId: normalizeHex32(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .bundlerSubmissionId,
      "appSmartAccountDeployEndpointSubmission.bundlerSubmissionId"
    ),
    endpointSubmissionKind: normalizeString(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .endpointSubmissionKind,
      "appSmartAccountDeployEndpointSubmission.endpointSubmissionKind"
    ),
    endpointSubmissionId: normalizeHex32(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .endpointSubmissionId,
      "appSmartAccountDeployEndpointSubmission.endpointSubmissionId"
    ),
    endpointRequestHash: normalizeHex32(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .endpointRequestHash,
      "appSmartAccountDeployEndpointSubmission.endpointRequestHash"
    ),
    ready:
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .ready === true,
    status: normalizeString(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .status,
      "appSmartAccountDeployEndpointSubmission.status"
    ),
    parityProven:
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .parityProven === true
  };

  assertTrue(
    appSmartAccountDeployEndpointSubmission.ready,
    "appSmartAccountDeployEndpointSubmission.ready"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.status,
    "smart-account-deploy-endpoint-submission-ready",
    "appSmartAccountDeployEndpointSubmission.status"
  );
  assertTrue(
    appSmartAccountDeployEndpointSubmission.parityProven,
    "appSmartAccountDeployEndpointSubmission.parityProven"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.recipient.toLowerCase(),
    deterministicSmartAccountDeployEndpointSubmission.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployEndpointSubmission.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.sender.toLowerCase(),
    deterministicSmartAccountDeployEndpointSubmission.targetAddress.toLowerCase(),
    "appSmartAccountDeployEndpointSubmission.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeployEndpointSubmission.entryPointAddress.toLowerCase(),
    "appSmartAccountDeployEndpointSubmission.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.chainId,
    deterministicSmartAccountDeployEndpointSubmission.chainId,
    "appSmartAccountDeployEndpointSubmission.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.endpointUrl,
    deterministicSmartAccountDeployEndpointSubmission.endpointBinding.endpointUrl,
    "appSmartAccountDeployEndpointSubmission.endpointUrl/endpointBinding.endpointUrl"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.bundlerSubmissionId,
    deterministicSmartAccountDeployEndpointSubmission.bundlerSubmissionId,
    "appSmartAccountDeployEndpointSubmission.bundlerSubmissionId/bundlerSubmissionId"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.endpointSubmissionKind,
    deterministicSmartAccountDeployEndpointSubmission.endpointSubmissionKind,
    "appSmartAccountDeployEndpointSubmission.endpointSubmissionKind/endpointSubmissionKind"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.endpointSubmissionId,
    deterministicSmartAccountDeployEndpointSubmission.endpointSubmissionId,
    "appSmartAccountDeployEndpointSubmission.endpointSubmissionId/endpointSubmissionId"
  );
  assertEqual(
    appSmartAccountDeployEndpointSubmission.endpointRequestHash,
    deterministicSmartAccountDeployEndpointSubmission.endpointRequestHash,
    "appSmartAccountDeployEndpointSubmission.endpointRequestHash/endpointRequestHash"
  );

  const smartAccountDeployClientSession =
    deriveDeterministicSmartAccountDeployClientSession({
      proofType: smartAccountDeployEndpointSubmission.proofType,
      ownerCommitment:
        deterministicSmartAccountDeployEndpointSubmission.ownerCommitment,
      consumerDataHash:
        deterministicSmartAccountDeployEndpointSubmission.consumerDataHash,
      canonicalRecipient:
        deterministicSmartAccountDeployEndpointSubmission.canonicalRecipient,
      walletId: deterministicSmartAccountDeployEndpointSubmission.walletId,
      targetId: deterministicSmartAccountDeployEndpointSubmission.targetId,
      targetAddress:
        deterministicSmartAccountDeployEndpointSubmission.targetAddress,
      entryPointAddress:
        deterministicSmartAccountDeployEndpointSubmission.entryPointAddress,
      chainId: deterministicSmartAccountDeployEndpointSubmission.chainId,
      userOpHash: deterministicSmartAccountDeployEndpointSubmission.userOpHash,
      bundlerSubmissionId:
        deterministicSmartAccountDeployEndpointSubmission.bundlerSubmissionId,
      endpointSubmissionKind:
        deterministicSmartAccountDeployEndpointSubmission.endpointSubmissionKind,
      endpointSubmissionId:
        deterministicSmartAccountDeployEndpointSubmission.endpointSubmissionId,
      endpointBinding:
        deterministicSmartAccountDeployEndpointSubmission.endpointBinding,
      endpointUrlHash:
        deterministicSmartAccountDeployEndpointSubmission.endpointUrlHash,
      endpointHeaders:
        deterministicSmartAccountDeployEndpointSubmission.endpointHeaders,
      endpointRequest:
        deterministicSmartAccountDeployEndpointSubmission.endpointRequest,
      endpointRequestHash:
        deterministicSmartAccountDeployEndpointSubmission.endpointRequestHash
    });

  return {
    version: 1,
    path: "phil-smart-account-deploy-client-session",
    smartAccountDeployClientSessionSource:
      "scripts/base/build-smart-account-deploy-client-session.cjs",
    smartAccountDeployEndpointSubmissionSource:
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSource,
    consumedPath: smartAccountDeployEndpointSubmission.path,
    proofType: smartAccountDeployEndpointSubmission.proofType,
    payloadShape: smartAccountDeployEndpointSubmission.payloadShape,
    smartAccountDeployClientSessionDomain: {
      label: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployEndpointSubmissionPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployEndpointSubmissionValid: true,
      deterministicSmartAccountDeployClientSessionDerived: true
    },
    smartAccountDeployClientSessionSummary: {
      ready: true,
      status: "smart-account-deploy-client-session-ready",
      reason: "validated-smart-account-deploy-endpoint-submission",
      parityProven: true
    },
    smartAccountDeployClientSession: {
      ownerCommitment: smartAccountDeployClientSession.ownerCommitment,
      consumerDataHash: smartAccountDeployClientSession.consumerDataHash,
      canonicalRecipient: smartAccountDeployClientSession.canonicalRecipient,
      walletId: smartAccountDeployClientSession.walletId,
      targetId: smartAccountDeployClientSession.targetId,
      targetAddress: smartAccountDeployClientSession.targetAddress,
      entryPointAddress: smartAccountDeployClientSession.entryPointAddress,
      chainId: smartAccountDeployClientSession.chainId,
      userOpHash: smartAccountDeployClientSession.userOpHash,
      bundlerSubmissionId: smartAccountDeployClientSession.bundlerSubmissionId,
      endpointSubmissionKind:
        smartAccountDeployClientSession.endpointSubmissionKind,
      endpointSubmissionId:
        smartAccountDeployClientSession.endpointSubmissionId,
      endpointRequestHash:
        smartAccountDeployClientSession.endpointRequestHash,
      clientSessionKind: smartAccountDeployClientSession.clientSessionKind,
      clientSessionContext:
        smartAccountDeployClientSession.clientSessionContext,
      clientSessionContextJson:
        smartAccountDeployClientSession.clientSessionContextJson,
      clientSessionContextHash:
        smartAccountDeployClientSession.clientSessionContextHash,
      clientSessionId: smartAccountDeployClientSession.clientSessionId,
      clientSessionHandoff:
        smartAccountDeployClientSession.clientSessionHandoff,
      clientSessionHandoffJson:
        smartAccountDeployClientSession.clientSessionHandoffJson,
      clientSessionHandoffBytes:
        smartAccountDeployClientSession.clientSessionHandoffBytes,
      clientSessionHandoffHash:
        smartAccountDeployClientSession.clientSessionHandoffHash
    },
    appSmartAccountDeployClientSession: {
      recipient: smartAccountDeployClientSession.canonicalRecipient,
      sender: smartAccountDeployClientSession.targetAddress,
      entryPointAddress: smartAccountDeployClientSession.entryPointAddress,
      chainId: smartAccountDeployClientSession.chainId,
      endpointUrl:
        smartAccountDeployClientSession.clientSessionContext.endpointUrl,
      clientSessionKind: smartAccountDeployClientSession.clientSessionKind,
      clientSessionId: smartAccountDeployClientSession.clientSessionId,
      clientSessionStage:
        smartAccountDeployClientSession.clientSessionContext.sessionStage,
      clientSessionHandoffHash:
        smartAccountDeployClientSession.clientSessionHandoffHash,
      ready: true,
      status: "smart-account-deploy-client-session-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-endpoint-submission") {
      parsed.smartAccountDeployEndpointSubmissionPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-client-session.cjs --smart-account-deploy-endpoint-submission <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployEndpointSubmissionPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployClientSession =
      buildSmartAccountDeployClientSession({
        smartAccountDeployEndpointSubmission: loadJson(
          path.resolve(parsed.smartAccountDeployEndpointSubmissionPath)
        )
      });
    console.log(JSON.stringify(smartAccountDeployClientSession, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_LABEL,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_CHANNEL,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DISPATCH_MODE,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_ATTEMPT_COUNT,
  deriveDeterministicSmartAccountDeployClientSession,
  buildSmartAccountDeployClientSession
};
