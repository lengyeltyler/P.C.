const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_V1";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_KIND =
  "erc4337-smart-account-deploy-submission-attempt-runner-v1";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_LABEL =
  "base-8453-no-send-submission-attempt-runner-v1";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CHANNEL =
  "device-app-local-submission-runner-v1";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STAGE =
  "local-pre-send-execution-recorded-no-send";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_ACTION =
  "execute-local-no-send-submission-attempt-runner";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_MODE = "local-no-send";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STEP =
  "pre-send-execution-record";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CLIENT_API = "fetch";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_TRANSPORT = "https-json-rpc";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NO_SEND_POLICY =
  "local-runner-record-only";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NEXT_ACTION =
  "external-client-may-perform-live-call";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_SOURCE_KIND =
  "erc4337-smart-account-deploy-dispatch-attempt-v1";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_SOURCE_STAGE =
  "attempt-recorded-no-send";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_SOURCE_ACTION =
  "record-no-send-dispatch-attempt";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_SOURCE_POLICY =
  "record-attempt-only";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_RPC_METHOD =
  "eth_sendUserOperation";
const SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_REQUEST_METHOD = "POST";

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

function assertFalse(value, label) {
  if (value !== false) {
    throw new Error(`${label} must be false`);
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

function normalizeSignedUserOperation(userOperation, label) {
  if (!userOperation || typeof userOperation !== "object") {
    throw new Error(`${label} is required`);
  }

  return {
    sender: normalizeAddress(userOperation.sender, `${label}.sender`),
    nonce: normalizeUintString(userOperation.nonce, `${label}.nonce`),
    initCode: normalizeBytes(userOperation.initCode, `${label}.initCode`),
    callData: normalizeBytes(userOperation.callData, `${label}.callData`),
    callGasLimit: normalizeUintString(
      userOperation.callGasLimit,
      `${label}.callGasLimit`
    ),
    verificationGasLimit: normalizeUintString(
      userOperation.verificationGasLimit,
      `${label}.verificationGasLimit`
    ),
    preVerificationGas: normalizeUintString(
      userOperation.preVerificationGas,
      `${label}.preVerificationGas`
    ),
    maxFeePerGas: normalizeUintString(
      userOperation.maxFeePerGas,
      `${label}.maxFeePerGas`
    ),
    maxPriorityFeePerGas: normalizeUintString(
      userOperation.maxPriorityFeePerGas,
      `${label}.maxPriorityFeePerGas`
    ),
    paymasterAndData: normalizeBytes(
      userOperation.paymasterAndData,
      `${label}.paymasterAndData`
    ),
    signature: normalizeBytes(userOperation.signature, `${label}.signature`)
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
    params: [
      normalizeSignedUserOperation(
        endpointBody.params[0],
        "endpointRequest.body.params[0]"
      ),
      normalizeAddress(endpointBody.params[1], "endpointRequest.body.params[1]")
    ]
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

function normalizeDispatchAttemptContext(dispatchAttemptContext) {
  if (!dispatchAttemptContext || typeof dispatchAttemptContext !== "object") {
    throw new Error("dispatchAttemptContext is required");
  }

  return {
    attemptLabel: normalizeString(
      dispatchAttemptContext.attemptLabel,
      "dispatchAttemptContext.attemptLabel"
    ),
    attemptChannel: normalizeString(
      dispatchAttemptContext.attemptChannel,
      "dispatchAttemptContext.attemptChannel"
    ),
    attemptStage: normalizeString(
      dispatchAttemptContext.attemptStage,
      "dispatchAttemptContext.attemptStage"
    ),
    attemptAction: normalizeString(
      dispatchAttemptContext.attemptAction,
      "dispatchAttemptContext.attemptAction"
    ),
    attemptOrdinal: normalizeUintString(
      dispatchAttemptContext.attemptOrdinal,
      "dispatchAttemptContext.attemptOrdinal"
    ),
    attemptState: normalizeString(
      dispatchAttemptContext.attemptState,
      "dispatchAttemptContext.attemptState"
    ),
    attemptExecutionMode: normalizeString(
      dispatchAttemptContext.attemptExecutionMode,
      "dispatchAttemptContext.attemptExecutionMode"
    ),
    nextAction: normalizeString(
      dispatchAttemptContext.nextAction,
      "dispatchAttemptContext.nextAction"
    ),
    noSendPolicy: normalizeString(
      dispatchAttemptContext.noSendPolicy,
      "dispatchAttemptContext.noSendPolicy"
    ),
    dispatchCommandId: normalizeHex32(
      dispatchAttemptContext.dispatchCommandId,
      "dispatchAttemptContext.dispatchCommandId"
    ),
    dispatchCommandHash: normalizeHex32(
      dispatchAttemptContext.dispatchCommandHash,
      "dispatchAttemptContext.dispatchCommandHash"
    ),
    endpointUrl: normalizeString(
      dispatchAttemptContext.endpointUrl,
      "dispatchAttemptContext.endpointUrl"
    ),
    requestMethod: normalizeString(
      dispatchAttemptContext.requestMethod,
      "dispatchAttemptContext.requestMethod"
    ),
    requestHash: normalizeHex32(
      dispatchAttemptContext.requestHash,
      "dispatchAttemptContext.requestHash"
    ),
    readyForNetworkBoundary: normalizeBoolean(
      dispatchAttemptContext.readyForNetworkBoundary,
      "dispatchAttemptContext.readyForNetworkBoundary"
    ),
    networkSubmissionPerformed: normalizeBoolean(
      dispatchAttemptContext.networkSubmissionPerformed,
      "dispatchAttemptContext.networkSubmissionPerformed"
    ),
    responseObserved: normalizeBoolean(
      dispatchAttemptContext.responseObserved,
      "dispatchAttemptContext.responseObserved"
    ),
    pollingEnabled: normalizeBoolean(
      dispatchAttemptContext.pollingEnabled,
      "dispatchAttemptContext.pollingEnabled"
    )
  };
}

function normalizeAttemptGuard(attemptGuard) {
  if (!attemptGuard || typeof attemptGuard !== "object") {
    throw new Error("attemptGuard is required");
  }

  return {
    dispatchCommandKind: normalizeString(
      attemptGuard.dispatchCommandKind,
      "attemptGuard.dispatchCommandKind"
    ),
    dispatchCommandId: normalizeHex32(
      attemptGuard.dispatchCommandId,
      "attemptGuard.dispatchCommandId"
    ),
    dispatchCommandHash: normalizeHex32(
      attemptGuard.dispatchCommandHash,
      "attemptGuard.dispatchCommandHash"
    ),
    commandReady: normalizeBoolean(
      attemptGuard.commandReady,
      "attemptGuard.commandReady"
    ),
    attemptOrdinal: normalizeUintString(
      attemptGuard.attemptOrdinal,
      "attemptGuard.attemptOrdinal"
    ),
    attemptState: normalizeString(
      attemptGuard.attemptState,
      "attemptGuard.attemptState"
    ),
    noSendPolicy: normalizeString(
      attemptGuard.noSendPolicy,
      "attemptGuard.noSendPolicy"
    ),
    networkSubmissionPerformed: normalizeBoolean(
      attemptGuard.networkSubmissionPerformed,
      "attemptGuard.networkSubmissionPerformed"
    )
  };
}

function normalizeDispatchAttempt(dispatchAttempt) {
  if (!dispatchAttempt || typeof dispatchAttempt !== "object") {
    throw new Error("dispatchAttempt is required");
  }

  return {
    attemptId: normalizeHex32(dispatchAttempt.attemptId, "dispatchAttempt.attemptId"),
    context: normalizeDispatchAttemptContext(dispatchAttempt.context),
    request: normalizeEndpointRequest(dispatchAttempt.request),
    guard: normalizeAttemptGuard(dispatchAttempt.guard)
  };
}

function deriveSmartAccountDeployAttemptRunner({
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
  endpointSubmissionId,
  endpointRequestHash,
  dispatchIntentId,
  dispatchIntentHash,
  dispatchCommandId,
  dispatchCommandHash,
  dispatchAttemptKind,
  dispatchAttemptContext,
  dispatchAttemptContextHash,
  dispatchAttemptRequest,
  dispatchAttemptRequestBytes,
  dispatchAttemptRequestHash,
  attemptGuard,
  attemptGuardHash,
  dispatchAttemptId,
  dispatchAttempt,
  dispatchAttemptHash
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
  const normalizedEndpointSubmissionId = normalizeHex32(
    endpointSubmissionId,
    "endpointSubmissionId"
  );
  const normalizedEndpointRequestHash = normalizeHex32(
    endpointRequestHash,
    "endpointRequestHash"
  );
  const normalizedDispatchIntentId = normalizeHex32(
    dispatchIntentId,
    "dispatchIntentId"
  );
  const normalizedDispatchIntentHash = normalizeHex32(
    dispatchIntentHash,
    "dispatchIntentHash"
  );
  const normalizedDispatchCommandId = normalizeHex32(
    dispatchCommandId,
    "dispatchCommandId"
  );
  const normalizedDispatchCommandHash = normalizeHex32(
    dispatchCommandHash,
    "dispatchCommandHash"
  );
  const normalizedDispatchAttemptKind = normalizeString(
    dispatchAttemptKind,
    "dispatchAttemptKind"
  );
  const normalizedDispatchAttemptContext =
    normalizeDispatchAttemptContext(dispatchAttemptContext);
  const normalizedDispatchAttemptContextHash = normalizeHex32(
    dispatchAttemptContextHash,
    "dispatchAttemptContextHash"
  );
  const normalizedDispatchAttemptRequest =
    normalizeEndpointRequest(dispatchAttemptRequest);
  const normalizedDispatchAttemptRequestBytes = normalizeBytes(
    dispatchAttemptRequestBytes,
    "dispatchAttemptRequestBytes"
  );
  const normalizedDispatchAttemptRequestHash = normalizeHex32(
    dispatchAttemptRequestHash,
    "dispatchAttemptRequestHash"
  );
  const normalizedAttemptGuard = normalizeAttemptGuard(attemptGuard);
  const normalizedAttemptGuardHash = normalizeHex32(
    attemptGuardHash,
    "attemptGuardHash"
  );
  const normalizedDispatchAttemptId = normalizeHex32(
    dispatchAttemptId,
    "dispatchAttemptId"
  );
  const normalizedDispatchAttempt = normalizeDispatchAttempt(dispatchAttempt);
  const normalizedDispatchAttemptHash = normalizeHex32(
    dispatchAttemptHash,
    "dispatchAttemptHash"
  );

  assertEqual(
    normalizedDispatchAttemptKind,
    SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_SOURCE_KIND,
    "dispatchAttemptKind"
  );
  assertEqual(
    normalizedDispatchAttemptContext.attemptStage,
    SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_SOURCE_STAGE,
    "dispatchAttemptContext.attemptStage"
  );
  assertEqual(
    normalizedDispatchAttemptContext.attemptAction,
    SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_SOURCE_ACTION,
    "dispatchAttemptContext.attemptAction"
  );
  assertEqual(
    normalizedDispatchAttemptContext.noSendPolicy,
    SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_SOURCE_POLICY,
    "dispatchAttemptContext.noSendPolicy"
  );
  assertTrue(
    normalizedDispatchAttemptContext.readyForNetworkBoundary,
    "dispatchAttemptContext.readyForNetworkBoundary"
  );
  assertFalse(
    normalizedDispatchAttemptContext.networkSubmissionPerformed,
    "dispatchAttemptContext.networkSubmissionPerformed"
  );
  assertFalse(
    normalizedDispatchAttemptContext.responseObserved,
    "dispatchAttemptContext.responseObserved"
  );
  assertFalse(
    normalizedDispatchAttemptContext.pollingEnabled,
    "dispatchAttemptContext.pollingEnabled"
  );
  assertEqual(
    normalizedDispatchAttemptContext.dispatchCommandId,
    normalizedDispatchCommandId,
    "dispatchAttemptContext.dispatchCommandId/dispatchCommandId"
  );
  assertEqual(
    normalizedDispatchAttemptContext.dispatchCommandHash,
    normalizedDispatchCommandHash,
    "dispatchAttemptContext.dispatchCommandHash/dispatchCommandHash"
  );
  assertEqual(
    normalizedDispatchAttemptContext.requestHash,
    normalizedEndpointRequestHash,
    "dispatchAttemptContext.requestHash/endpointRequestHash"
  );

  const recomputedDispatchAttemptContextJson = JSON.stringify(
    normalizedDispatchAttemptContext
  );
  const recomputedDispatchAttemptContextHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedDispatchAttemptContextJson)
  );
  assertEqual(
    recomputedDispatchAttemptContextHash,
    normalizedDispatchAttemptContextHash,
    "dispatchAttemptContextHash"
  );

  const recomputedDispatchAttemptRequestJson = JSON.stringify(
    normalizedDispatchAttemptRequest
  );
  const recomputedDispatchAttemptRequestBytes = ethers.hexlify(
    ethers.toUtf8Bytes(recomputedDispatchAttemptRequestJson)
  );
  const recomputedDispatchAttemptRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedDispatchAttemptRequestJson)
  );
  assertEqual(
    recomputedDispatchAttemptRequestBytes,
    normalizedDispatchAttemptRequestBytes,
    "dispatchAttemptRequestBytes"
  );
  assertEqual(
    recomputedDispatchAttemptRequestHash,
    normalizedDispatchAttemptRequestHash,
    "dispatchAttemptRequestHash"
  );
  assertEqual(
    normalizedDispatchAttemptRequestHash,
    normalizedEndpointRequestHash,
    "dispatchAttemptRequestHash/endpointRequestHash"
  );
  assertEqual(
    normalizedDispatchAttemptRequest.url,
    normalizedDispatchAttemptContext.endpointUrl,
    "dispatchAttemptRequest.url/dispatchAttemptContext.endpointUrl"
  );
  assertEqual(
    normalizedDispatchAttemptRequest.method,
    SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_REQUEST_METHOD,
    "dispatchAttemptRequest.method"
  );
  assertEqual(
    normalizedDispatchAttemptRequest.method,
    normalizedDispatchAttemptContext.requestMethod,
    "dispatchAttemptRequest.method/dispatchAttemptContext.requestMethod"
  );
  assertEqual(
    normalizedDispatchAttemptRequest.body.method,
    SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_RPC_METHOD,
    "dispatchAttemptRequest.body.method"
  );
  assertEqual(
    normalizedDispatchAttemptRequest.body.params[0].sender.toLowerCase(),
    normalizedTargetAddress.toLowerCase(),
    "signedUserOperation.sender/targetAddress"
  );
  assertEqual(
    normalizedDispatchAttemptRequest.body.params[1].toLowerCase(),
    normalizedEntryPointAddress.toLowerCase(),
    "endpointRequest.entryPoint/entryPointAddress"
  );

  assertEqual(
    normalizedAttemptGuard.dispatchCommandId,
    normalizedDispatchCommandId,
    "attemptGuard.dispatchCommandId/dispatchCommandId"
  );
  assertEqual(
    normalizedAttemptGuard.dispatchCommandHash,
    normalizedDispatchCommandHash,
    "attemptGuard.dispatchCommandHash/dispatchCommandHash"
  );
  assertTrue(normalizedAttemptGuard.commandReady, "attemptGuard.commandReady");
  assertEqual(
    normalizedAttemptGuard.attemptOrdinal,
    normalizedDispatchAttemptContext.attemptOrdinal,
    "attemptGuard.attemptOrdinal/dispatchAttemptContext.attemptOrdinal"
  );
  assertEqual(
    normalizedAttemptGuard.attemptState,
    normalizedDispatchAttemptContext.attemptState,
    "attemptGuard.attemptState/dispatchAttemptContext.attemptState"
  );
  assertFalse(
    normalizedAttemptGuard.networkSubmissionPerformed,
    "attemptGuard.networkSubmissionPerformed"
  );
  const recomputedAttemptGuardJson = JSON.stringify(normalizedAttemptGuard);
  const recomputedAttemptGuardHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedAttemptGuardJson)
  );
  assertEqual(recomputedAttemptGuardHash, normalizedAttemptGuardHash, "attemptGuardHash");

  assertEqual(
    normalizedDispatchAttempt.attemptId,
    normalizedDispatchAttemptId,
    "dispatchAttempt.attemptId/dispatchAttemptId"
  );
  assertEqual(
    normalizedDispatchAttempt.context.dispatchCommandId,
    normalizedDispatchCommandId,
    "dispatchAttempt.context.dispatchCommandId/dispatchCommandId"
  );
  assertEqual(
    normalizedDispatchAttempt.request.body.method,
    SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_RPC_METHOD,
    "dispatchAttempt.request.body.method"
  );
  assertEqual(
    normalizedDispatchAttempt.guard.dispatchCommandHash,
    normalizedDispatchCommandHash,
    "dispatchAttempt.guard.dispatchCommandHash/dispatchCommandHash"
  );
  const recomputedDispatchAttemptJson = JSON.stringify(normalizedDispatchAttempt);
  const recomputedDispatchAttemptHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedDispatchAttemptJson)
  );
  assertEqual(
    recomputedDispatchAttemptHash,
    normalizedDispatchAttemptHash,
    "dispatchAttemptHash"
  );

  const idempotencyKey = normalizeHex32(
    normalizedDispatchAttemptRequest.headers["idempotency-key"],
    "dispatchAttemptRequest.headers.idempotency-key"
  );

  const runnerContext = {
    runnerLabel: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_LABEL,
    runnerChannel: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CHANNEL,
    runnerStage: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STAGE,
    runnerAction: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_ACTION,
    runnerMode: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_MODE,
    runnerStep: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STEP,
    noSendPolicy: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NO_SEND_POLICY,
    nextAction: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NEXT_ACTION,
    dispatchAttemptId: normalizedDispatchAttemptId,
    dispatchAttemptHash: normalizedDispatchAttemptHash,
    dispatchAttemptOrdinal: normalizedDispatchAttemptContext.attemptOrdinal,
    endpointUrl: normalizedDispatchAttemptRequest.url,
    requestMethod: normalizedDispatchAttemptRequest.method,
    rpcMethod: normalizedDispatchAttemptRequest.body.method,
    requestHash: normalizedDispatchAttemptRequestHash,
    requestBytes: normalizedDispatchAttemptRequestBytes,
    readyForLiveCall: true,
    liveNetworkCallPerformed: false,
    networkSubmissionPerformed: false,
    responseObserved: false,
    pollingEnabled: false
  };
  const runnerContextJson = JSON.stringify(runnerContext);
  const runnerContextHash = ethers.keccak256(
    ethers.toUtf8Bytes(runnerContextJson)
  );

  const clientCallBoundary = {
    transport: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_TRANSPORT,
    clientApi: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CLIENT_API,
    endpointUrl: normalizedDispatchAttemptRequest.url,
    requestMethod: normalizedDispatchAttemptRequest.method,
    rpcMethod: normalizedDispatchAttemptRequest.body.method,
    entryPointAddress: normalizedEntryPointAddress,
    chainId: normalizedChainId,
    sender: normalizedTargetAddress,
    idempotencyKey,
    requestHash: normalizedDispatchAttemptRequestHash,
    requestBytes: normalizedDispatchAttemptRequestBytes,
    liveNetworkCallPerformed: false
  };
  const clientCallBoundaryJson = JSON.stringify(clientCallBoundary);
  const clientCallBoundaryHash = ethers.keccak256(
    ethers.toUtf8Bytes(clientCallBoundaryJson)
  );

  const runnerGuard = {
    dispatchAttemptKind: normalizedDispatchAttemptKind,
    dispatchAttemptId: normalizedDispatchAttemptId,
    dispatchAttemptHash: normalizedDispatchAttemptHash,
    attemptReady: true,
    readyForNetworkBoundary: true,
    readyForLiveCall: true,
    noSendPolicy: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NO_SEND_POLICY,
    liveNetworkCallPerformed: false,
    networkSubmissionPerformed: false
  };
  const runnerGuardJson = JSON.stringify(runnerGuard);
  const runnerGuardHash = ethers.keccak256(ethers.toUtf8Bytes(runnerGuardJson));

  const runnerId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_HASH,
        normalizedTargetId,
        normalizedDispatchAttemptId,
        runnerContextHash,
        normalizedDispatchAttemptRequestHash,
        runnerGuardHash
      ]
    )
  );

  const localPreSendExecutionRecord = {
    runnerId,
    context: runnerContext,
    clientCallBoundary,
    request: normalizedDispatchAttemptRequest,
    guard: runnerGuard
  };
  const localPreSendExecutionRecordJson = JSON.stringify(
    localPreSendExecutionRecord
  );
  const localPreSendExecutionRecordBytes = ethers.hexlify(
    ethers.toUtf8Bytes(localPreSendExecutionRecordJson)
  );
  const localPreSendExecutionRecordHash = ethers.keccak256(
    ethers.toUtf8Bytes(localPreSendExecutionRecordJson)
  );

  return {
    proofType: normalizedProofType,
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
    endpointSubmissionId: normalizedEndpointSubmissionId,
    endpointRequestHash: normalizedEndpointRequestHash,
    dispatchIntentId: normalizedDispatchIntentId,
    dispatchIntentHash: normalizedDispatchIntentHash,
    dispatchCommandId: normalizedDispatchCommandId,
    dispatchCommandHash: normalizedDispatchCommandHash,
    dispatchAttemptKind: normalizedDispatchAttemptKind,
    dispatchAttemptId: normalizedDispatchAttemptId,
    dispatchAttemptHash: normalizedDispatchAttemptHash,
    runnerKind: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_KIND,
    runnerContext,
    runnerContextJson,
    runnerContextHash,
    clientCallBoundary,
    clientCallBoundaryJson,
    clientCallBoundaryHash,
    runnerGuard,
    runnerGuardJson,
    runnerGuardHash,
    runnerId,
    localPreSendExecutionRecord,
    localPreSendExecutionRecordJson,
    localPreSendExecutionRecordBytes,
    localPreSendExecutionRecordHash,
    request: normalizedDispatchAttemptRequest,
    requestJson: recomputedDispatchAttemptRequestJson,
    requestBytes: normalizedDispatchAttemptRequestBytes,
    requestHash: normalizedDispatchAttemptRequestHash
  };
}

function runSmartAccountDeployAttemptRunner({ smartAccountDeployDispatchAttempt }) {
  if (
    !smartAccountDeployDispatchAttempt ||
    typeof smartAccountDeployDispatchAttempt !== "object"
  ) {
    throw new Error("smartAccountDeployDispatchAttempt is required");
  }

  assertEqual(
    smartAccountDeployDispatchAttempt.path,
    "phil-smart-account-deploy-dispatch-attempt",
    "smartAccountDeployDispatchAttempt.path"
  );
  assertEqual(
    smartAccountDeployDispatchAttempt.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployDispatchAttempt.payloadShape"
  );

  if (
    !smartAccountDeployDispatchAttempt.validationChecks ||
    typeof smartAccountDeployDispatchAttempt.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployDispatchAttempt.validationChecks is required");
  }
  if (
    !smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary ||
    typeof smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary is required"
    );
  }
  if (
    !smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt ||
    typeof smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt is required"
    );
  }
  if (
    !smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt ||
    typeof smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt is required"
    );
  }

  assertTrue(
    smartAccountDeployDispatchAttempt.validationChecks
      .smartAccountDeployDispatchCommandPathValid,
    "validationChecks.smartAccountDeployDispatchCommandPathValid"
  );
  assertTrue(
    smartAccountDeployDispatchAttempt.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployDispatchAttempt.validationChecks
      .upstreamSmartAccountDeployDispatchCommandValid,
    "validationChecks.upstreamSmartAccountDeployDispatchCommandValid"
  );
  assertTrue(
    smartAccountDeployDispatchAttempt.validationChecks
      .deterministicSmartAccountDeployDispatchAttemptDerived,
    "validationChecks.deterministicSmartAccountDeployDispatchAttemptDerived"
  );
  assertTrue(
    smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary.ready,
    "smartAccountDeployDispatchAttemptSummary.ready"
  );
  assertEqual(
    smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary
      .status,
    "smart-account-deploy-dispatch-attempt-ready",
    "smartAccountDeployDispatchAttemptSummary.status"
  );
  assertTrue(
    smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary
      .parityProven,
    "smartAccountDeployDispatchAttemptSummary.parityProven"
  );

  const deterministicRunner = deriveSmartAccountDeployAttemptRunner({
    proofType: smartAccountDeployDispatchAttempt.proofType,
    ownerCommitment:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .ownerCommitment,
    consumerDataHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .consumerDataHash,
    canonicalRecipient:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .canonicalRecipient,
    walletId:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.walletId,
    targetId:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.targetId,
    targetAddress:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .targetAddress,
    entryPointAddress:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .entryPointAddress,
    chainId:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.chainId,
    userOpHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.userOpHash,
    bundlerSubmissionId:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .bundlerSubmissionId,
    endpointSubmissionId:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .endpointSubmissionId,
    endpointRequestHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .endpointRequestHash,
    dispatchIntentId:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchIntentId,
    dispatchIntentHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchIntentHash,
    dispatchCommandId:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchCommandId,
    dispatchCommandHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchCommandHash,
    dispatchAttemptKind:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptKind,
    dispatchAttemptContext:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptContext,
    dispatchAttemptContextHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptContextHash,
    dispatchAttemptRequest:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequest,
    dispatchAttemptRequestBytes:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequestBytes,
    dispatchAttemptRequestHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequestHash,
    attemptGuard:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .attemptGuard,
    attemptGuardHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .attemptGuardHash,
    dispatchAttemptId:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptId,
    dispatchAttempt:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttempt,
    dispatchAttemptHash:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptHash
  });

  const appSmartAccountDeployDispatchAttempt = {
    recipient: normalizeAddress(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .recipient,
      "appSmartAccountDeployDispatchAttempt.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt.sender,
      "appSmartAccountDeployDispatchAttempt.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .entryPointAddress,
      "appSmartAccountDeployDispatchAttempt.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt.chainId,
      "appSmartAccountDeployDispatchAttempt.chainId"
    ),
    endpointUrl: normalizeString(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .endpointUrl,
      "appSmartAccountDeployDispatchAttempt.endpointUrl"
    ),
    requestMethod: normalizeString(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .requestMethod,
      "appSmartAccountDeployDispatchAttempt.requestMethod"
    ),
    dispatchCommandId: normalizeHex32(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchCommandId,
      "appSmartAccountDeployDispatchAttempt.dispatchCommandId"
    ),
    dispatchAttemptKind: normalizeString(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptKind,
      "appSmartAccountDeployDispatchAttempt.dispatchAttemptKind"
    ),
    dispatchAttemptId: normalizeHex32(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptId,
      "appSmartAccountDeployDispatchAttempt.dispatchAttemptId"
    ),
    dispatchAttemptHash: normalizeHex32(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptHash,
      "appSmartAccountDeployDispatchAttempt.dispatchAttemptHash"
    ),
    noSendPolicy: normalizeString(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .noSendPolicy,
      "appSmartAccountDeployDispatchAttempt.noSendPolicy"
    ),
    readyForNetworkBoundary:
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .readyForNetworkBoundary === true,
    networkSubmissionPerformed:
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .networkSubmissionPerformed === true,
    ready:
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt.ready ===
      true,
    status: normalizeString(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt.status,
      "appSmartAccountDeployDispatchAttempt.status"
    ),
    parityProven:
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .parityProven === true
  };

  assertTrue(
    appSmartAccountDeployDispatchAttempt.ready,
    "appSmartAccountDeployDispatchAttempt.ready"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.status,
    "smart-account-deploy-dispatch-attempt-ready",
    "appSmartAccountDeployDispatchAttempt.status"
  );
  assertTrue(
    appSmartAccountDeployDispatchAttempt.parityProven,
    "appSmartAccountDeployDispatchAttempt.parityProven"
  );
  assertTrue(
    appSmartAccountDeployDispatchAttempt.readyForNetworkBoundary,
    "appSmartAccountDeployDispatchAttempt.readyForNetworkBoundary"
  );
  assertFalse(
    appSmartAccountDeployDispatchAttempt.networkSubmissionPerformed,
    "appSmartAccountDeployDispatchAttempt.networkSubmissionPerformed"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.recipient.toLowerCase(),
    deterministicRunner.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployDispatchAttempt.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.sender.toLowerCase(),
    deterministicRunner.targetAddress.toLowerCase(),
    "appSmartAccountDeployDispatchAttempt.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.entryPointAddress.toLowerCase(),
    deterministicRunner.entryPointAddress.toLowerCase(),
    "appSmartAccountDeployDispatchAttempt.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.chainId,
    deterministicRunner.chainId,
    "appSmartAccountDeployDispatchAttempt.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.endpointUrl,
    deterministicRunner.runnerContext.endpointUrl,
    "appSmartAccountDeployDispatchAttempt.endpointUrl/runnerContext.endpointUrl"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.requestMethod,
    deterministicRunner.runnerContext.requestMethod,
    "appSmartAccountDeployDispatchAttempt.requestMethod/runnerContext.requestMethod"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.dispatchAttemptId,
    deterministicRunner.dispatchAttemptId,
    "appSmartAccountDeployDispatchAttempt.dispatchAttemptId/dispatchAttemptId"
  );
  assertEqual(
    appSmartAccountDeployDispatchAttempt.dispatchAttemptHash,
    deterministicRunner.dispatchAttemptHash,
    "appSmartAccountDeployDispatchAttempt.dispatchAttemptHash/dispatchAttemptHash"
  );

  return {
    version: 1,
    path: "phil-smart-account-deploy-submission-attempt-runner",
    smartAccountDeployAttemptRunnerSource:
      "scripts/base/run-smart-account-deploy-attempt-runner.cjs",
    smartAccountDeployDispatchAttemptSource:
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSource,
    consumedPath: smartAccountDeployDispatchAttempt.path,
    proofType: smartAccountDeployDispatchAttempt.proofType,
    payloadShape: smartAccountDeployDispatchAttempt.payloadShape,
    smartAccountDeployAttemptRunnerDomain: {
      label: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployDispatchAttemptPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployDispatchAttemptValid: true,
      localNoSendRunnerStepExecuted: true
    },
    smartAccountDeployAttemptRunnerSummary: {
      ready: true,
      status: "smart-account-deploy-attempt-runner-ready",
      reason: "validated-smart-account-deploy-dispatch-attempt",
      networkSubmissionPerformed: false,
      parityProven: true
    },
    smartAccountDeployAttemptRunner: {
      ownerCommitment: deterministicRunner.ownerCommitment,
      consumerDataHash: deterministicRunner.consumerDataHash,
      canonicalRecipient: deterministicRunner.canonicalRecipient,
      walletId: deterministicRunner.walletId,
      targetId: deterministicRunner.targetId,
      targetAddress: deterministicRunner.targetAddress,
      entryPointAddress: deterministicRunner.entryPointAddress,
      chainId: deterministicRunner.chainId,
      userOpHash: deterministicRunner.userOpHash,
      bundlerSubmissionId: deterministicRunner.bundlerSubmissionId,
      endpointSubmissionId: deterministicRunner.endpointSubmissionId,
      endpointRequestHash: deterministicRunner.endpointRequestHash,
      dispatchIntentId: deterministicRunner.dispatchIntentId,
      dispatchIntentHash: deterministicRunner.dispatchIntentHash,
      dispatchCommandId: deterministicRunner.dispatchCommandId,
      dispatchCommandHash: deterministicRunner.dispatchCommandHash,
      dispatchAttemptKind: deterministicRunner.dispatchAttemptKind,
      dispatchAttemptId: deterministicRunner.dispatchAttemptId,
      dispatchAttemptHash: deterministicRunner.dispatchAttemptHash,
      runnerKind: deterministicRunner.runnerKind,
      runnerContext: deterministicRunner.runnerContext,
      runnerContextJson: deterministicRunner.runnerContextJson,
      runnerContextHash: deterministicRunner.runnerContextHash,
      clientCallBoundary: deterministicRunner.clientCallBoundary,
      clientCallBoundaryJson: deterministicRunner.clientCallBoundaryJson,
      clientCallBoundaryHash: deterministicRunner.clientCallBoundaryHash,
      runnerGuard: deterministicRunner.runnerGuard,
      runnerGuardJson: deterministicRunner.runnerGuardJson,
      runnerGuardHash: deterministicRunner.runnerGuardHash,
      runnerId: deterministicRunner.runnerId,
      localPreSendExecutionRecord:
        deterministicRunner.localPreSendExecutionRecord,
      localPreSendExecutionRecordJson:
        deterministicRunner.localPreSendExecutionRecordJson,
      localPreSendExecutionRecordBytes:
        deterministicRunner.localPreSendExecutionRecordBytes,
      localPreSendExecutionRecordHash:
        deterministicRunner.localPreSendExecutionRecordHash,
      request: deterministicRunner.request,
      requestJson: deterministicRunner.requestJson,
      requestBytes: deterministicRunner.requestBytes,
      requestHash: deterministicRunner.requestHash
    },
    appSmartAccountDeployAttemptRunner: {
      recipient: deterministicRunner.canonicalRecipient,
      sender: deterministicRunner.targetAddress,
      entryPointAddress: deterministicRunner.entryPointAddress,
      chainId: deterministicRunner.chainId,
      endpointUrl: deterministicRunner.runnerContext.endpointUrl,
      requestMethod: deterministicRunner.runnerContext.requestMethod,
      rpcMethod: deterministicRunner.runnerContext.rpcMethod,
      dispatchAttemptId: deterministicRunner.dispatchAttemptId,
      dispatchAttemptHash: deterministicRunner.dispatchAttemptHash,
      runnerKind: deterministicRunner.runnerKind,
      runnerId: deterministicRunner.runnerId,
      runnerStage: deterministicRunner.runnerContext.runnerStage,
      runnerAction: deterministicRunner.runnerContext.runnerAction,
      runnerMode: deterministicRunner.runnerContext.runnerMode,
      runnerStep: deterministicRunner.runnerContext.runnerStep,
      localPreSendExecutionRecordHash:
        deterministicRunner.localPreSendExecutionRecordHash,
      noSendPolicy: deterministicRunner.runnerContext.noSendPolicy,
      readyForLiveCall: true,
      liveNetworkCallPerformed: false,
      networkSubmissionPerformed: false,
      ready: true,
      status: "smart-account-deploy-attempt-runner-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-dispatch-attempt") {
      parsed.smartAccountDeployDispatchAttemptPath = argv[i + 1];
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
      "  node scripts/base/run-smart-account-deploy-attempt-runner.cjs --smart-account-deploy-dispatch-attempt <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployDispatchAttemptPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployAttemptRunner = runSmartAccountDeployAttemptRunner({
      smartAccountDeployDispatchAttempt: loadJson(
        path.resolve(parsed.smartAccountDeployDispatchAttemptPath)
      )
    });
    console.log(JSON.stringify(smartAccountDeployAttemptRunner, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_KIND,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_LABEL,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CHANNEL,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STAGE,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_ACTION,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_MODE,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STEP,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CLIENT_API,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_TRANSPORT,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NO_SEND_POLICY,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_RPC_METHOD,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_REQUEST_METHOD,
  deriveSmartAccountDeployAttemptRunner,
  runSmartAccountDeployAttemptRunner
};
