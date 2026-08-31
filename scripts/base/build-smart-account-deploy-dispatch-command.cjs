const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NO_SEND_POLICY
} = require("./build-smart-account-deploy-dispatch-intent.cjs");

const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_V1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND =
  "erc4337-smart-account-deploy-dispatch-command-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_LABEL =
  "base-8453-no-send-client-command-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_CHANNEL =
  "device-app-command-loop-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE = "command-prepared-no-send";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION =
  "execute-no-send-http-json-rpc";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_TRANSPORT = "http-json-rpc";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_EXECUTION_MODE = "no-send";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NEXT_ACTION =
  "handoff-to-client-network-boundary";
const SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY =
  "prepare-command-only";

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

function normalizeClientSessionContext(clientSessionContext) {
  if (!clientSessionContext || typeof clientSessionContext !== "object") {
    throw new Error("clientSessionContext is required");
  }

  return {
    sessionLabel: normalizeString(clientSessionContext.sessionLabel, "clientSessionContext.sessionLabel"),
    sessionChannel: normalizeString(clientSessionContext.sessionChannel, "clientSessionContext.sessionChannel"),
    sessionStage: normalizeString(clientSessionContext.sessionStage, "clientSessionContext.sessionStage"),
    dispatchMode: normalizeString(clientSessionContext.dispatchMode, "clientSessionContext.dispatchMode"),
    nextAction: normalizeString(clientSessionContext.nextAction, "clientSessionContext.nextAction"),
    attemptCount: normalizeUintString(clientSessionContext.attemptCount, "clientSessionContext.attemptCount"),
    networkSubmissionPerformed: normalizeBoolean(
      clientSessionContext.networkSubmissionPerformed,
      "clientSessionContext.networkSubmissionPerformed"
    ),
    responseObserved: normalizeBoolean(
      clientSessionContext.responseObserved,
      "clientSessionContext.responseObserved"
    ),
    pollingEnabled: normalizeBoolean(
      clientSessionContext.pollingEnabled,
      "clientSessionContext.pollingEnabled"
    ),
    readyToDispatch: normalizeBoolean(
      clientSessionContext.readyToDispatch,
      "clientSessionContext.readyToDispatch"
    ),
    endpointLabel: normalizeString(clientSessionContext.endpointLabel, "clientSessionContext.endpointLabel"),
    endpointUrl: normalizeString(clientSessionContext.endpointUrl, "clientSessionContext.endpointUrl"),
    requestMethod: normalizeString(clientSessionContext.requestMethod, "clientSessionContext.requestMethod"),
    requestHash: normalizeHex32(clientSessionContext.requestHash, "clientSessionContext.requestHash")
  };
}

function normalizeClientSessionHandoff(clientSessionHandoff) {
  if (!clientSessionHandoff || typeof clientSessionHandoff !== "object") {
    throw new Error("clientSessionHandoff is required");
  }

  return {
    sessionId: normalizeHex32(clientSessionHandoff.sessionId, "clientSessionHandoff.sessionId"),
    session: normalizeClientSessionContext(clientSessionHandoff.session),
    endpointRequest: normalizeEndpointRequest(clientSessionHandoff.endpointRequest)
  };
}

function normalizeDispatchIntentContext(dispatchIntentContext) {
  if (!dispatchIntentContext || typeof dispatchIntentContext !== "object") {
    throw new Error("dispatchIntentContext is required");
  }

  return {
    intentLabel: normalizeString(dispatchIntentContext.intentLabel, "dispatchIntentContext.intentLabel"),
    intentChannel: normalizeString(dispatchIntentContext.intentChannel, "dispatchIntentContext.intentChannel"),
    intentStage: normalizeString(dispatchIntentContext.intentStage, "dispatchIntentContext.intentStage"),
    approvalMode: normalizeString(dispatchIntentContext.approvalMode, "dispatchIntentContext.approvalMode"),
    approvalState: normalizeString(dispatchIntentContext.approvalState, "dispatchIntentContext.approvalState"),
    approvalScope: normalizeString(dispatchIntentContext.approvalScope, "dispatchIntentContext.approvalScope"),
    dispatchMode: normalizeString(dispatchIntentContext.dispatchMode, "dispatchIntentContext.dispatchMode"),
    nextAction: normalizeString(dispatchIntentContext.nextAction, "dispatchIntentContext.nextAction"),
    noSendPolicy: normalizeString(dispatchIntentContext.noSendPolicy, "dispatchIntentContext.noSendPolicy"),
    approvedForDispatch: normalizeBoolean(
      dispatchIntentContext.approvedForDispatch,
      "dispatchIntentContext.approvedForDispatch"
    ),
    networkSubmissionPerformed: normalizeBoolean(
      dispatchIntentContext.networkSubmissionPerformed,
      "dispatchIntentContext.networkSubmissionPerformed"
    ),
    responseObserved: normalizeBoolean(
      dispatchIntentContext.responseObserved,
      "dispatchIntentContext.responseObserved"
    ),
    pollingEnabled: normalizeBoolean(
      dispatchIntentContext.pollingEnabled,
      "dispatchIntentContext.pollingEnabled"
    ),
    clientSessionId: normalizeHex32(dispatchIntentContext.clientSessionId, "dispatchIntentContext.clientSessionId"),
    clientSessionHandoffHash: normalizeHex32(
      dispatchIntentContext.clientSessionHandoffHash,
      "dispatchIntentContext.clientSessionHandoffHash"
    ),
    endpointUrl: normalizeString(dispatchIntentContext.endpointUrl, "dispatchIntentContext.endpointUrl"),
    requestMethod: normalizeString(dispatchIntentContext.requestMethod, "dispatchIntentContext.requestMethod"),
    requestHash: normalizeHex32(dispatchIntentContext.requestHash, "dispatchIntentContext.requestHash")
  };
}

function normalizeUserApproval(userApproval) {
  if (!userApproval || typeof userApproval !== "object") {
    throw new Error("userApproval is required");
  }

  return {
    approvalMode: normalizeString(userApproval.approvalMode, "userApproval.approvalMode"),
    approvalState: normalizeString(userApproval.approvalState, "userApproval.approvalState"),
    approvalScope: normalizeString(userApproval.approvalScope, "userApproval.approvalScope"),
    approvalSubjectKind: normalizeString(
      userApproval.approvalSubjectKind,
      "userApproval.approvalSubjectKind"
    ),
    approvalSubjectId: normalizeHex32(
      userApproval.approvalSubjectId,
      "userApproval.approvalSubjectId"
    ),
    approvalSubjectHash: normalizeHex32(
      userApproval.approvalSubjectHash,
      "userApproval.approvalSubjectHash"
    ),
    approvedEndpointUrl: normalizeString(
      userApproval.approvedEndpointUrl,
      "userApproval.approvedEndpointUrl"
    ),
    approvedRequestHash: normalizeHex32(
      userApproval.approvedRequestHash,
      "userApproval.approvedRequestHash"
    ),
    approvalEffect: normalizeString(userApproval.approvalEffect, "userApproval.approvalEffect"),
    dispatchAuthorized: normalizeBoolean(
      userApproval.dispatchAuthorized,
      "userApproval.dispatchAuthorized"
    ),
    networkSubmissionPerformed: normalizeBoolean(
      userApproval.networkSubmissionPerformed,
      "userApproval.networkSubmissionPerformed"
    )
  };
}

function normalizeDispatchIntent(dispatchIntent) {
  if (!dispatchIntent || typeof dispatchIntent !== "object") {
    throw new Error("dispatchIntent is required");
  }

  return {
    intentId: normalizeHex32(dispatchIntent.intentId, "dispatchIntent.intentId"),
    intent: normalizeDispatchIntentContext(dispatchIntent.intent),
    userApproval: normalizeUserApproval(dispatchIntent.userApproval),
    clientSessionHandoff: normalizeClientSessionHandoff(
      dispatchIntent.clientSessionHandoff
    )
  };
}

function deriveDeterministicSmartAccountDeployDispatchCommand({
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
  clientSessionId,
  clientSessionHandoffHash,
  dispatchIntentKind,
  dispatchIntentId,
  dispatchIntent,
  dispatchIntentHash
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
  const normalizedClientSessionId = normalizeHex32(
    clientSessionId,
    "clientSessionId"
  );
  const normalizedClientSessionHandoffHash = normalizeHex32(
    clientSessionHandoffHash,
    "clientSessionHandoffHash"
  );
  const normalizedDispatchIntentKind = normalizeString(
    dispatchIntentKind,
    "dispatchIntentKind"
  );
  const normalizedDispatchIntentId = normalizeHex32(
    dispatchIntentId,
    "dispatchIntentId"
  );
  const normalizedDispatchIntent = normalizeDispatchIntent(dispatchIntent);
  const normalizedDispatchIntentHash = normalizeHex32(
    dispatchIntentHash,
    "dispatchIntentHash"
  );

  assertEqual(
    normalizedDispatchIntentKind,
    SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND,
    "dispatchIntentKind"
  );
  assertEqual(
    normalizedDispatchIntent.intentId,
    normalizedDispatchIntentId,
    "dispatchIntent.intentId/dispatchIntentId"
  );
  assertEqual(
    normalizedDispatchIntent.intent.intentStage,
    SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE,
    "dispatchIntent.intent.intentStage"
  );
  assertEqual(
    normalizedDispatchIntent.intent.approvalState,
    SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
    "dispatchIntent.intent.approvalState"
  );
  assertEqual(
    normalizedDispatchIntent.intent.noSendPolicy,
    SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NO_SEND_POLICY,
    "dispatchIntent.intent.noSendPolicy"
  );
  assertTrue(
    normalizedDispatchIntent.intent.approvedForDispatch,
    "dispatchIntent.intent.approvedForDispatch"
  );
  assertTrue(
    normalizedDispatchIntent.userApproval.dispatchAuthorized,
    "dispatchIntent.userApproval.dispatchAuthorized"
  );
  assertFalse(
    normalizedDispatchIntent.intent.networkSubmissionPerformed,
    "dispatchIntent.intent.networkSubmissionPerformed"
  );
  assertFalse(
    normalizedDispatchIntent.userApproval.networkSubmissionPerformed,
    "dispatchIntent.userApproval.networkSubmissionPerformed"
  );
  assertFalse(
    normalizedDispatchIntent.intent.responseObserved,
    "dispatchIntent.intent.responseObserved"
  );
  assertFalse(
    normalizedDispatchIntent.intent.pollingEnabled,
    "dispatchIntent.intent.pollingEnabled"
  );
  assertEqual(
    normalizedDispatchIntent.intent.clientSessionId,
    normalizedClientSessionId,
    "dispatchIntent.intent.clientSessionId/clientSessionId"
  );
  assertEqual(
    normalizedDispatchIntent.intent.clientSessionHandoffHash,
    normalizedClientSessionHandoffHash,
    "dispatchIntent.intent.clientSessionHandoffHash/clientSessionHandoffHash"
  );
  assertEqual(
    normalizedDispatchIntent.intent.requestHash,
    normalizedEndpointRequestHash,
    "dispatchIntent.intent.requestHash/endpointRequestHash"
  );
  assertEqual(
    normalizedDispatchIntent.userApproval.approvedRequestHash,
    normalizedEndpointRequestHash,
    "dispatchIntent.userApproval.approvedRequestHash/endpointRequestHash"
  );
  assertEqual(
    normalizedDispatchIntent.clientSessionHandoff.sessionId,
    normalizedClientSessionId,
    "dispatchIntent.clientSessionHandoff.sessionId/clientSessionId"
  );
  assertEqual(
    normalizedDispatchIntent.clientSessionHandoff.session.requestHash,
    normalizedEndpointRequestHash,
    "dispatchIntent.clientSessionHandoff.session.requestHash/endpointRequestHash"
  );

  const recomputedDispatchIntentJson = JSON.stringify(normalizedDispatchIntent);
  const recomputedDispatchIntentHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedDispatchIntentJson)
  );
  assertEqual(
    recomputedDispatchIntentHash,
    normalizedDispatchIntentHash,
    "dispatchIntentHash"
  );

  const dispatchCommandContext = {
    commandLabel: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_LABEL,
    commandChannel: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_CHANNEL,
    commandStage: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE,
    commandAction: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION,
    commandTransport: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_TRANSPORT,
    commandExecutionMode: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_EXECUTION_MODE,
    nextAction: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NEXT_ACTION,
    noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY,
    dispatchIntentId: normalizedDispatchIntentId,
    dispatchIntentHash: normalizedDispatchIntentHash,
    endpointUrl: normalizedDispatchIntent.intent.endpointUrl,
    requestMethod: normalizedDispatchIntent.intent.requestMethod,
    requestHash: normalizedEndpointRequestHash,
    approvedForDispatch: true,
    commandReady: true,
    networkSubmissionPerformed: false,
    responseObserved: false,
    pollingEnabled: false
  };
  const dispatchCommandContextJson = JSON.stringify(dispatchCommandContext);
  const dispatchCommandContextHash = ethers.keccak256(
    ethers.toUtf8Bytes(dispatchCommandContextJson)
  );

  const dispatchCommandRequest =
    normalizedDispatchIntent.clientSessionHandoff.endpointRequest;
  const dispatchCommandRequestJson = JSON.stringify(dispatchCommandRequest);
  const dispatchCommandRequestBytes = ethers.hexlify(
    ethers.toUtf8Bytes(dispatchCommandRequestJson)
  );
  const dispatchCommandRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(dispatchCommandRequestJson)
  );
  assertEqual(
    dispatchCommandRequestHash,
    normalizedEndpointRequestHash,
    "dispatchCommandRequestHash/endpointRequestHash"
  );

  const commandGuard = {
    dispatchIntentKind: normalizedDispatchIntentKind,
    dispatchIntentId: normalizedDispatchIntentId,
    dispatchIntentHash: normalizedDispatchIntentHash,
    approvalState: normalizedDispatchIntent.userApproval.approvalState,
    dispatchAuthorized: normalizedDispatchIntent.userApproval.dispatchAuthorized,
    noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY,
    networkSubmissionPerformed: false
  };
  const commandGuardJson = JSON.stringify(commandGuard);
  const commandGuardHash = ethers.keccak256(ethers.toUtf8Bytes(commandGuardJson));

  const dispatchCommandId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedDispatchIntentId,
        dispatchCommandContextHash,
        dispatchCommandRequestHash
      ]
    )
  );

  const dispatchCommand = {
    commandId: dispatchCommandId,
    context: dispatchCommandContext,
    request: dispatchCommandRequest,
    guard: commandGuard
  };
  const dispatchCommandJson = JSON.stringify(dispatchCommand);
  const dispatchCommandBytes = ethers.hexlify(
    ethers.toUtf8Bytes(dispatchCommandJson)
  );
  const dispatchCommandHash = ethers.keccak256(
    ethers.toUtf8Bytes(dispatchCommandJson)
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
    endpointSubmissionId: normalizedEndpointSubmissionId,
    endpointRequestHash: normalizedEndpointRequestHash,
    clientSessionId: normalizedClientSessionId,
    clientSessionHandoffHash: normalizedClientSessionHandoffHash,
    dispatchIntentKind: normalizedDispatchIntentKind,
    dispatchIntentId: normalizedDispatchIntentId,
    dispatchIntentHash: normalizedDispatchIntentHash,
    dispatchCommandKind: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND,
    dispatchCommandContext,
    dispatchCommandContextJson,
    dispatchCommandContextHash,
    dispatchCommandRequest,
    dispatchCommandRequestJson,
    dispatchCommandRequestBytes,
    dispatchCommandRequestHash,
    commandGuard,
    commandGuardJson,
    commandGuardHash,
    dispatchCommandId,
    dispatchCommand,
    dispatchCommandJson,
    dispatchCommandBytes,
    dispatchCommandHash,
    proofType: normalizedProofType
  };
}

function buildSmartAccountDeployDispatchCommand({ smartAccountDeployDispatchIntent }) {
  if (
    !smartAccountDeployDispatchIntent ||
    typeof smartAccountDeployDispatchIntent !== "object"
  ) {
    throw new Error("smartAccountDeployDispatchIntent is required");
  }

  assertEqual(
    smartAccountDeployDispatchIntent.path,
    "phil-smart-account-deploy-dispatch-intent",
    "smartAccountDeployDispatchIntent.path"
  );
  assertEqual(
    smartAccountDeployDispatchIntent.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployDispatchIntent.payloadShape"
  );

  if (
    !smartAccountDeployDispatchIntent.validationChecks ||
    typeof smartAccountDeployDispatchIntent.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployDispatchIntent.validationChecks is required");
  }
  if (
    !smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary ||
    typeof smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary is required"
    );
  }
  if (
    !smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent ||
    typeof smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent is required"
    );
  }
  if (
    !smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent ||
    typeof smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent is required"
    );
  }

  assertTrue(
    smartAccountDeployDispatchIntent.validationChecks
      .smartAccountDeployClientSessionPathValid,
    "validationChecks.smartAccountDeployClientSessionPathValid"
  );
  assertTrue(
    smartAccountDeployDispatchIntent.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployDispatchIntent.validationChecks
      .upstreamSmartAccountDeployClientSessionValid,
    "validationChecks.upstreamSmartAccountDeployClientSessionValid"
  );
  assertTrue(
    smartAccountDeployDispatchIntent.validationChecks
      .deterministicSmartAccountDeployDispatchIntentDerived,
    "validationChecks.deterministicSmartAccountDeployDispatchIntentDerived"
  );
  assertTrue(
    smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary.ready,
    "smartAccountDeployDispatchIntentSummary.ready"
  );
  assertEqual(
    smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary
      .status,
    "smart-account-deploy-dispatch-intent-ready",
    "smartAccountDeployDispatchIntentSummary.status"
  );
  assertTrue(
    smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary
      .parityProven,
    "smartAccountDeployDispatchIntentSummary.parityProven"
  );

  const deterministicSmartAccountDeployDispatchIntent = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .ownerCommitment,
      "smartAccountDeployDispatchIntent.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .consumerDataHash,
      "smartAccountDeployDispatchIntent.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .canonicalRecipient,
      "smartAccountDeployDispatchIntent.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.walletId,
      "smartAccountDeployDispatchIntent.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.targetId,
      "smartAccountDeployDispatchIntent.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .targetAddress,
      "smartAccountDeployDispatchIntent.targetAddress"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .entryPointAddress,
      "smartAccountDeployDispatchIntent.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.chainId,
      "smartAccountDeployDispatchIntent.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.userOpHash,
      "smartAccountDeployDispatchIntent.userOpHash"
    ),
    bundlerSubmissionId: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .bundlerSubmissionId,
      "smartAccountDeployDispatchIntent.bundlerSubmissionId"
    ),
    endpointSubmissionId: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .endpointSubmissionId,
      "smartAccountDeployDispatchIntent.endpointSubmissionId"
    ),
    endpointRequestHash: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .endpointRequestHash,
      "smartAccountDeployDispatchIntent.endpointRequestHash"
    ),
    clientSessionId: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .clientSessionId,
      "smartAccountDeployDispatchIntent.clientSessionId"
    ),
    clientSessionHandoffHash: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .clientSessionHandoffHash,
      "smartAccountDeployDispatchIntent.clientSessionHandoffHash"
    ),
    dispatchIntentKind: normalizeString(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentKind,
      "smartAccountDeployDispatchIntent.dispatchIntentKind"
    ),
    dispatchIntentId: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentId,
      "smartAccountDeployDispatchIntent.dispatchIntentId"
    ),
    dispatchIntent: normalizeDispatchIntent(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntent
    ),
    dispatchIntentHash: normalizeHex32(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentHash,
      "smartAccountDeployDispatchIntent.dispatchIntentHash"
    )
  };

  const appSmartAccountDeployDispatchIntent = {
    recipient: normalizeAddress(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .recipient,
      "appSmartAccountDeployDispatchIntent.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent.sender,
      "appSmartAccountDeployDispatchIntent.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .entryPointAddress,
      "appSmartAccountDeployDispatchIntent.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent.chainId,
      "appSmartAccountDeployDispatchIntent.chainId"
    ),
    endpointUrl: normalizeString(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .endpointUrl,
      "appSmartAccountDeployDispatchIntent.endpointUrl"
    ),
    clientSessionId: normalizeHex32(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .clientSessionId,
      "appSmartAccountDeployDispatchIntent.clientSessionId"
    ),
    dispatchIntentKind: normalizeString(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchIntentKind,
      "appSmartAccountDeployDispatchIntent.dispatchIntentKind"
    ),
    dispatchIntentId: normalizeHex32(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchIntentId,
      "appSmartAccountDeployDispatchIntent.dispatchIntentId"
    ),
    dispatchIntentStage: normalizeString(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchIntentStage,
      "appSmartAccountDeployDispatchIntent.dispatchIntentStage"
    ),
    dispatchIntentHash: normalizeHex32(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchIntentHash,
      "appSmartAccountDeployDispatchIntent.dispatchIntentHash"
    ),
    approved:
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .approved === true,
    dispatchAuthorized:
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchAuthorized === true,
    networkSubmissionPerformed:
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .networkSubmissionPerformed === true,
    ready:
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent.ready ===
      true,
    status: normalizeString(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent.status,
      "appSmartAccountDeployDispatchIntent.status"
    ),
    parityProven:
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .parityProven === true
  };

  assertTrue(
    appSmartAccountDeployDispatchIntent.ready,
    "appSmartAccountDeployDispatchIntent.ready"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.status,
    "smart-account-deploy-dispatch-intent-ready",
    "appSmartAccountDeployDispatchIntent.status"
  );
  assertTrue(
    appSmartAccountDeployDispatchIntent.parityProven,
    "appSmartAccountDeployDispatchIntent.parityProven"
  );
  assertTrue(
    appSmartAccountDeployDispatchIntent.approved,
    "appSmartAccountDeployDispatchIntent.approved"
  );
  assertTrue(
    appSmartAccountDeployDispatchIntent.dispatchAuthorized,
    "appSmartAccountDeployDispatchIntent.dispatchAuthorized"
  );
  assertFalse(
    appSmartAccountDeployDispatchIntent.networkSubmissionPerformed,
    "appSmartAccountDeployDispatchIntent.networkSubmissionPerformed"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.recipient.toLowerCase(),
    deterministicSmartAccountDeployDispatchIntent.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployDispatchIntent.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.sender.toLowerCase(),
    deterministicSmartAccountDeployDispatchIntent.targetAddress.toLowerCase(),
    "appSmartAccountDeployDispatchIntent.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeployDispatchIntent.entryPointAddress.toLowerCase(),
    "appSmartAccountDeployDispatchIntent.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.chainId,
    deterministicSmartAccountDeployDispatchIntent.chainId,
    "appSmartAccountDeployDispatchIntent.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.clientSessionId,
    deterministicSmartAccountDeployDispatchIntent.clientSessionId,
    "appSmartAccountDeployDispatchIntent.clientSessionId/clientSessionId"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.dispatchIntentKind,
    deterministicSmartAccountDeployDispatchIntent.dispatchIntentKind,
    "appSmartAccountDeployDispatchIntent.dispatchIntentKind/dispatchIntentKind"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.dispatchIntentId,
    deterministicSmartAccountDeployDispatchIntent.dispatchIntentId,
    "appSmartAccountDeployDispatchIntent.dispatchIntentId/dispatchIntentId"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.dispatchIntentStage,
    SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE,
    "appSmartAccountDeployDispatchIntent.dispatchIntentStage"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.dispatchIntentHash,
    deterministicSmartAccountDeployDispatchIntent.dispatchIntentHash,
    "appSmartAccountDeployDispatchIntent.dispatchIntentHash/dispatchIntentHash"
  );
  assertEqual(
    appSmartAccountDeployDispatchIntent.endpointUrl,
    deterministicSmartAccountDeployDispatchIntent.dispatchIntent.intent.endpointUrl,
    "appSmartAccountDeployDispatchIntent.endpointUrl/dispatchIntent.intent.endpointUrl"
  );

  const smartAccountDeployDispatchCommand =
    deriveDeterministicSmartAccountDeployDispatchCommand({
      proofType: smartAccountDeployDispatchIntent.proofType,
      ownerCommitment:
        deterministicSmartAccountDeployDispatchIntent.ownerCommitment,
      consumerDataHash:
        deterministicSmartAccountDeployDispatchIntent.consumerDataHash,
      canonicalRecipient:
        deterministicSmartAccountDeployDispatchIntent.canonicalRecipient,
      walletId: deterministicSmartAccountDeployDispatchIntent.walletId,
      targetId: deterministicSmartAccountDeployDispatchIntent.targetId,
      targetAddress:
        deterministicSmartAccountDeployDispatchIntent.targetAddress,
      entryPointAddress:
        deterministicSmartAccountDeployDispatchIntent.entryPointAddress,
      chainId: deterministicSmartAccountDeployDispatchIntent.chainId,
      userOpHash: deterministicSmartAccountDeployDispatchIntent.userOpHash,
      bundlerSubmissionId:
        deterministicSmartAccountDeployDispatchIntent.bundlerSubmissionId,
      endpointSubmissionId:
        deterministicSmartAccountDeployDispatchIntent.endpointSubmissionId,
      endpointRequestHash:
        deterministicSmartAccountDeployDispatchIntent.endpointRequestHash,
      clientSessionId:
        deterministicSmartAccountDeployDispatchIntent.clientSessionId,
      clientSessionHandoffHash:
        deterministicSmartAccountDeployDispatchIntent.clientSessionHandoffHash,
      dispatchIntentKind:
        deterministicSmartAccountDeployDispatchIntent.dispatchIntentKind,
      dispatchIntentId:
        deterministicSmartAccountDeployDispatchIntent.dispatchIntentId,
      dispatchIntent:
        deterministicSmartAccountDeployDispatchIntent.dispatchIntent,
      dispatchIntentHash:
        deterministicSmartAccountDeployDispatchIntent.dispatchIntentHash
    });

  return {
    version: 1,
    path: "phil-smart-account-deploy-dispatch-command",
    smartAccountDeployDispatchCommandSource:
      "scripts/base/build-smart-account-deploy-dispatch-command.cjs",
    smartAccountDeployDispatchIntentSource:
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSource,
    consumedPath: smartAccountDeployDispatchIntent.path,
    proofType: smartAccountDeployDispatchIntent.proofType,
    payloadShape: smartAccountDeployDispatchIntent.payloadShape,
    smartAccountDeployDispatchCommandDomain: {
      label: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployDispatchIntentPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployDispatchIntentValid: true,
      deterministicSmartAccountDeployDispatchCommandDerived: true
    },
    smartAccountDeployDispatchCommandSummary: {
      ready: true,
      status: "smart-account-deploy-dispatch-command-ready",
      reason: "validated-smart-account-deploy-dispatch-intent",
      parityProven: true
    },
    smartAccountDeployDispatchCommand: {
      ownerCommitment: smartAccountDeployDispatchCommand.ownerCommitment,
      consumerDataHash: smartAccountDeployDispatchCommand.consumerDataHash,
      canonicalRecipient: smartAccountDeployDispatchCommand.canonicalRecipient,
      walletId: smartAccountDeployDispatchCommand.walletId,
      targetId: smartAccountDeployDispatchCommand.targetId,
      targetAddress: smartAccountDeployDispatchCommand.targetAddress,
      entryPointAddress: smartAccountDeployDispatchCommand.entryPointAddress,
      chainId: smartAccountDeployDispatchCommand.chainId,
      userOpHash: smartAccountDeployDispatchCommand.userOpHash,
      bundlerSubmissionId:
        smartAccountDeployDispatchCommand.bundlerSubmissionId,
      endpointSubmissionId:
        smartAccountDeployDispatchCommand.endpointSubmissionId,
      endpointRequestHash:
        smartAccountDeployDispatchCommand.endpointRequestHash,
      clientSessionId: smartAccountDeployDispatchCommand.clientSessionId,
      clientSessionHandoffHash:
        smartAccountDeployDispatchCommand.clientSessionHandoffHash,
      dispatchIntentKind:
        smartAccountDeployDispatchCommand.dispatchIntentKind,
      dispatchIntentId: smartAccountDeployDispatchCommand.dispatchIntentId,
      dispatchIntentHash:
        smartAccountDeployDispatchCommand.dispatchIntentHash,
      dispatchCommandKind:
        smartAccountDeployDispatchCommand.dispatchCommandKind,
      dispatchCommandContext:
        smartAccountDeployDispatchCommand.dispatchCommandContext,
      dispatchCommandContextJson:
        smartAccountDeployDispatchCommand.dispatchCommandContextJson,
      dispatchCommandContextHash:
        smartAccountDeployDispatchCommand.dispatchCommandContextHash,
      dispatchCommandRequest:
        smartAccountDeployDispatchCommand.dispatchCommandRequest,
      dispatchCommandRequestJson:
        smartAccountDeployDispatchCommand.dispatchCommandRequestJson,
      dispatchCommandRequestBytes:
        smartAccountDeployDispatchCommand.dispatchCommandRequestBytes,
      dispatchCommandRequestHash:
        smartAccountDeployDispatchCommand.dispatchCommandRequestHash,
      commandGuard: smartAccountDeployDispatchCommand.commandGuard,
      commandGuardJson: smartAccountDeployDispatchCommand.commandGuardJson,
      commandGuardHash: smartAccountDeployDispatchCommand.commandGuardHash,
      dispatchCommandId: smartAccountDeployDispatchCommand.dispatchCommandId,
      dispatchCommand: smartAccountDeployDispatchCommand.dispatchCommand,
      dispatchCommandJson:
        smartAccountDeployDispatchCommand.dispatchCommandJson,
      dispatchCommandBytes:
        smartAccountDeployDispatchCommand.dispatchCommandBytes,
      dispatchCommandHash:
        smartAccountDeployDispatchCommand.dispatchCommandHash
    },
    appSmartAccountDeployDispatchCommand: {
      recipient: smartAccountDeployDispatchCommand.canonicalRecipient,
      sender: smartAccountDeployDispatchCommand.targetAddress,
      entryPointAddress: smartAccountDeployDispatchCommand.entryPointAddress,
      chainId: smartAccountDeployDispatchCommand.chainId,
      endpointUrl:
        smartAccountDeployDispatchCommand.dispatchCommandContext.endpointUrl,
      requestMethod:
        smartAccountDeployDispatchCommand.dispatchCommandContext.requestMethod,
      dispatchIntentId: smartAccountDeployDispatchCommand.dispatchIntentId,
      dispatchCommandKind:
        smartAccountDeployDispatchCommand.dispatchCommandKind,
      dispatchCommandId: smartAccountDeployDispatchCommand.dispatchCommandId,
      dispatchCommandStage:
        smartAccountDeployDispatchCommand.dispatchCommandContext.commandStage,
      dispatchCommandAction:
        smartAccountDeployDispatchCommand.dispatchCommandContext.commandAction,
      dispatchCommandHash:
        smartAccountDeployDispatchCommand.dispatchCommandHash,
      noSendPolicy:
        smartAccountDeployDispatchCommand.dispatchCommandContext.noSendPolicy,
      commandReady: true,
      networkSubmissionPerformed: false,
      ready: true,
      status: "smart-account-deploy-dispatch-command-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-dispatch-intent") {
      parsed.smartAccountDeployDispatchIntentPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-dispatch-command.cjs --smart-account-deploy-dispatch-intent <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployDispatchIntentPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployDispatchCommand =
      buildSmartAccountDeployDispatchCommand({
        smartAccountDeployDispatchIntent: loadJson(
          path.resolve(parsed.smartAccountDeployDispatchIntentPath)
        )
      });
    console.log(JSON.stringify(smartAccountDeployDispatchCommand, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_CHANNEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_TRANSPORT,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_EXECUTION_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY,
  deriveDeterministicSmartAccountDeployDispatchCommand,
  buildSmartAccountDeployDispatchCommand
};
