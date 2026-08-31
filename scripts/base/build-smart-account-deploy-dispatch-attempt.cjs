const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_TRANSPORT,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_EXECUTION_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY
} = require("./build-smart-account-deploy-dispatch-command.cjs");

const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_V1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_KIND =
  "erc4337-smart-account-deploy-dispatch-attempt-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_LABEL =
  "base-8453-no-send-client-attempt-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_CHANNEL =
  "device-app-attempt-loop-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STAGE =
  "attempt-recorded-no-send";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ACTION =
  "record-no-send-dispatch-attempt";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL = "1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STATE =
  "prepared-before-network-boundary";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_EXECUTION_MODE = "no-send";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NEXT_ACTION =
  "handoff-attempt-to-client-network-boundary";
const SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NO_SEND_POLICY =
  "record-attempt-only";

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

function normalizeDispatchCommandContext(dispatchCommandContext) {
  if (!dispatchCommandContext || typeof dispatchCommandContext !== "object") {
    throw new Error("dispatchCommandContext is required");
  }

  return {
    commandLabel: normalizeString(dispatchCommandContext.commandLabel, "dispatchCommandContext.commandLabel"),
    commandChannel: normalizeString(dispatchCommandContext.commandChannel, "dispatchCommandContext.commandChannel"),
    commandStage: normalizeString(dispatchCommandContext.commandStage, "dispatchCommandContext.commandStage"),
    commandAction: normalizeString(dispatchCommandContext.commandAction, "dispatchCommandContext.commandAction"),
    commandTransport: normalizeString(dispatchCommandContext.commandTransport, "dispatchCommandContext.commandTransport"),
    commandExecutionMode: normalizeString(
      dispatchCommandContext.commandExecutionMode,
      "dispatchCommandContext.commandExecutionMode"
    ),
    nextAction: normalizeString(dispatchCommandContext.nextAction, "dispatchCommandContext.nextAction"),
    noSendPolicy: normalizeString(dispatchCommandContext.noSendPolicy, "dispatchCommandContext.noSendPolicy"),
    dispatchIntentId: normalizeHex32(dispatchCommandContext.dispatchIntentId, "dispatchCommandContext.dispatchIntentId"),
    dispatchIntentHash: normalizeHex32(
      dispatchCommandContext.dispatchIntentHash,
      "dispatchCommandContext.dispatchIntentHash"
    ),
    endpointUrl: normalizeString(dispatchCommandContext.endpointUrl, "dispatchCommandContext.endpointUrl"),
    requestMethod: normalizeString(dispatchCommandContext.requestMethod, "dispatchCommandContext.requestMethod"),
    requestHash: normalizeHex32(dispatchCommandContext.requestHash, "dispatchCommandContext.requestHash"),
    approvedForDispatch: normalizeBoolean(
      dispatchCommandContext.approvedForDispatch,
      "dispatchCommandContext.approvedForDispatch"
    ),
    commandReady: normalizeBoolean(
      dispatchCommandContext.commandReady,
      "dispatchCommandContext.commandReady"
    ),
    networkSubmissionPerformed: normalizeBoolean(
      dispatchCommandContext.networkSubmissionPerformed,
      "dispatchCommandContext.networkSubmissionPerformed"
    ),
    responseObserved: normalizeBoolean(
      dispatchCommandContext.responseObserved,
      "dispatchCommandContext.responseObserved"
    ),
    pollingEnabled: normalizeBoolean(
      dispatchCommandContext.pollingEnabled,
      "dispatchCommandContext.pollingEnabled"
    )
  };
}

function normalizeCommandGuard(commandGuard) {
  if (!commandGuard || typeof commandGuard !== "object") {
    throw new Error("commandGuard is required");
  }

  return {
    dispatchIntentKind: normalizeString(commandGuard.dispatchIntentKind, "commandGuard.dispatchIntentKind"),
    dispatchIntentId: normalizeHex32(commandGuard.dispatchIntentId, "commandGuard.dispatchIntentId"),
    dispatchIntentHash: normalizeHex32(commandGuard.dispatchIntentHash, "commandGuard.dispatchIntentHash"),
    approvalState: normalizeString(commandGuard.approvalState, "commandGuard.approvalState"),
    dispatchAuthorized: normalizeBoolean(
      commandGuard.dispatchAuthorized,
      "commandGuard.dispatchAuthorized"
    ),
    noSendPolicy: normalizeString(commandGuard.noSendPolicy, "commandGuard.noSendPolicy"),
    networkSubmissionPerformed: normalizeBoolean(
      commandGuard.networkSubmissionPerformed,
      "commandGuard.networkSubmissionPerformed"
    )
  };
}

function normalizeDispatchCommand(dispatchCommand) {
  if (!dispatchCommand || typeof dispatchCommand !== "object") {
    throw new Error("dispatchCommand is required");
  }

  return {
    commandId: normalizeHex32(dispatchCommand.commandId, "dispatchCommand.commandId"),
    context: normalizeDispatchCommandContext(dispatchCommand.context),
    request: normalizeEndpointRequest(dispatchCommand.request),
    guard: normalizeCommandGuard(dispatchCommand.guard)
  };
}

function deriveDeterministicSmartAccountDeployDispatchAttempt({
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
  dispatchCommandKind,
  dispatchCommandId,
  dispatchCommand,
  dispatchCommandHash
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
  const normalizedDispatchCommandKind = normalizeString(
    dispatchCommandKind,
    "dispatchCommandKind"
  );
  const normalizedDispatchCommandId = normalizeHex32(
    dispatchCommandId,
    "dispatchCommandId"
  );
  const normalizedDispatchCommand = normalizeDispatchCommand(dispatchCommand);
  const normalizedDispatchCommandHash = normalizeHex32(
    dispatchCommandHash,
    "dispatchCommandHash"
  );

  assertEqual(
    normalizedDispatchCommandKind,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND,
    "dispatchCommandKind"
  );
  assertEqual(
    normalizedDispatchCommand.commandId,
    normalizedDispatchCommandId,
    "dispatchCommand.commandId/dispatchCommandId"
  );
  assertEqual(
    normalizedDispatchCommand.context.commandStage,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE,
    "dispatchCommand.context.commandStage"
  );
  assertEqual(
    normalizedDispatchCommand.context.commandAction,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION,
    "dispatchCommand.context.commandAction"
  );
  assertEqual(
    normalizedDispatchCommand.context.commandTransport,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_TRANSPORT,
    "dispatchCommand.context.commandTransport"
  );
  assertEqual(
    normalizedDispatchCommand.context.commandExecutionMode,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_EXECUTION_MODE,
    "dispatchCommand.context.commandExecutionMode"
  );
  assertEqual(
    normalizedDispatchCommand.context.noSendPolicy,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY,
    "dispatchCommand.context.noSendPolicy"
  );
  assertTrue(
    normalizedDispatchCommand.context.approvedForDispatch,
    "dispatchCommand.context.approvedForDispatch"
  );
  assertTrue(
    normalizedDispatchCommand.context.commandReady,
    "dispatchCommand.context.commandReady"
  );
  assertFalse(
    normalizedDispatchCommand.context.networkSubmissionPerformed,
    "dispatchCommand.context.networkSubmissionPerformed"
  );
  assertFalse(
    normalizedDispatchCommand.context.responseObserved,
    "dispatchCommand.context.responseObserved"
  );
  assertFalse(
    normalizedDispatchCommand.context.pollingEnabled,
    "dispatchCommand.context.pollingEnabled"
  );
  assertEqual(
    normalizedDispatchCommand.context.dispatchIntentId,
    normalizedDispatchIntentId,
    "dispatchCommand.context.dispatchIntentId/dispatchIntentId"
  );
  assertEqual(
    normalizedDispatchCommand.context.dispatchIntentHash,
    normalizedDispatchIntentHash,
    "dispatchCommand.context.dispatchIntentHash/dispatchIntentHash"
  );
  assertEqual(
    normalizedDispatchCommand.context.requestHash,
    normalizedEndpointRequestHash,
    "dispatchCommand.context.requestHash/endpointRequestHash"
  );
  assertEqual(
    normalizedDispatchCommand.guard.dispatchIntentId,
    normalizedDispatchIntentId,
    "dispatchCommand.guard.dispatchIntentId/dispatchIntentId"
  );
  assertEqual(
    normalizedDispatchCommand.guard.dispatchIntentHash,
    normalizedDispatchIntentHash,
    "dispatchCommand.guard.dispatchIntentHash/dispatchIntentHash"
  );
  assertTrue(
    normalizedDispatchCommand.guard.dispatchAuthorized,
    "dispatchCommand.guard.dispatchAuthorized"
  );
  assertFalse(
    normalizedDispatchCommand.guard.networkSubmissionPerformed,
    "dispatchCommand.guard.networkSubmissionPerformed"
  );

  const recomputedDispatchCommandJson = JSON.stringify(normalizedDispatchCommand);
  const recomputedDispatchCommandHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedDispatchCommandJson)
  );
  assertEqual(
    recomputedDispatchCommandHash,
    normalizedDispatchCommandHash,
    "dispatchCommandHash"
  );

  const dispatchAttemptContext = {
    attemptLabel: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_LABEL,
    attemptChannel: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_CHANNEL,
    attemptStage: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STAGE,
    attemptAction: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ACTION,
    attemptOrdinal: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL,
    attemptState: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STATE,
    attemptExecutionMode: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_EXECUTION_MODE,
    nextAction: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NEXT_ACTION,
    noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NO_SEND_POLICY,
    dispatchCommandId: normalizedDispatchCommandId,
    dispatchCommandHash: normalizedDispatchCommandHash,
    endpointUrl: normalizedDispatchCommand.context.endpointUrl,
    requestMethod: normalizedDispatchCommand.context.requestMethod,
    requestHash: normalizedEndpointRequestHash,
    readyForNetworkBoundary: true,
    networkSubmissionPerformed: false,
    responseObserved: false,
    pollingEnabled: false
  };
  const dispatchAttemptContextJson = JSON.stringify(dispatchAttemptContext);
  const dispatchAttemptContextHash = ethers.keccak256(
    ethers.toUtf8Bytes(dispatchAttemptContextJson)
  );

  const dispatchAttemptRequest = normalizedDispatchCommand.request;
  const dispatchAttemptRequestJson = JSON.stringify(dispatchAttemptRequest);
  const dispatchAttemptRequestBytes = ethers.hexlify(
    ethers.toUtf8Bytes(dispatchAttemptRequestJson)
  );
  const dispatchAttemptRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(dispatchAttemptRequestJson)
  );
  assertEqual(
    dispatchAttemptRequestHash,
    normalizedEndpointRequestHash,
    "dispatchAttemptRequestHash/endpointRequestHash"
  );

  const attemptGuard = {
    dispatchCommandKind: normalizedDispatchCommandKind,
    dispatchCommandId: normalizedDispatchCommandId,
    dispatchCommandHash: normalizedDispatchCommandHash,
    commandReady: true,
    attemptOrdinal: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL,
    attemptState: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STATE,
    noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NO_SEND_POLICY,
    networkSubmissionPerformed: false
  };
  const attemptGuardJson = JSON.stringify(attemptGuard);
  const attemptGuardHash = ethers.keccak256(ethers.toUtf8Bytes(attemptGuardJson));

  const dispatchAttemptId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedDispatchCommandId,
        dispatchAttemptContextHash,
        dispatchAttemptRequestHash
      ]
    )
  );

  const dispatchAttempt = {
    attemptId: dispatchAttemptId,
    context: dispatchAttemptContext,
    request: dispatchAttemptRequest,
    guard: attemptGuard
  };
  const dispatchAttemptJson = JSON.stringify(dispatchAttempt);
  const dispatchAttemptBytes = ethers.hexlify(
    ethers.toUtf8Bytes(dispatchAttemptJson)
  );
  const dispatchAttemptHash = ethers.keccak256(
    ethers.toUtf8Bytes(dispatchAttemptJson)
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
    dispatchIntentId: normalizedDispatchIntentId,
    dispatchIntentHash: normalizedDispatchIntentHash,
    dispatchCommandKind: normalizedDispatchCommandKind,
    dispatchCommandId: normalizedDispatchCommandId,
    dispatchCommandHash: normalizedDispatchCommandHash,
    dispatchAttemptKind: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_KIND,
    dispatchAttemptContext,
    dispatchAttemptContextJson,
    dispatchAttemptContextHash,
    dispatchAttemptRequest,
    dispatchAttemptRequestJson,
    dispatchAttemptRequestBytes,
    dispatchAttemptRequestHash,
    attemptGuard,
    attemptGuardJson,
    attemptGuardHash,
    dispatchAttemptId,
    dispatchAttempt,
    dispatchAttemptJson,
    dispatchAttemptBytes,
    dispatchAttemptHash,
    proofType: normalizedProofType
  };
}

function buildSmartAccountDeployDispatchAttempt({ smartAccountDeployDispatchCommand }) {
  if (
    !smartAccountDeployDispatchCommand ||
    typeof smartAccountDeployDispatchCommand !== "object"
  ) {
    throw new Error("smartAccountDeployDispatchCommand is required");
  }

  assertEqual(
    smartAccountDeployDispatchCommand.path,
    "phil-smart-account-deploy-dispatch-command",
    "smartAccountDeployDispatchCommand.path"
  );
  assertEqual(
    smartAccountDeployDispatchCommand.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployDispatchCommand.payloadShape"
  );

  if (
    !smartAccountDeployDispatchCommand.validationChecks ||
    typeof smartAccountDeployDispatchCommand.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployDispatchCommand.validationChecks is required");
  }
  if (
    !smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary ||
    typeof smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary is required"
    );
  }
  if (
    !smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand ||
    typeof smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand is required"
    );
  }
  if (
    !smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand ||
    typeof smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand is required"
    );
  }

  assertTrue(
    smartAccountDeployDispatchCommand.validationChecks
      .smartAccountDeployDispatchIntentPathValid,
    "validationChecks.smartAccountDeployDispatchIntentPathValid"
  );
  assertTrue(
    smartAccountDeployDispatchCommand.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployDispatchCommand.validationChecks
      .upstreamSmartAccountDeployDispatchIntentValid,
    "validationChecks.upstreamSmartAccountDeployDispatchIntentValid"
  );
  assertTrue(
    smartAccountDeployDispatchCommand.validationChecks
      .deterministicSmartAccountDeployDispatchCommandDerived,
    "validationChecks.deterministicSmartAccountDeployDispatchCommandDerived"
  );
  assertTrue(
    smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary.ready,
    "smartAccountDeployDispatchCommandSummary.ready"
  );
  assertEqual(
    smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary
      .status,
    "smart-account-deploy-dispatch-command-ready",
    "smartAccountDeployDispatchCommandSummary.status"
  );
  assertTrue(
    smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary
      .parityProven,
    "smartAccountDeployDispatchCommandSummary.parityProven"
  );

  const deterministicSmartAccountDeployDispatchCommand = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .ownerCommitment,
      "smartAccountDeployDispatchCommand.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .consumerDataHash,
      "smartAccountDeployDispatchCommand.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .canonicalRecipient,
      "smartAccountDeployDispatchCommand.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.walletId,
      "smartAccountDeployDispatchCommand.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.targetId,
      "smartAccountDeployDispatchCommand.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .targetAddress,
      "smartAccountDeployDispatchCommand.targetAddress"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .entryPointAddress,
      "smartAccountDeployDispatchCommand.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.chainId,
      "smartAccountDeployDispatchCommand.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.userOpHash,
      "smartAccountDeployDispatchCommand.userOpHash"
    ),
    bundlerSubmissionId: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .bundlerSubmissionId,
      "smartAccountDeployDispatchCommand.bundlerSubmissionId"
    ),
    endpointSubmissionId: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .endpointSubmissionId,
      "smartAccountDeployDispatchCommand.endpointSubmissionId"
    ),
    endpointRequestHash: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .endpointRequestHash,
      "smartAccountDeployDispatchCommand.endpointRequestHash"
    ),
    dispatchIntentId: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchIntentId,
      "smartAccountDeployDispatchCommand.dispatchIntentId"
    ),
    dispatchIntentHash: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchIntentHash,
      "smartAccountDeployDispatchCommand.dispatchIntentHash"
    ),
    dispatchCommandKind: normalizeString(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandKind,
      "smartAccountDeployDispatchCommand.dispatchCommandKind"
    ),
    dispatchCommandId: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandId,
      "smartAccountDeployDispatchCommand.dispatchCommandId"
    ),
    dispatchCommand: normalizeDispatchCommand(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommand
    ),
    dispatchCommandHash: normalizeHex32(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandHash,
      "smartAccountDeployDispatchCommand.dispatchCommandHash"
    )
  };

  const appSmartAccountDeployDispatchCommand = {
    recipient: normalizeAddress(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .recipient,
      "appSmartAccountDeployDispatchCommand.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand.sender,
      "appSmartAccountDeployDispatchCommand.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .entryPointAddress,
      "appSmartAccountDeployDispatchCommand.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand.chainId,
      "appSmartAccountDeployDispatchCommand.chainId"
    ),
    endpointUrl: normalizeString(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .endpointUrl,
      "appSmartAccountDeployDispatchCommand.endpointUrl"
    ),
    requestMethod: normalizeString(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .requestMethod,
      "appSmartAccountDeployDispatchCommand.requestMethod"
    ),
    dispatchIntentId: normalizeHex32(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchIntentId,
      "appSmartAccountDeployDispatchCommand.dispatchIntentId"
    ),
    dispatchCommandKind: normalizeString(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandKind,
      "appSmartAccountDeployDispatchCommand.dispatchCommandKind"
    ),
    dispatchCommandId: normalizeHex32(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandId,
      "appSmartAccountDeployDispatchCommand.dispatchCommandId"
    ),
    dispatchCommandStage: normalizeString(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandStage,
      "appSmartAccountDeployDispatchCommand.dispatchCommandStage"
    ),
    dispatchCommandAction: normalizeString(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandAction,
      "appSmartAccountDeployDispatchCommand.dispatchCommandAction"
    ),
    dispatchCommandHash: normalizeHex32(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandHash,
      "appSmartAccountDeployDispatchCommand.dispatchCommandHash"
    ),
    noSendPolicy: normalizeString(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .noSendPolicy,
      "appSmartAccountDeployDispatchCommand.noSendPolicy"
    ),
    commandReady:
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .commandReady === true,
    networkSubmissionPerformed:
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .networkSubmissionPerformed === true,
    ready:
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand.ready ===
      true,
    status: normalizeString(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand.status,
      "appSmartAccountDeployDispatchCommand.status"
    ),
    parityProven:
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .parityProven === true
  };

  assertTrue(
    appSmartAccountDeployDispatchCommand.ready,
    "appSmartAccountDeployDispatchCommand.ready"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.status,
    "smart-account-deploy-dispatch-command-ready",
    "appSmartAccountDeployDispatchCommand.status"
  );
  assertTrue(
    appSmartAccountDeployDispatchCommand.parityProven,
    "appSmartAccountDeployDispatchCommand.parityProven"
  );
  assertTrue(
    appSmartAccountDeployDispatchCommand.commandReady,
    "appSmartAccountDeployDispatchCommand.commandReady"
  );
  assertFalse(
    appSmartAccountDeployDispatchCommand.networkSubmissionPerformed,
    "appSmartAccountDeployDispatchCommand.networkSubmissionPerformed"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.recipient.toLowerCase(),
    deterministicSmartAccountDeployDispatchCommand.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployDispatchCommand.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.sender.toLowerCase(),
    deterministicSmartAccountDeployDispatchCommand.targetAddress.toLowerCase(),
    "appSmartAccountDeployDispatchCommand.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeployDispatchCommand.entryPointAddress.toLowerCase(),
    "appSmartAccountDeployDispatchCommand.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.chainId,
    deterministicSmartAccountDeployDispatchCommand.chainId,
    "appSmartAccountDeployDispatchCommand.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.endpointUrl,
    deterministicSmartAccountDeployDispatchCommand.dispatchCommand.context.endpointUrl,
    "appSmartAccountDeployDispatchCommand.endpointUrl/dispatchCommand.context.endpointUrl"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.requestMethod,
    deterministicSmartAccountDeployDispatchCommand.dispatchCommand.context.requestMethod,
    "appSmartAccountDeployDispatchCommand.requestMethod/dispatchCommand.context.requestMethod"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.dispatchIntentId,
    deterministicSmartAccountDeployDispatchCommand.dispatchIntentId,
    "appSmartAccountDeployDispatchCommand.dispatchIntentId/dispatchIntentId"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.dispatchCommandKind,
    deterministicSmartAccountDeployDispatchCommand.dispatchCommandKind,
    "appSmartAccountDeployDispatchCommand.dispatchCommandKind/dispatchCommandKind"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.dispatchCommandId,
    deterministicSmartAccountDeployDispatchCommand.dispatchCommandId,
    "appSmartAccountDeployDispatchCommand.dispatchCommandId/dispatchCommandId"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.dispatchCommandStage,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE,
    "appSmartAccountDeployDispatchCommand.dispatchCommandStage"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.dispatchCommandAction,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION,
    "appSmartAccountDeployDispatchCommand.dispatchCommandAction"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.dispatchCommandHash,
    deterministicSmartAccountDeployDispatchCommand.dispatchCommandHash,
    "appSmartAccountDeployDispatchCommand.dispatchCommandHash/dispatchCommandHash"
  );
  assertEqual(
    appSmartAccountDeployDispatchCommand.noSendPolicy,
    SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY,
    "appSmartAccountDeployDispatchCommand.noSendPolicy"
  );

  const smartAccountDeployDispatchAttempt =
    deriveDeterministicSmartAccountDeployDispatchAttempt({
      proofType: smartAccountDeployDispatchCommand.proofType,
      ownerCommitment:
        deterministicSmartAccountDeployDispatchCommand.ownerCommitment,
      consumerDataHash:
        deterministicSmartAccountDeployDispatchCommand.consumerDataHash,
      canonicalRecipient:
        deterministicSmartAccountDeployDispatchCommand.canonicalRecipient,
      walletId: deterministicSmartAccountDeployDispatchCommand.walletId,
      targetId: deterministicSmartAccountDeployDispatchCommand.targetId,
      targetAddress:
        deterministicSmartAccountDeployDispatchCommand.targetAddress,
      entryPointAddress:
        deterministicSmartAccountDeployDispatchCommand.entryPointAddress,
      chainId: deterministicSmartAccountDeployDispatchCommand.chainId,
      userOpHash: deterministicSmartAccountDeployDispatchCommand.userOpHash,
      bundlerSubmissionId:
        deterministicSmartAccountDeployDispatchCommand.bundlerSubmissionId,
      endpointSubmissionId:
        deterministicSmartAccountDeployDispatchCommand.endpointSubmissionId,
      endpointRequestHash:
        deterministicSmartAccountDeployDispatchCommand.endpointRequestHash,
      dispatchIntentId:
        deterministicSmartAccountDeployDispatchCommand.dispatchIntentId,
      dispatchIntentHash:
        deterministicSmartAccountDeployDispatchCommand.dispatchIntentHash,
      dispatchCommandKind:
        deterministicSmartAccountDeployDispatchCommand.dispatchCommandKind,
      dispatchCommandId:
        deterministicSmartAccountDeployDispatchCommand.dispatchCommandId,
      dispatchCommand:
        deterministicSmartAccountDeployDispatchCommand.dispatchCommand,
      dispatchCommandHash:
        deterministicSmartAccountDeployDispatchCommand.dispatchCommandHash
    });

  return {
    version: 1,
    path: "phil-smart-account-deploy-dispatch-attempt",
    smartAccountDeployDispatchAttemptSource:
      "scripts/base/build-smart-account-deploy-dispatch-attempt.cjs",
    smartAccountDeployDispatchCommandSource:
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSource,
    consumedPath: smartAccountDeployDispatchCommand.path,
    proofType: smartAccountDeployDispatchCommand.proofType,
    payloadShape: smartAccountDeployDispatchCommand.payloadShape,
    smartAccountDeployDispatchAttemptDomain: {
      label: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployDispatchCommandPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployDispatchCommandValid: true,
      deterministicSmartAccountDeployDispatchAttemptDerived: true
    },
    smartAccountDeployDispatchAttemptSummary: {
      ready: true,
      status: "smart-account-deploy-dispatch-attempt-ready",
      reason: "validated-smart-account-deploy-dispatch-command",
      parityProven: true
    },
    smartAccountDeployDispatchAttempt: {
      ownerCommitment: smartAccountDeployDispatchAttempt.ownerCommitment,
      consumerDataHash: smartAccountDeployDispatchAttempt.consumerDataHash,
      canonicalRecipient: smartAccountDeployDispatchAttempt.canonicalRecipient,
      walletId: smartAccountDeployDispatchAttempt.walletId,
      targetId: smartAccountDeployDispatchAttempt.targetId,
      targetAddress: smartAccountDeployDispatchAttempt.targetAddress,
      entryPointAddress: smartAccountDeployDispatchAttempt.entryPointAddress,
      chainId: smartAccountDeployDispatchAttempt.chainId,
      userOpHash: smartAccountDeployDispatchAttempt.userOpHash,
      bundlerSubmissionId:
        smartAccountDeployDispatchAttempt.bundlerSubmissionId,
      endpointSubmissionId:
        smartAccountDeployDispatchAttempt.endpointSubmissionId,
      endpointRequestHash:
        smartAccountDeployDispatchAttempt.endpointRequestHash,
      dispatchIntentId: smartAccountDeployDispatchAttempt.dispatchIntentId,
      dispatchIntentHash: smartAccountDeployDispatchAttempt.dispatchIntentHash,
      dispatchCommandKind:
        smartAccountDeployDispatchAttempt.dispatchCommandKind,
      dispatchCommandId: smartAccountDeployDispatchAttempt.dispatchCommandId,
      dispatchCommandHash:
        smartAccountDeployDispatchAttempt.dispatchCommandHash,
      dispatchAttemptKind:
        smartAccountDeployDispatchAttempt.dispatchAttemptKind,
      dispatchAttemptContext:
        smartAccountDeployDispatchAttempt.dispatchAttemptContext,
      dispatchAttemptContextJson:
        smartAccountDeployDispatchAttempt.dispatchAttemptContextJson,
      dispatchAttemptContextHash:
        smartAccountDeployDispatchAttempt.dispatchAttemptContextHash,
      dispatchAttemptRequest:
        smartAccountDeployDispatchAttempt.dispatchAttemptRequest,
      dispatchAttemptRequestJson:
        smartAccountDeployDispatchAttempt.dispatchAttemptRequestJson,
      dispatchAttemptRequestBytes:
        smartAccountDeployDispatchAttempt.dispatchAttemptRequestBytes,
      dispatchAttemptRequestHash:
        smartAccountDeployDispatchAttempt.dispatchAttemptRequestHash,
      attemptGuard: smartAccountDeployDispatchAttempt.attemptGuard,
      attemptGuardJson: smartAccountDeployDispatchAttempt.attemptGuardJson,
      attemptGuardHash: smartAccountDeployDispatchAttempt.attemptGuardHash,
      dispatchAttemptId: smartAccountDeployDispatchAttempt.dispatchAttemptId,
      dispatchAttempt: smartAccountDeployDispatchAttempt.dispatchAttempt,
      dispatchAttemptJson:
        smartAccountDeployDispatchAttempt.dispatchAttemptJson,
      dispatchAttemptBytes:
        smartAccountDeployDispatchAttempt.dispatchAttemptBytes,
      dispatchAttemptHash:
        smartAccountDeployDispatchAttempt.dispatchAttemptHash
    },
    appSmartAccountDeployDispatchAttempt: {
      recipient: smartAccountDeployDispatchAttempt.canonicalRecipient,
      sender: smartAccountDeployDispatchAttempt.targetAddress,
      entryPointAddress: smartAccountDeployDispatchAttempt.entryPointAddress,
      chainId: smartAccountDeployDispatchAttempt.chainId,
      endpointUrl:
        smartAccountDeployDispatchAttempt.dispatchAttemptContext.endpointUrl,
      requestMethod:
        smartAccountDeployDispatchAttempt.dispatchAttemptContext.requestMethod,
      dispatchCommandId: smartAccountDeployDispatchAttempt.dispatchCommandId,
      dispatchAttemptKind:
        smartAccountDeployDispatchAttempt.dispatchAttemptKind,
      dispatchAttemptId: smartAccountDeployDispatchAttempt.dispatchAttemptId,
      dispatchAttemptStage:
        smartAccountDeployDispatchAttempt.dispatchAttemptContext.attemptStage,
      dispatchAttemptAction:
        smartAccountDeployDispatchAttempt.dispatchAttemptContext.attemptAction,
      dispatchAttemptOrdinal:
        smartAccountDeployDispatchAttempt.dispatchAttemptContext.attemptOrdinal,
      dispatchAttemptHash:
        smartAccountDeployDispatchAttempt.dispatchAttemptHash,
      noSendPolicy:
        smartAccountDeployDispatchAttempt.dispatchAttemptContext.noSendPolicy,
      readyForNetworkBoundary: true,
      networkSubmissionPerformed: false,
      ready: true,
      status: "smart-account-deploy-dispatch-attempt-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-dispatch-command") {
      parsed.smartAccountDeployDispatchCommandPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-dispatch-attempt.cjs --smart-account-deploy-dispatch-command <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployDispatchCommandPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployDispatchAttempt =
      buildSmartAccountDeployDispatchAttempt({
        smartAccountDeployDispatchCommand: loadJson(
          path.resolve(parsed.smartAccountDeployDispatchCommandPath)
        )
      });
    console.log(JSON.stringify(smartAccountDeployDispatchAttempt, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_KIND,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_CHANNEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STAGE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STATE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_EXECUTION_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NO_SEND_POLICY,
  deriveDeterministicSmartAccountDeployDispatchAttempt,
  buildSmartAccountDeployDispatchAttempt
};
