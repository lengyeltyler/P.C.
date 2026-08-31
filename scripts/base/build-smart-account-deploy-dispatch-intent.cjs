const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE
} = require("./build-smart-account-deploy-client-session.cjs");

const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_V1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND =
  "erc4337-smart-account-deploy-dispatch-intent-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_LABEL =
  "base-8453-user-approved-no-send-dispatch-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_CHANNEL =
  "device-app-dispatch-loop-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE = "user-approved-no-send";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_MODE =
  "local-device-user-approved-no-send-v1";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE = "approved";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_SCOPE =
  "single-endpoint-bound-user-operation";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DISPATCH_MODE =
  "manual-client-dispatch-no-send";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NEXT_ACTION =
  "submit-through-client-loop";
const SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NO_SEND_POLICY =
  "record-intent-only";

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

function deriveDeterministicSmartAccountDeployDispatchIntent({
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
  clientSessionKind,
  clientSessionId,
  clientSessionHandoff,
  clientSessionHandoffHash
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
  const normalizedClientSessionKind = normalizeString(
    clientSessionKind,
    "clientSessionKind"
  );
  const normalizedClientSessionId = normalizeHex32(
    clientSessionId,
    "clientSessionId"
  );
  const normalizedClientSessionHandoff = normalizeClientSessionHandoff(
    clientSessionHandoff
  );
  const normalizedClientSessionHandoffHash = normalizeHex32(
    clientSessionHandoffHash,
    "clientSessionHandoffHash"
  );

  assertEqual(
    normalizedClientSessionKind,
    SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND,
    "clientSessionKind"
  );
  assertEqual(
    normalizedClientSessionHandoff.sessionId,
    normalizedClientSessionId,
    "clientSessionHandoff.sessionId/clientSessionId"
  );
  assertEqual(
    normalizedClientSessionHandoff.session.sessionStage,
    SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE,
    "clientSessionHandoff.session.sessionStage"
  );
  assertTrue(
    normalizedClientSessionHandoff.session.readyToDispatch,
    "clientSessionHandoff.session.readyToDispatch"
  );
  assertFalse(
    normalizedClientSessionHandoff.session.networkSubmissionPerformed,
    "clientSessionHandoff.session.networkSubmissionPerformed"
  );
  assertFalse(
    normalizedClientSessionHandoff.session.responseObserved,
    "clientSessionHandoff.session.responseObserved"
  );
  assertFalse(
    normalizedClientSessionHandoff.session.pollingEnabled,
    "clientSessionHandoff.session.pollingEnabled"
  );
  assertEqual(
    normalizedClientSessionHandoff.session.requestHash,
    normalizedEndpointRequestHash,
    "clientSessionHandoff.session.requestHash/endpointRequestHash"
  );

  const recomputedClientSessionHandoffJson = JSON.stringify(
    normalizedClientSessionHandoff
  );
  const recomputedClientSessionHandoffHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedClientSessionHandoffJson)
  );
  assertEqual(
    recomputedClientSessionHandoffHash,
    normalizedClientSessionHandoffHash,
    "clientSessionHandoffHash"
  );

  const dispatchIntentContext = {
    intentLabel: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_LABEL,
    intentChannel: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_CHANNEL,
    intentStage: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE,
    approvalMode: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_MODE,
    approvalState: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
    approvalScope: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_SCOPE,
    dispatchMode: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DISPATCH_MODE,
    nextAction: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NEXT_ACTION,
    noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NO_SEND_POLICY,
    approvedForDispatch: true,
    networkSubmissionPerformed: false,
    responseObserved: false,
    pollingEnabled: false,
    clientSessionId: normalizedClientSessionId,
    clientSessionHandoffHash: normalizedClientSessionHandoffHash,
    endpointUrl: normalizedClientSessionHandoff.session.endpointUrl,
    requestMethod: normalizedClientSessionHandoff.session.requestMethod,
    requestHash: normalizedEndpointRequestHash
  };
  const dispatchIntentContextJson = JSON.stringify(dispatchIntentContext);
  const dispatchIntentContextHash = ethers.keccak256(
    ethers.toUtf8Bytes(dispatchIntentContextJson)
  );

  const userApproval = {
    approvalMode: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_MODE,
    approvalState: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
    approvalScope: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_SCOPE,
    approvalSubjectKind: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND,
    approvalSubjectId: normalizedClientSessionId,
    approvalSubjectHash: normalizedClientSessionHandoffHash,
    approvedEndpointUrl: normalizedClientSessionHandoff.session.endpointUrl,
    approvedRequestHash: normalizedEndpointRequestHash,
    approvalEffect: "dispatch-intent-recorded-no-send",
    dispatchAuthorized: true,
    networkSubmissionPerformed: false
  };
  const userApprovalJson = JSON.stringify(userApproval);
  const userApprovalHash = ethers.keccak256(ethers.toUtf8Bytes(userApprovalJson));

  const dispatchIntentId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedClientSessionId,
        dispatchIntentContextHash,
        userApprovalHash
      ]
    )
  );

  const dispatchIntent = {
    intentId: dispatchIntentId,
    intent: dispatchIntentContext,
    userApproval,
    clientSessionHandoff: normalizedClientSessionHandoff
  };
  const dispatchIntentJson = JSON.stringify(dispatchIntent);
  const dispatchIntentBytes = ethers.hexlify(ethers.toUtf8Bytes(dispatchIntentJson));
  const dispatchIntentHash = ethers.keccak256(
    ethers.toUtf8Bytes(dispatchIntentJson)
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
    clientSessionKind: normalizedClientSessionKind,
    clientSessionId: normalizedClientSessionId,
    clientSessionHandoffHash: normalizedClientSessionHandoffHash,
    dispatchIntentKind: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND,
    dispatchIntentContext,
    dispatchIntentContextJson,
    dispatchIntentContextHash,
    userApproval,
    userApprovalJson,
    userApprovalHash,
    dispatchIntentId,
    dispatchIntent,
    dispatchIntentJson,
    dispatchIntentBytes,
    dispatchIntentHash,
    proofType: normalizedProofType
  };
}

function buildSmartAccountDeployDispatchIntent({ smartAccountDeployClientSession }) {
  if (
    !smartAccountDeployClientSession ||
    typeof smartAccountDeployClientSession !== "object"
  ) {
    throw new Error("smartAccountDeployClientSession is required");
  }

  assertEqual(
    smartAccountDeployClientSession.path,
    "phil-smart-account-deploy-client-session",
    "smartAccountDeployClientSession.path"
  );
  assertEqual(
    smartAccountDeployClientSession.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployClientSession.payloadShape"
  );

  if (
    !smartAccountDeployClientSession.validationChecks ||
    typeof smartAccountDeployClientSession.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployClientSession.validationChecks is required");
  }
  if (
    !smartAccountDeployClientSession.smartAccountDeployClientSessionSummary ||
    typeof smartAccountDeployClientSession.smartAccountDeployClientSessionSummary !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployClientSession.smartAccountDeployClientSessionSummary is required"
    );
  }
  if (
    !smartAccountDeployClientSession.smartAccountDeployClientSession ||
    typeof smartAccountDeployClientSession.smartAccountDeployClientSession !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployClientSession.smartAccountDeployClientSession is required"
    );
  }
  if (
    !smartAccountDeployClientSession.appSmartAccountDeployClientSession ||
    typeof smartAccountDeployClientSession.appSmartAccountDeployClientSession !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeployClientSession.appSmartAccountDeployClientSession is required"
    );
  }

  assertTrue(
    smartAccountDeployClientSession.validationChecks
      .smartAccountDeployEndpointSubmissionPathValid,
    "validationChecks.smartAccountDeployEndpointSubmissionPathValid"
  );
  assertTrue(
    smartAccountDeployClientSession.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployClientSession.validationChecks
      .upstreamSmartAccountDeployEndpointSubmissionValid,
    "validationChecks.upstreamSmartAccountDeployEndpointSubmissionValid"
  );
  assertTrue(
    smartAccountDeployClientSession.validationChecks
      .deterministicSmartAccountDeployClientSessionDerived,
    "validationChecks.deterministicSmartAccountDeployClientSessionDerived"
  );
  assertTrue(
    smartAccountDeployClientSession.smartAccountDeployClientSessionSummary.ready,
    "smartAccountDeployClientSessionSummary.ready"
  );
  assertEqual(
    smartAccountDeployClientSession.smartAccountDeployClientSessionSummary.status,
    "smart-account-deploy-client-session-ready",
    "smartAccountDeployClientSessionSummary.status"
  );
  assertTrue(
    smartAccountDeployClientSession.smartAccountDeployClientSessionSummary
      .parityProven,
    "smartAccountDeployClientSessionSummary.parityProven"
  );

  const deterministicSmartAccountDeployClientSession = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .ownerCommitment,
      "smartAccountDeployClientSession.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .consumerDataHash,
      "smartAccountDeployClientSession.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .canonicalRecipient,
      "smartAccountDeployClientSession.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession.walletId,
      "smartAccountDeployClientSession.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession.targetId,
      "smartAccountDeployClientSession.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .targetAddress,
      "smartAccountDeployClientSession.targetAddress"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .entryPointAddress,
      "smartAccountDeployClientSession.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployClientSession.smartAccountDeployClientSession.chainId,
      "smartAccountDeployClientSession.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession.userOpHash,
      "smartAccountDeployClientSession.userOpHash"
    ),
    bundlerSubmissionId: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .bundlerSubmissionId,
      "smartAccountDeployClientSession.bundlerSubmissionId"
    ),
    endpointSubmissionId: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .endpointSubmissionId,
      "smartAccountDeployClientSession.endpointSubmissionId"
    ),
    endpointRequestHash: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .endpointRequestHash,
      "smartAccountDeployClientSession.endpointRequestHash"
    ),
    clientSessionKind: normalizeString(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionKind,
      "smartAccountDeployClientSession.clientSessionKind"
    ),
    clientSessionId: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionId,
      "smartAccountDeployClientSession.clientSessionId"
    ),
    clientSessionHandoff: normalizeClientSessionHandoff(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionHandoff
    ),
    clientSessionHandoffHash: normalizeHex32(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionHandoffHash,
      "smartAccountDeployClientSession.clientSessionHandoffHash"
    )
  };

  const appSmartAccountDeployClientSession = {
    recipient: normalizeAddress(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .recipient,
      "appSmartAccountDeployClientSession.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.sender,
      "appSmartAccountDeployClientSession.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .entryPointAddress,
      "appSmartAccountDeployClientSession.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.chainId,
      "appSmartAccountDeployClientSession.chainId"
    ),
    endpointUrl: normalizeString(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .endpointUrl,
      "appSmartAccountDeployClientSession.endpointUrl"
    ),
    clientSessionKind: normalizeString(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .clientSessionKind,
      "appSmartAccountDeployClientSession.clientSessionKind"
    ),
    clientSessionId: normalizeHex32(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .clientSessionId,
      "appSmartAccountDeployClientSession.clientSessionId"
    ),
    clientSessionStage: normalizeString(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .clientSessionStage,
      "appSmartAccountDeployClientSession.clientSessionStage"
    ),
    clientSessionHandoffHash: normalizeHex32(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .clientSessionHandoffHash,
      "appSmartAccountDeployClientSession.clientSessionHandoffHash"
    ),
    ready:
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.ready ===
      true,
    status: normalizeString(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.status,
      "appSmartAccountDeployClientSession.status"
    ),
    parityProven:
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .parityProven === true
  };

  assertTrue(
    appSmartAccountDeployClientSession.ready,
    "appSmartAccountDeployClientSession.ready"
  );
  assertEqual(
    appSmartAccountDeployClientSession.status,
    "smart-account-deploy-client-session-ready",
    "appSmartAccountDeployClientSession.status"
  );
  assertTrue(
    appSmartAccountDeployClientSession.parityProven,
    "appSmartAccountDeployClientSession.parityProven"
  );
  assertEqual(
    appSmartAccountDeployClientSession.recipient.toLowerCase(),
    deterministicSmartAccountDeployClientSession.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployClientSession.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployClientSession.sender.toLowerCase(),
    deterministicSmartAccountDeployClientSession.targetAddress.toLowerCase(),
    "appSmartAccountDeployClientSession.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeployClientSession.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeployClientSession.entryPointAddress.toLowerCase(),
    "appSmartAccountDeployClientSession.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeployClientSession.chainId,
    deterministicSmartAccountDeployClientSession.chainId,
    "appSmartAccountDeployClientSession.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeployClientSession.clientSessionKind,
    deterministicSmartAccountDeployClientSession.clientSessionKind,
    "appSmartAccountDeployClientSession.clientSessionKind/clientSessionKind"
  );
  assertEqual(
    appSmartAccountDeployClientSession.clientSessionId,
    deterministicSmartAccountDeployClientSession.clientSessionId,
    "appSmartAccountDeployClientSession.clientSessionId/clientSessionId"
  );
  assertEqual(
    appSmartAccountDeployClientSession.clientSessionStage,
    SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE,
    "appSmartAccountDeployClientSession.clientSessionStage"
  );
  assertEqual(
    appSmartAccountDeployClientSession.clientSessionHandoffHash,
    deterministicSmartAccountDeployClientSession.clientSessionHandoffHash,
    "appSmartAccountDeployClientSession.clientSessionHandoffHash/clientSessionHandoffHash"
  );
  assertEqual(
    appSmartAccountDeployClientSession.endpointUrl,
    deterministicSmartAccountDeployClientSession.clientSessionHandoff.session
      .endpointUrl,
    "appSmartAccountDeployClientSession.endpointUrl/clientSessionHandoff.session.endpointUrl"
  );

  const smartAccountDeployDispatchIntent =
    deriveDeterministicSmartAccountDeployDispatchIntent({
      proofType: smartAccountDeployClientSession.proofType,
      ownerCommitment:
        deterministicSmartAccountDeployClientSession.ownerCommitment,
      consumerDataHash:
        deterministicSmartAccountDeployClientSession.consumerDataHash,
      canonicalRecipient:
        deterministicSmartAccountDeployClientSession.canonicalRecipient,
      walletId: deterministicSmartAccountDeployClientSession.walletId,
      targetId: deterministicSmartAccountDeployClientSession.targetId,
      targetAddress:
        deterministicSmartAccountDeployClientSession.targetAddress,
      entryPointAddress:
        deterministicSmartAccountDeployClientSession.entryPointAddress,
      chainId: deterministicSmartAccountDeployClientSession.chainId,
      userOpHash: deterministicSmartAccountDeployClientSession.userOpHash,
      bundlerSubmissionId:
        deterministicSmartAccountDeployClientSession.bundlerSubmissionId,
      endpointSubmissionId:
        deterministicSmartAccountDeployClientSession.endpointSubmissionId,
      endpointRequestHash:
        deterministicSmartAccountDeployClientSession.endpointRequestHash,
      clientSessionKind:
        deterministicSmartAccountDeployClientSession.clientSessionKind,
      clientSessionId:
        deterministicSmartAccountDeployClientSession.clientSessionId,
      clientSessionHandoff:
        deterministicSmartAccountDeployClientSession.clientSessionHandoff,
      clientSessionHandoffHash:
        deterministicSmartAccountDeployClientSession.clientSessionHandoffHash
    });

  return {
    version: 1,
    path: "phil-smart-account-deploy-dispatch-intent",
    smartAccountDeployDispatchIntentSource:
      "scripts/base/build-smart-account-deploy-dispatch-intent.cjs",
    smartAccountDeployClientSessionSource:
      smartAccountDeployClientSession.smartAccountDeployClientSessionSource,
    consumedPath: smartAccountDeployClientSession.path,
    proofType: smartAccountDeployClientSession.proofType,
    payloadShape: smartAccountDeployClientSession.payloadShape,
    smartAccountDeployDispatchIntentDomain: {
      label: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployClientSessionPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployClientSessionValid: true,
      deterministicSmartAccountDeployDispatchIntentDerived: true
    },
    smartAccountDeployDispatchIntentSummary: {
      ready: true,
      status: "smart-account-deploy-dispatch-intent-ready",
      reason: "validated-smart-account-deploy-client-session",
      parityProven: true
    },
    smartAccountDeployDispatchIntent: {
      ownerCommitment: smartAccountDeployDispatchIntent.ownerCommitment,
      consumerDataHash: smartAccountDeployDispatchIntent.consumerDataHash,
      canonicalRecipient: smartAccountDeployDispatchIntent.canonicalRecipient,
      walletId: smartAccountDeployDispatchIntent.walletId,
      targetId: smartAccountDeployDispatchIntent.targetId,
      targetAddress: smartAccountDeployDispatchIntent.targetAddress,
      entryPointAddress: smartAccountDeployDispatchIntent.entryPointAddress,
      chainId: smartAccountDeployDispatchIntent.chainId,
      userOpHash: smartAccountDeployDispatchIntent.userOpHash,
      bundlerSubmissionId:
        smartAccountDeployDispatchIntent.bundlerSubmissionId,
      endpointSubmissionId:
        smartAccountDeployDispatchIntent.endpointSubmissionId,
      endpointRequestHash:
        smartAccountDeployDispatchIntent.endpointRequestHash,
      clientSessionKind: smartAccountDeployDispatchIntent.clientSessionKind,
      clientSessionId: smartAccountDeployDispatchIntent.clientSessionId,
      clientSessionHandoffHash:
        smartAccountDeployDispatchIntent.clientSessionHandoffHash,
      dispatchIntentKind:
        smartAccountDeployDispatchIntent.dispatchIntentKind,
      dispatchIntentContext:
        smartAccountDeployDispatchIntent.dispatchIntentContext,
      dispatchIntentContextJson:
        smartAccountDeployDispatchIntent.dispatchIntentContextJson,
      dispatchIntentContextHash:
        smartAccountDeployDispatchIntent.dispatchIntentContextHash,
      userApproval: smartAccountDeployDispatchIntent.userApproval,
      userApprovalJson: smartAccountDeployDispatchIntent.userApprovalJson,
      userApprovalHash: smartAccountDeployDispatchIntent.userApprovalHash,
      dispatchIntentId: smartAccountDeployDispatchIntent.dispatchIntentId,
      dispatchIntent: smartAccountDeployDispatchIntent.dispatchIntent,
      dispatchIntentJson: smartAccountDeployDispatchIntent.dispatchIntentJson,
      dispatchIntentBytes: smartAccountDeployDispatchIntent.dispatchIntentBytes,
      dispatchIntentHash: smartAccountDeployDispatchIntent.dispatchIntentHash
    },
    appSmartAccountDeployDispatchIntent: {
      recipient: smartAccountDeployDispatchIntent.canonicalRecipient,
      sender: smartAccountDeployDispatchIntent.targetAddress,
      entryPointAddress: smartAccountDeployDispatchIntent.entryPointAddress,
      chainId: smartAccountDeployDispatchIntent.chainId,
      endpointUrl:
        smartAccountDeployDispatchIntent.dispatchIntentContext.endpointUrl,
      clientSessionId: smartAccountDeployDispatchIntent.clientSessionId,
      dispatchIntentKind:
        smartAccountDeployDispatchIntent.dispatchIntentKind,
      dispatchIntentId: smartAccountDeployDispatchIntent.dispatchIntentId,
      dispatchIntentStage:
        smartAccountDeployDispatchIntent.dispatchIntentContext.intentStage,
      dispatchIntentHash:
        smartAccountDeployDispatchIntent.dispatchIntentHash,
      approved: true,
      dispatchAuthorized: true,
      networkSubmissionPerformed: false,
      ready: true,
      status: "smart-account-deploy-dispatch-intent-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-client-session") {
      parsed.smartAccountDeployClientSessionPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-dispatch-intent.cjs --smart-account-deploy-client-session <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployClientSessionPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployDispatchIntent =
      buildSmartAccountDeployDispatchIntent({
        smartAccountDeployClientSession: loadJson(
          path.resolve(parsed.smartAccountDeployClientSessionPath)
        )
      });
    console.log(JSON.stringify(smartAccountDeployDispatchIntent, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_CHANNEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_SCOPE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DISPATCH_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NO_SEND_POLICY,
  deriveDeterministicSmartAccountDeployDispatchIntent,
  buildSmartAccountDeployDispatchIntent
};
