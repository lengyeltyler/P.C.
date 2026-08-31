const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
} = require("./build-smart-account-deploy-signature-request.cjs");
const {
  buildSmartAccountDeploySignedUserOp
} = require("./build-smart-account-deploy-signed-userop.cjs");
const {
  buildSmartAccountDeployBundlerSubmission
} = require("./build-smart-account-deploy-bundler-submission.cjs");
const {
  buildSmartAccountDeployEndpointSubmission
} = require("./build-smart-account-deploy-endpoint-submission.cjs");
const {
  buildSmartAccountDeployClientSession
} = require("./build-smart-account-deploy-client-session.cjs");
const {
  buildSmartAccountDeployDispatchIntent
} = require("./build-smart-account-deploy-dispatch-intent.cjs");
const {
  buildSmartAccountDeployDispatchCommand
} = require("./build-smart-account-deploy-dispatch-command.cjs");
const {
  buildSmartAccountDeployDispatchAttempt
} = require("./build-smart-account-deploy-dispatch-attempt.cjs");
const {
  runSmartAccountDeployAttemptRunner
} = require("./run-smart-account-deploy-attempt-runner.cjs");
const {
  runLocalSmartAccountDeploySession
} = require("./run-local-smart-account-deploy-session.cjs");
const {
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
} = require("./run-local-bundler-stub.cjs");

const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DOMAIN_LABEL =
  "PHIL_LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_V1";
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DOMAIN_LABEL)
);
const LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DOMAIN_LABEL =
  "PHIL_LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_V1";
const LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DOMAIN_HASH =
  ethers.keccak256(
    ethers.toUtf8Bytes(LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DOMAIN_LABEL)
  );
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_KIND =
  "local-device-signing-to-deploy-session-integration-v1";
const LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_KIND =
  "local-device-signing-to-deploy-session-matrix-integration-v1";
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_LOCAL_SIGNING =
  "./proving/out/local_device_signing/local_device_signing_result.json";
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_SIGNATURE_REQUEST =
  "./proving/out/smart_account_deploy_signature_request/smart_account_deploy_signature_request.json";
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT_DIR =
  "./proving/out/local_device_signing_session_integration";
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT =
  "./proving/out/local_device_signing_session_integration/local_device_signing_session_result.json";
const LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DEFAULT_OUT =
  "./proving/out/local_device_signing_session_integration/local_device_signing_session_matrix_result.json";
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_TIMEOUT_MS = 15000;
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODES = Object.freeze([
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
]);
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODE_CLASSIFICATIONS = Object.freeze({
  [LOCAL_BUNDLER_STUB_MODE_ACCEPTED]: "accepted-json-rpc-response",
  [LOCAL_BUNDLER_STUB_MODE_REJECTED]: "rejected-json-rpc-response",
  [LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR]: "transport-error-response"
});
const LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODE_METADATA = Object.freeze({
  [LOCAL_BUNDLER_STUB_MODE_ACCEPTED]: {
    sessionAliasKey: "acceptedLocalSession",
    validationChecks: {
      acceptedModeLocalSessionRan: true,
      acceptedModeUsedRealLocalSignature: true
    },
    integrationPath: "phil-local-device-signing-session-integration",
    integrationStatus: "local-device-signing-session-integration-complete",
    integrationReason: "local-device-signature-routed-through-accepted-local-session"
  },
  [LOCAL_BUNDLER_STUB_MODE_REJECTED]: {
    sessionAliasKey: "rejectedLocalSession",
    validationChecks: {
      rejectedModeLocalSessionRan: true,
      rejectedModeUsedRealLocalSignature: true
    },
    integrationPath: "phil-local-device-signing-rejected-session-integration",
    integrationStatus: "local-device-signing-rejected-session-integration-complete",
    integrationReason: "local-device-signature-routed-through-rejected-local-session"
  },
  [LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR]: {
    sessionAliasKey: "transportErrorLocalSession",
    validationChecks: {
      transportErrorModeLocalSessionRan: true,
      transportErrorModeUsedRealLocalSignature: true
    },
    integrationPath: "phil-local-device-signing-transport-session-integration",
    integrationStatus: "local-device-signing-transport-session-integration-complete",
    integrationReason:
      "local-device-signature-routed-through-transport-error-local-session"
  }
});
const LEGACY_DUMMY_EXTERNAL_SIGNATURE =
  "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111b";
const LOCAL_DEVICE_SIGNING_SESSION_MATRIX_EXPECTED_SCENARIOS = Object.freeze([
  {
    scenarioName: "accepted",
    mode: LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
    classification: "accepted-json-rpc-response"
  },
  {
    scenarioName: "rejected",
    mode: LOCAL_BUNDLER_STUB_MODE_REJECTED,
    classification: "rejected-json-rpc-response"
  },
  {
    scenarioName: "transport",
    mode: LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR,
    classification: "transport-error-response"
  }
]);

function loadJson(jsonPath) {
  if (!fs.existsSync(jsonPath)) {
    throw new Error(
      `Missing ${jsonPath}. Run npm run generate:local-fixtures first.`
    );
  }
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function writeJson(jsonPath, value) {
  fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
  fs.writeFileSync(jsonPath, `${JSON.stringify(value, null, 2)}\n`);
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

function normalizeSignature(value, label) {
  const normalized = normalizeBytes(value, label);
  if (normalized.length !== 132) {
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

function normalizePositiveInteger(value, label) {
  const normalized = Number.parseInt(String(value || ""), 10);
  if (!Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
  return normalized;
}

function normalizeMode(value) {
  const normalized = normalizeString(value, "mode");
  if (!LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODES.includes(normalized)) {
    throw new Error(
      `Invalid mode: ${normalized}. Expected one of ${LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODES.join(
        ", "
      )}`
    );
  }
  return normalized;
}

function assertValidationCheck(checks, key) {
  if (!checks || typeof checks !== "object") {
    throw new Error("validationChecks is required");
  }
  assertTrue(checks[key], `validationChecks.${key}`);
}

function validateLocalDeviceSigningResult(localDeviceSigningResult) {
  if (!localDeviceSigningResult || typeof localDeviceSigningResult !== "object") {
    throw new Error("localDeviceSigningResult is required");
  }

  assertEqual(
    localDeviceSigningResult.path,
    "phil-local-smart-account-deploy-device-signing",
    "localDeviceSigningResult.path"
  );
  assertEqual(
    localDeviceSigningResult.proofType,
    "stwo-unlock-keccak-v1",
    "localDeviceSigningResult.proofType"
  );
  assertEqual(
    localDeviceSigningResult.payloadShape,
    "[fact_high, fact_low]",
    "localDeviceSigningResult.payloadShape"
  );

  for (const key of [
    "smartAccountDeploySignatureRequestPathValid",
    "proofTypeValid",
    "payloadShapeValid",
    "upstreamSmartAccountDeploySignatureRequestValid",
    "signerPayloadConsumed",
    "signableDigestMatchesUserOpHash",
    "signatureTargetPreserved",
    "localDevSigningKeyResolved",
    "realLocalSignatureProduced",
    "signatureRecoverable",
    "existingSignedUserOpPathReused",
    "signedUserOpSignatureMatchesLocalSignature",
    "canonicalRecipientPreserved",
    "exactTwoFeltFactShapePreserved",
    "lockedBaseTupleSemanticsUnchanged",
    "localOnlyNoExternalBundlerCall"
  ]) {
    assertValidationCheck(localDeviceSigningResult.validationChecks, key);
  }

  if (
    !localDeviceSigningResult.localDeviceSigningSummary ||
    typeof localDeviceSigningResult.localDeviceSigningSummary !== "object"
  ) {
    throw new Error("localDeviceSigningSummary is required");
  }
  if (
    !localDeviceSigningResult.localDeviceSigning ||
    typeof localDeviceSigningResult.localDeviceSigning !== "object"
  ) {
    throw new Error("localDeviceSigning is required");
  }
  if (
    !localDeviceSigningResult.signedUserOpResult ||
    typeof localDeviceSigningResult.signedUserOpResult !== "object"
  ) {
    throw new Error("signedUserOpResult is required");
  }
  if (
    !localDeviceSigningResult.appLocalDeviceSigning ||
    typeof localDeviceSigningResult.appLocalDeviceSigning !== "object"
  ) {
    throw new Error("appLocalDeviceSigning is required");
  }

  assertTrue(
    localDeviceSigningResult.localDeviceSigningSummary.ready,
    "localDeviceSigningSummary.ready"
  );
  assertEqual(
    localDeviceSigningResult.localDeviceSigningSummary.status,
    "local-device-signing-complete",
    "localDeviceSigningSummary.status"
  );
  assertTrue(
    localDeviceSigningResult.localDeviceSigningSummary.localOnly,
    "localDeviceSigningSummary.localOnly"
  );
  assertTrue(
    localDeviceSigningResult.localDeviceSigningSummary.realLocalSignatureProduced,
    "localDeviceSigningSummary.realLocalSignatureProduced"
  );
  assertTrue(
    localDeviceSigningResult.localDeviceSigningSummary.signedUserOpPathReused,
    "localDeviceSigningSummary.signedUserOpPathReused"
  );

  const localSignature = normalizeSignature(
    localDeviceSigningResult.localDeviceSigning.localSignature,
    "localDeviceSigning.localSignature"
  );
  if (
    localSignature === SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER ||
    localSignature === LEGACY_DUMMY_EXTERNAL_SIGNATURE
  ) {
    throw new Error("local signature must be a real locally produced signature");
  }

  const signableDigest = normalizeHex32(
    localDeviceSigningResult.localDeviceSigning.signatureInput.signableDigest,
    "localDeviceSigning.signatureInput.signableDigest"
  );
  const recoveredAddress = normalizeAddress(
    localDeviceSigningResult.localDeviceSigning.recoveredAddress,
    "localDeviceSigning.recoveredAddress"
  );
  const signerAddress = normalizeAddress(
    localDeviceSigningResult.localDeviceSigning.key.signerAddress,
    "localDeviceSigning.key.signerAddress"
  );
  assertEqual(
    recoveredAddress.toLowerCase(),
    signerAddress.toLowerCase(),
    "localDeviceSigning.recoveredAddress/key.signerAddress"
  );
  assertEqual(
    normalizeAddress(ethers.recoverAddress(signableDigest, localSignature), "recoveredAddress").toLowerCase(),
    signerAddress.toLowerCase(),
    "recoverAddress(localSignature)"
  );
  assertEqual(
    normalizeBytes(localDeviceSigningResult.localDeviceSigning.localSignatureHash, "localSignatureHash"),
    ethers.keccak256(localSignature),
    "localSignatureHash"
  );
  assertEqual(
    localDeviceSigningResult.signedUserOpResult.path,
    "phil-smart-account-deploy-signed-userop",
    "signedUserOpResult.path"
  );
  assertEqual(
    normalizeSignature(
      localDeviceSigningResult.signedUserOpResult.smartAccountDeploySignedUserOp
        .externalSignature,
      "signedUserOpResult.externalSignature"
    ),
    localSignature,
    "signedUserOpResult.externalSignature/localSignature"
  );
  assertEqual(
    normalizeSignature(
      localDeviceSigningResult.signedUserOpResult.smartAccountDeploySignedUserOp
        .signedUserOperation.signature,
      "signedUserOpResult.signedUserOperation.signature"
    ),
    localSignature,
    "signedUserOpResult.signedUserOperation.signature/localSignature"
  );
  assertTrue(
    localDeviceSigningResult.appLocalDeviceSigning.ready,
    "appLocalDeviceSigning.ready"
  );
  assertEqual(
    localDeviceSigningResult.appLocalDeviceSigning.status,
    "local-device-signing-complete",
    "appLocalDeviceSigning.status"
  );
  assertTrue(
    localDeviceSigningResult.appLocalDeviceSigning.localOnly,
    "appLocalDeviceSigning.localOnly"
  );

  return {
    localSignature,
    localSignatureHash: normalizeHex32(
      localDeviceSigningResult.localDeviceSigning.localSignatureHash,
      "localDeviceSigning.localSignatureHash"
    ),
    signerAddress,
    signableDigest,
    signatureRequestId: normalizeHex32(
      localDeviceSigningResult.localDeviceSigning.signatureInput.signatureRequestId,
      "localDeviceSigning.signatureInput.signatureRequestId"
    ),
    localDeviceSigningId: normalizeHex32(
      localDeviceSigningResult.localDeviceSigning.localDeviceSigningId,
      "localDeviceSigning.localDeviceSigningId"
    ),
    signedUserOpId: normalizeHex32(
      localDeviceSigningResult.signedUserOpResult.smartAccountDeploySignedUserOp
        .signedUserOpId,
      "signedUserOpResult.signedUserOpId"
    ),
    signedBundlerRequestHash: normalizeHex32(
      localDeviceSigningResult.signedUserOpResult.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash,
      "signedUserOpResult.signedBundlerRequestHash"
    ),
    recipient: normalizeAddress(
      localDeviceSigningResult.appLocalDeviceSigning.recipient,
      "appLocalDeviceSigning.recipient"
    ),
    sender: normalizeAddress(
      localDeviceSigningResult.appLocalDeviceSigning.sender,
      "appLocalDeviceSigning.sender"
    ),
    entryPointAddress: normalizeAddress(
      localDeviceSigningResult.appLocalDeviceSigning.entryPointAddress,
      "appLocalDeviceSigning.entryPointAddress"
    ),
    chainId: normalizeString(
      localDeviceSigningResult.appLocalDeviceSigning.chainId,
      "appLocalDeviceSigning.chainId"
    ),
    userOpHash: normalizeHex32(
      localDeviceSigningResult.appLocalDeviceSigning.userOpHash,
      "appLocalDeviceSigning.userOpHash"
    )
  };
}

function validateSignatureRequestForLocalSigning({
  smartAccountDeploySignatureRequest,
  validatedLocalSigning
}) {
  if (
    !smartAccountDeploySignatureRequest ||
    typeof smartAccountDeploySignatureRequest !== "object"
  ) {
    throw new Error("smartAccountDeploySignatureRequest is required");
  }

  assertEqual(
    smartAccountDeploySignatureRequest.path,
    "phil-smart-account-deploy-signature-request",
    "smartAccountDeploySignatureRequest.path"
  );
  assertEqual(
    smartAccountDeploySignatureRequest.proofType,
    "stwo-unlock-keccak-v1",
    "smartAccountDeploySignatureRequest.proofType"
  );
  assertEqual(
    smartAccountDeploySignatureRequest.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeploySignatureRequest.payloadShape"
  );

  const request = smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest;
  const appRequest =
    smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest;
  if (!request || typeof request !== "object") {
    throw new Error("smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest is required");
  }
  if (!appRequest || typeof appRequest !== "object") {
    throw new Error("smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest is required");
  }

  assertEqual(
    normalizeHex32(request.signableDigest, "request.signableDigest"),
    validatedLocalSigning.signableDigest,
    "request.signableDigest/localSigning.signableDigest"
  );
  assertEqual(
    normalizeHex32(request.userOpHash, "request.userOpHash"),
    validatedLocalSigning.userOpHash,
    "request.userOpHash/localSigning.userOpHash"
  );
  assertEqual(
    normalizeHex32(request.signatureRequestId, "request.signatureRequestId"),
    validatedLocalSigning.signatureRequestId,
    "request.signatureRequestId/localSigning.signatureRequestId"
  );
  assertEqual(
    normalizeAddress(appRequest.recipient, "appRequest.recipient").toLowerCase(),
    validatedLocalSigning.recipient.toLowerCase(),
    "appRequest.recipient/localSigning.recipient"
  );
  assertEqual(
    normalizeAddress(appRequest.sender, "appRequest.sender").toLowerCase(),
    validatedLocalSigning.sender.toLowerCase(),
    "appRequest.sender/localSigning.sender"
  );
  assertEqual(
    normalizeAddress(appRequest.entryPointAddress, "appRequest.entryPointAddress").toLowerCase(),
    validatedLocalSigning.entryPointAddress.toLowerCase(),
    "appRequest.entryPointAddress/localSigning.entryPointAddress"
  );

  return {
    sourcePath: smartAccountDeploySignatureRequest.path,
    proofType: smartAccountDeploySignatureRequest.proofType,
    payloadShape: smartAccountDeploySignatureRequest.payloadShape
  };
}

function buildLocalDeviceSignedAttemptRunner({
  smartAccountDeploySignatureRequest,
  validatedLocalSigning
}) {
  const smartAccountDeploySignedUserOp = buildSmartAccountDeploySignedUserOp({
    smartAccountDeploySignatureRequest,
    externalSignature: validatedLocalSigning.localSignature
  });
  assertEqual(
    smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.externalSignature,
    validatedLocalSigning.localSignature,
    "smartAccountDeploySignedUserOp.externalSignature/localSignature"
  );
  assertEqual(
    smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOperation.signature,
    validatedLocalSigning.localSignature,
    "smartAccountDeploySignedUserOp.signedUserOperation.signature/localSignature"
  );
  assertEqual(
    smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId,
    validatedLocalSigning.signedUserOpId,
    "smartAccountDeploySignedUserOp.signedUserOpId/localSigning.signedUserOpId"
  );
  assertEqual(
    smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedBundlerRequestHash,
    validatedLocalSigning.signedBundlerRequestHash,
    "smartAccountDeploySignedUserOp.signedBundlerRequestHash/localSigning.signedBundlerRequestHash"
  );

  const smartAccountDeployBundlerSubmission =
    buildSmartAccountDeployBundlerSubmission({
      smartAccountDeploySignedUserOp
    });
  const smartAccountDeployEndpointSubmission =
    buildSmartAccountDeployEndpointSubmission({
      smartAccountDeployBundlerSubmission
    });
  const smartAccountDeployClientSession = buildSmartAccountDeployClientSession({
    smartAccountDeployEndpointSubmission
  });
  const smartAccountDeployDispatchIntent =
    buildSmartAccountDeployDispatchIntent({
      smartAccountDeployClientSession
    });
  const smartAccountDeployDispatchCommand =
    buildSmartAccountDeployDispatchCommand({
      smartAccountDeployDispatchIntent
    });
  const smartAccountDeployDispatchAttempt =
    buildSmartAccountDeployDispatchAttempt({
      smartAccountDeployDispatchCommand
    });
  const smartAccountDeployAttemptRunner = runSmartAccountDeployAttemptRunner({
    smartAccountDeployDispatchAttempt
  });

  assertEqual(
    smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.request.body.params[0]
      .signature,
    validatedLocalSigning.localSignature,
    "attemptRunner.request.signature/localSignature"
  );

  return {
    smartAccountDeploySignedUserOp,
    smartAccountDeployBundlerSubmission,
    smartAccountDeployEndpointSubmission,
    smartAccountDeployClientSession,
    smartAccountDeployDispatchIntent,
    smartAccountDeployDispatchCommand,
    smartAccountDeployDispatchAttempt,
    smartAccountDeployAttemptRunner
  };
}

function loadStubRequestSignature(stubRequestPath) {
  const stubRequest = loadJson(stubRequestPath);
  const parsedJson = stubRequest.request && stubRequest.request.parsedJson;
  if (!parsedJson || typeof parsedJson !== "object") {
    throw new Error("stub request parsedJson is required");
  }
  if (!Array.isArray(parsedJson.params) || parsedJson.params.length !== 2) {
    throw new Error("stub request params must contain [userOp, entryPoint]");
  }
  return {
    stubRequest,
    requestSignature: normalizeSignature(
      parsedJson.params[0].signature,
      "stubRequest.params[0].signature"
    ),
    requestBodyHash: normalizeHex32(
      stubRequest.request.rawBodyHash,
      "stubRequest.request.rawBodyHash"
    )
  };
}

function assertLocalDeviceSignedMatrixSession({
  localDeploySessionResult,
  validatedLocalSigning
}) {
  assertEqual(
    localDeploySessionResult.path,
    "phil-local-smart-account-deploy-session",
    "matrix.localDeploySessionResult.path"
  );
  assertEqual(
    localDeploySessionResult.localDeploySessionSummary.delegatedPath,
    "matrix",
    "matrix.localDeploySessionSummary.delegatedPath"
  );
  assertEqual(
    localDeploySessionResult.localDeploySessionSummary.sessionMode,
    "matrix",
    "matrix.localDeploySessionSummary.sessionMode"
  );
  assertEqual(
    localDeploySessionResult.localDeploySessionSummary.sessionClassification,
    "local-deploy-session-matrix-complete",
    "matrix.localDeploySessionSummary.sessionClassification"
  );

  const delegatedArtifact = localDeploySessionResult.localDeploySession.delegatedArtifact;
  if (!delegatedArtifact || typeof delegatedArtifact !== "object") {
    throw new Error("matrix delegatedArtifact is required");
  }
  assertEqual(
    delegatedArtifact.path,
    "phil-local-smart-account-deploy-submission-drill-matrix",
    "matrix.delegatedArtifact.path"
  );
  assertEqual(
    delegatedArtifact.localSubmissionDrillMatrixSummary.scenarioCount,
    LOCAL_DEVICE_SIGNING_SESSION_MATRIX_EXPECTED_SCENARIOS.length,
    "matrix.scenarioCount"
  );

  const scenarios = delegatedArtifact.localSubmissionDrillMatrix.scenarios;
  if (!Array.isArray(scenarios)) {
    throw new Error("matrix scenarios are required");
  }

  const scenarioProofs = [];
  for (let i = 0; i < LOCAL_DEVICE_SIGNING_SESSION_MATRIX_EXPECTED_SCENARIOS.length; i += 1) {
    const expected = LOCAL_DEVICE_SIGNING_SESSION_MATRIX_EXPECTED_SCENARIOS[i];
    const scenario = scenarios[i];
    if (!scenario || typeof scenario !== "object") {
      throw new Error(`matrix scenario ${expected.scenarioName} is required`);
    }
    assertEqual(
      scenario.scenarioName,
      expected.scenarioName,
      `${expected.scenarioName}.scenarioName`
    );
    assertEqual(scenario.mode, expected.mode, `${expected.scenarioName}.mode`);
    assertEqual(
      scenario.classification,
      expected.classification,
      `${expected.scenarioName}.classification`
    );
    const drillResultPath = normalizeString(
      scenario.drillResultPath,
      `${expected.scenarioName}.drillResultPath`
    );
    const drillArtifact = loadJson(drillResultPath);
    if (
      !drillArtifact.localSubmissionDrill ||
      typeof drillArtifact.localSubmissionDrill !== "object" ||
      !drillArtifact.localSubmissionDrill.drillRecord ||
      typeof drillArtifact.localSubmissionDrill.drillRecord !== "object"
    ) {
      throw new Error(`${expected.scenarioName}.drillRecord is required`);
    }
    const internalArtifacts = {
      stubRequestArtifactPath:
        drillArtifact.localSubmissionDrill.drillRecord.stubRequestArtifactPath,
      stubResponseArtifactPath:
        drillArtifact.localSubmissionDrill.drillRecord.stubResponseArtifactPath,
      liveRunnerResultPath:
        drillArtifact.localSubmissionDrill.drillRecord.liveRunnerResultPath
    };
    const stubRequestPath = normalizeString(
      internalArtifacts.stubRequestArtifactPath,
      `${expected.scenarioName}.stubRequestArtifactPath`
    );
    const { requestSignature, requestBodyHash } =
      loadStubRequestSignature(stubRequestPath);
    assertEqual(
      requestSignature,
      validatedLocalSigning.localSignature,
      `${expected.scenarioName}.stubRequest.signature/localSignature`
    );

    scenarioProofs.push({
      scenarioName: scenario.scenarioName,
      mode: scenario.mode,
      classification: scenario.classification,
      responseCaptured: scenario.responseCaptured,
      localHttpExchangeOccurred: scenario.localHttpExchangeOccurred,
      drillResultPath,
      stubRequestPath,
      stubResponsePath: internalArtifacts.stubResponseArtifactPath,
      liveRunnerResultPath: internalArtifacts.liveRunnerResultPath,
      stubRequestSignature: requestSignature,
      requestBodyHash
    });
  }

  return {
    delegatedArtifact,
    scenarioProofs
  };
}

async function runLocalDeviceSigningSessionIntegration({
  localDeviceSigningResult,
  smartAccountDeploySignatureRequest,
  mode = LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  outDir = LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT_DIR,
  timeoutMs = LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_TIMEOUT_MS,
  now = () => new Date().toISOString()
}) {
  const selectedMode = normalizeMode(mode);
  const expectedClassification =
    LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODE_CLASSIFICATIONS[selectedMode];
  const modeMetadata =
    LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODE_METADATA[selectedMode];
  const validatedLocalSigning =
    validateLocalDeviceSigningResult(localDeviceSigningResult);
  const validatedSignatureRequest = validateSignatureRequestForLocalSigning({
    smartAccountDeploySignatureRequest,
    validatedLocalSigning
  });
  const derived = buildLocalDeviceSignedAttemptRunner({
    smartAccountDeploySignatureRequest,
    validatedLocalSigning
  });

  const normalizedOutDir = path.resolve(normalizeString(outDir, "outDir"));
  const normalizedTimeoutMs = normalizePositiveInteger(timeoutMs, "timeoutMs");
  const sessionOutDir = path.join(normalizedOutDir, `${selectedMode}_session`);
  const localDeploySessionResult = await runLocalSmartAccountDeploySession({
    smartAccountDeployAttemptRunner: derived.smartAccountDeployAttemptRunner,
    mode: selectedMode,
    outDir: sessionOutDir,
    timeoutMs: normalizedTimeoutMs,
    now
  });

  assertEqual(
    localDeploySessionResult.localDeploySessionSummary.sessionMode,
    selectedMode,
    "localDeploySessionSummary.sessionMode"
  );
  assertEqual(
    localDeploySessionResult.localDeploySessionSummary.sessionClassification,
    expectedClassification,
    "localDeploySessionSummary.sessionClassification"
  );

  const stubRequestPath = path.join(sessionOutDir, "selected_run", "stub_request.json");
  const liveRunnerResultPath = path.join(
    sessionOutDir,
    "selected_run",
    "live_runner_result.json"
  );
  const { requestSignature, requestBodyHash } = loadStubRequestSignature(
    stubRequestPath
  );
  assertEqual(
    requestSignature,
    validatedLocalSigning.localSignature,
    `${selectedMode}-session.stubRequest.signature/localSignature`
  );

  const {
    sessionAliasKey,
    validationChecks: modeValidationChecks,
    integrationPath,
    integrationStatus,
    integrationReason
  } = modeMetadata;

  const integrationRecord = {
    integrationKind: LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_KIND,
    localDeviceSigningId: validatedLocalSigning.localDeviceSigningId,
    signerAddress: validatedLocalSigning.signerAddress,
    signatureRequestId: validatedLocalSigning.signatureRequestId,
    signableDigest: validatedLocalSigning.signableDigest,
    localSignatureHash: validatedLocalSigning.localSignatureHash,
    signedUserOpId: derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId,
    signedBundlerRequestHash:
      derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash,
    attemptRunnerId:
      derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .runnerId,
    localDeploySessionId:
      localDeploySessionResult.localDeploySession.sessionId,
    sessionMode: selectedMode,
    sessionClassification:
      localDeploySessionResult.localDeploySessionSummary.sessionClassification,
    requestBodyHash,
    stubRequestPath,
    liveRunnerResultPath,
    executedAt: now(),
    localOnly: true,
    externalBundlerCallPerformed: false
  };
  const integrationRecordJson = JSON.stringify(integrationRecord);
  const integrationRecordHash = ethers.keccak256(
    ethers.toUtf8Bytes(integrationRecordJson)
  );
  const integrationId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DOMAIN_HASH, integrationRecordHash]
    )
  );

  return {
    version: 1,
    path: integrationPath,
    localDeviceSigningSessionIntegrationSource:
      "scripts/base/run-local-device-signing-session-integration.cjs",
    localDeviceSigningSource:
      localDeviceSigningResult.localDeviceSigningSource,
    smartAccountDeploySignedUserOpSource:
      "scripts/base/build-smart-account-deploy-signed-userop.cjs",
    localDeploySessionSource:
      "scripts/base/run-local-smart-account-deploy-session.cjs",
    consumedPath: localDeviceSigningResult.path,
    proofType: localDeviceSigningResult.proofType,
    payloadShape: localDeviceSigningResult.payloadShape,
    localDeviceSigningSessionIntegrationDomain: {
      label: LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DOMAIN_LABEL,
      hash: LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DOMAIN_HASH
    },
    validationChecks: {
      localDeviceSigningPathValid: true,
      proofTypeValid: true,
      payloadShapeValid: true,
      localDeviceSigningSourceConsumed: true,
      realLocalSignatureConsumed: true,
      signatureRequestSourceMatched: true,
      existingSignedUserOpPathReused: true,
      downstreamNoSendAttemptRunnerBuilt: true,
      existingLocalDeploySessionPathReused: true,
      ...modeValidationChecks,
      canonicalRecipientPreserved: true,
      exactTwoFeltFactShapePreserved: true,
      lockedBaseTupleSemanticsUnchanged: true,
      localOnlyNoExternalBundlerCall: true
    },
    localDeviceSigningSessionIntegrationSummary: {
      ready: true,
      status: integrationStatus,
      reason: integrationReason,
      localOnly: true,
      sessionMode: selectedMode,
      sessionClassification:
        localDeploySessionResult.localDeploySessionSummary.sessionClassification,
      realLocalSignatureUsed: true,
      signedUserOpPathReused: true,
      localDeploySessionPathReused: true,
      signerAddress: validatedLocalSigning.signerAddress,
      signatureRequestId: validatedLocalSigning.signatureRequestId,
      signedUserOpId:
        derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
          .signedUserOpId,
      attemptRunnerId:
        derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
          .runnerId,
      localDeploySessionId:
        localDeploySessionResult.localDeploySession.sessionId,
      parityProven: true
    },
    localDeviceSigningSessionIntegration: {
      integrationKind: LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_KIND,
      integrationId,
      integrationRecord,
      integrationRecordJson,
      integrationRecordHash,
      sourceChecks: {
        signatureRequestSourcePath: validatedSignatureRequest.sourcePath,
        proofType: validatedSignatureRequest.proofType,
        payloadShape: validatedSignatureRequest.payloadShape
      },
      localSigning: {
        localDeviceSigningId: validatedLocalSigning.localDeviceSigningId,
        signerAddress: validatedLocalSigning.signerAddress,
        signableDigest: validatedLocalSigning.signableDigest,
        localSignature: validatedLocalSigning.localSignature,
        localSignatureHash: validatedLocalSigning.localSignatureHash
      },
      signedUserOp: {
        signedUserOpId:
          derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
            .signedUserOpId,
        signedBundlerRequestHash:
          derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
            .signedBundlerRequestHash,
        signature:
          derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
            .signedUserOperation.signature
      },
      attemptRunner: {
        path: derived.smartAccountDeployAttemptRunner.path,
        runnerId:
          derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .runnerId,
        requestHash:
          derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .requestHash,
        requestSignature:
          derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .request.body.params[0].signature
      },
      [sessionAliasKey]: {
        path: localDeploySessionResult.path,
        sessionId: localDeploySessionResult.localDeploySession.sessionId,
        sessionMode:
          localDeploySessionResult.localDeploySessionSummary.sessionMode,
        sessionClassification:
          localDeploySessionResult.localDeploySessionSummary.sessionClassification,
        stubRequestPath,
        liveRunnerResultPath,
        stubRequestSignature: requestSignature,
        requestBodyHash
      }
    },
    appLocalDeviceSigningSessionIntegration: {
      recipient: validatedLocalSigning.recipient,
      sender: validatedLocalSigning.sender,
      entryPointAddress: validatedLocalSigning.entryPointAddress,
      chainId: validatedLocalSigning.chainId,
      userOpHash: validatedLocalSigning.userOpHash,
      signerAddress: validatedLocalSigning.signerAddress,
      signedUserOpId:
        derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
          .signedUserOpId,
      sessionMode: selectedMode,
      sessionClassification:
        localDeploySessionResult.localDeploySessionSummary.sessionClassification,
      ready: true,
      status: integrationStatus,
      localOnly: true,
      parityProven: true
    }
  };
}

async function runLocalDeviceSigningSessionMatrixIntegration({
  localDeviceSigningResult,
  smartAccountDeploySignatureRequest,
  outDir = LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT_DIR,
  timeoutMs = LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_TIMEOUT_MS,
  now = () => new Date().toISOString()
}) {
  const validatedLocalSigning =
    validateLocalDeviceSigningResult(localDeviceSigningResult);
  const validatedSignatureRequest = validateSignatureRequestForLocalSigning({
    smartAccountDeploySignatureRequest,
    validatedLocalSigning
  });
  const derived = buildLocalDeviceSignedAttemptRunner({
    smartAccountDeploySignatureRequest,
    validatedLocalSigning
  });

  const normalizedOutDir = path.resolve(normalizeString(outDir, "outDir"));
  const normalizedTimeoutMs = normalizePositiveInteger(timeoutMs, "timeoutMs");
  const sessionOutDir = path.join(normalizedOutDir, "matrix_session");
  const localDeploySessionResult = await runLocalSmartAccountDeploySession({
    smartAccountDeployAttemptRunner: derived.smartAccountDeployAttemptRunner,
    matrix: true,
    outDir: sessionOutDir,
    timeoutMs: normalizedTimeoutMs,
    now
  });
  const { delegatedArtifact, scenarioProofs } =
    assertLocalDeviceSignedMatrixSession({
      localDeploySessionResult,
      validatedLocalSigning
    });

  const integrationRecord = {
    integrationKind: LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_KIND,
    localDeviceSigningId: validatedLocalSigning.localDeviceSigningId,
    signerAddress: validatedLocalSigning.signerAddress,
    signatureRequestId: validatedLocalSigning.signatureRequestId,
    signableDigest: validatedLocalSigning.signableDigest,
    localSignatureHash: validatedLocalSigning.localSignatureHash,
    signedUserOpId:
      derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedUserOpId,
    signedBundlerRequestHash:
      derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash,
    attemptRunnerId:
      derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .runnerId,
    localDeploySessionId:
      localDeploySessionResult.localDeploySession.sessionId,
    matrixId: delegatedArtifact.localSubmissionDrillMatrix.matrixId,
    matrixHash: delegatedArtifact.localSubmissionDrillMatrix.matrixHash,
    sessionMode: "matrix",
    sessionClassification:
      localDeploySessionResult.localDeploySessionSummary.sessionClassification,
    acceptedClassification: scenarioProofs[0].classification,
    rejectedClassification: scenarioProofs[1].classification,
    transportClassification: scenarioProofs[2].classification,
    scenarioCount: scenarioProofs.length,
    scenarioRequestBodyHashes: scenarioProofs.map((scenario) => ({
      scenarioName: scenario.scenarioName,
      requestBodyHash: scenario.requestBodyHash
    })),
    executedAt: now(),
    localOnly: true,
    externalBundlerCallPerformed: false
  };
  const integrationRecordJson = JSON.stringify(integrationRecord);
  const integrationRecordHash = ethers.keccak256(
    ethers.toUtf8Bytes(integrationRecordJson)
  );
  const integrationId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [
        LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DOMAIN_HASH,
        integrationRecordHash
      ]
    )
  );

  return {
    version: 1,
    path: "phil-local-device-signing-session-matrix-integration",
    localDeviceSigningSessionMatrixIntegrationSource:
      "scripts/base/run-local-device-signing-session-integration.cjs",
    localDeviceSigningSource:
      localDeviceSigningResult.localDeviceSigningSource,
    smartAccountDeploySignedUserOpSource:
      "scripts/base/build-smart-account-deploy-signed-userop.cjs",
    localDeploySessionSource:
      "scripts/base/run-local-smart-account-deploy-session.cjs",
    localDeploySessionMatrixSource:
      "scripts/base/run-local-smart-account-deploy-drill-matrix.cjs",
    consumedPath: localDeviceSigningResult.path,
    proofType: localDeviceSigningResult.proofType,
    payloadShape: localDeviceSigningResult.payloadShape,
    localDeviceSigningSessionMatrixIntegrationDomain: {
      label: LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DOMAIN_LABEL,
      hash: LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DOMAIN_HASH
    },
    validationChecks: {
      localDeviceSigningPathValid: true,
      proofTypeValid: true,
      payloadShapeValid: true,
      localDeviceSigningSourceConsumed: true,
      realLocalSignatureConsumed: true,
      signatureRequestSourceMatched: true,
      existingSignedUserOpPathReused: true,
      downstreamNoSendAttemptRunnerBuilt: true,
      existingLocalDeploySessionMatrixPathReused: true,
      acceptedModeLocalSessionRan: true,
      acceptedModeUsedRealLocalSignature: true,
      rejectedModeLocalSessionRan: true,
      rejectedModeUsedRealLocalSignature: true,
      transportErrorModeLocalSessionRan: true,
      transportErrorModeUsedRealLocalSignature: true,
      acceptedRejectedTransportMatrixRan: true,
      canonicalRecipientPreserved: true,
      exactTwoFeltFactShapePreserved: true,
      lockedBaseTupleSemanticsUnchanged: true,
      localOnlyNoExternalBundlerCall: true
    },
    localDeviceSigningSessionMatrixIntegrationSummary: {
      ready: true,
      status: "local-device-signing-session-matrix-integration-complete",
      reason:
        "local-device-signature-routed-through-accepted-rejected-transport-session-matrix",
      localOnly: true,
      sessionMode: "matrix",
      sessionClassification:
        localDeploySessionResult.localDeploySessionSummary.sessionClassification,
      scenarioCount: scenarioProofs.length,
      acceptedClassification: scenarioProofs[0].classification,
      rejectedClassification: scenarioProofs[1].classification,
      transportClassification: scenarioProofs[2].classification,
      realLocalSignatureUsed: true,
      signedUserOpPathReused: true,
      localDeploySessionMatrixPathReused: true,
      signerAddress: validatedLocalSigning.signerAddress,
      signatureRequestId: validatedLocalSigning.signatureRequestId,
      signedUserOpId:
        derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
          .signedUserOpId,
      attemptRunnerId:
        derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
          .runnerId,
      localDeploySessionId:
        localDeploySessionResult.localDeploySession.sessionId,
      matrixId: delegatedArtifact.localSubmissionDrillMatrix.matrixId,
      parityProven: true
    },
    localDeviceSigningSessionMatrixIntegration: {
      integrationKind: LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_KIND,
      integrationId,
      integrationRecord,
      integrationRecordJson,
      integrationRecordHash,
      sourceChecks: {
        signatureRequestSourcePath: validatedSignatureRequest.sourcePath,
        proofType: validatedSignatureRequest.proofType,
        payloadShape: validatedSignatureRequest.payloadShape
      },
      localSigning: {
        localDeviceSigningId: validatedLocalSigning.localDeviceSigningId,
        signerAddress: validatedLocalSigning.signerAddress,
        signableDigest: validatedLocalSigning.signableDigest,
        localSignature: validatedLocalSigning.localSignature,
        localSignatureHash: validatedLocalSigning.localSignatureHash
      },
      signedUserOp: {
        signedUserOpId:
          derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
            .signedUserOpId,
        signedBundlerRequestHash:
          derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
            .signedBundlerRequestHash,
        signature:
          derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
            .signedUserOperation.signature
      },
      attemptRunner: {
        path: derived.smartAccountDeployAttemptRunner.path,
        runnerId:
          derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .runnerId,
        requestHash:
          derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .requestHash,
        requestSignature:
          derived.smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .request.body.params[0].signature
      },
      matrixLocalSession: {
        path: localDeploySessionResult.path,
        sessionId: localDeploySessionResult.localDeploySession.sessionId,
        sessionMode:
          localDeploySessionResult.localDeploySessionSummary.sessionMode,
        sessionClassification:
          localDeploySessionResult.localDeploySessionSummary.sessionClassification,
        matrixId: delegatedArtifact.localSubmissionDrillMatrix.matrixId,
        matrixHash: delegatedArtifact.localSubmissionDrillMatrix.matrixHash,
        scenarioCount: scenarioProofs.length,
        scenarios: scenarioProofs
      }
    },
    appLocalDeviceSigningSessionMatrixIntegration: {
      recipient: validatedLocalSigning.recipient,
      sender: validatedLocalSigning.sender,
      entryPointAddress: validatedLocalSigning.entryPointAddress,
      chainId: validatedLocalSigning.chainId,
      userOpHash: validatedLocalSigning.userOpHash,
      signerAddress: validatedLocalSigning.signerAddress,
      signedUserOpId:
        derived.smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
          .signedUserOpId,
      sessionMode: "matrix",
      sessionClassification:
        localDeploySessionResult.localDeploySessionSummary.sessionClassification,
      acceptedClassification: scenarioProofs[0].classification,
      rejectedClassification: scenarioProofs[1].classification,
      transportClassification: scenarioProofs[2].classification,
      ready: true,
      status: "local-device-signing-session-matrix-integration-complete",
      localOnly: true,
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--local-device-signing") {
      parsed.localDeviceSigningPath = argv[i + 1];
      i += 1;
    } else if (arg === "--smart-account-deploy-signature-request") {
      parsed.smartAccountDeploySignatureRequestPath = argv[i + 1];
      i += 1;
    } else if (arg === "--mode") {
      parsed.mode = argv[i + 1];
      i += 1;
    } else if (arg === "--matrix") {
      parsed.matrix = true;
    } else if (arg === "--out-dir") {
      parsed.outDir = argv[i + 1];
      i += 1;
    } else if (arg === "--timeout-ms") {
      parsed.timeoutMs = argv[i + 1];
      i += 1;
    } else if (arg === "--out") {
      parsed.out = argv[i + 1];
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
      "  node scripts/base/run-local-device-signing-session-integration.cjs \\",
      `    [--local-device-signing ${LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_LOCAL_SIGNING}] \\`,
      `    [--smart-account-deploy-signature-request ${LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_SIGNATURE_REQUEST}] \\`,
      `    [--mode ${LOCAL_BUNDLER_STUB_MODE_ACCEPTED}|${LOCAL_BUNDLER_STUB_MODE_REJECTED}|${LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR}] | [--matrix] \\`,
      `    [--out-dir ${LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT_DIR}] \\`,
      `    [--timeout-ms ${LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_TIMEOUT_MS}] \\`,
      `    [--out ${LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT}]`
    ].join("\n")
  );
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.help) {
    printUsage();
    return 0;
  }

  const outDir =
    parsed.outDir || LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT_DIR;
  if (parsed.matrix === true && parsed.mode) {
    throw new Error("Choose either --mode or --matrix, not both");
  }
  const outPath = path.resolve(
    parsed.out ||
      (parsed.matrix === true
        ? LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DEFAULT_OUT
        : LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT)
  );
  const localDeviceSigningResult = loadJson(
    path.resolve(
      parsed.localDeviceSigningPath ||
        LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_LOCAL_SIGNING
    )
  );
  const smartAccountDeploySignatureRequest = loadJson(
    path.resolve(
      parsed.smartAccountDeploySignatureRequestPath ||
        LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_SIGNATURE_REQUEST
    )
  );
  const artifact = parsed.matrix === true
    ? await runLocalDeviceSigningSessionMatrixIntegration({
        localDeviceSigningResult,
        smartAccountDeploySignatureRequest,
        outDir,
        timeoutMs:
          parsed.timeoutMs ||
          LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_TIMEOUT_MS
      })
    : await runLocalDeviceSigningSessionIntegration({
        localDeviceSigningResult,
        smartAccountDeploySignatureRequest,
        mode: parsed.mode || LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
        outDir,
        timeoutMs:
          parsed.timeoutMs ||
          LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_TIMEOUT_MS
      });

  writeJson(outPath, artifact);
  console.log(JSON.stringify(artifact, null, 2));
  return 0;
}

if (require.main === module) {
  main()
    .then((code) => {
      process.exit(code);
    })
    .catch((error) => {
      console.error(String(error && error.message ? error.message : error));
      process.exit(1);
    });
}

module.exports = {
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DOMAIN_LABEL,
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DOMAIN_HASH,
  LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DOMAIN_LABEL,
  LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DOMAIN_HASH,
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_KIND,
  LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_KIND,
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_LOCAL_SIGNING,
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_SIGNATURE_REQUEST,
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT_DIR,
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_DEFAULT_OUT,
  LOCAL_DEVICE_SIGNING_SESSION_MATRIX_INTEGRATION_DEFAULT_OUT,
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODES,
  LOCAL_DEVICE_SIGNING_SESSION_INTEGRATION_MODE_CLASSIFICATIONS,
  runLocalDeviceSigningSessionIntegration,
  runLocalDeviceSigningSessionMatrixIntegration
};
