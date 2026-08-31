const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  runLocalDeviceSigningSessionIntegration,
  runLocalDeviceSigningSessionMatrixIntegration
} = require("../../scripts/base/run-local-device-signing-session-integration.cjs");

const LOCAL_DEVICE_SIGNING_RESULT_PATH = path.resolve(
  __dirname,
  "../../proving/out/local_device_signing/local_device_signing_result.json"
);
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH = path.resolve(
  __dirname,
  "../../proving/out/smart_account_deploy_signature_request/smart_account_deploy_signature_request.json"
);
const TEST_OUT_DIR = path.resolve(
  __dirname,
  "../../proving/out/local_device_signing_session_integration/test_session"
);
const REJECTED_TEST_OUT_DIR = path.resolve(
  __dirname,
  "../../proving/out/local_device_signing_session_integration/test_rejected_session"
);
const TRANSPORT_TEST_OUT_DIR = path.resolve(
  __dirname,
  "../../proving/out/local_device_signing_session_integration/test_transport_session"
);
const MATRIX_TEST_OUT_DIR = path.resolve(
  __dirname,
  "../../proving/out/local_device_signing_session_integration/test_matrix_session"
);
const LEGACY_DUMMY_EXTERNAL_SIGNATURE =
  "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111b";

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

describe("local device signing to deploy-session integration", function () {
  it("runs accepted local session with the real locally produced signature", async function () {
    const localDeviceSigningResult = loadJson(LOCAL_DEVICE_SIGNING_RESULT_PATH);
    const smartAccountDeploySignatureRequest = loadJson(
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH
    );
    const localSignature =
      localDeviceSigningResult.localDeviceSigning.localSignature;

    const result = await runLocalDeviceSigningSessionIntegration({
      localDeviceSigningResult,
      smartAccountDeploySignatureRequest,
      outDir: TEST_OUT_DIR,
      timeoutMs: 15000,
      now: () => "2026-04-24T00:00:00.000Z"
    });

    assert.equal(result.path, "phil-local-device-signing-session-integration");
    assert.equal(result.consumedPath, "phil-local-smart-account-deploy-device-signing");
    assert.equal(result.proofType, "stwo-unlock-keccak-v1");
    assert.equal(result.payloadShape, "[fact_high, fact_low]");
    assert.equal(result.validationChecks.localDeviceSigningSourceConsumed, true);
    assert.equal(result.validationChecks.realLocalSignatureConsumed, true);
    assert.equal(result.validationChecks.existingSignedUserOpPathReused, true);
    assert.equal(result.validationChecks.existingLocalDeploySessionPathReused, true);
    assert.equal(result.validationChecks.acceptedModeLocalSessionRan, true);
    assert.equal(result.validationChecks.acceptedModeUsedRealLocalSignature, true);
    assert.equal(result.validationChecks.exactTwoFeltFactShapePreserved, true);
    assert.equal(result.validationChecks.lockedBaseTupleSemanticsUnchanged, true);
    assert.equal(result.localDeviceSigningSessionIntegrationSummary.sessionMode, "accepted");
    assert.equal(
      result.localDeviceSigningSessionIntegrationSummary.sessionClassification,
      "accepted-json-rpc-response"
    );
    assert.match(localSignature, /^0x[0-9a-f]{130}$/);
    assert.notEqual(localSignature, LEGACY_DUMMY_EXTERNAL_SIGNATURE);
    assert.equal(
      result.localDeviceSigningSessionIntegration.signedUserOp.signature,
      localSignature
    );
    assert.equal(
      result.localDeviceSigningSessionIntegration.attemptRunner.requestSignature,
      localSignature
    );
    assert.equal(
      result.localDeviceSigningSessionIntegration.acceptedLocalSession
        .stubRequestSignature,
      localSignature
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.recipient,
      localDeviceSigningResult.appLocalDeviceSigning.recipient
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.sender,
      localDeviceSigningResult.appLocalDeviceSigning.sender
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.userOpHash,
      localDeviceSigningResult.appLocalDeviceSigning.userOpHash
    );
  });

  it("runs rejected local session with the real locally produced signature", async function () {
    const localDeviceSigningResult = loadJson(LOCAL_DEVICE_SIGNING_RESULT_PATH);
    const smartAccountDeploySignatureRequest = loadJson(
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH
    );
    const localSignature =
      localDeviceSigningResult.localDeviceSigning.localSignature;

    const result = await runLocalDeviceSigningSessionIntegration({
      localDeviceSigningResult,
      smartAccountDeploySignatureRequest,
      mode: "rejected",
      outDir: REJECTED_TEST_OUT_DIR,
      timeoutMs: 15000,
      now: () => "2026-04-24T00:00:00.000Z"
    });

    assert.equal(result.path, "phil-local-device-signing-rejected-session-integration");
    assert.equal(result.consumedPath, "phil-local-smart-account-deploy-device-signing");
    assert.equal(result.proofType, "stwo-unlock-keccak-v1");
    assert.equal(result.payloadShape, "[fact_high, fact_low]");
    assert.equal(result.validationChecks.localDeviceSigningSourceConsumed, true);
    assert.equal(result.validationChecks.realLocalSignatureConsumed, true);
    assert.equal(result.validationChecks.existingSignedUserOpPathReused, true);
    assert.equal(result.validationChecks.existingLocalDeploySessionPathReused, true);
    assert.equal(result.validationChecks.rejectedModeLocalSessionRan, true);
    assert.equal(result.validationChecks.rejectedModeUsedRealLocalSignature, true);
    assert.equal(result.validationChecks.exactTwoFeltFactShapePreserved, true);
    assert.equal(result.validationChecks.lockedBaseTupleSemanticsUnchanged, true);
    assert.equal(
      result.localDeviceSigningSessionIntegrationSummary.sessionMode,
      "rejected"
    );
    assert.equal(
      result.localDeviceSigningSessionIntegrationSummary.sessionClassification,
      "rejected-json-rpc-response"
    );
    assert.match(localSignature, /^0x[0-9a-f]{130}$/);
    assert.notEqual(localSignature, LEGACY_DUMMY_EXTERNAL_SIGNATURE);
    assert.equal(
      result.localDeviceSigningSessionIntegration.signedUserOp.signature,
      localSignature
    );
    assert.equal(
      result.localDeviceSigningSessionIntegration.attemptRunner.requestSignature,
      localSignature
    );
    assert.equal(
      result.localDeviceSigningSessionIntegration.rejectedLocalSession
        .stubRequestSignature,
      localSignature
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.sessionMode,
      "rejected"
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.sessionClassification,
      "rejected-json-rpc-response"
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.recipient,
      localDeviceSigningResult.appLocalDeviceSigning.recipient
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.sender,
      localDeviceSigningResult.appLocalDeviceSigning.sender
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.userOpHash,
      localDeviceSigningResult.appLocalDeviceSigning.userOpHash
    );
  });

  it("runs transport-error local session with the real locally produced signature", async function () {
    const localDeviceSigningResult = loadJson(LOCAL_DEVICE_SIGNING_RESULT_PATH);
    const smartAccountDeploySignatureRequest = loadJson(
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH
    );
    const localSignature =
      localDeviceSigningResult.localDeviceSigning.localSignature;

    const result = await runLocalDeviceSigningSessionIntegration({
      localDeviceSigningResult,
      smartAccountDeploySignatureRequest,
      mode: "transport-error",
      outDir: TRANSPORT_TEST_OUT_DIR,
      timeoutMs: 15000,
      now: () => "2026-04-24T00:00:00.000Z"
    });

    assert.equal(result.path, "phil-local-device-signing-transport-session-integration");
    assert.equal(result.consumedPath, "phil-local-smart-account-deploy-device-signing");
    assert.equal(result.proofType, "stwo-unlock-keccak-v1");
    assert.equal(result.payloadShape, "[fact_high, fact_low]");
    assert.equal(result.validationChecks.localDeviceSigningSourceConsumed, true);
    assert.equal(result.validationChecks.realLocalSignatureConsumed, true);
    assert.equal(result.validationChecks.existingSignedUserOpPathReused, true);
    assert.equal(result.validationChecks.existingLocalDeploySessionPathReused, true);
    assert.equal(result.validationChecks.transportErrorModeLocalSessionRan, true);
    assert.equal(result.validationChecks.transportErrorModeUsedRealLocalSignature, true);
    assert.equal(result.validationChecks.exactTwoFeltFactShapePreserved, true);
    assert.equal(result.validationChecks.lockedBaseTupleSemanticsUnchanged, true);
    assert.equal(
      result.localDeviceSigningSessionIntegrationSummary.sessionMode,
      "transport-error"
    );
    assert.equal(
      result.localDeviceSigningSessionIntegrationSummary.sessionClassification,
      "transport-error-response"
    );
    assert.match(localSignature, /^0x[0-9a-f]{130}$/);
    assert.notEqual(localSignature, LEGACY_DUMMY_EXTERNAL_SIGNATURE);
    assert.equal(
      result.localDeviceSigningSessionIntegration.signedUserOp.signature,
      localSignature
    );
    assert.equal(
      result.localDeviceSigningSessionIntegration.attemptRunner.requestSignature,
      localSignature
    );
    assert.equal(
      result.localDeviceSigningSessionIntegration.transportErrorLocalSession
        .stubRequestSignature,
      localSignature
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.sessionMode,
      "transport-error"
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.sessionClassification,
      "transport-error-response"
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.recipient,
      localDeviceSigningResult.appLocalDeviceSigning.recipient
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.sender,
      localDeviceSigningResult.appLocalDeviceSigning.sender
    );
    assert.equal(
      result.appLocalDeviceSigningSessionIntegration.userOpHash,
      localDeviceSigningResult.appLocalDeviceSigning.userOpHash
    );
  });

  it("runs the local session matrix with the real locally produced signature", async function () {
    const localDeviceSigningResult = loadJson(LOCAL_DEVICE_SIGNING_RESULT_PATH);
    const smartAccountDeploySignatureRequest = loadJson(
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH
    );
    const localSignature =
      localDeviceSigningResult.localDeviceSigning.localSignature;

    const result = await runLocalDeviceSigningSessionMatrixIntegration({
      localDeviceSigningResult,
      smartAccountDeploySignatureRequest,
      outDir: MATRIX_TEST_OUT_DIR,
      timeoutMs: 15000,
      now: () => "2026-04-24T00:00:00.000Z"
    });

    assert.equal(result.path, "phil-local-device-signing-session-matrix-integration");
    assert.equal(result.consumedPath, "phil-local-smart-account-deploy-device-signing");
    assert.equal(result.proofType, "stwo-unlock-keccak-v1");
    assert.equal(result.payloadShape, "[fact_high, fact_low]");
    assert.equal(result.validationChecks.localDeviceSigningSourceConsumed, true);
    assert.equal(result.validationChecks.realLocalSignatureConsumed, true);
    assert.equal(result.validationChecks.existingSignedUserOpPathReused, true);
    assert.equal(
      result.validationChecks.existingLocalDeploySessionMatrixPathReused,
      true
    );
    assert.equal(result.validationChecks.acceptedModeUsedRealLocalSignature, true);
    assert.equal(result.validationChecks.rejectedModeUsedRealLocalSignature, true);
    assert.equal(
      result.validationChecks.transportErrorModeUsedRealLocalSignature,
      true
    );
    assert.equal(result.validationChecks.acceptedRejectedTransportMatrixRan, true);
    assert.equal(result.validationChecks.exactTwoFeltFactShapePreserved, true);
    assert.equal(result.validationChecks.lockedBaseTupleSemanticsUnchanged, true);
    assert.equal(
      result.localDeviceSigningSessionMatrixIntegrationSummary.sessionMode,
      "matrix"
    );
    assert.equal(
      result.localDeviceSigningSessionMatrixIntegrationSummary.sessionClassification,
      "local-deploy-session-matrix-complete"
    );
    assert.equal(
      result.localDeviceSigningSessionMatrixIntegrationSummary.scenarioCount,
      3
    );
    assert.equal(
      result.localDeviceSigningSessionMatrixIntegrationSummary.acceptedClassification,
      "accepted-json-rpc-response"
    );
    assert.equal(
      result.localDeviceSigningSessionMatrixIntegrationSummary.rejectedClassification,
      "rejected-json-rpc-response"
    );
    assert.equal(
      result.localDeviceSigningSessionMatrixIntegrationSummary.transportClassification,
      "transport-error-response"
    );
    assert.match(localSignature, /^0x[0-9a-f]{130}$/);
    assert.notEqual(localSignature, LEGACY_DUMMY_EXTERNAL_SIGNATURE);
    assert.equal(
      result.localDeviceSigningSessionMatrixIntegration.signedUserOp.signature,
      localSignature
    );
    assert.equal(
      result.localDeviceSigningSessionMatrixIntegration.attemptRunner
        .requestSignature,
      localSignature
    );

    const scenarios =
      result.localDeviceSigningSessionMatrixIntegration.matrixLocalSession.scenarios;
    assert.equal(scenarios.length, 3);
    assert.deepEqual(
      scenarios.map((scenario) => scenario.mode),
      ["accepted", "rejected", "transport-error"]
    );
    assert.deepEqual(
      scenarios.map((scenario) => scenario.classification),
      [
        "accepted-json-rpc-response",
        "rejected-json-rpc-response",
        "transport-error-response"
      ]
    );
    for (const scenario of scenarios) {
      assert.equal(scenario.stubRequestSignature, localSignature);
    }

    assert.equal(
      result.appLocalDeviceSigningSessionMatrixIntegration.sessionMode,
      "matrix"
    );
    assert.equal(
      result.appLocalDeviceSigningSessionMatrixIntegration.sessionClassification,
      "local-deploy-session-matrix-complete"
    );
    assert.equal(
      result.appLocalDeviceSigningSessionMatrixIntegration.recipient,
      localDeviceSigningResult.appLocalDeviceSigning.recipient
    );
    assert.equal(
      result.appLocalDeviceSigningSessionMatrixIntegration.sender,
      localDeviceSigningResult.appLocalDeviceSigning.sender
    );
    assert.equal(
      result.appLocalDeviceSigningSessionMatrixIntegration.userOpHash,
      localDeviceSigningResult.appLocalDeviceSigning.userOpHash
    );
  });
});
