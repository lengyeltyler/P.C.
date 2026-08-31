const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
} = require("../../scripts/base/build-smart-account-deploy-signature-request.cjs");
const {
  LOCAL_DEVICE_SIGNING_KIND,
  LOCAL_DEVICE_SIGNING_SIGNATURE_KIND,
  runLocalSmartAccountDeploySigning
} = require("../../scripts/base/run-local-smart-account-deploy-signing.cjs");

const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH = path.resolve(
  __dirname,
  "../../proving/out/smart_account_deploy_signature_request/smart_account_deploy_signature_request.json"
);
const OLD_EXTERNAL_SIGNATURE_PLACEHOLDER =
  "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111b";

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

describe("local smart-account deploy device signing", function () {
  it("produces a real local signature and reuses the signed-userOp seam", function () {
    const smartAccountDeploySignatureRequest = loadJson(
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH
    );

    const result = runLocalSmartAccountDeploySigning({
      smartAccountDeploySignatureRequest,
      now: () => "2026-04-24T00:00:00.000Z"
    });

    const request =
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest;
    const signature = result.localDeviceSigning.localSignature;

    assert.equal(result.path, "phil-local-smart-account-deploy-device-signing");
    assert.equal(
      result.consumedPath,
      "phil-smart-account-deploy-signature-request"
    );
    assert.equal(result.proofType, "stwo-unlock-keccak-v1");
    assert.equal(result.payloadShape, "[fact_high, fact_low]");
    assert.equal(result.localDeviceSigning.localDeviceSigningKind, LOCAL_DEVICE_SIGNING_KIND);
    assert.equal(
      result.localDeviceSigning.signingRecord.signatureKind,
      LOCAL_DEVICE_SIGNING_SIGNATURE_KIND
    );
    assert.equal(result.validationChecks.signerPayloadConsumed, true);
    assert.equal(result.validationChecks.deviceIdentityProviderResolved, true);
    assert.equal(result.validationChecks.deviceIdentitySignedExpectedDigest, true);
    assert.equal(result.validationChecks.localDevProviderMarkedUnsafeForProduction, true);
    assert.equal(result.validationChecks.realLocalSignatureProduced, true);
    assert.equal(result.validationChecks.signatureRecoverable, true);
    assert.equal(result.validationChecks.existingSignedUserOpPathReused, true);
    assert.equal(result.validationChecks.exactTwoFeltFactShapePreserved, true);
    assert.equal(result.validationChecks.lockedBaseTupleSemanticsUnchanged, true);
    assert.equal(result.validationChecks.localOnlyNoExternalBundlerCall, true);
    assert.equal(result.localDeviceSigningSummary.keySource, "deterministic-local-dev-key");
    assert.equal(result.localDeviceSigningSummary.localOnly, true);
    assert.equal(
      result.localDeviceSigningSummary.deviceIdentityProviderKind,
      "local-dev-deterministic-device-identity-test-only-v1"
    );
    assert.equal(result.localDeviceSigningSummary.deviceIdentityProviderProductionSafe, false);
    assert.equal(result.localDeviceSigning.key.productionSafe, false);
    assert.equal(result.localDeviceSigning.key.privateMaterialExportable, false);
    assert.equal(result.localDeviceSigning.key.hardwareBacked, false);
    assert.equal(
      result.localDeviceSigning.deviceIdentity.authorization.signableDigest,
      request.signableDigest
    );
    assert.equal(
      result.localDeviceSigning.deviceIdentity.authorization.signatureHash,
      result.localDeviceSigning.localSignatureHash
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(
        result.localDeviceSigning.deviceIdentity.publicMetadata.philIdentity,
        "philSecret"
      ),
      false
    );
    assert.match(signature, /^0x[0-9a-f]{130}$/);
    assert.notEqual(signature, SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER);
    assert.notEqual(signature, OLD_EXTERNAL_SIGNATURE_PLACEHOLDER);
    assert.equal(
      ethers.recoverAddress(request.signableDigest, signature),
      result.localDeviceSigning.key.signerAddress
    );
    assert.equal(
      result.localDeviceSigning.recoveredAddress,
      result.localDeviceSigning.key.signerAddress
    );
    assert.equal(
      result.localDeviceSigning.signatureInput.signableDigest,
      request.signableDigest
    );
    assert.equal(
      result.localDeviceSigning.signatureInput.digestEncoding,
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING
    );
    assert.equal(
      result.localDeviceSigning.signatureInput.signatureTarget.bundlerRequestPath,
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH
    );
    assert.equal(result.signedUserOpResult.path, "phil-smart-account-deploy-signed-userop");
    assert.equal(
      result.signedUserOpResult.smartAccountDeploySignedUserOp.externalSignature,
      signature
    );
    assert.equal(
      result.signedUserOpResult.smartAccountDeploySignedUserOp.signedUserOperation
        .signature,
      signature
    );
    assert.equal(
      result.appLocalDeviceSigning.recipient,
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.recipient
    );
    assert.equal(
      result.appLocalDeviceSigning.sender,
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.sender
    );
    assert.equal(
      result.appLocalDeviceSigning.userOpHash,
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.userOpHash
    );
  });
});
