"use strict";

const assert = require("node:assert/strict");
const { ethers } = require("hardhat");
const { p256 } = require("@noble/curves/p256");
require("tsx/cjs");

const mint = require("../../apps/phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const device = require("../../apps/phil-device-sdk/src/deviceApprovalV1.ts");
const requestApi = require("../../apps/phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts");

const privateKey = Buffer.from("71".repeat(32), "hex");
const publicKey = p256.getPublicKey(privateKey, false);

function fixture() {
  const bindings = mint.derivePhilSepoliaMintBindingsV1({
    factory: "0x1000000000000000000000000000000000000001",
    smartAccount: "0x2000000000000000000000000000000000000002",
    actionGate: "0x3000000000000000000000000000000000000003",
    mintConsumer: "0x4000000000000000000000000000000000000004",
    mintRecipient: "0x5000000000000000000000000000000000000005",
    accountNonce: "7",
    validAfter: "1800000000",
    validUntil: "1800000120",
    maximumTotalFeeWei: "2500000000000000"
  });
  const authorization = mint.createPhilSepoliaMintAuthorizationV1({
    scopedOwnerCommitment: ethers.id("scoped-owner"),
    proofDescriptorHash: ethers.id("proof-descriptor"),
    rootProofNullifier: ethers.id("root-nullifier"),
    scopeEpoch: "2",
    deviceEpoch: "3",
    recoveryEpoch: "4",
    validatorEpoch: "5",
    bindings
  });
  const enrollment = device.createPhilDeviceEnrollmentRecordV1({
    deviceId: ethers.id("device"),
    deviceKeyId: ethers.id("device-key"),
    signatureSuiteId: mint.PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
    publicKey,
    deviceEpoch: "3",
    enrolledAt: "1799999000",
    assuranceClass: 3,
    policyHash: authorization.authorizationEnvelope.policyHash
  });
  const request = requestApi.createPhilSepoliaMintDeviceRequestV1({
    sessionId: ethers.id("transport-session"),
    authorization,
    enrollment,
    approvalNonce: ethers.id("approval-nonce"),
    approvedAt: "1800000005",
    approvalExpiresAt: "1800000100"
  });
  return { bindings, authorization, enrollment, request };
}

describe("Phil Sepolia mint physical device request", function () {
  it("binds one independently reproducible review and signs the exact device approval digest", function () {
    const value = fixture();
    assert.equal(value.request.platformSigningDigest, value.request.deviceApprovalDigest);
    assert.equal(value.request.humanPresentation.smartAccount, value.bindings.smartAccount);
    assert.equal(value.request.humanPresentation.mintRecipient, value.bindings.mintRecipient);
    assert.equal(value.request.humanPresentation.contract, value.bindings.mintConsumer);
    assert.match(value.request.humanPresentation.verificationBoundary, /verified locally/u);
    const signature = p256.sign(value.request.deviceApprovalDigest.slice(2), privateKey, {
      lowS: true,
      prehash: false
    });
    const raw = ethers.concat([ethers.toBeHex(signature.r, 32), ethers.toBeHex(signature.s, 32)]);
    const response = requestApi.createPhilSepoliaMintDeviceResponseV1({
      request: value.request,
      enrollment: value.enrollment,
      signature: raw
    });
    assert.equal(response.deviceApprovalDigest, value.request.deviceApprovalDigest);
    assert.equal(response.platformSigningDigest, value.request.deviceApprovalDigest);
    assert.deepEqual(
      requestApi.parsePhilSepoliaMintDeviceResponseJsonV1({
        request: value.request,
        enrollment: value.enrollment,
        json: JSON.stringify(response)
      }),
      response
    );
  });

  it("rejects every reviewed binding mutation and duplicate-key responses", function () {
    const value = fixture();
    for (const [label, mutate] of [
      ["network", (candidate) => { candidate.authorization.bindings.chainId = "1"; }],
      ["account", (candidate) => { candidate.authorization.bindings.smartAccount = "0x2000000000000000000000000000000000000006"; }],
      ["contract", (candidate) => { candidate.authorization.bindings.mintConsumer = "0x4000000000000000000000000000000000000006"; }],
      ["recipient", (candidate) => { candidate.authorization.bindings.mintRecipient = "0x5000000000000000000000000000000000000006"; }],
      ["fee", (candidate) => { candidate.authorization.bindings.maximumTotalFeeWei = "1"; }],
      ["expiry", (candidate) => { candidate.approvalExpiresAt = "1800000101"; }],
      ["digest", (candidate) => { candidate.deviceApprovalDigest = ethers.id("wrong"); }],
      ["presentation", (candidate) => { candidate.humanPresentation.action = "Send everything"; }]
    ]) {
      const candidate = structuredClone(value.request);
      mutate(candidate);
      assert.throws(
        () => requestApi.validatePhilSepoliaMintDeviceRequestV1(candidate, value.enrollment),
        undefined,
        label
      );
    }
    const signature = p256.sign(value.request.deviceApprovalDigest.slice(2), privateKey, {
      lowS: true,
      prehash: false
    });
    const response = requestApi.createPhilSepoliaMintDeviceResponseV1({
      request: value.request,
      enrollment: value.enrollment,
      signature: ethers.concat([ethers.toBeHex(signature.r, 32), ethers.toBeHex(signature.s, 32)])
    });
    const json = JSON.stringify(response).replace(
      `"responseHash":"${response.responseHash}"`,
      `"responseHash":"${response.responseHash}","responseHash":"${response.responseHash}"`
    );
    assert.throws(
      () => requestApi.parsePhilSepoliaMintDeviceResponseJsonV1({
        request: value.request, enrollment: value.enrollment, json
      }),
      (error) => error.code === "PHIL_SEPOLIA_MINT_DEVICE_RESPONSE_JSON_INVALID"
    );
  });
});
