"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createECDH } = require("node:crypto");
const { ethers } = require("ethers");
require("tsx/cjs");

const mint = require("../apps/phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const device = require("../apps/phil-device-sdk/src/deviceApprovalV1.ts");
const requestApi = require("../apps/phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts");
const transport = require("../apps/phil-device-sdk/src/routineAuthorizationTransportV1.ts");

const sessionId = `0x${"91".repeat(32)}`;
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
  scopedOwnerCommitment: ethers.id("swift-fixture-scoped-owner"),
  proofDescriptorHash: ethers.id("swift-fixture-proof-descriptor"),
  rootProofNullifier: ethers.id("swift-fixture-root-nullifier"),
  scopeEpoch: "2",
  deviceEpoch: "1",
  recoveryEpoch: "4",
  validatorEpoch: "5",
  bindings
});
const publicKey = "0x04e314d95ae35d27098435c67ab20b30ee05edde043ebd589129bba3d02ce5cabec76be73181d190cef8c6926322957470ef57b92f1ef6cd8e906671526445139c";
const enrollment = device.createPhilDeviceEnrollmentRecordV1({
  deviceId: "0x5c7b39d87dae4df3ee687b4bd7a59bafb2a27848cc92c9797205eb593c13750f",
  deviceKeyId: "0xb945e237adbfa47a7093c52d85fb7d3253249d04acccbacadbabafd46f4a140c",
  signatureSuiteId: mint.PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
  publicKey,
  deviceEpoch: "1",
  enrolledAt: "1799999000",
  assuranceClass: 3,
  policyHash: authorization.authorizationEnvelope.policyHash
});
const request = requestApi.createPhilSepoliaMintDeviceRequestV1({
  sessionId,
  authorization,
  enrollment,
  approvalNonce: ethers.id("swift-fixture-device-approval-nonce"),
  approvedAt: "1800000005",
  approvalExpiresAt: "1800000100"
});
const desktop = createECDH("prime256v1");
desktop.setPrivateKey(Buffer.from("03".repeat(32), "hex"));
const bootstrap = {
  sessionId,
  ipv4: "192.168.7.9",
  port: 43123,
  desktopPublicKeyX963: ethers.hexlify(desktop.getPublicKey(undefined, "uncompressed")),
  requestId: request.requestId,
  expiresAt: request.approvalExpiresAt
};
const output = Object.freeze({
  format: "phil-sepolia-mint-device-request-cross-language-fixture",
  version: 1,
  qrPayload: transport.encodePhilRoutineTransportBootstrapV1(bootstrap),
  bootstrap,
  request,
  enrollment
});
fs.writeFileSync(
  path.join(__dirname, "../config/adapters/PHIL_SEPOLIA_MINT_DEVICE_REQUEST_FIXTURE.json"),
  `${JSON.stringify(output, null, 2)}\n`,
  { mode: 0o644 }
);
