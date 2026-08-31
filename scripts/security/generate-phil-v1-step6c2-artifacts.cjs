"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { p256 } = require("@noble/curves/p256");

require("tsx/cjs");
const transport = require("../../apps/phil-device-sdk/src/routineAuthorizationTransportV1.ts");
const enrollment = require("../../apps/phil-device-sdk/src/routineDeviceEnrollmentTransportV2.ts");

const root = path.resolve(__dirname,"../..");
const write = process.argv.includes("--write");
const fixturePath = path.join(root,"config/adapters/PHIL_V1_STEP6C2_PRODUCT_WIRING_FIXTURE.json");
const manifestPath = path.join(root,"docs/reference/PHIL_V1_STEP6C2_ARTIFACT_MANIFEST.json");
const sourceFiles = [
  "package.json",
  "config/ci/classification.json",
  "config/adapters/PHIL_V1_STEP6C_LOCAL_COMPOSITION_FIXTURE.json",
  "README.md",
  "docs/CANONICAL_DOCS.md",
  "docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md",
  "docs/reference/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_PRODUCT_COMPOSITION_GATE.md",
  "docs/reference/PHIL_V1_STEP6C_IMPLEMENTATION_PACKET.md",
  "docs/reference/PHIL_V1_STEP4_REFERENCE_MANIFEST_MAINTENANCE.md",
  "docs/reference/PHIL_V1_STEP6C2_PRODUCT_WIRING_IMPLEMENTATION_REPORT.md",
  "docs/reference/PHIL_V1_STEP6C3_PHYSICAL_FAILURE_AND_CORRECTIVE_REPORT.md",
  "docs/reference/PHIL_V1_STEP6C3_CORRECTIVE_REVIEW_6670B93.md",
  "docs/reference/PHIL_V1_STEP6C3_SUCCESSOR_REVIEW_CAF077E.md",
  "docs/reference/PHIL_V1_STEP6C3_CORRECTIVE_ACCEPTANCE_C32D8F8.md",
  "docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_021E703.md",
  "docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_C40FA2C.md",
  "docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_75785F3.md",
  "docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_965F9ED.md",
  "docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_09E5A9E.md",
  "docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_8A2D906.md",
  "docs/reference/PHIL_V1_STEP6C2_INDEPENDENT_REVIEW_4A81B08.md",
  "docs/security/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_THREAT_MODEL.md",
  "apps/phil-device-sdk/src/routineDeviceEnrollmentTransportV2.ts",
  "hardhat.shared.cjs",
  "hardhat.phil-v1-step6c-product.config.cjs",
  "apps/phil-device-sdk/src/routineAuthorizationTransportV1.ts",
  "apps/phil-device-sdk/src/routineAuthorizationV1.ts",
  "apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts",
  "apps/philcore-desktop/src/main/routine-authorization-host.cjs",
  "apps/philcore-desktop/src/main/routine-authorization-local-product-runtime.cjs",
  "apps/philcore-desktop/src/main/routine-authorization-product-host.cjs",
  "apps/philcore-desktop/src/main/routine-device-enrollment-host.cjs",
  "apps/philcore-desktop/src/main/routine-authorization-ipc.cjs",
  "apps/philcore-desktop/src/main/routine-authorization-storage.cjs",
  "apps/philcore-desktop/src/main/recovery-secure-origin.cjs",
  "apps/philcore-desktop/src/main/main.cjs",
  "apps/philcore-desktop/scripts/package-local.cjs",
  "apps/philcore-desktop/scripts/release-utils.cjs",
  "apps/philcore-desktop/scripts/verify-package.cjs",
  "apps/philcore-desktop/scripts/test-packaged-action-lifecycle.cjs",
  "apps/philcore-desktop/scripts/test-packaged.cjs",
  "apps/philcore-desktop/src/preload/preload.cjs",
  "apps/philcore-desktop/src/shared/bridge-contract.cjs",
  "apps/philcore-desktop/src/renderer/index.html",
  "apps/philcore-desktop/src/renderer/routine-authorization-ui.cjs",
  "apps/philcore-desktop/src/renderer/unlock-transition-policy.cjs",
  "apps/philcore-desktop/src/renderer/app.js",
  "apps/philcore-desktop/test/desktop-alpha-product.test.cjs",
  "apps/philcore-desktop/test/run-desktop-tests.cjs",
  "apps/philcore-desktop/test/desktop-routine-authorization-ui-state.test.cjs",
  "apps/philcore-ios-companion/PhilCoreCompanion/Info.plist",
  "apps/philcore-ios-companion/PhilCoreCompanion/PhilCoreCompanionApp.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/QRScannerView.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/RoutineAuthorizationTransport.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/RoutineApprovalKeyManager.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/RoutineAuthorizationClient.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/RoutineAuthorizationCanonicalVerifier.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/RoutineDeviceEnrollmentClient.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/CompanionModel.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion/Models.swift",
  "apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj/project.pbxproj",
  "apps/philcore-ios-companion/scripts/test-routine-authorization-simulator.cjs",
  "test/unit/phil-v1-step6c2-transport.test.cjs",
  "test/unit/phil-v1-step6c2-enrollment.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-authorization.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-authorization-local-product-runtime.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-authorization-product-flow.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-authorization-product-host.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-device-enrollment-host.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-enrollment-urlsession-integration.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-authorization-ipc.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-authorization-storage.test.cjs",
  "apps/philcore-desktop/test/desktop-recovery-secure-origin.test.cjs",
  "scripts/ci/run-lane.cjs",
  "test/unit/ci-classification.test.cjs",
  "apps/philcore-ios-companion/PhilCoreCompanionTests/RoutineAuthorizationTests.swift",
  "scripts/security/generate-phil-v1-step6c2-artifacts.cjs"
];
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const identity = Object.fromEntries(sourceFiles.map((file) => {
  const value = fs.readFileSync(path.join(root,file));return [file,{ bytes:value.length, sha256:sha256(value) }];
}));
const inheritedFixture = JSON.parse(fs.readFileSync(
  path.join(root,"config/adapters/PHIL_V1_STEP6C_LOCAL_COMPOSITION_FIXTURE.json"),"utf8"
));
const inheritedRequest = inheritedFixture.requests.failedNonce0.request;
const desktop = crypto.createECDH("prime256v1");desktop.setPrivateKey(Buffer.alloc(32,3));
const iphone = crypto.createECDH("prime256v1");iphone.setPrivateKey(Buffer.alloc(32,4));
const bootstrap = {
  sessionId:inheritedRequest.authorizationCore.sessionId,
  ipv4:"192.168.7.9",port:43123,
  desktopPublicKeyX963:`0x${desktop.getPublicKey(undefined,"uncompressed").toString("hex")}`,
  requestId:inheritedRequest.requestId,
  expiresAt:inheritedRequest.authorizationCore.expiresAt
};
const qrPayload = transport.encodePhilRoutineTransportBootstrapV1(bootstrap);
const transcriptHash = transport.derivePhilRoutineTransportTranscriptHashV1({
  bootstrap,iphonePublicKeyX963:`0x${iphone.getPublicKey(undefined,"uncompressed").toString("hex")}`
});
const desktopAckPrivateKey=Buffer.from("05".repeat(32),"hex"),desktopAckPublicKey=Buffer.from(p256.getPublicKey(desktopAckPrivateKey,false));
const enrollmentBootstrap={sessionId:`0x${"11".repeat(32)}`,ipv4:"192.168.7.9",port:43124,
  challenge:`0x${"22".repeat(32)}`,expiresAt:"1800000500",expectedGeneration:"1",desktopAckPublicKeyX963:`0x${desktopAckPublicKey.toString("hex")}`};
const enrollmentPrivateKey=Buffer.from("2897c8d199907ffab6db9e3a1e67b88349a8233cf2693edf10c7dfb0244acbb4","hex");
const enrollmentPublicKey=Buffer.from(p256.getPublicKey(enrollmentPrivateKey,false));
const enrollmentRecord={schemaVersion:2,generation:"1",deviceId:"0x5c7b39d87dae4df3ee687b4bd7a59bafb2a27848cc92c9797205eb593c13750f",
  deviceKeyId:"0xb945e237adbfa47a7093c52d85fb7d3253249d04acccbacadbabafd46f4a140c",
  publicKeyX963:`0x${enrollmentPublicKey.toString("hex")}`,signatureSuiteId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.signatureSuiteId,
  providerProfileId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.providerProfileId,
  wireEncodingId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.wireEncodingId,
  publicKeyFingerprint:`0x${crypto.createHash("sha256").update(enrollmentPublicKey).digest("hex")}`,secureEnclaveBacked:false,userPresenceRequired:false};
const enrollmentAcceptanceDigest=enrollment.derivePhilRoutineDeviceEnrollmentAcceptanceDigestV2({bootstrap:enrollmentBootstrap,record:enrollmentRecord});
const enrollmentAcceptanceSignature=p256.sign(enrollmentAcceptanceDigest.slice(2),desktopAckPrivateKey,{lowS:true,prehash:false}).toDERRawBytes();
const enrollmentAcceptanceResponseJson=enrollment.serializePhilRoutineDeviceEnrollmentAcceptanceV2({bootstrap:enrollmentBootstrap,record:enrollmentRecord,acceptanceSignatureDER:enrollmentAcceptanceSignature});
const fixture = {
  format:"PHIL_V1_STEP6C2_PRODUCT_WIRING_FIXTURE_V3",
  generatedAtProtocolTime:"2026-08-22T00:00:00.000Z",
  inheritedStep6C1:{ sourceCommit:"6f048eb69ac2ca4bcd6f9649b9a543cf17f0b62c",sourceTree:"a9032b29802bcd3f4bfc7a2de48f911e9b805063",acceptedCandidate:"22b5cf31d068104c762c411cd4fa6ad8e0485eae",acceptedTree:"2b0ff7fdf25f6571852be23853a9ad9c6f3e064f" },
  transport:{ ...transport.PHIL_ROUTINE_TRANSPORT_V1,qrBootstrapBytes:216,bootstrap,qrPayload,
    iphonePublicKeyX963:`0x${iphone.getPublicKey(undefined,"uncompressed").toString("hex")}`,
    transcriptHash,comparisonFingerprint:transport.formatPhilRoutineTransportFingerprintV1(transcriptHash) },
  enrollment:{...enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2,bootstrap:enrollmentBootstrap,
    qrPayload:enrollment.encodePhilRoutineDeviceEnrollmentBootstrapV2(enrollmentBootstrap),
    comparisonFingerprint:enrollment.formatPhilRoutineDeviceEnrollmentFingerprintV2(enrollmentBootstrap),record:enrollmentRecord,
    proofDigest:enrollment.derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap:enrollmentBootstrap,record:enrollmentRecord}),
    acceptanceDigest:enrollmentAcceptanceDigest,acceptanceResponseJson:enrollmentAcceptanceResponseJson,evidenceClass:"synthetic_source_test"},
  focusedAutomatedTests:{typescriptTransport:6,typescriptEnrollment:3,desktopHost:4,desktopLocalProductRuntime:2,
    desktopProductFlow:1,desktopIpc:6,desktopStorage:3,desktopProductHost:3,desktopEnrollmentHost:1,
    desktopUrlSessionIntegration:1,desktopUiState:6,desktopSecureOrigin:1,swiftSimulator:26,total:63},
  classifications:{localPrototype:true,reviewedSource:false,physicalDeviceVerified:false,testnetAdmitted:false,
    productionAdmitted:false,postQuantumEnforced:false,externalNetwork:false,meaningfulAssets:false,productionAuthority:false},
  sourceFiles:identity
};
const fixtureText = `${JSON.stringify(fixture,null,2)}\n`;
const manifest = {
  format:"PHIL_V1_STEP6C2_ARTIFACT_MANIFEST_V3",generatedAtProtocolTime:fixture.generatedAtProtocolTime,
  candidateBinding:"Exact commit and tree are bound only by the independent Step 6C-2 review record.",
  fixture:{path:path.relative(root,fixturePath),bytes:Buffer.byteLength(fixtureText),sha256:sha256(fixtureText)},
  inheritedStep6C1:fixture.inheritedStep6C1,focusedAutomatedTests:fixture.focusedAutomatedTests,
  protocolIdentities:{authorization:{transcriptLabel:transport.PHIL_ROUTINE_TRANSPORT_V1.transcriptLabel,
    hkdfInfo:transport.PHIL_ROUTINE_TRANSPORT_V1.hkdfInfo,beginPath:transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath,
    completePath:transport.PHIL_ROUTINE_TRANSPORT_V1.completePath,qrPrefix:transport.PHIL_ROUTINE_TRANSPORT_V1.qrPrefix},
    enrollment:{transcriptLabel:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.transcriptLabel,
      acceptanceLabel:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.acceptanceLabel,
      preflightPath:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.preflightPath,
      completePath:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath,
      qrPrefix:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.qrPrefix,
      maximumGeneration:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.maximumGeneration,
      signatureSuiteId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.signatureSuiteId,
      providerProfileId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.providerProfileId,
      wireEncodingId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.wireEncodingId}},
  nonclaims:["physical iPhone verification","public or test network admission","production authority","post-quantum enforcement","production readiness"]
};
const manifestText = `${JSON.stringify(manifest,null,2)}\n`;
function check(location, expected) {
  if (!fs.existsSync(location) || fs.readFileSync(location,"utf8")!==expected) {
    process.stderr.write(`Step 6C-2 artifact mismatch: ${path.relative(root,location)}\n`);process.exitCode=1;
  }
}
if (write) { fs.writeFileSync(fixturePath,fixtureText);fs.writeFileSync(manifestPath,manifestText); }
else { check(fixturePath,fixtureText);check(manifestPath,manifestText); }
if (!process.exitCode) process.stdout.write(`Step 6C-2 artifacts ${write ? "generated" : "verified"}: ${fixture.focusedAutomatedTests.total} focused automated tests, physicalDeviceVerified=false\n`);
