const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { keccak256 } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(
  ROOT,
  "config/solidity/O43_NATIVE_IPHONE_IMPLEMENTATION_EVIDENCE.json"
);

const contracts = [
  ["PhilCoreV2StaticAuthorityVerifier",
    "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol"],
  ["PhilCoreV2MinimalAccountV2",
    "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol"],
  ["PhilCoreV2MinimalAccountFactoryV2",
    "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol"]
];

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function artifact(name, source) {
  const file = path.join(ROOT, "artifacts", source, `${name}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(`O43_ARTIFACT_MISSING:${name}`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function contractEvidence(name, source) {
  const value = artifact(name, source);
  const sourceContents = fs.readFileSync(path.join(ROOT, source));
  const runtimeBytes = (value.deployedBytecode.length - 2) / 2;
  const creationBytes = (value.bytecode.length - 2) / 2;
  const abi = value.abi
    .map((entry) => JSON.stringify(entry))
    .sort()
    .join("\n");
  return {
    source,
    sourceSha256: sha256(sourceContents),
    runtimeBytes,
    runtimeKeccak256: keccak256(value.deployedBytecode),
    creationBytes,
    creationKeccak256: keccak256(value.bytecode),
    abiSha256: sha256(abi),
    eip170WithinLimit: runtimeBytes <= 24_576,
    eip3860WithinLimit: creationBytes <= 49_152
  };
}

function buildEvidence() {
  const result = Object.fromEntries(
    contracts.map(([name, source]) => [
      name,
      contractEvidence(name, source)
    ])
  );
  return {
    phase: "O.43",
    classification: "LOCAL_ONLY_NATIVE_IOS_COMPANION_IMPLEMENTATION",
    publicMutationCount: 0,
    baseline: {
      initialHead: "c81deff878906cfa38443abfc8ca6ef03c68c916",
      branch: "codex/device-identity-v1",
      v1SourceSha256: {
        account:
          "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a",
        factory:
          "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
      },
      initialV2RuntimeKeccak256: {
        verifier:
          "0x665910b9989f3b83c3f025314fb127755d5abfc46e66ee386fbcbbfefc864dd7",
        account:
          "0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519",
        factory:
          "0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95"
      }
    },
    protocol: {
      role: 1,
      verifierKind: 4,
      descriptorVersion: 1,
      outerRecoveryEnvelopeVersion: 2,
      recoveryConfigurationVersion: 3,
      threshold: 2,
      validBitmaps: [3, 5, 6],
      validatorExcluded: true,
      appAttest: "DEFERRED_OPTIONAL_ENROLLMENT_ATTESTATION"
    },
    contracts: result,
    solidityImpact: {
      verifierChanged: true,
      accountChanged: false,
      factoryChanged: false,
      abiChanged: false,
      accountStorageChanged: false,
      verifierStorageSlots: 0,
      accountStorageSlots: 15,
      factoryStorageSlots: 0
    },
    localImplementation: {
      bundleIdentifier: "com.philcore.ios.companion.localalpha",
      teamId: "B342738S82",
      keychainAccessGroup:
        "B342738S82.com.philcore.ios.companion.localalpha",
      algorithm: "P-256 ECDSA",
      privateKeyExport: false,
      iCloudSynchronization: false,
      localApproval: "deviceOwnerAuthentication + key userPresence",
      transport: "selected private IPv4 interface",
      pairingCrypto: "P-256 ECDH / HKDF-SHA256 / AES-256-GCM",
      sessionTtlSeconds: 300,
      productionCredentialCreated: false,
      disposableCredentialCreated: false
    },
    gates: {
      deterministicFixtures: "PASS",
      nativeRole1SolidityPairs: "PASS",
      desktopPairingProtocol: "PASS",
      desktopFullRegression: "PASS",
      relevantSolidityLifecycleTests: "45_PASS",
      cleanBuildRuntimeReproduction: "PASS",
      changedVerifierSlitherHighOrCritical: 0,
      swiftSyntaxParse: "PASS",
      iOSProjectStructure: "PASS",
      iOSUITestTarget: "PRESENT_NOT_EXECUTED",
      iOSSimulatorBuild: "BLOCKED_FULL_XCODE_NOT_INSTALLED",
      physicalDeviceInstall: "BLOCKED_NO_XCODE_NO_DEVICE_NO_APPLE_DEVELOPMENT_IDENTITY",
      physicalSecureEnclaveTest: "NOT_RUN",
      productionCeremony: "NOT_RUN"
    },
    stopBoundary: {
      publicDeployment: false,
      publicTransaction: false,
      sepoliaAccess: false,
      externalRpcAccess: false,
      externalBundlerSubmission: false,
      fundsMoved: false,
      productionAccountDeployed: false,
      productionSecretCommitted: false,
      privateSecureEnclaveKeyExported: false,
      pushed: false
    }
  };
}
function main() {
  if (!process.argv.includes("--check")) require("./evidence-provenance-v2.cjs").refuseLegacyEvidenceWrite();
  const output = `${JSON.stringify(buildEvidence(), null, 2)}\n`;
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT) || fs.readFileSync(OUTPUT, "utf8") !== output) {
      throw new Error("O43_NATIVE_IPHONE_EVIDENCE_STALE");
    }
    process.stdout.write("O.43 native iPhone evidence is current\n");
    return;
  }
  require("./evidence-provenance-v2.cjs").refuseLegacyEvidenceWrite();
  return;
}

if (require.main === module) main();

module.exports = { buildEvidence };
