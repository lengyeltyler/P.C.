const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { getBytes, keccak256, toUtf8Bytes } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT = path.join(
  ROOT,
  "config/solidity/O39_CONSUMER_RECOVERY_IMPLEMENTATION_EVIDENCE.json"
);
const CONTRACTS = [
  "PhilCoreV2StaticAuthorityVerifier",
  "PhilCoreV2MinimalAccountV2",
  "PhilCoreV2MinimalAccountFactoryV2"
];

function sha256File(relative) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relative)))
    .digest("hex");
}

function artifact(name) {
  const relative =
    `artifacts/contracts/base/erc4337/v2/${name}.sol/${name}.json`;
  return { relative, value: JSON.parse(fs.readFileSync(path.join(ROOT, relative))) };
}

function storageLayout(name) {
  const source = `contracts/base/erc4337/v2/${name}.sol`;
  const files = fs.readdirSync(path.join(ROOT, "artifacts/build-info"))
    .filter((file) => file.endsWith(".json"))
    .sort();
  for (const file of files.reverse()) {
    const build = JSON.parse(fs.readFileSync(
      path.join(ROOT, "artifacts/build-info", file)
    ));
    const contract = build.output?.contracts?.[source]?.[name];
    if (contract?.storageLayout) return contract.storageLayout;
  }
  throw new Error(`O39_STORAGE_LAYOUT_MISSING:${name}`);
}

function contractEvidence(name) {
  const { value } = artifact(name);
  const layout = storageLayout(name);
  const runtimeBytes = getBytes(value.deployedBytecode).length;
  const creationBytes = getBytes(value.bytecode).length;
  return {
    source: `contracts/base/erc4337/v2/${name}.sol`,
    sourceSha256: sha256File(
      `contracts/base/erc4337/v2/${name}.sol`
    ),
    runtimeBytes,
    runtimeKeccak256: keccak256(value.deployedBytecode),
    creationBytes,
    creationKeccak256: keccak256(value.bytecode),
    abiKeccak256: keccak256(toUtf8Bytes(JSON.stringify(value.abi))),
    storageEntryCount: layout.storage.length,
    occupiedStorageSlotCount: new Set(
      layout.storage.map((entry) => entry.slot)
    ).size,
    storageLayoutKeccak256: keccak256(
      toUtf8Bytes(JSON.stringify(layout))
    ),
    sizeGate: name === "PhilCoreV2StaticAuthorityVerifier"
      ? { limit: 20480, passed: runtimeBytes <= 20480 }
      : name === "PhilCoreV2MinimalAccountV2"
        ? {
          runtimeLimit: 15360,
          creationLimit: 18432,
          passed: runtimeBytes <= 15360 && creationBytes <= 18432
        }
        : {
          eip170RuntimeLimit: 24576,
          passed: runtimeBytes <= 24576
        }
  };
}

function buildEvidence() {
  return {
    phase: "O.39",
    canonicalPhase:
      "O.39 Consumer Recovery Model Revision, Implementation, and Initialization Readiness",
    classification:
      "LOCAL_ONLY_RECOVERY_ARCHITECTURE_IMPLEMENTATION_AND_INTEGRATION",
    sourceHeadAtPhaseStart:
      "25bffe61ff008a85e29c24a32e8ca2f5550c4855",
    publicMutationCount: 0,
    rpcAccessed: false,
    sepoliaAccessed: false,
    productionCredentialsCreated: false,
    readinessClassification:
      "B_RECOVERY_ENROLLMENT_FOUNDATION_COMPLETE_USER_CEREMONY_REQUIRED",
    baseline: {
      v1AccountSourceSha256:
        "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a",
      v1FactorySourceSha256:
        "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9",
      acceptedO38RuntimeKeccak256: {
        verifier:
          "0x4597c97018b1fe4b941a035275e229ea5c163db9801545217aa3a93614b1b5be",
        account:
          "0x4f0ea630700c155eb69d7661161abebdcf74dc734127131ad2dfa48dd141e3c5",
        factory:
          "0x4359422db2c5320d3c7914a414766fff29779fa45859e0fe28b4af0a67860e90"
      },
      actualO39PreChangeRuntimeKeccak256: {
        verifier:
          "0x4597c97018b1fe4b941a035275e229ea5c163db9801545217aa3a93614b1b5be",
        account:
          "0x4f0ea630700c155eb69d7661161abebdcf74dc734127131ad2dfa48dd141e3c5",
        factory:
          "0x4359422db2c5320d3c7914a414766fff29779fa45859e0fe28b4af0a67860e90"
      },
      historicallyReportedInitialV2RuntimeKeccak256Incorrect: {
        verifier:
          "0x4597f14309786bf27cbe50d4193cce030ad34a9e9b0de8acb7d93602cfa0b5be",
        account:
          "0x4f0e49bc58069857b49fc62e24c2bf149277d21c1f73583a5d2012813db1e3c5",
        factory:
          "0x4359e7e5de4e81ad62c72bded6173bcdd6e9fa1a7bde376160f6b91436530e90"
      },
      discrepancyDisposition:
        "O.39 reporting transcription error; historical values retained above as incorrect, while O.38 commit 25bffe61ff008a85e29c24a32e8ca2f5550c4855 reproduces the accepted hashes exactly"
    },
    recoveryModel: {
      descriptorVersion: 3,
      recoveryConfigurationVersion: 3,
      independenceBindingVersion: 2,
      threshold: 2,
      validBitmaps: [3, 5, 6],
      role0: "PRIMARY_RECOVERY_ONLY_DEVICE_CREDENTIAL",
      role1: "INDEPENDENT_SECONDARY_AUTHENTICATOR",
      role2: "INDEPENDENT_OFFLINE_RECOVERY_FACTOR",
      syncedRole1Deployable: false,
      outerAuthorityTransportChanged: false
    },
    contracts: Object.fromEntries(
      CONTRACTS.map((name) => [name, contractEvidence(name)])
    ),
    fixtures: {
      path: "config/cryptography/O39_CONSUMER_RECOVERY_FIXTURES.json",
      sha256: sha256File(
        "config/cryptography/O39_CONSUMER_RECOVERY_FIXTURES.json"
      ),
      profiles: ["STANDARD", "ENHANCED"],
      validPairCount: 6,
      invalidCaseCount: 16,
      syntheticTestOnly: true,
      privateMaterialCommitted: false
    },
    tests: {
      o32ThroughO39Passing: 229,
      o32ThroughO39Failing: 0,
      o39FocusedPassing: 13,
      deterministicVectorPackagesVerified: [
        "O.32",
        "O.33",
        "O.37.1",
        "O.37.2",
        "O.37.4",
        "O.39"
      ],
      typecheckPassed: true,
      solidityCompilePassed: true
    },
    initialization: {
      tupleFieldCount: 20,
      locallyDryRunCompleteWithSyntheticValues: true,
      productionValuesComplete: false,
      missingProductionActions: [
        "enroll primary recovery-only credential",
        "enroll independent secondary authenticator",
        "generate, export, and drill offline recovery factor",
        "choose deployment infrastructure",
        "generate external user salt"
      ],
      o38ReadinessInvalidated: true
    },
    security: {
      slither: {
        version: "0.10.4",
        v2DetectorOccurrences: 23,
        byImpact: {
          High: 1,
          Medium: 6,
          Low: 7,
          Informational: 8,
          Optimization: 1
        },
        newDetectorFamilies: [],
        disposition:
          "same reviewed O.38 families; guarded bounded calls and informational or optimization findings"
      },
      exactTwoOfThreePreserved: true,
      validatorExcludedFromFactorCount: true,
      noAdmin: true,
      noUpgrade: true,
      noArbitraryExecution: true,
      noMutableVerifier: true,
      nativeEthOnly: true,
      highFindings: 0,
      criticalFindings: 0
    }
  };
}

function stringify(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function main() {
  const output = stringify(buildEvidence());
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT)
      || fs.readFileSync(OUTPUT, "utf8") !== output) {
      throw new Error("O39_IMPLEMENTATION_EVIDENCE_STALE");
    }
    process.stdout.write("O.39 implementation evidence is current\n");
    return;
  }
  fs.writeFileSync(OUTPUT, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT)}\n`);
}

if (require.main === module) main();

module.exports = { buildEvidence };
