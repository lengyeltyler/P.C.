const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  AbiCoder,
  concat,
  getCreate2Address,
  id,
  keccak256,
  toUtf8Bytes
} = require("ethers");

const root = path.resolve(__dirname, "../..");
const checkOnly = process.argv.includes("--check");
const artifactRoot = path.join(root, "artifacts/contracts/base/erc4337/v2");
const accountArtifactPath = path.join(
  artifactRoot,
  "PhilCoreV2MinimalAccountV2.sol/PhilCoreV2MinimalAccountV2.json"
);
const factoryArtifactPath = path.join(
  artifactRoot,
  "PhilCoreV2MinimalAccountFactoryV2.sol/PhilCoreV2MinimalAccountFactoryV2.json"
);
const verifierArtifactPath = path.join(
  artifactRoot,
  "PhilCoreV2StaticAuthorityVerifier.sol/PhilCoreV2StaticAuthorityVerifier.json"
);
const accountSource =
  "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol";
const factorySource =
  "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol";
const verifierSource =
  "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol";

function readJson(relativeOrAbsolute) {
  const target = path.isAbsolute(relativeOrAbsolute)
    ? relativeOrAbsolute
    : path.join(root, relativeOrAbsolute);
  return JSON.parse(fs.readFileSync(target, "utf8"));
}

function sha256File(relativePath) {
  return crypto
    .createHash("sha256")
    .update(fs.readFileSync(path.join(root, relativePath)))
    .digest("hex");
}

function byteLength(hex) {
  return (hex.length - 2) / 2;
}

function canonicalHash(value) {
  return keccak256(toUtf8Bytes(JSON.stringify(value)));
}

function findBuildInfo() {
  const directory = path.join(root, "artifacts/build-info");
  for (const name of fs.readdirSync(directory).sort()) {
    const value = readJson(path.join(directory, name));
    if (
      value.output.contracts?.[accountSource]?.PhilCoreV2MinimalAccountV2
        ?.storageLayout &&
      value.output.contracts?.[factorySource]
        ?.PhilCoreV2MinimalAccountFactoryV2
    ) {
      return { name, value };
    }
  }
  throw new Error("O37_10_BUILD_INFO_NOT_FOUND");
}

function scanOpcodes(bytecode) {
  const raw = Buffer.from(bytecode.slice(2), "hex");
  const metadataLength =
    raw.length >= 2 ? raw.readUInt16BE(raw.length - 2) + 2 : 0;
  const bytes =
    metadataLength > 2 && metadataLength <= raw.length
      ? raw.subarray(0, raw.length - metadataLength)
      : raw;
  const counts = new Map();
  for (let cursor = 0; cursor < bytes.length; cursor += 1) {
    const opcode = bytes[cursor];
    counts.set(opcode, (counts.get(opcode) || 0) + 1);
    if (opcode >= 0x60 && opcode <= 0x7f) cursor += opcode - 0x5f;
  }
  return {
    executableBytesScanned: bytes.length,
    metadataBytesExcluded: raw.length - bytes.length,
    sstore: counts.get(0x55) || 0,
    call: counts.get(0xf1) || 0,
    staticcall: counts.get(0xfa) || 0,
    delegatecall: counts.get(0xf4) || 0,
    create: counts.get(0xf0) || 0,
    create2: counts.get(0xf5) || 0,
    selfdestruct: counts.get(0xff) || 0
  };
}

const account = readJson(accountArtifactPath);
const factory = readJson(factoryArtifactPath);
const verifier = readJson(verifierArtifactPath);
const { name: buildInfoName, value: buildInfo } = findBuildInfo();
const accountOutput =
  buildInfo.output.contracts[accountSource].PhilCoreV2MinimalAccountV2;
const factoryOutput =
  buildInfo.output.contracts[factorySource]
    .PhilCoreV2MinimalAccountFactoryV2;
const accountLayout = accountOutput.storageLayout.storage.map(
  ({ label, offset, slot, type }) => ({ label, offset, slot, type })
);
const factoryLayout = factoryOutput.storageLayout.storage.map(
  ({ label, offset, slot, type }) => ({ label, offset, slot, type })
);
const accountFunctions = account.abi
  .filter((entry) => entry.type === "function")
  .map((entry) => entry.name)
  .sort();
const factoryFunctions = factory.abi
  .filter((entry) => entry.type === "function")
  .map((entry) => entry.name)
  .sort();
const packageLock = readJson("package-lock.json");

const accountVersionLabel =
  "philcore-v2-minimal-account-v3-consumer-recovery";
const accountVersionId = id(accountVersionLabel);
const factoryVersionLabel = "philcore-v2-minimal-factory-v2";
const factoryVersionId = id(factoryVersionLabel);

function assertSourcesDeclareAccountVersionId(expectedId) {
  for (const relativePath of [accountSource, factorySource]) {
    const source = fs.readFileSync(path.join(root, relativePath), "utf8");
    const match = source.match(
      /bytes32\s+private\s+constant\s+ACCOUNT_VERSION_ID\s*=\s*(0x[0-9a-fA-F]+)\s*;/
    );
    if (!match || match[1].toLowerCase() !== expectedId.toLowerCase()) {
      throw new Error(
        `O37_10_ACCOUNT_VERSION_ID_MISMATCH:${relativePath}:expected=${expectedId}:found=${
          match ? match[1] : "MISSING"
        }`
      );
    }
  }
}

assertSourcesDeclareAccountVersionId(accountVersionId);

function assertSourcesDeclareRecoveryConfigurationTypeString(expectedTypeString) {
  for (const relativePath of [accountSource, factorySource]) {
    const source = fs.readFileSync(path.join(root, relativePath), "utf8");
    const match = source.match(
      /bytes32\s+private\s+constant\s+RECOVERY_CONFIGURATION_TYPEHASH\s*=\s*keccak256\s*\(\s*"([^"]*)"\s*\)\s*;/
    );
    if (!match || match[1] !== expectedTypeString) {
      throw new Error(
        `O37_10_RECOVERY_CONFIGURATION_TYPE_STRING_MISMATCH:${relativePath}:expected=${expectedTypeString}:found=${
          match ? match[1] : "MISSING"
        }`
      );
    }
  }
}

const recoveryConfigurationTypeString =
  "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)";
assertSourcesDeclareRecoveryConfigurationTypeString(
  recoveryConfigurationTypeString
);

const securityModelId = id(
  "philcore-v2-typed-intent-local-proof-gated-v1"
);
const identityBindingTypeHash =
  "0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8";
const ownerSchemeId =
  "0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e";
const validatorTypeHash = id(
  "PhilCoreV2ValidatorCommitment(uint8 verifierKind,address validator,bytes32 validatorKeyIdBinding)"
);
const recoveryTypeHash = id(recoveryConfigurationTypeString);
const abiCoder = AbiCoder.defaultAbiCoder();
const tupleType =
  "tuple(address entryPoint,uint256 deploymentChainId,bytes32 ownerCommitment,bytes32 identityBindingCommitment,address factoryBinding,bytes32 accountVersionId,bytes32 securityModelId,address confirmationTarget,address initialValidator,uint8 validatorVerifierKind,bytes32 validatorKeyIdBinding,bytes32 validatorCommitment,uint64 validatorEpoch,bytes32 primaryDeviceRecoveryCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 independentRecoveryFactorCommitment,bytes32 recoveryConfigurationHash,uint64 recoveryEpoch,uint64 recoveryDelaySeconds,uint64 recoveryExpirySeconds)";
const vectorBase = {
  entryPoint: "0x0000000000000000000000000000000000004337",
  deploymentChainId: 31337n,
  ownerCommitment: id("o37-10-evidence-owner"),
  factoryBinding: "0x00000000000000000000000000000000000F3710",
  confirmationTarget: "0x000000000000000000000000000000000000C0F1",
  initialValidator: "0x000000000000000000000000000000000000A110",
  validatorVerifierKind: 1,
  validatorKeyIdBinding: id("o37-10-evidence-validator-key"),
  validatorEpoch: 1,
  primaryDeviceRecoveryCommitment: id("o37-10-evidence-primary"),
  hardwareSecurityKeyCommitment: id("o37-10-evidence-hardware"),
  independentRecoveryFactorCommitment: id("o37-10-evidence-independent"),
  recoveryEpoch: 1,
  recoveryDelaySeconds: 172800,
  recoveryExpirySeconds: 604800,
  accountVersionId,
  securityModelId
};
vectorBase.identityBindingCommitment = keccak256(
  abiCoder.encode(
    ["bytes32", "uint8", "bytes32", "bytes32"],
    [
      identityBindingTypeHash,
      1,
      vectorBase.ownerCommitment,
      ownerSchemeId
    ]
  )
);
vectorBase.validatorCommitment = keccak256(
  abiCoder.encode(
    ["bytes32", "uint8", "address", "bytes32"],
    [
      validatorTypeHash,
      1,
      vectorBase.initialValidator,
      vectorBase.validatorKeyIdBinding
    ]
  )
);
vectorBase.recoveryConfigurationHash = keccak256(
  abiCoder.encode(
    ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
    [
      recoveryTypeHash,
      3,
      2,
      vectorBase.primaryDeviceRecoveryCommitment,
      vectorBase.hardwareSecurityKeyCommitment,
      vectorBase.independentRecoveryFactorCommitment
    ]
  )
);

const initArguments = abiCoder.encode([tupleType], [vectorBase]);
const exactInitCode = concat([account.bytecode, initArguments]);
const exactInitCodeHash = keccak256(exactInitCode);
const create2Vectors = ["alpha", "beta", "gamma"].map((label) => {
  const userSalt = id(`o37-10-evidence-${label}`);
  const deploymentSalt = keccak256(
    abiCoder.encode(
      [
        "bytes32",
        "uint256",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32"
      ],
      [
        id("PHILCORE_V2_CREATE2_SALT_V1"),
        vectorBase.deploymentChainId,
        accountVersionId,
        securityModelId,
        vectorBase.ownerCommitment,
        vectorBase.identityBindingCommitment,
        userSalt
      ]
    )
  );
  return {
    classification: "DETERMINISTIC_LOCAL_TEST_VECTOR_ONLY",
    label,
    userSalt,
    deploymentSalt,
    accountCreationCodeHash: exactInitCodeHash,
    syntheticFactoryAddress: vectorBase.factoryBinding,
    predictedAddress: getCreate2Address(
      vectorBase.factoryBinding,
      deploymentSalt,
      exactInitCodeHash
    ),
    canonicalProductionAddress: false
  };
});

const compilerSettings = {
  solidity: buildInfo.solcLongVersion,
  evmVersion: buildInfo.input.settings.evmVersion,
  optimizerEnabled: buildInfo.input.settings.optimizer.enabled,
  optimizerRuns: buildInfo.input.settings.optimizer.runs,
  viaIR: buildInfo.input.settings.viaIR,
  metadata: buildInfo.input.settings.metadata
};
const dependencies = {
  openZeppelinContracts:
    packageLock.packages["node_modules/@openzeppelin/contracts"].version,
  accountAbstractionContracts:
    packageLock.packages["node_modules/@account-abstraction/contracts"]
      .version,
  hardhat: packageLock.packages["node_modules/hardhat"].version,
  hardhatEthers:
    packageLock.packages["node_modules/@nomicfoundation/hardhat-ethers"]
      .version,
  ethers: packageLock.packages["node_modules/ethers"].version,
  node: fs.readFileSync(path.join(root, ".node-version"), "utf8").trim(),
  npm: "11.12.1",
  packageLockVersion: packageLock.lockfileVersion
};

const sizeReport = {
  schemaVersion: 1,
  phase: "O.37.10",
  compilerSettings,
  contracts: {
    verifier: {
      runtimeBytes: byteLength(verifier.deployedBytecode),
      creationBytes: byteLength(verifier.bytecode),
      runtimeKeccak256: keccak256(verifier.deployedBytecode),
      creationKeccak256: keccak256(verifier.bytecode),
      eip170ReserveBytes: 24576 - byteLength(verifier.deployedBytecode),
      accepted: byteLength(verifier.deployedBytecode) <= 20480
    },
    account: {
      runtimeBytes: byteLength(account.deployedBytecode),
      creationBytes: byteLength(account.bytecode),
      sampleExactInitCodeBytes: byteLength(exactInitCode),
      runtimeKeccak256: keccak256(account.deployedBytecode),
      creationKeccak256: keccak256(account.bytecode),
      sampleExactInitCodeKeccak256: exactInitCodeHash,
      preferredRuntimeMaximumBytes: 15360,
      reviewedRuntimeMaximumBytes: 20480,
      eip170MaximumBytes: 24576,
      eip170ReserveBytes: 24576 - byteLength(account.deployedBytecode),
      eip3860MaximumInitCodeBytes: 49152,
      eip3860ReserveBytes: 49152 - byteLength(exactInitCode),
      accepted: byteLength(account.deployedBytecode) <= 15360
    },
    factory: {
      runtimeBytes: byteLength(factory.deployedBytecode),
      creationBytes: byteLength(factory.bytecode),
      constructorArgumentBytes: 160,
      exactDeploymentInitCodeBytes: byteLength(factory.bytecode) + 160,
      runtimeKeccak256: keccak256(factory.deployedBytecode),
      creationKeccak256: keccak256(factory.bytecode),
      eip170ReserveBytes: 24576 - byteLength(factory.deployedBytecode),
      eip3860ReserveBytes:
        49152 - (byteLength(factory.bytecode) + 160),
      accepted: byteLength(factory.deployedBytecode) < 24576
    }
  },
  contributorAnalysis: {
    method:
      "QUALITATIVE_SECURITY_REVIEW_WITH_EXACT_WHOLE_ARTIFACT_MEASUREMENT",
    accountDominantContributors: [
      "canonical fixed-word ABI decoding and typed O.32 intent hashing",
      "ERC-4337 sender, hash, keyed nonce, fee, validity, and paymaster checks",
      "factory verifier-binding and verifier STATICCALL validation",
      "validator and exact delayed recovery lifecycle transitions",
      "four aggregate views and two commitment-oriented events"
    ],
    factoryDominantContributors: [
      "embedded exact account creation code",
      "canonical 20-field initialization validation",
      "CREATE2 salt, init-code hash, address prediction, and deployment"
    ],
    securityChecksRemovedForSize: false,
    note:
      "viaIR inlining prevents defensible per-function byte counts; no synthetic byte attribution is claimed"
  }
};

const abiReport = {
  schemaVersion: 1,
  phase: "O.37.10",
  account: {
    functionCount: accountFunctions.length,
    functions: accountFunctions,
    abiKeccak256: canonicalHash(account.abi),
    abi: account.abi
  },
  factory: {
    functionCount: factoryFunctions.length,
    functions: factoryFunctions,
    abiKeccak256: canonicalHash(factory.abi),
    abi: factory.abi
  },
  verifier: {
    functionCount: verifier.abi.filter((entry) => entry.type === "function")
      .length,
    abiKeccak256: canonicalHash(verifier.abi)
  }
};

const storageReport = {
  schemaVersion: 1,
  phase: "O.37.10",
  account: {
    highestMutableSlot: Math.max(
      ...accountLayout.map((entry) => Number(entry.slot))
    ),
    storageLayoutKeccak256: canonicalHash(accountLayout),
    layout: accountLayout,
    duplicateNonceStorage: false,
    verifierStorage: false,
    adminOrUpgradeStorage: false
  },
  factory: {
    mutableStorageEntries: factoryLayout.length,
    storageLayoutKeccak256: canonicalHash(factoryLayout),
    layout: factoryLayout
  }
};

const create2Report = {
  schemaVersion: 1,
  phase: "O.37.10",
  accountVersionLabel,
  accountVersionId,
  factoryVersionLabel,
  factoryVersionId,
  creationTupleFieldCount: 20,
  accountCreationCodeHash: exactInitCodeHash,
  sampleExactInitCodeBytes: byteLength(exactInitCode),
  syntheticVectorInputs: {
    ...vectorBase,
    deploymentChainId: vectorBase.deploymentChainId.toString()
  },
  vectors: create2Vectors,
  productionAddressDeclaredCanonical: false
};

const implementationEvidence = {
  schemaVersion: 1,
  phase: "O.37.10",
  canonicalPhaseName:
    "O.37.10 V2 Minimal Account, Factory, and Local Lifecycle Implementation",
  classification: "LOCAL_ONLY_SOLIDITY_IMPLEMENTATION_AND_INTEGRATION",
  result: "COMPLETE_LOCAL_DEPLOYABLE_PACKAGE",
  sourceHeadAtPhaseStart:
    "b98acd6c3b81ea324c15a17e14d1dc7703a6bf5d",
  publicMutationCount: 0,
  baseline: {
    repository: "<repository-root>",
    branch: "codex/device-identity-v1",
    trackedWorktreeClean: true,
    v1AccountSourceSha256:
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a",
    v1FactorySourceSha256:
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
  },
  sourceBindings: {
    accountInterfaceSha256: sha256File(
      "contracts/base/erc4337/v2/IPhilCoreV2MinimalAccountV2.sol"
    ),
    accountSha256: sha256File(accountSource),
    factorySha256: sha256File(factorySource),
    unchangedVerifierSha256: sha256File(verifierSource),
    lifecycleTestSha256: sha256File(
      "test/unit/o37-10-v2-minimal-account.test.cjs"
    ),
    op054TraceTestSha256: sha256File(
      "test/unit/o37-10-v2-erc7562-op054.test.cjs"
    )
  },
  fixtureBindings: {
    o37_2Sha256: sha256File(
      "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json"
    ),
    o37_4Sha256: sha256File(
      "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json"
    )
  },
  buildInfoFile: buildInfoName,
  compilerSettings,
  dependencies,
  accountVersionLabel,
  factoryVersionLabel,
  ids: { accountVersionId, factoryVersionId, securityModelId },
  artifacts: {
    sizeReport: "config/solidity/O37_10_SIZE_REPORT.json",
    abiReport: "config/solidity/O37_10_ABI_REPORT.json",
    storageReport: "config/solidity/O37_10_STORAGE_LAYOUT_REPORT.json",
    create2Report: "config/solidity/O37_10_CREATE2_VECTORS.json",
    staticAnalysisTriage:
      "config/solidity/O37_10_STATIC_ANALYSIS_TRIAGE.json"
  },
  opcodeChecks: {
    methodology:
      "LINEAR_PUSH_AWARE_SCAN_EXCLUDING_TRAILING_CBOR; factory scan includes embedded account creation bytes",
    accountRuntime: scanOpcodes(account.deployedBytecode),
    factoryRuntime: scanOpcodes(factory.deployedBytecode),
    unchangedVerifierValidatedByO37_7ReachabilityTest: true
  },
  securityBoundary: {
    administrator: false,
    ownerOverride: false,
    proxy: false,
    upgrade: false,
    delegatecall: false,
    genericExecution: false,
    mutableVerifier: false,
    modulesOrPluginsOrSessions: false,
    paymasterOrAggregator: false,
    tokenSurface: false,
    duplicateNonceStorage: false,
    externalRpcUsed: false,
    publicDeployment: false,
    publicMutationCount: 0,
    pushPerformed: false
  }
};

const staticAnalysisTriage = {
  schemaVersion: 1,
  phase: "O.37.10",
  tool: "Slither",
  toolVersion: "0.10.4",
  scope: [
    accountSource,
    factorySource
  ],
  status: "COMPLETED_WITH_REVIEWED_FINDINGS",
  formalExternalAudit: false,
  actionableChangesApplied: [
    "factory explicitly implements the verifier-binding interface",
    "unused factory-version source constant removed",
    "both EIP-1559 fee words are consumed and priority fee above max fee is rejected",
    "permissionless recovery settlements reject execution-lock reentrancy"
  ],
  acceptedDetectorFamilies: {
    reentrancy:
      "execution lock is set before each external action; every action and both permissionless settlements reject the lock; malicious-recipient regression proves settlement cannot reenter",
    strictEquality:
      "zero timestamp is the exact no-pending-state sentinel in aggregate views",
    timestamp:
      "fixed recovery delay and expiry comparisons are required lifecycle rules",
    assembly:
      "bounded canonical 64-byte binding decode and fixed-word calldata reads are length and range checked",
    cyclomaticComplexity:
      "one closed eight-action decoder prevents alternate dispatch and generic execution",
    lowLevelCalls:
      "EntryPoint prefund, typed native transfer, factory STATICCALL, and verifier STATICCALL are the reviewed bounded calls",
    tooManyDigits:
      "detector applies to type(PhilCoreV2MinimalAccountV2).creationCode syntax, not a numeric literal",
    immutableState:
      "validator verifier kind remains in frozen O.37.9 slot 0 and has no mutation surface"
  },
  remainingUntriagedFindings: 0,
  highOrCriticalUnmitigatedFindings: 0,
  regressionTest:
    "test/unit/o37-10-v2-minimal-account.test.cjs",
  externalAuditStillRequiredBeforePublicDeployment: true
};

const outputs = new Map([
  [
    "config/solidity/O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_EVIDENCE.json",
    implementationEvidence
  ],
  ["config/solidity/O37_10_SIZE_REPORT.json", sizeReport],
  ["config/solidity/O37_10_ABI_REPORT.json", abiReport],
  ["config/solidity/O37_10_STORAGE_LAYOUT_REPORT.json", storageReport],
  ["config/solidity/O37_10_CREATE2_VECTORS.json", create2Report],
  [
    "config/solidity/O37_10_STATIC_ANALYSIS_TRIAGE.json",
    staticAnalysisTriage
  ]
]);

for (const [relativePath, value] of outputs) {
  const expected = `${JSON.stringify(value, null, 2)}\n`;
  const absolutePath = path.join(root, relativePath);
  if (checkOnly) {
    if (!fs.existsSync(absolutePath)) {
      throw new Error(`O37_10_EVIDENCE_MISSING:${relativePath}`);
    }
    const current = fs.readFileSync(absolutePath, "utf8");
    if (current !== expected) {
      throw new Error(`O37_10_EVIDENCE_STALE:${relativePath}`);
    }
  } else {
    fs.writeFileSync(absolutePath, expected);
  }
}

console.log(
  checkOnly
    ? "O.37.10 deterministic implementation evidence is current"
    : "Generated O.37.10 deterministic implementation evidence"
);
