"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { ethers, network } = require("hardhat");

const helper = require("../../test/helpers/phil-v1-step6c-fixture.cjs");
const journal = require("../../apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts");

const ROOT = path.resolve(__dirname, "../..");
const FIXTURE_RELATIVE = "config/adapters/PHIL_V1_STEP6C_LOCAL_COMPOSITION_FIXTURE.json";
const MANIFEST_RELATIVE = "docs/reference/PHIL_V1_STEP6C_ARTIFACT_MANIFEST.json";
const REPORT_RELATIVE = "docs/reference/PHIL_V1_STEP6C_IMPLEMENTATION_REPORT.md";
const GENERATOR_RELATIVE = "scripts/security/generate-phil-v1-step6c-artifacts.cjs";
const TEST_PATHS = Object.freeze([
  "test/helpers/phil-v1-step6c-fixture.cjs",
  "test/unit/phil-v1-step6c-wire.test.cjs",
  "test/unit/phil-v1-step6c-records.test.cjs",
  "test/unit/phil-v1-step6c-entrypoint.test.cjs",
  "test/unit/phil-v1-step6c-journal.test.cjs",
  "test/unit/phil-v1-step6c-desktop.test.cjs",
  "test/unit/phil-v1-step6c-ios-synthetic.test.cjs"
]);
const SUPPORT_PATHS = Object.freeze([
  "hardhat.phil-v1-step6c.config.cjs",
  "package.json",
  "package-lock.json",
  "config/ci/classification.json",
  GENERATOR_RELATIVE
]);
const DOCUMENT_PATHS = Object.freeze([
  "README.md",
  "docs/CANONICAL_DOCS.md",
  "docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md",
  "docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md",
  "docs/reference/PHIL_V1_STEP4_REFERENCE_MANIFEST_MAINTENANCE.md",
  "docs/reference/PHIL_V1_STEP6B_LOCAL_SMART_ACCOUNT_GATE.md",
  "docs/reference/PHIL_V1_STEP6C_IMPLEMENTATION_BLOCKER_NONCE_CATALOG.md",
  "docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_A158688.md",
  "docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_AEA7359.md",
  "docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_591F6B6.md",
  "docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_5AB4650.md",
  "docs/reference/PHIL_V1_STEP6C_INDEPENDENT_REVIEW_22B5CF3.md",
  "docs/reference/PHIL_V1_STEP6C_IMPLEMENTATION_PACKET.md",
  "docs/reference/PHIL_V1_STEP6C_IMPLEMENTATION_REPORT.md",
  "docs/reference/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_PRODUCT_COMPOSITION_GATE.md",
  "docs/security/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_THREAT_MODEL.md"
]);
const WRITE = process.argv.includes("--write");

function normalize(_key, value) {
  if (typeof value === "bigint") return value.toString(10);
  if (value instanceof Uint8Array) return ethers.hexlify(value);
  return value;
}

function canonicalJson(value) {
  return `${JSON.stringify(value, normalize, 2)}\n`;
}

function sha256Bytes(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function fileRecord(relative) {
  const bytes = fs.readFileSync(path.join(ROOT, relative));
  return Object.freeze({ path: relative, bytes: bytes.length, sha256: sha256Bytes(bytes) });
}

function git(...args) {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim();
}

function sourceIdentity() {
  const exportPath = path.join(ROOT, "config/release/clean-public-source-manifest.json");
  if (!fs.existsSync(exportPath)) {
    const sourceCommit = git("log", "-1", "--format=%H", "--", ...helper.SOURCE_PATHS);
    return { sourceCommit, sourceTree: git("show", "-s", "--format=%T", sourceCommit) };
  }
  // A new public root cannot embed its own commit hash. Preserve the historical
  // evidence identity only while every bound product source byte still matches.
  const exported = JSON.parse(fs.readFileSync(exportPath, "utf8"));
  const binding = exported.step6CHistoricalSourceBinding;
  if (exported.schemaVersion !== 1 || exported.kind !== "philcore-clean-public-source-export" ||
      !binding || !/^[a-f0-9]{40}$/.test(binding.sourceCommit) ||
      !/^[a-f0-9]{40}$/.test(binding.sourceTree) || !Array.isArray(binding.sourceFiles) ||
      binding.sourceFiles.length !== helper.SOURCE_PATHS.length) {
    throw new Error("Clean export Step 6C historical source binding is invalid");
  }
  for (const [index, relative] of helper.SOURCE_PATHS.entries()) {
    const expected = binding.sourceFiles[index];
    const actual = fileRecord(relative);
    if (!expected || expected.path !== relative || expected.bytes !== actual.bytes ||
        expected.sha256 !== actual.sha256) {
      throw new Error(`Clean export Step 6C source binding mismatch: ${relative}`);
    }
  }
  return { sourceCommit: binding.sourceCommit, sourceTree: binding.sourceTree };
}

function transition(current, nextState, recordedAt, evidence = {}) {
  return journal.transitionPhilRoutineJournalRecordV1({
    current,
    expectedGeneration: current.generation,
    expectedRecordHash: current.recordHash,
    nextState,
    recordedAt,
    evidence
  });
}

function compiledArtifactRecord(relative) {
  const artifact = JSON.parse(fs.readFileSync(path.join(ROOT, relative), "utf8"));
  const debug = JSON.parse(fs.readFileSync(path.join(ROOT, relative.replace(/\.json$/, ".dbg.json")), "utf8"));
  const buildInfoPath = path.resolve(path.dirname(path.join(ROOT, relative)), debug.buildInfo);
  const buildInfo = JSON.parse(fs.readFileSync(buildInfoPath, "utf8"));
  const compilerInputSources=Object.entries(buildInfo.input.sources).sort(([a],[b])=>a.localeCompare(b)).map(([sourceName,record])=>{
    const candidates=[path.join(ROOT,sourceName),path.join(ROOT,"node_modules",sourceName)];
    const sourcePath=candidates.find((candidate)=>fs.existsSync(candidate));
    if (!sourcePath || typeof record.content!=="string" || record.content!==fs.readFileSync(sourcePath,"utf8")) {
      throw new Error(`${relative} compiler input ${sourceName} does not match the current exact source`);
    }
    return Object.freeze({source:sourceName,bytes:Buffer.byteLength(record.content),sha256:sha256Bytes(Buffer.from(record.content))});
  });
  const compiledSource = buildInfo.input.sources[artifact.sourceName]?.content;
  if (typeof compiledSource!=="string") throw new Error(`${relative} primary compiler input is missing`);
  return Object.freeze({
    artifact: relative,
    creationCodeBytes: ethers.getBytes(artifact.bytecode).length,
    creationCodeHash: ethers.keccak256(artifact.bytecode),
    runtimeCodeBytes: ethers.getBytes(artifact.deployedBytecode).length,
    runtimeCodeHash: ethers.keccak256(artifact.deployedBytecode),
    source: artifact.sourceName,
    sourceSha256: sha256Bytes(Buffer.from(compiledSource)),
    buildInfoSha256: sha256Bytes(fs.readFileSync(buildInfoPath)),
    compilerInputSources
  });
}

function transitiveSourceRecords() {
  const visited = new Set();
  const visit = (relative) => {
    const normalized=relative.split(path.sep).join("/");
    if (visited.has(normalized)) return;
    visited.add(normalized);
    const source=fs.readFileSync(path.join(ROOT,normalized),"utf8");
    const imports=[...source.matchAll(/(?:from\s+|import\s+(?:[^"']*?\s+from\s+)?)["']([^"']+)["']/g)].map((match)=>match[1]);
    for (const specifier of imports) {
      let resolved;
      if (specifier.startsWith(".")) resolved=path.relative(ROOT,path.resolve(path.dirname(path.join(ROOT,normalized)),specifier));
      else if (normalized.endsWith(".sol")) resolved=path.join("node_modules",specifier);
      else continue;
      if (!path.extname(resolved)) {
        if (fs.existsSync(path.join(ROOT,`${resolved}.ts`))) resolved=`${resolved}.ts`;
        else if (fs.existsSync(path.join(ROOT,`${resolved}.sol`))) resolved=`${resolved}.sol`;
      }
      if (fs.existsSync(path.join(ROOT,resolved))) visit(resolved);
    }
  };
  helper.SOURCE_PATHS.forEach(visit);
  return [...visited].sort().map(fileRecord);
}

async function build() {
  await network.provider.send("evm_setNextBlockTimestamp", [1800000000]);
  await network.provider.send("evm_mine");
  const deployed = await helper.deployStep6CFixture();
  const failed = await helper.buildRequestForNonce(deployed, {
    nonceSequence: 0,
    shouldRevert: true,
    issuedAt: 1800000020,
    sessionLabel: "artifact-failed-n"
  });
  await helper.setNextTimestamp(1800000021);
  const failedTransaction = await deployed.entryPoint.handleOps([failed.userOp], deployed.beneficiary.address);
  const failedReceipt = await failedTransaction.wait();
  if (await deployed.entryPoint.getNonce(deployed.accountAddress, 0)!==1n
    || await deployed.target.recordedSequence()!==0n || failedReceipt.status!==1) {
    throw new Error("failed nonce-0 fixture did not advance the official EntryPoint sequence exactly once");
  }
  const success = await helper.buildRequestForNonce(deployed, {
    nonceSequence: 1,
    shouldRevert: false,
    issuedAt: 1800000030,
    sessionLabel: "artifact-success-n-plus-one"
  });

  let journalRecord = journal.createPhilRoutineJournalRecordV1({
    requestId: success.request.requestId,
    sessionId: success.request.authorizationCore.sessionId,
    recordedAt: 1800000030
  });
  for (const state of [2, 3, 4, 5]) {
    journalRecord = transition(journalRecord, state, BigInt(journalRecord.recordedAt) + 1n);
  }
  const packed = helper.serializePackedUserOperation(success.userOp);
  const scanBlock = await ethers.provider.getBlock("latest");
  const scanStartBlockNumber = scanBlock.number;
  const scanStartBlockHash = scanBlock.hash;
  const targetPreStateHash = journal.derivePhilRoutineTargetPreStateHashV1({
    target: deployed.targetAddress,
    approvedTargetRuntimeCodeHash: deployed.targetCodeHash,
    recordedValueBefore: ethers.ZeroHash,
    recordedSequenceBefore: 0,
    scanStartBlockNumber,
    scanStartBlockHash
  });
  journalRecord = transition(journalRecord, 6, 1800000035, {
    entryPoint: deployed.entryPointAddress,
    sender: deployed.accountAddress,
    userOperationNonce: success.userOp.nonce,
    serializedUserOperationHash: ethers.keccak256(packed),
    officialUserOperationHash: success.userOpHash,
    packedUserOperationBytes: packed,
    target: deployed.targetAddress,
    targetRecordedValueBefore: ethers.ZeroHash,
    targetRecordedSequenceBefore: 0,
    targetPreStateHash,
    scanStartBlockNumber,
    scanStartBlockHash
  });

  const disclosedPrivateKey = ethers.hexlify(helper.syntheticPrivateKey());
  const { sourceCommit, sourceTree } = sourceIdentity();
  const fixture = {
    format: "phil-v1-step6c-local-composition-fixture-v1",
    classification: "disclosed-synthetic-local-hardhat-only",
    generatedAtProtocolTime: "1800000000",
    sourceCommit,
    sourceTree,
    localEnvironment: {
      network: "Hardhat in-process only",
      chainId: "31337",
      entryPointVersion: "0.7.0",
      entryPoint: deployed.entryPointAddress,
      entryPointRuntimeCodeHash: deployed.entryPointCodeHash,
      senderCreator: deployed.senderCreator,
      senderCreatorRuntimeCodeHash: deployed.senderCreatorCodeHash,
      account: deployed.accountAddress,
      accountRuntimeCodeHash: deployed.accountRuntimeCodeHash,
      target: deployed.targetAddress,
      targetRuntimeCodeHash: deployed.targetCodeHash,
      reentrancySlotValue: deployed.reentrancySlot
    },
    implementationIdentity: deployed.identity,
    adapterManifest: deployed.manifest,
    signatureRegistry: deployed.signatureRegistry,
    deviceEnrollment: deployed.enrollment,
    accountConfiguration: deployed.configuration,
    parameterSchemaId: deployed.parameterSchemaId,
    catalog: deployed.catalog,
    capabilityPolicy: deployed.policy,
    disclosedSyntheticKey: {
      privateKey: disclosedPrivateKey,
      publicKeyX963: deployed.enrollment.publicKeyX963,
      purpose: "deterministic local test vectors only",
      secureEnclaveBacked: false,
      userPresenceRequired: false,
      productionSecret: false
    },
    requests: {
      failedNonce0: {
        action: failed.action,
        request: failed.request,
        response: failed.response,
        signature: failed.signature,
        packedUserOperationBytes: helper.serializePackedUserOperation(failed.userOp),
        officialUserOperationHash: failed.userOpHash,
        localTransactionHash: failedReceipt.hash,
        localBlockHash: failedReceipt.blockHash,
        officialEntryPointNonceAfter: "1",
        targetRecordedSequenceAfter: "0"
      },
      successfulNonce1: {
        action: success.action,
        request: success.request,
        response: success.response,
        signature: success.signature,
        packedUserOperationBytes: packed,
        serializedUserOperationHash: ethers.keccak256(packed),
        officialUserOperationHash: success.userOpHash
      }
    },
    journalSubmissionCommit: journalRecord,
    evidenceClassification: {
      physicalDeviceUsed: false,
      secureEnclaveEvidence: false,
      userPresenceEvidence: false,
      externalNetwork: false,
      rpcUsed: false,
      publicBundlerUsed: false,
      transactionBroadcast: false,
      deploymentOutsideEphemeralHardhat: false,
      meaningfulAssets: false,
      realSecretUsed: false,
      productionAuthority: false,
      proofBackendSelected: false,
      step6C2Complete: false,
      finalStep6Complete: false
    }
  };
  const fixtureJson = canonicalJson(fixture);

  const candidateRecords = [
    ...helper.SOURCE_PATHS,
    ...TEST_PATHS,
    ...SUPPORT_PATHS,
    ...DOCUMENT_PATHS.filter((relative)=>fs.existsSync(path.join(ROOT,relative)))
  ].map(fileRecord);
  const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const artifactManifest = {
    format: "phil-v1-step6c-artifact-manifest-v1",
    sourceCommit,
    sourceTree,
    implementationHash: deployed.identity.implementationHash,
    auditStatusHash: deployed.identity.auditStatusHash,
    candidateFiles: candidateRecords,
    fixture: {
      path: FIXTURE_RELATIVE,
      bytes: Buffer.byteLength(fixtureJson),
      sha256: sha256Bytes(fixtureJson)
    },
    compiledContracts: [
      compiledArtifactRecord("artifacts/@account-abstraction/contracts/core/EntryPoint.sol/EntryPoint.json"),
      compiledArtifactRecord("artifacts/@account-abstraction/contracts/core/SenderCreator.sol/SenderCreator.json"),
      compiledArtifactRecord("artifacts/contracts/base/erc4337/PhilV1Step6CAccount.sol/PhilV1Step6CAccount.json"),
      compiledArtifactRecord("artifacts/contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol/PhilV1Step6CHarmlessTarget.json"),
      compiledArtifactRecord("artifacts/contracts/base/erc4337/test/PhilV1Step6CReentrantTarget.sol/PhilV1Step6CReentrantTarget.json")
    ],
    transitiveImportedSources: transitiveSourceRecords(),
    constructorStorageAssertions: {
      entryPoint: (await deployed.account.entryPoint()).toLowerCase(),
      chainId: (await deployed.account.chainId()).toString(),
      executionEnvironmentHash: await deployed.account.executionEnvironmentHash(),
      adapterManifestHash: await deployed.account.adapterManifestHash(),
      signatureRegistryHash: await deployed.account.signatureRegistryHash(),
      deviceEnrollmentHash: await deployed.account.deviceEnrollmentHash(),
      accountConfigurationHash: await deployed.account.accountConfigurationHash(),
      accountRuntimeCodeHash: await deployed.account.accountRuntimeCodeHash(),
      catalogHash: await deployed.account.catalogHash(),
      capabilityPolicyHash: await deployed.account.capabilityPolicyHash(),
      parameterSchemaId: await deployed.account.parameterSchemaId(),
      applicationId: await deployed.account.applicationId(),
      principalIdHash: await deployed.account.principalIdHash(),
      scopedOwnerCommitment: await deployed.account.scopedOwnerCommitment(),
      scopeId: await deployed.account.scopeId(),
      scopeInstance: await deployed.account.scopeInstance(),
      scopeEpoch: (await deployed.account.scopeEpoch()).toString(),
      capabilityId: await deployed.account.capabilityId(),
      capabilityEpoch: (await deployed.account.capabilityEpoch()).toString(),
      policyEpoch: (await deployed.account.policyEpoch()).toString(),
      deviceId: await deployed.account.deviceId(),
      deviceKeyId: await deployed.account.deviceKeyId(),
      deviceEpoch: (await deployed.account.deviceEpoch()).toString(),
      signatureSuiteId: await deployed.account.signatureSuiteId(),
      providerProfileId: await deployed.account.providerProfileId(),
      wireEncodingId: await deployed.account.wireEncodingId(),
      devicePublicKeyX: await deployed.account.devicePublicKeyX(),
      devicePublicKeyY: await deployed.account.devicePublicKeyY(),
      recoveryEpoch: (await deployed.account.recoveryEpoch()).toString(),
      validatorEpoch: (await deployed.account.validatorEpoch()).toString(),
      approvedTarget: (await deployed.account.approvedTarget()).toLowerCase(),
      approvedTargetRuntimeCodeHash: await deployed.account.approvedTargetRuntimeCodeHash(),
      actionTypeHash: await deployed.account.actionTypeHash(),
      nonceKey: (await deployed.account.nonceKey()).toString(),
      maximumValueWei: (await deployed.account.maximumValueWei()).toString(),
      maximumTotalFeeWei: (await deployed.account.maximumTotalFeeWei()).toString(),
      profilePolicyValidAfter: (await deployed.account.profilePolicyValidAfter()).toString(),
      profilePolicyValidUntil: (await deployed.account.profilePolicyValidUntil()).toString(),
      catalogDisplayTextHashes: await Promise.all([0,1,2,3,4,5].map((index)=>deployed.account.catalogDisplayTextHashes(index)))
    },
    inheritedIdentities: {
      step5RegistryHash: deployed.signatureRegistry.inheritedRegistryHash,
      step5RegistryEpoch: deployed.signatureRegistry.inheritedRegistryEpoch,
      routineRegistryHash: deployed.signatureRegistry.registryHash,
      routineRegistryEpoch: deployed.signatureRegistry.registryEpoch
    },
    semanticIdentities: {
      domainHashes: helper.auth.PHIL_ROUTINE_DOMAIN_HASHES_V1,
      parameterSchemaId: deployed.parameterSchemaId,
      capabilityId: deployed.policy.capabilityId,
      catalogHash: deployed.catalog.catalogHash,
      catalogEntries: deployed.catalog.entries,
      capabilityPolicyHash: deployed.policy.capabilityPolicyHash,
      profilePolicySeconds: helper.auth.PHIL_STEP6C_PROFILE_POLICY_SECONDS,
      requestSeconds: helper.auth.PHIL_STEP6C_REQUEST_SECONDS
    },
    abiTypeInventory: {
      implementationIdentity: ["bytes32","bytes32[6]"],
      executionEnvironment: ["bytes32","uint8","uint256","bytes32","bytes32","bytes32","bytes32","address","bytes32","address","bytes32","bool","bool","bool"],
      deviceEnrollment: ["bytes32","bytes32","bytes32","uint64","uint64","bytes32","bytes32","bytes32","bytes32","bytes","bytes32","bytes32","bytes32","bool","bool","uint8"],
      applicationPrincipal: ["bytes32","bytes32"],
      scopeInstance: ["bytes32","bytes32","bytes32","bytes32","address"],
      parameterSchema: ["bytes32","address","bytes32","bytes4","bytes32"],
      capability: ["bytes32","bytes32","bytes32","address","bytes32","bytes32","bytes32"],
      accountConfiguration: ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint64","uint64","uint64","address","bytes32","bytes32","bytes32","address","bytes32","bytes32","uint192","uint256","uint256"],
      catalogEntry: ["bytes32","uint8","bytes32","bytes32","bytes32"],
      catalog: ["bytes32","bytes32[6]"],
      capabilityPolicy: ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint64","uint64","uint64","bytes32","uint64","uint64","bytes32","bytes32","bytes32","bytes32","bytes32","address","bytes32","bytes32","uint256","uint256","uint48","uint48","bool"],
      humanPresentation: ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint64","bytes32","bytes32","address","bytes32","address","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint256","uint256","uint48","uint48","bytes32","uint64","bytes32","uint64","bool","bool","bool"],
      authorizationCore: ["bytes32","bytes32","bytes32","bytes32","uint64","uint64","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32"],
      approvalNonce: ["bytes32","bytes32","bytes32","bytes32"],
      authorizationRequest: ["bytes32","bytes32","bytes32","bytes32"],
      authorizationResponse: ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint64","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32"],
      authorizationReceipt: ["bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","bytes32","uint256","uint256","uint64","bool","bool","bool","bool"],
      eventCommitment: ["address","bytes32","bytes32","bytes32","bytes32","bytes32","uint256","bytes32","bytes32"],
      journalRecord: ["bytes32","uint64","bytes32","bytes32","bytes32","uint8","address","address","uint256","bytes32","bytes32","bytes","address","bytes32","uint64","bytes32","uint64","bytes32","bytes32","bytes32","bytes32","uint64","bytes32"],
      platformSigningPrehash: ["bytes32","bytes32"],
      packedUserOperationV07: ["address","uint256","bytes","bytes","bytes32","uint256","bytes32","bytes","bytes"],
      officialUserOperationHashV07: ["bytes32","address","uint256"],
      journalFrameAad: ["bytes32","bytes32","uint64"],
      targetPreState: ["address","bytes32","bytes32","uint64","uint64","bytes32"],
      finalTargetState: ["address","bytes32","uint64","bytes32","bytes32"],
      routineSignatureRegistryV2: ["bytes32","uint64","uint64","bytes32","bytes32","bytes32","bytes32","uint8","bool","bool"]
    },
    testMatrix: {
      focusedFiles: TEST_PATHS.slice(1),
      literalMochaCases: 37,
      categoriesRequiredByDefinition: 20,
      literalCategoryMap: {
        "1": ["records: constructs the acyclic local profile and independently validates every derived request hash"],
        "2": ["records: keeps schema, capability, catalog, and policy stable while every nonce-bearing request identity changes", "records: rejects an independent substitution of every authorization-core field"],
        "3": ["records: rejects unknown, duplicate, BOM, alternate-scalar, nested, and response JSON substitutions"],
        "4": ["wire: validates X9.63 keys and verifies exactly one raw low-S signature without a second prehash", "wire: strictly parses DER and normalizes high-S while raw input rejects high-S", "wire: rejects nonminimal, negative, zero, trailing, wrong-length, and invalid-key encodings"],
        "5": ["records: rejects independent raw-record and top-level derived-identity substitutions", "EntryPoint: fails closed before execution for wrong signature and packed-operation substitution"],
        "6": ["iOS: derives every displayed field from admitted records and raw calldata", "iOS: rejects selector, value, boolean, trailing-byte, summary, and signing-digest substitution"],
        "7": ["records: rejects calldata, action, request-window, Base-profile, and derived-hash substitution"],
        "8": ["wire: freezes the distinct suite, provider, wire, and terminal SHA-256 prehash identities", "records: constructs the acyclic local profile and independently validates every derived request hash"],
        "9": ["EntryPoint: normally deploys official v0.7 constructor state and the bound local profile"],
        "10": ["EntryPoint: consumes failed nonce n and accepts a fresh signed success at n+1 without a second nonce"],
        "11": ["EntryPoint: consumes failed nonce n and accepts a fresh signed success at n+1 without a second nonce"],
        "12": ["Desktop: snapshots simulation evidence and terminally records an ambiguous submission outcome", "Desktop: fails terminally on policy drift, lock/session replacement, and pre-state drift before commit"],
        "13": ["journal: admits every declared public transition and rejects every other public state pair", "journal: enforces a hash-chained CAS and an evidence-complete point of no return", "journal: round-trips strict journal-record and outer-frame JSON with fresh canonical AES-256-GCM nonces", "journal: publishes a CAS transition only after its injected durable flush succeeds", "Desktop: reconciles a restored state-6 commit to unknown and admits only exact late failed-event evidence", "Desktop: reconciles every pre-submission crash and both submitted receipt outcomes without resubmission", "Desktop: covers the remaining state-6 failure, state-7 unknown, and restored state-8 verifier transitions"],
        "14": ["journal: allows cancellation before commit and makes every post-commit cancellation impossible", "Desktop: serializes cancellation and expiry ahead of any response or submission authority"],
        "15": ["Desktop: serializes response, simulation, commit, execution, cancellation, and restart through the protected lifecycle", "Desktop: serializes cancellation and expiry ahead of any response or submission authority", "Desktop: serializes actual cancel-versus-submission and cancel-versus-receipt races at the point of no return", "Desktop: fails terminally on policy drift, lock/session replacement, and pre-state drift before commit"],
        "16": ["iOS: rejects selector, value, boolean, trailing-byte, summary, and signing-digest substitution", "EntryPoint: consumes failed nonce n and accepts a fresh signed success at n+1 without a second nonce", "EntryPoint: rejects an executing target reentry attempt while preserving the admitted outer action", "Desktop: keeps production sources isolated from public RPC, recovery signers, STWO, generic execution, and runtime-code copying"],
        "17": ["EntryPoint: consumes failed nonce n and accepts a fresh signed success at n+1 without a second nonce"],
        "18": ["Desktop: exposes only the sanitized four-field status and no request, signature, operation, or journal evidence"],
        "19": ["Desktop: exposes no direct account execution path even for a valid approved package", "Desktop: keeps production sources isolated from public RPC, recovery signers, STWO, generic execution, and runtime-code copying"],
        "20": ["Desktop: keeps production sources isolated from public RPC, recovery signers, STWO, generic execution, and runtime-code copying", "iOS: does not relabel the disclosed synthetic key as Secure Enclave or user-presence evidence"]
      },
      independentAcceptance: true
    },
    dependencyVersions: {
      accountAbstraction: packageJson.dependencies?.["@account-abstraction/contracts"] ?? packageJson.devDependencies["@account-abstraction/contracts"],
      nobleCurves: packageJson.dependencies?.["@noble/curves"] ?? packageJson.devDependencies["@noble/curves"],
      ethers: packageJson.dependencies?.ethers ?? packageJson.devDependencies.ethers,
      hardhat: packageJson.devDependencies.hardhat,
      solc: packageJson.devDependencies.solc,
      packageLockSha256: fileRecord("package-lock.json").sha256
    },
    nonclaims: fixture.evidenceClassification
  };
  return { fixtureJson, artifactManifestJson: canonicalJson(artifactManifest) };
}

function writeOrCheck(relative, expected) {
  const target = path.join(ROOT, relative);
  if (WRITE) {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, expected);
    return;
  }
  if (!fs.existsSync(target) || fs.readFileSync(target, "utf8") !== expected) {
    throw new Error(`${relative} is missing or stale`);
  }
}

build().then(({ fixtureJson, artifactManifestJson }) => {
  writeOrCheck(FIXTURE_RELATIVE, fixtureJson);
  writeOrCheck(MANIFEST_RELATIVE, artifactManifestJson);
  console.log(WRITE ? "wrote Step 6C artifacts" : "verified Step 6C artifacts");
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
