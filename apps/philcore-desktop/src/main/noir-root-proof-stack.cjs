"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

require("tsx/cjs");
const {
  AbiCoder,
  getBytes,
  hexlify,
  keccak256,
  toUtf8Bytes
} = require("ethers");
const {
  createPhilRootProofPublicInputsV1,
  packPhilRootProofPublicInputsV1
} = require("../../../phil-device-sdk/src/rootProofV1.ts");
const {
  UNLOCK_PROOF_SCHEMA_VERSION,
  UNLOCK_PROOF_TYPE
} = require("../../../phil-device-sdk/src/hashes.ts");

const abiCoder = AbiCoder.defaultAbiCoder();

const PHIL_NOIR_ROOT_PROOF_ALPHA_CLASSIFICATION =
  "PHIL_NOIR_ULTRA_KECCAK_ZK_HONK_LOCAL_ALPHA_V1";
const PHIL_NOIR_ROOT_PROOF_TYPE =
  "phil-noir-ultra-keccak-zk-honk-garaga-v1";
const NARGO_VERSION = "1.0.0-beta.16";
const BB_VERSION = "3.0.0-nightly.20251104";
const EXPECTED_NARGO_SHA256 =
  "7960d2a6fbcfa547ef52b8fdd8c158e2eb6a1a753500198bbe7711efe50c5fce";
const EXPECTED_BB_SHA256 =
  "fe5cdb8b85c2f76d806ab86fdfff450cf5c25b017c6b94c7a69f187c02bea565";
// Extracted executable hashes from the official, archive-checksum-pinned
// assets in config/ci/starknet-toolchain-assets.json.
const EXPECTED_NARGO_SHA256_BY_PLATFORM = Object.freeze({
  "darwin-arm64": EXPECTED_NARGO_SHA256,
  "linux-x64": "05514ed29c47d1c348234212b8e574f77949df5435dca692c1d7471bc3d458db"
});
const EXPECTED_BB_SHA256_BY_PLATFORM = Object.freeze({
  "darwin-arm64": EXPECTED_BB_SHA256,
  "linux-x64": "1c28d0bcd137ee1101eb12df8274c9118a4dda48b74872bae067e3c63879a7d0"
});
const EXPECTED_NARGO_MANIFEST_SHA256 =
  "b6c3ff90580f7e3b05d9c64723a024b2bae3092f69bb5df9a868b3e7f43c3c30";
const EXPECTED_CIRCUIT_SHA256 =
  "c94dcfa3db7576536df5c92f6b97e303d314e5fc75937e886d92dc31c22f6f6e";
const EXPECTED_VERIFICATION_KEY_SHA256 =
  "c830f13279278714cec8da9dc9e0114705d8f6eaf4a90c72b8c3b7b660abf3fd";
const EXPECTED_DESCRIPTOR_SHA256 =
  "0086db6aa2a7acc274eec859492def616215dbcd07c6e83f271d1a3b4d1d8aa1";
const EXPECTED_PROOF_DESCRIPTOR_HASH =
  "0xccc5b3202fdccaa2378075eb21ad8f0180961b12a937b0a37fcac79a8851f135";
const LOCAL_ALPHA_SCOPE_ID = keccak256(
  toUtf8Bytes("PHIL_DESKTOP_LOCAL_ALPHA_EXCEPTIONAL_SCOPE_V1")
);
const LOCAL_ALPHA_SCOPE_EPOCH = "1";

function approved(value) {
  return { status: "approved", value };
}

function failed(message) {
  return {
    status: "failed",
    error: {
      code: "PHIL_NOIR_ROOT_PROOF_FAILED",
      message: sanitizeError(message)
    }
  };
}

function sanitizeError(value) {
  return String(value || "Noir root proof failed")
    .replace(/0x[0-9a-fA-F]{64}/gu, "0x[redacted-bytes32]")
    .replace(/philSecret|phil_secret|nullifierSeed|nullifier_seed/giu, "[redacted-witness-field]")
    .slice(0, 500);
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function assertRegularFile(filePath, label) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file`);
  }
}

function assertExecutable(filePath, expectedHashes, label) {
  assertRegularFile(filePath, label);
  if ((fs.statSync(filePath).mode & 0o111) === 0) {
    throw new Error(`${label} is not executable`);
  }
  if (!expectedHashes.includes(sha256File(filePath))) {
    throw new Error(`${label} hash mismatch`);
  }
}

function expectedExecutableHash(platformHashes, label) {
  const platformKey = `${process.platform}-${process.arch}`;
  const expectedHash = platformHashes[platformKey];
  if (!expectedHash) {
    throw new Error(`${label} is unsupported on ${platformKey}`);
  }
  return expectedHash;
}

function packagedSignedToolHash(repositoryRoot, resourceName) {
  const manifestPath = path.join(
    repositoryRoot,
    "config/release/philcore-desktop-local-alpha.json"
  );
  if (!fs.existsSync(manifestPath)) return undefined;
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (manifest?.sourceTree?.dirty || manifest?.securityStatus?.productionApproved) return undefined;
    return manifest?.bundledResources?.[resourceName]?.sha256;
  } catch {
    return undefined;
  }
}

function firstExisting(paths) {
  return paths.find((candidate) => candidate && fs.existsSync(candidate));
}

function resolveNoirRootProofPaths(repositoryRoot, overrides = {}) {
  const arch = process.arch === "arm64" ? "darwin-arm64" : "darwin-x64";
  const cacheRoot = process.env.PHIL_STEP3_CACHE_DIR
    || path.join(os.homedir(), ".cache/phil-v1-step3");
  const nargoPath = firstExisting([
    overrides.nargoPath,
    process.env.PHILCORE_NOIR_NARGO_BIN,
    path.join(repositoryRoot, "bin", arch, "nargo"),
    path.join(cacheRoot, `toolchains/nargo-${NARGO_VERSION}/nargo`)
  ]);
  const bbPath = firstExisting([
    overrides.bbPath,
    process.env.PHILCORE_NOIR_BB_BIN,
    path.join(repositoryRoot, "bin", arch, "bb"),
    path.join(cacheRoot, `toolchains/bb-${BB_VERSION}/bb`)
  ]);
  const circuitRoot = path.join(repositoryRoot, "proofs/phil-v1-step3-noir");
  return Object.freeze({
    repositoryRoot,
    circuitRoot,
    nargoPath,
    bbPath,
    nargoManifestPath: path.join(circuitRoot, "Nargo.toml"),
    circuitSourcePath: path.join(circuitRoot, "src/main.nr"),
    verificationKeyPath: path.join(circuitRoot, "artifacts/vk"),
    descriptorPath: path.join(circuitRoot, "artifacts/descriptor.json")
  });
}

function validateNoirRootProofPaths(paths) {
  if (!paths.nargoPath || !paths.bbPath) {
    throw new Error("pinned Noir root-proof toolchain is unavailable");
  }
  assertExecutable(paths.nargoPath, [
    expectedExecutableHash(EXPECTED_NARGO_SHA256_BY_PLATFORM, "nargo"),
    packagedSignedToolHash(paths.repositoryRoot, "noirNargo")
  ].filter(Boolean), "nargo");
  assertExecutable(paths.bbPath, [
    expectedExecutableHash(EXPECTED_BB_SHA256_BY_PLATFORM, "barretenberg"),
    packagedSignedToolHash(paths.repositoryRoot, "noirBarretenberg")
  ].filter(Boolean), "barretenberg");
  for (const [filePath, label] of [
    [paths.nargoManifestPath, "Noir manifest"],
    [paths.circuitSourcePath, "Noir circuit"],
    [paths.verificationKeyPath, "verification key"],
    [paths.descriptorPath, "proof descriptor"]
  ]) assertRegularFile(filePath, label);

  for (const [filePath, expectedHash, label] of [
    [paths.nargoManifestPath, EXPECTED_NARGO_MANIFEST_SHA256, "Noir manifest"],
    [paths.circuitSourcePath, EXPECTED_CIRCUIT_SHA256, "Noir circuit"],
    [paths.verificationKeyPath, EXPECTED_VERIFICATION_KEY_SHA256, "verification key"],
    [paths.descriptorPath, EXPECTED_DESCRIPTOR_SHA256, "proof descriptor"]
  ]) {
    if (sha256File(filePath) !== expectedHash) throw new Error(`${label} hash mismatch`);
  }

  const descriptorDocument = JSON.parse(fs.readFileSync(paths.descriptorPath, "utf8"));
  const circuitHash = keccak256(fs.readFileSync(paths.circuitSourcePath));
  const verificationKeyHash = keccak256(fs.readFileSync(paths.verificationKeyPath));
  if (descriptorDocument?.descriptor?.circuitOrProgramId !== circuitHash) {
    throw new Error("Noir circuit does not match the accepted proof descriptor");
  }
  if (descriptorDocument?.descriptor?.verificationKeyHash !== verificationKeyHash) {
    throw new Error("verification key does not match the accepted proof descriptor");
  }
  if (descriptorDocument?.proofDescriptorHash !== EXPECTED_PROOF_DESCRIPTOR_HASH) {
    throw new Error("proof descriptor identity mismatch");
  }
  return Object.freeze({ paths, descriptorDocument });
}

function bytes32Array(value, label) {
  const bytes = Array.from(getBytes(value));
  if (bytes.length !== 32) throw new Error(`${label} must be bytes32`);
  return bytes;
}

function proverToml(input) {
  const packed = packPhilRootProofPublicInputsV1(input.publicInputs).felts;
  const names = [
    "scoped_owner_commitment_high",
    "scoped_owner_commitment_low",
    "scope_id_high",
    "scope_id_low",
    "scope_instance_high",
    "scope_instance_low",
    "scope_epoch",
    "authorization_envelope_digest_high",
    "authorization_envelope_digest_low",
    "root_proof_nullifier_high",
    "root_proof_nullifier_low",
    "proof_descriptor_hash_high",
    "proof_descriptor_hash_low"
  ];
  const lines = [
    `phil_secret = [${bytes32Array(input.philSecret, "philSecret").join(", ")}]`,
    `nullifier_seed = [${bytes32Array(input.nullifierSeed, "nullifierSeed").join(", ")}]`,
    ""
  ];
  for (let index = 0; index < names.length; index += 1) {
    lines.push(`${names[index]} = "${packed[index]}"`);
  }
  return `${lines.join("\n")}\n`;
}

function expectedPackedPublicInputBytes(publicInputs) {
  return Buffer.concat(packPhilRootProofPublicInputsV1(publicInputs).felts.map((value) => {
    const encoded = BigInt(value).toString(16).padStart(64, "0");
    return Buffer.from(encoded, "hex");
  }));
}

function collectChild(child, label) {
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > 64 * 1024) child.kill("SIGKILL");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      if (stderr.length > 64 * 1024) child.kill("SIGKILL");
    });
    child.on("error", reject);
    child.on("close", (code, signal) => {
      if (code !== 0) {
        reject(new Error(`${label} exited ${code ?? signal}: ${sanitizeError(stderr)}`));
      } else {
        resolve({ stdout, stderr });
      }
    });
  });
}

function runChecked(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: options.timeoutMs || 120_000
  });
  if (result.error || result.status !== 0) {
    throw new Error(`${options.label || path.basename(command)} failed: ${sanitizeError(result.stderr || result.error?.message)}`);
  }
  return result;
}

function copyCircuitProject(paths, temporaryRoot) {
  fs.copyFileSync(paths.nargoManifestPath, path.join(temporaryRoot, "Nargo.toml"));
  fs.cpSync(path.join(paths.circuitRoot, "src"), path.join(temporaryRoot, "src"), {
    recursive: true,
    dereference: false
  });
}

async function proveNoirRootProofV1(input) {
  const validated = validateNoirRootProofPaths(input.paths);
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phil-noir-root-proof-"));
  fs.chmodSync(temporaryRoot, 0o700);
  const timeoutMs = Math.max(10_000, Math.min(input.timeoutMs || 120_000, 300_000));
  let nargoChild;
  let bbChild;
  let timer;
  try {
    copyCircuitProject(validated.paths, temporaryRoot);
    runChecked(validated.paths.nargoPath, [
      "compile", "--package", "phil_v1_step3_root_proof", "--silence-warnings"
    ], { cwd: temporaryRoot, timeoutMs, label: "Noir compilation" });

    const target = path.join(temporaryRoot, "target");
    const output = path.join(temporaryRoot, "proof-output");
    const proverPipe = path.join(temporaryRoot, "Runtime.toml");
    const witnessPipe = path.join(target, "runtime_witness.gz");
    fs.mkdirSync(output, { recursive: true, mode: 0o700 });
    runChecked("/usr/bin/mkfifo", [proverPipe], { cwd: temporaryRoot, label: "prover input pipe" });
    runChecked("/usr/bin/mkfifo", [witnessPipe], { cwd: temporaryRoot, label: "witness pipe" });
    fs.chmodSync(proverPipe, 0o600);
    fs.chmodSync(witnessPipe, 0o600);

    const startedAt = Date.now();
    bbChild = spawn(validated.paths.bbPath, [
      "prove", "-s", "ultra_honk", "--oracle_hash", "keccak",
      "-b", path.join(target, "phil_v1_step3_root_proof.json"),
      "-w", witnessPipe,
      "-k", validated.paths.verificationKeyPath,
      "--vk_policy", "check",
      "-o", output,
      "--verify"
    ], { cwd: temporaryRoot, stdio: ["ignore", "pipe", "pipe"] });
    nargoChild = spawn(validated.paths.nargoPath, [
      "execute", "runtime_witness",
      "--package", "phil_v1_step3_root_proof",
      "--prover-name", "Runtime",
      "--silence-warnings"
    ], { cwd: temporaryRoot, stdio: ["ignore", "pipe", "pipe"] });

    const writeProverInput = new Promise((resolve, reject) => {
      const stream = fs.createWriteStream(proverPipe, { encoding: "utf8", mode: 0o600 });
      stream.on("error", reject);
      stream.on("finish", resolve);
      stream.end(proverToml(input));
    });
    timer = setTimeout(() => {
      nargoChild?.kill("SIGKILL");
      bbChild?.kill("SIGKILL");
    }, timeoutMs);
    await Promise.all([
      collectChild(nargoChild, "Noir witness generation"),
      collectChild(bbChild, "Barretenberg proof generation"),
      writeProverInput
    ]);
    clearTimeout(timer);
    timer = undefined;

    const proof = fs.readFileSync(path.join(output, "proof"));
    const publicInputBytes = fs.readFileSync(path.join(output, "public_inputs"));
    const expected = expectedPackedPublicInputBytes(input.publicInputs);
    if (publicInputBytes.length !== expected.length
      || !crypto.timingSafeEqual(publicInputBytes, expected)) {
      throw new Error("Barretenberg public inputs do not match the accepted Phil binding");
    }
    return Object.freeze({
      proof: hexlify(proof),
      publicInputBytes: hexlify(publicInputBytes),
      proofDigest: keccak256(proof),
      proofByteLength: proof.length,
      publicInputByteLength: publicInputBytes.length,
      durationMs: Date.now() - startedAt,
      rootPublicInputs: input.publicInputs,
      proofDescriptorHash: validated.descriptorDocument.proofDescriptorHash,
      witnessFileUsed: false,
      witnessPipeUsed: true,
      proverInputFileUsed: false,
      proverInputPipeUsed: true,
      serializedPrivateMaterialReturned: false
    });
  } finally {
    if (timer) clearTimeout(timer);
    nargoChild?.kill("SIGKILL");
    bbChild?.kill("SIGKILL");
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function verifyNoirRootProofV1(input) {
  const validated = validateNoirRootProofPaths(input.paths);
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phil-noir-root-verify-"));
  fs.chmodSync(temporaryRoot, 0o700);
  try {
    const proofPath = path.join(temporaryRoot, "proof");
    const publicInputsPath = path.join(temporaryRoot, "public_inputs");
    fs.writeFileSync(proofPath, Buffer.from(getBytes(input.proof)), { mode: 0o600 });
    fs.writeFileSync(publicInputsPath, Buffer.from(getBytes(input.publicInputBytes)), { mode: 0o600 });
    const expected = expectedPackedPublicInputBytes(input.publicInputs);
    const actual = fs.readFileSync(publicInputsPath);
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      throw new Error("root-proof public input bytes do not match the expected binding");
    }
    const startedAt = Date.now();
    runChecked(validated.paths.bbPath, [
      "verify", "-s", "ultra_honk", "--oracle_hash", "keccak",
      "-i", publicInputsPath,
      "-p", proofPath,
      "-k", validated.paths.verificationKeyPath
    ], { cwd: temporaryRoot, timeoutMs: input.timeoutMs, label: "Barretenberg verification" });
    return Object.freeze({ verified: true, durationMs: Date.now() - startedAt });
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

function factShapePreview(proofInputHash) {
  const raw = String(proofInputHash).slice(2).padStart(64, "0");
  return Object.freeze({
    factShapeReference: "[fact_high, fact_low]",
    factHigh: `0x${raw.slice(0, 32)}`,
    factLow: `0x${raw.slice(32)}`,
    sourceProofInputHash: proofInputHash,
    ordering: "fact_high_then_fact_low",
    factPublished: false,
    onChainRegistered: false
  });
}

function createNoirRootProofStack(options) {
  const paths = resolveNoirRootProofPaths(options.repositoryRoot, options);
  const validated = validateNoirRootProofPaths(paths);
  const proofDescriptorHash = validated.descriptorDocument.proofDescriptorHash;

  return Object.freeze({
    classification: PHIL_NOIR_ROOT_PROOF_ALPHA_CLASSIFICATION,
    proofType: PHIL_NOIR_ROOT_PROOF_TYPE,
    paths,
    async generateActionUnlockProof(input) {
      try {
        const draft = input.authorizationPackageDraft;
        const context = {
          requestId: `${input.requestId}:witness`,
          authorizationPackageDraftId: draft.authorizationPackageDraftId,
          ownerCommitment: draft.binding.ownerCommitment,
          nullifier: draft.nullifierReference.nullifier,
          sessionId: draft.binding.sessionId,
          applicationId: draft.binding.applicationId,
          auditCorrelationId: input.auditCorrelationId,
          issuedAt: input.issuedAt,
          expiresAt: input.expiresAt,
          metadata: {
            actionHash: draft.hashSummary.actionHash,
            policyHash: draft.hashSummary.policyHash,
            proofInputHash: draft.hashSummary.proofInputHash
          }
        };
        const availability = await input.witnessProvider.checkAvailability(context);
        if (!availability.available) throw new Error(availability.reason || "protected witness unavailable");
        const handleResult = await input.witnessProvider.prepareWitnessHandle(context);
        if (handleResult.status !== "approved" || !handleResult.value?.handle) {
          throw new Error(handleResult.error?.message || "protected witness handle rejected");
        }
        const scopeInstance = keccak256(abiCoder.encode(
          ["bytes32", "bytes32"],
          [draft.binding.ownerCommitment, draft.hashSummary.actionHash]
        ));
        const generated = await input.witnessProvider.consumeWitnessForProving(
          handleResult.value.handle,
          draft,
          async (witness) => {
            const rootPublicInputs = createPhilRootProofPublicInputsV1({
              philSecret: witness.philSecret,
              nullifierSeed: witness.nullifierSeed,
              scopeId: LOCAL_ALPHA_SCOPE_ID,
              scopeInstance,
              scopeEpoch: LOCAL_ALPHA_SCOPE_EPOCH,
              authorizationEnvelopeDigest: draft.hashSummary.proofInputHash,
              proofDescriptorHash
            });
            return proveNoirRootProofV1({
              paths,
              philSecret: witness.philSecret,
              nullifierSeed: witness.nullifierSeed,
              publicInputs: rootPublicInputs,
              timeoutMs: input.timeoutMs
            });
          }
        );
        return approved({
          proofGenerationArtifactId: `${input.requestId}:noir-generation`,
          status: "proof_generated",
          outcome: "proof_generated",
          binding: {
            authorizationPackageDraftId: draft.authorizationPackageDraftId,
            proofInputHash: draft.hashSummary.proofInputHash,
            authorizationEnvelopeDigest: draft.hashSummary.proofInputHash,
            rootProofNullifier: generated.rootPublicInputs.rootProofNullifier,
            auditCorrelationId: input.auditCorrelationId
          },
          publicInputs: draft.actionUnlockPublicInputDraft.publicInputs,
          rootPublicInputs: generated.rootPublicInputs,
          proofInputHash: draft.hashSummary.proofInputHash,
          proofArtifact: {
            proofArtifactId: `${input.requestId}:noir-proof`,
            proofType: PHIL_NOIR_ROOT_PROOF_TYPE,
            proofSuite: "Noir + Barretenberg UltraKeccakZK Honk + Garaga",
            proofDigest: generated.proofDigest,
            proofByteLength: generated.proofByteLength,
            publicInputByteLength: generated.publicInputByteLength,
            proofBlobIncluded: false,
            proofBytesLogged: false,
            nonSecretProofArtifact: true,
            containsWitnessOpenings: false,
            safeForExternalVerifierTransmission: true,
            executableByAdapters: false,
            classification: PHIL_NOIR_ROOT_PROOF_ALPHA_CLASSIFICATION,
            proof: generated.proof,
            publicInputBytes: generated.publicInputBytes
          },
          summary: {
            durationMs: generated.durationMs,
            publicInputsMatched: true,
            witnessFileUsed: false,
            proverInputFileUsed: false,
            privateWitnessReturned: false
          },
          classification: PHIL_NOIR_ROOT_PROOF_ALPHA_CLASSIFICATION
        });
      } catch (error) {
        return failed(error instanceof Error ? error.message : error);
      }
    },
    async verifyGeneratedActionUnlockProof(input) {
      try {
        const draft = input.authorizationPackageDraft;
        const generation = input.proofGenerationArtifact;
        if (generation.binding.authorizationEnvelopeDigest !== draft.hashSummary.proofInputHash) {
          throw new Error("root proof is not bound to the accepted authorization draft");
        }
        if (generation.rootPublicInputs.proofDescriptorHash !== proofDescriptorHash) {
          throw new Error("root proof descriptor binding mismatch");
        }
        const verification = verifyNoirRootProofV1({
          paths,
          proof: generation.proofArtifact.proof,
          publicInputBytes: generation.proofArtifact.publicInputBytes,
          publicInputs: generation.rootPublicInputs,
          timeoutMs: input.timeoutMs
        });
        return approved({
          proofVerificationResultId: `${input.requestId}:noir-verification`,
          status: "proof_verified",
          outcome: "proof_verified",
          binding: {
            authorizationPackageDraftId: draft.authorizationPackageDraftId,
            proofGenerationArtifactId: generation.proofGenerationArtifactId,
            proofArtifactId: generation.proofArtifact.proofArtifactId,
            proofInputHash: draft.hashSummary.proofInputHash,
            rootProofNullifier: generation.rootPublicInputs.rootProofNullifier,
            auditCorrelationId: input.auditCorrelationId
          },
          publicInputs: draft.actionUnlockPublicInputDraft.publicInputs,
          rootPublicInputs: generation.rootPublicInputs,
          proofInputHash: draft.hashSummary.proofInputHash,
          proofVerifiedLocally: true,
          factShapePreview: factShapePreview(draft.hashSummary.proofInputHash),
          summary: { durationMs: verification.durationMs },
          classification: PHIL_NOIR_ROOT_PROOF_ALPHA_CLASSIFICATION
        });
      } catch (error) {
        return failed(error instanceof Error ? error.message : error);
      }
    },
    finalizeAuthorizationPackage(input) {
      try {
        const draft = input.authorizationPackageDraft;
        const generation = input.proofGenerationArtifact;
        const verification = input.proofVerificationResult;
        if (!verification.proofVerifiedLocally) throw new Error("verified root proof required");
        const publicInputs = draft.actionUnlockPublicInputDraft.publicInputs;
        return approved({
          finalizedAuthorizationPackageId: `${input.requestId}:noir-gated-finalized-package`,
          status: "authorization_package_finalized",
          outcome: "authorization_package_finalized",
          binding: {
            authorizationPackageDraftId: draft.authorizationPackageDraftId,
            proofGenerationArtifactId: generation.proofGenerationArtifactId,
            proofVerificationResultId: verification.proofVerificationResultId,
            sessionId: draft.binding.sessionId,
            applicationId: draft.binding.applicationId,
            intentId: draft.binding.intentId,
            capabilityName: draft.binding.capabilityName,
            ownerCommitment: draft.binding.ownerCommitment,
            proofInputHash: draft.hashSummary.proofInputHash,
            rootProofNullifier: generation.rootPublicInputs.rootProofNullifier,
            auditCorrelationId: input.auditCorrelationId
          },
          actionUnlockAuthorization: {
            version: UNLOCK_PROOF_SCHEMA_VERSION,
            proofType: UNLOCK_PROOF_TYPE,
            ...publicInputs,
            expiry: BigInt(publicInputs.expiry).toString(),
            proofInputHash: draft.hashSummary.proofInputHash,
            factShapeReference: "[fact_high, fact_low]"
          },
          rootProofAuthorization: {
            proofType: PHIL_NOIR_ROOT_PROOF_TYPE,
            descriptorHash: proofDescriptorHash,
            publicInputs: generation.rootPublicInputs,
            proofDigest: generation.proofArtifact.proofDigest,
            verifiedLocally: true
          },
          proofArtifact: {
            ...generation.proofArtifact,
            proof: undefined,
            publicInputBytes: undefined
          },
          evidence: {
            rootProofGenerated: true,
            rootProofVerifiedLocally: true,
            rootProofDescriptorMatched: true,
            rootProofAuthorizationDigestMatched: true,
            legacyLocalActionFixtureUsedAfterRootProofGate: true,
            publicInputsMatched: true,
            proofInputHashMatched: true
          },
          factShapePreview: factShapePreview(draft.hashSummary.proofInputHash),
          validity: { issuedAt: input.issuedAt, expiresAt: input.expiresAt, expired: false },
          limitations: [
            "local_alpha_only",
            "desktop_proving_only",
            "no_public_network_activity",
            "no_starknet_deployment",
            "legacy_local_action_fixture_after_verified_noir_root_proof"
          ],
          authorizationPackageFinalized: true,
          proofGenerated: true,
          proofVerifiedLocally: true,
          verifiedFactPublished: false,
          onChainVerificationPerformed: false,
          nullifierConsumed: false,
          adapterExecutionAllowed: false,
          contractExecutionAllowed: false,
          transactionSubmitted: false,
          executableByApplications: false,
          witnessMaterialExposed: false,
          persisted: false,
          classification: PHIL_NOIR_ROOT_PROOF_ALPHA_CLASSIFICATION
        });
      } catch (error) {
        return failed(error instanceof Error ? error.message : error);
      }
    }
  });
}

module.exports = {
  BB_VERSION,
  EXPECTED_BB_SHA256,
  EXPECTED_NARGO_SHA256,
  LOCAL_ALPHA_SCOPE_EPOCH,
  LOCAL_ALPHA_SCOPE_ID,
  NARGO_VERSION,
  PHIL_NOIR_ROOT_PROOF_ALPHA_CLASSIFICATION,
  PHIL_NOIR_ROOT_PROOF_TYPE,
  createNoirRootProofStack,
  proveNoirRootProofV1,
  resolveNoirRootProofPaths,
  validateNoirRootProofPaths,
  verifyNoirRootProofV1
};
