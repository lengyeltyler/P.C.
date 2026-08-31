const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const {
  concat,
  keccak256,
  toUtf8Bytes
} = require("ethers");
const {
  PHIL_ZERO_BYTES32,
  derivePhilAuthorizationEnvelopeDigestV1
} = require("../../apps/phil-device-sdk/src/authorizationEnvelopeV1.ts");
const {
  PHIL_PROOF_DESCRIPTOR_V1_HASH,
  PHIL_ROOT_PROOF_PUBLIC_INPUTS_U128X2_V1_ID,
  PHIL_GARAGA_ULTRA_KECCAK_ZK_HONK_CALLDATA_V1_ID,
  PHIL_VERIFIER_BINDING_V1_HASH,
  derivePhilVerifierBindingHashV1,
  derivePhilProofDescriptorHashV1,
  createPhilRootProofPublicInputsV1,
  packPhilRootProofPublicInputsV1
} = require("../../apps/phil-device-sdk/src/rootProofV1.ts");
const {
  derivePhilScopedOwnerCommitmentV1
} = require("../../apps/phil-device-sdk/src/secureIdentityV1.ts");
const { derivePhilIdentityRoot } = require("../../apps/phil-device-sdk/src/identity.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const WRITE = process.argv.includes("--write");
function hashLabel(label) {
  return keccak256(toUtf8Bytes(label));
}

function raw(relative) {
  return new Uint8Array(fs.readFileSync(path.join(REPO_ROOT, relative)));
}

function sha256(relative) {
  return crypto.createHash("sha256").update(raw(relative)).digest("hex");
}

function artifact(relative) {
  const absolute = path.join(REPO_ROOT, relative);
  return {
    path: relative,
    bytes: fs.statSync(absolute).size,
    sha256: sha256(relative),
    keccak256: keccak256(raw(relative))
  };
}

function documentArtifact(relative, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  return {
    path: relative,
    bytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    keccak256: keccak256(bytes)
  };
}

const verifierSourceFiles = fs
  .readdirSync(path.join(REPO_ROOT, "starknet/phil-v1-step3-verifier/src"))
  .filter((name) => name.endsWith(".cairo"))
  .sort()
  .map((name) => `starknet/phil-v1-step3-verifier/src/${name}`);
const verifierChunks = [];
for (const relative of verifierSourceFiles) {
  verifierChunks.push(
    toUtf8Bytes(`${relative.replace("starknet/phil-v1-step3-verifier/", "")}\0`),
    raw(relative)
  );
}

const proofSuiteId = hashLabel("PHIL_NOIR_ULTRA_KECCAK_ZK_HONK_GARAGA_V1");
const proofSystemVersionHash = hashLabel(
  "nargo-1.0.0-beta.16|bb-3.0.0-nightly.20251104|garaga-1.0.1|cairo-2.14.0"
);
const verifierBindingDomain = PHIL_VERIFIER_BINDING_V1_HASH;
const descriptor = {
  descriptorVersionHash: PHIL_PROOF_DESCRIPTOR_V1_HASH,
  proofSuiteId,
  proofSystemVersionHash,
  circuitOrProgramId: keccak256(raw("proofs/phil-v1-step3-noir/src/main.nr")),
  publicInputSchemaId: PHIL_ROOT_PROOF_PUBLIC_INPUTS_U128X2_V1_ID,
  verificationKeyHash: keccak256(raw("proofs/phil-v1-step3-noir/artifacts/vk")),
  verifierCodeHash: keccak256(concat(verifierChunks)),
  verifierBindingHash: PHIL_ZERO_BYTES32,
  codecId: PHIL_GARAGA_ULTRA_KECCAK_ZK_HONK_CALLDATA_V1_ID
};
descriptor.verifierBindingHash = derivePhilVerifierBindingHashV1(descriptor);
const proofDescriptorHash = derivePhilProofDescriptorHashV1(descriptor);

const philSecret = `0x${(0x1234567890n).toString(16).padStart(64, "0")}`;
const nullifierSeed = hashLabel("phil-v1-step3-synthetic-nullifier-seed");
const scopeId = hashLabel("phil-v1-step3-synthetic-scope-id");
const scopeInstance = hashLabel("phil-v1-step3-synthetic-scope-instance");
const scopeEpoch = "7";
const scopedOwnerCommitment = derivePhilScopedOwnerCommitmentV1({
  identityRoot: derivePhilIdentityRoot(philSecret),
  scopeId,
  scopeInstance,
  scopeEpoch
});
const pendingEnvelope = {
  operationClass: 2,
  scopedOwnerCommitment,
  scopeId,
  scopeInstance,
  scopeEpoch,
  principalIdHash: hashLabel("synthetic-principal"),
  capabilityId: PHIL_ZERO_BYTES32,
  capabilityEpoch: "3",
  networkIdHash: hashLabel("SN_SEPOLIA_REFERENCE_ONLY"),
  accountBindingHash: hashLabel("synthetic-starknet-account-binding"),
  adapterId: hashLabel("PHIL_STARKNET_REFERENCE_ADAPTER_V1"),
  actionTypeHash: hashLabel("synthetic-exceptional-rotation"),
  parametersHash: hashLabel("synthetic-parameters"),
  intentDigest: hashLabel("synthetic-intent"),
  policyHash: hashLabel("synthetic-policy-v3"),
  nonceDomain: hashLabel("synthetic-nullifier-nonce-domain"),
  nonce: "11",
  rootProofNullifier: PHIL_ZERO_BYTES32,
  validAfter: "1800000000",
  validUntil: "1800000300",
  valueLimit: "0",
  feeLimit: "1000000000000000",
  deviceEpoch: "4",
  recoveryEpoch: "5",
  validatorEpoch: "6",
  deviceSignatureSuiteId: hashLabel("PHIL_SECURE_ENCLAVE_P256_DEVICE_APPROVAL_V1"),
  proofDescriptorHash,
  humanPresentationHash: hashLabel("synthetic-human-presentation")
};
const authorizationEnvelopeDigest = derivePhilAuthorizationEnvelopeDigestV1(
  pendingEnvelope
);
const publicInputs = createPhilRootProofPublicInputsV1({
  philSecret,
  nullifierSeed,
  scopeId,
  scopeInstance,
  scopeEpoch,
  authorizationEnvelopeDigest,
  proofDescriptorHash
});

const descriptorDocument = {
  format: "phil-proof-descriptor-v1",
  productionAuthority: false,
  networkActivity: false,
  verifierBindingDomain,
  descriptor,
  proofDescriptorHash,
  verifierSourceHashRule:
    "keccak256(concat(utf8(repo-relative-src-path-within-verifier + NUL), raw-file-bytes) for sorted Cairo source paths)"
};
const vectorDocument = {
  format: "phil-v1-step3-root-proof-vector-v1",
  classification: "disclosed-synthetic-private-fixture",
  productionAuthority: false,
  networkActivity: false,
  privateWitness: { philSecret, nullifierSeed },
  pendingAuthorizationEnvelope: pendingEnvelope,
  authorizationEnvelopeDigest,
  finalizedAuthorizationEnvelope: {
    ...pendingEnvelope,
    rootProofNullifier: publicInputs.rootProofNullifier
  },
  logicalPublicInputs: publicInputs,
  packedPublicInputs: packPhilRootProofPublicInputsV1(publicInputs)
};
const manifestDocument = {
  format: "phil-v1-step3-reference-artifact-manifest-v1",
  status: "exact-candidate-pending-independent-review",
  productionBackendSelected: false,
  productionAuthority: false,
  networkActivity: false,
  physicalDeviceUsed: false,
  proofSystem: "UltraKeccakZK Honk",
  toolchain: {
    nargo: {
      version: "1.0.0-beta.16",
      releaseArchiveSha256: "e21d6d09639831568850b365002e0c60456328155b143296ccf6fb3ca4cec794",
      executableSha256: "7960d2a6fbcfa547ef52b8fdd8c158e2eb6a1a753500198bbe7711efe50c5fce"
    },
    barretenberg: {
      version: "3.0.0-nightly.20251104",
      releaseArchiveSha256: "fc30922f8ee2db86a3fb0ddca026f8ab4cf123e6cffbbff17169ede50e513ef4",
      executableSha256: "fe5cdb8b85c2f76d806ab86fdfff450cf5c25b017c6b94c7a69f187c02bea565"
    },
    garaga: {
      version: "1.0.1",
      sourceCommit: "aa91b6504c86995789edb4e78f9f9ba20571625c",
      python: "3.10.18"
    },
    generatedCairoTarget: "2.14.0",
    localScarbCompiler: {
      version: "2.14.0",
      releaseArchiveSha256: "3667608675ded9e13322cf5cf1fcda06d6d84b0857e04e846148c6ae8cf5f576",
      executableSha256: "2e20da95b4cd51c030c54c0e5977a3a398ca18c8b68eefe6dc6e000d91467488"
    },
    starknetFoundry: {
      version: "0.53.0",
      releaseArchiveSha256: "4c3be134ad09c4fb2093dda68272520d5cea595ac2b7a1c1714d39877f77b4b8",
      snforgeExecutableSha256: "fb2d19e2c4befbdf2ffd9937351b6a6d9363421c50aafe86d252a92d19442d72"
    },
    universalSierraCompiler: {
      version: "2.10.0",
      releaseArchiveSha256: "3b7806314732b7cff266b95fcf0c8f0927e4776819e36f94a2c2a2eaff8ad2d0",
      executableSha256: "de6d1d4e03b8398cd895238ff2205d848b73488b0c2e8b8c7fec427a0281c4f1"
    }
  },
  descriptor: descriptorDocument,
  artifacts: [
    artifact("apps/phil-device-sdk/src/authorizationEnvelopeV1.ts"),
    artifact("apps/phil-device-sdk/src/rootProofV1.ts"),
    artifact("test/unit/phil-v1-step3-root-proof-adapter.test.cjs"),
    artifact("scripts/security/test-phil-v1-step3-noir.cjs"),
    artifact("proofs/phil-v1-step3-noir/Nargo.toml"),
    artifact("proofs/phil-v1-step3-noir/Prover.toml"),
    artifact("proofs/phil-v1-step3-noir/README.md"),
    artifact("proofs/phil-v1-step3-noir/src/main.nr"),
    documentArtifact(
      "proofs/phil-v1-step3-noir/artifacts/descriptor.json",
      descriptorDocument
    ),
    documentArtifact(
      "proofs/phil-v1-step3-noir/fixtures/canonical-vector.json",
      vectorDocument
    ),
    artifact("proofs/phil-v1-step3-noir/artifacts/phil_v1_step3_root_proof.json"),
    artifact("proofs/phil-v1-step3-noir/artifacts/vk"),
    artifact("proofs/phil-v1-step3-noir/artifacts/vk_hash"),
    artifact("proofs/phil-v1-step3-noir/artifacts/synthetic_proof"),
    artifact("proofs/phil-v1-step3-noir/artifacts/synthetic_public_inputs"),
    ...verifierSourceFiles.map(artifact),
    artifact("starknet/phil-v1-step3-verifier/README.md"),
    artifact("starknet/phil-v1-step3-verifier/Scarb.toml"),
    artifact("starknet/phil-v1-step3-verifier/Scarb.lock"),
    artifact("starknet/phil-v1-step3-verifier/.tool-versions"),
    artifact("starknet/phil-v1-step3-verifier/tests/test_phil_v1_step3_verifier.cairo"),
    artifact("starknet/phil-v1-step3-verifier/tests/proof_calldata.txt")
  ],
  measurements: {
    acirOpcodes: 3894,
    circuitSize: 94786,
    logicalPublicInputs: 7,
    packedPublicInputs: 13,
    witnessSolveSeconds: 0.12,
    witnessSolveMaximumResidentBytes: 71172096,
    verificationKeyGenerationSeconds: 0.64,
    verificationKeyMaximumResidentBytes: 209108992,
    proofGenerationSeconds: 0.8,
    proofGenerationMaximumResidentBytes: 260915200,
    proofBytes: 9408,
    nativePublicInputBytes: 416,
    garagaCalldataTextBytes: 77538,
    cairoBuild: "passed",
    cairoBuildSeconds: 2.97,
    cairoBuildMaximumResidentBytes: 1591541760,
    sierraContractClassBytes: 1691441,
    sierraProgramFelts: 36843,
    sierraClassHash:
      "0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd",
    casmContractClassBytes: 1221983,
    casmBytecodeFelts: 66178,
    casmHints: 531,
    casmCompiledClassHash:
      "0x154b6afe8acf0e963177e9e80f46b7c760d2b554245f41aec3d2d78710d8911",
    localCairoVerification: "passed",
    cairoTestCount: 2,
    cairoTestMaximumResidentBytes: 2160181248,
    validProofTotalL2Gas: 272378527,
    validProofVerifierL2Gas: 259670377,
    tamperedProofTotalL2GasUntilRejection: 76215386,
    tamperedProofVerifierL2GasUntilRejection: 42923366,
    cairoKeccakSyscallsPerCase: 94,
    cairoLibraryCallsPerCase: 1,
    networkFeeMeasurement: "not measured; no RPC or network activity authorized"
  },
  negativeEvidence: {
    circuitMismatchCases: 10,
    malformedProofRejected: true,
    repeatedProofsRandomized: true,
    serializedSyntheticPhilSecretAbsent: true,
    serializedSyntheticNullifierSeedAbsent: true,
    adapterEnvelopeBindingTests: true,
    noAuthorityReachabilityTests: true
  },
  residualLimits: [
    "Noir compiler is beta and Barretenberg is a nightly compatibility pin.",
    "The generated verifier and local compiler are pinned to Cairo and Scarb 2.14.0; this remains reference evidence, not a production compiler selection.",
    "Desktop proving only; iPhone proving is unverified and out of Step 3 scope.",
    "No account composition, deployment, RPC, signing, transaction, or production enablement is included."
  ]
};

const outputs = new Map([
  ["proofs/phil-v1-step3-noir/artifacts/descriptor.json", descriptorDocument],
  ["proofs/phil-v1-step3-noir/fixtures/canonical-vector.json", vectorDocument],
  ["docs/reference/PHIL_V1_STEP3_ARTIFACT_MANIFEST.json", manifestDocument]
]);
let mismatch = false;
for (const [relative, value] of outputs) {
  const expected = `${JSON.stringify(value, null, 2)}\n`;
  const absolute = path.join(REPO_ROOT, relative);
  if (WRITE) {
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    fs.writeFileSync(absolute, expected);
  } else if (!fs.existsSync(absolute) || fs.readFileSync(absolute, "utf8") !== expected) {
    process.stderr.write(`stale or missing Step 3 artifact: ${relative}\n`);
    mismatch = true;
  }
}
if (mismatch) process.exitCode = 1;
else process.stdout.write(`${WRITE ? "wrote" : "verified"} ${outputs.size} Step 3 artifacts\n`);
