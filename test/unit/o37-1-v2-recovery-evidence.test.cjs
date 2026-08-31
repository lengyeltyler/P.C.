require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  AbiCoder,
  keccak256,
  toUtf8Bytes
} = require("ethers");

const {
  PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPE,
  PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH,
  PHILCORE_V2_RECOVERY_DOMAIN_ID,
  assertPhilCoreV2RecoveryEvidenceMembership,
  assertPhilCoreV2RecoveryEvidenceState,
  computePhilCoreV2RecoveryDescriptorCommitment,
  computePhilCoreV2RecoveryEvidenceContextHash,
  validatePhilCoreV2RecoveryDescriptorSet,
  validatePhilCoreV2RecoveryRotation
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  buildO371VectorPackage
} = require("../../scripts/cryptography/generate-o37-1-recovery-evidence-vectors.cjs");

const ROOT = path.resolve(__dirname, "../..");
const VECTORS_PATH =
  "config/cryptography/O37_1_V2_RECOVERY_EVIDENCE_TEST_VECTORS.json";
const V1_ACCOUNT =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const V1_FACTORY =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";
const abiCoder = AbiCoder.defaultAbiCoder();

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function sha256(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

function stringify(value) {
  return `${JSON.stringify(
    value,
    (_key, item) => typeof item === "bigint" ? item.toString() : item,
    2
  )}\n`;
}

function solidityFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name);
    if (entry.isDirectory()) return solidityFiles(resolved);
    return entry.name.endsWith(".sol") ? [resolved] : [];
  });
}

function assertP256Point({ qx, qy }) {
  const point = Buffer.from(
    `04${qx.slice(2)}${qy.slice(2)}`,
    "hex"
  );
  assert.doesNotThrow(() => crypto.ECDH.convertKey(point, "prime256v1"));
}

describe("O.37.1 V2 recovery evidence and descriptor completion", function () {
  const vectors = readJson(VECTORS_PATH);
  const descriptors = [
    vectors.currentDescriptors.primaryDevice,
    vectors.currentDescriptors.hardwareSecurityKey,
    vectors.currentDescriptors.recoveryFactor
  ];

  it("records the exact local-only baseline and preserves frozen V1", function () {
    assert.equal(vectors.phase, "O.37.1");
    assert.equal(
      vectors.sourceHeadAtPhaseStart,
      "6dcc4099a78cd719d484c4e33c808586d2472780"
    );
    assert.equal(vectors.publicMutationCount, 0);
    assert.equal(
      sha256(V1_ACCOUNT),
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a"
    );
    assert.equal(
      sha256(V1_FACTORY),
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    );
  });

  it("locks every type hash independently", function () {
    for (const [name, typeString] of Object.entries(
      PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPE
    )) {
      assert.equal(
        keccak256(toUtf8Bytes(typeString)),
        PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH[name]
      );
      assert.equal(
        vectors.typeBindings[name].typeHash,
        PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH[name]
      );
    }
    assert.equal(
      PHILCORE_V2_RECOVERY_DOMAIN_ID,
      keccak256(toUtf8Bytes("PHILCORE_V2_RECOVERY_FACTOR_DESCRIPTOR_V2"))
    );
  });

  it("uses valid distinct public P-256 points without credentials or signatures", function () {
    assertP256Point(vectors.publicFixtureMaterial.primaryDevice);
    assertP256Point(vectors.publicFixtureMaterial.hardwareSecurityKey);
    assert.notDeepEqual(
      vectors.publicFixtureMaterial.primaryDevice,
      vectors.publicFixtureMaterial.hardwareSecurityKey
    );
    assert.equal(vectors.publicFixtureMaterial.realCredential, false);
    assert.equal(vectors.publicFixtureMaterial.privateKey, false);
    assert.equal(vectors.publicFixtureMaterial.signature, false);
  });

  it("binds every complete descriptor field with standard ABI encoding", function () {
    const primary = descriptors[0];
    const independentlyEncoded = abiCoder.encode(
      [
        "bytes32",
        "uint8",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint8",
        "uint8",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint8",
        "uint8",
        "uint8",
        "uint8",
        "uint64"
      ],
      [
        PHILCORE_V2_RECOVERY_DESCRIPTOR_TYPEHASH.FACTOR_DESCRIPTOR,
        primary.descriptorVersion,
        primary.accountVersionId,
        primary.securityModelId,
        primary.recoveryDomainId,
        primary.role,
        primary.verifierKind,
        primary.publicVerificationMaterialHash,
        primary.credentialIdHash,
        primary.rpIdHash,
        primary.originPolicyHash,
        primary.independenceBindingHash,
        primary.userVerificationPolicy,
        primary.backupPolicy,
        primary.authenticatorAttachmentPolicy,
        primary.attestationPolicy,
        primary.credentialGeneration
      ]
    );
    assert.equal(
      keccak256(independentlyEncoded),
      vectors.currentCommitments.primaryDevice
    );
    assert.equal(
      computePhilCoreV2RecoveryDescriptorCommitment(primary),
      vectors.currentCommitments.primaryDevice
    );
  });

  it("enforces role, verifier, policy, independence, and configuration uniqueness", function () {
    const result = validatePhilCoreV2RecoveryDescriptorSet(descriptors);
    assert.deepEqual(result.commitments, [
      vectors.currentCommitments.primaryDevice,
      vectors.currentCommitments.hardwareSecurityKey,
      vectors.currentCommitments.recoveryFactor
    ]);
    assert.equal(
      result.recoveryConfigHash,
      vectors.currentCommitments.recoveryConfigHash
    );
    assert.equal(descriptors[0].role, 0);
    assert.equal(descriptors[1].role, 1);
    assert.equal(descriptors[2].role, 2);
    assert.equal(descriptors[0].backupPolicy, 1);
    assert.equal(descriptors[1].backupPolicy, 1);
    assert.equal(descriptors[2].backupPolicy, 0);
  });

  it("reconstructs exact selected evidence membership and canonical context", function () {
    assert.equal(
      assertPhilCoreV2RecoveryEvidenceMembership({
        context: vectors.validRecoveryRequest.context,
        firstDescriptor: descriptors[0],
        secondDescriptor: descriptors[1]
      }),
      true
    );
    assert.equal(
      computePhilCoreV2RecoveryEvidenceContextHash(
        vectors.validRecoveryRequest.context
      ),
      vectors.validRecoveryRequest.contextHash
    );
    assert.equal(
      vectors.validRecoveryRequest.context.requestId,
      vectors.validRecoveryRequest.context.authorizedIntentHash
    );
  });

  it("rejects one-factor, zero, three-factor, stale, and request replay shapes", function () {
    for (const bitmap of [0, 1, 2, 4, 7, 8]) {
      assert.throws(
        () => computePhilCoreV2RecoveryEvidenceContextHash({
          ...vectors.validRecoveryRequest.context,
          factorBitmap: bitmap
        }),
        /recovery_factor_bitmap_invalid/
      );
    }
    assert.throws(
      () => computePhilCoreV2RecoveryEvidenceContextHash({
        ...vectors.validRecoveryRequest.context,
        requestId: keccak256(toUtf8Bytes("o37.1:replayed-request"))
      }),
      /recovery_request_id_must_equal_authorized_intent_hash/
    );
    assert.throws(
      () => assertPhilCoreV2RecoveryEvidenceState({
        context: {
          ...vectors.validRecoveryRequest.context,
          recoveryEpoch: 1,
          proposedRecoveryEpoch: 2
        },
        expectedAccount: vectors.validRecoveryRequest.context.account,
        expectedChainId: vectors.validRecoveryRequest.context.chainId,
        expectedEntryPoint: vectors.validRecoveryRequest.context.entryPoint,
        currentValidatorEpoch: 3,
        currentRecoveryEpoch: 2
      }),
      /recovery_epoch_stale/
    );
  });

  it("requires replacement, one-step generation, and epoch revocation", function () {
    const proposed = [
      descriptors[0],
      descriptors[1],
      vectors.validRotationRequest.proposedDescriptor
    ];
    const result = validatePhilCoreV2RecoveryRotation({
      currentRecoveryEpoch: 2,
      proposedRecoveryEpoch: 3,
      currentDescriptors: descriptors,
      proposedDescriptors: proposed
    });
    assert.deepEqual(result.changedRoles, [2]);
    assert.equal(
      result.proposedRecoveryConfigHash,
      vectors.validRotationRequest.proposedRecoveryConfigHash
    );
    assert.notEqual(
      result.currentRecoveryConfigHash,
      result.proposedRecoveryConfigHash
    );
  });

  it("covers all required negative vectors without authority material", function () {
    assert.deepEqual(
      vectors.negativeVectors.map(({ id }) => id),
      [
        "modified_credential_generation",
        "modified_policy_hash",
        "wrong_role",
        "wrong_verifier_kind",
        "wrong_domain",
        "stale_epoch",
        "duplicate_factor",
        "invalid_bitmap",
        "same_factor_rotation"
      ]
    );
    for (const vector of vectors.negativeVectors) {
      assert.equal(vector.rejected, true);
      assert.equal(vector.signatureCreated, false);
      assert.equal(vector.userOperationCreated, false);
    }
  });

  it("is deterministic and keeps O.32/O.33 packages unchanged", function () {
    assert.equal(stringify(buildO371VectorPackage()), read(VECTORS_PATH));
    assert.equal(vectors.compatibility.o32VectorPackageChanged, false);
    assert.equal(vectors.compatibility.o33VectorPackageChanged, false);
    assert.equal(
      vectors.implementationBindings.o32VectorPackageSha256,
      sha256("config/cryptography/O32_V2_CRYPTOGRAPHIC_TEST_VECTORS.json")
    );
    assert.equal(
      vectors.implementationBindings.o33VectorPackageSha256,
      sha256(
        "config/cryptography/O33_V2_VALIDATOR_AUTHORIZATION_TEST_VECTORS.json"
      )
    );
  });

  it("pins the exact Node/npm runtime and lockfile policy", function () {
    const packageJson = readJson("package.json");
    const packageLock = readJson("package-lock.json");
    assert.equal(read(".node-version").trim(), "26.0.0");
    assert.equal(packageJson.engines.node, "26.0.0");
    assert.equal(packageJson.engines.npm, "11.12.1");
    assert.equal(packageJson.packageManager, "npm@11.12.1");
    assert.equal(packageLock.lockfileVersion, 3);
    assert.match(read(".npmrc"), /engine-strict=true/);
  });

  it("indexes every deliverable and marks the narrow O.36.1 supersession", function () {
    const canonical = read("docs/CANONICAL_DOCS.md");
    const model = read("docs/reference/LOCAL_PROOF_GATED_ACCOUNT_MODEL.md");
    const o36Hardware = read(
      "docs/reference/O36_1_HARDWARE_RECOVERY_SPECIFICATION.md"
    );
    const o36Freeze = read(
      "docs/reference/O36_1_SOLIDITY_IMPLEMENTATION_FREEZE.md"
    );
    for (const filename of [
      "O37_1_CRYPTOGRAPHIC_DESCRIPTOR_SPECIFICATION.md",
      "O37_1_RECOVERY_EVIDENCE_SPECIFICATION.md",
      "O37_1_RECOVERY_LIFECYCLE_UPDATE.md",
      "O37_1_IMPLEMENTATION_READINESS_REVIEW.md"
    ]) {
      assert.equal(canonical.includes(filename), true, filename);
      assert.equal(model.includes(filename), true, filename);
    }
    assert.match(o36Hardware, /superseded.*O\.37\.1/is);
    assert.match(o36Freeze, /superseded.*O\.37\.1/is);
  });

  it("contains no V2 Solidity and keeps every mutation boundary false", function () {
    for (const sourcePath of solidityFiles(path.join(ROOT, "contracts"))) {
      const source = fs.readFileSync(sourcePath, "utf8");
      assert.doesNotMatch(
        source,
        /contract\s+PhilCoreV2(?:Account|AccountFactory)\b/
      );
    }
    for (const [key, value] of Object.entries(vectors.securityBoundary)) {
      if (key.endsWith("Occurred")) assert.equal(value, false, key);
      if (
        key.endsWith("Created")
        || key.endsWith("Performed")
        || key.endsWith("Moved")
        || key.endsWith("Used")
        || key.endsWith("Stored")
        || key.endsWith("Committed")
      ) {
        assert.equal(value, false, key);
      }
    }
  });
});
