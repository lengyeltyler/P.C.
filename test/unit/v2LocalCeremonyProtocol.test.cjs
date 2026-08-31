require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { getAddress, keccak256, toUtf8Bytes } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const O46_PATH = path.join(
  ROOT,
  "config/cryptography/O46_LOCAL_CEREMONY_HASH_VECTORS.json"
);
const O37_2_PATH = path.join(
  ROOT,
  "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json"
);
const MODULE_PATH = path.join(
  ROOT,
  "apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts"
);

const {
  PHILCORE_V2_SECURITY_MODEL_ID
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_O37_2_SECP256K1_ORDER,
  PHILCORE_O37_2_SECP256K1_HALF_ORDER
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");

const protocol = require("../../apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts");

const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ALT_BYTES32 =
  "0x1111111111111111111111111111111111111111111111111111111111111111";

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function enrollmentInput(o46, overrides = {}) {
  const base = o46.enrollment;
  return {
    ceremonyId: base.ceremonyId,
    account: base.account,
    chainId: base.chainId,
    entryPoint: base.entryPoint,
    accountVersionId: base.accountVersionId,
    securityModelId: base.securityModelId,
    recoveryDomainId: base.recoveryDomainId,
    expectedRecoveryEpoch: base.expectedRecoveryEpoch,
    expectedValidatorEpoch: base.expectedValidatorEpoch,
    expiresAt: base.expiresAt,
    ...overrides
  };
}

function proofInput(o46, overrides = {}) {
  const base = o46.role2Proof;
  return {
    proofVersion: base.proofVersion,
    enrollmentCeremonyHash: base.enrollmentCeremonyHash,
    independenceBindingHash: base.independenceBindingHash,
    factorCommitment: base.factorCommitment,
    credentialGeneration: base.credentialGeneration,
    account: base.account,
    chainId: base.chainId,
    entryPoint: base.entryPoint,
    signer: base.signer,
    ...overrides
  };
}

function assertCode(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(error.name, "PhilCoreV2LocalCeremonyProtocolError");
    assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
    return true;
  });
}

function withInheritedSubstitute(base, key, inheritedValue) {
  const own = { ...base };
  delete own[key];
  const proto = Object.create(null);
  proto[key] = inheritedValue;
  return Object.assign(Object.create(proto), own);
}

function walkSourceFiles(directory, predicate) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    const resolved = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "release") continue;
      out.push(...walkSourceFiles(resolved, predicate));
      continue;
    }
    if (predicate(resolved, entry.name)) out.push(resolved);
  }
  return out;
}

describe("PhilCore V2 local ceremony protocol primitives (O.46)", function () {
  const o46 = readJson(O46_PATH);
  const o372 = readJson(O37_2_PATH);
  const validSig = o372.validatorSignatureFixtures.valid;
  const invalidById = Object.fromEntries(
    o372.validatorSignatureFixtures.invalid.map((entry) => [entry.id, entry])
  );

  it("locks exact enrollment/proof literals and known typehashes", function () {
    assert.equal(
      protocol.PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_LITERAL,
      o46.protocolConstants.enrollmentLiteral
    );
    assert.equal(
      protocol.PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_LITERAL,
      o46.protocolConstants.role2ProofLiteral
    );
    assert.equal(
      protocol.PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_TYPEHASH,
      o46.protocolConstants.enrollmentTypehash
    );
    assert.equal(
      protocol.PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_TYPEHASH,
      o46.protocolConstants.role2ProofTypehash
    );
    assert.equal(
      keccak256(toUtf8Bytes(protocol.PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_LITERAL)),
      o46.protocolConstants.enrollmentTypehash
    );
    assert.equal(
      keccak256(toUtf8Bytes(protocol.PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_LITERAL)),
      o46.protocolConstants.role2ProofTypehash
    );
    assert.deepEqual(
      protocol.PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_ABI_TYPES,
      o46.protocolConstants.enrollmentAbiTypes
    );
    assert.deepEqual(
      protocol.PHILCORE_V2_LOCAL_ROLE2_CEREMONY_PROOF_ABI_TYPES,
      o46.protocolConstants.proofAbiTypes
    );
    assert.equal(protocol.PHILCORE_V2_LOCAL_ROLE2_PROOF_VERSION, 1);
    assert.equal(
      protocol.PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
      PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID
    );
    assert.equal(
      protocol.PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
      PHILCORE_V2_SECURITY_MODEL_ID
    );
    assert.equal(
      protocol.PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
      PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID
    );
  });

  it("records hash-only O46 fixture provenance and limitations", function () {
    assert.equal(o46.hashOnly, true);
    assert.equal(o46.provenance.secretsCommitted, false);
    assert.equal(o46.provenance.privateScalarsCommitted, false);
    assert.equal(o46.provenance.fixtureGeneratorExists, false);
    assert.equal(o46.provenance.signingScriptExists, false);
    assert.equal(o46.provenance.combinedRole2ProofVerificationTestable, false);
    const serialized = fs.readFileSync(O46_PATH, "utf8");
    for (const forbidden of [
      "\"privateScalar\"",
      "\"privateKey\"",
      "\"mnemonic\"",
      "\"seed\"",
      "\"recoveryCode\"",
      "\"signature\"",
      "\"r\":",
      "\"s\":",
      "\"v\":"
    ]) {
      assert.equal(
        serialized.includes(forbidden),
        false,
        `fixture must not contain ${forbidden}`
      );
    }
    assert.match(
      o46.limitations.join(" "),
      /hash-only|neither signatures nor private|cannot test combined|deterministic public|no fixture generator/i
    );
  });

  it("matches both O46 known-answer hashes for string and bigint integer forms", function () {
    const enrollmentHash = protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
      enrollmentInput(o46)
    );
    assert.equal(
      enrollmentHash,
      o46.enrollment.expectedEnrollmentCeremonyHash
    );
    const enrollmentHashBigint =
      protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, {
          chainId: 11155111n,
          expectedRecoveryEpoch: 1n,
          expectedValidatorEpoch: 1n,
          expiresAt: 2000000000n
        })
      );
    assert.equal(enrollmentHashBigint, enrollmentHash);

    const proofDigest = protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
      proofInput(o46)
    );
    assert.equal(
      proofDigest,
      o46.role2Proof.expectedRole2CeremonyProofDigest
    );
    const proofDigestBigint =
      protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
        proofInput(o46, {
          proofVersion: 1n,
          credentialGeneration: 1n,
          chainId: 11155111n
        })
      );
    assert.equal(proofDigestBigint, proofDigest);
  });

  it("is sensitive to valid mutable field changes", function () {
    const baseEnrollment = protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
      enrollmentInput(o46)
    );
    const mutatedEnrollment =
      protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { ceremonyId: ALT_BYTES32 })
      );
    assert.notEqual(mutatedEnrollment, baseEnrollment);

    const baseProof = protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
      proofInput(o46)
    );
    const mutatedProof = protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
      proofInput(o46, { independenceBindingHash: ALT_BYTES32 })
    );
    assert.notEqual(mutatedProof, baseProof);
  });

  it("rejects pinned-field mutations rather than hashing alternates", function () {
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { accountVersionId: ALT_BYTES32 })
      ),
      "ACCOUNT_VERSION_ID_MISMATCH"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { securityModelId: ALT_BYTES32 })
      ),
      "SECURITY_MODEL_ID_MISMATCH"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { recoveryDomainId: ALT_BYTES32 })
      ),
      "RECOVERY_DOMAIN_ID_MISMATCH"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
        proofInput(o46, { proofVersion: "2" })
      ),
      "PROOF_VERSION_MISMATCH"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
        proofInput(o46, { proofVersion: 2n })
      ),
      "PROOF_VERSION_MISMATCH"
    );
  });

  it("enforces exact own-key schemas including inherited substitutes", function () {
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(null),
      "INPUT_NOT_OBJECT"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash([]),
      "INPUT_NOT_OBJECT"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest("x"),
      "INPUT_NOT_OBJECT"
    );

    const enrollmentExtra = enrollmentInput(o46);
    enrollmentExtra.extra = "nope";
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(enrollmentExtra),
      "EXTRA_OWN_KEY"
    );

    const enrollmentMissing = enrollmentInput(o46);
    delete enrollmentMissing.account;
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(enrollmentMissing),
      "MISSING_OWN_KEY"
    );

    const inheritedEnrollment = withInheritedSubstitute(
      enrollmentInput(o46),
      "ceremonyId",
      o46.enrollment.ceremonyId
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(inheritedEnrollment, "ceremonyId"),
      false
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(inheritedEnrollment),
      "MISSING_OWN_KEY"
    );

    const proofExtra = proofInput(o46);
    proofExtra.extra = true;
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(proofExtra),
      "EXTRA_OWN_KEY"
    );

    const inheritedProof = withInheritedSubstitute(
      proofInput(o46),
      "signer",
      o46.role2Proof.signer
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(inheritedProof),
      "MISSING_OWN_KEY"
    );

    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, null),
      "SIGNATURE_SHAPE_INVALID"
    );
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, [validSig.r, validSig.s, validSig.v]),
      "SIGNATURE_SHAPE_INVALID"
    );
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, {
        r: validSig.r,
        s: validSig.s,
        v: validSig.v,
        extra: 1
      }),
      "SIGNATURE_SHAPE_INVALID"
    );
    const inheritedSignature = withInheritedSubstitute(
      { r: validSig.r, s: validSig.s, v: validSig.v },
      "v",
      27
    );
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, inheritedSignature),
      "SIGNATURE_SHAPE_INVALID"
    );
  });

  it("rejects invalid/zero bytes32 and zero addresses", function () {
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { ceremonyId: "0x1234" })
      ),
      "BYTES32_INVALID"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { ceremonyId: ZERO_BYTES32 })
      ),
      "BYTES32_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
        proofInput(o46, { factorCommitment: ZERO_BYTES32 })
      ),
      "BYTES32_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { account: ZERO_ADDRESS })
      ),
      "ADDRESS_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { entryPoint: ZERO_ADDRESS })
      ),
      "ADDRESS_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
        proofInput(o46, { signer: ZERO_ADDRESS })
      ),
      "ADDRESS_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { account: "not-an-address" })
      ),
      "ADDRESS_INVALID"
    );
  });

  it("rejects JavaScript numbers and non-canonical decimal strings", function () {
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { chainId: 11155111 })
      ),
      "INTEGER_NUMBER_REJECTED"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { expiresAt: 2000000000 })
      ),
      "INTEGER_NUMBER_REJECTED"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
        proofInput(o46, { credentialGeneration: 1 })
      ),
      "INTEGER_NUMBER_REJECTED"
    );

    for (const bad of [" 1", "1 ", "+1", "-1", "01", "1e3", "0x1", "1.0", ""]) {
      assertCode(
        () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
          enrollmentInput(o46, { chainId: bad })
        ),
        "INTEGER_SYNTAX_INVALID"
      );
    }
  });

  it("enforces uint boundaries, nonzero requirements, and later epochs", function () {
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { chainId: "0" })
      ),
      "CHAIN_ID_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { expectedRecoveryEpoch: "0" })
      ),
      "EXPECTED_RECOVERY_EPOCH_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { expectedValidatorEpoch: "0" })
      ),
      "EXPECTED_VALIDATOR_EPOCH_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { expiresAt: "0" })
      ),
      "EXPIRES_AT_ZERO"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
        proofInput(o46, { credentialGeneration: "0" })
      ),
      "CREDENTIAL_GENERATION_ZERO"
    );

    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { expiresAt: (1n << 48n).toString() })
      ),
      "UINT_OUT_OF_RANGE"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, {
          expectedRecoveryEpoch: (1n << 64n).toString()
        })
      ),
      "UINT_OUT_OF_RANGE"
    );
    assertCode(
      () => protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
        proofInput(o46, { proofVersion: "256" })
      ),
      "UINT_OUT_OF_RANGE"
    );

    const laterEnrollment =
      protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, {
          expectedRecoveryEpoch: "9",
          expectedValidatorEpoch: "7"
        })
      );
    assert.match(laterEnrollment, /^0x[0-9a-f]{64}$/);
    assert.notEqual(
      laterEnrollment,
      o46.enrollment.expectedEnrollmentCeremonyHash
    );

    const laterProof = protocol.computePhilCoreV2LocalRole2CeremonyProofDigest(
      proofInput(o46, { credentialGeneration: "42" })
    );
    assert.match(laterProof, /^0x[0-9a-f]{64}$/);
    assert.notEqual(
      laterProof,
      o46.role2Proof.expectedRole2CeremonyProofDigest
    );
  });

  it("hashes expiresAt with no clock comparison dependency", function () {
    const before = Date.now;
    let nowCalled = false;
    Date.now = function patchedNow() {
      nowCalled = true;
      return before.call(Date);
    };
    try {
      const past = protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { expiresAt: "1" })
      );
      const future = protocol.computePhilCoreV2LocalEnrollmentCeremonyHash(
        enrollmentInput(o46, { expiresAt: "4000000000" })
      );
      assert.match(past, /^0x[0-9a-f]{64}$/);
      assert.match(future, /^0x[0-9a-f]{64}$/);
      assert.notEqual(past, future);
      assert.equal(nowCalled, false);
    } finally {
      Date.now = before;
    }
  });

  it("recovers the O37_2 public valid secp256k1 signer", function () {
    const recovered = protocol.recoverCanonicalSecp256k1Signer(validSig.digest, {
      r: validSig.r,
      s: validSig.s,
      v: validSig.v
    });
    assert.equal(
      recovered,
      getAddress(o372.fixtureIdentities.executionValidator.address)
    );
  });

  it("rejects invalid digests and malformed signature components with distinct codes", function () {
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer("0x1234", {
        r: validSig.r,
        s: validSig.s,
        v: validSig.v
      }),
      "DIGEST_SHAPE_INVALID"
    );
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, {
        r: "0x12",
        s: validSig.s,
        v: validSig.v
      }),
      "SIGNATURE_R_INVALID"
    );
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, {
        r: validSig.r,
        s: "not-hex",
        v: validSig.v
      }),
      "SIGNATURE_S_INVALID"
    );
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, {
        r: validSig.r,
        s: validSig.s,
        v: 0
      }),
      "SIGNATURE_V_INVALID"
    );
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, {
        r: validSig.r,
        s: validSig.s,
        v: 1
      }),
      "SIGNATURE_V_INVALID"
    );
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, {
        r: validSig.r,
        s: validSig.s,
        v: "27"
      }),
      "SIGNATURE_V_INVALID"
    );

    const zeroR = invalidById.zero_r;
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(zeroR.digest, {
        r: zeroR.envelope.r,
        s: zeroR.envelope.s,
        v: zeroR.envelope.v
      }),
      "SIGNATURE_R_OUT_OF_RANGE"
    );

    const zeroS = invalidById.zero_s;
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(zeroS.digest, {
        r: zeroS.envelope.r,
        s: zeroS.envelope.s,
        v: zeroS.envelope.v
      }),
      "SIGNATURE_S_OUT_OF_RANGE"
    );

    const invalidV = invalidById.invalid_v;
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(invalidV.digest, {
        r: invalidV.envelope.r,
        s: invalidV.envelope.s,
        v: invalidV.envelope.v
      }),
      "SIGNATURE_V_INVALID"
    );

    const highS = invalidById.high_s;
    assert.ok(BigInt(highS.envelope.s) > PHILCORE_O37_2_SECP256K1_HALF_ORDER);
    assert.ok(BigInt(highS.envelope.s) < PHILCORE_O37_2_SECP256K1_ORDER);
    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(highS.digest, {
        r: highS.envelope.r,
        s: highS.envelope.s,
        v: highS.envelope.v
      }),
      "SIGNATURE_HIGH_S"
    );

    assertCode(
      () => protocol.recoverCanonicalSecp256k1Signer(validSig.digest, {
        r: `0x${"ff".repeat(32)}`,
        s: validSig.s,
        v: validSig.v
      }),
      "SIGNATURE_R_OUT_OF_RANGE"
    );
  });

  it("recovers a different public address for modified digest without signer-mismatch semantics", function () {
    const modified = invalidById.modified_digest;
    const recovered = protocol.recoverCanonicalSecp256k1Signer(modified.digest, {
      r: modified.envelope.r,
      s: modified.envelope.s,
      v: modified.envelope.v
    });
    assert.equal(recovered, getAddress("0x7517c3b40Eb399e50A130bf880954115E7C73768"));
    assert.notEqual(
      recovered.toLowerCase(),
      o372.fixtureIdentities.executionValidator.address.toLowerCase()
    );
    assert.equal(
      Object.values(protocol.PHILCORE_V2_LOCAL_CEREMONY_ERROR_CODE)
        .includes("SIGNER_MISMATCH"),
      false
    );
  });

  it("exports only the three operational functions and forbids verifier/signing/secret APIs", function () {
    assert.equal(
      typeof protocol.computePhilCoreV2LocalEnrollmentCeremonyHash,
      "function"
    );
    assert.equal(
      typeof protocol.computePhilCoreV2LocalRole2CeremonyProofDigest,
      "function"
    );
    assert.equal(typeof protocol.recoverCanonicalSecp256k1Signer, "function");
    assert.equal(
      typeof protocol.verifyPhilCoreV2LocalRole2CeremonyProof,
      "undefined"
    );

    const forbiddenExact = [
      "verifyPhilCoreV2LocalRole2CeremonyProof",
      "SIGNER_MISMATCH",
      "sign",
      "signer",
      "privateKey",
      "privateScalar",
      "mnemonic",
      "seed",
      "recoveryCode",
      "entropy"
    ];
    for (const key of Object.keys(protocol)) {
      assert.ok(
        !forbiddenExact.includes(key),
        `forbidden export present: ${key}`
      );
      assert.ok(!/^sign/i.test(key), `forbidden signing-shaped export: ${key}`);
      assert.ok(!/^verify/i.test(key), `forbidden verify export: ${key}`);
    }

    const source = fs.readFileSync(MODULE_PATH, "utf8");
    for (const forbidden of [
      "privateKey",
      "privateScalar",
      "mnemonic",
      "seed",
      "recoveryCode",
      "entropy",
      "expectedSigner",
      "SIGNER_MISMATCH",
      "verifyPhilCoreV2LocalRole2CeremonyProof"
    ]) {
      assert.equal(
        source.includes(forbidden),
        false,
        `production source must not mention ${forbidden}`
      );
    }
  });

  it("keeps an SDK-only import boundary with no Desktop/iOS coupling", function () {
    const source = fs.readFileSync(MODULE_PATH, "utf8");
    assert.equal(/philcore-desktop|apps\/ios|iphone|LocalAuthentication/i.test(source), false);

    const desktopAndIos = [
      ...walkSourceFiles(path.join(ROOT, "apps/philcore-desktop"), (_p, name) =>
        /\.(ts|tsx|js|cjs|mjs)$/.test(name)
      ),
      ...walkSourceFiles(path.join(ROOT, "apps"), (resolved, name) =>
        /ios/i.test(resolved) && /\.(ts|tsx|js|cjs|mjs|swift)$/.test(name)
      )
    ];
    for (const file of desktopAndIos) {
      const text = fs.readFileSync(file, "utf8");
      assert.equal(
        text.includes("v2LocalCeremonyProtocol"),
        false,
        `${path.relative(ROOT, file)} must not import the new module`
      );
    }
  });
});
