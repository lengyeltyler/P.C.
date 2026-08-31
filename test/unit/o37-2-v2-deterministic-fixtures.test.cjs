require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  AbiCoder,
  Signature,
  getBytes,
  keccak256,
  recoverAddress,
  sha256,
  toUtf8Bytes
} = require("ethers");

const {
  computePhilCoreV2IntentCoreHash
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  computePhilCoreV2RecoveryFactorDigest,
  computePhilCoreV2ValidatorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  computePhilCoreV2RecoveryDescriptorCommitment,
  computePhilCoreV2RecoveryEvidenceContextHash,
  validatePhilCoreV2RecoveryDescriptorSet
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  PHILCORE_O37_2_P256_HALF_ORDER,
  PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE,
  PHILCORE_O37_2_SECP256K1_EVIDENCE_TUPLE,
  PHILCORE_O37_2_VALIDATOR_ENVELOPE_ABI,
  PHILCORE_O37_2_WEBAUTHN_EVIDENCE_TUPLE,
  computePhilCoreO372PackedUserOperationHash,
  computePhilCoreO372PackedUserOperationStructHash,
  computePhilCoreO372RpIdHash,
  computePhilCoreO372WebAuthnMessageHash,
  encodePhilCoreO372RecoveryEnvelope,
  encodePhilCoreO372Secp256k1Evidence,
  encodePhilCoreO372ValidatorEnvelope,
  encodePhilCoreO372WebAuthnEvidence,
  verifyPhilCoreO372P256Signature,
  verifyPhilCoreO372ValidatorEnvelope
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  buildO372FixturePackage
} = require("../../scripts/cryptography/generate-o37-2-deterministic-fixtures.cjs");

const ROOT = path.resolve(__dirname, "../..");
const FIXTURES_PATH =
  "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json";
const O371_PATH =
  "config/cryptography/O37_1_V2_RECOVERY_EVIDENCE_TEST_VECTORS.json";
const V1_ACCOUNT =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const V1_FACTORY =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";
const CLASSIFICATION = "TEST_FIXTURE_ONLY";
const abiCoder = AbiCoder.defaultAbiCoder();

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function sha256File(relativePath) {
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

function validatorVerificationInput(vectors, fixture) {
  return {
    digest: fixture.digest,
    envelope: fixture.envelope,
    expectedValidator: vectors.fixtureIdentities.executionValidator.address,
    expectedKeyIdBinding:
      vectors.fixtureIdentities.executionValidator.keyIdentifierBinding,
    expectedValidatorEpoch: 3,
    expectedRecoveryEpoch: 2
  };
}

function verifyWebAuthn(evidence) {
  const messageHash = computePhilCoreO372WebAuthnMessageHash({
    authenticatorData: evidence.authenticatorData,
    clientDataJSON: evidence.clientDataJSON
  });
  return verifyPhilCoreO372P256Signature({
    messageHash,
    qx: evidence.qx,
    qy: evidence.qy,
    r: evidence.r,
    s: evidence.s
  });
}

describe("O.37.2 V2 deterministic cryptographic test fixtures", function () {
  const vectors = readJson(FIXTURES_PATH);
  const o371 = readJson(O371_PATH);
  const identities = vectors.fixtureIdentities;

  it("records the exact local-only baseline and preserves frozen V1", function () {
    assert.equal(vectors.phase, "O.37.2");
    assert.equal(
      vectors.canonicalPhaseName,
      "O.37.2 V2 Deterministic Cryptographic Test Fixture Generation"
    );
    assert.equal(vectors.sourceHeadAtPhaseStart,
      "569fe5671cc82640a464f37a0c34efe8c1159bc6");
    assert.equal(vectors.classification, CLASSIFICATION);
    assert.equal(vectors.publicMutationCount, 0);
    assert.equal(
      sha256File(V1_ACCOUNT),
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a"
    );
    assert.equal(
      sha256File(V1_FACTORY),
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    );
    const v2Solidity = solidityFiles(path.join(ROOT, "contracts"))
      .filter((file) => /philcore.*v2/i.test(path.basename(file)));
    assert.deepEqual(
      v2Solidity.map((file) => path.relative(ROOT, file)).sort(),
      [
        "contracts/base/erc4337/v2/IPhilCoreV2MinimalAccountV2.sol",
        "contracts/base/erc4337/v2/IPhilCoreV2StaticAuthorityVerifier.sol",
        "contracts/base/erc4337/v2/PhilCoreV2ConfirmationTargetV1.sol", "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol",
        "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol",
        "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol",
        "contracts/test/PhilCoreV2ConfirmationTargetTestMocks.sol", "contracts/test/PhilCoreV2MinimalAccountTestMocks.sol"
      ]
    );
  });

  it("rebuilds byte-for-byte and commits no private or canonical authority", function () {
    assert.equal(stringify(buildO372FixturePackage()), read(FIXTURES_PATH));
    const committed = read(FIXTURES_PATH);
    for (const forbidden of [
      "identity_abab9766da60_24afd015",
      "validator_key_3c5b2ebebc4f3f3b",
      "0x1b41145742566cf69621da7e1d6f29609a8b1bda",
      "\"privateScalar\"",
      "\"privateKey\"",
      "\"mnemonic\"",
      "\"seed\""
    ]) {
      assert.equal(committed.toLowerCase().includes(forbidden), false);
    }
    assert.equal(vectors.securityBoundary.privateScalarsCommitted, false);
    assert.equal(vectors.securityBoundary.environmentFileUsed, false);
    assert.equal(vectors.securityBoundary.rpcUsed, false);
  });

  it("isolates every fixture identity from every other fixture role", function () {
    const addresses = [
      identities.executionValidator.address,
      identities.invalidValidator.address,
      identities.proposedRecoveryValidator.address,
      identities.independentRecoveryFactor.address,
      vectors.fixtureDomain.account,
      vectors.fixtureDomain.entryPoint
    ].map((value) => value.toLowerCase());
    assert.equal(new Set(addresses).size, addresses.length);
    for (const identity of Object.values(identities)) {
      assert.equal(identity.classification, CLASSIFICATION);
      assert.ok(identity.generation || identity.descriptor.credentialGeneration);
    }
    assert.equal(vectors.fixtureDomain.chainId, "31337");
    assert.equal(vectors.fixtureDomain.liveNetwork, false);
    assert.match(vectors.fixtureDomain.rpId, /\.invalid$/);
  });

  it("accepts the canonical validator signature and rejects every malformed vector", function () {
    const valid = vectors.validAuthorizationFixture;
    const result = verifyPhilCoreO372ValidatorEnvelope({
      digest: valid.validatorDigest,
      envelope: valid.validatorEnvelope,
      expectedValidator: identities.executionValidator.address,
      expectedKeyIdBinding: identities.executionValidator.keyIdentifierBinding,
      expectedValidatorEpoch: 3,
      expectedRecoveryEpoch: 2
    });
    assert.equal(result.accepted, true);
    assert.equal(result.recoveredAddress, identities.executionValidator.address);
    assert.equal(
      getBytes(valid.encodedValidatorEnvelope).length,
      vectors.encodingRules.validatorEnvelopeBytes
    );
    assert.equal(
      encodePhilCoreO372ValidatorEnvelope(valid.validatorEnvelope),
      valid.encodedValidatorEnvelope
    );
    for (const fixture of vectors.validatorSignatureFixtures.invalid) {
      const rejected = verifyPhilCoreO372ValidatorEnvelope(
        validatorVerificationInput(vectors, fixture)
      );
      assert.equal(rejected.accepted, false, fixture.id);
      assert.equal(rejected.code, fixture.expectedCode, fixture.id);
      assert.equal(fixture.expectedResult, "REJECTED");
    }
  });

  it("uses canonical fixed-width ABI encoding for validator evidence", function () {
    const encoded = vectors.validAuthorizationFixture.encodedValidatorEnvelope;
    const decoded = abiCoder.decode(
      PHILCORE_O37_2_VALIDATOR_ENVELOPE_ABI,
      encoded
    );
    assert.equal(
      abiCoder.encode(PHILCORE_O37_2_VALIDATOR_ENVELOPE_ABI, decoded),
      encoded
    );
    assert.equal(decoded[3], identities.executionValidator.address);
  });

  it("reproduces the exact ERC-4337 v0.7 PackedUserOperation hash", function () {
    const fixture = vectors.packedUserOperationFixtures;
    const operation = fixture.valid.operation;
    const independentStructHash = keccak256(abiCoder.encode(
      [
        "address", "uint256", "bytes32", "bytes32",
        "bytes32", "uint256", "bytes32", "bytes32"
      ],
      [
        operation.sender,
        operation.nonce,
        keccak256(operation.initCode),
        keccak256(operation.callData),
        operation.accountGasLimits,
        operation.preVerificationGas,
        operation.gasFees,
        keccak256(operation.paymasterAndData)
      ]
    ));
    assert.equal(independentStructHash, fixture.valid.structHash);
    assert.equal(
      computePhilCoreO372PackedUserOperationStructHash(operation),
      fixture.valid.structHash
    );
    assert.equal(
      computePhilCoreO372PackedUserOperationHash(
        operation,
        fixture.entryPoint,
        fixture.chainId
      ),
      fixture.valid.userOperationHash
    );
    assert.equal(
      computePhilCoreO372PackedUserOperationHash(
        { ...operation, signature: "0x" },
        fixture.entryPoint,
        fixture.chainId
      ),
      fixture.valid.userOperationHash
    );
  });

  it("binds sender, nonce lane, calldata, fees, chain, EntryPoint, and authorization", function () {
    const fixture = vectors.packedUserOperationFixtures;
    for (const negative of fixture.invalid) {
      assert.equal(
        computePhilCoreO372PackedUserOperationHash(
          negative.operation,
          negative.entryPoint,
          negative.chainId
        ),
        negative.userOperationHash,
        negative.id
      );
      assert.notEqual(
        negative.userOperationHash,
        fixture.valid.userOperationHash,
        negative.id
      );
      assert.equal(negative.matchesValidUserOperationHash, false);
      assert.equal(negative.expectedResult, "REJECTED");
    }
  });

  it("links O.32 intent, O.33 validator authority, and the UserOperation", function () {
    const valid = vectors.validAuthorizationFixture;
    const recomputed = computePhilCoreV2ValidatorDigest(
      {
        chainId: vectors.fixtureDomain.chainId,
        account: vectors.fixtureDomain.account
      },
      valid.validatorAuthorizationInput
    );
    assert.equal(recomputed.structHash, valid.validatorStructHash);
    assert.equal(recomputed.digest, valid.validatorDigest);
    assert.equal(
      valid.validatorAuthorizationInput.authorizedIntentHash,
      valid.authorizedIntentHash
    );
    assert.equal(
      valid.validatorAuthorizationInput.userOperationHash,
      valid.userOperationHash
    );
    assert.equal(valid.intentCoreHash.length, 66);
    assert.equal(valid.authorizedIntentHash.length, 66);
    assert.equal(valid.expectedResult, "ACCEPTED");
  });

  it("verifies both P-256 WebAuthn assertions and exact WebAuthn bindings", function () {
    const recovery = vectors.recoveryAuthorizationFixtures;
    for (const pair of [
      recovery.primaryAndHardware,
      recovery.primaryAndRecovery
    ]) {
      const evidence = pair.firstEvidence;
      assert.equal(verifyWebAuthn(evidence).accepted, true);
      assert.equal(
        computePhilCoreO372RpIdHash(vectors.fixtureDomain.rpId),
        evidence.descriptor.rpIdHash
      );
      assert.equal(
        evidence.authenticatorData.slice(0, 66),
        evidence.descriptor.rpIdHash
      );
      const challenge = Buffer.from(getBytes(pair.recoveryDigest))
        .toString("base64url");
      assert.equal(
        evidence.clientDataJSON.indexOf(`"challenge":"${challenge}"`),
        evidence.challengeIndex
      );
      assert.equal(
        evidence.clientDataJSON.indexOf('"type":"webauthn.get"'),
        evidence.typeIndex
      );
      assert.ok(BigInt(evidence.s) <= PHILCORE_O37_2_P256_HALF_ORDER);
    }
    assert.equal(
      verifyWebAuthn(recovery.primaryAndHardware.secondEvidence).accepted,
      true
    );
  });

  it("verifies recovery-factor signatures, membership, contexts, and ABI blobs", function () {
    const descriptors = [
      identities.primaryDevice.descriptor,
      identities.hardwareSecurityKey.descriptor,
      identities.independentRecoveryFactor.descriptor
    ];
    const descriptorSet = validatePhilCoreV2RecoveryDescriptorSet(descriptors);
    assert.deepEqual(
      descriptorSet.commitments,
      Object.values(vectors.recoveryConfiguration.commitments)
    );
    assert.equal(
      descriptorSet.recoveryConfigHash,
      vectors.recoveryConfiguration.recoveryConfigHash
    );
    const recovery = vectors.recoveryAuthorizationFixtures;
    for (const pair of [recovery.primaryAndHardware, recovery.primaryAndRecovery]) {
      assert.equal(
        computePhilCoreV2RecoveryEvidenceContextHash(pair.context),
        pair.contextHash
      );
      assert.equal(
        computePhilCoreV2RecoveryFactorDigest(
          {
            chainId: vectors.fixtureDomain.chainId,
            account: vectors.fixtureDomain.account
          },
          pair.authorizationInput
        ).digest,
        pair.recoveryDigest
      );
      assert.equal(
        computePhilCoreV2RecoveryDescriptorCommitment(pair.firstEvidence.descriptor),
        pair.firstEvidence.factorCommitment
      );
      assert.equal(
        encodePhilCoreO372WebAuthnEvidence(pair.firstEvidence),
        pair.encodedFirstEvidence
      );
      assert.equal(
        encodePhilCoreO372RecoveryEnvelope({
          context: pair.context,
          firstFactorEvidence: pair.encodedFirstEvidence,
          secondFactorEvidence: pair.encodedSecondEvidence
        }),
        pair.encodedRecoveryEnvelope
      );
      const decoded = abiCoder.decode(
        [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
        pair.encodedRecoveryEnvelope
      );
      assert.equal(
        abiCoder.encode([PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE], decoded),
        pair.encodedRecoveryEnvelope
      );
    }
    const hardware = recovery.primaryAndHardware.secondEvidence;
    assert.equal(
      encodePhilCoreO372WebAuthnEvidence(hardware),
      recovery.primaryAndHardware.encodedSecondEvidence
    );
    const secp = recovery.primaryAndRecovery.secondEvidence;
    assert.equal(
      recoverAddress(
        recovery.primaryAndRecovery.recoveryDigest,
        Signature.from({ r: secp.r, s: secp.s, v: secp.v })
      ),
      secp.signer
    );
    assert.equal(
      encodePhilCoreO372Secp256k1Evidence(secp),
      recovery.primaryAndRecovery.encodedSecondEvidence
    );
    for (const [type, encoded] of [
      [PHILCORE_O37_2_WEBAUTHN_EVIDENCE_TUPLE,
        recovery.primaryAndHardware.encodedSecondEvidence],
      [PHILCORE_O37_2_SECP256K1_EVIDENCE_TUPLE,
        recovery.primaryAndRecovery.encodedSecondEvidence]
    ]) {
      const decoded = abiCoder.decode([type], encoded);
      assert.equal(abiCoder.encode([type], decoded), encoded);
    }
  });

  it("covers exact 2-of-3, descriptor mutation, stale epoch, and replay rejection", function () {
    assert.deepEqual(
      [
        vectors.recoveryAuthorizationFixtures.primaryAndHardware.bitmap,
        vectors.recoveryAuthorizationFixtures.primaryAndRecovery.bitmap
      ],
      [3, 5]
    );
    assert.equal(vectors.recoveryConfiguration.threshold, 2);
    const negativeIds = new Set(o371.negativeVectors.map(({ id }) => id));
    for (const id of [
      "invalid_bitmap",
      "duplicate_factor",
      "modified_credential_generation",
      "modified_policy_hash",
      "stale_epoch"
    ]) {
      assert.equal(negativeIds.has(id), true, id);
    }
    const valid = vectors.validAuthorizationFixture;
    const domainChanged = computePhilCoreV2ValidatorDigest(
      {
        chainId: BigInt(vectors.fixtureDomain.chainId) + 1n,
        account: vectors.fixtureDomain.account
      },
      valid.validatorAuthorizationInput
    ).digest;
    const accountChanged = computePhilCoreV2ValidatorDigest(
      {
        chainId: vectors.fixtureDomain.chainId,
        account: "0x00000000000000000000000000000000000F3703"
      },
      valid.validatorAuthorizationInput
    ).digest;
    assert.notEqual(domainChanged, valid.validatorDigest);
    assert.notEqual(accountChanged, valid.validatorDigest);
    assert.equal(valid.intent.header.specificationVersion, 1);
    assert.throws(
      () => computePhilCoreV2IntentCoreHash({
        ...valid.intent,
        header: { ...valid.intent.header, specificationVersion: 2 }
      }),
      /specificationVersion_unsupported/
    );
    const isWithinValidity = (header, now) =>
      BigInt(now) >= BigInt(header.validAfter)
      && BigInt(now) <= BigInt(header.validUntil);
    assert.equal(
      isWithinValidity(valid.intent.header,
        BigInt(valid.intent.header.validUntil) + 1n),
      false
    );
  });

  it("records a hard stop at fixtures with no live or submission capability", function () {
    assert.deepEqual(vectors.securityBoundary, {
      classification: CLASSIFICATION,
      canonicalIdentityUsed: false,
      canonicalValidatorUsed: false,
      deviceVaultUsed: false,
      environmentFileUsed: false,
      realCredentialCreated: false,
      privateScalarsCommitted: false,
      productionSignatureCreated: false,
      productionUserOperationCreated: false,
      userOperationSubmitted: false,
      solidityCreated: false,
      bytecodeCreated: false,
      deploymentPerformed: false,
      rpcUsed: false,
      fundsMoved: false,
      publicMutationOccurred: false
    });
    const generator = read(
      "scripts/cryptography/generate-o37-2-deterministic-fixtures.cjs"
    );
    assert.equal(/JsonRpcProvider|eth_send|sendUserOperation|fetch\s*\(/.test(generator),
      false);
    assert.equal(vectors.packedUserOperationFixtures.valid.operation.initCode, "0x");
    assert.equal(
      vectors.packedUserOperationFixtures.valid.operation.paymasterAndData,
      "0x"
    );
  });
});
