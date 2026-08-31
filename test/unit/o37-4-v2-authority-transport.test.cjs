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
  toUtf8Bytes
} = require("ethers");

const {
  computePhilCoreV2ConfigRotationDigest,
  computePhilCoreV2RecoveryFactorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  assertPhilCoreV2RecoveryEvidenceMembership,
  assertPhilCoreV2RecoveryEvidenceState,
  computePhilCoreV2RecoveryEvidenceContextHash,
  validatePhilCoreV2RecoveryRotation
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE,
  PHILCORE_O37_2_SECP256K1_EVIDENCE_TUPLE,
  PHILCORE_O37_2_WEBAUTHN_EVIDENCE_TUPLE,
  computePhilCoreO372WebAuthnMessageHash,
  verifyPhilCoreO372P256Signature,
  verifyPhilCoreO372ValidatorEnvelope
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  PHILCORE_O37_4_AUTHORITY_CLASS,
  PHILCORE_O37_4_COMBINED_AUTHORITY_ABI,
  PHILCORE_O37_4_COMBINED_AUTHORITY_TYPE,
  PHILCORE_O37_4_COMBINED_AUTHORITY_TYPEHASH,
  PHILCORE_O37_4_COMBINED_EVIDENCE_MAX_BYTES,
  PHILCORE_O37_4_COMBINED_EVIDENCE_MIN_BYTES,
  PHILCORE_O37_4_RECOVERY_EVIDENCE_MAX_BYTES,
  PHILCORE_O37_4_RECOVERY_EVIDENCE_MIN_BYTES,
  decodePhilCoreO374AuthorityTransport,
  decodePhilCoreO374CombinedAuthorityEnvelope,
  decodePhilCoreO374RecoveryEvidence,
  encodePhilCoreO374CombinedAuthorityEnvelope
} = require("../../apps/phil-device-sdk/src/v2AuthorityTransport.ts");
const {
  buildO374AuthorityTransportPackage
} = require(
  "../../scripts/cryptography/generate-o37-4-authority-transport-vectors.cjs"
);

const ROOT = path.resolve(__dirname, "../..");
const VECTORS_PATH =
  "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json";
const O372_PATH =
  "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json";
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

function decodeRecoveryEnvelope(encoded) {
  return abiCoder.decode(
    [PHILCORE_O37_2_RECOVERY_ENVELOPE_TUPLE],
    encoded
  )[0];
}

function decodeWebAuthnEvidence(encoded) {
  return abiCoder.decode(
    [PHILCORE_O37_2_WEBAUTHN_EVIDENCE_TUPLE],
    encoded
  )[0];
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

describe("O.37.4 V2 authority transport and ERC-4337 envelope freeze", function () {
  const vectors = readJson(VECTORS_PATH);
  const o372 = readJson(O372_PATH);
  const valid = vectors.valid;

  it("records the exact local-only baseline and preserves V1 and O.37.2", function () {
    assert.equal(vectors.phase, "O.37.4");
    assert.equal(
      vectors.sourceHeadAtPhaseStart,
      "888319327e6a50f17e188132711a7e5c307bc473"
    );
    assert.equal(vectors.classification, "TEST_FIXTURE_ONLY");
    assert.equal(vectors.publicMutationCount, 0);
    assert.equal(
      sha256(V1_ACCOUNT),
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a"
    );
    assert.equal(
      sha256(V1_FACTORY),
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    );
    assert.equal(
      sha256(O372_PATH),
      vectors.priorFixturePackage.sha256
    );
    assert.equal(vectors.priorFixturePackage.modifiedByO37_4, false);
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

  it("rebuilds byte-for-byte without private material or UserOperations", function () {
    assert.equal(
      stringify(buildO374AuthorityTransportPackage()),
      read(VECTORS_PATH)
    );
    const serialized = read(VECTORS_PATH).toLowerCase();
    for (const forbidden of [
      "\"privatescalar\"",
      "\"privatekey\"",
      "\"mnemonic\"",
      "\"seed\"",
      "\"packeduseroperation\"",
      "\"calldata\"",
      "\"initcode\"",
      "\"paymasteranddata\""
    ]) {
      assert.equal(serialized.includes(forbidden), false, forbidden);
    }
    assert.equal(vectors.securityBoundary.productionUserOperationCreated, false);
    assert.equal(vectors.securityBoundary.userOperationSubmitted, false);
    assert.equal(vectors.securityBoundary.userOperationEstimated, false);
  });

  it("freezes the combined type hash, field order, and exact length formula", function () {
    assert.equal(
      keccak256(toUtf8Bytes(PHILCORE_O37_4_COMBINED_AUTHORITY_TYPE)),
      PHILCORE_O37_4_COMBINED_AUTHORITY_TYPEHASH
    );
    assert.equal(
      vectors.authorityTransportFreeze.combined.typeHash,
      PHILCORE_O37_4_COMBINED_AUTHORITY_TYPEHASH
    );
    assert.deepEqual(
      vectors.authorityTransportFreeze.combined.abiTypes,
      [...PHILCORE_O37_4_COMBINED_AUTHORITY_ABI]
    );
    for (const fixture of [
      valid.validatorPlusPrimaryAndHardwareConfigRotation,
      valid.validatorPlusPrimaryAndRecoveryFactorRotation
    ]) {
      const decoded =
        decodePhilCoreO374CombinedAuthorityEnvelope(fixture.encodedSignature);
      assert.equal(
        getBytes(fixture.encodedSignature).length,
        544 + getBytes(decoded.recoveryEvidence).length
      );
      assert.ok(
        getBytes(fixture.encodedSignature).length
        >= PHILCORE_O37_4_COMBINED_EVIDENCE_MIN_BYTES
      );
      assert.ok(
        getBytes(fixture.encodedSignature).length
        <= PHILCORE_O37_4_COMBINED_EVIDENCE_MAX_BYTES
      );
      assert.equal(decoded.canonicalEncoding, fixture.encodedSignature);
      assert.equal(
        encodePhilCoreO374CombinedAuthorityEnvelope(decoded),
        fixture.encodedSignature
      );
    }
  });

  it("dispatches every action to one exact authority class", function () {
    for (const action of vectors.authorityTransportFreeze.actionDispatch
      .validatorOnly) {
      assert.equal(
        decodePhilCoreO374AuthorityTransport(
          action,
          valid.normalValidatorExecution.encodedSignature
        ).authorityClass,
        PHILCORE_O37_4_AUTHORITY_CLASS.VALIDATOR_ONLY
      );
    }
    assert.equal(
      decodePhilCoreO374AuthorityTransport(
        8,
        o372.recoveryAuthorizationFixtures.primaryAndHardware
          .encodedRecoveryEnvelope
      ).authorityClass,
      PHILCORE_O37_4_AUTHORITY_CLASS.RECOVERY_ONLY
    );
    assert.equal(
      decodePhilCoreO374AuthorityTransport(
        10,
        valid.validatorPlusPrimaryAndHardwareConfigRotation.encodedSignature
      ).authorityClass,
      PHILCORE_O37_4_AUTHORITY_CLASS.VALIDATOR_AND_RECOVERY
    );
    assert.equal(
      decodePhilCoreO374AuthorityTransport(
        11,
        valid.recoveryConfigCancellation.encodedSignature
      ).authorityClass,
      PHILCORE_O37_4_AUTHORITY_CLASS.RECOVERY_ONLY
    );
    assert.throws(
      () => decodePhilCoreO374AuthorityTransport(
        10,
        valid.normalValidatorExecution.encodedSignature
      ),
      /combined_authority_envelope_length_invalid/
    );
    assert.throws(
      () => decodePhilCoreO374AuthorityTransport(
        2,
        valid.validatorPlusPrimaryAndHardwareConfigRotation.encodedSignature
      ),
      /validator_evidence_length_invalid/
    );
  });

  it("verifies the nested validator evidence over the config-rotation digest", function () {
    for (const fixture of [
      valid.validatorPlusPrimaryAndHardwareConfigRotation,
      valid.validatorPlusPrimaryAndRecoveryFactorRotation
    ]) {
      const result = verifyPhilCoreO372ValidatorEnvelope({
        digest: fixture.validatorDigest,
        envelope: fixture.validatorEnvelope,
        expectedValidator:
          o372.fixtureIdentities.executionValidator.address,
        expectedKeyIdBinding:
          o372.fixtureIdentities.executionValidator.keyIdentifierBinding,
        expectedValidatorEpoch: 3,
        expectedRecoveryEpoch: 2
      });
      assert.equal(result.accepted, true);
      const recomputed = computePhilCoreV2ConfigRotationDigest(
        {
          chainId: o372.fixtureDomain.chainId,
          account: o372.fixtureDomain.account
        },
        {
          authorizedIntentHash: fixture.authorizedIntentHash,
          userOperationHash: fixture.userOperationHashBinding,
          validator: o372.fixtureIdentities.executionValidator.address,
          validatorEpoch: 3,
          recoveryConfigHash:
            o372.recoveryConfiguration.recoveryConfigHash,
          recoveryEpoch: 2,
          proposedRecoveryConfigHash:
            vectors.proposedFactorRotation.proposedRecoveryConfigHash,
          proposedRecoveryEpoch: 3,
          factorBitmap: fixture.recoveryEvidence.context.factorBitmap
        }
      );
      assert.equal(recomputed.digest, fixture.validatorDigest);
    }
  });

  it("verifies both 2-of-3 recovery combinations over their separate digest", function () {
    const hardwarePair =
      valid.validatorPlusPrimaryAndHardwareConfigRotation.recoveryEvidence;
    const recoveryPair =
      valid.validatorPlusPrimaryAndRecoveryFactorRotation.recoveryEvidence;
    for (const pair of [hardwarePair, recoveryPair]) {
      assert.equal(verifyWebAuthn(pair.firstEvidence).accepted, true);
      assert.equal(
        computePhilCoreV2RecoveryFactorDigest(
          {
            chainId: o372.fixtureDomain.chainId,
            account: o372.fixtureDomain.account
          },
          pair.authorizationInput
        ).digest,
        pair.recoveryDigest
      );
      assert.equal(
        computePhilCoreV2RecoveryEvidenceContextHash(pair.context),
        pair.contextHash
      );
      assert.equal(
        assertPhilCoreV2RecoveryEvidenceMembership({
          context: pair.context,
          firstDescriptor: pair.firstEvidence.descriptor,
          secondDescriptor: pair.secondEvidence.descriptor
        }),
        true
      );
    }
    assert.equal(verifyWebAuthn(hardwarePair.secondEvidence).accepted, true);
    const secp = recoveryPair.secondEvidence;
    assert.equal(
      recoverAddress(
        recoveryPair.recoveryDigest,
        Signature.from({ r: secp.r, s: secp.s, v: secp.v })
      ),
      secp.signer
    );
  });

  it("validates the replacement descriptor and one-step factor rotation", function () {
    const proposed = vectors.proposedFactorRotation;
    const result = validatePhilCoreV2RecoveryRotation({
      currentDescriptors: [
        o372.fixtureIdentities.primaryDevice.descriptor,
        o372.fixtureIdentities.hardwareSecurityKey.descriptor,
        o372.fixtureIdentities.independentRecoveryFactor.descriptor
      ],
      proposedDescriptors: [
        o372.fixtureIdentities.primaryDevice.descriptor,
        proposed.proposedHardwareDescriptor,
        o372.fixtureIdentities.independentRecoveryFactor.descriptor
      ],
      currentRecoveryEpoch: proposed.currentRecoveryEpoch,
      proposedRecoveryEpoch: proposed.proposedRecoveryEpoch
    });
    assert.deepEqual(result.changedRoles, [1]);
    assert.equal(
      result.proposedRecoveryConfigHash,
      proposed.proposedRecoveryConfigHash
    );
  });

  it("accepts exact recovery-only cancellation and no validator double counting", function () {
    const cancellation = valid.recoveryConfigCancellation;
    const transport = decodePhilCoreO374AuthorityTransport(
      cancellation.actionType,
      cancellation.encodedSignature
    );
    assert.equal(
      transport.authorityClass,
      PHILCORE_O37_4_AUTHORITY_CLASS.RECOVERY_ONLY
    );
    assert.equal(transport.validatorEvidence, "0x");
    assert.equal(cancellation.recoveryEvidence.context.factorBitmap, 5);
    assert.equal(
      cancellation.recoveryEvidence.context.requestId,
      valid.validatorPlusPrimaryAndHardwareConfigRotation
        .authorizedIntentHash
    );
  });

  it("rejects every malformed transport mutation at its frozen layer", function () {
    for (const fixture of vectors.invalid.filter(
      ({ expectedTransportAccepted }) => !expectedTransportAccepted
    )) {
      assert.throws(
        () => decodePhilCoreO374AuthorityTransport(
          fixture.actionType,
          fixture.encodedEnvelope
        ),
        new RegExp(fixture.expectedCode),
        fixture.id
      );
      assert.equal(fixture.expectedResult, "REJECTED");
    }
  });

  it("passes canonical transport then rejects role order, commitment, and stale epoch", function () {
    const byId = Object.fromEntries(
      vectors.invalid.map((fixture) => [fixture.id, fixture])
    );
    for (const id of ["wrong_role_order", "altered_commitment", "stale_epoch"]) {
      assert.equal(byId[id].expectedTransportAccepted, true);
      decodePhilCoreO374AuthorityTransport(
        byId[id].actionType,
        byId[id].encodedEnvelope
      );
    }

    const wrongRoleCombined =
      decodePhilCoreO374CombinedAuthorityEnvelope(
        byId.wrong_role_order.encodedEnvelope
      );
    const wrongRoleRecovery = decodeRecoveryEnvelope(
      wrongRoleCombined.recoveryEvidence
    );
    const wrongRoleFirst = decodeWebAuthnEvidence(
      wrongRoleRecovery.firstFactorEvidence
    );
    const wrongRoleSecond = decodeWebAuthnEvidence(
      wrongRoleRecovery.secondFactorEvidence
    );
    assert.throws(
      () => assertPhilCoreV2RecoveryEvidenceMembership({
        context: wrongRoleRecovery.context,
        firstDescriptor: wrongRoleFirst.descriptor,
        secondDescriptor: wrongRoleSecond.descriptor
      }),
      /factor_evidence_role_order_invalid/
    );

    const alteredCombined = decodePhilCoreO374CombinedAuthorityEnvelope(
      byId.altered_commitment.encodedEnvelope
    );
    const alteredRecovery = decodeRecoveryEnvelope(
      alteredCombined.recoveryEvidence
    );
    assert.throws(
      () => computePhilCoreV2RecoveryEvidenceContextHash(
        alteredRecovery.context
      ),
      /factor_commitment_order_or_membership_invalid/
    );

    const staleCombined = decodePhilCoreO374CombinedAuthorityEnvelope(
      byId.stale_epoch.encodedEnvelope
    );
    const staleRecovery = decodeRecoveryEnvelope(staleCombined.recoveryEvidence);
    assert.throws(
      () => assertPhilCoreV2RecoveryEvidenceState({
        context: staleRecovery.context,
        expectedAccount: o372.fixtureDomain.account,
        expectedChainId: o372.fixtureDomain.chainId,
        expectedEntryPoint: o372.fixtureDomain.entryPoint,
        currentValidatorEpoch: 3,
        currentRecoveryEpoch: 2
      }),
      /recovery_epoch_stale/
    );
  });

  it("binds account and chain independently and rejects replay substitution", function () {
    const fixture =
      valid.validatorPlusPrimaryAndHardwareConfigRotation;
    const common = {
      authorizedIntentHash: fixture.authorizedIntentHash,
      userOperationHash: fixture.userOperationHashBinding,
      validator: o372.fixtureIdentities.executionValidator.address,
      validatorEpoch: 3,
      recoveryConfigHash: o372.recoveryConfiguration.recoveryConfigHash,
      recoveryEpoch: 2,
      proposedRecoveryConfigHash:
        vectors.proposedFactorRotation.proposedRecoveryConfigHash,
      proposedRecoveryEpoch: 3,
      factorBitmap: fixture.recoveryEvidence.context.factorBitmap
    };
    assert.notEqual(
      computePhilCoreV2ConfigRotationDigest(
        {
          chainId: BigInt(o372.fixtureDomain.chainId) + 1n,
          account: o372.fixtureDomain.account
        },
        common
      ).digest,
      fixture.validatorDigest
    );
    assert.notEqual(
      computePhilCoreV2ConfigRotationDigest(
        {
          chainId: o372.fixtureDomain.chainId,
          account: "0x00000000000000000000000000000000000F3703"
        },
        common
      ).digest,
      fixture.validatorDigest
    );
  });

  it("freezes EntryPoint nonce ownership without duplicate account storage", function () {
    assert.deepEqual(vectors.nonceBoundary.lanes, {
      ordinary: 0,
      maintenance: 1,
      recovery: 2
    });
    assert.equal(vectors.nonceBoundary.entryPointOwnsKeyedSequenceState, true);
    assert.equal(vectors.nonceBoundary.accountDuplicateNonceStorage, false);
    assert.equal(
      vectors.nonceBoundary.nonceEncoding,
      "(uint192 lane << 64) | uint64 sequence"
    );
    assert.equal(
      BigInt(valid.validatorPlusPrimaryAndHardwareConfigRotation
        .recoveryEvidence.context.factorBitmap),
      3n
    );
  });

  it("freezes the commitment-only constructor and local descriptor boundary", function () {
    assert.equal(vectors.constructorBoundary.fieldCount, 20);
    assert.equal(vectors.constructorBoundary.descriptorsInConstructor, false);
    assert.equal(
      vectors.constructorBoundary.onchainRecoveryMaterial,
      "THREE_DESCRIPTOR_COMMITMENTS_AND_CONFIGURATION_HASH"
    );
    assert.equal(
      vectors.constructorBoundary.runtimeValidatesFullDescriptorsBeforeDeployment,
      true
    );
    assert.equal(
      vectors.constructorBoundary.create2BindsCompleteConstructorArguments,
      true
    );
  });

  it("indexes every specification and freezes the closed ABI surface", function () {
    const index = read("docs/CANONICAL_DOCS.md");
    const required = [
      "docs/reference/O37_4_AUTHORITY_TRANSPORT_SPECIFICATION.md",
      "docs/reference/O37_4_ERC4337_INTEGRATION_SPECIFICATION.md",
      "docs/reference/O37_4_RECOVERY_ROTATION_SPECIFICATION.md",
      "docs/reference/O37_4_ABI_FREEZE.md",
      "docs/security/O37_4_AUTHORITY_TRANSPORT_THREAT_ANALYSIS.md"
    ];
    for (const document of required) {
      const basename = path.basename(document);
      assert.match(index, new RegExp(basename.replaceAll(".", "\\.")));
      assert.match(read(document), /COMPLETE_LOCAL_SECURITY_INTERFACE/);
    }
    const abiFreeze = read("docs/reference/O37_4_ABI_FREEZE.md");
    for (const requiredFunction of [
      "validateUserOp",
      "requestRecoveryConfigRotation",
      "cancelRecoveryConfigRotation",
      "completeRecoveryConfigRotation",
      "createAccount",
      "getAddress"
    ]) {
      assert.match(abiFreeze, new RegExp(requiredFunction));
    }
    for (const forbiddenFunction of [
      "delegatecall",
      "upgradeTo",
      "installModule",
      "setOwner",
      "approve",
      "setVerifier"
    ]) {
      assert.match(abiFreeze, new RegExp(forbiddenFunction));
    }
  });

  it("records the absolute local-only stop boundary", function () {
    assert.deepEqual(vectors.securityBoundary, {
      classification: "TEST_FIXTURE_ONLY",
      priorFixtureModified: false,
      privateScalarsCommitted: false,
      realCredentialCreated: false,
      productionSignatureCreated: false,
      productionUserOperationCreated: false,
      userOperationSubmitted: false,
      userOperationEstimated: false,
      solidityCreated: false,
      bytecodeCreated: false,
      deploymentPerformed: false,
      rpcUsed: false,
      fundsMoved: false,
      publicMutationOccurred: false
    });
  });
});
