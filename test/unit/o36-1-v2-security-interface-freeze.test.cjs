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
  PHILCORE_V2_AUTHORIZATION_TYPE,
  PHILCORE_V2_AUTHORIZATION_TYPEHASH
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");

const ROOT = path.resolve(__dirname, "../..");
const FREEZE_PATH = path.join(
  ROOT,
  "config/cryptography/O36_1_V2_SECURITY_INTERFACE_FREEZE.json"
);
const V1_ACCOUNT =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const V1_FACTORY =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";
const abiCoder = AbiCoder.defaultAbiCoder();

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function sha256(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

function identityBinding(ownerCommitment, schemeId) {
  const binding = freeze.typeBindings.identityBinding;
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "bytes32", "bytes32"],
    [binding.typeHash, binding.bindingVersion, ownerCommitment, schemeId]
  ));
}

function validateValidatorEnvelopeShape(input = {}) {
  const expected = {
    byteLength: freeze.validatorEnvelope.exactBytes,
    envelopeVersion: freeze.validatorEnvelope.version,
    authorityKind: freeze.validatorEnvelope.authorityKind,
    verifierKind: freeze.validatorEnvelope.verifierKind,
    validatorEpoch: 4,
    recoveryEpoch: 3,
    chainId: 11155111,
    account: "0x1000000000000000000000000000000000000001",
    nonceConsumed: false,
    ...input.expected
  };
  const supplied = {
    ...expected,
    ...input.supplied
  };
  if (supplied.byteLength !== expected.byteLength) {
    return "VALIDATOR_EVIDENCE_LENGTH_INVALID";
  }
  if (
    supplied.envelopeVersion !== expected.envelopeVersion
    || supplied.authorityKind !== expected.authorityKind
    || supplied.verifierKind !== expected.verifierKind
  ) {
    return "VALIDATOR_EVIDENCE_MALFORMED";
  }
  if (supplied.chainId !== expected.chainId) return "DOMAIN_MISMATCH";
  if (supplied.account !== expected.account) return "ACCOUNT_MISMATCH";
  if (supplied.validatorEpoch !== expected.validatorEpoch) {
    return supplied.validatorEpoch < expected.validatorEpoch
      ? "VALIDATOR_EPOCH_STALE"
      : "VALIDATOR_EPOCH_FUTURE";
  }
  if (supplied.recoveryEpoch !== expected.recoveryEpoch) {
    return supplied.recoveryEpoch < expected.recoveryEpoch
      ? "RECOVERY_EPOCH_STALE"
      : "RECOVERY_EPOCH_FUTURE";
  }
  if (supplied.nonceConsumed) return "NONCE_REPLAY";
  return "SHAPE_ACCEPTED_CRYPTOGRAPHY_NOT_PERFORMED";
}

function validateRecoveryAuthorityShape(input = {}) {
  const {
    bitmap = 3,
    currentRecoveryEpoch = 3,
    suppliedRecoveryEpoch = 3,
    authorityKind = "recovery_threshold"
  } = input;
  if (authorityKind !== "recovery_threshold") {
    return "AUTHORITY_KIND_MISMATCH";
  }
  if ([1, 2, 4].includes(bitmap)) return "RECOVERY_THRESHOLD_NOT_MET";
  if (!freeze.recovery.validBitmaps.includes(bitmap)) {
    return "RECOVERY_FACTOR_BITMAP_INVALID";
  }
  if (suppliedRecoveryEpoch !== currentRecoveryEpoch) {
    return suppliedRecoveryEpoch < currentRecoveryEpoch
      ? "RECOVERY_EPOCH_STALE"
      : "RECOVERY_EPOCH_FUTURE";
  }
  return "SHAPE_ACCEPTED_CRYPTOGRAPHY_NOT_PERFORMED";
}

function solidityFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name);
    if (entry.isDirectory()) return solidityFiles(resolved);
    return entry.name.endsWith(".sol") ? [resolved] : [];
  });
}

const freeze = JSON.parse(fs.readFileSync(FREEZE_PATH, "utf8"));

describe("O.36.1 V2 security interface freeze", function () {
  it("records the exact local-only phase baseline", function () {
    assert.equal(freeze.phase, "O.36.1");
    assert.equal(freeze.classification, "COMPLETE_LOCAL_INTERFACE_FREEZE");
    assert.equal(
      freeze.sourceHeadAtPhaseStart,
      "402b48710eddc8c183dd7ebdc5bba6dc86f5c640"
    );
    assert.equal(freeze.publicMutationCount, 0);
  });

  it("preserves frozen V1 source", function () {
    assert.equal(
      sha256(V1_ACCOUNT),
      "39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a"
    );
    assert.equal(
      sha256(V1_FACTORY),
      "59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9"
    );
  });

  it("freezes direct WebAuthn hardware roles and independent recovery", function () {
    assert.equal(freeze.recovery.threshold, 2);
    assert.deepEqual(freeze.recovery.validBitmaps, [3, 5, 6]);
    assert.deepEqual(
      freeze.recovery.roles.map(({ id, verifierKind }) => [id, verifierKind]),
      [[0, 1], [1, 1], [2, 2]]
    );
    assert.equal(freeze.recovery.validatorCountsAsFactor, false);
    assert.equal(freeze.recovery.combinedValidatorOneFactorAccepted, false);
  });

  it("matches every frozen type hash independently and against O.32", function () {
    for (const name of [
      "identityBinding",
      "webAuthnPublicMaterial",
      "secp256k1PublicMaterial",
      "validatorAuthorization",
      "recoveryFactor",
      "recoveryAuthorization",
      "retiredCombinedCancellation"
    ]) {
      const value = freeze.typeBindings[name];
      assert.equal(keccak256(toUtf8Bytes(value.typeString)), value.typeHash);
    }
    assert.equal(
      freeze.typeBindings.validatorAuthorization.typeString,
      PHILCORE_V2_AUTHORIZATION_TYPE.VALIDATOR_AUTHORIZATION
    );
    assert.equal(
      freeze.typeBindings.validatorAuthorization.typeHash,
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.VALIDATOR_AUTHORIZATION
    );
    assert.equal(
      freeze.typeBindings.recoveryFactor.typeHash,
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.RECOVERY_FACTOR
    );
    assert.equal(
      freeze.typeBindings.recoveryAuthorization.typeHash,
      PHILCORE_V2_AUTHORIZATION_TYPEHASH.RECOVERY_AUTHORIZATION
    );
  });

  it("binds identity deterministically without chain or account input", function () {
    const ownerA = keccak256(toUtf8Bytes("o36.1:public-owner-a"));
    const ownerB = keccak256(toUtf8Bytes("o36.1:public-owner-b"));
    const scheme = freeze.typeBindings.identityBinding.ownerCommitmentSchemeId;
    const sameA = identityBinding(ownerA, scheme);
    assert.equal(identityBinding(ownerA, scheme), sameA);
    assert.notEqual(identityBinding(ownerB, scheme), sameA);
    assert.notEqual(
      identityBinding(ownerA, keccak256(toUtf8Bytes("different-scheme"))),
      sameA
    );
    assert.equal(freeze.typeBindings.identityBinding.chainIndependent, true);
    assert.equal(freeze.typeBindings.identityBinding.accountIndependent, true);
  });

  it("freezes canonical validator evidence and replay bindings", function () {
    assert.equal(freeze.validatorEnvelope.exactBytes, 320);
    assert.equal(freeze.validatorEnvelope.fields.length, 10);
    assert.equal(freeze.validatorEnvelope.lowSRequired, true);
    assert.deepEqual(freeze.validatorEnvelope.canonicalV, [27, 28]);
    assert.equal(freeze.validatorEnvelope.personalSignAccepted, false);
    assert.match(
      freeze.typeBindings.validatorAuthorization.typeString,
      /authorizedIntentHash.*userOpHash.*validatorEpoch.*recoveryEpoch/
    );
  });

  it("rejects malformed, stale, wrong-domain, wrong-account, and replayed validator evidence", function () {
    assert.equal(
      validateValidatorEnvelopeShape({ supplied: { byteLength: 319 } }),
      "VALIDATOR_EVIDENCE_LENGTH_INVALID"
    );
    assert.equal(
      validateValidatorEnvelopeShape({ supplied: { envelopeVersion: 2 } }),
      "VALIDATOR_EVIDENCE_MALFORMED"
    );
    assert.equal(
      validateValidatorEnvelopeShape({ supplied: { validatorEpoch: 3 } }),
      "VALIDATOR_EPOCH_STALE"
    );
    assert.equal(
      validateValidatorEnvelopeShape({ supplied: { chainId: 1 } }),
      "DOMAIN_MISMATCH"
    );
    assert.equal(
      validateValidatorEnvelopeShape({
        supplied: {
          account: "0x2000000000000000000000000000000000000002"
        }
      }),
      "ACCOUNT_MISMATCH"
    );
    assert.equal(
      validateValidatorEnvelopeShape({ supplied: { nonceConsumed: true } }),
      "NONCE_REPLAY"
    );
  });

  it("rejects one-factor, invalid, stale, and combined recovery authority", function () {
    for (const bitmap of [1, 2, 4]) {
      assert.equal(
        validateRecoveryAuthorityShape({ bitmap }),
        "RECOVERY_THRESHOLD_NOT_MET"
      );
    }
    for (const bitmap of [0, 7, 8]) {
      assert.equal(
        validateRecoveryAuthorityShape({ bitmap }),
        "RECOVERY_FACTOR_BITMAP_INVALID"
      );
    }
    assert.equal(
      validateRecoveryAuthorityShape({ suppliedRecoveryEpoch: 2 }),
      "RECOVERY_EPOCH_STALE"
    );
    assert.equal(
      validateRecoveryAuthorityShape({
        authorityKind: "combined_validator_recovery"
      }),
      "AUTHORITY_KIND_MISMATCH"
    );
    for (const bitmap of freeze.recovery.validBitmaps) {
      assert.equal(
        validateRecoveryAuthorityShape({ bitmap }),
        "SHAPE_ACCEPTED_CRYPTOGRAPHY_NOT_PERFORMED"
      );
    }
  });

  it("rejects retired combined cancellation in model and specification", function () {
    const engine = read(
      "apps/phil-device-sdk/src/v2AuthorizationEngine.ts"
    );
    const authoritySelection = engine.slice(
      engine.indexOf("function requiredAuthorityKinds"),
      engine.indexOf("function authorizedTransition")
    );
    assert.doesNotMatch(
      authoritySelection,
      /return \["recovery_threshold", "combined_validator_recovery"\]/
    );
    assert.equal(
      freeze.typeBindings.retiredCombinedCancellation.acceptedByV2Account,
      false
    );
    assert.equal(
      freeze.recovery.cancelAuthority,
      "EXACT_TWO_CURRENT_RECOVERY_FACTORS"
    );
  });

  it("freezes exact implementation versions and closed ABI", function () {
    assert.deepEqual(
      {
        solidity: freeze.solidityFreeze.solidity,
        openzeppelin: freeze.solidityFreeze.openzeppelinContracts,
        accountAbstraction:
          freeze.solidityFreeze.accountAbstractionContracts,
        hardhat: freeze.solidityFreeze.hardhat,
        ethers: freeze.solidityFreeze.ethers
      },
      {
        solidity: "0.8.27",
        openzeppelin: "5.6.1",
        accountAbstraction: "0.7.0",
        hardhat: "2.28.4",
        ethers: "6.17.0"
      }
    );
    assert.equal(freeze.abi.requiredAccountFunctions.length, 16);
    assert.equal(freeze.abi.requiredFactoryFunctions.length, 4);
    for (const forbidden of [
      "execute",
      "executeBatch",
      "delegatecall",
      "upgradeTo",
      "installModule",
      "sweep",
      "approve",
      "setVerifier"
    ]) {
      assert.equal(freeze.abi.forbiddenFunctions.includes(forbidden), true);
    }
  });

  it("keeps unsafe funding and incomplete initialization closed", function () {
    assert.equal(freeze.abi.accountInitializationFieldCount, 20);
    assert.equal(freeze.abi.constructorOnlyInitialization, true);
    assert.equal(freeze.lifecycle.counterfactualFundingAllowed, false);
    assert.equal(
      freeze.lifecycle.fundingBeforeIndependentDeploymentVerificationAllowed,
      false
    );
    assert.equal(freeze.lifecycle.completeInitializationRequired, true);
    assert.equal(freeze.lifecycle.verifiedReleasePathRequiredBeforeFunding, true);
  });

  it("indexes every O.36.1 deliverable and contains no V2 Solidity", function () {
    const canonical = read("docs/CANONICAL_DOCS.md");
    for (const filename of [
      "O36_1_HARDWARE_RECOVERY_SPECIFICATION.md",
      "O36_1_VALIDATOR_INTERFACE_SPECIFICATION.md",
      "O36_1_IDENTITY_COMMITMENT_SPECIFICATION.md",
      "O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md",
      "O36_1_SOLIDITY_IMPLEMENTATION_FREEZE.md",
      "O36_1_SECURITY_GATE_RESOLUTION.md"
    ]) {
      assert.equal(canonical.includes(filename), true, filename);
    }
    for (const sourcePath of solidityFiles(path.join(ROOT, "contracts"))) {
      assert.doesNotMatch(
        fs.readFileSync(sourcePath, "utf8"),
        /contract\s+PhilCoreV2(?:Account|AccountFactory)\b/
      );
    }
  });

  it("creates no authority, account, funds, RPC use, or public mutation", function () {
    for (const [field, value] of Object.entries(freeze.phaseBoundary)) {
      assert.equal(value, field === "publicMutationCount" ? 0 : false, field);
    }
  });
});
