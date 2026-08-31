require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { AbiCoder, keccak256, toUtf8Bytes, getAddress } = require("ethers");

const mod = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts"
);
const {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
  computePhilCoreV2ConsumerRecoveryIndependenceBinding
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_V2_SECURITY_MODEL_ID
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  computePhilCoreV2LocalEnrollmentCeremonyHash
} = require("../../apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts");
const {
  buildO39ConsumerRecoveryFixturePackage
} = require("../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs");

const abiCoder = AbiCoder.defaultAbiCoder();
const C = mod.PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_PROTOCOL_ERROR_CODE;

const INTENT_LITERAL =
  "PhilCoreV2LocalGenesisDeploymentIntentV1(uint8 intentVersion,bytes32 intentId,uint256 chainId,address entryPoint,address factoryBinding,address confirmationTarget,address verifier,bytes32 verifierRuntimeCodeHash,bytes32 accountCreationBytecodeHash,bytes32 accountVersionId,bytes32 securityModelId,bytes32 recoveryDomainId,bytes32 ownerCommitment,bytes32 identityBindingCommitment,address initialValidator,uint8 validatorVerifierKind,bytes32 validatorKeyIdBinding,bytes32 validatorCommitment,uint64 validatorEpoch,uint64 recoveryEpoch,uint64 recoveryDelaySeconds,uint64 recoveryExpirySeconds,bytes32 userSalt,uint48 expiresAt)";

const CEREMONY_LITERAL =
  "PhilCoreV2LocalGenesisEnrollmentCeremonyV1(uint8 ceremonyVersion,bytes32 ceremonyId,bytes32 genesisDeploymentIntentHash,uint8 role,uint64 credentialGeneration,uint48 expiresAt)";

const INTENT_ABI_TYPES = [
  "bytes32", "uint8", "bytes32", "uint256", "address", "address",
  "address", "address", "bytes32", "bytes32", "bytes32", "bytes32",
  "bytes32", "bytes32", "bytes32", "address", "uint8", "bytes32",
  "bytes32", "uint64", "uint64", "uint64", "uint64", "bytes32", "uint48"
];

const CEREMONY_ABI_TYPES = [
  "bytes32", "uint8", "bytes32", "bytes32", "uint8", "uint64", "uint48"
];

const INTENT_FIELD_ORDER = [
  "intentVersion", "intentId", "chainId", "entryPoint", "factoryBinding",
  "confirmationTarget", "verifier", "verifierRuntimeCodeHash",
  "accountCreationBytecodeHash", "accountVersionId", "securityModelId",
  "recoveryDomainId", "ownerCommitment", "identityBindingCommitment",
  "initialValidator", "validatorVerifierKind", "validatorKeyIdBinding",
  "validatorCommitment", "validatorEpoch", "recoveryEpoch",
  "recoveryDelaySeconds", "recoveryExpirySeconds", "userSalt", "expiresAt"
];

const CEREMONY_FIELD_ORDER = [
  "ceremonyVersion", "ceremonyId", "genesisDeploymentIntentHash", "role",
  "credentialGeneration", "expiresAt"
];

const DESCRIPTOR_FIELD_ORDER = [
  "descriptorVersion", "accountVersionId", "securityModelId",
  "recoveryDomainId", "role", "verifierKind",
  "publicVerificationMaterialHash", "credentialIdHash", "rpIdHash",
  "originPolicyHash", "independenceBindingHash", "userVerificationPolicy",
  "backupPolicy", "authenticatorAttachmentPolicy", "attestationPolicy",
  "credentialGeneration"
];

const INDEPENDENCE_FIELD_ORDER = [
  "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
  "independenceAssurance", "credentialIdHash", "enrollmentCeremonyHash",
  "attestationEvidenceHash", "custodyDomainCommitment", "credentialGeneration"
];

function validIntentFields(overrides = {}) {
  return {
    intentVersion: "1",
    intentId: `0x${"11".repeat(32)}`,
    chainId: "11155111",
    entryPoint: getAddress(`0x${"22".repeat(20)}`),
    factoryBinding: getAddress(`0x${"33".repeat(20)}`),
    confirmationTarget: getAddress(`0x${"44".repeat(20)}`),
    verifier: getAddress(`0x${"55".repeat(20)}`),
    verifierRuntimeCodeHash: `0x${"66".repeat(32)}`,
    accountCreationBytecodeHash: `0x${"77".repeat(32)}`,
    accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
    ownerCommitment: `0x${"88".repeat(32)}`,
    identityBindingCommitment: `0x${"99".repeat(32)}`,
    initialValidator: getAddress(`0x${"aa".repeat(20)}`),
    validatorVerifierKind: "1",
    validatorKeyIdBinding: `0x${"bb".repeat(32)}`,
    validatorCommitment: `0x${"cc".repeat(32)}`,
    validatorEpoch: "1",
    recoveryEpoch: "1",
    recoveryDelaySeconds: "172800",
    recoveryExpirySeconds: "604800",
    userSalt: `0x${"dd".repeat(32)}`,
    expiresAt: "1900000000",
    ...overrides
  };
}

function referenceIntentDigest(fields) {
  return keccak256(
    abiCoder.encode(INTENT_ABI_TYPES, [
      mod.PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_TYPEHASH,
      BigInt(fields.intentVersion),
      fields.intentId,
      BigInt(fields.chainId),
      fields.entryPoint,
      fields.factoryBinding,
      fields.confirmationTarget,
      fields.verifier,
      fields.verifierRuntimeCodeHash,
      fields.accountCreationBytecodeHash,
      fields.accountVersionId,
      fields.securityModelId,
      fields.recoveryDomainId,
      fields.ownerCommitment,
      fields.identityBindingCommitment,
      fields.initialValidator,
      BigInt(fields.validatorVerifierKind),
      fields.validatorKeyIdBinding,
      fields.validatorCommitment,
      BigInt(fields.validatorEpoch),
      BigInt(fields.recoveryEpoch),
      BigInt(fields.recoveryDelaySeconds),
      BigInt(fields.recoveryExpirySeconds),
      fields.userSalt,
      BigInt(fields.expiresAt)
    ])
  );
}

function validCeremonyFields(role, intentHash, overrides = {}) {
  return {
    ceremonyVersion: "1",
    ceremonyId: `0x${String(role + 1).padStart(2, "0")}${"a1".repeat(31)}`,
    genesisDeploymentIntentHash: intentHash,
    role: String(role),
    credentialGeneration: "1",
    expiresAt: "1900000000",
    ...overrides
  };
}

function referenceCeremonyDigest(fields) {
  return keccak256(
    abiCoder.encode(CEREMONY_ABI_TYPES, [
      mod.PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_TYPEHASH,
      BigInt(fields.ceremonyVersion),
      fields.ceremonyId,
      fields.genesisDeploymentIntentHash,
      BigInt(fields.role),
      BigInt(fields.credentialGeneration),
      BigInt(fields.expiresAt)
    ])
  );
}

const ROOT = path.resolve(__dirname, "../..");
const FIXTURE_PATH = path.join(
  ROOT,
  "config/cryptography/O39_CONSUMER_RECOVERY_FIXTURES.json"
);
const fixtures = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));

// Builds a fully valid genesis-shaped 3-role profile: reuses the O.39
// fixture package's structural (policy/material/custody) values for each
// role, but rebinds independence.enrollmentCeremonyHash and generation to
// genesis semantics and recomputes independenceBindingHash accordingly --
// mirroring O.39's own established `rebind()` technique exactly.
function buildValidGenesisProfile(intentOverrides = {}) {
  // The genesis intent's own initialValidator is the validator the account
  // installs on-chain at genesis (PhilCoreV2MinimalAccountV2.sol sets
  // _activeValidator = initialization.initialValidator). The profile's
  // separately supplied executionValidator must match it exactly, so the
  // default fixture binds them to the same canonical address by construction
  // -- a caller that wants to test a mismatch overrides initialValidator
  // explicitly via intentOverrides.
  const intentFields = validIntentFields({
    initialValidator: fixtures.profiles.standard.request.validator,
    ...intentOverrides
  });
  const intentHash = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(intentFields);

  const source = fixtures.profiles.standard.factors;
  const roleSources = [source.primary, source.secondary, source.offline];

  const ceremonies = [0, 1, 2].map((role) =>
    validCeremonyFields(role, intentHash)
  );
  const ceremonyHashes = ceremonies.map((ceremony) =>
    mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(ceremony)
  );

  const factors = [0, 1, 2].map((role) => {
    const base = roleSources[role];
    // The O.39 fixture package is loaded from JSON, so its numeric fields
    // (role, etc.) are plain JS numbers. This module's own validators reject
    // JS numbers for numeric public inputs, so every numeric field re-used
    // from the fixture is explicitly normalized to bigint here.
    const independence = {
      ...base.independence,
      role: BigInt(role),
      enrollmentCeremonyHash: ceremonyHashes[role],
      credentialGeneration: 1n
    };
    const descriptor = {
      ...base.descriptor,
      role: BigInt(role),
      credentialGeneration: 1n,
      independenceBindingHash:
        computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence)
    };
    const factor = { descriptor, independence };
    if (base.signer) factor.signer = base.signer;
    return factor;
  });

  return {
    intent: intentFields,
    intentHash,
    ceremonies,
    ceremonyHashes,
    factors,
    executionValidator: fixtures.profiles.standard.request.validator
  };
}

function cloneFactorsPlain(factors) {
  return factors.map((factor) => ({
    descriptor: { ...factor.descriptor },
    independence: { ...factor.independence },
    ...(factor.signer ? { signer: factor.signer } : {})
  }));
}

// Confirms that no own or inherited property of a caught, classified error
// (including a non-enumerable `cause`) holds the exact hostile marker
// object -- i.e. the marker is genuinely unreachable from the outside.
function assertMarkerUnreachable(caught, marker) {
  assert.ok(caught instanceof mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError);
  assert.notEqual(caught.cause, marker);
  const names = Object.getOwnPropertyNames(caught);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(caught, name);
    assert.notEqual(descriptor.value, marker, `own property ${name} must not hold the marker`);
  }
}

describe("V2 consumer recovery genesis protocol (Package 5B-0.2)", function () {
  describe("export surface", function () {
    it("exports exactly the nine authorized runtime values", function () {
      const expected = [
        "PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_LITERAL",
        "PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_TYPEHASH",
        "PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_LITERAL",
        "PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_TYPEHASH",
        "PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_PROTOCOL_ERROR_CODE",
        "PhilCoreV2ConsumerRecoveryGenesisProtocolError",
        "computePhilCoreV2LocalGenesisDeploymentIntentHash",
        "computePhilCoreV2LocalGenesisEnrollmentCeremonyHash",
        "validatePhilCoreV2ConsumerRecoveryGenesisProfile"
      ];
      const actual = Object.keys(mod).sort();
      assert.deepEqual(actual, [...expected].sort());
      assert.equal(actual.length, 9);
    });
  });

  describe("literals and typehashes", function () {
    it("exact literal strings byte-for-byte", function () {
      assert.equal(mod.PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_LITERAL, INTENT_LITERAL);
      assert.equal(mod.PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_LITERAL, CEREMONY_LITERAL);
    });

    it("typehashes are independently recomputed keccak256(toUtf8Bytes(literal))", function () {
      assert.equal(
        mod.PHILCORE_V2_LOCAL_GENESIS_DEPLOYMENT_INTENT_TYPEHASH,
        keccak256(toUtf8Bytes(INTENT_LITERAL))
      );
      assert.equal(
        mod.PHILCORE_V2_LOCAL_GENESIS_ENROLLMENT_CEREMONY_TYPEHASH,
        keccak256(toUtf8Bytes(CEREMONY_LITERAL))
      );
    });
  });

  describe("computePhilCoreV2LocalGenesisDeploymentIntentHash", function () {
    it("known-answer digest via ABI (not packed) encoding, independently proving all 24 fields including pinned fields are present and correctly positioned", function () {
      const fields = validIntentFields();
      assert.equal(
        mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields),
        referenceIntentDigest(fields)
      );
    });

    it("each of the 15 non-pinned fields is load-bearing (the other 9 -- accountVersionId, securityModelId, recoveryDomainId, validatorVerifierKind, intentVersion, validatorEpoch, recoveryEpoch, recoveryDelaySeconds, recoveryExpirySeconds -- are pinned to a single valid value and cannot be mutated while remaining valid; their presence is proven by the known-answer digest test above)", function () {
      const base = validIntentFields();
      const baseDigest = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(base);
      const mutations = {
        intentId: `0x${"12".repeat(32)}`,
        userSalt: `0x${"ed".repeat(32)}`,
        verifierRuntimeCodeHash: `0x${"67".repeat(32)}`,
        accountCreationBytecodeHash: `0x${"78".repeat(32)}`,
        ownerCommitment: `0x${"89".repeat(32)}`,
        identityBindingCommitment: `0x${"9a".repeat(32)}`,
        validatorKeyIdBinding: `0x${"bc".repeat(32)}`,
        validatorCommitment: `0x${"cd".repeat(32)}`,
        chainId: "1",
        entryPoint: getAddress(`0x${"23".repeat(20)}`),
        factoryBinding: getAddress(`0x${"34".repeat(20)}`),
        confirmationTarget: getAddress(`0x${"45".repeat(20)}`),
        verifier: getAddress(`0x${"56".repeat(20)}`),
        initialValidator: getAddress(`0x${"ab".repeat(20)}`),
        expiresAt: "1900000001"
      };
      assert.equal(Object.keys(mutations).length, 15);
      for (const [field, mutated] of Object.entries(mutations)) {
        const digest = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash({
          ...base,
          [field]: mutated
        });
        assert.notEqual(digest, baseDigest, `field ${field} must be load-bearing`);
      }
    });

    it("different intent IDs differ", function () {
      const a = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(validIntentFields());
      const b = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
        validIntentFields({ intentId: `0x${"aa".repeat(32)}` })
      );
      assert.notEqual(a, b);
    });

    it("different user salts differ", function () {
      const a = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(validIntentFields());
      const b = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
        validIntentFields({ userSalt: `0x${"ee".repeat(32)}` })
      );
      assert.notEqual(a, b);
    });

    it("exact 24-key own-key surface excludes account, factor commitments, and recovery configuration hash", function () {
      const keys = Object.keys(validIntentFields());
      assert.equal(keys.length, 24);
      assert.deepEqual(keys.sort(), [...INTENT_FIELD_ORDER].sort());
      for (const forbidden of [
        "account", "counterfactualAccount", "primaryDeviceRecoveryCommitment",
        "hardwareSecurityKeyCommitment", "independentRecoveryFactorCommitment",
        "recoveryConfigurationHash", "accountCreationCodeHash"
      ]) {
        assert.equal(keys.includes(forbidden), false);
      }
    });

    it("rejects null, arrays, and non-object input", function () {
      for (const bad of [null, [], "x", 1, undefined]) {
        assert.throws(
          () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(bad),
          (error) => error.code === C.INTENT_INPUT_NOT_OBJECT
        );
      }
    });

    it("rejects an extra own key", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash({
          ...validIntentFields(),
          extra: "0x00"
        }),
        (error) => error.code === C.INTENT_EXTRA_OWN_KEY
      );
    });

    it("rejects an extra non-enumerable own key", function () {
      const fields = validIntentFields();
      Object.defineProperty(fields, "hiddenExtra", {
        value: "x", enumerable: false, configurable: true
      });
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields),
        (error) => error.code === C.INTENT_EXTRA_OWN_KEY
      );
    });

    it("rejects an extra symbol own key", function () {
      const fields = validIntentFields();
      fields[Symbol("extra")] = "x";
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields),
        (error) => error.code === C.INTENT_EXTRA_OWN_KEY
      );
    });

    it("rejects a nested __proto__ own-key payload before snapshot construction", function () {
      const fields = validIntentFields();
      Object.defineProperty(fields, "__proto__", {
        value: { polluted: true }, enumerable: true, configurable: true
      });
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields),
        (error) => error.code === C.INTENT_EXTRA_OWN_KEY
      );
    });

    it("rejects a missing own key", function () {
      const fields = validIntentFields();
      delete fields.userSalt;
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields),
        (error) => error.code === C.INTENT_MISSING_OWN_KEY
      );
    });

    it("rejects an inherited-only key (not an own property)", function () {
      const proto = { userSalt: `0x${"dd".repeat(32)}` };
      const fields = Object.assign(Object.create(proto), validIntentFields());
      delete fields.userSalt;
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields),
        (error) => error.code === C.INTENT_MISSING_OWN_KEY
      );
    });

    it("rejects explicit undefined for a required field", function () {
      assert.throws(() =>
        mod.computePhilCoreV2LocalGenesisDeploymentIntentHash({
          ...validIntentFields(),
          userSalt: undefined
        })
      );
    });

    it("rejects a throwing getter without leaking the raw thrown value", function () {
      const fields = validIntentFields();
      const marker = { poison: "raw-value-must-not-escape" };
      let reads = 0;
      Object.defineProperty(fields, "userSalt", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.INTENT_PROPERTY_READ_FAILED);
      assertMarkerUnreachable(caught, marker);
      assert.doesNotMatch(JSON.stringify(caught, Object.getOwnPropertyNames(caught)), /raw-value-must-not-escape/u);
      assert.equal(reads, 1);
    });

    it("rejects an ownKeys trap that throws", function () {
      const trap = new Proxy(validIntentFields(), {
        ownKeys() {
          throw new Error("enumeration hostile");
        }
      });
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(trap),
        (error) => error.code === C.INTENT_ENUMERATION_FAILED
      );
    });

    it("rejects a revoked Proxy safely, no raw TypeError escapes uncoded", function () {
      const { proxy, revoke } = Proxy.revocable(validIntentFields(), {});
      revoke();
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(proxy),
        (error) => typeof error.code === "string"
      );
    });

    it("rejects intentVersion !== 1", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ intentVersion: "2" })
        ),
        (error) => error.code === C.INTENT_VERSION_MISMATCH
      );
    });

    it("rejects a zero intentId", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ intentId: `0x${"00".repeat(32)}` })
        ),
        (error) => error.code === C.INTENT_ID_ZERO
      );
    });

    it("rejects a malformed intentId", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ intentId: "0x1234" })
        ),
        (error) => error.code === C.INTENT_ID_INVALID
      );
    });

    it("rejects a zero chainId", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ chainId: "0" })
        ),
        (error) => error.code === C.CHAIN_ID_ZERO
      );
    });

    it("rejects non-EIP-55-canonical addresses", function () {
      const lower = getAddress(`0x${"aa".repeat(20)}`).toLowerCase();
      assert.notEqual(lower, getAddress(`0x${"aa".repeat(20)}`));
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ initialValidator: lower })
        ),
        (error) => error.code === C.INITIAL_VALIDATOR_INVALID
      );
    });

    it("rejects zero addresses per field with a distinguishable code", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ entryPoint: "0x0000000000000000000000000000000000000000" })
        ),
        (error) => error.code === C.ENTRY_POINT_ZERO
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ factoryBinding: "0x0000000000000000000000000000000000000000" })
        ),
        (error) => error.code === C.FACTORY_BINDING_ZERO
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ confirmationTarget: "0x0000000000000000000000000000000000000000" })
        ),
        (error) => error.code === C.CONFIRMATION_TARGET_ZERO
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ verifier: "0x0000000000000000000000000000000000000000" })
        ),
        (error) => error.code === C.VERIFIER_ZERO
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ initialValidator: "0x0000000000000000000000000000000000000000" })
        ),
        (error) => error.code === C.INITIAL_VALIDATOR_ZERO
      );
    });

    it("rejects each zero bytes32 field with a distinguishable code (no two unrelated fields share a code)", function () {
      const zero = `0x${"00".repeat(32)}`;
      const cases = [
        ["verifierRuntimeCodeHash", C.VERIFIER_RUNTIME_CODE_HASH_ZERO],
        ["accountCreationBytecodeHash", C.ACCOUNT_CREATION_BYTECODE_HASH_ZERO],
        ["ownerCommitment", C.OWNER_COMMITMENT_ZERO],
        ["identityBindingCommitment", C.IDENTITY_BINDING_COMMITMENT_ZERO],
        ["validatorKeyIdBinding", C.VALIDATOR_KEY_ID_BINDING_ZERO],
        ["validatorCommitment", C.VALIDATOR_COMMITMENT_ZERO],
        ["userSalt", C.USER_SALT_ZERO]
      ];
      const codes = new Set();
      for (const [field, code] of cases) {
        assert.throws(
          () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
            validIntentFields({ [field]: zero })
          ),
          (error) => error.code === code
        );
        codes.add(code);
      }
      assert.equal(codes.size, cases.length, "every field must have a distinct zero code");
      // Cross-check the specific triple the review called out by name.
      assert.notEqual(C.INTENT_ID_INVALID, C.USER_SALT_INVALID);
      assert.notEqual(C.USER_SALT_INVALID, C.VALIDATOR_COMMITMENT_INVALID);
      assert.notEqual(C.INTENT_ID_INVALID, C.VALIDATOR_COMMITMENT_INVALID);
    });

    it("rejects mismatched accountVersionId, securityModelId, recoveryDomainId", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ accountVersionId: `0x${"01".repeat(32)}` })
        ),
        (error) => error.code === C.ACCOUNT_VERSION_ID_MISMATCH
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ securityModelId: `0x${"01".repeat(32)}` })
        ),
        (error) => error.code === C.SECURITY_MODEL_ID_MISMATCH
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ recoveryDomainId: `0x${"01".repeat(32)}` })
        ),
        (error) => error.code === C.RECOVERY_DOMAIN_ID_MISMATCH
      );
    });

    it("rejects mismatched validatorVerifierKind", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ validatorVerifierKind: "2" })
        ),
        (error) => error.code === C.VALIDATOR_VERIFIER_KIND_MISMATCH
      );
    });

    it("rejects mismatched validatorEpoch, recoveryEpoch, recoveryDelaySeconds, recoveryExpirySeconds", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(validIntentFields({ validatorEpoch: "2" })),
        (error) => error.code === C.VALIDATOR_EPOCH_MISMATCH
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(validIntentFields({ recoveryEpoch: "2" })),
        (error) => error.code === C.RECOVERY_EPOCH_MISMATCH
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(validIntentFields({ recoveryDelaySeconds: "1" })),
        (error) => error.code === C.RECOVERY_DELAY_SECONDS_MISMATCH
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(validIntentFields({ recoveryExpirySeconds: "1" })),
        (error) => error.code === C.RECOVERY_EXPIRY_SECONDS_MISMATCH
      );
    });

    it("rejects a zero expiresAt", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ expiresAt: "0" })
        ),
        (error) => error.code === C.INTENT_EXPIRES_AT_ZERO
      );
    });

    it("rejects JavaScript numbers for numeric fields with a field-specific code", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ chainId: 11155111 })
        ),
        (error) => error.code === C.CHAIN_ID_INVALID
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ intentVersion: 1 })
        ),
        (error) => error.code === C.INTENT_VERSION_INVALID
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ validatorVerifierKind: 1 })
        ),
        (error) => error.code === C.VALIDATOR_VERIFIER_KIND_INVALID
      );
    });

    it("rejects leading zeros, signs, whitespace, exponents, decimals, and empty numeric strings", function () {
      for (const bad of ["01", "+1", " 1", "1 ", "1e2", "1.0", "", "-1"]) {
        assert.throws(
          () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
            validIntentFields({ chainId: bad })
          ),
          (error) => error.code === C.CHAIN_ID_INVALID
        );
      }
    });

    it("rejects width overflow at each numeric field's own bit width", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ validatorEpoch: (1n << 64n).toString(10) })
        ),
        (error) => error.code === C.VALIDATOR_EPOCH_INVALID
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ chainId: (1n << 256n).toString(10) })
        ),
        (error) => error.code === C.CHAIN_ID_INVALID
      );
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ expiresAt: (1n << 48n).toString(10) })
        ),
        (error) => error.code === C.INTENT_EXPIRES_AT_INVALID
      );
    });

    it("rejects non-lowercase bytes32", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
          validIntentFields({ userSalt: `0x${"DD".repeat(32)}` })
        ),
        (error) => error.code === C.USER_SALT_INVALID
      );
    });
  });

  describe("computePhilCoreV2LocalGenesisEnrollmentCeremonyHash", function () {
    const intentHash = `0x${"ab".repeat(32)}`;

    it("known-answer digest via ABI encoding, independently proving all six fields including pinned fields are present", function () {
      const ceremony = validCeremonyFields(0, intentHash);
      assert.equal(
        mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(ceremony),
        referenceCeremonyDigest(ceremony)
      );
    });

    it("each of the 4 non-pinned fields is load-bearing (ceremonyVersion and credentialGeneration are pinned to 1 and cannot be mutated while remaining valid; their presence is proven by the known-answer digest test above)", function () {
      const base = validCeremonyFields(1, intentHash);
      const baseDigest = mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(base);
      const mutations = {
        ceremonyId: `0x${"ff".repeat(32)}`,
        genesisDeploymentIntentHash: `0x${"cd".repeat(32)}`,
        role: "2",
        expiresAt: "1900000001"
      };
      assert.equal(Object.keys(mutations).length, 4);
      for (const [field, mutated] of Object.entries(mutations)) {
        const digest = mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash({
          ...base,
          [field]: mutated
        });
        assert.notEqual(digest, baseDigest, `field ${field} must be load-bearing`);
      }
    });

    it("exact six-key own-key surface excludes account, chainId, entryPoint, and any binding-kind field", function () {
      const keys = Object.keys(validCeremonyFields(0, intentHash));
      assert.deepEqual(keys.sort(), [...CEREMONY_FIELD_ORDER].sort());
      for (const forbidden of ["account", "chainId", "entryPoint", "bindingKind", "intentId"]) {
        assert.equal(keys.includes(forbidden), false);
      }
    });

    it("rejects ceremonyVersion !== 1", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
          validCeremonyFields(0, intentHash, { ceremonyVersion: "2" })
        ),
        (error) => error.code === C.CEREMONY_VERSION_MISMATCH
      );
    });

    it("rejects a zero ceremonyId", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
          validCeremonyFields(0, intentHash, { ceremonyId: `0x${"00".repeat(32)}` })
        ),
        (error) => error.code === C.CEREMONY_ID_ZERO
      );
    });

    it("rejects a zero genesisDeploymentIntentHash", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
          validCeremonyFields(0, intentHash, {
            genesisDeploymentIntentHash: `0x${"00".repeat(32)}`
          })
        ),
        (error) => error.code === C.CEREMONY_GENESIS_DEPLOYMENT_INTENT_HASH_ZERO
      );
    });

    it("rejects a role outside {0,1,2}", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
          validCeremonyFields(0, intentHash, { role: "3" })
        ),
        (error) => error.code === C.CEREMONY_ROLE_INVALID
      );
    });

    it("rejects credentialGeneration !== 1", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
          validCeremonyFields(0, intentHash, { credentialGeneration: "2" })
        ),
        (error) => error.code === C.CEREMONY_GENERATION_MISMATCH
      );
    });

    it("rejects a zero expiresAt", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(
          validCeremonyFields(0, intentHash, { expiresAt: "0" })
        ),
        (error) => error.code === C.CEREMONY_EXPIRES_AT_ZERO
      );
    });

    it("rejects extra (enumerable, non-enumerable, symbol), missing, inherited, and explicit undefined fields", function () {
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash({
          ...validCeremonyFields(0, intentHash),
          extra: "0x00"
        }),
        (error) => error.code === C.CEREMONY_EXTRA_OWN_KEY
      );
      const hiddenExtra = validCeremonyFields(0, intentHash);
      Object.defineProperty(hiddenExtra, "hidden", {
        value: "x", enumerable: false, configurable: true
      });
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(hiddenExtra),
        (error) => error.code === C.CEREMONY_EXTRA_OWN_KEY
      );
      const symbolExtra = validCeremonyFields(0, intentHash);
      symbolExtra[Symbol("extra")] = "x";
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(symbolExtra),
        (error) => error.code === C.CEREMONY_EXTRA_OWN_KEY
      );
      const missing = validCeremonyFields(0, intentHash);
      delete missing.role;
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(missing),
        (error) => error.code === C.CEREMONY_MISSING_OWN_KEY
      );
      const proto = { role: "0" };
      const inherited = Object.assign(Object.create(proto), validCeremonyFields(0, intentHash));
      delete inherited.role;
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(inherited),
        (error) => error.code === C.CEREMONY_MISSING_OWN_KEY
      );
      assert.throws(() =>
        mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash({
          ...validCeremonyFields(0, intentHash),
          role: undefined
        })
      );
    });

    it("rejects a getter that throws without leaking the raw thrown value, and reads it exactly once", function () {
      const fields = validCeremonyFields(0, intentHash);
      const marker = { poison: "ceremony-field-marker" };
      let reads = 0;
      Object.defineProperty(fields, "ceremonyId", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(fields);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.CEREMONY_PROPERTY_READ_FAILED);
      assertMarkerUnreachable(caught, marker);
      assert.equal(reads, 1);
    });
  });

  describe("validatePhilCoreV2ConsumerRecoveryGenesisProfile", function () {
    it("accepts a fully valid genesis profile and returns a deeply frozen result at every reachable level", function () {
      const built = buildValidGenesisProfile();
      const result = mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
        intent: built.intent,
        ceremonies: built.ceremonies,
        factors: built.factors,
        executionValidator: built.executionValidator
      });
      assert.equal(result.genesisDeploymentIntentHash, built.intentHash);
      assert.deepEqual(
        [...result.genesisEnrollmentCeremonyHashes],
        built.ceremonyHashes
      );
      assert.equal(result.profile.profile, "STANDARD");
      assert.equal(Object.isFrozen(result), true);
      assert.equal(Object.isFrozen(result.genesisEnrollmentCeremonyHashes), true);
      assert.equal(Object.isFrozen(result.profile), true);
      assert.equal(Object.isFrozen(result.profile.descriptors), true);
      assert.equal(Object.isFrozen(result.profile.commitments), true);
      assert.equal(Object.isFrozen(result.profile.warnings), true);
    });

    it("accepts when executionValidator exactly canonically equals intent.initialValidator (matching canonical values pass)", function () {
      const built = buildValidGenesisProfile();
      assert.equal(built.intent.initialValidator, built.executionValidator);
      assert.doesNotThrow(() =>
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: built.factors,
          executionValidator: built.executionValidator
        })
      );
    });

    it("rejects a structurally valid profile whose executionValidator differs from intent.initialValidator", function () {
      const built = buildValidGenesisProfile();
      const differentValidator = getAddress(`0x${"cc".repeat(20)}`);
      assert.notEqual(differentValidator, built.intent.initialValidator);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: built.factors,
          executionValidator: differentValidator
        }),
        (error) => error.code === C.EXECUTION_VALIDATOR_INTENT_MISMATCH
      );
    });

    it("rejects a lowercase/non-canonical executionValidator with the same mismatch code", function () {
      const built = buildValidGenesisProfile();
      const lower = built.intent.initialValidator.toLowerCase();
      assert.notEqual(lower, built.intent.initialValidator);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: built.factors,
          executionValidator: lower
        }),
        (error) => error.code === C.EXECUTION_VALIDATOR_INTENT_MISMATCH
      );
    });

    it("rejects a zero, malformed, or non-string executionValidator with the same mismatch code", function () {
      const built = buildValidGenesisProfile();
      for (const bad of [
        "0x0000000000000000000000000000000000000000",
        "0x1234",
        "not-an-address",
        1,
        null,
        undefined,
        {}
      ]) {
        assert.throws(
          () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
            intent: built.intent,
            ceremonies: built.ceremonies,
            factors: built.factors,
            executionValidator: bad
          }),
          (error) => error.code === C.EXECUTION_VALIDATOR_INTENT_MISMATCH,
          `expected EXECUTION_VALIDATOR_INTENT_MISMATCH for executionValidator ${JSON.stringify(bad)}`
        );
      }
    });

    it("reads the executionValidator getter exactly once", function () {
      const built = buildValidGenesisProfile();
      let reads = 0;
      const input = {
        intent: built.intent,
        ceremonies: built.ceremonies,
        factors: built.factors
      };
      Object.defineProperty(input, "executionValidator", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          return built.executionValidator;
        }
      });
      mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile(input);
      assert.equal(reads, 1);
    });

    it("a throwing executionValidator getter still classifies as PROFILE_PROPERTY_READ_FAILED, not the mismatch code", function () {
      const built = buildValidGenesisProfile();
      const marker = { poison: "execution-validator-getter-marker" };
      const input = {
        intent: built.intent,
        ceremonies: built.ceremonies,
        factors: built.factors
      };
      Object.defineProperty(input, "executionValidator", {
        enumerable: true,
        configurable: true,
        get() {
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile(input);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.PROFILE_PROPERTY_READ_FAILED);
      assert.notEqual(caught.cause, marker);
    });

    it("an earlier ceremony/factor provenance failure precedes the executionValidator mismatch check", function () {
      const built = buildValidGenesisProfile();
      const differentValidator = getAddress(`0x${"cc".repeat(20)}`);
      const tampered = cloneFactorsPlain(built.factors);
      tampered[0].descriptor.role = 1n;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: differentValidator
        }),
        (error) => error.code === C.FACTOR_ROLE_MISMATCH
      );
    });

    it("after executionValidator equality succeeds, a genuine generic-profile defect still maps to GENERIC_PROFILE_VALIDATION_FAILED", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      tampered[1].independence.credentialIdHash = tampered[0].independence.credentialIdHash;
      tampered[1].descriptor.credentialIdHash = tampered[0].descriptor.credentialIdHash;
      tampered[1].descriptor.independenceBindingHash =
        computePhilCoreV2ConsumerRecoveryIndependenceBinding(tampered[1].independence);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.GENERIC_PROFILE_VALIDATION_FAILED
      );
    });

    it("rejects non-object top-level input", function () {
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile(null),
        (error) => error.code === C.PROFILE_INPUT_NOT_OBJECT
      );
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile([]),
        (error) => error.code === C.PROFILE_INPUT_NOT_OBJECT
      );
    });

    it("rejects extra and missing top-level keys, including non-enumerable and symbol extras", function () {
      const built = buildValidGenesisProfile();
      const base = {
        intent: built.intent,
        ceremonies: built.ceremonies,
        factors: built.factors,
        executionValidator: built.executionValidator
      };
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({ ...base, extra: 1 }),
        (error) => error.code === C.PROFILE_EXTRA_OWN_KEY
      );
      const hiddenExtra = { ...base };
      Object.defineProperty(hiddenExtra, "hidden", {
        value: 1, enumerable: false, configurable: true
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile(hiddenExtra),
        (error) => error.code === C.PROFILE_EXTRA_OWN_KEY
      );
      const symbolExtra = { ...base };
      symbolExtra[Symbol("extra")] = 1;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile(symbolExtra),
        (error) => error.code === C.PROFILE_EXTRA_OWN_KEY
      );
      const missing = { ...base };
      delete missing.executionValidator;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile(missing),
        (error) => error.code === C.PROFILE_MISSING_OWN_KEY
      );
    });

    it("rejects ceremonies that are not an exact three-tuple", function () {
      const built = buildValidGenesisProfile();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies.slice(0, 2),
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONIES_NOT_TUPLE
      );
    });

    it("rejects factors that are not an exact three-tuple", function () {
      const built = buildValidGenesisProfile();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [...built.factors, built.factors[0]],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTORS_NOT_TUPLE
      );
    });

    it("rejects a getter at ceremonies[0] that throws a raw marker -- the marker never escapes and the tuple is rejected as CEREMONIES_NOT_TUPLE", function () {
      const built = buildValidGenesisProfile();
      const marker = { poison: "ceremonies-index-0-marker" };
      const hostileCeremonies = [...built.ceremonies];
      Object.defineProperty(hostileCeremonies, "0", {
        enumerable: true,
        configurable: true,
        get() {
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: hostileCeremonies,
          factors: built.factors,
          executionValidator: built.executionValidator
        });
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.CEREMONIES_NOT_TUPLE);
      assertMarkerUnreachable(caught, marker);
    });

    it("rejects a getter at factors[0] that throws a raw marker -- the marker never escapes and the tuple is rejected as FACTORS_NOT_TUPLE", function () {
      const built = buildValidGenesisProfile();
      const marker = { poison: "factors-index-0-marker" };
      const hostileFactors = [...built.factors];
      Object.defineProperty(hostileFactors, "0", {
        enumerable: true,
        configurable: true,
        get() {
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: hostileFactors,
          executionValidator: built.executionValidator
        });
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.FACTORS_NOT_TUPLE);
      assertMarkerUnreachable(caught, marker);
    });

    it("rejects a Proxy tuple whose length descriptor inspection throws a raw marker -- the marker never escapes", function () {
      // Tuple length and indices are now read exclusively from a verified
      // Object.getOwnPropertyDescriptor result (see the own-property Proxy
      // corrective pass below), never from an ordinary property GET -- so a
      // Proxy that only overrides `get` no longer intercepts the read at
      // all. The hostile boundary that remains reachable for "length" is
      // the getOwnPropertyDescriptor trap itself.
      const built = buildValidGenesisProfile();
      const marker = { poison: "length-getOwnPropertyDescriptor-marker" };
      const hostileCeremonies = new Proxy(built.ceremonies, {
        getOwnPropertyDescriptor(target, prop) {
          if (prop === "length") throw marker;
          return Reflect.getOwnPropertyDescriptor(target, prop);
        }
      });
      let caught = null;
      try {
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: hostileCeremonies,
          factors: built.factors,
          executionValidator: built.executionValidator
        });
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.CEREMONIES_NOT_TUPLE);
      assertMarkerUnreachable(caught, marker);
    });

    it("rejects a revoked Proxy presented as the ceremonies tuple", function () {
      const built = buildValidGenesisProfile();
      const { proxy, revoke } = Proxy.revocable(built.ceremonies, {});
      revoke();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: proxy,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONIES_NOT_TUPLE
      );
    });

    it("rejects a revoked Proxy presented as the factors tuple", function () {
      const built = buildValidGenesisProfile();
      const { proxy, revoke } = Proxy.revocable(built.factors, {});
      revoke();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: proxy,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTORS_NOT_TUPLE
      );
    });

    it("rejects a sparse (holed) ceremonies tuple", function () {
      const built = buildValidGenesisProfile();
      const sparse = [built.ceremonies[0], , built.ceremonies[2]];
      assert.equal(sparse.length, 3);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: sparse,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONIES_NOT_TUPLE
      );
    });

    it("rejects an extra own property on the ceremonies array itself (not an index, not length)", function () {
      const built = buildValidGenesisProfile();
      const withExtra = [...built.ceremonies];
      withExtra.extraProp = "hostile";
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: withExtra,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONIES_NOT_TUPLE
      );
    });

    it("rejects a symbol-keyed extra property on the factors array itself", function () {
      const built = buildValidGenesisProfile();
      const withExtra = [...built.factors];
      withExtra[Symbol("extra")] = "hostile";
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: withExtra,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTORS_NOT_TUPLE
      );
    });

    it("rejects a length !== 3 disguised via an ownKeys trap that lies about indices", function () {
      const built = buildValidGenesisProfile();
      const hostile = new Proxy([built.ceremonies[0], built.ceremonies[1]], {});
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: hostile,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONIES_NOT_TUPLE
      );
    });

    it("rejects a ceremony object with an extra non-enumerable own key", function () {
      const built = buildValidGenesisProfile();
      const hostileCeremony = { ...built.ceremonies[0] };
      Object.defineProperty(hostileCeremony, "hidden", {
        value: "x", enumerable: false, configurable: true
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: [hostileCeremony, built.ceremonies[1], built.ceremonies[2]],
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONY_EXTRA_OWN_KEY
      );
    });

    it("rejects an intent with an extra symbol own key at the profile boundary", function () {
      const built = buildValidGenesisProfile();
      const hostileIntent = { ...built.intent };
      hostileIntent[Symbol("extra")] = "x";
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: hostileIntent,
          ceremonies: built.ceremonies,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.INTENT_EXTRA_OWN_KEY
      );
    });

    it("rejects a factor object with an extra non-enumerable own key", function () {
      const built = buildValidGenesisProfile();
      const hostileFactor = { descriptor: built.factors[0].descriptor, independence: built.factors[0].independence };
      Object.defineProperty(hostileFactor, "hidden", {
        value: "x", enumerable: false, configurable: true
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [hostileFactor, built.factors[1], built.factors[2]],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INPUT_NOT_OBJECT
      );
    });

    it("rejects a descriptor with an extra own key (enumerable, non-enumerable, and symbol)", function () {
      const built = buildValidGenesisProfile();
      const withExtra = cloneFactorsPlain(built.factors);
      withExtra[0].descriptor.extra = "x";
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: withExtra,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );

      const withHidden = cloneFactorsPlain(built.factors);
      Object.defineProperty(withHidden[0].descriptor, "hidden", {
        value: "x", enumerable: false, configurable: true
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: withHidden,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );

      const withSymbol = cloneFactorsPlain(built.factors);
      withSymbol[0].descriptor[Symbol("extra")] = "x";
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: withSymbol,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );
    });

    it("rejects an independence record with an extra own key (enumerable, non-enumerable, and symbol)", function () {
      const built = buildValidGenesisProfile();
      const withExtra = cloneFactorsPlain(built.factors);
      withExtra[1].independence.extra = "x";
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: withExtra,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INDEPENDENCE_INVALID
      );

      const withHidden = cloneFactorsPlain(built.factors);
      Object.defineProperty(withHidden[1].independence, "hidden", {
        value: "x", enumerable: false, configurable: true
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: withHidden,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INDEPENDENCE_INVALID
      );

      const withSymbol = cloneFactorsPlain(built.factors);
      withSymbol[1].independence[Symbol("extra")] = "x";
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: withSymbol,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INDEPENDENCE_INVALID
      );
    });

    it("rejects a descriptor missing a required key and one built from an inherited-only substitute", function () {
      const built = buildValidGenesisProfile();
      const missing = cloneFactorsPlain(built.factors);
      delete missing[0].descriptor.role;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: missing,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );

      const inherited = cloneFactorsPlain(built.factors);
      const proto = { role: 0n };
      inherited[0].descriptor = Object.assign(Object.create(proto), inherited[0].descriptor);
      delete inherited[0].descriptor.role;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: inherited,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );
    });

    it("rejects an independence record missing a required key", function () {
      const built = buildValidGenesisProfile();
      const missing = cloneFactorsPlain(built.factors);
      delete missing[2].independence.enrollmentCeremonyHash;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: missing,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INDEPENDENCE_INVALID
      );
    });

    it("rejects a nested __proto__ own-key payload on a descriptor before snapshot construction", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      Object.defineProperty(tampered[0].descriptor, "__proto__", {
        value: { polluted: true }, enumerable: true, configurable: true
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );
    });

    it("rejects a descriptor whose ownKeys trap throws, and a throwing descriptor field getter, without leaking the raw marker", function () {
      const built = buildValidGenesisProfile();
      const trap = new Proxy(built.factors[0].descriptor, {
        ownKeys() {
          throw new Error("descriptor enumeration hostile");
        }
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            { descriptor: trap, independence: built.factors[0].independence },
            built.factors[1],
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );

      const marker = { poison: "descriptor-field-marker" };
      const hostileDescriptor = { ...built.factors[0].descriptor };
      Object.defineProperty(hostileDescriptor, "credentialIdHash", {
        enumerable: true,
        configurable: true,
        get() {
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            { descriptor: hostileDescriptor, independence: built.factors[0].independence },
            built.factors[1],
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        });
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.FACTOR_DESCRIPTOR_INVALID);
      assertMarkerUnreachable(caught, marker);
    });

    it("rejects an independence record whose ownKeys trap throws, and a throwing independence field getter, without leaking the raw marker", function () {
      const built = buildValidGenesisProfile();
      const trap = new Proxy(built.factors[1].independence, {
        ownKeys() {
          throw new Error("independence enumeration hostile");
        }
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            built.factors[0],
            { descriptor: built.factors[1].descriptor, independence: trap },
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INDEPENDENCE_INVALID
      );

      const marker = { poison: "independence-field-marker" };
      const hostileIndependence = { ...built.factors[1].independence };
      Object.defineProperty(hostileIndependence, "custodyDomainCommitment", {
        enumerable: true,
        configurable: true,
        get() {
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            built.factors[0],
            { descriptor: built.factors[1].descriptor, independence: hostileIndependence },
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        });
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.FACTOR_INDEPENDENCE_INVALID);
      assertMarkerUnreachable(caught, marker);
    });

    it("rejects mixed genesis intents: a ceremony bound to a different intent hash", function () {
      const built = buildValidGenesisProfile();
      const otherIntentHash = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(
        validIntentFields({ userSalt: `0x${"ee".repeat(32)}` })
      );
      const tamperedCeremonies = [...built.ceremonies];
      tamperedCeremonies[1] = validCeremonyFields(1, otherIntentHash);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: tamperedCeremonies,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONY_INTENT_MISMATCH
      );
    });

    it("rejects ceremonies out of role order", function () {
      const built = buildValidGenesisProfile();
      const reordered = [built.ceremonies[1], built.ceremonies[0], built.ceremonies[2]];
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: reordered,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONY_ROLE_ORDER_INVALID
      );
    });

    it("rejects duplicate ceremony IDs", function () {
      const built = buildValidGenesisProfile();
      const duplicated = [...built.ceremonies];
      duplicated[1] = { ...duplicated[1], ceremonyId: duplicated[0].ceremonyId };
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: duplicated,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONY_ID_DUPLICATE
      );
    });

    it("accepts ceremony expiry equal to intent expiry, rejects ceremony expiry after intent expiry", function () {
      const intentFields = validIntentFields({ expiresAt: "1900000000" });
      const intentHash = mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(intentFields);
      const equalCeremony = validCeremonyFields(0, intentHash, { expiresAt: "1900000000" });
      assert.doesNotThrow(() =>
        mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(equalCeremony)
      );
      const built = buildValidGenesisProfile();
      const laterCeremonies = [...built.ceremonies];
      laterCeremonies[0] = { ...laterCeremonies[0], expiresAt: "1900000001" };
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: laterCeremonies,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONY_EXPIRY_EXCEEDS_INTENT
      );
    });

    it("rejects descriptor/independence role mismatch with slot", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      tampered[0].descriptor.role = 1n;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_ROLE_MISMATCH
      );
    });

    it("rejects descriptor/independence generation mismatch (not exactly 1)", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      tampered[2].descriptor.credentialGeneration = 2n;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_GENERATION_MISMATCH
      );
    });

    it("rejects a factor whose independence.enrollmentCeremonyHash does not match its slot's recomputed genesis ceremony hash", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      tampered[1].independence.enrollmentCeremonyHash = built.ceremonyHashes[2];
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_CEREMONY_HASH_MISMATCH
      );
    });

    it("rejects the existing account-bound enrollment ceremony hash presented as genesis provenance", function () {
      const built = buildValidGenesisProfile();
      const legacyHash = computePhilCoreV2LocalEnrollmentCeremonyHash({
        ceremonyId: `0x${"01".repeat(32)}`,
        account: getAddress(`0x${"11".repeat(20)}`),
        chainId: "11155111",
        entryPoint: getAddress(`0x${"22".repeat(20)}`),
        accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
        securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
        recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
        expectedRecoveryEpoch: "1",
        expectedValidatorEpoch: "1",
        expiresAt: "1900000000"
      });
      const tampered = cloneFactorsPlain(built.factors);
      tampered[0].independence.enrollmentCeremonyHash = legacyHash;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_CEREMONY_HASH_MISMATCH
      );
    });

    it("still runs and enforces the existing generic profile validator: duplicate credentials rejected", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      tampered[1].independence.credentialIdHash = tampered[0].independence.credentialIdHash;
      tampered[1].descriptor.credentialIdHash = tampered[0].descriptor.credentialIdHash;
      tampered[1].descriptor.independenceBindingHash =
        computePhilCoreV2ConsumerRecoveryIndependenceBinding(tampered[1].independence);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.GENERIC_PROFILE_VALIDATION_FAILED
      );
    });

    it("still runs and enforces the existing generic profile validator: duplicate public verification material rejected", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      tampered[2].descriptor.publicVerificationMaterialHash =
        tampered[0].descriptor.publicVerificationMaterialHash;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.GENERIC_PROFILE_VALIDATION_FAILED
      );
    });

    it("still runs and enforces the existing generic profile validator: duplicate custody domain commitments rejected", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      tampered[1].independence.custodyDomainCommitment =
        tampered[0].independence.custodyDomainCommitment;
      tampered[1].descriptor.independenceBindingHash =
        computePhilCoreV2ConsumerRecoveryIndependenceBinding(tampered[1].independence);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.GENERIC_PROFILE_VALIDATION_FAILED
      );
    });

    it("still runs and enforces the existing generic profile validator: offline signer equal to execution validator rejected", function () {
      // executionValidator is now required to canonically equal
      // intent.initialValidator, so exercising the generic validator's own
      // offline-signer-aliases-execution-validator rejection requires a
      // profile where the offline signer legitimately is the validator the
      // account would install at genesis -- not an arbitrary mismatched
      // executionValidator, which would now be caught earlier by
      // EXECUTION_VALIDATOR_INTENT_MISMATCH instead.
      const base = buildValidGenesisProfile();
      const offlineSigner = base.factors[2].signer;
      const built = buildValidGenesisProfile({ initialValidator: offlineSigner });
      assert.equal(built.intent.initialValidator, offlineSigner);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: built.factors,
          executionValidator: offlineSigner
        }),
        (error) => error.code === C.GENERIC_PROFILE_VALIDATION_FAILED
      );
    });

    it("never re-reads a caller-owned factor object once it has been snapshotted", function () {
      const built = buildValidGenesisProfile();
      let descriptorReads = 0;
      const hostileFactor = {
        get descriptor() {
          descriptorReads += 1;
          return built.factors[0].descriptor;
        },
        independence: built.factors[0].independence
      };
      mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
        intent: built.intent,
        ceremonies: built.ceremonies,
        factors: [hostileFactor, built.factors[1], built.factors[2]],
        executionValidator: built.executionValidator
      });
      assert.equal(descriptorReads, 1);
    });

    it("never re-reads the caller-owned intent object once it has been snapshotted", function () {
      const built = buildValidGenesisProfile();
      let expiresAtReads = 0;
      const hostileIntent = { ...built.intent };
      Object.defineProperty(hostileIntent, "expiresAt", {
        enumerable: true,
        configurable: true,
        get() {
          expiresAtReads += 1;
          return built.intent.expiresAt;
        }
      });
      mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
        intent: hostileIntent,
        ceremonies: built.ceremonies,
        factors: built.factors,
        executionValidator: built.executionValidator
      });
      assert.equal(expiresAtReads, 1);
    });

    it("never re-reads a caller-owned ceremony object once it has been snapshotted", function () {
      const built = buildValidGenesisProfile();
      let roleReads = 0;
      const hostileCeremony = { ...built.ceremonies[0] };
      Object.defineProperty(hostileCeremony, "role", {
        enumerable: true,
        configurable: true,
        get() {
          roleReads += 1;
          return built.ceremonies[0].role;
        }
      });
      mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
        intent: built.intent,
        ceremonies: [hostileCeremony, built.ceremonies[1], built.ceremonies[2]],
        factors: built.factors,
        executionValidator: built.executionValidator
      });
      assert.equal(roleReads, 1);
    });
  });

  describe("own-property Proxy corrective pass (Package 5B-0.2.3)", function () {
    // Constructs a hostile Proxy whose target is extensible and has ZERO own
    // properties for `keys` (every value is only reachable through the
    // target's prototype), while its `ownKeys` trap falsely reports `keys`
    // as if they were own. No `getOwnPropertyDescriptor` or `get` trap is
    // defined: the default Proxy behavior already reproduces the attack --
    // `Object.getOwnPropertyDescriptor(proxy, key)` correctly resolves to
    // `undefined` (the target genuinely has no own property), while an
    // ordinary `proxy[key]` read still resolves through the prototype chain
    // to the real, valid value. This is spec-legal: for an extensible target
    // with zero own properties, the `ownKeys` trap has no invariant to
    // violate by reporting arbitrary names.
    function fakeOwnKeysProxy(realObject, keys) {
      const proto = { ...realObject };
      const target = Object.create(proto);
      return new Proxy(target, {
        ownKeys() {
          return keys;
        }
      });
    }

    // Same attack, specialized for an exact-three tuple. Every array object
    // is required by the language to carry its own "length"; that own
    // "length" is deliberately set to the correct value 3 (so it is
    // genuinely own, not fabricated) while the three numeric indices are
    // left entirely absent from the target and are instead only reachable
    // via the prototype (a real 3-element array holding the actual values).
    // The `ownKeys` trap then falsely reports "0", "1", "2" as own
    // alongside the genuinely-own "length".
    function fakeOwnKeysTupleProxy(realTuple) {
      const target = [];
      target.length = 3;
      Object.setPrototypeOf(target, [...realTuple]);
      return new Proxy(target, {
        ownKeys() {
          return ["0", "1", "2", "length"];
        }
      });
    }

    it("rejects an intent Proxy whose 24 fields are inherited-only but falsely reported as own by ownKeys", function () {
      const real = validIntentFields();
      const hostile = fakeOwnKeysProxy(real, INTENT_FIELD_ORDER);
      for (const key of INTENT_FIELD_ORDER) {
        assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, key), undefined);
        assert.notEqual(hostile[key], undefined);
      }
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(hostile),
        (error) => error.code === C.INTENT_MISSING_OWN_KEY
      );
    });

    it("rejects a ceremony Proxy whose 6 fields are inherited-only but falsely reported as own by ownKeys", function () {
      const real = validCeremonyFields(0, `0x${"11".repeat(32)}`);
      const hostile = fakeOwnKeysProxy(real, CEREMONY_FIELD_ORDER);
      for (const key of CEREMONY_FIELD_ORDER) {
        assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, key), undefined);
        assert.notEqual(hostile[key], undefined);
      }
      assert.throws(
        () => mod.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(hostile),
        (error) => error.code === C.CEREMONY_MISSING_OWN_KEY
      );
    });

    it("rejects a top-level profile-input Proxy whose 4 fields are inherited-only but falsely reported as own by ownKeys", function () {
      const built = buildValidGenesisProfile();
      const real = {
        intent: built.intent,
        ceremonies: built.ceremonies,
        factors: built.factors,
        executionValidator: built.executionValidator
      };
      const hostile = fakeOwnKeysProxy(real, ["intent", "ceremonies", "factors", "executionValidator"]);
      for (const key of ["intent", "ceremonies", "factors", "executionValidator"]) {
        assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, key), undefined);
        assert.notEqual(hostile[key], undefined);
      }
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile(hostile),
        (error) => error.code === C.PROFILE_MISSING_OWN_KEY
      );
    });

    it("rejects a factor Proxy whose descriptor/independence are inherited-only but falsely reported as own by ownKeys", function () {
      const built = buildValidGenesisProfile();
      const real = { descriptor: built.factors[0].descriptor, independence: built.factors[0].independence };
      const hostile = fakeOwnKeysProxy(real, ["descriptor", "independence"]);
      assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, "descriptor"), undefined);
      assert.notEqual(hostile.descriptor, undefined);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [hostile, built.factors[1], built.factors[2]],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INPUT_NOT_OBJECT
      );
    });

    it("rejects a descriptor Proxy whose 16 fields are inherited-only but falsely reported as own by ownKeys", function () {
      const built = buildValidGenesisProfile();
      const hostileDescriptor = fakeOwnKeysProxy(built.factors[0].descriptor, DESCRIPTOR_FIELD_ORDER);
      for (const key of DESCRIPTOR_FIELD_ORDER) {
        assert.deepEqual(Object.getOwnPropertyDescriptor(hostileDescriptor, key), undefined);
        assert.notEqual(hostileDescriptor[key], undefined);
      }
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            { descriptor: hostileDescriptor, independence: built.factors[0].independence },
            built.factors[1],
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );
    });

    it("rejects an independence Proxy whose 10 fields are inherited-only but falsely reported as own by ownKeys", function () {
      const built = buildValidGenesisProfile();
      const hostileIndependence = fakeOwnKeysProxy(built.factors[1].independence, INDEPENDENCE_FIELD_ORDER);
      for (const key of INDEPENDENCE_FIELD_ORDER) {
        assert.deepEqual(Object.getOwnPropertyDescriptor(hostileIndependence, key), undefined);
        assert.notEqual(hostileIndependence[key], undefined);
      }
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            built.factors[0],
            { descriptor: built.factors[1].descriptor, independence: hostileIndependence },
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INDEPENDENCE_INVALID
      );
    });

    it("Role 2: a signer name fabricated by ownKeys but not genuinely own is treated as absent, not present", function () {
      const built = buildValidGenesisProfile();
      const real = built.factors[2];
      const proto = { signer: real.signer };
      const target = Object.create(proto);
      target.descriptor = real.descriptor;
      target.independence = real.independence;
      const hostile = new Proxy(target, {
        ownKeys() {
          return ["descriptor", "independence", "signer"];
        }
      });
      assert.deepEqual(
        Object.getOwnPropertyDescriptor(hostile, "descriptor"),
        Object.getOwnPropertyDescriptor(target, "descriptor")
      );
      assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, "signer"), undefined);
      assert.notEqual(hostile.signer, undefined);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [built.factors[0], built.factors[1], hostile],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.GENERIC_PROFILE_VALIDATION_FAILED
      );
    });

    it("Roles 0/1: a genuinely own signer property remains forbidden by the shared factor-policy validator", function () {
      const built = buildValidGenesisProfile();
      for (const role of [0, 1]) {
        const factor = {
          descriptor: built.factors[role].descriptor,
          independence: built.factors[role].independence,
          signer: built.factors[2].signer
        };
        const factors = role === 0
          ? [factor, built.factors[1], built.factors[2]]
          : [built.factors[0], factor, built.factors[2]];
        assert.throws(
          () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
            intent: built.intent,
            ceremonies: built.ceremonies,
            factors,
            executionValidator: built.executionValidator
          }),
          (error) => error.code === C.GENERIC_PROFILE_VALIDATION_FAILED
        );
      }
    });

    it("rejects a ceremonies tuple Proxy whose indices are inherited-only but falsely reported as own by ownKeys", function () {
      const built = buildValidGenesisProfile();
      const hostile = fakeOwnKeysTupleProxy(built.ceremonies);
      assert.equal(Array.isArray(hostile), true);
      assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, "0"), undefined);
      assert.notEqual(hostile[0], undefined);
      assert.equal(hostile.length, 3);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: hostile,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONIES_NOT_TUPLE
      );
    });

    it("rejects a factors tuple Proxy whose indices are inherited-only but falsely reported as own by ownKeys", function () {
      const built = buildValidGenesisProfile();
      const hostile = fakeOwnKeysTupleProxy(built.factors);
      assert.equal(Array.isArray(hostile), true);
      assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, "1"), undefined);
      assert.notEqual(hostile[1], undefined);
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: hostile,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTORS_NOT_TUPLE
      );
    });

    it("contains a getOwnPropertyDescriptor trap on the intent that throws a raw marker, without leaking it", function () {
      const real = validIntentFields();
      const marker = { poison: "intent-getOwnPropertyDescriptor-marker" };
      const hostile = new Proxy(real, {
        getOwnPropertyDescriptor() {
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(hostile);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.INTENT_ENUMERATION_FAILED);
      assertMarkerUnreachable(caught, marker);
    });

    it("rejects a revoked Proxy specifically during independence own-property-descriptor inspection", function () {
      const built = buildValidGenesisProfile();
      const { proxy: revokedIndependence, revoke } = Proxy.revocable(built.factors[1].independence, {});
      revoke();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            built.factors[0],
            { descriptor: built.factors[1].descriptor, independence: revokedIndependence },
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INDEPENDENCE_INVALID
      );
    });

    it("rejects a descriptor key whose getOwnPropertyDescriptor trap explicitly reports undefined despite ownKeys reporting it", function () {
      const built = buildValidGenesisProfile();
      const real = built.factors[0].descriptor;
      const hostileDescriptor = new Proxy(real, {
        getOwnPropertyDescriptor(target, key) {
          if (key === "role") return undefined;
          return Reflect.getOwnPropertyDescriptor(target, key);
        }
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            { descriptor: hostileDescriptor, independence: built.factors[0].independence },
            built.factors[1],
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );
    });

    it("rejects an own accessor descriptor field with no getter (set-only)", function () {
      const built = buildValidGenesisProfile();
      const hostileDescriptor = { ...built.factors[0].descriptor };
      delete hostileDescriptor.role;
      Object.defineProperty(hostileDescriptor, "role", {
        enumerable: true,
        configurable: true,
        set() {}
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            { descriptor: hostileDescriptor, independence: built.factors[0].independence },
            built.factors[1],
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_DESCRIPTOR_INVALID
      );
    });

    it("rejects a ceremonies tuple with a set-only accessor at index 0 (no getter)", function () {
      const built = buildValidGenesisProfile();
      const hostileCeremonies = [...built.ceremonies];
      delete hostileCeremonies[0];
      Object.defineProperty(hostileCeremonies, "0", {
        enumerable: true,
        configurable: true,
        set() {}
      });
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: hostileCeremonies,
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONIES_NOT_TUPLE
      );
    });

    it("accepts a genuine non-enumerable own descriptor field -- ownership, not enumerability, is what's required", function () {
      const built = buildValidGenesisProfile();
      const hostileDescriptor = { ...built.factors[0].descriptor };
      const roleValue = hostileDescriptor.role;
      delete hostileDescriptor.role;
      Object.defineProperty(hostileDescriptor, "role", {
        value: roleValue, enumerable: false, configurable: true, writable: true
      });
      assert.doesNotThrow(() =>
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [
            { descriptor: hostileDescriptor, independence: built.factors[0].independence },
            built.factors[1],
            built.factors[2]
          ],
          executionValidator: built.executionValidator
        })
      );
    });

    it("reads a genuine own accessor descriptor field exactly once", function () {
      const built = buildValidGenesisProfile();
      const hostileDescriptor = { ...built.factors[0].descriptor };
      const generationValue = hostileDescriptor.credentialGeneration;
      delete hostileDescriptor.credentialGeneration;
      let reads = 0;
      Object.defineProperty(hostileDescriptor, "credentialGeneration", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          return generationValue;
        }
      });
      mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
        intent: built.intent,
        ceremonies: built.ceremonies,
        factors: [
          { descriptor: hostileDescriptor, independence: built.factors[0].independence },
          built.factors[1],
          built.factors[2]
        ],
        executionValidator: built.executionValidator
      });
      assert.equal(reads, 1);
    });
  });

  describe("raw cause containment (Codex review round 1)", function () {
    it("a classified error thrown from any hostile-getter path never exposes the original marker as .cause or under any other own property", function () {
      const built = buildValidGenesisProfile();
      const marker = { secretPayload: "must-never-be-reachable" };
      const hostileIntent = { ...built.intent };
      Object.defineProperty(hostileIntent, "chainId", {
        enumerable: true,
        configurable: true,
        get() {
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: hostileIntent,
          ceremonies: built.ceremonies,
          factors: built.factors,
          executionValidator: built.executionValidator
        });
      } catch (error) {
        caught = error;
      }
      assert.ok(caught);
      assertMarkerUnreachable(caught, marker);
      assert.equal(caught.cause, undefined);
      for (const symbol of Object.getOwnPropertySymbols(caught)) {
        assert.notEqual(caught[symbol], marker);
      }
    });

    it("does not read .code, .message, or .name from a hostile thrown value while classifying it", function () {
      let codeReads = 0;
      let messageReads = 0;
      let nameReads = 0;
      const hostile = {
        get code() { codeReads += 1; return "FAKE"; },
        get message() { messageReads += 1; return "fake message"; },
        get name() { nameReads += 1; return "FakeError"; }
      };
      const fields = validIntentFields();
      Object.defineProperty(fields, "userSalt", {
        enumerable: true,
        configurable: true,
        get() {
          throw hostile;
        }
      });
      assert.throws(() => mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields));
      assert.equal(codeReads, 0);
      assert.equal(messageReads, 0);
      assert.equal(nameReads, 0);
    });
  });

  describe("branded error identity", function () {
    it("a genuine error passes instanceof", function () {
      let caught = null;
      try {
        mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(null);
      } catch (error) {
        caught = error;
      }
      assert.ok(caught instanceof mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError);
    });

    it("Object.create(prototype) spoof does not pass instanceof", function () {
      const spoof = Object.create(mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError.prototype);
      spoof.code = "INTENT_VERSION_MISMATCH";
      assert.equal(spoof instanceof mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError, false);
    });

    it("a prototype-lying Proxy does not pass instanceof", function () {
      const proxy = new Proxy({}, {
        getPrototypeOf() {
          return mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError.prototype;
        }
      });
      assert.equal(proxy instanceof mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError, false);
    });

    it("Symbol.hasInstance is locked against reassignment", function () {
      const descriptor = Object.getOwnPropertyDescriptor(
        mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError,
        Symbol.hasInstance
      );
      assert.equal(descriptor.writable, false);
      assert.equal(descriptor.configurable, false);
    });

    it("a prototype-spoofed classified error thrown from a getter is reclassified without ever reading its spoofed properties", function () {
      let codeReads = 0;
      const spoof = Object.create(mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError.prototype);
      Object.defineProperty(spoof, "code", {
        enumerable: true,
        configurable: true,
        get() {
          codeReads += 1;
          return "INTENT_VERSION_MISMATCH";
        }
      });
      assert.equal(spoof instanceof mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError, false);

      const fields = validIntentFields();
      Object.defineProperty(fields, "userSalt", {
        enumerable: true,
        configurable: true,
        get() {
          throw spoof;
        }
      });
      let caught = null;
      try {
        mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.INTENT_PROPERTY_READ_FAILED);
      assert.notEqual(caught, spoof);
      assert.equal(codeReads, 0, "the spoof's .code getter must never be invoked during classification");
    });

    it("a genuine branded error thrown internally by a hostile getter is rethrown unchanged, not re-wrapped", function () {
      const genuine = new mod.PhilCoreV2ConsumerRecoveryGenesisProtocolError(
        C.CHAIN_ID_ZERO
      );
      const fields = validIntentFields();
      Object.defineProperty(fields, "userSalt", {
        enumerable: true,
        configurable: true,
        get() {
          throw genuine;
        }
      });
      let caught = null;
      try {
        mod.computePhilCoreV2LocalGenesisDeploymentIntentHash(fields);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, genuine);
      assert.equal(caught.code, C.CHAIN_ID_ZERO);
    });
  });

  describe("validation precedence", function () {
    it("top-level schema is checked before ceremony/factor tuples are read", function () {
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: "not-an-object",
          ceremonies: [1, 2, 3],
          factors: [1, 2, 3],
          executionValidator: "x"
        }),
        (error) => error.code === C.INTENT_INPUT_NOT_OBJECT
      );
    });

    it("tuple shape is checked before intent fields are read", function () {
      const built = buildValidGenesisProfile();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: { ...built.intent, expiresAt: "0" },
          ceremonies: built.ceremonies.slice(0, 2),
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONIES_NOT_TUPLE
      );
    });

    it("intent fields are checked before ceremony fields", function () {
      const built = buildValidGenesisProfile();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: { ...built.intent, expiresAt: "0" },
          ceremonies: [{ garbage: true }, { garbage: true }, { garbage: true }],
          factors: built.factors,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.INTENT_EXPIRES_AT_ZERO
      );
    });

    it("ceremony fields are checked before factor tuple/schema", function () {
      const built = buildValidGenesisProfile();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: [
            { ...built.ceremonies[0], role: "5" },
            built.ceremonies[1],
            built.ceremonies[2]
          ],
          factors: [{ garbage: true }, { garbage: true }, { garbage: true }],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.CEREMONY_ROLE_INVALID
      );
    });

    it("factor schema is checked before cross-record provenance", function () {
      const built = buildValidGenesisProfile();
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: [{ garbage: true }, built.factors[1], built.factors[2]],
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_INPUT_NOT_OBJECT
      );
    });

    it("cross-record provenance is checked before delegated generic-profile validation", function () {
      const built = buildValidGenesisProfile();
      const tampered = cloneFactorsPlain(built.factors);
      // Both a provenance defect (role mismatch) and a generic-validator
      // defect (duplicated credential) are present; provenance must win.
      tampered[0].descriptor.role = 1n;
      tampered[1].independence.credentialIdHash = tampered[0].independence.credentialIdHash;
      assert.throws(
        () => mod.validatePhilCoreV2ConsumerRecoveryGenesisProfile({
          intent: built.intent,
          ceremonies: built.ceremonies,
          factors: tampered,
          executionValidator: built.executionValidator
        }),
        (error) => error.code === C.FACTOR_ROLE_MISMATCH
      );
    });
  });
});
