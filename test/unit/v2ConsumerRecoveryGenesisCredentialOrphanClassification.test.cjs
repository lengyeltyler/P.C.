require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const SDK_SRC = path.join(ROOT, "apps/phil-device-sdk/src");
const OBLIGATION_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts"
);
const CLASSIFIER_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialOrphanClassification.ts"
);
const CLASSIFICATION_JSON_PATH = path.join(ROOT, "config/ci/classification.json");

const obligationReal = require(OBLIGATION_PATH);
const {
  mintPhilCoreV2GenesisRoleCeremony
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts");
const {
  computePhilCoreV2LocalGenesisEnrollmentCeremonyHash
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts");

const {
  createPhilCoreV2GenesisCredentialObligation,
  authorizePhilCoreV2GenesisCredentialCreation,
  recordPhilCoreV2GenesisCreatedCredential,
  orphanPhilCoreV2GenesisCredentialObligation,
  toPhilCoreV2GenesisCredentialObligationCeremonyHashInput
} = obligationReal;

const validatorHarness = {
  target: obligationReal.validatePhilCoreV2GenesisCredentialObligationRecord,
  calls: 0,
  lastArgs: null
};
const stableValidatorWrapper = function (...args) {
  validatorHarness.calls += 1;
  validatorHarness.lastArgs = args;
  return validatorHarness.target(...args);
};

function makeShim(real, wrappedKey, wrapper) {
  const shim = Object.create(null);
  for (const key of Object.keys(real)) shim[key] = real[key];
  shim[wrappedKey] = wrapper;
  return shim;
}

const obligationModule = require.cache[OBLIGATION_PATH];
const originalExportsDescriptor = Object.getOwnPropertyDescriptor(
  obligationModule,
  "exports"
);
const originalExports = obligationModule.exports;
assert.equal(originalExports, obligationReal);
assert.equal(originalExportsDescriptor.value, obligationReal);

const cacheKeysBeforeShim = new Set(Object.keys(require.cache));
const obligationShim = makeShim(
  obligationReal,
  "validatePhilCoreV2GenesisCredentialObligationRecord",
  stableValidatorWrapper
);
obligationModule.exports = obligationShim;

const classifier = require(CLASSIFIER_PATH);
const REQUIRE_TIME_COUNTS = Object.freeze({
  validatorCalls: validatorHarness.calls
});
const shimOwnedCacheKeys = Object.keys(require.cache).filter(
  (key) => !cacheKeysBeforeShim.has(key)
);
Object.defineProperty(obligationModule, "exports", originalExportsDescriptor);
assert.equal(obligationModule.exports, obligationReal);

const {
  PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_SCHEMA_VERSION,
  PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_FORMAT_PROVENANCE,
  PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CONDITION,
  PHILCORE_V2_GENESIS_CREDENTIAL_KNOWLEDGE,
  PHILCORE_V2_GENESIS_CREDENTIAL_UNRESOLVED_BINDING,
  PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_ERROR_CODE,
  PhilCoreV2GenesisCredentialOrphanClassificationError,
  classifyPhilCoreV2GenesisCredentialOrphan
} = classifier;

const E = PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_ERROR_CODE;
const CLASSIFIER_SOURCE = fs.readFileSync(CLASSIFIER_PATH, "utf8");

const CEREMONY_IDS = Object.freeze({
  0: "0x827fb6a1d6c993f9398090b62cbb32171b4fdc11fc6b9d885f263e18402faf34",
  1: "0x1111111111111111111111111111111111111111111111111111111111111111",
  2: "0x2222222222222222222222222222222222222222222222222222222222222222"
});
const INTENT_ID =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INTENT_HASH =
  "0x3d2b7a1c9e4f6058b1c2d3e4f50617283940a1b2c3d4e5f60718293a4b5c6d7e";
const CREDENTIAL_ID_HASH =
  "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PUBLIC_MATERIAL_HASH =
  "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const NOW = 1_700_000_000;
const FAR_INTENT_EXPIRY = 1_800_000_000n;

const CLASSIFICATION_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "intentId",
  "genesisDeploymentIntentHash",
  "ceremonyVersion",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "role",
  "credentialGeneration",
  "orphanReason",
  "orphanCondition",
  "credentialKnowledge",
  "credentialIdHash",
  "publicVerificationMaterialHash",
  "unresolvedBinding"
]);

const CONDITION_KEYS = Object.freeze([
  "UNCONSUMED_CREATION_OUTCOME",
  "DURABLE_MANIFEST_BINDING_CONFLICT"
]);
const KNOWLEDGE_KEYS = Object.freeze([
  "KNOWN_PRIMARY_PLATFORM_CREDENTIAL",
  "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED",
  "KNOWN_OFFLINE_PUBLIC_MATERIAL",
  "UNKNOWN_CREDENTIAL"
]);
const UNRESOLVED_KEYS = Object.freeze([
  "CREDENTIAL_ID_AND_PUBLIC_MATERIAL",
  "PUBLIC_MATERIAL_ONLY",
  "NONE",
  "SIDECAR_AND_UNPROJECTED_MANIFEST_BINDING_CONFLICT",
  "UNPROJECTED_MANIFEST_BINDING_CONFLICT_ONLY"
]);
const ERROR_CODE_KEYS = Object.freeze([
  "ORPHAN_CLASSIFICATION_STATE_INVALID",
  "ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION"
]);

const NONCONFLICTING_REASONS = Object.freeze([
  "RESTART_DURING_CREATION",
  "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION",
  "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION",
  "TERMINAL_JOURNAL_WITH_UNCONSUMED_CREATION"
]);
const ALL_ORPHAN_REASONS = Object.freeze([
  ...NONCONFLICTING_REASONS,
  "RECORDED_CREDENTIAL_MISMATCH"
]);
const ROLES = Object.freeze(["0", "1", "2"]);
const PACKAGE_RELATIVE_PATHS = Object.freeze([
  "apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialOrphanClassification.ts",
  "apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts",
  "test/unit/v2ConsumerRecoveryGenesisCredentialOrphanClassification.test.cjs",
  "test/unit/v2ConsumerRecoveryGenesisManifestBindingConflictProjection.test.cjs",
  "config/ci/classification.json"
]);
const SCAN_SKIP_DIR_NAMES = Object.freeze([
  ".git",
  "node_modules",
  "artifacts",
  "cache",
  "dist",
  "build",
  "coverage",
  "release",
  "target"
]);

function resetHarness() {
  validatorHarness.target =
    obligationReal.validatePhilCoreV2GenesisCredentialObligationRecord;
  validatorHarness.calls = 0;
  validatorHarness.lastArgs = null;
}

function withHarness(run) {
  resetHarness();
  try {
    return run();
  } finally {
    resetHarness();
  }
}

function mintCeremony(role) {
  return mintPhilCoreV2GenesisRoleCeremony({
    current: null,
    ceremonyId: CEREMONY_IDS[role],
    role: BigInt(role),
    genesisDeploymentIntentHash: INTENT_HASH,
    intentExpiresAtUnixSeconds: FAR_INTENT_EXPIRY,
    nowUnixSeconds: NOW
  });
}

function createActive(role) {
  return createPhilCoreV2GenesisCredentialObligation({
    ceremony: mintCeremony(role),
    intentId: INTENT_ID,
    nowUnixSeconds: NOW
  });
}

function authorize(current) {
  return authorizePhilCoreV2GenesisCredentialCreation({
    current,
    expectedCeremonyId: current.ceremonyId,
    nowUnixSeconds: NOW + 1
  });
}

function recordCredential(current) {
  return recordPhilCoreV2GenesisCreatedCredential({
    current,
    expectedCeremonyId: current.ceremonyId,
    credentialIdHash: current.role === "2" ? ZERO_BYTES32 : CREDENTIAL_ID_HASH,
    publicVerificationMaterialHash: PUBLIC_MATERIAL_HASH,
    nowUnixSeconds: NOW + 2
  });
}

function orphan(current, reason) {
  return orphanPhilCoreV2GenesisCredentialObligation({
    current,
    reason,
    nowUnixSeconds: Number(current.updatedAtUnixSeconds) + 1
  });
}

function makeOrphaned(role, known, reason) {
  const authorized = authorize(createActive(role));
  if (!known) {
    return orphan(authorized, reason);
  }
  return orphan(recordCredential(authorized), reason);
}

function expectedKnowledge(role, credentialIdHash, publicVerificationMaterialHash) {
  const unknown =
    credentialIdHash === null && publicVerificationMaterialHash === null;
  if (unknown) return "UNKNOWN_CREDENTIAL";
  if (role === "0") return "KNOWN_PRIMARY_PLATFORM_CREDENTIAL";
  if (role === "1") return "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED";
  return "KNOWN_OFFLINE_PUBLIC_MATERIAL";
}

function expectedCondition(reason) {
  return reason === "RECORDED_CREDENTIAL_MISMATCH"
    ? "DURABLE_MANIFEST_BINDING_CONFLICT"
    : "UNCONSUMED_CREATION_OUTCOME";
}

function expectedUnresolved(knowledge, condition) {
  if (condition === "UNCONSUMED_CREATION_OUTCOME") {
    if (
      knowledge === "KNOWN_PRIMARY_PLATFORM_CREDENTIAL"
      || knowledge === "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED"
    ) {
      return "CREDENTIAL_ID_AND_PUBLIC_MATERIAL";
    }
    if (knowledge === "KNOWN_OFFLINE_PUBLIC_MATERIAL") {
      return "PUBLIC_MATERIAL_ONLY";
    }
    return "NONE";
  }
  return knowledge === "UNKNOWN_CREDENTIAL"
    ? "UNPROJECTED_MANIFEST_BINDING_CONFLICT_ONLY"
    : "SIDECAR_AND_UNPROJECTED_MANIFEST_BINDING_CONFLICT";
}

function ownKeyOrder(value) {
  return Reflect.ownKeys(value).map(String);
}

function expectClassifierCode(fn, code, label) {
  let thrown;
  let threw = false;
  try {
    fn();
  } catch (error) {
    threw = true;
    thrown = error;
  }
  assert.ok(threw, `expected a throw for ${label ?? code}`);
  assert.ok(
    thrown instanceof PhilCoreV2GenesisCredentialOrphanClassificationError,
    `expected branded classifier error for ${label ?? code}, got ${String(thrown)}`
  );
  assert.equal(thrown.code, code, `wrong code for ${label ?? code}`);
  assert.equal(
    Object.prototype.hasOwnProperty.call(thrown, "cause"),
    false,
    `raw cause retained for ${label ?? code}`
  );
  assert.deepEqual(
    Reflect.ownKeys(thrown).filter((key) => key !== "stack").sort(),
    ["code", "message", "name"],
    `unexpected retained own properties for ${label ?? code}`
  );
  return thrown;
}

function assertDeepFrozenClassification(result) {
  assert.equal(Object.isFrozen(result), true, "classification is not frozen");
  assert.equal(Object.getPrototypeOf(result), null);
  for (const key of CLASSIFICATION_KEYS) {
    const value = result[key];
    assert.ok(
      value === null || (typeof value !== "object" && typeof value !== "function"),
      `classification.${key} is not a primitive, so freezing is not deep`
    );
  }
}

function assertSemanticClassification(record, result) {
  const knowledge = expectedKnowledge(
    record.role,
    record.credentialIdHash,
    record.publicVerificationMaterialHash
  );
  const condition = expectedCondition(record.orphanReason);
  const unresolved = expectedUnresolved(knowledge, condition);
  assert.equal(result.schemaVersion, 1);
  assert.equal(
    result.formatProvenance,
    "PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_V1"
  );
  assert.equal(result.intentId, record.intentId);
  assert.equal(result.genesisDeploymentIntentHash, record.genesisDeploymentIntentHash);
  assert.equal(result.ceremonyVersion, record.ceremonyVersion);
  assert.equal(result.ceremonyId, record.ceremonyId);
  assert.equal(result.ceremonyExpiresAtUnixSeconds, record.ceremonyExpiresAtUnixSeconds);
  assert.equal(result.genesisEnrollmentCeremonyHash, record.genesisEnrollmentCeremonyHash);
  assert.equal(result.role, record.role);
  assert.equal(result.credentialGeneration, record.credentialGeneration);
  assert.equal(result.orphanReason, record.orphanReason);
  assert.equal(result.orphanCondition, condition);
  assert.equal(result.credentialKnowledge, knowledge);
  assert.equal(result.credentialIdHash, record.credentialIdHash);
  assert.equal(result.publicVerificationMaterialHash, record.publicVerificationMaterialHash);
  assert.equal(result.unresolvedBinding, unresolved);
  const hashesNull =
    record.credentialIdHash === null && record.publicVerificationMaterialHash === null;
  if (hashesNull) {
    assert.equal(result.credentialKnowledge, "UNKNOWN_CREDENTIAL");
    assert.equal(result.credentialKnowledge.startsWith("KNOWN_"), false);
    assert.notEqual(result.unresolvedBinding, "CREDENTIAL_ID_AND_PUBLIC_MATERIAL");
    assert.notEqual(result.unresolvedBinding, "PUBLIC_MATERIAL_ONLY");
    assert.notEqual(
      result.unresolvedBinding,
      "SIDECAR_AND_UNPROJECTED_MANIFEST_BINDING_CONFLICT"
    );
  }
  if (record.role === "1" && !hashesNull) {
    assert.equal(
      result.credentialKnowledge,
      "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED"
    );
  }
  assertDeepFrozenClassification(result);
}

function assertWrapperHygiene() {
  assert.equal(require.cache[OBLIGATION_PATH].exports, obligationReal);
  assert.deepEqual(Object.keys(obligationShim).sort(), Object.keys(obligationReal).sort());
  for (const key of Object.keys(obligationReal)) {
    if (key === "validatePhilCoreV2GenesisCredentialObligationRecord") {
      assert.equal(obligationShim[key], stableValidatorWrapper);
    } else {
      assert.equal(obligationShim[key], obligationReal[key]);
    }
  }
  assert.equal(
    validatorHarness.target,
    obligationReal.validatePhilCoreV2GenesisCredentialObligationRecord
  );
  assert.equal(validatorHarness.calls, 0);
  assert.equal(validatorHarness.lastArgs, null);
  assert.equal(originalExportsDescriptor.value, obligationReal);
  assert.equal(originalExports, obligationReal);
}

function restoreObligationWrapper() {
  const cached = require.cache[OBLIGATION_PATH];
  assert.equal(cached, obligationModule);
  Object.defineProperty(cached, "exports", originalExportsDescriptor);
  assert.equal(cached.exports, originalExports);
  assert.equal(
    cached.exports.validatePhilCoreV2GenesisCredentialObligationRecord,
    obligationReal.validatePhilCoreV2GenesisCredentialObligationRecord
  );
  for (const key of shimOwnedCacheKeys) {
    delete require.cache[key];
  }
  for (const key of shimOwnedCacheKeys) {
    assert.equal(Object.prototype.hasOwnProperty.call(require.cache, key), false);
  }
}

beforeEach(resetHarness);

describe("v2ConsumerRecoveryGenesisCredentialOrphanClassification", () => {
  it("C01: known role-0 primary-platform classification", () => {
    const record = makeOrphaned("0", true, "RESTART_DURING_CREATION");
    const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assertSemanticClassification(record, result);
    assert.equal(result.credentialKnowledge, "KNOWN_PRIMARY_PLATFORM_CREDENTIAL");
    assert.equal(result.orphanCondition, "UNCONSUMED_CREATION_OUTCOME");
    assert.equal(result.unresolvedBinding, "CREDENTIAL_ID_AND_PUBLIC_MATERIAL");
  });

  it("C02: known role-1 carrier-undetermined classification", () => {
    const record = makeOrphaned("1", true, "RESTART_DURING_CREATION");
    const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assertSemanticClassification(record, result);
    assert.equal(
      result.credentialKnowledge,
      "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED"
    );
    assert.equal(result.unresolvedBinding, "CREDENTIAL_ID_AND_PUBLIC_MATERIAL");
  });

  it("C03: known role-2 public-material classification and zero credential-ID preservation", () => {
    const record = makeOrphaned("2", true, "RESTART_DURING_CREATION");
    const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assertSemanticClassification(record, result);
    assert.equal(record.credentialIdHash, ZERO_BYTES32);
    assert.equal(result.credentialIdHash, ZERO_BYTES32);
    assert.equal(result.credentialKnowledge, "KNOWN_OFFLINE_PUBLIC_MATERIAL");
    assert.equal(result.unresolvedBinding, "PUBLIC_MATERIAL_ONLY");
  });

  it("C04: unknown role-0 classification", () => {
    const record = makeOrphaned("0", false, "RESTART_DURING_CREATION");
    const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assertSemanticClassification(record, result);
    assert.equal(result.credentialKnowledge, "UNKNOWN_CREDENTIAL");
    assert.equal(result.unresolvedBinding, "NONE");
  });

  it("C05: unknown role-1 classification", () => {
    const record = makeOrphaned("1", false, "RESTART_DURING_CREATION");
    const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assertSemanticClassification(record, result);
    assert.equal(result.credentialKnowledge, "UNKNOWN_CREDENTIAL");
    assert.equal(result.unresolvedBinding, "NONE");
  });

  it("C06: unknown role-2 classification", () => {
    const record = makeOrphaned("2", false, "RESTART_DURING_CREATION");
    const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assertSemanticClassification(record, result);
    assert.equal(result.credentialKnowledge, "UNKNOWN_CREDENTIAL");
    assert.equal(result.unresolvedBinding, "NONE");
  });

  it("C07: the four non-conflicting orphan reasons are preserved with UNCONSUMED_CREATION_OUTCOME", () => {
    for (const reason of NONCONFLICTING_REASONS) {
      const record = makeOrphaned("0", true, reason);
      const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
      assert.equal(result.orphanReason, reason);
      assert.equal(result.orphanCondition, "UNCONSUMED_CREATION_OUTCOME");
      assertSemanticClassification(record, result);
    }
  });

  it("C08: RECORDED_CREDENTIAL_MISMATCH is classified distinctly and orthogonally", () => {
    for (const role of ROLES) {
      for (const known of [true, false]) {
        const record = makeOrphaned(role, known, "RECORDED_CREDENTIAL_MISMATCH");
        const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
        assert.equal(result.orphanReason, "RECORDED_CREDENTIAL_MISMATCH");
        assert.equal(result.orphanCondition, "DURABLE_MANIFEST_BINDING_CONFLICT");
        assertSemanticClassification(record, result);
        if (known && role === "1") {
          assert.equal(
            result.credentialKnowledge,
            "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED"
          );
        }
        assert.equal(
          result.unresolvedBinding,
          known
            ? "SIDECAR_AND_UNPROJECTED_MANIFEST_BINDING_CONFLICT"
            : "UNPROJECTED_MANIFEST_BINDING_CONFLICT_ONLY"
        );
      }
    }
  });

  it("C09: exact 16-key order, classifier provenance, null prototype, complete six-field preimage, frozen vocabularies", () => {
    const record = makeOrphaned("0", true, "RESTART_DURING_CREATION");
    const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assert.deepEqual(ownKeyOrder(result), [...CLASSIFICATION_KEYS]);
    assert.equal(CLASSIFICATION_KEYS.length, 16);
    assert.equal(Object.getPrototypeOf(result), null);
    assert.equal(
      result.schemaVersion,
      PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_SCHEMA_VERSION
    );
    assert.equal(
      result.formatProvenance,
      PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_FORMAT_PROVENANCE
    );
    assert.equal(result.schemaVersion, 1);
    assert.equal(
      result.formatProvenance,
      "PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_V1"
    );

    const preimage = toPhilCoreV2GenesisCredentialObligationCeremonyHashInput(record);
    assert.equal(result.ceremonyVersion, preimage.ceremonyVersion);
    assert.equal(result.ceremonyId, preimage.ceremonyId);
    assert.equal(result.genesisDeploymentIntentHash, preimage.genesisDeploymentIntentHash);
    assert.equal(result.role, preimage.role);
    assert.equal(result.credentialGeneration, preimage.credentialGeneration);
    assert.equal(result.ceremonyExpiresAtUnixSeconds, preimage.expiresAt);
    assert.equal(
      result.genesisEnrollmentCeremonyHash,
      computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(preimage)
    );

    const vocabularies = [
      [PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CONDITION, CONDITION_KEYS],
      [PHILCORE_V2_GENESIS_CREDENTIAL_KNOWLEDGE, KNOWLEDGE_KEYS],
      [PHILCORE_V2_GENESIS_CREDENTIAL_UNRESOLVED_BINDING, UNRESOLVED_KEYS],
      [PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_ERROR_CODE, ERROR_CODE_KEYS]
    ];
    for (const [table, keys] of vocabularies) {
      assert.equal(Object.isFrozen(table), true);
      assert.deepEqual(ownKeyOrder(table), [...keys]);
      for (const key of keys) {
        assert.equal(table[key], key);
      }
    }
  });

  it("C10: every result container is frozen and the primitive-only result is deeply frozen", () => {
    const record = makeOrphaned("1", true, "TERMINAL_JOURNAL_WITH_UNCONSUMED_CREATION");
    const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assertDeepFrozenClassification(result);
    assert.equal(Object.isFrozen(PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CONDITION), true);
    assert.equal(Object.isFrozen(PHILCORE_V2_GENESIS_CREDENTIAL_KNOWLEDGE), true);
    assert.equal(Object.isFrozen(PHILCORE_V2_GENESIS_CREDENTIAL_UNRESOLVED_BINDING), true);
    assert.equal(
      Object.isFrozen(PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_ERROR_CODE),
      true
    );
  });

  it("C11: no input or validated-record mutation", () => {
    const frozen = makeOrphaned("0", true, "RESTART_DURING_CREATION");
    const frozenBefore = JSON.stringify(frozen);
    const resultFromFrozen = classifyPhilCoreV2GenesisCredentialOrphan(frozen);
    assert.equal(JSON.stringify(frozen), frozenBefore);
    assert.notEqual(resultFromFrozen, frozen);

    const mutable = JSON.parse(frozenBefore);
    const mutableBefore = JSON.stringify(mutable);
    assert.equal(Object.isFrozen(mutable), false);
    const resultFromMutable = classifyPhilCoreV2GenesisCredentialOrphan(mutable);
    assert.equal(JSON.stringify(mutable), mutableBefore);
    assert.equal(Object.isFrozen(mutable), false);
    assert.notEqual(resultFromMutable, mutable);
    assert.deepEqual(resultFromMutable, resultFromFrozen);
  });

  it("C12: exact one-call lower delegation", () => {
    const record = makeOrphaned("0", true, "RESTART_DURING_CREATION");
    assertWrapperHygiene();
    withHarness(() => {
      classifyPhilCoreV2GenesisCredentialOrphan(record);
      assert.equal(validatorHarness.calls, 1);
      assert.equal(validatorHarness.lastArgs.length, 1);
      assert.equal(validatorHarness.lastArgs[0], record);
    });
    assertWrapperHygiene();
  });

  it("C13: lower-layer errors rethrow by identity", () => {
    const marker = Object.freeze({ marker: "obligation-validator" });
    withHarness(() => {
      validatorHarness.target = () => {
        throw marker;
      };
      let caught;
      try {
        classifyPhilCoreV2GenesisCredentialOrphan({});
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, marker);
      assert.equal(validatorHarness.calls, 1);
    });

    let traps = 0;
    const hostileThrown = new Proxy({}, {
      get() { traps += 1; throw new Error("get trap"); },
      ownKeys() { traps += 1; throw new Error("ownKeys trap"); },
      getOwnPropertyDescriptor() { traps += 1; throw new Error("descriptor trap"); }
    });
    withHarness(() => {
      validatorHarness.target = () => {
        throw hostileThrown;
      };
      let caught;
      try {
        classifyPhilCoreV2GenesisCredentialOrphan({});
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, hostileThrown);
      assert.equal(traps, 0);
    });
  });

  it("C14: ACTIVE is rejected with the classifier-owned state code", () => {
    const active = createActive("0");
    expectClassifierCode(
      () => classifyPhilCoreV2GenesisCredentialOrphan(active),
      E.ORPHAN_CLASSIFICATION_STATE_INVALID,
      "ACTIVE"
    );
  });

  it("C15: CREATION_AUTHORIZED is rejected with the classifier-owned state code", () => {
    const authorized = authorize(createActive("0"));
    expectClassifierCode(
      () => classifyPhilCoreV2GenesisCredentialOrphan(authorized),
      E.ORPHAN_CLASSIFICATION_STATE_INVALID,
      "CREATION_AUTHORIZED"
    );
  });

  it("C16: CREDENTIAL_RECORDED is rejected with the classifier-owned state code", () => {
    const recorded = recordCredential(authorize(createActive("0")));
    expectClassifierCode(
      () => classifyPhilCoreV2GenesisCredentialOrphan(recorded),
      E.ORPHAN_CLASSIFICATION_STATE_INVALID,
      "CREDENTIAL_RECORDED"
    );
  });

  it("C17: hostile input is not inspected before lower delegation", () => {
    const accepted = makeOrphaned("0", true, "RESTART_DURING_CREATION");
    let reads = 0;
    const hostile = new Proxy({}, {
      ownKeys() { reads += 1; return []; },
      getOwnPropertyDescriptor() { reads += 1; return undefined; },
      get() { reads += 1; return undefined; },
      getPrototypeOf() { reads += 1; return Object.prototype; }
    });
    withHarness(() => {
      validatorHarness.target = () => accepted;
      const result = classifyPhilCoreV2GenesisCredentialOrphan(hostile);
      assert.equal(reads, 0);
      assert.equal(validatorHarness.calls, 1);
      assert.equal(validatorHarness.lastArgs[0], hostile);
      assertSemanticClassification(accepted, result);
    });
  });

  it("C18: branded classifier error rejects prototype-forged instanceof and retains no hostile thrown value", () => {
    const forged = Object.create(
      PhilCoreV2GenesisCredentialOrphanClassificationError.prototype
    );
    forged.code = E.ORPHAN_CLASSIFICATION_STATE_INVALID;
    assert.equal(
      forged instanceof PhilCoreV2GenesisCredentialOrphanClassificationError,
      false
    );
    const adopted = {
      code: E.ORPHAN_CLASSIFICATION_STATE_INVALID,
      name: "PhilCoreV2GenesisCredentialOrphanClassificationError"
    };
    Object.setPrototypeOf(
      adopted,
      PhilCoreV2GenesisCredentialOrphanClassificationError.prototype
    );
    assert.equal(
      adopted instanceof PhilCoreV2GenesisCredentialOrphanClassificationError,
      false
    );

    const hasInstance = Object.getOwnPropertyDescriptor(
      PhilCoreV2GenesisCredentialOrphanClassificationError,
      Symbol.hasInstance
    );
    assert.equal(hasInstance.writable, false);
    assert.equal(hasInstance.configurable, false);
    assert.throws(() => {
      Object.defineProperty(
        PhilCoreV2GenesisCredentialOrphanClassificationError,
        Symbol.hasInstance,
        { value: () => true }
      );
    });

    const genuine = expectClassifierCode(
      () => classifyPhilCoreV2GenesisCredentialOrphan(createActive("0")),
      E.ORPHAN_CLASSIFICATION_STATE_INVALID
    );
    assert.equal(
      genuine instanceof PhilCoreV2GenesisCredentialOrphanClassificationError,
      true
    );
    assert.equal(genuine instanceof Error, true);
    assert.equal("cause" in genuine, false);

    const hostile = Object.freeze({ hostile: true });
    withHarness(() => {
      validatorHarness.target = () => createActive("0");
      const owned = expectClassifierCode(
        () => classifyPhilCoreV2GenesisCredentialOrphan(hostile),
        E.ORPHAN_CLASSIFICATION_STATE_INVALID,
        "hostile-state"
      );
      for (const key of Reflect.ownKeys(owned)) {
        if (key === "stack") continue;
        assert.notEqual(owned[key], hostile);
      }
    });

    const sentinel = Object.freeze({ sentinel: "orphan-classification-state-read" });
    const throwingRecord = new Proxy(Object.create(null), {
      get(_target, prop) {
        if (prop === "state") {
          throw sentinel;
        }
        return undefined;
      }
    });
    withHarness(() => {
      validatorHarness.target = () => throwingRecord;
      const owned = expectClassifierCode(
        () => classifyPhilCoreV2GenesisCredentialOrphan({}),
        E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION,
        "state-sentinel"
      );
      for (const key of Reflect.ownKeys(owned)) {
        const descriptor = Object.getOwnPropertyDescriptor(owned, key);
        assert.notEqual(owned[key], sentinel);
        if (descriptor && Object.prototype.hasOwnProperty.call(descriptor, "value")) {
          assert.notEqual(descriptor.value, sentinel);
        }
      }
    });
  });

  it("C19: all 30 real-validator-admissible role x hash-nullability x orphan-reason combinations", () => {
    const seen = [];
    for (const role of ROLES) {
      for (const known of [true, false]) {
        for (const reason of ALL_ORPHAN_REASONS) {
          const record = makeOrphaned(role, known, reason);
          assert.equal(record.state, "ORPHANED");
          const hashesNull =
            record.credentialIdHash === null
            && record.publicVerificationMaterialHash === null;
          assert.equal(hashesNull, !known);
          const result = classifyPhilCoreV2GenesisCredentialOrphan(record);
          assertSemanticClassification(record, result);
          if (role === "1" && known) {
            assert.equal(
              result.credentialKnowledge,
              "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED"
            );
          }
          seen.push(`${role}:${known ? "known" : "unknown"}:${reason}`);
        }
      }
    }
    assert.equal(seen.length, 30);
    assert.equal(new Set(seen).size, 30);
  });

  it("C20: repeated classification is byte-equivalent and returns distinct frozen objects", () => {
    const record = makeOrphaned("2", true, "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION");
    const first = classifyPhilCoreV2GenesisCredentialOrphan(record);
    const second = classifyPhilCoreV2GenesisCredentialOrphan(record);
    assert.notEqual(first, second);
    assert.equal(JSON.stringify(first), JSON.stringify(second));
    assertDeepFrozenClassification(first);
    assertDeepFrozenClassification(second);
  });

  it("C21: require time performs no filesystem, host, coordinator, product, device, or network work", () => {
    assert.deepEqual(REQUIRE_TIME_COUNTS, { validatorCalls: 0 });
    const forbidden = [
      ["fs", /\bnode:fs\b|["'`]fs["'`]|\breadFileSync\b|\bwriteFileSync\b|\bexistsSync\b/u],
      ["Date", /\bDate\b/u],
      ["process", /\bprocess\b/u],
      ["timer", /\bset(?:Timeout|Interval|Immediate)\b|\bclear(?:Timeout|Interval|Immediate)\b|\bqueueMicrotask\b|\bperformance\s*\.|\bhrtime\b/u],
      ["network", /\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bnode:(?:http|https|net|tls|dgram)\b/u],
      ["randomness", /\bMath\s*\.\s*random\b|\bgetRandomValues\b|\brandomUUID\b/u],
      ["dynamic require/import", /\b(?:require|import)\s*\(/u],
      ["globals", /\bglobalThis\b|\b__dirname\b|\b__filename\b/u]
    ];
    for (const [label, pattern] of forbidden) {
      assert.equal(
        pattern.test(CLASSIFIER_SOURCE),
        false,
        `classifier contains a ${label} reference: ${String(CLASSIFIER_SOURCE.match(pattern))}`
      );
    }
    const again = require(CLASSIFIER_PATH);
    assert.equal(again, classifier);
  });

  it("C22: source/reference/require-graph scans prove exact three-file dormant isolation", () => {
    const imports = [...CLASSIFIER_SOURCE.matchAll(/\bfrom\s+["']([^"']+)["']/g)]
      .map((match) => match[1]);
    assert.deepEqual(imports, [
      "./v2ConsumerRecoveryGenesisCredentialObligation.ts"
    ]);
    for (const literal of [
      "node:fs",
      "node:path",
      "node:crypto",
      "node:net",
      "ipcMain",
      "ipcRenderer",
      "contextBridge",
      "electron",
      "recovery-genesis-staging-host",
      "recovery-genesis-staging-coordinator",
      "v2ConsumerRecoveryGenesisStagingJournal",
      "v2ConsumerRecoveryGenesisStagingProfile",
      "v2ConsumerRecoveryGenesisFinalizedProfile",
      "deviceAdapter",
      "secret",
      "sepolia"
    ]) {
      assert.equal(CLASSIFIER_SOURCE.includes(literal), false, literal);
    }
    for (const [label, pattern] of [
      ["clearing", /\bclearing\b/u],
      ["deletion", /\bdeletion\b/u],
      ["evidence", /\bevidence\b/u],
      ["provider", /\bprovider\b/u],
      ["device", /\bdevice\b/u],
      ["host", /\bhost\b/u],
      ["coordinator", /\bcoordinator\b/u]
    ]) {
      assert.equal(
        pattern.test(CLASSIFIER_SOURCE),
        false,
        `classifier source contains ${label} authority: ${String(CLASSIFIER_SOURCE.match(pattern))}`
      );
    }

    const visited = new Set();
    function scanImports(file) {
      const resolved = path.resolve(file);
      if (visited.has(resolved)) return;
      visited.add(resolved);
      const source = fs.readFileSync(resolved, "utf8");
      for (const match of source.matchAll(/\bfrom\s+["'](\.[^"']+)["']/g)) {
        scanImports(path.resolve(path.dirname(resolved), match[1]));
      }
    }
    scanImports(CLASSIFIER_PATH);
    const graph = [...visited].map((file) => path.relative(ROOT, file)).join("\n");
    assert.equal(graph.includes("recovery-genesis-staging-host"), false);
    assert.equal(graph.includes("recovery-genesis-staging-coordinator"), false);
    assert.equal(graph.includes("v2LocalCeremonyProtocol"), false);
    assert.ok(graph.includes("v2ConsumerRecoveryGenesisCredentialObligation.ts"));

    const needle = "v2ConsumerRecoveryGenesisCredentialOrphanClassification";
    const hits = [];
    function scanTree(target) {
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) return;
      if (stat.isDirectory()) {
        if (SCAN_SKIP_DIR_NAMES.includes(path.basename(target))) return;
        for (const name of fs.readdirSync(target)) {
          scanTree(path.join(target, name));
        }
        return;
      }
      if (!/\.(?:cjs|mjs|js|ts|tsx|json|html|yml|yaml|md)$/.test(target)) return;
      const relative = path.relative(ROOT, target);
      const source = fs.readFileSync(target, "utf8");
      if (relative.includes(needle) || source.includes(needle)) {
        hits.push(relative);
      }
    }
    scanTree(ROOT);
    assert.deepEqual(hits.sort(), [...PACKAGE_RELATIVE_PATHS].sort());

    for (const relative of PACKAGE_RELATIVE_PATHS) {
      const absolute = path.join(ROOT, relative);
      const stat = fs.lstatSync(absolute);
      assert.equal(stat.isSymbolicLink(), false, relative);
      assert.equal(stat.isFile(), true, relative);
      assert.equal(stat.mode & 0o170000, 0o100000, `${relative} is not a regular file`);
    }
  });
});

after(function () {
  resetHarness();
  restoreObligationWrapper();
  assert.equal(require.cache[OBLIGATION_PATH].exports, obligationReal);
});
