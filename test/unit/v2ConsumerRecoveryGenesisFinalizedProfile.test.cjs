require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { getAddress } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const JOURNAL_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingJournal.ts"
);
const PROTOCOL_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts"
);
const ADAPTER_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingProfile.ts"
);
const FINALIZED_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisFinalizedProfile.ts"
);

function assertPristineNamespace(namespace) {
  assert.equal(Object.getPrototypeOf(namespace), Object.prototype);
  assert.deepEqual(Object.getOwnPropertyDescriptor(namespace, "__esModule"), {
    value: true,
    writable: false,
    enumerable: false,
    configurable: false
  });
}

function assertSameReference(actual, expected, label) {
  assert.ok(actual === expected, `${label} reference changed`);
}

function assertExportsDescriptor(moduleObject, expected, label) {
  const actual = Object.getOwnPropertyDescriptor(moduleObject, "exports");
  assert.ok(actual !== undefined, `${label} exports descriptor is missing`);
  assertSameReference(actual.value, expected.value, `${label} exports value`);
  assert.equal(actual.writable, expected.writable);
  assert.equal(actual.enumerable, expected.enumerable);
  assert.equal(actual.configurable, expected.configurable);
}

const journalReal = require(JOURNAL_PATH);
const protocolReal = require(PROTOCOL_PATH);
assertPristineNamespace(journalReal);
assertPristineNamespace(protocolReal);

// Seed uncontaminated global subjects so both displacements and exact
// restorations are unconditional, observable parts of this suite's seam.
const adapterSeed = require(ADAPTER_PATH);
const finalizedSeed = require(FINALIZED_PATH);
assertPristineNamespace(adapterSeed);
assertPristineNamespace(finalizedSeed);
const journalModule = require.cache[JOURNAL_PATH];
const adapterSeedModule = require.cache[ADAPTER_PATH];
const finalizedSeedModule = require.cache[FINALIZED_PATH];
const journalExportsDescriptor = Object.getOwnPropertyDescriptor(
  journalModule,
  "exports"
);
const cacheKeysBeforeWindow = new Set(Object.keys(require.cache));

const journalHarness = {
  target: journalReal.validateGenesisStagingJournalRecord,
  calls: 0
};
const adapterHarness = {
  target: null,
  calls: 0,
  captured: []
};
const stableJournalWrapper = function (...args) {
  journalHarness.calls += 1;
  return journalHarness.target(...args);
};

function makeShim(real, wrappedKey, wrapper) {
  const shim = Object.create(null);
  for (const key of Object.keys(real)) shim[key] = real[key];
  shim[wrappedKey] = wrapper;
  return shim;
}

const journalShim = makeShim(
  journalReal,
  "validateGenesisStagingJournalRecord",
  stableJournalWrapper
);
journalModule.exports = journalShim;

delete require.cache[ADAPTER_PATH];
assert.equal(Object.prototype.hasOwnProperty.call(require.cache, ADAPTER_PATH), false);
const adapterReal = require(ADAPTER_PATH);
const privateAdapterModule = require.cache[ADAPTER_PATH];
assert.ok(
  privateAdapterModule !== adapterSeedModule,
  "private adapter module was not displaced"
);
adapterHarness.target = adapterReal.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile;
const stableAdapterWrapper = function (...args) {
  adapterHarness.calls += 1;
  adapterHarness.captured.push([...args]);
  return adapterHarness.target(...args);
};
const adapterShim = makeShim(
  adapterReal,
  "validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile",
  stableAdapterWrapper
);
privateAdapterModule.exports = adapterShim;

delete require.cache[FINALIZED_PATH];
assert.equal(Object.prototype.hasOwnProperty.call(require.cache, FINALIZED_PATH), false);
const mod = require(FINALIZED_PATH);
const privateFinalizedModule = require.cache[FINALIZED_PATH];
assert.ok(
  privateFinalizedModule !== finalizedSeedModule,
  "private finalized module was not displaced"
);
const REQUIRE_TIME_COUNTS = Object.freeze({
  journal: journalHarness.calls,
  adapter: adapterHarness.calls,
  captured: adapterHarness.captured.length
});
Object.defineProperty(journalModule, "exports", journalExportsDescriptor);
require.cache[ADAPTER_PATH] = adapterSeedModule;
require.cache[FINALIZED_PATH] = finalizedSeedModule;
const cacheKeysAddedByWindow = Object.freeze(
  Object.keys(require.cache).filter((key) => !cacheKeysBeforeWindow.has(key))
);

function assertCacheWindowHygiene() {
  assertSameReference(
    require.cache[JOURNAL_PATH],
    journalModule,
    "journal cache entry"
  );
  assertSameReference(
    require.cache[ADAPTER_PATH],
    adapterSeedModule,
    "adapter cache entry"
  );
  assertSameReference(
    require.cache[FINALIZED_PATH],
    finalizedSeedModule,
    "finalized cache entry"
  );
  assertExportsDescriptor(journalModule, journalExportsDescriptor, "journal");
  assertSameReference(journalModule.exports, journalReal, "journal exports");
  assertSameReference(adapterSeedModule.exports, adapterSeed, "adapter exports");
  assertSameReference(
    finalizedSeedModule.exports,
    finalizedSeed,
    "finalized exports"
  );
  assert.ok(
    privateAdapterModule !== adapterSeedModule,
    "private adapter module aliases the restored seed"
  );
  assert.ok(
    privateFinalizedModule !== finalizedSeedModule,
    "private finalized module aliases the restored seed"
  );
  assertSameReference(
    privateAdapterModule.exports,
    adapterShim,
    "private adapter exports"
  );
  assertSameReference(privateFinalizedModule.exports, mod, "private finalized exports");
  assert.deepEqual(cacheKeysAddedByWindow, []);
  assertPristineNamespace(journalModule.exports);
  assertPristineNamespace(adapterSeedModule.exports);
  assertPristineNamespace(finalizedSeedModule.exports);
}

assertCacheWindowHygiene();

const {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
  computePhilCoreV2ConsumerRecoveryIndependenceBinding
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_V2_SECURITY_MODEL_ID
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  buildO39ConsumerRecoveryFixturePackage
} = require("../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs");

const fixtures = buildO39ConsumerRecoveryFixturePackage();
const C = mod.PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_ERROR_CODE;
const ADAPTER_C = adapterReal.PHILCORE_V2_GENESIS_STAGING_PROFILE_ERROR_CODE;

const RECORD_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "state",
  "intentId",
  "genesisDeploymentIntentHash",
  "sourceJournalIntegrityChecksum",
  "finalizedAtUnixSeconds",
  "sourceJournal",
  "validationResult",
  "integrityChecksum"
]);
const RESULT_KEYS = Object.freeze([
  "genesisDeploymentIntentHash",
  "genesisEnrollmentCeremonyHashes",
  "profile"
]);
const PROFILE_RESULT_KEYS = Object.freeze([
  "profile",
  "descriptors",
  "commitments",
  "recoveryConfigurationHash",
  "independenceAssurance",
  "warnings"
]);
const DESCRIPTOR_KEYS = Object.freeze([
  "descriptorVersion",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "role",
  "verifierKind",
  "publicVerificationMaterialHash",
  "credentialIdHash",
  "rpIdHash",
  "originPolicyHash",
  "independenceBindingHash",
  "userVerificationPolicy",
  "backupPolicy",
  "authenticatorAttachmentPolicy",
  "attestationPolicy",
  "credentialGeneration"
]);

const DESCRIPTOR_NUMERIC_FIELDS = Object.freeze([
  "descriptorVersion",
  "role",
  "verifierKind",
  "userVerificationPolicy",
  "backupPolicy",
  "authenticatorAttachmentPolicy",
  "attestationPolicy",
  "credentialGeneration"
]);
const INDEPENDENCE_NUMERIC_FIELDS = Object.freeze([
  "bindingVersion",
  "role",
  "authenticatorClass",
  "synchronizationClass",
  "independenceAssurance",
  "credentialGeneration"
]);

function resetHarnesses() {
  journalHarness.target = journalReal.validateGenesisStagingJournalRecord;
  journalHarness.calls = 0;
  adapterHarness.target =
    adapterReal.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile;
  adapterHarness.calls = 0;
  adapterHarness.captured.length = 0;
}

function withHarnesses(run) {
  resetHarnesses();
  try {
    return run();
  } finally {
    resetHarnesses();
  }
}

function expectFinalizedCode(run, code) {
  assert.throws(run, (error) => {
    assert.ok(
      error instanceof mod.PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError
    );
    assert.equal(error.code, code);
    return true;
  });
}

function expectAdapterCode(run, code) {
  assert.throws(run, (error) => {
    assert.ok(
      error instanceof adapterReal.PhilCoreV2ConsumerRecoveryGenesisStagingProfileError
    );
    assert.equal(error.code, code);
    return true;
  });
}

function validIntent(overrides = {}) {
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
    initialValidator: fixtures.profiles.standard.request.validator,
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

function bigintFields(source, numericFields) {
  const output = { ...source };
  for (const key of numericFields) {
    if (typeof output[key] === "number") output[key] = BigInt(output[key]);
  }
  return output;
}

function buildScenario() {
  const now = 1000;
  const intent = validIntent();
  const intentHash =
    protocolReal.computePhilCoreV2LocalGenesisDeploymentIntentHash(intent);
  const ceremonies = [0, 1, 2].map((role) => ({
    ceremonyVersion: "1",
    ceremonyId: `0x${String(role + 1).padStart(2, "0")}${"a1".repeat(31)}`,
    genesisDeploymentIntentHash: intentHash,
    role: String(role),
    credentialGeneration: "1",
    expiresAt: "1899999999"
  }));
  const ceremonyHashes = ceremonies.map((value) =>
    protocolReal.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(value)
  );
  const source = fixtures.profiles.standard.factors;
  const roleSources = [source.primary, source.secondary, source.offline];
  const factors = roleSources.map((base, role) => {
    const independence = {
      ...bigintFields(base.independence, INDEPENDENCE_NUMERIC_FIELDS),
      role: BigInt(role),
      enrollmentCeremonyHash: ceremonyHashes[role],
      credentialGeneration: 1n
    };
    const descriptor = {
      ...bigintFields(base.descriptor, DESCRIPTOR_NUMERIC_FIELDS),
      role: BigInt(role),
      independenceBindingHash:
        computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence),
      credentialGeneration: 1n
    };
    return {
      descriptor,
      independence,
      ...(base.signer ? { signer: base.signer } : {})
    };
  });
  let journal = journalReal.createGenesisStagingJournal(intent, now);
  for (const role of [0, 1, 2]) {
    journal = journalReal.stageGenesisRoleCandidate(
      journal,
      role,
      { ...factors[role], currentRoleCeremony: ceremonies[role] },
      now + role + 1
    );
  }
  return {
    now,
    intent,
    intentHash,
    ceremonies,
    ceremonyHashes,
    factors,
    journal,
    validNow: now + 3
  };
}

function authoritativeResult(scenario) {
  return adapterReal.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
    scenario.journal,
    scenario.validNow
  );
}

function buildValidRecord(scenario) {
  return mod.createGenesisFinalizedProfileRecord(
    scenario.journal,
    authoritativeResult(scenario),
    scenario.validNow
  );
}

function recordWithoutChecksum(record) {
  const {
    integrityChecksum: _ignored,
    ...withoutChecksum
  } = record;
  return withoutChecksum;
}

function assertWrapperHygiene() {
  assert.deepEqual(Object.keys(journalShim).sort(), Object.keys(journalReal).sort());
  assert.deepEqual(Object.keys(adapterShim).sort(), Object.keys(adapterReal).sort());
  for (const key of Object.keys(journalReal)) {
    if (key === "validateGenesisStagingJournalRecord") {
      assert.equal(journalShim[key], stableJournalWrapper);
    } else {
      assert.equal(journalShim[key], journalReal[key]);
    }
  }
  for (const key of Object.keys(adapterReal)) {
    if (key === "validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile") {
      assert.equal(adapterShim[key], stableAdapterWrapper);
    } else {
      assert.equal(adapterShim[key], adapterReal[key]);
    }
  }
  assert.equal(
    journalHarness.target,
    journalReal.validateGenesisStagingJournalRecord
  );
  assert.equal(
    adapterHarness.target,
    adapterReal.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile
  );
  assert.equal(journalHarness.calls, 0);
  assert.equal(adapterHarness.calls, 0);
  assert.deepEqual(adapterHarness.captured, []);
}

function allObjectReferences(value, output = new Set()) {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    return output;
  }
  if (output.has(value)) return output;
  output.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor && "value" in descriptor) {
      allObjectReferences(descriptor.value, output);
    }
  }
  return output;
}

describe("Dormant genesis finalized profile — AT", function () {
  it("AT-F1 exports exactly the accepted ten runtime values", function () {
    assert.deepEqual(Object.keys(mod).sort(), [
      "MAX_GENESIS_FINALIZED_PROFILE_FILE_BYTES",
      "PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_ERROR_CODE",
      "PHILCORE_V2_GENESIS_FINALIZED_PROFILE_CHECKSUM_PREFIX",
      "PHILCORE_V2_GENESIS_FINALIZED_PROFILE_FORMAT_PROVENANCE",
      "PHILCORE_V2_GENESIS_FINALIZED_PROFILE_SCHEMA_VERSION",
      "PHILCORE_V2_GENESIS_FINALIZED_PROFILE_STATE",
      "PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError",
      "computeGenesisFinalizedProfileChecksum",
      "createGenesisFinalizedProfileRecord",
      "validateGenesisFinalizedProfileRecord"
    ].sort());
  });

  it("AT-F2 exposes the five accepted literal constants", function () {
    assert.equal(mod.PHILCORE_V2_GENESIS_FINALIZED_PROFILE_SCHEMA_VERSION, 1);
    assert.equal(
      mod.PHILCORE_V2_GENESIS_FINALIZED_PROFILE_FORMAT_PROVENANCE,
      "philcore-v2-consumer-recovery-genesis-finalized-profile-v1"
    );
    assert.equal(mod.PHILCORE_V2_GENESIS_FINALIZED_PROFILE_STATE, "FINALIZED");
    assert.equal(
      mod.PHILCORE_V2_GENESIS_FINALIZED_PROFILE_CHECKSUM_PREFIX,
      "PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_FINALIZED_PROFILE_V1|"
    );
    assert.equal(mod.MAX_GENESIS_FINALIZED_PROFILE_FILE_BYTES, 32768);
  });

  it("AT-F3 exposes a closed frozen twenty-four-code branded error surface", function () {
    assert.equal(Object.isFrozen(C), true);
    assert.deepEqual(Object.keys(C), [
      "FINALIZED_PROFILE_RECORD_NOT_OBJECT",
      "FINALIZED_PROFILE_RECORD_MISSING_KEY",
      "FINALIZED_PROFILE_RECORD_EXTRA_KEY",
      "FINALIZED_PROFILE_RECORD_ENUMERATION_FAILED",
      "FINALIZED_PROFILE_RECORD_PROPERTY_READ_FAILED",
      "FINALIZED_PROFILE_SCHEMA_VERSION_UNSUPPORTED",
      "FINALIZED_PROFILE_FORMAT_PROVENANCE_INVALID",
      "FINALIZED_PROFILE_STATE_INVALID",
      "FINALIZED_PROFILE_FINALIZED_AT_INVALID",
      "FINALIZED_PROFILE_SOURCE_TIMESTAMP_INVALID",
      "FINALIZED_PROFILE_INTENT_ID_MISMATCH",
      "FINALIZED_PROFILE_INTENT_HASH_MISMATCH",
      "FINALIZED_PROFILE_SOURCE_CHECKSUM_MISMATCH",
      "FINALIZED_PROFILE_RESULT_NOT_OBJECT",
      "FINALIZED_PROFILE_RESULT_MISSING_KEY",
      "FINALIZED_PROFILE_RESULT_EXTRA_KEY",
      "FINALIZED_PROFILE_RESULT_ENUMERATION_FAILED",
      "FINALIZED_PROFILE_RESULT_PROPERTY_READ_FAILED",
      "FINALIZED_PROFILE_RESULT_SHAPE_INVALID",
      "FINALIZED_PROFILE_RESULT_MISMATCH",
      "FINALIZED_PROFILE_CHECKSUM_FORMAT_INVALID",
      "FINALIZED_PROFILE_CHECKSUM_MISMATCH",
      "FINALIZED_PROFILE_RECORD_OVERSIZED",
      "FINALIZED_PROFILE_SERIALIZATION_REJECTED"
    ]);
    const error = new mod.PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError(
      C.FINALIZED_PROFILE_RECORD_NOT_OBJECT
    );
    assert.ok(
      error instanceof mod.PhilCoreV2ConsumerRecoveryGenesisFinalizedProfileError
    );
    assert.equal(error.code, C.FINALIZED_PROFILE_RECORD_NOT_OBJECT);
  });

  it("AT-F4 builds a valid record from a fully populated STAGING journal", function () {
    const scenario = buildScenario();
    const record = buildValidRecord(scenario);
    assert.equal(record.state, "FINALIZED");
    assert.equal(record.schemaVersion, 1);
    assert.equal(record.finalizedAtUnixSeconds, String(scenario.validNow));
  });

  it("AT-F5 preserves exact top-level, result, profile, and descriptor key orders", function () {
    const record = buildValidRecord(buildScenario());
    assert.deepEqual(Object.keys(record), RECORD_KEYS);
    assert.deepEqual(Object.keys(record.validationResult), RESULT_KEYS);
    assert.deepEqual(Object.keys(record.validationResult.profile), PROFILE_RESULT_KEYS);
    for (const descriptor of record.validationResult.profile.descriptors) {
      assert.deepEqual(Object.keys(descriptor), DESCRIPTOR_KEYS);
    }
  });

  it("AT-F6 binds identity fields to the embedded source journal", function () {
    const scenario = buildScenario();
    const validated = journalReal.validateGenesisStagingJournalRecord(scenario.journal);
    const record = buildValidRecord(scenario);
    assert.equal(record.intentId, validated.intentId);
    assert.equal(record.genesisDeploymentIntentHash, validated.genesisDeploymentIntentHash);
    assert.equal(record.sourceJournalIntegrityChecksum, validated.integrityChecksum);
    assert.deepEqual(record.sourceJournal, validated);
  });

  it("AT-F7 computes the accepted checksum vector", function () {
    const record = buildValidRecord(buildScenario());
    const withoutChecksum = recordWithoutChecksum(record);
    const projection = JSON.stringify(withoutChecksum);
    const digest = createHash("sha256")
      .update(mod.PHILCORE_V2_GENESIS_FINALIZED_PROFILE_CHECKSUM_PREFIX, "utf8")
      .update(projection, "utf8")
      .digest("hex");
    assert.equal(record.integrityChecksum, `0x${digest}`);
    assert.equal(
      mod.computeGenesisFinalizedProfileChecksum(withoutChecksum),
      record.integrityChecksum
    );
  });

  it("AT-F8 round-trips through stored validation", function () {
    const record = buildValidRecord(buildScenario());
    const parsed = JSON.parse(JSON.stringify(record));
    const validated = mod.validateGenesisFinalizedProfileRecord(parsed);
    assert.deepEqual(validated, record);
  });

  it("AT-F9 returns deeply frozen owned containers", function () {
    const record = buildValidRecord(buildScenario());
    const containers = [
      record,
      record.sourceJournal,
      record.validationResult,
      record.validationResult.genesisEnrollmentCeremonyHashes,
      record.validationResult.profile,
      record.validationResult.profile.descriptors,
      ...record.validationResult.profile.descriptors,
      record.validationResult.profile.commitments,
      record.validationResult.profile.warnings
    ];
    for (const value of containers) {
      assert.equal(Object.isFrozen(value), true);
    }
    const journalRefs = allObjectReferences(buildScenario().journal);
    const recordRefs = allObjectReferences(record);
    for (const ref of recordRefs) {
      assert.equal(journalRefs.has(ref), false);
    }
  });

  it("AT-F10 delegates to the staging-profile adapter exactly once in the builder", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      mod.createGenesisFinalizedProfileRecord(
        scenario.journal,
        authoritativeResult(scenario),
        scenario.validNow
      );
      assert.equal(adapterHarness.calls, 1);
    });
  });

  it("AT-F11 delegates to the staging-profile adapter exactly once in stored validation", function () {
    const record = buildValidRecord(buildScenario());
    withHarnesses(() => {
      mod.validateGenesisFinalizedProfileRecord(record);
      assert.equal(adapterHarness.calls, 1);
    });
  });

  it("AT-F12 revalidates stored records at stored finalizedAtUnixSeconds", function () {
    const scenario = buildScenario();
    const record = buildValidRecord(scenario);
    withHarnesses(() => {
      mod.validateGenesisFinalizedProfileRecord(record);
      assert.equal(adapterHarness.calls, 1);
      assert.equal(adapterHarness.captured.length, 1);
      assert.equal(
        adapterHarness.captured[0][1],
        Number(record.finalizedAtUnixSeconds)
      );
      assert.notEqual(
        adapterHarness.captured[0][1],
        Number(scenario.journal.expiresAt)
      );
    });
  });

  it("AT-F13 is dormant at require time", function () {
    assert.deepEqual(REQUIRE_TIME_COUNTS, {
      journal: 0,
      adapter: 0,
      captured: 0
    });
  });

  it("AT-F14 maintains the wrapper-specific hygiene contract", function () {
    resetHarnesses();
    assertWrapperHygiene();
  });

  it("AT-F15 restores the seeded module cache immediately and exactly", function () {
    assertCacheWindowHygiene();
  });

  it("AT-F16 private adapter captures the stable journal wrapper", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      authoritativeResult(scenario);
      assert.equal(journalHarness.calls, 1);
    });
  });
});

describe("Dormant genesis finalized profile — AD", function () {
  it("AD-F1 rethrows adapter-layer errors and raw values by identity", function () {
    const scenario = buildScenario();
    const marker = Object.freeze({ marker: "adapter" });
    withHarnesses(() => {
      adapterHarness.target = () => { throw marker; };
      let caught;
      try {
        mod.createGenesisFinalizedProfileRecord(
          scenario.journal,
          authoritativeResult(scenario),
          scenario.validNow
        );
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, marker);
      assert.equal(adapterHarness.calls, 1);
    });
  });

  it("AD-F2 rethrows journal-layer errors and raw values by identity", function () {
    const scenario = buildScenario();
    const marker = Object.freeze({ marker: "journal" });
    withHarnesses(() => {
      journalHarness.target = () => { throw marker; };
      let caught;
      try {
        mod.validateGenesisFinalizedProfileRecord(buildValidRecord(scenario));
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, marker);
    });
  });

  it("AD-F3 invalid now outranks hostile expected-result inspection", function () {
    const scenario = buildScenario();
    const marker = new Error("expected result must not be inspected");
    const hostile = new Proxy({}, {
      ownKeys() { throw marker; },
      getOwnPropertyDescriptor() { throw marker; },
      getPrototypeOf() { throw marker; }
    });
    withHarnesses(() => {
      expectAdapterCode(
        () => mod.createGenesisFinalizedProfileRecord(scenario.journal, hostile, 0),
        ADAPTER_C.STAGING_PROFILE_INVALID_NOW
      );
      assert.equal(adapterHarness.calls, 1);
    });
  });

  it("AD-F4 performs zero adapter-attributable reads of the caller journal object", function () {
    const scenario = buildScenario();
    const accepted = journalReal.validateGenesisStagingJournalRecord(scenario.journal);
    let reads = 0;
    const hostile = new Proxy({}, {
      ownKeys() { reads += 1; return []; },
      getOwnPropertyDescriptor() { reads += 1; return undefined; },
      get() { reads += 1; return undefined; },
      getPrototypeOf() { reads += 1; return Object.prototype; }
    });
    withHarnesses(() => {
      adapterHarness.target = () => authoritativeResult(scenario);
      journalHarness.target = () => accepted;
      mod.createGenesisFinalizedProfileRecord(
        hostile,
        authoritativeResult(scenario),
        scenario.validNow
      );
      assert.equal(reads, 0);
      assert.equal(adapterHarness.calls, 1);
    });
  });

  it("AD-F5 rejects an expected-result mismatch only after authority succeeds", function () {
    const scenario = buildScenario();
    const wrong = authoritativeResult(scenario);
    const tampered = {
      ...wrong,
      genesisDeploymentIntentHash: `0x${"ff".repeat(32)}`
    };
    withHarnesses(() => {
      expectFinalizedCode(
        () => mod.createGenesisFinalizedProfileRecord(
          scenario.journal,
          tampered,
          scenario.validNow
        ),
        C.FINALIZED_PROFILE_RESULT_MISMATCH
      );
      assert.equal(adapterHarness.calls, 1);
    });
  });

  it("AD-F6 accepts expiry-minus-one and rejects expiry equality in the builder", function () {
    const scenario = buildScenario();
    const expected = authoritativeResult(scenario);
    const atBoundary = Number(scenario.journal.expiresAt) - 1;
    assert.doesNotThrow(() =>
      mod.createGenesisFinalizedProfileRecord(scenario.journal, expected, atBoundary)
    );
    withHarnesses(() => {
      expectAdapterCode(
        () => mod.createGenesisFinalizedProfileRecord(
          scenario.journal,
          expected,
          Number(scenario.journal.expiresAt)
        ),
        ADAPTER_C.STAGING_PROFILE_JOURNAL_EXPIRED
      );
      assert.equal(adapterHarness.calls, 1);
    });
  });

  it("AD-F7 rejects clock regression before expected-result inspection", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      expectAdapterCode(
        () => mod.createGenesisFinalizedProfileRecord(
          scenario.journal,
          authoritativeResult(scenario),
          scenario.validNow - 1
        ),
        ADAPTER_C.STAGING_PROFILE_CLOCK_REGRESSION_DETECTED
      );
      assert.equal(adapterHarness.calls, 1);
    });
  });

  it("AD-F8 rejects non-STAGING embedded journals during stored validation", function () {
    const scenario = buildScenario();
    const record = buildValidRecord(scenario);
    const terminal = journalReal.cancelGenesisStagingJournal(
      journalReal.createGenesisStagingJournal(scenario.intent, scenario.now),
      scenario.now + 1
    );
    const tampered = {
      ...record,
      sourceJournal: terminal
    };
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord(tampered),
      C.FINALIZED_PROFILE_STATE_INVALID
    );
  });

  it("AD-F9 rejects intent identity mismatches during stored validation", function () {
    const record = buildValidRecord(buildScenario());
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({
        ...record,
        intentId: `0x${"ee".repeat(32)}`
      }),
      C.FINALIZED_PROFILE_INTENT_ID_MISMATCH
    );
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({
        ...record,
        genesisDeploymentIntentHash: `0x${"dd".repeat(32)}`
      }),
      C.FINALIZED_PROFILE_INTENT_HASH_MISMATCH
    );
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({
        ...record,
        sourceJournalIntegrityChecksum: `0x${"cc".repeat(32)}`
      }),
      C.FINALIZED_PROFILE_SOURCE_CHECKSUM_MISMATCH
    );
  });

  it("AD-F10 rejects stored literal, checksum, and key-boundary failures", function () {
    const record = buildValidRecord(buildScenario());
    expectFinalizedCode(() => mod.validateGenesisFinalizedProfileRecord(null), C.FINALIZED_PROFILE_RECORD_NOT_OBJECT);
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({ ...record, schemaVersion: 2 }),
      C.FINALIZED_PROFILE_SCHEMA_VERSION_UNSUPPORTED
    );
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({
        ...record,
        formatProvenance: "foreign"
      }),
      C.FINALIZED_PROFILE_FORMAT_PROVENANCE_INVALID
    );
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({ ...record, state: "STAGING" }),
      C.FINALIZED_PROFILE_STATE_INVALID
    );
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({
        ...record,
        finalizedAtUnixSeconds: "0"
      }),
      C.FINALIZED_PROFILE_FINALIZED_AT_INVALID
    );
    const extra = { ...record, foreignKey: "x" };
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord(extra),
      C.FINALIZED_PROFILE_RECORD_EXTRA_KEY
    );
    const missing = { ...record };
    delete missing.intentId;
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord(missing),
      C.FINALIZED_PROFILE_RECORD_MISSING_KEY
    );
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({
        ...record,
        integrityChecksum: "not-a-checksum"
      }),
      C.FINALIZED_PROFILE_CHECKSUM_FORMAT_INVALID
    );
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord({
        ...record,
        integrityChecksum: `0x${"00".repeat(32)}`
      }),
      C.FINALIZED_PROFILE_CHECKSUM_MISMATCH
    );
  });

  it("AD-F11 rejects an oversized stored record before checksum equality", function () {
    const record = buildValidRecord(buildScenario());
    const oversized = JSON.parse(JSON.stringify(record));
    oversized.validationResult.profile.profile = "x".repeat(40000);
    oversized.integrityChecksum = mod.computeGenesisFinalizedProfileChecksum(
      recordWithoutChecksum(oversized)
    );
    expectFinalizedCode(
      () => mod.validateGenesisFinalizedProfileRecord(oversized),
      C.FINALIZED_PROFILE_RECORD_OVERSIZED
    );
  });

  it("AD-F12 never inspects hostile thrown values or retains markers in owned errors", function () {
    let traps = 0;
    const hostileThrown = new Proxy({}, {
      get() { traps += 1; throw new Error("get trap"); },
      ownKeys() { traps += 1; throw new Error("ownKeys trap"); },
      getOwnPropertyDescriptor() { traps += 1; throw new Error("descriptor trap"); }
    });
    withHarnesses(() => {
      adapterHarness.target = () => { throw hostileThrown; };
      let caught;
      try {
        mod.createGenesisFinalizedProfileRecord(buildScenario().journal, {}, 1);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, hostileThrown);
      assert.equal(traps, 0);
    });
    let coercions = 0;
    const marker = { valueOf() { coercions += 1; return 1; } };
    let owned;
    try {
      mod.createGenesisFinalizedProfileRecord({}, marker, marker);
    } catch (error) {
      owned = error;
    }
    assert.equal(coercions, 0);
    for (const key of Object.getOwnPropertyNames(owned)) {
      assert.notEqual(Object.getOwnPropertyDescriptor(owned, key).value, marker);
    }
  });

  it("AD-F13 enforces domain separation, two imports, and dormancy", function () {
    const source = fs.readFileSync(FINALIZED_PATH, "utf8");
    const imports = [...source.matchAll(/from\s+"([^"]+)"/g)]
      .map((match) => match[1]);
    assert.deepEqual(imports.sort(), [
      "./v2ConsumerRecoveryGenesisStagingJournal.ts",
      "./v2ConsumerRecoveryGenesisStagingProfile.ts",
      "node:crypto"
    ].sort());
    for (const literal of [
      "node:fs",
      "node:path",
      "process.",
      "ipcMain",
      "ipcRenderer",
      "contextBridge",
      "electron",
      "supersession",
      "deviceAdapter"
    ]) {
      assert.equal(source.includes(literal), false, literal);
    }
    assert.equal(source.includes("node:crypto"), true);
  });

  it("AD-F14 bounds warnings before allocating caller-controlled tuple indexes", function () {
    const scenario = buildScenario();
    const expected = authoritativeResult(scenario);
    const hostile = {
      ...expected,
      profile: {
        ...expected.profile,
        warnings: new Array(2 ** 31)
      }
    };
    expectFinalizedCode(
      () => mod.createGenesisFinalizedProfileRecord(
        scenario.journal,
        hostile,
        scenario.validNow
      ),
      C.FINALIZED_PROFILE_RESULT_SHAPE_INVALID
    );
  });

  it("AD-F15 contains hostile source-journal traversal in the checksum export", function () {
    const record = buildValidRecord(buildScenario());
    const marker = Object.freeze({ marker: "source-journal-proxy" });
    const hostile = new Proxy({}, {
      ownKeys() { throw marker; },
      getOwnPropertyDescriptor() { throw marker; },
      get() { throw marker; }
    });
    let caught;
    try {
      mod.computeGenesisFinalizedProfileChecksum({
        ...recordWithoutChecksum(record),
        sourceJournal: hostile
      });
    } catch (error) {
      caught = error;
    }
    assert.notEqual(caught, marker);
    assert.ok(caught instanceof journalReal.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError);
    assert.equal(
      caught.code,
      journalReal.PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_JOURNAL_ERROR_CODE
        .JOURNAL_ENUMERATION_FAILED
    );
    for (const key of Object.getOwnPropertyNames(caught)) {
      assert.notEqual(Object.getOwnPropertyDescriptor(caught, key).value, marker);
    }
  });
});

describe("Dormant genesis finalized profile — PF", function () {
  it("PF-F1 preserves builder output across a JSON record round-trip", function () {
    const scenario = buildScenario();
    const built = buildValidRecord(scenario);
    const parsed = JSON.parse(JSON.stringify(built));
    const validated = mod.validateGenesisFinalizedProfileRecord(parsed);
    assert.deepEqual(validated, built);
  });

  it("PF-F2 does not mutate the caller journal or expected result", function () {
    const scenario = buildScenario();
    const expected = authoritativeResult(scenario);
    const journalBefore = JSON.stringify(scenario.journal);
    const expectedBefore = JSON.stringify(expected);
    mod.createGenesisFinalizedProfileRecord(
      scenario.journal,
      expected,
      scenario.validNow
    );
    assert.equal(JSON.stringify(scenario.journal), journalBefore);
    assert.equal(JSON.stringify(expected), expectedBefore);
  });

  it("PF-F3 validates through a fresh parsed record without freezing caller input", function () {
    const record = buildValidRecord(buildScenario());
    const parsed = JSON.parse(JSON.stringify(record));
    const before = JSON.stringify(parsed);
    assert.equal(Object.isFrozen(parsed), false);
    const validated = mod.validateGenesisFinalizedProfileRecord(parsed);
    assert.equal(Object.isFrozen(parsed), false);
    assert.equal(JSON.stringify(parsed), before);
    assert.notEqual(validated, parsed);
  });

  it("PF-F4 agrees with pure expiry transitions on stored revalidation", function () {
    const scenario = buildScenario();
    const expected = authoritativeResult(scenario);
    const atBoundary = Number(scenario.journal.expiresAt) - 1;
    const record = mod.createGenesisFinalizedProfileRecord(
      scenario.journal,
      expected,
      atBoundary
    );
    assert.doesNotThrow(() => mod.validateGenesisFinalizedProfileRecord(record));
    const expiredRecord = {
      ...record,
      finalizedAtUnixSeconds: String(Number(scenario.journal.expiresAt))
    };
    expectAdapterCode(
      () => mod.validateGenesisFinalizedProfileRecord(expiredRecord),
      ADAPTER_C.STAGING_PROFILE_JOURNAL_EXPIRED
    );
  });
});

after(function () {
  resetHarnesses();
  assertCacheWindowHygiene();
});
