require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
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

// Seed an uncontaminated global subject so displacement and exact restoration
// are unconditional, observable parts of this suite's cache seam.
const adapterSeed = require(ADAPTER_PATH);
assertPristineNamespace(adapterSeed);
const journalModule = require.cache[JOURNAL_PATH];
const protocolModule = require.cache[PROTOCOL_PATH];
const adapterSeedModule = require.cache[ADAPTER_PATH];
const journalExportsDescriptor = Object.getOwnPropertyDescriptor(
  journalModule,
  "exports"
);
const protocolExportsDescriptor = Object.getOwnPropertyDescriptor(
  protocolModule,
  "exports"
);
const cacheKeysBeforeWindow = new Set(Object.keys(require.cache));

// Stable dispatching wrappers are installed before the adapter's first
// require. This works whether the transpiler emits a load-time capture or a
// call-time namespace lookup: both see the same stable wrapper object.
const journalHarness = {
  target: journalReal.validateGenesisStagingJournalRecord,
  calls: 0
};
const protocolHarness = {
  target: protocolReal.validatePhilCoreV2ConsumerRecoveryGenesisProfile,
  calls: 0,
  captured: []
};
const stableJournalWrapper = function (...args) {
  journalHarness.calls += 1;
  return journalHarness.target(...args);
};
const stableProtocolWrapper = function (...args) {
  protocolHarness.calls += 1;
  protocolHarness.captured.push(args[0]);
  return protocolHarness.target(...args);
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
const protocolShim = makeShim(
  protocolReal,
  "validatePhilCoreV2ConsumerRecoveryGenesisProfile",
  stableProtocolWrapper
);
journalModule.exports = journalShim;
protocolModule.exports = protocolShim;
delete require.cache[ADAPTER_PATH];
assert.equal(Object.prototype.hasOwnProperty.call(require.cache, ADAPTER_PATH), false);
const adapter = require(ADAPTER_PATH);
const privateAdapterModule = require.cache[ADAPTER_PATH];
assert.ok(
  privateAdapterModule !== adapterSeedModule,
  "private adapter module was not displaced"
);
const REQUIRE_TIME_COUNTS = Object.freeze({
  journal: journalHarness.calls,
  protocol: protocolHarness.calls,
  captured: protocolHarness.captured.length
});
Object.defineProperty(journalModule, "exports", journalExportsDescriptor);
Object.defineProperty(protocolModule, "exports", protocolExportsDescriptor);
require.cache[ADAPTER_PATH] = adapterSeedModule;
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
    require.cache[PROTOCOL_PATH],
    protocolModule,
    "protocol cache entry"
  );
  assertSameReference(
    require.cache[ADAPTER_PATH],
    adapterSeedModule,
    "adapter cache entry"
  );
  assertExportsDescriptor(journalModule, journalExportsDescriptor, "journal");
  assertExportsDescriptor(protocolModule, protocolExportsDescriptor, "protocol");
  assertSameReference(journalModule.exports, journalReal, "journal exports");
  assertSameReference(protocolModule.exports, protocolReal, "protocol exports");
  assertSameReference(adapterSeedModule.exports, adapterSeed, "adapter exports");
  assert.ok(
    privateAdapterModule !== adapterSeedModule,
    "private adapter module aliases the restored seed"
  );
  assertSameReference(privateAdapterModule.exports, adapter, "private adapter exports");
  assert.deepEqual(cacheKeysAddedByWindow, []);
  assertPristineNamespace(journalModule.exports);
  assertPristineNamespace(protocolModule.exports);
  assertPristineNamespace(adapterSeedModule.exports);
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
const gateB = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts"
);
const {
  buildO39ConsumerRecoveryFixturePackage
} = require("../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs");

const fixtures = buildO39ConsumerRecoveryFixturePackage();
const C = adapter.PHILCORE_V2_GENESIS_STAGING_PROFILE_ERROR_CODE;

const INTENT_KEYS = Object.freeze([
  "intentVersion", "intentId", "chainId", "entryPoint", "factoryBinding",
  "confirmationTarget", "verifier", "verifierRuntimeCodeHash",
  "accountCreationBytecodeHash", "accountVersionId", "securityModelId",
  "recoveryDomainId", "ownerCommitment", "identityBindingCommitment",
  "initialValidator", "validatorVerifierKind", "validatorKeyIdBinding",
  "validatorCommitment", "validatorEpoch", "recoveryEpoch",
  "recoveryDelaySeconds", "recoveryExpirySeconds", "userSalt", "expiresAt"
]);
const CEREMONY_KEYS = Object.freeze([
  "ceremonyVersion", "ceremonyId", "genesisDeploymentIntentHash", "role",
  "credentialGeneration", "expiresAt"
]);
const DESCRIPTOR_KEYS = Object.freeze([
  "descriptorVersion", "accountVersionId", "securityModelId",
  "recoveryDomainId", "role", "verifierKind",
  "publicVerificationMaterialHash", "credentialIdHash", "rpIdHash",
  "originPolicyHash", "independenceBindingHash", "userVerificationPolicy",
  "backupPolicy", "authenticatorAttachmentPolicy", "attestationPolicy",
  "credentialGeneration"
]);
const INDEPENDENCE_KEYS = Object.freeze([
  "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
  "independenceAssurance", "credentialIdHash", "enrollmentCeremonyHash",
  "attestationEvidenceHash", "custodyDomainCommitment", "credentialGeneration"
]);

const DESCRIPTOR_NUMERIC_FIELDS = Object.freeze([
  "descriptorVersion", "role", "verifierKind", "userVerificationPolicy",
  "backupPolicy", "authenticatorAttachmentPolicy", "attestationPolicy",
  "credentialGeneration"
]);
const INDEPENDENCE_NUMERIC_FIELDS = Object.freeze([
  "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
  "independenceAssurance", "credentialGeneration"
]);

function resetHarnesses() {
  journalHarness.target = journalReal.validateGenesisStagingJournalRecord;
  journalHarness.calls = 0;
  protocolHarness.target =
    protocolReal.validatePhilCoreV2ConsumerRecoveryGenesisProfile;
  protocolHarness.calls = 0;
  protocolHarness.captured.length = 0;
}

function withHarnesses(run) {
  resetHarnesses();
  try {
    return run();
  } finally {
    resetHarnesses();
  }
}

function expectAdapterCode(run, code) {
  assert.throws(run, (error) => {
    assert.ok(
      error instanceof
        adapter.PhilCoreV2ConsumerRecoveryGenesisStagingProfileError
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

function expectedProjection(record) {
  const intent = Object.fromEntries(INTENT_KEYS.map((key) => [key, record[key]]));
  const ceremonies = [0, 1, 2].map((slot) => {
    const entry = record.manifest[String(slot)];
    return {
      ceremonyVersion: "1",
      ceremonyId: entry.ceremonyId,
      genesisDeploymentIntentHash: record.genesisDeploymentIntentHash,
      role: entry.role,
      credentialGeneration: "1",
      expiresAt: entry.ceremonyExpiresAtUnixSeconds
    };
  });
  const factors = [0, 1, 2].map((slot) => {
    const entry = record.manifest[String(slot)];
    return {
      descriptor: entry.descriptor,
      independence: entry.independence,
      ...(slot === 2 ? { signer: entry.signer } : {})
    };
  });
  return {
    intent,
    ceremonies,
    factors,
    executionValidator: record.initialValidator
  };
}

function directResult(record) {
  return protocolReal.validatePhilCoreV2ConsumerRecoveryGenesisProfile(
    expectedProjection(record)
  );
}

function assertWrapperHygiene() {
  assert.deepEqual(Object.keys(journalShim).sort(), Object.keys(journalReal).sort());
  assert.deepEqual(Object.keys(protocolShim).sort(), Object.keys(protocolReal).sort());
  for (const key of Object.keys(journalReal)) {
    if (key === "validateGenesisStagingJournalRecord") {
      assert.equal(journalShim[key], stableJournalWrapper);
    } else {
      assert.equal(journalShim[key], journalReal[key]);
    }
  }
  for (const key of Object.keys(protocolReal)) {
    if (key === "validatePhilCoreV2ConsumerRecoveryGenesisProfile") {
      assert.equal(protocolShim[key], stableProtocolWrapper);
    } else {
      assert.equal(protocolShim[key], protocolReal[key]);
    }
  }
  assert.equal(
    journalHarness.target,
    journalReal.validateGenesisStagingJournalRecord
  );
  assert.equal(
    protocolHarness.target,
    protocolReal.validatePhilCoreV2ConsumerRecoveryGenesisProfile
  );
  assert.equal(journalHarness.calls, 0);
  assert.equal(protocolHarness.calls, 0);
  assert.deepEqual(protocolHarness.captured, []);
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

describe("Dormant genesis staging profile composition — AT", function () {
  it("AT-P1 exports exactly the accepted three runtime values", function () {
    assert.deepEqual(Object.keys(adapter).sort(), [
      "PHILCORE_V2_GENESIS_STAGING_PROFILE_ERROR_CODE",
      "PhilCoreV2ConsumerRecoveryGenesisStagingProfileError",
      "validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile"
    ].sort());
  });

  it("AT-P2 validates a full journal to the real genesis profile", function () {
    const scenario = buildScenario();
    assert.deepEqual(
      adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        scenario.journal,
        scenario.validNow
      ),
      directResult(scenario.journal)
    );
  });

  it("AT-P3 preserves the exact deployment-intent hash", function () {
    const scenario = buildScenario();
    const result = adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
      scenario.journal,
      scenario.validNow
    );
    assert.equal(result.genesisDeploymentIntentHash, scenario.intentHash);
  });

  it("AT-P4 preserves all three role-ordered ceremony hashes", function () {
    const scenario = buildScenario();
    const result = adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
      scenario.journal,
      scenario.validNow
    );
    assert.deepEqual(result.genesisEnrollmentCeremonyHashes, scenario.ceremonyHashes);
  });

  it("AT-P5 is differentially equal to an independently assembled projection", function () {
    const scenario = buildScenario();
    const expected = protocolReal.validatePhilCoreV2ConsumerRecoveryGenesisProfile(
      expectedProjection(scenario.journal)
    );
    const actual = adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
      scenario.journal,
      scenario.validNow
    );
    assert.deepEqual(actual, expected);
  });

  it("AT-P6 delegates to the profile validator exactly once", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        scenario.journal,
        scenario.validNow
      );
      assert.equal(protocolHarness.calls, 1);
      // The wrapper observes the exported journal-validator binding once;
      // allGenesisStagingSlotsPopulated also revalidates through its internal binding.
      assert.equal(journalHarness.calls, 1);
    });
  });

  it("AT-P7 projects exact top-level, intent, ceremony, descriptor, and independence orders", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        scenario.journal,
        scenario.validNow
      );
      const projection = protocolHarness.captured[0];
      assert.deepEqual(Object.keys(projection), [
        "intent", "ceremonies", "factors", "executionValidator"
      ]);
      assert.deepEqual(Object.keys(projection.intent), INTENT_KEYS);
      assert.equal(projection.ceremonies.length, 3);
      assert.equal(projection.factors.length, 3);
      for (const ceremony of projection.ceremonies) {
        assert.deepEqual(Object.keys(ceremony), CEREMONY_KEYS);
      }
      for (const factor of projection.factors) {
        assert.deepEqual(Object.keys(factor.descriptor), DESCRIPTOR_KEYS);
        assert.deepEqual(Object.keys(factor.independence), INDEPENDENCE_KEYS);
      }
    });
  });

  it("AT-P8 determines signer presence only from slot two", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        scenario.journal,
        scenario.validNow
      );
      const factors = protocolHarness.captured[0].factors;
      assert.deepEqual(Object.getOwnPropertyNames(factors[0]), [
        "descriptor", "independence"
      ]);
      assert.deepEqual(Object.getOwnPropertyNames(factors[1]), [
        "descriptor", "independence"
      ]);
      assert.deepEqual(Object.getOwnPropertyNames(factors[2]), [
        "descriptor", "independence", "signer"
      ]);
    });
  });

  it("AT-P9 binds executionValidator to journal.initialValidator", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        scenario.journal,
        scenario.validNow
      );
      const projection = protocolHarness.captured[0];
      assert.equal(projection.executionValidator, scenario.journal.initialValidator);
      assert.equal(projection.executionValidator, projection.intent.initialValidator);
    });
  });

  it("AT-P10 returns exactly the nine accepted frozen result containers", function () {
    const scenario = buildScenario();
    const real = directResult(scenario.journal);
    const unfrozen = {
      genesisDeploymentIntentHash: real.genesisDeploymentIntentHash,
      genesisEnrollmentCeremonyHashes: [...real.genesisEnrollmentCeremonyHashes],
      profile: {
        ...real.profile,
        descriptors: real.profile.descriptors.map((value) => ({ ...value })),
        commitments: [...real.profile.commitments],
        warnings: [...real.profile.warnings]
      }
    };
    const before = allObjectReferences(unfrozen);
    for (const value of before) assert.equal(Object.isFrozen(value), false);
    withHarnesses(() => {
      protocolHarness.target = () => unfrozen;
      const result = adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        scenario.journal,
        scenario.validNow
      );
      assert.equal(result, unfrozen);
      const containers = [
        result,
        result.genesisEnrollmentCeremonyHashes,
        result.profile,
        result.profile.descriptors,
        ...result.profile.descriptors,
        result.profile.commitments,
        result.profile.warnings
      ];
      assert.equal(containers.length, 9);
      for (const value of containers) assert.equal(Object.isFrozen(value), true);
      for (const [key, value] of Object.entries(result.profile)) {
        if (!containers.includes(value)) {
          assert.ok(
            value === null || typeof value !== "object",
            `profile leaf ${key} must be primitive`
          );
        }
      }
    });
  });

  it("AT-P11 exposes a closed frozen five-code branded error surface", function () {
    assert.equal(Object.isFrozen(C), true);
    assert.deepEqual(Object.keys(C), [
      "STAGING_PROFILE_INVALID_NOW",
      "STAGING_PROFILE_JOURNAL_NOT_STAGING",
      "STAGING_PROFILE_SLOTS_NOT_POPULATED",
      "STAGING_PROFILE_CLOCK_REGRESSION_DETECTED",
      "STAGING_PROFILE_JOURNAL_EXPIRED"
    ]);
    const error = new adapter.PhilCoreV2ConsumerRecoveryGenesisStagingProfileError(
      C.STAGING_PROFILE_INVALID_NOW
    );
    assert.ok(
      error instanceof adapter.PhilCoreV2ConsumerRecoveryGenesisStagingProfileError
    );
    assert.equal(error.code, C.STAGING_PROFILE_INVALID_NOW);
  });

  it("AT-P12 is dormant at require time", function () {
    assert.deepEqual(REQUIRE_TIME_COUNTS, {
      journal: 0,
      protocol: 0,
      captured: 0
    });
  });

  it("AT-P13 does not mutate the caller journal", function () {
    const scenario = buildScenario();
    const before = JSON.stringify(scenario.journal);
    adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
      scenario.journal,
      scenario.validNow
    );
    assert.equal(JSON.stringify(scenario.journal), before);
  });

  it("AT-P14 returns no journal object alias", function () {
    const scenario = buildScenario();
    const result = adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
      scenario.journal,
      scenario.validNow
    );
    const journalRefs = allObjectReferences(scenario.journal);
    const resultRefs = allObjectReferences(result);
    for (const ref of resultRefs) assert.equal(journalRefs.has(ref), false);
  });

  it("AT-P15 maintains the wrapper-specific five-rule hygiene contract", function () {
    resetHarnesses();
    assertWrapperHygiene();
  });

  it("AT-P16 reconstruction constants equal the landed Gate-B constants", function () {
    assert.equal(BigInt("1"), BigInt(gateB.PHILCORE_V2_GENESIS_ROLE_CEREMONY_VERSION));
    assert.equal(BigInt("1"), BigInt(gateB.PHILCORE_V2_GENESIS_ROLE_CEREMONY_GENERATION));
  });

  it("AT-P17 restores the seeded module cache immediately and exactly", function () {
    assertCacheWindowHygiene();
  });
});

describe("Dormant genesis staging profile composition — AD", function () {
  it("AD-P1 rethrows journal-layer errors and raw values by identity", function () {
    const marker = Object.freeze({ marker: "journal" });
    withHarnesses(() => {
      journalHarness.target = () => { throw marker; };
      let caught;
      try {
        adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile({}, 1);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, marker);
      assert.equal(protocolHarness.calls, 0);
    });
  });

  it("AD-P2 performs zero adapter-attributable reads of the caller object", function () {
    const scenario = buildScenario();
    const accepted = journalReal.validateGenesisStagingJournalRecord(scenario.journal);
    assert.equal(Object.isFrozen(accepted), true);
    let reads = 0;
    const hostile = new Proxy({}, {
      ownKeys() { reads += 1; return []; },
      getOwnPropertyDescriptor() { reads += 1; return undefined; },
      get() { reads += 1; return undefined; },
      getPrototypeOf() { reads += 1; return Object.prototype; }
    });
    withHarnesses(() => {
      journalHarness.target = () => accepted;
      adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        hostile,
        scenario.validNow
      );
      assert.equal(reads, 0);
      assert.equal(protocolHarness.calls, 1);
    });
  });

  it("AD-P3 invalid now outranks hostile journal inspection", function () {
    const marker = new Error("journal must not be inspected");
    const hostile = new Proxy({}, {
      ownKeys() { throw marker; },
      getOwnPropertyDescriptor() { throw marker; },
      getPrototypeOf() { throw marker; }
    });
    expectAdapterCode(
      () => adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        hostile,
        0
      ),
      C.STAGING_PROFILE_INVALID_NOW
    );
  });

  it("AD-P4 rethrows protocol-layer errors and raw values by identity", function () {
    const scenario = buildScenario();
    const marker = Object.freeze({ marker: "protocol" });
    withHarnesses(() => {
      protocolHarness.target = () => { throw marker; };
      let caught;
      try {
        adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
          scenario.journal,
          scenario.validNow
        );
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, marker);
      assert.equal(protocolHarness.calls, 1);
    });
  });

  it("AD-P5 rejects the complete invalid-now domain", function () {
    const values = [
      undefined, null, "1", 1n, NaN, Infinity, -Infinity, 0, -1, 1.5,
      Number.MAX_SAFE_INTEGER, 281474976710656
    ];
    for (const value of values) {
      expectAdapterCode(
        () => adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
          {},
          value
        ),
        C.STAGING_PROFILE_INVALID_NOW
      );
    }
  });

  it("AD-P6 rejects non-STAGING journals before profile delegation", function () {
    const scenario = buildScenario();
    const empty = journalReal.createGenesisStagingJournal(
      scenario.intent,
      scenario.now
    );
    const terminal = journalReal.cancelGenesisStagingJournal(
      empty,
      scenario.now + 1
    );
    withHarnesses(() => {
      expectAdapterCode(
        () => adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
          terminal,
          scenario.now + 1
        ),
        C.STAGING_PROFILE_JOURNAL_NOT_STAGING
      );
      assert.equal(protocolHarness.calls, 0);
    });
  });

  it("AD-P7 rejects incomplete manifests before profile delegation", function () {
    const scenario = buildScenario();
    const empty = journalReal.createGenesisStagingJournal(scenario.intent, scenario.now);
    withHarnesses(() => {
      expectAdapterCode(
        () => adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
          empty,
          scenario.now - 1
        ),
        C.STAGING_PROFILE_SLOTS_NOT_POPULATED
      );
      assert.equal(protocolHarness.calls, 0);
    });
  });

  it("AD-P8 rejects clock regression before profile delegation", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      expectAdapterCode(
        () => adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
          scenario.journal,
          scenario.validNow - 1
        ),
        C.STAGING_PROFILE_CLOCK_REGRESSION_DETECTED
      );
      assert.equal(protocolHarness.calls, 0);
    });
  });

  it("AD-P9 rejects expiry equality and later before profile delegation", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      for (const now of [
        Number(scenario.journal.expiresAt),
        Number(scenario.journal.expiresAt) + 1
      ]) {
        expectAdapterCode(
          () => adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
            scenario.journal,
            now
          ),
          C.STAGING_PROFILE_JOURNAL_EXPIRED
        );
      }
      assert.equal(protocolHarness.calls, 0);
    });
  });

  it("AD-P10 never inspects hostile thrown values or retains markers in owned errors", function () {
    let traps = 0;
    const hostileThrown = new Proxy({}, {
      get() { traps += 1; throw new Error("get trap"); },
      ownKeys() { traps += 1; throw new Error("ownKeys trap"); },
      getOwnPropertyDescriptor() { traps += 1; throw new Error("descriptor trap"); }
    });
    withHarnesses(() => {
      journalHarness.target = () => { throw hostileThrown; };
      let caught;
      try {
        adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile({}, 1);
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
      adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile({}, marker);
    } catch (error) {
      owned = error;
    }
    assert.equal(coercions, 0);
    for (const key of Object.getOwnPropertyNames(owned)) {
      assert.notEqual(Object.getOwnPropertyDescriptor(owned, key).value, marker);
    }
  });

  it("AD-P11 enforces domain separation, two imports, dormancy, and reference absence", function () {
    const adapterSource = fs.readFileSync(ADAPTER_PATH, "utf8");
    const imports = [...adapterSource.matchAll(/from\s+"([^"]+)"/g)]
      .map((match) => match[1]);
    assert.deepEqual(imports.sort(), [
      "./v2ConsumerRecoveryGenesisProtocol.ts",
      "./v2ConsumerRecoveryGenesisStagingJournal.ts"
    ].sort());
    for (const literal of [
      "node:fs", "node:path", "node:crypto", "process.", "ipcMain",
      "ipcRenderer", "contextBridge", "electron", "supersession",
      "deviceAdapter", "PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_TYPEHASH"
    ]) {
      assert.equal(adapterSource.includes(literal), false, literal);
    }

    const visited = new Set();
    function scanImports(file) {
      const resolved = path.resolve(file);
      if (visited.has(resolved)) return;
      visited.add(resolved);
      const source = fs.readFileSync(resolved, "utf8");
      for (const match of source.matchAll(/from\s+"(\.[^"]+)"/g)) {
        scanImports(path.resolve(path.dirname(resolved), match[1]));
      }
    }
    scanImports(ADAPTER_PATH);
    const graph = [...visited].join("\n");
    assert.equal(graph.includes("v2LocalCeremonyProtocol"), false);
    assert.equal(graph.includes("recovery-ceremony-host"), false);

    const forbiddenReferences = [];
    function scanReferencePath(target) {
      const stat = fs.statSync(target);
      if (stat.isDirectory()) {
        if (path.basename(target) === "release") return;
        for (const name of fs.readdirSync(target)) {
          scanReferencePath(path.join(target, name));
        }
      } else if (/\.(?:cjs|mjs|js|ts|tsx|html)$/.test(target)) {
        if (fs.readFileSync(target, "utf8").includes("v2ConsumerRecoveryGenesisStagingProfile")) {
          forbiddenReferences.push(path.relative(ROOT, target));
        }
      }
    }
    scanReferencePath(path.join(ROOT, "apps/philcore-desktop"));
    for (const candidate of [
      path.join(ROOT, "scripts/build-local.cjs"),
      path.join(ROOT, "build-local.cjs")
    ]) {
      if (fs.existsSync(candidate)) scanReferencePath(candidate);
    }
    assert.deepEqual(forbiddenReferences, []);
  });
});

describe("Dormant genesis staging profile composition — PF", function () {
  it("PF-P1 preserves projection and result across a JSON record round-trip", function () {
    const scenario = buildScenario();
    const parsed = JSON.parse(JSON.stringify(scenario.journal));
    let projectionR;
    let resultR;
    let projectionP;
    let resultP;
    withHarnesses(() => {
      resultR = adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        scenario.journal,
        scenario.validNow
      );
      projectionR = protocolHarness.captured[0];
    });
    withHarnesses(() => {
      resultP = adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        parsed,
        scenario.validNow
      );
      projectionP = protocolHarness.captured[0];
    });
    assert.deepEqual(projectionP, projectionR);
    assert.deepEqual(resultP, resultR);
  });

  it("PF-P2 validates through a fresh record without freezing or mutating caller input", function () {
    const scenario = buildScenario();
    const parsed = JSON.parse(JSON.stringify(scenario.journal));
    const before = JSON.stringify(parsed);
    assert.equal(Object.isFrozen(parsed), false);
    const result = adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
      parsed,
      scenario.validNow
    );
    assert.equal(Object.isFrozen(parsed), false);
    assert.equal(JSON.stringify(parsed), before);
    assert.notEqual(result, parsed);
  });

  it("PF-P3 agrees with pure expiry and terminal-state transitions", function () {
    const scenario = buildScenario();
    const R = scenario.journal;
    assert.doesNotThrow(() =>
      adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        R,
        Number(R.expiresAt) - 1
      )
    );
    const nowExpired = Number(R.expiresAt);
    const E = journalReal.expireGenesisStagingJournalIfNeeded(R, nowExpired);
    assert.equal(E.state, "EXPIRED");
    expectAdapterCode(
      () => adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        E,
        nowExpired
      ),
      C.STAGING_PROFILE_JOURNAL_NOT_STAGING
    );
    expectAdapterCode(
      () => adapter.validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
        R,
        nowExpired
      ),
      C.STAGING_PROFILE_JOURNAL_EXPIRED
    );
  });
});

after(function () {
  resetHarnesses();
  assertCacheWindowHygiene();
});
