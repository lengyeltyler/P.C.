require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { getAddress } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const OBLIGATION_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts"
);
const CLASSIFIER_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialOrphanClassification.ts"
);
const JOURNAL_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingJournal.ts"
);
const ADAPTER_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts"
);
const CLASSIFICATION_PATH = path.join(ROOT, "config/ci/classification.json");
const WINDOW_PATHS = Object.freeze([
  OBLIGATION_PATH,
  CLASSIFIER_PATH,
  JOURNAL_PATH,
  ADAPTER_PATH
]);
const initialCacheEntries = new Map(
  WINDOW_PATHS.map((modulePath) => [modulePath, require.cache[modulePath]])
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
  assert.ok(actual !== undefined, `${label} exports descriptor missing`);
  assertSameReference(actual.value, expected.value, `${label} exports value`);
  assert.equal(actual.writable, expected.writable);
  assert.equal(actual.enumerable, expected.enumerable);
  assert.equal(actual.configurable, expected.configurable);
}

function makeShim(real, wrappedKey, wrapper) {
  const shim = Object.create(null);
  for (const key of Object.keys(real)) shim[key] = real[key];
  shim[wrappedKey] = wrapper;
  return shim;
}

const obligationReal = require(OBLIGATION_PATH);
const journalReal = require(JOURNAL_PATH);
const classifierSeed = require(CLASSIFIER_PATH);
const adapterSeed = require(ADAPTER_PATH);
assertPristineNamespace(obligationReal);
assertPristineNamespace(journalReal);
assertPristineNamespace(classifierSeed);
assertPristineNamespace(adapterSeed);

const obligationModule = require.cache[OBLIGATION_PATH];
const journalModule = require.cache[JOURNAL_PATH];
const classifierSeedModule = require.cache[CLASSIFIER_PATH];
const adapterSeedModule = require.cache[ADAPTER_PATH];
const obligationDescriptor = Object.getOwnPropertyDescriptor(obligationModule, "exports");
const journalDescriptor = Object.getOwnPropertyDescriptor(journalModule, "exports");
const classifierDescriptor = Object.getOwnPropertyDescriptor(
  classifierSeedModule,
  "exports"
);
const cacheKeysBeforeWindows = new Set(Object.keys(require.cache));

const obligationHarness = {
  target: obligationReal.validatePhilCoreV2GenesisCredentialObligationRecord,
  calls: 0,
  lastArgs: null
};
const stableObligationWrapper = function (...args) {
  obligationHarness.calls += 1;
  obligationHarness.lastArgs = args;
  return obligationHarness.target(...args);
};
const obligationShim = makeShim(
  obligationReal,
  "validatePhilCoreV2GenesisCredentialObligationRecord",
  stableObligationWrapper
);

// Load a private classifier while the stable obligation wrapper is installed,
// then immediately restore the exact public cache entry and descriptor.
obligationModule.exports = obligationShim;
delete require.cache[CLASSIFIER_PATH];
const classifierPrivate = require(CLASSIFIER_PATH);
const classifierPrivateModule = require.cache[CLASSIFIER_PATH];
Object.defineProperty(obligationModule, "exports", obligationDescriptor);
require.cache[CLASSIFIER_PATH] = classifierSeedModule;

const classifierHarness = {
  target: classifierPrivate.classifyPhilCoreV2GenesisCredentialOrphan,
  calls: 0,
  lastArgs: null
};
const journalHarness = {
  target: journalReal.validateGenesisStagingJournalRecord,
  calls: 0,
  lastArgs: null
};
const stableClassifierWrapper = function (...args) {
  classifierHarness.calls += 1;
  classifierHarness.lastArgs = args;
  return classifierHarness.target(...args);
};
const stableJournalWrapper = function (...args) {
  journalHarness.calls += 1;
  journalHarness.lastArgs = args;
  return journalHarness.target(...args);
};
const classifierShim = makeShim(
  classifierSeed,
  "classifyPhilCoreV2GenesisCredentialOrphan",
  stableClassifierWrapper
);
const journalShim = makeShim(
  journalReal,
  "validateGenesisStagingJournalRecord",
  stableJournalWrapper
);

// Install both stable lower-authority wrappers before the adapter's private
// first require, independent of transpiler import capture behavior.
classifierSeedModule.exports = classifierShim;
journalModule.exports = journalShim;
delete require.cache[ADAPTER_PATH];
const adapter = require(ADAPTER_PATH);
const adapterPrivateModule = require.cache[ADAPTER_PATH];
const REQUIRE_TIME_COUNTS = Object.freeze({
  obligation: obligationHarness.calls,
  classifier: classifierHarness.calls,
  journal: journalHarness.calls
});
Object.defineProperty(classifierSeedModule, "exports", classifierDescriptor);
Object.defineProperty(journalModule, "exports", journalDescriptor);
const cacheKeysAddedByWindows = Object.freeze(
  Object.keys(require.cache).filter((key) => !cacheKeysBeforeWindows.has(key))
);
for (const modulePath of WINDOW_PATHS) {
  const initial = initialCacheEntries.get(modulePath);
  if (initial === undefined) {
    delete require.cache[modulePath];
  } else {
    require.cache[modulePath] = initial;
  }
}
const CACHE_RESTORATION_PROOF = Object.freeze(
  WINDOW_PATHS.map((modulePath) => {
    const initial = initialCacheEntries.get(modulePath);
    return initial === undefined
      ? !Object.prototype.hasOwnProperty.call(require.cache, modulePath)
      : require.cache[modulePath] === initial;
  })
);
assert.equal(CACHE_RESTORATION_PROOF.every(Boolean), true);

const protocol = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts"
);
const gateB = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts"
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
  buildO39ConsumerRecoveryFixturePackage
} = require("../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs");

const fixtures = buildO39ConsumerRecoveryFixturePackage();
const E =
  adapter.PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_ERROR_CODE;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const SIDE_ID = `0x${"e1".repeat(32)}`;
const SIDE_PUBLIC = `0x${"e2".repeat(32)}`;
const ALT_INTENT_ID = `0x${"e3".repeat(32)}`;
const ALT_INTENT_HASH = `0x${"e4".repeat(32)}`;

const ROOT_KEYS = Object.freeze([
  "schemaVersion", "formatProvenance", "projectionKind",
  "resolutionAuthority", "transitionAuthority", "intentId",
  "genesisDeploymentIntentHash", "role", "credentialGeneration",
  "bindingContext", "sidecarBinding", "manifestBinding", "mismatch"
]);
const CONTEXT_KEYS = Object.freeze([
  "ceremonyVersion", "ceremonyId", "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash", "manifestSlot", "journalState"
]);
const SIDECAR_KEYS = Object.freeze([
  "sourceAuthority", "sourceSchemaVersion", "sourceFormatProvenance",
  "orphanReason", "orphanCondition", "credentialKnowledge",
  "credentialIdHash", "publicVerificationMaterialHash"
]);
const MANIFEST_KEYS = Object.freeze([
  "sourceAuthority", "journalSchemaVersion", "journalFormatProvenance",
  "journalIntegrityChecksum", "factorCommitment", "stagedAtUnixSeconds",
  "descriptorVersion", "credentialGeneration", "credentialIdHash",
  "publicVerificationMaterialHash"
]);
const MISMATCH_KEYS = Object.freeze([
  "kind", "credentialIdHashDiffers", "publicVerificationMaterialHashDiffers"
]);
const ERROR_KEYS = Object.freeze([
  "MANIFEST_BINDING_CONFLICT_CONDITION_INVALID",
  "MANIFEST_BINDING_CONFLICT_SIDECAR_BINDING_UNAVAILABLE",
  "MANIFEST_BINDING_CONFLICT_JOURNAL_CONTEXT_MISMATCH",
  "MANIFEST_BINDING_CONFLICT_MANIFEST_ENTRY_MISSING",
  "MANIFEST_BINDING_CONFLICT_CEREMONY_CONTEXT_MISMATCH",
  "MANIFEST_BINDING_CONFLICT_BINDINGS_EQUAL",
  "MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION"
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
  obligationHarness.target =
    obligationReal.validatePhilCoreV2GenesisCredentialObligationRecord;
  obligationHarness.calls = 0;
  obligationHarness.lastArgs = null;
  classifierHarness.target =
    classifierPrivate.classifyPhilCoreV2GenesisCredentialOrphan;
  classifierHarness.calls = 0;
  classifierHarness.lastArgs = null;
  journalHarness.target = journalReal.validateGenesisStagingJournalRecord;
  journalHarness.calls = 0;
  journalHarness.lastArgs = null;
}

function withHarnesses(run) {
  resetHarnesses();
  try {
    return run();
  } finally {
    resetHarnesses();
  }
}

function assertCacheHygiene() {
  assert.equal(CACHE_RESTORATION_PROOF.every(Boolean), true);
  assertExportsDescriptor(obligationModule, obligationDescriptor, "obligation");
  assertExportsDescriptor(classifierSeedModule, classifierDescriptor, "classifier");
  assertExportsDescriptor(journalModule, journalDescriptor, "journal");
  assertSameReference(obligationModule.exports, obligationReal, "obligation exports");
  assertSameReference(classifierSeedModule.exports, classifierSeed, "classifier exports");
  assertSameReference(journalModule.exports, journalReal, "journal exports");
  assertSameReference(adapterSeedModule.exports, adapterSeed, "adapter exports");
  assert.ok(classifierPrivateModule !== classifierSeedModule);
  assert.ok(adapterPrivateModule !== adapterSeedModule);
  assertSameReference(classifierPrivateModule.exports, classifierPrivate, "private classifier");
  assertSameReference(adapterPrivateModule.exports, adapter, "private adapter");
  assert.deepEqual(cacheKeysAddedByWindows, []);
  assertPristineNamespace(obligationReal);
  assertPristineNamespace(classifierSeed);
  assertPristineNamespace(journalReal);
  assertPristineNamespace(adapterSeed);
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

function mintCeremony(intentHash, intentExpiresAt, role, ceremonyId, now) {
  return gateB.mintPhilCoreV2GenesisRoleCeremony({
    current: null,
    ceremonyId,
    role: BigInt(role),
    genesisDeploymentIntentHash: intentHash,
    intentExpiresAtUnixSeconds: BigInt(intentExpiresAt),
    nowUnixSeconds: now
  });
}

function buildScenario() {
  const now = 1000;
  const intent = validIntent();
  const intentHash = protocol.computePhilCoreV2LocalGenesisDeploymentIntentHash(intent);
  const ceremonyIds = [0, 1, 2].map(
    (role) => `0x${String(role + 1).padStart(2, "0")}${"a1".repeat(31)}`
  );
  const ceremonies = [0, 1, 2].map((role) =>
    mintCeremony(intentHash, intent.expiresAt, role, ceremonyIds[role], now)
  );
  const source = fixtures.profiles.standard.factors;
  const roleSources = [source.primary, source.secondary, source.offline];
  const factors = roleSources.map((base, role) => {
    const independence = {
      ...bigintFields(base.independence, INDEPENDENCE_NUMERIC_FIELDS),
      role: BigInt(role),
      enrollmentCeremonyHash: ceremonies[role].genesisEnrollmentCeremonyHash,
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
      {
        ...factors[role],
        currentRoleCeremony:
          gateB.toPhilCoreV2GenesisRoleCeremonyHashInput(ceremonies[role])
      },
      now + role + 1
    );
  }
  return { now, intent, intentHash, ceremonyIds, ceremonies, factors, journal };
}

function createOrphaned(
  scenario,
  role,
  mode = "both",
  options = {}
) {
  const entry = scenario.journal.manifest[String(role)];
  const ceremony = options.ceremony ?? scenario.ceremonies[role];
  const intentId = options.intentId ?? scenario.intent.intentId;
  const obligationNow = Number(ceremony.mintedAtUnixSeconds);
  let current = obligationReal.createPhilCoreV2GenesisCredentialObligation({
    ceremony,
    intentId,
    nowUnixSeconds: obligationNow
  });
  current = obligationReal.authorizePhilCoreV2GenesisCredentialCreation({
    current,
    expectedCeremonyId: current.ceremonyId,
    nowUnixSeconds: obligationNow + 1
  });
  if (!options.unknown) {
    const credentialIdHash = role === 2
      ? ZERO_BYTES32
      : mode === "public" || mode === "equal"
        ? entry.descriptor.credentialIdHash
        : SIDE_ID;
    const publicVerificationMaterialHash = mode === "id" || mode === "equal"
      ? entry.descriptor.publicVerificationMaterialHash
      : SIDE_PUBLIC;
    current = obligationReal.recordPhilCoreV2GenesisCreatedCredential({
      current,
      expectedCeremonyId: current.ceremonyId,
      credentialIdHash,
      publicVerificationMaterialHash,
      nowUnixSeconds: obligationNow + 2
    });
  }
  return obligationReal.orphanPhilCoreV2GenesisCredentialObligation({
    current,
    reason: options.reason ?? "RECORDED_CREDENTIAL_MISMATCH",
    nowUnixSeconds: obligationNow + 3
  });
}

function journalWithOnlySlotZero(scenario) {
  const empty = journalReal.createGenesisStagingJournal(
    scenario.intent,
    scenario.now
  );
  return journalReal.stageGenesisRoleCandidate(
    empty,
    0,
    {
      ...scenario.factors[0],
      currentRoleCeremony:
        gateB.toPhilCoreV2GenesisRoleCeremonyHashInput(scenario.ceremonies[0])
    },
    scenario.now + 1
  );
}

function expectCode(run, code) {
  let thrown;
  try {
    run();
  } catch (error) {
    thrown = error;
  }
  assert.ok(
    thrown instanceof adapter.PhilCoreV2GenesisManifestBindingConflictProjectionError,
    `expected branded ${code}`
  );
  assert.equal(thrown.code, code);
  assert.equal(Object.prototype.hasOwnProperty.call(thrown, "cause"), false);
  assert.deepEqual(
    Reflect.ownKeys(thrown).filter((key) => key !== "stack").sort(),
    ["code", "message", "name"]
  );
  return thrown;
}

function project(scenario, role, mode = "both", options = {}) {
  const obligation = createOrphaned(scenario, role, mode, options);
  return adapter.projectPhilCoreV2GenesisManifestBindingConflict(
    obligation,
    options.journal ?? scenario.journal
  );
}

function cloneClassification(value, overrides = {}) {
  return Object.freeze(Object.assign(Object.create(null), value, overrides));
}

function cloneJournalWithEntry(record, role, entry) {
  return {
    ...record,
    manifest: { ...record.manifest, [String(role)]: entry }
  };
}

function alternateCeremony(scenario, role, overrides = {}) {
  return mintCeremony(
    overrides.intentHash ?? scenario.intentHash,
    scenario.intent.expiresAt,
    role,
    overrides.ceremonyId ?? scenario.ceremonyIds[role],
    overrides.now ?? scenario.now
  );
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

beforeEach(resetHarnesses);

describe("Dormant genesis manifest-binding conflict projection", function () {
  it("CP01: role-0 conflict where only credential ID differs", function () {
    const result = project(buildScenario(), 0, "id");
    assert.equal(result.mismatch.kind, "CREDENTIAL_BINDING_MISMATCH");
    assert.equal(result.mismatch.credentialIdHashDiffers, true);
    assert.equal(result.mismatch.publicVerificationMaterialHashDiffers, false);
  });

  it("CP02: role-0 conflict where only public material differs", function () {
    const result = project(buildScenario(), 0, "public");
    assert.equal(result.mismatch.credentialIdHashDiffers, false);
    assert.equal(result.mismatch.publicVerificationMaterialHashDiffers, true);
  });

  it("CP03: role-0 conflict where both fields differ", function () {
    const result = project(buildScenario(), 0, "both");
    assert.equal(result.mismatch.credentialIdHashDiffers, true);
    assert.equal(result.mismatch.publicVerificationMaterialHashDiffers, true);
  });

  it("CP04: role-1 preserves carrier-undetermined knowledge without choosing a carrier", function () {
    const result = project(buildScenario(), 1, "both");
    assert.equal(
      result.sidecarBinding.credentialKnowledge,
      "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED"
    );
    assert.equal(result.resolutionAuthority, "NONE");
    assert.equal(JSON.stringify(result).includes("carrier"), false);
  });

  it("CP05: role-2 preserves zero credential-ID sentinel and only public mismatch", function () {
    const result = project(buildScenario(), 2, "both");
    assert.equal(result.sidecarBinding.credentialIdHash, ZERO_BYTES32);
    assert.equal(result.manifestBinding.credentialIdHash, ZERO_BYTES32);
    assert.equal(result.mismatch.credentialIdHashDiffers, false);
    assert.equal(result.mismatch.publicVerificationMaterialHashDiffers, true);
  });

  it("CP06: all four journal states are accepted as historical facts", function () {
    const scenario = buildScenario();
    const states = [
      scenario.journal,
      journalReal.cancelGenesisStagingJournal(scenario.journal, scenario.now + 4),
      journalReal.expireGenesisStagingJournalIfNeeded(
        scenario.journal,
        Number(scenario.intent.expiresAt)
      ),
      journalReal.supersedeGenesisStagingJournal(scenario.journal, scenario.now + 4)
    ];
    assert.deepEqual(states.map((record) => record.state), [
      "STAGING", "CANCELLED", "EXPIRED", "SUPERSEDED"
    ]);
    const obligation = createOrphaned(scenario, 0, "both");
    for (const record of states) {
      const result = adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        obligation,
        record
      );
      assert.equal(result.bindingContext.journalState, record.state);
      assert.equal(Object.prototype.hasOwnProperty.call(result, "freshness"), false);
    }
  });

  it("CP07: exact key orders and null prototypes", function () {
    const result = project(buildScenario(), 0, "both");
    assert.deepEqual(Object.keys(result), ROOT_KEYS);
    assert.deepEqual(Object.keys(result.bindingContext), CONTEXT_KEYS);
    assert.deepEqual(Object.keys(result.sidecarBinding), SIDECAR_KEYS);
    assert.deepEqual(Object.keys(result.manifestBinding), MANIFEST_KEYS);
    assert.deepEqual(Object.keys(result.mismatch), MISMATCH_KEYS);
    for (const value of [
      result,
      result.bindingContext,
      result.sidecarBinding,
      result.manifestBinding,
      result.mismatch
    ]) assert.equal(Object.getPrototypeOf(value), null);
  });

  it("CP08: exact provenance and frozen vocabulary literals", function () {
    const result = project(buildScenario(), 0, "both");
    assert.equal(result.schemaVersion, 1);
    assert.equal(
      result.formatProvenance,
      "PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_V1"
    );
    assert.equal(result.projectionKind, "FACTUAL_CONFLICT_ONLY");
    assert.equal(result.resolutionAuthority, "NONE");
    assert.equal(result.transitionAuthority, "NONE");
    assert.equal(
      result.sidecarBinding.sourceAuthority,
      "GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION"
    );
    assert.equal(
      result.manifestBinding.sourceAuthority,
      "GENESIS_STAGING_JOURNAL_MANIFEST_ENTRY"
    );
    const tables = [
      adapter.PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_KIND,
      adapter.PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_AUTHORITY,
      adapter.PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_SOURCE_AUTHORITY,
      adapter.PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_MISMATCH_KIND,
      E
    ];
    for (const table of tables) assert.equal(Object.isFrozen(table), true);
    assert.deepEqual(Object.keys(E), ERROR_KEYS);
    for (const key of ERROR_KEYS) assert.equal(E[key], key);
  });

  it("CP09: exactly five result containers are deeply frozen", function () {
    const result = project(buildScenario(), 0, "both");
    const references = [...allObjectReferences(result)];
    assert.equal(references.length, 5);
    for (const value of references) assert.equal(Object.isFrozen(value), true);
  });

  it("CP10: no mutation and repeated calls are byte-equivalent with distinct containers", function () {
    const scenario = buildScenario();
    const obligation = createOrphaned(scenario, 0, "both");
    const beforeObligation = JSON.stringify(obligation);
    const beforeJournal = JSON.stringify(scenario.journal);
    const first = adapter.projectPhilCoreV2GenesisManifestBindingConflict(
      obligation,
      scenario.journal
    );
    const second = adapter.projectPhilCoreV2GenesisManifestBindingConflict(
      obligation,
      scenario.journal
    );
    assert.equal(JSON.stringify(obligation), beforeObligation);
    assert.equal(JSON.stringify(scenario.journal), beforeJournal);
    assert.deepEqual(second, first);
    assert.notEqual(second, first);
    assert.notEqual(second.bindingContext, first.bindingContext);
  });

  it("CP11: classifier direct delegation count is exactly one", function () {
    const scenario = buildScenario();
    const obligation = createOrphaned(scenario, 0, "both");
    withHarnesses(() => {
      adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        obligation,
        scenario.journal
      );
      assert.equal(classifierHarness.calls, 1);
      assert.equal(classifierHarness.lastArgs.length, 1);
      assert.equal(classifierHarness.lastArgs[0], obligation);
    });
  });

  it("CP12: journal-validator direct delegation count is exactly one", function () {
    const scenario = buildScenario();
    withHarnesses(() => {
      adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        createOrphaned(scenario, 0, "both"),
        scenario.journal
      );
      assert.equal(journalHarness.calls, 1);
      assert.equal(journalHarness.lastArgs.length, 1);
      assert.equal(journalHarness.lastArgs[0], scenario.journal);
    });
  });

  it("CP13: real path transitively calls the obligation validator once and not directly", function () {
    const scenario = buildScenario();
    const obligation = createOrphaned(scenario, 0, "both");
    withHarnesses(() => {
      adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        obligation,
        scenario.journal
      );
      assert.equal(classifierHarness.calls, 1);
      assert.equal(obligationHarness.calls, 1);
      assert.equal(obligationHarness.lastArgs[0], obligation);
      const source = fs.readFileSync(ADAPTER_PATH, "utf8");
      assert.equal(
        source.includes("validatePhilCoreV2GenesisCredentialObligationRecord"),
        false
      );
    });
  });

  it("CP14: classifier and lower-obligation errors rethrow by exact identity", function () {
    const scenario = buildScenario();
    const classifierMarker = Object.freeze({ marker: "classifier" });
    withHarnesses(() => {
      classifierHarness.target = () => { throw classifierMarker; };
      let caught;
      try {
        adapter.projectPhilCoreV2GenesisManifestBindingConflict({}, scenario.journal);
      } catch (error) { caught = error; }
      assert.equal(caught, classifierMarker);
      assert.equal(journalHarness.calls, 0);
    });
    const obligationMarker = Object.freeze({ marker: "obligation" });
    withHarnesses(() => {
      obligationHarness.target = () => { throw obligationMarker; };
      let caught;
      try {
        adapter.projectPhilCoreV2GenesisManifestBindingConflict({}, scenario.journal);
      } catch (error) { caught = error; }
      assert.equal(caught, obligationMarker);
      assert.equal(classifierHarness.calls, 1);
      assert.equal(journalHarness.calls, 0);
    });
  });

  it("CP15: journal-validator errors rethrow by exact identity", function () {
    const scenario = buildScenario();
    const marker = Object.freeze({ marker: "journal" });
    withHarnesses(() => {
      journalHarness.target = () => { throw marker; };
      let caught;
      try {
        adapter.projectPhilCoreV2GenesisManifestBindingConflict(
          createOrphaned(scenario, 0, "both"),
          scenario.journal
        );
      } catch (error) { caught = error; }
      assert.equal(caught, marker);
      assert.equal(classifierHarness.calls, 1);
      assert.equal(journalHarness.calls, 1);
    });
  });

  it("CP16: non-conflict orphan fails before journal inspection", function () {
    const scenario = buildScenario();
    const obligation = createOrphaned(scenario, 0, "both", {
      reason: "RESTART_DURING_CREATION"
    });
    withHarnesses(() => {
      expectCode(
        () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
          obligation,
          new Proxy({}, { ownKeys() { throw new Error("journal inspected"); } })
        ),
        E.MANIFEST_BINDING_CONFLICT_CONDITION_INVALID
      );
      assert.equal(journalHarness.calls, 0);
    });
  });

  it("CP17: lower-valid unknown-sidecar mismatch fails before journal inspection", function () {
    const scenario = buildScenario();
    const obligation = createOrphaned(scenario, 0, "both", { unknown: true });
    withHarnesses(() => {
      expectCode(
        () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
          obligation,
          new Proxy({}, { ownKeys() { throw new Error("journal inspected"); } })
        ),
        E.MANIFEST_BINDING_CONFLICT_SIDECAR_BINDING_UNAVAILABLE
      );
      assert.equal(journalHarness.calls, 0);
    });
  });

  it("CP18: intent-ID then deployment-intent-hash mismatches map to context error", function () {
    const scenario = buildScenario();
    const intentMismatch = createOrphaned(scenario, 0, "both", {
      intentId: ALT_INTENT_ID
    });
    expectCode(
      () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        intentMismatch,
        scenario.journal
      ),
      E.MANIFEST_BINDING_CONFLICT_JOURNAL_CONTEXT_MISMATCH
    );
    const otherCeremony = alternateCeremony(scenario, 0, {
      intentHash: ALT_INTENT_HASH
    });
    const hashMismatch = createOrphaned(scenario, 0, "both", {
      ceremony: otherCeremony
    });
    expectCode(
      () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        hashMismatch,
        scenario.journal
      ),
      E.MANIFEST_BINDING_CONFLICT_JOURNAL_CONTEXT_MISMATCH
    );
  });

  it("CP19: missing selected role slot fails while another slot is populated", function () {
    const scenario = buildScenario();
    const prefixJournal = journalWithOnlySlotZero(scenario);
    assert.notEqual(prefixJournal.manifest["0"], null);
    assert.equal(prefixJournal.manifest["1"], null);
    expectCode(
      () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        createOrphaned(scenario, 1, "both"),
        prefixJournal
      ),
      E.MANIFEST_BINDING_CONFLICT_MANIFEST_ENTRY_MISSING
    );
  });

  it("CP20: genuine ceremony ID/expiry and seam-only hash mismatches map to ceremony error", function () {
    const scenario = buildScenario();
    const idMismatch = createOrphaned(scenario, 0, "both", {
      ceremony: alternateCeremony(scenario, 0, {
        ceremonyId: `0x${"f1".repeat(32)}`
      })
    });
    expectCode(
      () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        idMismatch,
        scenario.journal
      ),
      E.MANIFEST_BINDING_CONFLICT_CEREMONY_CONTEXT_MISMATCH
    );
    const expiryMismatch = createOrphaned(scenario, 0, "both", {
      ceremony: alternateCeremony(scenario, 0, { now: scenario.now + 1 })
    });
    expectCode(
      () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        expiryMismatch,
        scenario.journal
      ),
      E.MANIFEST_BINDING_CONFLICT_CEREMONY_CONTEXT_MISMATCH
    );
    const obligation = createOrphaned(scenario, 0, "both");
    withHarnesses(() => {
      const classified = classifierPrivate.classifyPhilCoreV2GenesisCredentialOrphan(
        obligation
      );
      classifierHarness.target = () => cloneClassification(classified, {
        genesisEnrollmentCeremonyHash: `0x${"f2".repeat(32)}`
      });
      expectCode(
        () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
          obligation,
          scenario.journal
        ),
        E.MANIFEST_BINDING_CONFLICT_CEREMONY_CONTEXT_MISMATCH
      );
    });
  });

  it("CP21: seam-only role/version/generation/slot invariants map to invariant error", function () {
    const scenario = buildScenario();
    const obligation = createOrphaned(scenario, 0, "both");
    const classified = classifierPrivate.classifyPhilCoreV2GenesisCredentialOrphan(
      obligation
    );
    for (const overrides of [
      { role: "9" },
      { ceremonyVersion: "2" },
      { credentialGeneration: "2" }
    ]) {
      withHarnesses(() => {
        classifierHarness.target = () => cloneClassification(classified, overrides);
        expectCode(
          () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
            obligation,
            scenario.journal
          ),
          E.MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION
        );
      });
    }
    const entry = scenario.journal.manifest["0"];
    for (const replacement of [
      { ...entry, role: "1" },
      { ...entry, descriptor: { ...entry.descriptor, credentialGeneration: "2" } },
      { ...entry, independence: { ...entry.independence, credentialGeneration: "2" } }
    ]) {
      withHarnesses(() => {
        journalHarness.target = () =>
          cloneJournalWithEntry(scenario.journal, 0, replacement);
        expectCode(
          () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
            obligation,
            scenario.journal
          ),
          E.MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION
        );
      });
    }
  });

  it("CP22: equal bindings are rejected despite the mismatch reason", function () {
    const scenario = buildScenario();
    expectCode(
      () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        createOrphaned(scenario, 0, "equal"),
        scenario.journal
      ),
      E.MANIFEST_BINDING_CONFLICT_BINDINGS_EQUAL
    );
  });

  it("CP23: three reachable inequality rows emit exact flags", function () {
    const scenario = buildScenario();
    const rows = [
      ["id", true, false],
      ["public", false, true],
      ["both", true, true]
    ];
    for (const [mode, idDiffers, publicDiffers] of rows) {
      const result = project(scenario, 0, mode);
      assert.equal(result.mismatch.credentialIdHashDiffers, idDiffers);
      assert.equal(
        result.mismatch.publicVerificationMaterialHashDiffers,
        publicDiffers
      );
    }
    expectCode(
      () => project(scenario, 0, "equal"),
      E.MANIFEST_BINDING_CONFLICT_BINDINGS_EQUAL
    );
  });

  it("CP24: hostile obligation is passed directly without preinspection", function () {
    const scenario = buildScenario();
    const real = classifierPrivate.classifyPhilCoreV2GenesisCredentialOrphan(
      createOrphaned(scenario, 0, "both")
    );
    let traps = 0;
    const hostile = new Proxy({}, {
      get() { traps += 1; throw new Error("get"); },
      ownKeys() { traps += 1; throw new Error("ownKeys"); },
      getOwnPropertyDescriptor() { traps += 1; throw new Error("descriptor"); }
    });
    withHarnesses(() => {
      classifierHarness.target = (value) => {
        assert.equal(value, hostile);
        return real;
      };
      adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        hostile,
        scenario.journal
      );
      assert.equal(traps, 0);
      assert.equal(classifierHarness.calls, 1);
    });
  });

  it("CP25: hostile journal remains untouched on both early exits", function () {
    const scenario = buildScenario();
    let traps = 0;
    const hostileJournal = new Proxy({}, {
      get() { traps += 1; throw new Error("get"); },
      ownKeys() { traps += 1; throw new Error("ownKeys"); },
      getOwnPropertyDescriptor() { traps += 1; throw new Error("descriptor"); }
    });
    for (const obligation of [
      createOrphaned(scenario, 0, "both", {
        reason: "RESTART_DURING_CREATION"
      }),
      createOrphaned(scenario, 0, "both", { unknown: true })
    ]) {
      withHarnesses(() => {
        try {
          adapter.projectPhilCoreV2GenesisManifestBindingConflict(
            obligation,
            hostileJournal
          );
        } catch {}
        assert.equal(journalHarness.calls, 0);
        assert.equal(traps, 0);
      });
    }
  });

  it("CP26: branding cannot be forged and hostile internal causes are discarded", function () {
    const forged = Object.create(
      adapter.PhilCoreV2GenesisManifestBindingConflictProjectionError.prototype
    );
    assert.equal(
      forged instanceof adapter.PhilCoreV2GenesisManifestBindingConflictProjectionError,
      false
    );
    const scenario = buildScenario();
    const obligation = createOrphaned(scenario, 0, "both");
    const classified = classifierPrivate.classifyPhilCoreV2GenesisCredentialOrphan(
      obligation
    );
    const marker = Object.freeze({ marker: "discard-me" });
    const hostileClassification = Object.assign(Object.create(null), classified);
    Object.defineProperty(hostileClassification, "intentId", {
      enumerable: true,
      get() { throw marker; }
    });
    withHarnesses(() => {
      classifierHarness.target = () => hostileClassification;
      const thrown = expectCode(
        () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
          obligation,
          scenario.journal
        ),
        E.MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION
      );
      assert.notEqual(thrown, marker);
      assert.equal(JSON.stringify(thrown).includes("discard-me"), false);
    });
  });

  it("CP27: real roles 0/1/2 produce only source-consistent facts", function () {
    const scenario = buildScenario();
    for (const role of [0, 1, 2]) {
      const obligation = createOrphaned(scenario, role, "both");
      const classification = classifierSeed.classifyPhilCoreV2GenesisCredentialOrphan(
        obligation
      );
      const journal = journalReal.validateGenesisStagingJournalRecord(scenario.journal);
      const entry = journal.manifest[String(role)];
      const result = adapter.projectPhilCoreV2GenesisManifestBindingConflict(
        obligation,
        scenario.journal
      );
      assert.equal(result.intentId, classification.intentId);
      assert.equal(result.role, classification.role);
      assert.equal(result.bindingContext.manifestSlot, String(role));
      assert.equal(result.sidecarBinding.credentialIdHash, classification.credentialIdHash);
      assert.equal(result.manifestBinding.credentialIdHash, entry.descriptor.credentialIdHash);
      assert.equal(result.manifestBinding.factorCommitment, entry.factorCommitment);
      assert.equal(result.manifestBinding.journalIntegrityChecksum, journal.integrityChecksum);
    }
  });

  it("CP28: require-time dormancy and exact cache-window hygiene", function () {
    assert.deepEqual(REQUIRE_TIME_COUNTS, {
      obligation: 0,
      classifier: 0,
      journal: 0
    });
    assertCacheHygiene();
  });

  it("CP29: exact reference set, split source exclusions, graph dormancy, and classification total 114", function () {
    const source = fs.readFileSync(ADAPTER_PATH, "utf8");
    const imports = [...source.matchAll(/\bfrom\s+["'](\.[^"']+)["']/g)]
      .map((match) => match[1]);
    assert.deepEqual(imports, [
      "./v2ConsumerRecoveryGenesisCredentialOrphanClassification.ts",
      "./v2ConsumerRecoveryGenesisStagingJournal.ts"
    ]);
    for (const literal of [
      "node:fs", "node:path", "node:crypto", "node:net", "ipcMain",
      "ipcRenderer", "contextBridge", "electron", "recovery-genesis-staging-host",
      "recovery-genesis-coordinator", "v2ConsumerRecoveryGenesisStagingProfile",
      "v2ConsumerRecoveryGenesisFinalizedProfile", "v2LocalCeremonyProtocol",
      "deviceAdapter", "secret", "sepolia"
    ]) assert.equal(source.includes(literal), false, literal);

    const visited = new Set();
    function scanImports(file) {
      const resolved = path.resolve(file);
      if (visited.has(resolved)) return;
      visited.add(resolved);
      const text = fs.readFileSync(resolved, "utf8");
      for (const match of text.matchAll(/\bfrom\s+["'](\.[^"']+)["']/g)) {
        scanImports(path.resolve(path.dirname(resolved), match[1]));
      }
    }
    scanImports(ADAPTER_PATH);
    const graph = [...visited].map((file) => path.relative(ROOT, file)).join("\n");
    assert.ok(graph.includes("v2ConsumerRecoveryGenesisCredentialOrphanClassification.ts"));
    assert.ok(graph.includes("v2ConsumerRecoveryGenesisStagingJournal.ts"));
    for (const forbidden of [
      "recovery-genesis-staging-host", "recovery-genesis-coordinator",
      "v2ConsumerRecoveryGenesisStagingProfile",
      "v2ConsumerRecoveryGenesisFinalizedProfile", "v2LocalCeremonyProtocol"
    ]) assert.equal(graph.includes(forbidden), false, forbidden);

    const needle = "v2ConsumerRecoveryGenesisCredentialOrphanClassification";
    const hits = [];
    const skip = new Set([".git", "node_modules", "artifacts", "cache", "dist", "build", "coverage", "release", "target"]);
    function scanTree(target) {
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) return;
      if (stat.isDirectory()) {
        if (skip.has(path.basename(target))) return;
        for (const name of fs.readdirSync(target)) scanTree(path.join(target, name));
        return;
      }
      if (!/\.(?:cjs|mjs|js|ts|tsx|json|html|yml|yaml|md)$/.test(target)) return;
      const relative = path.relative(ROOT, target);
      const text = fs.readFileSync(target, "utf8");
      if (relative.includes(needle) || text.includes(needle)) hits.push(relative);
    }
    scanTree(ROOT);
    assert.deepEqual(hits.sort(), [
      "apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialOrphanClassification.ts",
      "apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts",
      "config/ci/classification.json",
      "test/unit/v2ConsumerRecoveryGenesisCredentialOrphanClassification.test.cjs",
      "test/unit/v2ConsumerRecoveryGenesisManifestBindingConflictProjection.test.cjs"
    ].sort());
    const classification = JSON.parse(fs.readFileSync(CLASSIFICATION_PATH, "utf8"));
    assert.equal(classification.totals.required_product_runtime, 114);
    assert.ok(classification.items.some((item) =>
      item.id === "unit:v2ConsumerRecoveryGenesisManifestBindingConflictProjection.test.cjs"
      && item.lane === "required_product_runtime"
    ));
  });

  it("CP30: bounded named harness kills all twelve architecture mutants", function () {
    const scenario = buildScenario();
    const kills = Object.freeze({
      M01() {
        withHarnesses(() => {
          project(scenario, 0, "both");
          assert.equal(classifierHarness.calls, 1);
          assert.equal(obligationHarness.calls, 1);
        });
      },
      M02() {
        expectCode(
          () => project(scenario, 0, "both", {
            reason: "RESTART_DURING_CREATION"
          }),
          E.MANIFEST_BINDING_CONFLICT_CONDITION_INVALID
        );
      },
      M03() {
        expectCode(
          () => project(scenario, 0, "both", { unknown: true }),
          E.MANIFEST_BINDING_CONFLICT_SIDECAR_BINDING_UNAVAILABLE
        );
      },
      M04() {
        let traps = 0;
        const hostile = new Proxy({}, { get() { traps += 1; throw new Error("read"); } });
        withHarnesses(() => {
          try {
            adapter.projectPhilCoreV2GenesisManifestBindingConflict(
              createOrphaned(scenario, 0, "both", {
                reason: "RESTART_DURING_CREATION"
              }),
              hostile
            );
          } catch {}
          assert.equal(traps, 0);
          assert.equal(journalHarness.calls, 0);
        });
      },
      M05() {
        withHarnesses(() => {
          project(scenario, 0, "both");
          assert.equal(journalHarness.calls, 1);
        });
      },
      M06() {
        const prefix = journalWithOnlySlotZero(scenario);
        const roleOneObligation = createOrphaned(scenario, 1, "both");
        expectCode(
          () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
            roleOneObligation,
            prefix
          ),
          E.MANIFEST_BINDING_CONFLICT_MANIFEST_ENTRY_MISSING
        );
        const roleMatchingSeamEntry = {
          ...prefix.manifest["0"],
          role: "1"
        };
        withHarnesses(() => {
          journalHarness.target = () =>
            cloneJournalWithEntry(prefix, 0, roleMatchingSeamEntry);
          expectCode(
            () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
              roleOneObligation,
              prefix
            ),
            E.MANIFEST_BINDING_CONFLICT_MANIFEST_ENTRY_MISSING
          );
        });
      },
      M07() {
        const mismatch = createOrphaned(scenario, 0, "both", {
          ceremony: alternateCeremony(scenario, 0, {
            ceremonyId: `0x${"f3".repeat(32)}`
          })
        });
        expectCode(
          () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
            mismatch,
            scenario.journal
          ),
          E.MANIFEST_BINDING_CONFLICT_CEREMONY_CONTEXT_MISMATCH
        );
      },
      M08() {
        const equal = createOrphaned(scenario, 0, "equal");
        const entry = scenario.journal.manifest["0"];
        const impossibleEntry = {
          ...entry,
          independence: { ...entry.independence, credentialIdHash: SIDE_ID }
        };
        withHarnesses(() => {
          journalHarness.target = () =>
            cloneJournalWithEntry(scenario.journal, 0, impossibleEntry);
          expectCode(
            () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
              equal,
              scenario.journal
            ),
            E.MANIFEST_BINDING_CONFLICT_BINDINGS_EQUAL
          );
        });
      },
      M09() {
        const result = project(scenario, 2, "both");
        assert.equal(result.sidecarBinding.credentialIdHash, ZERO_BYTES32);
      },
      M10() {
        expectCode(
          () => project(scenario, 0, "equal"),
          E.MANIFEST_BINDING_CONFLICT_BINDINGS_EQUAL
        );
      },
      M11() {
        const result = project(scenario, 0, "both");
        assert.equal(result.resolutionAuthority, "NONE");
        assert.equal(result.transitionAuthority, "NONE");
        assert.equal([...allObjectReferences(result)].every(Object.isFrozen), true);
      },
      M12() {
        const marker = Object.freeze({ marker: "hostile" });
        const obligation = createOrphaned(scenario, 0, "both");
        const classified = classifierPrivate.classifyPhilCoreV2GenesisCredentialOrphan(
          obligation
        );
        const hostile = Object.assign(Object.create(null), classified);
        Object.defineProperty(hostile, "intentId", {
          enumerable: true,
          get() { throw marker; }
        });
        withHarnesses(() => {
          classifierHarness.target = () => hostile;
          const thrown = expectCode(
            () => adapter.projectPhilCoreV2GenesisManifestBindingConflict(
              obligation,
              scenario.journal
            ),
            E.MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION
          );
          assert.notEqual(thrown, marker);
        });
      }
    });
    assert.deepEqual(Object.keys(kills), [
      "M01", "M02", "M03", "M04", "M05", "M06",
      "M07", "M08", "M09", "M10", "M11", "M12"
    ]);
    for (const kill of Object.values(kills)) kill();
  });
});

after(function () {
  resetHarnesses();
  assertCacheHygiene();
});
