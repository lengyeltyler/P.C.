require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { getAddress } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const OBLIGATION_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts"
);
const JOURNAL_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingJournal.ts"
);
const PROJECTION_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts"
);
const VALIDATOR_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisConflictEvidenceValidation.ts"
);
const CLASSIFICATION_PATH = path.join(ROOT, "config/ci/classification.json");
const WINDOW_PATHS = Object.freeze([PROJECTION_PATH, VALIDATOR_PATH]);
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
const projectionSeed = require(PROJECTION_PATH);
const validatorSeed = require(VALIDATOR_PATH);
assertPristineNamespace(obligationReal);
assertPristineNamespace(journalReal);
assertPristineNamespace(projectionSeed);
assertPristineNamespace(validatorSeed);

const projectionModule = require.cache[PROJECTION_PATH];
const validatorSeedModule = require.cache[VALIDATOR_PATH];
const projectionDescriptor = Object.getOwnPropertyDescriptor(
  projectionModule,
  "exports"
);
const cacheKeysBeforeWindows = new Set(Object.keys(require.cache));

const projectionHarness = {
  target: projectionSeed.projectPhilCoreV2GenesisManifestBindingConflict,
  calls: 0,
  lastArgs: null
};
const stableProjectionWrapper = function (...args) {
  projectionHarness.calls += 1;
  projectionHarness.lastArgs = args;
  return projectionHarness.target(...args);
};
const projectionShim = makeShim(
  projectionSeed,
  "projectPhilCoreV2GenesisManifestBindingConflict",
  stableProjectionWrapper
);

projectionModule.exports = projectionShim;
delete require.cache[VALIDATOR_PATH];
const adapter = require(VALIDATOR_PATH);
const validatorPrivateModule = require.cache[VALIDATOR_PATH];
const REQUIRE_TIME_COUNTS = Object.freeze({
  projection: projectionHarness.calls
});
Object.defineProperty(projectionModule, "exports", projectionDescriptor);
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
const E = adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_ERROR_CODE;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const SIDE_ID = `0x${"e1".repeat(32)}`;
const SIDE_PUBLIC = `0x${"e2".repeat(32)}`;
const CHALLENGE = `0x${"c1".repeat(32)}`;
const ALT_HASH = `0x${"c2".repeat(32)}`;
const ALT_HASH_2 = `0x${"c3".repeat(32)}`;

const ENVELOPE_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "challengeReference",
  "challengeBindingHash",
  "issuedAtUnixSeconds",
  "expiresAtUnixSeconds",
  "intentId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "journalIntegrityChecksum",
  "journalState",
  "sidecarCredentialIdHash",
  "sidecarPublicVerificationMaterialHash",
  "manifestCredentialIdHash",
  "manifestPublicVerificationMaterialHash"
]);
const BINDING_KEYS = Object.freeze([
  "intentId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "journalIntegrityChecksum",
  "journalState",
  "sidecarCredentialIdHash",
  "sidecarPublicVerificationMaterialHash",
  "manifestCredentialIdHash",
  "manifestPublicVerificationMaterialHash",
  "challengeReference",
  "issuedAtUnixSeconds",
  "expiresAtUnixSeconds"
]);
const OUTPUT_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "validationKind",
  "resolutionAuthority",
  "transitionAuthority",
  "possessionAuthority",
  "replayStateAuthority",
  "signatureAuthority",
  "providerAuthority",
  "replayStoreConsulted",
  "verifiedPossession",
  "verifiedSignature",
  "trustedProvider",
  "intentId",
  "genesisDeploymentIntentHash",
  "role",
  "challengeReference",
  "challengeBindingHash",
  "issuedAtUnixSeconds",
  "expiresAtUnixSeconds",
  "validatedAtUnixSeconds",
  "ceremonyExpiresAtUnixSeconds",
  "journalIntegrityChecksum",
  "sidecarCredentialIdHash",
  "manifestCredentialIdHash",
  "freshnessOutcome"
]);
const IDENTITY_MISMATCH_FIELDS = Object.freeze([
  ["intentId", ALT_HASH],
  ["genesisDeploymentIntentHash", ALT_HASH],
  ["role", "1"],
  ["ceremonyId", ALT_HASH],
  ["ceremonyExpiresAtUnixSeconds", "123456"],
  ["genesisEnrollmentCeremonyHash", ALT_HASH],
  ["journalIntegrityChecksum", ALT_HASH],
  ["journalState", "CANCELLED"],
  ["sidecarCredentialIdHash", ALT_HASH],
  ["sidecarPublicVerificationMaterialHash", ALT_HASH],
  ["manifestCredentialIdHash", ALT_HASH],
  ["manifestPublicVerificationMaterialHash", ALT_HASH]
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
  projectionHarness.target =
    projectionSeed.projectPhilCoreV2GenesisManifestBindingConflict;
  projectionHarness.calls = 0;
  projectionHarness.lastArgs = null;
}

function withHarnesses(run) {
  resetHarnesses();
  try {
    return run();
  } finally {
    resetHarnesses();
  }
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

function createOrphaned(scenario, role, mode = "both", options = {}) {
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

function expectCode(run, code) {
  let thrown;
  try {
    run();
  } catch (error) {
    thrown = error;
  }
  assert.ok(
    thrown instanceof adapter.PhilCoreV2GenesisConflictEvidenceValidationError,
    `expected branded ${code}`
  );
  assert.equal(thrown.code, code);
  assert.equal(thrown.message, code);
  assert.equal(Object.prototype.hasOwnProperty.call(thrown, "cause"), false);
  assert.deepEqual(
    Reflect.ownKeys(thrown).filter((key) => key !== "stack").sort(),
    ["code", "message", "name"]
  );
  return thrown;
}

function project(obligation, journal) {
  return projectionSeed.projectPhilCoreV2GenesisManifestBindingConflict(
    obligation,
    journal
  );
}

function bindingFieldsFrom(projection, overrides = {}) {
  const fields = Object.create(null);
  fields.intentId = projection.intentId;
  fields.genesisDeploymentIntentHash = projection.genesisDeploymentIntentHash;
  fields.role = projection.role;
  fields.credentialGeneration = projection.credentialGeneration;
  fields.ceremonyId = projection.bindingContext.ceremonyId;
  fields.ceremonyExpiresAtUnixSeconds =
    projection.bindingContext.ceremonyExpiresAtUnixSeconds;
  fields.genesisEnrollmentCeremonyHash =
    projection.bindingContext.genesisEnrollmentCeremonyHash;
  fields.journalIntegrityChecksum =
    projection.manifestBinding.journalIntegrityChecksum;
  fields.journalState = projection.bindingContext.journalState;
  fields.sidecarCredentialIdHash = projection.sidecarBinding.credentialIdHash;
  fields.sidecarPublicVerificationMaterialHash =
    projection.sidecarBinding.publicVerificationMaterialHash;
  fields.manifestCredentialIdHash = projection.manifestBinding.credentialIdHash;
  fields.manifestPublicVerificationMaterialHash =
    projection.manifestBinding.publicVerificationMaterialHash;
  fields.challengeReference = CHALLENGE;
  fields.issuedAtUnixSeconds = "1000";
  fields.expiresAtUnixSeconds = "1100";
  for (const [key, value] of Object.entries(overrides)) {
    fields[key] = value;
  }
  return fields;
}

function makeEnvelope(projection, overrides = {}) {
  const binding = bindingFieldsFrom(projection, overrides);
  const challengeBindingHash = Object.prototype.hasOwnProperty.call(
    overrides,
    "challengeBindingHash"
  )
    ? overrides.challengeBindingHash
    : adapter.computePhilCoreV2GenesisConflictEvidenceBindingHash(binding);
  const envelope = Object.create(null);
  envelope.schemaVersion =
    adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_SCHEMA_VERSION;
  envelope.formatProvenance =
    adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_FORMAT_PROVENANCE;
  envelope.challengeReference = binding.challengeReference;
  envelope.challengeBindingHash = challengeBindingHash;
  envelope.issuedAtUnixSeconds = binding.issuedAtUnixSeconds;
  envelope.expiresAtUnixSeconds = binding.expiresAtUnixSeconds;
  envelope.intentId = binding.intentId;
  envelope.genesisDeploymentIntentHash = binding.genesisDeploymentIntentHash;
  envelope.role = binding.role;
  envelope.credentialGeneration = binding.credentialGeneration;
  envelope.ceremonyId = binding.ceremonyId;
  envelope.ceremonyExpiresAtUnixSeconds = binding.ceremonyExpiresAtUnixSeconds;
  envelope.genesisEnrollmentCeremonyHash = binding.genesisEnrollmentCeremonyHash;
  envelope.journalIntegrityChecksum = binding.journalIntegrityChecksum;
  envelope.journalState = binding.journalState;
  envelope.sidecarCredentialIdHash = binding.sidecarCredentialIdHash;
  envelope.sidecarPublicVerificationMaterialHash =
    binding.sidecarPublicVerificationMaterialHash;
  envelope.manifestCredentialIdHash = binding.manifestCredentialIdHash;
  envelope.manifestPublicVerificationMaterialHash =
    binding.manifestPublicVerificationMaterialHash;
  return envelope;
}

function conflictPair(role = 0) {
  const scenario = buildScenario();
  const obligation = createOrphaned(scenario, role, "both");
  const projection = project(obligation, scenario.journal);
  return { scenario, obligation, projection, journal: scenario.journal };
}

function validatePair(pair, envelope, nowUnixSeconds) {
  return adapter.validatePhilCoreV2GenesisConflictEvidence(
    envelope,
    pair.obligation,
    pair.journal,
    nowUnixSeconds
  );
}

beforeEach(resetHarnesses);

describe("Dormant genesis conflict-evidence validation", function () {
  it("EV01: happy path role 0, now == issued (inclusive start)", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const result = validatePair(pair, envelope, 1000);
    assert.equal(result.freshnessOutcome, "WITHIN_CALLER_CLOCK_WINDOW");
    assert.equal(result.validatedAtUnixSeconds, "1000");
    assert.equal(result.role, "0");
  });

  it("EV02: now == expires is EXPIRED; now == expires - 1 is fresh", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection, {
      issuedAtUnixSeconds: "1000",
      expiresAtUnixSeconds: "1100"
    });
    expectCode(() => validatePair(pair, envelope, 1100), E.CONFLICT_EVIDENCE_EXPIRED);
    const fresh = validatePair(pair, envelope, 1099);
    assert.equal(fresh.freshnessOutcome, "WITHIN_CALLER_CLOCK_WINDOW");
    assert.equal(fresh.validatedAtUnixSeconds, "1099");
  });

  it("EV02b: now == expires remains expired when expires == ceremonyExpires", function () {
    const pair = conflictPair(0);
    const ceremonyExpires = pair.projection.bindingContext.ceremonyExpiresAtUnixSeconds;
    const envelope = makeEnvelope(pair.projection, {
      issuedAtUnixSeconds: "1000",
      expiresAtUnixSeconds: ceremonyExpires
    });
    expectCode(
      () => validatePair(pair, envelope, Number(ceremonyExpires)),
      E.CONFLICT_EVIDENCE_EXPIRED
    );
  });

  it("EV03: role 1 and role 2, preserving role-2 zero credential-id", function () {
    const role1 = conflictPair(1);
    const result1 = validatePair(role1, makeEnvelope(role1.projection), 1000);
    assert.equal(result1.role, "1");
    const role2 = conflictPair(2);
    assert.equal(role2.projection.sidecarBinding.credentialIdHash, ZERO_BYTES32);
    const result2 = validatePair(role2, makeEnvelope(role2.projection), 1000);
    assert.equal(result2.role, "2");
    assert.equal(result2.sidecarCredentialIdHash, ZERO_BYTES32);
    assert.equal(result2.manifestCredentialIdHash, ZERO_BYTES32);
  });

  it("EV04: exact 26-key output, null prototype, frozen authorities NONE/false", function () {
    const pair = conflictPair(0);
    const result = validatePair(pair, makeEnvelope(pair.projection), 1000);
    assert.deepEqual(Object.keys(result), [...OUTPUT_KEYS]);
    assert.equal(Object.getPrototypeOf(result), null);
    assert.equal(Object.isFrozen(result), true);
    assert.equal(result.schemaVersion, 1);
    assert.equal(
      result.formatProvenance,
      "PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_V1"
    );
    assert.equal(result.validationKind, "CALLER_CLOCK_FORMAT_ONLY");
    for (const key of [
      "resolutionAuthority",
      "transitionAuthority",
      "possessionAuthority",
      "replayStateAuthority",
      "signatureAuthority",
      "providerAuthority"
    ]) {
      assert.equal(result[key], "NONE");
    }
    assert.equal(result.replayStoreConsulted, false);
    assert.equal(result.verifiedPossession, false);
    assert.equal(result.verifiedSignature, false);
    assert.equal(result.trustedProvider, false);
    result.resolutionAuthority = "X";
    assert.equal(result.resolutionAuthority, "NONE");
  });

  it("EV05: binding hash helper matches validator", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const binding = bindingFieldsFrom(pair.projection);
    assert.equal(
      adapter.computePhilCoreV2GenesisConflictEvidenceBindingHash(binding),
      envelope.challengeBindingHash
    );
    const result = validatePair(pair, envelope, 1000);
    assert.equal(result.challengeBindingHash, envelope.challengeBindingHash);
  });

  it("EV06: repeated calls byte-equal, distinct objects, no input mutation", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const before = JSON.stringify(envelope);
    const first = validatePair(pair, envelope, 1000);
    const second = validatePair(pair, envelope, 1000);
    assert.equal(JSON.stringify(first), JSON.stringify(second));
    assert.ok(first !== second);
    assert.equal(JSON.stringify(envelope), before);
    assert.equal(JSON.stringify(pair.obligation) === JSON.stringify(pair.obligation), true);
  });

  it("EV07: exactly one projection call per validation", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    withHarnesses(() => {
      validatePair(pair, envelope, 1000);
      assert.equal(projectionHarness.calls, 1);
      assert.equal(projectionHarness.lastArgs[0], pair.obligation);
      assert.equal(projectionHarness.lastArgs[1], pair.journal);
    });
  });

  it("EV08: projection errors rethrow by identity", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const marker = new Error("lower-marker");
    withHarnesses(() => {
      projectionHarness.target = () => {
        throw marker;
      };
      let thrown;
      try {
        validatePair(pair, envelope, 1000);
      } catch (error) {
        thrown = error;
      }
      assert.equal(thrown, marker);
    });
    const branded = new projectionSeed.PhilCoreV2GenesisManifestBindingConflictProjectionError(
      projectionSeed.PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_ERROR_CODE
        .MANIFEST_BINDING_CONFLICT_CONDITION_INVALID
    );
    withHarnesses(() => {
      projectionHarness.target = () => {
        throw branded;
      };
      let thrown;
      try {
        validatePair(pair, envelope, 1000);
      } catch (error) {
        thrown = error;
      }
      assert.equal(thrown, branded);
      assert.equal(
        thrown instanceof adapter.PhilCoreV2GenesisConflictEvidenceValidationError,
        false
      );
    });
  });

  it("EV09: missing, extra, and wrong-order keys", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const missing = { ...envelope };
    delete missing.role;
    expectCode(
      () => validatePair(pair, missing, 1000),
      E.CONFLICT_EVIDENCE_MISSING_KEY
    );
    const extra = { ...envelope, extra: "nope" };
    expectCode(
      () => validatePair(pair, extra, 1000),
      E.CONFLICT_EVIDENCE_EXTRA_KEY
    );
    const withSymbol = { ...envelope };
    Object.defineProperty(withSymbol, Symbol("x"), { value: 1 });
    expectCode(
      () => validatePair(pair, withSymbol, 1000),
      E.CONFLICT_EVIDENCE_EXTRA_KEY
    );
    const reordered = {};
    const keys = Object.keys(envelope);
    reordered[keys[1]] = envelope[keys[1]];
    for (const key of keys) {
      if (key !== keys[1]) reordered[key] = envelope[key];
    }
    expectCode(
      () => validatePair(pair, reordered, 1000),
      E.CONFLICT_EVIDENCE_KEY_ORDER_INVALID
    );
  });

  it("EV10: schema mismatch", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    envelope.schemaVersion = 2;
    expectCode(
      () => validatePair(pair, envelope, 1000),
      E.CONFLICT_EVIDENCE_SCHEMA_INVALID
    );
    envelope.schemaVersion = 1;
    envelope.formatProvenance = "OTHER";
    expectCode(
      () => validatePair(pair, envelope, 1000),
      E.CONFLICT_EVIDENCE_SCHEMA_INVALID
    );
  });

  it("EV11: field format — zero challenge, uppercase hex, leading-zero uint, bad generation", function () {
    const pair = conflictPair(0);
    const zeroChallenge = makeEnvelope(pair.projection);
    zeroChallenge.challengeReference = ZERO_BYTES32;
    expectCode(
      () => validatePair(pair, zeroChallenge, 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    const uppercase = makeEnvelope(pair.projection);
    uppercase.intentId = `0X${"11".repeat(32)}`;
    expectCode(
      () => validatePair(pair, uppercase, 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    const leadingZero = makeEnvelope(pair.projection);
    leadingZero.issuedAtUnixSeconds = "01000";
    expectCode(
      () => validatePair(pair, leadingZero, 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    const badGen = makeEnvelope(pair.projection);
    badGen.credentialGeneration = "2";
    expectCode(
      () => validatePair(pair, badGen, 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    const zeroJournal = makeEnvelope(pair.projection);
    zeroJournal.journalIntegrityChecksum = ZERO_BYTES32;
    expectCode(
      () => validatePair(pair, zeroJournal, 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    const zeroPublic = makeEnvelope(pair.projection);
    zeroPublic.sidecarPublicVerificationMaterialHash = ZERO_BYTES32;
    expectCode(
      () => validatePair(pair, zeroPublic, 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    const zeroSidecarId = makeEnvelope(pair.projection);
    zeroSidecarId.sidecarCredentialIdHash = ZERO_BYTES32;
    expectCode(
      () => validatePair(pair, zeroSidecarId, 1000),
      E.CONFLICT_EVIDENCE_BINDING_MISMATCH
    );
  });

  it("EV12: each identity-field mismatch is BINDING_MISMATCH", function () {
    const pair = conflictPair(0);
    for (const [field, value] of IDENTITY_MISMATCH_FIELDS) {
      const envelope = makeEnvelope(pair.projection, { [field]: value });
      expectCode(
        () => validatePair(pair, envelope, 1000),
        E.CONFLICT_EVIDENCE_BINDING_MISMATCH
      );
    }
  });

  it("EV13: wrong challengeBindingHash", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection, {
      challengeBindingHash: ALT_HASH
    });
    expectCode(
      () => validatePair(pair, envelope, 1000),
      E.CONFLICT_EVIDENCE_CHALLENGE_BINDING_MISMATCH
    );
  });

  it("EV14: issued == expires and issued > expires", function () {
    const pair = conflictPair(0);
    const equal = makeEnvelope(pair.projection, {
      issuedAtUnixSeconds: "1100",
      expiresAtUnixSeconds: "1100"
    });
    expectCode(
      () => validatePair(pair, equal, 1000),
      E.CONFLICT_EVIDENCE_TIMESTAMP_ORDER_INVALID
    );
    const inverted = makeEnvelope(pair.projection, {
      issuedAtUnixSeconds: "1200",
      expiresAtUnixSeconds: "1100"
    });
    expectCode(
      () => validatePair(pair, inverted, 1000),
      E.CONFLICT_EVIDENCE_TIMESTAMP_ORDER_INVALID
    );
  });

  it("EV15: expires == ceremonyExpires allowed; +1 forbidden", function () {
    const pair = conflictPair(0);
    const ceremonyExpires = pair.projection.bindingContext.ceremonyExpiresAtUnixSeconds;
    const allowed = makeEnvelope(pair.projection, {
      issuedAtUnixSeconds: "1000",
      expiresAtUnixSeconds: ceremonyExpires
    });
    const result = validatePair(pair, allowed, 1000);
    assert.equal(result.expiresAtUnixSeconds, ceremonyExpires);
    const forbidden = makeEnvelope(pair.projection, {
      issuedAtUnixSeconds: "1000",
      expiresAtUnixSeconds: String(BigInt(ceremonyExpires) + 1n)
    });
    expectCode(
      () => validatePair(pair, forbidden, 1000),
      E.CONFLICT_EVIDENCE_LIFETIME_EXCEEDS_CEREMONY
    );
  });

  it("EV16: issued after ceremony expiry", function () {
    const pair = conflictPair(0);
    const ceremonyExpires = pair.projection.bindingContext.ceremonyExpiresAtUnixSeconds;
    const issued = String(BigInt(ceremonyExpires) + 1n);
    const expires = String(BigInt(ceremonyExpires) + 2n);
    const envelope = makeEnvelope(pair.projection, {
      issuedAtUnixSeconds: issued,
      expiresAtUnixSeconds: expires
    });
    expectCode(
      () => validatePair(pair, envelope, Number(issued)),
      E.CONFLICT_EVIDENCE_LIFETIME_EXCEEDS_CEREMONY
    );
  });

  it("EV17: now = issued-1 and now = expires+1", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection, {
      issuedAtUnixSeconds: "1000",
      expiresAtUnixSeconds: "1100"
    });
    expectCode(
      () => validatePair(pair, envelope, 999),
      E.CONFLICT_EVIDENCE_NOT_YET_VALID
    );
    expectCode(
      () => validatePair(pair, envelope, 1101),
      E.CONFLICT_EVIDENCE_EXPIRED
    );
  });

  it("EV18: non-number / 0 / non-integer / > uint48 now", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    for (const now of ["1000", 0, 1.5, 281474976710656, NaN, null, undefined]) {
      expectCode(
        () => validatePair(pair, envelope, now),
        E.CONFLICT_EVIDENCE_CLOCK_INVALID
      );
    }
  });

  it("EV19: hostile getter, false-own-key Proxy, revoked Proxy, throwing ownKeys, boxed primitive", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const getterMarker = new Error("getter-marker");
    const hostile = { ...envelope };
    Object.defineProperty(hostile, "role", {
      enumerable: true,
      configurable: true,
      get() {
        throw getterMarker;
      }
    });
    const getterThrown = expectCode(
      () => validatePair(pair, hostile, 1000),
      E.CONFLICT_EVIDENCE_PROPERTY_READ_FAILED
    );
    assert.notEqual(getterThrown, getterMarker);
    assert.equal(JSON.stringify(getterThrown).includes("getter-marker"), false);

    const falseOwn = new Proxy(envelope, {
      getOwnPropertyDescriptor(target, key) {
        if (key === "role") return undefined;
        return Object.getOwnPropertyDescriptor(target, key);
      }
    });
    expectCode(
      () => validatePair(pair, falseOwn, 1000),
      E.CONFLICT_EVIDENCE_MISSING_KEY
    );

    const { proxy, revoke } = Proxy.revocable({ ...envelope }, {});
    revoke();
    expectCode(
      () => validatePair(pair, proxy, 1000),
      E.CONFLICT_EVIDENCE_INVARIANT_VIOLATION
    );

    const ownKeysMarker = new Error("ownKeys-marker");
    const throwingKeys = new Proxy(
      {},
      {
        ownKeys() {
          throw ownKeysMarker;
        },
        getOwnPropertyDescriptor() {
          return { configurable: true, enumerable: true, value: 1 };
        }
      }
    );
    const ownKeysThrown = expectCode(
      () => validatePair(pair, throwingKeys, 1000),
      E.CONFLICT_EVIDENCE_INVARIANT_VIOLATION
    );
    assert.notEqual(ownKeysThrown, ownKeysMarker);

    expectCode(
      () => validatePair(pair, Object(1), 1000),
      E.CONFLICT_EVIDENCE_NOT_OBJECT
    );
  });

  it("EV20: branded error has no cause, instanceof locked, hostile throw discarded", function () {
    const pair = conflictPair(0);
    const forged = Object.create(
      adapter.PhilCoreV2GenesisConflictEvidenceValidationError.prototype
    );
    forged.code = E.CONFLICT_EVIDENCE_EXPIRED;
    forged.message = E.CONFLICT_EVIDENCE_EXPIRED;
    forged.name = "PhilCoreV2GenesisConflictEvidenceValidationError";
    assert.equal(
      forged instanceof adapter.PhilCoreV2GenesisConflictEvidenceValidationError,
      false
    );
    const envelope = makeEnvelope(pair.projection);
    const marker = new Error("raw-cause");
    Object.defineProperty(envelope, "intentId", {
      enumerable: true,
      configurable: true,
      get() {
        throw marker;
      }
    });
    const thrown = expectCode(
      () => validatePair(pair, envelope, 1000),
      E.CONFLICT_EVIDENCE_PROPERTY_READ_FAILED
    );
    assert.equal(Object.prototype.hasOwnProperty.call(thrown, "cause"), false);
    assert.notEqual(thrown, marker);
    assert.equal(String(thrown.stack || "").includes("raw-cause"), false);
  });

  it("EV21: require-time purity (0 projection calls at load)", function () {
    assert.equal(REQUIRE_TIME_COUNTS.projection, 0);
    assert.equal(CACHE_RESTORATION_PROOF.every(Boolean), true);
    assertExportsDescriptor(projectionModule, projectionDescriptor, "projection");
    assertSameReference(projectionModule.exports, projectionSeed, "projection exports");
    assertSameReference(validatorSeedModule.exports, validatorSeed, "validator exports");
    assert.ok(validatorPrivateModule !== validatorSeedModule);
    assert.deepEqual(cacheKeysAddedByWindows, []);
  });

  it("EV22: source/reference/graph dormancy and classification total 114", function () {
    const source = fs.readFileSync(VALIDATOR_PATH, "utf8");
    const imports = [...source.matchAll(/\bfrom\s+["'](\.[^"']+)["']/g)]
      .map((match) => match[1]);
    assert.deepEqual(imports, [
      "./v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts"
    ]);
    for (const literal of [
      "Date.now",
      "node:fs",
      "node:net",
      "ipcMain",
      "ipcRenderer",
      "contextBridge",
      "electron",
      "recovery-genesis-staging-host",
      "recovery-genesis-coordinator",
      "deviceAdapter",
      "sepolia",
      "webauthn",
      "secure enclave",
      "authenticationEvidence",
      "possessionVerification"
    ]) {
      assert.equal(source.includes(literal), false, literal);
    }
    assert.equal(source.includes("node:crypto"), true);

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
    scanImports(VALIDATOR_PATH);
    const graph = [...visited].map((file) => path.relative(ROOT, file)).join("\n");
    assert.ok(
      graph.includes("v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts")
    );
    for (const forbidden of [
      "recovery-genesis-staging-host",
      "recovery-genesis-coordinator",
      "v2LocalCeremonyProtocol"
    ]) {
      assert.equal(graph.includes(forbidden), false, forbidden);
    }

    const needle = "v2ConsumerRecoveryGenesisConflictEvidenceValidation";
    const hits = [];
    const skip = new Set([
      ".git", "node_modules", "artifacts", "cache", "dist", "build",
      "coverage", "release", "target"
    ]);
    function scanTree(target) {
      const stat = fs.lstatSync(target);
      if (stat.isSymbolicLink()) return;
      if (stat.isDirectory()) {
        if (skip.has(path.basename(target))) return;
        for (const name of fs.readdirSync(target)) {
          scanTree(path.join(target, name));
        }
        return;
      }
      if (!/\.(?:cjs|mjs|js|ts|tsx|json|html|yml|yaml|md)$/.test(target)) return;
      const relative = path.relative(ROOT, target);
      const text = fs.readFileSync(target, "utf8");
      if (relative.includes(needle) || text.includes(needle)) hits.push(relative);
    }
    scanTree(ROOT);
    assert.deepEqual(hits.sort(), [
      "apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisConflictEvidenceValidation.ts",
      "config/ci/classification.json",
      "test/unit/v2ConsumerRecoveryGenesisConflictEvidenceNonResolver.test.cjs",
      "test/unit/v2ConsumerRecoveryGenesisConflictEvidenceValidation.test.cjs"
    ].sort());

    const classification = JSON.parse(fs.readFileSync(CLASSIFICATION_PATH, "utf8"));
    assert.equal(classification.totals.required_product_runtime, 114);
    const item = classification.items.find((entry) =>
      entry.id === "unit:v2ConsumerRecoveryGenesisConflictEvidenceValidation.test.cjs"
    );
    assert.ok(item);
    assert.equal(item.lane, "required_product_runtime");
  });

  it("EV23: named mutants — binding, hash, expiry, clock, wrap, authority, runtime import", function () {
    const pair = conflictPair(0);
    const kills = Object.freeze({
      skipBinding() {
        const envelope = makeEnvelope(pair.projection, { intentId: ALT_HASH });
        expectCode(
          () => validatePair(pair, envelope, 1000),
          E.CONFLICT_EVIDENCE_BINDING_MISMATCH
        );
      },
      skipHash() {
        const envelope = makeEnvelope(pair.projection, {
          challengeBindingHash: ALT_HASH_2
        });
        expectCode(
          () => validatePair(pair, envelope, 1000),
          E.CONFLICT_EVIDENCE_CHALLENGE_BINDING_MISMATCH
        );
      },
      skipExpiry() {
        const envelope = makeEnvelope(pair.projection);
        expectCode(
          () => validatePair(pair, envelope, 1100),
          E.CONFLICT_EVIDENCE_EXPIRED
        );
      },
      noDateNow() {
        const source = fs.readFileSync(VALIDATOR_PATH, "utf8");
        assert.equal(source.includes("Date.now"), false);
      },
      noWrapLower() {
        const marker = new Error("must-not-wrap");
        withHarnesses(() => {
          projectionHarness.target = () => {
            throw marker;
          };
          let thrown;
          try {
            validatePair(pair, makeEnvelope(pair.projection), 1000);
          } catch (error) {
            thrown = error;
          }
          assert.equal(thrown, marker);
        });
      },
      authorityNone() {
        const result = validatePair(pair, makeEnvelope(pair.projection), 1000);
        assert.equal(result.providerAuthority, "NONE");
        assert.equal(result.possessionAuthority, "NONE");
        assert.equal(result.replayStateAuthority, "NONE");
        assert.equal(result.signatureAuthority, "NONE");
      },
      noRuntimeEvidenceImport() {
        const source = fs.readFileSync(VALIDATOR_PATH, "utf8");
        assert.equal(source.includes("authenticationEvidence"), false);
        assert.equal(source.includes("possessionVerification"), false);
      }
    });
    for (const [name, run] of Object.entries(kills)) {
      run();
      void name;
    }
  });

  it("EV24: hostile evidence is unread when projection fails", function () {
    const scenario = buildScenario();
    const obligation = createOrphaned(scenario, 0, "both", {
      reason: "RESTART_DURING_CREATION"
    });
    let traps = 0;
    const hostile = new Proxy({}, {
      get() {
        traps += 1;
        throw new Error("evidence-get");
      },
      ownKeys() {
        traps += 1;
        throw new Error("evidence-ownKeys");
      }
    });
    let thrown;
    try {
      adapter.validatePhilCoreV2GenesisConflictEvidence(
        hostile,
        obligation,
        scenario.journal,
        1000
      );
    } catch (error) {
      thrown = error;
    }
    assert.equal(traps, 0);
    assert.ok(thrown);
    assert.equal(
      thrown instanceof adapter.PhilCoreV2GenesisConflictEvidenceValidationError,
      false
    );
  });

  it("EV25: identical envelope twice inside the window succeeds without replay-store claim", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const first = validatePair(pair, envelope, 1000);
    const second = validatePair(pair, envelope, 1050);
    assert.equal(first.replayStoreConsulted, false);
    assert.equal(second.replayStoreConsulted, false);
    assert.equal(second.freshnessOutcome, "WITHIN_CALLER_CLOCK_WINDOW");
  });

  it("EV26: runtime export surface and exact domain/version literals", function () {
    assert.equal(
      adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_SCHEMA_VERSION,
      1
    );
    assert.equal(
      adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_FORMAT_PROVENANCE,
      "PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_V1"
    );
    assert.equal(
      adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_BINDING_PREFIX,
      "PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_BINDING_V1|"
    );
    assert.equal(
      adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_KIND
        .CALLER_CLOCK_FORMAT_ONLY,
      "CALLER_CLOCK_FORMAT_ONLY"
    );
    assert.equal(
      adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_AUTHORITY.NONE,
      "NONE"
    );
    assert.deepEqual(Object.keys(E), [
      "CONFLICT_EVIDENCE_NOT_OBJECT",
      "CONFLICT_EVIDENCE_MISSING_KEY",
      "CONFLICT_EVIDENCE_EXTRA_KEY",
      "CONFLICT_EVIDENCE_KEY_ORDER_INVALID",
      "CONFLICT_EVIDENCE_SCHEMA_INVALID",
      "CONFLICT_EVIDENCE_FIELD_INVALID",
      "CONFLICT_EVIDENCE_PROPERTY_READ_FAILED",
      "CONFLICT_EVIDENCE_BINDING_MISMATCH",
      "CONFLICT_EVIDENCE_CHALLENGE_BINDING_MISMATCH",
      "CONFLICT_EVIDENCE_TIMESTAMP_ORDER_INVALID",
      "CONFLICT_EVIDENCE_LIFETIME_EXCEEDS_CEREMONY",
      "CONFLICT_EVIDENCE_CLOCK_INVALID",
      "CONFLICT_EVIDENCE_NOT_YET_VALID",
      "CONFLICT_EVIDENCE_EXPIRED",
      "CONFLICT_EVIDENCE_INVARIANT_VIOLATION"
    ]);
  });
});

after(function () {
  resetHarnesses();
});
