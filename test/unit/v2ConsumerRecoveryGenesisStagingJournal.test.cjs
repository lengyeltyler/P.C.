require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { getAddress } = require("ethers");

const mod = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingJournal.ts"
);
const genesis = require(
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
  buildO39ConsumerRecoveryFixturePackage
} = require("../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs");

const C = mod.PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_JOURNAL_ERROR_CODE;

const ROOT = path.resolve(__dirname, "../..");
const FIXTURE_PATH = path.join(
  ROOT,
  "config/cryptography/O39_CONSUMER_RECOVERY_FIXTURES.json"
);
const fixtures = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));

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

function validCeremonyFields(role, intentHash, overrides = {}) {
  return {
    ceremonyVersion: "1",
    ceremonyId: `0x${String(role + 1).padStart(2, "0")}${"a1".repeat(31)}`,
    genesisDeploymentIntentHash: intentHash,
    role: String(role),
    credentialGeneration: "1",
    expiresAt: "1899999999",
    ...overrides
  };
}

// Builds valid, genesis-shaped per-role factors (descriptor + independence +
// optional signer) bound to the given ceremony hashes, reusing the O.39
// fixture package's structural material exactly like the genesis-protocol
// module's own test file does.
// The O.39 JSON fixture file stores numeric descriptor/independence fields
// as JSON numbers (unquoted), which JSON.parse yields as JavaScript
// `number`. Package 5B-0.4's candidate boundary is exactly
// ExactUintInput = bigint | string (a JavaScript number is excluded), so
// every numeric field is converted to bigint here, in the test helper --
// never in production -- before it is ever passed to stageGenesisRoleCandidate.
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

function toBigintFields(source, numericFields) {
  const out = { ...source };
  for (const field of numericFields) {
    if (typeof out[field] === "number") {
      out[field] = BigInt(out[field]);
    }
  }
  return out;
}

function buildFactorsForCeremonies(ceremonyHashes) {
  const source = fixtures.profiles.standard.factors;
  const roleSources = [source.primary, source.secondary, source.offline];
  return [0, 1, 2].map((role) => {
    const base = roleSources[role];
    const baseIndependence = toBigintFields(base.independence, INDEPENDENCE_NUMERIC_FIELDS);
    const baseDescriptor = toBigintFields(base.descriptor, DESCRIPTOR_NUMERIC_FIELDS);
    const independence = {
      ...baseIndependence,
      role: BigInt(role),
      enrollmentCeremonyHash: ceremonyHashes[role],
      credentialGeneration: 1n
    };
    const descriptor = {
      ...baseDescriptor,
      role: BigInt(role),
      credentialGeneration: 1n,
      independenceBindingHash:
        computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence)
    };
    const roleInput = { descriptor, independence };
    if (base.signer) roleInput.signer = base.signer;
    return roleInput;
  });
}

// Builds a fully valid, freshly created journal plus every ingredient
// needed to stage any subset of its three roles, mirroring the genesis
// module's own `buildValidGenesisProfile` helper.
function buildScenario(intentOverrides = {}) {
  const now = 1000;
  const intent = validIntentFields(intentOverrides);
  const intentHash = genesis.computePhilCoreV2LocalGenesisDeploymentIntentHash(intent);
  const ceremonies = [0, 1, 2].map((role) => validCeremonyFields(role, intentHash));
  const ceremonyHashes = ceremonies.map((c) =>
    genesis.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(c)
  );
  const roleInputs = buildFactorsForCeremonies(ceremonyHashes);
  const journal = mod.createGenesisStagingJournal(intent, now);
  return { now, intent, intentHash, ceremonies, ceremonyHashes, roleInputs, journal };
}

function stageRole(scenario, role, now = scenario.now + role + 1, overrideInput = {}) {
  const candidate = {
    ...scenario.roleInputs[role],
    currentRoleCeremony: scenario.ceremonies[role],
    ...overrideInput
  };
  return mod.stageGenesisRoleCandidate(scenario.journal, role, candidate, now);
}

// Rebinds a role's ceremony/independence/descriptor hash chain after
// overriding fields, mirroring the genesis module's own established
// `rebind()` technique: changing a ceremony field changes its hash, which
// must be re-threaded into independence.enrollmentCeremonyHash, which in
// turn changes descriptor.independenceBindingHash.
function rebindCeremonyAndFactor(scenario, role, overrides = {}) {
  const ceremony = { ...scenario.ceremonies[role], ...(overrides.ceremony || {}) };
  const ceremonyHash = genesis.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(ceremony);
  const independence = {
    ...scenario.roleInputs[role].independence,
    ...(overrides.independence || {}),
    enrollmentCeremonyHash: ceremonyHash
  };
  const descriptor = {
    ...scenario.roleInputs[role].descriptor,
    ...(overrides.descriptor || {}),
    independenceBindingHash: computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence)
  };
  return { ceremony, independence, descriptor, ceremonyHash };
}

function stageAllThree(scenario) {
  let journal = scenario.journal;
  let now = scenario.now;
  for (const role of [0, 1, 2]) {
    now += 1;
    journal = mod.stageGenesisRoleCandidate(
      journal,
      role,
      { ...scenario.roleInputs[role], currentRoleCeremony: scenario.ceremonies[role] },
      now
    );
  }
  return { journal, lastNow: now };
}

// Constructs a hostile Proxy whose target is extensible and has ZERO own
// properties for `keys` (every value only reachable through the target's
// prototype), while its `ownKeys` trap falsely reports `keys` as if they
// were own. Matches the proven 5B-0.2.2/0.2.3 attack construction exactly.
function fakeOwnKeysProxy(realObject, keys) {
  const proto = { ...realObject };
  const target = Object.create(proto);
  return new Proxy(target, {
    ownKeys() {
      return keys;
    }
  });
}

function assertMarkerUnreachable(caught, marker) {
  assert.ok(caught instanceof mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError);
  assert.notEqual(caught.cause, marker);
  const names = Object.getOwnPropertyNames(caught);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(caught, name);
    assert.notEqual(descriptor.value, marker, `own property ${name} must not hold the marker`);
  }
}

describe("V2 consumer recovery genesis candidate staging journal (Package 5B-0.4)", function () {
  describe("export surface", function () {
    it("exports exactly the nineteen authorized runtime values", function () {
      const expected = [
        "PHILCORE_V2_GENESIS_STAGING_JOURNAL_SCHEMA_VERSION",
        "PHILCORE_V2_GENESIS_STAGING_JOURNAL_FORMAT_PROVENANCE",
        "PHILCORE_V2_GENESIS_STAGING_JOURNAL_CHECKSUM_PREFIX",
        "MAX_GENESIS_MANIFEST_ENTRY_BYTES",
        "MAX_GENESIS_JOURNAL_FILE_BYTES",
        "PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING",
        "PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED",
        "PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED",
        "PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED",
        "PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_JOURNAL_ERROR_CODE",
        "PhilCoreV2ConsumerRecoveryGenesisStagingJournalError",
        "computeGenesisStagingJournalChecksum",
        "validateGenesisStagingJournalRecord",
        "createGenesisStagingJournal",
        "stageGenesisRoleCandidate",
        "cancelGenesisStagingJournal",
        "expireGenesisStagingJournalIfNeeded",
        "supersedeGenesisStagingJournal",
        "allGenesisStagingSlotsPopulated"
      ];
      const actual = Object.keys(mod).sort();
      assert.deepEqual(actual, [...expected].sort());
      assert.equal(actual.length, 19);
    });
  });

  describe("constants", function () {
    it("pins exact schema version, format provenance, checksum prefix, and byte ceilings", function () {
      assert.equal(mod.PHILCORE_V2_GENESIS_STAGING_JOURNAL_SCHEMA_VERSION, 1);
      assert.equal(
        mod.PHILCORE_V2_GENESIS_STAGING_JOURNAL_FORMAT_PROVENANCE,
        "philcore-v2-genesis-ceremony-staging-journal-v1"
      );
      assert.equal(
        mod.PHILCORE_V2_GENESIS_STAGING_JOURNAL_CHECKSUM_PREFIX,
        "PHILCORE_V2_GENESIS_CEREMONY_STAGING_JOURNAL_V1|"
      );
      assert.equal(mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES, 4096);
      assert.equal(mod.MAX_GENESIS_JOURNAL_FILE_BYTES, 16384);
      assert.equal(mod.PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_STAGING, "STAGING");
      assert.equal(mod.PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_CANCELLED, "CANCELLED");
      assert.equal(mod.PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_EXPIRED, "EXPIRED");
      assert.equal(mod.PHILCORE_V2_GENESIS_STAGING_JOURNAL_STATE_SUPERSEDED, "SUPERSEDED");
    });

    it("locks exactly sixty-five error identifiers, each valued as itself, zero duplicates", function () {
      const codes = Object.keys(C);
      assert.equal(codes.length, 65);
      for (const code of codes) {
        assert.equal(C[code], code);
      }
      assert.equal(new Set(codes).size, 65);
      assert.equal(Object.isFrozen(C), true);
    });
  });

  describe("createGenesisStagingJournal", function () {
    it("creates an empty STAGING journal with the recomputed intent hash and matching checksum", function () {
      const { journal, intentHash, now, intent } = buildScenario();
      assert.equal(journal.state, "STAGING");
      assert.equal(journal.endReason, null);
      assert.equal(journal.genesisDeploymentIntentHash, intentHash);
      assert.equal(journal.createdAtUnixSeconds, String(now));
      assert.equal(journal.updatedAtUnixSeconds, String(now));
      assert.deepEqual(journal.manifest, { "0": null, "1": null, "2": null });
      assert.equal(journal.intentVersion, intent.intentVersion);
      assert.equal(journal.initialValidator, intent.initialValidator);
      const { integrityChecksum: _checksum1, ...withoutChecksum1 } = journal;
      assert.equal(
        mod.computeGenesisStagingJournalChecksum(withoutChecksum1),
        journal.integrityChecksum
      );
      assert.equal(Object.isFrozen(journal), true);
      assert.equal(Object.isFrozen(journal.manifest), true);
    });

    it("rejects creation at or after intent expiry", function () {
      const intent = validIntentFields({ expiresAt: "1000" });
      assert.throws(
        () => mod.createGenesisStagingJournal(intent, 1000),
        (error) => error.code === C.JOURNAL_CREATION_NOT_BEFORE_EXPIRY
      );
      assert.throws(
        () => mod.createGenesisStagingJournal(intent, 1001),
        (error) => error.code === C.JOURNAL_CREATION_NOT_BEFORE_EXPIRY
      );
      assert.doesNotThrow(() => mod.createGenesisStagingJournal(intent, 999));
    });

    it("rejects a JavaScript number for a numeric intent field before delegation", function () {
      const intent = { ...validIntentFields(), chainId: 11155111 };
      assert.throws(
        () => mod.createGenesisStagingJournal(intent, 1000),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
    });

    it("accepts a bigint numeric intent field and stores it as a canonical decimal string", function () {
      const intent = { ...validIntentFields(), chainId: 11155111n };
      const journal = mod.createGenesisStagingJournal(intent, 1000);
      assert.equal(journal.chainId, "11155111");
      assert.equal(typeof journal.chainId, "string");
    });

    it("collapses a genuine genesis-validation failure into GENESIS_INTENT_VALIDATION_FAILED", function () {
      const intent = validIntentFields({ intentId: `0x${"00".repeat(32)}` });
      assert.throws(
        () => mod.createGenesisStagingJournal(intent, 1000),
        (error) => error.code === C.GENESIS_INTENT_VALIDATION_FAILED
      );
    });

    it("rejects a non-object intent", function () {
      for (const bad of [null, [], "x", 1, undefined]) {
        assert.throws(
          () => mod.createGenesisStagingJournal(bad, 1000),
          (error) => error.code === C.JOURNAL_NOT_OBJECT
        );
      }
    });

    it("rejects a missing or extra intent key", function () {
      const missing = validIntentFields();
      delete missing.userSalt;
      assert.throws(
        () => mod.createGenesisStagingJournal(missing, 1000),
        (error) => error.code === C.JOURNAL_MISSING_KEY
      );
      const extra = { ...validIntentFields(), extra: "0x00" };
      assert.throws(
        () => mod.createGenesisStagingJournal(extra, 1000),
        (error) => error.code === C.JOURNAL_EXTRA_KEY
      );
    });

    it("rejects a false-own-key Proxy intent whose fields are inherited-only", function () {
      const real = validIntentFields();
      const hostile = fakeOwnKeysProxy(real, Object.keys(real));
      assert.throws(
        () => mod.createGenesisStagingJournal(hostile, 1000),
        (error) => error.code === C.JOURNAL_MISSING_KEY
      );
    });

    it("never rereads the caller's intent object after snapshotting", function () {
      const intent = validIntentFields();
      let reads = 0;
      Object.defineProperty(intent, "expiresAt", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          return "1900000000";
        }
      });
      mod.createGenesisStagingJournal(intent, 1000);
      assert.equal(reads, 1);
    });
  });

  describe("stageGenesisRoleCandidate -- happy path and sequencing", function () {
    it("stages all three roles in order and returns a fully populated STAGING journal", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      assert.equal(journal.state, "STAGING");
      assert.notEqual(journal.manifest["0"], null);
      assert.notEqual(journal.manifest["1"], null);
      assert.notEqual(journal.manifest["2"], null);
      assert.equal(journal.manifest["0"].role, "0");
      assert.equal(journal.manifest["1"].role, "1");
      assert.equal(journal.manifest["2"].role, "2");
      assert.equal(journal.manifest["2"].signer, scenario.roleInputs[2].signer);
      assert.equal(journal.manifest["0"].signer, null);
      assert.equal(journal.manifest["1"].signer, null);
      const { integrityChecksum: _checksum2, ...withoutChecksum2 } = journal;
      assert.equal(
        mod.computeGenesisStagingJournalChecksum(withoutChecksum2),
        journal.integrityChecksum
      );
      assert.equal(mod.allGenesisStagingSlotsPopulated(journal), true);
      assert.equal(Object.isFrozen(journal.manifest["0"]), true);
      assert.equal(Object.isFrozen(journal.manifest["0"].descriptor), true);
    });

    it("rejects staging role 1 before role 0", function () {
      const scenario = buildScenario();
      assert.throws(
        () => stageRole(scenario, 1),
        (error) => error.code === C.ROLE_SEQUENCE_VIOLATION
      );
    });

    it("rejects staging role 2 before role 0/1", function () {
      const scenario = buildScenario();
      assert.throws(
        () => stageRole(scenario, 2),
        (error) => error.code === C.ROLE_SEQUENCE_VIOLATION
      );
    });

    it("rejects replaying an already-populated slot, including byte-identical resubmission", function () {
      const scenario = buildScenario();
      const journal = stageRole(scenario, 0);
      scenario.journal = journal;
      assert.throws(
        () => stageRole(scenario, 0, scenario.now + 5),
        (error) => error.code === C.ROLE_SLOT_ALREADY_POPULATED
      );
    });

    it("rejects an out-of-range expectedRole", function () {
      const scenario = buildScenario();
      for (const bad of [-1, 3, 1.5]) {
        assert.throws(
          () => mod.stageGenesisRoleCandidate(
            scenario.journal,
            bad,
            { ...scenario.roleInputs[0], currentRoleCeremony: scenario.ceremonies[0] },
            scenario.now + 1
          ),
          (error) => error.code === C.ROLE_INVALID
        );
      }
    });

    it("rejects staging on a non-STAGING journal", function () {
      const scenario = buildScenario();
      const cancelled = mod.cancelGenesisStagingJournal(scenario.journal, scenario.now + 1);
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          cancelled,
          0,
          { ...scenario.roleInputs[0], currentRoleCeremony: scenario.ceremonies[0] },
          scenario.now + 2
        ),
        (error) => error.code === C.JOURNAL_NOT_STAGING
      );
    });
  });

  describe("stageGenesisRoleCandidate -- candidate numeric boundary (bigint|string only)", function () {
    it("rejects a JavaScript number in a descriptor numeric field before factor-policy delegation", function () {
      const scenario = buildScenario();
      const candidate = {
        ...scenario.roleInputs[0],
        descriptor: { ...scenario.roleInputs[0].descriptor, descriptorVersion: 3 },
        currentRoleCeremony: scenario.ceremonies[0]
      };
      assert.throws(
        () => mod.stageGenesisRoleCandidate(scenario.journal, 0, candidate, scenario.now + 1),
        (error) => error.code === C.CANDIDATE_PROPERTY_READ_FAILED
      );
    });

    it("rejects a JavaScript number in an independence numeric field before factor-policy delegation", function () {
      const scenario = buildScenario();
      const candidate = {
        ...scenario.roleInputs[0],
        independence: { ...scenario.roleInputs[0].independence, bindingVersion: 2 },
        currentRoleCeremony: scenario.ceremonies[0]
      };
      assert.throws(
        () => mod.stageGenesisRoleCandidate(scenario.journal, 0, candidate, scenario.now + 1),
        (error) => error.code === C.CANDIDATE_PROPERTY_READ_FAILED
      );
    });

    it("accepts an all-bigint descriptor/independence candidate (the fixture default) and stages successfully", function () {
      const scenario = buildScenario();
      assert.doesNotThrow(() => stageRole(scenario, 0));
    });

    it("accepts an all-canonical-string descriptor/independence candidate", function () {
      const scenario = buildScenario();
      const toStringFields = (source, fields) => {
        const out = { ...source };
        for (const field of fields) {
          if (typeof out[field] === "bigint") out[field] = out[field].toString(10);
        }
        return out;
      };
      const candidate = {
        descriptor: toStringFields(scenario.roleInputs[0].descriptor, DESCRIPTOR_NUMERIC_FIELDS),
        independence: toStringFields(scenario.roleInputs[0].independence, INDEPENDENCE_NUMERIC_FIELDS),
        currentRoleCeremony: scenario.ceremonies[0]
      };
      assert.doesNotThrow(() =>
        mod.stageGenesisRoleCandidate(scenario.journal, 0, candidate, scenario.now + 1)
      );
    });

    it("rejects a false-own-key Proxy descriptor whose fields are inherited-only, at the candidate snapshot boundary", function () {
      const scenario = buildScenario();
      const hostileDescriptor = fakeOwnKeysProxy(
        scenario.roleInputs[0].descriptor,
        Object.keys(scenario.roleInputs[0].descriptor)
      );
      const candidate = {
        ...scenario.roleInputs[0],
        descriptor: hostileDescriptor,
        currentRoleCeremony: scenario.ceremonies[0]
      };
      assert.throws(
        () => mod.stageGenesisRoleCandidate(scenario.journal, 0, candidate, scenario.now + 1),
        (error) => error.code === C.CANDIDATE_INPUT_MISSING_KEY
      );
    });

    it("rejects a revoked Proxy independence at the candidate snapshot boundary", function () {
      const scenario = buildScenario();
      const { proxy, revoke } = Proxy.revocable(scenario.roleInputs[0].independence, {});
      revoke();
      const candidate = {
        ...scenario.roleInputs[0],
        independence: proxy,
        currentRoleCeremony: scenario.ceremonies[0]
      };
      assert.throws(
        () => mod.stageGenesisRoleCandidate(scenario.journal, 0, candidate, scenario.now + 1),
        (error) => error.code === C.CANDIDATE_INPUT_NOT_OBJECT
      );
    });

    it("reads each descriptor/independence field exactly once, never rereading the caller's argument after the snapshot", function () {
      const scenario = buildScenario();
      let descriptorVersionReads = 0;
      const hostileDescriptor = { ...scenario.roleInputs[0].descriptor };
      Object.defineProperty(hostileDescriptor, "descriptorVersion", {
        enumerable: true,
        configurable: true,
        get() {
          descriptorVersionReads += 1;
          return scenario.roleInputs[0].descriptor.descriptorVersion;
        }
      });
      const candidate = {
        ...scenario.roleInputs[0],
        descriptor: hostileDescriptor,
        currentRoleCeremony: scenario.ceremonies[0]
      };
      assert.doesNotThrow(() =>
        mod.stageGenesisRoleCandidate(scenario.journal, 0, candidate, scenario.now + 1)
      );
      assert.equal(descriptorVersionReads, 1);
    });
  });

  describe("stageGenesisRoleCandidate -- expiry precedence", function () {
    it("returns an EXPIRED journal without adding the candidate at exactly intent.expiresAt, and does not throw", function () {
      const scenario = buildScenario({ expiresAt: "2000" });
      const { ceremony, independence, descriptor } = rebindCeremonyAndFactor(scenario, 0, {
        ceremony: { expiresAt: "1999" }
      });
      const result = mod.stageGenesisRoleCandidate(
        scenario.journal,
        0,
        { descriptor, independence, currentRoleCeremony: ceremony },
        2000
      );
      assert.equal(result.state, "EXPIRED");
      assert.equal(result.endReason, "EXPIRED");
      assert.deepEqual(result.manifest, { "0": null, "1": null, "2": null });
    });

    it("returns EXPIRED (not a throw) after intent.expiresAt too", function () {
      const scenario = buildScenario({ expiresAt: "2000" });
      const { ceremony, independence, descriptor } = rebindCeremonyAndFactor(scenario, 0, {
        ceremony: { expiresAt: "1999" }
      });
      const result = mod.stageGenesisRoleCandidate(
        scenario.journal,
        0,
        { descriptor, independence, currentRoleCeremony: ceremony },
        2001
      );
      assert.equal(result.state, "EXPIRED");
    });

    it("throws CURRENT_ROLE_CEREMONY_EXPIRED at or after the role ceremony's own expiry while intent remains live, leaving the journal unchanged", function () {
      const scenario = buildScenario({ expiresAt: "5000" });
      const { ceremony, independence, descriptor } = rebindCeremonyAndFactor(scenario, 0, {
        ceremony: { expiresAt: "2000" }
      });
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          scenario.journal,
          0,
          { descriptor, independence, currentRoleCeremony: ceremony },
          2000
        ),
        (error) => error.code === C.CURRENT_ROLE_CEREMONY_EXPIRED
      );
      const stillStaging = mod.validateGenesisStagingJournalRecord(scenario.journal);
      assert.equal(stillStaging.updatedAtUnixSeconds, scenario.journal.updatedAtUnixSeconds);
    });

    it("rejects a role ceremony whose own expiry exceeds the intent's expiry, before now/clock checks", function () {
      const scenario = buildScenario({ expiresAt: "5000" });
      const { ceremony, independence, descriptor } = rebindCeremonyAndFactor(scenario, 0, {
        ceremony: { expiresAt: "6000" }
      });
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          scenario.journal,
          0,
          { descriptor, independence, currentRoleCeremony: ceremony },
          1000
        ),
        (error) => error.code === C.CEREMONY_EXPIRY_EXCEEDS_INTENT_EXPIRY
      );
    });

    it("a later role may be staged under its own independently live ceremony after an earlier one's ceremony has since expired relative to wall clock, without retroactively invalidating the earlier stored slot", function () {
      const scenario = buildScenario();
      let journal = mod.stageGenesisRoleCandidate(
        scenario.journal,
        0,
        { ...scenario.roleInputs[0], currentRoleCeremony: scenario.ceremonies[0] },
        scenario.now + 1
      );
      // Role 0's own ceremony.expiresAt has not literally passed here, but
      // validation only checks the two historical inequalities, never
      // re-checking against current wall clock, so a later stage succeeds
      // regardless of any subsequent narrative time.
      journal = mod.stageGenesisRoleCandidate(
        journal,
        1,
        { ...scenario.roleInputs[1], currentRoleCeremony: scenario.ceremonies[1] },
        scenario.now + 2
      );
      assert.notEqual(journal.manifest["0"], null);
      assert.notEqual(journal.manifest["1"], null);
    });

    it("rejects clock regression", function () {
      const scenario = buildScenario();
      const journal = stageRole(scenario, 0, scenario.now + 10);
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          journal,
          1,
          { ...scenario.roleInputs[1], currentRoleCeremony: scenario.ceremonies[1] },
          scenario.now + 5
        ),
        (error) => error.code === C.CLOCK_REGRESSION_DETECTED
      );
    });
  });

  describe("stageGenesisRoleCandidate -- progressive uniqueness", function () {
    it("rejects a duplicate ceremonyId across roles", function () {
      const scenario = buildScenario();
      const journal = stageRole(scenario, 0);
      scenario.journal = journal;
      const { ceremony, independence, descriptor } = rebindCeremonyAndFactor(scenario, 1, {
        ceremony: { ceremonyId: scenario.ceremonies[0].ceremonyId }
      });
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          scenario.journal,
          1,
          { descriptor, independence, currentRoleCeremony: ceremony },
          scenario.now + 2
        ),
        (error) => error.code === C.CEREMONY_ID_DUPLICATE
      );
    });

    it("rejects a duplicate credentialIdHash between roles 0 and 1", function () {
      const scenario = buildScenario();
      const journal = stageRole(scenario, 0);
      scenario.journal = journal;
      const role0Independence = scenario.roleInputs[0].independence;
      const collidingIndependence = {
        ...scenario.roleInputs[1].independence,
        credentialIdHash: role0Independence.credentialIdHash
      };
      const collidingDescriptor = {
        ...scenario.roleInputs[1].descriptor,
        credentialIdHash: role0Independence.credentialIdHash,
        independenceBindingHash: computePhilCoreV2ConsumerRecoveryIndependenceBinding(collidingIndependence)
      };
      assert.throws(
        () => stageRole(scenario, 1, scenario.now + 2, {
          descriptor: collidingDescriptor,
          independence: collidingIndependence
        }),
        (error) => error.code === C.CREDENTIAL_ID_HASH_DUPLICATE
      );
    });

    it("rejects a duplicate publicVerificationMaterialHash across any role pair", function () {
      const scenario = buildScenario();
      const journal = stageRole(scenario, 0);
      scenario.journal = journal;
      const collidingDescriptor = {
        ...scenario.roleInputs[1].descriptor,
        publicVerificationMaterialHash: scenario.roleInputs[0].descriptor.publicVerificationMaterialHash
      };
      assert.throws(
        () => stageRole(scenario, 1, scenario.now + 2, { descriptor: collidingDescriptor }),
        (error) => error.code === C.PUBLIC_VERIFICATION_MATERIAL_HASH_DUPLICATE
      );
    });

    it("rejects a duplicate custodyDomainCommitment across any role pair", function () {
      const scenario = buildScenario();
      const journal = stageRole(scenario, 0);
      scenario.journal = journal;
      const { ceremony, independence, descriptor } = rebindCeremonyAndFactor(scenario, 1, {
        independence: { custodyDomainCommitment: scenario.roleInputs[0].independence.custodyDomainCommitment }
      });
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          scenario.journal,
          1,
          { descriptor, independence, currentRoleCeremony: ceremony },
          scenario.now + 2
        ),
        (error) => error.code === C.CUSTODY_DOMAIN_COMMITMENT_DUPLICATE
      );
    });
  });

  describe("stageGenesisRoleCandidate -- signer rules", function () {
    it("rejects a caller-supplied signer for roles 0/1 (delegated to the shared factor-policy validator)", function () {
      const scenario = buildScenario();
      assert.throws(
        () => stageRole(scenario, 0, scenario.now + 1, { signer: scenario.roleInputs[2].signer }),
        (error) => error.code === C.FACTOR_POLICY_VALIDATION_FAILED
      );
    });

    it("rejects Role 2 signer aliasing intent.initialValidator", function () {
      const scenario = buildScenario({ initialValidator: fixtures.profiles.standard.factors.offline.signer });
      const journal0 = stageRole(scenario, 0);
      scenario.journal = journal0;
      const journal1 = stageRole(scenario, 1, scenario.now + 2);
      scenario.journal = journal1;
      assert.throws(
        () => stageRole(scenario, 2, scenario.now + 3),
        (error) => error.code === C.SIGNER_ALIASES_INITIAL_VALIDATOR
      );
    });

    it("requires a Role 2 signer (delegated) and stores it verbatim on success", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      assert.equal(journal.manifest["2"].signer, scenario.roleInputs[2].signer);
    });
  });

  describe("terminal transitions", function () {
    it("cancels a live journal to CANCELLED", function () {
      const scenario = buildScenario();
      const result = mod.cancelGenesisStagingJournal(scenario.journal, scenario.now + 5);
      assert.equal(result.state, "CANCELLED");
      assert.equal(result.endReason, "CANCELLED");
    });

    it("cancellation at or after intent expiry yields EXPIRED, not CANCELLED", function () {
      const scenario = buildScenario({ expiresAt: "2000" });
      const result = mod.cancelGenesisStagingJournal(scenario.journal, 2000);
      assert.equal(result.state, "EXPIRED");
      assert.equal(result.endReason, "EXPIRED");
    });

    it("expireGenesisStagingJournalIfNeeded is a no-op before expiry and transitions at/after it", function () {
      const scenario = buildScenario({ expiresAt: "2000" });
      const before = mod.expireGenesisStagingJournalIfNeeded(scenario.journal, 1999);
      assert.equal(before.state, "STAGING");
      assert.equal(before.integrityChecksum, scenario.journal.integrityChecksum);
      const at = mod.expireGenesisStagingJournalIfNeeded(scenario.journal, 2000);
      assert.equal(at.state, "EXPIRED");
    });

    it("supersedes only from STAGING", function () {
      const scenario = buildScenario();
      const superseded = mod.supersedeGenesisStagingJournal(scenario.journal, scenario.now + 1);
      assert.equal(superseded.state, "SUPERSEDED");
      assert.equal(superseded.endReason, "SUPERSEDED");
      assert.throws(
        () => mod.supersedeGenesisStagingJournal(superseded, scenario.now + 2),
        (error) => error.code === C.JOURNAL_NOT_STAGING
      );
    });

    it("rejects further mutation of every terminal state", function () {
      const scenario = buildScenario();
      const cancelled = mod.cancelGenesisStagingJournal(scenario.journal, scenario.now + 1);
      for (const mutator of [
        () => mod.cancelGenesisStagingJournal(cancelled, scenario.now + 2),
        () => mod.expireGenesisStagingJournalIfNeeded(cancelled, scenario.now + 2),
        () => mod.supersedeGenesisStagingJournal(cancelled, scenario.now + 2),
        () => mod.stageGenesisRoleCandidate(
          cancelled,
          0,
          { ...scenario.roleInputs[0], currentRoleCeremony: scenario.ceremonies[0] },
          scenario.now + 2
        )
      ]) {
        assert.throws(mutator, (error) => error.code === C.JOURNAL_NOT_STAGING);
      }
    });

    it("rejects clock regression on cancel/expire/supersede", function () {
      const scenario = buildScenario();
      // updatedAtUnixSeconds only advances on a real mutation, so stage a
      // role first to move the clock forward before testing regression.
      const staged = stageRole(scenario, 0, scenario.now + 50);
      assert.throws(
        () => mod.cancelGenesisStagingJournal(staged, scenario.now + 10),
        (error) => error.code === C.CLOCK_REGRESSION_DETECTED
      );
      assert.throws(
        () => mod.expireGenesisStagingJournalIfNeeded(staged, scenario.now + 10),
        (error) => error.code === C.CLOCK_REGRESSION_DETECTED
      );
      assert.throws(
        () => mod.supersedeGenesisStagingJournal(staged, scenario.now + 10),
        (error) => error.code === C.CLOCK_REGRESSION_DETECTED
      );
    });
  });

  describe("allGenesisStagingSlotsPopulated", function () {
    it("is false until all three roles are staged, true after", function () {
      const scenario = buildScenario();
      assert.equal(mod.allGenesisStagingSlotsPopulated(scenario.journal), false);
      const staged0 = stageRole(scenario, 0);
      assert.equal(mod.allGenesisStagingSlotsPopulated(staged0), false);
      const { journal } = stageAllThree(scenario);
      assert.equal(mod.allGenesisStagingSlotsPopulated(journal), true);
    });

    it("fully validates the record before returning its predicate", function () {
      const scenario = buildScenario();
      const forged = { ...scenario.journal, manifest: { ...scenario.journal.manifest, extra: null } };
      assert.throws(
        () => mod.allGenesisStagingSlotsPopulated(forged),
        (error) => error.code === C.MANIFEST_EXTRA_KEY
      );
    });
  });

  describe("computeGenesisStagingJournalChecksum -- known answer", function () {
    it("independently reproduces the empty-manifest journal checksum", function () {
      const scenario = buildScenario();
      const { integrityChecksum, ...withoutChecksum } = scenario.journal;
      const prefix = Buffer.from(
        "PHILCORE_V2_GENESIS_CEREMONY_STAGING_JOURNAL_V1|",
        "utf8"
      );
      const projection = Buffer.from(
        JSON.stringify({
          schemaVersion: withoutChecksum.schemaVersion,
          formatProvenance: withoutChecksum.formatProvenance,
          intentVersion: withoutChecksum.intentVersion,
          intentId: withoutChecksum.intentId,
          chainId: withoutChecksum.chainId,
          entryPoint: withoutChecksum.entryPoint,
          factoryBinding: withoutChecksum.factoryBinding,
          confirmationTarget: withoutChecksum.confirmationTarget,
          verifier: withoutChecksum.verifier,
          verifierRuntimeCodeHash: withoutChecksum.verifierRuntimeCodeHash,
          accountCreationBytecodeHash: withoutChecksum.accountCreationBytecodeHash,
          accountVersionId: withoutChecksum.accountVersionId,
          securityModelId: withoutChecksum.securityModelId,
          recoveryDomainId: withoutChecksum.recoveryDomainId,
          ownerCommitment: withoutChecksum.ownerCommitment,
          identityBindingCommitment: withoutChecksum.identityBindingCommitment,
          initialValidator: withoutChecksum.initialValidator,
          validatorVerifierKind: withoutChecksum.validatorVerifierKind,
          validatorKeyIdBinding: withoutChecksum.validatorKeyIdBinding,
          validatorCommitment: withoutChecksum.validatorCommitment,
          validatorEpoch: withoutChecksum.validatorEpoch,
          recoveryEpoch: withoutChecksum.recoveryEpoch,
          recoveryDelaySeconds: withoutChecksum.recoveryDelaySeconds,
          recoveryExpirySeconds: withoutChecksum.recoveryExpirySeconds,
          userSalt: withoutChecksum.userSalt,
          expiresAt: withoutChecksum.expiresAt,
          genesisDeploymentIntentHash: withoutChecksum.genesisDeploymentIntentHash,
          state: withoutChecksum.state,
          createdAtUnixSeconds: withoutChecksum.createdAtUnixSeconds,
          updatedAtUnixSeconds: withoutChecksum.updatedAtUnixSeconds,
          manifest: { "0": null, "1": null, "2": null },
          endReason: withoutChecksum.endReason
        }),
        "utf8"
      );
      const expected = `0x${createHash("sha256").update(prefix).update(projection).digest("hex")}`;
      assert.equal(integrityChecksum, expected);
      assert.equal(mod.computeGenesisStagingJournalChecksum(withoutChecksum), expected);
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum(scenario.journal),
        (error) => error.code === C.JOURNAL_EXTRA_KEY
      );
    });

    it("independently reproduces the fully-populated three-role journal checksum", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const manifestProjection = {};
      for (const slot of ["0", "1", "2"]) {
        const entry = journal.manifest[slot];
        manifestProjection[slot] = {
          role: entry.role,
          ceremonyId: entry.ceremonyId,
          ceremonyExpiresAtUnixSeconds: entry.ceremonyExpiresAtUnixSeconds,
          genesisEnrollmentCeremonyHash: entry.genesisEnrollmentCeremonyHash,
          descriptor: entry.descriptor,
          independence: entry.independence,
          signer: entry.signer,
          factorCommitment: entry.factorCommitment,
          stagedAtUnixSeconds: entry.stagedAtUnixSeconds
        };
      }
      const { integrityChecksum, ...withoutChecksum } = journal;
      const projection = Buffer.from(
        JSON.stringify({
          schemaVersion: withoutChecksum.schemaVersion,
          formatProvenance: withoutChecksum.formatProvenance,
          intentVersion: withoutChecksum.intentVersion,
          intentId: withoutChecksum.intentId,
          chainId: withoutChecksum.chainId,
          entryPoint: withoutChecksum.entryPoint,
          factoryBinding: withoutChecksum.factoryBinding,
          confirmationTarget: withoutChecksum.confirmationTarget,
          verifier: withoutChecksum.verifier,
          verifierRuntimeCodeHash: withoutChecksum.verifierRuntimeCodeHash,
          accountCreationBytecodeHash: withoutChecksum.accountCreationBytecodeHash,
          accountVersionId: withoutChecksum.accountVersionId,
          securityModelId: withoutChecksum.securityModelId,
          recoveryDomainId: withoutChecksum.recoveryDomainId,
          ownerCommitment: withoutChecksum.ownerCommitment,
          identityBindingCommitment: withoutChecksum.identityBindingCommitment,
          initialValidator: withoutChecksum.initialValidator,
          validatorVerifierKind: withoutChecksum.validatorVerifierKind,
          validatorKeyIdBinding: withoutChecksum.validatorKeyIdBinding,
          validatorCommitment: withoutChecksum.validatorCommitment,
          validatorEpoch: withoutChecksum.validatorEpoch,
          recoveryEpoch: withoutChecksum.recoveryEpoch,
          recoveryDelaySeconds: withoutChecksum.recoveryDelaySeconds,
          recoveryExpirySeconds: withoutChecksum.recoveryExpirySeconds,
          userSalt: withoutChecksum.userSalt,
          expiresAt: withoutChecksum.expiresAt,
          genesisDeploymentIntentHash: withoutChecksum.genesisDeploymentIntentHash,
          state: withoutChecksum.state,
          createdAtUnixSeconds: withoutChecksum.createdAtUnixSeconds,
          updatedAtUnixSeconds: withoutChecksum.updatedAtUnixSeconds,
          manifest: manifestProjection,
          endReason: withoutChecksum.endReason
        }),
        "utf8"
      );
      const prefix = Buffer.from("PHILCORE_V2_GENESIS_CEREMONY_STAGING_JOURNAL_V1|", "utf8");
      const expected = `0x${createHash("sha256").update(prefix).update(projection).digest("hex")}`;
      assert.equal(integrityChecksum, expected);
    });
  });

  describe("computeGenesisStagingJournalChecksum -- hostile-input boundary", function () {
    it("rejects a missing top-level key", function () {
      const scenario = buildScenario();
      const { integrityChecksum, chainId, ...rest } = scenario.journal;
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum(rest),
        (error) => error.code === C.JOURNAL_MISSING_KEY
      );
    });

    it("rejects an arbitrary extra top-level key beyond the exact thirty-two", function () {
      const scenario = buildScenario();
      const { integrityChecksum, ...withoutChecksum } = scenario.journal;
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({ ...withoutChecksum, extraTopLevelKey: "x" }),
        (error) => error.code === C.JOURNAL_EXTRA_KEY
      );
    });

    it("rejects a missing nested manifest slot key", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const { "2": _drop, ...manifestMissingSlot } = withoutChecksum.manifest;
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: manifestMissingSlot
        }),
        (error) => error.code === C.MANIFEST_MISSING_KEY
      );
    });

    it("rejects a manifest entry with a missing own key", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const { role: _drop, ...entryMissingRole } = withoutChecksum.manifest["0"];
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: { ...withoutChecksum.manifest, "0": entryMissingRole }
        }),
        (error) => error.code === C.MANIFEST_ENTRY_MISSING_KEY
      );
    });

    it("rejects a nested descriptor with an extra own key, and never invokes a hostile toJSON planted alongside it", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      let toJSONCalls = 0;
      const hostileDescriptor = {
        ...withoutChecksum.manifest["0"].descriptor,
        toJSON() {
          toJSONCalls += 1;
          return "LEAKED";
        }
      };
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: {
            ...withoutChecksum.manifest,
            "0": { ...withoutChecksum.manifest["0"], descriptor: hostileDescriptor }
          }
        }),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
      assert.equal(toJSONCalls, 0);
    });

    it("rejects a nested independence with a false-own-key Proxy whose fields are inherited-only", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const hostileIndependence = fakeOwnKeysProxy(
        withoutChecksum.manifest["0"].independence,
        Object.keys(withoutChecksum.manifest["0"].independence)
      );
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: {
            ...withoutChecksum.manifest,
            "0": { ...withoutChecksum.manifest["0"], independence: hostileIndependence }
          }
        }),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("rejects a nested descriptor that is a revoked Proxy", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const { proxy, revoke } = Proxy.revocable(withoutChecksum.manifest["0"].descriptor, {});
      revoke();
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: {
            ...withoutChecksum.manifest,
            "0": { ...withoutChecksum.manifest["0"], descriptor: proxy }
          }
        }),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("rejects a nested descriptor whose getOwnPropertyDescriptor trap throws, without leaking the raw thrown marker", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const marker = { leak: "trap-thrown-value" };
      const hostileDescriptor = new Proxy(withoutChecksum.manifest["0"].descriptor, {
        getOwnPropertyDescriptor() {
          throw marker;
        }
      });
      let caught;
      try {
        mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: {
            ...withoutChecksum.manifest,
            "0": { ...withoutChecksum.manifest["0"], descriptor: hostileDescriptor }
          }
        });
      } catch (error) {
        caught = error;
      }
      assertMarkerUnreachable(caught, marker);
      assert.equal(caught.code, C.MANIFEST_ENTRY_PROPERTY_READ_FAILED);
    });

    // --- Hostile object-valued leaves. Every one of these values is read
    // successfully (a guarded property read never invokes toJSON -- only
    // JSON.stringify does), so each test proves the checksum function
    // rejects the object BEFORE ever handing it to JSON.stringify, and the
    // hostile toJSON counter must therefore stay at exactly zero.
    function hostileLeaf(counters, name) {
      return {
        toJSON() {
          counters[name] = (counters[name] || 0) + 1;
          return "LEAKED";
        }
      };
    }

    it("rejects an object-valued top-level intent field (intentId) with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { integrityChecksum, ...withoutChecksum } = scenario.journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          intentId: hostileLeaf(counters, "intentId")
        }),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
      assert.equal(counters.intentId || 0, 0);
    });

    it("rejects an object-valued schemaVersion (must be number-shaped) with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { integrityChecksum, ...withoutChecksum } = scenario.journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          schemaVersion: hostileLeaf(counters, "schemaVersion")
        }),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
      assert.equal(counters.schemaVersion || 0, 0);
    });

    it("rejects an object-valued state with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { integrityChecksum, ...withoutChecksum } = scenario.journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          state: hostileLeaf(counters, "state")
        }),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
      assert.equal(counters.state || 0, 0);
    });

    it("rejects an object-valued createdAtUnixSeconds timestamp with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { integrityChecksum, ...withoutChecksum } = scenario.journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          createdAtUnixSeconds: hostileLeaf(counters, "createdAtUnixSeconds")
        }),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
      assert.equal(counters.createdAtUnixSeconds || 0, 0);
    });

    it("rejects an object-valued endReason (must be null or string) with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { integrityChecksum, ...withoutChecksum } = scenario.journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          endReason: hostileLeaf(counters, "endReason")
        }),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
      assert.equal(counters.endReason || 0, 0);
    });

    it("rejects an object-valued manifest-entry scalar (stagedAtUnixSeconds) with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: {
            ...withoutChecksum.manifest,
            "0": {
              ...withoutChecksum.manifest["0"],
              stagedAtUnixSeconds: hostileLeaf(counters, "stagedAtUnixSeconds")
            }
          }
        }),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
      assert.equal(counters.stagedAtUnixSeconds || 0, 0);
    });

    it("rejects an object-valued descriptor field with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: {
            ...withoutChecksum.manifest,
            "0": {
              ...withoutChecksum.manifest["0"],
              descriptor: {
                ...withoutChecksum.manifest["0"].descriptor,
                descriptorVersion: hostileLeaf(counters, "descriptorVersion")
              }
            }
          }
        }),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
      assert.equal(counters.descriptorVersion || 0, 0);
    });

    it("rejects an object-valued independence field with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: {
            ...withoutChecksum.manifest,
            "0": {
              ...withoutChecksum.manifest["0"],
              independence: {
                ...withoutChecksum.manifest["0"].independence,
                bindingVersion: hostileLeaf(counters, "bindingVersion")
              }
            }
          }
        }),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
      assert.equal(counters.bindingVersion || 0, 0);
    });

    it("rejects an object-valued signer (must be null or string) with a hostile toJSON, invoked zero times", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const counters = {};
      assert.throws(
        () => mod.computeGenesisStagingJournalChecksum({
          ...withoutChecksum,
          manifest: {
            ...withoutChecksum.manifest,
            "2": { ...withoutChecksum.manifest["2"], signer: hostileLeaf(counters, "signer") }
          }
        }),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
      assert.equal(counters.signer || 0, 0);
    });

    it("never invokes a globally polluted Object.prototype.toJSON anywhere in checksum or size-measurement serialization", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum, ...withoutChecksum } = journal;
      const cleanChecksum = mod.computeGenesisStagingJournalChecksum(withoutChecksum);

      // A grossly oversized manifest-entry field, forged into an otherwise
      // structurally valid journal. validateGenesisStagingJournalRecord
      // reaches extractTentativeManifestEntry's byte-ceiling check (which
      // exercises compactStoredEntryBytes/nullProtoClone, the
      // size-measurement path under test) entirely before any
      // genesis-protocol hash recomputation runs -- this isolates the
      // size-measurement serialization path from ethers/genesis-protocol
      // internals that are a different module's concern and are not
      // expected to tolerate an arbitrary global prototype pollution.
      const hostileEntry = {
        ...withoutChecksum.manifest["0"],
        factorCommitment: `0x${"a".repeat(mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES * 2)}`
      };
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { ...withoutChecksum.manifest, "0": hostileEntry }
      };
      const codeFor = (withoutChecksumRecord) => {
        try {
          mod.validateGenesisStagingJournalRecord({
            ...withoutChecksumRecord,
            integrityChecksum: mod.computeGenesisStagingJournalChecksum(withoutChecksumRecord)
          });
          return null;
        } catch (error) {
          return error.code;
        }
      };
      assert.equal(codeFor(forgedWithoutChecksum), C.MANIFEST_ENTRY_OVERSIZED);

      let pollutedCalls = 0;
      // eslint-disable-next-line no-extend-native
      Object.prototype.toJSON = function toJSON() {
        pollutedCalls += 1;
        return { POLLUTED: true };
      };
      try {
        const checksumUnderPollution = mod.computeGenesisStagingJournalChecksum(withoutChecksum);
        assert.equal(checksumUnderPollution, cleanChecksum);
        assert.equal(codeFor(forgedWithoutChecksum), C.MANIFEST_ENTRY_OVERSIZED);
        assert.equal(pollutedCalls, 0);
      } finally {
        delete Object.prototype.toJSON;
      }
    });
  });

  describe("validateGenesisStagingJournalRecord -- closed reconstruction against forged records", function () {
    // Builds a forged record from a genuinely valid one, tampers a field
    // that does NOT participate in the stored checksum's own input
    // integrity in an obviously-detectable way, then recomputes the
    // checksum over the tampered record so the checksum itself is
    // internally "consistent" -- proving the forgery is caught by an
    // independently reconstructed invariant, not merely by a stale
        // checksum.
    function forge(journal, mutate) {
      const draft = JSON.parse(JSON.stringify(journal));
      mutate(draft);
      delete draft.integrityChecksum;
      draft.integrityChecksum = mod.computeGenesisStagingJournalChecksum(draft);
      return draft;
    }

    it("accepts a genuinely valid empty and fully-populated record", function () {
      const scenario = buildScenario();
      assert.doesNotThrow(() => mod.validateGenesisStagingJournalRecord(scenario.journal));
      const { journal } = stageAllThree(scenario);
      const validated = mod.validateGenesisStagingJournalRecord(journal);
      assert.equal(validated.integrityChecksum, journal.integrityChecksum);
    });

    it("rejects a forged manifest prefix (role 1 populated while role 0 is null), even with a recomputed checksum", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        draft.manifest["0"] = null;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
    });

    it("rejects an invalid prefix combined with a wrong-role entry as MANIFEST_SEQUENCE_INVALID, not MANIFEST_SLOT_ROLE_MISMATCH", function () {
      // {0: null, 1: <genuine role-0 entry>, 2: null}: an invalid populated-
      // slot shape (only slot 1 populated) whose entry's own role field
      // ("0") disagrees with its manifest slot ("1"). Per-entry inspection
      // (extractTentativeManifestEntry) would throw MANIFEST_SLOT_ROLE_
      // MISMATCH on this entry if it ran; the manifest-shape check must
      // outrank it and never let per-entry inspection run at all.
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        draft.manifest["1"] = draft.manifest["0"];
        draft.manifest["0"] = null;
        draft.manifest["2"] = null;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
    });

    it("rejects an invalid prefix even when the sole populated entry's own role matches its slot (the shape alone is the defect)", function () {
      // {0: null, 1: null, 2: <genuine role-2 entry>}: the entry is
      // internally self-consistent (role "2" in slot "2"), so per-entry
      // inspection alone would not object to it -- only the populated-slot
      // shape itself ({2} is not one of {}, {0}, {0,1}, {0,1,2}) is
      // defective. Proves the shape check does not merely happen to fire
      // as a side effect of some other per-entry defect.
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        draft.manifest["0"] = null;
        draft.manifest["1"] = null;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
    });

    it("rejects an invalid prefix combined with a non-null signer defect as MANIFEST_SEQUENCE_INVALID, not MANIFEST_ENTRY_SIGNER_MUST_BE_NULL", function () {
      // {0: null, 1: <role-1 entry, role matches slot, but signer forged
      // non-null>, 2: null}: role/slot agreement alone would let per-entry
      // inspection proceed past the role check to the signer check, which
      // would throw MANIFEST_ENTRY_SIGNER_MUST_BE_NULL if per-entry
      // inspection ran at all. The shape check must outrank it.
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        draft.manifest["1"].signer = draft.manifest["2"].signer;
        draft.manifest["0"] = null;
        draft.manifest["2"] = null;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
    });

    it("rejects an invalid prefix combined with a malformed nested descriptor as MANIFEST_SEQUENCE_INVALID", function () {
      // Checksum is computed over the genuine (pre-mutation) record --
      // computeGenesisStagingJournalChecksum's own exact-key verification
      // would otherwise reject the deliberately malformed descriptor before
      // validateGenesisStagingJournalRecord is ever reached. The resulting
      // integrityChecksum mismatch is immaterial: MANIFEST_SEQUENCE_INVALID
      // must fire long before the checksum comparison, which is checked last.
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { independenceBindingHash: _drop, ...descriptorMissingKey } = journal.manifest["1"].descriptor;
      const hostileEntry = { ...journal.manifest["1"], descriptor: descriptorMissingKey };
      const { integrityChecksum, ...withoutChecksum } = journal;
      const forged = {
        ...withoutChecksum,
        manifest: { "0": null, "1": hostileEntry, "2": null },
        integrityChecksum
      };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
    });

    it("rejects an invalid prefix combined with a malformed nested independence as MANIFEST_SEQUENCE_INVALID", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const hostileEntry = {
        ...journal.manifest["1"],
        independence: { ...journal.manifest["1"].independence, extraKey: "x" }
      };
      const { integrityChecksum, ...withoutChecksum } = journal;
      const forged = {
        ...withoutChecksum,
        manifest: { "0": null, "1": hostileEntry, "2": null },
        integrityChecksum
      };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
    });

    it("rejects an invalid prefix combined with a grossly oversized entry as MANIFEST_SEQUENCE_INVALID, not MANIFEST_ENTRY_OVERSIZED", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const hostileEntry = {
        ...journal.manifest["1"],
        factorCommitment: `0x${"a".repeat(mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES * 2)}`
      };
      const { integrityChecksum, ...withoutChecksum } = journal;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { "0": null, "1": hostileEntry, "2": null }
      };
      const forged = {
        ...forgedWithoutChecksum,
        integrityChecksum: mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum)
      };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
    });

    it("never invokes a deep getter inside an out-of-sequence populated entry before rejecting the shape", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      let reads = 0;
      // Base entry is role-correct for slot 1 (role "1"), so the only
      // defect under test is the invalid populated-slot shape itself --
      // not a compounded role mismatch.
      const hostileEntry = { ...journal.manifest["1"] };
      Object.defineProperty(hostileEntry, "role", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          return journal.manifest["1"].role;
        }
      });
      const { integrityChecksum, ...withoutChecksum } = journal;
      // The checksum is computed over the genuine (pre-instrumentation)
      // entry -- getOwnPropertyDescriptor on the instrumented copy still
      // reports an accessor property, which computeGenesisStagingJournalChecksum's
      // own guarded read would legitimately invoke, conflating it with the
      // read count under test. Using the genuine record's own checksum
      // keeps that count isolated to validateGenesisStagingJournalRecord alone.
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { "0": null, "1": hostileEntry, "2": null }
      };
      const forged = { ...forgedWithoutChecksum, integrityChecksum };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
      assert.equal(reads, 0);
    });

    it("never invokes a Proxy trap inside an out-of-sequence populated entry before rejecting the shape", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      let trapCalls = 0;
      const hostileEntry = new Proxy(journal.manifest["1"], {
        get(target, prop, receiver) {
          trapCalls += 1;
          return Reflect.get(target, prop, receiver);
        },
        has(target, prop) {
          trapCalls += 1;
          return Reflect.has(target, prop);
        },
        ownKeys(target) {
          trapCalls += 1;
          return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor(target, prop) {
          trapCalls += 1;
          return Reflect.getOwnPropertyDescriptor(target, prop);
        }
      });
      const { integrityChecksum, ...withoutChecksum } = journal;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { "0": null, "1": hostileEntry, "2": null }
      };
      const forged = { ...forgedWithoutChecksum, integrityChecksum };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
      assert.equal(trapCalls, 0);
    });

    it("never inspects the contents of a revoked Proxy inside an out-of-sequence populated entry before rejecting the shape", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { proxy, revoke } = Proxy.revocable(journal.manifest["0"], {});
      revoke();
      const { integrityChecksum, ...withoutChecksum } = journal;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { "0": null, "1": proxy, "2": null }
      };
      // A revoked Proxy cannot be safely passed through computeGenesisStagingJournalChecksum
      // (any guarded read of its contents would throw), so the checksum
      // here is deliberately taken from the genuine pre-revocation record --
      // the resulting integrityChecksum mismatch is immaterial, since
      // MANIFEST_SEQUENCE_INVALID must fire first, well before the
      // checksum comparison (checked last) is ever reached.
      const forged = { ...forgedWithoutChecksum, integrityChecksum };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SEQUENCE_INVALID
      );
    });

    it("never reads a hostile out-of-sequence entry whose properties throw, so a thrown marker cannot escape or appear as a raw cause", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const marker = { leak: "trap-thrown-value" };
      const hostileEntry = { ...journal.manifest["1"] };
      Object.defineProperty(hostileEntry, "role", {
        enumerable: true,
        configurable: true,
        get() {
          throw marker;
        }
      });
      const { integrityChecksum, ...withoutChecksum } = journal;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { "0": null, "1": hostileEntry, "2": null }
      };
      const forged = { ...forgedWithoutChecksum, integrityChecksum };
      let caught;
      try {
        mod.validateGenesisStagingJournalRecord(forged);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.MANIFEST_SEQUENCE_INVALID);
      assertMarkerUnreachable(caught, marker);
    });

    it("rejects a forged entry.role that disagrees with its manifest slot", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        draft.manifest["0"].role = "1";
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SLOT_ROLE_MISMATCH
      );
    });

    it("rejects a forged non-null signer stored for role 0/1, never silently omitting it", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        draft.manifest["0"].signer = journal.manifest["2"].signer;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_SIGNER_MUST_BE_NULL
      );
    });

    it("rejects a forged role-2 signer aliasing initialValidator, self-consistently bound so factor-policy itself would accept it", function () {
      // Live staging already independently proves SIGNER_ALIASES_INITIAL_
      // VALIDATOR at staging time (see the signer-rules describe block
      // above), which necessarily means such a role-2 entry can never be
      // produced via the public staging path. To prove stored-record
      // validation *also* independently re-derives and rejects the alias
      // -- defense against a directly forged/edited file that never went
      // through live staging at all -- a role-2 entry is built here via
      // the same shared factor-policy validator the module itself
      // delegates to, with its public material genuinely, self-
      // consistently bound to the alias signer (so factor-policy's own
      // binding check would not itself catch it), then injected directly.
      const {
        validatePhilCoreV2ConsumerRecoveryFactorPolicy,
        computePhilCoreV2Secp256k1PublicMaterialHash
      } = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      scenario.journal = staged0;
      const staged1 = stageRole(scenario, 1, scenario.now + 2);

      const aliasSigner = scenario.intent.initialValidator;
      const descriptor2 = {
        ...scenario.roleInputs[2].descriptor,
        publicVerificationMaterialHash: computePhilCoreV2Secp256k1PublicMaterialHash({ signer: aliasSigner })
      };
      const result2 = validatePhilCoreV2ConsumerRecoveryFactorPolicy(
        { descriptor: descriptor2, independence: scenario.roleInputs[2].independence, signer: aliasSigner },
        2
      );
      const ceremony2 = scenario.ceremonies[2];
      const ceremonyHash2 = genesis.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(ceremony2);

      const forged = JSON.parse(JSON.stringify(staged1));
      forged.manifest["2"] = {
        role: "2",
        ceremonyId: ceremony2.ceremonyId,
        ceremonyExpiresAtUnixSeconds: ceremony2.expiresAt,
        genesisEnrollmentCeremonyHash: ceremonyHash2,
        descriptor: {
          descriptorVersion: "3",
          accountVersionId: result2.factor.descriptor.accountVersionId,
          securityModelId: result2.factor.descriptor.securityModelId,
          recoveryDomainId: result2.factor.descriptor.recoveryDomainId,
          role: "2",
          verifierKind: String(result2.factor.descriptor.verifierKind),
          publicVerificationMaterialHash: result2.factor.descriptor.publicVerificationMaterialHash,
          credentialIdHash: result2.factor.descriptor.credentialIdHash,
          rpIdHash: result2.factor.descriptor.rpIdHash,
          originPolicyHash: result2.factor.descriptor.originPolicyHash,
          independenceBindingHash: result2.factor.descriptor.independenceBindingHash,
          userVerificationPolicy: String(result2.factor.descriptor.userVerificationPolicy),
          backupPolicy: String(result2.factor.descriptor.backupPolicy),
          authenticatorAttachmentPolicy: String(result2.factor.descriptor.authenticatorAttachmentPolicy),
          attestationPolicy: String(result2.factor.descriptor.attestationPolicy),
          credentialGeneration: "1"
        },
        independence: {
          bindingVersion: String(result2.factor.independence.bindingVersion),
          role: "2",
          authenticatorClass: String(result2.factor.independence.authenticatorClass),
          synchronizationClass: String(result2.factor.independence.synchronizationClass),
          independenceAssurance: String(result2.factor.independence.independenceAssurance),
          credentialIdHash: result2.factor.independence.credentialIdHash,
          enrollmentCeremonyHash: ceremonyHash2,
          attestationEvidenceHash: result2.factor.independence.attestationEvidenceHash,
          custodyDomainCommitment: result2.factor.independence.custodyDomainCommitment,
          credentialGeneration: "1"
        },
        signer: aliasSigner,
        factorCommitment: result2.factorCommitment,
        stagedAtUnixSeconds: staged1.updatedAtUnixSeconds
      };
      forged.updatedAtUnixSeconds = staged1.updatedAtUnixSeconds;
      delete forged.integrityChecksum;
      forged.integrityChecksum = mod.computeGenesisStagingJournalChecksum(forged);

      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.SIGNER_ALIASES_INITIAL_VALIDATOR
      );
    });

    it("rejects a recomputed ceremony-hash mismatch (forged stored ceremonyId)", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        draft.manifest["0"].ceremonyId = `0x${"ef".repeat(32)}`;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_CEREMONY_HASH_RECOMPUTATION_MISMATCH
      );
    });

    it("rejects a forged factorCommitment that disagrees with the recomputed value", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        draft.manifest["0"].factorCommitment = `0x${"12".repeat(32)}`;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_FACTOR_COMMITMENT_MISMATCH
      );
    });

    it("rejects a forged intent field that changes the recomputed intent hash", function () {
      const scenario = buildScenario();
      const forged = forge(scenario.journal, (draft) => {
        draft.userSalt = `0x${"77".repeat(32)}`;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_CONTEXT_HASH_MISMATCH
      );
    });

    it("rejects out-of-order (decreasing) staged times across populated slots", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const forged = forge(journal, (draft) => {
        const laterThanRole2 = String(BigInt(draft.manifest["2"].stagedAtUnixSeconds) + 100n);
        draft.manifest["0"].stagedAtUnixSeconds = laterThanRole2;
        draft.updatedAtUnixSeconds = draft.manifest["2"].stagedAtUnixSeconds;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_STAGED_AT_SEQUENCE_INVALID
      );
    });

    it("rejects a forged historical chronology: journal createdAtUnixSeconds after a populated entry's own stagedAtUnixSeconds", function () {
      // The exact scenario: a forged terminal record with
      // createdAtUnixSeconds "1000", a populated entry with
      // stagedAtUnixSeconds "999", otherwise valid chronology, semantics,
      // and a recomputed checksum. CANCELLED (not EXPIRED) is used so the
      // terminal updatedAt-floor check (updated >= max(createdAt,
      // lastPopulated.stagedAt)) is satisfiable without also tripping the
      // unrelated EXPIRED-state timestamp invariant; updatedAt is set to
      // exactly that floor (1000) so JOURNAL_TIMESTAMP_ORDER_INVALID and
      // JOURNAL_UPDATED_AT_TERMINAL_INVALID both stay satisfied and only
      // the historical-chronology invariant itself is violated.
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const cancelled = mod.cancelGenesisStagingJournal(staged0, scenario.now + 20);
      const forged = forge(cancelled, (draft) => {
        draft.createdAtUnixSeconds = "1000";
        draft.manifest["0"].stagedAtUnixSeconds = "999";
        draft.updatedAtUnixSeconds = "1000";
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_STAGED_AT_ORDER_INVALID
      );
    });

    it("rejects a STAGING journal whose updatedAt disagrees with the last populated entry's stagedAt", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forge(staged0, (draft) => {
        draft.updatedAtUnixSeconds = String(BigInt(draft.updatedAtUnixSeconds) + 5n);
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_UPDATED_AT_STAGING_MISMATCH
      );
    });

    it("rejects an empty STAGING journal whose updatedAt disagrees with createdAt", function () {
      const scenario = buildScenario();
      const forged = forge(scenario.journal, (draft) => {
        draft.updatedAtUnixSeconds = String(BigInt(draft.updatedAtUnixSeconds) + 1n);
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_UPDATED_AT_STAGING_MISMATCH
      );
    });

    it("rejects a terminal journal whose updatedAt precedes the final populated entry's stagedAt", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const cancelled = mod.cancelGenesisStagingJournal(staged0, scenario.now + 20);
      const forged = forge(cancelled, (draft) => {
        draft.updatedAtUnixSeconds = draft.manifest["0"].stagedAtUnixSeconds;
        // Move strictly before the entry's own staged time to trip the floor.
        draft.updatedAtUnixSeconds = String(BigInt(draft.manifest["0"].stagedAtUnixSeconds) - 1n);
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_UPDATED_AT_TERMINAL_INVALID
      );
    });

    it("rejects state/endReason inconsistency", function () {
      const scenario = buildScenario();
      const cancelled = mod.cancelGenesisStagingJournal(scenario.journal, scenario.now + 5);
      const forged = forge(cancelled, (draft) => {
        draft.endReason = "EXPIRED";
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_STATE_END_REASON_MISMATCH
      );
    });

    it("rejects a present-but-wrong schemaVersion distinctly from a missing key", function () {
      const scenario = buildScenario();
      const forged = forge(scenario.journal, (draft) => {
        draft.schemaVersion = 2;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_SCHEMA_VERSION_UNSUPPORTED
      );
    });

    it("rejects a present-but-wrong formatProvenance distinctly from a missing key", function () {
      const scenario = buildScenario();
      const forged = forge(scenario.journal, (draft) => {
        draft.formatProvenance = "wrong-provenance";
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_FORMAT_PROVENANCE_INVALID
      );
    });

    it("rejects a checksum-mismatched record last, after every other invariant has already passed", function () {
      const scenario = buildScenario();
      const tampered = { ...scenario.journal, updatedAtUnixSeconds: scenario.journal.updatedAtUnixSeconds };
      const withBadChecksum = JSON.parse(JSON.stringify(tampered));
      withBadChecksum.integrityChecksum = `0x${"ab".repeat(32)}`;
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(withBadChecksum),
        (error) => error.code === C.JOURNAL_CHECKSUM_MISMATCH
      );
    });

    it("rejects a malformed checksum format before attempting a checksum comparison", function () {
      const scenario = buildScenario();
      const withBadFormat = JSON.parse(JSON.stringify(scenario.journal));
      withBadFormat.integrityChecksum = "0xnothex";
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(withBadFormat),
        (error) => error.code === C.JOURNAL_CHECKSUM_FORMAT_INVALID
      );
    });
  });

  describe("stored-value numeric strictness -- every stored numeric field must already be a canonical decimal string", function () {
    // JSON.stringify cannot serialize a bigint (it throws), and the
    // checksum function's own exact-key verification would reject an
    // added/removed nested key -- so the checksum is computed over the
    // genuine (pre-mutation) values first, and the hostile mutation is
    // applied only afterward, directly, never through the forge() helper's
    // JSON round-trip. The checksum on the returned forged record is
    // therefore stale, but that is immaterial: every test below expects
    // rejection at the type/shape check, which runs long before the
    // checksum-mismatch comparison (checked last).
    function forgeDirect(journal, mutate) {
      const { integrityChecksum, ...withoutChecksum } = journal;
      const draft = {
        ...withoutChecksum,
        integrityChecksum,
        manifest: {
          "0": journal.manifest["0"] === null ? null : { ...journal.manifest["0"] },
          "1": journal.manifest["1"] === null ? null : { ...journal.manifest["1"] },
          "2": journal.manifest["2"] === null ? null : { ...journal.manifest["2"] }
        }
      };
      mutate(draft);
      return draft;
    }

    it("rejects a stored createdAtUnixSeconds forged as a bigint rather than a canonical decimal string", function () {
      const scenario = buildScenario();
      const forged = forgeDirect(scenario.journal, (draft) => {
        draft.createdAtUnixSeconds = 1000n;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
    });

    it("rejects a stored updatedAtUnixSeconds forged as a bigint rather than a canonical decimal string", function () {
      const scenario = buildScenario();
      const forged = forgeDirect(scenario.journal, (draft) => {
        draft.updatedAtUnixSeconds = 1000n;
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
    });

    it("rejects a stored manifest entry's stagedAtUnixSeconds forged as a bigint rather than a canonical decimal string", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forgeDirect(staged0, (draft) => {
        draft.manifest["0"] = { ...draft.manifest["0"], stagedAtUnixSeconds: 999n };
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("rejects a stored manifest entry's ceremonyExpiresAtUnixSeconds forged as a bigint rather than a canonical decimal string", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forgeDirect(staged0, (draft) => {
        draft.manifest["0"] = {
          ...draft.manifest["0"],
          ceremonyExpiresAtUnixSeconds: BigInt(draft.manifest["0"].ceremonyExpiresAtUnixSeconds)
        };
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("rejects a stored descriptor numeric field forged as a bigint rather than a canonical decimal string", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forgeDirect(staged0, (draft) => {
        draft.manifest["0"] = {
          ...draft.manifest["0"],
          descriptor: { ...draft.manifest["0"].descriptor, role: 0n }
        };
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("rejects a stored independence numeric field forged as a bigint rather than a canonical decimal string", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forgeDirect(staged0, (draft) => {
        draft.manifest["0"] = {
          ...draft.manifest["0"],
          independence: { ...draft.manifest["0"].independence, credentialGeneration: 1n }
        };
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("rejects a stored descriptor field forged as a JavaScript number rather than a canonical decimal string", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forgeDirect(staged0, (draft) => {
        draft.manifest["0"] = {
          ...draft.manifest["0"],
          descriptor: { ...draft.manifest["0"].descriptor, credentialGeneration: 1 }
        };
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("rejects a stored manifest entry role stored as a JavaScript number rather than the string \"0\"/\"1\"/\"2\"", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forgeDirect(staged0, (draft) => {
        draft.manifest["0"] = { ...draft.manifest["0"], role: 0 };
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_SLOT_ROLE_MISMATCH
      );
    });

    it("stores a manifest entry's role as the string \"0\"/\"1\"/\"2\", never a JavaScript number, on a genuinely staged entry", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      assert.equal(typeof journal.manifest["0"].role, "string");
      assert.equal(typeof journal.manifest["1"].role, "string");
      assert.equal(typeof journal.manifest["2"].role, "string");
      assert.equal(journal.manifest["0"].role, "0");
      assert.equal(journal.manifest["1"].role, "1");
      assert.equal(journal.manifest["2"].role, "2");
    });

    it("rejects a stored descriptor with an extra own key beyond the exact sixteen -- no arbitrary Record<string, string> escape hatch", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forgeDirect(staged0, (draft) => {
        draft.manifest["0"] = {
          ...draft.manifest["0"],
          descriptor: { ...draft.manifest["0"].descriptor, extraKey: "1" }
        };
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("rejects a stored independence with a missing own key out of the exact ten", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const forged = forgeDirect(staged0, (draft) => {
        const { bindingVersion: _drop, ...rest } = draft.manifest["0"].independence;
        draft.manifest["0"] = { ...draft.manifest["0"], independence: rest };
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });
  });

  describe("hostile-surface adversarial matrix", function () {
    it("rejects a false-own-key Proxy journal whose fields are inherited-only", function () {
      const scenario = buildScenario();
      const hostile = fakeOwnKeysProxy(scenario.journal, Object.keys(scenario.journal));
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(hostile),
        (error) => error.code === C.JOURNAL_MISSING_KEY
      );
    });

    it("rejects a false-own-key Proxy candidate roleInput whose fields are inherited-only", function () {
      const scenario = buildScenario();
      const real = { ...scenario.roleInputs[0], currentRoleCeremony: scenario.ceremonies[0] };
      const hostile = fakeOwnKeysProxy(real, Object.keys(real));
      assert.throws(
        () => mod.stageGenesisRoleCandidate(scenario.journal, 0, hostile, scenario.now + 1),
        (error) => error.code === C.CANDIDATE_INPUT_MISSING_KEY
      );
    });

    it("rejects a false-own-key Proxy ceremony whose fields are inherited-only", function () {
      const scenario = buildScenario();
      const hostile = fakeOwnKeysProxy(scenario.ceremonies[0], Object.keys(scenario.ceremonies[0]));
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          scenario.journal,
          0,
          { ...scenario.roleInputs[0], currentRoleCeremony: hostile },
          scenario.now + 1
        ),
        (error) => error.code === C.CANDIDATE_INPUT_MISSING_KEY
      );
    });

    it("rejects a false-own-key Proxy manifest entry whose fields are inherited-only", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const real = staged0.manifest["0"];
      const hostile = fakeOwnKeysProxy(real, Object.keys(real));
      const forged = { ...staged0, manifest: { ...staged0.manifest, "0": hostile } };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_MISSING_KEY
      );
    });

    it("rejects a symbol own key and a non-enumerable extra own key on the intent", function () {
      const scenario = buildScenario();
      const withSymbol = validIntentFields();
      withSymbol[Symbol("extra")] = "x";
      assert.throws(
        () => mod.createGenesisStagingJournal(withSymbol, 1000),
        (error) => error.code === C.JOURNAL_EXTRA_KEY
      );
      const withHidden = validIntentFields();
      Object.defineProperty(withHidden, "hidden", { value: "x", enumerable: false, configurable: true });
      assert.throws(
        () => mod.createGenesisStagingJournal(withHidden, 1000),
        (error) => error.code === C.JOURNAL_EXTRA_KEY
      );
    });

    it("contains an ownKeys trap that throws on the journal", function () {
      const scenario = buildScenario();
      const hostile = new Proxy(scenario.journal, {
        ownKeys() {
          throw new Error("enumeration hostile");
        }
      });
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(hostile),
        (error) => error.code === C.JOURNAL_ENUMERATION_FAILED
      );
    });

    it("contains a getOwnPropertyDescriptor trap that throws, without leaking the raw marker", function () {
      const scenario = buildScenario();
      const marker = { poison: "gopd-marker" };
      const hostile = new Proxy(scenario.journal, {
        getOwnPropertyDescriptor(target, key) {
          if (key === "userSalt") throw marker;
          return Reflect.getOwnPropertyDescriptor(target, key);
        }
      });
      let caught = null;
      try {
        mod.validateGenesisStagingJournalRecord(hostile);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.code, C.JOURNAL_ENUMERATION_FAILED);
      assertMarkerUnreachable(caught, marker);
    });

    it("rejects a revoked Proxy at the journal, candidate, and ceremony boundaries", function () {
      const scenario = buildScenario();
      const { proxy: revokedJournal, revoke: revokeJournal } = Proxy.revocable(scenario.journal, {});
      revokeJournal();
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(revokedJournal),
        (error) => typeof error.code === "string"
      );

      const { proxy: revokedCandidate, revoke: revokeCandidate } = Proxy.revocable(
        { ...scenario.roleInputs[0], currentRoleCeremony: scenario.ceremonies[0] },
        {}
      );
      revokeCandidate();
      assert.throws(
        () => mod.stageGenesisRoleCandidate(scenario.journal, 0, revokedCandidate, scenario.now + 1),
        (error) => typeof error.code === "string"
      );

      const { proxy: revokedCeremony, revoke: revokeCeremony } = Proxy.revocable(scenario.ceremonies[0], {});
      revokeCeremony();
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          scenario.journal,
          0,
          { ...scenario.roleInputs[0], currentRoleCeremony: revokedCeremony },
          scenario.now + 1
        ),
        (error) => typeof error.code === "string"
      );
    });

    it("rejects a set-only accessor own property with no getter", function () {
      const scenario = buildScenario();
      const hostile = validIntentFields();
      delete hostile.userSalt;
      Object.defineProperty(hostile, "userSalt", { enumerable: true, configurable: true, set() {} });
      assert.throws(
        () => mod.createGenesisStagingJournal(hostile, 1000),
        (error) => error.code === C.JOURNAL_PROPERTY_READ_FAILED
      );
    });

    it("accepts a genuine non-enumerable own data property on the intent", function () {
      const fields = validIntentFields();
      const salt = fields.userSalt;
      delete fields.userSalt;
      Object.defineProperty(fields, "userSalt", { value: salt, enumerable: false, configurable: true, writable: true });
      assert.doesNotThrow(() => mod.createGenesisStagingJournal(fields, 1000));
    });

    it("reads a genuine own accessor property exactly once", function () {
      const fields = validIntentFields();
      const salt = fields.userSalt;
      delete fields.userSalt;
      let reads = 0;
      Object.defineProperty(fields, "userSalt", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          return salt;
        }
      });
      mod.createGenesisStagingJournal(fields, 1000);
      assert.equal(reads, 1);
    });

    it("a property-changing second-read trap on the journal proves stageGenesisRoleCandidate never rereads the caller's argument after validation", function () {
      const scenario = buildScenario();
      let reads = 0;
      const realValue = scenario.journal.expiresAt;
      const hostile = { ...scenario.journal };
      Object.defineProperty(hostile, "expiresAt", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          return realValue;
        }
      });
      mod.stageGenesisRoleCandidate(
        hostile,
        0,
        { ...scenario.roleInputs[0], currentRoleCeremony: scenario.ceremonies[0] },
        scenario.now + 1
      );
      assert.equal(reads, 1);
    });

    it("post-call caller mutation cannot alter a returned record", function () {
      const scenario = buildScenario();
      const mutableIntent = validIntentFields();
      const journal = mod.createGenesisStagingJournal(mutableIntent, 1000);
      const originalUserSalt = journal.userSalt;
      mutableIntent.userSalt = `0x${"ff".repeat(32)}`;
      assert.equal(journal.userSalt, originalUserSalt);
      assert.equal(Object.isFrozen(journal), true);
      // Assignment to a frozen object's property is a silent no-op in
      // non-strict scope rather than a throw; the meaningful invariant is
      // that the value never actually changes.
      journal.userSalt = `0x${"ee".repeat(32)}`;
      assert.equal(journal.userSalt, originalUserSalt);
    });
  });

  describe("branded error identity and raw-cause containment", function () {
    it("a genuine error passes instanceof", function () {
      let caught = null;
      try {
        mod.createGenesisStagingJournal(null, 1000);
      } catch (error) {
        caught = error;
      }
      assert.ok(caught instanceof mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError);
    });

    it("Object.create(prototype) spoof does not pass instanceof", function () {
      const spoof = Object.create(mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError.prototype);
      assert.equal(spoof instanceof mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError, false);
    });

    it("a prototype-lying Proxy does not pass instanceof", function () {
      const proxy = new Proxy({}, {
        getPrototypeOf() {
          return mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError.prototype;
        }
      });
      assert.equal(proxy instanceof mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError, false);
    });

    it("Symbol.hasInstance is locked against reassignment", function () {
      const descriptor = Object.getOwnPropertyDescriptor(
        mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError,
        Symbol.hasInstance
      );
      assert.equal(descriptor.writable, false);
      assert.equal(descriptor.configurable, false);
    });

    it("does not read .code, .name, or .message from a hostile thrown value while classifying it", function () {
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
      assert.throws(() => mod.createGenesisStagingJournal(fields, 1000));
      assert.equal(codeReads, 0);
      assert.equal(messageReads, 0);
      assert.equal(nameReads, 0);
    });

    it("never exposes a hostile thrown marker as .cause or under any other own property, enumerable or not", function () {
      const marker = { secretPayload: "must-never-be-reachable" };
      const fields = validIntentFields();
      Object.defineProperty(fields, "chainId", {
        enumerable: true,
        configurable: true,
        get() {
          throw marker;
        }
      });
      let caught = null;
      try {
        mod.createGenesisStagingJournal(fields, 1000);
      } catch (error) {
        caught = error;
      }
      assert.ok(caught);
      assertMarkerUnreachable(caught, marker);
      assert.equal(caught.cause, undefined);
      assert.equal("cause" in caught, false);
      for (const symbol of Object.getOwnPropertySymbols(caught)) {
        assert.notEqual(caught[symbol], marker);
      }
    });

    it("rethrows a genuine same-module branded error unchanged rather than re-wrapping it", function () {
      // A hostile getter on the intent throws a genuine, already-classified
      // instance of this module's own error; failWithCause must rethrow it
      // unchanged (same code, same identity), never collapse it further.
      const fields = validIntentFields();
      let thrown;
      Object.defineProperty(fields, "chainId", {
        enumerable: true,
        configurable: true,
        get() {
          thrown = new mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError(C.INVALID_NOW);
          throw thrown;
        }
      });
      let caught = null;
      try {
        mod.createGenesisStagingJournal(fields, 1000);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught, thrown);
      assert.equal(caught.code, C.INVALID_NOW);
    });

    it("does not recognize a prototype-spoofed classified error thrown from a getter -- reclassifies it", function () {
      const spoof = Object.create(mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError.prototype);
      spoof.code = C.INVALID_NOW;
      const fields = validIntentFields();
      Object.defineProperty(fields, "chainId", {
        enumerable: true,
        configurable: true,
        get() {
          throw spoof;
        }
      });
      let caught = null;
      try {
        mod.createGenesisStagingJournal(fields, 1000);
      } catch (error) {
        caught = error;
      }
      assert.notEqual(caught, spoof);
      assert.equal(caught instanceof mod.PhilCoreV2ConsumerRecoveryGenesisStagingJournalError, true);
    });
  });

  describe("byte ceilings", function () {
    // Every hash/address field in a stored entry or journal is fixed-width
    // by cryptographic construction (a bytes32 hex string is always
    // exactly 66 characters; an address is always exactly 42); every
    // descriptor/independence enum-like numeric field (role, verifierKind,
    // the policy fields, *Version, credentialGeneration) is constrained by
    // the shared factor-policy validator to one of a small closed set of
    // single-digit values, so it can never be wider than what a genuinely
    // valid entry already carries; every genesis-protocol-pinned intent
    // field (intentVersion, validatorVerifierKind, validatorEpoch,
    // recoveryEpoch, recoveryDelaySeconds, recoveryExpirySeconds) must
    // equal one specific pinned decimal value, so it likewise cannot be
    // wider than that pinned value's own width. The only fields whose
    // *width* can legitimately vary up to a declared bit-width ceiling are
    // the five uint48 timestamps (the journal's own top-level expiresAt --
    // see genesis-protocol's requireCanonicalUint(expiresAt, 48, ...) --
    // plus createdAtUnixSeconds, updatedAtUnixSeconds,
    // ceremonyExpiresAtUnixSeconds, and stagedAtUnixSeconds), the journal's
    // chainId (a uint256, per genesis-protocol's own
    // requireCanonicalUint(chainId, 256, ...) call), and the enum-valued
    // state/endReason strings (four valid values each, of differing
    // length). The true maximum entry/journal size is therefore
    // mechanically obtained by widening exactly those fields on an
    // otherwise-genuine record to their declared bit-width ceilings (or,
    // for state/endReason, their widest valid string) and measuring -- not
    // by repeating a historical number in a comment.
    const MAX_UINT48 = (1n << 48n) - 1n;
    const MAX_UINT48_STRING = MAX_UINT48.toString(10);
    const MAX_UINT256_STRING = ((1n << 256n) - 1n).toString(10);

    it("mechanically confirms the exact true maximum entry and journal byte counts (every variable-width field at its declared bit-width ceiling, including chainId and the top-level expiresAt, plus the widest valid state/endReason strings)", function () {
      // Every hash/address field is fixed-width by cryptographic
      // construction; every descriptor/independence enum field is
      // policy-constrained to a small closed set of single-digit values
      // (see the shared factor-policy validator's role-specific checks);
      // the four-part chronology (createdAt <= stagedAt < ceremonyExpiresAt
      // <= intentExpiresAt) is preserved at maximum decimal width by using
      // the uint48 ceiling and its immediate predecessors, which remain
      // fifteen decimal digits each -- the ceiling (281474976710655) is
      // nowhere near a power-of-ten boundary. state/endReason are widened
      // to "SUPERSEDED" (ten characters, the longest of the four valid
      // state strings, and a state/endReason pair the module's own
      // consistency rule accepts) rather than left at "STAGING"/null.
      //
      // These exact figures (1874 / 7540 bytes) were independently,
      // mechanically re-derived for this module's OWN
      // StoredGenesisManifestEntry/GenesisStagingJournalRecord schemas, and
      // are authoritative per user-approved Architecture Revision 7 (the
      // Byte-Boundary Addendum), which explicitly supersedes Architecture
      // Revision 5's stale 1,934/7,790-byte estimates in their entirety.
      // Revision 6 never explicitly corrected those figures; Revision 7
      // closes that silence by explicit correction, confirmed by three
      // independent mechanical derivations (this implementation test, an
      // independent architecture-review derivation, and Codex's own
      // adversarial probe) that agree on 1874/7540 exactly.
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);

      const ceremonyExpiresAtMax = MAX_UINT48_STRING;
      const staged0Max = (MAX_UINT48 - 3n).toString(10);
      const staged1Max = (MAX_UINT48 - 2n).toString(10);
      const staged2Max = (MAX_UINT48 - 1n).toString(10);
      const createdAtMax = (MAX_UINT48 - 4n).toString(10);
      const updatedAtMax = staged2Max;
      assert.equal(ceremonyExpiresAtMax.length, 15);
      assert.equal(staged2Max.length, 15);
      assert.equal(createdAtMax.length, 15);

      const widenEntry = (entry, stagedAtMax) => ({
        ...entry,
        ceremonyExpiresAtUnixSeconds: ceremonyExpiresAtMax,
        stagedAtUnixSeconds: stagedAtMax
      });
      const widenedEntry0 = widenEntry(journal.manifest["0"], staged0Max);
      const widenedEntry1 = widenEntry(journal.manifest["1"], staged1Max);
      const widenedEntry2 = widenEntry(journal.manifest["2"], staged2Max);
      const entryBytes = Buffer.byteLength(JSON.stringify(widenedEntry2), "utf8");

      const widenedJournal = {
        ...journal,
        chainId: MAX_UINT256_STRING,
        expiresAt: MAX_UINT48_STRING,
        state: "SUPERSEDED",
        endReason: "SUPERSEDED",
        createdAtUnixSeconds: createdAtMax,
        updatedAtUnixSeconds: updatedAtMax,
        manifest: { "0": widenedEntry0, "1": widenedEntry1, "2": widenedEntry2 }
      };
      const journalBytes = Buffer.byteLength(JSON.stringify(widenedJournal), "utf8");

      assert.equal(entryBytes, 1874, `true maximum entry size drifted -- got ${entryBytes} bytes`);
      assert.equal(journalBytes, 7540, `true maximum journal size drifted -- got ${journalBytes} bytes`);
      assert.ok(entryBytes < mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES);
      assert.ok(journalBytes < mod.MAX_GENESIS_JOURNAL_FILE_BYTES);
    });

    it("comparator boundary: an entry measuring exactly 4096 bytes passes the size comparator and proceeds to its later format rejection", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const baseEntry = staged0.manifest["0"];
      const baselineBytes = Buffer.byteLength(JSON.stringify(baseEntry), "utf8");
      const padding = mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES - baselineBytes;
      const entryAtCeiling = { ...baseEntry, ceremonyId: baseEntry.ceremonyId + "a".repeat(padding) };
      assert.equal(
        Buffer.byteLength(JSON.stringify(entryAtCeiling), "utf8"),
        mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES
      );
      const { integrityChecksum, ...withoutChecksum } = staged0;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { ...withoutChecksum.manifest, "0": entryAtCeiling }
      };
      const forged = {
        ...forgedWithoutChecksum,
        integrityChecksum: mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum)
      };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_PROPERTY_READ_FAILED
      );
    });

    it("comparator boundary: an otherwise identical 4097-byte entry fails with MANIFEST_ENTRY_OVERSIZED", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const baseEntry = staged0.manifest["0"];
      const baselineBytes = Buffer.byteLength(JSON.stringify(baseEntry), "utf8");
      const padding = mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES + 1 - baselineBytes;
      const entryOverCeiling = { ...baseEntry, ceremonyId: baseEntry.ceremonyId + "a".repeat(padding) };
      assert.equal(
        Buffer.byteLength(JSON.stringify(entryOverCeiling), "utf8"),
        mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES + 1
      );
      const { integrityChecksum, ...withoutChecksum } = staged0;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { ...withoutChecksum.manifest, "0": entryOverCeiling }
      };
      const forged = {
        ...forgedWithoutChecksum,
        integrityChecksum: mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum)
      };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_OVERSIZED
      );
    });

    it("comparator boundary: a journal measuring exactly 16384 bytes passes the size comparator and proceeds to its later validation error", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const baselineBytes = Buffer.byteLength(JSON.stringify(staged0), "utf8");
      const padding = mod.MAX_GENESIS_JOURNAL_FILE_BYTES - baselineBytes;
      const { integrityChecksum, ...withoutChecksum } = staged0;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        intentId: withoutChecksum.intentId + "a".repeat(padding)
      };
      const forged = {
        ...forgedWithoutChecksum,
        integrityChecksum: mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum)
      };
      assert.equal(
        Buffer.byteLength(JSON.stringify(forged), "utf8"),
        mod.MAX_GENESIS_JOURNAL_FILE_BYTES
      );
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.GENESIS_INTENT_VALIDATION_FAILED
      );
    });

    it("comparator boundary: an otherwise identical 16385-byte journal fails with JOURNAL_OVERSIZED", function () {
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const baselineBytes = Buffer.byteLength(JSON.stringify(staged0), "utf8");
      const padding = mod.MAX_GENESIS_JOURNAL_FILE_BYTES + 1 - baselineBytes;
      const { integrityChecksum, ...withoutChecksum } = staged0;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        intentId: withoutChecksum.intentId + "a".repeat(padding)
      };
      const forged = {
        ...forgedWithoutChecksum,
        integrityChecksum: mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum)
      };
      assert.equal(
        Buffer.byteLength(JSON.stringify(forged), "utf8"),
        mod.MAX_GENESIS_JOURNAL_FILE_BYTES + 1
      );
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_OVERSIZED
      );
    });

    it("reaches MANIFEST_ENTRY_OVERSIZED for a correctly shaped, string-typed but grossly oversized stored entry, before its malformed field ever reaches canonical format validation", function () {
      // Phase 1 (extractTentativeManifestEntry) only verifies exact key
      // ownership and that every field is string-typed -- it performs no
      // canonical-format validation. A field that is a legal JS string but
      // grossly exceeds its canonical width (here, factorCommitment) is
      // therefore accepted into the tentative entry and measured by the
      // byte-ceiling guard before validateStoredManifestEntry's phase 2
      // ever reaches requireNonZeroBytes32 on that same field -- this is a
      // mechanically constructed type-correct raw snapshot, never padded
      // otherwise-valid data.
      const scenario = buildScenario();
      const staged0 = stageRole(scenario, 0);
      const hostileEntry = {
        ...staged0.manifest["0"],
        factorCommitment: `0x${"a".repeat(mod.MAX_GENESIS_MANIFEST_ENTRY_BYTES * 2)}`
      };
      const { integrityChecksum: _discard, ...withoutChecksum } = staged0;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        manifest: { ...staged0.manifest, "0": hostileEntry }
      };
      const forged = {
        ...forgedWithoutChecksum,
        integrityChecksum: mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum)
      };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.MANIFEST_ENTRY_OVERSIZED
      );
    });

    it("reaches JOURNAL_OVERSIZED at the journal boundary before deeper hash recomputation or per-entry validation runs, for a journal whose own intent field is hostile (no single manifest entry is oversized)", function () {
      // A hostile top-level intent field (never counted toward the
      // per-entry MANIFEST_ENTRY_OVERSIZED measurement) isolates
      // JOURNAL_OVERSIZED from MANIFEST_ENTRY_OVERSIZED: this proves the
      // journal-level guard is reachable on its own terms, not merely as
      // a side effect of an already-oversized entry. Like the manifest
      // entry's own phase 1, the top-level intent snapshot is only
      // type-checked (string-typed), not format-validated, before the
      // journal-level byte-ceiling guard runs.
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const { integrityChecksum: _discard, ...withoutChecksum } = journal;
      const forgedWithoutChecksum = {
        ...withoutChecksum,
        intentId: `0x${"a".repeat(mod.MAX_GENESIS_JOURNAL_FILE_BYTES * 2)}`
      };
      const forged = {
        ...forgedWithoutChecksum,
        integrityChecksum: mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum)
      };
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord(forged),
        (error) => error.code === C.JOURNAL_OVERSIZED
      );
    });

    it("rejects a grossly oversized but type-correct hostile ceremonyId string during live staging via format validation (the live-staging path validates format before assembling an entry, unlike stored-record validation)", function () {
      const scenario = buildScenario();
      const hostileCeremony = {
        ...scenario.ceremonies[0],
        ceremonyId: `0x${"a".repeat(20000)}`
      };
      assert.throws(
        () => mod.stageGenesisRoleCandidate(
          scenario.journal,
          0,
          { ...scenario.roleInputs[0], currentRoleCeremony: hostileCeremony },
          scenario.now + 1
        ),
        (error) => error.code === C.GENESIS_CEREMONY_VALIDATION_FAILED
      );
    });

    it("computeGenesisStagingJournalChecksum's guarded reads tolerate a grossly oversized hostile field without ever calling ordinary JSON.stringify on the live hostile object directly", function () {
      const scenario = buildScenario();
      const { journal } = stageAllThree(scenario);
      const hostileEntry = {
        ...journal.manifest["0"],
        ceremonyId: `0x${"a".repeat(20000)}`
      };
      const { integrityChecksum: _discardChecksum, ...forgedWithoutChecksum } = journal;
      forgedWithoutChecksum.manifest = { ...journal.manifest, "0": hostileEntry };
      // The checksum function itself is a pure projection+hash over
      // guarded reads -- it does not enforce the size ceiling (that is the
      // journal/entry byte-ceiling guards' concern) -- so it succeeds
      // mechanically here without throwing; the same hostile record is
      // rejected by full record validation via the per-entry byte
      // ceiling, reached before any deeper per-entry format/semantic
      // validation runs (Revision 5 ordering).
      assert.doesNotThrow(() => mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum));
      assert.throws(
        () => mod.validateGenesisStagingJournalRecord({
          ...forgedWithoutChecksum,
          integrityChecksum: mod.computeGenesisStagingJournalChecksum(forgedWithoutChecksum)
        }),
        (error) => error.code === C.MANIFEST_ENTRY_OVERSIZED
      );
    });
  });
});
