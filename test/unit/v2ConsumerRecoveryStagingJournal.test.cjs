require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { getAddress } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const MODULE_PATH = path.join(
  ROOT,
  "apps/phil-device-sdk/src/v2ConsumerRecoveryStagingJournal.ts"
);

const {
  computePhilCoreV2LocalEnrollmentCeremonyHash,
  PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
  PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
  PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID
} = require("../../apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts");

const protocol = require("../../apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts");
const mod = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryStagingJournal.ts");

const CEREMONY_ID =
  "0x827fb6a1d6c993f9398090b62cbb32171b4fdc11fc6b9d885f263e18402faf34";
const ALT_CEREMONY_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT = "0xd5520BEEC59848D796EBA0badAa9c65f1be6E6F6";
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const CHAIN_ID = "11155111";
const MINTED_AT = 1_700_000_000;
const EXPIRES = "1700000300";
const ENROLLMENT_HASH =
  "0xa25696743026591b11d05287ac1b31fbcca2f26140a08d79bedf565b71d515e7";
const COMMITMENT_A =
  "0x2222222222222222222222222222222222222222222222222222222222222222";
const COMMITMENT_B =
  "0x3333333333333333333333333333333333333333333333333333333333333333";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const UINT48_MAX = (1n << 48n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;

const CONTEXT_OWN_KEYS = Object.freeze([
  "ceremonyId",
  "enrollmentCeremonyHash",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "account",
  "chainId",
  "entryPoint",
  "expectedRecoveryEpoch",
  "expectedValidatorEpoch",
  "expiresAtUnixSeconds"
]);

const JOURNAL_OWN_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "ceremonyId",
  "enrollmentCeremonyHash",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "account",
  "chainId",
  "entryPoint",
  "expectedRecoveryEpoch",
  "expectedValidatorEpoch",
  "expiresAtUnixSeconds",
  "state",
  "createdAtUnixSeconds",
  "updatedAtUnixSeconds",
  "manifest",
  "endReason",
  "integrityChecksum"
]);

const CANDIDATE_INPUT_OWN_KEYS = Object.freeze([
  "candidateKind",
  "candidateVersion",
  "publicCandidateCommitment",
  "credentialGeneration"
]);

const MANIFEST_ENTRY_OWN_KEYS = Object.freeze([
  "role",
  "candidateKind",
  "candidateVersion",
  "publicCandidateCommitment",
  "credentialGeneration",
  "stagedAtUnixSeconds"
]);

const ROLE_KIND = Object.freeze({
  0: "ROLE0_PUBLIC_CANDIDATE_COMMITMENT_V1",
  1: "ROLE1_PUBLIC_CANDIDATE_COMMITMENT_V1",
  2: "ROLE2_PUBLIC_CANDIDATE_COMMITMENT_V1"
});

const STAGING_STATES = Object.freeze([
  "STAGING",
  "CANCELLED",
  "EXPIRED",
  "SUPERSEDED"
]);

const EXPECTED_EXPORTS = Object.freeze([
  "createStagingJournal",
  "stageRoleCandidate",
  "cancelStagingJournal",
  "expireStagingJournalIfNeeded",
  "supersedeStagingJournal",
  "validateStagingJournalRecord",
  "computeStagingJournalChecksum",
  "PhilCoreV2ConsumerRecoveryStagingJournalError",
  "PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE",
  "PHILCORE_V2_STAGING_JOURNAL_SCHEMA_VERSION",
  "PHILCORE_V2_STAGING_JOURNAL_FORMAT_PROVENANCE",
  "PHILCORE_V2_STAGING_JOURNAL_CHECKSUM_PREFIX",
  "MAX_JOURNAL_FILE_BYTES",
  "MAX_MANIFEST_ENTRY_BYTES",
  "PHILCORE_V2_STAGING_ROLE0_CANDIDATE_KIND",
  "PHILCORE_V2_STAGING_ROLE1_CANDIDATE_KIND",
  "PHILCORE_V2_STAGING_ROLE2_CANDIDATE_KIND",
  "PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING",
  "PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED",
  "PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED",
  "PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED"
]);

const PROHIBITED_EXPORT_PATTERNS = [
  /^createRecoveryStagingHost$/,
  /^fsOps$/,
  /^processInfo$/,
  /^resetStagingHostPoison$/,
  /^writeStagingJournalAtomic$/,
  /testOnly/i,
  /Host$/
];

const PURE_ERROR_CODES = Object.freeze([
  "INVALID_NOW",
  "CLOCK_REGRESSION_DETECTED",
  "CEREMONY_CONTEXT_NOT_OBJECT",
  "CEREMONY_CONTEXT_MISSING_KEY",
  "CEREMONY_CONTEXT_EXTRA_KEY",
  "CEREMONY_ID_INVALID",
  "ENROLLMENT_CEREMONY_HASH_INVALID",
  "ACCOUNT_VERSION_ID_INVALID",
  "ACCOUNT_VERSION_ID_MISMATCH",
  "SECURITY_MODEL_ID_INVALID",
  "SECURITY_MODEL_ID_MISMATCH",
  "RECOVERY_DOMAIN_ID_INVALID",
  "RECOVERY_DOMAIN_ID_MISMATCH",
  "ACCOUNT_INVALID",
  "CHAIN_ID_INVALID",
  "ENTRY_POINT_INVALID",
  "EXPECTED_RECOVERY_EPOCH_INVALID",
  "EXPECTED_VALIDATOR_EPOCH_INVALID",
  "CEREMONY_EXPIRY_INVALID",
  "CEREMONY_CONTEXT_HASH_MISMATCH",
  "CEREMONY_CONTEXT_EXPIRED",
  "STAGE_ROLE_INVALID",
  "CANDIDATE_INPUT_NOT_OBJECT",
  "CANDIDATE_INPUT_MISSING_KEY",
  "CANDIDATE_INPUT_EXTRA_KEY",
  "CANDIDATE_INPUT_KIND_TYPE_INVALID",
  "CANDIDATE_INPUT_VERSION_TYPE_INVALID",
  "CANDIDATE_INPUT_COMMITMENT_TYPE_INVALID",
  "CANDIDATE_INPUT_GENERATION_TYPE_INVALID",
  "CANDIDATE_INPUT_KIND_MISMATCH",
  "CANDIDATE_INPUT_VERSION_INVALID",
  "CANDIDATE_INPUT_COMMITMENT_INVALID",
  "CANDIDATE_INPUT_GENERATION_INVALID",
  "MANIFEST_ENTRY_OVERSIZED",
  "MANIFEST_ENTRY_NOT_OBJECT",
  "MANIFEST_ENTRY_MISSING_KEY",
  "MANIFEST_ENTRY_EXTRA_KEY",
  "MANIFEST_ROLE_INVALID",
  "MANIFEST_SLOT_ROLE_MISMATCH",
  "MANIFEST_CANDIDATE_KIND_INVALID",
  "MANIFEST_ROLE_KIND_MISMATCH",
  "MANIFEST_CANDIDATE_VERSION_INVALID",
  "MANIFEST_COMMITMENT_INVALID",
  "MANIFEST_CREDENTIAL_GENERATION_INVALID",
  "MANIFEST_STAGED_AT_INVALID",
  "MANIFEST_STAGED_AT_ORDER_INVALID",
  "JOURNAL_NOT_OBJECT",
  "JOURNAL_MISSING_KEY",
  "JOURNAL_EXTRA_KEY",
  "JOURNAL_SCHEMA_VERSION_UNSUPPORTED",
  "JOURNAL_FORMAT_PROVENANCE_INVALID",
  "JOURNAL_CEREMONY_ID_INVALID",
  "JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID",
  "JOURNAL_ACCOUNT_VERSION_ID_INVALID",
  "JOURNAL_ACCOUNT_VERSION_ID_MISMATCH",
  "JOURNAL_SECURITY_MODEL_ID_INVALID",
  "JOURNAL_SECURITY_MODEL_ID_MISMATCH",
  "JOURNAL_RECOVERY_DOMAIN_ID_INVALID",
  "JOURNAL_RECOVERY_DOMAIN_ID_MISMATCH",
  "JOURNAL_ACCOUNT_INVALID",
  "JOURNAL_CHAIN_ID_INVALID",
  "JOURNAL_ENTRY_POINT_INVALID",
  "JOURNAL_EXPECTED_RECOVERY_EPOCH_INVALID",
  "JOURNAL_EXPECTED_VALIDATOR_EPOCH_INVALID",
  "JOURNAL_EXPIRY_INVALID",
  "JOURNAL_STATE_INVALID",
  "JOURNAL_CREATED_AT_INVALID",
  "JOURNAL_UPDATED_AT_INVALID",
  "JOURNAL_TIMESTAMP_ORDER_INVALID",
  "JOURNAL_CREATION_NOT_BEFORE_EXPIRY",
  "JOURNAL_STATE_TIMESTAMP_MISMATCH",
  "JOURNAL_MANIFEST_NOT_OBJECT",
  "JOURNAL_MANIFEST_MISSING_KEY",
  "JOURNAL_MANIFEST_EXTRA_KEY",
  "JOURNAL_END_REASON_INVALID",
  "JOURNAL_STATE_END_REASON_MISMATCH",
  "JOURNAL_CONTEXT_HASH_MISMATCH",
  "JOURNAL_CHECKSUM_FORMAT_INVALID",
  "JOURNAL_CHECKSUM_MISMATCH",
  "JOURNAL_OVERSIZED",
  "JOURNAL_JSON_INVALID",
  "JOURNAL_FILENAME_ID_MISMATCH",
  "JOURNAL_NOT_STAGING"
]);

const HOST_ERROR_CODES = Object.freeze([
  "HOST_DEPENDENCIES_NOT_OBJECT",
  "HOST_DEPENDENCY_MISSING",
  "HOST_DEPENDENCY_EXTRA",
  "HOST_DEPENDENCY_INVALID",
  "HOST_PROCESS_POISONED",
  "HOST_CLOSED",
  "STORAGE_ROOT_INVALID",
  "STORAGE_ROOT_UNSAFE",
  "STORAGE_DIRECTORY_INVALID",
  "STORAGE_DIRECTORY_OWNER_INVALID",
  "STORAGE_DIRECTORY_MODE_INVALID",
  "STORAGE_SHARED_PARENT_MODE_REPAIR_FAILED",
  "STORAGE_SHARED_PARENT_MODE_REPAIR_INDETERMINATE",
  "QUARANTINE_DIRECTORY_INVALID",
  "QUARANTINE_DIRECTORY_OWNER_INVALID",
  "QUARANTINE_DIRECTORY_MODE_INVALID",
  "DURABILITY_UNSUPPORTED",
  "RECONCILIATION_REQUIRED",
  "RECONCILIATION_FAILED",
  "JOURNAL_ALREADY_EXISTS",
  "JOURNAL_NOT_FOUND",
  "DISK_STATE_CHANGED",
  "LOCK_HELD",
  "LOCK_HELD_OR_AMBIGUOUS",
  "LOCK_FILE_OVERSIZED",
  "LOCK_FILE_JSON_INVALID",
  "LOCK_FILE_NOT_OBJECT",
  "LOCK_FILE_MISSING_KEY",
  "LOCK_FILE_EXTRA_KEY",
  "LOCK_PID_INVALID",
  "LOCK_CREATED_AT_INVALID",
  "LOCK_LIVENESS_RESULT_INVALID",
  "LOCK_DESCRIPTOR_INVALID",
  "LOCK_LOST_OR_REPLACED",
  "LOCK_ACQUISITION_FAILED",
  "LOCK_ACQUISITION_INDETERMINATE",
  "STALE_LOCK_QUARANTINE_BOUND_EXCEEDED",
  "STALE_LOCK_QUARANTINE_INDETERMINATE",
  "LOCK_RELEASE_INDETERMINATE",
  "MULTIPLE_JOURNALS_FOUND",
  "UNEXPECTED_STAGING_ENTRY",
  "JOURNAL_DESCRIPTOR_INVALID",
  "CORRUPT_QUARANTINE_BOUND_EXCEEDED",
  "CORRUPT_QUARANTINE_INDETERMINATE",
  "TEMP_FILE_BOUND_EXCEEDED",
  "RECONCILIATION_TEMP_SWEEP_BOUND_EXCEEDED",
  "RECONCILIATION_OPERATION_BOUND_EXCEEDED",
  "TEMP_REMOVAL_INDETERMINATE",
  "FILESYSTEM_READ_FAILED",
  "FILESYSTEM_MUTATION_FAILED",
  "DURABILITY_WRITE_FAILED",
  "DURABILITY_INDETERMINATE",
  "JOURNAL_REMOVAL_INDETERMINATE",
  "CEREMONY_RETIREMENT_FAILED",
  "CEREMONY_RETIREMENT_THENABLE_REJECTED",
  "CEREMONY_RETIREMENT_RESULT_INVALID"
]);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function assertCode(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
    assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
    return true;
  });
}

function toCanonicalDecimal(value) {
  if (typeof value === "bigint") {
    return value.toString(10);
  }
  return String(value);
}

function independentEnrollmentHash(fieldsOrExpires = {}) {
  const fields =
    fieldsOrExpires !== null
    && typeof fieldsOrExpires === "object"
    && !Array.isArray(fieldsOrExpires)
      ? fieldsOrExpires
      : { expiresAt: fieldsOrExpires };
  return computePhilCoreV2LocalEnrollmentCeremonyHash({
    ceremonyId: fields.ceremonyId ?? CEREMONY_ID,
    account: getAddress(fields.account ?? ACCOUNT),
    chainId: toCanonicalDecimal(fields.chainId ?? CHAIN_ID),
    entryPoint: getAddress(fields.entryPoint ?? ENTRY_POINT),
    accountVersionId: fields.accountVersionId ?? PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
    securityModelId: fields.securityModelId ?? PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
    recoveryDomainId: fields.recoveryDomainId ?? PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
    expectedRecoveryEpoch: toCanonicalDecimal(fields.expectedRecoveryEpoch ?? "1"),
    expectedValidatorEpoch: toCanonicalDecimal(fields.expectedValidatorEpoch ?? "1"),
    expiresAt: toCanonicalDecimal(fields.expiresAt ?? fields.expiresAtUnixSeconds ?? EXPIRES)
  });
}

function validContext(overrides = {}) {
  const base = {
    ceremonyId: CEREMONY_ID,
    enrollmentCeremonyHash: ENROLLMENT_HASH,
    accountVersionId: PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
    account: ACCOUNT,
    chainId: CHAIN_ID,
    entryPoint: ENTRY_POINT,
    expectedRecoveryEpoch: "1",
    expectedValidatorEpoch: "1",
    expiresAtUnixSeconds: EXPIRES
  };
  const merged = { ...base, ...overrides };
  if (!Object.prototype.hasOwnProperty.call(overrides, "enrollmentCeremonyHash")) {
    try {
      merged.enrollmentCeremonyHash = independentEnrollmentHash(merged);
    } catch {
      // Invalid expiry/epoch fixtures still need a context object so
      // createStagingJournal can reject the field error itself.
      merged.enrollmentCeremonyHash = ENROLLMENT_HASH;
    }
  }
  // Preserve exact Package 5B-1 ceremony-context key order.
  return {
    ceremonyId: merged.ceremonyId,
    enrollmentCeremonyHash: merged.enrollmentCeremonyHash,
    accountVersionId: merged.accountVersionId,
    securityModelId: merged.securityModelId,
    recoveryDomainId: merged.recoveryDomainId,
    account: merged.account,
    chainId: merged.chainId,
    entryPoint: merged.entryPoint,
    expectedRecoveryEpoch: merged.expectedRecoveryEpoch,
    expectedValidatorEpoch: merged.expectedValidatorEpoch,
    expiresAtUnixSeconds: merged.expiresAtUnixSeconds
  };
}

function candidateInput(role, overrides = {}) {
  return {
    candidateKind: ROLE_KIND[role],
    candidateVersion: 1,
    publicCandidateCommitment: COMMITMENT_A,
    credentialGeneration: "1",
    ...overrides
  };
}

function mintJournal(contextOverrides = {}, now = MINTED_AT) {
  return mod.createStagingJournal(validContext(contextOverrides), now);
}

function withoutChecksum(journal) {
  const copy = clone(journal);
  delete copy.integrityChecksum;
  return copy;
}

function compactStoredEntryBytes(entry) {
  return Buffer.byteLength(
    JSON.stringify({
      role: entry.role,
      candidateKind: entry.candidateKind,
      candidateVersion: entry.candidateVersion,
      publicCandidateCommitment: entry.publicCandidateCommitment,
      credentialGeneration: entry.credentialGeneration,
      stagedAtUnixSeconds: entry.stagedAtUnixSeconds
    }),
    "utf8"
  );
}

function assertNoBigInt(value, path = "root") {
  if (typeof value === "bigint") {
    assert.fail(`bigint at ${path}`);
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoBigInt(item, `${path}[${index}]`));
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    assertNoBigInt(nested, `${path}.${key}`);
  }
}

function reorderedObject(source, keyOrder) {
  const out = Object.create(null);
  for (const key of keyOrder) {
    out[key] = source[key];
  }
  return out;
}

function attachChecksum(recordWithoutChecksum) {
  return {
    ...recordWithoutChecksum,
    integrityChecksum: mod.computeStagingJournalChecksum(recordWithoutChecksum)
  };
}

describe("PhilCore V2 consumer recovery staging journal (5B-1 pure)", function () {
  it("locks schema, provenance, checksum prefix, and byte limits", function () {
    assert.equal(mod.PHILCORE_V2_STAGING_JOURNAL_SCHEMA_VERSION, 1);
    assert.equal(
      mod.PHILCORE_V2_STAGING_JOURNAL_FORMAT_PROVENANCE,
      "philcore-v2-ceremony-staging-journal-v1"
    );
    assert.equal(
      mod.PHILCORE_V2_STAGING_JOURNAL_CHECKSUM_PREFIX,
      "PHILCORE_V2_CEREMONY_STAGING_JOURNAL_V1|"
    );
    assert.equal(mod.MAX_JOURNAL_FILE_BYTES, 8192);
    assert.equal(mod.MAX_MANIFEST_ENTRY_BYTES, 512);
  });

  it("locks candidate kind literals and staging states", function () {
    assert.equal(
      mod.PHILCORE_V2_STAGING_ROLE0_CANDIDATE_KIND,
      "ROLE0_PUBLIC_CANDIDATE_COMMITMENT_V1"
    );
    assert.equal(
      mod.PHILCORE_V2_STAGING_ROLE1_CANDIDATE_KIND,
      "ROLE1_PUBLIC_CANDIDATE_COMMITMENT_V1"
    );
    assert.equal(
      mod.PHILCORE_V2_STAGING_ROLE2_CANDIDATE_KIND,
      "ROLE2_PUBLIC_CANDIDATE_COMMITMENT_V1"
    );
    assert.equal(mod.PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING, "STAGING");
    assert.equal(mod.PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED, "CANCELLED");
    assert.equal(mod.PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED, "EXPIRED");
    assert.equal(mod.PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED, "SUPERSEDED");
    assert.deepEqual(STAGING_STATES, [
      mod.PHILCORE_V2_STAGING_JOURNAL_STATE_STAGING,
      mod.PHILCORE_V2_STAGING_JOURNAL_STATE_CANCELLED,
      mod.PHILCORE_V2_STAGING_JOURNAL_STATE_EXPIRED,
      mod.PHILCORE_V2_STAGING_JOURNAL_STATE_SUPERSEDED
    ]);
  });

  it("exports the exact pure surface and forbids host or test-only exports", function () {
    for (const key of EXPECTED_EXPORTS) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(mod, key),
        `missing export ${key}`
      );
    }
    for (const key of Object.keys(mod)) {
      assert.ok(
        EXPECTED_EXPORTS.includes(key),
        `unexpected export ${key}`
      );
      assert.ok(
        !PROHIBITED_EXPORT_PATTERNS.some((pattern) => pattern.test(key)),
        `prohibited export ${key}`
      );
    }
    assert.equal(
      Object.prototype.hasOwnProperty.call(mod, "ValidateStagingJournalOptions"),
      false
    );
    assert.equal(mod.validateStagingJournalRecord.length, 1);
  });

  it("freezes the closed error-code map with pure and host literals", function () {
    const codes = mod.PHILCORE_V2_CONSUMER_RECOVERY_STAGING_JOURNAL_ERROR_CODE;
    assert.ok(Object.isFrozen(codes));
    for (const code of PURE_ERROR_CODES) {
      assert.equal(codes[code], code, `missing pure code ${code}`);
    }
    for (const code of HOST_ERROR_CODES) {
      assert.equal(codes[code], code, `missing host code ${code}`);
    }
    assert.equal(Object.keys(codes).length, PURE_ERROR_CODES.length + HOST_ERROR_CODES.length);
  });

  it("uses PhilCoreV2ConsumerRecoveryStagingJournalError with literal .code", function () {
    assertCode(() => mod.createStagingJournal(null, MINTED_AT), "CEREMONY_CONTEXT_NOT_OBJECT");
    try {
      mod.createStagingJournal(null, MINTED_AT);
    } catch (error) {
      assert.ok(error instanceof mod.PhilCoreV2ConsumerRecoveryStagingJournalError);
    }
  });

  it("requires runtime ceremony context with eleven keys in exact order", function () {
    const ctx = validContext();
    assert.deepEqual(Object.keys(ctx), [...CONTEXT_OWN_KEYS]);
    const journal = mintJournal();
    for (const key of CONTEXT_OWN_KEYS) {
      if (key === "expiresAtUnixSeconds") {
        assert.equal(journal.expiresAtUnixSeconds, EXPIRES);
        continue;
      }
      if (key === "enrollmentCeremonyHash") {
        assert.equal(journal.enrollmentCeremonyHash, ENROLLMENT_HASH);
        continue;
      }
      if (key === "account") {
        assert.equal(journal.account, getAddress(ACCOUNT));
        continue;
      }
      if (key === "entryPoint") {
        assert.equal(journal.entryPoint, getAddress(ENTRY_POINT));
        continue;
      }
      assert.equal(journal[key], ctx[key]);
    }
  });

  it("accepts bigint numeric fields and stores canonical decimal strings", function () {
    const journal = mintJournal({
      chainId: 11155111n,
      expectedRecoveryEpoch: 1n,
      expectedValidatorEpoch: 1n,
      expiresAtUnixSeconds: BigInt(EXPIRES)
    });
    assert.equal(journal.chainId, CHAIN_ID);
    assert.equal(journal.expectedRecoveryEpoch, "1");
    assert.equal(journal.expectedValidatorEpoch, "1");
    assert.equal(journal.expiresAtUnixSeconds, EXPIRES);
    assert.equal(typeof journal.chainId, "string");
  });

  it("accepts canonical decimal strings for numeric fields", function () {
    const journal = mintJournal({
      chainId: CHAIN_ID,
      expectedRecoveryEpoch: "9",
      expectedValidatorEpoch: "7",
      expiresAtUnixSeconds: EXPIRES
    });
    assert.equal(journal.expectedRecoveryEpoch, "9");
    assert.equal(journal.expectedValidatorEpoch, "7");
  });

  it("produces byte-identical journals and checksums for bigint versus string inputs", function () {
    const stringJournal = mintJournal({
      chainId: CHAIN_ID,
      expectedRecoveryEpoch: "1",
      expectedValidatorEpoch: "1",
      expiresAtUnixSeconds: EXPIRES
    });
    const bigintJournal = mintJournal({
      chainId: 11155111n,
      expectedRecoveryEpoch: 1n,
      expectedValidatorEpoch: 1n,
      expiresAtUnixSeconds: BigInt(EXPIRES)
    });
    assert.deepEqual(withoutChecksum(stringJournal), withoutChecksum(bigintJournal));
    assert.equal(stringJournal.integrityChecksum, bigintJournal.integrityChecksum);
    assert.equal(
      JSON.stringify(stringJournal),
      JSON.stringify(bigintJournal)
    );
  });

  it("never serializes bigint values into journal JSON", function () {
    const journal = mintJournal({
      chainId: 11155111n,
      expectedRecoveryEpoch: 1n,
      expectedValidatorEpoch: 1n,
      expiresAtUnixSeconds: BigInt(EXPIRES)
    });
    assertNoBigInt(journal);
    assert.doesNotThrow(() => JSON.stringify(journal));
    const staged = mod.stageRoleCandidate(
      journal,
      0,
      candidateInput(0, { credentialGeneration: "42" }),
      MINTED_AT + 1
    );
    assertNoBigInt(staged);
    assert.doesNotThrow(() => JSON.stringify(staged));
  });

  it("recomputes enrollmentCeremonyHash from normalized ten-key Package 5A projection", function () {
    const journal = mintJournal();
    assert.equal(journal.enrollmentCeremonyHash, ENROLLMENT_HASH);
    assert.equal(journal.enrollmentCeremonyHash, independentEnrollmentHash(EXPIRES));
    assertCode(
      () => mod.createStagingJournal(
        validContext({ enrollmentCeremonyHash: ALT_CEREMONY_ID }),
        MINTED_AT
      ),
      "CEREMONY_CONTEXT_HASH_MISMATCH"
    );
  });

  it("rejects JavaScript number types for numeric context fields", function () {
    for (const field of [
      "chainId",
      "expectedRecoveryEpoch",
      "expectedValidatorEpoch",
      "expiresAtUnixSeconds"
    ]) {
      assertCode(
        () => mod.createStagingJournal(validContext({ [field]: 1 }), MINTED_AT),
        field === "chainId"
          ? "CHAIN_ID_INVALID"
          : field === "expectedRecoveryEpoch"
            ? "EXPECTED_RECOVERY_EPOCH_INVALID"
            : field === "expectedValidatorEpoch"
              ? "EXPECTED_VALIDATOR_EPOCH_INVALID"
              : "CEREMONY_EXPIRY_INVALID"
      );
    }
  });

  it("rejects invalid numeric syntax and range for context fields", function () {
    const cases = [
      ["chainId", "-1", "CHAIN_ID_INVALID"],
      ["chainId", "0", "CHAIN_ID_INVALID"],
      ["chainId", "01", "CHAIN_ID_INVALID"],
      ["chainId", "1.5", "CHAIN_ID_INVALID"],
      ["chainId", "1e3", "CHAIN_ID_INVALID"],
      ["chainId", " 1", "CHAIN_ID_INVALID"],
      ["expectedRecoveryEpoch", "0", "EXPECTED_RECOVERY_EPOCH_INVALID"],
      ["expectedValidatorEpoch", "0", "EXPECTED_VALIDATOR_EPOCH_INVALID"],
      ["expiresAtUnixSeconds", "0", "CEREMONY_EXPIRY_INVALID"],
      ["chainId", -1n, "CHAIN_ID_INVALID"],
      ["expectedRecoveryEpoch", 0n, "EXPECTED_RECOVERY_EPOCH_INVALID"]
    ];
    for (const [field, value, code] of cases) {
      assertCode(
        () => mod.createStagingJournal(validContext({ [field]: value }), MINTED_AT),
        code
      );
    }
  });

  it("creates a STAGING journal with nineteen fields and null manifest slots", function () {
    const journal = mintJournal();
    assert.deepEqual(Object.keys(journal), [...JOURNAL_OWN_KEYS]);
    assert.equal(journal.schemaVersion, 1);
    assert.equal(
      journal.formatProvenance,
      "philcore-v2-ceremony-staging-journal-v1"
    );
    assert.equal(journal.state, "STAGING");
    assert.equal(journal.endReason, null);
    assert.equal(journal.createdAtUnixSeconds, String(MINTED_AT));
    assert.equal(journal.updatedAtUnixSeconds, String(MINTED_AT));
    assert.deepEqual(journal.manifest, { 0: null, 1: null, 2: null });
    assert.match(journal.integrityChecksum, /^0x[0-9a-f]{64}$/);
  });

  it("maps role to candidate kind for all manifest roles", function () {
    let journal = mintJournal();
    for (const role of [0, 1, 2]) {
      journal = mod.stageRoleCandidate(
        journal,
        role,
        candidateInput(role),
        MINTED_AT + role + 1
      );
      const entry = journal.manifest[String(role)];
      assert.equal(entry.role, role);
      assert.equal(entry.candidateKind, ROLE_KIND[role]);
      assert.equal(entry.candidateVersion, 1);
    }
  });

  it("authors role and stagedAtUnixSeconds from host arguments, not candidate input", function () {
    const journal = mintJournal();
    const staged = mod.stageRoleCandidate(
      journal,
      1,
      candidateInput(1),
      MINTED_AT + 5
    );
    const entry = staged.manifest["1"];
    assert.equal(entry.role, 1);
    assert.equal(entry.stagedAtUnixSeconds, String(MINTED_AT + 5));
    assertCode(
      () => mod.stageRoleCandidate(
        journal,
        1,
        { ...candidateInput(1), role: 0, stagedAtUnixSeconds: "999" },
        MINTED_AT + 5
      ),
      "CANDIDATE_INPUT_EXTRA_KEY"
    );
  });

  it("replaces a manifest slot with whole-entry replacement", function () {
    const journal = mintJournal();
    const first = mod.stageRoleCandidate(
      journal,
      0,
      candidateInput(0, { publicCandidateCommitment: COMMITMENT_A }),
      MINTED_AT + 1
    );
    const second = mod.stageRoleCandidate(
      first,
      0,
      candidateInput(0, {
        publicCandidateCommitment: COMMITMENT_B,
        credentialGeneration: "2"
      }),
      MINTED_AT + 2
    );
    assert.equal(second.manifest["0"].publicCandidateCommitment, COMMITMENT_B);
    assert.equal(second.manifest["0"].credentialGeneration, "2");
    assert.equal(second.manifest["0"].stagedAtUnixSeconds, String(MINTED_AT + 2));
    assert.notEqual(first.integrityChecksum, second.integrityChecksum);
  });

  it("accepts compact stored entries up to 512 bytes and rejects 513 bytes", function () {
    const journal = mintJournal();
    const staged = mod.stageRoleCandidate(
      journal,
      0,
      candidateInput(0, { credentialGeneration: UINT64_MAX.toString(10) }),
      MINTED_AT + 1
    );
    assert.ok(
      compactStoredEntryBytes(staged.manifest["0"]) <= mod.MAX_MANIFEST_ENTRY_BYTES
    );

    const oversizeKind = `${ROLE_KIND[0]}${"X".repeat(480)}`;
    assertCode(
      () => mod.stageRoleCandidate(
        journal,
        0,
        candidateInput(0, { candidateKind: oversizeKind }),
        MINTED_AT + 1
      ),
      "MANIFEST_ENTRY_OVERSIZED"
    );
  });

  it("recomputes checksum independently and ignores object insertion order", function () {
    const journal = mintJournal();
    const without = withoutChecksum(journal);
    const reversed = reorderedObject(without, [...JOURNAL_OWN_KEYS].slice(0, -1).reverse());
    assert.equal(
      mod.computeStagingJournalChecksum(without),
      mod.computeStagingJournalChecksum(reversed)
    );
    assert.equal(
      journal.integrityChecksum,
      mod.computeStagingJournalChecksum(without)
    );
  });

  it("detects checksum mutation sensitivity and null-role projection", function () {
    const journal = mintJournal();
    const checksum = journal.integrityChecksum;
    const mutated = clone(withoutChecksum(journal));
    mutated.accountVersionId = ALT_CEREMONY_ID;
    assert.notEqual(mod.computeStagingJournalChecksum(mutated), checksum);

    const withNullRoles = clone(withoutChecksum(journal));
    withNullRoles.manifest = { 2: null, 0: null, 1: null };
    assert.equal(
      mod.computeStagingJournalChecksum(withNullRoles),
      mod.computeStagingJournalChecksum(withoutChecksum(journal))
    );
  });

  it("transitions STAGING to CANCELLED before expiry", function () {
    const journal = mintJournal();
    const cancelled = mod.cancelStagingJournal(journal, MINTED_AT + 10);
    assert.equal(cancelled.state, "CANCELLED");
    assert.equal(cancelled.endReason, "CANCELLED");
    assert.equal(cancelled.updatedAtUnixSeconds, String(MINTED_AT + 10));
    assert.ok(Number(cancelled.updatedAtUnixSeconds) < Number(cancelled.expiresAtUnixSeconds));
  });

  it("transitions STAGING to EXPIRED at exact expiry via cancel, expire, and stageRole", function () {
    const journal = mintJournal();
    const expiryNow = Number(EXPIRES);

    const viaCancel = mod.cancelStagingJournal(journal, expiryNow);
    assert.equal(viaCancel.state, "EXPIRED");
    assert.equal(viaCancel.endReason, "EXPIRED");

    const viaExpire = mod.expireStagingJournalIfNeeded(journal, expiryNow);
    assert.equal(viaExpire.state, "EXPIRED");
    assert.equal(viaExpire.endReason, "EXPIRED");

    const viaStage = mod.stageRoleCandidate(
      journal,
      0,
      candidateInput(0),
      expiryNow
    );
    assert.equal(viaStage.state, "EXPIRED");
    assert.equal(viaStage.endReason, "EXPIRED");
    assert.equal(viaStage.manifest["0"], null);
  });

  it("leaves STAGING unchanged immediately before expiry", function () {
    const journal = mintJournal();
    const before = Number(EXPIRES) - 1;
    const unchanged = mod.expireStagingJournalIfNeeded(journal, before);
    assert.equal(unchanged.state, "STAGING");
    assert.equal(unchanged.endReason, null);
    assert.deepEqual(unchanged.manifest, journal.manifest);
  });

  it("supports restart-only SUPERSEDED transition from STAGING", function () {
    const journal = mintJournal();
    const superseded = mod.supersedeStagingJournal(journal, MINTED_AT + 1);
    assert.equal(superseded.state, "SUPERSEDED");
    assert.equal(superseded.endReason, "SUPERSEDED");
  });

  it("rejects mutations on terminal journals and non-STAGING stageRoleCandidate", function () {
    const journal = mintJournal();
    const cancelled = mod.cancelStagingJournal(journal, MINTED_AT + 1);
    for (const fn of [
      () => mod.stageRoleCandidate(cancelled, 0, candidateInput(0), MINTED_AT + 2),
      () => mod.cancelStagingJournal(cancelled, MINTED_AT + 2),
      () => mod.supersedeStagingJournal(cancelled, MINTED_AT + 2)
    ]) {
      assertCode(fn, "JOURNAL_NOT_STAGING");
    }
  });

  it("rejects clock regression across staging operations", function () {
    const journal = mintJournal();
    const staged = mod.stageRoleCandidate(journal, 0, candidateInput(0), MINTED_AT + 5);
    assertCode(
      () => mod.stageRoleCandidate(staged, 1, candidateInput(1), MINTED_AT + 4),
      "CLOCK_REGRESSION_DETECTED"
    );
    assertCode(
      () => mod.cancelStagingJournal(staged, MINTED_AT + 4),
      "CLOCK_REGRESSION_DETECTED"
    );
    assertCode(
      () => mod.expireStagingJournalIfNeeded(staged, MINTED_AT + 4),
      "CLOCK_REGRESSION_DETECTED"
    );
  });

  it("deep-freezes journals, manifest objects, and non-null entries", function () {
    const journal = mintJournal();
    assert.ok(Object.isFrozen(journal));
    assert.ok(Object.isFrozen(journal.manifest));
    const staged = mod.stageRoleCandidate(journal, 0, candidateInput(0), MINTED_AT + 1);
    assert.ok(Object.isFrozen(staged));
    assert.ok(Object.isFrozen(staged.manifest));
    assert.ok(Object.isFrozen(staged.manifest["0"]));
  });

  it("rejects invalid nowUnixSeconds values", function () {
    for (const now of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      assertCode(() => mintJournal({}, now), "INVALID_NOW");
    }
  });

  it("rejects createStagingJournal when ceremony context is already expired", function () {
    assertCode(
      () => mod.createStagingJournal(validContext(), Number(EXPIRES)),
      "CEREMONY_CONTEXT_EXPIRED"
    );
    assertCode(
      () => mod.createStagingJournal(validContext(), Number(EXPIRES) + 1),
      "CEREMONY_CONTEXT_EXPIRED"
    );
  });

  it("covers context validation error codes", function () {
    const cases = [
      [null, "CEREMONY_CONTEXT_NOT_OBJECT"],
      [{ ...validContext(), extra: "x" }, "CEREMONY_CONTEXT_EXTRA_KEY"],
      [(() => {
        const ctx = validContext();
        delete ctx.ceremonyId;
        return ctx;
      })(), "CEREMONY_CONTEXT_MISSING_KEY"],
      [validContext({ ceremonyId: ZERO_BYTES32 }), "CEREMONY_ID_INVALID"],
      [validContext({ enrollmentCeremonyHash: "0x1234" }), "ENROLLMENT_CEREMONY_HASH_INVALID"],
      [validContext({ accountVersionId: "0x1234" }), "ACCOUNT_VERSION_ID_INVALID"],
      [validContext({ accountVersionId: ALT_CEREMONY_ID }), "ACCOUNT_VERSION_ID_MISMATCH"],
      [validContext({ securityModelId: "0x1234" }), "SECURITY_MODEL_ID_INVALID"],
      [validContext({ securityModelId: ALT_CEREMONY_ID }), "SECURITY_MODEL_ID_MISMATCH"],
      [validContext({ recoveryDomainId: "0x1234" }), "RECOVERY_DOMAIN_ID_INVALID"],
      [validContext({ recoveryDomainId: ALT_CEREMONY_ID }), "RECOVERY_DOMAIN_ID_MISMATCH"],
      [validContext({ account: ZERO_ADDRESS }), "ACCOUNT_INVALID"],
      [validContext({ entryPoint: ZERO_ADDRESS }), "ENTRY_POINT_INVALID"]
    ];
    for (const [ctx, code] of cases) {
      assertCode(() => mod.createStagingJournal(ctx, MINTED_AT), code);
    }
  });

  it("covers candidate input validation error codes", function () {
    const journal = mintJournal();
    const cases = [
      [3, candidateInput(0), "STAGE_ROLE_INVALID"],
      [0, null, "CANDIDATE_INPUT_NOT_OBJECT"],
      [0, (() => {
        const input = candidateInput(0);
        delete input.candidateKind;
        return input;
      })(), "CANDIDATE_INPUT_MISSING_KEY"],
      [0, { ...candidateInput(0), extra: "x" }, "CANDIDATE_INPUT_EXTRA_KEY"],
      [0, { ...candidateInput(0), candidateKind: 1 }, "CANDIDATE_INPUT_KIND_TYPE_INVALID"],
      [0, { ...candidateInput(0), candidateVersion: "1" }, "CANDIDATE_INPUT_VERSION_TYPE_INVALID"],
      [0, { ...candidateInput(0), publicCandidateCommitment: 1 }, "CANDIDATE_INPUT_COMMITMENT_TYPE_INVALID"],
      [0, { ...candidateInput(0), credentialGeneration: 1n }, "CANDIDATE_INPUT_GENERATION_TYPE_INVALID"],
      [0, candidateInput(0, { candidateKind: ROLE_KIND[1] }), "CANDIDATE_INPUT_KIND_MISMATCH"],
      [0, candidateInput(0, { candidateVersion: 2 }), "CANDIDATE_INPUT_VERSION_INVALID"],
      [0, candidateInput(0, { publicCandidateCommitment: ZERO_BYTES32 }), "CANDIDATE_INPUT_COMMITMENT_INVALID"],
      [0, candidateInput(0, { credentialGeneration: "0" }), "CANDIDATE_INPUT_GENERATION_INVALID"]
    ];
    for (const [role, input, code] of cases) {
      assertCode(
        () => mod.stageRoleCandidate(journal, role, input, MINTED_AT + 1),
        code
      );
    }
  });

  it("covers stored manifest entry validation error codes via validateStagingJournalRecord", function () {
    const base = mintJournal();
    const validEntry = {
      role: 0,
      candidateKind: ROLE_KIND[0],
      candidateVersion: 1,
      publicCandidateCommitment: COMMITMENT_A,
      credentialGeneration: "1",
      stagedAtUnixSeconds: String(MINTED_AT + 1)
    };
    function journalWithManifestSlot(slot, entry) {
      const record = clone(withoutChecksum(base));
      record.manifest = { 0: null, 1: null, 2: null };
      record.manifest[String(slot)] = entry;
      record.integrityChecksum = base.integrityChecksum;
      return record;
    }

    const cases = [
      [(() => {
        const record = clone(withoutChecksum(base));
        record.manifest = "bad";
        record.integrityChecksum = base.integrityChecksum;
        return record;
      })(), "JOURNAL_MANIFEST_NOT_OBJECT"],
      [journalWithManifestSlot(0, "bad"), "MANIFEST_ENTRY_NOT_OBJECT"],
      [journalWithManifestSlot(0, (() => {
        const entry = clone(validEntry);
        delete entry.role;
        return entry;
      })()), "MANIFEST_ENTRY_MISSING_KEY"],
      [journalWithManifestSlot(0, { ...validEntry, extra: "x" }), "MANIFEST_ENTRY_EXTRA_KEY"],
      [journalWithManifestSlot(0, { ...validEntry, candidateKind: `${ROLE_KIND[0]}${"Q".repeat(500)}` }), "MANIFEST_ENTRY_OVERSIZED"],
      [journalWithManifestSlot(0, { ...validEntry, role: 3 }), "MANIFEST_ROLE_INVALID"],
      [journalWithManifestSlot(1, { ...validEntry, role: 0 }), "MANIFEST_SLOT_ROLE_MISMATCH"],
      [journalWithManifestSlot(0, { ...validEntry, candidateKind: "BAD" }), "MANIFEST_CANDIDATE_KIND_INVALID"],
      [journalWithManifestSlot(0, { ...validEntry, candidateKind: ROLE_KIND[1] }), "MANIFEST_ROLE_KIND_MISMATCH"],
      [journalWithManifestSlot(0, { ...validEntry, candidateVersion: 2 }), "MANIFEST_CANDIDATE_VERSION_INVALID"],
      [journalWithManifestSlot(0, { ...validEntry, publicCandidateCommitment: ZERO_BYTES32 }), "MANIFEST_COMMITMENT_INVALID"],
      [journalWithManifestSlot(0, { ...validEntry, credentialGeneration: "0" }), "MANIFEST_CREDENTIAL_GENERATION_INVALID"],
      [journalWithManifestSlot(0, { ...validEntry, stagedAtUnixSeconds: "0" }), "MANIFEST_STAGED_AT_INVALID"],
      [journalWithManifestSlot(0, { ...validEntry, stagedAtUnixSeconds: String(Number(EXPIRES) + 1) }), "MANIFEST_STAGED_AT_ORDER_INVALID"]
    ];
    for (const [record, code] of cases) {
      assertCode(() => mod.validateStagingJournalRecord(record), code);
    }
  });

  it("covers journal record validation error codes via validateStagingJournalRecord", function () {
    const valid = mintJournal();
    function mutate(mutator) {
      const record = clone(withoutChecksum(valid));
      mutator(record);
      return attachChecksum(record);
    }

    const cases = [
      [null, "JOURNAL_NOT_OBJECT"],
      [(() => {
        const record = clone(withoutChecksum(valid));
        delete record.schemaVersion;
        return attachChecksum(record);
      })(), "JOURNAL_MISSING_KEY"],
      [mutate((record) => {
        record.extra = "x";
      }), "JOURNAL_EXTRA_KEY"],
      [mutate((record) => {
        record.schemaVersion = 2;
      }), "JOURNAL_SCHEMA_VERSION_UNSUPPORTED"],
      [mutate((record) => {
        record.formatProvenance = "bad";
      }), "JOURNAL_FORMAT_PROVENANCE_INVALID"],
      [mutate((record) => {
        record.ceremonyId = ZERO_BYTES32;
      }), "JOURNAL_CEREMONY_ID_INVALID"],
      [mutate((record) => {
        record.enrollmentCeremonyHash = "0x1234";
      }), "JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID"],
      [mutate((record) => {
        record.accountVersionId = "0x1234";
      }), "JOURNAL_ACCOUNT_VERSION_ID_INVALID"],
      [mutate((record) => {
        record.accountVersionId = ALT_CEREMONY_ID;
      }), "JOURNAL_ACCOUNT_VERSION_ID_MISMATCH"],
      [mutate((record) => {
        record.securityModelId = "0x1234";
      }), "JOURNAL_SECURITY_MODEL_ID_INVALID"],
      [mutate((record) => {
        record.securityModelId = ALT_CEREMONY_ID;
      }), "JOURNAL_SECURITY_MODEL_ID_MISMATCH"],
      [mutate((record) => {
        record.recoveryDomainId = "0x1234";
      }), "JOURNAL_RECOVERY_DOMAIN_ID_INVALID"],
      [mutate((record) => {
        record.recoveryDomainId = ALT_CEREMONY_ID;
      }), "JOURNAL_RECOVERY_DOMAIN_ID_MISMATCH"],
      [mutate((record) => {
        record.account = ZERO_ADDRESS;
      }), "JOURNAL_ACCOUNT_INVALID"],
      [mutate((record) => {
        record.chainId = "0";
      }), "JOURNAL_CHAIN_ID_INVALID"],
      [mutate((record) => {
        record.entryPoint = ZERO_ADDRESS;
      }), "JOURNAL_ENTRY_POINT_INVALID"],
      [mutate((record) => {
        record.expectedRecoveryEpoch = "0";
      }), "JOURNAL_EXPECTED_RECOVERY_EPOCH_INVALID"],
      [mutate((record) => {
        record.expectedValidatorEpoch = "0";
      }), "JOURNAL_EXPECTED_VALIDATOR_EPOCH_INVALID"],
      [mutate((record) => {
        record.expiresAtUnixSeconds = "0";
      }), "JOURNAL_EXPIRY_INVALID"],
      [mutate((record) => {
        record.state = "BAD";
      }), "JOURNAL_STATE_INVALID"],
      [mutate((record) => {
        record.createdAtUnixSeconds = "0";
      }), "JOURNAL_CREATED_AT_INVALID"],
      [mutate((record) => {
        record.updatedAtUnixSeconds = "0";
      }), "JOURNAL_UPDATED_AT_INVALID"],
      [mutate((record) => {
        record.updatedAtUnixSeconds = String(MINTED_AT - 1);
      }), "JOURNAL_TIMESTAMP_ORDER_INVALID"],
      [mutate((record) => {
        record.createdAtUnixSeconds = EXPIRES;
      }), "JOURNAL_CREATION_NOT_BEFORE_EXPIRY"],
      [mutate((record) => {
        record.state = "EXPIRED";
        record.updatedAtUnixSeconds = String(MINTED_AT);
      }), "JOURNAL_STATE_TIMESTAMP_MISMATCH"],
      [mutate((record) => {
        record.manifest = null;
      }), "JOURNAL_MANIFEST_NOT_OBJECT"],
      [mutate((record) => {
        record.manifest = { 0: null, 1: null };
      }), "JOURNAL_MANIFEST_MISSING_KEY"],
      [mutate((record) => {
        record.manifest = { 0: null, 1: null, 2: null, 3: null };
      }), "JOURNAL_MANIFEST_EXTRA_KEY"],
      [mutate((record) => {
        record.endReason = "BAD";
      }), "JOURNAL_END_REASON_INVALID"],
      [mutate((record) => {
        record.state = "CANCELLED";
        record.endReason = null;
      }), "JOURNAL_STATE_END_REASON_MISMATCH"],
      [mutate((record) => {
        record.enrollmentCeremonyHash = ENROLLMENT_HASH;
        record.expiresAtUnixSeconds = String(Number(EXPIRES) + 1);
      }), "JOURNAL_CONTEXT_HASH_MISMATCH"],
      [(() => {
        const record = attachChecksum(clone(withoutChecksum(valid)));
        return { ...record, integrityChecksum: "0x1234" };
      })(), "JOURNAL_CHECKSUM_FORMAT_INVALID"],
      [(() => {
        const record = clone(valid);
        record.integrityChecksum = ALT_CEREMONY_ID;
        return record;
      })(), "JOURNAL_CHECKSUM_MISMATCH"],
      [(() => {
        const record = clone(valid);
        record.accountVersionId = ALT_CEREMONY_ID;
        return record;
      })(), "JOURNAL_ACCOUNT_VERSION_ID_MISMATCH"]
    ];
    for (const [record, code] of cases) {
      assertCode(() => mod.validateStagingJournalRecord(record), code);
    }
  });

  it("exposes validateStagingJournalRecord as single-argument API without ValidateStagingJournalOptions export", function () {
    assert.equal(mod.validateStagingJournalRecord.length, 1);
    assert.equal(
      Object.prototype.hasOwnProperty.call(mod, "ValidateStagingJournalOptions"),
      false
    );
  });

  it("rejects alternate-epoch enrollmentCeremonyHash at createStagingJournal", function () {
    const hashForEpochs1 = independentEnrollmentHash(EXPIRES);
    assertCode(
      () => mod.createStagingJournal(
        validContext({
          expectedRecoveryEpoch: "9",
          expectedValidatorEpoch: "9",
          enrollmentCeremonyHash: hashForEpochs1
        }),
        MINTED_AT
      ),
      "CEREMONY_CONTEXT_HASH_MISMATCH"
    );
  });

  it("classifies well-formed enrollmentCeremonyHash mismatch as JOURNAL_CONTEXT_HASH_MISMATCH", function () {
    const valid = mintJournal();
    const mismatched = attachChecksum({
      ...clone(withoutChecksum(valid)),
      enrollmentCeremonyHash: ALT_CEREMONY_ID
    });
    assertCode(
      () => mod.validateStagingJournalRecord(mismatched),
      "JOURNAL_CONTEXT_HASH_MISMATCH"
    );
  });

  it("classifies malformed enrollmentCeremonyHash as JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID", function () {
    const valid = mintJournal();
    const malformed = attachChecksum({
      ...clone(withoutChecksum(valid)),
      enrollmentCeremonyHash: "0x1234"
    });
    assertCode(
      () => mod.validateStagingJournalRecord(malformed),
      "JOURNAL_ENROLLMENT_CEREMONY_HASH_INVALID"
    );
  });

  it("validates candidate and manifest entry own-key schemas", function () {
    const input = candidateInput(0);
    assert.deepEqual(Object.keys(input), [...CANDIDATE_INPUT_OWN_KEYS]);
    const journal = mod.stageRoleCandidate(
      mintJournal(),
      0,
      input,
      MINTED_AT + 1
    );
    assert.deepEqual(Object.keys(journal.manifest["0"]), [...MANIFEST_ENTRY_OWN_KEYS]);
    assert.deepEqual(Object.keys(journal.manifest), ["0", "1", "2"]);
  });

  it("enforces state, endReason, and timestamp invariants across transitions", function () {
    const journal = mintJournal();
    assert.equal(journal.state, "STAGING");
    assert.equal(journal.endReason, null);
    assert.ok(Number(journal.createdAtUnixSeconds) < Number(journal.expiresAtUnixSeconds));
    assert.ok(Number(journal.updatedAtUnixSeconds) >= Number(journal.createdAtUnixSeconds));

    const cancelled = mod.cancelStagingJournal(journal, MINTED_AT + 1);
    assert.equal(cancelled.endReason, cancelled.state);
    assert.ok(Number(cancelled.updatedAtUnixSeconds) < Number(cancelled.expiresAtUnixSeconds));

    const expired = mod.expireStagingJournalIfNeeded(journal, Number(EXPIRES));
    assert.equal(expired.endReason, expired.state);
    assert.ok(Number(expired.updatedAtUnixSeconds) >= Number(expired.expiresAtUnixSeconds));
  });

  it("rejects nowUnixSeconds above uint48 maximum as INVALID_NOW", function () {
    const max = 281474976710655;
    assertCode(() => mintJournal({}, max + 1), "INVALID_NOW");
    const farExpires = String(max);
    const farHash = independentEnrollmentHash({
      expiresAt: farExpires,
      expectedRecoveryEpoch: "1",
      expectedValidatorEpoch: "1"
    });
    const journal = mod.createStagingJournal(
      validContext({
        expiresAtUnixSeconds: farExpires,
        enrollmentCeremonyHash: farHash
      }),
      1
    );
    const expired = mod.expireStagingJournalIfNeeded(journal, max);
    assert.equal(expired.state, "EXPIRED");
    assertCode(
      () => mod.expireStagingJournalIfNeeded(journal, max + 1),
      "INVALID_NOW"
    );
  });

  it("validates candidate before INVALID_NOW, clock regression, and expiry in stageRoleCandidate", function () {
    const journal = mintJournal();
    assertCode(
      () => mod.stageRoleCandidate(
        journal,
        0,
        candidateInput(0, { candidateKind: ROLE_KIND[1] }),
        Number.NaN
      ),
      "CANDIDATE_INPUT_KIND_MISMATCH"
    );
    assertCode(
      () => mod.stageRoleCandidate(
        journal,
        0,
        candidateInput(0, { credentialGeneration: "0" }),
        Number(EXPIRES)
      ),
      "CANDIDATE_INPUT_GENERATION_INVALID"
    );
    const staged = mod.stageRoleCandidate(
      journal,
      0,
      candidateInput(0),
      MINTED_AT + 5
    );
    assertCode(
      () => mod.stageRoleCandidate(
        staged,
        1,
        candidateInput(1, { candidateVersion: 2 }),
        MINTED_AT + 4
      ),
      "CANDIDATE_INPUT_VERSION_INVALID"
    );
  });

  it("enforces journal validator precedence across combined invalid fields", function () {
    const valid = mintJournal();

    const pinnedAndBadChecksum = attachChecksum({
      ...clone(withoutChecksum(valid)),
      accountVersionId: ALT_CEREMONY_ID
    });
    pinnedAndBadChecksum.integrityChecksum = "0x1234";
    assertCode(
      () => mod.validateStagingJournalRecord(pinnedAndBadChecksum),
      "JOURNAL_ACCOUNT_VERSION_ID_MISMATCH"
    );

    const contextAndBadChecksum = {
      ...clone(withoutChecksum(valid)),
      enrollmentCeremonyHash: ALT_CEREMONY_ID,
      integrityChecksum: "0x1234"
    };
    assertCode(
      () => mod.validateStagingJournalRecord(contextAndBadChecksum),
      "JOURNAL_CONTEXT_HASH_MISMATCH"
    );

    const contextAndWrongChecksum = attachChecksum({
      ...clone(withoutChecksum(valid)),
      enrollmentCeremonyHash: ALT_CEREMONY_ID
    });
    // attachChecksum makes checksum match mutated record; force mismatch too.
    contextAndWrongChecksum.integrityChecksum = valid.integrityChecksum;
    assertCode(
      () => mod.validateStagingJournalRecord(contextAndWrongChecksum),
      "JOURNAL_CONTEXT_HASH_MISMATCH"
    );

    const badFormatOnly = clone(valid);
    badFormatOnly.integrityChecksum = "0x1234";
    assertCode(
      () => mod.validateStagingJournalRecord(badFormatOnly),
      "JOURNAL_CHECKSUM_FORMAT_INVALID"
    );
  });

  it("rejects uppercase and mixed-case bytes32 input without silent lowercasing", function () {
    const upperCeremony = `0x${CEREMONY_ID.slice(2).toUpperCase()}`;
    const mixedCeremony = `0x${CEREMONY_ID.slice(2, 10).toUpperCase()}${CEREMONY_ID.slice(10)}`;
    assertCode(
      () => mintJournal({ ceremonyId: upperCeremony }),
      "CEREMONY_ID_INVALID"
    );
    assertCode(
      () => mintJournal({ ceremonyId: mixedCeremony }),
      "CEREMONY_ID_INVALID"
    );
    assertCode(
      () => mintJournal({
        enrollmentCeremonyHash: `0x${ENROLLMENT_HASH.slice(2).toUpperCase()}`
      }),
      "ENROLLMENT_CEREMONY_HASH_INVALID"
    );
    assertCode(
      () => mintJournal({
        accountVersionId: `0x${PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID.slice(2).toUpperCase()}`
      }),
      "ACCOUNT_VERSION_ID_INVALID"
    );
    assertCode(
      () => mintJournal({
        securityModelId: `0x${PHILCORE_V2_LOCAL_SECURITY_MODEL_ID.slice(2).toUpperCase()}`
      }),
      "SECURITY_MODEL_ID_INVALID"
    );
    assertCode(
      () => mintJournal({
        recoveryDomainId: `0x${PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID.slice(2).toUpperCase()}`
      }),
      "RECOVERY_DOMAIN_ID_INVALID"
    );

    const journal = mintJournal();
    const mixedCommitment = `0x${"aB".repeat(32)}`;
    assertCode(
      () => mod.stageRoleCandidate(
        journal,
        0,
        candidateInput(0, {
          publicCandidateCommitment: mixedCommitment
        }),
        MINTED_AT + 1
      ),
      "CANDIDATE_INPUT_COMMITMENT_INVALID"
    );
    assertCode(
      () => mod.stageRoleCandidate(
        journal,
        0,
        candidateInput(0, {
          publicCandidateCommitment: `0x${"AB".repeat(32)}`
        }),
        MINTED_AT + 1
      ),
      "CANDIDATE_INPUT_COMMITMENT_INVALID"
    );

    const upperPinnedWellFormed = `0x${"AA".repeat(32)}`;
    assertCode(
      () => mintJournal({ accountVersionId: upperPinnedWellFormed }),
      "ACCOUNT_VERSION_ID_INVALID"
    );

    const storedUpper = attachChecksum({
      ...clone(withoutChecksum(journal)),
      ceremonyId: upperCeremony
    });
    assertCode(
      () => mod.validateStagingJournalRecord(storedUpper),
      "JOURNAL_CEREMONY_ID_INVALID"
    );

    const staged = mod.stageRoleCandidate(
      journal,
      0,
      candidateInput(0),
      MINTED_AT + 1
    );
    const entry = clone(staged.manifest["0"]);
    entry.publicCandidateCommitment = `0x${"AB".repeat(32)}`;
    const storedEntryUpper = attachChecksum({
      ...clone(withoutChecksum(staged)),
      manifest: { "0": entry, "1": null, "2": null }
    });
    assertCode(
      () => mod.validateStagingJournalRecord(storedEntryUpper),
      "MANIFEST_COMMITMENT_INVALID"
    );
  });

  it("rejects noncanonical EIP-55 account and entryPoint without silent upgrade", function () {
    assertCode(
      () => mintJournal({ account: ACCOUNT.toLowerCase() }),
      "ACCOUNT_INVALID"
    );
    assertCode(
      () => mintJournal({ account: ACCOUNT.toUpperCase().replace("0X", "0x") }),
      "ACCOUNT_INVALID"
    );
    const wrongChecksum = `0x${ACCOUNT.slice(2, 4).toLowerCase()}${ACCOUNT.slice(4)}`;
    if (wrongChecksum !== ACCOUNT) {
      assertCode(
        () => mintJournal({ account: wrongChecksum }),
        "ACCOUNT_INVALID"
      );
    }
    assertCode(
      () => mintJournal({ entryPoint: ENTRY_POINT.toLowerCase() }),
      "ENTRY_POINT_INVALID"
    );
    assertCode(
      () => mintJournal({ entryPoint: ZERO_ADDRESS }),
      "ENTRY_POINT_INVALID"
    );

    const journal = mintJournal();
    const storedLowerAccount = attachChecksum({
      ...clone(withoutChecksum(journal)),
      account: ACCOUNT.toLowerCase()
    });
    assertCode(
      () => mod.validateStagingJournalRecord(storedLowerAccount),
      "JOURNAL_ACCOUNT_INVALID"
    );
    const storedLowerEntry = attachChecksum({
      ...clone(withoutChecksum(journal)),
      entryPoint: ENTRY_POINT.toLowerCase()
    });
    assertCode(
      () => mod.validateStagingJournalRecord(storedLowerEntry),
      "JOURNAL_ENTRY_POINT_INVALID"
    );
  });

  it("imports no filesystem durability, network, signing, or secret patterns", function () {
    const source = fs.readFileSync(MODULE_PATH, "utf8");
    assert.equal(/F_FULLFSYNC|fsync|node:fs|node:net|fetch\(|http\.|https\.|WebSocket/i.test(source), false);
    assert.equal(/sign\(|signMessage|privateKey|mnemonic|seed|secret|ciphertext|password/i.test(source), false);
    assert.equal(/Date\.now\(|randomBytes|node:crypto\.random/i.test(source), false);
    assert.ok(source.includes("computePhilCoreV2LocalEnrollmentCeremonyHash"));
    assert.ok(source.includes("PHILCORE_V2_STAGING_JOURNAL_CHECKSUM_PREFIX"));
  });
});

describe("PhilCore V2 consumer recovery staging journal (5B-1 pure) -- property-access safety", function () {
  function throwingGetterObject(base, key, error) {
    const out = { ...base };
    Object.defineProperty(out, key, {
      get() {
        throw error;
      },
      enumerable: true,
      configurable: true
    });
    return out;
  }

  // Object.keys() and Object.prototype.hasOwnProperty.call() both rely on
  // the same [[GetOwnProperty]] trap, so a blanket getOwnPropertyDescriptor
  // throw is caught by whichever runs first (enumeration). To isolate the
  // presence-check path specifically, let the trap succeed for exactly the
  // number of calls Object.keys() will make (one per own key), then throw
  // on the next call -- which is the first hasOwnProperty-driven check.
  function presenceOnlyTrap(base, ownKeyCount) {
    let calls = 0;
    return new Proxy(base, {
      getOwnPropertyDescriptor(target, key) {
        calls += 1;
        if (calls > ownKeyCount) {
          throw new Error("presence trap");
        }
        return Object.getOwnPropertyDescriptor(target, key);
      }
    });
  }

  function assertClassified(fn, code) {
    let threw = false;
    try {
      fn();
    } catch (error) {
      threw = true;
      assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
      assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
      assert.ok(error.cause, "expected a cause to be attached");
      assert.equal(
        Object.prototype.propertyIsEnumerable.call(error, "cause"),
        false,
        "cause must be non-enumerable"
      );
    }
    assert.ok(threw, "expected function to throw");
  }

  describe("ceremony context (createStagingJournal / normalizeCeremonyContext)", function () {
    it("classifies a throwing Object.keys/ownKeys trap as CEREMONY_CONTEXT_NOT_OBJECT", function () {
      const trap = new Proxy(validContext(), {
        ownKeys() {
          throw new Error("enumeration trap");
        }
      });
      assertClassified(() => mod.createStagingJournal(trap, MINTED_AT), "CEREMONY_CONTEXT_NOT_OBJECT");
    });

    it("classifies a throwing hasOwnProperty/getOwnPropertyDescriptor trap as CEREMONY_CONTEXT_MISSING_KEY", function () {
      const base = validContext();
      const trap = presenceOnlyTrap(base, Object.keys(base).length);
      assertClassified(() => mod.createStagingJournal(trap, MINTED_AT), "CEREMONY_CONTEXT_MISSING_KEY");
    });

    it("classifies a throwing getter on each of the eleven context fields with that field's own code", function () {
      const fieldCodes = [
        ["ceremonyId", "CEREMONY_ID_INVALID"],
        ["enrollmentCeremonyHash", "ENROLLMENT_CEREMONY_HASH_INVALID"],
        ["accountVersionId", "ACCOUNT_VERSION_ID_INVALID"],
        ["securityModelId", "SECURITY_MODEL_ID_INVALID"],
        ["recoveryDomainId", "RECOVERY_DOMAIN_ID_INVALID"],
        ["account", "ACCOUNT_INVALID"],
        ["chainId", "CHAIN_ID_INVALID"],
        ["entryPoint", "ENTRY_POINT_INVALID"],
        ["expectedRecoveryEpoch", "EXPECTED_RECOVERY_EPOCH_INVALID"],
        ["expectedValidatorEpoch", "EXPECTED_VALIDATOR_EPOCH_INVALID"],
        ["expiresAtUnixSeconds", "CEREMONY_EXPIRY_INVALID"]
      ];
      for (const [field, code] of fieldCodes) {
        const hostile = throwingGetterObject(validContext(), field, new Error(`boom:${field}`));
        assertClassified(() => mod.createStagingJournal(hostile, MINTED_AT), code);
      }
    });

    it("lets an earlier field's semantic error win over a later field's throwing getter", function () {
      // ceremonyId (field 1) is semantically invalid; expiresAtUnixSeconds
      // (field 11) has a throwing getter. Field 1 must be read and
      // validated -- and fail -- before field 11 is ever touched.
      const hostile = throwingGetterObject(
        validContext({ ceremonyId: ZERO_BYTES32 }),
        "expiresAtUnixSeconds",
        new Error("must never be reached")
      );
      assertCode(() => mod.createStagingJournal(hostile, MINTED_AT), "CEREMONY_ID_INVALID");
    });

    it("rejects an extra key before ever reading any field getter", function () {
      const hostile = throwingGetterObject(
        { ...validContext(), extraField: "x" },
        "ceremonyId",
        new Error("must never be reached")
      );
      assertCode(() => mod.createStagingJournal(hostile, MINTED_AT), "CEREMONY_CONTEXT_EXTRA_KEY");
    });

    it("rejects a missing key before ever reading any field getter", function () {
      const base = validContext();
      delete base.chainId;
      const hostile = throwingGetterObject(base, "ceremonyId", new Error("must never be reached"));
      assertCode(() => mod.createStagingJournal(hostile, MINTED_AT), "CEREMONY_CONTEXT_MISSING_KEY");
    });

    it("reads each context field getter exactly once", function () {
      const reads = {};
      const base = validContext();
      const counted = {};
      for (const key of CONTEXT_OWN_KEYS) {
        reads[key] = 0;
        Object.defineProperty(counted, key, {
          get() {
            reads[key] += 1;
            return base[key];
          },
          enumerable: true,
          configurable: true
        });
      }
      const journal = mod.createStagingJournal(counted, MINTED_AT);
      assert.equal(journal.state, "STAGING");
      for (const key of CONTEXT_OWN_KEYS) {
        assert.equal(reads[key], 1, `expected exactly one read of ${key}, got ${reads[key]}`);
      }
    });
  });

  describe("candidate input (stageRoleCandidate / validateCandidateInput)", function () {
    it("classifies a throwing enumeration trap as CANDIDATE_INPUT_NOT_OBJECT", function () {
      const journal = mintJournal();
      const trap = new Proxy(candidateInput(0), {
        ownKeys() {
          throw new Error("enumeration trap");
        }
      });
      assertClassified(
        () => mod.stageRoleCandidate(journal, 0, trap, MINTED_AT + 1),
        "CANDIDATE_INPUT_NOT_OBJECT"
      );
    });

    it("classifies a throwing presence trap as CANDIDATE_INPUT_MISSING_KEY", function () {
      const journal = mintJournal();
      const base = candidateInput(0);
      const trap = presenceOnlyTrap(base, Object.keys(base).length);
      assertClassified(
        () => mod.stageRoleCandidate(journal, 0, trap, MINTED_AT + 1),
        "CANDIDATE_INPUT_MISSING_KEY"
      );
    });

    it("classifies a throwing getter on each of the four candidate fields with that field's own type code", function () {
      const journal = mintJournal();
      const fieldCodes = [
        ["candidateKind", "CANDIDATE_INPUT_KIND_TYPE_INVALID"],
        ["candidateVersion", "CANDIDATE_INPUT_VERSION_TYPE_INVALID"],
        ["publicCandidateCommitment", "CANDIDATE_INPUT_COMMITMENT_TYPE_INVALID"],
        ["credentialGeneration", "CANDIDATE_INPUT_GENERATION_TYPE_INVALID"]
      ];
      for (const [field, code] of fieldCodes) {
        const hostile = throwingGetterObject(candidateInput(0), field, new Error(`boom:${field}`));
        assertClassified(
          () => mod.stageRoleCandidate(journal, 0, hostile, MINTED_AT + 1),
          code
        );
      }
    });

    it("lets an earlier field's type error win over a later field's throwing getter", function () {
      const journal = mintJournal();
      const hostile = throwingGetterObject(
        candidateInput(0, { candidateKind: 42 }),
        "credentialGeneration",
        new Error("must never be reached")
      );
      assertCode(
        () => mod.stageRoleCandidate(journal, 0, hostile, MINTED_AT + 1),
        "CANDIDATE_INPUT_KIND_TYPE_INVALID"
      );
    });

    it("rejects an extra candidate key before reading any field getter", function () {
      const journal = mintJournal();
      const hostile = throwingGetterObject(
        { ...candidateInput(0), extra: "x" },
        "candidateKind",
        new Error("must never be reached")
      );
      assertCode(
        () => mod.stageRoleCandidate(journal, 0, hostile, MINTED_AT + 1),
        "CANDIDATE_INPUT_EXTRA_KEY"
      );
    });

    it("rejects a missing candidate key before reading any field getter", function () {
      const journal = mintJournal();
      const base = candidateInput(0);
      delete base.credentialGeneration;
      const hostile = throwingGetterObject(base, "candidateKind", new Error("must never be reached"));
      assertCode(
        () => mod.stageRoleCandidate(journal, 0, hostile, MINTED_AT + 1),
        "CANDIDATE_INPUT_MISSING_KEY"
      );
    });

    it("reads each candidate field getter exactly once", function () {
      const journal = mintJournal();
      const base = candidateInput(0);
      const reads = { candidateKind: 0, candidateVersion: 0, publicCandidateCommitment: 0, credentialGeneration: 0 };
      const counted = {};
      for (const key of Object.keys(reads)) {
        Object.defineProperty(counted, key, {
          get() {
            reads[key] += 1;
            return base[key];
          },
          enumerable: true,
          configurable: true
        });
      }
      const next = mod.stageRoleCandidate(journal, 0, counted, MINTED_AT + 1);
      assert.equal(next.manifest["0"].candidateKind, base.candidateKind);
      for (const key of Object.keys(reads)) {
        assert.equal(reads[key], 1, `expected exactly one read of ${key}, got ${reads[key]}`);
      }
    });
  });

  describe("stored journal and manifest (validateStagingJournalRecord)", function () {
    it("classifies a throwing top-level enumeration trap as JOURNAL_NOT_OBJECT", function () {
      const journal = mintJournal();
      const trap = new Proxy(journal, {
        ownKeys() {
          throw new Error("enumeration trap");
        }
      });
      assertClassified(() => mod.validateStagingJournalRecord(trap), "JOURNAL_NOT_OBJECT");
    });

    it("classifies a throwing top-level presence trap as JOURNAL_MISSING_KEY", function () {
      const journal = mintJournal();
      const trap = presenceOnlyTrap(journal, Object.keys(journal).length);
      assertClassified(() => mod.validateStagingJournalRecord(trap), "JOURNAL_MISSING_KEY");
    });

    it("classifies a throwing getter on representative journal fields with each field's own code", function () {
      const journal = mintJournal();
      const fieldCodes = [
        ["ceremonyId", "JOURNAL_CEREMONY_ID_INVALID"],
        ["chainId", "JOURNAL_CHAIN_ID_INVALID"],
        ["state", "JOURNAL_STATE_INVALID"],
        ["createdAtUnixSeconds", "JOURNAL_CREATED_AT_INVALID"],
        ["endReason", "JOURNAL_END_REASON_INVALID"],
        ["integrityChecksum", "JOURNAL_CHECKSUM_FORMAT_INVALID"]
      ];
      for (const [field, code] of fieldCodes) {
        const hostile = throwingGetterObject(journal, field, new Error(`boom:${field}`));
        assertClassified(() => mod.validateStagingJournalRecord(hostile), code);
      }
    });

    it("lets an earlier field's semantic error win over a later field's throwing getter", function () {
      const journal = mintJournal();
      // ceremonyId (field 3) is malformed; integrityChecksum (field 19,
      // read only after every semantic field) has a throwing getter.
      const hostile = throwingGetterObject(
        { ...journal, ceremonyId: ZERO_BYTES32 },
        "integrityChecksum",
        new Error("must never be reached")
      );
      assertCode(() => mod.validateStagingJournalRecord(hostile), "JOURNAL_CEREMONY_ID_INVALID");
    });

    it("classifies a throwing manifest enumeration/presence trap distinctly from entry traps", function () {
      const journal = mintJournal();
      const hostileManifest = new Proxy(journal.manifest, {
        ownKeys() {
          throw new Error("manifest enumeration trap");
        }
      });
      assertClassified(
        () => mod.validateStagingJournalRecord({ ...journal, manifest: hostileManifest }),
        "JOURNAL_MANIFEST_NOT_OBJECT"
      );
    });

    it("classifies a throwing manifest slot getter as JOURNAL_MANIFEST_NOT_OBJECT (via MANIFEST_ENTRY_NOT_OBJECT read code)", function () {
      const journal = mod.stageRoleCandidate(mintJournal(), 0, candidateInput(0), MINTED_AT + 1);
      const hostileManifest = throwingGetterObject(journal.manifest, "0", new Error("slot trap"));
      assertClassified(
        () => mod.validateStagingJournalRecord({ ...journal, manifest: hostileManifest }),
        "MANIFEST_ENTRY_NOT_OBJECT"
      );
    });

    it("classifies a throwing getter on every stored-entry field category, oversized-check requiring all six reads first", function () {
      const staged = mod.stageRoleCandidate(mintJournal(), 0, candidateInput(0), MINTED_AT + 1);
      const validEntry = staged.manifest["0"];
      const fieldCodes = [
        ["role", "MANIFEST_ROLE_INVALID"],
        ["candidateKind", "MANIFEST_CANDIDATE_KIND_INVALID"],
        ["candidateVersion", "MANIFEST_CANDIDATE_VERSION_INVALID"],
        ["publicCandidateCommitment", "MANIFEST_COMMITMENT_INVALID"],
        ["credentialGeneration", "MANIFEST_CREDENTIAL_GENERATION_INVALID"],
        ["stagedAtUnixSeconds", "MANIFEST_STAGED_AT_INVALID"]
      ];
      for (const [field, code] of fieldCodes) {
        const hostileEntry = throwingGetterObject(validEntry, field, new Error(`boom:${field}`));
        const hostileJournal = {
          ...staged,
          manifest: { ...staged.manifest, "0": hostileEntry }
        };
        assertClassified(() => mod.validateStagingJournalRecord(hostileJournal), code);
      }
    });

    it("lets a throwing getter on an earlier stored-entry field (role) surface before touching a later field", function () {
      const staged = mod.stageRoleCandidate(mintJournal(), 0, candidateInput(0), MINTED_AT + 1);
      const validEntry = staged.manifest["0"];
      let laterFieldRead = false;
      const hostileEntry = { ...validEntry };
      Object.defineProperty(hostileEntry, "role", {
        get() {
          throw new Error("role trap");
        },
        enumerable: true,
        configurable: true
      });
      Object.defineProperty(hostileEntry, "credentialGeneration", {
        get() {
          laterFieldRead = true;
          return validEntry.credentialGeneration;
        },
        enumerable: true,
        configurable: true
      });
      const hostileJournal = { ...staged, manifest: { ...staged.manifest, "0": hostileEntry } };
      assertClassified(() => mod.validateStagingJournalRecord(hostileJournal), "MANIFEST_ROLE_INVALID");
      assert.equal(laterFieldRead, false, "credentialGeneration must not be read when role's own getter throws");
    });

    it("checks end-reason and context-hash before ever inspecting the checksum", function () {
      const journal = mintJournal();
      const hostile = throwingGetterObject(
        { ...journal, endReason: "NOT_A_VALID_REASON" },
        "integrityChecksum",
        new Error("must never be reached")
      );
      assertCode(() => mod.validateStagingJournalRecord(hostile), "JOURNAL_END_REASON_INVALID");
    });

    it("checks checksum format before checksum mismatch, and checksum mismatch is last", function () {
      const journal = mintJournal();
      assertCode(
        () => mod.validateStagingJournalRecord({ ...journal, integrityChecksum: "not-hex" }),
        "JOURNAL_CHECKSUM_FORMAT_INVALID"
      );
      assertCode(
        () => mod.validateStagingJournalRecord({ ...journal, integrityChecksum: `0x${"ab".repeat(32)}` }),
        "JOURNAL_CHECKSUM_MISMATCH"
      );
    });

    it("performs no rereads of a hostile top-level object across a full successful validation", function () {
      const journal = mintJournal();
      const reads = {};
      const counted = {};
      for (const key of JOURNAL_OWN_KEYS) {
        reads[key] = 0;
        Object.defineProperty(counted, key, {
          get() {
            reads[key] += 1;
            return journal[key];
          },
          enumerable: true,
          configurable: true
        });
      }
      const validated = mod.validateStagingJournalRecord(counted);
      assert.equal(validated.state, "STAGING");
      for (const key of JOURNAL_OWN_KEYS) {
        assert.equal(reads[key], 1, `expected exactly one read of ${key}, got ${reads[key]}`);
      }
    });
  });

  describe("checksum and manifest projection (computeStagingJournalChecksum)", function () {
    it("classifies a throwing top-level field getter with that field's own structural code", function () {
      const journal = mintJournal();
      const hostile = throwingGetterObject(withoutChecksum(journal), "chainId", new Error("boom"));
      assertClassified(() => mod.computeStagingJournalChecksum(hostile), "JOURNAL_CHAIN_ID_INVALID");
    });

    it("classifies a throwing manifest slot getter during checksum projection", function () {
      const journal = mintJournal();
      const hostileManifest = throwingGetterObject(journal.manifest, "0", new Error("slot boom"));
      const hostile = { ...withoutChecksum(journal), manifest: hostileManifest };
      assertClassified(() => mod.computeStagingJournalChecksum(hostile), "JOURNAL_MANIFEST_NOT_OBJECT");
    });

    it("classifies a throwing manifest entry field getter during checksum projection", function () {
      const staged = mod.stageRoleCandidate(mintJournal(), 0, candidateInput(0), MINTED_AT + 1);
      const hostileEntry = throwingGetterObject(staged.manifest["0"], "credentialGeneration", new Error("field boom"));
      const hostile = {
        ...withoutChecksum(staged),
        manifest: { ...staged.manifest, "0": hostileEntry }
      };
      assertClassified(
        () => mod.computeStagingJournalChecksum(hostile),
        "MANIFEST_CREDENTIAL_GENERATION_INVALID"
      );
    });

    it("classifies a hostile toJSON that throws during JSON.stringify as JOURNAL_NOT_OBJECT with the raw value as cause", function () {
      const journal = withoutChecksum(mintJournal());
      const hostileChainId = {
        toJSON() {
          throw new Error("toJSON boom");
        }
      };
      const hostile = { ...journal, chainId: hostileChainId };
      assertClassified(() => mod.computeStagingJournalChecksum(hostile), "JOURNAL_NOT_OBJECT");
    });
  });
});

describe("PhilCore V2 consumer recovery staging journal (5B-1 pure) -- hostile-Proxy and explicit-undefined hardening", function () {
  function throwingGetterObject(base, key, error) {
    const out = { ...base };
    Object.defineProperty(out, key, {
      get() {
        throw error;
      },
      enumerable: true,
      configurable: true
    });
    return out;
  }

  // A Proxy whose getPrototypeOf trap throws is itself hostile to
  // `instanceof` (used internally to detect an already-classified error);
  // if that trap's own thrown value escaped raw, it would defeat the whole
  // classification mechanism.
  const rawEscape = new Error("raw escape from getPrototypeOf trap");
  function hostileThrownValue() {
    return new Proxy(
      {},
      {
        getPrototypeOf() {
          throw rawEscape;
        }
      }
    );
  }

  function assertClassifiedNotRawEscape(fn, code) {
    let threw = false;
    try {
      fn();
    } catch (error) {
      threw = true;
      assert.notEqual(error, rawEscape, "the getPrototypeOf trap's raw value must never escape");
      assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
      assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
      assert.ok(
        Object.prototype.hasOwnProperty.call(error, "cause"),
        "expected a cause property to be attached"
      );
      assert.equal(error.cause, hostileThrownValueRef, "cause must be the original hostile value, not rawEscape");
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected function to throw");
  }

  let hostileThrownValueRef;

  it("classifies a field getter throwing a hostile Proxy (instanceof-unsafe cause) without leaking the trap's raw value", function () {
    hostileThrownValueRef = hostileThrownValue();
    const ctx = throwingGetterObject(validContext(), "ceremonyId", hostileThrownValueRef);
    assertClassifiedNotRawEscape(() => mod.createStagingJournal(ctx, MINTED_AT), "CEREMONY_ID_INVALID");
  });

  it("classifies an enumeration trap throwing a hostile Proxy without leaking the trap's raw value", function () {
    hostileThrownValueRef = hostileThrownValue();
    const capturedHostile = hostileThrownValueRef;
    const trap = new Proxy(validContext(), {
      ownKeys() {
        throw capturedHostile;
      }
    });
    assertClassifiedNotRawEscape(() => mod.createStagingJournal(trap, MINTED_AT), "CEREMONY_CONTEXT_NOT_OBJECT");
  });

  it("classifies a presence trap throwing a hostile Proxy without leaking the trap's raw value", function () {
    hostileThrownValueRef = hostileThrownValue();
    const capturedHostile = hostileThrownValueRef;
    const base = validContext();
    let calls = 0;
    const trap = new Proxy(base, {
      getOwnPropertyDescriptor(target, key) {
        calls += 1;
        if (calls > Object.keys(base).length) {
          throw capturedHostile;
        }
        return Object.getOwnPropertyDescriptor(target, key);
      }
    });
    assertClassifiedNotRawEscape(() => mod.createStagingJournal(trap, MINTED_AT), "CEREMONY_CONTEXT_MISSING_KEY");
  });

  it("classifies a property getter throwing undefined, with its own non-enumerable cause equal to undefined", function () {
    const ctx = { ...validContext() };
    Object.defineProperty(ctx, "chainId", {
      get() {
        // eslint-disable-next-line no-throw-literal
        throw undefined;
      },
      enumerable: true,
      configurable: true
    });
    let threw = false;
    try {
      mod.createStagingJournal(ctx, MINTED_AT);
    } catch (error) {
      threw = true;
      assert.equal(error.code, "CHAIN_ID_INVALID");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"), "expected an own cause property");
      assert.equal(error.cause, undefined);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected createStagingJournal to throw");
  });

  describe("revoked Proxy (raw TypeError from Array.isArray) at every caller-controlled surface", function () {
    function revoked() {
      const { proxy, revoke } = Proxy.revocable({}, {});
      revoke();
      return proxy;
    }

    function assertClassifiedNotRawTypeError(fn, code) {
      let threw = false;
      try {
        fn();
      } catch (error) {
        threw = true;
        assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
        assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
        assert.notEqual(error.constructor && error.constructor.name, "TypeError");
        assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
        assert.ok(error.cause instanceof TypeError, "the underlying revoked-proxy TypeError must be retained as cause");
      }
      assert.ok(threw, "expected function to throw");
    }

    it("ceremony context -> CEREMONY_CONTEXT_NOT_OBJECT", function () {
      assertClassifiedNotRawTypeError(
        () => mod.createStagingJournal(revoked(), MINTED_AT),
        "CEREMONY_CONTEXT_NOT_OBJECT"
      );
    });

    it("candidate input -> CANDIDATE_INPUT_NOT_OBJECT", function () {
      const journal = mintJournal();
      assertClassifiedNotRawTypeError(
        () => mod.stageRoleCandidate(journal, 0, revoked(), MINTED_AT + 1),
        "CANDIDATE_INPUT_NOT_OBJECT"
      );
    });

    it("top-level journal (validateStagingJournalRecord) -> JOURNAL_NOT_OBJECT", function () {
      assertClassifiedNotRawTypeError(
        () => mod.validateStagingJournalRecord(revoked()),
        "JOURNAL_NOT_OBJECT"
      );
    });

    it("checksum input (computeStagingJournalChecksum) -> JOURNAL_NOT_OBJECT", function () {
      assertClassifiedNotRawTypeError(
        () => mod.computeStagingJournalChecksum(revoked()),
        "JOURNAL_NOT_OBJECT"
      );
    });

    it("manifest -> JOURNAL_MANIFEST_NOT_OBJECT", function () {
      const journal = mintJournal();
      assertClassifiedNotRawTypeError(
        () => mod.validateStagingJournalRecord({ ...journal, manifest: revoked() }),
        "JOURNAL_MANIFEST_NOT_OBJECT"
      );
    });

    it("stored manifest entry -> MANIFEST_ENTRY_NOT_OBJECT", function () {
      const staged = mod.stageRoleCandidate(mintJournal(), 0, candidateInput(0), MINTED_AT + 1);
      const hostileJournal = { ...staged, manifest: { ...staged.manifest, "0": revoked() } };
      assertClassifiedNotRawTypeError(
        () => mod.validateStagingJournalRecord(hostileJournal),
        "MANIFEST_ENTRY_NOT_OBJECT"
      );
    });
  });
});

describe("PhilCore V2 consumer recovery staging journal (5B-1 pure) -- unforgeable classified-error brand", function () {
  // `instanceof` alone is forgeable: any caller can construct
  // `Object.create(PhilCoreV2ConsumerRecoveryStagingJournalError.prototype)`
  // (or have a Proxy report that prototype from getPrototypeOf) and pass an
  // ordinary instanceof check without ever going through the real
  // constructor. Such a spoof must be classified like any other
  // unclassified thrown value, never rethrown unchanged.
  function makeSpoof(overrides = {}) {
    const spoof = Object.create(mod.PhilCoreV2ConsumerRecoveryStagingJournalError.prototype);
    spoof.code = "HOST_PROCESS_POISONED"; // an arbitrary, unrelated fake code
    spoof.message = "spoofed";
    Object.assign(spoof, overrides);
    return spoof;
  }

  it("confirms the spoof passes a raw instanceof check but is not the branded class", function () {
    const spoof = makeSpoof();
    assert.equal(
      Object.getPrototypeOf(spoof),
      mod.PhilCoreV2ConsumerRecoveryStagingJournalError.prototype,
      "sanity: spoof really does share the real prototype"
    );
    assert.equal(spoof instanceof mod.PhilCoreV2ConsumerRecoveryStagingJournalError, false);
  });

  it("wraps a field getter that throws Object.create(ErrorClass.prototype) with the field's exact code, spoof retained only as non-enumerable cause", function () {
    const spoof = makeSpoof();
    const ctx = { ...validContext() };
    Object.defineProperty(ctx, "ceremonyId", {
      get() {
        throw spoof;
      },
      enumerable: true,
      configurable: true
    });
    let threw = false;
    try {
      mod.createStagingJournal(ctx, MINTED_AT);
    } catch (error) {
      threw = true;
      assert.notEqual(error, spoof, "the spoof must never escape unchanged");
      assert.equal(error.name, "PhilCoreV2ConsumerRecoveryStagingJournalError");
      assert.equal(error.code, "CEREMONY_ID_INVALID", "must carry the field's exact real code, not the spoof's fake one");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
      assert.equal(error.cause, spoof, "the spoof itself is retained only as cause");
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected createStagingJournal to throw");
  });

  it("wraps an enumeration trap that throws a Proxy whose getPrototypeOf reports the error prototype", function () {
    // A Proxy that never went through the real constructor, but whose
    // getPrototypeOf trap lies and claims the branded prototype -- a
    // distinct spoofing vector from Object.create(ErrorClass.prototype).
    const prototypeSpoofingProxy = new Proxy(
      {},
      {
        getPrototypeOf() {
          return mod.PhilCoreV2ConsumerRecoveryStagingJournalError.prototype;
        }
      }
    );
    const trap = new Proxy(validContext(), {
      ownKeys() {
        throw prototypeSpoofingProxy;
      }
    });
    let threw = false;
    try {
      mod.createStagingJournal(trap, MINTED_AT);
    } catch (error) {
      threw = true;
      assert.notEqual(error, prototypeSpoofingProxy);
      assert.equal(error.code, "CEREMONY_CONTEXT_NOT_OBJECT");
      assert.ok(Object.prototype.hasOwnProperty.call(error, "cause"));
      assert.equal(error.cause, prototypeSpoofingProxy);
      assert.equal(Object.prototype.propertyIsEnumerable.call(error, "cause"), false);
    }
    assert.ok(threw, "expected createStagingJournal to throw");
  });

  it("still recognizes a genuine error and rethrows it unchanged where the property-access contract requires that", function () {
    const genuine = new mod.PhilCoreV2ConsumerRecoveryStagingJournalError("CEREMONY_ID_INVALID");
    const ctx = { ...validContext() };
    Object.defineProperty(ctx, "ceremonyId", {
      get() {
        throw genuine;
      },
      enumerable: true,
      configurable: true
    });
    let threw = false;
    try {
      mod.createStagingJournal(ctx, MINTED_AT);
    } catch (error) {
      threw = true;
      assert.equal(error, genuine, "a genuine classified error must be rethrown unchanged, not re-wrapped");
      assert.equal(error.code, "CEREMONY_ID_INVALID");
    }
    assert.ok(threw, "expected createStagingJournal to throw");
  });
});
