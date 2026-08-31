require("tsx/cjs");

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const SDK_SRC = path.join(ROOT, "apps/phil-device-sdk/src");
const MODULE_PATH = path.join(
  SDK_SRC,
  "v2ConsumerRecoveryGenesisCredentialObligation.ts"
);

const {
  computePhilCoreV2LocalGenesisEnrollmentCeremonyHash
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts");

const {
  mintPhilCoreV2GenesisRoleCeremony,
  cancelPhilCoreV2GenesisRoleCeremony,
  toPhilCoreV2GenesisRoleCeremonyHashInput
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts");

const obligation = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts"
);

const {
  PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_SCHEMA_VERSION,
  PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_FORMAT_PROVENANCE,
  PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_CHECKSUM_PREFIX,
  MAX_GENESIS_CREDENTIAL_OBLIGATION_BYTES,
  PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_ERROR_CODE,
  PhilCoreV2GenesisCredentialObligationError,
  validatePhilCoreV2GenesisCredentialObligationRecord,
  createPhilCoreV2GenesisCredentialObligation,
  toPhilCoreV2GenesisCredentialObligationCeremonyHashInput,
  authorizePhilCoreV2GenesisCredentialCreation,
  recordPhilCoreV2GenesisCreatedCredential,
  orphanPhilCoreV2GenesisCredentialObligation
} = obligation;

const E = PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_ERROR_CODE;
const MODULE_SOURCE = fs.readFileSync(MODULE_PATH, "utf8");

const CEREMONY_ID =
  "0x827fb6a1d6c993f9398090b62cbb32171b4fdc11fc6b9d885f263e18402faf34";
const ALT_CEREMONY_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const INTENT_ID =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INTENT_HASH =
  "0x3d2b7a1c9e4f6058b1c2d3e4f50617283940a1b2c3d4e5f60718293a4b5c6d7e";
const CREDENTIAL_ID_HASH =
  "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PUBLIC_MATERIAL_HASH =
  "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const ALT_HASH =
  "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

const UINT48_MAX_NUMBER = 281474976710655;
const NOW = 1_700_000_000;
const FAR_INTENT_EXPIRY = 1_800_000_000n;

const RECORD_KEYS = [
  "schemaVersion",
  "formatProvenance",
  "intentId",
  "genesisDeploymentIntentHash",
  "ceremonyVersion",
  "role",
  "credentialGeneration",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "state",
  "credentialIdHash",
  "publicVerificationMaterialHash",
  "createdAtUnixSeconds",
  "updatedAtUnixSeconds",
  "creationAuthorizedAtUnixSeconds",
  "orphanReason",
  "integrityChecksum"
];

const PROJECTION_KEYS = [
  "ceremonyVersion",
  "ceremonyId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "expiresAt"
];

const RUNTIME_EXPORTS = [
  "PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_SCHEMA_VERSION",
  "PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_FORMAT_PROVENANCE",
  "PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_CHECKSUM_PREFIX",
  "MAX_GENESIS_CREDENTIAL_OBLIGATION_BYTES",
  "PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_ERROR_CODE",
  "PhilCoreV2GenesisCredentialObligationError",
  "validatePhilCoreV2GenesisCredentialObligationRecord",
  "createPhilCoreV2GenesisCredentialObligation",
  "toPhilCoreV2GenesisCredentialObligationCeremonyHashInput",
  "authorizePhilCoreV2GenesisCredentialCreation",
  "recordPhilCoreV2GenesisCreatedCredential",
  "orphanPhilCoreV2GenesisCredentialObligation"
];

const ERROR_CODE_KEYS = [
  "OBLIGATION_NOT_OBJECT",
  "OBLIGATION_MISSING_KEY",
  "OBLIGATION_EXTRA_KEY",
  "OBLIGATION_ENUMERATION_FAILED",
  "OBLIGATION_PROPERTY_READ_FAILED",
  "OBLIGATION_SCHEMA_VERSION_UNSUPPORTED",
  "OBLIGATION_FORMAT_PROVENANCE_INVALID",
  "OBLIGATION_STATE_INVALID",
  "OBLIGATION_STATE_COHERENCE_INVALID",
  "OBLIGATION_FIELD_INVALID",
  "OBLIGATION_TIMESTAMP_INVALID",
  "OBLIGATION_CHECKSUM_FORMAT_INVALID",
  "OBLIGATION_CHECKSUM_MISMATCH",
  "OBLIGATION_OVERSIZED",
  "INPUT_NOT_OBJECT",
  "INPUT_MISSING_KEY",
  "INPUT_EXTRA_KEY",
  "INPUT_ENUMERATION_FAILED",
  "INPUT_PROPERTY_READ_FAILED",
  "INVALID_NOW",
  "CLOCK_REGRESSION_DETECTED",
  "INVALID_TRANSITION",
  "CEREMONY_VALIDATION_FAILED",
  "CEREMONY_CONTEXT_MISMATCH",
  "CEREMONY_ID_MISMATCH",
  "CREDENTIAL_HASH_INVALID",
  "ORPHAN_REASON_INVALID"
];

function mintCeremony(overrides = {}) {
  return mintPhilCoreV2GenesisRoleCeremony({
    current: null,
    ceremonyId: CEREMONY_ID,
    role: 0n,
    genesisDeploymentIntentHash: INTENT_HASH,
    intentExpiresAtUnixSeconds: FAR_INTENT_EXPIRY,
    nowUnixSeconds: NOW,
    ...overrides
  });
}

function createArgs(overrides = {}) {
  return {
    ceremony: mintCeremony(),
    intentId: INTENT_ID,
    nowUnixSeconds: NOW,
    ...overrides
  };
}

function createActive(overrides = {}) {
  return createPhilCoreV2GenesisCredentialObligation(createArgs(overrides));
}

function authorize(current, overrides = {}) {
  return authorizePhilCoreV2GenesisCredentialCreation({
    current,
    expectedCeremonyId: current.ceremonyId,
    nowUnixSeconds: NOW + 1,
    ...overrides
  });
}

function recordCredential(current, overrides = {}) {
  return recordPhilCoreV2GenesisCreatedCredential({
    current,
    expectedCeremonyId: current.ceremonyId,
    credentialIdHash: CREDENTIAL_ID_HASH,
    publicVerificationMaterialHash: PUBLIC_MATERIAL_HASH,
    nowUnixSeconds: NOW + 2,
    ...overrides
  });
}

function orphan(current, reason, overrides = {}) {
  return orphanPhilCoreV2GenesisCredentialObligation({
    current,
    reason,
    nowUnixSeconds: Number(current.updatedAtUnixSeconds) + 1,
    ...overrides
  });
}

function expectCode(fn, code, label) {
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
    thrown instanceof PhilCoreV2GenesisCredentialObligationError,
    `expected branded obligation error for ${label ?? code}, got ${String(thrown)}`
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

function ownKeyOrder(value) {
  return Reflect.ownKeys(value).map(String);
}

function assertDeepFrozenRecord(record) {
  assert.equal(Object.isFrozen(record), true, "record is not frozen");
  for (const key of RECORD_KEYS) {
    const value = record[key];
    assert.ok(
      value === null || (typeof value !== "object" && typeof value !== "function"),
      `record.${key} is not a primitive, so freezing is not deep`
    );
  }
}

function recordCopy(record, overrides = {}) {
  const copy = {};
  for (const key of RECORD_KEYS) {
    copy[key] = record[key];
  }
  return Object.assign(copy, overrides);
}

function recomputeChecksum(record) {
  const projection = Object.create(null);
  for (const key of RECORD_KEYS) {
    if (key === "integrityChecksum") continue;
    projection[key] = record[key];
  }
  const digest = createHash("sha256")
    .update(PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_CHECKSUM_PREFIX, "utf8")
    .update(JSON.stringify(projection), "utf8")
    .digest("hex");
  return `0x${digest}`;
}

function importClosure(rootFile) {
  const closure = new Set();
  const worklist = [rootFile];
  while (worklist.length > 0) {
    const file = worklist.pop();
    const source = fs.readFileSync(file, "utf8");
    const specifiers = [];
    const fromRe = /\bfrom\s*["']([^"']+)["']/g;
    let match = fromRe.exec(source);
    while (match !== null) {
      specifiers.push(match[1]);
      match = fromRe.exec(source);
    }
    const bareRe = /^\s*import\s*["']([^"']+)["']\s*;?/gm;
    match = bareRe.exec(source);
    while (match !== null) {
      specifiers.push(match[1]);
      match = bareRe.exec(source);
    }
    for (const specifier of specifiers) {
      if (!specifier.startsWith(".")) continue;
      const resolved = path.resolve(path.dirname(file), specifier);
      const relative = path.relative(SDK_SRC, resolved);
      if (relative.startsWith("..") || path.isAbsolute(relative)) continue;
      if (closure.has(resolved)) continue;
      closure.add(resolved);
      worklist.push(resolved);
    }
  }
  return [...closure].map((file) => path.basename(file)).sort();
}

describe("v2ConsumerRecoveryGenesisCredentialObligation", () => {
  it("P01: create yields a frozen ACTIVE record with null hashes, authorized time, and orphan reason", () => {
    const ceremony = mintCeremony();
    const record = createActive({ ceremony });
    assert.equal(record.state, "ACTIVE");
    assert.equal(record.credentialIdHash, null);
    assert.equal(record.publicVerificationMaterialHash, null);
    assert.equal(record.creationAuthorizedAtUnixSeconds, null);
    assert.equal(record.orphanReason, null);
    assert.equal(record.intentId, INTENT_ID);
    assert.equal(record.ceremonyId, ceremony.ceremonyId);
    assert.equal(record.genesisDeploymentIntentHash, ceremony.genesisDeploymentIntentHash);
    assert.equal(record.genesisEnrollmentCeremonyHash, ceremony.genesisEnrollmentCeremonyHash);
    assert.equal(record.role, "0");
    assert.equal(record.ceremonyVersion, "1");
    assert.equal(record.credentialGeneration, "1");
    assert.equal(record.createdAtUnixSeconds, String(NOW));
    assert.equal(record.updatedAtUnixSeconds, String(NOW));
    assertDeepFrozenRecord(record);
    assert.deepEqual(
      validatePhilCoreV2GenesisCredentialObligationRecord(record),
      record
    );
  });

  it("P02: authorize persists CREATION_AUTHORIZED with a non-null authorized time and still-null hashes", () => {
    const authorized = authorize(createActive());
    assert.equal(authorized.state, "CREATION_AUTHORIZED");
    assert.equal(authorized.credentialIdHash, null);
    assert.equal(authorized.publicVerificationMaterialHash, null);
    assert.equal(authorized.creationAuthorizedAtUnixSeconds, String(NOW + 1));
    assert.equal(authorized.updatedAtUnixSeconds, String(NOW + 1));
    assert.equal(authorized.orphanReason, null);
    assert.equal(authorized.createdAtUnixSeconds, String(NOW));
    assertDeepFrozenRecord(authorized);
  });

  it("P03: record binds both public hashes from CREATION_AUTHORIZED", () => {
    const recorded = recordCredential(authorize(createActive()));
    assert.equal(recorded.state, "CREDENTIAL_RECORDED");
    assert.equal(recorded.credentialIdHash, CREDENTIAL_ID_HASH);
    assert.equal(recorded.publicVerificationMaterialHash, PUBLIC_MATERIAL_HASH);
    assert.equal(recorded.creationAuthorizedAtUnixSeconds, String(NOW + 1));
    assert.equal(recorded.updatedAtUnixSeconds, String(NOW + 2));
    assert.equal(recorded.orphanReason, null);
    assertDeepFrozenRecord(recorded);
  });

  it("P04: orphan-known preserves both hashes and records a closed reason", () => {
    const recorded = recordCredential(authorize(createActive()));
    const orphaned = orphan(recorded, "RESTART_DURING_CREATION");
    assert.equal(orphaned.state, "ORPHANED");
    assert.equal(orphaned.orphanReason, "RESTART_DURING_CREATION");
    assert.equal(orphaned.credentialIdHash, CREDENTIAL_ID_HASH);
    assert.equal(orphaned.publicVerificationMaterialHash, PUBLIC_MATERIAL_HASH);
    assert.equal(orphaned.creationAuthorizedAtUnixSeconds, recorded.creationAuthorizedAtUnixSeconds);
    assertDeepFrozenRecord(orphaned);
  });

  it("P05: orphan-unknown from CREATION_AUTHORIZED keeps both hashes null", () => {
    const authorized = authorize(createActive());
    const orphaned = orphan(authorized, "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION");
    assert.equal(orphaned.state, "ORPHANED");
    assert.equal(orphaned.credentialIdHash, null);
    assert.equal(orphaned.publicVerificationMaterialHash, null);
    assert.equal(
      orphaned.orphanReason,
      "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION"
    );
    assertDeepFrozenRecord(orphaned);
  });

  it("P06: the stored record has the exact 18-key order and six-field ceremony projection", () => {
    const ceremony = mintCeremony();
    const record = createActive({ ceremony });
    assert.deepEqual(ownKeyOrder(record), RECORD_KEYS);
    assert.equal(RECORD_KEYS.length, 18);

    const projection = toPhilCoreV2GenesisCredentialObligationCeremonyHashInput(record);
    assert.deepEqual(ownKeyOrder(projection), PROJECTION_KEYS);
    assert.equal(Object.getPrototypeOf(projection), null);
    assert.equal(Object.isFrozen(projection), true);
    assert.equal(projection.ceremonyVersion, "1");
    assert.equal(projection.ceremonyId, ceremony.ceremonyId);
    assert.equal(projection.genesisDeploymentIntentHash, ceremony.genesisDeploymentIntentHash);
    assert.equal(projection.role, "0");
    assert.equal(projection.credentialGeneration, "1");
    assert.equal(projection.expiresAt, ceremony.expiresAtUnixSeconds.toString(10));
    assert.deepEqual(
      projection,
      toPhilCoreV2GenesisRoleCeremonyHashInput(ceremony)
    );
    assert.equal(
      record.genesisEnrollmentCeremonyHash,
      computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(projection)
    );
  });

  it("P07: checksum is SHA-256 over the fixed prefix and the 17-key null-prototype projection", () => {
    const record = createActive();
    assert.equal(record.integrityChecksum, recomputeChecksum(record));
    assert.match(record.integrityChecksum, /^0x[0-9a-f]{64}$/u);
  });

  it("P08: the stored record stays under the 4096-byte ceiling and OBLIGATION_OVERSIZED rejects a larger owned snapshot", () => {
    const record = recordCredential(authorize(createActive()));
    const bytes = Buffer.byteLength(JSON.stringify(record), "utf8");
    assert.ok(bytes <= MAX_GENESIS_CREDENTIAL_OBLIGATION_BYTES, `saw ${bytes}`);
    assert.equal(MAX_GENESIS_CREDENTIAL_OBLIGATION_BYTES, 4096);

    const oversized = recordCopy(record);
    oversized.formatProvenance = "x".repeat(5000);
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(oversized),
      E.OBLIGATION_OVERSIZED,
      "oversized owned snapshot"
    );
  });

  it("P09: every transition returns a new deep-frozen record and never mutates the current input", () => {
    const active = createActive();
    const activeCopy = recordCopy(active);
    const authorized = authorize(active);
    assert.deepEqual(recordCopy(active), activeCopy);
    assert.notEqual(authorized, active);
    const recorded = recordCredential(authorized);
    assert.notEqual(recorded, authorized);
    const orphaned = orphan(recorded, "RECORDED_CREDENTIAL_MISMATCH");
    assert.notEqual(orphaned, recorded);
    for (const record of [active, authorized, recorded, orphaned]) {
      assertDeepFrozenRecord(record);
    }
  });

  it("P10: ACTIVE coherence rejects any non-null hash, authorized time, or orphan reason", () => {
    const active = createActive();
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(active, { credentialIdHash: CREDENTIAL_ID_HASH, integrityChecksum: "x" })
      ),
      E.OBLIGATION_STATE_COHERENCE_INVALID,
      "ACTIVE with one hash"
    );
    const authorized = authorize(active);
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(authorized, { state: "ACTIVE", integrityChecksum: "x" })
      ),
      E.OBLIGATION_STATE_COHERENCE_INVALID,
      "ACTIVE with authorized time"
    );
  });

  it("P11: CREATION_AUTHORIZED requires authorized time, null hashes, and a null orphan reason", () => {
    const authorized = authorize(createActive());
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(authorized, { creationAuthorizedAtUnixSeconds: null, integrityChecksum: "x" })
      ),
      E.OBLIGATION_STATE_COHERENCE_INVALID,
      "authorized without time"
    );
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(authorized, { credentialIdHash: CREDENTIAL_ID_HASH, integrityChecksum: "x" })
      ),
      E.OBLIGATION_STATE_COHERENCE_INVALID,
      "authorized with one hash"
    );
  });

  it("P12: CREDENTIAL_RECORDED requires both hashes and a non-null authorized time", () => {
    const recorded = recordCredential(authorize(createActive()));
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(recorded, { publicVerificationMaterialHash: null, integrityChecksum: "x" })
      ),
      E.OBLIGATION_STATE_COHERENCE_INVALID,
      "recorded with one hash"
    );
  });

  it("P13: ORPHANED requires a reason, authorized time, and hashes that are both null or both known", () => {
    const known = orphan(
      recordCredential(authorize(createActive())),
      "TERMINAL_JOURNAL_WITH_UNCONSUMED_CREATION"
    );
    const unknown = orphan(
      authorize(createActive()),
      "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION"
    );
    assert.equal(known.credentialIdHash, CREDENTIAL_ID_HASH);
    assert.equal(unknown.credentialIdHash, null);
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(known, { orphanReason: null, integrityChecksum: "x" })
      ),
      E.OBLIGATION_STATE_COHERENCE_INVALID,
      "orphaned without reason"
    );
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(known, {
          publicVerificationMaterialHash: null,
          integrityChecksum: "x"
        })
      ),
      E.OBLIGATION_STATE_COHERENCE_INVALID,
      "orphaned mixed hashes"
    );
  });

  it("P14: timestamp ordering rejects updatedAt before createdAt and authorized time outside that window", () => {
    const authorized = authorize(createActive());
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(authorized, { updatedAtUnixSeconds: String(NOW - 1), integrityChecksum: "x" })
      ),
      E.OBLIGATION_TIMESTAMP_INVALID,
      "updated before created"
    );
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(authorized, {
          creationAuthorizedAtUnixSeconds: String(NOW - 1),
          integrityChecksum: "x"
        })
      ),
      E.OBLIGATION_TIMESTAMP_INVALID,
      "authorized before created"
    );
  });

  it("P15: invalid-transition ladder rejects authorize/record/orphan from the wrong state", () => {
    const active = createActive();
    const authorized = authorize(active);
    const recorded = recordCredential(authorized);
    const orphaned = orphan(authorized, "RESTART_DURING_CREATION");

    expectCode(
      () => recordCredential(active),
      E.INVALID_TRANSITION,
      "record from ACTIVE"
    );
    expectCode(
      () => authorize(authorized),
      E.INVALID_TRANSITION,
      "authorize from CREATION_AUTHORIZED"
    );
    expectCode(
      () => authorize(recorded, { nowUnixSeconds: NOW + 3 }),
      E.INVALID_TRANSITION,
      "authorize from CREDENTIAL_RECORDED"
    );
    expectCode(
      () => orphan(active, "RESTART_DURING_CREATION"),
      E.INVALID_TRANSITION,
      "orphan from ACTIVE"
    );
    expectCode(
      () => recordCredential(orphaned),
      E.INVALID_TRANSITION,
      "record from ORPHANED"
    );
  });

  it("P16: clock-domain failures outrank transition-state guards", () => {
    const active = createActive();
    expectCode(
      () => authorize(active, { nowUnixSeconds: 0 }),
      E.INVALID_NOW,
      "now = 0"
    );
    expectCode(
      () => authorize(active, { nowUnixSeconds: 1.5 }),
      E.INVALID_NOW,
      "non-integer now"
    );
    expectCode(
      () => authorize(active, { nowUnixSeconds: UINT48_MAX_NUMBER + 1 }),
      E.INVALID_NOW,
      "now above UINT48"
    );
    expectCode(
      () => authorize(active, { nowUnixSeconds: "1700000001" }),
      E.INVALID_NOW,
      "string now"
    );
  });

  it("P17: clock regression outranks the transition-state guard", () => {
    const active = createActive();
    expectCode(
      () => authorize(active, { nowUnixSeconds: NOW - 1 }),
      E.CLOCK_REGRESSION_DETECTED,
      "authorize regression"
    );
    const authorized = authorize(active);
    expectCode(
      () => recordCredential(authorized, { nowUnixSeconds: NOW }),
      E.CLOCK_REGRESSION_DETECTED,
      "record regression"
    );
  });

  it("P18: input key/read failures outrank current-record validation", () => {
    expectCode(
      () => createPhilCoreV2GenesisCredentialObligation(null),
      E.INPUT_NOT_OBJECT,
      "null create input"
    );
    expectCode(
      () => authorizePhilCoreV2GenesisCredentialCreation({
        current: { forged: true },
        extra: 1,
        expectedCeremonyId: CEREMONY_ID,
        nowUnixSeconds: NOW
      }),
      E.INPUT_EXTRA_KEY,
      "extra key before current validation"
    );
    expectCode(
      () => authorizePhilCoreV2GenesisCredentialCreation({
        expectedCeremonyId: CEREMONY_ID,
        nowUnixSeconds: NOW
      }),
      E.INPUT_MISSING_KEY,
      "missing current"
    );
    const hostileEnum = new Proxy({
      current: createActive(),
      expectedCeremonyId: CEREMONY_ID,
      nowUnixSeconds: NOW
    }, {
      ownKeys() { throw new Error("ownKeys trap"); }
    });
    expectCode(
      () => authorizePhilCoreV2GenesisCredentialCreation(hostileEnum),
      E.INPUT_ENUMERATION_FAILED,
      "enumeration trap"
    );
  });

  it("P19: create collapses imported lifecycle errors to CEREMONY_VALIDATION_FAILED", () => {
    expectCode(
      () => createActive({ ceremony: { not: "a ceremony" } }),
      E.CEREMONY_VALIDATION_FAILED,
      "invalid ceremony object"
    );
    expectCode(
      () => createActive({ ceremony: null }),
      E.CEREMONY_VALIDATION_FAILED,
      "null ceremony"
    );
  });

  it("P20: create rejects a validated but non-ACTIVE ceremony as CEREMONY_CONTEXT_MISMATCH", () => {
    const minted = mintCeremony();
    const ended = cancelPhilCoreV2GenesisRoleCeremony({
      current: minted,
      nowUnixSeconds: NOW + 1
    });
    expectCode(
      () => createActive({ ceremony: ended, nowUnixSeconds: NOW + 1 }),
      E.CEREMONY_CONTEXT_MISMATCH,
      "ENDED ceremony"
    );
    expectCode(
      () => createActive({ ceremony: minted, nowUnixSeconds: Number(minted.expiresAtUnixSeconds) }),
      E.CEREMONY_CONTEXT_MISMATCH,
      "expired ceremony clock"
    );
  });

  it("P21: authorize and record reject a ceremony-ID mismatch", () => {
    const active = createActive();
    expectCode(
      () => authorize(active, { expectedCeremonyId: ALT_CEREMONY_ID }),
      E.CEREMONY_ID_MISMATCH,
      "authorize id mismatch"
    );
    const authorized = authorize(active);
    expectCode(
      () => recordCredential(authorized, { expectedCeremonyId: ALT_CEREMONY_ID }),
      E.CEREMONY_ID_MISMATCH,
      "record id mismatch"
    );
  });

  it("P22: record enforces role-specific credential IDs and rejects zero public material", () => {
    const authorized0 = authorize(createActive());
    expectCode(
      () => recordCredential(authorized0, { credentialIdHash: ZERO_BYTES32 }),
      E.CREDENTIAL_HASH_INVALID,
      "role 0 zero credential id"
    );
    expectCode(
      () => recordCredential(authorized0, { publicVerificationMaterialHash: ZERO_BYTES32 }),
      E.CREDENTIAL_HASH_INVALID,
      "zero public material"
    );
    const authorized1 = authorize(createActive({
      ceremony: mintCeremony({ role: 1n, ceremonyId: ALT_CEREMONY_ID })
    }));
    expectCode(
      () => recordCredential(authorized1, { credentialIdHash: ZERO_BYTES32 }),
      E.CREDENTIAL_HASH_INVALID,
      "role 1 zero credential id"
    );
    const authorized2 = authorize(createActive({
      ceremony: mintCeremony({
        role: 2n,
        ceremonyId: "0x2222222222222222222222222222222222222222222222222222222222222222"
      })
    }));
    expectCode(
      () => recordCredential(authorized2, { credentialIdHash: CREDENTIAL_ID_HASH }),
      E.CREDENTIAL_HASH_INVALID,
      "role 2 nonzero credential id"
    );
    const recorded2 = recordCredential(authorized2, { credentialIdHash: ZERO_BYTES32 });
    assert.equal(recorded2.credentialIdHash, ZERO_BYTES32);
    expectCode(
      () => recordCredential(authorized2, { publicVerificationMaterialHash: ZERO_BYTES32 }),
      E.CREDENTIAL_HASH_INVALID,
      "role 2 zero public material"
    );
    expectCode(
      () => orphan(authorized0, "CONSUMED"),
      E.ORPHAN_REASON_INVALID,
      "unknown orphan reason"
    );
  });

  it("P23: extra, missing, symbol, and non-enumerable own keys are rejected at both boundaries", () => {
    const active = createActive();
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(recordCopy(active, { extra: 1 })),
      E.OBLIGATION_EXTRA_KEY,
      "extra stored key"
    );
    const missing = recordCopy(active);
    delete missing.orphanReason;
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(missing),
      E.OBLIGATION_MISSING_KEY,
      "missing stored key"
    );

    const symbolKeyed = recordCopy(active);
    symbolKeyed[Symbol("smuggled")] = 1;
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(symbolKeyed),
      E.OBLIGATION_EXTRA_KEY,
      "symbol stored key"
    );

    const hidden = recordCopy(active);
    Object.defineProperty(hidden, "forged", {
      value: 1, enumerable: false, configurable: true, writable: true
    });
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(hidden),
      E.OBLIGATION_EXTRA_KEY,
      "non-enumerable extra key"
    );
  });

  it("P24: proxy ownKeys/getPrototypeOf traps classify as enumeration/not-object and retain no raw cause", () => {
    const ownKeysTrap = new Proxy({}, {
      ownKeys() { throw new Error("hostile ownKeys"); }
    });
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(ownKeysTrap),
      E.OBLIGATION_ENUMERATION_FAILED,
      "ownKeys trap"
    );

    const protoTrap = new Proxy({
      ceremony: mintCeremony(),
      intentId: INTENT_ID,
      nowUnixSeconds: NOW
    }, {
      getPrototypeOf() { throw new Error("hostile getPrototypeOf"); }
    });
    expectCode(
      () => createPhilCoreV2GenesisCredentialObligation(protoTrap),
      E.INPUT_NOT_OBJECT,
      "getPrototypeOf trap"
    );
  });

  it("P25: a throwing getter is classified as a property-read failure and the raw throw is discarded", () => {
    const active = createActive();
    const getterRecord = {};
    for (const key of RECORD_KEYS) {
      if (key === "state") {
        Object.defineProperty(getterRecord, key, {
          enumerable: true,
          configurable: true,
          get() { throw new Error("hostile getter"); }
        });
      } else {
        getterRecord[key] = active[key];
      }
    }
    const thrown = expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(getterRecord),
      E.OBLIGATION_PROPERTY_READ_FAILED,
      "throwing getter"
    );
    assert.equal(JSON.stringify(thrown).includes("hostile getter"), false);

    const getterInput = {
      ceremony: mintCeremony(),
      intentId: INTENT_ID
    };
    Object.defineProperty(getterInput, "nowUnixSeconds", {
      enumerable: true,
      configurable: true,
      get() { throw new Error("hostile"); }
    });
    expectCode(
      () => createPhilCoreV2GenesisCredentialObligation(getterInput),
      E.INPUT_PROPERTY_READ_FAILED,
      "throwing input getter"
    );
  });

  it("P26: boxed primitives, arrays, and exotic prototypes fail as non-objects", () => {
    for (const value of [undefined, 1, "x", true, 1n, Object(1), [1], Object.create({ a: 1 })]) {
      expectCode(
        () => validatePhilCoreV2GenesisCredentialObligationRecord(value),
        E.OBLIGATION_NOT_OBJECT,
        `non-object ${String(value)}`
      );
    }
  });

  it("P27: instanceof cannot be forged and raw thrown values never survive as causes", () => {
    const forged = Object.create(PhilCoreV2GenesisCredentialObligationError.prototype);
    forged.code = E.OBLIGATION_FIELD_INVALID;
    assert.equal(forged instanceof PhilCoreV2GenesisCredentialObligationError, false);

    const genuine = expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(null),
      E.OBLIGATION_NOT_OBJECT
    );
    assert.equal(genuine instanceof PhilCoreV2GenesisCredentialObligationError, true);
    assert.equal(genuine instanceof Error, true);
    assert.equal("cause" in genuine, false);
  });

  it("P28: checksum format failures outrank checksum mismatch", () => {
    const active = createActive();
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(active, { integrityChecksum: "not-a-hash" })
      ),
      E.OBLIGATION_CHECKSUM_FORMAT_INVALID,
      "format"
    );
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(active, { integrityChecksum: ALT_HASH })
      ),
      E.OBLIGATION_CHECKSUM_MISMATCH,
      "mismatch"
    );
  });

  it("P29: schema, provenance, state, and field failures follow stored-record precedence", () => {
    const active = createActive();
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(active, { schemaVersion: 2 })
      ),
      E.OBLIGATION_SCHEMA_VERSION_UNSUPPORTED,
      "schema"
    );
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(active, { formatProvenance: "other" })
      ),
      E.OBLIGATION_FORMAT_PROVENANCE_INVALID,
      "provenance"
    );
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(active, { state: "CONSUMED" })
      ),
      E.OBLIGATION_STATE_INVALID,
      "state"
    );
    expectCode(
      () => validatePhilCoreV2GenesisCredentialObligationRecord(
        recordCopy(active, { intentId: ZERO_BYTES32 })
      ),
      E.OBLIGATION_FIELD_INVALID,
      "zero intentId"
    );
  });

  it("P30: same-module branded errors are rethrown by identity", () => {
    const branded = new PhilCoreV2GenesisCredentialObligationError(E.OBLIGATION_FIELD_INVALID);
    const current = {
      get schemaVersion() { throw branded; }
    };
    for (const key of RECORD_KEYS) {
      if (key === "schemaVersion") continue;
      current[key] = createActive()[key];
    }
    let thrown;
    try {
      validatePhilCoreV2GenesisCredentialObligationRecord(current);
    } catch (error) {
      thrown = error;
    }
    assert.equal(thrown, branded);
  });

  it("P31: require-time purity — no filesystem, clock, network, or dynamic import, and a second require is identity", () => {
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
        pattern.test(MODULE_SOURCE),
        false,
        `module contains a ${label} reference: ${String(MODULE_SOURCE.match(pattern))}`
      );
    }
    assert.match(MODULE_SOURCE, /from "node:crypto"/u);

    const runtimeNames = Reflect.ownKeys(obligation)
      .filter((key) => typeof key === "string" && key !== "__esModule")
      .sort();
    assert.deepEqual(runtimeNames, [...RUNTIME_EXPORTS].sort());
    const again = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts"
    );
    assert.equal(again, obligation);
  });

  it("P32: the genesis lifecycle remains domain-separated; no account-bound ceremony import is present", () => {
    const closure = importClosure(MODULE_PATH);
    assert.equal(closure.includes("v2ConsumerRecoveryCeremonyLifecycle.ts"), false);
    assert.equal(closure.includes("v2LocalCeremonyProtocol.ts"), false);
    assert.ok(closure.includes("v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts"));
    assert.ok(closure.includes("v2ConsumerRecoveryGenesisProtocol.ts"));

    for (const literal of [
      "v2ConsumerRecoveryCeremonyLifecycle",
      "v2LocalCeremonyProtocol",
      "PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_TYPEHASH",
      "PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS"
    ]) {
      assert.equal(MODULE_SOURCE.includes(literal), false, literal);
    }

    const codes = PHILCORE_V2_GENESIS_CREDENTIAL_OBLIGATION_ERROR_CODE;
    assert.equal(Object.isFrozen(codes), true);
    assert.deepEqual(Object.keys(codes).sort(), [...ERROR_CODE_KEYS].sort());
    assert.equal(Object.keys(codes).length, 27);
  });
});
