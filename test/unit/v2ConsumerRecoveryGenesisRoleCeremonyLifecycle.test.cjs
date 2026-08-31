require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const SDK_SRC = path.join(ROOT, "apps/phil-device-sdk/src");
const MODULE_PATH = path.join(
  SDK_SRC,
  "v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts"
);

const {
  computePhilCoreV2LocalGenesisEnrollmentCeremonyHash
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts");

// The account-bound ceremony domain is imported by THIS TEST ONLY, solely to
// prove cross-domain non-collision in AT-B6. The Gate-B module itself must
// never name it (AT-B1 direct-only assertion, and the closure assertion).
const {
  computePhilCoreV2LocalEnrollmentCeremonyHash,
  PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
  PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
  PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID
} = require("../../apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts");

const lifecycle = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts"
);

const {
  PHILCORE_V2_GENESIS_ROLE_CEREMONY_TTL_SECONDS,
  PHILCORE_V2_GENESIS_ROLE_CEREMONY_VERSION,
  PHILCORE_V2_GENESIS_ROLE_CEREMONY_GENERATION,
  PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE,
  PhilCoreV2GenesisRoleCeremonyLifecycleError,
  mintPhilCoreV2GenesisRoleCeremony,
  observePhilCoreV2GenesisRoleCeremonyStatus,
  cancelPhilCoreV2GenesisRoleCeremony,
  consumePhilCoreV2GenesisRoleCeremony,
  retirePhilCoreV2GenesisRoleCeremony,
  validatePhilCoreV2GenesisRoleCeremonyRecord,
  toPhilCoreV2GenesisRoleCeremonyHashInput
} = lifecycle;

const E = PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE;

const MODULE_SOURCE = fs.readFileSync(MODULE_PATH, "utf8");

const CEREMONY_ID =
  "0x827fb6a1d6c993f9398090b62cbb32171b4fdc11fc6b9d885f263e18402faf34";
const ALT_CEREMONY_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const INTENT_HASH =
  "0x3d2b7a1c9e4f6058b1c2d3e4f50617283940a1b2c3d4e5f60718293a4b5c6d7e";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

const ACCOUNT = "0xd5520BEEC59848D796EBA0badAa9c65f1be6E6F6";
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

const UINT48_MAX_BIGINT = (1n << 48n) - 1n;
const UINT48_MAX_NUMBER = 281474976710655;
const TTL = 300n;

const NOW = 1_700_000_000;
const FAR_INTENT_EXPIRY = 1_800_000_000n;

const RECORD_KEYS = [
  "state",
  "endReason",
  "ceremonyVersion",
  "ceremonyId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "expiresAtUnixSeconds",
  "mintedAtUnixSeconds",
  "lastObservedAtUnixSeconds",
  "genesisEnrollmentCeremonyHash"
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
  "PHILCORE_V2_GENESIS_ROLE_CEREMONY_TTL_SECONDS",
  "PHILCORE_V2_GENESIS_ROLE_CEREMONY_VERSION",
  "PHILCORE_V2_GENESIS_ROLE_CEREMONY_GENERATION",
  "PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE",
  "PhilCoreV2GenesisRoleCeremonyLifecycleError",
  "mintPhilCoreV2GenesisRoleCeremony",
  "observePhilCoreV2GenesisRoleCeremonyStatus",
  "cancelPhilCoreV2GenesisRoleCeremony",
  "consumePhilCoreV2GenesisRoleCeremony",
  "retirePhilCoreV2GenesisRoleCeremony",
  "validatePhilCoreV2GenesisRoleCeremonyRecord",
  "toPhilCoreV2GenesisRoleCeremonyHashInput"
];

const ERROR_CODE_KEYS = [
  "CEREMONY_ALREADY_ACTIVE",
  "CEREMONY_PENDING_RETIREMENT",
  "CEREMONY_NOT_ACTIVE",
  "CEREMONY_NOT_INSTALLED",
  "CEREMONY_STILL_ACTIVE",
  "CEREMONY_ID_MISMATCH",
  "INVALID_RECORD",
  "INPUT_NOT_OBJECT",
  "INPUT_EXTRA_KEY",
  "INPUT_MISSING_KEY",
  "INPUT_ENUMERATION_FAILED",
  "INPUT_PROPERTY_READ_FAILED",
  "CEREMONY_ID_INVALID",
  "INTENT_HASH_INVALID",
  "ROLE_INVALID",
  "INVALID_NOW",
  "INTENT_EXPIRY_INVALID",
  "EXPIRY_OVERFLOW",
  "EXPIRY_NOT_IN_FUTURE",
  "CLOCK_REGRESSION_DETECTED",
  "CEREMONY_HASH_COMPUTATION_FAILED"
];

// Declared but deliberately NOT exercised anywhere in this suite: it is
// reachable only if the trusted imported genesis hash implementation violates
// its own validated contract. See section 5.7 of the Gate-B contract.
const DEFENSIVE_ONLY_CODE = "CEREMONY_HASH_COMPUTATION_FAILED";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function mintArgs(overrides = {}) {
  return {
    current: null,
    ceremonyId: CEREMONY_ID,
    role: 0n,
    genesisDeploymentIntentHash: INTENT_HASH,
    intentExpiresAtUnixSeconds: FAR_INTENT_EXPIRY,
    nowUnixSeconds: NOW,
    ...overrides
  };
}

function mint(overrides = {}) {
  return mintPhilCoreV2GenesisRoleCeremony(mintArgs(overrides));
}

/**
 * Asserts `fn` throws the branded Gate-B error with exactly `code`, that the
 * thrown error retains no raw inner value under `cause` or any other own
 * property beyond `code`, and returns the error.
 */
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
    thrown instanceof PhilCoreV2GenesisRoleCeremonyLifecycleError,
    `expected branded lifecycle error for ${label ?? code}, got ${String(thrown)}`
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

/** Builds an ENDED record carrying each of the three end reasons. */
function endedRecords() {
  const active = mint();
  const cancelled = cancelPhilCoreV2GenesisRoleCeremony({
    current: active,
    nowUnixSeconds: NOW + 1
  });
  const expired = observePhilCoreV2GenesisRoleCeremonyStatus({
    current: active,
    nowUnixSeconds: Number(active.expiresAtUnixSeconds)
  });
  const consumed = consumePhilCoreV2GenesisRoleCeremony({
    current: active,
    nowUnixSeconds: NOW + 1
  });
  assert.equal(cancelled.endReason, "CANCELLED");
  assert.equal(expired.endReason, "EXPIRED");
  assert.equal(consumed.endReason, "CONSUMED");
  return { active, cancelled, expired, consumed };
}

/** A mutable plain copy of a record, preserving the 11-key order. */
function recordCopy(record, overrides = {}) {
  const copy = {};
  for (const key of RECORD_KEYS) {
    copy[key] = record[key];
  }
  return Object.assign(copy, overrides);
}

/**
 * Transitive import closure per section 10.1 of the Gate-B contract.
 * Extracts every `from "..."` specifier (covering `import`, `import type`,
 * multi-line forms, and `export ... from`) plus bare side-effect imports,
 * resolves relative specifiers, and keeps only files under the SDK src tree.
 */
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

describe("v2ConsumerRecoveryGenesisRoleCeremonyLifecycle (Gate B)", () => {
  it("AT-B1: transitive import closure excludes the account-bound ceremony modules, and (direct-only) the source names none of the four forbidden literals", () => {
    const closure = importClosure(MODULE_PATH);

    // Binding assertion: over the real transitive closure.
    assert.equal(
      closure.includes("v2ConsumerRecoveryCeremonyLifecycle.ts"),
      false,
      `forbidden module in import closure: ${closure.join(", ")}`
    );
    assert.equal(
      closure.includes("v2LocalCeremonyProtocol.ts"),
      false,
      `forbidden module in import closure: ${closure.join(", ")}`
    );

    // The closure is recorded, not merely constrained: these six SDK-source
    // dependencies are correct and expected, and any delta is reviewed.
    assert.deepEqual(closure, [
      "hashes.ts",
      "v2Authorization.ts",
      "v2ConsumerRecovery.ts",
      "v2ConsumerRecoveryGenesisProtocol.ts",
      "v2Intent.ts",
      "v2RecoveryEvidence.ts"
    ]);

    // Second assertion, EXPLICITLY NARROWER AND DIRECT-ONLY: the Gate-B source
    // text itself names none of these four literals. This is a direct-text
    // check, strictly weaker than the closure assertion above, and never a
    // substitute for it.
    for (const literal of [
      "v2ConsumerRecoveryCeremonyLifecycle",
      "v2LocalCeremonyProtocol",
      "PHILCORE_V2_LOCAL_ENROLLMENT_CEREMONY_TYPEHASH",
      "PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS"
    ]) {
      assert.equal(
        MODULE_SOURCE.includes(literal),
        false,
        `Gate-B source directly names forbidden literal: ${literal}`
      );
    }

    // The three remaining directly-prohibited module names.
    for (const literal of ["v2ConsumerRecovery.ts", "v2Intent.ts", "recovery-ceremony-host"]) {
      assert.equal(
        MODULE_SOURCE.includes(literal),
        false,
        `Gate-B source directly imports forbidden module: ${literal}`
      );
    }
  });

  it("AT-B2: the genesis TTL is 300n and is a distinct binding with no relationship to the account-bound TTL", () => {
    assert.equal(typeof PHILCORE_V2_GENESIS_ROLE_CEREMONY_TTL_SECONDS, "bigint");
    assert.equal(PHILCORE_V2_GENESIS_ROLE_CEREMONY_TTL_SECONDS, 300n);

    // Gate B declares its own literal and neither imports nor names the
    // account-bound binding.
    assert.equal(
      MODULE_SOURCE.includes("PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS"),
      false
    );
    assert.equal(
      MODULE_SOURCE.includes("v2ConsumerRecoveryCeremonyLifecycle"),
      false
    );
    assert.match(
      MODULE_SOURCE,
      /export const PHILCORE_V2_GENESIS_ROLE_CEREMONY_TTL_SECONDS\s*(?::\s*bigint\s*)?=\s*300n\s*;/u
    );

    // The module's whole import list is exactly the two contracted lines.
    const importLines = MODULE_SOURCE.match(/^\s*(?:import|export)[^\n]*\bfrom\b[^\n]*$/gmu) ?? [];
    assert.deepEqual(
      importLines.map((line) => line.trim()),
      [
        'import type { Hex } from "./hashes.ts";',
        'import { computePhilCoreV2LocalGenesisEnrollmentCeremonyHash } from "./v2ConsumerRecoveryGenesisProtocol.ts";'
      ]
    );

    // The module owns this declaration, which is what the TTL-provenance rule
    // requires.
    assert.equal(PHILCORE_V2_GENESIS_ROLE_CEREMONY_VERSION, 1n);
    assert.equal(PHILCORE_V2_GENESIS_ROLE_CEREMONY_GENERATION, 1n);
  });

  it("AT-B3: expiry selection is min(now + TTL, intentExpiry)", () => {
    // TTL-bound: intentExpiry strictly greater than now + 300n.
    const ttlBound = mint({
      intentExpiresAtUnixSeconds: BigInt(NOW) + TTL + 1n
    });
    assert.equal(ttlBound.expiresAtUnixSeconds, BigInt(NOW) + TTL);

    const farTtlBound = mint({ intentExpiresAtUnixSeconds: FAR_INTENT_EXPIRY });
    assert.equal(farTtlBound.expiresAtUnixSeconds, BigInt(NOW) + TTL);

    // Intent-bound: intentExpiry less than or equal to now + 300n.
    const intentBound = mint({
      intentExpiresAtUnixSeconds: BigInt(NOW) + TTL - 1n
    });
    assert.equal(intentBound.expiresAtUnixSeconds, BigInt(NOW) + TTL - 1n);

    // Exact equality picks the same value from either side of the min().
    const equalBound = mint({ intentExpiresAtUnixSeconds: BigInt(NOW) + TTL });
    assert.equal(equalBound.expiresAtUnixSeconds, BigInt(NOW) + TTL);

    const nearBound = mint({ intentExpiresAtUnixSeconds: BigInt(NOW) + 1n });
    assert.equal(nearBound.expiresAtUnixSeconds, BigInt(NOW) + 1n);

    for (const record of [ttlBound, farTtlBound, intentBound, equalBound, nearBound]) {
      assert.equal(typeof record.expiresAtUnixSeconds, "bigint");
      assert.ok(record.expiresAtUnixSeconds > record.mintedAtUnixSeconds);
    }
  });

  it("AT-B4: EXPIRY_NOT_IN_FUTURE when the intent expiry is at or before now", () => {
    expectCode(
      () => mint({ intentExpiresAtUnixSeconds: BigInt(NOW) }),
      E.EXPIRY_NOT_IN_FUTURE,
      "intentExpiry exactly equal to now"
    );
    expectCode(
      () => mint({ intentExpiresAtUnixSeconds: BigInt(NOW) - 1n }),
      E.EXPIRY_NOT_IN_FUTURE,
      "intentExpiry one second before now"
    );
    expectCode(
      () => mint({ intentExpiresAtUnixSeconds: 1n }),
      E.EXPIRY_NOT_IN_FUTURE,
      "intentExpiry far in the past"
    );

    // One second into the future is accepted, so the boundary is exact.
    const accepted = mint({ intentExpiresAtUnixSeconds: BigInt(NOW) + 1n });
    assert.equal(accepted.expiresAtUnixSeconds, BigInt(NOW) + 1n);
  });

  it("AT-B5: EXPIRY_OVERFLOW at now === UINT48_MAX_NUMBER - 299 and above", () => {
    expectCode(
      () =>
        mint({
          nowUnixSeconds: UINT48_MAX_NUMBER - 299,
          intentExpiresAtUnixSeconds: UINT48_MAX_BIGINT
        }),
      E.EXPIRY_OVERFLOW,
      "now === UINT48_MAX_NUMBER - 299"
    );
    expectCode(
      () =>
        mint({
          nowUnixSeconds: UINT48_MAX_NUMBER - 1,
          intentExpiresAtUnixSeconds: UINT48_MAX_BIGINT
        }),
      E.EXPIRY_OVERFLOW,
      "now === UINT48_MAX_NUMBER - 1"
    );
    expectCode(
      () =>
        mint({
          nowUnixSeconds: UINT48_MAX_NUMBER,
          intentExpiresAtUnixSeconds: UINT48_MAX_BIGINT
        }),
      E.EXPIRY_OVERFLOW,
      "now === UINT48_MAX_NUMBER"
    );

    // One second earlier is the last accepted instant: ttlExpiry === UINT48_MAX.
    const boundary = mint({
      nowUnixSeconds: UINT48_MAX_NUMBER - 300,
      intentExpiresAtUnixSeconds: UINT48_MAX_BIGINT
    });
    assert.equal(boundary.expiresAtUnixSeconds, UINT48_MAX_BIGINT);
    assert.equal(boundary.mintedAtUnixSeconds, UINT48_MAX_BIGINT - TTL);
  });

  it("AT-B6: the record hash equals the genesis-domain hash of its own projection, and does not collide with an independently valid account-bound commitment", () => {
    const record = mint();
    const projection = toPhilCoreV2GenesisRoleCeremonyHashInput(record);
    const recomputed = computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(projection);
    assert.equal(record.genesisEnrollmentCeremonyHash, recomputed);
    assert.match(record.genesisEnrollmentCeremonyHash, /^0x[0-9a-f]{64}$/u);

    // A SEPARATE, independently valid ten-key input for the account-bound
    // domain. The two schemas are disjoint and are never presented as one
    // shared object; they overlap only on ceremonyId and expiresAt.
    const accountBoundInput = {
      ceremonyId: CEREMONY_ID,
      account: ACCOUNT,
      chainId: "11155111",
      entryPoint: ENTRY_POINT,
      accountVersionId: PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
      securityModelId: PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
      recoveryDomainId: PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
      expectedRecoveryEpoch: "1",
      expectedValidatorEpoch: "1",
      expiresAt: record.expiresAtUnixSeconds.toString(10)
    };
    assert.equal(Object.keys(accountBoundInput).length, 10);
    const accountBoundHash =
      computePhilCoreV2LocalEnrollmentCeremonyHash(accountBoundInput);
    assert.match(accountBoundHash, /^0x[0-9a-f]{64}$/u);

    assert.notEqual(
      record.genesisEnrollmentCeremonyHash,
      accountBoundHash,
      "genesis and account-bound domains must never cross-validate"
    );

    // Role separation inside the genesis domain is also a real commitment.
    const roleOne = mint({ role: 1n });
    const roleTwo = mint({ role: 2n });
    assert.notEqual(
      record.genesisEnrollmentCeremonyHash,
      roleOne.genesisEnrollmentCeremonyHash
    );
    assert.notEqual(
      roleOne.genesisEnrollmentCeremonyHash,
      roleTwo.genesisEnrollmentCeremonyHash
    );
  });

  it("AT-B7: the projection is a frozen null-prototype six-key object whose numeric members are canonical decimal strings", () => {
    const record = mint({ role: 2n });
    const projection = toPhilCoreV2GenesisRoleCeremonyHashInput(record);

    assert.equal(Object.getPrototypeOf(projection), null);
    assert.equal(Object.isFrozen(projection), true);
    assert.deepEqual(ownKeyOrder(projection), PROJECTION_KEYS);

    assert.equal(projection.ceremonyVersion, "1");
    assert.equal(projection.credentialGeneration, "1");
    assert.equal(projection.role, "2");
    assert.equal(
      projection.expiresAt,
      record.expiresAtUnixSeconds.toString(10)
    );
    assert.equal(projection.ceremonyId, record.ceremonyId);
    assert.equal(
      projection.genesisDeploymentIntentHash,
      record.genesisDeploymentIntentHash
    );

    for (const key of ["ceremonyVersion", "role", "credentialGeneration", "expiresAt"]) {
      assert.equal(typeof projection[key], "string", `${key} must be a string`);
      assert.match(projection[key], /^(?:0|[1-9][0-9]*)$/u, `${key} is not canonical`);
    }
    for (const key of ["ceremonyId", "genesisDeploymentIntentHash"]) {
      assert.match(projection[key], /^0x[0-9a-f]{64}$/u);
    }

    // Feeding it to the genesis hash function does not throw.
    assert.doesNotThrow(() =>
      computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(projection)
    );

    // The deliberate field-name asymmetry is real: the record key is
    // expiresAtUnixSeconds, the projection key is expiresAt.
    assert.equal(
      Object.prototype.hasOwnProperty.call(projection, "expiresAtUnixSeconds"),
      false
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(record, "expiresAt"),
      false
    );

    // A malformed record is rejected before any projection is produced.
    expectCode(
      () => toPhilCoreV2GenesisRoleCeremonyHashInput(recordCopy(record, { role: 3n })),
      E.INVALID_RECORD,
      "projection of a malformed record"
    );
  });

  it("AT-B8: mint and retire gating across all three end reasons", () => {
    const { active, cancelled, expired, consumed } = endedRecords();

    // ACTIVE blocks a new mint.
    expectCode(
      () => mint({ current: active, ceremonyId: ALT_CEREMONY_ID }),
      E.CEREMONY_ALREADY_ACTIVE,
      "mint over an ACTIVE ceremony"
    );

    // ENDED blocks a new mint for every one of the three end reasons.
    for (const ended of [cancelled, expired, consumed]) {
      expectCode(
        () => mint({ current: ended, ceremonyId: ALT_CEREMONY_ID }),
        E.CEREMONY_PENDING_RETIREMENT,
        `mint over an ENDED/${ended.endReason} ceremony`
      );
    }

    // Retire from ACTIVE fails.
    expectCode(
      () =>
        retirePhilCoreV2GenesisRoleCeremony({
          current: active,
          expectedCeremonyId: CEREMONY_ID
        }),
      E.CEREMONY_STILL_ACTIVE,
      "retire an ACTIVE ceremony"
    );

    // Retire with a wrong (but well-formed) id fails.
    expectCode(
      () =>
        retirePhilCoreV2GenesisRoleCeremony({
          current: cancelled,
          expectedCeremonyId: ALT_CEREMONY_ID
        }),
      E.CEREMONY_ID_MISMATCH,
      "retire with a mismatched ceremony id"
    );

    // Retire succeeds from each of the three end reasons, and a fresh mint
    // then succeeds against the emptied slot.
    for (const ended of [cancelled, expired, consumed]) {
      const retired = retirePhilCoreV2GenesisRoleCeremony({
        current: ended,
        expectedCeremonyId: CEREMONY_ID
      });
      assert.equal(retired.state, "ENDED");
      assert.equal(retired.endReason, ended.endReason);
      assert.equal(retired.ceremonyId, CEREMONY_ID);
      assertDeepFrozenRecord(retired);

      // The caller sets the slot to null; a fresh mint then succeeds.
      const fresh = mint({ current: null, ceremonyId: ALT_CEREMONY_ID });
      assert.equal(fresh.state, "ACTIVE");
      assert.equal(fresh.endReason, null);
      assert.equal(fresh.ceremonyId, ALT_CEREMONY_ID);
    }
  });

  it("AT-B9: expiry outranks cancellation and observation, but consume never reapplies expiry precedence", () => {
    const active = mint();
    const expiresAt = Number(active.expiresAtUnixSeconds);

    const cancelledAtExpiry = cancelPhilCoreV2GenesisRoleCeremony({
      current: active,
      nowUnixSeconds: expiresAt
    });
    assert.equal(cancelledAtExpiry.state, "ENDED");
    assert.equal(cancelledAtExpiry.endReason, "EXPIRED");

    const observedAtExpiry = observePhilCoreV2GenesisRoleCeremonyStatus({
      current: active,
      nowUnixSeconds: expiresAt
    });
    assert.equal(observedAtExpiry.state, "ENDED");
    assert.equal(observedAtExpiry.endReason, "EXPIRED");

    // One second before expiry, cancel yields CANCELLED, so the precedence is
    // an expiry rule and not a blanket rewrite.
    const cancelledBefore = cancelPhilCoreV2GenesisRoleCeremony({
      current: active,
      nowUnixSeconds: expiresAt - 1
    });
    assert.equal(cancelledBefore.endReason, "CANCELLED");

    // consume at exactly the expiry instant, and well past it, still yields
    // CONSUMED: the staging journal has already published a manifest entry.
    const consumedAtExpiry = consumePhilCoreV2GenesisRoleCeremony({
      current: active,
      nowUnixSeconds: expiresAt
    });
    assert.equal(consumedAtExpiry.state, "ENDED");
    assert.equal(consumedAtExpiry.endReason, "CONSUMED");
    assert.equal(consumedAtExpiry.lastObservedAtUnixSeconds, BigInt(expiresAt));

    for (const later of [expiresAt + 1, expiresAt + 100_000, UINT48_MAX_NUMBER]) {
      const consumedLater = consumePhilCoreV2GenesisRoleCeremony({
        current: active,
        nowUnixSeconds: later
      });
      assert.equal(consumedLater.endReason, "CONSUMED");
      assert.equal(consumedLater.lastObservedAtUnixSeconds, BigInt(later));
    }
  });

  it("AT-B10: consume rejects every out-of-contract input", () => {
    const { cancelled, expired, consumed } = endedRecords();

    for (const ended of [cancelled, expired, consumed]) {
      expectCode(
        () =>
          consumePhilCoreV2GenesisRoleCeremony({
            current: ended,
            nowUnixSeconds: NOW + 2
          }),
        E.CEREMONY_NOT_ACTIVE,
        `consume an ENDED/${ended.endReason} ceremony`
      );
    }

    expectCode(
      () =>
        consumePhilCoreV2GenesisRoleCeremony({
          current: null,
          nowUnixSeconds: NOW
        }),
      E.CEREMONY_NOT_INSTALLED,
      "consume an empty slot"
    );

    const active = mint({ nowUnixSeconds: NOW });
    expectCode(
      () =>
        consumePhilCoreV2GenesisRoleCeremony({
          current: active,
          nowUnixSeconds: NOW - 1
        }),
      E.CLOCK_REGRESSION_DETECTED,
      "consume with a regressing clock"
    );

    for (const badNow of [0, -1, UINT48_MAX_NUMBER + 1, 1.5, "1700000000", 1700000000n]) {
      expectCode(
        () =>
          consumePhilCoreV2GenesisRoleCeremony({
            current: active,
            nowUnixSeconds: badNow
          }),
        E.INVALID_NOW,
        `consume with out-of-domain now: ${String(badNow)}`
      );
    }

    expectCode(
      () =>
        consumePhilCoreV2GenesisRoleCeremony({
          current: active,
          nowUnixSeconds: NOW,
          extra: 1
        }),
      E.INPUT_EXTRA_KEY,
      "consume with an extra input key"
    );

    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony({ current: active }),
      E.INPUT_MISSING_KEY,
      "consume with a missing input key"
    );
    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony({ nowUnixSeconds: NOW }),
      E.INPUT_MISSING_KEY,
      "consume with no current key"
    );

    expectCode(
      () =>
        consumePhilCoreV2GenesisRoleCeremony({
          current: recordCopy(active, { ceremonyVersion: 2n }),
          nowUnixSeconds: NOW
        }),
      E.INVALID_RECORD,
      "consume a malformed record"
    );
  });

  it("AT-B11: the consume output is a deep-frozen 11-key record carrying every other field forward unchanged", () => {
    const active = mint({ role: 1n });
    const now = NOW + 42;
    const consumed = consumePhilCoreV2GenesisRoleCeremony({
      current: active,
      nowUnixSeconds: now
    });

    assertDeepFrozenRecord(consumed);
    assert.deepEqual(ownKeyOrder(consumed), RECORD_KEYS);
    assert.equal(consumed.state, "ENDED");
    assert.equal(consumed.endReason, "CONSUMED");
    assert.equal(consumed.lastObservedAtUnixSeconds, BigInt(now));

    // All eight remaining fields are strictly equal to the input record's.
    const carried = [
      "ceremonyVersion",
      "ceremonyId",
      "genesisDeploymentIntentHash",
      "role",
      "credentialGeneration",
      "expiresAtUnixSeconds",
      "mintedAtUnixSeconds",
      "genesisEnrollmentCeremonyHash"
    ];
    assert.equal(carried.length, 8);
    for (const key of carried) {
      assert.equal(consumed[key], active[key], `field ${key} was not carried forward`);
    }

    // The input record is untouched.
    assert.equal(active.state, "ACTIVE");
    assert.equal(active.endReason, null);
    assert.equal(active.lastObservedAtUnixSeconds, BigInt(NOW));
  });

  it("AT-B12: lastObservedAtUnixSeconds is monotonic across observe, cancel, and consume, and ENDED records never have endReason rewritten", () => {
    const active = mint();
    assert.equal(active.lastObservedAtUnixSeconds, BigInt(NOW));

    // Equality is accepted by all three clock-bearing transitions.
    const observedSame = observePhilCoreV2GenesisRoleCeremonyStatus({
      current: active,
      nowUnixSeconds: NOW
    });
    assert.equal(observedSame.lastObservedAtUnixSeconds, BigInt(NOW));
    assert.equal(observedSame.state, "ACTIVE");
    assert.equal(
      cancelPhilCoreV2GenesisRoleCeremony({ current: active, nowUnixSeconds: NOW })
        .lastObservedAtUnixSeconds,
      BigInt(NOW)
    );
    assert.equal(
      consumePhilCoreV2GenesisRoleCeremony({ current: active, nowUnixSeconds: NOW })
        .lastObservedAtUnixSeconds,
      BigInt(NOW)
    );

    // A strict decrease is rejected by all three.
    const advanced = observePhilCoreV2GenesisRoleCeremonyStatus({
      current: active,
      nowUnixSeconds: NOW + 10
    });
    assert.equal(advanced.lastObservedAtUnixSeconds, BigInt(NOW + 10));
    for (const [name, operation] of [
      ["observeStatus", observePhilCoreV2GenesisRoleCeremonyStatus],
      ["cancel", cancelPhilCoreV2GenesisRoleCeremony],
      ["consume", consumePhilCoreV2GenesisRoleCeremony]
    ]) {
      expectCode(
        () => operation({ current: advanced, nowUnixSeconds: NOW + 9 }),
        E.CLOCK_REGRESSION_DETECTED,
        `${name} with a regressing clock`
      );
    }

    // ENDED records advance observation only; endReason is never rewritten.
    const { cancelled, expired, consumed } = endedRecords();
    for (const ended of [cancelled, expired, consumed]) {
      const before = ended.endReason;
      const later = Number(ended.lastObservedAtUnixSeconds) + 1_000_000;
      const observedEnded = observePhilCoreV2GenesisRoleCeremonyStatus({
        current: ended,
        nowUnixSeconds: later
      });
      assert.equal(observedEnded.state, "ENDED");
      assert.equal(observedEnded.endReason, before);
      assert.equal(observedEnded.lastObservedAtUnixSeconds, BigInt(later));
      for (const key of RECORD_KEYS) {
        if (key === "lastObservedAtUnixSeconds") continue;
        assert.equal(observedEnded[key], ended[key], `ENDED record rewrote ${key}`);
      }
      expectCode(
        () =>
          observePhilCoreV2GenesisRoleCeremonyStatus({
            current: ended,
            nowUnixSeconds: Number(ended.lastObservedAtUnixSeconds) - 1
          }),
        E.CLOCK_REGRESSION_DETECTED,
        `observe an ENDED/${before} record with a regressing clock`
      );
    }
  });

  it("AT-B13: every returned numeric field is a bigint, the clock domain rejects every non-number and out-of-domain value, and no comparison in the module has a string operand", () => {
    const numericFields = [
      "ceremonyVersion",
      "role",
      "credentialGeneration",
      "expiresAtUnixSeconds",
      "mintedAtUnixSeconds",
      "lastObservedAtUnixSeconds"
    ];
    const { active, cancelled, expired, consumed } = endedRecords();
    const retired = retirePhilCoreV2GenesisRoleCeremony({
      current: cancelled,
      expectedCeremonyId: CEREMONY_ID
    });
    const validated = validatePhilCoreV2GenesisRoleCeremonyRecord(active);
    for (const record of [active, cancelled, expired, consumed, retired, validated]) {
      for (const key of numericFields) {
        assert.equal(typeof record[key], "bigint", `${key} is not a bigint`);
      }
      assert.equal(typeof record.state, "string");
      assert.ok(record.endReason === null || typeof record.endReason === "string");
    }

    // The clock domain is JS number, safe integer, 1 .. UINT48_MAX_NUMBER.
    const badNows = [
      1700000000n,
      "1700000000",
      1700000000.5,
      Number.MAX_SAFE_INTEGER,
      UINT48_MAX_NUMBER + 1,
      0,
      -1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      null,
      undefined,
      true
    ];
    for (const badNow of badNows) {
      expectCode(
        () => mint({ nowUnixSeconds: badNow }),
        E.INVALID_NOW,
        `mint with now: ${String(badNow)}`
      );
      expectCode(
        () =>
          observePhilCoreV2GenesisRoleCeremonyStatus({
            current: active,
            nowUnixSeconds: badNow
          }),
        E.INVALID_NOW,
        `observe with now: ${String(badNow)}`
      );
      expectCode(
        () =>
          cancelPhilCoreV2GenesisRoleCeremony({
            current: active,
            nowUnixSeconds: badNow
          }),
        E.INVALID_NOW,
        `cancel with now: ${String(badNow)}`
      );
    }

    // Both ends of the clock domain are accepted.
    assert.equal(
      observePhilCoreV2GenesisRoleCeremonyStatus({
        current: active,
        nowUnixSeconds: UINT48_MAX_NUMBER
      }).lastObservedAtUnixSeconds,
      UINT48_MAX_BIGINT
    );

    // Record fields are bigint-only: a canonical decimal string in a record
    // field is not silently accepted anywhere.
    for (const key of numericFields) {
      expectCode(
        () =>
          validatePhilCoreV2GenesisRoleCeremonyRecord(
            recordCopy(active, { [key]: active[key].toString(10) })
          ),
        E.INVALID_RECORD,
        `record field ${key} supplied as a string`
      );
      expectCode(
        () =>
          validatePhilCoreV2GenesisRoleCeremonyRecord(
            recordCopy(active, { [key]: Number(active[key]) })
          ),
        E.INVALID_RECORD,
        `record field ${key} supplied as a number`
      );
    }

    // Mechanical proxy for "no comparison has a string operand": no relational
    // operator in the module source is adjacent to a string literal.
    assert.equal(
      /["'][^"'\n]*["']\s*(?:<=|>=|<|>)/u.test(MODULE_SOURCE),
      false,
      "a string literal appears on the left of a relational operator"
    );
    assert.equal(
      /(?:<=|>=|<)\s*["']/u.test(MODULE_SOURCE),
      false,
      "a string literal appears on the right of a relational operator"
    );
    assert.equal(
      /\bparseInt\b|\bparseFloat\b|\bNumber\s*\(/u.test(MODULE_SOURCE),
      false,
      "the module coerces through parseInt/parseFloat/Number()"
    );
  });

  it("AT-B14: hostile inputs are classified, never coerced, retain no raw thrown value, and instanceof cannot be forged", () => {
    const active = mint();
    const validConsumeArgs = () => ({ current: active, nowUnixSeconds: NOW + 1 });

    // A throwing ownKeys trap is classified before anything else.
    const enumerationTrap = new Proxy(validConsumeArgs(), {
      ownKeys() {
        throw new Error("hostile ownKeys");
      }
    });
    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony(enumerationTrap),
      E.INPUT_ENUMERATION_FAILED,
      "throwing ownKeys trap"
    );

    // A throwing getPrototypeOf trap is classified as a non-object.
    const prototypeTrap = new Proxy(validConsumeArgs(), {
      getPrototypeOf() {
        throw new Error("hostile getPrototypeOf");
      }
    });
    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony(prototypeTrap),
      E.INPUT_NOT_OBJECT,
      "throwing getPrototypeOf trap"
    );

    // Symbol own keys are rejected outright.
    const symbolKeyed = validConsumeArgs();
    symbolKeyed[Symbol("smuggled")] = 1;
    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony(symbolKeyed),
      E.INPUT_EXTRA_KEY,
      "symbol own key"
    );

    // Non-enumerable extra keys are rejected too.
    const nonEnumerable = validConsumeArgs();
    Object.defineProperty(nonEnumerable, "smuggled", {
      value: 1,
      enumerable: false,
      configurable: true,
      writable: true
    });
    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony(nonEnumerable),
      E.INPUT_EXTRA_KEY,
      "non-enumerable extra own key"
    );

    // A genuine `__proto__` own key is an extra key, not a prototype write.
    const protoKeyed = validConsumeArgs();
    Object.defineProperty(protoKeyed, "__proto__", {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
      writable: true
    });
    assert.equal(Object.getPrototypeOf(protoKeyed), Object.prototype);
    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony(protoKeyed),
      E.INPUT_EXTRA_KEY,
      "__proto__ own key"
    );

    // A set-only accessor yields a read failure, never a silent undefined.
    const setOnly = { current: active };
    Object.defineProperty(setOnly, "nowUnixSeconds", {
      set() {},
      enumerable: true,
      configurable: true
    });
    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony(setOnly),
      E.INPUT_PROPERTY_READ_FAILED,
      "set-only accessor"
    );

    // A throwing getter is classified and its thrown value is discarded.
    const throwingGetter = { current: active };
    Object.defineProperty(throwingGetter, "nowUnixSeconds", {
      get() {
        throw new Error("hostile getter");
      },
      enumerable: true,
      configurable: true
    });
    expectCode(
      () => consumePhilCoreV2GenesisRoleCeremony(throwingGetter),
      E.INPUT_PROPERTY_READ_FAILED,
      "throwing getter"
    );

    // Every boxed primitive and every non-plain prototype is a non-object.
    const notObjects = [
      null,
      undefined,
      0,
      1,
      "",
      "x",
      true,
      1n,
      Symbol("s"),
      [],
      [1, 2],
      new Number(1),
      new String("x"),
      new Boolean(true),
      Object(1n),
      Object(Symbol("boxed")),
      Object.create({ inherited: true }),
      new (class Hostile {})(),
      new Map(),
      new Date(0)
    ];
    for (const value of notObjects) {
      expectCode(
        () => consumePhilCoreV2GenesisRoleCeremony(value),
        E.INPUT_NOT_OBJECT,
        `non-object input: ${String(typeof value)}`
      );
    }

    // A null-prototype argument object is accepted; that is the whole point of
    // permitting exactly Object.prototype and null.
    const nullProto = Object.assign(Object.create(null), validConsumeArgs());
    assert.equal(
      consumePhilCoreV2GenesisRoleCeremony(nullProto).endReason,
      "CONSUMED"
    );

    // Record boundaries collapse the same conditions to INVALID_RECORD.
    for (const value of [new Number(1), Object.create({ inherited: true }), [], "x", 1n]) {
      expectCode(
        () => validatePhilCoreV2GenesisRoleCeremonyRecord(value),
        E.INVALID_RECORD,
        `record boundary non-object: ${String(typeof value)}`
      );
      expectCode(
        () =>
          consumePhilCoreV2GenesisRoleCeremony({
            current: value,
            nowUnixSeconds: NOW + 1
          }),
        E.INVALID_RECORD,
        `current as non-object: ${String(typeof value)}`
      );
    }
    const recordEnumerationTrap = new Proxy(recordCopy(active), {
      ownKeys() {
        throw new Error("hostile ownKeys");
      }
    });
    expectCode(
      () => validatePhilCoreV2GenesisRoleCeremonyRecord(recordEnumerationTrap),
      E.INVALID_RECORD,
      "record boundary enumeration failure"
    );

    // instanceof cannot be forged against the branded error class.
    const forged = { code: E.INVALID_NOW, name: "PhilCoreV2GenesisRoleCeremonyLifecycleError" };
    Object.setPrototypeOf(forged, PhilCoreV2GenesisRoleCeremonyLifecycleError.prototype);
    assert.equal(forged instanceof PhilCoreV2GenesisRoleCeremonyLifecycleError, false);
    assert.equal(
      Object.create(PhilCoreV2GenesisRoleCeremonyLifecycleError.prototype) instanceof
        PhilCoreV2GenesisRoleCeremonyLifecycleError,
      false
    );
    const hasInstance = Object.getOwnPropertyDescriptor(
      PhilCoreV2GenesisRoleCeremonyLifecycleError,
      Symbol.hasInstance
    );
    assert.equal(hasInstance.writable, false);
    assert.equal(hasInstance.configurable, false);
    assert.throws(() => {
      Object.defineProperty(
        PhilCoreV2GenesisRoleCeremonyLifecycleError,
        Symbol.hasInstance,
        { value: () => true }
      );
    });
    // A genuine error still passes the brand.
    const genuine = expectCode(() => mint({ role: 9n }), E.ROLE_INVALID, "brand check");
    assert.equal(genuine instanceof PhilCoreV2GenesisRoleCeremonyLifecycleError, true);
  });

  it("AT-B15: the frozen error table has exactly 21 keys, of which exactly 20 are reachable through the public API and CEREMONY_HASH_COMPUTATION_FAILED is defensive-only", () => {
    assert.equal(Object.isFrozen(PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE), true);
    assert.deepEqual(
      ownKeyOrder(PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE),
      ERROR_CODE_KEYS
    );
    assert.equal(ERROR_CODE_KEYS.length, 21);
    for (const key of ERROR_CODE_KEYS) {
      assert.equal(PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE[key], key);
    }

    const active = mint();
    const { cancelled } = endedRecords();
    const reached = new Set();
    const reach = (fn, code, label) => {
      reached.add(expectCode(fn, code, label).code);
    };

    reach(() => mint({ current: active }), E.CEREMONY_ALREADY_ACTIVE, "already active");
    reach(() => mint({ current: cancelled }), E.CEREMONY_PENDING_RETIREMENT, "pending retirement");
    reach(
      () => cancelPhilCoreV2GenesisRoleCeremony({ current: cancelled, nowUnixSeconds: NOW + 5 }),
      E.CEREMONY_NOT_ACTIVE,
      "not active"
    );
    reach(
      () => cancelPhilCoreV2GenesisRoleCeremony({ current: null, nowUnixSeconds: NOW }),
      E.CEREMONY_NOT_INSTALLED,
      "not installed"
    );
    reach(
      () =>
        retirePhilCoreV2GenesisRoleCeremony({
          current: active,
          expectedCeremonyId: CEREMONY_ID
        }),
      E.CEREMONY_STILL_ACTIVE,
      "still active"
    );
    reach(
      () =>
        retirePhilCoreV2GenesisRoleCeremony({
          current: cancelled,
          expectedCeremonyId: ALT_CEREMONY_ID
        }),
      E.CEREMONY_ID_MISMATCH,
      "id mismatch"
    );
    reach(
      () => validatePhilCoreV2GenesisRoleCeremonyRecord(recordCopy(active, { state: "OTHER" })),
      E.INVALID_RECORD,
      "invalid record"
    );
    reach(() => consumePhilCoreV2GenesisRoleCeremony(7), E.INPUT_NOT_OBJECT, "input not object");
    reach(
      () => consumePhilCoreV2GenesisRoleCeremony({ current: active, nowUnixSeconds: NOW, x: 1 }),
      E.INPUT_EXTRA_KEY,
      "input extra key"
    );
    reach(
      () => consumePhilCoreV2GenesisRoleCeremony({ current: active }),
      E.INPUT_MISSING_KEY,
      "input missing key"
    );
    reach(
      () =>
        consumePhilCoreV2GenesisRoleCeremony(
          new Proxy(
            { current: active, nowUnixSeconds: NOW },
            {
              ownKeys() {
                throw new Error("hostile");
              }
            }
          )
        ),
      E.INPUT_ENUMERATION_FAILED,
      "input enumeration failed"
    );
    reach(
      () => {
        const hostile = { current: active };
        Object.defineProperty(hostile, "nowUnixSeconds", {
          get() {
            throw new Error("hostile");
          },
          enumerable: true,
          configurable: true
        });
        consumePhilCoreV2GenesisRoleCeremony(hostile);
      },
      E.INPUT_PROPERTY_READ_FAILED,
      "input property read failed"
    );
    reach(() => mint({ ceremonyId: ZERO_BYTES32 }), E.CEREMONY_ID_INVALID, "ceremony id zero");
    reach(() => mint({ ceremonyId: CEREMONY_ID.toUpperCase() }), E.CEREMONY_ID_INVALID, "ceremony id uppercase");
    reach(
      () => mint({ genesisDeploymentIntentHash: ZERO_BYTES32 }),
      E.INTENT_HASH_INVALID,
      "intent hash zero"
    );
    reach(() => mint({ role: 3n }), E.ROLE_INVALID, "role out of range");
    reach(() => mint({ nowUnixSeconds: 0 }), E.INVALID_NOW, "invalid now");
    reach(
      () => mint({ intentExpiresAtUnixSeconds: 0n }),
      E.INTENT_EXPIRY_INVALID,
      "intent expiry zero"
    );
    reach(
      () =>
        mint({
          nowUnixSeconds: UINT48_MAX_NUMBER - 299,
          intentExpiresAtUnixSeconds: UINT48_MAX_BIGINT
        }),
      E.EXPIRY_OVERFLOW,
      "expiry overflow"
    );
    reach(
      () => mint({ intentExpiresAtUnixSeconds: BigInt(NOW) }),
      E.EXPIRY_NOT_IN_FUTURE,
      "expiry not in future"
    );
    reach(
      () =>
        observePhilCoreV2GenesisRoleCeremonyStatus({
          current: active,
          nowUnixSeconds: NOW - 1
        }),
      E.CLOCK_REGRESSION_DETECTED,
      "clock regression"
    );

    // Exactly 20 reachable; the 21st is defensive-only and is deliberately NOT
    // exercised. No assertion of universal reachability is made anywhere.
    const expectedReachable = ERROR_CODE_KEYS.filter((key) => key !== DEFENSIVE_ONLY_CODE);
    assert.equal(expectedReachable.length, 20);
    assert.deepEqual([...reached].sort(), [...expectedReachable].sort());
    assert.equal(reached.has(DEFENSIVE_ONLY_CODE), false);
    assert.equal(
      Object.prototype.hasOwnProperty.call(
        PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE,
        DEFENSIVE_ONLY_CODE
      ),
      true,
      "the defensive-only code must still be a member of the frozen table"
    );

    // The validator round-trips every returned record unchanged.
    const { expired, consumed } = endedRecords();
    const retired = retirePhilCoreV2GenesisRoleCeremony({
      current: consumed,
      expectedCeremonyId: CEREMONY_ID
    });
    for (const record of [active, cancelled, expired, consumed, retired]) {
      const roundTripped = validatePhilCoreV2GenesisRoleCeremonyRecord(record);
      assert.deepEqual(ownKeyOrder(roundTripped), RECORD_KEYS);
      for (const key of RECORD_KEYS) {
        assert.equal(roundTripped[key], record[key], `round trip changed ${key}`);
      }
      assertDeepFrozenRecord(roundTripped);
    }

    // The endReason union accepts exactly null, CANCELLED, EXPIRED, CONSUMED.
    for (const reason of ["CANCELLED", "EXPIRED", "CONSUMED"]) {
      const ok = validatePhilCoreV2GenesisRoleCeremonyRecord(
        recordCopy(cancelled, { endReason: reason })
      );
      assert.equal(ok.endReason, reason);
    }
    assert.equal(
      validatePhilCoreV2GenesisRoleCeremonyRecord(recordCopy(active)).endReason,
      null
    );
    for (const reason of ["RETIRED", "cancelled", "", 0, 1n, false, undefined, {}, ["EXPIRED"]]) {
      expectCode(
        () =>
          validatePhilCoreV2GenesisRoleCeremonyRecord(
            recordCopy(cancelled, { endReason: reason })
          ),
        E.INVALID_RECORD,
        `ENDED endReason: ${String(reason)}`
      );
    }
    // null is only valid while ACTIVE, and a reason is only valid while ENDED.
    expectCode(
      () =>
        validatePhilCoreV2GenesisRoleCeremonyRecord(
          recordCopy(cancelled, { endReason: null })
        ),
      E.INVALID_RECORD,
      "ENDED with a null endReason"
    );
    expectCode(
      () =>
        validatePhilCoreV2GenesisRoleCeremonyRecord(
          recordCopy(active, { endReason: "CANCELLED" })
        ),
      E.INVALID_RECORD,
      "ACTIVE with a non-null endReason"
    );
  });

  it("AT-B16: the module is pure and its runtime export set is exactly the 12 contracted names", () => {
    const forbidden = [
      ["fs", /\bnode:fs\b|["'`]fs["'`]|\breadFileSync\b|\bwriteFileSync\b|\bexistsSync\b/u],
      ["crypto", /\bnode:crypto\b|["'`]crypto["'`]|\bwebcrypto\b|\bcrypto\s*\.|\bgetRandomValues\b|\brandomUUID\b/u],
      ["Date", /\bDate\b/u],
      ["process", /\bprocess\b/u],
      ["timer", /\bset(?:Timeout|Interval|Immediate)\b|\bclear(?:Timeout|Interval|Immediate)\b|\bqueueMicrotask\b|\bperformance\s*\.|\bhrtime\b/u],
      ["network", /\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bnode:(?:http|https|net|dns|tls|dgram)\b/u],
      ["randomness", /\bMath\s*\.\s*random\b/u],
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

    // The runtime export surface is exactly the 12 contracted names.
    // `__esModule` is the transpiler's interop marker, not a module export.
    const runtimeNames = Reflect.ownKeys(lifecycle)
      .filter((key) => typeof key === "string" && key !== "__esModule")
      .sort();
    assert.deepEqual(runtimeNames, [...RUNTIME_EXPORTS].sort());
    assert.equal(runtimeNames.length, 12);
    for (const name of RUNTIME_EXPORTS) {
      assert.notEqual(lifecycle[name], undefined, `missing runtime export: ${name}`);
    }
    assert.equal(
      Object.prototype.hasOwnProperty.call(lifecycle, "default"),
      false,
      "the module must not have a default export"
    );

    // Requiring the module performs no work: the export surface is the only
    // observable effect, and a second require is the identical namespace.
    const again = require(
      "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts"
    );
    assert.equal(again, lifecycle);

    // Composition: 3 constants, 1 frozen table, 1 error class, 5 transitions,
    // 1 projection, 1 validator.
    const functions = RUNTIME_EXPORTS.filter((name) => typeof lifecycle[name] === "function");
    assert.deepEqual(functions.sort(), [
      "PhilCoreV2GenesisRoleCeremonyLifecycleError",
      "cancelPhilCoreV2GenesisRoleCeremony",
      "consumePhilCoreV2GenesisRoleCeremony",
      "mintPhilCoreV2GenesisRoleCeremony",
      "observePhilCoreV2GenesisRoleCeremonyStatus",
      "retirePhilCoreV2GenesisRoleCeremony",
      "toPhilCoreV2GenesisRoleCeremonyHashInput",
      "validatePhilCoreV2GenesisRoleCeremonyRecord"
    ]);
    assert.equal(typeof lifecycle.PHILCORE_V2_GENESIS_ROLE_CEREMONY_ERROR_CODE, "object");
  });
});
