"use strict";

// PhilCore Gate C — dormant genesis staging coordinator suite (58 contracts).
//
// Module under test: apps/philcore-desktop/src/main/recovery-genesis-coordinator.cjs
//
// The coordinator exclusively owns one Package 5B-0.5 recovery genesis staging
// host and one pure Gate-B genesis role-ceremony lifecycle slot. It performs no
// filesystem access of its own, is required by no main, preload, renderer, IPC,
// or bridge-contract file, and takes deterministic injected clock/randomness
// only. No IPC. No renderer. No device adapter. No second validation or
// persistence authority. No network. No signing. No physical ceremony.
//
// Observability (§5.1): every assertion reaches through exactly four channels —
// (1) the coordinator's public methods and returned objects; (2) the host's
// public methods on a SEPARATELY CONSTRUCTED, test-owned host instance;
// (3) public exports of the pure Gate-B / 5B-0.4 modules called directly;
// (4) the §7.1 module-cache seam on exactly those two pure `.ts` paths.
//
// §7.2 is binding: THERE IS NO HOST-METHOD SPY IN THIS FILE, and none may be
// created. Host-boundary facts are proven only by the §7.2.2 instruments —
// 5B-0.4 shim call counts for the three one-for-one host methods, the host's
// own closed rejection surfaces, durable journal-file state, the
// reconciliation guard, and coordinator-error identity. The host module is
// required here solely to construct test-owned hosts (channel 2) and is never
// seamed, patched, wrapped, or decorated.

require("tsx/cjs");

const assert = require("node:assert/strict");
const child_process = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { getAddress } = require("ethers");

const {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
  computePhilCoreV2ConsumerRecoveryIndependenceBinding
} = require("../../phil-device-sdk/src/v2ConsumerRecovery.ts");
const { PHILCORE_V2_SECURITY_MODEL_ID } = require("../../phil-device-sdk/src/v2Intent.ts");

// ---------------------------------------------------------------------------
// §7.1 authorized test seam — module-cache substitution, exactly two paths
// ---------------------------------------------------------------------------
// The tsx export namespace is non-configurable, so an in-place wrapper is
// impossible; the Gate A host suite establishes this precedent and solves it by
// installing a mutable key-for-key copy in require.cache. Applied here at load
// time, BEFORE the coordinator module is required, to exactly two paths: the
// Gate-B lifecycle module and the 5B-0.4 staging-journal module. It is never
// applied to the coordinator module, the host module, or any other module.

const GATE_B_PATH = require.resolve(
  "../../phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts"
);
const gateBReal = require(GATE_B_PATH);
const gateBShim = {};
for (const key of Object.keys(gateBReal)) gateBShim[key] = gateBReal[key];
require.cache[GATE_B_PATH].exports = gateBShim;

const PURE_JOURNAL_PATH = require.resolve(
  "../../phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingJournal.ts"
);
const pureJournalReal = require(PURE_JOURNAL_PATH);
const pureJournalShim = {};
for (const key of Object.keys(pureJournalReal)) pureJournalShim[key] = pureJournalReal[key];
require.cache[PURE_JOURNAL_PATH].exports = pureJournalShim;

const genesisProtocol = require("../../phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts");
const stagingProfileAdapter = require(
  "../../phil-device-sdk/src/v2ConsumerRecoveryGenesis" + "StagingProfile.ts"
);
const validateGenesisStagingProfileAdapter = stagingProfileAdapter[
  "validatePhilCoreV2ConsumerRecoveryGenesis" + "StagingProfile"
];

const O39_FIXTURES = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, "../../../config/cryptography/O39_CONSUMER_RECOVERY_FIXTURES.json"),
    "utf8"
  )
);

// Channel 2 only: test-owned host instances. Never seamed or spied.
const hostModule = require("../src/main/recovery-genesis-staging-host.cjs");
const { createRecoveryGenesisStagingHost } = hostModule;
const HostError = hostModule.PhilCoreV2ConsumerRecoveryGenesisStagingHostError;

// The module under test. Required after the seams so the coordinator's lazy
// accessors resolve the same specifiers and receive the shim objects.
const COORDINATOR_PATH = path.resolve(__dirname, "../src/main/recovery-genesis-coordinator.cjs");
const coordinatorModule = require("../src/main/recovery-genesis-coordinator.cjs");
const {
  createRecoveryGenesisCoordinator,
  PhilCoreV2RecoveryGenesisCoordinatorError,
  PHILCORE_V2_RECOVERY_GENESIS_COORDINATOR_ERROR_CODE: CODE
} = coordinatorModule;

// ---------------------------------------------------------------------------
// File-local hand-rolled harness (the established desktop-suite shape)
// ---------------------------------------------------------------------------
let passed = 0;
const failures = [];
function test(name, fn) {
  try { fn(); passed += 1; }
  catch (error) { failures.push({ name, error }); }
}

// ---------------------------------------------------------------------------
// Constants and expectations
// ---------------------------------------------------------------------------
const UINT48_MAX = 281474976710655;
const NOW = 1700000000;
const HOST_METHOD_NAMES = [
  "reconcileRestart", "createJournal", "stageRole", "cancel",
  "finalizeProfile", "status", "acknowledgeTerminal", "close",
  "beginCredentialObligation", "authorizeCredentialCreation",
  "recordCreatedCredential", "cancelCredentialObligation"
];
const COORDINATOR_METHOD_NAMES = [
  "reconcileRestart", "createJournal", "beginRole", "authorizeCredentialCreation",
  "recordCreatedCredential", "stageRole", "cancelRoleCeremony", "cancelEnrollment",
  "finalizeProfile", "status", "acknowledgeTerminal", "close"
];
const EXPECTED_CODES = [
  "COORDINATOR_DEPENDENCIES_NOT_OBJECT",
  "COORDINATOR_DEPENDENCY_ENUMERATION_FAILED",
  "COORDINATOR_DEPENDENCY_EXTRA",
  "COORDINATOR_DEPENDENCY_MISSING",
  "COORDINATOR_DEPENDENCY_INVALID",
  "COORDINATOR_DEPENDENCY_READ_FAILED",
  "COORDINATOR_CLOSED",
  "COORDINATOR_POISONED",
  "COORDINATOR_INVALID_STATE",
  "COORDINATOR_ALREADY_RECONCILED",
  "COORDINATOR_CANDIDATE_NOT_OBJECT",
  "COORDINATOR_CANDIDATE_ENUMERATION_FAILED",
  "COORDINATOR_CANDIDATE_EXTRA_KEY",
  "COORDINATOR_CANDIDATE_MISSING_KEY",
  "COORDINATOR_CANDIDATE_READ_FAILED",
  "COORDINATOR_INVALID_NOW",
  "COORDINATOR_CLOCK_REGRESSION_DETECTED",
  "COORDINATOR_JOURNAL_TIMESTAMP_INVALID",
  "COORDINATOR_CEREMONY_ID_GENERATION_FAILED"
];
const GATE_B_FUNCTION_NAMES = [
  "validatePhilCoreV2GenesisRoleCeremonyRecord",
  "toPhilCoreV2GenesisRoleCeremonyHashInput",
  "mintPhilCoreV2GenesisRoleCeremony",
  "observePhilCoreV2GenesisRoleCeremonyStatus",
  "cancelPhilCoreV2GenesisRoleCeremony",
  "consumePhilCoreV2GenesisRoleCeremony",
  "retirePhilCoreV2GenesisRoleCeremony"
];
const PURE_WATCHED_NAMES = [
  "createGenesisStagingJournal",
  "stageGenesisRoleCandidate",
  "cancelGenesisStagingJournal",
  "expireGenesisStagingJournalIfNeeded"
];

// Every coordinator-originated code observed anywhere in the suite; AT-C25
// asserts the closure of this set against the frozen table.
const OBSERVED_COORDINATOR_CODES = new Set();

// ---------------------------------------------------------------------------
// Roots and cleanup
// ---------------------------------------------------------------------------
let tmpSeq = 0;
const createdRoots = [];
function freshRoot() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `philcore-gatec-${process.pid}-${tmpSeq++}-`));
  createdRoots.push(dir);
  return dir;
}
function withRoot(fn) {
  const dir = freshRoot();
  try { return fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
function stagingDir(dir) {
  return path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
}
function journalFilePath(dir, record) {
  const base = String(record.ceremonyId || record.intentId).replace(/^0x/u, "");
  return path.join(stagingDir(dir), `ceremony_${base}.v1.json`);
}
function obligationFilePath(dir) {
  return path.join(stagingDir(dir), "genesis-credential-obligation.v1.json");
}
function profilesDir(dir) {
  return path.join(dir, "philcore-recovery-enrollment", "genesis-profiles");
}
function finalizedProfileFilePath(dir, record) {
  const hash = String(record.genesisDeploymentIntentHash).replace(/^0x/u, "");
  return path.join(profilesDir(dir), `profile_${hash}.v1.json`);
}
function expectedValidationFor(coord, now) {
  const journal = coord.status().journal;
  return validateGenesisStagingProfileAdapter(
    journal,
    now === undefined ? NOW : now
  );
}
function profileReadyCoordinator(dir, overrides) {
  const coord = stagingCoordinator(dir, overrides);
  fillAllRoles(coord);
  return coord;
}

// ---------------------------------------------------------------------------
// Deterministic injected clock. `calls` counts every invocation, including the
// host's own samples through the same forwarded reference.
// ---------------------------------------------------------------------------
function makeClock(initial) {
  const clock = { value: initial === undefined ? NOW : initial, calls: 0, impl: null };
  clock.fn = () => {
    clock.calls += 1;
    if (clock.impl !== null) return clock.impl();
    return clock.value;
  };
  return clock;
}

function baseDeps(dir, overrides) {
  return Object.assign(
    { storageRoot: dir, nowFn: () => NOW, livenessProbeFn: () => "DEAD" },
    overrides || {}
  );
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
function validIntent(overrides) {
  const rep = (byte, times) => `0x${byte.repeat(times)}`;
  return Object.assign(
    {
      intentVersion: "1",
      intentId: rep("11", 32),
      chainId: "11155111",
      entryPoint: getAddress(rep("22", 20)),
      factoryBinding: getAddress(rep("33", 20)),
      confirmationTarget: getAddress(rep("44", 20)),
      verifier: getAddress(rep("55", 20)),
      verifierRuntimeCodeHash: rep("66", 32),
      accountCreationBytecodeHash: rep("77", 32),
      accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
      securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
      recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
      ownerCommitment: rep("bb", 32),
      identityBindingCommitment: rep("cc", 32),
      initialValidator: getAddress(rep("dd", 20)),
      validatorVerifierKind: "1",
      validatorKeyIdBinding: rep("ee", 32),
      validatorCommitment: rep("ff", 32),
      validatorEpoch: "1",
      recoveryEpoch: "1",
      recoveryDelaySeconds: "172800",
      recoveryExpirySeconds: "604800",
      userSalt: rep("ab", 32),
      expiresAt: "1900000000"
    },
    overrides || {}
  );
}

const DESCRIPTOR_NUMERIC_FIELDS = [
  "descriptorVersion", "role", "verifierKind", "userVerificationPolicy",
  "backupPolicy", "authenticatorAttachmentPolicy", "attestationPolicy", "credentialGeneration"
];
const INDEPENDENCE_NUMERIC_FIELDS = [
  "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
  "independenceAssurance", "credentialGeneration"
];
function toBigintFields(source, fields) {
  const out = Object.assign({}, source);
  for (const field of fields) if (typeof out[field] === "number") out[field] = BigInt(out[field]);
  return out;
}

// A schema-valid candidate for `role`, bound to the REAL minted Gate-B
// ceremony's own enrollment hash. The coordinator supplies
// `currentRoleCeremony` itself (§5.6 step 7); the caller never does.
function candidateFor(minted, role) {
  const factors = O39_FIXTURES.profiles.standard.factors;
  const base = [factors.primary, factors.secondary, factors.offline][role];
  const independence = Object.assign(
    toBigintFields(base.independence, INDEPENDENCE_NUMERIC_FIELDS),
    {
      role: BigInt(role),
      enrollmentCeremonyHash: minted.genesisEnrollmentCeremonyHash,
      credentialGeneration: 1n
    }
  );
  const descriptor = Object.assign(
    toBigintFields(base.descriptor, DESCRIPTOR_NUMERIC_FIELDS),
    {
      role: BigInt(role),
      credentialGeneration: 1n,
      independenceBindingHash: computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence)
    }
  );
  const candidate = { descriptor, independence };
  if (base.signer) candidate.signer = base.signer;
  return candidate;
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------
function assertCoordError(fn, code) {
  let thrown = null;
  let threw = false;
  try { fn(); } catch (error) { threw = true; thrown = error; }
  assert.ok(threw, `expected a throw with code ${code}`);
  assert.ok(
    thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError,
    `expected a coordinator error, got ${thrown && thrown.code ? thrown.code : String(thrown)}`
  );
  assert.equal(thrown.code, code);
  OBSERVED_COORDINATOR_CODES.add(thrown.code);
  return thrown;
}

function captureThrow(fn) {
  try { fn(); } catch (error) { return error; }
  throw new Error("expected a throw");
}

// A host instance is identified by carrying ALL TWELVE host method names. The
// coordinator deliberately shares several of those names but exposes no `cancel`,
// so this predicate separates the two precisely. AT-C1 validates the predicate
// against a real test-owned host before relying on it, so the assertion can
// never be vacuous.
function isHostLike(value) {
  if (value === null) return false;
  if (typeof value !== "object" && typeof value !== "function") return false;
  for (const name of HOST_METHOD_NAMES) {
    let member;
    try { member = value[name]; } catch { return false; }
    if (typeof member !== "function") return false;
  }
  return true;
}

// Bounded own-key walk asserting nothing reachable resembles the host or a
// host method table.
function assertNoHostReachable(root, label) {
  const seen = new Set();
  const walk = (value, depth) => {
    if (depth > 6) return;
    if (value === null) return;
    if (typeof value !== "object" && typeof value !== "function") return;
    if (seen.has(value)) return;
    seen.add(value);
    assert.ok(!isHostLike(value), `${label}: host-like object reachable`);
    for (const key of Object.getOwnPropertyNames(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor)) continue;
      walk(descriptor.value, depth + 1);
    }
  };
  walk(root, 0);
}

function assertDeepFrozen(value, label, depth) {
  const level = depth === undefined ? 0 : depth;
  if (level > 5) return;
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return;
  assert.ok(Object.isFrozen(value), `${label}: expected frozen`);
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) continue;
    assertDeepFrozen(descriptor.value, `${label}.${key}`, level + 1);
  }
}

// ---------------------------------------------------------------------------
// §7.1 seam instruments. Every replacement is restored in a `finally`, so no
// arm can leak a fault into a later block.
// ---------------------------------------------------------------------------
function withGateBSpy(body) {
  const calls = [];
  const originals = {};
  for (const name of GATE_B_FUNCTION_NAMES) {
    originals[name] = gateBShim[name];
    gateBShim[name] = (...args) => {
      calls.push({ fn: name, args });
      return originals[name](...args);
    };
  }
  try { return body(calls); }
  finally { for (const name of GATE_B_FUNCTION_NAMES) gateBShim[name] = originals[name]; }
}

function withGateBReplaced(name, impl, body) {
  const original = gateBShim[name];
  gateBShim[name] = impl;
  try { return body(original); }
  finally { gateBShim[name] = original; }
}

function withPureSpy(body) {
  const calls = [];
  const originals = {};
  for (const name of PURE_WATCHED_NAMES) {
    originals[name] = pureJournalShim[name];
    pureJournalShim[name] = (...args) => {
      calls.push({ fn: name, args });
      return originals[name](...args);
    };
  }
  try { return body(calls); }
  finally { for (const name of PURE_WATCHED_NAMES) pureJournalShim[name] = originals[name]; }
}

function withPureReplaced(name, impl, body) {
  const original = pureJournalShim[name];
  pureJournalShim[name] = impl;
  try { return body(original); }
  finally { pureJournalShim[name] = original; }
}

function countCalls(calls, name) {
  return calls.filter((entry) => entry.fn === name).length;
}

function assertShimsPristine() {
  for (const name of GATE_B_FUNCTION_NAMES) {
    assert.equal(gateBShim[name], gateBReal[name], `gate-B shim ${name} not restored`);
  }
  for (const name of Object.keys(gateBReal)) {
    assert.equal(gateBShim[name], gateBReal[name], `gate-B shim ${name} not key-identical`);
  }
  for (const name of Object.keys(pureJournalReal)) {
    assert.equal(pureJournalShim[name], pureJournalReal[name], `5B-0.4 shim ${name} not key-identical`);
  }
}

// ---------------------------------------------------------------------------
// Drivers
// ---------------------------------------------------------------------------
function newCoordinator(dir, overrides) {
  return createRecoveryGenesisCoordinator(baseDeps(dir, overrides));
}

// Reconciled coordinator holding a fresh STAGING journal (READY_STAGING).
function stagingCoordinator(dir, overrides, intentOverrides) {
  const coord = newCoordinator(dir, overrides);
  coord.reconcileRestart();
  coord.createJournal(validIntent(intentOverrides));
  return coord;
}

function recordRole(coord, begun) {
  coord.authorizeCredentialCreation();
  const candidate = candidateFor(begun.ceremony, begun.role);
  coord.recordCreatedCredential({
    credentialIdHash: candidate.descriptor.credentialIdHash,
    publicVerificationMaterialHash: candidate.descriptor.publicVerificationMaterialHash
  });
  return candidate;
}

function stageOneRole(coord, role) {
  const begun = coord.beginRole();
  assert.equal(begun.role, role);
  return coord.stageRole(recordRole(coord, begun));
}

function fillAllRoles(coord) {
  const results = [];
  for (const role of [0, 1, 2]) results.push(stageOneRole(coord, role));
  return results;
}

// Poisons a storage root through the host's own documented behaviour, using a
// test-owned host (channel 2): removing the lock file makes `close()` fail, and
// every releaseLock failure path inserts the root into the host module's
// poisoned-root registry.
function poisonRoot(dir) {
  const host = createRecoveryGenesisStagingHost({
    storageRoot: dir, nowFn: () => NOW, livenessProbeFn: () => "DEAD"
  });
  host.reconcileRestart();
  fs.unlinkSync(path.join(stagingDir(dir), ".staging.lock"));
  const error = captureThrow(() => host.close());
  assert.ok(error instanceof HostError);
  return error;
}

// Drives a coordinator to POISONED through the authorized §7.1 seam: a pure
// 5B-0.4 throw carrying an INDETERMINATE commit state propagates by identity
// through the host and satisfies the coordinator's poison rule.
function poisonCoordinator(coord) {
  const sentinel = new HostError("HOST_FILESYSTEM_MUTATION_FAILED", {
    commitState: "INDETERMINATE",
    operation: "createJournal",
    phase: "TEST",
    primaryCode: null,
    subject: null
  });
  withPureReplaced("createGenesisStagingJournal", () => { throw sentinel; }, () => {
    const thrown = captureThrow(() => coord.createJournal(validIntent()));
    assert.equal(thrown, sentinel);
  });
  assertCoordError(() => coord.status(), "COORDINATOR_POISONED");
  return coord;
}

function plantStaleLock(dir, ageSeconds) {
  const staging = stagingDir(dir);
  fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.join(dir, "philcore-recovery-enrollment"), 0o700);
  fs.chmodSync(staging, 0o700);
  const lock = path.join(staging, ".staging.lock");
  fs.writeFileSync(
    lock,
    JSON.stringify({ pid: "999999", createdAtUnixSeconds: String(NOW - ageSeconds) }),
    { mode: 0o600 }
  );
  return lock;
}

// ===========================================================================
// AT-C1
// ===========================================================================
test("AT-C1: host unreachable — own keys, prototype chain, and every returned object", () => {
  // Positive control: the host-detector must actually detect a real host
  // (channel 2), otherwise every assertion below would be vacuous.
  withRoot((controlDir) => {
    const controlHost = createRecoveryGenesisStagingHost(baseDeps(controlDir));
    assert.ok(isHostLike(controlHost), "the host detector fails to detect a real host");
    assert.deepEqual(Object.keys(controlHost).sort(), HOST_METHOD_NAMES.slice().sort());
    controlHost.close();
  });

  withRoot((dir) => {
    const coord = newCoordinator(dir);

    // The coordinator exposes no `cancel`, so it is not itself host-shaped.
    assert.equal(coord.cancel, undefined);
    assert.ok(!isHostLike(coord));

    assert.deepEqual(Object.getOwnPropertyNames(coord).sort(), COORDINATOR_METHOD_NAMES.slice().sort());
    assert.equal(Object.getOwnPropertySymbols(coord).length, 0);
    assert.equal(Object.getOwnPropertyNames(coord).length, 12);
    assert.ok(Object.isFrozen(coord));
    for (const name of COORDINATOR_METHOD_NAMES) assert.equal(typeof coord[name], "function");

    // No own property of the coordinator is or reaches the host.
    assertNoHostReachable(coord, "coordinator");

    // The prototype chain carries no host reference either.
    let proto = Object.getPrototypeOf(coord);
    let depth = 0;
    while (proto !== null && depth < 5) {
      assert.ok(!isHostLike(proto), "prototype chain exposes a host-like object");
      proto = Object.getPrototypeOf(proto);
      depth += 1;
    }

    // Every object returned by every method, walked.
    const returned = [];
    returned.push(coord.reconcileRestart());
    returned.push(coord.status());
    returned.push(coord.createJournal(validIntent()));
    const begun = coord.beginRole();
    returned.push(begun);
    returned.push(coord.status());
    returned.push(coord.authorizeCredentialCreation());
    returned.push(coord.recordCreatedCredential({
      credentialIdHash: candidateFor(begun.ceremony, 0).descriptor.credentialIdHash,
      publicVerificationMaterialHash: candidateFor(begun.ceremony, 0).descriptor.publicVerificationMaterialHash
    }));
    returned.push(coord.stageRole(candidateFor(begun.ceremony, 0)));
    returned.push(coord.cancelEnrollment());
    returned.push(coord.acknowledgeTerminal());
    for (const value of returned) assertNoHostReachable(value, "returned");

    // Errors do not carry the host either.
    const error = assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");
    assertNoHostReachable(error, "error");

    coord.close();
  });
});

// ===========================================================================
// AT-C2
// ===========================================================================
test("AT-C2: caller-supplied currentRoleCeremony is rejected as COORDINATOR_CANDIDATE_EXTRA_KEY", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const base = recordRole(coord, begun);

    const enumerable = Object.assign({}, base, { currentRoleCeremony: { forged: true } });

    const nonEnumerable = Object.assign({}, base);
    Object.defineProperty(nonEnumerable, "currentRoleCeremony", {
      value: { forged: true }, enumerable: false, configurable: true, writable: true
    });

    const symbolKeyed = Object.assign({}, base);
    symbolKeyed[Symbol("currentRoleCeremony")] = { forged: true };

    const proxied = new Proxy(Object.assign({}, base), {
      ownKeys(target) { return [...Reflect.ownKeys(target), "currentRoleCeremony"]; },
      getOwnPropertyDescriptor(target, key) {
        if (key === "currentRoleCeremony") {
          return { value: { forged: true }, enumerable: true, configurable: true, writable: true };
        }
        return Reflect.getOwnPropertyDescriptor(target, key);
      }
    });

    withPureSpy((calls) => {
      for (const variant of [enumerable, nonEnumerable, symbolKeyed, proxied]) {
        assertCoordError(() => coord.stageRole(variant), "COORDINATOR_CANDIDATE_EXTRA_KEY");
      }
      // §7.2.2: the one-for-one 5B-0.4 witness proves the host was never reached.
      assert.equal(countCalls(calls, "stageGenesisRoleCandidate"), 0);
    });

    // Never overwritten, never probed: the rejection left the recorded obligation intact.
    assert.equal(coord.status().state, "CREDENTIAL_RECORDED");
    const staged = coord.stageRole(candidateFor(begun.ceremony, 0));
    assert.equal(staged.staged, true);
    coord.close();
  });
});

// ===========================================================================
// AT-C3
// ===========================================================================
test("AT-C3: delegated candidate is null-prototype, correctly ordered, and carries the projection", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);

    // Role 0 — no signer.
    const begun0 = coord.beginRole();
    const expectedProjection = gateBShim.toPhilCoreV2GenesisRoleCeremonyHashInput(begun0.ceremony);
    withPureSpy((calls) => {
      coord.stageRole(recordRole(coord, begun0));
      const call = calls.find((entry) => entry.fn === "stageGenesisRoleCandidate");
      assert.ok(call, "the 5B-0.4 shim observed no stage delegation");
      const roleInput = call.args[2];
      assert.equal(Object.getPrototypeOf(roleInput), null);
      assert.deepEqual(Object.keys(roleInput), ["descriptor", "independence", "currentRoleCeremony"]);
      // Fresh frozen object per call, so deepStrictEqual — never ===.
      assert.deepStrictEqual(roleInput.currentRoleCeremony, expectedProjection);
      assert.notEqual(roleInput.currentRoleCeremony, expectedProjection);
      assert.ok(Object.isFrozen(roleInput.currentRoleCeremony));
      assert.equal(Object.getPrototypeOf(roleInput.currentRoleCeremony), null);
      assert.equal(Object.keys(roleInput.currentRoleCeremony).length, 6);
      assert.deepEqual(Object.keys(roleInput.currentRoleCeremony), [
        "ceremonyVersion", "ceremonyId", "genesisDeploymentIntentHash",
        "role", "credentialGeneration", "expiresAt"
      ]);
      for (const key of Object.keys(roleInput.currentRoleCeremony)) {
        assert.equal(typeof roleInput.currentRoleCeremony[key], "string");
      }
    });

    // Role 1, then role 2 — signer present, and it sits before currentRoleCeremony.
    stageOneRole(coord, 1);
    const begun2 = coord.beginRole();
    withPureSpy((calls) => {
      coord.stageRole(recordRole(coord, begun2));
      const call = calls.find((entry) => entry.fn === "stageGenesisRoleCandidate");
      const roleInput = call.args[2];
      assert.equal(Object.getPrototypeOf(roleInput), null);
      assert.deepEqual(
        Object.keys(roleInput),
        ["descriptor", "independence", "signer", "currentRoleCeremony"]
      );
    });
    coord.close();
  });
});

// ===========================================================================
// AT-C4
// ===========================================================================
test("AT-C4: regressing nowFn across beginRole -> stageRole still commits durably and never wedges", () => {
  withRoot((dir) => {
    const clock = makeClock(1000);
    const coord = newCoordinator(dir, { nowFn: clock.fn });
    coord.reconcileRestart();
    const created = coord.createJournal(validIntent());
    assert.equal(created.journal.updatedAtUnixSeconds, "1000");

    // beginRole samples the coordinator clock and then the host clock.
    clock.value = 1100;
    const begun = coord.beginRole();
    assert.equal(begun.ceremony.lastObservedAtUnixSeconds, 1100n);

    const candidate = recordRole(coord, begun);
    clock.value = 1105;
    let result = null;
    withPureSpy((calls) => {
      result = coord.stageRole(candidate);                                   // (a) returns
      // (f) exactly one host.stageRole delegation, per §7.2 — the authorized
      // one-for-one 5B-0.4 witness, NOT a host-method spy.
      assert.equal(countCalls(calls, "stageGenesisRoleCandidate"), 1);
    });

    assert.equal(result.journal.manifest[String(result.role)] !== null, true);  // (b)
    assert.equal(result.staged, true);                                          // (c)
    assert.equal(result.ceremony, null);                                        // (d)
    assert.ok(["READY_STAGING", "READY_FOR_PROFILE_VALIDATION"].includes(result.state)); // (e)
    assert.equal(result.state, "READY_STAGING");
    assert.equal(result.journal.updatedAtUnixSeconds, "1105");

    // (g) a subsequent beginRole succeeds and mints for the new nextRole.
    clock.value = 1110;
    const status = coord.status();
    assert.equal(status.nextRole, 1);
    const next = coord.beginRole();
    assert.equal(next.role, 1);
    assert.equal(next.ceremony.state, "ACTIVE");
    assert.notEqual(next.ceremony.ceremonyId, begun.ceremony.ceremonyId);

    // (h) no duplicate/sequence failure was ever raised.
    const staged1 = coord.stageRole(recordRole(coord, next));
    assert.equal(staged1.staged, true);
    coord.close();
  });
});

// ===========================================================================
// AT-C5
// ===========================================================================
test("AT-C5: any Gate-B post-commit failure is absorbed and the journal always wins", () => {
  // Arm 1 — consume throws (staged === true takes the consume path).
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);
    const result = withGateBReplaced(
      "consumePhilCoreV2GenesisRoleCeremony",
      () => { throw new Error("consume exploded"); },
      () => coord.stageRole(candidate)
    );
    assert.equal(result.staged, true);
    assert.equal(result.ceremony, null);
    assert.equal(result.state, "READY_STAGING");
    assert.equal(coord.status().journal, result.journal);
    coord.close();
  });

  // Arm 2 — retire throws, reached through a genuinely ENDED consume result.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);
    const result = withGateBReplaced(
      "retirePhilCoreV2GenesisRoleCeremony",
      () => { throw new Error("retire exploded"); },
      () => coord.stageRole(candidate)
    );
    assert.equal(result.staged, true);
    assert.equal(result.ceremony, null);
    assert.equal(coord.status().ceremony, null);
    coord.close();
  });

  // Arm 3 — terminal journal (staged === false) with observeStatus throwing.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn }, { expiresAt: String(NOW + 100) });
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);
    clock.value = NOW + 200;
    const result = withGateBReplaced(
      "observePhilCoreV2GenesisRoleCeremonyStatus",
      () => { throw new Error("observe exploded"); },
      () => coord.stageRole(candidate)
    );
    assert.equal(result.staged, false);
    assert.equal(result.ceremony, null);
    assert.equal(result.state, "ORPHAN_CREDENTIAL_BLOCKED");
    assert.equal(result.obligation.state, "ORPHANED");
    assert.equal(result.journal.state, "EXPIRED");
    assert.equal(coord.status().journal, result.journal);
    coord.close();
  });

  // Arm 4 — an unusable returned.updatedAtUnixSeconds: no Gate-B call at all,
  // and the ceremony is still discarded unconditionally.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);
    const real = pureJournalReal.stageGenesisRoleCandidate;
    const result = withPureReplaced(
      "stageGenesisRoleCandidate",
      (...args) => Object.assign({}, real(...args), { updatedAtUnixSeconds: "0" }),
      () => withGateBSpy((calls) => {
        const staged = coord.stageRole(candidate);
        assert.equal(countCalls(calls, "consumePhilCoreV2GenesisRoleCeremony"), 0);
        assert.equal(countCalls(calls, "observePhilCoreV2GenesisRoleCeremonyStatus"), 0);
        assert.equal(countCalls(calls, "retirePhilCoreV2GenesisRoleCeremony"), 0);
        return staged;
      })
    );
    assert.equal(result.ceremony, null);
    assert.equal(result.journal.updatedAtUnixSeconds, "0");
    assert.equal(result.staged, true);
    // The unusable journal was still adopted by reference: reading it back
    // through the public surface now raises the timestamp code, which is only
    // possible if the coordinator retained that exact record.
    assertCoordError(() => coord.status(), "COORDINATOR_JOURNAL_TIMESTAMP_INVALID");
    coord.close();
  });
});

// ===========================================================================
// AT-C6
// ===========================================================================
test("AT-C6: clock-call totals against the bare-host baseline, plus path-conditional construction", () => {
  const clock = makeClock(NOW);
  const snapshot = () => clock.calls;
  const delta = (fn) => { const before = snapshot(); fn(); return snapshot() - before; };

  // Arm 1 — bare host baseline (channel 2), its own storage root.
  withRoot((dirA) => {
    let host = null;
    assert.equal(delta(() => {
      host = createRecoveryGenesisStagingHost({
        storageRoot: dirA, nowFn: clock.fn, livenessProbeFn: () => "DEAD"
      });
    }), 1, "bare host construction on a lock-free root");

    assert.equal(delta(() => { host.reconcileRestart(); }), 1, "host.reconcileRestart");

    let journal = null;
    assert.equal(delta(() => { journal = host.createJournal(validIntent()).journal; }), 1, "host.createJournal");

    // Mint + project directly (channel 3) so the bare host can be driven
    // through stageRole exactly as the coordinator drives it. Neither call
    // touches nowFn.
    const minted = gateBShim.mintPhilCoreV2GenesisRoleCeremony({
      current: null,
      ceremonyId: `0x${"ab".repeat(32)}`,
      role: 0n,
      genesisDeploymentIntentHash: journal.genesisDeploymentIntentHash,
      intentExpiresAtUnixSeconds: BigInt(journal.expiresAt),
      nowUnixSeconds: NOW
    });
    const projection = gateBShim.toPhilCoreV2GenesisRoleCeremonyHashInput(minted);
    const candidate = candidateFor(minted, 0);
    const roleInput = Object.assign({}, candidate, { currentRoleCeremony: projection });

    assert.equal(delta(() => { host.beginCredentialObligation(minted); }), 1, "host.beginCredentialObligation");
    assert.equal(delta(() => { host.authorizeCredentialCreation(minted.ceremonyId); }), 1, "host.authorizeCredentialCreation");
    assert.equal(delta(() => {
      host.recordCreatedCredential({
        expectedCeremonyId: minted.ceremonyId,
        credentialIdHash: candidate.descriptor.credentialIdHash,
        publicVerificationMaterialHash: candidate.descriptor.publicVerificationMaterialHash
      });
    }), 1, "host.recordCreatedCredential");
    assert.equal(delta(() => { host.stageRole(0, roleInput); }), 1, "host.stageRole");

    let terminal = null;
    assert.equal(delta(() => { terminal = host.cancel().journal; }), 1, "host.cancel");
    assert.equal(delta(() => { host.status(); }), 0, "host.status");
    assert.equal(delta(() => {
      host.acknowledgeTerminal({
        intentId: terminal.intentId, integrityChecksum: terminal.integrityChecksum
      });
    }), 0, "host.acknowledgeTerminal");
    assert.equal(delta(() => { host.close(); }), 0, "host.close");
  });

  // Arm 2 — the coordinator, sharing the same nowFn spy, its own storage root.
  withRoot((dirB) => {
    let coord = null;
    assert.equal(delta(() => {
      coord = createRecoveryGenesisCoordinator({
        storageRoot: dirB, nowFn: clock.fn, livenessProbeFn: () => "DEAD"
      });
    }), 1, "coordinator construction on a lock-free root");

    assert.equal(delta(() => { coord.reconcileRestart(); }), 1, "coordinator.reconcileRestart");
    assert.equal(delta(() => { coord.createJournal(validIntent()); }), 1, "coordinator.createJournal");

    // Coordinator-only operations with no host counterpart.
    let begun = null;
    assert.equal(delta(() => { begun = coord.beginRole(); }), 2, "coordinator.beginRole");
    assert.equal(delta(() => { coord.status(); }), 1, "coordinator.status");

    const candidate = recordRole(coord, begun);
    assert.equal(delta(() => { coord.stageRole(candidate); }), 1, "coordinator.stageRole");
    assert.equal(delta(() => { coord.cancelEnrollment(); }), 1, "coordinator.cancelEnrollment");
    assert.equal(delta(() => { coord.acknowledgeTerminal(); }), 0, "coordinator.acknowledgeTerminal");
    assert.equal(delta(() => { coord.close(); }), 0, "coordinator.close");
  });

  // Arm 3 — path-conditional construction counts.
  withRoot((dir) => {
    plantStaleLock(dir, 10);
    const live = makeClock(NOW);
    const heldError = captureThrow(() => createRecoveryGenesisCoordinator({
      storageRoot: dir, nowFn: live.fn, livenessProbeFn: () => "LIVE"
    }));
    assert.equal(heldError.code, "HOST_LOCK_HELD");
    assert.equal(live.calls, 0, "liveness LIVE takes zero samples");
  });
  withRoot((dir) => {
    plantStaleLock(dir, 10);
    const ambiguous = makeClock(NOW);
    const ambiguousError = captureThrow(() => createRecoveryGenesisCoordinator({
      storageRoot: dir, nowFn: ambiguous.fn, livenessProbeFn: () => "AMBIGUOUS"
    }));
    assert.equal(ambiguousError.code, "HOST_LOCK_HELD_OR_AMBIGUOUS");
    assert.equal(ambiguous.calls, 0, "liveness AMBIGUOUS takes zero samples");
  });
  withRoot((dir) => {
    plantStaleLock(dir, 10);
    const windowed = makeClock(NOW);
    const windowError = captureThrow(() => createRecoveryGenesisCoordinator({
      storageRoot: dir, nowFn: windowed.fn, livenessProbeFn: () => "DEAD"
    }));
    assert.equal(windowError.code, "HOST_LOCK_HELD_OR_AMBIGUOUS");
    assert.equal(windowed.calls, 1, "staleness-window rejection takes one sample");
  });
  withRoot((dir) => {
    plantStaleLock(dir, 6000);
    const replaced = makeClock(NOW);
    const coord = createRecoveryGenesisCoordinator({
      storageRoot: dir, nowFn: replaced.fn, livenessProbeFn: () => "DEAD"
    });
    assert.equal(replaced.calls, 2, "stale-lock replacement plus creation takes two samples");
    coord.close();
  });

  // Arm 4 — dependency-key OMISSION, on its own fresh root. `deps` genuinely
  // omits every optional own key, so the coordinator must build the host
  // dependency object by CONDITIONAL key insertion. This arm is what binds that
  // discipline: the host decides presence by ownKeys membership and then
  // requires the value to be a function, so an unconditional
  // {storageRoot, nowFn: providedNowFn, livenessProbeFn: providedLivenessProbeFn}
  // would forward undefined for both and fail construction outright with
  // HOST_DEPENDENCY_INVALID. randomBytesFn is omitted too, consistently with the
  // operations exercised here: no ceremony is minted, so no entropy is drawn.
  withRoot((dir) => {
    const deps = { storageRoot: dir };
    assert.deepEqual(Reflect.ownKeys(deps), ["storageRoot"], "the fixture must omit every optional key");
    assert.ok(!Object.hasOwn(deps, "nowFn"));
    assert.ok(!Object.hasOwn(deps, "livenessProbeFn"));
    assert.ok(!Object.hasOwn(deps, "randomBytesFn"));

    // Construction succeeds: the host received exactly {storageRoot}. Any extra
    // key would have raised HOST_DEPENDENCY_EXTRA, and a present-but-undefined
    // optional would have raised HOST_DEPENDENCY_INVALID.
    const coord = createRecoveryGenesisCoordinator(deps);
    assert.equal(typeof coord, "object");
    assert.ok(Object.isFrozen(coord));

    // Normal lifecycle behaviour under the host's OWN default clock and default
    // liveness probe, neither of which the caller supplied.
    const report = coord.reconcileRestart();
    assert.equal(report.outcome, "NOTHING_TO_RECONCILE");
    assert.equal(report.corruptionCode, null);
    assert.equal(report.journal, null);
    assert.equal(report.state, "READY_ABSENT");

    // status exercises the module's own defaultNowFn, Math.floor(Date.now()/1000).
    // `retained` is null here, so no journal comparison can fire and the real
    // wall clock is safe to use.
    const status = coord.status();
    assert.equal(status.state, "READY_ABSENT");
    assert.equal(status.journal, null);
    assert.equal(status.nextRole, null);
    assert.equal(status.ceremony, null);

    assert.equal(coord.close(), undefined);
    assertCoordError(() => coord.status(), "COORDINATOR_CLOSED");
  });
});

// ===========================================================================
// AT-C7
// ===========================================================================
test("AT-C7: non-mutating sampling through the one shared clock guard", () => {
  const badClocks = [
    ["throwing", () => { throw new Error("clock exploded"); }],
    ["non-number", () => "1700000000"],
    ["non-safe-integer", () => 1.5],
    ["zero", () => 0],
    ["above UINT48_MAX", () => UINT48_MAX + 1]
  ];

  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn });

    // Exactly one sample each, unconditionally.
    let before = clock.calls;
    coord.beginRole();
    assert.equal(clock.calls - before, 2, "beginRole samples coordinator then host");
    coord.cancelRoleCeremony();
    before = clock.calls;
    coord.status();
    assert.equal(clock.calls - before, 1, "status samples exactly once");

    // Byte-identical behaviour across the full guard matrix, from BOTH entry
    // points — the executable proof that one shared helper owns the catch.
    for (const [label, impl] of badClocks) {
      clock.impl = impl;
      try {
        before = clock.calls;
        assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_NOW");
        assert.equal(clock.calls - before, 1, `beginRole/${label} samples exactly once`);
        before = clock.calls;
        assertCoordError(() => coord.status(), "COORDINATOR_INVALID_NOW");
        assert.equal(clock.calls - before, 1, `status/${label} samples exactly once`);
      } finally {
        clock.impl = null;
      }
    }

    // A regressing sample yields the coordinator's regression code, from both.
    clock.value = NOW - 1;
    assertCoordError(() => coord.beginRole(), "COORDINATOR_CLOCK_REGRESSION_DETECTED");
    assertCoordError(() => coord.status(), "COORDINATOR_CLOCK_REGRESSION_DETECTED");
    clock.value = NOW;

    // beginRole still samples exactly once when randomBytesFn throws, proving
    // the sample precedes ceremonyId generation.
    coord.close();
  });

  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, {
      nowFn: clock.fn,
      randomBytesFn: () => { throw new Error("entropy exploded"); }
    });
    const before = clock.calls;
    assertCoordError(() => coord.beginRole(), "COORDINATOR_CEREMONY_ID_GENERATION_FAILED");
    assert.equal(clock.calls - before, 1, "the clock sample precedes ceremonyId generation");
    coord.close();
  });

  // cancelRoleCeremony samples at most once, never throws for any nowFn
  // behaviour, and therefore does not route through the shared helper.
  for (const [label, impl] of badClocks) {
    withRoot((dir) => {
      const clock = makeClock(NOW);
      const coord = stagingCoordinator(dir, { nowFn: clock.fn });
      coord.beginRole();
      clock.impl = impl;
      try {
        const before = clock.calls;
        const result = coord.cancelRoleCeremony();
        assert.ok(clock.calls - before <= 1, `cancelRoleCeremony/${label} samples at most once`);
        assert.equal(result.ceremony, null);
        assert.equal(result.state, "READY_STAGING");
      } finally {
        clock.impl = null;
      }
      coord.close();
    });
  }
});

// ===========================================================================
// AT-C8
// ===========================================================================
test("AT-C8: time- and role-type discipline at both boundaries", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);

    withGateBSpy((gateBCalls) => {
      withPureSpy((pureCalls) => {
        const staged = coord.stageRole(candidate);

        // Every nowUnixSeconds handed to Gate B is a safe-integer number, and
        // on mutation paths equals Number(returned.updatedAtUnixSeconds).
        const clocked = gateBCalls.filter((entry) =>
          entry.args[0] && typeof entry.args[0] === "object" && "nowUnixSeconds" in entry.args[0]);
        assert.ok(clocked.length >= 1);
        for (const entry of clocked) {
          const value = entry.args[0].nowUnixSeconds;
          assert.equal(typeof value, "number");
          assert.ok(Number.isSafeInteger(value));
          assert.equal(value, Number(staged.journal.updatedAtUnixSeconds));
        }

        // The host-boundary value, per §7.2: the 5B-0.4 shim's expectedRole is
        // the very value the coordinator passed to host.stageRole, forwarded
        // unchanged by the host. No host-method spy is used, and none may be.
        const stage = pureCalls.find((entry) => entry.fn === "stageGenesisRoleCandidate");
        const expectedRole = stage.args[1];
        assert.equal(typeof expectedRole, "number");
        assert.equal(expectedRole, 0);
        assert.notEqual(typeof expectedRole, "string");
      });
    });

    // Mint-boundary capture on a fresh ceremony.
    withGateBSpy((gateBCalls) => {
      const next = coord.beginRole();
      const mint = gateBCalls.find((entry) => entry.fn === "mintPhilCoreV2GenesisRoleCeremony");
      assert.ok(mint, "no mint call observed");
      const input = mint.args[0];
      assert.equal(typeof input.role, "bigint");
      assert.equal(input.role, 1n);
      assert.equal(typeof input.intentExpiresAtUnixSeconds, "bigint");
      assert.equal(typeof input.nowUnixSeconds, "number");
      assert.equal(next.role, 1);
      assert.equal(typeof next.role, "number");
      // Both boundaries denote the same member of {0,1,2}.
      assert.equal(Number(input.role), next.role);
      coord.cancelRoleCeremony();
    });
    coord.close();
  });

  // A journal timestamp at UINT48_MAX round-trips exactly.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const real = pureJournalReal.createGenesisStagingJournal;
    const coord = newCoordinator(dir, { nowFn: clock.fn });
    coord.reconcileRestart();
    withPureReplaced(
      "createGenesisStagingJournal",
      (...args) => Object.assign({}, real(...args), { updatedAtUnixSeconds: String(UINT48_MAX) }),
      () => { coord.createJournal(validIntent()); }
    );
    clock.value = UINT48_MAX;
    const status = coord.status();
    assert.equal(status.journal.updatedAtUnixSeconds, String(UINT48_MAX));
    assert.equal(status.state, "READY_STAGING");
    coord.close();
  });

  // "9" vs "10" is ordered numerically, never lexicographically.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const real = pureJournalReal.createGenesisStagingJournal;
    const coord = newCoordinator(dir, { nowFn: clock.fn });
    coord.reconcileRestart();
    withPureReplaced(
      "createGenesisStagingJournal",
      (...args) => Object.assign({}, real(...args), { updatedAtUnixSeconds: "9" }),
      () => { coord.createJournal(validIntent()); }
    );
    clock.value = 10;
    // Lexicographically "10" < "9"; numerically 10 > 9, so this must not raise.
    const status = coord.status();
    assert.equal(status.journal.updatedAtUnixSeconds, "9");
    coord.close();
  });
});

// ===========================================================================
// AT-C9
// ===========================================================================
test("AT-C9: terminal-on-success reports staged:false and disposes via observeStatus, never consume", () => {
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn }, { expiresAt: String(NOW + 100) });
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);

    clock.value = NOW + 200;
    const result = withGateBSpy((calls) => {
      const staged = coord.stageRole(candidate);
      assert.equal(countCalls(calls, "observePhilCoreV2GenesisRoleCeremonyStatus"), 1);
      assert.equal(countCalls(calls, "consumePhilCoreV2GenesisRoleCeremony"), 0);
      return staged;
    });

    assert.equal(result.staged, false);
    assert.equal(result.state, "ORPHAN_CREDENTIAL_BLOCKED");
    assert.equal(result.obligation.state, "ORPHANED");
    assert.equal(result.ceremony, null);
    assert.equal(result.journal.state, "EXPIRED");
    assert.equal(result.journal.manifest["0"], null);
    assert.equal(result.journal.manifest["1"], null);
    assert.equal(result.journal.manifest["2"], null);
    assert.equal(result.role, 0, "the role is not advanced");
    assert.equal(coord.status().nextRole, null);
    coord.close();
  });
});

// ===========================================================================
// AT-C10
// ===========================================================================
test("AT-C10: cancelEnrollment disposition from all three permitted starting states", () => {
  // READY_STAGING — no ceremony.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    assert.equal(coord.status().state, "READY_STAGING");
    const result = withPureSpy((calls) => {
      const cancelled = coord.cancelEnrollment();
      assert.equal(countCalls(calls, "cancelGenesisStagingJournal"), 1);
      return cancelled;
    });
    assert.equal(result.ceremony, null);
    assert.equal(result.state, "READY_TERMINAL");
    assert.equal(result.obligation, null);
    assert.ok(["CANCELLED", "EXPIRED"].includes(result.journal.state));
    assert.equal(result.journal.state, "CANCELLED");
    coord.close();
  });

  // ROLE_CEREMONY_ACTIVE — consume is never called, and a forced Gate-B throw
  // during disposition does not prevent success.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    assert.equal(coord.status().state, "ROLE_CEREMONY_ACTIVE");
    const result = withPureSpy((pureCalls) => withGateBSpy((gateBCalls) => {
      const cancelled = coord.cancelEnrollment();
      assert.equal(countCalls(pureCalls, "cancelGenesisStagingJournal"), 1);
      assert.equal(countCalls(gateBCalls, "consumePhilCoreV2GenesisRoleCeremony"), 0);
      assert.equal(countCalls(gateBCalls, "observePhilCoreV2GenesisRoleCeremonyStatus"), 1);
      return cancelled;
    }));
    assert.equal(result.ceremony, null);
    assert.equal(result.state, "READY_TERMINAL");
    assert.equal(result.obligation, null);
    coord.close();
  });
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    const result = withGateBReplaced(
      "observePhilCoreV2GenesisRoleCeremonyStatus",
      () => { throw new Error("observe exploded"); },
      () => coord.cancelEnrollment()
    );
    assert.equal(result.ceremony, null);
    assert.equal(result.state, "READY_TERMINAL");
    coord.close();
  });

  // READY_FOR_PROFILE_VALIDATION — full manifest, no ceremony.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    fillAllRoles(coord);
    assert.equal(coord.status().state, "READY_FOR_PROFILE_VALIDATION");
    const result = withPureSpy((calls) => {
      const cancelled = coord.cancelEnrollment();
      assert.equal(countCalls(calls, "cancelGenesisStagingJournal"), 1);
      return cancelled;
    });
    assert.equal(result.ceremony, null);
    assert.equal(result.state, "READY_TERMINAL");
    coord.close();
  });

  // An EXPIRED journal is reported faithfully by the same call.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn }, { expiresAt: String(NOW + 100) });
    clock.value = NOW + 500;
    const result = coord.cancelEnrollment();
    assert.equal(result.journal.state, "EXPIRED");
    assert.equal(result.state, "READY_TERMINAL");
    coord.close();
  });
});

// ===========================================================================
// AT-C11
// ===========================================================================
test("AT-C11: host-first precedence — the durable journal EXPIRED transition wins", () => {
  const coordinatorOutcome = withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn }, { expiresAt: String(NOW + 100) });
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);
    // Past BOTH the ceremony expiry (NOW+100) and the journal expiry (NOW+100).
    clock.value = NOW + 1000;
    const result = coord.stageRole(candidate);
    assert.equal(result.staged, false);
    assert.equal(result.journal.state, "EXPIRED");
    assert.equal(result.journal.endReason, "EXPIRED");
    assert.equal(result.state, "ORPHAN_CREDENTIAL_BLOCKED");
    assert.equal(result.obligation.state, "ORPHANED");
    coord.close();
    return { state: result.journal.state, endReason: result.journal.endReason };
  });

  // The bare host / pure layer produces the same durable outcome (channel 2/3),
  // so the coordinator neither pre-empted nor converted it.
  const bareOutcome = withRoot((dir) => {
    const host = createRecoveryGenesisStagingHost({
      storageRoot: dir, nowFn: () => NOW, livenessProbeFn: () => "DEAD"
    });
    host.reconcileRestart();
    const journal = host.createJournal(validIntent({ expiresAt: String(NOW + 100) })).journal;
    const minted = gateBShim.mintPhilCoreV2GenesisRoleCeremony({
      current: null,
      ceremonyId: `0x${"cd".repeat(32)}`,
      role: 0n,
      genesisDeploymentIntentHash: journal.genesisDeploymentIntentHash,
      intentExpiresAtUnixSeconds: BigInt(journal.expiresAt),
      nowUnixSeconds: NOW
    });
    const projection = gateBShim.toPhilCoreV2GenesisRoleCeremonyHashInput(minted);
    const roleInput = Object.assign({}, candidateFor(minted, 0), { currentRoleCeremony: projection });
    const staged = pureJournalShim.stageGenesisRoleCandidate(journal, 0, roleInput, NOW + 1000);
    host.close();
    return { state: staged.state, endReason: staged.endReason };
  });

  assert.deepEqual(coordinatorOutcome, bareOutcome);
});

// ===========================================================================
// AT-C12
// ===========================================================================
test("AT-C12: error identity outside the two absorption boundaries", () => {
  // A pure 5B-0.4 error reaching Phase D propagates as the identical object.
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    const sentinel = { code: "PURE_SENTINEL", detail: { commitState: "NOT_COMMITTED" } };
    withPureReplaced("createGenesisStagingJournal", () => { throw sentinel; }, () => {
      const thrown = captureThrow(() => coord.createJournal(validIntent()));
      assert.equal(thrown, sentinel, "the pure error was not rethrown by identity");
    });
    // Genuine 5B-0.4 validation errors are not rewritten either.
    const real = captureThrow(() => coord.createJournal({ nonsense: true }));
    assert.ok(!(real instanceof PhilCoreV2RecoveryGenesisCoordinatorError));
    coord.close();
  });

  // A host error reaching Phase D propagates as the identical object.
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    coord.createJournal(validIntent());
    fs.unlinkSync(path.join(stagingDir(dir), ".staging.lock"));
    const thrown = captureThrow(() => coord.cancelEnrollment());
    assert.ok(thrown instanceof HostError);
    assert.equal(thrown.code, "HOST_LOCK_LOST_OR_REPLACED");
    assert.ok(!(thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError));
  });

  // A Gate-B mint error from beginRole (Phase P) propagates by identity.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const sentinel = { gateB: "mint" };
    withGateBReplaced("mintPhilCoreV2GenesisRoleCeremony", () => { throw sentinel; }, () => {
      const thrown = captureThrow(() => coord.beginRole());
      assert.equal(thrown, sentinel);
    });
    // Nothing was mutated: the slot is still null and a retry succeeds.
    assert.equal(coord.status().ceremony, null);
    assert.equal(coord.beginRole().ceremony.state, "ACTIVE");
    coord.close();
  });

  // A Gate-B observe error from status propagates by identity, and status
  // swallows nothing: with retire forced to throw, a status that ENDS the
  // ceremony still returns, because status invokes retire ZERO times.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn });
    coord.beginRole();
    const sentinel = { gateB: "observe" };
    withGateBReplaced("observePhilCoreV2GenesisRoleCeremonyStatus", () => { throw sentinel; }, () => {
      const thrown = captureThrow(() => coord.status());
      assert.equal(thrown, sentinel);
    });
    // The slot was left ACTIVE and unmodified by the failed observation.
    assert.equal(coord.status().state, "ROLE_CEREMONY_ACTIVE");

    clock.value = NOW + 100000;   // past the ceremony's TTL expiry
    withGateBReplaced("retirePhilCoreV2GenesisRoleCeremony", () => {
      throw new Error("retire must never be called from status");
    }, () => {
      const observed = withGateBSpy((calls) => {
        const result = coord.status();
        assert.equal(countCalls(calls, "retirePhilCoreV2GenesisRoleCeremony"), 0);
        return result;
      });
      assert.equal(observed.ceremony, null);
      assert.equal(observed.state, "READY_STAGING");
    });
    coord.close();
  });
});

// ===========================================================================
// AT-C13
// ===========================================================================
test("AT-C13: the poison rule, including the missing-detail case", () => {
  const hostError = (code, commitState) => new HostError(code, {
    commitState,
    operation: "createJournal",
    phase: "TEST",
    primaryCode: null,
    subject: null
  });
  const arms = [
    [hostError("HOST_FILESYSTEM_MUTATION_FAILED", "INDETERMINATE"), true],
    [hostError("HOST_DESCRIPTOR_CLOSE_FAILED", "COMMITTED"), true],
    [hostError("HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID", "SUPERSESSION_INDETERMINATE"), true],
    [hostError("HOST_CLOCK_REGRESSION_DETECTED", "PROFILE_COMMITTED"), false],
    [hostError("HOST_FILESYSTEM_MUTATION_FAILED", "NOT_COMMITTED"), false],
    [hostError("HOST_INVALID_NOW", "NOT_APPLICABLE"), false],
    [{ code: "F", detail: { commitState: "INDETERMINATE" } }, false],
    ["a primitive throw", false],
    [hostError("HOST_PROCESS_POISONED", "NOT_APPLICABLE"), true],
    [hostError("HOST_FINALIZED_PROFILE_CONFLICT", "PROFILE_COMMITTED"), true],
    [hostError("HOST_UNEXPECTED_FINALIZED_PROFILE_ENTRY", "NOT_APPLICABLE"), true],
    [hostError("HOST_MULTIPLE_FINALIZED_PROFILES_FOUND", "NOT_APPLICABLE"), true]
  ];

  for (const [sentinel, shouldPoison] of arms) {
    withRoot((dir) => {
      const coord = newCoordinator(dir);
      coord.reconcileRestart();
      withPureReplaced("createGenesisStagingJournal", () => { throw sentinel; }, () => {
        const thrown = captureThrow(() => coord.createJournal(validIntent()));
        assert.equal(thrown, sentinel, "poison classification must not disturb identity");
      });
      if (shouldPoison) {
        assertCoordError(() => coord.status(), "COORDINATOR_POISONED");
        assertCoordError(() => coord.reconcileRestart(), "COORDINATOR_POISONED");
        assertCoordError(() => coord.close(), "COORDINATOR_POISONED");
      } else {
        // Not poisoned, the detail read did not throw, and state is unchanged.
        assert.equal(coord.status().state, "READY_ABSENT");
        coord.createJournal(validIntent());
        assert.equal(coord.status().state, "READY_STAGING");
        coord.close();
      }
    });
  }

  let traps = 0;
  const hostile = new Proxy({}, {
    get() { traps += 1; throw new Error("get trap"); },
    getPrototypeOf() { traps += 1; throw new Error("prototype trap"); },
    getOwnPropertyDescriptor() { traps += 1; throw new Error("descriptor trap"); }
  });
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    withPureReplaced("createGenesisStagingJournal", () => { throw hostile; }, () => {
      assert.equal(captureThrow(() => coord.createJournal(validIntent())), hostile);
    });
    assert.equal(coord.status().state, "READY_ABSENT");
    coord.close();
  });
  assert.equal(traps, 0, "raw thrown proxies must remain entirely unread");
});

// ===========================================================================
// AT-C14
// ===========================================================================
test("AT-C14: close() — normal, idempotent, throwing-poisons, and never re-entered", () => {
  // Normal close.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    assert.equal(coord.close(), undefined);
    assertCoordError(() => coord.status(), "COORDINATOR_CLOSED");
    assert.equal(coord.close(), undefined, "close is idempotent");
    assertCoordError(() => coord.reconcileRestart(), "COORDINATOR_CLOSED");
  });

  // Zero clock samples and zero Gate-B operations across the whole of close(),
  // with a ceremony retained and discarded.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn });
    coord.beginRole();
    const before = clock.calls;
    withGateBSpy((calls) => {
      coord.close();
      assert.equal(calls.length, 0, "close invoked a Gate-B operation");
    });
    assert.equal(clock.calls - before, 0, "close sampled the clock");
  });

  // Throwing close: POISONED, the same host error object rethrown, and
  // host.close() is NOT re-entered — proven per §7.2 without a host spy.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    fs.unlinkSync(path.join(stagingDir(dir), ".staging.lock"));
    const thrown = captureThrow(() => coord.close());
    assert.ok(thrown instanceof HostError, "close must rethrow the host's own error object");
    assert.equal(thrown.code, "HOST_LOCK_LOST_OR_REPLACED");
    assert.ok(!(thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError));

    // A re-entry would either return (yielding CLOSED) or throw a host-coded
    // error; both are excluded by a coordinator error carrying POISONED.
    const second = assertCoordError(() => coord.close(), "COORDINATOR_POISONED");
    assert.ok(!(second instanceof HostError));
    assertCoordError(() => coord.status(), "COORDINATOR_POISONED");
  });

  // The same holds for a coordinator poisoned by a mutating method.
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    poisonCoordinator(coord);
    const thrown = assertCoordError(() => coord.close(), "COORDINATOR_POISONED");
    assert.ok(!(thrown instanceof HostError), "a poisoned coordinator must never reach host.close()");
  });

  // From FINALIZED — zero clock samples, zero Gate-B operations, lock released.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = profileReadyCoordinator(dir, { nowFn: clock.fn });
    const expected = expectedValidationFor(coord);
    coord.finalizeProfile(expected);
    assert.equal(coord.status().state, "FINALIZED");
    const before = clock.calls;
    withGateBSpy((calls) => {
      coord.close();
      assert.equal(calls.length, 0, "close invoked a Gate-B operation from FINALIZED");
    });
    assert.equal(clock.calls - before, 0, "close sampled the clock from FINALIZED");
    assertCoordError(() => coord.status(), "COORDINATOR_CLOSED");
  });
});

// ===========================================================================
// AT-C15
// ===========================================================================
test("AT-C15: constructor poison — no coordinator object and no POISONED instance", () => {
  withRoot((dir) => {
    poisonRoot(dir);
    let produced = null;
    const thrown = captureThrow(() => {
      produced = createRecoveryGenesisCoordinator(baseDeps(dir));
    });
    assert.equal(produced, null, "no coordinator object may be produced");
    assert.ok(thrown instanceof HostError);
    assert.equal(thrown.code, "HOST_PROCESS_POISONED");
    assert.ok(!(thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError),
      "construction-time poison is a constructor failure, not a coordinator state");
  });
});

// ===========================================================================
// AT-C16
// ===========================================================================
test("AT-C16: UNRECONCILED outranks derivation, and HOST_RECONCILIATION_REQUIRED is masked", () => {
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    assert.equal(coord.status().state, "UNRECONCILED");
    assert.notEqual(coord.status().state, "READY_ABSENT");
    assert.equal(coord.status().journal, null);
    assert.equal(coord.status().nextRole, null);
    assert.equal(coord.status().ceremony, null);

    const attempts = [
      ["createJournal", () => coord.createJournal(validIntent())],
      ["beginRole", () => coord.beginRole()],
      ["authorizeCredentialCreation", () => coord.authorizeCredentialCreation()],
      ["recordCreatedCredential", () => coord.recordCreatedCredential({
        credentialIdHash: `0x${"11".repeat(32)}`,
        publicVerificationMaterialHash: `0x${"22".repeat(32)}`
      })],
      ["stageRole", () => coord.stageRole({ descriptor: {}, independence: {} })],
      ["cancelRoleCeremony", () => coord.cancelRoleCeremony()],
      ["cancelEnrollment", () => coord.cancelEnrollment()],
      ["finalizeProfile", () => coord.finalizeProfile({})],
      ["acknowledgeTerminal", () => coord.acknowledgeTerminal()]
    ];

    withPureSpy((calls) => {
      for (const [, attempt] of attempts) {
        const thrown = assertCoordError(attempt, "COORDINATOR_INVALID_STATE");
        // HOST_RECONCILIATION_REQUIRED is never observed at the boundary.
        assert.notEqual(thrown.code, "HOST_RECONCILIATION_REQUIRED");
        assert.ok(!(thrown instanceof HostError));
      }
      // Zero host calls, per §7.2: the 5B-0.4 shim saw nothing. For
      // acknowledgeTerminal — invisible to the shim — the decisive evidence is
      // the absence of HOST_RECONCILIATION_REQUIRED, which every host method
      // except close raises first when unreconciled.
      assert.equal(calls.length, 0);
    });

    // The masking is real: a bare host in the same condition does raise it.
    const bareThrow = withRoot((otherDir) => {
      const host = createRecoveryGenesisStagingHost(baseDeps(otherDir));
      const error = captureThrow(() => host.acknowledgeTerminal({
        intentId: `0x${"11".repeat(32)}`, integrityChecksum: `0x${"22".repeat(32)}`
      }));
      host.close();
      return error;
    });
    assert.equal(bareThrow.code, "HOST_RECONCILIATION_REQUIRED");

    coord.close();
  });
});

// ===========================================================================
// AT-C17
// ===========================================================================
test("AT-C17: ceremony-slot invariant and no ceremony end-reason leakage", () => {
  const assertCeremonyValid = (value, label) => {
    if (value === null) return;
    assert.equal(value.state, "ACTIVE", `${label}: only null or ACTIVE may surface`);
    assert.equal(value.endReason, null, `${label}: an ACTIVE ceremony carries no end reason`);
  };
  const assertNoTopLevelEndReason = (result, label) => {
    for (const key of Object.keys(result)) {
      if (key === "journal") continue;
      const value = result[key];
      if (value === null || typeof value !== "object") continue;
      assert.ok(!("endReason" in value) || value.endReason === null,
        `${label}.${key}: a coordinator return key exposes an end reason`);
    }
    assert.ok(!("endReason" in result), `${label}: top-level endReason key`);
  };

  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = newCoordinator(dir, { nowFn: clock.fn });
    const results = [];
    results.push(["reconcileRestart", coord.reconcileRestart()]);
    results.push(["status/absent", coord.status()]);
    results.push(["createJournal", coord.createJournal(validIntent())]);
    const begun = coord.beginRole();
    results.push(["beginRole", begun]);
    results.push(["status/active", coord.status()]);
    results.push(["cancelRoleCeremony", coord.cancelRoleCeremony()]);
    const begun2 = coord.beginRole();
    results.push(["beginRole/2", begun2]);
    results.push(["stageRole", coord.stageRole(recordRole(coord, begun2))]);
    results.push(["status/staged", coord.status()]);
    results.push(["cancelEnrollment", coord.cancelEnrollment()]);
    results.push(["status/terminal", coord.status()]);
    results.push(["acknowledgeTerminal", coord.acknowledgeTerminal()]);
    results.push(["status/final", coord.status()]);

    for (const [label, result] of results) {
      if ("ceremony" in result) assertCeremonyValid(result.ceremony, label);
      assertNoTopLevelEndReason(result, label);
    }

    // journal.endReason is expressly permitted and expected on terminal journals.
    const terminal = results.find(([label]) => label === "cancelEnrollment")[1];
    assert.ok("endReason" in terminal.journal);
    assert.equal(terminal.journal.endReason, "CANCELLED");
    coord.close();
  });

  // A status that ENDS the ceremony surfaces null, never an ENDED record.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn });
    coord.beginRole();
    clock.value = NOW + 100000;
    const observed = coord.status();
    assert.equal(observed.ceremony, null);
    // close also discards without surfacing anything.
    coord.close();
  });
});

// ===========================================================================
// AT-C18
// ===========================================================================
test("AT-C18: status availability and its exact Gate-B call profile", () => {
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = newCoordinator(dir, { nowFn: clock.fn });

    // UNRECONCILED — success here is also the §7.2.2 proof that host.status()
    // was never invoked: host.status() calls requireReconciled first and would
    // have raised HOST_RECONCILIATION_REQUIRED.
    assert.equal(coord.status().state, "UNRECONCILED");
    coord.reconcileRestart();
    assert.equal(coord.status().state, "READY_ABSENT");
    coord.createJournal(validIntent());
    assert.equal(coord.status().state, "READY_STAGING");

    const begun = coord.beginRole();
    const observedActive = withGateBSpy((calls) => {
      const result = coord.status();
      assert.equal(countCalls(calls, "observePhilCoreV2GenesisRoleCeremonyStatus"), 1);
      // Every other Gate-B function, with no exemptions. The seam intercepts
      // only calls made THROUGH the namespace object, which is exactly the set
      // the coordinator makes; Gate B's own internal use of
      // validatePhilCoreV2GenesisRoleCeremonyRecord resolves lexically inside
      // the .ts module and is therefore not counted here.
      for (const name of GATE_B_FUNCTION_NAMES) {
        if (name === "observePhilCoreV2GenesisRoleCeremonyStatus") continue;
        assert.equal(countCalls(calls, name), 0, `${name} must not be called by status`);
      }
      return result;
    });
    assert.equal(observedActive.state, "ROLE_CEREMONY_ACTIVE");
    assert.equal(observedActive.ceremony.state, "ACTIVE");

    // It advances lastObservedAtUnixSeconds while leaving the ceremony ACTIVE.
    clock.value = NOW + 10;
    const advanced = coord.status();
    assert.equal(advanced.ceremony.state, "ACTIVE");
    assert.equal(advanced.ceremony.lastObservedAtUnixSeconds, BigInt(NOW + 10));
    assert.ok(advanced.ceremony.lastObservedAtUnixSeconds > begun.ceremony.lastObservedAtUnixSeconds);

    // An observation that ENDS the ceremony: observeStatus once, retire zero,
    // and ceremony === null carried by the direct discard alone.
    clock.value = NOW + 100000;
    const ended = withGateBSpy((calls) => {
      const result = coord.status();
      assert.equal(countCalls(calls, "observePhilCoreV2GenesisRoleCeremonyStatus"), 1);
      assert.equal(countCalls(calls, "retirePhilCoreV2GenesisRoleCeremony"), 0);
      return result;
    });
    assert.equal(ended.ceremony, null);

    clock.value = NOW + 100000;
    fillAllRoles(coord);
    assert.equal(coord.status().state, "READY_FOR_PROFILE_VALIDATION");
    coord.cancelEnrollment();
    assert.equal(coord.status().state, "READY_TERMINAL");
    coord.close();
    assertCoordError(() => coord.status(), "COORDINATOR_CLOSED");
  });

  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    poisonCoordinator(coord);
    assertCoordError(() => coord.status(), "COORDINATOR_POISONED");
  });
});

// ===========================================================================
// AT-C19
// ===========================================================================
test("AT-C19: full-manifest exit completes end to end", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    fillAllRoles(coord);
    assert.equal(coord.status().state, "READY_FOR_PROFILE_VALIDATION");
    assert.equal(coord.status().nextRole, null);

    const cancelled = coord.cancelEnrollment();
    assert.equal(cancelled.state, "READY_TERMINAL");
    assert.equal(cancelled.ceremony, null);

    const acknowledged = coord.acknowledgeTerminal();
    assert.equal(acknowledged.state, "READY_ABSENT");
    assert.equal(acknowledged.acknowledged, true);
    assert.equal(coord.status().state, "READY_ABSENT");
    assert.equal(coord.status().journal, null);
    coord.close();
  });
});

// ===========================================================================
// AT-C20
// ===========================================================================
test("AT-C20: beginRole rejections, the exact mint input, and the guarded ceremonyId contract", () => {
  // All seven states.
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");          // UNRECONCILED
    coord.reconcileRestart();
    assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");          // READY_ABSENT
    coord.createJournal(validIntent());
    const begun = coord.beginRole();                                                 // READY_STAGING ok
    assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");          // ROLE_CEREMONY_ACTIVE
    coord.stageRole(recordRole(coord, begun));
    stageOneRole(coord, 1);
    stageOneRole(coord, 2);
    assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");          // READY_FOR_PROFILE_VALIDATION
    coord.cancelEnrollment();
    assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");          // READY_TERMINAL
    coord.close();
    assertCoordError(() => coord.beginRole(), "COORDINATOR_CLOSED");                 // CLOSED
  });
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    poisonCoordinator(coord);
    assertCoordError(() => coord.beginRole(), "COORDINATOR_POISONED");               // POISONED
  });

  // The exact six-key mint input, captured through the §7.1 Gate-B shim.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    withGateBSpy((calls) => {
      const begun = coord.beginRole();
      const mint = calls.find((entry) => entry.fn === "mintPhilCoreV2GenesisRoleCeremony");
      const input = mint.args[0];
      assert.deepEqual(Object.keys(input), [
        "current", "ceremonyId", "role", "genesisDeploymentIntentHash",
        "intentExpiresAtUnixSeconds", "nowUnixSeconds"
      ]);
      assert.equal(input.current, null);
      assert.equal(Object.getOwnPropertySymbols(input).length, 0);
      assert.match(input.ceremonyId, /^0x[0-9a-f]{64}$/u);
      assert.equal(begun.ceremony.ceremonyId, input.ceremonyId);
    });
    coord.close();
  });

  // ceremonyId derives from the 32 bytes randomBytesFn returned.
  withRoot((dir) => {
    const bytes = Buffer.from("5a".repeat(32), "hex");
    const coord = stagingCoordinator(dir, { randomBytesFn: (size) => {
      assert.equal(size, 32);
      return bytes;
    } });
    const begun = coord.beginRole();
    assert.equal(begun.ceremony.ceremonyId, `0x${"5a".repeat(32)}`);
    assert.match(begun.ceremony.ceremonyId, /^0x[0-9a-f]{64}$/u);
    coord.close();
  });

  // The exhaustive rejection set, with no raw value surfaced on the error.
  const rejections = [
    ["throws", () => { throw new Error("nope"); }],
    ["31 bytes", () => Buffer.alloc(31)],
    ["33 bytes", () => Buffer.alloc(33)],
    ["string", () => "a".repeat(64)],
    ["plain object with length", () => ({ length: 32 })],
    ["null", () => null],
    ["undefined", () => undefined],
    ["number", () => 32],
    ["array", () => new Array(32).fill(0)]
  ];
  for (const [label, randomBytesFn] of rejections) {
    withRoot((dir) => {
      const coord = stagingCoordinator(dir, { randomBytesFn });
      const thrown = assertCoordError(() => coord.beginRole(), "COORDINATOR_CEREMONY_ID_GENERATION_FAILED");
      assert.ok(!("cause" in thrown), `${label}: the error must carry no cause`);
      coord.close();
    });
  }

  // Three mandatory hostile-Proxy arms. An unguarded touch of the result would
  // leak a raw caller-controlled value (§5.3.2).
  const assertNoSentinelRetained = (error, sentinel, label) => {
    assert.notEqual(error, sentinel, `${label}: the sentinel was rethrown by identity`);
    assert.ok(error instanceof PhilCoreV2RecoveryGenesisCoordinatorError, `${label}: not a coordinator error`);
    assert.equal(error.code, "COORDINATOR_CEREMONY_ID_GENERATION_FAILED");
    assert.ok(!("cause" in error), `${label}: cause present`);
    const seen = new Set();
    const walk = (value, depth) => {
      if (depth > 6 || value === null) return;
      if (typeof value !== "object" && typeof value !== "function") return;
      if (seen.has(value)) return;
      seen.add(value);
      assert.notEqual(value, sentinel, `${label}: the sentinel is retained on the error`);
      for (const key of Object.getOwnPropertyNames(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !("value" in descriptor)) continue;
        walk(descriptor.value, depth + 1);
      }
    };
    walk(error, 0);
  };

  // (i) a revoked Proxy — `instanceof` throws a raw TypeError unguarded.
  withRoot((dir) => {
    const revocable = Proxy.revocable(new Uint8Array(32), {});
    revocable.revoke();
    const coord = stagingCoordinator(dir, { randomBytesFn: () => revocable.proxy });
    const thrown = assertCoordError(() => coord.beginRole(), "COORDINATOR_CEREMONY_ID_GENERATION_FAILED");
    assert.ok(!(thrown instanceof TypeError));
    assert.notEqual(thrown, revocable.proxy);
    assertNoSentinelRetained(thrown, revocable.proxy, "revoked Proxy");
    coord.close();
  });

  // (ii) a getPrototypeOf trap that throws a captured sentinel.
  withRoot((dir) => {
    const sentinel = { sentinel: "getPrototypeOf" };
    const hostile = new Proxy(new Uint8Array(32), {
      getPrototypeOf() { throw sentinel; }
    });
    const coord = stagingCoordinator(dir, { randomBytesFn: () => hostile });
    const thrown = assertCoordError(() => coord.beginRole(), "COORDINATOR_CEREMONY_ID_GENERATION_FAILED");
    assertNoSentinelRetained(thrown, sentinel, "throwing getPrototypeOf");
    coord.close();
  });

  // (iii) a get trap that throws a captured sentinel for `length` — the second
  // caller-controlled touch inside the same guard.
  withRoot((dir) => {
    const sentinel = { sentinel: "length" };
    const hostile = new Proxy(new Uint8Array(32), {
      get(target, key, receiver) {
        if (key === "length") throw sentinel;
        return Reflect.get(target, key, target);
      }
    });
    const coord = stagingCoordinator(dir, { randomBytesFn: () => hostile });
    const thrown = assertCoordError(() => coord.beginRole(), "COORDINATOR_CEREMONY_ID_GENERATION_FAILED");
    assertNoSentinelRetained(thrown, sentinel, "throwing length accessor");
    coord.close();
  });
});

// ===========================================================================
// AT-C21
// ===========================================================================
test("AT-C21: restart derivation after a durable stageRole", () => {
  withRoot((dir) => {
    const first = stagingCoordinator(dir);
    stageOneRole(first, 0);
    first.close();

    const second = newCoordinator(dir);
    const report = second.reconcileRestart();
    assert.equal(report.outcome, "ACTIVE");
    assert.equal(report.corruptionCode, null);
    assert.equal(report.journal.state, "STAGING");
    const status = second.status();
    assert.equal(status.state, "READY_STAGING");
    assert.equal(status.nextRole, 1);
    assert.equal(typeof status.nextRole, "number");
    assert.equal(status.ceremony, null);

    // stageRole before beginRole is rejected.
    assertCoordError(
      () => second.stageRole({ descriptor: {}, independence: {} }),
      "COORDINATOR_INVALID_STATE"
    );
    second.close();
  });
});

// ===========================================================================
// AT-C22
// ===========================================================================
test("AT-C22: non-replay from READY_TERMINAL", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    stageOneRole(coord, 0);
    coord.cancelEnrollment();
    assert.equal(coord.status().state, "READY_TERMINAL");

    assertCoordError(
      () => coord.stageRole({ descriptor: {}, independence: {} }),
      "COORDINATOR_INVALID_STATE"
    );
    assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");
    assertCoordError(() => coord.cancelEnrollment(), "COORDINATOR_INVALID_STATE");
    assertCoordError(() => coord.cancelRoleCeremony(), "COORDINATOR_INVALID_STATE");
    assertCoordError(() => coord.createJournal(validIntent()), "COORDINATOR_INVALID_STATE");
    assertCoordError(() => coord.reconcileRestart(), "COORDINATOR_ALREADY_RECONCILED");

    // Only acknowledgeTerminal and close proceed.
    assert.equal(coord.acknowledgeTerminal().state, "READY_ABSENT");
    assert.equal(coord.close(), undefined);
  });
});

// ===========================================================================
// AT-C23
// ===========================================================================
test("AT-C23: a second coordinator on the same root fails in its constructor with HOST_LOCK_HELD", () => {
  withRoot((dir) => {
    const first = createRecoveryGenesisCoordinator({
      storageRoot: dir, nowFn: () => NOW, livenessProbeFn: () => "LIVE"
    });
    let second = null;
    const thrown = captureThrow(() => {
      second = createRecoveryGenesisCoordinator({
        storageRoot: dir, nowFn: () => NOW, livenessProbeFn: () => "LIVE"
      });
    });
    assert.equal(second, null);
    assert.ok(thrown instanceof HostError);
    assert.equal(thrown.code, "HOST_LOCK_HELD");
    assert.ok(!(thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError));
    first.close();
  });
});

// ===========================================================================
// AT-C24
// ===========================================================================
test("AT-C24: acknowledgeTerminal takes no arguments and is proven by host validation", () => {
  // The four negative arms, driven against a test-owned host on its own root
  // (§5.1 channel 2), demonstrating that the host's rejection surface is real.
  withRoot((dir) => {
    const host = createRecoveryGenesisStagingHost(baseDeps(dir));
    host.reconcileRestart();
    const journal = host.createJournal(validIntent()).journal;
    const terminal = host.cancel().journal;
    assert.notEqual(terminal.state, "STAGING");
    const good = { intentId: terminal.intentId, integrityChecksum: terminal.integrityChecksum };

    const extra = captureThrow(() => host.acknowledgeTerminal(
      Object.assign({}, good, { extra: 1 })
    ));
    assert.equal(extra.code, "HOST_ACKNOWLEDGMENT_INPUT_EXTRA_KEY");

    const missing = captureThrow(() => host.acknowledgeTerminal({ intentId: good.intentId }));
    assert.equal(missing.code, "HOST_ACKNOWLEDGMENT_INPUT_MISSING_KEY");

    const identity = captureThrow(() => host.acknowledgeTerminal(
      Object.assign({}, good, { intentId: `0x${"99".repeat(32)}` })
    ));
    assert.equal(identity.code, "HOST_ACKNOWLEDGMENT_IDENTITY_MISMATCH");

    const checksum = captureThrow(() => host.acknowledgeTerminal(
      Object.assign({}, good, { integrityChecksum: `0x${"98".repeat(32)}` })
    ));
    assert.equal(checksum.code, "HOST_ACKNOWLEDGMENT_CHECKSUM_MISMATCH");

    // The positive arm on the same surface.
    assert.deepEqual(host.acknowledgeTerminal(good), { acknowledged: true });
    host.close();
    void journal;
  });

  // The coordinator's own positive arm: no arguments, after a restart into
  // READY_TERMINAL using only the Gate-A-supplied record. Because the four
  // negative arms above prove the host rejects every deviation, this success is
  // evidence — not assumption — that the acknowledgment object's own keys were
  // exactly ["intentId","integrityChecksum"] with the retained values.
  withRoot((dir) => {
    const first = stagingCoordinator(dir);
    first.cancelEnrollment();
    first.close();

    const second = newCoordinator(dir);
    const report = second.reconcileRestart();
    assert.equal(second.status().state, "READY_TERMINAL");

    // The retained record is the very deep-frozen record the host returned.
    assert.equal(second.status().journal, report.journal);
    assertDeepFrozen(report.journal, "retained journal");

    assert.equal(second.acknowledgeTerminal.length, 0, "acknowledgeTerminal takes no arguments");
    const acknowledged = second.acknowledgeTerminal();
    assert.equal(acknowledged.acknowledged, true);
    assert.equal(acknowledged.state, "READY_ABSENT");
    second.close();
  });
});

// ===========================================================================
// AT-C25
// ===========================================================================
test("AT-C25: error-code closure over the frozen 19-code table", () => {
  assert.deepEqual(Object.keys(CODE).sort(), EXPECTED_CODES.slice().sort());
  assert.equal(Object.keys(CODE).length, 19);
  assert.ok(Object.isFrozen(CODE));
  for (const key of Object.keys(CODE)) assert.equal(CODE[key], key);

  const reached = new Set();
  const reach = (fn, code) => { reached.add(assertCoordError(fn, code).code); };

  // The six constructor-only dependency codes.
  withRoot((dir) => {
    reach(() => createRecoveryGenesisCoordinator(null), "COORDINATOR_DEPENDENCIES_NOT_OBJECT");
    reach(() => createRecoveryGenesisCoordinator(new Proxy({}, {
      ownKeys() { throw new Error("enumeration exploded"); }
    })), "COORDINATOR_DEPENDENCY_ENUMERATION_FAILED");
    reach(() => createRecoveryGenesisCoordinator({ storageRoot: dir, bogus: 1 }),
      "COORDINATOR_DEPENDENCY_EXTRA");
    reach(() => createRecoveryGenesisCoordinator({}), "COORDINATOR_DEPENDENCY_MISSING");
    reach(() => createRecoveryGenesisCoordinator({ storageRoot: 5 }),
      "COORDINATOR_DEPENDENCY_INVALID");
    reach(() => createRecoveryGenesisCoordinator(new Proxy({ storageRoot: dir }, {
      get() { throw new Error("read exploded"); }
    })), "COORDINATOR_DEPENDENCY_READ_FAILED");
  });

  // Lifecycle and candidate codes. Every candidate code lies past the step-3
  // state precondition, so all five are reached from ROLE_CEREMONY_ACTIVE.
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    recordRole(coord, begun);
    reach(() => coord.stageRole(null), "COORDINATOR_CANDIDATE_NOT_OBJECT");
    reach(() => coord.stageRole(new Proxy({}, {
      ownKeys() { throw new Error("candidate enumeration exploded"); }
    })), "COORDINATOR_CANDIDATE_ENUMERATION_FAILED");
    reach(() => coord.stageRole({ descriptor: 1, independence: 2, nope: 3 }),
      "COORDINATOR_CANDIDATE_EXTRA_KEY");
    reach(() => coord.stageRole({ descriptor: 1 }), "COORDINATOR_CANDIDATE_MISSING_KEY");
    const throwingGetter = { independence: 2 };
    Object.defineProperty(throwingGetter, "descriptor", {
      get() { throw new Error("getter exploded"); }, enumerable: true, configurable: true
    });
    reach(() => coord.stageRole(throwingGetter), "COORDINATOR_CANDIDATE_READ_FAILED");
    reach(() => coord.reconcileRestart(), "COORDINATOR_ALREADY_RECONCILED");
    coord.cancelRoleCeremony();
    coord.close();
    reach(() => coord.status(), "COORDINATOR_CLOSED");
  });
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    reach(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");
    coord.reconcileRestart();
    poisonCoordinator(coord);
    reach(() => coord.status(), "COORDINATOR_POISONED");
  });

  // Clock and ceremonyId codes.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn });
    clock.impl = () => { throw new Error("clock exploded"); };
    try { reach(() => coord.status(), "COORDINATOR_INVALID_NOW"); }
    finally { clock.impl = null; }
    clock.value = NOW - 5;
    reach(() => coord.status(), "COORDINATOR_CLOCK_REGRESSION_DETECTED");
    clock.value = NOW;
    coord.close();
  });
  withRoot((dir) => {
    const coord = stagingCoordinator(dir, { randomBytesFn: () => null });
    reach(() => coord.beginRole(), "COORDINATOR_CEREMONY_ID_GENERATION_FAILED");
    coord.close();
  });

  // COORDINATOR_JOURNAL_TIMESTAMP_INVALID is reachable only through the §7.1
  // 5B-0.4 seam, per DISCLOSURE E: the host serializer applies no range check.
  withRoot((dir) => {
    const real = pureJournalReal.createGenesisStagingJournal;
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    withPureReplaced(
      "createGenesisStagingJournal",
      (...args) => Object.assign({}, real(...args), { updatedAtUnixSeconds: "not-a-number" }),
      () => { coord.createJournal(validIntent()); }
    );
    reach(() => coord.status(), "COORDINATOR_JOURNAL_TIMESTAMP_INVALID");
    reach(() => coord.beginRole(), "COORDINATOR_JOURNAL_TIMESTAMP_INVALID");
    coord.close();
  });

  // COORDINATOR_INVALID_NOW is asserted UNREACHABLE from cancelRoleCeremony and
  // from close: with a permanently throwing nowFn, both still complete.
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn });
    coord.beginRole();
    clock.impl = () => { throw new Error("clock exploded"); };
    try {
      const cancelled = coord.cancelRoleCeremony();
      assert.equal(cancelled.ceremony, null);
      assert.equal(cancelled.state, "READY_STAGING");
      assert.equal(coord.close(), undefined, "close must not sample the clock");
    } finally {
      clock.impl = null;
    }
  });

  assert.equal(reached.size, 19, `only ${reached.size} of 19 codes were reached`);
  for (const code of reached) assert.ok(Object.hasOwn(CODE, code));

  // Every coordinator-originated code observed anywhere in this suite is a
  // member of the table.
  for (const code of OBSERVED_COORDINATOR_CODES) {
    assert.ok(Object.hasOwn(CODE, code), `${code} is not a member of the frozen table`);
  }

  // Errors the module PROPAGATES BY IDENTITY from the host, 5B-0.4, and Gate B
  // carry codes outside this table by design, and are never rewritten.
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    const sentinel = { code: "NOT_A_COORDINATOR_CODE", detail: { commitState: "NOT_COMMITTED" } };
    withPureReplaced("createGenesisStagingJournal", () => { throw sentinel; }, () => {
      const thrown = captureThrow(() => coord.createJournal(validIntent()));
      assert.equal(thrown, sentinel);
      assert.ok(!Object.hasOwn(CODE, thrown.code));
      assert.ok(!(thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError));
    });
    coord.close();
  });
});

// ===========================================================================
// AT-C26
// ===========================================================================
test("AT-C26: require-time dormancy in a fresh child process, and no product wiring", () => {
  // A child process is mandatory: this test file installs the §7.1 shims at its
  // own load time and therefore cannot observe an unpolluted require.cache.
  const script = `
    const path = require("node:path");
    const before = Object.keys(require.cache).length;
    const mod = require(${JSON.stringify(COORDINATOR_PATH)});
    const keys = Object.keys(require.cache);
    const leaked = keys.filter((k) =>
      k.endsWith("v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts")
      || k.endsWith("v2ConsumerRecoveryGenesisStagingJournal.ts"));
    const tsx = keys.filter((k) => k.split(path.sep).includes("tsx"));
    process.stdout.write(JSON.stringify({
      exports: Object.keys(mod).sort(),
      leaked,
      tsx,
      before
    }));
  `;
  const child = child_process.spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
  assert.equal(child.status, 0, `child failed: ${child.stderr}`);
  const observed = JSON.parse(child.stdout);
  assert.deepEqual(observed.leaked, [], "a pure .ts module was loaded at require time");
  assert.deepEqual(observed.tsx, [], "tsx/cjs was loaded at require time");
  assert.deepEqual(observed.exports, [
    "PHILCORE_V2_RECOVERY_GENESIS_COORDINATOR_ERROR_CODE",
    "PhilCoreV2RecoveryGenesisCoordinatorError",
    "createRecoveryGenesisCoordinator"
  ]);

  // No host construction at require time: constructing one performs filesystem
  // work, and the child created no storage root because the factory was never
  // called. Proven positively — the child's own temp dir stays empty.
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), `philcore-gatec-dormancy-${process.pid}-`));
  try {
    const probeScript = `
      require(${JSON.stringify(COORDINATOR_PATH)});
      process.stdout.write(String(require("node:fs").readdirSync(${JSON.stringify(probeDir)}).length));
    `;
    const probe = child_process.spawnSync(process.execPath, ["-e", probeScript], { encoding: "utf8" });
    assert.equal(probe.status, 0, `dormancy probe failed: ${probe.stderr}`);
    assert.equal(probe.stdout, "0", "requiring the coordinator performed filesystem work");
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }

  // Absence from build-local.cjs requiredFiles.
  const buildLocal = fs.readFileSync(
    path.resolve(__dirname, "../scripts/build-local.cjs"), "utf8"
  );
  assert.ok(!buildLocal.includes("recovery-genesis-coordinator"),
    "the coordinator must be absent from build-local.cjs requiredFiles");

  // The classification entry exists.
  const classification = JSON.parse(fs.readFileSync(
    path.resolve(__dirname, "../../../config/ci/classification.json"), "utf8"
  ));
  const entry = classification.items.find((item) =>
    item.id === "desktop_file:apps/philcore-desktop/test/desktop-recovery-genesis-coordinator.test.cjs");
  assert.ok(entry, "the Gate-C classification entry is missing");
  assert.equal(entry.kind, "desktop_test_file");
  assert.equal(entry.lane, "desktop");
  assert.equal(entry.command,
    "node apps/philcore-desktop/test/desktop-recovery-genesis-coordinator.test.cjs");

  // No main/preload/renderer/IPC/bridge file references the module.
  const referencing = [];
  const SKIP_DIRS = new Set(["node_modules", "dist", "dist-local", "release", ".git"]);
  const scan = (dir) => {
    for (const dirent of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, dirent.name);
      if (dirent.isSymbolicLink()) continue;
      if (dirent.isDirectory()) {
        if (!SKIP_DIRS.has(dirent.name)) scan(full);
        continue;
      }
      if (!/\.(cjs|js|mjs|ts|json|html)$/u.test(dirent.name)) continue;
      if (full.endsWith("recovery-genesis-coordinator.cjs")) continue;
      if (full.endsWith("desktop-recovery-genesis-coordinator.test.cjs")) continue;
      if (fs.readFileSync(full, "utf8").includes("recovery-genesis-coordinator")) {
        referencing.push(full);
      }
    }
  };
  scan(path.resolve(__dirname, ".."));
  assert.deepEqual(referencing, [], `unexpected references: ${referencing.join(", ")}`);

  // No renderer channel, bridge-contract entry, device adapter, profile
  // validation, or supersession call appears anywhere in the module.
  const source = fs.readFileSync(COORDINATOR_PATH, "utf8");
  for (const forbidden of [
    "ipcMain", "ipcRenderer", "BrowserWindow", "webContents", "contextBridge",
    "bridge-contract", "registerChannel", "deviceAdapter", "validateProfile",
    "profileValidation", "supersede", "supersession", "electron"
  ]) {
    assert.ok(!source.includes(forbidden), `module references ${forbidden}`);
  }
});

// ===========================================================================
// AT-C27
// ===========================================================================
test("AT-C27: the module has no filesystem surface", () => {
  const source = fs.readFileSync(COORDINATOR_PATH, "utf8");

  assert.ok(!/require\(\s*["']node:fs["']\s*\)/u.test(source), "module requires node:fs");
  assert.ok(!/require\(\s*["']fs["']\s*\)/u.test(source), "module requires fs");
  assert.ok(!/require\(\s*["']node:path["']\s*\)/u.test(source), "module requires node:path");
  assert.ok(!/require\(\s*["']path["']\s*\)/u.test(source), "module requires path");

  // No staging path, filename, or directory literal. THREE authorized/mandated
  // specifier strings are excised first, each asserted present beforehand: the
  // host-module specifier "./recovery-genesis-staging-host.cjs", which
  // necessarily contains the substring "genesis-staging" and which §5.1 and
  // §11.2 mandate; the §5.12.1 Gate-B lifecycle specifier; and the §5.12.1 lazy
  // "tsx/cjs" hook, which must live inside the accessor. Excising them changes
  // no positive-presence gate and no forbidden-literal semantics — everything
  // else in the source must still be free of staging-surface literals.
  const AUTHORIZED_SPECIFIERS = [
    "./recovery-genesis-staging-host.cjs",
    "../../../phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts",
    "tsx/cjs"
  ];
  let scannable = source;
  for (const specifier of AUTHORIZED_SPECIFIERS) {
    assert.ok(source.includes(specifier), `the mandated specifier ${specifier} is missing`);
    scannable = scannable.split(specifier).join("<authorized-specifier>");
  }
  for (const literal of [
    "philcore-recovery-enrollment", "genesis-staging", ".staging.lock",
    "ceremony_", ".v1.json", ".corrupt-quarantine", ".stale-lock-quarantine",
    ".tmp", "/tmp", "mkdir", "readdir", "unlink", "rename", "fsync", "openSync",
    "writeFile", "readFile", "existsSync", "lstat"
  ]) {
    assert.ok(!scannable.includes(literal), `module contains the literal ${literal}`);
  }

  // The complete top-level require set is exactly two entries. Only column-zero
  // declarations count as top level; the §5.12.1 lazy accessor's own requires
  // are indented inside the function body and are deliberately excluded.
  const topLevel = [];
  for (const line of source.split("\n")) {
    if (!/^(const|let|var)\s/u.test(line)) continue;
    const match = line.match(/require\(\s*["']([^"']+)["']\s*\)/u);
    if (match) topLevel.push(match[1]);
  }
  assert.deepEqual(topLevel.sort(), ["./recovery-genesis-staging-host.cjs", "node:crypto"]);

  // The lazy Gate-B accessor exists and is indented (never top level).
  assert.ok(/\n\s+require\("tsx\/cjs"\);/u.test(source), "the tsx hook must be inside the accessor");
  assert.ok(!/^require\(/mu.test(source), "no bare top-level require call");

  // node:crypto and the global Buffer are expressly permitted.
  assert.ok(source.includes("node:crypto"));
});

// ===========================================================================
// AT-C28
// ===========================================================================
test("AT-C28: the acknowledgement post-success rule, not the generic Phase R", () => {
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const first = stagingCoordinator(dir, { nowFn: clock.fn });
    const cancelled = first.cancelEnrollment();
    first.close();

    const coord = newCoordinator(dir, { nowFn: clock.fn });
    const report = coord.reconcileRestart();
    assert.equal(coord.status().state, "READY_TERMINAL");

    // Durable evidence, per §7.2: the journal file exists before the call.
    const journalPath = journalFilePath(dir, report.journal);
    assert.ok(fs.existsSync(journalPath), "the journal file must exist before acknowledgement");

    const before = clock.calls;
    const acknowledged = withGateBSpy((calls) => {
      const result = coord.acknowledgeTerminal();
      assert.equal(calls.length, 0, "acknowledgeTerminal invoked a Gate-B operation");
      return result;
    });
    assert.equal(clock.calls - before, 0, "acknowledgeTerminal sampled the clock");

    // Exactly the own keys ["state","acknowledged"] and no journal key.
    assert.deepEqual(Object.keys(acknowledged), ["state", "acknowledged"]);
    assert.ok(!("journal" in acknowledged));
    assert.ok(Object.isFrozen(acknowledged));
    assert.equal(acknowledged.acknowledged, true);
    assert.equal(acknowledged.state, "READY_ABSENT");

    // The state is DERIVED: journal === null and reconciled === true.
    const status = coord.status();
    assert.equal(status.state, "READY_ABSENT");
    assert.equal(status.journal, null);
    assert.equal(status.ceremony, null);
    assert.equal(status.nextRole, null);

    // reconciled remains true — proved through the public surface, never by
    // reading a private field.
    assertCoordError(() => coord.reconcileRestart(), "COORDINATOR_ALREADY_RECONCILED");

    // Exactly one host acknowledgment operation, proven durably: the file is
    // gone (excludes zero) and an immediate second call is rejected because the
    // state is no longer READY_TERMINAL (excludes two).
    assert.ok(!fs.existsSync(journalPath), "the journal file must be gone after acknowledgement");
    assertCoordError(() => coord.acknowledgeTerminal(), "COORDINATOR_INVALID_STATE");
    coord.close();
    void cancelled;
  });

  // Negative arm: on a Phase-D throw nothing is cleared.
  withRoot((dir) => {
    const first = stagingCoordinator(dir);
    first.cancelEnrollment();
    first.close();

    const coord = newCoordinator(dir);
    const report = coord.reconcileRestart();
    assert.equal(coord.status().state, "READY_TERMINAL");

    // Removing the journal file makes the host's initial CAS fail with a
    // NOT_COMMITTED, non-poisoning error.
    fs.unlinkSync(journalFilePath(dir, report.journal));
    const thrown = captureThrow(() => coord.acknowledgeTerminal());
    assert.ok(thrown instanceof HostError);
    assert.ok(!(thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError));

    // Retained record, reconciled flag, and derived state are all unchanged.
    const status = coord.status();
    assert.equal(status.state, "READY_TERMINAL");
    assert.equal(status.journal, report.journal);
    assertCoordError(() => coord.reconcileRestart(), "COORDINATOR_ALREADY_RECONCILED");
  });
});

// ===========================================================================
// AT-C29
// ===========================================================================
test("AT-C29: finalizeProfile guards — READY_FOR_PROFILE_VALIDATION only, no ceremony", () => {
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    assertCoordError(() => coord.finalizeProfile({}), "COORDINATOR_INVALID_STATE"); // UNRECONCILED
    coord.reconcileRestart();
    assertCoordError(() => coord.finalizeProfile({}), "COORDINATOR_INVALID_STATE"); // READY_ABSENT
    coord.createJournal(validIntent());
    assertCoordError(() => coord.finalizeProfile({}), "COORDINATOR_INVALID_STATE"); // READY_STAGING
    const begun = coord.beginRole();
    assertCoordError(() => coord.finalizeProfile({}), "COORDINATOR_INVALID_STATE"); // ROLE_CEREMONY_ACTIVE
    coord.stageRole(recordRole(coord, begun));
    stageOneRole(coord, 1);
    stageOneRole(coord, 2);
    assert.equal(coord.status().state, "READY_FOR_PROFILE_VALIDATION");
    assert.equal(coord.status().ceremony, null);
    const expected = expectedValidationFor(coord);
    const finalized = coord.finalizeProfile(expected);
    assert.equal(finalized.state, "FINALIZED");
    assertCoordError(() => coord.finalizeProfile(expected), "COORDINATOR_INVALID_STATE"); // FINALIZED
    coord.close();
    assertCoordError(() => coord.finalizeProfile({}), "COORDINATOR_CLOSED"); // CLOSED
  });

  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    poisonCoordinator(coord);
    assertCoordError(() => coord.finalizeProfile({}), "COORDINATOR_POISONED"); // POISONED
  });

  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.cancelEnrollment();
    assertCoordError(() => coord.finalizeProfile({}), "COORDINATOR_INVALID_STATE"); // READY_TERMINAL
    coord.close();
  });
});

// ===========================================================================
// AT-C30
// ===========================================================================
test("AT-C30: finalizeProfile forwards the caller reference unchanged once", () => {
  withRoot((dir) => {
    const coord = profileReadyCoordinator(dir);
    const expected = expectedValidationFor(coord);
    const forwarded = expected;
    const profilePath = finalizedProfileFilePath(dir, {
      genesisDeploymentIntentHash: coord.status().journal.genesisDeploymentIntentHash
    });
    assert.ok(!fs.existsSync(profilePath), "no final profile file before finalizeProfile");

    const result = coord.finalizeProfile(forwarded);
    assert.equal(result.state, "FINALIZED");
    assert.ok(fs.existsSync(profilePath), "exactly one host finalizeProfile publication");
    assertCoordError(() => coord.finalizeProfile(forwarded), "COORDINATOR_INVALID_STATE");
    coord.close();
  });

  // The coordinator does not read expectedValidationResult: a getter-only trap
  // survives until the host inspects the forwarded reference.
  withRoot((dir) => {
    const coord = profileReadyCoordinator(dir);
    const unreadable = {};
    Object.defineProperty(unreadable, "genesisDeploymentIntentHash", {
      get() { throw new Error("coordinator read expectedValidationResult"); },
      enumerable: true, configurable: true
    });
    const thrown = captureThrow(() => coord.finalizeProfile(unreadable));
    assert.ok(!(thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError));
    assert.notEqual(String(thrown && thrown.message), "coordinator read expectedValidationResult");
    coord.close();
  });
});

// ===========================================================================
// AT-C31
// ===========================================================================
test("AT-C31: FINALIZED derive precedence over every journal state", () => {
  withRoot((dir) => {
    const coord = profileReadyCoordinator(dir);
    const expected = expectedValidationFor(coord);
    const result = coord.finalizeProfile(expected);
    assert.equal(result.state, "FINALIZED");
    assert.equal(result.journal.state, "SUPERSEDED");
    assert.ok(result.finalizedProfile !== null);

    const status = coord.status();
    assert.equal(status.state, "FINALIZED");
    assert.equal(status.journal.state, "SUPERSEDED");
    assert.equal(status.finalizedProfile, result.finalizedProfile);
    assert.equal(status.nextRole, null);
    assert.equal(status.ceremony, null);

    assertCoordError(() => coord.beginRole(), "COORDINATOR_INVALID_STATE");
    assertCoordError(() => coord.cancelEnrollment(), "COORDINATOR_INVALID_STATE");
    coord.close();
  });
});

// ===========================================================================
// AT-C32
// ===========================================================================
test("AT-C32: PROFILE_COMMITTED is retryable and claims no coordinator final", () => {
  withRoot((dir) => {
    const coord = profileReadyCoordinator(dir);
    const expected = expectedValidationFor(coord);
    const profilePath = finalizedProfileFilePath(dir, {
      genesisDeploymentIntentHash: coord.status().journal.genesisDeploymentIntentHash
    });
    const sentinel = { code: "PURE_SUPERSEDE_FAULT", detail: { commitState: "PROFILE_COMMITTED" } };

    withPureReplaced("supersedeGenesisStagingJournal", () => { throw sentinel; }, () => {
      const thrown = captureThrow(() => coord.finalizeProfile(expected));
      assert.equal(thrown, sentinel, "PROFILE_COMMITTED fault propagates by identity");
      assert.ok(!(thrown instanceof PhilCoreV2RecoveryGenesisCoordinatorError));
    });

    assert.equal(coord.status().state, "READY_FOR_PROFILE_VALIDATION");
    assert.equal(coord.status().finalizedProfile, undefined);
    assert.ok(fs.existsSync(profilePath), "the host final is durable before supersession completes");

    const recovered = coord.finalizeProfile(expected);
    assert.equal(recovered.state, "FINALIZED");
    assert.equal(coord.status().state, "FINALIZED");
    assert.equal(coord.status().finalizedProfile, recovered.finalizedProfile);
    coord.close();
  });
});

// ===========================================================================
// AT-C33
// ===========================================================================
test("AT-C33: restart derivation with a retained finalizedProfile", () => {
  withRoot((dir) => {
    const first = profileReadyCoordinator(dir);
    const expected = expectedValidationFor(first);
    const finalized = first.finalizeProfile(expected);
    first.close();

    const second = newCoordinator(dir);
    const report = second.reconcileRestart();
    assert.ok(["FINALIZED", "RECOVERED_FINALIZED_AND_SUPERSEDED"].includes(report.outcome));
    assert.ok(report.finalizedProfile !== null);
    assertDeepFrozen(report.finalizedProfile, "reconciled finalizedProfile");
    assert.equal(second.status().state, "FINALIZED");
    assert.equal(second.status().finalizedProfile, report.finalizedProfile);
    if (report.journal !== null) {
      assert.equal(report.journal.state, "SUPERSEDED");
      assert.equal(second.status().journal.state, "SUPERSEDED");
    } else {
      assert.equal(second.status().journal, null);
    }
    assert.equal(second.status().nextRole, null);
    assertCoordError(() => second.reconcileRestart(), "COORDINATOR_ALREADY_RECONCILED");
    void finalized;
    second.close();
  });
});

// ===========================================================================
// AT-C34
// ===========================================================================
test("AT-C34: acknowledgeTerminal from FINALIZED — superseded journal and idempotent absent", () => {
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = profileReadyCoordinator(dir, { nowFn: clock.fn });
    const expected = expectedValidationFor(coord);
    coord.finalizeProfile(expected);
    assert.equal(coord.status().state, "FINALIZED");
    assert.equal(coord.status().journal.state, "SUPERSEDED");

    const journalPath = journalFilePath(dir, coord.status().journal);
    assert.ok(fs.existsSync(journalPath), "superseded journal file exists before acknowledgement");

    const before = clock.calls;
    const acknowledged = withGateBSpy((calls) => {
      const result = coord.acknowledgeTerminal();
      assert.equal(calls.length, 0, "acknowledgeTerminal invoked a Gate-B operation");
      return result;
    });
    assert.equal(clock.calls - before, 0, "acknowledgeTerminal sampled no clock");
    assert.equal(acknowledged.state, "FINALIZED");
    assert.equal(acknowledged.acknowledged, true);
    assert.deepEqual(Object.keys(acknowledged), ["state", "acknowledged"]);
    assert.ok(!("journal" in acknowledged));

    const status = coord.status();
    assert.equal(status.state, "FINALIZED");
    assert.equal(status.journal, null);
    assert.equal(status.finalizedProfile, coord.status().finalizedProfile);
    assert.ok(!fs.existsSync(journalPath), "journal file is gone after acknowledgement");
    const secondAck = coord.acknowledgeTerminal();
    assert.equal(secondAck.state, "FINALIZED");
    assert.equal(secondAck.acknowledged, false);
    coord.close();
  });

  withRoot((dir) => {
    const first = profileReadyCoordinator(dir);
    const expected = expectedValidationFor(first);
    first.finalizeProfile(expected);
    const journalPath = journalFilePath(dir, first.status().journal);
    first.acknowledgeTerminal();
    first.close();
    assert.ok(!fs.existsSync(journalPath));

    const coord = newCoordinator(dir);
    const report = coord.reconcileRestart();
    assert.equal(report.outcome, "FINALIZED");
    assert.equal(report.journal, null);
    assert.ok(report.finalizedProfile !== null);
    assert.equal(coord.status().state, "FINALIZED");
    assert.equal(coord.status().journal, null);

    const idempotent = withGateBSpy((calls) => {
      const result = coord.acknowledgeTerminal();
      assert.equal(calls.length, 0, "idempotent acknowledgeTerminal reached Gate B");
      return result;
    });
    assert.equal(idempotent.state, "FINALIZED");
    assert.equal(idempotent.acknowledged, false);
    assert.deepEqual(Object.keys(idempotent), ["state", "acknowledged"]);
    assert.equal(coord.status().state, "FINALIZED");
    assert.equal(coord.status().finalizedProfile, report.finalizedProfile);
    coord.close();
  });
});

// ---------------------------------------------------------------------------
// ===========================================================================
// Durable credential-obligation additions C01-C24
// ===========================================================================
test("OB-C01: beginRole publishes and adopts the durable ACTIVE obligation", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    assert.equal(begun.state, "ROLE_CEREMONY_ACTIVE");
    assert.equal(begun.obligation.state, "ACTIVE");
    assert.equal(begun.obligation.ceremonyId, begun.ceremony.ceremonyId);
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    coord.close();
  });
});

test("OB-C02: authorizeCredentialCreation adopts CREATION_AUTHORIZED", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const result = coord.authorizeCredentialCreation();
    assert.equal(result.state, "CREDENTIAL_CREATION_AUTHORIZED");
    assert.equal(result.obligation.state, "CREATION_AUTHORIZED");
    assert.equal(result.obligation.ceremonyId, begun.ceremony.ceremonyId);
    coord.close();
  });
});

test("OB-C03: recordCreatedCredential adopts the two durable public hashes", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);
    const status = coord.status();
    assert.equal(status.state, "CREDENTIAL_RECORDED");
    assert.equal(status.credentialObligation.state, "CREDENTIAL_RECORDED");
    assert.equal(status.credentialObligation.credentialIdHash, candidate.descriptor.credentialIdHash);
    assert.equal(status.credentialObligation.publicVerificationMaterialHash,
      candidate.descriptor.publicVerificationMaterialHash);
    coord.close();
  });
});

test("OB-C04: stageRole consumes only after a recorded credential", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const result = stageOneRole(coord, 0);
    assert.equal(result.staged, true);
    assert.equal(result.state, "READY_STAGING");
    assert.equal(result.obligation, null);
    assert.notEqual(result.journal.manifest["0"], null);
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    coord.close();
  });
});

test("OB-C05: role cancellation before authorization safely removes ACTIVE", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    const result = coord.cancelRoleCeremony();
    assert.equal(result.state, "READY_STAGING");
    assert.equal(result.obligation, null);
    assert.equal(coord.status().journal.state, "STAGING");
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    coord.close();
  });
});

test("OB-C06: enrollment cancellation before authorization removes ACTIVE then terminates", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    const result = coord.cancelEnrollment();
    assert.equal(result.state, "READY_TERMINAL");
    assert.equal(result.journal.state, "CANCELLED");
    assert.equal(result.obligation, null);
    coord.close();
  });
});

test("OB-C07: role cancellation after authorization durably blocks as ORPHANED", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    coord.authorizeCredentialCreation();
    const result = coord.cancelRoleCeremony();
    assert.equal(result.state, "ORPHAN_CREDENTIAL_BLOCKED");
    assert.equal(result.obligation.state, "ORPHANED");
    assert.equal(result.obligation.orphanReason,
      "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION");
    assert.equal(coord.status().journal.state, "STAGING");
    coord.close();
  });
});

test("OB-C08: enrollment expiry after authorization preserves an orphan", () => {
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn }, { expiresAt: String(NOW + 10) });
    coord.beginRole();
    coord.authorizeCredentialCreation();
    clock.value = NOW + 20;
    const result = coord.cancelEnrollment();
    assert.equal(result.journal.state, "EXPIRED");
    assert.equal(result.state, "ORPHAN_CREDENTIAL_BLOCKED");
    assert.equal(result.obligation.orphanReason,
      "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION");
    coord.close();
  });
});

test("OB-C09: restart restores an ACTIVE durable obligation", () => {
  withRoot((dir) => {
    const first = stagingCoordinator(dir);
    const begun = first.beginRole();
    first.close();
    const recovered = newCoordinator(dir);
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ACTIVE");
    assert.equal(report.state, "ROLE_CEREMONY_ACTIVE");
    assert.equal(report.credentialObligation.ceremonyId, begun.ceremony.ceremonyId);
    recovered.close();
  });
});

test("OB-C10: restart converts an authorized unknown result to an unknown orphan", () => {
  withRoot((dir) => {
    const first = stagingCoordinator(dir);
    first.beginRole();
    first.authorizeCredentialCreation();
    first.close();
    const recovered = newCoordinator(dir);
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.state, "ORPHAN_CREDENTIAL_BLOCKED");
    assert.equal(report.credentialObligation.credentialIdHash, null);
    assert.equal(report.credentialObligation.publicVerificationMaterialHash, null);
    assert.equal(report.credentialObligation.orphanReason, "RESTART_DURING_CREATION");
    recovered.close();
  });
});

test("OB-C11: restart converts a recorded result to a known orphan", () => {
  withRoot((dir) => {
    const first = stagingCoordinator(dir);
    const begun = first.beginRole();
    const candidate = recordRole(first, begun);
    first.close();
    const recovered = newCoordinator(dir);
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.state, "ORPHAN_CREDENTIAL_BLOCKED");
    assert.equal(report.credentialObligation.credentialIdHash, candidate.descriptor.credentialIdHash);
    assert.equal(report.credentialObligation.publicVerificationMaterialHash,
      candidate.descriptor.publicVerificationMaterialHash);
    recovered.close();
  });
});

test("OB-C12: restart recovers consumption when the manifest proves the retained sidecar", () => {
  withRoot((dir) => {
    const first = stagingCoordinator(dir);
    const begun = first.beginRole();
    const candidate = recordRole(first, begun);
    const retainedBytes = fs.readFileSync(obligationFilePath(dir));
    first.stageRole(candidate);
    first.close();
    fs.writeFileSync(obligationFilePath(dir), retainedBytes, { mode: 0o600 });
    const recovered = newCoordinator(dir);
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "CONSUMED_RECOVERED");
    assert.equal(report.credentialObligation, null);
    assert.equal(report.state, "READY_STAGING");
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    recovered.close();
  });
});

test("OB-C13: a validated manifest hash mismatch is rejected before publication", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);
    const credentialIdHash = `0x${"09".repeat(32)}`;
    const independence = { ...candidate.independence, credentialIdHash };
    const mismatched = {
      descriptor: {
        ...candidate.descriptor,
        credentialIdHash,
        independenceBindingHash: computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence)
      },
      independence
    };
    if (candidate.signer) mismatched.signer = candidate.signer;
    const error = captureThrow(() => coord.stageRole(mismatched));
    assert.equal(error.code, "HOST_CREDENTIAL_OBLIGATION_CREDENTIAL_MISMATCH");
    assert.equal(coord.status().state, "CREDENTIAL_RECORDED");
    coord.close();
  });
});

test("OB-C14: profile finalization is blocked while an obligation exists", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    assertCoordError(() => coord.finalizeProfile(Object.freeze({})), "COORDINATOR_INVALID_STATE");
    coord.close();
  });
});

test("OB-C15: terminal acknowledgement cannot erase an orphan", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    coord.authorizeCredentialCreation();
    coord.cancelEnrollment();
    assertCoordError(() => coord.acknowledgeTerminal(), "COORDINATOR_INVALID_STATE");
    assert.equal(coord.status().state, "ORPHAN_CREDENTIAL_BLOCKED");
    coord.close();
  });
});

test("OB-C16: close retains the durable sidecar for restart", () => {
  withRoot((dir) => {
    const first = stagingCoordinator(dir);
    first.beginRole();
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    first.close();
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    const second = newCoordinator(dir);
    assert.equal(second.reconcileRestart().credentialOutcome, "ACTIVE");
    second.close();
  });
});

test("OB-C17: hostile credential input cannot inject durable state", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    coord.authorizeCredentialCreation();
    const hostile = new Proxy({}, {
      ownKeys() { throw new Error("raw-marker"); },
      getOwnPropertyDescriptor() { throw new Error("raw-marker"); }
    });
    const error = captureThrow(() => coord.recordCreatedCredential(hostile));
    assert.ok(typeof error.code === "string");
    assert.equal(String(error).includes("raw-marker"), false);
    assert.equal(coord.status().state, "CREDENTIAL_CREATION_AUTHORIZED");
    coord.close();
  });
});

test("OB-C18: throwing credential getters are contained without a raw cause", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    coord.beginRole();
    coord.authorizeCredentialCreation();
    const marker = { secret: "must-not-escape" };
    const input = {};
    Object.defineProperty(input, "credentialIdHash", { get() { throw marker; } });
    Object.defineProperty(input, "publicVerificationMaterialHash", { value: `0x${"03".repeat(32)}` });
    const error = captureThrow(() => coord.recordCreatedCredential(input));
    assert.notEqual(error, marker);
    assert.equal(Object.hasOwn(error, "cause"), false);
    assert.equal(JSON.stringify(error).includes(marker.secret), false);
    coord.close();
  });
});

test("OB-C19: a lower ceremony-layer failure is rethrown by identity", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const sentinel = Object.freeze({ code: "LOWER_SENTINEL" });
    withGateBReplaced("mintPhilCoreV2GenesisRoleCeremony", () => { throw sentinel; }, () => {
      assert.equal(captureThrow(() => coord.beginRole()), sentinel);
    });
    assert.equal(coord.status().state, "READY_STAGING");
    coord.close();
  });
});

test("OB-C20: poisoning host ambiguity outranks every durable derived state", () => {
  withRoot((dir) => {
    const coord = newCoordinator(dir);
    coord.reconcileRestart();
    const sentinel = new HostError("HOST_FILESYSTEM_MUTATION_FAILED", {
      commitState: "OBLIGATION_RETIREMENT_INDETERMINATE",
      operation: "test", phase: "TEST", primaryCode: null, subject: null
    });
    withPureReplaced("createGenesisStagingJournal", () => { throw sentinel; }, () => {
      assert.equal(captureThrow(() => coord.createJournal(validIntent())), sentinel);
    });
    assertCoordError(() => coord.status(), "COORDINATOR_POISONED");
  });
});

test("OB-C21: obligation path clock calls are exact", () => {
  withRoot((dir) => {
    const clock = makeClock(NOW);
    const coord = stagingCoordinator(dir, { nowFn: clock.fn });
    let before = clock.calls;
    const begun = coord.beginRole();
    assert.equal(clock.calls - before, 2);
    before = clock.calls;
    coord.authorizeCredentialCreation();
    assert.equal(clock.calls - before, 1);
    const candidate = candidateFor(begun.ceremony, begun.role);
    before = clock.calls;
    coord.recordCreatedCredential({
      credentialIdHash: candidate.descriptor.credentialIdHash,
      publicVerificationMaterialHash: candidate.descriptor.publicVerificationMaterialHash
    });
    assert.equal(clock.calls - before, 1);
    before = clock.calls;
    coord.stageRole(candidate);
    assert.equal(clock.calls - before, 1);
    before = clock.calls;
    coord.status();
    assert.equal(clock.calls - before, 1);
    coord.close();
  });
});

test("OB-C22: callers cannot supply obligation or ceremony state", () => {
  withRoot((dir) => {
    const coord = stagingCoordinator(dir);
    const begun = coord.beginRole();
    const candidate = recordRole(coord, begun);
    assertCoordError(
      () => coord.stageRole({ ...candidate, credentialObligation: Object.freeze({ state: "ACTIVE" }) }),
      "COORDINATOR_CANDIDATE_EXTRA_KEY"
    );
    assertCoordError(
      () => coord.stageRole({ ...candidate, currentRoleCeremony: begun.ceremony }),
      "COORDINATOR_CANDIDATE_EXTRA_KEY"
    );
    coord.close();
  });
});

test("OB-C23: fresh require remains transitively dormant", () => {
  const script = `
    const fs = require("node:fs");
    for (const name of ["openSync", "writeFileSync", "mkdirSync", "renameSync", "unlinkSync"]) {
      fs[name] = () => { throw new Error("filesystem touched: " + name); };
    }
    const mod = require(${JSON.stringify(COORDINATOR_PATH)});
    const loaded = Object.keys(require.cache);
    process.stdout.write(JSON.stringify({
      exports: Object.keys(mod).length,
      obligationLoaded: loaded.some((p) => p.endsWith("v2ConsumerRecoveryGenesisCredentialObligation.ts"))
    }));
  `;
  const child = child_process.spawnSync(process.execPath, ["-e", script], { encoding: "utf8" });
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(JSON.parse(child.stdout), { exports: 3, obligationLoaded: false });
});

test("OB-C24: no product entry point or build list references the dormant package", () => {
  const desktopRoot = path.resolve(__dirname, "..");
  const forbiddenFiles = [
    "src/main/main.cjs", "src/preload/preload.cjs", "scripts/build-local.cjs"
  ];
  for (const relative of forbiddenFiles) {
    const file = path.join(desktopRoot, relative);
    if (!fs.existsSync(file)) continue;
    const source = fs.readFileSync(file, "utf8");
    assert.equal(source.includes("v2ConsumerRecoveryGenesisCredentialObligation"), false, relative);
    assert.equal(source.includes("recovery-genesis-credential-obligation"), false, relative);
  }
  const coordinatorSource = fs.readFileSync(COORDINATOR_PATH, "utf8");
  for (const forbidden of ["ipcMain", "ipcRenderer", "contextBridge", "BrowserWindow", "webContents"])
    assert.equal(coordinatorSource.includes(forbidden), false, forbidden);
});

// §7.1 constraint 3 / §11.9 seam hygiene. This is a mechanical-gate check, not
// an acceptance contract, so it is deliberately NOT a test block: the focused
// suite total must be exactly 58.
// ---------------------------------------------------------------------------
let seamHygiene = "ok";
try { assertShimsPristine(); }
catch (error) { seamHygiene = `FAILED: ${error && error.message}`; process.exitCode = 1; }

for (const root of createdRoots) fs.rmSync(root, { recursive: true, force: true });

console.log(`seam hygiene (both §7.1 shims restored key-for-key): ${seamHygiene}`);
console.log(`\n${passed} passed, ${failures.length} failed, ${passed + failures.length} total`);
if (failures.length > 0) {
  for (const failure of failures) {
    console.log(`\nFAILED: ${failure.name}\n${failure.error && failure.error.stack}`);
  }
  process.exitCode = 1;
}
