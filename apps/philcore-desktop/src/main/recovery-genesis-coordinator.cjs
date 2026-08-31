"use strict";

// PhilCore Gate C — dormant genesis staging coordinator (main process only).
//
// A dormant coordinator that exclusively owns one Package 5B-0.5 recovery
// genesis staging host and one pure Gate-B genesis role-ceremony lifecycle
// slot. It is required by no main, preload, renderer, IPC, or bridge file, and
// it is deliberately absent from build-local.cjs requiredFiles.
//
// Boundaries:
//   * No filesystem surface of its own. The host's seven public methods are the
//     only durable-state channel; there is no second source of truth.
//   * No work at require time. The only top-level requires are the host module
//     and node:crypto, both inert; Gate B is loaded lazily on first use.
//   * The host is stored in a closure variable and is never returned, exposed,
//     passed to a callback, or reachable through any property, getter, or error.
//   * No product wiring of any kind. No device adapter.
//   * Deterministic injected clock and randomness only.
//
// Error discipline: every error from the host, from the pure genesis layers,
// and from Gate B is rethrown as the SAME object, with exactly two bounded
// exceptions that absorb Gate-B errors only — post-commit reconciliation
// (Phase R) and cancelRoleCeremony. Every other catch in this module either
// classifies poison and rethrows by identity, or converts a caller-supplied
// throw into a closed coordinator code with the raw value discarded unread.

const { createRecoveryGenesisStagingHost, PhilCoreV2ConsumerRecoveryGenesisStagingHostError } = require("./recovery-genesis-staging-host.cjs");
const crypto = require("node:crypto");

// ---------------------------------------------------------------------------
// Error surface — 19 codes, frozen, closed, all reachable
// ---------------------------------------------------------------------------
const PHILCORE_V2_RECOVERY_GENESIS_COORDINATOR_ERROR_CODE = Object.freeze({
  COORDINATOR_DEPENDENCIES_NOT_OBJECT:       "COORDINATOR_DEPENDENCIES_NOT_OBJECT",
  COORDINATOR_DEPENDENCY_ENUMERATION_FAILED: "COORDINATOR_DEPENDENCY_ENUMERATION_FAILED",
  COORDINATOR_DEPENDENCY_EXTRA:              "COORDINATOR_DEPENDENCY_EXTRA",
  COORDINATOR_DEPENDENCY_MISSING:            "COORDINATOR_DEPENDENCY_MISSING",
  COORDINATOR_DEPENDENCY_INVALID:            "COORDINATOR_DEPENDENCY_INVALID",
  COORDINATOR_DEPENDENCY_READ_FAILED:        "COORDINATOR_DEPENDENCY_READ_FAILED",
  COORDINATOR_CLOSED:                        "COORDINATOR_CLOSED",
  COORDINATOR_POISONED:                      "COORDINATOR_POISONED",
  COORDINATOR_INVALID_STATE:                 "COORDINATOR_INVALID_STATE",
  COORDINATOR_ALREADY_RECONCILED:            "COORDINATOR_ALREADY_RECONCILED",
  COORDINATOR_CANDIDATE_NOT_OBJECT:          "COORDINATOR_CANDIDATE_NOT_OBJECT",
  COORDINATOR_CANDIDATE_ENUMERATION_FAILED:  "COORDINATOR_CANDIDATE_ENUMERATION_FAILED",
  COORDINATOR_CANDIDATE_EXTRA_KEY:           "COORDINATOR_CANDIDATE_EXTRA_KEY",
  COORDINATOR_CANDIDATE_MISSING_KEY:         "COORDINATOR_CANDIDATE_MISSING_KEY",
  COORDINATOR_CANDIDATE_READ_FAILED:         "COORDINATOR_CANDIDATE_READ_FAILED",
  COORDINATOR_INVALID_NOW:                   "COORDINATOR_INVALID_NOW",
  COORDINATOR_CLOCK_REGRESSION_DETECTED:     "COORDINATOR_CLOCK_REGRESSION_DETECTED",
  COORDINATOR_JOURNAL_TIMESTAMP_INVALID:     "COORDINATOR_JOURNAL_TIMESTAMP_INVALID",
  COORDINATOR_CEREMONY_ID_GENERATION_FAILED: "COORDINATOR_CEREMONY_ID_GENERATION_FAILED"
});
const C = PHILCORE_V2_RECOVERY_GENESIS_COORDINATOR_ERROR_CODE;

// `code` is readonly. No `cause`, and no raw thrown value is ever retained
// under any property.
class PhilCoreV2RecoveryGenesisCoordinatorError extends Error {
  constructor(code) {
    super(code);
    this.name = "PhilCoreV2RecoveryGenesisCoordinatorError";
    Object.defineProperty(this, "code", {
      value: code, writable: false, enumerable: true, configurable: false
    });
  }
}

function coordinatorError(code) {
  return new PhilCoreV2RecoveryGenesisCoordinatorError(code);
}

// ---------------------------------------------------------------------------
// Constants and total helpers
// ---------------------------------------------------------------------------
const UINT48_MAX = 281474976710655;
const DEPENDENCY_OWN_KEYS = Object.freeze([
  "storageRoot", "nowFn", "livenessProbeFn", "randomBytesFn"
]);
const CANDIDATE_OWN_KEYS = Object.freeze(["descriptor", "independence", "signer"]);
const MANIFEST_SLOT_KEYS = Object.freeze(["0", "1", "2"]);

// Only `typeof` is ever applied to a caller-supplied value; it invokes no trap.
function isObjectLike(value) {
  return (typeof value === "object" && value !== null) || typeof value === "function";
}

function defaultNowFn() {
  return Math.floor(Date.now() / 1000);
}

// The journal field is a canonical decimal string; Gate B requires a safe
// integer number. Number(...) is exact because every valid journal timestamp is
// at most UINT48_MAX, strictly below Number.MAX_SAFE_INTEGER.
function journalTimeToNumber(decimalString) {
  const n = Number(decimalString);
  if (!Number.isSafeInteger(n) || n < 1 || n > UINT48_MAX) {
    throw coordinatorError(C.COORDINATOR_JOURNAL_TIMESTAMP_INVALID);
  }
  return n;
}

// A number in {0,1,2,3}. Values are read from the host's own deep-frozen
// record, which is trusted output of the layer below, not caller input.
function populatedCount(manifest) {
  let count = 0;
  for (const slot of MANIFEST_SLOT_KEYS) {
    if (manifest[slot] !== null) count += 1;
  }
  return count;
}

// ---------------------------------------------------------------------------
// Lazy Gate-B loader. Both statements live inside the accessor: a top-level
// require("tsx/cjs") would break require-time dormancy. The namespace is never
// destructured — every call site reads its function off the namespace object at
// call time, so the authorized test seam can substitute per arm.
// ---------------------------------------------------------------------------
let gateBModule = null;

function gateB() {
  if (gateBModule === null) {
    require("tsx/cjs");
    gateBModule = require("../../../phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts");
  }
  return gateBModule;
}

let obligationModule = null;

function obligationApi() {
  if (obligationModule === null) {
    require("tsx/cjs");
    obligationModule = require("../../../phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts");
  }
  return obligationModule;
}

// ---------------------------------------------------------------------------
// Poison rule. A missing `detail` is non-poisoning: pure-layer errors carry no
// detail and every pure delegation completes strictly before any write, so such
// an error proves nothing was written.
// ---------------------------------------------------------------------------
function poisonRuleFires(error) {
  if (typeof error !== "object" || error === null) return false;
  try {
    if (!(error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError)) {
      return false;
    }
    const codeDescriptor = Object.getOwnPropertyDescriptor(error, "code");
    const detailDescriptor = Object.getOwnPropertyDescriptor(error, "detail");
    if (!codeDescriptor || !("value" in codeDescriptor)) return false;
    if (!detailDescriptor || !("value" in detailDescriptor)) return false;
    const code = codeDescriptor.value;
    if (code === "HOST_PROCESS_POISONED") return true;
    if (code === "HOST_FINALIZED_PROFILE_CONFLICT") return true;
    if (code === "HOST_UNEXPECTED_FINALIZED_PROFILE_ENTRY") return true;
    if (code === "HOST_MULTIPLE_FINALIZED_PROFILES_FOUND") return true;
    if (code === "HOST_CREDENTIAL_OBLIGATION_INVALID") return true;
    if (code === "HOST_CREDENTIAL_OBLIGATION_OVERSIZED") return true;
    if (code === "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH") return true;
    if (code === "HOST_CREDENTIAL_OBLIGATION_TEMP_BOUND_EXCEEDED") return true;
    if (code === "HOST_CREDENTIAL_OBLIGATION_UNEXPECTED_ENTRY") return true;
    const detail = detailDescriptor.value;
    if (typeof detail !== "object" || detail === null) return false;
    const commitDescriptor = Object.getOwnPropertyDescriptor(detail, "commitState");
    if (!commitDescriptor || !("value" in commitDescriptor)) return false;
    const commitState = commitDescriptor.value;
    return commitState === "INDETERMINATE"
      || commitState === "COMMITTED"
      || commitState === "SUPERSESSION_INDETERMINATE"
      || commitState === "OBLIGATION_RETIREMENT_INDETERMINATE";
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------
function createRecoveryGenesisCoordinator(deps) {
  // --- Dependency validation, ordered ------------------------------------
  if (!isObjectLike(deps)) throw coordinatorError(C.COORDINATOR_DEPENDENCIES_NOT_OBJECT);

  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(deps);                   // guard C1
  } catch {
    throw coordinatorError(C.COORDINATOR_DEPENDENCY_ENUMERATION_FAILED);
  }

  for (const key of ownKeys) {
    if (typeof key === "symbol" || !DEPENDENCY_OWN_KEYS.includes(key)) {
      throw coordinatorError(C.COORDINATOR_DEPENDENCY_EXTRA);
    }
  }

  if (!ownKeys.includes("storageRoot")) throw coordinatorError(C.COORDINATOR_DEPENDENCY_MISSING);

  // Presence is decided by own-key membership, never by an undefined test.
  const nowFnProvided = ownKeys.includes("nowFn");
  const livenessProbeFnProvided = ownKeys.includes("livenessProbeFn");
  const randomBytesFnProvided = ownKeys.includes("randomBytesFn");

  const readDependency = (key) => {
    try {
      return Reflect.get(deps, key);                   // guard C2
    } catch {
      throw coordinatorError(C.COORDINATOR_DEPENDENCY_READ_FAILED);
    }
  };

  const storageRoot = readDependency("storageRoot");
  const providedNowFn = nowFnProvided ? readDependency("nowFn") : null;
  const providedLivenessProbeFn = livenessProbeFnProvided
    ? readDependency("livenessProbeFn")
    : null;
  const providedRandomBytesFn = randomBytesFnProvided
    ? readDependency("randomBytesFn")
    : null;

  if (typeof storageRoot !== "string" || storageRoot.length === 0) {
    throw coordinatorError(C.COORDINATOR_DEPENDENCY_INVALID);
  }
  if (nowFnProvided && typeof providedNowFn !== "function") {
    throw coordinatorError(C.COORDINATOR_DEPENDENCY_INVALID);
  }
  if (livenessProbeFnProvided && typeof providedLivenessProbeFn !== "function") {
    throw coordinatorError(C.COORDINATOR_DEPENDENCY_INVALID);
  }
  if (randomBytesFnProvided && typeof providedRandomBytesFn !== "function") {
    throw coordinatorError(C.COORDINATOR_DEPENDENCY_INVALID);
  }

  const nowFn = nowFnProvided ? providedNowFn : defaultNowFn;
  const randomBytesFn = randomBytesFnProvided ? providedRandomBytesFn : crypto.randomBytes;

  // --- Exclusive host ownership ------------------------------------------
  // Optional host dependency keys are OMITTED, never forwarded as undefined:
  // the host decides presence by ownKeys membership and then requires a
  // function, so a forwarded {nowFn: undefined} would fail construction.
  // nowFn and livenessProbeFn cross as the exact same function references.
  // randomBytesFn is never forwarded — the host rejects every other key.
  const hostDeps = { storageRoot };
  if (nowFnProvided) hostDeps.nowFn = providedNowFn;
  if (livenessProbeFnProvided) hostDeps.livenessProbeFn = providedLivenessProbeFn;

  // Construction-time host failure is a constructor failure, not a state: the
  // exact object propagates, no coordinator instance exists, and there is
  // therefore no POISONED instance. No wrapping and no catch here.
  const host = createRecoveryGenesisStagingHost(hostDeps);

  // --- Internal state ----------------------------------------------------
  let closed = false;
  let poisoned = false;
  let reconciled = false;
  let retained = null;
  let finalizedProfile = null;
  let ceremony = null;
  let obligation = null;

  // The §5.4 ladder is the single source of truth for `state`. No method
  // assigns a state literal; every method re-runs this ladder over the six
  // internal fields. derive() takes no arguments.
  function derive() {
    if (closed) return "CLOSED";
    if (poisoned) return "POISONED";
    if (!reconciled) return "UNRECONCILED";
    if (obligation !== null && obligation.state === "ORPHANED") return "ORPHAN_CREDENTIAL_BLOCKED";
    if (finalizedProfile !== null) return "FINALIZED";
    if (retained === null) return "READY_ABSENT";
    if (retained.state !== "STAGING") return "READY_TERMINAL";
    if (populatedCount(retained.manifest) === 3) return "READY_FOR_PROFILE_VALIDATION";
    if (obligation !== null && obligation.state === "CREDENTIAL_RECORDED") return "CREDENTIAL_RECORDED";
    if (obligation !== null && obligation.state === "CREATION_AUTHORIZED") return "CREDENTIAL_CREATION_AUTHORIZED";
    if (obligation !== null && obligation.state === "ACTIVE") return "ROLE_CEREMONY_ACTIVE";
    return "READY_STAGING";
  }

  // The single shared caller-clock guard, defined exactly once and called from
  // exactly two sites: beginRole and status. nowFn is invoked exactly once per
  // call; both a throw (value discarded unread) and an out-of-domain return map
  // to COORDINATOR_INVALID_NOW. This absorbs nothing from any lower layer.
  function sampleCallerClock() {
    let sample;
    try {
      sample = nowFn();                                // guard C8
    } catch {
      throw coordinatorError(C.COORDINATOR_INVALID_NOW);
    }
    if (typeof sample !== "number" || !Number.isSafeInteger(sample)
        || sample < 1 || sample > UINT48_MAX) {
      throw coordinatorError(C.COORDINATOR_INVALID_NOW);
    }
    return sample;
  }

  // The injected randomBytesFn's RESULT is untrusted. Every operation that can
  // invoke caller-controlled code — the brand test, the length read, and
  // Buffer.from — sits inside the guard, because `instanceof` is not total: it
  // walks the operand's prototype chain and therefore throws on a revoked Proxy
  // or a throwing getPrototypeOf trap.
  //
  // This is a guarded prototype-chain test, NOT a nominal brand guarantee: the
  // brand test alone can be forged, since a getPrototypeOf trap may return
  // Uint8Array.prototype. It is not the last line of defence. Verified under the
  // pinned Node 26.0.0: when a forged operand's `length` read reaches the real
  // TypedArray length accessor, that accessor throws for the incompatible
  // receiver, so the guard rejects with COORDINATOR_CEREMONY_ID_GENERATION_FAILED
  // — this is what happens both to a Proxy wrapping a genuine Uint8Array and to
  // an Object.create(Uint8Array.prototype). A forger that also supplies its own
  // `length === 32` data property does pass the whole guarded path; that is
  // accepted and is not an escalation, because randomBytesFn already chooses the
  // ceremony's entropy outright, so such a caller could equally have returned
  // the bytes it wanted. Every rejection discards the raw value unread.
  function generateCeremonyId() {
    let bytes;
    try {
      bytes = randomBytesFn(32);                       // guard C6
    } catch {
      throw coordinatorError(C.COORDINATOR_CEREMONY_ID_GENERATION_FAILED);
    }

    let hex;
    try {                                              // guard C7
      if (!(bytes instanceof Uint8Array)) throw new Error();
      if (bytes.length !== 32) throw new Error();
      hex = Buffer.from(bytes).toString("hex");
    } catch {
      throw coordinatorError(C.COORDINATOR_CEREMONY_ID_GENERATION_FAILED);
    }

    if (!/^[0-9a-f]{64}$/u.test(hex)) {
      throw coordinatorError(C.COORDINATOR_CEREMONY_ID_GENERATION_FAILED);
    }
    return `0x${hex}`;
  }

  // Shared classification body for the Category-B delegation guards. The catch
  // itself stays per-call-site because the rethrow must preserve identity.
  function classifyPoison(error) {
    if (poisonRuleFires(error)) poisoned = true;
  }

  function requireLive() {
    if (closed) throw coordinatorError(C.COORDINATOR_CLOSED);
    if (poisoned) throw coordinatorError(C.COORDINATOR_POISONED);
  }

  // The candidate rejection contract. currentRoleCeremony present as an own key
  // — enumerable or not, string or symbol — is rejected, never overwritten.
  function buildDelegatedCandidate(candidate) {
    if (!isObjectLike(candidate)) throw coordinatorError(C.COORDINATOR_CANDIDATE_NOT_OBJECT);

    let keys;
    try {
      keys = Reflect.ownKeys(candidate);               // guard C3
    } catch {
      throw coordinatorError(C.COORDINATOR_CANDIDATE_ENUMERATION_FAILED);
    }

    for (const key of keys) {
      if (typeof key === "symbol" || !CANDIDATE_OWN_KEYS.includes(key)) {
        throw coordinatorError(C.COORDINATOR_CANDIDATE_EXTRA_KEY);
      }
    }

    if (!keys.includes("descriptor") || !keys.includes("independence")) {
      throw coordinatorError(C.COORDINATOR_CANDIDATE_MISSING_KEY);
    }

    // Independently re-verify every reported key: a name reported by ownKeys
    // with no genuine own descriptor is treated as MISSING, not present.
    const descriptors = new Map();
    try {                                              // guard C4
      for (const key of CANDIDATE_OWN_KEYS) {
        if (!keys.includes(key)) continue;
        const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
        if (descriptor !== undefined) descriptors.set(key, descriptor);
      }
    } catch {
      throw coordinatorError(C.COORDINATOR_CANDIDATE_ENUMERATION_FAILED);
    }

    if (!descriptors.has("descriptor") || !descriptors.has("independence")) {
      throw coordinatorError(C.COORDINATOR_CANDIDATE_MISSING_KEY);
    }

    // Read every value only from its verified descriptor, never via a fresh
    // ordinary lookup. A set-only accessor is rejected outright; a getter is
    // invoked at most once with the candidate as receiver.
    const readFromDescriptor = (descriptor) => {
      if (Object.hasOwn(descriptor, "value")) return descriptor.value;
      if (typeof descriptor.get !== "function") throw new Error();
      return descriptor.get.call(candidate);
    };

    const signerPresent = descriptors.has("signer");
    let descriptorValue;
    let independenceValue;
    let signerValue;
    try {                                              // guard C5
      descriptorValue = readFromDescriptor(descriptors.get("descriptor"));
      independenceValue = readFromDescriptor(descriptors.get("independence"));
      if (signerPresent) signerValue = readFromDescriptor(descriptors.get("signer"));
    } catch {
      throw coordinatorError(C.COORDINATOR_CANDIDATE_READ_FAILED);
    }

    // Setting the ceremony LAST means no caller-controlled assignment can
    // follow it; the null prototype means no inherited setter or toJSON can
    // intercept. A Gate-B error from the projection propagates by identity.
    const delegated = Object.create(null);
    delegated.descriptor = descriptorValue;
    delegated.independence = independenceValue;
    if (signerPresent) delegated.signer = signerValue;
    delegated.currentRoleCeremony =
      obligationApi().toPhilCoreV2GenesisCredentialObligationCeremonyHashInput(obligation);
    return delegated;
  }

  // Post-commit reconciliation (Phase R). Entered only after the host returned
  // a journal. NO THROW MAY ESCAPE IT. This is one of the two bounded Gate-B
  // absorption boundaries; it contains three physical catch statements and is
  // shared by every mutating method that receives a journal.
  function runPostCommitReconciliation(returned, consumedThisCall) {
    retained = returned;                               // 1. adopt FIRST

    let nowNumber = null;                              // 2. best-effort time
    try {
      nowNumber = journalTimeToNumber(returned.updatedAtUnixSeconds);
    } catch {
      nowNumber = null;
    }

    if (ceremony !== null) {                           // 3. best-effort disposition
      try {
        if (nowNumber !== null) {
          const ended = consumedThisCall
            ? gateB().consumePhilCoreV2GenesisRoleCeremony({
              current: ceremony, nowUnixSeconds: nowNumber
            })
            : gateB().observePhilCoreV2GenesisRoleCeremonyStatus({
              current: ceremony, nowUnixSeconds: nowNumber
            });
          if (ended.state === "ENDED") {
            try {
              gateB().retirePhilCoreV2GenesisRoleCeremony({
                current: ended, expectedCeremonyId: ended.ceremonyId
              });
            } catch { /* discarded */ }
          }
        }
      } catch { /* discarded */ }
      ceremony = null;                                 // 4. UNCONDITIONAL discard
    }
  }

  // --- The twelve methods -------------------------------------------------
  const coordinator = {
    reconcileRestart() {
      if (closed) throw coordinatorError(C.COORDINATOR_CLOSED);
      if (poisoned) throw coordinatorError(C.COORDINATOR_POISONED);
      if (reconciled) throw coordinatorError(C.COORDINATOR_ALREADY_RECONCILED);

      let report;
      try {
        report = host.reconcileRestart();              // Phase D, exactly one call
      } catch (error) {
        classifyPoison(error);
        throw error;                                   // same object
      }

      retained = report.journal;
      finalizedProfile = report.finalizedProfile;
      reconciled = true;
      ceremony = null;
      obligation = report.credentialObligation || null;
      return Object.freeze({
        state: derive(),
        outcome: report.outcome,
        corruptionCode: report.corruptionCode,
        journal: retained,
        finalizedProfile: finalizedProfile,
        credentialObligation: obligation,
        credentialOutcome: report.credentialOutcome
      });
    },

    createJournal(intent) {
      requireLive();
      if (derive() !== "READY_ABSENT") throw coordinatorError(C.COORDINATOR_INVALID_STATE);

      // `intent` is forwarded by reference: not enumerated, not copied, not
      // frozen, not validated, not coerced, not probed. The pure layer reads it
      // hostile-safely and its errors propagate by identity.
      let returned;
      try {
        returned = host.createJournal(intent).journal;  // Phase D
      } catch (error) {
        classifyPoison(error);
        throw error;
      }

      runPostCommitReconciliation(returned, false);
      return Object.freeze({ state: derive(), journal: returned });
    },

    beginRole() {
      if (closed) throw coordinatorError(C.COORDINATOR_CLOSED);
      if (poisoned) throw coordinatorError(C.COORDINATOR_POISONED);
      if (derive() !== "READY_STAGING") throw coordinatorError(C.COORDINATOR_INVALID_STATE);

      // Exactly one sample, unconditionally and before any other work, through
      // the shared helper — never re-implemented here. beginRole itself has no
      // catch, so a Gate-B mint error propagates by identity.
      const sample = sampleCallerClock();
      const journalTime = journalTimeToNumber(retained.updatedAtUnixSeconds);
      if (sample < journalTime) {
        throw coordinatorError(C.COORDINATOR_CLOCK_REGRESSION_DETECTED);
      }

      const roleNumber = populatedCount(retained.manifest);
      const ceremonyId = generateCeremonyId();

      const minted = gateB().mintPhilCoreV2GenesisRoleCeremony({
        current: null,
        ceremonyId: ceremonyId,
        role: BigInt(roleNumber),
        genesisDeploymentIntentHash: retained.genesisDeploymentIntentHash,
        intentExpiresAtUnixSeconds: BigInt(retained.expiresAt),
        nowUnixSeconds: sample
      });

      let returned;
      try {
        returned = host.beginCredentialObligation(minted);
      } catch (error) {
        classifyPoison(error);
        throw error;
      }

      ceremony = minted;
      obligation = returned.obligation;
      return Object.freeze({
        state: derive(),
        role: roleNumber,
        ceremony: minted,
        obligation: obligation
      });
    },

    authorizeCredentialCreation() {
      requireLive();
      if (derive() !== "ROLE_CEREMONY_ACTIVE") {
        throw coordinatorError(C.COORDINATOR_INVALID_STATE);
      }
      let returned;
      try {
        returned = host.authorizeCredentialCreation(obligation.ceremonyId);
      } catch (error) {
        classifyPoison(error);
        throw error;
      }
      obligation = returned.obligation;
      return Object.freeze({ state: derive(), obligation: obligation });
    },

    recordCreatedCredential(input) {
      requireLive();
      if (derive() !== "CREDENTIAL_CREATION_AUTHORIZED") {
        throw coordinatorError(C.COORDINATOR_INVALID_STATE);
      }
      const forwarded = Object.create(null);
      forwarded.expectedCeremonyId = obligation.ceremonyId;
      if (isObjectLike(input)) {
        for (const key of ["credentialIdHash", "publicVerificationMaterialHash"]) {
          let descriptor;
          try {
            descriptor = Object.getOwnPropertyDescriptor(input, key);
          } catch {
            descriptor = undefined;
          }
          if (!descriptor) continue;
          try {
            if (Object.prototype.hasOwnProperty.call(descriptor, "value")) {
              forwarded[key] = descriptor.value;
            } else if (typeof descriptor.get === "function") {
              forwarded[key] = descriptor.get.call(input);
            }
          } catch {
            forwarded[key] = undefined;
          }
        }
      }
      let returned;
      try {
        returned = host.recordCreatedCredential(forwarded);
      } catch (error) {
        classifyPoison(error);
        throw error;
      }
      obligation = returned.obligation;
      return Object.freeze({ state: derive(), obligation: obligation });
    },

    stageRole(candidate) {
      requireLive();
      if (derive() !== "CREDENTIAL_RECORDED") {
        throw coordinatorError(C.COORDINATOR_INVALID_STATE);
      }

      // No lazy expiry and no clock sample before the host call: the pure layer
      // resolves journal expiry first and returns a durable EXPIRED journal, so
      // pre-expiring would convert that into a non-durable coordinator error.
      const roleNumber = populatedCount(retained.manifest);
      const delegated = buildDelegatedCandidate(candidate);

      let returned;
      let returnedObligation;
      try {
        const hostResult = host.stageRole(roleNumber, delegated);   // Phase D
        returned = hostResult.journal;
        returnedObligation = hostResult.obligation;
      } catch (error) {
        classifyPoison(error);
        throw error;
      }

      const staged = returned.state === "STAGING";
      runPostCommitReconciliation(returned, staged);
      obligation = returnedObligation;
      return Object.freeze({
        state: derive(),
        role: roleNumber,
        staged: staged,
        journal: returned,
        ceremony: null,
        obligation: obligation
      });
    },

    // The guaranteed escape hatch: no host call, and non-throwing after its
    // guards. This is the second bounded Gate-B absorption boundary, with three
    // physical catch statements. It deliberately does NOT use the shared clock
    // helper, which throws; its own guard yields null instead.
    cancelRoleCeremony() {
      requireLive();
      const current = derive();
      if (
        current !== "ROLE_CEREMONY_ACTIVE"
        && current !== "CREDENTIAL_CREATION_AUTHORIZED"
        && current !== "CREDENTIAL_RECORDED"
        && current !== "ORPHAN_CREDENTIAL_BLOCKED"
      ) {
        throw coordinatorError(C.COORDINATOR_INVALID_STATE);
      }

      let returned;
      try {
        returned = host.cancelCredentialObligation(obligation.ceremonyId);
      } catch (error) {
        classifyPoison(error);
        throw error;
      }

      obligation = returned.obligation;
      ceremony = null;
      return Object.freeze({ state: derive(), ceremony: null, obligation: obligation });
    },

    cancelEnrollment() {
      requireLive();
      const current = derive();
      if (current !== "READY_STAGING" && current !== "ROLE_CEREMONY_ACTIVE"
          && current !== "CREDENTIAL_CREATION_AUTHORIZED"
          && current !== "CREDENTIAL_RECORDED"
          && current !== "ORPHAN_CREDENTIAL_BLOCKED"
          && current !== "READY_FOR_PROFILE_VALIDATION") {
        throw coordinatorError(C.COORDINATOR_INVALID_STATE);
      }

      let returned;
      try {
        returned = host.cancel();                      // Phase D
      } catch (error) {
        classifyPoison(error);
        throw error;
      }

      // host.cancel() creates no manifest entry, so it never consumes.
      runPostCommitReconciliation(returned.journal, false);
      obligation = returned.obligation === undefined ? null : returned.obligation;
      return Object.freeze({
        state: derive(),
        journal: returned.journal,
        ceremony: null,
        obligation: obligation
      });
    },

    finalizeProfile(expectedValidationResult) {
      requireLive();
      if (derive() !== "READY_FOR_PROFILE_VALIDATION") {
        throw coordinatorError(C.COORDINATOR_INVALID_STATE);
      }
      if (ceremony !== null && ceremony.state === "ACTIVE") {
        throw coordinatorError(C.COORDINATOR_INVALID_STATE);
      }

      let returned;
      try {
        returned = host.finalizeProfile(expectedValidationResult);
      } catch (error) {
        classifyPoison(error);
        throw error;
      }

      finalizedProfile = returned.finalizedProfile;
      retained = returned.journal;
      ceremony = null;
      return Object.freeze({
        state: derive(),
        finalizedProfile: finalizedProfile,
        journal: retained
      });
    },

    // In-memory plus lazy ceremony expiry. It never calls host.status(), which
    // returns only a state literal and would buy nothing but a syscall. status
    // is not an absorption point: its Gate-B observe call is entirely
    // unguarded, its own body contains no try/catch at all, and its only
    // reachable catch is the shared caller-clock guard.
    status() {
      if (closed) throw coordinatorError(C.COORDINATOR_CLOSED);
      if (poisoned) throw coordinatorError(C.COORDINATOR_POISONED);

      const sample = sampleCallerClock();

      if (retained !== null) {
        const journalTime = journalTimeToNumber(retained.updatedAtUnixSeconds);
        if (sample < journalTime) {
          throw coordinatorError(C.COORDINATOR_CLOCK_REGRESSION_DETECTED);
        }
      }

      if (ceremony !== null && obligation !== null && obligation.state === "ACTIVE") {
        const observed = gateB().observePhilCoreV2GenesisRoleCeremonyStatus({
          current: ceremony, nowUnixSeconds: sample
        });
        if (observed.state === "ENDED") {
          let returned;
          try {
            returned = host.cancelCredentialObligation(obligation.ceremonyId);
          } catch (error) {
            classifyPoison(error);
            throw error;
          }
          obligation = returned.obligation;
          ceremony = null;
        } else {
          ceremony = observed;
        }
      }

      const state = derive();
      const nextRole = (state === "READY_STAGING" || state === "ROLE_CEREMONY_ACTIVE")
        ? populatedCount(retained.manifest)
        : null;
      const snapshot = {
        state,
        journal: retained,
        nextRole,
        ceremony,
        credentialObligation: obligation
      };
      if (state === "FINALIZED") snapshot.finalizedProfile = finalizedProfile;
      return Object.freeze(snapshot);
    },

    // Takes no arguments: the coordinator supplies both fields from its own
    // retained record, removing a hostile-input surface. The record is the
    // host's own deep-frozen output, so ordinary property access is correct.
    // This is the post-success specialization, NOT the generic Phase R: the
    // host returns no journal, so there is nothing to adopt or convert.
    acknowledgeTerminal() {
      requireLive();
      const current = derive();

      if (current === "FINALIZED") {
        if (retained === null) {
          return Object.freeze({ state: derive(), acknowledged: false });
        }
        if (retained.state !== "SUPERSEDED") {
          throw coordinatorError(C.COORDINATOR_INVALID_STATE);
        }

        const ack = {
          intentId: retained.intentId,
          integrityChecksum: retained.integrityChecksum
        };

        try {
          host.acknowledgeTerminal(ack);               // Phase D
        } catch (error) {
          classifyPoison(error);
          throw error;                                 // nothing is cleared
        }

        retained = null;
        ceremony = null;
        return Object.freeze({ state: derive(), acknowledged: true });
      }

      if (current !== "READY_TERMINAL") {
        throw coordinatorError(C.COORDINATOR_INVALID_STATE);
      }

      const ack = {
        intentId: retained.intentId,
        integrityChecksum: retained.integrityChecksum
      };

      try {
        host.acknowledgeTerminal(ack);                 // Phase D
      } catch (error) {
        classifyPoison(error);
        throw error;                                   // nothing is cleared
      }

      retained = null;
      ceremony = null;
      reconciled = true;
      return Object.freeze({ state: derive(), acknowledged: true });
    },

    // Zero clock samples and zero Gate-B operations.
    close() {
      if (closed) return undefined;
      if (poisoned) throw coordinatorError(C.COORDINATOR_POISONED);

      // The ceremony is in-memory only, the coordinator is its sole holder, and
      // no durable record refers to it, so a bare discard is complete disposal.
      ceremony = null;

      try {
        host.close();
      } catch (error) {
        // The host's lock release poisons the root on every failure path and
        // leaves its own closed flag false, so a retry would re-probe a
        // possibly-removed lock. Non-retryable; the same object is rethrown.
        poisoned = true;
        throw error;
      }

      closed = true;
      retained = null;
      return undefined;
    }
  };

  return Object.freeze(coordinator);
}

module.exports = {
  createRecoveryGenesisCoordinator,
  PhilCoreV2RecoveryGenesisCoordinatorError,
  PHILCORE_V2_RECOVERY_GENESIS_COORDINATOR_ERROR_CODE
};
