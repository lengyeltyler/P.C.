"use strict";

const crypto = require("node:crypto");
require("tsx/cjs");

const lifecycle = require("../../../phil-device-sdk/src/v2ConsumerRecoveryCeremonyLifecycle.ts");

const {
  PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS,
  PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE,
  mintPhilCoreV2ConsumerRecoveryCeremony,
  cancelPhilCoreV2ConsumerRecoveryCeremony,
  checkPhilCoreV2ConsumerRecoveryCeremonyExpiry,
  evaluatePhilCoreV2ConsumerRecoveryCeremonyStatus,
  normalizePhilCoreV2ConsumerRecoveryCeremonyExpectations,
  PhilCoreV2ConsumerRecoveryCeremonyLifecycleError
} = lifecycle;

const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const RETIREMENT_CEREMONY_ID_RE = /^0x[0-9a-fA-F]{64}$/;

function defaultNowUnixSeconds() {
  return Math.floor(Date.now() / 1000);
}

function bytesToCeremonyId(bytes) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
      PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_INJECTED_CEREMONY_ID
    );
  }
  const buffer = Buffer.from(bytes);
  if (buffer.length !== 32) {
    throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
      PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_INJECTED_CEREMONY_ID
    );
  }
  return `0x${buffer.toString("hex")}`;
}

function snapshot(record) {
  if (record === null) return null;
  return Object.freeze({ ...record });
}

function normalizeRetirementCeremonyId(value) {
  if (typeof value !== "string" || !RETIREMENT_CEREMONY_ID_RE.test(value)) {
    throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
      PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.RETIREMENT_CEREMONY_ID_INVALID
    );
  }
  const normalized = value.toLowerCase();
  if (normalized === ZERO_BYTES32) {
    throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
      PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.RETIREMENT_CEREMONY_ID_INVALID
    );
  }
  return normalized;
}

/**
 * Main-only dormant ceremony host.
 * No renderer surface, no channel registration, and no production wiring in Package 5B-0.1.
 */
function createRecoveryCeremonyHost(deps = {}) {
  if (deps === null || typeof deps !== "object" || Array.isArray(deps)) {
    throw new TypeError("createRecoveryCeremonyHost deps must be an object");
  }
  const allowed = new Set(["nowFn", "randomBytesFn"]);
  for (const key of Object.keys(deps)) {
    if (!allowed.has(key)) {
      throw new TypeError(`unexpected host dependency: ${key}`);
    }
  }

  const nowFn = Object.prototype.hasOwnProperty.call(deps, "nowFn")
    ? deps.nowFn
    : defaultNowUnixSeconds;
  const randomBytesFn = Object.prototype.hasOwnProperty.call(deps, "randomBytesFn")
    ? deps.randomBytesFn
    : crypto.randomBytes;

  if (typeof nowFn !== "function") {
    throw new TypeError("nowFn must be a function");
  }
  if (typeof randomBytesFn !== "function") {
    throw new TypeError("randomBytesFn must be a function");
  }

  let current = null;

  return Object.freeze({
    mint(callerExpectations) {
      if (current !== null) {
        if (current.state === "ACTIVE") {
          throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
            PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_ALREADY_ACTIVE
          );
        }
        if (current.state === "ENDED") {
          throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
            PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_PENDING_RETIREMENT
          );
        }
        throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
          PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_RECORD
        );
      }
      const nowUnixSeconds = nowFn();
      normalizePhilCoreV2ConsumerRecoveryCeremonyExpectations(callerExpectations);
      const ceremonyId = bytesToCeremonyId(randomBytesFn(32));
      current = mintPhilCoreV2ConsumerRecoveryCeremony({
        current,
        ceremonyId,
        nowUnixSeconds,
        expectations: callerExpectations
      });
      return snapshot(current);
    },

    cancel() {
      if (current === null) {
        throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
          PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_NOT_ACTIVE
        );
      }
      const nowUnixSeconds = nowFn();
      current = cancelPhilCoreV2ConsumerRecoveryCeremony({
        current,
        nowUnixSeconds
      });
      return snapshot(current);
    },

    checkExpiry() {
      if (current === null) {
        throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
          PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_NOT_ACTIVE
        );
      }
      const nowUnixSeconds = nowFn();
      current = checkPhilCoreV2ConsumerRecoveryCeremonyExpiry({
        current,
        nowUnixSeconds
      });
      return snapshot(current);
    },

    status() {
      if (current === null) return null;
      const nowUnixSeconds = nowFn();
      current = evaluatePhilCoreV2ConsumerRecoveryCeremonyStatus({
        current,
        nowUnixSeconds
      });
      return snapshot(current);
    },

    retire(expectedCeremonyId) {
      const expectedId = normalizeRetirementCeremonyId(expectedCeremonyId);
      if (current === null) {
        throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
          PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_NOT_INSTALLED
        );
      }
      if (current.state === "ACTIVE") {
        throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
          PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_STILL_ACTIVE
        );
      }
      if (current.state !== "ENDED") {
        throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
          PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.INVALID_RECORD
        );
      }
      if (current.ceremonyId !== expectedId) {
        throw new PhilCoreV2ConsumerRecoveryCeremonyLifecycleError(
          PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE.CEREMONY_ID_MISMATCH
        );
      }
      const retired = snapshot(current);
      current = null;
      return retired;
    }
  });
}

module.exports = {
  createRecoveryCeremonyHost,
  PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS,
  PhilCoreV2ConsumerRecoveryCeremonyLifecycleError
};
