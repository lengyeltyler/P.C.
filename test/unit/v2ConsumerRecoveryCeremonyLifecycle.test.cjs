require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { getAddress } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const MODULE_PATH = path.join(
  ROOT,
  "apps/phil-device-sdk/src/v2ConsumerRecoveryCeremonyLifecycle.ts"
);

const {
  computePhilCoreV2LocalEnrollmentCeremonyHash,
  PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
  PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
  PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID
} = require("../../apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts");

const lifecycle = require("../../apps/phil-device-sdk/src/v2ConsumerRecoveryCeremonyLifecycle.ts");

const CEREMONY_ID =
  "0x827fb6a1d6c993f9398090b62cbb32171b4fdc11fc6b9d885f263e18402faf34";
const ALT_CEREMONY_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const ACCOUNT = "0xd5520BEEC59848D796EBA0badAa9c65f1be6E6F6";
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const CHAIN_ID = "11155111";
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const UINT48_MAX = (1n << 48n) - 1n;
const MINTED_AT = 1_700_000_000;
const EXPECTED_HASH =
  "0xa25696743026591b11d05287ac1b31fbcca2f26140a08d79bedf565b71d515e7";

function expectations(overrides = {}) {
  return {
    account: ACCOUNT,
    chainId: CHAIN_ID,
    entryPoint: ENTRY_POINT,
    expectedRecoveryEpoch: "1",
    expectedValidatorEpoch: "1",
    ...overrides
  };
}

function mintArgs(overrides = {}) {
  return {
    current: null,
    ceremonyId: CEREMONY_ID,
    nowUnixSeconds: MINTED_AT,
    expectations: expectations(),
    ...overrides
  };
}

function assertCode(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(error.name, "PhilCoreV2ConsumerRecoveryCeremonyLifecycleError");
    assert.equal(error.code, code, `expected ${code}, got ${error.code}`);
    return true;
  });
}

function independentHash(ceremonyId, expiresAt) {
  return computePhilCoreV2LocalEnrollmentCeremonyHash({
    ceremonyId,
    account: ACCOUNT,
    chainId: CHAIN_ID,
    entryPoint: ENTRY_POINT,
    accountVersionId: PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_LOCAL_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID,
    expectedRecoveryEpoch: "1",
    expectedValidatorEpoch: "1",
    expiresAt: String(expiresAt)
  });
}

describe("PhilCore V2 consumer recovery ceremony lifecycle (5B-0 pure)", function () {
  it("locks TTL and pinned authority constants", function () {
    assert.equal(lifecycle.PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS, 300n);
    assert.equal(
      lifecycle.PHILCORE_V2_RECOVERY_CEREMONY_ACCOUNT_VERSION_ID,
      PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID
    );
    assert.equal(
      lifecycle.PHILCORE_V2_RECOVERY_CEREMONY_SECURITY_MODEL_ID,
      PHILCORE_V2_LOCAL_SECURITY_MODEL_ID
    );
    assert.equal(
      lifecycle.PHILCORE_V2_RECOVERY_CEREMONY_RECOVERY_DOMAIN_ID,
      PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID
    );
  });

  it("mints from absence with canonical hash matching independent Package 5A computation", function () {
    const record = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    assert.equal(record.state, "ACTIVE");
    assert.equal(record.endReason, null);
    assert.equal(record.ceremonyId, CEREMONY_ID);
    assert.equal(record.mintedAtUnixSeconds, BigInt(MINTED_AT));
    assert.equal(record.expiresAtUnixSeconds, BigInt(MINTED_AT + 300));
    assert.equal(record.lastObservedAtUnixSeconds, BigInt(MINTED_AT));
    assert.equal(record.account, getAddress(ACCOUNT));
    assert.equal(record.chainId, 11155111n);
    assert.equal(record.entryPoint, getAddress(ENTRY_POINT));
    assert.equal(record.expectedRecoveryEpoch, 1n);
    assert.equal(record.expectedValidatorEpoch, 1n);
    assert.equal(record.accountVersionId, PHILCORE_V2_LOCAL_ACCOUNT_VERSION_ID);
    assert.equal(record.securityModelId, PHILCORE_V2_LOCAL_SECURITY_MODEL_ID);
    assert.equal(record.recoveryDomainId, PHILCORE_V2_LOCAL_RECOVERY_DOMAIN_ID);
    assert.equal(record.enrollmentCeremonyHash, EXPECTED_HASH);
    assert.equal(
      record.enrollmentCeremonyHash,
      independentHash(CEREMONY_ID, MINTED_AT + 300)
    );
  });

  it("never accepts a caller-precomputed enrollment hash", function () {
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony({
        ...mintArgs(),
        expectations: {
          ...expectations(),
          enrollmentCeremonyHash: EXPECTED_HASH
        }
      }),
      "INVALID_EXPECTED_CONTEXT"
    );
    const source = fs.readFileSync(MODULE_PATH, "utf8");
    assert.equal(/enrollmentCeremonyHash\s*:/.test(
      source.split("mintPhilCoreV2ConsumerRecoveryCeremony")[1]?.slice(0, 800) || ""
    ) && source.includes("input.enrollmentCeremonyHash"), false);
  });

  it("rejects mint while an unexpired ACTIVE ceremony exists", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        current: active,
        ceremonyId: ALT_CEREMONY_ID,
        nowUnixSeconds: MINTED_AT + 10
      })),
      "CEREMONY_ALREADY_ACTIVE"
    );
  });

  it("rejects direct mint against expired-but-unobserved ACTIVE", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    assert.equal(active.state, "ACTIVE");
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        current: active,
        ceremonyId: ALT_CEREMONY_ID,
        nowUnixSeconds: MINTED_AT + 300
      })),
      "CEREMONY_ALREADY_ACTIVE"
    );
    assert.equal(active.state, "ACTIVE");
    assert.equal(active.endReason, null);
    assert.equal(active.ceremonyId, CEREMONY_ID);
  });

  it("rejects mint against ENDED records until retirement clears the slot", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    const cancelled = lifecycle.cancelPhilCoreV2ConsumerRecoveryCeremony({
      current: active,
      nowUnixSeconds: MINTED_AT + 1
    });
    assert.equal(cancelled.state, "ENDED");
    assert.equal(cancelled.endReason, "CANCELLED");
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        current: cancelled,
        ceremonyId: ALT_CEREMONY_ID,
        nowUnixSeconds: MINTED_AT + 2
      })),
      "CEREMONY_PENDING_RETIREMENT"
    );

    const expired = lifecycle.evaluatePhilCoreV2ConsumerRecoveryCeremonyStatus({
      current: active,
      nowUnixSeconds: MINTED_AT + 300
    });
    assert.equal(expired.state, "ENDED");
    assert.equal(expired.endReason, "EXPIRED");
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        current: expired,
        ceremonyId: ALT_CEREMONY_ID,
        nowUnixSeconds: MINTED_AT + 300
      })),
      "CEREMONY_PENDING_RETIREMENT"
    );
  });

  it("preserves expired identity and allows mint only from an absent slot after retirement", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    const expired = lifecycle.evaluatePhilCoreV2ConsumerRecoveryCeremonyStatus({
      current: active,
      nowUnixSeconds: MINTED_AT + 300
    });
    assert.equal(expired.state, "ENDED");
    assert.equal(expired.endReason, "EXPIRED");
    assert.equal(expired.ceremonyId, active.ceremonyId);
    assert.equal(expired.enrollmentCeremonyHash, active.enrollmentCeremonyHash);
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        current: expired,
        ceremonyId: ALT_CEREMONY_ID,
        nowUnixSeconds: MINTED_AT + 300
      })),
      "CEREMONY_PENDING_RETIREMENT"
    );

    // Pure mint may proceed only once the installed slot is absent (host retire clears it).
    const next = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
      current: null,
      ceremonyId: ALT_CEREMONY_ID,
      nowUnixSeconds: MINTED_AT + 300
    }));
    assert.equal(next.state, "ACTIVE");
    assert.equal(next.ceremonyId, ALT_CEREMONY_ID);
    assert.notEqual(next.ceremonyId, expired.ceremonyId);
    assert.equal(next.mintedAtUnixSeconds, BigInt(MINTED_AT + 300));
    assert.equal(
      next.enrollmentCeremonyHash,
      independentHash(ALT_CEREMONY_ID, MINTED_AT + 600)
    );
  });

  it("locks the five retirement error codes and forbids an SDK retirement acknowledge export", function () {
    const codes = lifecycle.PHILCORE_V2_CONSUMER_RECOVERY_CEREMONY_ERROR_CODE;
    assert.equal(codes.CEREMONY_PENDING_RETIREMENT, "CEREMONY_PENDING_RETIREMENT");
    assert.equal(codes.RETIREMENT_CEREMONY_ID_INVALID, "RETIREMENT_CEREMONY_ID_INVALID");
    assert.equal(codes.CEREMONY_NOT_INSTALLED, "CEREMONY_NOT_INSTALLED");
    assert.equal(codes.CEREMONY_STILL_ACTIVE, "CEREMONY_STILL_ACTIVE");
    assert.equal(codes.CEREMONY_ID_MISMATCH, "CEREMONY_ID_MISMATCH");
    assert.ok(Object.isFrozen(codes));

    assert.equal(
      typeof lifecycle.acknowledgePhilCoreV2ConsumerRecoveryCeremonyRetirement,
      "undefined"
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(
        lifecycle,
        "acknowledgePhilCoreV2ConsumerRecoveryCeremonyRetirement"
      ),
      false
    );
  });

  it("cancels an ACTIVE ceremony and expires cancel at exact expiry boundary", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    const cancelled = lifecycle.cancelPhilCoreV2ConsumerRecoveryCeremony({
      current: active,
      nowUnixSeconds: MINTED_AT + 50
    });
    assert.equal(cancelled.state, "ENDED");
    assert.equal(cancelled.endReason, "CANCELLED");
    assert.equal(cancelled.lastObservedAtUnixSeconds, BigInt(MINTED_AT + 50));

    const active2 = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
      current: null,
      ceremonyId: ALT_CEREMONY_ID,
      nowUnixSeconds: MINTED_AT + 60
    }));
    const expiredViaCancel = lifecycle.cancelPhilCoreV2ConsumerRecoveryCeremony({
      current: active2,
      nowUnixSeconds: Number(active2.expiresAtUnixSeconds)
    });
    assert.equal(expiredViaCancel.state, "ENDED");
    assert.equal(expiredViaCancel.endReason, "EXPIRED");
  });

  it("checks expiry immediately before and exactly at the boundary", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    const stillActive = lifecycle.checkPhilCoreV2ConsumerRecoveryCeremonyExpiry({
      current: active,
      nowUnixSeconds: MINTED_AT + 299
    });
    assert.equal(stillActive.state, "ACTIVE");
    assert.equal(stillActive.endReason, null);
    assert.equal(stillActive.lastObservedAtUnixSeconds, BigInt(MINTED_AT + 299));

    const expired = lifecycle.checkPhilCoreV2ConsumerRecoveryCeremonyExpiry({
      current: stillActive,
      nowUnixSeconds: MINTED_AT + 300
    });
    assert.equal(expired.state, "ENDED");
    assert.equal(expired.endReason, "EXPIRED");
    assert.equal(expired.enrollmentCeremonyHash, active.enrollmentCeremonyHash);
  });

  it("rejects clock regression on mint, cancel, expiry, and status evaluation", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    const observed = lifecycle.checkPhilCoreV2ConsumerRecoveryCeremonyExpiry({
      current: active,
      nowUnixSeconds: MINTED_AT + 10
    });
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        current: observed,
        ceremonyId: ALT_CEREMONY_ID,
        nowUnixSeconds: MINTED_AT + 9
      })),
      "CEREMONY_ALREADY_ACTIVE"
    );
    assertCode(
      () => lifecycle.cancelPhilCoreV2ConsumerRecoveryCeremony({
        current: observed,
        nowUnixSeconds: MINTED_AT + 9
      }),
      "CLOCK_REGRESSION_DETECTED"
    );
    assertCode(
      () => lifecycle.checkPhilCoreV2ConsumerRecoveryCeremonyExpiry({
        current: observed,
        nowUnixSeconds: MINTED_AT + 9
      }),
      "CLOCK_REGRESSION_DETECTED"
    );
    assertCode(
      () => lifecycle.evaluatePhilCoreV2ConsumerRecoveryCeremonyStatus({
        current: observed,
        nowUnixSeconds: MINTED_AT + 9
      }),
      "CLOCK_REGRESSION_DETECTED"
    );
  });

  it("accepts uint48 exact expiry boundary and rejects first overflow", function () {
    const boundaryMinted = Number(UINT48_MAX - 300n);
    const ok = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
      nowUnixSeconds: boundaryMinted
    }));
    assert.equal(ok.expiresAtUnixSeconds, UINT48_MAX);

    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        nowUnixSeconds: Number(UINT48_MAX - 299n)
      })),
      "EXPIRY_OVERFLOW"
    );
  });

  it("rejects invalid ceremony IDs and expected context", function () {
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        ceremonyId: ZERO_BYTES32
      })),
      "INVALID_INJECTED_CEREMONY_ID"
    );
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        ceremonyId: "0x1234"
      })),
      "INVALID_INJECTED_CEREMONY_ID"
    );
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        expectations: expectations({ account: ZERO_ADDRESS })
      })),
      "INVALID_EXPECTED_CONTEXT"
    );
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        expectations: expectations({ chainId: "0" })
      })),
      "INVALID_EXPECTED_CONTEXT"
    );
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        expectations: expectations({ entryPoint: "not-an-address" })
      })),
      "INVALID_EXPECTED_CONTEXT"
    );
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        expectations: expectations({ expectedRecoveryEpoch: "0" })
      })),
      "INVALID_EXPECTED_CONTEXT"
    );
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        expectations: expectations({ expectedValidatorEpoch: 1 })
      })),
      "INVALID_EXPECTED_CONTEXT"
    );
  });

  it("accepts epochs greater than 1 and rejects invalid now", function () {
    const record = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
      expectations: expectations({
        expectedRecoveryEpoch: "9",
        expectedValidatorEpoch: "7"
      })
    }));
    assert.equal(record.expectedRecoveryEpoch, 9n);
    assert.equal(record.expectedValidatorEpoch, 7n);
    assert.match(record.enrollmentCeremonyHash, /^0x[0-9a-f]{64}$/);

    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        nowUnixSeconds: 0
      })),
      "INVALID_NOW"
    );
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        nowUnixSeconds: 1.5
      })),
      "INVALID_NOW"
    );
    assertCode(
      () => lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs({
        nowUnixSeconds: Number.MAX_SAFE_INTEGER + 1
      })),
      "INVALID_NOW"
    );
  });

  it("freezes records and rejects operations on non-active terminals", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    assert.ok(Object.isFrozen(active));
    assert.equal(
      Object.getOwnPropertyDescriptor(active, "state")?.writable,
      false
    );
    const cancelled = lifecycle.cancelPhilCoreV2ConsumerRecoveryCeremony({
      current: active,
      nowUnixSeconds: MINTED_AT + 1
    });
    assertCode(
      () => lifecycle.cancelPhilCoreV2ConsumerRecoveryCeremony({
        current: cancelled,
        nowUnixSeconds: MINTED_AT + 2
      }),
      "CEREMONY_NOT_ACTIVE"
    );
    assertCode(
      () => lifecycle.checkPhilCoreV2ConsumerRecoveryCeremonyExpiry({
        current: cancelled,
        nowUnixSeconds: MINTED_AT + 2
      }),
      "CEREMONY_NOT_ACTIVE"
    );
  });

  it("status evaluation lazily expires ACTIVE and updates lastObserved on ENDED", function () {
    const active = lifecycle.mintPhilCoreV2ConsumerRecoveryCeremony(mintArgs());
    const expired = lifecycle.evaluatePhilCoreV2ConsumerRecoveryCeremonyStatus({
      current: active,
      nowUnixSeconds: MINTED_AT + 300
    });
    assert.equal(expired.state, "ENDED");
    assert.equal(expired.endReason, "EXPIRED");

    const observedEnded = lifecycle.evaluatePhilCoreV2ConsumerRecoveryCeremonyStatus({
      current: expired,
      nowUnixSeconds: MINTED_AT + 301
    });
    assert.equal(observedEnded.state, "ENDED");
    assert.equal(observedEnded.endReason, "EXPIRED");
    assert.equal(observedEnded.lastObservedAtUnixSeconds, BigInt(MINTED_AT + 301));
  });

  it("exports no factor/completion APIs and imports no clock/random/Desktop/iOS", function () {
    for (const key of Object.keys(lifecycle)) {
      assert.ok(!/^sign/i.test(key));
      assert.ok(!/factor|staging|complete|verify|persist|ipc|retire|acknowledge/i.test(key));
    }
    assert.equal(
      typeof lifecycle.acknowledgePhilCoreV2ConsumerRecoveryCeremonyRetirement,
      "undefined"
    );
    const source = fs.readFileSync(MODULE_PATH, "utf8");
    assert.equal(/Date\.now|node:crypto|randomBytes|electron|philcore-desktop|apps\/ios/i.test(source), false);
    assert.equal(/fs\.|fetch\(|http\.|net\./.test(source), false);
    assert.equal(
      source.includes("acknowledgePhilCoreV2ConsumerRecoveryCeremonyRetirement"),
      false
    );
    assert.ok(source.includes("computePhilCoreV2LocalEnrollmentCeremonyHash"));
  });
});
