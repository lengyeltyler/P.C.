"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Module = require("node:module");

// Desktop lane runs this file with `node` (no mocha). Provide a minimal harness.
const __nodeSuite = { beforeEach: null, tests: [] };
const __usedNodeShim = typeof describe !== "function";
if (__usedNodeShim) {
  global.describe = function describe(_name, fn) {
    const ctx = { timeout() {} };
    fn.call(ctx);
  };
  global.it = function it(name, fn) {
    __nodeSuite.tests.push({ name, fn });
  };
  global.beforeEach = function beforeEach(fn) {
    __nodeSuite.beforeEach = fn;
  };
}

const HOST_PATH = path.resolve(
  __dirname,
  "../src/main/recovery-ceremony-host.cjs"
);
const MAIN_PATH = path.resolve(__dirname, "../src/main/main.cjs");
const PRELOAD_DIR = path.resolve(__dirname, "../src/preload");

const REAL_REQUIRE = Module.prototype.require;
let requireGuardEnabled = false;
let cryptoRandomBytesCalls = 0;

Module.prototype.require = function guardedRequire(request) {
  if (
    requireGuardEnabled
    && (request === "node:crypto" || request === "crypto")
  ) {
    const crypto = REAL_REQUIRE.apply(this, arguments);
    return new Proxy(crypto, {
      get(target, prop, receiver) {
        if (prop === "randomBytes") {
          return function trackedRandomBytes() {
            cryptoRandomBytesCalls += 1;
            throw new Error("REAL_CRYPTO_RANDOMBYTES_MUST_NOT_EXECUTE_IN_TESTS");
          };
        }
        return Reflect.get(target, prop, receiver);
      }
    });
  }
  return REAL_REQUIRE.apply(this, arguments);
};

requireGuardEnabled = true;
const hostModule = require("../src/main/recovery-ceremony-host.cjs");
requireGuardEnabled = false;

const {
  createRecoveryCeremonyHost,
  PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS
} = hostModule;


const LABEL_A = Buffer.from(
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "hex"
);
const LABEL_B = Buffer.from(
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "hex"
);
const LABEL_C = Buffer.from(
  "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "hex"
);

function hex32(buffer) {
  return `0x${Buffer.from(buffer).toString("hex")}`;
}

function expectations(overrides = {}) {
  return {
    account: "0xd5520BEEC59848D796EBA0badAa9c65f1be6E6F6",
    chainId: "11155111",
    entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
    expectedRecoveryEpoch: "1",
    expectedValidatorEpoch: "1",
    ...overrides
  };
}

function createHarness(buffers, startNow = 1_700_000_000) {
  let cursor = 0;
  let now = startNow;
  let randomCalls = 0;
  let nowCalls = 0;
  const randomBytesFn = (size) => {
    assert.equal(size, 32);
    randomCalls += 1;
    assert.ok(cursor < buffers.length, "random buffer sequence exhausted");
    const next = buffers[cursor];
    cursor += 1;
    assert.equal(Buffer.isBuffer(next), true);
    assert.equal(next.length, 32);
    assert.notEqual(next.equals(Buffer.alloc(32, 0)), true);
    return Buffer.from(next);
  };
  const host = createRecoveryCeremonyHost({
    nowFn: () => {
      nowCalls += 1;
      return now;
    },
    randomBytesFn
  });
  return {
    host,
    setNow(value) {
      now = value;
    },
    advance(seconds) {
      now += seconds;
    },
    getNow: () => now,
    randomCalls: () => randomCalls,
    nowCalls: () => nowCalls,
    realCryptoCalls: () => cryptoRandomBytesCalls
  };
}

describe("desktop recovery ceremony host (5B-0.1)", function () {
  beforeEach(function () {
    cryptoRandomBytesCalls = 0;
  });

  it("exports TTL and constructs with deterministic injected dependencies only", function () {
    assert.equal(PHILCORE_V2_RECOVERY_CEREMONY_TTL_SECONDS, 300n);
    const harness = createHarness([LABEL_A]);
    assert.equal(typeof harness.host.mint, "function");
    assert.equal(typeof harness.host.cancel, "function");
    assert.equal(typeof harness.host.checkExpiry, "function");
    assert.equal(typeof harness.host.status, "function");
    assert.equal(typeof harness.host.retire, "function");
    assert.equal(harness.host.mint.length, 1);
    assert.equal(harness.host.cancel.length, 0);
    assert.equal(harness.host.checkExpiry.length, 0);
    assert.equal(harness.host.status.length, 0);
    assert.equal(harness.host.retire.length, 1);
  });

  it("never executes default node:crypto.randomBytes during tests", function () {
    const before = cryptoRandomBytesCalls;
    const harness = createHarness([LABEL_A, LABEL_B]);
    harness.host.mint(expectations());
    harness.advance(1);
    harness.host.cancel();
    harness.host.retire(hex32(LABEL_A));
    assert.equal(cryptoRandomBytesCalls, before);
    assert.equal(harness.randomCalls(), 1);
  });

  it("blocks mint on installed ACTIVE or ENDED before clock and randomness", function () {
    const harness = createHarness([LABEL_A, LABEL_B, LABEL_C]);
    const first = harness.host.mint(expectations());
    assert.equal(first.ceremonyId, hex32(LABEL_A));
    const afterFirstNow = harness.nowCalls();
    const afterFirstRandom = harness.randomCalls();

    assert.throws(
      () => harness.host.mint(expectations()),
      (error) => error.code === "CEREMONY_ALREADY_ACTIVE"
    );
    assert.equal(harness.nowCalls(), afterFirstNow);
    assert.equal(harness.randomCalls(), afterFirstRandom);

    harness.advance(1);
    const cancelled = harness.host.cancel();
    assert.equal(cancelled.endReason, "CANCELLED");
    const afterCancelNow = harness.nowCalls();

    assert.throws(
      () => harness.host.mint(expectations()),
      (error) => error.code === "CEREMONY_PENDING_RETIREMENT"
    );
    assert.equal(harness.nowCalls(), afterCancelNow);
    assert.equal(harness.randomCalls(), afterFirstRandom);
    assert.equal(harness.host.status().ceremonyId, hex32(LABEL_A));
  });

  it("requires retirement after cancel before a later mint can succeed", function () {
    const harness = createHarness([LABEL_A, LABEL_B]);
    const first = harness.host.mint(expectations());
    harness.advance(1);
    const cancelled = harness.host.cancel();
    assert.equal(cancelled.state, "ENDED");

    assert.throws(
      () => harness.host.mint(expectations()),
      (error) => error.code === "CEREMONY_PENDING_RETIREMENT"
    );
    assert.equal(harness.randomCalls(), 1);

    const beforeRetireNow = harness.nowCalls();
    const retired = harness.host.retire(hex32(LABEL_A));
    assert.equal(retired.ceremonyId, first.ceremonyId);
    assert.equal(retired.endReason, "CANCELLED");
    assert.equal(retired.lastObservedAtUnixSeconds, cancelled.lastObservedAtUnixSeconds);
    assert.equal(harness.nowCalls(), beforeRetireNow, "retire must not call nowFn");
    assert.equal(harness.host.status(), null);

    harness.advance(1);
    const second = harness.host.mint(expectations());
    assert.equal(second.ceremonyId, hex32(LABEL_B));
    assert.equal(harness.randomCalls(), 2);
  });

  it("keeps the terminal record installed when external cleanup is not acknowledged", function () {
    const harness = createHarness([LABEL_A]);
    harness.host.mint(expectations());
    harness.advance(1);
    const cancelled = harness.host.cancel();
    assert.equal(cancelled.state, "ENDED");
    // Simulated external cleanup failure: retire is never called.
    assert.throws(
      () => harness.host.mint(expectations()),
      (error) => error.code === "CEREMONY_PENDING_RETIREMENT"
    );
    assert.equal(harness.host.status().ceremonyId, hex32(LABEL_A));
    assert.equal(harness.host.status().endReason, "CANCELLED");
    assert.equal(harness.randomCalls(), 1);
  });

  it("owns the clock internally and lazily expires through status", function () {
    const harness = createHarness([LABEL_A]);
    const minted = harness.host.mint(expectations());
    assert.equal(minted.expiresAtUnixSeconds, BigInt(harness.getNow() + 300));

    harness.setNow(Number(minted.expiresAtUnixSeconds) - 1);
    const stillActive = harness.host.status();
    assert.equal(stillActive.state, "ACTIVE");
    assert.equal(harness.randomCalls(), 1);

    harness.setNow(Number(minted.expiresAtUnixSeconds));
    const expired = harness.host.status();
    assert.equal(expired.state, "ENDED");
    assert.equal(expired.endReason, "EXPIRED");
    assert.equal(harness.randomCalls(), 1);

    const again = harness.host.status();
    assert.equal(again.state, "ENDED");
    assert.equal(again.endReason, "EXPIRED");
  });

  it("blocks mint after explicit expiry until retirement clears the slot", function () {
    const harness = createHarness([LABEL_A, LABEL_B]);
    const first = harness.host.mint(expectations());
    harness.setNow(Number(first.expiresAtUnixSeconds));
    const expired = harness.host.checkExpiry();
    assert.equal(expired.endReason, "EXPIRED");
    assert.equal(expired.ceremonyId, first.ceremonyId);
    assert.equal(harness.randomCalls(), 1);

    const afterExpiryNow = harness.nowCalls();
    assert.throws(
      () => harness.host.mint(expectations()),
      (error) => error.code === "CEREMONY_PENDING_RETIREMENT"
    );
    assert.equal(harness.nowCalls(), afterExpiryNow);
    assert.equal(harness.randomCalls(), 1);

    const beforeRetireNow = harness.nowCalls();
    const retired = harness.host.retire(first.ceremonyId);
    assert.equal(retired.ceremonyId, first.ceremonyId);
    assert.equal(retired.endReason, "EXPIRED");
    assert.equal(harness.nowCalls(), beforeRetireNow);
    assert.equal(harness.host.status(), null);

    const next = harness.host.mint(expectations());
    assert.equal(next.ceremonyId, hex32(LABEL_B));
    assert.notEqual(next.ceremonyId, retired.ceremonyId);
    assert.equal(harness.randomCalls(), 2);
  });

  it("enforces retire precedence without clearing on rejection", function () {
    const harness = createHarness([LABEL_A]);
    const zero = `0x${"00".repeat(32)}`;
    assert.throws(
      () => harness.host.retire(zero),
      (error) => error.code === "RETIREMENT_CEREMONY_ID_INVALID"
    );
    assert.equal(harness.host.status(), null);
    assert.equal(harness.randomCalls(), 0);

    assert.throws(
      () => harness.host.retire(hex32(LABEL_A)),
      (error) => error.code === "CEREMONY_NOT_INSTALLED"
    );

    const minted = harness.host.mint(expectations());
    assert.throws(
      () => harness.host.retire(hex32(LABEL_A)),
      (error) => error.code === "CEREMONY_STILL_ACTIVE"
    );
    assert.equal(harness.host.status().state, "ACTIVE");
    assert.equal(harness.randomCalls(), 1);

    harness.advance(1);
    harness.host.cancel();
    assert.throws(
      () => harness.host.retire(hex32(LABEL_B)),
      (error) => error.code === "CEREMONY_ID_MISMATCH"
    );
    assert.equal(harness.host.status().ceremonyId, minted.ceremonyId);
    assert.equal(harness.randomCalls(), 1);

    const beforeRetireNow = harness.nowCalls();
    const retired = harness.host.retire(`0x${LABEL_A.toString("hex").toUpperCase()}`);
    assert.equal(retired.ceremonyId, hex32(LABEL_A));
    assert.equal(harness.nowCalls(), beforeRetireNow);
    assert.equal(harness.host.status(), null);
  });

  it("rejects invalid expected context before consuming randomness when idle", function () {
    const harness = createHarness([LABEL_A]);
    assert.throws(
      () => harness.host.mint(expectations({ expectedRecoveryEpoch: "0" })),
      (error) => error.code === "INVALID_EXPECTED_CONTEXT"
    );
    assert.equal(harness.randomCalls(), 0);
    assert.equal(harness.host.status(), null);

    const minted = harness.host.mint(expectations());
    assert.equal(minted.ceremonyId, hex32(LABEL_A));
    assert.equal(harness.randomCalls(), 1);

    const afterMintNow = harness.nowCalls();
    assert.throws(
      () => harness.host.mint(expectations({ chainId: "0" })),
      (error) => error.code === "CEREMONY_ALREADY_ACTIVE"
    );
    assert.equal(harness.nowCalls(), afterMintNow);
    assert.equal(harness.randomCalls(), 1);
  });

  it("returns frozen snapshots and starts idle with null status", function () {
    const harness = createHarness([LABEL_A]);
    assert.equal(harness.host.status(), null);
    const minted = harness.host.mint(expectations());
    assert.ok(Object.isFrozen(minted));
    assert.equal(
      Object.getOwnPropertyDescriptor(minted, "state")?.writable,
      false
    );
  });

  it("is not registered in main.cjs and has no preload IPC surface", function () {
    const mainSource = fs.readFileSync(MAIN_PATH, "utf8");
    assert.equal(mainSource.includes("recovery-ceremony-host"), false);
    assert.equal(mainSource.includes("createRecoveryCeremonyHost"), false);

    const hostSource = fs.readFileSync(HOST_PATH, "utf8");
    assert.equal(/ipcMain|BrowserWindow|contextBridge|preload/i.test(hostSource), false);
    assert.equal(
      /require\(["']electron["']\)|require\(["']node:http["']\)|require\(["']http["']\)|require\(["']node:net["']\)|require\(["']net["']\)|require\(["']node:fs["']\)|require\(["']fs["']\)/.test(hostSource),
      false
    );
    assert.ok(hostSource.includes('require("tsx/cjs")'));
    assert.ok(hostSource.includes("v2ConsumerRecoveryCeremonyLifecycle.ts"));

    assert.equal(
      fs.existsSync(PRELOAD_DIR),
      true,
      `expected preload directory missing: ${PRELOAD_DIR}`
    );
    for (const name of fs.readdirSync(PRELOAD_DIR)) {
      const text = fs.readFileSync(path.join(PRELOAD_DIR, name), "utf8");
      assert.equal(text.includes("recovery-ceremony-host"), false);
      assert.equal(text.includes("createRecoveryCeremonyHost"), false);
    }
  });

  it("loads the TypeScript lifecycle module through the existing CJS/tsx loader", function () {
    const harness = createHarness([LABEL_A]);
    const record = harness.host.mint(expectations({
      expectedRecoveryEpoch: "3",
      expectedValidatorEpoch: "4"
    }));
    assert.equal(record.expectedRecoveryEpoch, 3n);
    assert.equal(record.expectedValidatorEpoch, 4n);
    assert.match(record.enrollmentCeremonyHash, /^0x[0-9a-f]{64}$/);
  });
});

async function runNodeSuite() {
  try {
    for (const entry of __nodeSuite.tests) {
      if (typeof __nodeSuite.beforeEach === "function") {
        await __nodeSuite.beforeEach();
      }
      await entry.fn();
      console.log(`ok - ${entry.name}`);
    }
  } catch (error) {
    console.error("not ok - desktop recovery ceremony host");
    console.error(error);
    process.exitCode = 1;
  }
}

if (__usedNodeShim) {
  runNodeSuite();
}
