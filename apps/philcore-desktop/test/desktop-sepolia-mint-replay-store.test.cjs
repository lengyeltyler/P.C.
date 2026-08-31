"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createSepoliaMintReplayStore } = require("../src/main/sepolia-mint-replay-store.cjs");

const reservation = Object.freeze({
  authorizationEnvelopeDigest: `0x${"11".repeat(32)}`,
  rootProofNullifier: `0x${"22".repeat(32)}`,
  deviceApprovalNonce: `0x${"33".repeat(32)}`,
  accountNonce: "7"
});

test("Sepolia mint replay reservations survive restart and reject every reused key", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phil-sepolia-mint-replay-"));
  const ledgerPath = path.join(root, "replay", "ledger-v1.json");
  const create = () => createSepoliaMintReplayStore({
    ledgerPath,
    now: () => "2026-08-24T22:00:00.000Z"
  });
  const first = create();
  first.reserve(reservation);
  assert.equal(first.snapshot().count, 1);
  assert.equal(fs.statSync(ledgerPath).mode & 0o777, 0o600);

  const restarted = create();
  assert.equal(restarted.hasExactReservation(reservation), true);
  assert.equal(restarted.hasExactReservation({ ...reservation, accountNonce: "8" }), false);
  assert.equal(restarted.hasEnvelopeDigest(reservation.authorizationEnvelopeDigest), true);
  assert.equal(restarted.hasRootNullifier(reservation.rootProofNullifier), true);
  assert.equal(restarted.hasDeviceApprovalNonce(reservation.deviceApprovalNonce), true);
  assert.equal(restarted.hasAccountNonce(reservation.accountNonce), true);
  for (const [field, value, code] of [
    ["authorizationEnvelopeDigest", `0x${"44".repeat(32)}`, "SEPOLIA_MINT_REPLAY_NULLIFIER_REPLAY"],
    ["rootProofNullifier", `0x${"44".repeat(32)}`, "SEPOLIA_MINT_REPLAY_ENVELOPE_REPLAY"],
    ["deviceApprovalNonce", `0x${"44".repeat(32)}`, "SEPOLIA_MINT_REPLAY_ENVELOPE_REPLAY"],
    ["accountNonce", "8", "SEPOLIA_MINT_REPLAY_ENVELOPE_REPLAY"]
  ]) {
    assert.throws(
      () => restarted.reserve({ ...reservation, [field]: value }),
      (error) => error.code === code
    );
  }
  restarted.markConsumed(reservation);
  restarted.markConsumed(reservation);
  assert.equal(restarted.hasExactReservation(reservation), false);
  assert.equal(restarted.snapshot().records[0].state, "consumed");
  const consumedRestart = create();
  assert.equal(consumedRestart.hasExactReservation(reservation), false);
  assert.throws(
    () => consumedRestart.reserve(reservation),
    (error) => error.code === "SEPOLIA_MINT_REPLAY_ENVELOPE_REPLAY"
  );
  fs.rmSync(root, { recursive: true, force: true });
});

test("an interrupted temporary write cannot replace the last durable reservation", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phil-sepolia-mint-interrupt-"));
  const directory = path.join(root, "replay");
  const ledgerPath = path.join(directory, "ledger-v1.json");
  const store = createSepoliaMintReplayStore({ ledgerPath, now: () => "2026-08-24T22:00:00.000Z" });
  store.reserve(reservation);
  fs.writeFileSync(path.join(directory, ".ledger-v1.json.interrupted.tmp"), "{", { mode: 0o600 });
  const restarted = createSepoliaMintReplayStore({ ledgerPath, now: () => "2026-08-24T22:01:00.000Z" });
  assert.equal(restarted.snapshot().count, 1);
  assert.equal(restarted.hasEnvelopeDigest(reservation.authorizationEnvelopeDigest), true);
  fs.rmSync(root, { recursive: true, force: true });
});

test("corrupt or duplicate canonical ledgers fail closed", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phil-sepolia-mint-corrupt-"));
  const ledgerPath = path.join(root, "ledger-v1.json");
  fs.writeFileSync(ledgerPath, "{", { mode: 0o600 });
  assert.throws(
    () => createSepoliaMintReplayStore({ ledgerPath, now: () => "2026-08-24T22:00:00.000Z" }),
    (error) => error.code === "SEPOLIA_MINT_REPLAY_LEDGER_INVALID"
  );
  fs.writeFileSync(ledgerPath, `${JSON.stringify({
    format: "phil-sepolia-mint-replay-ledger",
    version: 1,
    records: [
      { ...reservation, state: "reserved", reservedAt: "2026-08-24T22:00:00.000Z" },
      { ...reservation, rootProofNullifier: `0x${"44".repeat(32)}`, state: "reserved", reservedAt: "2026-08-24T22:01:00.000Z" }
    ]
  })}\n`, { mode: 0o600 });
  assert.throws(
    () => createSepoliaMintReplayStore({ ledgerPath, now: () => "2026-08-24T22:00:00.000Z" }),
    (error) => error.code === "SEPOLIA_MINT_REPLAY_LEDGER_DUPLICATE"
  );
  fs.rmSync(root, { recursive: true, force: true });
});
