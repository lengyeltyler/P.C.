"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const ui = require("../src/renderer/sepolia-mint-ui.cjs");

const requestId = `0x${"12".repeat(32)}`;
const presentation = Object.freeze({ network: "Ethereum Sepolia", value: "0 ETH" });

function liveState() {
  return ui.beginState({
    requestId,
    qrDataUrl: "data:image/png;base64,AA",
    expiresAt: "1800000120",
    status: "waiting",
    presentation
  });
}

test("a fresh proof preparation clears every prior attempt projection", () => {
  const previous = { ...liveState(), completion: { submitted: false }, comparisonFingerprint: "AAAA BBBB" };
  const fresh = ui.preparingState();
  assert.equal(fresh.requestId, null);
  assert.equal(fresh.qrDataUrl, null);
  assert.equal(fresh.comparisonFingerprint, null);
  assert.equal(fresh.expiresAt, null);
  assert.equal(fresh.presentation, null);
  assert.equal(fresh.completion, null);
  assert.equal(fresh.state, "preparing");
});

test("late status responses cannot take ownership of a newer attempt", () => {
  assert.equal(ui.ownsRefresh(requestId, requestId, 7, 7), true);
  assert.equal(ui.ownsRefresh(`0x${"34".repeat(32)}`, requestId, 7, 7), false);
  assert.equal(ui.ownsRefresh(requestId, requestId, 8, 7), false);
  assert.equal(ui.ownsRefresh(requestId, requestId, 8, null), true);
});

test("cancel, expiry, and failure remove all stale QR and authorization data", () => {
  for (const state of ["cancelled", "expired", "failed"]) {
    const terminal = state === "cancelled"
      ? ui.cancelledState(liveState(), true)
      : ui.refreshedState(liveState(), { requestId, state });
    assert.equal(terminal.requestId, null);
    assert.equal(terminal.qrDataUrl, null);
    assert.equal(terminal.comparisonFingerprint, null);
    assert.equal(terminal.expiresAt, null);
    assert.equal(terminal.presentation, null);
    assert.equal(terminal.completion, null);
    assert.equal(terminal.state, state);
    assert.match(terminal.notice, /Nothing was sent publicly/u);
  }
});

test("only a completed request retains its exact authorization and signed evidence", () => {
  const completion = Object.freeze({ submitted: false, userOperationHash: `0x${"56".repeat(32)}` });
  const completed = ui.refreshedState(liveState(), {
    requestId,
    state: "completed",
    comparisonFingerprint: "AAAA BBBB",
    completion
  });
  assert.equal(completed.requestId, requestId);
  assert.equal(completed.qrDataUrl, null);
  assert.equal(completed.presentation, presentation);
  assert.equal(completed.completion, completion);
  assert.equal(completed.completion.submitted, false);
});

test("failed begins cannot preserve a prior request or expose arbitrary errors", () => {
  const safe = ui.failedBeginState("sepolia_mint_runtime_unavailable");
  assert.equal(safe.requestId, null);
  assert.equal(safe.presentation, null);
  assert.match(safe.notice, /sepolia_mint_runtime_unavailable/u);
  const redacted = ui.failedBeginState("private detail: /Users/example");
  assert.doesNotMatch(redacted.notice, /private detail|Users/u);
});
