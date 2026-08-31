"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function bytes32(value, label) {
  const normalized = String(value || "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/u.test(normalized) || /^0x0{64}$/u.test(normalized)) {
    fail(`SEPOLIA_MINT_REPLAY_${label}_INVALID`);
  }
  return normalized;
}

function uint(value, label) {
  const normalized = String(value);
  if (!/^(0|[1-9][0-9]*)$/u.test(normalized)) fail(`SEPOLIA_MINT_REPLAY_${label}_INVALID`);
  return normalized;
}

function syncDirectory(directory) {
  const descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

function atomicWrite(location, contents) {
  const directory = path.dirname(location);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const temporary = path.join(
    directory,
    `.${path.basename(location)}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`
  );
  let descriptor;
  try {
    descriptor = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
      0o600
    );
    fs.writeFileSync(descriptor, contents);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, location);
    fs.chmodSync(location, 0o600);
    syncDirectory(directory);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    try { fs.unlinkSync(temporary); } catch {}
  }
}

function normalizeRecord(record) {
  if (!record || Object.keys(record).sort().join(",") !== [
    "accountNonce",
    "authorizationEnvelopeDigest",
    "deviceApprovalNonce",
    "reservedAt",
    "rootProofNullifier",
    "state"
  ].join(",")) fail("SEPOLIA_MINT_REPLAY_RECORD_INVALID");
  if (record.state !== "reserved" && record.state !== "consumed") {
    fail("SEPOLIA_MINT_REPLAY_STATE_INVALID");
  }
  if (typeof record.reservedAt !== "string" || !Number.isFinite(Date.parse(record.reservedAt))) {
    fail("SEPOLIA_MINT_REPLAY_TIME_INVALID");
  }
  return Object.freeze({
    authorizationEnvelopeDigest: bytes32(record.authorizationEnvelopeDigest, "ENVELOPE"),
    rootProofNullifier: bytes32(record.rootProofNullifier, "NULLIFIER"),
    deviceApprovalNonce: bytes32(record.deviceApprovalNonce, "APPROVAL_NONCE"),
    accountNonce: uint(record.accountNonce, "ACCOUNT_NONCE"),
    state: record.state,
    reservedAt: record.reservedAt
  });
}

function createSepoliaMintReplayStore(options) {
  if (!options || Object.keys(options).sort().join(",") !== "ledgerPath,now") {
    fail("SEPOLIA_MINT_REPLAY_OPTIONS_INVALID");
  }
  if (typeof options.ledgerPath !== "string" || !path.isAbsolute(options.ledgerPath)
    || options.ledgerPath === "/" || options.ledgerPath.includes("\0")
    || typeof options.now !== "function") fail("SEPOLIA_MINT_REPLAY_OPTIONS_INVALID");
  let poisoned = false;
  let records = [];
  if (fs.existsSync(options.ledgerPath)) {
    let parsed;
    try { parsed = JSON.parse(fs.readFileSync(options.ledgerPath, "utf8")); }
    catch { fail("SEPOLIA_MINT_REPLAY_LEDGER_INVALID"); }
    if (!parsed || Object.keys(parsed).sort().join(",") !== "format,records,version"
      || parsed.format !== "phil-sepolia-mint-replay-ledger"
      || parsed.version !== 1 || !Array.isArray(parsed.records) || parsed.records.length > 10_000) {
      fail("SEPOLIA_MINT_REPLAY_LEDGER_INVALID");
    }
    records = parsed.records.map(normalizeRecord);
    for (const field of [
      "authorizationEnvelopeDigest",
      "rootProofNullifier",
      "deviceApprovalNonce",
      "accountNonce"
    ]) {
      if (new Set(records.map((record) => record[field])).size !== records.length) {
        fail("SEPOLIA_MINT_REPLAY_LEDGER_DUPLICATE");
      }
    }
  }

  function assertAvailable() {
    if (poisoned) fail("SEPOLIA_MINT_REPLAY_STORE_POISONED");
  }
  function has(field, value) {
    assertAvailable();
    return records.some((record) => record[field] === value);
  }
  function persist(candidate) {
    try {
      atomicWrite(options.ledgerPath, `${JSON.stringify({
        format: "phil-sepolia-mint-replay-ledger",
        version: 1,
        records: candidate
      })}\n`);
    } catch (error) {
      poisoned = true;
      throw error;
    }
    records = candidate;
  }
  function reserve(input) {
    assertAvailable();
    const record = normalizeRecord({
      authorizationEnvelopeDigest: input.authorizationEnvelopeDigest,
      rootProofNullifier: input.rootProofNullifier,
      deviceApprovalNonce: input.deviceApprovalNonce,
      accountNonce: input.accountNonce,
      state: "reserved",
      reservedAt: options.now()
    });
    if (has("authorizationEnvelopeDigest", record.authorizationEnvelopeDigest)) {
      fail("SEPOLIA_MINT_REPLAY_ENVELOPE_REPLAY");
    }
    if (has("rootProofNullifier", record.rootProofNullifier)) {
      fail("SEPOLIA_MINT_REPLAY_NULLIFIER_REPLAY");
    }
    if (has("deviceApprovalNonce", record.deviceApprovalNonce)) {
      fail("SEPOLIA_MINT_REPLAY_APPROVAL_NONCE_REPLAY");
    }
    if (has("accountNonce", record.accountNonce)) {
      fail("SEPOLIA_MINT_REPLAY_ACCOUNT_NONCE_REPLAY");
    }
    persist(Object.freeze([...records, record]));
  }
  function hasExactReservation(input) {
    assertAvailable();
    const expected = {
      authorizationEnvelopeDigest: bytes32(input.authorizationEnvelopeDigest, "ENVELOPE"),
      rootProofNullifier: bytes32(input.rootProofNullifier, "NULLIFIER"),
      deviceApprovalNonce: bytes32(input.deviceApprovalNonce, "APPROVAL_NONCE"),
      accountNonce: uint(input.accountNonce, "ACCOUNT_NONCE")
    };
    return records.some((record) => record.state === "reserved"
      && record.authorizationEnvelopeDigest === expected.authorizationEnvelopeDigest
      && record.rootProofNullifier === expected.rootProofNullifier
      && record.deviceApprovalNonce === expected.deviceApprovalNonce
      && record.accountNonce === expected.accountNonce);
  }
  function markConsumed(input) {
    assertAvailable();
    const expected = {
      authorizationEnvelopeDigest: bytes32(input.authorizationEnvelopeDigest, "ENVELOPE"),
      rootProofNullifier: bytes32(input.rootProofNullifier, "NULLIFIER"),
      deviceApprovalNonce: bytes32(input.deviceApprovalNonce, "APPROVAL_NONCE"),
      accountNonce: uint(input.accountNonce, "ACCOUNT_NONCE")
    };
    const index = records.findIndex((record) =>
      record.authorizationEnvelopeDigest === expected.authorizationEnvelopeDigest
      && record.rootProofNullifier === expected.rootProofNullifier
      && record.deviceApprovalNonce === expected.deviceApprovalNonce
      && record.accountNonce === expected.accountNonce);
    if (index < 0) fail("SEPOLIA_MINT_REPLAY_EXACT_RESERVATION_MISSING");
    if (records[index].state === "consumed") return;
    const next = records.map((record, recordIndex) => recordIndex === index
      ? Object.freeze({ ...record, state: "consumed" }) : record);
    persist(Object.freeze(next));
  }
  return Object.freeze({
    hasEnvelopeDigest: (value) => has("authorizationEnvelopeDigest", bytes32(value, "ENVELOPE")),
    hasRootNullifier: (value) => has("rootProofNullifier", bytes32(value, "NULLIFIER")),
    hasDeviceApprovalNonce: (value) => has("deviceApprovalNonce", bytes32(value, "APPROVAL_NONCE")),
    hasAccountNonce: (value) => has("accountNonce", uint(value, "ACCOUNT_NONCE")),
    hasExactReservation,
    markConsumed,
    reserve,
    snapshot: () => Object.freeze({ count: records.length, poisoned, records: Object.freeze(records.map((record) => Object.freeze({ ...record }))) })
  });
}

module.exports = { createSepoliaMintReplayStore };
