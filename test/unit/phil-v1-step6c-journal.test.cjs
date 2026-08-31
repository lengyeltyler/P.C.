const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const journal = require("../../apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts");
const auth = require("../../apps/phil-device-sdk/src/routineAuthorizationV1.ts");

function advance(current, nextState, recordedAt, evidence = {}) {
  return journal.transitionPhilRoutineJournalRecordV1({
    current,
    expectedGeneration: current.generation,
    expectedRecordHash: current.recordHash,
    nextState,
    recordedAt,
    evidence
  });
}

function throughSimulation() {
  let record = journal.createPhilRoutineJournalRecordV1({
    requestId: ethers.id("journal-request"),
    sessionId: ethers.id("journal-session"),
    recordedAt: 100
  });
  for (const next of [2, 3, 4, 5]) record = advance(record, next, BigInt(record.recordedAt) + 1n);
  return record;
}

function commitEvidence() {
  const packed = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "uint256", "bytes", "bytes", "bytes32", "uint256", "bytes32", "bytes", "bytes"],
    ["0x2000000000000000000000000000000000000002", 0, "0x", "0x1234", ethers.toBeHex(1, 32),
      1, ethers.toBeHex(1, 32), "0x", `0x${"11".repeat(64)}`]
  );
  const target = "0x3000000000000000000000000000000000000003";
  const codeHash = ethers.id("target-code");
  const blockHash = ethers.id("scan-block");
  return {
    entryPoint: "0x1000000000000000000000000000000000000001",
    sender: "0x2000000000000000000000000000000000000002",
    userOperationNonce: "0",
    serializedUserOperationHash: ethers.keccak256(packed),
    officialUserOperationHash: auth.derivePhilOfficialUserOperationHashV07({
      packedUserOperationBytes: packed,
      entryPoint: "0x1000000000000000000000000000000000000001",
      chainId: 31337
    }),
    packedUserOperationBytes: packed,
    target,
    targetRecordedValueBefore: ethers.ZeroHash,
    targetRecordedSequenceBefore: "0",
    targetPreStateHash: journal.derivePhilRoutineTargetPreStateHashV1({
      target,
      approvedTargetRuntimeCodeHash: codeHash,
      recordedValueBefore: ethers.ZeroHash,
      recordedSequenceBefore: 0,
      scanStartBlockNumber: 9,
      scanStartBlockHash: blockHash
    }),
    scanStartBlockNumber: "9",
    scanStartBlockHash: blockHash
  };
}

function recordAtState(targetState) {
  let record = journal.createPhilRoutineJournalRecordV1({
    requestId: ethers.id(`journal-request-${targetState}`),
    sessionId: ethers.id(`journal-session-${targetState}`),
    recordedAt: 100
  });
  for (const next of [2, 3, 4, 5]) {
    if (record.state === targetState) return record;
    record = advance(record, next, BigInt(record.recordedAt) + 1n);
  }
  if (record.state === targetState) return record;
  record = advance(record, 6, BigInt(record.recordedAt) + 1n, commitEvidence());
  if (record.state === targetState) return record;
  record = advance(record, 7, BigInt(record.recordedAt) + 1n,
    { localTransactionHash: ethers.id(`transaction-${targetState}`) });
  if (record.state === targetState) return record;
  const fields = { ...record, state: targetState };
  delete fields.recordHash;
  return { ...fields, recordHash: journal.derivePhilRoutineJournalRecordHashV1(fields) };
}

function evidenceFor(nextState) {
  if (nextState === 6) return commitEvidence();
  if (nextState === 7) return { localTransactionHash: ethers.id("transition-matrix-transaction") };
  if ([22, 23, 24, 25].includes(nextState)) return { reasonHash: ethers.id(`transition-matrix-${nextState}`) };
  return {};
}

describe("Phil V1 Step 6C durable routine journal", function () {
  it("admits every declared public transition and rejects every other public state pair", function () {
    const states = Object.values(journal.PHIL_ROUTINE_JOURNAL_STATE_V1);
    const allowed = new Map([
      [1, [2, 20, 21, 22]], [2, [3, 4, 20, 21, 22]], [3, [4, 20, 21, 22]],
      [4, [5, 20, 21, 22]], [5, [6, 20, 21, 22]], [6, [7, 25]], [7, [25]]
    ]);
    for (const source of states) {
      for (const target of states) {
        const current = recordAtState(source);
        const operation = () => advance(current, target, BigInt(current.recordedAt) + 1n, evidenceFor(target));
        if ((allowed.get(source) ?? []).includes(target)) assert.equal(operation().state, target, `${source}->${target}`);
        else assert.throws(operation, (error) => error.code === "PHIL_ROUTINE_JOURNAL_TRANSITION_INVALID",
          `${source}->${target}`);
      }
    }
  });

  it("enforces a hash-chained CAS and an evidence-complete point of no return", function () {
    const simulated = throughSimulation();
    assert.equal(simulated.state, journal.PHIL_ROUTINE_JOURNAL_STATE_V1.SIMULATION_PASSED);
    assert.throws(() => journal.transitionPhilRoutineJournalRecordV1({
      current: simulated,
      expectedGeneration: 1,
      expectedRecordHash: simulated.recordHash,
      nextState: 6,
      recordedAt: 110,
      evidence: commitEvidence()
    }), (error) => error.code === "PHIL_ROUTINE_JOURNAL_CAS_CONFLICT");
    assert.throws(() => advance(simulated, 6, 110),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_COMMIT_EVIDENCE_INCOMPLETE");
    const committed = advance(simulated, 6, 110, commitEvidence());
    assert.equal(committed.previousRecordHash, simulated.recordHash);
    assert.equal(committed.generation, "6");
    assert.equal(committed.serializedUserOperationHash, ethers.keccak256(committed.packedUserOperationBytes));
  });

  it("allows cancellation before commit and makes every post-commit cancellation impossible", function () {
    const simulated = throughSimulation();
    const cancelled = advance(simulated, 20, 110);
    assert.equal(cancelled.state, 20);
    assert.throws(() => advance(cancelled, 6, 111),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_TRANSITION_INVALID");
    const committed = advance(simulated, 6, 110, commitEvidence());
    assert.throws(() => advance(committed, 20, 111),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_TRANSITION_INVALID");
  });

  it("never resubmits outcome-unknown work or admits unverified late summaries", function () {
    const committed = advance(throughSimulation(), 6, 110, commitEvidence());
    const unknown = advance(committed, 25, 111, { reasonHash: ethers.id("no-event-at-captured-head") });
    assert.throws(() => advance(unknown, 7, 112),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_TRANSITION_INVALID");
    assert.throws(() => advance(unknown, 9, 112),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_TRANSITION_INVALID");
    assert.throws(() => advance(unknown, 23, 112, { reasonHash: ethers.id("caller-claimed-failure") }),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_TRANSITION_INVALID");

    const unknown2 = advance(committed, 25, 111, { reasonHash: ethers.id("temporarily-inaccessible") });
    assert.throws(() => advance(unknown2, 8, 112, {
      localTransactionHash: ethers.id("verified-transaction"),
      receiptHash: ethers.id("verified-receipt"),
      localBlockHash: ethers.id("receipt-block")
    }), (error) => error.code === "PHIL_ROUTINE_JOURNAL_TRANSITION_INVALID");
  });

  it("round-trips strict journal-record and outer-frame JSON with fresh canonical AES-256-GCM nonces", function () {
    const aad = journal.derivePhilRoutineJournalFrameAadV1({
      disposableProfileId: ethers.id("profile"),
      generation: 5
    });
    assert.equal(ethers.getBytes(aad).length, 96);
    const key = ethers.getBytes(ethers.id("disclosed-synthetic-journal-key"));
    const nonce = ethers.getBytes("0x000102030405060708090a0b");
    const record = throughSimulation();
    const writer = new journal.PhilRoutineJournalFrameCipherV1({ key,
      disposableProfileId: ethers.id("profile"), randomNonce: () => nonce });
    const frameJson = writer.encryptRecord(record);
    const frame = JSON.parse(frameJson);
    assert.equal(frame.version, 1);
    assert.doesNotMatch(frame.nonce + frame.ciphertext + frame.tag, /[=+\/\s]/);
    const reader = new journal.PhilRoutineJournalFrameCipherV1({ key, disposableProfileId: ethers.id("profile") });
    assert.deepEqual(reader.decryptRecord({ frameJson, expectedGeneration: 5 }), record);
    assert.throws(() => reader.decryptRecord({ frameJson, expectedGeneration: 5 }),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_NONCE_REUSE");
    assert.throws(() => writer.encryptRecord(record),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_NONCE_REUSE");

    const wrongGenerationReader = new journal.PhilRoutineJournalFrameCipherV1({ key,
      disposableProfileId: ethers.id("profile") });
    assert.throws(() => wrongGenerationReader.decryptRecord({ frameJson, expectedGeneration: 4 }),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_AUTHENTICATION_FAILED");
    const tamperedFrame = { ...frame, ciphertext: `${frame.ciphertext[0] === "A" ? "B" : "A"}${frame.ciphertext.slice(1)}` };
    assert.throws(() => new journal.PhilRoutineJournalFrameCipherV1({ key,
      disposableProfileId: ethers.id("profile") }).decryptRecord({
      frameJson: JSON.stringify(tamperedFrame), expectedGeneration: 5
    }), (error) => error.code === "PHIL_ROUTINE_JOURNAL_AUTHENTICATION_FAILED");
    assert.throws(() => journal.parsePhilRoutineJournalFrameJsonV1(
      frameJson.replace("{", '{"version":1,')
    ), (error) => error.code === "PHIL_ROUTINE_JSON_DUPLICATE_KEY");
    assert.throws(() => journal.parsePhilRoutineJournalFrameJsonV1(JSON.stringify({ ...frame, unknown: true })),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_FRAME_SCHEMA_INVALID");
    assert.throws(() => journal.parsePhilRoutineJournalFrameJsonV1(JSON.stringify({ ...frame, nonce: `${frame.nonce}=` })),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_BASE64URL_INVALID");
    const recordJson = journal.serializePhilRoutineJournalRecordJsonV1(record);
    assert.deepEqual(journal.parsePhilRoutineJournalRecordJsonV1(recordJson), record);
    assert.throws(() => journal.parsePhilRoutineJournalRecordJsonV1(
      recordJson.replace("{", `{"formatVersionHash":"${record.formatVersionHash}",`)
    ), (error) => error.code === "PHIL_ROUTINE_JSON_DUPLICATE_KEY");
  });

  it("publishes a CAS transition only after its injected durable flush succeeds", async function () {
    const initial = throughSimulation();
    let shouldFail = true;
    const host = new journal.PhilRoutineJournalSyntheticCasHostV1({
      initial,
      flush: async () => { if (shouldFail) throw new Error("synthetic fullfsync failure"); }
    });
    await assert.rejects(host.compareAndSwap({
      expectedGeneration: initial.generation,
      expectedRecordHash: initial.recordHash,
      nextState: 6,
      recordedAt: 110,
      evidence: commitEvidence()
    }), /fullfsync failure/);
    assert.equal(host.read().recordHash, initial.recordHash);
    assert.equal(host.read().state, 5);
    shouldFail = false;
    const committed = await host.compareAndSwap({
      expectedGeneration: initial.generation,
      expectedRecordHash: initial.recordHash,
      nextState: 6,
      recordedAt: 110,
      evidence: commitEvidence()
    });
    assert.equal(host.read().recordHash, committed.recordHash);
    assert.equal(host.read().state, 6);
  });
});
