const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("hardhat");

const {
  SOURCE_PATHS,
  auth,
  deployStep6CFixture,
  buildRequestForNonce,
  eventCommitment,
  setNextTimestamp,
  serializePackedUserOperation,
  toContractAction,
  toContractApproval,
  toContractCore,
  toContractEnvelope,
  toContractPresentation
} = require("../helpers/phil-v1-step6c-fixture.cjs");
const journal = require("../../apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts");

function trustedState(request, overrides = {}) {
  return { request, desktopUnlocked: true, iphoneSessionCurrent: true, ...overrides };
}

function coordinatorInput(request, input = {}) {
  return {
    flush: async () => {},
    readTrustedState: async () => trustedState(request),
    reconcile: async () => { throw new Error("reconciliation must be explicitly supplied"); },
    ...input
  };
}

function simulationFor(f, built, scanStart) {
  const packedUserOperationBytes = serializePackedUserOperation(built.userOp);
  return {
    entryPoint: f.entryPointAddress,
    sender: f.accountAddress,
    userOperationNonce: built.request.action.userOpNonce,
    serializedUserOperationHash: ethers.keccak256(packedUserOperationBytes),
    officialUserOperationHash: built.userOpHash,
    packedUserOperationBytes,
    target: f.targetAddress,
    targetRecordedValueBefore: ethers.ZeroHash,
    targetRecordedSequenceBefore: 0,
    targetPreStateHash: journal.derivePhilRoutineTargetPreStateHashV1({
      target: f.targetAddress,
      approvedTargetRuntimeCodeHash: f.targetCodeHash,
      recordedValueBefore: ethers.ZeroHash,
      recordedSequenceBefore: 0,
      scanStartBlockNumber: scanStart.number,
      scanStartBlockHash: scanStart.hash
    }),
    scanStartBlockNumber: scanStart.number,
    scanStartBlockHash: scanStart.hash
  };
}

function journalChainFor(request, simulation, state = 6, transactionHash = ethers.ZeroHash) {
  let record = journal.createPhilRoutineJournalRecordV1({
    requestId: request.requestId,
    sessionId: request.authorizationCore.sessionId,
    recordedAt: request.authorizationCore.issuedAt
  });
  const records = [record];
  if (state === 1) return records;
  for (const nextState of [2, 3, 4, 5]) {
    record = journal.transitionPhilRoutineJournalRecordV1({ current: record, expectedGeneration: record.generation,
      expectedRecordHash: record.recordHash, nextState, recordedAt: BigInt(record.recordedAt) + 1n });
    records.push(record);
    if (state === nextState) return records;
  }
  record = journal.transitionPhilRoutineJournalRecordV1({ current: record, expectedGeneration: record.generation,
    expectedRecordHash: record.recordHash, nextState: 6, recordedAt: BigInt(record.recordedAt) + 1n,
    evidence: simulation });
  records.push(record);
  if (state === 6) return records;
  if (state === 7) {
    record = journal.transitionPhilRoutineJournalRecordV1({ current: record, expectedGeneration: record.generation,
      expectedRecordHash: record.recordHash, nextState: 7, recordedAt: BigInt(record.recordedAt) + 1n,
      evidence: { localTransactionHash: transactionHash } });
    records.push(record);
  }
  return records;
}

function committedJournalFor(request, simulation, state = 6, transactionHash = ethers.ZeroHash) {
  return journalChainFor(request, simulation, state, transactionHash).at(-1);
}

async function executeFailedEvidence(f, built, simulation) {
  await setNextTimestamp(BigInt(built.request.authorizationCore.issuedAt) + 10n);
  const tx = await f.entryPoint.handleOps([built.userOp], f.beneficiary.address);
  const chainReceipt = await tx.wait();
  const block = await ethers.provider.getBlock(chainReceipt.blockNumber);
  return {
    scanStartBlockNumber: simulation.scanStartBlockNumber,
    scanStartBlockHash: simulation.scanStartBlockHash,
    capturedHeadBlockNumber: block.number,
    capturedHeadBlockHash: block.hash,
    eventBlockNumber: block.number,
    transactionStatus: chainReceipt.status,
    transactionHash: chainReceipt.hash,
    blockHash: block.hash,
    logs: chainReceipt.logs.map((log) => ({ address: log.address, topics: [...log.topics], data: log.data,
      index: log.index, transactionHash: log.transactionHash, blockHash: log.blockHash, removed: false })),
    entryPointNonceAfter: 1,
    targetCodeHash: f.targetCodeHash,
    targetRecordedValueAfter: ethers.ZeroHash,
    targetRecordedSequenceAfter: 0
  };
}

async function executeSuccessOutcome(f, built, simulation) {
  await setNextTimestamp(BigInt(built.request.authorizationCore.issuedAt) + 10n);
  const tx = await f.entryPoint.handleOps([built.userOp], f.beneficiary.address);
  const chainReceipt = await tx.wait();
  const block = await ethers.provider.getBlock(chainReceipt.blockNumber);
  const entryTopic = ethers.id("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
  const accountTopic = ethers.id("PhilV1Step6CAuthorizationConsumed(bytes32,bytes32,bytes32,bytes32,bytes32,address)");
  const targetTopic = ethers.id("ValueRecorded(bytes32,uint64)");
  const entryLog = chainReceipt.logs.find((log) => log.topics[0] === entryTopic);
  const accountLog = chainReceipt.logs.find((log) => log.topics[0] === accountTopic);
  const targetLog = chainReceipt.logs.find((log) => log.topics[0] === targetTopic);
  const nonceBefore = BigInt(built.request.action.userOpNonce);
  const nonceAfter = nonceBefore + 1n;
  const receipt = auth.createPhilRoutineAuthorizationReceiptV1({
    requestId: built.request.requestId,
    authorizationCoreDigest: built.request.authorizationCoreDigest,
    authorizationEnvelopeDigest: built.request.authorizationEnvelopeDigest,
    deviceApprovalDigest: built.request.deviceApprovalDigest,
    platformSigningDigest: built.request.platformSigningDigest,
    serializedUserOperationHash: simulation.serializedUserOperationHash,
    userOperationHash: built.userOpHash,
    executionEnvironmentHash: f.environment.executionEnvironmentHash,
    entryPointEventCommitment: eventCommitment(entryLog),
    accountEventCommitment: eventCommitment(accountLog),
    targetEventCommitment: eventCommitment(targetLog),
    targetPreStateHash: simulation.targetPreStateHash,
    finalTargetStateHash: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes32", "uint64", "bytes32", "bytes32"],
      [f.targetAddress, auth.PHIL_STEP6C_RECORDED_VALUE, 1, chainReceipt.hash, block.hash]
    )),
    entryPointCodeHash: f.entryPointCodeHash,
    senderCreatorCodeHash: f.senderCreatorCodeHash,
    accountCodeHash: f.accountRuntimeCodeHash,
    targetCodeHash: f.targetCodeHash,
    transactionHash: chainReceipt.hash,
    blockHash: block.hash,
    entryPointNonceBefore: nonceBefore,
    entryPointNonceAfter: nonceAfter,
    executedAt: block.timestamp,
    simulationPassed: true,
    executionSucceeded: true,
    externalNetwork: false,
    productionAuthority: false
  });
  return {
    kind: "success",
    receipt,
    evidence: {
      packedUserOperationBytes: simulation.packedUserOperationBytes,
      userOperationHash: built.userOpHash,
      logs: chainReceipt.logs.map((log) => ({ address: log.address, topics: [...log.topics], data: log.data,
        index: log.index, transactionHash: log.transactionHash, blockHash: log.blockHash, removed: false })),
      transactionStatus: chainReceipt.status,
      targetRecordedValueBefore: simulation.targetRecordedValueBefore,
      targetRecordedSequenceBefore: simulation.targetRecordedSequenceBefore,
      scanStartBlockNumber: simulation.scanStartBlockNumber,
      scanStartBlockHash: simulation.scanStartBlockHash,
      targetRecordedValueAfter: auth.PHIL_STEP6C_RECORDED_VALUE,
      targetRecordedSequenceAfter: 1,
      blockTimestamp: block.timestamp,
      entryPointNonceBefore: nonceBefore,
      entryPointNonceAfter: nonceAfter,
      entryPointCodeHash: f.entryPointCodeHash,
      senderCreatorCodeHash: f.senderCreatorCodeHash,
      accountCodeHash: f.accountRuntimeCodeHash,
      targetCodeHash: f.targetCodeHash,
      transactionHash: chainReceipt.hash,
      blockHash: block.hash
    }
  };
}

describe("Phil V1 Step 6C protected Desktop boundary", function () {
  it("revalidates protected request state before accepting the one matching device response", async function () {
    const f = await deployStep6CFixture();
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt: BigInt(f.policy.validAfter) + 20n,
      sessionLabel: "desktop-response"
    });
    const verified = auth.verifyPhilRoutineAuthorizationResponseV1({
      request: built.request,
      response: built.response
    });
    assert.equal(verified.requestId, built.request.requestId);
    assert.throws(() => auth.verifyPhilRoutineAuthorizationResponseV1({
      request: { ...built.request, requestId: ethers.id("renderer-substitution") },
      response: built.response
    }), (error) => error.code === "PHIL_ROUTINE_REQUEST_MISMATCH");
    assert.throws(() => auth.verifyPhilRoutineAuthorizationResponseV1({
      request: built.request,
      response: { ...built.response, requestId: ethers.id("other-request") }
    }), (error) => error.code === "PHIL_ROUTINE_RESPONSE_MISMATCH");
    let clock = BigInt(built.request.authorizationCore.issuedAt) + 1n;
    const coordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(built.request, {
      now: () => clock++,
      simulate: async () => { throw new Error("unused"); },
      execute: async () => { throw new Error("unused"); }
    }));
    await coordinator.beginRoutineAuthorization(built.request);
    await assert.rejects(coordinator.acceptRoutineDeviceResponse({
      requestId: built.request.requestId,
      response: { ...built.response, responseHash: ethers.id("invalid-response") }
    }), (error) => error.code === "PHIL_ROUTINE_RESPONSE_MISMATCH");
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 2);
  });

  it("exposes no direct account execution path even for a valid approved package", async function () {
    const f = await deployStep6CFixture();
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt: BigInt(f.policy.validAfter) + 20n,
      sessionLabel: "desktop-direct-call"
    });
    await assert.rejects(
      f.account.executeAuthorized(
        toContractAction(built.request.action),
        toContractEnvelope(built.request.authorizationEnvelope),
        toContractApproval(built.request),
        toContractPresentation(built.request.humanPresentation),
        toContractCore(built.request.authorizationCore),
        built.request.targetCalldata
      ),
      /PhilStep6COnlyEntryPoint/
    );
    assert.equal(await f.target.recordedSequence(), 0n);
  });

  it("keeps production sources isolated from public RPC, recovery signers, STWO, generic execution, and runtime-code copying", function () {
    const root = path.resolve(__dirname, "../..");
    const joined = SOURCE_PATHS.map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n");
    assert.doesNotMatch(joined, /hardhat_setCode|BASE_RPC_URL|SEPOLIA_RPC_URL|https:\/\//);
    assert.doesNotMatch(joined, /from\s+["'][^"']*(?:v2Recovery|stwo|rootProof)/i);
    assert.doesNotMatch(joined, /function\s+(?:execute|delegatecall|setOwner|setPolicy|recover)\s*\(/);
    assert.doesNotMatch(joined, /private[_-]?key|mnemonic|phil_secret/i);
    assert.doesNotMatch(joined, /console\.|logger\.|audit(?:Log|Event|Payload)/);
    const target = fs.readFileSync(path.join(root, "contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol"), "utf8");
    assert.doesNotMatch(target, /\.call\{|delegatecall|staticcall/);
  });

  it("exposes only the sanitized status and terminal reason and no request, signature, operation, or journal evidence", async function () {
    const f = await deployStep6CFixture();
    const built = await buildRequestForNonce(f, { nonceSequence: 0, shouldRevert: false,
      issuedAt: BigInt(f.policy.validAfter) + 20n, sessionLabel: "desktop-sanitized-status" });
    let clock = BigInt(built.request.authorizationCore.issuedAt) + 1n;
    const coordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(built.request, {
      now: () => clock++, simulate: async () => { throw new Error("unused"); },
      execute: async () => { throw new Error("unused"); }
    }));
    await coordinator.beginRoutineAuthorization(built.request);
    const status = coordinator.getRoutineAuthorizationStatus(built.request.requestId);
    assert.deepEqual(Object.keys(status).sort(), ["generation", "recordHash", "requestId", "state", "terminalReason"]);
    const serialized = JSON.stringify(status);
    for (const forbidden of ["signatureR", "signatureS", "packedUserOperationBytes", "nonceSeed",
      "targetCalldata", "deviceApprovalDigest", "localTransactionHash"]) {
      assert.doesNotMatch(serialized, new RegExp(forbidden));
    }
  });

  it("serializes response, simulation, commit, execution, cancellation, and restart through the protected lifecycle", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    let clock = issuedAt + 1n;
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt,
      sessionLabel: "desktop-coordinator"
    });
    const scanStart = await ethers.provider.getBlock("latest");
    const simulation = simulationFor(f, built, scanStart);
    let verifiedOutcome;
    let reconcileOutcome;
    const flushedStates = [];
    const coordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(built.request, {
      now: () => clock++,
      flush: async (candidate) => { flushedStates.push(candidate.state); },
      simulate: async () => simulation,
      execute: async (_request, _response, _simulation, committed) => {
        assert.equal(committed.state, 6);
        assert.equal(flushedStates.at(-1), 6);
        verifiedOutcome = await executeSuccessOutcome(f, built, simulation);
        reconcileOutcome = verifiedOutcome;
        return verifiedOutcome;
      },
      reconcile: async () => reconcileOutcome
    }));
    await coordinator.beginRoutineAuthorization(built.request);
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 2);
    await coordinator.acceptRoutineDeviceResponse({ requestId: built.request.requestId, response: built.response });
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 4);
    assert.equal(flushedStates.includes(3), false);
    await coordinator.simulateApprovedRoutineAuthorization(built.request.requestId);
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 5);
    await coordinator.commitAndExecuteSimulatedRoutineAuthorization(built.request.requestId);
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 8);
    assert.equal(await coordinator.cancelRoutineAuthorization(built.request.requestId), "too_late_submission_committed");
    reconcileOutcome = { ...verifiedOutcome, evidence: { ...verifiedOutcome.evidence, transactionStatus: 0 } };
    await assert.rejects(coordinator.reconcileRoutineAuthorization(built.request.requestId),
      (error) => error.code === "PHIL_ROUTINE_RECEIPT_MISMATCH");
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 8);
    reconcileOutcome = verifiedOutcome;
    await coordinator.reconcileRoutineAuthorization(built.request.requestId);
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 9);

    const submittedChain = journalChainFor(built.request, simulation, 7, verifiedOutcome.receipt.transactionHash);
    let replayClock = issuedAt + 50n;
    const restoredSubmitted = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(built.request, {
      now: () => replayClock++,
      simulate: async () => { throw new Error("must not simulate submitted work"); },
      execute: async () => { throw new Error("must not resubmit submitted work"); },
      reconcile: async () => verifiedOutcome
    }));
    restoredSubmitted.restoreRoutineAuthorization({ request: built.request, journalChain: submittedChain });
    await restoredSubmitted.reconcileRoutineAuthorization(built.request.requestId);
    assert.equal(restoredSubmitted.getRoutineAuthorizationStatus(built.request.requestId).state, 8);
    await restoredSubmitted.reconcileRoutineAuthorization(built.request.requestId);
    assert.equal(restoredSubmitted.getRoutineAuthorizationStatus(built.request.requestId).state, 9);

    const retry = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt: issuedAt + 20n,
      sessionLabel: "desktop-cancel"
    });
    await coordinator.beginRoutineAuthorization(retry.request);
    assert.equal(await coordinator.cancelRoutineAuthorization(retry.request.requestId), "cancelled");
    assert.equal(coordinator.getRoutineAuthorizationStatus(retry.request.requestId).state, 20);
  });

  it("snapshots simulation evidence and terminally records an ambiguous submission outcome", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    let clock = issuedAt + 1n;
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt,
      sessionLabel: "desktop-outcome-unknown"
    });
    const packed = serializePackedUserOperation(built.userOp);
    const supplied = {
      entryPoint: f.entryPointAddress,
      sender: f.accountAddress,
      userOperationNonce: 0,
      serializedUserOperationHash: ethers.keccak256(packed),
      officialUserOperationHash: built.userOpHash,
      packedUserOperationBytes: packed,
      target: f.targetAddress,
      targetRecordedValueBefore: ethers.ZeroHash,
      targetRecordedSequenceBefore: 0,
      targetPreStateHash: journal.derivePhilRoutineTargetPreStateHashV1({
        target: f.targetAddress,
        approvedTargetRuntimeCodeHash: f.targetCodeHash,
        recordedValueBefore: ethers.ZeroHash,
        recordedSequenceBefore: 0,
        scanStartBlockNumber: 1,
        scanStartBlockHash: ethers.id("unknown-scan-block")
      }),
      scanStartBlockNumber: 1,
      scanStartBlockHash: ethers.id("unknown-scan-block")
    };
    const coordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(built.request, {
      now: () => clock++,
      simulate: async () => supplied,
      execute: async () => { throw new Error("connection closed after submit"); }
    }));
    await coordinator.beginRoutineAuthorization(built.request);
    await coordinator.acceptRoutineDeviceResponse({ requestId: built.request.requestId, response: built.response });
    const snapshot = await coordinator.simulateApprovedRoutineAuthorization(built.request.requestId);
    assert.equal(Object.isFrozen(snapshot), true);
    supplied.serializedUserOperationHash = ethers.id("mutated-after-simulation");
    assert.equal(snapshot.serializedUserOperationHash, ethers.keccak256(packed));
    supplied.serializedUserOperationHash = ethers.keccak256(packed);
    await assert.rejects(
      coordinator.commitAndExecuteSimulatedRoutineAuthorization(built.request.requestId),
      (error) => error.code === "PHIL_ROUTINE_COORDINATOR_SUBMISSION_OUTCOME_UNKNOWN"
    );
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 25);
    await assert.rejects(
      coordinator.commitAndExecuteSimulatedRoutineAuthorization(built.request.requestId),
      (error) => error.code === "PHIL_ROUTINE_COORDINATOR_STATE_INVALID"
    );
    assert.equal(await coordinator.cancelRoutineAuthorization(built.request.requestId), "too_late_submission_committed");
  });

  it("reconciles a restored state-6 commit to unknown and admits only exact late failed-event evidence", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: true,
      issuedAt,
      sessionLabel: "desktop-late-failure"
    });
    const scanStart = await ethers.provider.getBlock("latest");
    const simulation = simulationFor(f, built, scanStart);
    const committedChain = journalChainFor(built.request, simulation);
    const committed = committedChain.at(-1);
    let reconciliation = {
      kind: "unknown",
      evidence: {
        scanStartBlockNumber: scanStart.number,
        scanStartBlockHash: scanStart.hash,
        chainAccessible: true,
        capturedHeadBlockNumber: scanStart.number,
        capturedHeadBlockHash: scanStart.hash,
        matchingUserOperationLogs: [],
        entryPointNonceAfter: 0,
        targetCodeHash: f.targetCodeHash,
        targetRecordedValueAfter: ethers.ZeroHash,
        targetRecordedSequenceAfter: 0
      }
    };
    let clock = BigInt(committed.recordedAt) + 1n;
    const coordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(built.request, {
      now: () => clock++,
      simulate: async () => { throw new Error("must not simulate restored work"); },
      execute: async () => { throw new Error("must not resubmit restored work"); },
      reconcile: async () => reconciliation
    }));
    const tamperedChain = [...committedChain.slice(0, -1), { ...committed,
      targetPreStateHash: ethers.id("tampered-persisted-head") }];
    assert.throws(() => coordinator.restoreRoutineAuthorization({ request: built.request, journalChain: tamperedChain }),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_RECORD_HASH_INVALID");
    const gapFields = { ...committed, generation: (BigInt(committed.generation) + 1n).toString() };
    delete gapFields.recordHash;
    const gap = { ...gapFields, recordHash: journal.derivePhilRoutineJournalRecordHashV1(gapFields) };
    assert.throws(() => coordinator.restoreRoutineAuthorization({ request: built.request,
      journalChain: [...committedChain.slice(0, -1), gap] }),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_CHAIN_INVALID");
    assert.throws(() => coordinator.restoreRoutineAuthorization({ request: built.request,
      journalChain: [{ ...committedChain[0], unknownPersistedField: true }, ...committedChain.slice(1)] }),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_SCHEMA_INVALID");
    const foreignGenesisFields = { ...committedChain[0], entryPoint: f.entryPointAddress };
    delete foreignGenesisFields.recordHash;
    const foreignGenesis = { ...foreignGenesisFields,
      recordHash: journal.derivePhilRoutineJournalRecordHashV1(foreignGenesisFields) };
    assert.throws(() => coordinator.restoreRoutineAuthorization({ request: built.request,
      journalChain: [foreignGenesis, ...committedChain.slice(1)] }),
      (error) => error.code === "PHIL_ROUTINE_JOURNAL_CHAIN_INVALID");
    const frameKey = ethers.getBytes(ethers.id("desktop-restored-state6-frame-key"));
    let frameNonce = 0;
    const frameWriter = new journal.PhilRoutineJournalFrameCipherV1({ key: frameKey,
      disposableProfileId: ethers.id("desktop-restored-state6-profile"),
      randomNonce: () => ethers.getBytes(ethers.toBeHex(++frameNonce, 12)) });
    const frameJsonChain = committedChain.map((record) => frameWriter.encryptRecord(record));
    const frameReader = new journal.PhilRoutineJournalFrameCipherV1({ key: frameKey,
      disposableProfileId: ethers.id("desktop-restored-state6-profile") });
    coordinator.restoreEncryptedRoutineAuthorization({ request: built.request, frameCipher: frameReader,
      journalFrameJsonChain: frameJsonChain });
    await coordinator.reconcileRoutineAuthorization(built.request.requestId);
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 25);

    const failedEvidence = await executeFailedEvidence(f, built, simulation);
    reconciliation = { kind: "failed", evidence: { ...failedEvidence, transactionHash: ethers.id("fabricated") } };
    await assert.rejects(coordinator.reconcileRoutineAuthorization(built.request.requestId),
      (error) => error.code === "PHIL_ROUTINE_RECONCILIATION_EVENT_INVALID");
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 25);
    reconciliation = { kind: "failed", evidence: failedEvidence };
    await coordinator.reconcileRoutineAuthorization(built.request.requestId);
    assert.equal(coordinator.getRoutineAuthorizationStatus(built.request.requestId).state, 23);
    assert.equal(await f.target.recordedSequence(), 0n);
    assert.equal(await f.entryPoint.getNonce(f.accountAddress, 0), 1n);
  });

  it("reconciles every pre-submission crash and both submitted receipt outcomes without resubmission", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    for (const crashState of [1, 2, 3, 4, 5]) {
      const built = await buildRequestForNonce(f, { nonceSequence: 0, shouldRevert: false,
        issuedAt: issuedAt + BigInt(crashState * 130), sessionLabel: `desktop-crash-${crashState}` });
      const scanStart = await ethers.provider.getBlock("latest");
      const chain = journalChainFor(built.request, simulationFor(f, built, scanStart), crashState);
      let clock = BigInt(chain.at(-1).recordedAt) + 1n;
      const restored = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(built.request, {
        now: () => clock++,
        simulate: async () => { throw new Error("must not simulate crashed work"); },
        execute: async () => { throw new Error("must not execute crashed work"); }
      }));
      restored.restoreRoutineAuthorization({ request: built.request, journalChain: chain });
      await restored.reconcileRoutineAuthorization(built.request.requestId);
      assert.equal(restored.getRoutineAuthorizationStatus(built.request.requestId).state, 22, `state ${crashState}`);
    }

    const failed = await buildRequestForNonce(f, { nonceSequence: 0, shouldRevert: true,
      issuedAt: issuedAt + 800n, sessionLabel: "desktop-restored-submitted-failure" });
    const failedStart = await ethers.provider.getBlock("latest");
    const failedSimulation = simulationFor(f, failed, failedStart);
    const failedEvidence = await executeFailedEvidence(f, failed, failedSimulation);
    let failedClock = BigInt(failed.request.authorizationCore.issuedAt) + 50n;
    const restoredFailed = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(failed.request, {
      now: () => failedClock++, simulate: async () => { throw new Error("must not simulate"); },
      execute: async () => { throw new Error("must not resubmit"); },
      reconcile: async () => ({ kind: "failed", evidence: failedEvidence })
    }));
    restoredFailed.restoreRoutineAuthorization({ request: failed.request,
      journalChain: journalChainFor(failed.request, failedSimulation, 7, failedEvidence.transactionHash) });
    await restoredFailed.reconcileRoutineAuthorization(failed.request.requestId);
    assert.equal(restoredFailed.getRoutineAuthorizationStatus(failed.request.requestId).state, 23);

    const success = await buildRequestForNonce(f, { nonceSequence: 1, shouldRevert: false,
      issuedAt: issuedAt + 950n, sessionLabel: "desktop-restored-unknown-success" });
    const successStart = await ethers.provider.getBlock("latest");
    const successSimulation = simulationFor(f, success, successStart);
    const successOutcome = await executeSuccessOutcome(f, success, successSimulation);
    const committed = journalChainFor(success.request, successSimulation);
    const state25 = journal.transitionPhilRoutineJournalRecordV1({ current: committed.at(-1),
      expectedGeneration: committed.at(-1).generation, expectedRecordHash: committed.at(-1).recordHash,
      nextState: 25, recordedAt: BigInt(committed.at(-1).recordedAt) + 1n,
      evidence: { reasonHash: ethers.id("captured-head-had-no-event") } });
    let successClock = BigInt(state25.recordedAt) + 1n;
    const restoredSuccess = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(success.request, {
      now: () => successClock++, simulate: async () => { throw new Error("must not simulate"); },
      execute: async () => { throw new Error("must not resubmit"); },
      reconcile: async () => successOutcome
    }));
    restoredSuccess.restoreRoutineAuthorization({ request: success.request, journalChain: [...committed, state25] });
    await restoredSuccess.reconcileRoutineAuthorization(success.request.requestId);
    assert.equal(restoredSuccess.getRoutineAuthorizationStatus(success.request.requestId).state, 8);
    await restoredSuccess.reconcileRoutineAuthorization(success.request.requestId);
    assert.equal(restoredSuccess.getRoutineAuthorizationStatus(success.request.requestId).state, 9);

    const invalid = await buildRequestForNonce(f, { nonceSequence: 2, shouldRevert: false,
      issuedAt: issuedAt + 1100n, sessionLabel: "desktop-restored-invalid-receipt" });
    const invalidStart = await ethers.provider.getBlock("latest");
    const invalidSimulation = simulationFor(f, invalid, invalidStart);
    const invalidOutcome = await executeSuccessOutcome(f, invalid, invalidSimulation);
    invalidOutcome.evidence.transactionStatus = 0;
    let invalidClock = BigInt(invalid.request.authorizationCore.issuedAt) + 50n;
    const restoredInvalid = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(invalid.request, {
      now: () => invalidClock++, simulate: async () => { throw new Error("must not simulate"); },
      execute: async () => { throw new Error("must not resubmit"); },
      reconcile: async () => invalidOutcome
    }));
    restoredInvalid.restoreRoutineAuthorization({ request: invalid.request,
      journalChain: journalChainFor(invalid.request, invalidSimulation, 7, invalidOutcome.receipt.transactionHash) });
    await restoredInvalid.reconcileRoutineAuthorization(invalid.request.requestId);
    assert.equal(restoredInvalid.getRoutineAuthorizationStatus(invalid.request.requestId).state, 24);
  });

  it("covers the remaining state-6 failure, state-7 unknown, and restored state-8 verifier transitions", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    const failed = await buildRequestForNonce(f, { nonceSequence: 0, shouldRevert: true, issuedAt,
      sessionLabel: "desktop-state6-failed" });
    const failedStart = await ethers.provider.getBlock("latest");
    const failedSimulation = simulationFor(f, failed, failedStart);
    const failedEvidence = await executeFailedEvidence(f, failed, failedSimulation);
    let clock = issuedAt + 50n;
    const state6 = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(failed.request, {
      now: () => clock++, simulate: async () => { throw new Error("must not simulate"); },
      execute: async () => { throw new Error("must not resubmit"); },
      reconcile: async () => ({ kind: "failed", evidence: failedEvidence })
    }));
    state6.restoreRoutineAuthorization({ request: failed.request,
      journalChain: journalChainFor(failed.request, failedSimulation) });
    await state6.reconcileRoutineAuthorization(failed.request.requestId);
    assert.equal(state6.getRoutineAuthorizationStatus(failed.request.requestId).state, 23);

    const unknown = await buildRequestForNonce(f, { nonceSequence: 1, shouldRevert: false,
      issuedAt: issuedAt + 150n, sessionLabel: "desktop-state7-unknown" });
    const unknownStart = await ethers.provider.getBlock("latest");
    const unknownSimulation = simulationFor(f, unknown, unknownStart);
    const unknownEvidence = {
      scanStartBlockNumber: unknownStart.number, scanStartBlockHash: unknownStart.hash,
      chainAccessible: true, capturedHeadBlockNumber: unknownStart.number, capturedHeadBlockHash: unknownStart.hash,
      matchingUserOperationLogs: [], entryPointNonceAfter: 1, targetCodeHash: f.targetCodeHash,
      targetRecordedValueAfter: ethers.ZeroHash, targetRecordedSequenceAfter: 0
    };
    clock = BigInt(unknown.request.authorizationCore.issuedAt) + 50n;
    const state7 = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(unknown.request, {
      now: () => clock++, simulate: async () => { throw new Error("must not simulate"); },
      execute: async () => { throw new Error("must not resubmit"); },
      reconcile: async () => ({ kind: "unknown", evidence: unknownEvidence })
    }));
    state7.restoreRoutineAuthorization({ request: unknown.request,
      journalChain: journalChainFor(unknown.request, unknownSimulation, 7, ethers.id("state7-unknown-transaction")) });
    await state7.reconcileRoutineAuthorization(unknown.request.requestId);
    assert.equal(state7.getRoutineAuthorizationStatus(unknown.request.requestId).state, 25);

    const success = await buildRequestForNonce(f, { nonceSequence: 1, shouldRevert: false,
      issuedAt: issuedAt + 300n, sessionLabel: "desktop-restored-state8" });
    const successStart = await ethers.provider.getBlock("latest");
    const successSimulation = simulationFor(f, success, successStart);
    const successOutcome = await executeSuccessOutcome(f, success, successSimulation);
    const committedChain = journalChainFor(success.request, successSimulation);
    const committed = committedChain.at(-1);
    const verified = journal.verifyPhilRoutineSuccessfulOutcomeV1({ request: success.request,
      journal: committed, outcome: successOutcome });
    const state8Host = new journal.PhilRoutineJournalSyntheticCasHostV1({ initial: committed, flush: async () => {} });
    const receiptVerified = await state8Host.publishVerifiedOutcome(verified, BigInt(committed.recordedAt) + 1n);
    clock = BigInt(receiptVerified.recordedAt) + 1n;
    const restoredState8 = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(success.request, {
      now: () => clock++, simulate: async () => { throw new Error("must not simulate"); },
      execute: async () => { throw new Error("must not resubmit"); }, reconcile: async () => successOutcome
    }));
    restoredState8.restoreRoutineAuthorization({ request: success.request,
      journalChain: [...committedChain, receiptVerified] });
    await restoredState8.reconcileRoutineAuthorization(success.request.requestId);
    assert.equal(restoredState8.getRoutineAuthorizationStatus(success.request.requestId).state, 9);
  });

  it("serializes cancellation and expiry ahead of any response or submission authority", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    const cancelled = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt,
      sessionLabel: "desktop-cancel-race"
    });
    let clock = issuedAt + 1n;
    let currentTrustedRequest = cancelled.request;
    const coordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1({
      now: () => clock,
      flush: async () => {},
      readTrustedState: async () => trustedState(currentTrustedRequest),
      simulate: async () => { throw new Error("must not simulate"); },
      execute: async () => { throw new Error("must not execute"); },
      reconcile: async () => { throw new Error("must not reconcile"); }
    });
    await coordinator.beginRoutineAuthorization(cancelled.request);
    const [cancelResult, responseResult] = await Promise.allSettled([
      coordinator.cancelRoutineAuthorization(cancelled.request.requestId),
      coordinator.acceptRoutineDeviceResponse({ requestId: cancelled.request.requestId, response: cancelled.response })
    ]);
    assert.equal(cancelResult.status, "fulfilled");
    assert.equal(cancelResult.value, "cancelled");
    assert.equal(responseResult.status, "rejected");
    assert.equal(coordinator.getRoutineAuthorizationStatus(cancelled.request.requestId).state, 20);

    const expired = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt: issuedAt + 200n,
      sessionLabel: "desktop-expiry-race"
    });
    clock = BigInt(expired.request.authorizationCore.expiresAt) + 1n;
    currentTrustedRequest = expired.request;
    await coordinator.beginRoutineAuthorization(expired.request);
    await assert.rejects(coordinator.acceptRoutineDeviceResponse({
      requestId: expired.request.requestId,
      response: expired.response
    }), (error) => error.code === "PHIL_ROUTINE_COORDINATOR_EXPIRED");
    assert.equal(coordinator.getRoutineAuthorizationStatus(expired.request.requestId).state, 21);
  });

  it("serializes actual cancel-versus-submission and cancel-versus-receipt races at the point of no return", async function () {
    const cancelledFixture = await deployStep6CFixture();
    const cancelledIssuedAt = BigInt(cancelledFixture.policy.validAfter) + 20n;
    const cancelled = await buildRequestForNonce(cancelledFixture, { nonceSequence: 0, shouldRevert: false,
      issuedAt: cancelledIssuedAt, sessionLabel: "desktop-cancel-wins-submit-race" });
    const cancelledHead = await ethers.provider.getBlock("latest");
    const cancelledSimulation = simulationFor(cancelledFixture, cancelled, cancelledHead);
    let cancelledClock = cancelledIssuedAt + 1n;
    const cancelWins = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(cancelled.request, {
      now: () => cancelledClock++, simulate: async () => cancelledSimulation,
      execute: async () => { throw new Error("cancelled request must not execute"); }
    }));
    await cancelWins.beginRoutineAuthorization(cancelled.request);
    await cancelWins.acceptRoutineDeviceResponse({ requestId: cancelled.request.requestId, response: cancelled.response });
    await cancelWins.simulateApprovedRoutineAuthorization(cancelled.request.requestId);
    const cancelFirst = cancelWins.cancelRoutineAuthorization(cancelled.request.requestId);
    const submitSecond = cancelWins.commitAndExecuteSimulatedRoutineAuthorization(cancelled.request.requestId);
    const [cancelResult, submitResult] = await Promise.allSettled([cancelFirst, submitSecond]);
    assert.deepEqual([cancelResult.status, cancelResult.value], ["fulfilled", "cancelled"]);
    assert.equal(submitResult.status, "rejected");
    assert.equal(cancelWins.getRoutineAuthorizationStatus(cancelled.request.requestId).state, 20);

    const submittedFixture = await deployStep6CFixture();
    const submittedIssuedAt = BigInt(submittedFixture.policy.validAfter) + 20n;
    const submitted = await buildRequestForNonce(submittedFixture, { nonceSequence: 0, shouldRevert: false,
      issuedAt: submittedIssuedAt, sessionLabel: "desktop-submit-wins-cancel-race" });
    const submittedHead = await ethers.provider.getBlock("latest");
    const submittedSimulation = simulationFor(submittedFixture, submitted, submittedHead);
    let submittedClock = submittedIssuedAt + 1n;
    let releaseExecution;
    const executionRelease = new Promise((resolve) => { releaseExecution = resolve; });
    let signalExecution;
    const executionEntered = new Promise((resolve) => { signalExecution = resolve; });
    let outcome;
    let releaseReceipt;
    const receiptRelease = new Promise((resolve) => { releaseReceipt = resolve; });
    let signalReceipt;
    const receiptEntered = new Promise((resolve) => { signalReceipt = resolve; });
    const submitWins = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(submitted.request, {
      now: () => submittedClock++, simulate: async () => submittedSimulation,
      execute: async () => {
        signalExecution();
        await executionRelease;
        outcome = await executeSuccessOutcome(submittedFixture, submitted, submittedSimulation);
        return outcome;
      },
      reconcile: async () => {
        signalReceipt();
        await receiptRelease;
        return outcome;
      }
    }));
    await submitWins.beginRoutineAuthorization(submitted.request);
    await submitWins.acceptRoutineDeviceResponse({ requestId: submitted.request.requestId, response: submitted.response });
    await submitWins.simulateApprovedRoutineAuthorization(submitted.request.requestId);
    const submitFirst = submitWins.commitAndExecuteSimulatedRoutineAuthorization(submitted.request.requestId);
    await executionEntered;
    const cancelDuringSubmit = submitWins.cancelRoutineAuthorization(submitted.request.requestId);
    releaseExecution();
    const [submitRace, cancelSubmitRace] = await Promise.allSettled([submitFirst, cancelDuringSubmit]);
    assert.equal(submitRace.status, "fulfilled");
    assert.deepEqual([cancelSubmitRace.status, cancelSubmitRace.value], ["fulfilled", "too_late_submission_committed"]);
    assert.equal(submitWins.getRoutineAuthorizationStatus(submitted.request.requestId).state, 8);

    const receiptFirst = submitWins.reconcileRoutineAuthorization(submitted.request.requestId);
    await receiptEntered;
    const cancelDuringReceipt = submitWins.cancelRoutineAuthorization(submitted.request.requestId);
    releaseReceipt();
    const [receiptRace, cancelReceiptRace] = await Promise.allSettled([receiptFirst, cancelDuringReceipt]);
    assert.equal(receiptRace.status, "fulfilled");
    assert.deepEqual([cancelReceiptRace.status, cancelReceiptRace.value], ["fulfilled", "too_late_submission_committed"]);
    assert.equal(submitWins.getRoutineAuthorizationStatus(submitted.request.requestId).state, 9);
  });

  it("fails terminally on policy drift, lock/session replacement, and pre-state drift before commit", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    const drifted = await buildRequestForNonce(f, { nonceSequence: 0, shouldRevert: false, issuedAt,
      sessionLabel: "desktop-policy-drift" });
    let clock = issuedAt + 1n;
    const driftCoordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(drifted.request, {
      now: () => clock++,
      readTrustedState: async () => trustedState({ ...drifted.request, catalogHash: ethers.id("changed-catalog") }),
      simulate: async () => { throw new Error("must not simulate drifted work"); },
      execute: async () => { throw new Error("must not execute drifted work"); }
    }));
    await driftCoordinator.beginRoutineAuthorization(drifted.request);
    await assert.rejects(driftCoordinator.acceptRoutineDeviceResponse({ requestId: drifted.request.requestId,
      response: drifted.response }), (error) => error.code === "PHIL_ROUTINE_COORDINATOR_TRUSTED_STATE_DRIFT");
    assert.equal(driftCoordinator.getRoutineAuthorizationStatus(drifted.request.requestId).state, 22);

    const locked = await buildRequestForNonce(f, { nonceSequence: 0, shouldRevert: false, issuedAt: issuedAt + 20n,
      sessionLabel: "desktop-session-lock" });
    clock = BigInt(locked.request.authorizationCore.issuedAt) + 1n;
    const lockCoordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(locked.request, {
      now: () => clock++,
      readTrustedState: async () => trustedState(locked.request, { desktopUnlocked: false }),
      simulate: async () => { throw new Error("must not simulate locked work"); },
      execute: async () => { throw new Error("must not execute locked work"); }
    }));
    await lockCoordinator.beginRoutineAuthorization(locked.request);
    await assert.rejects(lockCoordinator.acceptRoutineDeviceResponse({ requestId: locked.request.requestId,
      response: locked.response }), (error) => error.code === "PHIL_ROUTINE_COORDINATOR_SESSION_INVALID");
    assert.equal(lockCoordinator.getRoutineAuthorizationStatus(locked.request.requestId).state, 22);

    const prestate = await buildRequestForNonce(f, { nonceSequence: 0, shouldRevert: false, issuedAt: issuedAt + 40n,
      sessionLabel: "desktop-prestate-drift" });
    const head = await ethers.provider.getBlock("latest");
    const first = simulationFor(f, prestate, head);
    const changedHead = { number: head.number, hash: ethers.id("replacement-head") };
    const changed = simulationFor(f, prestate, changedHead);
    let simulations = 0;
    clock = BigInt(prestate.request.authorizationCore.issuedAt) + 1n;
    const prestateCoordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1(coordinatorInput(prestate.request, {
      now: () => clock++,
      simulate: async () => (++simulations === 1 ? first : changed),
      execute: async () => { throw new Error("must not execute changed pre-state"); }
    }));
    await prestateCoordinator.beginRoutineAuthorization(prestate.request);
    await prestateCoordinator.acceptRoutineDeviceResponse({ requestId: prestate.request.requestId, response: prestate.response });
    await prestateCoordinator.simulateApprovedRoutineAuthorization(prestate.request.requestId);
    await assert.rejects(prestateCoordinator.commitAndExecuteSimulatedRoutineAuthorization(prestate.request.requestId),
      (error) => error.code === "PHIL_ROUTINE_COORDINATOR_TRUSTED_STATE_DRIFT");
    assert.equal(prestateCoordinator.getRoutineAuthorizationStatus(prestate.request.requestId).state, 22);
  });
});
