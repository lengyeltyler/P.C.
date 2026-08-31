const assert = require("node:assert/strict");
const { createECDH } = require("node:crypto");
const http = require("node:http");
const os = require("node:os");
const { ethers } = require("hardhat");

const {
  auth,
  deployStep6CFixture,
  buildRequestForNonce,
  eventCommitment,
  serializePackedUserOperation,
  setNextTimestamp
} = require("../../../test/helpers/phil-v1-step6c-fixture.cjs");
const journal = require("../../phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts");
const transport = require("../../phil-device-sdk/src/routineAuthorizationTransportV1.ts");
const { createRoutineAuthorizationHost } = require("../src/main/routine-authorization-host.cjs");

function simulationFor(fixture, built, head) {
  const packedUserOperationBytes = serializePackedUserOperation(built.userOp);
  return {
    entryPoint: fixture.entryPointAddress,
    sender: fixture.accountAddress,
    userOperationNonce: built.request.action.userOpNonce,
    serializedUserOperationHash: ethers.keccak256(packedUserOperationBytes),
    officialUserOperationHash: built.userOpHash,
    packedUserOperationBytes,
    target: fixture.targetAddress,
    targetRecordedValueBefore: ethers.ZeroHash,
    targetRecordedSequenceBefore: 0,
    targetPreStateHash: journal.derivePhilRoutineTargetPreStateHashV1({
      target: fixture.targetAddress,
      approvedTargetRuntimeCodeHash: fixture.targetCodeHash,
      recordedValueBefore: ethers.ZeroHash,
      recordedSequenceBefore: 0,
      scanStartBlockNumber: head.number,
      scanStartBlockHash: head.hash
    }),
    scanStartBlockNumber: head.number,
    scanStartBlockHash: head.hash
  };
}

async function executeSuccess(fixture, built, simulation) {
  await setNextTimestamp(BigInt(built.request.authorizationCore.issuedAt) + 10n);
  const transaction = await fixture.entryPoint.handleOps([built.userOp], fixture.beneficiary.address);
  const chainReceipt = await transaction.wait();
  const block = await ethers.provider.getBlock(chainReceipt.blockNumber);
  const topics = [
    ethers.id("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"),
    ethers.id("PhilV1Step6CAuthorizationConsumed(bytes32,bytes32,bytes32,bytes32,bytes32,address)"),
    ethers.id("ValueRecorded(bytes32,uint64)")
  ];
  const logs = topics.map((topic) => chainReceipt.logs.find((log) => log.topics[0] === topic));
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
    executionEnvironmentHash: fixture.environment.executionEnvironmentHash,
    entryPointEventCommitment: eventCommitment(logs[0]),
    accountEventCommitment: eventCommitment(logs[1]),
    targetEventCommitment: eventCommitment(logs[2]),
    targetPreStateHash: simulation.targetPreStateHash,
    finalTargetStateHash: ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes32", "uint64", "bytes32", "bytes32"],
      [fixture.targetAddress, auth.PHIL_STEP6C_RECORDED_VALUE, 1, chainReceipt.hash, block.hash]
    )),
    entryPointCodeHash: fixture.entryPointCodeHash,
    senderCreatorCodeHash: fixture.senderCreatorCodeHash,
    accountCodeHash: fixture.accountRuntimeCodeHash,
    targetCodeHash: fixture.targetCodeHash,
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
      logs: chainReceipt.logs.map((log) => ({
        address: log.address, topics: [...log.topics], data: log.data, index: log.index,
        transactionHash: log.transactionHash, blockHash: log.blockHash, removed: false
      })),
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
      entryPointCodeHash: fixture.entryPointCodeHash,
      senderCreatorCodeHash: fixture.senderCreatorCodeHash,
      accountCodeHash: fixture.accountRuntimeCodeHash,
      targetCodeHash: fixture.targetCodeHash,
      transactionHash: chainReceipt.hash,
      blockHash: block.hash
    }
  };
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

function stores() {
  const keys = new Map();
  const chains = new Map();
  const requests = new Map();
  return {
    keys,
    chains,
    requests,
    protectedKeyStore: {
      create(id, key) { assert.equal(keys.has(id), false);keys.set(id, Buffer.from(key));return Buffer.from(key); },
      load(id) { return Buffer.from(keys.get(id)); },
      delete(id) { keys.delete(id); }
    },
    journalStore: {
      async append(requestId, generation, frame) {
        const chain = chains.get(requestId) || [];
        assert.equal(Number(generation), chain.length + 1);
        chain.push(frame);chains.set(requestId, chain);
      },
      async read(requestId) { return [...(chains.get(requestId) || [])]; },
      async list() { return [...chains.keys()]; },
      async delete(requestId) { chains.delete(requestId); }
    },
    requestStore: {
      async save(requestId, value) { assert.equal(requests.has(requestId),false);requests.set(requestId,value); },
      async load(requestId) { if (!requests.has(requestId)) throw new Error("missing request");return requests.get(requestId); },
      async list() { return [...requests.keys()]; },
      async delete(requestId) { requests.delete(requestId); }
    }
  };
}

function headers(bootstrap, contentType, body) {
  return {
    host: `${bootstrap.ipv4}:${bootstrap.port}`,
    "x-philcore-routine-request": bootstrap.requestId,
    "content-length": String(body.length),
    "content-type": contentType,
    "cache-control": "no-store"
  };
}

function privateAddress() { return Object.values(os.networkInterfaces()).flat().find((value)=>value?.family==="IPv4"&&!value.internal&&
  (/^10\./u.test(value.address)||/^192\.168\./u.test(value.address)||/^172\.(?:1[6-9]|2[0-9]|3[01])\./u.test(value.address)))?.address; }
function postHttp(bootstrap,pathName,contentType,body) { return new Promise((resolve,reject)=>{const request=http.request({host:bootstrap.ipv4,port:bootstrap.port,
  path:pathName,method:"POST",headers:headers(bootstrap,contentType,body)},(response)=>{const chunks=[];response.on("data",(chunk)=>chunks.push(chunk));
    response.on("end",()=>resolve({status:response.statusCode,body:Buffer.concat(chunks),headers:response.headers}));});request.once("error",reject);request.end(body);}); }

describe("Phil V1 Step 6C-2 protected Desktop product wiring", function () {
  for (const outcomeKind of ["success","submission_unknown","invalid_receipt","failed_execution"]) {
  it(`runs the encrypted QR-to-receipt path with ${outcomeKind} and protects durable outcomes`, async function () {
    const fixture = await deployStep6CFixture();
    const initialBlock = await ethers.provider.getBlock("latest");
    const issuedAt = Number(initialBlock.timestamp) + 20;
    const built = await buildRequestForNonce(fixture, {
      nonceSequence: 0,
      shouldRevert: outcomeKind === "failed_execution",
      issuedAt,
      sessionLabel: "step6c2-product"
    });
    const head = await ethers.provider.getBlock("latest");
    const simulation = simulationFor(fixture, built, head);
    const storage = stores();
    let now = BigInt(issuedAt + 1);
    let acceptedOutcome = null;
    const hostOptions = {
      disposableProfileId: ethers.id("PHIL_STEP6C2_DISPOSABLE_PROFILE"),
      ipv4: "192.168.7.9",
      requestFactory: async (intent) => { assert.deepEqual(intent, { action: "record_harmless_value" });return built.request; },
      readTrustedState: async () => ({ request: built.request, desktopUnlocked: true, iphoneSessionCurrent: true }),
      simulate: async () => simulation,
      execute: async () => {
        if(outcomeKind==="submission_unknown") throw new Error("submission connection lost");
        if(outcomeKind==="failed_execution") return acceptedOutcome={kind:"failed",evidence:await executeFailedEvidence(fixture,built,simulation)};
        acceptedOutcome=await executeSuccess(fixture,built,simulation);
        if(outcomeKind==="invalid_receipt") acceptedOutcome.evidence.transactionStatus=0;
        return acceptedOutcome;
      },
      reconcile: async () => acceptedOutcome || {kind:"unknown",evidence:{
        scanStartBlockNumber:head.number,scanStartBlockHash:head.hash,chainAccessible:true,
        capturedHeadBlockNumber:head.number,capturedHeadBlockHash:head.hash,matchingUserOperationLogs:[],
        entryPointNonceAfter:0,targetCodeHash:fixture.targetCodeHash,targetRecordedValueAfter:ethers.ZeroHash,targetRecordedSequenceAfter:0}},
      readCurrentNonce:async()=>String(await fixture.entryPoint.getNonce(fixture.accountAddress,0)),
      protectedKeyStore: storage.protectedKeyStore,
      journalStore: storage.journalStore,
      requestStore: storage.requestStore,
      now: () => now++
    };
    const host = createRoutineAuthorizationHost(hostOptions);
    const begun = await host.beginRoutineAuthorization({ action: "record_harmless_value" }, { port: 43123 });
    const bootstrap = transport.decodePhilRoutineTransportBootstrapV1(begun.qrPayload);
    assert.equal(storage.chains.get(built.request.requestId).length, 2, "genesis and waiting must both be durable");

    const phone = createECDH("prime256v1");phone.setPrivateKey(Buffer.from("02".repeat(32), "hex"));
    const phonePublic = phone.getPublicKey(undefined, "uncompressed");
    const beginBody = Buffer.from(transport.serializePhilRoutineTransportBeginJsonV1({
      protocolVersion: 1,
      sessionId: bootstrap.sessionId,
      requestId: bootstrap.requestId,
      iphonePublicKey: `0x${phonePublic.toString("hex")}`
    }));
    const beginResult = await host.dispatchHttp({
      requestId: bootstrap.requestId,
      method: "POST",
      path: transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath,
      headers: headers(bootstrap, "application/json", beginBody),
      body: beginBody
    });
    assert.equal(beginResult.status, 200);
    const transcriptHash = transport.derivePhilRoutineTransportTranscriptHashV1({
      bootstrap,
      iphonePublicKeyX963: phonePublic
    });
    const phoneKey = transport.derivePhilRoutineTransportKeyV1({
      privateKey: phone.getPrivateKey(),
      peerPublicKeyX963: bootstrap.desktopPublicKeyX963,
      transcriptHash
    });
    const phoneCipher = new transport.PhilRoutineTransportCipherV1({ key: phoneKey });
    const requestAad = transport.derivePhilRoutineTransportAadV1({
      direction: "request", sessionId: bootstrap.sessionId, requestId: bootstrap.requestId
    });
    const decryptedRequest = phoneCipher.decrypt({ frame: beginResult.body, aad: requestAad });
    assert.deepEqual(auth.parsePhilRoutineAuthorizationRequestJsonV1(decryptedRequest), built.request);
    const status = await host.getRoutineAuthorizationStatus(built.request.requestId);
    assert.deepEqual(Object.keys(status).sort(), ["comparisonFingerprint", "expiresAt", "requestId", "state", "terminalReason"]);
    assert.equal(status.comparisonFingerprint, transport.formatPhilRoutineTransportFingerprintV1(transcriptHash));

    const responsePlaintext = auth.serializePhilRoutineAuthorizationResponseJsonV1({
      request: built.request,
      response: built.response
    });
    const responseAad = transport.derivePhilRoutineTransportAadV1({
      direction: "response", sessionId: bootstrap.sessionId, requestId: bootstrap.requestId
    });
    const responseFrame = phoneCipher.encrypt({ plaintext: responsePlaintext, aad: responseAad });
    const completeResult = await host.dispatchHttp({
      requestId: bootstrap.requestId,
      method: "POST",
      path: transport.PHIL_ROUTINE_TRANSPORT_V1.completePath,
      headers: headers(bootstrap, "application/octet-stream", responseFrame),
      body: responseFrame
    });
    if(outcomeKind==="failed_execution") {
      assert.notEqual(completeResult.status,204);
      assert.equal((await host.getRoutineAuthorizationStatus(built.request.requestId)).state,23);
      assert.equal(await fixture.target.recordedSequence(),0n);
      return;
    }
    if(outcomeKind!=="success") {
      assert.notEqual(completeResult.status,204,"non-successful durable state must never acknowledge success");
      const expected=outcomeKind==="submission_unknown" ? 25 : 6;
      assert.equal((await host.getRoutineAuthorizationStatus(built.request.requestId)).state,expected);
      for(const current of [host,createRoutineAuthorizationHost(hostOptions)]) {
        if(current!==host) {
          if(outcomeKind==="invalid_receipt") await assert.rejects(current.restoreAllRoutineAuthorizations());
          else await current.restoreAllRoutineAuthorizations();
        }
        assert.equal((await current.getRoutineAuthorizationStatus(built.request.requestId)).state,expected);
        assert.equal((await current.acceptanceBaseline()).unresolvedSubmissionCount,1);
        await assert.rejects(current.beginRoutineAuthorization({action:"record_harmless_value"},{port:43123}),/UNRESOLVED_SUBMISSION/);
        assert.throws(()=>current.assertDisposableProfileDeletionSafe(),/TOO_EARLY/);
        assert.throws(()=>current.disposeForDeviceReplacement(),/TOO_EARLY/);
        await assert.rejects(current.deleteDisposableProfile(),/TOO_EARLY/);
        assert.equal(await current.cancelRoutineAuthorization(built.request.requestId),"too_late_submission_committed");
      }
      assert.equal(await fixture.target.recordedSequence(),outcomeKind==="submission_unknown"?0n:1n);
      return;
    }
    assert.equal(completeResult.status, 204);
    assert.equal(completeResult.body.length, 0);
    assert.equal((await host.getRoutineAuthorizationStatus(built.request.requestId)).state, 9);
    assert.equal(await fixture.target.recordedSequence(), 1n);
    assert.equal(storage.chains.get(built.request.requestId).length, 7);
  });

  }

  it("fails closed on header, ordering, replay, cancellation, and exact disposable deletion", async function () {
    const fixture = await deployStep6CFixture();
    const initialBlock = await ethers.provider.getBlock("latest");
    const issuedAt = Number(initialBlock.timestamp) + 20;
    const built = await buildRequestForNonce(fixture, {
      nonceSequence: 0, shouldRevert: false, issuedAt, sessionLabel: "step6c2-fail-closed"
    });
    const head = await ethers.provider.getBlock("latest");
    const simulation = simulationFor(fixture, built, head);
    const storage = stores();let now = BigInt(issuedAt + 1);
    const host = createRoutineAuthorizationHost({
      disposableProfileId: ethers.id("PHIL_STEP6C2_DISPOSABLE_PROFILE_FAIL"),
      ipv4: "192.168.7.9",
      requestFactory: async () => built.request,
      readTrustedState: async () => ({ request: built.request, desktopUnlocked: true, iphoneSessionCurrent: true }),
      simulate: async () => simulation,
      execute: async () => { throw new Error("must not execute"); },
      reconcile: async () => { throw new Error("must not reconcile"); },
      protectedKeyStore: storage.protectedKeyStore,
      journalStore: storage.journalStore,
      requestStore: storage.requestStore,
      now: () => now++
    });
    const begun = await host.beginRoutineAuthorization({}, { port: 43123 });
    await assert.rejects(host.beginRoutineAuthorization({}, { port: 43124 }), /ROUTINE_ACTIVE_SESSION_EXISTS/);
    await assert.rejects(host.deleteDisposableProfile(),/ROUTINE_PROFILE_DELETE_TOO_EARLY/);
    const bootstrap = transport.decodePhilRoutineTransportBootstrapV1(begun.qrPayload);
    const premature = Buffer.from([1]);
    assert.equal((await host.dispatchHttp({ requestId: bootstrap.requestId, method: "POST",
      path: transport.PHIL_ROUTINE_TRANSPORT_V1.completePath,
      headers: headers(bootstrap, "application/octet-stream", premature), body: premature })).status, 409);
    const cancelled = await host.cancelRoutineAuthorization(bootstrap.requestId);
    assert.equal(cancelled, "cancelled");
    assert.equal((await host.getRoutineAuthorizationStatus(bootstrap.requestId)).state, 20);
    const deleted = await host.deleteDisposableProfile();
    assert.deepEqual(deleted, { status: "deleted", identityOrRecoveryStateTouched: false });
    assert.equal(storage.keys.size, 0);
    assert.equal(storage.chains.size, 0);
  });

  it("reopens the protected journal key and terminally reconciles an interrupted pre-commit request", async function () {
    const fixture = await deployStep6CFixture();
    const initialBlock = await ethers.provider.getBlock("latest"), issuedAt = Number(initialBlock.timestamp) + 20;
    const built = await buildRequestForNonce(fixture, { nonceSequence: 0, shouldRevert: false, issuedAt, sessionLabel: "step6c2-restart" });
    const storage = stores();let now = BigInt(issuedAt + 1);
    const options = {
      disposableProfileId: ethers.id("PHIL_STEP6C2_DISPOSABLE_PROFILE_RESTART"), ipv4: "192.168.7.9",
      requestFactory: async () => built.request,
      readTrustedState: async () => ({ request: built.request, desktopUnlocked: true, iphoneSessionCurrent: true }),
      simulate: async () => { throw new Error("pre-commit restore must not simulate"); },
      execute: async () => { throw new Error("pre-commit restore must not execute"); },
      reconcile: async () => { throw new Error("pre-commit restore must not scan chain"); },
      protectedKeyStore: storage.protectedKeyStore, journalStore: storage.journalStore,
      requestStore: storage.requestStore, now: () => now++
    };
    const first = createRoutineAuthorizationHost(options);
    await first.beginRoutineAuthorization({}, { port: 43123 });
    assert.equal(storage.chains.get(built.request.requestId).length,2);
    const restarted = createRoutineAuthorizationHost(options);
    const restored = await restarted.restoreAllRoutineAuthorizations();
    assert.equal(restored.length,1);
    assert.equal(restored[0].requestId,built.request.requestId);
    assert.equal((await restarted.getRoutineAuthorizationStatus(built.request.requestId)).state,22);
    assert.equal(storage.chains.get(built.request.requestId).length,3);
  });

  it("routes the real listener completion only to the new active session after cancellation",async function () {
    const ipv4=privateAddress();assert.ok(ipv4,"private test interface required");const fixture=await deployStep6CFixture();
    const initial=await ethers.provider.getBlock("latest"),issuedAt=Number(initial.timestamp)+20;
    const firstBuilt=await buildRequestForNonce(fixture,{nonceSequence:0,shouldRevert:false,issuedAt,sessionLabel:"listener-cancelled"});
    const secondBuilt=await buildRequestForNonce(fixture,{nonceSequence:0,shouldRevert:false,issuedAt,sessionLabel:"listener-active"});
    const head=await ethers.provider.getBlock("latest"),simulation=simulationFor(fixture,secondBuilt,head),storage=stores();let now=BigInt(issuedAt+1),index=0,outcome;
    const host=createRoutineAuthorizationHost({disposableProfileId:ethers.id("PHIL_STEP6C2_LISTENER_PROFILE"),ipv4,
      requestFactory:async()=>[firstBuilt.request,secondBuilt.request][index++],readTrustedState:async()=>({request:secondBuilt.request,desktopUnlocked:true,iphoneSessionCurrent:true}),
      simulate:async()=>simulation,execute:async()=>outcome=await executeSuccess(fixture,secondBuilt,simulation),reconcile:async()=>outcome,
      protectedKeyStore:storage.protectedKeyStore,journalStore:storage.journalStore,requestStore:storage.requestStore,now:()=>now++});
    await host.startListener();try {
      const first=await host.beginRoutineAuthorization({action:"record_harmless_value"});await host.cancelRoutineAuthorization(first.requestId);
      const second=await host.beginRoutineAuthorization({action:"record_harmless_value"}),bootstrap=transport.decodePhilRoutineTransportBootstrapV1(second.qrPayload);
      const phone=createECDH("prime256v1");phone.setPrivateKey(Buffer.from("07".repeat(32),"hex"));
      const beginBody=Buffer.from(transport.serializePhilRoutineTransportBeginJsonV1({protocolVersion:1,sessionId:bootstrap.sessionId,requestId:bootstrap.requestId,
        iphonePublicKey:`0x${phone.getPublicKey(undefined,"uncompressed").toString("hex")}`}));
      const beginResult=await postHttp(bootstrap,transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath,"application/json",beginBody);assert.equal(beginResult.status,200);
      const transcriptHash=transport.derivePhilRoutineTransportTranscriptHashV1({bootstrap,iphonePublicKeyX963:phone.getPublicKey(undefined,"uncompressed")});
      const phoneCipher=new transport.PhilRoutineTransportCipherV1({key:transport.derivePhilRoutineTransportKeyV1({privateKey:phone.getPrivateKey(),peerPublicKeyX963:bootstrap.desktopPublicKeyX963,transcriptHash})});
      const responseFrame=phoneCipher.encrypt({plaintext:auth.serializePhilRoutineAuthorizationResponseJsonV1({request:secondBuilt.request,response:secondBuilt.response}),
        aad:transport.derivePhilRoutineTransportAadV1({direction:"response",sessionId:bootstrap.sessionId,requestId:bootstrap.requestId})});
      const completed=await postHttp(bootstrap,transport.PHIL_ROUTINE_TRANSPORT_V1.completePath,"application/octet-stream",responseFrame);
      assert.equal(completed.status,204);assert.equal((await host.getRoutineAuthorizationStatus(second.requestId)).state,9);
    } finally { await host.stopListener(); }
  });
});
