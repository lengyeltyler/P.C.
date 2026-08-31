"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const ui = require("../src/renderer/routine-authorization-ui.cjs");

const requestId = `0x${"12".repeat(32)}`;

test("fallback enrollment is never presented as an authorization request", () => {
  const state = ui.beginState({
    requestId,
    qrDataUrl: "data:image/png;base64,AA",
    comparisonFingerprint: "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF",
    expiresAt: "1800000300",
    status: "enrollment_waiting"
  });
  assert.equal(state.kind, "enrollment");
  assert.match(state.notice, /needs a routine approval key/u);
  assert.match(state.notice, /Open Phil > Approve/u);
  assert.match(state.notice, /Do not use Pair/u);
  assert.equal(ui.panelCopy(state).heading, "Enroll your iPhone routine key");
  assert.match(ui.panelCopy(state).description, /Open Phil > Approve/u);
});

test("authorization and replacement enrollment retain distinct product copy", () => {
  const authorization = ui.beginState({ requestId, qrDataUrl: "data:x", expiresAt: "1", status: "transport_waiting" });
  const replacement = ui.beginState({ requestId, qrDataUrl: "data:y", expiresAt: "1", status: "enrollment_waiting", enrollmentMode: "replacement" });
  assert.equal(authorization.kind, "authorization");
  assert.match(authorization.notice, /Open Phil > Approve/u);
  assert.equal(ui.panelCopy(authorization).heading, "Approve with your iPhone");
  assert.equal(replacement.kind, "replacement_enrollment");
  assert.match(replacement.notice, /Do not use Pair/u);
  assert.equal(ui.panelCopy(replacement).heading, "Replace your iPhone routine key");
});

test("a stale asynchronous status response cannot take ownership of a newer request", () => {
  assert.equal(ui.ownsRefresh(requestId, requestId, 4, 4), true);
  assert.equal(ui.ownsRefresh(`0x${"34".repeat(32)}`, requestId, 4, 4), false);
  assert.equal(ui.ownsRefresh(requestId, requestId, 5, 4), false);
  assert.equal(ui.ownsRefresh(requestId, requestId, 5, null), true);
});

test("terminal refresh removes stale QR material and states the next action", () => {
  const enrollment = ui.beginState({ requestId, qrDataUrl: "data:stale", expiresAt: "1", status: "enrollment_waiting" });
  const completed = ui.refreshedState(enrollment, { requestId, state: "completed", expiresAt: "1", comparisonFingerprint: "AAAA" });
  assert.equal(completed.qrDataUrl, null);
  assert.match(completed.notice, /durably enrolled/u);
  assert.equal(ui.isTerminalState(completed.state), true);

  const authorization = ui.beginState({ requestId, qrDataUrl: "data:stale", expiresAt: "1", status: "transport_waiting" });
  const expired = ui.refreshedState(authorization, { requestId, state: "expired", expiresAt: "1" });
  assert.equal(expired.qrDataUrl, null);
  assert.match(expired.notice, /expired/u);
});

test("enrollment refresh exposes only sanitized connection and rejection diagnostics", () => {
  const enrollment = ui.beginState({ requestId, qrDataUrl: "data:live", expiresAt: "1", status: "enrollment_waiting" });
  const reached = ui.refreshedState(enrollment, {
    requestId, state: "waiting", preflightCount: 1, completionAttemptCount: 0,
    lastAttempt: { stage: "preflight_accepted", code: null, at: "1", preflightCount: 1, completionAttemptCount: 0 }
  });
  assert.match(reached.notice, /reached this Mac/u);assert.equal(reached.preflightCount,1);
  const rejected = ui.refreshedState(reached, {
    requestId, state: "waiting", preflightCount: 1, completionAttemptCount: 1,
    lastAttempt: { stage: "completion_rejected", code: "PHIL_ROUTINE_ENROLLMENT_PROOF_INVALID", at: "2", preflightCount: 1, completionAttemptCount: 1 }
  });
  assert.match(rejected.notice, /did not match this request/u);assert.doesNotMatch(rejected.notice,/PHIL_ROUTINE_ENROLLMENT_PROOF_INVALID/u);
  assert.equal(rejected.qrDataUrl,"data:live");assert.equal(rejected.completionAttemptCount,1);
});

test("begin request classifies success, safe failure, bridge rejection, and slow progress", async () => {
  const started = await ui.beginRequest({
    action: "record_harmless_value",
    invoke: async () => ({ requestId: `0x${"11".repeat(32)}`, qrDataUrl: "data:image/png;base64,AA" })
  });
  assert.equal(started.kind, "started");

  const failed = await ui.beginRequest({
    invoke: async () => ({ status: "failed", reason: "routine_authorization_environment_failed" })
  });
  assert.deepEqual(failed, { kind: "failed", reason: "routine_authorization_environment_failed" });

  const rejected = await ui.beginRequest({ invoke: async () => { throw new Error("sensitive detail"); } });
  assert.deepEqual(rejected, { kind: "failed", reason: "routine_authorization_bridge_failed" });
  assert.equal(JSON.stringify(rejected).includes("sensitive detail"), false);

  let slow = false;
  let scheduled = null;
  let resolvePending;
  const pending = ui.beginRequest({
    invoke: () => new Promise((resolve) => { resolvePending = resolve; }),
    onSlow: () => { slow = true; },
    schedule: (callback) => { scheduled = callback; return 7; },
    cancel: () => {}
  });
  scheduled();
  assert.equal(slow, true);
  resolvePending({ status: "failed", reason: "routine_authorization_failed" });
  assert.equal((await pending).kind, "failed");
});


test("terminal projection distinguishes rejection, cancellation, expiry, failure and unknown", () => {
  for (const [state,reason,stage] of [[9,null,"success"],[20,"rejected","rejected"],[20,null,"cancelled"],
    [21,null,"expired"],[22,null,"failure"],[23,null,"execution_failed"],[24,null,"receipt_invalid"],[25,null,"unknown"]]) {
    const result={state,terminalReason:reason};assert.equal(ui.terminalStage(result),stage);
    const projected=ui.refreshedState({kind:"authorization",qrDataUrl:"old",terminalReason:"rejected"},result);
    assert.equal(projected.qrDataUrl,null);assert.equal(projected.terminalReason,reason);
    if(stage!=="rejected") assert.doesNotMatch(projected.notice,/You rejected/);
  }
  assert.match(ui.guidanceForStage("unknown").message,/Do not retry/);
  for(const state of [6,7,8,24,25]) assert.equal(ui.blocksNewWork({state}),true);
  for(const state of [9,20,21]) assert.equal(ui.blocksNewWork({state}),false);
});


function baselineSchemaInput(presentationState="idle") {
  const common={schemaVersion:1,observedAt:"100",pendingRequestCount:0,pairingState:"enrolled",pairingGeneration:"1",
    pairingFingerprint:"0x"+"ab".repeat(32),sourceCommit:"a".repeat(40),sourceTree:"b".repeat(40)};
  const desktop={...common,desktopProcessId:12345,activeRequestId:null,unresolvedSubmissionCount:0,presentationRequestId:null,qrVisible:false,presentationState,expectedNonce:"0",
    preRequest:{documentReadyState:"complete",runtimeInitialized:true,beginInFlight:false,pollGeneration:0,
      expiresAt:null,qrPayload:null,comparisonFingerprint:null,terminalReason:null,lastAttempt:null,
      preflightCount:0,completionAttemptCount:0,lastFailureReason:null,notice:""}};
  const ios={...common,phase:"idle",build:"58",simulator:false,secureEnclaveBacked:true,userPresenceRequired:true,
    deviceIdentifier:"test-device-only",installedArtifactReadback:{source:"installed-device-bundle-readback",deviceIdentifier:"test-device-only",appPath:"/synthetic/InstalledPhone.app",observedAt:"100"}};
  const freeze={schemaVersion:1,configuration:"Release",fixtureInjection:false,sourceCommit:common.sourceCommit,sourceTree:common.sourceTree,
    desktop:{appPath:"/synthetic/Desktop.app",directorySha256:"c".repeat(64)},ios:{appPath:"/synthetic/Phone.app",directorySha256:"d".repeat(64),build:"58"}};
  return {desktop,ios,freeze,now:100,verifyArtifacts:false};
}

test("pre-physical baseline fails closed on stale, unknown, mismatched and synthetic state", () => {
  const {validateBaseline}=require("../../../scripts/release/routine-acceptance-baseline.cjs");
  const input=baselineSchemaInput(),{desktop,ios}=input;
  assert.equal(validateBaseline(input).verdict,"BASELINE SCHEMA ONLY: PASS");
  assert.equal(validateBaseline(input).errors.length,0,"unit schema check only; artifact verification deliberately not run");
  for(const delta of [{desktopProcessId:null},{pendingRequestCount:1},{expectedNonce:"1"},{qrVisible:true},{presentationRequestId:"old"},
    {observedAt:"10"},{unresolvedSubmissionCount:1},{pairingFingerprint:"wrong"},{sourceTree:"unknown"}]) {
    assert.ok(validateBaseline({...input,desktop:{...desktop,...delta}}).errors.length);
  }
  for(const delta of [{installedArtifactReadback:null},{deviceIdentifier:"other-device"},{phase:"failed"},{build:"57"},{simulator:true},{secureEnclaveBacked:false},{userPresenceRequired:false}]) {
    assert.ok(validateBaseline({...input,ios:{...ios,...delta}}).errors.length);
  }
  assert.ok(validateBaseline({...input,verifyArtifacts:true}).errors.includes("desktop_artifact_unreadable"));
  assert.ok(validateBaseline({}).errors.length);
});

test("acceptance orchestration owns generation and stops before creating on contamination", async () => {
  const {createAcceptanceProcedure}=require("../../../scripts/release/routine-acceptance-procedure.cjs");
  const make=()=>createAcceptanceProcedure({baseline:{verdict:"PHYSICAL ACCEPTANCE BASELINE: PASS",errors:[],verifiedAt:100},now:()=>100});
  const request=id=>({requestId:id,qrPayload:`qr${id}`,expiresAt:"220"});
  const procedure=make();assert.match(procedure.instructions,/without stopping to report/);
  assert.equal((await procedure.generateRequest(async()=>request("1"))).decision,"approve");
  assert.equal(procedure.observe({requestId:"1",state:9}),"CONTINUE");
  assert.equal((await procedure.generateRequest(async()=>request("2"))).decision,"reject");
  assert.equal(procedure.observe({requestId:"2",state:20,terminalReason:"rejected"}),"COMPLETE");
  const dirty=make();await dirty.generateRequest(async()=>request("1"));let calls=0;
  await assert.rejects(dirty.generateRequest(async()=>{calls++;return request("2");}),/STOP_AND_DEBUG/);
  assert.equal(calls,0);assert.equal(dirty.status().stopped,true);
  assert.throws(()=>dirty.observe({requestId:"1",state:9}),/UNKNOWN_REQUEST/);
  const expired=make();await assert.rejects(expired.generateRequest(async()=>({...request("1"),expiresAt:"200"})),/CONTAMINATED/);
  assert.equal(expired.status().stopped,true);
  const failed=make();await failed.generateRequest(async()=>request("1"));
  assert.throws(()=>failed.observe({requestId:"1",state:25}),/STOP_AND_DEBUG/);assert.equal(failed.status().stopped,true);
  const concurrent=make();let release;const pending=concurrent.generateRequest(()=>new Promise(resolve=>{release=resolve;}));
  await assert.rejects(concurrent.generateRequest(async()=>{calls++;return request("2");}),/STOP_AND_DEBUG/);
  release(request("1"));await assert.rejects(pending,/STOP_AND_DEBUG/);assert.equal(calls,0);
  let clock=100;const stale=createAcceptanceProcedure({baseline:{verdict:"PHYSICAL ACCEPTANCE BASELINE: PASS",errors:[],verifiedAt:100},now:()=>clock});
  clock=131;await assert.rejects(stale.generateRequest(async()=>{calls++;return request("1");}),/BASELINE_STALE/);assert.equal(calls,0);
});


for(const state of ["not_started","idle","ready"]) {
  test(`clean ${state} passes baseline schema without claiming artifact verification`,()=>{
    const {validateBaseline}=require("../../../scripts/release/routine-acceptance-baseline.cjs");
    const result=validateBaseline(baselineSchemaInput(state));
    assert.deepEqual(result.errors,[]);
    assert.equal(result.verdict,"BASELINE SCHEMA ONLY: PASS");
  });
}

const dirtyNotStartedCases=[
  ["active request",{activeRequestId:requestId},"desktop_active_or_unknown"],
  ["stale presentation request",{presentationRequestId:requestId},"desktop_stale_presentation"],
  ["QR present",{qrVisible:true},"desktop_stale_presentation"],
  ["pending authority",{pendingRequestCount:1},"desktop_pending_request"],
  ["unknown or in-flight submission",{unresolvedSubmissionCount:1},"desktop_active_or_unknown"],
  ["nonfresh nonce",{expectedNonce:"1"},"desktop_nonce_not_fresh_runtime"],
  ["unknown pairing",{pairingState:"missing"},"desktop_pairing_unknown"]
];
for(const [label,delta,error] of dirtyNotStartedCases) {
  test(`not_started rejects ${label}`,()=>{
    const {validateBaseline}=require("../../../scripts/release/routine-acceptance-baseline.cjs");
    const input=baselineSchemaInput("not_started");
    const result=validateBaseline({...input,desktop:{...input.desktop,...delta}});
    assert.ok(result.errors.includes(error));
    assert.equal(result.verdict,"PHYSICAL ACCEPTANCE BASELINE: FAIL");
  });
}

for(const [label,delta,error] of [
  ["unfinished startup",{documentReadyState:"loading"},"desktop_not_started_runtime_unready"],
  ["uninitialized runtime",{runtimeInitialized:false},"desktop_not_started_runtime_unready"],
  ["begin in flight",{beginInFlight:true},"desktop_not_started_request_activity"],
  ["polling history",{pollGeneration:1},"desktop_not_started_request_activity"],
  ["request expiry timer",{expiresAt:"200"},"desktop_not_started_stale_presentation"],
  ["QR payload residue",{qrPayload:"stale"},"desktop_not_started_stale_presentation"],
  ["fingerprint residue",{comparisonFingerprint:"stale"},"desktop_not_started_stale_presentation"],
  ["stale rejected terminal state",{terminalReason:"rejected"},"desktop_not_started_stale_presentation"],
  ["unknown terminal residue",{terminalReason:"unknown"},"desktop_not_started_stale_presentation"],
  ["retry attempt",{lastAttempt:{stage:"completion_rejected"}},"desktop_not_started_retry_state"],
  ["preflight attempt",{preflightCount:1},"desktop_not_started_retry_state"],
  ["completion attempt",{completionAttemptCount:1},"desktop_not_started_retry_state"],
  ["failed begin",{lastFailureReason:"routine_authorization_failed"},"desktop_not_started_retry_state"],
  ["stale notice",{notice:"Request stopped"},"desktop_not_started_retry_state"]
]) {
  test(`not_started rejects ${label}`,()=>{
    const {validateBaseline}=require("../../../scripts/release/routine-acceptance-baseline.cjs");
    const input=baselineSchemaInput("not_started");
    const result=validateBaseline({...input,desktop:{...input.desktop,preRequest:{...input.desktop.preRequest,...delta}}});
    assert.ok(result.errors.includes(error));
    assert.equal(result.verdict,"PHYSICAL ACCEPTANCE BASELINE: FAIL");
  });
}

test("not_started alone and incomplete clean-state evidence fail closed",()=>{
  const {validateBaseline}=require("../../../scripts/release/routine-acceptance-baseline.cjs");
  const input=baselineSchemaInput("not_started");
  for(const preRequest of [undefined,null,{},...Object.keys(input.desktop.preRequest).map(key=>{
    const partial={...input.desktop.preRequest};delete partial[key];return partial;
  })]) {
    const result=validateBaseline({...input,desktop:{...input.desktop,preRequest}});
    assert.equal(result.verdict,"PHYSICAL ACCEPTANCE BASELINE: FAIL");
  }
});

for(const state of ["failed","rejected","expired","unknown","completed","cancelled","waiting","review","approved",
  "transport_waiting","enrollment_waiting","persisting",1,2,3,4,5,6,7,8,9,20,21,22,23,24,25]) {
  test(`nonbaseline presentation ${state} cannot pass by clearing request and QR fields`,()=>{
    const {validateBaseline}=require("../../../scripts/release/routine-acceptance-baseline.cjs");
    const result=validateBaseline(baselineSchemaInput(state));
    assert.ok(result.errors.includes("desktop_not_ready"));
    assert.equal(result.verdict,"PHYSICAL ACCEPTANCE BASELINE: FAIL");
  });
}
