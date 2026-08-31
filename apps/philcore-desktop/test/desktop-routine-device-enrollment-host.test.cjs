"use strict";
const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const http=require("node:http");
const os=require("node:os");
const test=require("node:test");
const { p256 }=require("@noble/curves/p256");
require("tsx/cjs");
const enrollment=require("../../phil-device-sdk/src/routineDeviceEnrollmentTransportV2.ts");
const { createRoutineDeviceEnrollmentHost }=require("../src/main/routine-device-enrollment-host.cjs");

function privateAddress() { return Object.values(os.networkInterfaces()).flat().find((value)=>value?.family==="IPv4"&&!value.internal&&
  (/^10\./u.test(value.address)||/^192\.168\./u.test(value.address)||/^172\.(?:1[6-9]|2[0-9]|3[01])\./u.test(value.address)))?.address; }
function post(bootstrap,body) { return new Promise((resolve,reject)=>{const request=http.request({host:bootstrap.ipv4,port:bootstrap.port,
  path:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath,method:"POST",headers:{host:`${bootstrap.ipv4}:${bootstrap.port}`,
    "content-type":"application/json","content-length":String(body.length),"cache-control":"no-store",connection:"close"}},(response)=>{
      const chunks=[];response.on("data",(chunk)=>chunks.push(chunk));response.on("end",()=>resolve({status:response.statusCode,body:Buffer.concat(chunks)}));});
  request.once("error",reject);request.end(body);}); }
function duplicateHeaderPost(bootstrap,body) { return new Promise((resolve,reject)=>{const request=http.request({host:bootstrap.ipv4,port:bootstrap.port,
  path:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath,method:"POST",headers:["Host",`${bootstrap.ipv4}:${bootstrap.port}`,
    "Content-Type","application/json","Content-Length",String(body.length),"Cache-Control","no-store","Cache-Control","no-store","Connection","close"]},
  (response)=>{const chunks=[];response.on("data",(chunk)=>chunks.push(chunk));response.on("end",()=>resolve({status:response.statusCode,body:Buffer.concat(chunks)}));});
  request.once("error",reject);request.end(body);}); }
function preflight(bootstrap,{sessionId=bootstrap.sessionId,method="HEAD",path=enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.preflightPath}={}) { return new Promise((resolve,reject)=>{const request=http.request({host:bootstrap.ipv4,port:bootstrap.port,
  path,method,headers:{host:`${bootstrap.ipv4}:${bootstrap.port}`,
    "cache-control":"no-store",connection:"close","x-philcore-enrollment-session":sessionId}},(response)=>{
      const chunks=[];response.on("data",(chunk)=>chunks.push(chunk));response.on("end",()=>resolve({status:response.statusCode,headers:response.headers,body:Buffer.concat(chunks)}));});
  request.once("error",reject);request.end();}); }
function completionFixture(bootstrap,generation,byte) {
  const privateKey=Buffer.from(byte.repeat(32),"hex"),publicKey=Buffer.from(p256.getPublicKey(privateKey,false));
  const record={schemaVersion:2,generation:String(generation),deviceId:`0x${byte.repeat(32)}`,deviceKeyId:`0x${(Number.parseInt(byte,16)+1).toString(16).padStart(2,"0").repeat(32)}`,
    signatureSuiteId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.signatureSuiteId,
    providerProfileId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.providerProfileId,
    wireEncodingId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.wireEncodingId,
    publicKeyX963:`0x${publicKey.toString("hex")}`,publicKeyFingerprint:`0x${crypto.createHash("sha256").update(publicKey).digest("hex")}`,
    secureEnclaveBacked:false,userPresenceRequired:false};
  const digest=enrollment.derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap,record});
  const signature=p256.sign(digest.slice(2),privateKey,{lowS:true,prehash:false}).toDERRawBytes();
  return {record,body:Buffer.from(enrollment.serializePhilRoutineDeviceEnrollmentResponseV2({bootstrap,record,proofSignatureDER:signature}))};
}

test("dedicated enrollment listener verifies proof of possession before protected persistence",async(t)=>{
  const ipv4=privateAddress();assert.ok(ipv4,"private test interface required");let stored=null,loadFailure=null,now=1_800_000_000n;
  const store={async save(_id,json,evidenceClass){stored={canonicalEnrollmentJson:json,evidenceClass};},async load(){if(loadFailure)throw loadFailure;if(!stored)throw Object.assign(new Error("missing"),{code:"ROUTINE_ENROLLMENT_NOT_FOUND"});return stored;},async delete(){stored=null;}};
  const host=createRoutineDeviceEnrollmentHost({disposableProfileId:`0x${"77".repeat(32)}`,ipv4,enrollmentStore:store,now:()=>now,allowSynthetic:true});
  await host.start();t.after(()=>host.stop());const begun=await host.beginEnrollment(),bootstrap=enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(begun.qrPayload);
  await assert.rejects(host.beginEnrollment(),(error)=>error.code==="ROUTINE_ENROLLMENT_ACTIVE_SESSION_EXISTS");
  const rejectedPreflight=await preflight(bootstrap,{sessionId:`0x${"00".repeat(32)}`});
  assert.equal(rejectedPreflight.status,400);assert.equal(host.status(begun.requestId).state,"waiting");assert.equal(stored,null);
  for (const malformed of [{method:"GET"},{path:`${enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.preflightPath}?x=1`},{method:"POST"}]) {
    assert.equal((await preflight(bootstrap,malformed)).status,400);assert.equal(host.status(begun.requestId).state,"waiting");assert.equal(stored,null);
  }
  assert.equal((await post(bootstrap,Buffer.from("{}"))).status,400);assert.equal(host.status(begun.requestId).state,"waiting");assert.equal(stored,null);
  const acceptedPreflight=await preflight(bootstrap);
  assert.equal(acceptedPreflight.status,204);assert.equal(acceptedPreflight.headers["content-length"],"0");
  assert.equal(acceptedPreflight.headers["cache-control"],"no-store");assert.equal(acceptedPreflight.headers.connection,"close");
  assert.equal(acceptedPreflight.headers["content-type"],undefined);assert.equal(acceptedPreflight.body.length,0);
  const preflightStatus=host.status(begun.requestId);assert.equal(preflightStatus.state,"waiting");assert.equal(preflightStatus.preflightCount,1);
  assert.equal(preflightStatus.completionAttemptCount,0);assert.equal(preflightStatus.lastAttempt.stage,"preflight_accepted");assert.equal(stored,null);
  const privateKey=Buffer.from("06".repeat(32),"hex"),publicKey=Buffer.from(p256.getPublicKey(privateKey,false));
  const record={schemaVersion:2,generation:"1",deviceId:`0x${"61".repeat(32)}`,deviceKeyId:`0x${"62".repeat(32)}`,
    signatureSuiteId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.signatureSuiteId,
    providerProfileId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.providerProfileId,
    wireEncodingId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.wireEncodingId,
    publicKeyX963:`0x${publicKey.toString("hex")}`,publicKeyFingerprint:`0x${crypto.createHash("sha256").update(publicKey).digest("hex")}`,
    secureEnclaveBacked:false,userPresenceRequired:false};
  const digest=enrollment.derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap,record}),signature=p256.sign(digest.slice(2),privateKey,{lowS:true,prehash:false}).toDERRawBytes();
  const body=Buffer.from(enrollment.serializePhilRoutineDeviceEnrollmentResponseV2({bootstrap,record,proofSignatureDER:signature}));
  assert.equal((await duplicateHeaderPost(bootstrap,body)).status,400);
  const headerRejected=host.status(begun.requestId);assert.equal(headerRejected.state,"waiting");assert.equal(headerRejected.completionAttemptCount,1);
  assert.equal(headerRejected.lastAttempt.stage,"completion_rejected");assert.equal(headerRejected.lastAttempt.code,"ROUTINE_ENROLLMENT_HTTP_INVALID");assert.equal(stored,null);
  const malformedProof=JSON.parse(body);malformedProof.proofSignatureDER="0x00";
  assert.equal((await post(bootstrap,Buffer.from(JSON.stringify(malformedProof)))).status,400);
  const proofRejected=host.status(begun.requestId);assert.equal(proofRejected.state,"waiting");assert.equal(proofRejected.completionAttemptCount,2);
  assert.equal(proofRejected.lastAttempt.stage,"completion_rejected");assert.equal(proofRejected.lastAttempt.code,"PHIL_ROUTINE_ENROLLMENT_PROOF_INVALID");assert.equal(stored,null);
  const accepted=await post(bootstrap,body);assert.equal(accepted.status,200);
  enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2({json:accepted.body,bootstrap,record});
  assert.deepEqual(await post(bootstrap,body),accepted);const completedStatus=host.status(begun.requestId);assert.equal(completedStatus.state,"completed");
  assert.equal(completedStatus.completionAttemptCount,4);assert.equal(completedStatus.lastAttempt.stage,"completion_replay_accepted");
  assert.deepEqual(JSON.parse(stored.canonicalEnrollmentJson),record);assert.equal(stored.evidenceClass,"synthetic_source_test");
  now=BigInt(bootstrap.expiresAt);assert.deepEqual(await post(bootstrap,body),{status:410,body:Buffer.alloc(0)});now=1_800_000_000n;
  const replacementBegun=await host.beginEnrollment(),replacementBootstrap=enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(replacementBegun.qrPayload);
  assert.equal(replacementBootstrap.expectedGeneration,"2");
  const replacementPrivateKey=Buffer.from("07".repeat(32),"hex"),replacementPublicKey=Buffer.from(p256.getPublicKey(replacementPrivateKey,false));
  const replacementRecord={...record,generation:"2",deviceId:`0x${"63".repeat(32)}`,deviceKeyId:`0x${"64".repeat(32)}`,
    publicKeyX963:`0x${replacementPublicKey.toString("hex")}`,publicKeyFingerprint:`0x${crypto.createHash("sha256").update(replacementPublicKey).digest("hex")}`};
  const replacementDigest=enrollment.derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap:replacementBootstrap,record:replacementRecord});
  const replacementSignature=p256.sign(replacementDigest.slice(2),replacementPrivateKey,{lowS:true,prehash:false}).toDERRawBytes();
  const replacementBody=Buffer.from(enrollment.serializePhilRoutineDeviceEnrollmentResponseV2({bootstrap:replacementBootstrap,record:replacementRecord,proofSignatureDER:replacementSignature}));
  assert.equal((await preflight(replacementBootstrap)).status,204);
  const replacementAccepted=await post(replacementBootstrap,replacementBody);assert.equal(replacementAccepted.status,200);
  enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2({json:replacementAccepted.body,bootstrap:replacementBootstrap,record:replacementRecord});
  assert.deepEqual(JSON.parse(stored.canonicalEnrollmentJson),replacementRecord);
  const validStored=stored;stored={...stored,canonicalEnrollmentJson:"null"};
  await assert.rejects(host.beginEnrollment(),(error)=>error.code==="PHIL_ROUTINE_ENROLLMENT_RECORD_INVALID");stored=validStored;
  loadFailure=Object.assign(new Error("protected enrollment unavailable"),{code:"ROUTINE_ENROLLMENT_UNAVAILABLE"});
  await assert.rejects(host.beginEnrollment(),(error)=>error.code==="ROUTINE_ENROLLMENT_UNAVAILABLE");
});

test("enrollment host isolates cancelled, expired, old, out-of-order, and persistence-failed attempts",async(t)=>{
  const ipv4=privateAddress();assert.ok(ipv4,"private test interface required");let now=1_800_100_000n,stored=null,saveCalls=0;
  const store={async save(_id,json,evidenceClass){saveCalls+=1;stored={canonicalEnrollmentJson:json,evidenceClass};},async load(){if(!stored)throw Object.assign(new Error("missing"),{code:"ROUTINE_ENROLLMENT_NOT_FOUND"});return stored;},async delete(){stored=null;}};
  const host=createRoutineDeviceEnrollmentHost({disposableProfileId:`0x${"88".repeat(32)}`,ipv4,enrollmentStore:store,now:()=>now,allowSynthetic:true});
  await host.start();t.after(()=>host.stop());
  const first=await host.beginEnrollment(),firstBootstrap=enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(first.qrPayload),firstCompletion=completionFixture(firstBootstrap,1,"08");
  assert.equal((await post(firstBootstrap,firstCompletion.body)).status,400);
  assert.equal(host.status(first.requestId).lastAttempt.code,"ROUTINE_ENROLLMENT_PREFLIGHT_REQUIRED");
  assert.equal(saveCalls,0);
  assert.equal((await preflight(firstBootstrap)).status,204);assert.equal(host.cancel(first.requestId),"cancelled");
  assert.equal((await post(firstBootstrap,firstCompletion.body)).status,404);assert.equal(saveCalls,0);

  const second=await host.beginEnrollment(),secondBootstrap=enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(second.qrPayload),secondCompletion=completionFixture(secondBootstrap,1,"0a");
  assert.equal((await preflight(secondBootstrap)).status,204);
  assert.equal((await post(secondBootstrap,firstCompletion.body)).status,400);
  assert.equal(host.status(second.requestId).completionAttemptCount,0,"old response must not increment the new attempt");
  const wrongGeneration=JSON.parse(secondCompletion.body);wrongGeneration.generation="7";
  assert.equal((await post(secondBootstrap,Buffer.from(JSON.stringify(wrongGeneration)))).status,400);
  assert.equal(host.status(second.requestId).lastAttempt.code,"PHIL_ROUTINE_ENROLLMENT_RESPONSE_INVALID");
  assert.equal((await post(secondBootstrap,secondCompletion.body)).status,200);assert.equal(saveCalls,1);

  const third=await host.beginEnrollment(),thirdBootstrap=enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(third.qrPayload),thirdCompletion=completionFixture(thirdBootstrap,2,"0c");
  now=BigInt(thirdBootstrap.expiresAt);
  assert.equal((await preflight(thirdBootstrap)).status,410);
  assert.equal((await post(thirdBootstrap,thirdCompletion.body)).status,410);
  assert.equal(host.status(third.requestId).state,"expired");assert.equal(saveCalls,1);

  let failedSaveCalls=0;
  const failingHost=createRoutineDeviceEnrollmentHost({disposableProfileId:`0x${"99".repeat(32)}`,ipv4,enrollmentStore:{
    async save(){failedSaveCalls+=1;throw Object.assign(new Error("do not serialize this message"),{code:"ROUTINE_ENROLLMENT_STORE_WRITE_FAILED"});},
    async load(){throw Object.assign(new Error("missing"),{code:"ROUTINE_ENROLLMENT_NOT_FOUND"});},async delete(){}
  },now:()=>1_800_200_000n,allowSynthetic:true});
  await failingHost.start();t.after(()=>failingHost.stop());
  const failed=await failingHost.beginEnrollment(),failedBootstrap=enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(failed.qrPayload),failedCompletion=completionFixture(failedBootstrap,1,"0e");
  assert.equal((await preflight(failedBootstrap)).status,204);
  assert.equal((await post(failedBootstrap,failedCompletion.body)).status,400);
  const failedStatus=failingHost.status(failed.requestId);
  assert.equal(failedStatus.state,"failed");assert.equal(failedStatus.lastAttempt.stage,"completion_internal_failure");
  assert.equal(failedStatus.lastAttempt.code,"ROUTINE_ENROLLMENT_STORE_WRITE_FAILED");assert.equal(failedSaveCalls,1);
});
