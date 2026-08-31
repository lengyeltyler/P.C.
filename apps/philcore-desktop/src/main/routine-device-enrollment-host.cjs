"use strict";

const http = require("node:http");
const crypto = require("node:crypto");
const { p256 } = require("@noble/curves/p256");

require("tsx/cjs");
const enrollment = require("../../../phil-device-sdk/src/routineDeviceEnrollmentTransportV2.ts");

class RoutineDeviceEnrollmentHostError extends Error {
  constructor(code) { super(code);this.name="RoutineDeviceEnrollmentHostError";this.code=code; }
}
function fail(code) { throw new RoutineDeviceEnrollmentHostError(code); }
function exactOptions(value, keys) {
  if (!value||typeof value!=="object"||Array.isArray(value)||Object.keys(value).sort().join(",")!==[...keys].sort().join(",")) fail("ROUTINE_ENROLLMENT_HOST_OPTIONS_INVALID");
}
function exactHeaders(request, bootstrap, body) {
  const names=request.rawHeaders.filter((_value,index)=>index%2===0).map((name)=>name.toLowerCase());
  if (request.httpVersion!=="1.1"||new Set(names).size!==names.length||request.method!=="POST"
    ||request.url!==enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath
    ||request.headers.host!==`${bootstrap.ipv4}:${bootstrap.port}`||request.headers["content-type"]!=="application/json"
    ||request.headers["content-length"]!==String(body.length)||request.headers["cache-control"]!=="no-store"
    ||request.headers["content-encoding"]!==undefined||request.headers["transfer-encoding"]!==undefined
    ||request.headers.cookie!==undefined||request.headers.authorization!==undefined||request.headers["proxy-authorization"]!==undefined) fail("ROUTINE_ENROLLMENT_HTTP_INVALID");
}
function exactPreflightHeaders(request, bootstrap) {
  const names=request.rawHeaders.filter((_value,index)=>index%2===0).map((name)=>name.toLowerCase());
  if (request.httpVersion!=="1.1"||new Set(names).size!==names.length||request.method!=="HEAD"
    ||request.url!==enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.preflightPath
    ||request.headers.host!==`${bootstrap.ipv4}:${bootstrap.port}`||request.headers["cache-control"]!=="no-store"
    ||request.headers.connection!=="close"||request.headers["x-philcore-enrollment-session"]!==bootstrap.sessionId
    ||request.headers["content-type"]!==undefined||request.headers["content-length"]!==undefined
    ||request.headers["content-encoding"]!==undefined||request.headers["transfer-encoding"]!==undefined
    ||request.headers.cookie!==undefined||request.headers.authorization!==undefined||request.headers["proxy-authorization"]!==undefined) {
    fail("ROUTINE_ENROLLMENT_PREFLIGHT_HTTP_INVALID");
  }
}
function response(response,status) { response.writeHead(status,{"content-length":"0","cache-control":"no-store",connection:"close"});response.end(); }
function jsonResponse(response,status,body) { response.writeHead(status,{"content-type":"application/json","content-length":String(body.length),"cache-control":"no-store",connection:"close"});response.end(body); }
function isBoundCompletionAttempt(body,bootstrap) {
  try {
    const value=JSON.parse(body.toString("utf8"));
    return Boolean(value&&typeof value==="object"&&!Array.isArray(value)&&value.protocolVersion===2
      &&value.sessionId===bootstrap.sessionId&&value.challenge===bootstrap.challenge);
  } catch { return false; }
}
function diagnosticCode(error) {
  return typeof error?.code==="string"&&/^[A-Z0-9_]{1,96}$/u.test(error.code)
    ? error.code:"ROUTINE_ENROLLMENT_REJECTION_UNCLASSIFIED";
}
function recordDiagnostic(activeSession,stage,now,error=null) {
  activeSession.lastAttempt=Object.freeze({stage,code:error?diagnosticCode(error):null,at:BigInt(now()).toString(),
    completionAttemptCount:activeSession.completionAttemptCount,preflightCount:activeSession.preflightCount});
}

function createRoutineDeviceEnrollmentHost(options) {
  exactOptions(options,["disposableProfileId","ipv4","enrollmentStore","now","allowSynthetic"]);
  if (typeof options.now!=="function"||typeof options.enrollmentStore?.save!=="function"||typeof options.enrollmentStore?.load!=="function"
    ||typeof options.enrollmentStore?.delete!=="function"||typeof options.allowSynthetic!=="boolean") fail("ROUTINE_ENROLLMENT_HOST_DEPENDENCY_INVALID");
  let listener=null,session=null,activeOperations=0,deleting=false;

  async function loadPriorEnrollment() {
    try {
      const stored=await options.enrollmentStore.load(options.disposableProfileId);
      return enrollment.validatePhilRoutineDevicePublicRecordV2(JSON.parse(stored.canonicalEnrollmentJson),options.allowSynthetic);
    }
    catch (error) { if (error?.code==="ROUTINE_ENROLLMENT_NOT_FOUND") return null;throw error; }
  }

  async function start() {
    if (listener) fail("ROUTINE_ENROLLMENT_LISTENER_ALREADY_STARTED");
    listener=http.createServer(async (request,responseObject)=>{
      if (!session) return response(responseObject,404);
      const activeSession=session;activeOperations+=1;
      if (request.method!=="POST"||request.url!==enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath) {
        try {
          exactPreflightHeaders(request,activeSession.bootstrap);
          if (session!==activeSession||activeSession.state!=="waiting") return response(responseObject,409);
          if (BigInt(options.now())>=BigInt(activeSession.bootstrap.expiresAt)) {
            activeSession.state="expired";activeSession.ackPrivateKey.fill(0);return response(responseObject,410);
          }
          activeSession.preflightCount+=1;recordDiagnostic(activeSession,"preflight_accepted",options.now);
          return response(responseObject,204);
        } catch { return response(responseObject,400); }
        finally { activeOperations-=1; }
      }
      const chunks=[];let size=0,poisonOnFailure=false,boundAttempt=false;
      try {
        for await (const chunk of request) {
          size+=chunk.length;if (size>enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.maximumHttpBodyBytes) return response(responseObject,413);
          chunks.push(chunk);
        }
        const body=Buffer.concat(chunks);boundAttempt=isBoundCompletionAttempt(body,activeSession.bootstrap);
        if (boundAttempt) { activeSession.completionAttemptCount+=1;recordDiagnostic(activeSession,"completion_received",options.now); }
        exactHeaders(request,activeSession.bootstrap,body);
        if (activeSession.state==="completed") {
          if (BigInt(options.now())>=BigInt(activeSession.bootstrap.expiresAt)||!activeSession.acceptanceBody) { activeSession.acceptanceBody=null;return response(responseObject,410); }
          const replayRecord=enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentResponseV2({json:body,bootstrap:activeSession.bootstrap,allowSynthetic:options.allowSynthetic});
          if (JSON.stringify(replayRecord)===JSON.stringify(activeSession.record)) {
            if (boundAttempt) recordDiagnostic(activeSession,"completion_replay_accepted",options.now);
            return jsonResponse(responseObject,200,activeSession.acceptanceBody);
          }
          return response(responseObject,409);
        }
        if (activeSession.state==="expired") return response(responseObject,410);
        if (activeSession.state!=="waiting"||session!==activeSession) return response(responseObject,404);
        if (BigInt(options.now())>=BigInt(session.bootstrap.expiresAt)) { session.state="expired";session.ackPrivateKey.fill(0);return response(responseObject,410); }
        if (activeSession.preflightCount===0) fail("ROUTINE_ENROLLMENT_PREFLIGHT_REQUIRED");
        const record=enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentResponseV2({json:body,bootstrap:session.bootstrap,allowSynthetic:options.allowSynthetic});
        let prior;try { prior=await loadPriorEnrollment(); } catch (error) { poisonOnFailure=true;throw error; }
        if (record.generation!==session.bootstrap.expectedGeneration
          ||prior&&(BigInt(record.generation)!==BigInt(prior.generation)+1n||record.deviceId===prior.deviceId||record.deviceKeyId===prior.deviceKeyId)) {
          fail("ROUTINE_ENROLLMENT_REPLACEMENT_INVALID");
        }
        if (deleting||session!==activeSession||session.state!=="waiting") fail("ROUTINE_ENROLLMENT_SESSION_REPLACED");
        poisonOnFailure=true;
        const acceptanceDigest=enrollment.derivePhilRoutineDeviceEnrollmentAcceptanceDigestV2({bootstrap:activeSession.bootstrap,record});
        const acceptanceSignatureDER=p256.sign(acceptanceDigest.slice(2),activeSession.ackPrivateKey,{lowS:true,prehash:false}).toDERRawBytes();
        const acceptanceBody=Buffer.from(enrollment.serializePhilRoutineDeviceEnrollmentAcceptanceV2({bootstrap:activeSession.bootstrap,record,acceptanceSignatureDER}));
        activeSession.ackPrivateKey.fill(0);activeSession.state="persisting";
        await options.enrollmentStore.save(options.disposableProfileId,JSON.stringify(record),options.allowSynthetic?"synthetic_source_test":"physical_device_unverified");
        activeSession.record=record;activeSession.acceptanceBody=acceptanceBody;activeSession.state="completed";
        recordDiagnostic(activeSession,"completion_accepted",options.now);
        return jsonResponse(responseObject,200,acceptanceBody);
      } catch (error) {
        if (boundAttempt&&session===activeSession) recordDiagnostic(activeSession,poisonOnFailure?"completion_internal_failure":"completion_rejected",options.now,error);
        if (poisonOnFailure&&session===activeSession&&(activeSession.state==="waiting"||activeSession.state==="persisting")) { activeSession.state="failed";activeSession.ackPrivateKey.fill(0); }
        const status=error?.code?.includes("REPLACEMENT")||error?.code?.includes("REPLACED")?409:400;
        return response(responseObject,status);
      } finally { activeOperations-=1; }
    });
    await new Promise((resolve,reject)=>{listener.once("error",reject);listener.listen({host:options.ipv4,port:0,exclusive:true},resolve);});
    return Object.freeze({ipv4:options.ipv4,port:listener.address().port});
  }

  async function beginEnrollment() {
    if (!listener) fail("ROUTINE_ENROLLMENT_LISTENER_NOT_STARTED");
    if (session&&(session.state==="waiting"||session.state==="persisting")) fail("ROUTINE_ENROLLMENT_ACTIVE_SESSION_EXISTS");
    const prior=await loadPriorEnrollment();
    if (prior&&BigInt(prior.generation)>=BigInt(enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.maximumGeneration)) fail("ROUTINE_ENROLLMENT_GENERATION_EXHAUSTED");
    if (session?.ackPrivateKey) session.ackPrivateKey.fill(0);
    const ackPrivateKey=Buffer.from(p256.utils.randomPrivateKey()),desktopAckPublicKeyX963=`0x${Buffer.from(p256.getPublicKey(ackPrivateKey,false)).toString("hex")}`;
    const expectedGeneration=(prior?BigInt(prior.generation)+1n:1n).toString();
    const bootstrap=Object.freeze({sessionId:`0x${crypto.randomBytes(32).toString("hex")}`,ipv4:options.ipv4,port:listener.address().port,
      challenge:`0x${crypto.randomBytes(32).toString("hex")}`,expiresAt:(BigInt(options.now())+300n).toString(),expectedGeneration,desktopAckPublicKeyX963});
    session={bootstrap,state:"waiting",record:null,ackPrivateKey,acceptanceBody:null,preflightCount:0,completionAttemptCount:0,lastAttempt:null};
    return Object.freeze({requestId:bootstrap.sessionId,qrPayload:enrollment.encodePhilRoutineDeviceEnrollmentBootstrapV2(bootstrap),
      comparisonFingerprint:enrollment.formatPhilRoutineDeviceEnrollmentFingerprintV2(bootstrap),expiresAt:bootstrap.expiresAt,status:"enrollment_waiting"});
  }
  function status(requestId) {
    if (!session||String(requestId).toLowerCase()!==session.bootstrap.sessionId) fail("ROUTINE_ENROLLMENT_REQUEST_UNKNOWN");
    if (session.state==="waiting"&&BigInt(options.now())>=BigInt(session.bootstrap.expiresAt)) { session.state="expired";session.ackPrivateKey.fill(0); }
    return Object.freeze({requestId:session.bootstrap.sessionId,state:session.state,comparisonFingerprint:enrollment.formatPhilRoutineDeviceEnrollmentFingerprintV2(session.bootstrap),expiresAt:session.bootstrap.expiresAt,
      preflightCount:session.preflightCount,completionAttemptCount:session.completionAttemptCount,lastAttempt:session.lastAttempt});
  }
  function cancel(requestId) {
    if (!session||String(requestId).toLowerCase()!==session.bootstrap.sessionId) fail("ROUTINE_ENROLLMENT_REQUEST_UNKNOWN");
    if (session.state==="waiting") { session.state="cancelled";session.ackPrivateKey.fill(0); }return session.state;
  }
  async function activeEnrollment() {
    const stored=await options.enrollmentStore.load(options.disposableProfileId);
    return Object.freeze({...stored,record:enrollment.validatePhilRoutineDevicePublicRecordV2(JSON.parse(stored.canonicalEnrollmentJson),options.allowSynthetic)});
  }
  function assertDeletionSafe() {
    if (deleting||activeOperations>0||(session&&session.state==="waiting")) fail("ROUTINE_ENROLLMENT_DELETE_TOO_EARLY");return true;
  }
  async function deleteEnrollment() { assertDeletionSafe();deleting=true;try { await options.enrollmentStore.delete(options.disposableProfileId);session?.ackPrivateKey?.fill(0);session=null; } finally { deleting=false; } }
  function disposeAfterDurableDeletion() { assertDeletionSafe();session?.ackPrivateKey?.fill(0);session=null; }
  async function stop() { if (!listener) return;const current=listener;listener=null;await new Promise((resolve,reject)=>current.close((error)=>error?reject(error):resolve()));session?.ackPrivateKey?.fill(0); }
  return Object.freeze({start,stop,beginEnrollment,status,cancel,activeEnrollment,assertDeletionSafe,deleteEnrollment,disposeAfterDurableDeletion});
}

module.exports={RoutineDeviceEnrollmentHostError,createRoutineDeviceEnrollmentHost};
