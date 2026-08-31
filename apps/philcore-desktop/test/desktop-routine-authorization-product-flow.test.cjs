"use strict";
const assert=require("node:assert/strict");
const crypto=require("node:crypto");
const fs=require("node:fs");
const http=require("node:http");
const os=require("node:os");
const path=require("node:path");
const { p256 }=require("@noble/curves/p256");
const hardhat=require("hardhat");
require("tsx/cjs");
const auth=require("../../phil-device-sdk/src/routineAuthorizationV1.ts");
const enrollment=require("../../phil-device-sdk/src/routineDeviceEnrollmentTransportV2.ts");
const transport=require("../../phil-device-sdk/src/routineAuthorizationTransportV1.ts");
const wire=require("../../phil-device-sdk/src/p256SignatureWireV2.ts");
const { createRoutineAuthorizationProtectedStores }=require("../src/main/routine-authorization-storage.cjs");
const { createRoutineDeviceEnrollmentHost }=require("../src/main/routine-device-enrollment-host.cjs");
const { createRoutineAuthorizationHost }=require("../src/main/routine-authorization-host.cjs");
const { createRoutineAuthorizationProductHost }=require("../src/main/routine-authorization-product-host.cjs");
const { createRoutineAuthorizationLocalProductRuntime }=require("../src/main/routine-authorization-local-product-runtime.cjs");

function privateAddress(){return Object.values(os.networkInterfaces()).flat().find((v)=>v?.family==="IPv4"&&!v.internal&&(/^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)/u.test(v.address)))?.address;}
function wrappingAdapter(){const key=crypto.createHash("sha256").update("STEP6C2_PRODUCT_FLOW_TEST_ONLY").digest();return{isAvailable:()=>true,encrypt(text){const nonce=crypto.randomBytes(12),cipher=crypto.createCipheriv("aes-256-gcm",key,nonce),body=Buffer.concat([cipher.update(String(text)),cipher.final()]);return Buffer.concat([nonce,cipher.getAuthTag(),body]);},decrypt(value){const input=Buffer.from(value),decipher=crypto.createDecipheriv("aes-256-gcm",key,input.subarray(0,12));decipher.setAuthTag(input.subarray(12,28));return Buffer.concat([decipher.update(input.subarray(28)),decipher.final()]).toString();}};}
function post(host,port,pathName,contentType,body,requestId){return new Promise((resolve,reject)=>{const request=http.request({host,port,path:pathName,method:"POST",headers:{host:`${host}:${port}`,...(requestId ? {"x-philcore-routine-request":requestId} : {}),
  "content-type":contentType,"content-length":String(body.length),"cache-control":"no-store",connection:"close"}},(response)=>{const chunks=[];response.on("data",(c)=>chunks.push(c));response.on("end",()=>resolve({status:response.statusCode,body:Buffer.concat(chunks)}));});request.once("error",reject);request.end(body);});}
function enrollmentPreflight(bootstrap){return new Promise((resolve,reject)=>{const request=http.request({host:bootstrap.ipv4,port:bootstrap.port,
  path:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.preflightPath,method:"HEAD",headers:{host:`${bootstrap.ipv4}:${bootstrap.port}`,
    "cache-control":"no-store",connection:"close","x-philcore-enrollment-session":bootstrap.sessionId}},(response)=>{response.resume();response.on("end",()=>resolve(response.statusCode));});request.once("error",reject);request.end();});}
async function completeAuthorization(product,ipv4,privateKey,phoneByte){
  const authorizationStart=await product.beginRoutineAuthorization({action:"record_harmless_value"}),bootstrap=transport.decodePhilRoutineTransportBootstrapV1(authorizationStart.qrPayload);
  const phone=crypto.createECDH("prime256v1");phone.setPrivateKey(Buffer.from(phoneByte.repeat(32),"hex"));
  const beginBody=Buffer.from(transport.serializePhilRoutineTransportBeginJsonV1({protocolVersion:1,sessionId:bootstrap.sessionId,requestId:bootstrap.requestId,
    iphonePublicKey:`0x${phone.getPublicKey(undefined,"uncompressed").toString("hex")}`}));
  const begun=await post(ipv4,bootstrap.port,transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath,"application/json",beginBody);assert.equal(begun.status,200);
  const transcript=transport.derivePhilRoutineTransportTranscriptHashV1({bootstrap,iphonePublicKeyX963:phone.getPublicKey(undefined,"uncompressed")});
  const cipher=new transport.PhilRoutineTransportCipherV1({key:transport.derivePhilRoutineTransportKeyV1({privateKey:phone.getPrivateKey(),peerPublicKeyX963:bootstrap.desktopPublicKeyX963,transcriptHash:transcript})});
  const request=auth.parsePhilRoutineAuthorizationRequestJsonV1(cipher.decrypt({frame:begun.body,aad:transport.derivePhilRoutineTransportAadV1({direction:"request",sessionId:bootstrap.sessionId,requestId:bootstrap.requestId})}));
  const signature=p256.sign(request.platformSigningDigest.slice(2),privateKey,{lowS:true,prehash:false}),response=auth.createPhilRoutineAuthorizationResponseV1({request,
    signature:wire.encodePhilP256RawSignatureV2({r:`0x${signature.r.toString(16).padStart(64,"0")}`,s:`0x${signature.s.toString(16).padStart(64,"0")}`})});
  const responseFrame=cipher.encrypt({plaintext:auth.serializePhilRoutineAuthorizationResponseJsonV1({request,response}),aad:transport.derivePhilRoutineTransportAadV1({direction:"response",sessionId:bootstrap.sessionId,requestId:bootstrap.requestId})});
  const completion=await post(ipv4,bootstrap.port,transport.PHIL_ROUTINE_TRANSPORT_V1.completePath,"application/octet-stream",responseFrame,bootstrap.requestId);
  assert.equal(completion.status,204,JSON.stringify(await product.getRoutineAuthorizationStatus(authorizationStart.requestId)));
  assert.equal((await product.getRoutineAuthorizationStatus(authorizationStart.requestId)).state,9);return authorizationStart.requestId;
}

describe("Phil V1 Step 6C-2 complete product flow",function(){
it("uses protected enrollment and generation-2 replacement through local receipts without renderer authority",async function(){
  const ipv4=privateAddress();assert.ok(ipv4);const root=fs.mkdtempSync(path.join(os.tmpdir(),"phil-step6c2-product-flow-"));
  const profileId=`0x${"79".repeat(32)}`,stores=createRoutineAuthorizationProtectedStores({storageRoot:root,encryptionAdapter:wrappingAdapter()});
  const enrollmentHost=createRoutineDeviceEnrollmentHost({disposableProfileId:profileId,ipv4,enrollmentStore:stores.enrollmentStore,
    now:()=>BigInt(Math.floor(Date.now()/1000)),allowSynthetic:true});
  const product=createRoutineAuthorizationProductHost({enrollmentHost,deleteProfileAtomically:()=>stores.profileStore.deleteAll(profileId),authorizationHostFactory:async(stored)=>{
    const runtime=await createRoutineAuthorizationLocalProductRuntime({hardhat,repositoryRoot:process.cwd(),enrollment:stored.record,
      // Match production: request and transport share wall-clock time. The local
      // chain can advance while deploying replacement contracts.
      now:async()=>BigInt(Math.floor(Date.now()/1000)),
      desktopUnlocked:async()=>true,iphoneSessionCurrent:async()=>true});
    return createRoutineAuthorizationHost({disposableProfileId:profileId,ipv4,requestFactory:runtime.requestFactory,readTrustedState:runtime.readTrustedState,
      simulate:runtime.simulate,execute:runtime.execute,reconcile:runtime.reconcile,protectedKeyStore:stores.protectedKeyStore,journalStore:stores.journalStore,
      requestStore:stores.requestStore,now:()=>BigInt(Math.floor(Date.now()/1000))});}});
  await product.initialize();const privateKey=Buffer.from("08".repeat(32),"hex"),publicKey=Buffer.from(p256.getPublicKey(privateKey,false));
  const enrollmentStart=await product.beginRoutineAuthorization({action:"record_harmless_value"}),enrollmentBootstrap=enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(enrollmentStart.qrPayload);
  const record={schemaVersion:2,generation:"1",deviceId:`0x${"71".repeat(32)}`,deviceKeyId:`0x${"72".repeat(32)}`,publicKeyX963:`0x${publicKey.toString("hex")}`,
    signatureSuiteId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.signatureSuiteId,
    providerProfileId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.providerProfileId,
    wireEncodingId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.wireEncodingId,
    publicKeyFingerprint:`0x${crypto.createHash("sha256").update(publicKey).digest("hex")}`,secureEnclaveBacked:false,userPresenceRequired:false};
  const enrollmentDigest=enrollment.derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap:enrollmentBootstrap,record}),enrollmentDer=p256.sign(enrollmentDigest.slice(2),privateKey,{lowS:true,prehash:false}).toDERRawBytes();
  const enrollmentBody=Buffer.from(enrollment.serializePhilRoutineDeviceEnrollmentResponseV2({bootstrap:enrollmentBootstrap,record,proofSignatureDER:enrollmentDer}));
  assert.equal(await enrollmentPreflight(enrollmentBootstrap),204);
  const enrollmentAccepted=await post(ipv4,enrollmentBootstrap.port,enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath,"application/json",enrollmentBody);
  assert.equal(enrollmentAccepted.status,200);enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2({json:enrollmentAccepted.body,bootstrap:enrollmentBootstrap,record});
  assert.equal((await product.getRoutineAuthorizationStatus(enrollmentStart.requestId)).state,"completed");

  const sameProcessRequestId=await completeAuthorization(product,ipv4,privateKey,"09");
  assert.equal((await stores.journalStore.read(sameProcessRequestId)).length,7);
  const replacementKey=Buffer.from("0a".repeat(32),"hex"),replacementPublicKey=Buffer.from(p256.getPublicKey(replacementKey,false));
  const replacementStart=await product.beginRoutineAuthorization({action:"replace_routine_device"}),replacementBootstrap=enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(replacementStart.qrPayload);
  assert.equal(replacementBootstrap.expectedGeneration,"2");
  const replacementRecord={...record,generation:"2",deviceId:`0x${"73".repeat(32)}`,deviceKeyId:`0x${"74".repeat(32)}`,
    publicKeyX963:`0x${replacementPublicKey.toString("hex")}`,publicKeyFingerprint:`0x${crypto.createHash("sha256").update(replacementPublicKey).digest("hex")}`};
  const replacementDigest=enrollment.derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap:replacementBootstrap,record:replacementRecord});
  const replacementDer=p256.sign(replacementDigest.slice(2),replacementKey,{lowS:true,prehash:false}).toDERRawBytes();
  const replacementBody=Buffer.from(enrollment.serializePhilRoutineDeviceEnrollmentResponseV2({bootstrap:replacementBootstrap,record:replacementRecord,proofSignatureDER:replacementDer}));
  assert.equal(await enrollmentPreflight(replacementBootstrap),204);
  const replacementAccepted=await post(ipv4,replacementBootstrap.port,enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.completePath,"application/json",replacementBody);
  assert.equal(replacementAccepted.status,200);enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2({json:replacementAccepted.body,bootstrap:replacementBootstrap,record:replacementRecord});
  await completeAuthorization(product,ipv4,replacementKey,"0b");
  assert.deepEqual(await product.deleteDisposableProfile(),{status:"deleted",identityOrRecoveryStateTouched:false});
  assert.equal((await stores.requestStore.list()).length,0);assert.equal((await stores.journalStore.list()).length,0);
  await product.stop();fs.rmSync(root,{recursive:true,force:true});
});
});
