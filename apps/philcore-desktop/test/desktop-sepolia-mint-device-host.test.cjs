"use strict";

const assert=require("node:assert/strict");
const fs=require("node:fs");
const os=require("node:os");
const path=require("node:path");
const {createECDH}=require("node:crypto");
const test=require("node:test");
const {p256}=require("@noble/curves/p256");
const {ethers}=require("ethers");
require("tsx/cjs");
const mint=require("../../phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const device=require("../../phil-device-sdk/src/deviceApprovalV1.ts");
const requestApi=require("../../phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts");
const transport=require("../../phil-device-sdk/src/routineAuthorizationTransportV1.ts");
const {createSepoliaMintCeremonyStore}=require("../src/main/sepolia-mint-ceremony-store.cjs");
const {createSepoliaMintDeviceAuthorizationHost}=require("../src/main/sepolia-mint-device-authorization-host.cjs");

const devicePrivate=Buffer.from("71".repeat(32),"hex"),devicePublic=p256.getPublicKey(devicePrivate,false);
function fixture(root){
  const bindings=mint.derivePhilSepoliaMintBindingsV1({factory:"0x1000000000000000000000000000000000000001",smartAccount:"0x2000000000000000000000000000000000000002",actionGate:"0x3000000000000000000000000000000000000003",mintConsumer:"0x4000000000000000000000000000000000000004",mintRecipient:"0x5000000000000000000000000000000000000005",accountNonce:"7",validAfter:"1800000000",validUntil:"1800000120",maximumTotalFeeWei:"2500000000000000"});
  const authorization=mint.createPhilSepoliaMintAuthorizationV1({scopedOwnerCommitment:ethers.id("owner"),proofDescriptorHash:ethers.id("proof"),rootProofNullifier:ethers.id("nullifier"),scopeEpoch:"1",deviceEpoch:"1",recoveryEpoch:"1",validatorEpoch:"1",bindings});
  const enrollment=device.createPhilDeviceEnrollmentRecordV1({deviceId:ethers.id("device"),deviceKeyId:ethers.id("device-key"),signatureSuiteId:mint.PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,publicKey:devicePublic,deviceEpoch:"1",enrolledAt:"1799999000",assuranceClass:3,policyHash:authorization.authorizationEnvelope.policyHash});
  const encryptionAdapter={isAvailable:()=>true,encrypt:(value)=>Buffer.from(`protected:${value}`,"utf8"),decrypt:(value)=>{const text=Buffer.from(value).toString("utf8");if(!text.startsWith("protected:"))throw new Error("bad");return text.slice(10);}};
  const ceremonyStore=createSepoliaMintCeremonyStore({storageRoot:path.join(root,"ceremonies"),encryptionAdapter});
  const requestFactory=({sessionId,approvalNonce})=>requestApi.createPhilSepoliaMintDeviceRequestV1({sessionId,authorization,enrollment,approvalNonce,approvedAt:"1800000005",approvalExpiresAt:"1800000100"});
  return {authorization,enrollment,ceremonyStore,requestFactory};
}
function requestEnvelope(session,type,body,pathValue){return {requestId:session.requestId,method:"POST",path:pathValue,headers:{host:`192.168.7.9:43123`,"content-type":type,"content-length":String(body.length),"cache-control":"no-store"},body};}

test("encrypted Sepolia iPhone approval is durably saved before composition and resumes after restart",async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"phil-sepolia-device-host-"));
  try{
    const value=fixture(root);let firstCalls=0;
    const host=createSepoliaMintDeviceAuthorizationHost({ceremonyStore:value.ceremonyStore,enrollment:value.enrollment,ipv4:"192.168.7.9",now:()=>"1800000010",requestFactory:value.requestFactory,onApproved:async()=>{firstCalls+=1;throw new Error("SIMULATED_PROCESS_INTERRUPTION");}});
    const started=await host.begin({port:43123}),bootstrap=transport.decodePhilRoutineTransportBootstrapV1(started.qrPayload);
    const iphone=createECDH("prime256v1");iphone.setPrivateKey(Buffer.from("04".repeat(32),"hex"));
    const beginBody=Buffer.from(transport.serializePhilRoutineTransportBeginJsonV1({protocolVersion:1,sessionId:bootstrap.sessionId,requestId:bootstrap.requestId,iphonePublicKey:`0x${iphone.getPublicKey(undefined,"uncompressed").toString("hex")}`}));
    const begun=await host.dispatchHttp(requestEnvelope(started,"application/json",beginBody,transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath));assert.equal(begun.status,200);
    const transcript=transport.derivePhilRoutineTransportTranscriptHashV1({bootstrap,iphonePublicKeyX963:`0x${iphone.getPublicKey(undefined,"uncompressed").toString("hex")}`});
    const key=transport.derivePhilRoutineTransportKeyV1({privateKey:iphone.getPrivateKey(),peerPublicKeyX963:bootstrap.desktopPublicKeyX963,transcriptHash:transcript}),cipher=new transport.PhilRoutineTransportCipherV1({key});
    const request=JSON.parse(cipher.decrypt({frame:begun.body,aad:transport.derivePhilRoutineTransportAadV1({direction:"request",sessionId:bootstrap.sessionId,requestId:bootstrap.requestId})}));
    assert.equal(request.platformSigningDigest,request.deviceApprovalDigest);
    const signature=p256.sign(request.deviceApprovalDigest.slice(2),devicePrivate,{lowS:true,prehash:false});
    const responseValue=requestApi.createPhilSepoliaMintDeviceResponseV1({request,enrollment:value.enrollment,signature:ethers.concat([ethers.toBeHex(signature.r,32),ethers.toBeHex(signature.s,32)])});
    const frame=cipher.encrypt({plaintext:JSON.stringify(responseValue),aad:transport.derivePhilRoutineTransportAadV1({direction:"response",sessionId:bootstrap.sessionId,requestId:bootstrap.requestId})});
    const completed=await host.dispatchHttp(requestEnvelope(started,"application/octet-stream",frame,transport.PHIL_ROUTINE_TRANSPORT_V1.completePath));
    assert.equal(completed.status,400);assert.equal(firstCalls,1);assert.equal(value.ceremonyStore.load(started.requestId).state,"approved");
    let restoredCalls=0;
    const restarted=createSepoliaMintDeviceAuthorizationHost({ceremonyStore:value.ceremonyStore,enrollment:value.enrollment,ipv4:"192.168.7.9",now:()=>"1800000010",requestFactory:value.requestFactory,onApproved:async({request:restoredRequest,response})=>{restoredCalls+=1;assert.equal(response.deviceApprovalDigest,restoredRequest.deviceApprovalDigest);return {status:"signed_unsubmitted"};}});
    const outcomes=await restarted.restoreApproved();assert.equal(outcomes.length,1);assert.equal(restoredCalls,1);assert.equal(value.ceremonyStore.load(started.requestId).state,"completed");
  }finally{fs.rmSync(root,{recursive:true,force:true});}
});

test("Sepolia device host rejects altered encrypted responses and never calls composition",async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"phil-sepolia-device-host-negative-"));
  try{
    const value=fixture(root);let calls=0;const host=createSepoliaMintDeviceAuthorizationHost({ceremonyStore:value.ceremonyStore,enrollment:value.enrollment,ipv4:"192.168.7.9",now:()=>"1800000010",requestFactory:value.requestFactory,onApproved:async()=>{calls+=1;}});
    const started=await host.begin({port:43123}),bad=await host.dispatchHttp(requestEnvelope(started,"application/octet-stream",Buffer.from("not-authenticated"),transport.PHIL_ROUTINE_TRANSPORT_V1.completePath));
    assert.equal(bad.status,409);assert.equal(calls,0);assert.equal(value.ceremonyStore.load(started.requestId).state,"waiting");
  }finally{fs.rmSync(root,{recursive:true,force:true});}
});
