"use strict";

const assert=require("node:assert/strict");
const fs=require("node:fs");
const os=require("node:os");
const path=require("node:path");
const {p256}=require("@noble/curves/p256");
const {ethers}=require("ethers");
require("tsx/cjs");
const mint=require("../../phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const device=require("../../phil-device-sdk/src/deviceApprovalV1.ts");
const requestApi=require("../../phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts");
const workflow=require("../src/main/sepolia-mint-composed-workflow.cjs");
const {createSepoliaMintReplayStore}=require("../src/main/sepolia-mint-replay-store.cjs");

async function main(){
  const repositoryRoot=path.resolve(__dirname,"../../.."),temporary=fs.mkdtempSync(path.join(os.tmpdir(),"phil-sepolia-product-workflow-"));
  try{
    const devicePrivate=Buffer.from("43".repeat(32),"hex"),executionOwner=new ethers.Wallet(`0x${"61".repeat(32)}`);
    const enrollment=device.createPhilDeviceEnrollmentRecordV1({deviceId:ethers.id("product-device"),deviceKeyId:ethers.id("product-device-key"),signatureSuiteId:mint.PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,publicKey:p256.getPublicKey(devicePrivate,false),deviceEpoch:"1",enrolledAt:"1799999000",assuranceClass:3,policyHash:ethers.id("active-device-policy")});
    const bindingsInput={factory:"0x1000000000000000000000000000000000000001",smartAccount:"0x2000000000000000000000000000000000000002",actionGate:"0x3000000000000000000000000000000000000003",mintConsumer:"0x4000000000000000000000000000000000000004",mintRecipient:"0x5000000000000000000000000000000000000005",accountNonce:"0",validAfter:"1800000000",validUntil:"1800000120",maximumTotalFeeWei:"2500000000000000"};
    const prepared=await workflow.preparePhilSepoliaMintComposedWorkflow({repositoryRoot,protectedMaterial:{philSecret:`0x${"07".repeat(32)}`},bindingsInput,epochs:{scopeEpoch:"1",deviceEpoch:"1",recoveryEpoch:"1",validatorEpoch:"1"},enrollment,executionOwner:executionOwner.address,ownerCommitment:ethers.id("execution-owner-commitment"),accountSalt:"9",accountDeployed:false,gas:{callGasLimit:"180000",verificationGasLimit:"500000",preVerificationGas:"90000",maxFeePerGas:"2000000000",maxPriorityFeePerGas:"1000000000"},proofTimeoutMs:120000,dependencies:{randomBytes:()=>Buffer.from("08".repeat(32),"hex")}});
    assert.equal(prepared.context.philSecretReturned,false);assert.equal(prepared.context.nullifierSeedReturned,false);assert.equal(JSON.stringify(prepared.context).includes("07070707"),false);assert.equal(JSON.stringify(prepared.context).includes("08080808"),false);
    const ceremony=prepared.createDeviceRequest({sessionId:ethers.id("product-session"),approvalNonce:ethers.id("product-approval-nonce"),now:"1800000005"});
    assert.equal(ceremony.request.platformSigningDigest,ceremony.request.deviceApprovalDigest);
    const approvalSignature=p256.sign(ceremony.request.deviceApprovalDigest.slice(2),devicePrivate,{lowS:true,prehash:false});
    const response=requestApi.createPhilSepoliaMintDeviceResponseV1({request:ceremony.request,enrollment,signature:ethers.concat([ethers.toBeHex(approvalSignature.r,32),ethers.toBeHex(approvalSignature.s,32)])});
    const replayStore=createSepoliaMintReplayStore({ledgerPath:path.join(temporary,"replay.json"),now:()=>"2026-08-24T22:00:00.000Z"});let signerRequests=0;
    const descriptor={signerId:"device-vault-product-test",mode:"device_vault_beta_ecdsa",ownerAddress:executionOwner.address,keyReference:{keyReferenceId:"encrypted-product-test-key",mode:"device_vault_beta_ecdsa",custody:"device_vault_encrypted",privateKeyExportable:false,derivedFromPhilSecret:false},available:true,productionApproved:false,arbitraryMessageSigning:false,arbitraryTransactionSigning:false};
    const signed=await workflow.completePhilSepoliaMintComposedWorkflow({repositoryRoot,context:ceremony.context,request:ceremony.request,response,enrollment,replayStore,trustedState:{now:"1800000010",scopeEpoch:"1",deviceEpoch:"1",recoveryEpoch:"1",validatorEpoch:"1",accountNonce:"0",valueWei:"0",maximumTotalFeeWei:bindingsInput.maximumTotalFeeWei,emergencyStop:false,scopeActive:true,policyActive:true,proofDescriptorActive:true,deviceActive:true,recoveryStateCurrent:true,validatorActive:true,cancelled:false,denied:false},createDeviceVaultSigner:async()=>{assert.equal(replayStore.hasExactReservation({authorizationEnvelopeDigest:ceremony.request.authorization.authorizationEnvelopeDigest,rootProofNullifier:ceremony.request.authorization.authorizationEnvelope.rootProofNullifier,deviceApprovalNonce:ceremony.request.approvalNonce,accountNonce:"0"}),true,"durable replay reservation must precede Device Vault session creation");return {describeSigner:async()=>descriptor,checkAvailability:async()=>descriptor,getOwnerAddress:async()=>executionOwner.address,signUserOperationHash:async(request)=>{signerRequests+=1;return {status:"signed",signature:await executionOwner.signMessage(ethers.getBytes(request.userOperationHash)),signerDescriptor:descriptor,signedAt:"2026-08-24T22:00:00.000Z"};},invalidateSigningSession:async()=>{}};}});
    assert.equal(signerRequests,1);assert.equal(signed.signed,true);assert.equal(signed.submitted,false);assert.equal(signed.ethereumVerifiesNoirProof,false);assert.equal(signed.ethereumVerifiesP256Approval,false);assert.equal(ethers.verifyMessage(ethers.getBytes(signed.userOperationHash),signed.userOperation.signature),executionOwner.address);assert.equal(replayStore.snapshot().count,1);
    console.log("ok - real Noir, exact iPhone P-256 digest, durable replay, and Device Vault UserOperation signing compose end to end without submission");
  }finally{fs.rmSync(temporary,{recursive:true,force:true});}
}
main().catch((error)=>{console.error(error instanceof Error?error.message:error);process.exitCode=1;});
