const assert=require("node:assert/strict");
const { createHash }=require("node:crypto");
const { p256 }=require("@noble/curves/p256");
const hardhat=require("hardhat");

require("tsx/cjs");
const auth=require("../../phil-device-sdk/src/routineAuthorizationV1.ts");
const journal=require("../../phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts");
const wire=require("../../phil-device-sdk/src/p256SignatureWireV2.ts");
const { createRoutineAuthorizationLocalProductRuntime }=require("../src/main/routine-authorization-local-product-runtime.cjs");

describe("Phil V1 Step 6C-2 product-owned local runtime",function () {
  it("provisions from an enrolled public key with a fresh random deployer and executes the exact signed local request",async function () {
    const privateKey=Buffer.from("05".repeat(32),"hex"),publicKey=Buffer.from(p256.getPublicKey(privateKey,false));
    const enrollment={schemaVersion:2,generation:"1",deviceId:`0x${"31".repeat(32)}`,deviceKeyId:`0x${"32".repeat(32)}`,
      signatureSuiteId:wire.PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,providerProfileId:wire.PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
      wireEncodingId:wire.PHIL_ROUTINE_WIRE_ENCODING_V2_ID,
      publicKeyX963:`0x${publicKey.toString("hex")}`,publicKeyFingerprint:`0x${createHash("sha256").update(publicKey).digest("hex")}`,
      secureEnclaveBacked:false,userPresenceRequired:false};
    let protectedNow=null;
    const runtime=await createRoutineAuthorizationLocalProductRuntime({hardhat,repositoryRoot:process.cwd(),enrollment,
      now:async()=>protectedNow??BigInt((await hardhat.ethers.provider.getBlock("latest")).timestamp),
      desktopUnlocked:async()=>true,iphoneSessionCurrent:async()=>true});
    protectedNow=BigInt((await hardhat.ethers.provider.getBlock("latest")).timestamp)+10n;
    const request=await runtime.requestFactory({action:"record_harmless_value"});
    const signature=p256.sign(request.platformSigningDigest.slice(2),privateKey,{lowS:true,prehash:false});
    const response=auth.createPhilRoutineAuthorizationResponseV1({request,signature:wire.encodePhilP256RawSignatureV2({r:`0x${signature.r.toString(16).padStart(64,"0")}`,
      s:`0x${signature.s.toString(16).padStart(64,"0")}`})});
    const simulation=await runtime.simulate(request,response),outcome=await runtime.execute(request,response,simulation);
    assert.equal(outcome.kind,"success");assert.equal(outcome.receipt.requestId,request.requestId);
    assert.equal(await runtime.context.target.recordedSequence(),1n);
    assert.equal(runtime.classification.usesFreshRandomDeployer,true);assert.equal(runtime.classification.externalNetwork,false);
    assert.equal(Array.isArray(hardhat.config.networks.hardhat.accounts),true);assert.equal(hardhat.config.networks.hardhat.accounts.length,1);
    assert.notEqual(runtime.context.deployer.address.toLowerCase(),(await hardhat.ethers.getSigners())[0].address.toLowerCase());
  });
  it("rebuilds and verifies a committed successful outcome from matching local-chain evidence",async function () {
    const privateKey=Buffer.from("15".repeat(32),"hex"),publicKey=Buffer.from(p256.getPublicKey(privateKey,false));
    const enrollment={schemaVersion:2,generation:"1",deviceId:`0x${"41".repeat(32)}`,deviceKeyId:`0x${"42".repeat(32)}`,
      signatureSuiteId:wire.PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,providerProfileId:wire.PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
      wireEncodingId:wire.PHIL_ROUTINE_WIRE_ENCODING_V2_ID,publicKeyX963:`0x${publicKey.toString("hex")}`,
      publicKeyFingerprint:`0x${createHash("sha256").update(publicKey).digest("hex")}`,secureEnclaveBacked:false,userPresenceRequired:false};
    const runtime=await createRoutineAuthorizationLocalProductRuntime({hardhat,repositoryRoot:process.cwd(),enrollment,
      now:async()=>BigInt((await hardhat.ethers.provider.getBlock("latest")).timestamp),
      desktopUnlocked:async()=>true,iphoneSessionCurrent:async()=>true});
    const request=await runtime.requestFactory({action:"record_harmless_value"}),signature=p256.sign(request.platformSigningDigest.slice(2),privateKey,{lowS:true,prehash:false});
    const response=auth.createPhilRoutineAuthorizationResponseV1({request,signature:wire.encodePhilP256RawSignatureV2({r:`0x${signature.r.toString(16).padStart(64,"0")}`,
      s:`0x${signature.s.toString(16).padStart(64,"0")}`})}),simulation=await runtime.simulate(request,response);
    let record=journal.createPhilRoutineJournalRecordV1({requestId:request.requestId,sessionId:request.authorizationCore.sessionId,recordedAt:request.authorizationCore.issuedAt});
    const advance=(nextState,evidence={})=>{record=journal.transitionPhilRoutineJournalRecordV1({current:record,expectedGeneration:record.generation,
      expectedRecordHash:record.recordHash,nextState,recordedAt:request.authorizationCore.issuedAt,evidence});};
    advance(2);advance(3);advance(4);advance(5);advance(6,{...simulation});
    await runtime.execute(request,response,simulation);runtime.context.outcomes.delete(request.requestId);
    const rebuilt=await runtime.reconcile(request,record),verified=journal.verifyPhilRoutineSuccessfulOutcomeV1({request,journal:record,outcome:rebuilt});
    assert.equal(rebuilt.kind,"success");assert.equal(verified.nextState,8);assert.equal(rebuilt.receipt.requestId,request.requestId);
  });
});
