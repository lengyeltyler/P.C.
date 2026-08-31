"use strict";
// Test-process only. Never packaged or imported by the Desktop application.
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const root = path.resolve(__dirname, "../../../..");
process.env.HARDHAT_CONFIG = path.join(root, "hardhat.phil-v1-step6c-product.config.cjs");
const hardhat = require("hardhat");
require("tsx/cjs");
const {createRoutineAuthorizationProtectedStores} = require("../../src/main/routine-authorization-storage.cjs");
const {createRoutineDeviceEnrollmentHost} = require("../../src/main/routine-device-enrollment-host.cjs");
const {createRoutineAuthorizationHost} = require("../../src/main/routine-authorization-host.cjs");
const {createRoutineAuthorizationProductHost} = require("../../src/main/routine-authorization-product-host.cjs");
const {createRoutineAuthorizationLocalProductRuntime} = require("../../src/main/routine-authorization-local-product-runtime.cjs");
const {createDesktopRuntimeHost,createFixturePlatformKeyAdapter} = require("../../src/main/runtime-host.cjs");
const {CHANNELS} = require("../../src/shared/bridge-contract.cjs");
const ipv4 = Object.values(os.networkInterfaces()).flat().find(v => v?.family === "IPv4" && !v.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(v.address))?.address;
assert.ok(ipv4, "Private test interface is required; no loopback policy bypass");
const output = path.join(root, ".local/release-validation");
fs.mkdirSync(output,{recursive:true});
const dataRoot = fs.mkdtempSync(path.join(os.tmpdir(),"phil-routine-longitudinal-"));
// Only OS credential wrapping is synthetic. Protected store serialization,
// durable replacement, enrollment proof and acknowledgments remain production.
const wrappingKey = crypto.randomBytes(32);
const adapter = {isAvailable:()=>true,encrypt(text){
  const nonce=crypto.randomBytes(12),c=crypto.createCipheriv("aes-256-gcm",wrappingKey,nonce);
  const body=Buffer.concat([c.update(String(text)),c.final()]);return Buffer.concat([nonce,c.getAuthTag(),body]);
},decrypt(raw){const b=Buffer.from(raw),d=crypto.createDecipheriv("aes-256-gcm",wrappingKey,b.subarray(0,12));
  d.setAuthTag(b.subarray(12,28));return Buffer.concat([d.update(b.subarray(28)),d.final()]).toString();}};
const stores = createRoutineAuthorizationProtectedStores({storageRoot:path.join(dataRoot,"routine"),encryptionAdapter:adapter});
const profileId="0x"+"79".repeat(32), passphrase="Longitudinal-test-only-1!";
let desktop,identityId,product,enrollmentHost,lastRequest,offset=0,executions=0,requests=0,restarts=0;
const now=()=>BigInt(Math.floor(Date.now()/1000)+offset);
async function initialize() {
  desktop=createDesktopRuntimeHost({preferencesPath:path.join(dataRoot,"prefs.json"),identityStorageRoot:path.join(dataRoot,"identity"),platformKeyAdapter:createFixturePlatformKeyAdapter(),sessionTtlMs:3600000});
  if (!identityId) identityId=desktop.invoke(CHANNELS.CREATE_LOCAL_IDENTITY,{label:"Longitudinal synthetic",passphrase,createRecoveryAuthority:true}).identity.identityId;
  else desktop.invoke(CHANNELS.OPEN_LOCAL_IDENTITY,{identityId});
  desktop.invoke(CHANNELS.AUTHENTICATE_LOCAL,{passphrase});
  assert.equal(desktop.invoke(CHANNELS.UNLOCK_VAULT,{}).snapshot.session.lockState,"unlocked");
  enrollmentHost=createRoutineDeviceEnrollmentHost({disposableProfileId:profileId,ipv4,enrollmentStore:stores.enrollmentStore,now,allowSynthetic:true});
  product=createRoutineAuthorizationProductHost({enrollmentHost,deleteProfileAtomically:()=>stores.profileStore.deleteAll(profileId),authorizationHostFactory:async stored=>{
    const runtime=await createRoutineAuthorizationLocalProductRuntime({hardhat,repositoryRoot:root,enrollment:stored.record,now:async()=>now(),
      desktopUnlocked:async()=>desktop.snapshot().session.lockState==="unlocked",
      iphoneSessionCurrent:async()=> (await enrollmentHost.activeEnrollment()).record.generation===stored.record.generation});
    // Local deployment may advance the chain a few seconds beyond wall time.
    offset=Math.max(offset,Number((await hardhat.ethers.provider.getBlock("latest")).timestamp)-Math.floor(Date.now()/1000));
    return createRoutineAuthorizationHost({disposableProfileId:profileId,ipv4,now,
      readCurrentNonce:runtime.readCurrentNonce,
      requestFactory:async intent=>{lastRequest=await runtime.requestFactory(intent);requests++;return lastRequest;},
      readTrustedState:runtime.readTrustedState,simulate:runtime.simulate,
      execute:async(...args)=>{executions++;return runtime.execute(...args);},reconcile:runtime.reconcile,
      protectedKeyStore:stores.protectedKeyStore,journalStore:stores.journalStore,requestStore:stores.requestStore});
  }});
  await product.initialize();
}
async function command(value) {
  assert.ok(value && typeof value.op==="string");
  switch(value.op) {
    case "begin": {const result=await product.beginRoutineAuthorization({action:"record_harmless_value"});return {...result,nonce:lastRequest?.action.nonceSequence ?? null,now:String(now())};}
    case "status": return {...await product.getRoutineAuthorizationStatus(value.requestId),executions,now:String(now())};
    case "cancel": return {outcome:await product.cancelRoutineAuthorization(value.requestId),now:String(now())};
    case "expire": {
      const status=await product.getRoutineAuthorizationStatus(value.requestId);
      offset=Number(status.expiresAt)+1-Math.floor(Date.now()/1000);
      await hardhat.ethers.provider.send("evm_setNextBlockTimestamp",[Number(now())]);
      await hardhat.ethers.provider.send("evm_mine",[]);
      return {...await product.getRoutineAuthorizationStatus(value.requestId),now:String(now())};
    }
    case "restart": {
      await product.stop();await hardhat.ethers.provider.send("hardhat_reset",[]);restarts++;await initialize();
      const active=await enrollmentHost.activeEnrollment();return {generation:active.record.generation,publicKeyFingerprint:active.record.publicKeyFingerprint,now:String(now())};
    }
    case "baseline": return product.acceptanceBaseline();
    case "stats": return {executions,requests,restarts,now:String(now()),publicMutations:0};
    default: throw new Error("unknown test command");
  }
}
(async()=>{
  await initialize();
  let tail=Promise.resolve();
  const server=http.createServer(async(req,res)=>{
    try {
      assert.equal(req.method,"POST");assert.equal(req.url,"/command");
      let size=0,chunks=[];for await(const c of req){size+=c.length;assert.ok(size<4096);chunks.push(c);}
      const operation=()=>command(JSON.parse(Buffer.concat(chunks).toString()));
      const result=tail.then(operation);tail=result.catch(()=>{});
      const body=JSON.stringify(await result);res.writeHead(200,{"content-type":"application/json","content-length":Buffer.byteLength(body)});res.end(body);
    } catch(e){res.writeHead(500,{"content-type":"application/json"});res.end(JSON.stringify({error:e.code||e.message}));}
  });
  await new Promise(resolve=>server.listen(0,"127.0.0.1",resolve));
  const info={url:`http://127.0.0.1:${server.address().port}/command`,classification:"synthetic-test-process-only",pid:process.pid};
  fs.writeFileSync(path.join(output,"harness-control.json"),JSON.stringify(info));
  process.stdout.write("LONGITUDINAL_BACKEND_READY\n");
  process.on("SIGTERM",async()=>{await product.stop();server.close();wrappingKey.fill(0);process.exit(0);});
})().catch(e=>{console.error(e.code||e.message);process.exit(1);});
