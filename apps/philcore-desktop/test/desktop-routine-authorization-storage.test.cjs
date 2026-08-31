"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { createRoutineAuthorizationProtectedStores } = require("../src/main/routine-authorization-storage.cjs");

function encryptionAdapter() {
  const wrappingKey = crypto.createHash("sha256").update("STEP6C2_STORAGE_TEST_ONLY").digest();
  return {
    isAvailable: () => true,
    encrypt(plaintext) {
      const nonce = Buffer.alloc(12, 7), cipher = crypto.createCipheriv("aes-256-gcm", wrappingKey, nonce);
      const ciphertext = Buffer.concat([cipher.update(String(plaintext),"utf8"),cipher.final()]);
      return Buffer.concat([nonce,cipher.getAuthTag(),ciphertext]);
    },
    decrypt(input) {
      const value = Buffer.from(input), decipher = crypto.createDecipheriv("aes-256-gcm", wrappingKey, value.subarray(0,12));
      decipher.setAuthTag(value.subarray(12,28));return Buffer.concat([decipher.update(value.subarray(28)),decipher.final()]).toString("utf8");
    }
  };
}

test("routine storage protects the canonical request, journal key, and durable ordered frames", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phil-step6c2-storage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const profileId = `0x${"12".repeat(32)}`, requestId = `0x${"34".repeat(32)}`, key = Buffer.alloc(32,5);
  const adapter=encryptionAdapter(),encrypt=adapter.encrypt.bind(adapter);let failDeletionEncryption=false;
  adapter.encrypt=(plaintext)=>{if(failDeletionEncryption&&String(plaintext).includes('"status":"committed"'))throw new Error("deletion encryption precommit failure");return encrypt(plaintext);};
  const first = createRoutineAuthorizationProtectedStores({ storageRoot: root, encryptionAdapter: adapter });
  assert.deepEqual(first.protectedKeyStore.create(profileId,key),key);
  const canonicalRequest = `{"requestId":"${requestId}","private":"must-not-appear"}`;
  const canonicalEnrollment = `{"deviceId":"0x${"78".repeat(32)}","public":"protected-at-rest"}`;
  await first.enrollmentStore.save(profileId,canonicalEnrollment,"synthetic_source_test");
  await first.requestStore.save(requestId,canonicalRequest);
  await first.journalStore.append(requestId,1,"frame-one");await first.journalStore.append(requestId,2,"frame-two");
  const keyFile = fs.readdirSync(first.paths.keysRoot)[0];
  const stored = fs.readFileSync(path.join(first.paths.keysRoot,keyFile),"utf8");
  assert.equal(stored.includes(key.toString("base64url")),false,"plaintext journal key must not be stored");
  const requestFile = fs.readdirSync(first.paths.requestsRoot)[0];
  const protectedRequest = fs.readFileSync(path.join(first.paths.requestsRoot,requestFile),"utf8");
  assert.equal(protectedRequest.includes("must-not-appear"),false,"canonical request must be protected at rest");
  const enrollmentFile = fs.readdirSync(first.paths.enrollmentsRoot)[0];
  assert.equal(fs.readFileSync(path.join(first.paths.enrollmentsRoot,enrollmentFile),"utf8").includes("protected-at-rest"),false);
  const reopened = createRoutineAuthorizationProtectedStores({ storageRoot: root, encryptionAdapter: adapter });
  assert.deepEqual(reopened.protectedKeyStore.load(profileId),key);
  assert.deepEqual(await reopened.requestStore.list(),[requestId]);
  assert.equal(await reopened.requestStore.load(requestId),canonicalRequest);
  assert.deepEqual(await reopened.enrollmentStore.load(profileId),{
    canonicalEnrollmentJson:canonicalEnrollment,evidenceClass:"synthetic_source_test"
  });
  assert.deepEqual(await reopened.journalStore.read(requestId),["frame-one","frame-two"]);
  assert.throws(() => reopened.protectedKeyStore.create(profileId,key),/ROUTINE_STORAGE_ALREADY_EXISTS/);
  await assert.rejects(reopened.journalStore.append(requestId,4,"gap"),/ROUTINE_JOURNAL_GENERATION_GAP/);
  failDeletionEncryption=true;await assert.rejects(reopened.profileStore.deleteAll(profileId),/deletion encryption precommit failure/u);
  assert.equal(await reopened.requestStore.load(requestId),canonicalRequest);failDeletionEncryption=false;
  assert.deepEqual(await reopened.profileStore.deleteAll(profileId),{status:"deleted",identityOrRecoveryStateTouched:false});
  assert.equal(fs.readdirSync(reopened.paths.journalsRoot).length,0);assert.equal(fs.readdirSync(reopened.paths.requestsRoot).length,0);assert.equal(fs.readdirSync(reopened.paths.enrollmentsRoot).length,0);assert.equal(fs.readdirSync(reopened.paths.keysRoot).length,0);
});

test("a durably committed product-wide deletion finishes after process interruption",async(t)=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),"phil-step6c2-storage-delete-recovery-"));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const adapter=encryptionAdapter(),profileId=`0x${"66".repeat(32)}`,requestId=`0x${"67".repeat(32)}`,stores=createRoutineAuthorizationProtectedStores({storageRoot:root,encryptionAdapter:adapter});
  stores.protectedKeyStore.create(profileId,Buffer.alloc(32,4));await stores.enrollmentStore.save(profileId,"{}","synthetic_source_test");
  await stores.requestStore.save(requestId,"{}");await stores.journalStore.append(requestId,1,"frame");
  fs.writeFileSync(path.join(root,"profile-deletion-v1.json"),`${JSON.stringify({version:1,profileId,status:"committed"})}\n`);
  assert.throws(()=>createRoutineAuthorizationProtectedStores({storageRoot:root,encryptionAdapter:adapter}),/ROUTINE_PROFILE_DELETION_RECORD_INVALID/);
  assert.notEqual(fs.readdirSync(stores.paths.keysRoot).length,0,"unauthenticated marker must not delete the profile");
  const protectedDeletion=Buffer.from(adapter.encrypt(JSON.stringify({version:1,profileId,status:"committed"}))).toString("base64url");
  fs.writeFileSync(path.join(root,"profile-deletion-v1.json"),`${JSON.stringify({version:1,protectedDeletion})}\n`);
  const recovered=createRoutineAuthorizationProtectedStores({storageRoot:root,encryptionAdapter:adapter});
  for (const directory of [recovered.paths.keysRoot,recovered.paths.journalsRoot,recovered.paths.requestsRoot,recovered.paths.enrollmentsRoot]) assert.deepEqual(fs.readdirSync(directory),[]);
  assert.equal(fs.existsSync(path.join(root,"profile-deletion-v1.json")),false);
});

test("routine storage authentication failure is terminal and isolated", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "phil-step6c2-storage-tamper-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const profileId = `0x${"56".repeat(32)}`;
  const stores = createRoutineAuthorizationProtectedStores({ storageRoot: root, encryptionAdapter: encryptionAdapter() });
  stores.protectedKeyStore.create(profileId,Buffer.alloc(32,9));
  const location = path.join(stores.paths.keysRoot,fs.readdirSync(stores.paths.keysRoot)[0]);
  const record = JSON.parse(fs.readFileSync(location,"utf8"));record.wrappedKey = `${record.wrappedKey.slice(0,-1)}A`;
  fs.writeFileSync(location,JSON.stringify(record));
  assert.throws(() => stores.protectedKeyStore.load(profileId),/ROUTINE_JOURNAL_KEY_UNAVAILABLE|ROUTINE_JOURNAL_KEY_INVALID/);
  assert.equal(fs.existsSync(path.join(root,"identity")),false);assert.equal(fs.existsSync(path.join(root,"recovery")),false);
});
