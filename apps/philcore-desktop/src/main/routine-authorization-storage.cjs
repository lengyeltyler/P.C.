"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

function fail(code) { const error = new Error(code);error.code = code;throw error; }
function id(value, label) {
  const normalized = String(value).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/u.test(normalized) || /^0x0{64}$/u.test(normalized)) fail(`ROUTINE_${label}_INVALID`);
  return normalized;
}
function ensureRoot(root) {
  if (typeof root !== "string" || !path.isAbsolute(root) || root === "/" || root.includes("\0")) fail("ROUTINE_STORAGE_ROOT_INVALID");
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });fs.chmodSync(root, 0o700);return root;
}
function syncDirectory(directory) { const fd = fs.openSync(directory, fs.constants.O_RDONLY);try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function durableWrite(location, contents, { exclusive = false } = {}) {
  const directory = path.dirname(location);ensureRoot(directory);
  const temporary = path.join(directory, `.${path.basename(location)}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`);
  let fd;
  try {
    fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
    fs.writeFileSync(fd, contents);fs.fsyncSync(fd);fs.closeSync(fd);fd = undefined;
    if (exclusive && fs.existsSync(location)) fail("ROUTINE_STORAGE_ALREADY_EXISTS");
    fs.renameSync(temporary, location);fs.chmodSync(location, 0o600);syncDirectory(directory);
  } finally { if (fd !== undefined) fs.closeSync(fd);try { fs.unlinkSync(temporary); } catch {} }
}

function createRoutineAuthorizationProtectedStores(options) {
  if (!options || Object.keys(options).sort().join(",") !== "encryptionAdapter,storageRoot") fail("ROUTINE_STORAGE_OPTIONS_INVALID");
  const root = ensureRoot(options.storageRoot), keysRoot = ensureRoot(path.join(root, "keys-v1")), journalsRoot = ensureRoot(path.join(root, "journals-v1")), requestsRoot = ensureRoot(path.join(root, "requests-v1")), enrollmentsRoot = ensureRoot(path.join(root, "enrollments-v2"));
  const deletionMarkerPath=path.join(root,"profile-deletion-v1.json");
  if (!options.encryptionAdapter || typeof options.encryptionAdapter.encrypt !== "function" || typeof options.encryptionAdapter.decrypt !== "function"
    || options.encryptionAdapter.isAvailable?.() !== true) fail("ROUTINE_STORAGE_PROTECTION_UNAVAILABLE");
  const keyPath = (profileId) => path.join(keysRoot, `${id(profileId,"PROFILE_ID").slice(2)}.wrapped-key.json`);
  const requestRoot = (requestId) => path.join(journalsRoot, id(requestId,"REQUEST_ID").slice(2));
  const requestPath = (requestId) => path.join(requestsRoot, `${id(requestId,"REQUEST_ID").slice(2)}.protected-request.json`);
  const enrollmentPath = (profileId) => path.join(enrollmentsRoot, `${id(profileId,"PROFILE_ID").slice(2)}.protected-enrollment.json`);
  let deletionCommitted=false;
  function decodeDeletionMarker() {
    let outer,plaintext,marker;
    try {
      const stats=fs.lstatSync(deletionMarkerPath);if (!stats.isFile()||stats.isSymbolicLink()||stats.size<2||stats.size>8192) fail("ROUTINE_PROFILE_DELETION_RECORD_INVALID");
      outer=JSON.parse(fs.readFileSync(deletionMarkerPath,"utf8"));
    }
    catch { fail("ROUTINE_PROFILE_DELETION_RECORD_INVALID"); }
    if (!outer||Object.keys(outer).sort().join(",")!=="protectedDeletion,version"||outer.version!==1
      ||typeof outer.protectedDeletion!=="string"||/[=+\/\s]/u.test(outer.protectedDeletion)) fail("ROUTINE_PROFILE_DELETION_RECORD_INVALID");
    try {
      const protectedBytes=Buffer.from(outer.protectedDeletion,"base64url");if (protectedBytes.toString("base64url")!==outer.protectedDeletion) fail("ROUTINE_PROFILE_DELETION_RECORD_INVALID");
      plaintext=options.encryptionAdapter.decrypt(protectedBytes);marker=JSON.parse(String(plaintext));
    }
    catch { fail("ROUTINE_PROFILE_DELETION_RECORD_INVALID"); }
    if (!marker||Object.keys(marker).sort().join(",")!=="profileId,status,version"||marker.version!==1||marker.status!=="committed") fail("ROUTINE_PROFILE_DELETION_RECORD_INVALID");
    return id(marker.profileId,"PROFILE_ID");
  }
  function clearCommittedProfile(profileId) {
    const expected=id(profileId,"PROFILE_ID").slice(2);
    for (const name of fs.readdirSync(journalsRoot)) {
      if (!/^[0-9a-f]{64}$/u.test(name)) fail("ROUTINE_JOURNAL_FILE_INVALID");
      const directory=path.join(journalsRoot,name);
      for (const frame of fs.readdirSync(directory)) { if (!/^\d{12}\.frame\.json$/u.test(frame)) fail("ROUTINE_JOURNAL_FILE_INVALID");fs.unlinkSync(path.join(directory,frame)); }
      fs.rmdirSync(directory);
    }
    for (const name of fs.readdirSync(requestsRoot)) { if (!/^[0-9a-f]{64}\.protected-request\.json$/u.test(name)) fail("ROUTINE_REQUEST_FILE_INVALID");fs.unlinkSync(path.join(requestsRoot,name)); }
    for (const [directory,name] of [[keysRoot,`${expected}.wrapped-key.json`],[enrollmentsRoot,`${expected}.protected-enrollment.json`]]) {
      for (const actual of fs.readdirSync(directory)) { if (actual!==name) fail("ROUTINE_PROFILE_FILE_INVALID");fs.unlinkSync(path.join(directory,actual)); }
    }
    for (const directory of [journalsRoot,requestsRoot,keysRoot,enrollmentsRoot]) syncDirectory(directory);
  }
  if (fs.existsSync(deletionMarkerPath)) {
    clearCommittedProfile(decodeDeletionMarker());fs.unlinkSync(deletionMarkerPath);syncDirectory(root);
  }
  function assertProfileAvailable() { if (deletionCommitted||fs.existsSync(deletionMarkerPath)) fail("ROUTINE_PROFILE_DELETION_COMMITTED"); }
  const protectedKeyStore = Object.freeze({
    create(profileId, keyInput) {
      assertProfileAvailable();
      const key = Buffer.from(keyInput);if (key.length !== 32) fail("ROUTINE_JOURNAL_KEY_INVALID");
      const encrypted = Buffer.from(options.encryptionAdapter.encrypt(key.toString("base64url")));
      const record = { version: 1, profileId: id(profileId,"PROFILE_ID"), wrappedKey: encrypted.toString("base64url") };
      durableWrite(keyPath(profileId), `${JSON.stringify(record)}\n`, { exclusive: true });return Buffer.from(key);
    },
    load(profileId) {
      assertProfileAvailable();
      const expected = id(profileId,"PROFILE_ID");let record;
      try { record = JSON.parse(fs.readFileSync(keyPath(expected), "utf8")); } catch { fail("ROUTINE_JOURNAL_KEY_UNAVAILABLE"); }
      if (!record || Object.keys(record).sort().join(",") !== "profileId,version,wrappedKey" || record.version !== 1 || record.profileId !== expected
        || typeof record.wrappedKey !== "string" || /[=+\/\s]/u.test(record.wrappedKey)) fail("ROUTINE_JOURNAL_KEY_RECORD_INVALID");
      let plaintext;try { plaintext = options.encryptionAdapter.decrypt(Buffer.from(record.wrappedKey,"base64url")); } catch { fail("ROUTINE_JOURNAL_KEY_UNAVAILABLE"); }
      const key = Buffer.from(String(plaintext),"base64url");if (key.length !== 32 || key.toString("base64url") !== String(plaintext)) fail("ROUTINE_JOURNAL_KEY_INVALID");return key;
    },
    delete(profileId) { try { fs.unlinkSync(keyPath(profileId));syncDirectory(keysRoot); } catch (error) { if (error.code !== "ENOENT") throw error; } }
  });
  const journalStore = Object.freeze({
    async append(requestId, generation, frame) {
      assertProfileAvailable();
      const requestDirectory = ensureRoot(requestRoot(requestId));
      if (!Number.isSafeInteger(Number(generation)) || Number(generation) < 1 || String(Number(generation)) !== String(generation)) fail("ROUTINE_JOURNAL_GENERATION_INVALID");
      const prior = Number(generation) - 1;
      if ((prior === 0 && fs.readdirSync(requestDirectory).length !== 0)
        || (prior > 0 && !fs.existsSync(path.join(requestDirectory, `${String(prior).padStart(12,"0")}.frame.json`)))) fail("ROUTINE_JOURNAL_GENERATION_GAP");
      durableWrite(path.join(requestDirectory, `${String(generation).padStart(12,"0")}.frame.json`), `${String(frame)}\n`, { exclusive: true });
    },
    async read(requestId) {
      assertProfileAvailable();
      const directory = requestRoot(requestId);if (!fs.existsSync(directory)) return [];
      const names = fs.readdirSync(directory).sort();
      if (names.some((name,index) => name !== `${String(index+1).padStart(12,"0")}.frame.json`)) fail("ROUTINE_JOURNAL_GENERATION_GAP");
      return names.map((name) => fs.readFileSync(path.join(directory,name),"utf8").trimEnd());
    },
    async list() {
      assertProfileAvailable();
      return fs.readdirSync(journalsRoot).map((name) => id(`0x${name}`,"REQUEST_ID"));
    },
    async delete(requestId) {
      const directory = requestRoot(requestId);if (!fs.existsSync(directory)) return;
      for (const name of fs.readdirSync(directory)) { if (!/^\d{12}\.frame\.json$/u.test(name)) fail("ROUTINE_JOURNAL_FILE_INVALID");fs.unlinkSync(path.join(directory,name)); }
      fs.rmdirSync(directory);syncDirectory(journalsRoot);
    }
  });
  const requestStore = Object.freeze({
    async save(requestId, canonicalRequestJson) {
      assertProfileAvailable();
      const expected = id(requestId,"REQUEST_ID");
      if (typeof canonicalRequestJson !== "string" || canonicalRequestJson.length < 2 || canonicalRequestJson.length > 65503) {
        fail("ROUTINE_REQUEST_PLAINTEXT_INVALID");
      }
      const encrypted = Buffer.from(options.encryptionAdapter.encrypt(canonicalRequestJson));
      const record = { version: 1, requestId: expected, protectedRequest: encrypted.toString("base64url") };
      durableWrite(requestPath(expected), `${JSON.stringify(record)}\n`, { exclusive: true });
    },
    async load(requestId) {
      assertProfileAvailable();
      const expected = id(requestId,"REQUEST_ID");let record;
      try { record = JSON.parse(fs.readFileSync(requestPath(expected),"utf8")); } catch { fail("ROUTINE_REQUEST_UNAVAILABLE"); }
      if (!record || Object.keys(record).sort().join(",") !== "protectedRequest,requestId,version" || record.version !== 1
        || record.requestId !== expected || typeof record.protectedRequest !== "string" || /[=+\/\s]/u.test(record.protectedRequest)) {
        fail("ROUTINE_REQUEST_RECORD_INVALID");
      }
      let plaintext;try { plaintext = options.encryptionAdapter.decrypt(Buffer.from(record.protectedRequest,"base64url")); }
      catch { fail("ROUTINE_REQUEST_UNAVAILABLE"); }
      if (typeof plaintext !== "string" || plaintext.length < 2 || plaintext.length > 65503) fail("ROUTINE_REQUEST_PLAINTEXT_INVALID");
      return plaintext;
    },
    async list() {
      assertProfileAvailable();
      return fs.readdirSync(requestsRoot).map((name) => {
        const match = /^([0-9a-f]{64})\.protected-request\.json$/u.exec(name);
        if (!match) fail("ROUTINE_REQUEST_FILE_INVALID");
        return id(`0x${match[1]}`,"REQUEST_ID");
      }).sort();
    },
    async delete(requestId) {
      try { fs.unlinkSync(requestPath(requestId));syncDirectory(requestsRoot); }
      catch (error) { if (error.code !== "ENOENT") throw error; }
    }
  });
  const enrollmentStore = Object.freeze({
    async save(profileId, canonicalEnrollmentJson, evidenceClass) {
      assertProfileAvailable();
      const expected=id(profileId,"PROFILE_ID");
      if (typeof canonicalEnrollmentJson!=="string"||canonicalEnrollmentJson.length<2||canonicalEnrollmentJson.length>4096
        || !["synthetic_source_test","physical_device_unverified"].includes(evidenceClass)) fail("ROUTINE_ENROLLMENT_PLAINTEXT_INVALID");
      const encrypted=Buffer.from(options.encryptionAdapter.encrypt(canonicalEnrollmentJson));
      const record={version:2,profileId:expected,evidenceClass,protectedEnrollment:encrypted.toString("base64url")};
      durableWrite(enrollmentPath(expected),`${JSON.stringify(record)}\n`);
    },
    async load(profileId) {
      assertProfileAvailable();
      const expected=id(profileId,"PROFILE_ID");let serialized,record;
      try { serialized=fs.readFileSync(enrollmentPath(expected),"utf8"); }
      catch (error) { if (error?.code==="ENOENT") fail("ROUTINE_ENROLLMENT_NOT_FOUND");fail("ROUTINE_ENROLLMENT_UNAVAILABLE"); }
      try { record=JSON.parse(serialized); } catch { fail("ROUTINE_ENROLLMENT_UNAVAILABLE"); }
      if (!record||Object.keys(record).sort().join(",")!=="evidenceClass,profileId,protectedEnrollment,version"||record.version!==2
        ||record.profileId!==expected||!["synthetic_source_test","physical_device_unverified"].includes(record.evidenceClass)
        ||typeof record.protectedEnrollment!=="string"||/[=+\/\s]/u.test(record.protectedEnrollment)) fail("ROUTINE_ENROLLMENT_RECORD_INVALID");
      let plaintext;try { plaintext=options.encryptionAdapter.decrypt(Buffer.from(record.protectedEnrollment,"base64url")); }
      catch { fail("ROUTINE_ENROLLMENT_UNAVAILABLE"); }
      if (typeof plaintext!=="string"||plaintext.length<2||plaintext.length>4096) fail("ROUTINE_ENROLLMENT_PLAINTEXT_INVALID");
      return Object.freeze({canonicalEnrollmentJson:plaintext,evidenceClass:record.evidenceClass});
    },
    async delete(profileId) {
      try { fs.unlinkSync(enrollmentPath(profileId));syncDirectory(enrollmentsRoot); }
      catch (error) { if (error.code!=="ENOENT") throw error; }
    }
  });
  const profileStore=Object.freeze({
    async deleteAll(profileId) {
      const expected=id(profileId,"PROFILE_ID");assertProfileAvailable();
      const plaintext=JSON.stringify({version:1,profileId:expected,status:"committed"});
      const protectedDeletion=Buffer.from(options.encryptionAdapter.encrypt(plaintext)).toString("base64url");
      let committed=false;
      try {
        durableWrite(deletionMarkerPath,`${JSON.stringify({version:1,protectedDeletion})}\n`,{exclusive:true});deletionCommitted=true;committed=true;
        clearCommittedProfile(expected);fs.unlinkSync(deletionMarkerPath);syncDirectory(root);deletionCommitted=false;
        return Object.freeze({status:"deleted",identityOrRecoveryStateTouched:false});
      } catch (error) {
        const markerPresent=fs.existsSync(deletionMarkerPath);
        if (committed||markerPresent) {
          deletionCommitted=true;
          if (error&&typeof error==="object") error.profileDeletionCommitted=true;
        }
        throw error;
      }
    }
  });
  return Object.freeze({ protectedKeyStore, journalStore, requestStore, enrollmentStore, profileStore,
    paths: Object.freeze({ root, keysRoot, journalsRoot, requestsRoot, enrollmentsRoot }) });
}

module.exports = { createRoutineAuthorizationProtectedStores };
