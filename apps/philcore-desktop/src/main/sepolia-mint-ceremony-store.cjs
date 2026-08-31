"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function fail(code) { const error=new Error(code);error.code=code;throw error; }
function requestId(value) { const result=String(value||"").toLowerCase();if(!/^0x[0-9a-f]{64}$/u.test(result)||/^0x0{64}$/u.test(result))fail("SEPOLIA_MINT_CEREMONY_REQUEST_ID_INVALID");return result; }
function syncDirectory(directory) { const descriptor=fs.openSync(directory,fs.constants.O_RDONLY);try{fs.fsyncSync(descriptor);}finally{fs.closeSync(descriptor);} }
function writeAtomic(location,contents,{exclusive=false}={}) {
  const directory=path.dirname(location);fs.mkdirSync(directory,{recursive:true,mode:0o700});fs.chmodSync(directory,0o700);
  const temporary=path.join(directory,`.${path.basename(location)}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`);
  let descriptor;
  try {
    descriptor=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);
    fs.writeFileSync(descriptor,contents);fs.fsyncSync(descriptor);fs.closeSync(descriptor);descriptor=undefined;
    if(exclusive&&fs.existsSync(location))fail("SEPOLIA_MINT_CEREMONY_ALREADY_EXISTS");
    fs.renameSync(temporary,location);fs.chmodSync(location,0o600);syncDirectory(directory);
  } finally { if(descriptor!==undefined)fs.closeSync(descriptor);try{fs.unlinkSync(temporary);}catch{} }
}

function createSepoliaMintCeremonyStore(options) {
  if(!options||Object.keys(options).sort().join(",")!=="encryptionAdapter,storageRoot")fail("SEPOLIA_MINT_CEREMONY_OPTIONS_INVALID");
  if(typeof options.storageRoot!=="string"||!path.isAbsolute(options.storageRoot)||options.storageRoot==="/"||options.storageRoot.includes("\0"))fail("SEPOLIA_MINT_CEREMONY_ROOT_INVALID");
  if(!options.encryptionAdapter||options.encryptionAdapter.isAvailable?.()!==true||typeof options.encryptionAdapter.encrypt!=="function"||typeof options.encryptionAdapter.decrypt!=="function")fail("SEPOLIA_MINT_CEREMONY_PROTECTION_UNAVAILABLE");
  fs.mkdirSync(options.storageRoot,{recursive:true,mode:0o700});fs.chmodSync(options.storageRoot,0o700);
  const location=(id)=>path.join(options.storageRoot,`${requestId(id).slice(2)}.ceremony-v1.json`);
  function protect(record) {
    const encrypted=Buffer.from(options.encryptionAdapter.encrypt(JSON.stringify(record))).toString("base64url");
    return `${JSON.stringify({version:1,requestId:record.requestId,protectedCeremony:encrypted})}\n`;
  }
  function load(id) {
    const expected=requestId(id);let outer,record;
    try{outer=JSON.parse(fs.readFileSync(location(expected),"utf8"));}catch{fail("SEPOLIA_MINT_CEREMONY_UNAVAILABLE");}
    if(!outer||Object.keys(outer).sort().join(",")!=="protectedCeremony,requestId,version"||outer.version!==1||outer.requestId!==expected||typeof outer.protectedCeremony!=="string"||/[=+\/\s]/u.test(outer.protectedCeremony))fail("SEPOLIA_MINT_CEREMONY_RECORD_INVALID");
    try{record=JSON.parse(String(options.encryptionAdapter.decrypt(Buffer.from(outer.protectedCeremony,"base64url"))));}catch{fail("SEPOLIA_MINT_CEREMONY_UNAVAILABLE");}
    if(!record||record.version!==1||record.requestId!==expected||!["waiting","approved","completed","cancelled","expired"].includes(record.state)||typeof record.requestJson!=="string"||record.requestJson.length<2||record.requestJson.length>65503||typeof record.contextJson!=="string"||record.contextJson.length<2||record.contextJson.length>1048576)fail("SEPOLIA_MINT_CEREMONY_RECORD_INVALID");
    if((record.state==="approved"||record.state==="completed")&&typeof record.responseJson!=="string")fail("SEPOLIA_MINT_CEREMONY_RECORD_INVALID");
    return Object.freeze({...record});
  }
  function update(id,mutate) { const current=load(id),next=Object.freeze(mutate(current));writeAtomic(location(id),protect(next));return next; }
  return Object.freeze({
    saveRequest(input) {
      const record=Object.freeze({version:1,requestId:requestId(input.requestId),state:"waiting",requestJson:String(input.requestJson),contextJson:String(input.contextJson||"{}"),createdAt:String(input.createdAt),expiresAt:String(input.expiresAt)});
      writeAtomic(location(record.requestId),protect(record),{exclusive:true});return record;
    },
    saveResponse(id,responseJson) { return update(id,(record)=>{if(record.state!=="waiting")fail("SEPOLIA_MINT_CEREMONY_RESPONSE_OUT_OF_ORDER");return {...record,state:"approved",responseJson:String(responseJson)};}); },
    markCompleted(id,result) { return update(id,(record)=>{if(record.state!=="approved")fail("SEPOLIA_MINT_CEREMONY_COMPLETION_OUT_OF_ORDER");return {...record,state:"completed",completion:result};}); },
    markTerminal(id,state) { if(!["cancelled","expired"].includes(state))fail("SEPOLIA_MINT_CEREMONY_TERMINAL_INVALID");return update(id,(record)=>({...record,state})); },
    load,
    list() { return fs.readdirSync(options.storageRoot).map((name)=>{const match=/^([0-9a-f]{64})\.ceremony-v1\.json$/u.exec(name);if(!match)fail("SEPOLIA_MINT_CEREMONY_FILE_INVALID");return `0x${match[1]}`;}).sort(); }
  });
}

module.exports={createSepoliaMintCeremonyStore};
