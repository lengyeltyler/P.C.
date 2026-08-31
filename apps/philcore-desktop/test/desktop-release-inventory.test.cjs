"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path");
const {runtimePackageSelection,selectedNodeModuleEntry}=require("../scripts/runtime-package-inventory.cjs");
const {REQUIRED_NOTICES}=require("../scripts/distribution-notices.cjs");
const {createSbom,verifySbom}=require("../scripts/sbom.cjs");
// This SBOM fixture includes the native coverage contract added by B3.
function putNativeCoverage(app, put) {
  const hash = value => require("node:crypto").createHash("sha256").update(value).digest("hex");
  const bytes = Buffer.from("cffaedfe0001020304050607", "hex");
  const binary = "Contents/MacOS/test-native";
  fs.mkdirSync(path.join(app, "Contents/MacOS"), { recursive: true });
  fs.writeFileSync(path.join(app, binary), bytes);
  const notice = { path: "LICENSES/test-native.txt", sha256: hash("synthetic notice") };
  put(notice.path, "synthetic notice");
  const inventoryBytes = JSON.stringify({ requiredReferences: [notice] });
  const inventory = { path: "LICENSES/test-native-inventory.json", sha256: hash(inventoryBytes) };
  put(inventory.path, inventoryBytes);
  put("LICENSES/native-notice-coverage.json", JSON.stringify({ schemaVersion: 1, coverageStatus: "COMPLETE",
    inventories: [inventory], notices: [notice], nativeFiles: [{ path: binary, inputSha256: hash(bytes),
      packagedInputSha256: hash(bytes), sourceRevision: "synthetic-test-only", licenseIds: ["MIT"],
      inventoryReferences: [inventory.path], noticeReferences: [notice.path] }] }));
}
const root=path.resolve(__dirname,"../../..");
test("runtime closure keeps required engine and excludes compiler/test/other-platform packages",()=>{const s=runtimePackageSelection(root);for(const name of["hardhat","tsx","esbuild","ethers","starknet","@account-abstraction/contracts"])assert(s.packages.some(p=>p.name===name));for(const name of["mocha","solc","typescript","adm-zip","uuid","immutable","@sentry/node"])assert(!s.packages.some(p=>p.name===name),name);assert(!selectedNodeModuleEntry("hardhat/node_modules/solc/package.json",s));assert(!selectedNodeModuleEntry("keccak/build/Release/obj.target/addon/src/addon.o",s));assert(!selectedNodeModuleEntry("keccak/prebuilds/darwin-x64/node.napi.node",s));assert(selectedNodeModuleEntry("keccak/build/Release/addon.node",s));assert(selectedNodeModuleEntry("hardhat/internal/lib/hardhat-lib.js",s));assert(!s.packages.some(p=>p.name.startsWith("@nomicfoundation/edr-")&&p.name!=="@nomicfoundation/edr-darwin-arm64"));});
test("exact SBOM rejects missing notices, added packages and altered payload bytes",()=>{const app=fs.mkdtempSync(path.join(os.tmpdir(),"phil-sbom-test-")),payload=path.join(app,"Contents/Resources/app");const put=(p,s)=>{fs.mkdirSync(path.dirname(path.join(payload,p)),{recursive:true});fs.writeFileSync(path.join(payload,p),s);};try{for(const f of REQUIRED_NOTICES)put(f,"synthetic notice fixture\n");put("LICENSES/npm-notice-index.json","[]");put("config/release/runtime-package-inventory.json",JSON.stringify({packages:[],hardhatModification:{}}));put("package-lock.json","{}");putNativeCoverage(app,put);const sbom=createSbom(app);assert(verifySbom(app,sbom));put("new-file.txt","changed");assert.throws(()=>verifySbom(app,sbom),/artifact_hash_mismatch/);fs.rmSync(path.join(payload,"new-file.txt"));put("node_modules/unexpected/package.json",JSON.stringify({name:"unexpected",version:"1.0.0"}));assert.throws(()=>createSbom(app),/runtime_inventory_mismatch/);fs.rmSync(path.join(payload,"node_modules"),{recursive:true});fs.rmSync(path.join(payload,REQUIRED_NOTICES[0]));assert.throws(()=>createSbom(app),/distribution_notice_missing/);}finally{fs.rmSync(app,{recursive:true,force:true});}});
