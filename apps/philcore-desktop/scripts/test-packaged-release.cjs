#!/usr/bin/env node
"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),os=require("node:os"),{spawnSync}=require("node:child_process");
const release=require("./release-utils.cjs"),{createSbom,verifySbom}=require("./sbom.cjs");
const app=process.env.PHILCORE_DESKTOP_TEST_APP_PATH||release.appBundlePath,exe=path.join(app,"Contents/MacOS",release.executableName),payload=path.join(app,"Contents/Resources/app");
const scratch=fs.mkdtempSync(path.join(os.tmpdir(),"phil-release-selector-"));
try{
 const sbom=createSbom(app);assert(verifySbom(app,sbom));
 for(const file of["main.cjs","runtime-host.cjs","macos-user-presence.cjs"]){const source=fs.readFileSync(path.join(payload,"apps/philcore-desktop/src/main",file),"utf8");assert.doesNotMatch(source,/createFixturePlatformKeyAdapter|createFixtureMacOsUserPresenceProvider|philcore-desktop-e2e-platform-key|philcore-desktop-fixture-platform-key|philcore-o41-e2e-safe-storage-adapter/);}
 const clean={...process.env};for(const name of Object.keys(clean))if(/^PHILCORE_(?:DESKTOP_(?:E2E|DEV)|UI_TEST_|MACOS_USER_PRESENCE_HELPER)/.test(name))delete clean[name];delete clean.ELECTRON_RUN_AS_NODE;
 const cases=[...['PHILCORE_DESKTOP_E2E','PHILCORE_DESKTOP_E2E_UI_UNLOCK_FLOW','PHILCORE_DESKTOP_DEV','PHILCORE_UI_TEST_STATE','PHILCORE_MACOS_USER_PRESENCE_HELPER'].map(name=>({name,env:{[name]:"1"},args:[]})),...['--philcore-e2e','--fixture','--test-auth'].map(arg=>({name:arg,env:{},args:[arg]}))];
 for(const c of cases){const data=path.join(scratch,c.name.replaceAll('-','_'));const p=spawnSync(exe,c.args,{encoding:"utf8",env:{...clean,...c.env,PHILCORE_DESKTOP_USER_DATA_DIR:data},timeout:15000});assert.equal(p.status,78,`${c.name}: ${p.stderr}`);assert.match(p.stderr,/PHILCORE_RELEASE_TEST_SELECTOR_REJECTED/);assert(!fs.existsSync(data),"selector must stop before user storage initialization");}
 console.log(JSON.stringify({status:"passed",releaseFixtureAuthenticationPathAvailable:false,binarySelectorRejections:cases.length,exactSbomVerified:true,appBundleSha256:sbom.appBundleSha256,runtimePackages:sbom.packages.length,physicalAcceptancePerformed:false,publicNetworkMutation:false}));
}finally{fs.rmSync(scratch,{recursive:true,force:true});}
