#!/usr/bin/env node
"use strict";
// Reuse existing tests outside the app. The app never contains a test runner,
// synthetic credentials, or a launch switch that selects test authentication.
const fs=require("node:fs"),path=require("node:path"),os=require("node:os"),assert=require("node:assert/strict"),{spawnSync}=require("node:child_process");
const release=require("./release-utils.cjs"),{directorySha256}=require("./release-artifact-lineage.cjs");
const app=process.env.PHILCORE_DESKTOP_TEST_APP_PATH||release.appBundlePath,payload=path.join(app,"Contents/Resources/app"),before=directorySha256(app),stage=fs.mkdtempSync(path.join(os.tmpdir(),"phil-packaged-runtime-"));
try{
 fs.cpSync(payload,stage,{recursive:true,mode:fs.constants.COPYFILE_FICLONE,verbatimSymlinks:true});fs.chmodSync(stage,fs.statSync(payload).mode & 0o7777);assert.equal(directorySha256(stage),directorySha256(payload));
 const nodeTests=["desktop-routine-authorization-product-host.test.cjs","desktop-routine-authorization-storage.test.cjs","desktop-routine-authorization-ipc.test.cjs","desktop-routine-authorization-ui-state.test.cjs"];
 const mochaTests=["desktop-routine-authorization-local-product-runtime.test.cjs","desktop-routine-authorization-product-flow.test.cjs"];
 for(const f of[...nodeTests,...mochaTests]){const dest=path.join(stage,"apps/philcore-desktop/test",f);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(release.repoRoot,"apps/philcore-desktop/test",f),dest);}
 for(const file of ["apps/philcore-desktop/scripts/package-local.cjs","scripts/release/routine-acceptance-baseline.cjs","scripts/release/routine-acceptance-procedure.cjs","apps/philcore-desktop/scripts/release-artifact-lineage.cjs","apps/philcore-desktop/build/release-profiles.json"]){const source=path.join(release.repoRoot,file);if(!fs.existsSync(source))continue;const dest=path.join(stage,file);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(source,dest);}
 const env={...process.env,HARDHAT_CONFIG:path.join(stage,"hardhat.phil-v1-step6c-product.config.cjs")};delete env.NODE_PATH;
 for(const file of nodeTests){const r=spawnSync(process.execPath,[path.join(stage,"apps/philcore-desktop/test",file)],{cwd:stage,env,stdio:"inherit"});assert.equal(r.status,0,file);}
 for(const file of mochaTests){const r=spawnSync(process.execPath,["-e","const Mocha=require(process.argv[1]);const m=new Mocha({timeout:120000});m.addFile(process.argv[2]);m.run(f=>process.exitCode=f?1:0)",path.join(release.repoRoot,"node_modules/mocha"),path.join(stage,"apps/philcore-desktop/test",file)],{cwd:stage,env,stdio:"inherit"});assert.equal(r.status,0,file);}
 assert.equal(directorySha256(app),before);console.log(JSON.stringify({status:"passed",source:"exact_packaged_modules_and_dependencies",existingRegressionFiles:6,appBundleSha256:before,releaseArtifactUnchanged:true,physicalAcceptancePerformed:false,publicNetworkMutation:false}));
}finally{fs.rmSync(stage,{recursive:true,force:true});}
