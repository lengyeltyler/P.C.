"use strict";
const {spawnSync}=require("node:child_process");
const path=require("node:path"),fs=require("node:fs");
const root=path.resolve(__dirname,"../.."),output=path.join(root,".local/release-validation");
fs.mkdirSync(output,{recursive:true});
const unit=["phil-v1-step6c-wire","phil-v1-step6c-records","phil-v1-step6c-journal","phil-v1-step6c-ios-synthetic",
  "phil-v1-step6c2-transport","phil-v1-step6c2-enrollment","ci-classification"].map(name=>`test/unit/${name}.test.cjs`);
const steps=[
  ["typecheck","npm",["run","typecheck"]],
  ["classification",process.execPath,["scripts/ci/validate-classification.cjs"]],
  ["compile","npx",["hardhat","compile"]],
  ["security-invariants","npx",["hardhat","test","--no-compile",...unit]],
  ["preload","npm",["run","desktop:bundle-preload"]],
  // The coordinator is now executed by this lane, exactly once in this gate.
  ["desktop",process.execPath,["scripts/ci/run-lane.cjs","desktop"]],
  ["ios-longitudinal-and-release",process.execPath,["apps/philcore-ios-companion/scripts/test-routine-authorization-simulator.cjs"]]
];
const results=[];
for(const [name,command,args] of steps){
  console.log(`PRE-PHYSICAL: ${name}`);
  const log=fs.openSync(path.join(output,`gate-${name}.log`),"w");
  const result=spawnSync(command,args,{cwd:root,env:process.env,stdio:["ignore",log,log]});fs.closeSync(log);
  results.push({name,status:result.status??1});
  if(result.status!==0){fs.writeFileSync(path.join(output,"prephysical-gate.json"),JSON.stringify({verdict:"FAIL",results},null,2));
    console.error(`AUTOMATED PRE-PHYSICAL RELEASE GATE: FAIL (${name})`);process.exit(1);}
}
fs.writeFileSync(path.join(output,"prephysical-gate.json"),JSON.stringify({verdict:"PASS",physicalRetestReady:false,results},null,2));
console.log("AUTOMATED PRE-PHYSICAL RELEASE GATE: PASS");
console.log("READY FOR PHYSICAL RETEST RIGHT NOW: NO (new frozen artifacts and owner acceptance still required)");
