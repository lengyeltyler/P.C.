#!/usr/bin/env node
"use strict";
const {spawnSync}=require("node:child_process"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const root=path.resolve(__dirname,"../.."),output=process.env.PHILCORE_NPM_AUDIT_REPORT||path.join(root,"config/security/philcore-npm-audit-report.json");
const policy=JSON.parse(fs.readFileSync(path.join(root,"config/security/desktop-runtime-advisory-disposition.json")));
const hash=(b)=>crypto.createHash("sha256").update(b).digest("hex");
const lock=fs.readFileSync(path.join(root,"package-lock.json"));
if(hash(lock)!==policy.packageLockSha256)throw Error("dependency_disposition_lockfile_changed");
function audit(args){const p=spawnSync("npm",["audit",...args,"--json"],{cwd:root,encoding:"utf8",maxBuffer:16*1024*1024});if(![0,1].includes(p.status))throw Error("npm_audit_failed");const value=JSON.parse(p.stdout);if(value.error||!value.metadata||!value.vulnerabilities)throw Error("npm_audit_incomplete");return value;}
const full=audit([]),production=audit(["--omit=dev"]);
const app=process.env.PHILCORE_DESKTOP_AUDIT_APP;
let packages,artifactSha256=null;
if(app){const sbom=require("../../apps/philcore-desktop/scripts/sbom.cjs").createSbom(app);packages=sbom.packages;artifactSha256=sbom.appBundleSha256;}
else packages=require("../../apps/philcore-desktop/scripts/runtime-package-inventory.cjs").runtimePackageSelection(root).packages;
const inventory=Object.entries(full.vulnerabilities).map(([name,v])=>{
 const reviewed=policy.packages[name],direct=v.via.filter(x=>typeof x==='object');
 const currentIds=direct.map(x=>x.url.split('/').pop()).sort();
 const known=Boolean(reviewed)&&JSON.stringify(currentIds)===JSON.stringify(reviewed.advisoryIds.slice().sort());
 const shipped=(v.nodes||[]).filter(node=>packages.some(p=>p.path===node));
 const validVersions=known&&shipped.every(node=>reviewed.reviewedVersions.includes(packages.find(p=>p.path===node).version));
 const reviewedUnreachable=known&&validVersions&&reviewed.vulnerableSinkReachable===false;
 return{package:name,severity:v.severity,nodes:v.nodes,shippedPaths:shipped,shipped:shipped.length>0,
  runtimePackageReachable:shipped.length>0,vulnerableSinkReachable:shipped.length===0?false:reviewedUnreachable?false:"UNREVIEWED",
  releaseBlocker:!known||!validVersions||(!reviewedUnreachable&&shipped.length>0),
  fixedVersion:reviewed?.fixedVersion||"UNREVIEWED",rationale:shipped.length?reviewed?.runtimeRationale:"Excluded from the actual release selection; remains a pinned trusted build/test dependency only.",
  advisories:direct.map(x=>({id:x.url.split('/').pop(),url:x.url,title:x.title,severity:x.severity,range:x.range})),viaPackages:v.via.filter(x=>typeof x==='string'),npmFixAvailable:v.fixAvailable};
});
const report={schemaVersion:2,generatedAt:new Date().toISOString(),status:inventory.some(x=>x.releaseBlocker)?"FAIL":"PASS",packageLockSha256:hash(lock),actualArtifactVerified:Boolean(app),artifactSha256,scope:app?"actual_shipped_application":"proposed_package_selection_not_artifact_acceptance",productionAudit:production.metadata,fullAudit:full.metadata,runtimePackages:packages.length,inventory,productionRuntimeHighCriticalExploitableFindings:inventory.filter(x=>x.shipped&&x.releaseBlocker&&['high','critical'].includes(x.severity)).length,publicNetworkMutation:false};
fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify(report,null,2)+"\n");console.log(JSON.stringify({status:report.status,output,actualArtifactVerified:report.actualArtifactVerified,blockers:inventory.filter(x=>x.releaseBlocker).map(x=>x.package)}));if(report.status!=="PASS")process.exitCode=1;
