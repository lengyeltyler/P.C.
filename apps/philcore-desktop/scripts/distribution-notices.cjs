"use strict";
const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const hash=(b)=>crypto.createHash("sha256").update(b).digest("hex");
const REQUIRED_NOTICES=Object.freeze(["LICENSE","THIRD_PARTY_NOTICES.md","LICENSES/Electron-MIT.txt","LICENSES/Mantle-LICENSE.txt","LICENSES/ReactiveObjC-LICENSE.txt","LICENSES/Squirrel.Mac-LICENSE.txt","LICENSES/Chromium-Third-Party-Notices.html","LICENSES/GPL-3.0-only.txt","LICENSES/Apache-2.0.txt","LICENSES/Noir-Nargo-MIT.txt","LICENSES/Barretenberg-Apache-2.0.txt","LICENSES/OFL-1.1-Pixelify-Sans.txt","LICENSES/PHIL-BRAND-ASSETS.txt"]);
function copyDependencyNotices(repoRoot,payload,selection){
 const records=[];
 for(const pkg of selection.packages){
  const source=path.join(repoRoot,pkg.path),files=fs.readdirSync(source).filter(f=>/^(licen[cs]e|copying|notice)/i.test(f)&&fs.statSync(path.join(source,f)).isFile());
  let candidates=files.map(f=>path.join(source,f));
  if(!candidates.length){
   const readme=fs.readdirSync(source).find(f=>/^readme/i.test(f));
   if(readme && /Permission is hereby granted|Redistribution and use/i.test(fs.readFileSync(path.join(source,readme),"utf8")))candidates=[path.join(source,readme)];
   else {
    const fallback={"@account-abstraction/contracts":"LICENSES/Account-Abstraction-GPL-3.0.txt","@openzeppelin/contracts":`LICENSES/OpenZeppelin-${pkg.version.startsWith("5.")?"5.6.1":"3.4.2"}-MIT.txt`,"@ethersproject/logger":"LICENSES/Ethers-5.8.0-MIT.txt","@esbuild/darwin-arm64":"node_modules/esbuild/LICENSE.md","@nomicfoundation/edr-darwin-arm64":"node_modules/@nomicfoundation/edr/LICENSE"}[pkg.name];
    if(!fallback)throw Error(`dependency_notice_missing:${pkg.name}@${pkg.version}`);
    candidates=[path.join(repoRoot,fallback)];
   }
  }
  for(const file of candidates){const target=`LICENSES/npm/${pkg.path.replaceAll("/","_")}/${path.basename(file)}`;const bytes=fs.readFileSync(file);fs.mkdirSync(path.dirname(path.join(payload,target)),{recursive:true});fs.writeFileSync(path.join(payload,target),bytes);records.push({packagePath:pkg.path,name:pkg.name,version:pkg.version,declaredLicense:pkg.license,source:path.relative(repoRoot,file),notice:target,sha256:hash(bytes)});}
 }
 fs.writeFileSync(path.join(payload,"LICENSES/npm-notice-index.json"),JSON.stringify(records,null,2)+"\n");return records;
}
function verifyNotices(payload){for(const f of REQUIRED_NOTICES)if(!fs.existsSync(path.join(payload,f))||fs.statSync(path.join(payload,f)).size===0)throw Error(`distribution_notice_missing:${f}`);const index=JSON.parse(fs.readFileSync(path.join(payload,"LICENSES/npm-notice-index.json")));for(const item of index)if(hash(fs.readFileSync(path.join(payload,item.notice)))!==item.sha256)throw Error(`distribution_notice_hash_mismatch:${item.notice}`);return index;}
module.exports={REQUIRED_NOTICES,copyDependencyNotices,verifyNotices};
