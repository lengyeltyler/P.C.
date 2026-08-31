"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync, spawn } = require("node:child_process");
const { RESULT_PATH, OBSERVATION_PATH, runWithDurableResult } = require("../../../scripts/ci/longitudinal-evidence.cjs");

const repositoryRoot = path.resolve(__dirname, "../../..");
// A preflight failure must not leave a previous invocation's PASS artifact.
fs.rmSync(path.join(repositoryRoot, RESULT_PATH), { force: true });
fs.rmSync(path.join(repositoryRoot, OBSERVATION_PATH), { force: true });
const companionRoot = path.join(repositoryRoot, "apps/philcore-ios-companion/PhilCoreCompanion");
const visualSystem = fs.readFileSync(path.join(companionRoot, "PhilVisualSystem.swift"), "utf8");
const rootView = fs.readFileSync(path.join(companionRoot, "RootView.swift"), "utf8");
const infoPlist = fs.readFileSync(path.join(companionRoot, "Info.plist"), "utf8");
const fontPath = path.join(companionRoot, "Fonts/PixelifySans-wght.ttf");
const oflPath = path.join(repositoryRoot, "LICENSES/OFL-1.1-Pixelify-Sans.txt");
const characterNoticePath = path.join(repositoryRoot, "LICENSES/PHIL-BRAND-ASSETS.txt");
const characterRoot = path.join(companionRoot, "Characters");
if (
  !fs.statSync(fontPath).isFile()
  || !fs.statSync(oflPath).isFile()
  || !fs.statSync(characterNoticePath).isFile()
  || fs.readdirSync(characterRoot).filter((name) => name.endsWith(".png")).length !== 25
  || !fs.existsSync(path.join(characterRoot, "philenator_bg.png"))
  || fs.readdirSync(characterRoot).some((name) => name.startsWith("pair_"))
  || !visualSystem.includes("PixelifySans-Bold")
  || !visualSystem.includes("PhilCutCornerShape")
  || !visualSystem.includes("PhilBackdrop")
  || !visualSystem.includes("PhilCharacterArtwork")
  || !visualSystem.includes("forResource: \"philenator_bg\"")
  || visualSystem.includes(".saturation(0)")
  || !visualSystem.includes(".saturation(1.08)")
  || !rootView.includes("I'm your security sidekick")
  || !rootView.includes("The Controlled Sepolia Beta uses Ethereum's Sepolia test network and test-only assets")
  || !rootView.includes("Ask Phil")
  || !rootView.includes("ZStack(alignment: .topTrailing)")
  || !/case \.accepted:[\s\S]*routine\.accepted\.scan\.button/u.test(rootView)
  || !rootView.includes('forInfoDictionaryKey: "CFBundleShortVersionString"')
  || !rootView.includes('forInfoDictionaryKey: "CFBundleVersion"')
  || !rootView.includes('forInfoDictionaryKey: "PhilCoreSourceCommit"')
  || !rootView.includes('forInfoDictionaryKey: "PhilCoreSourceTree"')
  || !infoPlist.includes("PixelifySans-wght.ttf")
  || !infoPlist.includes("PhilCoreSourceCommit")
  || !infoPlist.includes("PhilCoreSourceTree")
) {
  process.stderr.write("PhilUI-derived iOS visual resources are incomplete\n");
  process.exit(2);
}
const xcode = "/Applications/Xcode.app/Contents/Developer";
if (!fs.existsSync(path.join(xcode, "usr/bin/xcodebuild"))) {
  process.stderr.write("Step 6C-2 iOS simulator gate requires /Applications/Xcode.app\n");
  process.exit(2);
}
const environment = { ...process.env, DEVELOPER_DIR: xcode };
const listed = spawnSync("/usr/bin/xcrun", ["simctl","list","devices","available","-j"], { encoding: "utf8", env: environment });
if (listed.status !== 0) { process.stderr.write(listed.stderr || "Unable to list iOS simulators\n");process.exit(2); }
const devices = Object.values(JSON.parse(listed.stdout).devices).flat()
  .filter((device) => device.isAvailable && /^iPhone /u.test(device.name));
const selected = devices.find((device) => device.name === "iPhone 17 Pro Max") || devices[0];
if (!selected) { process.stderr.write("No available iPhone simulator found\n");process.exit(2); }
// One backend and one dedicated Simulator for the entire multi-request gate.
// No physical-device command is used, and no existing Simulator data is reset.
async function run() {
  const output=path.join(repositoryRoot,".local/release-validation");fs.mkdirSync(output,{recursive:true});
  const control=path.join(output,"harness-control.json"),resultPath=path.join(output,"longitudinal-result.json");
  if(fs.existsSync(control)) throw new Error("Longitudinal backend control already exists; inspect the prior test process first");
  if(fs.existsSync(resultPath)) fs.unlinkSync(resultPath);
  const runtime=Object.entries(JSON.parse(listed.stdout).devices).find(([,values])=>values.some(v=>v.udid===selected.udid))[0];
  const created=spawnSync("/usr/bin/xcrun",["simctl","create",`PhilCore-longitudinal-${process.pid}`,selected.deviceTypeIdentifier,runtime],{env:environment,encoding:"utf8"});
  if(created.status!==0) throw new Error(created.stderr||"Unable to create isolated Simulator");
  const simulator=created.stdout.trim();
  const log=fs.openSync(path.join(output,"longitudinal-backend.log"),"w");
  const backend=spawn(process.execPath,["apps/philcore-desktop/test/helpers/routine-longitudinal-server.cjs"],{cwd:repositoryRoot,env:environment,stdio:["ignore",log,log]});
  fs.closeSync(log);
  try {
    const deadline=Date.now()+30000;
    while(!fs.existsSync(control) && Date.now()<deadline && backend.exitCode===null) await new Promise(resolve=>setTimeout(resolve,100));
    if(!fs.existsSync(control)||JSON.parse(fs.readFileSync(control,"utf8")).pid!==backend.pid) throw new Error("Longitudinal backend did not become ready");
    const boot=spawnSync("/usr/bin/xcrun",["simctl","boot",simulator],{env:environment,encoding:"utf8"});
    if(boot.status!==0) throw new Error(boot.stderr||"Unable to boot isolated Simulator");
    const result=await new Promise((resolve,reject)=>{
      const child=spawn(path.join(xcode,"usr/bin/xcodebuild"),[
        "test","-quiet","-project","apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj",
        "-scheme","PhilCoreCompanion","-destination",`platform=iOS Simulator,id=${simulator}`,
        "-parallel-testing-enabled","NO","-only-testing:PhilCoreCompanionTests/RoutineAuthorizationTests","CODE_SIGNING_ALLOWED=NO"
      ],{cwd:repositoryRoot,env:environment,stdio:"inherit"});
      child.once("error",reject);child.once("exit",code=>resolve(code??1));
    });
    if(result!==0) return result;
    if(!fs.existsSync(resultPath)||JSON.parse(fs.readFileSync(resultPath,"utf8")).result!=="PASS") throw new Error("Longitudinal evidence missing after successful XCTest result");
    const releaseRoot=path.join(output,"ReleaseDerivedData");
    const release=await new Promise((resolve,reject)=>{
      const child=spawn(path.join(xcode,"usr/bin/xcodebuild"),["build","-quiet","-project","apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj",
        "-scheme","PhilCoreCompanion","-configuration","Release","-sdk","iphonesimulator",
        "-destination","generic/platform=iOS Simulator","-derivedDataPath",releaseRoot,"CODE_SIGNING_ALLOWED=NO"],
        {cwd:repositoryRoot,env:environment,stdio:"inherit"});child.once("error",reject);child.once("exit",code=>resolve(code??1));
    });
    if(release!==0) return release;
    const binary=path.join(releaseRoot,"Build/Products/Release-iphonesimulator/PhilCoreCompanion.app/PhilCoreCompanion");
    const strings=spawnSync("/usr/bin/strings",[binary],{encoding:"utf8",maxBuffer:16*1024*1024});
    if(strings.status!==0) throw new Error("Unable to inspect Release executable");
    for(const token of ["--philcore-ui-test-state","PHILCORE_UI_TEST_STATE","SyntheticRoutineSigner","RecordingLongitudinalTransport","LongitudinalClock"])
      if(strings.stdout.includes(token)) throw new Error(`Release fixture marker present: ${token}`);
    fs.writeFileSync(path.join(output,"release-fixture-exclusion.json"),JSON.stringify({result:"PASS",configuration:"Release",platform:"iOS Simulator",signed:false,physicalRelease:false}));
    console.log("RELEASE-MODE FIXTURE EXCLUSION: PASS (Simulator build, not a signed release)");return 0;
  } finally {
    backend.kill("SIGTERM");
    await new Promise(resolve=>{if(backend.exitCode!==null)resolve();else {backend.once("exit",resolve);setTimeout(resolve,5000);}});
    if(fs.existsSync(control)&&JSON.parse(fs.readFileSync(control,"utf8")).pid===backend.pid) fs.unlinkSync(control);
    // Delete only the Simulator created by this invocation.
    spawnSync("/usr/bin/xcrun",["simctl","shutdown",simulator],{env:environment,stdio:"ignore"});
    spawnSync("/usr/bin/xcrun",["simctl","delete",simulator],{env:environment,stdio:"ignore"});
  }
}
runWithDurableResult({root:repositoryRoot,run})
  .then(code=>{
    if(code===0) console.log("LONGITUDINAL MULTI-REQUEST TEST: PASS");
    process.exitCode=code;
  }).catch(error=>{console.error(error.message);process.exitCode=1;});
