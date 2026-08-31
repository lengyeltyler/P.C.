"use strict";
const fs=require("node:fs"),path=require("node:path");
const {execFileSync}=require("node:child_process");
const {directorySha256}=require("../../apps/philcore-desktop/scripts/release-artifact-lineage.cjs");

// Captures are observations, never authorization. Missing/stale/fixture evidence
// fails closed. This checker neither starts requests nor contacts a device.
function validateBaseline({desktop,ios,freeze,now=Math.floor(Date.now()/1000),verifyArtifacts=true}) {
  const errors=[];const check=(value,code)=>{if(!value)errors.push(code);};
  check(freeze?.schemaVersion===1,"freeze_schema");
  check(freeze?.configuration==="Release"&&freeze?.fixtureInjection===false,"release_configuration");
  check(ios?.simulator===false&&ios?.secureEnclaveBacked===true&&ios?.userPresenceRequired===true,"ios_physical_key_policy");
  check(/^[0-9a-f]{40}$/.test(freeze?.sourceCommit||""),"freeze_commit");
  check(/^[0-9a-f]{40}$/.test(freeze?.sourceTree||""),"freeze_tree");
  for(const [name,value] of [["desktop",desktop],["ios",ios]]) {
    check(value?.schemaVersion===1,`${name}_schema`);
    const timestamp=Number(value?.observedAt);
    check(Number.isSafeInteger(timestamp)&&timestamp<=now+5&&timestamp>=now-30,`${name}_stale_capture`);
    check(value?.pendingRequestCount===0,`${name}_pending_request`);
    check(value?.pairingState==="enrolled",`${name}_pairing_unknown`);
    check(value?.sourceCommit===freeze?.sourceCommit&&value?.sourceTree===freeze?.sourceTree,`${name}_source_identity`);
  }
  check(desktop?.activeRequestId===null&&desktop?.unresolvedSubmissionCount===0,"desktop_active_or_unknown");
  check(desktop?.presentationRequestId===null&&desktop?.qrVisible===false,"desktop_stale_presentation");
  check(["not_started","idle","ready"].includes(desktop?.presentationState),"desktop_not_ready");
  if(desktop?.presentationState==="not_started") {
    // The frozen renderer uses not_started before its first request, including
    // while begin is pending or after begin fails. Require a read-only snapshot
    // of its clean initial fields; the state label alone grants no readiness.
    const initial=desktop.preRequest;
    check(initial?.documentReadyState==="complete"&&initial?.runtimeInitialized===true,"desktop_not_started_runtime_unready");
    // Poll generation starts at zero and increments whenever polling starts or
    // stops. Together with begin=false this excludes polling and the slow-begin
    // timer without resetting either in the running product.
    check(initial?.beginInFlight===false&&initial?.pollGeneration===0,"desktop_not_started_request_activity");
    check(initial?.expiresAt===null&&initial?.qrPayload===null&&initial?.comparisonFingerprint===null
      &&initial?.terminalReason===null,"desktop_not_started_stale_presentation");
    check(initial?.lastAttempt===null&&initial?.preflightCount===0&&initial?.completionAttemptCount===0
      &&initial?.lastFailureReason===null&&initial?.notice==="","desktop_not_started_retry_state");
  }
  check(desktop?.expectedNonce==="0","desktop_nonce_not_fresh_runtime");
  check(ios?.phase==="idle","ios_not_idle");
  check(/^[1-9][0-9]*$/.test(ios?.pairingGeneration||"")&&ios?.pairingGeneration===desktop?.pairingGeneration,"pairing_generation");
  check(/^0x[0-9a-f]{64}$/.test(ios?.pairingFingerprint||"")&&ios?.pairingFingerprint===desktop?.pairingFingerprint,"pairing_identity");
  check(/^[1-9][0-9]*$/.test(freeze?.ios?.build||"")&&ios?.build===freeze?.ios?.build,"ios_build_identity");
  for(const name of ["desktop","ios"]) {
    const artifact=freeze?.[name];
    check(typeof artifact?.appPath==="string"&&path.isAbsolute(artifact.appPath),`${name}_artifact_path`);
    check(/^[0-9a-f]{64}$/.test(artifact?.directorySha256||""),`${name}_artifact_digest`);
    if(verifyArtifacts) {
      try{check(directorySha256(artifact.appPath)===artifact.directorySha256,`${name}_artifact_changed`);}
      catch{errors.push(`${name}_artifact_unreadable`);}
    }
  }
  // Bind the frozen artifacts to runtime evidence, not just editable build labels.
  check(Number.isSafeInteger(desktop?.desktopProcessId)&&desktop.desktopProcessId>0,"desktop_process_identity");
  const installed=ios?.installedArtifactReadback;
  check(installed?.source==="installed-device-bundle-readback"&&typeof installed?.deviceIdentifier==="string"&&installed.deviceIdentifier.length>0
    &&installed.deviceIdentifier===ios?.deviceIdentifier,"ios_installed_readback_provenance");
  check(typeof installed?.appPath==="string"&&path.isAbsolute(installed.appPath),"ios_installed_readback_path");
  const readbackAt=Number(installed?.observedAt);
  check(Number.isSafeInteger(readbackAt)&&readbackAt>=now-30&&readbackAt<=now+5,"ios_installed_readback_stale");
  if(verifyArtifacts) {
    try {
      if(process.platform!=="darwin"||!Number.isSafeInteger(desktop?.desktopProcessId)||desktop.desktopProcessId<1) throw new Error("invalid process");
      const executable=execFileSync("/bin/ps",["-p",String(desktop.desktopProcessId),"-o","comm="],{encoding:"utf8"}).trim();
      const suffix=executable.indexOf(".app/Contents/MacOS/");
      if(suffix<0) throw new Error("not an application process");
      const running=fs.realpathSync(executable.slice(0,suffix+4));
      check(running===fs.realpathSync(freeze.desktop.appPath),"desktop_running_artifact_path");
      check(directorySha256(running)===freeze.desktop.directorySha256,"desktop_running_artifact_changed");
    } catch {errors.push("desktop_running_artifact_unverified");}
    try {
      check(fs.realpathSync(installed.appPath)!==fs.realpathSync(freeze.ios.appPath),"ios_readback_is_frozen_source");
      check(directorySha256(installed.appPath)===freeze.ios.directorySha256,"ios_installed_artifact_changed");
    } catch {errors.push("ios_installed_artifact_unverified");}
  }
  return Object.freeze({verifiedAt:now,verdict:errors.length?"PHYSICAL ACCEPTANCE BASELINE: FAIL":verifyArtifacts?"PHYSICAL ACCEPTANCE BASELINE: PASS":"BASELINE SCHEMA ONLY: PASS",errors});
}
if(require.main===module) {
  try {
    if(process.argv.length!==4) throw new Error("Usage: node scripts/release/routine-acceptance-baseline.cjs <capture.json> <freeze.json>");
    const capture=JSON.parse(fs.readFileSync(process.argv[2],"utf8")),freeze=JSON.parse(fs.readFileSync(process.argv[3],"utf8"));
    const result=validateBaseline({...capture,freeze,verifyArtifacts:true,now:Math.floor(Date.now()/1000)});
    console.log(JSON.stringify(result,null,2));if(result.errors.length)process.exitCode=1;
  } catch {console.error("PHYSICAL ACCEPTANCE BASELINE: FAIL (missing or invalid evidence)");process.exitCode=1;}
}
module.exports={validateBaseline};
