"use strict";

function createRoutineAuthorizationProductHost(options) {
  if (!options||Object.keys(options).sort().join(",")!=="authorizationHostFactory,deleteProfileAtomically,enrollmentHost") throw new TypeError("routine product options are invalid");
  if (typeof options.authorizationHostFactory!=="function"||typeof options.deleteProfileAtomically!=="function"||typeof options.enrollmentHost?.start!=="function") throw new TypeError("routine product dependencies are invalid");
  let authorizationHost=null,authorizationGeneration=null,started=false,deleting=false,deleted=false,lifecycleTail=Promise.resolve();
  const routes=new Map();

  function exclusive(operation) {
    const result=lifecycleTail.then(operation);lifecycleTail=result.catch(()=>{});return result;
  }
  function productUnavailable() {
    const code=deleted?"ROUTINE_PROFILE_DELETED":"ROUTINE_PRODUCT_NOT_INITIALIZED";
    throw Object.assign(new Error(code),{code});
  }
  async function ensureAuthorizationHost() {
    const enrolled=await options.enrollmentHost.activeEnrollment();
    if (authorizationHost&&authorizationGeneration===enrolled.record.generation) return authorizationHost;
    if (authorizationHost) {
      authorizationHost.assertDisposableProfileDeletionSafe();await authorizationHost.stopListener();
      authorizationHost.disposeForDeviceReplacement();authorizationHost=null;authorizationGeneration=null;
    }
    const host=await options.authorizationHostFactory(enrolled);
    try { await host.startListener();await host.restoreAllRoutineAuthorizations(); }
    catch (error) { try { await host.stopListener(); } catch {}try { host.disposeForDeviceReplacement(); } catch {}throw error; }
    authorizationHost=host;authorizationGeneration=enrolled.record.generation;return host;
  }
  async function initializeUnlocked() {
    if (deleted) productUnavailable();if (started) return;
    await options.enrollmentHost.start();started=true;
    try { await ensureAuthorizationHost(); }
    catch (error) {
      if (error?.code==="ROUTINE_ENROLLMENT_NOT_FOUND") return;
      await options.enrollmentHost.stop();started=false;throw error;
    }
  }
  async function beginUnlocked(intent) {
    if (!started||deleting||deleted) productUnavailable();
    if (intent?.action==="replace_routine_device") {
      let enrollmentMode="replacement";
      try { await options.enrollmentHost.activeEnrollment(); }
      catch (error) {
        if (error?.code!=="ROUTINE_ENROLLMENT_NOT_FOUND") throw error;
        enrollmentMode="initial";
      }
      if (enrollmentMode==="replacement") authorizationHost?.assertDisposableProfileDeletionSafe();
      const result=await options.enrollmentHost.beginEnrollment();routes.set(result.requestId,"enrollment");return Object.freeze({...result,enrollmentMode});
    }
    let host;try { host=await ensureAuthorizationHost(); }
    catch (error) {
      if (error?.code!=="ROUTINE_ENROLLMENT_NOT_FOUND") throw error;
      const result=await options.enrollmentHost.beginEnrollment();routes.set(result.requestId,"enrollment");return Object.freeze({...result,enrollmentMode:"initial"});
    }
    const result=await host.beginRoutineAuthorization(intent);routes.set(result.requestId,"authorization");return result;
  }
  async function statusUnlocked(requestId) {
    if (deleting||deleted) throw Object.assign(new Error("ROUTINE_PROFILE_DELETION_COMMITTED"),{code:"ROUTINE_PROFILE_DELETION_COMMITTED"});
    if (routes.get(String(requestId).toLowerCase())==="enrollment") return options.enrollmentHost.status(requestId);
    if (!authorizationHost) throw Object.assign(new Error("ROUTINE_AUTHORIZATION_PRODUCT_RUNTIME_UNAVAILABLE"),{code:"ROUTINE_AUTHORIZATION_PRODUCT_RUNTIME_UNAVAILABLE"});
    return authorizationHost.getRoutineAuthorizationStatus(requestId);
  }
  async function baselineUnlocked() {
    if(!started||deleting||deleted) productUnavailable();
    const enrollment=await options.enrollmentHost.activeEnrollment();
    const host=await ensureAuthorizationHost();
    const result=await host.acceptanceBaseline();
    return Object.freeze({...result,desktopProcessId:process.pid,pairingState:"enrolled",pairingGeneration:enrollment.record.generation,
      pairingFingerprint:enrollment.record.publicKeyFingerprint});
  }
  async function cancelUnlocked(requestId) {
    if (deleting||deleted) throw Object.assign(new Error("ROUTINE_PROFILE_DELETION_COMMITTED"),{code:"ROUTINE_PROFILE_DELETION_COMMITTED"});
    if (routes.get(String(requestId).toLowerCase())==="enrollment") return options.enrollmentHost.cancel(requestId);
    if (!authorizationHost) throw Object.assign(new Error("ROUTINE_AUTHORIZATION_PRODUCT_RUNTIME_UNAVAILABLE"),{code:"ROUTINE_AUTHORIZATION_PRODUCT_RUNTIME_UNAVAILABLE"});
    return authorizationHost.cancelRoutineAuthorization(requestId);
  }
  async function deleteUnlocked() {
    if (!started||deleting||deleted) productUnavailable();
    options.enrollmentHost.assertDeletionSafe();authorizationHost?.assertDisposableProfileDeletionSafe();deleting=true;
    let result;try { result=await options.deleteProfileAtomically(); }
    catch (error) { if (error?.profileDeletionCommitted!==true) deleting=false;throw error; }
    if (authorizationHost) { await authorizationHost.stopListener();authorizationHost.disposeAfterDurableDeletion();authorizationHost=null;authorizationGeneration=null; }
    options.enrollmentHost.disposeAfterDurableDeletion();routes.clear();deleted=true;started=false;return result;
  }
  async function stopUnlocked() {
    await authorizationHost?.stopListener();authorizationHost=null;authorizationGeneration=null;
    await options.enrollmentHost.stop();started=false;
  }
  return Object.freeze({
    initialize:()=>exclusive(initializeUnlocked),
    acceptanceBaseline:()=>exclusive(baselineUnlocked),
    beginRoutineAuthorization:(intent)=>exclusive(()=>beginUnlocked(intent)),
    getRoutineAuthorizationStatus:(requestId)=>exclusive(()=>statusUnlocked(requestId)),
    cancelRoutineAuthorization:(requestId)=>exclusive(()=>cancelUnlocked(requestId)),
    deleteDisposableProfile:()=>exclusive(deleteUnlocked),
    stop:()=>exclusive(stopUnlocked)
  });
}

module.exports={createRoutineAuthorizationProductHost};
