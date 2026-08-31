"use strict";
const assert=require("node:assert/strict");
const test=require("node:test");
const { createRoutineAuthorizationProductHost }=require("../src/main/routine-authorization-product-host.cjs");

test("product host orders V2 enrollment before protected runtime provisioning without adding renderer authority",async()=>{
  const calls=[];let enrolled=false,enrollmentState="waiting",enrollmentGeneration="1";
  const enrollmentHost={
    async start(){calls.push("enrollment-start");},async stop(){calls.push("enrollment-stop");},
    async activeEnrollment(){if(!enrolled)throw Object.assign(new Error("missing"),{code:"ROUTINE_ENROLLMENT_NOT_FOUND"});return {record:{deviceId:`enrolled-${enrollmentGeneration}`,generation:enrollmentGeneration},evidenceClass:"synthetic_source_test"};},
    async beginEnrollment(){calls.push("enrollment-begin");return {requestId:`0x${"11".repeat(32)}`,qrPayload:"phil-step6c-routine-enrollment-v2:x",status:"enrollment_waiting"};},
    status(requestId){return {requestId,state:enrollmentState};},cancel(){enrollmentState="cancelled";return "cancelled";},
    assertDeletionSafe(){return true;},disposeAfterDurableDeletion(){calls.push("enrollment-dispose");}
  };
  const authorizationHost={async startListener(){calls.push("authorization-listener-start");},async restoreAllRoutineAuthorizations(){calls.push("authorization-restore");return[];},
    async beginRoutineAuthorization(){calls.push("authorization-begin");return {requestId:`0x${"22".repeat(32)}`,qrPayload:"phil-step6c-routine-v1:x",status:"transport_waiting"};},
    getRoutineAuthorizationStatus(requestId){return {requestId,state:2};},async cancelRoutineAuthorization(){return"cancelled";},
    assertDisposableProfileDeletionSafe(){return true;},
    disposeForDeviceReplacement(){calls.push("authorization-replace-dispose");},disposeAfterDurableDeletion(){calls.push("authorization-delete-dispose");},async stopListener(){calls.push("authorization-listener-stop");}};
  const product=createRoutineAuthorizationProductHost({enrollmentHost,deleteProfileAtomically:async()=>{calls.push("atomic-delete");return{status:"deleted",identityOrRecoveryStateTouched:false};},authorizationHostFactory:async(value)=>{calls.push(`runtime:${value.record.deviceId}`);return authorizationHost;}});
  await product.initialize();const enrollment=await product.beginRoutineAuthorization({action:"record_harmless_value"});
  assert.equal(enrollment.status,"enrollment_waiting");assert.equal(enrollment.enrollmentMode,"initial");assert.equal((await product.getRoutineAuthorizationStatus(enrollment.requestId)).state,"waiting");
  enrolled=true;enrollmentState="completed";
  const authorization=await product.beginRoutineAuthorization({action:"record_harmless_value"});assert.equal(authorization.status,"transport_waiting");
  assert.equal((await product.getRoutineAuthorizationStatus(authorization.requestId)).state,2);
  enrollmentState="waiting";const replacement=await product.beginRoutineAuthorization({action:"replace_routine_device"});assert.equal(replacement.status,"enrollment_waiting");assert.equal(replacement.enrollmentMode,"replacement");
  enrollmentGeneration="2";enrollmentState="completed";await product.beginRoutineAuthorization({action:"record_harmless_value"});
  await product.deleteDisposableProfile();await product.stop();
  assert.deepEqual(calls,["enrollment-start","enrollment-begin","runtime:enrolled-1","authorization-listener-start","authorization-restore","authorization-begin",
    "enrollment-begin","authorization-listener-stop","authorization-replace-dispose","runtime:enrolled-2","authorization-listener-start","authorization-restore","authorization-begin",
    "atomic-delete","authorization-listener-stop","authorization-delete-dispose","enrollment-dispose","enrollment-stop"]);
});

test("product lifecycle serializes in-flight initialization before committed deletion",async()=>{
  const calls=[];let releaseFactory,enteredFactory;
  const factoryEntered=new Promise((resolve)=>{enteredFactory=resolve;}),factoryRelease=new Promise((resolve)=>{releaseFactory=resolve;});
  const enrollmentHost={async start(){calls.push("enrollment-start");},async stop(){calls.push("enrollment-stop");},
    async activeEnrollment(){return{record:{deviceId:"enrolled-1",generation:"1"},evidenceClass:"synthetic_source_test"};},
    async beginEnrollment(){throw new Error("unexpected enrollment");},status(){},cancel(){},assertDeletionSafe(){calls.push("enrollment-delete-safe");return true;},
    disposeAfterDurableDeletion(){calls.push("enrollment-dispose");}};
  const authorizationHost={async startListener(){calls.push("authorization-start");},async restoreAllRoutineAuthorizations(){calls.push("authorization-restore");return[];},
    async beginRoutineAuthorization(){calls.push("authorization-begin");return{requestId:`0x${"22".repeat(32)}`};},assertDisposableProfileDeletionSafe(){calls.push("authorization-delete-safe");return true;},
    async stopListener(){calls.push("authorization-stop");},disposeForDeviceReplacement(){},disposeAfterDurableDeletion(){calls.push("authorization-dispose");}};
  const product=createRoutineAuthorizationProductHost({enrollmentHost,authorizationHostFactory:async()=>{calls.push("factory-enter");enteredFactory();await factoryRelease;calls.push("factory-release");return authorizationHost;},
    deleteProfileAtomically:async()=>{calls.push("delete-committed");return{status:"deleted",identityOrRecoveryStateTouched:false};}});
  const initialization=product.initialize();await factoryEntered;const deletion=product.deleteDisposableProfile();
  releaseFactory();await initialization;await deletion;
  await assert.rejects(product.beginRoutineAuthorization({action:"record_harmless_value"}),(error)=>error.code==="ROUTINE_PROFILE_DELETED");
  await product.stop();
  assert.deepEqual(calls,["enrollment-start","factory-enter","factory-release","authorization-start","authorization-restore","enrollment-delete-safe",
    "authorization-delete-safe","delete-committed","authorization-stop","authorization-dispose","enrollment-dispose","enrollment-stop"]);
});

test("product host propagates runtime failures and distinguishes retryable from committed deletion failures",async()=>{
  let enrollmentBegins=0;
  const enrolledHost={async start(){},async stop(){},async activeEnrollment(){return{record:{deviceId:"enrolled-1",generation:"1"},evidenceClass:"synthetic_source_test"};},
    async beginEnrollment(){enrollmentBegins+=1;return{requestId:`0x${"11".repeat(32)}`};},status(){},cancel(){},assertDeletionSafe(){return true;},disposeAfterDurableDeletion(){}};
  const runtimeFailure=Object.assign(new Error("runtime unavailable"),{code:"ROUTINE_RUNTIME_PROVISIONING_FAILED"});
  const runtimeProduct=createRoutineAuthorizationProductHost({enrollmentHost:enrolledHost,authorizationHostFactory:async()=>{throw runtimeFailure;},deleteProfileAtomically:async()=>({})});
  await assert.rejects(runtimeProduct.initialize(),(error)=>error===runtimeFailure);
  await assert.rejects(runtimeProduct.beginRoutineAuthorization({action:"record_harmless_value"}),(error)=>error.code==="ROUTINE_PRODUCT_NOT_INITIALIZED");
  assert.equal(enrollmentBegins,0);

  let attempts=0,disposals=0;
  const missingHost={async start(){},async stop(){},async activeEnrollment(){throw Object.assign(new Error("missing"),{code:"ROUTINE_ENROLLMENT_NOT_FOUND"});},
    async beginEnrollment(){return{requestId:`0x${"12".repeat(32)}`};},status(){},cancel(){},assertDeletionSafe(){return true;},disposeAfterDurableDeletion(){disposals+=1;}};
  const retryable=createRoutineAuthorizationProductHost({enrollmentHost:missingHost,authorizationHostFactory:async()=>{throw new Error("unexpected");},
    deleteProfileAtomically:async()=>{attempts+=1;if(attempts===1)throw new Error("precommit");return{status:"deleted",identityOrRecoveryStateTouched:false};}});
  await retryable.initialize();
  const initialSetup=await retryable.beginRoutineAuthorization({action:"replace_routine_device"});assert.equal(initialSetup.enrollmentMode,"initial");
  await assert.rejects(retryable.deleteDisposableProfile(),/precommit/u);
  assert.deepEqual(await retryable.deleteDisposableProfile(),{status:"deleted",identityOrRecoveryStateTouched:false});assert.equal(attempts,2);assert.equal(disposals,1);

  const poisoned=createRoutineAuthorizationProductHost({enrollmentHost:{...missingHost,disposeAfterDurableDeletion(){}},authorizationHostFactory:async()=>{throw new Error("unexpected");},
    deleteProfileAtomically:async()=>{throw Object.assign(new Error("postcommit"),{profileDeletionCommitted:true});}});
  await poisoned.initialize();await assert.rejects(poisoned.deleteDisposableProfile(),/postcommit/u);
  await assert.rejects(poisoned.deleteDisposableProfile(),(error)=>error.code==="ROUTINE_PRODUCT_NOT_INITIALIZED");
  await assert.rejects(poisoned.getRoutineAuthorizationStatus(`0x${"13".repeat(32)}`),(error)=>error.code==="ROUTINE_PROFILE_DELETION_COMMITTED");
});
