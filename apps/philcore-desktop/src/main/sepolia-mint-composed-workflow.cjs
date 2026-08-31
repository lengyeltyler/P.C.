"use strict";

const path=require("node:path");
const {randomBytes}=require("node:crypto");
const {p256}=require("@noble/curves/p256");
const {ethers}=require("ethers");
require("tsx/cjs");
const {derivePhilIdentityRoot}=require("../../../phil-device-sdk/src/identity.ts");
const {derivePhilScopedOwnerCommitmentV1}=require("../../../phil-device-sdk/src/secureIdentityV1.ts");
const {createPhilRootProofPublicInputsV1}=require("../../../phil-device-sdk/src/rootProofV1.ts");
const mint=require("../../../phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const device=require("../../../phil-device-sdk/src/deviceApprovalV1.ts");
const requestApi=require("../../../phil-device-sdk/src/sepoliaMintDeviceRequestV1.ts");
const composed=require("../../../phil-device-sdk/src/sepoliaMintComposedAuthorizationV1.ts");
const operation=require("../../../phil-device-sdk/src/sepoliaMintUserOperationV1.ts");
const wire=require("../../../phil-device-sdk/src/p256SignatureWireV2.ts");
const noir=require("./noir-root-proof-stack.cjs");

function fail(code){const error=new Error(code);error.code=code;throw error;}
function freeze(value){return Object.freeze(JSON.parse(JSON.stringify(value)));}
function rawResponseSignature(response){return ethers.concat([response.signatureR,response.signatureS]);}
function nativeDeviceVerifier(){return Object.freeze({verifierId:"apple-secure-enclave-p256-low-s-native-v1",verify({digest,signature,publicKey}){try{wire.decodePhilP256RawSignatureV2(signature);return p256.verify(signature.slice(2),digest.slice(2),publicKey.slice(2),{lowS:true,prehash:false});}catch{return false;}}});}

async function preparePhilSepoliaMintComposedWorkflow(input){
  if(!input?.protectedMaterial?.philSecret)fail("PHIL_SEPOLIA_MINT_IDENTITY_LOCKED");
  const repositoryRoot=input.repositoryRoot||path.resolve(__dirname,"../../../.."),paths=noir.resolveNoirRootProofPaths(repositoryRoot),descriptor=noir.validateNoirRootProofPaths(paths).descriptorDocument.proofDescriptorHash;
  const bindings=mint.derivePhilSepoliaMintBindingsV1(input.bindingsInput),epochs=Object.freeze({...input.epochs});
  const scopedOwnerCommitment=derivePhilScopedOwnerCommitmentV1({identityRoot:derivePhilIdentityRoot(input.protectedMaterial.philSecret),scopeId:mint.PHIL_SEPOLIA_MINT_SCOPE_ID,scopeInstance:bindings.scopeInstance,scopeEpoch:epochs.scopeEpoch});
  const envelopeDigest=mint.derivePhilSepoliaMintAuthorizationEnvelopeDigestV1({scopedOwnerCommitment,proofDescriptorHash:descriptor,scopeEpoch:epochs.scopeEpoch,deviceEpoch:epochs.deviceEpoch,recoveryEpoch:epochs.recoveryEpoch,validatorEpoch:epochs.validatorEpoch,bindings});
  const nullifierSeed=`0x${(input.dependencies?.randomBytes||randomBytes)(32).toString("hex")}`;
  const proofPublicInputs=createPhilRootProofPublicInputsV1({philSecret:input.protectedMaterial.philSecret,nullifierSeed,scopeId:mint.PHIL_SEPOLIA_MINT_SCOPE_ID,scopeInstance:bindings.scopeInstance,scopeEpoch:epochs.scopeEpoch,authorizationEnvelopeDigest:envelopeDigest,proofDescriptorHash:descriptor});
  const prove=input.dependencies?.proveNoirRootProofV1||noir.proveNoirRootProofV1,verify=input.dependencies?.verifyNoirRootProofV1||noir.verifyNoirRootProofV1;
  const proofArtifact=await prove({paths,philSecret:input.protectedMaterial.philSecret,nullifierSeed,publicInputs:proofPublicInputs,timeoutMs:input.proofTimeoutMs||120000});
  if(!verify({paths,proof:proofArtifact.proof,publicInputBytes:proofArtifact.publicInputBytes,publicInputs:proofPublicInputs,timeoutMs:input.proofTimeoutMs||120000}).verified)fail("PHIL_SEPOLIA_MINT_NOIR_PROOF_INVALID");
  const authorization=mint.createPhilSepoliaMintAuthorizationV1({scopedOwnerCommitment,proofDescriptorHash:descriptor,rootProofNullifier:proofPublicInputs.rootProofNullifier,scopeEpoch:epochs.scopeEpoch,deviceEpoch:epochs.deviceEpoch,recoveryEpoch:epochs.recoveryEpoch,validatorEpoch:epochs.validatorEpoch,bindings});
  if(authorization.authorizationEnvelopeDigest!==envelopeDigest)fail("PHIL_SEPOLIA_MINT_ENVELOPE_DIGEST_CHANGED");
  const context=freeze({format:"phil-sepolia-mint-composed-workflow-context-v1",authorization,bindingsInput:input.bindingsInput,epochs,proofPublicInputs,proofArtifact,execution:{executionOwner:input.executionOwner,ownerCommitment:input.ownerCommitment,accountSalt:String(input.accountSalt),accountDeployed:Boolean(input.accountDeployed),gas:input.gas},proofVerifierId:"native-barretenberg-ultra-keccak-zk-honk",serializedPrivateMaterialReturned:false,philSecretReturned:false,nullifierSeedReturned:false});
  return Object.freeze({
    context,
    createDeviceRequest({sessionId,approvalNonce,now}){
      const approvedAt=BigInt(now),approvalExpiresAt=approvedAt+120n>BigInt(bindings.validUntil)?BigInt(bindings.validUntil):approvedAt+120n;
      if(approvalExpiresAt<=approvedAt)fail("PHIL_SEPOLIA_MINT_DEVICE_WINDOW_INVALID");
      return Object.freeze({request:requestApi.createPhilSepoliaMintDeviceRequestV1({sessionId,authorization,enrollment:input.enrollment,approvalNonce,approvedAt,approvalExpiresAt}),context});
    }
  });
}

async function completePhilSepoliaMintComposedWorkflow(input){
  const context=input.context;if(context?.format!=="phil-sepolia-mint-composed-workflow-context-v1"||context.serializedPrivateMaterialReturned!==false)fail("PHIL_SEPOLIA_MINT_CONTEXT_INVALID");
  const request=requestApi.validatePhilSepoliaMintDeviceRequestV1(input.request,input.enrollment);
  if(JSON.stringify(request.authorization)!==JSON.stringify(context.authorization))fail("PHIL_SEPOLIA_MINT_CONTEXT_AUTHORIZATION_MISMATCH");
  const response=requestApi.parsePhilSepoliaMintDeviceResponseJsonV1({request,enrollment:input.enrollment,json:JSON.stringify(input.response)});
  const approval=device.createPhilDeviceApprovalEvidenceV1({authorizationEnvelopeDigest:request.authorization.authorizationEnvelopeDigest,enrollment:input.enrollment,approvalNonce:request.approvalNonce,approvedAt:request.approvedAt,approvalExpiresAt:request.approvalExpiresAt,humanPresentationHash:request.humanPresentationHash,signature:rawResponseSignature(response)});
  const paths=noir.resolveNoirRootProofPaths(input.repositoryRoot||path.resolve(__dirname,"../../../..")),verify=input.dependencies?.verifyNoirRootProofV1||noir.verifyNoirRootProofV1;
  const release=await composed.authorizePhilSepoliaMintCompositionV1({authorization:request.authorization,expectedBindings:context.bindingsInput,proofPublicInputs:context.proofPublicInputs,proofArtifact:context.proofArtifact,proofVerifier:{verifierId:context.proofVerifierId,verify({proofArtifact,publicInputs}){return verify({paths,proof:proofArtifact.proof,publicInputBytes:proofArtifact.publicInputBytes,publicInputs,timeoutMs:input.proofTimeoutMs||120000}).verified;}},deviceApproval:approval,deviceEnrollment:input.enrollment,deviceVerifier:input.dependencies?.deviceVerifier||nativeDeviceVerifier(),replayStore:input.replayStore,trustedState:input.trustedState});
  const prepared=operation.preparePhilSepoliaMintUserOperationV1({authorization:request.authorization,release,...context.execution});
  // This callback is intentionally unreachable until local composition has
  // succeeded and the replay reservation has been durably written.
  const signer=await input.createDeviceVaultSigner({authorization:request.authorization,release,prepared});
  try{
    const signed=await operation.signPhilSepoliaMintUserOperationV1({authorization:request.authorization,release,prepared,replayStore:input.replayStore,signer});
    return freeze({format:"phil-sepolia-mint-signed-unsubmitted-v1",authorizationEnvelopeDigest:release.authorizationEnvelopeDigest,rootProofNullifier:release.rootProofNullifier,deviceApprovalNonce:release.deviceApprovalNonce,accountNonce:release.accountNonce,userOperationHash:signed.userOperationHash,userOperation:signed.userOperation,smartAccount:signed.smartAccount,actionGate:signed.actionGate,maximumTotalFeeWei:signed.maximumTotalFeeWei,signed:true,submitted:false,ethereumVerifiesNoirProof:false,ethereumVerifiesP256Approval:false});
  }finally{await signer.invalidateSigningSession?.("phil-sepolia-mint-signing-complete");}
}

module.exports={preparePhilSepoliaMintComposedWorkflow,completePhilSepoliaMintComposedWorkflow};
