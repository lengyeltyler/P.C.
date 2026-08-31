"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { p256 } = require("@noble/curves/p256");

require("tsx/cjs");
const auth = require("../../../phil-device-sdk/src/routineAuthorizationV1.ts");
const registryApi = require("../../../phil-device-sdk/src/routineSignatureRegistryV2.ts");
const adapter = require("../../../phil-device-sdk/src/networkAdapterV1.ts");
const journal = require("../../../phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts");
const { PHIL_DEVICE_APPROVAL_V1_HASH } = require("../../../phil-device-sdk/src/deviceApprovalV1.ts");

const SOURCE_PATHS=Object.freeze([
  "apps/phil-device-sdk/src/p256SignatureWireV2.ts","apps/phil-device-sdk/src/routineAuthorizationV1.ts",
  "apps/phil-device-sdk/src/routineSignatureRegistryV2.ts","apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts",
  "contracts/base/erc4337/PhilV1Step6CAccount.sol","contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol"
]);
const REENTRANCY_SLOT="0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00";
const ZERO=`0x${"00".repeat(32)}`;

function exactOptions(value,keys) {
  if (!value||typeof value!=="object"||Array.isArray(value)||Object.keys(value).sort().join(",")!==[...keys].sort().join(",")) throw new Error("ROUTINE_LOCAL_RUNTIME_OPTIONS_INVALID");
}
function sourceIdentity(ethers,root) {
  const coder=ethers.AbiCoder.defaultAbiCoder();
  const entries=SOURCE_PATHS.map((file)=>ethers.keccak256(coder.encode(["bytes32","bytes32"],[ethers.id(file),
    `0x${crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")}`])));
  const implementationHash=ethers.keccak256(coder.encode(["bytes32","bytes32[6]"],[auth.PHIL_ROUTINE_DOMAIN_HASHES_V1.IMPLEMENTATION_SET,entries]));
  const auditStatusHash=ethers.keccak256(coder.encode(["bytes32","uint8","bytes32","bytes32"],[auth.PHIL_ROUTINE_DOMAIN_HASHES_V1.AUDIT_STATUS,1,implementationHash,ZERO]));
  return {implementationHash,auditStatusHash};
}
function packedGas(ethers,high,low) { return ethers.hexlify(ethers.concat([ethers.zeroPadValue(ethers.toBeHex(high),16),ethers.zeroPadValue(ethers.toBeHex(low),16)])); }
function serializePacked(ethers,userOp) { return ethers.AbiCoder.defaultAbiCoder().encode(["address","uint256","bytes","bytes","bytes32","uint256","bytes32","bytes","bytes"],
  [userOp.sender,userOp.nonce,userOp.initCode,userOp.callData,userOp.accountGasLimits,userOp.preVerificationGas,userOp.gasFees,userOp.paymasterAndData,userOp.signature]); }
function eventCommitment(ethers,log) {
  const topics=[...log.topics,ZERO,ZERO,ZERO].slice(0,4);return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ["address","bytes32","bytes32","bytes32","bytes32","bytes32","uint256","bytes32","bytes32"],
    [log.address,topics[0],topics[1],topics[2],topics[3],ethers.keccak256(log.data),log.index,log.transactionHash,log.blockHash]));
}
function contractAction(action) { return {target:action.target,targetCalldataHash:action.targetCalldataHash,valueWei:action.valueWei,nonceKey:action.nonceKey,
  nonceSequence:action.nonceSequence,callGasLimit:action.callGasLimit,verificationGasLimit:action.verificationGasLimit,preVerificationGas:action.preVerificationGas,
  maxFeePerGas:action.maxFeePerGas,maxPriorityFeePerGas:action.maxPriorityFeePerGas,validAfter:action.validAfter,validUntil:action.validUntil}; }
function contractApproval(request) { return {formatVersionHash:PHIL_DEVICE_APPROVAL_V1_HASH,authorizationEnvelopeDigest:request.authorizationEnvelopeDigest,...request.unsignedDeviceApproval}; }
function contractPresentation(value) { const {humanPresentationHash:_hash,...wire}=value;return wire; }
function contractCore(value) { const {authorizationCoreDigest:_hash,...wire}=value;return wire; }

async function createRoutineAuthorizationLocalProductRuntime(options) {
  exactOptions(options,["hardhat","repositoryRoot","enrollment","now","desktopUnlocked","iphoneSessionCurrent"]);
  const { ethers,artifacts,network }=options.hardhat;
  const configuredAccounts=options.hardhat.config?.networks?.hardhat?.accounts;
  if (network.name!=="hardhat"||(await ethers.provider.getNetwork()).chainId!==31337n||options.hardhat.config?.networks?.hardhat?.forking?.enabled===true
    ||!Array.isArray(configuredAccounts)||configuredAccounts.length!==1||typeof configuredAccounts[0]?.privateKey!=="string") {
    throw new Error("ROUTINE_LOCAL_CHAIN_ID_INVALID");
  }
  const deployer=ethers.Wallet.createRandom().connect(ethers.provider),beneficiary=ethers.Wallet.createRandom().address;
  await network.provider.send("hardhat_setBalance",[deployer.address,ethers.toBeHex(ethers.parseEther("10"))]);
  const deploy=async (name,args=[])=>{
    const artifact=await artifacts.readArtifact(name),factory=new ethers.ContractFactory(artifact.abi,artifact.bytecode,deployer),contract=await factory.deploy(...args);
    await contract.waitForDeployment();return contract;
  };
  const entryPoint=await deploy("@account-abstraction/contracts/core/EntryPoint.sol:EntryPoint"),entryPointAddress=(await entryPoint.getAddress()).toLowerCase();
  const senderCreator=ethers.getCreateAddress({from:entryPointAddress,nonce:1}).toLowerCase();
  const entryPointCode=await ethers.provider.getCode(entryPointAddress),senderCreatorCode=await ethers.provider.getCode(senderCreator);
  if (entryPointCode==="0x"||senderCreatorCode==="0x"||await ethers.provider.getStorage(entryPointAddress,REENTRANCY_SLOT)!==ethers.toBeHex(1,32)) throw new Error("ROUTINE_LOCAL_ENTRYPOINT_INVALID");
  const target=await deploy("PhilV1Step6CHarmlessTarget"),targetAddress=(await target.getAddress()).toLowerCase(),targetCodeHash=ethers.keccak256(await ethers.provider.getCode(targetAddress));
  const accountArtifact=await artifacts.readArtifact("PhilV1Step6CAccount"),accountRuntimeCodeHash=ethers.keccak256(accountArtifact.deployedBytecode);
  const predictedAccount=ethers.getCreateAddress({from:deployer.address,nonce:await ethers.provider.getTransactionCount(deployer.address)}).toLowerCase();
  const environment=auth.createPhilExecutionEnvironmentV1({entryPoint:entryPointAddress,entryPointRuntimeCodeHash:ethers.keccak256(entryPointCode),senderCreator,senderCreatorRuntimeCodeHash:ethers.keccak256(senderCreatorCode)});
  const manifest=auth.createPhilStep6CLocalAdapterManifestV1(sourceIdentity(ethers,options.repositoryRoot)),signatureRegistry=registryApi.createPhilRoutineSignatureRegistryV2();
  const enrollment=auth.createPhilRoutineDeviceEnrollmentV2({deviceId:options.enrollment.deviceId,deviceKeyId:options.enrollment.deviceKeyId,generation:options.enrollment.generation,
    signatureRegistry,publicKeyX963:options.enrollment.publicKeyX963,secureEnclaveBacked:options.enrollment.secureEnclaveBacked,userPresenceRequired:options.enrollment.userPresenceRequired});
  const configuration=auth.createPhilRoutineAccountConfigurationV1({environment,adapterManifest:manifest,enrollment,account:predictedAccount,accountRuntimeCodeHash,
    scopedOwnerCommitment:ethers.hexlify(crypto.randomBytes(32)),approvedTarget:targetAddress,approvedTargetRuntimeCodeHash:targetCodeHash,nonceKey:0,maximumValueWei:0,maximumTotalFeeWei:20_000_000});
  const parameterSchemaId=auth.derivePhilRoutineParameterSchemaIdV1(configuration),catalog=auth.createPhilRoutineCatalogV1({environment,configuration,parameterSchemaId});
  const profilePolicyValidAfter=BigInt(await options.now());
  if (profilePolicyValidAfter<=0n||profilePolicyValidAfter>=(1n<<48n)) throw new Error("ROUTINE_LOCAL_CLOCK_INVALID");
  const policy=auth.createPhilRoutineCapabilityPolicyV1({environment,adapterManifest:manifest,enrollment,configuration,catalog,profilePolicyValidAfter});
  const constructorConfig={entryPoint:entryPointAddress,executionEnvironmentHash:environment.executionEnvironmentHash,adapterManifestHash:manifest.manifestHash,
    signatureRegistryHash:signatureRegistry.registryHash,deviceEnrollmentHash:enrollment.deviceEnrollmentHash,accountConfigurationHash:configuration.accountConfigurationHash,
    catalogHash:catalog.catalogHash,capabilityPolicyHash:policy.capabilityPolicyHash,catalogDisplayTextHashes:auth.PHIL_STEP6C_CATALOG_TEXT_HASHES,
    accountRuntimeCodeHash,applicationId:configuration.applicationId,principalIdHash:configuration.principalIdHash,scopedOwnerCommitment:configuration.scopedOwnerCommitment,
    scopeId:configuration.scopeId,scopeInstance:configuration.scopeInstance,scopeEpoch:1,capabilityId:policy.capabilityId,capabilityEpoch:1,policyEpoch:1,
    deviceId:enrollment.deviceId,deviceKeyId:enrollment.deviceKeyId,deviceEpoch:1,signatureSuiteId:enrollment.signatureSuiteId,providerProfileId:enrollment.providerProfileId,
    wireEncodingId:enrollment.wireEncodingId,publicKeyX:enrollment.publicKeyX,publicKeyY:enrollment.publicKeyY,recoveryEpoch:1,validatorEpoch:1,
    approvedTarget:targetAddress,approvedTargetRuntimeCodeHash:targetCodeHash,actionTypeHash:adapter.PHIL_EVM_SINGLE_CALL_V1_HASH,parameterSchemaId,nonceKey:0,
    maximumValueWei:0,maximumTotalFeeWei:configuration.maximumTotalFeeWei,profilePolicyValidAfter:policy.validAfter,profilePolicyValidUntil:policy.validUntil};
  const account=await deploy("PhilV1Step6CAccount",[constructorConfig]);
  if ((await account.getAddress()).toLowerCase()!==predictedAccount||ethers.keccak256(await ethers.provider.getCode(predictedAccount))!==accountRuntimeCodeHash) throw new Error("ROUTINE_LOCAL_ACCOUNT_INVALID");
  await (await entryPoint.connect(deployer).depositTo(predictedAccount,{value:ethers.parseEther("1")})).wait();
  const context={entryPoint,entryPointAddress,senderCreator,target,targetAddress,targetCodeHash,account,accountAddress:predictedAccount,accountRuntimeCodeHash,
    entryPointCodeHash:ethers.keccak256(entryPointCode),senderCreatorCodeHash:ethers.keccak256(senderCreatorCode),environment,manifest,signatureRegistry,enrollment,configuration,catalog,policy,
    deployer,beneficiary,requests:new Map(),responses:new Map(),outcomes:new Map()};

  function userOperation(request,response) {
    const signature=`${response.signatureR}${response.signatureS.slice(2)}`;
    const callData=account.interface.encodeFunctionData("executeAuthorized",[contractAction(request.action),request.authorizationEnvelope,contractApproval(request),
      contractPresentation(request.humanPresentation),contractCore(request.authorizationCore),request.targetCalldata]);
    return {sender:context.accountAddress,nonce:request.action.userOpNonce,initCode:"0x",callData,
      accountGasLimits:packedGas(ethers,request.action.verificationGasLimit,request.action.callGasLimit),preVerificationGas:request.action.preVerificationGas,
      gasFees:packedGas(ethers,request.action.maxPriorityFeePerGas,request.action.maxFeePerGas),paymasterAndData:"0x",signature};
  }
  async function requestFactory(intent) {
    if (!intent||Object.keys(intent).join(",")!=="action"||intent.action!=="record_harmless_value") throw new Error("ROUTINE_LOCAL_INTENT_INVALID");
    let latest=await ethers.provider.getBlock("latest");const issuedAt=BigInt(await options.now()),nonce=await entryPoint.getNonce(context.accountAddress,0);
    if (issuedAt<profilePolicyValidAfter||issuedAt+120n>policy.validUntil||issuedAt+5n<BigInt(latest.timestamp)) throw new Error("ROUTINE_LOCAL_CLOCK_INVALID");
    if (issuedAt>BigInt(latest.timestamp)) { await network.provider.send("evm_setNextBlockTimestamp",[Number(issuedAt)]);await network.provider.send("evm_mine");latest=await ethers.provider.getBlock("latest"); }
    const targetCalldata=target.interface.encodeFunctionData("record",[auth.PHIL_STEP6C_RECORDED_VALUE,false]);
    const action=adapter.createPhilEvmSingleCallV1({chainId:auth.PHIL_STEP6C_CHAIN_ID,account:context.accountAddress,entryPoint:context.entryPointAddress,target:context.targetAddress,
      targetCalldataHash:ethers.keccak256(targetCalldata),valueWei:0,nonceKey:0,nonceSequence:nonce,callGasLimit:350_000,verificationGasLimit:4_000_000,
      preVerificationGas:100_000,maxFeePerGas:1,maxPriorityFeePerGas:0,validAfter:issuedAt,validUntil:issuedAt+120n});
    const request=auth.createPhilRoutineAuthorizationRequestV1({executionEnvironment:environment,adapterManifest:manifest,signatureRegistry,deviceEnrollment:enrollment,
      accountConfiguration:configuration,catalog,capabilityPolicy:policy,action,targetCalldata,sessionId:ethers.hexlify(crypto.randomBytes(32)),nonceSeed:ethers.hexlify(crypto.randomBytes(32)),
      issuedAt,expiresAt:issuedAt+120n});context.requests.set(request.requestId,request);return request;
  }
  async function readTrustedState(requestId) {
    const request=context.requests.get(requestId);if (!request) throw new Error("ROUTINE_LOCAL_REQUEST_UNKNOWN");
    return {request,desktopUnlocked:Boolean(await options.desktopUnlocked()),iphoneSessionCurrent:Boolean(await options.iphoneSessionCurrent(enrollment))};
  }
  async function simulate(request,response) {
    if (!response) throw new Error("ROUTINE_LOCAL_RESPONSE_REQUIRED");context.responses.set(request.requestId,response);
    const userOp=userOperation(request,response),packedUserOperationBytes=serializePacked(ethers,userOp),head=await ethers.provider.getBlock("latest");
    const recordedValue=await target.recordedValue(),recordedSequence=await target.recordedSequence();
    const result={entryPoint:entryPointAddress,sender:context.accountAddress,userOperationNonce:request.action.userOpNonce,
      serializedUserOperationHash:ethers.keccak256(packedUserOperationBytes),officialUserOperationHash:await entryPoint.getUserOpHash(userOp),packedUserOperationBytes,
      target:targetAddress,targetRecordedValueBefore:recordedValue,targetRecordedSequenceBefore:recordedSequence,
      targetPreStateHash:journal.derivePhilRoutineTargetPreStateHashV1({target:targetAddress,approvedTargetRuntimeCodeHash:targetCodeHash,recordedValueBefore:recordedValue,
        recordedSequenceBefore:recordedSequence,scanStartBlockNumber:head.number,scanStartBlockHash:head.hash}),scanStartBlockNumber:head.number,scanStartBlockHash:head.hash};
    await ethers.provider.call({from:deployer.address,to:entryPointAddress,data:entryPoint.interface.encodeFunctionData("handleOps",[[userOp],beneficiary])});return result;
  }
  async function execute(request,response,simulation) {
    const userOp=userOperation(request,response),transaction=await entryPoint.connect(deployer).handleOps([userOp],beneficiary),chainReceipt=await transaction.wait(),block=await ethers.provider.getBlock(chainReceipt.blockNumber);
    const topics=[ethers.id("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"),ethers.id("PhilV1Step6CAuthorizationConsumed(bytes32,bytes32,bytes32,bytes32,bytes32,address)"),ethers.id("ValueRecorded(bytes32,uint64)")];
    const logs=topics.map((topic)=>chainReceipt.logs.find((log)=>log.topics[0]===topic));if (logs.some((log)=>!log)) throw new Error("ROUTINE_LOCAL_RECEIPT_LOG_MISSING");
    const before=BigInt(request.action.userOpNonce),after=before+1n;
    const receipt=auth.createPhilRoutineAuthorizationReceiptV1({requestId:request.requestId,authorizationCoreDigest:request.authorizationCoreDigest,
      authorizationEnvelopeDigest:request.authorizationEnvelopeDigest,deviceApprovalDigest:request.deviceApprovalDigest,platformSigningDigest:request.platformSigningDigest,
      serializedUserOperationHash:simulation.serializedUserOperationHash,userOperationHash:simulation.officialUserOperationHash,executionEnvironmentHash:environment.executionEnvironmentHash,
      entryPointEventCommitment:eventCommitment(ethers,logs[0]),accountEventCommitment:eventCommitment(ethers,logs[1]),targetEventCommitment:eventCommitment(ethers,logs[2]),
      targetPreStateHash:simulation.targetPreStateHash,finalTargetStateHash:ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address","bytes32","uint64","bytes32","bytes32"],
        [targetAddress,auth.PHIL_STEP6C_RECORDED_VALUE,BigInt(simulation.targetRecordedSequenceBefore)+1n,chainReceipt.hash,block.hash])),entryPointCodeHash:context.entryPointCodeHash,
      senderCreatorCodeHash:context.senderCreatorCodeHash,accountCodeHash:accountRuntimeCodeHash,targetCodeHash,transactionHash:chainReceipt.hash,blockHash:block.hash,
      entryPointNonceBefore:before,entryPointNonceAfter:after,executedAt:block.timestamp,simulationPassed:true,executionSucceeded:true,externalNetwork:false,productionAuthority:false});
    const outcome={kind:"success",receipt,evidence:{packedUserOperationBytes:simulation.packedUserOperationBytes,userOperationHash:simulation.officialUserOperationHash,
      logs:chainReceipt.logs.map((log)=>({address:log.address,topics:[...log.topics],data:log.data,index:log.index,transactionHash:log.transactionHash,blockHash:log.blockHash,removed:false})),
      transactionStatus:chainReceipt.status,targetRecordedValueBefore:simulation.targetRecordedValueBefore,targetRecordedSequenceBefore:simulation.targetRecordedSequenceBefore,
      scanStartBlockNumber:simulation.scanStartBlockNumber,scanStartBlockHash:simulation.scanStartBlockHash,targetRecordedValueAfter:auth.PHIL_STEP6C_RECORDED_VALUE,
      targetRecordedSequenceAfter:BigInt(simulation.targetRecordedSequenceBefore)+1n,blockTimestamp:block.timestamp,entryPointNonceBefore:before,entryPointNonceAfter:after,
      entryPointCodeHash:context.entryPointCodeHash,senderCreatorCodeHash:context.senderCreatorCodeHash,accountCodeHash:accountRuntimeCodeHash,targetCodeHash,
      transactionHash:chainReceipt.hash,blockHash:block.hash}};context.outcomes.set(request.requestId,outcome);return outcome;
  }
  async function rebuildOutcome(request,record,chainReceipt,capturedHead) {
    const block=await ethers.provider.getBlock(chainReceipt.blockNumber);
    if (!block||chainReceipt.status!==1) throw new Error("ROUTINE_LOCAL_RECONCILIATION_RECEIPT_INVALID");
    const entryTopic=ethers.id("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
    const accountTopic=ethers.id("PhilV1Step6CAuthorizationConsumed(bytes32,bytes32,bytes32,bytes32,bytes32,address)");
    const targetTopic=ethers.id("ValueRecorded(bytes32,uint64)");
    const entryLogs=chainReceipt.logs.filter((log)=>log.address.toLowerCase()===entryPointAddress&&log.topics[0]===entryTopic&&log.topics[1]===record.officialUserOperationHash);
    if (entryLogs.length!==1) throw new Error("ROUTINE_LOCAL_RECONCILIATION_EVENT_AMBIGUOUS");
    const entryLog=entryLogs[0],parsed=entryPoint.interface.parseLog({topics:[...entryLog.topics],data:entryLog.data});
    const receiptLogs=chainReceipt.logs.map((log)=>({address:log.address,topics:[...log.topics],data:log.data,index:log.index,
      transactionHash:log.transactionHash,blockHash:log.blockHash,removed:false}));
    const entryPointNonceAfter=await entryPoint.getNonce(context.accountAddress,0),targetRecordedValueAfter=await target.recordedValue(),
      targetRecordedSequenceAfter=await target.recordedSequence();
    if (parsed?.args?.success!==true) return {kind:"failed",evidence:{scanStartBlockNumber:record.scanStartBlockNumber,
      scanStartBlockHash:record.scanStartBlockHash,capturedHeadBlockNumber:capturedHead.number,capturedHeadBlockHash:capturedHead.hash,
      eventBlockNumber:block.number,transactionStatus:chainReceipt.status,transactionHash:chainReceipt.hash,blockHash:block.hash,logs:receiptLogs,
      entryPointNonceAfter,targetCodeHash,targetRecordedValueAfter,targetRecordedSequenceAfter}};
    const accountLogs=chainReceipt.logs.filter((log)=>log.topics[0]===accountTopic),targetLogs=chainReceipt.logs.filter((log)=>log.topics[0]===targetTopic);
    if (accountLogs.length!==1||targetLogs.length!==1) throw new Error("ROUTINE_LOCAL_RECEIPT_LOG_MISSING");
    const targetParsed=target.interface.parseLog({topics:[...targetLogs[0].topics],data:targetLogs[0].data});
    const afterSequence=BigInt(targetParsed.args.sequence),before=BigInt(record.userOperationNonce);
    const receipt=auth.createPhilRoutineAuthorizationReceiptV1({requestId:request.requestId,authorizationCoreDigest:request.authorizationCoreDigest,
      authorizationEnvelopeDigest:request.authorizationEnvelopeDigest,deviceApprovalDigest:request.deviceApprovalDigest,platformSigningDigest:request.platformSigningDigest,
      serializedUserOperationHash:record.serializedUserOperationHash,userOperationHash:record.officialUserOperationHash,executionEnvironmentHash:environment.executionEnvironmentHash,
      entryPointEventCommitment:eventCommitment(ethers,entryLog),accountEventCommitment:eventCommitment(ethers,accountLogs[0]),
      targetEventCommitment:eventCommitment(ethers,targetLogs[0]),targetPreStateHash:record.targetPreStateHash,
      finalTargetStateHash:ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["address","bytes32","uint64","bytes32","bytes32"],
        [targetAddress,auth.PHIL_STEP6C_RECORDED_VALUE,afterSequence,chainReceipt.hash,block.hash])),entryPointCodeHash:context.entryPointCodeHash,
      senderCreatorCodeHash:context.senderCreatorCodeHash,accountCodeHash:accountRuntimeCodeHash,targetCodeHash,transactionHash:chainReceipt.hash,blockHash:block.hash,
      entryPointNonceBefore:before,entryPointNonceAfter:before+1n,executedAt:block.timestamp,simulationPassed:true,executionSucceeded:true,externalNetwork:false,productionAuthority:false});
    return {kind:"success",receipt,evidence:{packedUserOperationBytes:record.packedUserOperationBytes,userOperationHash:record.officialUserOperationHash,logs:receiptLogs,
      transactionStatus:chainReceipt.status,targetRecordedValueBefore:record.targetRecordedValueBefore,targetRecordedSequenceBefore:record.targetRecordedSequenceBefore,
      scanStartBlockNumber:record.scanStartBlockNumber,scanStartBlockHash:record.scanStartBlockHash,targetRecordedValueAfter:auth.PHIL_STEP6C_RECORDED_VALUE,
      targetRecordedSequenceAfter:afterSequence,blockTimestamp:block.timestamp,entryPointNonceBefore:before,entryPointNonceAfter:before+1n,
      entryPointCodeHash:context.entryPointCodeHash,senderCreatorCodeHash:context.senderCreatorCodeHash,accountCodeHash:accountRuntimeCodeHash,targetCodeHash,
      transactionHash:chainReceipt.hash,blockHash:block.hash}};
  }
  async function reconcile(request,record) {
    if (record.state===8&&context.outcomes.has(request.requestId)) return context.outcomes.get(request.requestId);
    const head=await ethers.provider.getBlock("latest"),anchor=await ethers.provider.getBlock(Number(record.scanStartBlockNumber)).catch(()=>null);
    if (!anchor||anchor.hash!==record.scanStartBlockHash) return {kind:"unknown",evidence:{scanStartBlockNumber:record.scanStartBlockNumber,
      scanStartBlockHash:record.scanStartBlockHash,chainAccessible:false,capturedHeadBlockNumber:0,capturedHeadBlockHash:ZERO,matchingUserOperationLogs:[],
      entryPointNonceAfter:0,targetCodeHash:ZERO,targetRecordedValueAfter:ZERO,targetRecordedSequenceAfter:0}};
    const logs=await ethers.provider.getLogs({address:entryPointAddress,fromBlock:Number(record.scanStartBlockNumber)+1,toBlock:head.number,
      topics:[ethers.id("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"),record.officialUserOperationHash]});
    if (logs.length>1) throw new Error("ROUTINE_LOCAL_RECONCILIATION_EVENT_AMBIGUOUS");
    if (logs.length===1) {
      const chainReceipt=await ethers.provider.getTransactionReceipt(logs[0].transactionHash);
      if (!chainReceipt) throw new Error("ROUTINE_LOCAL_RECONCILIATION_RECEIPT_MISSING");
      return rebuildOutcome(request,record,chainReceipt,head);
    }
    return {kind:"unknown",evidence:{scanStartBlockNumber:record.scanStartBlockNumber,scanStartBlockHash:record.scanStartBlockHash,chainAccessible:true,
      capturedHeadBlockNumber:head.number,capturedHeadBlockHash:head.hash,matchingUserOperationLogs:[],entryPointNonceAfter:await entryPoint.getNonce(context.accountAddress,0),targetCodeHash,
      targetRecordedValueAfter:await target.recordedValue(),targetRecordedSequenceAfter:await target.recordedSequence()}};
  }
  return Object.freeze({requestFactory,readTrustedState,simulate,execute,reconcile,readCurrentNonce:async()=>String(await entryPoint.getNonce(context.accountAddress,0)),context:Object.freeze(context),classification:Object.freeze({localOnly:true,externalNetwork:false,
    productionAuthority:false,physicalDeviceVerified:false,usesFreshRandomDeployer:true})});
}

module.exports={SOURCE_PATHS,createRoutineAuthorizationLocalProductRuntime};
