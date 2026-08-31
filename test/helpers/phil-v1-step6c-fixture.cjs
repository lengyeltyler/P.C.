const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { p256 } = require("@noble/curves/p256");
const { ethers, artifacts, network } = require("hardhat");

const auth = require("../../apps/phil-device-sdk/src/routineAuthorizationV1.ts");
const registryApi = require("../../apps/phil-device-sdk/src/routineSignatureRegistryV2.ts");
const p256Wire = require("../../apps/phil-device-sdk/src/p256SignatureWireV2.ts");
const adapter = require("../../apps/phil-device-sdk/src/networkAdapterV1.ts");
const { PHIL_DEVICE_APPROVAL_V1_HASH } = require("../../apps/phil-device-sdk/src/deviceApprovalV1.ts");

const ROOT = path.resolve(__dirname, "../..");
const ZERO = ethers.ZeroHash;
const SOURCE_PATHS = Object.freeze([
  "apps/phil-device-sdk/src/p256SignatureWireV2.ts",
  "apps/phil-device-sdk/src/routineAuthorizationV1.ts",
  "apps/phil-device-sdk/src/routineSignatureRegistryV2.ts",
  "apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts",
  "contracts/base/erc4337/PhilV1Step6CAccount.sol",
  "contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol"
]);
const REENTRANCY_SLOT =
  "0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00";

function sha256File(file) {
  return `0x${crypto.createHash("sha256").update(fs.readFileSync(path.join(ROOT, file))).digest("hex")}`;
}

function implementationIdentity() {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  const entries = SOURCE_PATHS.map((file) => ethers.keccak256(coder.encode(
    ["bytes32", "bytes32"],
    [ethers.id(file), sha256File(file)]
  )));
  const implementationHash = ethers.keccak256(coder.encode(
    ["bytes32", "bytes32[6]"],
    [auth.PHIL_ROUTINE_DOMAIN_HASHES_V1.IMPLEMENTATION_SET, entries]
  ));
  const auditStatusHash = ethers.keccak256(coder.encode(
    ["bytes32", "uint8", "bytes32", "bytes32"],
    [auth.PHIL_ROUTINE_DOMAIN_HASHES_V1.AUDIT_STATUS, 1, implementationHash, ZERO]
  ));
  return Object.freeze({ sourcePaths: SOURCE_PATHS, entries, implementationHash, auditStatusHash });
}

function syntheticPrivateKey() {
  const order = p256.CURVE.n;
  const value = (BigInt(ethers.id("PHIL_STEP6C_DISCLOSED_SYNTHETIC_DEVICE_KEY_V1")) % (order - 1n)) + 1n;
  return ethers.getBytes(ethers.toBeHex(value, 32));
}

function rawSignature(digest, privateKey) {
  const signature = p256.sign(ethers.getBytes(digest), privateKey, { lowS: true, prehash: false });
  return p256Wire.encodePhilP256RawSignatureV2({
    r: ethers.toBeHex(signature.r, 32),
    s: ethers.toBeHex(signature.s, 32)
  });
}

function toContractAction(action) {
  return {
    target: action.target,
    targetCalldataHash: action.targetCalldataHash,
    valueWei: action.valueWei,
    nonceKey: action.nonceKey,
    nonceSequence: action.nonceSequence,
    callGasLimit: action.callGasLimit,
    verificationGasLimit: action.verificationGasLimit,
    preVerificationGas: action.preVerificationGas,
    maxFeePerGas: action.maxFeePerGas,
    maxPriorityFeePerGas: action.maxPriorityFeePerGas,
    validAfter: action.validAfter,
    validUntil: action.validUntil
  };
}

function toContractEnvelope(envelope) {
  return { ...envelope };
}

function toContractApproval(request) {
  return {
    formatVersionHash: PHIL_DEVICE_APPROVAL_V1_HASH,
    authorizationEnvelopeDigest: request.authorizationEnvelopeDigest,
    ...request.unsignedDeviceApproval
  };
}

function toContractPresentation(presentation) {
  const { humanPresentationHash: _hash, ...wire } = presentation;
  return wire;
}

function toContractCore(core) {
  const { authorizationCoreDigest: _digest, ...wire } = core;
  return wire;
}

function packedGas(high, low) {
  return ethers.hexlify(ethers.concat([
    ethers.zeroPadValue(ethers.toBeHex(high), 16),
    ethers.zeroPadValue(ethers.toBeHex(low), 16)
  ]));
}

function serializePackedUserOperation(userOp) {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "uint256", "bytes", "bytes", "bytes32", "uint256", "bytes32", "bytes", "bytes"],
    [userOp.sender, userOp.nonce, userOp.initCode, userOp.callData, userOp.accountGasLimits,
      userOp.preVerificationGas, userOp.gasFees, userOp.paymasterAndData, userOp.signature]
  );
}

function eventCommitment(log) {
  const topics = [...log.topics, ZERO, ZERO, ZERO].slice(0, 4);
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
    [log.address, topics[0], topics[1], topics[2], topics[3], ethers.keccak256(log.data),
      log.index, log.transactionHash, log.blockHash]
  ));
}

async function deployStep6CFixture({ fundDeposit = true,
  targetContractName = "PhilV1Step6CHarmlessTarget" } = {}) {
  const [deployer, beneficiary] = await ethers.getSigners();
  const EntryPoint = await ethers.getContractFactory(
    "@account-abstraction/contracts/core/EntryPoint.sol:EntryPoint"
  );
  const entryPoint = await EntryPoint.deploy();
  await entryPoint.waitForDeployment();
  const entryPointAddress = (await entryPoint.getAddress()).toLowerCase();
  const senderCreator = ethers.getCreateAddress({ from: entryPointAddress, nonce: 1 }).toLowerCase();
  const entryPointCode = await ethers.provider.getCode(entryPointAddress);
  const senderCreatorCode = await ethers.provider.getCode(senderCreator);
  if (entryPointCode === "0x" || senderCreatorCode === "0x") throw new Error("official EntryPoint deployment incomplete");

  const Target = await ethers.getContractFactory(targetContractName);
  const target = await Target.deploy();
  await target.waitForDeployment();
  const targetAddress = (await target.getAddress()).toLowerCase();
  const targetCodeHash = ethers.keccak256(await ethers.provider.getCode(targetAddress));

  const Account = await ethers.getContractFactory("PhilV1Step6CAccount");
  const accountArtifact = await artifacts.readArtifact("PhilV1Step6CAccount");
  const accountRuntimeCodeHash = ethers.keccak256(accountArtifact.deployedBytecode);
  const deployerNonce = await ethers.provider.getTransactionCount(deployer.address);
  const predictedAccount = ethers.getCreateAddress({ from: deployer.address, nonce: deployerNonce }).toLowerCase();

  const identity = implementationIdentity();
  const environment = auth.createPhilExecutionEnvironmentV1({
    entryPoint: entryPointAddress,
    entryPointRuntimeCodeHash: ethers.keccak256(entryPointCode),
    senderCreator,
    senderCreatorRuntimeCodeHash: ethers.keccak256(senderCreatorCode)
  });
  const manifest = auth.createPhilStep6CLocalAdapterManifestV1(identity);
  const signatureRegistry = registryApi.createPhilRoutineSignatureRegistryV2();
  const privateKey = syntheticPrivateKey();
  const publicKeyX963 = ethers.hexlify(p256.getPublicKey(privateKey, false));
  const enrollment = auth.createPhilRoutineDeviceEnrollmentV2({
    deviceId: ethers.id("PHIL_STEP6C_SYNTHETIC_DEVICE_ID_V1"),
    deviceKeyId: ethers.id("PHIL_STEP6C_SYNTHETIC_DEVICE_KEY_ID_V1"),
    signatureRegistry,
    publicKeyX963,
    secureEnclaveBacked: false,
    userPresenceRequired: false
  });
  const configuration = auth.createPhilRoutineAccountConfigurationV1({
    environment,
    adapterManifest: manifest,
    enrollment,
    account: predictedAccount,
    accountRuntimeCodeHash,
    scopedOwnerCommitment: ethers.id("PHIL_STEP6C_SYNTHETIC_SCOPED_OWNER_V1"),
    approvedTarget: targetAddress,
    approvedTargetRuntimeCodeHash: targetCodeHash,
    nonceKey: 0,
    maximumValueWei: 0,
    maximumTotalFeeWei: 20_000_000
  });
  const parameterSchemaId = auth.derivePhilRoutineParameterSchemaIdV1(configuration);
  const catalog = auth.createPhilRoutineCatalogV1({ environment, configuration, parameterSchemaId });
  const latest = await ethers.provider.getBlock("latest");
  const profilePolicyValidAfter = BigInt(latest.timestamp);
  const policy = auth.createPhilRoutineCapabilityPolicyV1({
    environment,
    adapterManifest: manifest,
    enrollment,
    configuration,
    catalog,
    profilePolicyValidAfter
  });

  const constructorConfig = {
    entryPoint: entryPointAddress,
    executionEnvironmentHash: environment.executionEnvironmentHash,
    adapterManifestHash: manifest.manifestHash,
    signatureRegistryHash: signatureRegistry.registryHash,
    deviceEnrollmentHash: enrollment.deviceEnrollmentHash,
    accountConfigurationHash: configuration.accountConfigurationHash,
    catalogHash: catalog.catalogHash,
    capabilityPolicyHash: policy.capabilityPolicyHash,
    catalogDisplayTextHashes: auth.PHIL_STEP6C_CATALOG_TEXT_HASHES,
    accountRuntimeCodeHash,
    applicationId: configuration.applicationId,
    principalIdHash: configuration.principalIdHash,
    scopedOwnerCommitment: configuration.scopedOwnerCommitment,
    scopeId: configuration.scopeId,
    scopeInstance: configuration.scopeInstance,
    scopeEpoch: 1,
    capabilityId: policy.capabilityId,
    capabilityEpoch: 1,
    policyEpoch: 1,
    deviceId: enrollment.deviceId,
    deviceKeyId: enrollment.deviceKeyId,
    deviceEpoch: 1,
    signatureSuiteId: enrollment.signatureSuiteId,
    providerProfileId: enrollment.providerProfileId,
    wireEncodingId: enrollment.wireEncodingId,
    publicKeyX: enrollment.publicKeyX,
    publicKeyY: enrollment.publicKeyY,
    recoveryEpoch: 1,
    validatorEpoch: 1,
    approvedTarget: targetAddress,
    approvedTargetRuntimeCodeHash: targetCodeHash,
    actionTypeHash: adapter.PHIL_EVM_SINGLE_CALL_V1_HASH,
    parameterSchemaId,
    nonceKey: 0,
    maximumValueWei: 0,
    maximumTotalFeeWei: configuration.maximumTotalFeeWei,
    profilePolicyValidAfter: policy.validAfter,
    profilePolicyValidUntil: policy.validUntil
  };
  const account = await Account.deploy(constructorConfig);
  await account.waitForDeployment();
  if ((await account.getAddress()).toLowerCase() !== predictedAccount) throw new Error("predicted account mismatch");
  if (ethers.keccak256(await ethers.provider.getCode(predictedAccount)) !== accountRuntimeCodeHash) {
    throw new Error("account runtime code hash mismatch");
  }
  const depositBefore = await entryPoint.balanceOf(predictedAccount);
  if (fundDeposit) await (await entryPoint.depositTo(predictedAccount, { value: ethers.parseEther("1") })).wait();

  return {
    deployer,
    beneficiary,
    entryPoint,
    entryPointAddress,
    senderCreator,
    target,
    targetAddress,
    account,
    accountAddress: predictedAccount,
    environment,
    manifest,
    signatureRegistry,
    enrollment,
    configuration,
    parameterSchemaId,
    catalog,
    policy,
    identity,
    privateKey,
    accountRuntimeCodeHash,
    targetCodeHash,
    entryPointCodeHash: ethers.keccak256(entryPointCode),
    senderCreatorCodeHash: ethers.keccak256(senderCreatorCode),
    reentrancySlot: await ethers.provider.getStorage(entryPointAddress, REENTRANCY_SLOT),
    constructorConfig,
    depositBefore
  };
}

async function buildRequestForNonce(fixture, { nonceSequence, shouldRevert, issuedAt, sessionLabel }) {
  const targetCalldata = fixture.target.interface.encodeFunctionData("record", [
    auth.PHIL_STEP6C_RECORDED_VALUE,
    shouldRevert
  ]);
  const action = adapter.createPhilEvmSingleCallV1({
    chainId: auth.PHIL_STEP6C_CHAIN_ID,
    account: fixture.accountAddress,
    entryPoint: fixture.entryPointAddress,
    target: fixture.targetAddress,
    targetCalldataHash: ethers.keccak256(targetCalldata),
    valueWei: 0,
    nonceKey: 0,
    nonceSequence,
    callGasLimit: 350_000,
    verificationGasLimit: 4_000_000,
    preVerificationGas: 100_000,
    maxFeePerGas: 1,
    maxPriorityFeePerGas: 0,
    validAfter: issuedAt,
    validUntil: BigInt(issuedAt) + 120n
  });
  const request = auth.createPhilRoutineAuthorizationRequestV1({
    executionEnvironment: fixture.environment,
    adapterManifest: fixture.manifest,
    signatureRegistry: fixture.signatureRegistry,
    deviceEnrollment: fixture.enrollment,
    accountConfiguration: fixture.configuration,
    catalog: fixture.catalog,
    capabilityPolicy: fixture.policy,
    action,
    targetCalldata,
    sessionId: ethers.id(`PHIL_STEP6C_SESSION:${sessionLabel}`),
    nonceSeed: ethers.id(`PHIL_STEP6C_NONCE_SEED:${sessionLabel}`),
    issuedAt,
    expiresAt: BigInt(issuedAt) + 120n
  });
  const signature = rawSignature(request.platformSigningDigest, fixture.privateKey);
  const response = auth.createPhilRoutineAuthorizationResponseV1({ request, signature });
  const callData = fixture.account.interface.encodeFunctionData("executeAuthorized", [
    toContractAction(request.action),
    toContractEnvelope(request.authorizationEnvelope),
    toContractApproval(request),
    toContractPresentation(request.humanPresentation),
    toContractCore(request.authorizationCore),
    request.targetCalldata
  ]);
  const userOp = {
    sender: fixture.accountAddress,
    nonce: action.userOpNonce,
    initCode: "0x",
    callData,
    accountGasLimits: packedGas(action.verificationGasLimit, action.callGasLimit),
    preVerificationGas: action.preVerificationGas,
    gasFees: packedGas(action.maxPriorityFeePerGas, action.maxFeePerGas),
    paymasterAndData: "0x",
    signature
  };
  const userOpHash = await fixture.entryPoint.getUserOpHash(userOp);
  return { action, request, response, signature, callData, userOp, userOpHash, targetCalldata };
}

async function setNextTimestamp(timestamp) {
  await network.provider.send("evm_setNextBlockTimestamp", [Number(timestamp)]);
  await network.provider.send("evm_mine");
}

module.exports = {
  REENTRANCY_SLOT,
  SOURCE_PATHS,
  ZERO,
  auth,
  adapter,
  registryApi,
  p256Wire,
  implementationIdentity,
  syntheticPrivateKey,
  rawSignature,
  deployStep6CFixture,
  buildRequestForNonce,
  setNextTimestamp,
  toContractAction,
  toContractApproval,
  toContractCore,
  toContractEnvelope,
  toContractPresentation,
  packedGas,
  serializePackedUserOperation,
  eventCommitment
};
