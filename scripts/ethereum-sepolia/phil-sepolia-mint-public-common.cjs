"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");
require("tsx/cjs");
const {
  computePhilCore4337UserOperationHash
} = require("../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts");

const ROOT = path.resolve(__dirname, "../..");
const CHAIN_ID = 11155111;
const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
const APPROVAL_PHRASE = "I_APPROVE_THE_EXACT_PHIL_SEPOLIA_MINT_PUBLIC_MUTATIONS_V1";
const CONFIG_PATH = path.join(ROOT, "config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_V1.json");
const PREFLIGHT_PATH = path.join(ROOT, "config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_READ_ONLY_PREFLIGHT.json");
const DEFAULT_PLAN_PATH = path.join(ROOT, "artifacts/phil-sepolia-mint/public-mutation-plan-v1.json");
const DEFAULT_RECEIPT_PATH = path.join(ROOT, "artifacts/phil-sepolia-mint/public-mutation-receipt-v1.json");
const LEGACY_ALPHA_RUNNER_RETIRED_CODE =
  "PHIL_SEPOLIA_MINT_LEGACY_ALPHA_RUNNER_RETIRED_USE_CONTROLLED_BETA_STAGES";

const factoryInterface = new ethers.Interface([
  "function createAccount(address executionOwner,bytes32 ownerCommitment,uint256 salt) returns (address)",
  "function isPhilSepoliaMintAccount(address account) view returns (bool)"
]);
const accountInterface = new ethers.Interface([
  "function execute(address target,uint256 value,bytes data)"
]);
const gateInterface = new ethers.Interface([
  "function verifyAndConsume(bytes32 authorizationEnvelopeDigest,bytes32 rootProofNullifier,bytes32 deviceApprovalNonce,uint64 validUntil,address mintRecipient)",
  "function consumedEnvelopeDigest(bytes32) view returns (bool)",
  "function consumedRootNullifier(bytes32) view returns (bool)",
  "function consumedDeviceApprovalNonce(bytes32) view returns (bool)",
  "event PhilSepoliaLocalComposedAuthorizationConsumed(bytes32 indexed authorizationEnvelopeDigest,bytes32 indexed rootProofNullifier,bytes32 indexed deviceApprovalNonce,address account,address recipient,uint256 tokenId)"
]);
const consumerInterface = new ethers.Interface([
  "function tokenIdByEnvelopeDigest(bytes32) view returns (uint256)",
  "function tokenIdByRootNullifier(bytes32) view returns (uint256)",
  "function ownerOf(uint256) view returns (address)",
  "event PhilSepoliaMintPassIssued(bytes32 indexed authorizationEnvelopeDigest,bytes32 indexed rootProofNullifier,address indexed recipient,uint256 tokenId)"
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function assertLegacyAlphaRunnerRetired() {
  fail(LEGACY_ALPHA_RUNNER_RETIRED_CODE);
}

function readJson(location) {
  return JSON.parse(fs.readFileSync(location, "utf8"));
}

function atomicWriteJson(location, value) {
  fs.mkdirSync(path.dirname(location), { recursive: true, mode: 0o700 });
  const temporary = `${location}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  fs.renameSync(temporary, location);
  fs.chmodSync(location, 0o600);
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, nested]) => [key, stable(nested)]));
  }
  return value;
}

function canonicalDigest(value) {
  return ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(stable(value))));
}

function required(name) {
  const value = process.env[name];
  if (!value) fail(`${name}_REQUIRED`);
  return value;
}

function sanitizedEndpoint(value) {
  const parsed = new URL(value);
  return `${parsed.protocol}//${parsed.hostname}/<redacted>`;
}

function endpointDigest(value) {
  // Parsing first rejects non-URL inputs while the digest binds the complete
  // credential-bearing endpoint without serializing it into plan evidence.
  new URL(value);
  return `0x${crypto.createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function assertEndpointBindings(bindings, rpcUrl, bundlerUrl) {
  const expected = {
    rpcUrlSha256: endpointDigest(rpcUrl),
    bundlerUrlSha256: endpointDigest(bundlerUrl)
  };
  if (!bindings || JSON.stringify(bindings) !== JSON.stringify(expected)) {
    fail("PHIL_SEPOLIA_MINT_ENDPOINT_BINDING_MISMATCH");
  }
  return expected;
}

function artifact(relative) {
  const value = readJson(path.join(ROOT, "artifacts", relative));
  if (!value?.abi || !/^0x[0-9a-f]+$/iu.test(value.bytecode || "")) {
    fail("PHIL_SEPOLIA_MINT_ARTIFACT_INVALID");
  }
  return value;
}

function artifacts() {
  const compiled = {
    factory: artifact("contracts/base/erc4337/PhilSepoliaMintAccountFactoryV1.sol/PhilSepoliaMintAccountFactoryV1.json"),
    account: artifact("contracts/base/erc4337/PhilSepoliaMintAccountV1.sol/PhilSepoliaMintAccountV1.json"),
    actionGate: artifact("contracts/base/PhilSepoliaLocalComposedActionGateV1.sol/PhilSepoliaLocalComposedActionGateV1.json"),
    mintConsumer: artifact("contracts/base/PhilSepoliaMintPassConsumerV1.sol/PhilSepoliaMintPassConsumerV1.json")
  };
  assertArtifactBytecodeHashes(compiled, readJson(PREFLIGHT_PATH).bytecodeHashes);
  return compiled;
}

function assertArtifactBytecodeHashes(compiled, frozenHashes) {
  const actual = {
    factoryCreationCode: ethers.keccak256(compiled.factory.bytecode),
    accountCreationCode: ethers.keccak256(compiled.account.bytecode),
    actionGateCreationCode: ethers.keccak256(compiled.actionGate.bytecode),
    mintConsumerCreationCode: ethers.keccak256(compiled.mintConsumer.bytecode)
  };
  if (!frozenHashes || JSON.stringify(actual) !== JSON.stringify(frozenHashes)) {
    fail("PHIL_SEPOLIA_MINT_FROZEN_ARTIFACT_BYTECODE_MISMATCH");
  }
  return actual;
}

function unpack128(value) {
  const packed = BigInt(value);
  return { high: packed >> 128n, low: packed & ((1n << 128n) - 1n) };
}

function rpcV07(userOperation) {
  const initCode = userOperation.initCode;
  const paymasterAndData = userOperation.paymasterAndData;
  if (!/^0x[0-9a-f]*$/iu.test(initCode) || initCode.length < 42) fail("PHIL_SEPOLIA_MINT_INIT_CODE_INVALID");
  if (paymasterAndData !== "0x") fail("PHIL_SEPOLIA_MINT_PAYMASTER_FORBIDDEN");
  const gas = unpack128(userOperation.accountGasLimits);
  const fees = unpack128(userOperation.gasFees);
  return {
    sender: ethers.getAddress(userOperation.sender),
    nonce: ethers.toQuantity(userOperation.nonce),
    factory: ethers.getAddress(initCode.slice(0, 42)),
    factoryData: `0x${initCode.slice(42)}`,
    callData: userOperation.callData,
    verificationGasLimit: ethers.toQuantity(gas.high),
    callGasLimit: ethers.toQuantity(gas.low),
    preVerificationGas: ethers.toQuantity(userOperation.preVerificationGas),
    maxFeePerGas: ethers.toQuantity(fees.low),
    maxPriorityFeePerGas: ethers.toQuantity(fees.high),
    paymaster: null,
    signature: userOperation.signature
  };
}

function parseSignedArtifact(signed, config, compiled) {
  if (signed?.format !== "phil-sepolia-mint-signed-unsubmitted-v1"
    || signed.signed !== true || signed.submitted !== false
    || signed.ethereumVerifiesNoirProof !== false || signed.ethereumVerifiesP256Approval !== false) {
    fail("PHIL_SEPOLIA_MINT_SIGNED_ARTIFACT_INVALID");
  }
  const op = signed.userOperation;
  const rpc = rpcV07(op);
  if (rpc.factory.toLowerCase() !== config.infrastructure.factory.toLowerCase()
    || rpc.sender.toLowerCase() !== signed.smartAccount.toLowerCase()
    || BigInt(op.nonce) !== 0n) fail("PHIL_SEPOLIA_MINT_OPERATION_BINDING_INVALID");
  const factoryCall = factoryInterface.parseTransaction({ data: rpc.factoryData });
  if (!factoryCall || factoryCall.name !== "createAccount") fail("PHIL_SEPOLIA_MINT_FACTORY_CALL_INVALID");
  const [executionOwner, ownerCommitment, salt] = factoryCall.args;
  if (BigInt(salt) !== BigInt(config.accountSalt)) fail("PHIL_SEPOLIA_MINT_ACCOUNT_SALT_INVALID");
  const constructor = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "address", "bytes32", "address"],
    [config.entryPoint, executionOwner, ownerCommitment, config.infrastructure.actionGate]
  );
  const predicted = ethers.getCreate2Address(
    config.infrastructure.factory,
    config.accountSalt,
    ethers.keccak256(ethers.concat([compiled.account.bytecode, constructor]))
  );
  if (predicted.toLowerCase() !== rpc.sender.toLowerCase()) fail("PHIL_SEPOLIA_MINT_COUNTERFACTUAL_ACCOUNT_INVALID");
  const accountCall = accountInterface.parseTransaction({ data: op.callData });
  if (!accountCall || accountCall.name !== "execute"
    || accountCall.args[0].toLowerCase() !== config.infrastructure.actionGate.toLowerCase()
    || BigInt(accountCall.args[1]) !== 0n) fail("PHIL_SEPOLIA_MINT_ACCOUNT_CALL_INVALID");
  const gateCall = gateInterface.parseTransaction({ data: accountCall.args[2] });
  if (!gateCall || gateCall.name !== "verifyAndConsume") fail("PHIL_SEPOLIA_MINT_GATE_CALL_INVALID");
  const [envelope, nullifier, approvalNonce, validUntil, recipient] = gateCall.args;
  if (envelope.toLowerCase() !== signed.authorizationEnvelopeDigest.toLowerCase()
    || nullifier.toLowerCase() !== signed.rootProofNullifier.toLowerCase()
    || approvalNonce.toLowerCase() !== signed.deviceApprovalNonce.toLowerCase()
    || recipient.toLowerCase() !== rpc.sender.toLowerCase()) fail("PHIL_SEPOLIA_MINT_GATE_BINDING_INVALID");
  const localHash = computePhilCore4337UserOperationHash({
    userOperation: op,
    entryPointAddress: config.entryPoint,
    chainId: CHAIN_ID
  });
  if (localHash.toLowerCase() !== signed.userOperationHash.toLowerCase()) fail("PHIL_SEPOLIA_MINT_USER_OPERATION_HASH_INVALID");
  if (ethers.verifyMessage(ethers.getBytes(localHash), op.signature).toLowerCase()
    !== executionOwner.toLowerCase()) fail("PHIL_SEPOLIA_MINT_EXECUTION_SIGNATURE_INVALID");
  const gas = unpack128(op.accountGasLimits);
  const fees = unpack128(op.gasFees);
  const maximum = (gas.high + gas.low + BigInt(op.preVerificationGas)) * fees.low;
  if (maximum !== BigInt(signed.maximumTotalFeeWei)
    || maximum > BigInt(config.maximumTotalFeeWei)) fail("PHIL_SEPOLIA_MINT_FEE_BINDING_INVALID");
  return {
    rpc,
    executionOwner: ethers.getAddress(executionOwner),
    ownerCommitment,
    validUntil: BigInt(validUntil),
    recipient: ethers.getAddress(recipient),
    maximumTotalFeeWei: maximum,
    localUserOperationHash: localHash
  };
}

async function deploymentTransactions(config, compiled, provider) {
  const plans = [
    ["factory", compiled.factory, [ENTRY_POINT, config.infrastructure.actionGate]],
    ["actionGate", compiled.actionGate, [CHAIN_ID, config.infrastructure.factory, config.infrastructure.mintConsumer]],
    ["mintConsumer", compiled.mintConsumer, [config.infrastructure.actionGate]]
  ];
  const result = [];
  for (let index = 0; index < plans.length; index += 1) {
    const [label, item, args] = plans[index];
    const nonce = Number(config.startingNonce) + index;
    const expected = config.infrastructure[label];
    const data = (await new ethers.ContractFactory(item.abi, item.bytecode).getDeployTransaction(...args)).data;
    if (ethers.getCreateAddress({ from: config.deployer, nonce }).toLowerCase() !== expected.toLowerCase()) {
      fail("PHIL_SEPOLIA_MINT_DEPLOYMENT_ADDRESS_INVALID");
    }
    const estimated = await provider.estimateGas({ from: config.deployer, nonce, data });
    const gasLimit = estimated * 125n / 100n;
    result.push({ label, nonce: String(nonce), expectedContractAddress: ethers.getAddress(expected), data, dataHash: ethers.keccak256(data), gasEstimate: estimated.toString(), gasLimit: gasLimit.toString() });
  }
  return result;
}

module.exports = {
  ROOT, CHAIN_ID, ENTRY_POINT, APPROVAL_PHRASE, CONFIG_PATH, PREFLIGHT_PATH,
  DEFAULT_PLAN_PATH, DEFAULT_RECEIPT_PATH, factoryInterface, gateInterface,
  consumerInterface, fail, readJson, atomicWriteJson, canonicalDigest, required,
  sanitizedEndpoint, endpointDigest, assertEndpointBindings, artifacts, rpcV07,
  parseSignedArtifact, deploymentTransactions, assertArtifactBytecodeHashes,
  LEGACY_ALPHA_RUNNER_RETIRED_CODE, assertLegacyAlphaRunnerRetired
};
