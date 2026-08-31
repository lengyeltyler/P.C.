"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { ethers } = require("ethers");
require("tsx/cjs");
const {
  computePhilCore4337UserOperationHash
} = require("../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts");
const p1 = require("./philcore-controlled-sepolia-beta-p1-common.cjs");

const P2_MUTATION_COUNT = 2;
const P2_RECOVERY_MUTATION_COUNT = 1;
const MINIMUM_BUNDLER_PRIORITY_FEE_WEI = 100_000_000n;
const P2_FINAL_VERIFICATION_GAS_LIMIT = 150_000n;
const P3_VERIFICATION_GAS_LIMIT = 80_000n;
const P2_FINAL_ORIGIN = Object.freeze({
  planDigest: "0xde6052b2b94b28118afa05d4cbc73b343b893171991818d020610ef7d0da836e",
  receiptByteSha256: "0x821dfa42c6c554725a6a31d7038ca7487dde1a2a8d51a2de60a5a7481efecec7",
  userOperationHash: "0x0d96fa9ff4fd9a0fe3717b217b3151fbfeda51d682bf9d071b350086e251b670",
  transactionHash: "0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934",
  blockNumber: "11573471",
  authorizationEnvelopeDigest:
    "0xe4962daa72bb3d11de8054959f9c012b1feff7e173093e09d91fdbc005a37f46",
  rootProofNullifier:
    "0xd4eea817f0068971cd0b9c9170525884e4b3ce6b0ea4f2bcf36ec3aba075b452",
  deviceApprovalNonce:
    "0x314c40d0d8f71c9385f6c1155844d744a6685a5d3f37a3e745f456862692078b",
  tokenId: "1",
  resultingNonce: "1",
  entryPointDepositWei: "779861479486230",
  resultingBalance: "1",
  resultingNextTokenId: "2"
});
const P3_REJECTED_SUBMISSION_ORIGIN = Object.freeze({
  planDigest: "0x211ce78797e0c9a85d7b2071bfc280e4fa98c3de316ca565bacdc09bcceb7b45",
  userOperationHash: "0x3cb1fffacce39bfdabce03f4636375f04f623f95c82aa0d445ea74f89e9ca843",
  verificationGasLimit: "150000",
  requiredEfficiency: "0.4",
  observedEfficiency: "0.2502533333333333",
  rpcCode: -32602,
  rejection: "VERIFICATION_GAS_LIMIT_EFFICIENCY_TOO_LOW",
  resultingNonce: "1",
  resultingNextTokenId: "2"
});
const P2_RECOVERY_ORIGIN = Object.freeze({
  originalPlanDigest: "0x23467979ac3c95b6f7aa2c288292aa4718b4ae5c94e2998636ed7f9868ae0997",
  originalSourceCommit: "93966d02da445cc871447874aa8959e62ccd02cb",
  originalSourceTree: "47500c8ba00ad9d4ea73c3eca80e95e2790f631c",
  confirmedFundingTransactionHash:
    "0x60029b4b50246fa4c318caaf61ea184b838d6c28e2c41be6782409ff15136c9a",
  confirmedFundingBlockNumber: "11568484",
  confirmedFundingValueWei: "4840000000000000",
  confirmedFundingGasUsed: "21000",
  rejectedUserOperationHash:
    "0xff258b993d44b5d8729b1bee326887b9e65166b71bbf0337525f03be5e9e2cf6",
  originalAuthorizationEnvelopeDigest:
    "0xc5721ce3ab6d32bb09a3ab48d559f459dfe1deaf0fe79dfed22c0bc0871ce7e7",
  originalRootProofNullifier:
    "0xc102a31e0f9b17cf603c46fe94b6ea3f881b86375e20d6787db1e6c9e50b8b2d",
  originalDeviceApprovalNonce:
    "0xc20c377ea13fd1bc135948861a3a757da9b2603b0d9d8dc831c6045564b61f0d",
  rejectionCode: -32000,
  rejectionMessage:
    "precheck failed: maxPriorityFeePerGas is 1000000 but must be at least 100000000"
});
const PROVIDER_OPTIONS = Object.freeze({ staticNetwork: true, batchMaxCount: 1 });
const CONFIG_PATH = path.join(
  p1.ROOT,
  "config/ethereum-sepolia/PHILCORE_CONTROLLED_SEPOLIA_BETA_P2_V1.json"
);
const PRIVATE_EVIDENCE_ROOT = path.join(
  p1.ROOT, ".philcore-local/controlled-sepolia-beta"
);
const DEFAULT_SIGNED_ARTIFACT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-signed-unsubmitted-v1.json"
);
const DEFAULT_PLAN_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-plan.json"
);
const DEFAULT_RECEIPT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-receipt.json"
);
const DEFAULT_EXECUTION_LOCK_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-execution-attempt.lock.json"
);
const DEFAULT_RECOVERY_SIGNED_ARTIFACT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-recovery-signed-unsubmitted-v1.json"
);
const DEFAULT_RECOVERY_PLAN_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-recovery-plan.json"
);
const DEFAULT_RECOVERY_RECEIPT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-recovery-receipt.json"
);
const DEFAULT_RECOVERY_EXECUTION_LOCK_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-recovery-execution-attempt.lock.json"
);
const DEFAULT_ACCOUNT_DEPLOYMENT_PLAN_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-account-deployment-plan.json"
);
const DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-account-deployment-receipt.json"
);
const DEFAULT_ACCOUNT_DEPLOYMENT_EXECUTION_LOCK_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-account-deployment-execution-attempt.lock.json"
);
const DEFAULT_ACCOUNT_DEPLOYMENT_RECONCILIATION_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-account-deployment-reconciliation.json"
);
const DEFAULT_ACCOUNT_DEPLOYMENT_STOPPED_RECEIPT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-account-deployment-stopped-receipt.json"
);
const DEFAULT_FINAL_SIGNED_ARTIFACT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-final-signed-unsubmitted-v1.json"
);
const DEFAULT_FINAL_PLAN_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-final-plan.json"
);
const DEFAULT_FINAL_RECEIPT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-final-receipt.json"
);
const DEFAULT_FINAL_EXECUTION_LOCK_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p2-final-execution-attempt.lock.json"
);
const DEFAULT_P3_SIGNED_ARTIFACT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p3-signed-unsubmitted-v1.json"
);
const DEFAULT_P3_PLAN_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p3-plan.json"
);
const DEFAULT_P3_RECEIPT_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p3-receipt.json"
);
const DEFAULT_P3_EXECUTION_LOCK_PATH = path.join(
  PRIVATE_EVIDENCE_ROOT, "p3-execution-attempt.lock.json"
);

const factoryInterface = new ethers.Interface([
  "function createAccount(address owner,bytes32 ownerCommitment,uint256 salt) returns (address)",
  "function getAddress(address owner,bytes32 ownerCommitment,uint256 salt) view returns (address)",
  "function isPhilSepoliaMintAccount(address account) view returns (bool)",
  "function entryPoint() view returns (address)",
  "function approvedActionGate() view returns (address)",
  "function recoveryAuthority() view returns (address)",
  "function recoveryDelaySeconds() view returns (uint64)",
  "function recoveryExpirySeconds() view returns (uint64)",
  "event PhilCore4337AccountCreated(address indexed account,address indexed owner,bytes32 indexed ownerCommitment,address approvedActionGate,address recoveryAuthority,uint256 salt)"
]);
const accountInterface = new ethers.Interface([
  "function execute(address target,uint256 value,bytes data)",
  "function owner() view returns (address)",
  "function ownerCommitment() view returns (bytes32)",
  "function approvedActionGate() view returns (address)",
  "function recoveryAuthority() view returns (address)",
  "function entryPoint() view returns (address)",
  "function recoveryDelaySeconds() view returns (uint64)",
  "function recoveryExpirySeconds() view returns (uint64)"
]);
const gateInterface = new ethers.Interface([
  "function expectedChainId() view returns (uint256)",
  "function accountFactory() view returns (address)",
  "function mintConsumer() view returns (address)",
  "function authorizedAccount() view returns (address)",
  "function consumedEnvelopeDigest(bytes32) view returns (bool)",
  "function consumedRootNullifier(bytes32) view returns (bool)",
  "function consumedDeviceApprovalNonce(bytes32) view returns (bool)",
  "function verifyAndConsume(bytes32 authorizationEnvelopeDigest,bytes32 rootProofNullifier,bytes32 deviceApprovalNonce,uint64 validUntil,address mintRecipient)",
  "event PhilSepoliaLocalComposedAuthorizationConsumed(bytes32 indexed authorizationEnvelopeDigest,bytes32 indexed rootProofNullifier,bytes32 indexed deviceApprovalNonce,address account,address recipient,uint256 tokenId)"
]);
const consumerInterface = new ethers.Interface([
  "function actionGate() view returns (address)",
  "function nextTokenId() view returns (uint256)",
  "function ownerOf(uint256) view returns (address)",
  "function balanceOf(address) view returns (uint256)",
  "function tokenIdByEnvelopeDigest(bytes32) view returns (uint256)",
  "function tokenIdByRootNullifier(bytes32) view returns (uint256)",
  "event PhilSepoliaMintPassIssued(bytes32 indexed authorizationEnvelopeDigest,bytes32 indexed rootProofNullifier,address indexed recipient,uint256 tokenId)"
]);
const entryPointInterface = new ethers.Interface([
  "function getNonce(address sender,uint192 key) view returns (uint256)",
  "function balanceOf(address account) view returns (uint256)",
  "event UserOperationEvent(bytes32 indexed userOpHash,address indexed sender,address indexed paymaster,uint256 nonce,bool success,uint256 actualGasCost,uint256 actualGasUsed)"
]);

function sameAddress(left, right) {
  return ethers.getAddress(left).toLowerCase() === ethers.getAddress(right).toLowerCase();
}

function canonicalSignedArtifactAddress(value) {
  return ethers.getAddress(value).toLowerCase();
}

function sha256Bytes(value) {
  return `0x${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function loadConfiguration() {
  const value = p1.readJson(CONFIG_PATH);
  if (value?.format !== "philcore-controlled-sepolia-beta-p2-configuration-v1"
    || value.version !== 1
    || value.status !== "p1_infrastructure_confirmed_p2_not_authorized"
    || value.chainId !== String(p1.CHAIN_ID)
    || !sameAddress(value.entryPoint, p1.ENTRY_POINT)
    || value.publicMutationEnabled !== false
    || value.submissionEnabled !== false
    || value.automaticRetryAllowed !== false
    || Object.values(value.runtimeCodeHashes || {}).length !== 4
    || Object.values(value.runtimeCodeHashes || {}).some((hash) => (
      !/^0x[0-9a-f]{64}$/u.test(hash)
    ))
    || BigInt(value.maximumTotalFeeWei) > ethers.parseEther("0.005")
    || BigInt(value.maximumNativeAccountBalanceWei) !== ethers.parseEther("0.01")
    || BigInt(value.maximumEntryPointDepositWei) !== ethers.parseEther("0.01")
    || BigInt(value.maximumOperatorExposureWei) !== ethers.parseEther("0.05")
    || BigInt(value.gasPolicy?.maxPriorityFeePerGas || 0)
      < MINIMUM_BUNDLER_PRIORITY_FEE_WEI
    || BigInt(value.gasPolicy?.maxPriorityFeePerGas || 0)
      > BigInt(value.gasPolicy?.maxFeePerGas || 0)
    || p1.canonicalJson(value.phoneAssurance) !== p1.canonicalJson({
      assuranceClass: "trusted_philcore_ios_application_enforced_unattested",
      trustedPhilCoreIOSApplicationRequired: true,
      secureEnclaveBackedRecordRequired: true,
      userPresenceRequiredRecordRequired: true,
      p256ProofOfPossessionRequired: true,
      remoteHardwareAttestationEstablished: false,
      maliciousAlternateClientResistanceClaimed: false
    })) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_CONFIGURATION_INVALID");
  }
  return Object.freeze(value);
}

function assertConfigurationMetadata(config, metadata) {
  const graph = p1.deploymentGraph({
    compiled: p1.artifacts(),
    deployer: metadata.addresses.deployer,
    startingNonce: 0,
    executionOwner: metadata.addresses.initialExecutionValidator,
    recoveryAuthority: metadata.addresses.initialRecoveryAuthority,
    ownerCommitment: metadata.ownerCommitment,
    accountSalt: metadata.accountSalt
  });
  if (!sameAddress(config.deployer, metadata.addresses.deployer)
    || !sameAddress(config.infrastructure.factory, graph.factory)
    || !sameAddress(config.infrastructure.actionGate, graph.gate)
    || !sameAddress(config.infrastructure.mintConsumer, graph.consumer)
    || !sameAddress(config.account.predictedAddress, graph.account)
    || !sameAddress(config.account.initialExecutionValidator, metadata.addresses.initialExecutionValidator)
    || !sameAddress(config.account.initialRecoveryAuthority, metadata.addresses.initialRecoveryAuthority)
    || config.account.ownerCommitment.toLowerCase() !== metadata.ownerCommitment.toLowerCase()
    || config.account.salt.toLowerCase() !== metadata.accountSalt.toLowerCase()) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_CONFIGURATION_METADATA_MISMATCH");
  }
  return graph;
}

function accountRuntimeIdentity(code) {
  if (!/^0x[0-9a-f]+$/iu.test(code || "") || code === "0x") {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_RUNTIME_INVALID");
  }
  const compiled = p1.artifacts().account.deployedBytecode;
  const debugPath = path.join(
    p1.ROOT,
    "artifacts/contracts/base/erc4337/PhilCore4337Account.sol/PhilCore4337Account.dbg.json"
  );
  const debug = p1.readJson(debugPath);
  const buildInfoPath = path.resolve(path.dirname(debugPath), debug.buildInfo || "");
  const buildInfo = p1.readJson(buildInfoPath);
  const references = buildInfo?.output?.contracts?.[
    "contracts/base/erc4337/PhilCore4337Account.sol"
  ]?.PhilCore4337Account?.evm?.deployedBytecode?.immutableReferences;
  if (!references || Object.keys(references).length !== 5) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_IMMUTABLE_REFERENCES_INVALID");
  }
  const expected = Buffer.from(compiled.slice(2), "hex");
  const actual = Buffer.from(code.slice(2), "hex");
  if (actual.length !== expected.length) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_RUNTIME_LENGTH_INVALID");
  }
  const normalizedExpected = Buffer.from(expected);
  const normalizedActual = Buffer.from(actual);
  const ranges = Object.values(references).flat();
  if (ranges.length !== 24) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_IMMUTABLE_RANGES_INVALID");
  }
  for (const reference of ranges) {
    if (!Number.isSafeInteger(reference?.start) || !Number.isSafeInteger(reference?.length)
      || reference.start < 0 || reference.length <= 0
      || reference.start + reference.length > actual.length) {
      p1.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_IMMUTABLE_RANGE_INVALID");
    }
    normalizedExpected.fill(0, reference.start, reference.start + reference.length);
    normalizedActual.fill(0, reference.start, reference.start + reference.length);
  }
  if (!normalizedActual.equals(normalizedExpected)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_RUNTIME_TEMPLATE_INVALID");
  }
  return Object.freeze({
    runtimeCodeHash: ethers.keccak256(code),
    immutableMaskedRuntimeCodeHash: ethers.keccak256(normalizedActual)
  });
}

function unpack128(value) {
  const packed = BigInt(value);
  return { high: packed >> 128n, low: packed & ((1n << 128n) - 1n) };
}

function assertFinalRuntimeCodeHashes(planned, configured) {
  const expectedKeys = [
    "account", "accountImmutableMasked", "consumer", "entryPoint", "factory", "gate"
  ];
  const infrastructure = Object.fromEntries(
    Object.keys(configured || {}).map((key) => [key, planned?.[key]])
  );
  if (p1.canonicalJson(Object.keys(planned || {}).sort()) !== p1.canonicalJson(expectedKeys)
    || p1.canonicalJson(infrastructure) !== p1.canonicalJson(configured)
    || !/^0x[0-9a-f]{64}$/u.test(planned?.account || "")
    || !/^0x[0-9a-f]{64}$/u.test(planned?.accountImmutableMasked || "")) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_RUNTIME_CODE_HASHES_INVALID");
  }
  return Object.freeze({ ...planned });
}

function rpcV07(userOperation, options = {}) {
  const initCode = String(userOperation?.initCode || "");
  const accountDeployed = options.accountDeployed === true;
  if (accountDeployed) {
    if (initCode !== "0x") p1.fail("PHILCORE_CONTROLLED_BETA_P2_INIT_CODE_MUST_BE_EMPTY");
  } else if (!/^0x[0-9a-f]+$/iu.test(initCode) || initCode.length <= 42) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_INIT_CODE_INVALID");
  }
  if (userOperation.paymasterAndData !== "0x") {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_PAYMASTER_FORBIDDEN");
  }
  const gas = unpack128(userOperation.accountGasLimits);
  const fees = unpack128(userOperation.gasFees);
  return Object.freeze({
    sender: ethers.getAddress(userOperation.sender),
    nonce: ethers.toQuantity(userOperation.nonce),
    factory: accountDeployed ? null : ethers.getAddress(initCode.slice(0, 42)),
    factoryData: accountDeployed ? null : `0x${initCode.slice(42)}`,
    callData: userOperation.callData,
    verificationGasLimit: ethers.toQuantity(gas.high),
    callGasLimit: ethers.toQuantity(gas.low),
    preVerificationGas: ethers.toQuantity(userOperation.preVerificationGas),
    maxFeePerGas: ethers.toQuantity(fees.low),
    maxPriorityFeePerGas: ethers.toQuantity(fees.high),
    paymaster: null,
    signature: userOperation.signature
  });
}

function parseSignedArtifact(signed, config, compiled, options = {}) {
  if (signed?.format !== "phil-sepolia-mint-signed-unsubmitted-v1"
    || signed.signed !== true || signed.submitted !== false
    || signed.ethereumVerifiesNoirProof !== false
    || signed.ethereumVerifiesP256Approval !== false
    || p1.canonicalJson(signed.phoneAssurance) !== p1.canonicalJson(config.phoneAssurance)
    || !/^0x[0-9a-f]{64}$/u.test(signed.authorizationEnvelopeDigest || "")
    || !/^0x[0-9a-f]{64}$/u.test(signed.rootProofNullifier || "")
    || !/^0x[0-9a-f]{64}$/u.test(signed.deviceApprovalNonce || "")) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_SIGNED_ARTIFACT_INVALID");
  }
  const op = signed.userOperation;
  const accountDeployed = options.accountDeployed === true;
  const expectedNonce = BigInt(options.expectedNonce ?? 0);
  const rpc = rpcV07(op, { accountDeployed });
  if ((!accountDeployed && !sameAddress(rpc.factory, config.infrastructure.factory))
    || (accountDeployed && rpc.factory !== null)
    || !sameAddress(rpc.sender, signed.smartAccount)
    || !sameAddress(rpc.sender, config.account.predictedAddress)
    || !sameAddress(signed.actionGate, config.infrastructure.actionGate)
    || BigInt(op.nonce) !== expectedNonce
    || BigInt(signed.accountNonce) !== expectedNonce) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_OPERATION_BINDING_INVALID");
  }
  let executionOwner = config.account.initialExecutionValidator;
  let ownerCommitment = config.account.ownerCommitment;
  let salt = config.account.salt;
  if (!accountDeployed) {
    const factoryCall = factoryInterface.parseTransaction({ data: rpc.factoryData });
    if (!factoryCall || factoryCall.name !== "createAccount") {
      p1.fail("PHILCORE_CONTROLLED_BETA_P2_FACTORY_CALL_INVALID");
    }
    [executionOwner, ownerCommitment, salt] = factoryCall.args;
  }
  if (!sameAddress(executionOwner, config.account.initialExecutionValidator)
    || String(ownerCommitment).toLowerCase() !== config.account.ownerCommitment.toLowerCase()
    || BigInt(salt) !== BigInt(config.account.salt)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_FACTORY_BINDING_INVALID");
  }
  const constructor = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "address", "bytes32", "address", "address", "uint64", "uint64"],
    [
      config.entryPoint,
      executionOwner,
      ownerCommitment,
      config.infrastructure.actionGate,
      config.account.initialRecoveryAuthority,
      p1.RECOVERY_DELAY_SECONDS,
      p1.RECOVERY_EXPIRY_SECONDS
    ]
  );
  const predicted = ethers.getCreate2Address(
    config.infrastructure.factory,
    ethers.zeroPadValue(ethers.toBeHex(BigInt(config.account.salt)), 32),
    ethers.keccak256(ethers.concat([compiled.account.bytecode, constructor]))
  );
  if (!sameAddress(predicted, rpc.sender)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_COUNTERFACTUAL_ACCOUNT_INVALID");
  }
  const accountCall = accountInterface.parseTransaction({ data: op.callData });
  if (!accountCall || accountCall.name !== "execute"
    || !sameAddress(accountCall.args[0], config.infrastructure.actionGate)
    || BigInt(accountCall.args[1]) !== 0n) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_CALL_INVALID");
  }
  const gateCall = gateInterface.parseTransaction({ data: accountCall.args[2] });
  if (!gateCall || gateCall.name !== "verifyAndConsume") {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_GATE_CALL_INVALID");
  }
  const [envelope, nullifier, approvalNonce, validUntil, recipient] = gateCall.args;
  if (String(envelope).toLowerCase() !== signed.authorizationEnvelopeDigest.toLowerCase()
    || String(nullifier).toLowerCase() !== signed.rootProofNullifier.toLowerCase()
    || String(approvalNonce).toLowerCase() !== signed.deviceApprovalNonce.toLowerCase()
    || !sameAddress(recipient, executionOwner)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_GATE_BINDING_INVALID");
  }
  const localHash = computePhilCore4337UserOperationHash({
    userOperation: op,
    entryPointAddress: config.entryPoint,
    chainId: p1.CHAIN_ID
  });
  if (localHash.toLowerCase() !== signed.userOperationHash.toLowerCase()
    || ethers.verifyMessage(ethers.getBytes(localHash), op.signature).toLowerCase()
      !== ethers.getAddress(executionOwner).toLowerCase()) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_EXECUTION_SIGNATURE_INVALID");
  }
  const gas = unpack128(op.accountGasLimits);
  const fees = unpack128(op.gasFees);
  const maximum = (gas.high + gas.low + BigInt(op.preVerificationGas)) * fees.low;
  if (maximum !== BigInt(signed.maximumTotalFeeWei)
    || maximum > BigInt(config.maximumTotalFeeWei)
    || fees.high < MINIMUM_BUNDLER_PRIORITY_FEE_WEI
    || fees.high > fees.low) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_FEE_BINDING_INVALID");
  }
  return Object.freeze({
    rpc,
    executionOwner: ethers.getAddress(executionOwner),
    ownerCommitment: String(ownerCommitment).toLowerCase(),
    validUntil: BigInt(validUntil),
    recipient: ethers.getAddress(recipient),
    maximumTotalFeeWei: maximum,
    localUserOperationHash: localHash,
    accountDeployed,
    gas: Object.freeze({
      verificationGasLimit: gas.high,
      callGasLimit: gas.low,
      preVerificationGas: BigInt(op.preVerificationGas),
      maxFeePerGas: fees.low,
      maxPriorityFeePerGas: fees.high
    })
  });
}

async function assertProviderPair(primary, reconciliation, config, parsed, options = {}) {
  const expectUnfunded = options.expectUnfunded !== false;
  const expectDeployed = options.expectDeployed === true;
  const expectedNonce = BigInt(options.expectedNonce ?? 0);
  const expectedNextTokenId = BigInt(options.expectedNextTokenId ?? 1);
  const expectedEntryPointDepositWei = BigInt(options.expectedEntryPointDepositWei ?? 0);
  const compiled = p1.artifacts();
  const [leftChain, rightChain] = await Promise.all([
    primary.send("eth_chainId", []), reconciliation.send("eth_chainId", [])
  ]);
  if (BigInt(leftChain) !== BigInt(p1.CHAIN_ID) || BigInt(rightChain) !== BigInt(p1.CHAIN_ID)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_WRONG_CHAIN");
  }
  for (const [label, address] of Object.entries({
    entryPoint: config.entryPoint,
    consumer: config.infrastructure.mintConsumer,
    gate: config.infrastructure.actionGate,
    factory: config.infrastructure.factory
  })) {
    const [left, right] = await Promise.all([primary.getCode(address), reconciliation.getCode(address)]);
    if (left === "0x" || left.toLowerCase() !== right.toLowerCase()
      || ethers.keccak256(left).toLowerCase() !== config.runtimeCodeHashes[label].toLowerCase()) {
      p1.fail(`PHILCORE_CONTROLLED_BETA_P2_${label.toUpperCase()}_CODE_INVALID`);
    }
  }
  const [leftAccountCode, rightAccountCode, leftAccountBalance, rightAccountBalance] = await Promise.all([
    primary.getCode(config.account.predictedAddress),
    reconciliation.getCode(config.account.predictedAddress),
    primary.getBalance(config.account.predictedAddress),
    reconciliation.getBalance(config.account.predictedAddress)
  ]);
  let deployedAccountRuntime = null;
  if (expectDeployed && leftAccountCode !== "0x" && rightAccountCode !== "0x"
    && leftAccountCode.toLowerCase() === rightAccountCode.toLowerCase()) {
    deployedAccountRuntime = accountRuntimeIdentity(leftAccountCode);
  }
  if ((expectDeployed && (!deployedAccountRuntime
      || leftAccountCode.toLowerCase() !== rightAccountCode.toLowerCase()))
    || (!expectDeployed && (leftAccountCode !== "0x" || rightAccountCode !== "0x"))
    || leftAccountBalance !== rightAccountBalance
    || (expectUnfunded && leftAccountBalance !== 0n)
    || leftAccountBalance > BigInt(config.maximumNativeAccountBalanceWei)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_ACCOUNT_STATE_INVALID");
  }
  const consumerLeft = new ethers.Contract(config.infrastructure.mintConsumer, compiled.consumer.abi, primary);
  const consumerRight = new ethers.Contract(config.infrastructure.mintConsumer, compiled.consumer.abi, reconciliation);
  const gateLeft = new ethers.Contract(config.infrastructure.actionGate, compiled.gate.abi, primary);
  const gateRight = new ethers.Contract(config.infrastructure.actionGate, compiled.gate.abi, reconciliation);
  const factoryLeft = new ethers.Contract(config.infrastructure.factory, compiled.factory.abi, primary);
  const factoryRight = new ethers.Contract(config.infrastructure.factory, compiled.factory.abi, reconciliation);
  const entryLeft = new ethers.Contract(config.entryPoint, entryPointInterface, primary);
  const entryRight = new ethers.Contract(config.entryPoint, entryPointInterface, reconciliation);
  const calls = async (consumer, gate, factory, entry) => Promise.all([
    consumer.actionGate(), consumer.nextTokenId(),
    gate.expectedChainId(), gate.accountFactory(), gate.mintConsumer(), gate.authorizedAccount(),
    factory.entryPoint(), factory.approvedActionGate(), factory.recoveryAuthority(),
    factory.recoveryDelaySeconds(), factory.recoveryExpirySeconds(),
    factory["getAddress(address,bytes32,uint256)"](
      config.account.initialExecutionValidator,
      config.account.ownerCommitment,
      config.account.salt
    ),
    factory.isPhilSepoliaMintAccount(config.account.predictedAddress),
    entry.getNonce(config.account.predictedAddress, 0),
    entry.balanceOf(config.account.predictedAddress),
    gate.consumedEnvelopeDigest(parsed.authorizationEnvelopeDigest),
    gate.consumedRootNullifier(parsed.rootProofNullifier),
    gate.consumedDeviceApprovalNonce(parsed.deviceApprovalNonce),
    consumer.tokenIdByEnvelopeDigest(parsed.authorizationEnvelopeDigest),
    consumer.tokenIdByRootNullifier(parsed.rootProofNullifier)
  ]);
  const [left, right] = await Promise.all([
    calls(consumerLeft, gateLeft, factoryLeft, entryLeft),
    calls(consumerRight, gateRight, factoryRight, entryRight)
  ]);
  if (p1.canonicalJson(left.map(String)) !== p1.canonicalJson(right.map(String))
    || !sameAddress(left[0], config.infrastructure.actionGate)
    || left[1] !== expectedNextTokenId || left[2] !== BigInt(p1.CHAIN_ID)
    || !sameAddress(left[3], config.infrastructure.factory)
    || !sameAddress(left[4], config.infrastructure.mintConsumer)
    || !sameAddress(left[5], config.account.predictedAddress)
    || !sameAddress(left[6], config.entryPoint)
    || !sameAddress(left[7], config.infrastructure.actionGate)
    || !sameAddress(left[8], config.account.initialRecoveryAuthority)
    || left[9] !== p1.RECOVERY_DELAY_SECONDS || left[10] !== p1.RECOVERY_EXPIRY_SECONDS
    || !sameAddress(left[11], config.account.predictedAddress)
    || left[12] !== expectDeployed || left[13] !== expectedNonce
    || left[14] !== expectedEntryPointDepositWei
    || left[15] !== false || left[16] !== false || left[17] !== false
    || left[18] !== 0n || left[19] !== 0n) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_P1_BINDINGS_OR_REPLAY_INVALID");
  }
  if (expectDeployed) {
    const accountLeft = new ethers.Contract(config.account.predictedAddress, accountInterface, primary);
    const accountRight = new ethers.Contract(
      config.account.predictedAddress, accountInterface, reconciliation
    );
    const accountCalls = (account) => Promise.all([
      account.owner(), account.ownerCommitment(), account.approvedActionGate(),
      account.recoveryAuthority(), account.entryPoint(),
      account.recoveryDelaySeconds(), account.recoveryExpirySeconds()
    ]);
    const [leftAccount, rightAccount] = await Promise.all([
      accountCalls(accountLeft), accountCalls(accountRight)
    ]);
    if (p1.canonicalJson(leftAccount.map(String)) !== p1.canonicalJson(rightAccount.map(String))
      || !sameAddress(leftAccount[0], config.account.initialExecutionValidator)
      || String(leftAccount[1]).toLowerCase() !== config.account.ownerCommitment.toLowerCase()
      || !sameAddress(leftAccount[2], config.infrastructure.actionGate)
      || !sameAddress(leftAccount[3], config.account.initialRecoveryAuthority)
      || !sameAddress(leftAccount[4], config.entryPoint)
      || leftAccount[5] !== p1.RECOVERY_DELAY_SECONDS
      || leftAccount[6] !== p1.RECOVERY_EXPIRY_SECONDS) {
      p1.fail("PHILCORE_CONTROLLED_BETA_P2_DEPLOYED_ACCOUNT_BINDING_INVALID");
    }
  }
  return Object.freeze({
    accountBalanceWei: leftAccountBalance.toString(),
    entryPointNonce: left[13].toString(),
    entryPointDepositWei: left[14].toString(),
    nextTokenId: left[1].toString(),
    accountCodeHash: deployedAccountRuntime?.runtimeCodeHash || null,
    accountImmutableMaskedRuntimeCodeHash:
      deployedAccountRuntime?.immutableMaskedRuntimeCodeHash || null
  });
}

function assertP2FinalReceipt(receipt, receiptBytes, config) {
  const mutation = receipt?.mutations?.[0];
  if (receipt?.format !== "philcore-controlled-sepolia-beta-p2-final-receipt-v1"
    || receipt.version !== 1 || receipt.stageId !== "P2F"
    || receipt.status !== "P2_FINAL_CONFIRMED"
    || receipt.planDigest !== P2_FINAL_ORIGIN.planDigest
    || sha256Bytes(receiptBytes) !== P2_FINAL_ORIGIN.receiptByteSha256
    || receipt.publicMutationOccurred !== true || receipt.automaticRetryOccurred !== false
    || receipt.additionalFundingWei !== "0" || receipt.mutations?.length !== 1
    || mutation?.status !== "confirmed_by_bundler_and_both_providers"
    || mutation?.userOperationHash !== P2_FINAL_ORIGIN.userOperationHash
    || mutation?.transactionHash !== P2_FINAL_ORIGIN.transactionHash
    || mutation?.blockNumber !== P2_FINAL_ORIGIN.blockNumber
    || receipt.finalState?.entryPointNonce !== P2_FINAL_ORIGIN.resultingNonce
    || receipt.finalState?.entryPointDepositWei !== P2_FINAL_ORIGIN.entryPointDepositWei
    || receipt.finalState?.tokenId !== P2_FINAL_ORIGIN.tokenId
    || !sameAddress(receipt.finalState?.passOwner, config.account.initialExecutionValidator)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_P2_FINAL_RECEIPT_INVALID");
  }
  return Object.freeze(receipt);
}

function assertP2FinalPlan(plan, config) {
  const digestBody = { ...plan };
  delete digestBody.planDigest;
  digestBody.approval = { requiredPhrase: null, approved: false };
  const digest = p1.canonicalSha256(digestBody);
  if (plan?.format !== "philcore-controlled-sepolia-beta-p2-final-plan-v1"
    || plan.version !== 1 || plan.stageId !== "P2F"
    || plan.status !== "EXACT_P2_FINAL_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || digest !== P2_FINAL_ORIGIN.planDigest || plan.planDigest !== digest
    || plan.approval?.requiredPhrase !== p1.approvalPhrase("P2F", digest)
    || plan.approval?.approved !== false || plan.publicMutationCount !== 1
    || plan.publicMutationOccurred !== false || plan.automaticRetryAllowed !== false
    || plan.userOperation?.hash !== P2_FINAL_ORIGIN.userOperationHash
    || plan.userOperation?.packed?.initCode !== "0x"
    || plan.account?.startingNonce !== "0"
    || !sameAddress(plan.account?.address, config.account.predictedAddress)
    || plan.maximumAdditionalFundingWei !== "0") {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_P2_FINAL_PLAN_INVALID");
  }
  assertFinalRuntimeCodeHashes(plan.runtimeCodeHashes, config.runtimeCodeHashes);
  return Object.freeze(plan);
}

async function assertP2FinalOriginLive(primary, reconciliation, bundler, config) {
  const origin = P2_FINAL_ORIGIN;
  const [bundlerReceipt, leftReceipt, rightReceipt] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [origin.userOperationHash]),
    primary.getTransactionReceipt(origin.transactionHash),
    reconciliation.getTransactionReceipt(origin.transactionHash)
  ]);
  if (!bundlerReceipt || bundlerReceipt.success !== true
    || String(bundlerReceipt?.receipt?.transactionHash).toLowerCase() !== origin.transactionHash
    || !leftReceipt || !rightReceipt || leftReceipt.status !== 1 || rightReceipt.status !== 1
    || String(leftReceipt.blockNumber) !== origin.blockNumber
    || String(rightReceipt.blockNumber) !== origin.blockNumber
    || leftReceipt.blockHash.toLowerCase() !== rightReceipt.blockHash.toLowerCase()) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_P2_FINAL_ORIGIN_RECEIPT_INVALID");
  }
  const snapshot = async (provider) => {
    const gate = new ethers.Contract(config.infrastructure.actionGate, gateInterface, provider);
    const consumer = new ethers.Contract(
      config.infrastructure.mintConsumer, consumerInterface, provider
    );
    const entry = new ethers.Contract(config.entryPoint, entryPointInterface, provider);
    const values = await Promise.all([
      entry.getNonce(config.account.predictedAddress, 0),
      gate.consumedEnvelopeDigest(origin.authorizationEnvelopeDigest),
      gate.consumedRootNullifier(origin.rootProofNullifier),
      gate.consumedDeviceApprovalNonce(origin.deviceApprovalNonce),
      consumer.tokenIdByEnvelopeDigest(origin.authorizationEnvelopeDigest),
      consumer.tokenIdByRootNullifier(origin.rootProofNullifier),
      consumer.balanceOf(config.account.initialExecutionValidator),
      consumer.nextTokenId(),
      consumer.ownerOf(BigInt(origin.tokenId))
    ]);
    return values.map(String);
  };
  const [left, right] = await Promise.all([snapshot(primary), snapshot(reconciliation)]);
  if (p1.canonicalJson(left) !== p1.canonicalJson(right)
    || left[0] !== origin.resultingNonce
    || left[1] !== "true" || left[2] !== "true" || left[3] !== "true"
    || left[4] !== origin.tokenId || left[5] !== origin.tokenId
    || left[6] !== origin.resultingBalance || left[7] !== origin.resultingNextTokenId
    || !sameAddress(left[8], config.account.initialExecutionValidator)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_P2_FINAL_ORIGIN_STATE_INVALID");
  }
  return Object.freeze({
    userOperationHash: origin.userOperationHash,
    transactionHash: origin.transactionHash,
    blockNumber: origin.blockNumber,
    blockHash: leftReceipt.blockHash,
    entryPointNonce: left[0],
    replayFieldsConsumed: true,
    tokenId: left[4],
    recipientBalance: left[6],
    nextTokenId: left[7],
    confirmedByBothProviders: true
  });
}

async function assertStaleP2UserOperationRejected(bundler, signedArtifact, config) {
  if (signedArtifact?.userOperationHash?.toLowerCase() !== P2_FINAL_ORIGIN.userOperationHash) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_STALE_P2_USER_OPERATION_INVALID");
  }
  const parsed = parseSignedArtifact(
    signedArtifact, config, p1.artifacts(), { accountDeployed: true, expectedNonce: 0 }
  );
  let rejection = null;
  try {
    await bundler.send("eth_estimateUserOperationGas", [parsed.rpc, p1.ENTRY_POINT]);
  } catch (error) {
    const text = [error?.code, error?.shortMessage, error?.message,
      error?.error?.code, error?.error?.message,
      error?.info?.error?.code, error?.info?.error?.message,
      error?.info?.responseBody].filter(Boolean).join(" ");
    if (/(AA25|invalid account nonce|nonce)/iu.test(text)) {
      rejection = "ENTRYPOINT_NONCE_REJECTED_READ_ONLY_ESTIMATE";
    }
  }
  if (!rejection) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_STALE_P2_REJECTION_NOT_PROVEN");
  }
  return Object.freeze({
    method: "eth_estimateUserOperationGas",
    publicMutationOccurred: false,
    staleUserOperationHash: P2_FINAL_ORIGIN.userOperationHash,
    staleNonce: "0",
    liveNonce: "1",
    rejection
  });
}

async function assertRejectedP3SubmissionAbsent(bundler) {
  const [receipt, operation] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [P3_REJECTED_SUBMISSION_ORIGIN.userOperationHash]),
    bundler.send("eth_getUserOperationByHash", [P3_REJECTED_SUBMISSION_ORIGIN.userOperationHash])
  ]);
  if (receipt !== null || operation !== null) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_REJECTED_SUBMISSION_FOUND");
  }
  return Object.freeze({
    ...P3_REJECTED_SUBMISSION_ORIGIN,
    bundlerReceipt: null,
    bundlerOperation: null,
    confirmedAbsent: true,
    publicMutationConfirmedOnChain: false
  });
}

async function assertP2RecoveryOriginLive(primary, reconciliation, bundler, config) {
  const origin = P2_RECOVERY_ORIGIN;
  const [oldReceipt, oldOperation, leftReceipt, rightReceipt, leftTransaction,
    rightTransaction] = await Promise.all([
    bundler.send("eth_getUserOperationReceipt", [origin.rejectedUserOperationHash]),
    bundler.send("eth_getUserOperationByHash", [origin.rejectedUserOperationHash]),
    primary.getTransactionReceipt(origin.confirmedFundingTransactionHash),
    reconciliation.getTransactionReceipt(origin.confirmedFundingTransactionHash),
    primary.getTransaction(origin.confirmedFundingTransactionHash),
    reconciliation.getTransaction(origin.confirmedFundingTransactionHash)
  ]);
  if (oldReceipt !== null || oldOperation !== null || !leftReceipt || !rightReceipt
    || !leftTransaction || !rightTransaction
    || leftReceipt.status !== 1 || rightReceipt.status !== 1
    || String(leftReceipt.blockNumber) !== origin.confirmedFundingBlockNumber
    || String(rightReceipt.blockNumber) !== origin.confirmedFundingBlockNumber
    || leftReceipt.blockHash.toLowerCase() !== rightReceipt.blockHash.toLowerCase()
    || leftReceipt.gasUsed.toString() !== origin.confirmedFundingGasUsed
    || rightReceipt.gasUsed.toString() !== origin.confirmedFundingGasUsed
    || leftTransaction.hash.toLowerCase() !== origin.confirmedFundingTransactionHash
    || rightTransaction.hash.toLowerCase() !== origin.confirmedFundingTransactionHash
    || String(leftTransaction.blockNumber) !== origin.confirmedFundingBlockNumber
    || String(rightTransaction.blockNumber) !== origin.confirmedFundingBlockNumber
    || !sameAddress(leftTransaction.from, config.deployer)
    || !sameAddress(rightTransaction.from, config.deployer)
    || typeof leftTransaction.to !== "string" || typeof rightTransaction.to !== "string"
    || !sameAddress(leftTransaction.to, config.account.predictedAddress)
    || !sameAddress(rightTransaction.to, config.account.predictedAddress)
    || leftTransaction.nonce !== 3 || rightTransaction.nonce !== 3
    || leftTransaction.value !== BigInt(origin.confirmedFundingValueWei)
    || rightTransaction.value !== BigInt(origin.confirmedFundingValueWei)
    || leftTransaction.data !== "0x" || rightTransaction.data !== "0x") {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_ORIGIN_LIVE_INVALID");
  }
  const oldReplay = async (provider) => {
    const gate = new ethers.Contract(config.infrastructure.actionGate, gateInterface, provider);
    const consumer = new ethers.Contract(
      config.infrastructure.mintConsumer, consumerInterface, provider
    );
    return Promise.all([
      gate.consumedEnvelopeDigest(origin.originalAuthorizationEnvelopeDigest),
      gate.consumedRootNullifier(origin.originalRootProofNullifier),
      gate.consumedDeviceApprovalNonce(origin.originalDeviceApprovalNonce),
      consumer.tokenIdByEnvelopeDigest(origin.originalAuthorizationEnvelopeDigest),
      consumer.tokenIdByRootNullifier(origin.originalRootProofNullifier)
    ]);
  };
  const [leftReplay, rightReplay] = await Promise.all([
    oldReplay(primary), oldReplay(reconciliation)
  ]);
  if (p1.canonicalJson(leftReplay.map(String)) !== p1.canonicalJson(rightReplay.map(String))
    || leftReplay[0] !== false || leftReplay[1] !== false || leftReplay[2] !== false
    || leftReplay[3] !== 0n || leftReplay[4] !== 0n) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_ORIGINAL_REPLAY_STATE_INVALID");
  }
  return Object.freeze({
    fundingBlockHash: leftReceipt.blockHash,
    fundingTransactionHash: leftTransaction.hash
  });
}

function normalizeEstimate(value) {
  const row = {
    verificationGasLimit: BigInt(value.verificationGasLimit),
    callGasLimit: BigInt(value.callGasLimit),
    preVerificationGas: BigInt(value.preVerificationGas)
  };
  if (row.verificationGasLimit <= 0n || row.callGasLimit <= 0n || row.preVerificationGas <= 0n) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_BUNDLER_ESTIMATE_INVALID");
  }
  return Object.freeze(row);
}

function assertEstimateWithinSignedCaps(estimate, parsed) {
  if (estimate.verificationGasLimit > parsed.gas.verificationGasLimit
    || estimate.callGasLimit > parsed.gas.callGasLimit
    || estimate.preVerificationGas > parsed.gas.preVerificationGas) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_SIGNED_GAS_CAP_INSUFFICIENT");
  }
}

function p2FinalGasPolicy(configured) {
  const configuredVerificationGasLimit = BigInt(configured?.verificationGasLimit || 0);
  if (configuredVerificationGasLimit < P2_FINAL_VERIFICATION_GAS_LIMIT) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_VERIFICATION_GAS_CAP_INSUFFICIENT");
  }
  return Object.freeze({
    ...configured,
    verificationGasLimit: P2_FINAL_VERIFICATION_GAS_LIMIT.toString()
  });
}

function assertP2FinalGasPolicy(actual, configured) {
  const expected = p2FinalGasPolicy(configured);
  if (BigInt(actual?.verificationGasLimit || 0) !== P2_FINAL_VERIFICATION_GAS_LIMIT
    || BigInt(actual?.callGasLimit || 0) !== BigInt(expected.callGasLimit)
    || BigInt(actual?.preVerificationGas || 0) !== BigInt(expected.preVerificationGas)
    || BigInt(actual?.maxFeePerGas || 0) !== BigInt(expected.maxFeePerGas)
    || BigInt(actual?.maxPriorityFeePerGas || 0) !== BigInt(expected.maxPriorityFeePerGas)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_FINAL_GAS_POLICY_INVALID");
  }
  return expected;
}

function p3GasPolicy(configured) {
  const configuredVerificationGasLimit = BigInt(configured?.verificationGasLimit || 0);
  if (configuredVerificationGasLimit < P3_VERIFICATION_GAS_LIMIT) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_VERIFICATION_GAS_CAP_INSUFFICIENT");
  }
  return Object.freeze({
    ...configured,
    verificationGasLimit: P3_VERIFICATION_GAS_LIMIT.toString()
  });
}

function assertP3GasPolicy(actual, configured) {
  const expected = p3GasPolicy(configured);
  if (BigInt(actual?.verificationGasLimit || 0) !== P3_VERIFICATION_GAS_LIMIT
    || BigInt(actual?.callGasLimit || 0) !== BigInt(expected.callGasLimit)
    || BigInt(actual?.preVerificationGas || 0) !== BigInt(expected.preVerificationGas)
    || BigInt(actual?.maxFeePerGas || 0) !== BigInt(expected.maxFeePerGas)
    || BigInt(actual?.maxPriorityFeePerGas || 0) !== BigInt(expected.maxPriorityFeePerGas)) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P3_GAS_POLICY_INVALID");
  }
  return expected;
}

async function signFundingTransaction(plan, wallet) {
  const raw = await wallet.signTransaction({
    chainId: p1.CHAIN_ID,
    type: 2,
    nonce: Number(plan.funding.nonce),
    to: plan.funding.recipient,
    value: BigInt(plan.funding.valueWei),
    gasLimit: BigInt(plan.funding.gasLimit),
    maxFeePerGas: BigInt(plan.funding.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(plan.funding.maxPriorityFeePerGas),
    data: "0x"
  });
  const hash = ethers.keccak256(raw);
  if (plan.funding.transactionHash
    && hash.toLowerCase() !== plan.funding.transactionHash.toLowerCase()) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_FUNDING_TRANSACTION_CHANGED");
  }
  return Object.freeze({ raw, hash });
}

function acquireExecutionLock(planDigest, source, target = DEFAULT_EXECUTION_LOCK_PATH) {
  if (!/^0x[0-9a-f]{64}$/u.test(planDigest || "")
    || !/^[0-9a-f]{40}$/u.test(source?.commit || "")
    || !/^[0-9a-f]{40}$/u.test(source?.tree || "")) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_EXECUTION_LOCK_INPUT_INVALID");
  }
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  let descriptor;
  try {
    descriptor = fs.openSync(target, "wx", 0o600);
  } catch (error) {
    if (error?.code === "EEXIST") {
      p1.fail("PHILCORE_CONTROLLED_BETA_P2_EXECUTION_ALREADY_ATTEMPTED");
    }
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_EXECUTION_LOCK_CREATE_FAILED");
  }
  const record = Object.freeze({
    format: "philcore-controlled-sepolia-beta-p2-execution-attempt-lock-v1",
    version: 1,
    stageId: "P2",
    planDigest,
    source,
    acquiredAt: new Date().toISOString(),
    publicMutationOccurredAtAcquisition: false,
    automaticRetryAllowed: false,
    disposition: "PERSIST_UNTIL_READ_ONLY_RECONCILIATION"
  });
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8" });
    fs.fsyncSync(descriptor);
  } catch {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_EXECUTION_LOCK_WRITE_FAILED");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  return record;
}

function acquireRecoveryExecutionLock(
  planDigest,
  source,
  target = DEFAULT_RECOVERY_EXECUTION_LOCK_PATH
) {
  if (!/^0x[0-9a-f]{64}$/u.test(planDigest || "")
    || !/^[0-9a-f]{40}$/u.test(source?.commit || "")
    || !/^[0-9a-f]{40}$/u.test(source?.tree || "")) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_EXECUTION_LOCK_INPUT_INVALID");
  }
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  let descriptor;
  try {
    descriptor = fs.openSync(target, "wx", 0o600);
  } catch (error) {
    if (error?.code === "EEXIST") {
      p1.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_EXECUTION_ALREADY_ATTEMPTED");
    }
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_EXECUTION_LOCK_CREATE_FAILED");
  }
  const record = Object.freeze({
    format: "philcore-controlled-sepolia-beta-p2-recovery-execution-attempt-lock-v1",
    version: 1,
    stageId: "P2R",
    planDigest,
    source,
    acquiredAt: new Date().toISOString(),
    publicMutationOccurredAtAcquisition: false,
    automaticRetryAllowed: false,
    disposition: "PERSIST_UNTIL_READ_ONLY_RECONCILIATION"
  });
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8" });
    fs.fsyncSync(descriptor);
  } catch {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_RECOVERY_EXECUTION_LOCK_WRITE_FAILED");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  return record;
}

function acquireBoundedExecutionLock(planDigest, source, stageId, target) {
  if (!/^0x[0-9a-f]{64}$/u.test(planDigest || "")
    || !/^[0-9a-f]{40}$/u.test(source?.commit || "")
    || !/^[0-9a-f]{40}$/u.test(source?.tree || "")
    || !/^[A-Z0-9]{2,8}$/u.test(stageId || "")) {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_BOUNDED_EXECUTION_LOCK_INPUT_INVALID");
  }
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  let descriptor;
  try {
    descriptor = fs.openSync(target, "wx", 0o600);
  } catch (error) {
    if (error?.code === "EEXIST") {
      p1.fail("PHILCORE_CONTROLLED_BETA_P2_BOUNDED_EXECUTION_ALREADY_ATTEMPTED");
    }
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_BOUNDED_EXECUTION_LOCK_CREATE_FAILED");
  }
  const record = Object.freeze({
    format: `philcore-controlled-sepolia-beta-${stageId.toLowerCase()}-execution-attempt-lock-v1`,
    version: 1,
    stageId,
    planDigest,
    source,
    acquiredAt: new Date().toISOString(),
    publicMutationOccurredAtAcquisition: false,
    automaticRetryAllowed: false,
    disposition: "PERSIST_UNTIL_READ_ONLY_RECONCILIATION"
  });
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8" });
    fs.fsyncSync(descriptor);
  } catch {
    p1.fail("PHILCORE_CONTROLLED_BETA_P2_BOUNDED_EXECUTION_LOCK_WRITE_FAILED");
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  return record;
}

module.exports = {
  ...p1,
  P2_MUTATION_COUNT,
  P2_RECOVERY_MUTATION_COUNT,
  MINIMUM_BUNDLER_PRIORITY_FEE_WEI,
  P2_FINAL_VERIFICATION_GAS_LIMIT,
  P3_VERIFICATION_GAS_LIMIT,
  P2_FINAL_ORIGIN,
  P3_REJECTED_SUBMISSION_ORIGIN,
  P2_RECOVERY_ORIGIN,
  PROVIDER_OPTIONS,
  CONFIG_PATH,
  DEFAULT_SIGNED_ARTIFACT_PATH,
  DEFAULT_PLAN_PATH,
  DEFAULT_RECEIPT_PATH,
  DEFAULT_EXECUTION_LOCK_PATH,
  PRIVATE_EVIDENCE_ROOT,
  DEFAULT_RECOVERY_SIGNED_ARTIFACT_PATH,
  DEFAULT_RECOVERY_PLAN_PATH,
  DEFAULT_RECOVERY_RECEIPT_PATH,
  DEFAULT_RECOVERY_EXECUTION_LOCK_PATH,
  DEFAULT_ACCOUNT_DEPLOYMENT_PLAN_PATH,
  DEFAULT_ACCOUNT_DEPLOYMENT_RECEIPT_PATH,
  DEFAULT_ACCOUNT_DEPLOYMENT_EXECUTION_LOCK_PATH,
  DEFAULT_ACCOUNT_DEPLOYMENT_RECONCILIATION_PATH,
  DEFAULT_ACCOUNT_DEPLOYMENT_STOPPED_RECEIPT_PATH,
  DEFAULT_FINAL_SIGNED_ARTIFACT_PATH,
  DEFAULT_FINAL_PLAN_PATH,
  DEFAULT_FINAL_RECEIPT_PATH,
  DEFAULT_FINAL_EXECUTION_LOCK_PATH,
  DEFAULT_P3_SIGNED_ARTIFACT_PATH,
  DEFAULT_P3_PLAN_PATH,
  DEFAULT_P3_RECEIPT_PATH,
  DEFAULT_P3_EXECUTION_LOCK_PATH,
  factoryInterface,
  accountInterface,
  gateInterface,
  consumerInterface,
  entryPointInterface,
  sameAddress,
  canonicalSignedArtifactAddress,
  sha256Bytes,
  loadConfiguration,
  assertConfigurationMetadata,
  accountRuntimeIdentity,
  assertFinalRuntimeCodeHashes,
  rpcV07,
  parseSignedArtifact,
  assertProviderPair,
  assertP2FinalReceipt,
  assertP2FinalPlan,
  assertP2FinalOriginLive,
  assertStaleP2UserOperationRejected,
  assertRejectedP3SubmissionAbsent,
  assertP2RecoveryOriginLive,
  normalizeEstimate,
  assertEstimateWithinSignedCaps,
  p2FinalGasPolicy,
  assertP2FinalGasPolicy,
  p3GasPolicy,
  assertP3GasPolicy,
  signFundingTransaction,
  acquireExecutionLock,
  acquireRecoveryExecutionLock,
  acquireBoundedExecutionLock
};
