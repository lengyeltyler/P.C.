const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

// ---------------------------------------------------------------------------
// ERC-7562 OP-054 forbids an account from accessing the EntryPoint's own code
// or storage during validation. PhilCoreV2MinimalAccountV2.validateUserOp
// currently recomputes `_entryPoint.getUserOpHash(userOp)` and compares it to
// the EntryPoint-supplied `userOpHash` parameter -- a STATICCALL into the
// EntryPoint's code, and also a redundant check, since the EntryPoint always
// supplies the hash it itself computed for this exact userOp. This file
// proves the forbidden access exists at baseline via a real EVM trace, and
// (after the one-condition deletion) that it is gone, while every other
// validateUserOp guarantee is preserved.
// ---------------------------------------------------------------------------

const ACCOUNT_VERSION_ID =
  "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f";
const SECURITY_MODEL_ID = ethers.id(
  "philcore-v2-typed-intent-local-proof-gated-v1"
);
const IDENTITY_BINDING_TYPEHASH =
  "0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8";
const OWNER_COMMITMENT_SCHEME_ID =
  "0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e";
const VALIDATOR_COMMITMENT_TYPEHASH = ethers.id(
  "PhilCoreV2ValidatorCommitment(uint8 verifierKind,address validator,bytes32 validatorKeyIdBinding)"
);
const RECOVERY_CONFIGURATION_TYPEHASH = ethers.id(
  "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"
);
const INTENT_CORE_HEADER_TYPEHASH = ethers.id(
  "PhilCoreV2IntentCoreHeader(uint8 specificationVersion,bytes32 securityModelId,uint8 actionType,bytes32 actionId,bytes32 purpose,bytes32 ownerCommitment,uint256 chainId,address entryPoint,address account,uint192 nonceKey,uint64 nonceSequence,uint64 validatorEpoch,uint64 recoveryEpoch,bytes32 applicationContextHash,bytes32 fundLifecycleDigest,uint256 maxTotalFeeWei,uint48 validAfter,uint48 validUntil)"
);
const AUTHORIZED_INTENT_TYPEHASH = ethers.id(
  "PhilCoreV2AuthorizedIntent(bytes32 intentCoreHash,bytes32 runtimeAuthorizationDigest)"
);

const ACTION = { TRANSFER: 2 };
const PURPOSE = {
  [ACTION.TRANSFER]: ethers.id("PHILCORE_V2_PURPOSE_TRANSFER_ASSET")
};
const ACTION_TYPE = {
  [ACTION.TRANSFER]: ethers.id(
    "PhilCoreV2NativeTransferIntent(bytes32 coreHeaderHash,address recipient,uint256 amountWei)"
  )
};

const GET_USER_OP_HASH_SELECTOR = "0x22cdde4c";
const VALIDATE_USER_OP_SELECTOR = "0x19822f7c";
const DEFAULT_MAX_TOTAL_FEE_WEI = ethers.parseEther("1");

const abi = ethers.AbiCoder.defaultAbiCoder();

function packUints(high128, low128) {
  return ethers.toBeHex((BigInt(high128) << 128n) | BigInt(low128), 32);
}

function identityBinding(ownerCommitment) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "uint8", "bytes32", "bytes32"],
      [
        IDENTITY_BINDING_TYPEHASH,
        1,
        ownerCommitment,
        OWNER_COMMITMENT_SCHEME_ID
      ]
    )
  );
}

function validatorCommitment(validator, keyBinding) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "uint8", "address", "bytes32"],
      [VALIDATOR_COMMITMENT_TYPEHASH, 1, validator, keyBinding]
    )
  );
}

function recoveryConfigHash(primary, hardware, independent) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
      [
        RECOVERY_CONFIGURATION_TYPEHASH,
        3,
        2,
        primary,
        hardware,
        independent
      ]
    )
  );
}

function headerHash(core) {
  return ethers.keccak256(
    abi.encode(
      [
        "bytes32",
        "uint8",
        "bytes32",
        "uint8",
        "bytes32",
        "bytes32",
        "bytes32",
        "uint256",
        "address",
        "address",
        "uint192",
        "uint64",
        "uint64",
        "uint64",
        "bytes32",
        "bytes32",
        "uint256",
        "uint48",
        "uint48"
      ],
      [
        INTENT_CORE_HEADER_TYPEHASH,
        core.specificationVersion,
        core.securityModelId,
        core.actionType,
        core.actionId,
        core.purpose,
        core.ownerCommitment,
        core.chainId,
        core.entryPoint,
        core.account,
        core.nonceKey,
        core.nonceSequence,
        core.validatorEpoch,
        core.recoveryEpoch,
        core.applicationContextHash,
        core.fundLifecycleDigest,
        core.maxTotalFeeWei,
        core.validAfter,
        core.validUntil
      ]
    )
  );
}

function actionCoreHash(core, args) {
  const head = headerHash(core);
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "address", "uint256"],
      [ACTION_TYPE[ACTION.TRANSFER], head, args[0], args[1]]
    )
  );
}

function authorizedIntentHash(intent, intentCoreHash) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32"],
      [
        AUTHORIZED_INTENT_TYPEHASH,
        intentCoreHash,
        intent.runtimeAuthorizationDigest
      ]
    )
  );
}

function initialization({
  entryPoint,
  chainId,
  ownerCommitment,
  factory,
  confirmationTarget,
  validator,
  validatorKey,
  primary,
  hardware,
  independent
}) {
  return {
    entryPoint,
    deploymentChainId: chainId,
    ownerCommitment,
    identityBindingCommitment: identityBinding(ownerCommitment),
    factoryBinding: factory,
    accountVersionId: ACCOUNT_VERSION_ID,
    securityModelId: SECURITY_MODEL_ID,
    confirmationTarget,
    initialValidator: validator,
    validatorVerifierKind: 1,
    validatorKeyIdBinding: validatorKey,
    validatorCommitment: validatorCommitment(validator, validatorKey),
    validatorEpoch: 1,
    primaryDeviceRecoveryCommitment: primary,
    hardwareSecurityKeyCommitment: hardware,
    independentRecoveryFactorCommitment: independent,
    recoveryConfigurationHash: recoveryConfigHash(
      primary,
      hardware,
      independent
    ),
    recoveryEpoch: 1,
    recoveryDelaySeconds: 172800,
    recoveryExpirySeconds: 604800
  };
}

async function deployEntryPoint(deployer) {
  return new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
}

// Deposits 4 ETH of EntryPoint balance for the account so that a normal
// transferNative op never needs a missingAccountFunds prefund transfer,
// keeping the validation-phase trace free of an extra account-originated
// CALL back to the EntryPoint that would otherwise confound attribution.
async function fixture() {
  const signers = await ethers.getSigners();
  const [deployer, validator, nextValidator, recipient, beneficiary, attacker] =
    signers;
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const entryPoint = await deployEntryPoint(deployer);
  const Confirmation = await ethers.getContractFactory(
    "PhilCoreV2ConfirmationTargetMock"
  );
  const confirmation = await Confirmation.deploy();
  const Verifier = await ethers.getContractFactory(
    "PhilCoreV2StaticAuthorityVerifier"
  );
  const verifier = await Verifier.deploy();
  const verifierAddress = await verifier.getAddress();
  const verifierCodeHash = ethers.keccak256(
    await ethers.provider.getCode(verifierAddress)
  );
  const Factory = await ethers.getContractFactory(
    "PhilCoreV2MinimalAccountFactoryV2"
  );
  const factory = await Factory.deploy(
    await entryPoint.getAddress(),
    chainId,
    await confirmation.getAddress(),
    verifierAddress,
    verifierCodeHash
  );
  const values = {
    ownerCommitment: ethers.id("o37-10-7562exp-owner"),
    validatorKey: ethers.id("o37-10-7562exp-validator-key"),
    primary: ethers.id("o37-10-7562exp-primary"),
    hardware: ethers.id("o37-10-7562exp-hardware"),
    independent: ethers.id("o37-10-7562exp-independent"),
    userSalt: ethers.id("o37-10-7562exp-user-salt")
  };
  const init = initialization({
    entryPoint: await entryPoint.getAddress(),
    chainId,
    ownerCommitment: values.ownerCommitment,
    factory: await factory.getAddress(),
    confirmationTarget: await confirmation.getAddress(),
    validator: validator.address,
    validatorKey: values.validatorKey,
    primary: values.primary,
    hardware: values.hardware,
    independent: values.independent
  });
  const predicted = await factory
    .getFunction("getAddress")
    .staticCall(init, values.userSalt);
  await (await factory.createAccount(init, values.userSalt)).wait();
  const account = await ethers.getContractAt(
    "PhilCoreV2MinimalAccountV2",
    predicted
  );
  await (
    await entryPoint.depositTo(predicted, { value: ethers.parseEther("4") })
  ).wait();
  return {
    signers,
    deployer,
    validator,
    nextValidator,
    recipient,
    beneficiary,
    attacker,
    chainId,
    entryPoint,
    confirmation,
    verifier,
    verifierCodeHash,
    factory,
    init,
    account,
    accountAddress: predicted,
    ...values
  };
}

async function securityState(env) {
  const state = await env.account.accountSecurityState();
  return {
    validator: state[0],
    validatorCommitment: state[1],
    validatorKey: state[2],
    validatorEpoch: state[3],
    recoveryEpoch: state[6]
  };
}

async function buildOperation(
  env,
  { args, lane, signer = env.validator, mutateCore, mutateOperation }
) {
  const state = await securityState(env);
  const latest = await ethers.provider.getBlock("latest");
  const nonce = await env.entryPoint.getNonce(env.accountAddress, lane);
  const core = {
    specificationVersion: 1,
    securityModelId: SECURITY_MODEL_ID,
    actionType: ACTION.TRANSFER,
    actionId: ethers.id(`o37-10-7562exp-action-${nonce}`),
    purpose: PURPOSE[ACTION.TRANSFER],
    ownerCommitment: env.ownerCommitment,
    chainId: env.chainId,
    entryPoint: await env.entryPoint.getAddress(),
    account: env.accountAddress,
    nonceKey: BigInt(lane),
    nonceSequence: BigInt(nonce) & ((1n << 64n) - 1n),
    validatorEpoch: state.validatorEpoch,
    recoveryEpoch: state.recoveryEpoch,
    applicationContextHash: ethers.id("o37-10-7562exp-application-context"),
    fundLifecycleDigest: ethers.id("o37-10-7562exp-fund-lifecycle"),
    maxTotalFeeWei: DEFAULT_MAX_TOTAL_FEE_WEI,
    validAfter: BigInt(latest.timestamp - 1),
    validUntil: BigInt(latest.timestamp + 500)
  };
  if (mutateCore) mutateCore(core);
  const intent = {
    core,
    runtimeAuthorizationDigest: ethers.id(`o37-10-7562exp-runtime-${nonce}`)
  };
  const callData = env.account.interface.encodeFunctionData(
    "transferNative",
    [intent, ...args]
  );
  let userOp = {
    sender: env.accountAddress,
    nonce,
    initCode: "0x",
    callData,
    accountGasLimits: packUints(3_000_000n, 1_000_000n),
    preVerificationGas: 200_000n,
    gasFees: packUints(1_000_000_000n, 30_000_000_000n),
    paymasterAndData: "0x",
    signature: "0x"
  };
  if (mutateOperation) userOp = mutateOperation(userOp);
  const userOpHash = await env.entryPoint.getUserOpHash(userOp);
  const coreHash = actionCoreHash(core, args);
  const authHash = authorizedIntentHash(intent, coreHash);
  const raw = await signer.signTypedData(
    {
      name: "PhilCore V2 Account",
      version: "1",
      chainId: env.chainId,
      verifyingContract: env.accountAddress
    },
    {
      PhilCoreV2Authorization: [
        { name: "authorizedIntentHash", type: "bytes32" },
        { name: "userOpHash", type: "bytes32" },
        { name: "validator", type: "address" },
        { name: "validatorKeyIdBinding", type: "bytes32" },
        { name: "validatorEpoch", type: "uint64" },
        { name: "recoveryEpoch", type: "uint64" }
      ]
    },
    {
      authorizedIntentHash: authHash,
      userOpHash,
      validator: state.validator,
      validatorKeyIdBinding: state.validatorKey,
      validatorEpoch: state.validatorEpoch,
      recoveryEpoch: state.recoveryEpoch
    }
  );
  const parsed = ethers.Signature.from(raw);
  const signature = abi.encode(
    [
      "uint8",
      "uint8",
      "uint8",
      "address",
      "bytes32",
      "uint64",
      "uint64",
      "bytes32",
      "bytes32",
      "uint8"
    ],
    [
      1,
      1,
      1,
      state.validator,
      state.validatorKey,
      state.validatorEpoch,
      state.recoveryEpoch,
      parsed.r,
      parsed.s,
      parsed.v
    ]
  );
  return { ...userOp, signature };
}

async function execute(env, userOp) {
  return env.entryPoint.handleOps([userOp], env.beneficiary.address, {
    gasLimit: 12_000_000
  });
}

// Calls validateUserOp directly, impersonating the EntryPoint, with
// caller-chosen userOpHash/missingAccountFunds parameters that real
// handleOps could never independently supply (EntryPoint always derives its
// own hash and gas-accounted prefund). Used only to reach specific
// defensive branches in isolation.
async function directValidate(env, userOp, { userOpHash, missingAccountFunds }) {
  const entryPointAddress = await env.entryPoint.getAddress();
  const entryPointSigner = await ethers.getImpersonatedSigner(entryPointAddress);
  await env.deployer.sendTransaction({
    to: entryPointAddress,
    value: ethers.parseEther("1")
  });
  return env.account
    .connect(entryPointSigner)
    .validateUserOp(userOp, userOpHash, missingAccountFunds);
}

// ---------------------------------------------------------------------------
// Trace decoder: pure functions over debug_traceTransaction structLogs.
// Exported at module scope (not just used inline) so the classifier tests
// below exercise the exact same implementation the real-trace tests use.
// ---------------------------------------------------------------------------

const CALL_WITH_VALUE_OPS = new Set(["CALL", "CALLCODE"]);
const CALL_NO_VALUE_OPS = new Set(["STATICCALL", "DELEGATECALL"]);
const EXTCODE_SINGLE_ARG_OPS = new Set([
  "EXTCODESIZE",
  "EXTCODEHASH",
  "EXTCODECOPY"
]);
const FORBIDDEN_SCAN_OPS = new Set([
  "CALL",
  "STATICCALL",
  "DELEGATECALL",
  "CALLCODE",
  "EXTCODESIZE",
  "EXTCODEHASH",
  "EXTCODECOPY"
]);

function normalizeStackAddress(word) {
  const hex = word.startsWith("0x") ? word.slice(2) : word;
  return `0x${hex.slice(-40).toLowerCase()}`;
}

// Stack input orderings per evm.codes (top-of-stack is stack[length-1]):
//   CALL/CALLCODE:       gas, addr, value, argsOffset, argsSize, retOffset, retSize
//   STATICCALL/DELEGATECALL: gas, addr, argsOffset, argsSize, retOffset, retSize
//   EXTCODESIZE/EXTCODEHASH: addr
//   EXTCODECOPY:          addr, destOffset, offset, size
function decodeCallTargetAddress(op, stack) {
  const len = stack.length;
  if (CALL_WITH_VALUE_OPS.has(op) || CALL_NO_VALUE_OPS.has(op)) {
    return normalizeStackAddress(stack[len - 2]);
  }
  if (EXTCODE_SINGLE_ARG_OPS.has(op)) {
    return normalizeStackAddress(stack[len - 1]);
  }
  return undefined;
}

function decodeCallArgs(op, stack) {
  const len = stack.length;
  if (CALL_WITH_VALUE_OPS.has(op)) {
    return {
      argsOffset: parseInt(stack[len - 4], 16),
      argsSize: parseInt(stack[len - 5], 16)
    };
  }
  if (CALL_NO_VALUE_OPS.has(op)) {
    return {
      argsOffset: parseInt(stack[len - 3], 16),
      argsSize: parseInt(stack[len - 4], 16)
    };
  }
  return undefined;
}

// EVM memory reads past the tracked high-water mark are implicitly zero;
// structLogs only report words actually touched, so a missing word is
// zero-filled rather than treated as a decoding failure.
function readMemorySlice(memoryWords, offset, size) {
  if (!memoryWords || size <= 0) return "0x";
  const bytes = [];
  for (let i = 0; i < size; i++) {
    const byteOffset = offset + i;
    const wordIdx = Math.floor(byteOffset / 32);
    const byteInWord = byteOffset % 32;
    const word = memoryWords[wordIdx];
    if (word === undefined) {
      bytes.push("00");
      continue;
    }
    const hexWord = word.startsWith("0x") ? word.slice(2) : word;
    bytes.push(hexWord.slice(byteInWord * 2, byteInWord * 2 + 2));
  }
  return `0x${bytes.join("")}`;
}

function decodeCallInputSelector(op, stack, memoryWords) {
  const args = decodeCallArgs(op, stack);
  if (!args || args.argsSize < 4) return undefined;
  return readMemorySlice(memoryWords, args.argsOffset, 4);
}

// Finds every depth-1 CALL whose target and 4-byte calldata selector match
// the given account/selector pair. Depth 1 is the top-level call frame in
// Hardhat/geth-style structLogs (the transaction's own frame, i.e. the
// EntryPoint executing handleOps); a depth-1 CALL is therefore necessarily
// EntryPoint-originated.
function findEntryPointOriginatedCalls(structLogs, { targetAddress, selector }) {
  const target = targetAddress.toLowerCase();
  const matches = [];
  for (let i = 0; i < structLogs.length; i++) {
    const log = structLogs[i];
    if (log.op !== "CALL" || log.depth !== 1) continue;
    if (decodeCallTargetAddress(log.op, log.stack) !== target) continue;
    if (decodeCallInputSelector(log.op, log.stack, log.memory) !== selector) {
      continue;
    }
    matches.push(i);
  }
  return matches;
}

// Given the index of a CALL-family opcode, returns the exclusive index range
// [start, end) of the frame it enters: from the first log at depth+1 up to
// (but excluding) the first later log back at depth <= the call's own depth.
// This span necessarily includes every nested descendant call made while
// inside that frame, and nothing from sibling calls made later at the same
// depth as the original CALL.
function findCalledFrameRange(structLogs, callSiteIndex) {
  const callDepth = structLogs[callSiteIndex].depth;
  let end = structLogs.length;
  for (let i = callSiteIndex + 1; i < structLogs.length; i++) {
    if (structLogs[i].depth <= callDepth) {
      end = i;
      break;
    }
  }
  return { start: callSiteIndex + 1, end };
}

function scanForbiddenTargetAccess(structLogs, range, forbiddenTargetAddress) {
  const target = forbiddenTargetAddress.toLowerCase();
  const findings = [];
  for (let i = range.start; i < range.end; i++) {
    const log = structLogs[i];
    if (!FORBIDDEN_SCAN_OPS.has(log.op)) continue;
    const addr = decodeCallTargetAddress(log.op, log.stack);
    if (addr !== target) continue;
    const finding = { index: i, op: log.op, depth: log.depth, targetAddress: addr };
    if (CALL_WITH_VALUE_OPS.has(log.op) || CALL_NO_VALUE_OPS.has(log.op)) {
      finding.selector = decodeCallInputSelector(log.op, log.stack, log.memory);
    }
    findings.push(finding);
  }
  return findings;
}

function findTargetAccess(structLogs, range, targetAddress) {
  return scanForbiddenTargetAccess(structLogs, range, targetAddress);
}

async function traceExecutedTransaction(txResponse) {
  const receipt = await txResponse.wait();
  assert.equal(receipt.status, 1, "expected the traced transaction to succeed");
  const trace = await ethers.provider.send("debug_traceTransaction", [
    receipt.hash,
    { disableStorage: true, disableMemory: false, disableStack: false }
  ]);
  assert.equal(trace.failed, false, "expected the traced call to have succeeded");
  return trace;
}

// ---------------------------------------------------------------------------
// 1. Trace decoder classifier tests -- synthetic fixtures only. These prove
//    the decoding/attribution *logic* is correct; they are not claims about
//    what PhilCore actually does. Real-PhilCore claims are made only in the
//    sections below that trace an actual executed transaction.
// ---------------------------------------------------------------------------

// Builds structLog-shaped 32-byte hex words the same way Hardhat's
// debug_traceTransaction does (64 hex chars, no 0x prefix), programmatically
// rather than by hand, to eliminate hand-counted-hex transcription errors.
function word(value) {
  return ethers.zeroPadValue(ethers.toBeHex(value), 32).slice(2);
}

function addressWord(address) {
  return ethers.zeroPadValue(address, 32).slice(2);
}

// Builds the `memory` array of a structLog (32-byte words) containing
// `dataBytes` (a Uint8Array/hex string) placed at byte offset `offset`,
// zero-filled elsewhere, sized to exactly cover the data.
function memoryWithBytesAt(offset, dataHex) {
  const data = ethers.getBytes(dataHex);
  const end = offset + data.length;
  const wordCount = Math.ceil(end / 32);
  const buf = new Uint8Array(wordCount * 32);
  buf.set(data, offset);
  const words = [];
  for (let w = 0; w < wordCount; w++) {
    words.push(ethers.hexlify(buf.slice(w * 32, w * 32 + 32)).slice(2));
  }
  return words;
}


module.exports = {
  VALIDATE_USER_OP_SELECTOR,
  GET_USER_OP_HASH_SELECTOR,
  CALL_WITH_VALUE_OPS,
  fixture,
  buildOperation,
  execute,
  directValidate,
  decodeCallTargetAddress,
  decodeCallInputSelector,
  findEntryPointOriginatedCalls,
  findCalledFrameRange,
  scanForbiddenTargetAccess,
  findTargetAccess,
  traceExecutedTransaction
};
