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
    ownerCommitment: ethers.id("o37-10-op054-owner"),
    validatorKey: ethers.id("o37-10-op054-validator-key"),
    primary: ethers.id("o37-10-op054-primary"),
    hardware: ethers.id("o37-10-op054-hardware"),
    independent: ethers.id("o37-10-op054-independent"),
    userSalt: ethers.id("o37-10-op054-user-salt")
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
    actionId: ethers.id(`o37-10-op054-action-${nonce}`),
    purpose: PURPOSE[ACTION.TRANSFER],
    ownerCommitment: env.ownerCommitment,
    chainId: env.chainId,
    entryPoint: await env.entryPoint.getAddress(),
    account: env.accountAddress,
    nonceKey: BigInt(lane),
    nonceSequence: BigInt(nonce) & ((1n << 64n) - 1n),
    validatorEpoch: state.validatorEpoch,
    recoveryEpoch: state.recoveryEpoch,
    applicationContextHash: ethers.id("o37-10-op054-application-context"),
    fundLifecycleDigest: ethers.id("o37-10-op054-fund-lifecycle"),
    maxTotalFeeWei: DEFAULT_MAX_TOTAL_FEE_WEI,
    validAfter: BigInt(latest.timestamp - 1),
    validUntil: BigInt(latest.timestamp + 500)
  };
  if (mutateCore) mutateCore(core);
  const intent = {
    core,
    runtimeAuthorizationDigest: ethers.id(`o37-10-op054-runtime-${nonce}`)
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

describe("OP-054 trace decoder (classifier unit tests, synthetic fixtures)", function () {
  // decodeCallTargetAddress always normalizes to lowercase.
  const TARGET = ethers.getAddress(ethers.zeroPadValue("0xc0ffee", 20)).toLowerCase();
  const TARGET_WORD = addressWord(TARGET);

  it("decodes the target address operand for CALL and CALLCODE (gas,addr,value,argsOffset,argsSize,retOffset,retSize)", function () {
    const stack = [
      word(0x10), // retSize
      word(0x20), // retOffset
      word(0x30), // argsSize
      word(0x40), // argsOffset
      word(0), // value
      TARGET_WORD, // addr
      word(0x30d40) // gas (TOS)
    ];
    assert.equal(decodeCallTargetAddress("CALL", stack), TARGET);
    assert.equal(decodeCallTargetAddress("CALLCODE", stack), TARGET);
  });

  it("decodes the target address operand for STATICCALL and DELEGATECALL (gas,addr,argsOffset,argsSize,retOffset,retSize)", function () {
    const stack = [
      word(0x10), // retSize
      word(0x20), // retOffset
      word(0x30), // argsSize
      word(0x40), // argsOffset
      TARGET_WORD, // addr
      word(0x30d40) // gas (TOS)
    ];
    assert.equal(decodeCallTargetAddress("STATICCALL", stack), TARGET);
    assert.equal(decodeCallTargetAddress("DELEGATECALL", stack), TARGET);
  });

  it("decodes the single address operand for EXTCODESIZE and EXTCODEHASH", function () {
    const stack = [TARGET_WORD];
    assert.equal(decodeCallTargetAddress("EXTCODESIZE", stack), TARGET);
    assert.equal(decodeCallTargetAddress("EXTCODEHASH", stack), TARGET);
  });

  it("decodes the leading (top-of-stack) address operand for EXTCODECOPY", function () {
    const stack = [
      word(0x10), // size
      word(0x20), // offset
      word(0x30), // destOffset
      TARGET_WORD // addr (TOS)
    ];
    assert.equal(decodeCallTargetAddress("EXTCODECOPY", stack), TARGET);
  });

  it("returns undefined for opcodes with no target operand", function () {
    assert.equal(decodeCallTargetAddress("PUSH1", ["0x01"]), undefined);
    assert.equal(decodeCallTargetAddress("SSTORE", ["0x01", "0x02"]), undefined);
  });

  it("decodes a word-aligned CALL-family calldata selector from memory", function () {
    const stack = [
      word(0x10),
      word(0x20),
      word(4), // argsSize
      word(32), // argsOffset = 32 (word 1)
      TARGET_WORD,
      word(0x30d40)
    ];
    const memory = memoryWithBytesAt(32, GET_USER_OP_HASH_SELECTOR);
    assert.equal(
      decodeCallInputSelector("STATICCALL", stack, memory),
      GET_USER_OP_HASH_SELECTOR
    );
  });

  it("decodes a non-word-aligned calldata selector that spans two memory words", function () {
    const stack = [
      word(0x10),
      word(0x20),
      word(4), // argsSize
      word(30), // argsOffset = 30, spans word 0 (bytes 30-31) and word 1 (bytes 0-1)
      TARGET_WORD,
      word(0x30d40)
    ];
    const memory = memoryWithBytesAt(30, GET_USER_OP_HASH_SELECTOR);
    assert.equal(memory.length, 2, "selector at offset 30 must span exactly two words");
    assert.equal(
      decodeCallInputSelector("STATICCALL", stack, memory),
      GET_USER_OP_HASH_SELECTOR
    );
  });

  it("zero-fills a calldata selector read past the reported memory high-water mark", function () {
    const stack = [
      word(0x10),
      word(0x20),
      word(4),
      word(64), // argsOffset = 64 (word 2, never reported)
      TARGET_WORD,
      word(0x30d40)
    ];
    const memory = [word(0)];
    assert.equal(decodeCallInputSelector("STATICCALL", stack, memory), "0x00000000");
  });

  it("returns undefined for a selector read of a CALL with fewer than 4 argument bytes", function () {
    const stack = [
      word(0x10),
      word(0x20),
      word(2), // argsSize = 2
      word(0),
      TARGET_WORD,
      word(0x30d40)
    ];
    assert.equal(decodeCallInputSelector("STATICCALL", stack, ["0x"]), undefined);
  });

  it("bounds a called frame to its own depth range and excludes sibling calls at the caller's depth", function () {
    // Synthetic structLogs: depth1 CALL -> depth2 frame containing a nested
    // STATICCALL to an "EntryPoint-like" address -> return to depth1 -> a
    // later, unrelated depth1 CALL to the very same address. The frame range
    // computed from the first CALL must exclude the later sibling call.
    const forbidden = ethers.getAddress(ethers.zeroPadValue("0xee", 20));
    const forbiddenWord = addressWord(forbidden);
    const callStack = () => ["0", "0", "0", "0", "0", forbiddenWord, "0"];
    const staticcallStack = () => ["0", "0", "0", "0", forbiddenWord, "0"];
    const structLogs = [
      { depth: 1, op: "CALL", stack: callStack() }, // index 0: enters account (not itself scanned)
      { depth: 2, op: "PUSH1", stack: [] }, // index 1: inside account frame
      { depth: 2, op: "STATICCALL", stack: staticcallStack() }, // index 2: forbidden nested access, inside the frame
      { depth: 2, op: "STOP", stack: [] }, // index 3: still inside frame
      { depth: 1, op: "PUSH1", stack: [] }, // index 4: back at caller depth -> frame ends here
      { depth: 1, op: "CALL", stack: callStack() } // index 5: unrelated later sibling call, must be excluded
    ];
    const range = findCalledFrameRange(structLogs, 0);
    assert.deepEqual(range, { start: 1, end: 4 });
    const findings = findTargetAccess(structLogs, range, forbidden);
    assert.deepEqual(findings.map((f) => f.index), [2]);
  });

  it("requires unambiguous depth-1 selector-matched attribution of the entry call", function () {
    const target = ethers.getAddress(ethers.zeroPadValue("0xaa", 20));
    const targetWord = addressWord(target);
    const matchingCall = (selectorHex) => ({
      depth: 1,
      op: "CALL",
      stack: [
        "0",
        "0",
        word(4), // argsSize
        word(0), // argsOffset
        "0",
        targetWord,
        "0"
      ],
      memory: memoryWithBytesAt(0, selectorHex)
    });

    const zeroMatches = findEntryPointOriginatedCalls(
      [matchingCall("0xaaaaaaaa")],
      { targetAddress: target, selector: VALIDATE_USER_OP_SELECTOR }
    );
    assert.deepEqual(zeroMatches, []);

    const oneMatch = findEntryPointOriginatedCalls(
      [matchingCall(VALIDATE_USER_OP_SELECTOR)],
      { targetAddress: target, selector: VALIDATE_USER_OP_SELECTOR }
    );
    assert.deepEqual(oneMatch, [0]);

    const twoMatches = findEntryPointOriginatedCalls(
      [matchingCall(VALIDATE_USER_OP_SELECTOR), matchingCall(VALIDATE_USER_OP_SELECTOR)],
      { targetAddress: target, selector: VALIDATE_USER_OP_SELECTOR }
    );
    assert.equal(twoMatches.length, 2);
  });
});

// ---------------------------------------------------------------------------
// 2. Real PhilCore trace attribution -- a genuine handleOps transaction
//    against the pinned @account-abstraction/contracts@0.7.0 EntryPoint on
//    local Hardhat, traced with debug_traceTransaction.
// ---------------------------------------------------------------------------

describe("O.37.10 real PhilCore validateUserOp trace attribution (ERC-7562 OP-054)", function () {
  it("locates exactly one EntryPoint-originated call into validateUserOp and scopes the validation subtree to it", async function () {
    const env = await fixture();
    await env.deployer.sendTransaction({
      to: env.accountAddress,
      value: ethers.parseEther("2")
    });
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    const trace = await traceExecutedTransaction(await execute(env, op));

    const entryCalls = findEntryPointOriginatedCalls(trace.structLogs, {
      targetAddress: env.accountAddress,
      selector: VALIDATE_USER_OP_SELECTOR
    });
    assert.equal(
      entryCalls.length,
      1,
      `trace-frame attribution is ambiguous: found ${entryCalls.length} ` +
        "candidate EntryPoint-originated validateUserOp entry calls"
    );

    const range = findCalledFrameRange(trace.structLogs, entryCalls[0]);
    assert.ok(range.end > range.start, "validation frame must be non-empty");

    // The entry CALL opcode itself (at entryCalls[0]) is excluded: the scan
    // range starts strictly after it.
    assert.equal(range.start, entryCalls[0] + 1);

    // Positive control: legitimate calls made during validation (the
    // factory's verifierBinding() query and the verifier's own
    // verifyAuthority STATICCALL) must still be observable inside the
    // scoped range, proving the range genuinely covers validation and the
    // scan is not vacuously empty.
    const factoryAddress = await env.factory.getAddress();
    const verifierAddress = await env.verifier.getAddress();
    const factoryAccess = findTargetAccess(trace.structLogs, range, factoryAddress);
    const verifierAccess = findTargetAccess(trace.structLogs, range, verifierAddress);
    assert.ok(factoryAccess.length >= 1, "expected a factory verifierBinding() query in the validation subtree");
    assert.ok(verifierAccess.length >= 1, "expected a verifier.verifyAuthority STATICCALL in the validation subtree");
  });

  it("requires zero account-originated access to EntryPoint code or storage in the validation subtree (OP-054)", async function () {
    const env = await fixture();
    await env.deployer.sendTransaction({
      to: env.accountAddress,
      value: ethers.parseEther("2")
    });
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    const trace = await traceExecutedTransaction(await execute(env, op));

    const entryCalls = findEntryPointOriginatedCalls(trace.structLogs, {
      targetAddress: env.accountAddress,
      selector: VALIDATE_USER_OP_SELECTOR
    });
    assert.equal(
      entryCalls.length,
      1,
      `trace-frame attribution is ambiguous: found ${entryCalls.length} ` +
        "candidate EntryPoint-originated validateUserOp entry calls"
    );
    const range = findCalledFrameRange(trace.structLogs, entryCalls[0]);

    const entryPointAddress = await env.entryPoint.getAddress();
    const findings = scanForbiddenTargetAccess(
      trace.structLogs,
      range,
      entryPointAddress
    );

    // Diagnostic identification: at the tests-only commit (baseline
    // bytecode), the single forbidden access is a STATICCALL whose calldata
    // selector is exactly getUserOpHash. This proves specific attribution,
    // not merely "something changed" -- before the gating assertion below
    // turns this same finding into a failure.
    if (findings.length > 0) {
      assert.equal(
        findings.length,
        1,
        `expected at most the single known getUserOpHash access, found ${findings.length}`
      );
      assert.equal(findings[0].op, "STATICCALL");
      assert.equal(findings[0].selector, GET_USER_OP_HASH_SELECTOR);
    }

    // The gate: after the OP-054 correction this must be zero. At the
    // tests-only commit (unmodified baseline bytecode) this fails because
    // the finding identified and confirmed above still exists.
    assert.equal(
      findings.length,
      0,
      "account-originated access to EntryPoint code/storage in the validation " +
        `subtree must be zero; found: ${JSON.stringify(findings)}`
    );
  });
});

// ---------------------------------------------------------------------------
// 3. Behavioral validation preserved by the OP-054 correction.
// ---------------------------------------------------------------------------

describe("O.37.10 behavioral validation preserved after the OP-054 correction", function () {
  it("rejects a caller other than the EntryPoint", async function () {
    const env = await fixture();
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    const hash = await env.entryPoint.getUserOpHash(op);
    await assert.rejects(
      env.account.connect(env.attacker).validateUserOp(op, hash, 0)
    );
  });

  it("rejects a zero supplied userOpHash even though local recomputation was removed", async function () {
    const env = await fixture();
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    await assert.rejects(
      directValidate(env, op, {
        userOpHash: ethers.ZeroHash,
        missingAccountFunds: 0
      })
    );
  });

  it("rejects a userOp whose sender does not match this account", async function () {
    const env = await fixture();
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    const wrongSenderOp = { ...op, sender: env.attacker.address };
    const hash = await env.entryPoint.getUserOpHash(wrongSenderOp);
    await assert.rejects(
      directValidate(env, wrongSenderOp, {
        userOpHash: hash,
        missingAccountFunds: 0
      })
    );
  });

  // The account also carries a raw `block.chainid != _deploymentChainId`
  // EVM-level guard. That immutable is fixed at construction (the factory's
  // constructor itself requires deploymentChainId == block.chainid), so a
  // live mismatch can only be produced by running validateUserOp on a chain
  // whose id differs from deployment. Hardhat's in-process network used by
  // this suite exposes no supported JSON-RPC method to mutate chainId at
  // runtime (hardhat_setChainId is unsupported; hardhat_reset silently
  // ignores a chainId override) -- confirmed by direct probing. This test
  // instead exercises the header-level chain binding
  // (`header.chainId != _deploymentChainId`, checked in
  // _validateHeaderAndOperation), the other chain-binding guard reachable
  // through a real handleOps call. The raw block.chainid guard is visibly
  // untouched by the OP-054 diff (the deletion is scoped to the
  // getUserOpHash clause only) and is not independently re-provable in this
  // environment.
  it("rejects a deployment-chain-mismatched intent header", async function () {
    const env = await fixture();
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0,
      mutateCore: (core) => {
        core.chainId += 1n;
      }
    });
    await assert.rejects(execute(env, op));
  });

  it("rejects a malformed or unauthorized signature/authority binding", async function () {
    const env = await fixture();
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0,
      signer: env.attacker
    });
    await assert.rejects(execute(env, op));
  });

  it("rejects disallowed paymaster data", async function () {
    const env = await fixture();
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0,
      mutateOperation: (userOp) => ({
        ...userOp,
        paymasterAndData: ethers.concat([
          env.attacker.address,
          ethers.toBeHex(0, 32),
          ethers.toBeHex(0, 32)
        ])
      })
    });
    await assert.rejects(execute(env, op));
  });

  it("rejects an invalid factory/initCode binding", async function () {
    const env = await fixture();
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0,
      mutateOperation: (userOp) => ({
        ...userOp,
        initCode: ethers.concat([env.attacker.address, "0x00"])
      })
    });
    await assert.rejects(execute(env, op));
  });

  it("rejects missingAccountFunds exceeding the intent's authorized maxTotalFeeWei", async function () {
    const env = await fixture();
    await env.deployer.sendTransaction({
      to: env.accountAddress,
      value: ethers.parseEther("10")
    });
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    const hash = await env.entryPoint.getUserOpHash(op);
    await assert.rejects(
      directValidate(env, op, {
        userOpHash: hash,
        missingAccountFunds: DEFAULT_MAX_TOTAL_FEE_WEI + 1n
      })
    );
  });

  it("rejects missingAccountFunds exceeding the account's available balance", async function () {
    const env = await fixture();
    // Fresh fixture: the account holds an EntryPoint deposit but zero native
    // balance of its own.
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    const hash = await env.entryPoint.getUserOpHash(op);
    assert.equal(await ethers.provider.getBalance(env.accountAddress), 0n);
    await assert.rejects(
      directValidate(env, op, { userOpHash: hash, missingAccountFunds: 1n })
    );
  });

  it("keeps the EntryPoint-supplied hash cryptographically bound through the typed authorization signature after removing local recomputation", async function () {
    const env = await fixture();
    await env.deployer.sendTransaction({
      to: env.accountAddress,
      value: ethers.parseEther("2")
    });
    const op = await buildOperation(env, {
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    const realHash = await env.entryPoint.getUserOpHash(op);
    const tamperedHash = ethers.keccak256(
      ethers.concat([realHash, "0x01"])
    );
    assert.notEqual(tamperedHash, realHash);
    assert.notEqual(tamperedHash, ethers.ZeroHash);
    // The signature was computed over realHash; supplying a different,
    // well-formed, nonzero hash must still be rejected -- now via the
    // typed-authorization signature path rather than the removed local
    // recomputation.
    await assert.rejects(
      directValidate(env, op, {
        userOpHash: tamperedHash,
        missingAccountFunds: 0
      })
    );
  });
});
