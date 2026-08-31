const assert = require("node:assert/strict");
const { artifacts, ethers } = require("hardhat");

const {
  ACTION,
  fixture,
  buildOperation,
  execute
} = require("../helpers/v2-minimal-account-test-harness.cjs");

const {
  VALIDATE_USER_OP_SELECTOR,
  GET_USER_OP_HASH_SELECTOR,
  CALL_WITH_VALUE_OPS,
  directValidate,
  decodeCallTargetAddress,
  decodeCallInputSelector,
  findEntryPointOriginatedCalls,
  findCalledFrameRange,
  scanForbiddenTargetAccess,
  findTargetAccess,
  traceExecutedTransaction
} = require("../helpers/erc7562-validation-harness.cjs");

// ERC-7562 OP-011 blocked environment opcodes. CHAINID (0x46) is intentionally
// absent: it is not on the OP-011 list, and Phil binds deploymentChainId at
// construction.
const OP011_BLOCKED_OPS = Object.freeze([
  "ORIGIN",
  "GASPRICE",
  "BLOCKHASH",
  "COINBASE",
  "TIMESTAMP",
  "NUMBER",
  "PREVRANDAO",
  "DIFFICULTY",
  "GASLIMIT",
  "BASEFEE",
  "BLOBHASH",
  "BLOBBASEFEE",
  "CREATE",
  "INVALID",
  "SELFDESTRUCT"
]);

const OP080_BALANCE_OPS = Object.freeze(["BALANCE", "SELFBALANCE"]);
const MUTATING_CALL_OPS = Object.freeze(["CALL", "CALLCODE", "DELEGATECALL"]);
const CREATE_OPS = Object.freeze(["CREATE", "CREATE2"]);
const KNOWN_PRECOMPILES = new Set([
  ...Array.from({ length: 17 }, (_, i) => `0x${(i + 1).toString(16).padStart(40, "0")}`),
  `0x${(0x100).toString(16).padStart(40, "0")}`
]);

function validationRange(trace, env) {
  const entryCalls = findEntryPointOriginatedCalls(trace.structLogs, {
    targetAddress: env.accountAddress,
    selector: VALIDATE_USER_OP_SELECTOR
  });
  assert.equal(entryCalls.length, 1, "expected one validateUserOp entry call");
  return findCalledFrameRange(trace.structLogs, entryCalls[0]);
}

function logsInRange(structLogs, range) {
  return structLogs.slice(range.start, range.end);
}

function callValue(op, stack) {
  if (!CALL_WITH_VALUE_OPS.has(op)) return 0n;
  return BigInt(`0x${stack[stack.length - 3]}`);
}

function assertGasImmediatelyCalls(logs) {
  for (let i = 0; i < logs.length; i++) {
    if (logs[i].op !== "GAS") continue;
    const consumer = logs[i + 1];
    assert.ok(consumer, "OP-012: GAS must be consumed");
    assert.match(
      consumer.op,
      /^(CALL|STATICCALL|DELEGATECALL|CALLCODE)$/,
      `OP-012: GAS at relative ${i} consumed by ${consumer && consumer.op}`
    );
  }
}

async function fundedTransferTrace() {
  const env = await fixture();
  await env.deployer.sendTransaction({
    to: env.accountAddress,
    value: ethers.parseEther("2")
  });
  const op = await buildOperation(env, {
    action: ACTION.TRANSFER,
    args: [env.recipient.address, ethers.parseEther("0.1")],
    lane: 0
  });
  const trace = await traceExecutedTransaction(await execute(env, op));
  return { env, trace, range: validationRange(trace, env) };
}

async function traceDirectValidation(env, op, missingAccountFunds = 0n) {
  const entryPointAddress = await env.entryPoint.getAddress();
  const userOpHash = await env.entryPoint.getUserOpHash(op);
  const trace = await ethers.provider.send("debug_traceCall", [
    {
      from: entryPointAddress,
      to: env.accountAddress,
      data: env.account.interface.encodeFunctionData("validateUserOp", [
        op,
        userOpHash,
        missingAccountFunds
      ])
    },
    "latest",
    { disableStorage: true, disableMemory: true, disableStack: false }
  ]);
  assert.equal(trace.failed, false, "validation trace must succeed");
  return trace.structLogs;
}

function executableBytecode(bytecode) {
  const bytes = Buffer.from(bytecode.slice(2), "hex");
  assert.ok(bytes.length > 2, "runtime bytecode must include metadata length");
  const metadataLength = bytes.readUInt16BE(bytes.length - 2);
  const codeEnd = bytes.length - metadataLength - 2;
  assert.ok(codeEnd > 0, "metadata length must leave executable bytecode");
  return bytes.subarray(0, codeEnd);
}

function assertEveryGasOpcodeImmediatelyCalls(bytecode, label) {
  const code = executableBytecode(bytecode);
  const callFamily = new Set([0xf1, 0xf2, 0xf4, 0xfa]);
  const gasSites = [];
  for (let pc = 0; pc < code.length; pc += 1) {
    const opcode = code[pc];
    if (opcode >= 0x60 && opcode <= 0x7f) {
      pc += opcode - 0x5f;
      continue;
    }
    if (opcode !== 0x5a) continue;
    gasSites.push(pc);
    assert.ok(
      callFamily.has(code[pc + 1]),
      `${label}: GAS at pc ${pc} is followed by 0x${(code[pc + 1] || 0)
        .toString(16)
        .padStart(2, "0")}`
    );
  }
  return gasSites.length;
}

describe("ERC-7562 V2 validation-path expansion (beyond OP-054)", function () {
  it("OP-011: validation subtree does not execute blocked environment opcodes", async function () {
    const { trace, range } = await fundedTransferTrace();
    const hits = logsInRange(trace.structLogs, range).filter((log) =>
      OP011_BLOCKED_OPS.includes(log.op)
    );
    assert.deepEqual(
      hits.map((log) => log.op),
      [],
      `OP-011 blocked opcodes in validateUserOp: ${JSON.stringify(hits)}`
    );
  });

  it("OP-012: every GAS in the validation subtree is immediately followed by *CALL", async function () {
    const { trace, range } = await fundedTransferTrace();
    const logs = logsInRange(trace.structLogs, range);
    assertGasImmediatelyCalls(logs);
  });

  it("OP-012: all executable GAS sites in account, verifier, and initCode factory runtime bytecode are call-adjacent", async function () {
    const accountArtifact = await artifacts.readArtifact(
      "PhilCoreV2MinimalAccountV2"
    );
    const verifierArtifact = await artifacts.readArtifact(
      "PhilCoreV2StaticAuthorityVerifier"
    );
    const factoryArtifact = await artifacts.readArtifact(
      "PhilCoreV2MinimalAccountFactoryV2"
    );
    const gasCounts = [];
    gasCounts.push(assertEveryGasOpcodeImmediatelyCalls(
      accountArtifact.deployedBytecode,
      "V2 account runtime"
    ));
    gasCounts.push(assertEveryGasOpcodeImmediatelyCalls(
      verifierArtifact.deployedBytecode,
      "V2 verifier runtime"
    ));
    gasCounts.push(assertEveryGasOpcodeImmediatelyCalls(
      factoryArtifact.deployedBytecode,
      "V2 initCode factory runtime"
    ));
    assert.ok(
      gasCounts.reduce((sum, count) => sum + count, 0) > 0,
      "the guarded V2 validation artifacts should contain applicable GAS sites"
    );
  });

  it("OP-012: every material ordinary action validation path preserves GAS-to-call adjacency", async function () {
    const env = await fixture();
    const cases = [
      [ACTION.CONFIRM, [ethers.id("op012-confirm")], 0],
      [ACTION.TRANSFER, [env.recipient.address, 1n], 0],
      [ACTION.WITHDRAW, [env.recipient.address, 1n], 0],
      [
        ACTION.ROTATE,
        [env.nextValidator.address, ethers.id("op012-next-validator"), 2],
        1
      ]
    ];

    for (const [action, args, lane] of cases) {
      const op = await buildOperation(env, { action, args, lane });
      assertGasImmediatelyCalls(await traceDirectValidation(env, op));
    }
  });

  it("OP-012: recovery request/cancel and configuration request/cancel validation paths preserve adjacency", async function () {
    const recoveryEnv = await fixture({ realVerifier: false });
    const request = await buildOperation(recoveryEnv, {
      action: ACTION.RECOVERY_REQUEST,
      args: [
        recoveryEnv.nextValidator.address,
        ethers.id("op012-recovery-key"),
        2,
        ethers.id("op012-recovery-salt")
      ],
      lane: 2,
      signatureOverride: "0x01"
    });
    assertGasImmediatelyCalls(await traceDirectValidation(recoveryEnv, request));
    await (await execute(recoveryEnv, request)).wait();
    const recoveryId = (await recoveryEnv.account.pendingRecovery())[0];
    const cancel = await buildOperation(recoveryEnv, {
      action: ACTION.RECOVERY_CANCEL,
      args: [recoveryId],
      lane: 2,
      signatureOverride: "0x01"
    });
    assertGasImmediatelyCalls(await traceDirectValidation(recoveryEnv, cancel));

    const configEnv = await fixture({ realVerifier: false });
    const configRequest = await buildOperation(configEnv, {
      action: ACTION.CONFIG_REQUEST,
      args: [
        ethers.id("op012-primary-replacement"),
        configEnv.hardware,
        configEnv.independent,
        2
      ],
      lane: 2,
      signatureOverride: "0x01"
    });
    assertGasImmediatelyCalls(
      await traceDirectValidation(configEnv, configRequest)
    );
    await (await execute(configEnv, configRequest)).wait();
    const configId = (
      await configEnv.account.pendingRecoveryConfigRotation()
    )[0];
    const configCancel = await buildOperation(configEnv, {
      action: ACTION.CONFIG_CANCEL,
      args: [configId],
      lane: 2,
      signatureOverride: "0x01"
    });
    assertGasImmediatelyCalls(
      await traceDirectValidation(configEnv, configCancel)
    );
  });

  it("OP-054: funded validation still has zero account access to EntryPoint code or storage", async function () {
    const { env, trace, range } = await fundedTransferTrace();
    const findings = scanForbiddenTargetAccess(
      trace.structLogs,
      range,
      await env.entryPoint.getAddress()
    );
    assert.equal(
      findings.length,
      0,
      `OP-054 regression: ${JSON.stringify(findings)}`
    );
    assert.equal(
      findings.some((finding) => finding.selector === GET_USER_OP_HASH_SELECTOR),
      false
    );
  });

  it("OP-061: validation subtree performs no CALL with value", async function () {
    const { trace, range } = await fundedTransferTrace();
    const valued = logsInRange(trace.structLogs, range).filter((log) => {
      if (!CALL_WITH_VALUE_OPS.has(log.op)) return false;
      return callValue(log.op, log.stack) !== 0n;
    });
    assert.deepEqual(
      valued.map((log) => log.op),
      [],
      `OP-061 valued calls during validation: ${JSON.stringify(valued)}`
    );
  });

  it("OP-041/external calls: validation only STATICCALLs the factory and verifier, never empty-code targets", async function () {
    const { env, trace, range } = await fundedTransferTrace();
    const factory = (await env.factory.getAddress()).toLowerCase();
    const verifier = (await env.verifier.getAddress()).toLowerCase();
    const account = env.accountAddress.toLowerCase();
    const allowed = new Set([factory, verifier, account, ...KNOWN_PRECOMPILES]);
    const calls = [];
    for (const log of logsInRange(trace.structLogs, range)) {
      if (
        !["CALL", "STATICCALL", "DELEGATECALL", "CALLCODE", "EXTCODESIZE", "EXTCODEHASH", "EXTCODECOPY"].includes(
          log.op
        )
      ) {
        continue;
      }
      const target = decodeCallTargetAddress(log.op, log.stack);
      if (!target || target === `0x${"00".repeat(20)}`) continue;
      calls.push({ op: log.op, target, selector: decodeCallInputSelector(log.op, log.stack, log.memory) });
      if (KNOWN_PRECOMPILES.has(target)) {
        continue;
      }
      const code = await ethers.provider.getCode(target);
      assert.notEqual(code, "0x", `OP-041: validation used address without code ${target}`);
      assert.ok(
        allowed.has(target),
        `unexpected validation-time target ${log.op} ${target}`
      );
    }
    assert.equal(
      calls.some((call) => MUTATING_CALL_OPS.includes(call.op)),
      false,
      `mutating calls during validation: ${JSON.stringify(calls)}`
    );
    assert.ok(
      calls.some((call) => call.target === factory && call.op === "STATICCALL"),
      "expected factory verifierBinding STATICCALL"
    );
    assert.ok(
      calls.some((call) => call.target === verifier && call.op === "STATICCALL"),
      "expected verifier.verifyAuthority STATICCALL"
    );
  });

  it("OP-080: funded validation (unstaked account, missingAccountFunds=0) does not execute BALANCE or SELFBALANCE", async function () {
    const { trace, range } = await fundedTransferTrace();
    const hits = logsInRange(trace.structLogs, range).filter((log) =>
      OP080_BALANCE_OPS.includes(log.op)
    );
    assert.deepEqual(
      hits.map((log) => log.op),
      [],
      `OP-080 balance opcodes on funded path: ${JSON.stringify(hits)}`
    );
  });

  it("STO-010: validation SLOADs only the account; factory and verifier storage stay empty", async function () {
    const { env, trace, range } = await fundedTransferTrace();
    const account = env.accountAddress.toLowerCase();
    const factory = (await env.factory.getAddress()).toLowerCase();
    const verifier = (await env.verifier.getAddress()).toLowerCase();
    const storageOps = logsInRange(trace.structLogs, range).filter((log) =>
      ["SLOAD", "SSTORE", "TLOAD", "TSTORE"].includes(log.op)
    );
    assert.equal(
      storageOps.some((log) => log.op === "SSTORE" || log.op === "TSTORE"),
      false,
      "validation must not write storage"
    );
    // Hardhat structLogs do not always include the current address; SLOAD in
    // the account frame is attributed by depth relative to validateUserOp.
    const accountDepth = trace.structLogs[range.start].depth;
    for (const log of storageOps) {
      assert.equal(log.op, "SLOAD");
      assert.equal(
        log.depth,
        accountDepth,
        "SLOAD outside the account validation frame"
      );
    }
    assert.equal(await ethers.provider.getStorage(factory, 0), ethers.ZeroHash);
    assert.equal(await ethers.provider.getStorage(verifier, 0), ethers.ZeroHash);
    assert.notEqual(account, factory);
    assert.notEqual(account, verifier);
  });

  it("CREATE/CREATE2/DELEGATECALL are absent from validateUserOp of an already-deployed account", async function () {
    const { trace, range } = await fundedTransferTrace();
    const hits = logsInRange(trace.structLogs, range).filter((log) =>
      [...CREATE_OPS, "DELEGATECALL", "CALLCODE", "SELFDESTRUCT"].includes(log.op)
    );
    assert.deepEqual(hits.map((log) => log.op), []);
  });

  it("OP-080/OP-053: prefund validation avoids balance opcodes and pays only EntryPoint", async function () {
    const env = await fixture();
    await env.deployer.sendTransaction({
      to: env.accountAddress,
      value: ethers.parseEther("1")
    });
    const op = await buildOperation(env, {
      action: ACTION.TRANSFER,
      args: [env.recipient.address, ethers.parseEther("0.1")],
      lane: 0
    });
    const hash = await env.entryPoint.getUserOpHash(op);
    const entryPointAddress = await env.entryPoint.getAddress();
    const entryPointSigner = await ethers.getImpersonatedSigner(entryPointAddress);
    await env.deployer.sendTransaction({
      to: entryPointAddress,
      value: ethers.parseEther("1")
    });
    const trace = await ethers.provider.send("debug_traceCall", [
      {
        from: entryPointAddress,
        to: env.accountAddress,
        data: env.account.interface.encodeFunctionData("validateUserOp", [
          op,
          hash,
          ethers.parseEther("0.01")
        ])
      },
      "latest",
      { disableStorage: true, disableMemory: true, disableStack: false }
    ]);
    assert.equal(trace.failed, false);
    assertGasImmediatelyCalls(trace.structLogs);
    const balanceOps = trace.structLogs.filter((log) =>
      OP080_BALANCE_OPS.includes(log.op)
    );
    assert.deepEqual(
      balanceOps.map((log) => log.op),
      [],
      `OP-080 balance opcodes on prefund path: ${JSON.stringify(balanceOps)}`
    );
    const valuedCalls = trace.structLogs.filter(
      (log) => CALL_WITH_VALUE_OPS.has(log.op) && callValue(log.op, log.stack) !== 0n
    );
    assert.equal(valuedCalls.length, 1, "expected exactly one prefund value call");
    assert.equal(valuedCalls[0].op, "CALL");
    assert.equal(
      decodeCallTargetAddress(valuedCalls[0].op, valuedCalls[0].stack),
      entryPointAddress.toLowerCase()
    );
    assert.equal(await entryPointSigner.getAddress(), entryPointAddress);
    await assert.doesNotReject(
      directValidate(env, op, {
        userOpHash: hash,
        missingAccountFunds: ethers.parseEther("0.01")
      })
    );
  });
});
