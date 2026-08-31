const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("hardhat");

const {
  ACTION,
  fixture,
  securityState,
  buildOperation,
  execute,
  increaseTime,
  recoveryConfigHash
} = require("../helpers/v2-minimal-account-test-harness.cjs");

const ROOT = path.resolve(__dirname, "../..");
const VERIFIER_SOURCE = path.join(
  ROOT,
  "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol"
);
const ACCOUNT_SOURCE = path.join(
  ROOT,
  "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol"
);
const O374 = JSON.parse(
  fs.readFileSync(
    path.join(
      ROOT,
      "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json"
    ),
    "utf8"
  )
);
const O372 = JSON.parse(
  fs.readFileSync(
    path.join(
      ROOT,
      "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json"
    ),
    "utf8"
  )
);

const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const DELAY_SECONDS = 172800;
const EXPIRY_SECONDS = 604800;
const ALLOWED_FACTOR_BITMAPS = Object.freeze([3, 5, 6]);

async function requestRecovery(env, saltSuffix) {
  const args = [
    env.nextValidator.address,
    ethers.id(`fsm-recovered-key-${saltSuffix}`),
    2,
    ethers.id(`fsm-recovery-salt-${saltSuffix}`)
  ];
  const request = await buildOperation(env, {
    action: ACTION.RECOVERY_REQUEST,
    args,
    lane: 2,
    signatureOverride: "0x01"
  });
  await (await execute(env, request)).wait();
  return env.account.pendingRecovery();
}

async function cancelPendingRecovery(env, requestId) {
  const cancel = await buildOperation(env, {
    action: ACTION.RECOVERY_CANCEL,
    args: [requestId],
    lane: 2,
    signatureOverride: "0x01"
  });
  await (await execute(env, cancel)).wait();
}

async function snapshotUnrelatedState(env) {
  const config = await env.account.accountConfiguration();
  const state = await securityState(env);
  const native = await ethers.provider.getBalance(env.accountAddress);
  return {
    entryPoint: config[0],
    chainId: config[1],
    ownerCommitment: config[2],
    identityBinding: config[3],
    factory: config[4],
    accountVersionId: config[5],
    securityModelId: config[6],
    confirmationTarget: config[7],
    primary: state.primary,
    hardware: state.hardware,
    independent: state.independent,
    recoveryConfigHash: state.recoveryConfigHash,
    verifierKind: state.verifierKind,
    native
  };
}

function assertUnrelatedStateFrozen(before, after, { nativeMayChange = false } = {}) {
  assert.equal(after.entryPoint, before.entryPoint);
  assert.equal(after.chainId, before.chainId);
  assert.equal(after.ownerCommitment, before.ownerCommitment);
  assert.equal(after.identityBinding, before.identityBinding);
  assert.equal(after.factory, before.factory);
  assert.equal(after.accountVersionId, before.accountVersionId);
  assert.equal(after.securityModelId, before.securityModelId);
  assert.equal(after.confirmationTarget, before.confirmationTarget);
  assert.equal(after.primary, before.primary);
  assert.equal(after.hardware, before.hardware);
  assert.equal(after.independent, before.independent);
  assert.equal(after.recoveryConfigHash, before.recoveryConfigHash);
  assert.equal(after.verifierKind, before.verifierKind);
  if (!nativeMayChange) {
    assert.equal(after.native, before.native);
  }
}

async function bumpPackedValidatorEpoch(accountAddress) {
  const slot0 = await ethers.provider.getStorage(accountAddress, 0);
  const word = BigInt(slot0);
  const epochShift = 160n;
  const bumped = word + (1n << epochShift);
  await ethers.provider.send("hardhat_setStorageAt", [
    accountAddress,
    ethers.toBeHex(0, 32),
    ethers.toBeHex(bumped, 32)
  ]);
}

function recoveryRequestFromFixture(validFixture) {
  const recovery = validFixture.recoveryEvidence;
  const context = recovery.context;
  const validatorEnvelope =
    validFixture.validatorEnvelope ||
    O374.valid.validatorPlusPrimaryAndHardwareConfigRotation.validatorEnvelope;
  const descriptor = recovery.firstEvidence.descriptor;
  return {
    actionType: Number(context.actionType),
    account: context.account,
    chainId: context.chainId,
    entryPoint: context.entryPoint,
    accountVersionId: descriptor.accountVersionId,
    securityModelId: descriptor.securityModelId,
    authorizedIntentHash: context.authorizedIntentHash,
    userOpHash: context.userOperationHash,
    validator: validatorEnvelope.validator,
    validatorKeyIdBinding: validatorEnvelope.validatorKeyIdBinding,
    validatorEpoch: context.validatorEpoch,
    recoveryEpoch: context.recoveryEpoch,
    recoveryConfigHash: context.currentRecoveryConfigHash,
    requestId: context.requestId,
    validAfter: context.validAfter,
    validUntil: context.validUntil,
    proposedValidatorCommitment: context.proposedValidatorCommitment,
    proposedRecoveryConfigHash: context.proposedRecoveryConfigHash,
    proposedRecoveryEpoch: context.proposedRecoveryEpoch,
    primaryDeviceCommitment: context.primaryDeviceCommitment,
    hardwareSecurityKeyCommitment: context.hardwareSecurityKeyCommitment,
    recoveryFactorCommitment: context.recoveryFactorCommitment
  };
}

describe("V2 recovery FSM invariants (CL-020)", function () {
  it("locks exact permitted 2-of-3 factor bitmaps in the verifier (properties 3-6)", function () {
    const source = fs.readFileSync(VERIFIER_SOURCE, "utf8");
    assert.match(source, /if \(bitmap == 3\) return \(0, 1\);/);
    assert.match(source, /if \(bitmap == 5\) return \(0, 2\);/);
    assert.match(source, /if \(bitmap == 6\) return \(1, 2\);/);
    assert.match(source, /revert RecoveryFactorBitmapInvalid/);
    assert.equal(source.includes("if (bitmap == 7)"), false);
    assert.equal(source.includes("if (bitmap == 1)"), false);
    assert.equal(source.includes("if (bitmap == 2)"), false);
    assert.equal(source.includes("if (bitmap == 4)"), false);
    const account = fs.readFileSync(ACCOUNT_SOURCE, "utf8");
    assert.match(account, /uint8 private constant ACTION_RECOVERY_REQUEST = 8;/);
    assert.match(account, /function settleRecovery\(bytes32 recoveryRequestId\)/);
  });

  it("rejects invalid bitmap, single-factor quorum, and duplicate-factor evidence at the verifier (properties 3-5)", async function () {
    const Verifier = await ethers.getContractFactory(
      "PhilCoreV2StaticAuthorityVerifier"
    );
    const verifier = await Verifier.deploy();
    const valid = O374.valid.validatorPlusPrimaryAndHardwareConfigRotation;
    const request = recoveryRequestFromFixture(valid);
    await ethers.provider.send("hardhat_impersonateAccount", [request.account]);
    await ethers.provider.send("hardhat_setBalance", [
      request.account,
      ethers.toBeHex(ethers.parseEther("1"))
    ]);
    const signer = await ethers.getSigner(request.account);
    const connected = verifier.connect(signer);

    for (const id of ["wrong_bitmap", "duplicate_factor", "wrong_role_order"]) {
      const invalid = O374.invalid.find((candidate) => candidate.id === id);
      assert.ok(invalid, id);
      await assert.rejects(
        connected.verifyAuthority.staticCall(request, invalid.encodedEnvelope),
        id
      );
    }
  });

  it("cannot settle before the recovery delay (property 1)", async function () {
    const env = await fixture({ realVerifier: false });
    const pending = await requestRecovery(env, "before-delay");
    await assert.rejects(env.account.settleRecovery(pending[0]));
    await increaseTime(DELAY_SECONDS / 2);
    await assert.rejects(env.account.settleRecovery(pending[0]));
    assert.equal((await env.account.pendingRecovery())[0], pending[0]);
  });

  it("cannot complete recovery after expiry; pending is cleared fail-closed (property 2)", async function () {
    const env = await fixture({ realVerifier: false });
    const before = await snapshotUnrelatedState(env);
    const pending = await requestRecovery(env, "after-expiry");
    const validatorBefore = (await securityState(env)).validator;
    await increaseTime(EXPIRY_SECONDS);
    await (await env.account.settleRecovery(pending[0])).wait();
    const state = await securityState(env);
    assert.equal(state.validator, validatorBefore);
    assert.equal(state.validatorEpoch, 1n);
    assert.equal(state.recoveryEpoch, 1n);
    assert.equal((await env.account.pendingRecovery())[0], ethers.ZeroHash);
    assertUnrelatedStateFrozen(before, await snapshotUnrelatedState(env));
    await assert.rejects(env.account.settleRecovery(pending[0]));
  });

  it("rejects validator-only recovery and unknown callData (properties 4 and 8)", async function () {
    const env = await fixture();
    const validatorOnly = await buildOperation(env, {
      action: ACTION.RECOVERY_REQUEST,
      args: [
        env.nextValidator.address,
        ethers.id("fsm-validator-only-key"),
        2,
        ethers.id("fsm-validator-only-salt")
      ],
      lane: 2
    });
    await assert.rejects(execute(env, validatorOnly));

    await assert.rejects(
      env.attacker.sendTransaction({
        to: env.accountAddress,
        data: "0xdeadbeef"
      })
    );
  });

  it("recovery settlement cannot transfer value or mutate unrelated account state (properties 7 and 9)", async function () {
    const env = await fixture({ realVerifier: false });
    await env.deployer.sendTransaction({
      to: env.accountAddress,
      value: ethers.parseEther("1")
    });
    const recipientBefore = await ethers.provider.getBalance(env.recipient.address);
    const before = await snapshotUnrelatedState(env);
    const pending = await requestRecovery(env, "no-value");
    await increaseTime(DELAY_SECONDS);
    await (await env.account.settleRecovery(pending[0])).wait();
    const after = await snapshotUnrelatedState(env);
    const state = await securityState(env);
    assert.equal(state.validator, env.nextValidator.address);
    assert.equal(state.validatorEpoch, 2n);
    assert.equal(state.recoveryEpoch, 2n);
    assert.equal(after.native, before.native);
    assert.equal(
      await ethers.provider.getBalance(env.recipient.address),
      recipientBefore
    );
    assertUnrelatedStateFrozen(before, after);
  });

  it("freezes conflicting rotation while recovery is pending, and stale source epochs cannot settle (property 10)", async function () {
    const env = await fixture({ realVerifier: false });
    const pending = await requestRecovery(env, "stale-epoch");
    const rotate = await buildOperation(env, {
      action: ACTION.ROTATE,
      args: [
        env.nextValidator.address,
        ethers.id("fsm-conflicting-validator-key"),
        2
      ],
      lane: 1,
      signatureOverride: "0x01"
    });
    await assert.rejects(execute(env, rotate));
    const configRotate = await buildOperation(env, {
      action: ACTION.CONFIG_REQUEST,
      args: [
        ethers.id("fsm-conflicting-primary"),
        env.hardware,
        env.independent,
        2
      ],
      lane: 2,
      signatureOverride: "0x01"
    });
    await assert.rejects(execute(env, configRotate));
    const pendingAfterConflict = await env.account.pendingRecovery();
    assert.deepEqual([...pendingAfterConflict], [...pending]);
    const configAfterConflict =
      await env.account.pendingRecoveryConfigRotation();
    assert.equal(configAfterConflict[0], ethers.ZeroHash);
    assert.equal(configAfterConflict[1], ethers.ZeroHash);
    assert.equal(configAfterConflict[5], 0n);

    await bumpPackedValidatorEpoch(env.accountAddress);
    await increaseTime(DELAY_SECONDS);
    await assert.rejects(env.account.settleRecovery(pending[0]));
    assert.equal((await env.account.pendingRecovery())[0], pending[0]);
  });

  it("cancelled recovery cannot later settle (property 12)", async function () {
    const env = await fixture({ realVerifier: false });
    const pending = await requestRecovery(env, "cancel-then-settle");
    await cancelPendingRecovery(env, pending[0]);
    assert.equal((await env.account.pendingRecovery())[0], ethers.ZeroHash);
    assert.equal((await securityState(env)).recoveryState, 3n);
    await increaseTime(DELAY_SECONDS);
    await assert.rejects(env.account.settleRecovery(pending[0]));
  });

  it("settled recovery cannot settle again or be replayed (properties 11 and 13)", async function () {
    const env = await fixture({ realVerifier: false });
    const pending = await requestRecovery(env, "settle-replay");
    await increaseTime(DELAY_SECONDS);
    await (await env.account.settleRecovery(pending[0])).wait();
    assert.equal((await securityState(env)).recoveryState, 2n);
    await assert.rejects(env.account.settleRecovery(pending[0]));
    await assert.rejects(env.account.settleRecovery(ethers.ZeroHash));
  });

  it("recovery-factor rotation preserves the exact 2-of-3 role model and does not mutate validator authority (properties 14 and 16)", async function () {
    const env = await fixture({ realVerifier: false });
    const validatorBefore = await securityState(env);
    const replacement = ethers.id("fsm-primary-replacement");
    const args = [replacement, env.hardware, env.independent, 2];
    const request = await buildOperation(env, {
      action: ACTION.CONFIG_REQUEST,
      args,
      lane: 2,
      signatureOverride: "0x01"
    });
    await (await execute(env, request)).wait();
    const pending = await env.account.pendingRecoveryConfigRotation();
    await increaseTime(DELAY_SECONDS);
    await (await env.account.settleRecoveryConfigRotation(pending[0])).wait();
    const after = await securityState(env);
    assert.equal(after.validator, validatorBefore.validator);
    assert.equal(after.validatorKey, validatorBefore.validatorKey);
    assert.equal(after.validatorEpoch, validatorBefore.validatorEpoch);
    assert.equal(after.primary, replacement);
    assert.equal(after.hardware, env.hardware);
    assert.equal(after.independent, env.independent);
    assert.notEqual(after.primary, after.hardware);
    assert.notEqual(after.primary, after.independent);
    assert.notEqual(after.hardware, after.independent);
    assert.equal(
      after.recoveryConfigHash,
      recoveryConfigHash(replacement, env.hardware, env.independent)
    );
    assert.equal(after.recoveryEpoch, 2n);
  });

  it("validator rotation cannot silently mutate recovery authority (property 15)", async function () {
    const env = await fixture({ realVerifier: false });
    const before = await securityState(env);
    const rotate = await buildOperation(env, {
      action: ACTION.ROTATE,
      args: [
        env.nextValidator.address,
        ethers.id("fsm-rotated-validator-key"),
        2
      ],
      lane: 1,
      signatureOverride: "0x01"
    });
    await (await execute(env, rotate)).wait();
    const after = await securityState(env);
    assert.equal(after.validator, env.nextValidator.address);
    assert.equal(after.validatorEpoch, 2n);
    assert.equal(after.primary, before.primary);
    assert.equal(after.hardware, before.hardware);
    assert.equal(after.independent, before.independent);
    assert.equal(after.recoveryConfigHash, before.recoveryConfigHash);
    assert.equal(after.recoveryEpoch, before.recoveryEpoch);
  });

  it("malformed recovery transitions fail closed (property 17)", async function () {
    const env = await fixture({ realVerifier: false });
    await assert.rejects(env.account.settleRecovery(ethers.ZeroHash));
    await assert.rejects(env.account.settleRecovery(ethers.id("missing")));
    await assert.rejects(
      buildOperation(env, {
        action: ACTION.RECOVERY_CANCEL,
        args: [ethers.id("not-pending")],
        lane: 2,
        signatureOverride: "0x01"
      }).then((op) => execute(env, op))
    );

    const pending = await requestRecovery(env, "malformed");
    const second = await buildOperation(env, {
      action: ACTION.RECOVERY_REQUEST,
      args: [
        env.nextValidator.address,
        ethers.id("fsm-second-key"),
        2,
        ethers.id("fsm-second-salt")
      ],
      lane: 2,
      signatureOverride: "0x01"
    });
    await assert.rejects(execute(env, second));
    const confirm = await buildOperation(env, {
      action: ACTION.CONFIRM,
      args: [ethers.id("frozen-confirm")],
      lane: 0,
      signatureOverride: "0x01"
    });
    await assert.rejects(execute(env, confirm));
    await assert.rejects(env.account.settleRecovery(ethers.id("wrong-id")));
    assert.equal((await env.account.pendingRecovery())[0], pending[0]);
  });
});

describe("V2 recovery FSM permitted factor bitmap lock", function () {
  it("documents that only bitmaps 3, 5, and 6 are exact 2-of-3 role pairs (property 6)", function () {
    assert.deepEqual([...ALLOWED_FACTOR_BITMAPS], [3, 5, 6]);
    const source = fs.readFileSync(VERIFIER_SOURCE, "utf8");
    const matches = [...source.matchAll(/if \(bitmap == (\d+)\) return/g)].map(
      (match) => Number(match[1])
    );
    assert.deepEqual(matches, [3, 5, 6]);
    assert.ok(O372 || O374);
  });
});
