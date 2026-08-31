const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { p256 } = require("@noble/curves/p256");
const { ethers } = require("hardhat");
const {
  createPhilAuthorizationEnvelopeV1,
  derivePhilAuthorizationEnvelopeDigestV1
} = require("../../apps/phil-device-sdk/src/authorizationEnvelopeV1.ts");
const { derivePhilDeviceApprovalDigestV1 } = require(
  "../../apps/phil-device-sdk/src/deviceApprovalV1.ts"
);
const {
  PHIL_BASE_MAINNET_CHAIN_ID,
  PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS,
  createPhilBaseMainnetAdapterAuthorizationV1,
  createPhilEvmSingleCallV1,
  derivePhilEvmAccountBindingHashV1,
  derivePhilEvmIntentDigestV1,
  derivePhilEvmNonceDomainV1
} = require("../../apps/phil-device-sdk/src/networkAdapterV1.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const STEP6A_FIXTURE = JSON.parse(fs.readFileSync(
  path.join(REPO_ROOT, "config/adapters/PHIL_V1_STEP6A_BASE_ADAPTER_FIXTURE.json"),
  "utf8"
));
const SYNTHETIC_PRIVATE_KEY = Uint8Array.from({ length: 32 }, (_, index) => index === 31 ? 1 : 0);
const SYNTHETIC_PUBLIC_KEY = p256.getPublicKey(SYNTHETIC_PRIVATE_KEY, false);
const PUBLIC_KEY_X = `0x${Buffer.from(SYNTHETIC_PUBLIC_KEY.slice(1, 33)).toString("hex")}`;
const PUBLIC_KEY_Y = `0x${Buffer.from(SYNTHETIC_PUBLIC_KEY.slice(33, 65)).toString("hex")}`;
const VALID_AFTER = 1_800_000_000;
const VALID_UNTIL = 1_800_003_600;
const POLICY_MAX_VALUE_WEI = 2_000n;
const POLICY_MAX_FEE_WEI = 6_000_000_000_000_000n;
const P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const UINT64_MAX = (1n << 64n) - 1n;

function capabilityBindingHash(envelope = STEP6A_FIXTURE.envelope) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "uint64"],
    [
      ethers.id("PHIL_STEP6B_CAPABILITY_BINDING_V1"),
      envelope.scopeId,
      envelope.scopeInstance,
      envelope.scopeEpoch,
      envelope.principalIdHash,
      envelope.capabilityId,
      envelope.capabilityEpoch
    ]
  ));
}

function pack128(high, low) {
  return ethers.toBeHex((BigInt(high) << 128n) | BigInt(low), 32);
}

function contractAction(action) {
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

function contractEnvelope(envelope) {
  const { formatVersionHash: _formatVersionHash, ...rest } = envelope;
  return rest;
}

function encodeExecutionCall(account, built, overrides = {}) {
  return account.interface.encodeFunctionData("executeAuthorized", [
    overrides.action ?? contractAction(built.action),
    overrides.envelope ?? contractEnvelope(built.envelope),
    overrides.approval ?? built.approval,
    overrides.targetCalldata ?? built.targetCalldata
  ]);
}

function encodeP256Signature(signature) {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32"],
    [ethers.toBeHex(signature.r, 32), ethers.toBeHex(signature.s, 32)]
  );
}

async function expectCustomError(promise, errorName, label = errorName) {
  await assert.rejects(promise, new RegExp(errorName), `${label} did not reach ${errorName}`);
}

async function accountConstructorArgs(target, overrides = {}) {
  return [
    overrides.trustedManifestHash ?? STEP6A_FIXTURE.manifest.manifestHash,
    overrides.enrolledDeviceId ?? STEP6A_FIXTURE.deviceApproval.deviceId,
    overrides.enrolledDeviceKeyId ?? STEP6A_FIXTURE.deviceApproval.deviceKeyId,
    overrides.enrolledDeviceEpoch ?? STEP6A_FIXTURE.deviceApproval.deviceEpoch,
    overrides.enrolledScopedOwnerCommitment ?? STEP6A_FIXTURE.envelope.scopedOwnerCommitment,
    overrides.enforcedPolicyHash ?? STEP6A_FIXTURE.envelope.policyHash,
    overrides.trustedCapabilityBindingHash ?? capabilityBindingHash(),
    overrides.approvedTarget ?? await target.getAddress(),
    overrides.policyMaxValueWei ?? POLICY_MAX_VALUE_WEI,
    overrides.policyMaxFeeWei ?? POLICY_MAX_FEE_WEI,
    overrides.devicePublicKeyX ?? PUBLIC_KEY_X,
    overrides.devicePublicKeyY ?? PUBLIC_KEY_Y
  ];
}

async function installEntryPointHarness() {
  const Harness = await ethers.getContractFactory("PhilV1Step6BLocalEntryPointHarness");
  const deployed = await Harness.deploy();
  await deployed.waitForDeployment();
  const runtimeCode = await ethers.provider.getCode(await deployed.getAddress());
  await ethers.provider.send("hardhat_setCode", [PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS, runtimeCode]);
  return ethers.getContractAt("PhilV1Step6BLocalEntryPointHarness", PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS);
}

async function fixture({ timestamp = VALID_AFTER + 100, mineTimestamp = true } = {}) {
  await ethers.provider.send("hardhat_reset", []);
  assert.equal((await ethers.provider.getNetwork()).chainId, PHIL_BASE_MAINNET_CHAIN_ID);
  const entryPoint = await installEntryPointHarness();
  const Target = await ethers.getContractFactory("PhilSmartAccountExecutionTarget");
  const target = await Target.deploy();
  const Account = await ethers.getContractFactory("PhilV1Step6BLocalAccount");
  const account = await Account.deploy(...await accountConstructorArgs(target));
  await account.waitForDeployment();
  await ethers.provider.send("evm_setNextBlockTimestamp", [timestamp]);
  if (mineTimestamp) await ethers.provider.send("evm_mine");
  return { account, entryPoint, target };
}

async function buildUserOperation({
  account,
  target,
  nonceKey = 7n,
  nonceSequence = 0n,
  targetFunction = "ping",
  valueWei = 0n,
  maxFeePerGas = 1_000_000_000n
}) {
  const targetCalldata = target.interface.encodeFunctionData(targetFunction, targetFunction === "ping"
    ? [ethers.id(`step6b-ping-${nonceSequence}`)]
    : []);
  const action = createPhilEvmSingleCallV1({
    chainId: PHIL_BASE_MAINNET_CHAIN_ID,
    account: await account.getAddress(),
    entryPoint: PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS,
    target: await target.getAddress(),
    targetCalldataHash: ethers.keccak256(targetCalldata),
    valueWei,
    nonceKey,
    nonceSequence,
    callGasLimit: 300_000,
    verificationGasLimit: 5_000_000,
    preVerificationGas: 50_000,
    maxFeePerGas,
    maxPriorityFeePerGas: 100_000_000,
    validAfter: VALID_AFTER,
    validUntil: VALID_UNTIL
  });
  const envelope = createPhilAuthorizationEnvelopeV1({
    ...STEP6A_FIXTURE.envelope,
    accountBindingHash: derivePhilEvmAccountBindingHashV1(STEP6A_FIXTURE.manifest, action),
    parametersHash: action.actionHash,
    intentDigest: derivePhilEvmIntentDigestV1(STEP6A_FIXTURE.manifest, action),
    nonceDomain: derivePhilEvmNonceDomainV1(STEP6A_FIXTURE.manifest, action),
    nonce: action.userOpNonce,
    validAfter: action.validAfter,
    validUntil: action.validUntil,
    valueLimit: action.valueWei,
    feeLimit: action.maxTotalFeeWei
  });
  const approval = {
    ...STEP6A_FIXTURE.deviceApproval,
    approvedAt: VALID_AFTER + 1,
    approvalExpiresAt: VALID_AFTER + 300,
    approvalNonce: ethers.id(`step6b-approval-${nonceSequence}`)
  };
  const authorization = createPhilBaseMainnetAdapterAuthorizationV1({
    manifest: STEP6A_FIXTURE.manifest,
    trustedManifestHash: STEP6A_FIXTURE.manifest.manifestHash,
    envelope,
    action,
    deviceApproval: approval
  });
  assert.equal(derivePhilAuthorizationEnvelopeDigestV1(envelope), authorization.authorizationEnvelopeDigest);
  assert.equal(derivePhilDeviceApprovalDigestV1({
    authorizationEnvelopeDigest: authorization.authorizationEnvelopeDigest,
    ...approval
  }), authorization.deviceApprovalDigest);

  const signature = p256.sign(
    ethers.getBytes(authorization.deviceApprovalDigest),
    SYNTHETIC_PRIVATE_KEY,
    { lowS: true }
  );
  const encodedSignature = encodeP256Signature(signature);
  const callData = account.interface.encodeFunctionData("executeAuthorized", [
    contractAction(action),
    contractEnvelope(envelope),
    approval,
    targetCalldata
  ]);
  return {
    action,
    envelope,
    approval,
    authorization,
    targetCalldata,
    userOp: {
      sender: await account.getAddress(),
      nonce: action.userOpNonce,
      initCode: "0x",
      callData,
      accountGasLimits: pack128(action.verificationGasLimit, action.callGasLimit),
      preVerificationGas: action.preVerificationGas,
      gasFees: pack128(action.maxPriorityFeePerGas, action.maxFeePerGas),
      paymasterAndData: "0x",
      signature: encodedSignature
    }
  };
}

describe("Phil V1 Step 6B local smart-account enforcement", function () {
  it("reproduces Step 6A hashes, verifies a real low-S P-256 approval, and executes exactly once", async function () {
    const { account, entryPoint, target } = await fixture();
    const built = await buildUserOperation({ account, target });
    assert.equal(await account.trustedManifestHash(), STEP6A_FIXTURE.manifest.manifestHash);
    assert.equal(await account.EVM_SINGLE_CALL_V1(), built.envelope.actionTypeHash);
    const preview = await account.previewAuthorization(
      contractAction(built.action),
      contractEnvelope(built.envelope),
      built.approval,
      built.targetCalldata
    );
    assert.equal(preview.deviceApprovalDigest, built.authorization.deviceApprovalDigest);
    assert.equal(preview.envelopeDigest, built.authorization.authorizationEnvelopeDigest);
    assert.equal(preview.authorizationHash, built.authorization.authorizationHash);
    await entryPoint.validateAndExecute(built.userOp, { gasLimit: 12_000_000 });
    assert.equal(await target.calls(), 1n);
    assert.equal(await target.lastCaller(), await account.getAddress());
    assert.equal(await account.nextNonceSequence(7), 1n);
    assert.equal(await account.consumedAuthorization(built.authorization.authorizationHash), true);
    await assert.rejects(
      entryPoint.validateAndExecute(built.userOp, { gasLimit: 12_000_000 }),
      /PhilStep6B(NonceMismatch|AuthorizationAlreadyConsumed)/
    );
    assert.equal(await target.calls(), 1n);
  });

  it("blocks every direct execution path, including a valid approved package", async function () {
    const { account, target } = await fixture();
    const built = await buildUserOperation({ account, target });
    await assert.rejects(
      account.executeAuthorized(
        contractAction(built.action),
        contractEnvelope(built.envelope),
        built.approval,
        built.targetCalldata
      ),
      /PhilStep6BOnlyEntryPoint/
    );
    assert.equal(await target.calls(), 0n);
  });

  it("fails closed on signature, raw UserOperation, action, envelope, device, and calldata substitution", async function () {
    const cases = [
      ["signature", "PhilStep6BHarnessSignatureFailed", (built) => ({
        ...built.userOp,
        signature: `0x${"00".repeat(64)}`
      })],
      ["nonce", "PhilStep6BUserOperationMismatch", (built) => ({
        ...built.userOp,
        nonce: BigInt(built.userOp.nonce) + 1n
      })],
      ["gas", "PhilStep6BUserOperationMismatch", (built) => ({
        ...built.userOp,
        preVerificationGas: BigInt(built.userOp.preVerificationGas) + 1n
      })],
      ["initCode", "PhilStep6BUserOperationMismatch", (built) => ({ ...built.userOp, initCode: "0x01" })],
      ["paymaster", "PhilStep6BUserOperationMismatch", (built) => ({
        ...built.userOp,
        paymasterAndData: "0x01"
      })],
      ["selector", "PhilStep6BMalformedCallData", (built) => ({
        ...built.userOp,
        callData: `0xdeadbeef${built.userOp.callData.slice(10)}`
      })],
      ["noncanonical trailing calldata", "PhilStep6BMalformedCallData", (built) => ({
        ...built.userOp,
        callData: `${built.userOp.callData}00`
      })],
      ["target calldata", "PhilStep6BBindingMismatch", (built, account) => ({
        ...built.userOp,
        callData: account.interface.encodeFunctionData("executeAuthorized", [
          contractAction(built.action), contractEnvelope(built.envelope), built.approval, "0x1234"
        ])
      })],
      ["action target", "PhilStep6BBindingMismatch", (built, account) => ({
        ...built.userOp,
        callData: account.interface.encodeFunctionData("executeAuthorized", [
          { ...contractAction(built.action), target: ethers.ZeroAddress },
          contractEnvelope(built.envelope), built.approval, built.targetCalldata
        ])
      })],
      ["policy", "PhilStep6BPolicyMismatch", (built, account) => ({
        ...built.userOp,
        callData: account.interface.encodeFunctionData("executeAuthorized", [
          contractAction(built.action),
          { ...contractEnvelope(built.envelope), policyHash: ethers.id("substituted-policy") },
          built.approval,
          built.targetCalldata
        ])
      })],
      ["scope", "PhilStep6BBindingMismatch", (built, account) => ({
        ...built.userOp,
        callData: account.interface.encodeFunctionData("executeAuthorized", [
          contractAction(built.action),
          { ...contractEnvelope(built.envelope), scopeId: ethers.ZeroHash },
          built.approval,
          built.targetCalldata
        ])
      })],
      ["capability", "PhilStep6BBindingMismatch", (built, account) => ({
        ...built.userOp,
        callData: account.interface.encodeFunctionData("executeAuthorized", [
          contractAction(built.action),
          { ...contractEnvelope(built.envelope), capabilityId: ethers.id("substituted-capability") },
          built.approval,
          built.targetCalldata
        ])
      })],
      ["device", "PhilStep6BPolicyMismatch", (built, account) => ({
        ...built.userOp,
        callData: account.interface.encodeFunctionData("executeAuthorized", [
          contractAction(built.action), contractEnvelope(built.envelope),
          { ...built.approval, deviceId: ethers.id("substituted-device") },
          built.targetCalldata
        ])
      })],
      ["approval nonce", "PhilStep6BValidityMismatch", (built, account) => ({
        ...built.userOp,
        callData: account.interface.encodeFunctionData("executeAuthorized", [
          contractAction(built.action), contractEnvelope(built.envelope),
          { ...built.approval, approvalNonce: ethers.ZeroHash },
          built.targetCalldata
        ])
      })]
    ];
    for (const [label, errorName, mutate] of cases) {
      const { account, entryPoint, target } = await fixture();
      const built = await buildUserOperation({ account, target });
      await expectCustomError(
        entryPoint.validateAndExecute(mutate(built, account), { gasLimit: 12_000_000 }),
        errorName,
        label
      );
      assert.equal(await target.calls(), 0n, `${label} substitution executed`);
      assert.equal(await account.nextNonceSequence(7), 0n, `${label} substitution consumed nonce`);
    }
  });

  it("rejects malformed-length, zero, high-S, and wrong-key P-256 signatures at the exact signature gate", async function () {
    const { account, entryPoint, target } = await fixture();
    const built = await buildUserOperation({ account, target });
    const [signatureR, signatureS] = ethers.AbiCoder.defaultAbiCoder().decode(
      ["bytes32", "bytes32"],
      built.userOp.signature
    );
    const wrongPrivateKey = Uint8Array.from({ length: 32 }, (_, index) => index === 31 ? 2 : 0);
    const wrongKeySignature = p256.sign(
      ethers.getBytes(built.authorization.deviceApprovalDigest),
      wrongPrivateKey,
      { lowS: true }
    );
    const signatures = [
      ["malformed length", "0x12"],
      ["zero signature", `0x${"00".repeat(64)}`],
      ["high-S signature", ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32"],
        [signatureR, ethers.toBeHex(P256_N - BigInt(signatureS), 32)]
      )],
      ["wrong-key signature", encodeP256Signature(wrongKeySignature)]
    ];
    for (const [label, signature] of signatures) {
      await expectCustomError(
        entryPoint.validateAndExecute({ ...built.userOp, signature }, { gasLimit: 12_000_000 }),
        "PhilStep6BHarnessSignatureFailed",
        label
      );
      assert.equal(await target.calls(), 0n, `${label} executed`);
      assert.equal(await account.nextNonceSequence(7), 0n, `${label} consumed nonce`);
    }
  });

  it("rejects every raw packed gas field, wrong sender/hash, direct validation, and missing prefund", async function () {
    const { account, entryPoint, target } = await fixture();
    const built = await buildUserOperation({ account, target });
    const mutations = [
      ["sender", { ...built.userOp, sender: ethers.ZeroAddress }],
      ["verification gas", {
        ...built.userOp,
        accountGasLimits: pack128(BigInt(built.action.verificationGasLimit) + 1n, built.action.callGasLimit)
      }],
      ["call gas", {
        ...built.userOp,
        accountGasLimits: pack128(built.action.verificationGasLimit, BigInt(built.action.callGasLimit) + 1n)
      }],
      ["priority fee", {
        ...built.userOp,
        gasFees: pack128(BigInt(built.action.maxPriorityFeePerGas) + 1n, built.action.maxFeePerGas)
      }],
      ["maximum fee", {
        ...built.userOp,
        gasFees: pack128(built.action.maxPriorityFeePerGas, BigInt(built.action.maxFeePerGas) + 1n)
      }]
    ];
    for (const [label, userOp] of mutations) {
      const userOpHash = await entryPoint.getUserOpHash(userOp);
      await expectCustomError(
        entryPoint.validateOnlyFor.staticCall(await account.getAddress(), userOp, userOpHash, 0),
        "PhilStep6BUserOperationMismatch",
        label
      );
    }

    const canonicalHash = await entryPoint.getUserOpHash(built.userOp);
    await expectCustomError(
      account.validateUserOp(built.userOp, canonicalHash, 0),
      "PhilStep6BOnlyEntryPoint",
      "direct validateUserOp caller"
    );
    await expectCustomError(
      entryPoint.validateOnlyFor.staticCall(
        await account.getAddress(), built.userOp, ethers.id("wrong-userop-hash"), 0
      ),
      "PhilStep6BUserOperationHashMismatch",
      "wrong supplied userOpHash"
    );
    await expectCustomError(
      entryPoint.validateOnlyFor.staticCall(await account.getAddress(), built.userOp, canonicalHash, 1),
      "PhilStep6BUserOperationMismatch",
      "nonzero missing account funds"
    );

    const validationData = await entryPoint.validateOnlyFor.staticCall(
      await account.getAddress(), built.userOp, canonicalHash, 0
    );
    assert.equal(BigInt.asUintN(160, validationData), 0n);
    assert.equal((validationData >> 160n) & ((1n << 48n) - 1n), BigInt(built.approval.approvalExpiresAt));
    assert.equal((validationData >> 208n) & ((1n << 48n) - 1n), BigInt(built.approval.approvedAt));
  });

  it("executes every immutable envelope, device, root-proof, and approval rejection class", async function () {
    const { account, entryPoint, target } = await fixture();
    const built = await buildUserOperation({ account, target });
    const baseEnvelope = contractEnvelope(built.envelope);
    const bindingCases = [
      ["operation class", { operationClass: 2 }],
      ["root nullifier", { rootProofNullifier: ethers.id("forbidden-root-nullifier") }],
      ["proof descriptor", { proofDescriptorHash: ethers.id("forbidden-proof-descriptor") }],
      ["zero capability", { capabilityId: ethers.ZeroHash }],
      ["scoped owner", { scopedOwnerCommitment: ethers.id("other-scoped-owner") }],
      ["scope instance", { scopeInstance: ethers.id("other-scope-instance") }],
      ["zero scope epoch", { scopeEpoch: 0 }],
      ["scope epoch", { scopeEpoch: 2 }],
      ["zero principal", { principalIdHash: ethers.ZeroHash }],
      ["zero capability epoch", { capabilityEpoch: 0 }],
      ["capability epoch", { capabilityEpoch: 2 }],
      ["network", { networkIdHash: ethers.id("other-network") }],
      ["account binding", { accountBindingHash: ethers.id("other-account-binding") }],
      ["adapter", { adapterId: ethers.id("other-adapter") }],
      ["action type", { actionTypeHash: ethers.id("other-action-type") }],
      ["parameters", { parametersHash: ethers.id("other-parameters") }],
      ["intent", { intentDigest: ethers.id("other-intent") }],
      ["nonce domain", { nonceDomain: ethers.id("other-nonce-domain") }],
      ["envelope nonce", { nonce: BigInt(baseEnvelope.nonce) + 1n }],
      ["valid after", { validAfter: BigInt(baseEnvelope.validAfter) + 1n }],
      ["valid until", { validUntil: BigInt(baseEnvelope.validUntil) - 1n }],
      ["fee limit", { feeLimit: 1 }],
      ["zero recovery epoch", { recoveryEpoch: 0 }],
      ["zero validator epoch", { validatorEpoch: 0 }],
      ["zero presentation", { humanPresentationHash: ethers.ZeroHash }]
    ];
    for (const [label, mutation] of bindingCases) {
      const userOp = {
        ...built.userOp,
        callData: encodeExecutionCall(account, built, { envelope: { ...baseEnvelope, ...mutation } })
      };
      await expectCustomError(
        entryPoint.validateAndExecute(userOp, { gasLimit: 12_000_000 }),
        "PhilStep6BBindingMismatch",
        label
      );
    }

    const policyCases = [
      ["policy hash", { envelope: { ...baseEnvelope, policyHash: ethers.id("other-policy") } }],
      ["envelope device epoch", { envelope: { ...baseEnvelope, deviceEpoch: 2 } }],
      ["signature suite", {
        envelope: { ...baseEnvelope, deviceSignatureSuiteId: ethers.id("other-signature-suite") }
      }],
      ["device id", { approval: { ...built.approval, deviceId: ethers.id("other-device") } }],
      ["device key id", { approval: { ...built.approval, deviceKeyId: ethers.id("other-device-key") } }],
      ["approval device epoch", { approval: { ...built.approval, deviceEpoch: 2 } }]
    ];
    for (const [label, overrides] of policyCases) {
      const userOp = { ...built.userOp, callData: encodeExecutionCall(account, built, overrides) };
      await expectCustomError(
        entryPoint.validateAndExecute(userOp, { gasLimit: 12_000_000 }),
        "PhilStep6BPolicyMismatch",
        label
      );
    }

    const validityCases = [
      ["zero approvedAt", { ...built.approval, approvedAt: 0 }],
      ["expiry before approval", {
        ...built.approval,
        approvedAt: VALID_AFTER + 2,
        approvalExpiresAt: VALID_AFTER + 1
      }],
      ["approval before action", { ...built.approval, approvedAt: VALID_AFTER - 1 }],
      ["approval after action", { ...built.approval, approvalExpiresAt: VALID_UNTIL + 1 }]
    ];
    for (const [label, approval] of validityCases) {
      const userOp = {
        ...built.userOp,
        callData: encodeExecutionCall(account, built, { approval })
      };
      await expectCustomError(
        entryPoint.validateAndExecute(userOp, { gasLimit: 12_000_000 }),
        "PhilStep6BValidityMismatch",
        label
      );
    }

    const actionCases = [
      ["self target", { target: await account.getAddress() }],
      ["target calldata hash", { targetCalldataHash: ethers.id("other-target-calldata") }],
      ["zero call gas", { callGasLimit: 0 }],
      ["zero verification gas", { verificationGasLimit: 0 }],
      ["zero pre-verification gas", { preVerificationGas: 0 }],
      ["zero maximum fee", { maxFeePerGas: 0 }],
      ["priority fee relation", { maxPriorityFeePerGas: 2_000_000_000 }],
      ["zero valid until", { validUntil: 0 }],
      ["reversed validity", { validAfter: VALID_UNTIL, validUntil: VALID_AFTER }]
    ];
    for (const [label, mutation] of actionCases) {
      const userOp = {
        ...built.userOp,
        callData: encodeExecutionCall(account, built, {
          action: { ...contractAction(built.action), ...mutation }
        })
      };
      await expectCustomError(
        entryPoint.validateAndExecute(userOp, { gasLimit: 12_000_000 }),
        "PhilStep6BBindingMismatch",
        label
      );
    }

    const valueBound = await buildUserOperation({ account, target, valueWei: 1n });
    const valueEnvelope = { ...contractEnvelope(valueBound.envelope), valueLimit: 0 };
    await expectCustomError(
      entryPoint.validateAndExecute({
        ...valueBound.userOp,
        callData: encodeExecutionCall(account, valueBound, { envelope: valueEnvelope })
      }, { gasLimit: 12_000_000 }),
      "PhilStep6BBindingMismatch",
      "envelope value limit"
    );
    assert.equal(await target.calls(), 0n);
    assert.equal(await account.nextNonceSequence(7), 0n);
  });

  it("rejects constructor trust-anchor and invalid P-256 public-key configurations", async function () {
    await ethers.provider.send("hardhat_reset", []);
    const Target = await ethers.getContractFactory("PhilSmartAccountExecutionTarget");
    const target = await Target.deploy();
    const Account = await ethers.getContractFactory("PhilV1Step6BLocalAccount");
    const cases = [
      ["manifest", { trustedManifestHash: ethers.ZeroHash }],
      ["device id", { enrolledDeviceId: ethers.ZeroHash }],
      ["device key", { enrolledDeviceKeyId: ethers.ZeroHash }],
      ["device epoch", { enrolledDeviceEpoch: 0 }],
      ["scoped owner", { enrolledScopedOwnerCommitment: ethers.ZeroHash }],
      ["policy", { enforcedPolicyHash: ethers.ZeroHash }],
      ["capability binding", { trustedCapabilityBindingHash: ethers.ZeroHash }],
      ["target", { approvedTarget: ethers.ZeroAddress }],
      ["EntryPoint target", { approvedTarget: PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS }],
      ["fee ceiling", { policyMaxFeeWei: 0 }],
      ["P-256 point", {
        devicePublicKeyX: ethers.toBeHex(1, 32),
        devicePublicKeyY: ethers.toBeHex(1, 32)
      }]
    ];
    for (const [label, overrides] of cases) {
      await expectCustomError(
        Account.deploy(...await accountConstructorArgs(target, overrides)),
        "PhilStep6BInvalidConstructor",
        label
      );
    }
  });

  it("rejects Step 6B fee arithmetic overflow before any binding or signature can execute", async function () {
    const { account, entryPoint, target } = await fixture();
    const built = await buildUserOperation({ account, target });
    const overflowingAction = {
      ...contractAction(built.action),
      preVerificationGas: ethers.MaxUint256,
      maxFeePerGas: 2,
      maxPriorityFeePerGas: 1
    };
    const userOp = {
      ...built.userOp,
      callData: encodeExecutionCall(account, built, { action: overflowingAction }),
      preVerificationGas: ethers.MaxUint256,
      gasFees: pack128(1, 2)
    };
    await expectCustomError(
      entryPoint.validateAndExecute(userOp, { gasLimit: 12_000_000 }),
      "PhilStep6BFeeOverflow"
    );
    assert.equal(await target.calls(), 0n);
    assert.equal(await account.nextNonceSequence(7), 0n);
  });

  it("uses the narrower device-approval window for validation and execution", async function () {
    const { account, entryPoint, target } = await fixture();
    const built = await buildUserOperation({ account, target });
    await ethers.provider.send("evm_setNextBlockTimestamp", [built.approval.approvalExpiresAt + 1]);
    await assert.rejects(
      entryPoint.validateAndExecute(built.userOp, { gasLimit: 12_000_000 }),
      /PhilStep6BHarnessOutsideValidity/
    );
    assert.equal(await target.calls(), 0n);
    assert.equal(await account.nextNonceSequence(7), 0n);
  });

  it("independently executes the account's before-action and approval-expiry guards", async function () {
    {
      const { account, entryPoint, target } = await fixture({
        timestamp: VALID_AFTER - 1,
        mineTimestamp: false
      });
      const built = await buildUserOperation({ account, target });
      await expectCustomError(
        entryPoint.executeOnly(await account.getAddress(), built.userOp.callData, { gasLimit: 2_000_000 }),
        "PhilStep6BExecutionOutsideValidity",
        "before-action execution"
      );
      const executionBlock = await ethers.provider.getBlock("latest");
      assert.equal(executionBlock.timestamp, VALID_AFTER - 1);
      assert.equal(await target.calls(), 0n);
      assert.equal(await account.nextNonceSequence(7), 0n);
    }

    {
      const { account, entryPoint, target } = await fixture();
      const built = await buildUserOperation({ account, target });
      const canonicalHash = await entryPoint.getUserOpHash(built.userOp);
      const validationData = await entryPoint.validateOnlyFor.staticCall(
        await account.getAddress(), built.userOp, canonicalHash, 0
      );
      assert.equal(BigInt.asUintN(160, validationData), 0n);
      await ethers.provider.send("evm_setNextBlockTimestamp", [built.approval.approvalExpiresAt + 1]);
      await expectCustomError(
        entryPoint.executeOnly(await account.getAddress(), built.userOp.callData, { gasLimit: 2_000_000 }),
        "PhilStep6BExecutionOutsideValidity",
        "expired-approval execution"
      );
      assert.equal(await target.calls(), 0n);
      assert.equal(await account.nextNonceSequence(7), 0n);
      assert.equal(await account.consumedAuthorization(built.authorization.authorizationHash), false);
    }
  });

  it("covers nonce gaps, independent keys, consumed authorization, and terminal uint64 overflow", async function () {
    {
      const { account, entryPoint, target } = await fixture();
      const gap = await buildUserOperation({ account, target, nonceSequence: 1n });
      await expectCustomError(
        entryPoint.validateAndExecute(gap.userOp, { gasLimit: 12_000_000 }),
        "PhilStep6BNonceMismatch",
        "nonce gap"
      );
      await expectCustomError(
        entryPoint.executeOnly(await account.getAddress(), gap.userOp.callData, { gasLimit: 2_000_000 }),
        "PhilStep6BNonceMismatch",
        "execution-time nonce gap"
      );
      assert.equal(await account.nextNonceSequence(7), 0n);
    }

    {
      const { account, entryPoint, target } = await fixture();
      const independentKey = await buildUserOperation({ account, target, nonceKey: 8n });
      await entryPoint.validateAndExecute(independentKey.userOp, { gasLimit: 12_000_000 });
      assert.equal(await account.nextNonceSequence(7), 0n);
      assert.equal(await account.nextNonceSequence(8), 1n);

      const consumedHash = await entryPoint.getUserOpHash(independentKey.userOp);
      await expectCustomError(
        entryPoint.validateOnlyFor.staticCall(
          await account.getAddress(), independentKey.userOp, consumedHash, 0
        ),
        "PhilStep6BAuthorizationAlreadyConsumed",
        "consumed authorization"
      );
      await expectCustomError(
        entryPoint.executeOnly(
          await account.getAddress(), independentKey.userOp.callData, { gasLimit: 2_000_000 }
        ),
        "PhilStep6BAuthorizationAlreadyConsumed",
        "execution-time consumed authorization"
      );
    }

    {
      const { account, entryPoint, target } = await fixture();
      const accountAddress = await account.getAddress();
      const sequenceSlot = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["uint192", "uint256"], [7, 0])
      );
      await ethers.provider.send("hardhat_setStorageAt", [
        accountAddress,
        sequenceSlot,
        ethers.toBeHex(UINT64_MAX, 32)
      ]);
      assert.equal(await account.nextNonceSequence(7), UINT64_MAX);
      const terminal = await buildUserOperation({ account, target, nonceSequence: UINT64_MAX });
      const terminalHash = await entryPoint.getUserOpHash(terminal.userOp);
      const validationData = await entryPoint.validateOnlyFor.staticCall(
        accountAddress, terminal.userOp, terminalHash, 0
      );
      assert.equal(BigInt.asUintN(160, validationData), 0n);
      await assert.rejects(
        entryPoint.executeOnly(accountAddress, terminal.userOp.callData, { gasLimit: 2_000_000 }),
        /overflow|panic code 0x11/i
      );
      assert.equal(await target.calls(), 0n);
      assert.equal(await account.nextNonceSequence(7), UINT64_MAX);
      assert.equal(await account.consumedAuthorization(terminal.authorization.authorizationHash), false);
    }
  });

  it("enforces immutable target, capability, value, and maximum-fee policy ceilings", async function () {
    for (const overrides of [
      { valueWei: POLICY_MAX_VALUE_WEI + 1n },
      { maxFeePerGas: 2_000_000_000n }
    ]) {
      const { account, entryPoint, target } = await fixture();
      const built = await buildUserOperation({ account, target, ...overrides });
      await assert.rejects(
        entryPoint.validateAndExecute(built.userOp, { gasLimit: 12_000_000 }),
        /PhilStep6BBindingMismatch/
      );
      assert.equal(await target.calls(), 0n);
      assert.equal(await account.nextNonceSequence(7), 0n);
    }
  });

  it("rolls nonce and authorization consumption back when the approved target reverts", async function () {
    const { account, entryPoint, target } = await fixture();
    const built = await buildUserOperation({ account, target, targetFunction: "fail" });
    await assert.rejects(
      entryPoint.validateAndExecute(built.userOp, { gasLimit: 12_000_000 }),
      /PhilStep6BHarnessExecutionFailed/
    );
    assert.equal(await account.nextNonceSequence(7), 0n);
    assert.equal(await account.consumedAuthorization(built.authorization.authorizationHash), false);
  });

  it("contains no RPC, deployment, device, transaction submission, legacy runtime, or STWO reachability", function () {
    const source = fs.readFileSync(
      path.join(REPO_ROOT, "contracts/base/erc4337/PhilV1Step6BLocalAccount.sol"),
      "utf8"
    );
    assert.doesNotMatch(source, /from\s+["']\.\/runtime\//);
    assert.doesNotMatch(
      source,
      /fetch\s*\(|XMLHttpRequest|WebSocket|JsonRpcProvider|sendTransaction|sendUserOperation|eth_sendUserOperation|stwo|STWO|delegatecall|selfdestruct/
    );
    assert.match(source, /Local-only Step 6B reference account/);
    assert.match(source, /not deployed, audited, upgradeable, recovery-capable, or production-authorized/);
  });
});
