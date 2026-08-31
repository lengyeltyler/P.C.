const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const OWNER_COMMITMENT = ethers.id("local-proof-owner-commitment");
const VALIDATOR_KEY_ID = ethers.id("device-vault-validator-key-v1");
const MODEL_ID = ethers.id("local-proof-gated-v1");
const SIGNATURE_DOMAIN = ethers.id("PHILCORE_LOCAL_PROOF_GATED_ACCOUNT_SIGNATURE_V1");
const SIGNATURE_VERSION = 1;

function packUints(high128, low128) {
  return ethers.toBeHex((BigInt(high128) << 128n) + BigInt(low128), 32);
}

function unsignedUserOp({ sender, nonce, callData, initCode = "0x", overrides = {} }) {
  return {
    sender,
    nonce,
    initCode,
    callData,
    accountGasLimits: packUints(1_500_000n, 500_000n),
    preVerificationGas: 120_000n,
    gasFees: packUints(1_000_000_000n, 30_000_000_000n),
    paymasterAndData: "0x",
    signature: "0x",
    ...overrides
  };
}

async function fixture() {
  const [deployer, owner, other, beneficiary] = await ethers.getSigners();
  const entryPoint = await new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
  const Target = await ethers.getContractFactory("PhilCoreLocalProofConfirmationTargetV1");
  const target = await Target.deploy();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const Factory = await ethers.getContractFactory("PhilCore4337LocalProofAccountFactoryV1");
  const factory = await Factory.deploy(await entryPoint.getAddress(), await target.getAddress(), chainId);
  return { deployer, owner, other, beneficiary, entryPoint, target, chainId, factory };
}

async function createAccount(env, salt = 1n) {
  const predicted = await env.factory.getFunction("getAddress").staticCall(
    env.owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    salt
  );
  await env.factory.createAccount(
    env.owner.address,
    OWNER_COMMITMENT,
    VALIDATOR_KEY_ID,
    salt
  );
  const account = await ethers.getContractAt("PhilCore4337LocalProofAccountV1", predicted);
  return { account, predicted };
}

async function signedOperation({
  env,
  account,
  sender,
  nonce,
  actionId = ethers.id("first-local-proof-action"),
  authorizationDigest = ethers.id("runtime-authorization"),
  expiry,
  initCode = "0x",
  signer,
  envelopeOverrides = {},
  operationOverrides = {}
}) {
  const expires = expiry ?? BigInt(Math.floor(Date.now() / 1000) + 3600);
  const callData = account.interface.encodeFunctionData("executeLocalProofAuthorization", [
    actionId,
    authorizationDigest,
    expires
  ]);
  const unsigned = unsignedUserOp({
    sender,
    nonce,
    callData,
    initCode,
    overrides: operationOverrides
  });
  const userOpHash = await env.entryPoint.getUserOpHash(unsigned);
  const signingDigest = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "bytes32", "uint8", "bytes32", "uint256", "address", "address",
        "bytes32", "bytes32", "bytes32", "uint64", "bytes32"
      ],
      [
        SIGNATURE_DOMAIN,
        SIGNATURE_VERSION,
        MODEL_ID,
        env.chainId,
        await env.entryPoint.getAddress(),
        sender,
        userOpHash,
        actionId,
        authorizationDigest,
        expires,
        VALIDATOR_KEY_ID
      ]
    )
  );
  const rawSignature = ethers.Signature.from(
    await (signer ?? env.owner).signMessage(ethers.getBytes(signingDigest))
  );
  const signature = ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint8", "bytes32", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "bytes32", "uint8"],
    [
      envelopeOverrides.version ?? SIGNATURE_VERSION,
      envelopeOverrides.modelId ?? MODEL_ID,
      envelopeOverrides.actionId ?? actionId,
      envelopeOverrides.authorizationDigest ?? authorizationDigest,
      envelopeOverrides.expiry ?? expires,
      envelopeOverrides.validatorKeyId ?? VALIDATOR_KEY_ID,
      rawSignature.r,
      rawSignature.s,
      rawSignature.v
    ]
  );
  return { ...unsigned, signature };
}

async function handle(env, userOp) {
  return env.entryPoint.handleOps([userOp], env.beneficiary.address, { gasLimit: 7_000_000 });
}

describe("PhilCore local-proof-gated-v1 account", function () {
  it("is a separate, deterministic, chain-bound account with explicit security labels", async function () {
    const env = await fixture();
    const predicted = await env.factory.getFunction("getAddress").staticCall(
      env.owner.address,
      OWNER_COMMITMENT,
      VALIDATOR_KEY_ID,
      11n
    );
    const changedKey = await env.factory.getFunction("getAddress").staticCall(
      env.owner.address,
      OWNER_COMMITMENT,
      ethers.id("other-key"),
      11n
    );
    assert.notEqual(predicted, changedKey);

    const { account } = await createAccount(env, 11n);
    assert.equal(await account.owner(), env.owner.address);
    assert.equal(await account.ownerCommitment(), OWNER_COMMITMENT);
    assert.equal(await account.validatorKeyId(), VALIDATOR_KEY_ID);
    assert.equal(await account.securityModelId(), MODEL_ID);
    assert.equal(await account.expectedChainId(), BigInt(env.chainId));
    assert.equal(await account.approvedConfirmationTarget(), await env.target.getAddress());
    assert.equal(await env.factory.createAccount.staticCall(
      env.owner.address,
      OWNER_COMMITMENT,
      VALIDATOR_KEY_ID,
      11n
    ), predicted);
  });

  it("executes exactly one zero-value confirmation through EntryPoint and rejects replay", async function () {
    const env = await fixture();
    const { account, predicted } = await createAccount(env);
    await env.owner.sendTransaction({ to: predicted, value: ethers.parseEther("1") });
    const nonce = await env.entryPoint.getNonce(predicted, 0);
    const userOp = await signedOperation({ env, account, sender: predicted, nonce });
    const receipt = await (await handle(env, userOp)).wait();

    assert.equal(receipt.status, 1);
    assert.equal(await env.target.confirmationCount(), 1n);
    assert.equal(await env.target.lastAccount(), predicted);
    assert.equal(await env.target.lastActionId(), ethers.id("first-local-proof-action"));
    assert.equal(await env.target.lastAuthorizationDigest(), ethers.id("runtime-authorization"));
    await assert.rejects(handle(env, userOp), /reverted/);
  });

  it("supports counterfactual deployment with the first bounded call", async function () {
    const env = await fixture();
    const salt = 77n;
    const predicted = await env.factory.getFunction("getAddress").staticCall(
      env.owner.address,
      OWNER_COMMITMENT,
      VALIDATOR_KEY_ID,
      salt
    );
    const account = await ethers.getContractAt("PhilCore4337LocalProofAccountV1", predicted);
    const factoryCall = env.factory.interface.encodeFunctionData("createAccount", [
      env.owner.address,
      OWNER_COMMITMENT,
      VALIDATOR_KEY_ID,
      salt
    ]);
    const initCode = ethers.concat([await env.factory.getAddress(), factoryCall]);
    await env.entryPoint.depositTo(predicted, { value: ethers.parseEther("1") });

    const userOp = await signedOperation({
      env,
      account,
      sender: predicted,
      nonce: 0n,
      initCode
    });
    const receipt = await (await handle(env, userOp)).wait();
    assert.equal(receipt.status, 1);
    assert.notEqual(await ethers.provider.getCode(predicted), "0x");
    assert.equal(await env.target.lastAccount(), predicted);
  });

  it("rejects direct execution and direct target calls", async function () {
    const env = await fixture();
    const { account } = await createAccount(env);
    await assert.rejects(
      account.connect(env.owner).executeLocalProofAuthorization(
        ethers.id("direct"),
        ethers.id("authorization"),
        Math.floor(Date.now() / 1000) + 60
      ),
      /UnauthorizedExecuteCaller/
    );
    await assert.rejects(
      env.target.connect(env.owner).confirmPhilCoreAction(
        ethers.id("direct"),
        ethers.id("authorization")
      ),
      /CallerIsNotContract/
    );
  });

  it("rejects malformed signatures and every structured signature substitution", async function () {
    const env = await fixture();
    const { account, predicted } = await createAccount(env);
    await env.owner.sendTransaction({ to: predicted, value: ethers.parseEther("2") });
    const cases = [
      { name: "wrong signer", signer: env.other },
      { name: "version", envelopeOverrides: { version: 2 } },
      { name: "model", envelopeOverrides: { modelId: ethers.id("ethereum-fact-enforced-v1") } },
      { name: "action", envelopeOverrides: { actionId: ethers.id("other-action") } },
      { name: "authorization", envelopeOverrides: { authorizationDigest: ethers.id("other-auth") } },
      { name: "expiry", envelopeOverrides: { expiry: BigInt(Math.floor(Date.now() / 1000) + 7200) } },
      { name: "key", envelopeOverrides: { validatorKeyId: ethers.id("other-key") } }
    ];
    for (const testCase of cases) {
      const nonce = await env.entryPoint.getNonce(predicted, 0);
      const userOp = await signedOperation({
        env,
        account,
        sender: predicted,
        nonce,
        signer: testCase.signer,
        envelopeOverrides: testCase.envelopeOverrides
      });
      await assert.rejects(handle(env, userOp), /reverted/, testCase.name);
    }
    const nonce = await env.entryPoint.getNonce(predicted, 0);
    const valid = await signedOperation({ env, account, sender: predicted, nonce });
    await assert.rejects(handle(env, { ...valid, signature: "0x1234" }), /reverted/);
  });

  it("rejects paymasters, changed calldata, wrong selectors, nonzero-value APIs, and expired actions", async function () {
    const env = await fixture();
    const { account, predicted } = await createAccount(env);
    await env.owner.sendTransaction({ to: predicted, value: ethers.parseEther("2") });
    const nonce = await env.entryPoint.getNonce(predicted, 0);
    const paymaster = await signedOperation({
      env,
      account,
      sender: predicted,
      nonce,
      operationOverrides: { paymasterAndData: "0x1234" }
    });
    await assert.rejects(handle(env, paymaster), /reverted/);

    const valid = await signedOperation({ env, account, sender: predicted, nonce });
    const changedCall = account.interface.encodeFunctionData("executeLocalProofAuthorization", [
      ethers.id("changed"),
      ethers.id("runtime-authorization"),
      BigInt(Math.floor(Date.now() / 1000) + 3600)
    ]);
    await assert.rejects(handle(env, { ...valid, callData: changedCall }), /reverted/);
    await assert.rejects(handle(env, { ...valid, callData: "0x12345678" }), /reverted/);

    const expired = await signedOperation({
      env,
      account,
      sender: predicted,
      nonce,
      expiry: BigInt(Math.floor(Date.now() / 1000) - 1)
    });
    await assert.rejects(handle(env, expired), /reverted/);

    assert.equal(account.interface.hasFunction("execute(address,uint256,bytes)"), false);
    assert.equal(account.interface.hasFunction("executeBatch"), false);
    assert.equal(account.interface.hasFunction("upgradeTo"), false);
  });

  it("rejects wrong-chain factory construction", async function () {
    const env = await fixture();
    const Factory = await ethers.getContractFactory("PhilCore4337LocalProofAccountFactoryV1");
    await assert.rejects(
      Factory.deploy(await env.entryPoint.getAddress(), await env.target.getAddress(), env.chainId + 1),
      /WrongDeploymentChain/
    );
  });
});
