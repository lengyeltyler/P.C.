require("tsx/cjs");

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  AbiCoder,
  concat,
  getCreate2Address,
  getCreateAddress,
  keccak256,
  toBeHex,
  zeroPadValue
} = require("ethers");

const {
  artifactBindings,
  compilerBinding,
  ensureNoCollision,
  sourceBinding,
  validateO22Proposal
} = require("../../scripts/ethereum-sepolia/generate-o22-readiness.cjs");

const ROOT = path.resolve(__dirname, "../..");
const PROPOSAL_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O22_CURRENT_SOURCE_DEPLOYMENT_PROPOSAL.json"
);
const FUNDING_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O22_FIRST_SEPOLIA_FUNDING_READINESS.json"
);
const abiCoder = AbiCoder.defaultAbiCoder();

function readJson(location) {
  return JSON.parse(fs.readFileSync(location, "utf8"));
}

function git(args) {
  const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function sha256File(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

describe("O.22 current-source deployment and funding readiness", function () {
  it("binds the proposal to the generation HEAD and the still-current source tree", function () {
    const proposal = readJson(PROPOSAL_PATH);
    const generationHead = proposal.sourceBinding.sourceCommitAtGeneration;
    assert.equal(git(["cat-file", "-t", generationHead]), "commit");
    assert.equal(
      git(["merge-base", "--is-ancestor", generationHead, "HEAD"]),
      ""
    );
    for (const source of proposal.sourceBinding.sources) {
      assert.equal(source.sha256, sha256File(source.path), source.path);
    }
    const current = sourceBinding(generationHead);
    assert.equal(
      current.deploymentSourceTreeSha256,
      proposal.sourceBinding.deploymentSourceTreeSha256
    );
  });

  it("rejects stale source and compiler bindings", function () {
    const proposal = readJson(PROPOSAL_PATH);
    const expected = {
      sourceCommitAtGeneration: proposal.sourceBinding.sourceCommitAtGeneration,
      deploymentSourceTreeSha256:
        proposal.sourceBinding.deploymentSourceTreeSha256,
      compiler: proposal.compiler
    };
    assert.equal(validateO22Proposal(proposal, expected).valid, true);
    assert.deepEqual(
      validateO22Proposal(proposal, {
        ...expected,
        sourceCommitAtGeneration: "0".repeat(40)
      }).errors,
      ["source_commit_stale"]
    );
    assert.deepEqual(
      validateO22Proposal(proposal, {
        ...expected,
        compiler: { ...expected.compiler, optimizerRuns: 1 }
      }).errors,
      ["compiler_configuration_mismatch"]
    );
  });

  it("binds compiler settings and artifact hashes to current compiled outputs", function () {
    const proposal = readJson(PROPOSAL_PATH);
    const compiler = compilerBinding();
    assert.equal(compiler.version, "0.8.24");
    assert.equal(compiler.optimizerEnabled, true);
    assert.equal(compiler.optimizerRuns, 200);
    assert.equal(compiler.viaIR, true);
    assert.deepEqual(artifactBindings(), proposal.artifacts);
  });

  it("uses live nonce sequencing and independently reproduces CREATE addresses", function () {
    const proposal = readJson(PROPOSAL_PATH);
    const sequence = proposal.addressSequence;
    const deployer = proposal.deployerObservation.address;
    const target = getCreateAddress({
      from: deployer,
      nonce: BigInt(proposal.deployerObservation.pendingNonce)
    });
    const factory = getCreateAddress({
      from: deployer,
      nonce: BigInt(proposal.deployerObservation.pendingNonce) + 1n
    });
    assert.equal(sequence.targetAddress, target);
    assert.equal(sequence.factoryAddress, factory);
    assert.equal(sequence.targetDeploymentNonce, proposal.deployerObservation.pendingNonce);
    assert.equal(
      sequence.factoryDeploymentNonce,
      (BigInt(sequence.targetDeploymentNonce) + 1n).toString()
    );

    const accountArtifact = readJson(path.join(
      ROOT,
      "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol/PhilCore4337LocalProofAccountV1.json"
    ));
    const constructorData = abiCoder.encode(
      ["address", "address", "bytes32", "address", "bytes32", "uint256"],
      proposal.initialization.accountConstructorArguments
    );
    const initCodeHash = keccak256(concat([accountArtifact.bytecode, constructorData]));
    const account = getCreate2Address(
      factory,
      zeroPadValue(toBeHex(BigInt(sequence.accountSalt)), 32),
      initCodeHash
    );
    assert.equal(account, sequence.counterfactualAccountAddress);
    assert.equal(initCodeHash, proposal.initialization.create2.accountInitCodeHash);
  });

  it("records collision-free addresses with no code, balance, or history", function () {
    const proposal = readJson(PROPOSAL_PATH);
    assert.equal(proposal.addressSequence.unexpectedCollision, false);
    for (const observation of Object.values(
      proposal.addressSequence.currentCollisionChecks
    )) {
      assert.equal(observation.codeStatus, "empty");
      assert.equal(observation.balanceWei, "0");
    }
    for (const observation of Object.values(
      proposal.addressSequence.currentAddressHistory
    )) {
      assert.equal(observation.latestTransactionCount, "0");
    }
  });

  it("rejects code or balance collisions without selecting a substitute address", function () {
    assert.throws(
      () => ensureNoCollision({
        proposedAddresses: {
          target: {
            address: "0x1000000000000000000000000000000000000001",
            codeStatus: "code_present",
            balanceWei: "0"
          }
        }
      }),
      /PROPOSED_ADDRESS_COLLISION:target/
    );
    assert.throws(
      () => ensureNoCollision({
        proposedAddresses: {
          account: {
            address: "0x2000000000000000000000000000000000000002",
            codeStatus: "empty",
            balanceWei: "1"
          }
        }
      }),
      /PROPOSED_ADDRESS_COLLISION:account/
    );
  });

  it("keeps the first operation fixed, unsigned, zero-value, and non-submittable", function () {
    const operation = readJson(PROPOSAL_PATH).firstOperationTemplate;
    assert.equal(operation.status, "NOT_SUBMISSION_READY");
    assert.equal(operation.valueWei, "0");
    assert.equal(operation.tokenMovement, false);
    assert.equal(operation.approvalCall, false);
    assert.equal(operation.batching, false);
    assert.equal(operation.delegatecall, false);
    assert.equal(operation.arbitraryExecution, false);
    assert.equal(operation.paymaster, false);
    assert.equal(operation.recoveryOperation, false);
    assert.equal(operation.signature, "0x");
    assert.equal(operation.reusedO21AuthorizationOrSignature, false);
  });

  it("keeps deployer and account funding separate and within unchanged ceilings", function () {
    const proposal = readJson(PROPOSAL_PATH);
    const funding = readJson(FUNDING_PATH);
    assert.notEqual(
      funding.disposableDeployer.estimatedMinimum.wei,
      funding.counterfactualSmartAccount.estimatedMinimum.wei
    );
    assert.equal(funding.counterfactualSmartAccount.entryPointDepositRequired, false);
    assert.equal(
      funding.counterfactualSmartAccount.prefundMechanism,
      "direct ETH transfer to the counterfactual address"
    );
    assert.equal(proposal.gasEstimates.ceilings.verificationGas, "1500000");
    assert.equal(proposal.gasEstimates.ceilings.callGas, "300000");
    assert.equal(proposal.gasEstimates.ceilings.preVerificationGas, "200000");
    assert.equal(proposal.gasEstimates.ceilings.maxFeePerGasWei, "100000000000");
    assert.equal(
      proposal.gasEstimates.ceilings.maxPriorityFeePerGasWei,
      "5000000000"
    );
  });

  it("redacts the RPC and records no bundler contact, approvals, secrets, or mutation", function () {
    const proposalText = fs.readFileSync(PROPOSAL_PATH, "utf8");
    const fundingText = fs.readFileSync(FUNDING_PATH, "utf8");
    const proposal = JSON.parse(proposalText);
    assert.match(proposal.network.rpcClassification, /<redacted>$/);
    assert.equal(proposal.gasEstimates.bundler.status, "BUNDLER_ESTIMATE_NOT_CONFIGURED");
    assert.equal(proposal.gasEstimates.bundler.contacted, false);
    assert.ok(Object.values(proposal.approvals).every((value) => value === false));
    assert.equal(proposal.accepted, false);
    assert.equal(proposal.mutationState.mutationMethodsExposed, false);
    assert.equal(proposal.mutationState.publicMutationOccurred, false);
    assert.equal(proposal.mutationState.transactionSubmitted, false);
    assert.equal(proposal.mutationState.userOperationSubmitted, false);
    const generator = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/generate-o22-readiness.cjs"
    ), "utf8");
    assert.doesNotMatch(generator, /eth_sendRawTransaction|eth_sendUserOperation/);
    assert.doesNotMatch(
      `${proposalText}${fundingText}`,
      /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey/i
    );
  });
});
