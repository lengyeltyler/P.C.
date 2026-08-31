require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  Wallet,
  getCreateAddress,
  keccak256
} = require("ethers");

const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  EXPECTED_VALIDATOR,
  MAX_FEE_PER_GAS,
  ROOT,
  assertRoleSeparation,
  ensureNoSecrets,
  readJson
} = require("../../scripts/ethereum-sepolia/o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET,
  FACTORY_DEPLOYMENT_NONCE,
  O24_PROPOSAL_PATH,
  O24_RECEIPT_PATH,
  assertFreshO24ReceiptPath,
  buildFactoryDeploymentData,
  buildFactoryDeploymentTransaction,
  canonicalDigest,
  expectedFactoryRuntimeBinding,
  factoryConstructorBinding,
  validateFactoryDeploymentTransaction,
  verifySignedFactoryDeployment
} = require("../../scripts/ethereum-sepolia/o24-factory-common.cjs");

describe("O.24 factory-only Sepolia deployment", function () {
  it("preserves account roles and the canonical target/factory/account sequence", function () {
    assert.deepEqual(assertRoleSeparation({
      deployer: EXPECTED_DEPLOYER,
      funding: EXPECTED_FUNDING,
      validator: EXPECTED_VALIDATOR
    }), {
      deployer: EXPECTED_DEPLOYER,
      funding: EXPECTED_FUNDING,
      validator: EXPECTED_VALIDATOR
    });
    assert.equal(
      getCreateAddress({
        from: EXPECTED_DEPLOYER,
        nonce: BigInt(FACTORY_DEPLOYMENT_NONCE)
      }),
      EXPECTED_FACTORY
    );
    const proposal = readJson(O24_PROPOSAL_PATH);
    assert.equal(proposal.confirmationTargetEvidence.address, EXPECTED_TARGET);
    assert.equal(proposal.confirmationTargetEvidence.unchanged, true);
    assert.equal(proposal.counterfactualAccount.address, EXPECTED_ACCOUNT);
  });

  it("binds the reviewed factory bytecode, constructor, and immutable runtime", function () {
    const proposal = readJson(O24_PROPOSAL_PATH);
    const deployment = buildFactoryDeploymentData();
    const constructor = factoryConstructorBinding();
    const runtime = expectedFactoryRuntimeBinding();
    assert.equal(
      proposal.factory.deployment.creationBytecodeHash,
      deployment.creationBytecodeHash
    );
    assert.equal(
      proposal.factory.deployment.constructorDataHash,
      constructor.dataHash
    );
    assert.equal(proposal.factory.deployment.dataHash, deployment.dataHash);
    assert.equal(proposal.factory.expectedRuntime.bytecodeHash, runtime.bytecodeHash);
    assert.equal(constructor.entryPoint,
      "0x0000000071727De22E5E9d8BAf0edAc6f37da032");
    assert.equal(constructor.approvedConfirmationTarget, EXPECTED_TARGET);
    assert.equal(constructor.standaloneImplementationRequired, false);
  });

  it("records an exact one-time factory approval with no downstream approval", function () {
    const proposal = readJson(O24_PROPOSAL_PATH);
    const approval = { ...proposal.factoryOnlyApproval };
    delete approval.approvalDigest;
    delete approval.approved;
    delete approval.consumed;
    assert.equal(canonicalDigest(approval), proposal.factoryOnlyApproval.approvalDigest);
    assert.equal(proposal.factoryOnlyApproval.approvedScope, "factory-deployment-only");
    assert.equal(proposal.factoryOnlyApproval.approved, true);
    assert.equal(proposal.factoryOnlyApproval.consumed, false);
    assert.equal(proposal.factoryOnlyApproval.fundingWalletUseApproved, false);
    assert.equal(proposal.factoryOnlyApproval.smartAccountDeploymentApproved, false);
    assert.equal(proposal.factoryOnlyApproval.smartAccountFundingApproved, false);
    assert.equal(proposal.factoryOnlyApproval.deviceVaultSigningApproved, false);
    assert.equal(proposal.factoryOnlyApproval.bundlerContactApproved, false);
    assert.equal(proposal.factoryOnlyApproval.userOperationSubmissionApproved, false);
  });

  it("constructs and recovers exactly one zero-value EIP-1559 factory deployment", async function () {
    const deployment = buildFactoryDeploymentData();
    const request = buildFactoryDeploymentTransaction({
      data: deployment.data,
      dataHash: deployment.dataHash,
      gasLimit: "1400000",
      maxFeePerGas: "10000000000",
      maxPriorityFeePerGas: "1000000000"
    });
    const wallet = Wallet.createRandom();
    const signed = await wallet.signTransaction(request);
    const parsed = verifySignedFactoryDeployment(signed, {
      ...request,
      signer: wallet.address,
      transactionHash: keccak256(signed),
      dataHash: deployment.dataHash,
      creationBytecodeLength: deployment.creationBytecodeLength,
      creationBytecodeHash: deployment.creationBytecodeHash,
      constructorDataHash: deployment.constructorDataHash
    });
    assert.equal(parsed.from, wallet.address);
    assert.equal(parsed.to, null);
    assert.equal(parsed.value, 0n);
    assert.equal(parsed.nonce, 2);
  });

  it("rejects nonce, chain, value, fee, and deployment-data mutations", function () {
    const deployment = buildFactoryDeploymentData();
    const request = buildFactoryDeploymentTransaction({
      data: deployment.data,
      dataHash: deployment.dataHash,
      gasLimit: "1400000",
      maxFeePerGas: "10000000000",
      maxPriorityFeePerGas: "1000000000"
    });
    for (const [mutation, pattern] of [
      [{ ...request, nonce: 3 }, /nonce_mismatch/],
      [{ ...request, chainId: 1 }, /wrong_chain/],
      [{ ...request, value: 1n }, /value_must_be_zero/],
      [{ ...request, maxFeePerGas: MAX_FEE_PER_GAS + 1n }, /max_fee/],
      [{ ...request, data: "0x6000" }, /data_mismatch/]
    ]) {
      assert.throws(
        () => validateFactoryDeploymentTransaction(mutation, {
          dataHash: deployment.dataHash
        }),
        pattern
      );
    }
  });

  it("rejects approval replay once a receipt path exists", function () {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o24-"));
    const receipt = path.join(directory, "receipt.json");
    assert.doesNotThrow(() => assertFreshO24ReceiptPath(receipt));
    fs.writeFileSync(receipt, "{}");
    assert.throws(
      () => assertFreshO24ReceiptPath(receipt),
      /O24_FACTORY_APPROVAL_ALREADY_CONSUMED/
    );
  });

  it("reconciles the receipt to the expected factory and untouched account", function () {
    const receipt = readJson(O24_RECEIPT_PATH);
    assert.equal(receipt.receiptStatus, "success");
    assert.equal(receipt.signerPublicAddress, EXPECTED_DEPLOYER);
    assert.equal(receipt.signerRecovered, EXPECTED_DEPLOYER);
    assert.equal(receipt.nonce, FACTORY_DEPLOYMENT_NONCE);
    assert.equal(receipt.predictedFactory, EXPECTED_FACTORY);
    assert.equal(receipt.actualFactory, EXPECTED_FACTORY);
    assert.equal(receipt.runtimeCodeVerification.matched, true);
    assert.equal(receipt.constructorStateVerification.matched, true);
    assert.equal(receipt.entryPointBinding.matched, true);
    assert.equal(receipt.counterfactualAccount.expected, EXPECTED_ACCOUNT);
    assert.equal(receipt.counterfactualAccount.returnedByFactory, EXPECTED_ACCOUNT);
    assert.equal(receipt.counterfactualAccount.deployed, false);
    assert.equal(receipt.counterfactualAccount.funded, false);
    assert.equal(
      BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPriceWei),
      BigInt(receipt.exactTransactionCostWei)
    );
  });

  it("proves no funding, account creation, Device Vault, bundler, or UserOperation use", function () {
    const text = fs.readFileSync(O24_RECEIPT_PATH, "utf8");
    const receipt = JSON.parse(text);
    assert.equal(receipt.publicMutationScope, "factory-deployment-only");
    assert.equal(receipt.confirmationTargetChanged, false);
    assert.equal(receipt.fundingWalletUsed, false);
    assert.equal(receipt.smartAccountDeployed, false);
    assert.equal(receipt.smartAccountFunded, false);
    assert.equal(receipt.factoryAccountCreationCalled, false);
    assert.equal(receipt.entryPointDepositCreated, false);
    assert.equal(receipt.deviceVaultSignatureGenerated, false);
    assert.equal(receipt.bundlerContacted, false);
    assert.equal(receipt.userOperationSubmitted, false);
    assert.deepEqual(receipt.stateBefore.account2, receipt.stateAfter.account2);
    assert.doesNotMatch(
      text,
      /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey/i
    );
    ensureNoSecrets(receipt);
  });

  it("keeps the live deployer restricted to one broadcast and Account 1 only", function () {
    const script = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/deploy-o24-factory.cjs"
    ), "utf8");
    assert.equal((script.match(/broadcastTransaction\(/g) ?? []).length, 1);
    assert.equal((script.match(/new Wallet\(/g) ?? []).length, 1);
    assert.match(script, /PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY/);
    assert.doesNotMatch(script, /PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY/);
    assert.doesNotMatch(script, /eth_sendUserOperation/);
    assert.match(
      script,
      /factory\["getAddress\(address,bytes32,bytes32,uint256\)"\]/
    );
    const reconciler = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/reconcile-o24-factory.cjs"
    ), "utf8");
    assert.doesNotMatch(reconciler, /broadcastTransaction|new Wallet|signTransaction/);
  });
});
