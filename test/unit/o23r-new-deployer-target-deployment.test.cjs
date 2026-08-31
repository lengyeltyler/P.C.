require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {
  Transaction,
  Wallet,
  getAddress,
  getCreateAddress,
  keccak256
} = require("ethers");

const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  EXPECTED_VALIDATOR,
  MAX_FEE_PER_GAS,
  O23R_FUNDING_PATH,
  O23R_PROPOSAL_PATH,
  O23R_RECEIPT_PATH,
  OLD_ADDRESSES,
  ROOT,
  assertRoleSeparation,
  buildTargetDeploymentTransaction,
  canonicalDigest,
  ensureNoSecrets,
  readJson,
  validateTargetDeploymentTransaction,
  verifySignedTargetDeployment
} = require("../../scripts/ethereum-sepolia/o23r-common.cjs");
const {
  selectApprovedMaxFee
} = require("../../scripts/ethereum-sepolia/generate-o23r-readiness.cjs");

describe("O.23R new-deployer target-only deployment", function () {
  it("keeps the deployment, funding, and canonical validator roles separate", function () {
    const roles = assertRoleSeparation({
      deployer: EXPECTED_DEPLOYER,
      funding: EXPECTED_FUNDING,
      validator: EXPECTED_VALIDATOR
    });
    assert.equal(roles.deployer, EXPECTED_DEPLOYER);
    assert.equal(roles.funding, EXPECTED_FUNDING);
    assert.equal(roles.validator, EXPECTED_VALIDATOR);
    assert.throws(
      () => assertRoleSeparation({
        deployer: EXPECTED_DEPLOYER,
        funding: EXPECTED_DEPLOYER,
        validator: EXPECTED_VALIDATOR
      }),
      /funding_address_mismatch|roles_not_separate/
    );
  });

  it("invalidates the old O.22 addresses and binds the new nonce sequence", function () {
    const proposal = readJson(O23R_PROPOSAL_PATH);
    assert.deepEqual(
      {
        target: proposal.oldAddressInvalidation.target,
        factory: proposal.oldAddressInvalidation.factory,
        account: proposal.oldAddressInvalidation.account
      },
      OLD_ADDRESSES
    );
    assert.equal(
      proposal.addressSequence.targetAddress,
      getCreateAddress({
        from: EXPECTED_DEPLOYER,
        nonce: BigInt(proposal.addressSequence.targetDeploymentNonce)
      })
    );
    assert.equal(
      proposal.addressSequence.factoryAddress,
      getCreateAddress({
        from: EXPECTED_DEPLOYER,
        nonce: BigInt(proposal.addressSequence.targetDeploymentNonce) + 1n
      })
    );
    assert.equal(
      proposal.addressSequence.factoryDeploymentNonce,
      (BigInt(proposal.addressSequence.targetDeploymentNonce) + 1n).toString()
    );
  });

  it("records collision-free target, factory, and account proposals", function () {
    const proposal = readJson(O23R_PROPOSAL_PATH);
    assert.equal(proposal.addressSequence.unexpectedCollision, false);
    for (const observation of Object.values(
      proposal.addressSequence.proposedAddressObservations
    )) {
      assert.equal(observation.codeStatus, "empty");
      assert.equal(observation.balanceWei, "0");
      assert.equal(observation.latestNonce, "0");
      assert.equal(observation.pendingNonce, "0");
    }
  });

  it("binds one target-only approval while rejecting downstream authority", function () {
    const proposal = readJson(O23R_PROPOSAL_PATH);
    const approval = { ...proposal.targetOnlyApproval };
    delete approval.approvalDigest;
    delete approval.approved;
    delete approval.consumed;
    assert.equal(canonicalDigest(approval), proposal.targetOnlyApproval.approvalDigest);
    assert.equal(proposal.targetOnlyApproval.approvedScope,
      "new-deployer-confirmation-target-only");
    assert.equal(proposal.approvals.targetDeploymentApproved, true);
    assert.equal(proposal.approvals.factoryDeploymentApproved, false);
    assert.equal(proposal.approvals.smartAccountFundingApproved, false);
    assert.equal(proposal.approvals.fundingWalletUseApproved, false);
    assert.equal(proposal.approvals.deviceVaultSigningApproved, false);
    assert.equal(proposal.approvals.bundlerContactApproved, false);
    assert.equal(proposal.approvals.userOperationSubmissionApproved, false);
  });

  it("constructs and recovers the exact zero-value EIP-1559 deployment", async function () {
    const wallet = Wallet.createRandom();
    const creationBytecode = "0x6000600055";
    const request = buildTargetDeploymentTransaction({
      nonce: "3",
      creationBytecode,
      creationBytecodeHash: keccak256(creationBytecode),
      gasLimit: "100000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000"
    });
    const signed = await wallet.signTransaction(request);
    const hash = keccak256(signed);
    const parsed = verifySignedTargetDeployment(signed, {
      ...request,
      signer: wallet.address,
      nonce: "3",
      creationBytecodeHash: keccak256(creationBytecode),
      transactionHash: hash
    });
    assert.equal(parsed.from, wallet.address);
    assert.equal(parsed.to, null);
    assert.equal(parsed.value, 0n);
    assert.equal(parsed.type, 2);
  });

  it("rejects wrong chain, nonzero value, fee overflow, and bytecode mutation", function () {
    const creationBytecode = "0x6000600055";
    const base = buildTargetDeploymentTransaction({
      nonce: "1",
      creationBytecode,
      creationBytecodeHash: keccak256(creationBytecode),
      gasLimit: "100000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000"
    });
    assert.throws(
      () => validateTargetDeploymentTransaction(
        { ...base, chainId: 1 },
        { nonce: "1", creationBytecodeHash: keccak256(creationBytecode) }
      ),
      /wrong_chain/
    );
    assert.throws(
      () => validateTargetDeploymentTransaction(
        { ...base, value: 1n },
        { nonce: "1", creationBytecodeHash: keccak256(creationBytecode) }
      ),
      /value_must_be_zero/
    );
    assert.throws(
      () => validateTargetDeploymentTransaction(
        { ...base, maxFeePerGas: MAX_FEE_PER_GAS + 1n },
        { nonce: "1", creationBytecodeHash: keccak256(creationBytecode) }
      ),
      /max_fee/
    );
    assert.throws(
      () => validateTargetDeploymentTransaction(
        { ...base, data: "0x6001" },
        { nonce: "1", creationBytecodeHash: keccak256(creationBytecode) }
      ),
      /bytecode_mismatch/
    );
  });

  it("uses a bounded fee cap with drift room instead of a momentary quote", function () {
    assert.equal(selectApprovedMaxFee(2_000_000_000n), 10_000_000_000n);
    assert.equal(selectApprovedMaxFee(4_000_000_000n), 16_000_000_000n);
    assert.equal(selectApprovedMaxFee(30_000_000_000n), MAX_FEE_PER_GAS);
  });

  it("keeps proposal and funding evidence secret-free and non-submitting", function () {
    const proposalText = fs.readFileSync(O23R_PROPOSAL_PATH, "utf8");
    const fundingText = fs.readFileSync(O23R_FUNDING_PATH, "utf8");
    const scripts = [
      "scripts/ethereum-sepolia/generate-o23r-readiness.cjs",
      "scripts/ethereum-sepolia/deploy-o23r-target.cjs"
    ].map((file) => fs.readFileSync(path.join(ROOT, file), "utf8")).join("\n");
    const deployerScript = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/deploy-o23r-target.cjs"
    ), "utf8");
    assert.doesNotMatch(
      `${proposalText}${fundingText}`,
      /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey/i
    );
    assert.doesNotMatch(scripts, /eth_sendUserOperation/);
    assert.equal((deployerScript.match(/broadcastTransaction\(/g) ?? []).length, 1);
    assert.equal((deployerScript.match(/new Wallet\(/g) ?? []).length, 1);
    assert.match(deployerScript, /PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY/);
    assert.doesNotMatch(deployerScript, /PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY/);
    ensureNoSecrets(JSON.parse(proposalText));
    ensureNoSecrets(JSON.parse(fundingText));
  });

  it("reconciles the one successful receipt to the exact approved target", function () {
    const proposal = readJson(O23R_PROPOSAL_PATH);
    const receipt = readJson(O23R_RECEIPT_PATH);
    assert.equal(receipt.receiptStatus, "success");
    assert.equal(receipt.signerPublicAddress, EXPECTED_DEPLOYER);
    assert.equal(receipt.signerRecovered, EXPECTED_DEPLOYER);
    assert.equal(receipt.nonce, proposal.addressSequence.targetDeploymentNonce);
    assert.equal(receipt.predictedTarget, proposal.addressSequence.targetAddress);
    assert.equal(receipt.actualTarget, proposal.addressSequence.targetAddress);
    assert.match(receipt.transactionHash, /^0x[0-9a-f]{64}$/);
    assert.equal(receipt.runtimeCodeVerification.matched, true);
    assert.equal(
      receipt.runtimeCodeVerification.expectedHash,
      proposal.artifacts.find((artifact) =>
        artifact.id === "confirmationTarget"
      ).deployedBytecodeHash
    );
    assert.equal(receipt.constructorStateVerification.matched, true);
    assert.equal(
      BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPriceWei),
      BigInt(receipt.exactTransactionCostWei)
    );
  });

  it("proves that O.23R stopped before every downstream mutation", function () {
    const receiptText = fs.readFileSync(O23R_RECEIPT_PATH, "utf8");
    const receipt = JSON.parse(receiptText);
    assert.equal(receipt.publicMutationOccurred, true);
    assert.equal(
      receipt.publicMutationScope,
      "new-deployer-confirmation-target-only"
    );
    assert.equal(receipt.factoryDeployed, false);
    assert.equal(receipt.smartAccountFunded, false);
    assert.equal(receipt.fundingWalletUsed, false);
    assert.equal(receipt.deviceVaultSignatureGenerated, false);
    assert.equal(receipt.bundlerContacted, false);
    assert.equal(receipt.userOperationSubmitted, false);
    assert.equal(receipt.stateAfter.factory.codeStatus, "empty");
    assert.equal(receipt.stateAfter.factory.balanceWei, "0");
    assert.equal(receipt.stateAfter.smartAccount.codeStatus, "empty");
    assert.equal(receipt.stateAfter.smartAccount.balanceWei, "0");
    assert.deepEqual(
      receipt.stateAfter.futurePrefundingWallet,
      receipt.stateBefore.futurePrefundingWallet
    );
    assert.doesNotMatch(
      receiptText,
      /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey/i
    );
  });
});
