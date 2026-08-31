require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { Wallet } = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  ROOT,
  ensureNoSecrets
} = require("../../scripts/ethereum-sepolia/o23r-common.cjs");
const {
  DIRECT_TRANSFER_GAS_LIMIT,
  EXPECTED_ACCOUNT,
  EXPECTED_DEPLOYER,
  EXPECTED_FACTORY,
  EXPECTED_FUNDING,
  EXPECTED_TARGET,
  O27_PROPOSAL_PATH,
  O27_RECEIPT_PATH,
  assertO27ApprovalBoundState,
  buildO27Proposal,
  buildO27Transaction,
  createO27OneShotBroadcastClient,
  createO27ReadOnlyClient,
  validateO27Proposal,
  validateO27Transaction,
  verifySignedO27Transaction
} = require("../../scripts/ethereum-sepolia/o27-account2-prefund-common.cjs");

function fixtureState() {
  return {
    block: {
      number: "11370413",
      hash: `0x${"11".repeat(32)}`,
      timestamp: 1785264228
    },
    infrastructure: {
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      entryPoint: {
        address: ERC4337_V07_CANONICAL_ENTRYPOINT,
        codeHash: `0x${"22".repeat(32)}`
      },
      target: {
        address: EXPECTED_TARGET,
        codeHash: `0x${"33".repeat(32)}`
      },
      factory: {
        address: EXPECTED_FACTORY,
        codeHash: `0x${"44".repeat(32)}`
      },
      bindingDigest: `0x${"55".repeat(32)}`
    },
    account: {
      address: EXPECTED_ACCOUNT,
      locallyDerivedAddress: EXPECTED_ACCOUNT,
      factoryDerivedAddress: EXPECTED_ACCOUNT,
      codeStatus: "empty",
      codeHash: null,
      balanceWei: "0",
      latestTransactionCount: "0",
      pendingTransactionCount: "0",
      entryPointNonce: "0",
      entryPointDepositWei: "0"
    },
    accounts: {
      account1: {
        address: EXPECTED_DEPLOYER,
        latestNonce: "3",
        pendingNonce: "3",
        balanceWei: "270073390298140959"
      },
      account2: {
        address: EXPECTED_FUNDING,
        latestNonce: "0",
        pendingNonce: "0",
        balanceWei: "92576112524973299"
      }
    }
  };
}

function fixtureProposal() {
  const state = fixtureState();
  return buildO27Proposal({
    generatedAt: "2026-07-28T18:43:48.000Z",
    expiresAt: "2099-07-28T18:58:48.000Z",
    sourceHead: `0x${"66".repeat(32)}`,
    branch: "codex/device-identity-v1",
    senderNonce: "0",
    recipientBalanceWei: "0",
    recipientCodeStatus: "empty",
    account2BalanceWei: state.accounts.account2.balanceWei,
    valueWei: "5020561254000000",
    maxFeePerGasWei: "2510280627",
    maxPriorityFeePerGasWei: "1875000",
    expectedOperationCostWei: "1039801311467270",
    expectedResidualWei: "3980759942532730",
    estimatedMinimumPrefundWei: "4016449004000000",
    remoteDeclaredGas: {
      verificationGasLimit: "1500000",
      callGasLimit: "300000",
      preVerificationGas: "200000",
      totalDeclaredGas: "2000000"
    },
    o261CompatibilityBinding: "fixture-provider-binding",
    o261GasEstimateBinding: `0x${"77".repeat(32)}`,
    state
  });
}

describe("O.27 Account 2 direct prefunding", function () {
  it("binds only Account 2 to one exact empty-calldata Sepolia transfer", function () {
    const proposal = fixtureProposal();
    const transaction = buildO27Transaction(proposal);
    assert.equal(proposal.phase, "O.27");
    assert.equal(proposal.sender, EXPECTED_FUNDING);
    assert.equal(proposal.verifiedDerivedSender, EXPECTED_FUNDING);
    assert.equal(proposal.recipient, EXPECTED_ACCOUNT);
    assert.equal(transaction.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(transaction.nonce, 0);
    assert.equal(transaction.to, EXPECTED_ACCOUNT);
    assert.equal(transaction.data, "0x");
    assert.equal(transaction.gasLimit, DIRECT_TRANSFER_GAS_LIMIT);
    assert.equal(transaction.value, 5020561254000000n);
    assert.equal(
      proposal.maximumTransactionFee.wei,
      (DIRECT_TRANSFER_GAS_LIMIT * 2510280627n).toString()
    );
  });

  it("rejects chain, nonce, recipient, calldata, gas, value, and fee changes", function () {
    const proposal = fixtureProposal();
    const transaction = buildO27Transaction(proposal);
    for (const [mutation, pattern] of [
      [{ ...transaction, chainId: 1 }, /WRONG_CHAIN/],
      [{ ...transaction, nonce: 1 }, /NONCE_MISMATCH/],
      [{ ...transaction, to: EXPECTED_DEPLOYER }, /RECIPIENT_MISMATCH/],
      [{ ...transaction, data: "0x00" }, /CALLDATA_MUST_BE_EMPTY/],
      [{ ...transaction, gasLimit: 22000n }, /GAS_LIMIT_MISMATCH/],
      [{ ...transaction, value: transaction.value + 1n }, /TRANSFER_VALUE_MISMATCH/],
      [{ ...transaction, maxFeePerGas: transaction.maxFeePerGas + 1n }, /FEE_ENVELOPE_MISMATCH/],
      [{
        ...transaction,
        maxPriorityFeePerGas: transaction.maxPriorityFeePerGas + 1n
      }, /FEE_ENVELOPE_MISMATCH/]
    ]) {
      assert.throws(() => validateO27Transaction(mutation, proposal), pattern);
    }
  });

  it("recovers the signer and rejects any signer other than Account 2 by default", async function () {
    const proposal = fixtureProposal();
    const wallet = Wallet.createRandom();
    const raw = await wallet.signTransaction(buildO27Transaction(proposal));
    assert.throws(
      () => verifySignedO27Transaction(raw, proposal),
      /SIGNER_RECOVERY_FAILED/
    );
    const parsed = verifySignedO27Transaction(raw, proposal, wallet.address);
    assert.equal(parsed.from, wallet.address);
    assert.equal(parsed.data, "0x");
    assert.equal(parsed.value, 5020561254000000n);
  });

  it("uses a one-shot raw-transaction client and never retries", async function () {
    const calls = [];
    const client = createO27OneShotBroadcastClient({
      transport: {
        async request(method, params) {
          calls.push({ method, params });
          throw new Error("ambiguous transport failure");
        }
      }
    });
    await assert.rejects(client.broadcastOnce("0x1234"), /ambiguous/);
    await assert.rejects(
      client.broadcastOnce("0x1234"),
      /BROADCAST_ALREADY_ATTEMPTED/
    );
    assert.equal(client.broadcastCount, 1);
    assert.deepEqual(calls.map((call) => call.method), ["eth_sendRawTransaction"]);
    assert.equal(client.automaticRetryEnabled, false);
  });

  it("keeps the read client method-specific and mutation-free", function () {
    const client = createO27ReadOnlyClient({
      transport: { async request() { return null; } }
    });
    assert.equal(client.mutationMethodsExposed, false);
    assert.equal("request" in client, false);
    assert.equal("sendRawTransaction" in client, false);
    assert.equal("sendUserOperation" in client, false);
  });

  it("invalidates exact approval on infrastructure or recipient changes", function () {
    const proposal = fixtureProposal();
    const infrastructureChanged = structuredClone(fixtureState());
    infrastructureChanged.infrastructure.bindingDigest = `0x${"88".repeat(32)}`;
    assert.throws(
      () => assertO27ApprovalBoundState(proposal, infrastructureChanged),
      /INVALIDATED_INFRASTRUCTURE/
    );
    const recipientChanged = structuredClone(fixtureState());
    recipientChanged.account.balanceWei = "1";
    assert.throws(
      () => assertO27ApprovalBoundState(proposal, recipientChanged),
      /INVALIDATED_RECIPIENT_STATE/
    );
  });

  it("invalidates approval on Account 2 nonce or insufficient balance", function () {
    const proposal = fixtureProposal();
    const nonceChanged = structuredClone(fixtureState());
    nonceChanged.accounts.account2.pendingNonce = "1";
    assert.throws(
      () => assertO27ApprovalBoundState(proposal, nonceChanged),
      /INVALIDATED_ACCOUNT2_NONCE/
    );
    const balanceChanged = structuredClone(fixtureState());
    balanceChanged.accounts.account2.balanceWei =
      (BigInt(proposal.maximumTotalAccount2Debit.wei) - 1n).toString();
    assert.throws(
      () => assertO27ApprovalBoundState(proposal, balanceChanged),
      /INVALIDATED_ACCOUNT2_BALANCE/
    );
  });

  it("prohibits Account 1 use and invalidates approval if Account 1 changes", function () {
    const proposal = fixtureProposal();
    assert.equal(proposal.authority.account1UseAuthorized, false);
    const changed = structuredClone(fixtureState());
    changed.accounts.account1.balanceWei = "1";
    assert.throws(
      () => assertO27ApprovalBoundState(proposal, changed),
      /ACCOUNT1_STATE_CHANGED/
    );
    const executionSource = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/execute-o27-account2-prefund.cjs"
    ), "utf8");
    assert.match(executionSource, /PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY/);
    assert.doesNotMatch(executionSource, /PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY/);
  });

  it("stores no reusable approval, signed raw transaction, or expanded authority", function () {
    const proposal = fixtureProposal();
    assert.equal(validateO27Proposal(proposal, { now: Date.now() }), true);
    assert.equal(proposal.approval.approved, false);
    assert.equal(proposal.approval.approvalReceived, false);
    assert.equal(proposal.approval.reusableApprovalArtifact, false);
    assert.equal(proposal.authority.account2DirectEthTransferAuthorized, false);
    assert.equal(proposal.authority.factoryCallAuthorized, false);
    assert.equal(proposal.authority.accountDeploymentAuthorized, false);
    assert.equal(proposal.authority.proofGenerationAuthorized, false);
    assert.equal(proposal.authority.deviceVaultSigningAuthorized, false);
    assert.equal(proposal.authority.userOperationSubmissionAuthorized, false);
    assert.equal(proposal.authority.secondTransactionAuthorized, false);
    assert.equal(proposal.signed, false);
    assert.equal(proposal.broadcast, false);
    assert.equal(proposal.publicMutationOccurred, false);
    assert.doesNotMatch(JSON.stringify(proposal), /rawSigned|rawTransaction/);
    ensureNoSecrets(proposal);
  });

  it("keeps the generated live proposal exact, sanitized, and unapproved", function () {
    const proposal = JSON.parse(fs.readFileSync(O27_PROPOSAL_PATH, "utf8"));
    assert.equal(validateO27Proposal(proposal), true);
    assert.equal(proposal.sender, EXPECTED_FUNDING);
    assert.equal(proposal.recipient, EXPECTED_ACCOUNT);
    assert.equal(proposal.senderNonce, "0");
    assert.equal(proposal.recipientBalanceBefore.wei, "0");
    assert.equal(proposal.recipientCodeStatusBefore, "empty");
    assert.equal(proposal.calldata, "0x");
    assert.equal(proposal.gasLimit, "21000");
    assert.equal(proposal.snapshot.account.entryPointNonce, "0");
    assert.equal(proposal.snapshot.account.entryPointDepositWei, "0");
    assert.equal(proposal.snapshot.account1.latestNonce, "3");
    assert.equal(proposal.snapshot.account2.latestNonce, "0");
    assert.equal(proposal.approval.approved, false);
    assert.equal(proposal.signed, false);
    assert.equal(proposal.broadcast, false);
    assert.equal(proposal.publicMutationOccurred, false);
    ensureNoSecrets(proposal);
  });

  it("requires a new exact proposal after expiry or digest mutation", function () {
    const proposal = fixtureProposal();
    assert.throws(
      () => validateO27Proposal(proposal, {
        now: Date.parse(proposal.expiresAt) + 1
      }),
      /PROPOSAL_EXPIRED/
    );
    const changed = structuredClone(proposal);
    changed.transferValue.wei = (BigInt(changed.transferValue.wei) + 1n).toString();
    assert.throws(
      () => validateO27Proposal(changed),
      /PROPOSAL_DIGEST_MISMATCH/
    );
  });

  it("contains one broadcast callsite, no retry loop, and no bundler submission", function () {
    const commonSource = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/o27-account2-prefund-common.cjs"
    ), "utf8");
    const executionSource = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/execute-o27-account2-prefund.cjs"
    ), "utf8");
    assert.equal((commonSource.match(/eth_sendRawTransaction/g) ?? []).length, 1);
    assert.doesNotMatch(executionSource, /broadcastOnce\\([^)]*\\).*broadcastOnce/s);
    assert.doesNotMatch(
      `${commonSource}\n${executionSource}`,
      /eth_sendUserOperation|sendUserOperation/
    );
    assert.equal(fs.existsSync(O27_RECEIPT_PATH), true);
  });

  it("reconciles the one successful transfer and exact post-transfer state", function () {
    const receipt = JSON.parse(fs.readFileSync(O27_RECEIPT_PATH, "utf8"));
    assert.equal(receipt.phase, "O.27");
    assert.equal(receipt.status, "COMPLETE");
    assert.equal(
      receipt.proposalDigest,
      "0x9ff157d194184e38216546071b3f052ddebf41552d33505001811192d005e0e9"
    );
    assert.equal(
      receipt.transaction.hash,
      "0x37d191d70cf45cc6a4eaa83c9518a980a6d9a575e211ea70796e28143e51431d"
    );
    assert.equal(receipt.transaction.sender, EXPECTED_FUNDING);
    assert.equal(receipt.transaction.recoveredSigner, EXPECTED_FUNDING);
    assert.equal(receipt.transaction.recipient, EXPECTED_ACCOUNT);
    assert.equal(receipt.transaction.nonce, "0");
    assert.equal(receipt.transaction.value.wei, "5124486704000000");
    assert.equal(receipt.transaction.calldata, "0x");
    assert.equal(receipt.transaction.gasLimit, "21000");
    assert.equal(receipt.transaction.signedOnlyByAccount2, true);
    assert.equal(receipt.transaction.decodedAndMatchedApproval, true);
    assert.equal(receipt.receipt.found, true);
    assert.equal(receipt.receipt.status, "success");
    assert.equal(receipt.receipt.logCount, 0);
    assert.equal(receipt.receipt.gasUsed, "21000");
    assert.equal(
      BigInt(receipt.receipt.gasUsed)
        * BigInt(receipt.receipt.effectiveGasPrice.wei),
      BigInt(receipt.receipt.exactTransactionFee.wei)
    );
    assert.equal(
      BigInt(receipt.transaction.value.wei)
        + BigInt(receipt.receipt.exactTransactionFee.wei),
      BigInt(receipt.receipt.exactTotalAccount2Debit.wei)
    );
    assert.deepEqual(
      receipt.stateBefore.accounts.account1,
      receipt.stateAfter.accounts.account1
    );
    assert.equal(receipt.stateBefore.accounts.account2.latestNonce, "0");
    assert.equal(receipt.stateAfter.accounts.account2.latestNonce, "1");
    assert.equal(receipt.stateBefore.account.balanceWei, "0");
    assert.equal(receipt.stateAfter.account.balanceWei, "5124486704000000");
    assert.equal(receipt.stateAfter.account.codeStatus, "empty");
    assert.equal(receipt.stateAfter.account.entryPointNonce, "0");
    assert.equal(receipt.stateAfter.account.entryPointDepositWei, "0");
    assert.equal(receipt.controls.broadcastCount, 1);
    assert.equal(receipt.controls.automaticRetryPerformed, false);
    assert.equal(receipt.controls.secondTransactionPerformed, false);
    assert.equal(receipt.controls.factoryCallPerformed, false);
    assert.equal(receipt.controls.deviceVaultSigningPerformed, false);
    assert.equal(receipt.controls.userOperationSubmitted, false);
    assert.equal(receipt.controls.bundlerSubmissionPerformed, false);
    assert.equal(receipt.exactPublicMutationCount, 1);
    ensureNoSecrets(receipt);
  });
});
