require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  Interface,
  concat,
  getAddress,
  keccak256
} = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  LOCAL_PROOF_GATED_PREPARATION_LIMITS,
  createRestrictedSepoliaBundlerClient,
  redactRpcEndpoint
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  EXPECTED_VALIDATOR,
  ROOT,
  ensureNoSecrets,
  readJson
} = require("../../scripts/ethereum-sepolia/o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET
} = require("../../scripts/ethereum-sepolia/o24-factory-common.cjs");
const {
  O25_PREFUND_PATH,
  O25_READINESS_PATH,
  O25_USER_OPERATION_PATH,
  buildEstimationOnlyUserOperation,
  buildFundingProposal,
  calculateNoPaymasterRequiredPrefund,
  validateEstimationOnlyUserOperation,
  validateFundingProposal
} = require("../../scripts/ethereum-sepolia/o25-readiness-common.cjs");

const FACTORY_ARTIFACT = require(
  "../../artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol/PhilCore4337LocalProofAccountFactoryV1.json"
);

describe("O.25 counterfactual prefund and bundler readiness", function () {
  const readiness = readJson(O25_READINESS_PATH);
  const funding = readJson(O25_PREFUND_PATH);
  const estimation = readJson(O25_USER_OPERATION_PATH);

  it("preserves the live target, factory, EntryPoint, and canonical identity bindings", function () {
    assert.equal(readiness.confirmationTarget.address, EXPECTED_TARGET);
    assert.equal(readiness.confirmationTarget.matched, true);
    assert.equal(readiness.factory.address, EXPECTED_FACTORY);
    assert.equal(readiness.factory.matched, true);
    assert.equal(readiness.factory.entryPoint, ERC4337_V07_CANONICAL_ENTRYPOINT);
    assert.equal(readiness.factory.approvedConfirmationTarget, EXPECTED_TARGET);
    assert.equal(readiness.factory.expectedChainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(readiness.entryPoint.address, ERC4337_V07_CANONICAL_ENTRYPOINT);
    assert.equal(readiness.entryPoint.version, "0.7");
    assert.equal(readiness.entryPoint.matched, true);
    assert.equal(readiness.canonicalIdentity.validatorAddress, EXPECTED_VALIDATOR);
    assert.equal(readiness.canonicalIdentity.preserved, true);
    assert.equal(readiness.accounts.account1.address, EXPECTED_DEPLOYER);
    assert.equal(readiness.accounts.account2.address, EXPECTED_FUNDING);
  });

  it("binds independent CREATE2 and factory getAddress to the untouched account", function () {
    const account = readiness.counterfactualAccount;
    assert.equal(account.address, EXPECTED_ACCOUNT);
    assert.equal(account.localCreate2Derivation, EXPECTED_ACCOUNT);
    assert.equal(account.factoryGetAddressResult, EXPECTED_ACCOUNT);
    assert.equal(account.agreement, true);
    assert.equal(account.factory, EXPECTED_FACTORY);
    assert.equal(account.saltBytes32.length, 66);
    assert.equal(account.codeStatus, "empty");
    assert.equal(account.balance.wei, "0");
    assert.equal(account.entryPointNonce, "0");
    assert.equal(account.entryPointDeposit.wei, "0");
    assert.equal(account.latestTransactionCount, "0");
    assert.equal(account.pendingTransactionCount, "0");
    assert.equal(account.deployed, false);
    assert.equal(account.funded, false);
  });

  it("uses exact v0.7 factory data and an atomic first-operation model", function () {
    const factory = new Interface(FACTORY_ARTIFACT.abi);
    const decoded = factory.decodeFunctionData(
      "createAccount",
      estimation.factoryData
    );
    assert.equal(getAddress(decoded.owner), EXPECTED_VALIDATOR);
    assert.equal(decoded.ownerCommitment, readiness.canonicalIdentity.ownerCommitment);
    assert.equal(decoded.validatorKeyId, readiness.canonicalIdentity.validatorKeyIdBinding);
    assert.equal(decoded.salt.toString(), readiness.counterfactualAccount.saltDecimal);
    assert.equal(
      estimation.packedUserOperation.initCode,
      concat([EXPECTED_FACTORY, estimation.factoryData])
    );
    assert.equal(readiness.initialization.v07RpcRepresentation, "factory_and_factoryData");
    assert.equal(readiness.initialization.expectedSender, EXPECTED_ACCOUNT);
    assert.equal(readiness.initialization.expectedEntryPointNonce, "0");
    assert.equal(readiness.initialization.recoveryAuthorityPresent, false);
    assert.equal(readiness.initialization.arbitraryOwnerSubstitutionAllowed, false);
    assert.equal(readiness.initialization.accountCreationAndConfirmationAtomic, true);
    assert.equal(readiness.initialization.failureRollsBackCreation, true);
  });

  it("keeps the estimation template structurally useful and impossible to mistake for authority", function () {
    assert.equal(validateEstimationOnlyUserOperation(estimation), true);
    assert.equal(estimation.estimationOnly, true);
    assert.equal(estimation.submissionReady, false);
    assert.equal(estimation.proofGenerated, false);
    assert.equal(estimation.authorizationGenerated, false);
    assert.equal(estimation.userApprovalGenerated, false);
    assert.equal(estimation.freshPresenceGenerated, false);
    assert.equal(estimation.deviceVaultSignatureGenerated, false);
    assert.equal(estimation.userOperationSigned, false);
    assert.equal(estimation.userOperationSubmitted, false);
    assert.equal(estimation.paymasterEnabled, false);
    assert.equal(estimation.valueWei, "0");
    assert.match(estimation.packedUserOperation.signature, /^0x0+$/);
    assert.equal(estimation.packedUserOperation.signature.length, 2 + 288 * 2);
    assert.equal(
      keccak256(estimation.factoryData),
      estimation.factoryDataHash
    );
  });

  it("reproduces the exact no-paymaster EntryPoint v0.7 prefund formula", function () {
    const calculation = calculateNoPaymasterRequiredPrefund({
      verificationGasLimit: "1500000",
      callGasLimit: "300000",
      preVerificationGas: "200000",
      maxFeePerGas: "2500000000"
    });
    assert.equal(calculation.requiredGas, "2000000");
    assert.equal(calculation.requiredPrefundWei, "5000000000000000");
    assert.match(calculation.formula, /verificationGasLimit/);
    assert.throws(
      () => calculateNoPaymasterRequiredPrefund({
        verificationGasLimit: "1",
        callGasLimit: "1",
        preVerificationGas: "1",
        maxFeePerGas: "1",
        paymasterVerificationGasLimit: "1"
      }),
      /paymaster_not_permitted/
    );
    assert.equal(
      readiness.prefund.hardCeilingCalculation.requiredPrefundWei,
      (
        (
          LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxVerificationGasLimit
          + LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxCallGasLimit
          + LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxPreVerificationGas
        ) * LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei
      ).toString()
    );
    assert.equal(readiness.prefund.recommendationUsesHardCeiling, false);
  });

  it("proves local account creation, confirmation, nonce transition, prefund, and rollback checks", function () {
    const simulation = readiness.localSimulation;
    assert.equal(simulation.source, "isolated_local_hardhat_entrypoint_v0_7");
    assert.equal(simulation.evidenceClassification, "local_fixture");
    assert.equal(simulation.fixtureSignatureOnly, true);
    assert.equal(simulation.realUserSignatureGenerated, false);
    assert.equal(simulation.publicNetworkContacted, false);
    assert.equal(simulation.accountCreation.atomicWithFirstOperation, true);
    assert.equal(simulation.accountCreation.codeAfterPresent, true);
    assert.equal(simulation.state.nonceBefore, "0");
    assert.equal(simulation.state.nonceAfter, "1");
    assert.equal(simulation.state.confirmationSucceeded, true);
    assert.equal(simulation.allFailureChecksPassed, true);
    for (const passed of Object.values(simulation.rollbackAndFailureChecks)) {
      assert.equal(passed, true);
    }
  });

  it("selects direct prefunding from Account 2 without creating funding authority", function () {
    assert.equal(
      readiness.fundingMechanism.selected,
      "direct_eth_transfer_to_counterfactual_address"
    );
    assert.equal(readiness.fundingMechanism.entryPointDepositRequired, false);
    assert.equal(readiness.fundingMechanism.create2AddressAffectedByBalance, false);
    assert.equal(readiness.fundingMechanism.transactionHistoryIntroducedByFunding, true);
    assert.match(readiness.fundingMechanism.residualFunds, /no general withdrawal/);
    assert.equal(funding.status, "proposed");
    assert.equal(funding.approved, false);
    assert.equal(funding.signed, false);
    assert.equal(funding.broadcast, false);
    assert.equal(funding.sender, EXPECTED_FUNDING);
    assert.equal(funding.recipient, EXPECTED_ACCOUNT);
    assert.equal(funding.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(funding.calldata, "0x");
    assert.equal(funding.factoryCall, false);
    assert.equal(funding.entryPointCall, false);
    assert.equal(funding.accountDeployment, false);
    assert.equal(
      funding.value.wei,
      readiness.prefund.proposedMaximumFundingApproval.wei
    );
    assert.equal(
      validateFundingProposal(funding, {
        now: new Date(funding.observedAt).getTime()
      }),
      true
    );
  });

  it("fails closed on funding replay, mutation, wrong role, and fee escalation", function () {
    const now = new Date(funding.observedAt).getTime();
    for (const [mutation, pattern] of [
      [{ ...funding, chainId: 1 }, /wrong_chain/],
      [{ ...funding, sender: EXPECTED_DEPLOYER }, /wrong_funder/],
      [{ ...funding, recipient: EXPECTED_TARGET }, /wrong_recipient/],
      [{ ...funding, calldata: "0x01" }, /calldata_nonempty/],
      [{
        ...funding,
        maxFeePerGas: {
          ...funding.maxFeePerGas,
          wei: (LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei + 1n).toString()
        }
      }, /max_fee_ceiling/],
      [{ ...funding, approved: true }, /authority_marker/]
    ]) {
      assert.throws(
        () => validateFundingProposal(mutation, { now }),
        pattern
      );
    }
    assert.throws(
      () => validateFundingProposal(funding, {
        now: new Date(funding.expiresAt).getTime() + 1
      }),
      /expired/
    );
  });

  it("rejects insufficient Account 2 balance and preserves a bounded transfer", function () {
    assert.throws(
      () => buildFundingProposal({
        valueWei: "1000000000000000",
        maxFeePerGasWei: "1000000000",
        maxPriorityFeePerGasWei: "1000000",
        nonce: "0",
        senderBalanceWei: "1",
        smartAccountBalanceWei: "0",
        latestBlockNumber: "1",
        latestBlockHash: `0x${"11".repeat(32)}`,
        observedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-01T00:15:00.000Z"
      }),
      /balance_insufficient/
    );
    assert.equal(BigInt(funding.gasLimit), 21_000n);
    assert.ok(
      BigInt(funding.senderBalanceAfterAtMaximumCost.wei) > 0n
    );
  });

  it("keeps bundler discovery read-only and records the unconfigured boundary", async function () {
    assert.equal(readiness.bundler.status, "BUNDLER_NOT_CONFIGURED");
    assert.equal(readiness.bundler.configured, false);
    assert.equal(readiness.bundler.contacted, false);
    assert.equal(readiness.bundler.submissionMethodCalled, false);
    assert.equal(redactRpcEndpoint("https://example.test/secret"), "https://example.test/<redacted>");
    const called = [];
    const client = createRestrictedSepoliaBundlerClient({
      url: "https://example.test/secret",
      transport: {
        async request(method) {
          called.push(method);
          return method === "eth_chainId" ? "0xaa36a7" : [];
        }
      }
    });
    assert.equal(await client.request("eth_chainId", []), "0xaa36a7");
    await client.request("eth_supportedEntryPoints", []);
    assert.deepEqual(called, ["eth_chainId", "eth_supportedEntryPoints"]);
    await assert.rejects(
      client.request("eth_sendUserOperation", []),
      /BUNDLER_METHOD_NOT_ALLOWED/
    );
  });

  it("contains no mutation path, protected material, or public submission result", function () {
    const generator = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/generate-o25-readiness.cjs"
    ), "utf8");
    assert.doesNotMatch(
      generator,
      /\.request\(\s*["']eth_sendTransaction|\.request\(\s*["']eth_sendRawTransaction|\.request\(\s*["']eth_sendUserOperation/
    );
    assert.doesNotMatch(generator, /broadcastTransaction|signTransaction|sendTransaction\(/);
    assert.equal(readiness.stopBoundary.ethTransferred, false);
    assert.equal(readiness.stopBoundary.entryPointDepositCreated, false);
    assert.equal(readiness.stopBoundary.accountDeployed, false);
    assert.equal(readiness.stopBoundary.starkProofGenerated, false);
    assert.equal(readiness.stopBoundary.deviceVaultUsed, false);
    assert.equal(readiness.stopBoundary.userOperationSigned, false);
    assert.equal(readiness.stopBoundary.userOperationSubmitted, false);
    assert.equal(readiness.stopBoundary.publicMutationOccurred, false);
    for (const value of [readiness, funding, estimation]) ensureNoSecrets(value);
    const combined = [
      O25_READINESS_PATH,
      O25_PREFUND_PATH,
      O25_USER_OPERATION_PATH
    ].map((file) => fs.readFileSync(file, "utf8")).join("\n");
    assert.doesNotMatch(
      combined,
      /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey/i
    );
  });

  it("reruns the deterministic local fixture without public contact", function () {
    const result = spawnSync(
      process.execPath,
      ["scripts/ethereum-sepolia/estimate-o25-local-entrypoint.cjs"],
      { cwd: ROOT, encoding: "utf8" }
    );
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.publicNetworkContacted, false);
    assert.equal(output.fixtureMutationOnly, true);
    assert.equal(output.transactionSubmittedToPublicNetwork, false);
    assert.equal(output.allFailureChecksPassed, true);
  });
});
