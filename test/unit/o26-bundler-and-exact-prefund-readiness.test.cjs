require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  LOCAL_PROOF_GATED_PREPARATION_LIMITS,
  createRestrictedSepoliaBundlerClient
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const {
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
  O26_COMPATIBILITY_PATH,
  O26_ESTIMATE_PATH,
  O26_PREFUND_PATH,
  calculatePrefundEvidence,
  hashEndpointBinding,
  reconcileGasEstimates,
  validateBundlerCapabilities,
  validateBundlerEstimateResponse,
  validateO26EstimationOnlyUserOperation
} = require("../../scripts/ethereum-sepolia/o26-bundler-readiness-common.cjs");

describe("O.26 bundler compatibility and exact prefund readiness", function () {
  const compatibility = readJson(O26_COMPATIBILITY_PATH);
  const estimate = readJson(O26_ESTIMATE_PATH);
  const prefund = readJson(O26_PREFUND_PATH);
  const userOperation = estimate.estimationOnlyUserOperation;

  it("records a fail-closed unconfigured bundler boundary without contacting one", function () {
    assert.equal(compatibility.status, "BUNDLER_CONFIGURATION_REQUIRED");
    assert.equal(compatibility.configuredBundler.configured, false);
    assert.equal(compatibility.configuredBundler.contacted, false);
    assert.equal(compatibility.configuredBundler.estimationPerformed, false);
    assert.equal(compatibility.configuredBundler.submissionMethodExposed, false);
    assert.equal(compatibility.configuredBundler.submissionMethodCalled, false);
    assert.equal(compatibility.recommendation.primary, "Pimlico");
    assert.equal(compatibility.recommendation.fallback, "Alchemy");
    assert.equal(compatibility.recommendation.automaticallySelected, false);
  });

  it("redacts and hashes provider URLs without retaining credentials", function () {
    const binding = hashEndpointBinding(
      "https://bundler.example.test/v2/11155111/rpc?apikey=not-for-output"
    );
    assert.equal(binding.configured, true);
    assert.equal(binding.redacted, "https://bundler.example.test/<redacted>");
    assert.match(binding.sha256, /^[0-9a-f]{64}$/);
    assert.doesNotMatch(JSON.stringify(binding), /not-for-output/);
    assert.equal(hashEndpointBinding("").redacted, "not_configured");
  });

  it("validates Sepolia, EntryPoint v0.7, required methods, and no mandatory paymaster", function () {
    const methods = [
      "eth_supportedEntryPoints",
      "eth_estimateUserOperationGas",
      "eth_getUserOperationByHash",
      "eth_getUserOperationReceipt"
    ];
    assert.equal(validateBundlerCapabilities({
      chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
      supportedEntryPoints: [ERC4337_V07_CANONICAL_ENTRYPOINT],
      supportedMethods: methods,
      paymasterRequired: false
    }), true);
    assert.throws(
      () => validateBundlerCapabilities({
        chainId: 1,
        supportedEntryPoints: [ERC4337_V07_CANONICAL_ENTRYPOINT],
        supportedMethods: methods,
        paymasterRequired: false
      }),
      /BUNDLER_WRONG_CHAIN/
    );
    assert.throws(
      () => validateBundlerCapabilities({
        chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
        supportedEntryPoints: ["0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"],
        supportedMethods: methods,
        paymasterRequired: false
      }),
      /ENTRYPOINT_V07_UNSUPPORTED/
    );
    assert.throws(
      () => validateBundlerCapabilities({
        chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
        supportedEntryPoints: [ERC4337_V07_CANONICAL_ENTRYPOINT],
        supportedMethods: methods,
        paymasterRequired: true
      }),
      /MANDATORY_PAYMASTER/
    );
    assert.throws(
      () => validateBundlerCapabilities({
        chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
        supportedEntryPoints: [ERC4337_V07_CANONICAL_ENTRYPOINT],
        supportedMethods: methods.filter((method) =>
          method !== "eth_getUserOperationReceipt"
        ),
        paymasterRequired: false
      }),
      /REQUIRED_METHOD_UNSUPPORTED/
    );
  });

  it("constructs a decoder-correct but cryptographically invalid estimation envelope", function () {
    assert.equal(validateO26EstimationOnlyUserOperation(userOperation), true);
    assert.equal(userOperation.sender, EXPECTED_ACCOUNT);
    assert.equal(userOperation.factory, EXPECTED_FACTORY);
    assert.equal(userOperation.target, EXPECTED_TARGET);
    assert.equal(userOperation.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(userOperation.entryPoint, ERC4337_V07_CANONICAL_ENTRYPOINT);
    assert.equal(userOperation.placeholders.signatureLengthBytes, 288);
    assert.equal(userOperation.placeholders.cryptographicAuthority, false);
    assert.doesNotMatch(userOperation.rpcV07Representation.signature, /^0x0+$/);
    assert.equal(userOperation.estimationOnly, true);
    assert.equal(userOperation.submissionReady, false);
    assert.equal(userOperation.realProofGenerated, false);
    assert.equal(userOperation.realAuthorizationGenerated, false);
    assert.equal(userOperation.realApprovalGenerated, false);
    assert.equal(userOperation.freshPresenceRecorded, false);
    assert.equal(userOperation.deviceVaultSignatureGenerated, false);
    assert.equal(userOperation.accountFunded, false);
    assert.equal(userOperation.userOperationSubmitted, false);
  });

  it("rejects bundler response mutation, paymaster fields, and gas above hard ceilings", function () {
    const valid = {
      verificationGasLimit: "0xdbba0",
      callGasLimit: "0x186a0",
      preVerificationGas: "0x186a0"
    };
    assert.equal(
      validateBundlerEstimateResponse(valid).verificationGasLimit,
      900000n
    );
    for (const [mutation, pattern] of [
      [{ ...valid, sender: EXPECTED_TARGET }, /attempted_userop_replacement/],
      [{ ...valid, factory: EXPECTED_TARGET }, /attempted_userop_replacement/],
      [{ ...valid, factoryData: "0x01" }, /attempted_userop_replacement/],
      [{ ...valid, callData: "0x01" }, /attempted_userop_replacement/],
      [{ ...valid, signature: "0x01" }, /attempted_userop_replacement/],
      [{ ...valid, paymasterVerificationGasLimit: "1" }, /introduced_paymaster/],
      [{
        ...valid,
        verificationGasLimit:
          (LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxVerificationGasLimit + 1n).toString()
      }, /verification_gas_hard_ceiling/],
      [{
        ...valid,
        callGasLimit:
          (LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxCallGasLimit + 1n).toString()
      }, /call_gas_hard_ceiling/],
      [{
        ...valid,
        preVerificationGas:
          (LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxPreVerificationGas + 1n).toString()
      }, /preverification_gas_hard_ceiling/]
    ]) {
      assert.throws(() => validateBundlerEstimateResponse(mutation), pattern);
    }
  });

  it("reconciles local and fixture bundler estimates with bounded margins", function () {
    const local = {
      approximateFirstOperationCreationGasComponent: "690770",
      validationGasEstimate: "19880",
      executionGasEstimate: "50694"
    };
    const blocked = reconcileGasEstimates(local, null);
    assert.equal(blocked.status, "BUNDLER_CONFIGURATION_REQUIRED");
    assert.equal(blocked.selected.verificationGasLimit, "1500000");
    assert.equal(blocked.selected.callGasLimit, "300000");
    assert.equal(blocked.selected.preVerificationGas, "200000");
    const reconciled = reconcileGasEstimates(local, {
      verificationGasLimit: "800000",
      callGasLimit: "60000",
      preVerificationGas: "100000"
    });
    assert.equal(reconciled.status, "RECONCILED");
    assert.equal(reconciled.selected.verificationGasLimit, "960000");
    assert.equal(reconciled.selected.callGasLimit, "72000");
    assert.equal(reconciled.selected.preVerificationGas, "120000");
  });

  it("reproduces the no-paymaster prefund and residual-risk model", function () {
    const result = calculatePrefundEvidence({
      selectedGas: {
        verificationGasLimit: "1500000",
        callGasLimit: "300000",
        preVerificationGas: "200000",
        paymasterVerificationGasLimit: "0",
        paymasterPostOpGasLimit: "0"
      },
      currentMaxFeePerGasWei: "2000000000",
      recommendedMaxFeePerGasWei: "2500000000",
      localActualGasUsed: "1000000",
      observedGasPriceWei: "1000000000"
    });
    assert.equal(result.estimatedMinimumPrefundWei, "4000000000000000");
    assert.equal(result.recommendedDisposableTestPrefundWei, "5000000000000000");
    assert.equal(result.proposedMaximumFundingApprovalWei, "5000000000000000");
    assert.equal(result.absoluteRejectionCeilingExposureWei, "200000000000000000");
    assert.equal(result.expectedResidualAfterSuccessWei, "4000000000000000");
    assert.equal(
      result.residualRiskClassification,
      "RESIDUAL_FUNDS_NONRECOVERABLE_BY_CURRENT_ACCOUNT"
    );
  });

  it("records current provisional gas, fee, prefund, and stranded-fund evidence", function () {
    assert.equal(estimate.status, "BUNDLER_CONFIGURATION_REQUIRED");
    assert.equal(estimate.counterfactualAccount.unchanged, true);
    assert.equal(estimate.counterfactualAccount.code, "0x");
    assert.equal(estimate.counterfactualAccount.balance.wei, "0");
    assert.equal(estimate.counterfactualAccount.deposit.wei, "0");
    assert.equal(estimate.counterfactualAccount.entryPointNonce, "0");
    assert.equal(estimate.bundlerEstimate.performed, false);
    assert.equal(estimate.reconciliation.selected.totalDeclaredGas, "2000000");
    assert.equal(prefund.status, "BLOCKED_PENDING_BUNDLER_CONFIGURATION");
    assert.equal(prefund.approved, false);
    assert.equal(prefund.signed, false);
    assert.equal(prefund.broadcast, false);
    assert.equal(
      prefund.fundingMechanism.residualRiskClassification,
      "RESIDUAL_FUNDS_NONRECOVERABLE_BY_CURRENT_ACCOUNT"
    );
    assert.equal(prefund.fundingMechanism.generalWithdrawalAvailable, false);
    assert.equal(
      prefund.fundingMechanism.entryPointDepositWithdrawalAvailableThroughAccount,
      false
    );
  });

  it("exposes no bundler send method and performs no signing or public mutation", async function () {
    const called = [];
    const client = createRestrictedSepoliaBundlerClient({
      url: "https://bundler.example.test/hidden",
      transport: {
        async request(method) {
          called.push(method);
          return method === "eth_chainId" ? "0xaa36a7" : [];
        }
      }
    });
    await client.request("eth_chainId", []);
    await client.request("eth_supportedEntryPoints", []);
    await assert.rejects(
      client.request("eth_sendUserOperation", []),
      /BUNDLER_METHOD_NOT_ALLOWED/
    );
    assert.deepEqual(called, ["eth_chainId", "eth_supportedEntryPoints"]);

    const generator = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/generate-o26-readiness.cjs"
    ), "utf8");
    assert.doesNotMatch(
      generator,
      /\.request\(\s*["']eth_sendUserOperation|eth_sendTransaction|eth_sendRawTransaction/
    );
    assert.doesNotMatch(generator, /signTransaction|sendTransaction\(|broadcastTransaction/);
    assert.equal(estimate.accounts.account1.signingUsed, false);
    assert.equal(estimate.accounts.account2.signingUsed, false);
    assert.equal(estimate.authority.deviceVaultUsed, false);
    assert.equal(estimate.authority.signatureGenerated, false);
    assert.equal(estimate.authority.userOperationSubmitted, false);
    assert.equal(estimate.authority.publicMutationOccurred, false);
    assert.equal(prefund.ethTransferred, false);
    assert.equal(prefund.accountDeployed, false);
    assert.equal(prefund.publicMutationOccurred, false);
  });

  it("keeps every committed O.26 artifact free of protected material", function () {
    for (const artifact of [compatibility, estimate, prefund]) ensureNoSecrets(artifact);
    const combined = [
      O26_COMPATIBILITY_PATH,
      O26_ESTIMATE_PATH,
      O26_PREFUND_PATH
    ].map((file) => fs.readFileSync(file, "utf8")).join("\n");
    assert.doesNotMatch(
      combined,
      /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey/i
    );
    assert.doesNotMatch(combined, /apikey=[^<{\s"]+/i);
  });
});
