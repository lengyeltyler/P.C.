require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET
} = require("../../scripts/ethereum-sepolia/o24-factory-common.cjs");
const {
  ROOT,
  ensureNoSecrets,
  readJson
} = require("../../scripts/ethereum-sepolia/o23r-common.cjs");
const {
  O26_1_COMPATIBILITY_PATH,
  O26_1_ESTIMATE_PATH,
  O26_1_PREFUND_PATH,
  buildO261Prefund,
  classifyEstimationResult,
  classifyProviderEndpoint,
  createO261LogicalClients,
  reconcileO261Gas,
  sanitizeBundlerError,
  validateO261EndpointConfiguration
} = require("../../scripts/ethereum-sepolia/o26-1-live-bundler-common.cjs");
const {
  validateO26EstimationOnlyUserOperation
} = require("../../scripts/ethereum-sepolia/o26-bundler-readiness-common.cjs");

describe("O.26.1 live Alchemy bundler estimation", function () {
  const compatibility = readJson(O26_1_COMPATIBILITY_PATH);
  const estimate = readJson(O26_1_ESTIMATE_PATH);
  const prefund = readJson(O26_1_PREFUND_PATH);

  it("allows an explicitly classified Alchemy shared endpoint without exposing it", function () {
    const endpoint = "https://eth-sepolia.g.alchemy.com/v2/test-fixture-key";
    const classification = classifyProviderEndpoint(endpoint);
    assert.equal(classification.provider, "alchemy");
    assert.equal(classification.sharedEndpointSupported, true);
    assert.equal(classification.logicalClientSeparationRequired, true);
    assert.equal(
      classification.endpointClassification,
      "https://eth-sepolia.g.alchemy.com/<redacted>"
    );
    assert.doesNotMatch(JSON.stringify(classification), /test-fixture-key/);
    const config = validateO261EndpointConfiguration({
      rpcUrl: endpoint,
      bundlerUrl: endpoint
    });
    assert.equal(config.sharedEndpoint, true);
    assert.equal(config.sharedEndpointSupported, true);
    assert.equal(config.chainRpcBindingSha256, config.bundlerBindingSha256);
  });

  it("rejects missing, placeholder, malformed, insecure, and unclassified shared endpoints", function () {
    assert.throws(
      () => classifyProviderEndpoint(""),
      /BUNDLER_URL_MISSING/
    );
    assert.throws(
      () => classifyProviderEndpoint("https://example.com/v2/PLACEHOLDER"),
      /BUNDLER_URL_PLACEHOLDER/
    );
    assert.throws(
      () => classifyProviderEndpoint("not a URL"),
      /BUNDLER_URL_MALFORMED/
    );
    assert.throws(
      () => classifyProviderEndpoint("http://eth-sepolia.g.alchemy.com/v2/key"),
      /SCHEME_UNSUPPORTED/
    );
    assert.throws(
      () => validateO261EndpointConfiguration({
        rpcUrl: "https://bundler.vendor.test/v2/key",
        bundlerUrl: "https://bundler.vendor.test/v2/key"
      }),
      /SHARED_ENDPOINT_PROVIDER_UNSUPPORTED/
    );
  });

  it("constructs separate explicit clients with independent fail-closed allowlists", async function () {
    const endpoint = "https://eth-sepolia.g.alchemy.com/v2/test-fixture-key";
    const chainCalls = [];
    const bundlerCalls = [];
    const clients = createO261LogicalClients({
      rpcUrl: endpoint,
      bundlerUrl: endpoint,
      chainTransport: {
        async request(method) {
          chainCalls.push(method);
          return method === "eth_chainId" ? "0xaa36a7" : "0x";
        }
      },
      bundlerTransport: {
        async request(method) {
          bundlerCalls.push(method);
          if (method === "eth_chainId") return "0xaa36a7";
          if (method === "eth_supportedEntryPoints") {
            return [ERC4337_V07_CANONICAL_ENTRYPOINT];
          }
          return null;
        }
      }
    });
    assert.equal(clients.distinctClientInstances, true);
    assert.equal(clients.genericRequestExposed, false);
    assert.equal(clients.submissionMethodExposed, false);
    assert.equal("request" in clients.chain, false);
    assert.equal("request" in clients.bundler, false);
    assert.equal("sendUserOperation" in clients.bundler, false);
    assert.equal("sendTransaction" in clients.chain, false);
    await clients.chain.getChainId();
    await assert.rejects(
      clients.bundler.getSupportedEntryPoints(),
      /CHAIN_ID_MUST_BE_VERIFIED_FIRST/
    );
    await clients.bundler.getChainId();
    await clients.bundler.getSupportedEntryPoints();
    assert.deepEqual(chainCalls, ["eth_chainId"]);
    assert.deepEqual(bundlerCalls, ["eth_chainId", "eth_supportedEntryPoints"]);
  });

  it("fails closed when the Bundler API reports another chain", async function () {
    const endpoint = "https://eth-sepolia.g.alchemy.com/v2/test-fixture-key";
    const clients = createO261LogicalClients({
      rpcUrl: endpoint,
      bundlerUrl: endpoint,
      chainTransport: { async request() { return "0xaa36a7"; } },
      bundlerTransport: { async request() { return "0x1"; } }
    });
    await assert.rejects(clients.bundler.getChainId(), /BUNDLER_WRONG_CHAIN/);
  });

  it("records authenticated Sepolia and canonical EntryPoint v0.7 support", function () {
    assert.equal(compatibility.status, "BUNDLER_ESTIMATION_SUCCEEDED");
    assert.equal(compatibility.provider.name, "alchemy");
    assert.equal(compatibility.provider.authenticationPassed, true);
    assert.equal(compatibility.provider.sharedEndpoint, true);
    assert.equal(compatibility.provider.sharedEndpointSupported, true);
    assert.equal(compatibility.network.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(compatibility.network.chainRpcVerified, true);
    assert.equal(compatibility.network.bundlerChainVerified, true);
    assert.ok(
      compatibility.supportedEntryPoints.includes(
        ERC4337_V07_CANONICAL_ENTRYPOINT
      )
    );
    assert.equal(compatibility.canonicalEntryPointV07Supported, true);
    for (const method of [
      "eth_supportedEntryPoints",
      "eth_estimateUserOperationGas",
      "eth_getUserOperationByHash",
      "eth_getUserOperationReceipt"
    ]) {
      assert.equal(compatibility.methodChecks[method].status, "supported");
    }
    assert.equal(compatibility.paymasterRequired, false);
  });

  it("uses a decoder-correct, cryptographically invalid 288-byte envelope", function () {
    const userOperation = estimate.estimationOnlyUserOperation;
    assert.equal(validateO26EstimationOnlyUserOperation(userOperation), true);
    assert.equal(estimate.estimationEnvelope.lengthBytes, 288);
    assert.equal(estimate.estimationEnvelope.decoderCorrect, true);
    assert.equal(estimate.estimationEnvelope.cryptographicallyValid, false);
    assert.equal(estimate.estimationEnvelope.submissionAuthority, false);
    assert.equal(estimate.estimationEnvelope.localInvalidityVerified, true);
    assert.equal(userOperation.estimationOnly, true);
    assert.equal(userOperation.submissionReady, false);
    assert.equal(userOperation.realProofGenerated, false);
    assert.equal(userOperation.deviceVaultSignatureGenerated, false);
  });

  it("binds the exact request and proves no client or provider mutation", function () {
    assert.equal(estimate.request.method, "eth_estimateUserOperationGas");
    assert.match(estimate.request.digest, /^0x[0-9a-f]{64}$/);
    assert.equal(
      estimate.request.objectDigestBefore,
      estimate.request.objectDigestAfter
    );
    assert.equal(estimate.request.mutated, false);
    assert.equal(estimate.request.sentOnce, true);
    assert.equal(estimate.request.retryPerformed, false);
    assert.equal(estimate.estimationOnlyUserOperation.sender, EXPECTED_ACCOUNT);
    assert.equal(estimate.estimationOnlyUserOperation.factory, EXPECTED_FACTORY);
    assert.equal(estimate.estimationOnlyUserOperation.target, EXPECTED_TARGET);
  });

  it("classifies sanitized errors without retaining endpoint credentials", function () {
    const error = Object.assign(
      new Error("AA24 signature error at https://host.test/v2/secret"),
      { code: -32500, requestId: 7 }
    );
    const sanitized = sanitizeBundlerError(error);
    assert.equal(sanitized.code, -32500);
    assert.equal(sanitized.aaCode, "AA24");
    assert.equal(sanitized.requestId, 7);
    assert.doesNotMatch(sanitized.message, /secret/);
    assert.equal(
      classifyEstimationResult({ response: null, error: sanitized }),
      "BUNDLER_REQUIRES_REAL_SIGNATURE_FOR_ESTIMATION"
    );
    assert.equal(
      classifyEstimationResult({
        response: null,
        error: { message: "AA13 initCode failed" }
      }),
      "BUNDLER_FACTORY_DATA_REJECTED"
    );
  });

  it("reconciles the exact Alchemy response without silently tightening or raising ceilings", function () {
    const result = reconcileO261Gas({
      local: {
        approximateFirstOperationCreationGasComponent: "690770",
        validationGasEstimate: "19850",
        executionGasEstimate: "50694",
        declaredPreVerificationGas: "200000",
        actualGasUsed: "1034770",
        handleOpsEstimate: "1059768"
      },
      remote: {
        verificationGasLimit: "0x16e360",
        callGasLimit: "0x493e0",
        preVerificationGas: "0x30d40"
      }
    });
    assert.equal(result.status, "RECONCILED_WITHOUT_TIGHTENING");
    assert.equal(result.selected.verificationGasLimit, "1500000");
    assert.equal(result.selected.callGasLimit, "300000");
    assert.equal(result.selected.preVerificationGas, "200000");
    assert.equal(result.selected.totalDeclaredGas, "2000000");
    assert.equal(result.remoteVsLocalActualDifference, "965230");
  });

  it("recalculates exact no-paymaster prefund and preserves residual risk", function () {
    const result = buildO261Prefund({
      selectedGas: {
        verificationGasLimit: "1500000",
        callGasLimit: "300000",
        preVerificationGas: "200000",
        paymasterVerificationGasLimit: "0",
        paymasterPostOpGasLimit: "0"
      },
      currentMaxFeePerGasWei: "2000000000",
      recommendedMaxFeePerGasWei: "2500000000",
      hardMaxFeePerGasWei: "100000000000",
      localActualGasUsed: "1000000",
      observedGasPriceWei: "1000000000"
    });
    assert.equal(result.estimatedMinimum.wei, "4000000000000000");
    assert.equal(result.recommendedDisposableTestPrefund.wei, "5000000000000000");
    assert.equal(result.proposedMaximumFundingApproval.wei, "5000000000000000");
    assert.equal(result.expectedResidualAfterSuccess.wei, "4000000000000000");
    assert.equal(
      result.residualFundClassification,
      "RESIDUAL_FUNDS_NONRECOVERABLE_BY_CURRENT_ACCOUNT"
    );
  });

  it("creates only a short-lived, unsigned, unbroadcast Account 2 proposal", function () {
    const proposal = prefund.fundingProposal;
    assert.equal(prefund.status, "FUNDING_READY_FOR_SEPARATE_APPROVAL");
    assert.equal(proposal.sender, "0xaDef2F2fdA57e92b593943f367D37d8Ce6B2F598");
    assert.equal(proposal.recipient, EXPECTED_ACCOUNT);
    assert.equal(proposal.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(proposal.nonce, "0");
    assert.equal(proposal.gasLimit, "21000");
    assert.equal(proposal.calldata, "0x");
    assert.equal(proposal.approved, false);
    assert.equal(proposal.signed, false);
    assert.equal(proposal.broadcast, false);
    assert.equal(proposal.publicMutationOccurred, false);
    assert.equal(proposal.value.wei, prefund.prefund.recommendedDisposableTestPrefund.wei);
  });

  it("contains no signing, submission, transfer, proof, or public mutation path", function () {
    const generator = fs.readFileSync(path.join(
      ROOT,
      "scripts/ethereum-sepolia/generate-o26-1-live-bundler-readiness.cjs"
    ), "utf8");
    assert.doesNotMatch(
      generator,
      /\.request\(\s*["']eth_sendUserOperation|eth_sendTransaction|eth_sendRawTransaction/
    );
    assert.doesNotMatch(generator, /signTransaction|sendTransaction\(|broadcastTransaction/);
    assert.equal(compatibility.clientIsolation.submissionMethodExposed, false);
    assert.equal(compatibility.submissionMethodCalled, false);
    assert.equal(estimate.accounts.account1.signingUsed, false);
    assert.equal(estimate.accounts.account2.signingUsed, false);
    assert.equal(estimate.authority.realProofGenerated, false);
    assert.equal(estimate.authority.deviceVaultSignatureGenerated, false);
    assert.equal(estimate.authority.userOperationSubmitted, false);
    assert.equal(prefund.ethTransferred, false);
    assert.equal(prefund.accountDeployed, false);
    assert.equal(prefund.publicMutationOccurred, false);
  });

  it("keeps live evidence sanitized and free of protected material", function () {
    for (const artifact of [compatibility, estimate, prefund]) ensureNoSecrets(artifact);
    const combined = [
      O26_1_COMPATIBILITY_PATH,
      O26_1_ESTIMATE_PATH,
      O26_1_PREFUND_PATH
    ].map((file) => fs.readFileSync(file, "utf8")).join("\n");
    assert.doesNotMatch(
      combined,
      /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey/i
    );
    assert.doesNotMatch(combined, /\/v2\/[A-Za-z0-9_-]{20,}/);
  });
});
