require("tsx/cjs");

const crypto = require("node:crypto");
const path = require("node:path");
const { getAddress } = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  createRestrictedSepoliaBundlerClient,
  createRestrictedSepoliaReadOnlyClient
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const { ROOT } = require("./o23r-common.cjs");
const {
  amount,
  buildFundingProposal,
  calculateNoPaymasterRequiredPrefund,
  canonicalDigest
} = require("./o25-readiness-common.cjs");
const {
  validateBundlerEstimateResponse,
  validateO26EstimationOnlyUserOperation
} = require("./o26-bundler-readiness-common.cjs");

const O26_1_COMPATIBILITY_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_1_LIVE_BUNDLER_COMPATIBILITY_REPORT.json"
);
const O26_1_ESTIMATE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_1_REMOTE_USEROP_GAS_ESTIMATE.json"
);
const O26_1_PREFUND_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_1_REFRESHED_PREFUND_PROPOSAL.json"
);

const REQUIRED_BUNDLER_METHODS = Object.freeze([
  "eth_supportedEntryPoints",
  "eth_estimateUserOperationGas",
  "eth_getUserOperationByHash",
  "eth_getUserOperationReceipt"
]);

function endpointHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function classifyProviderEndpoint(rawUrl) {
  const value = String(rawUrl ?? "").trim();
  if (!value) throw new Error("BUNDLER_URL_MISSING");
  if (/YOUR_|PLACEHOLDER|example\.com|<[^>]+>/i.test(value)) {
    throw new Error("BUNDLER_URL_PLACEHOLDER");
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("BUNDLER_URL_MALFORMED");
  }
  if (parsed.protocol !== "https:") throw new Error("BUNDLER_URL_SCHEME_UNSUPPORTED");
  const hostname = parsed.hostname.toLowerCase();
  const isAlchemy = hostname === "alchemy.com" || hostname.endsWith(".alchemy.com");
  const hasAlchemyV2Path = /^\/v2\/[^/]+\/?$/.test(parsed.pathname);
  const provider = isAlchemy && hasAlchemyV2Path ? "alchemy" : "unclassified";
  return Object.freeze({
    provider,
    sharedEndpointSupported: provider === "alchemy",
    logicalClientSeparationRequired: true,
    endpointClassification:
      `${parsed.protocol}//${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}/<redacted>`,
    endpointBindingSha256: endpointHash(value)
  });
}

function validateO261EndpointConfiguration(input) {
  const rpcUrl = String(input.rpcUrl ?? "").trim();
  const bundlerUrl = String(input.bundlerUrl ?? "").trim();
  if (!rpcUrl) throw new Error("CHAIN_RPC_URL_MISSING");
  const bundler = classifyProviderEndpoint(bundlerUrl);
  const sharedEndpoint = endpointHash(rpcUrl) === endpointHash(bundlerUrl);
  if (sharedEndpoint && !bundler.sharedEndpointSupported) {
    throw new Error("SHARED_ENDPOINT_PROVIDER_UNSUPPORTED");
  }
  return Object.freeze({
    provider: bundler.provider,
    sharedEndpoint,
    sharedEndpointSupported: sharedEndpoint && bundler.sharedEndpointSupported,
    logicalClientSeparationRequired: true,
    chainRpcBindingSha256: endpointHash(rpcUrl),
    bundlerBindingSha256: bundler.endpointBindingSha256,
    endpointClassification: bundler.endpointClassification,
    completeEndpointRecorded: false
  });
}

function createO261LogicalClients(input) {
  const configuration = validateO261EndpointConfiguration(input);
  const chainInternal = createRestrictedSepoliaReadOnlyClient({
    url: input.rpcUrl,
    transport: input.chainTransport
  });
  const bundlerInternal = createRestrictedSepoliaBundlerClient({
    url: input.bundlerUrl,
    transport: input.bundlerTransport
  });
  let bundlerChainVerified = false;

  const chain = Object.freeze({
    auditClassification: "ethereum_sepolia_chain_read_only",
    endpointClassification: chainInternal.endpointClassification,
    mutationMethodsExposed: false,
    async getChainId() {
      return chainInternal.request("eth_chainId", []);
    },
    async getCode(address, block = "latest") {
      return chainInternal.request("eth_getCode", [address, block]);
    },
    async getBalance(address, block = "latest") {
      return chainInternal.request("eth_getBalance", [address, block]);
    },
    async getTransactionCount(address, block = "latest") {
      return chainInternal.request("eth_getTransactionCount", [address, block]);
    }
  });

  async function requireBundlerChain() {
    if (!bundlerChainVerified) throw new Error("BUNDLER_CHAIN_ID_MUST_BE_VERIFIED_FIRST");
  }

  const bundler = Object.freeze({
    auditClassification: "alchemy_erc4337_bundler_read_only_estimation",
    endpointClassification: bundlerInternal.endpointClassification,
    mutationMethodsExposed: false,
    async getChainId() {
      const result = await bundlerInternal.request("eth_chainId", []);
      if (Number(BigInt(String(result))) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
        throw new Error("BUNDLER_WRONG_CHAIN");
      }
      bundlerChainVerified = true;
      return result;
    },
    async getSupportedEntryPoints() {
      await requireBundlerChain();
      return bundlerInternal.request("eth_supportedEntryPoints", []);
    },
    async estimateUserOperationGas(userOperation, entryPoint) {
      await requireBundlerChain();
      return bundlerInternal.request("eth_estimateUserOperationGas", [
        userOperation,
        entryPoint
      ]);
    },
    async getUserOperationByHash(userOperationHash) {
      await requireBundlerChain();
      return bundlerInternal.request("eth_getUserOperationByHash", [
        userOperationHash
      ]);
    },
    async getUserOperationReceipt(userOperationHash) {
      await requireBundlerChain();
      return bundlerInternal.request("eth_getUserOperationReceipt", [
        userOperationHash
      ]);
    }
  });

  return Object.freeze({
    configuration,
    chain,
    bundler,
    distinctClientInstances: chain !== bundler,
    genericRequestExposed: false,
    submissionMethodExposed: false
  });
}

function sanitizeBundlerError(error) {
  const rawMessage = error instanceof Error ? error.message : String(error);
  const message = rawMessage
    .replace(/https?:\/\/[^\s"']+/gi, "<redacted-endpoint>")
    .replace(/[A-Za-z0-9_-]{24,}/g, "<redacted>");
  const dataText = error && typeof error === "object" && "data" in error
    ? JSON.stringify(error.data)
    : "";
  const aaMatch = `${rawMessage} ${dataText}`.match(/\bAA\d{2}\b/);
  return Object.freeze({
    name: error instanceof Error ? error.name : "Error",
    code:
      error && typeof error === "object" && "code" in error
        ? error.code ?? null
        : null,
    message,
    aaCode: aaMatch?.[0] ?? null,
    requestId:
      error && typeof error === "object" && "requestId" in error
        ? error.requestId ?? null
        : null,
    credentialsExposed: false
  });
}

function classifyEstimationResult(input) {
  if (input.response) {
    validateBundlerEstimateResponse(input.response);
    return "BUNDLER_ESTIMATION_SUCCEEDED";
  }
  const error = input.error ?? {};
  const text = `${error.message ?? ""} ${error.aaCode ?? ""}`;
  if (/signature|AA24/i.test(text)) {
    return input.partialGas
      ? "BUNDLER_ESTIMATION_PARTIAL_SIGNATURE_REJECTION"
      : "BUNDLER_REQUIRES_REAL_SIGNATURE_FOR_ESTIMATION";
  }
  if (/factory|initCode|AA1[0-9]/i.test(text)) return "BUNDLER_FACTORY_DATA_REJECTED";
  if (/validation|AA2[0-9]|AA3[0-9]/i.test(text)) {
    return "BUNDLER_ACCOUNT_VALIDATION_INCOMPATIBLE";
  }
  return "BUNDLER_RESPONSE_INCONCLUSIVE";
}

function percentageDifference(remote, local) {
  const remoteValue = BigInt(remote);
  const localValue = BigInt(local);
  if (localValue === 0n) return null;
  const basisPoints =
    (remoteValue > localValue ? remoteValue - localValue : localValue - remoteValue)
    * 1_000_000n
    / localValue;
  return Number(basisPoints) / 10_000;
}

function reconcileO261Gas(input) {
  const remote = validateBundlerEstimateResponse(input.remote);
  const localVerificationBasis =
    BigInt(input.local.approximateFirstOperationCreationGasComponent)
    + BigInt(input.local.validationGasEstimate);
  const localCall = BigInt(input.local.executionGasEstimate);
  const localPreVerification = BigInt(input.local.declaredPreVerificationGas);
  const remoteTotal =
    remote.verificationGasLimit + remote.callGasLimit + remote.preVerificationGas;
  const components = {
    verificationGasLimit: {
      localBasis: localVerificationBasis.toString(),
      remote: remote.verificationGasLimit.toString(),
      absoluteDifference: (
        remote.verificationGasLimit > localVerificationBasis
          ? remote.verificationGasLimit - localVerificationBasis
          : localVerificationBasis - remote.verificationGasLimit
      ).toString(),
      percentageDifference: percentageDifference(
        remote.verificationGasLimit,
        localVerificationBasis
      ),
      selected: remote.verificationGasLimit.toString(),
      marginOverLocalBasis: (
        remote.verificationGasLimit - localVerificationBasis
      ).toString(),
      justification:
        "Alchemy returned the existing reviewed ceiling; no tighter remote value was established."
    },
    callGasLimit: {
      localBasis: localCall.toString(),
      remote: remote.callGasLimit.toString(),
      absoluteDifference: (remote.callGasLimit - localCall).toString(),
      percentageDifference: percentageDifference(remote.callGasLimit, localCall),
      selected: remote.callGasLimit.toString(),
      marginOverLocalBasis: (remote.callGasLimit - localCall).toString(),
      justification:
        "Alchemy returned the existing reviewed ceiling; no tighter remote value was established."
    },
    preVerificationGas: {
      localBasis: localPreVerification.toString(),
      remote: remote.preVerificationGas.toString(),
      absoluteDifference: (
        remote.preVerificationGas > localPreVerification
          ? remote.preVerificationGas - localPreVerification
          : localPreVerification - remote.preVerificationGas
      ).toString(),
      percentageDifference: percentageDifference(
        remote.preVerificationGas,
        localPreVerification
      ),
      selected: remote.preVerificationGas.toString(),
      marginOverLocalBasis: (
        remote.preVerificationGas - localPreVerification
      ).toString(),
      justification: "Local declared and Alchemy returned values match."
    }
  };
  return Object.freeze({
    status: "RECONCILED_WITHOUT_TIGHTENING",
    components: Object.freeze(components),
    selected: Object.freeze({
      verificationGasLimit: remote.verificationGasLimit.toString(),
      callGasLimit: remote.callGasLimit.toString(),
      preVerificationGas: remote.preVerificationGas.toString(),
      paymasterVerificationGasLimit: "0",
      paymasterPostOpGasLimit: "0",
      totalDeclaredGas: remoteTotal.toString()
    }),
    localActualGasUsed: String(input.local.actualGasUsed),
    localHandleOpsEstimate: String(input.local.handleOpsEstimate),
    remoteTotalDeclaredGas: remoteTotal.toString(),
    remoteVsLocalActualDifference: (
      remoteTotal - BigInt(input.local.actualGasUsed)
    ).toString(),
    remoteVsLocalActualPercentage: percentageDifference(
      remoteTotal,
      input.local.actualGasUsed
    )
  });
}

function buildO261Prefund(input) {
  const gas = input.selectedGas;
  const current = calculateNoPaymasterRequiredPrefund({
    ...gas,
    maxFeePerGas: input.currentMaxFeePerGasWei
  });
  const recommended = calculateNoPaymasterRequiredPrefund({
    ...gas,
    maxFeePerGas: input.recommendedMaxFeePerGasWei
  });
  const hard = calculateNoPaymasterRequiredPrefund({
    ...gas,
    maxFeePerGas: input.hardMaxFeePerGasWei
  });
  const expectedActualCost =
    BigInt(input.localActualGasUsed) * BigInt(input.observedGasPriceWei);
  const recommendedValue = BigInt(recommended.requiredPrefundWei);
  return Object.freeze({
    formula: recommended.formula,
    estimatedMinimum: amount(current.requiredPrefundWei),
    recommendedDisposableTestPrefund: amount(recommended.requiredPrefundWei),
    proposedMaximumFundingApproval: amount(recommended.requiredPrefundWei),
    expectedActualCost: amount(expectedActualCost),
    expectedResidualAfterSuccess: amount(
      recommendedValue > expectedActualCost
        ? recommendedValue - expectedActualCost
        : 0n
    ),
    absoluteRejectionCeilingExposure: amount(hard.requiredPrefundWei),
    residualFundClassification:
      "RESIDUAL_FUNDS_NONRECOVERABLE_BY_CURRENT_ACCOUNT"
  });
}

function buildO261FundingProposal(input) {
  const base = buildFundingProposal(input);
  const proposal = {
    ...base,
    schemaVersion: "philcore-o26-1-account2-funding-proposal-v1",
    phase: "O.26.1",
    status: "proposed_pending_separate_approval",
    providerBinding: input.providerBinding,
    gasEstimateBinding: input.gasEstimateBinding,
    infrastructureBinding: input.infrastructureBinding,
    fundingReadiness: "FUNDING_READY_FOR_SEPARATE_APPROVAL",
    approved: false,
    signed: false,
    broadcast: false,
    publicMutationOccurred: false
  };
  delete proposal.proposalDigest;
  proposal.proposalDigest = canonicalDigest(proposal);
  return Object.freeze(proposal);
}

function requestDigest(userOperation) {
  validateO26EstimationOnlyUserOperation(userOperation);
  return canonicalDigest({
    method: "eth_estimateUserOperationGas",
    params: [
      userOperation.rpcV07Representation,
      ERC4337_V07_CANONICAL_ENTRYPOINT
    ]
  });
}

module.exports = {
  O26_1_COMPATIBILITY_PATH,
  O26_1_ESTIMATE_PATH,
  O26_1_PREFUND_PATH,
  REQUIRED_BUNDLER_METHODS,
  buildO261FundingProposal,
  buildO261Prefund,
  classifyEstimationResult,
  classifyProviderEndpoint,
  createO261LogicalClients,
  reconcileO261Gas,
  requestDigest,
  sanitizeBundlerError,
  validateO261EndpointConfiguration
};
