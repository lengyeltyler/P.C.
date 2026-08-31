require("tsx/cjs");

const crypto = require("node:crypto");
const path = require("node:path");
const {
  AbiCoder,
  getAddress,
  isHexString,
  keccak256,
  toBeHex,
  zeroPadValue
} = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  LOCAL_PROOF_GATED_PREPARATION_LIMITS,
  deriveLocalProofGatedValidatorKeyIdBinding,
  redactRpcEndpoint
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET
} = require("./o24-factory-common.cjs");
const {
  ESTIMATION_ACTION_ID,
  ESTIMATION_AUTHORIZATION_DIGEST,
  ROOT,
  buildEstimationOnlyUserOperation,
  calculateNoPaymasterRequiredPrefund,
  canonicalDigest
} = (() => {
  const o23r = require("./o23r-common.cjs");
  const o25 = require("./o25-readiness-common.cjs");
  return {
    ...o25,
    ROOT: o23r.ROOT
  };
})();

const abiCoder = AbiCoder.defaultAbiCoder();
const SECURITY_MODEL_ID = keccak256(Buffer.from("local-proof-gated-v1"));
const SIGNATURE_ENVELOPE_LENGTH = 9 * 32;
const GAS_MARGIN_BASIS_POINTS = 2_000n;

const O26_COMPATIBILITY_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_BUNDLER_COMPATIBILITY_REPORT.json"
);
const O26_ESTIMATE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_FIRST_USEROP_GAS_ESTIMATE.json"
);
const O26_PREFUND_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O26_REFRESHED_PREFUND_PROPOSAL.json"
);

const BUNDLER_PROVIDER_COMPARISON = Object.freeze([
  Object.freeze({
    provider: "Pimlico",
    recommendation: "recommended",
    sepoliaSupported: true,
    entryPointV07Supported: true,
    endpointFormat:
      "public: https://public.pimlico.io/v2/{CHAIN_ID}/rpc; authenticated endpoint requires an externally managed API key",
    methods: [
      "eth_supportedEntryPoints",
      "eth_estimateUserOperationGas",
      "eth_sendUserOperation",
      "eth_getUserOperationByHash",
      "eth_getUserOperationReceipt"
    ],
    paymasterRequired: false,
    customAccountCompatibility:
      "standard ERC-4337 account; the account must supply its own structurally valid dummy signature",
    testAllowance:
      "public endpoint available without an API key; 20 requests per minute per IP",
    requestLimits: "public endpoint: 20 requests per minute per IP",
    setupBurden: "low for an explicitly configured public test endpoint",
    risks: [
      "shared public endpoint has strict rate limits",
      "provider simulation remains advisory",
      "custom PhilCore envelope compatibility must be verified remotely"
    ],
    officialSources: [
      "https://docs.pimlico.io/references/bundler/public-endpoint",
      "https://docs.pimlico.io/references/bundler/endpoints/eth_estimateUserOperationGas"
    ]
  }),
  Object.freeze({
    provider: "Alchemy",
    recommendation: "fallback",
    sepoliaSupported: true,
    entryPointV07Supported: true,
    endpointFormat: "Alchemy Bundler endpoint with an externally managed API key",
    methods: [
      "eth_supportedEntryPoints",
      "eth_estimateUserOperationGas",
      "eth_sendUserOperation",
      "eth_getUserOperationByHash",
      "eth_getUserOperationReceipt"
    ],
    paymasterRequired: false,
    customAccountCompatibility:
      "v0.7 PackedUserOperation accounts are supported; account-specific dummy signature required",
    testAllowance: "plan-dependent; not assumed by PhilCore",
    requestLimits: "plan-dependent; verify in the selected Alchemy account",
    setupBurden: "moderate; requires explicit bundler endpoint configuration",
    risks: [
      "credential-bearing URL must remain outside the repository",
      "fee and rate limits depend on the selected plan",
      "custom PhilCore envelope compatibility must be verified remotely"
    ],
    officialSources: [
      "https://www.alchemy.com/docs/wallets/supported-chains",
      "https://www.alchemy.com/docs/wallets/transactions/low-level-infra/bundler/overview",
      "https://www.alchemy.com/docs/wallets/reference/bundler-faqs"
    ]
  }),
  Object.freeze({
    provider: "Candide",
    recommendation: "alternative",
    sepoliaSupported: true,
    entryPointV07Supported: true,
    endpointFormat:
      "public: https://api.candide.dev/public/v3/{CHAIN_ID}; authenticated: https://api.candide.dev/api/v3/{CHAIN_ID}/{API_KEY}",
    methods: [
      "eth_supportedEntryPoints",
      "eth_estimateUserOperationGas",
      "eth_sendUserOperation",
      "eth_getUserOperationByHash",
      "eth_getUserOperationReceipt"
    ],
    paymasterRequired: false,
    customAccountCompatibility:
      "standard ERC-4337 API; semi-valid account-specific signature shape may be required",
    testAllowance: "public endpoint available without an API key",
    requestLimits: "public endpoint is IP rate-limited; exact numeric limit is not published",
    setupBurden: "low for an explicitly configured public test endpoint",
    risks: [
      "public numeric rate limit is unspecified",
      "full credential-bearing authenticated URL is secret",
      "custom PhilCore envelope compatibility must be verified remotely"
    ],
    officialSources: [
      "https://docs.candide.dev/wallet/api/supported-networks/",
      "https://docs.candide.dev/wallet/api/public-endpoints/",
      "https://docs.candide.dev/wallet/bundler/rpc-methods/"
    ]
  })
]);

function hashEndpointBinding(url) {
  const value = String(url ?? "").trim();
  return Object.freeze({
    configured: value.length > 0,
    redacted: value.length > 0 ? redactRpcEndpoint(value) : "not_configured",
    sha256: crypto.createHash("sha256").update(value).digest("hex")
  });
}

function buildStructuredInvalidSignature(input) {
  const signature = abiCoder.encode(
    ["uint8", "bytes32", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "bytes32", "uint8"],
    [
      1,
      SECURITY_MODEL_ID,
      input.actionId,
      input.authorizationDigest,
      BigInt(input.expiry),
      input.validatorKeyIdBinding,
      zeroPadValue("0x01", 32),
      zeroPadValue("0x01", 32),
      27
    ]
  );
  if ((signature.length - 2) / 2 !== SIGNATURE_ENVELOPE_LENGTH) {
    throw new Error("o26_signature_envelope_length_invalid");
  }
  return signature;
}

function buildO26EstimationOnlyUserOperation(input) {
  const base = buildEstimationOnlyUserOperation(input);
  const validatorKeyIdBinding = deriveLocalProofGatedValidatorKeyIdBinding(
    input.identity.validatorKeyId
  );
  const signature = buildStructuredInvalidSignature({
    actionId: ESTIMATION_ACTION_ID,
    authorizationDigest: ESTIMATION_AUTHORIZATION_DIGEST,
    expiry: input.expiry,
    validatorKeyIdBinding
  });
  const artifact = {
    ...base,
    schemaVersion: "philcore-o26-estimation-only-unpacked-user-operation-v1",
    phase: "O.26",
    status: "estimation_only",
    rpcV07Representation: {
      ...base.rpcV07Representation,
      signature
    },
    packedUserOperation: {
      ...base.packedUserOperation,
      signature
    },
    placeholders: {
      ...base.placeholders,
      signatureKind:
        "decoder_correct_cryptographically_invalid_estimation_envelope",
      signatureLengthBytes: SIGNATURE_ENVELOPE_LENGTH,
      cryptographicAuthority: false
    },
    realProofGenerated: false,
    realAuthorizationGenerated: false,
    realApprovalGenerated: false,
    freshPresenceRecorded: false,
    accountFunded: false,
    proofGenerated: false,
    authorizationGenerated: false,
    userApprovalGenerated: false,
    freshPresenceGenerated: false,
    deviceVaultSignatureGenerated: false,
    userOperationSigned: false,
    userOperationSubmitted: false,
    publicMutationOccurred: false
  };
  delete artifact.artifactDigest;
  artifact.artifactDigest = canonicalDigest(artifact);
  validateO26EstimationOnlyUserOperation(artifact);
  return Object.freeze(artifact);
}

function validateO26EstimationOnlyUserOperation(artifact) {
  if (
    artifact.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID
    || getAddress(artifact.entryPoint) !== getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT)
  ) {
    throw new Error("o26_user_operation_network_binding_invalid");
  }
  if (
    getAddress(artifact.sender) !== EXPECTED_ACCOUNT
    || getAddress(artifact.factory) !== EXPECTED_FACTORY
    || getAddress(artifact.target) !== EXPECTED_TARGET
  ) {
    throw new Error("o26_user_operation_contract_binding_invalid");
  }
  for (const [key, expected] of Object.entries({
    estimationOnly: true,
    submissionReady: false,
    realProofGenerated: false,
    realAuthorizationGenerated: false,
    realApprovalGenerated: false,
    freshPresenceRecorded: false,
    deviceVaultSignatureGenerated: false,
    accountFunded: false,
    userOperationSubmitted: false,
    publicMutationOccurred: false
  })) {
    if (artifact[key] !== expected) throw new Error(`o26_marker_invalid:${key}`);
  }
  const rpc = artifact.rpcV07Representation;
  if (rpc.paymaster !== null || artifact.packedUserOperation.paymasterAndData !== "0x") {
    throw new Error("o26_paymaster_not_permitted");
  }
  if (!isHexString(rpc.signature, SIGNATURE_ENVELOPE_LENGTH)) {
    throw new Error("o26_signature_envelope_shape_invalid");
  }
  const decoded = abiCoder.decode(
    ["uint8", "bytes32", "bytes32", "bytes32", "uint64", "bytes32", "bytes32", "bytes32", "uint8"],
    rpc.signature
  );
  if (
    Number(decoded[0]) !== 1
    || decoded[1] !== SECURITY_MODEL_ID
    || decoded[2] !== artifact.placeholders.actionId
    || decoded[3] !== artifact.placeholders.authorizationDigest
    || decoded[4].toString() !== artifact.placeholders.expiry
    || decoded[6] !== zeroPadValue("0x01", 32)
    || decoded[7] !== zeroPadValue("0x01", 32)
    || Number(decoded[8]) !== 27
  ) {
    throw new Error("o26_signature_envelope_binding_invalid");
  }
  return true;
}

function validateBundlerCapabilities(input) {
  if (Number(input.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("BUNDLER_WRONG_CHAIN");
  }
  const entryPoints = (input.supportedEntryPoints ?? []).map((value) =>
    getAddress(String(value))
  );
  if (!entryPoints.includes(getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT))) {
    throw new Error("BUNDLER_ENTRYPOINT_V07_UNSUPPORTED");
  }
  if (input.paymasterRequired === true) {
    throw new Error("BUNDLER_MANDATORY_PAYMASTER_UNSUPPORTED");
  }
  const requiredMethods = [
    "eth_supportedEntryPoints",
    "eth_estimateUserOperationGas",
    "eth_getUserOperationByHash",
    "eth_getUserOperationReceipt"
  ];
  for (const method of requiredMethods) {
    if (!(input.supportedMethods ?? []).includes(method)) {
      throw new Error(`BUNDLER_REQUIRED_METHOD_UNSUPPORTED:${method}`);
    }
  }
  return true;
}

function parseGas(value, field) {
  if (value === undefined || value === null) throw new Error(`bundler_estimate_missing:${field}`);
  const parsed = BigInt(value);
  if (parsed < 0n) throw new Error(`bundler_estimate_negative:${field}`);
  return parsed;
}

function validateBundlerEstimateResponse(response) {
  const limits = LOCAL_PROOF_GATED_PREPARATION_LIMITS;
  for (const field of [
    "sender",
    "nonce",
    "factory",
    "factoryData",
    "callData",
    "accountGasLimits",
    "gasFees",
    "authorizationDigest",
    "expiry",
    "signature"
  ]) {
    if (Object.prototype.hasOwnProperty.call(response, field)) {
      throw new Error(`bundler_response_attempted_userop_replacement:${field}`);
    }
  }
  const verificationGasLimit = parseGas(response.verificationGasLimit, "verificationGasLimit");
  const callGasLimit = parseGas(response.callGasLimit, "callGasLimit");
  const preVerificationGas = parseGas(response.preVerificationGas, "preVerificationGas");
  const paymasterVerificationGasLimit = BigInt(response.paymasterVerificationGasLimit ?? 0);
  const paymasterPostOpGasLimit = BigInt(response.paymasterPostOpGasLimit ?? 0);
  if (paymasterVerificationGasLimit !== 0n || paymasterPostOpGasLimit !== 0n) {
    throw new Error("bundler_estimate_introduced_paymaster");
  }
  if (verificationGasLimit > limits.maxVerificationGasLimit) {
    throw new Error("bundler_verification_gas_hard_ceiling_exceeded");
  }
  if (callGasLimit > limits.maxCallGasLimit) {
    throw new Error("bundler_call_gas_hard_ceiling_exceeded");
  }
  if (preVerificationGas > limits.maxPreVerificationGas) {
    throw new Error("bundler_preverification_gas_hard_ceiling_exceeded");
  }
  return Object.freeze({
    verificationGasLimit,
    callGasLimit,
    preVerificationGas,
    paymasterVerificationGasLimit,
    paymasterPostOpGasLimit
  });
}

function withMargin(value) {
  return value * (10_000n + GAS_MARGIN_BASIS_POINTS) / 10_000n;
}

function reconcileGasEstimates(local, bundlerResponse) {
  const limits = LOCAL_PROOF_GATED_PREPARATION_LIMITS;
  if (!bundlerResponse) {
    return Object.freeze({
      status: "BUNDLER_CONFIGURATION_REQUIRED",
      bundlerEstimateAvailable: false,
      selected: Object.freeze({
        verificationGasLimit: limits.maxVerificationGasLimit.toString(),
        callGasLimit: limits.maxCallGasLimit.toString(),
        preVerificationGas: limits.maxPreVerificationGas.toString(),
        paymasterVerificationGasLimit: "0",
        paymasterPostOpGasLimit: "0",
        totalDeclaredGas: (
          limits.maxVerificationGasLimit
          + limits.maxCallGasLimit
          + limits.maxPreVerificationGas
        ).toString(),
        selectionStatus: "provisional_hard_ceiling_pending_bundler_estimate"
      })
    });
  }
  const parsed = validateBundlerEstimateResponse(bundlerResponse);
  const selectedVerification = withMargin(
    parsed.verificationGasLimit > BigInt(local.approximateFirstOperationCreationGasComponent)
      ? parsed.verificationGasLimit
      : BigInt(local.approximateFirstOperationCreationGasComponent)
  );
  const selectedCall = withMargin(
    parsed.callGasLimit > BigInt(local.executionGasEstimate)
      ? parsed.callGasLimit
      : BigInt(local.executionGasEstimate)
  );
  const selectedPreVerification = withMargin(parsed.preVerificationGas);
  if (
    selectedVerification > limits.maxVerificationGasLimit
    || selectedCall > limits.maxCallGasLimit
    || selectedPreVerification > limits.maxPreVerificationGas
  ) {
    throw new Error("bundler_estimate_margin_exceeds_hard_ceiling");
  }
  return Object.freeze({
    status: "RECONCILED",
    bundlerEstimateAvailable: true,
    selected: Object.freeze({
      verificationGasLimit: selectedVerification.toString(),
      callGasLimit: selectedCall.toString(),
      preVerificationGas: selectedPreVerification.toString(),
      paymasterVerificationGasLimit: "0",
      paymasterPostOpGasLimit: "0",
      totalDeclaredGas: (
        selectedVerification + selectedCall + selectedPreVerification
      ).toString(),
      selectionStatus: "largest_observed_component_plus_20_percent"
    })
  });
}

function calculatePrefundEvidence(input) {
  const selected = input.selectedGas;
  const current = calculateNoPaymasterRequiredPrefund({
    ...selected,
    maxFeePerGas: input.currentMaxFeePerGasWei
  });
  const recommended = calculateNoPaymasterRequiredPrefund({
    ...selected,
    maxFeePerGas: input.recommendedMaxFeePerGasWei
  });
  const hard = calculateNoPaymasterRequiredPrefund({
    ...selected,
    maxFeePerGas: LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei
  });
  const expectedActualCost =
    BigInt(input.localActualGasUsed) * BigInt(input.observedGasPriceWei);
  const recommendedValue = BigInt(recommended.requiredPrefundWei);
  return Object.freeze({
    formula: recommended.formula,
    estimatedMinimumPrefundWei: current.requiredPrefundWei,
    recommendedDisposableTestPrefundWei: recommended.requiredPrefundWei,
    proposedMaximumFundingApprovalWei: recommended.requiredPrefundWei,
    absoluteRejectionCeilingExposureWei: hard.requiredPrefundWei,
    expectedActualCostAtObservedGasPriceWei: expectedActualCost.toString(),
    expectedResidualAfterSuccessWei:
      (recommendedValue > expectedActualCost
        ? recommendedValue - expectedActualCost
        : 0n).toString(),
    residualRiskClassification:
      "RESIDUAL_FUNDS_NONRECOVERABLE_BY_CURRENT_ACCOUNT"
  });
}

module.exports = {
  BUNDLER_PROVIDER_COMPARISON,
  GAS_MARGIN_BASIS_POINTS,
  O26_COMPATIBILITY_PATH,
  O26_ESTIMATE_PATH,
  O26_PREFUND_PATH,
  SECURITY_MODEL_ID,
  SIGNATURE_ENVELOPE_LENGTH,
  buildO26EstimationOnlyUserOperation,
  buildStructuredInvalidSignature,
  calculatePrefundEvidence,
  hashEndpointBinding,
  reconcileGasEstimates,
  validateBundlerCapabilities,
  validateBundlerEstimateResponse,
  validateO26EstimationOnlyUserOperation
};
