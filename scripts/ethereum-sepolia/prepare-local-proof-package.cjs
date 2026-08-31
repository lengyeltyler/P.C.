require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { AbiCoder, concat, getAddress } = require("ethers");

const {
  calculateLocalProofGatedFundingPlan,
  calculateLocalProofGatedProposedAddresses,
  createLocalProofGatedFirstUserOperationProposal,
  createRestrictedSepoliaBundlerClient,
  createRestrictedSepoliaReadOnlyClient,
  deriveLocalProofGatedValidatorKeyIdBinding,
  redactRpcEndpoint,
  runLocalProofGatedPreparationPreflight
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const { loadSepoliaLocalEnvironment } = require("./local-environment.cjs");

const ROOT = path.resolve(__dirname, "../..");
const CONFIG_DIR = path.join(ROOT, "config/ethereum-sepolia");
const MANIFEST_PATH = path.join(CONFIG_DIR, "LOCAL_PROOF_GATED_DEPLOYMENT_MANIFEST_PROPOSED.json");
const PREFLIGHT_PATH = path.join(CONFIG_DIR, "ETHEREUM_SEPOLIA_READ_ONLY_PREFLIGHT.json");
const USEROP_PATH = path.join(CONFIG_DIR, "LOCAL_PROOF_GATED_FIRST_USEROP_FINAL_PROPOSED.json");
const EVIDENCE_PATH = path.join(CONFIG_DIR, "LOCAL_PROOF_GATED_PREPARATION_EVIDENCE.json");
const abiCoder = AbiCoder.defaultAbiCoder();

function readJson(location) {
  return JSON.parse(fs.readFileSync(location, "utf8"));
}

function writeJson(location, value) {
  fs.writeFileSync(location, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function sha256File(location) {
  return crypto.createHash("sha256").update(fs.readFileSync(location)).digest("hex");
}

function git(args) {
  const result = spawnSync("git", args, {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }
  });
  if (result.status !== 0) throw new Error(`git ${args[0]} failed`);
  return result.stdout.trim();
}

function artifactPath(contract) {
  const sources = {
    PhilCoreLocalProofConfirmationTargetV1:
      "base/PhilCoreLocalProofConfirmationTargetV1.sol",
    PhilCore4337LocalProofAccountV1:
      "base/erc4337/PhilCore4337LocalProofAccountV1.sol",
    PhilCore4337LocalProofAccountFactoryV1:
      "base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol"
  };
  return path.join(ROOT, "artifacts/contracts", sources[contract], `${contract}.json`);
}

function publicInputs(accountBytecode) {
  const validatorKeyId = deriveLocalProofGatedValidatorKeyIdBinding(
    process.env.PHILCORE_SEPOLIA_VALIDATOR_KEY_ID
  );
  return {
    deployerAddress: process.env.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS,
    deployerNonce: process.env.PHILCORE_SEPOLIA_DEPLOYER_NONCE,
    ownerAddress: process.env.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS,
    ownerCommitment: process.env.PHILCORE_SEPOLIA_OWNER_COMMITMENT,
    validatorKeyId,
    accountSalt: process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT,
    accountCreationBytecode: accountBytecode
  };
}

function requiredUserOperationInputs(addresses, gasPriceWei) {
  if (addresses.status !== "calculated") return undefined;
  const values = {
    sender: addresses.accountAddress,
    factoryAddress: addresses.factoryAddress,
    ownerAddress: process.env.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS,
    ownerCommitment: process.env.PHILCORE_SEPOLIA_OWNER_COMMITMENT,
    validatorKeyId: deriveLocalProofGatedValidatorKeyIdBinding(
      process.env.PHILCORE_SEPOLIA_VALIDATOR_KEY_ID
    ),
    accountSalt: process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT,
    actionId: process.env.PHILCORE_LOCAL_PROOF_ACTION_ID,
    authorizationDigest: process.env.PHILCORE_LOCAL_PROOF_AUTHORIZATION_DIGEST,
    expiry: process.env.PHILCORE_LOCAL_PROOF_EXPIRY,
    nonce: process.env.PHILCORE_LOCAL_PROOF_NONCE ?? "0",
    verificationGasLimit: process.env.PHILCORE_LOCAL_PROOF_VERIFICATION_GAS_LIMIT,
    callGasLimit: process.env.PHILCORE_LOCAL_PROOF_CALL_GAS_LIMIT,
    preVerificationGas: process.env.PHILCORE_LOCAL_PROOF_PRE_VERIFICATION_GAS,
    maxFeePerGas: process.env.PHILCORE_LOCAL_PROOF_MAX_FEE_PER_GAS ?? gasPriceWei,
    maxPriorityFeePerGas: process.env.PHILCORE_LOCAL_PROOF_MAX_PRIORITY_FEE_PER_GAS
  };
  return Object.values(values).some((value) => value === undefined || value === "")
    ? undefined
    : values;
}

function missingUserOperationInputs(addresses, gasPriceWei) {
  const missing = [];
  if (addresses.status !== "calculated") missing.push("calculated counterfactual addresses");
  const required = {
    PHILCORE_LOCAL_PROOF_ACTION_ID: process.env.PHILCORE_LOCAL_PROOF_ACTION_ID,
    PHILCORE_LOCAL_PROOF_AUTHORIZATION_DIGEST:
      process.env.PHILCORE_LOCAL_PROOF_AUTHORIZATION_DIGEST,
    PHILCORE_LOCAL_PROOF_EXPIRY: process.env.PHILCORE_LOCAL_PROOF_EXPIRY,
    PHILCORE_LOCAL_PROOF_VERIFICATION_GAS_LIMIT:
      process.env.PHILCORE_LOCAL_PROOF_VERIFICATION_GAS_LIMIT,
    PHILCORE_LOCAL_PROOF_CALL_GAS_LIMIT:
      process.env.PHILCORE_LOCAL_PROOF_CALL_GAS_LIMIT,
    PHILCORE_LOCAL_PROOF_PRE_VERIFICATION_GAS:
      process.env.PHILCORE_LOCAL_PROOF_PRE_VERIFICATION_GAS,
    PHILCORE_LOCAL_PROOF_MAX_FEE_PER_GAS:
      process.env.PHILCORE_LOCAL_PROOF_MAX_FEE_PER_GAS ?? gasPriceWei,
    PHILCORE_LOCAL_PROOF_MAX_PRIORITY_FEE_PER_GAS:
      process.env.PHILCORE_LOCAL_PROOF_MAX_PRIORITY_FEE_PER_GAS
  };
  for (const [name, value] of Object.entries(required)) {
    if (value === undefined || value === "") missing.push(name);
  }
  return missing;
}

async function estimateDeployments({ client, manifest, addresses }) {
  const unresolved = {
    source: "unresolved",
    bundlerEstimateStatus: process.env.PHILCORE_SEPOLIA_BUNDLER_URL
      ? "failed"
      : "BUNDLER_ESTIMATE_NOT_CONFIGURED"
  };
  if (!client || addresses.status !== "calculated") return unresolved;
  const deployer = addresses.inputs.deployerAddress;
  const targetArtifact = readJson(artifactPath("PhilCoreLocalProofConfirmationTargetV1"));
  const factoryArtifact = readJson(artifactPath("PhilCore4337LocalProofAccountFactoryV1"));
  const factoryConstructor = abiCoder.encode(
    ["address", "address", "uint256"],
    [ERC4337_V07_CANONICAL_ENTRYPOINT, addresses.targetAddress, ETHEREUM_SEPOLIA_CHAIN_ID]
  );
  try {
    const targetDeploymentGas = BigInt(String(await client.request("eth_estimateGas", [{
      from: deployer,
      data: targetArtifact.bytecode,
      value: "0x0"
    }]))).toString();
    const factoryDeploymentGas = BigInt(String(await client.request("eth_estimateGas", [{
      from: deployer,
      data: concat([factoryArtifact.bytecode, factoryConstructor]),
      value: "0x0"
    }]))).toString();
    return {
      source: "live_read_only_rpc",
      targetDeploymentGas,
      factoryDeploymentGas,
      gasPriceWei: undefined,
      bundlerEstimateStatus: process.env.PHILCORE_SEPOLIA_BUNDLER_URL
        ? "configured_read_only"
        : "BUNDLER_ESTIMATE_NOT_CONFIGURED"
    };
  } catch {
    return { ...unresolved, source: "unresolved" };
  }
}

async function inspectBundler(preflight) {
  const bundlerUrl = process.env.PHILCORE_SEPOLIA_BUNDLER_URL;
  if (!bundlerUrl) {
    return {
      status: "BUNDLER_ESTIMATE_NOT_CONFIGURED",
      endpointClassification: "not_configured",
      mutationMethodsExposed: false,
      supportedEntryPoint: "not_checked"
    };
  }
  if (preflight.status !== "READ_ONLY_PREFLIGHT_PASSED") {
    return {
      status: "blocked_by_rpc_preflight",
      endpointClassification: redactRpcEndpoint(bundlerUrl),
      mutationMethodsExposed: false,
      supportedEntryPoint: "not_checked"
    };
  }
  const client = createRestrictedSepoliaBundlerClient({ url: bundlerUrl });
  try {
    const supported = await client.request("eth_supportedEntryPoints", []);
    const list = Array.isArray(supported) ? supported.map(String) : [];
    return {
      status: list.some((value) =>
        value.toLowerCase() === ERC4337_V07_CANONICAL_ENTRYPOINT.toLowerCase()
      )
        ? "configured_read_only"
        : "entry_point_not_supported",
      endpointClassification: client.endpointClassification,
      mutationMethodsExposed: client.mutationMethodsExposed,
      supportedEntryPoint: list.some((value) =>
        value.toLowerCase() === ERC4337_V07_CANONICAL_ENTRYPOINT.toLowerCase()
      )
    };
  } catch (error) {
    return {
      status: "bundler_read_failed",
      endpointClassification: client.endpointClassification,
      mutationMethodsExposed: false,
      supportedEntryPoint: false,
      error: error instanceof Error ? error.message : "bundler read failed"
    };
  }
}

async function main() {
  const localEnvironment = loadSepoliaLocalEnvironment({ root: ROOT });
  const manifest = readJson(MANIFEST_PATH);
  const accountArtifact = readJson(artifactPath("PhilCore4337LocalProofAccountV1"));
  const addresses = calculateLocalProofGatedProposedAddresses(
    publicInputs(accountArtifact.bytecode)
  );
  const rpcUrl = process.env.PHILCORE_SEPOLIA_RPC_URL;
  const client = rpcUrl
    ? createRestrictedSepoliaReadOnlyClient({ url: rpcUrl })
    : undefined;
  const preflight = await runLocalProofGatedPreparationPreflight({
    client,
    deployer: {
      address: process.env.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS,
      configuredPendingNonce: process.env.PHILCORE_SEPOLIA_DEPLOYER_NONCE
    },
    validatorAddress: process.env.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS,
    proposedAddresses: addresses.status === "calculated"
      ? {
          confirmationTarget: addresses.targetAddress,
          accountFactory: addresses.factoryAddress,
          firstAccount: addresses.accountAddress
        }
      : undefined
  });
  const bundler = await inspectBundler(preflight);
  const estimates = await estimateDeployments({ client, manifest, addresses });
  if (preflight.feeData.gasPriceWei) {
    estimates.gasPriceWei = preflight.feeData.gasPriceWei;
    estimates.maxFeePerGasWei = process.env.PHILCORE_LOCAL_PROOF_MAX_FEE_PER_GAS;
    estimates.maxPriorityFeePerGasWei =
      process.env.PHILCORE_LOCAL_PROOF_MAX_PRIORITY_FEE_PER_GAS;
  }
  const funding = calculateLocalProofGatedFundingPlan({
    estimates,
    bufferBasisPoints: 2_500,
    hardMaximumExposureWei: process.env.PHILCORE_LOCAL_PROOF_HARD_MAX_EXPOSURE_WEI
  });
  const userOperationInput = requiredUserOperationInputs(
    addresses,
    preflight.feeData.gasPriceWei
  );
  const firstUserOperation = userOperationInput
    ? createLocalProofGatedFirstUserOperationProposal(userOperationInput)
    : {
        status: "inputs_required",
        securityModel: "local-proof-gated-v1",
        sender: addresses.accountAddress ?? null,
        nonce: null,
        factory: addresses.factoryAddress ?? null,
        factoryData: null,
        callData: null,
        gasFields: null,
        feeFields: null,
        paymasterAndData: "0x",
        signature: "0x",
        actionId: null,
        authorizationDigest: null,
        expiry: null,
        valueWei: "0",
        tokenMovement: false,
        batchEnabled: false,
        delegatecallEnabled: false,
        paymasterEnabled: false,
        signaturePresent: false,
        publicMutationAuthorized: false,
        publicMutationOccurred: false,
        missingInputs: missingUserOperationInputs(
          addresses,
          preflight.feeData.gasPriceWei
        )
      };
  const head = git(["rev-parse", "HEAD"]);
  const status = git(["status", "--porcelain=v1"]);
  const security = readJson(path.join(ROOT, "config/security/philcore-solidity-static-analysis.json"));
  const invariants = readJson(path.join(ROOT, "config/security/philcore-contract-invariants-report.json"));
  const updatedManifest = {
    ...manifest,
    phase: "O.20",
    sourceCommit: head,
    roles: {
      ...manifest.roles,
      deployer: {
        ...manifest.roles.deployer,
        reference: process.env.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS
      },
      validator: {
        ...manifest.roles.validator,
        reference: process.env.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS
      }
    },
    proposedAddresses: {
      status: addresses.status,
      target: addresses.targetAddress ?? null,
      factory: addresses.factoryAddress ?? null,
      firstAccount: addresses.accountAddress ?? null,
      targetDeploymentNonce: addresses.targetDeploymentNonce ?? null,
      factoryDeploymentNonce: addresses.factoryDeploymentNonce ?? null,
      liveEmptyAddressCheckPassed:
        preflight.status === "READ_ONLY_PREFLIGHT_PASSED"
        && Object.values(preflight.proposedAddresses)
          .every((observation) => observation.codeStatus === "empty"),
      deployed: false,
      verified: false,
      accepted: false
    },
    gasAndFees: {
      ...manifest.gasAndFees,
      estimateSource: estimates.source,
      targetDeploymentGas: estimates.targetDeploymentGas ?? null,
      factoryDeploymentGas: estimates.factoryDeploymentGas ?? null,
      currentGasPriceWei: estimates.gasPriceWei ?? null,
      bundlerEstimateStatus: estimates.bundlerEstimateStatus
    },
    funding: {
      ...manifest.funding,
      status: funding.status,
      deployerMinimumWei: funding.deployerMinimumWei ?? null,
      accountPrefundMinimumWei: funding.accountPrefundMinimumWei ?? null,
      conservativeRecommendedWei: funding.conservativeRecommendedWei ?? null,
      fundingApproved: false
    }
  };
  writeJson(MANIFEST_PATH, updatedManifest);
  const evidence = {
    schemaVersion: "philcore-local-proof-gated-preparation-evidence-v1",
    phase: "O.20",
    generatedAt: new Date().toISOString(),
    architectureApproval: {
      status: manifest.approval.architectureApprovalStatus,
      scope: "one disposable Ethereum Sepolia experiment preparation only",
      ethereumVerifiesStwoProof: false
    },
    canonicalIdentityBinding: {
      identityId: localEnvironment.identity.identityId,
      ownerCommitment: localEnvironment.identity.ownerCommitment,
      validatorAddress: localEnvironment.identity.validatorAddress,
      validatorKeyReferenceId: localEnvironment.identity.validatorKeyId,
      validatorKeyIdBinding: deriveLocalProofGatedValidatorKeyIdBinding(
        localEnvironment.identity.validatorKeyId
      ),
      sameCanonicalRecord: true,
      privateMaterialAccessed: false
    },
    sourceCommit: head,
    repositoryCleanAtGeneration: status.length === 0,
    manifest: {
      path: path.relative(ROOT, MANIFEST_PATH),
      status: manifest.status,
      sha256: sha256File(MANIFEST_PATH)
    },
    compiler: updatedManifest.compiler,
    bytecode: updatedManifest.contracts.map((contract) => ({
      contract: contract.contract,
      creationBytecodeHash: contract.creationBytecodeHash,
      deployedBytecodeHash: contract.deployedBytecodeHash
    })),
    staticAnalysis: {
      status: security.status,
      unresolvedCriticalOrHigh: security.unresolvedCriticalOrHigh ?? []
    },
    contractInvariants: {
      status: invariants.status,
      failed: invariants.failed ?? []
    },
    readOnlyPreflight: preflight,
    bundler,
    proposedAddresses: addresses,
    gasEstimates: estimates,
    funding,
    firstUserOperation,
    mutationGatesPresent: false,
    mutationAttempted: false,
    publicMutationOccurred: false,
    deploymentManifestAccepted: false,
    productionApproved: false
  };
  writeJson(PREFLIGHT_PATH, preflight);
  writeJson(USEROP_PATH, firstUserOperation);
  writeJson(EVIDENCE_PATH, evidence);
  process.stdout.write(`${JSON.stringify({
    status: "preparation_evidence_created",
    preflight: preflight.status,
    addresses: addresses.status,
    bundler: bundler.status,
    funding: funding.status,
    firstUserOperation: firstUserOperation.status,
    rpcClassification: preflight.rpcClassification,
    publicMutationOccurred: false,
    files: [
      path.relative(ROOT, PREFLIGHT_PATH),
      path.relative(ROOT, USEROP_PATH),
      path.relative(ROOT, EVIDENCE_PATH)
    ]
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
