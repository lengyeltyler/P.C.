require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  AbiCoder,
  Interface,
  concat,
  formatEther,
  formatUnits,
  getAddress,
  keccak256,
  toBeHex,
  zeroPadValue
} = require("ethers");

const {
  LOCAL_PROOF_GATED_PREPARATION_LIMITS,
  calculateLocalProofGatedProposedAddresses,
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
const PREVIOUS_MANIFEST_PATH = path.join(
  CONFIG_DIR,
  "LOCAL_PROOF_GATED_DEPLOYMENT_MANIFEST_PROPOSED.json"
);
const PROPOSAL_PATH = path.join(
  CONFIG_DIR,
  "O22_CURRENT_SOURCE_DEPLOYMENT_PROPOSAL.json"
);
const FUNDING_PATH = path.join(
  CONFIG_DIR,
  "O22_FIRST_SEPOLIA_FUNDING_READINESS.json"
);
const SOURCE_PATHS = Object.freeze([
  "contracts/base/PhilCoreLocalProofConfirmationTargetV1.sol",
  "contracts/base/interfaces/IPhilCoreLocalProofAccountV1.sol",
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol",
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol",
  "apps/phil-device-sdk/src/runtime/localProofGatedAccount.ts",
  "apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts",
  "apps/phil-device-sdk/src/runtime/deviceVaultEcdsaCustody.ts",
  "apps/phil-device-sdk/src/runtime/philcore4337UserOperationSigning.ts"
]);
const CONTRACTS = Object.freeze([
  {
    id: "confirmationTarget",
    contract: "PhilCoreLocalProofConfirmationTargetV1",
    source: "contracts/base/PhilCoreLocalProofConfirmationTargetV1.sol",
    artifact:
      "artifacts/contracts/base/PhilCoreLocalProofConfirmationTargetV1.sol/PhilCoreLocalProofConfirmationTargetV1.json"
  },
  {
    id: "accountFactory",
    contract: "PhilCore4337LocalProofAccountFactoryV1",
    source: "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol",
    artifact:
      "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol/PhilCore4337LocalProofAccountFactoryV1.json"
  },
  {
    id: "account",
    contract: "PhilCore4337LocalProofAccountV1",
    source: "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol",
    artifact:
      "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol/PhilCore4337LocalProofAccountV1.json"
  }
]);
const PREVIOUS_SOURCE_COMMIT = "13b28149f99c4fae261b96f56fb9ad2790b21e23";
const OBSERVATION_FRESHNESS_MS = 15 * 60 * 1000;
const BUFFER_BASIS_POINTS = 2500n;
const abiCoder = AbiCoder.defaultAbiCoder();

function readJson(location) {
  return JSON.parse(fs.readFileSync(location, "utf8"));
}

function writeJson(location, value) {
  fs.writeFileSync(location, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(relativePath) {
  return sha256(fs.readFileSync(path.join(ROOT, relativePath)));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function runGit(args) {
  const result = spawnSync("git", args, {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }
  });
  if (result.status !== 0) throw new Error(`git_${args[0]}_failed`);
  return result.stdout.trim();
}

function compilerBinding() {
  const buildInfoDir = path.join(ROOT, "artifacts/build-info");
  const files = fs.readdirSync(buildInfoDir).filter((name) => name.endsWith(".json"));
  if (files.length !== 1) throw new Error("compiler_build_info_ambiguous");
  const buildInfo = readJson(path.join(buildInfoDir, files[0]));
  const optimizer = buildInfo.input?.settings?.optimizer;
  const binding = {
    version: buildInfo.solcVersion,
    optimizerEnabled: optimizer?.enabled === true,
    optimizerRuns: optimizer?.runs,
    viaIR: buildInfo.input?.settings?.viaIR === true,
    evmVersion: buildInfo.input?.settings?.evmVersion ?? "default",
    buildInfoSha256: sha256File(path.relative(ROOT, path.join(buildInfoDir, files[0])))
  };
  if (
    binding.version !== "0.8.24"
    || !binding.optimizerEnabled
    || binding.optimizerRuns !== 200
    || !binding.viaIR
  ) {
    throw new Error("compiler_configuration_mismatch");
  }
  return binding;
}

function sourceBinding(head) {
  const sources = SOURCE_PATHS.map((sourcePath) => ({
    path: sourcePath,
    sha256: sha256File(sourcePath)
  }));
  const deploymentSourceTreeSha256 = sha256(canonicalJson(sources));
  const changedPaths = runGit([
    "diff",
    "--name-only",
    `${PREVIOUS_SOURCE_COMMIT}..${head}`,
    "--",
    ...SOURCE_PATHS
  ]).split("\n").filter(Boolean);
  return {
    sourceCommitAtGeneration: head,
    previousSourceCommit: PREVIOUS_SOURCE_COMMIT,
    deploymentSourceTreeSha256,
    sources,
    o21Changes: changedPaths.map((sourcePath) => {
      if (sourcePath.endsWith("localProofGatedAccount.ts")) {
        return {
          path: sourcePath,
          classifications: [
            "UserOperation-affecting",
            "authorization-digest-validation-affecting",
            "signature-validation-affecting"
          ],
          deploymentBytecodeChanged: false,
          accountAddressChanged: false
        };
      }
      if (sourcePath.endsWith("deviceVaultEcdsaCustody.ts")) {
        return {
          path: sourcePath,
          classifications: [
            "Device-Vault-signing-boundary-affecting",
            "non-deployment-affecting"
          ],
          deploymentBytecodeChanged: false,
          accountAddressChanged: false
        };
      }
      if (sourcePath.endsWith("localProofGatedDeploymentPreparation.ts")) {
        return {
          path: sourcePath,
          classifications: [
            "read-only-preparation-evidence-affecting",
            "non-deployment-affecting"
          ],
          deploymentBytecodeChanged: false,
          accountAddressChanged: false
        };
      }
      return {
        path: sourcePath,
        classifications: ["review_required"],
        deploymentBytecodeChanged: sourcePath.endsWith(".sol"),
        accountAddressChanged: sourcePath.includes("AccountV1.sol")
      };
    })
  };
}

function artifactBindings() {
  return CONTRACTS.map((item) => {
    const artifact = readJson(path.join(ROOT, item.artifact));
    return {
      ...item,
      sourceSha256: sha256File(item.source),
      abiSha256: sha256(canonicalJson(artifact.abi)),
      creationBytecodeHash: keccak256(artifact.bytecode),
      deployedBytecodeHash: keccak256(artifact.deployedBytecode),
      creationBytecodeSize: (artifact.bytecode.length - 2) / 2,
      deployedBytecodeSize: (artifact.deployedBytecode.length - 2) / 2
    };
  });
}

function accountArtifact() {
  return readJson(path.join(
    ROOT,
    CONTRACTS.find((item) => item.id === "account").artifact
  ));
}

async function readNonce(client, address, blockTag) {
  return BigInt(String(await client.request(
    "eth_getTransactionCount",
    [address, blockTag]
  ))).toString();
}

async function readAddressHistory(client, addresses) {
  const result = {};
  for (const [name, address] of Object.entries(addresses)) {
    result[name] = {
      address,
      latestTransactionCount: await readNonce(client, address, "latest")
    };
  }
  return result;
}

async function liveDeploymentGas(client, deployer, addresses) {
  const target = readJson(path.join(ROOT, CONTRACTS[0].artifact));
  const factory = readJson(path.join(ROOT, CONTRACTS[1].artifact));
  const factoryConstructorData = abiCoder.encode(
    ["address", "address", "uint256"],
    [
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      addresses.targetAddress,
      ETHEREUM_SEPOLIA_CHAIN_ID
    ]
  );
  const targetDeploymentGas = BigInt(String(await client.request(
    "eth_estimateGas",
    [{ from: deployer, data: target.bytecode, value: "0x0" }]
  ))).toString();
  const factoryDeploymentGas = BigInt(String(await client.request(
    "eth_estimateGas",
    [{
      from: deployer,
      data: concat([factory.bytecode, factoryConstructorData]),
      value: "0x0"
    }]
  ))).toString();
  return {
    source: "ethereum_sepolia_eth_estimateGas",
    targetDeploymentGas,
    factoryDeploymentGas
  };
}

function localGasEstimates() {
  const result = spawnSync(
    process.execPath,
    ["scripts/ethereum-sepolia/estimate-o22-local-gas.cjs"],
    { cwd: ROOT, encoding: "utf8", env: { ...process.env } }
  );
  if (result.status !== 0) {
    throw new Error(`local_gas_estimation_failed:${result.stderr.trim()}`);
  }
  return JSON.parse(result.stdout);
}

function withBuffer(value) {
  return value * (10_000n + BUFFER_BASIS_POINTS) / 10_000n;
}

function amount(value) {
  return {
    wei: value.toString(),
    gwei: formatUnits(value, "gwei"),
    eth: formatEther(value)
  };
}

function fundingReadiness(input) {
  const gasPrice = BigInt(input.gasPriceWei);
  const recommendedMaxFee = gasPrice * 2n > LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei
    ? LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei
    : gasPrice * 2n;
  const deploymentGas = BigInt(input.liveGas.targetDeploymentGas)
    + BigInt(input.liveGas.factoryDeploymentGas);
  const bufferedDeploymentGas = withBuffer(deploymentGas);
  const accountGasCeiling =
    LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxVerificationGasLimit
    + LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxCallGasLimit
    + LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxPreVerificationGas;
  const deployerMinimum = deploymentGas * gasPrice;
  const deployerRecommended = bufferedDeploymentGas * recommendedMaxFee;
  const deployerHardCeiling =
    bufferedDeploymentGas * LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei;
  const accountMinimum =
    BigInt(input.localGas.counterfactualFirstUserOperation.userOperation.actualGasUsed)
    * gasPrice;
  const accountRecommended = accountGasCeiling * recommendedMaxFee;
  const accountHardCeiling =
    accountGasCeiling * LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei;
  return {
    schemaVersion: "philcore-o22-first-sepolia-funding-readiness-v1",
    phase: "O.22",
    status: "proposed_estimates_only",
    accepted: false,
    fundingApproved: false,
    fundingPerformed: false,
    assumptions: {
      currentGasPrice: amount(gasPrice),
      recommendedMaxFeePerGas: amount(recommendedMaxFee),
      maxFeePerGasCeiling: amount(
        LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei
      ),
      maxPriorityFeePerGasCeiling: amount(
        LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxPriorityFeePerGasWei
      ),
      safetyBufferBasisPoints: Number(BUFFER_BASIS_POINTS)
    },
    disposableDeployer: {
      purpose: "confirmation target and account factory deployments only",
      estimatedMinimum: amount(deployerMinimum),
      recommendedTestAmount: amount(deployerRecommended),
      configuredHardCeilingExposure: amount(deployerHardCeiling),
      gasUnits: {
        targetDeployment: input.liveGas.targetDeploymentGas,
        factoryDeployment: input.liveGas.factoryDeploymentGas,
        combined: deploymentGas.toString(),
        buffered: bufferedDeploymentGas.toString()
      }
    },
    counterfactualSmartAccount: {
      purpose: "first counterfactual deployment and confirmation UserOperation prefund",
      estimatedMinimum: amount(accountMinimum),
      recommendedTestAmount: amount(accountRecommended),
      configuredHardCeilingExposure: amount(accountHardCeiling),
      hardGasCeiling: accountGasCeiling.toString(),
      prefundMechanism: "direct ETH transfer to the counterfactual address",
      entryPointDepositRequired: false,
      mechanismRationale:
        "BaseAccount pays missingAccountFunds from the account balance during validation; the predicted address may be prefunded before CREATE2 deployment",
      withdrawalWarning:
        "the experimental account exposes no withdrawal or recovery method; unused prefund may be stranded"
    },
    totalConfiguredHardCeilingExposure: amount(
      deployerHardCeiling + accountHardCeiling
    ),
    bundlerStatus: "BUNDLER_ESTIMATE_NOT_CONFIGURED",
    exactBundlerPrefundResolved: false,
    publicMutationOccurred: false
  };
}

function initializationBinding(addresses, identity) {
  const factoryInterface = new Interface([
    "function createAccount(address owner,bytes32 ownerCommitment,bytes32 validatorKeyId,uint256 salt)"
  ]);
  const validatorKeyId = deriveLocalProofGatedValidatorKeyIdBinding(
    identity.validatorKeyId
  );
  const salt = BigInt(process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT);
  const factoryCalldata = factoryInterface.encodeFunctionData("createAccount", [
    identity.validatorAddress,
    identity.ownerCommitment,
    validatorKeyId,
    salt
  ]);
  const factoryConstructorData = abiCoder.encode(
    ["address", "address", "uint256"],
    [
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      addresses.targetAddress,
      ETHEREUM_SEPOLIA_CHAIN_ID
    ]
  );
  const accountConstructorData = abiCoder.encode(
    ["address", "address", "bytes32", "address", "bytes32", "uint256"],
    [
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      identity.validatorAddress,
      identity.ownerCommitment,
      addresses.targetAddress,
      validatorKeyId,
      ETHEREUM_SEPOLIA_CHAIN_ID
    ]
  );
  const accountCreationCode = accountArtifact().bytecode;
  const accountInitCode = concat([accountCreationCode, accountConstructorData]);
  return {
    factoryConstructorArguments: [
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      addresses.targetAddress,
      ETHEREUM_SEPOLIA_CHAIN_ID
    ],
    factoryConstructorData,
    factoryCalldata,
    entryPointInitCode: concat([addresses.factoryAddress, factoryCalldata]),
    accountConstructorArguments: [
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      identity.validatorAddress,
      identity.ownerCommitment,
      addresses.targetAddress,
      validatorKeyId,
      ETHEREUM_SEPOLIA_CHAIN_ID
    ],
    accountConstructorData,
    create2: {
      factory: addresses.factoryAddress,
      saltDecimal: salt.toString(),
      saltBytes32: zeroPadValue(toBeHex(salt), 32),
      accountCreationBytecodeHash: keccak256(accountCreationCode),
      accountConstructorDataHash: keccak256(accountConstructorData),
      accountInitCodeHash: keccak256(accountInitCode),
      predictedAccount: addresses.accountAddress
    }
  };
}

function ensureNoCollision(preflight) {
  for (const [name, observation] of Object.entries(preflight.proposedAddresses)) {
    if (observation.codeStatus !== "empty" || BigInt(observation.balanceWei ?? "0") !== 0n) {
      throw new Error(`PROPOSED_ADDRESS_COLLISION:${name}`);
    }
  }
}

function ensureNoSecrets(value) {
  const serialized = JSON.stringify(value);
  if (
    /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey|recoverySecret/i
      .test(serialized)
  ) {
    throw new Error("secret_field_detected");
  }
  if (serialized.includes(process.env.PHILCORE_SEPOLIA_RPC_URL)) {
    throw new Error("rpc_url_leak_detected");
  }
}

function validateO22Proposal(proposal, expected) {
  const errors = [];
  if (proposal.status !== "proposed" || proposal.accepted !== false) {
    errors.push("proposal_status_invalid");
  }
  if (
    proposal.sourceBinding.sourceCommitAtGeneration
      !== expected.sourceCommitAtGeneration
  ) {
    errors.push("source_commit_stale");
  }
  if (
    proposal.sourceBinding.deploymentSourceTreeSha256
      !== expected.deploymentSourceTreeSha256
  ) {
    errors.push("source_tree_hash_mismatch");
  }
  const compiler = proposal.compiler;
  if (
    compiler.version !== expected.compiler.version
    || compiler.optimizerEnabled !== expected.compiler.optimizerEnabled
    || compiler.optimizerRuns !== expected.compiler.optimizerRuns
    || compiler.viaIR !== expected.compiler.viaIR
  ) {
    errors.push("compiler_configuration_mismatch");
  }
  if (proposal.publicMutationApproved !== false) {
    errors.push("public_mutation_approval_invalid");
  }
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

async function main() {
  const localEnvironment = loadSepoliaLocalEnvironment({ root: ROOT });
  const head = runGit(["rev-parse", "HEAD"]);
  if (runGit(["status", "--porcelain=v1"]) !== "") {
    throw new Error("repository_must_be_clean_before_o22_generation");
  }
  const previousManifest = readJson(PREVIOUS_MANIFEST_PATH);
  const compiler = compilerBinding();
  const artifacts = artifactBindings();
  const sources = sourceBinding(head);
  const client = createRestrictedSepoliaReadOnlyClient({
    url: process.env.PHILCORE_SEPOLIA_RPC_URL
  });
  const chainId = Number(BigInt(String(await client.request("eth_chainId", []))));
  if (chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) throw new Error("WRONG_ETHEREUM_CHAIN");
  const deployer = getAddress(process.env.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS);
  const latestNonce = await readNonce(client, deployer, "latest");
  const pendingNonce = await readNonce(client, deployer, "pending");
  const addresses = calculateLocalProofGatedProposedAddresses({
    deployerAddress: deployer,
    deployerNonce: pendingNonce,
    ownerAddress: localEnvironment.identity.validatorAddress,
    ownerCommitment: localEnvironment.identity.ownerCommitment,
    validatorKeyId: deriveLocalProofGatedValidatorKeyIdBinding(
      localEnvironment.identity.validatorKeyId
    ),
    accountSalt: process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT,
    accountCreationBytecode: accountArtifact().bytecode
  });
  if (addresses.status !== "calculated") {
    throw new Error(`address_calculation_failed:${addresses.errors.join(",")}`);
  }
  const preflight = await runLocalProofGatedPreparationPreflight({
    client,
    deployer: { address: deployer, configuredPendingNonce: pendingNonce },
    validatorAddress: localEnvironment.identity.validatorAddress,
    proposedAddresses: {
      confirmationTarget: addresses.targetAddress,
      accountFactory: addresses.factoryAddress,
      firstAccount: addresses.accountAddress
    }
  });
  if (preflight.status !== "READ_ONLY_PREFLIGHT_PASSED") {
    throw new Error(`o22_preflight_failed:${preflight.errors.join(",")}`);
  }
  ensureNoCollision(preflight);
  const previousAddressObservations = await readAddressHistory(client, {
    previousTarget: previousManifest.proposedAddresses.target,
    previousFactory: previousManifest.proposedAddresses.factory,
    previousAccount: previousManifest.proposedAddresses.firstAccount
  });
  const currentAddressHistory = await readAddressHistory(client, {
    target: addresses.targetAddress,
    factory: addresses.factoryAddress,
    account: addresses.accountAddress
  });
  const liveGas = await liveDeploymentGas(client, deployer, addresses);
  const localGas = localGasEstimates();
  const funding = fundingReadiness({
    gasPriceWei: preflight.feeData.gasPriceWei,
    liveGas,
    localGas
  });
  const checkedAt = new Date();
  const initialization = initializationBinding(addresses, localEnvironment.identity);
  const previousAddresses = {
    target: previousManifest.proposedAddresses.target,
    factory: previousManifest.proposedAddresses.factory,
    account: previousManifest.proposedAddresses.firstAccount
  };
  const currentAddresses = {
    target: addresses.targetAddress,
    factory: addresses.factoryAddress,
    account: addresses.accountAddress
  };
  const proposal = {
    schemaVersion: "philcore-o22-current-source-deployment-proposal-v1",
    phase: "O.22",
    status: "proposed",
    accepted: false,
    deploymentApproved: false,
    fundingApproved: false,
    signingApproved: false,
    submissionApproved: false,
    publicMutationApproved: false,
    sourceBinding: sources,
    compiler,
    artifacts,
    changeImpact: {
      solidityDeploymentSourcesChangedSinceO20:
        sources.o21Changes.some((change) => change.path.endsWith(".sol")),
      creationOrRuntimeBytecodeChangedSinceO20:
        artifacts.some((artifact) => {
          const previous = previousManifest.contracts.find(
            (candidate) => candidate.id === artifact.id
          );
          return !previous
            || previous.creationBytecodeHash !== artifact.creationBytecodeHash
            || previous.deployedBytecodeHash !== artifact.deployedBytecodeHash;
        }),
      accountAddressAffectingChangeSinceO20: false,
      runtimeAuthorizationAndSigningBoundaryChanged: true
    },
    network: {
      profileId: "ethereum_sepolia",
      chainId,
      entryPointVersion: "0.7",
      entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
      entryPointCodePresent: preflight.entryPoint.codePresent,
      entryPointCodeHash: preflight.entryPoint.codeHash,
      expectedPriorEntryPointCodeHash:
        previousManifest.network.entryPointAddress === ERC4337_V07_CANONICAL_ENTRYPOINT
          ? readJson(path.join(CONFIG_DIR, "ETHEREUM_SEPOLIA_READ_ONLY_PREFLIGHT.json"))
            .entryPoint.codeHash
          : null,
      entryPointNonceCallSupported: preflight.entryPoint.getNonceCallSupported,
      rpcClassification: redactRpcEndpoint(process.env.PHILCORE_SEPOLIA_RPC_URL),
      checkedAt: checkedAt.toISOString(),
      freshUntil: new Date(checkedAt.getTime() + OBSERVATION_FRESHNESS_MS).toISOString()
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
    deployerObservation: {
      address: deployer,
      configuredNonceInLocalEnvironment: process.env.PHILCORE_SEPOLIA_DEPLOYER_NONCE,
      previousObservedNonce: previousManifest.proposedAddresses.targetDeploymentNonce,
      latestNonce,
      pendingNonce,
      nonceChangedSinceO20:
        pendingNonce !== previousManifest.proposedAddresses.targetDeploymentNonce,
      pendingTransactionsPresent: latestNonce !== pendingNonce,
      balanceWei: preflight.deployer.balanceWei
    },
    addressSequence: {
      targetDeploymentNonce: addresses.targetDeploymentNonce,
      targetAddress: addresses.targetAddress,
      factoryDeploymentNonce: addresses.factoryDeploymentNonce,
      factoryAddress: addresses.factoryAddress,
      accountSalt: addresses.inputs.accountSalt,
      counterfactualAccountAddress: addresses.accountAddress,
      previousAddresses,
      addressesChangedSinceO20:
        Object.keys(currentAddresses).some((key) =>
          currentAddresses[key].toLowerCase() !== previousAddresses[key].toLowerCase()
        ),
      currentCollisionChecks: preflight.proposedAddresses,
      currentAddressHistory,
      previousAddressHistory: previousAddressObservations,
      unexpectedCollision: false
    },
    initialization,
    firstOperationTemplate: {
      status: "NOT_SUBMISSION_READY",
      action:
        "atomic counterfactual account deployment and one zero-value confirmation",
      accountMethod:
        "executeLocalProofAuthorization(bytes32,bytes32,uint64)",
      targetMethod: "confirmPhilCoreAction(bytes32,bytes32)",
      sender: addresses.accountAddress,
      nonceTemplate: "fresh EntryPoint getNonce(sender,0) required",
      initCode: initialization.entryPointInitCode,
      callDataTemplate:
        "0x44413cab || abi.encode(fresh actionId,fresh authorizationDigest,fresh expiry)",
      valueWei: "0",
      tokenMovement: false,
      approvalCall: false,
      batching: false,
      delegatecall: false,
      arbitraryExecution: false,
      paymaster: false,
      recoveryOperation: false,
      signature: "0x",
      freshExecutionFields: [
        "actionId",
        "authorizationDigest",
        "proofArtifactDigest",
        "publicNullifier",
        "proofVerificationEvidence",
        "preparationApproval",
        "signingApproval",
        "freshPresenceEvidence",
        "expiry",
        "accountNonce",
        "gasLimits",
        "feeValues",
        "userOperationHash",
        "DeviceVaultSignature"
      ],
      reusedO21AuthorizationOrSignature: false
    },
    gasEstimates: {
      liveReadOnly: liveGas,
      localDeterministic: localGas,
      bundler: {
        status: "BUNDLER_ESTIMATE_NOT_CONFIGURED",
        contacted: false,
        approved: false
      },
      ceilings: {
        verificationGas: LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxVerificationGasLimit.toString(),
        callGas: LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxCallGasLimit.toString(),
        preVerificationGas: LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxPreVerificationGas.toString(),
        maxFeePerGasWei: LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei.toString(),
        maxPriorityFeePerGasWei:
          LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxPriorityFeePerGasWei.toString(),
        authorizationLifetimeSeconds:
          LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxAuthorizationLifetimeSeconds.toString()
      }
    },
    fundingReference: path.relative(ROOT, FUNDING_PATH),
    unresolvedRequirements: [
      "human acceptance of current source, compiler, artifacts, and addresses",
      "fresh pre-deployment nonce and collision checks",
      "separate target deployment approval",
      "separate factory deployment approval",
      "approved ERC-4337 v0.7 bundler",
      "exact bundler UserOperation gas and prefund estimate",
      "approved disposable funding amounts and hard exposure",
      "fresh O.21.1 proof-backed preparation after deployment",
      "fresh O.21.2 signing approval, user presence, and Device Vault signature",
      "separate exact public UserOperation submission approval"
    ],
    approvals: {
      publicNetwork: false,
      ethereumSepolia: false,
      experimentalSecurityModel: false,
      targetDeployment: false,
      factoryDeployment: false,
      accountFunding: false,
      freshProtectedPreparation: false,
      deviceVaultSigning: false,
      bundlerSubmission: false
    },
    mutationState: {
      rpcMethodsReadOnly: true,
      mutationMethodsExposed: false,
      contractDeployed: false,
      addressFunded: false,
      transactionSigned: false,
      userOperationSigned: false,
      transactionSubmitted: false,
      userOperationSubmitted: false,
      publicMutationOccurred: false
    },
    acp0002Status: "Proposed",
    betaApproved: false,
    productionApproved: false
  };
  ensureNoSecrets(proposal);
  ensureNoSecrets(funding);
  writeJson(PROPOSAL_PATH, proposal);
  writeJson(FUNDING_PATH, funding);
  process.stdout.write(`${JSON.stringify({
    status: "O22_READINESS_PROPOSAL_CREATED",
    sourceCommitAtGeneration: head,
    chainId,
    latestNonce,
    pendingNonce,
    addresses: currentAddresses,
    addressesChangedSinceO20: proposal.addressSequence.addressesChangedSinceO20,
    bundlerStatus: proposal.gasEstimates.bundler.status,
    manifestStatus: proposal.status,
    accepted: proposal.accepted,
    publicMutationOccurred: false,
    rpcClassification: proposal.network.rpcClassification,
    files: [
      path.relative(ROOT, PROPOSAL_PATH),
      path.relative(ROOT, FUNDING_PATH)
    ]
  }, null, 2)}\n`);
}

module.exports = {
  artifactBindings,
  compilerBinding,
  ensureNoCollision,
  fundingReadiness,
  sourceBinding,
  validateO22Proposal
};

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
