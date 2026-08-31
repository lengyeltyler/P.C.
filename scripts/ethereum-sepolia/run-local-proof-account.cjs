require("tsx/cjs");

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { keccak256 } = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  calculateLocalProofGatedProposedAddresses,
  createRestrictedSepoliaReadOnlyClient,
  deriveLocalProofGatedValidatorKeyIdBinding,
  evaluateLocalProofGatedMutationGate,
  redactRpcEndpoint,
  runLocalProofGatedPreparationPreflight
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");

const ROOT = path.resolve(__dirname, "../..");
const MANIFEST_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/LOCAL_PROOF_GATED_DEPLOYMENT_MANIFEST_PROPOSED.json"
);
const MUTATION_STAGES = new Set([
  "deploy-confirmation-target",
  "deploy-account-implementation",
  "deploy-account-factory",
  "fund-local-proof-account",
  "submit-first-userop"
]);
const MUTATION_STAGE_KIND = Object.freeze({
  "deploy-confirmation-target": "target_deployment",
  "deploy-account-factory": "factory_deployment",
  "fund-local-proof-account": "account_funding",
  "submit-first-userop": "first_user_operation_submission"
});
const SOURCE_BINDING_PATHS = Object.freeze([
  "contracts/base/PhilCoreLocalProofConfirmationTargetV1.sol",
  "contracts/base/interfaces/IPhilCoreLocalProofAccountV1.sol",
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol",
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol",
  "apps/phil-device-sdk/src/runtime/localProofGatedAccount.ts",
  "apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts",
  "apps/phil-device-sdk/src/runtime/deviceVaultEcdsaCustody.ts",
  "apps/phil-device-sdk/src/runtime/philcore4337UserOperationSigning.ts",
  "scripts/ethereum-sepolia/run-local-proof-account.cjs",
  "scripts/ethereum-sepolia/prepare-local-proof-package.cjs",
  "scripts/ethereum-sepolia/local-environment.cjs"
]);

function runGit(args) {
  return spawnSync("git", args, {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }
  });
}

function verifySourceBinding(manifest) {
  const sourceCommit = manifest.sourceCommit;
  const revision = runGit(["rev-parse", "--verify", `${sourceCommit}^{commit}`]);
  const status = runGit(["status", "--porcelain=v1"]);
  const diff = revision.status === 0
    ? runGit(["diff", "--quiet", sourceCommit, "--", ...SOURCE_BINDING_PATHS])
    : { status: 2 };
  const implementationPathsMatch = diff.status === 0;
  const repositoryClean = status.status === 0 && status.stdout.trim().length === 0;
  return {
    valid: revision.status === 0 && implementationPathsMatch && repositoryClean,
    sourceCommit,
    sourceCommitExists: revision.status === 0,
    implementationPathsMatch,
    repositoryClean,
    paths: SOURCE_BINDING_PATHS
  };
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

function verifyBytecode(manifest) {
  const results = manifest.contracts.map((contract) => {
    const location = artifactPath(contract.contract);
    if (!fs.existsSync(location)) {
      return { contract: contract.contract, valid: false, error: "artifact_missing" };
    }
    const artifact = JSON.parse(fs.readFileSync(location, "utf8"));
    const creationBytecodeHash = keccak256(artifact.bytecode);
    const deployedBytecodeHash = keccak256(artifact.deployedBytecode);
    return {
      contract: contract.contract,
      valid:
        creationBytecodeHash === contract.creationBytecodeHash
        && deployedBytecodeHash === contract.deployedBytecodeHash,
      creationBytecodeHash,
      deployedBytecodeHash
    };
  });
  return { valid: results.every((result) => result.valid), results };
}

function calculateAddresses(manifest) {
  const account = manifest.contracts.find((candidate) =>
    candidate.contract === "PhilCore4337LocalProofAccountV1"
  );
  const artifact = account ? JSON.parse(fs.readFileSync(artifactPath(account.contract), "utf8")) : {};
  const validatorKeyReferenceId = process.env.PHILCORE_SEPOLIA_VALIDATOR_KEY_ID;
  const validatorKeyId = validatorKeyReferenceId
    ? deriveLocalProofGatedValidatorKeyIdBinding(validatorKeyReferenceId)
    : process.env.PHILCORE_LOCAL_PROOF_VALIDATOR_KEY_ID;
  return calculateLocalProofGatedProposedAddresses({
    deployerAddress: process.env.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS,
    deployerNonce: process.env.PHILCORE_SEPOLIA_DEPLOYER_NONCE,
    ownerAddress:
      process.env.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS
      ?? process.env.PHILCORE_LOCAL_PROOF_VALIDATOR_ADDRESS,
    ownerCommitment:
      process.env.PHILCORE_SEPOLIA_OWNER_COMMITMENT
      ?? process.env.PHILCORE_LOCAL_PROOF_OWNER_COMMITMENT,
    validatorKeyId,
    accountSalt:
      process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT
      ?? process.env.PHILCORE_LOCAL_PROOF_ACCOUNT_SALT,
    accountCreationBytecode: artifact.bytecode
  });
}

function mutationErrors(stage, manifest, sourceBinding, bytecode) {
  if (stage === "deploy-account-implementation") {
    return ["standalone_account_implementation_deployment_not_supported"];
  }
  const result = evaluateLocalProofGatedMutationGate({
    stage: MUTATION_STAGE_KIND[stage],
    environment: process.env,
    manifestStatus: manifest.status,
    architectureApprovalStatus: manifest.approval.architectureApprovalStatus,
    repositoryClean: sourceBinding.repositoryClean
  });
  const errors = [...result.errors];
  if (manifest.approval.acp0002Status !== "Proposed") errors.push("acp_0002_status_changed");
  if (manifest.network.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) errors.push("chain_id_mismatch");
  if (manifest.network.entryPointAddress !== ERC4337_V07_CANONICAL_ENTRYPOINT) {
    errors.push("entry_point_mismatch");
  }
  if (!sourceBinding.sourceCommitExists) errors.push("source_commit_missing");
  if (!sourceBinding.implementationPathsMatch) errors.push("source_binding_mismatch");
  if (!bytecode.valid) errors.push("bytecode_hash_mismatch");
  return errors;
}

async function main() {
  const stageIndex = process.argv.indexOf("--stage");
  const stage = stageIndex >= 0 ? process.argv[stageIndex + 1] : "inspect-config";
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  const bytecode = verifyBytecode(manifest);
  const sourceBinding = verifySourceBinding(manifest);
  const addresses = calculateAddresses(manifest);
  const common = {
    phase: "O.20",
    stage,
    securityModel: manifest.security.securityModel,
    manifestStatus: manifest.status,
    bytecode,
    sourceBinding,
    addresses,
    publicMutationPerformed: false,
    transactionSigned: false,
    transactionSubmitted: false,
    userOperationSubmitted: false
  };

  if (stage === "read-only-preflight") {
    const rpcUrl = process.env.PHILCORE_SEPOLIA_RPC_URL;
    const client = rpcUrl
      ? createRestrictedSepoliaReadOnlyClient({ url: rpcUrl })
      : undefined;
    const result = await runLocalProofGatedPreparationPreflight({
      client,
      proposedAddresses: addresses.status === "calculated"
        ? {
            confirmationTarget: addresses.targetAddress,
            accountFactory: addresses.factoryAddress,
            firstAccount: addresses.accountAddress
          }
        : undefined
    });
    process.stdout.write(`${JSON.stringify({ ...common, preflight: result }, null, 2)}\n`);
    process.exitCode = result.status === "READ_ONLY_PREFLIGHT_FAILED" ? 1 : 0;
    return;
  }

  if (MUTATION_STAGES.has(stage)) {
    const errors = mutationErrors(stage, manifest, sourceBinding, bytecode);
    process.stdout.write(`${JSON.stringify({
      ...common,
      mode: "dry_run_mutation_blocked",
      allowed: false,
      transportImplemented: false,
      rpcClassification: redactRpcEndpoint(process.env.PHILCORE_SEPOLIA_RPC_URL),
      errors
    }, null, 2)}\n`);
    process.exitCode = 2;
    return;
  }

  const supported = new Set([
    "inspect-config",
    "calculate-addresses",
    "verify-bytecode",
    "estimate-deployment",
    "prepare-manifest",
    "manifest-diff",
    "prepare-evidence",
    "display-deployment-plan",
    "verify-contracts",
    "prepare-first-userop",
    "simulate-first-userop",
    "display-first-userop",
    "reconcile-first-userop"
  ]);
  if (!supported.has(stage)) throw new Error(`Unsupported local-proof account stage: ${stage}`);
  process.stdout.write(`${JSON.stringify({
    ...common,
    status: bytecode.valid ? "LOCAL_PROPOSAL_VALID" : "LOCAL_PROPOSAL_INVALID",
    deterministicAddressesCalculated: addresses.status === "calculated",
    reason: addresses.status === "calculated"
      ? "explicit public proposal inputs supplied; addresses remain proposed only"
      : "disposable deployer/validator public inputs remain unresolved",
    manifestDiff: stage === "manifest-diff"
      ? {
          currentStatus: manifest.status,
          hypotheticalStatus: "accepted",
          changesRequired: [
            "accepted deployment addresses",
            "live read-only collision checks",
            "live gas and fee evidence",
            "independent deployment approval"
          ],
          manifestChanged: false
        }
      : undefined,
    rpcContacted: false
  }, null, 2)}\n`);
  if (!bytecode.valid) process.exitCode = 1;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
