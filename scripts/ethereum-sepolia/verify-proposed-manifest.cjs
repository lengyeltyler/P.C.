const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { keccak256 } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const MANIFEST_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/ETHEREUM_SEPOLIA_DEPLOYMENT_MANIFEST_PROPOSED.json"
);
const ARTIFACT_PATHS = new Map([
  ["PhilL1ProofInputHashAnchor", "artifacts/contracts/l1/PhilL1ProofInputHashAnchor.sol/PhilL1ProofInputHashAnchor.json"],
  ["PhilL1FactUnlockProofVerifier", "artifacts/contracts/base/PhilL1FactUnlockProofVerifier.sol/PhilL1FactUnlockProofVerifier.json"],
  ["PhilBaseActionGate", "artifacts/contracts/base/PhilBaseActionGate.sol/PhilBaseActionGate.json"],
  ["PhilUnlockConsumer", "artifacts/contracts/base/PhilUnlockConsumer.sol/PhilUnlockConsumer.json"],
  ["PhilCoreAuthorizationConfirmationTarget", "artifacts/contracts/base/PhilCoreAuthorizationConfirmationTarget.sol/PhilCoreAuthorizationConfirmationTarget.json"],
  ["PhilCore4337AccountFactory", "artifacts/contracts/base/erc4337/PhilCore4337AccountFactory.sol/PhilCore4337AccountFactory.json"],
  ["PhilCore4337Account", "artifacts/contracts/base/erc4337/PhilCore4337Account.sol/PhilCore4337Account.json"]
]);

function main() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  const errors = [];
  if (manifest.status !== "proposed") errors.push("manifest status must remain proposed");
  if (manifest.network.chainId !== 11155111) errors.push("chain ID mismatch");
  if (manifest.entryPoint.version !== "0.7") errors.push("EntryPoint version mismatch");
  if (manifest.entryPoint.address.toLowerCase() !== "0x0000000071727de22e5e9d8baf0edac6f37da032") {
    errors.push("EntryPoint address mismatch");
  }
  for (const [field, value] of Object.entries(manifest.approval)) {
    if (field !== "acp0002Status" && value !== false) {
      errors.push(`approval.${field} must remain false`);
    }
  }
  if (manifest.approval.acp0002Status !== "Proposed") errors.push("ACP-0002 must remain Proposed");

  try {
    execFileSync("git", ["cat-file", "-e", `${manifest.sourceCommit}^{commit}`], {
      cwd: ROOT,
      stdio: "ignore"
    });
  } catch {
    errors.push("source commit is not available");
  }

  for (const contract of manifest.contracts) {
    const relativeArtifactPath = ARTIFACT_PATHS.get(contract.contract);
    if (!relativeArtifactPath) {
      errors.push(`artifact path missing for ${contract.contract}`);
      continue;
    }
    const artifactPath = path.join(ROOT, relativeArtifactPath);
    if (!fs.existsSync(artifactPath)) {
      errors.push(`compiled artifact missing for ${contract.contract}`);
      continue;
    }
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
    const actualHash = keccak256(artifact.bytecode);
    if (actualHash.toLowerCase() !== String(contract.bytecodeHash).toLowerCase()) {
      errors.push(`bytecode hash mismatch for ${contract.contract}`);
    }
    if (contract.address !== null) errors.push(`${contract.contract} address must remain null`);
    if (contract.acceptanceStatus !== "not_accepted") {
      errors.push(`${contract.contract} must remain not accepted`);
    }
  }

  process.stdout.write(JSON.stringify({
    valid: errors.length === 0,
    status: manifest.status,
    chainId: manifest.network.chainId,
    sourceCommit: manifest.sourceCommit,
    contractsVerified: manifest.contracts.length,
    publicMutationPerformed: false,
    errors
  }, null, 2) + "\n");
  if (errors.length > 0) process.exitCode = 1;
}

main();
