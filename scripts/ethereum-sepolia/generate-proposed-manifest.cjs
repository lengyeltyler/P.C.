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

function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function sourceCommit() {
  return execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: ROOT,
    encoding: "utf8"
  }).trim();
}

function main() {
  const manifest = loadJson(MANIFEST_PATH);
  manifest.sourceCommit = sourceCommit();
  for (const contract of manifest.contracts) {
    const relativeArtifactPath = ARTIFACT_PATHS.get(contract.contract);
    if (!relativeArtifactPath) {
      throw new Error(`No artifact path configured for ${contract.contract}`);
    }
    const artifactPath = path.join(ROOT, relativeArtifactPath);
    if (!fs.existsSync(artifactPath)) {
      throw new Error(`Missing compiled artifact: ${relativeArtifactPath}`);
    }
    const artifact = loadJson(artifactPath);
    if (typeof artifact.bytecode !== "string" || artifact.bytecode === "0x") {
      throw new Error(`Compiled bytecode missing for ${contract.contract}`);
    }
    contract.bytecodeHash = keccak256(artifact.bytecode);
  }
  fs.writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(JSON.stringify({
    status: manifest.status,
    chainId: manifest.network.chainId,
    entryPoint: manifest.entryPoint.address,
    sourceCommit: manifest.sourceCommit,
    contractsHashed: manifest.contracts.length,
    publicMutationPerformed: false
  }, null, 2) + "\n");
}

main();
