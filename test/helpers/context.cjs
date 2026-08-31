const assert = require("node:assert/strict");

const hre = require("hardhat");
const { ethers: standaloneEthers } = require("ethers");

const artifactCache = new Map();

async function getArtifact(contractName) {
  if (!artifactCache.has(contractName)) {
    artifactCache.set(contractName, await hre.artifacts.readArtifact(contractName));
  }
  return artifactCache.get(contractName);
}

async function deployContract(signer, contractName, args = []) {
  const artifact = await getArtifact(contractName);
  const factory = new standaloneEthers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

async function expectRevert(send, label = "expected revert") {
  try {
    const result = await send();
    if (result && typeof result === "object" && typeof result.wait === "function") {
      await result.wait();
    }
    assert.fail(label);
  } catch (error) {
    const message = String(
      (error && typeof error === "object" && "shortMessage" in error && error.shortMessage) ||
        (error && typeof error === "object" && "message" in error && error.message) ||
        error
    );

    assert.match(
      message,
      /(revert|reverted|CALL_EXCEPTION|custom error|missing revert data)/i,
      `${label}: expected a revert-style failure, received ${message}`
    );
  }
}

module.exports = {
  deployContract,
  expectRevert
};
