"use strict";

const fs = require("node:fs");
const { ethers } = require("ethers");
const p5 = require("./philcore-controlled-sepolia-beta-p5-common.cjs");

function loadExactlyOnePlan(planPaths) {
  if (!Array.isArray(planPaths) || planPaths.length !== 1) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_EXACTLY_ONE_PLAN_REQUIRED");
  }
  const planPath = planPaths[0];
  if (!planPath || !fs.existsSync(planPath)) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_UNSIGNED_PLAN_MISSING");
  }
  const planBytes = fs.readFileSync(planPath);
  let plan;
  try { plan = JSON.parse(planBytes); } catch {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_UNSIGNED_PLAN_CORRUPT");
  }
  return Object.freeze({ plan, planBytes, planPath });
}

function createSignedArtifact({ plan, planBytes, config, signature }) {
  if (plan.approval?.approved !== false) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_PLAN_ALREADY_APPROVED_BEFORE_SIGNING");
  }
  p5.assertPlanIntegrity(plan, config);
  const unsigned = p5.assertUnsignedOperationBinding(plan, config).userOperation;
  const signedOperation = Object.freeze({ ...unsigned, signature });
  const stableHash = p5.computePhilCore4337UserOperationHash({
    userOperation: signedOperation,
    entryPointAddress: plan.entryPoint,
    chainId: Number(plan.chainId)
  });
  if (stableHash.toLowerCase() !== plan.userOperation.hash.toLowerCase()) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_SIGNING_HASH_CHANGED");
  }
  let recovered;
  try {
    recovered = ethers.verifyMessage(ethers.getBytes(stableHash), signature);
  } catch {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_OWNER_SIGNATURE_INVALID");
  }
  if (!p5.sameAddress(recovered, plan.account.owner)) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_OWNER_SIGNATURE_INVALID");
  }
  return Object.freeze({
    format: p5.ARTIFACT_FORMAT,
    version: 2,
    stageId: p5.STAGE_ID,
    lineageId: plan.lineageId,
    signed: true,
    submitted: false,
    planDigest: plan.planDigest,
    planCanonicalSha256: p5.canonicalSha256(plan),
    planByteSha256: p5.sha256Bytes(planBytes),
    source: plan.source,
    owner: ethers.getAddress(recovered),
    additionalFundingWei: "0",
    userOperationHash: stableHash,
    userOperation: signedOperation
  });
}

async function signPlanWithDependencies({ plan, planBytes, config, signer, readState,
  sourceMatches = p5.sourceIdentityMatches, outputPath,
  persist = p5.atomicCreateJson }) {
  if (plan.approval?.approved !== false) {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_PLAN_ALREADY_APPROVED_BEFORE_SIGNING");
  }
  p5.assertPlanIntegrity(plan, config);
  if (!sourceMatches(plan.source)) {
    p5.fail("PHILCORE_CONTROLLED_BETA_SOURCE_IDENTITY_CHANGED");
  }
  if (typeof readState !== "function") {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_SIGNING_REVALIDATION_REQUIRED");
  }
  const live = await readState();
  p5.assertStateEqualsPlan(live, plan.account);
  if (!signer || typeof signer.signUserOperationHash !== "function") {
    p5.fail("PHILCORE_CONTROLLED_BETA_P5_CONFIGURED_CUSTODY_REQUIRED");
  }
  if (typeof signer.getOwnerAddress === "function") {
    const custodyOwner = await signer.getOwnerAddress();
    if (!p5.sameAddress(custodyOwner, plan.account.owner)) {
      p5.fail("PHILCORE_CONTROLLED_BETA_P5_CUSTODY_OWNER_MISMATCH");
    }
  }
  const signingResult = await signer.signUserOperationHash({
    userOperationHash: plan.userOperation.hash,
    expectedOwner: plan.account.owner,
    chainId: Number(plan.chainId),
    entryPointAddress: plan.entryPoint,
    smartAccountAddress: plan.account.account,
    nonce: plan.account.nonce,
    callDataHash: plan.cleanup.callDataHash,
    planDigest: plan.planDigest
  });
  const signature = signingResult?.status === "signed" && signingResult.signature;
  if (!signature) p5.fail("PHILCORE_CONTROLLED_BETA_P5_CUSTODY_SIGNING_REJECTED");
  const artifact = createSignedArtifact({ plan, planBytes, config, signature });
  const exactOutputPath = outputPath ?? p5.lineagePaths(plan.lineageId).signedArtifact;
  persist(exactOutputPath, artifact);
  return artifact;
}

async function signPlanFilesWithDependencies({ planPaths, ...dependencies }) {
  const loaded = loadExactlyOnePlan(planPaths);
  return signPlanWithDependencies({
    ...dependencies,
    plan: loaded.plan,
    planBytes: loaded.planBytes
  });
}

module.exports = {
  loadExactlyOnePlan,
  createSignedArtifact,
  signPlanWithDependencies,
  signPlanFilesWithDependencies
};
