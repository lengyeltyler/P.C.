#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const readJson = (relative) => JSON.parse(fs.readFileSync(path.join(root, relative), "utf8"));
const exists = (relative) => fs.existsSync(path.join(root, relative));

const profile = readJson("config/controlled-sepolia-beta-v1.json");
const audit = readJson("config/security/philcore-controlled-sepolia-beta-audit-scope-v1.json");
const invariants = readJson("config/security/philcore-contract-invariants-report.json");
const staticAnalysis = readJson("config/security/philcore-solidity-static-analysis.json");
const dependency = readJson("config/security/philcore-npm-audit-report.json");

const scopedFiles = [
  ...audit.architecture,
  ...audit.contracts,
  ...audit.localAuthorizationRuntime,
  ...audit.publicMutationControl,
  ...audit.securityEvidence,
  ...audit.requiredAdversarialTests
];
const protectedPath = path.join(root, "pqREADME.md");
const protectedHash = exists("pqREADME.md")
  ? crypto.createHash("sha256").update(fs.readFileSync(protectedPath)).digest("hex")
  : null;

const checks = [
  ["profile_chain", profile.network.chainId === 11155111],
  ["mainnet_prohibited", profile.release.mainnetAllowed === false && audit.network.mainnetAuthorized === false],
  ["action_zero_value", profile.ordinaryAction.maximumValueWei === "0"],
  ["paymaster_prohibited", profile.account.paymasterAllowed === false],
  ["meaningful_assets_prohibited", profile.funding.meaningfulAssetsAllowed === false],
  ["automatic_retry_prohibited", profile.ordinaryAction.automaticRetry === false],
  ["scope_files_present", scopedFiles.every(exists)],
  ["contract_invariants_pass", invariants.status === "passed" && invariants.checks.length === 41],
  ["slither_has_no_beta_blocker", staticAnalysis.triageSummary.betaBlocking === 0],
  ["production_dependency_audit_clean", dependency.productionAudit.metadata.vulnerabilities.total === 0],
  ["independent_ai_corrective_review_recorded", audit.internalEvidence.independentAiReviewComplete === true
    && audit.internalEvidence.independentAiReviewCommit === "8fac929bb12bc46a4eb792fc8fef2f6408c7fd1a"
    && audit.internalEvidence.independentAiReviewUnresolvedCritical === 0
    && audit.internalEvidence.independentAiReviewUnresolvedHigh === 0
    && audit.internalEvidence.p1RunnerExactSourceReviewComplete === true
    && audit.internalEvidence.p1RunnerReviewedCommit === "5e68d23d67f25d2b6b4b0edff8cbdb4f1c2bb234"
    && audit.internalEvidence.p1RunnerReviewedTree === "587161741f98c514141a23d25bd4309073e8c85a"
    && audit.internalEvidence.p1RunnerUnresolvedCritical === 0
    && audit.internalEvidence.p1RunnerUnresolvedHigh === 0
    && audit.internalEvidence.p1RecoveryRunnerExactSourceReviewComplete === true
    && audit.internalEvidence.p1RecoveryRunnerReviewedCommit === "64eb809859f8612dc09ee2302729747efdc700b9"
    && audit.internalEvidence.p1RecoveryRunnerReviewedTree === "edd6005ab8f28868a7efa5d4b7b49ad95afaa468"
    && audit.internalEvidence.p1RecoveryRunnerUnresolvedCritical === 0
    && audit.internalEvidence.p1RecoveryRunnerUnresolvedHigh === 0
    && audit.internalEvidence.p2RunnerExactSourceReviewComplete === true
    && audit.internalEvidence.p2RunnerReviewedCommit === "b6341e294045050c0bb5bb7e265a338968849692"
    && audit.internalEvidence.p2RunnerReviewedTree === "150df1d6e0e62b541a96337a9a3bfc707bbd1b8a"
    && audit.internalEvidence.p2RunnerReviewReportSha256 === "cc690ffe2a642a58120dfde81116658390aabd2663ccd046f17cf207e58a13d0"
    && audit.internalEvidence.p2RunnerUnresolvedCritical === 0
    && audit.internalEvidence.p2RunnerUnresolvedHigh === 0
    && audit.internalEvidence.p2AccountDeploymentConfirmed === true
    && audit.internalEvidence.p2FinalUserOperationConfirmed === true
    && audit.internalEvidence.p2FinalEntryPointNonce === 1
    && audit.internalEvidence.p2FinalPassTokenId === 1
    && audit.internalEvidence.p2AutomaticRetryOccurred === false],
  ["professional_audit_not_falsely_claimed", audit.internalEvidence.professionalExternalAuditComplete === false],
  ["owner_ai_only_risk_acceptance_recorded", audit.internalEvidence.ownerRiskAcceptance === "AI_REVIEW_PLUS_OWNER_RISK_ACCEPTANCE"],
  ["provider_acceptance_recorded_without_credentials", audit.internalEvidence.providerAcceptance.chainAgreement === true
    && audit.internalEvidence.providerAcceptance.bundlerEntryPointV07Accepted === true
    && audit.internalEvidence.providerAcceptance.credentialMaterialTracked === false
    && audit.internalEvidence.p2FinalReconciliation.providersAgree === true
    && audit.internalEvidence.p2FinalReconciliation.credentialMaterialTracked === false],
  ["public_mutation_not_falsely_claimed", audit.publicMutationAuthorized === false],
  ["protected_file_unchanged", protectedHash === "7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8"]
].map(([id, passed]) => ({ id, passed }));

const failed = checks.filter((check) => !check.passed);
const result = {
  format: "philcore-controlled-sepolia-beta-candidate-check-v1",
  status: failed.length === 0 ? "internal_candidate_prepared_external_gates_open" : "failed",
  checks,
  failed,
  internalCandidatePrepared: failed.length === 0,
  betaReady: false,
  publicMutationAuthorized: false,
  releaseBlockers: audit.releaseBlockers
};

process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (failed.length > 0) process.exitCode = 1;
