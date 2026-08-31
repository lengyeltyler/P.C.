#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const configPath = path.join(repoRoot, "config/security/philcore-recovery-authority-rotation.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
const json = process.argv.includes("--json");

const diagnostic = {
  phase: config.phase,
  boundary: config.boundary,
  status: config.status,
  selectedModel: config.selectedModel,
  requesters: config.authorityRules.requesters,
  canceller: config.authorityRules.canceller,
  completionPermissionlessAfterDelay: config.contract.completionPermissionlessAfterDelay,
  recoveryAuthorityOrdinaryExecutionAuthority: config.authorityRules.recoveryAuthorityOrdinaryExecutionAuthority,
  recoveryAuthorityAssetTransferAuthority: config.authorityRules.recoveryAuthorityAssetTransferAuthority,
  recoveryAuthorityActionGateBypass: config.authorityRules.recoveryAuthorityActionGateBypass,
  accountAddressChanged: config.immutability.accountAddressChanged,
  ownerCommitmentChanged: config.immutability.ownerCommitmentChanged,
  entryPointChanged: config.immutability.entryPointChanged,
  actionGateChanged: config.immutability.actionGateChanged,
  localAlphaApproval: config.localAlphaApproval,
  baseSepoliaBetaApproval: config.baseSepoliaBetaApproval,
  productionApproval: config.productionApproval,
  liveAccountTouched: false,
  userOperationSigned: false,
  userOperationSubmitted: false,
  vaultAccessed: false,
  privateKeyExposed: false,
  chainStateMutated: false
};

if (json) {
  process.stdout.write(`${JSON.stringify(diagnostic, null, 2)}\n`);
} else {
  process.stdout.write([
    "PhilCore recovery authority rotation diagnostic",
    `phase: ${diagnostic.phase}`,
    `status: ${diagnostic.status}`,
    `model: ${diagnostic.selectedModel}`,
    `requesters: ${diagnostic.requesters.join(", ")}`,
    `canceller: ${diagnostic.canceller}`,
    `completion permissionless after delay: ${diagnostic.completionPermissionlessAfterDelay}`,
    "no vault access, no signing, no submission, no chain mutation",
    ""
  ].join("\n"));
}
