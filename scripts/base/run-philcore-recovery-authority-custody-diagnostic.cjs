#!/usr/bin/env node

const mode = process.argv.find((arg) => arg.startsWith("--mode="))?.slice("--mode=".length) ?? "custody";

const report = {
  diagnostic: "philcore_recovery_authority_custody",
  mode,
  environment: "local_fixture_only",
  publicNetworkMutation: false,
  publicBundlerSubmission: false,
  liveAccountDeployment: false,
  paymasterInvoked: false,
  normalConsumerExecution: false,
  nullifierConsumed: false,
  privateRecoveryKeyPrinted: false,
  productionRecoveryAuthorityActivated: false,
  supportedActions: [
    "requestRecovery(address)",
    "completeRecovery(bytes32,address)"
  ],
  cancellationAuthority: "current_owner_or_entrypoint_owner_signature_only",
  recoveryAuthorityRestrictions: {
    canExecuteOrdinaryActions: false,
    canTransferAssets: false,
    canCallActionGateDirectly: false,
    canChangeEntryPoint: false,
    canChangeActionGate: false,
    canChangeOwnerCommitment: false,
    canUsePaymaster: false,
    canUseSessionKeys: false
  },
  betaGate: {
    status: "blocked",
    reason: "ACP-0002 remains Proposed; N.6 Slither/static analysis is reproducible, but high tooling advisories, recovery-authority rotation disposition, deployments, external audit, and public submission approvals remain incomplete."
  }
};

console.log(JSON.stringify(report, null, 2));
