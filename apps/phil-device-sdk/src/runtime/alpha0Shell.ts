import { createInterface } from "node:readline/promises";
import * as nodeCrypto from "node:crypto";
import {
  dataHash,
  nullifier as deriveNullifier,
  policyHash as derivePolicyHash
} from "../hashes.ts";
import {
  createEncryptedDeviceIdentityRegistryStore,
  createInMemoryDeviceIdentityRegistryStorageBackend,
  createLocalDevPassphraseKeyProvider
} from "../deviceIdentityStorage.ts";
import { createPhilCredentialRegistry } from "../deviceIdentityLifecycle.ts";
import { arrayBufferToBase64Url } from "../deviceIdentityWebAuthn.ts";
import { createPhilIdentityPrivate, derivePhilIdentityPublic } from "../identity.ts";
import {
  ALPHA0_DEMO_SCENARIOS,
  isAlpha0DemoScenario,
  runNonAuthoritativeAlpha0Demo,
  type Alpha0DemoResult,
  type Alpha0DemoScenario,
  type Alpha0DemoStage
} from "./alpha0Demo.ts";
import {
  createProductionAuthenticationRequest,
  createDeveloperFixtureAuthenticationProviderAdapter,
  type ProductionAuthenticationRequirement
} from "./authenticationEvidence.ts";
import {
  createEphemeralFixtureEvidenceConsumptionStore,
  transitionUserSessionWithVerifiedFixtureEvidence,
  verifyDeveloperFixtureAuthenticationEvidence,
  type FixtureAuthenticationVerificationArtifact
} from "./fixtureAuthenticationLifecycle.ts";
import {
  createEphemeralProductionVerificationConsumptionStore,
  createLifecycleTransitionCandidate,
  transitionUserSessionWithProductionVerification,
  type LifecycleTransitionCandidate,
  type ProductionVerifiedPartialUnlockResultValue
} from "./productionVerifiedPartialUnlock.ts";
import {
  createEphemeralVaultUnlockConsumptionStore,
  transitionUserSessionWithVerifiedVaultUnlock,
  verifyDeviceVaultUnlock,
  type DeviceVaultUnlockResultValue,
  type VerifiedVaultSessionUnlockResultValue
} from "./deviceVaultUnlock.ts";
import {
  createProtectedStateView,
  type ProtectedStateViewResultValue
} from "./protectedStateView.ts";
import {
  requestPublicCredentialDirectory,
  type PublicCredentialDirectoryResultValue
} from "./publicCredentialDirectory.ts";
import {
  requestSelectedCredentialPublicMaterial,
  type SelectedCredentialPublicMaterialResultValue
} from "./selectedCredentialPublicMaterial.ts";
import {
  createTrustManagerVerificationInput,
  type TrustManagerVerificationInputResultValue
} from "./trustManagerVerificationInput.ts";
import {
  evaluateBoundedTrustDecisionCandidate,
  type BoundedTrustDecisionCandidate
} from "./boundedTrustDecisionCandidate.ts";
import {
  persistVerifiedCredentialCounter,
  resolveCounterPersistenceRequirement,
  type CredentialCounterPersistenceReceipt,
  type TrustDecisionCandidateCounterResolution
} from "./credentialCounterPersistence.ts";
import {
  createEphemeralTrustManagerVerificationConsumptionStore,
  verifyTrustManagerProductionAssertion,
  type TrustManagerProductionVerificationResultValue
} from "./trustManagerProductionVerification.ts";
import {
  createEphemeralTrustDecisionEvidenceConsumptionStore,
  createAuthoritativeTrustDecision,
  type AuthoritativeTrustDecision
} from "./authoritativeTrustDecision.ts";
import {
  createEphemeralPolicyDecisionEvidenceConsumptionStore,
  createAuthoritativePolicyDecision,
  type AuthoritativePolicyDecision
} from "./authoritativePolicyDecision.ts";
import {
  createEphemeralUserApprovalArtifactConsumptionStore,
  createPlatformUserApprovalDecision,
  createPlatformUserApprovalRequest,
  createUserApprovalPresentationDigest,
  type PlatformUserApprovalDecision,
  type PlatformUserApprovalDecisionOutcome,
  type PlatformUserApprovalDecisionResult,
  type UserApprovalPresentationSummary
} from "./platformUserApprovalDecision.ts";
import {
  createAuthoritativeCapabilityGrant,
  createEphemeralCapabilityActivationEvidenceConsumptionStore,
  createInMemoryAuthoritativeCapabilityGrantStore,
  type AuthoritativeCapabilityGrant,
  type UserSessionCapabilityMutationResult
} from "./authoritativeCapabilityGrant.ts";
import {
  createAuthorizationActionDigestPreview,
  createAuthorizationDecisionCandidate,
  createEphemeralAuthorizationCandidateConsumptionStore,
  createInMemoryAuthorizationDecisionCandidateStore,
  type AuthorizationActionType,
  type AuthorizationDecisionCandidate,
  type AuthorizationDecisionCandidateActionSummary
} from "./authorizationDecisionCandidate.ts";
import {
  createAuthorizationPackageDraft,
  createEphemeralAuthorizationPackageDraftConsumptionStore,
  createInMemoryAuthorizationPackageDraftStore,
  deriveCanonicalAuthorizationActionHash,
  type AuthorizationPackageDraft
} from "./authorizationPackageDraft.ts";
import {
  createEphemeralActionUnlockProofGenerationConsumptionStore,
  createInMemoryActionUnlockProofGenerationArtifactStore,
  createStaticActionUnlockProtectedWitnessProvider,
  generateActionUnlockProof,
  type ActionUnlockProofGenerationArtifact
} from "./actionUnlockProofGeneration.ts";
import {
  createEphemeralActionUnlockProofVerificationConsumptionStore,
  createEphemeralFinalizedAuthorizationPackageConsumptionStore,
  createInMemoryActionUnlockProofVerificationResultStore,
  createInMemoryFinalizedAuthorizationPackageStore,
  finalizeAuthorizationPackage,
  verifyGeneratedActionUnlockProof,
  type ActionUnlockProofVerificationResultValue,
  type FinalizedAuthorizationPackage
} from "./actionUnlockProofFinalization.ts";
import {
  createFixtureAuthorizationNullifierStateReader,
  createFixtureVerifiedFactStateReader,
  createInMemoryAuthorizationExecutionReadinessResultStore,
  createInMemoryVerifiedFactPublicationRequestDraftStore,
  createVerifiedFactPublicationRequestDraft,
  evaluateAuthorizationExecutionReadiness,
  type AuthorizationExecutionReadinessResultValue,
  type AuthorizationNullifierState,
  type VerifiedFactPublicationRequestDraft,
  type VerifiedFactPublicationTarget,
  type VerifiedFactState
} from "./authorizationExecutionReadiness.ts";
import {
  verifyProductionWebAuthnAuthentication,
  type ProductionAuthenticationVerificationResultValue
} from "./productionAuthenticationVerification.ts";
import {
  USER_SESSION_LIFECYCLE_TRANSITION_TABLE,
  createEphemeralUserSessionLifecycleStore,
  isUserSessionLifecycleState,
  type UserSessionLifecycleEvent,
  type UserSessionLifecycleState,
  type UserSessionTransitionResult
} from "./sessionLifecycle.ts";

export type Alpha0LifecycleDiagnosticSequence =
  | "states"
  | "valid_unlock"
  | "fixture_unlock"
  | "production_webauthn_partial_unlock"
  | "production_webauthn_vault_unlock"
  | "production_protected_state_view"
  | "production_public_credential_directory"
  | "production_selected_credential_public_material"
  | "production_trust_manager_verification_input"
  | "production_trust_manager_assertion_verification"
  | "production_trust_decision_candidate"
  | "production_credential_counter_persistence"
  | "production_authoritative_trust_decision"
  | "production_authoritative_policy_decision"
  | "production_platform_user_approval_decision"
  | "production_authoritative_capability_activation"
  | "production_authorization_decision_candidate"
  | "production_authorization_package_draft"
  | "production_action_unlock_proof_generation"
  | "production_finalized_authorization_package"
  | "production_authorization_execution_readiness"
  | "invalid_transition"
  | "timeout"
  | "recovery";

export type Alpha0PlatformApprovalDiagnosticOutcome =
  | "approve"
  | "deny"
  | "cancel"
  | "expired"
  | "digest_mismatch";

export type Alpha0AuthorizationCandidateDiagnosticScenario =
  | "exact"
  | "capability_mismatch"
  | "scope_widening"
  | "target_mismatch"
  | "value_limit_exceeded"
  | "additional_approval_required";

export type Alpha0AuthorizationPackageDraftDiagnosticScenario =
  | "exact"
  | "mutated_action"
  | "invalid_nullifier"
  | "expiry_beyond_capability_grant"
  | "evidence_chain_mismatch"
  | "consumer_data_mismatch";

export type Alpha0ActionUnlockProofGenerationDiagnosticScenario =
  | "exact"
  | "witness_binding_mismatch"
  | "prover_failure"
  | "proof_input_hash_mismatch"
  | "timeout"
  | "witness_replay";

export type Alpha0FinalizedAuthorizationPackageDiagnosticScenario =
  | "exact"
  | "invalid_proof"
  | "public_input_mismatch"
  | "proof_input_hash_mismatch"
  | "fact_shape_mismatch"
  | "verification_timeout"
  | "expired_package";

export type Alpha0AuthorizationExecutionReadinessDiagnosticScenario =
  | "exact"
  | "fact_already_published"
  | "nullifier_already_consumed"
  | "fact_state_unknown"
  | "nullifier_state_unknown"
  | "configuration_mismatch"
  | "expired_package";

export interface Alpha0ShellParsedArgs {
  readonly scenario?: Alpha0DemoScenario | string;
  readonly json: boolean;
  readonly debug: boolean;
  readonly help: boolean;
  readonly list: boolean;
  readonly interactive: boolean;
  readonly strictFailures: boolean;
  readonly lifecycle: boolean;
  readonly lifecycleSequence?: Alpha0LifecycleDiagnosticSequence | string;
  readonly approvalOutcome?: Alpha0PlatformApprovalDiagnosticOutcome | string;
  readonly authorizationCandidateScenario?:
    Alpha0AuthorizationCandidateDiagnosticScenario | string;
  readonly authorizationPackageDraftScenario?:
    Alpha0AuthorizationPackageDraftDiagnosticScenario | string;
  readonly actionUnlockProofGenerationScenario?:
    Alpha0ActionUnlockProofGenerationDiagnosticScenario | string;
  readonly finalizedAuthorizationPackageScenario?:
    Alpha0FinalizedAuthorizationPackageDiagnosticScenario | string;
  readonly authorizationExecutionReadinessScenario?:
    Alpha0AuthorizationExecutionReadinessDiagnosticScenario | string;
  readonly error?: string;
}

export interface Alpha0ShellRunOptions {
  readonly argv?: readonly string[];
  readonly input?: NodeJS.ReadableStream;
  readonly output?: NodeJS.WritableStream;
  readonly errorOutput?: NodeJS.WritableStream;
}

export interface Alpha0ShellRunResult {
  readonly exitCode: number;
  readonly parsedArgs: Alpha0ShellParsedArgs;
}

const STAGES_THAT_EMIT_AUDIT_DRAFTS = new Set<Alpha0DemoStage>([
  "capability_grant_draft",
  "trust_evaluation_draft",
  "public_trust_metadata_evaluation",
  "possession_verification_draft",
  "webauthn_fixture_verification",
  "possession_evaluation",
  "bounded_trust_evaluation",
  "bounded_policy_evaluation",
  "user_approval_request_draft",
  "user_decision_fixture",
  "capability_activation_candidate"
]);

function writeLine(output: NodeJS.WritableStream, text = ""): void {
  output.write(`${text}\n`);
}

export function parseAlpha0ShellArgs(
  argv: readonly string[] = []
): Alpha0ShellParsedArgs {
  let scenario: string | undefined;
  let json = false;
  let debug = false;
  let help = false;
  let list = false;
  let interactive = false;
  let strictFailures = false;
  let lifecycle = false;
  let lifecycleSequence: string | undefined;
  let approvalOutcome: string | undefined;
  let authorizationCandidateScenario: string | undefined;
  let authorizationPackageDraftScenario: string | undefined;
  let actionUnlockProofGenerationScenario: string | undefined;
  let finalizedAuthorizationPackageScenario: string | undefined;
  let authorizationExecutionReadinessScenario: string | undefined;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--json") {
      json = true;
      continue;
    }
    if (arg === "--debug") {
      debug = true;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      help = true;
      continue;
    }
    if (arg === "--list") {
      list = true;
      continue;
    }
    if (arg === "--interactive") {
      interactive = true;
      continue;
    }
    if (arg === "--strict-failures") {
      strictFailures = true;
      continue;
    }
    if (arg === "--lifecycle") {
      lifecycle = true;
      continue;
    }
    if (arg === "--lifecycle-sequence") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return {
          json,
          debug,
          help,
          list,
          interactive,
          strictFailures,
          lifecycle,
          lifecycleSequence,
          approvalOutcome,
          authorizationCandidateScenario,
          authorizationPackageDraftScenario,
          error: "--lifecycle-sequence requires a sequence value"
        };
      }
      lifecycle = true;
      lifecycleSequence = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--lifecycle-sequence=")) {
      lifecycle = true;
      lifecycleSequence = arg.slice("--lifecycle-sequence=".length);
      continue;
    }
    if (arg === "--approval-outcome") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return {
          json,
          debug,
          help,
          list,
          interactive,
          strictFailures,
          lifecycle,
          lifecycleSequence,
          approvalOutcome,
          authorizationCandidateScenario,
          authorizationPackageDraftScenario,
          error: "--approval-outcome requires approve, deny, cancel, expired, or digest_mismatch"
        };
      }
      approvalOutcome = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--approval-outcome=")) {
      approvalOutcome = arg.slice("--approval-outcome=".length);
      continue;
    }
    if (arg === "--authorization-candidate-scenario") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return {
          json,
          debug,
          help,
          list,
          interactive,
          strictFailures,
          lifecycle,
          lifecycleSequence,
          approvalOutcome,
          authorizationCandidateScenario,
          authorizationPackageDraftScenario,
          error: "--authorization-candidate-scenario requires exact, capability_mismatch, scope_widening, target_mismatch, value_limit_exceeded, or additional_approval_required"
        };
      }
      authorizationCandidateScenario = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--authorization-candidate-scenario=")) {
      authorizationCandidateScenario = arg.slice("--authorization-candidate-scenario=".length);
      continue;
    }
    if (arg === "--authorization-package-draft-scenario") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return {
          json,
          debug,
          help,
          list,
          interactive,
          strictFailures,
          lifecycle,
          lifecycleSequence,
          approvalOutcome,
          authorizationCandidateScenario,
          authorizationPackageDraftScenario,
          actionUnlockProofGenerationScenario,
          error: "--authorization-package-draft-scenario requires exact, mutated_action, invalid_nullifier, expiry_beyond_capability_grant, evidence_chain_mismatch, or consumer_data_mismatch"
        };
      }
      authorizationPackageDraftScenario = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--authorization-package-draft-scenario=")) {
      authorizationPackageDraftScenario =
        arg.slice("--authorization-package-draft-scenario=".length);
      continue;
    }
    if (arg === "--action-unlock-proof-generation-scenario") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return {
          json,
          debug,
          help,
          list,
          interactive,
          strictFailures,
          lifecycle,
          lifecycleSequence,
          approvalOutcome,
          authorizationCandidateScenario,
          authorizationPackageDraftScenario,
          actionUnlockProofGenerationScenario,
          error: "--action-unlock-proof-generation-scenario requires exact, witness_binding_mismatch, prover_failure, proof_input_hash_mismatch, timeout, or witness_replay"
        };
      }
      actionUnlockProofGenerationScenario = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--action-unlock-proof-generation-scenario=")) {
      actionUnlockProofGenerationScenario =
        arg.slice("--action-unlock-proof-generation-scenario=".length);
      continue;
    }
    if (arg === "--finalized-authorization-package-scenario") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return {
          json,
          debug,
          help,
          list,
          interactive,
          strictFailures,
          lifecycle,
          lifecycleSequence,
          approvalOutcome,
          authorizationCandidateScenario,
          authorizationPackageDraftScenario,
          actionUnlockProofGenerationScenario,
          finalizedAuthorizationPackageScenario,
          error: "--finalized-authorization-package-scenario requires exact, invalid_proof, public_input_mismatch, proof_input_hash_mismatch, fact_shape_mismatch, verification_timeout, or expired_package"
        };
      }
      finalizedAuthorizationPackageScenario = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--finalized-authorization-package-scenario=")) {
      finalizedAuthorizationPackageScenario =
        arg.slice("--finalized-authorization-package-scenario=".length);
      continue;
    }
    if (arg === "--authorization-execution-readiness-scenario") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return {
          json,
          debug,
          help,
          list,
          interactive,
          strictFailures,
          lifecycle,
          lifecycleSequence,
          approvalOutcome,
          authorizationCandidateScenario,
          authorizationPackageDraftScenario,
          actionUnlockProofGenerationScenario,
          finalizedAuthorizationPackageScenario,
          authorizationExecutionReadinessScenario,
          error: "--authorization-execution-readiness-scenario requires exact, fact_already_published, nullifier_already_consumed, fact_state_unknown, nullifier_state_unknown, configuration_mismatch, or expired_package"
        };
      }
      authorizationExecutionReadinessScenario = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--authorization-execution-readiness-scenario=")) {
      authorizationExecutionReadinessScenario =
        arg.slice("--authorization-execution-readiness-scenario=".length);
      continue;
    }
    if (arg === "--scenario") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        return {
          json,
          debug,
          help,
          list,
          interactive,
          strictFailures,
          lifecycle,
          lifecycleSequence,
          approvalOutcome,
          authorizationCandidateScenario,
          authorizationPackageDraftScenario,
          error: "--scenario requires a scenario value"
        };
      }
      scenario = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--scenario=")) {
      scenario = arg.slice("--scenario=".length);
      continue;
    }
    if (arg.startsWith("--")) {
      return {
        json,
        debug,
        help,
        list,
        interactive,
        strictFailures,
        lifecycle,
        lifecycleSequence,
        approvalOutcome,
        authorizationCandidateScenario,
        authorizationPackageDraftScenario,
        error: `unknown option ${arg}`
      };
    }
    if (scenario !== undefined) {
      return {
        json,
        debug,
        help,
        list,
        interactive,
        strictFailures,
        lifecycle,
        lifecycleSequence,
        approvalOutcome,
        authorizationCandidateScenario,
        authorizationPackageDraftScenario,
        error: "only one scenario may be provided"
      };
    }
    scenario = arg;
  }

  return {
    scenario,
    json,
    debug,
    help,
    list,
    interactive,
    strictFailures,
    lifecycle,
    lifecycleSequence,
    approvalOutcome,
    authorizationCandidateScenario,
    authorizationPackageDraftScenario,
    actionUnlockProofGenerationScenario,
    finalizedAuthorizationPackageScenario,
    authorizationExecutionReadinessScenario
  };
}

export function formatAlpha0ScenarioList(): string {
  return [
    "Available Alpha 0 scenarios:",
    ...ALPHA0_DEMO_SCENARIOS.map((scenario, index) => `${index + 1}. ${scenario}`)
  ].join("\n");
}

export function formatAlpha0ShellHelp(): string {
  return [
    "PhilCore Alpha 0 local shell",
    "",
    "Usage:",
    "  npm run demo:runtime-alpha0-shell",
    "  npm run demo:runtime-alpha0-shell -- --scenario ordinary_success",
    "  npm run demo:runtime-alpha0-shell -- ordinary_success --json",
    "  npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence valid_unlock",
    "",
    formatAlpha0ScenarioList(),
    "",
    "Flags:",
    "  --json              Emit sanitized JSON for one scenario.",
    "  --list              Print available scenarios.",
    "  --lifecycle         Run User Session lifecycle diagnostic mode.",
    "  --lifecycle-sequence states|valid_unlock|fixture_unlock|production_webauthn_partial_unlock|production_webauthn_vault_unlock|production_protected_state_view|production_public_credential_directory|production_selected_credential_public_material|production_trust_manager_verification_input|production_trust_manager_assertion_verification|production_trust_decision_candidate|production_credential_counter_persistence|production_authoritative_trust_decision|production_authoritative_policy_decision|production_platform_user_approval_decision|production_authoritative_capability_activation|production_authorization_decision_candidate|production_authorization_package_draft|production_action_unlock_proof_generation|production_finalized_authorization_package|production_authorization_execution_readiness|invalid_transition|timeout|recovery",
    "  --approval-outcome approve|deny|cancel|expired|digest_mismatch",
    "  --authorization-candidate-scenario exact|capability_mismatch|scope_widening|target_mismatch|value_limit_exceeded|additional_approval_required",
    "  --authorization-package-draft-scenario exact|mutated_action|invalid_nullifier|expiry_beyond_capability_grant|evidence_chain_mismatch|consumer_data_mismatch",
    "  --action-unlock-proof-generation-scenario exact|witness_binding_mismatch|prover_failure|proof_input_hash_mismatch|timeout|witness_replay",
    "  --finalized-authorization-package-scenario exact|invalid_proof|public_input_mismatch|proof_input_hash_mismatch|fact_shape_mismatch|verification_timeout|expired_package",
    "  --authorization-execution-readiness-scenario exact|fact_already_published|nullifier_already_consumed|fact_state_unknown|nullifier_state_unknown|configuration_mismatch|expired_package",
    "  --interactive       Force interactive mode.",
    "  --strict-failures   Exit non-zero when an expected scenario fails.",
    "  --debug             Print exception details.",
    "  --help              Show this help."
  ].join("\n");
}

export function isAlpha0LifecycleDiagnosticSequence(
  value: unknown
): value is Alpha0LifecycleDiagnosticSequence {
  return value === "states"
    || value === "valid_unlock"
    || value === "fixture_unlock"
    || value === "production_webauthn_partial_unlock"
    || value === "production_webauthn_vault_unlock"
    || value === "production_protected_state_view"
    || value === "production_public_credential_directory"
    || value === "production_selected_credential_public_material"
    || value === "production_trust_manager_verification_input"
    || value === "production_trust_manager_assertion_verification"
    || value === "production_trust_decision_candidate"
    || value === "production_credential_counter_persistence"
    || value === "production_authoritative_trust_decision"
    || value === "production_authoritative_policy_decision"
    || value === "production_platform_user_approval_decision"
    || value === "production_authoritative_capability_activation"
    || value === "production_authorization_decision_candidate"
    || value === "production_authorization_package_draft"
    || value === "production_action_unlock_proof_generation"
    || value === "production_finalized_authorization_package"
    || value === "production_authorization_execution_readiness"
    || value === "invalid_transition"
    || value === "timeout"
    || value === "recovery";
}

function isAlpha0PlatformApprovalDiagnosticOutcome(
  value: unknown
): value is Alpha0PlatformApprovalDiagnosticOutcome {
  return value === "approve"
    || value === "deny"
    || value === "cancel"
    || value === "expired"
    || value === "digest_mismatch";
}

function isAlpha0AuthorizationCandidateDiagnosticScenario(
  value: unknown
): value is Alpha0AuthorizationCandidateDiagnosticScenario {
  return value === "exact"
    || value === "capability_mismatch"
    || value === "scope_widening"
    || value === "target_mismatch"
    || value === "value_limit_exceeded"
    || value === "additional_approval_required";
}

function isAlpha0AuthorizationPackageDraftDiagnosticScenario(
  value: unknown
): value is Alpha0AuthorizationPackageDraftDiagnosticScenario {
  return value === "exact"
    || value === "mutated_action"
    || value === "invalid_nullifier"
    || value === "expiry_beyond_capability_grant"
    || value === "evidence_chain_mismatch"
    || value === "consumer_data_mismatch";
}

function isAlpha0ActionUnlockProofGenerationDiagnosticScenario(
  value: unknown
): value is Alpha0ActionUnlockProofGenerationDiagnosticScenario {
  return value === "exact"
    || value === "witness_binding_mismatch"
    || value === "prover_failure"
    || value === "proof_input_hash_mismatch"
    || value === "timeout"
    || value === "witness_replay";
}

function isAlpha0FinalizedAuthorizationPackageDiagnosticScenario(
  value: unknown
): value is Alpha0FinalizedAuthorizationPackageDiagnosticScenario {
  return value === "exact"
    || value === "invalid_proof"
    || value === "public_input_mismatch"
    || value === "proof_input_hash_mismatch"
    || value === "fact_shape_mismatch"
    || value === "verification_timeout"
    || value === "expired_package";
}

function isAlpha0AuthorizationExecutionReadinessDiagnosticScenario(
  value: unknown
): value is Alpha0AuthorizationExecutionReadinessDiagnosticScenario {
  return value === "exact"
    || value === "fact_already_published"
    || value === "nullifier_already_consumed"
    || value === "fact_state_unknown"
    || value === "nullifier_state_unknown"
    || value === "configuration_mismatch"
    || value === "expired_package";
}

export function formatUserSessionLifecycleStates(): string {
  const states: readonly UserSessionLifecycleState[] = [
    "uninitialized",
    "locked",
    "unlocking",
    "partially_unlocked",
    "unlocked",
    "suspending",
    "suspended",
    "resuming",
    "expiring",
    "expired",
    "recovery_mode",
    "closing",
    "closed"
  ];

  return [
    "PhilCore User Session lifecycle states:",
    ...states.map((state, index) => `${index + 1}. ${state}`),
    "",
    "Allowed transition rules:",
    ...USER_SESSION_LIFECYCLE_TRANSITION_TABLE.map(
      (rule) => `- ${rule.currentState} + ${rule.event} -> ${rule.nextState}`
    )
  ].join("\n");
}

export interface Alpha0LifecycleDiagnosticResult {
  readonly sequence: Alpha0LifecycleDiagnosticSequence;
  readonly finalStatus: "succeeded" | "failed";
  readonly finalState?: UserSessionLifecycleState;
  readonly transitions: readonly UserSessionTransitionResult[];
  readonly fixtureAuthenticationVerification?: FixtureAuthenticationVerificationArtifact;
  readonly productionAuthenticationVerification?: ProductionAuthenticationVerificationResultValue;
  readonly lifecycleTransitionCandidate?: LifecycleTransitionCandidate;
  readonly productionVerifiedPartialUnlock?: ProductionVerifiedPartialUnlockResultValue;
  readonly deviceVaultUnlockResult?: DeviceVaultUnlockResultValue;
  readonly verifiedVaultSessionUnlock?: VerifiedVaultSessionUnlockResultValue;
  readonly protectedStateView?: ProtectedStateViewResultValue;
  readonly publicCredentialDirectory?: PublicCredentialDirectoryResultValue;
  readonly selectedCredentialPublicMaterial?: SelectedCredentialPublicMaterialResultValue;
  readonly trustManagerVerificationInput?: TrustManagerVerificationInputResultValue;
  readonly trustManagerProductionVerification?: TrustManagerProductionVerificationResultValue;
  readonly boundedTrustDecisionCandidate?: BoundedTrustDecisionCandidate;
  readonly credentialCounterPersistenceReceipt?: CredentialCounterPersistenceReceipt;
  readonly trustDecisionCandidateCounterResolution?: TrustDecisionCandidateCounterResolution;
  readonly authoritativeTrustDecision?: AuthoritativeTrustDecision;
  readonly authoritativePolicyDecision?: AuthoritativePolicyDecision;
  readonly platformUserApprovalDecision?: PlatformUserApprovalDecision;
  readonly platformUserApprovalDecisionOutcome?: PlatformUserApprovalDecisionOutcome;
  readonly platformUserApprovalDecisionErrorCode?: string;
  readonly platformUserApprovalArtifactSurface?: string;
  readonly platformUserApprovalArtifactOutcome?: string;
  readonly authoritativeCapabilityGrant?: AuthoritativeCapabilityGrant;
  readonly authoritativeCapabilityGrantErrorCode?: string;
  readonly userSessionCapabilityMutation?: UserSessionCapabilityMutationResult;
  readonly authorizationCandidateScenario?: Alpha0AuthorizationCandidateDiagnosticScenario;
  readonly authorizationDecisionCandidate?: AuthorizationDecisionCandidate;
  readonly authorizationDecisionCandidateErrorCode?: string;
  readonly authorizationPackageDraftScenario?: Alpha0AuthorizationPackageDraftDiagnosticScenario;
  readonly authorizationPackageDraft?: AuthorizationPackageDraft;
  readonly authorizationPackageDraftErrorCode?: string;
  readonly actionUnlockProofGenerationScenario?:
    Alpha0ActionUnlockProofGenerationDiagnosticScenario;
  readonly actionUnlockProofGenerationArtifact?: ActionUnlockProofGenerationArtifact;
  readonly actionUnlockProofGenerationErrorCode?: string;
  readonly finalizedAuthorizationPackageScenario?:
    Alpha0FinalizedAuthorizationPackageDiagnosticScenario;
  readonly actionUnlockProofVerification?: ActionUnlockProofVerificationResultValue;
  readonly actionUnlockProofVerificationErrorCode?: string;
  readonly finalizedAuthorizationPackage?: FinalizedAuthorizationPackage;
  readonly finalizedAuthorizationPackageErrorCode?: string;
  readonly authorizationExecutionReadinessScenario?:
    Alpha0AuthorizationExecutionReadinessDiagnosticScenario;
  readonly verifiedFactPublicationRequestDraft?: VerifiedFactPublicationRequestDraft;
  readonly verifiedFactPublicationRequestDraftErrorCode?: string;
  readonly authorizationExecutionReadiness?: AuthorizationExecutionReadinessResultValue;
  readonly authorizationExecutionReadinessErrorCode?: string;
  readonly stateList?: readonly UserSessionLifecycleState[];
  readonly limitations: readonly string[];
  readonly productionAuthenticationPerformed: boolean;
  readonly vaultUnlocked: boolean;
  readonly activeCapabilityCreated: boolean;
  readonly authorizationCreated: false;
  readonly proofExecuted: false;
  readonly adapterExecuted: false;
  readonly persisted: false;
}

function transitionEventsForLifecycleSequence(
  sequence: Alpha0LifecycleDiagnosticSequence
): readonly UserSessionLifecycleEvent[] {
  if (sequence === "valid_unlock") {
    return ["request_unlock", "unlock_succeeded"];
  }
  if (sequence === "invalid_transition") {
    return ["unlock_succeeded"];
  }
  if (sequence === "timeout") {
    return ["request_unlock", "unlock_succeeded", "timeout_warning", "timeout_reached", "request_lock"];
  }
  if (sequence === "recovery") {
    return ["request_recovery", "recovery_entered", "recovery_cancelled"];
  }
  return [];
}

function futureIso(ms = 60_000): string {
  return new Date(Date.now() + ms).toISOString();
}

function generateP256CredentialKeyPair() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const publicKeySpki = publicKey.export({
    type: "spki",
    format: "der"
  });

  return {
    privateKey,
    publicKeyHex: `0x${Buffer.from(publicKeySpki).toString("hex")}` as `0x${string}`
  };
}

function sha256(value: Buffer | string): Buffer {
  return nodeCrypto.createHash("sha256").update(Buffer.from(value)).digest();
}

function buildAuthenticatorData(input: {
  readonly rpId: string;
  readonly flags?: number;
  readonly signCount?: number;
}): Buffer {
  const out = Buffer.alloc(37);
  sha256(Buffer.from(input.rpId, "utf8")).copy(out, 0);
  out[32] = input.flags ?? 0x05;
  out.writeUInt32BE((input.signCount ?? 1) >>> 0, 33);
  return out;
}

function buildAlpha0WebAuthnAssertion(input: {
  readonly credentialId: string;
  readonly privateKey: nodeCrypto.KeyObject;
  readonly rpId: string;
  readonly origin: string;
  readonly challenge: string;
  readonly signCount: number;
}) {
  const authenticatorData = buildAuthenticatorData({
    rpId: input.rpId,
    flags: 0x05,
    signCount: input.signCount
  });
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge: input.challenge,
    origin: input.origin
  }));
  const signer = nodeCrypto.createSign("SHA256");
  signer.update(Buffer.concat([authenticatorData, sha256(clientDataJSON)]));
  signer.end();
  const signature = signer.sign(input.privateKey);

  return {
    id: input.credentialId,
    rawId: input.credentialId,
    type: "public-key" as const,
    authenticatorAttachment: "platform" as const,
    response: {
      authenticatorData: arrayBufferToBase64Url(authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(clientDataJSON),
      signature: arrayBufferToBase64Url(signature),
      userHandle: null
    },
    clientExtensionResults: {}
  };
}

async function runProductionWebAuthnPartialUnlockLifecycleDiagnostic():
  Promise<Alpha0LifecycleDiagnosticResult> {
  const sessionId = "alpha0-production-webauthn-session";
  const transitionRequestId = "alpha0-production-webauthn-unlock-succeeded";
  const auditCorrelationId = `${sessionId}:production-webauthn-partial-unlock`;
  const store = createEphemeralUserSessionLifecycleStore();
  const transitions: UserSessionTransitionResult[] = [];
  const initialized = store.initialize({
    sessionId,
    transitionRequestId: "alpha0-production-webauthn-initialize"
  });
  if (initialized.transitionResult) transitions.push(initialized.transitionResult);
  const requestUnlock = store.requestTransition({
    transitionRequestId: "alpha0-production-webauthn-request-unlock",
    event: "request_unlock"
  });
  if (requestUnlock.transitionResult) transitions.push(requestUnlock.transitionResult);

  const keyPair = generateP256CredentialKeyPair();
  const credentialId = "alpha0-production-webauthn-credential";
  const challenge = "alpha0-production-webauthn-challenge";
  const challengeReferenceId = "alpha0-production-webauthn-challenge-reference";
  const origin = "https://alpha0.local";
  const rpId = "alpha0.local";
  const verification = await verifyProductionWebAuthnAuthentication({
    requestId: "alpha0-production-webauthn-verification",
    providerKind: "webauthn_passkey",
    providerId: "alpha0-production-webauthn-provider",
    assertion: buildAlpha0WebAuthnAssertion({
      credentialId,
      privateKey: keyPair.privateKey,
      rpId,
      origin,
      challenge,
      signCount: 7
    }),
    credential: {
      credentialId,
      credentialIdHash: "0xalpha0",
      rawId: credentialId,
      publicKey: keyPair.publicKeyHex,
      publicKeyAlgorithm: -7,
      signCount: 6
    },
    expectedChallenge: challenge,
    expectedRpId: rpId,
    expectedOrigin: origin,
    expectedUserVerification: "required",
    storedSignCount: 6,
    correlation: {
      sessionId,
      lifecycleTransitionRequestId: transitionRequestId,
      lifecycleEvent: "unlock_succeeded",
      ownerCommitment: "0xalpha0productionownercommitment",
      applicationId: "ethereum-net",
      credentialId,
      providerId: "alpha0-production-webauthn-provider",
      challengeReferenceId,
      auditCorrelationId
    },
    requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    freshness: {
      collectedAt: new Date().toISOString(),
      expiresAt: futureIso()
    },
    auditCorrelationId
  });
  const snapshot = store.getSnapshot();
  const candidate = verification.value && snapshot
    ? createLifecycleTransitionCandidate({
      requestId: "alpha0-production-webauthn-candidate",
      productionAuthenticationVerification: verification.value,
      lifecycleEligibility: verification.value.lifecycleEligibility,
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId,
        event: "unlock_succeeded"
      },
      expectedSessionId: sessionId,
      expectedOwnerCommitment: "0xalpha0productionownercommitment",
      expectedCredentialId: credentialId,
      expectedProviderId: "alpha0-production-webauthn-provider",
      expectedChallengeReferenceId: challengeReferenceId,
      requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
      auditCorrelationId
    })
    : undefined;
  const partialUnlock = candidate?.value && snapshot
    ? transitionUserSessionWithProductionVerification({
      requestId: "alpha0-production-webauthn-partial-unlock",
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId,
        event: "unlock_succeeded"
      },
      candidate: candidate.value,
      consumptionStore: createEphemeralProductionVerificationConsumptionStore(),
      auditCorrelationId
    })
    : undefined;
  if (partialUnlock?.value?.transitionResult) {
    transitions.push(partialUnlock.value.transitionResult);
    if (partialUnlock.value.transitionResult.snapshot) {
      store.replaceSnapshot(partialUnlock.value.transitionResult.snapshot);
    }
  }

  return Object.freeze({
    sequence: "production_webauthn_partial_unlock",
    finalStatus: verification.status === "approved"
      && candidate?.status === "approved"
      && partialUnlock?.status === "approved"
      && store.getSnapshot()?.state === "partially_unlocked"
      ? "succeeded"
      : "failed",
    finalState: store.getSnapshot()?.state,
    transitions: Object.freeze(transitions),
    productionAuthenticationVerification: verification.value,
    lifecycleTransitionCandidate: candidate?.value,
    productionVerifiedPartialUnlock: partialUnlock?.value,
    limitations: Object.freeze([
      "diagnostic_only",
      "production_webauthn_assertion_verified_from_explicit_inputs",
      "browser_webauthn_prompt_not_invoked",
      "credential_not_loaded_from_device_vault",
      "device_vault_remains_locked",
      "session_not_fully_unlocked",
      "no_active_capability",
      "no_authorization",
      "no_persistence"
    ]),
    productionAuthenticationPerformed: true,
    vaultUnlocked: false,
    activeCapabilityCreated: false,
    authorizationCreated: false,
    proofExecuted: false,
    adapterExecuted: false,
    persisted: false
  });
}

async function runProductionWebAuthnVaultUnlockLifecycleDiagnostic(input: {
  readonly includeProtectedStateView?: boolean;
  readonly includePublicCredentialDirectory?: boolean;
  readonly includeSelectedCredentialPublicMaterial?: boolean;
  readonly includeTrustManagerVerificationInput?: boolean;
  readonly includeTrustManagerProductionVerification?: boolean;
  readonly includeBoundedTrustDecisionCandidate?: boolean;
  readonly includeCredentialCounterPersistence?: boolean;
  readonly includeAuthoritativeTrustDecision?: boolean;
  readonly includeAuthoritativePolicyDecision?: boolean;
  readonly includePlatformUserApprovalDecision?: boolean;
  readonly includeAuthoritativeCapabilityActivation?: boolean;
  readonly includeAuthorizationDecisionCandidate?: boolean;
  readonly includeAuthorizationPackageDraft?: boolean;
  readonly includeActionUnlockProofGeneration?: boolean;
  readonly includeFinalizedAuthorizationPackage?: boolean;
  readonly includeAuthorizationExecutionReadiness?: boolean;
  readonly approvalOutcome?: Alpha0PlatformApprovalDiagnosticOutcome;
  readonly authorizationCandidateScenario?: Alpha0AuthorizationCandidateDiagnosticScenario;
  readonly authorizationPackageDraftScenario?: Alpha0AuthorizationPackageDraftDiagnosticScenario;
  readonly actionUnlockProofGenerationScenario?:
    Alpha0ActionUnlockProofGenerationDiagnosticScenario;
  readonly finalizedAuthorizationPackageScenario?:
    Alpha0FinalizedAuthorizationPackageDiagnosticScenario;
  readonly authorizationExecutionReadinessScenario?:
    Alpha0AuthorizationExecutionReadinessDiagnosticScenario;
  readonly sequence?: Extract<
    Alpha0LifecycleDiagnosticSequence,
    "production_webauthn_vault_unlock"
      | "production_protected_state_view"
      | "production_public_credential_directory"
      | "production_selected_credential_public_material"
      | "production_trust_manager_verification_input"
      | "production_trust_manager_assertion_verification"
      | "production_trust_decision_candidate"
      | "production_credential_counter_persistence"
      | "production_authoritative_trust_decision"
      | "production_authoritative_policy_decision"
      | "production_platform_user_approval_decision"
      | "production_authoritative_capability_activation"
      | "production_authorization_decision_candidate"
      | "production_authorization_package_draft"
      | "production_action_unlock_proof_generation"
      | "production_finalized_authorization_package"
      | "production_authorization_execution_readiness"
  >;
} = {}):
  Promise<Alpha0LifecycleDiagnosticResult> {
  const privateIdentity = createPhilIdentityPrivate();
  const identity = derivePhilIdentityPublic(privateIdentity);
  const sessionId = "alpha0-production-webauthn-vault-session";
  const partialTransitionRequestId = "alpha0-production-webauthn-vault-partial-unlock";
  const vaultTransitionRequestId = "alpha0-production-webauthn-vault-unlock-succeeded";
  const auditCorrelationId = `${sessionId}:production-webauthn-vault-unlock`;
  const lifecycleStore = createEphemeralUserSessionLifecycleStore();
  const transitions: UserSessionTransitionResult[] = [];
  const initialized = lifecycleStore.initialize({
    sessionId,
    transitionRequestId: "alpha0-production-webauthn-vault-initialize"
  });
  if (initialized.transitionResult) transitions.push(initialized.transitionResult);
  const requestUnlock = lifecycleStore.requestTransition({
    transitionRequestId: "alpha0-production-webauthn-vault-request-unlock",
    event: "request_unlock"
  });
  if (requestUnlock.transitionResult) transitions.push(requestUnlock.transitionResult);

  const keyPair = generateP256CredentialKeyPair();
  const credentialId = "alpha0-production-webauthn-vault-credential";
  const challenge = "alpha0-production-webauthn-vault-challenge";
  const challengeReferenceId = "alpha0-production-webauthn-vault-challenge-reference";
  const origin = "https://alpha0.local";
  const rpId = "alpha0.local";
  const verification = await verifyProductionWebAuthnAuthentication({
    requestId: "alpha0-production-webauthn-vault-verification",
    providerKind: "webauthn_passkey",
    providerId: "alpha0-production-webauthn-vault-provider",
    assertion: buildAlpha0WebAuthnAssertion({
      credentialId,
      privateKey: keyPair.privateKey,
      rpId,
      origin,
      challenge,
      signCount: 7
    }),
    credential: {
      credentialId,
      credentialIdHash: "0xalpha0vault",
      rawId: credentialId,
      publicKey: keyPair.publicKeyHex,
      publicKeyAlgorithm: -7,
      signCount: 6
    },
    expectedChallenge: challenge,
    expectedRpId: rpId,
    expectedOrigin: origin,
    expectedUserVerification: "required",
    storedSignCount: 6,
    correlation: {
      sessionId,
      lifecycleTransitionRequestId: partialTransitionRequestId,
      lifecycleEvent: "unlock_succeeded",
      ownerCommitment: identity.ownerCommitment,
      applicationId: "ethereum-net",
      credentialId,
      providerId: "alpha0-production-webauthn-vault-provider",
      challengeReferenceId,
      auditCorrelationId
    },
    requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
    freshness: {
      collectedAt: new Date().toISOString(),
      expiresAt: futureIso()
    },
    auditCorrelationId
  });
  const unlockingSnapshot = lifecycleStore.getSnapshot();
  const candidate = verification.value && unlockingSnapshot
    ? createLifecycleTransitionCandidate({
      requestId: "alpha0-production-webauthn-vault-candidate",
      productionAuthenticationVerification: verification.value,
      lifecycleEligibility: verification.value.lifecycleEligibility,
      lifecycleSnapshot: unlockingSnapshot,
      transitionRequest: {
        transitionRequestId: partialTransitionRequestId,
        event: "unlock_succeeded"
      },
      expectedSessionId: sessionId,
      expectedOwnerCommitment: identity.ownerCommitment,
      expectedCredentialId: credentialId,
      expectedProviderId: "alpha0-production-webauthn-vault-provider",
      expectedChallengeReferenceId: challengeReferenceId,
      requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
      auditCorrelationId
    })
    : undefined;
  const partialUnlock = candidate?.value && unlockingSnapshot
    ? transitionUserSessionWithProductionVerification({
      requestId: "alpha0-production-webauthn-vault-partial-unlock",
      lifecycleSnapshot: unlockingSnapshot,
      transitionRequest: {
        transitionRequestId: partialTransitionRequestId,
        event: "unlock_succeeded"
      },
      candidate: candidate.value,
      consumptionStore: createEphemeralProductionVerificationConsumptionStore(),
      auditCorrelationId
    })
    : undefined;
  if (partialUnlock?.value?.transitionResult) {
    transitions.push(partialUnlock.value.transitionResult);
    if (partialUnlock.value.transitionResult.snapshot) {
      lifecycleStore.replaceSnapshot(partialUnlock.value.transitionResult.snapshot);
    }
  }

  const keyProvider = createLocalDevPassphraseKeyProvider({
    passphrase: "alpha0 explicit in-memory vault passphrase",
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
  const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
  const registryStore = createEncryptedDeviceIdentityRegistryStore({
    backend,
    keyProvider
  });
  const includeFinalizedAuthorizationPackageStage =
    input.includeFinalizedAuthorizationPackage || input.includeAuthorizationExecutionReadiness;
  const includeActionUnlockProofGenerationStage =
    input.includeActionUnlockProofGeneration || includeFinalizedAuthorizationPackageStage;
  const includeAuthorizationPackageDraftStage =
    input.includeAuthorizationPackageDraft || includeActionUnlockProofGenerationStage;
  const includePublicCredentialDirectory = input.includePublicCredentialDirectory
    || input.includeSelectedCredentialPublicMaterial
    || input.includeTrustManagerVerificationInput
    || input.includeTrustManagerProductionVerification
    || input.includeBoundedTrustDecisionCandidate
    || input.includeCredentialCounterPersistence
    || input.includeAuthoritativeTrustDecision
    || input.includeAuthoritativePolicyDecision
    || input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage;
  const includeSelectedCredentialPublicMaterial = input.includeSelectedCredentialPublicMaterial
    || input.includeTrustManagerVerificationInput
    || input.includeTrustManagerProductionVerification
    || input.includeBoundedTrustDecisionCandidate
    || input.includeCredentialCounterPersistence
    || input.includeAuthoritativeTrustDecision
    || input.includeAuthoritativePolicyDecision
    || input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage;
  const includeTrustManagerVerificationInput = input.includeTrustManagerVerificationInput
    || input.includeTrustManagerProductionVerification
    || input.includeBoundedTrustDecisionCandidate
    || input.includeCredentialCounterPersistence
    || input.includeAuthoritativeTrustDecision
    || input.includeAuthoritativePolicyDecision
    || input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage;
  const registry = includePublicCredentialDirectory
    ? createPhilCredentialRegistry({
      philIdentity: identity,
      credentials: [Object.freeze({
        credentialId: "alpha0-public-directory-credential",
        providerKind: "webauthn_passkey",
        algorithm: "ES256",
        label: "Alpha 0 passkey",
        createdAt: new Date().toISOString(),
        status: "active",
        signCount: 7,
        deviceType: "platform",
        transport: Object.freeze({
          transports: Object.freeze(["internal"]),
          authenticatorAttachment: "platform"
        }),
        priority: 1,
        publicKey: keyPair.publicKeyHex,
        publicKeyHash: keyPair.publicKeyHex
          ? nodeCrypto.createHash("sha256")
            .update(Buffer.from(keyPair.publicKeyHex.slice(2), "hex"))
            .digest("hex")
            .replace(/^/u, "0x") as `0x${string}`
          : undefined
      })]
    }).getSnapshot()
    : await registryStore.createNewRegistry(identity);
  await registryStore.saveRegistry(registry);
  const encryptedBlob = await backend.read();
  const partialSnapshot = lifecycleStore.getSnapshot();
  const deviceVaultUnlockResult = encryptedBlob && partialSnapshot
    ? await verifyDeviceVaultUnlock({
      requestId: "alpha0-production-webauthn-vault-unlock-verification",
      lifecycleSnapshot: partialSnapshot,
      identity,
      envelope: {
        envelopeId: "alpha0-production-webauthn-vault-envelope",
        encryptedBlob,
        ownerCommitment: identity.ownerCommitment
      },
      unlockMaterial: {
        materialId: "alpha0-production-webauthn-vault-unlock-material",
        keyProvider,
        providerKind: keyProvider.providerKind,
        unsafeForProduction: keyProvider.unsafeForProduction
      },
      correlation: {
        sessionId,
        ownerCommitment: identity.ownerCommitment,
        lifecycleTransitionRequestId: vaultTransitionRequestId,
        applicationId: "ethereum-net",
        auditCorrelationId
      },
      expectedOwnerCommitment: identity.ownerCommitment,
      expectedSessionId: sessionId,
      expectedAuditCorrelationId: auditCorrelationId,
      auditCorrelationId
    })
    : undefined;
  const verifiedVaultSessionUnlock = deviceVaultUnlockResult?.value && partialSnapshot
    ? transitionUserSessionWithVerifiedVaultUnlock({
      requestId: "alpha0-production-webauthn-vault-session-unlock",
      lifecycleSnapshot: partialSnapshot,
      transitionRequest: {
        transitionRequestId: vaultTransitionRequestId,
        event: "unlock_succeeded"
      },
      vaultUnlockResult: deviceVaultUnlockResult.value,
      consumptionStore: createEphemeralVaultUnlockConsumptionStore(),
      auditCorrelationId
    })
    : undefined;
  if (verifiedVaultSessionUnlock?.value?.transitionResult) {
    transitions.push(verifiedVaultSessionUnlock.value.transitionResult);
    if (verifiedVaultSessionUnlock.value.transitionResult.snapshot) {
      lifecycleStore.replaceSnapshot(verifiedVaultSessionUnlock.value.transitionResult.snapshot);
    }
  }
  const unlockedSnapshot = lifecycleStore.getSnapshot();
  const protectedStateView = input.includeProtectedStateView
    && encryptedBlob
    && deviceVaultUnlockResult?.value?.unlockedVaultHandle
    && unlockedSnapshot
    ? await createProtectedStateView({
      requestId: "alpha0-production-protected-state-view",
      viewType: "identity_summary",
      lifecycleSnapshot: unlockedSnapshot,
      unlockedVaultHandle: deviceVaultUnlockResult.value.unlockedVaultHandle,
      identity,
      envelope: {
        envelopeId: "alpha0-production-webauthn-vault-envelope",
        encryptedBlob,
        ownerCommitment: identity.ownerCommitment
      },
      unlockMaterial: {
        materialId: "alpha0-production-protected-state-view-material",
        keyProvider,
        providerKind: keyProvider.providerKind,
        unsafeForProduction: keyProvider.unsafeForProduction
      },
      expectedOwnerCommitment: identity.ownerCommitment,
      expectedSessionId: sessionId,
      auditCorrelationId: `${auditCorrelationId}:protected-state-view`
    })
    : undefined;
  const publicCredentialDirectory = includePublicCredentialDirectory
    && encryptedBlob
    && deviceVaultUnlockResult?.value?.unlockedVaultHandle
    && unlockedSnapshot
    ? await requestPublicCredentialDirectory({
      requestId: "alpha0-production-public-credential-directory",
      operation: "list_credentials",
      lifecycleSnapshot: unlockedSnapshot,
      unlockedVaultHandle: deviceVaultUnlockResult.value.unlockedVaultHandle,
      identity,
      envelope: {
        envelopeId: "alpha0-production-webauthn-vault-envelope",
        encryptedBlob,
        ownerCommitment: identity.ownerCommitment
      },
      unlockMaterial: {
        materialId: "alpha0-production-public-credential-directory-material",
        keyProvider,
        providerKind: keyProvider.providerKind,
        unsafeForProduction: keyProvider.unsafeForProduction
      },
      query: {
        limit: 10
      },
      expectedOwnerCommitment: identity.ownerCommitment,
      expectedSessionId: sessionId,
      auditCorrelationId: `${auditCorrelationId}:public-credential-directory`
    })
    : undefined;
  const selectedCredentialPublicMaterial = includeSelectedCredentialPublicMaterial
    && encryptedBlob
    && deviceVaultUnlockResult?.value?.unlockedVaultHandle
    && unlockedSnapshot
    && publicCredentialDirectory?.value
    ? await requestSelectedCredentialPublicMaterial({
      requestId: "alpha0-production-selected-credential-public-material",
      operation: "materialize_selected_credential_public_data",
      credentialId: "alpha0-public-directory-credential",
      lifecycleSnapshot: unlockedSnapshot,
      unlockedVaultHandle: deviceVaultUnlockResult.value.unlockedVaultHandle,
      publicCredentialDirectory: publicCredentialDirectory.value,
      identity,
      envelope: {
        envelopeId: "alpha0-production-webauthn-vault-envelope",
        encryptedBlob,
        ownerCommitment: identity.ownerCommitment
      },
      unlockMaterial: {
        materialId: "alpha0-production-selected-credential-public-material",
        keyProvider,
        providerKind: keyProvider.providerKind,
        unsafeForProduction: keyProvider.unsafeForProduction
      },
      expectedOwnerCommitment: identity.ownerCommitment,
      expectedSessionId: sessionId,
      auditCorrelationId: `${auditCorrelationId}:public-credential-directory`
    })
    : undefined;
  const trustManagerAuditCorrelationId = `${auditCorrelationId}:trust-manager-verification-input`;
  const trustManagerChallengeReferenceId = "alpha0-trust-manager-verification-input-challenge";
  const productionAuthenticationRequest = includeTrustManagerVerificationInput
    ? createProductionAuthenticationRequest({
      requestId: "alpha0-production-trust-manager-authentication-request",
      purpose: "high_risk_action",
      providerId: "alpha0-production-webauthn-vault-provider",
      providerKind: "webauthn_passkey",
      requirement: {
        purpose: "high_risk_action",
        provider: {
          providerKind: "webauthn_passkey",
          providerId: "alpha0-production-webauthn-vault-provider",
          minimumAssurance: ["user_presence", "user_verification", "phishing_resistant"],
          userPresenceRequired: true,
          userVerificationRequired: true,
          phishingResistantRequired: true
        },
        challengeReference: {
          challengeReferenceId: trustManagerChallengeReferenceId,
          challengeBindingHash: "alpha0-trust-manager-challenge-binding",
          createdAt: new Date().toISOString(),
          expiresAt: futureIso(),
          generatedChallenge: false
        },
        correlation: {
          sessionId,
          ownerCommitment: identity.ownerCommitment,
          applicationId: "ethereum-net",
          credentialId: "alpha0-public-directory-credential",
          providerId: "alpha0-production-webauthn-vault-provider",
          auditCorrelationId: trustManagerAuditCorrelationId
        },
        expiresAt: futureIso(),
        requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"]
      },
      metadata: {
        rpId,
        origin
      }
    })
    : undefined;
  const trustManagerVerificationInput = includeTrustManagerVerificationInput
    && unlockedSnapshot
    && selectedCredentialPublicMaterial?.value
    && productionAuthenticationRequest?.value
    ? createTrustManagerVerificationInput({
      requestId: "alpha0-production-trust-manager-verification-input",
      selectedCredentialVerificationProfile:
        selectedCredentialPublicMaterial.value.verificationProfile,
      selectedCredentialVerificationHandle:
        selectedCredentialPublicMaterial.value.verificationHandle,
      productionAuthenticationRequest: productionAuthenticationRequest.value,
      lifecycleSnapshot: unlockedSnapshot,
      userSessionContext: {
        sessionId,
        ownerCommitment: identity.ownerCommitment,
        status: "unlocked",
        activeApplicationId: "ethereum-net",
        activeCapabilityIds: [],
        pendingIntentIds: [],
        policyMode: "default",
        metadata: {
          deviceVaultUnlocked: true,
          protectedStateAvailable: true
        }
      },
      applicationId: "ethereum-net",
      sessionId,
      ownerCommitment: identity.ownerCommitment,
      credentialId: "alpha0-public-directory-credential",
      providerId: "alpha0-production-webauthn-vault-provider",
      authenticationPurpose: "high_risk_action",
      challengeReferenceId: trustManagerChallengeReferenceId,
      requiredAssurance: ["user_presence", "user_verification", "phishing_resistant"],
      auditCorrelationId: trustManagerAuditCorrelationId
    })
    : undefined;
  const includeTrustManagerProductionVerification =
    input.includeTrustManagerProductionVerification
    || input.includeBoundedTrustDecisionCandidate
    || input.includeCredentialCounterPersistence
    || input.includeAuthoritativeTrustDecision
    || input.includeAuthoritativePolicyDecision
    || input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage;
  const trustManagerAssertion = includeTrustManagerProductionVerification
    ? buildAlpha0WebAuthnAssertion({
      credentialId: "alpha0-public-directory-credential",
      privateKey: keyPair.privateKey,
      rpId,
      origin,
      challenge: trustManagerChallengeReferenceId,
      signCount: 8
    })
    : undefined;
  const trustManagerProductionVerification = includeTrustManagerProductionVerification
    && trustManagerVerificationInput?.value
    && trustManagerAssertion
    ? await verifyTrustManagerProductionAssertion({
      requestId: "alpha0-production-trust-manager-assertion-verification",
      verificationInput: trustManagerVerificationInput.value.verificationInput,
      assertion: trustManagerAssertion,
      expectedChallenge: trustManagerChallengeReferenceId,
      expectedOrigin: origin,
      expectedRpId: rpId,
      previousSignCounter: 7,
      expectedSessionId: sessionId,
      expectedOwnerCommitment: identity.ownerCommitment,
      expectedApplicationId: "ethereum-net",
      expectedAuthenticationPurpose: "high_risk_action",
      expectedProviderId: "alpha0-production-webauthn-vault-provider",
      expectedAuditCorrelationId: trustManagerAuditCorrelationId,
      auditCorrelationId: trustManagerAuditCorrelationId,
      collectedAt: new Date().toISOString(),
      expiresAt: futureIso()
    }, createEphemeralTrustManagerVerificationConsumptionStore())
    : undefined;
  const boundedTrustDecisionCandidate = (input.includeBoundedTrustDecisionCandidate
    || input.includeCredentialCounterPersistence
    || input.includeAuthoritativeTrustDecision
    || input.includeAuthoritativePolicyDecision
    || input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    && trustManagerProductionVerification?.value
    ? evaluateBoundedTrustDecisionCandidate({
      requestId: "alpha0-production-trust-decision-candidate",
      productionVerificationResult: trustManagerProductionVerification.value,
      credentialLifecycleStatus: "active",
      credentialId: "alpha0-public-directory-credential",
      providerKind: "webauthn_passkey",
      ownerCommitment: identity.ownerCommitment,
      sessionId,
      lifecycleState: lifecycleStore.getSnapshot()?.state ?? "unlocked",
      applicationId: "ethereum-net",
      authenticationPurpose: "high_risk_action",
      requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
      verificationTimestamp: new Date().toISOString(),
      expiresAt: futureIso(),
      auditCorrelationId: trustManagerAuditCorrelationId
    })
    : undefined;
  const credentialCounterPersistence = (input.includeCredentialCounterPersistence
    || input.includeAuthoritativeTrustDecision
    || input.includeAuthoritativePolicyDecision
    || input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    && boundedTrustDecisionCandidate?.value
    && trustManagerProductionVerification?.value
    && verifiedVaultSessionUnlock?.value?.transitionResult.snapshot
    && deviceVaultUnlockResult?.value?.unlockedVaultHandle
    ? await persistVerifiedCredentialCounter({
      operationId: "alpha0-production-credential-counter-persistence-operation",
      requestId: "alpha0-production-credential-counter-persistence",
      identity,
      storageBackend: backend,
      unlockMaterial: {
        materialId: "alpha0-production-credential-counter-persistence-material",
        keyProvider,
        providerKind: keyProvider.providerKind,
        unsafeForProduction: keyProvider.unsafeForProduction
      },
      unlockedVaultHandle: deviceVaultUnlockResult.value.unlockedVaultHandle,
      lifecycleSnapshot: verifiedVaultSessionUnlock.value.transitionResult.snapshot,
      productionVerificationResult: trustManagerProductionVerification.value,
      boundedTrustDecisionCandidate: boundedTrustDecisionCandidate.value,
      credentialId: "alpha0-public-directory-credential",
      ownerCommitment: identity.ownerCommitment,
      sessionId,
      applicationId: "ethereum-net",
      previousVerificationCounter: 7,
      verifiedReturnedCounter: 8,
      expectedStoredCounter: 7,
      expectedRegistryVersion: "phil-device-credential-registry-v1",
      expectedStorageVersion: 1,
      auditCorrelationId: trustManagerAuditCorrelationId,
      requestedAt: new Date().toISOString(),
      expiresAt: futureIso()
    })
    : undefined;
  const trustDecisionCandidateCounterResolution =
    credentialCounterPersistence?.value && boundedTrustDecisionCandidate?.value
      ? resolveCounterPersistenceRequirement({
        boundedTrustDecisionCandidate: boundedTrustDecisionCandidate.value,
        receipt: credentialCounterPersistence.value
      })
      : undefined;
  const authoritativeTrustDecision = (input.includeAuthoritativeTrustDecision
    || input.includeAuthoritativePolicyDecision
    || input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    && trustManagerProductionVerification?.value
    && boundedTrustDecisionCandidate?.value
    && credentialCounterPersistence?.value
    && trustDecisionCandidateCounterResolution
    && verifiedVaultSessionUnlock?.value?.transitionResult.snapshot
    ? createAuthoritativeTrustDecision(
      {
        requestId: "alpha0-production-authoritative-trust-decision",
        productionVerificationResult: trustManagerProductionVerification.value,
        boundedTrustDecisionCandidate: boundedTrustDecisionCandidate.value,
        counterPersistenceReceipt: credentialCounterPersistence.value,
        counterResolution: trustDecisionCandidateCounterResolution,
        credentialLifecycleStatus: "active",
        lifecycleSnapshot: verifiedVaultSessionUnlock.value.transitionResult.snapshot,
        credentialId: "alpha0-public-directory-credential",
        providerKind: "webauthn_passkey",
        ownerCommitment: identity.ownerCommitment,
        sessionId,
        applicationId: "ethereum-net",
        authenticationPurpose: "high_risk_action",
        requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
        issuedAt: new Date().toISOString(),
        expiresAt: futureIso(),
        auditCorrelationId: trustManagerAuditCorrelationId
      },
      createEphemeralTrustDecisionEvidenceConsumptionStore()
    )
    : undefined;
  const authoritativePolicyDecision = (input.includeAuthoritativePolicyDecision
    || input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    && authoritativeTrustDecision?.value
    && verifiedVaultSessionUnlock?.value?.transitionResult.snapshot
    ? createAuthoritativePolicyDecision(
      {
        requestId: "alpha0-production-authoritative-policy-decision",
        authoritativeTrustDecision: authoritativeTrustDecision.value,
        capabilityRequest: {
          requestId: "alpha0-policy-capability-request",
          applicationId: "ethereum-net",
          capability: "request_transaction_submission",
          sensitivity: "privileged",
          scope: {
            applicationId: "ethereum-net",
            chainId: 8453,
            action: "send_eth",
            resource: "alpha0-demo-target",
            expiresAt: futureIso()
          },
          reason: "Alpha 0 policy diagnostic",
          requestedAt: new Date().toISOString()
        },
        actionContext: {
          actionType: "send_eth",
          targetReference: "alpha0-demo-target",
          requestedValue: "0.01 ETH",
          requestedDurationSeconds: 300,
          requestedScope: {
            applicationId: "ethereum-net",
            chainId: 8453,
            action: "send_eth",
            resource: "alpha0-demo-target"
          },
          chainId: 8453,
          network: "base"
        },
        policySet: {
          policySetId: "alpha0-authoritative-policy-set",
          version: "alpha0-policy-v1",
          expiresAt: futureIso(),
          rules: [
            {
              ruleId: "alpha0-require-user-approval",
              type: "require_user_approval",
              effect: "require_user_approval"
            },
            {
              ruleId: "alpha0-limit-duration",
              type: "limit_duration",
              effect: "restrict_duration",
              constraints: [{
                constraintId: "alpha0-duration-limit",
                kind: "duration",
                value: 300
              }]
            },
            {
              ruleId: "alpha0-limit-value",
              type: "limit_value",
              effect: "restrict_value",
              constraints: [{
                constraintId: "alpha0-value-limit",
                kind: "value",
                value: "0.01 ETH"
              }]
            },
            {
              ruleId: "alpha0-restrict-target",
              type: "restrict_target",
              effect: "restrict_target",
              constraints: [{
                constraintId: "alpha0-target-limit",
                kind: "custom",
                value: "alpha0-demo-target"
              }]
            }
          ]
        },
        lifecycleSnapshot: verifiedVaultSessionUnlock.value.transitionResult.snapshot,
        sessionId,
        lifecycleState: verifiedVaultSessionUnlock.value.transitionResult.snapshot.state,
        ownerCommitment: identity.ownerCommitment,
        applicationId: "ethereum-net",
        capabilityName: "request_transaction_submission",
        requestedScope: {
          applicationId: "ethereum-net",
          chainId: 8453,
          action: "send_eth",
          resource: "alpha0-demo-target"
        },
        requestedDurationSeconds: 300,
        actionType: "send_eth",
        targetReference: "alpha0-demo-target",
        requestedValue: "0.01 ETH",
        chainId: 8453,
        network: "base",
        authenticationPurpose: "high_risk_action",
        requestedAssurance: ["user_presence", "user_verification", "phishing_resistant"],
        issuedAt: new Date().toISOString(),
        expiresAt: futureIso(),
        auditCorrelationId: trustManagerAuditCorrelationId
      },
      createEphemeralPolicyDecisionEvidenceConsumptionStore()
    )
    : undefined;
  const platformApprovalActionRequest = (input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    ? Object.freeze({
      sessionId,
      applicationId: "ethereum-net",
      ownerCommitment: identity.ownerCommitment,
      capabilityName: "request_transaction_submission",
      actionType: "send_eth",
      targetReference: "alpha0-demo-target",
      requestedValue: "0.01 ETH",
      effectiveScope: {
        applicationId: "ethereum-net",
        chainId: 8453,
        action: "send_eth",
        resource: "alpha0-demo-target"
      },
      effectiveDurationSeconds: 300,
      chainId: 8453,
      network: "base",
      auditCorrelationId: trustManagerAuditCorrelationId
    })
    : undefined;
  const platformApprovalSummary: UserApprovalPresentationSummary | undefined =
    (input.includePlatformUserApprovalDecision || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    ? Object.freeze({
      applicationId: "ethereum-net",
      applicationName: "Ethereum Net",
      capabilityName: "request_transaction_submission",
      actionType: "send_eth",
      targetReference: "alpha0-demo-target",
      requestedValue: "0.01 ETH",
      effectiveScope: {
        applicationId: "ethereum-net",
        chainId: 8453,
        action: "send_eth",
        resource: "alpha0-demo-target"
      },
      effectiveDurationSeconds: 300,
      chainId: 8453,
      network: "base",
      trustLimitations: ["Trust Manager decision only; no application authority."],
      policyRestrictions: {
        effectiveDurationSeconds: 300,
        effectiveValueLimit: "0.01 ETH",
        effectiveTargetRestrictions: ["alpha0-demo-target"],
        policyRestrictions: ["explicit user approval required"]
      },
      riskDisclosures: [{
        disclosureId: "alpha0-user-approval-risk",
        summary: "Transaction submission remains blocked until future capability activation and authorization.",
        severity: "medium" as const
      }],
      expiresAt: futureIso()
    })
    : undefined;
  const platformApprovalRequest = (input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    && authoritativeTrustDecision?.value
    && authoritativePolicyDecision?.value
    && verifiedVaultSessionUnlock?.value?.transitionResult.snapshot
    && platformApprovalActionRequest
    && platformApprovalSummary
    ? createPlatformUserApprovalRequest({
      requestId: "alpha0-production-platform-user-approval-request",
      authoritativeTrustDecision: authoritativeTrustDecision.value,
      authoritativePolicyDecision: authoritativePolicyDecision.value,
      actionRequest: platformApprovalActionRequest,
      lifecycleSnapshot: verifiedVaultSessionUnlock.value.transitionResult.snapshot,
      approvalSurface: "desktop_native",
      approvalChallengeReference: "alpha0-platform-approval-challenge",
      presentationSummary: platformApprovalSummary,
      requestedAt: new Date().toISOString(),
      expiresAt: futureIso(),
      auditCorrelationId: trustManagerAuditCorrelationId,
      humanReadableSummary:
        "Explicit in-memory local platform artifact for Alpha 0 user approval diagnostic; no OS consent is claimed."
    })
    : undefined;
  const platformApprovalArtifactOutcome = input.approvalOutcome === "deny"
    ? "denied"
    : input.approvalOutcome === "cancel"
      ? "cancelled"
      : input.approvalOutcome === "expired"
        ? "expired"
        : "approved";
  const platformApprovalArtifact = platformApprovalRequest?.value
    ? Object.freeze({
      platformUserApprovalArtifactId: "alpha0-platform-user-approval-artifact",
      platformUserApprovalRequestId:
        platformApprovalRequest.value.platformUserApprovalRequestId,
      approvalSurface: "desktop_native",
      outcome: platformApprovalArtifactOutcome,
      decidedAt: new Date().toISOString(),
      presentationDigest: input.approvalOutcome === "digest_mismatch"
        ? createUserApprovalPresentationDigest({
          ...(platformApprovalSummary as UserApprovalPresentationSummary),
          targetReference: "alpha0-hidden-mutated-target"
        })
        : platformApprovalRequest.value.presentationDigest,
      approvalChallengeReference:
        platformApprovalRequest.value.approvalChallengeReference,
      sessionId,
      applicationId: "ethereum-net",
      ownerCommitment: identity.ownerCommitment,
      deviceReference: "alpha0-local-desktop-device",
      platformProviderReference:
        "alpha0-explicit-in-memory-local-platform-artifact",
      userPresenceIndicated: platformApprovalArtifactOutcome === "approved",
      userVerificationIndicated: platformApprovalArtifactOutcome === "approved",
      productionBound: true,
      fixtureOnly: false,
      expiresAt: input.approvalOutcome === "expired" ? new Date(Date.now() - 1000).toISOString() : futureIso(),
      auditCorrelationId: trustManagerAuditCorrelationId,
      biometricTemplateIncluded: false as const,
      rawPlatformSecretIncluded: false as const,
      rawPrivateKeyIncluded: false as const,
      rawWebAuthnPrivateMaterialIncluded: false as const,
      vaultMaterialIncluded: false as const,
      credentialRecordIncluded: false as const,
      authorizationPackageIncluded: false as const,
      adapterPayloadIncluded: false as const
    })
    : undefined;
  const platformUserApprovalDecision = (input.includePlatformUserApprovalDecision
    || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    && authoritativeTrustDecision?.value
    && authoritativePolicyDecision?.value
    && platformApprovalRequest?.value
    && platformApprovalArtifact
    && verifiedVaultSessionUnlock?.value?.transitionResult.snapshot
    && platformApprovalActionRequest
    ? createPlatformUserApprovalDecision({
      requestId: "alpha0-production-platform-user-approval-decision",
      authoritativeTrustDecision: authoritativeTrustDecision.value,
      authoritativePolicyDecision: authoritativePolicyDecision.value,
      actionRequest: platformApprovalActionRequest,
      platformApprovalRequest: platformApprovalRequest.value,
      platformApprovalArtifact,
      lifecycleSnapshot: verifiedVaultSessionUnlock.value.transitionResult.snapshot,
      issuedAt: new Date().toISOString(),
      expiresAt: futureIso(),
      auditCorrelationId: trustManagerAuditCorrelationId
    }, createEphemeralUserApprovalArtifactConsumptionStore())
    : undefined;
  const platformUserApprovalDecisionOutcome =
    platformUserApprovalDecision?.value?.outcome
      ?? (platformUserApprovalDecision?.error?.code === "PLATFORM_USER_APPROVAL_PRESENTATION_DIGEST_MISMATCH"
        ? "presentation_digest_mismatch"
        : platformUserApprovalDecision?.error?.code === "PLATFORM_USER_APPROVAL_ARTIFACT_REPLAYED"
          ? "evidence_replayed"
          : platformUserApprovalDecision?.error
            ? "approval_artifact_invalid"
            : undefined);
  const capabilityGrantStore = createInMemoryAuthoritativeCapabilityGrantStore();
  const authoritativeCapabilityGrantResult = (input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    && authoritativeTrustDecision?.value
    && authoritativePolicyDecision?.value
    && platformUserApprovalDecision?.value
    && verifiedVaultSessionUnlock?.value?.transitionResult.snapshot
    ? createAuthoritativeCapabilityGrant({
      requestId: "alpha0-production-authoritative-capability-activation",
      authoritativeTrustDecision: authoritativeTrustDecision.value,
      authoritativePolicyDecision: authoritativePolicyDecision.value,
      platformUserApprovalDecision: platformUserApprovalDecision.value,
      lifecycleSnapshot: verifiedVaultSessionUnlock.value.transitionResult.snapshot,
      userSessionContext: {
        sessionId,
        ownerCommitment: identity.ownerCommitment,
        status: "unlocked",
        activeApplicationId: "ethereum-net",
        activeCapabilityIds: [],
        pendingIntentIds: [],
        policyMode: "default",
        metadata: {
          deviceVaultUnlocked: true,
          protectedStateAvailable: true
        }
      },
      ownerCommitment: identity.ownerCommitment,
      sessionId,
      applicationId: "ethereum-net",
      capabilityName: "request_transaction_submission",
      requestedScope: {
        applicationId: "ethereum-net",
        chainId: 8453,
        action: "send_eth",
        resource: "alpha0-demo-target"
      },
      effectiveScope: authoritativePolicyDecision.value.effectiveScope,
      requestedDurationSeconds: 300,
      effectiveDurationSeconds: authoritativePolicyDecision.value.effectiveDurationSeconds,
      allowedTargets: authoritativePolicyDecision.value.effectiveTargetRestrictions,
      valueLimit: authoritativePolicyDecision.value.effectiveValueLimit,
      actionTypes: [authoritativePolicyDecision.value.scope.actionType],
      chainId: 8453,
      network: "base",
      issuedAt: new Date().toISOString(),
      expiresAt: futureIso(),
      auditCorrelationId: trustManagerAuditCorrelationId
    }, createEphemeralCapabilityActivationEvidenceConsumptionStore())
    : undefined;
  const userSessionCapabilityMutation =
    authoritativeCapabilityGrantResult?.value
      ? capabilityGrantStore.activate(authoritativeCapabilityGrantResult.value)
      : undefined;
  const authoritativeCapabilityGrant =
    userSessionCapabilityMutation?.grant ?? authoritativeCapabilityGrantResult?.value;
  const activationDiagnosticSucceeded = (!input.includeAuthoritativeCapabilityActivation
    && !input.includeAuthorizationDecisionCandidate
    && !includeAuthorizationPackageDraftStage)
    || (input.approvalOutcome === undefined || input.approvalOutcome === "approve"
      ? authoritativeCapabilityGrantResult?.status === "approved"
        && userSessionCapabilityMutation?.status === "activated"
      : authoritativeCapabilityGrantResult === undefined
        || authoritativeCapabilityGrantResult.status !== "approved");
  const authorizationCandidateScenario =
    input.authorizationCandidateScenario ?? "exact";
  const candidateActionType: AuthorizationActionType =
    authorizationCandidateScenario === "capability_mismatch"
      ? "transaction_preparation"
      : "transaction_submission";
  const candidateTarget = authorizationCandidateScenario === "target_mismatch"
    ? "alpha0-mutated-target"
    : "alpha0-demo-target";
  const candidateValue = authorizationCandidateScenario === "value_limit_exceeded"
    ? "1 ETH"
    : "0.01 ETH";
  const candidateScope = authorizationCandidateScenario === "scope_widening"
    ? {
      applicationId: "ethereum-net",
      chainId: 8453,
      action: "send_eth",
      resource: "alpha0-mutated-target"
    }
    : {
      applicationId: "ethereum-net",
      chainId: 8453,
      action: "send_eth",
      resource: "alpha0-demo-target"
    };
  const candidateConsumerDataReference =
    authorizationCandidateScenario === "additional_approval_required"
      ? "alpha0-consumer-data-mutated"
      : "alpha0-consumer-data-original";
  const approvedActionDigestPreview =
    authorizationCandidateScenario === "additional_approval_required"
      ? createAuthorizationActionDigestPreview({
        intentId: "alpha0-production-authorization-intent",
        actionType: candidateActionType,
        applicationId: "ethereum-net",
        sessionId,
        ownerCommitment: identity.ownerCommitment,
        requiredCapability: "request_transaction_submission",
        target: "alpha0-demo-target",
        method: "send_eth",
        value: "0.01 ETH",
        scope: {
          applicationId: "ethereum-net",
          chainId: 8453,
          action: "send_eth",
          resource: "alpha0-demo-target"
        },
        requestedDurationSeconds: 300,
        chainId: 8453,
        network: "base",
        consumerDataReference: "alpha0-consumer-data-original",
        issuedAt: "alpha0-approved-action-issued-at",
        expiresAt: "alpha0-approved-action-expires-at",
        auditCorrelationId: trustManagerAuditCorrelationId
      } as AuthorizationDecisionCandidateActionSummary).digestPreview
      : undefined;
  const authorizationCandidateExpiresAt = authoritativeCapabilityGrant
    ? new Date(Date.parse(authoritativeCapabilityGrant.validity.expiresAt) - 1_000).toISOString()
    : futureIso();
  const authorizationDecisionCandidateResult = (input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage)
    && authoritativeCapabilityGrant
    && verifiedVaultSessionUnlock?.value?.transitionResult.snapshot
    ? createAuthorizationDecisionCandidate({
      requestId: "alpha0-production-authorization-decision-candidate",
      activeCapabilityGrant: authoritativeCapabilityGrant,
      intent: {
        intentId: "alpha0-production-authorization-intent",
        kind: candidateActionType === "transaction_preparation"
          ? "prepare-transaction"
          : "submit-transaction",
        applicationId: "ethereum-net",
        requestedCapabilities: [
          candidateActionType === "transaction_preparation"
            ? "request_transaction_preparation"
            : "request_transaction_submission"
        ],
        payload: {
          chainId: 8453,
          target: candidateTarget,
          value: candidateValue,
          callData: "0x"
        },
        status: "created",
        createdAt: new Date().toISOString(),
        expiresAt: authorizationCandidateExpiresAt
      },
      actionType: candidateActionType,
      lifecycleSnapshot: verifiedVaultSessionUnlock.value.transitionResult.snapshot,
      userSessionContext: {
        sessionId,
        ownerCommitment: identity.ownerCommitment,
        status: "unlocked",
        activeApplicationId: "ethereum-net",
        activeCapabilityIds: [authoritativeCapabilityGrant.authoritativeCapabilityGrantId],
        pendingIntentIds: ["alpha0-production-authorization-intent"],
        policyMode: "default",
        metadata: {
          deviceVaultUnlocked: true,
          protectedStateAvailable: true
        }
      },
      ownerCommitment: identity.ownerCommitment,
      sessionId,
      applicationId: "ethereum-net",
      target: candidateTarget,
      method: "send_eth",
      value: candidateValue,
      scope: candidateScope,
      requestedDurationSeconds: 300,
      chainId: 8453,
      network: "base",
      consumerDataReference: candidateConsumerDataReference,
      approvedActionDigestPreview,
      issuedAt: new Date().toISOString(),
      expiresAt: authorizationCandidateExpiresAt,
      auditCorrelationId: trustManagerAuditCorrelationId
    }, createEphemeralAuthorizationCandidateConsumptionStore(),
    createInMemoryAuthorizationDecisionCandidateStore())
    : undefined;
  const authorizationDecisionCandidate = authorizationDecisionCandidateResult?.value;
  const authorizationCandidateDiagnosticSucceeded = (!input.includeAuthorizationDecisionCandidate
    && !includeAuthorizationPackageDraftStage)
    || (includeAuthorizationPackageDraftStage || authorizationCandidateScenario === "exact"
      ? authorizationDecisionCandidateResult?.status === "approved"
      : authorizationDecisionCandidateResult !== undefined
        && authorizationDecisionCandidateResult.status !== "approved");
  const authorizationPackageDraftScenario =
    input.authorizationPackageDraftScenario ?? "exact";
  const alpha0UnlockConsumer = "0x1000000000000000000000000000000000000001";
  const alpha0UnlockAccount = "0x1000000000000000000000000000000000000002";
  const alpha0UnlockTarget = "0x1000000000000000000000000000000000000003";
  const alpha0NullifierSeed = "0x00000000000000000000000000000000000000000000000000000000a1fa0001";
  const packageDraftExpiresAt = authorizationPackageDraftScenario === "expiry_beyond_capability_grant"
    && authoritativeCapabilityGrant
    ? new Date(Date.parse(authoritativeCapabilityGrant.validity.expiresAt) + 60_000).toISOString()
    : authorizationCandidateExpiresAt;
  const packageDraftAuditCorrelationId =
    authorizationPackageDraftScenario === "evidence_chain_mismatch"
      ? `${trustManagerAuditCorrelationId}:mutated`
      : trustManagerAuditCorrelationId;
  const packageDraftCanonicalAction = deriveCanonicalAuthorizationActionHash({
    chainId: 8453,
    consumer: alpha0UnlockConsumer,
    account: alpha0UnlockAccount,
    target: alpha0UnlockTarget,
    value: 0,
    callData: "0x"
  });
  const packageDraftCanonicalPolicyHash = derivePolicyHash({
    chainId: 8453,
    consumer: alpha0UnlockConsumer,
    target: alpha0UnlockTarget,
    expiry: BigInt(Math.floor(Date.parse(packageDraftExpiresAt) / 1000)),
    policyDataHash: dataHash("0x")
  });
  const packageDraftNullifier = authorizationPackageDraftScenario === "invalid_nullifier"
    ? "0x1234"
    : includeActionUnlockProofGenerationStage
      ? deriveNullifier({
        ownerCommitment: identity.ownerCommitment,
        actionHash: packageDraftCanonicalAction.actionHash,
        policyHash: packageDraftCanonicalPolicyHash,
        nullifierSeed: alpha0NullifierSeed
      })
      : `0x${nodeCrypto.createHash("sha256").update([
        sessionId,
        identity.ownerCommitment,
        "alpha0-public-package-draft-nullifier"
      ].join(":")).digest("hex")}`;
  const expectedPackageDraftActionHash = authorizationPackageDraftScenario === "mutated_action"
    ? deriveCanonicalAuthorizationActionHash({
      chainId: 8453,
      consumer: alpha0UnlockConsumer,
      account: alpha0UnlockAccount,
      target: alpha0UnlockTarget,
      value: 0,
      callData: "0x"
    }).actionHash
    : undefined;
  const authorizationPackageDraftResult = includeAuthorizationPackageDraftStage
    && authoritativeCapabilityGrant
    && authorizationDecisionCandidate
    && authoritativeTrustDecision?.value
    && authoritativePolicyDecision?.value
    && platformUserApprovalDecision?.value
    ? createAuthorizationPackageDraft({
      requestId: "alpha0-production-authorization-package-draft",
      activeCapabilityGrant: authoritativeCapabilityGrant,
      authorizationDecisionCandidate,
      authoritativeTrustDecision: authoritativeTrustDecision.value,
      authoritativePolicyDecision: authoritativePolicyDecision.value,
      platformUserApprovalDecision: platformUserApprovalDecision.value,
      intent: {
        intentId: authorizationDecisionCandidate.binding.intentId,
        kind: "submit-transaction",
        applicationId: "ethereum-net",
        requestedCapabilities: [authorizationDecisionCandidate.binding.requiredCapability],
        payload: {
          chainId: 8453,
          target: authorizationDecisionCandidate.actionSummary.target,
          value: authorizationDecisionCandidate.actionSummary.value,
          consumer: alpha0UnlockConsumer,
          account: alpha0UnlockAccount,
          actionUnlockTarget: alpha0UnlockTarget
        },
        status: "created",
        createdAt: new Date().toISOString(),
        expiresAt: packageDraftExpiresAt
      },
      chainId: 8453,
      consumer: alpha0UnlockConsumer,
      account: alpha0UnlockAccount,
      target: authorizationPackageDraftScenario === "mutated_action"
        ? "0x1000000000000000000000000000000000000004"
        : alpha0UnlockTarget,
      method: "send_eth",
      value: 0,
      callData: authorizationPackageDraftScenario === "consumer_data_mismatch"
        ? "0x1234"
        : "0x",
      policyData: "0x",
      nullifier: packageDraftNullifier as `0x${string}`,
      nullifierSafeReference: "alpha0-public-nullifier-reference",
      expectedConsumerDataHash: authorizationPackageDraftScenario === "consumer_data_mismatch"
        ? "0x0000000000000000000000000000000000000000000000000000000000000001"
        : undefined,
      expectedActionHash: expectedPackageDraftActionHash,
      issuedAt: new Date().toISOString(),
      expiresAt: packageDraftExpiresAt,
      auditCorrelationId: packageDraftAuditCorrelationId
    }, createEphemeralAuthorizationPackageDraftConsumptionStore(),
    createInMemoryAuthorizationPackageDraftStore())
    : undefined;
  const authorizationPackageDraft = authorizationPackageDraftResult?.value;
  const authorizationPackageDraftDiagnosticSucceeded = !includeAuthorizationPackageDraftStage
    || (authorizationPackageDraftScenario === "exact"
      ? authorizationPackageDraftResult?.status === "approved"
      : authorizationPackageDraftResult !== undefined
        && authorizationPackageDraftResult.status !== "approved");
  const actionUnlockProofGenerationScenario =
    input.actionUnlockProofGenerationScenario ?? "exact";
  const proofGenerationConsumptionStore =
    createEphemeralActionUnlockProofGenerationConsumptionStore();
  const proofGenerationArtifactStore = createInMemoryActionUnlockProofGenerationArtifactStore();
  const actionUnlockProofGenerationResult = includeActionUnlockProofGenerationStage
    && authorizationPackageDraft
    ? await generateActionUnlockProof({
      requestId: "alpha0-production-action-unlock-proof-generation",
      authorizationPackageDraft,
      witnessProvider: createStaticActionUnlockProtectedWitnessProvider({
        providerId: "alpha0-action-unlock-proof-witness-provider",
        providerKind: "local_test_fixture",
        displayName: "Alpha 0 local ACTION_UNLOCK proof witness provider",
        philSecret: privateIdentity.philSecret,
        nullifierSeed: actionUnlockProofGenerationScenario === "witness_binding_mismatch"
          ? "0x00000000000000000000000000000000000000000000000000000000a1fa0002"
          : alpha0NullifierSeed,
        failOnConsume: actionUnlockProofGenerationScenario === "prover_failure"
      }),
      issuedAt: new Date().toISOString(),
      expiresAt: authorizationPackageDraft.validity.expiresAt,
      auditCorrelationId: trustManagerAuditCorrelationId,
      timeoutMs: actionUnlockProofGenerationScenario === "timeout" ? 1 : 120_000,
      includeProofBlob: includeFinalizedAuthorizationPackageStage === true,
      expectedProofInputHash: actionUnlockProofGenerationScenario === "proof_input_hash_mismatch"
        ? "0x0000000000000000000000000000000000000000000000000000000000000001"
        : authorizationPackageDraft.hashSummary.proofInputHash
    }, proofGenerationConsumptionStore, proofGenerationArtifactStore)
    : undefined;
  const actionUnlockProofGenerationReplayResult =
    includeActionUnlockProofGenerationStage
      && actionUnlockProofGenerationScenario === "witness_replay"
      && authorizationPackageDraft
      ? await generateActionUnlockProof({
        requestId: "alpha0-production-action-unlock-proof-generation-replay",
        authorizationPackageDraft,
        witnessProvider: createStaticActionUnlockProtectedWitnessProvider({
          providerId: "alpha0-action-unlock-proof-witness-provider-replay",
          providerKind: "local_test_fixture",
          displayName: "Alpha 0 local ACTION_UNLOCK proof witness provider replay",
          philSecret: privateIdentity.philSecret,
          nullifierSeed: alpha0NullifierSeed
        }),
        issuedAt: new Date().toISOString(),
        expiresAt: authorizationPackageDraft.validity.expiresAt,
        auditCorrelationId: trustManagerAuditCorrelationId,
        timeoutMs: 120_000,
        includeProofBlob: includeFinalizedAuthorizationPackageStage === true,
        expectedProofInputHash: authorizationPackageDraft.hashSummary.proofInputHash
      }, proofGenerationConsumptionStore, proofGenerationArtifactStore)
      : undefined;
  const effectiveActionUnlockProofGenerationResult =
    actionUnlockProofGenerationReplayResult ?? actionUnlockProofGenerationResult;
  const actionUnlockProofGenerationArtifact =
    effectiveActionUnlockProofGenerationResult?.value;
  const actionUnlockProofGenerationDiagnosticSucceeded =
    !includeActionUnlockProofGenerationStage
    || (actionUnlockProofGenerationScenario === "exact"
      ? effectiveActionUnlockProofGenerationResult?.status === "approved"
      : effectiveActionUnlockProofGenerationResult !== undefined
        && effectiveActionUnlockProofGenerationResult.status !== "approved");
  const finalizedAuthorizationPackageScenario =
    input.finalizedAuthorizationPackageScenario ?? "exact";
  const proofArtifactForVerification: ActionUnlockProofGenerationArtifact | undefined =
    includeFinalizedAuthorizationPackageStage && actionUnlockProofGenerationArtifact
      ? finalizedAuthorizationPackageScenario === "invalid_proof"
        ? Object.freeze({
          ...actionUnlockProofGenerationArtifact,
          proofArtifact: Object.freeze({
            ...actionUnlockProofGenerationArtifact.proofArtifact,
            proofBlob: "0x1234" as `0x${string}`,
            proofBlobIncluded: true,
            proofDigest: dataHash("0x1234"),
            proofByteLength: 2
          })
        })
        : finalizedAuthorizationPackageScenario === "public_input_mismatch"
          ? Object.freeze({
            ...actionUnlockProofGenerationArtifact,
            publicInputs: Object.freeze({
              ...actionUnlockProofGenerationArtifact.publicInputs,
              actionHash:
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            })
          })
          : actionUnlockProofGenerationArtifact
      : undefined;
  const actionUnlockProofVerificationConsumptionStore =
    createEphemeralActionUnlockProofVerificationConsumptionStore();
  const actionUnlockProofVerificationResultStore =
    createInMemoryActionUnlockProofVerificationResultStore();
  const actionUnlockProofVerificationResult =
    includeFinalizedAuthorizationPackageStage
    && authorizationPackageDraft
    && proofArtifactForVerification
      ? await verifyGeneratedActionUnlockProof({
        requestId: "alpha0-production-action-unlock-proof-verification",
        authorizationPackageDraft,
        proofGenerationArtifact: proofArtifactForVerification,
        issuedAt: new Date().toISOString(),
        expiresAt: authorizationPackageDraft.validity.expiresAt,
        auditCorrelationId: trustManagerAuditCorrelationId,
        timeoutMs: finalizedAuthorizationPackageScenario === "verification_timeout"
          ? 1
          : 120_000,
        expectedProofInputHash:
          finalizedAuthorizationPackageScenario === "proof_input_hash_mismatch"
            ? "0x0000000000000000000000000000000000000000000000000000000000000001"
            : authorizationPackageDraft.hashSummary.proofInputHash,
        expectedFactShapeReference:
          finalizedAuthorizationPackageScenario === "fact_shape_mismatch"
            ? ("[invalid_fact_shape]" as "[fact_high, fact_low]")
            : "[fact_high, fact_low]"
      }, actionUnlockProofVerificationConsumptionStore,
      actionUnlockProofVerificationResultStore)
      : undefined;
  const actionUnlockProofVerification = actionUnlockProofVerificationResult?.value;
  const finalizedAuthorizationPackageConsumptionStore =
    createEphemeralFinalizedAuthorizationPackageConsumptionStore();
  const finalizedAuthorizationPackageStore = createInMemoryFinalizedAuthorizationPackageStore();
  const finalizedAuthorizationPackageResult =
    includeFinalizedAuthorizationPackageStage
    && authorizationPackageDraft
    && actionUnlockProofGenerationArtifact
    && actionUnlockProofVerification
      ? finalizeAuthorizationPackage({
        requestId: "alpha0-production-finalized-authorization-package",
        authorizationPackageDraft,
        proofGenerationArtifact: actionUnlockProofGenerationArtifact,
        proofVerificationResult: actionUnlockProofVerification,
        issuedAt: new Date().toISOString(),
        expiresAt: finalizedAuthorizationPackageScenario === "expired_package"
          ? new Date(Date.now() - 1_000).toISOString()
          : authorizationPackageDraft.validity.expiresAt,
        auditCorrelationId: trustManagerAuditCorrelationId,
        includeProofBlob: false
      }, finalizedAuthorizationPackageConsumptionStore,
      finalizedAuthorizationPackageStore)
      : undefined;
  const finalizedAuthorizationPackage = finalizedAuthorizationPackageResult?.value;
  const finalizedAuthorizationPackageDiagnosticSucceeded =
    !includeFinalizedAuthorizationPackageStage
    || (finalizedAuthorizationPackageScenario === "exact"
      ? actionUnlockProofVerificationResult?.status === "approved"
        && finalizedAuthorizationPackageResult?.status === "approved"
      : finalizedAuthorizationPackageScenario === "expired_package"
        ? actionUnlockProofVerificationResult?.status === "approved"
          && finalizedAuthorizationPackageResult !== undefined
          && finalizedAuthorizationPackageResult.status !== "approved"
        : actionUnlockProofVerificationResult !== undefined
          && actionUnlockProofVerificationResult.status !== "approved"
          && finalizedAuthorizationPackageResult === undefined);
  const authorizationExecutionReadinessScenario =
    input.authorizationExecutionReadinessScenario ?? "exact";
  const basePublicationTarget: VerifiedFactPublicationTarget = Object.freeze({
    chainProfile: Object.freeze({
      chainId: 8453,
      network: "base",
      profileId: "ethereum-base",
      adapterId: "ethereum",
      ethereumFirstExecutionPath: true
    }),
    verifier: Object.freeze({
      verifierReference: "alpha0-base-action-unlock-verifier",
      verifierAddress: "0x1000000000000000000000000000000000000004" as `0x${string}`,
      proofType: "stwo-unlock-keccak-v1"
    }),
    registry: Object.freeze({
      registryReference: "alpha0-base-verified-fact-registry",
      registryAddress: "0x1000000000000000000000000000000000000005" as `0x${string}`,
      factShapeReference: "[fact_high, fact_low]"
    }),
    consumer: Object.freeze({
      consumerReference: "alpha0-base-action-unlock-consumer",
      consumerAddress: alpha0UnlockConsumer as `0x${string}`,
      smartAccountReference: alpha0UnlockAccount
    }),
    smartAccount: Object.freeze({
      smartAccountReference: alpha0UnlockAccount,
      smartAccountAddress: alpha0UnlockAccount as `0x${string}`,
      authorityModel: "erc4337_smart_account",
      requiresPhilCoreAuthorization: true
    })
  });
  const publicationTarget: VerifiedFactPublicationTarget =
    authorizationExecutionReadinessScenario === "configuration_mismatch"
      ? Object.freeze({
        ...basePublicationTarget,
        chainProfile: Object.freeze({
          ...basePublicationTarget.chainProfile,
          chainId: 1 as 8453
        })
      })
      : basePublicationTarget;
  const packageForPublication = input.includeAuthorizationExecutionReadiness
    && finalizedAuthorizationPackage
    && authorizationExecutionReadinessScenario === "expired_package"
    ? Object.freeze({
      ...finalizedAuthorizationPackage,
      validity: Object.freeze({
        ...finalizedAuthorizationPackage.validity,
        expiresAt: new Date(Date.now() - 1_000).toISOString()
      })
    })
    : finalizedAuthorizationPackage;
  const verifiedFactPublicationRequestDraftStore =
    createInMemoryVerifiedFactPublicationRequestDraftStore();
  const verifiedFactPublicationRequestDraftResult =
    input.includeAuthorizationExecutionReadiness
    && packageForPublication
      ? createVerifiedFactPublicationRequestDraft({
        requestId: "alpha0-production-verified-fact-publication-request",
        finalizedAuthorizationPackage: packageForPublication,
        target: publicationTarget,
        issuedAt: new Date().toISOString(),
        expiresAt: packageForPublication.validity.expiresAt,
        auditCorrelationId: trustManagerAuditCorrelationId,
        expectedChainId: 8453,
        expectedNetwork: "base",
        expectedProofInputHash:
          packageForPublication.actionUnlockAuthorization.proofInputHash,
        expectedFactHigh: packageForPublication.factShapePreview.factHigh,
        expectedFactLow: packageForPublication.factShapePreview.factLow,
        expectedNullifier: packageForPublication.actionUnlockAuthorization.nullifier
      }, verifiedFactPublicationRequestDraftStore)
      : undefined;
  const verifiedFactPublicationRequestDraft =
    verifiedFactPublicationRequestDraftResult?.value;
  const fixtureFactState: VerifiedFactState =
    authorizationExecutionReadinessScenario === "fact_already_published"
      ? "fact_already_published"
      : authorizationExecutionReadinessScenario === "fact_state_unknown"
        ? "fact_state_unknown"
        : "fact_not_published";
  const fixtureNullifierState: AuthorizationNullifierState =
    authorizationExecutionReadinessScenario === "nullifier_already_consumed"
      ? "nullifier_already_consumed"
      : authorizationExecutionReadinessScenario === "nullifier_state_unknown"
        ? "nullifier_state_unknown"
        : "nullifier_available";
  const authorizationExecutionReadinessResultStore =
    createInMemoryAuthorizationExecutionReadinessResultStore();
  const authorizationExecutionReadinessResult =
    input.includeAuthorizationExecutionReadiness
    && verifiedFactPublicationRequestDraft
      ? await evaluateAuthorizationExecutionReadiness({
        requestId: "alpha0-production-authorization-execution-readiness",
        publicationRequestDraft: verifiedFactPublicationRequestDraft,
        factStateReader: createFixtureVerifiedFactStateReader({
          state: fixtureFactState,
          blockReference: "fixture-block:alpha0-readiness",
          freshnessWindowMs: 30_000
        }),
        nullifierStateReader: createFixtureAuthorizationNullifierStateReader({
          state: fixtureNullifierState,
          blockReference: "fixture-block:alpha0-readiness",
          freshnessWindowMs: 30_000
        }),
        issuedAt: new Date().toISOString(),
        expiresAt: verifiedFactPublicationRequestDraft.validity.expiresAt,
        auditCorrelationId: trustManagerAuditCorrelationId,
        expectedChainId: 8453,
        expectedNetwork: "base"
      }, authorizationExecutionReadinessResultStore)
      : undefined;
  const authorizationExecutionReadiness =
    authorizationExecutionReadinessResult?.value;
  const authorizationExecutionReadinessDiagnosticSucceeded =
    !input.includeAuthorizationExecutionReadiness
    || (authorizationExecutionReadinessScenario === "exact"
      ? verifiedFactPublicationRequestDraftResult?.status === "approved"
        && authorizationExecutionReadinessResult?.status === "approved"
      : authorizationExecutionReadinessScenario === "configuration_mismatch"
        || authorizationExecutionReadinessScenario === "expired_package"
        ? verifiedFactPublicationRequestDraftResult !== undefined
          && verifiedFactPublicationRequestDraftResult.status !== "approved"
          && authorizationExecutionReadinessResult === undefined
        : verifiedFactPublicationRequestDraftResult?.status === "approved"
          && authorizationExecutionReadinessResult !== undefined
          && authorizationExecutionReadinessResult.status !== "approved");

  return Object.freeze({
    sequence: input.sequence ?? "production_webauthn_vault_unlock",
    finalStatus: verification.status === "approved"
      && candidate?.status === "approved"
      && partialUnlock?.status === "approved"
      && deviceVaultUnlockResult?.status === "approved"
      && verifiedVaultSessionUnlock?.status === "approved"
      && (!input.includeProtectedStateView || protectedStateView?.status === "approved")
      && (!includePublicCredentialDirectory || publicCredentialDirectory?.status === "approved")
      && (!includeSelectedCredentialPublicMaterial
        || selectedCredentialPublicMaterial?.status === "approved")
      && (!includeTrustManagerVerificationInput
        || trustManagerVerificationInput?.status === "approved")
      && (!input.includeTrustManagerProductionVerification
        || trustManagerProductionVerification?.status === "approved")
      && (!input.includeBoundedTrustDecisionCandidate
        || boundedTrustDecisionCandidate?.status === "approved")
      && (!input.includeCredentialCounterPersistence
        || credentialCounterPersistence?.status === "approved")
      && (!input.includeAuthoritativeTrustDecision
        || authoritativeTrustDecision?.status === "approved")
      && (!input.includeAuthoritativePolicyDecision
        || authoritativePolicyDecision?.status === "approved")
      && (!input.includePlatformUserApprovalDecision
        || platformUserApprovalDecision?.status === "approved"
        || input.approvalOutcome === "digest_mismatch")
      && activationDiagnosticSucceeded
      && authorizationCandidateDiagnosticSucceeded
      && authorizationPackageDraftDiagnosticSucceeded
      && actionUnlockProofGenerationDiagnosticSucceeded
      && finalizedAuthorizationPackageDiagnosticSucceeded
      && authorizationExecutionReadinessDiagnosticSucceeded
      && lifecycleStore.getSnapshot()?.state === "unlocked"
      ? "succeeded"
      : "failed",
    finalState: lifecycleStore.getSnapshot()?.state,
    transitions: Object.freeze(transitions),
    productionAuthenticationVerification: verification.value,
    lifecycleTransitionCandidate: candidate?.value,
    productionVerifiedPartialUnlock: partialUnlock?.value,
    deviceVaultUnlockResult: deviceVaultUnlockResult?.value,
    verifiedVaultSessionUnlock: verifiedVaultSessionUnlock?.value,
    protectedStateView: protectedStateView?.value,
    publicCredentialDirectory: publicCredentialDirectory?.value,
    selectedCredentialPublicMaterial: selectedCredentialPublicMaterial?.value,
    trustManagerVerificationInput: trustManagerVerificationInput?.value,
    trustManagerProductionVerification: trustManagerProductionVerification?.value,
    boundedTrustDecisionCandidate: boundedTrustDecisionCandidate?.value,
    credentialCounterPersistenceReceipt: credentialCounterPersistence?.value,
    trustDecisionCandidateCounterResolution,
    authoritativeTrustDecision: authoritativeTrustDecision?.value,
    authoritativePolicyDecision: authoritativePolicyDecision?.value,
    platformUserApprovalDecision: platformUserApprovalDecision?.value,
    platformUserApprovalDecisionOutcome,
    platformUserApprovalDecisionErrorCode: platformUserApprovalDecision?.error?.code,
    platformUserApprovalArtifactSurface: platformApprovalArtifact?.approvalSurface,
    platformUserApprovalArtifactOutcome: platformApprovalArtifact?.outcome,
    authoritativeCapabilityGrant,
    authoritativeCapabilityGrantErrorCode: authoritativeCapabilityGrantResult?.error?.code,
    userSessionCapabilityMutation,
    authorizationCandidateScenario: input.includeAuthorizationDecisionCandidate
      ? authorizationCandidateScenario
      : undefined,
    authorizationDecisionCandidate,
    authorizationDecisionCandidateErrorCode:
      authorizationDecisionCandidateResult?.error?.code,
    authorizationPackageDraftScenario: includeAuthorizationPackageDraftStage
      ? authorizationPackageDraftScenario
      : undefined,
    authorizationPackageDraft,
    authorizationPackageDraftErrorCode:
      authorizationPackageDraftResult?.error?.code,
    actionUnlockProofGenerationScenario: includeActionUnlockProofGenerationStage
      ? actionUnlockProofGenerationScenario
      : undefined,
    actionUnlockProofGenerationArtifact,
    actionUnlockProofGenerationErrorCode:
      effectiveActionUnlockProofGenerationResult?.error?.code,
    finalizedAuthorizationPackageScenario: includeFinalizedAuthorizationPackageStage
      ? finalizedAuthorizationPackageScenario
      : undefined,
    actionUnlockProofVerification,
    actionUnlockProofVerificationErrorCode:
      actionUnlockProofVerificationResult?.error?.code,
    finalizedAuthorizationPackage,
    finalizedAuthorizationPackageErrorCode:
      finalizedAuthorizationPackageResult?.error?.code,
    authorizationExecutionReadinessScenario: input.includeAuthorizationExecutionReadiness
      ? authorizationExecutionReadinessScenario
      : undefined,
    verifiedFactPublicationRequestDraft,
    verifiedFactPublicationRequestDraftErrorCode:
      verifiedFactPublicationRequestDraftResult?.error?.code,
    authorizationExecutionReadiness,
    authorizationExecutionReadinessErrorCode:
      authorizationExecutionReadinessResult?.error?.code,
    limitations: Object.freeze([
      "diagnostic_only",
      "production_webauthn_assertion_verified_from_explicit_inputs",
      "browser_webauthn_prompt_not_invoked",
      "credential_not_loaded_from_device_vault",
      "device_vault_unlock_performed_against_explicit_in_memory_test_envelope",
      ...(input.includeProtectedStateView
        ? ["protected_state_identity_summary_only"]
        : []),
      ...(includePublicCredentialDirectory
        ? ["public_credential_directory_descriptors_only"]
        : []),
      ...(includeSelectedCredentialPublicMaterial
        ? ["selected_credential_public_material_single_credential_only"]
        : []),
      ...(includeTrustManagerVerificationInput
        ? ["trust_manager_verification_input_no_trust_decision"]
        : []),
      ...(includeTrustManagerProductionVerification
        ? ["trust_manager_production_verification_evidence_only"]
        : []),
      ...(input.includeBoundedTrustDecisionCandidate
        || input.includeCredentialCounterPersistence
        || input.includeAuthoritativePolicyDecision
        ? ["bounded_trust_decision_candidate_no_authority"]
        : []),
      ...(input.includeCredentialCounterPersistence
        || input.includeAuthoritativeTrustDecision
        || input.includeAuthoritativePolicyDecision
        ? ["credential_counter_persistence_counter_field_only"]
        : []),
      ...(input.includeAuthoritativeTrustDecision
        || input.includeAuthoritativePolicyDecision
        ? ["authoritative_trust_decision_trust_manager_only"]
        : []),
      ...(input.includeAuthoritativePolicyDecision
        || input.includePlatformUserApprovalDecision
        ? ["authoritative_policy_decision_security_policy_only"]
        : []),
      ...(input.includePlatformUserApprovalDecision
        ? ["platform_user_approval_decision_only", "explicit_in_memory_platform_artifact_no_native_ui"]
        : []),
      ...(input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage
        ? [
          "authoritative_capability_grant_session_scoped_only",
          "capability_grant_is_not_action_authorization",
          "active_capability_process_local_only",
          "explicit_in_memory_platform_artifact_no_native_ui"
        ]
        : []),
      ...(input.includeAuthorizationDecisionCandidate
        || includeAuthorizationPackageDraftStage
        ? [
          "authorization_decision_candidate_only",
          "authorization_candidate_is_not_action_authorization",
          "action_digest_preview_not_proof_input_hash",
          "action_unlock_not_assembled"
        ]
        : []),
      ...(includeAuthorizationPackageDraftStage
        ? [
          "authorization_package_draft_only",
          "action_unlock_public_tuple_draft_only",
          includeActionUnlockProofGenerationStage
            ? "proof_input_hash_computed_before_bounded_proof_generation"
            : "proof_input_hash_computed_but_no_proof_generated",
          "nullifier_not_consumed",
          "authorization_package_not_executable"
        ]
        : []),
      ...(includeActionUnlockProofGenerationStage
        ? [
          "ordinary_action_unlock_proof_generation_quarantined",
          "experimental_secret_bearing_proof_requires_explicit_research_gate",
          "device_vault_witness_proof_generation_disabled",
          "no_proof_artifact_returned",
          "proof_not_verified_by_runtime",
          "verified_fact_not_published",
          "nullifier_not_consumed",
          "authorization_package_not_finalized",
          "adapter_execution_not_allowed"
        ]
        : []),
      ...(includeFinalizedAuthorizationPackageStage
        ? [
          "finalization_blocked_before_local_proof_verification",
          "no_finalized_authorization_package",
          "no_fact_shape_preview",
          "verified_fact_not_published",
          "on_chain_verifier_not_called",
          "nullifier_not_consumed",
          "contract_execution_not_allowed",
          "transaction_not_submitted"
        ]
        : []),
      ...(input.includeAuthorizationExecutionReadiness
        ? [
          "verified_fact_publication_request_only",
          "read_only_fact_state_check_only",
          "read_only_nullifier_state_check_only",
          "readiness_is_not_execution_authority",
          "state_snapshot_requires_revalidation_before_transaction",
          "contract_not_called",
          "user_operation_not_created",
          "transaction_not_signed_or_submitted",
          "chain_state_not_mutated"
        ]
        : []),
      "opaque_process_local_vault_handle_only",
      "phil_secret_not_exposed",
      "raw_vault_key_not_exposed",
      "raw_vault_contents_not_exposed",
      "application_credentials_not_loaded",
      ...(authoritativeCapabilityGrant
        ? []
        : ["no_active_capability"]),
      "no_session_key",
      "no_authorization",
      input.includeCredentialCounterPersistence
        || input.includeAuthoritativeTrustDecision
        || input.includeAuthoritativePolicyDecision
        || input.includePlatformUserApprovalDecision
        || input.includeAuthoritativeCapabilityActivation
    || input.includeAuthorizationDecisionCandidate
    || includeAuthorizationPackageDraftStage
    || includeActionUnlockProofGenerationStage
        ? "no_authority_persistence"
        : "no_persistence"
    ]),
    productionAuthenticationPerformed: true,
    vaultUnlocked: deviceVaultUnlockResult?.value?.deviceVaultUnlocked === true,
    activeCapabilityCreated: userSessionCapabilityMutation?.activeCapabilityCreated === true,
    authorizationCreated: false,
    proofExecuted: false,
    adapterExecuted: false,
    persisted: false
  });
}

function runFixtureUnlockLifecycleDiagnostic(): Alpha0LifecycleDiagnosticResult {
  const store = createEphemeralUserSessionLifecycleStore();
  const transitions: UserSessionTransitionResult[] = [];
  const initialized = store.initialize({
    sessionId: "alpha0-fixture-lifecycle-session",
    transitionRequestId: "alpha0-fixture-initialize"
  });
  if (initialized.transitionResult) {
    transitions.push(initialized.transitionResult);
  }
  const requestUnlock = store.requestTransition({
    transitionRequestId: "alpha0-fixture-request-unlock",
    event: "request_unlock"
  });
  if (requestUnlock.transitionResult) {
    transitions.push(requestUnlock.transitionResult);
  }

  const adapter = createDeveloperFixtureAuthenticationProviderAdapter();
  const requirement: ProductionAuthenticationRequirement = {
    purpose: "session_unlock" as const,
    provider: {
      providerKind: "developer_fixture" as const,
      providerId: adapter.describeProvider().providerId,
      minimumAssurance: ["developer_fixture", "user_presence"] as const,
      userPresenceRequired: true
    },
    challengeReference: {
      challengeReferenceId: "alpha0-fixture-unlock-challenge",
      createdAt: new Date().toISOString(),
      expiresAt: futureIso(),
      generatedChallenge: false as const
    },
    correlation: {
      sessionId: "alpha0-fixture-lifecycle-session",
      lifecycleTransitionRequestId: "alpha0-fixture-unlock-succeeded",
      lifecycleEvent: "unlock_succeeded" as const,
      ownerCommitment: "0xalpha0fixtureownercommitment",
      applicationId: "ethereum-net" as const,
      providerId: adapter.describeProvider().providerId,
      auditCorrelationId: "alpha0-fixture-lifecycle-session:fixture-unlock"
    },
    expiresAt: futureIso(),
    requestedAssurance: ["developer_fixture", "user_presence"] as const
  };
  const authRequest = adapter.createAuthenticationRequest(requirement).value;
  const evidence = authRequest
    ? adapter.normalizeEvidence({
      request: authRequest,
      providerResponseReference: {
        kind: "webauthn" as const,
        credentialId: "alpha0-fixture-credential",
        authenticatorDataReference: "alpha0-fixture-authenticator-data-reference",
        clientDataHashReference: "alpha0-fixture-client-data-hash-reference",
        signatureReference: "alpha0-fixture-signature-reference",
        signCounter: 1,
        userPresent: true,
        userVerified: true,
        origin: "https://alpha0.local",
        rpId: "alpha0.local",
        challengeBindingReference: "alpha0-fixture-unlock-challenge"
      },
      expiresAt: futureIso(),
      providedAssurance: ["developer_fixture", "user_presence"]
    }).value
    : undefined;
  const verification = authRequest && evidence
    ? verifyDeveloperFixtureAuthenticationEvidence({
      requestId: "alpha0-fixture-verification",
      authenticationRequest: authRequest,
      evidence,
      expectedSessionId: "alpha0-fixture-lifecycle-session",
      expectedLifecycleTransitionRequestId: "alpha0-fixture-unlock-succeeded",
      expectedOwnerCommitment: "0xalpha0fixtureownercommitment",
      expectedChallengeReferenceId: "alpha0-fixture-unlock-challenge",
      expectedProviderId: adapter.describeProvider().providerId,
      expectedAuditCorrelationId: "alpha0-fixture-lifecycle-session:fixture-unlock",
      expectedAssurance: ["developer_fixture", "user_presence"]
    })
    : undefined;
  const snapshot = store.getSnapshot();
  if (verification?.value?.verifiedFixtureEvidenceReference && snapshot) {
    const transition = transitionUserSessionWithVerifiedFixtureEvidence({
      lifecycleSnapshot: snapshot,
      transitionRequest: {
        transitionRequestId: "alpha0-fixture-unlock-succeeded",
        event: "unlock_succeeded"
      },
      verifiedFixtureEvidenceReference: verification.value.verifiedFixtureEvidenceReference
    });
    if (transition.value?.transitionResult) {
      transitions.push(transition.value.transitionResult);
      if (transition.value.transitionResult.snapshot) {
        store.replaceSnapshot(transition.value.transitionResult.snapshot);
      }
    }
  }

  return Object.freeze({
    sequence: "fixture_unlock",
    finalStatus: verification?.status === "approved" && store.getSnapshot()?.state === "unlocked"
      ? "succeeded"
      : "failed",
    finalState: store.getSnapshot()?.state,
    transitions: Object.freeze(transitions),
    fixtureAuthenticationVerification: verification?.value,
    limitations: Object.freeze([
      "diagnostic_only",
      "fixture_only_authentication",
      "production_authentication_not_performed",
      "device_vault_not_unlocked",
      "no_active_capability",
      "no_authorization",
      "no_persistence"
    ]),
    productionAuthenticationPerformed: false,
    vaultUnlocked: false,
    activeCapabilityCreated: false,
    authorizationCreated: false,
    proofExecuted: false,
    adapterExecuted: false,
    persisted: false
  });
}

function evidenceReferencesForLifecycleEvent(
  event: UserSessionLifecycleEvent
) {
  if (event === "unlock_succeeded") {
    return [{
      referenceId: "alpha0-unverified-unlock-evidence-reference",
      kind: "unlock_evidence" as const,
      source: "alpha0-diagnostic",
      verified: false as const,
      rawEvidenceIncluded: false as const
    }];
  }
  if (event === "timeout_warning" || event === "timeout_reached") {
    return [{
      referenceId: "alpha0-unverified-timeout-reference",
      kind: "timeout_source" as const,
      source: "alpha0-diagnostic",
      verified: false as const,
      rawEvidenceIncluded: false as const
    }];
  }
  if (event === "request_recovery" || event === "recovery_entered") {
    return [{
      referenceId: "alpha0-unverified-recovery-reference",
      kind: "recovery_evidence" as const,
      source: "alpha0-diagnostic",
      verified: false as const,
      rawEvidenceIncluded: false as const
    }];
  }
  return undefined;
}

export function runAlpha0LifecycleDiagnostic(
  sequence: Alpha0LifecycleDiagnosticSequence = "states"
): Alpha0LifecycleDiagnosticResult {
  const stateList = Object.freeze(USER_SESSION_LIFECYCLE_TRANSITION_TABLE
    .flatMap((rule) => [rule.currentState, rule.nextState])
    .filter((state, index, states) => states.indexOf(state) === index)
    .filter(isUserSessionLifecycleState));

  if (sequence === "states") {
    return Object.freeze({
      sequence,
      finalStatus: "succeeded",
      stateList,
      transitions: Object.freeze([]),
      limitations: Object.freeze([
        "diagnostic_only",
        "no_authentication",
        "no_vault_unlock",
        "no_authority"
      ]),
      productionAuthenticationPerformed: false,
      vaultUnlocked: false,
      activeCapabilityCreated: false,
      authorizationCreated: false,
      proofExecuted: false,
      adapterExecuted: false,
      persisted: false
    });
  }

  if (sequence === "fixture_unlock") {
    return runFixtureUnlockLifecycleDiagnostic();
  }

  if (
    sequence === "production_webauthn_partial_unlock"
    || sequence === "production_webauthn_vault_unlock"
    || sequence === "production_protected_state_view"
    || sequence === "production_public_credential_directory"
    || sequence === "production_selected_credential_public_material"
    || sequence === "production_trust_manager_verification_input"
    || sequence === "production_trust_manager_assertion_verification"
    || sequence === "production_trust_decision_candidate"
    || sequence === "production_credential_counter_persistence"
    || sequence === "production_authoritative_trust_decision"
    || sequence === "production_authoritative_policy_decision"
    || sequence === "production_platform_user_approval_decision"
    || sequence === "production_authoritative_capability_activation"
    || sequence === "production_authorization_decision_candidate"
    || sequence === "production_authorization_package_draft"
    || sequence === "production_action_unlock_proof_generation"
    || sequence === "production_finalized_authorization_package"
    || sequence === "production_authorization_execution_readiness"
  ) {
    return Object.freeze({
      sequence,
      finalStatus: "failed",
      transitions: Object.freeze([]),
      limitations: Object.freeze([
        "diagnostic_only",
        "production_webauthn_lifecycle_diagnostic_requires_async_verifier"
      ]),
      productionAuthenticationPerformed: false,
      vaultUnlocked: false,
      activeCapabilityCreated: false,
      authorizationCreated: false,
      proofExecuted: false,
      adapterExecuted: false,
      persisted: false
    });
  }

  const store = createEphemeralUserSessionLifecycleStore();
  const transitions: UserSessionTransitionResult[] = [];
  const initialized = store.initialize({
    sessionId: "alpha0-lifecycle-session",
    transitionRequestId: "alpha0-lifecycle-initialize"
  });
  if (initialized.transitionResult) {
    transitions.push(initialized.transitionResult);
  }

  for (const [index, event] of transitionEventsForLifecycleSequence(sequence).entries()) {
    const transition = store.requestTransition({
      transitionRequestId: `alpha0-lifecycle-${sequence}-${index + 1}`,
      event,
      evidenceReferences: evidenceReferencesForLifecycleEvent(event)
    });
    if (transition.transitionResult) {
      transitions.push(transition.transitionResult);
    }
  }

  const hasRejectedTransition = transitions.some((transition) => transition.status !== "transitioned");

  return Object.freeze({
    sequence,
    finalStatus: hasRejectedTransition && sequence !== "invalid_transition" ? "failed" : "succeeded",
    finalState: store.getSnapshot()?.state,
    transitions: Object.freeze(transitions),
    limitations: Object.freeze([
      "diagnostic_only",
      "evidence_references_unverified",
      "no_authentication",
      "no_vault_unlock",
      "no_active_capability",
      "no_authorization",
      "no_persistence"
    ]),
    productionAuthenticationPerformed: false,
    vaultUnlocked: false,
    activeCapabilityCreated: false,
    authorizationCreated: false,
    proofExecuted: false,
    adapterExecuted: false,
    persisted: false
  });
}

export async function runAlpha0LifecycleDiagnosticAsync(
  sequence: Alpha0LifecycleDiagnosticSequence = "states",
  options: {
    readonly approvalOutcome?: Alpha0PlatformApprovalDiagnosticOutcome;
    readonly authorizationCandidateScenario?: Alpha0AuthorizationCandidateDiagnosticScenario;
    readonly authorizationPackageDraftScenario?: Alpha0AuthorizationPackageDraftDiagnosticScenario;
    readonly actionUnlockProofGenerationScenario?: Alpha0ActionUnlockProofGenerationDiagnosticScenario;
    readonly finalizedAuthorizationPackageScenario?:
      Alpha0FinalizedAuthorizationPackageDiagnosticScenario;
    readonly authorizationExecutionReadinessScenario?:
      Alpha0AuthorizationExecutionReadinessDiagnosticScenario;
  } = {}
): Promise<Alpha0LifecycleDiagnosticResult> {
  if (sequence === "production_webauthn_partial_unlock") {
    return runProductionWebAuthnPartialUnlockLifecycleDiagnostic();
  }
  if (sequence === "production_webauthn_vault_unlock") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic();
  }
  if (sequence === "production_protected_state_view") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeProtectedStateView: true,
      sequence: "production_protected_state_view"
    });
  }
  if (sequence === "production_public_credential_directory") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includePublicCredentialDirectory: true,
      sequence: "production_public_credential_directory"
    });
  }
  if (sequence === "production_selected_credential_public_material") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeSelectedCredentialPublicMaterial: true,
      sequence: "production_selected_credential_public_material"
    });
  }
  if (sequence === "production_trust_manager_verification_input") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeTrustManagerVerificationInput: true,
      sequence: "production_trust_manager_verification_input"
    });
  }
  if (sequence === "production_trust_manager_assertion_verification") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeTrustManagerProductionVerification: true,
      sequence: "production_trust_manager_assertion_verification"
    });
  }
  if (sequence === "production_trust_decision_candidate") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeBoundedTrustDecisionCandidate: true,
      sequence: "production_trust_decision_candidate"
    });
  }
  if (sequence === "production_credential_counter_persistence") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeCredentialCounterPersistence: true,
      sequence: "production_credential_counter_persistence"
    });
  }
  if (sequence === "production_authoritative_trust_decision") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeAuthoritativeTrustDecision: true,
      sequence: "production_authoritative_trust_decision"
    });
  }
  if (sequence === "production_authoritative_policy_decision") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeAuthoritativePolicyDecision: true,
      sequence: "production_authoritative_policy_decision"
    });
  }
  if (sequence === "production_platform_user_approval_decision") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includePlatformUserApprovalDecision: true,
      approvalOutcome: options.approvalOutcome ?? "approve",
      sequence: "production_platform_user_approval_decision"
    });
  }
  if (sequence === "production_authoritative_capability_activation") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeAuthoritativeCapabilityActivation: true,
      approvalOutcome: options.approvalOutcome ?? "approve",
      sequence: "production_authoritative_capability_activation"
    });
  }
  if (sequence === "production_authorization_decision_candidate") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeAuthorizationDecisionCandidate: true,
      approvalOutcome: options.approvalOutcome ?? "approve",
      authorizationCandidateScenario: options.authorizationCandidateScenario ?? "exact",
      sequence: "production_authorization_decision_candidate"
    });
  }
  if (sequence === "production_authorization_package_draft") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeAuthorizationPackageDraft: true,
      approvalOutcome: options.approvalOutcome ?? "approve",
      authorizationCandidateScenario: "exact",
      authorizationPackageDraftScenario: options.authorizationPackageDraftScenario ?? "exact",
      sequence: "production_authorization_package_draft"
    });
  }
  if (sequence === "production_action_unlock_proof_generation") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeActionUnlockProofGeneration: true,
      approvalOutcome: options.approvalOutcome ?? "approve",
      authorizationCandidateScenario: "exact",
      authorizationPackageDraftScenario: "exact",
      actionUnlockProofGenerationScenario:
        options.actionUnlockProofGenerationScenario ?? "exact",
      sequence: "production_action_unlock_proof_generation"
    });
  }
  if (sequence === "production_finalized_authorization_package") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeFinalizedAuthorizationPackage: true,
      approvalOutcome: options.approvalOutcome ?? "approve",
      authorizationCandidateScenario: "exact",
      authorizationPackageDraftScenario: "exact",
      actionUnlockProofGenerationScenario: "exact",
      finalizedAuthorizationPackageScenario:
        options.finalizedAuthorizationPackageScenario ?? "exact",
      sequence: "production_finalized_authorization_package"
    });
  }
  if (sequence === "production_authorization_execution_readiness") {
    return runProductionWebAuthnVaultUnlockLifecycleDiagnostic({
      includeAuthorizationExecutionReadiness: true,
      approvalOutcome: options.approvalOutcome ?? "approve",
      authorizationCandidateScenario: "exact",
      authorizationPackageDraftScenario: "exact",
      actionUnlockProofGenerationScenario: "exact",
      finalizedAuthorizationPackageScenario: "exact",
      authorizationExecutionReadinessScenario:
        options.authorizationExecutionReadinessScenario ?? "exact",
      sequence: "production_authorization_execution_readiness"
    });
  }
  return runAlpha0LifecycleDiagnostic(sequence);
}

export function sanitizeAlpha0LifecycleDiagnosticResult(
  result: Alpha0LifecycleDiagnosticResult
): Readonly<Record<string, unknown>> {
  return Object.freeze({
    sequence: result.sequence,
    finalStatus: result.finalStatus,
    finalState: result.finalState,
    stateList: result.stateList,
    transitions: result.transitions.map((transition) => Object.freeze({
      status: transition.status,
      previousState: transition.previousState,
      event: transition.event,
      nextState: transition.nextState,
      reason: transition.reason,
      evidenceReferencesVerified: transition.evidenceReferencesVerified,
      futureRequirements: transition.futureRequirements
    })),
    fixtureAuthenticationVerification: result.fixtureAuthenticationVerification
      ? Object.freeze({
        status: result.fixtureAuthenticationVerification.status,
        outcome: result.fixtureAuthenticationVerification.outcome,
        fixtureOnly: result.fixtureAuthenticationVerification.fixtureOnly,
        productionAuthenticationPerformed:
          result.fixtureAuthenticationVerification.productionAuthenticationPerformed,
        vaultUnlocked: result.fixtureAuthenticationVerification.vaultUnlocked,
        grantsAuthority: result.fixtureAuthenticationVerification.grantsAuthority,
        persisted: result.fixtureAuthenticationVerification.persisted
      })
      : undefined,
    productionAuthenticationVerification: result.productionAuthenticationVerification
      ? Object.freeze({
        status: result.productionAuthenticationVerification.status,
        outcome: result.productionAuthenticationVerification.outcome,
        productionVerified: result.productionAuthenticationVerification.evidenceSummary.productionVerified,
        browserCredentialPrompted: result.productionAuthenticationVerification.browserCredentialPrompted,
        vaultUnlocked: result.productionAuthenticationVerification.vaultUnlocked,
        grantsCapability: result.productionAuthenticationVerification.grantsCapability,
        authorizationCreated:
          result.productionAuthenticationVerification.createsAuthorizationPackage,
        persisted: result.productionAuthenticationVerification.persisted
      })
      : undefined,
    lifecycleTransitionCandidate: result.lifecycleTransitionCandidate
      ? Object.freeze({
        status: result.lifecycleTransitionCandidate.status,
        outcome: result.lifecycleTransitionCandidate.outcome,
        targetState: result.lifecycleTransitionCandidate.targetState,
        browserWebAuthnInvocationPerformed:
          result.lifecycleTransitionCandidate.browserWebAuthnInvocationPerformed,
        credentialLoadedFromVault:
          result.lifecycleTransitionCandidate.credentialLoadedFromVault,
        deviceVaultUnlocked: result.lifecycleTransitionCandidate.deviceVaultUnlocked,
        activeCapabilityCreated:
          result.lifecycleTransitionCandidate.activeCapabilityCreated,
        authorizationCreated: result.lifecycleTransitionCandidate.authorizationCreated,
        persisted: result.lifecycleTransitionCandidate.persisted
      })
      : undefined,
    productionVerifiedPartialUnlock: result.productionVerifiedPartialUnlock
      ? Object.freeze({
        nextState: result.productionVerifiedPartialUnlock.transitionResult.nextState,
        deviceVaultUnlocked: result.productionVerifiedPartialUnlock.deviceVaultUnlocked,
        protectedIdentityStateAvailable:
          result.productionVerifiedPartialUnlock.protectedIdentityStateAvailable,
        activeCapabilitiesAvailable:
          result.productionVerifiedPartialUnlock.activeCapabilitiesAvailable,
        sessionKeysCreated: result.productionVerifiedPartialUnlock.sessionKeysCreated,
        authorizationCreated: result.productionVerifiedPartialUnlock.authorizationCreated,
        persisted: result.productionVerifiedPartialUnlock.persisted
      })
      : undefined,
    deviceVaultUnlockResult: result.deviceVaultUnlockResult
      ? Object.freeze({
        status: result.deviceVaultUnlockResult.status,
        outcome: result.deviceVaultUnlockResult.outcome,
        deviceVaultUnlocked: result.deviceVaultUnlockResult.deviceVaultUnlocked,
        protectedStateAvailable: result.deviceVaultUnlockResult.protectedStateAvailable,
        vaultHandleId: result.deviceVaultUnlockResult.unlockedVaultHandle?.handleId,
        philSecretExposed: result.deviceVaultUnlockResult.philSecretExposed,
        rawVaultKeyExposed: result.deviceVaultUnlockResult.rawVaultKeyExposed,
        applicationCredentialsLoaded:
          result.deviceVaultUnlockResult.applicationCredentialsLoaded,
        activeCapabilityCreated: result.deviceVaultUnlockResult.activeCapabilityCreated,
        sessionKeyCreated: result.deviceVaultUnlockResult.sessionKeyCreated,
        authorizationCreated: result.deviceVaultUnlockResult.authorizationCreated,
        persistedRuntimeState: result.deviceVaultUnlockResult.persistedRuntimeState
      })
      : undefined,
    verifiedVaultSessionUnlock: result.verifiedVaultSessionUnlock
      ? Object.freeze({
        nextState: result.verifiedVaultSessionUnlock.transitionResult.nextState,
        deviceVaultUnlocked: result.verifiedVaultSessionUnlock.deviceVaultUnlocked,
        protectedStateAvailable: result.verifiedVaultSessionUnlock.protectedStateAvailable,
        philSecretExposed: result.verifiedVaultSessionUnlock.philSecretExposed,
        rawVaultKeyExposed: result.verifiedVaultSessionUnlock.rawVaultKeyExposed,
        applicationCredentialsLoaded:
          result.verifiedVaultSessionUnlock.applicationCredentialsLoaded,
        activeCapabilityCreated: result.verifiedVaultSessionUnlock.activeCapabilityCreated,
        sessionKeyCreated: result.verifiedVaultSessionUnlock.sessionKeyCreated,
        authorizationCreated: result.verifiedVaultSessionUnlock.authorizationCreated,
        persistedRuntimeState: result.verifiedVaultSessionUnlock.persistedRuntimeState
      })
      : undefined,
    protectedStateView: result.protectedStateView
      ? Object.freeze({
        status: result.protectedStateView.status,
        outcome: result.protectedStateView.outcome,
        viewType: result.protectedStateView.viewType,
        summary: result.protectedStateView.summary,
        containsSecrets: result.protectedStateView.containsSecrets,
        containsCredentials: result.protectedStateView.containsCredentials,
        containsPrivateKeys: result.protectedStateView.containsPrivateKeys,
        containsAuthorization: result.protectedStateView.containsAuthorization,
        containsSessionKeys: result.protectedStateView.containsSessionKeys,
        activeCapabilityCreated: result.protectedStateView.activeCapabilityCreated,
        sessionKeyCreated: result.protectedStateView.sessionKeyCreated,
        authorizationCreated: result.protectedStateView.authorizationCreated,
        persisted: result.protectedStateView.persisted
      })
      : undefined,
    publicCredentialDirectory: result.publicCredentialDirectory
      ? Object.freeze({
        status: result.publicCredentialDirectory.status,
        outcome: result.publicCredentialDirectory.outcome,
        operation: result.publicCredentialDirectory.operation,
        credentialCount: result.publicCredentialDirectory.summary.returnedCredentialCount,
        providerKinds: result.publicCredentialDirectory.summary.providerKinds,
        lifecycleStatuses: result.publicCredentialDirectory.summary.lifecycleStatuses,
        recoveryOnlyCount: result.publicCredentialDirectory.summary.recoveryOnlyCount,
        ordinaryUseEligibleCount:
          result.publicCredentialDirectory.summary.ordinaryUseEligibleCount,
        descriptors: result.publicCredentialDirectory.descriptors.map((descriptor) =>
          Object.freeze({
            descriptorId: descriptor.descriptorId,
            credentialId: descriptor.credentialId,
            displayLabel: descriptor.displayLabel,
            providerKind: descriptor.providerKind,
            lifecycleStatus: descriptor.publicLifecycleStatus,
            recoveryOnly: descriptor.recoveryOnly,
            eligibleForOrdinaryEvaluation: descriptor.eligibleForOrdinaryEvaluation,
            containsPrivateMaterial: descriptor.containsPrivateMaterial,
            containsRawAssertionData: descriptor.containsRawAssertionData,
            providesTrustDecision: descriptor.providesTrustDecision,
            grantsAuthority: descriptor.grantsAuthority
          })
        ),
        containsPrivateMaterial: result.publicCredentialDirectory.containsPrivateMaterial,
        containsRawAssertionData: result.publicCredentialDirectory.containsRawAssertionData,
        containsVaultKeys: result.publicCredentialDirectory.containsVaultKeys,
        containsPhilSecret: result.publicCredentialDirectory.containsPhilSecret,
        providesTrustDecision: result.publicCredentialDirectory.providesTrustDecision,
        grantsAuthority: result.publicCredentialDirectory.grantsAuthority
      })
      : undefined,
    selectedCredentialPublicMaterial: result.selectedCredentialPublicMaterial
      ? Object.freeze({
        status: result.selectedCredentialPublicMaterial.status,
        outcome: result.selectedCredentialPublicMaterial.outcome,
        credentialSafeReference:
          result.selectedCredentialPublicMaterial.summary.credentialSafeReference,
        providerKind: result.selectedCredentialPublicMaterial.summary.providerKind,
        publicKeyAlgorithm:
          result.selectedCredentialPublicMaterial.summary.publicKeyAlgorithm,
        publicKeyFingerprint:
          result.selectedCredentialPublicMaterial.summary.publicKeyFingerprint,
        lifecycleStatus:
          result.selectedCredentialPublicMaterial.summary.lifecycleStatus,
        supportedVerificationMethods:
          result.selectedCredentialPublicMaterial.summary.supportedVerificationMethods,
        verificationHandleCreated:
          result.selectedCredentialPublicMaterial.summary.verificationHandleCreated,
        verificationHandleId:
          result.selectedCredentialPublicMaterial.verificationHandle.handleId,
        containsPrivateMaterial:
          result.selectedCredentialPublicMaterial.containsPrivateMaterial,
        containsVaultKey:
          result.selectedCredentialPublicMaterial.containsVaultKey,
        containsPhilSecret:
          result.selectedCredentialPublicMaterial.containsPhilSecret,
        containsRawAssertionPayload:
          result.selectedCredentialPublicMaterial.containsRawAssertionPayload,
        containsRawRegistrationPayload:
          result.selectedCredentialPublicMaterial.containsRawRegistrationPayload,
        trustDecisionCreated:
          result.selectedCredentialPublicMaterial.trustDecisionCreated,
        grantsAuthority:
          result.selectedCredentialPublicMaterial.grantsAuthority,
        verificationPerformed:
          result.selectedCredentialPublicMaterial.verificationPerformed,
        persisted:
          result.selectedCredentialPublicMaterial.persisted
      })
      : undefined,
    trustManagerVerificationInput: result.trustManagerVerificationInput
      ? Object.freeze({
        status: result.trustManagerVerificationInput.status,
        outcome: result.trustManagerVerificationInput.outcome,
        inputId:
          result.trustManagerVerificationInput.verificationInput.trustManagerVerificationInputId,
        credentialSafeReference:
          result.trustManagerVerificationInput.verificationInput.credentialSafeReference,
        providerKind:
          result.trustManagerVerificationInput.verificationInput.providerKind,
        publicKeyAlgorithm:
          result.trustManagerVerificationInput.verificationInput.publicKeyAlgorithm,
        authenticationPurpose:
          result.trustManagerVerificationInput.verificationInput.authenticationPurpose,
        requiredAssurance:
          result.trustManagerVerificationInput.verificationInput.assuranceRequirement.requiredAssurance,
        challengeReferenceId:
          result.trustManagerVerificationInput.verificationInput.challengeBinding.challengeReferenceId,
        challengeCorrelationStatus:
          result.trustManagerVerificationInput.outcome === "verification_input_created"
            ? "matched"
            : "not_matched",
        lifecycleEligible:
          result.trustManagerVerificationInput.outcome === "verification_input_created",
        expiresAt: result.trustManagerVerificationInput.expiresAt,
        verificationPerformed:
          result.trustManagerVerificationInput.verificationPerformed,
        trustDecisionCreated:
          result.trustManagerVerificationInput.trustDecisionCreated,
        authenticationPerformed:
          result.trustManagerVerificationInput.authenticationPerformed,
        vaultHandleExposed:
          result.trustManagerVerificationInput.vaultHandleExposed,
        registryAccessProvided:
          result.trustManagerVerificationInput.registryAccessProvided,
        privateMaterialIncluded:
          result.trustManagerVerificationInput.privateMaterialIncluded,
        grantsAuthority:
          result.trustManagerVerificationInput.grantsAuthority,
        persisted:
          result.trustManagerVerificationInput.persisted
      })
      : undefined,
    trustManagerProductionVerification: result.trustManagerProductionVerification
      ? Object.freeze({
        status: result.trustManagerProductionVerification.status,
        outcome: result.trustManagerProductionVerification.outcome,
        credentialSafeReference:
          result.trustManagerProductionVerification.correlation.credentialSafeReference,
        providerKind: result.trustManagerProductionVerification.correlation.providerKind,
        algorithm:
          result.trustManagerProductionVerification.evidenceSummary.publicKeyAlgorithm,
        challengeVerified:
          result.trustManagerProductionVerification.challengeBindingVerified,
        originVerified:
          result.trustManagerProductionVerification.originVerified,
        rpIdHashVerified:
          result.trustManagerProductionVerification.rpIdHashVerified,
        signatureVerified:
          result.trustManagerProductionVerification.signatureVerified,
        userPresenceVerified:
          result.trustManagerProductionVerification.evidenceSummary.userPresenceVerified,
        userVerificationVerified:
          result.trustManagerProductionVerification.evidenceSummary.userVerificationVerified,
        counterStatus:
          result.trustManagerProductionVerification.counterAssessment.counterStatus,
        counterPersisted:
          result.trustManagerProductionVerification.counterPersisted,
        productionVerifierUsed:
          result.trustManagerProductionVerification.productionVerifierUsed,
        trustDecisionCreated:
          result.trustManagerProductionVerification.trustDecisionCreated,
        capabilityGranted:
          result.trustManagerProductionVerification.capabilityGranted,
        authorizationCreated:
          result.trustManagerProductionVerification.authorizationCreated,
        deviceVaultAccessed:
          result.trustManagerProductionVerification.deviceVaultAccessed,
        persisted:
          result.trustManagerProductionVerification.persisted
      })
      : undefined,
    boundedTrustDecisionCandidate: result.boundedTrustDecisionCandidate
      ? Object.freeze({
        status: result.boundedTrustDecisionCandidate.status,
        outcome: result.boundedTrustDecisionCandidate.outcome,
        credentialLifecycleStatus:
          result.boundedTrustDecisionCandidate.lifecycleAssessment.credentialLifecycleStatus,
        sessionLifecycleState:
          result.boundedTrustDecisionCandidate.lifecycleAssessment.sessionLifecycleState,
        assuranceSufficient:
          result.boundedTrustDecisionCandidate.assurance.sufficient,
        counterStatus:
          result.boundedTrustDecisionCandidate.evidence.counterStatus,
        requiresCounterPersistence:
          result.boundedTrustDecisionCandidate.requiresCounterPersistence,
        requiresWorldIdEnrollment:
          result.boundedTrustDecisionCandidate.requiresWorldIdEnrollment,
        eligibleForAuthoritativeTrustDecision:
          result.boundedTrustDecisionCandidate.eligibleForAuthoritativeTrustDecision,
        activeTrustDecisionCreated:
          result.boundedTrustDecisionCandidate.activeTrustDecisionCreated,
        capabilityGranted:
          result.boundedTrustDecisionCandidate.capabilityGranted,
        authorizationCreated:
          result.boundedTrustDecisionCandidate.authorizationCreated,
        vaultAccessGranted:
          result.boundedTrustDecisionCandidate.vaultAccessGranted,
        persisted:
          result.boundedTrustDecisionCandidate.persisted
      })
      : undefined,
    credentialCounterPersistenceReceipt: result.credentialCounterPersistenceReceipt
      ? Object.freeze({
        status: result.credentialCounterPersistenceReceipt.status,
        outcome: result.credentialCounterPersistenceReceipt.outcome,
        credentialSafeReference:
          result.credentialCounterPersistenceReceipt.correlation.credentialSafeReference,
        previousStoredCounter:
          result.credentialCounterPersistenceReceipt.mutationSummary.previousStoredCounter,
        verifiedReturnedCounter:
          result.credentialCounterPersistenceReceipt.counterState.verifiedReturnedCounter,
        persistedCounter:
          result.credentialCounterPersistenceReceipt.mutationSummary.persistedCounter,
        mutationPerformed:
          result.credentialCounterPersistenceReceipt.mutationSummary.mutationPerformed,
        onlyCounterFieldChanged:
          result.credentialCounterPersistenceReceipt.mutationSummary.onlyCounterFieldChanged,
        registryIntegrityVerified:
          result.credentialCounterPersistenceReceipt.registryIntegrityVerified,
        writeVerified:
          result.credentialCounterPersistenceReceipt.writeVerified,
        counterPersisted:
          result.credentialCounterPersistenceReceipt.counterPersisted,
        trustDecisionCreated:
          result.credentialCounterPersistenceReceipt.trustDecisionCreated,
        capabilityGranted:
          result.credentialCounterPersistenceReceipt.capabilityGranted,
        authorizationCreated:
          result.credentialCounterPersistenceReceipt.authorizationCreated,
        registryPlaintextExposed:
          result.credentialCounterPersistenceReceipt.registryPlaintextExposed,
        privateMaterialExposed:
          result.credentialCounterPersistenceReceipt.privateMaterialExposed
      })
      : undefined,
    trustDecisionCandidateCounterResolution: result.trustDecisionCandidateCounterResolution
      ? Object.freeze({
        resolutionId: result.trustDecisionCandidateCounterResolution.resolutionId,
        counterRequirementSatisfied:
          result.trustDecisionCandidateCounterResolution.counterRequirementSatisfied,
        activeTrustDecisionCreated:
          result.trustDecisionCandidateCounterResolution.activeTrustDecisionCreated,
        capabilityGranted:
          result.trustDecisionCandidateCounterResolution.capabilityGranted,
        authorizationCreated:
          result.trustDecisionCandidateCounterResolution.authorizationCreated,
        persisted:
          result.trustDecisionCandidateCounterResolution.persisted
      })
      : undefined,
    authoritativeTrustDecision: result.authoritativeTrustDecision
      ? Object.freeze({
        status: result.authoritativeTrustDecision.status,
        outcome: result.authoritativeTrustDecision.outcome,
        credentialSafeReference:
          result.authoritativeTrustDecision.scope.credentialSafeReference,
        authenticationPurpose:
          result.authoritativeTrustDecision.scope.authenticationPurpose,
        sessionId: result.authoritativeTrustDecision.scope.sessionId,
        applicationId: result.authoritativeTrustDecision.scope.applicationId,
        assuranceSatisfied:
          result.authoritativeTrustDecision.assuranceSatisfied,
        credentialCounterCommitted:
          result.authoritativeTrustDecision.credentialCounterCommitted,
        acceptedZeroCounterSemantics:
          result.authoritativeTrustDecision.acceptedZeroCounterSemantics,
        expiresAt: result.authoritativeTrustDecision.validity.expiresAt,
        trustDecisionCreated:
          result.authoritativeTrustDecision.trustDecisionCreated,
        capabilityGranted:
          result.authoritativeTrustDecision.capabilityGranted,
        policyApproved:
          result.authoritativeTrustDecision.policyApproved,
        userApprovalCollected:
          result.authoritativeTrustDecision.userApprovalCollected,
        authorizationCreated:
          result.authoritativeTrustDecision.authorizationCreated,
        sessionKeyCreated:
          result.authoritativeTrustDecision.sessionKeyCreated,
        executionAllowed:
          result.authoritativeTrustDecision.executionAllowed,
        worldIdVerified:
          result.authoritativeTrustDecision.worldIdVerified,
        vaultMaterialExposed:
          result.authoritativeTrustDecision.vaultMaterialExposed,
        persistedAsAuthority:
          result.authoritativeTrustDecision.persistedAsAuthority
      })
      : undefined,
    authoritativePolicyDecision: result.authoritativePolicyDecision
      ? Object.freeze({
        status: result.authoritativePolicyDecision.status,
        outcome: result.authoritativePolicyDecision.outcome,
        policySetId: result.authoritativePolicyDecision.binding.policySetId,
        policySetVersion: result.authoritativePolicyDecision.binding.policySetVersion,
        capabilityName: result.authoritativePolicyDecision.scope.capabilityName,
        actionType: result.authoritativePolicyDecision.scope.actionType,
        targetReference: result.authoritativePolicyDecision.scope.targetReference,
        effectiveDurationSeconds:
          result.authoritativePolicyDecision.effectiveDurationSeconds,
        effectiveValueLimit:
          result.authoritativePolicyDecision.effectiveValueLimit,
        effectiveTargetRestrictions:
          result.authoritativePolicyDecision.effectiveTargetRestrictions,
        requiresUserApproval:
          result.authoritativePolicyDecision.requiresUserApproval,
        eligibleForCapabilityActivationReview:
          result.authoritativePolicyDecision.eligibleForCapabilityActivationReview,
        policyDecisionCreated:
          result.authoritativePolicyDecision.policyDecisionCreated,
        trustDecisionAccepted:
          result.authoritativePolicyDecision.trustDecisionAccepted,
        rulesEvaluated:
          result.authoritativePolicyDecision.rulesEvaluated,
        capabilityGranted:
          result.authoritativePolicyDecision.capabilityGranted,
        userApprovalCollected:
          result.authoritativePolicyDecision.userApprovalCollected,
        authorizationCreated:
          result.authoritativePolicyDecision.authorizationCreated,
        sessionKeyCreated:
          result.authoritativePolicyDecision.sessionKeyCreated,
        executionAllowed:
          result.authoritativePolicyDecision.executionAllowed,
        proofExecuted:
          result.authoritativePolicyDecision.proofExecuted,
        adapterExecuted:
          result.authoritativePolicyDecision.adapterExecuted,
        worldIdVerified:
          result.authoritativePolicyDecision.worldIdVerified,
        persistedAsAuthority:
          result.authoritativePolicyDecision.persistedAsAuthority
      })
      : undefined,
    platformUserApprovalDecision: result.platformUserApprovalDecision
      ? Object.freeze({
        status: result.platformUserApprovalDecision.status,
        outcome: result.platformUserApprovalDecision.outcome,
        surface: result.platformUserApprovalDecision.evidence.approvalSurface,
        artifactOutcome: result.platformUserApprovalArtifactOutcome,
        trustDecisionAccepted:
          result.platformUserApprovalDecision.trustDecisionAccepted,
        policyDecisionAccepted:
          result.platformUserApprovalDecision.policyDecisionAccepted,
        presentationDigestMatched:
          result.platformUserApprovalDecision.presentationDigestMatched,
        userPresenceIndicated:
          result.platformUserApprovalDecision.evidence.userPresenceIndicated,
        userVerificationIndicated:
          result.platformUserApprovalDecision.evidence.userVerificationIndicated,
        userApproved: result.platformUserApprovalDecision.userApproved,
        userDenied: result.platformUserApprovalDecision.userDenied,
        userCancelled: result.platformUserApprovalDecision.userCancelled,
        approvalExpired: result.platformUserApprovalDecision.approvalExpired,
        eligibleForCapabilityActivationReview:
          result.platformUserApprovalDecision.eligibleForCapabilityActivationReview,
        productionBound: result.platformUserApprovalDecision.productionBound,
        fixtureOnly: result.platformUserApprovalDecision.fixtureOnly,
        capabilityGranted: result.platformUserApprovalDecision.capabilityGranted,
        authorizationCreated: result.platformUserApprovalDecision.authorizationCreated,
        sessionKeyCreated: result.platformUserApprovalDecision.sessionKeyCreated,
        executionAllowed: result.platformUserApprovalDecision.executionAllowed,
        proofExecuted: result.platformUserApprovalDecision.proofExecuted,
        adapterExecuted: result.platformUserApprovalDecision.adapterExecuted,
        transactionSubmitted: result.platformUserApprovalDecision.transactionSubmitted,
        biometricTemplateStored:
          result.platformUserApprovalDecision.biometricTemplateStored,
        rawPlatformSecretIncluded:
          result.platformUserApprovalDecision.rawPlatformSecretIncluded,
        persistedAsAuthority:
          result.platformUserApprovalDecision.persistedAsAuthority
      })
      : result.platformUserApprovalDecisionOutcome
        ? Object.freeze({
          status: "rejected",
          outcome: result.platformUserApprovalDecisionOutcome,
          errorCode: result.platformUserApprovalDecisionErrorCode,
          surface: result.platformUserApprovalArtifactSurface,
          artifactOutcome: result.platformUserApprovalArtifactOutcome,
          trustDecisionAccepted: false,
          policyDecisionAccepted: false,
          presentationDigestMatched:
            result.platformUserApprovalDecisionOutcome !== "presentation_digest_mismatch",
          userApproved: false,
          userDenied: false,
          userCancelled: false,
          approvalExpired:
            result.platformUserApprovalDecisionOutcome === "approval_expired",
          eligibleForCapabilityActivationReview: false,
          productionBound: false,
          fixtureOnly: false,
          capabilityGranted: false,
          authorizationCreated: false,
          sessionKeyCreated: false,
          executionAllowed: false,
          proofExecuted: false,
          adapterExecuted: false,
          transactionSubmitted: false,
          biometricTemplateStored: false,
          rawPlatformSecretIncluded: false,
          persistedAsAuthority: false
        })
        : undefined,
    authoritativeCapabilityGrant: result.authoritativeCapabilityGrant
      ? Object.freeze({
        status: result.authoritativeCapabilityGrant.status,
        outcome: result.authoritativeCapabilityGrant.outcome,
        grantId: result.authoritativeCapabilityGrant.authoritativeCapabilityGrantId,
        sessionId: result.authoritativeCapabilityGrant.binding.sessionId,
        applicationId: result.authoritativeCapabilityGrant.binding.applicationId,
        capabilityName: result.authoritativeCapabilityGrant.scope.capabilityName,
        effectiveScope: result.authoritativeCapabilityGrant.scope.effectiveScope,
        effectiveDurationSeconds:
          result.authoritativeCapabilityGrant.scope.effectiveDurationSeconds,
        allowedTargets: result.authoritativeCapabilityGrant.scope.allowedTargets,
        valueLimit: result.authoritativeCapabilityGrant.scope.valueLimit,
        actionTypes: result.authoritativeCapabilityGrant.scope.actionTypes,
        expiresAt: result.authoritativeCapabilityGrant.validity.expiresAt,
        capabilityGranted: result.authoritativeCapabilityGrant.capabilityGranted,
        activeCapabilityCreated:
          result.authoritativeCapabilityGrant.activeCapabilityCreated,
        actionAuthorized: result.authoritativeCapabilityGrant.actionAuthorized,
        authorizationCreated: result.authoritativeCapabilityGrant.authorizationCreated,
        authorizationPackageCreated:
          result.authoritativeCapabilityGrant.authorizationPackageCreated,
        sessionKeyCreated: result.authoritativeCapabilityGrant.sessionKeyCreated,
        executionAllowed: result.authoritativeCapabilityGrant.executionAllowed,
        proofExecuted: result.authoritativeCapabilityGrant.proofExecuted,
        adapterExecuted: result.authoritativeCapabilityGrant.adapterExecuted,
        transactionSubmitted: result.authoritativeCapabilityGrant.transactionSubmitted,
        vaultAccessed: result.authoritativeCapabilityGrant.vaultAccessed,
        worldIdVerified: result.authoritativeCapabilityGrant.worldIdVerified,
        persistedAsAuthority: result.authoritativeCapabilityGrant.persistedAsAuthority
      })
      : result.authoritativeCapabilityGrantErrorCode
        ? Object.freeze({
          status: "rejected",
          errorCode: result.authoritativeCapabilityGrantErrorCode,
          capabilityGranted: false,
          activeCapabilityCreated: false,
          actionAuthorized: false,
          authorizationCreated: false,
          authorizationPackageCreated: false,
          sessionKeyCreated: false,
          executionAllowed: false,
          proofExecuted: false,
          adapterExecuted: false,
          transactionSubmitted: false,
          vaultAccessed: false,
          worldIdVerified: false,
          persistedAsAuthority: false
        })
        : undefined,
    userSessionCapabilityMutation: result.userSessionCapabilityMutation
      ? Object.freeze({
        status: result.userSessionCapabilityMutation.status,
        activeCapabilityCreated:
          result.userSessionCapabilityMutation.activeCapabilityCreated,
        activeGrantCount:
          result.userSessionCapabilityMutation.state.activeGrants.length,
        authorizationCreated:
          result.userSessionCapabilityMutation.authorizationCreated,
        sessionKeyCreated:
          result.userSessionCapabilityMutation.sessionKeyCreated,
        executionAllowed:
          result.userSessionCapabilityMutation.executionAllowed,
        persisted: result.userSessionCapabilityMutation.persisted
      })
      : undefined,
    authorizationDecisionCandidate: result.authorizationDecisionCandidate
      ? Object.freeze({
        scenario: result.authorizationCandidateScenario,
        status: result.authorizationDecisionCandidate.status,
        outcome: result.authorizationDecisionCandidate.outcome,
        candidateId:
          result.authorizationDecisionCandidate.authorizationDecisionCandidateId,
        activeCapabilityGrantAccepted:
          result.authorizationDecisionCandidate.activeCapabilityGrantAccepted,
        requiredCapability:
          result.authorizationDecisionCandidate.actionSummary.requiredCapability,
        actionType: result.authorizationDecisionCandidate.actionSummary.actionType,
        target: result.authorizationDecisionCandidate.actionSummary.target,
        method: result.authorizationDecisionCandidate.actionSummary.method,
        value: result.authorizationDecisionCandidate.actionSummary.value,
        scope: result.authorizationDecisionCandidate.actionSummary.scope,
        chainId: result.authorizationDecisionCandidate.actionSummary.chainId,
        network: result.authorizationDecisionCandidate.actionSummary.network,
        consumerDataReference:
          result.authorizationDecisionCandidate.actionSummary.consumerDataReference,
        actionDigestPreview:
          result.authorizationDecisionCandidate.evidence.actionDigestPreview.digestPreview,
        proofRequirement:
          result.authorizationDecisionCandidate.proofRequirement,
        authorizationDecisionCandidateCreated:
          result.authorizationDecisionCandidate.authorizationDecisionCandidateCreated,
        authorizationPackageCreated:
          result.authorizationDecisionCandidate.authorizationPackageCreated,
        actionAuthorized:
          result.authorizationDecisionCandidate.actionAuthorized,
        proofInputHashCreated:
          result.authorizationDecisionCandidate.proofInputHashCreated,
        proofExecuted:
          result.authorizationDecisionCandidate.proofExecuted,
        signatureCreated:
          result.authorizationDecisionCandidate.signatureCreated,
        sessionKeyCreated:
          result.authorizationDecisionCandidate.sessionKeyCreated,
        adapterExecutionAllowed:
          result.authorizationDecisionCandidate.adapterExecutionAllowed,
        transactionSubmitted:
          result.authorizationDecisionCandidate.transactionSubmitted,
        vaultAccessed:
          result.authorizationDecisionCandidate.vaultAccessed,
        worldIdVerified:
          result.authorizationDecisionCandidate.worldIdVerified,
        persistedAsAuthority:
          result.authorizationDecisionCandidate.persistedAsAuthority
      })
      : result.authorizationDecisionCandidateErrorCode
        ? Object.freeze({
          scenario: result.authorizationCandidateScenario,
          status: "rejected",
          errorCode: result.authorizationDecisionCandidateErrorCode,
          authorizationDecisionCandidateCreated: false,
          activeCapabilityGrantAccepted: false,
          authorizationPackageCreated: false,
          actionAuthorized: false,
          proofInputHashCreated: false,
          proofExecuted: false,
          signatureCreated: false,
          sessionKeyCreated: false,
          adapterExecutionAllowed: false,
          transactionSubmitted: false,
          vaultAccessed: false,
          worldIdVerified: false,
          persistedAsAuthority: false
        })
        : undefined,
    authorizationPackageDraft: result.authorizationPackageDraft
      ? Object.freeze({
        scenario: result.authorizationPackageDraftScenario,
        status: result.authorizationPackageDraft.status,
        outcome: result.authorizationPackageDraft.outcome,
        draftId: result.authorizationPackageDraft.authorizationPackageDraftId,
        ownerCommitment:
          result.authorizationPackageDraft.actionUnlockPublicInputDraft.publicInputs.ownerCommitment,
        actionHash:
          result.authorizationPackageDraft.hashSummary.actionHash,
        policyHash:
          result.authorizationPackageDraft.hashSummary.policyHash,
        nullifier:
          result.authorizationPackageDraft.nullifierReference.nullifier,
        consumerDataHash:
          result.authorizationPackageDraft.hashSummary.consumerDataHash,
        expiry:
          result.authorizationPackageDraft.validity.expiry.toString(),
        proofInputHash:
          result.authorizationPackageDraft.hashSummary.proofInputHash,
        proofType:
          result.authorizationPackageDraft.actionUnlockPublicInputDraft.proofType,
        tupleFieldOrder:
          result.authorizationPackageDraft.actionUnlockPublicInputDraft.tupleFieldOrder,
        factShapeReference:
          result.authorizationPackageDraft.actionUnlockPublicInputDraft.factShapeReference,
        proofRequirement:
          result.authorizationPackageDraft.proofRequirement,
        m1ActionDigestPreview:
          result.authorizationPackageDraft.hashSummary.m1ActionDigestPreview,
        m1PreviewIsCanonicalActionHash:
          result.authorizationPackageDraft.hashSummary.m1PreviewIsCanonicalActionHash,
        authorizationPackageDraftCreated:
          result.authorizationPackageDraft.authorizationPackageDraftCreated,
        authorizationPackageExecutable:
          result.authorizationPackageDraft.authorizationPackageExecutable,
        actionAuthorized:
          result.authorizationPackageDraft.actionAuthorized,
        proofGenerated:
          result.authorizationPackageDraft.proofGenerated,
        proofVerified:
          result.authorizationPackageDraft.proofVerified,
        verifiedFactAvailable:
          result.authorizationPackageDraft.verifiedFactAvailable,
        nullifierConsumed:
          result.authorizationPackageDraft.nullifierConsumed,
        adapterExecutionAllowed:
          result.authorizationPackageDraft.adapterExecutionAllowed,
        transactionSubmitted:
          result.authorizationPackageDraft.transactionSubmitted,
        signatureCreated:
          result.authorizationPackageDraft.signatureCreated,
        sessionKeyCreated:
          result.authorizationPackageDraft.sessionKeyCreated,
        vaultAccessed:
          result.authorizationPackageDraft.vaultAccessed,
        persistedAsAuthority:
          result.authorizationPackageDraft.persistedAsAuthority
      })
      : result.authorizationPackageDraftErrorCode
        ? Object.freeze({
          scenario: result.authorizationPackageDraftScenario,
          status: "rejected",
          errorCode: result.authorizationPackageDraftErrorCode,
          authorizationPackageDraftCreated: false,
          authorizationPackageExecutable: false,
          actionAuthorized: false,
          proofGenerated: false,
          proofVerified: false,
          verifiedFactAvailable: false,
          nullifierConsumed: false,
          adapterExecutionAllowed: false,
          transactionSubmitted: false,
          signatureCreated: false,
          sessionKeyCreated: false,
          vaultAccessed: false,
          persistedAsAuthority: false
        })
        : undefined,
    actionUnlockProofGeneration: result.actionUnlockProofGenerationArtifact
      ? Object.freeze({
        scenario: result.actionUnlockProofGenerationScenario,
        status: result.actionUnlockProofGenerationArtifact.status,
        outcome: result.actionUnlockProofGenerationArtifact.outcome,
        artifactId: result.actionUnlockProofGenerationArtifact.proofGenerationArtifactId,
        proofType: result.actionUnlockProofGenerationArtifact.proofType,
        proofInputHash: result.actionUnlockProofGenerationArtifact.proofInputHash,
        proverUsed: result.actionUnlockProofGenerationArtifact.summary.proverUsed,
        proverInvocation: result.actionUnlockProofGenerationArtifact.summary.proverInvocation,
        proofGenerated: result.actionUnlockProofGenerationArtifact.proofGenerated,
        proofByteLength:
          result.actionUnlockProofGenerationArtifact.proofArtifact.proofByteLength,
        proofDigest: result.actionUnlockProofGenerationArtifact.proofArtifact.proofDigest,
        proofBlobIncluded:
          result.actionUnlockProofGenerationArtifact.proofArtifact.proofBlobIncluded,
        publicInputsMatched:
          result.actionUnlockProofGenerationArtifact.summary.publicInputsMatched,
        proofInputHashMatched:
          result.actionUnlockProofGenerationArtifact.summary.proofInputHashMatched,
        temporaryWitnessFileUsed:
          result.actionUnlockProofGenerationArtifact.summary.temporaryWitnessFileUsed,
        temporaryWitnessCleanupStatus:
          result.actionUnlockProofGenerationArtifact.summary.temporaryWitnessCleanupStatus,
        proofVerifiedByRuntime:
          result.actionUnlockProofGenerationArtifact.proofVerifiedByRuntime,
        verifiedFactPublished:
          result.actionUnlockProofGenerationArtifact.verifiedFactPublished,
        nullifierConsumed:
          result.actionUnlockProofGenerationArtifact.nullifierConsumed,
        authorizationPackageFinalized:
          result.actionUnlockProofGenerationArtifact.authorizationPackageFinalized,
        adapterExecutionAllowed:
          result.actionUnlockProofGenerationArtifact.adapterExecutionAllowed,
        transactionSubmitted:
          result.actionUnlockProofGenerationArtifact.transactionSubmitted,
        witnessMaterialExposed:
          result.actionUnlockProofGenerationArtifact.witnessMaterialExposed,
        persisted:
          result.actionUnlockProofGenerationArtifact.persisted
      })
      : result.actionUnlockProofGenerationErrorCode
        ? Object.freeze({
          scenario: result.actionUnlockProofGenerationScenario,
          status: "rejected",
          errorCode: result.actionUnlockProofGenerationErrorCode,
          proofGenerated: false,
          proofVerifiedByRuntime: false,
          verifiedFactPublished: false,
          nullifierConsumed: false,
          authorizationPackageFinalized: false,
          adapterExecutionAllowed: false,
          transactionSubmitted: false,
          witnessMaterialExposed: false,
          persisted: false
        })
        : undefined,
    actionUnlockProofVerification: result.actionUnlockProofVerification
      ? Object.freeze({
        scenario: result.finalizedAuthorizationPackageScenario,
        status: result.actionUnlockProofVerification.status,
        outcome: result.actionUnlockProofVerification.outcome,
        verificationId:
          result.actionUnlockProofVerification.proofVerificationResultId,
        proofType:
          result.actionUnlockProofVerification.verifiedProofReference.proofType,
        proofInputHash: result.actionUnlockProofVerification.proofInputHash,
        proofDigest:
          result.actionUnlockProofVerification.verifiedProofReference.proofDigest,
        proofByteLength:
          result.actionUnlockProofVerification.verifiedProofReference.proofByteLength,
        factShapeReference:
          result.actionUnlockProofVerification.factShapePreview.factShapeReference,
        factHigh: result.actionUnlockProofVerification.factShapePreview.factHigh,
        factLow: result.actionUnlockProofVerification.factShapePreview.factLow,
        verifierUsed: result.actionUnlockProofVerification.summary.verifierUsed,
        verifierInvocation:
          result.actionUnlockProofVerification.summary.verifierInvocation,
        proofVerifiedLocally:
          result.actionUnlockProofVerification.proofVerifiedLocally,
        proofTypeMatched:
          result.actionUnlockProofVerification.proofTypeMatched,
        publicInputsMatched:
          result.actionUnlockProofVerification.publicInputsMatched,
        proofInputHashMatched:
          result.actionUnlockProofVerification.proofInputHashMatched,
        factShapeValidated:
          result.actionUnlockProofVerification.factShapeValidated,
        verifiedFactPublished:
          result.actionUnlockProofVerification.verifiedFactPublished,
        onChainVerificationPerformed:
          result.actionUnlockProofVerification.onChainVerificationPerformed,
        nullifierConsumed: result.actionUnlockProofVerification.nullifierConsumed,
        adapterExecutionAllowed:
          result.actionUnlockProofVerification.adapterExecutionAllowed,
        transactionSubmitted:
          result.actionUnlockProofVerification.transactionSubmitted,
        proofBytesExposedToAudit:
          result.actionUnlockProofVerification.proofBytesExposedToAudit,
        witnessMaterialExposed:
          result.actionUnlockProofVerification.witnessMaterialExposed,
        persisted: result.actionUnlockProofVerification.persisted
      })
      : result.actionUnlockProofVerificationErrorCode
        ? Object.freeze({
          scenario: result.finalizedAuthorizationPackageScenario,
          status: "rejected",
          errorCode: result.actionUnlockProofVerificationErrorCode,
          proofVerifiedLocally: false,
          verifiedFactPublished: false,
          onChainVerificationPerformed: false,
          nullifierConsumed: false,
          adapterExecutionAllowed: false,
          transactionSubmitted: false,
          proofBytesExposedToAudit: false,
          witnessMaterialExposed: false,
          persisted: false
        })
        : undefined,
    finalizedAuthorizationPackage: result.finalizedAuthorizationPackage
      ? Object.freeze({
        scenario: result.finalizedAuthorizationPackageScenario,
        status: result.finalizedAuthorizationPackage.status,
        outcome: result.finalizedAuthorizationPackage.outcome,
        packageId:
          result.finalizedAuthorizationPackage.finalizedAuthorizationPackageId,
        draftId:
          result.finalizedAuthorizationPackage.binding.authorizationPackageDraftId,
        proofVerificationResultId:
          result.finalizedAuthorizationPackage.binding.proofVerificationResultId,
        proofType:
          result.finalizedAuthorizationPackage.actionUnlockAuthorization.proofType,
        proofInputHash:
          result.finalizedAuthorizationPackage.actionUnlockAuthorization.proofInputHash,
        proofDigest:
          result.finalizedAuthorizationPackage.proofArtifact.proofDigest,
        proofByteLength:
          result.finalizedAuthorizationPackage.proofArtifact.proofByteLength,
        proofBlobIncluded:
          result.finalizedAuthorizationPackage.proofArtifact.proofBlobIncluded,
        factShapeReference:
          result.finalizedAuthorizationPackage.factShapePreview.factShapeReference,
        factHigh: result.finalizedAuthorizationPackage.factShapePreview.factHigh,
        factLow: result.finalizedAuthorizationPackage.factShapePreview.factLow,
        authorizationPackageFinalized:
          result.finalizedAuthorizationPackage.authorizationPackageFinalized,
        proofGenerated: result.finalizedAuthorizationPackage.proofGenerated,
        proofVerifiedLocally:
          result.finalizedAuthorizationPackage.proofVerifiedLocally,
        verifiedFactPublished:
          result.finalizedAuthorizationPackage.verifiedFactPublished,
        onChainVerificationPerformed:
          result.finalizedAuthorizationPackage.onChainVerificationPerformed,
        nullifierConsumed: result.finalizedAuthorizationPackage.nullifierConsumed,
        adapterExecutionAllowed:
          result.finalizedAuthorizationPackage.adapterExecutionAllowed,
        contractExecutionAllowed:
          result.finalizedAuthorizationPackage.contractExecutionAllowed,
        transactionSubmitted:
          result.finalizedAuthorizationPackage.transactionSubmitted,
        executableByApplications:
          result.finalizedAuthorizationPackage.executableByApplications,
        witnessMaterialExposed:
          result.finalizedAuthorizationPackage.witnessMaterialExposed,
        persisted: result.finalizedAuthorizationPackage.persisted
      })
      : result.finalizedAuthorizationPackageErrorCode
        ? Object.freeze({
          scenario: result.finalizedAuthorizationPackageScenario,
          status: "rejected",
          errorCode: result.finalizedAuthorizationPackageErrorCode,
          authorizationPackageFinalized: false,
          proofGenerated: false,
          proofVerifiedLocally: result.actionUnlockProofVerification !== undefined,
          verifiedFactPublished: false,
          onChainVerificationPerformed: false,
          nullifierConsumed: false,
          adapterExecutionAllowed: false,
          contractExecutionAllowed: false,
          transactionSubmitted: false,
          executableByApplications: false,
          witnessMaterialExposed: false,
          persisted: false
        })
        : undefined,
    verifiedFactPublicationRequestDraft: result.verifiedFactPublicationRequestDraft
      ? Object.freeze({
        scenario: result.authorizationExecutionReadinessScenario,
        status: result.verifiedFactPublicationRequestDraft.status,
        outcome: result.verifiedFactPublicationRequestDraft.outcome,
        draftId:
          result.verifiedFactPublicationRequestDraft.verifiedFactPublicationRequestDraftId,
        finalizedAuthorizationPackageId:
          result.verifiedFactPublicationRequestDraft.binding.finalizedAuthorizationPackageId,
        proofInputHash: result.verifiedFactPublicationRequestDraft.binding.proofInputHash,
        proofDigest: result.verifiedFactPublicationRequestDraft.binding.proofDigest,
        factHigh: result.verifiedFactPublicationRequestDraft.binding.factHigh,
        factLow: result.verifiedFactPublicationRequestDraft.binding.factLow,
        publicNullifier: result.verifiedFactPublicationRequestDraft.binding.nullifier,
        chainId: result.verifiedFactPublicationRequestDraft.target.chainProfile.chainId,
        network: result.verifiedFactPublicationRequestDraft.target.chainProfile.network,
        verifierReference:
          result.verifiedFactPublicationRequestDraft.target.verifier.verifierReference,
        registryReference:
          result.verifiedFactPublicationRequestDraft.target.registry.registryReference,
        consumerReference:
          result.verifiedFactPublicationRequestDraft.target.consumer.consumerReference,
        smartAccountReference:
          result.verifiedFactPublicationRequestDraft.target.smartAccount.smartAccountReference,
        proofBytesIncluded:
          result.verifiedFactPublicationRequestDraft.payloadDraft.proofBytesIncluded,
        executableCalldataIncluded:
          result.verifiedFactPublicationRequestDraft.payloadDraft.executableCalldataIncluded,
        factPublished: result.verifiedFactPublicationRequestDraft.factPublished,
        nullifierConsumed: result.verifiedFactPublicationRequestDraft.nullifierConsumed,
        contractCalled: result.verifiedFactPublicationRequestDraft.contractCalled,
        userOperationCreated:
          result.verifiedFactPublicationRequestDraft.userOperationCreated,
        transactionSigned: result.verifiedFactPublicationRequestDraft.transactionSigned,
        transactionSubmitted: result.verifiedFactPublicationRequestDraft.transactionSubmitted,
        adapterExecuted: result.verifiedFactPublicationRequestDraft.adapterExecuted,
        chainStateMutated: result.verifiedFactPublicationRequestDraft.chainStateMutated,
        persisted: result.verifiedFactPublicationRequestDraft.persisted
      })
      : result.verifiedFactPublicationRequestDraftErrorCode
        ? Object.freeze({
          scenario: result.authorizationExecutionReadinessScenario,
          status: "rejected",
          errorCode: result.verifiedFactPublicationRequestDraftErrorCode,
          factPublished: false,
          nullifierConsumed: false,
          contractCalled: false,
          userOperationCreated: false,
          transactionSigned: false,
          transactionSubmitted: false,
          adapterExecuted: false,
          chainStateMutated: false,
          persisted: false
        })
        : undefined,
    authorizationExecutionReadiness: result.authorizationExecutionReadiness
      ? Object.freeze({
        scenario: result.authorizationExecutionReadinessScenario,
        status: result.authorizationExecutionReadiness.status,
        outcome: result.authorizationExecutionReadiness.outcome,
        readinessResultId:
          result.authorizationExecutionReadiness.authorizationExecutionReadinessResultId,
        publicationRequestDraftId:
          result.authorizationExecutionReadiness.binding.verifiedFactPublicationRequestDraftId,
        finalizedAuthorizationPackageId:
          result.authorizationExecutionReadiness.binding.finalizedAuthorizationPackageId,
        proofInputHash: result.authorizationExecutionReadiness.binding.proofInputHash,
        proofDigest: result.authorizationExecutionReadiness.binding.proofDigest,
        factHigh: result.authorizationExecutionReadiness.binding.factHigh,
        factLow: result.authorizationExecutionReadiness.binding.factLow,
        publicNullifier: result.authorizationExecutionReadiness.binding.nullifier,
        chainId: result.authorizationExecutionReadiness.binding.chainId,
        network: result.authorizationExecutionReadiness.binding.network,
        verifierReference: result.authorizationExecutionReadiness.binding.verifierReference,
        registryReference: result.authorizationExecutionReadiness.binding.registryReference,
        consumerReference: result.authorizationExecutionReadiness.binding.consumerReference,
        smartAccountReference:
          result.authorizationExecutionReadiness.binding.smartAccountReference,
        factState: result.authorizationExecutionReadiness.summary.factState,
        nullifierState: result.authorizationExecutionReadiness.summary.nullifierState,
        factBlockReference:
          result.authorizationExecutionReadiness.summary.factBlockReference,
        nullifierBlockReference:
          result.authorizationExecutionReadiness.summary.nullifierBlockReference,
        freshnessWindowMs:
          result.authorizationExecutionReadiness.summary.freshnessWindowMs,
        raceConditionWarning:
          result.authorizationExecutionReadiness.summary.raceConditionWarning,
        revalidationRequiredBeforeTransaction:
          result.authorizationExecutionReadiness.summary.revalidationRequiredBeforeTransaction,
        executionPreparationAllowedNow:
          result.authorizationExecutionReadiness.summary.executionPreparationAllowedNow,
        factPublished: result.authorizationExecutionReadiness.factPublished,
        nullifierConsumed: result.authorizationExecutionReadiness.nullifierConsumed,
        contractCalled: result.authorizationExecutionReadiness.contractCalled,
        userOperationCreated: result.authorizationExecutionReadiness.userOperationCreated,
        transactionSigned: result.authorizationExecutionReadiness.transactionSigned,
        transactionSubmitted: result.authorizationExecutionReadiness.transactionSubmitted,
        adapterExecuted: result.authorizationExecutionReadiness.adapterExecuted,
        chainStateMutated: result.authorizationExecutionReadiness.chainStateMutated,
        persisted: result.authorizationExecutionReadiness.persisted
      })
      : result.authorizationExecutionReadinessErrorCode
        ? Object.freeze({
          scenario: result.authorizationExecutionReadinessScenario,
          status: "rejected",
          errorCode: result.authorizationExecutionReadinessErrorCode,
          factPublished: false,
          nullifierConsumed: false,
          contractCalled: false,
          userOperationCreated: false,
          transactionSigned: false,
          transactionSubmitted: false,
          adapterExecuted: false,
          chainStateMutated: false,
          persisted: false
        })
        : undefined,
    limitations: result.limitations,
    nonAuthority: Object.freeze({
      productionAuthenticationPerformed: result.productionAuthenticationPerformed,
      vaultUnlocked: result.vaultUnlocked,
      activeCapabilityCreated: result.activeCapabilityCreated,
      authorizationCreated: result.authorizationCreated,
      proofExecuted: result.proofExecuted,
      adapterExecuted: result.adapterExecuted,
      persisted: result.persisted
    })
  });
}

export function formatAlpha0LifecycleDiagnosticResult(
  result: Alpha0LifecycleDiagnosticResult
): string {
  if (result.sequence === "states") {
    return [
      formatUserSessionLifecycleStates(),
      "",
      "This lifecycle mode is diagnostic only. It does not authenticate users or unlock vaults."
    ].join("\n");
  }

  const lines = [
    `PhilCore Alpha 0 lifecycle diagnostic: ${result.sequence}`,
    `Final status: ${result.finalStatus}`,
    `Final lifecycle state: ${result.finalState ?? "none"}`,
    "",
    "Transitions:"
  ];
  for (const transition of result.transitions) {
    lines.push(
      `- ${transition.previousState} + ${transition.event} -> ${transition.nextState}: ${transition.status} (${transition.reason})`
    );
    if (transition.futureRequirements.length > 0) {
      lines.push(`  evidence references verified: ${transition.evidenceReferencesVerified}`);
    }
  }
  lines.push("");
  if (result.fixtureAuthenticationVerification) {
    lines.push("Fixture authentication:");
    lines.push(`- outcome: ${result.fixtureAuthenticationVerification.outcome}`);
    lines.push("- fixture-only authentication: yes");
    lines.push("- production authentication: not performed");
    lines.push("- Device Vault unlock: not performed");
    lines.push("- authority granted: no");
    lines.push("");
  }
  if (result.productionAuthenticationVerification) {
    lines.push("Production WebAuthn verification:");
    lines.push(`- outcome: ${result.productionAuthenticationVerification.outcome}`);
    lines.push("- production WebAuthn assertion verified from explicit in-memory inputs: yes");
    lines.push("- browser WebAuthn prompt invoked: no");
    lines.push("- credential loaded from Device Vault: no");
    lines.push(`- Device Vault unlock: ${result.deviceVaultUnlockResult ? "handled by separate explicit vault step" : "not performed"}`);
    lines.push(`- session fully unlocked: ${result.verifiedVaultSessionUnlock ? "yes, by controlled vault transition" : "no"}`);
    lines.push("");
  }
  if (result.lifecycleTransitionCandidate) {
    lines.push("Lifecycle candidate:");
    lines.push(`- outcome: ${result.lifecycleTransitionCandidate.outcome}`);
    lines.push(`- target state: ${result.lifecycleTransitionCandidate.targetState}`);
    lines.push("- authority granted: no");
    lines.push("");
  }
  if (result.deviceVaultUnlockResult) {
    lines.push("Device Vault unlock:");
    lines.push(`- outcome: ${result.deviceVaultUnlockResult.outcome}`);
    lines.push("- Device Vault unlock performed against explicit in-memory test envelope");
    lines.push(`- protected state available: ${result.deviceVaultUnlockResult.protectedStateAvailable ? "yes" : "no"}`);
    lines.push(`- opaque vault handle: ${result.deviceVaultUnlockResult.unlockedVaultHandle?.handleId ?? "none"}`);
    lines.push("- phil_secret exposed: no");
    lines.push("- raw vault key exposed: no");
    lines.push("- decrypted registry plaintext returned: no");
    lines.push("- application credentials loaded: no");
    lines.push("- active capability created: no");
    lines.push("- session key created: no");
    lines.push("- authorization created: no");
    lines.push("- persistence: not performed");
    lines.push("");
  }
  if (result.verifiedVaultSessionUnlock) {
    lines.push("Verified vault session transition:");
    lines.push(`- next state: ${result.verifiedVaultSessionUnlock.transitionResult.nextState}`);
    lines.push("- no active capabilities/no authorization/no persistence");
    lines.push("");
  }
  if (result.protectedStateView) {
    lines.push("Protected state view:");
    lines.push(`- view: ${result.protectedStateView.viewType}`);
    lines.push(`- outcome: ${result.protectedStateView.outcome}`);
    lines.push("- identity summary returned: yes");
    lines.push("- secrets remain protected: yes");
    lines.push("- credentials loaded into applications: no");
    lines.push("- raw vault contents exposed: no");
    lines.push("- applications still have no authority");
    lines.push(`- contains secrets: ${result.protectedStateView.containsSecrets ? "yes" : "no"}`);
    lines.push(`- contains credentials: ${result.protectedStateView.containsCredentials ? "yes" : "no"}`);
    lines.push(`- contains authorization: ${result.protectedStateView.containsAuthorization ? "yes" : "no"}`);
    lines.push("");
  }
  if (result.publicCredentialDirectory) {
    lines.push("Public credential directory:");
    lines.push(`- operation: ${result.publicCredentialDirectory.operation}`);
    lines.push(`- credential count: ${result.publicCredentialDirectory.summary.returnedCredentialCount}`);
    lines.push(`- provider kinds: ${result.publicCredentialDirectory.summary.providerKinds.join(", ") || "none"}`);
    lines.push(`- lifecycle statuses: ${JSON.stringify(result.publicCredentialDirectory.summary.lifecycleStatuses)}`);
    lines.push(`- recovery-only count: ${result.publicCredentialDirectory.summary.recoveryOnlyCount}`);
    lines.push(`- ordinary-use eligible count: ${result.publicCredentialDirectory.summary.ordinaryUseEligibleCount}`);
    lines.push("- sanitized descriptor references:");
    for (const descriptor of result.publicCredentialDirectory.descriptors) {
      lines.push(`  - ${descriptor.descriptorId} (${descriptor.providerKind}, ${descriptor.publicLifecycleStatus})`);
    }
    lines.push("- no private credential material loaded");
    lines.push("- no assertion executed");
    lines.push("- no Trust Decision made");
    lines.push("- no capability or authorization created");
    lines.push("- no persistence");
    lines.push("");
  }
  if (result.selectedCredentialPublicMaterial) {
    lines.push("Selected credential public material:");
    lines.push(`- selected credential reference: ${result.selectedCredentialPublicMaterial.summary.credentialSafeReference}`);
    lines.push(`- provider kind: ${result.selectedCredentialPublicMaterial.summary.providerKind}`);
    lines.push(`- algorithm: ${result.selectedCredentialPublicMaterial.summary.publicKeyAlgorithm}`);
    lines.push(`- lifecycle status: ${result.selectedCredentialPublicMaterial.summary.lifecycleStatus}`);
    lines.push(`- supported verification method: ${result.selectedCredentialPublicMaterial.summary.supportedVerificationMethods.join(", ")}`);
    lines.push(`- verification handle created: ${result.selectedCredentialPublicMaterial.summary.verificationHandleCreated ? "yes" : "no"}`);
    lines.push(`- verification handle: ${result.selectedCredentialPublicMaterial.verificationHandle.handleId}`);
    lines.push(`- public key fingerprint: ${result.selectedCredentialPublicMaterial.summary.publicKeyFingerprint}`);
    lines.push("- raw public key bytes: not printed");
    lines.push("- private credential material: no");
    lines.push("- authentication performed: no");
    lines.push("- WebAuthn assertion invoked: no");
    lines.push("- Trust Decision made: no");
    lines.push("- authority granted: no");
    lines.push("- persistence: not performed");
    lines.push("");
  }
  if (result.trustManagerVerificationInput) {
    lines.push("Trust Manager verification input:");
    lines.push(`- credential safe reference: ${result.trustManagerVerificationInput.verificationInput.credentialSafeReference}`);
    lines.push(`- provider kind: ${result.trustManagerVerificationInput.verificationInput.providerKind}`);
    lines.push(`- algorithm: ${result.trustManagerVerificationInput.verificationInput.publicKeyAlgorithm}`);
    lines.push(`- authentication purpose: ${result.trustManagerVerificationInput.verificationInput.authenticationPurpose}`);
    lines.push(`- assurance requirement: ${result.trustManagerVerificationInput.verificationInput.assuranceRequirement.requiredAssurance.join(", ")}`);
    lines.push("- challenge correlation: matched");
    lines.push("- lifecycle eligibility: eligible for input construction only");
    lines.push(`- input expiry: ${result.trustManagerVerificationInput.expiresAt}`);
    lines.push("- authentication performed: no");
    lines.push("- WebAuthn assertion invoked: no");
    lines.push("- Trust Decision made: no");
    lines.push("- vault access granted to Trust Manager: no");
    lines.push("- credential enumeration granted to Trust Manager: no");
    lines.push("- authority granted: no");
    lines.push("- persistence: not performed");
    lines.push("");
  }
  if (result.trustManagerProductionVerification) {
    lines.push("Trust Manager production assertion verification:");
    lines.push(`- selected credential reference: ${result.trustManagerProductionVerification.correlation.credentialSafeReference}`);
    lines.push(`- provider kind: ${result.trustManagerProductionVerification.correlation.providerKind}`);
    lines.push(`- algorithm: ${result.trustManagerProductionVerification.evidenceSummary.publicKeyAlgorithm}`);
    lines.push(`- challenge verified: ${result.trustManagerProductionVerification.challengeBindingVerified ? "yes" : "no"}`);
    lines.push(`- origin verified: ${result.trustManagerProductionVerification.originVerified ? "yes" : "no"}`);
    lines.push(`- RP ID verified: ${result.trustManagerProductionVerification.rpIdHashVerified ? "yes" : "no"}`);
    lines.push(`- signature verified: ${result.trustManagerProductionVerification.signatureVerified ? "yes" : "no"}`);
    lines.push(`- user presence verified: ${result.trustManagerProductionVerification.evidenceSummary.userPresenceVerified ? "yes" : "no"}`);
    lines.push(`- user verification verified: ${result.trustManagerProductionVerification.evidenceSummary.userVerificationVerified ? "yes" : "no"}`);
    lines.push(`- counter assessment: ${result.trustManagerProductionVerification.counterAssessment.counterStatus}`);
    lines.push(`- production verifier used: ${result.trustManagerProductionVerification.productionVerifierUsed ? "yes" : "no"}`);
    lines.push("- Trust Decision made: no");
    lines.push("- capability grant created: no");
    lines.push("- authorization created: no");
    lines.push("- vault access by Trust Manager: no");
    lines.push("- counter persisted: no");
    lines.push("- persistence: not performed");
    lines.push("");
  }
  if (result.boundedTrustDecisionCandidate) {
    lines.push("Bounded Trust Decision candidate:");
    lines.push(`- candidate outcome: ${result.boundedTrustDecisionCandidate.outcome}`);
    lines.push(`- credential lifecycle status: ${result.boundedTrustDecisionCandidate.lifecycleAssessment.credentialLifecycleStatus}`);
    lines.push(`- assurance sufficient: ${result.boundedTrustDecisionCandidate.assurance.sufficient ? "yes" : "no"}`);
    lines.push(`- counter assessment: ${result.boundedTrustDecisionCandidate.evidence.counterStatus}`);
    lines.push(`- counter persistence required: ${result.boundedTrustDecisionCandidate.requiresCounterPersistence ? "yes" : "no"}`);
    lines.push(`- World ID enrollment required: ${result.boundedTrustDecisionCandidate.requiresWorldIdEnrollment ? "yes" : "no"}`);
    lines.push("- authoritative Trust Decision created: no");
    lines.push("- capability grant created: no");
    lines.push("- authorization created: no");
    lines.push("- vault access granted: no");
    lines.push("- persistence: not performed");
    lines.push("");
  }
  if (result.credentialCounterPersistenceReceipt) {
    lines.push("Credential counter persistence:");
    lines.push(`- credential safe reference: ${result.credentialCounterPersistenceReceipt.correlation.credentialSafeReference}`);
    lines.push(`- previous counter: ${result.credentialCounterPersistenceReceipt.mutationSummary.previousStoredCounter}`);
    lines.push(`- verified returned counter: ${result.credentialCounterPersistenceReceipt.counterState.verifiedReturnedCounter}`);
    lines.push(`- persisted counter: ${result.credentialCounterPersistenceReceipt.mutationSummary.persistedCounter}`);
    lines.push(`- registry verification status: ${result.credentialCounterPersistenceReceipt.registryIntegrityVerified && result.credentialCounterPersistenceReceipt.writeVerified ? "verified" : "not verified"}`);
    lines.push(`- only selected counter field changed: ${result.credentialCounterPersistenceReceipt.mutationSummary.onlyCounterFieldChanged ? "yes" : "no"}`);
    lines.push(`- candidate counter requirement resolved: ${result.trustDecisionCandidateCounterResolution?.counterRequirementSatisfied ? "yes" : "no"}`);
    lines.push("- active Trust Decision created: no");
    lines.push("- capability grant created: no");
    lines.push("- authorization created: no");
    lines.push("- raw credential or vault contents exposed: no");
    lines.push("");
  }
  if (result.authoritativeTrustDecision) {
    lines.push("Authoritative bounded Trust Decision:");
    lines.push(`- decision outcome: ${result.authoritativeTrustDecision.outcome}`);
    lines.push("- assertion verified: yes");
    lines.push(`- counter committed: ${result.authoritativeTrustDecision.credentialCounterCommitted ? "yes" : "accepted zero-counter semantics"}`);
    lines.push("- credential lifecycle eligible: yes");
    lines.push(`- session binding: ${result.authoritativeTrustDecision.scope.sessionId}`);
    lines.push(`- purpose binding: ${result.authoritativeTrustDecision.scope.authenticationPurpose}`);
    lines.push(`- assurance satisfied: ${result.authoritativeTrustDecision.assuranceSatisfied ? "yes" : "no"}`);
    lines.push(`- decision expiry: ${result.authoritativeTrustDecision.validity.expiresAt}`);
    lines.push("- Trust Decision created: yes, Trust Manager authority only");
    lines.push("- capability grant created: no");
    lines.push("- policy approved: no");
    lines.push("- user approval collected: no");
    lines.push("- Authorization Package created: no");
    lines.push("- session key created: no");
    lines.push("- execution allowed: no");
    lines.push("- raw credential or vault contents exposed: no");
    lines.push("");
  }
  if (result.authoritativePolicyDecision) {
    lines.push("Authoritative Security Policy Decision:");
    lines.push(`- policy outcome: ${result.authoritativePolicyDecision.outcome}`);
    lines.push("- Trust Decision accepted: yes");
    lines.push("- policy rules evaluated: yes");
    lines.push(`- capability: ${result.authoritativePolicyDecision.scope.capabilityName}`);
    lines.push(`- action: ${result.authoritativePolicyDecision.scope.actionType}`);
    lines.push(`- target: ${result.authoritativePolicyDecision.scope.targetReference ?? "not specified"}`);
    lines.push(`- effective duration: ${result.authoritativePolicyDecision.effectiveDurationSeconds ?? "not restricted"}`);
    lines.push(`- effective value limit: ${result.authoritativePolicyDecision.effectiveValueLimit ?? "not restricted"}`);
    lines.push(`- effective target restrictions: ${result.authoritativePolicyDecision.effectiveTargetRestrictions.length > 0 ? result.authoritativePolicyDecision.effectiveTargetRestrictions.join(", ") : "not restricted"}`);
    lines.push(`- user approval required: ${result.authoritativePolicyDecision.requiresUserApproval ? "yes" : "no"}`);
    lines.push(`- capability activation review allowed: ${result.authoritativePolicyDecision.eligibleForCapabilityActivationReview ? "yes" : "no"}`);
    lines.push("- capability grant created: no");
    lines.push("- user approval collected: no");
    lines.push("- Authorization Package created: no");
    lines.push("- session key created: no");
    lines.push("- execution allowed: no");
    lines.push("- proof execution: not performed");
    lines.push("- adapter execution: not performed");
    lines.push("- raw credential or vault contents exposed: no");
    lines.push("");
  }
  if (result.platformUserApprovalDecision || result.platformUserApprovalDecisionOutcome) {
    lines.push("Platform User Approval Decision:");
    lines.push(`- approval outcome: ${result.platformUserApprovalDecision?.outcome ?? result.platformUserApprovalDecisionOutcome}`);
    lines.push(`- Trust Decision accepted: ${result.platformUserApprovalDecision?.trustDecisionAccepted ? "yes" : result.platformUserApprovalDecision ? "no" : "not accepted"}`);
    lines.push(`- Policy Decision requires approval: ${result.authoritativePolicyDecision?.requiresUserApproval ? "yes" : "not confirmed"}`);
    lines.push(`- presentation digest matched: ${result.platformUserApprovalDecision?.presentationDigestMatched ? "yes" : "no"}`);
    lines.push(`- approval surface: ${result.platformUserApprovalDecision?.evidence.approvalSurface ?? result.platformUserApprovalArtifactSurface ?? "none"}`);
    lines.push(`- user outcome: ${result.platformUserApprovalDecision?.outcome ?? result.platformUserApprovalArtifactOutcome ?? "rejected"}`);
    lines.push(`- approval validity: ${result.platformUserApprovalDecision?.validity.expiresAt ?? "not valid"}`);
    lines.push("- explicit in-memory local platform artifact: yes");
    lines.push("- native OS consent claimed: no");
    lines.push("- capability grant created: no");
    lines.push("- Authorization Package created: no");
    lines.push("- session key created: no");
    lines.push("- execution allowed: no");
    lines.push("- transaction submitted: no");
    lines.push("- proof execution: not performed");
    lines.push("- adapter execution: not performed");
    lines.push("- raw biometric/platform/vault data exposed: no");
    lines.push("");
  }
  if (result.authoritativeCapabilityGrant || result.authoritativeCapabilityGrantErrorCode) {
    lines.push("Authoritative scoped Capability Grant:");
    lines.push(`- activation status: ${result.authoritativeCapabilityGrant?.status ?? "rejected"}`);
    lines.push(`- activation error: ${result.authoritativeCapabilityGrantErrorCode ?? "none"}`);
    lines.push(`- capability: ${result.authoritativeCapabilityGrant?.scope.capabilityName ?? "none"}`);
    lines.push(`- session binding: ${result.authoritativeCapabilityGrant?.binding.sessionId ?? "none"}`);
    lines.push(`- application binding: ${result.authoritativeCapabilityGrant?.binding.applicationId ?? "none"}`);
    lines.push(`- effective duration: ${result.authoritativeCapabilityGrant?.scope.effectiveDurationSeconds ?? "none"}`);
    lines.push(`- allowed targets: ${result.authoritativeCapabilityGrant?.scope.allowedTargets.join(", ") ?? "none"}`);
    lines.push(`- value limit: ${result.authoritativeCapabilityGrant?.scope.valueLimit ?? "none"}`);
    lines.push(`- active session capability created: ${result.userSessionCapabilityMutation?.activeCapabilityCreated ? "yes" : "no"}`);
    lines.push(`- session mutation status: ${result.userSessionCapabilityMutation?.status ?? "none"}`);
    lines.push("- action authorized: no");
    lines.push("- Authorization Package created: no");
    lines.push("- session key created: no");
    lines.push("- execution allowed: no");
    lines.push("- proof execution: not performed");
    lines.push("- adapter execution: not performed");
    lines.push("- transaction submitted: no");
    lines.push("- Device Vault access: no");
    lines.push("- World ID verification: not performed");
    lines.push("- durable capability persistence: not performed");
    lines.push("");
  }
  if (result.authorizationDecisionCandidate || result.authorizationDecisionCandidateErrorCode) {
    lines.push("Authorization Decision Candidate:");
    lines.push(`- scenario: ${result.authorizationCandidateScenario ?? "none"}`);
    lines.push(`- candidate status: ${result.authorizationDecisionCandidate?.status ?? "rejected"}`);
    lines.push(`- candidate error: ${result.authorizationDecisionCandidateErrorCode ?? "none"}`);
    lines.push(`- active capability accepted: ${result.authorizationDecisionCandidate?.activeCapabilityGrantAccepted ? "yes" : "no"}`);
    lines.push(`- required capability: ${result.authorizationDecisionCandidate?.actionSummary.requiredCapability ?? "none"}`);
    lines.push(`- action type: ${result.authorizationDecisionCandidate?.actionSummary.actionType ?? "none"}`);
    lines.push(`- target: ${result.authorizationDecisionCandidate?.actionSummary.target ?? "none"}`);
    lines.push(`- method: ${result.authorizationDecisionCandidate?.actionSummary.method ?? "none"}`);
    lines.push(`- value: ${result.authorizationDecisionCandidate?.actionSummary.value ?? "none"}`);
    lines.push(`- action digest preview: ${result.authorizationDecisionCandidate?.evidence.actionDigestPreview.digestPreview ?? "none"}`);
    lines.push(`- proof requirement: ${result.authorizationDecisionCandidate?.proofRequirement ?? "none"}`);
    lines.push("- Authorization Package created: no");
    lines.push("- ACTION_UNLOCK assembled: no");
    lines.push("- proofInputHash created: no");
    lines.push("- action authorized: no");
    lines.push("- signature created: no");
    lines.push("- session key created: no");
    lines.push("- execution allowed: no");
    lines.push("- adapter execution: not performed");
    lines.push("- transaction submitted: no");
    lines.push("- raw credential/vault/proof data exposed: no");
    lines.push("");
  }
  if (result.authorizationPackageDraft || result.authorizationPackageDraftErrorCode) {
    lines.push("Authorization Package Draft:");
    lines.push(`- scenario: ${result.authorizationPackageDraftScenario ?? "none"}`);
    lines.push(`- package draft status: ${result.authorizationPackageDraft?.status ?? "rejected"}`);
    lines.push(`- package draft error: ${result.authorizationPackageDraftErrorCode ?? "none"}`);
    lines.push(`- owner commitment: ${result.authorizationPackageDraft?.actionUnlockPublicInputDraft.publicInputs.ownerCommitment ?? "none"}`);
    lines.push(`- actionHash: ${result.authorizationPackageDraft?.hashSummary.actionHash ?? "none"}`);
    lines.push(`- policyHash: ${result.authorizationPackageDraft?.hashSummary.policyHash ?? "none"}`);
    lines.push(`- public nullifier reference: ${result.authorizationPackageDraft?.nullifierReference.nullifier ?? "none"}`);
    lines.push(`- consumerDataHash: ${result.authorizationPackageDraft?.hashSummary.consumerDataHash ?? "none"}`);
    lines.push(`- expiry: ${result.authorizationPackageDraft?.validity.expiry.toString() ?? "none"}`);
    lines.push(`- proofInputHash: ${result.authorizationPackageDraft?.hashSummary.proofInputHash ?? "none"}`);
    lines.push(`- proof type: ${result.authorizationPackageDraft?.actionUnlockPublicInputDraft.proofType ?? "none"}`);
    lines.push(`- fact shape reference: ${result.authorizationPackageDraft?.actionUnlockPublicInputDraft.factShapeReference ?? "none"}`);
    lines.push(`- proof requirement: ${result.authorizationPackageDraft?.proofRequirement ?? "none"}`);
    lines.push(`- M.1 preview digest is canonical actionHash: ${result.authorizationPackageDraft?.hashSummary.m1PreviewIsCanonicalActionHash ? "yes" : "no"}`);
    lines.push(`- package draft created: ${result.authorizationPackageDraft?.authorizationPackageDraftCreated ? "yes" : "no"}`);
    lines.push("- proof generated: no");
    lines.push("- proof verified: no");
    lines.push("- verified fact available: no");
    lines.push("- authorization executable: no");
    lines.push("- action authorized: no");
    lines.push("- nullifier consumed: no");
    lines.push("- adapter execution allowed: no");
    lines.push("- transaction submitted: no");
    lines.push("- phil_secret/nullifierSeed exposed: no");
    lines.push("");
  }
  if (result.actionUnlockProofGenerationArtifact || result.actionUnlockProofGenerationErrorCode) {
    lines.push("ACTION_UNLOCK proof generation:");
    lines.push(`- scenario: ${result.actionUnlockProofGenerationScenario ?? "none"}`);
    lines.push(`- proof generation status: ${result.actionUnlockProofGenerationArtifact?.status ?? "rejected"}`);
    lines.push(`- proof generation error: ${result.actionUnlockProofGenerationErrorCode ?? "none"}`);
    lines.push(`- proof type: ${result.actionUnlockProofGenerationArtifact?.proofType ?? "none"}`);
    lines.push(`- proofInputHash: ${result.actionUnlockProofGenerationArtifact?.proofInputHash ?? "none"}`);
    lines.push(`- prover used: ${result.actionUnlockProofGenerationArtifact?.summary.proverUsed ?? "none"}`);
    lines.push(`- prover invocation: ${result.actionUnlockProofGenerationArtifact?.summary.proverInvocation ?? "none"}`);
    lines.push(`- proof generated: ${result.actionUnlockProofGenerationArtifact?.proofGenerated ? "yes" : "no"}`);
    lines.push(`- proof byte length: ${result.actionUnlockProofGenerationArtifact?.proofArtifact.proofByteLength ?? "none"}`);
    lines.push(`- proof digest: ${result.actionUnlockProofGenerationArtifact?.proofArtifact.proofDigest ?? "none"}`);
    lines.push(`- proof blob included in shell output: ${result.actionUnlockProofGenerationArtifact?.proofArtifact.proofBlobIncluded ? "yes" : "no"}`);
    lines.push(`- public inputs matched draft: ${result.actionUnlockProofGenerationArtifact?.summary.publicInputsMatched ? "yes" : "no"}`);
    lines.push(`- proofInputHash matched draft: ${result.actionUnlockProofGenerationArtifact?.summary.proofInputHashMatched ? "yes" : "no"}`);
    lines.push(`- temporary witness file used: ${result.actionUnlockProofGenerationArtifact?.summary.temporaryWitnessFileUsed ? "yes" : "no"}`);
    lines.push(`- temporary witness cleanup: ${result.actionUnlockProofGenerationArtifact?.summary.temporaryWitnessCleanupStatus ?? "none"}`);
    lines.push("- phil_secret/nullifierSeed exposed: no");
    lines.push("- witness material returned: no");
    lines.push("- proof verified by Runtime: no");
    lines.push("- verified fact published: no");
    lines.push("- nullifier consumed: no");
    lines.push("- Authorization Package finalized: no");
    lines.push("- adapter execution allowed: no");
    lines.push("- transaction submitted: no");
    lines.push("- persistence: not performed");
    lines.push("");
  }
  if (result.actionUnlockProofVerification || result.actionUnlockProofVerificationErrorCode) {
    lines.push("ACTION_UNLOCK local proof verification:");
    lines.push(`- scenario: ${result.finalizedAuthorizationPackageScenario ?? "none"}`);
    lines.push(`- verification status: ${result.actionUnlockProofVerification?.status ?? "rejected"}`);
    lines.push(`- verification error: ${result.actionUnlockProofVerificationErrorCode ?? "none"}`);
    lines.push(`- verifier used: ${result.actionUnlockProofVerification?.summary.verifierUsed ?? "none"}`);
    lines.push(`- proofInputHash: ${result.actionUnlockProofVerification?.proofInputHash ?? "none"}`);
    lines.push(`- proof digest: ${result.actionUnlockProofVerification?.verifiedProofReference.proofDigest ?? "none"}`);
    lines.push(`- fact shape: ${result.actionUnlockProofVerification?.factShapePreview.factShapeReference ?? "none"}`);
    lines.push(`- fact high: ${result.actionUnlockProofVerification?.factShapePreview.factHigh ?? "none"}`);
    lines.push(`- fact low: ${result.actionUnlockProofVerification?.factShapePreview.factLow ?? "none"}`);
    lines.push(`- proof verified locally: ${result.actionUnlockProofVerification?.proofVerifiedLocally ? "yes" : "no"}`);
    lines.push("- on-chain verification: not performed");
    lines.push("- verified fact published: no");
    lines.push("- nullifier consumed: no");
    lines.push("- adapter execution allowed: no");
    lines.push("- transaction submitted: no");
    lines.push("- proof bytes exposed to audit: no");
    lines.push("- witness material exposed: no");
    lines.push("- persistence: not performed");
    lines.push("");
  }
  if (result.finalizedAuthorizationPackage || result.finalizedAuthorizationPackageErrorCode) {
    lines.push("Finalized non-executing Authorization Package:");
    lines.push(`- scenario: ${result.finalizedAuthorizationPackageScenario ?? "none"}`);
    lines.push(`- finalization status: ${result.finalizedAuthorizationPackage?.status ?? "rejected"}`);
    lines.push(`- finalization error: ${result.finalizedAuthorizationPackageErrorCode ?? "none"}`);
    lines.push(`- package ID: ${result.finalizedAuthorizationPackage?.finalizedAuthorizationPackageId ?? "none"}`);
    lines.push(`- proofInputHash: ${result.finalizedAuthorizationPackage?.actionUnlockAuthorization.proofInputHash ?? "none"}`);
    lines.push(`- proof digest: ${result.finalizedAuthorizationPackage?.proofArtifact.proofDigest ?? "none"}`);
    lines.push(`- proof blob included: ${result.finalizedAuthorizationPackage?.proofArtifact.proofBlobIncluded ? "yes" : "no"}`);
    lines.push(`- fact shape: ${result.finalizedAuthorizationPackage?.factShapePreview.factShapeReference ?? "none"}`);
    lines.push(`- fact high: ${result.finalizedAuthorizationPackage?.factShapePreview.factHigh ?? "none"}`);
    lines.push(`- fact low: ${result.finalizedAuthorizationPackage?.factShapePreview.factLow ?? "none"}`);
    lines.push("- verified fact published: no");
    lines.push("- on-chain verifier called: no");
    lines.push("- nullifier consumed: no");
    lines.push("- executable by applications: no");
    lines.push("- adapter execution allowed: no");
    lines.push("- contract execution allowed: no");
    lines.push("- transaction submitted: no");
    lines.push("- witness material exposed: no");
    lines.push("- persistence: not performed");
    lines.push("");
  }
  if (
    result.verifiedFactPublicationRequestDraft
    || result.verifiedFactPublicationRequestDraftErrorCode
  ) {
    lines.push("Verified-fact publication request draft:");
    lines.push(`- scenario: ${result.authorizationExecutionReadinessScenario ?? "none"}`);
    lines.push(`- publication draft status: ${result.verifiedFactPublicationRequestDraft?.status ?? "rejected"}`);
    lines.push(`- publication draft error: ${result.verifiedFactPublicationRequestDraftErrorCode ?? "none"}`);
    lines.push(`- finalized package ID: ${result.verifiedFactPublicationRequestDraft?.binding.finalizedAuthorizationPackageId ?? "none"}`);
    lines.push(`- proofInputHash: ${result.verifiedFactPublicationRequestDraft?.binding.proofInputHash ?? "none"}`);
    lines.push(`- proof digest: ${result.verifiedFactPublicationRequestDraft?.binding.proofDigest ?? "none"}`);
    lines.push(`- fact high: ${result.verifiedFactPublicationRequestDraft?.binding.factHigh ?? "none"}`);
    lines.push(`- fact low: ${result.verifiedFactPublicationRequestDraft?.binding.factLow ?? "none"}`);
    lines.push(`- public nullifier: ${result.verifiedFactPublicationRequestDraft?.binding.nullifier ?? "none"}`);
    lines.push(`- target chain/profile: ${result.verifiedFactPublicationRequestDraft ? `${result.verifiedFactPublicationRequestDraft.target.chainProfile.network}/${result.verifiedFactPublicationRequestDraft.target.chainProfile.profileId}` : "none"}`);
    lines.push(`- verifier reference: ${result.verifiedFactPublicationRequestDraft?.target.verifier.verifierReference ?? "none"}`);
    lines.push(`- fact registry reference: ${result.verifiedFactPublicationRequestDraft?.target.registry.registryReference ?? "none"}`);
    lines.push(`- consumer reference: ${result.verifiedFactPublicationRequestDraft?.target.consumer.consumerReference ?? "none"}`);
    lines.push("- verified fact published: no");
    lines.push("- nullifier consumed: no");
    lines.push("- contract called: no");
    lines.push("- UserOperation created: no");
    lines.push("- transaction signed/submitted: no");
    lines.push("- adapter executed: no");
    lines.push("- chain state mutated: no");
    lines.push("");
  }
  if (
    result.authorizationExecutionReadiness
    || result.authorizationExecutionReadinessErrorCode
  ) {
    lines.push("Authorization execution readiness:");
    lines.push(`- scenario: ${result.authorizationExecutionReadinessScenario ?? "none"}`);
    lines.push(`- readiness status: ${result.authorizationExecutionReadiness?.status ?? "rejected"}`);
    lines.push(`- readiness error: ${result.authorizationExecutionReadinessErrorCode ?? "none"}`);
    lines.push(`- readiness outcome: ${result.authorizationExecutionReadiness?.outcome ?? "blocked"}`);
    lines.push(`- fact state: ${result.authorizationExecutionReadiness?.summary.factState ?? "none"}`);
    lines.push(`- nullifier state: ${result.authorizationExecutionReadiness?.summary.nullifierState ?? "none"}`);
    lines.push(`- freshness window: ${result.authorizationExecutionReadiness?.summary.freshnessWindowMs ?? "none"} ms`);
    lines.push(`- race warning: ${result.authorizationExecutionReadiness?.summary.raceConditionWarning ?? "readiness_not_created"}`);
    lines.push(`- revalidation before transaction: ${result.authorizationExecutionReadiness?.summary.revalidationRequiredBeforeTransaction ? "required" : "not available"}`);
    lines.push("- fact not published by this diagnostic");
    lines.push("- nullifier not consumed by this diagnostic");
    lines.push("- contract not called");
    lines.push("- UserOperation not created");
    lines.push("- transaction not signed or submitted");
    lines.push("- adapter not executed");
    lines.push("- chain state not mutated");
    lines.push("");
  }
  lines.push("");
  lines.push("Non-authority summary:");
  lines.push(`- production authentication: ${result.productionAuthenticationPerformed ? "WebAuthn verification performed from explicit inputs" : "not performed"}`);
  lines.push(`- production WebAuthn verification: ${result.productionAuthenticationPerformed ? "performed from explicit inputs" : "not performed"}`);
  lines.push("- browser WebAuthn prompt: not invoked");
  lines.push("- credential loaded from Device Vault: no");
  lines.push(`- vault unlock: ${result.vaultUnlocked ? "performed against explicit in-memory test envelope" : "not performed"}`);
  lines.push(`- full unlock: ${result.finalState === "unlocked" ? "controlled lifecycle state reached" : "not performed"}`);
  lines.push(`- protected state view: ${result.protectedStateView ? "explicit non-secret summary only" : "not requested"}`);
  lines.push(`- public credential directory: ${result.publicCredentialDirectory ? "allowlisted public descriptors only" : "not requested"}`);
  lines.push(`- selected credential public material: ${result.selectedCredentialPublicMaterial ? "one allowlisted verifier-ready public profile only" : "not requested"}`);
  lines.push(`- Trust Manager verification input: ${result.trustManagerVerificationInput ? "bounded input only, no Trust Decision" : "not requested"}`);
  lines.push(`- Trust Manager production verification: ${result.trustManagerProductionVerification ? "bounded assertion evidence only, no Trust Decision" : "not requested"}`);
  lines.push(`- bounded Trust Decision candidate: ${result.boundedTrustDecisionCandidate ? "candidate only, no authority" : "not requested"}`);
  lines.push(`- credential counter persistence: ${result.credentialCounterPersistenceReceipt ? "selected counter field only, no authority" : "not requested"}`);
  lines.push(`- authoritative Trust Decision: ${result.authoritativeTrustDecision ? "Trust Manager decision only, no application authority" : "not requested"}`);
  lines.push(`- authoritative Policy Decision: ${result.authoritativePolicyDecision ? "Security Policy decision only, no application authority" : "not requested"}`);
  lines.push(`- platform user approval decision: ${result.platformUserApprovalDecision ? "User Approval decision accepted as one gate" : result.platformUserApprovalDecisionOutcome ? "rejected diagnostic only" : "not requested"}`);
  lines.push(`- active capability: ${result.activeCapabilityCreated ? "created, scoped to this session only" : "not created"}`);
  lines.push(`- authorization candidate: ${result.authorizationDecisionCandidate ? "created, package construction still required" : result.authorizationDecisionCandidateErrorCode ? "rejected diagnostic only" : "not requested"}`);
  lines.push(`- authorization package draft: ${result.authorizationPackageDraft ? "created, proof generation still required" : result.authorizationPackageDraftErrorCode ? "rejected diagnostic only" : "not requested"}`);
  lines.push(`- ACTION_UNLOCK proof generation: ${result.actionUnlockProofGenerationArtifact ? "proof artifact generated, not verified or executed" : result.actionUnlockProofGenerationErrorCode ? "rejected diagnostic only" : "not requested"}`);
  lines.push(`- ACTION_UNLOCK local proof verification: ${result.actionUnlockProofVerification ? "verified locally with existing Rust verifier only" : result.actionUnlockProofVerificationErrorCode ? "rejected diagnostic only" : "not requested"}`);
  lines.push(`- finalized Authorization Package: ${result.finalizedAuthorizationPackage ? "created as non-executing package only" : result.finalizedAuthorizationPackageErrorCode ? "rejected diagnostic only" : "not requested"}`);
  lines.push(`- verified-fact publication request: ${result.verifiedFactPublicationRequestDraft ? "draft created only, no publication" : result.verifiedFactPublicationRequestDraftErrorCode ? "rejected diagnostic only" : "not requested"}`);
  lines.push(`- authorization execution readiness: ${result.authorizationExecutionReadiness ? "read-only snapshot only, no execution authority" : result.authorizationExecutionReadinessErrorCode ? "blocked diagnostic only" : "not requested"}`);
  lines.push("- session key: not created");
  lines.push("- authorization: not created");
  lines.push("- proof execution: not performed");
  lines.push("- adapter execution: not performed");
  lines.push(`- persistence: ${result.credentialCounterPersistenceReceipt ? "selected credential counter only" : "not performed"}`);
  lines.push("");
  lines.push("Limitations:");
  for (const limitation of result.limitations) {
    lines.push(`- ${limitation}`);
  }
  return lines.join("\n");
}

export function sanitizeAlpha0DemoResult(result: Alpha0DemoResult): Readonly<Record<string, unknown>> {
  return Object.freeze({
    status: result.status,
    scenario: result.scenario,
    stages: result.stages.map((stage) => Object.freeze({
      stage: stage.stage,
      status: stage.status,
      outcome: stage.outcome,
      artifactId: stage.artifactId,
      summary: stage.summary,
      producedAuditDraft: STAGES_THAT_EMIT_AUDIT_DRAFTS.has(stage.stage)
    })),
    artifacts: result.artifacts,
    finalCapabilityActivationCandidateStatus: result.finalCapabilityActivationCandidateStatus,
    auditDraftCount: result.auditDraftCount,
    auditSummary: result.auditSummary,
    limitations: result.limitations,
    worldIdRequiredForChosenContext: result.worldIdRequiredForChosenContext,
    failure: result.failure,
    nonAuthority: Object.freeze({
      fixtureOnly: result.fixtureOnly,
      productionAuthenticationPerformed: result.productionAuthenticationPerformed,
      productionUserConsentCollected: result.productionUserConsentCollected,
      worldIdEnrollmentVerified: result.worldIdEnrollmentVerified,
      activeCapabilityCreated: result.activeCapabilityCreated,
      authorizationCreated: result.authorizationCreated,
      proofExecuted: result.proofExecuted,
      adapterExecuted: result.adapterExecuted,
      persisted: result.persisted
    })
  });
}

export function formatAlpha0DemoResult(result: Alpha0DemoResult): string {
  const finalStage = result.failure?.stage ?? result.stages.at(-1)?.stage ?? "unknown";
  const lines = [
    `PhilCore Alpha 0 shell: ${result.scenario}`,
    `Final status: ${result.status}`,
    `Final stage: ${finalStage}`,
    `Capability activation candidate status: ${result.finalCapabilityActivationCandidateStatus ?? "none"}`,
    `Audit drafts: ${result.auditDraftCount}`,
    `World ID required for chosen context: ${result.worldIdRequiredForChosenContext}`,
    "",
    "Stages:"
  ];

  for (const stage of result.stages) {
    const outcome = stage.outcome ? ` | outcome: ${stage.outcome}` : "";
    const artifact = stage.artifactId ? ` | artifact: ${stage.artifactId}` : "";
    const audit = STAGES_THAT_EMIT_AUDIT_DRAFTS.has(stage.stage) ? "yes" : "no";
    const stopped = result.failure?.stage === stage.stage && stage.status === "failed"
      ? " | stopped: yes"
      : "";
    lines.push(`- ${stage.stage}: ${stage.status}${outcome}${artifact} | audit draft: ${audit}${stopped}`);
    lines.push(`  ${stage.summary}`);
  }

  if (result.failure) {
    lines.push("");
    lines.push("Failure:");
    lines.push(`- stage: ${result.failure.stage}`);
    lines.push(`- outcome: ${result.failure.outcome ?? "none"}`);
    lines.push(`- reason: ${result.failure.reason}`);
  }

  lines.push("");
  lines.push("Sanitized audit summary:");
  if (result.auditSummary.length === 0) {
    lines.push("- none");
  } else {
    for (const audit of result.auditSummary) {
      lines.push(`- ${audit.category}/${audit.outcome}: ${audit.summary}`);
    }
  }

  lines.push("");
  lines.push("Non-authority summary:");
  lines.push("- production authentication: not performed");
  lines.push("- production user consent: not collected");
  lines.push("- active capability: not created");
  lines.push("- authorization: not created");
  lines.push("- World ID verification: not performed");
  lines.push("- proof execution: not performed");
  lines.push("- adapter execution: not performed");
  lines.push("- persistence: not performed");
  lines.push("");
  lines.push("Limitations:");
  for (const limitation of [...new Set(result.limitations)]) {
    lines.push(`- ${limitation}`);
  }

  lines.push("");
  lines.push("This shell is a diagnostic developer tool. A successful ordinary scenario is not production authorization.");
  return lines.join("\n");
}

async function runScenario(
  scenario: Alpha0DemoScenario,
  parsedArgs: Alpha0ShellParsedArgs,
  output: NodeJS.WritableStream
): Promise<number> {
  const result = await runNonAuthoritativeAlpha0Demo({
    scenario,
    strictFailures: parsedArgs.strictFailures
  });

  if (parsedArgs.json) {
    writeLine(output, JSON.stringify(sanitizeAlpha0DemoResult(result), null, 2));
  } else {
    writeLine(output, formatAlpha0DemoResult(result));
  }

  return result.status === "failed" && parsedArgs.strictFailures ? 1 : 0;
}

async function runLifecycleDiagnosticMode(
  parsedArgs: Alpha0ShellParsedArgs,
  output: NodeJS.WritableStream,
  errorOutput: NodeJS.WritableStream
): Promise<number> {
  const sequence = parsedArgs.lifecycleSequence ?? "states";
  if (!isAlpha0LifecycleDiagnosticSequence(sequence)) {
    writeLine(errorOutput, `Unknown lifecycle sequence: ${sequence}`);
    writeLine(errorOutput, "Available lifecycle sequences: states, valid_unlock, fixture_unlock, production_webauthn_partial_unlock, production_webauthn_vault_unlock, production_protected_state_view, production_public_credential_directory, production_selected_credential_public_material, production_trust_manager_verification_input, production_trust_manager_assertion_verification, production_trust_decision_candidate, production_credential_counter_persistence, production_authoritative_trust_decision, production_authoritative_policy_decision, production_platform_user_approval_decision, production_authoritative_capability_activation, production_authorization_decision_candidate, production_authorization_package_draft, production_action_unlock_proof_generation, production_finalized_authorization_package, production_authorization_execution_readiness, invalid_transition, timeout, recovery");
    return 2;
  }
  const approvalOutcome = parsedArgs.approvalOutcome ?? "approve";
  if (!isAlpha0PlatformApprovalDiagnosticOutcome(approvalOutcome)) {
    writeLine(errorOutput, `Unknown approval outcome: ${approvalOutcome}`);
    writeLine(errorOutput, "Available approval outcomes: approve, deny, cancel, expired, digest_mismatch");
    return 2;
  }
  const authorizationCandidateScenario =
    parsedArgs.authorizationCandidateScenario ?? "exact";
  if (!isAlpha0AuthorizationCandidateDiagnosticScenario(authorizationCandidateScenario)) {
    writeLine(errorOutput, `Unknown authorization candidate scenario: ${authorizationCandidateScenario}`);
    writeLine(errorOutput, "Available authorization candidate scenarios: exact, capability_mismatch, scope_widening, target_mismatch, value_limit_exceeded, additional_approval_required");
    return 2;
  }
  const authorizationPackageDraftScenario =
    parsedArgs.authorizationPackageDraftScenario ?? "exact";
  if (!isAlpha0AuthorizationPackageDraftDiagnosticScenario(authorizationPackageDraftScenario)) {
    writeLine(errorOutput, `Unknown authorization package draft scenario: ${authorizationPackageDraftScenario}`);
    writeLine(errorOutput, "Available authorization package draft scenarios: exact, mutated_action, invalid_nullifier, expiry_beyond_capability_grant, evidence_chain_mismatch, consumer_data_mismatch");
    return 2;
  }
  const actionUnlockProofGenerationScenario =
    parsedArgs.actionUnlockProofGenerationScenario ?? "exact";
  if (
    !isAlpha0ActionUnlockProofGenerationDiagnosticScenario(actionUnlockProofGenerationScenario)
  ) {
    writeLine(
      errorOutput,
      `Unknown ACTION_UNLOCK proof generation scenario: ${actionUnlockProofGenerationScenario}`
    );
    writeLine(errorOutput, "Available ACTION_UNLOCK proof generation scenarios: exact, witness_binding_mismatch, prover_failure, proof_input_hash_mismatch, timeout, witness_replay");
    return 2;
  }
  const finalizedAuthorizationPackageScenario =
    parsedArgs.finalizedAuthorizationPackageScenario ?? "exact";
  if (
    !isAlpha0FinalizedAuthorizationPackageDiagnosticScenario(
      finalizedAuthorizationPackageScenario
    )
  ) {
    writeLine(
      errorOutput,
      `Unknown finalized Authorization Package scenario: ${finalizedAuthorizationPackageScenario}`
    );
    writeLine(errorOutput, "Available finalized Authorization Package scenarios: exact, invalid_proof, public_input_mismatch, proof_input_hash_mismatch, fact_shape_mismatch, verification_timeout, expired_package");
    return 2;
  }
  const authorizationExecutionReadinessScenario =
    parsedArgs.authorizationExecutionReadinessScenario ?? "exact";
  if (
    !isAlpha0AuthorizationExecutionReadinessDiagnosticScenario(
      authorizationExecutionReadinessScenario
    )
  ) {
    writeLine(
      errorOutput,
      `Unknown authorization execution readiness scenario: ${authorizationExecutionReadinessScenario}`
    );
    writeLine(errorOutput, "Available authorization execution readiness scenarios: exact, fact_already_published, nullifier_already_consumed, fact_state_unknown, nullifier_state_unknown, configuration_mismatch, expired_package");
    return 2;
  }
  const result = await runAlpha0LifecycleDiagnosticAsync(sequence, {
    approvalOutcome,
    authorizationCandidateScenario,
    authorizationPackageDraftScenario,
    actionUnlockProofGenerationScenario,
    finalizedAuthorizationPackageScenario,
    authorizationExecutionReadinessScenario
  });
  if (parsedArgs.json) {
    writeLine(output, JSON.stringify(sanitizeAlpha0LifecycleDiagnosticResult(result), null, 2));
  } else {
    writeLine(output, formatAlpha0LifecycleDiagnosticResult(result));
  }
  return result.finalStatus === "failed" && parsedArgs.strictFailures ? 1 : 0;
}

async function runInteractive(
  parsedArgs: Alpha0ShellParsedArgs,
  input: NodeJS.ReadableStream,
  output: NodeJS.WritableStream
): Promise<number> {
  const readline = createInterface({ input, output });
  try {
    writeLine(output, "PhilCore Alpha 0 local shell");
    writeLine(output, "Type a scenario number/name, 'lifecycle', 'lifecycle valid_unlock', 'list', or 'exit'.");
    while (true) {
      writeLine(output);
      writeLine(output, formatAlpha0ScenarioList());
      const answer = (await readline.question("> ")).trim();
      if (answer === "" || answer === "exit" || answer === "quit" || answer === "q") {
        writeLine(output, "Exiting Alpha 0 shell.");
        return 0;
      }
      if (answer === "list") {
        continue;
      }
      if (answer === "lifecycle" || answer.startsWith("lifecycle ")) {
        const [, requestedSequence] = answer.split(/\s+/u);
        const sequence = requestedSequence ?? "states";
        if (!isAlpha0LifecycleDiagnosticSequence(sequence)) {
          writeLine(output, `Unknown lifecycle sequence: ${sequence}`);
          continue;
        }
        writeLine(output);
        writeLine(output, formatAlpha0LifecycleDiagnosticResult(
          await runAlpha0LifecycleDiagnosticAsync(sequence)
        ));
        await readline.question("Press Enter to return to the scenario menu...");
        continue;
      }
      const numeric = Number(answer);
      const scenario = Number.isInteger(numeric)
        ? ALPHA0_DEMO_SCENARIOS[numeric - 1]
        : answer;
      if (!isAlpha0DemoScenario(scenario)) {
        writeLine(output, `Unknown scenario: ${answer}`);
        continue;
      }
      const result = await runNonAuthoritativeAlpha0Demo({
        scenario,
        strictFailures: parsedArgs.strictFailures
      });
      writeLine(output);
      writeLine(output, formatAlpha0DemoResult(result));
      await readline.question("Press Enter to return to the scenario menu...");
    }
  } finally {
    readline.close();
  }
}

export async function runAlpha0Shell(
  options: Alpha0ShellRunOptions = {}
): Promise<Alpha0ShellRunResult> {
  const argv = options.argv ?? [];
  const output = options.output ?? process.stdout;
  const errorOutput = options.errorOutput ?? process.stderr;
  const input = options.input ?? process.stdin;
  const parsedArgs = parseAlpha0ShellArgs(argv);

  if (parsedArgs.error) {
    writeLine(errorOutput, `Error: ${parsedArgs.error}`);
    writeLine(errorOutput, formatAlpha0ScenarioList());
    return {
      exitCode: 2,
      parsedArgs
    };
  }
  if (parsedArgs.help) {
    writeLine(output, formatAlpha0ShellHelp());
    return {
      exitCode: 0,
      parsedArgs
    };
  }
  if (parsedArgs.list) {
    writeLine(output, formatAlpha0ScenarioList());
    return {
      exitCode: 0,
      parsedArgs
    };
  }

  try {
    if (parsedArgs.lifecycle) {
      return {
        exitCode: await runLifecycleDiagnosticMode(parsedArgs, output, errorOutput),
        parsedArgs
      };
    }

    if (parsedArgs.scenario !== undefined) {
      if (!isAlpha0DemoScenario(parsedArgs.scenario)) {
        writeLine(errorOutput, `Unknown scenario: ${parsedArgs.scenario}`);
        writeLine(errorOutput, formatAlpha0ScenarioList());
        return {
          exitCode: 2,
          parsedArgs
        };
      }
      return {
        exitCode: await runScenario(parsedArgs.scenario, parsedArgs, output),
        parsedArgs
      };
    }

    if (parsedArgs.interactive !== true && (input as { readonly isTTY?: boolean }).isTTY === false) {
      writeLine(errorOutput, "No scenario provided and interactive terminal input is unavailable.");
      writeLine(errorOutput, "Provide a scenario or use --list.");
      return {
        exitCode: 2,
        parsedArgs
      };
    }

    return {
      exitCode: await runInteractive(parsedArgs, input, output),
      parsedArgs
    };
  } catch (error) {
    writeLine(errorOutput, "Alpha 0 shell failed.");
    if (parsedArgs.debug) {
      writeLine(errorOutput, error instanceof Error ? error.stack ?? error.message : String(error));
    } else {
      writeLine(errorOutput, "Run with --debug for details.");
    }
    return {
      exitCode: 1,
      parsedArgs
    };
  }
}
