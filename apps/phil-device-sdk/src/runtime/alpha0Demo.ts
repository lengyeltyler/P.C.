import nodeCrypto from "node:crypto";
import { arrayBufferToBase64Url } from "../deviceIdentityWebAuthn.ts";
import {
  createCapabilityRequestDraft,
  createUserSessionContext
} from "./helpers.ts";
import { createInMemoryAuditDraftCollector } from "./audit.ts";
import {
  createInMemoryCapabilityActivationCandidateCollector,
  type CapabilityActivationCandidate
} from "./capabilityActivationCandidates.ts";
import { createValidationOnlyRuntimeApi } from "./facade.ts";
import { createEphemeralUserSessionStore } from "./sessionStore.ts";
import type {
  RuntimeResult
} from "./types.ts";

export type Alpha0DemoScenario =
  | "ordinary_success"
  | "malformed_capability_request"
  | "insufficient_public_trust_metadata"
  | "failed_webauthn_fixture"
  | "revoked_credential_lifecycle"
  | "policy_denial"
  | "canonical_activation_world_id_required"
  | "denied_user_decision_fixture"
  | "expired_artifact_chain"
  | "correlation_mismatch";

export const ALPHA0_DEMO_SCENARIOS: readonly Alpha0DemoScenario[] = Object.freeze([
  "ordinary_success",
  "malformed_capability_request",
  "insufficient_public_trust_metadata",
  "failed_webauthn_fixture",
  "revoked_credential_lifecycle",
  "policy_denial",
  "canonical_activation_world_id_required",
  "denied_user_decision_fixture",
  "expired_artifact_chain",
  "correlation_mismatch"
]);

export function isAlpha0DemoScenario(value: unknown): value is Alpha0DemoScenario {
  return typeof value === "string"
    && (ALPHA0_DEMO_SCENARIOS as readonly string[]).includes(value);
}

export type Alpha0DemoStatus = "succeeded" | "failed";

export type Alpha0DemoStage =
  | "runtime_api_created"
  | "user_session_context_created"
  | "capability_request_created"
  | "capability_grant_draft"
  | "trust_evaluation_draft"
  | "public_trust_metadata_evaluation"
  | "possession_verification_draft"
  | "webauthn_fixture_verification"
  | "possession_evaluation"
  | "bounded_trust_evaluation"
  | "bounded_policy_evaluation"
  | "user_approval_request_draft"
  | "user_decision_fixture"
  | "capability_activation_candidate"
  | "audit_trail_inspected"
  | "final_summary";

export interface Alpha0DemoRequest {
  readonly scenario?: Alpha0DemoScenario;
  readonly strictFailures?: boolean;
}

export interface Alpha0DemoStageResult {
  readonly stage: Alpha0DemoStage;
  readonly status: "succeeded" | "failed";
  readonly outcome?: string;
  readonly artifactId?: string;
  readonly summary: string;
}

export interface Alpha0DemoArtifactSummary {
  readonly capabilityGrantDraftId?: string;
  readonly trustEvaluationDraftId?: string;
  readonly publicTrustMetadataEvaluationId?: string;
  readonly possessionVerificationRequestDraftId?: string;
  readonly webAuthnFixtureVerificationArtifactId?: string;
  readonly possessionEvaluationResultId?: string;
  readonly boundedTrustEvaluationResultId?: string;
  readonly boundedPolicyEvaluationResultId?: string;
  readonly userApprovalRequestDraftId?: string;
  readonly userDecisionFixtureArtifactId?: string;
  readonly capabilityActivationCandidateId?: string;
}

export interface Alpha0DemoFailure {
  readonly stage: Alpha0DemoStage;
  readonly reason: string;
  readonly outcome?: string;
}

export interface Alpha0DemoResult {
  readonly status: Alpha0DemoStatus;
  readonly scenario: Alpha0DemoScenario;
  readonly stages: readonly Alpha0DemoStageResult[];
  readonly artifacts: Alpha0DemoArtifactSummary;
  readonly finalCapabilityActivationCandidateStatus?: CapabilityActivationCandidate["status"];
  readonly auditDraftCount: number;
  readonly auditSummary: readonly {
    readonly eventDraftId: string;
    readonly category: string;
    readonly outcome: string;
    readonly requestKind?: string;
    readonly summary: string;
  }[];
  readonly limitations: readonly string[];
  readonly worldIdRequiredForChosenContext: boolean;
  readonly failure?: Alpha0DemoFailure;
  readonly fixtureOnly: true;
  readonly productionAuthenticationPerformed: false;
  readonly productionUserConsentCollected: false;
  readonly worldIdEnrollmentVerified: false;
  readonly activeCapabilityCreated: false;
  readonly authorizationCreated: false;
  readonly proofExecuted: false;
  readonly adapterExecuted: false;
  readonly persisted: false;
}

const OWNER_COMMITMENT = "0xalpha0ownercommitment" as const;
const APPLICATION_ID = "ethereum-net";
const SESSION_ID = "alpha0-session";
const CREDENTIAL_ID = "alpha0-credential";
const DEVICE_ID = "alpha0-device";
const REQUESTED_AT = "2026-07-10T00:00:00.000Z";

function isApproved<TValue>(result: RuntimeResult<TValue>): result is RuntimeResult<TValue> & {
  readonly value: TValue;
} {
  return result.status === "approved" && result.value !== undefined;
}

type MutableArtifactSummary = {
  -readonly [Key in keyof Alpha0DemoArtifactSummary]: Alpha0DemoArtifactSummary[Key];
};

function publicDeviceMetadata(publicKeyHex: `0x${string}`) {
  return {
    version: "phil-device-identity-v1",
    providerKind: "webauthn-passkey-device-identity-v1",
    deviceIdentityId: "0xalpha0device",
    deviceKeyId: "0xalpha0devicekey",
    credentialId: CREDENTIAL_ID,
    credentialPublicKey: publicKeyHex,
    philIdentity: {
      version: "phil-identity-v1",
      identityRoot: "0xalpha0identityroot",
      ownerCommitment: OWNER_COMMITMENT
    },
    productionSafe: false,
    privateMaterialExportable: false,
    hardwareBacked: false,
    createdAt: REQUESTED_AT,
    metadata: {
      fixture: {
        localOnly: true,
        testOnly: true,
        nonProduction: true,
        nonAuthoritative: true
      }
    }
  } as const;
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
  sha256(input.rpId).copy(out, 0);
  out[32] = input.flags ?? 0x05;
  out.writeUInt32BE((input.signCount ?? 7) >>> 0, 33);
  return out;
}

function buildAssertion(input: {
  readonly privateKey: nodeCrypto.KeyObject;
  readonly challenge: string;
  readonly origin: string;
  readonly rpId: string;
  readonly invalidSignature?: boolean;
}) {
  const authenticatorData = buildAuthenticatorData({
    rpId: input.rpId,
    flags: 0x05,
    signCount: 7
  });
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge: input.challenge,
    origin: input.origin
  }));
  const signedBytes = Buffer.concat([
    authenticatorData,
    sha256(clientDataJSON)
  ]);
  const signer = nodeCrypto.createSign("SHA256");
  signer.update(signedBytes);
  signer.end();
  const signature = Buffer.from(signer.sign(input.privateKey));
  if (input.invalidSignature) {
    signature[signature.length - 1] ^= 0x01;
  }

  return {
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      authenticatorData: arrayBufferToBase64Url(authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(clientDataJSON),
      signature: arrayBufferToBase64Url(signature),
      userHandle: null
    },
    clientExtensionResults: {}
  };
}

function makeResult(input: {
  readonly status: Alpha0DemoStatus;
  readonly scenario: Alpha0DemoScenario;
  readonly stages: Alpha0DemoStageResult[];
  readonly artifacts: MutableArtifactSummary;
  readonly auditCollector: ReturnType<typeof createInMemoryAuditDraftCollector>;
  readonly limitations?: readonly string[];
  readonly candidate?: CapabilityActivationCandidate;
  readonly worldIdRequiredForChosenContext?: boolean;
  readonly failure?: Alpha0DemoFailure;
}): Alpha0DemoResult {
  const auditDrafts = input.auditCollector.getAll();
  return Object.freeze({
    status: input.status,
    scenario: input.scenario,
    stages: Object.freeze([...input.stages]),
    artifacts: Object.freeze({ ...input.artifacts }),
    finalCapabilityActivationCandidateStatus: input.candidate?.status,
    auditDraftCount: auditDrafts.length,
    auditSummary: Object.freeze(auditDrafts.map((draft) => Object.freeze({
      eventDraftId: draft.eventDraftId,
      category: draft.category,
      outcome: draft.outcome,
      requestKind: draft.requestKind,
      summary: draft.summary
    }))),
    limitations: Object.freeze([
      "local_demo_only",
      "fixture_only",
      "no_production_authentication",
      "no_production_user_consent",
      "no_active_capability",
      "no_authorization",
      "no_proof_execution",
      "no_adapter_execution",
      "no_persistence",
      ...(input.limitations ?? []),
      ...(input.candidate?.limitations ?? [])
    ]),
    worldIdRequiredForChosenContext: input.worldIdRequiredForChosenContext ?? false,
    failure: input.failure,
    fixtureOnly: true,
    productionAuthenticationPerformed: false,
    productionUserConsentCollected: false,
    worldIdEnrollmentVerified: false,
    activeCapabilityCreated: false,
    authorizationCreated: false,
    proofExecuted: false,
    adapterExecuted: false,
    persisted: false
  });
}

function fail(input: {
  readonly scenario: Alpha0DemoScenario;
  readonly stages: Alpha0DemoStageResult[];
  readonly artifacts: MutableArtifactSummary;
  readonly auditCollector: ReturnType<typeof createInMemoryAuditDraftCollector>;
  readonly stage: Alpha0DemoStage;
  readonly reason: string;
  readonly outcome?: string;
  readonly worldIdRequiredForChosenContext?: boolean;
}): Alpha0DemoResult {
  input.stages.push(Object.freeze({
    stage: input.stage,
    status: "failed",
    outcome: input.outcome,
    summary: input.reason
  }));
  return makeResult({
    status: "failed",
    scenario: input.scenario,
    stages: input.stages,
    artifacts: input.artifacts,
    auditCollector: input.auditCollector,
    worldIdRequiredForChosenContext: input.worldIdRequiredForChosenContext,
    failure: {
      stage: input.stage,
      reason: input.reason,
      outcome: input.outcome
    }
  });
}

function stage(
  stages: Alpha0DemoStageResult[],
  input: Alpha0DemoStageResult
): void {
  stages.push(Object.freeze(input));
}

export async function runNonAuthoritativeAlpha0Demo(
  request: Alpha0DemoRequest = {}
): Promise<Alpha0DemoResult> {
  const scenario = request.scenario ?? "ordinary_success";
  const stages: Alpha0DemoStageResult[] = [];
  const artifacts: MutableArtifactSummary = {};
  const auditCollector = createInMemoryAuditDraftCollector();
  const candidateCollector = createInMemoryCapabilityActivationCandidateCollector();
  const sessionContextResult = createUserSessionContext({
    sessionId: SESSION_ID,
    ownerCommitment: OWNER_COMMITMENT,
    status: "unlocked",
    activeApplicationId: APPLICATION_ID,
    activeCapabilityIds: [],
    pendingIntentIds: [],
    policyMode: "local-dev",
    metadata: {
      requestMetadata: {
        localOnly: true,
        testOnly: true,
        nonProduction: true,
        nonAuthoritative: true
      }
    }
  });

  if (!sessionContextResult.context) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "user_session_context_created",
      reason: "Alpha 0 fixture session context failed shape validation."
    });
  }

  const sessionStore = createEphemeralUserSessionStore({
    initialSessionContext: sessionContextResult.context
  });
  const api = createValidationOnlyRuntimeApi({
    auditDraftCollector: auditCollector,
    capabilityActivationCandidateCollector: candidateCollector,
    userSessionStore: sessionStore
  });
  stage(stages, {
    stage: "runtime_api_created",
    status: "succeeded",
    summary: "Validation-only Runtime API created with ephemeral collectors."
  });
  stage(stages, {
    stage: "user_session_context_created",
    status: "succeeded",
    artifactId: SESSION_ID,
    summary: "Ephemeral User Session context/store created without secrets or active capabilities."
  });

  const keyPair = generateP256CredentialKeyPair();
  const capabilityRequest = createCapabilityRequestDraft({
    requestId: "alpha0-capability-request",
    applicationId: scenario === "malformed_capability_request" ? "" : APPLICATION_ID,
    capability: "request_message_signature",
    sensitivity: "sensitive",
    reason: "Alpha 0 local demo request",
    requestedAt: REQUESTED_AT,
    scope: scenario === "expired_artifact_chain"
      ? { chainId: 8453, action: "demo_message_signature" }
      : { chainId: 8453, action: "demo_message_signature" }
  });
  stage(stages, {
    stage: "capability_request_created",
    status: "succeeded",
    artifactId: capabilityRequest.requestId,
    summary: "Capability request fixture created."
  });

  const capabilityResult = api.requestCapability(capabilityRequest);
  const capabilityDraft = capabilityResult.value?.capabilityGrantDraft;
  if (!isApproved(capabilityResult) || !capabilityDraft) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "capability_grant_draft",
      reason: "Capability request failed validation and no draft was created.",
      outcome: capabilityResult.status
    });
  }
  artifacts.capabilityGrantDraftId = capabilityDraft.capabilityGrantDraftId;
  stage(stages, {
    stage: "capability_grant_draft",
    status: "succeeded",
    artifactId: capabilityDraft.capabilityGrantDraftId,
    outcome: capabilityDraft.outcome,
    summary: "Capability Grant Draft created without authority."
  });

  if (capabilityDraft.status === "expired") {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "capability_grant_draft",
      reason: "Expired artifact chain stopped at the expired capability draft.",
      outcome: capabilityDraft.status
    });
  }

  const trustDraftResult = api.requestTrustEvaluationDraft({
    requestId: "alpha0-trust-draft-request",
    capabilityGrantDraft: capabilityDraft,
    credentialReference: {
      credentialId: CREDENTIAL_ID,
      credentialKind: "webauthn",
      providerKind: "webauthn-passkey-device-identity-v1",
      credentialStatusReference: "active"
    },
    deviceReference: {
      deviceId: DEVICE_ID,
      providerKind: "webauthn-passkey-device-identity-v1"
    },
    ownerCommitment: OWNER_COMMITMENT,
    auditCorrelationId: "alpha0-trust-draft",
    createdAt: REQUESTED_AT,
    metadata: {
      localOnly: true,
      testOnly: true,
      nonProduction: true,
      nonAuthoritative: true
    }
  });
  const trustDraft = trustDraftResult.value?.trustEvaluationDraft;
  if (!isApproved(trustDraftResult) || !trustDraft) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "trust_evaluation_draft",
      reason: "Trust Evaluation Draft failed validation.",
      outcome: trustDraftResult.status
    });
  }
  artifacts.trustEvaluationDraftId = trustDraft.trustEvaluationDraftId;
  stage(stages, {
    stage: "trust_evaluation_draft",
    status: "succeeded",
    artifactId: trustDraft.trustEvaluationDraftId,
    outcome: trustDraft.outcome,
    summary: "Trust Evaluation Draft created using public references only."
  });

  const metadataResult = api.requestPublicTrustMetadataEvaluation({
    requestId: "alpha0-public-trust-metadata",
    trustEvaluationDraft: trustDraft,
    credential: scenario === "insufficient_public_trust_metadata"
      ? undefined
      : {
        credentialId: CREDENTIAL_ID,
        credentialKind: "webauthn",
        providerKind: "webauthn-passkey-device-identity-v1",
        lifecycleStatus: "active",
        ownerCommitment: OWNER_COMMITMENT
      },
    device: scenario === "insufficient_public_trust_metadata"
      ? undefined
      : {
        deviceId: DEVICE_ID,
        providerKind: "webauthn-passkey-device-identity-v1",
        lifecycleStatus: "active",
        ownerCommitment: OWNER_COMMITMENT,
        publicMetadata: publicDeviceMetadata(keyPair.publicKeyHex)
      },
    ownerCommitment: OWNER_COMMITMENT,
    auditCorrelationId: "alpha0-public-trust-metadata"
  });
  const publicTrust = metadataResult.value?.publicTrustMetadataEvaluation;
  if (!isApproved(metadataResult) || !publicTrust) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "public_trust_metadata_evaluation",
      reason: "Public Trust metadata evaluation request failed validation.",
      outcome: metadataResult.status
    });
  }
  artifacts.publicTrustMetadataEvaluationId = publicTrust.evaluationId;
  stage(stages, {
    stage: "public_trust_metadata_evaluation",
    status: "succeeded",
    artifactId: publicTrust.evaluationId,
    outcome: publicTrust.outcome,
    summary: "Explicit public Trust metadata evaluated without credential loading."
  });
  if (!publicTrust.eligibleForFurtherEvaluation) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "public_trust_metadata_evaluation",
      reason: "Public Trust metadata was insufficient for further local evaluation.",
      outcome: publicTrust.outcome
    });
  }

  const possessionDraftResult = api.requestPossessionVerificationDraft({
    requestId: "alpha0-possession-draft",
    publicTrustMetadataEvaluation: publicTrust,
    auditCorrelationId: "alpha0-possession-draft",
    createdAt: REQUESTED_AT
  });
  const possessionDraft = possessionDraftResult.value?.possessionVerificationRequestDraft;
  if (!isApproved(possessionDraftResult) || !possessionDraft) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "possession_verification_draft",
      reason: "Possession Verification Draft failed validation.",
      outcome: possessionDraftResult.status
    });
  }
  artifacts.possessionVerificationRequestDraftId =
    possessionDraft.possessionVerificationRequestDraftId;
  stage(stages, {
    stage: "possession_verification_draft",
    status: "succeeded",
    artifactId: possessionDraft.possessionVerificationRequestDraftId,
    outcome: possessionDraft.outcome,
    summary: "Possession Verification Draft created; no browser WebAuthn invoked."
  });

  const challenge = "alpha0-fixture-challenge";
  const origin = "http://localhost";
  const rpId = "localhost";
  const webAuthnResult = await api.requestWebAuthnFixturePossessionVerification({
    requestId: "alpha0-webauthn-fixture",
    possessionVerificationRequestDraft: possessionDraft,
    fixture: {
      assertion: buildAssertion({
        privateKey: keyPair.privateKey,
        challenge,
        origin,
        rpId,
        invalidSignature: scenario === "failed_webauthn_fixture"
      }),
      credential: {
        credentialId: CREDENTIAL_ID,
        credentialIdHash: `0x${sha256(CREDENTIAL_ID).toString("hex")}`,
        rawId: CREDENTIAL_ID,
        publicKey: keyPair.publicKeyHex,
        publicKeyAlgorithm: -7,
        signCount: 6
      },
      descriptor: {
        fixtureId: "alpha0-webauthn-fixture",
        challengeBindingReference: possessionDraft.challengeDescriptor.challengeReference,
        expectedChallenge: challenge,
        expectedOrigin: origin,
        expectedRpId: rpId,
        expectedUserVerification: "required",
        previousSignCount: 6,
        metadata: {
          localOnly: true,
          testOnly: true,
          nonProduction: true,
          nonAuthoritative: true
        }
      }
    },
    auditCorrelationId: "alpha0-webauthn-fixture"
  });
  const webAuthnArtifact = webAuthnResult.value?.webAuthnFixtureVerificationArtifact;
  if (!isApproved(webAuthnResult) || !webAuthnArtifact) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "webauthn_fixture_verification",
      reason: "WebAuthn fixture verification request failed validation.",
      outcome: webAuthnResult.status
    });
  }
  artifacts.webAuthnFixtureVerificationArtifactId = webAuthnArtifact.artifactId;
  stage(stages, {
    stage: "webauthn_fixture_verification",
    status: "succeeded",
    artifactId: webAuthnArtifact.artifactId,
    outcome: webAuthnArtifact.outcome,
    summary: "Explicit local WebAuthn fixture checked without production authentication."
  });
  if (webAuthnArtifact.outcome !== "fixture_verified") {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "webauthn_fixture_verification",
      reason: "WebAuthn fixture did not satisfy local fixture checks.",
      outcome: webAuthnArtifact.outcome
    });
  }

  const possessionEvaluationResult = api.requestFixturePossessionEvaluation({
    requestId: "alpha0-possession-evaluation",
    possessionVerificationRequestDraft: possessionDraft,
    webAuthnFixtureVerificationArtifact: webAuthnArtifact,
    auditCorrelationId: "alpha0-possession-evaluation"
  });
  const possessionEvaluation = possessionEvaluationResult.value?.possessionEvaluationResult;
  if (!isApproved(possessionEvaluationResult) || !possessionEvaluation) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "possession_evaluation",
      reason: "Possession Evaluation Result failed validation.",
      outcome: possessionEvaluationResult.status
    });
  }
  artifacts.possessionEvaluationResultId = possessionEvaluation.possessionEvaluationResultId;
  stage(stages, {
    stage: "possession_evaluation",
    status: "succeeded",
    artifactId: possessionEvaluation.possessionEvaluationResultId,
    outcome: possessionEvaluation.outcome,
    summary: "Non-authoritative fixture possession result created."
  });
  if (possessionEvaluation.outcome !== "fixture_possession_checks_satisfied") {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "possession_evaluation",
      reason: "Fixture possession evidence was insufficient.",
      outcome: possessionEvaluation.outcome
    });
  }

  const evaluationContext = scenario === "canonical_activation_world_id_required"
    ? "canonical_phil_activation"
    : "ordinary_runtime";
  const boundedTrustResult = api.requestBoundedTrustEvaluation({
    requestId: "alpha0-bounded-trust",
    trustEvaluationDraft: trustDraft,
    publicTrustMetadataEvaluation: publicTrust,
    possessionEvaluationResult: possessionEvaluation,
    credentialLifecycleStatus: scenario === "revoked_credential_lifecycle" ? "revoked" : "active",
    evaluationContext,
    ownerCommitment: OWNER_COMMITMENT,
    auditCorrelationId: "alpha0-bounded-trust"
  });
  const boundedTrust = boundedTrustResult.value?.boundedTrustEvaluationResult;
  if (!isApproved(boundedTrustResult) || !boundedTrust) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "bounded_trust_evaluation",
      reason: "Bounded Trust evaluation failed validation.",
      outcome: boundedTrustResult.status
    });
  }
  artifacts.boundedTrustEvaluationResultId = boundedTrust.boundedTrustEvaluationResultId;
  stage(stages, {
    stage: "bounded_trust_evaluation",
    status: "succeeded",
    artifactId: boundedTrust.boundedTrustEvaluationResultId,
    outcome: boundedTrust.outcome,
    summary: "Bounded Trust result created without trust authority."
  });
  if (!boundedTrust.eligibleForPolicyReview) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "bounded_trust_evaluation",
      reason: "Bounded Trust result was not eligible for policy review.",
      outcome: boundedTrust.outcome
    });
  }

  const worldIdRequiredForChosenContext =
    scenario === "canonical_activation_world_id_required";
  const policyRules = scenario === "policy_denial"
    ? [{
      ruleId: "alpha0-deny",
      type: "deny_capability" as const,
      effect: "deny" as const
    }]
    : scenario === "canonical_activation_world_id_required"
      ? [{
        ruleId: "alpha0-world-id",
        type: "require_world_id_enrollment" as const,
        effect: "require_world_id_enrollment" as const
      }]
      : [{
        ruleId: "alpha0-require-user",
        type: "require_user_approval" as const,
        effect: "require_user_approval" as const
      }];
  const boundedPolicyResult = api.requestBoundedPolicyEvaluation({
    requestId: "alpha0-bounded-policy",
    capabilityGrantDraft: capabilityDraft,
    boundedTrustEvaluationResult: boundedTrust,
    policySet: {
      policySetId: "alpha0-policy-set",
      rules: policyRules
    },
    context: {
      applicationId: APPLICATION_ID,
      sessionId: SESSION_ID,
      sessionStatus: "unlocked",
      policyMode: "local-dev",
      evaluationContext,
      action: {
        actionId: "alpha0-action",
        actionKind: "message_signature",
        canonicalPhilActivation: scenario === "canonical_activation_world_id_required",
        humanUniquenessProviderKind: scenario === "canonical_activation_world_id_required"
          ? "development_fixture"
          : "unsupported"
      }
    },
    actionContext: {
      actionId: "alpha0-action",
      actionKind: "message_signature",
      canonicalPhilActivation: scenario === "canonical_activation_world_id_required",
      humanUniquenessProviderKind: scenario === "canonical_activation_world_id_required"
        ? "development_fixture"
        : "unsupported"
    },
    auditCorrelationId: "alpha0-bounded-policy"
  });
  const boundedPolicy = boundedPolicyResult.value?.boundedPolicyEvaluationResult;
  if (!isApproved(boundedPolicyResult) || !boundedPolicy) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "bounded_policy_evaluation",
      reason: "Bounded policy evaluation failed validation.",
      outcome: boundedPolicyResult.status,
      worldIdRequiredForChosenContext
    });
  }
  artifacts.boundedPolicyEvaluationResultId = boundedPolicy.boundedPolicyEvaluationResultId;
  stage(stages, {
    stage: "bounded_policy_evaluation",
    status: "succeeded",
    artifactId: boundedPolicy.boundedPolicyEvaluationResultId,
    outcome: boundedPolicy.outcome,
    summary: "Explicit policy set evaluated without policy authority."
  });
  if (
    boundedPolicy.outcome !== "eligible_for_user_approval"
    && boundedPolicy.outcome !== "eligible_for_future_authorization"
  ) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "bounded_policy_evaluation",
      reason: "Bounded policy result was not eligible for user approval or future authorization.",
      outcome: boundedPolicy.outcome,
      worldIdRequiredForChosenContext
    });
  }

  const approvalResult = api.requestUserApprovalDraft({
    requestId: "alpha0-user-approval-draft",
    capabilityGrantDraft: capabilityDraft,
    boundedTrustEvaluationResult: boundedTrust,
    boundedPolicyEvaluationResult: boundedPolicy,
    approvalSurface: "developer_fixture",
    requestedScope: capabilityDraft.scope,
    effectiveScope: capabilityDraft.scope,
    requestedDurationSeconds: 300,
    effectiveDurationSeconds: 300,
    auditCorrelationId: "alpha0-user-approval-draft",
    expiresAt: scenario === "expired_artifact_chain"
      ? "2000-01-01T00:00:00.000Z"
      : undefined
  });
  const approvalDraft = approvalResult.value?.userApprovalRequestDraft;
  if (!isApproved(approvalResult) || !approvalDraft) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "user_approval_request_draft",
      reason: "User Approval Request Draft failed validation.",
      outcome: approvalResult.status,
      worldIdRequiredForChosenContext
    });
  }
  artifacts.userApprovalRequestDraftId = approvalDraft.userApprovalRequestDraftId;
  stage(stages, {
    stage: "user_approval_request_draft",
    status: "succeeded",
    artifactId: approvalDraft.userApprovalRequestDraftId,
    outcome: approvalDraft.outcome,
    summary: "User Approval Request Draft created; no user decision collected."
  });

  const decisionResult = api.requestUserDecisionFixture({
    requestId: "alpha0-user-decision-fixture",
    userApprovalRequestDraft: approvalDraft,
    boundedPolicyEvaluationResult: boundedPolicy,
    boundedTrustEvaluationResult: boundedTrust,
    capabilityGrantDraft: capabilityDraft,
    outcome: scenario === "denied_user_decision_fixture" ? "deny" : "approve",
    source: "developer_fixture",
    auditCorrelationId: "alpha0-user-decision-fixture",
    recordedAt: REQUESTED_AT
  });
  const decisionFixture = decisionResult.value?.userDecisionFixtureArtifact;
  if (!isApproved(decisionResult) || !decisionFixture) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "user_decision_fixture",
      reason: "User Decision Fixture Artifact failed validation.",
      outcome: decisionResult.status,
      worldIdRequiredForChosenContext
    });
  }
  artifacts.userDecisionFixtureArtifactId = decisionFixture.userDecisionFixtureArtifactId;
  stage(stages, {
    stage: "user_decision_fixture",
    status: "succeeded",
    artifactId: decisionFixture.userDecisionFixtureArtifactId,
    outcome: decisionFixture.outcome,
    summary: "Local user decision fixture recorded; not production consent."
  });
  if (decisionFixture.outcome !== "approve") {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "user_decision_fixture",
      reason: "Only an approve fixture may proceed to capability activation candidacy.",
      outcome: decisionFixture.outcome,
      worldIdRequiredForChosenContext
    });
  }

  const candidateFixture = scenario === "correlation_mismatch"
    ? Object.freeze({
      ...decisionFixture,
      capabilityGrantDraftId: "alpha0-wrong-capability-draft"
    })
    : decisionFixture;
  const candidateResult = api.requestCapabilityActivationCandidate({
    requestId: "alpha0-capability-activation-candidate",
    capabilityGrantDraft: capabilityDraft,
    boundedTrustEvaluationResult: boundedTrust,
    boundedPolicyEvaluationResult: boundedPolicy,
    userApprovalRequestDraft: approvalDraft,
    userDecisionFixtureArtifact: candidateFixture,
    applicationId: APPLICATION_ID,
    sessionId: SESSION_ID,
    ownerCommitment: OWNER_COMMITMENT,
    capabilityName: capabilityDraft.capabilityName,
    auditCorrelationId: scenario === "correlation_mismatch"
      ? decisionFixture.auditCorrelationId
      : undefined,
    createdAt: REQUESTED_AT
  });
  const candidate = candidateResult.value?.capabilityActivationCandidate;
  if (!isApproved(candidateResult) || !candidate) {
    return fail({
      scenario,
      stages,
      artifacts,
      auditCollector,
      stage: "capability_activation_candidate",
      reason: "Capability Activation Candidate failed validation.",
      outcome: candidateResult.status,
      worldIdRequiredForChosenContext
    });
  }
  artifacts.capabilityActivationCandidateId = candidate.capabilityActivationCandidateId;
  stage(stages, {
    stage: "capability_activation_candidate",
    status: "succeeded",
    artifactId: candidate.capabilityActivationCandidateId,
    outcome: candidate.status,
    summary: "Capability Activation Candidate created; no active capability was created."
  });
  stage(stages, {
    stage: "audit_trail_inspected",
    status: "succeeded",
    outcome: String(auditCollector.count()),
    summary: "Ephemeral audit draft trail inspected without persistence."
  });
  stage(stages, {
    stage: "final_summary",
    status: "succeeded",
    outcome: candidate.status,
    summary: "Alpha 0 non-authoritative orchestration completed and stopped before authority."
  });

  return makeResult({
    status: "succeeded",
    scenario,
    stages,
    artifacts,
    auditCollector,
    candidate,
    worldIdRequiredForChosenContext
  });
}
