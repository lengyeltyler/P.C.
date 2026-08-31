import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { getBytes, hexlify, keccak256 } from "ethers";

import {
  UNLOCK_PROOF_SCHEMA_VERSION,
  UNLOCK_PROOF_TYPE,
  canonicalOwnerCommitmentFromIdentityRoot,
  identityRootFromPhilSecret,
  nullifier as deriveNullifier,
  proofInputHash,
  type Hex,
  type UnlockProofPublicInputs
} from "../hashes.ts";
import { normalizePhilSecret } from "../identity.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  type AuthorizationPackageDraft,
  validateAuthorizationPackageDraftShape
} from "./authorizationPackageDraft.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeFailed,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type ActionUnlockWitnessRequestStatus =
  | "witness_request_created"
  | "witness_request_rejected"
  | "witness_request_malformed"
  | "witness_request_expired"
  | "witness_request_replayed"
  | "witness_request_unsupported";

export type ActionUnlockWitnessRequestOutcome =
  | "witness_request_created"
  | "draft_ineligible"
  | "vault_state_ineligible"
  | "identity_binding_mismatch"
  | "nullifier_binding_mismatch"
  | "provider_unavailable"
  | "witness_material_unavailable"
  | "witness_expired"
  | "witness_replayed"
  | "malformed"
  | "unsupported";

export type ActionUnlockProofGenerationStatus =
  | "proof_generated"
  | "proof_generation_rejected"
  | "proof_generation_failed"
  | "proof_generation_malformed"
  | "proof_generation_replayed"
  | "proof_generation_expired";

export type ActionUnlockProofGenerationOutcome =
  | "proof_generated"
  | "draft_ineligible"
  | "witness_ineligible"
  | "prover_unavailable"
  | "prover_failed"
  | "prover_timeout"
  | "public_input_mismatch"
  | "proof_input_hash_mismatch"
  | "proof_type_mismatch"
  | "proof_artifact_malformed"
  | "proof_generation_expired"
  | "proof_generation_replayed"
  | "malformed"
  | "unsupported";

export type ActionUnlockWitnessRequirement =
  | "valid_authorization_package_draft"
  | "unlocked_session_context"
  | "protected_witness_provider"
  | "owner_bound_identity_witness"
  | "draft_bound_nullifier_witness"
  | "one_time_witness_handle";

export type ActionUnlockWitnessLimitation =
  | "process_local_witness_handle_only"
  | "provider_internal_witness_material_only"
  | "no_witness_material_returned"
  | "no_witness_persistence"
  | "no_runtime_secret_access"
  | "no_application_witness_access";

export type ActionUnlockProofGenerationLimitation =
  | "proof_generation_only"
  | "subprocess_boundary"
  | "stdin_witness_transfer_to_existing_prover"
  | "no_temporary_witness_file"
  | "no_verified_fact_publication"
  | "no_nullifier_consumption"
  | "no_authorization_package_finalization"
  | "no_adapter_execution"
  | "no_transaction_submission"
  | "process_local_replay_protection_only"
  | "local_synthetic_research_only"
  | "not_for_real_secrets"
  | "proof_artifact_contains_witness_openings"
  | "no_external_verifier_transmission";

export const EXPERIMENTAL_SECRET_BEARING_PROOF_GATE =
  "EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT_LOCAL_SYNTHETIC_RESEARCH_ONLY" as const;

export const EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT =
  "EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT" as const;

export type ProtectedWitnessProviderKind =
  | "local_device_vault"
  | "local_test_fixture"
  | "unsupported";

export type ProtectedWitnessProviderId = string;

export interface ProtectedWitnessProviderDescriptor {
  readonly providerId: ProtectedWitnessProviderId;
  readonly providerKind: ProtectedWitnessProviderKind;
  readonly displayName: string;
  readonly version: string;
  readonly processLocalOnly: boolean;
  readonly witnessMaterialReturnedToRuntime: false;
  readonly witnessMaterialPersisted: false;
}

export interface ProtectedWitnessRequestContext {
  readonly requestId: string;
  readonly authorizationPackageDraftId: string;
  readonly ownerCommitment: Hex;
  readonly nullifier: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly auditCorrelationId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ProtectedWitnessHandleMetadata {
  readonly providerId: ProtectedWitnessProviderId;
  readonly providerKind: ProtectedWitnessProviderKind;
  readonly authorizationPackageDraftId: string;
  readonly ownerCommitment: Hex;
  readonly nullifier: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly processLocalOnly: true;
  readonly oneTimeUse: true;
  readonly rawWitnessIncluded: false;
}

export interface ProtectedWitnessHandle {
  readonly handleId: string;
  readonly metadata: ProtectedWitnessHandleMetadata;
}

export interface ActionUnlockWitnessBinding {
  readonly authorizationPackageDraftId: string;
  readonly ownerCommitment: Hex;
  readonly nullifier: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly auditCorrelationId: string;
  readonly providerId: ProtectedWitnessProviderId;
}

export interface ActionUnlockWitnessRequest {
  readonly requestId: string;
  readonly authorizationPackageDraft: AuthorizationPackageDraft;
  readonly provider: ActionUnlockProtectedWitnessProvider;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ActionUnlockWitnessRequestResultValue {
  readonly witnessRequestId: string;
  readonly status: "witness_request_created";
  readonly outcome: "witness_request_created";
  readonly binding: ActionUnlockWitnessBinding;
  readonly handle: ProtectedWitnessHandle;
  readonly provider: ProtectedWitnessProviderDescriptor;
  readonly requirements: readonly ActionUnlockWitnessRequirement[];
  readonly limitations: readonly ActionUnlockWitnessLimitation[];
  readonly witnessMaterialExposed: false;
  readonly persisted: false;
}

export type ActionUnlockWitnessRequestResult =
  RuntimeResult<ActionUnlockWitnessRequestResultValue>;

export interface ActionUnlockProtectedWitnessProvider {
  describeProvider(): ProtectedWitnessProviderDescriptor;
  checkAvailability(context: ProtectedWitnessRequestContext): Promise<{
    readonly available: boolean;
    readonly reason?: string;
  }>;
  prepareWitnessHandle(
    context: ProtectedWitnessRequestContext
  ): Promise<ActionUnlockWitnessRequestResult>;
  consumeWitnessForProving<TValue>(
    handle: ProtectedWitnessHandle,
    draft: AuthorizationPackageDraft,
    consumer: (witness: ProtectedActionUnlockWitnessMaterial) => Promise<TValue>
  ): Promise<TValue>;
  invalidateWitnessHandle(handle: ProtectedWitnessHandle): Promise<{
    readonly status: "invalidated" | "not_found" | "already_consumed";
    readonly handleId: string;
  }>;
}

interface ProtectedActionUnlockWitnessMaterial {
  readonly philSecret: Hex;
  readonly nullifierSeed: Hex;
}

export interface ActionUnlockProofArtifactReference {
  readonly artifactClassification: typeof EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT;
  readonly proofArtifactId: string;
  readonly proofType: typeof UNLOCK_PROOF_TYPE;
  readonly codec: string;
  readonly proofByteLength: number;
  readonly proofDigest: Hex;
  readonly proofBlob?: Hex;
  readonly proofBlobIncluded: boolean;
  readonly nonSecretProofArtifact: false;
  readonly containsWitnessOpenings: true;
  readonly safeForExternalVerifierTransmission: false;
  readonly executableByAdapters: false;
}

export interface ActionUnlockProofGenerationBinding {
  readonly authorizationPackageDraftId: string;
  readonly witnessHandleId: string;
  readonly providerId: ProtectedWitnessProviderId;
  readonly ownerCommitment: Hex;
  readonly nullifier: Hex;
  readonly proofInputHash: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly auditCorrelationId: string;
}

export interface ActionUnlockProofGenerationSummary {
  readonly proverUsed: string;
  readonly proverInvocation: "subprocess";
  readonly proverVersionReference: string;
  readonly proverSelfCheckPerformed: false;
  readonly publicInputsMatched: true;
  readonly proofInputHashMatched: true;
  readonly temporaryWitnessFileUsed: false;
  readonly temporaryWitnessCleanupStatus: "not_required";
  readonly durationMs: number;
}

export interface ActionUnlockProofGenerationArtifact {
  readonly artifactClassification: typeof EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT;
  readonly proofGenerationArtifactId: string;
  readonly status: "proof_generated";
  readonly outcome: "proof_generated";
  readonly proofGenerated: true;
  readonly proofType: typeof UNLOCK_PROOF_TYPE;
  readonly binding: ActionUnlockProofGenerationBinding;
  readonly proofArtifact: ActionUnlockProofArtifactReference;
  readonly publicInputs: UnlockProofPublicInputs;
  readonly proofInputHash: Hex;
  readonly summary: ActionUnlockProofGenerationSummary;
  readonly limitations: readonly ActionUnlockProofGenerationLimitation[];
  readonly proofVerifiedByRuntime: false;
  readonly verifiedFactPublished: false;
  readonly nullifierConsumed: false;
  readonly authorizationPackageFinalized: false;
  readonly adapterExecutionAllowed: false;
  readonly transactionSubmitted: false;
  readonly rawWitnessFieldsReturned: false;
  readonly witnessRecoverableFromProof: true;
  /** Raw philSecret/nullifierSeed fields are not returned directly. The proof
   * artifact is still secret-bearing; see containsWitnessOpenings. */
  readonly witnessMaterialExposed: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: ActionUnlockProofGenerationCollectionResult;
}

export interface ActionUnlockProofGenerationRequest {
  readonly requestId: string;
  readonly authorizationPackageDraft: AuthorizationPackageDraft;
  readonly witnessProvider: ActionUnlockProtectedWitnessProvider;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  /** Required quarantine acknowledgement. The current proof contains queried
   * witness openings and may be generated only from a local synthetic fixture. */
  readonly experimentalSecretBearingProofGate?:
    typeof EXPERIMENTAL_SECRET_BEARING_PROOF_GATE;
  readonly timeoutMs?: number;
  readonly includeProofBlob?: boolean;
  readonly expectedProofInputHash?: Hex;
  readonly expectedProofType?: typeof UNLOCK_PROOF_TYPE;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type ActionUnlockProofGenerationResult =
  RuntimeResult<ActionUnlockProofGenerationArtifact>;

export interface ActionUnlockProofGenerationConsumptionRecord {
  readonly proofGenerationRequestId: string;
  readonly authorizationPackageDraftId: string;
  readonly witnessHandleId: string;
  readonly proofInputHash: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export interface EphemeralActionUnlockProofGenerationConsumptionStore {
  consume(record: ActionUnlockProofGenerationConsumptionRecord): {
    readonly status: "consumed" | "replayed" | "cleared";
    readonly record?: ActionUnlockProofGenerationConsumptionRecord;
    readonly records: readonly ActionUnlockProofGenerationConsumptionRecord[];
    readonly reason?: string;
  };
  hasRequest(proofGenerationRequestId: string): boolean;
  hasDraft(authorizationPackageDraftId: string): boolean;
  clear(): {
    readonly status: "cleared";
    readonly records: readonly ActionUnlockProofGenerationConsumptionRecord[];
  };
  getAll(): readonly ActionUnlockProofGenerationConsumptionRecord[];
}

export type ActionUnlockProofGenerationCollectionStatus =
  | "collected"
  | "duplicate_rejected"
  | "cleared";

export interface ActionUnlockProofGenerationCollectionResult {
  readonly status: ActionUnlockProofGenerationCollectionStatus;
  readonly artifact?: ActionUnlockProofGenerationArtifact;
  readonly artifacts: readonly ActionUnlockProofGenerationArtifact[];
  readonly count: number;
  readonly persisted: false;
  readonly reason?: string;
}

export interface ActionUnlockProofGenerationArtifactStore {
  addArtifact(
    artifact: ActionUnlockProofGenerationArtifact
  ): ActionUnlockProofGenerationCollectionResult;
  getById(artifactId: string): ActionUnlockProofGenerationArtifact | undefined;
  getAll(): readonly ActionUnlockProofGenerationArtifact[];
  count(): number;
  clear(): ActionUnlockProofGenerationCollectionResult;
}

export interface InMemoryActionUnlockProofGenerationArtifactStoreOptions {
  readonly maxArtifactCount?: number;
}

export interface StaticActionUnlockProtectedWitnessProviderInput {
  readonly providerId: ProtectedWitnessProviderId;
  readonly providerKind?: ProtectedWitnessProviderKind;
  readonly displayName?: string;
  readonly version?: string;
  readonly philSecret: Hex;
  readonly nullifierSeed: Hex;
  readonly unavailable?: boolean;
  readonly failOnConsume?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

const PROOF_GENERATION_STATUSES = new Set<ActionUnlockProofGenerationStatus>([
  "proof_generated",
  "proof_generation_rejected",
  "proof_generation_failed",
  "proof_generation_malformed",
  "proof_generation_replayed",
  "proof_generation_expired"
]);

const WITNESS_REQUEST_STATUSES = new Set<ActionUnlockWitnessRequestStatus>([
  "witness_request_created",
  "witness_request_rejected",
  "witness_request_malformed",
  "witness_request_expired",
  "witness_request_replayed",
  "witness_request_unsupported"
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isHex32(value: unknown): value is Hex {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function hasValidDateShape(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function expired(value: string | undefined, now = Date.now()): boolean {
  return value !== undefined && Date.parse(value) <= now;
}

function validation(errors: string[]): RuntimeValidationResult {
  return Object.freeze({
    valid: errors.length === 0,
    errors: Object.freeze(errors)
  });
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as TValue;
  if (isRecord(value)) {
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, freezeRecord(entry)]))
    ) as TValue;
  }
  return value;
}

function proofError(
  code: string,
  category: RuntimeErrorDescriptor["category"],
  message: string,
  outcome: ActionUnlockProofGenerationOutcome | ActionUnlockWitnessRequestOutcome,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    code,
    category,
    message,
    recoverable: false,
    details: {
      outcome,
      errors
    }
  };
}

function outcomeForErrors(errors: readonly string[]): ActionUnlockProofGenerationOutcome {
  if (errors.some((error) => error.includes("expired"))) return "proof_generation_expired";
  if (errors.some((error) => error.includes("proofType"))) return "proof_type_mismatch";
  if (errors.some((error) => error.includes("proofInputHash"))) return "proof_input_hash_mismatch";
  if (errors.some((error) => error.includes("public input"))) return "public_input_mismatch";
  if (errors.some((error) => error.includes("prover"))) return "prover_failed";
  if (errors.some((error) => error.includes("witness"))) return "witness_ineligible";
  if (errors.some((error) => error.includes("draft"))) return "draft_ineligible";
  return "malformed";
}

function witnessOutcomeForErrors(errors: readonly string[]): ActionUnlockWitnessRequestOutcome {
  if (errors.some((error) => error.includes("provider"))) return "provider_unavailable";
  if (errors.some((error) => error.includes("owner"))) return "identity_binding_mismatch";
  if (errors.some((error) => error.includes("nullifier"))) return "nullifier_binding_mismatch";
  if (errors.some((error) => error.includes("expired"))) return "witness_expired";
  if (errors.some((error) => error.includes("witness"))) return "witness_material_unavailable";
  if (errors.some((error) => error.includes("draft"))) return "draft_ineligible";
  return "malformed";
}

function publicInputsFromDraft(draft: AuthorizationPackageDraft): UnlockProofPublicInputs {
  return draft.actionUnlockPublicInputDraft.publicInputs;
}

function publicInputsToProverJson(publicInputs: UnlockProofPublicInputs) {
  return {
    ownerCommitment: publicInputs.ownerCommitment,
    actionHash: publicInputs.actionHash,
    policyHash: publicInputs.policyHash,
    nullifier: publicInputs.nullifier,
    consumerDataHash: publicInputs.consumerDataHash,
    expiry: BigInt(publicInputs.expiry).toString()
  };
}

function validateDraftForProofGeneration(draft: AuthorizationPackageDraft): readonly string[] {
  const errors: string[] = [];
  errors.push(...validateAuthorizationPackageDraftShape(draft).errors.map((error) => `draft.${error}`));
  if (draft.actionUnlockPublicInputDraft.proofType !== UNLOCK_PROOF_TYPE) {
    errors.push("proofType mismatch");
  }
  if (draft.actionUnlockPublicInputDraft.version !== UNLOCK_PROOF_SCHEMA_VERSION) {
    errors.push("proof version mismatch");
  }
  if (draft.actionUnlockPublicInputDraft.factShapeReference !== "[fact_high, fact_low]") {
    errors.push("fact shape mismatch");
  }
  if (draft.authorizationPackageExecutable !== false) {
    errors.push("draft is executable");
  }
  if (draft.proofGenerated !== false) errors.push("draft already marks proof generated");
  if (draft.nullifierConsumed !== false) errors.push("draft already marks nullifier consumed");
  if (expired(draft.validity.expiresAt)) errors.push("draft expired");
  const expectedProofInputHash = proofInputHash({
    version: draft.actionUnlockPublicInputDraft.version,
    proofType: draft.actionUnlockPublicInputDraft.proofType,
    publicInputs: publicInputsFromDraft(draft)
  });
  if (expectedProofInputHash !== draft.actionUnlockPublicInputDraft.proofInputHash
    || expectedProofInputHash !== draft.hashSummary.proofInputHash) {
    errors.push("proofInputHash mismatch");
  }
  return Object.freeze([...new Set(errors)]);
}

export function validateActionUnlockWitnessRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["witness request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.authorizationPackageDraft)) {
    errors.push("authorizationPackageDraft is required");
  } else {
    errors.push(...validateDraftForProofGeneration(
      request.authorizationPackageDraft as unknown as AuthorizationPackageDraft
    ));
  }
  if (!request.provider || typeof request.provider !== "object") {
    errors.push("provider is required");
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a date string");
  if (hasValidDateShape(request.expiresAt) && expired(request.expiresAt)) {
    errors.push("witness request expired");
  }
  if (!isNonEmptyString(request.auditCorrelationId)) {
    errors.push("auditCorrelationId is required");
  }
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  }
  return validation(errors);
}

export function validateActionUnlockProofGenerationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["proof generation request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.authorizationPackageDraft)) {
    errors.push("authorizationPackageDraft is required");
  } else {
    errors.push(...validateDraftForProofGeneration(
      request.authorizationPackageDraft as unknown as AuthorizationPackageDraft
    ));
  }
  if (!request.witnessProvider || typeof request.witnessProvider !== "object") {
    errors.push("witnessProvider is required");
  } else {
    try {
      const provider = (request.witnessProvider as ActionUnlockProtectedWitnessProvider)
        .describeProvider?.();
      if (provider?.providerKind !== "local_test_fixture"
        || provider.processLocalOnly !== true) {
        errors.push("secret-bearing proof research requires a process-local synthetic fixture provider");
      }
    } catch {
      errors.push("witnessProvider descriptor is invalid");
    }
  }
  if (request.experimentalSecretBearingProofGate
    !== EXPERIMENTAL_SECRET_BEARING_PROOF_GATE) {
    errors.push("experimental secret-bearing proof gate is required");
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a date string");
  if (hasValidDateShape(request.expiresAt) && expired(request.expiresAt)) {
    errors.push("proof generation request expired");
  }
  if (!isNonEmptyString(request.auditCorrelationId)) {
    errors.push("auditCorrelationId is required");
  }
  if (request.expectedProofInputHash !== undefined
    && !isHex32(request.expectedProofInputHash)) {
    errors.push("expectedProofInputHash must be bytes32");
  }
  if (request.expectedProofType !== undefined
    && request.expectedProofType !== UNLOCK_PROOF_TYPE) {
    errors.push("proofType mismatch");
  }
  if (isRecord(request.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  }
  return validation(errors);
}

export function isActionUnlockWitnessRequestStatus(
  value: unknown
): value is ActionUnlockWitnessRequestStatus {
  return WITNESS_REQUEST_STATUSES.has(value as ActionUnlockWitnessRequestStatus);
}

export function isActionUnlockProofGenerationStatus(
  value: unknown
): value is ActionUnlockProofGenerationStatus {
  return PROOF_GENERATION_STATUSES.has(value as ActionUnlockProofGenerationStatus);
}

function createWitnessAuditDraft(input: {
  readonly request: ActionUnlockWitnessRequest;
  readonly outcome: ActionUnlockWitnessRequestOutcome;
  readonly handle?: ProtectedWitnessHandle;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  const draft = input.request.authorizationPackageDraft;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.handle ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    intentId: draft.binding.intentId,
    capability: draft.binding.capabilityName,
    summary: input.handle
      ? "ACTION_UNLOCK witness handle created; witness material was not exposed, persisted, or returned."
      : "ACTION_UNLOCK witness request rejected; witness material was not exposed, persisted, or returned.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authorizationPackageDraftId: draft.authorizationPackageDraftId,
      witnessHandleId: input.handle?.handleId,
      providerId: input.request.provider.describeProvider().providerId,
      proofType: UNLOCK_PROOF_TYPE,
      proofInputHash: draft.hashSummary.proofInputHash,
      outcome: input.outcome,
      witnessMaterialExposed: false,
      persisted: false,
      errors: input.errors ?? []
    }
  });
}

function createProofAuditDraft(input: {
  readonly request: ActionUnlockProofGenerationRequest;
  readonly outcome: ActionUnlockProofGenerationOutcome;
  readonly artifact?: ActionUnlockProofGenerationArtifact;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  const draft = input.request.authorizationPackageDraft;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.artifact ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    intentId: draft.binding.intentId,
    capability: draft.binding.capabilityName,
    summary: input.artifact
      ? "ACTION_UNLOCK STARK proof artifact generated; no fact publication, nullifier consumption, package finalization, adapter call, or execution occurred."
      : "ACTION_UNLOCK proof generation rejected or failed; no fact publication, nullifier consumption, package finalization, adapter call, or execution occurred.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authorizationPackageDraftId: draft.authorizationPackageDraftId,
      proofGenerationArtifactId: input.artifact?.proofGenerationArtifactId,
      proofType: UNLOCK_PROOF_TYPE,
      proofInputHash: draft.hashSummary.proofInputHash,
      proofDigest: input.artifact?.proofArtifact.proofDigest,
      proofByteLength: input.artifact?.proofArtifact.proofByteLength,
      providerId: input.request.witnessProvider.describeProvider().providerId,
      proverUsed: input.artifact?.summary.proverUsed ?? "generate-unlock-proof-json",
      temporaryWitnessFileUsed: false,
      temporaryWitnessCleanupStatus: "not_required",
      outcome: input.outcome,
      witnessMaterialExposed: false,
      proofBytesLogged: false,
      verifiedFactPublished: false,
      nullifierConsumed: false,
      authorizationPackageFinalized: false,
      adapterExecutionAllowed: false,
      transactionSubmitted: false,
      errors: input.errors ?? []
    }
  });
}

export function createStaticActionUnlockProtectedWitnessProvider(
  input: StaticActionUnlockProtectedWitnessProviderInput
): ActionUnlockProtectedWitnessProvider {
  const philSecret = normalizePhilSecret(input.philSecret);
  const nullifierSeed = input.nullifierSeed;
  const descriptor = freezeRecord({
    providerId: input.providerId,
    providerKind: input.providerKind ?? "local_test_fixture",
    displayName: input.displayName ?? "Local test ACTION_UNLOCK witness provider",
    version: input.version ?? "v1",
    processLocalOnly: true,
    witnessMaterialReturnedToRuntime: false as const,
    witnessMaterialPersisted: false as const
  });
  const handles = new Map<string, {
    readonly handle: ProtectedWitnessHandle;
    readonly consumed: boolean;
  }>();

  function bindingErrors(context: ProtectedWitnessRequestContext): readonly string[] {
    const errors: string[] = [];
    if (input.unavailable) errors.push("provider unavailable");
    if (expired(context.expiresAt)) errors.push("witness request expired");
    const ownerCommitment = canonicalOwnerCommitmentFromIdentityRoot(
      identityRootFromPhilSecret(philSecret)
    );
    if (ownerCommitment !== context.ownerCommitment) {
      errors.push("owner commitment mismatch");
    }
    const expectedNullifier = deriveNullifier({
      ownerCommitment: context.ownerCommitment,
      actionHash: context.metadata?.actionHash as Hex,
      policyHash: context.metadata?.policyHash as Hex,
      nullifierSeed
    });
    if (expectedNullifier !== context.nullifier) {
      errors.push("nullifier binding mismatch");
    }
    if (isRecord(input.metadata)) {
      errors.push(...validateNoSensitiveMetadataKeys(input.metadata).errors);
    }
    return Object.freeze(errors);
  }

  return {
    describeProvider() {
      return descriptor;
    },
    async checkAvailability(context) {
      const errors = bindingErrors(context);
      return freezeRecord({
        available: errors.length === 0,
        reason: errors.join("; ") || undefined
      });
    },
    async prepareWitnessHandle(context) {
      const fakeRequest = {
        requestId: context.requestId,
        authorizationPackageDraft: {
          authorizationPackageDraftId: context.authorizationPackageDraftId,
          binding: {
            sessionId: context.sessionId,
            applicationId: context.applicationId,
            intentId: "",
            capabilityName: "",
            auditCorrelationId: context.auditCorrelationId
          },
          hashSummary: { proofInputHash: context.metadata?.proofInputHash }
        },
        provider: this,
        auditCorrelationId: context.auditCorrelationId
      } as unknown as ActionUnlockWitnessRequest;
      const errors = bindingErrors(context);
      if (errors.length > 0) {
        const outcome = witnessOutcomeForErrors(errors);
        return runtimeDenied(proofError(
          "ACTION_UNLOCK_WITNESS_REJECTED",
          "proof_failed",
          "ACTION_UNLOCK witness request was rejected.",
          outcome,
          errors
        ), { auditEventId: createWitnessAuditDraft({
          request: fakeRequest,
          outcome,
          errors
        }).eventDraftId });
      }
      const handle = freezeRecord({
        handleId: createAuditCorrelationId([
          context.authorizationPackageDraftId,
          context.sessionId,
          context.auditCorrelationId,
          "action-unlock-witness-handle"
        ]),
        metadata: {
          providerId: descriptor.providerId,
          providerKind: descriptor.providerKind,
          authorizationPackageDraftId: context.authorizationPackageDraftId,
          ownerCommitment: context.ownerCommitment,
          nullifier: context.nullifier,
          sessionId: context.sessionId,
          applicationId: context.applicationId,
          createdAt: context.issuedAt,
          expiresAt: context.expiresAt,
          processLocalOnly: true as const,
          oneTimeUse: true as const,
          rawWitnessIncluded: false as const
        }
      });
      handles.set(handle.handleId, { handle, consumed: false });
      return runtimeOk(freezeRecord({
        witnessRequestId: context.requestId,
        status: "witness_request_created" as const,
        outcome: "witness_request_created" as const,
        binding: {
          authorizationPackageDraftId: context.authorizationPackageDraftId,
          ownerCommitment: context.ownerCommitment,
          nullifier: context.nullifier,
          sessionId: context.sessionId,
          applicationId: context.applicationId,
          auditCorrelationId: context.auditCorrelationId,
          providerId: descriptor.providerId
        },
        handle,
        provider: descriptor,
        requirements: [
          "valid_authorization_package_draft",
          "unlocked_session_context",
          "protected_witness_provider",
          "owner_bound_identity_witness",
          "draft_bound_nullifier_witness",
          "one_time_witness_handle"
        ],
        limitations: [
          "process_local_witness_handle_only",
          "provider_internal_witness_material_only",
          "no_witness_material_returned",
          "no_witness_persistence",
          "no_runtime_secret_access",
          "no_application_witness_access"
        ],
        witnessMaterialExposed: false as const,
        persisted: false as const
      }));
    },
    async consumeWitnessForProving(handle, draft, consumer) {
      const record = handles.get(handle.handleId);
      if (!record) {
        throw new Error("witness handle not found");
      }
      if (record.consumed) {
        throw new Error("witness handle already consumed");
      }
      if (expired(handle.metadata.expiresAt)) {
        handles.delete(handle.handleId);
        throw new Error("witness handle expired");
      }
      if (handle.metadata.authorizationPackageDraftId !== draft.authorizationPackageDraftId
        || handle.metadata.ownerCommitment !== draft.binding.ownerCommitment
        || handle.metadata.nullifier !== draft.nullifierReference.nullifier
        || handle.metadata.sessionId !== draft.binding.sessionId
        || handle.metadata.applicationId !== draft.binding.applicationId) {
        throw new Error("witness handle binding mismatch");
      }
      handles.set(handle.handleId, { handle: record.handle, consumed: true });
      try {
        if (input.failOnConsume) {
          throw new Error("witness provider failed during prover handoff");
        }
        return await consumer({ philSecret, nullifierSeed });
      } finally {
        handles.delete(handle.handleId);
      }
    },
    async invalidateWitnessHandle(handle) {
      const record = handles.get(handle.handleId);
      if (!record) return { status: "not_found", handleId: handle.handleId };
      handles.delete(handle.handleId);
      return {
        status: record.consumed ? "already_consumed" : "invalidated",
        handleId: handle.handleId
      };
    }
  };
}

async function invokeExistingActionUnlockProver(input: {
  readonly publicInputs: UnlockProofPublicInputs;
  readonly philSecret: Hex;
  readonly nullifierSeed: Hex;
  readonly timeoutMs: number;
}): Promise<{
  readonly proofType: string;
  readonly codec: string;
  readonly proofBlob: Hex;
  readonly timedOut: boolean;
  readonly stderr: string;
}> {
  const bundledProver = process.env.PHILCORE_ACTION_UNLOCK_PROVER_BIN;
  const command = bundledProver && bundledProver.length > 0 ? bundledProver : "cargo";
  const args = bundledProver && bundledProver.length > 0
    ? []
    : [
      "+nightly-2025-07-14",
      "run",
      "--quiet",
      "--manifest-path",
      "./proving/Cargo.toml",
      "--bin",
      "generate-unlock-proof-json"
    ];
  const child = spawn(
    command,
    args,
    {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
      shell: false
    }
  );
  const requestJson = JSON.stringify({
    publicInputs: publicInputsToProverJson(input.publicInputs),
    philSecret: input.philSecret,
    nullifierSeed: input.nullifierSeed
  });
  let stdout = "";
  let stderr = "";
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, input.timeoutMs);

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
    if (stdout.length > 2_000_000) child.kill("SIGKILL");
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
    if (stderr.length > 20_000) child.kill("SIGKILL");
  });

  const exit = new Promise<{ readonly code: number | null; readonly signal: NodeJS.Signals | null }>(
    (resolve, reject) => {
      child.on("error", reject);
      child.on("close", (code, signal) => resolve({ code, signal }));
    }
  );
  child.stdin.end(requestJson);
  const result = await exit;
  clearTimeout(timer);

  if (timedOut) {
    throw new Error("prover timeout");
  }
  if (result.code !== 0) {
    throw new Error(`prover failed with exit code ${result.code ?? "signal"}: ${sanitizeProverError(stderr)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("prover returned malformed JSON");
  }
  if (!isRecord(parsed)
    || parsed.proofType !== UNLOCK_PROOF_TYPE
    || !isNonEmptyString(parsed.codec)
    || typeof parsed.proofBlob !== "string") {
    throw new Error("prover returned malformed proof artifact");
  }
  return {
    proofType: parsed.proofType,
    codec: parsed.codec,
    proofBlob: hexlify(parsed.proofBlob) as Hex,
    timedOut: false,
    stderr: sanitizeProverError(stderr)
  };
}

function sanitizeProverError(stderr: string): string {
  return stderr
    .replace(/0x[0-9a-fA-F]{64}/g, "0x[redacted-bytes32]")
    .replace(/philSecret|phil_secret|nullifierSeed|nullifier_seed/gi, "[redacted-witness-field]")
    .slice(0, 500);
}

export async function requestActionUnlockWitness(
  request: ActionUnlockWitnessRequest,
  auditDraftCollector?: AuditDraftCollector
): Promise<ActionUnlockWitnessRequestResult> {
  const requestShape = validateActionUnlockWitnessRequest(request);
  if (!requestShape.valid) {
    const outcome = witnessOutcomeForErrors(requestShape.errors);
    const auditEventDraft = createWitnessAuditDraft({
      request,
      outcome,
      errors: requestShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_WITNESS_MALFORMED",
      "invalid_authorization_package",
      "ACTION_UNLOCK witness request is malformed.",
      outcome,
      requestShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const draft = request.authorizationPackageDraft;
  const context = {
    requestId: request.requestId,
    authorizationPackageDraftId: draft.authorizationPackageDraftId,
    ownerCommitment: draft.binding.ownerCommitment,
    nullifier: draft.nullifierReference.nullifier,
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    auditCorrelationId: request.auditCorrelationId,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    metadata: {
      actionHash: draft.hashSummary.actionHash,
      policyHash: draft.hashSummary.policyHash,
      proofInputHash: draft.hashSummary.proofInputHash
    }
  };
  const availability = await request.provider.checkAvailability(context);
  if (!availability.available) {
    const errors = [availability.reason ?? "provider unavailable"];
    const outcome = witnessOutcomeForErrors(errors);
    const auditEventDraft = createWitnessAuditDraft({ request, outcome, errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_WITNESS_PROVIDER_UNAVAILABLE",
      "vault_unavailable",
      "ACTION_UNLOCK witness provider is unavailable.",
      outcome,
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const result = await request.provider.prepareWitnessHandle(context);
  const auditEventDraft = createWitnessAuditDraft({
    request,
    outcome: result.value ? "witness_request_created" : witnessOutcomeForErrors([
      result.error?.message ?? "witness request rejected"
    ]),
    handle: result.value?.handle,
    errors: result.error ? [result.error.message] : undefined
  });
  auditDraftCollector?.addDraft(auditEventDraft);
  if (result.status !== "approved" || !result.value) {
    return result;
  }
  return runtimeOk(freezeRecord({
    ...result.value
  }), { auditEventId: auditEventDraft.eventDraftId });
}

export async function generateActionUnlockProof(
  request: ActionUnlockProofGenerationRequest,
  consumptionStore?: EphemeralActionUnlockProofGenerationConsumptionStore,
  artifactStore?: ActionUnlockProofGenerationArtifactStore,
  auditDraftCollector?: AuditDraftCollector
): Promise<ActionUnlockProofGenerationResult> {
  const requestShape = validateActionUnlockProofGenerationRequest(request);
  if (!requestShape.valid) {
    const outcome = outcomeForErrors(requestShape.errors);
    const auditEventDraft = createProofAuditDraft({
      request,
      outcome,
      errors: requestShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_PROOF_REQUEST_MALFORMED",
      "invalid_authorization_package",
      "ACTION_UNLOCK proof generation request is malformed.",
      outcome,
      requestShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const draft = request.authorizationPackageDraft;
  if (request.expectedProofInputHash !== undefined
    && request.expectedProofInputHash !== draft.hashSummary.proofInputHash) {
    const errors = ["proofInputHash mismatch"];
    const auditEventDraft = createProofAuditDraft({
      request,
      outcome: "proof_input_hash_mismatch",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_PROOF_INPUT_HASH_MISMATCH",
      "proof_failed",
      "ACTION_UNLOCK proofInputHash did not match the expected value.",
      "proof_input_hash_mismatch",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  if (consumptionStore?.hasRequest(request.requestId)
    || consumptionStore?.hasDraft(draft.authorizationPackageDraftId)) {
    const errors = ["proof generation request or draft was already used locally"];
    const auditEventDraft = createProofAuditDraft({
      request,
      outcome: "proof_generation_replayed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_PROOF_GENERATION_REPLAYED",
      "proof_failed",
      "ACTION_UNLOCK proof generation was already requested locally.",
      "proof_generation_replayed",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const witnessRequest = await requestActionUnlockWitness({
    requestId: `${request.requestId}:witness`,
    authorizationPackageDraft: draft,
    provider: request.witnessProvider,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    auditCorrelationId: request.auditCorrelationId,
    metadata: request.metadata
  }, auditDraftCollector);
  if (witnessRequest.status !== "approved" || !witnessRequest.value) {
    const errors = [witnessRequest.error?.message ?? "witness request failed"];
    const outcome = "witness_ineligible";
    const auditEventDraft = createProofAuditDraft({ request, outcome, errors });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_WITNESS_INELIGIBLE",
      "proof_failed",
      "ACTION_UNLOCK witness request failed.",
      outcome,
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const startedAt = Date.now();
  let proverOutput: Awaited<ReturnType<typeof invokeExistingActionUnlockProver>>;
  try {
    proverOutput = await request.witnessProvider.consumeWitnessForProving(
      witnessRequest.value.handle,
      draft,
      (witness) => invokeExistingActionUnlockProver({
        publicInputs: publicInputsFromDraft(draft),
        philSecret: witness.philSecret,
        nullifierSeed: witness.nullifierSeed,
        timeoutMs: Math.max(1, Math.floor(request.timeoutMs ?? 120_000))
      })
    );
  } catch (error) {
    await request.witnessProvider.invalidateWitnessHandle(witnessRequest.value.handle);
    const message = error instanceof Error ? error.message : "prover failed";
    const outcome: ActionUnlockProofGenerationOutcome = message.includes("timeout")
      ? "prover_timeout"
      : message.includes("witness")
        ? "witness_ineligible"
        : "prover_failed";
    const auditEventDraft = createProofAuditDraft({
      request,
      outcome,
      errors: [sanitizeProverError(message)]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeFailed(proofError(
      outcome === "prover_timeout"
        ? "ACTION_UNLOCK_PROVER_TIMEOUT"
        : "ACTION_UNLOCK_PROVER_FAILED",
      "proof_failed",
      "Existing ACTION_UNLOCK prover failed.",
      outcome,
      [sanitizeProverError(message)]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const durationMs = Date.now() - startedAt;
  const proofBlob = proverOutput.proofBlob;
  const proofBytes = getBytes(proofBlob);
  const proofDigest = keccak256(proofBlob) as Hex;
  if (proverOutput.proofType !== UNLOCK_PROOF_TYPE) {
    const errors = ["proofType mismatch"];
    const auditEventDraft = createProofAuditDraft({
      request,
      outcome: "proof_type_mismatch",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_PROOF_TYPE_MISMATCH",
      "proof_failed",
      "Generated proof type did not match ACTION_UNLOCK.",
      "proof_type_mismatch",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const artifactId = createAuditCorrelationId([
    draft.authorizationPackageDraftId,
    draft.hashSummary.proofInputHash,
    proofDigest,
    "action-unlock-proof-generation"
  ]);
  const artifactBase = {
    artifactClassification: EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT,
    proofGenerationArtifactId: artifactId,
    status: "proof_generated" as const,
    outcome: "proof_generated" as const,
    proofGenerated: true as const,
    proofType: UNLOCK_PROOF_TYPE,
    binding: {
      authorizationPackageDraftId: draft.authorizationPackageDraftId,
      witnessHandleId: witnessRequest.value.handle.handleId,
      providerId: request.witnessProvider.describeProvider().providerId,
      ownerCommitment: draft.binding.ownerCommitment,
      nullifier: draft.nullifierReference.nullifier,
      proofInputHash: draft.hashSummary.proofInputHash,
      sessionId: draft.binding.sessionId,
      applicationId: draft.binding.applicationId,
      auditCorrelationId: request.auditCorrelationId
    },
    proofArtifact: {
      artifactClassification: EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT,
      proofArtifactId: artifactId,
      proofType: UNLOCK_PROOF_TYPE,
      codec: proverOutput.codec,
      proofByteLength: proofBytes.length,
      proofDigest,
      proofBlob: request.includeProofBlob === false ? undefined : proofBlob,
      proofBlobIncluded: request.includeProofBlob !== false,
      nonSecretProofArtifact: false as const,
      containsWitnessOpenings: true as const,
      safeForExternalVerifierTransmission: false as const,
      executableByAdapters: false as const
    },
    publicInputs: publicInputsFromDraft(draft),
    proofInputHash: draft.hashSummary.proofInputHash,
    summary: {
      proverUsed: "generate-unlock-proof-json",
      proverInvocation: "subprocess" as const,
      proverVersionReference: "proving/Cargo.toml::generate-unlock-proof-json",
      proverSelfCheckPerformed: false as const,
      publicInputsMatched: true as const,
      proofInputHashMatched: true as const,
      temporaryWitnessFileUsed: false as const,
      temporaryWitnessCleanupStatus: "not_required" as const,
      durationMs
    },
    limitations: [
      "proof_generation_only",
      "subprocess_boundary",
      "stdin_witness_transfer_to_existing_prover",
      "no_temporary_witness_file",
      "no_verified_fact_publication",
      "no_nullifier_consumption",
      "no_authorization_package_finalization",
      "no_adapter_execution",
      "no_transaction_submission",
      "process_local_replay_protection_only",
      "local_synthetic_research_only",
      "not_for_real_secrets",
      "proof_artifact_contains_witness_openings",
      "no_external_verifier_transmission"
    ] as const,
    proofVerifiedByRuntime: false as const,
    verifiedFactPublished: false as const,
    nullifierConsumed: false as const,
    authorizationPackageFinalized: false as const,
    adapterExecutionAllowed: false as const,
    transactionSubmitted: false as const,
    rawWitnessFieldsReturned: false as const,
    witnessRecoverableFromProof: true as const,
    witnessMaterialExposed: false as const,
    persisted: false as const
  };
  const artifact = freezeRecord(artifactBase) as ActionUnlockProofGenerationArtifact;
  const artifactShape = validateActionUnlockProofGenerationArtifact(artifact);
  if (!artifactShape.valid) {
    const auditEventDraft = createProofAuditDraft({
      request,
      outcome: "proof_artifact_malformed",
      errors: artifactShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_PROOF_ARTIFACT_MALFORMED",
      "proof_failed",
      "Generated ACTION_UNLOCK proof artifact was malformed.",
      "proof_artifact_malformed",
      artifactShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const consumed = consumptionStore?.consume({
    proofGenerationRequestId: request.requestId,
    authorizationPackageDraftId: draft.authorizationPackageDraftId,
    witnessHandleId: witnessRequest.value.handle.handleId,
    proofInputHash: draft.hashSummary.proofInputHash,
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const errors = ["proof generation request or draft was already used locally"];
    const auditEventDraft = createProofAuditDraft({
      request,
      outcome: "proof_generation_replayed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(proofError(
      "ACTION_UNLOCK_PROOF_GENERATION_REPLAYED",
      "proof_failed",
      "ACTION_UNLOCK proof generation was already requested locally.",
      "proof_generation_replayed",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const auditEventDraft = createProofAuditDraft({
    request,
    outcome: "proof_generated",
    artifact
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const collectionResult = artifactStore?.addArtifact(artifact);
  return runtimeOk(freezeRecord({
    ...artifactBase,
    auditEventDraft,
    auditDraftCollectionResult,
    collectionResult
  }) as ActionUnlockProofGenerationArtifact, {
    auditEventId: auditEventDraft.eventDraftId
  });
}

export function validateActionUnlockProofGenerationArtifact(
  artifact: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(artifact)) return validation(["proof artifact must be an object"]);
  if (!isNonEmptyString(artifact.proofGenerationArtifactId)) {
    errors.push("proofGenerationArtifactId is required");
  }
  if (artifact.status !== "proof_generated") errors.push("status must be proof_generated");
  if (artifact.artifactClassification !== EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT) {
    errors.push("artifactClassification must identify an experimental secret-bearing proof artifact");
  }
  if (artifact.outcome !== "proof_generated") errors.push("outcome must be proof_generated");
  if (artifact.proofGenerated !== true) errors.push("proofGenerated must be true");
  if (artifact.proofType !== UNLOCK_PROOF_TYPE) errors.push("proofType mismatch");
  if (!isRecord(artifact.binding)) errors.push("binding is required");
  if (!isRecord(artifact.proofArtifact)) {
    errors.push("proofArtifact is required");
  } else {
    if (artifact.proofArtifact.artifactClassification
      !== EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT) {
      errors.push("proof artifact classification mismatch");
    }
    if (!isHex32(artifact.proofArtifact.proofDigest)) errors.push("proofDigest must be bytes32");
    if (typeof artifact.proofArtifact.proofByteLength !== "number"
      || artifact.proofArtifact.proofByteLength <= 0) {
      errors.push("proofByteLength must be positive");
    }
  }
  if (artifact.rawWitnessFieldsReturned !== false) {
    errors.push("rawWitnessFieldsReturned must be false");
  }
  if (artifact.witnessRecoverableFromProof !== true) {
    errors.push("witnessRecoverableFromProof must be true");
  }
  if (!isRecord(artifact.summary)) errors.push("summary is required");
  for (const field of [
    "proofVerifiedByRuntime",
    "verifiedFactPublished",
    "nullifierConsumed",
    "authorizationPackageFinalized",
    "adapterExecutionAllowed",
    "transactionSubmitted",
    "witnessMaterialExposed",
    "persisted"
  ]) {
    if (artifact[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

export function createEphemeralActionUnlockProofGenerationConsumptionStore():
  EphemeralActionUnlockProofGenerationConsumptionStore {
  const records = new Map<string, ActionUnlockProofGenerationConsumptionRecord>();
  const draftIds = new Set<string>();
  function all() {
    return Object.freeze(Array.from(records.values()).map(freezeRecord));
  }
  return {
    consume(record) {
      if (records.has(record.proofGenerationRequestId)
        || draftIds.has(record.authorizationPackageDraftId)) {
        return freezeRecord({
          status: "replayed" as const,
          record: records.get(record.proofGenerationRequestId),
          records: all(),
          reason: "proof generation request or draft already used locally"
        });
      }
      const frozen = freezeRecord(record);
      records.set(record.proofGenerationRequestId, frozen);
      draftIds.add(record.authorizationPackageDraftId);
      return freezeRecord({ status: "consumed" as const, record: frozen, records: all() });
    },
    hasRequest(proofGenerationRequestId) {
      return records.has(proofGenerationRequestId);
    },
    hasDraft(authorizationPackageDraftId) {
      return draftIds.has(authorizationPackageDraftId);
    },
    clear() {
      records.clear();
      draftIds.clear();
      return freezeRecord({ status: "cleared" as const, records: all() });
    },
    getAll: all
  };
}

export function createInMemoryActionUnlockProofGenerationArtifactStore(
  options: InMemoryActionUnlockProofGenerationArtifactStoreOptions = {}
): ActionUnlockProofGenerationArtifactStore {
  const maxArtifactCount = Math.max(1, Math.floor(options.maxArtifactCount ?? 20));
  const artifacts = new Map<string, ActionUnlockProofGenerationArtifact>();
  function all() {
    return Object.freeze(Array.from(artifacts.values()).map(freezeRecord));
  }
  function collectionResult(input: {
    readonly status: ActionUnlockProofGenerationCollectionStatus;
    readonly artifact?: ActionUnlockProofGenerationArtifact;
    readonly reason?: string;
  }): ActionUnlockProofGenerationCollectionResult {
    return freezeRecord({
      status: input.status,
      artifact: input.artifact,
      artifacts: all(),
      count: artifacts.size,
      persisted: false as const,
      reason: input.reason
    });
  }
  return {
    addArtifact(artifact) {
      if (artifacts.has(artifact.proofGenerationArtifactId)) {
        return collectionResult({
          status: "duplicate_rejected",
          artifact: artifacts.get(artifact.proofGenerationArtifactId),
          reason: "proof generation artifact already exists"
        });
      }
      if (artifacts.size >= maxArtifactCount) {
        const oldest = artifacts.keys().next().value as string | undefined;
        if (oldest !== undefined) artifacts.delete(oldest);
      }
      const frozen = freezeRecord(artifact);
      artifacts.set(frozen.proofGenerationArtifactId, frozen);
      return collectionResult({ status: "collected", artifact: frozen });
    },
    getById(artifactId) {
      return artifacts.get(artifactId);
    },
    getAll: all,
    count() {
      return artifacts.size;
    },
    clear() {
      artifacts.clear();
      return collectionResult({ status: "cleared" });
    }
  };
}
