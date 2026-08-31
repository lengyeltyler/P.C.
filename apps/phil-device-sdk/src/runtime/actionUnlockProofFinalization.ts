import { spawn } from "node:child_process";
import { getBytes, hexlify, keccak256 } from "ethers";

import {
  UNLOCK_PROOF_SCHEMA_VERSION,
  UNLOCK_PROOF_TYPE,
  proofInputHash,
  type Hex,
  type UnlockProofPublicInputs
} from "../hashes.ts";
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
  type ActionUnlockProofGenerationArtifact,
  validateActionUnlockProofGenerationArtifact
} from "./actionUnlockProofGeneration.ts";
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

export type ActionUnlockProofVerificationStatus =
  | "proof_verified_locally"
  | "proof_verification_rejected"
  | "proof_verification_failed"
  | "proof_verification_malformed"
  | "proof_verification_replayed"
  | "proof_verification_expired";

export type ActionUnlockProofVerificationOutcome =
  | "proof_verified_locally"
  | "proof_rejected"
  | "proof_artifact_malformed"
  | "proof_type_mismatch"
  | "draft_mismatch"
  | "public_input_mismatch"
  | "proof_input_hash_mismatch"
  | "fact_shape_mismatch"
  | "verifier_unavailable"
  | "verifier_failed"
  | "verification_timeout"
  | "verification_expired"
  | "verification_replayed"
  | "malformed"
  | "unsupported";

export type ActionUnlockProofVerificationReason =
  | "local_verifier_accepted_proof"
  | "local_verifier_rejected_proof"
  | "proof_generation_artifact_missing_proof_blob"
  | "draft_and_proof_artifact_mismatch"
  | "proof_input_hash_mismatch"
  | "fact_shape_mismatch"
  | "verification_request_expired"
  | "verification_request_replayed"
  | "verifier_subprocess_failed"
  | "verifier_subprocess_timeout";

export type ActionUnlockProofVerificationRequirement =
  | "valid_authorization_package_draft"
  | "valid_action_unlock_proof_generation_artifact"
  | "bounded_proof_blob_available"
  | "local_rust_stwo_verifier"
  | "exact_public_input_correlation"
  | "exact_proof_input_hash_correlation"
  | "fact_high_low_shape";

export type ActionUnlockProofVerificationLimitation =
  | "local_verification_only"
  | "subprocess_boundary"
  | "no_on_chain_verification"
  | "no_verified_fact_publication"
  | "no_nullifier_consumption"
  | "no_adapter_execution"
  | "no_transaction_submission"
  | "process_local_replay_protection_only";

export type ActionUnlockFactShapeReference = "[fact_high, fact_low]";

export interface ActionUnlockFactShapePreview {
  readonly factShapeReference: ActionUnlockFactShapeReference;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly sourceProofInputHash: Hex;
  readonly ordering: "fact_high_then_fact_low";
  readonly factPublished: false;
  readonly onChainRegistered: false;
}

export type ActionUnlockFactPreview = ActionUnlockFactShapePreview;

export interface ActionUnlockVerifiedProofReference {
  readonly verifiedProofReferenceId: string;
  readonly proofGenerationArtifactId: string;
  readonly proofType: typeof UNLOCK_PROOF_TYPE;
  readonly proofDigest: Hex;
  readonly proofByteLength: number;
  readonly proofInputHash: Hex;
  readonly localVerificationOnly: true;
  readonly onChainVerified: false;
  readonly verifiedFactPublished: false;
}

export interface ActionUnlockProofVerificationBinding {
  readonly authorizationPackageDraftId: string;
  readonly proofGenerationArtifactId: string;
  readonly ownerCommitment: Hex;
  readonly nullifier: Hex;
  readonly proofInputHash: Hex;
  readonly proofDigest: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly auditCorrelationId: string;
}

export interface ActionUnlockProofVerificationSummary {
  readonly verifierUsed: "verify-unlock-proof-json";
  readonly verifierInvocation: "subprocess";
  readonly verifierVersionReference: string;
  readonly proofTypeMatched: true;
  readonly publicInputsMatched: true;
  readonly proofInputHashMatched: true;
  readonly factShapeValidated: true;
  readonly proofBytesLogged: false;
  readonly durationMs: number;
}

export interface ActionUnlockProofVerificationResultValue {
  readonly proofVerificationResultId: string;
  readonly status: "proof_verified_locally";
  readonly outcome: "proof_verified_locally";
  readonly proofVerifiedLocally: true;
  readonly binding: ActionUnlockProofVerificationBinding;
  readonly verifiedProofReference: ActionUnlockVerifiedProofReference;
  readonly factShapePreview: ActionUnlockFactShapePreview;
  readonly publicInputs: UnlockProofPublicInputs;
  readonly proofInputHash: Hex;
  readonly summary: ActionUnlockProofVerificationSummary;
  readonly requirements: readonly ActionUnlockProofVerificationRequirement[];
  readonly limitations: readonly ActionUnlockProofVerificationLimitation[];
  readonly proofTypeMatched: true;
  readonly publicInputsMatched: true;
  readonly proofInputHashMatched: true;
  readonly factShapeValidated: true;
  readonly verifiedFactPublished: false;
  readonly onChainVerificationPerformed: false;
  readonly nullifierConsumed: false;
  readonly adapterExecutionAllowed: false;
  readonly transactionSubmitted: false;
  readonly proofBytesExposedToAudit: false;
  readonly witnessMaterialExposed: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: ActionUnlockProofVerificationCollectionResult;
}

export interface ActionUnlockProofVerificationRequest {
  readonly requestId: string;
  readonly authorizationPackageDraft: AuthorizationPackageDraft;
  readonly proofGenerationArtifact: ActionUnlockProofGenerationArtifact;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly timeoutMs?: number;
  readonly expectedProofInputHash?: Hex;
  readonly expectedProofType?: typeof UNLOCK_PROOF_TYPE;
  readonly expectedFactShapeReference?: ActionUnlockFactShapeReference;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type ActionUnlockProofVerificationResult =
  RuntimeResult<ActionUnlockProofVerificationResultValue>;

export type FinalizedAuthorizationPackageStatus =
  | "authorization_package_finalized"
  | "authorization_package_finalization_rejected"
  | "authorization_package_finalization_malformed"
  | "authorization_package_finalization_replayed"
  | "authorization_package_finalization_expired";

export type FinalizedAuthorizationPackageOutcome =
  | "authorization_package_finalized"
  | "draft_ineligible"
  | "proof_generation_ineligible"
  | "proof_verification_ineligible"
  | "public_input_mismatch"
  | "proof_input_hash_mismatch"
  | "proof_type_mismatch"
  | "fact_shape_mismatch"
  | "evidence_expired"
  | "evidence_replayed"
  | "secret_bearing_proof_quarantined"
  | "malformed"
  | "unsupported";

export type FinalizedAuthorizationPackageReason =
  | "local_proof_verified"
  | "evidence_chain_matched"
  | "finalized_non_executing_package_created"
  | "evidence_chain_rejected"
  | "finalization_replayed"
  | "evidence_expired";

export type FinalizedAuthorizationPackageLimitation =
  | "local_finalization_only"
  | "non_executing_authorization_package"
  | "no_verified_fact_publication"
  | "no_on_chain_verification"
  | "no_nullifier_consumption"
  | "no_adapter_execution"
  | "no_contract_execution"
  | "no_transaction_submission"
  | "process_local_package_store_only"
  | "proof_artifact_contains_witness_openings"
  | "no_external_verifier_transmission";

export interface FinalizedProofArtifactReference {
  readonly proofArtifactId: string;
  readonly proofGenerationArtifactId: string;
  readonly proofVerificationResultId: string;
  readonly proofType: typeof UNLOCK_PROOF_TYPE;
  readonly proofDigest: Hex;
  readonly proofByteLength: number;
  readonly proofInputHash: Hex;
  readonly proofBlob?: Hex;
  readonly proofBlobIncluded: boolean;
  readonly proofBytesLogged: false;
  readonly nonSecretProofArtifact: boolean;
  readonly containsWitnessOpenings: boolean;
  readonly safeForExternalVerifierTransmission: boolean;
  readonly executableByAdapters: false;
}

export interface FinalizedActionUnlockAuthorization {
  readonly version: typeof UNLOCK_PROOF_SCHEMA_VERSION;
  readonly proofType: typeof UNLOCK_PROOF_TYPE;
  readonly ownerCommitment: Hex;
  readonly actionHash: Hex;
  readonly policyHash: Hex;
  readonly nullifier: Hex;
  readonly consumerDataHash: Hex;
  readonly expiry: string;
  readonly proofInputHash: Hex;
  readonly factShapeReference: ActionUnlockFactShapeReference;
}

export interface FinalizedAuthorizationPackageBinding {
  readonly authorizationPackageDraftId: string;
  readonly proofGenerationArtifactId: string;
  readonly proofVerificationResultId: string;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly intentId: string;
  readonly capabilityName: string;
  readonly ownerCommitment: Hex;
  readonly proofInputHash: Hex;
  readonly auditCorrelationId: string;
}

export interface FinalizedAuthorizationPackageEvidence {
  readonly proofGenerated: true;
  readonly proofVerifiedLocally: true;
  readonly proofTypeMatched: true;
  readonly publicInputsMatched: true;
  readonly proofInputHashMatched: true;
  readonly factShapeValidated: true;
  readonly localVerificationResultId: string;
  readonly verifiedProofReferenceId: string;
}

export interface FinalizedAuthorizationPackageValidity {
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly expired: false;
}

export interface FinalizedAuthorizationPackage {
  readonly finalizedAuthorizationPackageId: string;
  readonly status: "authorization_package_finalized";
  readonly outcome: "authorization_package_finalized";
  readonly binding: FinalizedAuthorizationPackageBinding;
  readonly actionUnlockAuthorization: FinalizedActionUnlockAuthorization;
  readonly proofArtifact: FinalizedProofArtifactReference;
  readonly evidence: FinalizedAuthorizationPackageEvidence;
  readonly factShapePreview: ActionUnlockFactShapePreview;
  readonly validity: FinalizedAuthorizationPackageValidity;
  readonly limitations: readonly FinalizedAuthorizationPackageLimitation[];
  readonly authorizationPackageFinalized: true;
  readonly proofGenerated: true;
  readonly proofVerifiedLocally: true;
  readonly verifiedFactPublished: false;
  readonly onChainVerificationPerformed: false;
  readonly nullifierConsumed: false;
  readonly adapterExecutionAllowed: false;
  readonly contractExecutionAllowed: false;
  readonly transactionSubmitted: false;
  readonly executableByApplications: false;
  /** A finalized package is valid only for a reviewed witness-hiding proof.
   * The current experimental secret-bearing artifact is rejected before this
   * object can be created. */
  readonly witnessMaterialExposed: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: FinalizedAuthorizationPackageCollectionResult;
}

export interface FinalizedAuthorizationPackageRequest {
  readonly requestId: string;
  readonly authorizationPackageDraft: AuthorizationPackageDraft;
  readonly proofGenerationArtifact: ActionUnlockProofGenerationArtifact;
  readonly proofVerificationResult: ActionUnlockProofVerificationResultValue;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly includeProofBlob?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type FinalizedAuthorizationPackageResult =
  RuntimeResult<FinalizedAuthorizationPackage>;

export interface ActionUnlockProofVerificationConsumptionRecord {
  readonly proofVerificationRequestId: string;
  readonly authorizationPackageDraftId: string;
  readonly proofGenerationArtifactId: string;
  readonly proofDigest: Hex;
  readonly proofInputHash: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export interface EphemeralActionUnlockProofVerificationConsumptionStore {
  consume(record: ActionUnlockProofVerificationConsumptionRecord): {
    readonly status: "consumed" | "replayed" | "cleared";
    readonly record?: ActionUnlockProofVerificationConsumptionRecord;
    readonly records: readonly ActionUnlockProofVerificationConsumptionRecord[];
    readonly reason?: string;
  };
  hasRequest(proofVerificationRequestId: string): boolean;
  hasProofArtifact(proofGenerationArtifactId: string): boolean;
  clear(): {
    readonly status: "cleared";
    readonly records: readonly ActionUnlockProofVerificationConsumptionRecord[];
  };
  getAll(): readonly ActionUnlockProofVerificationConsumptionRecord[];
}

export type ActionUnlockProofVerificationCollectionStatus =
  | "collected"
  | "duplicate_rejected"
  | "cleared";

export interface ActionUnlockProofVerificationCollectionResult {
  readonly status: ActionUnlockProofVerificationCollectionStatus;
  readonly verification?: ActionUnlockProofVerificationResultValue;
  readonly verifications: readonly ActionUnlockProofVerificationResultValue[];
  readonly count: number;
  readonly persisted: false;
  readonly reason?: string;
}

export interface ActionUnlockProofVerificationResultStore {
  addVerification(
    verification: ActionUnlockProofVerificationResultValue
  ): ActionUnlockProofVerificationCollectionResult;
  getById(verificationId: string): ActionUnlockProofVerificationResultValue | undefined;
  getAll(): readonly ActionUnlockProofVerificationResultValue[];
  count(): number;
  clear(): ActionUnlockProofVerificationCollectionResult;
}

export interface InMemoryActionUnlockProofVerificationResultStoreOptions {
  readonly maxVerificationCount?: number;
}

export interface FinalizedAuthorizationPackageConsumptionRecord {
  readonly finalizationRequestId: string;
  readonly authorizationPackageDraftId: string;
  readonly proofGenerationArtifactId: string;
  readonly proofVerificationResultId: string;
  readonly proofInputHash: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly auditCorrelationId: string;
  readonly consumedAt: string;
}

export interface EphemeralFinalizedAuthorizationPackageConsumptionStore {
  consume(record: FinalizedAuthorizationPackageConsumptionRecord): {
    readonly status: "consumed" | "replayed" | "cleared";
    readonly record?: FinalizedAuthorizationPackageConsumptionRecord;
    readonly records: readonly FinalizedAuthorizationPackageConsumptionRecord[];
    readonly reason?: string;
  };
  hasRequest(finalizationRequestId: string): boolean;
  hasDraft(authorizationPackageDraftId: string): boolean;
  clear(): {
    readonly status: "cleared";
    readonly records: readonly FinalizedAuthorizationPackageConsumptionRecord[];
  };
  getAll(): readonly FinalizedAuthorizationPackageConsumptionRecord[];
}

export type FinalizedAuthorizationPackageCollectionStatus =
  | "collected"
  | "duplicate_rejected"
  | "cleared";

export interface FinalizedAuthorizationPackageCollectionResult {
  readonly status: FinalizedAuthorizationPackageCollectionStatus;
  readonly package?: FinalizedAuthorizationPackage;
  readonly packages: readonly FinalizedAuthorizationPackage[];
  readonly count: number;
  readonly persisted: false;
  readonly reason?: string;
}

export interface FinalizedAuthorizationPackageStore {
  addPackage(packageValue: FinalizedAuthorizationPackage): FinalizedAuthorizationPackageCollectionResult;
  getById(packageId: string): FinalizedAuthorizationPackage | undefined;
  getAll(): readonly FinalizedAuthorizationPackage[];
  count(): number;
  clear(): FinalizedAuthorizationPackageCollectionResult;
}

export interface InMemoryFinalizedAuthorizationPackageStoreOptions {
  readonly maxPackageCount?: number;
}

export interface FutureVerifiedFactPublicationInput {
  readonly finalizedAuthorizationPackageId: string;
  readonly factShapePreview: ActionUnlockFactShapePreview;
  readonly futureOnly: true;
}

export interface FutureVerifiedFactPublicationRequest {
  readonly requestId: string;
  readonly input: FutureVerifiedFactPublicationInput;
  readonly notImplementedInM4: true;
}

export interface NullifierConsumptionRequest {
  readonly requestId: string;
  readonly finalizedAuthorizationPackageId: string;
  readonly nullifier: Hex;
  readonly notImplementedInM4: true;
}

export interface AuthorizationPackageExecutionInput {
  readonly finalizedAuthorizationPackageId: string;
  readonly notImplementedInM4: true;
}

export interface EthereumAdapterAuthorizationInput {
  readonly finalizedAuthorizationPackageId: string;
  readonly ethereumFirstExecutionPath: true;
  readonly notImplementedInM4: true;
}

export interface SmartAccountAuthorizationInput {
  readonly finalizedAuthorizationPackageId: string;
  readonly erc4337PreferredAuthorityModel: true;
  readonly notImplementedInM4: true;
}

const PROOF_VERIFICATION_STATUSES = new Set<ActionUnlockProofVerificationStatus>([
  "proof_verified_locally",
  "proof_verification_rejected",
  "proof_verification_failed",
  "proof_verification_malformed",
  "proof_verification_replayed",
  "proof_verification_expired"
]);

const FINALIZED_PACKAGE_STATUSES = new Set<FinalizedAuthorizationPackageStatus>([
  "authorization_package_finalized",
  "authorization_package_finalization_rejected",
  "authorization_package_finalization_malformed",
  "authorization_package_finalization_replayed",
  "authorization_package_finalization_expired"
]);

const FINALIZED_PACKAGE_OUTCOMES = new Set<FinalizedAuthorizationPackageOutcome>([
  "authorization_package_finalized",
  "draft_ineligible",
  "proof_generation_ineligible",
  "proof_verification_ineligible",
  "public_input_mismatch",
  "proof_input_hash_mismatch",
  "proof_type_mismatch",
  "fact_shape_mismatch",
  "evidence_expired",
  "evidence_replayed",
  "malformed",
  "unsupported"
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isHex(value: unknown): value is Hex {
  return typeof value === "string" && /^0x[0-9a-fA-F]*$/.test(value);
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
    errors: Object.freeze([...new Set(errors)])
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

function runtimeError(
  code: string,
  category: RuntimeErrorDescriptor["category"],
  message: string,
  outcome: ActionUnlockProofVerificationOutcome | FinalizedAuthorizationPackageOutcome,
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

function publicInputsFromDraft(draft: AuthorizationPackageDraft): UnlockProofPublicInputs {
  return draft.actionUnlockPublicInputDraft.publicInputs;
}

function publicInputsToVerifierJson(publicInputs: UnlockProofPublicInputs) {
  return {
    ownerCommitment: publicInputs.ownerCommitment,
    actionHash: publicInputs.actionHash,
    policyHash: publicInputs.policyHash,
    nullifier: publicInputs.nullifier,
    consumerDataHash: publicInputs.consumerDataHash,
    expiry: BigInt(publicInputs.expiry).toString()
  };
}

function publicInputsEqual(
  left: UnlockProofPublicInputs,
  right: UnlockProofPublicInputs
): boolean {
  return left.ownerCommitment === right.ownerCommitment
    && left.actionHash === right.actionHash
    && left.policyHash === right.policyHash
    && left.nullifier === right.nullifier
    && left.consumerDataHash === right.consumerDataHash
    && BigInt(left.expiry) === BigInt(right.expiry);
}

function expectedProofInputHash(draft: AuthorizationPackageDraft): Hex {
  return proofInputHash({
    version: draft.actionUnlockPublicInputDraft.version,
    proofType: draft.actionUnlockPublicInputDraft.proofType,
    publicInputs: publicInputsFromDraft(draft)
  });
}

function validateDraftForM4(draft: AuthorizationPackageDraft): readonly string[] {
  const errors: string[] = [];
  errors.push(...validateAuthorizationPackageDraftShape(draft).errors.map((error) => `draft.${error}`));
  if (draft.actionUnlockPublicInputDraft.version !== UNLOCK_PROOF_SCHEMA_VERSION) {
    errors.push("proof version mismatch");
  }
  if (draft.actionUnlockPublicInputDraft.proofType !== UNLOCK_PROOF_TYPE) {
    errors.push("proof type mismatch");
  }
  if (draft.actionUnlockPublicInputDraft.factShapeReference !== "[fact_high, fact_low]") {
    errors.push("fact shape mismatch");
  }
  if (expectedProofInputHash(draft) !== draft.hashSummary.proofInputHash
    || expectedProofInputHash(draft) !== draft.actionUnlockPublicInputDraft.proofInputHash) {
    errors.push("proofInputHash mismatch");
  }
  if (draft.nullifierConsumed !== false) errors.push("nullifier already consumed");
  if (draft.authorizationPackageExecutable !== false) errors.push("draft unexpectedly executable");
  if (expired(draft.validity.expiresAt)) errors.push("draft expired");
  return Object.freeze([...new Set(errors)]);
}

function correlationErrors(input: {
  readonly draft: AuthorizationPackageDraft;
  readonly proofGenerationArtifact: ActionUnlockProofGenerationArtifact;
  readonly expectedProofInputHash?: Hex;
  readonly expectedProofType?: typeof UNLOCK_PROOF_TYPE;
  readonly expectedFactShapeReference?: ActionUnlockFactShapeReference;
}): readonly string[] {
  const { draft, proofGenerationArtifact: artifact } = input;
  const errors: string[] = [];
  errors.push(...validateDraftForM4(draft));
  errors.push(...validateActionUnlockProofGenerationArtifact(artifact).errors.map((error) => `proofArtifact.${error}`));
  if (artifact.binding.authorizationPackageDraftId !== draft.authorizationPackageDraftId) {
    errors.push("draft mismatch");
  }
  if (artifact.binding.sessionId !== draft.binding.sessionId
    || artifact.binding.applicationId !== draft.binding.applicationId
    || artifact.binding.ownerCommitment !== draft.binding.ownerCommitment
    || artifact.binding.nullifier !== draft.nullifierReference.nullifier) {
    errors.push("draft binding mismatch");
  }
  if (artifact.proofType !== UNLOCK_PROOF_TYPE
    || artifact.proofArtifact.proofType !== UNLOCK_PROOF_TYPE
    || input.expectedProofType && input.expectedProofType !== UNLOCK_PROOF_TYPE) {
    errors.push("proof type mismatch");
  }
  if (!publicInputsEqual(artifact.publicInputs, publicInputsFromDraft(draft))) {
    errors.push("public input mismatch");
  }
  if (artifact.proofInputHash !== draft.hashSummary.proofInputHash
    || artifact.binding.proofInputHash !== draft.hashSummary.proofInputHash
    || input.expectedProofInputHash && input.expectedProofInputHash !== draft.hashSummary.proofInputHash) {
    errors.push("proofInputHash mismatch");
  }
  if (input.expectedFactShapeReference !== undefined
    && input.expectedFactShapeReference !== "[fact_high, fact_low]") {
    errors.push("fact shape mismatch");
  }
  if (artifact.proofArtifact.proofBlob === undefined) {
    errors.push("proof artifact missing bounded proof blob");
  } else {
    const digest = keccak256(artifact.proofArtifact.proofBlob) as Hex;
    if (digest !== artifact.proofArtifact.proofDigest) {
      errors.push("proof digest mismatch");
    }
    if (getBytes(artifact.proofArtifact.proofBlob).length !== artifact.proofArtifact.proofByteLength) {
      errors.push("proof byte length mismatch");
    }
  }
  if (artifact.verifiedFactPublished !== false
    || artifact.nullifierConsumed !== false
    || artifact.authorizationPackageFinalized !== false
    || artifact.adapterExecutionAllowed !== false
    || artifact.transactionSubmitted !== false
    || artifact.witnessMaterialExposed !== false) {
    errors.push("proof artifact already carries downstream authority");
  }
  return Object.freeze([...new Set(errors)]);
}

function verificationOutcomeForErrors(
  errors: readonly string[]
): ActionUnlockProofVerificationOutcome {
  if (errors.some((error) => error.includes("expired"))) return "verification_expired";
  if (errors.some((error) => error.includes("proof artifact"))) return "proof_artifact_malformed";
  if (errors.some((error) => error.includes("proof type"))) return "proof_type_mismatch";
  if (errors.some((error) => error.includes("draft"))) return "draft_mismatch";
  if (errors.some((error) => error.includes("public input"))) return "public_input_mismatch";
  if (errors.some((error) => error.includes("proofInputHash"))) return "proof_input_hash_mismatch";
  if (errors.some((error) => error.includes("fact shape"))) return "fact_shape_mismatch";
  if (errors.some((error) => error.includes("verifier"))) return "verifier_failed";
  return "malformed";
}

function finalizationOutcomeForErrors(
  errors: readonly string[]
): FinalizedAuthorizationPackageOutcome {
  if (errors.some((error) => error.includes("secret-bearing proof artifact"))) {
    return "secret_bearing_proof_quarantined";
  }
  if (errors.some((error) => error.includes("expired"))) return "evidence_expired";
  if (errors.some((error) => error.includes("proof generation"))) return "proof_generation_ineligible";
  if (errors.some((error) => error.includes("proof verification"))) return "proof_verification_ineligible";
  if (errors.some((error) => error.includes("public input"))) return "public_input_mismatch";
  if (errors.some((error) => error.includes("proofInputHash"))) return "proof_input_hash_mismatch";
  if (errors.some((error) => error.includes("proof type"))) return "proof_type_mismatch";
  if (errors.some((error) => error.includes("fact shape"))) return "fact_shape_mismatch";
  if (errors.some((error) => error.includes("draft"))) return "draft_ineligible";
  return "malformed";
}

function factPreviewFromProofInputHash(proofHash: Hex): ActionUnlockFactShapePreview {
  const normalized = proofHash.slice(2).padStart(64, "0").toLowerCase();
  return freezeRecord({
    factShapeReference: "[fact_high, fact_low]" as const,
    factHigh: `0x${normalized.slice(0, 32)}` as Hex,
    factLow: `0x${normalized.slice(32)}` as Hex,
    sourceProofInputHash: `0x${normalized}` as Hex,
    ordering: "fact_high_then_fact_low" as const,
    factPublished: false as const,
    onChainRegistered: false as const
  });
}

function sanitizeVerifierError(stderr: string): string {
  return stderr
    .replace(/0x[0-9a-fA-F]{64}/g, "0x[redacted-bytes32]")
    .replace(/philSecret|phil_secret|nullifierSeed|nullifier_seed/gi, "[redacted-witness-field]")
    .slice(0, 500);
}

async function invokeExistingActionUnlockVerifier(input: {
  readonly proofBlob: Hex;
  readonly publicInputs: UnlockProofPublicInputs;
  readonly timeoutMs: number;
}): Promise<{
  readonly verified: boolean;
  readonly proofType: string;
  readonly codec: string;
  readonly version: string;
  readonly durationMs: number;
}> {
  const startedAt = Date.now();
  const bundledVerifier = process.env.PHILCORE_ACTION_UNLOCK_VERIFIER_BIN;
  const command = bundledVerifier && bundledVerifier.length > 0 ? bundledVerifier : "cargo";
  const args = bundledVerifier && bundledVerifier.length > 0
    ? []
    : [
      "+nightly-2025-07-14",
      "run",
      "--quiet",
      "--manifest-path",
      "./proving/Cargo.toml",
      "--bin",
      "verify-unlock-proof-json"
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
    proofBlob: input.proofBlob,
    publicInputs: publicInputsToVerifierJson(input.publicInputs)
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
    if (stdout.length > 50_000) child.kill("SIGKILL");
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

  if (timedOut) throw new Error("verifier timeout");
  if (result.code !== 0) {
    throw new Error(`verifier failed with exit code ${result.code ?? "signal"}: ${sanitizeVerifierError(stderr)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("verifier returned malformed JSON");
  }
  if (!isRecord(parsed)
    || typeof parsed.verified !== "boolean"
    || parsed.proofType !== UNLOCK_PROOF_TYPE
    || !isNonEmptyString(parsed.codec)
    || !isNonEmptyString(parsed.version)) {
    throw new Error("verifier returned malformed result");
  }
  return {
    verified: parsed.verified,
    proofType: parsed.proofType,
    codec: parsed.codec,
    version: parsed.version,
    durationMs: Date.now() - startedAt
  };
}

function createVerificationAuditDraft(input: {
  readonly request: ActionUnlockProofVerificationRequest;
  readonly outcome: ActionUnlockProofVerificationOutcome;
  readonly verification?: ActionUnlockProofVerificationResultValue;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  const draft = input.request.authorizationPackageDraft;
  const artifact = input.request.proofGenerationArtifact;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.verification ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    intentId: draft.binding.intentId,
    capability: draft.binding.capabilityName,
    summary: input.verification
      ? "ACTION_UNLOCK proof verified locally; no fact publication, nullifier consumption, adapter call, or execution occurred."
      : "ACTION_UNLOCK local proof verification rejected or failed; no fact publication, nullifier consumption, adapter call, or execution occurred.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authorizationPackageDraftId: draft.authorizationPackageDraftId,
      proofGenerationArtifactId: artifact.proofGenerationArtifactId,
      proofVerificationResultId: input.verification?.proofVerificationResultId,
      proofType: UNLOCK_PROOF_TYPE,
      proofInputHash: draft.hashSummary.proofInputHash,
      proofDigest: artifact.proofArtifact.proofDigest,
      proofByteLength: artifact.proofArtifact.proofByteLength,
      factShapeReference: input.verification?.factShapePreview.factShapeReference
        ?? "[fact_high, fact_low]",
      verifierUsed: "verify-unlock-proof-json",
      outcome: input.outcome,
      proofBytesLogged: false,
      witnessMaterialExposed: false,
      verifiedFactPublished: false,
      onChainVerificationPerformed: false,
      nullifierConsumed: false,
      adapterExecutionAllowed: false,
      transactionSubmitted: false,
      errors: input.errors ?? []
    }
  });
}

function createFinalizationAuditDraft(input: {
  readonly request: FinalizedAuthorizationPackageRequest;
  readonly outcome: FinalizedAuthorizationPackageOutcome;
  readonly packageValue?: FinalizedAuthorizationPackage;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  const draft = input.request.authorizationPackageDraft;
  const artifact = input.request.proofGenerationArtifact;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.packageValue ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    intentId: draft.binding.intentId,
    capability: draft.binding.capabilityName,
    summary: input.packageValue
      ? "Finalized non-executing ACTION_UNLOCK Authorization Package created; no fact publication, nullifier consumption, adapter call, contract call, or transaction occurred."
      : "ACTION_UNLOCK Authorization Package finalization rejected; no fact publication, nullifier consumption, adapter call, contract call, or transaction occurred.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      authorizationPackageDraftId: draft.authorizationPackageDraftId,
      proofGenerationArtifactId: artifact.proofGenerationArtifactId,
      proofVerificationResultId: input.request.proofVerificationResult.proofVerificationResultId,
      finalizedAuthorizationPackageId: input.packageValue?.finalizedAuthorizationPackageId,
      proofType: UNLOCK_PROOF_TYPE,
      proofInputHash: draft.hashSummary.proofInputHash,
      proofDigest: artifact.proofArtifact.proofDigest,
      factShapeReference: input.request.proofVerificationResult.factShapePreview.factShapeReference,
      outcome: input.outcome,
      authorizationPackageFinalized: input.packageValue?.authorizationPackageFinalized ?? false,
      executableByApplications: false,
      proofBytesLogged: false,
      witnessMaterialExposed: false,
      verifiedFactPublished: false,
      onChainVerificationPerformed: false,
      nullifierConsumed: false,
      adapterExecutionAllowed: false,
      contractExecutionAllowed: false,
      transactionSubmitted: false,
      errors: input.errors ?? []
    }
  });
}

export function validateActionUnlockProofVerificationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["proof verification request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.authorizationPackageDraft)) {
    errors.push("authorizationPackageDraft is required");
  }
  if (!isRecord(request.proofGenerationArtifact)) {
    errors.push("proofGenerationArtifact is required");
  }
  if (isRecord(request.authorizationPackageDraft) && isRecord(request.proofGenerationArtifact)) {
    errors.push(...correlationErrors({
      draft: request.authorizationPackageDraft as unknown as AuthorizationPackageDraft,
      proofGenerationArtifact:
        request.proofGenerationArtifact as unknown as ActionUnlockProofGenerationArtifact,
      expectedProofInputHash: request.expectedProofInputHash as Hex | undefined,
      expectedProofType: request.expectedProofType as typeof UNLOCK_PROOF_TYPE | undefined,
      expectedFactShapeReference:
        request.expectedFactShapeReference as ActionUnlockFactShapeReference | undefined
    }));
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a date string");
  if (hasValidDateShape(request.expiresAt) && expired(request.expiresAt)) {
    errors.push("verification request expired");
  }
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (isRecord(request.metadata)) errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  return validation(errors);
}

export function validateFinalizedAuthorizationPackageRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["finalized package request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.authorizationPackageDraft)) errors.push("authorizationPackageDraft is required");
  if (!isRecord(request.proofGenerationArtifact)) errors.push("proofGenerationArtifact is required");
  if (!isRecord(request.proofVerificationResult)) errors.push("proofVerificationResult is required");
  if (isRecord(request.authorizationPackageDraft) && isRecord(request.proofGenerationArtifact)) {
    errors.push(...correlationErrors({
      draft: request.authorizationPackageDraft as unknown as AuthorizationPackageDraft,
      proofGenerationArtifact:
        request.proofGenerationArtifact as unknown as ActionUnlockProofGenerationArtifact
    }));
    // The only generation artifact supported by this release is the explicitly
    // quarantined, witness-recoverable research artifact. A future witness-hiding
    // artifact needs a separate reviewed type and finalization implementation.
    errors.push("experimental secret-bearing proof artifact cannot be finalized");
  }
  if (isRecord(request.proofVerificationResult)) {
    const verification = request.proofVerificationResult as unknown as ActionUnlockProofVerificationResultValue;
    if (verification.status !== "proof_verified_locally"
      || verification.outcome !== "proof_verified_locally"
      || verification.proofVerifiedLocally !== true) {
      errors.push("proof verification ineligible");
    }
  }
  if (isRecord(request.authorizationPackageDraft)
    && isRecord(request.proofGenerationArtifact)
    && isRecord(request.proofVerificationResult)) {
    const draft = request.authorizationPackageDraft as unknown as AuthorizationPackageDraft;
    const artifact = request.proofGenerationArtifact as unknown as ActionUnlockProofGenerationArtifact;
    const verification = request.proofVerificationResult as unknown as ActionUnlockProofVerificationResultValue;
    if (verification.binding.authorizationPackageDraftId !== draft.authorizationPackageDraftId
      || verification.binding.proofGenerationArtifactId !== artifact.proofGenerationArtifactId
      || verification.binding.proofInputHash !== draft.hashSummary.proofInputHash
      || verification.binding.proofDigest !== artifact.proofArtifact.proofDigest
      || !publicInputsEqual(verification.publicInputs, publicInputsFromDraft(draft))) {
      errors.push("evidence chain mismatch");
    }
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a date string");
  if (hasValidDateShape(request.expiresAt) && expired(request.expiresAt)) {
    errors.push("finalized package request expired");
  }
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (isRecord(request.metadata)) errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  return validation(errors);
}

export function isActionUnlockProofVerificationStatus(
  value: unknown
): value is ActionUnlockProofVerificationStatus {
  return PROOF_VERIFICATION_STATUSES.has(value as ActionUnlockProofVerificationStatus);
}

export function isFinalizedAuthorizationPackageStatus(
  value: unknown
): value is FinalizedAuthorizationPackageStatus {
  return FINALIZED_PACKAGE_STATUSES.has(value as FinalizedAuthorizationPackageStatus);
}

export function isFinalizedAuthorizationPackageOutcome(
  value: unknown
): value is FinalizedAuthorizationPackageOutcome {
  return FINALIZED_PACKAGE_OUTCOMES.has(value as FinalizedAuthorizationPackageOutcome);
}

export async function verifyGeneratedActionUnlockProof(
  request: ActionUnlockProofVerificationRequest,
  consumptionStore?: EphemeralActionUnlockProofVerificationConsumptionStore,
  verificationStore?: ActionUnlockProofVerificationResultStore,
  auditDraftCollector?: AuditDraftCollector
): Promise<ActionUnlockProofVerificationResult> {
  const requestShape = validateActionUnlockProofVerificationRequest(request);
  if (!requestShape.valid) {
    const outcome = verificationOutcomeForErrors(requestShape.errors);
    const auditEventDraft = createVerificationAuditDraft({
      request,
      outcome,
      errors: requestShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "ACTION_UNLOCK_PROOF_VERIFICATION_REQUEST_MALFORMED",
      "invalid_authorization_package",
      "ACTION_UNLOCK proof verification request is malformed.",
      outcome,
      requestShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const draft = request.authorizationPackageDraft;
  const artifact = request.proofGenerationArtifact;
  if (consumptionStore?.hasRequest(request.requestId)
    || consumptionStore?.hasProofArtifact(artifact.proofGenerationArtifactId)) {
    const errors = ["proof verification request or artifact was already used locally"];
    const auditEventDraft = createVerificationAuditDraft({
      request,
      outcome: "verification_replayed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "ACTION_UNLOCK_PROOF_VERIFICATION_REPLAYED",
      "proof_failed",
      "ACTION_UNLOCK proof verification was already requested locally.",
      "verification_replayed",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  let verifierResult: Awaited<ReturnType<typeof invokeExistingActionUnlockVerifier>>;
  try {
    verifierResult = await invokeExistingActionUnlockVerifier({
      proofBlob: artifact.proofArtifact.proofBlob as Hex,
      publicInputs: publicInputsFromDraft(draft),
      timeoutMs: Math.max(1, Math.floor(request.timeoutMs ?? 120_000))
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "verifier failed";
    const outcome: ActionUnlockProofVerificationOutcome = message.includes("timeout")
      ? "verification_timeout"
      : "verifier_failed";
    const auditEventDraft = createVerificationAuditDraft({
      request,
      outcome,
      errors: [sanitizeVerifierError(message)]
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeFailed(runtimeError(
      outcome === "verification_timeout"
        ? "ACTION_UNLOCK_VERIFIER_TIMEOUT"
        : "ACTION_UNLOCK_VERIFIER_FAILED",
      "proof_failed",
      "Existing ACTION_UNLOCK verifier failed.",
      outcome,
      [sanitizeVerifierError(message)]
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  if (!verifierResult.verified) {
    const errors = ["local verifier rejected proof"];
    const auditEventDraft = createVerificationAuditDraft({
      request,
      outcome: "proof_rejected",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "ACTION_UNLOCK_PROOF_REJECTED",
      "proof_failed",
      "Local ACTION_UNLOCK verifier rejected the proof.",
      "proof_rejected",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const factShapePreview = factPreviewFromProofInputHash(draft.hashSummary.proofInputHash);
  const proofVerificationResultId = createAuditCorrelationId([
    draft.authorizationPackageDraftId,
    artifact.proofGenerationArtifactId,
    artifact.proofArtifact.proofDigest,
    "action-unlock-proof-verification"
  ]);
  const verificationBase = {
    proofVerificationResultId,
    status: "proof_verified_locally" as const,
    outcome: "proof_verified_locally" as const,
    proofVerifiedLocally: true as const,
    binding: {
      authorizationPackageDraftId: draft.authorizationPackageDraftId,
      proofGenerationArtifactId: artifact.proofGenerationArtifactId,
      ownerCommitment: draft.binding.ownerCommitment,
      nullifier: draft.nullifierReference.nullifier,
      proofInputHash: draft.hashSummary.proofInputHash,
      proofDigest: artifact.proofArtifact.proofDigest,
      sessionId: draft.binding.sessionId,
      applicationId: draft.binding.applicationId,
      auditCorrelationId: request.auditCorrelationId
    },
    verifiedProofReference: {
      verifiedProofReferenceId: proofVerificationResultId,
      proofGenerationArtifactId: artifact.proofGenerationArtifactId,
      proofType: UNLOCK_PROOF_TYPE,
      proofDigest: artifact.proofArtifact.proofDigest,
      proofByteLength: artifact.proofArtifact.proofByteLength,
      proofInputHash: draft.hashSummary.proofInputHash,
      localVerificationOnly: true as const,
      onChainVerified: false as const,
      verifiedFactPublished: false as const
    },
    factShapePreview,
    publicInputs: publicInputsFromDraft(draft),
    proofInputHash: draft.hashSummary.proofInputHash,
    summary: {
      verifierUsed: "verify-unlock-proof-json" as const,
      verifierInvocation: "subprocess" as const,
      verifierVersionReference: `proving/Cargo.toml::verify-unlock-proof-json:${verifierResult.version}`,
      proofTypeMatched: true as const,
      publicInputsMatched: true as const,
      proofInputHashMatched: true as const,
      factShapeValidated: true as const,
      proofBytesLogged: false as const,
      durationMs: verifierResult.durationMs
    },
    requirements: [
      "valid_authorization_package_draft",
      "valid_action_unlock_proof_generation_artifact",
      "bounded_proof_blob_available",
      "local_rust_stwo_verifier",
      "exact_public_input_correlation",
      "exact_proof_input_hash_correlation",
      "fact_high_low_shape"
    ] as const,
    limitations: [
      "local_verification_only",
      "subprocess_boundary",
      "no_on_chain_verification",
      "no_verified_fact_publication",
      "no_nullifier_consumption",
      "no_adapter_execution",
      "no_transaction_submission",
      "process_local_replay_protection_only"
    ] as const,
    proofTypeMatched: true as const,
    publicInputsMatched: true as const,
    proofInputHashMatched: true as const,
    factShapeValidated: true as const,
    verifiedFactPublished: false as const,
    onChainVerificationPerformed: false as const,
    nullifierConsumed: false as const,
    adapterExecutionAllowed: false as const,
    transactionSubmitted: false as const,
    proofBytesExposedToAudit: false as const,
    witnessMaterialExposed: false as const,
    persisted: false as const
  };

  const consumed = consumptionStore?.consume({
    proofVerificationRequestId: request.requestId,
    authorizationPackageDraftId: draft.authorizationPackageDraftId,
    proofGenerationArtifactId: artifact.proofGenerationArtifactId,
    proofDigest: artifact.proofArtifact.proofDigest,
    proofInputHash: draft.hashSummary.proofInputHash,
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const errors = ["proof verification request or artifact was already used locally"];
    const auditEventDraft = createVerificationAuditDraft({
      request,
      outcome: "verification_replayed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "ACTION_UNLOCK_PROOF_VERIFICATION_REPLAYED",
      "proof_failed",
      "ACTION_UNLOCK proof verification was already requested locally.",
      "verification_replayed",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const verification = freezeRecord(verificationBase) as ActionUnlockProofVerificationResultValue;
  const auditEventDraft = createVerificationAuditDraft({
    request,
    outcome: "proof_verified_locally",
    verification
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const collectionResult = verificationStore?.addVerification(verification);
  return runtimeOk(freezeRecord({
    ...verificationBase,
    auditEventDraft,
    auditDraftCollectionResult,
    collectionResult
  }) as ActionUnlockProofVerificationResultValue, {
    auditEventId: auditEventDraft.eventDraftId
  });
}

export function finalizeAuthorizationPackage(
  request: FinalizedAuthorizationPackageRequest,
  consumptionStore?: EphemeralFinalizedAuthorizationPackageConsumptionStore,
  packageStore?: FinalizedAuthorizationPackageStore,
  auditDraftCollector?: AuditDraftCollector
): FinalizedAuthorizationPackageResult {
  const requestShape = validateFinalizedAuthorizationPackageRequest(request);
  if (!requestShape.valid) {
    const outcome = finalizationOutcomeForErrors(requestShape.errors);
    const auditEventDraft = createFinalizationAuditDraft({
      request,
      outcome,
      errors: requestShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "FINALIZED_AUTHORIZATION_PACKAGE_REQUEST_MALFORMED",
      "invalid_authorization_package",
      "Finalized Authorization Package request is malformed.",
      outcome,
      requestShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const draft = request.authorizationPackageDraft;
  const artifact = request.proofGenerationArtifact;
  const verification = request.proofVerificationResult;
  if (consumptionStore?.hasRequest(request.requestId)
    || consumptionStore?.hasDraft(draft.authorizationPackageDraftId)) {
    const errors = ["finalization request or draft was already used locally"];
    const auditEventDraft = createFinalizationAuditDraft({
      request,
      outcome: "evidence_replayed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "FINALIZED_AUTHORIZATION_PACKAGE_REPLAYED",
      "invalid_authorization_package",
      "Finalized Authorization Package request was already used locally.",
      "evidence_replayed",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const packageId = createAuditCorrelationId([
    draft.authorizationPackageDraftId,
    artifact.proofGenerationArtifactId,
    verification.proofVerificationResultId,
    "finalized-authorization-package"
  ]);
  const publicInputs = publicInputsFromDraft(draft);
  const packageBase = {
    finalizedAuthorizationPackageId: packageId,
    status: "authorization_package_finalized" as const,
    outcome: "authorization_package_finalized" as const,
    binding: {
      authorizationPackageDraftId: draft.authorizationPackageDraftId,
      proofGenerationArtifactId: artifact.proofGenerationArtifactId,
      proofVerificationResultId: verification.proofVerificationResultId,
      sessionId: draft.binding.sessionId,
      applicationId: draft.binding.applicationId,
      intentId: draft.binding.intentId,
      capabilityName: draft.binding.capabilityName,
      ownerCommitment: draft.binding.ownerCommitment,
      proofInputHash: draft.hashSummary.proofInputHash,
      auditCorrelationId: request.auditCorrelationId
    },
    actionUnlockAuthorization: {
      version: UNLOCK_PROOF_SCHEMA_VERSION,
      proofType: UNLOCK_PROOF_TYPE,
      ownerCommitment: publicInputs.ownerCommitment,
      actionHash: publicInputs.actionHash,
      policyHash: publicInputs.policyHash,
      nullifier: publicInputs.nullifier,
      consumerDataHash: publicInputs.consumerDataHash,
      expiry: BigInt(publicInputs.expiry).toString(),
      proofInputHash: draft.hashSummary.proofInputHash,
      factShapeReference: "[fact_high, fact_low]" as const
    },
    proofArtifact: {
      proofArtifactId: artifact.proofArtifact.proofArtifactId,
      proofGenerationArtifactId: artifact.proofGenerationArtifactId,
      proofVerificationResultId: verification.proofVerificationResultId,
      proofType: UNLOCK_PROOF_TYPE,
      proofDigest: artifact.proofArtifact.proofDigest,
      proofByteLength: artifact.proofArtifact.proofByteLength,
      proofInputHash: draft.hashSummary.proofInputHash,
      proofBlob: request.includeProofBlob === true ? artifact.proofArtifact.proofBlob : undefined,
      proofBlobIncluded: request.includeProofBlob === true,
      proofBytesLogged: false as const,
      nonSecretProofArtifact: false as const,
      containsWitnessOpenings: true as const,
      safeForExternalVerifierTransmission: false as const,
      executableByAdapters: false as const
    },
    evidence: {
      proofGenerated: true as const,
      proofVerifiedLocally: true as const,
      proofTypeMatched: true as const,
      publicInputsMatched: true as const,
      proofInputHashMatched: true as const,
      factShapeValidated: true as const,
      localVerificationResultId: verification.proofVerificationResultId,
      verifiedProofReferenceId: verification.verifiedProofReference.verifiedProofReferenceId
    },
    factShapePreview: verification.factShapePreview,
    validity: {
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      expired: false as const
    },
    limitations: [
      "local_finalization_only",
      "non_executing_authorization_package",
      "no_verified_fact_publication",
      "no_on_chain_verification",
      "no_nullifier_consumption",
      "no_adapter_execution",
      "no_contract_execution",
      "no_transaction_submission",
      "process_local_package_store_only",
      "proof_artifact_contains_witness_openings",
      "no_external_verifier_transmission"
    ] as const,
    authorizationPackageFinalized: true as const,
    proofGenerated: true as const,
    proofVerifiedLocally: true as const,
    verifiedFactPublished: false as const,
    onChainVerificationPerformed: false as const,
    nullifierConsumed: false as const,
    adapterExecutionAllowed: false as const,
    contractExecutionAllowed: false as const,
    transactionSubmitted: false as const,
    executableByApplications: false as const,
    witnessMaterialExposed: false as const,
    persisted: false as const
  };

  const packageValue = freezeRecord(packageBase) as FinalizedAuthorizationPackage;
  const packageShape = validateFinalizedAuthorizationPackageShape(packageValue);
  if (!packageShape.valid) {
    const outcome = finalizationOutcomeForErrors(packageShape.errors);
    const auditEventDraft = createFinalizationAuditDraft({
      request,
      outcome,
      errors: packageShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "FINALIZED_AUTHORIZATION_PACKAGE_MALFORMED",
      "invalid_authorization_package",
      "Finalized Authorization Package shape is malformed.",
      outcome,
      packageShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const consumed = consumptionStore?.consume({
    finalizationRequestId: request.requestId,
    authorizationPackageDraftId: draft.authorizationPackageDraftId,
    proofGenerationArtifactId: artifact.proofGenerationArtifactId,
    proofVerificationResultId: verification.proofVerificationResultId,
    proofInputHash: draft.hashSummary.proofInputHash,
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    auditCorrelationId: request.auditCorrelationId,
    consumedAt: new Date().toISOString()
  });
  if (consumed?.status === "replayed") {
    const errors = ["finalization request or draft was already used locally"];
    const auditEventDraft = createFinalizationAuditDraft({
      request,
      outcome: "evidence_replayed",
      errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "FINALIZED_AUTHORIZATION_PACKAGE_REPLAYED",
      "invalid_authorization_package",
      "Finalized Authorization Package request was already used locally.",
      "evidence_replayed",
      errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const auditEventDraft = createFinalizationAuditDraft({
    request,
    outcome: "authorization_package_finalized",
    packageValue
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const collectionResult = packageStore?.addPackage(packageValue);
  return runtimeOk(freezeRecord({
    ...packageBase,
    auditEventDraft,
    auditDraftCollectionResult,
    collectionResult
  }) as FinalizedAuthorizationPackage, {
    auditEventId: auditEventDraft.eventDraftId
  });
}

export function validateActionUnlockProofVerificationResult(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) return validation(["proof verification result must be an object"]);
  if (!isNonEmptyString(result.proofVerificationResultId)) {
    errors.push("proofVerificationResultId is required");
  }
  if (result.status !== "proof_verified_locally") errors.push("status must be proof_verified_locally");
  if (result.outcome !== "proof_verified_locally") errors.push("outcome must be proof_verified_locally");
  if (result.proofVerifiedLocally !== true) errors.push("proofVerifiedLocally must be true");
  if (!isRecord(result.binding)) errors.push("binding is required");
  if (!isRecord(result.verifiedProofReference)) errors.push("verifiedProofReference is required");
  if (!isRecord(result.factShapePreview)) {
    errors.push("factShapePreview is required");
  } else {
    if (result.factShapePreview.factShapeReference !== "[fact_high, fact_low]") {
      errors.push("fact shape mismatch");
    }
    if (!isHex(result.factShapePreview.factHigh)
      || !isHex(result.factShapePreview.factLow)) {
      errors.push("fact preview values must be hex");
    }
  }
  for (const field of [
    "verifiedFactPublished",
    "onChainVerificationPerformed",
    "nullifierConsumed",
    "adapterExecutionAllowed",
    "transactionSubmitted",
    "proofBytesExposedToAudit",
    "witnessMaterialExposed",
    "persisted"
  ]) {
    if (result[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

export function validateFinalizedAuthorizationPackageShape(
  packageValue: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(packageValue)) return validation(["finalized package must be an object"]);
  if (!isNonEmptyString(packageValue.finalizedAuthorizationPackageId)) {
    errors.push("finalizedAuthorizationPackageId is required");
  }
  if (packageValue.status !== "authorization_package_finalized") {
    errors.push("status must be authorization_package_finalized");
  }
  if (packageValue.outcome !== "authorization_package_finalized") {
    errors.push("outcome must be authorization_package_finalized");
  }
  if (!isRecord(packageValue.binding)) errors.push("binding is required");
  if (!isRecord(packageValue.actionUnlockAuthorization)) {
    errors.push("actionUnlockAuthorization is required");
  } else {
    if (packageValue.actionUnlockAuthorization.proofType !== UNLOCK_PROOF_TYPE) {
      errors.push("proof type mismatch");
    }
    if (packageValue.actionUnlockAuthorization.factShapeReference !== "[fact_high, fact_low]") {
      errors.push("fact shape mismatch");
    }
    if (!isHex32(packageValue.actionUnlockAuthorization.proofInputHash)) {
      errors.push("proofInputHash must be bytes32");
    }
  }
  if (!isRecord(packageValue.proofArtifact)) errors.push("proofArtifact is required");
  else if (packageValue.proofArtifact.nonSecretProofArtifact !== true
    || packageValue.proofArtifact.containsWitnessOpenings !== false
    || packageValue.proofArtifact.safeForExternalVerifierTransmission !== true
    || packageValue.proofArtifact.proofBlobIncluded === true
    || packageValue.proofArtifact.proofBlob !== undefined) {
    errors.push("finalized package requires a non-secret witness-hiding proof reference without proof bytes");
  }
  if (!isRecord(packageValue.evidence)) errors.push("evidence is required");
  if (!isRecord(packageValue.factShapePreview)) errors.push("factShapePreview is required");
  if (!isRecord(packageValue.validity)) errors.push("validity is required");
  for (const field of [
    "authorizationPackageFinalized",
    "proofGenerated",
    "proofVerifiedLocally"
  ]) {
    if (packageValue[field] !== true) errors.push(`${field} must be true`);
  }
  for (const field of [
    "verifiedFactPublished",
    "onChainVerificationPerformed",
    "nullifierConsumed",
    "adapterExecutionAllowed",
    "contractExecutionAllowed",
    "transactionSubmitted",
    "executableByApplications",
    "witnessMaterialExposed",
    "persisted"
  ]) {
    if (packageValue[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

export function createEphemeralActionUnlockProofVerificationConsumptionStore():
EphemeralActionUnlockProofVerificationConsumptionStore {
  const records = new Map<string, ActionUnlockProofVerificationConsumptionRecord>();
  return {
    consume(record) {
      if (records.has(`request:${record.proofVerificationRequestId}`)
        || records.has(`artifact:${record.proofGenerationArtifactId}`)) {
        return freezeRecord({
          status: "replayed" as const,
          records: Array.from(records.values()),
          reason: "proof verification request or artifact already consumed locally"
        });
      }
      records.set(`request:${record.proofVerificationRequestId}`, record);
      records.set(`artifact:${record.proofGenerationArtifactId}`, record);
      return freezeRecord({
        status: "consumed" as const,
        record,
        records: Array.from(new Set(records.values()))
      });
    },
    hasRequest(proofVerificationRequestId) {
      return records.has(`request:${proofVerificationRequestId}`);
    },
    hasProofArtifact(proofGenerationArtifactId) {
      return records.has(`artifact:${proofGenerationArtifactId}`);
    },
    clear() {
      records.clear();
      return freezeRecord({
        status: "cleared" as const,
        records: []
      });
    },
    getAll() {
      return freezeRecord(Array.from(new Set(records.values())));
    }
  };
}

export function createInMemoryActionUnlockProofVerificationResultStore(
  options: InMemoryActionUnlockProofVerificationResultStoreOptions = {}
): ActionUnlockProofVerificationResultStore {
  const maxCount = Math.max(1, Math.floor(options.maxVerificationCount ?? 100));
  const verifications = new Map<string, ActionUnlockProofVerificationResultValue>();
  function collection(
    status: ActionUnlockProofVerificationCollectionStatus,
    verification?: ActionUnlockProofVerificationResultValue,
    reason?: string
  ): ActionUnlockProofVerificationCollectionResult {
    return freezeRecord({
      status,
      verification,
      verifications: Array.from(verifications.values()),
      count: verifications.size,
      persisted: false as const,
      reason
    });
  }
  return {
    addVerification(verification) {
      if (verifications.has(verification.proofVerificationResultId)) {
        return collection("duplicate_rejected", verification, "duplicate proof verification result id");
      }
      while (verifications.size >= maxCount) {
        const oldest = verifications.keys().next().value;
        if (oldest === undefined) break;
        verifications.delete(oldest);
      }
      verifications.set(verification.proofVerificationResultId, freezeRecord(verification));
      return collection("collected", verification);
    },
    getById(verificationId) {
      const value = verifications.get(verificationId);
      return value ? freezeRecord(value) : undefined;
    },
    getAll() {
      return freezeRecord(Array.from(verifications.values()));
    },
    count() {
      return verifications.size;
    },
    clear() {
      verifications.clear();
      return collection("cleared");
    }
  };
}

export function createEphemeralFinalizedAuthorizationPackageConsumptionStore():
EphemeralFinalizedAuthorizationPackageConsumptionStore {
  const records = new Map<string, FinalizedAuthorizationPackageConsumptionRecord>();
  return {
    consume(record) {
      if (records.has(`request:${record.finalizationRequestId}`)
        || records.has(`draft:${record.authorizationPackageDraftId}`)) {
        return freezeRecord({
          status: "replayed" as const,
          records: Array.from(records.values()),
          reason: "finalization request or draft already consumed locally"
        });
      }
      records.set(`request:${record.finalizationRequestId}`, record);
      records.set(`draft:${record.authorizationPackageDraftId}`, record);
      return freezeRecord({
        status: "consumed" as const,
        record,
        records: Array.from(new Set(records.values()))
      });
    },
    hasRequest(finalizationRequestId) {
      return records.has(`request:${finalizationRequestId}`);
    },
    hasDraft(authorizationPackageDraftId) {
      return records.has(`draft:${authorizationPackageDraftId}`);
    },
    clear() {
      records.clear();
      return freezeRecord({
        status: "cleared" as const,
        records: []
      });
    },
    getAll() {
      return freezeRecord(Array.from(new Set(records.values())));
    }
  };
}

export function createInMemoryFinalizedAuthorizationPackageStore(
  options: InMemoryFinalizedAuthorizationPackageStoreOptions = {}
): FinalizedAuthorizationPackageStore {
  const maxCount = Math.max(1, Math.floor(options.maxPackageCount ?? 100));
  const packages = new Map<string, FinalizedAuthorizationPackage>();
  function collection(
    status: FinalizedAuthorizationPackageCollectionStatus,
    packageValue?: FinalizedAuthorizationPackage,
    reason?: string
  ): FinalizedAuthorizationPackageCollectionResult {
    return freezeRecord({
      status,
      package: packageValue,
      packages: Array.from(packages.values()),
      count: packages.size,
      persisted: false as const,
      reason
    });
  }
  return {
    addPackage(packageValue) {
      if (packages.has(packageValue.finalizedAuthorizationPackageId)) {
        return collection("duplicate_rejected", packageValue, "duplicate finalized package id");
      }
      while (packages.size >= maxCount) {
        const oldest = packages.keys().next().value;
        if (oldest === undefined) break;
        packages.delete(oldest);
      }
      packages.set(packageValue.finalizedAuthorizationPackageId, freezeRecord(packageValue));
      return collection("collected", packageValue);
    },
    getById(packageId) {
      const value = packages.get(packageId);
      return value ? freezeRecord(value) : undefined;
    },
    getAll() {
      return freezeRecord(Array.from(packages.values()));
    },
    count() {
      return packages.size;
    },
    clear() {
      packages.clear();
      return collection("cleared");
    }
  };
}
