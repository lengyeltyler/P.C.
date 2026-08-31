import {
  UNLOCK_PROOF_TYPE,
  type Hex
} from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  type FinalizedAuthorizationPackage,
  validateFinalizedAuthorizationPackageShape
} from "./actionUnlockProofFinalization.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { validateNoSensitiveMetadataKeys } from "./redaction.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult
} from "./types.ts";

export type VerifiedFactPublicationRequestStatus =
  | "publication_request_created"
  | "publication_request_rejected"
  | "publication_request_malformed"
  | "publication_request_expired";

export type VerifiedFactPublicationRequestOutcome =
  | "publication_request_created"
  | "package_ineligible"
  | "proof_verification_ineligible"
  | "fact_shape_invalid"
  | "fact_already_published"
  | "fact_state_unknown"
  | "nullifier_already_consumed"
  | "nullifier_state_unknown"
  | "chain_configuration_invalid"
  | "verifier_configuration_invalid"
  | "registry_configuration_invalid"
  | "consumer_configuration_invalid"
  | "network_mismatch"
  | "package_expired"
  | "correlation_mismatch"
  | "malformed"
  | "unsupported";

export type VerifiedFactPublicationRequestReason =
  | "finalized_package_accepted"
  | "fact_pair_bound"
  | "target_configuration_bound"
  | "package_rejected"
  | "configuration_rejected"
  | "state_reader_blocked";

export type VerifiedFactPublicationRequirement =
  | "valid_finalized_authorization_package"
  | "ethereum_base_chain_profile"
  | "verified_local_action_unlock_proof"
  | "fact_high_low_shape"
  | "read_only_fact_state_check"
  | "read_only_nullifier_state_check"
  | "freshness_revalidation_before_execution";

export type VerifiedFactPublicationLimitation =
  | "publication_request_only"
  | "no_fact_publication"
  | "no_contract_call"
  | "no_nullifier_consumption"
  | "no_adapter_execution"
  | "no_user_operation"
  | "read_only_state_snapshot"
  | "race_condition_requires_revalidation";

export interface AuthorizationExecutionChainProfile {
  readonly chainId: 8453;
  readonly network: "base";
  readonly profileId: "ethereum-base";
  readonly adapterId: "ethereum";
  readonly ethereumFirstExecutionPath: true;
}

export interface AuthorizationVerifierConfiguration {
  readonly verifierReference: string;
  readonly verifierAddress?: Hex;
  readonly contractInterfaceVersion: string;
  readonly expectedProofType: typeof UNLOCK_PROOF_TYPE;
  readonly expectedFactShape: "[fact_high, fact_low]";
}

export interface AuthorizationFactRegistryConfiguration {
  readonly registryReference: string;
  readonly registryAddress?: Hex;
  readonly contractInterfaceVersion: string;
  readonly expectedFactShape: "[fact_high, fact_low]";
}

export interface AuthorizationConsumerConfiguration {
  readonly consumerReference: string;
  readonly consumerAddress?: Hex;
  readonly smartAccountReference: string;
  readonly expectedNullifierConsumption: "future_execution_consumes_nullifier";
}

export interface AuthorizationSmartAccountConfiguration {
  readonly smartAccountReference: string;
  readonly smartAccountAddress?: Hex;
  readonly authorityModel: "erc4337_smart_account";
  readonly requiresPhilCoreAuthorization: true;
}

export interface AuthorizationBundlerConfigurationReference {
  readonly bundlerReference: string;
  readonly optional: true;
  readonly contactedInM5: false;
}

export interface AuthorizationPaymasterConfigurationReference {
  readonly paymasterReference: string;
  readonly optional: true;
  readonly contactedInM5: false;
}

export interface VerifiedFactVerifierReference {
  readonly verifierReference: string;
  readonly verifierAddress?: Hex;
  readonly proofType: typeof UNLOCK_PROOF_TYPE;
}

export interface VerifiedFactRegistryReference {
  readonly registryReference: string;
  readonly registryAddress?: Hex;
  readonly factShapeReference: "[fact_high, fact_low]";
}

export interface VerifiedFactConsumerReference {
  readonly consumerReference: string;
  readonly consumerAddress?: Hex;
  readonly smartAccountReference: string;
}

export interface VerifiedFactPublicationTarget {
  readonly chainProfile: AuthorizationExecutionChainProfile;
  readonly verifier: VerifiedFactVerifierReference;
  readonly registry: VerifiedFactRegistryReference;
  readonly consumer: VerifiedFactConsumerReference;
  readonly smartAccount: AuthorizationSmartAccountConfiguration;
  readonly bundler?: AuthorizationBundlerConfigurationReference;
  readonly paymaster?: AuthorizationPaymasterConfigurationReference;
}

export interface VerifiedFactPublicationBinding {
  readonly finalizedAuthorizationPackageId: string;
  readonly authorizationPackageDraftId: string;
  readonly proofGenerationArtifactId: string;
  readonly proofVerificationResultId: string;
  readonly proofInputHash: Hex;
  readonly proofDigest: Hex;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly nullifier: Hex;
  readonly sessionId: string;
  readonly applicationId: ApplicationId;
  readonly ownerCommitment: Hex;
  readonly actionHash: Hex;
  readonly auditCorrelationId: string;
}

export interface VerifiedFactPublicationEvidence {
  readonly packageFinalized: true;
  readonly proofVerifiedLocally: true;
  readonly proofTypeMatched: true;
  readonly factShapeMatched: true;
  readonly proofInputHashMatched: true;
  readonly localVerificationResultId: string;
}

export interface VerifiedFactPublicationValidity {
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly expired: false;
}

export interface VerifiedFactPublicationPayloadDraft {
  readonly proofType: typeof UNLOCK_PROOF_TYPE;
  readonly proofArtifactId: string;
  readonly proofDigest: Hex;
  readonly proofInputHash: Hex;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly ownerCommitment: Hex;
  readonly publicNullifier: Hex;
  readonly finalizedAuthorizationPackageId: string;
  readonly verifierReference: string;
  readonly registryReference: string;
  readonly expiry: string;
  readonly auditCorrelationId: string;
  readonly proofBytesIncluded: false;
  readonly executableCalldataIncluded: false;
}

export interface VerifiedFactPublicationRequestDraft {
  readonly verifiedFactPublicationRequestDraftId: string;
  readonly status: "publication_request_created";
  readonly outcome: "publication_request_created";
  readonly binding: VerifiedFactPublicationBinding;
  readonly target: VerifiedFactPublicationTarget;
  readonly payloadDraft: VerifiedFactPublicationPayloadDraft;
  readonly evidence: VerifiedFactPublicationEvidence;
  readonly validity: VerifiedFactPublicationValidity;
  readonly requirements: readonly VerifiedFactPublicationRequirement[];
  readonly limitations: readonly VerifiedFactPublicationLimitation[];
  readonly factPublished: false;
  readonly nullifierConsumed: false;
  readonly contractCalled: false;
  readonly userOperationCreated: false;
  readonly transactionSigned: false;
  readonly transactionSubmitted: false;
  readonly adapterExecuted: false;
  readonly chainStateMutated: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: VerifiedFactPublicationRequestDraftCollectionResult;
}

export interface VerifiedFactPublicationRequest {
  readonly requestId: string;
  readonly finalizedAuthorizationPackage: FinalizedAuthorizationPackage;
  readonly target: VerifiedFactPublicationTarget;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly expectedChainId?: 8453;
  readonly expectedNetwork?: "base";
  readonly expectedProofInputHash?: Hex;
  readonly expectedFactHigh?: Hex;
  readonly expectedFactLow?: Hex;
  readonly expectedNullifier?: Hex;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export type VerifiedFactPublicationRequestResult =
  RuntimeResult<VerifiedFactPublicationRequestDraft>;

export type VerifiedFactState =
  | "fact_not_published"
  | "fact_already_published"
  | "fact_state_unknown"
  | "reader_unavailable"
  | "configuration_mismatch";

export interface VerifiedFactStateReadRequest {
  readonly requestId: string;
  readonly publicationRequestDraft: VerifiedFactPublicationRequestDraft;
  readonly target: VerifiedFactPublicationTarget;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly proofInputHash: Hex;
  readonly auditCorrelationId: string;
}

export interface VerifiedFactStateReadResult {
  readonly status: VerifiedFactState;
  readonly source: "fixture" | "read_only_rpc" | "unavailable";
  readonly checkedAt: string;
  readonly blockReference?: string;
  readonly freshnessWindowMs?: number;
  readonly contractCalled: false;
  readonly chainStateMutated: false;
  readonly error?: string;
}

export interface VerifiedFactStateReader {
  readFactState(request: VerifiedFactStateReadRequest): Promise<VerifiedFactStateReadResult> | VerifiedFactStateReadResult;
}

export type AuthorizationNullifierState =
  | "nullifier_available"
  | "nullifier_already_consumed"
  | "nullifier_state_unknown"
  | "reader_unavailable"
  | "configuration_mismatch";

export interface AuthorizationNullifierStateReadRequest {
  readonly requestId: string;
  readonly publicationRequestDraft: VerifiedFactPublicationRequestDraft;
  readonly target: VerifiedFactPublicationTarget;
  readonly nullifier: Hex;
  readonly proofInputHash: Hex;
  readonly auditCorrelationId: string;
}

export interface AuthorizationNullifierStateReadResult {
  readonly status: AuthorizationNullifierState;
  readonly source: "fixture" | "read_only_rpc" | "unavailable";
  readonly checkedAt: string;
  readonly blockReference?: string;
  readonly freshnessWindowMs?: number;
  readonly nullifierReserved: false;
  readonly nullifierConsumed: false;
  readonly contractCalled: false;
  readonly chainStateMutated: false;
  readonly error?: string;
}

export interface AuthorizationNullifierStateReader {
  readNullifierState(
    request: AuthorizationNullifierStateReadRequest
  ): Promise<AuthorizationNullifierStateReadResult> | AuthorizationNullifierStateReadResult;
}

export type AuthorizationExecutionReadinessStatus =
  | "ready_for_future_execution_preparation"
  | "readiness_blocked"
  | "readiness_malformed"
  | "readiness_expired";

export type AuthorizationExecutionReadinessOutcome =
  | "ready_for_fact_publication_review"
  | "ready_for_future_execution_preparation"
  | "package_ineligible"
  | "fact_already_published"
  | "nullifier_already_consumed"
  | "fact_state_unresolved"
  | "nullifier_state_unresolved"
  | "configuration_invalid"
  | "package_expired"
  | "session_ineligible"
  | "network_mismatch"
  | "additional_approval_required"
  | "malformed"
  | "unsupported";

export type AuthorizationExecutionReadinessReason =
  | "package_and_configuration_valid"
  | "fact_state_clear"
  | "nullifier_state_clear"
  | "readiness_snapshot_created"
  | "package_rejected"
  | "state_reader_blocked"
  | "configuration_rejected"
  | "freshness_revalidation_required";

export type AuthorizationExecutionReadinessRequirement =
  | VerifiedFactPublicationRequirement
  | "future_publisher_revalidates_fact_state"
  | "future_executor_revalidates_nullifier_state"
  | "future_adapter_remains_downstream";

export type AuthorizationExecutionReadinessLimitation =
  | VerifiedFactPublicationLimitation
  | "not_execution_authority"
  | "not_transaction_authority"
  | "state_may_change_after_read"
  | "future_revalidation_required";

export interface AuthorizationExecutionReadinessBinding extends VerifiedFactPublicationBinding {
  readonly verifiedFactPublicationRequestDraftId: string;
  readonly chainId: 8453;
  readonly network: "base";
  readonly verifierReference: string;
  readonly registryReference: string;
  readonly consumerReference: string;
  readonly smartAccountReference: string;
}

export interface AuthorizationExecutionReadinessSummary {
  readonly factState: VerifiedFactState;
  readonly nullifierState: AuthorizationNullifierState;
  readonly factCheckedAt: string;
  readonly nullifierCheckedAt: string;
  readonly factBlockReference?: string;
  readonly nullifierBlockReference?: string;
  readonly freshnessWindowMs?: number;
  readonly raceConditionWarning: "read_only_snapshot_must_be_revalidated_before_execution";
  readonly revalidationRequiredBeforeTransaction: true;
  readonly executionPreparationAllowedNow: false;
}

export interface AuthorizationExecutionReadinessRequest {
  readonly requestId: string;
  readonly publicationRequestDraft: VerifiedFactPublicationRequestDraft;
  readonly factStateReader: VerifiedFactStateReader;
  readonly nullifierStateReader: AuthorizationNullifierStateReader;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly auditCorrelationId: string;
  readonly expectedChainId?: 8453;
  readonly expectedNetwork?: "base";
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface AuthorizationExecutionReadinessResultValue {
  readonly authorizationExecutionReadinessResultId: string;
  readonly status: "ready_for_future_execution_preparation";
  readonly outcome: "ready_for_future_execution_preparation";
  readonly binding: AuthorizationExecutionReadinessBinding;
  readonly publicationRequestDraft: VerifiedFactPublicationRequestDraft;
  readonly factStateRead: VerifiedFactStateReadResult;
  readonly nullifierStateRead: AuthorizationNullifierStateReadResult;
  readonly summary: AuthorizationExecutionReadinessSummary;
  readonly requirements: readonly AuthorizationExecutionReadinessRequirement[];
  readonly limitations: readonly AuthorizationExecutionReadinessLimitation[];
  readonly factPublished: false;
  readonly nullifierConsumed: false;
  readonly contractCalled: false;
  readonly userOperationCreated: false;
  readonly transactionSigned: false;
  readonly transactionSubmitted: false;
  readonly adapterExecuted: false;
  readonly chainStateMutated: false;
  readonly persisted: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: AuthorizationExecutionReadinessResultCollectionResult;
}

export type AuthorizationExecutionReadinessResult =
  RuntimeResult<AuthorizationExecutionReadinessResultValue>;

export type VerifiedFactPublicationRequestDraftCollectionStatus =
  | "collected"
  | "duplicate_rejected"
  | "cleared";

export interface VerifiedFactPublicationRequestDraftCollectionResult {
  readonly status: VerifiedFactPublicationRequestDraftCollectionStatus;
  readonly draft?: VerifiedFactPublicationRequestDraft;
  readonly drafts: readonly VerifiedFactPublicationRequestDraft[];
  readonly count: number;
  readonly persisted: false;
  readonly reason?: string;
}

export interface VerifiedFactPublicationRequestDraftStore {
  addDraft(draft: VerifiedFactPublicationRequestDraft): VerifiedFactPublicationRequestDraftCollectionResult;
  getById(draftId: string): VerifiedFactPublicationRequestDraft | undefined;
  getAll(): readonly VerifiedFactPublicationRequestDraft[];
  count(): number;
  clear(): VerifiedFactPublicationRequestDraftCollectionResult;
}

export interface InMemoryVerifiedFactPublicationRequestDraftStoreOptions {
  readonly maxDraftCount?: number;
}

export type AuthorizationExecutionReadinessResultCollectionStatus =
  | "collected"
  | "duplicate_rejected"
  | "cleared";

export interface AuthorizationExecutionReadinessResultCollectionResult {
  readonly status: AuthorizationExecutionReadinessResultCollectionStatus;
  readonly result?: AuthorizationExecutionReadinessResultValue;
  readonly results: readonly AuthorizationExecutionReadinessResultValue[];
  readonly count: number;
  readonly persisted: false;
  readonly reason?: string;
}

export interface AuthorizationExecutionReadinessResultStore {
  addResult(result: AuthorizationExecutionReadinessResultValue): AuthorizationExecutionReadinessResultCollectionResult;
  getById(resultId: string): AuthorizationExecutionReadinessResultValue | undefined;
  getAll(): readonly AuthorizationExecutionReadinessResultValue[];
  count(): number;
  clear(): AuthorizationExecutionReadinessResultCollectionResult;
}

export interface InMemoryAuthorizationExecutionReadinessResultStoreOptions {
  readonly maxResultCount?: number;
}

export interface VerifiedFactPublisher {
  readonly notImplementedInM5: true;
  publishVerifiedFact(input: unknown): never;
}

export interface AuthorizationNullifierConsumer {
  readonly notImplementedInM5: true;
  consumeNullifier(input: unknown): never;
}

export interface SmartAccountUserOperationPreparationInput {
  readonly finalizedAuthorizationPackageId: string;
  readonly readinessResultId: string;
  readonly requiresIndependentRevalidation: true;
  readonly notImplementedInM5: true;
}

export interface EthereumAuthorizationExecutionPreparer {
  readonly notImplementedInM5: true;
  prepareExecution(input: SmartAccountUserOperationPreparationInput): never;
}

export interface EthereumAdapterFinalizedAuthorizationInput {
  readonly finalizedAuthorizationPackageId: string;
  readonly readinessResultId?: string;
  readonly readinessIsNotAuthority: true;
  readonly notImplementedInM5: true;
}

const READINESS_STATUSES = new Set<AuthorizationExecutionReadinessStatus>([
  "ready_for_future_execution_preparation",
  "readiness_blocked",
  "readiness_malformed",
  "readiness_expired"
]);

const READINESS_OUTCOMES = new Set<AuthorizationExecutionReadinessOutcome>([
  "ready_for_fact_publication_review",
  "ready_for_future_execution_preparation",
  "package_ineligible",
  "fact_already_published",
  "nullifier_already_consumed",
  "fact_state_unresolved",
  "nullifier_state_unresolved",
  "configuration_invalid",
  "package_expired",
  "session_ineligible",
  "network_mismatch",
  "additional_approval_required",
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
  outcome: VerifiedFactPublicationRequestOutcome | AuthorizationExecutionReadinessOutcome,
  errors: readonly string[]
): RuntimeErrorDescriptor {
  return {
    code,
    category,
    message,
    recoverable: false,
    details: { outcome, errors }
  };
}

function publicationOutcomeForErrors(
  errors: readonly string[]
): VerifiedFactPublicationRequestOutcome {
  if (errors.some((error) => error.includes("expired"))) return "package_expired";
  if (errors.some((error) => error.includes("proof verification"))) return "proof_verification_ineligible";
  if (errors.some((error) => error.includes("fact shape"))) return "fact_shape_invalid";
  if (errors.some((error) => error.includes("network") || error.includes("chain"))) return "network_mismatch";
  if (errors.some((error) => error.includes("verifier"))) return "verifier_configuration_invalid";
  if (errors.some((error) => error.includes("registry"))) return "registry_configuration_invalid";
  if (errors.some((error) => error.includes("consumer") || error.includes("smart account"))) return "consumer_configuration_invalid";
  if (errors.some((error) => error.includes("correlation") || error.includes("mismatch"))) return "correlation_mismatch";
  if (errors.some((error) => error.includes("package"))) return "package_ineligible";
  return "malformed";
}

function readinessOutcomeForErrors(
  errors: readonly string[]
): AuthorizationExecutionReadinessOutcome {
  if (errors.some((error) => error.includes("expired"))) return "package_expired";
  if (errors.some((error) => error.includes("network") || error.includes("configuration"))) return "configuration_invalid";
  if (errors.some((error) => error.includes("fact already"))) return "fact_already_published";
  if (errors.some((error) => error.includes("nullifier already"))) return "nullifier_already_consumed";
  if (errors.some((error) => error.includes("fact state"))) return "fact_state_unresolved";
  if (errors.some((error) => error.includes("nullifier state"))) return "nullifier_state_unresolved";
  if (errors.some((error) => error.includes("package"))) return "package_ineligible";
  return "malformed";
}

function targetErrors(target: VerifiedFactPublicationTarget | undefined): readonly string[] {
  const errors: string[] = [];
  if (!target) return ["target is required"];
  if (target.chainProfile.chainId !== 8453) errors.push("chain ID mismatch");
  if (target.chainProfile.network !== "base") errors.push("network mismatch");
  if (target.chainProfile.profileId !== "ethereum-base") errors.push("chain profile mismatch");
  if (target.chainProfile.adapterId !== "ethereum") errors.push("adapter profile mismatch");
  if (!isNonEmptyString(target.verifier.verifierReference)) errors.push("verifier reference required");
  if (target.verifier.proofType !== UNLOCK_PROOF_TYPE) errors.push("verifier proof type mismatch");
  if (!isNonEmptyString(target.registry.registryReference)) errors.push("registry reference required");
  if (target.registry.factShapeReference !== "[fact_high, fact_low]") {
    errors.push("registry fact shape mismatch");
  }
  if (!isNonEmptyString(target.consumer.consumerReference)) errors.push("consumer reference required");
  if (!isNonEmptyString(target.consumer.smartAccountReference)) {
    errors.push("consumer smart account reference required");
  }
  if (target.smartAccount.authorityModel !== "erc4337_smart_account"
    || target.smartAccount.requiresPhilCoreAuthorization !== true) {
    errors.push("smart account configuration invalid");
  }
  return Object.freeze(errors);
}

function packageErrors(packageValue: FinalizedAuthorizationPackage): readonly string[] {
  const errors: string[] = [];
  errors.push(...validateFinalizedAuthorizationPackageShape(packageValue).errors.map((error) => `package.${error}`));
  if (packageValue.proofVerifiedLocally !== true) errors.push("proof verification ineligible");
  if (packageValue.actionUnlockAuthorization.proofType !== UNLOCK_PROOF_TYPE) {
    errors.push("proof type mismatch");
  }
  if (packageValue.actionUnlockAuthorization.factShapeReference !== "[fact_high, fact_low]"
    || packageValue.factShapePreview.factShapeReference !== "[fact_high, fact_low]") {
    errors.push("fact shape mismatch");
  }
  if (packageValue.factShapePreview.sourceProofInputHash
    !== packageValue.actionUnlockAuthorization.proofInputHash) {
    errors.push("fact/proofInputHash correlation mismatch");
  }
  if (packageValue.binding.proofInputHash
    !== packageValue.actionUnlockAuthorization.proofInputHash
    || packageValue.proofArtifact.proofInputHash
    !== packageValue.actionUnlockAuthorization.proofInputHash) {
    errors.push("proofInputHash correlation mismatch");
  }
  if (packageValue.actionUnlockAuthorization.nullifier === undefined
    || !isHex32(packageValue.actionUnlockAuthorization.nullifier)) {
    errors.push("public nullifier invalid");
  }
  if (packageValue.verifiedFactPublished !== false
    || packageValue.nullifierConsumed !== false
    || packageValue.adapterExecutionAllowed !== false
    || packageValue.contractExecutionAllowed !== false
    || packageValue.transactionSubmitted !== false
    || packageValue.executableByApplications !== false
    || packageValue.persisted !== false) {
    errors.push("package carries downstream authority");
  }
  if (expired(packageValue.validity.expiresAt)) errors.push("package expired");
  return Object.freeze([...new Set(errors)]);
}

function createPublicationAuditDraft(input: {
  readonly request: VerifiedFactPublicationRequest;
  readonly outcome: VerifiedFactPublicationRequestOutcome;
  readonly draft?: VerifiedFactPublicationRequestDraft;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  const packageValue = input.request.finalizedAuthorizationPackage;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.draft ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: packageValue.binding.sessionId,
    applicationId: packageValue.binding.applicationId,
    intentId: packageValue.binding.intentId,
    capability: packageValue.binding.capabilityName,
    summary: input.draft
      ? "Verified-fact publication request draft created; no contract call, fact publication, nullifier consumption, adapter call, or transaction occurred."
      : "Verified-fact publication request rejected; no contract call, fact publication, nullifier consumption, adapter call, or transaction occurred.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      finalizedAuthorizationPackageId: packageValue.finalizedAuthorizationPackageId,
      proofDigest: packageValue.proofArtifact.proofDigest,
      proofInputHash: packageValue.actionUnlockAuthorization.proofInputHash,
      factHigh: packageValue.factShapePreview.factHigh,
      factLow: packageValue.factShapePreview.factLow,
      publicNullifier: packageValue.actionUnlockAuthorization.nullifier,
      chainId: input.request.target.chainProfile.chainId,
      network: input.request.target.chainProfile.network,
      verifierReference: input.request.target.verifier.verifierReference,
      registryReference: input.request.target.registry.registryReference,
      consumerReference: input.request.target.consumer.consumerReference,
      outcome: input.outcome,
      factPublished: false,
      nullifierConsumed: false,
      contractCalled: false,
      userOperationCreated: false,
      transactionSubmitted: false,
      adapterExecuted: false,
      chainStateMutated: false,
      errors: input.errors ?? []
    }
  });
}

function createReadinessAuditDraft(input: {
  readonly request: AuthorizationExecutionReadinessRequest;
  readonly outcome: AuthorizationExecutionReadinessOutcome;
  readonly result?: AuthorizationExecutionReadinessResultValue;
  readonly factStateRead?: VerifiedFactStateReadResult;
  readonly nullifierStateRead?: AuthorizationNullifierStateReadResult;
  readonly errors?: readonly string[];
}): AuditEventDraft {
  const draft = input.request.publicationRequestDraft;
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.result ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: draft.binding.sessionId,
    applicationId: draft.binding.applicationId,
    summary: input.result
      ? "Authorization execution readiness snapshot created; no fact publication, nullifier consumption, contract call, UserOperation, adapter call, or transaction occurred."
      : "Authorization execution readiness blocked; no fact publication, nullifier consumption, contract call, UserOperation, adapter call, or transaction occurred.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      verifiedFactPublicationRequestDraftId: draft.verifiedFactPublicationRequestDraftId,
      finalizedAuthorizationPackageId: draft.binding.finalizedAuthorizationPackageId,
      proofDigest: draft.binding.proofDigest,
      proofInputHash: draft.binding.proofInputHash,
      factHigh: draft.binding.factHigh,
      factLow: draft.binding.factLow,
      publicNullifier: draft.binding.nullifier,
      factState: input.factStateRead?.status,
      nullifierState: input.nullifierStateRead?.status,
      factBlockReference: input.factStateRead?.blockReference,
      nullifierBlockReference: input.nullifierStateRead?.blockReference,
      outcome: input.outcome,
      factPublished: false,
      nullifierConsumed: false,
      contractCalled: false,
      userOperationCreated: false,
      transactionSubmitted: false,
      adapterExecuted: false,
      chainStateMutated: false,
      errors: input.errors ?? []
    }
  });
}

export function validateVerifiedFactPublicationRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["publication request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.finalizedAuthorizationPackage)) {
    errors.push("finalized package is required");
  } else {
    errors.push(...packageErrors(request.finalizedAuthorizationPackage as unknown as FinalizedAuthorizationPackage));
  }
  if (!isRecord(request.target)) {
    errors.push("target is required");
  } else {
    errors.push(...targetErrors(request.target as unknown as VerifiedFactPublicationTarget));
  }
  if (isRecord(request.finalizedAuthorizationPackage)) {
    const packageValue = request.finalizedAuthorizationPackage as unknown as FinalizedAuthorizationPackage;
    if (request.expectedProofInputHash !== undefined
      && request.expectedProofInputHash !== packageValue.actionUnlockAuthorization.proofInputHash) {
      errors.push("proofInputHash mismatch");
    }
    if (request.expectedFactHigh !== undefined
      && request.expectedFactHigh !== packageValue.factShapePreview.factHigh) {
      errors.push("fact high mismatch");
    }
    if (request.expectedFactLow !== undefined
      && request.expectedFactLow !== packageValue.factShapePreview.factLow) {
      errors.push("fact low mismatch");
    }
    if (request.expectedNullifier !== undefined
      && request.expectedNullifier !== packageValue.actionUnlockAuthorization.nullifier) {
      errors.push("nullifier mismatch");
    }
  }
  if (request.expectedChainId !== undefined && request.expectedChainId !== 8453) {
    errors.push("chain ID mismatch");
  }
  if (request.expectedNetwork !== undefined && request.expectedNetwork !== "base") {
    errors.push("network mismatch");
  }
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a date string");
  if (hasValidDateShape(request.expiresAt) && expired(request.expiresAt)) {
    errors.push("publication request expired");
  }
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (isRecord(request.metadata)) errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  return validation(errors);
}

export function createVerifiedFactPublicationRequestDraft(
  request: VerifiedFactPublicationRequest,
  draftStore?: VerifiedFactPublicationRequestDraftStore,
  auditDraftCollector?: AuditDraftCollector
): VerifiedFactPublicationRequestResult {
  const requestShape = validateVerifiedFactPublicationRequest(request);
  if (!requestShape.valid) {
    const outcome = publicationOutcomeForErrors(requestShape.errors);
    const auditEventDraft = createPublicationAuditDraft({
      request,
      outcome,
      errors: requestShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "VERIFIED_FACT_PUBLICATION_REQUEST_MALFORMED",
      "invalid_authorization_package",
      "Verified-fact publication request is malformed or ineligible.",
      outcome,
      requestShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const packageValue = request.finalizedAuthorizationPackage;
  const draftId = createAuditCorrelationId([
    packageValue.finalizedAuthorizationPackageId,
    packageValue.proofArtifact.proofDigest,
    packageValue.actionUnlockAuthorization.proofInputHash,
    "verified-fact-publication-request-draft"
  ]);
  const binding: VerifiedFactPublicationBinding = freezeRecord({
    finalizedAuthorizationPackageId: packageValue.finalizedAuthorizationPackageId,
    authorizationPackageDraftId: packageValue.binding.authorizationPackageDraftId,
    proofGenerationArtifactId: packageValue.binding.proofGenerationArtifactId,
    proofVerificationResultId: packageValue.binding.proofVerificationResultId,
    proofInputHash: packageValue.actionUnlockAuthorization.proofInputHash,
    proofDigest: packageValue.proofArtifact.proofDigest,
    factHigh: packageValue.factShapePreview.factHigh,
    factLow: packageValue.factShapePreview.factLow,
    nullifier: packageValue.actionUnlockAuthorization.nullifier,
    sessionId: packageValue.binding.sessionId,
    applicationId: packageValue.binding.applicationId,
    ownerCommitment: packageValue.actionUnlockAuthorization.ownerCommitment,
    actionHash: packageValue.actionUnlockAuthorization.actionHash,
    auditCorrelationId: request.auditCorrelationId
  });
  const draftBase = {
    verifiedFactPublicationRequestDraftId: draftId,
    status: "publication_request_created" as const,
    outcome: "publication_request_created" as const,
    binding,
    target: request.target,
    payloadDraft: {
      proofType: UNLOCK_PROOF_TYPE,
      proofArtifactId: packageValue.proofArtifact.proofArtifactId,
      proofDigest: packageValue.proofArtifact.proofDigest,
      proofInputHash: packageValue.actionUnlockAuthorization.proofInputHash,
      factHigh: packageValue.factShapePreview.factHigh,
      factLow: packageValue.factShapePreview.factLow,
      ownerCommitment: packageValue.actionUnlockAuthorization.ownerCommitment,
      publicNullifier: packageValue.actionUnlockAuthorization.nullifier,
      finalizedAuthorizationPackageId: packageValue.finalizedAuthorizationPackageId,
      verifierReference: request.target.verifier.verifierReference,
      registryReference: request.target.registry.registryReference,
      expiry: packageValue.actionUnlockAuthorization.expiry,
      auditCorrelationId: request.auditCorrelationId,
      proofBytesIncluded: false as const,
      executableCalldataIncluded: false as const
    },
    evidence: {
      packageFinalized: true as const,
      proofVerifiedLocally: true as const,
      proofTypeMatched: true as const,
      factShapeMatched: true as const,
      proofInputHashMatched: true as const,
      localVerificationResultId: packageValue.binding.proofVerificationResultId
    },
    validity: {
      issuedAt: request.issuedAt,
      expiresAt: request.expiresAt,
      expired: false as const
    },
    requirements: [
      "valid_finalized_authorization_package",
      "ethereum_base_chain_profile",
      "verified_local_action_unlock_proof",
      "fact_high_low_shape",
      "read_only_fact_state_check",
      "read_only_nullifier_state_check",
      "freshness_revalidation_before_execution"
    ] as const,
    limitations: [
      "publication_request_only",
      "no_fact_publication",
      "no_contract_call",
      "no_nullifier_consumption",
      "no_adapter_execution",
      "no_user_operation",
      "read_only_state_snapshot",
      "race_condition_requires_revalidation"
    ] as const,
    factPublished: false as const,
    nullifierConsumed: false as const,
    contractCalled: false as const,
    userOperationCreated: false as const,
    transactionSigned: false as const,
    transactionSubmitted: false as const,
    adapterExecuted: false as const,
    chainStateMutated: false as const,
    persisted: false as const
  };
  const draft = freezeRecord(draftBase) as VerifiedFactPublicationRequestDraft;
  const auditEventDraft = createPublicationAuditDraft({
    request,
    outcome: "publication_request_created",
    draft
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const collectionResult = draftStore?.addDraft(draft);
  return runtimeOk(freezeRecord({
    ...draftBase,
    auditEventDraft,
    auditDraftCollectionResult,
    collectionResult
  }) as VerifiedFactPublicationRequestDraft, {
    auditEventId: auditEventDraft.eventDraftId
  });
}

export function validateAuthorizationExecutionReadinessRequest(
  request: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(request)) return validation(["readiness request must be an object"]);
  if (!isNonEmptyString(request.requestId)) errors.push("requestId is required");
  if (!isRecord(request.publicationRequestDraft)) {
    errors.push("publicationRequestDraft is required");
  } else {
    const draft = request.publicationRequestDraft as unknown as VerifiedFactPublicationRequestDraft;
    if (draft.status !== "publication_request_created") errors.push("publication request draft invalid");
    if (draft.factPublished !== false || draft.nullifierConsumed !== false
      || draft.contractCalled !== false || draft.userOperationCreated !== false
      || draft.transactionSubmitted !== false || draft.adapterExecuted !== false
      || draft.chainStateMutated !== false) {
      errors.push("publication request draft carries downstream authority");
    }
    if (expired(draft.validity.expiresAt)) errors.push("publication request draft expired");
    if (draft.target.chainProfile.chainId !== 8453 || draft.target.chainProfile.network !== "base") {
      errors.push("network mismatch");
    }
  }
  if (!isRecord(request.factStateReader)) errors.push("factStateReader is required");
  if (!isRecord(request.nullifierStateReader)) errors.push("nullifierStateReader is required");
  if (!hasValidDateShape(request.issuedAt)) errors.push("issuedAt must be a date string");
  if (!hasValidDateShape(request.expiresAt)) errors.push("expiresAt must be a date string");
  if (hasValidDateShape(request.expiresAt) && expired(request.expiresAt)) {
    errors.push("readiness request expired");
  }
  if (request.expectedChainId !== undefined && request.expectedChainId !== 8453) {
    errors.push("chain ID mismatch");
  }
  if (request.expectedNetwork !== undefined && request.expectedNetwork !== "base") {
    errors.push("network mismatch");
  }
  if (!isNonEmptyString(request.auditCorrelationId)) errors.push("auditCorrelationId is required");
  if (isRecord(request.metadata)) errors.push(...validateNoSensitiveMetadataKeys(request.metadata).errors);
  return validation(errors);
}

function readStateErrors(input: {
  readonly factStateRead: VerifiedFactStateReadResult;
  readonly nullifierStateRead: AuthorizationNullifierStateReadResult;
}): readonly string[] {
  const errors: string[] = [];
  if (input.factStateRead.status === "fact_already_published") errors.push("fact already published");
  if (input.factStateRead.status === "fact_state_unknown") errors.push("fact state unknown");
  if (input.factStateRead.status === "reader_unavailable") errors.push("fact state reader unavailable");
  if (input.factStateRead.status === "configuration_mismatch") errors.push("fact state configuration mismatch");
  if (input.nullifierStateRead.status === "nullifier_already_consumed") {
    errors.push("nullifier already consumed");
  }
  if (input.nullifierStateRead.status === "nullifier_state_unknown") errors.push("nullifier state unknown");
  if (input.nullifierStateRead.status === "reader_unavailable") {
    errors.push("nullifier state reader unavailable");
  }
  if (input.nullifierStateRead.status === "configuration_mismatch") {
    errors.push("nullifier state configuration mismatch");
  }
  if (input.factStateRead.contractCalled !== false
    || input.factStateRead.chainStateMutated !== false
    || input.nullifierStateRead.contractCalled !== false
    || input.nullifierStateRead.chainStateMutated !== false
    || input.nullifierStateRead.nullifierReserved !== false
    || input.nullifierStateRead.nullifierConsumed !== false) {
    errors.push("state reader attempted mutation");
  }
  return Object.freeze(errors);
}

export async function evaluateAuthorizationExecutionReadiness(
  request: AuthorizationExecutionReadinessRequest,
  resultStore?: AuthorizationExecutionReadinessResultStore,
  auditDraftCollector?: AuditDraftCollector
): Promise<AuthorizationExecutionReadinessResult> {
  const requestShape = validateAuthorizationExecutionReadinessRequest(request);
  if (!requestShape.valid) {
    const outcome = readinessOutcomeForErrors(requestShape.errors);
    const auditEventDraft = createReadinessAuditDraft({
      request,
      outcome,
      errors: requestShape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "AUTHORIZATION_EXECUTION_READINESS_REQUEST_MALFORMED",
      "invalid_authorization_package",
      "Authorization execution readiness request is malformed or ineligible.",
      outcome,
      requestShape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const draft = request.publicationRequestDraft;
  const factStateRead = await request.factStateReader.readFactState({
    requestId: `${request.requestId}:fact-state`,
    publicationRequestDraft: draft,
    target: draft.target,
    factHigh: draft.binding.factHigh,
    factLow: draft.binding.factLow,
    proofInputHash: draft.binding.proofInputHash,
    auditCorrelationId: request.auditCorrelationId
  });
  const nullifierStateRead = await request.nullifierStateReader.readNullifierState({
    requestId: `${request.requestId}:nullifier-state`,
    publicationRequestDraft: draft,
    target: draft.target,
    nullifier: draft.binding.nullifier,
    proofInputHash: draft.binding.proofInputHash,
    auditCorrelationId: request.auditCorrelationId
  });
  const stateErrors = readStateErrors({ factStateRead, nullifierStateRead });
  if (stateErrors.length > 0) {
    const outcome = readinessOutcomeForErrors(stateErrors);
    const auditEventDraft = createReadinessAuditDraft({
      request,
      outcome,
      factStateRead,
      nullifierStateRead,
      errors: stateErrors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "AUTHORIZATION_EXECUTION_READINESS_BLOCKED",
      "unsupported_operation",
      "Authorization execution readiness is blocked by read-only state checks.",
      outcome,
      stateErrors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }

  const resultId = createAuditCorrelationId([
    draft.verifiedFactPublicationRequestDraftId,
    factStateRead.checkedAt,
    nullifierStateRead.checkedAt,
    "authorization-execution-readiness"
  ]);
  const resultBase = {
    authorizationExecutionReadinessResultId: resultId,
    status: "ready_for_future_execution_preparation" as const,
    outcome: "ready_for_future_execution_preparation" as const,
    binding: {
      ...draft.binding,
      verifiedFactPublicationRequestDraftId: draft.verifiedFactPublicationRequestDraftId,
      chainId: 8453 as const,
      network: "base" as const,
      verifierReference: draft.target.verifier.verifierReference,
      registryReference: draft.target.registry.registryReference,
      consumerReference: draft.target.consumer.consumerReference,
      smartAccountReference: draft.target.smartAccount.smartAccountReference
    },
    publicationRequestDraft: draft,
    factStateRead,
    nullifierStateRead,
    summary: {
      factState: factStateRead.status,
      nullifierState: nullifierStateRead.status,
      factCheckedAt: factStateRead.checkedAt,
      nullifierCheckedAt: nullifierStateRead.checkedAt,
      factBlockReference: factStateRead.blockReference,
      nullifierBlockReference: nullifierStateRead.blockReference,
      freshnessWindowMs: Math.min(
        factStateRead.freshnessWindowMs ?? 30_000,
        nullifierStateRead.freshnessWindowMs ?? 30_000
      ),
      raceConditionWarning: "read_only_snapshot_must_be_revalidated_before_execution" as const,
      revalidationRequiredBeforeTransaction: true as const,
      executionPreparationAllowedNow: false as const
    },
    requirements: [
      "valid_finalized_authorization_package",
      "ethereum_base_chain_profile",
      "verified_local_action_unlock_proof",
      "fact_high_low_shape",
      "read_only_fact_state_check",
      "read_only_nullifier_state_check",
      "freshness_revalidation_before_execution",
      "future_publisher_revalidates_fact_state",
      "future_executor_revalidates_nullifier_state",
      "future_adapter_remains_downstream"
    ] as const,
    limitations: [
      "publication_request_only",
      "no_fact_publication",
      "no_contract_call",
      "no_nullifier_consumption",
      "no_adapter_execution",
      "no_user_operation",
      "read_only_state_snapshot",
      "race_condition_requires_revalidation",
      "not_execution_authority",
      "not_transaction_authority",
      "state_may_change_after_read",
      "future_revalidation_required"
    ] as const,
    factPublished: false as const,
    nullifierConsumed: false as const,
    contractCalled: false as const,
    userOperationCreated: false as const,
    transactionSigned: false as const,
    transactionSubmitted: false as const,
    adapterExecuted: false as const,
    chainStateMutated: false as const,
    persisted: false as const
  };
  const result = freezeRecord(resultBase) as AuthorizationExecutionReadinessResultValue;
  const shape = validateAuthorizationExecutionReadinessResultShape(result);
  if (!shape.valid) {
    const outcome = readinessOutcomeForErrors(shape.errors);
    const auditEventDraft = createReadinessAuditDraft({
      request,
      outcome,
      factStateRead,
      nullifierStateRead,
      errors: shape.errors
    });
    auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied(runtimeError(
      "AUTHORIZATION_EXECUTION_READINESS_RESULT_MALFORMED",
      "invalid_authorization_package",
      "Authorization execution readiness result shape is malformed.",
      outcome,
      shape.errors
    ), { auditEventId: auditEventDraft.eventDraftId });
  }
  const auditEventDraft = createReadinessAuditDraft({
    request,
    outcome: "ready_for_future_execution_preparation",
    result,
    factStateRead,
    nullifierStateRead
  });
  const auditDraftCollectionResult = auditDraftCollector?.addDraft(auditEventDraft);
  const collectionResult = resultStore?.addResult(result);
  return runtimeOk(freezeRecord({
    ...resultBase,
    auditEventDraft,
    auditDraftCollectionResult,
    collectionResult
  }) as AuthorizationExecutionReadinessResultValue, {
    auditEventId: auditEventDraft.eventDraftId
  });
}

export function validateAuthorizationExecutionReadinessResultShape(
  result: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(result)) return validation(["readiness result must be an object"]);
  if (!isNonEmptyString(result.authorizationExecutionReadinessResultId)) {
    errors.push("authorizationExecutionReadinessResultId is required");
  }
  if (result.status !== "ready_for_future_execution_preparation") {
    errors.push("status must be ready_for_future_execution_preparation");
  }
  if (result.outcome !== "ready_for_future_execution_preparation") {
    errors.push("outcome must be ready_for_future_execution_preparation");
  }
  if (!isRecord(result.binding)) errors.push("binding is required");
  if (!isRecord(result.publicationRequestDraft)) errors.push("publicationRequestDraft is required");
  if (!isRecord(result.factStateRead)) errors.push("factStateRead is required");
  if (!isRecord(result.nullifierStateRead)) errors.push("nullifierStateRead is required");
  for (const field of [
    "factPublished",
    "nullifierConsumed",
    "contractCalled",
    "userOperationCreated",
    "transactionSigned",
    "transactionSubmitted",
    "adapterExecuted",
    "chainStateMutated",
    "persisted"
  ]) {
    if (result[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

export function isAuthorizationExecutionReadinessStatus(
  value: unknown
): value is AuthorizationExecutionReadinessStatus {
  return READINESS_STATUSES.has(value as AuthorizationExecutionReadinessStatus);
}

export function isAuthorizationExecutionReadinessOutcome(
  value: unknown
): value is AuthorizationExecutionReadinessOutcome {
  return READINESS_OUTCOMES.has(value as AuthorizationExecutionReadinessOutcome);
}

export function createFixtureVerifiedFactStateReader(input: {
  readonly state?: VerifiedFactState;
  readonly blockReference?: string;
  readonly freshnessWindowMs?: number;
} = {}): VerifiedFactStateReader {
  return {
    readFactState() {
      return freezeRecord({
        status: input.state ?? "fact_not_published",
        source: "fixture" as const,
        checkedAt: new Date().toISOString(),
        blockReference: input.blockReference ?? "fixture-block:alpha0",
        freshnessWindowMs: input.freshnessWindowMs ?? 30_000,
        contractCalled: false as const,
        chainStateMutated: false as const
      });
    }
  };
}

export function createFixtureAuthorizationNullifierStateReader(input: {
  readonly state?: AuthorizationNullifierState;
  readonly blockReference?: string;
  readonly freshnessWindowMs?: number;
} = {}): AuthorizationNullifierStateReader {
  return {
    readNullifierState() {
      return freezeRecord({
        status: input.state ?? "nullifier_available",
        source: "fixture" as const,
        checkedAt: new Date().toISOString(),
        blockReference: input.blockReference ?? "fixture-block:alpha0",
        freshnessWindowMs: input.freshnessWindowMs ?? 30_000,
        nullifierReserved: false as const,
        nullifierConsumed: false as const,
        contractCalled: false as const,
        chainStateMutated: false as const
      });
    }
  };
}

export function createInMemoryVerifiedFactPublicationRequestDraftStore(
  options: InMemoryVerifiedFactPublicationRequestDraftStoreOptions = {}
): VerifiedFactPublicationRequestDraftStore {
  const maxCount = Math.max(1, Math.floor(options.maxDraftCount ?? 100));
  const drafts = new Map<string, VerifiedFactPublicationRequestDraft>();
  function collection(
    status: VerifiedFactPublicationRequestDraftCollectionStatus,
    draft?: VerifiedFactPublicationRequestDraft,
    reason?: string
  ): VerifiedFactPublicationRequestDraftCollectionResult {
    return freezeRecord({
      status,
      draft,
      drafts: Array.from(drafts.values()),
      count: drafts.size,
      persisted: false as const,
      reason
    });
  }
  return {
    addDraft(draft) {
      if (drafts.has(draft.verifiedFactPublicationRequestDraftId)) {
        return collection("duplicate_rejected", draft, "duplicate publication request draft id");
      }
      while (drafts.size >= maxCount) {
        const oldest = drafts.keys().next().value;
        if (oldest === undefined) break;
        drafts.delete(oldest);
      }
      drafts.set(draft.verifiedFactPublicationRequestDraftId, freezeRecord(draft));
      return collection("collected", draft);
    },
    getById(draftId) {
      const value = drafts.get(draftId);
      return value ? freezeRecord(value) : undefined;
    },
    getAll() {
      return freezeRecord(Array.from(drafts.values()));
    },
    count() {
      return drafts.size;
    },
    clear() {
      drafts.clear();
      return collection("cleared");
    }
  };
}

export function createInMemoryAuthorizationExecutionReadinessResultStore(
  options: InMemoryAuthorizationExecutionReadinessResultStoreOptions = {}
): AuthorizationExecutionReadinessResultStore {
  const maxCount = Math.max(1, Math.floor(options.maxResultCount ?? 100));
  const results = new Map<string, AuthorizationExecutionReadinessResultValue>();
  function collection(
    status: AuthorizationExecutionReadinessResultCollectionStatus,
    result?: AuthorizationExecutionReadinessResultValue,
    reason?: string
  ): AuthorizationExecutionReadinessResultCollectionResult {
    return freezeRecord({
      status,
      result,
      results: Array.from(results.values()),
      count: results.size,
      persisted: false as const,
      reason
    });
  }
  return {
    addResult(result) {
      if (results.has(result.authorizationExecutionReadinessResultId)) {
        return collection("duplicate_rejected", result, "duplicate readiness result id");
      }
      while (results.size >= maxCount) {
        const oldest = results.keys().next().value;
        if (oldest === undefined) break;
        results.delete(oldest);
      }
      results.set(result.authorizationExecutionReadinessResultId, freezeRecord(result));
      return collection("collected", result);
    },
    getById(resultId) {
      const value = results.get(resultId);
      return value ? freezeRecord(value) : undefined;
    },
    getAll() {
      return freezeRecord(Array.from(results.values()));
    },
    count() {
      return results.size;
    },
    clear() {
      results.clear();
      return collection("cleared");
    }
  };
}
