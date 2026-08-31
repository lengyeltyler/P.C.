import type {
  PhilDeviceIdentityProviderKind,
  PhilDevicePublicMetadata
} from "../deviceIdentity.ts";
import type { Hex } from "../hashes.ts";
import type { CapabilityGrantDraft } from "./capabilityDrafts.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import { redactRuntimeMetadata } from "./redaction.ts";
import type {
  ApplicationId,
  RuntimeErrorDescriptor,
  RuntimeResult,
  TrustCredentialRequirement,
  TrustCredentialSummary,
  TrustRequirementLevel,
  UserSessionContext
} from "./types.ts";

export type TrustEvaluationDraftStatus =
  | "draft_created"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "pending_credential_resolution"
  | "pending_device_resolution"
  | "pending_trust_evaluation";

export type TrustEvaluationDraftOutcome =
  | "draft_created"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "pending_credential_resolution"
  | "pending_device_resolution"
  | "pending_trust_evaluation";

export type TrustEvaluationDraftReason =
  | "trust-request-valid"
  | "capability-draft-valid"
  | "awaiting-credential-resolution"
  | "awaiting-device-resolution"
  | "awaiting-future-trust-evaluation"
  | "malformed-request"
  | "private-material-not-allowed"
  | "active-trust-decision-not-allowed"
  | (string & {});

export interface TrustEvaluationSubject {
  readonly applicationId: ApplicationId;
  readonly capabilityGrantDraftId: string;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
}

export interface TrustEvaluationCredentialReference {
  readonly credentialId?: string;
  readonly credentialKind?: TrustCredentialSummary["credentialKind"];
  readonly providerKind?: PhilDeviceIdentityProviderKind;
  readonly credentialStatusReference?: TrustCredentialSummary["state"];
  readonly publicMetadata?: Readonly<Record<string, unknown>>;
}

export interface TrustEvaluationDeviceReference {
  readonly deviceId?: string;
  readonly deviceIdentityId?: Hex;
  readonly deviceKeyId?: Hex;
  readonly providerKind?: PhilDeviceIdentityProviderKind;
  readonly deviceMetadataReference?: PhilDevicePublicMetadata;
  readonly productionSafe?: boolean;
  readonly hardwareBacked?: boolean;
}

export interface TrustEvaluationRequirementDraft {
  readonly requirementId: string;
  readonly requestedTrustLevel: TrustRequirementLevel;
  readonly credentialRequirement?: TrustCredentialRequirement;
  readonly description?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface TrustEvaluationDraftInput {
  readonly requestId: string;
  readonly capabilityGrantDraft: CapabilityGrantDraft;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
  readonly userSessionContext?: UserSessionContext;
  readonly subject?: TrustEvaluationSubject;
  readonly credentialReference?: TrustEvaluationCredentialReference;
  readonly deviceReference?: TrustEvaluationDeviceReference;
  readonly requirements?: readonly TrustEvaluationRequirementDraft[];
  readonly requestedTrustLevel?: TrustRequirementLevel;
  readonly auditCorrelationId?: string;
  readonly humanReadableSummary?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly status?: TrustEvaluationDraftStatus;
  readonly outcome?: TrustEvaluationDraftOutcome;
}

export interface TrustEvaluationDraft {
  readonly trustEvaluationDraftId: string;
  readonly requestId: string;
  readonly capabilityGrantDraftId: string;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
  readonly subject: TrustEvaluationSubject;
  readonly credentialReference?: TrustEvaluationCredentialReference;
  readonly deviceReference?: TrustEvaluationDeviceReference;
  readonly requirements: readonly TrustEvaluationRequirementDraft[];
  readonly requestedTrustLevel?: TrustRequirementLevel;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerKind?: PhilDeviceIdentityProviderKind;
  readonly credentialStatusReference?: TrustCredentialSummary["state"];
  readonly deviceMetadataReference?: PhilDevicePublicMetadata;
  readonly createdAt: string;
  readonly expiresAt?: string;
  readonly status: TrustEvaluationDraftStatus;
  readonly outcome: TrustEvaluationDraftOutcome;
  readonly reasons: readonly TrustEvaluationDraftReason[];
  readonly auditCorrelationId: string;
  readonly humanReadableSummary: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly providesTrustDecision: false;
  readonly authenticated: false;
  readonly persisted: false;
}

export type TrustEvaluationDraftResult = RuntimeResult<TrustEvaluationDraft>;

export type TrustEvaluationDraftCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface TrustEvaluationDraftFilter {
  readonly trustEvaluationDraftId?: string;
  readonly requestId?: string;
  readonly capabilityGrantDraftId?: string;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly ownerCommitment?: Hex;
  readonly credentialId?: string;
  readonly deviceId?: string;
  readonly providerKind?: PhilDeviceIdentityProviderKind;
  readonly status?: TrustEvaluationDraftStatus;
  readonly outcome?: TrustEvaluationDraftOutcome;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface TrustEvaluationDraftQuery {
  readonly filter?: TrustEvaluationDraftFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface TrustEvaluationDraftCollection {
  readonly drafts: readonly TrustEvaluationDraft[];
  readonly count: number;
  readonly maxDraftCount: number;
}

export interface TrustEvaluationDraftCollectionResult {
  readonly status: TrustEvaluationDraftCollectionStatus;
  readonly draft?: TrustEvaluationDraft;
  readonly removedDraft?: TrustEvaluationDraft;
  readonly evictedDrafts?: readonly TrustEvaluationDraft[];
  readonly collection: TrustEvaluationDraftCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface TrustEvaluationDraftCollector {
  addDraft(draft: TrustEvaluationDraft): TrustEvaluationDraftCollectionResult;
  removeDraft(trustEvaluationDraftId: string): TrustEvaluationDraftCollectionResult;
  clear(): TrustEvaluationDraftCollectionResult;
  count(): number;
  getById(trustEvaluationDraftId: string): TrustEvaluationDraft | undefined;
  getAll(): readonly TrustEvaluationDraft[];
  query(query: TrustEvaluationDraftQuery): readonly TrustEvaluationDraft[];
  filter(filter: TrustEvaluationDraftFilter): readonly TrustEvaluationDraft[];
}

export interface InMemoryTrustEvaluationDraftCollectorOptions {
  readonly maxDraftCount?: number;
}

export type TrustEvaluationDraftResolutionState =
  | "draft_created"
  | "validation_failed"
  | "malformed"
  | "unsupported"
  | "pending_credential_resolution"
  | "pending_device_resolution"
  | "pending_trust_evaluation";

export type TrustEvaluationDraftPendingReason =
  | "credential_reference_missing"
  | "device_reference_missing"
  | "awaiting_future_trust_evaluation"
  | "validation_artifact_only"
  | (string & {});

export type TrustEvaluationDraftGroup =
  Readonly<Record<string, readonly TrustEvaluationDraft[]>>;

export type TrustEvaluationDraftReviewSource =
  | TrustEvaluationDraftCollector
  | TrustEvaluationDraftCollection
  | readonly TrustEvaluationDraft[];

export interface TrustEvaluationDraftSummary {
  readonly totalDraftCount: number;
  readonly draftsByApplication: Readonly<Record<string, number>>;
  readonly draftsBySession: Readonly<Record<string, number>>;
  readonly draftsByCredential: Readonly<Record<string, number>>;
  readonly draftsByDevice: Readonly<Record<string, number>>;
  readonly draftsByProviderKind: Readonly<Record<string, number>>;
  readonly draftsByStatus: Readonly<Record<string, number>>;
  readonly pendingCredentialResolutionCount: number;
  readonly pendingDeviceResolutionCount: number;
  readonly pendingTrustEvaluationCount: number;
  readonly expiredCount: number;
  readonly expiredDrafts: readonly TrustEvaluationDraft[];
  readonly pendingCredentialResolutionDrafts: readonly TrustEvaluationDraft[];
  readonly pendingDeviceResolutionDrafts: readonly TrustEvaluationDraft[];
  readonly pendingTrustEvaluationDrafts: readonly TrustEvaluationDraft[];
  readonly earliestCreatedAt?: string;
  readonly latestCreatedAt?: string;
  readonly providesTrustDecision: false;
}

export interface TrustEvaluationDraftReviewResult {
  readonly summary: TrustEvaluationDraftSummary;
  readonly groups: Readonly<{
    readonly byApplication: TrustEvaluationDraftGroup;
    readonly bySession: TrustEvaluationDraftGroup;
    readonly byCredential: TrustEvaluationDraftGroup;
    readonly byDevice: TrustEvaluationDraftGroup;
    readonly byProviderKind: TrustEvaluationDraftGroup;
    readonly byStatus: TrustEvaluationDraftGroup;
  }>;
  readonly providesTrustDecision: false;
}

const TRUST_EVALUATION_DRAFT_STATUSES = new Set<TrustEvaluationDraftStatus>([
  "draft_created",
  "validation_failed",
  "malformed",
  "unsupported",
  "pending_credential_resolution",
  "pending_device_resolution",
  "pending_trust_evaluation"
]);

const ACTIVE_TRUST_OR_PRIVATE_FIELDS = new Set([
  "philsecret",
  "privatekey",
  "signingkey",
  "vaultkey",
  "rawvaultkey",
  "password",
  "passphrase",
  "seed",
  "seedphrase",
  "mnemonic",
  "recoverysecret",
  "assertionsecret",
  "webauthnprivatematerial",
  "trusted",
  "approved",
  "authenticated",
  "verified",
  "trustdecision",
  "authorizationpackage",
  "capabilitygrant"
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function normalizeFieldName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

function hasValidDateShape(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function validation(errors: string[]): RuntimeValidationResult {
  return {
    valid: errors.length === 0,
    errors
  };
}

function freezeRecord<TValue>(value: TValue): TValue {
  if (Array.isArray(value)) {
    return Object.freeze(value.map(freezeRecord)) as TValue;
  }
  if (isRecord(value)) {
    return Object.freeze(
      Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, freezeRecord(entry)]))
    ) as TValue;
  }
  return value;
}

function findBlockedFields(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findBlockedFields(entry, `${path}[${index}]`));
  }
  if (!isRecord(value)) {
    return [];
  }
  const findings: string[] = [];
  for (const [key, entry] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (ACTIVE_TRUST_OR_PRIVATE_FIELDS.has(normalizeFieldName(key))) {
      if (entry === false) {
        continue;
      }
      findings.push(childPath);
    }
    findings.push(...findBlockedFields(entry, childPath));
  }
  return findings;
}

function malformedTrustDraftError(errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "TRUST_EVALUATION_DRAFT_INVALID",
    message: "trust evaluation draft input failed validation",
    boundary: "trust-manager",
    recoverable: true,
    details: {
      errors
    }
  };
}

export function isTrustEvaluationDraftStatus(
  value: unknown
): value is TrustEvaluationDraftStatus {
  return TRUST_EVALUATION_DRAFT_STATUSES.has(value as TrustEvaluationDraftStatus);
}

export function validateTrustEvaluationDraftInput(
  input: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["trust evaluation draft input must be an object"]);
  }

  if (!isNonEmptyString(input.requestId)) {
    errors.push("requestId is required");
  }
  if (!isRecord(input.capabilityGrantDraft)) {
    errors.push("capabilityGrantDraft is required");
  } else {
    if (!isNonEmptyString(input.capabilityGrantDraft.capabilityGrantDraftId)) {
      errors.push("capabilityGrantDraft.capabilityGrantDraftId is required");
    }
    if (!isNonEmptyString(input.capabilityGrantDraft.applicationId)) {
      errors.push("capabilityGrantDraft.applicationId is required");
    }
    if (input.capabilityGrantDraft.providesAuthority !== false) {
      errors.push("capabilityGrantDraft.providesAuthority must be false");
    }
    if (input.capabilityGrantDraft.persisted !== false) {
      errors.push("capabilityGrantDraft.persisted must be false");
    }
  }
  if (input.sessionId !== undefined && !isNonEmptyString(input.sessionId)) {
    errors.push("sessionId must be a non-empty string when provided");
  }
  if (input.status !== undefined && !isTrustEvaluationDraftStatus(input.status)) {
    errors.push("status is invalid");
  }
  if (input.outcome !== undefined && !isTrustEvaluationDraftStatus(input.outcome)) {
    errors.push("outcome is invalid");
  }
  if (input.createdAt !== undefined && !hasValidDateShape(input.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (input.expiresAt !== undefined && !hasValidDateShape(input.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (isRecord(input.credentialReference)) {
    if (
      input.credentialReference.credentialId !== undefined
      && !isNonEmptyString(input.credentialReference.credentialId)
    ) {
      errors.push("credentialReference.credentialId must be a non-empty string when provided");
    }
  }
  if (isRecord(input.deviceReference)) {
    if (
      input.deviceReference.deviceId !== undefined
      && !isNonEmptyString(input.deviceReference.deviceId)
    ) {
      errors.push("deviceReference.deviceId must be a non-empty string when provided");
    }
  }
  if (Array.isArray(input.requirements)) {
    input.requirements.forEach((requirement, index) => {
      if (!isRecord(requirement)) {
        errors.push(`requirements[${index}] must be an object`);
        return;
      }
      if (!isNonEmptyString(requirement.requirementId)) {
        errors.push(`requirements[${index}].requirementId is required`);
      }
      if (!isNonEmptyString(requirement.requestedTrustLevel)) {
        errors.push(`requirements[${index}].requestedTrustLevel is required`);
      }
    });
  }

  const blockedFields = findBlockedFields(input);
  if (blockedFields.length > 0) {
    errors.push(`private material or active trust fields are not allowed: ${blockedFields.join(", ")}`);
  }

  return validation(errors);
}

export function validateTrustEvaluationDraftShape(
  draft: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(draft)) {
    return validation(["trust evaluation draft must be an object"]);
  }

  if (!isNonEmptyString(draft.trustEvaluationDraftId)) {
    errors.push("trustEvaluationDraftId is required");
  }
  if (!isNonEmptyString(draft.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(draft.capabilityGrantDraftId)) {
    errors.push("capabilityGrantDraftId is required");
  }
  if (!isNonEmptyString(draft.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isTrustEvaluationDraftStatus(draft.status)) {
    errors.push("status is invalid");
  }
  if (!isTrustEvaluationDraftStatus(draft.outcome)) {
    errors.push("outcome is invalid");
  }
  if (
    draft.status === "trusted"
    || draft.status === "approved"
    || draft.status === "authenticated"
    || draft.status === "verified"
  ) {
    errors.push("trust evaluation drafts must never use active trust statuses");
  }
  if (draft.providesTrustDecision !== false) {
    errors.push("providesTrustDecision must be false");
  }
  if (draft.authenticated !== false) {
    errors.push("authenticated must be false");
  }
  if (draft.persisted !== false) {
    errors.push("persisted must be false");
  }
  if (draft.createdAt !== undefined && !hasValidDateShape(draft.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (draft.expiresAt !== undefined && !hasValidDateShape(draft.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }

  const blockedFields = findBlockedFields(draft);
  if (blockedFields.length > 0) {
    errors.push(`private material or active trust fields are not allowed: ${blockedFields.join(", ")}`);
  }

  return validation(errors);
}

function deriveTrustDraftStatus(input: TrustEvaluationDraftInput): TrustEvaluationDraftStatus {
  if (input.status) {
    return input.status;
  }
  if (!input.credentialReference?.credentialId) {
    return "pending_credential_resolution";
  }
  if (!input.deviceReference?.deviceId && !input.deviceReference?.deviceIdentityId) {
    return "pending_device_resolution";
  }
  return "pending_trust_evaluation";
}

function deriveReasons(status: TrustEvaluationDraftStatus): readonly TrustEvaluationDraftReason[] {
  const reasons: TrustEvaluationDraftReason[] = [
    "trust-request-valid",
    "capability-draft-valid"
  ];
  if (status === "pending_credential_resolution") {
    reasons.push("awaiting-credential-resolution");
  } else if (status === "pending_device_resolution") {
    reasons.push("awaiting-device-resolution");
  } else {
    reasons.push("awaiting-future-trust-evaluation");
  }
  return Object.freeze(reasons);
}

export function createTrustEvaluationDraft(
  input: TrustEvaluationDraftInput
): TrustEvaluationDraftResult {
  const validationResult = validateTrustEvaluationDraftInput(input);
  if (!validationResult.valid) {
    return runtimeDenied(malformedTrustDraftError(validationResult.errors));
  }

  const status = deriveTrustDraftStatus(input);
  const outcome = input.outcome ?? (status === "draft_created" ? "draft_created" : status);
  const createdAt = input.createdAt ?? new Date().toISOString();
  const sessionId = input.sessionId
    ?? input.userSessionContext?.sessionId
    ?? input.capabilityGrantDraft.sessionId;
  const ownerCommitment = input.ownerCommitment
    ?? input.userSessionContext?.ownerCommitment;
  const applicationId = input.capabilityGrantDraft.applicationId;
  const capabilityGrantDraftId = input.capabilityGrantDraft.capabilityGrantDraftId;
  const auditCorrelationId = input.auditCorrelationId ?? createAuditCorrelationId([
    applicationId,
    sessionId ?? "",
    capabilityGrantDraftId,
    input.requestId,
    "trust-evaluation-draft"
  ]);
  const subject = freezeRecord(input.subject ?? {
    applicationId,
    capabilityGrantDraftId,
    sessionId,
    ownerCommitment
  });
  const credentialReference = input.credentialReference
    ? freezeRecord(redactRuntimeMetadata(input.credentialReference).value as TrustEvaluationCredentialReference)
    : undefined;
  const deviceReference = input.deviceReference
    ? freezeRecord(redactRuntimeMetadata(input.deviceReference).value as TrustEvaluationDeviceReference)
    : undefined;
  const requirements = Object.freeze([...(input.requirements ?? [])].map(
    (requirement) => freezeRecord(
      redactRuntimeMetadata(requirement).value as TrustEvaluationRequirementDraft
    )
  ));
  const metadata = input.metadata
    ? redactRuntimeMetadata(input.metadata).value as Readonly<Record<string, unknown>>
    : undefined;

  const draft: TrustEvaluationDraft = Object.freeze({
    trustEvaluationDraftId: `${auditCorrelationId}:draft`,
    requestId: input.requestId,
    capabilityGrantDraftId,
    applicationId,
    sessionId,
    ownerCommitment,
    subject,
    credentialReference,
    deviceReference,
    requirements,
    requestedTrustLevel: input.requestedTrustLevel,
    credentialId: credentialReference?.credentialId,
    deviceId: deviceReference?.deviceId,
    providerKind: credentialReference?.providerKind ?? deviceReference?.providerKind,
    credentialStatusReference: credentialReference?.credentialStatusReference,
    deviceMetadataReference: deviceReference?.deviceMetadataReference,
    createdAt,
    expiresAt: input.expiresAt,
    status,
    outcome,
    reasons: deriveReasons(status),
    auditCorrelationId,
    humanReadableSummary: input.humanReadableSummary
      ?? `Trust evaluation request ${input.requestId} is structurally valid and awaiting future Trust Manager evaluation.`,
    metadata,
    providesTrustDecision: false,
    authenticated: false,
    persisted: false
  });

  return runtimeOk(draft);
}

function normalizeMaxDraftCount(maxDraftCount?: number): number {
  if (maxDraftCount === undefined) {
    return 100;
  }
  if (!Number.isFinite(maxDraftCount)) {
    return 100;
  }
  return Math.max(1, Math.floor(maxDraftCount));
}

function freezeDraft(draft: TrustEvaluationDraft): TrustEvaluationDraft {
  return freezeRecord(draft);
}

function matchesFilter(
  draft: TrustEvaluationDraft,
  filter: TrustEvaluationDraftFilter
): boolean {
  if (
    filter.trustEvaluationDraftId !== undefined
    && draft.trustEvaluationDraftId !== filter.trustEvaluationDraftId
  ) return false;
  if (filter.requestId !== undefined && draft.requestId !== filter.requestId) return false;
  if (
    filter.capabilityGrantDraftId !== undefined
    && draft.capabilityGrantDraftId !== filter.capabilityGrantDraftId
  ) return false;
  if (filter.applicationId !== undefined && draft.applicationId !== filter.applicationId) {
    return false;
  }
  if (filter.sessionId !== undefined && draft.sessionId !== filter.sessionId) return false;
  if (
    filter.ownerCommitment !== undefined
    && draft.ownerCommitment !== filter.ownerCommitment
  ) return false;
  if (filter.credentialId !== undefined && draft.credentialId !== filter.credentialId) {
    return false;
  }
  if (filter.deviceId !== undefined && draft.deviceId !== filter.deviceId) return false;
  if (filter.providerKind !== undefined && draft.providerKind !== filter.providerKind) {
    return false;
  }
  if (filter.status !== undefined && draft.status !== filter.status) return false;
  if (filter.outcome !== undefined && draft.outcome !== filter.outcome) return false;
  if (
    filter.auditCorrelationId !== undefined
    && draft.auditCorrelationId !== filter.auditCorrelationId
  ) return false;
  if (filter.since !== undefined && draft.createdAt < filter.since) return false;
  if (filter.until !== undefined && draft.createdAt > filter.until) return false;
  return true;
}

export function createInMemoryTrustEvaluationDraftCollector(
  options: InMemoryTrustEvaluationDraftCollectorOptions = {}
): TrustEvaluationDraftCollector {
  const maxDraftCount = normalizeMaxDraftCount(options.maxDraftCount);
  const drafts = new Map<string, TrustEvaluationDraft>();

  function getAll(): readonly TrustEvaluationDraft[] {
    return Object.freeze(Array.from(drafts.values()));
  }

  function collection(): TrustEvaluationDraftCollection {
    return Object.freeze({
      drafts: getAll(),
      count: drafts.size,
      maxDraftCount
    });
  }

  function filterDrafts(
    filter: TrustEvaluationDraftFilter
  ): readonly TrustEvaluationDraft[] {
    return Object.freeze(getAll().filter((draft) => matchesFilter(draft, filter)));
  }

  return {
    addDraft(draft) {
      const validationResult = validateTrustEvaluationDraftShape(draft);
      if (!validationResult.valid) {
        return {
          status: "rejected_invalid",
          collection: collection(),
          errors: validationResult.errors,
          reason: "Only valid Trust Evaluation Drafts may be collected."
        };
      }

      if (drafts.has(draft.trustEvaluationDraftId)) {
        return {
          status: "rejected_duplicate",
          draft: drafts.get(draft.trustEvaluationDraftId),
          collection: collection(),
          reason: "Trust Evaluation Draft IDs must be unique within an in-memory collector."
        };
      }

      const evictedDrafts: TrustEvaluationDraft[] = [];
      if (drafts.size >= maxDraftCount) {
        const oldestDraftId = drafts.keys().next().value as string | undefined;
        if (oldestDraftId !== undefined) {
          const oldestDraft = drafts.get(oldestDraftId);
          drafts.delete(oldestDraftId);
          if (oldestDraft) {
            evictedDrafts.push(oldestDraft);
          }
        }
      }

      const storedDraft = freezeDraft(draft);
      drafts.set(storedDraft.trustEvaluationDraftId, storedDraft);

      return {
        status: evictedDrafts.length > 0 ? "evicted_oldest" : "collected",
        draft: storedDraft,
        evictedDrafts: Object.freeze(evictedDrafts),
        collection: collection()
      };
    },
    removeDraft(trustEvaluationDraftId) {
      const removedDraft = drafts.get(trustEvaluationDraftId);
      if (!removedDraft) {
        return {
          status: "not_found",
          collection: collection(),
          reason: "No Trust Evaluation Draft with that ID exists in this in-memory collector."
        };
      }
      drafts.delete(trustEvaluationDraftId);
      return {
        status: "removed",
        removedDraft,
        collection: collection()
      };
    },
    clear() {
      drafts.clear();
      return {
        status: "cleared",
        collection: collection()
      };
    },
    count() {
      return drafts.size;
    },
    getById(trustEvaluationDraftId) {
      return drafts.get(trustEvaluationDraftId);
    },
    getAll,
    query(query) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter ? filterDrafts(query.filter) : getAll();
      const sliced = limit === undefined
        ? filtered.slice(offset)
        : filtered.slice(offset, offset + limit);
      return Object.freeze(sliced);
    },
    filter: filterDrafts
  };
}

function draftArrayFromReviewSource(
  source: TrustEvaluationDraftReviewSource
): readonly TrustEvaluationDraft[] {
  if (Array.isArray(source)) {
    return source;
  }
  if ("getAll" in source && typeof source.getAll === "function") {
    return source.getAll();
  }
  return (source as TrustEvaluationDraftCollection).drafts;
}

function freezeGroupMap(groups: Record<string, TrustEvaluationDraft[]>): TrustEvaluationDraftGroup {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(groups).map(([key, value]) => [key, Object.freeze([...value])])
    )
  );
}

function groupTrustDraftsBy(
  source: TrustEvaluationDraftReviewSource,
  keyForDraft: (draft: TrustEvaluationDraft) => string
): TrustEvaluationDraftGroup {
  const groups: Record<string, TrustEvaluationDraft[]> = {};
  for (const draft of draftArrayFromReviewSource(source)) {
    const key = keyForDraft(draft);
    groups[key] ??= [];
    groups[key].push(draft);
  }
  return freezeGroupMap(groups);
}

function countGroups(groups: TrustEvaluationDraftGroup): Readonly<Record<string, number>> {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(groups).map(([key, value]) => [key, value.length])
    )
  );
}

function draftCreationRange(drafts: readonly TrustEvaluationDraft[]): {
  readonly earliestCreatedAt?: string;
  readonly latestCreatedAt?: string;
} {
  const createdAtValues = drafts.map((draft) => draft.createdAt).filter(Boolean).sort();
  return {
    earliestCreatedAt: createdAtValues[0],
    latestCreatedAt: createdAtValues[createdAtValues.length - 1]
  };
}

function isExpiredTrustEvaluationDraft(draft: TrustEvaluationDraft): boolean {
  return draft.expiresAt !== undefined && Date.parse(draft.expiresAt) <= Date.now();
}

export function groupTrustEvaluationDraftsByApplication(
  source: TrustEvaluationDraftReviewSource
): TrustEvaluationDraftGroup {
  return groupTrustDraftsBy(source, (draft) => draft.applicationId);
}

export function groupTrustEvaluationDraftsBySession(
  source: TrustEvaluationDraftReviewSource
): TrustEvaluationDraftGroup {
  return groupTrustDraftsBy(source, (draft) => draft.sessionId ?? "no-session");
}

export function groupTrustEvaluationDraftsByCredential(
  source: TrustEvaluationDraftReviewSource
): TrustEvaluationDraftGroup {
  return groupTrustDraftsBy(source, (draft) => draft.credentialId ?? "no-credential");
}

export function groupTrustEvaluationDraftsByDevice(
  source: TrustEvaluationDraftReviewSource
): TrustEvaluationDraftGroup {
  return groupTrustDraftsBy(source, (draft) => draft.deviceId ?? "no-device");
}

export function groupTrustEvaluationDraftsByProviderKind(
  source: TrustEvaluationDraftReviewSource
): TrustEvaluationDraftGroup {
  return groupTrustDraftsBy(source, (draft) => draft.providerKind ?? "no-provider-kind");
}

export function groupTrustEvaluationDraftsByStatus(
  source: TrustEvaluationDraftReviewSource
): TrustEvaluationDraftGroup {
  return groupTrustDraftsBy(source, (draft) => draft.status);
}

export function getPendingCredentialResolutionDrafts(
  source: TrustEvaluationDraftReviewSource
): readonly TrustEvaluationDraft[] {
  return Object.freeze(
    draftArrayFromReviewSource(source).filter(
      (draft) => draft.status === "pending_credential_resolution"
        && !isExpiredTrustEvaluationDraft(draft)
    )
  );
}

export function getPendingDeviceResolutionDrafts(
  source: TrustEvaluationDraftReviewSource
): readonly TrustEvaluationDraft[] {
  return Object.freeze(
    draftArrayFromReviewSource(source).filter(
      (draft) => draft.status === "pending_device_resolution"
        && !isExpiredTrustEvaluationDraft(draft)
    )
  );
}

export function getPendingTrustEvaluationDrafts(
  source: TrustEvaluationDraftReviewSource
): readonly TrustEvaluationDraft[] {
  return Object.freeze(
    draftArrayFromReviewSource(source).filter(
      (draft) => draft.status === "pending_trust_evaluation"
        && !isExpiredTrustEvaluationDraft(draft)
    )
  );
}

export function getExpiredTrustEvaluationDrafts(
  source: TrustEvaluationDraftReviewSource
): readonly TrustEvaluationDraft[] {
  return Object.freeze(draftArrayFromReviewSource(source).filter(isExpiredTrustEvaluationDraft));
}

export function summarizeTrustEvaluationDrafts(
  source: TrustEvaluationDraftReviewSource
): TrustEvaluationDraftSummary {
  const drafts = draftArrayFromReviewSource(source);
  const byApplication = groupTrustEvaluationDraftsByApplication(drafts);
  const bySession = groupTrustEvaluationDraftsBySession(drafts);
  const byCredential = groupTrustEvaluationDraftsByCredential(drafts);
  const byDevice = groupTrustEvaluationDraftsByDevice(drafts);
  const byProviderKind = groupTrustEvaluationDraftsByProviderKind(drafts);
  const byStatus = groupTrustEvaluationDraftsByStatus(drafts);
  const pendingCredentialResolutionDrafts = getPendingCredentialResolutionDrafts(drafts);
  const pendingDeviceResolutionDrafts = getPendingDeviceResolutionDrafts(drafts);
  const pendingTrustEvaluationDrafts = getPendingTrustEvaluationDrafts(drafts);
  const expiredDrafts = getExpiredTrustEvaluationDrafts(drafts);
  const creationRange = draftCreationRange(drafts);

  return Object.freeze({
    totalDraftCount: drafts.length,
    draftsByApplication: countGroups(byApplication),
    draftsBySession: countGroups(bySession),
    draftsByCredential: countGroups(byCredential),
    draftsByDevice: countGroups(byDevice),
    draftsByProviderKind: countGroups(byProviderKind),
    draftsByStatus: countGroups(byStatus),
    pendingCredentialResolutionCount: pendingCredentialResolutionDrafts.length,
    pendingDeviceResolutionCount: pendingDeviceResolutionDrafts.length,
    pendingTrustEvaluationCount: pendingTrustEvaluationDrafts.length,
    expiredCount: expiredDrafts.length,
    expiredDrafts,
    pendingCredentialResolutionDrafts,
    pendingDeviceResolutionDrafts,
    pendingTrustEvaluationDrafts,
    earliestCreatedAt: creationRange.earliestCreatedAt,
    latestCreatedAt: creationRange.latestCreatedAt,
    providesTrustDecision: false
  });
}

export function reviewTrustEvaluationDrafts(
  source: TrustEvaluationDraftReviewSource
): TrustEvaluationDraftReviewResult {
  return Object.freeze({
    summary: summarizeTrustEvaluationDrafts(source),
    groups: Object.freeze({
      byApplication: groupTrustEvaluationDraftsByApplication(source),
      bySession: groupTrustEvaluationDraftsBySession(source),
      byCredential: groupTrustEvaluationDraftsByCredential(source),
      byDevice: groupTrustEvaluationDraftsByDevice(source),
      byProviderKind: groupTrustEvaluationDraftsByProviderKind(source),
      byStatus: groupTrustEvaluationDraftsByStatus(source)
    }),
    providesTrustDecision: false
  });
}
