import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  validateCapabilityRequestShape,
  type RuntimeValidationResult
} from "./helpers.ts";
import { redactRuntimeMetadata } from "./redaction.ts";
import type {
  ApplicationId,
  CapabilityName,
  CapabilityRequest,
  CapabilityScope,
  ProofRequirement,
  RuntimeErrorDescriptor,
  RuntimeResult,
  TrustRequirementLevel
} from "./types.ts";

export type CapabilityGrantDraftStatus =
  | "draft_created"
  | "validation_failed"
  | "unsupported"
  | "malformed"
  | "expired"
  | "pending_policy"
  | "pending_trust"
  | "pending_user_approval";

export type CapabilityGrantDraftOutcome =
  | "draft_created"
  | "validation_failed"
  | "unsupported"
  | "malformed"
  | "expired"
  | "pending_policy"
  | "pending_trust"
  | "pending_user_approval";

export type CapabilityGrantDraftReason =
  | "capability-request-valid"
  | "awaiting-trust-evaluation"
  | "awaiting-policy-evaluation"
  | "awaiting-user-approval"
  | "request-expired"
  | "unsupported-capability"
  | "malformed-request"
  | "active-authority-field-present"
  | (string & {});

export interface CapabilityGrantDraftConstraint {
  readonly constraintId: string;
  readonly description?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface CapabilityGrantDraftRequirement {
  readonly requirementId: string;
  readonly kind: "trust" | "policy" | "user_approval" | "proof";
  readonly description?: string;
  readonly trustLevel?: TrustRequirementLevel;
  readonly proofRequirement?: ProofRequirement;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface CapabilityGrantDraftInput {
  readonly capabilityRequest: CapabilityRequest;
  readonly sessionId?: string;
  readonly constraints?: readonly CapabilityGrantDraftConstraint[];
  readonly requirements?: readonly CapabilityGrantDraftRequirement[];
  readonly status?: CapabilityGrantDraftStatus;
  readonly outcome?: CapabilityGrantDraftOutcome;
  readonly requiredTrustLevel?: TrustRequirementLevel;
  readonly proofRequirement?: ProofRequirement;
  readonly auditCorrelationId?: string;
  readonly humanReadableSummary?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly createdAt?: string;
}

export interface CapabilityGrantDraft {
  readonly capabilityGrantDraftId: string;
  readonly capabilityRequestId: string;
  readonly capabilityName: CapabilityName;
  readonly applicationId: ApplicationId;
  readonly sessionId?: string;
  readonly scope?: CapabilityScope;
  readonly constraints: readonly CapabilityGrantDraftConstraint[];
  readonly requirements: readonly CapabilityGrantDraftRequirement[];
  readonly requestedAt?: string;
  readonly expiresAt?: string;
  readonly status: CapabilityGrantDraftStatus;
  readonly outcome: CapabilityGrantDraftOutcome;
  readonly reasons: readonly CapabilityGrantDraftReason[];
  readonly requiredTrustLevel?: TrustRequirementLevel;
  readonly proofRequirement?: ProofRequirement;
  readonly auditCorrelationId: string;
  readonly humanReadableSummary: string;
  readonly createdAt: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly providesAuthority: false;
  readonly persisted: false;
}

export type CapabilityGrantDraftResult = RuntimeResult<CapabilityGrantDraft>;

export type CapabilityGrantDraftCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "rejected_invalid"
  | "removed"
  | "not_found"
  | "cleared";

export interface CapabilityGrantDraftFilter {
  readonly capabilityGrantDraftId?: string;
  readonly capabilityRequestId?: string;
  readonly capabilityName?: CapabilityName;
  readonly applicationId?: ApplicationId;
  readonly sessionId?: string;
  readonly status?: CapabilityGrantDraftStatus;
  readonly outcome?: CapabilityGrantDraftOutcome;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface CapabilityGrantDraftQuery {
  readonly filter?: CapabilityGrantDraftFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface CapabilityGrantDraftCollection {
  readonly drafts: readonly CapabilityGrantDraft[];
  readonly count: number;
  readonly maxDraftCount: number;
}

export interface CapabilityGrantDraftCollectionResult {
  readonly status: CapabilityGrantDraftCollectionStatus;
  readonly draft?: CapabilityGrantDraft;
  readonly removedDraft?: CapabilityGrantDraft;
  readonly evictedDrafts?: readonly CapabilityGrantDraft[];
  readonly collection: CapabilityGrantDraftCollection;
  readonly errors?: readonly string[];
  readonly reason?: string;
}

export interface CapabilityGrantDraftCollector {
  addDraft(draft: CapabilityGrantDraft): CapabilityGrantDraftCollectionResult;
  removeDraft(capabilityGrantDraftId: string): CapabilityGrantDraftCollectionResult;
  clear(): CapabilityGrantDraftCollectionResult;
  count(): number;
  getById(capabilityGrantDraftId: string): CapabilityGrantDraft | undefined;
  getAll(): readonly CapabilityGrantDraft[];
  query(query: CapabilityGrantDraftQuery): readonly CapabilityGrantDraft[];
  filter(filter: CapabilityGrantDraftFilter): readonly CapabilityGrantDraft[];
}

export interface InMemoryCapabilityGrantDraftCollectorOptions {
  readonly maxDraftCount?: number;
}

export type CapabilityGrantDraftGroupMap =
  Readonly<Record<string, readonly CapabilityGrantDraft[]>>;

export interface CapabilityGrantDraftReviewSummary {
  readonly totalDraftCount: number;
  readonly draftsByApplication: Readonly<Record<string, number>>;
  readonly draftsBySession: Readonly<Record<string, number>>;
  readonly draftsByCapability: Readonly<Record<string, number>>;
  readonly draftsByStatus: Readonly<Record<string, number>>;
  readonly expiredDrafts: readonly CapabilityGrantDraft[];
  readonly pendingDrafts: readonly CapabilityGrantDraft[];
  readonly earliestCreatedAt?: string;
  readonly latestCreatedAt?: string;
  readonly providesAuthority: false;
}

const CAPABILITY_GRANT_DRAFT_STATUSES = new Set<CapabilityGrantDraftStatus>([
  "draft_created",
  "validation_failed",
  "unsupported",
  "malformed",
  "expired",
  "pending_policy",
  "pending_trust",
  "pending_user_approval"
]);

const ACTIVE_AUTHORITY_FIELDS = new Set([
  "grantid",
  "authoritytoken",
  "authorizationpackage",
  "authorizationpackageid",
  "signature",
  "signingauthority",
  "walletauthority",
  "privatekey",
  "signingkey",
  "vaultkey",
  "rawvaultkey"
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

function validation(errors: string[]): RuntimeValidationResult {
  return {
    valid: errors.length === 0,
    errors
  };
}

function malformedDraftError(errors: readonly string[]): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "CAPABILITY_GRANT_DRAFT_INVALID",
    message: "capability grant draft input failed validation",
    boundary: "runtime-api",
    recoverable: true,
    details: {
      errors
    }
  };
}

function findActiveAuthorityFields(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findActiveAuthorityFields(entry, `${path}[${index}]`));
  }
  if (!isRecord(value)) {
    return [];
  }
  const findings: string[] = [];
  for (const [key, entry] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (ACTIVE_AUTHORITY_FIELDS.has(normalizeFieldName(key))) {
      findings.push(childPath);
    }
    findings.push(...findActiveAuthorityFields(entry, childPath));
  }
  return findings;
}

export function isCapabilityGrantDraftStatus(
  value: unknown
): value is CapabilityGrantDraftStatus {
  return CAPABILITY_GRANT_DRAFT_STATUSES.has(value as CapabilityGrantDraftStatus);
}

export function validateCapabilityGrantDraftInput(
  input: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["capability grant draft input must be an object"]);
  }

  const capabilityRequest = input.capabilityRequest;
  const capabilityRequestValidation = validateCapabilityRequestShape(capabilityRequest);
  if (!capabilityRequestValidation.valid) {
    errors.push(...capabilityRequestValidation.errors.map((error) => `capabilityRequest.${error}`));
  }

  if (isRecord(capabilityRequest)) {
    if (!isNonEmptyString(capabilityRequest.requestId)) {
      errors.push("capabilityRequest.requestId is required");
    }
    if (!isNonEmptyString(capabilityRequest.applicationId)) {
      errors.push("capabilityRequest.applicationId is required");
    }
    if (!isNonEmptyString(capabilityRequest.capability)) {
      errors.push("capabilityRequest.capability is required");
    }
    if (isRecord(capabilityRequest.scope)) {
      if (
        capabilityRequest.scope.expiresAt !== undefined
        && !hasValidDateShape(capabilityRequest.scope.expiresAt)
      ) {
        errors.push("capabilityRequest.scope.expiresAt must be a parseable date string");
      }
    }
  }

  if (input.sessionId !== undefined && !isNonEmptyString(input.sessionId)) {
    errors.push("sessionId must be a non-empty string when provided");
  }
  if (input.status !== undefined && !isCapabilityGrantDraftStatus(input.status)) {
    errors.push("status is invalid");
  }
  if (input.outcome !== undefined && !isCapabilityGrantDraftStatus(input.outcome)) {
    errors.push("outcome is invalid");
  }
  if (input.createdAt !== undefined && !hasValidDateShape(input.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }

  const activeAuthorityFields = findActiveAuthorityFields(input);
  if (activeAuthorityFields.length > 0) {
    errors.push(`active authority fields are not allowed: ${activeAuthorityFields.join(", ")}`);
  }

  return validation(errors);
}

export function validateCapabilityGrantDraftShape(
  draft: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(draft)) {
    return validation(["capability grant draft must be an object"]);
  }

  if (!isNonEmptyString(draft.capabilityGrantDraftId)) {
    errors.push("capabilityGrantDraftId is required");
  }
  if (!isNonEmptyString(draft.capabilityRequestId)) {
    errors.push("capabilityRequestId is required");
  }
  if (!isNonEmptyString(draft.capabilityName)) {
    errors.push("capabilityName is required");
  }
  if (!isNonEmptyString(draft.applicationId)) {
    errors.push("applicationId is required");
  }
  if (draft.sessionId !== undefined && !isNonEmptyString(draft.sessionId)) {
    errors.push("sessionId must be a non-empty string when provided");
  }
  if (!isCapabilityGrantDraftStatus(draft.status)) {
    errors.push("status is invalid");
  }
  if (!isCapabilityGrantDraftStatus(draft.outcome)) {
    errors.push("outcome is invalid");
  }
  if (draft.status === "granted" || draft.outcome === "granted") {
    errors.push("capability grant drafts must never use granted status or outcome");
  }
  if (draft.providesAuthority !== false) {
    errors.push("providesAuthority must be false");
  }
  if (draft.persisted !== false) {
    errors.push("persisted must be false");
  }
  if (draft.expiresAt !== undefined && !hasValidDateShape(draft.expiresAt)) {
    errors.push("expiresAt must be a parseable date string");
  }
  if (draft.createdAt !== undefined && !hasValidDateShape(draft.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }

  const activeAuthorityFields = findActiveAuthorityFields(draft);
  if (activeAuthorityFields.length > 0) {
    errors.push(`active authority fields are not allowed: ${activeAuthorityFields.join(", ")}`);
  }

  return validation(errors);
}

function deriveDraftStatus(input: CapabilityGrantDraftInput): CapabilityGrantDraftStatus {
  if (input.status) {
    return input.status;
  }
  const expiresAt = input.capabilityRequest.scope?.expiresAt;
  if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
    return "expired";
  }
  return "pending_policy";
}

function deriveReasons(status: CapabilityGrantDraftStatus): readonly CapabilityGrantDraftReason[] {
  if (status === "expired") {
    return Object.freeze(["request-expired"]);
  }
  return Object.freeze([
    "capability-request-valid",
    "awaiting-trust-evaluation",
    "awaiting-policy-evaluation"
  ]);
}

export function createCapabilityGrantDraft(
  input: CapabilityGrantDraftInput
): CapabilityGrantDraftResult {
  const validationResult = validateCapabilityGrantDraftInput(input);
  if (!validationResult.valid) {
    return runtimeDenied(malformedDraftError(validationResult.errors));
  }

  const status = deriveDraftStatus(input);
  const outcome = input.outcome ?? (status === "expired" ? "expired" : "draft_created");
  const requestedAt = input.capabilityRequest.requestedAt;
  const expiresAt = input.capabilityRequest.scope?.expiresAt;
  const createdAt = input.createdAt ?? new Date().toISOString();
  const auditCorrelationId = input.auditCorrelationId ?? createAuditCorrelationId([
    input.capabilityRequest.applicationId,
    input.sessionId ?? "",
    input.capabilityRequest.requestId,
    input.capabilityRequest.capability,
    "capability-grant-draft"
  ]);

  const redactedScope = input.capabilityRequest.scope
    ? redactRuntimeMetadata(input.capabilityRequest.scope).value as CapabilityScope
    : undefined;
  const redactedMetadata = input.metadata
    ? redactRuntimeMetadata(input.metadata).value as Readonly<Record<string, unknown>>
    : undefined;

  const draft: CapabilityGrantDraft = Object.freeze({
    capabilityGrantDraftId: `${auditCorrelationId}:draft`,
    capabilityRequestId: input.capabilityRequest.requestId,
    capabilityName: input.capabilityRequest.capability,
    applicationId: input.capabilityRequest.applicationId,
    sessionId: input.sessionId,
    scope: redactedScope ? freezeRecord(redactedScope) : undefined,
    constraints: Object.freeze([...(input.constraints ?? [])].map(freezeRecord)),
    requirements: Object.freeze([...(input.requirements ?? [])].map(freezeRecord)),
    requestedAt,
    expiresAt,
    status,
    outcome,
    reasons: deriveReasons(status),
    requiredTrustLevel: input.requiredTrustLevel,
    proofRequirement: input.proofRequirement,
    auditCorrelationId,
    humanReadableSummary: input.humanReadableSummary
      ?? `Capability request ${input.capabilityRequest.requestId} is structurally valid and awaiting future evaluation.`,
    createdAt,
    metadata: redactedMetadata,
    providesAuthority: false,
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

function freezeDraft(draft: CapabilityGrantDraft): CapabilityGrantDraft {
  return freezeRecord(draft);
}

function matchesFilter(
  draft: CapabilityGrantDraft,
  filter: CapabilityGrantDraftFilter
): boolean {
  if (
    filter.capabilityGrantDraftId !== undefined
    && draft.capabilityGrantDraftId !== filter.capabilityGrantDraftId
  ) return false;
  if (
    filter.capabilityRequestId !== undefined
    && draft.capabilityRequestId !== filter.capabilityRequestId
  ) return false;
  if (filter.capabilityName !== undefined && draft.capabilityName !== filter.capabilityName) {
    return false;
  }
  if (filter.applicationId !== undefined && draft.applicationId !== filter.applicationId) {
    return false;
  }
  if (filter.sessionId !== undefined && draft.sessionId !== filter.sessionId) return false;
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

export function createInMemoryCapabilityGrantDraftCollector(
  options: InMemoryCapabilityGrantDraftCollectorOptions = {}
): CapabilityGrantDraftCollector {
  const maxDraftCount = normalizeMaxDraftCount(options.maxDraftCount);
  const drafts = new Map<string, CapabilityGrantDraft>();

  function getAll(): readonly CapabilityGrantDraft[] {
    return Object.freeze(Array.from(drafts.values()));
  }

  function collection(): CapabilityGrantDraftCollection {
    return Object.freeze({
      drafts: getAll(),
      count: drafts.size,
      maxDraftCount
    });
  }

  function filterDrafts(
    filter: CapabilityGrantDraftFilter
  ): readonly CapabilityGrantDraft[] {
    return Object.freeze(getAll().filter((draft) => matchesFilter(draft, filter)));
  }

  return {
    addDraft(draft) {
      const validationResult = validateCapabilityGrantDraftShape(draft);
      if (!validationResult.valid) {
        return {
          status: "rejected_invalid",
          collection: collection(),
          errors: validationResult.errors,
          reason: "Only valid capability grant drafts may be collected."
        };
      }

      if (drafts.has(draft.capabilityGrantDraftId)) {
        return {
          status: "rejected_duplicate",
          draft: drafts.get(draft.capabilityGrantDraftId),
          collection: collection(),
          reason: "Capability grant draft IDs must be unique within an in-memory collector."
        };
      }

      const evictedDrafts: CapabilityGrantDraft[] = [];
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
      drafts.set(storedDraft.capabilityGrantDraftId, storedDraft);

      return {
        status: evictedDrafts.length > 0 ? "evicted_oldest" : "collected",
        draft: storedDraft,
        evictedDrafts: Object.freeze(evictedDrafts),
        collection: collection()
      };
    },
    removeDraft(capabilityGrantDraftId) {
      const removedDraft = drafts.get(capabilityGrantDraftId);
      if (!removedDraft) {
        return {
          status: "not_found",
          collection: collection(),
          reason: "No capability grant draft with that ID exists in this in-memory collector."
        };
      }
      drafts.delete(capabilityGrantDraftId);
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
    getById(capabilityGrantDraftId) {
      return drafts.get(capabilityGrantDraftId);
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

function freezeGroupMap(groups: Record<string, CapabilityGrantDraft[]>): CapabilityGrantDraftGroupMap {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(groups).map(([key, value]) => [key, Object.freeze([...value])])
    )
  );
}

function groupCapabilityDraftsBy(
  drafts: readonly CapabilityGrantDraft[],
  keyForDraft: (draft: CapabilityGrantDraft) => string
): CapabilityGrantDraftGroupMap {
  const groups: Record<string, CapabilityGrantDraft[]> = {};
  for (const draft of drafts) {
    const key = keyForDraft(draft);
    groups[key] ??= [];
    groups[key].push(draft);
  }
  return freezeGroupMap(groups);
}

function countGroups(groups: CapabilityGrantDraftGroupMap): Readonly<Record<string, number>> {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(groups).map(([key, value]) => [key, value.length])
    )
  );
}

function isExpiredCapabilityGrantDraft(draft: CapabilityGrantDraft): boolean {
  return draft.status === "expired"
    || (draft.expiresAt !== undefined && Date.parse(draft.expiresAt) <= Date.now());
}

function isPendingCapabilityGrantDraft(draft: CapabilityGrantDraft): boolean {
  if (isExpiredCapabilityGrantDraft(draft)) {
    return false;
  }
  return draft.status === "draft_created"
    || draft.status === "pending_policy"
    || draft.status === "pending_trust"
    || draft.status === "pending_user_approval";
}

function draftCreationRange(drafts: readonly CapabilityGrantDraft[]): {
  readonly earliestCreatedAt?: string;
  readonly latestCreatedAt?: string;
} {
  const createdAtValues = drafts.map((draft) => draft.createdAt).filter(Boolean).sort();
  return {
    earliestCreatedAt: createdAtValues[0],
    latestCreatedAt: createdAtValues[createdAtValues.length - 1]
  };
}

export function groupCapabilityGrantDraftsByApplication(
  collector: CapabilityGrantDraftCollector
): CapabilityGrantDraftGroupMap {
  return groupCapabilityDraftsBy(collector.getAll(), (draft) => draft.applicationId);
}

export function groupCapabilityGrantDraftsBySession(
  collector: CapabilityGrantDraftCollector
): CapabilityGrantDraftGroupMap {
  return groupCapabilityDraftsBy(collector.getAll(), (draft) => draft.sessionId ?? "no-session");
}

export function groupCapabilityGrantDraftsByCapability(
  collector: CapabilityGrantDraftCollector
): CapabilityGrantDraftGroupMap {
  return groupCapabilityDraftsBy(collector.getAll(), (draft) => draft.capabilityName);
}

export function groupCapabilityGrantDraftsByStatus(
  collector: CapabilityGrantDraftCollector
): CapabilityGrantDraftGroupMap {
  return groupCapabilityDraftsBy(collector.getAll(), (draft) => draft.status);
}

export function getExpiredCapabilityGrantDrafts(
  collector: CapabilityGrantDraftCollector
): readonly CapabilityGrantDraft[] {
  return Object.freeze(collector.getAll().filter(isExpiredCapabilityGrantDraft));
}

export function getPendingCapabilityGrantDrafts(
  collector: CapabilityGrantDraftCollector
): readonly CapabilityGrantDraft[] {
  return Object.freeze(collector.getAll().filter(isPendingCapabilityGrantDraft));
}

export function summarizeCapabilityGrantDrafts(
  collector: CapabilityGrantDraftCollector
): CapabilityGrantDraftReviewSummary {
  const drafts = collector.getAll();
  const byApplication = groupCapabilityGrantDraftsByApplication(collector);
  const bySession = groupCapabilityGrantDraftsBySession(collector);
  const byCapability = groupCapabilityGrantDraftsByCapability(collector);
  const byStatus = groupCapabilityGrantDraftsByStatus(collector);
  const creationRange = draftCreationRange(drafts);

  return Object.freeze({
    totalDraftCount: drafts.length,
    draftsByApplication: countGroups(byApplication),
    draftsBySession: countGroups(bySession),
    draftsByCapability: countGroups(byCapability),
    draftsByStatus: countGroups(byStatus),
    expiredDrafts: getExpiredCapabilityGrantDrafts(collector),
    pendingDrafts: getPendingCapabilityGrantDrafts(collector),
    earliestCreatedAt: creationRange.earliestCreatedAt,
    latestCreatedAt: creationRange.latestCreatedAt,
    providesAuthority: false
  });
}
