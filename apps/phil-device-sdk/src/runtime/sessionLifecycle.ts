import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  createAuditCorrelationId,
  createUserSessionContext,
  type RuntimeValidationResult
} from "./helpers.ts";
import {
  redactRuntimeMetadata,
  validateNoSensitiveMetadataKeys
} from "./redaction.ts";
import type {
  UserSessionContext,
  UserSessionContextInput,
  UserSessionContextResult,
  UserSessionContextStatus
} from "./types.ts";

export type UserSessionLifecycleState =
  | "uninitialized"
  | "locked"
  | "unlocking"
  | "partially_unlocked"
  | "unlocked"
  | "suspending"
  | "suspended"
  | "resuming"
  | "expiring"
  | "expired"
  | "recovery_mode"
  | "closing"
  | "closed";

export type UserSessionLifecycleEvent =
  | "initialize"
  | "request_unlock"
  | "unlock_succeeded"
  | "unlock_failed"
  | "request_suspend"
  | "suspend_completed"
  | "request_resume"
  | "resume_succeeded"
  | "resume_failed"
  | "timeout_warning"
  | "timeout_reached"
  | "request_lock"
  | "lock_completed"
  | "request_recovery"
  | "recovery_entered"
  | "recovery_cancelled"
  | "recovery_completed"
  | "request_close"
  | "close_completed";

export type UserSessionTransitionStatus =
  | "transitioned"
  | "rejected"
  | "invalid_request";

export type UserSessionTransitionReason =
  | "initialized"
  | "unlock-requested"
  | "unlock-observed"
  | "unlock-failed"
  | "suspend-requested"
  | "suspend-observed"
  | "resume-requested"
  | "resume-observed"
  | "resume-failed"
  | "timeout-warning-observed"
  | "timeout-reached-observed"
  | "lock-requested"
  | "lock-observed"
  | "recovery-requested"
  | "recovery-observed"
  | "recovery-cancelled"
  | "recovery-completed"
  | "close-requested"
  | "close-observed"
  | "illegal-transition"
  | "invalid-snapshot"
  | "invalid-event"
  | "invalid-evidence-reference"
  | "duplicate-transition-request"
  | (string & {});

export type UserSessionEvidenceReferenceKind =
  | "authentication_evidence"
  | "unlock_evidence"
  | "recovery_evidence"
  | "timeout_source"
  | "user_presence_evidence"
  | (string & {});

export interface UserSessionLifecycleEvidenceReference {
  readonly referenceId: string;
  readonly kind: UserSessionEvidenceReferenceKind;
  readonly source?: string;
  readonly capturedAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly verified: false;
  readonly rawEvidenceIncluded: false;
}

export interface UserSessionLifecycleMetadata {
  readonly createdAt?: string;
  readonly updatedAt?: string;
  readonly lastTransitionAt?: string;
  readonly lastTransitionRequestId?: string;
  readonly lastTransitionEvent?: UserSessionLifecycleEvent;
  readonly lastTransitionReason?: UserSessionTransitionReason;
  readonly timeoutWarningAt?: string;
  readonly timeoutReachedAt?: string;
  readonly lockTimeoutAt?: string;
  readonly suspendedAt?: string;
  readonly recoveryModeEnteredAt?: string;
  readonly lifecycleAuthenticationFactorVerified?: boolean;
  readonly authenticationEvidenceReferenceId?: string;
  readonly deviceVaultUnlocked?: boolean;
  readonly protectedStateAvailable?: boolean;
  readonly activeCapabilitiesAvailable?: false;
  readonly authorizationAvailable?: false;
  readonly vaultHandleId?: string;
  readonly vaultUnlockedAt?: string;
  readonly strongerVaultUnlockRequired?: boolean;
  readonly persisted?: false;
  readonly requestMetadata?: Readonly<Record<string, unknown>>;
}

export interface UserSessionLifecycleLimitation {
  readonly limitationId: string;
  readonly description: string;
}

export interface UserSessionTransitionGuard {
  readonly requiredEvidenceReferences: readonly UserSessionEvidenceReferenceKind[];
  readonly evidenceReferencesVerified: false;
  readonly futureActiveCapabilityRevocationRequired: boolean;
  readonly futureReauthenticationRequired: boolean;
}

export interface UserSessionLifecycleTransitionRule {
  readonly currentState: UserSessionLifecycleState;
  readonly event: UserSessionLifecycleEvent;
  readonly nextState: UserSessionLifecycleState;
  readonly allowed: true;
  readonly requiredEvidenceReferences: readonly UserSessionEvidenceReferenceKind[];
  readonly reason: UserSessionTransitionReason;
  readonly auditCategory: AuditEventDraft["category"];
  readonly futureActiveCapabilityRevocationRequired: boolean;
  readonly futureReauthenticationRequired: boolean;
}

export interface UserSessionLifecycleSnapshot {
  readonly lifecycleId: string;
  readonly sessionId: string;
  readonly state: UserSessionLifecycleState;
  readonly sequence: number;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly lastTransition?: {
    readonly event: UserSessionLifecycleEvent;
    readonly previousState: UserSessionLifecycleState;
    readonly nextState: UserSessionLifecycleState;
    readonly reason: UserSessionTransitionReason;
    readonly transitionedAt: string;
    readonly transitionRequestId?: string;
  };
  readonly metadata?: UserSessionLifecycleMetadata;
  readonly limitations: readonly UserSessionLifecycleLimitation[];
  readonly persisted: false;
  readonly ownsSecrets: false;
  readonly authenticatesUser: false;
  readonly unlocksVault: boolean;
  readonly grantsAuthority: false;
}

export interface UserSessionLifecycle {
  readonly snapshot: UserSessionLifecycleSnapshot;
  readonly transitionTable: readonly UserSessionLifecycleTransitionRule[];
}

export interface UserSessionLifecycleSnapshotInput {
  readonly sessionId: string;
  readonly lifecycleId?: string;
  readonly state?: UserSessionLifecycleState;
  readonly sequence?: number;
  readonly version?: number;
  readonly createdAt?: string;
  readonly updatedAt?: string;
  readonly metadata?: UserSessionLifecycleMetadata;
}

export interface UserSessionTransitionRequest {
  readonly transitionRequestId?: string;
  readonly event: UserSessionLifecycleEvent;
  readonly requestedAt?: string;
  readonly auditCorrelationId?: string;
  readonly evidenceReferences?: readonly UserSessionLifecycleEvidenceReference[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface UserSessionTransitionFutureRequirement {
  readonly requirementId: string;
  readonly evidenceKind: UserSessionEvidenceReferenceKind;
  readonly satisfiedByReference: boolean;
  readonly verified: false;
}

export interface UserSessionTransitionResult {
  readonly status: UserSessionTransitionStatus;
  readonly previousState?: UserSessionLifecycleState;
  readonly nextState?: UserSessionLifecycleState;
  readonly event?: UserSessionLifecycleEvent;
  readonly reason: UserSessionTransitionReason;
  readonly transitionedAt: string;
  readonly auditCorrelationId: string;
  readonly snapshot?: UserSessionLifecycleSnapshot;
  readonly transitionRule?: UserSessionLifecycleTransitionRule;
  readonly guard?: UserSessionTransitionGuard;
  readonly futureRequirements: readonly UserSessionTransitionFutureRequirement[];
  readonly evidenceReferences: readonly UserSessionLifecycleEvidenceReference[];
  readonly evidenceReferencesVerified: false;
  readonly limitations: readonly UserSessionLifecycleLimitation[];
  readonly auditEventDraft?: AuditEventDraft;
  readonly errors?: readonly string[];
}

export interface UserSessionLifecycleStoreInitializeInput
  extends Omit<UserSessionLifecycleSnapshotInput, "state" | "sequence" | "version"> {
  readonly transitionRequestId?: string;
  readonly requestedAt?: string;
  readonly auditCorrelationId?: string;
}

export type EphemeralUserSessionLifecycleStoreStatus =
  | "empty"
  | "initialized"
  | "transitioned"
  | "rejected"
  | "invalid"
  | "replaced"
  | "cleared";

export interface EphemeralUserSessionLifecycleStoreOptions {
  readonly initialSnapshot?: UserSessionLifecycleSnapshot;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export interface EphemeralUserSessionLifecycleStoreState {
  readonly hasSnapshot: boolean;
  readonly sessionId?: string;
  readonly state?: UserSessionLifecycleState;
  readonly sequence?: number;
  readonly snapshot?: UserSessionLifecycleSnapshot;
}

export interface EphemeralUserSessionLifecycleStoreResult {
  readonly status: EphemeralUserSessionLifecycleStoreStatus;
  readonly state: EphemeralUserSessionLifecycleStoreState;
  readonly snapshot?: UserSessionLifecycleSnapshot;
  readonly transitionResult?: UserSessionTransitionResult;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly errors?: readonly string[];
}

export interface EphemeralUserSessionLifecycleStore {
  getSnapshot(): UserSessionLifecycleSnapshot | undefined;
  getState(): EphemeralUserSessionLifecycleStoreState;
  initialize(input: UserSessionLifecycleStoreInitializeInput): EphemeralUserSessionLifecycleStoreResult;
  requestTransition(request: UserSessionTransitionRequest): EphemeralUserSessionLifecycleStoreResult;
  replaceSnapshot(snapshot: UserSessionLifecycleSnapshot): EphemeralUserSessionLifecycleStoreResult;
  clear(): EphemeralUserSessionLifecycleStoreResult;
}

export interface SessionLifecycleContextDerivationInput {
  readonly userSessionContext: UserSessionContext;
  readonly lifecycleSnapshot: UserSessionLifecycleSnapshot;
}

const LIFECYCLE_STATES = new Set<UserSessionLifecycleState>([
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
]);

const LIFECYCLE_EVENTS = new Set<UserSessionLifecycleEvent>([
  "initialize",
  "request_unlock",
  "unlock_succeeded",
  "unlock_failed",
  "request_suspend",
  "suspend_completed",
  "request_resume",
  "resume_succeeded",
  "resume_failed",
  "timeout_warning",
  "timeout_reached",
  "request_lock",
  "lock_completed",
  "request_recovery",
  "recovery_entered",
  "recovery_cancelled",
  "recovery_completed",
  "request_close",
  "close_completed"
]);

const RAW_EVIDENCE_FIELD_NAMES = new Set([
  "assertion",
  "authenticatordata",
  "clientdatajson",
  "evidencepayload",
  "payload",
  "rawevidence",
  "signature",
  "webauthnassertion",
  "worldidproof"
]);

const DEFAULT_LIMITATIONS: readonly UserSessionLifecycleLimitation[] = Object.freeze([
  Object.freeze({
    limitationId: "no_vault_unlock",
    description: "Lifecycle transitions do not unlock Device Vault."
  }),
  Object.freeze({
    limitationId: "no_authentication",
    description: "Lifecycle transitions do not authenticate the user."
  }),
  Object.freeze({
    limitationId: "no_authority",
    description: "Lifecycle transitions do not grant active capability or authorization."
  }),
  Object.freeze({
    limitationId: "evidence_references_unverified",
    description: "Evidence references are identifiers only and are not verified."
  })
]);

export const USER_SESSION_LIFECYCLE_TRANSITION_TABLE: readonly UserSessionLifecycleTransitionRule[] =
  Object.freeze([
    rule("uninitialized", "initialize", "locked", "initialized"),
    rule("locked", "request_unlock", "unlocking", "unlock-requested", [], false, true),
    rule("unlocking", "unlock_succeeded", "unlocked", "unlock-observed", ["unlock_evidence"]),
    rule("unlocking", "unlock_failed", "locked", "unlock-failed"),
    rule("unlocked", "request_suspend", "suspending", "suspend-requested", [], true, true),
    rule("partially_unlocked", "request_suspend", "suspending", "suspend-requested", [], true, true),
    rule("suspending", "suspend_completed", "suspended", "suspend-observed", [], true, true),
    rule("suspended", "request_resume", "resuming", "resume-requested", [], false, true),
    rule("resuming", "resume_succeeded", "unlocked", "resume-observed", ["user_presence_evidence"]),
    rule("resuming", "resume_failed", "suspended", "resume-failed", [], false, true),
    rule("unlocked", "timeout_warning", "expiring", "timeout-warning-observed", ["timeout_source"], false, true),
    rule("expiring", "timeout_reached", "expired", "timeout-reached-observed", ["timeout_source"], true, true),
    rule("unlocked", "timeout_reached", "expired", "timeout-reached-observed", ["timeout_source"], true, true),
    rule("expired", "request_lock", "locked", "lock-requested", [], true, true),
    rule("unlocked", "request_lock", "locked", "lock-requested", [], true, true),
    rule("partially_unlocked", "request_lock", "locked", "lock-requested", [], true, true),
    rule("suspended", "request_lock", "locked", "lock-requested", [], true, true),
    rule("locked", "lock_completed", "locked", "lock-observed", [], true, true),
    rule("locked", "request_recovery", "recovery_mode", "recovery-requested", ["recovery_evidence"], false, true),
    rule("recovery_mode", "recovery_entered", "recovery_mode", "recovery-observed", ["recovery_evidence"], false, true),
    rule("recovery_mode", "recovery_cancelled", "locked", "recovery-cancelled", [], true, true),
    rule("recovery_mode", "recovery_completed", "locked", "recovery-completed", ["recovery_evidence"], true, true),
    rule("locked", "request_close", "closing", "close-requested", [], true, true),
    rule("unlocked", "request_close", "closing", "close-requested", [], true, true),
    rule("suspended", "request_close", "closing", "close-requested", [], true, true),
    rule("expired", "request_close", "closing", "close-requested", [], true, true),
    rule("recovery_mode", "request_close", "closing", "close-requested", [], true, true),
    rule("closing", "close_completed", "closed", "close-observed", [], true, true)
  ]);

function rule(
  currentState: UserSessionLifecycleState,
  event: UserSessionLifecycleEvent,
  nextState: UserSessionLifecycleState,
  reason: UserSessionTransitionReason,
  requiredEvidenceReferences: readonly UserSessionEvidenceReferenceKind[] = [],
  futureActiveCapabilityRevocationRequired = false,
  futureReauthenticationRequired = false
): UserSessionLifecycleTransitionRule {
  return Object.freeze({
    currentState,
    event,
    nextState,
    allowed: true,
    requiredEvidenceReferences: Object.freeze([...requiredEvidenceReferences]),
    reason,
    auditCategory: "runtime",
    futureActiveCapabilityRevocationRequired,
    futureReauthenticationRequired
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function hasValidDateShape(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function normalizeFieldName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
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

function findRawEvidenceFields(value: unknown, path = ""): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findRawEvidenceFields(entry, `${path}[${index}]`));
  }
  if (!isRecord(value)) {
    return [];
  }
  const findings: string[] = [];
  for (const [key, entry] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (RAW_EVIDENCE_FIELD_NAMES.has(normalizeFieldName(key))) {
      findings.push(childPath);
    }
    findings.push(...findRawEvidenceFields(entry, childPath));
  }
  return findings;
}

function transitionRuleFor(
  state: UserSessionLifecycleState,
  event: UserSessionLifecycleEvent
): UserSessionLifecycleTransitionRule | undefined {
  return USER_SESSION_LIFECYCLE_TRANSITION_TABLE.find(
    (entry) => entry.currentState === state && entry.event === event
  );
}

function lifecycleIdFor(sessionId: string): string {
  return `${sessionId}:lifecycle`;
}

function freezeEvidenceReference(
  reference: UserSessionLifecycleEvidenceReference
): UserSessionLifecycleEvidenceReference {
  return Object.freeze({
    referenceId: reference.referenceId,
    kind: reference.kind,
    source: reference.source,
    capturedAt: reference.capturedAt,
    metadata: reference.metadata
      ? freezeRecord(redactRuntimeMetadata(reference.metadata).value)
      : undefined,
    verified: false,
    rawEvidenceIncluded: false
  });
}

function futureRequirements(
  ruleEntry: UserSessionLifecycleTransitionRule | undefined,
  evidenceReferences: readonly UserSessionLifecycleEvidenceReference[]
): readonly UserSessionTransitionFutureRequirement[] {
  return Object.freeze((ruleEntry?.requiredEvidenceReferences ?? []).map((evidenceKind) => Object.freeze({
    requirementId: `${evidenceKind}:reference`,
    evidenceKind,
    satisfiedByReference: evidenceReferences.some((reference) => reference.kind === evidenceKind),
    verified: false
  })));
}

function snapshotLimitations(
  limitations?: readonly UserSessionLifecycleLimitation[]
): readonly UserSessionLifecycleLimitation[] {
  return Object.freeze([...(limitations ?? DEFAULT_LIMITATIONS)].map(freezeRecord));
}

function createLifecycleAuditDraft(
  result: Omit<UserSessionTransitionResult, "auditEventDraft">
): AuditEventDraft | undefined {
  if (!result.event && !result.snapshot) {
    return undefined;
  }

  return createAuditEventDraft({
    category: "runtime",
    outcome: result.status === "transitioned" ? "validation_succeeded" : "validation_failed",
    requestKind: "generic",
    sessionId: result.snapshot?.sessionId,
    summary: result.status === "transitioned"
      ? "User Session lifecycle transition validation completed."
      : "User Session lifecycle transition validation rejected the requested state change.",
    auditCorrelationId: result.auditCorrelationId,
    redactedDetails: {
      transitionStatus: result.status,
      previousState: result.previousState,
      requestedEvent: result.event,
      nextState: result.nextState,
      reason: result.reason,
      transitionSequence: result.snapshot?.sequence,
      evidenceReferenceIds: result.evidenceReferences.map((reference) => reference.referenceId),
      evidenceReferenceKinds: result.evidenceReferences.map((reference) => reference.kind),
      evidenceReferencesVerified: false,
      futureActiveCapabilityRevocationRequired:
        result.guard?.futureActiveCapabilityRevocationRequired,
      futureReauthenticationRequired: result.guard?.futureReauthenticationRequired,
      persisted: false
    }
  });
}

export function isUserSessionLifecycleState(
  value: unknown
): value is UserSessionLifecycleState {
  return LIFECYCLE_STATES.has(value as UserSessionLifecycleState);
}

export function isUserSessionLifecycleEvent(
  value: unknown
): value is UserSessionLifecycleEvent {
  return LIFECYCLE_EVENTS.has(value as UserSessionLifecycleEvent);
}

export function validateUserSessionLifecycleSnapshotShape(
  input: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["user session lifecycle snapshot must be an object"]);
  }
  if (!isNonEmptyString(input.lifecycleId)) {
    errors.push("lifecycleId is required");
  }
  if (!isNonEmptyString(input.sessionId)) {
    errors.push("sessionId is required");
  }
  if (!isUserSessionLifecycleState(input.state)) {
    errors.push("state is invalid");
  }
  if (!Number.isInteger(input.sequence) || Number(input.sequence) < 0) {
    errors.push("sequence must be a non-negative integer");
  }
  if (!Number.isInteger(input.version) || Number(input.version) < 0) {
    errors.push("version must be a non-negative integer");
  }
  if (!hasValidDateShape(input.createdAt)) {
    errors.push("createdAt must be a parseable date string");
  }
  if (!hasValidDateShape(input.updatedAt)) {
    errors.push("updatedAt must be a parseable date string");
  }
  if (input.persisted !== false) {
    errors.push("persisted must be false");
  }
  if (input.ownsSecrets !== false) {
    errors.push("ownsSecrets must be false");
  }
  if (input.authenticatesUser !== false) {
    errors.push("authenticatesUser must be false");
  }
  if (typeof input.unlocksVault !== "boolean") {
    errors.push("unlocksVault must be a boolean");
  }
  if (input.grantsAuthority !== false) {
    errors.push("grantsAuthority must be false");
  }
  if (isRecord(input.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(input.metadata).errors);
  }
  errors.push(...findRawEvidenceFields(input).map((field) => `raw evidence field is not allowed: ${field}`));
  return validation(errors);
}

export function validateUserSessionTransitionRequestShape(
  input: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["user session transition request must be an object"]);
  }
  if (!isUserSessionLifecycleEvent(input.event)) {
    errors.push("event is invalid");
  }
  if (
    input.transitionRequestId !== undefined
    && !isNonEmptyString(input.transitionRequestId)
  ) {
    errors.push("transitionRequestId must be a non-empty string when provided");
  }
  if (input.requestedAt !== undefined && !hasValidDateShape(input.requestedAt)) {
    errors.push("requestedAt must be a parseable date string");
  }
  if (input.evidenceReferences !== undefined && !Array.isArray(input.evidenceReferences)) {
    errors.push("evidenceReferences must be an array when provided");
  }
  if (Array.isArray(input.evidenceReferences)) {
    for (const [index, reference] of input.evidenceReferences.entries()) {
      if (!isRecord(reference)) {
        errors.push(`evidenceReferences[${index}] must be an object`);
        continue;
      }
      if (!isNonEmptyString(reference.referenceId)) {
        errors.push(`evidenceReferences[${index}].referenceId is required`);
      }
      if (!isNonEmptyString(reference.kind)) {
        errors.push(`evidenceReferences[${index}].kind is required`);
      }
      if (reference.capturedAt !== undefined && !hasValidDateShape(reference.capturedAt)) {
        errors.push(`evidenceReferences[${index}].capturedAt must be a parseable date string`);
      }
      if (reference.verified !== false && reference.verified !== undefined) {
        errors.push(`evidenceReferences[${index}].verified must be false`);
      }
      if (
        reference.rawEvidenceIncluded !== false
        && reference.rawEvidenceIncluded !== undefined
      ) {
        errors.push(`evidenceReferences[${index}].rawEvidenceIncluded must be false`);
      }
      if (isRecord(reference.metadata)) {
        errors.push(...validateNoSensitiveMetadataKeys(reference.metadata).errors);
      }
    }
  }
  if (isRecord(input.metadata)) {
    errors.push(...validateNoSensitiveMetadataKeys(input.metadata).errors);
  }
  errors.push(...findRawEvidenceFields(input).map((field) => `raw evidence field is not allowed: ${field}`));
  return validation(errors);
}

export function createUserSessionLifecycleSnapshot(
  input: UserSessionLifecycleSnapshotInput
): UserSessionLifecycleSnapshot {
  const now = new Date().toISOString();
  const state = input.state ?? "uninitialized";
  const createdAt = input.createdAt ?? now;
  const updatedAt = input.updatedAt ?? createdAt;
  const metadata = input.metadata
    ? freezeRecord(redactRuntimeMetadata(input.metadata).value)
    : undefined;

  return freezeRecord({
    lifecycleId: input.lifecycleId ?? lifecycleIdFor(input.sessionId),
    sessionId: input.sessionId,
    state,
    sequence: input.sequence ?? 0,
    version: input.version ?? 0,
    createdAt,
    updatedAt,
    metadata,
    limitations: DEFAULT_LIMITATIONS,
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: false,
    grantsAuthority: false
  });
}

export function transitionUserSessionLifecycle(
  snapshot: UserSessionLifecycleSnapshot,
  request: UserSessionTransitionRequest
): UserSessionTransitionResult {
  const snapshotValidation = validateUserSessionLifecycleSnapshotShape(snapshot);
  const requestValidation = validateUserSessionTransitionRequestShape(request);
  const transitionedAt = request.requestedAt ?? new Date().toISOString();
  const evidenceReferences = Object.freeze(
    [...(Array.isArray(request.evidenceReferences) ? request.evidenceReferences : [])]
      .filter(isRecord)
      .map((reference) => freezeEvidenceReference({
      ...reference,
      referenceId: String(reference.referenceId ?? ""),
      kind: String(reference.kind ?? ""),
      verified: false,
      rawEvidenceIncluded: false
    } as UserSessionLifecycleEvidenceReference))
  );
  const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
    snapshot.sessionId,
    request.transitionRequestId ?? "",
    request.event ?? "invalid-event",
    "session-lifecycle"
  ]);

  if (!snapshotValidation.valid || !requestValidation.valid) {
    const result: Omit<UserSessionTransitionResult, "auditEventDraft"> = freezeRecord({
      status: "invalid_request",
      previousState: snapshot.state,
      nextState: snapshot.state,
      event: isUserSessionLifecycleEvent(request.event) ? request.event : undefined,
      reason: !snapshotValidation.valid ? "invalid-snapshot" : "invalid-event",
      transitionedAt,
      auditCorrelationId,
      snapshot,
      futureRequirements: [],
      evidenceReferences,
      evidenceReferencesVerified: false,
      limitations: snapshotLimitations(snapshot.limitations),
      errors: [...snapshotValidation.errors, ...requestValidation.errors]
    });
    return freezeRecord({
      ...result,
      auditEventDraft: createLifecycleAuditDraft(result)
    });
  }

  const ruleEntry = transitionRuleFor(snapshot.state, request.event);
  if (!ruleEntry) {
    const result: Omit<UserSessionTransitionResult, "auditEventDraft"> = freezeRecord({
      status: "rejected",
      previousState: snapshot.state,
      nextState: snapshot.state,
      event: request.event,
      reason: "illegal-transition",
      transitionedAt,
      auditCorrelationId,
      snapshot,
      futureRequirements: [],
      evidenceReferences,
      evidenceReferencesVerified: false,
      limitations: snapshotLimitations(snapshot.limitations),
      errors: [`transition ${snapshot.state} + ${request.event} is not allowed`]
    });
    return freezeRecord({
      ...result,
      auditEventDraft: createLifecycleAuditDraft(result)
    });
  }

  const redactedRequestMetadata = request.metadata
    ? redactRuntimeMetadata(request.metadata).value as Readonly<Record<string, unknown>>
    : undefined;
  const metadata: UserSessionLifecycleMetadata = freezeRecord({
    ...(snapshot.metadata ?? {}),
    updatedAt: transitionedAt,
    lastTransitionAt: transitionedAt,
    lastTransitionRequestId: request.transitionRequestId,
    lastTransitionEvent: request.event,
    lastTransitionReason: ruleEntry.reason,
    timeoutWarningAt: request.event === "timeout_warning"
      ? transitionedAt
      : snapshot.metadata?.timeoutWarningAt,
    timeoutReachedAt: request.event === "timeout_reached"
      ? transitionedAt
      : snapshot.metadata?.timeoutReachedAt,
    suspendedAt: ruleEntry.nextState === "suspended"
      ? transitionedAt
      : snapshot.metadata?.suspendedAt,
    recoveryModeEnteredAt: ruleEntry.nextState === "recovery_mode"
      ? transitionedAt
      : snapshot.metadata?.recoveryModeEnteredAt,
    requestMetadata: redactedRequestMetadata
      ? {
        ...(snapshot.metadata?.requestMetadata ?? {}),
        ...redactedRequestMetadata
      }
      : snapshot.metadata?.requestMetadata
  });

  const nextSnapshot: UserSessionLifecycleSnapshot = freezeRecord({
    lifecycleId: snapshot.lifecycleId,
    sessionId: snapshot.sessionId,
    state: ruleEntry.nextState,
    sequence: snapshot.sequence + 1,
    version: snapshot.version + 1,
    createdAt: snapshot.createdAt,
    updatedAt: transitionedAt,
    lastTransition: {
      event: request.event,
      previousState: snapshot.state,
      nextState: ruleEntry.nextState,
      reason: ruleEntry.reason,
      transitionedAt,
      transitionRequestId: request.transitionRequestId
    },
    metadata,
    limitations: snapshotLimitations(snapshot.limitations),
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: false,
    grantsAuthority: false
  });

  const guard: UserSessionTransitionGuard = freezeRecord({
    requiredEvidenceReferences: ruleEntry.requiredEvidenceReferences,
    evidenceReferencesVerified: false,
    futureActiveCapabilityRevocationRequired:
      ruleEntry.futureActiveCapabilityRevocationRequired,
    futureReauthenticationRequired: ruleEntry.futureReauthenticationRequired
  });

  const result: Omit<UserSessionTransitionResult, "auditEventDraft"> = freezeRecord({
    status: "transitioned",
    previousState: snapshot.state,
    nextState: ruleEntry.nextState,
    event: request.event,
    reason: ruleEntry.reason,
    transitionedAt,
    auditCorrelationId,
    snapshot: nextSnapshot,
    transitionRule: ruleEntry,
    guard,
    futureRequirements: futureRequirements(ruleEntry, evidenceReferences),
    evidenceReferences,
    evidenceReferencesVerified: false,
    limitations: snapshotLimitations(nextSnapshot.limitations)
  });

  return freezeRecord({
    ...result,
    auditEventDraft: createLifecycleAuditDraft(result)
  });
}

function contextStatusForLifecycleState(
  state: UserSessionLifecycleState
): UserSessionContextStatus {
  if (state === "unlocked") return "unlocked";
  if (state === "partially_unlocked") return "partially-unlocked";
  if (state === "suspended" || state === "suspending" || state === "resuming") {
    return "suspended";
  }
  if (state === "recovery_mode") return "recovery";
  if (state === "expiring") return "unlocked";
  return "locked";
}

export function deriveUserSessionContextFromLifecycle(
  input: SessionLifecycleContextDerivationInput
): UserSessionContextResult {
  const metadata = input.userSessionContext.metadata ?? {};
  const lifecycleMetadata = input.lifecycleSnapshot.metadata;
  const contextInput: UserSessionContextInput = {
    sessionId: input.userSessionContext.sessionId,
    ownerCommitment: input.userSessionContext.ownerCommitment,
    status: contextStatusForLifecycleState(input.lifecycleSnapshot.state),
    activeApplicationId: input.userSessionContext.activeApplicationId,
    activeCapabilityIds: input.userSessionContext.activeCapabilityIds,
    pendingIntentIds: input.userSessionContext.pendingIntentIds,
    policyMode: input.lifecycleSnapshot.state === "recovery_mode"
      ? "recovery"
      : input.userSessionContext.policyMode,
    recoveryState: input.lifecycleSnapshot.state === "recovery_mode"
      ? "active"
      : input.userSessionContext.recoveryState,
    timeout: {
      lockTimeoutAt: lifecycleMetadata?.lockTimeoutAt
        ?? input.userSessionContext.timeout?.lockTimeoutAt,
      suspendedAt: lifecycleMetadata?.suspendedAt
        ?? input.userSessionContext.timeout?.suspendedAt
    },
    metadata: {
      ...metadata,
      updatedAt: input.lifecycleSnapshot.updatedAt,
      lifecycleState: input.lifecycleSnapshot.state,
      lifecycleTransitionSequence: input.lifecycleSnapshot.sequence,
      lastLifecycleTransitionAt: input.lifecycleSnapshot.metadata?.lastTransitionAt,
      requestMetadata: {
        ...(metadata.requestMetadata ?? {}),
        lifecycleState: input.lifecycleSnapshot.state,
        lifecycleTransitionSequence: input.lifecycleSnapshot.sequence,
        lifecycleAuthenticatesUser: false,
        lifecycleUnlocksVault: false,
        lifecycleGrantsAuthority: false
      }
    }
  };

  return createUserSessionContext(contextInput);
}

export function createEphemeralUserSessionLifecycleStore(
  options: EphemeralUserSessionLifecycleStoreOptions = {}
): EphemeralUserSessionLifecycleStore {
  let currentSnapshot: UserSessionLifecycleSnapshot | undefined;
  let lastTransitionRequestId: string | undefined;

  function state(): EphemeralUserSessionLifecycleStoreState {
    return freezeRecord({
      hasSnapshot: currentSnapshot !== undefined,
      sessionId: currentSnapshot?.sessionId,
      state: currentSnapshot?.state,
      sequence: currentSnapshot?.sequence,
      snapshot: currentSnapshot
    });
  }

  function result(
    status: EphemeralUserSessionLifecycleStoreStatus,
    transitionResult?: UserSessionTransitionResult,
    auditDraftCollectionResult?: AuditDraftCollectionResult,
    errors?: readonly string[]
  ): EphemeralUserSessionLifecycleStoreResult {
    return freezeRecord({
      status,
      state: state(),
      snapshot: currentSnapshot,
      transitionResult,
      auditDraftCollectionResult,
      errors
    });
  }

  function collectAuditDraft(
    transitionResult: UserSessionTransitionResult
  ): AuditDraftCollectionResult | undefined {
    if (!transitionResult.auditEventDraft) {
      return undefined;
    }
    return options.auditDraftCollector?.addDraft(transitionResult.auditEventDraft);
  }

  const store: EphemeralUserSessionLifecycleStore = {
    getSnapshot() {
      return currentSnapshot;
    },
    getState() {
      return state();
    },
    initialize(input) {
      const initialSnapshot = createUserSessionLifecycleSnapshot({
        ...input,
        state: "uninitialized",
        sequence: 0,
        version: 0
      });
      const transitionResult = transitionUserSessionLifecycle(initialSnapshot, {
        transitionRequestId: input.transitionRequestId,
        event: "initialize",
        requestedAt: input.requestedAt,
        auditCorrelationId: input.auditCorrelationId
      });
      if (transitionResult.status !== "transitioned" || !transitionResult.snapshot) {
        return result("invalid", transitionResult, collectAuditDraft(transitionResult), transitionResult.errors);
      }
      currentSnapshot = transitionResult.snapshot;
      lastTransitionRequestId = input.transitionRequestId;
      return result("initialized", transitionResult, collectAuditDraft(transitionResult));
    },
    requestTransition(request) {
      if (!currentSnapshot) {
        return result("invalid", undefined, undefined, ["lifecycle store has no snapshot"]);
      }
      if (
        request.transitionRequestId
        && request.transitionRequestId === lastTransitionRequestId
      ) {
        const auditCorrelationId = request.auditCorrelationId ?? createAuditCorrelationId([
          currentSnapshot.sessionId,
          request.transitionRequestId,
          request.event,
          "session-lifecycle"
        ]);
        const duplicateResult: Omit<UserSessionTransitionResult, "auditEventDraft"> = freezeRecord({
          status: "rejected",
          previousState: currentSnapshot.state,
          nextState: currentSnapshot.state,
          event: request.event,
          reason: "duplicate-transition-request",
          transitionedAt: request.requestedAt ?? new Date().toISOString(),
          auditCorrelationId,
          snapshot: currentSnapshot,
          futureRequirements: [],
          evidenceReferences: [],
          evidenceReferencesVerified: false,
          limitations: snapshotLimitations(currentSnapshot.limitations),
          errors: ["duplicate transitionRequestId rejected"]
        });
        const transitionResult = freezeRecord({
          ...duplicateResult,
          auditEventDraft: createLifecycleAuditDraft(duplicateResult)
        });
        return result("rejected", transitionResult, collectAuditDraft(transitionResult), transitionResult.errors);
      }

      const transitionResult = transitionUserSessionLifecycle(currentSnapshot, request);
      const auditDraftCollectionResult = collectAuditDraft(transitionResult);
      if (transitionResult.status === "transitioned" && transitionResult.snapshot) {
        currentSnapshot = transitionResult.snapshot;
        lastTransitionRequestId = request.transitionRequestId;
        return result("transitioned", transitionResult, auditDraftCollectionResult);
      }
      return result(
        transitionResult.status === "invalid_request" ? "invalid" : "rejected",
        transitionResult,
        auditDraftCollectionResult,
        transitionResult.errors
      );
    },
    replaceSnapshot(snapshot) {
      const validationResult = validateUserSessionLifecycleSnapshotShape(snapshot);
      if (!validationResult.valid) {
        return result("invalid", undefined, undefined, validationResult.errors);
      }
      currentSnapshot = freezeRecord(snapshot);
      lastTransitionRequestId = snapshot.metadata?.lastTransitionRequestId;
      return result("replaced");
    },
    clear() {
      currentSnapshot = undefined;
      lastTransitionRequestId = undefined;
      return result("cleared");
    }
  };

  if (options.initialSnapshot) {
    store.replaceSnapshot(options.initialSnapshot);
  }

  return store;
}
