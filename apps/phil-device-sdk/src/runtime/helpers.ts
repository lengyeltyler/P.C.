import type {
  AdapterManifest,
  AdapterStatus,
  ApplicationManifest,
  ApplicationTrustLevel,
  AuditEvent,
  CapabilityGrant,
  CapabilityRequest,
  CapabilitySensitivity,
  Intent,
  IntentKind,
  IntentStatus,
  RuntimeErrorCategory,
  RuntimeErrorDescriptor,
  RuntimeRequestContext,
  RuntimeResult,
  RuntimeResultStatus,
  SessionBoundRuntimeRequestContext,
  UserSessionContext,
  UserSessionContextInput,
  UserSessionContextResult,
  UserSessionContextStatus,
  UserSessionSnapshot,
  UserSessionState
} from "./types.ts";
import {
  redactRuntimeMetadata,
  validateNoSensitiveMetadataKeys
} from "./redaction.ts";

export interface RuntimeValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
}

export interface IntentDraftInput<TPayload = unknown> {
  readonly intentId: string;
  readonly kind: IntentKind;
  readonly applicationId: string;
  readonly requestedCapabilities: readonly string[];
  readonly payload: TPayload;
  readonly status?: IntentStatus;
  readonly createdAt?: string;
  readonly expiresAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface CapabilityRequestDraftInput {
  readonly requestId: string;
  readonly applicationId: string;
  readonly capability: string;
  readonly sensitivity: CapabilitySensitivity;
  readonly scope?: CapabilityRequest["scope"];
  readonly reason?: string;
  readonly requestedAt?: string;
}

export interface RuntimeRequestContextInput {
  readonly requestId: string;
  readonly sessionId?: string;
  readonly applicationId: string;
  readonly requestedAt?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface ApplicationManifestDraftInput {
  readonly applicationId: string;
  readonly displayName: string;
  readonly version: string;
  readonly requestedCapabilities: readonly string[];
  readonly optionalCapabilities?: readonly string[];
  readonly supportedPlatforms?: ApplicationManifest["supportedPlatforms"];
  readonly adapterDependencies?: readonly string[];
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface AdapterManifestDraftInput {
  readonly adapterId: string;
  readonly displayName: string;
  readonly version: string;
  readonly executionEnvironment: AdapterManifest["executionEnvironment"];
  readonly providedCapabilities: readonly string[];
  readonly supportedApplications?: readonly string[];
  readonly requiresAuthorizationPackage: boolean;
  readonly requiresProof?: boolean;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

const INTENT_STATUSES = new Set<IntentStatus>([
  "created",
  "evaluating",
  "approved",
  "denied",
  "expired",
  "cancelled",
  "executed",
  "failed"
]);

const CAPABILITY_DECISIONS = new Set<CapabilityGrant["decision"]>([
  "granted",
  "denied",
  "scoped",
  "expired",
  "revoked",
  "pending"
]);

const USER_SESSION_LOCK_STATES = new Set<UserSessionState["vaultUnlockState"]>([
  "locked",
  "unlocking",
  "unlocked",
  "suspended"
]);

const USER_SESSION_CONTEXT_STATUSES = new Set<UserSessionContextStatus>([
  "locked",
  "partially-unlocked",
  "unlocked",
  "recovery",
  "suspended"
]);

const USER_SESSION_POLICY_MODES = new Set<UserSessionState["policyMode"]>([
  "default",
  "strict",
  "recovery",
  "local-dev"
]);

const USER_SESSION_RECOVERY_STATES = new Set<NonNullable<UserSessionContext["recoveryState"]>>([
  "inactive",
  "available",
  "pending",
  "active",
  "completed"
]);

const APPLICATION_TRUST_LEVELS = new Set<ApplicationTrustLevel>([
  "system",
  "verified",
  "community",
  "developer",
  "experimental"
]);

const ADAPTER_STATUSES = new Set<AdapterStatus>([
  "available",
  "unavailable",
  "disabled",
  "deprecated",
  "experimental"
]);

const RUNTIME_RESULT_STATUSES = new Set<RuntimeResultStatus>([
  "approved",
  "denied",
  "pending",
  "failed"
]);

const RUNTIME_ERROR_CATEGORIES = new Set<RuntimeErrorCategory>([
  "runtime_locked",
  "session_expired",
  "capability_denied",
  "policy_denied",
  "trust_denied",
  "user_cancelled",
  "proof_required",
  "proof_failed",
  "adapter_unavailable",
  "network_unavailable",
  "bundler_unavailable",
  "vault_unavailable",
  "recovery_required",
  "invalid_intent",
  "invalid_authorization_package",
  "unsupported_operation",
  "experimental_feature_disabled"
]);

const CAPABILITY_SENSITIVITIES = new Set<CapabilitySensitivity>([
  "read",
  "sensitive",
  "privileged"
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isStringArray(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.length > 0 && value.every(isNonEmptyString);
}

function isOptionalStringArray(value: unknown): value is readonly string[] | undefined {
  return value === undefined || (Array.isArray(value) && value.every(isNonEmptyString));
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

function requireOptionalDateShape(errors: string[], value: unknown, label: string): void {
  if (value !== undefined && !hasValidDateShape(value)) {
    errors.push(`${label} must be a parseable date string`);
  }
}

export function validateRuntimeRequestContextShape(
  input: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["runtime request context must be an object"]);
  }

  if (!isNonEmptyString(input.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(input.applicationId)) {
    errors.push("applicationId is required");
  }
  if (input.sessionId !== undefined && !isNonEmptyString(input.sessionId)) {
    errors.push("sessionId must be a non-empty string when provided");
  }
  requireOptionalDateShape(errors, input.requestedAt, "requestedAt");

  return validation(errors);
}

export function validateUserSessionContextShape(input: unknown): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["user session context must be an object"]);
  }

  if (!isNonEmptyString(input.sessionId)) {
    errors.push("sessionId is required");
  }
  if (!USER_SESSION_CONTEXT_STATUSES.has(input.status as UserSessionContextStatus)) {
    errors.push("status is invalid");
  }
  if (
    input.activeApplicationId !== undefined
    && !isNonEmptyString(input.activeApplicationId)
  ) {
    errors.push("activeApplicationId must be a non-empty string when provided");
  }
  if (!isOptionalStringArray(input.activeCapabilityIds)) {
    errors.push("activeCapabilityIds must be a string array when provided");
  }
  if (!isOptionalStringArray(input.pendingIntentIds)) {
    errors.push("pendingIntentIds must be a string array when provided");
  }
  if (
    input.policyMode !== undefined
    && !USER_SESSION_POLICY_MODES.has(input.policyMode as UserSessionState["policyMode"])
  ) {
    errors.push("policyMode is invalid");
  }
  if (
    input.recoveryState !== undefined
    && !USER_SESSION_RECOVERY_STATES.has(input.recoveryState as NonNullable<UserSessionContext["recoveryState"]>)
  ) {
    errors.push("recoveryState is invalid");
  }
  if (isRecord(input.timeout)) {
    requireOptionalDateShape(errors, input.timeout.lockTimeoutAt, "timeout.lockTimeoutAt");
    requireOptionalDateShape(errors, input.timeout.suspendedAt, "timeout.suspendedAt");
  }
  if (isRecord(input.metadata)) {
    requireOptionalDateShape(errors, input.metadata.createdAt, "metadata.createdAt");
    requireOptionalDateShape(errors, input.metadata.updatedAt, "metadata.updatedAt");
    requireOptionalDateShape(errors, input.metadata.expiresAt, "metadata.expiresAt");
    requireOptionalDateShape(errors, input.metadata.lockTimeoutAt, "metadata.lockTimeoutAt");
    requireOptionalDateShape(errors, input.metadata.suspendedAt, "metadata.suspendedAt");
    errors.push(...validateNoSensitiveMetadataKeys(input.metadata).errors);
  }

  return validation(errors);
}

export function validateIntentShape(input: unknown): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["intent must be an object"]);
  }

  if (!isNonEmptyString(input.intentId)) {
    errors.push("intentId is required");
  }
  if (!isNonEmptyString(input.kind)) {
    errors.push("kind is required");
  }
  if (!isNonEmptyString(input.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isStringArray(input.requestedCapabilities)) {
    errors.push("requestedCapabilities must be a non-empty string array");
  }
  if (!Object.prototype.hasOwnProperty.call(input, "payload")) {
    errors.push("payload is required");
  }
  if (input.status !== undefined && !isIntentStatus(input.status)) {
    errors.push("status is invalid");
  }
  requireOptionalDateShape(errors, input.createdAt, "createdAt");
  requireOptionalDateShape(errors, input.expiresAt, "expiresAt");
  if (hasValidDateShape(input.expiresAt) && Date.parse(input.expiresAt) <= Date.now()) {
    errors.push("expiresAt must be in the future");
  }

  return validation(errors);
}

export function validateCapabilityRequestShape(input: unknown): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["capability request must be an object"]);
  }

  if (!isNonEmptyString(input.requestId)) {
    errors.push("requestId is required");
  }
  if (!isNonEmptyString(input.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isNonEmptyString(input.capability)) {
    errors.push("capability is required");
  }
  if (!CAPABILITY_SENSITIVITIES.has(input.sensitivity as CapabilitySensitivity)) {
    errors.push("sensitivity is invalid");
  }
  requireOptionalDateShape(errors, input.requestedAt, "requestedAt");
  if (isRecord(input.scope)) {
    requireOptionalDateShape(errors, input.scope.expiresAt, "scope.expiresAt");
  }

  return validation(errors);
}

export function validateApplicationManifestShape(input: unknown): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["application manifest must be an object"]);
  }

  if (!isNonEmptyString(input.applicationId)) {
    errors.push("applicationId is required");
  }
  if (!isNonEmptyString(input.displayName)) {
    errors.push("displayName is required");
  }
  if (!isNonEmptyString(input.version)) {
    errors.push("version is required");
  }
  if (!isStringArray(input.requestedCapabilities)) {
    errors.push("requestedCapabilities must be a non-empty string array");
  }

  return validation(errors);
}

export function validateAdapterManifestShape(input: unknown): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return validation(["adapter manifest must be an object"]);
  }

  if (!isNonEmptyString(input.adapterId)) {
    errors.push("adapterId is required");
  }
  if (!isNonEmptyString(input.displayName)) {
    errors.push("displayName is required");
  }
  if (!isNonEmptyString(input.version)) {
    errors.push("version is required");
  }
  if (!isNonEmptyString(input.executionEnvironment)) {
    errors.push("executionEnvironment is required");
  }
  if (!isStringArray(input.providedCapabilities)) {
    errors.push("providedCapabilities must be a non-empty string array");
  }
  if (typeof input.requiresAuthorizationPackage !== "boolean") {
    errors.push("requiresAuthorizationPackage must be a boolean");
  }

  return validation(errors);
}

export function createIntentDraft<TPayload>(
  input: IntentDraftInput<TPayload>
): Intent<TPayload> {
  return {
    intentId: input.intentId,
    kind: input.kind,
    applicationId: input.applicationId,
    requestedCapabilities: input.requestedCapabilities,
    payload: input.payload,
    status: input.status ?? "created",
    createdAt: input.createdAt,
    expiresAt: input.expiresAt,
    metadata: input.metadata
  };
}

export function createCapabilityRequestDraft(
  input: CapabilityRequestDraftInput
): CapabilityRequest {
  return {
    requestId: input.requestId,
    applicationId: input.applicationId,
    capability: input.capability,
    sensitivity: input.sensitivity,
    scope: input.scope,
    reason: input.reason,
    requestedAt: input.requestedAt
  };
}

export function createRuntimeRequestContext(
  input: RuntimeRequestContextInput
): RuntimeRequestContext {
  const metadata = input.metadata
    ? redactRuntimeMetadata(input.metadata).value as Readonly<Record<string, unknown>>
    : undefined;

  return {
    requestId: input.requestId,
    sessionId: input.sessionId,
    applicationId: input.applicationId,
    requestedAt: input.requestedAt,
    metadata
  };
}

export function createUserSessionContext(
  input: UserSessionContextInput
): UserSessionContextResult {
  const validationResult = validateUserSessionContextShape(input);
  if (!validationResult.valid) {
    return {
      status: "failed",
      errors: validationResult.errors
    };
  }

  const metadata = input.metadata
    ? redactRuntimeMetadata(input.metadata).value as UserSessionContext["metadata"]
    : undefined;

  const context: UserSessionContext = Object.freeze({
    sessionId: input.sessionId,
    ownerCommitment: input.ownerCommitment,
    status: input.status,
    activeApplicationId: input.activeApplicationId,
    activeCapabilityIds: Object.freeze([...(input.activeCapabilityIds ?? [])]),
    pendingIntentIds: Object.freeze([...(input.pendingIntentIds ?? [])]),
    policyMode: input.policyMode ?? "default",
    recoveryState: input.recoveryState,
    timeout: input.timeout ? Object.freeze({ ...input.timeout }) : undefined,
    metadata
  });

  return {
    status: "approved",
    context,
    snapshot: Object.freeze({
      context,
      capturedAt: new Date().toISOString()
    })
  };
}

export function createSessionBoundRuntimeRequestContext(
  input: RuntimeRequestContextInput,
  userSession: UserSessionContext
): SessionBoundRuntimeRequestContext {
  return bindSessionContextToRuntimeRequest(createRuntimeRequestContext(input), userSession);
}

export function bindSessionContextToRuntimeRequest<TContext extends RuntimeRequestContext>(
  context: TContext,
  userSession: UserSessionContext
): TContext & SessionBoundRuntimeRequestContext {
  const contextMetadata = context.metadata
    ? redactRuntimeMetadata(context.metadata).value as Readonly<Record<string, unknown>>
    : {};
  const sessionMetadata = userSession.metadata
    ? redactRuntimeMetadata(userSession.metadata).value
    : undefined;

  return Object.freeze({
    ...context,
    sessionId: context.sessionId ?? userSession.sessionId,
    applicationId: context.applicationId,
    metadata: Object.freeze({
      ...contextMetadata,
      userSession: {
        sessionId: userSession.sessionId,
        ownerCommitment: userSession.ownerCommitment,
        status: userSession.status,
        activeApplicationId: userSession.activeApplicationId,
        activeCapabilityIds: userSession.activeCapabilityIds,
        pendingIntentIds: userSession.pendingIntentIds,
        policyMode: userSession.policyMode,
        recoveryState: userSession.recoveryState,
        timeout: userSession.timeout,
        metadata: sessionMetadata
      }
    }),
    userSession
  });
}

export function createAuditCorrelationId(parts: readonly string[]): string {
  return parts.map((part) => String(part).trim()).filter(Boolean).join(":");
}

export function createApplicationManifestDraft(
  input: ApplicationManifestDraftInput
): ApplicationManifest {
  return {
    applicationId: input.applicationId,
    displayName: input.displayName,
    version: input.version,
    requestedCapabilities: input.requestedCapabilities,
    optionalCapabilities: input.optionalCapabilities,
    supportedPlatforms: input.supportedPlatforms,
    adapterDependencies: input.adapterDependencies,
    metadata: input.metadata
  };
}

export function createAdapterManifestDraft(
  input: AdapterManifestDraftInput
): AdapterManifest {
  return {
    adapterId: input.adapterId,
    displayName: input.displayName,
    version: input.version,
    executionEnvironment: input.executionEnvironment,
    providedCapabilities: input.providedCapabilities,
    supportedApplications: input.supportedApplications,
    requiresAuthorizationPackage: input.requiresAuthorizationPackage,
    requiresProof: input.requiresProof,
    metadata: input.metadata
  };
}

export function isRuntimeErrorCategory(value: unknown): value is RuntimeErrorCategory {
  return RUNTIME_ERROR_CATEGORIES.has(value as RuntimeErrorCategory);
}

export function isIntentStatus(value: unknown): value is IntentStatus {
  return INTENT_STATUSES.has(value as IntentStatus);
}

export function isCapabilityStatus(value: unknown): value is CapabilityGrant["decision"] {
  return CAPABILITY_DECISIONS.has(value as CapabilityGrant["decision"]);
}

export function isUserSessionLockState(
  value: unknown
): value is UserSessionState["vaultUnlockState"] {
  return USER_SESSION_LOCK_STATES.has(value as UserSessionState["vaultUnlockState"]);
}

export function isApplicationTrustLevel(value: unknown): value is ApplicationTrustLevel {
  return APPLICATION_TRUST_LEVELS.has(value as ApplicationTrustLevel);
}

export function isAdapterStatus(value: unknown): value is AdapterStatus {
  return ADAPTER_STATUSES.has(value as AdapterStatus);
}

export function isRuntimeResultStatus(value: unknown): value is RuntimeResultStatus {
  return RUNTIME_RESULT_STATUSES.has(value as RuntimeResultStatus);
}

export function runtimeOk<TValue>(
  value: TValue,
  metadata: {
    readonly auditEventId?: AuditEvent["auditEventId"];
  } = {}
): RuntimeResult<TValue> {
  return {
    status: "approved",
    value,
    auditEventId: metadata.auditEventId
  };
}

export function runtimePending<TValue = never>(
  metadata: {
    readonly value?: TValue;
    readonly pendingApprovalId?: string;
    readonly auditEventId?: AuditEvent["auditEventId"];
  } = {}
): RuntimeResult<TValue> {
  return {
    status: "pending",
    value: metadata.value,
    pendingApprovalId: metadata.pendingApprovalId,
    auditEventId: metadata.auditEventId
  };
}

export function runtimeDenied(
  error: RuntimeErrorDescriptor,
  metadata: {
    readonly auditEventId?: AuditEvent["auditEventId"];
  } = {}
): RuntimeResult<never> {
  return {
    status: "denied",
    error,
    auditEventId: metadata.auditEventId
  };
}

export function runtimeFailed(
  error: RuntimeErrorDescriptor,
  metadata: {
    readonly auditEventId?: AuditEvent["auditEventId"];
  } = {}
): RuntimeResult<never> {
  return {
    status: "failed",
    error,
    auditEventId: metadata.auditEventId
  };
}
