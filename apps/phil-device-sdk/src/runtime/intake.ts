import {
  runtimeDenied,
  runtimeFailed,
  runtimeOk,
  validateAdapterManifestShape,
  validateApplicationManifestShape,
  validateCapabilityRequestShape,
  validateIntentShape,
  validateRuntimeRequestContextShape
} from "./helpers.ts";
import type {
  AdapterManifest,
  ApplicationManifest,
  CapabilityRequest,
  Intent,
  RuntimeErrorDescriptor,
  RuntimeRequestContext,
  RuntimeResult
} from "./types.ts";

export type RuntimeRequestKind =
  | "capability"
  | "intent"
  | "application-registration"
  | "adapter-registration"
  | "generic";

export type RuntimeIntakeIssueCode =
  | "missing_request_kind"
  | "unknown_request_kind"
  | "missing_context"
  | "invalid_context"
  | "invalid_intent_shape"
  | "invalid_capability_shape"
  | "invalid_application_manifest_shape"
  | "invalid_adapter_manifest_shape"
  | "expired_intent_shape"
  | "missing_required_id";

export interface RuntimeIntakeValidationIssue {
  readonly code: RuntimeIntakeIssueCode;
  readonly message: string;
  readonly path?: string;
}

export interface RuntimeIntakeValidationReport {
  readonly valid: boolean;
  readonly issues: readonly RuntimeIntakeValidationIssue[];
}

export interface RuntimeRequestEnvelope {
  readonly kind?: RuntimeRequestKind | string;
  readonly context?: RuntimeRequestContext;
  readonly intent?: Intent;
  readonly capabilityRequest?: CapabilityRequest;
  readonly applicationManifest?: ApplicationManifest;
  readonly adapterManifest?: AdapterManifest;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface RuntimeIntakeInput {
  readonly envelope: RuntimeRequestEnvelope;
}

export type RuntimeIntakeResult = RuntimeResult<RuntimeIntakeValidationReport>;

const KNOWN_REQUEST_KINDS = new Set<RuntimeRequestKind>([
  "capability",
  "intent",
  "application-registration",
  "adapter-registration",
  "generic"
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function addIssues(
  issues: RuntimeIntakeValidationIssue[],
  code: RuntimeIntakeIssueCode,
  path: string,
  messages: readonly string[]
): void {
  for (const message of messages) {
    issues.push({ code, path, message });
  }
}

function malformedRequestError(
  message: string,
  details: Readonly<Record<string, unknown>>
): RuntimeErrorDescriptor {
  return {
    category: "invalid_intent",
    code: "RUNTIME_INTAKE_SHAPE_INVALID",
    message,
    boundary: "runtime-api",
    recoverable: true,
    details
  };
}

function report(issues: readonly RuntimeIntakeValidationIssue[]): RuntimeIntakeValidationReport {
  return {
    valid: issues.length === 0,
    issues
  };
}

export function validateRuntimeRequestIntake(
  envelope: RuntimeRequestEnvelope
): RuntimeIntakeResult {
  const issues: RuntimeIntakeValidationIssue[] = [];

  if (!isRecord(envelope)) {
    return runtimeFailed(malformedRequestError("runtime request envelope must be an object", {
      issueCodes: ["missing_required_id"]
    }));
  }

  if (typeof envelope.kind !== "string" || envelope.kind.trim() === "") {
    issues.push({
      code: "missing_request_kind",
      path: "kind",
      message: "request kind is required"
    });
  } else if (!KNOWN_REQUEST_KINDS.has(envelope.kind as RuntimeRequestKind)) {
    issues.push({
      code: "unknown_request_kind",
      path: "kind",
      message: `unknown request kind: ${envelope.kind}`
    });
  }

  if (envelope.context === undefined) {
    issues.push({
      code: "missing_context",
      path: "context",
      message: "runtime request context is required"
    });
  } else {
    const context = validateRuntimeRequestContextShape(envelope.context);
    if (!context.valid) {
      addIssues(issues, "invalid_context", "context", context.errors);
    }
  }

  if (envelope.intent !== undefined) {
    const intent = validateIntentShape(envelope.intent);
    if (!intent.valid) {
      const hasExpiredIntent = intent.errors.includes("expiresAt must be in the future");
      addIssues(
        issues,
        hasExpiredIntent ? "expired_intent_shape" : "invalid_intent_shape",
        "intent",
        intent.errors
      );
    }
  }

  if (envelope.capabilityRequest !== undefined) {
    const capability = validateCapabilityRequestShape(envelope.capabilityRequest);
    if (!capability.valid) {
      addIssues(issues, "invalid_capability_shape", "capabilityRequest", capability.errors);
    }
  }

  if (envelope.applicationManifest !== undefined) {
    const application = validateApplicationManifestShape(envelope.applicationManifest);
    if (!application.valid) {
      addIssues(
        issues,
        "invalid_application_manifest_shape",
        "applicationManifest",
        application.errors
      );
    }
  }

  if (envelope.adapterManifest !== undefined) {
    const adapter = validateAdapterManifestShape(envelope.adapterManifest);
    if (!adapter.valid) {
      addIssues(issues, "invalid_adapter_manifest_shape", "adapterManifest", adapter.errors);
    }
  }

  const validationReport = report(issues);
  if (validationReport.valid) {
    return runtimeOk(validationReport);
  }

  return runtimeDenied(malformedRequestError("runtime request intake failed shape validation", {
    issueCodes: issues.map((issue) => issue.code),
    issues
  }));
}

export function validateCapabilityRequestIntake(
  envelope: RuntimeRequestEnvelope
): RuntimeIntakeResult {
  return validateRuntimeRequestIntake({
    ...envelope,
    kind: envelope.kind ?? "capability"
  });
}

export function validateIntentRequestIntake(
  envelope: RuntimeRequestEnvelope
): RuntimeIntakeResult {
  return validateRuntimeRequestIntake({
    ...envelope,
    kind: envelope.kind ?? "intent"
  });
}

export function validateApplicationRegistrationIntake(
  envelope: RuntimeRequestEnvelope
): RuntimeIntakeResult {
  return validateRuntimeRequestIntake({
    ...envelope,
    kind: envelope.kind ?? "application-registration"
  });
}

export function validateAdapterRegistrationIntake(
  envelope: RuntimeRequestEnvelope
): RuntimeIntakeResult {
  return validateRuntimeRequestIntake({
    ...envelope,
    kind: envelope.kind ?? "adapter-registration"
  });
}
