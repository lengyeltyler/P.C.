import type { RuntimeValidationResult } from "./helpers.ts";

export type RuntimeSensitiveFieldName =
  | "phil_secret"
  | "privateKey"
  | "private_key"
  | "seed"
  | "seedPhrase"
  | "mnemonic"
  | "password"
  | "passphrase"
  | "secret"
  | "vaultKey"
  | "rawVaultKey"
  | "signingKey"
  | "recoverySecret"
  | (string & {});

export type RuntimeRedactionSeverity = "redacted" | "blocked";

export interface RuntimeRedactionIssue {
  readonly path: string;
  readonly fieldName: string;
  readonly severity: RuntimeRedactionSeverity;
  readonly message: string;
}

export interface RuntimeRedactionPolicy {
  readonly mode?: "redact" | "reject";
  readonly sensitiveFieldNames?: readonly RuntimeSensitiveFieldName[];
  readonly redactedValue?: string;
  readonly maxDepth?: number;
  readonly maxIssues?: number;
  readonly maxTraversedNodes?: number;
  readonly maxInspectedProperties?: number;
  readonly maxTotalCharacters?: number;
  readonly maxArrayLength?: number;
}

export interface RuntimeRedactionResult<TValue = unknown> {
  readonly value: TValue;
  readonly issues: readonly RuntimeRedactionIssue[];
  readonly redacted: boolean;
}

const DEFAULT_REDACTED_VALUE = "[REDACTED_RUNTIME_METADATA]";
const DEFAULT_MAX_DEPTH = 4;
const DEFAULT_MAX_ISSUES = 64;
const HARD_MAX_DEPTH = 64;
const HARD_MAX_ISSUES = 256;
const DEFAULT_MAX_TRAVERSED_NODES = 500;
const HARD_MAX_TRAVERSED_NODES = 10_000;
const DEFAULT_MAX_INSPECTED_PROPERTIES = 2_000;
const HARD_MAX_INSPECTED_PROPERTIES = 50_000;
const DEFAULT_MAX_TOTAL_CHARACTERS = 65_536;
const HARD_MAX_TOTAL_CHARACTERS = 1_048_576;
const DEFAULT_MAX_ARRAY_LENGTH = 1_000;
const HARD_MAX_ARRAY_LENGTH = 100_000;
const SENSITIVE_FIELD_MESSAGE =
  "metadata key matches a reserved sensitive runtime field name";
const MAX_DEPTH_MESSAGE =
  "metadata traversal exceeded maxDepth; subtree was replaced";
const CYCLE_MESSAGE =
  "metadata cycle detected; cyclic edge was replaced";
const UNSUPPORTED_VALUE_MESSAGE =
  "metadata value type is unsupported; subtree was replaced";
const UNSUPPORTED_PROPERTY_MESSAGE =
  "metadata property shape is unsupported; property was omitted";
const ACCESSOR_MESSAGE =
  "metadata accessor was not evaluated; value was replaced";
const REFLECTION_MESSAGE =
  "metadata reflection failed; subtree was replaced";
const MAX_ISSUES_MESSAGE =
  "metadata issue reporting limit reached; additional issues were suppressed";
const MAX_TRAVERSED_NODES_MESSAGE =
  "metadata traversal exceeded maxTraversedNodes; remaining metadata was omitted";
const MAX_INSPECTED_PROPERTIES_MESSAGE =
  "metadata traversal exceeded maxInspectedProperties; remaining metadata was omitted";
const MAX_TOTAL_CHARACTERS_MESSAGE =
  "metadata traversal exceeded maxTotalCharacters; remaining metadata was omitted";
const MAX_ARRAY_LENGTH_MESSAGE =
  "array length exceeded maxArrayLength; array was replaced";
const REDACTED_VALUE_INVALID_MESSAGE =
  "redactedValue was not a string and the default placeholder was used";

const DEFAULT_SENSITIVE_FIELD_NAMES: readonly RuntimeSensitiveFieldName[] = [
  "phil_secret",
  "privateKey",
  "private_key",
  "seed",
  "seedPhrase",
  "mnemonic",
  "password",
  "passphrase",
  "secret",
  "vaultKey",
  "rawVaultKey",
  "signingKey",
  "recoverySecret"
];

function normalizedFieldName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/gu, "");
}

interface NormalizedRuntimeRedactionPolicy {
  readonly mode: "redact" | "reject";
  readonly redactedValue: string;
  readonly maxDepth: number;
  readonly maxIssues: number;
  readonly maxTraversedNodes: number;
  readonly maxInspectedProperties: number;
  readonly maxTotalCharacters: number;
  readonly maxArrayLength: number;
  readonly sensitiveFieldNames: ReadonlySet<string>;
  readonly policyIssues: readonly RuntimeRedactionIssue[];
}

interface RuntimeRedactionTraversal {
  readonly policy: NormalizedRuntimeRedactionPolicy;
  readonly reporter: RuntimeIssueReporter;
  readonly ancestors: WeakSet<object>;
  changed: boolean;
  traversedNodes: number;
  inspectedProperties: number;
  totalCharacters: number;
  halted: boolean;
}

interface RuntimeIssueReporter {
  readonly issues: readonly RuntimeRedactionIssue[];
  add(issue: RuntimeRedactionIssue): void;
}

interface ContainerInspection {
  readonly kind?: "array" | "object";
  readonly prototype?: object | null;
  readonly reflectionFailed: boolean;
}

function isSensitiveFieldName(
  fieldName: string,
  policy: NormalizedRuntimeRedactionPolicy
): boolean {
  const normalized = normalizedFieldName(fieldName);
  return Array.from(policy.sensitiveFieldNames).some(
    (sensitive) => normalized === sensitive || normalized.includes(sensitive)
  );
}

function issueSeverity(mode: "redact" | "reject"): RuntimeRedactionSeverity {
  return mode === "reject" ? "blocked" : "redacted";
}

function policyIssue(
  mode: "redact" | "reject",
  fieldName: string,
  message: string
): RuntimeRedactionIssue {
  return Object.freeze({
    path: "$",
    fieldName,
    severity: issueSeverity(mode),
    message
  });
}

function normalizeResourceBudgetField(
  policyIssues: RuntimeRedactionIssue[],
  mode: "redact" | "reject",
  rawValue: unknown,
  fieldName: string,
  defaultValue: number,
  hardMax: number
): number {
  if (rawValue === undefined) {
    return defaultValue;
  }
  if (
    typeof rawValue === "number"
      && Number.isFinite(rawValue)
      && Number.isInteger(rawValue)
      && rawValue >= 0
      && rawValue <= hardMax
  ) {
    return rawValue;
  }
  if (
    typeof rawValue === "number"
      && Number.isFinite(rawValue)
      && Number.isInteger(rawValue)
      && rawValue > hardMax
  ) {
    policyIssues.push(policyIssue(
      mode,
      `<policy.${fieldName}>`,
      `${fieldName} exceeded the hard maximum and was normalized to ${hardMax}`
    ));
    return hardMax;
  }
  policyIssues.push(policyIssue(
    mode,
    `<policy.${fieldName}>`,
    `${fieldName} was invalid and was normalized to ${defaultValue}`
  ));
  return defaultValue;
}

function normalizePolicy(
  policy: RuntimeRedactionPolicy
): NormalizedRuntimeRedactionPolicy {
  const mode = policy.mode ?? "redact";
  const policyIssues: RuntimeRedactionIssue[] = [];
  let maxDepth = DEFAULT_MAX_DEPTH;
  let maxIssues = DEFAULT_MAX_ISSUES;

  if (policy.maxDepth !== undefined) {
    if (
      Number.isFinite(policy.maxDepth)
        && Number.isInteger(policy.maxDepth)
        && policy.maxDepth >= 0
        && policy.maxDepth <= HARD_MAX_DEPTH
    ) {
      maxDepth = policy.maxDepth;
    } else if (
      Number.isFinite(policy.maxDepth)
        && Number.isInteger(policy.maxDepth)
        && policy.maxDepth > HARD_MAX_DEPTH
    ) {
      maxDepth = HARD_MAX_DEPTH;
      policyIssues.push(policyIssue(
        mode,
        "<policy.maxDepth>",
        `maxDepth exceeded the hard maximum and was normalized to ${HARD_MAX_DEPTH}`
      ));
    } else {
      policyIssues.push(policyIssue(
        mode,
        "<policy.maxDepth>",
        `maxDepth was invalid and was normalized to ${DEFAULT_MAX_DEPTH}`
      ));
    }
  }

  if (policy.maxIssues !== undefined) {
    if (
      Number.isFinite(policy.maxIssues)
        && Number.isInteger(policy.maxIssues)
        && policy.maxIssues >= 1
        && policy.maxIssues <= HARD_MAX_ISSUES
    ) {
      maxIssues = policy.maxIssues;
    } else if (
      Number.isFinite(policy.maxIssues)
        && Number.isInteger(policy.maxIssues)
        && policy.maxIssues > HARD_MAX_ISSUES
    ) {
      maxIssues = HARD_MAX_ISSUES;
      policyIssues.push(policyIssue(
        mode,
        "<policy.maxIssues>",
        `maxIssues exceeded the hard maximum and was normalized to ${HARD_MAX_ISSUES}`
      ));
    } else {
      policyIssues.push(policyIssue(
        mode,
        "<policy.maxIssues>",
        `maxIssues was invalid and was normalized to ${DEFAULT_MAX_ISSUES}`
      ));
    }
  }

  let redactedValue = DEFAULT_REDACTED_VALUE;
  if (policy.redactedValue !== undefined) {
    if (typeof policy.redactedValue === "string") {
      redactedValue = policy.redactedValue;
    } else {
      policyIssues.push(policyIssue(
        mode,
        "<policy.redactedValue>",
        REDACTED_VALUE_INVALID_MESSAGE
      ));
    }
  }

  const maxTraversedNodes = normalizeResourceBudgetField(
    policyIssues,
    mode,
    policy.maxTraversedNodes,
    "maxTraversedNodes",
    DEFAULT_MAX_TRAVERSED_NODES,
    HARD_MAX_TRAVERSED_NODES
  );
  const maxInspectedProperties = normalizeResourceBudgetField(
    policyIssues,
    mode,
    policy.maxInspectedProperties,
    "maxInspectedProperties",
    DEFAULT_MAX_INSPECTED_PROPERTIES,
    HARD_MAX_INSPECTED_PROPERTIES
  );
  const maxTotalCharacters = normalizeResourceBudgetField(
    policyIssues,
    mode,
    policy.maxTotalCharacters,
    "maxTotalCharacters",
    DEFAULT_MAX_TOTAL_CHARACTERS,
    HARD_MAX_TOTAL_CHARACTERS
  );
  const maxArrayLength = normalizeResourceBudgetField(
    policyIssues,
    mode,
    policy.maxArrayLength,
    "maxArrayLength",
    DEFAULT_MAX_ARRAY_LENGTH,
    HARD_MAX_ARRAY_LENGTH
  );

  return {
    mode,
    redactedValue,
    maxDepth,
    maxIssues,
    maxTraversedNodes,
    maxInspectedProperties,
    maxTotalCharacters,
    maxArrayLength,
    sensitiveFieldNames: new Set(
      (policy.sensitiveFieldNames ?? DEFAULT_SENSITIVE_FIELD_NAMES)
        .map(normalizedFieldName)
    ),
    policyIssues: Object.freeze(policyIssues)
  };
}

function createIssueReporter(maxIssues: number): RuntimeIssueReporter {
  const issues: RuntimeRedactionIssue[] = [];
  let aggregateRecorded = false;

  return {
    get issues(): readonly RuntimeRedactionIssue[] {
      return issues;
    },
    add(issue): void {
      if (aggregateRecorded) {
        return;
      }

      if (issues.length < maxIssues) {
        issues.push(Object.freeze({ ...issue }));
        return;
      }

      issues[issues.length - 1] = Object.freeze({
        path: issue.path,
        fieldName: "<maxIssues>",
        severity: issue.severity,
        message: MAX_ISSUES_MESSAGE
      });
      aggregateRecorded = true;
    }
  };
}

function isSupportedScalar(value: unknown): boolean {
  if (value === null) return true;
  return ["string", "boolean", "number", "bigint", "undefined"]
    .includes(typeof value);
}

function inspectContainer(value: unknown): ContainerInspection {
  try {
    if (Array.isArray(value)) {
      return { kind: "array", prototype: Array.prototype, reflectionFailed: false };
    }
    if (value === null || typeof value !== "object") {
      return { reflectionFailed: false };
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype === Object.prototype || prototype === null) {
      return { kind: "object", prototype, reflectionFailed: false };
    }
    return { reflectionFailed: false };
  } catch {
    return { reflectionFailed: true };
  }
}

function pathForObjectKey(path: string, key: string): string {
  return path ? `${path}.${key}` : key;
}

function isCanonicalArrayIndex(key: string): boolean {
  if (key === "") return false;
  const index = Number(key);
  return Number.isInteger(index)
    && index >= 0
    && index < 4_294_967_295
    && String(index) === key;
}

function pathForArrayKey(path: string, key: string): string {
  if (isCanonicalArrayIndex(key)) {
    return `${path}[${key}]`;
  }
  return pathForObjectKey(path, key);
}

function traversalIssue(
  traversal: RuntimeRedactionTraversal,
  path: string,
  fieldName: string,
  message: string
): void {
  traversal.reporter.add({
    path: path || "$",
    fieldName,
    severity: issueSeverity(traversal.policy.mode),
    message
  });
}

function haltTraversal(
  traversal: RuntimeRedactionTraversal,
  path: string,
  fieldName: string,
  message: string
): void {
  if (traversal.halted) return;
  traversal.halted = true;
  traversal.changed = true;
  traversalIssue(traversal, path, fieldName, message);
}

function chargeTraversedNode(
  traversal: RuntimeRedactionTraversal,
  path: string
): boolean {
  if (traversal.halted) return false;
  if (traversal.traversedNodes >= traversal.policy.maxTraversedNodes) {
    haltTraversal(traversal, path, "<maxTraversedNodes>", MAX_TRAVERSED_NODES_MESSAGE);
    return false;
  }
  traversal.traversedNodes += 1;
  return true;
}

function chargeInspectedProperty(
  traversal: RuntimeRedactionTraversal,
  path: string
): boolean {
  if (traversal.halted) return false;
  if (traversal.inspectedProperties >= traversal.policy.maxInspectedProperties) {
    haltTraversal(traversal, path, "<maxInspectedProperties>", MAX_INSPECTED_PROPERTIES_MESSAGE);
    return false;
  }
  traversal.inspectedProperties += 1;
  return true;
}

function chargeCharacters(
  traversal: RuntimeRedactionTraversal,
  count: number
): boolean {
  // Deliberately does not gate on traversal.halted: this charge is also used to
  // insert the closing replacement for the value that directly triggers a halt
  // (mandatory semantic #8), which must still be attempted. Entry into any *new*
  // work after a halt is already prevented by chargeTraversedNode/chargeInspectedProperty.
  if (traversal.totalCharacters + count > traversal.policy.maxTotalCharacters) {
    return false;
  }
  traversal.totalCharacters += count;
  return true;
}

function chargeReplacementCharacters(
  traversal: RuntimeRedactionTraversal,
  path: string
): string {
  const placeholder = traversal.policy.redactedValue;
  if (chargeCharacters(traversal, placeholder.length)) {
    return placeholder;
  }
  haltTraversal(traversal, path, "<maxTotalCharacters>", MAX_TOTAL_CHARACTERS_MESSAGE);
  return "";
}

function replacement(
  traversal: RuntimeRedactionTraversal,
  path: string,
  fieldName: string,
  message: string
): string {
  traversal.changed = true;
  traversalIssue(traversal, path, fieldName, message);
  return chargeReplacementCharacters(traversal, path);
}

function defineSanitizedProperty(
  output: object,
  key: string,
  value: unknown,
  enumerable: boolean
): void {
  Object.defineProperty(output, key, {
    value,
    enumerable,
    configurable: true,
    writable: true
  });
}

function reflectionFailure(
  kind: "array" | "object",
  prototype: object | null,
  path: string,
  traversal: RuntimeRedactionTraversal,
  isRoot: boolean
): unknown {
  traversal.changed = true;
  traversalIssue(traversal, path, "<reflection>", REFLECTION_MESSAGE);
  if (!isRoot) return chargeReplacementCharacters(traversal, path);
  return kind === "array"
    ? Object.freeze([])
    : Object.freeze(Object.create(prototype));
}

function containerEntryDeniedReplacement(
  kind: "array" | "object",
  prototype: object | null,
  path: string,
  traversal: RuntimeRedactionTraversal,
  isRoot: boolean
): unknown {
  if (!isRoot) return chargeReplacementCharacters(traversal, path);
  return kind === "array"
    ? Object.freeze([])
    : Object.freeze(Object.create(prototype));
}

function sanitizeObject(
  value: object,
  prototype: object | null,
  path: string,
  depth: number,
  traversal: RuntimeRedactionTraversal,
  isRoot: boolean
): unknown {
  const output = Object.create(prototype) as Record<string, unknown>;
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    return reflectionFailure("object", prototype, path, traversal, isRoot);
  }

  traversal.ancestors.add(value);
  for (const key of keys) {
    if (!chargeInspectedProperty(traversal, path)) {
      break;
    }

    if (typeof key !== "string") {
      traversal.changed = true;
      traversalIssue(
        traversal,
        path,
        "<unsupportedProperty>",
        UNSUPPORTED_PROPERTY_MESSAGE
      );
      continue;
    }

    if (!chargeCharacters(traversal, key.length)) {
      haltTraversal(traversal, path, "<maxTotalCharacters>", MAX_TOTAL_CHARACTERS_MESSAGE);
      break;
    }

    const childPath = pathForObjectKey(path, key);
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      traversal.ancestors.delete(value);
      return reflectionFailure("object", prototype, path, traversal, isRoot);
    }
    if (descriptor === undefined) {
      traversal.ancestors.delete(value);
      return reflectionFailure("object", prototype, path, traversal, isRoot);
    }

    let sanitized: unknown;
    if (isSensitiveFieldName(key, traversal.policy)) {
      sanitized = replacement(
        traversal,
        childPath,
        key,
        SENSITIVE_FIELD_MESSAGE
      );
    } else if (!("value" in descriptor)) {
      sanitized = replacement(
        traversal,
        childPath,
        "<accessor>",
        ACCESSOR_MESSAGE
      );
    } else {
      sanitized = sanitizeValue(
        descriptor.value,
        childPath,
        depth + 1,
        traversal,
        false
      );
    }
    defineSanitizedProperty(output, key, sanitized, descriptor.enumerable ?? false);

    if (traversal.halted) break;
  }
  traversal.ancestors.delete(value);
  return Object.freeze(output);
}

function sanitizeArray(
  value: readonly unknown[],
  path: string,
  depth: number,
  traversal: RuntimeRedactionTraversal,
  isRoot: boolean
): unknown {
  if (!chargeInspectedProperty(traversal, path)) {
    return Object.freeze([]);
  }

  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  } catch {
    return reflectionFailure("array", Array.prototype, path, traversal, isRoot);
  }
  if (
    lengthDescriptor === undefined
      || !("value" in lengthDescriptor)
      || !Number.isSafeInteger(lengthDescriptor.value)
      || lengthDescriptor.value < 0
  ) {
    return reflectionFailure("array", Array.prototype, path, traversal, isRoot);
  }

  if (lengthDescriptor.value > traversal.policy.maxArrayLength) {
    return replacement(traversal, path, "<maxArrayLength>", MAX_ARRAY_LENGTH_MESSAGE);
  }

  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    return reflectionFailure("array", Array.prototype, path, traversal, isRoot);
  }

  let output: unknown[];
  try {
    output = new Array(lengthDescriptor.value);
  } catch {
    return reflectionFailure("array", Array.prototype, path, traversal, isRoot);
  }

  traversal.ancestors.add(value);
  for (const key of keys) {
    if (key === "length") continue;

    if (!chargeInspectedProperty(traversal, path)) {
      break;
    }

    if (typeof key !== "string") {
      traversal.changed = true;
      traversalIssue(
        traversal,
        path,
        "<unsupportedProperty>",
        UNSUPPORTED_PROPERTY_MESSAGE
      );
      continue;
    }

    if (!chargeCharacters(traversal, key.length)) {
      haltTraversal(traversal, path, "<maxTotalCharacters>", MAX_TOTAL_CHARACTERS_MESSAGE);
      break;
    }

    const childPath = pathForArrayKey(path, key);
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      traversal.ancestors.delete(value);
      return reflectionFailure("array", Array.prototype, path, traversal, isRoot);
    }
    if (descriptor === undefined) {
      traversal.ancestors.delete(value);
      return reflectionFailure("array", Array.prototype, path, traversal, isRoot);
    }

    let sanitized: unknown;
    if (isSensitiveFieldName(key, traversal.policy)) {
      sanitized = replacement(
        traversal,
        childPath,
        key,
        SENSITIVE_FIELD_MESSAGE
      );
    } else if (!("value" in descriptor)) {
      sanitized = replacement(
        traversal,
        childPath,
        "<accessor>",
        ACCESSOR_MESSAGE
      );
    } else {
      sanitized = sanitizeValue(
        descriptor.value,
        childPath,
        depth + 1,
        traversal,
        false
      );
    }
    defineSanitizedProperty(output, key, sanitized, descriptor.enumerable ?? false);

    if (traversal.halted) break;
  }
  traversal.ancestors.delete(value);
  return Object.freeze(output);
}

function sanitizeValue(
  value: unknown,
  path: string,
  depth: number,
  traversal: RuntimeRedactionTraversal,
  isRoot: boolean
): unknown {
  if (isSupportedScalar(value)) {
    if (typeof value === "string") {
      if (chargeCharacters(traversal, value.length)) {
        return value;
      }
      // The original string does not fit in the remaining character budget:
      // this is itself a global-budget exhaustion event, so halt traversal
      // here exactly once -- regardless of whether the smaller fail-closed
      // placeholder happens to fit -- then attempt the charged replacement
      // through the shared helper, which records no further issue whether
      // the placeholder fits or not (haltTraversal is a no-op once halted).
      haltTraversal(traversal, path, "<maxTotalCharacters>", MAX_TOTAL_CHARACTERS_MESSAGE);
      return chargeReplacementCharacters(traversal, path);
    }
    return value;
  }

  if (depth > traversal.policy.maxDepth) {
    return replacement(
      traversal,
      path,
      "<maxDepth>",
      MAX_DEPTH_MESSAGE
    );
  }

  const inspection = inspectContainer(value);
  if (inspection.reflectionFailed) {
    traversal.changed = true;
    traversalIssue(traversal, path, "<reflection>", REFLECTION_MESSAGE);
    if (!isRoot) return chargeReplacementCharacters(traversal, path);
    return Object.freeze({});
  }
  if (inspection.kind === undefined) {
    traversal.changed = true;
    traversalIssue(
      traversal,
      path,
      "<unsupportedValue>",
      UNSUPPORTED_VALUE_MESSAGE
    );
    if (isRoot) {
      const error = new TypeError("$: runtime metadata root is unsupported");
      error.name = "RuntimeMetadataRootRejectedError";
      throw error;
    }
    return chargeReplacementCharacters(traversal, path);
  }

  const objectValue = value as object;
  if (traversal.ancestors.has(objectValue)) {
    return replacement(traversal, path, "<cycle>", CYCLE_MESSAGE);
  }

  if (!chargeTraversedNode(traversal, path)) {
    return containerEntryDeniedReplacement(
      inspection.kind,
      inspection.prototype === undefined ? Object.prototype : inspection.prototype,
      path,
      traversal,
      isRoot
    );
  }

  return inspection.kind === "array"
    ? sanitizeArray(
      value as readonly unknown[],
      path,
      depth,
      traversal,
      isRoot
    )
    : sanitizeObject(
      objectValue,
      inspection.prototype === undefined
        ? Object.prototype
        : inspection.prototype,
      path,
      depth,
      traversal,
      isRoot
    );
}

function sanitizeMetadata(
  metadata: unknown,
  policy: RuntimeRedactionPolicy,
  rejectUnsupportedRoot: boolean
): {
  readonly value: unknown;
  readonly issues: readonly RuntimeRedactionIssue[];
  readonly redacted: boolean;
} {
  const normalized = normalizePolicy(policy);
  const reporter = createIssueReporter(normalized.maxIssues);
  for (const issue of normalized.policyIssues) reporter.add(issue);
  const traversal: RuntimeRedactionTraversal = {
    policy: normalized,
    reporter,
    ancestors: new WeakSet(),
    changed: false,
    traversedNodes: 0,
    inspectedProperties: 0,
    totalCharacters: 0,
    halted: false
  };

  let value: unknown;
  try {
    value = sanitizeValue(metadata, "", 0, traversal, true);
  } catch (error) {
    if (rejectUnsupportedRoot) throw error;
    value = normalized.redactedValue;
  }

  return {
    value,
    issues: Object.freeze([...reporter.issues]),
    redacted: traversal.changed || reporter.issues.length > 0
  };
}

export function detectSensitiveMetadataKeys(
  metadata: unknown,
  policy: RuntimeRedactionPolicy = {}
): readonly RuntimeRedactionIssue[] {
  const result = sanitizeMetadata(metadata, {
    ...policy,
    mode: policy.mode ?? "reject"
  }, false);
  return result.issues;
}

export function redactRuntimeMetadata<TValue = unknown>(
  metadata: TValue,
  policy: RuntimeRedactionPolicy = {}
): RuntimeRedactionResult<TValue> {
  const result = sanitizeMetadata(metadata, {
    ...policy,
    mode: policy.mode ?? "redact"
  }, true);

  return {
    value: result.value as TValue,
    issues: result.issues,
    redacted: result.redacted
  };
}

export function validateNoSensitiveMetadataKeys(
  metadata: unknown,
  policy: RuntimeRedactionPolicy = {}
): RuntimeValidationResult {
  const issues = detectSensitiveMetadataKeys(metadata, {
    ...policy,
    mode: "reject"
  });
  return {
    valid: issues.length === 0,
    errors: issues.map((issue) => issue.message === SENSITIVE_FIELD_MESSAGE
      ? `${issue.path} contains sensitive runtime metadata key ${issue.fieldName}`
      : `${issue.path}: ${issue.message}`)
  };
}

export function sanitizeAuditEventDraftInput<TInput extends {
  readonly redactedDetails?: Readonly<Record<string, unknown>>;
}>(
  input: TInput,
  policy: RuntimeRedactionPolicy = {}
): TInput {
  const redactedDetails = input.redactedDetails === undefined
    ? undefined
    : redactRuntimeMetadata(input.redactedDetails, {
      ...policy,
      mode: "redact"
    }).value as Readonly<Record<string, unknown>>;

  return Object.freeze({
    ...input,
    redactedDetails
  });
}
