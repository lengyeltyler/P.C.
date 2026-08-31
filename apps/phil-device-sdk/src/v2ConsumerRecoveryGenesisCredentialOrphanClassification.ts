import {
  validatePhilCoreV2GenesisCredentialObligationRecord,
  type PhilCoreV2GenesisCredentialObligationOrphanReason,
  type PhilCoreV2GenesisCredentialObligationRecord
} from "./v2ConsumerRecoveryGenesisCredentialObligation.ts";

// ---------------------------------------------------------------------------
// Pure, dormant genesis credential-orphan classifier.
//
// Converts a validated ORPHANED obligation into a versioned factual
// projection: what durable binding is known, what remains unbound, and
// whether the blocker is an unconsumed creation outcome or a durable
// manifest-binding conflict. It classifies the blocker without resolving it.
//
// The module is pure. It reads no clock, generates no entropy, touches no
// file system, opens no socket, and performs no work when it is first
// evaluated. It delegates exactly once to the landed obligation validator
// and never pre-reads the caller value.
// ---------------------------------------------------------------------------

export const PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_SCHEMA_VERSION =
  1 as const;
export const PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_FORMAT_PROVENANCE =
  "PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_V1" as const;

const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

export const PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CONDITION = Object.freeze({
  UNCONSUMED_CREATION_OUTCOME: "UNCONSUMED_CREATION_OUTCOME",
  DURABLE_MANIFEST_BINDING_CONFLICT: "DURABLE_MANIFEST_BINDING_CONFLICT"
} as const);

export type PhilCoreV2GenesisCredentialOrphanCondition =
  typeof PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CONDITION[
    keyof typeof PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CONDITION
  ];

export const PHILCORE_V2_GENESIS_CREDENTIAL_KNOWLEDGE = Object.freeze({
  KNOWN_PRIMARY_PLATFORM_CREDENTIAL: "KNOWN_PRIMARY_PLATFORM_CREDENTIAL",
  KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED:
    "KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED",
  KNOWN_OFFLINE_PUBLIC_MATERIAL: "KNOWN_OFFLINE_PUBLIC_MATERIAL",
  UNKNOWN_CREDENTIAL: "UNKNOWN_CREDENTIAL"
} as const);

export type PhilCoreV2GenesisCredentialKnowledge =
  typeof PHILCORE_V2_GENESIS_CREDENTIAL_KNOWLEDGE[
    keyof typeof PHILCORE_V2_GENESIS_CREDENTIAL_KNOWLEDGE
  ];

export const PHILCORE_V2_GENESIS_CREDENTIAL_UNRESOLVED_BINDING = Object.freeze({
  CREDENTIAL_ID_AND_PUBLIC_MATERIAL: "CREDENTIAL_ID_AND_PUBLIC_MATERIAL",
  PUBLIC_MATERIAL_ONLY: "PUBLIC_MATERIAL_ONLY",
  NONE: "NONE",
  SIDECAR_AND_UNPROJECTED_MANIFEST_BINDING_CONFLICT:
    "SIDECAR_AND_UNPROJECTED_MANIFEST_BINDING_CONFLICT",
  UNPROJECTED_MANIFEST_BINDING_CONFLICT_ONLY:
    "UNPROJECTED_MANIFEST_BINDING_CONFLICT_ONLY"
} as const);

export type PhilCoreV2GenesisCredentialUnresolvedBinding =
  typeof PHILCORE_V2_GENESIS_CREDENTIAL_UNRESOLVED_BINDING[
    keyof typeof PHILCORE_V2_GENESIS_CREDENTIAL_UNRESOLVED_BINDING
  ];

export const PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_ERROR_CODE =
  Object.freeze({
    ORPHAN_CLASSIFICATION_STATE_INVALID: "ORPHAN_CLASSIFICATION_STATE_INVALID",
    ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION:
      "ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION"
  } as const);

export type PhilCoreV2GenesisCredentialOrphanClassificationErrorCode =
  typeof PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_ERROR_CODE[
    keyof typeof PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_ERROR_CODE
  ];

type Code = PhilCoreV2GenesisCredentialOrphanClassificationErrorCode;

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

/**
 * The module's only thrown type. `instanceof` is answered from a private
 * WeakSet brand through a non-writable, non-configurable `Symbol.hasInstance`,
 * so a hostile object cannot forge membership by adopting the prototype, and
 * the check itself cannot be replaced. No thrown value from any inner call is
 * ever retained on an instance -- not as `cause`, not under any other name.
 */
export class PhilCoreV2GenesisCredentialOrphanClassificationError extends Error {
  readonly code: PhilCoreV2GenesisCredentialOrphanClassificationErrorCode;

  constructor(
    code: PhilCoreV2GenesisCredentialOrphanClassificationErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2GenesisCredentialOrphanClassificationError";
    this.code = code;
    CLASSIFIED_ERROR_BRAND.add(this);
  }

  static [Symbol.hasInstance](value: unknown): boolean {
    if (value === null || (typeof value !== "object" && typeof value !== "function")) {
      return false;
    }
    return CLASSIFIED_ERROR_BRAND.has(value as object);
  }
}

Object.defineProperty(
  PhilCoreV2GenesisCredentialOrphanClassificationError,
  Symbol.hasInstance,
  {
    value: PhilCoreV2GenesisCredentialOrphanClassificationError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

const E = PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_ERROR_CODE;
const CONDITION = PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CONDITION;
const KNOWLEDGE = PHILCORE_V2_GENESIS_CREDENTIAL_KNOWLEDGE;
const UNRESOLVED = PHILCORE_V2_GENESIS_CREDENTIAL_UNRESOLVED_BINDING;

const NONCONFLICTING_ORPHAN_REASONS = Object.freeze([
  "RESTART_DURING_CREATION",
  "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION",
  "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION",
  "TERMINAL_JOURNAL_WITH_UNCONSUMED_CREATION"
] as const);

export type PhilCoreV2GenesisCredentialOrphanClassification = {
  readonly schemaVersion: typeof PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_SCHEMA_VERSION;
  readonly formatProvenance: typeof PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_FORMAT_PROVENANCE;
  readonly intentId: PhilCoreV2GenesisCredentialObligationRecord["intentId"];
  readonly genesisDeploymentIntentHash: PhilCoreV2GenesisCredentialObligationRecord["genesisDeploymentIntentHash"];
  readonly ceremonyVersion: PhilCoreV2GenesisCredentialObligationRecord["ceremonyVersion"];
  readonly ceremonyId: PhilCoreV2GenesisCredentialObligationRecord["ceremonyId"];
  readonly ceremonyExpiresAtUnixSeconds: PhilCoreV2GenesisCredentialObligationRecord["ceremonyExpiresAtUnixSeconds"];
  readonly genesisEnrollmentCeremonyHash: PhilCoreV2GenesisCredentialObligationRecord["genesisEnrollmentCeremonyHash"];
  readonly role: PhilCoreV2GenesisCredentialObligationRecord["role"];
  readonly credentialGeneration: PhilCoreV2GenesisCredentialObligationRecord["credentialGeneration"];
  readonly orphanReason: PhilCoreV2GenesisCredentialObligationOrphanReason;
  readonly orphanCondition: PhilCoreV2GenesisCredentialOrphanCondition;
  readonly credentialKnowledge: PhilCoreV2GenesisCredentialKnowledge;
  readonly credentialIdHash: PhilCoreV2GenesisCredentialObligationRecord["credentialIdHash"];
  readonly publicVerificationMaterialHash: PhilCoreV2GenesisCredentialObligationRecord["publicVerificationMaterialHash"];
  readonly unresolvedBinding: PhilCoreV2GenesisCredentialUnresolvedBinding;
};

function fail(code: Code, message?: string): never {
  throw new PhilCoreV2GenesisCredentialOrphanClassificationError(code, message);
}

function isBrandedError(value: unknown): boolean {
  try {
    return value instanceof PhilCoreV2GenesisCredentialOrphanClassificationError;
  } catch {
    return false;
  }
}

function failDiscardingThrown(code: Code, thrown: unknown): never {
  if (isBrandedError(thrown)) {
    throw thrown;
  }
  void thrown;
  fail(code);
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) {
    return value;
  }
  const object = value as object;
  if (seen.has(object)) {
    return value;
  }
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor !== undefined && Object.prototype.hasOwnProperty.call(descriptor, "value")) {
      deepFreeze(descriptor.value, seen);
    }
  }
  Object.freeze(object);
  return value;
}

function requireOrphanReason(
  value: unknown
): PhilCoreV2GenesisCredentialObligationOrphanReason {
  if (value === "RECORDED_CREDENTIAL_MISMATCH") {
    return value;
  }
  for (const reason of NONCONFLICTING_ORPHAN_REASONS) {
    if (value === reason) {
      return reason;
    }
  }
  fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
}

function deriveOrphanCondition(
  reason: PhilCoreV2GenesisCredentialObligationOrphanReason
): PhilCoreV2GenesisCredentialOrphanCondition {
  if (reason === "RECORDED_CREDENTIAL_MISMATCH") {
    return CONDITION.DURABLE_MANIFEST_BINDING_CONFLICT;
  }
  for (const candidate of NONCONFLICTING_ORPHAN_REASONS) {
    if (reason === candidate) {
      return CONDITION.UNCONSUMED_CREATION_OUTCOME;
    }
  }
  fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
}

function deriveCredentialKnowledge(
  record: PhilCoreV2GenesisCredentialObligationRecord
): PhilCoreV2GenesisCredentialKnowledge {
  const role = record.role;
  const credentialIdHash = record.credentialIdHash;
  const publicVerificationMaterialHash = record.publicVerificationMaterialHash;
  const idNull = credentialIdHash === null;
  const publicNull = publicVerificationMaterialHash === null;
  if (idNull !== publicNull) {
    fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
  }
  if (role !== "0" && role !== "1" && role !== "2") {
    fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
  }
  if (idNull && publicNull) {
    return KNOWLEDGE.UNKNOWN_CREDENTIAL;
  }
  if (typeof credentialIdHash !== "string" || typeof publicVerificationMaterialHash !== "string") {
    fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
  }
  if (role === "0") {
    if (credentialIdHash === ZERO_BYTES32 || publicVerificationMaterialHash === ZERO_BYTES32) {
      fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
    }
    return KNOWLEDGE.KNOWN_PRIMARY_PLATFORM_CREDENTIAL;
  }
  if (role === "1") {
    if (credentialIdHash === ZERO_BYTES32 || publicVerificationMaterialHash === ZERO_BYTES32) {
      fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
    }
    return KNOWLEDGE.KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED;
  }
  if (credentialIdHash !== ZERO_BYTES32 || publicVerificationMaterialHash === ZERO_BYTES32) {
    fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
  }
  return KNOWLEDGE.KNOWN_OFFLINE_PUBLIC_MATERIAL;
}

function deriveUnresolvedBinding(
  knowledge: PhilCoreV2GenesisCredentialKnowledge,
  condition: PhilCoreV2GenesisCredentialOrphanCondition
): PhilCoreV2GenesisCredentialUnresolvedBinding {
  if (condition === CONDITION.UNCONSUMED_CREATION_OUTCOME) {
    if (
      knowledge === KNOWLEDGE.KNOWN_PRIMARY_PLATFORM_CREDENTIAL
      || knowledge === KNOWLEDGE.KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED
    ) {
      return UNRESOLVED.CREDENTIAL_ID_AND_PUBLIC_MATERIAL;
    }
    if (knowledge === KNOWLEDGE.KNOWN_OFFLINE_PUBLIC_MATERIAL) {
      return UNRESOLVED.PUBLIC_MATERIAL_ONLY;
    }
    if (knowledge === KNOWLEDGE.UNKNOWN_CREDENTIAL) {
      return UNRESOLVED.NONE;
    }
    fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
  }
  if (condition === CONDITION.DURABLE_MANIFEST_BINDING_CONFLICT) {
    if (knowledge === KNOWLEDGE.UNKNOWN_CREDENTIAL) {
      return UNRESOLVED.UNPROJECTED_MANIFEST_BINDING_CONFLICT_ONLY;
    }
    if (
      knowledge === KNOWLEDGE.KNOWN_PRIMARY_PLATFORM_CREDENTIAL
      || knowledge === KNOWLEDGE.KNOWN_SECONDARY_CREDENTIAL_CARRIER_UNDETERMINED
      || knowledge === KNOWLEDGE.KNOWN_OFFLINE_PUBLIC_MATERIAL
    ) {
      return UNRESOLVED.SIDECAR_AND_UNPROJECTED_MANIFEST_BINDING_CONFLICT;
    }
    fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
  }
  fail(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION);
}

function freezeClassification(fields: {
  readonly intentId: PhilCoreV2GenesisCredentialObligationRecord["intentId"];
  readonly genesisDeploymentIntentHash: PhilCoreV2GenesisCredentialObligationRecord["genesisDeploymentIntentHash"];
  readonly ceremonyVersion: PhilCoreV2GenesisCredentialObligationRecord["ceremonyVersion"];
  readonly ceremonyId: PhilCoreV2GenesisCredentialObligationRecord["ceremonyId"];
  readonly ceremonyExpiresAtUnixSeconds: PhilCoreV2GenesisCredentialObligationRecord["ceremonyExpiresAtUnixSeconds"];
  readonly genesisEnrollmentCeremonyHash: PhilCoreV2GenesisCredentialObligationRecord["genesisEnrollmentCeremonyHash"];
  readonly role: PhilCoreV2GenesisCredentialObligationRecord["role"];
  readonly credentialGeneration: PhilCoreV2GenesisCredentialObligationRecord["credentialGeneration"];
  readonly orphanReason: PhilCoreV2GenesisCredentialObligationOrphanReason;
  readonly orphanCondition: PhilCoreV2GenesisCredentialOrphanCondition;
  readonly credentialKnowledge: PhilCoreV2GenesisCredentialKnowledge;
  readonly credentialIdHash: PhilCoreV2GenesisCredentialObligationRecord["credentialIdHash"];
  readonly publicVerificationMaterialHash: PhilCoreV2GenesisCredentialObligationRecord["publicVerificationMaterialHash"];
  readonly unresolvedBinding: PhilCoreV2GenesisCredentialUnresolvedBinding;
}): PhilCoreV2GenesisCredentialOrphanClassification {
  const result = Object.create(null) as Record<string, unknown>;
  result.schemaVersion = PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_SCHEMA_VERSION;
  result.formatProvenance =
    PHILCORE_V2_GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION_FORMAT_PROVENANCE;
  result.intentId = fields.intentId;
  result.genesisDeploymentIntentHash = fields.genesisDeploymentIntentHash;
  result.ceremonyVersion = fields.ceremonyVersion;
  result.ceremonyId = fields.ceremonyId;
  result.ceremonyExpiresAtUnixSeconds = fields.ceremonyExpiresAtUnixSeconds;
  result.genesisEnrollmentCeremonyHash = fields.genesisEnrollmentCeremonyHash;
  result.role = fields.role;
  result.credentialGeneration = fields.credentialGeneration;
  result.orphanReason = fields.orphanReason;
  result.orphanCondition = fields.orphanCondition;
  result.credentialKnowledge = fields.credentialKnowledge;
  result.credentialIdHash = fields.credentialIdHash;
  result.publicVerificationMaterialHash = fields.publicVerificationMaterialHash;
  result.unresolvedBinding = fields.unresolvedBinding;
  return deepFreeze(result) as PhilCoreV2GenesisCredentialOrphanClassification;
}

export function classifyPhilCoreV2GenesisCredentialOrphan(
  obligation: unknown
): PhilCoreV2GenesisCredentialOrphanClassification {
  const validated = validatePhilCoreV2GenesisCredentialObligationRecord(obligation);
  try {
    if (validated.state !== "ORPHANED") {
      fail(E.ORPHAN_CLASSIFICATION_STATE_INVALID);
    }
    const orphanReason = requireOrphanReason(validated.orphanReason);
    const orphanCondition = deriveOrphanCondition(orphanReason);
    const credentialKnowledge = deriveCredentialKnowledge(validated);
    const unresolvedBinding = deriveUnresolvedBinding(
      credentialKnowledge,
      orphanCondition
    );
    return freezeClassification({
      intentId: validated.intentId,
      genesisDeploymentIntentHash: validated.genesisDeploymentIntentHash,
      ceremonyVersion: validated.ceremonyVersion,
      ceremonyId: validated.ceremonyId,
      ceremonyExpiresAtUnixSeconds: validated.ceremonyExpiresAtUnixSeconds,
      genesisEnrollmentCeremonyHash: validated.genesisEnrollmentCeremonyHash,
      role: validated.role,
      credentialGeneration: validated.credentialGeneration,
      orphanReason,
      orphanCondition,
      credentialKnowledge,
      credentialIdHash: validated.credentialIdHash,
      publicVerificationMaterialHash: validated.publicVerificationMaterialHash,
      unresolvedBinding
    });
  } catch (thrown) {
    failDiscardingThrown(E.ORPHAN_CLASSIFICATION_INVARIANT_VIOLATION, thrown);
  }
}
