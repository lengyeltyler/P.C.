import {
  classifyPhilCoreV2GenesisCredentialOrphan,
  type PhilCoreV2GenesisCredentialOrphanClassification
} from "./v2ConsumerRecoveryGenesisCredentialOrphanClassification.ts";
import {
  validateGenesisStagingJournalRecord,
  type GenesisStagingJournalRecord,
  type StoredGenesisManifestEntry
} from "./v2ConsumerRecoveryGenesisStagingJournal.ts";

// Pure, dormant projection of two lower-validated conflicting bindings. This
// module records facts only: it grants no resolution or transition authority,
// chooses no winner, reads no clock, and performs no I/O.

export const PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_SCHEMA_VERSION =
  1 as const;
export const PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_FORMAT_PROVENANCE =
  "PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_V1" as const;

export const PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_KIND =
  Object.freeze({
    FACTUAL_CONFLICT_ONLY: "FACTUAL_CONFLICT_ONLY"
  } as const);

export type PhilCoreV2GenesisManifestBindingConflictProjectionKind =
  typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_KIND[
    keyof typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_KIND
  ];

export const PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_AUTHORITY =
  Object.freeze({ NONE: "NONE" } as const);

export type PhilCoreV2GenesisManifestBindingConflictAuthority =
  typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_AUTHORITY[
    keyof typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_AUTHORITY
  ];

export const PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_SOURCE_AUTHORITY =
  Object.freeze({
    GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION:
      "GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION",
    GENESIS_STAGING_JOURNAL_MANIFEST_ENTRY:
      "GENESIS_STAGING_JOURNAL_MANIFEST_ENTRY"
  } as const);

export type PhilCoreV2GenesisManifestBindingConflictSourceAuthority =
  typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_SOURCE_AUTHORITY[
    keyof typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_SOURCE_AUTHORITY
  ];

export const PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_MISMATCH_KIND =
  Object.freeze({
    CREDENTIAL_BINDING_MISMATCH: "CREDENTIAL_BINDING_MISMATCH"
  } as const);

export type PhilCoreV2GenesisManifestBindingConflictMismatchKind =
  typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_MISMATCH_KIND[
    keyof typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_MISMATCH_KIND
  ];

export const PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_ERROR_CODE =
  Object.freeze({
    MANIFEST_BINDING_CONFLICT_CONDITION_INVALID:
      "MANIFEST_BINDING_CONFLICT_CONDITION_INVALID",
    MANIFEST_BINDING_CONFLICT_SIDECAR_BINDING_UNAVAILABLE:
      "MANIFEST_BINDING_CONFLICT_SIDECAR_BINDING_UNAVAILABLE",
    MANIFEST_BINDING_CONFLICT_JOURNAL_CONTEXT_MISMATCH:
      "MANIFEST_BINDING_CONFLICT_JOURNAL_CONTEXT_MISMATCH",
    MANIFEST_BINDING_CONFLICT_MANIFEST_ENTRY_MISSING:
      "MANIFEST_BINDING_CONFLICT_MANIFEST_ENTRY_MISSING",
    MANIFEST_BINDING_CONFLICT_CEREMONY_CONTEXT_MISMATCH:
      "MANIFEST_BINDING_CONFLICT_CEREMONY_CONTEXT_MISMATCH",
    MANIFEST_BINDING_CONFLICT_BINDINGS_EQUAL:
      "MANIFEST_BINDING_CONFLICT_BINDINGS_EQUAL",
    MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION:
      "MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION"
  } as const);

export type PhilCoreV2GenesisManifestBindingConflictProjectionErrorCode =
  typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_ERROR_CODE[
    keyof typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_ERROR_CODE
  ];

type Code = PhilCoreV2GenesisManifestBindingConflictProjectionErrorCode;
type Classification = PhilCoreV2GenesisCredentialOrphanClassification;
type Role = "0" | "1" | "2";

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

export class PhilCoreV2GenesisManifestBindingConflictProjectionError extends Error {
  readonly code: PhilCoreV2GenesisManifestBindingConflictProjectionErrorCode;

  constructor(
    code: PhilCoreV2GenesisManifestBindingConflictProjectionErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2GenesisManifestBindingConflictProjectionError";
    this.code = code;
    CLASSIFIED_ERROR_BRAND.add(this);
  }

  static [Symbol.hasInstance](value: unknown): boolean {
    if (
      value === null
      || (typeof value !== "object" && typeof value !== "function")
    ) {
      return false;
    }
    return CLASSIFIED_ERROR_BRAND.has(value as object);
  }
}

Object.defineProperty(
  PhilCoreV2GenesisManifestBindingConflictProjectionError,
  Symbol.hasInstance,
  {
    value:
      PhilCoreV2GenesisManifestBindingConflictProjectionError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

const E =
  PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_ERROR_CODE;
const KIND = PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_KIND;
const AUTHORITY = PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_AUTHORITY;
const SOURCE =
  PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_SOURCE_AUTHORITY;
const MISMATCH = PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_MISMATCH_KIND;

export type PhilCoreV2GenesisManifestBindingConflictBindingContext = Readonly<{
  ceremonyVersion: Classification["ceremonyVersion"];
  ceremonyId: Classification["ceremonyId"];
  ceremonyExpiresAtUnixSeconds: Classification["ceremonyExpiresAtUnixSeconds"];
  genesisEnrollmentCeremonyHash: Classification["genesisEnrollmentCeremonyHash"];
  manifestSlot: Role;
  journalState: GenesisStagingJournalRecord["state"];
}>;

export type PhilCoreV2GenesisManifestBindingConflictSidecarBinding = Readonly<{
  sourceAuthority: typeof SOURCE.GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION;
  sourceSchemaVersion: Classification["schemaVersion"];
  sourceFormatProvenance: Classification["formatProvenance"];
  orphanReason: Classification["orphanReason"];
  orphanCondition: Classification["orphanCondition"];
  credentialKnowledge: Classification["credentialKnowledge"];
  credentialIdHash: string;
  publicVerificationMaterialHash: string;
}>;

export type PhilCoreV2GenesisManifestBindingConflictManifestBinding = Readonly<{
  sourceAuthority: typeof SOURCE.GENESIS_STAGING_JOURNAL_MANIFEST_ENTRY;
  journalSchemaVersion: GenesisStagingJournalRecord["schemaVersion"];
  journalFormatProvenance: GenesisStagingJournalRecord["formatProvenance"];
  journalIntegrityChecksum: GenesisStagingJournalRecord["integrityChecksum"];
  factorCommitment: StoredGenesisManifestEntry["factorCommitment"];
  stagedAtUnixSeconds: StoredGenesisManifestEntry["stagedAtUnixSeconds"];
  descriptorVersion: StoredGenesisManifestEntry["descriptor"]["descriptorVersion"];
  credentialGeneration: StoredGenesisManifestEntry["descriptor"]["credentialGeneration"];
  credentialIdHash: StoredGenesisManifestEntry["descriptor"]["credentialIdHash"];
  publicVerificationMaterialHash: StoredGenesisManifestEntry["descriptor"]["publicVerificationMaterialHash"];
}>;

export type PhilCoreV2GenesisManifestBindingConflictMismatch = Readonly<{
  kind: typeof MISMATCH.CREDENTIAL_BINDING_MISMATCH;
  credentialIdHashDiffers: boolean;
  publicVerificationMaterialHashDiffers: boolean;
}>;

export type PhilCoreV2GenesisManifestBindingConflictProjection = Readonly<{
  schemaVersion: typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_SCHEMA_VERSION;
  formatProvenance: typeof PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_FORMAT_PROVENANCE;
  projectionKind: typeof KIND.FACTUAL_CONFLICT_ONLY;
  resolutionAuthority: typeof AUTHORITY.NONE;
  transitionAuthority: typeof AUTHORITY.NONE;
  intentId: Classification["intentId"];
  genesisDeploymentIntentHash: Classification["genesisDeploymentIntentHash"];
  role: Role;
  credentialGeneration: Classification["credentialGeneration"];
  bindingContext: PhilCoreV2GenesisManifestBindingConflictBindingContext;
  sidecarBinding: PhilCoreV2GenesisManifestBindingConflictSidecarBinding;
  manifestBinding: PhilCoreV2GenesisManifestBindingConflictManifestBinding;
  mismatch: PhilCoreV2GenesisManifestBindingConflictMismatch;
}>;

function fail(code: Code): never {
  throw new PhilCoreV2GenesisManifestBindingConflictProjectionError(code);
}

function isBrandedError(value: unknown): boolean {
  try {
    return value instanceof PhilCoreV2GenesisManifestBindingConflictProjectionError;
  } catch {
    return false;
  }
}

function failDiscardingThrown(thrown: unknown): never {
  if (isBrandedError(thrown)) throw thrown;
  void thrown;
  fail(E.MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION);
}

function withinAdapterBoundary<T>(operation: () => T): T {
  try {
    return operation();
  } catch (thrown) {
    failDiscardingThrown(thrown);
  }
}

function frozenNullPrototype(
  entries: readonly (readonly [string, unknown])[]
): Readonly<Record<string, unknown>> {
  const result = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of entries) result[key] = value;
  return Object.freeze(result);
}

function requireCanonicalRole(value: unknown): Role {
  if (value === "0" || value === "1" || value === "2") return value;
  fail(E.MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION);
}

function requireSelectedEntry(
  journal: GenesisStagingJournalRecord,
  role: Role
): StoredGenesisManifestEntry {
  const entry = journal.manifest[role];
  if (entry === null) {
    fail(E.MANIFEST_BINDING_CONFLICT_MANIFEST_ENTRY_MISSING);
  }
  return entry;
}

export function projectPhilCoreV2GenesisManifestBindingConflict(
  obligation: unknown,
  journal: unknown
): PhilCoreV2GenesisManifestBindingConflictProjection {
  // Lower calls deliberately sit outside the adapter-owned catch boundary.
  const classification = classifyPhilCoreV2GenesisCredentialOrphan(obligation);

  withinAdapterBoundary(() => {
    if (
      classification.orphanReason !== "RECORDED_CREDENTIAL_MISMATCH"
      || classification.orphanCondition !== "DURABLE_MANIFEST_BINDING_CONFLICT"
    ) {
      fail(E.MANIFEST_BINDING_CONFLICT_CONDITION_INVALID);
    }
    if (
      classification.credentialKnowledge === "UNKNOWN_CREDENTIAL"
      || typeof classification.credentialIdHash !== "string"
      || typeof classification.publicVerificationMaterialHash !== "string"
    ) {
      fail(E.MANIFEST_BINDING_CONFLICT_SIDECAR_BINDING_UNAVAILABLE);
    }
  });

  const validatedJournal = validateGenesisStagingJournalRecord(journal);

  return withinAdapterBoundary(() => {
    if (
      classification.intentId !== validatedJournal.intentId
      || classification.genesisDeploymentIntentHash
        !== validatedJournal.genesisDeploymentIntentHash
    ) {
      fail(E.MANIFEST_BINDING_CONFLICT_JOURNAL_CONTEXT_MISMATCH);
    }

    const role = requireCanonicalRole(classification.role);
    if (
      classification.ceremonyVersion !== "1"
      || classification.credentialGeneration !== "1"
    ) {
      fail(E.MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION);
    }

    const entry = requireSelectedEntry(validatedJournal, role);
    if (
      classification.ceremonyId !== entry.ceremonyId
      || classification.ceremonyExpiresAtUnixSeconds
        !== entry.ceremonyExpiresAtUnixSeconds
      || classification.genesisEnrollmentCeremonyHash
        !== entry.genesisEnrollmentCeremonyHash
    ) {
      fail(E.MANIFEST_BINDING_CONFLICT_CEREMONY_CONTEXT_MISMATCH);
    }
    if (
      entry.role !== role
      || entry.descriptor.credentialGeneration !== "1"
      || entry.independence.credentialGeneration !== "1"
    ) {
      fail(E.MANIFEST_BINDING_CONFLICT_INVARIANT_VIOLATION);
    }

    const credentialIdHashDiffers =
      classification.credentialIdHash !== entry.descriptor.credentialIdHash;
    const publicVerificationMaterialHashDiffers =
      classification.publicVerificationMaterialHash
        !== entry.descriptor.publicVerificationMaterialHash;
    if (!credentialIdHashDiffers && !publicVerificationMaterialHashDiffers) {
      fail(E.MANIFEST_BINDING_CONFLICT_BINDINGS_EQUAL);
    }

    const bindingContext = frozenNullPrototype([
      ["ceremonyVersion", classification.ceremonyVersion],
      ["ceremonyId", classification.ceremonyId],
      ["ceremonyExpiresAtUnixSeconds", classification.ceremonyExpiresAtUnixSeconds],
      ["genesisEnrollmentCeremonyHash", classification.genesisEnrollmentCeremonyHash],
      ["manifestSlot", role],
      ["journalState", validatedJournal.state]
    ]) as PhilCoreV2GenesisManifestBindingConflictBindingContext;
    const sidecarBinding = frozenNullPrototype([
      ["sourceAuthority", SOURCE.GENESIS_CREDENTIAL_ORPHAN_CLASSIFICATION],
      ["sourceSchemaVersion", classification.schemaVersion],
      ["sourceFormatProvenance", classification.formatProvenance],
      ["orphanReason", classification.orphanReason],
      ["orphanCondition", classification.orphanCondition],
      ["credentialKnowledge", classification.credentialKnowledge],
      ["credentialIdHash", classification.credentialIdHash],
      ["publicVerificationMaterialHash", classification.publicVerificationMaterialHash]
    ]) as PhilCoreV2GenesisManifestBindingConflictSidecarBinding;
    const manifestBinding = frozenNullPrototype([
      ["sourceAuthority", SOURCE.GENESIS_STAGING_JOURNAL_MANIFEST_ENTRY],
      ["journalSchemaVersion", validatedJournal.schemaVersion],
      ["journalFormatProvenance", validatedJournal.formatProvenance],
      ["journalIntegrityChecksum", validatedJournal.integrityChecksum],
      ["factorCommitment", entry.factorCommitment],
      ["stagedAtUnixSeconds", entry.stagedAtUnixSeconds],
      ["descriptorVersion", entry.descriptor.descriptorVersion],
      ["credentialGeneration", entry.descriptor.credentialGeneration],
      ["credentialIdHash", entry.descriptor.credentialIdHash],
      ["publicVerificationMaterialHash", entry.descriptor.publicVerificationMaterialHash]
    ]) as PhilCoreV2GenesisManifestBindingConflictManifestBinding;
    const mismatch = frozenNullPrototype([
      ["kind", MISMATCH.CREDENTIAL_BINDING_MISMATCH],
      ["credentialIdHashDiffers", credentialIdHashDiffers],
      ["publicVerificationMaterialHashDiffers", publicVerificationMaterialHashDiffers]
    ]) as PhilCoreV2GenesisManifestBindingConflictMismatch;

    return frozenNullPrototype([
      ["schemaVersion", PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_SCHEMA_VERSION],
      ["formatProvenance", PHILCORE_V2_GENESIS_MANIFEST_BINDING_CONFLICT_PROJECTION_FORMAT_PROVENANCE],
      ["projectionKind", KIND.FACTUAL_CONFLICT_ONLY],
      ["resolutionAuthority", AUTHORITY.NONE],
      ["transitionAuthority", AUTHORITY.NONE],
      ["intentId", classification.intentId],
      ["genesisDeploymentIntentHash", classification.genesisDeploymentIntentHash],
      ["role", role],
      ["credentialGeneration", classification.credentialGeneration],
      ["bindingContext", bindingContext],
      ["sidecarBinding", sidecarBinding],
      ["manifestBinding", manifestBinding],
      ["mismatch", mismatch]
    ]) as PhilCoreV2GenesisManifestBindingConflictProjection;
  });
}
