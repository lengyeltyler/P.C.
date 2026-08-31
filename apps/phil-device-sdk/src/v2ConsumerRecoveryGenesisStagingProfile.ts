import {
  allGenesisStagingSlotsPopulated,
  validateGenesisStagingJournalRecord,
  type GenesisStagingJournalRecord,
  type StoredGenesisManifestEntry
} from "./v2ConsumerRecoveryGenesisStagingJournal.ts";
import {
  validatePhilCoreV2ConsumerRecoveryGenesisProfile,
  type PhilCoreV2ConsumerRecoveryGenesisProfileResult,
  type PhilCoreV2LocalGenesisDeploymentIntentInput,
  type PhilCoreV2LocalGenesisEnrollmentCeremonyInput
} from "./v2ConsumerRecoveryGenesisProtocol.ts";

// Pure, dormant journal-to-profile composition. A successful result is valid
// only as of the caller-supplied nowUnixSeconds. It is not a lease, a durable
// freshness assertion, or a journal-state transition; every consumer must
// revalidate against its authoritative clock before acting.

const MAX_UINT48 = 281474976710655;

const INTENT_KEYS = Object.freeze([
  "intentVersion",
  "intentId",
  "chainId",
  "entryPoint",
  "factoryBinding",
  "confirmationTarget",
  "verifier",
  "verifierRuntimeCodeHash",
  "accountCreationBytecodeHash",
  "accountVersionId",
  "securityModelId",
  "recoveryDomainId",
  "ownerCommitment",
  "identityBindingCommitment",
  "initialValidator",
  "validatorVerifierKind",
  "validatorKeyIdBinding",
  "validatorCommitment",
  "validatorEpoch",
  "recoveryEpoch",
  "recoveryDelaySeconds",
  "recoveryExpirySeconds",
  "userSalt",
  "expiresAt"
] as const);

export const PHILCORE_V2_GENESIS_STAGING_PROFILE_ERROR_CODE = Object.freeze({
  STAGING_PROFILE_INVALID_NOW: "STAGING_PROFILE_INVALID_NOW",
  STAGING_PROFILE_JOURNAL_NOT_STAGING: "STAGING_PROFILE_JOURNAL_NOT_STAGING",
  STAGING_PROFILE_SLOTS_NOT_POPULATED: "STAGING_PROFILE_SLOTS_NOT_POPULATED",
  STAGING_PROFILE_CLOCK_REGRESSION_DETECTED:
    "STAGING_PROFILE_CLOCK_REGRESSION_DETECTED",
  STAGING_PROFILE_JOURNAL_EXPIRED: "STAGING_PROFILE_JOURNAL_EXPIRED"
} as const);

export type PhilCoreV2ConsumerRecoveryGenesisStagingProfileErrorCode =
  typeof PHILCORE_V2_GENESIS_STAGING_PROFILE_ERROR_CODE[
    keyof typeof PHILCORE_V2_GENESIS_STAGING_PROFILE_ERROR_CODE
  ];

const CLASSIFIED_ERROR_BRAND = new WeakSet<object>();

export class PhilCoreV2ConsumerRecoveryGenesisStagingProfileError extends Error {
  readonly code: PhilCoreV2ConsumerRecoveryGenesisStagingProfileErrorCode;

  constructor(
    code: PhilCoreV2ConsumerRecoveryGenesisStagingProfileErrorCode,
    message?: string
  ) {
    super(message ?? code);
    this.name = "PhilCoreV2ConsumerRecoveryGenesisStagingProfileError";
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
  PhilCoreV2ConsumerRecoveryGenesisStagingProfileError,
  Symbol.hasInstance,
  {
    value:
      PhilCoreV2ConsumerRecoveryGenesisStagingProfileError[Symbol.hasInstance],
    writable: false,
    configurable: false,
    enumerable: false
  }
);

const C = PHILCORE_V2_GENESIS_STAGING_PROFILE_ERROR_CODE;

function fail(
  code: PhilCoreV2ConsumerRecoveryGenesisStagingProfileErrorCode
): never {
  throw new PhilCoreV2ConsumerRecoveryGenesisStagingProfileError(code);
}

function nullPrototypeProjection(
  entries: readonly (readonly [string, unknown])[]
): Readonly<Record<string, unknown>> {
  const projection = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of entries) {
    projection[key] = value;
  }
  return Object.freeze(projection);
}

function projectIntent(
  journal: GenesisStagingJournalRecord
): PhilCoreV2LocalGenesisDeploymentIntentInput {
  return nullPrototypeProjection(
    INTENT_KEYS.map((key) => [key, journal[key]] as const)
  ) as unknown as PhilCoreV2LocalGenesisDeploymentIntentInput;
}

function projectCeremony(
  journal: GenesisStagingJournalRecord,
  entry: StoredGenesisManifestEntry
): PhilCoreV2LocalGenesisEnrollmentCeremonyInput {
  return nullPrototypeProjection([
    ["ceremonyVersion", "1"],
    ["ceremonyId", entry.ceremonyId],
    ["genesisDeploymentIntentHash", journal.genesisDeploymentIntentHash],
    ["role", entry.role],
    ["credentialGeneration", "1"],
    ["expiresAt", entry.ceremonyExpiresAtUnixSeconds]
  ]) as unknown as PhilCoreV2LocalGenesisEnrollmentCeremonyInput;
}

function requireManifestEntry(
  journal: GenesisStagingJournalRecord,
  slot: 0 | 1 | 2
): StoredGenesisManifestEntry {
  // Step 4 has already proved all three entries are populated. This helper
  // only narrows the public record type and does not add another authority.
  return journal.manifest[String(slot) as "0" | "1" | "2"] as StoredGenesisManifestEntry;
}

function projectFactor(
  entry: StoredGenesisManifestEntry,
  slot: 0 | 1 | 2
): Readonly<Record<string, unknown>> {
  const entries: (readonly [string, unknown])[] = [
    ["descriptor", entry.descriptor],
    ["independence", entry.independence]
  ];
  if (slot === 2) {
    entries.push(["signer", entry.signer]);
  }
  return nullPrototypeProjection(entries);
}

function deepFreezeResult<T>(value: T, seen = new WeakSet<object>()): T {
  if (
    value === null
    || (typeof value !== "object" && typeof value !== "function")
  ) {
    return value;
  }
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor !== undefined && "value" in descriptor) {
      deepFreezeResult(descriptor.value, seen);
    }
  }
  Object.freeze(object);
  return value;
}

export function validatePhilCoreV2ConsumerRecoveryGenesisStagingProfile(
  journal: unknown,
  nowUnixSeconds: number
): PhilCoreV2ConsumerRecoveryGenesisProfileResult {
  // 1) The caller-supplied clock domain outranks all journal inspection.
  if (
    typeof nowUnixSeconds !== "number"
    || !Number.isSafeInteger(nowUnixSeconds)
    || nowUnixSeconds <= 0
    || nowUnixSeconds > MAX_UINT48
  ) {
    fail(C.STAGING_PROFILE_INVALID_NOW);
  }

  // 2) The journal validator is the sole record-validation authority.
  const validated = validateGenesisStagingJournalRecord(journal);

  // 3) Terminal journals never enter profile composition.
  if (validated.state !== "STAGING") {
    fail(C.STAGING_PROFILE_JOURNAL_NOT_STAGING);
  }

  // 4) Reuse the journal module's population authority. Its internal
  // revalidation of this already-owned frozen record is intentional.
  if (!allGenesisStagingSlotsPopulated(validated)) {
    fail(C.STAGING_PROFILE_SLOTS_NOT_POPULATED);
  }

  const now = BigInt(nowUnixSeconds);
  // 5) Regression precedes expiry, matching the pure journal transition order.
  if (now < BigInt(validated.updatedAtUnixSeconds)) {
    fail(C.STAGING_PROFILE_CLOCK_REGRESSION_DETECTED);
  }

  // 6) Equality is expired; a success requires a strictly live intent.
  if (now >= BigInt(validated.expiresAt)) {
    fail(C.STAGING_PROFILE_JOURNAL_EXPIRED);
  }

  const entry0 = requireManifestEntry(validated, 0);
  const entry1 = requireManifestEntry(validated, 1);
  const entry2 = requireManifestEntry(validated, 2);
  const intent = projectIntent(validated);
  const ceremonies = Object.freeze([
    projectCeremony(validated, entry0),
    projectCeremony(validated, entry1),
    projectCeremony(validated, entry2)
  ]) as readonly [
    PhilCoreV2LocalGenesisEnrollmentCeremonyInput,
    PhilCoreV2LocalGenesisEnrollmentCeremonyInput,
    PhilCoreV2LocalGenesisEnrollmentCeremonyInput
  ];
  const factors = Object.freeze([
    projectFactor(entry0, 0),
    projectFactor(entry1, 1),
    projectFactor(entry2, 2)
  ]);
  const projection = nullPrototypeProjection([
    ["intent", intent],
    ["ceremonies", ceremonies],
    ["factors", factors],
    ["executionValidator", validated.initialValidator]
  ]);

  // 7) The pure genesis-profile validator is the sole profile authority.
  // Lower-layer thrown values are deliberately not caught or inspected.
  const result = validatePhilCoreV2ConsumerRecoveryGenesisProfile(
    projection as never
  );

  // 8) Reinforce the accepted immutable result boundary idempotently.
  return deepFreezeResult(result);
}
