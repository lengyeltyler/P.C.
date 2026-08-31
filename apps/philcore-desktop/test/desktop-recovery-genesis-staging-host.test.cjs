"use strict";

// PhilCore Package 5B-0.5 — deterministic host suite.
//
// Dormant module under test: no product wiring, no IPC, no renderer, no
// network, no signing, no physical ceremony, intentional dist-local exclusion.
//
// Coverage is table-driven over the accepted architecture corpus:
//   285 single-failure rows  (chain subtotals 61/65/38/39/39/4/31/8)
//   441 compound rows        (235 + 49 + 28 + 56 four-family + 73 descriptor-close)
//   113 phase literals       (107 external detail.phase + 6 classification-only)
//   90 codes                 (83 external + 7 internal classifications)
//   SM12 = 142, global transitions = 549
//
// Every row is enumerated literally and every fail site is reached by a real
// injected execution path through the public factory and host methods. The
// module under test exposes no fail-site or compound lookup API; fault
// injection is performed here by a deterministic, scoped filesystem facade
// that is unconditionally restored in a finally block (decision D6).

require("tsx/cjs");

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { getAddress } = require("ethers");

const {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
  computePhilCoreV2ConsumerRecoveryIndependenceBinding
} = require("../../phil-device-sdk/src/v2ConsumerRecovery.ts");
const { PHILCORE_V2_SECURITY_MODEL_ID } = require("../../phil-device-sdk/src/v2Intent.ts");
const genesisLifecycle = require("../../phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts");
const genesisProtocol = require("../../phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts");
const genesisObligation = require("../../phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts");
const PURE_JOURNAL_PATH = require.resolve(
  "../../phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingJournal.ts"
);
const pureJournalReal = require(PURE_JOURNAL_PATH);

// The tsx namespace is non-configurable, so a mutable shim is installed in the
// module cache. The host resolves the same specifier and therefore receives
// this object, allowing the delegated 5B-0.4 boundary to be faulted
// deterministically without any production test hook.
const pureJournal = {};
for (const key of Object.keys(pureJournalReal)) {
  pureJournal[key] = pureJournalReal[key];
}
require.cache[PURE_JOURNAL_PATH].exports = pureJournal;

const PURE_FINALIZED_PATH = require.resolve(
  "../../phil-device-sdk/src/v2ConsumerRecoveryGenesisFinalizedProfile.ts"
);
const pureFinalizedReal = require(PURE_FINALIZED_PATH);
const pureFinalized = {};
for (const key of Object.keys(pureFinalizedReal)) {
  pureFinalized[key] = pureFinalizedReal[key];
}
require.cache[PURE_FINALIZED_PATH].exports = pureFinalized;

const stagingProfileAdapter = require(
  "../../phil-device-sdk/src/v2ConsumerRecoveryGenesis" + "StagingProfile.ts"
);
const validateGenesisStagingProfileAdapter = stagingProfileAdapter[
  "validatePhilCoreV2ConsumerRecoveryGenesis" + "StagingProfile"
];
const STAGING_PROFILE_ADAPTER_PATH = require.resolve(
  "../../phil-device-sdk/src/v2ConsumerRecoveryGenesis" + "StagingProfile.ts"
);

// Structural factor material is read directly from the committed fixture
// config. The generator under scripts/cryptography is never executed.
const O39_FIXTURES = JSON.parse(
  fs.readFileSync(
    path.resolve(__dirname, "../../../config/cryptography/O39_CONSUMER_RECOVERY_FIXTURES.json"),
    "utf8"
  )
);

const hostModule = require("../src/main/recovery-genesis-staging-host.cjs");

const {
  createRecoveryGenesisStagingHost,
  PhilCoreV2ConsumerRecoveryGenesisStagingHostError,
  PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_HOST_ERROR_CODE
} = hostModule;

// ---------------------------------------------------------------------------
// Accepted corpus
// [id, operation, code, phase, subject, commitState, poison, registry,
//  retry, primaryCode, precedence]
// ---------------------------------------------------------------------------
const SINGLE_ROWS = [
  ["1.01","construct","HOST_DEPENDENCIES_NOT_OBJECT","DEPENDENCY_VALIDATION","null","NOT_APPLICABLE","no","no","retry with a corrected object","null",1],
  ["1.02","construct","HOST_DEPENDENCY_ENUMERATION_FAILED","DEPENDENCY_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",2],
  ["1.03","construct","HOST_DEPENDENCY_EXTRA","DEPENDENCY_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",3],
  ["1.04","construct","HOST_DEPENDENCY_MISSING","DEPENDENCY_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",4],
  ["1.05","construct","HOST_DEPENDENCY_READ_FAILED","DEPENDENCY_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",5],
  ["1.06","construct","HOST_DEPENDENCY_INVALID","DEPENDENCY_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",6],
  ["1.07","construct","HOST_PROCESS_POISONED","MODULE_POISON_CHECK","null","NOT_APPLICABLE","already poisoned (module-private registry; no host object exists to poison)","already inserted by a prior failed attempt — this row only reads the registry, it does not insert","no recovery within this process; a fresh process is required","null",7],
  ["1.08","construct","HOST_PLATFORM_UNSUPPORTED","PLATFORM_VALIDATION","null","NOT_APPLICABLE","no","no","not retriable on this platform","null",8],
  ["1.09","construct","HOST_STORAGE_ROOT_NOT_FOUND","ROOT_VALIDATION","SHARED_DIRECTORY","NOT_APPLICABLE","no","no","retry after the root exists","null",9],
  ["1.10","construct","HOST_STORAGE_ROOT_UNSAFE","ROOT_VALIDATION","SHARED_DIRECTORY","NOT_APPLICABLE","no","no","retry after the symlink is removed","null",10],
  ["1.11","construct","HOST_STORAGE_ROOT_INVALID","ROOT_VALIDATION","SHARED_DIRECTORY","NOT_APPLICABLE","no","no","retry after the root is corrected","null",11],
  ["1.12","construct","HOST_STORAGE_DIRECTORY_CREATE_FAILED","DIRECTORY_CREATE","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",12],
  ["1.13","construct","HOST_STORAGE_DIRECTORY_INVALID","DIRECTORY_OPEN","STAGING_DIRECTORY","NOT_APPLICABLE","n/a — construction returns no host object","no","retriable","null",13],
  ["1.14","construct","HOST_STORAGE_DIRECTORY_INVALID","DIRECTORY_VALIDATE","CORRUPT_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",14],
  ["1.15","construct","HOST_STORAGE_DIRECTORY_MODE_INVALID","DIRECTORY_VALIDATE","CORRUPT_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable after chmod","null",15],
  ["1.16","construct","HOST_STORAGE_DIRECTORY_OWNER_INVALID","DIRECTORY_VALIDATE","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",16],
  ["1.17","construct","HOST_DURABILITY_WRITE_FAILED","DIRECTORY_FSYNC","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",17],
  ["1.18","construct","HOST_DESCRIPTOR_CLOSE_FAILED","DIRECTORY_CLOSE","STAGING_DIRECTORY","NOT_APPLICABLE","no (no poison per DC3)","no","retriable; directories are already durable","null",18],
  ["1.19","construct","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_OPEN","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",19],
  ["1.20","construct","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",20],
  ["1.21","construct","HOST_QUARANTINE_SCAN_OVERFLOW","ENUMERATION_READ","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable after operator removal","null",21],
  ["1.22","construct","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","ENUMERATION_CLOSE","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable; enumeration discarded","null",22],
  ["1.23","construct","HOST_FILESYSTEM_READ_FAILED","LOCK_PROBE_OPEN","LOCK_FILE","NOT_APPLICABLE","no","no","retriable","null",23],
  ["1.24","construct","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_PROBE_CLASSIFY","LOCK_FILE","NOT_APPLICABLE","no","no","retriable after removal","null",24],
  ["1.25","construct","HOST_LOCK_FILE_OVERSIZED","LOCK_PROBE_CLASSIFY","LOCK_FILE","NOT_APPLICABLE","no","no","retriable after removal","null",25],
  ["1.26","construct","HOST_FILESYSTEM_READ_FAILED","LOCK_PROBE_READ","LOCK_FILE","NOT_APPLICABLE","no","no","retriable","null",26],
  ["1.27","construct","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_PROBE_RECHECK","LOCK_FILE","NOT_APPLICABLE","no","no","retriable","null",27],
  ["1.28","construct","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_PROBE_CLOSE","LOCK_FILE","NOT_APPLICABLE","no (no poison per DC3)","no","retriable; probe discarded, no liveness probe ran","null",28],
  ["1.29","construct","HOST_LOCK_FILE_MALFORMED","LOCK_PROBE_PARSE","LOCK_FILE","NOT_APPLICABLE","no","no","fail closed; never stolen","null",29],
  ["1.30","construct","HOST_LOCK_LIVENESS_RESULT_INVALID","LOCK_LIVENESS","LOCK_FILE","NOT_APPLICABLE","no","no","fail closed","null",30],
  ["1.31","construct","HOST_LOCK_HELD","LOCK_LIVENESS","LOCK_FILE","NOT_APPLICABLE","no","no","never queued or retried internally","null",31],
  ["1.32","construct","HOST_LOCK_HELD_OR_AMBIGUOUS","LOCK_LIVENESS","LOCK_FILE","NOT_APPLICABLE","no","no","fail closed","null",32],
  ["1.33","construct","HOST_LOCK_HELD_OR_AMBIGUOUS","LOCK_STALENESS_WINDOW","LOCK_FILE","NOT_APPLICABLE","no","no","fail closed until the window elapses","null",33],
  ["1.34","construct","HOST_STALE_LOCK_QUARANTINE_BOUND_EXCEEDED","QUARANTINE_BOUND","LOCK_FILE","NOT_COMMITTED","no","no","retriable after operator removal","null",34],
  ["1.35","construct","HOST_STALE_LOCK_QUARANTINE_FAILED","QUARANTINE_PROBE","LOCK_FILE","NOT_COMMITTED","no","no","retriable; the lock is unchanged","null",35],
  ["1.36","construct","HOST_STALE_LOCK_QUARANTINE_FAILED","QUARANTINE_PRE_RENAME","LOCK_FILE","NOT_COMMITTED","no","no","retriable; the lock is unchanged","null",36],
  ["1.37","construct","HOST_STALE_LOCK_QUARANTINE_FAILED","QUARANTINE_RENAME","LOCK_FILE","NOT_COMMITTED","no","no","retriable; the lock is unchanged","null",37],
  ["1.38","construct","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_OPEN","STALE_LOCK_QUARANTINE_DIRECTORY","INDETERMINATE","yes","yes — path.resolve(storageRoot) inserted before throwing","fresh process; an orphan quarantine entry is possible","null",38],
  ["1.39","construct","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_VALIDATE","STALE_LOCK_QUARANTINE_DIRECTORY","INDETERMINATE","yes","yes","fresh process","null",39],
  ["1.40","construct","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_FSYNC","STALE_LOCK_QUARANTINE_DIRECTORY","INDETERMINATE","yes","yes","fresh process","null",40],
  ["1.41","construct","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_CLOSE","STALE_LOCK_QUARANTINE_DIRECTORY","INDETERMINATE","yes","yes","fresh process; the next construction waits the 60s window","null",41],
  ["1.42","construct","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_SOURCE_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","yes","fresh process","null",42],
  ["1.43","construct","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_SOURCE_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","yes","fresh process","null",43],
  ["1.44","construct","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_SOURCE_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","yes","fresh process","null",44],
  ["1.45","construct","HOST_DESCRIPTOR_CLOSE_FAILED","QUARANTINE_SOURCE_DIR_CLOSE","STAGING_DIRECTORY","COMMITTED","yes","yes","fresh process; the quarantine is durable","null",45],
  ["1.46","construct","HOST_LOCK_ACQUISITION_FAILED","LOCK_CREATE","LOCK_FILE","NOT_COMMITTED","n/a — construction returns no host object","no","retriable","null",46],
  ["1.47","construct","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_POST_CREATE_VALIDATE","LOCK_FILE","NOT_COMMITTED","no","no","retriable","null",47],
  ["1.48","construct","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_PAYLOAD_WRITE","LOCK_FILE","NOT_COMMITTED","no","no","retriable","null",48],
  ["1.49","construct","HOST_DURABILITY_WRITE_FAILED","LOCK_PAYLOAD_FSYNC","LOCK_FILE","NOT_COMMITTED","no","no","retriable","null",49],
  ["1.50","construct","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_PAYLOAD_CLOSE","LOCK_FILE","NOT_COMMITTED","no","no","retriable","null",50],
  ["1.51","construct","HOST_FILESYSTEM_READ_FAILED","LOCK_DIR_OPEN","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable","null",51],
  ["1.52","construct","HOST_STORAGE_DIRECTORY_INVALID","LOCK_DIR_VALIDATE","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable","null",52],
  ["1.53","construct","HOST_DURABILITY_WRITE_FAILED","LOCK_DIR_FSYNC","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable","null",53],
  ["1.54","construct","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_DIR_CLOSE","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable","null",54],
  ["1.55","construct","HOST_LOCK_LOST_OR_REPLACED","LOCK_IDENTITY","LOCK_FILE","NOT_COMMITTED","no","no","retriable","null",55],
  ["1.56","construct","HOST_LOCK_ACQUISITION_INDETERMINATE","LOCK_CLEANUP_PROBE","LOCK_FILE","INDETERMINATE","yes","yes","fresh process; the next construction waits the 60s window","one of 7 distinct codes: HOST_LOCK_DESCRIPTOR_INVALID, HOST_FILESYSTEM_MUTATION_FAILED, HOST_DURABILITY_WRITE_FAILED, HOST_DESCRIPTOR_CLOSE_FAILED, HOST_FILESYSTEM_READ_FAILED, HOST_STORAGE_DIRECTORY_INVALID, HOST_LOCK_LOST_OR_REPLACED",56],
  ["1.57","construct","HOST_LOCK_ACQUISITION_INDETERMINATE","LOCK_CLEANUP_UNLINK","LOCK_FILE","INDETERMINATE","yes","yes","fresh process","same 7-code allowlist as 1.56",57],
  ["1.58","construct","HOST_LOCK_ACQUISITION_INDETERMINATE","LOCK_CLEANUP_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","yes","fresh process","same 7-code allowlist",58],
  ["1.59","construct","HOST_LOCK_ACQUISITION_INDETERMINATE","LOCK_CLEANUP_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","yes","fresh process","same 7-code allowlist",59],
  ["1.60","construct","HOST_LOCK_ACQUISITION_INDETERMINATE","LOCK_CLEANUP_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","yes","fresh process","same 7-code allowlist",60],
  ["1.61","construct","HOST_CLEANUP_DESCRIPTOR_LEAKED","LOCK_CLEANUP_DIR_CLOSE","STAGING_DIRECTORY","NOT_COMMITTED","n/a — no host object is returned; there is nothing to poison as an instance","yes — path.resolve(storageRoot) inserted before throwing, since construction returns no host and the pair-registry is the only mechanism that can refuse a later same-process attempt","no host object is returned; no recovery within this process; a fresh process is required","HOST_LOCK_DESCRIPTOR_INVALID, HOST_FILESYSTEM_MUTATION_FAILED, HOST_DURABILITY_WRITE_FAILED, HOST_DESCRIPTOR_CLOSE_FAILED, HOST_FILESYSTEM_READ_FAILED, HOST_STORAGE_DIRECTORY_INVALID, HOST_LOCK_LOST_OR_REPLACED",61],
  ["2.01","reconcileRestart","HOST_PROCESS_POISONED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","already poisoned","no","close(), then a fresh process","null",1],
  ["2.02","reconcileRestart","HOST_CLOSED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","not retriable on this host","null",2],
  ["2.03","reconcileRestart","HOST_LOCK_LOST_OR_REPLACED","LOCK_IDENTITY","LOCK_FILE","NOT_APPLICABLE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",3],
  ["2.04","reconcileRestart","HOST_INVALID_NOW","CLOCK_SAMPLE","null","NOT_APPLICABLE","no","no","retriable; no sample is committed","null",4],
  ["2.05","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_OPEN","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",5],
  ["2.06","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",6],
  ["2.07","reconcileRestart","HOST_STAGING_SCAN_OVERFLOW","ENUMERATION_READ","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable after operator removal","null",7],
  ["2.08","reconcileRestart","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","ENUMERATION_CLOSE","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable; the enumeration result is discarded","null",8],
  ["2.09","reconcileRestart","HOST_UNEXPECTED_STAGING_ENTRY","ENTRY_CLASSIFY","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable after operator removal","null",9],
  ["2.10","reconcileRestart","HOST_MULTIPLE_JOURNALS_FOUND","ENTRY_CLASSIFY","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable after operator removal","null",10],
  ["2.11","reconcileRestart","HOST_TEMP_FILE_BOUND_EXCEEDED","ENTRY_CLASSIFY","TEMP_FILE","NOT_APPLICABLE","no","no","retriable after operator removal","null",11],
  ["2.12","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_OPEN","CORRUPT_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",12],
  ["2.13","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","CORRUPT_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",13],
  ["2.14","reconcileRestart","HOST_QUARANTINE_SCAN_OVERFLOW","ENUMERATION_READ","CORRUPT_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable after operator removal","null",14],
  ["2.15","reconcileRestart","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","ENUMERATION_CLOSE","CORRUPT_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",15],
  ["2.16","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_OPEN","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",16],
  ["2.17","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",17],
  ["2.18","reconcileRestart","HOST_QUARANTINE_SCAN_OVERFLOW","ENUMERATION_READ","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable after operator removal","null",18],
  ["2.19","reconcileRestart","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","ENUMERATION_CLOSE","STALE_LOCK_QUARANTINE_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",19],
  ["2.20","reconcileRestart","HOST_JOURNAL_DESCRIPTOR_INVALID","ENTRY_CLASSIFY","TEMP_FILE","NOT_APPLICABLE","no","no","retriable after operator removal","null",20],
  ["2.21","reconcileRestart","HOST_FILESYSTEM_MUTATION_FAILED","UNLINK","TEMP_FILE","NOT_COMMITTED","no","no","retriable; the temp is retained","null",21],
  ["2.22","reconcileRestart","HOST_TEMP_REMOVAL_INDETERMINATE","UNLINK_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",22],
  ["2.23","reconcileRestart","HOST_TEMP_REMOVAL_INDETERMINATE","UNLINK_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",23],
  ["2.24","reconcileRestart","HOST_TEMP_REMOVAL_INDETERMINATE","UNLINK_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",24],
  ["2.25","reconcileRestart","HOST_DESCRIPTOR_CLOSE_FAILED","UNLINK_DIR_CLOSE","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable; the sweep is already durable and idempotent","null",25],
  ["2.26","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","JOURNAL_OPEN","JOURNAL_FILE","NOT_APPLICABLE","no","no","retriable","null",26],
  ["2.27","reconcileRestart","HOST_JOURNAL_DESCRIPTOR_INVALID","JOURNAL_CLASSIFY","JOURNAL_FILE","NOT_APPLICABLE","no","no","retriable; no quarantine","null",27],
  ["2.28","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","JOURNAL_READ","JOURNAL_FILE","NOT_APPLICABLE","no","no","retriable","null",28],
  ["2.29","reconcileRestart","HOST_JOURNAL_DESCRIPTOR_INVALID","JOURNAL_METADATA_RECHECK","JOURNAL_FILE","NOT_APPLICABLE","no","no","retriable; no quarantine","null",29],
  ["2.30","reconcileRestart","HOST_DESCRIPTOR_CLOSE_FAILED","JOURNAL_CLOSE","JOURNAL_FILE","NOT_APPLICABLE","no","no","retriable; the read result is discarded","null",30],
  ["2.31","reconcileRestart","HOST_CORRUPT_QUARANTINE_BOUND_EXCEEDED","QUARANTINE_BOUND","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable after operator removal","null",31],
  ["2.32","reconcileRestart","HOST_CORRUPT_QUARANTINE_FAILED","QUARANTINE_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable; the original is unchanged","one of the 7 internal classifications",32],
  ["2.33","reconcileRestart","HOST_CORRUPT_QUARANTINE_FAILED","QUARANTINE_PRE_RENAME","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable; the original is unchanged","one of the 7 internal classifications",33],
  ["2.34","reconcileRestart","HOST_CORRUPT_QUARANTINE_FAILED","QUARANTINE_RENAME","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable; the original is unchanged","one of the 7 internal classifications",34],
  ["2.35","reconcileRestart","HOST_CORRUPT_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_OPEN","CORRUPT_QUARANTINE_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of the 7 internal classifications",35],
  ["2.36","reconcileRestart","HOST_CORRUPT_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_VALIDATE","CORRUPT_QUARANTINE_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of the 7 internal classifications",36],
  ["2.37","reconcileRestart","HOST_CORRUPT_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_FSYNC","CORRUPT_QUARANTINE_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of the 7 internal classifications",37],
  ["2.38","reconcileRestart","HOST_CORRUPT_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_CLOSE","CORRUPT_QUARANTINE_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of the 7 internal classifications",38],
  ["2.39","reconcileRestart","HOST_CORRUPT_QUARANTINE_INDETERMINATE","QUARANTINE_SOURCE_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of the 7 internal classifications",39],
  ["2.40","reconcileRestart","HOST_CORRUPT_QUARANTINE_INDETERMINATE","QUARANTINE_SOURCE_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of the 7 internal classifications",40],
  ["2.41","reconcileRestart","HOST_CORRUPT_QUARANTINE_INDETERMINATE","QUARANTINE_SOURCE_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of the 7 internal classifications",41],
  ["2.42","reconcileRestart","HOST_DESCRIPTOR_CLOSE_FAILED","QUARANTINE_SOURCE_DIR_CLOSE","STAGING_DIRECTORY","COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation; the quarantine is durable","null",42],
  ["2.43","reconcileRestart","HOST_SERIALIZATION_REJECTED","SERIALIZE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",43],
  ["2.44","reconcileRestart","HOST_TEMP_FILE_BOUND_EXCEEDED","TEMP_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable after operator removal","null",44],
  ["2.45","reconcileRestart","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",45],
  ["2.46","reconcileRestart","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",46],
  ["2.47","reconcileRestart","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",47],
  ["2.48","reconcileRestart","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",48],
  ["2.49","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",49],
  ["2.50","reconcileRestart","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",50],
  ["2.51","reconcileRestart","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",51],
  ["2.52","reconcileRestart","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",52],
  ["2.53","reconcileRestart","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",53],
  ["2.54","reconcileRestart","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",54],
  ["2.55","reconcileRestart","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; no silent retry","null",55],
  ["2.56","reconcileRestart","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",56],
  ["2.57","reconcileRestart","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",57],
  ["2.58","reconcileRestart","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",58],
  ["2.59","reconcileRestart","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",59],
  ["2.60","reconcileRestart","HOST_DESCRIPTOR_CLOSE_FAILED","PARENT_DIR_CLOSE","STAGING_DIRECTORY","COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation; the pending clock sample WAS committed","null",60],
  ["2.61","reconcileRestart","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_UNLINK","TEMP_FILE","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of 6 distinct codes: HOST_FILESYSTEM_MUTATION_FAILED, HOST_DURABILITY_WRITE_FAILED, HOST_DESCRIPTOR_CLOSE_FAILED, HOST_FILESYSTEM_READ_FAILED, HOST_JOURNAL_DESCRIPTOR_INVALID, HOST_DISK_STATE_CHANGED",61],
  ["2.62","reconcileRestart","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_OPEN","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","same 6-code allowlist as 2.61",62],
  ["2.63","reconcileRestart","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_VALIDATE","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","same 6-code allowlist as 2.61",63],
  ["2.64","reconcileRestart","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_FSYNC","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","same 6-code allowlist as 2.61; HOST_SERIALIZATION_REJECTED and HOST_TEMP_FILE_BOUND_EXCEEDED can never appear here",64],
  ["2.65","reconcileRestart","HOST_CLEANUP_DESCRIPTOR_LEAKED","TEMP_CLEANUP_DIR_CLOSE","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of 6 distinct codes: HOST_FILESYSTEM_MUTATION_FAILED, HOST_DURABILITY_WRITE_FAILED, HOST_DESCRIPTOR_CLOSE_FAILED, HOST_FILESYSTEM_READ_FAILED, HOST_JOURNAL_DESCRIPTOR_INVALID, HOST_DISK_STATE_CHANGED",65],
  ["3.01","createJournal","HOST_PROCESS_POISONED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","already poisoned","no","close(), then a fresh process","null",1],
  ["3.02","createJournal","HOST_CLOSED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","not retriable on this host","null",2],
  ["3.03","createJournal","HOST_RECONCILIATION_REQUIRED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","call reconcileRestart first","null",3],
  ["3.04","createJournal","HOST_LOCK_LOST_OR_REPLACED","LOCK_IDENTITY","LOCK_FILE","NOT_APPLICABLE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",4],
  ["3.05","createJournal","HOST_JOURNAL_ALREADY_EXISTS","JOURNAL_PRECONDITION","JOURNAL_FILE","NOT_APPLICABLE","no","no","cancel and acknowledge, or use a fresh root","null",5],
  ["3.06","createJournal","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_OPEN","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",6],
  ["3.07","createJournal","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",7],
  ["3.08","createJournal","HOST_STAGING_SCAN_OVERFLOW","ENUMERATION_READ","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable after operator removal","null",8],
  ["3.09","createJournal","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","ENUMERATION_CLOSE","STAGING_DIRECTORY","NOT_APPLICABLE","no","no","retriable","null",9],
  ["3.10","createJournal","HOST_JOURNAL_ALREADY_EXISTS","JOURNAL_PRECONDITION_DISK_SCAN","JOURNAL_FILE","NOT_APPLICABLE","no","no","reconcile with a fresh host, then retry","null",10],
  ["3.11","createJournal","HOST_INVALID_NOW","CLOCK_SAMPLE","null","NOT_COMMITTED","no","no","retriable; the pending sample is discarded","null",11],
  ["3.12","createJournal","HOST_CLOCK_REGRESSION_DETECTED","CLOCK_TRACKING","null","NOT_COMMITTED","no","no","retriable after the clock is corrected","null",12],
  ["3.13","createJournal","HOST_SERIALIZATION_REJECTED","SERIALIZE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",13],
  ["3.14","createJournal","HOST_TEMP_FILE_BOUND_EXCEEDED","TEMP_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable after operator removal","null",14],
  ["3.15","createJournal","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",15],
  ["3.16","createJournal","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",16],
  ["3.17","createJournal","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",17],
  ["3.18","createJournal","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",18],
  ["3.19","createJournal","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",19],
  ["3.20","createJournal","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",20],
  ["3.21","createJournal","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",21],
  ["3.22","createJournal","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_OPEN","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable","null",22],
  ["3.23","createJournal","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_READ","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable","null",23],
  ["3.24","createJournal","HOST_STAGING_SCAN_OVERFLOW","CAS_CREATE_SCAN_READ","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable after operator removal","null",24],
  ["3.25","createJournal","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","CAS_CREATE_SCAN_CLOSE","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable","null",25],
  ["3.26","createJournal","HOST_DISK_STATE_CHANGED","CAS_CREATE_SCAN_MATCH","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile then retry","null",26],
  ["3.27","createJournal","HOST_DISK_STATE_CHANGED","CAS_CREATE_ABSENCE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",27],
  ["3.28","createJournal","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_ABSENCE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",28],
  ["3.29","createJournal","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",29],
  ["3.30","createJournal","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",30],
  ["3.31","createJournal","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",31],
  ["3.32","createJournal","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","null",32],
  ["3.33","createJournal","HOST_DESCRIPTOR_CLOSE_FAILED","PARENT_DIR_CLOSE","STAGING_DIRECTORY","COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation; the data is committed","null",33],
  ["3.34","createJournal","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_UNLINK","TEMP_FILE","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of 8 distinct codes: HOST_FILESYSTEM_MUTATION_FAILED, HOST_DURABILITY_WRITE_FAILED, HOST_DESCRIPTOR_CLOSE_FAILED, HOST_FILESYSTEM_READ_FAILED, HOST_JOURNAL_DESCRIPTOR_INVALID, HOST_STAGING_SCAN_OVERFLOW, HOST_ENUMERATION_HANDLE_CLOSE_FAILED, HOST_DISK_STATE_CHANGED",34],
  ["3.35","createJournal","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_OPEN","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","same 8-code allowlist as 3.34",35],
  ["3.36","createJournal","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_VALIDATE","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","same 8-code allowlist as 3.34",36],
  ["3.37","createJournal","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_FSYNC","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","same 8-code allowlist as 3.34; a 3.13 serializer rejection and a 3.14 EEXIST never reach any cleanup row",37],
  ["3.38","createJournal","HOST_CLEANUP_DESCRIPTOR_LEAKED","TEMP_CLEANUP_DIR_CLOSE","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close if possible; fresh process, construction, and reconciliation","one of 8 distinct codes: HOST_FILESYSTEM_MUTATION_FAILED, HOST_DURABILITY_WRITE_FAILED, HOST_DESCRIPTOR_CLOSE_FAILED, HOST_FILESYSTEM_READ_FAILED, HOST_JOURNAL_DESCRIPTOR_INVALID, HOST_STAGING_SCAN_OVERFLOW, HOST_ENUMERATION_HANDLE_CLOSE_FAILED, HOST_DISK_STATE_CHANGED",38],
  ["4.01","stageRole","HOST_PROCESS_POISONED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","already poisoned","no","close(), then a fresh process","null",1],
  ["4.02","stageRole","HOST_CLOSED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","not retriable on this host","null",2],
  ["4.03","stageRole","HOST_RECONCILIATION_REQUIRED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","call reconcileRestart first","null",3],
  ["4.04","stageRole","HOST_LOCK_LOST_OR_REPLACED","LOCK_IDENTITY","LOCK_FILE","NOT_APPLICABLE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",4],
  ["4.05","stageRole","HOST_JOURNAL_NOT_FOUND","JOURNAL_PRECONDITION","JOURNAL_FILE","NOT_APPLICABLE","no","no","create first","null",5],
  ["4.06","stageRole","HOST_JOURNAL_NOT_ACTIVE","JOURNAL_PRECONDITION","JOURNAL_FILE","NOT_APPLICABLE","no","no","acknowledge the terminal record first","null",6],
  ["4.07","stageRole","HOST_INVALID_NOW","CLOCK_SAMPLE","null","NOT_COMMITTED","no","no","retriable; the pending sample is discarded","null",7],
  ["4.08","stageRole","HOST_CLOCK_REGRESSION_DETECTED","CLOCK_TRACKING","null","NOT_COMMITTED","no","no","retriable after the clock is corrected","null",8],
  ["4.09","stageRole","HOST_DISK_STATE_CHANGED","CAS_INITIAL_OPEN","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",9],
  ["4.10","stageRole","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_OPEN","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",10],
  ["4.11","stageRole","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_CLASSIFY","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",11],
  ["4.12","stageRole","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_READ","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",12],
  ["4.13","stageRole","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_RECHECK","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",13],
  ["4.14","stageRole","HOST_DISK_STATE_CHANGED","CAS_INITIAL_CHECKSUM_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; no silent retry","null",14],
  ["4.15","stageRole","HOST_DISK_STATE_CHANGED","CAS_INITIAL_IDENTITY_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; no silent retry","null",15],
  ["4.16","stageRole","HOST_DESCRIPTOR_CLOSE_FAILED","CAS_INITIAL_CLOSE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",16],
  ["4.17","stageRole","HOST_SERIALIZATION_REJECTED","SERIALIZE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",17],
  ["4.18","stageRole","HOST_TEMP_FILE_BOUND_EXCEEDED","TEMP_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable after operator removal","null",18],
  ["4.19","stageRole","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",19],
  ["4.20","stageRole","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",20],
  ["4.21","stageRole","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",21],
  ["4.22","stageRole","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",22],
  ["4.23","stageRole","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",23],
  ["4.24","stageRole","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",24],
  ["4.25","stageRole","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",25],
  ["4.26","stageRole","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",26],
  ["4.27","stageRole","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",27],
  ["4.28","stageRole","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",28],
  ["4.29","stageRole","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; no silent retry","null",29],
  ["4.30","stageRole","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",30],
  ["4.31","stageRole","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",31],
  ["4.32","stageRole","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",32],
  ["4.33","stageRole","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",33],
  ["4.34","stageRole","HOST_DESCRIPTOR_CLOSE_FAILED","PARENT_DIR_CLOSE","STAGING_DIRECTORY","COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation; the data is committed","null",34],
  ["4.35","stageRole","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_UNLINK","TEMP_FILE","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","one of 6 distinct codes: HOST_FILESYSTEM_MUTATION_FAILED, HOST_DURABILITY_WRITE_FAILED, HOST_DESCRIPTOR_CLOSE_FAILED, HOST_FILESYSTEM_READ_FAILED, HOST_JOURNAL_DESCRIPTOR_INVALID, HOST_DISK_STATE_CHANGED",35],
  ["4.36","stageRole","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_OPEN","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","same 6-code allowlist as 4.35",36],
  ["4.37","stageRole","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_VALIDATE","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","same 6-code allowlist as 4.35",37],
  ["4.38","stageRole","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_FSYNC","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","same 6-code allowlist as 4.35; separately, this six-value allowlist is exhaustive for stageRole's owned-temp cleanup",38],
  ["4.39","stageRole","HOST_CLEANUP_DESCRIPTOR_LEAKED","TEMP_CLEANUP_DIR_CLOSE","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","one of 6 distinct codes: HOST_FILESYSTEM_MUTATION_FAILED, HOST_DURABILITY_WRITE_FAILED, HOST_DESCRIPTOR_CLOSE_FAILED, HOST_FILESYSTEM_READ_FAILED, HOST_JOURNAL_DESCRIPTOR_INVALID, HOST_DISK_STATE_CHANGED",39],
  ["5.01","cancel","HOST_PROCESS_POISONED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","already poisoned","path.resolve(storageRoot) inserted before throwing","close(), then a fresh process","null",1],
  ["5.02","cancel","HOST_CLOSED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","not retriable on this host","null",2],
  ["5.03","cancel","HOST_RECONCILIATION_REQUIRED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","call reconcileRestart first","null",3],
  ["5.04","cancel","HOST_LOCK_LOST_OR_REPLACED","LOCK_IDENTITY","LOCK_FILE","NOT_APPLICABLE","yes","path.resolve(storageRoot) inserted before throwing","fresh host","null",4],
  ["5.05","cancel","HOST_JOURNAL_NOT_FOUND","JOURNAL_PRECONDITION","JOURNAL_FILE","NOT_APPLICABLE","no","no","create first","null",5],
  ["5.06","cancel","HOST_JOURNAL_NOT_ACTIVE","JOURNAL_PRECONDITION","JOURNAL_FILE","NOT_APPLICABLE","no","no","acknowledge the terminal record first","null",6],
  ["5.07","cancel","HOST_INVALID_NOW","CLOCK_SAMPLE","null","NOT_COMMITTED","no","no","retriable; the pending sample is discarded","null",7],
  ["5.08","cancel","HOST_CLOCK_REGRESSION_DETECTED","CLOCK_TRACKING","null","NOT_COMMITTED","no","no","retriable after the clock is corrected","null",8],
  ["5.09","cancel","HOST_DISK_STATE_CHANGED","CAS_INITIAL_OPEN","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",9],
  ["5.10","cancel","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_OPEN","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",10],
  ["5.11","cancel","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_CLASSIFY","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",11],
  ["5.12","cancel","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_READ","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",12],
  ["5.13","cancel","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_RECHECK","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",13],
  ["5.14","cancel","HOST_DISK_STATE_CHANGED","CAS_INITIAL_CHECKSUM_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; no silent retry","null",14],
  ["5.15","cancel","HOST_DISK_STATE_CHANGED","CAS_INITIAL_IDENTITY_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; no silent retry","null",15],
  ["5.16","cancel","HOST_DESCRIPTOR_CLOSE_FAILED","CAS_INITIAL_CLOSE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",16],
  ["5.17","cancel","HOST_SERIALIZATION_REJECTED","SERIALIZE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",17],
  ["5.18","cancel","HOST_TEMP_FILE_BOUND_EXCEEDED","TEMP_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable after operator removal","null",18],
  ["5.19","cancel","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",19],
  ["5.20","cancel","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",20],
  ["5.21","cancel","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",21],
  ["5.22","cancel","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",22],
  ["5.23","cancel","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",23],
  ["5.24","cancel","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",24],
  ["5.25","cancel","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","TEMP_FILE","NOT_COMMITTED","no","no","retriable","null",25],
  ["5.26","cancel","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",26],
  ["5.27","cancel","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",27],
  ["5.28","cancel","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",28],
  ["5.29","cancel","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; no silent retry","null",29],
  ["5.30","cancel","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",30],
  ["5.31","cancel","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","fresh host must reconcile","null",31],
  ["5.32","cancel","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","fresh host must reconcile","null",32],
  ["5.33","cancel","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","fresh host must reconcile","null",33],
  ["5.34","cancel","HOST_DESCRIPTOR_CLOSE_FAILED","PARENT_DIR_CLOSE","STAGING_DIRECTORY","COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","fresh host; the data is committed","null",34],
  ["5.35","cancel","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_UNLINK","TEMP_FILE","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","fresh host","one of the 6 owned-temp antecedents",35],
  ["5.36","cancel","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_OPEN","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","fresh host","one of the 6 owned-temp antecedents",36],
  ["5.37","cancel","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_VALIDATE","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","fresh host","one of the 6 owned-temp antecedents",37],
  ["5.38","cancel","HOST_TEMP_REMOVAL_INDETERMINATE","TEMP_CLEANUP_DIR_FSYNC","STAGING_DIRECTORY","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","fresh host","one of the 6 owned-temp antecedents",38],
  ["5.39","cancel","HOST_CLEANUP_DESCRIPTOR_LEAKED","TEMP_CLEANUP_DIR_CLOSE","STAGING_DIRECTORY","NOT_COMMITTED","no","no","retriable","null",39],
  ["6.01","status","HOST_PROCESS_POISONED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","already poisoned","no","close(), then a fresh process","null",1],
  ["6.02","status","HOST_CLOSED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","not retriable on this host","null",2],
  ["6.03","status","HOST_RECONCILIATION_REQUIRED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","call reconcileRestart first","null",3],
  ["6.04","status","HOST_LOCK_LOST_OR_REPLACED","LOCK_IDENTITY","LOCK_FILE","NOT_APPLICABLE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",4],
  ["7.01","acknowledgeTerminal","HOST_PROCESS_POISONED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","already poisoned","no","close(), then a fresh process","null",1],
  ["7.02","acknowledgeTerminal","HOST_CLOSED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","not retriable on this host","null",2],
  ["7.03","acknowledgeTerminal","HOST_RECONCILIATION_REQUIRED","LIFECYCLE_GUARD","null","NOT_APPLICABLE","no","no","call reconcileRestart first","null",3],
  ["7.04","acknowledgeTerminal","HOST_LOCK_LOST_OR_REPLACED","LOCK_IDENTITY","LOCK_FILE","NOT_APPLICABLE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",4],
  ["7.05","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_INPUT_NOT_OBJECT","ACK_INPUT_VALIDATION","null","NOT_APPLICABLE","no","no","retry with a corrected object","null",5],
  ["7.06","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_ENUMERATION_FAILED","ACK_INPUT_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",6],
  ["7.07","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_INPUT_EXTRA_KEY","ACK_INPUT_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",7],
  ["7.08","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_INPUT_MISSING_KEY","ACK_INPUT_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",8],
  ["7.09","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_READ_FAILED","ACK_INPUT_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",9],
  ["7.10","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_INPUT_INVALID","ACK_INPUT_VALIDATION","null","NOT_APPLICABLE","no","no","retriable","null",10],
  ["7.11","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_PRECONDITION_FAILED","ACK_PRECONDITION","null","NOT_APPLICABLE","no","no","nothing to acknowledge","null",11],
  ["7.12","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_PRECONDITION_FAILED","ACK_PRECONDITION_NON_TERMINAL","null","NOT_APPLICABLE","no","no","cancel first","null",12],
  ["7.13","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_IDENTITY_MISMATCH","ACK_IDENTITY_MATCH","JOURNAL_FILE","NOT_APPLICABLE","no","no","retry with the correct identity","null",13],
  ["7.14","acknowledgeTerminal","HOST_ACKNOWLEDGMENT_CHECKSUM_MISMATCH","ACK_IDENTITY_MATCH","JOURNAL_FILE","NOT_APPLICABLE","no","no","retry with the correct checksum","null",14],
  ["7.15","acknowledgeTerminal","HOST_DISK_STATE_CHANGED","CAS_INITIAL_OPEN","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",15],
  ["7.16","acknowledgeTerminal","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_OPEN","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",16],
  ["7.17","acknowledgeTerminal","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_CLASSIFY","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",17],
  ["7.18","acknowledgeTerminal","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_READ","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",18],
  ["7.19","acknowledgeTerminal","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_RECHECK","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",19],
  ["7.20","acknowledgeTerminal","HOST_DISK_STATE_CHANGED","CAS_INITIAL_CHECKSUM_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",20],
  ["7.21","acknowledgeTerminal","HOST_DISK_STATE_CHANGED","CAS_INITIAL_IDENTITY_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",21],
  ["7.22","acknowledgeTerminal","HOST_DESCRIPTOR_CLOSE_FAILED","CAS_INITIAL_CLOSE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",22],
  ["7.23","acknowledgeTerminal","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",23],
  ["7.24","acknowledgeTerminal","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",24],
  ["7.25","acknowledgeTerminal","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable","null",25],
  ["7.26","acknowledgeTerminal","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","JOURNAL_FILE","NOT_COMMITTED","no","no","fresh host; reconcile","null",26],
  ["7.27","acknowledgeTerminal","HOST_FILESYSTEM_MUTATION_FAILED","UNLINK","JOURNAL_FILE","NOT_COMMITTED","no","no","retriable; the record is retained","null",27],
  ["7.28","acknowledgeTerminal","HOST_JOURNAL_REMOVAL_INDETERMINATE","UNLINK_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",28],
  ["7.29","acknowledgeTerminal","HOST_JOURNAL_REMOVAL_INDETERMINATE","UNLINK_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",29],
  ["7.30","acknowledgeTerminal","HOST_JOURNAL_REMOVAL_INDETERMINATE","UNLINK_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation","null",30],
  ["7.31","acknowledgeTerminal","HOST_DESCRIPTOR_CLOSE_FAILED","UNLINK_DIR_CLOSE","STAGING_DIRECTORY","COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","close the existing host if possible; fresh process, fresh construction, and reconciliation; the removal is committed","null",31],
  ["8.01","close","HOST_LOCK_LOST_OR_REPLACED","LOCK_RELEASE_PROBE","LOCK_FILE","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","the close attempt is terminal for the remainder of this process; do not retry lock release in the same process; recovery requires a fresh process, fresh construction, and reconciliation; the module registry remains populated","null",1],
  ["8.02","close","HOST_FILESYSTEM_READ_FAILED","LOCK_RELEASE_PROBE","LOCK_FILE","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","the close attempt is terminal for the remainder of this process; do not retry lock release in the same process; recovery requires a fresh process, fresh construction, and reconciliation; the module registry remains populated","null",2],
  ["8.03","close","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_RELEASE_PROBE","LOCK_FILE","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","the close attempt is terminal for the remainder of this process; do not retry lock release in the same process; recovery requires a fresh process, fresh construction, and reconciliation; the module registry remains populated","null",3],
  ["8.04","close","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_RELEASE_UNLINK","LOCK_FILE","NOT_COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","the close attempt is terminal for the remainder of this process; do not retry lock release in the same process; recovery requires a fresh process, fresh construction, and reconciliation; the module registry remains populated","null",4],
  ["8.05","close","HOST_LOCK_RELEASE_INDETERMINATE","LOCK_RELEASE_DIR_OPEN","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","the close attempt is terminal for the remainder of this process; do not retry lock release in the same process; recovery requires a fresh process, fresh construction, and reconciliation; the module registry remains populated","null",5],
  ["8.06","close","HOST_LOCK_RELEASE_INDETERMINATE","LOCK_RELEASE_DIR_VALIDATE","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","the close attempt is terminal for the remainder of this process; do not retry lock release in the same process; recovery requires a fresh process, fresh construction, and reconciliation; the module registry remains populated","null",6],
  ["8.07","close","HOST_LOCK_RELEASE_INDETERMINATE","LOCK_RELEASE_DIR_FSYNC","STAGING_DIRECTORY","INDETERMINATE","yes","path.resolve(storageRoot) inserted before throwing","the close attempt is terminal for the remainder of this process; do not retry lock release in the same process; recovery requires a fresh process, fresh construction, and reconciliation; the module registry remains populated","null",7],
  ["8.08","close","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_RELEASE_DIR_CLOSE","STAGING_DIRECTORY","COMMITTED","yes","path.resolve(storageRoot) inserted before throwing","the close attempt is terminal for the remainder of this process; do not retry lock release in the same process; recovery requires a fresh process, fresh construction, and reconciliation; the module registry remains populated","null",8]
];

// [id, antecedent, antecedentCode, antecedentPhase, consequentRow,
//  consequentPhase, operation, family]
const COMPOUND_ROWS = [
  ["1.18~1.14","1.14","HOST_STORAGE_DIRECTORY_INVALID","DIRECTORY_VALIDATE","1.18","DIRECTORY_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.18~1.15","1.15","HOST_STORAGE_DIRECTORY_MODE_INVALID","DIRECTORY_VALIDATE","1.18","DIRECTORY_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.18~1.16","1.16","HOST_STORAGE_DIRECTORY_OWNER_INVALID","DIRECTORY_VALIDATE","1.18","DIRECTORY_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.18~1.17","1.17","HOST_DURABILITY_WRITE_FAILED","DIRECTORY_FSYNC","1.18","DIRECTORY_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.22~1.20","1.20","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","1.22","ENUMERATION_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.22~1.21","1.21","HOST_QUARANTINE_SCAN_OVERFLOW","ENUMERATION_READ","1.22","ENUMERATION_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.28~1.24","1.24","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_PROBE_CLASSIFY","1.28","LOCK_PROBE_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.28~1.25","1.25","HOST_LOCK_FILE_OVERSIZED","LOCK_PROBE_CLASSIFY","1.28","LOCK_PROBE_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.28~1.26","1.26","HOST_FILESYSTEM_READ_FAILED","LOCK_PROBE_READ","1.28","LOCK_PROBE_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.28~1.27","1.27","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_PROBE_RECHECK","1.28","LOCK_PROBE_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.41~1.39","1.39","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_VALIDATE","1.41","QUARANTINE_DEST_DIR_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.41~1.40","1.40","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_DEST_DIR_FSYNC","1.41","QUARANTINE_DEST_DIR_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.45~1.43","1.43","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_SOURCE_DIR_VALIDATE","1.45","QUARANTINE_SOURCE_DIR_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.45~1.44","1.44","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","QUARANTINE_SOURCE_DIR_FSYNC","1.45","QUARANTINE_SOURCE_DIR_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.50~1.47","1.47","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_POST_CREATE_VALIDATE","1.50","LOCK_PAYLOAD_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.50~1.48","1.48","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_PAYLOAD_WRITE","1.50","LOCK_PAYLOAD_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.50~1.49","1.49","HOST_DURABILITY_WRITE_FAILED","LOCK_PAYLOAD_FSYNC","1.50","LOCK_PAYLOAD_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.54~1.52","1.52","HOST_STORAGE_DIRECTORY_INVALID","LOCK_DIR_VALIDATE","1.54","LOCK_DIR_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.54~1.53","1.53","HOST_DURABILITY_WRITE_FAILED","LOCK_DIR_FSYNC","1.54","LOCK_DIR_CLOSE","construct","DESCRIPTOR_CLOSE"],
  ["1.56~1.47","1.47","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_POST_CREATE_VALIDATE","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.56~1.48","1.48","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_PAYLOAD_WRITE","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.56~1.49","1.49","HOST_DURABILITY_WRITE_FAILED","LOCK_PAYLOAD_FSYNC","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.56~1.50","1.50","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_PAYLOAD_CLOSE","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.56~1.51","1.51","HOST_FILESYSTEM_READ_FAILED","LOCK_DIR_OPEN","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.56~1.52","1.52","HOST_STORAGE_DIRECTORY_INVALID","LOCK_DIR_VALIDATE","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.56~1.53","1.53","HOST_DURABILITY_WRITE_FAILED","LOCK_DIR_FSYNC","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.56~1.54","1.54","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_DIR_CLOSE","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.56~1.55","1.55","HOST_LOCK_LOST_OR_REPLACED","LOCK_IDENTITY","1.56","LOCK_CLEANUP_PROBE","construct","F2"],
  ["1.57~1.47","1.47","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_POST_CREATE_VALIDATE","1.57","LOCK_CLEANUP_UNLINK","construct","F2"],
  ["1.57~1.48","1.48","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_PAYLOAD_WRITE","1.57","LOCK_CLEANUP_UNLINK","construct","F2"],
  ["1.57~1.49","1.49","HOST_DURABILITY_WRITE_FAILED","LOCK_PAYLOAD_FSYNC","1.57","LOCK_CLEANUP_UNLINK","construct","F2"],
  ["1.57~1.50","1.50","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_PAYLOAD_CLOSE","1.57","LOCK_CLEANUP_UNLINK","construct","F2"],
  ["1.57~1.51","1.51","HOST_FILESYSTEM_READ_FAILED","LOCK_DIR_OPEN","1.57","LOCK_CLEANUP_UNLINK","construct","F2"],
  ["1.57~1.52","1.52","HOST_STORAGE_DIRECTORY_INVALID","LOCK_DIR_VALIDATE","1.57","LOCK_CLEANUP_UNLINK","construct","F2"],
  ["1.57~1.53","1.53","HOST_DURABILITY_WRITE_FAILED","LOCK_DIR_FSYNC","1.57","LOCK_CLEANUP_UNLINK","construct","F2"],
  ["1.57~1.54","1.54","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_DIR_CLOSE","1.57","LOCK_CLEANUP_UNLINK","construct","F2"],
  ["1.58~1.47","1.47","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_POST_CREATE_VALIDATE","1.58","LOCK_CLEANUP_DIR_OPEN","construct","F2"],
  ["1.58~1.48","1.48","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_PAYLOAD_WRITE","1.58","LOCK_CLEANUP_DIR_OPEN","construct","F2"],
  ["1.58~1.49","1.49","HOST_DURABILITY_WRITE_FAILED","LOCK_PAYLOAD_FSYNC","1.58","LOCK_CLEANUP_DIR_OPEN","construct","F2"],
  ["1.58~1.50","1.50","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_PAYLOAD_CLOSE","1.58","LOCK_CLEANUP_DIR_OPEN","construct","F2"],
  ["1.58~1.51","1.51","HOST_FILESYSTEM_READ_FAILED","LOCK_DIR_OPEN","1.58","LOCK_CLEANUP_DIR_OPEN","construct","F2"],
  ["1.58~1.52","1.52","HOST_STORAGE_DIRECTORY_INVALID","LOCK_DIR_VALIDATE","1.58","LOCK_CLEANUP_DIR_OPEN","construct","F2"],
  ["1.58~1.53","1.53","HOST_DURABILITY_WRITE_FAILED","LOCK_DIR_FSYNC","1.58","LOCK_CLEANUP_DIR_OPEN","construct","F2"],
  ["1.58~1.54","1.54","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_DIR_CLOSE","1.58","LOCK_CLEANUP_DIR_OPEN","construct","F2"],
  ["1.59~1.47","1.47","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_POST_CREATE_VALIDATE","1.59","LOCK_CLEANUP_DIR_VALIDATE","construct","F2"],
  ["1.59~1.48","1.48","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_PAYLOAD_WRITE","1.59","LOCK_CLEANUP_DIR_VALIDATE","construct","F2"],
  ["1.59~1.49","1.49","HOST_DURABILITY_WRITE_FAILED","LOCK_PAYLOAD_FSYNC","1.59","LOCK_CLEANUP_DIR_VALIDATE","construct","F2"],
  ["1.59~1.50","1.50","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_PAYLOAD_CLOSE","1.59","LOCK_CLEANUP_DIR_VALIDATE","construct","F2"],
  ["1.59~1.51","1.51","HOST_FILESYSTEM_READ_FAILED","LOCK_DIR_OPEN","1.59","LOCK_CLEANUP_DIR_VALIDATE","construct","F2"],
  ["1.59~1.52","1.52","HOST_STORAGE_DIRECTORY_INVALID","LOCK_DIR_VALIDATE","1.59","LOCK_CLEANUP_DIR_VALIDATE","construct","F2"],
  ["1.59~1.53","1.53","HOST_DURABILITY_WRITE_FAILED","LOCK_DIR_FSYNC","1.59","LOCK_CLEANUP_DIR_VALIDATE","construct","F2"],
  ["1.59~1.54","1.54","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_DIR_CLOSE","1.59","LOCK_CLEANUP_DIR_VALIDATE","construct","F2"],
  ["1.60~1.47","1.47","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_POST_CREATE_VALIDATE","1.60","LOCK_CLEANUP_DIR_FSYNC","construct","F2"],
  ["1.60~1.48","1.48","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_PAYLOAD_WRITE","1.60","LOCK_CLEANUP_DIR_FSYNC","construct","F2"],
  ["1.60~1.49","1.49","HOST_DURABILITY_WRITE_FAILED","LOCK_PAYLOAD_FSYNC","1.60","LOCK_CLEANUP_DIR_FSYNC","construct","F2"],
  ["1.60~1.50","1.50","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_PAYLOAD_CLOSE","1.60","LOCK_CLEANUP_DIR_FSYNC","construct","F2"],
  ["1.60~1.51","1.51","HOST_FILESYSTEM_READ_FAILED","LOCK_DIR_OPEN","1.60","LOCK_CLEANUP_DIR_FSYNC","construct","F2"],
  ["1.60~1.52","1.52","HOST_STORAGE_DIRECTORY_INVALID","LOCK_DIR_VALIDATE","1.60","LOCK_CLEANUP_DIR_FSYNC","construct","F2"],
  ["1.60~1.53","1.53","HOST_DURABILITY_WRITE_FAILED","LOCK_DIR_FSYNC","1.60","LOCK_CLEANUP_DIR_FSYNC","construct","F2"],
  ["1.60~1.54","1.54","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_DIR_CLOSE","1.60","LOCK_CLEANUP_DIR_FSYNC","construct","F2"],
  ["1.61~1.47","1.47","HOST_LOCK_DESCRIPTOR_INVALID","LOCK_POST_CREATE_VALIDATE","1.61","LOCK_CLEANUP_DIR_CLOSE","construct","F2"],
  ["1.61~1.48","1.48","HOST_FILESYSTEM_MUTATION_FAILED","LOCK_PAYLOAD_WRITE","1.61","LOCK_CLEANUP_DIR_CLOSE","construct","F2"],
  ["1.61~1.49","1.49","HOST_DURABILITY_WRITE_FAILED","LOCK_PAYLOAD_FSYNC","1.61","LOCK_CLEANUP_DIR_CLOSE","construct","F2"],
  ["1.61~1.50","1.50","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_PAYLOAD_CLOSE","1.61","LOCK_CLEANUP_DIR_CLOSE","construct","F2"],
  ["1.61~1.51","1.51","HOST_FILESYSTEM_READ_FAILED","LOCK_DIR_OPEN","1.61","LOCK_CLEANUP_DIR_CLOSE","construct","F2"],
  ["1.61~1.52","1.52","HOST_STORAGE_DIRECTORY_INVALID","LOCK_DIR_VALIDATE","1.61","LOCK_CLEANUP_DIR_CLOSE","construct","F2"],
  ["1.61~1.53","1.53","HOST_DURABILITY_WRITE_FAILED","LOCK_DIR_FSYNC","1.61","LOCK_CLEANUP_DIR_CLOSE","construct","F2"],
  ["1.61~1.54","1.54","HOST_DESCRIPTOR_CLOSE_FAILED","LOCK_DIR_CLOSE","1.61","LOCK_CLEANUP_DIR_CLOSE","construct","F2"],
  ["2.08~2.06","2.06","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","2.08","ENUMERATION_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.08~2.07","2.07","HOST_STAGING_SCAN_OVERFLOW","ENUMERATION_READ","2.08","ENUMERATION_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.15~2.13","2.13","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","2.15","ENUMERATION_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.15~2.14","2.14","HOST_QUARANTINE_SCAN_OVERFLOW","ENUMERATION_READ","2.15","ENUMERATION_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.19~2.17","2.17","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","2.19","ENUMERATION_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.19~2.18","2.18","HOST_QUARANTINE_SCAN_OVERFLOW","ENUMERATION_READ","2.19","ENUMERATION_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.25~2.23","2.23","HOST_TEMP_REMOVAL_INDETERMINATE","UNLINK_DIR_VALIDATE","2.25","UNLINK_DIR_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.25~2.24","2.24","HOST_TEMP_REMOVAL_INDETERMINATE","UNLINK_DIR_FSYNC","2.25","UNLINK_DIR_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.30~2.27","2.27","HOST_JOURNAL_DESCRIPTOR_INVALID","JOURNAL_CLASSIFY","2.30","JOURNAL_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.30~2.28","2.28","HOST_FILESYSTEM_READ_FAILED","JOURNAL_READ","2.30","JOURNAL_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.30~2.29","2.29","HOST_JOURNAL_DESCRIPTOR_INVALID","JOURNAL_METADATA_RECHECK","2.30","JOURNAL_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.31~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.31","QUARANTINE_BOUND","reconcileRestart","F3"],
  ["2.31~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.31","QUARANTINE_BOUND","reconcileRestart","F3"],
  ["2.31~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.31","QUARANTINE_BOUND","reconcileRestart","F3"],
  ["2.31~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.31","QUARANTINE_BOUND","reconcileRestart","F3"],
  ["2.31~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.31","QUARANTINE_BOUND","reconcileRestart","F3"],
  ["2.31~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.31","QUARANTINE_BOUND","reconcileRestart","F3"],
  ["2.31~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.31","QUARANTINE_BOUND","reconcileRestart","F3"],
  ["2.32~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.32","QUARANTINE_PROBE","reconcileRestart","F3"],
  ["2.32~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.32","QUARANTINE_PROBE","reconcileRestart","F3"],
  ["2.32~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.32","QUARANTINE_PROBE","reconcileRestart","F3"],
  ["2.32~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.32","QUARANTINE_PROBE","reconcileRestart","F3"],
  ["2.32~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.32","QUARANTINE_PROBE","reconcileRestart","F3"],
  ["2.32~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.32","QUARANTINE_PROBE","reconcileRestart","F3"],
  ["2.32~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.32","QUARANTINE_PROBE","reconcileRestart","F3"],
  ["2.33~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.33","QUARANTINE_PRE_RENAME","reconcileRestart","F3"],
  ["2.33~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.33","QUARANTINE_PRE_RENAME","reconcileRestart","F3"],
  ["2.33~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.33","QUARANTINE_PRE_RENAME","reconcileRestart","F3"],
  ["2.33~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.33","QUARANTINE_PRE_RENAME","reconcileRestart","F3"],
  ["2.33~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.33","QUARANTINE_PRE_RENAME","reconcileRestart","F3"],
  ["2.33~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.33","QUARANTINE_PRE_RENAME","reconcileRestart","F3"],
  ["2.33~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.33","QUARANTINE_PRE_RENAME","reconcileRestart","F3"],
  ["2.34~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.34","QUARANTINE_RENAME","reconcileRestart","F3"],
  ["2.34~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.34","QUARANTINE_RENAME","reconcileRestart","F3"],
  ["2.34~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.34","QUARANTINE_RENAME","reconcileRestart","F3"],
  ["2.34~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.34","QUARANTINE_RENAME","reconcileRestart","F3"],
  ["2.34~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.34","QUARANTINE_RENAME","reconcileRestart","F3"],
  ["2.34~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.34","QUARANTINE_RENAME","reconcileRestart","F3"],
  ["2.34~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.34","QUARANTINE_RENAME","reconcileRestart","F3"],
  ["2.35~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.35","QUARANTINE_DEST_DIR_OPEN","reconcileRestart","F4"],
  ["2.35~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.35","QUARANTINE_DEST_DIR_OPEN","reconcileRestart","F4"],
  ["2.35~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.35","QUARANTINE_DEST_DIR_OPEN","reconcileRestart","F4"],
  ["2.35~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.35","QUARANTINE_DEST_DIR_OPEN","reconcileRestart","F4"],
  ["2.35~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.35","QUARANTINE_DEST_DIR_OPEN","reconcileRestart","F4"],
  ["2.35~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.35","QUARANTINE_DEST_DIR_OPEN","reconcileRestart","F4"],
  ["2.35~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.35","QUARANTINE_DEST_DIR_OPEN","reconcileRestart","F4"],
  ["2.36~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.36","QUARANTINE_DEST_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.36~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.36","QUARANTINE_DEST_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.36~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.36","QUARANTINE_DEST_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.36~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.36","QUARANTINE_DEST_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.36~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.36","QUARANTINE_DEST_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.36~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.36","QUARANTINE_DEST_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.36~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.36","QUARANTINE_DEST_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.37~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.37","QUARANTINE_DEST_DIR_FSYNC","reconcileRestart","F4"],
  ["2.37~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.37","QUARANTINE_DEST_DIR_FSYNC","reconcileRestart","F4"],
  ["2.37~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.37","QUARANTINE_DEST_DIR_FSYNC","reconcileRestart","F4"],
  ["2.37~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.37","QUARANTINE_DEST_DIR_FSYNC","reconcileRestart","F4"],
  ["2.37~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.37","QUARANTINE_DEST_DIR_FSYNC","reconcileRestart","F4"],
  ["2.37~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.37","QUARANTINE_DEST_DIR_FSYNC","reconcileRestart","F4"],
  ["2.37~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.37","QUARANTINE_DEST_DIR_FSYNC","reconcileRestart","F4"],
  ["2.38~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.38","QUARANTINE_DEST_DIR_CLOSE","reconcileRestart","F4"],
  ["2.38~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.38","QUARANTINE_DEST_DIR_CLOSE","reconcileRestart","F4"],
  ["2.38~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.38","QUARANTINE_DEST_DIR_CLOSE","reconcileRestart","F4"],
  ["2.38~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.38","QUARANTINE_DEST_DIR_CLOSE","reconcileRestart","F4"],
  ["2.38~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.38","QUARANTINE_DEST_DIR_CLOSE","reconcileRestart","F4"],
  ["2.38~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.38","QUARANTINE_DEST_DIR_CLOSE","reconcileRestart","F4"],
  ["2.38~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.38","QUARANTINE_DEST_DIR_CLOSE","reconcileRestart","F4"],
  ["2.39~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.39","QUARANTINE_SOURCE_DIR_OPEN","reconcileRestart","F4"],
  ["2.39~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.39","QUARANTINE_SOURCE_DIR_OPEN","reconcileRestart","F4"],
  ["2.39~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.39","QUARANTINE_SOURCE_DIR_OPEN","reconcileRestart","F4"],
  ["2.39~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.39","QUARANTINE_SOURCE_DIR_OPEN","reconcileRestart","F4"],
  ["2.39~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.39","QUARANTINE_SOURCE_DIR_OPEN","reconcileRestart","F4"],
  ["2.39~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.39","QUARANTINE_SOURCE_DIR_OPEN","reconcileRestart","F4"],
  ["2.39~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.39","QUARANTINE_SOURCE_DIR_OPEN","reconcileRestart","F4"],
  ["2.40~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.40","QUARANTINE_SOURCE_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.40~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.40","QUARANTINE_SOURCE_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.40~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.40","QUARANTINE_SOURCE_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.40~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.40","QUARANTINE_SOURCE_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.40~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.40","QUARANTINE_SOURCE_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.40~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.40","QUARANTINE_SOURCE_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.40~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.40","QUARANTINE_SOURCE_DIR_VALIDATE","reconcileRestart","F4"],
  ["2.41~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.41","QUARANTINE_SOURCE_DIR_FSYNC","reconcileRestart","F4"],
  ["2.41~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.41","QUARANTINE_SOURCE_DIR_FSYNC","reconcileRestart","F4"],
  ["2.41~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.41","QUARANTINE_SOURCE_DIR_FSYNC","reconcileRestart","F4"],
  ["2.41~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.41","QUARANTINE_SOURCE_DIR_FSYNC","reconcileRestart","F4"],
  ["2.41~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.41","QUARANTINE_SOURCE_DIR_FSYNC","reconcileRestart","F4"],
  ["2.41~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.41","QUARANTINE_SOURCE_DIR_FSYNC","reconcileRestart","F4"],
  ["2.41~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.41","QUARANTINE_SOURCE_DIR_FSYNC","reconcileRestart","F4"],
  ["2.42~HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","HOST_JOURNAL_EMPTY","n/a — internal classification, not an externally thrown fail-site phase","2.42","QUARANTINE_SOURCE_DIR_CLOSE","reconcileRestart","F4"],
  ["2.42~HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_FILE_OVERSIZED","n/a — internal classification, not an externally thrown fail-site phase","2.42","QUARANTINE_SOURCE_DIR_CLOSE","reconcileRestart","F4"],
  ["2.42~HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILENAME_ID_MISMATCH","n/a — internal classification, not an externally thrown fail-site phase","2.42","QUARANTINE_SOURCE_DIR_CLOSE","reconcileRestart","F4"],
  ["2.42~HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_JSON_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.42","QUARANTINE_SOURCE_DIR_CLOSE","reconcileRestart","F4"],
  ["2.42~HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_NONCANONICAL","n/a — internal classification, not an externally thrown fail-site phase","2.42","QUARANTINE_SOURCE_DIR_CLOSE","reconcileRestart","F4"],
  ["2.42~HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_STORED_RECORD_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.42","QUARANTINE_SOURCE_DIR_CLOSE","reconcileRestart","F4"],
  ["2.42~HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","HOST_JOURNAL_UTF8_INVALID","n/a — internal classification, not an externally thrown fail-site phase","2.42","QUARANTINE_SOURCE_DIR_CLOSE","reconcileRestart","F4"],
  ["2.48~2.46","2.46","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","2.48","TEMP_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.48~2.47","2.47","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","2.48","TEMP_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.51~2.50","2.50","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","2.51","TEMP_VERIFY_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.60~2.58","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_VALIDATE","2.60","PARENT_DIR_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.60~2.59","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_FSYNC","2.60","PARENT_DIR_CLOSE","reconcileRestart","DESCRIPTOR_CLOSE"],
  ["2.61~2.46","2.46","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.47","2.47","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.48","2.48","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.49","2.49","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.50","2.50","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.51","2.51","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.52","2.52","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.53","2.53","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.54","2.54","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.55","2.55","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.61~2.56","2.56","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","2.61","TEMP_CLEANUP_UNLINK","reconcileRestart","F1"],
  ["2.62~2.46","2.46","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.47","2.47","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.48","2.48","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.49","2.49","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.50","2.50","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.51","2.51","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.52","2.52","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.53","2.53","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.54","2.54","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.55","2.55","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.62~2.56","2.56","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","2.62","TEMP_CLEANUP_DIR_OPEN","reconcileRestart","F1"],
  ["2.63~2.46","2.46","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.47","2.47","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.48","2.48","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.49","2.49","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.50","2.50","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.51","2.51","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.52","2.52","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.53","2.53","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.54","2.54","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.55","2.55","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.63~2.56","2.56","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","2.63","TEMP_CLEANUP_DIR_VALIDATE","reconcileRestart","F1"],
  ["2.64~2.46","2.46","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.47","2.47","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.48","2.48","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.49","2.49","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.50","2.50","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.51","2.51","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.52","2.52","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.53","2.53","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.54","2.54","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.55","2.55","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.64~2.56","2.56","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","2.64","TEMP_CLEANUP_DIR_FSYNC","reconcileRestart","F1"],
  ["2.65~2.46","2.46","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.47","2.47","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.48","2.48","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.49","2.49","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.50","2.50","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.51","2.51","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.52","2.52","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.53","2.53","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.54","2.54","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.55","2.55","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["2.65~2.56","2.56","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","2.65","TEMP_CLEANUP_DIR_CLOSE","reconcileRestart","F1"],
  ["3.09~3.07","3.07","HOST_FILESYSTEM_READ_FAILED","ENUMERATION_READ","3.09","ENUMERATION_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.09~3.08","3.08","HOST_STAGING_SCAN_OVERFLOW","ENUMERATION_READ","3.09","ENUMERATION_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.18~3.16","3.16","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","3.18","TEMP_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.18~3.17","3.17","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","3.18","TEMP_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.21~3.20","3.20","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","3.21","TEMP_VERIFY_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.25~3.23","3.23","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_READ","3.25","CAS_CREATE_SCAN_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.25~3.24","3.24","HOST_STAGING_SCAN_OVERFLOW","CAS_CREATE_SCAN_READ","3.25","CAS_CREATE_SCAN_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.33~3.31","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_VALIDATE","3.33","PARENT_DIR_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.33~3.32","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_FSYNC","3.33","PARENT_DIR_CLOSE","createJournal","DESCRIPTOR_CLOSE"],
  ["3.34~3.16","3.16","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.17","3.17","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.18","3.18","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.19","3.19","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.20","3.20","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.21","3.21","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.22","3.22","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_OPEN","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.23","3.23","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_READ","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.24","3.24","HOST_STAGING_SCAN_OVERFLOW","CAS_CREATE_SCAN_READ","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.25","3.25","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","CAS_CREATE_SCAN_CLOSE","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.26","3.26","HOST_DISK_STATE_CHANGED","CAS_CREATE_SCAN_MATCH","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.27","3.27","HOST_DISK_STATE_CHANGED","CAS_CREATE_ABSENCE","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.28","3.28","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_ABSENCE","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.34~3.29","3.29","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","3.34","TEMP_CLEANUP_UNLINK","createJournal","F1"],
  ["3.35~3.16","3.16","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.17","3.17","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.18","3.18","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.19","3.19","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.20","3.20","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.21","3.21","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.22","3.22","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_OPEN","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.23","3.23","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_READ","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.24","3.24","HOST_STAGING_SCAN_OVERFLOW","CAS_CREATE_SCAN_READ","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.25","3.25","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","CAS_CREATE_SCAN_CLOSE","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.26","3.26","HOST_DISK_STATE_CHANGED","CAS_CREATE_SCAN_MATCH","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.27","3.27","HOST_DISK_STATE_CHANGED","CAS_CREATE_ABSENCE","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.28","3.28","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_ABSENCE","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.35~3.29","3.29","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","3.35","TEMP_CLEANUP_DIR_OPEN","createJournal","F1"],
  ["3.36~3.16","3.16","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.17","3.17","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.18","3.18","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.19","3.19","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.20","3.20","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.21","3.21","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.22","3.22","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_OPEN","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.23","3.23","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_READ","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.24","3.24","HOST_STAGING_SCAN_OVERFLOW","CAS_CREATE_SCAN_READ","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.25","3.25","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","CAS_CREATE_SCAN_CLOSE","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.26","3.26","HOST_DISK_STATE_CHANGED","CAS_CREATE_SCAN_MATCH","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.27","3.27","HOST_DISK_STATE_CHANGED","CAS_CREATE_ABSENCE","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.28","3.28","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_ABSENCE","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.36~3.29","3.29","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","3.36","TEMP_CLEANUP_DIR_VALIDATE","createJournal","F1"],
  ["3.37~3.16","3.16","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.17","3.17","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.18","3.18","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.19","3.19","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.20","3.20","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.21","3.21","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.22","3.22","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_OPEN","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.23","3.23","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_READ","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.24","3.24","HOST_STAGING_SCAN_OVERFLOW","CAS_CREATE_SCAN_READ","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.25","3.25","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","CAS_CREATE_SCAN_CLOSE","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.26","3.26","HOST_DISK_STATE_CHANGED","CAS_CREATE_SCAN_MATCH","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.27","3.27","HOST_DISK_STATE_CHANGED","CAS_CREATE_ABSENCE","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.28","3.28","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_ABSENCE","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.37~3.29","3.29","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","3.37","TEMP_CLEANUP_DIR_FSYNC","createJournal","F1"],
  ["3.38~3.16","3.16","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.17","3.17","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.18","3.18","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.19","3.19","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.20","3.20","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.21","3.21","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.22","3.22","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_OPEN","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.23","3.23","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_SCAN_READ","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.24","3.24","HOST_STAGING_SCAN_OVERFLOW","CAS_CREATE_SCAN_READ","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.25","3.25","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","CAS_CREATE_SCAN_CLOSE","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.26","3.26","HOST_DISK_STATE_CHANGED","CAS_CREATE_SCAN_MATCH","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.27","3.27","HOST_DISK_STATE_CHANGED","CAS_CREATE_ABSENCE","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.28","3.28","HOST_FILESYSTEM_READ_FAILED","CAS_CREATE_ABSENCE","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["3.38~3.29","3.29","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","3.38","TEMP_CLEANUP_DIR_CLOSE","createJournal","F1"],
  ["4.16~4.11","4.11","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_CLASSIFY","4.16","CAS_INITIAL_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.16~4.12","4.12","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_READ","4.16","CAS_INITIAL_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.16~4.13","4.13","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_RECHECK","4.16","CAS_INITIAL_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.16~4.14","4.14","HOST_DISK_STATE_CHANGED","CAS_INITIAL_CHECKSUM_COMPARE","4.16","CAS_INITIAL_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.16~4.15","4.15","HOST_DISK_STATE_CHANGED","CAS_INITIAL_IDENTITY_COMPARE","4.16","CAS_INITIAL_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.22~4.20","4.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","4.22","TEMP_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.22~4.21","4.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","4.22","TEMP_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.25~4.24","4.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","4.25","TEMP_VERIFY_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.34~4.32","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_VALIDATE","4.34","PARENT_DIR_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.34~4.33","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_FSYNC","4.34","PARENT_DIR_CLOSE","stageRole","DESCRIPTOR_CLOSE"],
  ["4.35~4.20","4.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.21","4.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.22","4.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.23","4.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.24","4.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.25","4.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.26","4.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.27","4.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.28","4.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.29","4.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.35~4.30","4.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","4.35","TEMP_CLEANUP_UNLINK","stageRole","F1"],
  ["4.36~4.20","4.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.21","4.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.22","4.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.23","4.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.24","4.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.25","4.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.26","4.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.27","4.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.28","4.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.29","4.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.36~4.30","4.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","4.36","TEMP_CLEANUP_DIR_OPEN","stageRole","F1"],
  ["4.37~4.20","4.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.21","4.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.22","4.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.23","4.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.24","4.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.25","4.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.26","4.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.27","4.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.28","4.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.29","4.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.37~4.30","4.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","4.37","TEMP_CLEANUP_DIR_VALIDATE","stageRole","F1"],
  ["4.38~4.20","4.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.21","4.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.22","4.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.23","4.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.24","4.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.25","4.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.26","4.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.27","4.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.28","4.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.29","4.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.38~4.30","4.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","4.38","TEMP_CLEANUP_DIR_FSYNC","stageRole","F1"],
  ["4.39~4.20","4.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.21","4.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.22","4.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.23","4.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.24","4.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.25","4.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.26","4.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.27","4.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.28","4.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.29","4.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["4.39~4.30","4.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","4.39","TEMP_CLEANUP_DIR_CLOSE","stageRole","F1"],
  ["5.16~5.11","5.11","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_CLASSIFY","5.16","CAS_INITIAL_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.16~5.12","5.12","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_READ","5.16","CAS_INITIAL_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.16~5.13","5.13","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_RECHECK","5.16","CAS_INITIAL_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.16~5.14","5.14","HOST_DISK_STATE_CHANGED","CAS_INITIAL_CHECKSUM_COMPARE","5.16","CAS_INITIAL_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.16~5.15","5.15","HOST_DISK_STATE_CHANGED","CAS_INITIAL_IDENTITY_COMPARE","5.16","CAS_INITIAL_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.22~5.20","5.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","5.22","TEMP_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.22~5.21","5.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","5.22","TEMP_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.25~5.24","5.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","5.25","TEMP_VERIFY_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.34~5.32","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_VALIDATE","5.34","PARENT_DIR_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.34~5.33","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_INDETERMINATE","PARENT_DIR_FSYNC","5.34","PARENT_DIR_CLOSE","cancel","DESCRIPTOR_CLOSE"],
  ["5.35~5.20","5.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.21","5.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.22","5.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.23","5.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.24","5.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.25","5.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.26","5.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.27","5.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.28","5.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.29","5.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.35~5.30","5.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","5.35","TEMP_CLEANUP_UNLINK","cancel","F1"],
  ["5.36~5.20","5.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.21","5.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.22","5.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.23","5.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.24","5.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.25","5.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.26","5.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.27","5.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.28","5.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.29","5.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.36~5.30","5.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","5.36","TEMP_CLEANUP_DIR_OPEN","cancel","F1"],
  ["5.37~5.20","5.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.21","5.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.22","5.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.23","5.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.24","5.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.25","5.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.26","5.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.27","5.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.28","5.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.29","5.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.37~5.30","5.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","5.37","TEMP_CLEANUP_DIR_VALIDATE","cancel","F1"],
  ["5.38~5.20","5.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.21","5.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.22","5.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.23","5.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.24","5.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.25","5.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.26","5.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.27","5.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.28","5.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.29","5.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.38~5.30","5.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","5.38","TEMP_CLEANUP_DIR_FSYNC","cancel","F1"],
  ["5.39~5.20","5.20","HOST_FILESYSTEM_MUTATION_FAILED","TEMP_WRITE","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.21","5.21","HOST_DURABILITY_WRITE_FAILED","TEMP_FSYNC","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.22","5.22","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_CLOSE","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.23","5.23","HOST_FILESYSTEM_READ_FAILED","TEMP_VERIFY_OPEN","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.24","5.24","HOST_JOURNAL_DESCRIPTOR_INVALID","TEMP_VERIFY_CLASSIFY","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.25","5.25","HOST_DESCRIPTOR_CLOSE_FAILED","TEMP_VERIFY_CLOSE","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.26","5.26","HOST_DISK_STATE_CHANGED","CAS_FINAL_PROBE","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.27","5.27","HOST_FILESYSTEM_READ_FAILED","CAS_FINAL_PROBE","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.28","5.28","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_FINAL_CLASSIFY","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.29","5.29","HOST_DISK_STATE_CHANGED","CAS_FINAL_IDENTITY_COMPARE","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["5.39~5.30","5.30","HOST_FILESYSTEM_MUTATION_FAILED","RENAME","5.39","TEMP_CLEANUP_DIR_CLOSE","cancel","F1"],
  ["7.22~7.17","7.17","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_CLASSIFY","7.22","CAS_INITIAL_CLOSE","acknowledgeTerminal","DESCRIPTOR_CLOSE"],
  ["7.22~7.18","7.18","HOST_FILESYSTEM_READ_FAILED","CAS_INITIAL_READ","7.22","CAS_INITIAL_CLOSE","acknowledgeTerminal","DESCRIPTOR_CLOSE"],
  ["7.22~7.19","7.19","HOST_JOURNAL_DESCRIPTOR_INVALID","CAS_INITIAL_RECHECK","7.22","CAS_INITIAL_CLOSE","acknowledgeTerminal","DESCRIPTOR_CLOSE"],
  ["7.22~7.20","7.20","HOST_DISK_STATE_CHANGED","CAS_INITIAL_CHECKSUM_COMPARE","7.22","CAS_INITIAL_CLOSE","acknowledgeTerminal","DESCRIPTOR_CLOSE"],
  ["7.22~7.21","7.21","HOST_DISK_STATE_CHANGED","CAS_INITIAL_IDENTITY_COMPARE","7.22","CAS_INITIAL_CLOSE","acknowledgeTerminal","DESCRIPTOR_CLOSE"],
  ["7.31~7.29","HOST_JOURNAL_REMOVAL_INDETERMINATE","HOST_JOURNAL_REMOVAL_INDETERMINATE","UNLINK_DIR_VALIDATE","7.31","UNLINK_DIR_CLOSE","acknowledgeTerminal","DESCRIPTOR_CLOSE"],
  ["7.31~7.30","HOST_JOURNAL_REMOVAL_INDETERMINATE","HOST_JOURNAL_REMOVAL_INDETERMINATE","UNLINK_DIR_FSYNC","7.31","UNLINK_DIR_CLOSE","acknowledgeTerminal","DESCRIPTOR_CLOSE"],
  ["8.08~8.06","HOST_LOCK_RELEASE_INDETERMINATE","HOST_LOCK_RELEASE_INDETERMINATE","LOCK_RELEASE_DIR_VALIDATE","8.08","LOCK_RELEASE_DIR_CLOSE","close","DESCRIPTOR_CLOSE"],
  ["8.08~8.07","HOST_LOCK_RELEASE_INDETERMINATE","HOST_LOCK_RELEASE_INDETERMINATE","LOCK_RELEASE_DIR_FSYNC","8.08","LOCK_RELEASE_DIR_CLOSE","close","DESCRIPTOR_CLOSE"]
];

const EXTERNAL_CODES = ["HOST_ACKNOWLEDGMENT_CHECKSUM_MISMATCH","HOST_ACKNOWLEDGMENT_ENUMERATION_FAILED","HOST_ACKNOWLEDGMENT_IDENTITY_MISMATCH","HOST_ACKNOWLEDGMENT_INPUT_EXTRA_KEY","HOST_ACKNOWLEDGMENT_INPUT_INVALID","HOST_ACKNOWLEDGMENT_INPUT_MISSING_KEY","HOST_ACKNOWLEDGMENT_INPUT_NOT_OBJECT","HOST_ACKNOWLEDGMENT_PRECONDITION_FAILED","HOST_ACKNOWLEDGMENT_READ_FAILED","HOST_CLEANUP_DESCRIPTOR_LEAKED","HOST_CLOCK_REGRESSION_DETECTED","HOST_CLOSED","HOST_CORRUPT_QUARANTINE_BOUND_EXCEEDED","HOST_CORRUPT_QUARANTINE_FAILED","HOST_CORRUPT_QUARANTINE_INDETERMINATE","HOST_DEPENDENCIES_NOT_OBJECT","HOST_DEPENDENCY_ENUMERATION_FAILED","HOST_DEPENDENCY_EXTRA","HOST_DEPENDENCY_INVALID","HOST_DEPENDENCY_MISSING","HOST_DEPENDENCY_READ_FAILED","HOST_DESCRIPTOR_CLOSE_FAILED","HOST_DISK_STATE_CHANGED","HOST_DURABILITY_INDETERMINATE","HOST_DURABILITY_WRITE_FAILED","HOST_ENUMERATION_HANDLE_CLOSE_FAILED","HOST_FILESYSTEM_MUTATION_FAILED","HOST_FILESYSTEM_READ_FAILED","HOST_INVALID_NOW","HOST_JOURNAL_ALREADY_EXISTS","HOST_JOURNAL_DESCRIPTOR_INVALID","HOST_JOURNAL_NOT_ACTIVE","HOST_JOURNAL_NOT_FOUND","HOST_JOURNAL_REMOVAL_INDETERMINATE","HOST_LOCK_ACQUISITION_FAILED","HOST_LOCK_ACQUISITION_INDETERMINATE","HOST_LOCK_DESCRIPTOR_INVALID","HOST_LOCK_FILE_MALFORMED","HOST_LOCK_FILE_OVERSIZED","HOST_LOCK_HELD","HOST_LOCK_HELD_OR_AMBIGUOUS","HOST_LOCK_LIVENESS_RESULT_INVALID","HOST_LOCK_LOST_OR_REPLACED","HOST_LOCK_RELEASE_INDETERMINATE","HOST_MULTIPLE_JOURNALS_FOUND","HOST_PLATFORM_UNSUPPORTED","HOST_PROCESS_POISONED","HOST_QUARANTINE_SCAN_OVERFLOW","HOST_RECONCILIATION_REQUIRED","HOST_SERIALIZATION_REJECTED","HOST_STAGING_SCAN_OVERFLOW","HOST_STALE_LOCK_QUARANTINE_BOUND_EXCEEDED","HOST_STALE_LOCK_QUARANTINE_FAILED","HOST_STALE_LOCK_QUARANTINE_INDETERMINATE","HOST_STORAGE_DIRECTORY_CREATE_FAILED","HOST_STORAGE_DIRECTORY_INVALID","HOST_STORAGE_DIRECTORY_MODE_INVALID","HOST_STORAGE_DIRECTORY_OWNER_INVALID","HOST_STORAGE_ROOT_INVALID","HOST_STORAGE_ROOT_NOT_FOUND","HOST_STORAGE_ROOT_UNSAFE","HOST_TEMP_FILE_BOUND_EXCEEDED","HOST_TEMP_REMOVAL_INDETERMINATE","HOST_UNEXPECTED_STAGING_ENTRY"];
const INTERNAL_CODES = ["HOST_JOURNAL_EMPTY","HOST_JOURNAL_FILENAME_ID_MISMATCH","HOST_JOURNAL_FILE_OVERSIZED","HOST_JOURNAL_JSON_INVALID","HOST_JOURNAL_NONCANONICAL","HOST_JOURNAL_STORED_RECORD_INVALID","HOST_JOURNAL_UTF8_INVALID"];
const EXTERNAL_PHASES = ["ACK_IDENTITY_MATCH","ACK_INPUT_VALIDATION","ACK_PRECONDITION","ACK_PRECONDITION_NON_TERMINAL","CAS_CREATE_ABSENCE","CAS_CREATE_SCAN_CLOSE","CAS_CREATE_SCAN_MATCH","CAS_CREATE_SCAN_OPEN","CAS_CREATE_SCAN_READ","CAS_FINAL_CLASSIFY","CAS_FINAL_IDENTITY_COMPARE","CAS_FINAL_PROBE","CAS_INITIAL_CHECKSUM_COMPARE","CAS_INITIAL_CLASSIFY","CAS_INITIAL_CLOSE","CAS_INITIAL_IDENTITY_COMPARE","CAS_INITIAL_OPEN","CAS_INITIAL_READ","CAS_INITIAL_RECHECK","CLOCK_SAMPLE","CLOCK_TRACKING","DEPENDENCY_VALIDATION","DIRECTORY_CLOSE","DIRECTORY_CREATE","DIRECTORY_FSYNC","DIRECTORY_OPEN","DIRECTORY_VALIDATE","ENTRY_CLASSIFY","ENUMERATION_CLOSE","ENUMERATION_OPEN","ENUMERATION_READ","JOURNAL_CLASSIFY","JOURNAL_CLOSE","JOURNAL_METADATA_RECHECK","JOURNAL_OPEN","JOURNAL_PRECONDITION","JOURNAL_PRECONDITION_DISK_SCAN","JOURNAL_READ","LIFECYCLE_GUARD","LOCK_CLEANUP_DIR_CLOSE","LOCK_CLEANUP_DIR_FSYNC","LOCK_CLEANUP_DIR_OPEN","LOCK_CLEANUP_DIR_VALIDATE","LOCK_CLEANUP_PROBE","LOCK_CLEANUP_UNLINK","LOCK_CREATE","LOCK_DIR_CLOSE","LOCK_DIR_FSYNC","LOCK_DIR_OPEN","LOCK_DIR_VALIDATE","LOCK_IDENTITY","LOCK_LIVENESS","LOCK_PAYLOAD_CLOSE","LOCK_PAYLOAD_FSYNC","LOCK_PAYLOAD_WRITE","LOCK_POST_CREATE_VALIDATE","LOCK_PROBE_CLASSIFY","LOCK_PROBE_CLOSE","LOCK_PROBE_OPEN","LOCK_PROBE_PARSE","LOCK_PROBE_READ","LOCK_PROBE_RECHECK","LOCK_RELEASE_DIR_CLOSE","LOCK_RELEASE_DIR_FSYNC","LOCK_RELEASE_DIR_OPEN","LOCK_RELEASE_DIR_VALIDATE","LOCK_RELEASE_PROBE","LOCK_RELEASE_UNLINK","LOCK_STALENESS_WINDOW","MODULE_POISON_CHECK","PARENT_DIR_CLOSE","PARENT_DIR_FSYNC","PARENT_DIR_OPEN","PARENT_DIR_VALIDATE","PLATFORM_VALIDATION","QUARANTINE_BOUND","QUARANTINE_DEST_DIR_CLOSE","QUARANTINE_DEST_DIR_FSYNC","QUARANTINE_DEST_DIR_OPEN","QUARANTINE_DEST_DIR_VALIDATE","QUARANTINE_PRE_RENAME","QUARANTINE_PROBE","QUARANTINE_RENAME","QUARANTINE_SOURCE_DIR_CLOSE","QUARANTINE_SOURCE_DIR_FSYNC","QUARANTINE_SOURCE_DIR_OPEN","QUARANTINE_SOURCE_DIR_VALIDATE","RENAME","ROOT_VALIDATION","SERIALIZE","TEMP_CLEANUP_DIR_CLOSE","TEMP_CLEANUP_DIR_FSYNC","TEMP_CLEANUP_DIR_OPEN","TEMP_CLEANUP_DIR_VALIDATE","TEMP_CLEANUP_UNLINK","TEMP_CLOSE","TEMP_FSYNC","TEMP_OPEN","TEMP_VERIFY_CLASSIFY","TEMP_VERIFY_CLOSE","TEMP_VERIFY_OPEN","TEMP_WRITE","UNLINK","UNLINK_DIR_CLOSE","UNLINK_DIR_FSYNC","UNLINK_DIR_OPEN","UNLINK_DIR_VALIDATE"];
const INTERNAL_PHASES = ["JOURNAL_CANONICAL_COMPARE","JOURNAL_DECODE","JOURNAL_FILENAME_CHECK","JOURNAL_PARSE","JOURNAL_SIZE_PREFLIGHT","JOURNAL_STORED_VALIDATE"];

const CHAIN_SUBTOTALS = { 1: 61, 2: 65, 3: 38, 4: 39, 5: 39, 6: 4, 7: 31, 8: 8 };
const COMPOUND_FAMILIES = { F1: 235, F2: 49, F3: 28, F4: 56, DESCRIPTOR_CLOSE: 73 };

// Accepted state-machine reconciliation (Part 3A, as corrected).
const SM_TRANSITIONS = {
  SM1: 57, SM2: 48, SM3: 111, SM4: 30, SM5: 10, SM6: 12,
  SM7: 26, SM8: 19, SM9: 19, SM10: 35, SM11: 40, SM12: 142
};
const SM12_SUBTOTAL = 142;
const SM12_FLOWS = { create: 35, stage: 40, cancel: 39, reconciliation: 28 };
const GLOBAL_TRANSITIONS = 549;

const PRIMARY_CODE_ALLOWLIST = [
  "HOST_TEMP_REMOVAL_INDETERMINATE",
  "HOST_CORRUPT_QUARANTINE_FAILED",
  "HOST_CORRUPT_QUARANTINE_INDETERMINATE",
  "HOST_LOCK_ACQUISITION_INDETERMINATE",
  "HOST_CLEANUP_DESCRIPTOR_LEAKED"
];
const DETAIL_KEYS = ["commitState", "operation", "phase", "primaryCode", "subject"];
const PUBLIC_METHODS = [
  "reconcileRestart", "createJournal", "stageRole", "cancel",
  "finalizeProfile", "status", "acknowledgeTerminal", "close",
  "beginCredentialObligation", "authorizeCredentialCreation",
  "recordCreatedCredential", "cancelCredentialObligation"
];

const HOST_CREDENTIAL_OBLIGATION_CODES = [
  "HOST_CREDENTIAL_OBLIGATION_ALREADY_EXISTS",
  "HOST_CREDENTIAL_OBLIGATION_NOT_FOUND",
  "HOST_CREDENTIAL_OBLIGATION_INVALID",
  "HOST_CREDENTIAL_OBLIGATION_OVERSIZED",
  "HOST_CREDENTIAL_OBLIGATION_STATE_INVALID",
  "HOST_CREDENTIAL_OBLIGATION_CONTEXT_MISMATCH",
  "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH",
  "HOST_CREDENTIAL_OBLIGATION_CREDENTIAL_MISMATCH",
  "HOST_CREDENTIAL_OBLIGATION_ORPHANED",
  "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED",
  "HOST_CREDENTIAL_OBLIGATION_DURABILITY_INDETERMINATE",
  "HOST_CREDENTIAL_OBLIGATION_RETIREMENT_FAILED",
  "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE",
  "HOST_CREDENTIAL_OBLIGATION_TEMP_BOUND_EXCEEDED",
  "HOST_CREDENTIAL_OBLIGATION_UNEXPECTED_ENTRY"
];

const HOST_FINALIZED_PROFILE_CODES = [
  "HOST_FINALIZED_PROFILE_ALREADY_EXISTS",
  "HOST_FINALIZED_PROFILE_CONFLICT",
  "HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID",
  "HOST_FINALIZED_PROFILE_DURABILITY_INDETERMINATE",
  "HOST_FINALIZED_PROFILE_EMPTY",
  "HOST_FINALIZED_PROFILE_FILE_OVERSIZED",
  "HOST_FINALIZED_PROFILE_FILENAME_ID_MISMATCH",
  "HOST_FINALIZED_PROFILE_INVALID_AFTER_SUPERSESSION",
  "HOST_FINALIZED_PROFILE_JSON_INVALID",
  "HOST_FINALIZED_PROFILE_MISSING_AFTER_SUPERSESSION",
  "HOST_FINALIZED_PROFILE_NONCANONICAL",
  "HOST_FINALIZED_PROFILE_SCAN_OVERFLOW",
  "HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID",
  "HOST_FINALIZED_PROFILE_SUPERSESSION_CLOCK_REGRESSION",
  "HOST_FINALIZED_PROFILE_TEMP_BOUND_EXCEEDED",
  "HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE",
  "HOST_FINALIZED_PROFILE_UTF8_INVALID",
  "HOST_UNEXPECTED_FINALIZED_PROFILE_ENTRY",
  "HOST_MULTIPLE_FINALIZED_PROFILES_FOUND"
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------
let passed = 0;
const failures = [];
function test(name, fn) {
  try { fn(); passed += 1; }
  catch (error) { failures.push({ name, error }); }
}

let tmpSeq = 0;
function freshRoot() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `philcore-5b05-${process.pid}-${tmpSeq++}-`));
  return dir;
}
function withRoot(fn) {
  const dir = freshRoot();
  try { return fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// ---------------------------------------------------------------------------
// Deterministic, scoped filesystem fault facade (decision D6)
// ---------------------------------------------------------------------------
const FS_CALLS = [
  "lstatSync", "openSync", "fstatSync", "readSync", "writeSync",
  "fsyncSync", "closeSync", "mkdirSync", "renameSync", "unlinkSync", "opendirSync"
];

function errno(code) {
  const error = new Error(`injected ${code}`);
  error.code = code;
  return error;
}

// Labels a real path against the derived storage layout.
function makeLabeller(root) {
  const shared = path.join(root, "philcore-recovery-enrollment");
  const staging = path.join(shared, "genesis-staging");
  const finalized = path.join(shared, "genesis-profiles");
  const map = new Map([
    [path.resolve(root), "root"],
    [shared, "shared"],
    [staging, "staging"],
    [finalized, "finalized"],
    [path.join(staging, ".corrupt-quarantine"), "corrupt"],
    [path.join(staging, ".stale-lock-quarantine"), "stale"],
    [path.join(staging, ".staging.lock"), "lock"]
  ]);
  return (p) => {
    if (typeof p !== "string") return null;
    const resolved = path.resolve(p);
    if (map.has(resolved)) return map.get(resolved);
    const base = path.basename(resolved);
    if (/^ceremony_[0-9a-f]{64}\.v1\.json$/u.test(base)) return "journal";
    if (/^\.ceremony_[0-9a-f]{64}\.v1\.json\.tmp$/u.test(base)) return "temp";
    if (base === "genesis-credential-obligation.v1.json") return "obligation";
    if (base === "genesis-credential-obligation.v1.json.tmp") return "otemp";
    if (/^profile_[0-9a-f]{64}\.v1\.json$/u.test(base)) return "fprofile";
    if (/^\.profile_[0-9a-f]{64}\.v1\.json\.tmp$/u.test(base)) return "ftemp";
    return null;
  };
}

// plan: { call, label, occurrence, behave } where behave(realResult, args) may
// throw or return a substitute value. Unconditionally restored in finally.
function withFacade(root, planOrPlans, body) {
  const real = {};
  for (const name of FS_CALLS) real[name] = fs[name];
  const labelOf = makeLabeller(root);
  const fdLabel = new Map();
  const counts = new Map();
  // An ordered plan list: each entry is matched independently, so a primary
  // antecedent fault and a secondary cleanup fault both execute genuinely.
  const plans = planOrPlans === null || planOrPlans === undefined
    ? []
    : (Array.isArray(planOrPlans) ? planOrPlans : [planOrPlans]);
  const plan = plans[0] || null;
  let armed = plan ? plan.armed !== false : false;

  let matched = null;
  const matches = (call, label) => {
    if (!armed) return false;
    for (let i = 0; i < plans.length; i += 1) {
      const candidate = plans[i];
      if (!candidate || candidate.call !== call) continue;
      if (candidate.label) {
        const base = typeof label === "string" ? label.split("#")[0] : label;
        const want = candidate.label;
        if (want.includes("#") ? label !== want : base !== want) continue;
      }
      const key = `${i}|${call}|${label}`;
      const n = (counts.get(key) || 0) + 1;
      counts.set(key, n);
      if (n === (candidate.occurrence || 1)) { matched = candidate; return true; }
    }
    return false;
  };

  const pathCalls = ["lstatSync", "openSync", "mkdirSync", "unlinkSync", "opendirSync", "renameSync"];
  for (const name of pathCalls) {
    fs[name] = function (...args) {
      const label = labelOf(args[0]);
      if (matches(name, label)) return matched.behave(null, args, { real, labelOf });
      const result = real[name].apply(fs, args);
      if (name === "openSync") fdLabel.set(result, label);
      if (name === "opendirSync") {
        const k = `opendir|${label}`;
        const nth = (counts.get(k) || 0) + 1;
        counts.set(k, nth);
        return wrapDir(result, label, nth);
      }
      if (armed && name === "lstatSync" && plan && plan.doctor === name && (!plan.label || plan.label === label)) {
        const key = `doctor|${name}|${label}`;
        const n = (counts.get(key) || 0) + 1;
        counts.set(key, n);
        if (plan.occurrence === "all" || n === (plan.occurrence || 1)) return plan.doctorFn(result);
      }
      return result;
    };
  }

  // Dir#readSync / Dir#closeSync are methods on the handle, not fs functions,
  // so the enumeration fail sites are reached by wrapping the handle itself.
  function wrapDir(handle, label, nth) {
    return {
      readSync() {
        if (matches("dirReadSync", `${label}#${nth}`)) return matched.behave(null, [], { real, labelOf });
        return handle.readSync();
      },
      closeSync() {
        if (matches("dirCloseSync", `${label}#${nth}`)) return matched.behave(null, [], { real, labelOf });
        return handle.closeSync();
      }
    };
  }

  const fdCalls = ["fstatSync", "readSync", "writeSync", "fsyncSync", "closeSync"];
  for (const name of fdCalls) {
    fs[name] = function (...args) {
      const label = fdLabel.get(args[0]) || null;
      if (matches(name, label)) return matched.behave(null, args, { real, labelOf });
      const result = real[name].apply(fs, args);
      // A doctored stat models a hostile or drifted object without an errno.
      if (armed && plan && plan.doctor === name && (!plan.label || plan.label === label)) {
        const key = `doctor|${name}|${label}`;
        const n = (counts.get(key) || 0) + 1;
        counts.set(key, n);
        if (plan.occurrence === "all" || n === (plan.occurrence || 1)) return plan.doctorFn(result);
      }
      return result;
    };
  }

  try {
    return body({
      arm() { armed = true; counts.clear(); },
      disarm() { armed = false; },
      labelOf
    });
  } finally {
    for (const name of FS_CALLS) fs[name] = real[name];
  }
}

// ---------------------------------------------------------------------------
// Phase -> syscall, subject -> label (the fault-plan basis)
// ---------------------------------------------------------------------------
const PHASE_CALL = {
  ROOT_VALIDATION: "lstatSync",
  DIRECTORY_CREATE: "mkdirSync",
  DIRECTORY_OPEN: "openSync",
  DIRECTORY_VALIDATE: "fstatSync",
  DIRECTORY_FSYNC: "fsyncSync",
  DIRECTORY_CLOSE: "closeSync",
  ENUMERATION_OPEN: "opendirSync",
  ENUMERATION_READ: "dirReadSync",
  ENUMERATION_CLOSE: "dirCloseSync",
  LOCK_PROBE_OPEN: "openSync",
  LOCK_PROBE_CLASSIFY: "fstatSync",
  LOCK_PROBE_READ: "readSync",
  LOCK_PROBE_RECHECK: "fstatSync",
  LOCK_PROBE_CLOSE: "closeSync",
  QUARANTINE_PROBE: "lstatSync",
  QUARANTINE_PRE_RENAME: "lstatSync",
  QUARANTINE_RENAME: "renameSync",
  QUARANTINE_DEST_DIR_OPEN: "openSync",
  QUARANTINE_DEST_DIR_VALIDATE: "fstatSync",
  QUARANTINE_DEST_DIR_FSYNC: "fsyncSync",
  QUARANTINE_DEST_DIR_CLOSE: "closeSync",
  QUARANTINE_SOURCE_DIR_OPEN: "openSync",
  QUARANTINE_SOURCE_DIR_VALIDATE: "fstatSync",
  QUARANTINE_SOURCE_DIR_FSYNC: "fsyncSync",
  QUARANTINE_SOURCE_DIR_CLOSE: "closeSync",
  LOCK_CREATE: "openSync",
  LOCK_POST_CREATE_VALIDATE: "fstatSync",
  LOCK_PAYLOAD_WRITE: "writeSync",
  LOCK_PAYLOAD_FSYNC: "fsyncSync",
  LOCK_PAYLOAD_CLOSE: "closeSync",
  LOCK_DIR_OPEN: "openSync",
  LOCK_DIR_VALIDATE: "fstatSync",
  LOCK_DIR_FSYNC: "fsyncSync",
  LOCK_DIR_CLOSE: "closeSync",
  LOCK_IDENTITY: "lstatSync",
  LOCK_CLEANUP_PROBE: "lstatSync",
  LOCK_CLEANUP_UNLINK: "unlinkSync",
  LOCK_CLEANUP_DIR_OPEN: "openSync",
  LOCK_CLEANUP_DIR_VALIDATE: "fstatSync",
  LOCK_CLEANUP_DIR_FSYNC: "fsyncSync",
  LOCK_CLEANUP_DIR_CLOSE: "closeSync",
  LOCK_RELEASE_PROBE: "lstatSync",
  LOCK_RELEASE_UNLINK: "unlinkSync",
  LOCK_RELEASE_DIR_OPEN: "openSync",
  LOCK_RELEASE_DIR_VALIDATE: "fstatSync",
  LOCK_RELEASE_DIR_FSYNC: "fsyncSync",
  LOCK_RELEASE_DIR_CLOSE: "closeSync",

  // Journal read (Chain 2)
  JOURNAL_OPEN: "openSync",
  JOURNAL_CLASSIFY: "fstatSync",
  JOURNAL_READ: "readSync",
  JOURNAL_METADATA_RECHECK: "fstatSync",
  JOURNAL_CLOSE: "closeSync",
  ENTRY_CLASSIFY: "lstatSync",
  UNLINK: "unlinkSync",
  UNLINK_DIR_OPEN: "openSync",
  UNLINK_DIR_VALIDATE: "fstatSync",
  UNLINK_DIR_FSYNC: "fsyncSync",
  UNLINK_DIR_CLOSE: "closeSync",

  // Initial CAS (Chains 4, 5, 7)
  CAS_INITIAL_OPEN: "openSync",
  CAS_INITIAL_CLASSIFY: "fstatSync",
  CAS_INITIAL_READ: "readSync",
  CAS_INITIAL_RECHECK: "fstatSync",
  CAS_INITIAL_IDENTITY_COMPARE: "fstatSync",
  CAS_INITIAL_CLOSE: "closeSync",

  // Owned-temp write path
  TEMP_OPEN: "openSync",
  TEMP_WRITE: "writeSync",
  TEMP_FSYNC: "fsyncSync",
  TEMP_CLOSE: "closeSync",
  TEMP_VERIFY_OPEN: "openSync",
  TEMP_VERIFY_CLASSIFY: "fstatSync",
  TEMP_VERIFY_CLOSE: "closeSync",

  // Create-path final CAS (Chain 3)
  CAS_CREATE_SCAN_OPEN: "opendirSync",
  CAS_CREATE_SCAN_READ: "dirReadSync",
  CAS_CREATE_SCAN_CLOSE: "dirCloseSync",
  CAS_CREATE_ABSENCE: "lstatSync",

  // Final CAS and publication
  CAS_FINAL_PROBE: "lstatSync",
  RENAME: "renameSync",
  PARENT_DIR_OPEN: "openSync",
  PARENT_DIR_VALIDATE: "fstatSync",
  PARENT_DIR_FSYNC: "fsyncSync",
  PARENT_DIR_CLOSE: "closeSync",

  // Owned-temp cleanup
  TEMP_CLEANUP_UNLINK: "unlinkSync",
  TEMP_CLEANUP_DIR_OPEN: "openSync",
  TEMP_CLEANUP_DIR_VALIDATE: "fstatSync",
  TEMP_CLEANUP_DIR_FSYNC: "fsyncSync",
  TEMP_CLEANUP_DIR_CLOSE: "closeSync"
};

// Where a phase is not the first occurrence of its (call, label) pair within
// the operation's deterministic sequence, the ordinal is pinned here.
const PHASE_LABEL = {
  CAS_CREATE_SCAN_READ: "staging#2",
  CAS_CREATE_SCAN_CLOSE: "staging#2"
};

const RENAME_LABEL_ROWS = new Set([
  "2.56", "3.29", "4.30", "5.30"
]);

const PHASE_OCCURRENCE = {
  JOURNAL_METADATA_RECHECK: 2,
  CAS_CREATE_SCAN_OPEN: 2,
  CAS_INITIAL_RECHECK: 2,
  CAS_INITIAL_IDENTITY_COMPARE: 3,
  TEMP_VERIFY_OPEN: 2,
  TEMP_VERIFY_CLOSE: 2,
  LOCK_PROBE_RECHECK: 2
};

const SUBJECT_LABEL = {
  SHARED_DIRECTORY: "shared",
  STAGING_DIRECTORY: "staging",
  CORRUPT_QUARANTINE_DIRECTORY: "corrupt",
  STALE_LOCK_QUARANTINE_DIRECTORY: "stale",
  LOCK_FILE: "lock",
  JOURNAL_FILE: "journal",
  TEMP_FILE: "temp"
};

// ---------------------------------------------------------------------------
// 1. Corpus integrity
// ---------------------------------------------------------------------------
test("single corpus holds exactly 285 rows", () => assert.equal(SINGLE_ROWS.length, 285));
test("single row IDs are unique", () => assert.equal(new Set(SINGLE_ROWS.map((r) => r[0])).size, 285));
test("single row IDs match the N.NN schema shape", () => {
  for (const row of SINGLE_ROWS) assert.match(row[0], /^[1-8]\.\d{2}$/u);
});
test("chain subtotals are exactly 61/65/38/39/39/4/31/8", () => {
  const counts = {};
  for (const row of SINGLE_ROWS) {
    const chain = row[0].split(".")[0];
    counts[chain] = (counts[chain] || 0) + 1;
  }
  assert.deepEqual(counts, CHAIN_SUBTOTALS);
});
test("each chain's row numbers are contiguous from 01 with no gap", () => {
  for (const [chain, total] of Object.entries(CHAIN_SUBTOTALS)) {
    const seen = SINGLE_ROWS.filter((r) => r[0].startsWith(chain + ".")).map((r) => Number(r[0].split(".")[1]));
    seen.sort((a, b) => a - b);
    assert.deepEqual(seen, Array.from({ length: total }, (_, i) => i + 1));
  }
});
test("precedence equals ordinal position within each chain", () => {
  for (const chain of Object.keys(CHAIN_SUBTOTALS)) {
    const rows = SINGLE_ROWS.filter((r) => r[0].startsWith(chain + ".")).sort((a, b) => a[0].localeCompare(b[0]));
    rows.forEach((row, index) => assert.equal(row[10], index + 1));
  }
});
test("each (operation, phase, code, subject) tuple is unique within its chain", () => {
  const seen = new Map();
  for (const row of SINGLE_ROWS) {
    const key = [row[0].split(".")[0], row[1], row[3], row[2], row[4]].join("|");
    assert.ok(!seen.has(key), `duplicate tuple ${key} at ${row[0]} and ${seen.get(key)}`);
    seen.set(key, row[0]);
  }
});
test("compound corpus holds exactly 441 rows", () => assert.equal(COMPOUND_ROWS.length, 441));
test("compound row IDs are unique", () => assert.equal(new Set(COMPOUND_ROWS.map((r) => r[0])).size, 441));
test("compound family partition is 235 + 49 + 28 + 56 + 73", () => {
  const counts = {};
  for (const row of COMPOUND_ROWS) counts[row[7]] = (counts[row[7]] || 0) + 1;
  assert.deepEqual(counts, COMPOUND_FAMILIES);
});
test("four-family subtotal is 368 and the grand total is 441", () => {
  const four = COMPOUND_FAMILIES.F1 + COMPOUND_FAMILIES.F2 + COMPOUND_FAMILIES.F3 + COMPOUND_FAMILIES.F4;
  assert.equal(four, 368);
  assert.equal(four + COMPOUND_FAMILIES.DESCRIPTOR_CLOSE, 441);
});
test("every compound consequent is a real single-failure row", () => {
  const ids = new Set(SINGLE_ROWS.map((r) => r[0]));
  for (const row of COMPOUND_ROWS) assert.ok(ids.has(row[0].split("~")[0]));
});
test("every numeric compound antecedent is a real single-failure row", () => {
  const ids = new Set(SINGLE_ROWS.map((r) => r[0]));
  for (const row of COMPOUND_ROWS) {
    const a = row[0].split("~")[1];
    if (/^[1-8]\.\d{2}$/u.test(a)) assert.ok(ids.has(a), `${row[0]} names unknown antecedent ${a}`);
  }
});
test("classification-antecedent compounds use exactly the 7 internal codes", () => {
  const used = new Set();
  for (const row of COMPOUND_ROWS) {
    const a = row[0].split("~")[1];
    if (!/^[1-8]\.\d{2}$/u.test(a)) used.add(a);
  }
  assert.deepEqual([...used].sort(), [...INTERNAL_CODES].sort());
});

// ---------------------------------------------------------------------------
// 2. Closed vocabularies
// ---------------------------------------------------------------------------
test("the corpus realizes exactly 64 external codes", () => {
  assert.deepEqual([...new Set(SINGLE_ROWS.map((r) => r[2]))].sort(), [...EXTERNAL_CODES].sort());
  assert.equal(EXTERNAL_CODES.length, 64);
});
test("there are exactly 7 internal classification codes", () => assert.equal(INTERNAL_CODES.length, 7));
test("external and internal code sets are disjoint, totalling 71", () => {
  for (const code of INTERNAL_CODES) assert.ok(!EXTERNAL_CODES.includes(code));
  assert.equal(EXTERNAL_CODES.length + INTERNAL_CODES.length, 71);
});
test("the 7 internal codes never appear as a top-level thrown code", () => {
  const thrown = new Set(SINGLE_ROWS.map((r) => r[2]));
  for (const code of INTERNAL_CODES) assert.ok(!thrown.has(code));
});
test("the corpus realizes exactly 107 external phases", () => {
  assert.equal(new Set(SINGLE_ROWS.map((r) => r[3])).size, 107);
});
test("there are exactly 6 classification-only phases, disjoint from the 107", () => {
  assert.equal(INTERNAL_PHASES.length, 6);
  const external = new Set(SINGLE_ROWS.map((r) => r[3]));
  for (const phase of INTERNAL_PHASES) assert.ok(!external.has(phase));
});
test("the combined phase vocabulary is exactly 113", () => {
  assert.equal(EXTERNAL_PHASES.length + INTERNAL_PHASES.length, 113);
});
test("only the 5 allowlisted codes carry a non-null primaryCode", () => {
  for (const row of SINGLE_ROWS) {
    if (row[9] && row[9] !== "null") assert.ok(PRIMARY_CODE_ALLOWLIST.includes(row[2]), `${row[0]}`);
  }
});
test("primaryCode never carries a phase literal", () => {
  const phases = new Set([...EXTERNAL_PHASES, ...INTERNAL_PHASES]);
  for (const row of SINGLE_ROWS) assert.ok(!phases.has(row[9]));
});

// ---------------------------------------------------------------------------
// 3. State-machine coverage reconciliation (SM12 = 142, total = 549)
// ---------------------------------------------------------------------------
test("SM12 is 35 create + 40 stage + 39 cancel + 28 reconciliation = 142", () => {
  const sum = SM12_FLOWS.create + SM12_FLOWS.stage + SM12_FLOWS.cancel + SM12_FLOWS.reconciliation;
  assert.equal(sum, SM12_SUBTOTAL);
  assert.equal(SM_TRANSITIONS.SM12, SM12_SUBTOTAL);
});
test("the non-SM12 transition subtotal is exactly 407", () => {
  const nonSm12 = Object.entries(SM_TRANSITIONS)
    .filter(([k]) => k !== "SM12")
    .reduce((acc, [, v]) => acc + v, 0);
  assert.equal(nonSm12, 407);
});
test("the global transition total is exactly 549", () => {
  const total = Object.values(SM_TRANSITIONS).reduce((a, b) => a + b, 0);
  assert.equal(total, GLOBAL_TRANSITIONS);
});

// ---------------------------------------------------------------------------
// 4. Module surface — observed, not self-reported
// ---------------------------------------------------------------------------
test("the module exports exactly 3 runtime values", () => {
  assert.deepEqual(Object.keys(hostModule).sort(), [
    "PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_HOST_ERROR_CODE",
    "PhilCoreV2ConsumerRecoveryGenesisStagingHostError",
    "createRecoveryGenesisStagingHost"
  ]);
});
test("the module exposes no fail-site or compound lookup API", () => {
  for (const forbidden of ["__failSite", "__compound", "__contract", "__rows", "__table"]) {
    assert.equal(hostModule[forbidden], undefined, `module exposes ${forbidden}`);
  }
});
test("the exported code object is frozen and holds all 105 codes", () => {
  const codes = PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_HOST_ERROR_CODE;
  assert.ok(Object.isFrozen(codes));
  assert.equal(Object.keys(codes).length, 105);
  for (const code of [...EXTERNAL_CODES, ...INTERNAL_CODES, ...HOST_FINALIZED_PROFILE_CODES, ...HOST_CREDENTIAL_OBLIGATION_CODES]) {
    assert.equal(codes[code], code);
  }
});
test("the error class is a real Error subclass", () => {
  assert.ok(PhilCoreV2ConsumerRecoveryGenesisStagingHostError.prototype instanceof Error);
});
test("the host exposes exactly the 12 public methods", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost({ storageRoot: dir, nowFn: () => 1700000000, livenessProbeFn: () => "DEAD" });
    const own = Object.keys(instance).filter((k) => typeof instance[k] === "function");
    assert.deepEqual(own.sort(), [...PUBLIC_METHODS].sort());
    instance.close();
  });
});
test("construction creates the five derived directories and the lock, then close removes the lock", () => {
  withRoot((dir) => {
    const shared = path.join(dir, "philcore-recovery-enrollment");
    const staging = path.join(shared, "genesis-staging");
    const instance = createRecoveryGenesisStagingHost({ storageRoot: dir, nowFn: () => 1700000000, livenessProbeFn: () => "DEAD" });
    assert.ok(fs.existsSync(shared));
    assert.ok(fs.existsSync(staging));
    assert.ok(fs.existsSync(path.join(shared, "genesis-profiles")));
    assert.ok(fs.existsSync(path.join(staging, ".corrupt-quarantine")));
    assert.ok(fs.existsSync(path.join(staging, ".stale-lock-quarantine")));
    assert.ok(fs.existsSync(path.join(staging, ".staging.lock")));
    instance.close();
    assert.ok(!fs.existsSync(path.join(staging, ".staging.lock")));
  });
});

// ---------------------------------------------------------------------------
// 5. Error contract — five detail keys, closed domains, containment
// ---------------------------------------------------------------------------
test("thrown host errors carry exactly the 5 detail keys", () => {
  assert.throws(
    () => createRecoveryGenesisStagingHost(null),
    (error) => {
      assert.ok(error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError);
      assert.deepEqual(Object.keys(error.detail).sort(), DETAIL_KEYS);
      assert.ok(!("primaryPhase" in error.detail));
      return true;
    }
  );
});
test("detail.phase is drawn only from the 107-member external domain", () => {
  assert.throws(
    () => createRecoveryGenesisStagingHost(null),
    (error) => EXTERNAL_PHASES.includes(error.detail.phase)
  );
});
test("a hostile dependency object has no property read, enumerated, or coerced", () => {
  const hostile = new Proxy({}, {
    ownKeys() { throw new Error("ownKeys trap"); },
    get() { throw new Error("get trap"); },
    getOwnPropertyDescriptor() { throw new Error("gOPD trap"); }
  });
  assert.throws(
    () => createRecoveryGenesisStagingHost(hostile),
    (error) => {
      assert.equal(error.code, "HOST_DEPENDENCY_ENUMERATION_FAILED");
      assert.ok(!("cause" in error) || error.cause === undefined);
      assert.ok(!JSON.stringify({ ...error, detail: error.detail }).includes("trap"));
      return true;
    }
  );
});
test("no absolute path leaks into a thrown error", () => {
  withRoot((dir) => {
    const absent = path.join(dir, "definitely-absent-root");
    assert.throws(
      () => createRecoveryGenesisStagingHost({ storageRoot: absent, nowFn: () => 1, livenessProbeFn: () => "DEAD" }),
      (error) => {
        const serialized = JSON.stringify({ ...error, message: error.message, detail: error.detail });
        assert.ok(!serialized.includes(absent), "an absolute path leaked");
        return true;
      }
    );
  });
});

// ---------------------------------------------------------------------------
// 6. Scenario driver — every fail site reached by real injected execution
// ---------------------------------------------------------------------------
function baseDeps(dir, overrides) {
  return Object.assign({ storageRoot: dir, nowFn: () => 1700000000, livenessProbeFn: () => "DEAD" }, overrides || {});
}

// Operations whose fail sites lie past a loaded, active journal.
const NEEDS_JOURNAL = new Set(["stageRole", "cancel", "acknowledgeTerminal"]);

// A schema-valid genesis deployment intent, matching the 5B-0.4 fixture shape.
function validIntent(overrides) {
  const rep = (byte, times) => `0x${byte.repeat(times)}`;
  return Object.assign(
    {
      intentVersion: "1",
      intentId: rep("11", 32),
      chainId: "11155111",
      entryPoint: getAddress(rep("22", 20)),
      factoryBinding: getAddress(rep("33", 20)),
      confirmationTarget: getAddress(rep("44", 20)),
      verifier: getAddress(rep("55", 20)),
      verifierRuntimeCodeHash: rep("66", 32),
      accountCreationBytecodeHash: rep("77", 32),
      accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
      securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
      recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
      ownerCommitment: rep("bb", 32),
      identityBindingCommitment: rep("cc", 32),
      initialValidator: getAddress(rep("dd", 20)),
      validatorVerifierKind: "1",
      validatorKeyIdBinding: rep("ee", 32),
      validatorCommitment: rep("ff", 32),
      validatorEpoch: "1",
      recoveryEpoch: "1",
      recoveryDelaySeconds: "172800",
      recoveryExpirySeconds: "604800",
      userSalt: rep("ab", 32),
      expiresAt: "1900000000"
    },
    overrides || {}
  );
}

// Numeric candidate fields are bigint at 5B-0.4's boundary; the fixture JSON
// stores them as JSON numbers, so they are converted here, never in production.
const DESCRIPTOR_NUMERIC_FIELDS = [
  "descriptorVersion", "role", "verifierKind", "userVerificationPolicy",
  "backupPolicy", "authenticatorAttachmentPolicy", "attestationPolicy", "credentialGeneration"
];
const INDEPENDENCE_NUMERIC_FIELDS = [
  "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
  "independenceAssurance", "credentialGeneration"
];
function toBigintFields(source, fields) {
  const out = Object.assign({}, source);
  for (const field of fields) if (typeof out[field] === "number") out[field] = BigInt(out[field]);
  return out;
}

function ceremonyFields(role, intentHash, expiresAt) {
  return {
    ceremonyVersion: "1",
    ceremonyId: `0x${String(role + 1).padStart(2, "0")}${"a1".repeat(31)}`,
    genesisDeploymentIntentHash: intentHash,
    role: String(role),
    credentialGeneration: "1",
    expiresAt: expiresAt || "1899999999"
  };
}

function mintCeremonyFor(intent, role, now) {
  const intentHash = genesisProtocol.computePhilCoreV2LocalGenesisDeploymentIntentHash(intent);
  return genesisLifecycle.mintPhilCoreV2GenesisRoleCeremony({
    current: null,
    ceremonyId: `0x${String(role + 1).padStart(2, "0")}${"a1".repeat(31)}`,
    role: BigInt(role),
    genesisDeploymentIntentHash: intentHash,
    intentExpiresAtUnixSeconds: BigInt(intent.expiresAt),
    nowUnixSeconds: now === undefined ? 1700000000 : now
  });
}

function validStageInput(intent, role, ceremony) {
  const r = role === undefined ? 0 : role;
  const intentHash = genesisProtocol.computePhilCoreV2LocalGenesisDeploymentIntentHash(intent);
  const minted = ceremony || null;
  const ceremonyProjection = minted
    ? genesisLifecycle.toPhilCoreV2GenesisRoleCeremonyHashInput(minted)
    : ceremonyFields(r, intentHash);
  const ceremonyHash = genesisProtocol.computePhilCoreV2LocalGenesisEnrollmentCeremonyHash(ceremonyProjection);
  const factors = O39_FIXTURES.profiles.standard.factors;
  const base = [factors.primary, factors.secondary, factors.offline][r];
  const independence = Object.assign(
    toBigintFields(base.independence, INDEPENDENCE_NUMERIC_FIELDS),
    { role: BigInt(r), enrollmentCeremonyHash: ceremonyHash, credentialGeneration: 1n }
  );
  const descriptor = Object.assign(
    toBigintFields(base.descriptor, DESCRIPTOR_NUMERIC_FIELDS),
    {
      role: BigInt(r),
      credentialGeneration: 1n,
      independenceBindingHash: computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence)
    }
  );
  const roleInput = { descriptor, independence, currentRoleCeremony: ceremonyProjection };
  if (base.signer) roleInput.signer = base.signer;
  return { role: r, roleInput, ceremony: minted };
}

function establishRecordedCredential(instance, intent, role, now) {
  const minted = mintCeremonyFor(intent, role, now);
  instance.beginCredentialObligation(minted);
  instance.authorizeCredentialCreation(minted.ceremonyId);
  const call = validStageInput(intent, role, minted);
  instance.recordCreatedCredential({
    expectedCeremonyId: minted.ceremonyId,
    credentialIdHash: call.roleInput.descriptor.credentialIdHash,
    publicVerificationMaterialHash: call.roleInput.descriptor.publicVerificationMaterialHash
  });
  return { minted, call };
}

// Chain 4's accepted public API is stageRole(role, roleInput) — two ordered
// arguments, never a wrapper object. Staging requires a recorded credential.
function callStageRole(instance, intent, role) {
  const prepared = establishRecordedCredential(instance, intent, role);
  return instance.stageRole(prepared.call.role, prepared.call.roleInput);
}

function obligationFilePath(dir) {
  return path.join(
    dir, "philcore-recovery-enrollment", "genesis-staging",
    "genesis-credential-obligation.v1.json"
  );
}

function obligationTempPath(dir) {
  return path.join(
    dir, "philcore-recovery-enrollment", "genesis-staging",
    "genesis-credential-obligation.v1.json.tmp"
  );
}

function storedJournalPath(dir, record) {
  return path.join(
    dir, "philcore-recovery-enrollment", "genesis-staging",
    `ceremony_${String(record.intentId).replace(/^0x/u, "")}.v1.json`
  );
}

function writeStoredRecord(file, record) {
  fs.writeFileSync(file, JSON.stringify(record), { mode: 0o600 });
}

function plantRecordedCredentialMismatchExactMatch(dir, instance) {
  const intent = validIntent();
  const journal = instance.createJournal(intent).journal;
  const prepared = establishRecordedCredential(instance, intent, 0);
  const sidecarPath = obligationFilePath(dir);
  const recorded = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
  const orphaned = genesisObligation.orphanPhilCoreV2GenesisCredentialObligation({
    current: recorded,
    reason: "RECORDED_CREDENTIAL_MISMATCH",
    nowUnixSeconds: HOST_PROFILE_NOW + 1
  });
  writeStoredRecord(sidecarPath, orphaned);
  const occupied = pureJournal.stageGenesisRoleCandidate(
    journal, prepared.call.role, prepared.call.roleInput, HOST_PROFILE_NOW
  );
  writeStoredRecord(storedJournalPath(dir, occupied), occupied);
  return { intent, prepared, orphaned, occupied };
}

function captureHostFailure(run) {
  try {
    run();
    return null;
  } catch (error) {
    return error;
  }
}

const HOST_PROFILE_NOW = 1700000000;

function profilesDir(dir) {
  return path.join(dir, "philcore-recovery-enrollment", "genesis-profiles");
}

function finalizedProfileFilePath(dir, record) {
  const hash = String(record.genesisDeploymentIntentHash).replace(/^0x/u, "");
  return path.join(profilesDir(dir), `profile_${hash}.v1.json`);
}

function profileReadyHost(dir, overrides) {
  const opts = overrides || {};
  const instance = createRecoveryGenesisStagingHost(baseDeps(dir, opts.deps));
  instance.reconcileRestart();
  const intent = validIntent(opts.intentOverrides);
  instance.createJournal(intent);
  let journal = null;
  for (const role of [0, 1, 2]) {
    journal = callStageRole(instance, intent, role).journal;
  }
  return { instance, intent, journal };
}

function expectedValidationForHost(journal, now) {
  return validateGenesisStagingProfileAdapter(
    journal,
    now === undefined ? HOST_PROFILE_NOW : now
  );
}

let serializationGetterInvocations = 0;

function plantExpiredJournal(dir) {
  const shared = path.join(dir, "philcore-recovery-enrollment");
  const staging = path.join(shared, "genesis-staging");
  fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
  fs.chmodSync(shared, 0o700);
  fs.chmodSync(staging, 0o700);
  const expired = pureJournal.createGenesisStagingJournal(validIntent({ expiresAt: "1000" }), 1);
  const name = `ceremony_${String(expired.intentId).replace(/^0x/u, "")}.v1.json`;
  fs.writeFileSync(path.join(staging, name), JSON.stringify(expired), { mode: 0o600 });
  return expired;
}

// Writes a schema-valid, non-expired STAGING journal whose timestamps are old.
function plantStagingJournal(dir, createdAt) {
  const shared = path.join(dir, "philcore-recovery-enrollment");
  const staging = path.join(shared, "genesis-staging");
  fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
  fs.chmodSync(shared, 0o700);
  fs.chmodSync(staging, 0o700);
  const record = pureJournal.createGenesisStagingJournal(validIntent(), createdAt);
  const name = `ceremony_${String(record.intentId).replace(/^0x/u, "")}.v1.json`;
  fs.writeFileSync(path.join(staging, name), JSON.stringify(record), { mode: 0o600 });
  return record;
}

// Wraps the 5B-0.4 delegation boundary so the record handed to the host's
// serializer carries an accessor own property, while Object.prototype.toJSON
// is simultaneously polluted. The accepted projection must reject without ever
// invoking the getter and without consulting the pollution.
function withHostileSerialization(body) {
  const realFns = {
    createGenesisStagingJournal: pureJournal.createGenesisStagingJournal,
    stageGenesisRoleCandidate: pureJournal.stageGenesisRoleCandidate,
    cancelGenesisStagingJournal: pureJournal.cancelGenesisStagingJournal
  };
  let previous;
  let polluted = false;
  const withAccessor = (record) => {
    const shaped = {};
    for (const key of Object.keys(record)) {
      if (key === "state") {
        Object.defineProperty(shaped, key, {
          enumerable: true, configurable: true,
          get() { serializationGetterInvocations += 1; return record[key]; }
        });
      } else {
        shaped[key] = record[key];
      }
    }
    return shaped;
  };
  try {
    previous = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
    Object.defineProperty(Object.prototype, "toJSON", {
      value() { return { polluted: true }; },
      configurable: true, writable: true, enumerable: false
    });
    polluted = true;
    for (const name of Object.keys(realFns)) {
      pureJournal[name] = (...args) => withAccessor(realFns[name](...args));
    }
    serializationGetterInvocations = 0;
    return body();
  } finally {
    for (const name of Object.keys(realFns)) pureJournal[name] = realFns[name];
    if (polluted) {
      if (previous) Object.defineProperty(Object.prototype, "toJSON", previous);
      else delete Object.prototype.toJSON;
    }
  }
}

// The acknowledgment boundary is exactly the retained record's identity and
// its integrity checksum.
function validAck(record) {
  return { intentId: record.intentId, integrityChecksum: record.integrityChecksum };
}

// Disk state required before construction for specific reconcileRestart rows.
function plantReconcileFixture(id, dir) {
  const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
  const ensure = () => {
    fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
    fs.chmodSync(path.join(dir, "philcore-recovery-enrollment"), 0o700);
    fs.chmodSync(staging, 0o700);
  };
  const journalName = `ceremony_${"ab".repeat(32)}.v1.json`;
  const tempName = `.ceremony_${"ab".repeat(32)}.v1.json.tmp`;

  // Rows 2.09-2.11 classify staging entries.
  if (id === "2.09") { ensure(); fs.writeFileSync(path.join(staging, "unexpected-entry"), "x", { mode: 0o600 }); return; }
  if (id === "2.10") {
    ensure();
    fs.writeFileSync(path.join(staging, journalName), "{}", { mode: 0o600 });
    fs.writeFileSync(path.join(staging, `ceremony_${"cd".repeat(32)}.v1.json`), "{}", { mode: 0o600 });
    return;
  }
  if (id === "2.11") {
    ensure();
    for (let i = 0; i < 11; i += 1) {
      const name = `.ceremony_${String(i).padStart(2, "0").repeat(32)}.v1.json.tmp`;
      fs.writeFileSync(path.join(staging, name), "x", { mode: 0o600 });
    }
    return;
  }
  // Rows 2.20-2.25 sweep an abandoned temp.
  if (["2.20", "2.21", "2.22", "2.23", "2.24", "2.25"].includes(id)) {
    ensure();
    fs.writeFileSync(path.join(staging, tempName), "x", { mode: 0o600 });
    return;
  }
  const n = Number(id.split(".")[1]);

  // Row 2.31 needs the corrupt-quarantine slot bound already exhausted.
  if (n === 31) {
    ensure();
    fs.writeFileSync(path.join(staging, journalName), "not-json", { mode: 0o600 });
    for (let slot = 0; slot < 10; slot += 1) {
      fs.writeFileSync(path.join(staging, ".corrupt-quarantine", `${journalName}.corrupt.${slot}`), "x", { mode: 0o600 });
    }
    return;
  }
  // Rows 2.26-2.42 read, then quarantine, a corrupt journal.
  if (n >= 26 && n <= 42) {
    ensure();
    fs.writeFileSync(path.join(staging, journalName), "not-json", { mode: 0o600 });
    return;
  }
  // Rows 2.43-2.65 exercise the reconciliation expiry write, which requires a
  // schema-valid STAGING journal whose expiry has already passed.
  if (n >= 43 && n <= 65) {
    ensure();
    const intent = validIntent({ expiresAt: "1000" });
    const record = pureJournal.createGenesisStagingJournal(intent, 1);
    const name = `ceremony_${String(record.intentId).replace(/^0x/u, "")}.v1.json`;
    fs.writeFileSync(path.join(staging, name), JSON.stringify(record), { mode: 0o600 });
    return;
  }
  ensure();
}

// Builds a stale lock on disk so construction enters the quarantine path.
function plantStaleLock(dir, ageSeconds) {
  const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
  fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.join(dir, "philcore-recovery-enrollment"), 0o700);
  fs.chmodSync(staging, 0o700);
  const lock = path.join(staging, ".staging.lock");
  fs.writeFileSync(lock, JSON.stringify({ pid: "999999", createdAtUnixSeconds: String(1700000000 - ageSeconds) }), { mode: 0o600 });
  return lock;
}

// Executes the row's operation with the row's fault plan armed, returning the
// thrown error (or null when nothing was thrown).
function runRow(row) {
  const [id, operation, code, phase, subject] = row;
  const call = PHASE_CALL[phase];
  const label = subject && subject !== "null" ? SUBJECT_LABEL[subject] : null;

  return withRoot((dir) => {
    // Non-syscall fail sites are driven by shaping the inputs or host state.
    const nonSyscall = shapeNonSyscall(id, operation, phase, code, dir, subject);
    if (nonSyscall !== undefined) return nonSyscall;

    const multi = multiPlanFor(phase);
    if (multi && operation === "construct") {
      return withFacade(dir, multi, () => {
        try { createRecoveryGenesisStagingHost(baseDeps(dir)); return null; }
        catch (error) { return error; }
      });
    }
    if (multi) {
      return withFacade(dir, multi, (facade) => {
        facade.disarm();
        let instance;
        try { instance = createRecoveryGenesisStagingHost(baseDeps(dir)); }
        catch (error) { return { __setupFailed: `construct:${error.code}` }; }
        const intent = validIntent();
        if (operation === "reconcileRestart") {
          // The expiry write needs an already-expired STAGING journal.
          const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
          const expired = pureJournal.createGenesisStagingJournal(validIntent({ expiresAt: "1000" }), 1);
          const name = `ceremony_${String(expired.intentId).replace(/^0x/u, "")}.v1.json`;
          fs.writeFileSync(path.join(staging, name), JSON.stringify(expired), { mode: 0o600 });
          facade.arm();
          try { instance.reconcileRestart(); return null; } catch (error) { return error; }
        }
        try { instance.reconcileRestart(); } catch (error) { return { __setupFailed: `reconcile:${error.code}` }; }
        let prepared = null;
        if (NEEDS_JOURNAL.has(operation)) {
          try { instance.createJournal(intent); }
          catch (error) { return { __setupFailed: `createJournal:${error.code || error.message}` }; }
          if (operation === "stageRole") {
            try { prepared = establishRecordedCredential(instance, intent, 0); }
            catch (error) { return { __setupFailed: `recordCredential:${error.code || error.message}` }; }
          }
        }
        facade.arm();
        try {
          if (operation === "createJournal") instance.createJournal(intent);
          else if (operation === "stageRole") instance.stageRole(prepared.call.role, prepared.call.roleInput);
          else if (operation === "cancel") instance.cancel();
          return null;
        } catch (error) { return error; }
      });
    }

    const override = PLAN_OVERRIDE[id] || PHASE_PLAN[phase];
    if (!call && !override) return { __unplanned: `no syscall mapping for phase ${phase}` };
    const plan = Object.assign(
      {
        call,
        label: RENAME_LABEL_ROWS.has(id) ? "temp" : (PHASE_LABEL[phase] || label),
        occurrence: OCCURRENCE[id] || PHASE_OCCURRENCE[phase] || 1,
        behave: () => { throw errno(BEHAVIOUR[id] || "EIO"); }
      },
      override || {}
    );

    return withFacade(dir, plan, (facade) => {
      if (operation === "construct") {
        // Fixture planting is never subject to injection.
        if (PRE_STALE.has(id)) {
          facade.disarm();
          plantStaleLock(dir, 100000);
          facade.arm();
        }
        try { createRecoveryGenesisStagingHost(baseDeps(dir)); return null; }
        catch (error) { return error; }
      }

      // Host methods: construct cleanly with the facade disarmed, then arm.
      facade.disarm();
      if (operation === "reconcileRestart") plantReconcileFixture(id, dir);
      let instance;
      try { instance = createRecoveryGenesisStagingHost(baseDeps(dir)); }
      catch (error) { return { __setupFailed: `construct:${error.code}` }; }
      if (operation !== "reconcileRestart") {
        try { instance.reconcileRestart(); } catch (error) { return { __setupFailed: `reconcile:${error.code}` }; }
      }
      // Operations that mutate or acknowledge an existing journal need one on
      // disk and loaded into the host's retained record.
      const intent = validIntent();
      let currentRecord = null;
      let prepared = null;
      if (NEEDS_JOURNAL.has(operation)) {
        try { currentRecord = instance.createJournal(intent).journal; }
        catch (error) { return { __setupFailed: `createJournal:${error.code || error.message}` }; }
        if (operation === "acknowledgeTerminal") {
          // A terminal record is required before an acknowledgment is legal.
          try { currentRecord = instance.cancel().journal; }
          catch (error) { return { __setupFailed: `cancel:${error.code || error.message}` }; }
        }
        if (operation === "stageRole") {
          try { prepared = establishRecordedCredential(instance, intent, 0); }
          catch (error) { return { __setupFailed: `recordCredential:${error.code || error.message}` }; }
        }
      }
      facade.arm();
      try {
        if (operation === "close") instance.close();
        else if (operation === "status") instance.status();
        else if (operation === "reconcileRestart") instance.reconcileRestart();
        else if (operation === "createJournal") instance.createJournal(intent);
        else if (operation === "stageRole") instance.stageRole(prepared.call.role, prepared.call.roleInput);
        else if (operation === "cancel") instance.cancel();
        else if (operation === "acknowledgeTerminal") instance.acknowledgeTerminal(validAck(currentRecord));
        return null;
      } catch (error) { return error; }
    });
  });
}

// Rows whose fail site needs the existing-lock/quarantine path on disk.
const PRE_STALE = new Set([
  "1.23","1.24","1.25","1.26","1.27","1.28","1.29","1.30","1.31","1.32","1.33",
  "1.34","1.35","1.36","1.37","1.38","1.39","1.40","1.41","1.42","1.43","1.44","1.45"
]);

// Per-row occurrence and errno overrides where the first matching call is not
// the fail site, or where the code distinguishes ENOENT from other errno.
const OCCURRENCE = {
  "1.36": 2,
  "1.38": 2, "1.39": 2, "1.40": 1, "1.41": 2,
  "1.42": 2, "1.43": 2, "1.44": 1, "1.45": 2,
  "1.46": 2,
  "1.51": 2, "1.52": 2, "1.53": 2, "1.54": 2,
  "2.33": 2, "2.52": 2, "2.53": 2, "2.54": 2, "2.55": 2
};
const BEHAVIOUR = {
  "1.23": "EACCES", "8.01": "ENOENT",
  "4.09": "ENOENT", "4.26": "ENOENT",
  "5.09": "ENOENT", "5.26": "ENOENT", "7.15": "ENOENT", "7.23": "ENOENT",
  "2.52": "ENOENT", "2.44": "EEXIST", "3.14": "EEXIST", "4.18": "EEXIST", "5.18": "EEXIST"
};

// Fully specified plans for fail sites whose trigger is a doctored metadata
// result or a distinguishing errno rather than a generic EIO on the first
// matching call.
const STAT_PREDICATES = new Set([
  "isFile", "isDirectory", "isSymbolicLink", "isFIFO",
  "isSocket", "isBlockDevice", "isCharacterDevice"
]);
const doctored = (patch) => (stat) =>
  new Proxy(stat, {
    get(target, key) {
      if (Object.prototype.hasOwnProperty.call(patch, key)) {
        const value = patch[key];
        // Type predicates are methods; dev/ino/uid/mode/nlink/size are data.
        return STAT_PREDICATES.has(key) ? () => value : value;
      }
      const value = target[key];
      return typeof value === "function" ? value.bind(target) : value;
    }
  });

const PLAN_OVERRIDE = {
  // The absence probe finds a journal that appeared after the temp write.
  "3.27": {
    call: "lstatSync", label: "journal", occurrence: 1,
    behave: (_x, args, { real }) => {
      fs.writeFileSync(args[0], "{}", { mode: 0o600 });
      return real.lstatSync.apply(fs, args);
    }
  },
  // ROOT_VALIDATION operates on the storage root itself, not the shared leaf.
  "1.09": { call: "lstatSync", label: "root", behave: () => { throw errno("ENOENT"); } },
  "1.10": { call: null, label: "root", doctor: "lstatSync",
            doctorFn: doctored({ isSymbolicLink: true, isDirectory: false }) },
  "1.11": { call: null, label: "root", doctor: "lstatSync",
            doctorFn: doctored({ isSymbolicLink: false, isDirectory: false }) },

  // DIRECTORY_VALIDATE trio: non-directory, foreign owner, wrong mode.
  "1.14": { call: null, doctor: "fstatSync", label: "corrupt",
            doctorFn: doctored({ isDirectory: false }) },
  "1.15": { call: null, doctor: "fstatSync", label: "corrupt",
            doctorFn: doctored({ isDirectory: true, mode: 0o40755 }) },
  "1.16": { call: null, doctor: "fstatSync", label: "stale",
            doctorFn: doctored({ isDirectory: true, uid: 999999 }) },

  // Lock probe classification and recheck drift.
  "1.24": { call: null, doctor: "fstatSync", label: "lock",
            doctorFn: doctored({ isFile: false }) },
  "1.25": { call: null, doctor: "fstatSync", label: "lock",
            doctorFn: doctored({ isFile: true, size: 4096 }) },
  "1.27": { call: null, doctor: "fstatSync", label: "lock", occurrence: 2,
            doctorFn: doctored({ isFile: true, ino: 424242 }) },

  // Post-create lock validation and final identity drift.
  "1.47": { call: null, doctor: "fstatSync", label: "lock",
            doctorFn: doctored({ isFile: false }) },
  "1.55": { call: null, doctor: "lstatSync", label: "lock",
            doctorFn: doctored({ ino: 424242 }) },

  // Release-probe classification and identity drift (chain 8).
  "8.03": { call: null, doctor: "lstatSync", label: "lock",
            doctorFn: doctored({ isSymbolicLink: true }) },
  "8.02": { call: "lstatSync", label: "lock", behave: () => { throw errno("EACCES"); } }
};
for (const key of Object.keys(PLAN_OVERRIDE)) {
  const o = PLAN_OVERRIDE[key];
  if (o.behave === null) delete o.behave;
  if (o.call === null) { o.call = "__none__"; o.label = o.label; }
}

// Cleanup fail sites are only reachable after a genuine antecedent failure.
// The antecedent is a real injected temp-fsync failure, whose own code becomes
// the consequent's primaryCode; the secondary fault is the cleanup step.
const TEMP_ANTECEDENT = () => ({
  call: "fsyncSync", label: "temp", occurrence: 1,
  behave: () => { throw errno("EIO"); }
});
const CLEANUP_SECOND = {
  TEMP_CLEANUP_UNLINK: { call: "unlinkSync", label: "temp" },
  TEMP_CLEANUP_DIR_OPEN: { call: "openSync", label: "staging" },
  TEMP_CLEANUP_DIR_VALIDATE: { call: "fstatSync", label: "staging" },
  TEMP_CLEANUP_DIR_FSYNC: { call: "fsyncSync", label: "staging" },
  TEMP_CLEANUP_DIR_CLOSE: { call: "closeSync", label: "staging" }
};
// Chain 1's SM5 cleanup: a genuine lock-payload fsync failure, then the
// cleanup step's own independent failure.
const LOCK_CLEANUP_SECOND = {
  LOCK_CLEANUP_PROBE: { call: "lstatSync", label: "lock", occurrence: 1 },
  LOCK_CLEANUP_UNLINK: { call: "unlinkSync", label: "lock", occurrence: 1 },
  LOCK_CLEANUP_DIR_OPEN: { call: "openSync", label: "staging", occurrence: 2 },
  LOCK_CLEANUP_DIR_VALIDATE: { call: "fstatSync", label: "staging", occurrence: 2 },
  LOCK_CLEANUP_DIR_FSYNC: { call: "fsyncSync", label: "staging", occurrence: 2 },
  LOCK_CLEANUP_DIR_CLOSE: { call: "closeSync", label: "staging", occurrence: 2 }
};

function multiPlanFor(phase) {
  const lockSecond = LOCK_CLEANUP_SECOND[phase];
  if (lockSecond) {
    return [
      { call: "fsyncSync", label: "lock", occurrence: 1, behave: () => { throw errno("EIO"); } },
      Object.assign({ behave: () => { throw errno("EIO"); } }, lockSecond)
    ];
  }
  const second = CLEANUP_SECOND[phase];
  if (!second) return null;
  return [
    TEMP_ANTECEDENT(),
    Object.assign({ occurrence: 1, behave: () => { throw errno("EIO"); } }, second)
  ];
}

// Phases reached by shaping the captured stat of a syscall that does succeed.
const PHASE_PLAN = {
  CAS_CREATE_SCAN_MATCH: {
    call: "opendirSync", label: "staging", occurrence: 2,
    behave: (_x, args, { real }) => {
      // A competing journal appears between the temp write and the scan.
      const dir = args[0];
      fs.writeFileSync(path.join(dir, `ceremony_${"cd".repeat(32)}.v1.json`), "{}", { mode: 0o600 });
      return real.opendirSync.apply(fs, args);
    }
  },
  CAS_FINAL_CLASSIFY: { call: "__none__", doctor: "lstatSync", label: "journal",
                        doctorFn: doctored({ isFile: false }) },
  CAS_FINAL_IDENTITY_COMPARE: { call: "__none__", doctor: "lstatSync", label: "journal",
                                doctorFn: doctored({ ino: 424242 }) }
};

// Non-syscall fail sites: shaped inputs, host state, or injected callbacks.
function shapeNonSyscall(id, operation, phase, code, dir, subject) {
  const attempt = (fn) => { try { return fn(); } catch (error) { return error; } };

  if (phase === "DEPENDENCY_VALIDATION") {
    if (code === "HOST_DEPENDENCIES_NOT_OBJECT") return attempt(() => createRecoveryGenesisStagingHost(null));
    if (code === "HOST_DEPENDENCY_ENUMERATION_FAILED") {
      const hostile = new Proxy({}, { ownKeys() { throw new Error("x"); } });
      return attempt(() => createRecoveryGenesisStagingHost(hostile));
    }
    if (code === "HOST_DEPENDENCY_EXTRA") return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir, { extra: 1 })));
    if (code === "HOST_DEPENDENCY_MISSING") return attempt(() => createRecoveryGenesisStagingHost({ nowFn: () => 1, livenessProbeFn: () => "DEAD" }));
    if (code === "HOST_DEPENDENCY_READ_FAILED") {
      const target = { nowFn: () => 1, livenessProbeFn: () => "DEAD" };
      Object.defineProperty(target, "storageRoot", { enumerable: true, get() { throw new Error("x"); } });
      return attempt(() => createRecoveryGenesisStagingHost(target));
    }
    if (code === "HOST_DEPENDENCY_INVALID") return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir, { storageRoot: 7 })));
  }

  if (phase === "MODULE_POISON_CHECK") {
    // Poison the registry through a real indeterminate release, then rebuild.
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const plan = { call: "fsyncSync", label: "staging", occurrence: 1, behave: () => { throw errno("EIO"); } };
    withFacade(dir, plan, () => { try { instance.close(); } catch { /* poisons the root */ } });
    void staging;
    return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir)));
  }

  if (phase === "LOCK_PROBE_PARSE") {
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
    fs.chmodSync(path.join(dir, "philcore-recovery-enrollment"), 0o700);
    fs.chmodSync(staging, 0o700);
    fs.writeFileSync(path.join(staging, ".staging.lock"), "{ not json", { mode: 0o600 });
    return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir)));
  }

  if (phase === "LOCK_LIVENESS") {
    plantStaleLock(dir, 100000);
    const probe =
      code === "HOST_LOCK_HELD" ? () => "LIVE"
      : code === "HOST_LOCK_HELD_OR_AMBIGUOUS" ? () => "AMBIGUOUS"
      : () => "NOT_A_LITERAL";
    return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir, { livenessProbeFn: probe })));
  }

  if (phase === "LOCK_STALENESS_WINDOW") {
    plantStaleLock(dir, 5);
    return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir)));
  }

  if (phase === "QUARANTINE_BOUND" && id.startsWith("1.")) {
    plantStaleLock(dir, 100000);
    const staleDir = path.join(dir, "philcore-recovery-enrollment", "genesis-staging", ".stale-lock-quarantine");
    for (let slot = 0; slot < 10; slot += 1) fs.writeFileSync(path.join(staleDir, `staging.lock.stale.${slot}`), "x", { mode: 0o600 });
    return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir)));
  }

  // --- Bounded-enumeration overflow (real entry counts) --------------------
  if (code === "HOST_QUARANTINE_SCAN_OVERFLOW" || code === "HOST_STAGING_SCAN_OVERFLOW") {
    const shared = path.join(dir, "philcore-recovery-enrollment");
    const staging = path.join(shared, "genesis-staging");
    const corrupt = path.join(staging, ".corrupt-quarantine");
    const stale = path.join(staging, ".stale-lock-quarantine");
    const prepare = () => {
      fs.mkdirSync(corrupt, { recursive: true, mode: 0o700 });
      fs.mkdirSync(stale, { recursive: true, mode: 0o700 });
      fs.chmodSync(shared, 0o700);
      fs.chmodSync(staging, 0o700);
    };
    const fill = (target, count) => {
      for (let i = 0; i < count; i += 1) {
        fs.writeFileSync(path.join(target, `filler-${i}`), "x", { mode: 0o600 });
      }
    };
    const target =
      subject === "CORRUPT_QUARANTINE_DIRECTORY" ? corrupt
      : subject === "STALE_LOCK_QUARANTINE_DIRECTORY" ? stale
      : staging;

    // Construction enumerates the stale-lock directory, so its overflow is
    // planted before the host is built.
    if (operation === "construct") {
      prepare();
      fill(target, 65);
      return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir)));
    }

    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));

    if (operation === "reconcileRestart") {
      // Planted after construction so the construction-time scan still passes.
      // Staging already holds the lock and both quarantine directories.
      fill(target, target === staging ? 512 - 3 + 1 : 65);
      return attempt(() => instance.reconcileRestart());
    }

    instance.reconcileRestart();
    // The pre-create scan overflows outright; the create-CAS scan is tipped
    // over by the operation's own temp file.
    fill(staging, phase === "ENUMERATION_READ" ? 512 - 3 + 1 : 512 - 3);
    return attempt(() => instance.createJournal(validIntent()));
  }

  // --- Corrupt-quarantine slot bound (non-syscall) -------------------------
  if (phase === "QUARANTINE_BOUND" && id.startsWith("2.")) {
    const shared = path.join(dir, "philcore-recovery-enrollment");
    const staging = path.join(shared, "genesis-staging");
    const corrupt = path.join(staging, ".corrupt-quarantine");
    fs.mkdirSync(corrupt, { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
    fs.chmodSync(shared, 0o700);
    fs.chmodSync(staging, 0o700);
    const journalName = `ceremony_${"ab".repeat(32)}.v1.json`;
    fs.writeFileSync(path.join(staging, journalName), "not-json", { mode: 0o600 });
    for (let slot = 0; slot < 10; slot += 1) {
      fs.writeFileSync(path.join(corrupt, `${journalName}.corrupt.${slot}`), "x", { mode: 0o600 });
    }
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    return attempt(() => instance.reconcileRestart());
  }

  // --- Journal preconditions (non-syscall) --------------------------------
  if (phase === "JOURNAL_PRECONDITION" || phase === "JOURNAL_PRECONDITION_DISK_SCAN") {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    if (code === "HOST_JOURNAL_ALREADY_EXISTS" && phase === "JOURNAL_PRECONDITION") {
      instance.createJournal(intent);
      return attempt(() => instance.createJournal(intent));
    }
    if (code === "HOST_JOURNAL_ALREADY_EXISTS") {
      // A journal appears on disk without the host's in-memory record knowing.
      const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
      const name = `ceremony_${"ab".repeat(32)}.v1.json`;
      fs.writeFileSync(path.join(staging, name), "{}", { mode: 0o600 });
      return attempt(() => instance.createJournal(intent));
    }
    if (code === "HOST_JOURNAL_NOT_FOUND") {
      return attempt(() =>
        operation === "cancel" ? instance.cancel() : instance.stageRole(0, validStageInput(intent, 0).roleInput)
      );
    }
    if (code === "HOST_JOURNAL_NOT_ACTIVE") {
      instance.createJournal(intent);
      instance.cancel(); // drives the record terminal
      return attempt(() =>
        operation === "cancel" ? instance.cancel() : instance.stageRole(0, validStageInput(intent, 0).roleInput)
      );
    }
  }

  // --- Clock sample and regression (non-syscall) ---------------------------
  if (phase === "CLOCK_SAMPLE" || phase === "CLOCK_TRACKING") {
    let tick = 1700000000;
    let shouldThrow = false;
    const nowFn = () => {
      if (shouldThrow) throw new Error("nowFn marker");
      return tick;
    };

    if (code === "HOST_INVALID_NOW") {
      // A thrown nowFn substitutes the accepted sentinel; the delegated call
      // then fails with exactly INVALID_NOW, which maps to the host code.
      if (operation === "reconcileRestart") {
        const inst = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn }));
        shouldThrow = true;
        return attempt(() => inst.reconcileRestart());
      }
      const inst = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn }));
      inst.reconcileRestart();
      const intent = validIntent();
      let prepared = null;
      if (NEEDS_JOURNAL.has(operation)) inst.createJournal(intent);
      if (operation === "stageRole") prepared = establishRecordedCredential(inst, intent, 0);
      shouldThrow = true;
      if (operation === "createJournal") return attempt(() => inst.createJournal(intent));
      if (operation === "cancel") return attempt(() => inst.cancel());
      return attempt(() => inst.stageRole(prepared.call.role, prepared.call.roleInput));
    }

    // HOST_CLOCK_REGRESSION_DETECTED: the pure call must succeed first, so the
    // retained record's own timestamps must be older than the host's committed
    // sample. A planted STAGING journal supplies exactly that.
    if (operation === "createJournal") {
      tick = 1800000000;
      const inst = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn }));
      inst.reconcileRestart();
      tick = 1700000000;
      return attempt(() => inst.createJournal(validIntent()));
    }
    const planted = plantStagingJournal(dir, 1000);
    tick = 1700000000;
    const inst = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn }));
    inst.reconcileRestart();
    const intent = validIntent();
    let prepared = null;
    if (operation === "stageRole") prepared = establishRecordedCredential(inst, intent, 0);
    tick = 1600000000;
    if (operation === "cancel") return attempt(() => inst.cancel());
    if (operation === "reconcileRestart") return attempt(() => inst.reconcileRestart());
    void planted;
    return attempt(() => inst.stageRole(prepared.call.role, prepared.call.roleInput));
  }

  // --- Serialization rejection (non-syscall) ------------------------------
  if (phase === "SERIALIZE") {
    const intent = validIntent();
    if (operation === "reconcileRestart") {
      plantExpiredJournal(dir);
      const host2 = createRecoveryGenesisStagingHost(baseDeps(dir));
      // The expiry transition is delegated to the pure module, which rebuilds
      // the record through object literals, so an inherited setter can no
      // longer perturb its construction. The real transition is therefore
      // allowed to run to completion, and its genuine frozen record is then
      // wrapped in a transparent Proxy whose ownKeys trap throws a raw
      // non-Error marker. The host's projectContainer calls Reflect.ownKeys
      // inside a guarded try/catch and converts the throw into
      // SerializationRejected, which serializeRecord maps to this row's
      // outcome before any temp file exists.
      const realExpire = pureJournal.expireGenesisStagingJournalIfNeeded;
      const marker = { raw: "ROW_243_RAW_MARKER" };
      let transitionCompleted = false;
      let ownKeysTraps = 0;
      let observed;
      try {
        pureJournal.expireGenesisStagingJournalIfNeeded = (...args) => {
          const genuine = realExpire(...args);
          transitionCompleted = true;
          return new Proxy(genuine, {
            ownKeys() { ownKeysTraps += 1; throw marker; }
          });
        };
        observed = attempt(() => host2.reconcileRestart());
      } finally {
        pureJournal.expireGenesisStagingJournalIfNeeded = realExpire;
      }
      assert.equal(transitionCompleted, true, "the real transition must complete first");
      assert.equal(ownKeysTraps, 1, "the ownKeys trap must be invoked exactly once");
      assert.equal(pureJournal.expireGenesisStagingJournalIfNeeded, realExpire);
      // The raw marker is contained: it never escapes as the thrown value, is
      // not retained as a cause, and appears nowhere on the host error.
      assert.equal(observed === marker, false, "the raw marker must never escape");
      assert.ok(
        observed instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError,
        "the marker must be converted into a host error"
      );
      assert.ok(!("cause" in observed) || observed.cause === undefined);
      assert.deepEqual([...Object.keys(observed.detail)].sort(), [...DETAIL_KEYS].sort());
      assert.ok(
        !JSON.stringify({ ...observed, message: observed.message, detail: observed.detail })
          .includes("ROW_243_RAW_MARKER"),
        "the marker must not leak into the host error"
      );
      return observed;
    }
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    if (NEEDS_JOURNAL.has(operation)) instance.createJournal(intent);
    return withHostileSerialization(() => {
      if (operation === "createJournal") return attempt(() => instance.createJournal(intent));
      if (operation === "cancel") return attempt(() => instance.cancel());
      return attempt(() => callStageRole(instance, intent, 0));
    });
  }

  // --- Acknowledgment input, precondition, and identity --------------------
  if (phase.startsWith("ACK_")) {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    let record = instance.createJournal(intent).journal;

    if (phase === "ACK_PRECONDITION_NON_TERMINAL") {
      return attempt(() => instance.acknowledgeTerminal(validAck(record)));
    }
    record = instance.cancel().journal; // record is now terminal

    if (phase === "ACK_INPUT_VALIDATION") {
      if (code === "HOST_ACKNOWLEDGMENT_INPUT_NOT_OBJECT") {
        return attempt(() => instance.acknowledgeTerminal(null));
      }
      if (code === "HOST_ACKNOWLEDGMENT_ENUMERATION_FAILED") {
        const hostile = new Proxy({}, { ownKeys() { throw new Error("ownKeys trap"); } });
        return attempt(() => instance.acknowledgeTerminal(hostile));
      }
      if (code === "HOST_ACKNOWLEDGMENT_INPUT_EXTRA_KEY") {
        return attempt(() => instance.acknowledgeTerminal(Object.assign(validAck(record), { extra: 1 })));
      }
      if (code === "HOST_ACKNOWLEDGMENT_INPUT_MISSING_KEY") {
        return attempt(() => instance.acknowledgeTerminal({ intentId: record.intentId }));
      }
      if (code === "HOST_ACKNOWLEDGMENT_READ_FAILED") {
        const target = { integrityChecksum: record.integrityChecksum };
        Object.defineProperty(target, "intentId", { enumerable: true, get() { throw new Error("get trap"); } });
        return attempt(() => instance.acknowledgeTerminal(target));
      }
      if (code === "HOST_ACKNOWLEDGMENT_INPUT_INVALID") {
        return attempt(() => instance.acknowledgeTerminal({ intentId: 7, integrityChecksum: 9 }));
      }
    }
    if (phase === "ACK_PRECONDITION") {
      // A fresh host with no retained record cannot acknowledge anything.
      const other = freshRoot();
      try {
        const bare = createRecoveryGenesisStagingHost(baseDeps(other));
        bare.reconcileRestart();
        return attempt(() =>
          bare.acknowledgeTerminal({ intentId: record.intentId, integrityChecksum: record.integrityChecksum })
        );
      } finally {
        fs.rmSync(other, { recursive: true, force: true });
      }
    }
    if (phase === "ACK_IDENTITY_MATCH") {
      if (code === "HOST_ACKNOWLEDGMENT_IDENTITY_MISMATCH") {
        return attempt(() =>
          instance.acknowledgeTerminal({ intentId: `0x${"00".repeat(32)}`, integrityChecksum: record.integrityChecksum })
        );
      }
      return attempt(() =>
        instance.acknowledgeTerminal({ intentId: record.intentId, integrityChecksum: `0x${"00".repeat(32)}` })
      );
    }
  }

  // --- Initial-CAS checksum drift -----------------------------------------
  if (phase === "CAS_INITIAL_CHECKSUM_COMPARE") {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    const record = instance.createJournal(intent).journal;
    let ackRecord = record;
    if (operation === "acknowledgeTerminal") ackRecord = instance.cancel().journal;
    // Rewrite the on-disk record with a different integrity checksum, so the
    // retained record and the disk disagree at the initial CAS.
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const name = `ceremony_${String(ackRecord.intentId).replace(/^0x/u, "")}.v1.json`;
    const target = path.join(staging, name);
    const onDisk = JSON.parse(fs.readFileSync(target, "utf8"));
    onDisk.integrityChecksum = `0x${"00".repeat(32)}`;
    fs.writeFileSync(target, JSON.stringify(onDisk), { mode: 0o600 });
    if (operation === "cancel") return attempt(() => instance.cancel());
    if (operation === "acknowledgeTerminal") {
      return attempt(() => instance.acknowledgeTerminal(validAck(ackRecord)));
    }
    return attempt(() => callStageRole(instance, intent, 0));
  }

  if (phase === "PLATFORM_VALIDATION") {
    const original = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    try {
      return attempt(() => createRecoveryGenesisStagingHost(baseDeps(dir)));
    } finally {
      Object.defineProperty(process, "platform", original);
    }
  }

  if (phase === "LIFECYCLE_GUARD") {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const invoke = (inst) => {
      if (operation === "status") return inst.status();
      if (operation === "createJournal") return inst.createJournal({});
      if (operation === "stageRole") return inst.stageRole({});
      if (operation === "cancel") return inst.cancel();
      if (operation === "reconcileRestart") return inst.reconcileRestart();
      if (operation === "acknowledgeTerminal") return inst.acknowledgeTerminal({});
      return undefined;
    };
    if (code === "HOST_RECONCILIATION_REQUIRED") return attempt(() => invoke(instance));
    if (code === "HOST_CLOSED") { instance.close(); return attempt(() => invoke(instance)); }
    if (code === "HOST_PROCESS_POISONED") {
      const plan = { call: "fsyncSync", label: "staging", occurrence: 1, behave: () => { throw errno("EIO"); } };
      withFacade(dir, plan, () => { try { instance.close(); } catch { /* poisons */ } });
      return attempt(() => invoke(instance));
    }
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// 7. Per-row coverage — all 285 single-failure rows, real injected execution
// ---------------------------------------------------------------------------
for (const row of SINGLE_ROWS) {
  const [id, operation, code, phase, subject, commitState] = row;
  test(`single row ${id} — ${operation}/${code}/${phase}`, () => {
    const observed = runRow(row);
    assert.ok(observed, `row ${id} produced no error`);
    assert.ok(!observed.__unplanned, `row ${id}: ${observed.__unplanned}`);
    assert.ok(!observed.__setupFailed, `row ${id}: setup failed with ${observed.__setupFailed}`);
    assert.ok(
      observed instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError,
      `row ${id} threw a non-host error: ${observed && observed.message}`
    );
    const got = `${observed.code}/${observed.detail.phase}/${observed.detail.subject}/${observed.detail.commitState}`;
    const want = `${code}/${phase}/${subject === "null" ? null : subject}/${commitState}`;
    assert.equal(got, want, `row ${id} want ${want} got ${got}`);
    assert.equal(observed.detail.operation, operation, `row ${id} operation`);
  });
}

// ---------------------------------------------------------------------------
// 8. Compound coverage — all 441 compound rows
// ---------------------------------------------------------------------------
const SINGLE_BY_ID = new Map(SINGLE_ROWS.map((r) => [r[0], r]));

for (const row of COMPOUND_ROWS) {
  const [id, , antecedentCode, , , , operation, family] = row;
  test(`compound row ${id} — ${family}`, () => {
    const consequentId = id.split("~")[0];
    const antecedentId = id.split("~")[1];
    const consequent = SINGLE_BY_ID.get(consequentId);
    assert.ok(consequent, `unknown consequent ${consequentId}`);

    // The consequent's own externally observable obligations are fixed by its
    // single-failure row; the compound adds the antecedent relationship.
    if (/^[1-8]\.\d{2}$/u.test(antecedentId)) {
      const antecedent = SINGLE_BY_ID.get(antecedentId);
      assert.ok(antecedent, `unknown antecedent ${antecedentId}`);
      if (antecedentCode && /^HOST_[A-Z0-9_]+$/.test(antecedentCode)) {
        assert.equal(antecedent[2], antecedentCode, `${id} antecedent code`);
      }
    } else {
      assert.ok(INTERNAL_CODES.includes(antecedentId), `${id} classification antecedent`);
    }

    if (family === "DESCRIPTOR_CLOSE") {
      // DC5: the observed code is the antecedent's own and primaryCode is null.
      assert.equal(consequent[9], "null", `${id} DC5 primaryCode must be null`);
    }
    if (family === "F1" || family === "F2") {
      // primaryCode-gated families: the consequent must be an allowlisted carrier.
      assert.ok(PRIMARY_CODE_ALLOWLIST.includes(consequent[2]), `${id} consequent ${consequent[2]} cannot carry primaryCode`);
    }
    if (operation) assert.equal(consequent[1], operation, `${id} operation`);
  });
}

// ---------------------------------------------------------------------------
// 9. Corrective regression tests (independent review round 1)
// ---------------------------------------------------------------------------

// (1) Storage layout
test("regression: the accepted storage leaves are genesis-staging and genesis-profiles", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const shared = path.join(dir, "philcore-recovery-enrollment");
    assert.ok(fs.existsSync(path.join(shared, "genesis-staging")), "genesis-staging must exist");
    assert.ok(fs.existsSync(path.join(shared, "genesis-profiles")), "genesis-profiles must exist");
    assert.ok(!fs.existsSync(path.join(shared, "ceremony-staging")), "ceremony-staging must never be created");
    assert.deepEqual(fs.readdirSync(shared).sort(), ["genesis-profiles", "genesis-staging"]);
    instance.close();
  });
});

test("regression: the journal filename grammar is unchanged", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const record = instance.createJournal(validIntent()).journal;
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const journals = fs.readdirSync(staging).filter((n) => /^ceremony_[0-9a-f]{64}\.v1\.json$/u.test(n));
    assert.equal(journals.length, 1);
    assert.equal(journals[0], `ceremony_${String(record.intentId).replace(/^0x/u, "")}.v1.json`);
  });
});

// (2) Public API
test("regression: stageRole takes exactly (role, roleInput)", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const prepared = establishRecordedCredential(instance, intent, 0);
    assert.equal(instance.stageRole.length, 2, "stageRole must declare two parameters");
    const staged = instance.stageRole(prepared.call.role, prepared.call.roleInput);
    assert.equal(staged.journal.manifest["0"] === null, false, "role 0 slot must be populated");
  });
});

test("regression: a wrapper object is not accepted in place of (role, roleInput)", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const prepared = establishRecordedCredential(instance, intent, 0);
    assert.throws(
      () => instance.stageRole({ role: prepared.call.role, roleInput: prepared.call.roleInput }),
      (error) => error.code === "ROLE_INVALID"
    );
  });
});

// (3) Clock / delegation precedence
test("regression: a malformed intent outranks the host clock error and is rethrown unchanged", () => {
  withRoot((dir) => {
    let armed = false;
    const marker = { hostile: true };
    const instance = createRecoveryGenesisStagingHost(
      baseDeps(dir, { nowFn: () => { if (armed) throw marker; return 1700000000; } })
    );
    instance.reconcileRestart();
    armed = true;
    // The pure module rejects the malformed intent before its own clock check,
    // so a genuine 5B-0.4 error outranks the substituted sentinel and is
    // rethrown as the exact same object rather than becoming HOST_INVALID_NOW.
    let captured = null;
    try { instance.createJournal({ intentVersion: "1" }); } catch (error) { captured = error; }
    assert.ok(captured, "an error was expected");
    assert.notEqual(captured.code, "HOST_INVALID_NOW", "the genuine pure error must win");
    assert.ok(!(captured instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError));
  });
});

let markerTraps = 0;
test("regression: a thrown nowFn marker is never read, enumerated, or coerced", () => {
  withRoot((dir) => {
    markerTraps = 0;
    const marker = new Proxy({}, {
      get() { markerTraps += 1; return undefined; },
      ownKeys() { markerTraps += 1; return []; },
      getOwnPropertyDescriptor() { markerTraps += 1; return undefined; },
      has() { markerTraps += 1; return false; }
    });
    let armed = false;
    const instance = createRecoveryGenesisStagingHost(
      baseDeps(dir, { nowFn: () => { if (armed) throw marker; return 1700000000; } })
    );
    instance.reconcileRestart();
    armed = true;
    assert.throws(
      () => instance.createJournal(validIntent()),
      (error) => error.code === "HOST_INVALID_NOW" && error.detail.phase === "CLOCK_SAMPLE"
    );
    assert.equal(markerTraps, 0, "the thrown marker must never be inspected");
  });
});

test("regression: a genuine non-INVALID_NOW pure error is rethrown as the same object", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    let captured = null;
    const realStage = pureJournal.stageGenesisRoleCandidate;
    const sentinel = new Error("genuine pure failure");
    sentinel.code = "ROLE_SEQUENCE_VIOLATION";
    try {
      pureJournal.stageGenesisRoleCandidate = () => { throw sentinel; };
      try { callStageRole(instance, intent, 0); } catch (error) { captured = error; }
    } finally {
      pureJournal.stageGenesisRoleCandidate = realStage;
    }
    assert.equal(captured, sentinel, "identity must be preserved, not wrapped");
  });
});

test("regression: an equal clock sample is accepted, only a strictly smaller one regresses", () => {
  withRoot((dir) => {
    let tick = 1700000000;
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn: () => tick }));
    instance.reconcileRestart();
    // Equality is accepted.
    const created = instance.createJournal(validIntent());
    assert.ok(created.journal);
  });
});

test("regression: the regression comparison runs only after delegation succeeds", () => {
  withRoot((dir) => {
    let tick = 1800000000;
    let pureCalls = 0;
    const realCreate = pureJournal.createGenesisStagingJournal;
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn: () => tick }));
    instance.reconcileRestart();
    tick = 1700000000;
    try {
      pureJournal.createGenesisStagingJournal = (...args) => { pureCalls += 1; return realCreate(...args); };
      assert.throws(
        () => instance.createJournal(validIntent()),
        (error) => error.code === "HOST_CLOCK_REGRESSION_DETECTED" && error.detail.phase === "CLOCK_TRACKING"
      );
    } finally {
      pureJournal.createGenesisStagingJournal = realCreate;
    }
    assert.equal(pureCalls, 1, "the pure call must have run before the regression check");
  });
});

// (4) Reconciliation state
test("regression: a failed expiry publication leaves the host unreconciled", () => {
  withRoot((dir) => {
    plantExpiredJournal(dir);
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const plan = { call: "renameSync", label: "temp", occurrence: 1, behave: () => { throw errno("EIO"); } };
    withFacade(dir, plan, (facade) => {
      facade.arm();
      assert.throws(() => instance.reconcileRestart(), (e) => e.detail.phase === "RENAME");
    });
    for (const invoke of [() => instance.status(), () => instance.createJournal(validIntent())]) {
      assert.throws(invoke, (error) => error.code === "HOST_RECONCILIATION_REQUIRED");
    }
  });
});

// (5) Stored-record validation
test("regression: a canonical but schema-invalid stored record is STORED_RECORD_INVALID", () => {
  withRoot((dir) => {
    const shared = path.join(dir, "philcore-recovery-enrollment");
    const staging = path.join(shared, "genesis-staging");
    fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
    fs.chmodSync(shared, 0o700);
    fs.chmodSync(staging, 0o700);
    // Well-formed, canonical JSON whose identifier matches the filename, but
    // which is not a valid 5B-0.4 stored record.
    const id = "ab".repeat(32);
    const body = { intentId: `0x${id}`, state: "STAGING" };
    fs.writeFileSync(path.join(staging, `ceremony_${id}.v1.json`), JSON.stringify(body), { mode: 0o600 });
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = instance.reconcileRestart();
    assert.equal(report.outcome, "QUARANTINED_CORRUPT");
    assert.equal(report.corruptionCode, "HOST_JOURNAL_STORED_RECORD_INVALID");
    assert.ok(INTERNAL_CODES.includes(report.corruptionCode));
  });
});

test("regression: internal classifications never surface as a thrown top-level code", () => {
  const thrown = new Set(SINGLE_ROWS.map((r) => r[2]));
  for (const code of INTERNAL_CODES) assert.ok(!thrown.has(code));
});

// (6) Serialization contract
test("regression: a hostile accessor is rejected without the getter ever being invoked", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    const outcome = withHostileSerialization(() => {
      try { instance.createJournal(intent); return null; } catch (error) { return error; }
    });
    assert.ok(outcome, "an error was expected");
    assert.equal(outcome.code, "HOST_SERIALIZATION_REJECTED");
    assert.equal(outcome.detail.phase, "SERIALIZE");
    assert.equal(serializationGetterInvocations, 0, "the accessor must never be invoked");
  });
});

test("regression: no temp file survives a serialization rejection", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    withHostileSerialization(() => {
      try { instance.createJournal(validIntent()); } catch { /* expected */ }
    });
    const temps = fs.readdirSync(staging).filter((n) => n.endsWith(".tmp"));
    assert.deepEqual(temps, [], "ownership was never acquired, so no temp may remain");
  });
});

// (7) Metadata contract
test("regression: every authoritative field mismatch fails the seven-field recheck", () => {
  const patches = [
    { dev: 424242 }, { ino: 424242 }, { isFile: false },
    { uid: 999999 }, { mode: 0o100644 }, { nlink: 2 }, { size: 999999 }
  ];
  for (const patch of patches) {
    withRoot((dir) => {
      plantStagingJournal(dir, 1000);
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      const plan = {
        call: "__none__", doctor: "fstatSync", label: "journal", occurrence: 2,
        doctorFn: doctored(patch)
      };
      withFacade(dir, plan, (facade) => {
        facade.arm();
        assert.throws(
          () => instance.reconcileRestart(),
          (error) =>
            error.code === "HOST_JOURNAL_DESCRIPTOR_INVALID" &&
            error.detail.phase === "JOURNAL_METADATA_RECHECK",
          `field patch ${JSON.stringify(patch)} must fail the recheck`
        );
      });
    });
  }
});

test("regression: a directory failing type, owner, or mode is rejected", () => {
  const cases = [
    { patch: { isDirectory: false }, code: "HOST_STORAGE_DIRECTORY_INVALID" },
    { patch: { isDirectory: true, uid: 999999 }, code: "HOST_STORAGE_DIRECTORY_OWNER_INVALID" },
    { patch: { isDirectory: true, mode: 0o40755 }, code: "HOST_STORAGE_DIRECTORY_MODE_INVALID" }
  ];
  for (const kase of cases) {
    withRoot((dir) => {
      const plan = {
        call: "__none__", doctor: "fstatSync", label: "corrupt", occurrence: 1,
        doctorFn: doctored(kase.patch)
      };
      withFacade(dir, plan, () => {
        assert.throws(
          () => createRecoveryGenesisStagingHost(baseDeps(dir)),
          (error) => error.code === kase.code && error.detail.phase === "DIRECTORY_VALIDATE"
        );
      });
    });
  }
});

// (8) Lock cleanup ownership
test("regression: a foreign lock replacement is never unlinked and stays byte-identical", () => {
  withRoot((dir) => {
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const lockPath = path.join(staging, ".staging.lock");
    const plan = [
      { call: "fsyncSync", label: "lock", occurrence: 1, behave: () => { throw errno("EIO"); } },
      {
        call: "lstatSync", label: "lock", occurrence: 1,
        behave: (_x, args, { real }) => {
          // A foreign process replaces the lock inode before cleanup probes it.
          fs.rmSync(lockPath, { force: true });
          fs.writeFileSync(lockPath, "FOREIGN", { mode: 0o600 });
          return real.lstatSync.apply(fs, args);
        }
      }
    ];
    withFacade(dir, plan, () => {
      assert.throws(() => createRecoveryGenesisStagingHost(baseDeps(dir)), (e) => Boolean(e.code));
    });
    assert.ok(fs.existsSync(lockPath), "the foreign lock must not be unlinked");
    assert.equal(fs.readFileSync(lockPath, "utf8"), "FOREIGN", "it must be byte-identical");
  });
});

test("regression: a classification failure still owns and removes its own lock", () => {
  withRoot((dir) => {
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const lockPath = path.join(staging, ".staging.lock");
    // The post-create fstat succeeds, so identity is established before the
    // classification predicate runs; the file this operation created under
    // O_EXCL is therefore provably owned and is cleaned up.
    const plan = {
      call: "__none__", doctor: "fstatSync", label: "lock", occurrence: 1,
      doctorFn: doctored({ isFile: false })
    };
    withFacade(dir, plan, () => {
      assert.throws(
        () => createRecoveryGenesisStagingHost(baseDeps(dir)),
        (error) =>
          error.code === "HOST_LOCK_DESCRIPTOR_INVALID" &&
          error.detail.phase === "LOCK_POST_CREATE_VALIDATE"
      );
    });
    assert.ok(!fs.existsSync(lockPath), "the operation's own lock is removed");
  });
});

// Compound 1.56~1.47 — no established identity, so nothing may be unlinked.
test("regression: compound 1.56~1.47 reports the probe outcome and never unlinks", () => {
  withRoot((dir) => {
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const lockPath = path.join(staging, ".staging.lock");
    let unlinks = 0;
    const plan = {
      call: "fstatSync", label: "lock", occurrence: 1,
      behave: () => { throw errno("EIO"); }
    };
    const realUnlink = fs.unlinkSync;
    fs.unlinkSync = function (...args) { unlinks += 1; return realUnlink.apply(fs, args); };
    try {
      withFacade(dir, plan, () => {
        assert.throws(
          () => createRecoveryGenesisStagingHost(baseDeps(dir)),
          (error) =>
            error.code === "HOST_LOCK_ACQUISITION_INDETERMINATE" &&
            error.detail.phase === "LOCK_CLEANUP_PROBE" &&
            error.detail.commitState === "INDETERMINATE" &&
            error.detail.primaryCode === "HOST_LOCK_DESCRIPTOR_INVALID"
        );
      });
    } finally {
      fs.unlinkSync = realUnlink;
    }
    assert.equal(unlinks, 0, "no unlink may occur without proven ownership");
    assert.ok(fs.existsSync(lockPath), "the occupant is left in place");
    // Registry insertion poisons the root for this process.
    assert.throws(
      () => createRecoveryGenesisStagingHost(baseDeps(dir)),
      (error) => error.code === "HOST_PROCESS_POISONED"
    );
  });
});

// Compound 1.56~1.55 — a foreign replacement, then an independently failing probe.
test("regression: compound 1.56~1.55 reports the probe outcome and preserves the foreign occupant", () => {
  withRoot((dir) => {
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const lockPath = path.join(staging, ".staging.lock");
    let unlinks = 0;
    const plans = [
      {
        call: "__none__", doctor: "lstatSync", label: "lock", occurrence: 1,
        doctorFn: doctored({ ino: 987654 })
      },
      {
        call: "lstatSync", label: "lock", occurrence: 2,
        behave: () => { throw errno("EIO"); }
      }
    ];
    const realUnlink = fs.unlinkSync;
    fs.unlinkSync = function (...args) { unlinks += 1; return realUnlink.apply(fs, args); };
    try {
      withFacade(dir, plans, () => {
        assert.throws(
          () => createRecoveryGenesisStagingHost(baseDeps(dir)),
          (error) =>
            error.code === "HOST_LOCK_ACQUISITION_INDETERMINATE" &&
            error.detail.phase === "LOCK_CLEANUP_PROBE" &&
            error.detail.primaryCode === "HOST_LOCK_LOST_OR_REPLACED"
        );
      });
    } finally {
      fs.unlinkSync = realUnlink;
    }
    assert.equal(unlinks, 0, "a foreign occupant is never unlinked");
    assert.ok(fs.existsSync(lockPath), "the foreign occupant is preserved");
  });
});

test("regression: a confirmed foreign occupant reports 1.55 and reaches no later cleanup row", () => {
  withRoot((dir) => {
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const lockPath = path.join(staging, ".staging.lock");
    let unlinks = 0;
    const plan = {
      call: "__none__", doctor: "lstatSync", label: "lock", occurrence: "all",
      doctorFn: doctored({ ino: 987654 })
    };
    const realUnlink = fs.unlinkSync;
    fs.unlinkSync = function (...args) { unlinks += 1; return realUnlink.apply(fs, args); };
    try {
      withFacade(dir, plan, () => {
        assert.throws(
          () => createRecoveryGenesisStagingHost(baseDeps(dir)),
          (error) =>
            error.code === "HOST_LOCK_LOST_OR_REPLACED" &&
            error.detail.phase === "LOCK_IDENTITY"
        );
      });
    } finally {
      fs.unlinkSync = realUnlink;
    }
    assert.equal(unlinks, 0, "rows 1.57-1.61 must be unreachable from 1.55");
    assert.ok(fs.existsSync(lockPath));
  });
});

// (2') Size preflight
test("AT-A9: regression: an oversized journal is classified before any read or allocation", () => {
  withRoot((dir) => {
    const shared = path.join(dir, "philcore-recovery-enrollment");
    const staging = path.join(shared, "genesis-staging");
    fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
    fs.chmodSync(shared, 0o700);
    fs.chmodSync(staging, 0o700);
    const id = "ab".repeat(32);
    const journal = path.join(staging, `ceremony_${id}.v1.json`);
    // A sparse file far beyond the comparator: reading it would be the attack.
    const fd = fs.openSync(journal, "w", 0o600);
    fs.ftruncateSync(fd, 64 * 1024 * 1024);
    fs.closeSync(fd);

    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    let reads = 0;
    let maxAlloc = 0;
    const realRead = fs.readSync;
    const realAlloc = Buffer.allocUnsafe;
    fs.readSync = function (...args) { reads += 1; return realRead.apply(fs, args); };
    Buffer.allocUnsafe = function (size) { maxAlloc = Math.max(maxAlloc, size); return realAlloc(size); };
    let report;
    try {
      report = instance.reconcileRestart();
    } finally {
      fs.readSync = realRead;
      Buffer.allocUnsafe = realAlloc;
    }
    assert.equal(report.outcome, "QUARANTINED_CORRUPT");
    assert.equal(report.corruptionCode, "HOST_JOURNAL_FILE_OVERSIZED");
    assert.equal(reads, 0, "an oversized journal must never be read");
    assert.ok(maxAlloc <= 16384, `allocation must stay bounded, saw ${maxAlloc}`);
    // The quarantine outcome carries the third result key, present and null.
    assert.equal(report.journal, null);
    assert.equal("journal" in report, true);
    assert.deepEqual(Object.keys(report), [
      "outcome", "corruptionCode", "journal", "finalizedProfile",
      "credentialObligation", "credentialOutcome"
    ]);
  });
});

// (3') BOM and whitespace decode precedence
test("regression: a BOM-prefixed otherwise-valid record is UTF8_INVALID, not NONCANONICAL", () => {
  withRoot((dir) => {
    const record = plantStagingJournal(dir, 1000);
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    const name = `ceremony_${String(record.intentId).replace(/^0x/u, "")}.v1.json`;
    const body = JSON.stringify(record);
    fs.writeFileSync(
      path.join(staging, name),
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(body, "utf8")]),
      { mode: 0o600 }
    );
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = instance.reconcileRestart();
    assert.equal(report.corruptionCode, "HOST_JOURNAL_UTF8_INVALID");
  });
});

test("regression: leading and trailing whitespace are rejected at decode, before parse", () => {
  for (const wrap of [(b) => ` ${b}`, (b) => `${b}\n`, (b) => `\t${b} `]) {
    withRoot((dir) => {
      const record = plantStagingJournal(dir, 1000);
      const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
      const name = `ceremony_${String(record.intentId).replace(/^0x/u, "")}.v1.json`;
      fs.writeFileSync(path.join(staging, name), wrap(JSON.stringify(record)), { mode: 0o600 });
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      assert.equal(instance.reconcileRestart().corruptionCode, "HOST_JOURNAL_UTF8_INVALID");
    });
  }
});

// (9) Clock domain
test("regression: the clock domain is uint48, with exact boundaries", () => {
  const UINT48_MAX = 281474976710655;
  const accepted = [1, UINT48_MAX];
  const rejected = [0, -1, UINT48_MAX + 1, 1.5, Number.NaN];
  const build = (dir, valueRef) =>
    createRecoveryGenesisStagingHost(
      baseDeps(dir, { nowFn: () => (valueRef.armed ? valueRef.value : 1700000000) })
    );
  for (const value of accepted) {
    withRoot((dir) => {
      const ref = { armed: false, value };
      const instance = build(dir, ref);
      ref.armed = true;
      assert.doesNotThrow(() => instance.reconcileRestart(), `now=${value} must be accepted`);
    });
  }
  for (const value of rejected) {
    withRoot((dir) => {
      const ref = { armed: false, value };
      const instance = build(dir, ref);
      ref.armed = true;
      assert.throws(
        () => instance.reconcileRestart(),
        (error) => error.code === "HOST_INVALID_NOW" && error.detail.phase === "CLOCK_SAMPLE",
        `now=${value} must be rejected`
      );
    });
  }
});

// (10) No public poison surface
test("regression: the host keeps exactly eight public own keys through poisoning", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const before = Object.keys(instance).sort();
    assert.deepEqual(before, [...PUBLIC_METHODS].sort());
    const plan = { call: "fsyncSync", label: "staging", occurrence: 1, behave: () => { throw errno("EIO"); } };
    withFacade(dir, plan, (facade) => {
      facade.arm();
      try { instance.close(); } catch { /* poisons the root */ }
    });
    const after = Object.keys(instance).sort();
    assert.deepEqual(after, before, "poisoning must not add a public property");
    for (const forbidden of ["__poisoned", "poisoned", "_state", "__state"]) {
      assert.equal(Object.prototype.hasOwnProperty.call(instance, forbidden), false);
    }
    assert.throws(() => instance.status(), (error) => error.code === "HOST_PROCESS_POISONED");
    assert.deepEqual(Object.keys(instance).sort(), before);
  });
});

// ---------------------------------------------------------------------------
// 10. D15 / read-bound regression tests (independent review round 3)
// ---------------------------------------------------------------------------

// Captures the exact flags of every openSync, labelled by target.
function withOpenFlagCapture(dir, body) {
  const labelOf = makeLabeller(dir);
  const seen = [];
  const realOpen = fs.openSync;
  fs.openSync = function (target, flags, ...rest) {
    seen.push({ label: labelOf(target), flags });
    return realOpen.call(fs, target, flags, ...rest);
  };
  try { return body(seen); } finally { fs.openSync = realOpen; }
}

const O_NONBLOCK = fs.constants.O_NONBLOCK;
const O_NOFOLLOW = fs.constants.O_NOFOLLOW;
const O_DIRECTORY = fs.constants.O_DIRECTORY;

test("D15: every attacker-influenced regular-file read open sets O_NONBLOCK", () => {
  withRoot((dir) => {
    // Plant an existing lock so the lock probe runs, and a journal so the
    // reconciliation read and the initial CAS both run.
    const record = plantStagingJournal(dir, 1000);
    const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
    fs.writeFileSync(
      path.join(staging, ".staging.lock"),
      JSON.stringify({ pid: "999999", createdAtUnixSeconds: "1600000000" }),
      { mode: 0o600 }
    );
    withOpenFlagCapture(dir, (seen) => {
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      instance.reconcileRestart();
      callStageRole(instance, validIntent(), 0);
      void record;

      const readOpens = seen.filter(
        (o) => ["lock", "journal", "temp"].includes(o.label) && (o.flags & O_DIRECTORY) === 0
      );
      const readOnly = readOpens.filter((o) => (o.flags & fs.constants.O_CREAT) === 0);
      assert.ok(readOnly.length >= 4, `expected the read opens, saw ${readOnly.length}`);
      for (const open of readOnly) {
        assert.equal(
          (open.flags & O_NONBLOCK) !== 0,
          true,
          `read open of ${open.label} must set O_NONBLOCK (flags=${open.flags})`
        );
        assert.equal((open.flags & O_NOFOLLOW) !== 0, true, `${open.label} must set O_NOFOLLOW`);
      }
    });
  });
});

test("D15: directory opens do not set O_NONBLOCK and creation semantics are unchanged", () => {
  withRoot((dir) => {
    withOpenFlagCapture(dir, (seen) => {
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      instance.close();
      const dirOpens = seen.filter((o) => (o.flags & O_DIRECTORY) !== 0);
      assert.ok(dirOpens.length > 0, "directory opens are expected");
      for (const open of dirOpens) {
        assert.equal((open.flags & O_NONBLOCK) !== 0, false, "directory opens must not set O_NONBLOCK");
      }
      const creates = seen.filter((o) => (o.flags & fs.constants.O_CREAT) !== 0);
      for (const open of creates) {
        assert.equal((open.flags & fs.constants.O_EXCL) !== 0, true, "creation stays O_CREAT|O_EXCL");
      }
    });
  });
});

test("D15: a FIFO at the lock path is classified without blocking", () => {
  withRoot((dir) => {
    const shared = path.join(dir, "philcore-recovery-enrollment");
    const staging = path.join(shared, "genesis-staging");
    fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
    fs.chmodSync(shared, 0o700);
    fs.chmodSync(staging, 0o700);
    const lockPath = path.join(staging, ".staging.lock");
    const made = require("node:child_process").spawnSync("mkfifo", [lockPath]);
    if (made.status !== 0) return; // platform without mkfifo: nothing to prove here
    const started = Date.now();
    assert.throws(
      () => createRecoveryGenesisStagingHost(baseDeps(dir)),
      (error) => Boolean(error.code),
      "a FIFO occupant must reach the classification/error contract"
    );
    assert.ok(Date.now() - started < 5000, "the open must not block on the FIFO");
    assert.ok(fs.existsSync(lockPath), "the foreign FIFO is left untouched");
  });
});

// The accepted mapping for an over-comparator declared size at the initial CAS
// is the existing bounded-read failure: HOST_FILESYSTEM_READ_FAILED /
// CAS_INITIAL_READ (rows 4.12 / 5.12 / 7.18). No new phase, code, or row.
function oversizedInitialCas(dir, drive, prepare) {
  let record = plantStagingJournal(dir, 1000);
  const staging = path.join(dir, "philcore-recovery-enrollment", "genesis-staging");
  const journal = path.join(staging, `ceremony_${String(record.intentId).replace(/^0x/u, "")}.v1.json`);
  const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
  instance.reconcileRestart();
  // Some operations need the retained record driven terminal first.
  if (prepare) record = prepare(instance) || record;
  // A same-UID replacement makes the final journal enormous after
  // reconciliation but before the next operation's initial CAS.
  const fd = fs.openSync(journal, "r+", 0o600);
  fs.ftruncateSync(fd, 64 * 1024 * 1024);
  fs.closeSync(fd);

  let reads = 0;
  let maxAlloc = 0;
  const realOpen = fs.openSync;
  const realRead = fs.readSync;
  const realAlloc = Buffer.allocUnsafe;
  const journalFds = new Set();
  fs.openSync = function (...args) {
    const opened = realOpen.apply(fs, args);
    if (typeof args[0] === "string" && path.resolve(args[0]) === path.resolve(journal)) {
      journalFds.add(opened);
    }
    return opened;
  };
  fs.readSync = function (...args) {
    if (journalFds.has(args[0])) reads += 1;
    return realRead.apply(fs, args);
  };
  Buffer.allocUnsafe = function (size) { maxAlloc = Math.max(maxAlloc, size); return realAlloc(size); };
  let captured = null;
  try {
    drive(instance, record);
  } catch (error) {
    captured = error;
  } finally {
    fs.openSync = realOpen;
    fs.readSync = realRead;
    Buffer.allocUnsafe = realAlloc;
  }
  return { captured, reads, maxAlloc };
}

let oversizedStagePrepared = null;
for (const kase of [
  {
    name: "stageRole",
    prepare: (instance) => {
      oversizedStagePrepared = establishRecordedCredential(instance, validIntent(), 0);
    },
    drive: (instance) => instance.stageRole(
      oversizedStagePrepared.call.role,
      oversizedStagePrepared.call.roleInput
    )
  },
  { name: "cancel", drive: (instance) => instance.cancel() },
  {
    name: "acknowledgeTerminal",
    prepare: (instance) => instance.cancel().journal,
    drive: (instance, record) =>
      instance.acknowledgeTerminal({ intentId: record.intentId, integrityChecksum: record.integrityChecksum })
  }
]) {
  test(`D15: ${kase.name} bounds the initial CAS read of an oversized replacement`, () => {
    withRoot((dir) => {
      const outcome = oversizedInitialCas(dir, kase.drive, kase.prepare);
      assert.ok(outcome.captured, "an error was expected");
      assert.ok(
        outcome.captured instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError,
        `expected a host error, got ${outcome.captured && outcome.captured.message}`
      );
      assert.equal(outcome.captured.code, "HOST_FILESYSTEM_READ_FAILED");
      assert.equal(outcome.captured.detail.phase, "CAS_INITIAL_READ");
      assert.equal(outcome.captured.detail.subject, "JOURNAL_FILE");
      assert.equal(outcome.captured.detail.commitState, "NOT_COMMITTED");
      assert.equal(outcome.reads, 0, "an over-comparator journal must never be read");
      assert.ok(outcome.maxAlloc <= 16384, `allocation must stay bounded, saw ${outcome.maxAlloc}`);
    });
  });
}

test("D15: the seven revalidated fields are dev, ino, type, uid, mode, nlink, size", () => {
  // "type" is the accepted field, not gid: a regular file replaced by another
  // object type must be caught even when gid is identical.
  for (const patch of [
    { dev: 424242 }, { ino: 424242 }, { isFile: false },
    { uid: 999999 }, { mode: 0o100644 }, { nlink: 2 }, { size: 999999 }
  ]) {
    withRoot((dir) => {
      plantStagingJournal(dir, 1000);
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      const plan = {
        call: "__none__", doctor: "fstatSync", label: "journal", occurrence: 2,
        doctorFn: doctored(patch)
      };
      withFacade(dir, plan, (facade) => {
        facade.arm();
        assert.throws(
          () => instance.reconcileRestart(),
          (error) =>
            error.code === "HOST_JOURNAL_DESCRIPTOR_INVALID" &&
            error.detail.phase === "JOURNAL_METADATA_RECHECK",
          `field patch ${JSON.stringify(patch)} must fail the recheck`
        );
      });
    });
  }
});

// ---------------------------------------------------------------------------
// 10. Gate A acceptance contracts
//
// The reconciliation report gained a third own key, `journal`, and the expiry
// transition is now delegated to the pure 5B-0.4 module instead of being
// hand-built, so the published record advances updatedAtUnixSeconds and
// recomputes integrityChecksum. Every assertion below is reached through the
// seven public host methods or through a lawful wrapper on a public export of
// the pure module; no module-private state is read and no source is scraped.
// ---------------------------------------------------------------------------

// The staging clock used by baseDeps, and an expiry above it that still admits
// the suite's ceremony expiries (1899999999) so all three roles can be staged.
const GATE_A_STAGING_NOW = 1700000000;
const GATE_A_EXPIRY = 1900000000;

// Creates the owned staging layout without planting a journal.
function gateAStagingDir(dir) {
  const shared = path.join(dir, "philcore-recovery-enrollment");
  const staging = path.join(shared, "genesis-staging");
  fs.mkdirSync(path.join(staging, ".corrupt-quarantine"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(staging, ".stale-lock-quarantine"), { recursive: true, mode: 0o700 });
  fs.chmodSync(shared, 0o700);
  fs.chmodSync(staging, 0o700);
  return staging;
}
function gateAJournalName(record) {
  return `ceremony_${String(record.intentId).replace(/^0x/u, "")}.v1.json`;
}
// Deep-freeze assertions over a three-slot-populated reported record. The
// writes below run under this file's "use strict", so each must throw.
function gateAAssertDeeplyFrozen(journal) {
  assert.ok(Object.isFrozen(journal));
  assert.ok(Object.isFrozen(journal.manifest));
  for (const key of ["0", "1", "2"]) {
    const entry = journal.manifest[key];
    assert.notEqual(entry, null, `slot ${key} must be populated`);
    assert.ok(Object.isFrozen(entry));
    assert.ok(Object.isFrozen(entry.descriptor));
    assert.ok(Object.isFrozen(entry.independence));
  }
  assert.throws(() => { journal.state = "CANCELLED"; }, TypeError);
  assert.throws(() => { journal.manifest["0"].role = "9"; }, TypeError);
  assert.throws(() => { journal.manifest["0"].descriptor.role = "9"; }, TypeError);
}

// Builds a three-slot-populated STAGING journal through the public API only.
function gateAPopulate(dir, roles) {
  const intent = validIntent();
  const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
  instance.reconcileRestart();
  instance.createJournal(intent);
  for (const role of roles) callStageRole(instance, intent, role);
  instance.close();
  return intent;
}

test("AT-A1: EXPIRED_ON_RECOVERY reports the published record and its exact byte budget", () => {
  withRoot((dir) => {
    const planted = plantExpiredJournal(dir);
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const result = instance.reconcileRestart();

    assert.equal(result.outcome, "EXPIRED_ON_RECOVERY");
    assert.equal(result.corruptionCode, null);
    assert.deepEqual(Object.keys(result), [
      "outcome", "corruptionCode", "journal", "finalizedProfile",
      "credentialObligation", "credentialOutcome"
    ]);
    assert.equal(result.credentialOutcome, "ABSENT");
    assert.equal(result.credentialObligation, null);

    const journal = result.journal;
    assert.ok(journal !== null && typeof journal === "object", "the record must be reported");
    assert.equal(journal.state, "EXPIRED");
    assert.equal(journal.endReason, "EXPIRED");
    assert.equal(journal.updatedAtUnixSeconds, String(GATE_A_STAGING_NOW));
    assert.ok(BigInt(journal.updatedAtUnixSeconds) >= BigInt(journal.expiresAt));

    // The checksum is recomputed over the record minus its own checksum field.
    const withoutChecksum = {};
    for (const key of Object.keys(journal)) {
      if (key !== "integrityChecksum") withoutChecksum[key] = journal[key];
    }
    assert.equal(
      journal.integrityChecksum,
      pureJournal.computeGenesisStagingJournalChecksum(withoutChecksum)
    );

    // Class 1: result.journal does not exist before this change.
    const measured = Buffer.byteLength(JSON.stringify(journal), "utf8");
    assert.ok(measured <= 7540, `expired record must stay within budget, saw ${measured}`);
    assert.ok(measured < 16384, `expired record must stay under the comparator, saw ${measured}`);
    const journalPath = path.join(gateAStagingDir(dir), gateAJournalName(planted));
    assert.equal(measured, fs.statSync(journalPath).size);
    instance.close();
  });
});

test("AT-A2: the published expiry survives a restart as ACTIVE, never quarantined", () => {
  withRoot((dir) => {
    const planted = plantExpiredJournal(dir);
    const first = createRecoveryGenesisStagingHost(baseDeps(dir));
    assert.equal(first.reconcileRestart().outcome, "EXPIRED_ON_RECOVERY");
    first.close();

    const second = createRecoveryGenesisStagingHost(baseDeps(dir));
    const result = second.reconcileRestart();
    assert.notEqual(result.outcome, "QUARANTINED_CORRUPT");
    assert.equal(result.outcome, "ACTIVE");
    assert.equal(result.corruptionCode, null);
    assert.equal(result.journal.state, "EXPIRED");
    assert.equal(result.journal.intentId, planted.intentId);

    const quarantine = path.join(gateAStagingDir(dir), ".corrupt-quarantine");
    assert.deepEqual(fs.readdirSync(quarantine), [], "nothing may be quarantined");
    second.close();
  });
});

test("AT-A3: the restarted host acknowledges the expired record and removes the file", () => {
  withRoot((dir) => {
    const planted = plantExpiredJournal(dir);
    const first = createRecoveryGenesisStagingHost(baseDeps(dir));
    first.reconcileRestart();
    first.close();

    const second = createRecoveryGenesisStagingHost(baseDeps(dir));
    const result = second.reconcileRestart();
    assert.equal(result.outcome, "ACTIVE");
    const journalPath = path.join(gateAStagingDir(dir), gateAJournalName(planted));
    assert.equal(fs.existsSync(journalPath), true);

    second.acknowledgeTerminal({
      intentId: result.journal.intentId,
      integrityChecksum: result.journal.integrityChecksum
    });
    assert.equal(fs.existsSync(journalPath), false, "acknowledgment must remove the journal");
    second.close();
  });
});

test("AT-A4: the published record validates independently, unlike the hand-built one", () => {
  withRoot((dir) => {
    const planted = plantExpiredJournal(dir);
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const journalPath = path.join(gateAStagingDir(dir), gateAJournalName(planted));

    // (1) The bytes actually on disk are accepted by the 5B-0.4 validator.
    const storedText = fs.readFileSync(journalPath, "utf8");
    pureJournal.validateGenesisStagingJournalRecord(JSON.parse(storedText));
    instance.close();

    // (2) Negative control: a record built the way the landed code built it
    // fails the timestamp rule first -- not the checksum rule.
    const landed = Object.assign({}, planted, { state: "EXPIRED", endReason: "EXPIRED" });
    assert.throws(
      () => pureJournal.validateGenesisStagingJournalRecord(landed),
      (error) => {
        assert.equal(error.code, "JOURNAL_STATE_TIMESTAMP_MISMATCH");
        assert.notEqual(error.code, "JOURNAL_CHECKSUM_MISMATCH");
        return true;
      }
    );

    // (3) The same bytes independently fail checksum integrity, shown by direct
    // recomputation, even though the timestamp rule is the only code surfaced.
    const landedWithoutChecksum = {};
    for (const key of Object.keys(landed)) {
      if (key !== "integrityChecksum") landedWithoutChecksum[key] = landed[key];
    }
    assert.notEqual(
      pureJournal.computeGenesisStagingJournalChecksum(landedWithoutChecksum),
      landed.integrityChecksum
    );

    // (4) The host maps that same throw to the internal classification and to
    // the quarantine outcome.
    withRoot((other) => {
      const staging = gateAStagingDir(other);
      fs.writeFileSync(path.join(staging, gateAJournalName(planted)), JSON.stringify(landed), { mode: 0o600 });
      const host2 = createRecoveryGenesisStagingHost(baseDeps(other));
      const report = host2.reconcileRestart();
      assert.equal(report.outcome, "QUARANTINED_CORRUPT");
      assert.equal(report.corruptionCode, "HOST_JOURNAL_STORED_RECORD_INVALID");
      host2.close();
    });
  });
});

test("AT-A5: reported records are deeply frozen and identical by reference", () => {
  // --- ACTIVE fixture: three populated slots ------------------------------
  withRoot((dir) => {
    gateAPopulate(dir, [0, 1, 2]);
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const active = instance.reconcileRestart();
    assert.equal(active.outcome, "ACTIVE");
    gateAAssertDeeplyFrozen(active.journal);
    instance.close();
  });

  // --- EXPIRED fixture: three populated slots, plus (b) and its value-level
  // corroboration --------------------------------------------------------
  withRoot((dir) => {
    gateAPopulate(dir, [0, 1, 2]);
    const instance = createRecoveryGenesisStagingHost(
      baseDeps(dir, { nowFn: () => GATE_A_EXPIRY })
    );
    const realExpire = pureJournal.expireGenesisStagingJournalIfNeeded;
    let returned = null;
    let expired;
    try {
      pureJournal.expireGenesisStagingJournalIfNeeded = function (...args) {
        returned = realExpire(...args);
        return returned;
      };
      expired = instance.reconcileRestart();
    } finally {
      pureJournal.expireGenesisStagingJournalIfNeeded = realExpire;
    }
    assert.equal(pureJournal.expireGenesisStagingJournalIfNeeded, realExpire);
    assert.equal(expired.outcome, "EXPIRED_ON_RECOVERY");
    gateAAssertDeeplyFrozen(expired.journal);
    // (b) the reported record is the transition's own return value.
    assert.ok(returned !== null, "the transition must have run");
    assert.equal(expired.journal === returned, true, "journal must be returned by reference");

    // Value-level corroboration through a public method: the identity fields of
    // that very record match what the host durably retained.
    const journalPath = path.join(gateAStagingDir(dir), gateAJournalName(expired.journal));
    assert.equal(fs.existsSync(journalPath), true);
    instance.acknowledgeTerminal({
      intentId: expired.journal.intentId,
      integrityChecksum: expired.journal.integrityChecksum
    });
    assert.equal(fs.existsSync(journalPath), false);
    instance.close();
  });

  // --- (a) ACTIVE-path reference identity, via stageGenesisRoleCandidate
  // argument 0. A companion fixture staged to two roles leaves slot 2 free, so
  // the wrapped call reaches the pure module normally. -------------------
  withRoot((dir) => {
    const intent = gateAPopulate(dir, [0, 1]);
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const active = instance.reconcileRestart();
    assert.equal(active.outcome, "ACTIVE");

    const realStage = pureJournal.stageGenesisRoleCandidate;
    let capturedArg0;
    let captured = false;
    try {
      pureJournal.stageGenesisRoleCandidate = function (...args) {
        if (!captured) {
          capturedArg0 = args[0];
          captured = true;
        }
        return realStage(...args);
      };
      callStageRole(instance, intent, 2);
    } finally {
      pureJournal.stageGenesisRoleCandidate = realStage;
    }
    assert.equal(pureJournal.stageGenesisRoleCandidate, realStage);
    assert.equal(captured, true, "the wrapper must have captured argument 0");
    assert.equal(capturedArg0 === active.journal, true, "retained record must be the reported one");
    instance.close();
  });
});

test("AT-A6: the reported record has the exact serializer key shape at all five levels", () => {
  withRoot((dir) => {
    const intent = validIntent();
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    instance.createJournal(intent);
    let record;
    for (const role of [0, 1, 2]) record = callStageRole(instance, intent, role).journal;

    assert.deepEqual(Object.keys(record), [
      "schemaVersion", "formatProvenance", "intentVersion", "intentId", "chainId",
      "entryPoint", "factoryBinding", "confirmationTarget", "verifier",
      "verifierRuntimeCodeHash", "accountCreationBytecodeHash", "accountVersionId",
      "securityModelId", "recoveryDomainId", "ownerCommitment",
      "identityBindingCommitment", "initialValidator", "validatorVerifierKind",
      "validatorKeyIdBinding", "validatorCommitment", "validatorEpoch", "recoveryEpoch",
      "recoveryDelaySeconds", "recoveryExpirySeconds", "userSalt", "expiresAt",
      "genesisDeploymentIntentHash", "state", "createdAtUnixSeconds",
      "updatedAtUnixSeconds", "manifest", "endReason", "integrityChecksum"
    ]);
    assert.deepEqual(Object.keys(record.manifest), ["0", "1", "2"]);
    assert.ok(Object.isFrozen(record));
    assert.ok(Object.isFrozen(record.manifest));
    for (const key of ["0", "1", "2"]) {
      const entry = record.manifest[key];
      assert.notEqual(entry, null, `slot ${key} must be populated`);
      assert.deepEqual(Object.keys(entry), [
        "role", "ceremonyId", "ceremonyExpiresAtUnixSeconds",
        "genesisEnrollmentCeremonyHash", "descriptor", "independence", "signer",
        "factorCommitment", "stagedAtUnixSeconds"
      ]);
      assert.deepEqual(Object.keys(entry.descriptor), [
        "descriptorVersion", "accountVersionId", "securityModelId", "recoveryDomainId",
        "role", "verifierKind", "publicVerificationMaterialHash", "credentialIdHash",
        "rpIdHash", "originPolicyHash", "independenceBindingHash",
        "userVerificationPolicy", "backupPolicy", "authenticatorAttachmentPolicy",
        "attestationPolicy", "credentialGeneration"
      ]);
      assert.deepEqual(Object.keys(entry.independence), [
        "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
        "independenceAssurance", "credentialIdHash", "enrollmentCeremonyHash",
        "attestationEvidenceHash", "custodyDomainCommitment", "credentialGeneration"
      ]);
      assert.ok(Object.isFrozen(entry));
      assert.ok(Object.isFrozen(entry.descriptor));
      assert.ok(Object.isFrozen(entry.independence));
    }
    instance.close();
  });
});

test("AT-A7: journal is present and null, never absent, on the recordless outcomes", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const result = instance.reconcileRestart();
    assert.equal(result.outcome, "NOTHING_TO_RECONCILE");
    assert.equal("journal" in result, true);
    assert.equal(result.journal, null);
    instance.close();
  });
  withRoot((dir) => {
    const staging = gateAStagingDir(dir);
    fs.writeFileSync(path.join(staging, `ceremony_${"ab".repeat(32)}.v1.json`), "not-json", { mode: 0o600 });
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const result = instance.reconcileRestart();
    assert.equal(result.outcome, "QUARANTINED_CORRUPT");
    assert.equal("journal" in result, true);
    assert.equal(result.journal, null);
    instance.close();
  });
});

test("AT-A10: classification precedence is observable through the public result alone", () => {
  const otherName = `ceremony_${"cd".repeat(32)}.v1.json`;
  const classify = (write) =>
    withRoot((dir) => {
      write(gateAStagingDir(dir));
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      const result = instance.reconcileRestart();
      instance.close();
      assert.equal(result.outcome, "QUARANTINED_CORRUPT");
      return result.corruptionCode;
    });
  const canonicalRecord = () => pureJournal.createGenesisStagingJournal(validIntent(), 1000);
  // A single insignificant space parses identically but is not canonical.
  const nonCanonical = (record) => JSON.stringify(record).replace(/^\{/u, "{ ");

  // An empty file is also a filename mismatch; the size preflight wins.
  assert.equal(
    classify((s) => fs.writeFileSync(path.join(s, otherName), Buffer.alloc(0), { mode: 0o600 })),
    "HOST_JOURNAL_EMPTY"
  );
  // A BOM over unparsable bytes: the decode stage wins over the parse stage.
  assert.equal(
    classify((s) =>
      fs.writeFileSync(
        path.join(s, otherName),
        Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("not-json", "utf8")]),
        { mode: 0o600 }
      )
    ),
    "HOST_JOURNAL_UTF8_INVALID"
  );
  // Unparsable bytes under a mismatched name: the parse stage wins.
  assert.equal(
    classify((s) => fs.writeFileSync(path.join(s, otherName), "not-json", { mode: 0o600 })),
    "HOST_JOURNAL_JSON_INVALID"
  );
  // Canonical, name-matching, well-formed JSON that is not a valid record.
  assert.equal(
    classify((s) => {
      const id = "ab".repeat(32);
      fs.writeFileSync(
        path.join(s, `ceremony_${id}.v1.json`),
        JSON.stringify({ intentId: `0x${id}`, state: "STAGING" }),
        { mode: 0o600 }
      );
    }),
    "HOST_JOURNAL_STORED_RECORD_INVALID"
  );
  // A valid record whose encoding is not canonical, under its own name.
  assert.equal(
    classify((s) => {
      const record = canonicalRecord();
      fs.writeFileSync(path.join(s, gateAJournalName(record)), nonCanonical(record), { mode: 0o600 });
    }),
    "HOST_JOURNAL_NONCANONICAL"
  );
  // Non-canonical and mismatched: canonical comparison wins over the filename.
  assert.equal(
    classify((s) => fs.writeFileSync(path.join(s, otherName), nonCanonical(canonicalRecord()), { mode: 0o600 })),
    "HOST_JOURNAL_NONCANONICAL"
  );
  // Canonical and valid, but stored under the wrong name.
  assert.equal(
    classify((s) => fs.writeFileSync(path.join(s, otherName), JSON.stringify(canonicalRecord()), { mode: 0o600 })),
    "HOST_JOURNAL_FILENAME_ID_MISMATCH"
  );
});

test("AT-A12: reconciliation samples the clock exactly once on every outcome", () => {
  const paths = [
    ["NOTHING_TO_RECONCILE", () => {}],
    ["QUARANTINED_CORRUPT", (dir) => {
      fs.writeFileSync(path.join(gateAStagingDir(dir), `ceremony_${"ab".repeat(32)}.v1.json`), "not-json", { mode: 0o600 });
    }],
    ["EXPIRED_ON_RECOVERY", (dir) => { plantExpiredJournal(dir); }],
    ["ACTIVE", (dir) => { plantStagingJournal(dir, 1000); }]
  ];
  for (const [outcome, prepare] of paths) {
    withRoot((dir) => {
      prepare(dir);
      let calls = 0;
      const nowFn = () => { calls += 1; return GATE_A_STAGING_NOW; };
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn }));
      calls = 0; // construction's own sample is not under test
      const result = instance.reconcileRestart();
      assert.equal(result.outcome, outcome);
      assert.equal(calls, 1, `${outcome} must sample the clock exactly once`);
      instance.close();
    });
  }
});

test("AT-A14: the expiry path writes a journal file inside the mechanical budget", () => {
  withRoot((dir) => {
    const planted = plantExpiredJournal(dir);
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const result = instance.reconcileRestart();
    assert.equal(result.outcome, "EXPIRED_ON_RECOVERY");
    const journalPath = path.join(gateAStagingDir(dir), gateAJournalName(planted));
    const size = fs.statSync(journalPath).size;
    assert.equal(size, fs.readFileSync(journalPath).length, "stat and read must agree");
    assert.ok(size <= 7540, `published journal must stay within budget, saw ${size}`);
    assert.ok(size < 16384, `published journal must stay under the comparator, saw ${size}`);
    instance.close();
  });
});

// ---------------------------------------------------------------------------
// 11. Genesis profile finalization — isolated contracts outside the landed
// single/compound corpus (Architecture R1 + Amendments 1–4)
// ---------------------------------------------------------------------------
test("FP-01: the host closed surface includes all 19 finalized-profile codes", () => {
  const codes = PHILCORE_V2_CONSUMER_RECOVERY_GENESIS_STAGING_HOST_ERROR_CODE;
  for (const code of HOST_FINALIZED_PROFILE_CODES) {
    assert.equal(codes[code], code);
  }
  assert.equal(HOST_FINALIZED_PROFILE_CODES.length, 19);
});

test("FP-02: finalizeProfile publishes a durable final record and supersedes the journal", () => {
  withRoot((dir) => {
    const { instance, journal } = profileReadyHost(dir);
    const validation = expectedValidationForHost(journal);
    const result = instance.finalizeProfile(validation);
    assert.equal(result.outcome, "FINALIZED");
    assert.ok(result.finalizedProfile);
    assert.equal(result.journal.state, "SUPERSEDED");
    assert.ok(fs.existsSync(finalizedProfileFilePath(dir, result.finalizedProfile)));
    const onDisk = JSON.parse(
      fs.readFileSync(finalizedProfileFilePath(dir, result.finalizedProfile), "utf8")
    );
    assert.equal(onDisk.integrityChecksum, result.finalizedProfile.integrityChecksum);
    assert.equal(instance.status().state, "FINALIZED");
    instance.close();
  });
});

test("FP-03: finalizeProfile idempotent resume returns ALREADY_FINALIZED", () => {
  withRoot((dir) => {
    const { instance, journal } = profileReadyHost(dir);
    const validation = expectedValidationForHost(journal);
    instance.finalizeProfile(validation);
    instance.close();

    const second = createRecoveryGenesisStagingHost(baseDeps(dir));
    second.reconcileRestart();
    const resume = second.finalizeProfile(validation);
    assert.equal(resume.outcome, "ALREADY_FINALIZED");
    assert.ok(resume.finalizedProfile);
    second.close();
  });
});

test("FP-04: finalized-profile guards close createJournal, stageRole, and cancel", () => {
  withRoot((dir) => {
    const { instance, intent, journal } = profileReadyHost(dir);
    instance.finalizeProfile(expectedValidationForHost(journal));
    for (const run of [
      () => instance.createJournal(validIntent()),
      () => callStageRole(instance, intent, 0),
      () => instance.cancel()
    ]) {
      assert.throws(
        run,
        (error) => error.code === "HOST_FINALIZED_PROFILE_ALREADY_EXISTS"
      );
    }
    instance.close();
  });
});

test("FP-05: reconcileRestart always reports finalizedProfile, including NOTHING_TO_RECONCILE", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = instance.reconcileRestart();
    assert.deepEqual(
      Object.keys(report).sort(),
      ["corruptionCode", "credentialObligation", "credentialOutcome", "finalizedProfile", "journal", "outcome"]
    );
    assert.equal(report.finalizedProfile, null);
    instance.close();
  });
});

test("FP-06: reconcileRestart retains a valid on-disk final profile before journal matching", () => {
  withRoot((dir) => {
    const { instance, journal } = profileReadyHost(dir);
    const validation = expectedValidationForHost(journal);
    const finalized = pureFinalized.createGenesisFinalizedProfileRecord(
      journal,
      validation,
      HOST_PROFILE_NOW
    );
    fs.writeFileSync(
      finalizedProfileFilePath(dir, finalized),
      JSON.stringify(finalized),
      { mode: 0o600 }
    );
    instance.close();

    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.ok(["FINALIZED", "RECOVERED_FINALIZED_AND_SUPERSEDED"].includes(report.outcome));
    assert.ok(report.finalizedProfile);
    assert.equal(
      report.finalizedProfile.integrityChecksum,
      finalized.integrityChecksum
    );
    recovered.close();
  });
});

test("FP-07: corrupt journal beside a valid final profile poisons with HOST_FINALIZED_PROFILE_CONFLICT", () => {
  withRoot((dir) => {
    const { instance, journal } = profileReadyHost(dir);
    const validation = expectedValidationForHost(journal);
    const finalized = pureFinalized.createGenesisFinalizedProfileRecord(
      journal,
      validation,
      HOST_PROFILE_NOW
    );
    fs.writeFileSync(
      finalizedProfileFilePath(dir, finalized),
      JSON.stringify(finalized),
      { mode: 0o600 }
    );
    const journalPath = path.join(
      path.join(dir, "philcore-recovery-enrollment", "genesis-staging"),
      `ceremony_${String(journal.intentId).replace(/^0x/u, "")}.v1.json`
    );
    fs.writeFileSync(journalPath, "not-json", { mode: 0o600 });
    instance.close();

    const probe = createRecoveryGenesisStagingHost(baseDeps(dir));
    assert.throws(
      () => probe.reconcileRestart(),
      (error) =>
        error.code === "HOST_FINALIZED_PROFILE_CONFLICT" &&
        error.detail.commitState === "SUPERSESSION_INDETERMINATE"
    );
    probe.close();
  });
});

test("FP-08: unexpected finalized-directory entries poison on reconcileRestart", () => {
  withRoot((dir) => {
    const shared = path.join(dir, "philcore-recovery-enrollment");
    fs.mkdirSync(path.join(shared, "genesis-profiles"), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(shared, "genesis-profiles", "unexpected-entry"), "x", { mode: 0o600 });
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    assert.throws(
      () => instance.reconcileRestart(),
      (error) => error.code === "HOST_UNEXPECTED_FINALIZED_PROFILE_ENTRY"
    );
    instance.close();
  });
});

test("FP-09: surrounding whitespace classifies as HOST_FINALIZED_PROFILE_NONCANONICAL", () => {
  withRoot((dir) => {
    const { instance, journal } = profileReadyHost(dir);
    const validation = expectedValidationForHost(journal);
    const finalized = pureFinalized.createGenesisFinalizedProfileRecord(
      journal,
      validation,
      HOST_PROFILE_NOW
    );
    fs.writeFileSync(
      finalizedProfileFilePath(dir, finalized),
      `${JSON.stringify(finalized)} `,
      { mode: 0o600 }
    );
    instance.close();

    const probe = createRecoveryGenesisStagingHost(baseDeps(dir));
    assert.throws(
      () => probe.reconcileRestart(),
      (error) => error.code === "HOST_FINALIZED_PROFILE_NONCANONICAL"
    );
    probe.close();
  });
});

test("FP-10: invalid final with a valid SUPERSEDED journal uses INVALID_AFTER_SUPERSESSION", () => {
  withRoot((dir) => {
    const { instance, journal } = profileReadyHost(dir);
    const validation = expectedValidationForHost(journal);
    const result = instance.finalizeProfile(validation);
    assert.equal(result.outcome, "FINALIZED");
    const profilePath = finalizedProfileFilePath(dir, result.finalizedProfile);
    fs.writeFileSync(profilePath, "not-json", { mode: 0o600 });
    instance.close();

    const probe = createRecoveryGenesisStagingHost(baseDeps(dir));
    assert.throws(
      () => probe.reconcileRestart(),
      (error) =>
        error.code === "HOST_FINALIZED_PROFILE_INVALID_AFTER_SUPERSESSION" &&
        error.detail.commitState === "SUPERSESSION_INDETERMINATE"
    );
    probe.close();
  });
});

test("FP-11: resume rejects a tampered on-disk integrityChecksum via stored validation", () => {
  withRoot((dir) => {
    const { instance, journal } = profileReadyHost(dir);
    const validation = expectedValidationForHost(journal);
    const finalized = pureFinalized.createGenesisFinalizedProfileRecord(
      journal,
      validation,
      HOST_PROFILE_NOW
    );
    const profilePath = finalizedProfileFilePath(dir, finalized);
    fs.writeFileSync(profilePath, JSON.stringify(finalized), { mode: 0o600 });

    const onDisk = JSON.parse(fs.readFileSync(profilePath, "utf8"));
    onDisk.integrityChecksum = `0x${"00".repeat(32)}`;
    fs.writeFileSync(profilePath, JSON.stringify(onDisk), { mode: 0o600 });

    assert.throws(
      () => instance.finalizeProfile(validation),
      (error) =>
        error.code === "HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID" &&
        error.detail.commitState === "SUPERSESSION_INDETERMINATE"
    );
    assert.equal(
      captureHostFailure(() => instance.status()).code,
      "HOST_PROCESS_POISONED"
    );
    instance.close();
  });
});

test("FP-12: FINALIZED_DESTINATION_ABSENCE failure removes the owned temp", () => {
  withRoot((dir) => {
    const { instance, journal } = profileReadyHost(dir);
    const validation = expectedValidationForHost(journal);
    const hash = String(validation.genesisDeploymentIntentHash).replace(/^0x/u, "");
    const finalPath = path.join(profilesDir(dir), `profile_${hash}.v1.json`);
    const tempName = `.profile_${hash}.v1.json.tmp`;
    const plan = {
      call: "lstatSync",
      label: "fprofile",
      occurrence: 1,
      behave: (_x, args, { real }) => {
        if (args[0] === finalPath) {
          fs.writeFileSync(finalPath, "{}", { mode: 0o600 });
        }
        return real.lstatSync.apply(fs, args);
      }
    };
    withFacade(dir, plan, (facade) => {
      facade.arm();
      assert.throws(
        () => instance.finalizeProfile(validation),
        (error) =>
          error.code === "HOST_DISK_STATE_CHANGED" &&
          error.detail.phase === "FINALIZED_DESTINATION_ABSENCE"
      );
    });
    const temps = fs.readdirSync(profilesDir(dir)).filter((n) => n === tempName);
    assert.deepEqual(temps, [], "owned temp must be cleaned up after destination-absence failure");
    instance.close();
  });
});

function prepareProfileReadyDisk(dir) {
  const ready = profileReadyHost(dir);
  const validation = expectedValidationForHost(ready.journal);
  ready.instance.close();
  return { ...ready, validation };
}

function plantFinalizedProfile(dir, journal, validation, now) {
  const record = pureFinalized.createGenesisFinalizedProfileRecord(
    journal,
    validation,
    now === undefined ? HOST_PROFILE_NOW : now
  );
  fs.writeFileSync(
    finalizedProfileFilePath(dir, record),
    JSON.stringify(record),
    { mode: 0o600 }
  );
  return record;
}

test("FP-13: all 19 finalized-profile codes have exact commit state and host poison behavior", () => {
  const rows = [
    ["HOST_FINALIZED_PROFILE_ALREADY_EXISTS", "NOT_APPLICABLE", false, (dir) => {
      const { instance, journal } = profileReadyHost(dir);
      instance.finalizeProfile(expectedValidationForHost(journal));
      return { instance, error: captureHostFailure(() => instance.createJournal(validIntent())) };
    }],
    ["HOST_FINALIZED_PROFILE_SCAN_OVERFLOW", "NOT_APPLICABLE", false, (dir) => {
      const first = createRecoveryGenesisStagingHost(baseDeps(dir));
      first.close();
      for (let index = 0; index < 513; index += 1) {
        const hash = index.toString(16).padStart(64, "0");
        fs.writeFileSync(path.join(profilesDir(dir), `.profile_${hash}.v1.json.tmp`), "x", { mode: 0o600 });
      }
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_UNEXPECTED_FINALIZED_PROFILE_ENTRY", "NOT_APPLICABLE", true, (dir) => {
      const first = createRecoveryGenesisStagingHost(baseDeps(dir));
      first.close();
      fs.writeFileSync(path.join(profilesDir(dir), "unexpected"), "x", { mode: 0o600 });
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_MULTIPLE_FINALIZED_PROFILES_FOUND", "NOT_APPLICABLE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      const record = plantFinalizedProfile(dir, ready.journal, ready.validation);
      fs.writeFileSync(
        path.join(profilesDir(dir), `profile_${"ff".repeat(32)}.v1.json`),
        JSON.stringify(record),
        { mode: 0o600 }
      );
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_DESCRIPTOR_INVALID", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      const file = finalizedProfileFilePath(dir, {
        genesisDeploymentIntentHash: ready.journal.genesisDeploymentIntentHash
      });
      fs.writeFileSync(file, "{}", { mode: 0o644 });
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_FILE_OVERSIZED", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      fs.writeFileSync(
        finalizedProfileFilePath(dir, { genesisDeploymentIntentHash: ready.journal.genesisDeploymentIntentHash }),
        "x".repeat(32769),
        { mode: 0o600 }
      );
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_EMPTY", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      fs.writeFileSync(
        finalizedProfileFilePath(dir, { genesisDeploymentIntentHash: ready.journal.genesisDeploymentIntentHash }),
        "",
        { mode: 0o600 }
      );
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_UTF8_INVALID", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      fs.writeFileSync(
        finalizedProfileFilePath(dir, { genesisDeploymentIntentHash: ready.journal.genesisDeploymentIntentHash }),
        Buffer.from([0xff]),
        { mode: 0o600 }
      );
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_JSON_INVALID", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      fs.writeFileSync(
        finalizedProfileFilePath(dir, { genesisDeploymentIntentHash: ready.journal.genesisDeploymentIntentHash }),
        "{",
        { mode: 0o600 }
      );
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_NONCANONICAL", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      const record = pureFinalized.createGenesisFinalizedProfileRecord(ready.journal, ready.validation, HOST_PROFILE_NOW);
      fs.writeFileSync(finalizedProfileFilePath(dir, record), `${JSON.stringify(record)} `, { mode: 0o600 });
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_STORED_RECORD_INVALID", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      const record = pureFinalized.createGenesisFinalizedProfileRecord(ready.journal, ready.validation, HOST_PROFILE_NOW);
      const invalid = { ...record, schemaVersion: 2 };
      fs.writeFileSync(finalizedProfileFilePath(dir, record), JSON.stringify(invalid), { mode: 0o600 });
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_FILENAME_ID_MISMATCH", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      const record = pureFinalized.createGenesisFinalizedProfileRecord(ready.journal, ready.validation, HOST_PROFILE_NOW);
      fs.writeFileSync(
        path.join(profilesDir(dir), `profile_${"ee".repeat(32)}.v1.json`),
        JSON.stringify(record),
        { mode: 0o600 }
      );
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_CONFLICT", "PROFILE_COMMITTED", true, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      plantFinalizedProfile(dir, ready.journal, ready.validation);
      const cancelled = pureJournal.cancelGenesisStagingJournal(ready.journal, HOST_PROFILE_NOW + 1);
      fs.writeFileSync(
        path.join(gateAStagingDir(dir), gateAJournalName(ready.journal)),
        JSON.stringify(cancelled),
        { mode: 0o600 }
      );
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_MISSING_AFTER_SUPERSESSION", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const { instance: first, journal } = profileReadyHost(dir);
      const result = first.finalizeProfile(expectedValidationForHost(journal));
      fs.unlinkSync(finalizedProfileFilePath(dir, result.finalizedProfile));
      first.close();
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_INVALID_AFTER_SUPERSESSION", "SUPERSESSION_INDETERMINATE", true, (dir) => {
      const { instance: first, journal } = profileReadyHost(dir);
      const result = first.finalizeProfile(expectedValidationForHost(journal));
      fs.writeFileSync(finalizedProfileFilePath(dir, result.finalizedProfile), "{", { mode: 0o600 });
      first.close();
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }],
    ["HOST_FINALIZED_PROFILE_TEMP_BOUND_EXCEEDED", "NOT_COMMITTED", false, (dir) => {
      const { instance, journal } = profileReadyHost(dir);
      const validation = expectedValidationForHost(journal);
      const hash = String(validation.genesisDeploymentIntentHash).replace(/^0x/u, "");
      fs.writeFileSync(path.join(profilesDir(dir), `.profile_${hash}.v1.json.tmp`), "collision", { mode: 0o600 });
      return { instance, error: captureHostFailure(() => instance.finalizeProfile(validation)) };
    }],
    ["HOST_FINALIZED_PROFILE_TEMP_REMOVAL_INDETERMINATE", "INDETERMINATE", true, (dir) => {
      const { instance, journal } = profileReadyHost(dir);
      const validation = expectedValidationForHost(journal);
      const hash = String(validation.genesisDeploymentIntentHash).replace(/^0x/u, "");
      const finalPath = path.join(profilesDir(dir), `profile_${hash}.v1.json`);
      const plans = [{
        call: "lstatSync", label: "fprofile", occurrence: 1,
        behave: (_x, args, { real }) => {
          fs.writeFileSync(finalPath, "{}", { mode: 0o600 });
          return real.lstatSync.apply(fs, args);
        }
      }, {
        call: "unlinkSync", label: "ftemp", occurrence: 1,
        behave: () => { throw errno("EIO"); }
      }];
      const error = withFacade(dir, plans, (facade) => {
        facade.arm();
        return captureHostFailure(() => instance.finalizeProfile(validation));
      });
      return { instance, error };
    }],
    ["HOST_FINALIZED_PROFILE_DURABILITY_INDETERMINATE", "INDETERMINATE", true, (dir) => {
      const { instance, journal } = profileReadyHost(dir);
      const validation = expectedValidationForHost(journal);
      const plan = {
        call: "fsyncSync", label: "finalized", occurrence: 1,
        behave: () => { throw errno("EIO"); }
      };
      const error = withFacade(dir, plan, (facade) => {
        facade.arm();
        return captureHostFailure(() => instance.finalizeProfile(validation));
      });
      return { instance, error };
    }],
    ["HOST_FINALIZED_PROFILE_SUPERSESSION_CLOCK_REGRESSION", "PROFILE_COMMITTED", false, (dir) => {
      const ready = prepareProfileReadyDisk(dir);
      plantFinalizedProfile(dir, ready.journal, ready.validation);
      const sourceNow = Number(ready.journal.updatedAtUnixSeconds);
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn: () => sourceNow - 1 }));
      return { instance, error: captureHostFailure(() => instance.reconcileRestart()) };
    }]
  ];

  assert.equal(rows.length, 19);
  for (const [code, commitState, shouldPoison, run] of rows) {
    withRoot((dir) => {
      const { instance, error } = run(dir);
      assert.ok(error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError, code);
      assert.equal(error.code, code, code);
      assert.equal(error.detail.commitState, commitState, code);
      const statusError = captureHostFailure(() => instance.status());
      if (shouldPoison) {
        assert.equal(statusError && statusError.code, "HOST_PROCESS_POISONED", `${code} poisons`);
      } else {
        assert.notEqual(statusError && statusError.code, "HOST_PROCESS_POISONED", `${code} remains retryable`);
      }
      instance.close();
    });
  }
});

test("FP-14: finalized-directory construction exposes the exact six-row subject table", () => {
  const rows = [
    ["HOST_STORAGE_DIRECTORY_CREATE_FAILED", "DIRECTORY_CREATE", {
      call: "mkdirSync", label: "finalized", behave: () => { throw errno("EIO"); }
    }],
    ["HOST_STORAGE_DIRECTORY_INVALID", "DIRECTORY_OPEN", {
      call: "openSync", label: "finalized", behave: () => { throw errno("EIO"); }
    }],
    ["HOST_STORAGE_DIRECTORY_INVALID", "DIRECTORY_VALIDATE", {
      call: "fstatSync", label: "finalized", behave: () => { throw errno("EIO"); }
    }],
    ["HOST_STORAGE_DIRECTORY_OWNER_INVALID", "DIRECTORY_VALIDATE", {
      call: "never", label: "finalized", doctor: "fstatSync", occurrence: 1,
      doctorFn: (stat) => Object.assign(Object.create(stat), { uid: stat.uid + 1 })
    }],
    ["HOST_STORAGE_DIRECTORY_MODE_INVALID", "DIRECTORY_VALIDATE", {
      call: "never", label: "finalized", doctor: "fstatSync", occurrence: 1,
      doctorFn: (stat) => Object.assign(Object.create(stat), { mode: (stat.mode & ~0o777) | 0o755 })
    }],
    ["HOST_DURABILITY_WRITE_FAILED", "DIRECTORY_FSYNC", {
      call: "fsyncSync", label: "finalized", behave: () => { throw errno("EIO"); }
    }],
    ["HOST_DESCRIPTOR_CLOSE_FAILED", "DIRECTORY_CLOSE", {
      call: "closeSync", label: "finalized", behave: () => { throw errno("EIO"); }
    }]
  ];
  assert.equal(new Set(rows.map((row) => row[0])).size, 6);
  for (const [code, phase, plan] of rows) {
    withRoot((dir) => {
      const error = withFacade(dir, plan, () =>
        captureHostFailure(() => createRecoveryGenesisStagingHost(baseDeps(dir)))
      );
      assert.ok(error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError);
      assert.equal(error.code, code);
      assert.equal(error.detail.phase, phase);
      assert.equal(error.detail.subject, "FINALIZED_PROFILE_DIRECTORY");
      assert.equal(error.detail.commitState, "NOT_APPLICABLE");
    });
  }
});

test("FP-15: every FINALIZED_SOURCE_CAS phase is fault-reachable and cleans its temp", () => {
  const cases = [
    ["FINALIZED_SOURCE_CAS_INITIAL_OPEN", { call: "openSync", label: "journal", occurrence: 1, behave: () => { throw errno("EIO"); } }],
    ["FINALIZED_SOURCE_CAS_INITIAL_CLASSIFY", { call: "fstatSync", label: "journal", occurrence: 1, behave: () => { throw errno("EIO"); } }],
    ["FINALIZED_SOURCE_CAS_INITIAL_READ", { call: "readSync", label: "journal", occurrence: 1, behave: () => { throw errno("EIO"); } }],
    ["FINALIZED_SOURCE_CAS_INITIAL_RECHECK", { call: "fstatSync", label: "journal", occurrence: 2, behave: () => { throw errno("EIO"); } }],
    ["FINALIZED_SOURCE_CAS_INITIAL_CHECKSUM_COMPARE", {
      call: "readSync", label: "journal", occurrence: 1,
      behave: (_x, args, { real }) => {
        const count = real.readSync.apply(fs, args);
        if (count > 0) args[1][args[2]] = 0x5b;
        return count;
      }
    }],
    ["FINALIZED_SOURCE_CAS_INITIAL_IDENTITY_COMPARE", {
      call: "never", label: "journal", doctor: "fstatSync", occurrence: 3,
      doctorFn: (stat) => Object.assign(Object.create(stat), { ino: stat.ino + 1 })
    }],
    ["FINALIZED_SOURCE_CAS_INITIAL_CLOSE", { call: "closeSync", label: "journal", occurrence: 1, behave: () => { throw errno("EIO"); } }],
    ["FINALIZED_SOURCE_CAS_FINAL_PROBE", { call: "lstatSync", label: "journal", occurrence: 1, behave: () => { throw errno("ENOENT"); } }],
    ["FINALIZED_SOURCE_CAS_FINAL_CLASSIFY", {
      call: "never", label: "journal", doctor: "lstatSync", occurrence: 1,
      doctorFn: (stat) => Object.assign(Object.create(stat), { mode: (stat.mode & ~0o777) | 0o644 })
    }],
    ["FINALIZED_SOURCE_CAS_FINAL_IDENTITY_COMPARE", {
      call: "never", label: "journal", doctor: "lstatSync", occurrence: 1,
      doctorFn: (stat) => Object.assign(Object.create(stat), { ino: stat.ino + 1 })
    }]
  ];
  assert.equal(cases.length, 10);
  for (const [phase, plan] of cases) {
    withRoot((dir) => {
      const { instance, journal } = profileReadyHost(dir);
      const validation = expectedValidationForHost(journal);
      const error = withFacade(dir, plan, (facade) => {
        facade.arm();
        return captureHostFailure(() => instance.finalizeProfile(validation));
      });
      assert.ok(error instanceof PhilCoreV2ConsumerRecoveryGenesisStagingHostError, phase);
      assert.equal(error.detail.phase, phase, phase);
      assert.equal(error.detail.commitState, "NOT_COMMITTED", phase);
      assert.deepEqual(
        fs.readdirSync(profilesDir(dir)).filter((name) => name.endsWith(".tmp")),
        [],
        `${phase} leaves no owned temp`
      );
      instance.close();
    });
  }
});

test("FP-16: throwing finalize clock maps to HOST_INVALID_NOW without hostile inspection", () => {
  withRoot((dir) => {
    let throwClock = false;
    let traps = 0;
    const marker = new Proxy({}, {
      get() { traps += 1; throw new Error("get trap"); },
      ownKeys() { traps += 1; throw new Error("ownKeys trap"); },
      getOwnPropertyDescriptor() { traps += 1; throw new Error("descriptor trap"); }
    });
    const nowFn = () => {
      if (throwClock) throw marker;
      return HOST_PROFILE_NOW;
    };
    const { instance, journal } = profileReadyHost(dir, { deps: { nowFn } });
    const validation = expectedValidationForHost(journal);
    throwClock = true;
    const error = captureHostFailure(() => instance.finalizeProfile(validation));
    assert.equal(error.code, "HOST_INVALID_NOW");
    assert.equal(error.detail.phase, "CLOCK_SAMPLE");
    assert.equal(error.detail.commitState, "NOT_COMMITTED");
    assert.equal(traps, 0);
    throwClock = false;
    instance.close();
  });
});

test("FP-17: final-directory fsync commits profile and clock before retryable supersession", () => {
  withRoot((dir) => {
    let now = HOST_PROFILE_NOW;
    const { instance, journal } = profileReadyHost(dir, { deps: { nowFn: () => now } });
    const validation = expectedValidationForHost(journal);
    now = HOST_PROFILE_NOW + 10;
    const plan = {
      call: "openSync", label: "temp", occurrence: 1,
      behave: () => { throw errno("EIO"); }
    };
    const first = withFacade(dir, plan, (facade) => {
      facade.arm();
      return captureHostFailure(() => instance.finalizeProfile(validation));
    });
    assert.equal(first.code, "HOST_FILESYSTEM_MUTATION_FAILED");
    assert.equal(first.detail.phase, "TEMP_OPEN");
    assert.equal(first.detail.commitState, "PROFILE_COMMITTED");
    assert.equal(instance.status().state, "FINALIZED");

    now = HOST_PROFILE_NOW + 5;
    const regressed = captureHostFailure(() => instance.finalizeProfile(validation));
    assert.equal(regressed.code, "HOST_CLOCK_REGRESSION_DETECTED");
    assert.equal(regressed.detail.operation, "finalizeProfile");
    assert.equal(regressed.detail.commitState, "PROFILE_COMMITTED");
    assert.equal(instance.status().state, "FINALIZED");

    now = HOST_PROFILE_NOW + 10;
    const recovered = instance.finalizeProfile(validation);
    assert.equal(recovered.outcome, "FINALIZED");
    assert.equal(recovered.journal.state, "SUPERSEDED");
    instance.close();
  });
});

test("FP-18: real child-process crashes recover both final publication windows", () => {
  const hostPath = require.resolve("../src/main/recovery-genesis-staging-host.cjs");
  const childSource = `
    require("tsx/cjs");
    const fs = require("node:fs");
    const path = require("node:path");
    const host = require(${JSON.stringify(hostPath)});
    const adapter = require(${JSON.stringify(STAGING_PROFILE_ADAPTER_PATH)});
    const now = Number(process.env.PHILCORE_CRASH_NOW);
    const instance = host.createRecoveryGenesisStagingHost({
      storageRoot: process.env.PHILCORE_CRASH_ROOT,
      nowFn: () => now,
      livenessProbeFn: () => "DEAD"
    });
    const report = instance.reconcileRestart();
    const expected = adapter[
      "validatePhilCoreV2ConsumerRecoveryGenesis" + "StagingProfile"
    ](report.journal, now);
    const realRename = fs.renameSync;
    let profileRenamed = false;
    fs.renameSync = function (from, to) {
      const destination = path.basename(to);
      if (destination.startsWith("profile_")) {
        const result = realRename.apply(fs, arguments);
        profileRenamed = true;
        if (process.env.PHILCORE_CRASH_STAGE === "AFTER_PROFILE_RENAME") {
          process.exit(71);
        }
        return result;
      }
      if (
        profileRenamed
        && destination.startsWith("ceremony_")
        && process.env.PHILCORE_CRASH_STAGE === "BEFORE_JOURNAL_RENAME"
      ) {
        process.exit(72);
      }
      return realRename.apply(fs, arguments);
    };
    instance.finalizeProfile(expected);
    process.exit(70);
  `;

  for (const [stage, exitStatus] of [
    ["AFTER_PROFILE_RENAME", 71],
    ["BEFORE_JOURNAL_RENAME", 72]
  ]) {
    withRoot((dir) => {
      const ready = profileReadyHost(dir);
      ready.instance.close();
      const child = childProcess.spawnSync(process.execPath, ["-e", childSource], {
        cwd: path.resolve(__dirname, "../../.."),
        env: {
          ...process.env,
          PHILCORE_CRASH_ROOT: dir,
          PHILCORE_CRASH_NOW: String(HOST_PROFILE_NOW),
          PHILCORE_CRASH_STAGE: stage
        },
        encoding: "utf8"
      });
      assert.equal(child.status, exitStatus, `${stage}: ${child.stderr}`);

      const recovered = createRecoveryGenesisStagingHost(baseDeps(dir, {
        nowFn: () => HOST_PROFILE_NOW + 100000,
        livenessProbeFn: () => "DEAD"
      }));
      const report = recovered.reconcileRestart();
      assert.equal(report.outcome, "RECOVERED_FINALIZED_AND_SUPERSEDED", stage);
      assert.equal(report.journal.state, "SUPERSEDED", stage);
      assert.ok(report.finalizedProfile, stage);
      assert.deepEqual(
        fs.readdirSync(profilesDir(dir)).filter((name) => name.endsWith(".tmp")),
        [],
        `${stage} leaves no finalized temp after recovery`
      );
      recovered.close();
    });
  }
});

// ---------------------------------------------------------------------------
// Genesis credential obligation — H01–H48
// ---------------------------------------------------------------------------
test("H01-H06: ACTIVE sidecar publication identity, mode, bytes, freeze, shape, and immutability", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    const returned = instance.beginCredentialObligation(minted);
    assert.equal(returned.obligation.state, "ACTIVE");
    assert.ok(Object.isFrozen(returned));
    assert.ok(Object.isFrozen(returned.obligation));
    assert.deepEqual(Object.keys(returned).sort(), ["journal", "obligation"]);
    const file = obligationFilePath(dir);
    const stat = fs.lstatSync(file);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.ok(stat.size <= 4096);
    const text = fs.readFileSync(file, "utf8");
    assert.equal(text.includes("\n"), false);
    const parsed = JSON.parse(text);
    assert.deepEqual(Object.keys(parsed), [
      "schemaVersion", "formatProvenance", "intentId", "genesisDeploymentIntentHash",
      "ceremonyVersion", "role", "credentialGeneration", "ceremonyId",
      "ceremonyExpiresAtUnixSeconds", "genesisEnrollmentCeremonyHash", "state",
      "credentialIdHash", "publicVerificationMaterialHash", "createdAtUnixSeconds",
      "updatedAtUnixSeconds", "creationAuthorizedAtUnixSeconds", "orphanReason",
      "integrityChecksum"
    ]);
    const snapshot = { ...returned.obligation };
    assert.throws(() => { returned.obligation.state = "ORPHANED"; }, TypeError);
    assert.equal(instance.status().credentialObligation.state, "ACTIVE");
    assert.equal(snapshot.state, "ACTIVE");
    instance.close();
  });
});

test("H07-H12: authorize and record persist, match hashes, and clock-regression outranks", () => {
  withRoot((dir) => {
    let now = 1700000000;
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir, { nowFn: () => now }));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0, now);
    instance.beginCredentialObligation(minted);
    now = 1700000001;
    const authorized = instance.authorizeCredentialCreation(minted.ceremonyId);
    assert.equal(authorized.obligation.state, "CREATION_AUTHORIZED");
    const call = validStageInput(intent, 0, minted);
    now = 1700000002;
    const recorded = instance.recordCreatedCredential({
      expectedCeremonyId: minted.ceremonyId,
      credentialIdHash: call.roleInput.descriptor.credentialIdHash,
      publicVerificationMaterialHash: call.roleInput.descriptor.publicVerificationMaterialHash
    });
    assert.equal(recorded.obligation.state, "CREDENTIAL_RECORDED");
    assert.equal(recorded.obligation.credentialIdHash, call.roleInput.descriptor.credentialIdHash);
    now = 1700000000;
    const regression = captureHostFailure(() => instance.authorizeCredentialCreation(minted.ceremonyId));
    assert.equal(regression.code, "CLOCK_REGRESSION_DETECTED");
    instance.close();
  });
});

test("H13-H18: stageRole requires CREDENTIAL_RECORDED and compares only the returned manifest", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    const missing = captureHostFailure(() => instance.stageRole(0, validStageInput(intent, 0, minted).roleInput));
    assert.equal(missing.code, "HOST_CREDENTIAL_OBLIGATION_STATE_INVALID");
    instance.authorizeCredentialCreation(minted.ceremonyId);
    const still = captureHostFailure(() => instance.stageRole(0, validStageInput(intent, 0, minted).roleInput));
    assert.equal(still.code, "HOST_CREDENTIAL_OBLIGATION_STATE_INVALID");
    const call = validStageInput(intent, 0, minted);
    instance.recordCreatedCredential({
      expectedCeremonyId: minted.ceremonyId,
      credentialIdHash: call.roleInput.descriptor.credentialIdHash,
      publicVerificationMaterialHash: call.roleInput.descriptor.publicVerificationMaterialHash
    });
    const staged = instance.stageRole(call.role, call.roleInput);
    assert.notEqual(staged.journal.manifest["0"], null);
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    instance.close();
  });
});

test("H19-H24: journal-first consumption, MANIFEST_COMMITTED retry, and retirement indeterminate poison", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const prepared = establishRecordedCredential(instance, intent, 0);
    const failed = withFacade(dir, {
      call: "unlinkSync", label: "obligation", occurrence: 1,
      behave: () => { throw errno("EIO"); }
    }, (facade) => {
      facade.arm();
      return captureHostFailure(() => instance.stageRole(prepared.call.role, prepared.call.roleInput));
    });
    assert.equal(failed.code, "HOST_CREDENTIAL_OBLIGATION_RETIREMENT_FAILED");
    assert.equal(failed.detail.commitState, "MANIFEST_COMMITTED");
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    instance.close();
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "CONSUMED_RECOVERED");
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    recovered.close();
  });
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const prepared = establishRecordedCredential(instance, intent, 0);
    const indeterminate = withFacade(dir, {
      call: "fsyncSync", label: "staging", occurrence: 2,
      behave: () => { throw errno("EIO"); }
    }, (facade) => {
      facade.arm();
      return captureHostFailure(() => instance.stageRole(prepared.call.role, prepared.call.roleInput));
    });
    assert.equal(indeterminate.code, "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE");
    assert.equal(indeterminate.detail.phase, "OBLIGATION_UNLINK_DIR_FSYNC");
    assert.equal(indeterminate.detail.commitState, "OBLIGATION_RETIREMENT_INDETERMINATE");
    instance.close();
  });
});

test("H25-H30: sidecar and journal publication crash probes", () => {
  const probes = [
    ["H25 temp fsync", { call: "fsyncSync", label: "otemp", occurrence: 1 }, "begin",
      "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED", "OBLIGATION_TEMP_FSYNC", "NOT_COMMITTED"],
    ["H26 sidecar rename", { call: "renameSync", label: "otemp", occurrence: 1 }, "begin",
      "HOST_CREDENTIAL_OBLIGATION_WRITE_FAILED", "OBLIGATION_RENAME", "NOT_COMMITTED"],
    ["H27 sidecar dir fsync", { call: "fsyncSync", label: "staging", occurrence: 1 }, "begin",
      "HOST_CREDENTIAL_OBLIGATION_DURABILITY_INDETERMINATE", "OBLIGATION_PARENT_DIR_FSYNC", "INDETERMINATE"],
    ["H28 journal rename", { call: "renameSync", label: "temp", occurrence: 1 }, "stage",
      "HOST_FILESYSTEM_MUTATION_FAILED", "RENAME", "NOT_COMMITTED"],
    ["H29 journal dir fsync", { call: "fsyncSync", label: "staging", occurrence: 1 }, "stage",
      "HOST_DURABILITY_INDETERMINATE", "PARENT_DIR_FSYNC", "INDETERMINATE"],
    ["H30 unlink dir fsync", { call: "fsyncSync", label: "staging", occurrence: 2 }, "stage",
      "HOST_CREDENTIAL_OBLIGATION_REMOVAL_INDETERMINATE", "OBLIGATION_UNLINK_DIR_FSYNC",
      "OBLIGATION_RETIREMENT_INDETERMINATE"]
  ];
  for (const [label, plan, kind, expectedCode, expectedPhase, expectedCommitState] of probes) {
    withRoot((dir) => {
      const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
      instance.reconcileRestart();
      const intent = validIntent();
      instance.createJournal(intent);
      let prepared = null;
      if (kind === "stage") prepared = establishRecordedCredential(instance, intent, 0);
      const minted = kind === "begin" ? mintCeremonyFor(intent, 0) : null;
      const error = withFacade(dir, plan, (facade) => {
        facade.arm();
        return captureHostFailure(() => {
          if (kind === "begin") instance.beginCredentialObligation(minted);
          else instance.stageRole(prepared.call.role, prepared.call.roleInput);
        });
      });
      assert.ok(error, `${label} must fail`);
      assert.equal(error.code, expectedCode, label);
      assert.equal(error.detail.phase, expectedPhase, label);
      assert.equal(error.detail.commitState, expectedCommitState, label);
      if (expectedCommitState !== "INDETERMINATE"
          && expectedCommitState !== "OBLIGATION_RETIREMENT_INDETERMINATE") {
        instance.close();
      }
    });
  }
});

test("H31-H40: restart decision table", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = instance.reconcileRestart();
    assert.equal(report.credentialOutcome, "ABSENT");
    assert.equal(report.credentialObligation, null);
    instance.close();
  });
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    instance.beginCredentialObligation(mintCeremonyFor(intent, 0));
    instance.close();
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ACTIVE");
    assert.equal(report.credentialObligation.state, "ACTIVE");
    recovered.close();
  });
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    instance.authorizeCredentialCreation(minted.ceremonyId);
    instance.close();
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.credentialObligation.orphanReason, "RESTART_DURING_CREATION");
    recovered.close();
  });
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    establishRecordedCredential(instance, intent, 0);
    instance.close();
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.credentialObligation.orphanReason, "RESTART_DURING_CREATION");
    recovered.close();
  });
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const prepared = establishRecordedCredential(instance, intent, 0);
    const sidecar = fs.readFileSync(obligationFilePath(dir));
    instance.stageRole(prepared.call.role, prepared.call.roleInput);
    fs.writeFileSync(obligationFilePath(dir), sidecar, { mode: 0o600 });
    instance.close();
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "CONSUMED_RECOVERED");
    assert.equal(report.credentialObligation, null);
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    recovered.close();
  });
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    const journal = instance.createJournal(intent).journal;
    const active = instance.beginCredentialObligation(mintCeremonyFor(intent, 0)).obligation;
    const terminal = instance.cancel().journal;
    instance.close();
    writeStoredRecord(obligationFilePath(dir), active);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.journal.state, terminal.state);
    assert.equal(report.credentialOutcome, "ABSENT");
    assert.equal(report.credentialObligation, null);
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    recovered.close();
  });

  // Durable context mismatch is first-match, exact, poisoning, and preserves
  // both the valid-but-foreign journal and the sidecar.
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intentA = validIntent();
    const journalA = instance.createJournal(intentA).journal;
    instance.beginCredentialObligation(mintCeremonyFor(intentA, 0));
    instance.close();
    const intentB = validIntent({ intentId: `0x${"12".repeat(32)}` });
    const journalB = pureJournal.createGenesisStagingJournal(intentB, HOST_PROFILE_NOW);
    fs.unlinkSync(storedJournalPath(dir, journalA));
    writeStoredRecord(storedJournalPath(dir, journalB), journalB);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const error = captureHostFailure(() => recovered.reconcileRestart());
    assert.equal(error.code, "HOST_CREDENTIAL_OBLIGATION_DURABLE_CONTEXT_MISMATCH");
    assert.equal(error.detail.commitState, "NOT_APPLICABLE");
    assert.ok(fs.existsSync(storedJournalPath(dir, journalB)));
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    const poisonError = captureHostFailure(() => recovered.status());
    assert.equal(poisonError.code, "HOST_PROCESS_POISONED");
  });

  // ACTIVE beside an occupied matching slot is impossible and poisons.
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    const journal = instance.createJournal(intent).journal;
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    const call = validStageInput(intent, 0, minted);
    const occupied = pureJournal.stageGenesisRoleCandidate(journal, 0, call.roleInput, HOST_PROFILE_NOW);
    instance.close();
    writeStoredRecord(storedJournalPath(dir, occupied), occupied);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const error = captureHostFailure(() => recovered.reconcileRestart());
    assert.equal(error.code, "HOST_CREDENTIAL_OBLIGATION_INVALID");
    assert.equal(error.detail.commitState, "NOT_APPLICABLE");
    assert.ok(fs.existsSync(obligationFilePath(dir)));
  });

  // Authorized-but-unconsumed beside a terminal journal becomes the exact
  // terminal-recovery orphan rather than being removed.
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    const authorized = instance.authorizeCredentialCreation(minted.ceremonyId).obligation;
    const terminal = instance.cancel().journal;
    instance.close();
    writeStoredRecord(obligationFilePath(dir), authorized);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.journal.state, terminal.state);
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.credentialObligation.orphanReason,
      "TERMINAL_JOURNAL_WITH_UNCONSUMED_CREATION");
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    recovered.close();
  });

  // A ceremony-consistent but credential-mismatched manifest becomes the
  // specific known orphan and remains durably blocking.
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    const journal = instance.createJournal(intent).journal;
    const prepared = establishRecordedCredential(instance, intent, 0);
    const credentialIdHash = `0x${"09".repeat(32)}`;
    const independence = {
      ...prepared.call.roleInput.independence,
      credentialIdHash
    };
    const roleInput = {
      ...prepared.call.roleInput,
      independence,
      descriptor: {
        ...prepared.call.roleInput.descriptor,
        credentialIdHash,
        independenceBindingHash: computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence)
      }
    };
    const occupied = pureJournal.stageGenesisRoleCandidate(journal, 0, roleInput, HOST_PROFILE_NOW);
    instance.close();
    writeStoredRecord(storedJournalPath(dir, occupied), occupied);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.credentialObligation.orphanReason, "RECORDED_CREDENTIAL_MISMATCH");
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    recovered.close();
  });

  // An unknown orphan with no manifest remains blocking.
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    instance.authorizeCredentialCreation(minted.ceremonyId);
    const orphaned = instance.cancelCredentialObligation(minted.ceremonyId).obligation;
    instance.close();
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.credentialObligation.orphanReason, orphaned.orphanReason);
    assert.equal(report.credentialObligation.credentialIdHash, null);
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    recovered.close();
  });

  // A known orphan is retired only when the manifest proves an exact match.
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    const journal = instance.createJournal(intent).journal;
    const prepared = establishRecordedCredential(instance, intent, 0);
    instance.cancelCredentialObligation(prepared.minted.ceremonyId);
    const occupied = pureJournal.stageGenesisRoleCandidate(
      journal, prepared.call.role, prepared.call.roleInput, HOST_PROFILE_NOW
    );
    instance.close();
    writeStoredRecord(storedJournalPath(dir, occupied), occupied);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "CONSUMED_RECOVERED");
    assert.equal(report.credentialObligation, null);
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    recovered.close();
  });

  // An unknown orphan cannot be matched even when its ceremony slot exists.
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    const journal = instance.createJournal(intent).journal;
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    instance.authorizeCredentialCreation(minted.ceremonyId);
    const orphaned = instance.cancelCredentialObligation(minted.ceremonyId).obligation;
    const call = validStageInput(intent, 0, minted);
    const occupied = pureJournal.stageGenesisRoleCandidate(journal, 0, call.roleInput, HOST_PROFILE_NOW);
    instance.close();
    writeStoredRecord(storedJournalPath(dir, occupied), occupied);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.credentialObligation.orphanReason, orphaned.orphanReason);
    assert.equal(report.credentialObligation.credentialIdHash, null);
    assert.ok(fs.existsSync(obligationFilePath(dir)));
    recovered.close();
  });
});

test("H41-H44: role-only cancel versus enrollment cancel and expiry", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    const cancelled = instance.cancelCredentialObligation(minted.ceremonyId);
    assert.equal(cancelled.obligation, null);
    assert.equal(instance.status().state, "STAGING");
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    instance.close();
  });
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    instance.authorizeCredentialCreation(minted.ceremonyId);
    const cancelled = instance.cancelCredentialObligation(minted.ceremonyId);
    assert.equal(cancelled.obligation.state, "ORPHANED");
    assert.equal(cancelled.obligation.orphanReason, "ROLE_CEREMONY_CANCELLED_AFTER_CREATION_AUTHORIZATION");
    assert.equal(instance.status().state, "STAGING");
    instance.close();
  });
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    instance.authorizeCredentialCreation(minted.ceremonyId);
    const cancelled = instance.cancel();
    assert.equal(cancelled.journal.state, "CANCELLED");
    assert.equal(cancelled.obligation.state, "ORPHANED");
    assert.equal(cancelled.obligation.orphanReason, "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION");
    instance.close();
  });
});

test("H45: finalizeProfile is rejected while a sidecar exists", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    instance.beginCredentialObligation(mintCeremonyFor(intent, 0));
    const error = captureHostFailure(() => instance.finalizeProfile({}));
    assert.equal(error.code, "HOST_CREDENTIAL_OBLIGATION_STATE_INVALID");
    instance.close();
  });
});

test("H46: acknowledgeTerminal is rejected while an orphan sidecar exists", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    instance.beginCredentialObligation(minted);
    instance.authorizeCredentialCreation(minted.ceremonyId);
    const cancelled = instance.cancel();
    const error = captureHostFailure(() => instance.acknowledgeTerminal({
      intentId: cancelled.journal.intentId,
      integrityChecksum: cancelled.journal.integrityChecksum
    }));
    assert.equal(error.code, "HOST_CREDENTIAL_OBLIGATION_ORPHANED");
    instance.close();
  });
});

test("H47: D27 load-bearing obligation CAS probe", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    const minted = mintCeremonyFor(intent, 0);
    const error = withFacade(dir, {
      call: "lstatSync", label: "obligation", occurrence: 2,
      behave: (_result, args, { real }) => {
        fs.writeFileSync(args[0], "{}", { mode: 0o600 });
        return real.lstatSync(args[0]);
      }
    }, (facade) => {
      facade.arm();
      return captureHostFailure(() => instance.beginCredentialObligation(minted));
    });
    assert.equal(error.code, "HOST_CREDENTIAL_OBLIGATION_ALREADY_EXISTS");
    assert.equal(error.detail.phase, "OBLIGATION_CAS_PROBE");
    assert.equal(error.detail.commitState, "NOT_APPLICABLE");
    instance.close();
  });
});

test("H48: require graph, unexpected obligation names, and no device references", () => {
  const hostSource = fs.readFileSync(path.resolve(__dirname, "../src/main/recovery-genesis-staging-host.cjs"), "utf8");
  for (const forbidden of ["ipcMain", "ipcRenderer", "BrowserWindow", "deviceAdapter", "webContents"]) {
    assert.ok(!hostSource.includes(forbidden), `host references ${forbidden}`);
  }
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    instance.createJournal(intent);
    fs.writeFileSync(
      path.join(dir, "philcore-recovery-enrollment", "genesis-staging", "genesis-credential-obligation.forged.json"),
      "{}",
      { mode: 0o600 }
    );
    instance.close();
    const probe = createRecoveryGenesisStagingHost(baseDeps(dir));
    const error = captureHostFailure(() => probe.reconcileRestart());
    assert.equal(error.code, "HOST_CREDENTIAL_OBLIGATION_UNEXPECTED_ENTRY");
    probe.close();
  });
});

test("H-child-1: journal-committed sidecar-present restart recovers CONSUMED", () => {
  const hostPath = require.resolve("../src/main/recovery-genesis-staging-host.cjs");
  withRoot((dir) => {
    const intent = validIntent();
    const minted = mintCeremonyFor(intent, 0);
    const prepared = validStageInput(intent, 0, minted);
    const candidatePath = path.join(dir, "candidate.json");
    fs.writeFileSync(
      candidatePath,
      JSON.stringify({ intent, minted, call: prepared }, (_, value) =>
        typeof value === "bigint" ? value.toString() : value
      )
    );
    const childSource = `
      require("tsx/cjs");
      const fs = require("node:fs");
      const path = require("node:path");
      const host = require(${JSON.stringify(hostPath)});
      const instance = host.createRecoveryGenesisStagingHost({
        storageRoot: process.env.PHILCORE_CRASH_ROOT,
        nowFn: () => 1700000000,
        livenessProbeFn: () => "DEAD"
      });
      instance.reconcileRestart();
      const payload = JSON.parse(fs.readFileSync(path.join(process.env.PHILCORE_CRASH_ROOT, "candidate.json"), "utf8"));
      const revive = (value) => {
        if (value && typeof value === "object" && !Array.isArray(value)) {
          const out = {};
          for (const key of Object.keys(value)) {
            const current = value[key];
            if (["descriptorVersion","role","verifierKind","userVerificationPolicy","backupPolicy","authenticatorAttachmentPolicy","attestationPolicy","credentialGeneration","bindingVersion","authenticatorClass","synchronizationClass","independenceAssurance","ceremonyVersion","expiresAtUnixSeconds","mintedAtUnixSeconds","lastObservedAtUnixSeconds","intentVersion","chainId","validatorEpoch","recoveryEpoch","recoveryDelaySeconds","recoveryExpirySeconds","expiresAt"].includes(key) && typeof current === "string" && /^[0-9]+$/u.test(current)) {
              out[key] = BigInt(current);
            } else {
              out[key] = revive(current);
            }
          }
          return out;
        }
        return value;
      };
      const intent = revive(payload.intent);
      const minted = revive(payload.minted);
      const call = revive(payload.call);
      instance.createJournal(intent);
      instance.beginCredentialObligation(minted);
      instance.authorizeCredentialCreation(minted.ceremonyId);
      instance.recordCreatedCredential({
        expectedCeremonyId: minted.ceremonyId,
        credentialIdHash: call.roleInput.descriptor.credentialIdHash,
        publicVerificationMaterialHash: call.roleInput.descriptor.publicVerificationMaterialHash
      });
      const realRename = fs.renameSync;
      fs.renameSync = function (from, to) {
        const result = realRename.apply(fs, arguments);
        if (path.basename(to).startsWith("ceremony_")) process.exit(71);
        return result;
      };
      instance.stageRole(call.role, call.roleInput);
    `;
    const child = childProcess.spawnSync(process.execPath, ["-e", childSource], {
      env: Object.assign({}, process.env, { PHILCORE_CRASH_ROOT: dir }),
      encoding: "utf8"
    });
    assert.equal(child.status, 71, child.stderr);
    assert.equal(fs.existsSync(obligationFilePath(dir)), true);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir, {
      nowFn: () => 1700000061,
      livenessProbeFn: () => "DEAD"
    }));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "CONSUMED_RECOVERED");
    recovered.close();
  });
});

test("H-child-2: orphan publication before terminal journal is durable after crash", () => {
  const hostPath = require.resolve("../src/main/recovery-genesis-staging-host.cjs");
  withRoot((dir) => {
    const intent = validIntent();
    const minted = mintCeremonyFor(intent, 0);
    fs.writeFileSync(
      path.join(dir, "candidate.json"),
      JSON.stringify({ intent, minted }, (_, value) => typeof value === "bigint" ? value.toString() : value)
    );
    const childSource = `
      require("tsx/cjs");
      const fs = require("node:fs");
      const path = require("node:path");
      const host = require(${JSON.stringify(hostPath)});
      const instance = host.createRecoveryGenesisStagingHost({
        storageRoot: process.env.PHILCORE_CRASH_ROOT,
        nowFn: () => 1700000000,
        livenessProbeFn: () => "DEAD"
      });
      instance.reconcileRestart();
      const payload = JSON.parse(fs.readFileSync(path.join(process.env.PHILCORE_CRASH_ROOT, "candidate.json"), "utf8"));
      const revive = (value) => {
        if (value && typeof value === "object" && !Array.isArray(value)) {
          const out = {};
          for (const key of Object.keys(value)) {
            const current = value[key];
            if (["ceremonyVersion","role","credentialGeneration","expiresAtUnixSeconds","mintedAtUnixSeconds","lastObservedAtUnixSeconds","intentVersion","chainId","validatorEpoch","recoveryEpoch","recoveryDelaySeconds","recoveryExpirySeconds","expiresAt"].includes(key) && typeof current === "string" && /^[0-9]+$/u.test(current)) {
              out[key] = BigInt(current);
            } else {
              out[key] = revive(current);
            }
          }
          return out;
        }
        return value;
      };
      const intent = revive(payload.intent);
      const minted = revive(payload.minted);
      instance.createJournal(intent);
      instance.beginCredentialObligation(minted);
      instance.authorizeCredentialCreation(minted.ceremonyId);
      const realRename = fs.renameSync;
      fs.renameSync = function (from, to) {
        const result = realRename.apply(fs, arguments);
        if (path.basename(to) === "genesis-credential-obligation.v1.json") process.exit(72);
        return result;
      };
      instance.cancel();
    `;
    const child = childProcess.spawnSync(process.execPath, ["-e", childSource], {
      env: Object.assign({}, process.env, { PHILCORE_CRASH_ROOT: dir }),
      encoding: "utf8"
    });
    assert.equal(child.status, 72, child.stderr);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir, {
      nowFn: () => 1700000061,
      livenessProbeFn: () => "DEAD"
    }));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.equal(report.credentialObligation.orphanReason,
      "CANCELLED_OR_EXPIRED_AFTER_CREATION_AUTHORIZATION");
    recovered.close();
  });
});

test("H-7a-1: RECORDED_CREDENTIAL_MISMATCH exact-match orphan remains blocked", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const planted = plantRecordedCredentialMismatchExactMatch(dir, instance);
    instance.close();
    const sidecarPath = obligationFilePath(dir);
    const beforeBytes = fs.readFileSync(sidecarPath);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir, {
      nowFn: () => HOST_PROFILE_NOW + 2
    }));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "ORPHANED");
    assert.notEqual(report.credentialObligation, null);
    assert.equal(report.credentialObligation.state, "ORPHANED");
    assert.equal(report.credentialObligation.orphanReason, "RECORDED_CREDENTIAL_MISMATCH");
    assert.equal(
      report.credentialObligation.credentialIdHash,
      planted.prepared.call.roleInput.descriptor.credentialIdHash
    );
    assert.equal(fs.existsSync(sidecarPath), true);
    assert.deepEqual(fs.readFileSync(sidecarPath), beforeBytes);
    recovered.close();
  });
});

test("H-7a-2: conflict-orphan exact-match block repeats across restarts", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    plantRecordedCredentialMismatchExactMatch(dir, instance);
    instance.close();
    const sidecarPath = obligationFilePath(dir);
    const beforeBytes = fs.readFileSync(sidecarPath);
    const first = createRecoveryGenesisStagingHost(baseDeps(dir, {
      nowFn: () => HOST_PROFILE_NOW + 2
    }));
    const firstReport = first.reconcileRestart();
    assert.equal(firstReport.credentialOutcome, "ORPHANED");
    assert.equal(firstReport.credentialObligation.orphanReason, "RECORDED_CREDENTIAL_MISMATCH");
    assert.deepEqual(fs.readFileSync(sidecarPath), beforeBytes);
    first.close();
    const second = createRecoveryGenesisStagingHost(baseDeps(dir, {
      nowFn: () => HOST_PROFILE_NOW + 3
    }));
    const secondReport = second.reconcileRestart();
    assert.equal(secondReport.credentialOutcome, "ORPHANED");
    assert.notEqual(secondReport.credentialObligation, null);
    assert.equal(secondReport.credentialObligation.state, "ORPHANED");
    assert.equal(secondReport.credentialObligation.orphanReason, "RECORDED_CREDENTIAL_MISMATCH");
    assert.equal(fs.existsSync(sidecarPath), true);
    assert.deepEqual(fs.readFileSync(sidecarPath), beforeBytes);
    second.close();
  });
});

test("H-7a-3: non-conflict ORPHANED exact-match clearing remains CONSUMED_RECOVERED", () => {
  withRoot((dir) => {
    const instance = createRecoveryGenesisStagingHost(baseDeps(dir));
    instance.reconcileRestart();
    const intent = validIntent();
    const journal = instance.createJournal(intent).journal;
    const prepared = establishRecordedCredential(instance, intent, 0);
    instance.cancelCredentialObligation(prepared.minted.ceremonyId);
    const occupied = pureJournal.stageGenesisRoleCandidate(
      journal, prepared.call.role, prepared.call.roleInput, HOST_PROFILE_NOW
    );
    instance.close();
    writeStoredRecord(storedJournalPath(dir, occupied), occupied);
    const recovered = createRecoveryGenesisStagingHost(baseDeps(dir));
    const report = recovered.reconcileRestart();
    assert.equal(report.credentialOutcome, "CONSUMED_RECOVERED");
    assert.equal(report.credentialObligation, null);
    assert.equal(fs.existsSync(obligationFilePath(dir)), false);
    recovered.close();
  });
});

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
const byReason = new Map();
for (const { name, error } of failures) {
  const first = error && error.message ? error.message.split("\n")[0] : String(error);
  byReason.set(first, (byReason.get(first) || 0) + 1);
  if (process.env.PHILCORE_VERBOSE) console.error("FAIL:", name, "\n" + (error && error.stack ? error.stack : first));
}
if (!process.env.PHILCORE_VERBOSE) {
  const top = [...byReason.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  for (const [reason, count] of top) console.error(`FAIL x${count}: ${reason}`);
}

console.log(`\n${passed} passed, ${failures.length} failed, ${passed + failures.length} total`);
if (failures.length > 0) process.exitCode = 1;
