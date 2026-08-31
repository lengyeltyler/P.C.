require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { getAddress } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const OBLIGATION_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisCredentialObligation.ts"
);
const JOURNAL_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisStagingJournal.ts"
);
const PROJECTION_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts"
);
const VALIDATOR_PATH = require.resolve(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisConflictEvidenceValidation.ts"
);
const CLASSIFICATION_PATH = path.join(ROOT, "config/ci/classification.json");

const obligationReal = require(OBLIGATION_PATH);
const journalReal = require(JOURNAL_PATH);
const projectionReal = require(PROJECTION_PATH);
const adapter = require(VALIDATOR_PATH);

const protocol = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisProtocol.ts"
);
const gateB = require(
  "../../apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisRoleCeremonyLifecycle.ts"
);
const {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
  PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
  computePhilCoreV2ConsumerRecoveryIndependenceBinding
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_V2_SECURITY_MODEL_ID
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  buildO39ConsumerRecoveryFixturePackage
} = require("../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs");

const fixtures = buildO39ConsumerRecoveryFixturePackage();
const E = adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_ERROR_CODE;
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const SIDE_ID = `0x${"e1".repeat(32)}`;
const SIDE_PUBLIC = `0x${"e2".repeat(32)}`;
const CHALLENGE = `0x${"c1".repeat(32)}`;
const ALT_HASH = `0x${"c2".repeat(32)}`;
const ALT_HASH_2 = `0x${"c3".repeat(32)}`;

const AUTHORITY_KEYS = Object.freeze([
  "resolutionAuthority",
  "transitionAuthority",
  "possessionAuthority",
  "replayStateAuthority",
  "signatureAuthority",
  "providerAuthority"
]);
const PROOF_KEYS = Object.freeze([
  "replayStoreConsulted",
  "verifiedPossession",
  "verifiedSignature",
  "trustedProvider"
]);
const FORBIDDEN_RESULT_KEYS = Object.freeze([
  "winner",
  "selectedBinding",
  "resolvedOrphan",
  "clearedSidecar",
  "replayProtected",
  "singleUse",
  "authorizedTransition",
  "providerKind"
]);
const PRODUCT_PATHS = Object.freeze([
  "apps/philcore-desktop/src/main/main.cjs",
  "apps/philcore-desktop/src/preload/preload.cjs",
  "apps/philcore-desktop/src/shared/bridge-contract.cjs",
  "apps/philcore-desktop/scripts/build-local.cjs",
  "apps/philcore-desktop/src/main/recovery-genesis-staging-host.cjs",
  "apps/philcore-desktop/src/main/recovery-genesis-coordinator.cjs",
  "apps/phil-device-sdk/src/runtime/index.ts",
  "apps/phil-device-sdk/src/runtime/facade.ts"
]);
const RUNTIME_TRUST_PATHS = Object.freeze([
  "apps/phil-device-sdk/src/deviceIdentity.ts",
  "apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts",
  "apps/phil-device-sdk/src/deviceIdentityStorage.ts",
  "apps/phil-device-sdk/src/deviceIdentityLifecycle.ts",
  "apps/phil-device-sdk/src/deviceIdentityKeyLifecycle.ts",
  "apps/phil-device-sdk/src/deviceIdentityIndexedDbStorage.ts",
  "apps/phil-device-sdk/src/runtime/authoritativeTrustDecision.ts",
  "apps/phil-device-sdk/src/runtime/authenticationEvidence.ts",
  "apps/phil-device-sdk/src/runtime/possessionVerification.ts",
  "apps/phil-device-sdk/src/runtime/boundedTrustEvaluation.ts",
  "apps/phil-device-sdk/src/runtime/trustManagerProductionVerification.ts",
  "apps/phil-device-sdk/src/runtime/publicTrustMetadata.ts",
  "apps/phil-device-sdk/src/runtime/index.ts"
]);
const VALIDATOR_NEEDLES = Object.freeze([
  "v2ConsumerRecoveryGenesisConflictEvidenceValidation",
  "validatePhilCoreV2GenesisConflictEvidence"
]);
const FORBIDDEN_IMPORT_NEEDLES = Object.freeze([
  "deviceIdentity",
  "possessionVerification",
  "authenticationEvidence",
  "authoritativeTrustDecision",
  "boundedTrustEvaluation",
  "trust-manager",
  "trustManager",
  "webauthn",
  "WebAuthn",
  "credential-store",
  "replay-store",
  "platform-webauthn",
  "recovery-enrollment-host",
  "recovery-transport-host",
  "unlinkObligationSidecar",
  "sepolia",
  "mainnet"
]);
const ENVELOPE_KEYS = Object.freeze([
  "schemaVersion",
  "formatProvenance",
  "challengeReference",
  "challengeBindingHash",
  "issuedAtUnixSeconds",
  "expiresAtUnixSeconds",
  "intentId",
  "genesisDeploymentIntentHash",
  "role",
  "credentialGeneration",
  "ceremonyId",
  "ceremonyExpiresAtUnixSeconds",
  "genesisEnrollmentCeremonyHash",
  "journalIntegrityChecksum",
  "journalState",
  "sidecarCredentialIdHash",
  "sidecarPublicVerificationMaterialHash",
  "manifestCredentialIdHash",
  "manifestPublicVerificationMaterialHash"
]);
const GENESIS_TRUST_SCAN =
  /deviceIdentity|possessionVerification|authoritativeTrustDecision|boundedTrust|publicTrustMetadata|trustManager|authenticationEvidence|webauthnFixture/;
const SCAN_SKIP = new Set([
  ".git", "node_modules", "artifacts", "cache", "dist", "build",
  "coverage", "release", "target"
]);
const DESCRIPTOR_NUMERIC_FIELDS = Object.freeze([
  "descriptorVersion", "role", "verifierKind", "userVerificationPolicy",
  "backupPolicy", "authenticatorAttachmentPolicy", "attestationPolicy",
  "credentialGeneration"
]);
const INDEPENDENCE_NUMERIC_FIELDS = Object.freeze([
  "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
  "independenceAssurance", "credentialGeneration"
]);

function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
}

function readRepoFile(relative) {
  return fs.readFileSync(path.join(ROOT, relative), "utf8");
}

function importSpecifiers(source) {
  const specifiers = [];
  for (const match of source.matchAll(/\bfrom\s+["']([^"']+)["']/g)) {
    specifiers.push(match[1]);
  }
  for (const match of source.matchAll(/\bimport\s+["']([^"']+)["']/g)) {
    specifiers.push(match[1]);
  }
  for (const match of source.matchAll(/\brequire\s*\(\s*["']([^"']+)["']/g)) {
    specifiers.push(match[1]);
  }
  return specifiers;
}

function scanImportGraph(startFile) {
  const visited = new Set();
  function walk(file) {
    const resolved = path.resolve(file);
    if (visited.has(resolved)) return;
    visited.add(resolved);
    const text = fs.readFileSync(resolved, "utf8");
    for (const match of text.matchAll(/\bfrom\s+["'](\.[^"']+)["']/g)) {
      walk(path.resolve(path.dirname(resolved), match[1]));
    }
    for (const match of text.matchAll(/\bimport\s+["'](\.[^"']+)["']/g)) {
      walk(path.resolve(path.dirname(resolved), match[1]));
    }
  }
  walk(startFile);
  return [...visited].map((file) => path.relative(ROOT, file)).sort();
}

function scanNeedleHits(needle) {
  const hits = [];
  function scanTree(target) {
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink()) return;
    if (stat.isDirectory()) {
      if (SCAN_SKIP.has(path.basename(target))) return;
      for (const name of fs.readdirSync(target)) {
        scanTree(path.join(target, name));
      }
      return;
    }
    if (!/\.(?:cjs|mjs|js|ts|tsx|json|html|yml|yaml|md)$/.test(target)) return;
    const relative = path.relative(ROOT, target);
    const text = fs.readFileSync(target, "utf8");
    if (relative.includes(needle) || text.includes(needle)) hits.push(relative);
  }
  scanTree(ROOT);
  return hits.sort();
}

function walkMatchingFiles(relativeDir, predicate) {
  const files = [];
  function walk(target) {
    const stat = fs.lstatSync(target);
    if (stat.isSymbolicLink()) return;
    if (stat.isDirectory()) {
      if (SCAN_SKIP.has(path.basename(target))) return;
      for (const name of fs.readdirSync(target)) walk(path.join(target, name));
      return;
    }
    if (predicate(path.relative(ROOT, target), path.basename(target))) {
      files.push(path.relative(ROOT, target));
    }
  }
  walk(path.join(ROOT, relativeDir));
  return files.sort();
}

function expectCode(run, code) {
  let thrown;
  try {
    run();
  } catch (error) {
    thrown = error;
  }
  assert.ok(
    thrown instanceof adapter.PhilCoreV2GenesisConflictEvidenceValidationError,
    `expected branded ${code}`
  );
  assert.equal(thrown.code, code);
  assert.equal(thrown.message, code);
  assert.equal(Object.prototype.hasOwnProperty.call(thrown, "cause"), false);
  assert.deepEqual(
    Reflect.ownKeys(thrown).filter((key) => key !== "stack").sort(),
    ["code", "message", "name"]
  );
  return thrown;
}

function validIntent(overrides = {}) {
  return {
    intentVersion: "1",
    intentId: `0x${"11".repeat(32)}`,
    chainId: "11155111",
    entryPoint: getAddress(`0x${"22".repeat(20)}`),
    factoryBinding: getAddress(`0x${"33".repeat(20)}`),
    confirmationTarget: getAddress(`0x${"44".repeat(20)}`),
    verifier: getAddress(`0x${"55".repeat(20)}`),
    verifierRuntimeCodeHash: `0x${"66".repeat(32)}`,
    accountCreationBytecodeHash: `0x${"77".repeat(32)}`,
    accountVersionId: PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID,
    ownerCommitment: `0x${"88".repeat(32)}`,
    identityBindingCommitment: `0x${"99".repeat(32)}`,
    initialValidator: fixtures.profiles.standard.request.validator,
    validatorVerifierKind: "1",
    validatorKeyIdBinding: `0x${"bb".repeat(32)}`,
    validatorCommitment: `0x${"cc".repeat(32)}`,
    validatorEpoch: "1",
    recoveryEpoch: "1",
    recoveryDelaySeconds: "172800",
    recoveryExpirySeconds: "604800",
    userSalt: `0x${"dd".repeat(32)}`,
    expiresAt: "1900000000",
    ...overrides
  };
}

function bigintFields(source, numericFields) {
  const output = { ...source };
  for (const key of numericFields) {
    if (typeof output[key] === "number") output[key] = BigInt(output[key]);
  }
  return output;
}

function mintCeremony(intentHash, intentExpiresAt, role, ceremonyId, now) {
  return gateB.mintPhilCoreV2GenesisRoleCeremony({
    current: null,
    ceremonyId,
    role: BigInt(role),
    genesisDeploymentIntentHash: intentHash,
    intentExpiresAtUnixSeconds: BigInt(intentExpiresAt),
    nowUnixSeconds: now
  });
}

function buildScenario() {
  const now = 1000;
  const intent = validIntent();
  const intentHash = protocol.computePhilCoreV2LocalGenesisDeploymentIntentHash(intent);
  const ceremonyIds = [0, 1, 2].map(
    (role) => `0x${String(role + 1).padStart(2, "0")}${"a1".repeat(31)}`
  );
  const ceremonies = [0, 1, 2].map((role) =>
    mintCeremony(intentHash, intent.expiresAt, role, ceremonyIds[role], now)
  );
  const source = fixtures.profiles.standard.factors;
  const roleSources = [source.primary, source.secondary, source.offline];
  const factors = roleSources.map((base, role) => {
    const independence = {
      ...bigintFields(base.independence, INDEPENDENCE_NUMERIC_FIELDS),
      role: BigInt(role),
      enrollmentCeremonyHash: ceremonies[role].genesisEnrollmentCeremonyHash,
      credentialGeneration: 1n
    };
    const descriptor = {
      ...bigintFields(base.descriptor, DESCRIPTOR_NUMERIC_FIELDS),
      role: BigInt(role),
      independenceBindingHash:
        computePhilCoreV2ConsumerRecoveryIndependenceBinding(independence),
      credentialGeneration: 1n
    };
    return {
      descriptor,
      independence,
      ...(base.signer ? { signer: base.signer } : {})
    };
  });
  let journal = journalReal.createGenesisStagingJournal(intent, now);
  for (const role of [0, 1, 2]) {
    journal = journalReal.stageGenesisRoleCandidate(
      journal,
      role,
      {
        ...factors[role],
        currentRoleCeremony:
          gateB.toPhilCoreV2GenesisRoleCeremonyHashInput(ceremonies[role])
      },
      now + role + 1
    );
  }
  return { now, intent, intentHash, ceremonyIds, ceremonies, factors, journal };
}

function createOrphaned(scenario, role, mode = "both", options = {}) {
  const entry = scenario.journal.manifest[String(role)];
  const ceremony = options.ceremony ?? scenario.ceremonies[role];
  const intentId = options.intentId ?? scenario.intent.intentId;
  const obligationNow = Number(ceremony.mintedAtUnixSeconds);
  let current = obligationReal.createPhilCoreV2GenesisCredentialObligation({
    ceremony,
    intentId,
    nowUnixSeconds: obligationNow
  });
  current = obligationReal.authorizePhilCoreV2GenesisCredentialCreation({
    current,
    expectedCeremonyId: current.ceremonyId,
    nowUnixSeconds: obligationNow + 1
  });
  if (!options.unknown) {
    const credentialIdHash = role === 2
      ? ZERO_BYTES32
      : mode === "public" || mode === "equal"
        ? entry.descriptor.credentialIdHash
        : SIDE_ID;
    const publicVerificationMaterialHash = mode === "id" || mode === "equal"
      ? entry.descriptor.publicVerificationMaterialHash
      : SIDE_PUBLIC;
    current = obligationReal.recordPhilCoreV2GenesisCreatedCredential({
      current,
      expectedCeremonyId: current.ceremonyId,
      credentialIdHash,
      publicVerificationMaterialHash,
      nowUnixSeconds: obligationNow + 2
    });
  }
  return obligationReal.orphanPhilCoreV2GenesisCredentialObligation({
    current,
    reason: options.reason ?? "RECORDED_CREDENTIAL_MISMATCH",
    nowUnixSeconds: obligationNow + 3
  });
}

function project(obligation, journal) {
  return projectionReal.projectPhilCoreV2GenesisManifestBindingConflict(
    obligation,
    journal
  );
}

function bindingFieldsFrom(projection, overrides = {}) {
  const fields = Object.create(null);
  fields.intentId = projection.intentId;
  fields.genesisDeploymentIntentHash = projection.genesisDeploymentIntentHash;
  fields.role = projection.role;
  fields.credentialGeneration = projection.credentialGeneration;
  fields.ceremonyId = projection.bindingContext.ceremonyId;
  fields.ceremonyExpiresAtUnixSeconds =
    projection.bindingContext.ceremonyExpiresAtUnixSeconds;
  fields.genesisEnrollmentCeremonyHash =
    projection.bindingContext.genesisEnrollmentCeremonyHash;
  fields.journalIntegrityChecksum =
    projection.manifestBinding.journalIntegrityChecksum;
  fields.journalState = projection.bindingContext.journalState;
  fields.sidecarCredentialIdHash = projection.sidecarBinding.credentialIdHash;
  fields.sidecarPublicVerificationMaterialHash =
    projection.sidecarBinding.publicVerificationMaterialHash;
  fields.manifestCredentialIdHash = projection.manifestBinding.credentialIdHash;
  fields.manifestPublicVerificationMaterialHash =
    projection.manifestBinding.publicVerificationMaterialHash;
  fields.challengeReference = CHALLENGE;
  fields.issuedAtUnixSeconds = "1000";
  fields.expiresAtUnixSeconds = "1100";
  for (const [key, value] of Object.entries(overrides)) {
    fields[key] = value;
  }
  return fields;
}

function makeEnvelope(projection, overrides = {}) {
  const binding = bindingFieldsFrom(projection, overrides);
  const challengeBindingHash = Object.prototype.hasOwnProperty.call(
    overrides,
    "challengeBindingHash"
  )
    ? overrides.challengeBindingHash
    : adapter.computePhilCoreV2GenesisConflictEvidenceBindingHash(binding);
  const envelope = Object.create(null);
  envelope.schemaVersion =
    adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_SCHEMA_VERSION;
  envelope.formatProvenance =
    adapter.PHILCORE_V2_GENESIS_CONFLICT_EVIDENCE_VALIDATION_FORMAT_PROVENANCE;
  envelope.challengeReference = binding.challengeReference;
  envelope.challengeBindingHash = challengeBindingHash;
  envelope.issuedAtUnixSeconds = binding.issuedAtUnixSeconds;
  envelope.expiresAtUnixSeconds = binding.expiresAtUnixSeconds;
  envelope.intentId = binding.intentId;
  envelope.genesisDeploymentIntentHash = binding.genesisDeploymentIntentHash;
  envelope.role = binding.role;
  envelope.credentialGeneration = binding.credentialGeneration;
  envelope.ceremonyId = binding.ceremonyId;
  envelope.ceremonyExpiresAtUnixSeconds = binding.ceremonyExpiresAtUnixSeconds;
  envelope.genesisEnrollmentCeremonyHash = binding.genesisEnrollmentCeremonyHash;
  envelope.journalIntegrityChecksum = binding.journalIntegrityChecksum;
  envelope.journalState = binding.journalState;
  envelope.sidecarCredentialIdHash = binding.sidecarCredentialIdHash;
  envelope.sidecarPublicVerificationMaterialHash =
    binding.sidecarPublicVerificationMaterialHash;
  envelope.manifestCredentialIdHash = binding.manifestCredentialIdHash;
  envelope.manifestPublicVerificationMaterialHash =
    binding.manifestPublicVerificationMaterialHash;
  return envelope;
}

function conflictPair(role = 0) {
  const scenario = buildScenario();
  const obligation = createOrphaned(scenario, role, "both");
  const projection = project(obligation, scenario.journal);
  return { scenario, obligation, projection, journal: scenario.journal };
}

function validatePair(pair, envelope, nowUnixSeconds) {
  return adapter.validatePhilCoreV2GenesisConflictEvidence(
    envelope,
    pair.obligation,
    pair.journal,
    nowUnixSeconds
  );
}

function assertNonAuthority(result) {
  assert.equal(Object.getPrototypeOf(result), null);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(result.validationKind, "CALLER_CLOCK_FORMAT_ONLY");
  assert.equal(result.freshnessOutcome, "WITHIN_CALLER_CLOCK_WINDOW");
  for (const key of AUTHORITY_KEYS) {
    assert.equal(result[key], "NONE", key);
  }
  for (const key of PROOF_KEYS) {
    assert.equal(result[key], false, key);
  }
  const keys = Reflect.ownKeys(result);
  for (const forbidden of FORBIDDEN_RESULT_KEYS) {
    assert.equal(keys.includes(forbidden), false, forbidden);
  }
  assert.equal(Object.prototype.hasOwnProperty.call(result, "cause"), false);
}

function snapshotJson(value) {
  return JSON.stringify(value);
}

describe("Dormant genesis conflict-evidence non-resolver contract", function () {
  it("NR01: validator remains absent from product and runtime wiring", function () {
    for (const relative of PRODUCT_PATHS) {
      const text = readRepoFile(relative);
      for (const needle of VALIDATOR_NEEDLES) {
        assert.equal(text.includes(needle), false, `${relative} ${needle}`);
      }
    }
    const buildLocal = readRepoFile("apps/philcore-desktop/scripts/build-local.cjs");
    assert.equal(
      buildLocal.includes("v2ConsumerRecoveryGenesisConflictEvidenceValidation"),
      false
    );
    const host = readRepoFile(
      "apps/philcore-desktop/src/main/recovery-genesis-staging-host.cjs"
    );
    assert.equal(host.includes("unlinkObligationSidecar"), true);
    assert.equal(
      host.includes('sidecar.orphanReason !== "RECORDED_CREDENTIAL_MISMATCH"'),
      true
    );
  });

  it("NR02: re-loading the compiled validator arms no mutating side effect", function () {
    const counts = Object.create(null);
    const restorers = [];
    function trap(object, key, label = key) {
      if (typeof object[key] !== "function") return;
      counts[label] = 0;
      const original = object[key];
      const patched = function patchedSideEffect(...args) {
        counts[label] += 1;
        return original.apply(this, args);
      };
      object[key] = patched;
      restorers.push(() => {
        object[key] = original;
      });
    }
    const fsMod = require("node:fs");
    for (const key of [
      "writeFile", "writeFileSync", "appendFileSync", "mkdirSync",
      "renameSync", "unlinkSync", "rmdirSync",       "cpSync", "copyFileSync",
      "createWriteStream"
    ]) {
      trap(fsMod, key, `fs.${key}`);
    }
    const child = require("node:child_process");
    for (const key of ["spawn", "exec", "execFile", "fork", "spawnSync"]) {
      trap(child, key, `child_process.${key}`);
    }
    const net = require("node:net");
    for (const key of ["connect", "createServer", "createConnection"]) {
      trap(net, key, `net.${key}`);
    }
    const dgram = require("node:dgram");
    trap(dgram, "createSocket", "dgram.createSocket");
    const tls = require("node:tls");
    trap(tls, "connect", "tls.connect");
    const http = require("node:http");
    const https = require("node:https");
    trap(http, "request", "http.request");
    trap(https, "request", "https.request");
    const dns = require("node:dns");
    trap(dns, "lookup", "dns.lookup");
    trap(dns, "resolve", "dns.resolve");
    trap(global, "setTimeout", "setTimeout");
    trap(global, "setInterval", "setInterval");
    trap(global, "setImmediate", "setImmediate");
    if (typeof process.send === "function") {
      trap(process, "send", "process.send");
    }
    const saved = require.cache[VALIDATOR_PATH];
    delete require.cache[VALIDATOR_PATH];
    try {
      require(VALIDATOR_PATH);
    } finally {
      for (const restore of restorers) restore();
      if (saved !== undefined) require.cache[VALIDATOR_PATH] = saved;
      else delete require.cache[VALIDATOR_PATH];
    }
    for (const [label, count] of Object.entries(counts)) {
      assert.equal(count, 0, label);
    }
  });

  it("NR03: validator import graph excludes runtime trust and provider authority", function () {
    const source = fs.readFileSync(VALIDATOR_PATH, "utf8");
    const stripped = stripComments(source);
    assert.equal(stripped.includes("node:crypto"), true);
    const specifiers = importSpecifiers(stripped);
    assert.deepEqual(specifiers.sort(), [
      "./v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts",
      "node:crypto"
    ].sort());
    for (const needle of FORBIDDEN_IMPORT_NEEDLES) {
      const hit = specifiers.some((specifier) => specifier.includes(needle));
      assert.equal(hit, false, needle);
      if (needle === "unlinkObligationSidecar" || needle === "sepolia" || needle === "mainnet") {
        assert.equal(stripped.includes(needle), false, needle);
      }
    }
    assert.equal(stripped.includes("Date.now"), false);
    const graph = scanImportGraph(VALIDATOR_PATH);
    const graphText = graph.join("\n");
    assert.equal(
      graph.includes(
        "apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisConflictEvidenceValidation.ts"
      ),
      true
    );
    assert.equal(
      graph.includes(
        "apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisManifestBindingConflictProjection.ts"
      ),
      true
    );
    for (const forbidden of [
      "deviceIdentity",
      "deviceIdentityWebAuthn",
      "authoritativeTrustDecision",
      "authenticationEvidence",
      "possessionVerification",
      "boundedTrustEvaluation",
      "trustManagerProductionVerification",
      "publicTrustMetadata",
      "recovery-genesis-staging-host",
      "recovery-genesis-coordinator",
      "runtime/index.ts",
      "v2LocalCeremonyProtocol"
    ]) {
      assert.equal(graphText.includes(forbidden), false, forbidden);
    }
  });

  it("NR04: runtime trust modules do not import the genesis validator", function () {
    for (const relative of RUNTIME_TRUST_PATHS) {
      const text = readRepoFile(relative);
      for (const needle of VALIDATOR_NEEDLES) {
        assert.equal(text.includes(needle), false, `${relative} ${needle}`);
      }
    }
    const genesisTs = walkMatchingFiles(
      "apps/phil-device-sdk/src",
      (_rel, name) => /^v2ConsumerRecoveryGenesis.*\.ts$/.test(name)
    );
    const genesisHosts = walkMatchingFiles(
      "apps/philcore-desktop/src/main",
      (_rel, name) => /^recovery-genesis-.*\.cjs$/.test(name)
    );
    for (const relative of [...genesisTs, ...genesisHosts]) {
      const text = readRepoFile(relative);
      const match = text.match(GENESIS_TRUST_SCAN);
      assert.equal(match, null, `${relative} ${match && match[0]}`);
    }
  });

  it("NR05: valid evidence cannot win, clear, mutate, publish, invoke, persist, or authorize", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const result = validatePair(pair, envelope, 1000);
    assertNonAuthority(result);
    const host = readRepoFile(
      "apps/philcore-desktop/src/main/recovery-genesis-staging-host.cjs"
    );
    const coordinator = readRepoFile(
      "apps/philcore-desktop/src/main/recovery-genesis-coordinator.cjs"
    );
    const journalSource = fs.readFileSync(JOURNAL_PATH, "utf8");
    const validatorSource = fs.readFileSync(VALIDATOR_PATH, "utf8");
    for (const text of [host, coordinator, journalSource]) {
      for (const needle of VALIDATOR_NEEDLES) {
        assert.equal(text.includes(needle), false, needle);
      }
    }
    assert.equal(validatorSource.includes("unlinkObligationSidecar"), false);
    assert.equal(validatorSource.includes("stageGenesisRoleCandidate"), false);
    assert.equal(validatorSource.includes("finishReconcile"), false);
    const finalized = walkMatchingFiles(
      "apps/phil-device-sdk/src",
      (_rel, name) => name === "v2ConsumerRecoveryGenesisFinalizedProfile.ts"
    );
    for (const relative of finalized) {
      const text = readRepoFile(relative);
      for (const needle of VALIDATOR_NEEDLES) {
        assert.equal(text.includes(needle), false, `${relative} ${needle}`);
      }
    }
  });

  it("NR06: success and failure leave caller inputs unchanged", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const obligationBefore = snapshotJson(pair.obligation);
    const journalBefore = snapshotJson(pair.journal);
    const envelopeBefore = snapshotJson(envelope);
    const result = validatePair(pair, envelope, 1000);
    assertNonAuthority(result);
    assert.equal(snapshotJson(pair.obligation), obligationBefore);
    assert.equal(snapshotJson(pair.journal), journalBefore);
    assert.equal(snapshotJson(envelope), envelopeBefore);
    expectCode(
      () => validatePair(pair, envelope, 1100),
      E.CONFLICT_EVIDENCE_EXPIRED
    );
    assert.equal(snapshotJson(pair.obligation), obligationBefore);
    assert.equal(snapshotJson(pair.journal), journalBefore);
    assert.equal(snapshotJson(envelope), envelopeBefore);
  });

  it("NR07: freshness acceptance is not single-use or replay protection", function () {
    const pair = conflictPair(0);
    const envelope = makeEnvelope(pair.projection);
    const first = validatePair(pair, envelope, 1000);
    const second = validatePair(pair, envelope, 1050);
    assertNonAuthority(first);
    assertNonAuthority(second);
    assert.equal(first.replayStoreConsulted, false);
    assert.equal(second.replayStoreConsulted, false);
    assert.equal(second.freshnessOutcome, "WITHIN_CALLER_CLOCK_WINDOW");
    assert.notEqual(second.freshnessOutcome, "REPLAY_PROTECTED");
    const stripped = stripComments(fs.readFileSync(VALIDATOR_PATH, "utf8"));
    assert.equal(/\bnew Map\s*\(/.test(stripped), false);
    assert.equal(/\bnew Set\s*\(/.test(stripped), false);
    assert.equal(stripped.includes("IndexedDB"), false);
    assert.equal(stripped.includes("localStorage"), false);
    assert.equal(stripped.includes("REPLAY_PROTECTED"), false);
  });

  it("NR08: projection and hash validity do not imply authenticity, possession, UV, custody, or trust", function () {
    const pair = conflictPair(0);
    const result = validatePair(pair, makeEnvelope(pair.projection), 1000);
    assert.equal(result.verifiedPossession, false);
    assert.equal(result.verifiedSignature, false);
    assert.equal(result.trustedProvider, false);
    assert.equal(result.possessionAuthority, "NONE");
    assert.equal(result.signatureAuthority, "NONE");
    assert.equal(result.providerAuthority, "NONE");
    const stripped = stripComments(fs.readFileSync(VALIDATOR_PATH, "utf8"));
    assert.equal(/\bverify\s*\(/.test(stripped), false);
    assert.equal(/\bsign\s*\(/.test(stripped), false);
    assert.equal(stripped.includes("userVerified"), false);
    assert.equal(stripped.includes("credentialPrivateKey"), false);
    assert.equal(stripped.includes("secure enclave"), false);
    expectCode(
      () => validatePair(pair, makeEnvelope(pair.projection, { intentId: ALT_HASH }), 1000),
      E.CONFLICT_EVIDENCE_BINDING_MISMATCH
    );
    expectCode(
      () => validatePair(pair, makeEnvelope(pair.projection, {
        challengeBindingHash: ALT_HASH_2
      }), 1000),
      E.CONFLICT_EVIDENCE_CHALLENGE_BINDING_MISMATCH
    );
  });

  it("NR09: role-2 zero credential-id handling cannot broaden other identity-hash rules", function () {
    const role2 = conflictPair(2);
    assert.equal(role2.projection.sidecarBinding.credentialIdHash, ZERO_BYTES32);
    assert.equal(role2.projection.manifestBinding.credentialIdHash, ZERO_BYTES32);
    const ok = validatePair(role2, makeEnvelope(role2.projection), 1000);
    assertNonAuthority(ok);
    assert.equal(ok.sidecarCredentialIdHash, ZERO_BYTES32);
    assert.equal(ok.manifestCredentialIdHash, ZERO_BYTES32);
    expectCode(
      () => validatePair(role2, makeEnvelope(role2.projection, {
        sidecarPublicVerificationMaterialHash: ZERO_BYTES32
      }), 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    expectCode(
      () => validatePair(role2, makeEnvelope(role2.projection, {
        journalIntegrityChecksum: ZERO_BYTES32
      }), 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    expectCode(
      () => validatePair(role2, makeEnvelope(role2.projection, {
        challengeReference: ZERO_BYTES32
      }), 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
    const role0 = conflictPair(0);
    expectCode(
      () => validatePair(role0, makeEnvelope(role0.projection, {
        sidecarCredentialIdHash: ZERO_BYTES32
      }), 1000),
      E.CONFLICT_EVIDENCE_BINDING_MISMATCH
    );
    expectCode(
      () => validatePair(role0, makeEnvelope(role0.projection, {
        sidecarPublicVerificationMaterialHash: ZERO_BYTES32
      }), 1000),
      E.CONFLICT_EVIDENCE_FIELD_INVALID
    );
  });

  it("NR10: hostile proxies, getters, coercion, and markers cannot mint authority", function () {
    const pair = conflictPair(0);
    const extra = makeEnvelope(pair.projection);
    extra.resolutionAuthority = "WINNER";
    expectCode(
      () => validatePair(pair, extra, 1000),
      E.CONFLICT_EVIDENCE_EXTRA_KEY
    );
    let traps = 0;
    const baseEnvelope = makeEnvelope(pair.projection);
    const throwing = Object.create(null);
    for (const key of ENVELOPE_KEYS) {
      if (key === "intentId") {
        Object.defineProperty(throwing, key, {
          enumerable: true,
          configurable: true,
          get() {
            traps += 1;
            throw new Error("hostile-intent");
          }
        });
      } else {
        throwing[key] = baseEnvelope[key];
      }
    }
    const thrown = expectCode(
      () => validatePair(pair, throwing, 1000),
      E.CONFLICT_EVIDENCE_PROPERTY_READ_FAILED
    );
    assert.ok(traps >= 1);
    assert.equal(Object.prototype.hasOwnProperty.call(thrown, "cause"), false);
    assert.equal(thrown.message, E.CONFLICT_EVIDENCE_PROPERTY_READ_FAILED);
    const coercedNow = {
      valueOf() {
        return 1000;
      },
      toString() {
        return "1000";
      }
    };
    expectCode(
      () => validatePair(pair, makeEnvelope(pair.projection), coercedNow),
      E.CONFLICT_EVIDENCE_CLOCK_INVALID
    );
    const winnerNow = new Proxy({}, {
      get() {
        return "WINNER";
      }
    });
    expectCode(
      () => validatePair(pair, makeEnvelope(pair.projection), winnerNow),
      E.CONFLICT_EVIDENCE_CLOCK_INVALID
    );
    const marker = new Error("must-not-wrap");
    const projectionModule = require.cache[PROJECTION_PATH];
    const validatorModule = require.cache[VALIDATOR_PATH];
    const originalProjection = projectionModule.exports;
    const shim = Object.create(null);
    for (const key of Object.keys(originalProjection)) {
      shim[key] = originalProjection[key];
    }
    shim.projectPhilCoreV2GenesisManifestBindingConflict = () => {
      throw marker;
    };
    projectionModule.exports = shim;
    delete require.cache[VALIDATOR_PATH];
    let wrapped;
    try {
      const isolated = require(VALIDATOR_PATH);
      isolated.validatePhilCoreV2GenesisConflictEvidence(
        makeEnvelope(pair.projection),
        pair.obligation,
        pair.journal,
        1000
      );
    } catch (error) {
      wrapped = error;
    } finally {
      projectionModule.exports = originalProjection;
      if (validatorModule !== undefined) {
        require.cache[VALIDATOR_PATH] = validatorModule;
      } else {
        delete require.cache[VALIDATOR_PATH];
      }
    }
    assert.equal(wrapped, marker);
  });

  it("NR11: comments and documentation phrases are not executable proof", function () {
    const source = fs.readFileSync(VALIDATOR_PATH, "utf8");
    const stripped = stripComments(source);
    for (const key of AUTHORITY_KEYS) {
      assert.equal(
        stripped.includes(`["${key}", AUTHORITY.NONE]`),
        true,
        key
      );
    }
    assert.equal(stripped.includes('["replayStoreConsulted", false]'), true);
    assert.equal(stripped.includes('["verifiedPossession", false]'), true);
    assert.equal(stripped.includes('["verifiedSignature", false]'), true);
    assert.equal(stripped.includes('["trustedProvider", false]'), true);
    const pair = conflictPair(0);
    assertNonAuthority(validatePair(pair, makeEnvelope(pair.projection), 1000));
  });

  it("NR12: exact validator reachability set and classification total 114", function () {
    assert.deepEqual(
      scanNeedleHits("v2ConsumerRecoveryGenesisConflictEvidenceValidation"),
      [
        "apps/phil-device-sdk/src/v2ConsumerRecoveryGenesisConflictEvidenceValidation.ts",
        "config/ci/classification.json",
        "test/unit/v2ConsumerRecoveryGenesisConflictEvidenceNonResolver.test.cjs",
        "test/unit/v2ConsumerRecoveryGenesisConflictEvidenceValidation.test.cjs"
      ].sort()
    );
    const classification = JSON.parse(fs.readFileSync(CLASSIFICATION_PATH, "utf8"));
    assert.equal(classification.totals.required_product_runtime, 114);
    const item = classification.items.find((entry) =>
      entry.id === "unit:v2ConsumerRecoveryGenesisConflictEvidenceNonResolver.test.cjs"
    );
    assert.ok(item);
    assert.equal(item.kind, "unit_test");
    assert.equal(item.lane, "required_product_runtime");
    assert.equal(
      item.command,
      "npx hardhat test --no-compile ./test/unit/v2ConsumerRecoveryGenesisConflictEvidenceNonResolver.test.cjs"
    );
  });

  it("NR13: named mutants kill forbidden authority expansion on the live contract", function () {
    const pair = conflictPair(0);
    const kills = Object.freeze({
      noProductWiring() {
        const text = readRepoFile("apps/philcore-desktop/src/main/main.cjs");
        assert.equal(
          text.includes("validatePhilCoreV2GenesisConflictEvidence"),
          false
        );
      },
      noRuntimeIndex() {
        const text = readRepoFile("apps/phil-device-sdk/src/runtime/index.ts");
        assert.equal(
          text.includes("v2ConsumerRecoveryGenesisConflictEvidenceValidation"),
          false
        );
      },
      authorityNone() {
        assertNonAuthority(
          validatePair(pair, makeEnvelope(pair.projection), 1000)
        );
      },
      duplicateIsNotReplay() {
        const envelope = makeEnvelope(pair.projection);
        const second = validatePair(pair, envelope, 1050);
        assert.equal(second.replayStoreConsulted, false);
      },
      bindingStillRequired() {
        expectCode(
          () => validatePair(pair, makeEnvelope(pair.projection, {
            intentId: ALT_HASH
          }), 1000),
          E.CONFLICT_EVIDENCE_BINDING_MISMATCH
        );
      },
      hashStillRequired() {
        expectCode(
          () => validatePair(pair, makeEnvelope(pair.projection, {
            challengeBindingHash: ALT_HASH_2
          }), 1000),
          E.CONFLICT_EVIDENCE_CHALLENGE_BINDING_MISMATCH
        );
      },
      hostileExtraCannotAuthorize() {
        const extra = makeEnvelope(pair.projection);
        extra.winner = "sidecar";
        expectCode(
          () => validatePair(pair, extra, 1000),
          E.CONFLICT_EVIDENCE_EXTRA_KEY
        );
      },
      role2ZeroDoesNotZeroPublic() {
        const role2 = conflictPair(2);
        expectCode(
          () => validatePair(role2, makeEnvelope(role2.projection, {
            sidecarPublicVerificationMaterialHash: ZERO_BYTES32
          }), 1000),
          E.CONFLICT_EVIDENCE_FIELD_INVALID
        );
      },
      noValidateTimeWrite() {
        const fsMod = require("node:fs");
        const original = fsMod.writeFileSync;
        let writes = 0;
        fsMod.writeFileSync = function patchedWrite(...args) {
          writes += 1;
          return original.apply(this, args);
        };
        try {
          validatePair(pair, makeEnvelope(pair.projection), 1000);
        } finally {
          fsMod.writeFileSync = original;
        }
        assert.equal(writes, 0);
      }
    });
    for (const [name, run] of Object.entries(kills)) {
      run();
      void name;
    }
  });
});
