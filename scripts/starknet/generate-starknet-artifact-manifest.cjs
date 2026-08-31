const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "../..");
const TOOLCHAIN_PATH = path.join(REPO_ROOT, "config/starknet-toolchain.json");
const DEFAULT_OUT = path.join(REPO_ROOT, "config/starknet-publication-readiness.json");

function readJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function fileInfo(relativePath) {
  const absolutePath = path.join(REPO_ROOT, relativePath);
  if (!fs.existsSync(absolutePath)) {
    return {
      path: relativePath,
      present: false,
      sha256: null,
      bytes: 0
    };
  }

  const bytes = fs.readFileSync(absolutePath);
  return {
    path: relativePath,
    present: true,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.length
  };
}

function validateSummary(summary) {
  const issues = [];
  if (!summary || typeof summary !== "object") {
    return ["summary_missing_or_invalid"];
  }
  if (summary.proofType !== "stwo-unlock-keccak-v1") {
    issues.push("unexpected_proof_type");
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(summary.proofInputHash || ""))) {
    issues.push("invalid_proof_input_hash");
  }
  const expected = summary.expectedFactPayload;
  if (!Array.isArray(expected) || expected.length !== 2) {
    issues.push("invalid_expected_fact_payload");
  } else if (/^0x[0-9a-fA-F]{64}$/.test(String(summary.proofInputHash))) {
    const proofInputHash = BigInt(summary.proofInputHash);
    const high = `0x${(proofInputHash >> 128n).toString(16)}`;
    const low = `0x${(proofInputHash & ((1n << 128n) - 1n)).toString(16)}`;
    if (BigInt(expected[0]) !== BigInt(high)) issues.push("fact_high_mismatch");
    if (BigInt(expected[1]) !== BigInt(low)) issues.push("fact_low_mismatch");
  }

  const serialized = JSON.stringify(summary);
  for (const sensitive of ["philSecret", "phil_secret", "nullifierSeed", "privateKey", "vaultKey"]) {
    if (serialized.includes(sensitive)) {
      issues.push(`sensitive_field_${sensitive}`);
    }
  }
  return issues;
}

function buildManifest(options = {}) {
  const observedM6A1Success = Boolean(options.observedM6A1Success);
  const toolchain = readJson(TOOLCHAIN_PATH);
  const artifacts = toolchain.expectedArtifacts;
  const summaryInfo = fileInfo(artifacts.proofInputHashSliceSummary);
  let summary = null;
  let summaryIssues = ["summary_missing"];
  if (summaryInfo.present) {
    summary = readJson(path.join(REPO_ROOT, artifacts.proofInputHashSliceSummary));
    summaryIssues = validateSummary(summary);
  }

  const allArtifacts = {
    sierra: fileInfo(artifacts.starknetIntegrationSierra),
    casm: fileInfo(artifacts.starknetIntegrationCasm),
    packageSierra: fileInfo(artifacts.starknetIntegrationPackageSierra),
    starknetArtifacts: fileInfo(artifacts.starknetIntegrationArtifacts),
    proofInputHashSliceArgs: fileInfo(artifacts.proofInputHashSliceArgs),
    proofInputHashSliceSummary: summaryInfo
  };
  const artifactsPresent = Object.values(allArtifacts).every((item) => item.present);
  const parityVerified =
    allArtifacts.proofInputHashSliceArgs.present &&
    summaryInfo.present &&
    summaryIssues.length === 0;

  const packages = {
    cairo_air_adapter_spike: {
      classification: "adapter_spike",
      buildRequired: true,
      buildPassed: observedM6A1Success,
      testApplicable: true,
      testPassed: observedM6A1Success,
      productionApproved: false
    },
    starknet_integration: {
      classification: "production_candidate_contract",
      buildRequired: true,
      buildPassed: observedM6A1Success,
      testApplicable: true,
      testPassed: observedM6A1Success,
      sierraGenerationRequired: true,
      sierraGenerated: allArtifacts.sierra.present,
      casmGenerationRequired: true,
      casmGenerated: allArtifacts.casm.present,
      productionApproved: false
    },
    starknet_integration_runner: {
      classification: "executable_harness",
      buildRequired: true,
      buildPassed: observedM6A1Success,
      testApplicable: false,
      testPassed: null,
      testApplicabilityReason:
        "Scarb 2.15.0 cannot test this executable package without changing its required gas-disabled executable compilation mode; real syscall and L1 relay harnesses are mandatory instead.",
      executionHarnessRequired: true,
      syscallHarnessPassed: observedM6A1Success,
      l1RelayHarnessPassed: observedM6A1Success,
      productionApproved: false
    }
  };

  return {
    version: 1,
    kind: "starknet-verified-fact-publication-readiness",
    status: {
      toolchain_reproducible: observedM6A1Success,
      artifacts_reproducible: artifactsPresent,
      rust_cairo_parity_verified: parityVerified,
      cairo_tests_passed: observedM6A1Success,
      syscall_harness_passed: observedM6A1Success,
      l1_relay_harness_passed: observedM6A1Success,
      deployment_ready: false,
      production_approved: false
    },
    package: {
      name: "phil_starknet_integration",
      contractName: "phil_proof_input_hash_verifier",
      entrypoint: "verify_proof_input_hash_slice_and_send_to_l1"
    },
    toolchain: {
      scarbVersion: toolchain.scarb.version,
      cairoVersion: toolchain.cairo.version,
      rustNightlyToolchain: toolchain.rust.nightlyToolchain,
      nodeVersion: toolchain.node.version,
      npmVersion: toolchain.npm.version
    },
    artifacts: allArtifacts,
    packages,
    messageShape: {
      payload: "[fact_high, fact_low]",
      factHigh: "high128(proofInputHash)",
      factLow: "low128(proofInputHash)",
      l1RecipientConfiguration: "explicit l1_recipient entrypoint argument",
      expectedProofType: "stwo-unlock-keccak-v1",
      proofInputHash: summary ? summary.proofInputHash : null,
      expectedFactPayload: summary ? summary.expectedFactPayload : null
    },
    validation: {
      proofSummaryIssues: summaryIssues
    },
    accountModelStatus: "unresolved",
    deploymentStatus: "not_deployed",
    addressBindingStatus: "unresolved",
    readinessBlockers: [
      ...Object.entries(allArtifacts)
        .filter(([, artifact]) => !artifact.present)
        .map(([name, artifact]) => `${name} artifact missing at ${artifact.path}.`),
      "Starknet account/caller model is unresolved.",
      "No accepted production deployment exists.",
      "Runtime/Starknet Adapter transaction preparation is not implemented.",
      "Deployment readiness remains false until publication configuration, address binding, and account/caller decisions are resolved."
    ]
  };
}

function main() {
  const args = process.argv.slice(2);
  const outIndex = args.indexOf("--out");
  const outPath = outIndex >= 0 ? path.resolve(REPO_ROOT, args[outIndex + 1]) : DEFAULT_OUT;
  const checkOnly = args.includes("--check");
  const manifest = buildManifest({
    observedM6A1Success: args.includes("--observed-m6a1-success")
  });

  if (checkOnly) {
    const existing = fs.existsSync(outPath) ? readJson(outPath) : null;
    const normalizedExisting = existing ? JSON.stringify(existing, null, 2) : null;
    const normalizedNext = JSON.stringify(manifest, null, 2);
    if (normalizedExisting !== normalizedNext) {
      console.error(`Artifact manifest is out of date: ${path.relative(REPO_ROOT, outPath)}`);
      process.exit(1);
    }
    console.log(`Artifact manifest is current: ${path.relative(REPO_ROOT, outPath)}`);
    return;
  }

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Wrote ${path.relative(REPO_ROOT, outPath)}`);
}

if (require.main === module) {
  main();
}

module.exports = {
  buildManifest
};
