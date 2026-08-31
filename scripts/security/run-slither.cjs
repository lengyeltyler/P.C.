#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  assertNoAbsoluteDeveloperPaths,
  sanitizeSlitherReport
} = require("./sanitize-slither-report.cjs");

const repoRoot = path.resolve(__dirname, "..", "..");
const toolchain = JSON.parse(fs.readFileSync(path.join(repoRoot, "config/security/slither-toolchain.json"), "utf8"));
const venvPath = path.join(repoRoot, toolchain.venvPath);
const slitherBin = path.join(venvPath, "bin/slither");
const reportPath = path.join(repoRoot, "config/security/philcore-solidity-static-analysis.json");
const rawPath = path.join(repoRoot, "config/security/philcore-slither-results.raw.json");

function listSoliditySources(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return listSoliditySources(absolute);
    if (!entry.isFile() || !entry.name.endsWith(".sol")) return [];
    return [path.relative(repoRoot, absolute)];
  });
}

const scope = listSoliditySources(path.join(repoRoot, "contracts")).sort();

function run(command, args) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    env: process.env
  });
}

function writeReport(payload) {
  const sanitized = sanitizeSlitherReport(payload, repoRoot);
  assertNoAbsoluteDeveloperPaths(sanitized);
  fs.writeFileSync(reportPath, `${JSON.stringify(sanitized, null, 2)}\n`);
}

if (!fs.existsSync(slitherBin)) {
  writeReport({
    phase: "O.19",
    status: "blocked",
    reason: "slither_venv_missing",
    expectedVersion: toolchain.slither.version,
    setupCommand: "npm run security:setup-slither",
    scope
  });
  console.error(`Slither environment missing at ${toolchain.venvPath}. Run npm run security:setup-slither.`);
  process.exit(1);
}

const version = run(slitherBin, ["--version"]);
const installedVersionOutput = `${version.stdout}${version.stderr}`.trim();
const publicVersionOutput = sanitizeSlitherReport(installedVersionOutput, repoRoot);
const installedVersion = installedVersionOutput.split(/\r?\n/)[0];
if (version.status !== 0 || !installedVersionOutput.includes(toolchain.slither.version)) {
  writeReport({
    phase: "O.19",
    status: "blocked",
    reason: "slither_version_mismatch",
    expectedVersion: toolchain.slither.version,
    installedVersion: publicVersionOutput,
    scope
  });
  console.error(`Expected Slither ${toolchain.slither.version}; got ${publicVersionOutput || "unavailable"}.`);
  process.exit(1);
}

const startedAt = new Date().toISOString();
const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-slither-"));
const unsanitizedRawPath = path.join(temporaryDirectory, "slither.raw.json");
let analysis;
let raw = null;
try {
  analysis = run(slitherBin, [
    ".",
    "--config-file",
    "slither.config.json",
    "--json",
    unsanitizedRawPath
  ]);
  if (fs.existsSync(unsanitizedRawPath)) {
    raw = sanitizeSlitherReport(
      JSON.parse(fs.readFileSync(unsanitizedRawPath, "utf8")),
      repoRoot
    );
    assertNoAbsoluteDeveloperPaths(raw);
    fs.writeFileSync(rawPath, `${JSON.stringify(raw, null, 2)}\n`);
  }
} finally {
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
}

const detectors = raw?.results?.detectors || [];
const totalsByImpact = detectors.reduce((acc, finding) => {
  const impact = finding.impact || "Unknown";
  acc[impact] = (acc[impact] || 0) + 1;
  return acc;
}, {});

function classifyFinding(finding) {
  const filename = finding.elements?.[0]?.source_mapping?.filename_relative || "";
  const detector = finding.check || "unknown";
  const impact = finding.impact || "Unknown";

  if (filename.includes("/mocks/") || filename.startsWith("contracts/test/")) {
    return {
      classification: "accepted_local_only",
      exploitScenario: "Finding is in a mock/adversarial fixture used for local tests.",
      applicability: "local_test_fixture_only",
      remediation: "No production remediation; keep mocks excluded from deployment scope.",
      status: "accepted_local_only",
      regression: "N6 custom invariant checks and existing local fixture tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (filename.endsWith("PhilMintPassConsumer.sol") && detector === "locked-ether") {
    const mintSource = fs.readFileSync(path.join(repoRoot, "contracts/base/PhilMintPassConsumer.sol"), "utf8");
    const zeroValueGuarded = mintSource.includes("error UnexpectedMintPassValue()")
      && mintSource.includes("if (msg.value != 0) revert UnexpectedMintPassValue();");
    return {
      classification: zeroValueGuarded ? "accepted_zero_value_only" : "true_positive",
      exploitScenario: zeroValueGuarded
        ? "The authorization consumer interface is payable, but the MintPass implementation rejects nonzero msg.value before mint state changes."
        : "If a caller forwards ETH into the mint-pass consumer path, ETH can remain in the consumer because it has no withdrawal or refund behavior.",
      applicability: zeroValueGuarded
        ? "production_relevant_consumer_with_zero_value_only_policy"
        : "production_relevant_consumer_but_not_base_sepolia_beta_account_gate_scope",
      remediation: zeroValueGuarded
        ? "N.7 added an explicit UnexpectedMintPassValue guard and regression/invariant coverage; any future value-bearing mint path requires Architecture Change Control and a reviewed forwarding/refund model."
        : "Before deploying this consumer with value-bearing paths, either reject nonzero msg.value or add an explicitly reviewed recovery/refund model.",
      status: zeroValueGuarded ? "remediated" : "open",
      regression: zeroValueGuarded
        ? "N.7 MintPass nonzero-value regression test and N7-INV-018 custom invariant."
        : "No remediation applied; finding preserved for targeted remediation.",
      betaBlocking: false,
      productionBlocking: !zeroValueGuarded
    };
  }

  if (detector === "timestamp") {
    return {
      classification: "intended_time_boundary",
      exploitScenario: "Timestamp use controls explicit recovery delay/expiry or authorization expiry windows.",
      applicability: "accepted_design_with_testnet_finality_limitations",
      remediation: "No code change in N.6; preserve tests for early completion, expiry, and authorization expiry behavior.",
      status: "false_positive",
      regression: "Recovery and authorization expiry tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (
    detector === "incorrect-equality" &&
    filename.endsWith("PhilCoreV2MinimalAccountV2.sol") &&
    finding.description.includes("requested == 0")
  ) {
    return {
      classification: "intended_zero_timestamp_sentinel",
      exploitScenario: "The equality is a read-only projection of the explicit zero timestamp sentinel used when no recovery request exists; it does not compare balances, prices, or authorization quantities.",
      applicability: "recovery_view_projection_only",
      remediation: "Retain the zero sentinel and the pending-recovery tuple regression coverage.",
      status: "false_positive",
      regression: "O.37.10 recovery lifecycle tests and recovery FSM invariant suite.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (
    ["reentrancy-eth", "reentrancy-no-eth"].includes(detector) &&
    filename.endsWith("PhilCoreV2MinimalAccountV2.sol") &&
    ["transferNative", "withdrawEntryPointDeposit", "confirmIntent"].some((name) =>
      finding.description.includes(name)
    )
  ) {
    const accountSource = fs.readFileSync(
      path.join(repoRoot, "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol"),
      "utf8"
    );
    const guarded =
      accountSource.includes(
        "_enterExecution();\n        (bool success,) = recipient.call{value: amountWei}(\"\");"
      ) &&
      accountSource.includes(
        "_enterExecution();\n        try IPhilCoreV2ConfirmationTarget(_confirmationTarget)"
      ) &&
      accountSource.includes(
        "_enterExecution();\n        try _entryPoint.withdrawTo(recipient, amountWei)"
      ) &&
      accountSource.includes(
        "function _requireEntryPoint() private view {\n        if (msg.sender != address(_entryPoint)) revert UnauthorizedEntryPoint();\n        if (_executionLock) revert InvalidExecution(7);"
      ) &&
      accountSource.includes(
        "function settleRecovery(bytes32 recoveryRequestId) external {\n        if (_executionLock) revert InvalidExecution(7);"
      ) &&
      accountSource.includes(
        "function settleRecoveryConfigRotation(bytes32 rotationRequestId) external {\n        if (_executionLock) revert InvalidExecution(7);"
      ) &&
      accountSource.includes("receive() external payable {}") &&
      accountSource.includes("function _enterExecution() private") &&
      accountSource.includes("_executionLock = true;");
    return {
      classification: guarded
        ? "accepted_explicit_reentrancy_guard"
        : "true_positive",
      exploitScenario: guarded
        ? "The detector observes the intentional lock release after the native-value call. All EntryPoint-authorized state transitions and both permissionless settlement paths reject while the lock is set; receive() is state-free."
        : "The native-value call may permit cross-function reentrancy if the explicit execution lock is absent or incomplete.",
      applicability: "production_relevant_native_transfer_with_explicit_cross_function_guard",
      remediation: guarded
        ? "Retain the execution lock and its cross-function regression coverage; require fresh review if a new unguarded state-changing external surface is added."
        : "Block release until a complete cross-function reentrancy guard is restored.",
      status: guarded ? "false_positive" : "open",
      regression: "O.37.10 lifecycle reentrancy tests and account execution-lock assertions.",
      betaBlocking: !guarded,
      productionBlocking: !guarded
    };
  }

  if (detector === "unused-return" && finding.description.includes("ECDSA.tryRecover")) {
    return {
      classification: "intended_checked_signature_projection",
      exploitScenario: "OpenZeppelin tryRecover returns an auxiliary error argument in addition to the recovered address and error enum. Phil checks both security-relevant values and intentionally omits only that auxiliary detail.",
      applicability: "signature_verification_error_detail_only",
      remediation: "No code change; retain malformed-signature and signer-binding regressions.",
      status: "false_positive",
      regression: "Validator-envelope, recovery-factor, and local-proof signature verification tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (
    detector === "unused-return" &&
    filename.endsWith("PhilCoreV2ConfirmationTargetV1.sol") &&
    finding.description.includes("accountConfiguration()")
  ) {
    return {
      classification: "intended_configuration_tuple_projection",
      exploitScenario: "The confirmation target reads only the chain, version, security-model, and target bindings it is authorized to enforce; omitted configuration fields do not influence confirmation acceptance.",
      applicability: "confirmation_binding_projection_only",
      remediation: "No code change; retain malformed, reverting, and mismatched configuration-target tests.",
      status: "false_positive",
      regression: "V2 confirmation-target binding and malformed-configuration tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (detector === "assembly") {
    return {
      classification: "reviewed_bounded_assembly",
      exploitScenario: "The production assembly sites perform bounded ABI/calldata reads, fixed-size verifier-binding calls, or the EntryPoint prefund transfer; no generic execution authority is introduced.",
      applicability: "production_relevant_bounded_low_level_implementation",
      remediation: "Retain exact-length, canonical-encoding, verifier-binding, prefund, and conformance tests; include these sites in external audit scope before production.",
      status: "deferred_external_audit",
      regression: "V2 lifecycle, decoder, verifier-binding, recovery-factor, prefund, and ERC-7562 conformance tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (
    detector === "immutable-states" &&
    filename.endsWith("PhilCoreV2MinimalAccountV2.sol") &&
    finding.description.includes("_validatorVerifierKind")
  ) {
    return {
      classification: "informational_storage_layout_preserved",
      exploitScenario: "This is a gas-optimization suggestion, not an authority or state-integrity finding. The field is constructor-bound and retained in the frozen account security-state layout.",
      applicability: "non_security_optimization_with_frozen_layout",
      remediation: "Do not alter the frozen layout solely for this optimization; revisit only through Architecture Change Control.",
      status: "false_positive",
      regression: "O.37.9 storage-layout lock and V2 account initialization tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (detector === "reentrancy-events" || detector === "reentrancy-benign") {
    return {
      classification: "reviewed_no_state_authority_escalation",
      exploitScenario: "External call/event ordering is present, but N.6 review did not identify a high-impact authority escalation in the bounded route.",
      applicability: "requires_deployment_configuration_review_and_external_audit",
      remediation: "Keep deployment verification and external audit requirements before public Beta/production.",
      status: impact === "Low" ? "deferred_external_audit" : "open",
      regression: "ActionGate atomicity and cross-domain route tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (detector === "low-level-calls") {
    return {
      classification: "intended_bounded_external_call",
      exploitScenario: "PhilCore intentionally performs bounded calls through ActionGate/consumer routes; generic wallet execution remains blocked by custom invariants.",
      applicability: "bounded_authorization_or_fixture_path",
      remediation: "No code change in N.6; custom invariant checks enforce target/selector restrictions.",
      status: "false_positive",
      regression: "N6-INV-001 through N6-INV-017.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (["missing-inheritance", "too-many-digits", "cyclomatic-complexity"].includes(detector)) {
    return {
      classification: "informational_reviewed",
      exploitScenario: "No direct exploit path identified from this informational detector.",
      applicability: "code_quality_or_detector_limitation",
      remediation: "Track for audit readability; no N.6 behavior change.",
      status: "false_positive",
      regression: "Compile and existing focused tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  if (detector === "missing-zero-check") {
    return {
      classification: "reviewed_low_risk",
      exploitScenario: "Zero-address validation warning requires context-specific review.",
      applicability: "not_high_or_critical",
      remediation: "No N.6 behavior change; address only if found in production deployment path.",
      status: "deferred_external_audit",
      regression: "Compile and existing focused tests.",
      betaBlocking: false,
      productionBlocking: false
    };
  }

  return {
    classification: "requires_triage",
    exploitScenario: "Manual triage required.",
    applicability: "unclassified",
    remediation: "Classify before Beta if detector impact is Medium or above.",
    status: "open",
    regression: "none_recorded",
    betaBlocking: ["High", "Critical"].includes(impact),
    productionBlocking: ["Medium", "High", "Critical"].includes(impact)
  };
}

const findings = detectors.map((finding, index) => ({
  ...(() => {
    const triage = classifyFinding(finding);
    return {
      id: `N6-SLITHER-${String(index + 1).padStart(3, "0")}`,
      detector: finding.check,
      impact: finding.impact,
      confidence: finding.confidence,
      description: finding.description,
      firstElement: finding.elements?.[0]?.source_mapping
        ? {
            filename: finding.elements[0].source_mapping.filename_relative,
            lines: finding.elements[0].source_mapping.lines
          }
        : null,
      ...triage
    };
  })()
}));

const triageSummary = {
  requiresTriage: findings.filter((finding) => finding.classification === "requires_triage").length,
  betaBlocking: findings.filter((finding) => finding.betaBlocking).length,
  productionBlocking: findings.filter((finding) => finding.productionBlocking).length,
  byStatus: findings.reduce((acc, finding) => {
    acc[finding.status] = (acc[finding.status] || 0) + 1;
    return acc;
  }, {})
};

const status = analysis.status === 0 ? "passed" : findings.length > 0 ? "completed_with_findings" : "failed";
writeReport({
  phase: "O.19",
  status,
  nonAuditDisclaimer: "Slither output is internal static-analysis evidence, not a formal external audit.",
  startedAt,
  completedAt: new Date().toISOString(),
  toolchain: {
    model: toolchain.selectedModel,
    slitherVersion: installedVersion,
    slitherVersionWarnings: publicVersionOutput.split(/\r?\n/).slice(1),
    venvPath: toolchain.venvPath,
    hardhatVersion: toolchain.solidity.hardhatVersion,
    compilerVersion: toolchain.solidity.compilerVersion,
    compilerScope: toolchain.solidity.compilerScope,
    viaIR: toolchain.solidity.viaIR,
    optimizer: toolchain.solidity.optimizer
  },
  scope,
  command: `npm run security:slither`,
  rawReport: path.relative(repoRoot, rawPath),
  detectorTotals: {
    total: detectors.length,
    byImpact: totalsByImpact
  },
  triageSummary,
  findings,
  unresolvedCriticalOrHigh: findings.filter((finding) => finding.betaBlocking),
  betaGateImpact: findings.some((finding) => finding.betaBlocking)
    ? "blocked_pending_slither_triage"
    : "slither_completed_no_high_or_critical_findings_detected"
});

if (analysis.status !== 0 && findings.length === 0) {
  console.error(analysis.stdout);
  console.error(analysis.stderr);
  process.exit(analysis.status ?? 1);
}

process.stdout.write(fs.readFileSync(reportPath, "utf8"));
if (findings.some((finding) => finding.betaBlocking)) {
  process.exit(2);
}
