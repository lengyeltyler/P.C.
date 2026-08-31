"use strict";

const {
  LANES,
  REQUIRED_AUTOMATED_LANES,
  EXECUTION_MODES,
  PROHIBITED_ALLOWLIST_IDS,
  discoverUniverse,
  loadClassification,
  loadHistoricalManifest,
  commandLooksProhibited
} = require("./discovery.cjs");

function laneTotals(items) {
  const totals = {};
  for (const lane of LANES) totals[lane] = 0;
  for (const item of items) {
    if (totals[item.lane] !== undefined) totals[item.lane] += 1;
  }
  return totals;
}

function isOfflineTestItem(item) {
  if (item.kind === "unit_test" || item.kind === "desktop_test_file") return true;
  if (typeof item.command !== "string") return false;
  return /\bhardhat test\b/.test(item.command) || /\.test\.cjs\b/.test(item.command);
}

function validateHistoricalBijection(classification, manifest) {
  const errors = [];
  const historicalIds = classification.items
    .filter((item) => item.lane === "historical_known_baseline")
    .map((item) => item.id)
    .sort();
  const manifestIds = (manifest.entries || []).map((entry) => entry.id).sort();
  const histSet = new Set(historicalIds);
  const manSet = new Set(manifestIds);

  for (const id of historicalIds) {
    if (!manSet.has(id)) errors.push(`historical classification missing manifest entry: ${id}`);
  }
  for (const id of manifestIds) {
    if (!histSet.has(id)) {
      errors.push(`historical manifest has extra entry (not classified historical): ${id}`);
    }
  }
  if (manifestIds.length !== new Set(manifestIds).size) {
    errors.push("historical manifest contains duplicate ids");
  }
  return errors;
}

function validateHistoricalManifestPolicy(manifest) {
  const errors = [];
  if (manifest.schemaVersion !== 3) {
    errors.push(`historical manifest schemaVersion must be 3, got ${manifest.schemaVersion}`);
  }
  const policy = manifest.failureStatePolicy;
  if (!policy || !Array.isArray(policy.expectedFailureIds)
    || !Array.isArray(policy.retiredIds)) {
    return [...errors, "historical manifest failureStatePolicy is required"];
  }
  const entryIds = (manifest.entries || []).map((entry) => entry.id);
  const expected = new Set(policy.expectedFailureIds);
  const retired = new Set(policy.retiredIds);
  for (const id of expected) {
    if (retired.has(id)) errors.push(`historical id cannot be expected and retired: ${id}`);
    if (!entryIds.includes(id)) errors.push(`expected historical id missing entry: ${id}`);
  }
  for (const id of retired) {
    if (entryIds.includes(id)) errors.push(`retired historical id still has executable entry: ${id}`);
  }
  for (const id of entryIds) {
    if (!expected.has(id)) errors.push(`historical entry is not declared expected: ${id}`);
  }
  if (policy.expectedFailureIds.length !== expected.size) {
    errors.push("historical expectedFailureIds contains duplicates");
  }
  if (policy.retiredIds.length !== retired.size) {
    errors.push("historical retiredIds contains duplicates");
  }
  const drift = policy.normalizationToolchainDrift;
  if (!drift || drift.classification !== "node_major_stack_shape_only"
    || drift.semanticIdentityRequiredUnchanged !== true
    || !Array.isArray(drift.ids)) {
    errors.push("historical normalizationToolchainDrift policy is malformed");
  } else {
    const byId = new Map((manifest.entries || []).map((entry) => [entry.id, entry]));
    for (const id of drift.ids) {
      if (!expected.has(id)) errors.push(`normalization drift id is not expected: ${id}`);
      if (byId.get(id)?.matcher !== "structured_error") {
        errors.push(`normalization drift id must use structured_error matcher: ${id}`);
      }
    }
  }
  return errors;
}

function validateExecutionMappings(classification) {
  const errors = [];
  const byId = new Map(classification.items.map((item) => [item.id, item]));

  for (const item of classification.items) {
    if (item.kind !== "package_script" && item.kind !== "evidence_check") continue;
    if (
      !REQUIRED_AUTOMATED_LANES.includes(item.lane) &&
      item.lane !== "historical_known_baseline"
    ) {
      continue;
    }

    const mode = item.execution && item.execution.mode;
    if (!mode || !EXECUTION_MODES.includes(mode)) {
      if (REQUIRED_AUTOMATED_LANES.includes(item.lane) || item.lane === "historical_known_baseline") {
        errors.push(
          `package/evidence script ${item.id} in ${item.lane} missing execution.mode (${EXECUTION_MODES.join("|")})`
        );
      }
      continue;
    }

    if (mode === "alias_of") {
      const target = item.execution.aliasOf;
      if (!target || !byId.has(target)) {
        errors.push(`${item.id} execution.aliasOf missing or unknown: ${target}`);
      } else if (byId.get(target).lane !== item.lane) {
        errors.push(
          `${item.id} alias target ${target} is in lane ${byId.get(target).lane}, expected ${item.lane}`
        );
      }
    }

    if (mode === "workflow_step") {
      if (!item.execution.workflowStep || typeof item.execution.workflowStep !== "string") {
        errors.push(`${item.id} execution.workflowStep must name the workflow step`);
      }
    }
  }

  for (const lane of ["required_product_runtime", "solidity_erc4337", "historical_known_baseline"]) {
    const items = classification.items.filter((item) => item.lane === lane);
    const units = items.filter((item) => item.kind === "unit_test");
    const aliases = items.filter(
      (item) => item.kind === "package_script" && item.execution && item.execution.mode === "alias_of"
    );
    for (const alias of aliases) {
      const target = alias.execution.aliasOf;
      if (!units.some((unit) => unit.id === target) && !byId.has(target)) {
        errors.push(`${alias.id} claims alias_of ${target} but target is unknown`);
      } else if (byId.has(target) && byId.get(target).lane !== lane) {
        errors.push(`${alias.id} alias target ${target} not in lane ${lane}`);
      }
    }
  }

  return errors;
}

function validateClassification(
  classification = loadClassification(),
  universe = discoverUniverse(),
  manifest = loadHistoricalManifest()
) {
  const errors = [];
  const byId = new Map();

  if (!Array.isArray(classification.items)) {
    errors.push("classification.items must be an array");
    return { ok: false, errors };
  }

  for (const item of classification.items) {
    if (!item || typeof item.id !== "string") {
      errors.push("classification item missing id");
      continue;
    }
    if (byId.has(item.id)) {
      errors.push(`duplicate classification id: ${item.id}`);
    }
    byId.set(item.id, item);

    if (!LANES.includes(item.lane)) {
      errors.push(`unknown lane for ${item.id}: ${item.lane}`);
    }
    if (typeof item.command !== "string" || item.command.length === 0) {
      errors.push(`missing command for ${item.id}`);
    }
  }

  for (const expectedId of universe.expectedIds) {
    if (!byId.has(expectedId)) {
      errors.push(`unclassified item: ${expectedId}`);
    }
  }

  for (const id of byId.keys()) {
    if (!universe.expectedIds.includes(id)) {
      if (id !== "evidence:o37-10-v2-minimal-account:check") {
        errors.push(`classified unknown item (not discovered): ${id}`);
      }
    }
  }

  for (const lane of REQUIRED_AUTOMATED_LANES) {
    const commands = classification.items.filter((item) => item.lane === lane);
    if (commands.length === 0) {
      errors.push(`required lane has no commands: ${lane}`);
    }
  }

  for (const item of classification.items) {
    if (!REQUIRED_AUTOMATED_LANES.includes(item.lane)) continue;
    if (PROHIBITED_ALLOWLIST_IDS.has(item.id)) continue;
    if (isOfflineTestItem(item)) continue;
    if (commandLooksProhibited(item.command)) {
      errors.push(
        `prohibited public-network/ceremony command in automated lane ${item.lane}: ${item.id} -> ${item.command}`
      );
    }
  }

  for (const badId of ["script:test", "script:test:unit"]) {
    const item = byId.get(badId);
    if (item && REQUIRED_AUTOMATED_LANES.includes(item.lane)) {
      errors.push(`${badId} must not be in a required automated lane`);
    }
  }

  const pairs = [
    ["script:test:o37-1-recovery-evidence", "unit:o37-1-v2-recovery-evidence.test.cjs"],
    ["script:test:o37-2-deterministic-fixtures", "unit:o37-2-v2-deterministic-fixtures.test.cjs"],
    ["script:test:o37-4-authority-transport", "unit:o37-4-v2-authority-transport.test.cjs"]
  ];
  for (const [scriptId, unitId] of pairs) {
    const script = byId.get(scriptId);
    const unit = byId.get(unitId);
    if (script && unit && script.lane !== unit.lane) {
      errors.push(
        `${scriptId} lane ${script.lane} disagrees with ${unitId} lane ${unit.lane}`
      );
    }
  }

  errors.push(...validateHistoricalBijection(classification, manifest));
  errors.push(...validateHistoricalManifestPolicy(manifest));
  errors.push(...validateExecutionMappings(classification));

  const computedTotals = laneTotals(classification.items);
  for (const lane of LANES) {
    if (!classification.totals || classification.totals[lane] !== computedTotals[lane]) {
      errors.push(
        `declared total mismatch for ${lane}: ${classification.totals && classification.totals[lane]} !== ${computedTotals[lane]}`
      );
    }
  }

  return { ok: errors.length === 0, errors, counts: computedTotals };
}

function main() {
  const result = validateClassification();
  if (!result.ok) {
    console.error("CI classification validation failed:");
    for (const error of result.errors) console.error(` - ${error}`);
    process.exit(1);
  }
  console.log("CI classification validation passed");
  console.log(JSON.stringify(result.counts, null, 2));
}

if (require.main === module) {
  main();
}

module.exports = {
  validateClassification,
  validateHistoricalBijection,
  validateHistoricalManifestPolicy,
  validateExecutionMappings,
  laneTotals
};
