#!/usr/bin/env node
"use strict";

const {
  buildReleaseArtifactLineage,
  dryRunReport
} = require("./release-artifact-lineage.cjs");

if (!process.argv.includes("--dry-run")) {
  console.error(JSON.stringify({ status: "blocked", reason: "explicit_--dry-run_required" }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify(dryRunReport(buildReleaseArtifactLineage()), null, 2));
