#!/usr/bin/env node

async function main() {
  const { runNonAuthoritativeAlpha0Demo } = await import(
    "../apps/phil-device-sdk/src/runtime/alpha0Demo.ts"
  );
  const scenario = process.argv[2] ?? "ordinary_success";
  const strictFailures = process.argv.includes("--strict-failures");
  const result = await runNonAuthoritativeAlpha0Demo({
    scenario,
    strictFailures
  });

  console.log(`PhilCore Alpha 0 demo: ${result.scenario}`);
  console.log(`Status: ${result.status}`);
  console.log("");
  for (const stage of result.stages) {
    const outcome = stage.outcome ? ` (${stage.outcome})` : "";
    const artifact = stage.artifactId ? ` :: ${stage.artifactId}` : "";
    console.log(`- ${stage.status}: ${stage.stage}${outcome}${artifact}`);
    console.log(`  ${stage.summary}`);
  }
  console.log("");
  console.log(`Audit drafts: ${result.auditDraftCount}`);
  console.log(`World ID required for chosen context: ${result.worldIdRequiredForChosenContext}`);
  console.log("Non-authority flags:");
  console.log(`- fixtureOnly: ${result.fixtureOnly}`);
  console.log(`- productionAuthenticationPerformed: ${result.productionAuthenticationPerformed}`);
  console.log(`- productionUserConsentCollected: ${result.productionUserConsentCollected}`);
  console.log(`- worldIdEnrollmentVerified: ${result.worldIdEnrollmentVerified}`);
  console.log(`- activeCapabilityCreated: ${result.activeCapabilityCreated}`);
  console.log(`- authorizationCreated: ${result.authorizationCreated}`);
  console.log(`- proofExecuted: ${result.proofExecuted}`);
  console.log(`- adapterExecuted: ${result.adapterExecuted}`);
  console.log(`- persisted: ${result.persisted}`);
  if (result.failure) {
    console.log("");
    console.log(`Stopped at: ${result.failure.stage}`);
    console.log(`Reason: ${result.failure.reason}`);
  }

  if (result.status === "failed" && strictFailures) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
