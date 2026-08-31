#!/usr/bin/env node

async function main() {
  const { runAlpha0Shell } = await import(
    "../apps/phil-device-sdk/src/runtime/alpha0Shell.ts"
  );
  const result = await runAlpha0Shell({
    argv: process.argv.slice(2),
    input: process.stdin,
    output: process.stdout,
    errorOutput: process.stderr
  });
  process.exitCode = result.exitCode;
}

main().catch((error) => {
  console.error("Alpha 0 shell failed.");
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
