"use strict";

const {
  ROOT,
  REQUIRED_AUTOMATED_LANES,
  loadClassification
} = require("./discovery.cjs");
const { runArgv, argvForItem, argvForHardhatUnitFiles } = require("./command-runner.cjs");
const {
  prependPinnedProofToolchainPath
} = require("./install-pinned-starknet-toolchain.cjs");

function usage() {
  console.error(
    "Usage: node scripts/ci/run-lane.cjs <lane> [--dry-run]\n" +
      `Required automated lanes: ${REQUIRED_AUTOMATED_LANES.join(", ")}`
  );
  return 2;
}

function itemsForLane(lane, classification) {
  return classification.items.filter((item) => item.lane === lane);
}

function unitFiles(items) {
  return items
    .filter((item) => item.kind === "unit_test")
    .map((item) => `test/unit/${item.id.replace(/^unit:/, "")}`);
}

function desktopFiles(items) {
  return items
    .filter((item) => item.kind === "desktop_test_file")
    .map((item) => item.id.replace(/^desktop_file:/, ""));
}

function executablePackageItems(items) {
  return items.filter(
    (item) =>
      item.kind === "package_script" &&
      !(item.execution && item.execution.mode === "alias_of")
  );
}

function directlyExecutedPackageItems(items) {
  return items.filter(
    (item) => item.kind === "package_script" && item.execution?.mode === "executed_directly"
  );
}

function desktopExecutedItems(items) {
  const executable = items.filter(entry => entry.kind === "desktop_test_file" || entry.kind === "unit_test"
    || (entry.kind === "package_script" && entry.execution?.mode === "executed_directly"));
  for (const item of items) {
    if (!executable.includes(item) && !(item.kind === "package_script" && item.execution?.mode === "alias_of")) {
      throw new Error(`Unscheduled required Desktop item: ${item.id}`);
    }
  }
  return executable;
}

function printResult(result) {
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
}

function main() {
  const lane = process.argv[2];
  const dryRun = process.argv.includes("--dry-run");
  if (!lane) return usage();

  const classification = loadClassification();
  const items = itemsForLane(lane, classification);
  if (items.length === 0) {
    console.error(`No items classified in lane: ${lane}`);
    return 1;
  }

  console.log(`Running CI lane: ${lane} (${items.length} classified items)`);

  if (lane === "required_product_runtime" || lane === "solidity_erc4337") {
    const unitItems = items.filter((item) => item.kind === "unit_test");
    const packageItems = lane === "required_product_runtime"
      ? directlyExecutedPackageItems(items)
      : [];
    const files = unitFiles(items);
    if (files.length === 0) {
      console.error(`Lane ${lane} has no unit_test items`);
      return 1;
    }
    const compileArgv = ["npx", "hardhat", "compile"];
    if (dryRun) {
      console.log(compileArgv.join(" "));
      // Solidity isolates each file so chain-time from earlier suites cannot
      // invalidate independently green AA22 / expiry-sensitive tests.
      if (lane === "solidity_erc4337") {
        for (const item of unitItems) console.log(argvForItem(item).join(" "));
      } else {
        console.log(argvForHardhatUnitFiles(files).join(" "));
        for (const item of packageItems) console.log(argvForItem(item).join(" "));
      }
      return 0;
    }
    const compile = runArgv(compileArgv);
    printResult(compile);
    if (compile.status !== 0) return compile.status;

    if (lane === "solidity_erc4337") {
      for (const item of unitItems) {
        const argv = argvForItem(item);
        console.log(`$ ${argv.join(" ")}`);
        const result = runArgv(argv);
        printResult(result);
        if (result.status !== 0) return result.status;
      }
      return 0;
    }

    const result = runArgv(argvForHardhatUnitFiles(files));
    printResult(result);
    if (result.status !== 0) return result.status;
    for (const item of packageItems) {
      const argv = argvForItem(item);
      console.log(`$ ${argv.join(" ")}`);
      const packageResult = runArgv(argv);
      printResult(packageResult);
      if (packageResult.status !== 0) return packageResult.status;
    }
    return 0;
  }

  if (lane === "desktop") {
    const files = desktopFiles(items);
    if (files.length === 0) {
      console.error("Desktop lane has no desktop_test_file items");
      return 1;
    }
    // Intentionally does NOT call npm run desktop:test — that aggregate mixes
    // physical/manual suites and omits required desktop files.
    console.log(`Desktop automated compatibility files: ${files.length}`);
    for (const item of desktopExecutedItems(items)) {
      const argv = argvForItem(item);
      console.log(`$ ${argv.join(" ")}`);
      if (dryRun) continue;
      const result = runArgv(argv);
      printResult(result);
      if (result.status !== 0) return result.status;
    }
    return 0;
  }

  if (lane === "proving") {
    const files = unitFiles(items);
    const packageItems = executablePackageItems(items);
    const provingEnv = prependPinnedProofToolchainPath();
    const cargoItem = items.find((item) => item.kind === "proving_target");
    if (!cargoItem) {
      console.error("Proving lane missing proving_target");
      return 1;
    }
    if (dryRun) {
      if (files.length) console.log(argvForHardhatUnitFiles(files).join(" "));
      for (const item of packageItems) console.log(argvForItem(item).join(" "));
      console.log(argvForItem(cargoItem).join(" "));
      return 0;
    }
    if (files.length) {
      const compile = runArgv(["npx", "hardhat", "compile"]);
      printResult(compile);
      if (compile.status !== 0) return compile.status;
      const hardhat = runArgv(argvForHardhatUnitFiles(files));
      printResult(hardhat);
      if (hardhat.status !== 0) return hardhat.status;
    }
    for (const item of packageItems) {
      const argv = argvForItem(item);
      console.log(`$ ${argv.join(" ")}`);
      const packageResult = runArgv(argv, { env: provingEnv });
      printResult(packageResult);
      if (packageResult.status !== 0) return packageResult.status;
    }
    // Constant cargo argv from argvForItem — no shell.
    const result = runArgv(argvForItem(cargoItem));
    printResult(result);
    return result.status;
  }

  if (lane === "deterministic_evidence") {
    const commands = items.filter(
      (item) =>
        (item.kind === "package_script" || item.kind === "evidence_check") &&
        !(item.execution && item.execution.mode === "alias_of")
    );
    for (const item of commands) {
      if (item.execution && item.execution.mode === "workflow_step") {
        // Still executed here when the lane is invoked locally; workflow also names the step.
      }
      const argv = argvForItem(item);
      console.log(`$ ${argv.join(" ")}`);
      if (dryRun) continue;
      const result = runArgv(argv);
      printResult(result);
      if (result.status !== 0) return result.status;
    }
    // Unit tests classified into this lane (e.g. legacy lock + provenance schema
    // mechanics) must run on every deterministic-evidence CI invocation.
    const files = unitFiles(items);
    if (files.length) {
      const argv = argvForHardhatUnitFiles(files);
      console.log(`$ ${argv.join(" ")}`);
      if (!dryRun) {
        const result = runArgv(argv);
        printResult(result);
        if (result.status !== 0) return result.status;
      }
    }
    return 0;
  }

  console.error(
    `Lane ${lane} is not an executable required automated lane. ` +
      "Use run-historical-baseline.cjs for historical checks."
  );
  return 2;
}

if (require.main === module) {
  // Natural shutdown drains stdout/stderr, including the final Simulator result.
  process.exitCode = main();
}

module.exports = {
  itemsForLane,
  desktopExecutedItems,
  unitFiles,
  desktopFiles,
  executablePackageItems,
  directlyExecutedPackageItems
};
