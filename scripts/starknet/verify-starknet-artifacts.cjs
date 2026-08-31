const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const REPO_ROOT = path.resolve(__dirname, "../..");
const TOOLCHAIN_PATH = path.join(REPO_ROOT, "config/starknet-toolchain.json");

function expandHome(value) {
  if (!value || typeof value !== "string") return value;
  if (value === "~") return process.env.HOME || value;
  if (value.startsWith("~/")) return path.join(process.env.HOME || "", value.slice(2));
  return value;
}

function toolchainEnv() {
  const toolchain = JSON.parse(fs.readFileSync(TOOLCHAIN_PATH, "utf8"));
  const dirs = [
    toolchain.scarb?.pinnedBinary ? path.dirname(expandHome(toolchain.scarb.pinnedBinary)) : undefined,
    toolchain.cairo?.pinnedBinaryDirectory ? expandHome(toolchain.cairo.pinnedBinaryDirectory) : undefined
  ].filter(Boolean);
  return {
    ...process.env,
    PATH: `${dirs.join(path.delimiter)}${path.delimiter}${process.env.PATH || ""}`
  };
}

function run(label, command, args, options = {}) {
  console.log(`\n== ${label}`);
  console.log([command, ...args].join(" "));
  const result = spawnSync(command, args, {
    cwd: options.cwd || REPO_ROOT,
    stdio: "inherit",
    env: toolchainEnv(),
    shell: false
  });
  if (result.status !== 0) {
    throw new Error(`${label} failed with exit code ${result.status}`);
  }
}

function main() {
  const skipHarnesses = process.argv.includes("--skip-harnesses");
  const packages = [
    {
      dir: "cairo_air_adapter_spike",
      classification: "adapter_spike",
      scarbTestApplicable: true
    },
    {
      dir: "starknet_integration",
      classification: "production_candidate_contract",
      scarbTestApplicable: true
    },
    {
      dir: "starknet_integration_runner",
      classification: "executable_harness",
      scarbTestApplicable: false,
      reason:
        "Scarb 2.15.0 cannot test this executable package without changing its required gas-disabled executable compilation mode; real syscall and L1 relay harnesses are mandatory instead."
    }
  ];

  run("check Starknet toolchain", "node", [
    "scripts/starknet/check-starknet-toolchain.cjs"
  ]);

  console.log("\n== Starknet package verification matrix");
  for (const packageConfig of packages) {
    console.log(`${packageConfig.dir}:`);
    console.log(`  package_classification: ${packageConfig.classification}`);
    console.log("  build_required: true");
    console.log(`  scarb_test_applicable: ${packageConfig.scarbTestApplicable}`);
    if (packageConfig.reason) console.log(`  scarb_test_reason: ${packageConfig.reason}`);
    console.log(
      `  execution_harness_required: ${packageConfig.dir === "starknet_integration_runner"}`
    );
  }

  for (const packageConfig of packages) {
    run(`scarb build ${packageConfig.dir}`, "scarb", ["build"], {
      cwd: path.join(REPO_ROOT, packageConfig.dir)
    });
    if (packageConfig.scarbTestApplicable) {
      run(`scarb test ${packageConfig.dir}`, "scarb", ["test"], {
        cwd: path.join(REPO_ROOT, packageConfig.dir)
      });
    } else {
      console.log(`\n== scarb test ${packageConfig.dir}`);
      console.log("skipped: not applicable for executable harness package");
      console.log(packageConfig.reason);
    }
  }

  run("regenerate proof-input-hash slice args", "cargo", [
    "+nightly-2025-07-14",
    "run",
    "--manifest-path",
    "Cargo.toml",
    "--bin",
    "cairo_air_adapter_spike"
  ], {
    cwd: path.join(REPO_ROOT, "proving")
  });

  run("generate Starknet artifact manifest", "node", [
    "scripts/starknet/generate-starknet-artifact-manifest.cjs"
  ]);

  run("Rust proving tests", "npm", ["run", "test:proving"]);

  if (!skipHarnesses) {
    run("Starknet syscall harness", "cargo", [
      "+nightly-2025-07-14",
      "run",
      "--manifest-path",
      "proving/Cargo.toml",
      "--bin",
      "starknet-syscall-harness"
    ]);

    run("Starknet L1 relay harness", "cargo", [
      "+nightly-2025-07-14",
      "run",
      "--manifest-path",
      "proving/Cargo.toml",
      "--bin",
      "starknet-l1-relay-harness"
    ]);
  }

  if (!skipHarnesses) {
    run("record observed M.6A.1 readiness", "node", [
      "scripts/starknet/generate-starknet-artifact-manifest.cjs",
      "--observed-m6a1-success"
    ]);

    run("check observed M.6A.1 readiness manifest", "node", [
      "scripts/starknet/generate-starknet-artifact-manifest.cjs",
      "--observed-m6a1-success",
      "--check"
    ]);
  }

  const manifestPath = path.join(REPO_ROOT, "config/starknet-publication-readiness.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error("missing config/starknet-publication-readiness.json");
  }
  console.log("\nStarknet artifact verification complete.");
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`\n${error && error.message ? error.message : error}`);
    process.exit(1);
  }
}
