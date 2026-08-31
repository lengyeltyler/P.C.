"use strict";

const assert = require("node:assert/strict");

const {
  discoverUniverse,
  loadClassification,
  loadHistoricalManifest,
  commandLooksProhibited,
  ROOT
} = require("../../scripts/ci/discovery.cjs");
const {
  validateClassification,
  validateHistoricalManifestPolicy
} = require("../../scripts/ci/validate-classification.cjs");
const {
  normalizeFailureText,
  parseMochaFailures,
  sha256,
  failuresEqualExact,
  normalizedStreamDigests
} = require("../../scripts/ci/normalize-failures.cjs");
const { matchHistoricalResult } = require("../../scripts/ci/run-historical-baseline.cjs");
const {
  desktopFiles,
  unitFiles,
  itemsForLane,
  executablePackageItems,
  directlyExecutedPackageItems
} = require("../../scripts/ci/run-lane.cjs");
const {
  MAX_COMMAND_OUTPUT_BYTES,
  argvForItem
} = require("../../scripts/ci/command-runner.cjs");

function mochaResultFromStdout(stdout, extras = {}) {
  return {
    status: extras.status != null ? extras.status : 1,
    signal: extras.signal != null ? extras.signal : null,
    stdout,
    stderr: extras.stderr != null ? extras.stderr : "",
    combined: extras.combined != null ? extras.combined : `${stdout}\n${extras.stderr != null ? extras.stderr : ""}`
  };
}

function mochaEntryFromResult(result, overrides = {}) {
  const parsed = parseMochaFailures(result.combined, [ROOT]);
  const digests = normalizedStreamDigests(result, [ROOT]);
  return {
    id: "unit:example.test.cjs",
    matcher: "mocha_hardhat",
    expectedExitCode: result.status,
    expectedExitCategory: "nonzero_exit",
    passing: overrides.passing != null ? overrides.passing : 1,
    failing: overrides.failing != null ? overrides.failing : 1,
    failures:
      overrides.failures ||
      parsed.map((f) => ({ identity: f.identity, bodySha256: f.bodySha256 })),
    ...digests,
    ...overrides
  };
}

describe("PhilCore deterministic CI classification", function () {
  it("validates the committed classification against the discovered universe", function () {
    const result = validateClassification();
    assert.equal(result.ok, true, result.errors.join("\n"));
  });

  it("fails when a discovered test is unclassified", function () {
    const classification = loadClassification();
    const universe = discoverUniverse();
    const manifest = loadHistoricalManifest();
    const clone = structuredClone(classification);
    clone.items = clone.items.filter((item) => item.id !== "unit:runtime-redaction.test.cjs");
    const result = validateClassification(clone, universe, manifest);
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((error) => error.includes("unclassified item: unit:runtime-redaction.test.cjs")));
  });

  it("fails when an item is classified more than once", function () {
    const classification = loadClassification();
    const universe = discoverUniverse();
    const manifest = loadHistoricalManifest();
    const clone = structuredClone(classification);
    clone.items.push({ ...clone.items[0] });
    const result = validateClassification(clone, universe, manifest);
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((error) => error.includes("duplicate classification id")));
  });

  it("fails when declared lane totals drift from the classified universe", function () {
    const classification = structuredClone(loadClassification());
    classification.totals.solidity_erc4337 -= 1;
    const result = validateClassification(
      classification,
      discoverUniverse(),
      loadHistoricalManifest()
    );
    assert.equal(result.ok, false);
    assert.ok(
      result.errors.some((error) =>
        error.includes("declared total mismatch for solidity_erc4337")
      )
    );
  });

  it("fails when a prohibited public-network command appears in an automated lane", function () {
    const classification = loadClassification();
    const universe = discoverUniverse();
    const manifest = loadHistoricalManifest();
    const clone = structuredClone(classification);
    clone.items.push({
      id: "script:submit:userop",
      kind: "package_script",
      lane: "required_product_runtime",
      command: "npm run submit:userop",
      execution: { mode: "executed_directly" },
      notes: "synthetic"
    });
    const u = {
      ...universe,
      expectedIds: [...universe.expectedIds, "script:submit:userop"]
    };
    const result = validateClassification(clone, u, manifest);
    assert.equal(result.ok, false);
    assert.ok(result.errors.some((error) => /prohibited/.test(error)));
  });

  it("rejects prohibited operational command forms without banning offline signing tests", function () {
    assert.equal(
      commandLooksProhibited("npx hardhat run scripts/deploy.js --network sepolia"),
      true
    );
    assert.equal(commandLooksProhibited("npm run submit:userop"), true);
    assert.equal(commandLooksProhibited("npm run broadcast"), true);
    assert.equal(commandLooksProhibited("npm run fund:account"), true);
    assert.equal(
      commandLooksProhibited("npx hardhat test --no-compile ./test/unit/local-device-signing.test.cjs"),
      false
    );
    assert.equal(
      commandLooksProhibited("npx hardhat test ./test/unit/philcore-erc4337-user-operation-signing.test.cjs"),
      false
    );
  });

  it("requires historical manifest bijection (missing and extra entries fail)", function () {
    const classification = loadClassification();
    const universe = discoverUniverse();
    const manifest = structuredClone(loadHistoricalManifest());
    const missing = structuredClone(manifest);
    missing.entries = missing.entries.slice(1);
    const missingResult = validateClassification(classification, universe, missing);
    assert.equal(missingResult.ok, false);
    assert.ok(missingResult.errors.some((e) => /missing manifest entry/.test(e)));

    const extra = structuredClone(manifest);
    extra.entries.push({
      id: "unit:synthetic-extra.test.cjs",
      matcher: "mocha_hardhat",
      expectedExitCode: 1,
      expectedExitCategory: "nonzero_exit",
      passing: 0,
      failing: 1,
      failures: []
    });
    const extraResult = validateClassification(classification, universe, extra);
    assert.equal(extraResult.ok, false);
    assert.ok(extraResult.errors.some((e) => /extra entry/.test(e)));
  });

  it("distinguishes expected historical failures, retired entries, and reviewed toolchain drift", function () {
    const manifest = structuredClone(loadHistoricalManifest());
    assert.deepEqual(validateHistoricalManifestPolicy(manifest), []);

    const retired = structuredClone(manifest);
    const retiredId = retired.failureStatePolicy.expectedFailureIds[0];
    retired.failureStatePolicy.retiredIds.push(retiredId);
    assert.ok(validateHistoricalManifestPolicy(retired).some((error) =>
      error.includes("cannot be expected and retired")
    ));

    const unclassified = structuredClone(manifest);
    unclassified.failureStatePolicy.expectedFailureIds.pop();
    assert.ok(validateHistoricalManifestPolicy(unclassified).some((error) =>
      error.includes("entry is not declared expected")
    ));

    const invalidDrift = structuredClone(manifest);
    invalidDrift.failureStatePolicy.normalizationToolchainDrift.ids.push(
      "unit:o32-v2-cryptographic-foundation.test.cjs"
    );
    assert.ok(validateHistoricalManifestPolicy(invalidDrift).some((error) =>
      error.includes("must use structured_error matcher")
    ));
  });

  it("keeps monolithic test:unit out of required automated lanes", function () {
    const classification = loadClassification();
    const item = classification.items.find((entry) => entry.id === "script:test:unit");
    assert.ok(item);
    assert.equal(item.lane, "environment_dependent");
  });

  it("desktop lane executes classified desktop files and excludes physical suites", function () {
    const classification = loadClassification();
    const files = desktopFiles(itemsForLane("desktop", classification));
    assert.ok(files.includes("apps/philcore-desktop/test/desktop-e2e.test.cjs"));
    assert.ok(files.includes("apps/philcore-desktop/test/desktop-o9-distribution.test.cjs"));
    assert.ok(!files.includes("apps/philcore-desktop/test/desktop-native-iphone-pairing.test.cjs"));
    assert.ok(!files.includes("apps/philcore-desktop/test/desktop-platform-webauthn.test.cjs"));
    assert.ok(!files.includes("apps/philcore-desktop/test/desktop-user-presence.test.cjs"));
    const aggregate = classification.items.find((i) => i.id === "script:desktop:test");
    assert.equal(aggregate.lane, "environment_dependent");
  });

  it("Deterministic CI runs full validation on authoritative PRs and permits manual audits", function () {
    const fs = require("node:fs");
    const path = require("node:path");
    const workflowPath = path.join(ROOT, ".github/workflows/deterministic-ci.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const onIdx = workflow.indexOf("on:");
    const concurrencyIdx = workflow.indexOf("concurrency:");
    assert.notEqual(onIdx, -1, "workflow must declare on:");
    assert.notEqual(concurrencyIdx, -1, "workflow must declare concurrency:");
    assert.ok(onIdx < concurrencyIdx, "on: must precede concurrency:");
    const triggerBlock = workflow.slice(onIdx, concurrencyIdx);
    // Package CI-1: automatic base-branch push validation is removed (a
    // clean merge no longer re-runs the full six-lane suite a second time);
    // full validation remains mandatory on every pull request targeting the
    // authoritative branch only; workflow_dispatch remains available for a
    // deliberate manual emergency audit. This pins the complete trigger
    // block exactly, not a loose substring match, so no path filter or
    // alternate-branch trigger can be silently admitted alongside it.
    const expected = [
      "on:",
      "  pull_request:",
      "    branches:",
      '      - "main"',
      "  workflow_dispatch: {}",
      "",
      ""
    ].join("\n");
    assert.equal(triggerBlock, expected);
    // Belt-and-suspenders beyond the exact-literal match above: automatic
    // push-triggered validation must be genuinely absent, not merely
    // missing from this one expected string.
    assert.equal(triggerBlock.includes("push:"), false);
    assert.equal(triggerBlock.includes("phil-private/**"), false);
    assert.equal(triggerBlock.includes("cursor/**"), false);
    assert.equal(triggerBlock.includes('"codex/**"'), false);
    assert.equal(triggerBlock.includes("claude/**"), false);
  });

  it("Desktop workflow provisions the sandbox-safe preload bundle before the classified lane", function () {
    const fs = require("node:fs");
    const path = require("node:path");
    const workflowPath = path.join(ROOT, ".github/workflows/deterministic-ci.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");

    function jobBody(source, jobId) {
      const jobsIdx = source.indexOf("\njobs:");
      assert.notEqual(jobsIdx, -1, "workflow must declare jobs");
      const jobs = source.slice(jobsIdx);
      const start = jobs.search(new RegExp(`\\n  ${jobId}:\\n`));
      assert.notEqual(start, -1, `missing job: ${jobId}`);
      const after = jobs.slice(start + 1);
      const next = after.search(/\n  [A-Za-z0-9_-]+:\n/);
      return next === -1 ? after : after.slice(0, next);
    }

    const bundleCommand = "npm run desktop:bundle-preload";
    const laneCommand = "npm run ci:lane:desktop";
    const wholeMatches = workflow.match(new RegExp(bundleCommand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || [];
    assert.equal(wholeMatches.length, 1, "workflow must contain exactly one desktop:bundle-preload invocation");

    const desktop = jobBody(workflow, "desktop");
    assert.equal(
      (desktop.match(new RegExp(bundleCommand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length,
      1,
      "desktop job must own the preload bundle step"
    );
    for (const otherJob of ["product-runtime", "solidity-erc4337", "classification-static", "proving", "evidence-check"]) {
      assert.equal(
        jobBody(workflow, otherJob).includes(bundleCommand),
        false,
        `${otherJob} must not run desktop:bundle-preload`
      );
    }

    const bundleIdx = desktop.indexOf(bundleCommand);
    const laneIdx = desktop.indexOf(laneCommand);
    assert.notEqual(bundleIdx, -1);
    assert.notEqual(laneIdx, -1);
    assert.ok(bundleIdx < laneIdx, "preload bundle must run before ci:lane:desktop");

    const compileIdx = desktop.indexOf("npx hardhat compile");
    assert.notEqual(compileIdx, -1);
    assert.ok(compileIdx < bundleIdx, "preload bundle should follow Hardhat compilation");

    const bundleStepWindow = desktop.slice(Math.max(0, bundleIdx - 180), bundleIdx + bundleCommand.length + 80);
    assert.doesNotMatch(bundleStepWindow, /continue-on-error\s*:/u);
    assert.doesNotMatch(bundleStepWindow, /\bif:/u);
    assert.doesNotMatch(bundleStepWindow, /retry|max-attempts|download-artifact/iu);
    assert.doesNotMatch(desktop, /actions\/download-artifact/u);

    const { DISPOSABLE_DIRS, rmDisposable } = require("../../scripts/ci/verify-clean-tree.cjs");
    assert.ok(
      DISPOSABLE_DIRS.includes("apps/philcore-desktop/build/preload"),
      "clean-tree must dispose the exact preload output directory"
    );

    const os = require("node:os");
    const realWatch = [
      "artifacts",
      "cache",
      "proving/target",
      "apps/philcore-desktop/build/preload"
    ].map((rel) => {
      const abs = path.join(ROOT, rel);
      return {
        rel,
        abs,
        existed: fs.existsSync(abs),
        marker: path.join(abs, ".philcore-classifier-isolation-sentinel")
      };
    });
    for (const entry of realWatch) {
      assert.equal(
        fs.existsSync(entry.marker),
        false,
        `classifier test must not plant markers in the real worktree (${entry.rel})`
      );
    }

    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-clean-tree-"));
    try {
      for (const rel of DISPOSABLE_DIRS) {
        const dir = path.join(tmpRoot, rel);
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, "marker.cjs"), `// disposable ${rel}\n`);
      }
      const sentinel = path.join(tmpRoot, "sibling-sentinel.txt");
      fs.writeFileSync(sentinel, "retain\n");

      rmDisposable(tmpRoot);

      assert.equal(
        fs.existsSync(path.join(tmpRoot, "apps/philcore-desktop/build/preload")),
        false,
        "temporary preload directory must be removed"
      );
      for (const rel of DISPOSABLE_DIRS) {
        assert.equal(
          fs.existsSync(path.join(tmpRoot, rel)),
          false,
          `temporary disposable directory must be removed: ${rel}`
        );
      }
      assert.equal(fs.existsSync(sentinel), true, "sibling sentinel outside disposable dirs must remain");
      assert.equal(fs.readFileSync(sentinel, "utf8"), "retain\n");

      assert.throws(() => rmDisposable("/"), /DISPOSABLE_ROOT_FILESYSTEM_ROOT/);
      assert.throws(() => rmDisposable(""), /DISPOSABLE_ROOT_EMPTY/);
      assert.throws(() => rmDisposable("relative-root"), /DISPOSABLE_ROOT_NOT_ABSOLUTE/);

      const escapeLink = path.join(tmpRoot, "symlink-escape-root");
      fs.symlinkSync(ROOT, escapeLink);
      assert.throws(
        () => rmDisposable(escapeLink),
        /DISPOSABLE_ROOT_SYMLINK_ESCAPE/,
        "tmp symlink resolving outside the real temporary root must be rejected before deletion"
      );
      assert.equal(fs.lstatSync(escapeLink).isSymbolicLink(), true);
      assert.equal(fs.existsSync(path.join(ROOT, "package.json")), true);

      const outsideTarget = path.join(ROOT, "docs");
      const outsideMarker = path.join(outsideTarget, "engineering/DETERMINISTIC_CI.md");
      assert.equal(fs.existsSync(outsideMarker), true);
      const outsideBefore = fs.readFileSync(outsideMarker, "utf8");
      const escapeOutside = path.join(tmpRoot, "symlink-escape-outside");
      fs.symlinkSync(outsideTarget, escapeOutside);
      assert.throws(
        () => rmDisposable(escapeOutside),
        /DISPOSABLE_ROOT_SYMLINK_ESCAPE/
      );
      assert.equal(fs.existsSync(outsideMarker), true);
      assert.equal(fs.readFileSync(outsideMarker, "utf8"), outsideBefore);

      for (const entry of realWatch) {
        assert.equal(
          fs.existsSync(entry.abs),
          entry.existed,
          `real worktree path must be unchanged: ${entry.rel}`
        );
        assert.equal(
          fs.existsSync(entry.marker),
          false,
          `real worktree must remain free of classifier markers: ${entry.rel}`
        );
      }
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});

describe("PhilCore historical exact matcher", function () {
  const hardhatShaped = `

  Suite
    ✔ ok


  1 passing (1ms)
  1 failing

  1) Suite
       case:
     AssertionError: boom
`;

  it("accepts an exact mocha historical identity", function () {
    const result = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(result);
    const match = matchHistoricalResult(result, entry);
    assert.equal(match.ok, true, match.reasons && match.reasons.join("\n"));
  });

  it("rejects an approved token plus a new unrelated failure", function () {
    const shaped = `

  1 passing (1ms)
  2 failing

  1) Suite
       case:
     AssertionError: boom

  2) Suite
       other:
     Error: UNRELATED_FAILURE
`;
    const result = mochaResultFromStdout(shaped);
    const baseline = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(baseline, { failing: 1 });
    const match = matchHistoricalResult(result, entry);
    assert.equal(match.ok, false);
    assert.ok(match.reasons.some((r) => /failing|mismatch|normalized/i.test(r)));
  });

  it("rejects a changed failure body", function () {
    const shaped = `

  1 passing (1ms)
  1 failing

  1) Suite
       case:
     AssertionError: changed-body
`;
    const result = mochaResultFromStdout(shaped);
    const entry = mochaEntryFromResult(result, {
      failures: [
        {
          identity: parseMochaFailures(shaped, [ROOT])[0].identity,
          bodySha256: sha256("AssertionError: original-body")
        }
      ]
    });
    const match = matchHistoricalResult(result, entry);
    assert.equal(match.ok, false);
  });

  it("rejects an extra failure", function () {
    const shaped = `

  1 passing (1ms)
  2 failing

  1) Suite
       case:
     AssertionError: boom

  2) Suite
       extra:
     AssertionError: extra
`;
    const result = mochaResultFromStdout(shaped);
    const parsed = parseMochaFailures(shaped, [ROOT]);
    const baseline = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(baseline, {
      failing: 1,
      failures: [{ identity: parsed[0].identity, bodySha256: parsed[0].bodySha256 }]
    });
    const match = matchHistoricalResult(result, entry);
    assert.equal(match.ok, false);
  });

  it("rejects a missing failure", function () {
    const shaped = `

  2 passing (1ms)

`;
    const result = mochaResultFromStdout(shaped);
    const baseline = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(baseline, { passing: 2, failing: 1 });
    const match = matchHistoricalResult(result, entry);
    assert.equal(match.ok, false);
  });

  it("rejects an unexpected exit code or signal", function () {
    const result = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(result);
    const badExit = matchHistoricalResult({ ...result, status: 3 }, entry);
    assert.equal(badExit.ok, false);
    assert.ok(badExit.reasons.some((r) => /exit code/.test(r)));

    const badSignal = matchHistoricalResult({ ...result, signal: "SIGTERM" }, entry);
    assert.equal(badSignal.ok, false);
    assert.ok(badSignal.reasons.some((r) => /signal/.test(r)));
  });

  it("rejects an unrelated line prepended before the Mocha summary", function () {
    const result = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(result);
    const polluted = mochaResultFromStdout(`UNRELATED_PREPEND\n${hardhatShaped}`);
    const match = matchHistoricalResult(polluted, entry);
    assert.equal(match.ok, false);
    assert.ok(match.reasons.some((r) => /normalized(Output|Stdout)Sha256/.test(r)));
  });

  it("rejects unrelated stderr appended outside parsed failure blocks", function () {
    const result = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(result);
    const polluted = mochaResultFromStdout(hardhatShaped, {
      stderr: "UNRELATED_STDERR_LINE\n"
    });
    const match = matchHistoricalResult(polluted, entry);
    assert.equal(match.ok, false);
    assert.ok(match.reasons.some((r) => /normalized(Output|Stderr)Sha256/.test(r)));
  });

  it("rejects surrounding output changes when parsed failures stay unchanged", function () {
    const result = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(result);
    const surrounding = `

  Suite
    ✔ ok
    - extra chatter that is not a failure block


  1 passing (1ms)
  1 failing

  1) Suite
       case:
     AssertionError: boom
`;
    const polluted = mochaResultFromStdout(surrounding);
    const parsedSame = parseMochaFailures(surrounding, [ROOT]);
    assert.equal(parsedSame.length, 1);
    assert.equal(parsedSame[0].identity, entry.failures[0].identity);
    assert.equal(parsedSame[0].bodySha256, entry.failures[0].bodySha256);
    const match = matchHistoricalResult(polluted, entry);
    assert.equal(match.ok, false);
    assert.ok(match.reasons.some((r) => /normalizedOutputSha256/.test(r)));
  });

  it("still passes when expected normalized mocha output is unchanged", function () {
    const result = mochaResultFromStdout(hardhatShaped);
    const entry = mochaEntryFromResult(result);
    const again = mochaResultFromStdout(hardhatShaped);
    const match = matchHistoricalResult(again, entry);
    assert.equal(match.ok, true, match.reasons && match.reasons.join("\n"));
  });

  it("rejects structured evidence output when body digest changes", function () {
    const entry = {
      id: "script:verify:example",
      matcher: "structured_error",
      expectedExitCode: 1,
      expectedExitCategory: "nonzero_exit",
      errorCode: "O32_VECTOR_PACKAGE_STALE",
      normalizedOutputSha256: sha256(normalizeFailureText("Error: O32_VECTOR_PACKAGE_STALE\n", [ROOT]))
    };
    const ok = matchHistoricalResult(
      { status: 1, signal: null, combined: "Error: O32_VECTOR_PACKAGE_STALE\n" },
      entry
    );
    assert.equal(ok.ok, true, ok.reasons && ok.reasons.join("\n"));

    const changed = matchHistoricalResult(
      {
        status: 1,
        signal: null,
        combined: "Error: O32_VECTOR_PACKAGE_STALE\nError: UNRELATED_ALSO\n"
      },
      entry
    );
    assert.equal(changed.ok, false);
  });

  it("normalizes absolute paths and timing for failure comparison", function () {
    const normalized = normalizeFailureText(
      `${ROOT}/test/unit/foo.test.cjs (12ms) at 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
      [ROOT]
    );
    assert.equal(normalized.includes(ROOT), false);
    assert.ok(normalized.includes("<ms>"));
    assert.ok(normalized.includes("<ADDR>"));
    assert.equal(failuresEqualExact([], []), true);
  });

  it("normalizes Node runtime-only stack locations and version footers", function () {
    const first = normalizeFailureText(
      "    at Module._compile (node:internal/modules/cjs/loader:1829:14)\nNode.js v26.0.0\n"
    );
    const second = normalizeFailureText(
      "    at Module._compile (node:internal/modules/cjs/loader:1934:14)\nNode.js v26.5.1\n"
    );
    assert.equal(first, second);
    assert.match(first, /node:internal\/modules\/cjs\/loader:<line>:<column>/);
    assert.match(first, /Node\.js <version>/);
  });

  it("does not normalize application stack line numbers", function () {
    const normalized = normalizeFailureText(
      "    at main (scripts/cryptography/example.cjs:10:2)\n"
    );
    assert.match(normalized, /example\.cjs:10:2/);
  });

  it("records solidity unit execution counts without overstating aliases", function () {
    const classification = loadClassification();
    const items = itemsForLane("solidity_erc4337", classification);
    const files = unitFiles(items);
    assert.ok(files.includes("test/unit/o30-v2-account-specification.test.cjs"));
    assert.ok(files.includes("test/unit/o37-1-v2-recovery-evidence.test.cjs"));
    assert.ok(files.includes("test/unit/o37-9-conformance.test.cjs"));
    assert.ok(!files.includes("test/unit/o31-v2-implementation-architecture.test.cjs"));
    assert.ok(!files.includes("test/unit/o37-2-v2-deterministic-fixtures.test.cjs"));
  });

  it("keeps bounded headroom for full-lane command output", function () {
    assert.equal(MAX_COMMAND_OUTPUT_BYTES, 16 * 1024 * 1024);
  });

  it("executes every direct proving package script and excludes its alias", function () {
    const items = itemsForLane("proving", loadClassification());
    const packageItems = executablePackageItems(items);
    assert.deepEqual(
      packageItems.map((item) => argvForItem(item)),
      [
        ["npm", "run", "test:phil-v1-step3-cairo"],
        ["npm", "run", "test:phil-v1-step3-noir"],
        ["npm", "run", "test:phil-v1-step4-cairo"]
      ]
    );
    assert.equal(packageItems.some((item) => item.id === "script:test:proving"), false);
  });

  it("executes the directly classified product-runtime Simulator suite", function () {
    const items = itemsForLane("required_product_runtime", loadClassification());
    const packageItems = directlyExecutedPackageItems(items);
    assert.deepEqual(
      packageItems.map((item) => argvForItem(item)),
      [["npm", "run", "test:phil-v1-step6c2-ios-simulator"]]
    );
  });

  it("hosts the required product-runtime Simulator suite on macOS", function () {
    const fs = require("node:fs");
    const path = require("node:path");
    const workflow = fs.readFileSync(
      path.join(ROOT, ".github/workflows/deterministic-ci.yml"),
      "utf8"
    );
    const start = workflow.indexOf("\n  product-runtime:\n");
    const end = workflow.indexOf("\n  solidity-erc4337:\n", start);
    assert.notEqual(start, -1, "workflow must declare product-runtime");
    assert.notEqual(end, -1, "workflow must declare the following Solidity job");
    const productRuntimeJob = workflow.slice(start, end);

    assert.match(productRuntimeJob, /\n    runs-on: macos-26\n/u);
    assert.equal(
      (productRuntimeJob.match(/npm run ci:lane:product-runtime/gu) || []).length,
      1,
      "macOS product-runtime job must execute the classified lane exactly once"
    );
    assert.doesNotMatch(productRuntimeJob, /continue-on-error\s*:/u);
  });

  it("schedules the previously omitted coordinator exactly once and refuses unknown required kinds", function () {
    const {desktopExecutedItems} = require("../../scripts/ci/run-lane.cjs");
    const scheduled=desktopExecutedItems(itemsForLane("desktop",loadClassification()));
    assert.equal(scheduled.filter(item=>item.id==="unit:phil-v1-step6c-desktop.test.cjs").length,1);
    assert.throws(()=>desktopExecutedItems([{id:"required:unhandled",kind:"unknown"}]),/Unscheduled required/);
    const {spawnSync}=require("node:child_process");
    const result=spawnSync(process.execPath,["scripts/ci/run-lane.cjs","desktop","--dry-run"],{cwd:ROOT,encoding:"utf8"});
    assert.equal(result.status,0,result.stderr);
    assert.equal((result.stdout.match(/\.\/test\/unit\/phil-v1-step6c-desktop\.test\.cjs/g)||[]).length,1);
    const workflow=require("node:fs").readFileSync(require("node:path").join(ROOT,".github/workflows/deterministic-ci.yml"),"utf8");
    assert.match(workflow,/pull_request:/);assert.match(workflow,/run: npm run ci:lane:desktop/);
  });

  it("uses the required Hardhat harness for the three Desktop product-host suites", function () {
    const items = itemsForLane("desktop", loadClassification());
    const hardhatIds = new Set([
      "desktop_file:apps/philcore-desktop/test/desktop-routine-authorization.test.cjs",
      "desktop_file:apps/philcore-desktop/test/desktop-routine-authorization-local-product-runtime.test.cjs",
      "desktop_file:apps/philcore-desktop/test/desktop-routine-authorization-product-flow.test.cjs"
    ]);
    const productHostItems = items.filter((item) => hardhatIds.has(item.id));
    assert.equal(productHostItems.length, 3);
    for (const item of productHostItems) {
      const argv = argvForItem(item);
      assert.deepEqual(argv.slice(0, 3), ["npx", "hardhat", "test"]);
      assert.ok(argv.includes("--config"));
      assert.ok(argv.includes("--no-compile"));
      assert.equal(argv.at(-1), `./${item.id.replace(/^desktop_file:/, "")}`);
    }
  });

  it("uses the Base-chain Hardhat harness for the Step 6B account suite", function () {
    const item = itemsForLane("solidity_erc4337", loadClassification()).find(
      (entry) => entry.id === "unit:phil-v1-step6b-local-smart-account.test.cjs"
    );
    assert.ok(item);
    assert.deepEqual(argvForItem(item), [
      "npx",
      "hardhat",
      "test",
      "--config",
      "./hardhat.phil-v1-step6b.config.cjs",
      "--no-compile",
      "./test/unit/phil-v1-step6b-local-smart-account.test.cjs"
    ]);
  });

  it("uses the Sepolia-chain Hardhat harness for the composed mint contract suite", function () {
    const item = itemsForLane("solidity_erc4337", loadClassification()).find(
      (candidate) => candidate.id === "unit:phil-sepolia-local-composed-contracts.test.cjs"
    );
    assert.ok(item);
    assert.deepEqual(argvForItem(item), [
      "npx", "hardhat", "test", "--config", "./hardhat.phil-sepolia-mint.config.cjs",
      "--no-compile", "./test/unit/phil-sepolia-local-composed-contracts.test.cjs"
    ]);
  });
});

describe("PhilCore Mocha Spec reporter duration canonicalization", function () {
  const O33_CANONICAL_STDOUT_SHA256 =
    "5d8bfaba9a5ba70664d858f960a66a2b9b798195653b677def8ae243710701a5";

  function stripReporterDurationsForRebuild(text) {
    return String(text)
      .split("\n")
      .map((line) => {
        if (/^\s+[✔✓√]\s+/.test(line) || /^\s*\d+ passing\b/.test(line)) {
          return line
            .replace(/ \(\d+(?:\.\d+)?(?:ms|s)\)$/, "")
            .replace(/ \(<ms>\)$/, "");
        }
        return line;
      })
      .join("\n");
  }

  function withReporterDurations(strippedStdout, options) {
    const successDuration = options.successDuration;
    const summaryDuration = options.summaryDuration;
    const successCount = options.successCount != null ? options.successCount : 6;
    const lines = String(strippedStdout).split("\n");
    const successIdx = [];
    lines.forEach((line, index) => {
      if (/^\s+[✔✓√]\s+/.test(line)) successIdx.push(index);
    });
    assert.ok(
      successIdx.length >= successCount,
      `expected at least ${successCount} successful-test lines`
    );
    for (let i = 0; i < successCount; i += 1) {
      lines[successIdx[i]] += ` (${successDuration})`;
    }
    const passIdx = lines.findIndex((line) => /^\s*\d+ passing\b/.test(line));
    assert.ok(passIdx >= 0);
    lines[passIdx] += ` (${summaryDuration})`;
    return lines.join("\n");
  }

  it("canonicalizes deterministic millisecond and seconds O.33 timing forms byte-for-byte", function () {
    this.timeout(60000);
    const { runArgv, argvForItem } = require("../../scripts/ci/command-runner.cjs");
    const item = loadClassification().items.find(
      (entry) => entry.id === "unit:o33-v2-validator-authorization-engine.test.cjs"
    );
    assert.ok(item);

    // Raw Mocha Spec output is environment-dependent (ms vs s reporter units).
    // Use it only as a content source; reconstruct both timing forms explicitly.
    const rawSourceForm = runArgv(argvForItem(item)).stdout;
    assert.ok(
      /\d+ passing \(\d+(?:\.\d+)?(?:ms|s)\)/.test(rawSourceForm),
      "raw source must include a Mocha passing summary duration in ms or s"
    );

    const stripped = stripReporterDurationsForRebuild(rawSourceForm);
    const millisecondForm = withReporterDurations(stripped, {
      successDuration: "45ms",
      summaryDuration: "552ms",
      successCount: 6
    });
    const secondsForm = withReporterDurations(stripped, {
      successDuration: "45ms",
      summaryDuration: "1s",
      successCount: 6
    });

    assert.ok(/\d+ passing \(552ms\)/.test(millisecondForm));
    assert.ok(/\d+ passing \(1s\)/.test(secondsForm));
    const timedSuccessLines = secondsForm
      .split("\n")
      .filter((line) => /^\s+[✔✓√]\s+/.test(line) && / \(\d+ms\)$/.test(line));
    assert.equal(timedSuccessLines.length, 6);

    const millisecondNorm = normalizeFailureText(millisecondForm, [ROOT]);
    const secondsNorm = normalizeFailureText(secondsForm, [ROOT]);
    assert.equal(millisecondNorm, secondsNorm);
    assert.equal(Buffer.byteLength(millisecondNorm, "utf8"), 4306);
    assert.equal(sha256(millisecondNorm), O33_CANONICAL_STDOUT_SHA256);
    assert.equal(sha256(secondsNorm), O33_CANONICAL_STDOUT_SHA256);

    const millisecondLines = millisecondNorm.split("\n");
    const secondsLines = secondsNorm.split("\n");
    assert.equal(millisecondLines.length, secondsLines.length);
    const diffs = millisecondLines.filter((line, index) => line !== secondsLines[index]);
    assert.equal(diffs.length, 0);
    assert.equal(millisecondNorm.includes("(<ms>)"), false);
    assert.equal(/\(\d+(?:\.\d+)?(?:ms|s)\)/.test(millisecondNorm.replace(/\(<ms>\)/g, "")), false);

    // Raw environment form must also canonicalize to the same digest whether
    // the host reported millisecond or second summary units.
    const rawNorm = normalizeFailureText(rawSourceForm, [ROOT]);
    assert.equal(rawNorm, millisecondNorm);
    assert.equal(sha256(rawNorm), O33_CANONICAL_STDOUT_SHA256);
  });

  it("accepts a raw 23 passing (1s) summary as valid canonicalization input", function () {
    const source = `

  Suite
    ✔ ok


  23 passing (1s)
  1 failing

  1) Suite
       case:
     AssertionError: boom
`;
    assert.match(source, /23 passing \(1s\)/);
    assert.equal(normalizeFailureText(source, [ROOT]), normalizeFailureText(`

  Suite
    ✔ ok


  23 passing (552ms)
  1 failing

  1) Suite
       case:
     AssertionError: boom
`, [ROOT]));
    assert.match(normalizeFailureText(source, [ROOT]), /^\s*23 passing$/m);
  });

  it("strips successful-test millisecond and second reporter durations", function () {
    const msLine = "      ✔ rejects amount mutations (53ms)";
    const sLine = "      ✓ rejects amount mutations (1s)";
    const fallback = "      √ rejects amount mutations (1.5s)";
    assert.equal(
      normalizeFailureText(msLine, [ROOT]),
      "      ✔ rejects amount mutations"
    );
    assert.equal(
      normalizeFailureText(sLine, [ROOT]),
      "      ✓ rejects amount mutations"
    );
    assert.equal(
      normalizeFailureText(fallback, [ROOT]),
      "      √ rejects amount mutations"
    );
  });

  it("strips passing-summary millisecond and second reporter durations", function () {
    assert.equal(
      normalizeFailureText("  23 passing (552ms)", [ROOT]),
      "  23 passing"
    );
    assert.equal(
      normalizeFailureText("  23 passing (1s)", [ROOT]),
      "  23 passing"
    );
    assert.equal(
      normalizeFailureText("  23 passing (<ms>)", [ROOT]),
      "  23 passing"
    );
  });

  it("keeps meaningful (1s) or (<ms>) text inside a test name when not terminal reporter duration", function () {
    const titled = "      ✔ waits (1s) then continues";
    const titledMs = "      ✔ mentions (<ms>) in the title carefully";
    assert.equal(normalizeFailureText(titled, [ROOT]), titled);
    assert.equal(normalizeFailureText(titledMs, [ROOT]), titledMs);
  });

  it("keeps failure-body duration text intact under the new line rules", function () {
    const body = `

  1 passing (1ms)
  1 failing

  1) Suite
       case:
     AssertionError: timed out after (1s) and (12ms) budget
`;
    const normalized = normalizeFailureText(body, [ROOT]);
    // Global ms token rewrite still applies inside bodies; seconds and the
    // failure narrative are not stripped by reporter-line rules.
    assert.ok(normalized.includes("timed out after (1s)"));
    assert.ok(normalized.includes("(<ms>)") || normalized.includes("<ms>"));
    assert.ok(normalized.includes("  1 failing"));
    assert.match(normalized, /^\s*1 passing$/m);
  });

  it("leaves failing and pending summaries intact", function () {
    assert.equal(
      normalizeFailureText("  1 failing (1s)", [ROOT]),
      "  1 failing (1s)"
    );
    assert.equal(
      normalizeFailureText("  2 pending (45ms)", [ROOT]),
      "  2 pending (<ms>)"
    );
  });

  it("leaves arbitrary output lines ending in (1s) intact", function () {
    const chatter = "build step completed (1s)";
    assert.equal(normalizeFailureText(chatter, [ROOT]), chatter);
    assert.equal(
      normalizeFailureText("note: probe finished (2.5s)", [ROOT]),
      "note: probe finished (2.5s)"
    );
  });

  it("still rejects changed failure bodies, added stdout/stderr, and exit/signal changes", function () {
    const shaped = `

  Suite
    ✔ ok


  1 passing (1ms)
  1 failing

  1) Suite
       case:
     AssertionError: boom
`;
    const result = mochaResultFromStdout(shaped);
    const entry = mochaEntryFromResult(result);
    assert.equal(matchHistoricalResult(result, entry).ok, true);

    const changedBody = mochaResultFromStdout(`

  Suite
    ✔ ok


  1 passing (1ms)
  1 failing

  1) Suite
       case:
     AssertionError: changed-body
`);
    assert.equal(matchHistoricalResult(changedBody, entry).ok, false);

    const addedStdout = mochaResultFromStdout(`UNRELATED_PREPEND\n${shaped}`);
    assert.equal(matchHistoricalResult(addedStdout, entry).ok, false);
    assert.ok(
      matchHistoricalResult(addedStdout, entry).reasons.some((r) =>
        /normalized(Output|Stdout)Sha256/.test(r)
      )
    );

    const addedStderr = mochaResultFromStdout(shaped, { stderr: "UNRELATED_STDERR\n" });
    assert.equal(matchHistoricalResult(addedStderr, entry).ok, false);
    assert.ok(
      matchHistoricalResult(addedStderr, entry).reasons.some((r) =>
        /normalized(Output|Stderr)Sha256/.test(r)
      )
    );

    assert.equal(matchHistoricalResult({ ...result, status: 3 }, entry).ok, false);
    assert.equal(
      matchHistoricalResult({ ...result, signal: "SIGTERM" }, entry).ok,
      false
    );
  });
});

// Run durability contracts through the existing classified CI suite.
require("../helpers/ci-longitudinal-evidence.cjs");
