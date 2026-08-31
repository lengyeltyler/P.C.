const assert = require("node:assert/strict");

const {
  assertNoAbsoluteDeveloperPaths,
  sanitizeSlitherReport
} = require("../../scripts/security/sanitize-slither-report.cjs");

describe("public Slither report sanitization", function () {
  it("converts source mappings and embedded repository paths to repository-relative paths", function () {
    const repoRoot = "/Users/example/Developer/Phil";
    const sanitized = sanitizeSlitherReport(
      {
        description: `finding in ${repoRoot}/contracts/base/Account.sol`,
        source_mapping: {
          filename_absolute: `${repoRoot}/contracts/base/Account.sol`,
          filename_relative: "contracts/base/Account.sol",
          lines: [12, 13],
          starting_column: 5,
          ending_column: 9
        }
      },
      repoRoot
    );

    assert.equal(
      sanitized.description,
      "finding in contracts/base/Account.sol"
    );
    assert.equal(
      sanitized.source_mapping.filename_absolute,
      "contracts/base/Account.sol"
    );
    assert.deepEqual(sanitized.source_mapping.lines, [12, 13]);
    assert.equal(sanitized.source_mapping.starting_column, 5);
    assert.equal(sanitized.source_mapping.ending_column, 9);
    assert.doesNotThrow(() => assertNoAbsoluteDeveloperPaths(sanitized));
  });

  it("fails closed if any developer-home path survives sanitization", function () {
    assert.throws(
      () =>
        assertNoAbsoluteDeveloperPaths({
          path: "/Users/attacker/outside/Phil/contracts/Account.sol"
        }),
      /SLITHER_ABSOLUTE_DEVELOPER_PATH/
    );
  });

  it("redacts tool warnings that originate outside the repository", function () {
    const sanitized = sanitizeSlitherReport(
      "warning from /Users/example/.cache/tool/site-packages/module.py:12",
      "/work/Phil"
    );
    assert.equal(sanitized, "warning from <local-path>");
    assert.doesNotThrow(() => assertNoAbsoluteDeveloperPaths(sanitized));
  });
});
