"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");

const INFO_PLIST = "apps/philcore-ios-companion/PhilCoreCompanion/Info.plist";
const PBXPROJ =
  "apps/philcore-ios-companion/PhilCoreCompanion.xcodeproj/project.pbxproj";

const REQUIRED_PLIST_STRINGS = Object.freeze([
  ["CFBundleExecutable", "$(EXECUTABLE_NAME)"],
  ["CFBundleIdentifier", "$(PRODUCT_BUNDLE_IDENTIFIER)"],
  ["CFBundleName", "$(PRODUCT_NAME)"],
  ["CFBundlePackageType", "APPL"]
]);

const APP_REQUIRED_SETTINGS = Object.freeze({
  GENERATE_INFOPLIST_FILE: "NO",
  INFOPLIST_FILE: "PhilCoreCompanion/Info.plist",
  PRODUCT_BUNDLE_IDENTIFIER: "com.philcore.ios.companion.localalpha",
  PRODUCT_NAME: '"$(TARGET_NAME)"'
});

const PRODUCT_NAME_SETTING = '"$(TARGET_NAME)"';

const EXPECTED_PRODUCT_PATHS = Object.freeze([
  "PhilCoreCompanion.app",
  "PhilCoreCompanionTests.xctest",
  "PhilCoreCompanionUITests.xctest"
]);

const PROJECT_DEBUG_CONFIG_ID = "A00000000000000000000001";
const PROJECT_RELEASE_CONFIG_ID = "A00000000000000000000002";
const PROJECT_CONFIG_LIST_ID = "800000000000000000000003";
const TARGET_LEVEL_CONFIG_IDS = Object.freeze([
  "A00000000000000000000003",
  "A00000000000000000000004",
  "A00000000000000000000005",
  "A00000000000000000000006",
  "A00000000000000000000007",
  "A00000000000000000000008"
]);
const ARCH_OVERRIDE_KEYS = Object.freeze([
  "ONLY_ACTIVE_ARCH",
  "ARCHS",
  "EXCLUDED_ARCHS"
]);
const FORBIDDEN_TARGET_LEVEL_KEYS = Object.freeze([
  ...ARCH_OVERRIDE_KEYS,
  "ENABLE_TESTABILITY"
]);

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), "utf8");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Collect every occurrence of a plist key and classify its adjacent value.
 * Tolerant of whitespace/ordering; fail-closed on missing or non-string values.
 */
function plistKeyOccurrences(xml, key) {
  const keyRe = new RegExp(`<key>\\s*${escapeRegExp(key)}\\s*</key>`, "g");
  const occurrences = [];
  let match;
  while ((match = keyRe.exec(xml)) !== null) {
    const after = xml.slice(match.index + match[0].length);
    const trimmedStart = after.match(/^\s*/)[0].length;
    const rest = after.slice(trimmedStart);
    const stringMatch = rest.match(/^<string>([\s\S]*?)<\/string>/);
    if (stringMatch) {
      occurrences.push({ kind: "string", value: stringMatch[1] });
      continue;
    }
    const emptyMatch = rest.match(/^<([A-Za-z][A-Za-z0-9]*)\s*\/>/);
    if (emptyMatch) {
      occurrences.push({ kind: emptyMatch[1], value: null });
      continue;
    }
    const tagged = rest.match(/^<([A-Za-z][A-Za-z0-9]*)\b[^>]*>/);
    if (tagged) {
      occurrences.push({ kind: tagged[1], value: null });
      continue;
    }
    occurrences.push({ kind: "malformed", value: null });
  }
  return occurrences;
}

function assertExactPlistString(xml, key, expected) {
  const occurrences = plistKeyOccurrences(xml, key);
  assert.equal(
    occurrences.length,
    1,
    `expected exactly one <key>${key}</key>, found ${occurrences.length}`
  );
  const occurrence = occurrences[0];
  assert.equal(
    occurrence.kind,
    "string",
    `${key} must have a string value (found ${occurrence.kind})`
  );
  assert.equal(occurrence.value, expected, `${key} string value mismatch`);
}

/**
 * Resolve a PBXNativeTarget by exact name and return its stable IDs.
 * Rejects loose project-wide text matches.
 */
function resolveNativeTarget(pbx, targetName) {
  const marker = `/* ${targetName} */ = {`;
  let searchFrom = 0;
  while (searchFrom < pbx.length) {
    const start = pbx.indexOf(marker, searchFrom);
    assert.ok(start >= 0, `PBXNativeTarget ${targetName} not found`);
    // Walk backward to the target object ID on the same definition line/block.
    const lineStart = pbx.lastIndexOf("\n", start - 1) + 1;
    const prefix = pbx.slice(lineStart, start);
    const idMatch = prefix.match(/^\t\t([0-9A-F]{24})\s+/);
    assert.ok(idMatch, `${targetName} missing stable PBX object id`);
    const targetId = idMatch[1];
    const chunk = pbx.slice(start, start + 1200);
    if (
      /isa\s*=\s*PBXNativeTarget;/.test(chunk) &&
      new RegExp(`name\\s*=\\s*${escapeRegExp(targetName)};`).test(chunk)
    ) {
      const listMatch = chunk.match(/buildConfigurationList\s*=\s*([0-9A-F]{24});/);
      const productRefMatch = chunk.match(/productReference\s*=\s*([0-9A-F]{24});/);
      assert.ok(listMatch, `${targetName} missing buildConfigurationList id`);
      assert.ok(productRefMatch, `${targetName} missing productReference id`);
      return {
        targetId,
        targetName,
        configListId: listMatch[1],
        productReferenceId: productRefMatch[1]
      };
    }
    searchFrom = start + marker.length;
  }
  assert.fail(`PBXNativeTarget ${targetName} not resolved`);
}

function configurationIdsFromList(pbx, listId) {
  const listRe = new RegExp(
    `${listId}\\s*=\\s*\\{isa\\s*=\\s*XCConfigurationList;\\s*buildConfigurations\\s*=\\s*\\(([^)]+)\\)`
  );
  const match = pbx.match(listRe);
  assert.ok(match, `XCConfigurationList ${listId} not found`);
  const ids = match[1]
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  assert.ok(ids.length >= 1, `configuration list ${listId} is empty`);
  for (const id of ids) {
    assert.match(id, /^[0-9A-F]{24}$/, `invalid configuration id ${id}`);
  }
  return ids;
}

function parseBuildConfiguration(pbx, configId) {
  const configRe = new RegExp(
    `${configId}\\s*=\\s*\\{isa\\s*=\\s*XCBuildConfiguration;\\s*buildSettings\\s*=\\s*\\{([^}]*)\\};\\s*name\\s*=\\s*(\\w+);\\s*\\};`
  );
  const match = pbx.match(configRe);
  assert.ok(match, `XCBuildConfiguration ${configId} not found`);
  const settings = Object.create(null);
  for (const part of match[1]
    .split(";")
    .map((entry) => entry.trim())
    .filter(Boolean)) {
    const eq = part.indexOf(" = ");
    assert.ok(eq > 0, `malformed build setting in ${configId}: ${part}`);
    settings[part.slice(0, eq)] = part.slice(eq + 3);
  }
  return { id: configId, name: match[2], settings };
}

function configurationsForResolvedTarget(pbx, target) {
  const configIds = configurationIdsFromList(pbx, target.configListId);
  return configIds.map((id) => parseBuildConfiguration(pbx, id));
}

function productReferencePath(pbx, productReferenceId) {
  const re = new RegExp(
    `${productReferenceId}\\s*/\\*\\s*([^\\*]+?)\\s*\\*/\\s*=\\s*\\{isa\\s*=\\s*PBXFileReference;[\\s\\S]*?path\\s*=\\s*([^;]+);`
  );
  const match = pbx.match(re);
  assert.ok(match, `product reference ${productReferenceId} not found`);
  return match[2].trim();
}

describe("iOS companion bundle identity (static)", function () {
  let plist;
  let pbx;
  let appTarget;
  let unitTarget;
  let uiTarget;

  before(function () {
    plist = read(INFO_PLIST);
    pbx = read(PBXPROJ);
    appTarget = resolveNativeTarget(pbx, "PhilCoreCompanion");
    unitTarget = resolveNativeTarget(pbx, "PhilCoreCompanionTests");
    uiTarget = resolveNativeTarget(pbx, "PhilCoreCompanionUITests");
  });

  describe("Info.plist substitution keys", function () {
    for (const [key, expected] of REQUIRED_PLIST_STRINGS) {
      // Exactly-once asserts both presence and duplicate rejection.
      it(`defines ${key} exactly once as ${expected}`, function () {
        assertExactPlistString(plist, key, expected);
      });
    }
  });

  describe("project.pbxproj project-level Debug/Release settings", function () {
    it("project Debug configuration A00000000000000000000001 sets ONLY_ACTIVE_ARCH = YES", function () {
      const listIds = configurationIdsFromList(pbx, PROJECT_CONFIG_LIST_ID);
      assert.deepEqual(
        listIds.sort(),
        [PROJECT_DEBUG_CONFIG_ID, PROJECT_RELEASE_CONFIG_ID].sort(),
        "project configuration list must resolve the two project-level configs by id"
      );
      const debug = parseBuildConfiguration(pbx, PROJECT_DEBUG_CONFIG_ID);
      assert.equal(debug.name, "Debug");
      assert.equal(
        debug.settings.ONLY_ACTIVE_ARCH,
        "YES",
        `project Debug (${PROJECT_DEBUG_CONFIG_ID}) missing ONLY_ACTIVE_ARCH = YES`
      );
    });

    it("project Debug configuration A00000000000000000000001 sets ENABLE_TESTABILITY = YES", function () {
      const debug = parseBuildConfiguration(pbx, PROJECT_DEBUG_CONFIG_ID);
      assert.equal(debug.name, "Debug");
      assert.equal(
        debug.settings.ENABLE_TESTABILITY,
        "YES",
        `project Debug (${PROJECT_DEBUG_CONFIG_ID}) missing ENABLE_TESTABILITY = YES`
      );
    });

    it("project Release configuration A00000000000000000000002 does not enable ONLY_ACTIVE_ARCH", function () {
      const release = parseBuildConfiguration(pbx, PROJECT_RELEASE_CONFIG_ID);
      assert.equal(release.name, "Release");
      assert.equal(
        Object.prototype.hasOwnProperty.call(release.settings, "ONLY_ACTIVE_ARCH"),
        false,
        `project Release (${PROJECT_RELEASE_CONFIG_ID}) must not set ONLY_ACTIVE_ARCH`
      );
    });

    it("project Release configuration A00000000000000000000002 does not enable ENABLE_TESTABILITY", function () {
      const release = parseBuildConfiguration(pbx, PROJECT_RELEASE_CONFIG_ID);
      assert.equal(release.name, "Release");
      assert.equal(
        Object.prototype.hasOwnProperty.call(release.settings, "ENABLE_TESTABILITY"),
        false,
        `project Release (${PROJECT_RELEASE_CONFIG_ID}) must not set ENABLE_TESTABILITY`
      );
    });

    it("no target-level Debug/Release configuration overrides ONLY_ACTIVE_ARCH, ARCHS, EXCLUDED_ARCHS, or ENABLE_TESTABILITY", function () {
      for (const configId of TARGET_LEVEL_CONFIG_IDS) {
        const config = parseBuildConfiguration(pbx, configId);
        for (const key of FORBIDDEN_TARGET_LEVEL_KEYS) {
          assert.equal(
            Object.prototype.hasOwnProperty.call(config.settings, key),
            false,
            `target-level ${config.name} (${configId}) must not set ${key}`
          );
        }
      }
    });
  });

  describe("project.pbxproj target configurations", function () {
    it("app Debug and Release retain Info.plist, local-alpha identity, and PRODUCT_NAME", function () {
      const configs = configurationsForResolvedTarget(pbx, appTarget);
      assert.equal(configs.length, 2, "app target must have exactly two configurations");
      assert.deepEqual(
        configs.map((c) => c.name).sort(),
        ["Debug", "Release"]
      );

      for (const config of configs) {
        for (const [setting, expected] of Object.entries(APP_REQUIRED_SETTINGS)) {
          assert.equal(
            config.settings[setting],
            expected,
            `PhilCoreCompanion ${config.name} (${config.id}) ${setting}`
          );
        }
      }

      const appConfigIds = new Set(configs.map((c) => c.id));
      const allConfigs = [
        ...pbx.matchAll(
          /([0-9A-F]{24})\s*=\s*\{isa\s*=\s*XCBuildConfiguration;\s*buildSettings\s*=\s*\{([^}]*)\};/g
        )
      ].map((m) => ({ id: m[1], body: m[2] }));
      const outsidersWithBundleId = allConfigs.filter(
        (c) =>
          !appConfigIds.has(c.id) &&
          /PRODUCT_BUNDLE_IDENTIFIER\s*=\s*com\.philcore\.ios\.companion\.localalpha;/.test(
            c.body
          )
      );
      assert.equal(
        outsidersWithBundleId.length,
        0,
        "app PRODUCT_BUNDLE_IDENTIFIER must live only in the two app configurations"
      );
    });

    it("unit-test Debug and Release set explicit PRODUCT_NAME and retain TEST_HOST/BUNDLE_LOADER", function () {
      const configs = configurationsForResolvedTarget(pbx, unitTarget);
      assert.equal(
        configs.length,
        2,
        "unit-test target must have exactly two configurations"
      );
      assert.deepEqual(
        configs.map((c) => c.name).sort(),
        ["Debug", "Release"]
      );

      for (const config of configs) {
        assert.equal(
          config.settings.PRODUCT_NAME,
          PRODUCT_NAME_SETTING,
          `PhilCoreCompanionTests ${config.name} (${config.id}) missing explicit PRODUCT_NAME`
        );
        assert.equal(
          config.settings.TEST_HOST,
          '"$(BUILT_PRODUCTS_DIR)/PhilCoreCompanion.app/PhilCoreCompanion"',
          `PhilCoreCompanionTests ${config.name} (${config.id}) TEST_HOST`
        );
        assert.equal(
          config.settings.BUNDLE_LOADER,
          '"$(TEST_HOST)"',
          `PhilCoreCompanionTests ${config.name} (${config.id}) BUNDLE_LOADER`
        );
      }
    });

    it("UI-test Debug and Release set explicit PRODUCT_NAME and retain TEST_TARGET_NAME", function () {
      const configs = configurationsForResolvedTarget(pbx, uiTarget);
      assert.equal(
        configs.length,
        2,
        "UI-test target must have exactly two configurations"
      );
      assert.deepEqual(
        configs.map((c) => c.name).sort(),
        ["Debug", "Release"]
      );

      for (const config of configs) {
        assert.equal(
          config.settings.PRODUCT_NAME,
          PRODUCT_NAME_SETTING,
          `PhilCoreCompanionUITests ${config.name} (${config.id}) missing explicit PRODUCT_NAME`
        );
        assert.equal(
          config.settings.TEST_TARGET_NAME,
          "PhilCoreCompanion",
          `PhilCoreCompanionUITests ${config.name} (${config.id}) TEST_TARGET_NAME`
        );
      }
    });

    it("product references remain non-empty named app and xctest bundles", function () {
      const paths = [
        productReferencePath(pbx, appTarget.productReferenceId),
        productReferencePath(pbx, unitTarget.productReferenceId),
        productReferencePath(pbx, uiTarget.productReferenceId)
      ];
      assert.deepEqual(paths.sort(), [...EXPECTED_PRODUCT_PATHS].sort());

      for (const productPath of paths) {
        assert.notEqual(productPath, ".xctest", "empty .xctest product path");
        assert.notEqual(productPath, "-Runner.app", "empty -Runner.app product path");
        assert.doesNotMatch(
          productPath,
          /^\.xctest$/,
          `illegal empty xctest product: ${productPath}`
        );
        assert.doesNotMatch(
          productPath,
          /^-Runner\.app$/,
          `illegal empty runner product: ${productPath}`
        );
        assert.doesNotMatch(
          productPath,
          /(^|\/)\.xctest$/,
          `illegal empty PlugIns/.xctest-style product: ${productPath}`
        );
        assert.doesNotMatch(
          productPath,
          /(^|\/)-Runner\.app$/,
          `illegal empty -Runner.app-style product: ${productPath}`
        );
      }
    });
  });
});
