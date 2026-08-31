const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const EVIDENCE_PATH =
  "config/solidity/O37_6_V2_CODE_SIZE_ARCHITECTURE.json";
const V1_ACCOUNT =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol";
const V1_FACTORY =
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";
const O374_TRANSPORT =
  "docs/reference/O37_4_AUTHORITY_TRANSPORT_SPECIFICATION.md";
const O374_ABI = "docs/reference/O37_4_ABI_FREEZE.md";
const O371_RECOVERY =
  "docs/reference/O37_1_RECOVERY_EVIDENCE_SPECIFICATION.md";
const O374_FIXTURES =
  "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json";
const O375_EVIDENCE =
  "config/solidity/O37_5_V2_IMPLEMENTATION_CONFLICT_EVIDENCE.json";

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function readJson(relativePath) {
  return JSON.parse(read(relativePath));
}

function sha256(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

function solidityFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name);
    if (entry.isDirectory()) return solidityFiles(resolved);
    return entry.name.endsWith(".sol") ? [resolved] : [];
  });
}

describe("O.37.6 V2 code-size architecture reduction", function () {
  const evidence = readJson(EVIDENCE_PATH);
  const selected = evidence.selectedArchitecture;

  it("records the exact local-only baseline and preserves V1", function () {
    assert.equal(evidence.phase, "O.37.6");
    assert.equal(
      evidence.sourceHeadAtPhaseStart,
      "bb9efbc3ca5d8a391ecdc25aed1c4fad2a981e53"
    );
    assert.equal(evidence.result, "COMPLETE_ARCHITECTURE_ONLY");
    assert.equal(sha256(V1_ACCOUNT), evidence.baseline.v1AccountSourceSha256);
    assert.equal(sha256(V1_FACTORY), evidence.baseline.v1FactorySourceSha256);
  });

  it("preserves O.37.4 transport and O.37.5 evidence byte-for-byte", function () {
    assert.equal(
      sha256(O371_RECOVERY),
      evidence.baseline.o37_1RecoveryEvidenceDocumentSha256
    );
    assert.equal(
      sha256(O374_ABI),
      evidence.baseline.o37_4AbiFreezeDocumentSha256
    );
    assert.equal(
      sha256(O374_TRANSPORT),
      evidence.baseline.o37_4AuthorityTransportDocumentSha256
    );
    assert.equal(
      sha256(O374_FIXTURES),
      evidence.baseline.o37_4AuthorityFixtureSha256
    );
    assert.equal(
      sha256(O375_EVIDENCE),
      evidence.baseline.o37_5ConflictEvidenceSha256
    );
    assert.equal(selected.authorityTransportUnchanged, true);
    assert.equal(selected.historicalO37_4FullProfileUnchanged, true);
  });

  it("reconciles the rejected source-map size attribution exactly", function () {
    const attribution =
      evidence.sizeAttribution.rejectedNativeP256SourceMapAttribution;
    assert.equal(
      attribution.accountSourceBytes
        + attribution.authorityCryptoSourceBytes
        + attribution.openZeppelinDependencyBytes
        + attribution.accountAbstractionDependencyBytes
        + attribution.compilerGeneratedAndUnattributedBytes,
      attribution.accountRuntimeBytes
    );
    assert.equal(
      attribution.embeddedAccountCreationBytes
        + attribution.factoryShellBytes,
      attribution.factoryRuntimeBytes
    );
    assert.equal(
      attribution.accountRuntimeBytes
        + evidence.sizeAttribution.directOpenZeppelinDelta
          .fallbackWebAuthnP256AdditionalBytes,
      evidence.sizeAttribution.directFrozenOpenZeppelin.accountRuntimeBytes
    );
  });

  it("sets hard budgets with explicit EIP-170 reserve", function () {
    const maximum = evidence.sizeAttribution.eip170MaximumRuntimeBytes;
    const budgets = evidence.sizeBudgets;
    assert.equal(
      budgets.staticAuthorityVerifier.runtimeHardMaximumBytes
        + budgets.staticAuthorityVerifier.eip170ReserveBytes,
      maximum
    );
    assert.equal(
      budgets.minimalAccount.runtimeHardMaximumBytes
        + budgets.minimalAccount.eip170RuntimeReserveBytes,
      maximum
    );
    assert.equal(
      budgets.minimalFactory.runtimeHardMaximumBytes
        + budgets.minimalFactory.eip170ReserveBytes,
      maximum
    );
    assert.equal(
      budgets.minimalFactory.embeddedAccountCreationMaximumBytes
        + budgets.minimalFactory.factoryShellMaximumBytes,
      budgets.minimalFactory.runtimeHardMaximumBytes
    );
  });

  it("phases token capabilities without adding modules or generic execution", function () {
    assert.deepEqual(selected.minimalAccountActions, [1, 2, 6, 7, 8, 9, 10, 11]);
    assert.deepEqual(selected.deferredActions, [3, 4, 5]);
    assert.equal(
      selected.minimalAccountActions.some(
        (action) => selected.deferredActions.includes(action)
      ),
      false
    );
    assert.equal(selected.proxyUsed, false);
    assert.equal(selected.genericExecuteAdded, false);
    assert.equal(selected.moduleSystemAdded, false);
    assert.equal(selected.constructorFieldCount, 20);
    assert.equal(selected.constructorDescriptorsAdded, false);
  });

  it("freezes one code-hash-pinned STATICCALL verifier without hidden authority", function () {
    const verifier = selected.authorityVerifier;
    assert.equal(verifier.callOpcode, "STATICCALL");
    for (const field of [
      "storageAllowed",
      "adminAllowed",
      "upgradeAllowed",
      "selfDestructAllowed",
      "registryAllowed",
      "delegatecallAllowed",
      "runtimeBooleanAccepted",
      "nativeP256OnlyDependencySelected"
    ]) {
      assert.equal(verifier[field], false, field);
    }
    assert.equal(verifier.addressFixedByFactoryImmutable, true);
    assert.equal(verifier.runtimeCodeHashFixedByFactoryImmutable, true);
    assert.equal(verifier.accountChecksCodeHashBeforeEveryVerification, true);
    assert.equal(verifier.verifierRequiresCallingAccountBinding, true);
  });

  it("preserves exact 2-of-3 recovery and EntryPoint nonce ownership", function () {
    assert.equal(selected.recoveryThreshold, 2);
    assert.equal(selected.nonceOwner, "ENTRYPOINT_V0_7");
    const security = read(
      "docs/security/O37_6_CODE_SIZE_SECURITY_IMPACT_REVIEW.md"
    );
    assert.match(security, /bitmaps `3`, `5`, `6` remain/);
    assert.match(security, /sole nonce-sequence owner/);
    assert.match(security, /No alternate decoder/);
  });

  it("keeps CREATE2 on the exact immutable factory path", function () {
    const factory = evidence.factoryStrategy;
    assert.equal(factory.create2DeployerRemainsFactory, true);
    assert.equal(factory.deploymentSaltFormulaUnchanged, true);
    assert.equal(factory.accountInitializationFieldCount, 20);
    assert.equal(factory.accountConstructorExternalCallsAllowed, false);
    assert.equal(factory.verifierAddressAndCodeHashAreFactoryImmutables, true);
    assert.equal(factory.creationCodeSuppliedByCaller, false);
    assert.equal(factory.alternateDeployerAllowed, false);
  });

  it("evaluates all four required options and indexes every deliverable", function () {
    const review = read(
      "docs/reference/O37_6_CODE_SIZE_ARCHITECTURE_REVIEW.md"
    );
    for (const option of [
      "A — minimal account kernel",
      "B — capability phasing",
      "C — library usage",
      "D — factory reduction"
    ]) {
      assert.match(review, new RegExp(option));
    }
    const index = read("docs/CANONICAL_DOCS.md");
    for (const file of [
      "O37_6_CODE_SIZE_ARCHITECTURE_REVIEW.md",
      "O37_6_MINIMAL_ACCOUNT_ARCHITECTURE.md",
      "O37_6_FACTORY_SIZE_STRATEGY.md",
      "O37_6_CODE_SIZE_SECURITY_IMPACT_REVIEW.md",
      "O37_6_IMPLEMENTATION_ROADMAP.md"
    ]) {
      assert.match(index, new RegExp(file.replaceAll(".", "\\.")));
    }
  });

  it("records its historical zero-Solidity boundary and allows only reviewed later V2 sources", function () {
    const v2Solidity = solidityFiles(path.join(ROOT, "contracts"))
      .filter((file) => /philcore.*v2/i.test(path.basename(file)));
    assert.deepEqual(
      v2Solidity.map((file) => path.relative(ROOT, file)).sort(),
      [
        "contracts/base/erc4337/v2/IPhilCoreV2MinimalAccountV2.sol",
        "contracts/base/erc4337/v2/IPhilCoreV2StaticAuthorityVerifier.sol",
        "contracts/base/erc4337/v2/PhilCoreV2ConfirmationTargetV1.sol",
        "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol",
        "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol",
        "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol",
        "contracts/test/PhilCoreV2ConfirmationTargetTestMocks.sol",
        "contracts/test/PhilCoreV2MinimalAccountTestMocks.sol"
      ]
    );
    assert.equal(evidence.publicMutationCount, 0);
    for (const [field, value] of Object.entries(evidence.securityBoundary)) {
      assert.equal(value, false, field);
    }
  });
});
