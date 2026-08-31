const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const {
  auth,
  adapter,
  deployStep6CFixture,
  buildRequestForNonce,
  SOURCE_PATHS
} = require("../helpers/phil-v1-step6c-fixture.cjs");

describe("Phil V1 Step 6C canonical routine authorization records", function () {
  it("constructs the acyclic local profile and independently validates every derived request hash", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt,
      sessionLabel: "records-positive"
    });
    const validated = auth.validatePhilRoutineAuthorizationRequestV1(built.request);
    assert.equal(validated.requestId, built.request.requestId);
    assert.equal(validated.platformSigningDigest, built.request.platformSigningDigest);
    assert.equal(validated.executionEnvironment.chainId, "31337");
    assert.equal(validated.executionEnvironment.externalNetwork, false);
    assert.equal(validated.executionEnvironment.productionAuthority, false);
    assert.equal(validated.executionEnvironment.meaningfulAssets, false);
    assert.equal(validated.authorizationEnvelope.rootProofNullifier, ethers.ZeroHash);
    assert.equal(validated.authorizationEnvelope.proofDescriptorHash, ethers.ZeroHash);
    assert.equal(validated.deviceEnrollment.secureEnclaveBacked, false);
    assert.equal(validated.deviceEnrollment.userPresenceRequired, false);
  });

  it("keeps schema, capability, catalog, and policy stable while every nonce-bearing request identity changes", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 30n;
    const failed = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: true,
      issuedAt,
      sessionLabel: "records-failed"
    });
    const success = await buildRequestForNonce(f, {
      nonceSequence: 1,
      shouldRevert: false,
      issuedAt: issuedAt + 10n,
      sessionLabel: "records-success"
    });
    assert.equal(f.parameterSchemaId, auth.derivePhilRoutineParameterSchemaIdV1(f.configuration));
    assert.equal(f.policy.capabilityId, auth.derivePhilRoutineCapabilityIdV1({
      scopeInstance: f.configuration.scopeInstance,
      approvedTarget: f.targetAddress,
      approvedTargetRuntimeCodeHash: f.targetCodeHash,
      parameterSchemaId: f.parameterSchemaId
    }));
    assert.equal(f.catalog.entries[5].entryId, f.parameterSchemaId);
    assert.equal(f.catalog.entries[5].boundValueHash, f.parameterSchemaId);
    assert.equal(failed.request.catalogHash, success.request.catalogHash);
    assert.equal(failed.request.capabilityPolicyHash, success.request.capabilityPolicyHash);
    for (const field of ["actionHash", "humanPresentationHash", "authorizationEnvelopeDigest",
      "authorizationCoreDigest", "approvalNonce", "deviceApprovalDigest", "requestId", "platformSigningDigest"]) {
      assert.notEqual(failed.request[field], success.request[field], field);
    }
    assert.equal(failed.request.humanPresentation.parameterSummaryHash, auth.PHIL_STEP6C_PARAMETER_SUMMARY_FAILURE_HASH);
    assert.equal(success.request.humanPresentation.parameterSummaryHash, auth.PHIL_STEP6C_PARAMETER_SUMMARY_SUCCESS_HASH);
  });

  it("rejects calldata, action, request-window, Base-profile, and derived-hash substitution", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 40n;
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt,
      sessionLabel: "records-negative"
    });
    const badBool = `${built.targetCalldata.slice(0, -64)}${"2".padStart(64, "0")}`;
    assert.throws(() => auth.derivePhilRoutineParameterSummaryHashV1(badBool),
      (error) => error.code === "PHIL_ROUTINE_TARGET_CALLDATA_INVALID");
    assert.throws(() => auth.derivePhilRoutineParameterSummaryHashV1(`${built.targetCalldata}00`));
    assert.throws(() => auth.validatePhilRoutineAuthorizationRequestV1({
      ...built.request,
      action: { ...built.request.action, actionHash: ethers.id("substituted") }
    }), (error) => /MISMATCH|INVALID/.test(error.code));
    assert.throws(() => auth.createPhilRoutineAuthorizationRequestV1({
      executionEnvironment: f.environment,
      adapterManifest: f.manifest,
      signatureRegistry: f.signatureRegistry,
      deviceEnrollment: f.enrollment,
      accountConfiguration: f.configuration,
      catalog: f.catalog,
      capabilityPolicy: f.policy,
      action: built.action,
      targetCalldata: built.targetCalldata,
      sessionId: ethers.id("outside"),
      nonceSeed: ethers.id("outside-seed"),
      issuedAt: BigInt(f.policy.validUntil) - 10n,
      expiresAt: BigInt(f.policy.validUntil) + 110n
    }), (error) => error.code === "PHIL_ROUTINE_REQUEST_VALIDITY_INVALID");
    const base = adapter.createPhilBaseMainnetAdapterManifestV1({
      implementationHash: f.identity.implementationHash,
      auditStatusHash: f.identity.auditStatusHash
    });
    assert.throws(() => auth.validatePhilStep6CLocalAdapterManifestV1(base),
      (error) => error.code === "PHIL_ROUTINE_ADAPTER_MANIFEST_MISMATCH");
  });

  it("rejects an independent substitution of every authorization-core field", async function () {
    const f = await deployStep6CFixture();
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt: BigInt(f.policy.validAfter) + 45n,
      sessionLabel: "records-every-core-field"
    });
    const core = built.request.authorizationCore;
    const numeric = new Set(["issuedAt", "expiresAt"]);
    for (const field of Object.keys(core)) {
      const replacement = numeric.has(field)
        ? (BigInt(core[field]) + 1n).toString()
        : ethers.id(`independent-core-substitution:${field}`);
      assert.throws(() => auth.validatePhilRoutineAuthorizationRequestV1({
        ...built.request,
        authorizationCore: { ...core, [field]: replacement }
      }), (error) => /MISMATCH|INVALID|FORBIDDEN/.test(error.code), field);
    }
  });

  it("rejects independent raw-record and top-level derived-identity substitutions", async function () {
    const f = await deployStep6CFixture();
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0, shouldRevert: false, issuedAt: BigInt(f.policy.validAfter) + 47n,
      sessionLabel: "records-every-record-family"
    });
    const wrong = (label) => ethers.id(`independent-record-substitution:${label}`);
    const mutations = [
      ["environment", { ...built.request, executionEnvironment: {
        ...built.request.executionEnvironment, executionEnvironmentHash: wrong("environment") } }],
      ["adapter", { ...built.request, adapterManifest: {
        ...built.request.adapterManifest, manifestHash: wrong("adapter") } }],
      ["registry", { ...built.request, signatureRegistry: {
        ...built.request.signatureRegistry, registryHash: wrong("registry") } }],
      ["enrollment", { ...built.request, deviceEnrollment: {
        ...built.request.deviceEnrollment, deviceEnrollmentHash: wrong("enrollment") } }],
      ["configuration", { ...built.request, accountConfiguration: {
        ...built.request.accountConfiguration, accountConfigurationHash: wrong("configuration") } }],
      ["catalog", { ...built.request, catalogEntries: built.request.catalogEntries.map((entry, index) => index === 0
        ? { ...entry, boundValueHash: wrong("catalog") } : entry) }],
      ["policy", { ...built.request, capabilityPolicy: {
        ...built.request.capabilityPolicy, capabilityPolicyHash: wrong("policy") } }],
      ["action", { ...built.request, action: { ...built.request.action, actionHash: wrong("action") } }],
      ["calldata", { ...built.request, targetCalldata: `${built.request.targetCalldata.slice(0, -2)}01` }],
      ["envelope", { ...built.request, authorizationEnvelope: {
        ...built.request.authorizationEnvelope, intentDigest: wrong("envelope") } }],
      ["approval", { ...built.request, unsignedDeviceApproval: {
        ...built.request.unsignedDeviceApproval, approvalNonce: wrong("approval") } }],
      ["presentation", { ...built.request, humanPresentation: {
        ...built.request.humanPresentation, humanPresentationHash: wrong("presentation") } }]
    ];
    for (const [label, mutation] of mutations) {
      assert.throws(() => auth.validatePhilRoutineAuthorizationRequestV1(mutation),
        (error) => /MISMATCH|INVALID|FORBIDDEN/.test(error.code), label);
    }
    for (const field of ["executionEnvironmentHash", "adapterManifestHash", "signatureRegistryHash",
      "deviceEnrollmentHash", "accountConfigurationHash", "catalogHash", "capabilityPolicyHash", "actionHash",
      "authorizationEnvelopeDigest", "humanPresentationHash", "authorizationCoreDigest", "approvalNonce",
      "deviceApprovalDigest", "requestId", "platformSigningDigest"]) {
      assert.throws(() => auth.validatePhilRoutineAuthorizationRequestV1({ ...built.request, [field]: wrong(field) }),
        (error) => /MISMATCH|INVALID/.test(error.code), field);
    }
  });

  it("freezes the six-file implementation identity in bytewise path order", function () {
    assert.deepEqual(SOURCE_PATHS, [...SOURCE_PATHS].sort());
    assert.equal(SOURCE_PATHS.length, 6);
    assert.ok(SOURCE_PATHS.every((file) => !/test\/unit|artifact|fixture|report/.test(file)));
  });

  it("rejects unknown, duplicate, BOM, alternate-scalar, nested, and response JSON substitutions", async function () {
    const f = await deployStep6CFixture();
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt: BigInt(f.policy.validAfter) + 50n,
      sessionLabel: "records-strict-json"
    });
    const requestJson = JSON.stringify(built.request);
    assert.equal(auth.parsePhilRoutineAuthorizationRequestJsonV1(requestJson).requestId, built.request.requestId);
    assert.throws(() => auth.parsePhilRoutineAuthorizationRequestJsonV1(`\ufeff${requestJson}`),
      (error) => error.code === "PHIL_ROUTINE_JSON_INVALID");
    assert.throws(() => auth.parsePhilRoutineAuthorizationRequestJsonV1(
      requestJson.replace("{", `{"formatVersionHash":"${built.request.formatVersionHash}",`)
    ), (error) => error.code === "PHIL_ROUTINE_JSON_DUPLICATE_KEY");
    assert.throws(() => auth.validatePhilRoutineAuthorizationRequestV1({ ...built.request, unknownField: true }),
      (error) => error.code === "PHIL_ROUTINE_REQUEST_MISMATCH");
    assert.throws(() => auth.validatePhilRoutineAuthorizationRequestV1({
      ...built.request,
      accountConfiguration: { ...built.request.accountConfiguration, unknownNestedField: "forbidden" }
    }), (error) => error.code === "PHIL_ROUTINE_REQUEST_MISMATCH");
    assert.throws(() => auth.validatePhilRoutineAuthorizationRequestV1({
      ...built.request,
      authorizationCore: { ...built.request.authorizationCore, issuedAt: Number(built.request.authorizationCore.issuedAt) }
    }), (error) => error.code === "PHIL_ROUTINE_REQUEST_MISMATCH");
    assert.equal(auth.parsePhilRoutineAuthorizationResponseJsonV1({
      request: built.request,
      json: JSON.stringify(built.response)
    }).responseHash, built.response.responseHash);
    assert.throws(() => auth.verifyPhilRoutineAuthorizationResponseV1({
      request: built.request,
      response: { ...built.response, protocolContextHash: ethers.id("wrong-response-context") }
    }), (error) => error.code === "PHIL_ROUTINE_RESPONSE_MISMATCH");
    const invalidEntries = f.catalog.entries.map((entry, index) => index === 1
      ? { ...entry, displayText: "Phil  Local Network" }
      : entry);
    assert.throws(() => auth.validatePhilRoutineCatalogV1({
      ...f.catalog,
      entries: invalidEntries
    }, { environment: f.environment, configuration: f.configuration }),
    (error) => error.code === "PHIL_ROUTINE_CATALOG_TEXT_INVALID");
  });
});
