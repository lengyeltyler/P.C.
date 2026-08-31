const assert = require("node:assert/strict");

const {
  bindSessionContextToRuntimeRequest,
  createAuditEventDraft,
  createIntentDraft,
  createRuntimeRequestContext,
  createUserSessionContext,
  createValidationOnlyRuntimeApi,
  detectSensitiveMetadataKeys,
  redactRuntimeMetadata,
  sanitizeAuditEventDraftInput,
  validateNoSensitiveMetadataKeys
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function stringify(value) {
  return JSON.stringify(value);
}

function validIntentRequest(metadata = {}) {
  return {
    requestId: "request-1",
    applicationId: "ethereum-net",
    requestedAt: new Date().toISOString(),
    metadata,
    intent: createIntentDraft({
      intentId: "intent-1",
      kind: "submit-transaction",
      applicationId: "ethereum-net",
      requestedCapabilities: ["request_transaction_submission"],
      payload: {
        chainId: 8453n,
        target: "0x0000000000000000000000000000000000000001"
      },
      expiresAt: new Date(Date.now() + 60_000).toISOString()
    })
  };
}

describe("PhilCore runtime redaction guardrails", function () {
  it("detects obvious sensitive metadata keys", function () {
    const issues = detectSensitiveMetadataKeys({
      source: "unit-test",
      phil_secret: "root-secret",
      nested: {
        privateKey: "private-key"
      }
    });

    assert.equal(issues.length, 2);
    assert.deepEqual(issues.map((issue) => issue.path), ["phil_secret", "nested.privateKey"]);
  });

  it("redacts sensitive metadata values while preserving safe metadata", function () {
    const result = redactRuntimeMetadata({
      safe: "kept",
      password: "hunter2",
      nested: {
        seedPhrase: "abandon abandon abandon"
      }
    });

    assert.equal(result.redacted, true);
    assert.equal(result.value.safe, "kept");
    assert.equal(result.value.password, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.nested.seedPhrase, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(stringify(result.value).includes("hunter2"), false);
    assert.equal(stringify(result.value).includes("abandon abandon abandon"), false);
  });

  it("validates metadata without sensitive keys", function () {
    assert.deepEqual(validateNoSensitiveMetadataKeys({ source: "unit-test" }), {
      valid: true,
      errors: []
    });

    const result = validateNoSensitiveMetadataKeys({ rawVaultKey: "raw-key" });
    assert.deepEqual(result, {
      valid: false,
      errors: ["rawVaultKey contains sensitive runtime metadata key rawVaultKey"]
    });
  });

  it("fails closed instead of returning the reproduced default-depth array subtree", function () {
    const canary = "DEFAULT-DEPTH-ARRAY-CANARY";
    const input = {
      a: [{
        b: [{
          c: { password: canary }
        }]
      }]
    };

    const redacted = redactRuntimeMetadata(input);
    const rejected = validateNoSensitiveMetadataKeys(input);

    assert.equal(redacted.value.a[0].b[0].c, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(stringify(redacted.value).includes(canary), false);
    assert.deepEqual(redacted.issues.map((issue) => [issue.path, issue.fieldName]), [
      ["a[0].b[0].c", "<maxDepth>"]
    ]);
    assert.equal(rejected.valid, false);
    assert.deepEqual(rejected.errors, [
      "a[0].b[0].c: metadata traversal exceeded maxDepth; subtree was replaced"
    ]);
  });

  it("inspects direct sensitive keys at maxDepth zero and replaces deeper children", function () {
    const input = {
      privateKey: "MAX-DEPTH-ZERO-SECRET",
      nested: { safe: "must-not-be-returned-by-reference" }
    };

    const result = redactRuntimeMetadata(input, { maxDepth: 0 });

    assert.equal(result.value.privateKey, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.nested, "[REDACTED_RUNTIME_METADATA]");
    assert.deepEqual(result.issues.map((issue) => [issue.path, issue.fieldName]), [
      ["privateKey", "privateKey"],
      ["nested", "<maxDepth>"]
    ]);
    assert.equal(stringify(result.value).includes("MAX-DEPTH-ZERO-SECRET"), false);
  });

  it("still inspects direct sensitive keys on the default depth boundary", function () {
    const result = redactRuntimeMetadata({
      a: { b: { c: { d: { privateKey: "BOUNDARY-SECRET" } } } }
    });

    assert.equal(result.value.a.b.c.d.privateKey, "[REDACTED_RUNTIME_METADATA]");
    assert.deepEqual(result.issues.map((issue) => issue.path), ["a.b.c.d.privateKey"]);
  });

  it("returns no input containers, never freezes input, and deeply freezes output", function () {
    const beyondBoundary = { safe: "caller-owned" };
    const input = {
      safe: { nested: ["kept"] },
      beyondBoundary
    };

    const result = redactRuntimeMetadata(input, { maxDepth: 0 });

    assert.notEqual(result.value, input);
    assert.equal(result.value.safe, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.beyondBoundary, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(Object.isFrozen(input), false);
    assert.equal(Object.isFrozen(input.safe), false);
    assert.equal(Object.isFrozen(input.safe.nested), false);
    assert.equal(Object.isFrozen(beyondBoundary), false);
    assert.equal(Object.isFrozen(result.value), true);

    const withinBoundary = redactRuntimeMetadata({ safe: { nested: ["kept"] } });
    assert.equal(Object.isFrozen(withinBoundary.value), true);
    assert.equal(Object.isFrozen(withinBoundary.value.safe), true);
    assert.equal(Object.isFrozen(withinBoundary.value.safe.nested), true);
  });

  it("does not invoke getters, setters, toJSON, iterators, or collection traversal", function () {
    const calls = {
      getter: 0,
      setter: 0,
      toJSON: 0,
      iterator: 0
    };
    const accessorInput = {};
    Object.defineProperty(accessorInput, "privateKey", {
      enumerable: true,
      get() {
        calls.getter += 1;
        return "GETTER-SECRET";
      },
      set() {
        calls.setter += 1;
      }
    });
    const hostileHooks = {
      toJSON() {
        calls.toJSON += 1;
        return { password: "TOJSON-SECRET" };
      },
      [Symbol.iterator]() {
        calls.iterator += 1;
        return [][Symbol.iterator]();
      }
    };
    const collection = new Map([["password", "MAP-SECRET"]]);

    const result = redactRuntimeMetadata({ accessorInput, hostileHooks, collection });

    assert.deepEqual(calls, { getter: 0, setter: 0, toJSON: 0, iterator: 0 });
    assert.equal(result.value.accessorInput.privateKey, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.hostileHooks.toJSON, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.collection, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(stringify(result.value).includes("GETTER-SECRET"), false);
    assert.ok(result.issues.some((issue) => issue.fieldName === "<unsupportedProperty>"));
    assert.ok(result.issues.some((issue) => issue.fieldName === "<unsupportedValue>"));
  });

  it("fails closed when nested or root reflection throws", function () {
    const nested = new Proxy({}, {
      ownKeys() {
        throw new Error("hostile ownKeys trap");
      }
    });
    const root = new Proxy({}, {
      ownKeys() {
        throw new Error("hostile root ownKeys trap");
      }
    });

    const nestedResult = redactRuntimeMetadata({ nested });
    const rootResult = redactRuntimeMetadata(root);

    assert.equal(nestedResult.value.nested, "[REDACTED_RUNTIME_METADATA]");
    assert.deepEqual(
      nestedResult.issues.map((issue) => [issue.path, issue.fieldName]),
      [["nested", "<reflection>"]]
    );
    assert.equal(Object.getPrototypeOf(rootResult.value), Object.prototype);
    assert.deepEqual(Object.keys(rootResult.value), []);
    assert.deepEqual(
      rootResult.issues.map((issue) => [issue.path, issue.fieldName]),
      [["$", "<reflection>"]]
    );
  });

  it("replaces self and mutual cycles while copying shared non-cyclic aliases", function () {
    const self = { safe: "kept" };
    self.self = self;
    const left = { name: "left" };
    const right = { name: "right", left };
    left.right = right;
    const shared = { stable: true };

    const selfResult = redactRuntimeMetadata(self);
    const mutualResult = redactRuntimeMetadata(left);
    const sharedResult = redactRuntimeMetadata({ first: shared, second: shared });

    assert.equal(selfResult.value.self, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(mutualResult.value.right.left, "[REDACTED_RUNTIME_METADATA]");
    assert.deepEqual(selfResult.issues.map((issue) => issue.fieldName), ["<cycle>"]);
    assert.deepEqual(mutualResult.issues.map((issue) => issue.fieldName), ["<cycle>"]);
    assert.notEqual(sharedResult.value.first, shared);
    assert.notEqual(sharedResult.value.second, shared);
    assert.notEqual(sharedResult.value.first, sharedResult.value.second);
    assert.deepEqual(sharedResult.value.first, { stable: true });
    assert.deepEqual(sharedResult.value.second, { stable: true });
  });

  it("replaces unsupported nested values once and rejects unsupported roots deterministically", function () {
    class UnsupportedClass {
      constructor() {
        this.safe = "must-not-be-structurally-consumed";
      }
    }
    const result = redactRuntimeMetadata({
      date: new Date("2026-07-31T00:00:00.000Z"),
      map: new Map(),
      instance: new UnsupportedClass(),
      callable() {}
    });

    assert.deepEqual(result.value, {
      date: "[REDACTED_RUNTIME_METADATA]",
      map: "[REDACTED_RUNTIME_METADATA]",
      instance: "[REDACTED_RUNTIME_METADATA]",
      callable: "[REDACTED_RUNTIME_METADATA]"
    });
    assert.deepEqual(result.issues.map((issue) => issue.path), [
      "date",
      "map",
      "instance",
      "callable"
    ]);
    assert.throws(
      () => redactRuntimeMetadata(new Date("2026-07-31T00:00:00.000Z")),
      (error) => error?.name === "RuntimeMetadataRootRejectedError"
        && error?.message === "$: runtime metadata root is unsupported"
    );
    assert.deepEqual(validateNoSensitiveMetadataKeys(new Map()), {
      valid: false,
      errors: ["$: metadata value type is unsupported; subtree was replaced"]
    });
  });

  it("preserves ordinary sparse arrays without retaining their entries", function () {
    const input = new Array(4);
    input[1] = { password: "SPARSE-SECRET" };

    const result = redactRuntimeMetadata(input);

    assert.equal(result.value.length, 4);
    assert.equal(0 in result.value, false);
    assert.equal(1 in result.value, true);
    assert.equal(2 in result.value, false);
    assert.equal(3 in result.value, false);
    assert.notEqual(result.value[1], input[1]);
    assert.equal(result.value[1].password, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(Object.isFrozen(result.value), true);
    assert.equal(Object.isFrozen(result.value[1]), true);
    assert.equal(Object.isFrozen(input), false);
    assert.equal(Object.isFrozen(input[1]), false);
  });

  it("copies prototype-sensitive keys without prototype pollution", function () {
    const input = Object.create(null);
    Object.defineProperty(input, "__proto__", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: { password: "PROTO-SECRET" }
    });
    Object.defineProperty(input, "constructor", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: { safe: "constructor-value" }
    });
    Object.defineProperty(input, "prototype", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: { safe: "prototype-value" }
    });

    const result = redactRuntimeMetadata(input);

    assert.equal(Object.getPrototypeOf(result.value), null);
    assert.equal(Object.hasOwn(result.value, "__proto__"), true);
    assert.equal(result.value.__proto__.password, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.constructor.safe, "constructor-value");
    assert.equal(result.value.prototype.safe, "prototype-value");
    assert.equal(Object.prototype.password, undefined);
    assert.equal(Object.prototype.safe, undefined);
  });

  it("bounds issues while continuing to redact every sensitive field", function () {
    const input = {
      privateKey: "ONE",
      password: "TWO",
      seedPhrase: "THREE",
      recoverySecret: "FOUR"
    };

    const result = redactRuntimeMetadata(input, { maxIssues: 2 });

    assert.equal(result.issues.length, 2);
    assert.equal(result.issues[0].fieldName, "privateKey");
    assert.equal(result.issues[1].fieldName, "<maxIssues>");
    assert.deepEqual(result.value, {
      privateKey: "[REDACTED_RUNTIME_METADATA]",
      password: "[REDACTED_RUNTIME_METADATA]",
      seedPhrase: "[REDACTED_RUNTIME_METADATA]",
      recoverySecret: "[REDACTED_RUNTIME_METADATA]"
    });
  });

  it("normalizes invalid maxDepth and maxIssues with explicit policy issues", function () {
    const depth = redactRuntimeMetadata({
      safe: { password: "NORMALIZED-DEPTH-SECRET" }
    }, { maxDepth: Number.NaN });
    const issues = redactRuntimeMetadata({
      privateKey: "NORMALIZED-ISSUE-SECRET"
    }, { maxIssues: 0 });

    assert.ok(depth.issues.some((issue) => issue.path === "$"
      && issue.fieldName === "<policy.maxDepth>"));
    assert.equal(depth.value.safe.password, "[REDACTED_RUNTIME_METADATA]");
    assert.ok(issues.issues.some((issue) => issue.path === "$"
      && issue.fieldName === "<policy.maxIssues>"));
    assert.equal(issues.value.privateKey, "[REDACTED_RUNTIME_METADATA]");
  });

  it("fails closed on a nested revoked proxy instead of an uncaught Array.isArray exception", function () {
    const { proxy: revoked, revoke } = Proxy.revocable({}, {});
    revoke();

    const result = redactRuntimeMetadata({
      safe: "kept",
      nested: revoked,
      password: "NESTED-REVOKED-PROXY-SECRET"
    });

    assert.equal(result.value.safe, "kept");
    assert.equal(result.value.nested, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.password, "[REDACTED_RUNTIME_METADATA]");
    assert.ok(
      result.issues.some((issue) => issue.path === "nested" && issue.fieldName === "<reflection>"),
      JSON.stringify(result.issues)
    );
    assert.equal(stringify(result.value).includes("NESTED-REVOKED-PROXY-SECRET"), false);

    const rejected = validateNoSensitiveMetadataKeys({
      safe: "kept",
      nested: revoked,
      password: "NESTED-REVOKED-PROXY-SECRET"
    });
    assert.equal(rejected.valid, false);
    assert.ok(rejected.errors.some((error) => error.includes("nested")));
    assert.ok(rejected.errors.some((error) => error.includes("password")));
  });

  it("fails closed on a revoked root proxy through the documented reflection behavior", function () {
    const { proxy: revoked, revoke } = Proxy.revocable({}, {});
    revoke();

    const result = redactRuntimeMetadata(revoked);

    assert.equal(Object.getPrototypeOf(result.value), Object.prototype);
    assert.deepEqual(Object.keys(result.value), []);
    assert.deepEqual(
      result.issues.map((issue) => [issue.path, issue.fieldName]),
      [["$", "<reflection>"]]
    );

    const rejected = validateNoSensitiveMetadataKeys(revoked);
    assert.equal(rejected.valid, false);
    assert.deepEqual(rejected.errors, [
      "$: metadata reflection failed; subtree was replaced"
    ]);
  });

  it("returns the specific issue, not the aggregate, when maxIssues is 1 and exactly one issue occurs", function () {
    const result = redactRuntimeMetadata({
      privateKey: "MAX-ISSUES-ONE-SINGLE-SECRET"
    }, { maxIssues: 1 });

    assert.equal(result.issues.length, 1);
    assert.equal(result.issues[0].fieldName, "privateKey");
    assert.equal(result.value.privateKey, "[REDACTED_RUNTIME_METADATA]");
  });

  it("returns only the aggregate when maxIssues is 1 and two or more issues occur", function () {
    const result = redactRuntimeMetadata({
      privateKey: "MAX-ISSUES-ONE-FIRST-SECRET",
      password: "MAX-ISSUES-ONE-SECOND-SECRET"
    }, { maxIssues: 1 });

    assert.equal(result.issues.length, 1);
    assert.equal(result.issues[0].fieldName, "<maxIssues>");
    assert.equal(result.value.privateKey, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.password, "[REDACTED_RUNTIME_METADATA]");
  });

  it("preserves all N specific issues when the issue count exactly equals the cap", function () {
    const result = redactRuntimeMetadata({
      privateKey: "CAP-EXACT-ONE",
      password: "CAP-EXACT-TWO",
      seedPhrase: "CAP-EXACT-THREE"
    }, { maxIssues: 3 });

    assert.equal(result.issues.length, 3);
    assert.deepEqual(
      result.issues.map((issue) => issue.fieldName),
      ["privateKey", "password", "seedPhrase"]
    );
    assert.deepEqual(result.value, {
      privateKey: "[REDACTED_RUNTIME_METADATA]",
      password: "[REDACTED_RUNTIME_METADATA]",
      seedPhrase: "[REDACTED_RUNTIME_METADATA]"
    });
  });

  it("converts only the final slot to the aggregate on the N+1th issue while continuing to redact every sensitive field", function () {
    const result = redactRuntimeMetadata({
      privateKey: "CAP-OVERFLOW-ONE",
      password: "CAP-OVERFLOW-TWO",
      seedPhrase: "CAP-OVERFLOW-THREE",
      recoverySecret: "CAP-OVERFLOW-FOUR"
    }, { maxIssues: 3 });

    assert.equal(result.issues.length, 3);
    assert.deepEqual(
      result.issues.map((issue) => issue.fieldName),
      ["privateKey", "password", "<maxIssues>"]
    );
    assert.deepEqual(result.value, {
      privateKey: "[REDACTED_RUNTIME_METADATA]",
      password: "[REDACTED_RUNTIME_METADATA]",
      seedPhrase: "[REDACTED_RUNTIME_METADATA]",
      recoverySecret: "[REDACTED_RUNTIME_METADATA]"
    });
  });

  it("rejects secret-shaped User Session metadata before context creation", function () {
    const result = createUserSessionContext({
      sessionId: "session-1",
      status: "unlocked",
      metadata: {
        requestMetadata: {
          phil_secret: "must-not-enter-session-context"
        }
      }
    });

    assert.equal(result.status, "failed");
    assert.ok(result.errors.some((error) => error.includes("phil_secret")));
    assert.equal(stringify(result).includes("must-not-enter-session-context"), false);
  });

  it("redacts request metadata while binding session context", function () {
    const session = createUserSessionContext({
      sessionId: "session-1",
      status: "unlocked"
    }).context;
    const context = createRuntimeRequestContext({
      requestId: "request-1",
      applicationId: "ethereum-net",
      metadata: {
        safe: "kept",
        signingKey: "signing-key-value"
      }
    });

    const bound = bindSessionContextToRuntimeRequest(context, session);

    assert.equal(bound.metadata.safe, "kept");
    assert.equal(bound.metadata.signingKey, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(stringify(bound).includes("signing-key-value"), false);
  });

  it("sanitizes audit event draft inputs and created audit drafts", function () {
    const input = sanitizeAuditEventDraftInput({
      category: "runtime",
      outcome: "validation_succeeded",
      summary: "Runtime validation completed.",
      redactedDetails: {
        safe: "kept",
        recoverySecret: "recovery-secret-value"
      }
    });
    const draft = createAuditEventDraft(input);

    assert.equal(input.redactedDetails.recoverySecret, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(draft.redactedDetails.recoverySecret, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(stringify(draft).includes("recovery-secret-value"), false);
  });

  it("facade audit drafts redact unsafe request and session metadata", function () {
    const userSessionContext = {
      sessionId: "session-1",
      status: "unlocked",
      activeCapabilityIds: [],
      pendingIntentIds: [],
      policyMode: "default",
      metadata: {
        requestMetadata: {
          vaultKey: "vault-key-value"
        }
      }
    };
    const api = createValidationOnlyRuntimeApi({ userSessionContext });
    const result = api.requestIntent(validIntentRequest({
      safe: "kept",
      privateKey: "private-key-value"
    }));
    const draftText = stringify(result.value.auditEventDraft);

    assert.equal(result.status, "approved");
    assert.equal(result.value.auditEventDraft.redactedDetails.requestMetadata.safe, "kept");
    assert.equal(
      result.value.auditEventDraft.redactedDetails.requestMetadata.privateKey,
      "[REDACTED_RUNTIME_METADATA]"
    );
    assert.equal(
      result.value.auditEventDraft.redactedDetails.requestMetadata.userSession.metadata
        .requestMetadata.vaultKey,
      "[REDACTED_RUNTIME_METADATA]"
    );
    assert.equal(draftText.includes("private-key-value"), false);
    assert.equal(draftText.includes("vault-key-value"), false);
  });

  it("does not call vault, storage, trust, policy, authorization, proof, or adapter hooks", function () {
    const hooks = {
      vaultCalls: 0,
      storageCalls: 0,
      trustCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const api = createValidationOnlyRuntimeApi();
    const result = api.requestAuthorization(validIntentRequest({
      hooks,
      passphrase: "passphrase-value"
    }));

    assert.equal(result.status, "approved");
    assert.deepEqual(hooks, {
      vaultCalls: 0,
      storageCalls: 0,
      trustCalls: 0,
      policyCalls: 0,
      authorizationCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
    assert.equal(stringify(result).includes("passphrase-value"), false);
  });
});

// ---------------------------------------------------------------------------
// A2: resource-exhaustion budgets (maxTraversedNodes, maxInspectedProperties,
// maxTotalCharacters, maxArrayLength). These tests are written against the
// unmodified A1 implementation and are expected to fail at this commit --
// none of the new policy fields exist yet, so every budget is unenforced.
// ---------------------------------------------------------------------------

const DEFAULT_REDACTED_VALUE_LENGTH = "[REDACTED_RUNTIME_METADATA]".length;

function wideObject(width) {
  const o = {};
  for (let i = 0; i < width; i++) o[`k${i}`] = `v${i}`;
  return o;
}

// A linear chain of exactly `count` nested container objects (the innermost
// holds one scalar leaf, which is not itself a container).
function chainOfContainers(count) {
  let root = { leaf: "value" };
  for (let i = 0; i < count - 1; i++) root = { child: root };
  return root;
}

// Wraps `target` in a Proxy that counts ownKeys calls and getOwnPropertyDescriptor
// calls (split into "length" vs. everything else), without altering any
// returned value -- used to prove exactly how much reflection work happened.
function countingProxy(target) {
  const counters = { ownKeys: 0, lengthDescriptor: 0, elementDescriptor: 0 };
  const proxy = new Proxy(target, {
    ownKeys(t) {
      counters.ownKeys += 1;
      return Reflect.ownKeys(t);
    },
    getOwnPropertyDescriptor(t, key) {
      if (key === "length") counters.lengthDescriptor += 1;
      else counters.elementDescriptor += 1;
      return Reflect.getOwnPropertyDescriptor(t, key);
    }
  });
  return { proxy, counters };
}

describe("PhilCore runtime redaction A2: maxTraversedNodes", function () {
  it("allows exactly maxTraversedNodes containers and replaces the next one", function () {
    const atLimit = redactRuntimeMetadata(chainOfContainers(5), {
      maxDepth: 10,
      maxTraversedNodes: 5
    });
    assert.equal(atLimit.issues.some((i) => i.fieldName === "<maxTraversedNodes>"), false);

    const overLimit = redactRuntimeMetadata(chainOfContainers(6), {
      maxDepth: 10,
      maxTraversedNodes: 5
    });
    assert.ok(overLimit.issues.some((i) => i.fieldName === "<maxTraversedNodes>"));
  });

  it("treats zero as valid: the root container is retained but empty", function () {
    const result = redactRuntimeMetadata({ a: 1 }, { maxTraversedNodes: 0 });
    assert.deepEqual(result.value, {});
    assert.ok(result.issues.some((i) => i.fieldName === "<maxTraversedNodes>" && i.path === "$"));
  });

  it("normalizes maxTraversedNodes at the hard maximum, above it, and when invalid", function () {
    const atHardMax = redactRuntimeMetadata({ a: 1 }, { maxTraversedNodes: 10_000 });
    assert.equal(atHardMax.issues.some((i) => i.fieldName === "<policy.maxTraversedNodes>"), false);

    const aboveHardMax = redactRuntimeMetadata({ a: 1 }, { maxTraversedNodes: 10_001 });
    assert.ok(
      aboveHardMax.issues.some((i) =>
        i.fieldName === "<policy.maxTraversedNodes>" && i.message.includes("exceeded the hard maximum")),
      JSON.stringify(aboveHardMax.issues)
    );

    const negative = redactRuntimeMetadata({ a: 1 }, { maxTraversedNodes: -1 });
    assert.ok(
      negative.issues.some((i) =>
        i.fieldName === "<policy.maxTraversedNodes>" && i.message.includes("was invalid")),
      JSON.stringify(negative.issues)
    );

    const nonInteger = redactRuntimeMetadata({ a: 1 }, { maxTraversedNodes: 1.5 });
    assert.ok(nonInteger.issues.some((i) => i.fieldName === "<policy.maxTraversedNodes>"));

    const nonFinite = redactRuntimeMetadata({ a: 1 }, { maxTraversedNodes: Infinity });
    assert.ok(nonFinite.issues.some((i) => i.fieldName === "<policy.maxTraversedNodes>"));
  });

  it("charges traversed nodes globally across sibling branches, not per-branch", function () {
    const input = {
      branchA: { x: { y: "leaf" } },
      branchB: { x: { y: "leaf" } }
    };
    // Containers in traversal order: root(1), branchA(2), branchA.x(3) succeed;
    // branchB(4) is the first container over a budget of 3.
    const result = redactRuntimeMetadata(input, { maxDepth: 10, maxTraversedNodes: 3 });
    assert.deepEqual(result.value.branchA, { x: { y: "leaf" } });
    assert.equal(result.value.branchB, "[REDACTED_RUNTIME_METADATA]");
    assert.ok(result.issues.some((i) => i.fieldName === "<maxTraversedNodes>" && i.path === "branchB"));
  });

  it("charges shared non-cyclic references independently, once per occurrence", function () {
    const shared = { x: 1 };
    const result = redactRuntimeMetadata(
      { first: shared, second: shared, third: shared },
      { maxTraversedNodes: 3 }
    );
    // root(1) + first(2) + second(3) succeed; third(4) exceeds the budget.
    assert.deepEqual(result.value.first, { x: 1 });
    assert.deepEqual(result.value.second, { x: 1 });
    assert.equal(result.value.third, "[REDACTED_RUNTIME_METADATA]");
  });

  it("does not charge an extra traversed node for a cycle replacement", function () {
    const self = { self: null };
    self.self = self;
    const result = redactRuntimeMetadata(self, { maxTraversedNodes: 1 });
    assert.equal(result.value.self, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.issues.some((i) => i.fieldName === "<maxTraversedNodes>"), false);
  });

  it("does not charge a traversed node for a revoked-proxy reflection failure", function () {
    const { proxy: revoked, revoke } = Proxy.revocable({}, {});
    revoke();
    const result = redactRuntimeMetadata({ nested: revoked }, { maxTraversedNodes: 1 });
    assert.equal(result.value.nested, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.issues.some((i) => i.fieldName === "<maxTraversedNodes>"), false);
  });
});

describe("PhilCore runtime redaction A2: maxInspectedProperties", function () {
  it("allows exactly maxInspectedProperties properties and omits the next one", function () {
    const atLimit = redactRuntimeMetadata(wideObject(10), { maxInspectedProperties: 10 });
    assert.equal(Object.keys(atLimit.value).length, 10);
    assert.equal(atLimit.issues.some((i) => i.fieldName === "<maxInspectedProperties>"), false);

    const overLimit = redactRuntimeMetadata(wideObject(11), { maxInspectedProperties: 10 });
    assert.equal(Object.keys(overLimit.value).length, 10);
    assert.ok(overLimit.issues.some((i) => i.fieldName === "<maxInspectedProperties>"));
  });

  it("treats zero as valid: the root container is retained but empty", function () {
    const result = redactRuntimeMetadata({ a: 1, b: 2 }, { maxInspectedProperties: 0 });
    assert.deepEqual(result.value, {});
    assert.ok(result.issues.some((i) => i.fieldName === "<maxInspectedProperties>"));
  });

  it("normalizes maxInspectedProperties at the hard maximum, above it, and when invalid", function () {
    const atHardMax = redactRuntimeMetadata({ a: 1 }, { maxInspectedProperties: 50_000 });
    assert.equal(atHardMax.issues.some((i) => i.fieldName === "<policy.maxInspectedProperties>"), false);

    const aboveHardMax = redactRuntimeMetadata({ a: 1 }, { maxInspectedProperties: 50_001 });
    assert.ok(
      aboveHardMax.issues.some((i) =>
        i.fieldName === "<policy.maxInspectedProperties>" && i.message.includes("exceeded the hard maximum")),
      JSON.stringify(aboveHardMax.issues)
    );

    const negative = redactRuntimeMetadata({ a: 1 }, { maxInspectedProperties: -1 });
    assert.ok(
      negative.issues.some((i) =>
        i.fieldName === "<policy.maxInspectedProperties>" && i.message.includes("was invalid")),
      JSON.stringify(negative.issues)
    );

    const wrongType = redactRuntimeMetadata({ a: 1 }, { maxInspectedProperties: "10" });
    assert.ok(wrongType.issues.some((i) => i.fieldName === "<policy.maxInspectedProperties>"));
  });

  it("charges properties globally across nested containers, not per-container", function () {
    const input = { a: wideObject(5), b: wideObject(5) };
    // Root has 2 own keys ("a","b"): charging "a"(#1) then its 5 children (#2-#6) = 6.
    // Charging "b"(#7) reaches the budget exactly; b's own first child would be #8 and fails.
    const result = redactRuntimeMetadata(input, { maxDepth: 5, maxInspectedProperties: 7 });
    assert.equal(Object.keys(result.value.a).length, 5);
    assert.equal(Object.keys(result.value.b).length, 0);
    assert.ok(result.issues.some((i) => i.fieldName === "<maxInspectedProperties>"));
  });

  it("charges a property for a symbol key before rejecting it as unsupported", function () {
    // Reflect.ownKeys always orders string keys before symbol keys regardless
    // of definition order, so both keys here are symbols to keep iteration
    // order unambiguous: symA is charged and rejected as unsupported, then
    // symB's charge itself exhausts the budget.
    const symA = Symbol("a");
    const symB = Symbol("b");
    const target = {};
    Object.defineProperty(target, symA, { value: "x", enumerable: true, configurable: true });
    Object.defineProperty(target, symB, { value: "y", enumerable: true, configurable: true });
    const result = redactRuntimeMetadata(target, { maxInspectedProperties: 1 });
    assert.equal(Object.keys(result.value).length, 0);
    assert.ok(result.issues.some((i) => i.fieldName === "<unsupportedProperty>"));
    assert.ok(result.issues.some((i) => i.fieldName === "<maxInspectedProperties>"));
  });

  it("stops fetching descriptors exactly at the property budget, proven with a counting Proxy", function () {
    const { proxy, counters } = countingProxy(wideObject(1000));
    redactRuntimeMetadata(proxy, { maxInspectedProperties: 50 });
    assert.equal(counters.ownKeys, 1);
    assert.equal(counters.elementDescriptor, 50);
  });

  it("halts across nested containers and never fetches a descriptor beyond the global property budget", function () {
    const { proxy, counters } = countingProxy(wideObject(1000));
    redactRuntimeMetadata({ a: "x", nested: proxy }, { maxInspectedProperties: 20 });
    // top-level charges "a"(1) and "nested"(1) = 2; 18 remain for nested's contents.
    assert.equal(counters.elementDescriptor, 18);
  });
});

describe("PhilCore runtime redaction A2: maxTotalCharacters", function () {
  it("allows a property name at exactly the character budget and halts on one that exceeds it", function () {
    const name9 = "k".repeat(9);
    const atLimit = redactRuntimeMetadata({ [name9]: "v" }, { maxTotalCharacters: 10 });
    assert.equal(atLimit.value[name9], "v");
    assert.equal(atLimit.issues.some((i) => i.fieldName === "<maxTotalCharacters>"), false);

    const name10 = "k".repeat(10);
    const overLimit = redactRuntimeMetadata({ [name10]: "v" }, { maxTotalCharacters: 9 });
    assert.equal(Object.keys(overLimit.value).length, 0);
    assert.ok(overLimit.issues.some((i) => i.fieldName === "<maxTotalCharacters>"));
  });

  it("treats zero as valid: any non-empty content is omitted", function () {
    const result = redactRuntimeMetadata({ a: "x" }, { maxTotalCharacters: 0 });
    assert.deepEqual(result.value, {});
    assert.ok(result.issues.some((i) => i.fieldName === "<maxTotalCharacters>"));
  });

  it("normalizes maxTotalCharacters at the hard maximum, above it, and when invalid", function () {
    const atHardMax = redactRuntimeMetadata({ a: 1 }, { maxTotalCharacters: 1_048_576 });
    assert.equal(atHardMax.issues.some((i) => i.fieldName === "<policy.maxTotalCharacters>"), false);

    const aboveHardMax = redactRuntimeMetadata({ a: 1 }, { maxTotalCharacters: 1_048_577 });
    assert.ok(
      aboveHardMax.issues.some((i) =>
        i.fieldName === "<policy.maxTotalCharacters>" && i.message.includes("exceeded the hard maximum")),
      JSON.stringify(aboveHardMax.issues)
    );

    const negative = redactRuntimeMetadata({ a: 1 }, { maxTotalCharacters: -1 });
    assert.ok(
      negative.issues.some((i) =>
        i.fieldName === "<policy.maxTotalCharacters>" && i.message.includes("was invalid")),
      JSON.stringify(negative.issues)
    );
  });

  it("charges a very long property name and halts before fetching its descriptor", function () {
    const longName = "k".repeat(1000);
    const { proxy, counters } = countingProxy({ [longName]: "v", after: "unreachable" });
    const result = redactRuntimeMetadata(proxy, { maxTotalCharacters: 100 });
    assert.equal(counters.elementDescriptor, 0);
    assert.equal(Object.keys(result.value).length, 0);
  });

  it("retains a large string scalar value under a generous budget and replaces it once the budget is exceeded", function () {
    const big = "y".repeat(1000);
    const underBudget = redactRuntimeMetadata({ note: big }, { maxTotalCharacters: 2000 });
    assert.equal(underBudget.value.note, big);

    const overBudget = redactRuntimeMetadata({ note: big }, { maxTotalCharacters: 100 });
    assert.equal(overBudget.value.note, "[REDACTED_RUNTIME_METADATA]");
    assert.ok(overBudget.issues.some((i) => i.fieldName === "<maxTotalCharacters>"));
  });

  it("falls back to an empty string when even the redactedValue placeholder does not fit, never retaining part of the original value", function () {
    const result = redactRuntimeMetadata(
      { n: "x".repeat(1000) },
      { maxTotalCharacters: 1, redactedValue: "[REDACTED]" }
    );
    assert.equal(result.value.n, "");
    assert.equal(stringify(result.value).includes("x"), false);
    assert.ok(result.issues.some((i) => i.fieldName === "<maxTotalCharacters>"));
  });

  it("records exactly one <maxTotalCharacters> issue when a scalar string and its own placeholder both fail to fit", function () {
    const result = redactRuntimeMetadata({ n: "x".repeat(1000) }, { maxTotalCharacters: 1 });
    const budgetIssues = result.issues.filter((i) => i.fieldName === "<maxTotalCharacters>");
    assert.equal(budgetIssues.length, 1, JSON.stringify(result.issues));
    assert.equal(result.value.n, "");
    assert.equal(stringify(result.value).includes("x"), false);
  });

  it("keeps the specific <maxTotalCharacters> issue under maxIssues: 1 instead of the aggregate", function () {
    const result = redactRuntimeMetadata(
      { n: "x".repeat(1000) },
      { maxTotalCharacters: 1, maxIssues: 1 }
    );
    assert.equal(result.issues.length, 1, JSON.stringify(result.issues));
    assert.equal(result.issues[0].fieldName, "<maxTotalCharacters>");
  });

  it("halts traversal after a scalar-string character-budget exhaustion, omitting subsequent siblings", function () {
    const result = redactRuntimeMetadata(
      { n: "x".repeat(1000), after: "unreachable" },
      { maxTotalCharacters: 1 }
    );
    assert.equal(result.value.n, "");
    assert.equal("after" in result.value, false, "an unvisited sibling must be omitted once traversal halts");
    const budgetIssues = result.issues.filter((i) => i.fieldName === "<maxTotalCharacters>");
    assert.equal(budgetIssues.length, 1, JSON.stringify(result.issues));
  });

  it("halts traversal even when the fail-closed placeholder itself fits after a scalar string overflow, omitting later siblings", function () {
    // Budget covers "note"'s key name plus the full default placeholder, with
    // generous headroom left over -- enough that "after" would easily fit if
    // traversal incorrectly kept going. The original 1000-char string does not
    // fit, but the 27-char placeholder does; per the mandatory global-budget
    // rule this must still halt traversal, not just replace the one value.
    const budget = "note".length + DEFAULT_REDACTED_VALUE_LENGTH + 100;
    const result = redactRuntimeMetadata(
      { note: "x".repeat(1000), after: "unreachable" },
      { maxTotalCharacters: budget }
    );
    assert.equal(result.value.note, "[REDACTED_RUNTIME_METADATA]");
    assert.equal("after" in result.value, false, "an unvisited sibling must be omitted once traversal halts");
    const budgetIssues = result.issues.filter((i) => i.fieldName === "<maxTotalCharacters>");
    assert.equal(budgetIssues.length, 1, JSON.stringify(result.issues));
  });

  it("still records two distinct issues when a sensitive-field replacement is itself the event that exhausts the character budget", function () {
    // key "password" (8 chars) charges exactly to the budget; the 27-char default
    // placeholder cannot fit in the 0 characters left over -- this must still produce
    // both the sensitive-field reason issue and a single, separate budget-exhaustion issue.
    const result = redactRuntimeMetadata({ password: "s" }, { maxTotalCharacters: 8 });
    assert.equal(result.value.password, "");
    const fieldNames = result.issues.map((i) => i.fieldName);
    assert.ok(fieldNames.includes("password"), JSON.stringify(result.issues));
    assert.ok(fieldNames.includes("<maxTotalCharacters>"), JSON.stringify(result.issues));
    assert.equal(fieldNames.filter((f) => f === "<maxTotalCharacters>").length, 1, JSON.stringify(result.issues));
  });

  it("exhausts maxTotalCharacters through many small sensitive-key replacements and halts partway, omitting the remainder", function () {
    const KEY = "password_";
    const input = {};
    for (let i = 0; i < 10; i++) input[`${KEY}${i}`] = "s";
    const keyLength = `${KEY}0`.length;
    const budget = 5 * (keyLength + DEFAULT_REDACTED_VALUE_LENGTH) + keyLength;

    const result = redactRuntimeMetadata(input, { maxTotalCharacters: budget });
    const entries = Object.entries(result.value);
    const fullPlaceholders = entries.filter(([, v]) => v === "[REDACTED_RUNTIME_METADATA]");
    const emptyFallbacks = entries.filter(([, v]) => v === "");

    assert.equal(fullPlaceholders.length, 5);
    assert.equal(emptyFallbacks.length, 1);
    assert.equal(entries.length, 6);
    assert.ok(result.issues.some((i) => i.fieldName === "<maxTotalCharacters>"));
  });
});

describe("PhilCore runtime redaction A2: maxArrayLength", function () {
  it("allows an array at exactly maxArrayLength and replaces one exceeding it", function () {
    const atLimit = redactRuntimeMetadata({ list: new Array(10).fill("x") }, { maxArrayLength: 10 });
    assert.equal(atLimit.value.list.length, 10);
    assert.equal(atLimit.issues.some((i) => i.fieldName === "<maxArrayLength>"), false);

    const overLimit = redactRuntimeMetadata({ list: new Array(11).fill("x") }, { maxArrayLength: 10 });
    assert.equal(overLimit.value.list, "[REDACTED_RUNTIME_METADATA]");
    assert.ok(overLimit.issues.some((i) => i.fieldName === "<maxArrayLength>"));
  });

  it("treats zero as valid: an empty array is retained and a non-empty one is replaced", function () {
    const nonEmpty = redactRuntimeMetadata({ list: ["a"] }, { maxArrayLength: 0 });
    assert.equal(nonEmpty.value.list, "[REDACTED_RUNTIME_METADATA]");

    const empty = redactRuntimeMetadata({ list: [] }, { maxArrayLength: 0 });
    assert.deepEqual(empty.value.list, []);
  });

  it("normalizes maxArrayLength at the hard maximum, above it, and when invalid", function () {
    const atHardMax = redactRuntimeMetadata({ list: [] }, { maxArrayLength: 100_000 });
    assert.equal(atHardMax.issues.some((i) => i.fieldName === "<policy.maxArrayLength>"), false);

    const aboveHardMax = redactRuntimeMetadata({ list: [] }, { maxArrayLength: 100_001 });
    assert.ok(
      aboveHardMax.issues.some((i) =>
        i.fieldName === "<policy.maxArrayLength>" && i.message.includes("exceeded the hard maximum")),
      JSON.stringify(aboveHardMax.issues)
    );

    const negative = redactRuntimeMetadata({ list: [] }, { maxArrayLength: -1 });
    assert.ok(
      negative.issues.some((i) =>
        i.fieldName === "<policy.maxArrayLength>" && i.message.includes("was invalid")),
      JSON.stringify(negative.issues)
    );
  });

  it("rejects a dense oversized array before Reflect.ownKeys or per-element descriptor access", function () {
    const { proxy, counters } = countingProxy(new Array(5000).fill("x"));
    const result = redactRuntimeMetadata({ list: proxy }, { maxArrayLength: 1000 });
    assert.equal(result.value.list, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(counters.ownKeys, 0);
    assert.equal(counters.elementDescriptor, 0);
    assert.equal(counters.lengthDescriptor, 1);
  });

  it("rejects a sparse array with a huge declared length before Reflect.ownKeys or allocation, regardless of real element count", function () {
    const sparse = [];
    sparse[50_000_000] = "only-real-element";
    const { proxy, counters } = countingProxy(sparse);
    const result = redactRuntimeMetadata({ list: proxy }, { maxArrayLength: 1000 });
    assert.equal(result.value.list, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(counters.ownKeys, 0);
    assert.equal(counters.elementDescriptor, 0);
    assert.equal(counters.lengthDescriptor, 1);
    assert.equal(stringify(result.value).includes("only-real-element"), false);
  });

  it("is a local, per-array limit: traversal continues to a later sibling after an oversized-array replacement", function () {
    const result = redactRuntimeMetadata(
      { oversized: new Array(2000).fill("x"), after: { safe: "kept" } },
      { maxArrayLength: 1000 }
    );
    assert.equal(result.value.oversized, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.after.safe, "kept");
    assert.equal(result.issues.some((i) => i.fieldName === "<maxTraversedNodes>"), false);
  });
});

describe("PhilCore runtime redaction A2: redactedValue runtime validation", function () {
  it("accepts a custom string redactedValue", function () {
    const result = redactRuntimeMetadata({ password: "x" }, { redactedValue: "[GONE]" });
    assert.equal(result.value.password, "[GONE]");
  });

  it("falls back to the default and reports <policy.redactedValue> when redactedValue is not a string", function () {
    for (const invalid of [123, null, {}, [], true]) {
      const result = redactRuntimeMetadata({ password: "x" }, { redactedValue: invalid });
      assert.equal(result.value.password, "[REDACTED_RUNTIME_METADATA]");
      assert.ok(result.issues.some((i) => i.fieldName === "<policy.redactedValue>"));
    }
  });
});

describe("PhilCore runtime redaction A2: halted-flag propagation performs no further work", function () {
  it("performs no further reflection anywhere in the tree once the property budget halts, proven with instrumented Proxies", function () {
    const { proxy: laterSiblingProxy, counters: laterCounters } = countingProxy(wideObject(50));
    const result = redactRuntimeMetadata(
      { first: wideObject(10), second: laterSiblingProxy },
      { maxInspectedProperties: 10 }
    );
    // "first"(1) + 9 of its 10 children (charges 2-10) succeed against a budget of 10;
    // the 10th child (charge 11) fails and halts traversal entirely. "second" is an
    // unvisited sibling at that point, so per the mandatory halt semantics it must be
    // omitted outright, not replaced -- the loop unwinds without visiting it at all.
    assert.equal(laterCounters.ownKeys, 0, "a sibling container reached after the halt must never be entered");
    assert.equal("second" in result.value, false, "an unvisited sibling must be omitted, not replaced");
    assert.ok(result.issues.some((i) => i.fieldName === "<maxInspectedProperties>"));
  });

  it("unwinds immediately and retains only the already-sanitized safe prefix", function () {
    const result = redactRuntimeMetadata(wideObject(20), { maxInspectedProperties: 5 });
    assert.equal(Object.keys(result.value).length, 5);
    assert.deepEqual(Object.keys(result.value), ["k0", "k1", "k2", "k3", "k4"]);
  });
});

describe("PhilCore runtime redaction A2: A1 structural guarantees preserved", function () {
  it("preserves null-prototype object handling under the new budgets", function () {
    const input = Object.create(null);
    input.a = "kept";
    const result = redactRuntimeMetadata(input, { maxTraversedNodes: 100, maxInspectedProperties: 100 });
    assert.equal(Object.getPrototypeOf(result.value), null);
    assert.equal(result.value.a, "kept");
  });

  it("does not mutate or freeze the original input under the new budgets", function () {
    const input = { a: { b: "x" } };
    redactRuntimeMetadata(input, { maxTraversedNodes: 1, maxInspectedProperties: 1 });
    assert.equal(Object.isFrozen(input), false);
    assert.equal(Object.isFrozen(input.a), false);
  });

  it("still redacts sensitive fields correctly with every A2 budget at its default", function () {
    const result = redactRuntimeMetadata({ safe: "kept", password: "x", nested: { seed: "y" } });
    assert.equal(result.value.safe, "kept");
    assert.equal(result.value.password, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.value.nested.seed, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(result.issues.some((i) => i.fieldName.startsWith("<max")), false);
  });

  it("preserves maxDepth and maxIssues normalization and behavior unchanged", function () {
    const depthResult = redactRuntimeMetadata({
      a: { b: { c: { d: { e: { f: "too-deep" } } } } }
    });
    assert.equal(depthResult.value.a.b.c.d.e, "[REDACTED_RUNTIME_METADATA]");

    const issuesResult = redactRuntimeMetadata(
      { privateKey: "a", password: "b", seedPhrase: "c" },
      { maxIssues: 2 }
    );
    assert.equal(issuesResult.issues.length, 2);
    assert.equal(issuesResult.issues[1].fieldName, "<maxIssues>");
  });

  it("keeps default A2 budgets generous enough that ordinary consumer-shaped metadata is never touched", function () {
    const auditDraft = sanitizeAuditEventDraftInput({
      category: "runtime",
      outcome: "validation_succeeded",
      summary: "Runtime validation completed.",
      redactedDetails: {
        safe: "kept",
        recoverySecret: "recovery-secret-value",
        nested: { requestId: "abc-123", applicationId: "ethereum-net" }
      }
    });
    assert.equal(auditDraft.redactedDetails.safe, "kept");
    assert.equal(auditDraft.redactedDetails.recoverySecret, "[REDACTED_RUNTIME_METADATA]");
    assert.equal(auditDraft.redactedDetails.nested.requestId, "abc-123");
  });
});

// ---------------------------------------------------------------------------
// Residual limitation (documented, not eliminated): A2 bounds processing
// *after* Reflect.ownKeys/getOwnPropertyDescriptor return, but the initial
// call into a hostile trap is attacker-controlled and cannot be interrupted
// by any synchronous budget check. This test documents that the trap is
// still invoked at least once per container (unavoidable) while proving
// A2 bounds everything that happens with its result.
// ---------------------------------------------------------------------------
describe("PhilCore runtime redaction A2: documented residual limitation", function () {
  it("cannot prevent the first ownKeys call on a container from running attacker-controlled code, but bounds all work after it returns", function () {
    let trapInvocations = 0;
    const proxy = new Proxy(
      {},
      {
        ownKeys(t) {
          trapInvocations += 1;
          // A hostile trap could do arbitrary synchronous work here (including
          // blocking indefinitely); A2 has no way to interrupt this call itself.
          return Reflect.ownKeys(t);
        }
      }
    );
    redactRuntimeMetadata({ nested: proxy }, { maxTraversedNodes: 100 });
    assert.equal(trapInvocations, 1, "the trap is unavoidably invoked once to discover keys at all");
  });
});
