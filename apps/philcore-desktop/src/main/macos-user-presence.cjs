const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const VALID_POLICIES = Object.freeze([
  "device_owner_authentication",
  "device_owner_authentication_with_biometrics"
]);

const SUCCESS_OUTCOMES = Object.freeze([
  "device_owner_authentication_verified",
  "touch_id_biometric_verified"
]);
const DEFAULT_USER_PRESENCE_TIMEOUT_MS = 65_000;

function nowIso() {
  return new Date().toISOString();
}

function makeId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function sha256(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function frozen(value) {
  return Object.freeze(JSON.parse(JSON.stringify(value)));
}

function sanitizeReason(reason) {
  const text = String(reason || "Approve PhilCore local signing");
  return text.replace(/[\r\n\t]/g, " ").slice(0, 180);
}

function validateRequest(input = {}) {
  if (!input || typeof input !== "object") return { ok: false, reason: "request_must_be_object" };
  if (!VALID_POLICIES.includes(input.policy || "device_owner_authentication")) {
    return { ok: false, reason: "unsupported_policy" };
  }
  if (input.presentationDigest && !/^0x[a-fA-F0-9]{64}$/u.test(String(input.presentationDigest))) {
    return { ok: false, reason: "presentation_digest_invalid" };
  }
  return {
    ok: true,
    value: {
      version: 1,
      operation: "request_user_presence",
      reason: sanitizeReason(input.reason),
      policy: input.policy || "device_owner_authentication"
    }
  };
}

function createUnsupportedMacOsUserPresenceProvider(reason = "unsupported_platform") {
  return Object.freeze({
    kind: "unsupported_macos_user_presence_provider",
    getAvailability: () => frozen({
      status: "unsupported_platform",
      available: false,
      provider: "none",
      userPresenceGuaranteed: false,
      biometricClaimSupported: false,
      reason
    }),
    requestUserPresence: () => frozen({
      status: "unsupported_platform",
      outcome: "unsupported_platform",
      provider: "none",
      userPresenceVerified: false,
      biometricDataReturned: false,
      rawAuthenticationMaterialReturned: false,
      reason
    })
  });
}

function createFixtureMacOsUserPresenceProvider(options = {}) {
  let nextOutcome = null;
  const defaultOutcome = options.defaultOutcome || "device_owner_authentication_verified";
  return Object.freeze({
    kind: "fixture_macos_user_presence_provider",
    setNextOutcome(outcome) {
      nextOutcome = outcome;
    },
    getAvailability: () => frozen({
      status: options.available === false ? "device_authentication_unavailable" : "available",
      available: options.available !== false,
      provider: "fixture_macos_user_presence",
      userPresenceGuaranteed: options.available !== false,
      biometricClaimSupported: false,
      productionCandidate: false,
      reason: options.available === false ? "fixture_unavailable" : "fixture_available"
    }),
    requestUserPresence(input = {}) {
      const validated = validateRequest(input);
      if (!validated.ok) {
        return frozen({
          status: "helper_error",
          outcome: "malformed",
          provider: "fixture_macos_user_presence",
          userPresenceVerified: false,
          reason: validated.reason
        });
      }
      const outcome = nextOutcome || defaultOutcome;
      nextOutcome = null;
      const success = SUCCESS_OUTCOMES.includes(outcome) || outcome === "developer_fixture_verified";
      return frozen({
        status: success ? "user_presence_verified" : outcome,
        outcome: success ? "user_presence_verified" : outcome,
        evidenceClass: outcome,
        provider: "fixture_macos_user_presence",
        policy: validated.value.policy,
        userPresenceVerified: success,
        biometricDataReturned: false,
        rawAuthenticationMaterialReturned: false,
        fixture: true,
        issuedAt: nowIso()
      });
    }
  });
}

function createMacOsLocalAuthenticationProvider(options = {}) {
  const helperPath = options.helperPath || process.env.PHILCORE_MACOS_USER_PRESENCE_HELPER;
  const expectedSha256 = options.expectedSha256 || process.env.PHILCORE_MACOS_USER_PRESENCE_HELPER_SHA256 || "";
  const timeoutMs = Number.isInteger(options.timeoutMs) ? options.timeoutMs : DEFAULT_USER_PRESENCE_TIMEOUT_MS;
  const platform = options.platform || process.platform;

  function helperStatus() {
    if (platform !== "darwin") {
      return { ok: false, reason: "macos_only_boundary" };
    }
    if (!helperPath) return { ok: false, reason: "helper_not_configured" };
    if (!path.isAbsolute(helperPath)) return { ok: false, reason: "helper_path_must_be_absolute" };
    if (!fs.existsSync(helperPath)) return { ok: false, reason: "helper_missing" };
    const stat = fs.statSync(helperPath);
    if (!stat.isFile()) return { ok: false, reason: "helper_not_file" };
    if ((stat.mode & 0o111) === 0) return { ok: false, reason: "helper_not_executable" };
    const actualSha256 = sha256(helperPath);
    if (expectedSha256 && actualSha256 !== expectedSha256) {
      return { ok: false, reason: "helper_integrity_mismatch", actualSha256 };
    }
    return { ok: true, actualSha256 };
  }

  return Object.freeze({
    kind: "macos_local_authentication_provider",
    getAvailability() {
      const status = helperStatus();
      return frozen({
        status: status.ok ? "available" : status.reason,
        available: status.ok,
        provider: "macos_local_authentication_helper",
        helperPathConfigured: Boolean(helperPath),
        helperSha256: status.actualSha256 || "",
        expectedSha256: expectedSha256 || "",
        userPresenceGuaranteed: status.ok,
        biometricClaimSupported: true,
        productionCandidate: status.ok,
        reason: status.ok ? "helper_available" : status.reason
      });
    },
    requestUserPresence(input = {}) {
      const status = helperStatus();
      if (!status.ok) {
        return frozen({
          status: status.reason,
          outcome: status.reason,
          provider: "macos_local_authentication_helper",
          userPresenceVerified: false,
          helperSha256: status.actualSha256 || "",
          biometricDataReturned: false,
          rawAuthenticationMaterialReturned: false
        });
      }
      const validated = validateRequest(input);
      if (!validated.ok) {
        return frozen({
          status: "helper_error",
          outcome: "malformed",
          provider: "macos_local_authentication_helper",
          userPresenceVerified: false,
          reason: validated.reason
        });
      }
      const result = spawnSync(helperPath, [], {
        input: `${JSON.stringify(validated.value)}\n`,
        encoding: "utf8",
        shell: false,
        timeout: timeoutMs,
        maxBuffer: 32 * 1024,
        env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }
      });
      if (result.error?.code === "ETIMEDOUT") {
        return frozen({
          status: "helper_timeout",
          outcome: "helper_timeout",
          provider: "macos_local_authentication_helper",
          userPresenceVerified: false,
          helperSha256: status.actualSha256,
          biometricDataReturned: false,
          rawAuthenticationMaterialReturned: false
        });
      }
      const output = String(result.stdout || "").trim();
      if (output.length === 0 || output.length > 16_384) {
        return frozen({
          status: "helper_error",
          outcome: "malformed_output",
          provider: "macos_local_authentication_helper",
          userPresenceVerified: false,
          helperSha256: status.actualSha256,
          biometricDataReturned: false,
          rawAuthenticationMaterialReturned: false
        });
      }
      let parsed;
      try {
        parsed = JSON.parse(output);
      } catch {
        return frozen({
          status: "helper_error",
          outcome: "malformed_output",
          provider: "macos_local_authentication_helper",
          userPresenceVerified: false,
          helperSha256: status.actualSha256,
          biometricDataReturned: false,
          rawAuthenticationMaterialReturned: false
        });
      }
      if (parsed.version !== 1 || parsed.provider !== "macos_local_authentication_helper") {
        return frozen({
          status: "helper_error",
          outcome: "unexpected_output",
          provider: "macos_local_authentication_helper",
          userPresenceVerified: false,
          helperSha256: status.actualSha256,
          biometricDataReturned: false,
          rawAuthenticationMaterialReturned: false
        });
      }
      return frozen({
        status: parsed.status,
        outcome: parsed.outcome,
        evidenceClass: parsed.evidenceClass,
        provider: parsed.provider,
        policy: parsed.policy,
        userPresenceVerified: parsed.status === "user_presence_verified",
        helperSha256: status.actualSha256,
        biometricDataReturned: Boolean(parsed.biometricDataReturned),
        rawAuthenticationMaterialReturned: Boolean(parsed.rawAuthenticationMaterialReturned),
        limitation: parsed.limitation || "",
        issuedAt: nowIso()
      });
    }
  });
}

function createMacOsUserPresenceEvidence(input) {
  const result = input.result || {};
  const issuedAt = nowIso();
  return frozen({
    status: "fresh_authentication_satisfied",
    evidenceId: makeId("fresh_auth"),
    purpose: input.purpose,
    identityId: input.identityId,
    ownerCommitment: input.ownerCommitment,
    sessionId: input.sessionId,
    method: result.evidenceClass || "device_owner_authentication_verified",
    evidenceType: "macos_local_authentication_user_presence_without_secret",
    presentationId: input.presentationId || "",
    presentationDigest: input.presentationDigest || "",
    actionKind: input.actionKind || "",
    provider: result.provider || "macos_local_authentication_helper",
    policy: result.policy || "device_owner_authentication",
    userPresenceGuaranteed: Boolean(result.userPresenceVerified),
    biometricDataReturned: false,
    rawAuthenticationMaterialReturned: false,
    helperSha256: result.helperSha256 || "",
    limitation: result.limitation || "",
    issuedAt,
    expiresAt: new Date(Date.now() + input.ttlMs).toISOString(),
    keychainValueReturned: false,
    wrappingKeyReturned: false
  });
}

module.exports = {
  createFixtureMacOsUserPresenceProvider,
  createMacOsLocalAuthenticationProvider,
  createMacOsUserPresenceEvidence,
  createUnsupportedMacOsUserPresenceProvider,
  validateRequest
};
