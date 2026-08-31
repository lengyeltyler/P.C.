"use strict";

const { CHANNELS, ROUTINE_AUTHORIZATION_CHANNELS, validateBridgePayload } = require("../shared/bridge-contract.cjs");

function safeFailure(error) {
  const reason = error && typeof error.code === "string" && /^[A-Z0-9_]+$/u.test(error.code)
    ? error.code.toLowerCase()
    : "routine_authorization_failed";
  return Object.freeze({ status: "failed", reason });
}

function createUnavailableRoutineAuthorizationProductHost(reason = "routine_authorization_product_runtime_unavailable") {
  if (typeof reason !== "string" || !/^routine_authorization_[a-z0-9_]+$/u.test(reason)) {
    throw new TypeError("routine unavailable reason is invalid");
  }
  const blocked = async () => ({ status: "blocked", reason });
  return Object.freeze({
    acceptanceBaseline: blocked,
    beginRoutineAuthorization: blocked,
    getRoutineAuthorizationStatus: blocked,
    cancelRoutineAuthorization: blocked,
    deleteDisposableProfile: blocked
  });
}

function createRetryingRoutineAuthorizationProductHost(options) {
  if (!options || Object.keys(options).sort().join(",") !== "getActiveHost,getUnavailableReason,initialize") {
    throw new TypeError("retrying routine product options are invalid");
  }
  if (typeof options.getActiveHost !== "function"
    || typeof options.getUnavailableReason !== "function"
    || typeof options.initialize !== "function") {
    throw new TypeError("retrying routine product dependencies are invalid");
  }

  let initialization = null;

  function unavailable() {
    const reason = options.getUnavailableReason();
    const safeReason = typeof reason === "string" && /^routine_authorization_[a-z0-9_]+$/u.test(reason)
      ? reason
      : "routine_authorization_product_runtime_unavailable";
    const code = safeReason.toUpperCase();
    throw Object.assign(new Error(code), { code });
  }

  function activeHost() {
    const host = options.getActiveHost();
    if (!host || typeof host !== "object") return null;
    return host;
  }

  async function requireActiveHost({ retry }) {
    let host = activeHost();
    if (!host && retry) {
      const attempt = initialization || Promise.resolve().then(options.initialize);
      initialization = attempt;
      try {
        await attempt;
      } finally {
        if (initialization === attempt) initialization = null;
      }
      host = activeHost();
    }
    if (!host) unavailable();
    return host;
  }

  return Object.freeze({
    async acceptanceBaseline() { return (await requireActiveHost({retry:false})).acceptanceBaseline(); },
    async beginRoutineAuthorization(intent) {
      return (await requireActiveHost({ retry: true })).beginRoutineAuthorization(intent);
    },
    async getRoutineAuthorizationStatus(requestId) {
      return (await requireActiveHost({ retry: false })).getRoutineAuthorizationStatus(requestId);
    },
    async cancelRoutineAuthorization(requestId) {
      return (await requireActiveHost({ retry: false })).cancelRoutineAuthorization(requestId);
    },
    async deleteDisposableProfile() {
      return (await requireActiveHost({ retry: false })).deleteDisposableProfile();
    }
  });
}

function createRoutineAuthorizationIpc(productHost, options = {}) {
  if (!productHost || typeof productHost !== "object") throw new TypeError("routine product host is required");
  if (Object.keys(options).some((key) => key !== "createQrDataUrl")
    || (options.createQrDataUrl !== undefined && typeof options.createQrDataUrl !== "function")) {
    throw new TypeError("routine IPC options are invalid");
  }
  return Object.freeze({
    channels: ROUTINE_AUTHORIZATION_CHANNELS,
    async invoke(channel, payload) {
      if (!ROUTINE_AUTHORIZATION_CHANNELS.includes(channel)) {
        return Object.freeze({ status: "failed", reason: "routine_authorization_channel_not_supported" });
      }
      const validated = validateBridgePayload(channel, payload);
      if (!validated.ok) return Object.freeze({ status: "failed", reason: validated.reason });
      try {
        switch (channel) {
          case CHANNELS.ROUTINE_AUTHORIZATION_BEGIN:
          {
            const result = await productHost.beginRoutineAuthorization(validated.value.typedApplicationIntent);
            if (typeof result?.qrPayload !== "string" || !options.createQrDataUrl) return result;
            return Object.freeze({ ...result, qrDataUrl: options.createQrDataUrl(result.qrPayload) });
          }
          case CHANNELS.ROUTINE_AUTHORIZATION_BASELINE:
            return await productHost.acceptanceBaseline();
          case CHANNELS.ROUTINE_AUTHORIZATION_STATUS:
            return await productHost.getRoutineAuthorizationStatus(validated.value.requestId);
          case CHANNELS.ROUTINE_AUTHORIZATION_CANCEL:
            return Object.freeze({
              requestId: validated.value.requestId,
              result: await productHost.cancelRoutineAuthorization(validated.value.requestId)
            });
          case CHANNELS.ROUTINE_AUTHORIZATION_DELETE_DISPOSABLE_PROFILE:
            return await productHost.deleteDisposableProfile();
          default:
            return Object.freeze({ status: "failed", reason: "routine_authorization_channel_not_supported" });
        }
      } catch (error) {
        return safeFailure(error);
      }
    }
  });
}

module.exports = {
  createRoutineAuthorizationIpc,
  createRetryingRoutineAuthorizationProductHost,
  createUnavailableRoutineAuthorizationProductHost
};
