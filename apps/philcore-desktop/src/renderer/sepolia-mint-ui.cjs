(function exposeSepoliaMintUi(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PhilCoreSepoliaMintUi = api;
})(typeof globalThis === "object" ? globalThis : this, function createSepoliaMintUiApi() {
  "use strict";

  const TERMINAL_STATES = Object.freeze(["completed", "cancelled", "expired", "failed"]);

  function emptyState(notice = "", state = "not_started") {
    return Object.freeze({
      requestId: null,
      qrDataUrl: null,
      comparisonFingerprint: null,
      expiresAt: null,
      state,
      presentation: null,
      completion: null,
      notice
    });
  }

  function preparingState() {
    return emptyState(
      "Generating and independently verifying the bounded Noir proof. Nothing is being sent publicly.",
      "preparing"
    );
  }

  function beginState(result) {
    return Object.freeze({
      requestId: result.requestId,
      qrDataUrl: result.qrDataUrl,
      comparisonFingerprint: null,
      expiresAt: result.expiresAt,
      state: result.status || "waiting",
      presentation: result.presentation,
      completion: null,
      notice: "Scan with the enrolled PhilCore iPhone companion, compare details, then approve with Face ID."
    });
  }

  function ownsRefresh(currentRequestId, expectedRequestId, currentGeneration, expectedGeneration) {
    return Boolean(
      expectedRequestId
      && currentRequestId === expectedRequestId
      && (expectedGeneration == null || currentGeneration === expectedGeneration)
    );
  }

  function isTerminalState(value) { return TERMINAL_STATES.includes(value); }

  function terminalNotice(state) {
    if (state === "cancelled") return "The composed mint request was cancelled. Nothing was sent publicly.";
    if (state === "expired") return "The composed mint request expired. Create a fresh request before scanning. Nothing was sent publicly.";
    return "The composed mint request failed safely. Create a fresh request only after reviewing the failure. Nothing was sent publicly.";
  }

  function refreshedState(current, result) {
    if (result.state === "completed") {
      return Object.freeze({
        ...current,
        state: "completed",
        qrDataUrl: null,
        comparisonFingerprint: result.comparisonFingerprint || current.comparisonFingerprint,
        completion: result.completion || null,
        notice: "Proof, iPhone approval, policy, epochs, expiry, and replay state composed successfully. The exact UserOperation is signed but unsubmitted."
      });
    }
    if (isTerminalState(result.state)) return emptyState(terminalNotice(result.state), result.state);
    return Object.freeze({
      ...current,
      state: result.state,
      comparisonFingerprint: result.comparisonFingerprint || current.comparisonFingerprint,
      completion: result.completion || null,
      notice: result.state === "reviewing"
        ? "Encrypted iPhone session established. Compare the fingerprint and exact mint details before approval."
        : result.state === "approved"
          ? "iPhone approval is durably recorded; PhilCore is completing local composition."
          : current.notice
    });
  }

  function cancelledState(current, confirmed) {
    if (confirmed) return emptyState(terminalNotice("cancelled"), "cancelled");
    return Object.freeze({
      ...current,
      qrDataUrl: null,
      notice: "Cancellation could not be confirmed; the request remains fail closed."
    });
  }

  function failedBeginState(reason) {
    const safeReason = typeof reason === "string" && /^[a-z0-9_]+$/u.test(reason)
      ? reason
      : "local_runtime_unavailable";
    return emptyState(`The composed mint failed closed: ${safeReason}. Nothing was sent publicly.`, "failed");
  }

  return Object.freeze({
    beginState,
    cancelledState,
    emptyState,
    failedBeginState,
    isTerminalState,
    ownsRefresh,
    preparingState,
    refreshedState
  });
});
