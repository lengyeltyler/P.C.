(function exposeRoutineAuthorizationUi(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PhilCoreRoutineAuthorizationUi = api;
})(typeof globalThis === "object" ? globalThis : this, function createRoutineAuthorizationUiApi() {
  "use strict";

  const TERMINAL_STATES = Object.freeze([9, 20, 21, 22, 23, 24, 25, "completed", "cancelled", "expired", "failed"]);
  const DEFAULT_SLOW_REQUEST_MS = 8_000;
  const GUIDANCE = Object.freeze({
    ready: Object.freeze({ title: "Ready when you are", message: "You can review the completed Beta or start a separate harmless local demonstration." }),
    locked: Object.freeze({ title: "Unlock to continue", message: "Your Phil identity must be unlocked before a local approval request can begin." }),
    waiting_for_phone: Object.freeze({ title: "Waiting for your iPhone", message: "Open Phil on your enrolled iPhone, scan this request, and compare the fingerprint on both devices." }),
    review_on_phone: Object.freeze({ title: "Review on your iPhone", message: "Check who is asking, what will happen, where it will happen, and when the request expires before approving." }),
    local_proof: Object.freeze({ title: "Checking your protected identity", message: "Phil is checking that this request matches your protected identity. This check happens locally." }),
    protected_signing: Object.freeze({ title: "Protected signing", message: "The protected signing key is being used only for the action you approved." }),
    submitting: Object.freeze({ title: "Completing locally", message: "Phil is completing the approved action in the local test environment, not on public Sepolia." }),
    success: Object.freeze({ title: "Completed", message: "The approved local action completed and its receipt was verified." }),
    rejected: Object.freeze({ title: "Not approved", message: "You rejected the request. No approval was granted." }),
    expired: Object.freeze({ title: "Request expired", message: "The request expired and did not proceed. Start a fresh request if you still want to continue." }),
    cancelled: Object.freeze({ title:"Request cancelled", message:"The request was cancelled before submission. No local action was executed." }),
    unknown: Object.freeze({ title:"Outcome unknown", message:"The action may have been submitted. Do not retry; reconcile its status first." }),
    execution_failed: Object.freeze({ title:"Execution failed", message:"The submitted local action did not complete successfully. Check its recorded outcome before continuing." }),
    receipt_invalid: Object.freeze({ title:"Receipt could not be verified", message:"A local submission occurred, but its receipt could not be verified. Do not retry." }),
    failure: Object.freeze({ title: "Request stopped", message: "Phil stopped because a required check could not be completed. Review the reason before trying again." })
  });
  const FAILURE_COPY = Object.freeze({
    user_denied: "You rejected the request. No approval was granted.",
    request_expired: "The request expired and did not proceed. Start a fresh request if you still want to continue.",
    iphone_unavailable: "Phil cannot reach the enrolled iPhone. Keep both devices available on the same private Wi-Fi network, then create a fresh request.",
    device_response_mismatch: "The iPhone response did not match this request. Phil rejected it; compare the devices again with a fresh request.",
    local_proof_failed: "Phil could not confirm that this request matches your protected identity, so the request stopped before protected signing.",
    identity_locked: "Your Phil identity is locked. Unlock it before starting a protected request.",
    provider_unavailable: "A required network provider is unavailable. Phil cannot confirm the public status right now.",
    provider_disagreement: "The network providers disagree. Phil cannot confirm the public status; do not retry until the status is checked.",
    network_timeout: "The network did not answer in time. Phil cannot confirm the public status; check it before trying again.",
    ambiguous_public_status: "The public status is unclear. Do not retry or assume the action failed until the status is reconciled.",
    feature_deferred: "This feature is intentionally unavailable in the Controlled Sepolia Beta."
  });

  function isTerminalState(value) { return TERMINAL_STATES.includes(value); }

  async function beginRequest(options) {
    if (!options || typeof options.invoke !== "function") throw new TypeError("routine begin invoke is required");
    const slowRequestMs = Number.isInteger(options.slowRequestMs) && options.slowRequestMs >= 0
      ? options.slowRequestMs
      : DEFAULT_SLOW_REQUEST_MS;
    const schedule = typeof options.schedule === "function" ? options.schedule : setTimeout;
    const cancel = typeof options.cancel === "function" ? options.cancel : clearTimeout;
    const slowTimer = schedule(() => {
      try { options.onSlow?.(); } catch {}
    }, slowRequestMs);
    try {
      const result = await options.invoke(options.action);
      if (result?.requestId && result?.qrDataUrl) return Object.freeze({ kind: "started", result });
      const reason = typeof result?.reason === "string" && /^[a-z0-9_]+$/u.test(result.reason)
        ? result.reason
        : "routine_authorization_failed";
      return Object.freeze({ kind: "failed", reason });
    } catch {
      return Object.freeze({ kind: "failed", reason: "routine_authorization_bridge_failed" });
    } finally {
      cancel(slowTimer);
    }
  }

  function kindForResult(result) {
    if (result?.status !== "enrollment_waiting") return "authorization";
    return result?.enrollmentMode === "replacement" ? "replacement_enrollment" : "enrollment";
  }

  function beginState(result) {
    const kind = kindForResult(result);
    return Object.freeze({
      requestId: result.requestId,
      qrPayload: null,
      qrDataUrl: result.qrDataUrl,
      comparisonFingerprint: result.comparisonFingerprint || null,
      expiresAt: result.expiresAt,
      state: result.status,
      kind,
      lastAttempt: result.lastAttempt || null,
      preflightCount: result.preflightCount || 0,
      completionAttemptCount: result.completionAttemptCount || 0,
      notice: kind === "authorization"
        ? "Waiting for your enrolled iPhone. Open Phil > Approve, scan this request, and compare the fingerprint on both devices."
        : kind === "replacement_enrollment"
          ? "Open Phil > Approve on your iPhone. Scan this request and compare the fingerprint before replacing the routine key. Do not use Pair."
          : "This Mac needs a routine approval key. Open Phil > Approve on your iPhone, scan this request, and compare the fingerprint. Do not use Pair."
    });
  }

  function ownsRefresh(currentRequestId, expectedRequestId, currentGeneration, expectedGeneration) {
    return Boolean(
      expectedRequestId
      && currentRequestId === expectedRequestId
      && (expectedGeneration == null || currentGeneration === expectedGeneration)
    );
  }

  function enrollmentAttemptNotice(current, result) {
    if (current.kind === "authorization" || !result?.lastAttempt) return null;
    const attempt = result.lastAttempt;
    if (attempt.stage === "preflight_accepted") {
      return "The iPhone reached this Mac and passed the private connection check. Waiting for the signed enrollment response.";
    }
    if (attempt.stage === "completion_received") {
      return "This Mac received the signed enrollment response and is validating it.";
    }
    if (attempt.stage === "completion_rejected") {
      return FAILURE_COPY.device_response_mismatch;
    }
    if (attempt.stage === "completion_internal_failure") {
      return "Phil received the response but could not finish saving the routine key. Do not repeat enrollment until this state is reviewed.";
    }
    return null;
  }

  function refreshedState(current, result) {
    const terminal = isTerminalState(result.state);
    const attemptNotice = enrollmentAttemptNotice(current, result);
    const stage = terminalStage(result);
    const notice = result.state === "completed"
      ? "The disposable iPhone routine key was durably enrolled on this Mac. You may now request the harmless local action."
      : stage ? guidanceForStage(stage).message
      : attemptNotice || (current.kind === "authorization" ? GUIDANCE.waiting_for_phone.message
        : "The routine-key setup remains local and is waiting for fingerprint confirmation on the iPhone.");
    return Object.freeze({
      ...current,
      state: result.state,
      terminalReason: result.terminalReason || null,
      comparisonFingerprint: result.comparisonFingerprint || current.comparisonFingerprint,
      expiresAt: result.expiresAt || current.expiresAt,
      lastAttempt: result.lastAttempt || current.lastAttempt || null,
      preflightCount: result.preflightCount ?? current.preflightCount ?? 0,
      completionAttemptCount: result.completionAttemptCount ?? current.completionAttemptCount ?? 0,
      qrDataUrl: terminal ? null : current.qrDataUrl,
      notice
    });
  }

  function panelCopy(state) {
    if (state.kind === "enrollment") return Object.freeze({
      heading: "Enroll your iPhone routine key",
      description: "Open Phil > Approve on your iPhone and scan this request. Compare the fingerprint before allowing this Mac to use that separate routine approval key. Do not use Pair.",
      qrAlt: "Expiring iPhone routine-key enrollment QR code"
    });
    if (state.kind === "replacement_enrollment") return Object.freeze({
      heading: "Replace your iPhone routine key",
      description: "Open Phil > Approve on your iPhone and scan this request. Compare the fingerprint before replacing only the routine approval key. Phil identity and recovery are unchanged.",
      qrAlt: "Expiring iPhone routine-key replacement QR code"
    });
    return Object.freeze({
      heading: "Approve with your iPhone",
      description: "Open Phil > Approve on your enrolled iPhone and scan this request. Review the action and compare the fingerprint before approving one harmless local action.",
      qrAlt: "Expiring routine authorization QR code"
    });
  }

  function terminalStage(result) {
    if (result.state === 9 || result.state === "completed") return "success";
    if (result.state === 20 && result.terminalReason === "rejected") return "rejected";
    if (result.state === 20 || result.state === "cancelled") return "cancelled";
    if (result.state === 21 || result.state === "expired") return "expired";
    if (result.state === 25) return "unknown";
    if (result.state === 23) return "execution_failed";
    if (result.state === 24) return "receipt_invalid";
    if (result.state === 22 || result.state === "failed") return "failure";
    return null;
  }

  function blocksNewWork(result) { return [6,7,8,24,25].includes(result.state); }

  function guidanceForStage(stage) {
    return GUIDANCE[stage] || GUIDANCE.failure;
  }

  function failureMessage(reason) {
    return FAILURE_COPY[reason] || GUIDANCE.failure.message;
  }

  return Object.freeze({ blocksNewWork, terminalStage, beginRequest, beginState, failureMessage, guidanceForStage, isTerminalState, ownsRefresh, panelCopy, refreshedState });
});
