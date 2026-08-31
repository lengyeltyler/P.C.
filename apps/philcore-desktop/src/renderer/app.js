const navItems = [
  ["home", "Home"],
  ["recovery", "Recovery later"],
  ["audit", "Activity"],
  ["settings", "Settings"]
];

let currentView = "welcome";
let lastRenderedView = null;
let snapshot = null;
let introStep = 0;
let introReplay = false;
let introReturnView = "welcome";

const view = document.getElementById("view");
const nav = document.getElementById("nav");
const pageTitle = document.getElementById("page-title");
const lockState = document.getElementById("lock-state");
const gateState = document.getElementById("gate-state");
const modeLabel = document.getElementById("mode-label");
const approvalRoot = document.getElementById("approval-root");
const presentationSwitch = document.getElementById("presentation-switch");
const present = window.PhilCorePresentation;
const chainCatalog = window.PhilCoreChainCatalog;
const unlockTransitionPolicy = window.PhilCoreUnlockTransitionPolicy;
const philHelper = window.PhilHelper.mount({ document, window, element: document.getElementById("phil-helper") });
let activeApprovalSurface = null;
let latestResult = null;
let uiNotice = null;
let unlockReturnView = "home";
let currentChainId = "ethereum";
let settingsSection = "general";
let catalogQuery = "";
let activityVisibleCount = 12;
let recoveryUi = {
  state: "NOT_STARTED",
  preflight: null,
  pairingRequest: "",
  pairingResponse: "",
  iphonePairing: null,
  publicFactors: [],
  disposable: null,
  notice: ""
};
let routineAuthorizationUi = {
  requestId: null,
  qrPayload: null,
  qrDataUrl: null,
  comparisonFingerprint: null,
  expiresAt: null,
  state: "not_started",
  kind: "authorization",
  notice: ""
};
let routineAuthorizationPollGeneration = 0;
let routineAuthorizationBeginInFlight = false;
let routineAuthorizationLastFailureReason = null;
let sepoliaMintUi = window.PhilCoreSepoliaMintUi.emptyState();
let sepoliaMintPollGeneration = 0;
let sepoliaMintBeginInFlight = false;
let selectedPhilPreview = window.PhilPreviewProvider.localProvider.defaultPreview();
let worldIdPreviewOpen = false;
let featuredPreviewId = null;
let chainAccountPreviewId = null;
let worldTransitionPending = false;
let worldTransitionTimer = null;
const philPreviewProvider = window.PhilPreviewProvider.localProvider;
const externalCredentialProviders = window.PhilCoreExternalCredentialProviders;
const ecosystemDiscovery = window.PhilCoreEcosystemDiscovery;
const passphrasePolicy = Object.freeze([
  ["min_length", "At least 12 characters"],
  ["lowercase", "One lowercase letter"],
  ["uppercase", "One uppercase letter"],
  ["number", "One number"],
  ["special", "One special character"]
]);
const formState = {
  create: { name: "", passphrase: "", confirm: "", showPassphrase: false, showConfirm: false, errors: [] },
  unlock: { passphrase: "", showPassphrase: false, error: "" },
  platform: { passphrase: "", showPassphrase: false, error: "", processing: false }
};
const PROTECTED_ACTION_TIMEOUTS_MS = Object.freeze({
  preflight: 5_000,
  workflowPreparation: 150_000,
  userPresence: 70_000,
  localSigning: 60_000,
  bridgeRefresh: 10_000
});
const PROTECTED_ACTION_TERMINAL_STATES = new Set(["completed", "rejected", "cancelled", "failed", "timed_out"]);
const PROTECTED_ACTION_TRANSITIONS = Object.freeze({
  idle: ["preparing"],
  preparing: ["awaiting_approval", "failed", "timed_out", "cancelled"],
  awaiting_approval: ["approved", "rejected", "cancelled", "timed_out", "failed"],
  approved: ["generating_proof", "confirming_user_presence", "failed", "cancelled", "timed_out"],
  generating_proof: ["verifying_proof", "awaiting_approval", "completed", "failed", "cancelled", "timed_out"],
  verifying_proof: ["awaiting_approval", "failed", "cancelled", "timed_out"],
  confirming_user_presence: ["signing_locally", "failed", "cancelled", "timed_out"],
  signing_locally: ["completed", "failed", "cancelled", "timed_out"],
  completed: ["idle", "preparing"],
  rejected: ["idle", "preparing"],
  cancelled: ["idle", "preparing"],
  failed: ["idle", "preparing"],
  timed_out: ["idle", "preparing"]
});
let protectedActionLifecycle = Object.freeze({ actionId: null, state: "idle", generation: 0, workflowId: null });
let protectedActionCancellation = null;

function actionTimeout(name) {
  const override = globalThis.__PHILCORE_ACTION_LIFECYCLE_TEST__?.timeouts?.[name];
  return Number.isInteger(override) && override >= 50 ? override : PROTECTED_ACTION_TIMEOUTS_MS[name];
}

function startProtectedActionLifecycle(source) {
  if (!PROTECTED_ACTION_TERMINAL_STATES.has(protectedActionLifecycle.state) && protectedActionLifecycle.state !== "idle") return null;
  protectedActionLifecycle = Object.freeze({
    actionId: `desktop_action_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 10)}`,
    state: "preparing",
    generation: protectedActionLifecycle.generation + 1,
    workflowId: null,
    source,
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  return protectedActionLifecycle;
}

function transitionProtectedAction(actionId, state, details = {}) {
  if (protectedActionLifecycle.actionId !== actionId) return false;
  const allowed = PROTECTED_ACTION_TRANSITIONS[protectedActionLifecycle.state] || [];
  if (state !== protectedActionLifecycle.state && !allowed.includes(state)) return false;
  protectedActionLifecycle = Object.freeze({
    ...protectedActionLifecycle,
    ...details,
    state,
    updatedAt: new Date().toISOString()
  });
  return true;
}

function actionOwnsResult(actionId) {
  return protectedActionLifecycle.actionId === actionId && !PROTECTED_ACTION_TERMINAL_STATES.has(protectedActionLifecycle.state);
}

async function delayForActionTest(state) {
  const delayMs = globalThis.__PHILCORE_ACTION_LIFECYCLE_TEST__?.delays?.[state];
  if (Number.isInteger(delayMs) && delayMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
}

function throwInjectedActionFailure(state) {
  const reason = globalThis.__PHILCORE_ACTION_LIFECYCLE_TEST__?.failures?.[state];
  if (reason) throw new Error(String(reason));
}

function withBridgeTimeout(promise, timeoutMs = PROTECTED_ACTION_TIMEOUTS_MS.bridgeRefresh, reason = "bridge_timeout") {
  let handle;
  const timeout = new Promise((_, reject) => {
    handle = setTimeout(() => reject(new Error(reason)), timeoutMs);
  });
  return Promise.race([Promise.resolve(promise), timeout]).finally(() => clearTimeout(handle));
}

function activeSurfaceExpiry(surface = activeApprovalSurface) {
  return surface?.presentation?.expiresAt || surface?.signing?.presentation?.expiresAt || null;
}

function timeRemainingLabel(expiresAt) {
  if (!expiresAt) return "Not available";
  const ms = Date.parse(expiresAt) - Date.now();
  if (!Number.isFinite(ms) || ms <= 0) return "Expired";
  const seconds = Math.ceil(ms / 1000);
  if (seconds < 60) return `${seconds}s remaining`;
  return `${Math.ceil(seconds / 60)}m remaining`;
}

function approvalExpired(surface = activeApprovalSurface) {
  const expiresAt = activeSurfaceExpiry(surface);
  return Boolean(expiresAt && Date.parse(expiresAt) <= Date.now());
}

function approvalStatusText(surface = activeApprovalSurface) {
  if (approvalExpired(surface)) return "This request expired. Start again to review a fresh request.";
  if (surface?.decisionPending) return "Submitting your decision...";
  return `Ready for review - ${timeRemainingLabel(activeSurfaceExpiry(surface))}`;
}

function updateApprovalExpiryStatus() {
  const surface = activeApprovalSurface;
  if (!surface || surface.kind === "progress") return;
  const isExpired = approvalExpired(surface);
  const isSubmitting = Boolean(surface.decisionPending);
  const status = approvalRoot.querySelector("[data-approval-expiry-status]");
  if (status) {
    status.textContent = approvalStatusText(surface);
    status.className = `approval-status ${isExpired ? "warn" : isSubmitting ? "info" : "ok"}`;
  }
  const approveButton = approvalRoot.querySelector('[data-approval-action="approve"]');
  if (approveButton) approveButton.disabled = isExpired || isSubmitting;
}

function h(strings, ...values) {
  return strings.reduce((out, part, index) => out + part + escapeHtml(values[index] ?? ""), "");
}

function raw(html) {
  return { __html: html };
}

function html(strings, ...values) {
  return strings.reduce((out, part, index) => {
    const value = values[index];
    const trustedMarkup = value
      && typeof value === "object"
      && Object.prototype.hasOwnProperty.call(value, "__html");
    return out + part + (trustedMarkup ? value.__html : escapeHtml(value ?? ""));
  }, "");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function displayValue(value, depth = 0) {
  if (value && typeof value === "object" && Object.prototype.hasOwnProperty.call(value, "__html")) return "[rendered content]";
  if (value === null || value === undefined || value === "") return "not available";
  if (typeof value === "boolean") return present.yesNo(value);
  if (typeof value !== "object") {
    const text = String(value);
    const looksLikeStatus = /^[a-z0-9_-]+$/u.test(text) && /[_-]/u.test(text);
    return looksLikeStatus ? present.label(text) : text;
  }
  if (Array.isArray(value)) {
    if (!value.length) return "none";
    return value.map((item) => displayValue(item, depth + 1)).join(", ");
  }
  if (depth >= 2) return "details available";
  const preferred = value.label || value.status || value.state || value.id || value.reference;
  if (preferred) return present.label(preferred);
  const entries = Object.entries(value).filter(([, item]) => item !== undefined && typeof item !== "function");
  if (!entries.length) return "details available";
  return entries.slice(0, 4).map(([key, item]) => `${present.label(key)}: ${displayValue(item, depth + 1)}`).join("; ");
}

function recoveryPreflightNotice(preflight) {
  if (preflight?.blockers?.includes("PACKAGED_IDENTITY_MISMATCH")) {
    return "This unsigned local Alpha cannot create the production-bound Mac recovery credential. That limitation is expected for this test package; a correctly signed build with the required WebAuthn entitlement is needed. No recovery factor was created.";
  }
  return preflight?.state?.includes("BLOCKED")
    ? "The recovery environment check found a blocking requirement. No recovery factor was created."
    : "Recovery environment check complete.";
}

function setNotice(tone, title, message) {
  uiNotice = { tone, title, message };
}

function clearNotice() {
  uiNotice = null;
}

function validateNewIdentityPassphrase(passphrase) {
  const value = typeof passphrase === "string" ? passphrase : "";
  const checks = {
    min_length: value.length >= 12,
    lowercase: /[a-z]/u.test(value),
    uppercase: /[A-Z]/u.test(value),
    number: /[0-9]/u.test(value),
    special: /[^a-zA-Z0-9]/u.test(value)
  };
  return {
    ok: Object.values(checks).every(Boolean),
    checks
  };
}

function captureSensitiveFormValues() {
  const philName = document.getElementById("welcome-phil-name") || document.getElementById("create-label");
  if (philName) formState.create.name = philName.value;
  const createPassphrase = document.getElementById("create-passphrase");
  const createConfirm = document.getElementById("create-passphrase-confirm");
  const unlockPassphrase = document.getElementById("unlock-passphrase");
  const platformPassphrase = document.getElementById("platform-passphrase");
  if (createPassphrase) formState.create.passphrase = createPassphrase.value;
  if (createConfirm) formState.create.confirm = createConfirm.value;
  if (unlockPassphrase) formState.unlock.passphrase = unlockPassphrase.value;
  if (platformPassphrase) formState.platform.passphrase = platformPassphrase.value;
}

function clearSensitiveForm(scope) {
  if (scope === "create") formState.create = { name: formState.create.name, passphrase: "", confirm: "", showPassphrase: false, showConfirm: false, errors: [] };
  if (scope === "unlock") formState.unlock = { passphrase: "", showPassphrase: false, error: "" };
  if (scope === "platform") formState.platform = { passphrase: "", showPassphrase: false, error: "", processing: false };
}

function passphraseField({ id, label, value, shown, toggleField, autocomplete, describedBy }) {
  return raw(`<label class="field passphrase-field">${escapeHtml(label)}
    <span class="passphrase-control">
      <input id="${escapeHtml(id)}" type="${shown ? "text" : "password"}" autocomplete="${escapeHtml(autocomplete)}" value="${escapeHtml(value)}"${describedBy ? ` aria-describedby="${escapeHtml(describedBy)}"` : ""}>
      <button class="secondary reveal-button" data-action="togglePassphraseVisibility" data-field="${escapeHtml(toggleField)}" type="button">${shown ? "Hide" : "Show"}</button>
    </span>
  </label>`);
}

function passphraseRequirementsMarkup(passphrase) {
  const checks = validateNewIdentityPassphrase(passphrase).checks;
  return raw(`<ul class="requirement-list" id="passphrase-requirements">
    ${passphrasePolicy.map(([id, label]) => `<li data-passphrase-requirement="${escapeHtml(id)}" class="${checks[id] ? "met" : "missing"}"><span aria-hidden="true">${checks[id] ? "✓" : ""}</span>${escapeHtml(label)}</li>`).join("")}
  </ul>`);
}

function passphraseMatchMarkup() {
  const hasConfirmation = formState.create.confirm.length > 0;
  const matches = hasConfirmation && formState.create.passphrase === formState.create.confirm;
  return raw(`<p id="passphrase-match" class="requirement-match ${matches ? "met" : hasConfirmation ? "missing" : "empty"}" aria-live="polite">
    <span aria-hidden="true">${matches ? "✓" : ""}</span>${matches ? "Passphrases match" : hasConfirmation ? "Passphrases do not match yet" : "Enter the passphrase again"}
  </p>`);
}

function updatePassphraseFeedback() {
  const passphrase = document.getElementById("create-passphrase");
  const confirmation = document.getElementById("create-passphrase-confirm");
  if (!passphrase || !confirmation) return;
  formState.create.passphrase = passphrase.value;
  formState.create.confirm = confirmation.value;
  const checks = validateNewIdentityPassphrase(passphrase.value).checks;
  for (const [id, label] of passphrasePolicy) {
    const item = view.querySelector(`[data-passphrase-requirement="${id}"]`);
    if (!item) continue;
    item.className = checks[id] ? "met" : "missing";
    item.innerHTML = `<span aria-hidden="true">${checks[id] ? "✓" : ""}</span>${escapeHtml(label)}`;
  }
  const match = document.getElementById("passphrase-match");
  if (match) {
    const hasConfirmation = confirmation.value.length > 0;
    const matches = hasConfirmation && passphrase.value === confirmation.value;
    match.className = `requirement-match ${matches ? "met" : hasConfirmation ? "missing" : "empty"}`;
    match.innerHTML = `<span aria-hidden="true">${matches ? "✓" : ""}</span>${matches ? "Passphrases match" : hasConfirmation ? "Passphrases do not match yet" : "Enter the passphrase again"}`;
  }
}

function bindCreateFormRealtime() {
  for (const id of ["welcome-phil-name", "create-label"]) {
    view.querySelector(`#${id}`)?.addEventListener("input", (event) => { formState.create.name = event.target.value; });
  }
  for (const id of ["create-passphrase", "create-passphrase-confirm"]) {
    view.querySelector(`#${id}`)?.addEventListener("input", updatePassphraseFeedback);
  }
}

function inlineErrors(errors) {
  if (!errors?.length) return raw("");
  return stateCallout({
    tone: "failed",
    label: "Failed",
    title: "PhilCore could not continue",
    message: errors.join(" "),
    liveRole: "alert"
  });
}

const STATE_PRESENTATION = Object.freeze({
  success: { label: "Success", icon: "✓" },
  warning: { label: "Warning", icon: "!" },
  blocked: { label: "Blocked", icon: "■" },
  rejected: { label: "Rejected", icon: "×" },
  failed: { label: "Failed", icon: "!" },
  unknown: { label: "Status unknown", icon: "?" },
  loading: { label: "In progress", icon: "…" },
  info: { label: "Information", icon: "i" }
});

function stateCallout({ tone = "info", label, title, message, liveRole = "status" }) {
  const presentation = STATE_PRESENTATION[tone] || STATE_PRESENTATION.info;
  return raw(`<section class="state-callout ${escapeHtml(tone)}" role="${escapeHtml(liveRole)}" aria-live="polite">
    <span class="state-callout__icon" aria-hidden="true">${escapeHtml(presentation.icon)}</span>
    <div>
      <p class="state-callout__label">${escapeHtml(label || presentation.label)}</p>
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(message)}</p>
    </div>
  </section>`);
}

function loadingState(title, message) {
  return raw(`<section class="state-callout loading" role="status" aria-live="polite" aria-busy="true">
    <span class="state-callout__spinner" aria-hidden="true"></span>
    <div><p class="state-callout__label">In progress</p><strong>${escapeHtml(title)}</strong><p>${escapeHtml(message)}</p></div>
  </section>`);
}

function localDateTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? String(value || "soon") : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function noticeMarkup() {
  if (!uiNotice) return raw("");
  const tone = uiNotice.tone === "ok" ? "success" : uiNotice.tone === "warn" ? "warning" : "info";
  return stateCallout({ tone, title: uiNotice.title, message: uiNotice.message });
}

async function refresh() {
  const bridge = window.PhilCoreRendererStartup.requireBridge();
  snapshot = await bridge.runtime.getSnapshot();
  modeLabel.textContent = present.mode(snapshot);
  lockState.textContent = present.lock(snapshot);
  lockState.className = `status-pill ${present.statusTone(snapshot.session.lockState)}`;
  gateState.textContent = present.gate(snapshot);
  gateState.className = `status-pill ${snapshot.controlledBeta?.completed ? "ready" : "blocked"}`;
  gateState.hidden = !isTechnicalMode();
  if (!snapshot.settings?.introCompleted && !["intro", "welcome", "create"].includes(currentView)) currentView = "welcome";
  if (!snapshot.identity && !["intro", "welcome", "create", "settings"].includes(currentView)) currentView = "welcome";
  if (isLockedScreen()) currentView = "unlock";
  renderModeSwitch();
  renderNav();
  renderView();
}

function isTechnicalMode() {
  return snapshot?.settings?.presentationMode === "technical";
}

function isLockedScreen() {
  return Boolean(snapshot?.identity && (snapshot.session.lockState !== "unlocked" || snapshot.session.vaultState !== "unlocked"));
}

function developerSurfacesAllowed() {
  return snapshot?.release?.developerSurfacesAllowed === true;
}

function renderModeSwitch() {
  const standalone = ["intro", "welcome", "create", "unlock"].includes(currentView);
  const mode = isTechnicalMode() ? "technical" : "user";
  document.body.dataset.presentationMode = mode;
  document.body.dataset.standalone = standalone ? "true" : "false";
  document.body.dataset.locked = isLockedScreen() ? "true" : "false";
  document.querySelector(".sidebar").hidden = standalone;
  document.querySelector(".topbar").hidden = standalone;
  document.body.dataset.view = currentView;
  if (standalone) {
    presentationSwitch.innerHTML = "";
    return;
  }
  presentationSwitch.innerHTML = ["user", "technical"].map((value) => `
    <button type="button" data-presentation-mode="${value}" aria-pressed="${mode === value}">${value === "user" ? "User" : "Advanced"}</button>
  `).join("");
  presentationSwitch.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", async () => {
      if (button.dataset.presentationMode === mode) return;
      await window.philcore.settings.update({ presentationMode: button.dataset.presentationMode });
      await refresh();
    });
  });
}

function nextApplicationView() {
  if (!snapshot?.identity) return "welcome";
  if (snapshot.session.lockState !== "unlocked") return "unlock";
  return "home";
}

async function approvePresentation(input, options = {}) {
  const created = await withBridgeTimeout(window.philcore.approval.createPresentation(input), actionTimeout("bridgeRefresh"), "approval_creation_timeout");
  if (created.status !== "presentation_created") return created;
  const presentation = created.presentation;
  if (options.autoApprove) {
    return window.philcore.approval.respond(
      presentation.presentationId,
      "approve",
      options.typedConfirmation || ""
    );
  }
  const decision = await showRuntimeApprovalSurface({
    mode: "runtime_approval",
    presentation,
    title: presentation.kind === "local_authorization_execution"
      ? "Review a protected local action"
      : present.label(presentation.actionName),
    lead: "Phil prepared this summary so you can understand the request before anything protected continues.",
    approveLabel: "Approve",
    rejectLabel: "Reject",
    cancelLabel: "Cancel"
  });
  if (decision.decision !== "approve") {
    if (decision.decision === "expired") {
      await withBridgeTimeout(window.philcore.approval.cancel(presentation.presentationId), actionTimeout("bridgeRefresh"), "approval_cancellation_timeout");
      return { status: "expired", reason: "approval_expired" };
    }
    return withBridgeTimeout(window.philcore.approval.respond(presentation.presentationId, decision.decision), actionTimeout("bridgeRefresh"), "approval_response_timeout");
  }
  const current = await withBridgeTimeout(window.philcore.approval.getPresentation(presentation.presentationId), actionTimeout("bridgeRefresh"), "approval_refresh_timeout");
  if (current.status !== "presentation_found" || current.presentation.digest !== presentation.digest) {
    return { status: "failed", reason: "stale_or_changed_presentation", snapshot: current.snapshot };
  }
  return withBridgeTimeout(window.philcore.approval.respond(
    presentation.presentationId,
    "approve",
    options.typedConfirmation || ""
  ), actionTimeout("bridgeRefresh"), "approval_response_timeout");
}

async function runApprovedLocalDemo() {
  return startProtectedLocalAction({ source: "developer" });
}

async function startProtectedLocalAction(options = {}) {
  const lifecycle = startProtectedActionLifecycle(options.source || "normal");
  if (!lifecycle) {
    setNotice("warn", "Protected action already active", "Finish or cancel the current protected action before starting another one.");
    await refresh();
    return { status: "busy", reason: "protected_action_already_active" };
  }
  const actionId = lifecycle.actionId;
  latestResult = {
    status: "preparing",
    source: options.source || "normal",
    summary: "PhilCore is preparing a protected local action.",
    technical: {}
  };
  const preflight = await runProtectedActionOperation(actionId, {
    state: "preparing",
    timeoutMs: actionTimeout("preflight"),
    title: "Checking that Phil is ready",
    message: "Phil is checking the identity and local requirements before asking you to review anything."
  }, () => window.philcore.authorization.preflightLocalWorkflow());
  if (preflight.kind !== "result") return preflight;
  if (preflight.value.status !== "ready") {
    await finishProtectedAction(actionId, "failed", preflight.value.reason, preflight.value, { runtimeAlreadyTerminal: true });
    return preflight.value;
  }

  transitionProtectedAction(actionId, "awaiting_approval");
  const execution = await approvePresentation({ kind: "local_authorization_execution" });
  if (!actionOwnsResult(actionId)) return { status: protectedActionLifecycle.state, reason: protectedActionLifecycle.reason };
  if (execution.status !== "approved") {
    const terminal = execution.status === "deny" ? "rejected" : execution.status === "expired" ? "timed_out" : "cancelled";
    await finishProtectedAction(actionId, terminal, execution.reason || execution.status, execution, { runtimeAlreadyTerminal: true });
    return execution;
  }
  transitionProtectedAction(actionId, "approved", { workflowId: actionId });
  const startOutcome = await runProtectedActionOperation(actionId, {
    state: "generating_proof",
    timeoutMs: options.proofTimeoutMs || actionTimeout("workflowPreparation"),
    title: "Checking your protected identity",
    message: "Phil is checking that this request matches your protected identity. This check happens locally."
  }, () => window.philcore.authorization.startLocalWorkflow({
    approvalArtifactId: execution.approvalArtifact.approvalArtifactId,
    clientActionId: actionId,
    proofTimeoutMs: options.proofTimeoutMs || 120_000
  }));
  if (startOutcome.kind !== "result") return startOutcome;
  const started = startOutcome.value;
  if (!actionOwnsResult(actionId)) return started;
  if (globalThis.__PHILCORE_ACTION_LIFECYCLE_TEST__?.failures?.verifying_proof) {
    await finishProtectedAction(actionId, "failed", "proof_verification_failed", started, { runtimeAlreadyTerminal: false });
    return { status: "failed", reason: "proof_verification_failed" };
  }
  if (started.status !== "signing_approval_required") {
    await finishProtectedAction(actionId, started.status === "timed_out" ? "timed_out" : "failed", started.reason || started.status, started, { runtimeAlreadyTerminal: true });
    return started;
  }
  const workflow = started.workflow;
  transitionProtectedAction(actionId, "awaiting_approval", { workflowId: workflow.workflowId });
  const signing = workflow.pendingSigningPresentation;
  const decision = await showRuntimeApprovalSurface({
    mode: "signing_approval",
    workflow,
    signing,
    title: "Review protected signing",
    lead: "The protected signing key will be used only for the local action you already approved.",
    approveLabel: "Approve signing",
    rejectLabel: "Reject",
    cancelLabel: "Cancel"
  });
  if (!actionOwnsResult(actionId)) return { status: protectedActionLifecycle.state, reason: protectedActionLifecycle.reason };
  if (decision.decision !== "approve") {
    const result = decision.decision === "expired"
      ? await window.philcore.authorization.cancelWorkflow({
          workflowId: workflow.workflowId,
          terminalStatus: "timed_out",
          reason: "signing_approval_expired"
        })
      : await window.philcore.authorization.respondToApproval({
          workflowId: workflow.workflowId,
          decision: decision.decision,
          presentationDigest: signing.presentationDigest
        });
    const terminal = decision.decision === "deny" ? "rejected" : decision.decision === "expired" ? "timed_out" : "cancelled";
    await finishProtectedAction(actionId, terminal, result.reason || decision.decision, result, { runtimeAlreadyTerminal: true });
    return result;
  }
  transitionProtectedAction(actionId, "approved");
  const freshOutcome = await runProtectedActionOperation(actionId, {
    state: "confirming_user_presence",
    timeoutMs: actionTimeout("userPresence"),
    title: "Confirm it is you",
    message: "This Mac is confirming that you are present before Phil uses the protected signing key for the approved action."
  }, async () => {
    return window.philcore.authorization.requestFreshAuth(workflow.workflowId);
  });
  if (freshOutcome.kind !== "result") return freshOutcome;
  const fresh = freshOutcome.value;
  if (!actionOwnsResult(actionId)) return fresh;
  if (fresh.status !== "authenticated") {
    await finishProtectedAction(actionId, fresh.status === "timed_out" ? "timed_out" : fresh.status === "cancelled" ? "cancelled" : "failed", fresh.reason || fresh.status, fresh, { runtimeAlreadyTerminal: true });
    return fresh;
  }
  const completionOutcome = await runProtectedActionOperation(actionId, {
    state: "signing_locally",
    timeoutMs: actionTimeout("localSigning"),
    title: "Completing the approved action",
    message: "Phil is using the protected signing key only for your approved action and completing it in the local test environment."
  }, async () => {
    return window.philcore.authorization.respondToApproval({
      workflowId: workflow.workflowId,
      decision: "approve",
      presentationDigest: signing.presentationDigest,
      freshAuthenticationEvidenceId: fresh.evidence.evidenceId
    });
  });
  if (completionOutcome.kind !== "result") return completionOutcome;
  const completed = completionOutcome.value;
  await finishProtectedAction(actionId, completed.status === "completed" ? "completed" : "failed", completed.reason || completed.status, completed, { runtimeAlreadyTerminal: true });
  return completed;
}

async function runProtectedActionOperation(actionId, config, operation) {
  if (!transitionProtectedAction(actionId, config.state)) return { kind: "stale" };
  renderApprovalProgress(config.title, config.message, {
    actionId,
    state: config.state,
    timeoutMs: config.timeoutMs,
    cancellable: true
  });
  let timeoutHandle;
  let cancelResolve;
  const cancellation = new Promise((resolve) => {
    cancelResolve = resolve;
  });
  protectedActionCancellation = { actionId, resolve: cancelResolve };
  const operationResult = Promise.resolve()
    .then(async () => {
      await delayForActionTest(config.state);
      throwInjectedActionFailure(config.state);
      return operation();
    })
    .then((value) => ({ kind: "result", value }), (error) => ({ kind: "error", error }));
  const timeout = new Promise((resolve) => {
    timeoutHandle = setTimeout(() => resolve({ kind: "timeout" }), config.timeoutMs);
  });
  const outcome = await Promise.race([operationResult, cancellation, timeout]);
  clearTimeout(timeoutHandle);
  if (protectedActionCancellation?.actionId === actionId) protectedActionCancellation = null;

  if (outcome.kind === "timeout") {
    await finishProtectedAction(actionId, "timed_out", `${config.state}_timeout`, {}, { runtimeAlreadyTerminal: false });
  } else if (outcome.kind === "error") {
    await finishProtectedAction(actionId, "failed", `${config.state}_failed`, {}, { runtimeAlreadyTerminal: false });
  }

  if (outcome.kind !== "result") {
    void operationResult.then(async (late) => {
      const workflowId = late.value?.workflow?.workflowId;
      if (workflowId && protectedActionLifecycle.actionId === actionId && PROTECTED_ACTION_TERMINAL_STATES.has(protectedActionLifecycle.state)) {
        await window.philcore.authorization.cancelWorkflow({
          workflowId,
          terminalStatus: protectedActionLifecycle.state === "timed_out" ? "timed_out" : "cancelled",
          reason: "late_result_after_action_invalidated"
        });
      }
    });
  }
  return outcome;
}

async function finishProtectedAction(actionId, terminalState, reason, result = {}, options = {}) {
  if (protectedActionLifecycle.actionId !== actionId) return false;
  const workflowId = result.workflow?.workflowId || protectedActionLifecycle.workflowId;
  transitionProtectedAction(actionId, terminalState, { workflowId, reason });
  if (protectedActionCancellation?.actionId === actionId) {
    protectedActionCancellation.resolve({ kind: "cancelled" });
    protectedActionCancellation = null;
  }
  closeApprovalSurface();
  latestResult = protectedActionResultFromStatus(terminalState, reason, result);
  const tone = terminalState === "completed" ? "ok" : "warn";
  setNotice(tone, latestResult.title, latestResult.summary);
  renderView();
  if (workflowId && !options.runtimeAlreadyTerminal && terminalState !== "completed") {
    await withBridgeTimeout(
      window.philcore.authorization.cancelWorkflow({
        workflowId,
        terminalStatus: terminalState,
        reason: reason || terminalState
      }),
      actionTimeout("userPresence"),
      "workflow_cleanup_timeout"
    ).catch(() => undefined);
  }
  await withBridgeTimeout(refresh(), actionTimeout("bridgeRefresh"), "workflow_refresh_timeout").catch(() => undefined);
  return true;
}

async function cancelCurrentProtectedAction() {
  const actionId = protectedActionLifecycle.actionId;
  if (!actionId || PROTECTED_ACTION_TERMINAL_STATES.has(protectedActionLifecycle.state)) return;
  await finishProtectedAction(actionId, "cancelled", "user_cancelled", {}, { runtimeAlreadyTerminal: false });
}

function protectedActionResultFromStatus(status, reason, result = {}) {
  const workflow = result.workflow;
  const failureStage = workflow?.stages?.findLast?.((item) => item.status === "failed") || workflow?.stages?.at?.(-1);
  const proofQuarantined = workflow?.evidenceLabels?.starkProofGeneration === "unavailable_secret_bearing_proof_quarantined"
    || workflow?.stages?.some?.((item) => item.id === "proof_generating" && item.evidenceClass === "unavailable_secret_bearing_proof_quarantined");
  const base = {
    status,
    reason,
    workflowId: workflow?.workflowId,
    correlation: workflow?.correlation,
    technical: {
      reason,
      workflowStatus: workflow?.status,
      failedStage: failureStage?.id,
      userOperationHash: workflow?.execution?.userOperationHash,
      transactionHash: workflow?.execution?.transactionHash
    }
  };
  if (
    status === "completed"
    && workflow?.workflowKind === "ethereum_sepolia_unsigned_preparation"
  ) {
    return {
      ...base,
      tone: "ok",
      title: "Ethereum test action ready for review",
      summary: "Prepared locally. Nothing has been sent to Ethereum.",
      technical: {
        ...base.technical,
        artifactId: workflow.preparation?.artifactId,
        artifactLocation: workflow.preparation?.artifactLocation,
        userOperationHash: workflow.preparation?.userOperationHash,
        chainId: workflow.preparation?.chainId,
        ethereumVerifiedProof: false,
        starkVerificationLocation: "local",
        signaturePresent: false,
        publicNetworkMutation: false
      }
    };
  }
  if (status === "completed") {
    return {
      ...base,
      tone: "ok",
      title: "Protected action completed",
      summary: "Phil checked the request, confirmed you were present, used the protected signing key only for the approved action, and completed the local test. Nothing was sent publicly and no real funds were used."
    };
  }
  if (reason === "platform_unlock_not_enrolled") {
    return {
      ...base,
      tone: "warn",
      title: "Protected Mac unlock is not set up yet",
      summary: "Your Phil identity must be unlocked and protected Mac confirmation must be set up before this local action can continue. This request stopped before protected signing."
    };
  }
  if (reason === "native_user_presence_unavailable" || reason === "native_user_presence_required") {
    return {
      ...base,
      tone: "warn",
      title: "This Mac could not confirm user presence",
      summary: "Phil could not confirm that you were present, so the request stopped before protected signing. Check protected Mac unlock before trying again."
    };
  }
  if (status === "failed" && proofQuarantined) {
    return {
      ...base,
      tone: "warn",
      title: "Protected identity check stopped",
      summary: "Phil stopped at the privacy gate before protected signing or execution because the available proof could expose protected information."
    };
  }
  if (reason === "provider_unavailable") {
    return { ...base, tone: "warn", title: "Network status unavailable", summary: window.PhilCoreRoutineAuthorizationUi.failureMessage("provider_unavailable") };
  }
  if (reason === "provider_disagreement") {
    return { ...base, tone: "warn", title: "Network providers disagree", summary: window.PhilCoreRoutineAuthorizationUi.failureMessage("provider_disagreement") };
  }
  if (reason === "network_timeout") {
    return { ...base, tone: "warn", title: "Network timed out", summary: window.PhilCoreRoutineAuthorizationUi.failureMessage("network_timeout") };
  }
  if (reason === "ambiguous_public_status") {
    return { ...base, tone: "warn", title: "Public status unclear", summary: window.PhilCoreRoutineAuthorizationUi.failureMessage("ambiguous_public_status") };
  }
  if (["deny", "rejected", "failed"].includes(status) || reason?.includes("denied")) {
    return {
      ...base,
      tone: "warn",
      title: status === "failed" ? "Protected action failed" : "Protected action rejected",
      summary: status === "failed"
        ? `Phil stopped because ${present.label(failureStage?.label || failureStage?.id || reason || "a required check")} could not be completed. Review the reason before trying again.`
        : window.PhilCoreRoutineAuthorizationUi.failureMessage("user_denied")
    };
  }
  if (["cancel", "cancelled"].includes(status)) {
    return {
      ...base,
      tone: "warn",
      title: "Protected action cancelled",
      summary: "The request was cancelled. No approval was granted."
    };
  }
  if (status === "timed_out") {
    return {
      ...base,
      tone: "warn",
      title: "Protected action timed out",
      summary: "The local check took longer than allowed, so Phil stopped the request. Review the current state before trying again."
    };
  }
  if (status === "expired") {
    return {
      ...base,
      tone: "warn",
      title: "Approval expired",
      summary: window.PhilCoreRoutineAuthorizationUi.failureMessage("request_expired")
    };
  }
  return {
    ...base,
    tone: "info",
    title: "Protected action stopped",
    summary: "Phil stopped because a required check could not be completed. Review the details before trying again."
  };
}

function renderApprovalProgress(title, message, options = {}) {
  if (activeApprovalSurface?.timer) clearInterval(activeApprovalSurface.timer);
  activeApprovalSurface = {
    kind: "progress",
    title,
    message,
    actionId: options.actionId,
    state: options.state,
    timeoutMs: options.timeoutMs,
    cancellable: options.cancellable !== false,
    startedAt: Date.now(),
    longWaitMessage: "PhilCore is working locally. Nothing has been submitted publicly."
  };
  activeApprovalSurface.timer = setInterval(updateProgressSurface, 1_000);
  renderApprovalSurface();
}

function updateProgressSurface() {
  if (activeApprovalSurface?.kind !== "progress") return;
  const elapsed = approvalRoot.querySelector("[data-progress-elapsed]");
  if (!elapsed) return;
  const seconds = Math.max(0, Math.floor((Date.now() - activeApprovalSurface.startedAt) / 1_000));
  const remaining = Math.max(0, Math.ceil((activeApprovalSurface.timeoutMs - (Date.now() - activeApprovalSurface.startedAt)) / 1_000));
  elapsed.textContent = seconds >= 10
    ? `Still working locally. ${remaining}s remain before PhilCore stops this step automatically.`
    : `Elapsed: ${seconds}s`;
}

function closeApprovalSurface() {
  if (activeApprovalSurface?.timer) clearInterval(activeApprovalSurface.timer);
  if (activeApprovalSurface?.restoreFocus?.focus) {
    activeApprovalSurface.restoreFocus.focus({ preventScroll: true });
  }
  activeApprovalSurface = null;
  approvalRoot.innerHTML = "";
}

function showRuntimeApprovalSurface(config) {
  return new Promise((resolve) => {
    activeApprovalSurface = {
      ...config,
      restoreFocus: document.activeElement,
      resolve,
      decisionPending: false
    };
    if (activeSurfaceExpiry(activeApprovalSurface)) {
      activeApprovalSurface.timer = setInterval(() => {
        if (!activeApprovalSurface || activeApprovalSurface.kind === "progress") return;
        if (approvalExpired(activeApprovalSurface)) {
          const resolve = activeApprovalSurface.resolve;
          closeApprovalSurface();
          resolve?.({ decision: "expired" });
          return;
        }
        updateApprovalExpiryStatus();
      }, 1000);
    }
    renderApprovalSurface();
  });
}

function approvalSummaryRows(surface) {
  if (surface.mode === "signing_approval") {
    const signing = surface.signing;
    const workflow = surface.workflow;
    const expiresAt = activeSurfaceExpiry(surface) || workflow.updatedAt;
    return [
      ["Who", "Phil — Controlled Sepolia Beta on this Mac"],
      ["What", "Use the protected signing key for the one local action you already approved"],
      ["Where", "Local test environment on this Mac — not public Sepolia"],
      ["Value", "No money or meaningful asset"],
      ["Maximum cost", "None — local test only"],
      ["Expires", `${localDateTime(expiresAt)} (${timeRemainingLabel(expiresAt)})`],
      ["Why Phil allows it", "The request passed the local identity check and is bound to this one approved action"],
      ["If you reject", "No protected signature is created and the local action does not run"]
    ];
  }
  const presentation = surface.presentation;
  const expiresAt = activeSurfaceExpiry(surface);
  return [
    ["Who", "Phil — Controlled Sepolia Beta on this Mac"],
    ["What", presentation.kind === "local_authorization_execution"
      ? "Check that this request matches your protected identity, then ask again before protected signing"
      : `Review ${present.label(presentation.actionName)}`],
    ["Where", "Local test environment on this Mac — not public Sepolia"],
    ["Value", "No money or meaningful asset"],
    ["Maximum cost", "None — local test only"],
    ["Expires", `${localDateTime(presentation.expiresAt)} (${timeRemainingLabel(expiresAt)})`],
    ["Why Phil allows it", "This request is local, bounded, and requires a separate signing review before it can complete"],
    ["If you reject", "No authorization is granted, no protected signing occurs, and the local action does not run"]
  ];
}

function approvalTechnicalRows(surface) {
  if (surface.mode === "signing_approval") {
    return [
      ["Workflow ID", surface.workflow.workflowId],
      ["Presentation digest", surface.signing.presentationDigest],
      ["Protected authority", "Protected local signing key"],
      ["Local account", surface.workflow.execution?.account || "local test smart account"],
      ["Reusable", "No, one-time approval only"],
      ...surface.signing.fields.map((item) => [item.label, item.value])
    ];
  }
  const presentation = surface.presentation;
  return [
    ["Presentation ID", presentation.presentationId],
    ["Intent kind", presentation.kind],
    ["Digest algorithm", presentation.digestAlgorithm],
    ["Digest", presentation.digest],
    ["Session", presentation.sessionId],
    ["Identity", presentation.identityId],
    ["Owner commitment", presentation.ownerCommitmentShort],
    ["Approval authority", "One-time Phil approval"],
    ["Information signed now", presentation.kind === "local_authorization_execution" ? "Nothing; signing requires a separate review" : "Only the displayed bounded request"],
    ["Reusable", "No, one-time approval only"],
    ["Risk", presentation.risk],
    ...presentation.fields.map((item) => [item.label, item.value])
  ];
}

function renderApprovalSurface() {
  const surface = activeApprovalSurface;
  if (!surface) {
    approvalRoot.innerHTML = "";
    return;
  }
  if (surface.kind === "progress") {
    approvalRoot.innerHTML = `
      <div class="approval-backdrop" role="presentation">
        <section class="approval-dialog compact" role="dialog" aria-modal="true" aria-live="polite" aria-label="${escapeHtml(surface.title)}">
          <h3>${escapeHtml(surface.title)}</h3>
          <p>${escapeHtml(surface.message)}</p>
          <p class="muted">${escapeHtml(surface.longWaitMessage || "")}</p>
          <div class="progress-line" aria-hidden="true"></div>
          <p class="approval-status info" data-progress-elapsed>Elapsed: 0s</p>
          ${surface.cancellable ? '<div class="approval-actions"><button class="secondary" type="button" data-progress-action="cancel">Cancel</button></div>' : ""}
        </section>
      </div>`;
    const cancel = approvalRoot.querySelector('[data-progress-action="cancel"]');
    if (cancel) cancel.addEventListener("click", () => void cancelCurrentProtectedAction());
    return;
  }
  const isExpired = approvalExpired(surface);
  const isSubmitting = Boolean(surface.decisionPending);
  const summaryRows = approvalSummaryRows(surface);
  const technicalRows = approvalTechnicalRows(surface);
  approvalRoot.innerHTML = `
    <div class="approval-backdrop" role="presentation">
      <section class="approval-dialog" role="dialog" aria-modal="true" aria-labelledby="approval-title" aria-describedby="approval-description">
        <div class="approval-header">
          <div>
            <p class="eyebrow">Protected local action</p>
            <h3 id="approval-title">${escapeHtml(surface.title)}</h3>
          </div>
          <button class="secondary icon-close" type="button" data-approval-action="cancel" aria-label="Cancel approval">Cancel</button>
        </div>
        <p id="approval-description">${escapeHtml(surface.lead)}</p>
        <div class="approval-status ${isExpired ? "warn" : isSubmitting ? "info" : "ok"}" role="status" aria-live="polite" data-approval-expiry-status>
          ${escapeHtml(approvalStatusText(surface))}
        </div>
        <dl class="approval-grid" aria-label="Authorization summary">
          ${summaryRows.map(([label, value]) => `
            <div class="approval-row">
              <dt>${escapeHtml(label)}</dt>
              <dd>${escapeHtml(value)}</dd>
            </div>
          `).join("")}
        </dl>
        ${detailsMarkup("Details", kv(technicalRows))}
        <div class="approval-actions">
          <button class="secondary" type="button" data-approval-action="cancel" ${isSubmitting ? "disabled" : ""}>${escapeHtml(surface.cancelLabel || "Cancel")}</button>
          <button class="danger" type="button" data-approval-action="deny" ${isSubmitting ? "disabled" : ""}>${escapeHtml(surface.rejectLabel || "Reject")}</button>
          <button class="primary" type="button" data-approval-action="approve" ${isExpired || isSubmitting ? "disabled" : ""}>${escapeHtml(surface.approveLabel || "Approve")}</button>
        </div>
      </section>
    </div>`;
  const dialog = approvalRoot.querySelector(".approval-dialog");
  const buttons = [...approvalRoot.querySelectorAll("[data-approval-action]")];
  buttons.forEach((button) => button.addEventListener("click", () => {
    if (activeApprovalSurface?.decisionPending) return;
    const decision = button.dataset.approvalAction === "deny" ? "deny" : button.dataset.approvalAction;
    if (decision === "approve" && approvalExpired(activeApprovalSurface)) return;
    if (activeApprovalSurface) {
      activeApprovalSurface.decisionPending = true;
      buttons.forEach((item) => {
        item.disabled = true;
      });
    }
    const resolve = activeApprovalSurface?.resolve;
    closeApprovalSurface();
    resolve?.({ decision });
  }));
  dialog.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      if (activeApprovalSurface?.decisionPending) return;
      const resolve = activeApprovalSurface?.resolve;
      closeApprovalSurface();
      resolve?.({ decision: "cancel" });
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = buttons.filter((button) => !button.disabled);
    const first = focusable[0];
    const last = focusable.at(-1);
    if (!first || !last) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
  dialog.tabIndex = -1;
  dialog.focus({ preventScroll: true });
  updateApprovalExpiryStatus();
}

function routineGuidanceStage({ active, terminal, unlocked }) {
  if (!unlocked) return "locked";
  if (!active) return "ready";
  if (!terminal) return "waiting_for_phone";
  return window.PhilCoreRoutineAuthorizationUi.terminalStage(routineAuthorizationUi) || "failure";
}

function routineAuthorizationPanel() {
  const unresolved = window.PhilCoreRoutineAuthorizationUi.blocksNewWork(routineAuthorizationUi);
  const active = Boolean(routineAuthorizationUi.requestId);
  const terminal = window.PhilCoreRoutineAuthorizationUi.isTerminalState(routineAuthorizationUi.state);
  const copy = window.PhilCoreRoutineAuthorizationUi.panelCopy(routineAuthorizationUi);
  const unlocked = snapshot.session.lockState === "unlocked" && snapshot.session.vaultState === "unlocked";
  const guidance = window.PhilCoreRoutineAuthorizationUi.guidanceForStage(routineGuidanceStage({ active, terminal, unlocked }));
  const guidanceStage = routineGuidanceStage({ active, terminal, unlocked });
  const routineNoticeIsRedundant = [
    guidance.message,
    "Waiting for your enrolled iPhone. Open Phil > Approve, scan this request, and compare the fingerprint on both devices."
  ].includes(routineAuthorizationUi.notice);
  return raw(`<section class="user-section routine-authorization-panel" aria-labelledby="routine-authorization-title">
    <div class="section-heading"><div><p class="section-label">Reusable local demonstration</p><h3 id="routine-authorization-title">${escapeHtml(copy.heading)}</h3></div><span class="demo-label">Local only</span></div>
    ${!active || routineAuthorizationUi.kind !== "authorization" ? `<p>${escapeHtml(copy.description)}</p>` : ""}
    ${!active || terminal ? `<aside class="phil-stage-guidance ${escapeHtml(guidanceStage)}" role="status" aria-live="polite"><span class="phil-stage-guidance__label">Phil</span><strong>${escapeHtml(guidance.title)}</strong><p>${escapeHtml(guidance.message)}</p></aside>` : ""}
    ${active && !terminal ? loadingState(
      guidanceStage === "waiting_for_phone" ? "Waiting for phone" : "Checking local authorization",
      guidanceStage === "waiting_for_phone" ? "Keep Phil open on the enrolled iPhone and compare the fingerprint on both devices." : "PhilCore is checking the current local stage."
    ).__html : ""}
    ${routineAuthorizationUi.notice && !routineNoticeIsRedundant ? `<p class="field-help" role="status">${escapeHtml(routineAuthorizationUi.notice)}</p>` : ""}
    ${routineAuthorizationUi.qrDataUrl ? `<div class="pairing-qr"><img src="${escapeHtml(routineAuthorizationUi.qrDataUrl)}" alt="${escapeHtml(copy.qrAlt)}"><div><p class="section-label">Comparison fingerprint</p><p class="fingerprint">${escapeHtml(routineAuthorizationUi.comparisonFingerprint || "Waiting for iPhone")}</p><p class="muted">Expires ${escapeHtml(localDateTime(Number(routineAuthorizationUi.expiresAt) * 1000))}. Confirm the fingerprint on both devices before approving.</p></div></div>` : ""}
    <div class="actions">
      <button class="primary" data-action="routineAuthorizationBegin" type="button" ${!unlocked || unresolved || (active && !terminal) || routineAuthorizationBeginInFlight ? "disabled" : ""} ${routineAuthorizationBeginInFlight ? 'aria-busy="true"' : ""}>${unlocked ? (routineAuthorizationBeginInFlight ? "Preparing local request…" : "Request harmless local action") : "Unlock to request an action"}</button>
      ${!active || terminal ? `<button class="secondary" data-action="routineAuthorizationReplace" type="button" ${!unlocked || unresolved || routineAuthorizationBeginInFlight ? "disabled" : ""}>Set up or replace iPhone routine key</button>` : ""}
      ${active && !terminal ? `<button class="secondary" data-action="routineAuthorizationRefresh" type="button">Refresh status</button><button class="secondary danger" data-action="routineAuthorizationCancel" type="button">Cancel</button>` : ""}
      ${terminal && !unresolved ? `<button class="secondary danger" data-action="routineAuthorizationDelete" type="button">Delete disposable profile</button>` : ""}
    </div>
    ${isTechnicalMode() ? detailsMarkup("Technical request state", kv([
      ["State", routineAuthorizationUi.state],
      ["Request", routineAuthorizationUi.requestId || "none"],
      ["Last response stage", routineAuthorizationUi.lastAttempt?.stage || "none"],
      ["Last response code", routineAuthorizationUi.lastAttempt?.code || "none"]
    ])) : ""}
  </section>`);
}

function sepoliaMintPanel() {
  const active = Boolean(sepoliaMintUi.requestId);
  const terminal = window.PhilCoreSepoliaMintUi.isTerminalState(sepoliaMintUi.state);
  const presentation = sepoliaMintUi.presentation;
  const completed = sepoliaMintUi.state === "completed" && sepoliaMintUi.completion;
  const unlocked = snapshot.session.lockState === "unlocked" && snapshot.session.vaultState === "unlocked";
  return raw(`<section class="beta-capability-card sepolia-mint-panel" aria-labelledby="sepolia-mint-title">
    <div class="section-heading"><div><p class="section-label">Local demonstration / preparation</p><h3 id="sepolia-mint-title">Prepare a separate test authorization</h3></div><span class="demo-label">No public submission</span></div>
    <p>This reusable local demonstration combines a local privacy proof, iPhone approval, and protected signing. It does not recreate or submit the completed P2, P3, or P5 Beta actions.</p>
    ${!unlocked ? `<p class="unavailable-reason">Unlock your Phil identity before preparing a local authorization demonstration.</p>` : ""}
    ${details("Advanced verification boundary", kv([
      ["Local proof system", "Noir UltraKeccakZK"],
      ["Public account model", "ERC-4337 v0.7"],
      ["Restricted execution", "ActionGate"],
      ["On-chain proof verification", "No — proof and iPhone approval are verified locally"],
      ["Public submission", "Disabled"]
    ])).__html}
    ${sepoliaMintUi.notice ? `<p class="field-help" role="status">${escapeHtml(sepoliaMintUi.notice)}</p>` : ""}
    ${presentation ? `<dl class="approval-grid inline-summary" aria-label="Authorization summary">
      <div class="approval-row"><dt>Who</dt><dd>Phil — Controlled Sepolia Beta on this Mac</dd></div>
      <div class="approval-row"><dt>What</dt><dd>Prepare one local test authorization for review; do not submit it publicly</dd></div>
      <div class="approval-row"><dt>Where</dt><dd>${escapeHtml(presentation.network)} preparation on this Mac</dd></div>
      <div class="approval-row"><dt>Value</dt><dd>${escapeHtml(presentation.value)}</dd></div>
      <div class="approval-row"><dt>Maximum cost</dt><dd>${escapeHtml(presentation.maximumFeeWei)} test-network wei</dd></div>
      <div class="approval-row"><dt>Expires</dt><dd>${escapeHtml(localDateTime(Number(presentation.expiresAt) * 1000))}</dd></div>
      <div class="approval-row"><dt>Why Phil allows it</dt><dd>Preparation is local-only and public submission remains disabled</dd></div>
    </dl>${details("Details", kv([
      ["Smart account", presentation.smartAccount],
      ["Recipient", presentation.mintRecipient],
      ["Contract", presentation.contract],
      ["Action", presentation.action],
      ["Consequence", presentation.consequence],
      ["Verification boundary", presentation.verificationBoundary]
    ])).__html}` : ""}
    ${sepoliaMintUi.qrDataUrl && !terminal ? `<div class="pairing-qr"><img src="${escapeHtml(sepoliaMintUi.qrDataUrl)}" alt="Expiring iPhone composed Sepolia mint QR code"><div><p class="section-label">Comparison fingerprint</p><p class="fingerprint">${escapeHtml(sepoliaMintUi.comparisonFingerprint || "Waiting for encrypted iPhone session")}</p><p class="muted">Confirm every detail and the fingerprint on both devices before Face ID approval.</p></div></div>` : ""}
    ${completed ? `<div class="result success"><strong>Signed locally and ready for final testnet confirmation</strong><p>No deployment, funding transfer, bundler submission, or mint has occurred.</p>${details("Signed operation", kv([["Smart account", completed.smartAccount], ["ActionGate", completed.actionGate], ["UserOperation hash", completed.userOperationHash], ["Envelope digest", completed.authorizationEnvelopeDigest], ["Root nullifier", completed.rootProofNullifier], ["Device approval nonce", completed.deviceApprovalNonce], ["Account nonce", completed.accountNonce], ["Submitted", completed.submitted]])).__html}</div>` : ""}
    <div class="actions">
      <button class="primary" data-action="sepoliaMintBegin" type="button" ${!unlocked || (active && !terminal) || sepoliaMintBeginInFlight ? "disabled" : ""}>${unlocked ? (sepoliaMintBeginInFlight ? "Generating and verifying local privacy proof…" : "Prepare local test authorization") : "Unlock to prepare"}</button>
      ${active && !terminal ? `<button class="secondary" data-action="sepoliaMintRefresh" type="button">Refresh status</button><button class="secondary danger" data-action="sepoliaMintCancel" type="button">Cancel</button>` : ""}
    </div>
  </section>`);
}

function stopSepoliaMintPolling() { sepoliaMintPollGeneration += 1; }

async function beginSepoliaMint() {
  if (sepoliaMintBeginInFlight) return;
  sepoliaMintBeginInFlight = true;
  stopSepoliaMintPolling();
  const generation = sepoliaMintPollGeneration;
  sepoliaMintUi = window.PhilCoreSepoliaMintUi.preparingState();
  renderView();
  const result = await window.philcore.sepoliaMint.begin();
  sepoliaMintBeginInFlight = false;
  if (result?.requestId) {
    sepoliaMintUi = window.PhilCoreSepoliaMintUi.beginState(result);
    const requestId = result.requestId;
    const poll = async () => {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
      if (generation !== sepoliaMintPollGeneration || requestId !== sepoliaMintUi.requestId) return;
      const terminal = await refreshSepoliaMint(requestId, generation);
      if (!terminal && generation === sepoliaMintPollGeneration) void poll();
    };
    void poll();
  } else {
    sepoliaMintUi = window.PhilCoreSepoliaMintUi.failedBeginState(result?.reason);
  }
  renderView();
}

async function refreshSepoliaMint(requestId = sepoliaMintUi.requestId, expectedGeneration = null) {
  if (!requestId) return true;
  const result = await window.philcore.sepoliaMint.status(requestId);
  if (!window.PhilCoreSepoliaMintUi.ownsRefresh(
    sepoliaMintUi.requestId,
    requestId,
    sepoliaMintPollGeneration,
    expectedGeneration
  )) return true;
  if (!result?.requestId || result.requestId !== requestId) {
    sepoliaMintUi = { ...sepoliaMintUi, notice: "Status refresh failed closed. Nothing was sent publicly." };
    renderView();
    return false;
  }
  const terminal = window.PhilCoreSepoliaMintUi.isTerminalState(result.state);
  sepoliaMintUi = window.PhilCoreSepoliaMintUi.refreshedState(sepoliaMintUi, result);
  renderView();
  return terminal;
}

function stopRoutineAuthorizationPolling() { routineAuthorizationPollGeneration += 1; }

function setRoutineAuthorizationNotice(notice) {
  routineAuthorizationUi = { ...routineAuthorizationUi, notice };
}

function routineAuthorizationFailureNotice(reason, enrollment) {
  if (reason === "routine_authorization_product_runtime_unavailable"
    || reason === "routine_authorization_private_network_unavailable"
    || reason === "routine_authorization_environment_failed") {
    return window.PhilCoreRoutineAuthorizationUi.failureMessage("iphone_unavailable");
  }
  if (reason === "routine_authorization_bridge_failed") {
    return "Phil could not reach the local approval service on this Mac. Restart Phil before trying again.";
  }
  return enrollment
    ? "The iPhone-key enrollment request could not be created. No key or identity state changed."
    : "The harmless local request could not be created. Nothing was sent publicly.";
}

async function beginRoutineAuthorization(action, enrollment = false) {
  if (routineAuthorizationBeginInFlight) return;
  routineAuthorizationBeginInFlight = true;
  setRoutineAuthorizationNotice(enrollment
    ? "Preparing an expiring iPhone-key enrollment request…"
    : "Preparing a new expiring local request…");
  renderView();
  const outcome = await window.PhilCoreRoutineAuthorizationUi.beginRequest({
    action,
    invoke: (requestedAction) => window.philcore.routineAuthorization.begin(requestedAction),
    onSlow: () => {
      setRoutineAuthorizationNotice("PhilCore is still preparing the protected local request. Nothing has been sent publicly.");
      renderView();
    }
  });
  routineAuthorizationBeginInFlight = false;
  if (outcome.kind === "started") {
    routineAuthorizationLastFailureReason = null;
    routineAuthorizationUi = window.PhilCoreRoutineAuthorizationUi.beginState(outcome.result);
    startRoutineAuthorizationPolling();
  } else {
    routineAuthorizationLastFailureReason = outcome.reason;
    setRoutineAuthorizationNotice(routineAuthorizationFailureNotice(outcome.reason, enrollment));
  }
  renderView();
}

async function refreshRoutineAuthorizationStatus(
  expectedRequestId = routineAuthorizationUi.requestId,
  expectedGeneration = null
) {
  if (!window.PhilCoreRoutineAuthorizationUi.ownsRefresh(
    routineAuthorizationUi.requestId,
    expectedRequestId,
    routineAuthorizationPollGeneration,
    expectedGeneration
  )) return true;
  const result = await window.philcore.routineAuthorization.status(expectedRequestId);
  if (!window.PhilCoreRoutineAuthorizationUi.ownsRefresh(
    routineAuthorizationUi.requestId,
    expectedRequestId,
    routineAuthorizationPollGeneration,
    expectedGeneration
  )) return true;
  if (!result?.requestId || result.requestId !== expectedRequestId) {
    setRoutineAuthorizationNotice("Status could not be refreshed.");
    renderView();
    return false;
  }
  routineAuthorizationUi = window.PhilCoreRoutineAuthorizationUi.refreshedState(routineAuthorizationUi, result);
  renderView();
  return window.PhilCoreRoutineAuthorizationUi.isTerminalState(routineAuthorizationUi.state);
}

function startRoutineAuthorizationPolling() {
  const generation = ++routineAuthorizationPollGeneration;
  const requestId = routineAuthorizationUi.requestId;
  const poll = async () => {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    if (generation !== routineAuthorizationPollGeneration || requestId !== routineAuthorizationUi.requestId) return;
    let terminal = false;
    try { terminal = await refreshRoutineAuthorizationStatus(requestId, generation); }
    catch {
      if (window.PhilCoreRoutineAuthorizationUi.ownsRefresh(
        routineAuthorizationUi.requestId,
        requestId,
        routineAuthorizationPollGeneration,
        generation
      )) {
        setRoutineAuthorizationNotice("Status could not be refreshed. The request remains fail closed.");
        renderView();
      }
    }
    if (!terminal && generation === routineAuthorizationPollGeneration) void poll();
  };
  void poll();
}

async function runApprovedRecoveryScenario(scenario) {
  const kindByScenario = {
    owner_rotation: "execution_owner_rotation",
    request: "recovery_request",
    cancel: "recovery_cancel",
    complete: "recovery_complete",
    authority_rotation_request: "recovery_authority_rotation",
    authority_rotation_cancel: "recovery_authority_rotation",
    authority_rotation_complete: "recovery_authority_rotation"
  };
  const kind = kindByScenario[scenario];
  const approval = await approvePresentation({ kind, scenario });
  if (approval.status !== "approved") return approval;
  let fresh = null;
  if (["execution_owner_rotation", "recovery_request", "recovery_complete", "recovery_authority_rotation"].includes(kind)) {
    fresh = await window.philcore.platformAuth.requireFreshAuthentication(`recovery_${scenario}`, approval.presentation);
    if (fresh.status !== "authenticated") return fresh;
  }
  return window.philcore.recovery.runLocalDemo(scenario, {
    approvalArtifactId: approval.approvalArtifact.approvalArtifactId,
    freshAuthenticationEvidenceId: fresh?.evidence?.evidenceId
  });
}

function renderNav() {
  const utilityViews = new Set(["intro", "welcome", "create", "unlock", "chain"]);
  const visible = ["intro", "welcome", "create", "unlock"].includes(currentView) || isLockedScreen() ? [] : [
    ...(!snapshot?.identity ? [["welcome", "Welcome"]] : []),
    ...navItems
  ].filter(([id]) => snapshot?.identity || ["welcome", "settings"].includes(id));
  if (!visible.some(([id]) => id === currentView) && !utilityViews.has(currentView)) currentView = snapshot?.identity ? "home" : "welcome";
  nav.innerHTML = visible.map(([id, label]) => `
    <button type="button" data-nav="${id}" aria-current="${currentView === id ? "page" : "false"}">${label}</button>
  `).join("");
  nav.querySelectorAll("button").forEach((button) => {
    button.addEventListener("click", () => {
      currentView = button.dataset.nav;
      clearNotice();
      renderNav();
      renderView();
    });
  });
}

function renderView() {
  if (isLockedScreen()) currentView = "unlock";
  renderModeSwitch();
  const viewChanged = lastRenderedView !== currentView;
  const chainLabel = currentView === "chain" ? chainCatalog.getById(currentChainId)?.name : null;
  const label = chainLabel || [...navItems, ["intro", "Hello"], ["welcome", "Hello"], ["create", "Create Phil"], ["unlock", "Unlock"]].find(([id]) => id === currentView)?.[1] || "PhilCore";
  pageTitle.textContent = label;
  const renderer = views[currentView] || views.welcome;
  view.innerHTML = `${currentView === "unlock" ? "" : noticeMarkup().__html}${renderer()}`;
  syncPhilenatorBackground();
  bindActions();
  bindCatalogSearch();
  bindCreateFormRealtime();
  philHelper.update({ context: currentView, blocked: ["intro", "welcome", "create", "unlock"].includes(currentView) || Boolean(routineAuthorizationUi.requestId || sepoliaMintUi.requestId) });
  if (viewChanged) view.scrollTop = 0;
  lastRenderedView = currentView;
  view.focus({ preventScroll: true });
  if (worldTransitionPending && currentView === "home") {
    worldTransitionPending = false;
    requestAnimationFrame(playWorldTransition);
  }
}

function syncPhilenatorBackground() {
  const background = document.getElementById("philenator-background");
  const preview = snapshot?.identity ? previewForIdentity(snapshot.identity) : selectedPhilPreview;
  if (!background) return;
  if (preview?.backgroundUri) {
    background.src = preview.backgroundUri;
    background.hidden = false;
    document.body.dataset.philenatorBackground = "active";
  } else {
    background.removeAttribute("src");
    background.hidden = true;
    document.body.dataset.philenatorBackground = "pending";
  }
}

function playWorldTransition() {
  if (isLockedScreen() || snapshot?.session?.lockState !== "unlocked" || snapshot?.session?.vaultState !== "unlocked") return;
  const transition = document.getElementById("world-transition");
  if (!transition) return;
  if (worldTransitionTimer) clearTimeout(worldTransitionTimer);
  transition.classList.remove("is-opening");
  transition.setAttribute("aria-hidden", "false");
  void transition.offsetWidth;
  transition.classList.add("is-opening");
  const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
  worldTransitionTimer = setTimeout(() => {
    transition.classList.remove("is-opening");
    transition.setAttribute("aria-hidden", "true");
    worldTransitionTimer = null;
  }, reducedMotion ? 220 : 900);
}

function bytesToBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64UrlToBytes(value) {
  const padded = `${String(value).replaceAll("-", "+").replaceAll("_", "/")}${"=".repeat((4 - String(value).length % 4) % 4)}`;
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function publicCommitment(label) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`PHILCORE_O41_CUSTODY_DOMAIN_V1|${label}`));
  return `0x${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function serializeRegistration(credential) {
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || null,
    response: {
      clientDataJSON: bytesToBase64Url(credential.response.clientDataJSON),
      attestationObject: bytesToBase64Url(credential.response.attestationObject),
      transports: typeof credential.response.getTransports === "function"
        ? credential.response.getTransports()
        : [],
      publicKey: typeof credential.response.getPublicKey === "function" && credential.response.getPublicKey()
        ? bytesToBase64Url(credential.response.getPublicKey())
        : undefined,
      publicKeyAlgorithm: typeof credential.response.getPublicKeyAlgorithm === "function"
        ? credential.response.getPublicKeyAlgorithm()
        : -7
    }
  };
}

async function createRecoveryCredential(options) {
  const userId = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: base64UrlToBytes(options.challenge),
      rp: options.rp,
      user: {
        id: userId,
        name: `recovery-${bytesToBase64Url(userId).slice(0, 12)}`,
        displayName: "PhilCore recovery factor"
      },
      pubKeyCredParams: options.algorithms.map((alg) => ({ type: "public-key", alg })),
      authenticatorSelection: {
        authenticatorAttachment: options.authenticatorAttachment,
        residentKey: options.residentKey,
        requireResidentKey: true,
        userVerification: options.userVerification
      },
      attestation: options.attestation,
      timeout: options.timeoutMs
    }
  });
  if (!credential) throw new Error("recovery_credential_creation_cancelled");
  return serializeRegistration(credential);
}

function classifyWebAuthnFailure(error) {
  if (error?.name === "NotAllowedError") {
    return "The platform ended the WebAuthn request. This can mean cancellation, timeout, or no prompt; PhilCore does not label it a denial without a distinct OS result.";
  }
  if (error?.name === "NotSupportedError") {
    return "This runtime or authenticator does not support the requested device-bound WebAuthn credential.";
  }
  if (error?.name === "SecurityError") {
    return "The WebAuthn RP or secure-origin binding was rejected.";
  }
  if (error?.name === "AbortError") {
    return "The WebAuthn request was cancelled before completion.";
  }
  return "The platform credential request failed without exposing credential material.";
}

function bindActions() {
  view.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      captureSensitiveFormValues();
      const action = button.dataset.action;
      if (action === "sepoliaMintBegin") {
        await beginSepoliaMint();
        return;
      }
      if (action === "sepoliaMintRefresh") {
        await refreshSepoliaMint();
        return;
      }
      if (action === "sepoliaMintCancel") {
        const requestId = sepoliaMintUi.requestId;
        stopSepoliaMintPolling();
        const generation = sepoliaMintPollGeneration;
        const result = await window.philcore.sepoliaMint.cancel(requestId);
        if (!window.PhilCoreSepoliaMintUi.ownsRefresh(
          sepoliaMintUi.requestId,
          requestId,
          sepoliaMintPollGeneration,
          generation
        )) return;
        sepoliaMintUi = window.PhilCoreSepoliaMintUi.cancelledState(
          sepoliaMintUi,
          result?.result === "cancelled"
        );
        renderView();
        return;
      }
      if (action === "routineAuthorizationBegin") {
        await beginRoutineAuthorization("record_harmless_value");
        return;
      }
      if (action === "routineAuthorizationReplace") {
        await beginRoutineAuthorization("replace_routine_device", true);
        return;
      }
      if (action === "routineAuthorizationRefresh") {
        await refreshRoutineAuthorizationStatus();
        return;
      }
      if (action === "routineAuthorizationCancel") {
        stopRoutineAuthorizationPolling();
        const result = await window.philcore.routineAuthorization.cancel(routineAuthorizationUi.requestId);
        routineAuthorizationUi = {
          ...routineAuthorizationUi,
          state: result?.result === "cancelled" ? 20 : routineAuthorizationUi.state,
          qrPayload: null,
          qrDataUrl: null,
          notice: result?.result === "cancelled"
            ? "The pending request was cancelled before submission."
            : "Cancellation was too late or could not be confirmed."
        };
        renderView();
        return;
      }
      if (action === "routineAuthorizationDelete") {
        stopRoutineAuthorizationPolling();
        const result = await window.philcore.routineAuthorization.deleteDisposableProfile(
          "DELETE DISPOSABLE ROUTINE PROFILE"
        );
        if (result?.status === "deleted" && result?.identityOrRecoveryStateTouched === false) {
          routineAuthorizationUi = {
            requestId: null,
            qrPayload: null,
            qrDataUrl: null,
            comparisonFingerprint: null,
            expiresAt: null,
            state: "not_started",
            kind: "authorization",
            notice: "The disposable routine profile and journal were deleted. Your Phil identity and recovery state were not changed."
          };
        } else {
          setRoutineAuthorizationNotice("Disposable profile deletion could not be proven.");
        }
        renderView();
        return;
      }
      if (action === "togglePassphraseVisibility") {
        const field = button.dataset.field;
        if (field === "createPassphrase") formState.create.showPassphrase = !formState.create.showPassphrase;
        if (field === "createConfirm") formState.create.showConfirm = !formState.create.showConfirm;
        if (field === "unlockPassphrase") formState.unlock.showPassphrase = !formState.unlock.showPassphrase;
        if (field === "platformPassphrase") formState.platform.showPassphrase = !formState.platform.showPassphrase;
        renderView();
        return;
      }
      if (action === "randomizePhil") {
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
        try {
          selectedPhilPreview = await philPreviewProvider.randomize(selectedPhilPreview);
          clearNotice();
        } catch {
          setNotice("warn", "Philenator paused", "The local Philenator engine could not finish that combination. Your current Phil is unchanged.");
        }
        renderView();
        return;
      }
      if (action === "beginCreatePhil") {
        const name = window.PhilHelper.normalizeName(formState.create.name);
        if (!name) {
          setNotice("warn", "Choose a name for Phil", "Enter a local profile name of 1–64 characters, without control characters.");
          renderView();
          document.getElementById("welcome-phil-name")?.focus();
          return;
        }
        formState.create.name = name;
        if (!snapshot.settings?.introCompleted) {
          introStep = 0;
          introReplay = false;
          introReturnView = "create";
          currentView = "intro";
        } else {
          clearNotice();
          currentView = "create";
        }
      }
      if (action === "backWelcome") {
        clearSensitiveForm("create");
        clearNotice();
        currentView = "welcome";
      }
      if (action === "createIdentity") {
        const passphrase = formState.create.passphrase;
        const confirmation = formState.create.confirm;
        const label = window.PhilHelper.normalizeName(formState.create.name);
        const createRecoveryAuthority = Boolean(document.getElementById("create-recovery")?.checked);
        const validation = validateNewIdentityPassphrase(passphrase);
        const errors = [];
        if (!label) errors.push("Choose a local Phil name of 1–64 characters, without control characters.");
        if (!validation.ok) errors.push("Choose a passphrase that satisfies every requirement below.");
        if (passphrase !== confirmation) errors.push("Enter the same passphrase in both fields.");
        if (errors.length) {
          formState.create.errors = errors;
          setNotice("warn", "Passphrase needs attention", "Fix the highlighted passphrase requirements, then try again.");
          currentView = "create";
          await refresh();
          return;
        }
        const created = await window.philcore.identity.createLocal({
          label,
          passphrase,
          createRecoveryAuthority,
          philPreview: {
            selectionId: selectedPhilPreview.selectionId,
            sequence: selectedPhilPreview.sequence,
            traits: selectedPhilPreview.traits,
            source: selectedPhilPreview.source,
            artworkSource: selectedPhilPreview.artworkSource,
            generatorRevision: selectedPhilPreview.generatorRevision,
            mintStatus: selectedPhilPreview.mintStatus,
            publicToken: selectedPhilPreview.publicToken
          }
        });
        if (created?.identity) {
          clearSensitiveForm("create");
          setNotice("info", "Identity created", "Your identity is stored locally and locked. Enter the passphrase to unlock it.");
          unlockReturnView = "home";
          currentView = "unlock";
        } else {
          setNotice("warn", "Identity was not created", `PhilCore stopped safely: ${present.label(created?.reason || created?.status || "unknown_reason")}.`);
          currentView = "create";
        }
      }
      if (action === "introNext") {
        introStep = Math.min(introStep + 1, introSteps.length - 1);
      }
      if (action === "introBack") {
        introStep = Math.max(introStep - 1, 0);
      }
      if (action === "introFinish") {
        await window.philcore.settings.update({ introCompleted: true });
        introStep = 0;
        introReplay = false;
        clearNotice();
        currentView = introReturnView === "create"
          ? "create"
          : snapshot?.identity ? nextApplicationView() : "welcome";
        introReturnView = "welcome";
      }
      if (action === "replayIntro") {
        introReplay = true;
        introStep = 0;
        introReturnView = snapshot?.identity ? nextApplicationView() : "welcome";
        clearNotice();
        currentView = "intro";
      }
      if (action === "goUnlock") {
        unlockReturnView = "home";
        formState.unlock.error = "";
        setNotice("info", "Unlock your identity", "Use the passphrase you created for this identity. Protected Mac unlock appears here only after you enable it from Settings while already unlocked.");
        currentView = "unlock";
      }
      if (action === "openIdentity") {
        const identityId = button.dataset.identityId || snapshot.localIdentities[0]?.identityId;
        if (identityId) {
          if (!snapshot.settings?.introCompleted) {
            await window.philcore.settings.update({ introCompleted: true });
          }
          const opened = await window.philcore.identity.openLocal(identityId);
          if (opened?.identity) {
            setNotice("info", "Identity selected", "This identity is still locked. Unlock it before viewing protected state or testing a protected action.");
          } else {
            setNotice("warn", "Identity could not be opened", `PhilCore stopped safely: ${present.label(opened?.reason || opened?.status || "unknown_reason")}.`);
          }
        } else {
          setNotice("warn", "No identity selected", "Create or choose a local identity before unlocking.");
        }
        currentView = "unlock";
      }
      if (action === "exploreDemo") {
        const passphrase = "Local-demo-passphrase!1";
        const created = await window.philcore.identity.createLocal({
          label: "Local Demo Identity",
          passphrase,
          createRecoveryAuthority: true
        });
        if (!unlockTransitionPolicy.identityCreated(created)) {
          setNotice("warn", "Demo identity was not created", `PhilCore stopped safely: ${present.label(created?.reason || created?.status || "unknown_reason")}.`);
          currentView = "welcome";
        } else {
          const authenticated = await window.philcore.session.authenticateLocal(passphrase);
          if (!unlockTransitionPolicy.authenticationSucceeded(authenticated)) {
            setNotice("warn", "Demo unlock failed", "The guided identity was created but could not be authenticated. It remains locked.");
            currentView = "unlock";
          } else {
            const unlocked = await window.philcore.session.unlockVault();
            if (unlockTransitionPolicy.vaultUnlockSucceeded(unlocked)) {
              setNotice("ok", "Demo identity unlocked", "The guided local identity is ready for private-proof-gated local actions.");
              worldTransitionPending = true;
              currentView = "home";
            } else {
              setNotice("warn", "Demo unlock stopped", `PhilCore authenticated the guided identity but could not open protected state: ${present.label(unlocked.reason || unlocked.status)}.`);
              currentView = "unlock";
            }
          }
        }
      }
      if (action === "unlock") {
        const passphrase = formState.unlock.passphrase;
        if (!passphrase) {
          formState.unlock.error = "Enter the passphrase for this identity.";
          setNotice("warn", "Passphrase required", "Enter the passphrase for this local identity to unlock it.");
          currentView = "unlock";
        } else {
          const authenticated = await window.philcore.session.authenticateLocal(passphrase);
          if (!unlockTransitionPolicy.authenticationSucceeded(authenticated)) {
            formState.unlock.error = "That passphrase did not unlock this identity. Check it and try again.";
            setNotice("warn", "Unlock failed", "That passphrase did not unlock this identity. Nothing was changed, and you can try again.");
            currentView = "unlock";
          } else {
            const unlocked = await window.philcore.session.unlockVault();
            if (unlockTransitionPolicy.vaultUnlockSucceeded(unlocked)) {
              clearSensitiveForm("unlock");
              setNotice("ok", "Identity unlocked", "Your protected local identity is ready. You can now test a protected local action.");
              worldTransitionPending = true;
              currentView = unlockReturnView || "home";
            } else {
              formState.unlock.error = "PhilCore verified the passphrase but could not open protected state.";
              setNotice("warn", "Unlock stopped", `PhilCore verified the passphrase but could not open protected state: ${present.label(unlocked.reason || unlocked.status)}.`);
              currentView = "unlock";
            }
          }
        }
      }
      if (action === "platformUnlock") {
        const unlocked = await window.philcore.platformAuth.unlock();
        if (unlockTransitionPolicy.vaultUnlockSucceeded(unlocked)) {
          clearSensitiveForm("unlock");
          setNotice("ok", "Identity unlocked with this Mac", "Your protected local identity is ready. Sensitive actions still require approval.");
          worldTransitionPending = true;
          currentView = "home";
        } else {
          const reason = unlocked.reason || unlocked.status;
          if (["keychain_access_denied", "keychain_item_missing", "wrapping_key_invalid"].includes(reason)) {
            formState.unlock.error = "Protected Mac unlock is unavailable for this identity in the current build. Use the identity passphrase instead.";
            setNotice(
              "warn",
              "Protected Mac key unavailable",
              "This can happen when an identity was protected by an earlier unsigned Alpha build. Use the identity passphrase to unlock it. Nothing was changed, and PhilCore will not weaken or replace the protected key automatically."
            );
          } else {
            setNotice("warn", "Unlock with this Mac stopped", `PhilCore stopped safely: ${present.label(reason)}. Use the passphrase fallback if this continues.`);
          }
          currentView = "unlock";
        }
      }
      if (action === "enrollPlatformAuth") {
        const passphrase = formState.platform.passphrase;
        if (snapshot.session.lockState !== "unlocked") {
          formState.platform.error = "Unlock your identity with the passphrase first, then return to Settings to enable protected Mac unlock.";
          setNotice("warn", "Unlock first", "Protected Mac unlock can be enabled only after this identity is already unlocked.");
          currentView = "settings";
          await refresh();
          return;
        }
        if (!passphrase) {
          formState.platform.error = "Enter this identity's passphrase to enable protected Mac unlock.";
          setNotice("warn", "Passphrase required", "Confirm your identity passphrase before enabling protected Mac unlock.");
          currentView = "settings";
          await refresh();
          return;
        }
        formState.platform.processing = true;
        formState.platform.error = "";
        setNotice("info", "Enabling protected Mac unlock", "PhilCore is verifying the passphrase and asking macOS protection to store a local unlock key.");
        renderView();
        const approval = await approvePresentation({ kind: "platform_unlock_enrollment" });
        if (approval.status === "approved") {
          const enrolled = await window.philcore.platformAuth.enroll(passphrase, approval.approvalArtifact.approvalArtifactId);
          formState.platform.processing = false;
          if (enrolled.status === "enrolled") {
            clearSensitiveForm("platform");
            setNotice("ok", "Protected Mac unlock enabled", "You can now unlock this identity from this Mac without typing the passphrase each time. It still does not approve actions by itself.");
          } else {
            formState.platform.error = platformAuthFailureMessage(enrolled);
            setNotice("warn", "Protected Mac unlock was not enabled", formState.platform.error);
          }
        } else {
          formState.platform.processing = false;
          formState.platform.error = "Approval was not completed, so protected Mac unlock was not enabled.";
          setNotice("warn", "Enrollment cancelled", formState.platform.error);
        }
        currentView = "settings";
      }
      if (action === "disablePlatformAuth") {
        const passphrase = formState.platform.passphrase;
        const approval = await approvePresentation({ kind: "platform_unlock_disablement" });
        if (approval.status === "approved") {
          const fresh = await window.philcore.platformAuth.requireFreshAuthentication("platform_unlock_disablement", approval.presentation);
          if (fresh.status === "authenticated") {
            const disabled = await window.philcore.platformAuth.disable(passphrase, approval.approvalArtifact.approvalArtifactId, fresh.evidence.evidenceId);
            if (disabled.status === "disabled") {
              clearSensitiveForm("platform");
              setNotice("ok", "Protected Mac unlock disabled", "Passphrase unlock remains available.");
            } else {
              formState.platform.error = platformAuthFailureMessage(disabled);
              setNotice("warn", "Protected Mac unlock was not disabled", formState.platform.error);
            }
          }
        }
        currentView = "settings";
      }
      if (action === "freshPlatformAuth") {
        await window.philcore.platformAuth.requireFreshAuthentication("local_signing_presentation");
      }
      if (action === "lock") {
        await window.philcore.session.lock();
        currentView = "unlock";
      }
      if (action === "runDemo") {
        await runApprovedLocalDemo();
      }
      if (action === "startProtectedAction") {
        try {
          await startProtectedLocalAction({ source: button.dataset.surface || "normal" });
        } catch {
          const actionId = protectedActionLifecycle.actionId;
          if (actionId && actionOwnsResult(actionId)) {
            await finishProtectedAction(actionId, "failed", "unexpected_local_action_error", {}, { runtimeAlreadyTerminal: false });
          }
        }
      }
      if (action === "goProtectedMacSettings") {
        closeApprovalSurface();
        if (PROTECTED_ACTION_TERMINAL_STATES.has(protectedActionLifecycle.state)) {
          transitionProtectedAction(protectedActionLifecycle.actionId, "idle");
        }
        settingsSection = "security";
        currentView = "settings";
      }
      if (action === "dismissActionResult") {
        latestResult = null;
        if (PROTECTED_ACTION_TERMINAL_STATES.has(protectedActionLifecycle.state)) {
          transitionProtectedAction(protectedActionLifecycle.actionId, "idle");
        }
      }
      if (action && action.startsWith("recovery:")) {
        await runApprovedRecoveryScenario(action.slice("recovery:".length));
      }
      if (action === "recoveryEnvironmentCheck") {
        const webAuthnApiAvailable = Boolean(
          window.isSecureContext
          && navigator.credentials
          && window.PublicKeyCredential
        );
        const platformAuthenticatorAvailable = webAuthnApiAvailable
          && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
          && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        recoveryUi.preflight = await window.philcore.recovery.enrollment.preflight({
          profile: button.dataset.profile === "ENHANCED" ? "ENHANCED" : "STANDARD",
          webAuthnApiAvailable,
          platformAuthenticatorAvailable,
          packagedEnvironmentReady: true,
          dependencyAdvisoryGateReady: true
        });
        recoveryUi.state = recoveryUi.preflight.state;
        recoveryUi.notice = recoveryPreflightNotice(recoveryUi.preflight);
      }
      if (action === "recoveryDisposableMacCheck") {
        const enrollment = window.philcore.recovery.enrollment;
        try {
          recoveryUi.notice = "On this primary Mac, approve the macOS WebAuthn sheet for a disposable diagnostic. Main verifies create then get; this is not Role 0.";
          renderView();
          const disposable = await window.PhilCoreDisposablePlatformWebAuthn.run({
            rpId: "recovery.philcore.localhost",
            rpName: "PhilCore Recovery Disposable Test",
            begin: () => enrollment.beginDisposableDiagnostic(),
            verifyRegistration: (registration) =>
              enrollment.verifyDisposableRegistration(registration),
            verifyAssertion: (assertion) =>
              enrollment.verifyDisposableAssertion(assertion)
          });
          recoveryUi.disposable = disposable;
          const webAuthnApiAvailable = Boolean(
            window.isSecureContext
            && navigator.credentials
            && window.PublicKeyCredential
          );
          const platformAuthenticatorAvailable = webAuthnApiAvailable
            && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
            && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
          recoveryUi.preflight = await enrollment.preflight({
            profile: recoveryUi.preflight?.selectedProfile === "ENHANCED" ? "ENHANCED" : "STANDARD",
            webAuthnApiAvailable,
            platformAuthenticatorAvailable,
            packagedEnvironmentReady: true,
            dependencyAdvisoryGateReady: true
          });
          recoveryUi.state = recoveryUi.preflight.state;
          recoveryUi.notice = disposable.verified && disposable.disposableCreationAssertion
            ? "Main-verified disposable Mac diagnostic passed (UV=true, BE=false, BS=false). No PhilCore production authority was stored. Renderer policyAccepted alone has no authority."
            : "Disposable Mac diagnostic was not accepted by main-process verification.";
        } catch (error) {
          try {
            await enrollment.cancelDisposableDiagnostic();
          } catch {
            // Cancellation is best-effort; never claim OS credential deletion.
          }
          recoveryUi.notice = `${classifyWebAuthnFailure(error)} The disposable test was not accepted as PhilCore authority.`;
        }
      }
      if (action === "recoveryCreatePrimary") {
        try {
          const options = await window.philcore.recovery.enrollment.beginCredential();
          const registration = await createRecoveryCredential(options);
          const custodyDomainCommitment = await publicCommitment("primary-device-local-platform");
          const result = await window.philcore.recovery.enrollment.storeCredential({
            role: 0,
            registration,
            descriptorMetadata: { authenticatorClass: "PRIMARY_PLATFORM_DEVICE" },
            generation: 1,
            custodyDomainCommitment
          });
          if (result.status === "failed") throw new Error(result.reason);
          recoveryUi.state = "PRIMARY_COMPLETE";
          recoveryUi.publicFactors = await window.philcore.recovery.enrollment.listPublicFactors();
          recoveryUi.notice = "Primary recovery credential verified and stored under an opaque reference.";
        } catch (error) {
          recoveryUi.notice = `${classifyWebAuthnFailure(error)} No PhilCore recovery record was retained.`;
        }
      }
      if (action === "recoveryBeginPairing") {
        const pairingResult = await window.philcore.recovery.enrollment.beginPairing();
        if (pairingResult.status === "failed") {
          recoveryUi.notice = `Pairing could not start: ${pairingResult.reason}`;
        } else {
          recoveryUi.pairingRequest = pairingResult.encodedRequest;
          recoveryUi.state = "SECONDARY_PENDING";
          recoveryUi.notice = "Move this expiring public request to PhilCore Desktop on the independent device.";
        }
      }
      if (action === "recoveryBeginIPhonePairing") {
        const pairingResult = await window.philcore.recovery.enrollment.beginIPhonePairing();
        if (pairingResult.status === "BLOCKED" || pairingResult.status === "failed") {
          recoveryUi.notice = `iPhone pairing could not start: ${pairingResult.reason}`;
        } else {
          recoveryUi.iphonePairing = pairingResult;
          recoveryUi.state = "SECONDARY_PENDING";
          recoveryUi.notice = "Scan the QR code with PhilCore Companion, then compare the fingerprint on both devices.";
        }
      }
      if (action === "recoveryRefreshIPhonePairing") {
        const pairingResult = await window.philcore.recovery.enrollment.iPhonePairingStatus();
        recoveryUi.iphonePairing = {
          ...recoveryUi.iphonePairing,
          ...pairingResult.pairing,
          descriptor: pairingResult.descriptor
        };
        if (pairingResult.pairing?.status === "VERIFIED") {
          const enrollment = await window.philcore.recovery.enrollment.status();
          recoveryUi.state = enrollment.state || "SECONDARY_COMPLETE";
          recoveryUi.publicFactors = await window.philcore.recovery.enrollment.listPublicFactors();
          recoveryUi.notice = "The iPhone credential, transcript signature, and public descriptor were verified.";
        } else {
          recoveryUi.notice = `iPhone pairing status: ${pairingResult.pairing?.status || "unavailable"}`;
        }
      }
      if (action === "recoveryCancelIPhonePairing") {
        const cancelled = await window.philcore.recovery.enrollment.cancelIPhonePairing();
        recoveryUi.iphonePairing = null;
        recoveryUi.state = cancelled.state || "PRIMARY_COMPLETE";
        recoveryUi.notice = "The expiring iPhone session was cancelled. No response can be replayed.";
      }
      if (action === "recoveryCreateHardwareFallback") {
        try {
          const options = await window.philcore.recovery.enrollment.beginHardwareFallback();
          const registration = await createRecoveryCredential(options);
          const custodyDomainCommitment = await publicCommitment("independent-external-key-consumer-policy");
          const result = await window.philcore.recovery.enrollment.storeCredential({
            role: 1,
            registration,
            descriptorMetadata: {
              authenticatorClass: "EXTERNAL_HARDWARE_KEY",
              assuranceClassification: "CONSUMER_PLATFORM_NO_HARDWARE_ATTESTATION"
            },
            generation: 1,
            custodyDomainCommitment
          });
          if (result.status === "failed") throw new Error(result.reason);
          recoveryUi.state = "SECONDARY_COMPLETE";
          recoveryUi.publicFactors = await window.philcore.recovery.enrollment.listPublicFactors();
          recoveryUi.notice = "External key stored under Consumer Platform policy. Enhanced hardware assurance is not claimed.";
        } catch {
          recoveryUi.notice = "External-key fallback did not complete. Enhanced assurance remains blocked.";
        }
      }
      if (action === "recoveryCompanionCreate") {
        try {
          const encodedRequest = document.getElementById("recovery-pairing-request-input").value.trim();
          const request = JSON.parse(new TextDecoder().decode(base64UrlToBytes(encodedRequest)));
          const registration = await createRecoveryCredential({
            challenge: request.challenge,
            rp: { id: request.rpId, name: "PhilCore Recovery" },
            algorithms: [-7],
            authenticatorAttachment: "platform",
            residentKey: "required",
            userVerification: "required",
            attestation: "none",
            timeoutMs: 60_000
          });
          const custodyDomainCommitment = await publicCommitment("secondary-independent-platform-device");
          const accepted = await window.philcore.recovery.enrollment.acceptPairing(
            encodedRequest,
            {
              challenge: request.challenge,
              registration,
              descriptorMetadata: { authenticatorClass: "SECONDARY_PLATFORM_DEVICE" },
              generation: 1,
              custodyDomainCommitment
            }
          );
          if (accepted.status === "failed") throw new Error(accepted.reason);
          recoveryUi.pairingResponse = accepted.encodedResponse;
          recoveryUi.notice = "Secondary response encrypted. Return it to the primary device before it expires.";
        } catch {
          recoveryUi.notice = "Secondary enrollment did not complete. Check the request and device approval.";
        }
      }
      if (action === "recoveryCompletePairing") {
        const encodedResponse = document.getElementById("recovery-pairing-response-input").value.trim();
        const custodyDomainCommitment = await publicCommitment("secondary-independent-platform-device");
        const completed = await window.philcore.recovery.enrollment.completePairing(
          encodedResponse,
          custodyDomainCommitment
        );
        if (completed.status === "failed") {
          recoveryUi.notice = `Secondary response rejected: ${completed.reason}`;
        } else {
          recoveryUi.state = "SECONDARY_COMPLETE";
          recoveryUi.publicFactors = await window.philcore.recovery.enrollment.listPublicFactors();
          recoveryUi.notice = "Independent secondary credential verified and stored.";
        }
      }
      if (action === "recoveryGenerateOffline") {
        const generated = await window.philcore.recovery.enrollment.generateOffline();
        if (generated.status === "failed") {
          recoveryUi.notice = `Offline factor could not be generated: ${generated.reason}`;
        } else {
          recoveryUi.state = "OFFLINE_PENDING";
          recoveryUi.notice = `Offline factor generated. Public fingerprint: ${generated.safePublicFingerprint}`;
        }
      }
      if (action === "recoveryRevealOffline") {
        const revealed = await window.philcore.recovery.enrollment.revealOffline();
        recoveryUi.notice = revealed.status === "failed"
          ? `Protected reveal unavailable: ${revealed.reason}`
          : "The recovery code is shown only in the protected reveal window.";
      }
      if (action === "recoveryConfirmOfflineExport") {
        const confirmed = await window.philcore.recovery.enrollment.confirmOfflineExport();
        recoveryUi.state = confirmed.state || recoveryUi.state;
        recoveryUi.notice = confirmed.status === "failed"
          ? `Export confirmation rejected: ${confirmed.reason}`
          : "Storage confirmed. Restore the saved copy now to prove it works.";
      }
      if (action === "recoveryRestoreOffline") {
        const input = document.getElementById("recovery-restore-input");
        const restored = await window.philcore.recovery.enrollment.restoreOffline(input.value);
        input.value = "";
        recoveryUi.state = restored.status === "failed" ? "INVALIDATED" : "OFFLINE_DRILL_COMPLETE";
        recoveryUi.notice = restored.status === "failed"
          ? `Restoration failed closed: ${restored.reason}`
          : "Restoration matched. The active secret was cleared from application memory.";
      }
      if (action === "recoveryReviewIndependence") {
        const reviewed = await window.philcore.recovery.enrollment.reviewIndependence({
          acknowledged: Boolean(document.getElementById("recovery-independence-ack")?.checked),
          primaryAndSecondaryIndependent: Boolean(document.getElementById("recovery-domain-ack")?.checked)
        });
        recoveryUi.state = reviewed.state || "INVALIDATED";
        recoveryUi.notice = reviewed.status === "failed"
          ? `Independence review failed: ${reviewed.reason}`
          : "Recovery factors are ready for a separate commitment approval.";
      }
      if (action === "recoveryCancelEnrollment") {
        const cancelled = await window.philcore.recovery.enrollment.cancel();
        recoveryUi = {
          state: cancelled.state,
          preflight: recoveryUi.preflight,
          pairingRequest: "",
          pairingResponse: "",
          publicFactors: [],
          disposable: recoveryUi.disposable,
          notice: "Enrollment cancelled. Ephemeral pairing and offline material were cleared."
        };
      }
      if (action === "openChain") {
        const chain = chainCatalog.getById(button.dataset.chainId);
        if (chain) {
          currentChainId = chain.id;
          currentView = "chain";
          clearNotice();
        }
      }
      if (action === "openWorldIdPreview") {
        worldIdPreviewOpen = true;
      }
      if (action === "closeWorldIdPreview") {
        worldIdPreviewOpen = false;
      }
      if (action === "openFeaturedPreview") {
        featuredPreviewId = button.dataset.featuredId || null;
      }
      if (action === "closeFeaturedPreview") {
        featuredPreviewId = null;
      }
      if (action === "previewChainAccount") {
        chainAccountPreviewId = button.dataset.chainId || currentChainId;
      }
      if (action === "closeChainAccountPreview") {
        chainAccountPreviewId = null;
      }
      if (action === "backHome") {
        currentView = "home";
      }
      if (action === "openActivity") {
        currentView = "audit";
      }
      if (action === "openSettingsSection") {
        settingsSection = button.dataset.settingsSection || "general";
      }
      if (action === "openDeveloperTools") {
        if (developerSurfacesAllowed()) {
          settingsSection = "developer";
          currentView = "settings";
        }
      }
      if (action === "loadOlderActivity") {
        activityVisibleCount += 20;
      }
      if (action === "renameIdentity") {
        const label = window.PhilHelper.normalizeName(document.getElementById("identity-display-name")?.value);
        if (!label) {
          setNotice("warn", "Name required", "Enter a name for this Phil identity.");
        } else {
          const renamed = await window.philcore.identity.renameLocal(label);
          if (renamed.status === "renamed") {
            setNotice("ok", "Identity renamed", "The display name was updated on this Mac.");
          } else {
            setNotice("warn", "Name was not changed", "PhilCore could not update this local display name.");
          }
        }
      }
      if (action === "resetPhilPosition") philHelper.reset();
      if (action === "saveSettings") {
        const sessionTimeoutMinutes = Number(document.getElementById("setting-timeout")?.value || snapshot.settings.sessionTimeoutMinutes);
        const autoLockEnabled = document.getElementById("setting-autolock")?.checked ?? snapshot.settings.autoLockEnabled;
        const developerModeVisible = developerSurfacesAllowed()
          ? (document.getElementById("setting-devmode")?.checked ?? snapshot.settings.developerModeVisible)
          : false;
        const auditDetailLevel = developerSurfacesAllowed()
          ? (document.getElementById("setting-audit")?.value || snapshot.settings.auditDetailLevel)
          : "standard";
        await window.philcore.settings.update({ sessionTimeoutMinutes, autoLockEnabled, developerModeVisible, auditDetailLevel });
        setNotice("ok", "Settings saved", "Your local preferences were updated on this Mac.");
      }
      await refresh();
    });
  });
}

function bindCatalogSearch() {
  const input = view.querySelector("#catalog-search");
  if (!input) return;
  input.addEventListener("input", () => {
    catalogQuery = input.value;
    const results = view.querySelector("#chain-results");
    if (results) results.innerHTML = chainTiles(chainCatalog.search(catalogQuery), { searchResults: true }).__html;
    results?.querySelectorAll('[data-action="openChain"]').forEach((button) => {
      button.addEventListener("click", () => {
        currentChainId = button.dataset.chainId;
        currentView = "chain";
        renderNav();
        renderView();
      });
    });
  });
}

function kv(items) {
  return raw(`<dl class="kv">${items.map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(displayValue(v))}</dd>`).join("")}</dl>`);
}

function details(summary, body) {
  return raw(`<details class="technical-details"><summary>${escapeHtml(summary)}</summary>${body.__html || escapeHtml(body)}</details>`);
}

function detailsMarkup(summary, body) {
  return details(summary, body).__html;
}

function statusCard(title, value, description, tone = "neutral", action = "") {
  return raw(`<section class="status-card ${escapeHtml(tone)}">
    <div>
      <h3>${escapeHtml(title)}</h3>
      <strong>${escapeHtml(value)}</strong>
      <p>${escapeHtml(description)}</p>
    </div>
    ${action}
  </section>`);
}

function platformAuthFailureMessage(result = {}) {
  const reason = result.reason || result.status || "unknown_reason";
  if (reason === "identity_must_be_unlocked") return "Unlock this identity with its passphrase first, then return to Settings to enable protected Mac unlock.";
  if (reason === "authentication_failed_closed" || reason === "platform_enrollment_failed") return "PhilCore could not verify that passphrase or store the protected unlock key. Check the passphrase and try again.";
  if (reason === "unsupported_platform" || reason === "platform_authentication_unavailable") return "This package cannot use protected Mac unlock in the current environment. Passphrase unlock remains available.";
  if (reason === "keychain_adapter_not_configured") return "This unsigned test package does not have a configured macOS Keychain protection adapter here. Passphrase unlock remains available.";
  if (reason === "approval_required") return "Approval was not completed, so no protected Mac unlock credential was changed.";
  return `PhilCore stopped safely: ${present.label(reason)}. Passphrase unlock remains available.`;
}

function protectedActionEligibility(snapshot) {
  if (snapshot.protectedAction) {
    return {
      eligible: Boolean(snapshot.protectedAction.eligible),
      label: snapshot.protectedAction.eligible ? "Test a protected action" : present.label(snapshot.protectedAction.reason),
      reason: snapshot.protectedAction.explanation || "PhilCore cannot start the protected action right now."
    };
  }
  if (!snapshot.identity) {
    return { eligible: false, label: "Create identity first", reason: "Create or open a local identity before testing a protected action." };
  }
  if (snapshot.session.lockState !== "unlocked" || snapshot.session.vaultState !== "unlocked") {
    return { eligible: false, label: "Unlock identity first", reason: "PhilCore needs the identity unlocked before it can prepare a protected local action." };
  }
  if (snapshot.demo?.status && ["signing_approval_required", "preparing", "executing"].includes(snapshot.demo.status)) {
    return { eligible: false, label: "Action already active", reason: "Finish or cancel the current protected action before starting another one." };
  }
  if (snapshot.ethereum.validator?.status !== "available") {
    return { eligible: false, label: "Local signing key unavailable", reason: "The protected local signing key is required for this demonstration." };
  }
  return { eligible: true, label: "Test a protected action", reason: "PhilCore will request approval, generate and verify a fresh private proof, then require a separate signing approval and fresh user presence before local execution." };
}

function protectedActionPanel(surface) {
  const eligibility = protectedActionEligibility(snapshot);
  const action = eligibility.eligible
    ? `<button class="primary large-action" data-action="startProtectedAction" data-surface="${escapeHtml(surface)}" type="button">Run local demonstration</button>`
    : `<button class="secondary" disabled type="button" aria-disabled="true">${escapeHtml(eligibility.label)}</button>`;
  return raw(`<section class="beta-capability-card protected-action-panel">
    <div>
      <p class="section-label">Local demonstration</p>
      <h3>Protected action demonstration</h3>
      <p>${isTechnicalMode()
        ? "PhilCore checks trust and policy, asks for approval, generates and independently verifies a Noir UltraKeccakZK proof, then requires a separate signing approval and fresh presence before the local Ethereum fixture executes."
        : "See how PhilCore asks for permission, proves the protected identity condition privately, and asks again before signing and completing a harmless local action."}</p>
      <p class="muted">Nothing is sent publicly and no real funds are used.</p>
      ${!eligibility.eligible ? `<p class="unavailable-reason">${escapeHtml(eligibility.reason)}</p>` : ""}
    </div>
    <div class="actions">${action}</div>
    ${isTechnicalMode() ? detailsMarkup("Technical details", kv([
      ["Canonical operation", "startLocalWorkflow"],
      ["Runtime source", "authoritative desktop runtime snapshot"],
      ["Local execution", "Hardhat / local EntryPoint fixture"],
      ["Public network mutation", false],
      ["Arbitrary target selection", false],
      ["Current workflow", snapshot.demo?.workflowId || "none"],
      ["Current workflow state", snapshot.demo?.status || "not_started"]
    ])) : ""}
  </section>`);
}

function resultPanel() {
  if (!latestResult) return raw("");
  const nextActions = latestResult.reason === "platform_unlock_not_enrolled"
    ? '<div class="actions"><button class="primary" data-action="goProtectedMacSettings" type="button">Go to Settings</button><button class="secondary" data-action="dismissActionResult" type="button">Cancel</button></div>'
    : PROTECTED_ACTION_TERMINAL_STATES.has(latestResult.status)
      ? '<div class="actions"><button class="secondary" data-action="dismissActionResult" type="button">Close</button></div>'
      : "";
  const tone = latestResult.tone === "ok"
    ? "success"
    : latestResult.status === "rejected" || latestResult.status === "denied"
      ? "rejected"
      : latestResult.tone === "warn"
        ? "failed"
        : "info";
  return raw(`<section class="result-panel" aria-live="polite">
    ${stateCallout({ tone, title: latestResult.title || "Protected action result", message: latestResult.summary || "" }).__html}
    ${nextActions}
    ${isTechnicalMode() ? detailsMarkup("Technical details", kv([
      ["Status", latestResult.status],
      ["Reason", latestResult.reason || "none"],
      ["Workflow", latestResult.workflowId || "none"],
      ["Failed stage", latestResult.technical?.failedStage || "none"],
      ["UserOperation", latestResult.technical?.userOperationHash || "none"],
      ["Transaction", latestResult.technical?.transactionHash || "none"],
      ["Unsigned artifact", latestResult.technical?.artifactId || "none"],
      ["Private proof verification", latestResult.technical?.starkVerificationLocation || "not_run"],
      ["Ethereum verified proof", latestResult.technical?.ethereumVerifiedProof ?? false],
      ["Signature present", latestResult.technical?.signaturePresent ?? false],
      ["Public network mutation", false],
      ["Real funds used", false]
    ])) : ""}
  </section>`);
}

function pageIntro(title, body, action = "") {
  return raw(`<section class="page-intro">
    <div>
      <h3>${escapeHtml(title)}</h3>
      <p>${escapeHtml(body)}</p>
    </div>
    ${action}
  </section>`);
}

function pill(value, tone = present.statusTone(value)) {
  return raw(`<span class="inline-pill ${escapeHtml(tone)}">${escapeHtml(present.label(value))}</span>`);
}

function stageList(stages) {
  if (!stages?.length) return raw(`<p class="muted">No protected local action stages have run yet.</p>`);
  return raw(`<div class="timeline">${stages.map((stage, index) => `
    <div class="stage">
      <div class="stage-index">${index + 1}</div>
      <div>
        <strong>${escapeHtml(present.label(stage.label))}</strong>
        <p class="muted">${escapeHtml(stage.evidenceClass === "unavailable_secret_bearing_proof_quarantined"
          ? "Stopped by the proof-privacy quarantine before signing or execution."
          : stage.summary || present.label(stage.status) || "")}</p>
        ${detailsMarkup("Technical details", kv([["Raw stage", stage.label], ["Status", stage.status], ["Evidence", stage.evidenceClass], ["Safe stop", stage.evidenceClass === "unavailable_secret_bearing_proof_quarantined" ? "Current proof backend quarantined" : "Not applicable"]]))}
      </div>
    </div>
  `).join("")}</div>`);
}

function protectedWorkflowSummary() {
  const demo = snapshot.demo || {};
  if (!demo.stages?.length) {
    return raw(`<div class="empty-state"><strong>No protected action yet</strong><p>After you test a protected action, PhilCore will group approval, private-proof, signing, fresh-presence, and local-execution evidence here.</p></div>`);
  }
  const stageIds = new Set(demo.stages.map((stage) => stage.id));
  const failedStage = demo.stages.find((stage) => stage.status === "failed");
  const proofQuarantined = demo.evidenceLabels?.starkProofGeneration === "unavailable_secret_bearing_proof_quarantined"
    || demo.stages.some((stage) => stage.id === "proof_generating" && stage.evidenceClass === "unavailable_secret_bearing_proof_quarantined");
  const preparedUnsigned = demo.status === "prepared_unsigned";
  const terminal = preparedUnsigned
    ? "Ready for review"
    : demo.status === "completed"
    ? "Completed"
    : demo.status === "cancelled"
      ? "Cancelled"
      : demo.status === "failed"
        ? proofQuarantined ? "Proof safely quarantined" : "Failed"
        : present.label(demo.status || "in_progress");
  return raw(`<div class="workflow-summary ${escapeHtml(demo.status || "in_progress")}">
    <div>
      <p class="eyebrow">Protected action summary</p>
      <h3>${escapeHtml(terminal)}</h3>
      <p>${escapeHtml(preparedUnsigned
        ? "Prepared locally. Nothing has been sent to Ethereum."
        : demo.status === "completed"
        ? "PhilCore approved the local action, verified the proof, signed the bounded request, and completed the local Ethereum test."
        : proofQuarantined
          ? "PhilCore reached the proof-privacy gate and stopped before signing or execution. No public transaction was created."
        : failedStage
          ? `PhilCore stopped at ${present.label(failedStage.label || failedStage.id)}. No public transaction was created.`
          : "PhilCore is still working through the protected local action.")}</p>
    </div>
    <div class="workflow-facts">
      ${kv([
        ["Local only", true],
        ["Real funds", false],
        ["Approval granted", stageIds.has("approval_completed")],
        ["Proof verified", stageIds.has("proof_verified")],
        ["Local signer used", stageIds.has("user_operation_signed")],
        ["Local execution completed", stageIds.has("execution_verified")],
        ["Unsigned operation prepared", stageIds.has("user_operation_prepared")],
        ["Sent to Ethereum", false],
        ["Workflow", demo.workflowId || "none"]
      ]).__html}
    </div>
  </div>`);
}

function auditList(events, options = {}) {
  if (!events?.length) return raw(`<div class="empty-state"><strong>No activity yet</strong><p>PhilCore will record identity, unlock, approval, security-check, and local test events here.</p></div>`);
  return raw(`<div class="timeline">${events.map((event) => `
    <div class="event">
      <strong>${escapeHtml(present.auditTitle(event))}</strong>
      <p class="muted">${escapeHtml(options.technical ? event.timestamp : new Date(event.timestamp).toLocaleString())} - ${escapeHtml(present.auditDescription(event, options.technical))}</p>
      ${options.technical ? detailsMarkup("Technical details", kv([["Category", event.category], ["Action", event.action], ["Result", event.result], ["Evidence", event.evidenceClass], ["Correlation", event.correlationRef]])) : ""}
    </div>
  `).join("")}</div>`);
}

function approvalList(events) {
  if (!events?.length) return raw(`<div class="empty-state"><strong>No approvals yet</strong><p>Sensitive actions will ask for a digest-bound approval before PhilCore signs or executes anything locally.</p></div>`);
  return raw(`<div class="timeline">${events.map((event) => `
    <div class="event">
      <strong>${escapeHtml(present.approvalTitle(event))} - ${escapeHtml(present.label(event.decision))}</strong>
      <p class="muted">${escapeHtml(event.timestamp)} - ${escapeHtml(present.label(event.outcome))}</p>
      ${detailsMarkup("Technical details", kv([["Authentication", event.authenticationMethod], ["Digest", event.digestShort]]))}
    </div>
  `).join("")}</div>`);
}

const introSteps = Object.freeze([
  {
    eyebrow: "Phil",
    title: "I'm your security sidekick",
    body: "I help protect your digital identity, explain what is being requested, and make sure you know what you are approving before protected signing happens.",
    asset: "phil/phil_wave.png",
    alt: "Phil waving hello",
    bullets: [
      "Your identity stays protected on your devices.",
      "I explain requests in ordinary language.",
      "You choose whether anything protected continues."
    ]
  },
  {
    eyebrow: "Controlled Beta",
    title: "This Beta uses test-only Sepolia",
    body: "The Controlled Sepolia Beta uses Ethereum's Sepolia test network and test-only assets. It is not mainnet or production custody.",
    asset: "avastar/avastar_thoughtful_review.png",
    alt: "The Avastar reviewing the Controlled Sepolia Beta boundary",
    bullets: [
      "Completed Beta activity is read-only history.",
      "Local demonstrations do not create a new public transaction.",
      "No meaningful asset is used in this Beta."
    ]
  },
  {
    eyebrow: "Before protected signing",
    title: "Review first, then choose",
    body: "I show who is asking, what will happen, where it will happen, what value and maximum cost are involved, and when the request expires.",
    asset: "avastar/avastar_idle.png",
    alt: "The Avastar standing ready beside a protected request",
    bullets: [
      "Compare the fingerprint when your iPhone is involved.",
      "Rejecting grants no approval.",
      "Expired requests do not proceed."
    ]
  }
]);

function introProgress() {
  return raw(`<div class="intro-progress" aria-label="Introduction progress">
    ${introSteps.map((_, index) => `<span class="${index === introStep ? "active" : ""}">${index + 1}</span>`).join("")}
  </div>`);
}

function mentalModelSteps() {
  const steps = [
    ["identity", "Create your PhilCore identity", "PhilCore creates a personal digital identity on this Mac. It belongs to you."],
    ["lock", "Store it securely", "Sensitive identity material is encrypted and remains on this Mac."],
    ["key", "Unlock when needed", "Use your identity passphrase, or protected Mac unlock after you enable it."],
    ["review", "Review protected actions", "PhilCore shows what an application is requesting before anything sensitive happens."],
    ["choice", "Approve or reject", "You stay in control. A request can be approved, denied, or cancelled."],
    ["check", "Verify and sign locally", "PhilCore checks the approved action and signs locally on this device."],
    ["private", "Controlled Beta, bounded scope", "The completed Sepolia Beta used test-only assets. New public execution, mainnet, meaningful assets, and production custody remain unavailable."]
  ];
  return raw(`<div class="model-steps" role="list" aria-label="How PhilCore works">
    ${steps.map(([icon, title, body], index) => `<article class="model-step" role="listitem">
      <div class="model-icon ${escapeHtml(icon)}" aria-hidden="true">${index + 1}</div>
      <div>
        <h4>${escapeHtml(title)}</h4>
        <p>${escapeHtml(body)}</p>
      </div>
    </article>`).join("")}
  </div>`);
}

function previewForIdentity(identity) {
  return philPreviewProvider.fromStored(identity?.philPreview);
}

function characterAsset(relativePath) {
  return `./assets/characters/${relativePath}`;
}

function characterImage(relativePath, alt, className = "") {
  return raw(`<img class="character-art ${escapeHtml(className)}" src="${escapeHtml(characterAsset(relativePath))}" alt="${escapeHtml(alt)}">`);
}

function askPhilMarkup() {
  const answers = [
    ["What is Phil?", "Phil is your recovery and security sidekick. Phil helps protect your digital identity and explains requests before protected signing."],
    ["Why do I need my phone?", "Your enrolled iPhone provides a separate device-bound approval. Compare the fingerprint so you know the request belongs to this Mac."],
    ["What am I approving?", "Only the action shown in the summary, for the listed destination, value, maximum cost, and expiry."],
    ["What happens if I reject this?", "No approval is granted. The protected action does not continue."],
    ["What does locked mean?", "Your protected identity is closed. Unlock it before Phil can prepare a local approval request."],
    ["What is the Sepolia Beta?", "It is a controlled demonstration on Ethereum's Sepolia test network using test-only assets, not mainnet or production custody."],
    ["Is this using real money?", "No meaningful asset is used in this Beta. Sepolia assets and fees are test-only."],
    ["Is Phil post-quantum secure?", "Not currently. Today's authorization uses classical cryptography; future migration support does not make the current Beta post-quantum secure."],
    ["Why isn't recovery available yet?", "Recovery is intentionally unavailable in this Beta while the next recovery design is being prepared."]
  ];
  return raw(`<details class="ask-phil"><summary>Ask Phil</summary><dl>${answers.map(([question, answer]) => `<div><dt>${escapeHtml(question)}</dt><dd>${escapeHtml(answer)}</dd></div>`).join("")}</dl></details>`);
}

function companionGuideMarkup() {
  if (["intro", "welcome", "create", "unlock"].includes(currentView)) return raw("");
  const scenes = {
    home: ["phil/phil_wave.png", "Phil waving beside your identity", "Your next step", snapshot.session.lockState === "unlocked" ? "Your identity is unlocked. Review the completed Beta or run a separate harmless local demonstration." : "Your identity is locked. The completed Beta remains visible, but local actions require unlock."],
    chain: ["phil/phil_run_right.png", "Phil approaching a network", "A bounded connection", currentChainId === "ethereum" ? "The completed Sepolia Beta is read-only. Any reusable preparation below is a separate local demonstration." : "This destination is a preview and is not active in this Beta."],
    recovery: ["avastar/avastar_thoughtful_review.png", "The Avastar reviewing recovery protections", "Recovery guardian", "Recovery is intentionally unavailable in this Controlled Sepolia Beta."],
    audit: ["avastar/avastar_working_focus.png", "The Avastar reviewing the activity record", "Your activity trail", "Review the completed Controlled Beta history separately from actions performed locally on this Mac."],
    settings: ["phil/phil_seated_rest.png", "Phil sitting safely beside your settings", "Phil is still yours", "Security preferences can change how you unlock, but they do not hand identity authority to the interface."]
  };
  const scene = scenes[currentView] || scenes.home;
  return raw(`<aside class="companion-guide" aria-label="${escapeHtml(scene[2])}">
    ${characterImage(scene[0], scene[1], "companion-guide__art").__html}
    <div><p class="section-label">${escapeHtml(scene[2])}</p><p>${escapeHtml(scene[3])}</p>${askPhilMarkup().__html}</div>
  </aside>`);
}

function philAvatar(size = "large", preview = previewForIdentity(snapshot?.identity), options = {}) {
  const badge = options.badge
    ? `<span>${escapeHtml(options.badge)}</span>`
    : "";
  return raw(`<div class="phil-avatar ${escapeHtml(size)}">
    <img src="${escapeHtml(preview.imageUri)}" alt="${escapeHtml(preview.alt)}">
    ${badge}
  </div>`);
}

function worldIdPreviewPanel() {
  if (!worldIdPreviewOpen) return raw("");
  const provider = externalCredentialProviders.getById("world-id");
  return raw(`<section class="info-surface" role="status">
    <div class="section-heading"><div><p class="section-label">Preview</p><h3>World ID</h3></div><button class="text-button" data-action="closeWorldIdPreview" type="button">Close</button></div>
    <p>World ID integration is planned as an optional proof-of-personhood credential and trust signal.</p>
    <ul class="plain-list">
      <li>It is not required to own or control your PhilCore identity.</li>
      <li>It is not the PhilCore identity root.</li>
      <li>No World ID request occurs in this Beta.</li>
      <li>PhilCore requests or stores no World ID biometric information in this Beta.</li>
    </ul>
    ${isTechnicalMode() ? detailsMarkup("Provider boundary", kv([
      ["Provider", provider.providerId],
      ["Capabilities", provider.capabilities],
      ["Identity root authority", provider.identityRootAuthority],
      ["Remote SDK loaded", provider.remoteSdkLoaded],
      ["Network requests", provider.networkRequestsEnabled]
    ])) : ""}
  </section>`);
}

function featuredItemsMarkup() {
  const selected = ecosystemDiscovery.getById(featuredPreviewId);
  return raw(`<div class="featured-grid">${ecosystemDiscovery.items.map((item) => `
    <button class="featured-item" data-action="openFeaturedPreview" data-featured-id="${escapeHtml(item.id)}" type="button">
      <span class="catalog-icon" aria-hidden="true">${escapeHtml(item.iconText)}</span>
      <span><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(item.chainName)}</small></span>
      <span class="chain-status preview">${escapeHtml(item.status)}</span>
    </button>
  `).join("")}</div>
  ${selected ? `<section class="info-surface featured-preview">
    <div class="section-heading"><div><p class="section-label">${escapeHtml(selected.status)}</p><h3>${escapeHtml(selected.name)}</h3></div><button class="text-button" data-action="closeFeaturedPreview" type="button">Close</button></div>
    <p>${escapeHtml(selected.description)}</p>
    <p class="field-help">This bundled Beta example does not open a website, query live data, show prices, or perform a transaction.</p>
  </section>` : ""}`);
}

function chainAccountStatusLabel(chain) {
  const labels = {
    none: "No account",
    "local-test": "Local test setup",
    prepared: "Preparation only",
    "deployed-testnet": "Testnet account",
    "deployed-mainnet": "Mainnet account",
    unavailable: "Not available"
  };
  return labels[chain.accountStatus] || "Not available";
}

function chainAccountPreview(chain) {
  if (chainAccountPreviewId !== chain.id) return raw("");
  const ethereum = chain.id === "ethereum";
  return raw(`<section class="info-surface">
    <div class="section-heading"><div><p class="section-label">${ethereum ? "Controlled Beta" : "Preview"}</p><h3>${ethereum ? "Verified Sepolia account" : `Create a ${chain.name} account`}</h3></div><button class="text-button" data-action="closeChainAccountPreview" type="button">Close</button></div>
    <p>${ethereum
      ? "The completed Controlled Sepolia Beta account is present and independently reconciled. Viewing it does not create or submit a transaction."
      : `PhilCore account creation for ${chain.name} is not available in this Beta.`}</p>
    <p class="field-help">No seed phrase, new account, or public transaction is created from this read-only view.</p>
  </section>`);
}

function chainTiles(chains, options = {}) {
  if (!chains.length) {
    return raw(`<div class="empty-state catalog-empty"><strong>No local catalog match</strong><p>PhilCore does not have this ecosystem in its local catalog yet.</p></div>`);
  }
  return raw(`<div class="chain-grid ${options.searchResults ? "search-results" : ""}">${chains.map((chain) => `
    <button class="chain-tile" type="button" data-action="openChain" data-chain-id="${escapeHtml(chain.id)}">
      <span class="catalog-icon" aria-hidden="true">${escapeHtml(chain.iconText)}</span>
      <span class="chain-name">${escapeHtml(chain.name)}</span>
      <span class="chain-status ${chain.status === "Sepolia Beta" ? "available" : "preview"}">${escapeHtml(chain.status)}</span>
    </button>
  `).join("")}</div>`);
}

function userIdentityHeader() {
  const unlocked = snapshot.session.lockState === "unlocked";
  return raw(`<section class="identity-hero">
    ${philAvatar("large", previewForIdentity(snapshot.identity)).__html}
    <div class="identity-hero-copy">
      <p class="section-label">Your Phil</p>
      <h3>${escapeHtml(snapshot.identity?.label || "My Phil")}</h3>
      <p>${unlocked ? "Ready on this Mac" : "Locked on this Mac"}</p>
    </div>
    <div class="identity-hero-action">
      <span class="simple-status ${unlocked ? "ready" : "locked"}">${unlocked ? "Unlocked" : "Locked"}</span>
      <button class="${unlocked ? "secondary" : "primary"}" data-action="${unlocked ? "lock" : "goUnlock"}" type="button">${unlocked ? "Lock" : "Unlock"}</button>
      <button class="text-button world-id-button" data-action="openWorldIdPreview" type="button">Connect World ID <span>Preview</span></button>
    </div>
  </section>`);
}

function settingsTabs() {
  const sections = [
    ["general", "General"],
    ["identity", "Identity"],
    ["trust", "Trust"],
    ["recovery", "Recovery"],
    ["security", "Security"],
    ["about", "About Beta"]
  ];
  if (isTechnicalMode() && developerSurfacesAllowed() && snapshot.settings.developerModeVisible) sections.push(["developer", "Developer tools"]);
  return raw(`<nav class="settings-tabs" aria-label="Settings sections">${sections.map(([id, label]) => `
    <button type="button" data-action="openSettingsSection" data-settings-section="${id}" aria-current="${settingsSection === id ? "page" : "false"}">${label}</button>
  `).join("")}</nav>`);
}

function technicalReleasePanel() {
  return raw(`<section class="panel full technical-panel">
    <h3>Release and runtime</h3>
    ${kv([
      ["Version", snapshot.release.version],
      ["Channel", snapshot.release.channel],
      ["Bundle ID", snapshot.release.bundleIdentifier],
      ["Package profile", snapshot.release.packageProfile],
      ["Signing", snapshot.release.signingStatus],
      ["Notarization", snapshot.release.notarizationStatus],
      ["Gatekeeper", snapshot.release.gatekeeperStatus],
      ["Native user presence", snapshot.release.nativeUserPresenceStatus],
      ["Public network mode", snapshot.release.publicNetworkMode],
      ["Production approved", snapshot.release.productionApproved]
    ]).__html}
  </section>`);
}

function controlledBetaAdvancedEvidence() {
  const beta = snapshot.controlledBeta;
  if (!beta?.evidence) return raw("");
  const evidence = beta.evidence;
  return detailsMarkup("Advanced Beta evidence", kv([
    ["Release", beta.releaseId],
    ["App version", snapshot.release.version],
    ["Build channel", snapshot.release.channel],
    ["Bundle ID", snapshot.release.bundleIdentifier],
    ["Package profile", snapshot.release.packageProfile],
    ["UI package source", snapshot.release.sourceCommit],
    ["UI source tree", snapshot.release.sourceTreeClean ? "clean" : "not verified clean"],
    ["Beta evidence source commit", evidence.sourceCommit],
    ["Beta evidence source tree", evidence.sourceTree],
    ["Smart account", evidence.smartAccountAddress],
    ["Current owner", evidence.ownerAddress],
    ["EntryPoint", `${evidence.entryPointAddress} · v${evidence.entryPointVersion}`],
    ["Final nonce", beta.account.finalNonce],
    ["Final native balance (wei)", beta.account.nativeBalanceWei],
    ["Final EntryPoint deposit (wei)", beta.account.entryPointDepositWei],
    ["P2 transaction", evidence.P2.transactionHash],
    ["P2 UserOperation", evidence.P2.userOperationHash],
    ["P2 block", evidence.P2.blockNumber],
    ["P3 transaction", evidence.P3.transactionHash],
    ["P3 UserOperation", evidence.P3.userOperationHash],
    ["P3 block", evidence.P3.blockNumber],
    ["P5 transaction", evidence.P5.transactionHash],
    ["P5 UserOperation", evidence.P5.userOperationHash],
    ["P5 lineage", evidence.P5.lineage],
    ["P5 submissions / retries / added funding", `${evidence.P5.submissions} / ${evidence.P5.retries} / ${evidence.P5.additionalFundingWei} wei`],
    ["Reconciliation", beta.reconciliation.status]
  ]));
}

function controlledBetaStatusPanel(options = {}) {
  const beta = snapshot.controlledBeta;
  if (!beta) return raw("");
  if (options.compact) {
    return raw(`<section class="user-section controlled-beta-status compact" aria-labelledby="controlled-beta-title">
      <div class="section-heading"><div><p class="section-label">Ethereum Sepolia · Test only</p><h3 id="controlled-beta-title">Controlled Sepolia Beta</h3></div><span class="chain-status available">Verified</span></div>
      <p>Completed Beta history is read-only and available after unlock. Locking this identity does not change that verified history.</p>
      <div class="setting-status"><span>Final account state</span><strong>Nonce ${escapeHtml(beta.account.finalNonce)} · ${escapeHtml(beta.account.passBalance)} test passes</strong></div>
    </section>`);
  }
  const milestones = beta.milestones.map((milestone) => `
    <article class="status-card ready">
      <span class="status-icon" aria-hidden="true">✓</span>
      <div><p class="section-label">${escapeHtml(milestone.id)}</p><h3>${escapeHtml(milestone.title)}</h3><p>${escapeHtml(milestone.summary)}</p></div>
    </article>`).join("");
  return raw(`<section class="user-section controlled-beta-status" aria-labelledby="controlled-beta-title">
    <div class="section-heading"><div><p class="section-label">Ethereum Sepolia · Test only</p><h3 id="controlled-beta-title">Controlled Sepolia Beta</h3></div><span class="chain-status available">Beta verified</span></div>
    <p>The completed Beta used harmless test passes and bounded test funds. It is not mainnet, meaningful-asset use, or production custody.</p>
    <div class="setting-status"><span>Smart account</span><strong>Present and verified</strong></div>
    <div class="setting-status"><span>Final account state</span><strong>Nonce ${escapeHtml(beta.account.finalNonce)} · Native balance ${escapeHtml(beta.account.nativeBalanceEth)} ETH</strong></div>
    <div class="setting-status"><span>Remaining test deposit</span><strong>${escapeHtml(beta.account.entryPointDepositEth)} ETH</strong></div>
    <div class="setting-status"><span>Test passes</span><strong>${escapeHtml(beta.account.passBalance)} issued</strong></div>
    <div class="beta-milestones">${milestones}</div>
    <p class="field-help">${escapeHtml(beta.reconciliation.summary)}</p>
    ${controlledBetaAdvancedEvidence()}
  </section>`);
}

function controlledBetaActivityPanel() {
  const entries = [
    ["Beta authorization completed", "The controlled Sepolia authorization completed successfully."],
    ["First test pass issued", "P2 issued the first harmless test pass."],
    ["Second test pass issued", "P3 issued the second harmless test pass."],
    ["Test funds cleaned up", "P5 completed with one submission, no retry, and no new funding."],
    ["Reconciliation successful", "Independent providers agreed on the final account state."]
  ];
  return raw(`<section class="user-section controlled-beta-activity">
    <div class="section-heading"><div><p class="section-label">Read-only history</p><h3>Controlled Beta</h3></div><span class="chain-status available">Complete</span></div>
    <div class="event-list">${entries.map(([title, body]) => `<article class="event"><div><strong>${escapeHtml(title)}</strong><p>${escapeHtml(body)}</p></div><span class="event-result">Verified</span></article>`).join("")}</div>
    ${controlledBetaAdvancedEvidence()}
  </section>`);
}

function recoveryDeferredPanel() {
  return raw(`<section class="user-section recovery-deferred" aria-labelledby="recovery-deferred-title">
    <div class="section-heading"><div><p class="section-label">Coming later</p><h3 id="recovery-deferred-title">Recovery is unavailable in this Beta</h3></div><span class="chain-status preview">Deferred</span></div>
    ${stateCallout({ tone: "blocked", label: "Deferred", title: "Recovery is not available", message: "Recovery is intentionally outside this Beta while the next recovery design is prepared." }).__html}
    <p class="field-help">Local routine approval remains separate and available after unlock. This screen cannot enroll a recovery factor or approve a recovery request.</p>
  </section>`);
}

function controlledBetaAboutPanel() {
  const beta = snapshot.controlledBeta;
  return raw(`<section class="user-section beta-about">
    <div class="section-heading"><div><p class="section-label">About this release</p><h3>Phil — Controlled Sepolia Beta</h3></div><span class="chain-status available">Completed</span></div>
    <div class="setting-status"><span>App version</span><strong>${escapeHtml(snapshot.release.version)} · ${escapeHtml(snapshot.release.channel)}</strong></div>
    <div class="setting-status"><span>Network</span><strong>Ethereum Sepolia</strong></div>
    <div class="setting-status"><span>Usage</span><strong>Test only · Not mainnet</strong></div>
    <div class="setting-status"><span>Asset boundary</span><strong>No meaningful assets or production custody</strong></div>
    <div class="setting-status"><span>Recovery</span><strong>Deferred and unavailable</strong></div>
    <div class="setting-status"><span>Cryptography today</span><strong>Classical · Not post-quantum secure</strong></div>
    <p>PhilCore is designed to support future cryptographic migration, but current authorization uses classical cryptography and is not currently post-quantum secure.</p>
    ${controlledBetaAdvancedEvidence()}
  </section>`);
}

function platformSecuritySettings() {
  return raw(`<section class="panel full user-panel">
    <h3>Protected Mac unlock</h3>
    <p>Use this Mac's protected authentication to unlock PhilCore. Sensitive actions still ask for separate permission.</p>
    <div class="setting-status"><span>Status</span><strong>${escapeHtml(snapshot.platformAuth.enabled ? "Enabled" : "Not enabled")}</strong></div>
    ${snapshot.session.lockState !== "unlocked"
      ? `<div class="empty-state"><strong>Unlock first</strong><p>Unlock your identity before changing protected Mac unlock.</p><div class="actions"><button class="secondary" data-action="goUnlock" type="button">Go to Unlock</button></div></div>`
      : `
        ${passphraseField({ id: "platform-passphrase", label: "Confirm identity passphrase", value: formState.platform.passphrase, shown: formState.platform.showPassphrase, toggleField: "platformPassphrase", autocomplete: "current-password", describedBy: "platform-help" }).__html}
        <p id="platform-help" class="field-help">Your passphrase is checked locally and is never shown in Activity.</p>
        ${formState.platform.processing ? `<div class="progress-box" role="status"><div class="progress-line"></div><p>Setting up protected Mac unlock...</p></div>` : ""}
        ${inlineErrors(formState.platform.error ? [formState.platform.error] : []).__html}
        <div class="actions">
          <button class="primary" data-action="enrollPlatformAuth" type="button" ${formState.platform.processing ? "disabled" : ""}>${snapshot.platformAuth.enabled ? "Replace" : "Enable"}</button>
          <button class="secondary" data-action="disablePlatformAuth" type="button" ${(!snapshot.platformAuth.enabled || formState.platform.processing) ? "disabled" : ""}>Disable</button>
          <button class="secondary" data-action="freshPlatformAuth" type="button" ${formState.platform.processing ? "disabled" : ""}>Test confirmation</button>
        </div>`}
  </section>
  ${isTechnicalMode() ? `<section class="panel full technical-panel"><h3>Platform authentication details</h3>${kv([
    ["Status", snapshot.platformAuth.status],
    ["Protection", snapshot.platformAuth.protectionType],
    ["Availability", snapshot.platformAuth.availability],
    ["User presence guaranteed", snapshot.platformAuth.userPresenceGuaranteed]
  ]).__html}</section>` : ""}`);
}

function developerToolsPanel() {
  return raw(`<section class="panel full technical-panel">
    <h3>Developer tools</h3>
    <p>These diagnostics inspect the same protected action path. They cannot bypass approval, trust, policy, user presence, proof verification, or local-only network restrictions.</p>
    <div class="actions"><button class="primary" data-action="runDemo" type="button">Run protected action diagnostics</button></div>
  </section>
  <section class="panel technical-panel"><h3>Evidence labels</h3>${kv(Object.entries(snapshot.demo.evidenceLabels || {})).__html}</section>
  <section class="panel technical-panel"><h3>Proof status</h3>${kv([
    ["Proof type", snapshot.proof.proofType],
    ["Proof input", snapshot.proof.proofInputHash],
    ["Fact high", snapshot.proof.factHigh],
    ["Fact low", snapshot.proof.factLow],
    ["Generation", snapshot.proof.generationState],
    ["Verification", snapshot.proof.verificationState],
    ["Witness shown", snapshot.proof.witnessExposed]
  ]).__html}</section>
  <section class="panel full technical-panel"><h3>Workflow stages</h3>${stageList(snapshot.demo.stages).__html}</section>`);
}

const views = {
  intro: () => {
    const step = introSteps[introStep] || introSteps[0];
    const isLast = introStep === introSteps.length - 1;
    return html`
      <div class="intro-shell">
        <section class="intro-card">
          <div class="intro-character-stage">
            ${characterImage(step.asset, step.alt, "intro-character-stage__art")}
            <div class="intro-dialogue">
              <p class="eyebrow">${step.eyebrow}</p>
              <h3>${step.title}</h3>
              <p>${step.body}</p>
            </div>
          </div>
          <ul class="plain-list intro-list">
            ${raw(step.bullets.map((item) => `<li>${escapeHtml(item)}</li>`).join(""))}
          </ul>
          ${introProgress()}
          <div class="actions">
            ${introStep > 0 ? raw(`<button class="secondary" data-action="introBack" type="button">Back</button>`) : raw("")}
            ${isLast
              ? raw(`<button class="primary" data-action="introFinish" type="button">${introReplay ? "Return to PhilCore" : "Start using PhilCore"}</button>`)
              : raw(`<button class="primary" data-action="introNext" type="button">Continue</button>`)}
          </div>
        </section>
      </div>`;
  },
  welcome: () => html`
    <div class="grid">
      ${pageIntro("Welcome to PhilCore", "PhilCore protects a local identity on this Mac and asks for clear approval before sensitive actions. This Alpha stays local: no real funds, no public blockchain transactions, and no public account deployment.", `<div class="actions"><button class="secondary" data-action="exploreDemo" type="button">Create a guided demo identity</button></div>`)}
      <section class="panel">
        <h3>Create your local identity</h3>
        <p class="muted">Your PhilCore identity is not just a wallet. It is a local security identity that can later control approvals, trust, recovery, and smart-account actions.</p>
        <label class="field">Identity name <input id="create-label" type="text" autocomplete="off" value="Local Phil Identity" aria-describedby="identity-name-help"></label>
        <p id="identity-name-help" class="field-help">This label is only for display on this Mac.</p>
        <p id="passphrase-help" class="field-help">Choose a passphrase for this identity. It protects encrypted local records and is required when protected Mac unlock is unavailable.</p>
        ${passphraseField({ id: "create-passphrase", label: "Local passphrase", value: formState.create.passphrase, shown: formState.create.showPassphrase, toggleField: "createPassphrase", autocomplete: "new-password", describedBy: "passphrase-help passphrase-requirements" })}
        ${passphraseField({ id: "create-passphrase-confirm", label: "Enter passphrase again", value: formState.create.confirm, shown: formState.create.showConfirm, toggleField: "createConfirm", autocomplete: "new-password", describedBy: "passphrase-help" })}
        ${passphraseRequirementsMarkup(formState.create.passphrase)}
        ${inlineErrors(formState.create.errors)}
        <label class="check-row"><input id="create-recovery" type="checkbox" checked> Create a same-Mac fallback authority for local testing (does not count toward 2-of-3 recovery)</label>
        <p class="field-help">Local recovery is useful for Alpha testing, but same-Mac recovery is not the same as robust external recovery.</p>
        <div class="actions">
          <button class="primary" data-action="createIdentity" type="button">Create identity</button>
          <button class="secondary" disabled type="button">Restore identity later</button>
        </div>
      </section>
      <section class="panel">
        <h3>Open an existing identity</h3>
        ${raw(snapshot.localIdentities.length ? snapshot.localIdentities.map((identity) => `
          <div class="event">
            <strong>${escapeHtml(identity.label)}</strong>
            <p class="muted">Stored securely on this Mac. ${escapeHtml(present.label(identity.status))}.</p>
            ${detailsMarkup("Technical details", kv([["Identity reference", identity.identityId], ["Owner reference", identity.ownerCommitmentShort], ["Storage version", identity.storageFormatVersion], ["Platform unlock", present.label(identity.platformProtectionStatus)]]))}
            <button class="secondary" data-action="openIdentity" data-identity-id="${escapeHtml(identity.identityId)}" type="button">Open identity</button>
          </div>
        `).join("") : `<div class="empty-state"><strong>No identity found</strong><p>Create a local identity to begin, or use the guided demo identity for a quick Alpha walkthrough.</p></div>`)}
      </section>
      ${statusCard("Local-only boundary", "Public networks are off", "PhilCore will not submit public transactions, connect public wallets, or use meaningful assets in this Alpha.", "info")}
      ${statusCard("Recovery", "Optional same-Mac fallback", "This local testing authority is separate from the independent 2-of-3 recovery plan and does not count as one of its factors.", "warn")}
    </div>`,
  unlock: () => html`
    <div class="grid">
      ${pageIntro("Unlock your identity", "Use the passphrase you created for this identity. If protected Mac unlock is enabled, you can use this Mac instead. Unlocking does not approve actions by itself.")}
      <section class="panel">
        <h3>Passphrase unlock</h3>
        <p class="muted">Enter the passphrase for this identity. PhilCore will keep you on this screen if it does not work, so you can try again.</p>
        ${kv([["Name", snapshot.identity?.label], ["State", present.lock(snapshot)], ["Protected storage", present.label(snapshot.session.vaultState)], ["Platform unlock", present.label(snapshot.platformAuth.status)], ["Failed attempts", snapshot.session.failedUnlockAttempts]])}
        ${passphraseField({ id: "unlock-passphrase", label: "Identity passphrase", value: formState.unlock.passphrase, shown: formState.unlock.showPassphrase, toggleField: "unlockPassphrase", autocomplete: "current-password", describedBy: "unlock-help" })}
        <p id="unlock-help" class="field-help">This passphrase is checked locally against encrypted identity records on this Mac.</p>
        ${inlineErrors(formState.unlock.error ? [formState.unlock.error] : [])}
        <div class="actions">
          <button class="primary" data-action="unlock" type="button">Unlock</button>
          <button class="secondary" data-action="lock" type="button">Keep locked</button>
        </div>
      </section>
      <section class="panel">
        <h3>Unlock with this Mac</h3>
        ${snapshot.platformAuth.enabled
          ? raw(`<p class="muted">Protected Mac unlock is enabled for this identity. It can open the identity locally, but it still does not approve protected actions.</p>
            <div class="actions"><button class="primary" data-action="platformUnlock" type="button">${snapshot.platformAuth.userPresenceGuaranteed ? "Unlock with this Mac" : "Unlock with Keychain protection"}</button></div>`)
          : raw(`<p class="muted">Protected Mac unlock is not enabled yet. Passphrase unlock remains the primary unlock path. You can enable protected Mac unlock later in Settings after this identity is unlocked.</p>`)}
        <h3>After unlock</h3>
        <p class="muted">Home will update immediately and protected Alpha actions will become available when the identity is ready.</p>
        ${details("Technical details", kv([["Session", snapshot.session.sessionId || "none"], ["Authentication", snapshot.session.authentication], ["Timeout", snapshot.session.expiresAt || "not scheduled"], ["Protection type", snapshot.platformAuth.protectionType], ["User presence guaranteed", present.yesNo(snapshot.platformAuth.userPresenceGuaranteed)]]))}
      </section>
    </div>`,
  home: () => html`
    <div class="grid">
      ${pageIntro("Home", "A simple view of your local identity: whether it is ready, what to do next, what happened recently, and whether anything public occurred.", snapshot.session.lockState === "unlocked" ? `<div class="actions"><button class="secondary" data-action="lock" type="button">Lock PhilCore</button></div>` : `<div class="actions"><button class="primary" data-action="goUnlock" type="button">Unlock identity</button></div>`)}
      <section class="panel">
        <h3>Current status</h3>
        ${kv([["Identity", snapshot.identity?.label || "No identity"], ["Protection", present.lock(snapshot)], ["Stored", snapshot.identity ? "Securely on this Mac" : "Not created yet"]])}
        <p class="muted">${escapeHtml(snapshot.session.lockState === "unlocked" ? "Your identity is open for local Alpha workflows. Sensitive actions still ask for permission." : "Your identity is locked. Unlock it before testing a protected action.")}</p>
      </section>
      <section class="panel">
        <h3>Next step</h3>
        <p>${escapeHtml(protectedActionEligibility(snapshot).reason)}</p>
        <div class="actions">
          ${protectedActionEligibility(snapshot).eligible
            ? raw(`<button class="primary" data-action="startProtectedAction" data-surface="home" type="button">Test a protected action</button>`)
            : snapshot.session.lockState !== "unlocked"
              ? raw(`<button class="secondary" data-action="goUnlock" type="button">${escapeHtml(protectedActionEligibility(snapshot).label)}</button>`)
              : raw(`<button class="secondary" disabled type="button" aria-disabled="true">${escapeHtml(protectedActionEligibility(snapshot).label)}</button>`)}
        </div>
        ${details("Show how PhilCore works", mentalModelSteps())}
      </section>
      ${resultPanel()}
      <section class="panel">
        <h3>Recent activity</h3>
        ${auditList(snapshot.audit.recent.slice(0, 4))}
      </section>
      <section class="panel">
        <h3>Public activity</h3>
        <p><strong>Nothing public happened.</strong></p>
        <p class="muted">This Alpha does not submit public transactions, deploy public accounts, or use real funds.</p>
        ${details("Technical details", kv([["Mode", snapshot.app.mode], ["Public testnet", snapshot.publicTestnetMode], ["Base Sepolia Beta", snapshot.securityGate.baseSepoliaBeta], ["Session", snapshot.session.sessionId], ["Release channel", snapshot.release.channel]]))}
      </section>
    </div>`,
  identity: () => html`
    <div class="grid">
      ${pageIntro("Identity", "Your PhilCore identity is a local security identity stored on this Mac. It can later bind approvals, trust, recovery, and smart-account execution, but this Alpha does not connect it to public networks.")}
      ${statusCard("Identity name", snapshot.identity?.label || "No identity selected", snapshot.identity ? "This label should persist after close and reopen." : "Create or open an identity first.", snapshot.identity ? "ok" : "warn")}
      ${statusCard("Storage", present.label(snapshot.identity?.storageStatus), "Encrypted identity records are kept in this macOS user's app data.", "info")}
      ${statusCard("World ID", present.label(snapshot.identity?.worldIdStatus), "Human uniqueness is not connected in this local Alpha.", "neutral")}
      <section class="panel full">
        <h3>What this identity is</h3>
        <ul class="plain-list">
          <li>A local identity record protected on this Mac.</li>
          <li>A source of local signing and recovery references for Alpha workflows.</li>
          <li>Not a public wallet, exchange account, or public deployment.</li>
        </ul>
        ${details("Technical details", kv([["Identity reference", snapshot.identity?.identityId], ["Owner commitment", snapshot.identity?.ownerCommitment], ["Current device", snapshot.identity?.activeDevice], ["Validator owner", snapshot.ethereum.executionOwnerAddress], ["Recovery authority", snapshot.ethereum.recoveryAuthorityAddress], ["Storage version", snapshot.identity?.storageVersion]]))}
      </section>
      <section class="panel full warning">PhilCore does not render root secrets, decrypted registry contents, signing material, recovery material, or proof witnesses.</section>
    </div>`,
  trust: () => html`
    <div class="grid">
      ${pageIntro("Trust", "Trust shows which local credentials and devices PhilCore can see for this identity. In this Alpha, trust evidence is local and public-metadata based; it is not a production trust guarantee.")}
      <section class="panel">
        <h3>This device</h3>
        ${raw(snapshot.trust.devices.length ? snapshot.trust.devices.map((d) => `<div class="event">
          <strong>${escapeHtml(present.label(d.deviceId))}</strong>
          <p class="muted">${escapeHtml(present.label(d.lifecycleStatus))}. Production evidence: ${escapeHtml(present.yesNo(d.productionEvidence))}.</p>
          ${detailsMarkup("Technical details", kv([["Device reference", d.deviceId], ["Provider", d.providerType], ["Recovery only", present.yesNo(d.recoveryOnly)], ["Ordinary use", present.yesNo(d.ordinaryUseEligible)]]))}
        </div>`).join("") : `<div class="empty-state"><strong>No visible device credential</strong><p>Unlock the identity to inspect local public credential metadata.</p></div>`)}
      </section>
      <section class="panel">
        <h3>Credentials</h3>
        ${raw(snapshot.trust.credentials.length ? snapshot.trust.credentials.map((c) => `<div class="event">
          <strong>${escapeHtml(c.recoveryOnly ? "Recovery credential" : "Local signing credential")}</strong>
          <p class="muted">${escapeHtml(present.label(c.lifecycleStatus))}. ${escapeHtml(c.recoveryOnly ? "Can support recovery only." : "Can support local Alpha actions after approval.")}</p>
          ${detailsMarkup("Technical details", kv([["Credential reference", c.credentialId], ["Provider", c.providerType], ["Public owner", c.publicOwnerAddress], ["Recovery only", present.yesNo(c.recoveryOnly)]]))}
        </div>`).join("") : `<div class="empty-state"><strong>No credentials visible</strong><p>Credentials are visible only while protected state is unlocked.</p></div>`)}
      </section>
      <section class="panel full">
        <h3>Trust status</h3>
        ${kv([["Last check", snapshot.trust.lastEvaluation], ["Ready for this Alpha", snapshot.trust.publicMetadataSufficient]])}
        ${details("Technical details", kv([["Evidence class", snapshot.trust.evidenceClass]]))}
      </section>
    </div>`,
  recovery: () => html`
    <div class="grid">
      ${pageIntro("Recovery setup", "Set up three independent recovery factors. Exactly two are required for recovery; none are used for ordinary account actions.")}
      ${statusCard("Enrollment state", present.label(recoveryUi.state), recoveryUi.notice || "Run the environment check before creating any credential.", recoveryUi.state.includes("BLOCKED") || recoveryUi.state === "INVALIDATED" ? "warn" : "info")}
      ${recoveryUi.preflight?.blockers?.includes("PACKAGED_IDENTITY_MISMATCH") ? statusCard("Package identity", "Unsigned test-build limitation", "The current local package does not have the signed WebAuthn application identity required for a production-bound Mac recovery credential. This is expected here and no factor was enrolled.", "warn") : raw("")}
      ${statusCard("Standard profile", recoveryUi.preflight?.standard || "Not checked", "Primary Mac recovery, native iPhone companion, and offline factor. Exactly two are required.", recoveryUi.preflight?.standard === "BLOCKED" ? "warn" : "info")}
      ${statusCard(
        "Primary Mac Role 0",
        recoveryUi.preflight?.preflightV3?.primaryMacRole0?.status || "Not checked",
        "This step uses the PhilCore Desktop window on this Mac. The macOS WebAuthn sheet creates a real recovery credential only after complete Standard readiness.",
        recoveryUi.preflight?.preflightV3?.primaryMacRole0?.status === "BLOCKED" ? "warn" : "info"
      )}
      ${statusCard(
        "iPhone Role 1",
        recoveryUi.preflight?.preflightV3?.iphoneRole1?.status
          || recoveryUi.iphonePairing?.status
          || "Not checked",
        "Preflight reports desktop pairing transport/policy ready only. That is not physical iPhone verification. Enrollment still requires the native companion with a device-bound P-256 key and local Face ID or passcode approval.",
        recoveryUi.preflight?.preflightV3?.iphoneRole1?.status === "READY"
          || recoveryUi.iphonePairing?.status === "VERIFIED"
          ? "info"
          : "warn"
      )}
      ${statusCard("Enhanced profile", "Blocked", "Hardware-attested assurance is unavailable until a reviewed trust-root bundle and certificate-chain verifier are installed. A hardware key may only be labeled Consumer Platform today.", "warn")}
      <section class="panel full">
        <h3>Environment check</h3>
        <ul class="plain-list">
          <li>Secure origin: <code>recovery.philcore.localhost:18443</code> over pinned HTTPS</li>
          <li>RP ID: <code>recovery.philcore.localhost</code></li>
          <li>Encrypted records stay in the main process and expose only opaque references.</li>
          <li>The native iPhone flow binds one selected private LAN interface and adds application-level ECDH, HKDF, AES-GCM, expiry, and replay rejection.</li>
        </ul>
        <div class="actions">
          <button class="primary" data-action="recoveryEnvironmentCheck" data-profile="STANDARD" type="button">Check Standard environment</button>
          <button class="secondary" data-action="recoveryEnvironmentCheck" data-profile="ENHANCED" type="button">Check Enhanced environment</button>
          <button class="secondary" data-action="recoveryDisposableMacCheck" type="button" ${recoveryUi.preflight?.checks?.platformAuthenticator !== true ? "disabled" : ""}>Run disposable Mac credential check</button>
        </div>
        ${recoveryUi.preflight ? details("Safe preflight details", kv([
          ["Standard", recoveryUi.preflight.standard],
          ["Enhanced", recoveryUi.preflight.enhanced],
          ["Selected profile", recoveryUi.preflight.selectedProfile],
          ["Blockers", recoveryUi.preflight.blockers?.join(", ") || "None"],
          ["Electron configuration", recoveryUi.preflight.platformWebAuthnStartup?.result || "Unavailable"],
          ["Complete Standard ceremony", recoveryUi.preflight.preflightV3?.completeStandardCeremony?.status || "Legacy preflight"],
          ["iPhone Role 1 (desktop pairing transport/policy ready)", recoveryUi.preflight.preflightV3?.iphoneRole1?.status || "Unavailable"],
          ["Disposable diagnostic", recoveryUi.preflight.preflightV3?.checks?.disposableCreationAssertion === true ? "Main-verified" : "Not verified"]
        ])) : raw("")}
      </section>
      <section class="panel">
        <h3>1. Primary device</h3>
        <p class="muted"><strong>Device:</strong> this primary Mac. <strong>Window:</strong> PhilCore Desktop. The expected macOS sheet is a WebAuthn credential-creation prompt, not the ordinary Touch ID unlock prompt. This button creates a real Role 0 only after the complete Standard preflight passes. Never paste a credential ID or recovery secret into Codex.</p>
        <div class="actions">
          <button class="primary" data-action="recoveryCreatePrimary" type="button" ${recoveryUi.state !== "PRIMARY_PENDING" ? "disabled" : ""}>Create primary credential</button>
        </div>
      </section>
      <section class="panel">
        <h3>2. Independent secondary device (Role 1)</h3>
        <p class="muted"><strong>Standard:</strong> use the native PhilCore Companion on an independent iPhone. Its private key stays on that iPhone. The QR contains an expiring endpoint, public ECDH key, challenge, and exact PhilCore identity binding—never a recovery secret or desktop private key.</p>
        <button class="primary" data-action="recoveryBeginIPhonePairing" type="button" ${recoveryUi.state !== "PRIMARY_COMPLETE" ? "disabled" : ""}>Enroll iPhone companion</button>
        <button class="secondary" data-action="recoveryCreateHardwareFallback" type="button" ${recoveryUi.state !== "PRIMARY_COMPLETE" ? "disabled" : ""}>Use external key (Consumer policy)</button>
        ${recoveryUi.iphonePairing?.qrDataUrl ? raw(`
          <div class="pairing-qr">
            <img src="${escapeHtml(recoveryUi.iphonePairing.qrDataUrl)}" alt="Expiring PhilCore iPhone enrollment QR code">
            <div>
              <strong>Compare this fingerprint on both devices</strong>
              <p class="fingerprint">${escapeHtml(recoveryUi.iphonePairing.comparisonFingerprint)}</p>
              <p class="muted">Expires ${escapeHtml(recoveryUi.iphonePairing.expiresAt)}. Interface ${escapeHtml(recoveryUi.iphonePairing.interface?.name || "selected")}: ${escapeHtml(recoveryUi.iphonePairing.interface?.address || "private LAN")}.</p>
            </div>
          </div>
          <div class="actions">
            <button class="secondary" data-action="recoveryRefreshIPhonePairing" type="button">Check iPhone response</button>
            <button class="secondary danger" data-action="recoveryCancelIPhonePairing" type="button">Cancel iPhone pairing</button>
          </div>
        `) : raw("")}
      </section>
      <section class="panel full">
        <h3>Enhanced external-key option</h3>
        <p class="muted">The external hardware-key path remains available for the Enhanced profile. The legacy second-computer transfer controls below are retained for test compatibility; they are not the Standard iPhone path.</p>
        <label>Request from primary
          <textarea id="recovery-pairing-request-input" rows="4" autocomplete="off" spellcheck="false"></textarea>
        </label>
        <button class="secondary" data-action="recoveryCompanionCreate" type="button">Create secondary response on this device</button>
        ${recoveryUi.pairingResponse ? raw(`<label>Encrypted response<textarea readonly rows="4">${escapeHtml(recoveryUi.pairingResponse)}</textarea></label>`) : raw("")}
      </section>
      <section class="panel">
        <h3>3. Offline backup</h3>
        <p class="muted">The PHIL39-V1 code appears only in a protected reveal window. Clipboard copying is unavailable. Save it away from normal device backups.</p>
        <div class="actions">
          <button class="primary" data-action="recoveryGenerateOffline" type="button" ${recoveryUi.state !== "SECONDARY_COMPLETE" ? "disabled" : ""}>Generate offline factor</button>
          <button class="secondary" data-action="recoveryRevealOffline" type="button" ${!["OFFLINE_PENDING", "OFFLINE_EXPORT_CONFIRMED"].includes(recoveryUi.state) ? "disabled" : ""}>Reveal / print</button>
          <button class="secondary" data-action="recoveryConfirmOfflineExport" type="button" ${recoveryUi.state !== "OFFLINE_PENDING" ? "disabled" : ""}>I stored it safely</button>
        </div>
        <label>Restore from saved copy
          <input id="recovery-restore-input" type="password" autocomplete="off" autocapitalize="characters" spellcheck="false">
        </label>
        <button class="secondary" data-action="recoveryRestoreOffline" type="button" ${recoveryUi.state !== "OFFLINE_EXPORT_CONFIRMED" ? "disabled" : ""}>Verify saved copy</button>
      </section>
      <section class="panel">
        <h3>Independence review</h3>
        <label class="check-row"><input id="recovery-domain-ack" type="checkbox"> Primary and secondary credentials are controlled on different devices and custody domains.</label>
        <label class="check-row"><input id="recovery-independence-ack" type="checkbox"> I understand any two factors can recover and no password, email, SMS, TOTP, or server approval counts.</label>
        <button class="primary" data-action="recoveryReviewIndependence" type="button" ${recoveryUi.state !== "OFFLINE_DRILL_COMPLETE" ? "disabled" : ""}>Review readiness</button>
      </section>
      <section class="panel full">
        <h3>Safe public factor summary</h3>
        ${raw(recoveryUi.publicFactors.length ? recoveryUi.publicFactors.map((factor) => `
          <div class="event">
            <strong>Role ${escapeHtml(factor.role)}</strong>
            <p class="muted">Public fingerprint: ${escapeHtml(factor.safePublicFingerprint || "Unavailable")}</p>
            <p class="muted">Policy: ${escapeHtml(factor.policyId || factor.formatVersion || "PHIL39-V1")}</p>
          </div>
        `).join("") : `<p class="muted">No O.41 recovery factors have been enrolled.</p>`)}
        <p class="field-help">TOTP is deferred as an optional local warning barrier. It is not a recovery authority and never changes exact 2-of-3.</p>
        <button class="secondary danger" data-action="recoveryCancelEnrollment" type="button">Cancel and clear ephemeral material</button>
      </section>
    </div>`,
  ethereum: () => html`
    <div class="grid">
      ${pageIntro("Ethereum", "PhilCore can now prepare one composed, zero-value Sepolia mint through the restricted ERC-4337 account. Deployment, funding, and submission stay locked until a separate final confirmation.")}
      ${sepoliaMintPanel()}
      ${protectedActionPanel("ethereum")}
      ${resultPanel()}
      ${statusCard("Network mode", "Sepolia preparation only", "Read-only preflight is allowed; public mutations remain disabled.", "info")}
      ${statusCard("Smart account", present.label(snapshot.ethereum.smartAccountStatus), "The local account represents how future approved actions will be routed.", "info")}
      ${statusCard("Last action", present.label(snapshot.ethereum.lastConsumerExecution), snapshot.ethereum.lastConsumerExecution === "pending_signature" ? "A local signing approval is still pending. Refresh after approval completes." : "The latest local action result is projected from Runtime state.", present.statusTone(snapshot.ethereum.lastConsumerExecution))}
      ${statusCard("Replay protection", present.label(snapshot.ethereum.nullifierState), "PhilCore tracks whether this local action has already been used so the same approval cannot run twice.", present.statusTone(snapshot.ethereum.nullifierState))}
      <section class="panel full">
        <h3>Safe Alpha limits</h3>
        <ul class="plain-list">
          <li>No public transaction is submitted.</li>
          <li>No public smart account is deployed.</li>
          <li>No meaningful asset can be moved.</li>
          <li>No arbitrary target selection is exposed.</li>
        </ul>
        ${details("Technical details", kv([["Smart account", snapshot.ethereum.smartAccountAddress], ["EntryPoint", snapshot.ethereum.entryPointVersion], ["ActionGate", snapshot.ethereum.approvedActionGate], ["Execution owner", snapshot.ethereum.executionOwnerAddress], ["Recovery authority", snapshot.ethereum.recoveryAuthorityAddress], ["Replay protection state", snapshot.ethereum.nullifierState], ["Latest operation", snapshot.ethereum.latestUserOperation]]))}
      </section>
    </div>`,
  audit: () => html`
    <div class="grid">
      ${pageIntro("Activity", "Activity explains what PhilCore has done in human terms. Expand technical details when you need raw event names, evidence labels, or correlation references.")}
      <section class="panel full">
        <h3>Protected action</h3>
        ${protectedWorkflowSummary()}
      </section>
      <section class="panel full">
        <h3>Protected action details</h3>
        ${details("Show stage details", stageList(snapshot.demo.stages))}
      </section>
      <section class="panel full">
        <h3>Recent activity</h3>
        ${auditList(snapshot.audit.recent)}
      </section>
      <section class="panel full">
        <h3>Approvals</h3>
        ${approvalList(snapshot.approvals.history)}
      </section>
    </div>`,
  settings: () => html`
    <div class="grid">
      ${pageIntro("Settings", "Choose local app behavior here. Release, signing, and diagnostic details are available below without dominating normal settings.")}
      <section class="panel">
        <h3>User settings</h3>
        <label class="field">Session timeout in minutes <input id="setting-timeout" type="number" min="1" max="120" value="${snapshot.settings.sessionTimeoutMinutes}"></label>
        <label class="check-row"><input id="setting-autolock" type="checkbox" ${snapshot.settings.autoLockEnabled ? "checked" : ""}> Lock automatically after inactivity</label>
        <label class="check-row"><input id="setting-devmode" type="checkbox" ${snapshot.settings.developerModeVisible ? "checked" : ""}> Show Developer mode in the sidebar</label>
        <label class="field">Activity detail <select id="setting-audit"><option value="summary" ${snapshot.settings.auditDetailLevel === "summary" ? "selected" : ""}>Summary</option><option value="standard" ${snapshot.settings.auditDetailLevel === "standard" ? "selected" : ""}>Standard</option><option value="developer" ${snapshot.settings.auditDetailLevel === "developer" ? "selected" : ""}>Developer</option></select></label>
        <div class="actions">
          <button class="primary" data-action="saveSettings" type="button">Save settings</button>
          <button class="secondary" data-action="replayIntro" type="button">Replay introduction</button>
        </div>
      </section>
      <section class="panel">
        <h3>Unlock with this Mac</h3>
        <p class="muted">Use this Mac's protected authentication method to unlock PhilCore without typing your identity passphrase each time. It does not approve actions by itself.</p>
        ${kv([["Status", present.label(snapshot.platformAuth.status)], ["Protection", present.label(snapshot.platformAuth.protectionType)], ["Available", present.label(snapshot.platformAuth.availability)], ["User presence", present.yesNo(snapshot.platformAuth.userPresenceGuaranteed)]])}
        ${snapshot.session.lockState !== "unlocked"
          ? raw(`<div class="empty-state"><strong>Unlock from Home first</strong><p>Unlock your identity from Home before enabling protected Mac unlock. This keeps Settings focused on protected Mac unlock configuration after protected state is open.</p><div class="actions"><button class="secondary" data-action="goUnlock" type="button">Go to Unlock</button></div></div>`)
          : raw(`
            ${snapshot.platformAuth.enabled
              ? `<p class="success"><strong>Protected Mac unlock is enabled.</strong></p><p class="muted">You can use it from the Unlock screen. Passphrase unlock remains available as a fallback.</p>`
              : `<p class="muted">To enable it, first confirm your identity passphrase.</p>`}
            ${passphraseField({ id: "platform-passphrase", label: "Confirm identity passphrase", value: formState.platform.passphrase, shown: formState.platform.showPassphrase, toggleField: "platformPassphrase", autocomplete: "current-password", describedBy: "platform-help" }).__html}
            <p id="platform-help" class="field-help">PhilCore verifies this passphrase locally before storing a protected local unlock key through the available macOS protection boundary.</p>
            ${formState.platform.processing ? `<div class="progress-box" role="status"><div class="progress-line"></div><p>Working on protected Mac unlock setup...</p></div>` : ""}
            ${inlineErrors(formState.platform.error ? [formState.platform.error] : []).__html}
            <div class="actions">
              <button class="primary" data-action="enrollPlatformAuth" type="button" ${formState.platform.processing ? "disabled" : ""}>${snapshot.platformAuth.enabled ? "Replace protected Mac unlock" : "Enable protected Mac unlock"}</button>
              <button class="secondary" data-action="disablePlatformAuth" type="button" ${(!snapshot.platformAuth.enabled || formState.platform.processing) ? "disabled" : ""}>Disable</button>
              <button class="secondary" data-action="freshPlatformAuth" type="button" ${formState.platform.processing ? "disabled" : ""}>Test fresh authentication</button>
            </div>
          `)}
      </section>
      <section class="panel full">
        <h3>About and diagnostics</h3>
        ${kv([["Version", snapshot.release.version], ["Channel", snapshot.release.channel], ["Bundle ID", snapshot.release.bundleIdentifier], ["Package profile", snapshot.release.packageProfile], ["Signing", present.label(snapshot.release.signingStatus)], ["Notarization", present.label(snapshot.release.notarizationStatus)], ["Gatekeeper", present.label(snapshot.release.gatekeeperStatus)], ["Native user presence", present.label(snapshot.release.nativeUserPresenceStatus)], ["Public network mode", present.label(snapshot.release.publicNetworkMode)], ["Production approved", present.yesNo(snapshot.release.productionApproved)]])}
      </section>
      <section class="panel warning">Public RPC, bundlers, unrestricted signing, arbitrary targets, and security-gate overrides are not exposed in Settings.</section>
    </div>`,
  developer: () => html`
    <div class="grid">
      ${pageIntro("Developer mode", "This area exposes local fixture and runtime diagnostics for builders. It cannot skip approval, trust evaluation, proof verification, user presence, policy, or network restrictions.")}
      <section class="panel">
        <h3>Real local authorization</h3>
        <p class="muted">This diagnostic button now uses the same canonical protected-action operation exposed on Home and Ethereum. It shows raw stages for debugging, but it cannot bypass approval, trust, policy, user presence, proof verification, or Device Vault restrictions.</p>
        <div class="actions"><button class="primary" data-action="runDemo" type="button">Test protected action with diagnostics</button></div>
      </section>
      <section class="panel">
        <h3>Evidence labels</h3>
        ${kv(Object.entries(snapshot.demo.evidenceLabels || {}).map(([key, value]) => [key, value]))}
      </section>
      <section class="panel">
        <h3>Proof status</h3>
        ${kv([["Proof type", snapshot.proof.proofType], ["Proof input", snapshot.proof.proofInputHash], ["Fact high", snapshot.proof.factHigh], ["Fact low", snapshot.proof.factLow], ["Generation", snapshot.proof.generationState], ["Verification", snapshot.proof.verificationState], ["Witness shown", present.yesNo(snapshot.proof.witnessExposed)]])}
      </section>
      <section class="panel full">
        <h3>Workflow stages</h3>
        ${stageList(snapshot.demo.stages)}
      </section>
    </div>`
};

Object.assign(views, {
  welcome: () => {
    const identities = snapshot.localIdentities || [];
    return html`
      <div class="standalone-entry">
        <section class="welcome-entry">
          <p class="welcome-hello">Hello</p>
          <p class="welcome-positioning">I’m Phil, your secure digital identity. My purpose is to help protect your assets, privacy, and sovereignty as a human being in the digital world.</p>
          <div class="phil-preview-area">
            ${philAvatar("hero", selectedPhilPreview)}
            <button class="icon-button randomize-phil" data-action="randomizePhil" type="button" aria-label="Randomize Phil" title="Randomize Phil" ${selectedPhilPreview.generated ? "" : "disabled"}>⚄</button>
          </div>
          <div class="welcome-naming">
            <label class="field" for="welcome-phil-name">Choose a name for Phil</label>
            <input id="welcome-phil-name" type="text" maxlength="64" autocomplete="off" placeholder="Your Phil’s name" value="${formState.create.name}" aria-describedby="welcome-name-help">
            <p id="welcome-name-help" class="field-help">Your local profile name, just on this Mac. Connecting an ENS name to your Phil Ethereum account is planned for Mainnet and unavailable in this Beta.</p>
          </div>
          <button class="primary large-action create-phil-button" data-action="beginCreatePhil" type="button" ${selectedPhilPreview.generated ? "" : "disabled"}>${selectedPhilPreview.generated ? "Create Phil" : "Building Phil…"}</button>
          <p class="beta-footnote">Controlled Sepolia Beta · Test assets only</p>
        </section>
        ${identities.length ? raw(`<section class="returning-identities">
          <div class="section-heading"><div><p class="section-label">Existing identities</p><h3>Welcome back</h3></div></div>
          <div class="identity-list">${identities.map((identity) => `
            <article class="identity-choice">
              ${philAvatar("small", previewForIdentity(identity)).__html}
              <div><strong>${escapeHtml(identity.label)}</strong><p>Last used ${escapeHtml(identity.lastOpenedAt ? new Date(identity.lastOpenedAt).toLocaleDateString() : "on this Mac")} · Locked</p></div>
              <button class="primary" data-action="openIdentity" data-identity-id="${escapeHtml(identity.identityId)}" type="button">Continue</button>
            </article>`).join("")}
          </div>
        </section>`) : raw("")}
      </div>`;
  },
  create: () => html`
    <div class="standalone-entry creation-entry">
      <button class="back-button standalone-back" data-action="backWelcome" type="button">← Back</button>
      <section class="creation-form">
        <div class="creation-preview">${philAvatar("hero", selectedPhilPreview)}</div>
        <div>
          <p class="section-label">Create Phil</p>
          <h3>Make Phil yours</h3>
          <p>Choose a passphrase to protect your local Phil profile.</p>
        </div>
        <div class="creation-fields">
          <label class="field">Phil name <input id="create-label" type="text" autocomplete="off" maxlength="64" value="${formState.create.name}" aria-describedby="identity-name-help"></label>
          <p id="identity-name-help" class="field-help">This name is stored locally and can be changed in Settings. It is not ENS and does not change your cryptographic identity.</p>
          ${passphraseField({ id: "create-passphrase", label: "Passphrase", value: formState.create.passphrase, shown: formState.create.showPassphrase, toggleField: "createPassphrase", autocomplete: "new-password", describedBy: "passphrase-requirements" })}
          ${passphraseRequirementsMarkup(formState.create.passphrase)}
          ${passphraseField({ id: "create-passphrase-confirm", label: "Confirm passphrase", value: formState.create.confirm, shown: formState.create.showConfirm, toggleField: "createConfirm", autocomplete: "new-password", describedBy: "passphrase-match" })}
          ${passphraseMatchMarkup()}
          ${inlineErrors(formState.create.errors)}
          ${isTechnicalMode() ? raw(`<label class="check-row"><input id="create-recovery" type="checkbox"> Create a same-Mac engineering fallback (local testing only; not Beta recovery)</label>`) : raw("")}
          <div class="actions creation-actions">
            <button class="primary large-action" data-action="createIdentity" type="button">Create Phil identity</button>
            <button class="secondary" data-action="backWelcome" type="button">Back</button>
          </div>
        </div>
      </section>
    </div>`,
  unlock: () => html`
    <div class="lock-space unlock-gateway">
      <section class="lock-space__entry" aria-label="Unlock your Phil">
        <div class="lock-space__character">${philAvatar("hero")}</div>
        <p class="section-label">Your Phil</p>
        <h3>${snapshot.identity?.label || "My Phil"}</h3>
        <p class="lock-space__welcome">Welcome back.</p>
        ${passphraseField({ id: "unlock-passphrase", label: "Passphrase", value: formState.unlock.passphrase, shown: formState.unlock.showPassphrase, toggleField: "unlockPassphrase", autocomplete: "current-password", describedBy: "unlock-help" })}
        <p id="unlock-help" class="field-help">Your passphrase stays on this Mac.</p>
        ${inlineErrors(formState.unlock.error ? [formState.unlock.error] : [])}
        <div class="actions">
          <button class="primary large-action" data-action="unlock" type="button">Unlock</button>
          ${snapshot.platformAuth.enabled ? raw(`<button class="secondary large-action" data-action="platformUnlock" type="button">Use this Mac</button>`) : raw("")}
        </div>
      </section>
    </div>`,
  home: () => html`
    <div class="mobile-flow home-portal identity-world">
      <div class="identity-world__self">
      ${userIdentityHeader()}
      ${controlledBetaStatusPanel({ compact: true })}
      ${worldIdPreviewPanel()}
      ${resultPanel()}
      </div>
      <div class="identity-world__available">
      ${routineAuthorizationPanel()}
      <section class="user-section">
        <div class="section-heading"><div><p class="section-label">Local catalog</p><h3>Choose a destination</h3></div></div>
        ${chainTiles(chainCatalog.favorites)}
      </section>
      </div>
      <section class="catalog-search-section">
        <label for="catalog-search">Search blockchains, apps, and ecosystems</label>
        <div class="search-box"><span aria-hidden="true">⌕</span><input id="catalog-search" type="search" value="${catalogQuery}" placeholder="Search the bundled Beta catalog" autocomplete="off"></div>
        <p class="field-help">Searches only the catalog bundled with this Beta.</p>
        <div id="chain-results">${catalogQuery ? chainTiles(chainCatalog.search(catalogQuery), { searchResults: true }) : raw("")}</div>
      </section>
      <section class="user-section trending-section identity-world__later">
        <div class="section-heading"><div><p class="section-label">Coming later</p><h3>Trending</h3></div><span class="demo-label">Demo examples</span></div>
        ${featuredItemsMarkup()}
      </section>
      <section class="user-section">
        <div class="section-heading"><div><h3>Recent Activity</h3></div><button class="text-button" data-action="openActivity" type="button">View all activity</button></div>
        ${auditList((snapshot.audit.history || snapshot.audit.recent || []).slice(0, 4), { technical: false })}
      </section>
      ${isTechnicalMode() ? raw(`<section class="panel full technical-panel"><h3>Advanced status</h3>${kv([
        ["Runtime mode", snapshot.app.mode],
        ["Session", snapshot.session.sessionId],
        ["Protected action", snapshot.protectedAction?.status],
        ["Public testnet", snapshot.publicTestnetMode],
        ["Base Sepolia gate", snapshot.securityGate.baseSepoliaBeta],
        ["Chain catalog source", chainCatalog.source],
        ["Remote search enabled", chainCatalog.remoteSearchEnabled],
        ["Featured source", ecosystemDiscovery.source],
        ["Live trending", ecosystemDiscovery.liveTrending],
        ["World ID provider", externalCredentialProviders.getById("world-id").status]
      ]).__html}<div class="actions">${developerSurfacesAllowed() && snapshot.settings.developerModeVisible ? `<button class="secondary" data-action="openDeveloperTools" type="button">Developer tools</button>` : ""}</div></section>`) : raw("")}
    </div>`,
  chain: () => {
    const chain = chainCatalog.getById(currentChainId) || chainCatalog.chains[0];
    const ethereum = chain.id === "ethereum";
    return html`
      <div class="mobile-flow chain-page">
        <button class="back-button" data-action="backHome" type="button">← Back to Home</button>
        <section class="chain-hero">
          <span class="catalog-icon hero" aria-hidden="true">${escapeHtml(chain.iconText)}</span>
          <div><p class="section-label">${chain.symbol}</p><h3>${chain.name}</h3><p>${chain.description}</p></div>
          <span class="chain-status ${ethereum ? "available" : "preview"}">${chain.status}</span>
        </section>
        <section class="account-setup-row">
          <div><p class="section-label">Account status</p><strong>${escapeHtml(chainAccountStatusLabel(chain))}</strong></div>
        <button class="${ethereum ? "primary" : "secondary"}" data-action="previewChainAccount" data-chain-id="${escapeHtml(chain.id)}" type="button">${ethereum ? "View Beta account" : "Create account"}</button>
          ${!ethereum ? raw(`<span class="chain-status preview">Preview</span>`) : raw("")}
        </section>
        ${chainAccountPreview(chain)}
        ${ethereum ? raw(`
          ${controlledBetaStatusPanel().__html}
          <section class="user-section local-demonstrations" aria-labelledby="local-demonstrations-title">
            <div class="section-heading"><div><p class="section-label">Separate capability · Local only</p><h3 id="local-demonstrations-title">Local demonstrations</h3></div><span class="demo-label">No public submission</span></div>
            <p>These demonstrations run on this Mac and do not replay or recreate the completed Controlled Beta.</p>
            <div class="local-demo-options">
              ${sepoliaMintPanel().__html}
              ${protectedActionPanel("ethereum").__html}
            </div>
          </section>
          ${resultPanel().__html}
          <section class="user-section"><h3>Coming later</h3><ul class="plain-list"><li>Public account connection</li><li>Applications and services</li><li>Transfers and tokens</li><li>Identity-based permissions</li></ul></section>
        `) : raw(`<section class="user-section preview-message"><h3>Coming later</h3><p>PhilCore support for ${escapeHtml(chain.name)} is planned but not active in this Beta.</p></section>`)}
        ${isTechnicalMode() ? raw(`<section class="panel full technical-panel"><h3>${escapeHtml(chain.name)} implementation</h3>${kv([
          ["Catalog ID", chain.id],
          ["Adapter status", chain.adapterStatus],
          ["Public network enabled", chain.publicNetworkEnabled],
          ["Account status", chain.accountStatus],
          ["Supported capabilities", chain.supportedActions],
          ["Disabled capabilities", chain.disabledActions],
          ["Smart account", ethereum ? snapshot.ethereum.smartAccountStatus : "not_available"],
          ["Network mutation", false]
        ]).__html}</section>`) : raw("")}
      </div>`;
  },
  recovery: () => html`
    <div class="mobile-flow">
      ${pageIntro("Recovery later", "Recovery is intentionally outside this Controlled Sepolia Beta.")}
      ${recoveryDeferredPanel()}
      ${controlledBetaAboutPanel()}
    </div>`,
  audit: () => {
    const history = snapshot.audit.history || snapshot.audit.recent || [];
    const visible = history.slice(0, activityVisibleCount);
    return html`
      <div class="mobile-flow">
        ${pageIntro("Activity", "See what PhilCore has done on this Mac.")}
        ${controlledBetaActivityPanel()}
        <section class="user-section">
          <div class="section-heading"><div><p class="section-label">This Mac</p><h3>Local activity</h3></div></div>
          ${auditList(visible, { technical: isTechnicalMode() })}
          ${visible.length < history.length ? raw(`<div class="actions centered"><button class="secondary" data-action="loadOlderActivity" type="button">Load older</button></div>`) : raw("")}
          <p class="field-help">${visible.length} of ${history.length} available events shown.</p>
        </section>
        ${isTechnicalMode() ? raw(`
          <section class="panel full technical-panel"><h3>Protected workflow</h3>${protectedWorkflowSummary().__html}</section>
          <section class="panel full technical-panel"><h3>Workflow stages</h3>${stageList(snapshot.demo.stages).__html}</section>
          <section class="panel full technical-panel"><h3>Approval history</h3>${approvalList(snapshot.approvals.history).__html}</section>
        `) : raw("")}
      </div>`;
  },
  settings: () => {
    if ((!isTechnicalMode() || !developerSurfacesAllowed()) && settingsSection === "developer") settingsSection = "general";
    const general = raw(`<section class="user-section">
      <h3>General</h3>
      <p>Your Phil name is local display metadata. ENS is future Mainnet integration, unavailable in this Beta.</p>
      <label class="field">Phil name <input id="identity-display-name" type="text" maxlength="64" value="${escapeHtml(snapshot.identity?.label || "My Phil")}"></label>
      <div class="actions"><button class="secondary" data-action="renameIdentity" type="button" ${snapshot.identity ? "" : "disabled"}>Save name</button></div>
      <label class="field">Lock after <select id="setting-timeout"><option value="5" ${snapshot.settings.sessionTimeoutMinutes === 5 ? "selected" : ""}>5 minutes</option><option value="15" ${snapshot.settings.sessionTimeoutMinutes === 15 ? "selected" : ""}>15 minutes</option><option value="30" ${snapshot.settings.sessionTimeoutMinutes === 30 ? "selected" : ""}>30 minutes</option><option value="60" ${snapshot.settings.sessionTimeoutMinutes === 60 ? "selected" : ""}>1 hour</option></select></label>
      <label class="check-row"><input id="setting-autolock" type="checkbox" ${snapshot.settings.autoLockEnabled ? "checked" : ""}> Lock automatically when inactive</label>
      ${(isTechnicalMode() && developerSurfacesAllowed() ? raw(`<label class="check-row"><input id="setting-devmode" type="checkbox" ${snapshot.settings.developerModeVisible ? "checked" : ""}> Enable Developer tools</label><label class="field">Activity detail <select id="setting-audit"><option value="summary" ${snapshot.settings.auditDetailLevel === "summary" ? "selected" : ""}>Summary</option><option value="standard" ${snapshot.settings.auditDetailLevel === "standard" ? "selected" : ""}>Standard</option><option value="developer" ${snapshot.settings.auditDetailLevel === "developer" ? "selected" : ""}>Developer</option></select></label>`) : raw("")).__html}
      <div class="actions"><button class="primary" data-action="saveSettings" type="button">Save preferences</button><button class="secondary" data-action="replayIntro" type="button">Replay introduction</button><button class="secondary" data-action="resetPhilPosition" type="button">Reset Phil position</button></div>
      <details class="settings-phil-help"><summary>Phil help · Keyboard accessible</summary>${Object.entries(window.PhilHelper.topics).map(([topic, entries]) => `<section><h4>${escapeHtml(topic === "chain" ? "Ethereum" : topic === "audit" ? "Activity" : present.label(topic))}</h4>${entries.map(([question, answer]) => `<details><summary>${escapeHtml(question)}</summary><p>${escapeHtml(answer)}</p></details>`).join("")}</section>`).join("")}</details>
    </section>`);
    const identity = raw(`<section class="identity-hero compact">${philAvatar("large").__html}<div class="identity-hero-copy"><p class="section-label">Phil identity</p><h3>${escapeHtml(snapshot.identity?.label || "No identity selected")}</h3><p>Created and stored on this Mac. The artwork uses the local Philenator engine.</p></div></section>
      <section class="user-section"><h3>Identity</h3><p>Your Phil identity helps applications ask for permission without exposing protected local material.</p><label class="field">Phil name <input id="identity-display-name" type="text" maxlength="64" value="${escapeHtml(snapshot.identity?.label || "My Phil")}"></label><div class="actions"><button class="secondary" data-action="renameIdentity" type="button" ${snapshot.identity ? "" : "disabled"}>Save name</button></div><div class="setting-status"><span>Storage</span><strong>${snapshot.identity ? "On this Mac" : "Not created"}</strong></div><div class="setting-status"><span>Artwork</span><strong>Philenator · 13 trait groups</strong></div></section>
      ${isTechnicalMode() ? `<section class="panel full technical-panel"><h3>Identity details</h3>${kv([
        ["Identity root", snapshot.identity?.identityRootReference],
        ["Owner commitment", snapshot.identity?.ownerCommitment],
        ["Storage identifier", snapshot.identity?.identityId],
        ["Storage version", snapshot.identity?.storageVersion],
        ["Execution validator", snapshot.ethereum.executionOwnerAddress],
        ["Image source", snapshot.identity?.philPreview?.artworkSource || "philenator-local"],
        ["Artwork selection", snapshot.identity?.philPreview?.selectionId || "local-phil-00"],
        ["Mint status", snapshot.identity?.philPreview?.mintStatus || "not-minted"],
        ["Public token status", snapshot.identity?.philPreview?.publicToken || "none"]
      ]).__html}</section>` : ""}`);
    const trust = raw(`<section class="user-section"><h3>Trust</h3><p>Trusted devices and credentials are allowed to help confirm that it is really you.</p>${snapshot.trust.credentials.length ? snapshot.trust.credentials.map((credential) => `<div class="setting-status"><span>${credential.recoveryOnly ? "Same-Mac engineering fallback" : "This device"}</span><strong>${escapeHtml(present.label(credential.lifecycleStatus))}</strong></div>`).join("") : `<div class="empty-state"><strong>No credential details available</strong><p>Unlock your identity to view trusted local credentials.</p></div>`}<p class="field-help">A same-Mac engineering fallback is local test infrastructure. It is not the Beta recovery architecture, and recovery remains unavailable.</p></section>
      ${isTechnicalMode() ? `<section class="panel full technical-panel"><h3>Trust details</h3>${kv([
        ["Evidence class", snapshot.trust.evidenceClass],
        ["Last evaluation", snapshot.trust.lastEvaluation],
        ["Public metadata sufficient", snapshot.trust.publicMetadataSufficient],
        ["Credentials", snapshot.trust.credentials.length],
        ["Devices", snapshot.trust.devices.length]
      ]).__html}</section>` : ""}`);
    const recovery = raw(`${recoveryDeferredPanel().__html}
      ${isTechnicalMode() ? `<section class="panel full technical-panel"><h3>Recovery details</h3>${kv([
        ["Recovery authority", snapshot.ethereum.recoveryAuthorityAddress],
        ["Workflow state", snapshot.session.recoveryState],
        ["Custody type", snapshot.ethereum.recovery.custodyType],
        ["Rotation", snapshot.ethereum.recovery.rotationCapability],
        ["Same-device warning", snapshot.ethereum.recovery.sameDeviceWarning]
      ]).__html}${snapshot.settings.developerModeVisible ? `<p class="field-help">Future recovery engineering controls are intentionally absent from the ordinary Beta interface.</p>` : ""}</section>` : ""}`);
    const about = controlledBetaAboutPanel();
    const sections = {
      general,
      identity,
      trust,
      recovery,
      security: platformSecuritySettings(),
      about,
      developer: developerToolsPanel()
    };
    return html`
      <div class="settings-layout">
        ${pageIntro("Settings", "Manage your identity, security, and local preferences.")}
        ${settingsTabs()}
        <div class="settings-content">${sections[settingsSection] || general}</div>
        ${isTechnicalMode() && settingsSection !== "developer" ? technicalReleasePanel() : raw("")}
      </div>`;
  }
});

refresh().then(async () => {
  if (!snapshot.identity) {
    try {
      selectedPhilPreview = await philPreviewProvider.ensure(selectedPhilPreview);
    } catch {
      setNotice("warn", "Philenator unavailable", "PhilCore kept the 3D Phil preview because the local Philenator engine did not finish.");
    }
    renderView();
  }
}).catch((error) => {
  const diagnosticCode = error?.code || "PHILCORE_RENDERER_STARTUP_FAILED";
  console.error(`[${diagnosticCode}] PhilCore renderer startup blocked`);
  view.innerHTML = `<div class="panel full"><h3>Startup failed</h3><p>${escapeHtml(error.message)}</p><p class="muted">Diagnostic: ${escapeHtml(diagnosticCode)}</p></div>`;
});

// Read-only acceptance observation, available through the normal bridge.
// It creates no request and grants no authorization authority.
window.captureRoutineAcceptanceBaseline = async function captureRoutineAcceptanceBaseline() {
  const host = await window.philcore.routineAuthorization.baseline();
  return Object.freeze({...host,sourceCommit:snapshot?.release?.sourceCommit || "unavailable",sourceTree:snapshot?.release?.sourceTreeHash || "unavailable",
    presentationRequestId:routineAuthorizationUi.requestId || null,
    qrVisible:Boolean(routineAuthorizationUi.qrDataUrl),presentationState:routineAuthorizationUi.state || "idle"});
};
