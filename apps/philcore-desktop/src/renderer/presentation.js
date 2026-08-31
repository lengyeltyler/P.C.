(function () {
  const EXACT = Object.freeze({
    local_alpha: "Local testing mode",
    public_testnet_disabled: "Public blockchain connections are off",
    mainnet_disabled: "Mainnet is off",
    locked: "Locked",
    unlocked: "Unlocked",
    none: "None",
    desktop_local_encrypted_identity: "Stored securely on this Mac",
    main_process_file_backend_encrypted_registry: "Encrypted local storage",
    local_alpha_passphrase_scrypt_verified: "Passphrase verified locally",
    platform_keychain_unwrap_verified: "Unlocked with this Mac",
    opened_unlocked: "Identity unlocked",
    available_in_protected_boundary: "Available while unlocked",
    desktop_local_alpha_main_process: "This Mac",
    local_identity_created: "Local identity created",
    not_integrated: "Not connected yet",
    not_deployed: "Not deployed",
    prohibited: "Not allowed",
    available: "Ready",
    not_created: "Not set up",
    not_configured: "Not configured",
    locked_or_not_created: "Locked or not set up",
    configured: "Configured",
    configured_locked: "Configured, locked",
    incomplete: "Incomplete",
    device_vault_separate_ecdsa_key: "Separate local recovery key on this Mac",
    local_alpha_supported_not_beta_approved: "Available for local testing only",
    device_vault_ecdsa_local_alpha: "Local signing key on this Mac",
    device_vault_ecdsa_recovery_local_alpha: "Local recovery key on this Mac",
    active: "Active",
    recovery_only: "Recovery only",
    counterfactual_not_deployed: "Local test account ready",
    deployed_local_fixture: "Local test account ready",
    consumed_local_fixture: "Used in local test",
    available_or_pending_local_fixture: "Available for local test",
    verified_local_fixture: "Completed in local test",
    local_fixture_user_operation_included: "Local test operation included",
    pending_signature: "Waiting for approval",
    generated_real_local: "Generated on this Mac",
    verified_real_local: "Verified on this Mac",
    not_started: "Not started",
    local_fixture_fact_availability_public_route_not_executed: "Verified fact installed only in local test state",
    not_notarized: "Not notarized",
    not_accepted_or_not_checked: "Not checked",
    custom_macos_packager: "PhilCore local packager",
    not_available_or_not_checked: "Not checked",
    signed: "Signed",
    unsigned: "Unsigned",
    blocked: "Blocked",
    missing: "Missing",
    approval_consumed: "Approval used successfully",
    presentation_created: "Approval prepared",
    approved: "Approved",
    deny: "Denied",
    cancel: "Cancelled",
    cancelled: "Cancelled",
    expired: "Expired",
    completed: "Completed",
    failed: "Failed",
    interrupted: "Interrupted",
    local_authorization_execution: "Local sensitive action",
    user_operation_signing: "Sign local test operation",
    platform_unlock_enrollment: "Enable unlock with this Mac",
    platform_unlock_disablement: "Disable unlock with this Mac",
    local_identity_reset: "Reset local identity",
    recovery_request: "Request recovery",
    recovery_cancel: "Cancel recovery",
    recovery_complete: "Complete recovery",
    execution_owner_rotation: "Rotate local signing key",
    recovery_authority_rotation: "Rotate recovery key",
    validator_signing_session: "Local signing session",
    recovery_signing_session: "Recovery signing session",
    stwo_unlock_keccak_v1: "Local security proof"
  });

  const AUDIT_TITLES = Object.freeze({
    "identity:create_local": "Identity created",
    "identity:open_local": "Identity opened",
    "session:authenticate_local": "Passphrase accepted",
    "session:unlock_vault": "Identity unlocked",
    "session:lock": "Identity locked",
    "vault:unlock_device_vault": "Identity unlocked",
    "approval:presentation_created": "Approval requested",
    "approval:presentation_expired": "Approval expired",
    "approval:approve": "Approval granted",
    "approval:deny": "Approval denied",
    "approval:cancel": "Approval cancelled",
    "approval:approval_approved": "Action approved",
    "approval:approval_deny": "Action rejected",
    "approval:approval_cancel": "Action cancelled",
    "approval:action_approved": "Action approved",
    "approval:local_signing_approved": "Local signing approved",
    "authorization:local_workflow": "Protected action completed",
    "authorization:protected_action_preflight": "Protected action needs setup",
    "authorization:fresh_authentication_stopped": "User-presence check stopped",
    "authorization:real_local_workflow_cancelled": "Protected action cancelled",
    "authorization:real_local_workflow_timed_out": "Protected action timed out",
    "authorization:protected_action_interrupted": "Protected action interrupted",
    "authorization:protected_action_requested": "Protected action requested",
    "authorization:capability_activated": "Permission activated",
    "authorization:authorization_candidate_created": "Protected action prepared",
    "authorization:authorization_package_created": "Security request prepared",
    "authorization:local_ethereum_execution_prepared": "Local test prepared",
    "authorization:local_signing_approval_requested": "Your confirmation requested",
    "authorization:local_ethereum_test_action_submitted": "Local test started",
    "authorization:local_ethereum_test_action_completed": "Local test completed",
    "authorization:local_ethereum_test_action_failed": "Local test failed",
    "proof:generation": "Security check created",
    "proof:verification": "Security check verified",
    "proof:local_security_proof_generated": "Security check created",
    "proof:local_security_proof_verified": "Security check verified",
    "proof:local_fact_fixture_available": "Local verification prepared",
    "trust:trust_check_completed": "Identity check completed",
    "policy:policy_approved": "Request rules approved",
    "policy:policy_denied": "Request rules denied",
    "vault:device_vault_signature_created": "Local signing key used",
    "settings:update_local_preferences": "Settings updated",
    "registry:registry-created": "Encrypted identity record created",
    "registry:registry-saved": "Encrypted identity record updated",
    "recovery:request": "Recovery request recorded",
    "recovery:cancel": "Recovery cancellation recorded",
    "recovery:complete": "Recovery completion recorded"
  });

  function normalize(value) {
    return String(value ?? "")
      .replaceAll("-", "_")
      .replaceAll(" ", "_")
      .trim();
  }

  function titleCase(value) {
    const normalized = normalize(value);
    if (!normalized) return "Not available";
    return normalized
      .split("_")
      .filter(Boolean)
      .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
      .join(" ");
  }

  function label(value) {
    const normalized = normalize(value);
    return EXACT[normalized] || titleCase(value);
  }

  function short(value, size = 10) {
    const text = String(value ?? "");
    if (!text) return "Not available";
    if (text.length <= size * 2 + 3) return text;
    return `${text.slice(0, size)}...${text.slice(-size)}`;
  }

  function yesNo(value) {
    return value ? "Yes" : "No";
  }

  function mode(snapshot) {
    if (snapshot?.controlledBeta?.completed) return "Controlled Sepolia Beta";
    if (snapshot?.app?.localOnly) return "Local demonstration mode";
    return label(snapshot?.app?.mode);
  }

  function lock(snapshot) {
    const state = snapshot?.session?.lockState;
    const vault = snapshot?.session?.vaultState;
    if (state === "unlocked" && vault === "unlocked") return "Unlocked";
    if (snapshot?.identity) return "Locked";
    return "No identity";
  }

  function gate(snapshot) {
    if (snapshot?.controlledBeta?.completed) return "Beta verified";
    if (snapshot?.securityGate?.baseSepoliaBeta === "blocked") return "Beta blocked";
    return label(snapshot?.securityGate?.baseSepoliaBeta);
  }

  function auditTitle(event) {
    const key = `${event?.category || ""}:${event?.action || ""}`;
    return AUDIT_TITLES[key] || label(event?.action || event?.category);
  }

  function auditDescription(event, includeEvidence = false) {
    const result = label(event?.result);
    if (!includeEvidence) return `${result}.`;
    return `${result}. Evidence: ${label(event?.evidenceClass)}.`;
  }

  function approvalTitle(event) {
    return label(event?.actionName || event?.kind || "approval");
  }

  function statusTone(value) {
    const normalized = normalize(value);
    if (["unlocked", "available", "active", "completed", "approved", "verified_local_fixture", "consumed_local_fixture", "signed", "notarized"].includes(normalized)) return "ok";
    if (["blocked", "missing", "failed", "deny", "cancelled", "expired", "not_configured", "incomplete"].includes(normalized)) return "warn";
    if (["locked", "pending_signature", "not_started", "not_deployed", "counterfactual_not_deployed"].includes(normalized)) return "info";
    return "neutral";
  }

  window.PhilCorePresentation = Object.freeze({
    label,
    short,
    yesNo,
    mode,
    lock,
    gate,
    auditTitle,
    auditDescription,
    approvalTitle,
    statusTone
  });
})();
