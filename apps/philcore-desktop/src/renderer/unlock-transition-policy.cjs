(function exposeUnlockTransitionPolicy(root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.PhilCoreUnlockTransitionPolicy = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  "use strict";

  function identityCreated(result) {
    return Boolean(result?.identity);
  }

  function authenticationSucceeded(result) {
    return result?.status === "authenticated";
  }

  function vaultUnlockSucceeded(result) {
    return result?.status === "unlocked";
  }

  return Object.freeze({
    identityCreated,
    authenticationSucceeded,
    vaultUnlockSucceeded
  });
});
