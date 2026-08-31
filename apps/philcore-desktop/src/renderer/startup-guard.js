(function installPhilCoreRendererStartupGuard(globalObject) {
  const diagnosticCode = "PHILCORE_PRELOAD_BRIDGE_UNAVAILABLE";

  function unavailable(missingPath) {
    const error = new Error(
      `[${diagnosticCode}] Electron preload initialization did not expose ${missingPath}. `
      + "Renderer startup is blocked. Inspect the Electron terminal log for the underlying preload error."
    );
    error.code = diagnosticCode;
    error.missingPath = missingPath;
    return error;
  }

  function requireBridge() {
    const bridge = globalObject.philcore;
    if (!bridge || typeof bridge !== "object") throw unavailable("window.philcore");
    if (!bridge.runtime || typeof bridge.runtime.getSnapshot !== "function") {
      throw unavailable("window.philcore.runtime.getSnapshot");
    }
    return bridge;
  }

  Object.defineProperty(globalObject, "PhilCoreRendererStartup", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({ diagnosticCode, requireBridge })
  });
}(window));
