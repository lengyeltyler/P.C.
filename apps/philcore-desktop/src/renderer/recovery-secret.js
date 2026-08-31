(() => {
  "use strict";
  let activeSecret = "";
  const secret = document.getElementById("secret");
  const hide = document.getElementById("hide");
  const show = document.getElementById("show");
  const print = document.getElementById("print");
  const clear = document.getElementById("clear");

  function render() {
    secret.textContent = activeSecret || "Secret cleared.";
  }

  Object.defineProperty(window, "PhilCoreProtectedReveal", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: Object.freeze({
      show(value) {
        activeSecret = String(value);
        render();
      }
    })
  });

  hide.addEventListener("click", () => {
    secret.classList.add("hidden");
    hide.disabled = true;
    show.disabled = false;
  });
  show.addEventListener("click", () => {
    secret.classList.remove("hidden");
    hide.disabled = false;
    show.disabled = true;
  });
  print.addEventListener("click", () => window.print());
  clear.addEventListener("click", () => {
    activeSecret = "";
    render();
    window.close();
  });
  window.addEventListener("pagehide", () => {
    activeSecret = "";
    secret.textContent = "";
  });
})();
