// Landing page: one install terminal with a tab per OS. The visitor's OS is
// preselected (iPhone and iPad count as macOS); arrow keys move between tabs.
(function () {
  function detect() {
    var ua = navigator.userAgent;
    if (/Windows/.test(ua)) return "os-windows";
    if (/Linux/.test(ua) && !/Android/.test(ua)) return "os-linux";
    return "os-macos";
  }

  function mount() {
    var tabs = Array.prototype.slice.call(document.querySelectorAll("#install-term [role=tab]"));
    if (!tabs.length) return;
    function select(tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      });
      if (focus) tab.focus();
    }
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function () {
        select(t, false);
      });
      t.addEventListener("keydown", function (e) {
        var step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
        if (!step) return;
        e.preventDefault();
        select(tabs[(i + step + tabs.length) % tabs.length], true);
      });
    });
    select(document.getElementById(detect()), false);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
