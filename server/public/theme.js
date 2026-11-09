// Theme choice (system / light / dark) for every page. Classic script in <head>, no defer:
// data-theme is set before first paint, so the wrong theme never flashes. The choice is
// the only thing stored (localStorage "hort.theme"); every access is guarded.
(function () {
  var KEY = "hort.theme";
  var root = document.documentElement;

  function stored() {
    try {
      var v = localStorage.getItem(KEY);
      return v === "light" || v === "dark" ? v : "system";
    } catch (e) {
      return "system";
    }
  }

  function apply(choice) {
    if (choice === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", choice);
  }

  function save(choice) {
    try {
      if (choice === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, choice);
    } catch (e) {}
  }

  var current = stored();
  apply(current);

  function mount() {
    var nav = document.querySelector(".m-nav");
    if (!nav) return;
    var group = document.createElement("div");
    group.className = "theme-switch";
    group.setAttribute("role", "group");
    group.setAttribute("aria-label", "Theme");
    var buttons = ["system", "light", "dark"].map(function (choice) {
      var b = document.createElement("button");
      b.type = "button";
      b.textContent = choice;
      b.addEventListener("click", function () {
        current = choice;
        apply(choice);
        save(choice);
        render();
      });
      group.appendChild(b);
      return b;
    });
    function render() {
      buttons.forEach(function (b) {
        b.setAttribute("aria-pressed", String(b.textContent === current));
      });
    }
    render();
    nav.appendChild(group);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
