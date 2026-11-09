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

  // One small icon per choice: [element, attributes]; class "fill" is a filled shape.
  var ICONS = {
    system: [["circle", { cx: 8, cy: 8, r: 6 }], ["path", { d: "M8 2a6 6 0 0 0 0 12z", class: "fill" }]],
    light: [["circle", { cx: 8, cy: 8, r: 2.8 }], ["path", { d: "M8 1.2v1.6M8 13.2v1.6M1.2 8h1.6M13.2 8h1.6M3.2 3.2l1.1 1.1M11.7 11.7l1.1 1.1M3.2 12.8l1.1-1.1M11.7 4.3l1.1-1.1" }]],
    dark: [["path", { d: "M13.5 9.6A5.8 5.8 0 1 1 6.4 2.5a4.6 4.6 0 0 0 7.1 7.1z" }]],
  };

  function icon(choice) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("aria-hidden", "true");
    ICONS[choice].forEach(function (part) {
      var el = document.createElementNS(ns, part[0]);
      Object.keys(part[1]).forEach(function (k) {
        el.setAttribute(k, String(part[1][k]));
      });
      svg.appendChild(el);
    });
    return svg;
  }

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
      b.value = choice;
      b.title = choice + " theme";
      b.setAttribute("aria-label", choice);
      b.appendChild(icon(choice));
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
        b.setAttribute("aria-pressed", String(b.value === current));
      });
    }
    render();
    nav.appendChild(group);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
