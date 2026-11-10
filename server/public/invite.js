// Invite page: puts the invitation code from the link fragment into the init
// command. The fragment never reaches the server, and nothing here calls it.
(function () {
  function mount() {
    var cmd = document.getElementById("invite-cmd");
    var vault = document.getElementById("vault-link");
    vault.textContent = location.host + "/vault";
    var code = location.hash.slice(1);
    if (!/^[0-9a-f]{32}$/.test(code)) {
      cmd.textContent = "This link has no invitation code. Ask the person who invited you for the full link.";
      return;
    }
    var words = ["hort", "init", "--invite", code];
    // Another server than hort.pm needs its address on init.
    if (location.origin !== "https://hort.pm") words.push("--server", location.origin);
    var prompt = document.createElement("span");
    prompt.className = "t-p";
    prompt.textContent = "$";
    cmd.append(prompt);
    words.forEach(function (w) {
      var word = document.createElement("span");
      word.textContent = w;
      cmd.append(" ", word);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", mount);
  else mount();
})();
