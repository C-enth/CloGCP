// Applies the saved Light / Dark / System theme before the first paint (no flash).
// Nothing saved means Dark (pure black), the default.
// Loaded as a classic same-origin script from index.html; the CSP allows only 'self'.
(function () {
  var KEY = "closec-theme";
  var root = document.documentElement;
  var media = window.matchMedia
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : null;
  function preference() {
    try {
      var value = window.localStorage.getItem(KEY);
      return value === "light" || value === "dark" || value === "system"
        ? value
        : "dark";
    } catch (e) {
      return "dark";
    }
  }
  function apply(choice) {
    var dark =
      choice === "dark" || (choice === "system" && !!media && media.matches);
    root.setAttribute("data-theme", dark ? "dark" : "light");
    root.setAttribute("data-theme-preference", choice);
  }
  apply(preference());
  if (media) {
    var follow = function () {
      if (root.getAttribute("data-theme-preference") === "system")
        apply("system");
    };
    if (media.addEventListener) media.addEventListener("change", follow);
    else if (media.addListener) media.addListener(follow);
  }
})();
