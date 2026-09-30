// Applies the saved light/dark theme before first paint. Default: dark.
(function () {
  var t = "dark";
  try { t = localStorage.getItem("aegis-theme") || "dark"; } catch (e) { /* storage unavailable */ }
  document.documentElement.setAttribute("data-theme", t === "light" ? "light" : "dark");
})();
