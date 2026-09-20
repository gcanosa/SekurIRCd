// SekurIRCd site: shared header/footer/docs nav, theme toggle, copy buttons, changelog.
(function () {
  var root = document.body.dataset.root || "./";
  var page = document.body.dataset.page || "";
  var REPO = "https://github.com/gcanosa/SekurIRCd";
  var DOCS = [
    ["install", "Install", "docs/install.html"],
    ["configuration", "Configuration", "docs/configuration.html"],
    ["commands", "Commands & modes", "docs/commands.html"],
    ["protection", "Abuse protection", "docs/protection.html"],
    ["ircv3", "IRCv3 & SASL", "docs/ircv3.html"],
    ["chanserv", "ChanServ", "docs/chanserv.html"]
  ];
  var cur = function (k) { return page === k ? ' aria-current="page"' : ""; };

  var header = document.getElementById("site-header");
  if (header) {
    header.className = "site-header";
    header.innerHTML =
      '<div class="wrap"><a class="brand" href="' + root + '" aria-label="SekurIRCd home">' +
      '<img class="logo-dark" src="' + root + 'img/logo-dark.png" alt="SekurIRCd">' +
      '<img class="logo-light" src="' + root + 'img/logo-light.png" alt="SekurIRCd"></a>' +
      '<nav aria-label="Main"><a href="' + root + 'docs/"' + cur("docs") + '>Docs</a>' +
      '<a href="' + root + 'changelog.html"' + cur("changelog") + '>Changelog</a>' +
      '<a href="' + REPO + '">GitHub</a>' +
      '<button class="theme-btn" id="theme" type="button"></button></nav></div>';
  }

  var footer = document.getElementById("site-footer");
  if (footer) {
    footer.className = "site-footer";
    footer.innerHTML =
      '<div class="wrap"><span>SekurIRCd &middot; MIT licensed &middot; &copy; 2026 Gerardo Canosa</span>' +
      '<span><a href="' + REPO + '">Source</a> &middot; <a href="' + REPO + '/issues">Issues</a> &middot; ' +
      '<a href="' + REPO + '/blob/main/LICENSE">License</a></span></div>';
  }

  var side = document.getElementById("docs-nav");
  if (side) {
    side.innerHTML = "<h4>Documentation</h4><div>" + DOCS.map(function (d) {
      return '<a href="' + root + d[2] + '"' + cur(d[0]) + ">" + d[1] + "</a>";
    }).join("") + "</div>";
  }

  // theme toggle (head script already set data-theme before paint)
  var btn = document.getElementById("theme");
  var html = document.documentElement;
  function label() { btn.textContent = html.dataset.theme === "dark" ? "[light]" : "[dark]"; btn.setAttribute("aria-label", "Switch to " + (html.dataset.theme === "dark" ? "light" : "dark") + " theme"); }
  if (btn) {
    label();
    btn.addEventListener("click", function () {
      html.dataset.theme = html.dataset.theme === "dark" ? "light" : "dark";
      try { localStorage.setItem("theme", html.dataset.theme); } catch (e) {}
      label();
    });
  }

  // copy buttons on <pre>
  document.querySelectorAll("pre").forEach(function (pre) {
    if (pre.closest(".nocopy") || !navigator.clipboard) return;
    var b = document.createElement("button");
    b.className = "copy"; b.type = "button"; b.textContent = "copy";
    b.addEventListener("click", function () {
      var clone = pre.cloneNode(true);
      clone.querySelectorAll(".copy,.hl-p").forEach(function (n) { n.remove(); });
      navigator.clipboard.writeText(clone.textContent.replace(/\s+$/, "")).then(function () {
        b.textContent = "copied"; setTimeout(function () { b.textContent = "copy"; }, 1500);
      });
    });
    pre.appendChild(b);
  });

  // changelog.json (hand-curated) → version badge + changelog page
  var vers = document.querySelectorAll("[data-version]");
  var list = document.getElementById("changelog");
  if (vers.length || list) {
    fetch(root + "changelog.json").then(function (r) { return r.json(); }).then(function (rels) {
      if (!rels.length) return;
      var latest = rels.filter(function (r) { return r.tag[0] === "v"; })[0];
      if (latest) vers.forEach(function (v) { v.textContent = latest.tag; });
      if (!list) return;
      list.textContent = "";
      rels.forEach(function (r) {
        var s = document.createElement("section"); s.className = "rel";
        var h = document.createElement("h3"); h.textContent = r.tag;
        var t = document.createElement("time"); t.textContent = r.date;
        var ul = document.createElement("ul");
        r.changes.forEach(function (c) { var li = document.createElement("li"); li.textContent = c; ul.appendChild(li); });
        s.append(h, t, ul); list.appendChild(s);
      });
    }).catch(function () {
      if (list) list.innerHTML = '<p>Could not load the changelog. See <a href="' + REPO + '/releases">GitHub releases</a>.</p>';
    });
  }
})();
