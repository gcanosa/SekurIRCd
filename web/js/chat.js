// SekurNet web chat: a small IRC-over-WebSocket client locked to ONE network.
// The endpoint is a constant on purpose: there is no host field and no URL parameter that can change it.
// Single source for both sites: gcanosa.github.io/SekurIRCd/chat.html and www.sekurnet.org/chat/ (build.py copies it).
// A page only needs <div id="sekurchat"></div>, css/chat.css and this script; the markup below is built here.
(function () {
  var root = document.getElementById("sekurchat");
  if (!root) return;
  root.innerHTML = // static markup only; nothing from the network or the user goes through innerHTML
    '<form id="connect" class="chat-form">' +
    '<p>Join the <strong>SekurNet</strong> IRC network from your browser. Pick a nickname and one or more channels.</p>' +
    '<label>Nickname <input id="nick" maxlength="30" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" required></label>' +
    '<label>Channels <input id="chan" maxlength="200" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" required></label>' +
    '<details id="login" class="chat-login"><summary>Log in to your account (optional)</summary>' +
    '<label>Account <input id="acct" maxlength="30" autocomplete="username" autocapitalize="off" autocorrect="off" spellcheck="false"></label>' +
    '<label>Password <input id="pass" type="password" maxlength="200" autocomplete="current-password"></label>' +
    '<p class="hint">Logs in with SASL while connecting. The password goes only to irc.sekurnet.org, over TLS, and is never stored by this page. ' +
    'No account yet? Connect, then type <code>/msg NickServ REGISTER yourpassword</code>.</p></details>' +
    '<button class="btn primary" type="submit">Connect</button>' +
    '<p id="conn-err" class="err" role="alert"></p>' +
    '<p class="hint">Separate channels with spaces or commas. Prefer a desktop client? Connect to <code>irc.sekurnet.org</code> port 6697 (TLS) or 6667 (plain).</p>' +
    '</form>' +
    '<section id="chat" class="chat" hidden>' +
    '<div class="chat-bar"><div id="tabs" class="chat-tabs" role="tablist"></div>' +
    '<button id="users-btn" class="tool users-btn" type="button" aria-pressed="false" aria-label="Show users">users</button>' +
    '<button id="quit-btn" class="tool" type="button" aria-label="Leave the chat">quit</button></div>' +
    '<div id="topic" class="chat-topic"></div>' +
    '<div class="chat-body"><div id="log" class="chat-log" aria-live="polite"></div>' +
    '<aside class="chat-users closed" aria-label="Users"><div id="users"></div></aside></div>' +
    '<form id="send" class="chat-send">' +
    '<input id="input" maxlength="400" autocomplete="off" autocapitalize="off" autocorrect="off" enterkeyhint="send" aria-label="Message">' +
    '<button class="btn" type="submit">Send</button></form>' +
    '</section>';

  var WS_URL = "wss://irc.sekurnet.org:12155"; // [websocket] port with tls = true in sekurircd.toml
  var DEFAULT_CHAN = "#SekurNet";
  var NICK_RE = /^[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]{0,29}$/;
  var CHAN_RE = /^[#&][^\s,\x07]{1,49}$/;
  var MAX_CHANS = 10;
  // IRCv3 capabilities we use when the server offers them ("sasl" is added only when logging in).
  var WANT_CAPS = ["server-time", "message-tags", "batch", "draft/chathistory", "echo-message", "multi-prefix", "userhost-in-names", "draft/read-marker"];
  var HISTORY_ON_JOIN = 50; // messages shown when you join; a reconnect fetches everything missed (server max 100)

  var $ = function (id) { return document.getElementById(id); };
  var form = $("connect"), app = $("chat"), nickIn = $("nick"), chanIn = $("chan"), err = $("conn-err");
  var acctIn = $("acct"), passIn = $("pass");
  var tabs = $("tabs"), log = $("log"), users = $("users"), topic = $("topic"), input = $("input");

  // Highest prefix first (the server's PREFIX=(qaohv)~&@%+); "" is a regular user.
  var GROUPS = [{ prefix: "~", name: "Owners", cls: "owner" }, { prefix: "&", name: "Admins", cls: "admin" }, { prefix: "@", name: "Operators", cls: "op" },
                { prefix: "%", name: "Half-ops", cls: "halfop" }, { prefix: "+", name: "Voiced", cls: "voice" }, { prefix: "", name: "Users", cls: "user" }];
  var AWAY_AFTER = 30 * 60 * 1000; // idle time before auto-away
  var CLIENT = "SekurNet WebChat", CLIENT_V = "2.0";
  var BAR = " \x0314│\x0f ", SITE = "https://www.sekurnet.org/chat/";
  var QUIT_MSG = "\x02" + CLIENT + "\x02 v" + CLIENT_V + BAR + SITE; // the default quit message, same branding as CTCP VERSION
  var ws, nick, wantChan, registered, tries = 0, closing = false, timer, away = false, awayTimer;
  var bufs = {}, active = "*";
  var avail = {}, caps = {}, auth = null, sasl = null, account = "", batches = {};
  var unseen = 0, baseTitle = document.title, sent = [], spos = 0;
  var hosts = {}, ignored = {}; // hosts: nick -> host, for ban masks. ignored: kept in this browser only
  try { JSON.parse(localStorage.getItem("chat-ignore") || "[]").forEach(function (n) { ignored[n] = 1; }); } catch (e) {}
  var coarse = matchMedia("(pointer: coarse)").matches; // touch screens: a tap opens the nick menu (no right click there)

  var usersPane = users.parentNode, usersBtn = $("users-btn");
  function guest() { return "Guest" + Math.floor(1000 + Math.random() * 9000); }
  // A fresh nickname on every load, so a reload never retries a nick that is still held by the previous session.
  var guestNick = nickIn.value = guest();
  try { chanIn.value = localStorage.getItem("chat-chan") || ""; acctIn.value = localStorage.getItem("chat-acct") || ""; } catch (e) {}
  if (!chanIn.value) chanIn.value = DEFAULT_CHAN;
  if (acctIn.value) $("login").open = true;

  // IRC formatting: ^B bold, ^I italic (0x1d), ^_ underline, ^S strike (0x1e), ^R reverse, ^K color fg[,bg], ^O reset.
  // Built from text nodes, styled spans and http(s) links only, never innerHTML, so message text stays inert.
  var COLORS = ["#ffffff", "#000000", "#00007f", "#009300", "#ff0000", "#7f0000", "#9c009c", "#fc7f00",
                "#ffff00", "#00fc00", "#009393", "#00ffff", "#0000fc", "#ff00ff", "#7f7f7f", "#d2d2d2"];
  var URL_RE = /\bhttps?:\/\/[^\s<>"]*[^\s<>".,;:!?)\]}'*]/gi; // trailing punctuation stays outside the link
  function linkify(parent, s) {
    var last = 0, m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(s))) {
      if (m.index > last) parent.appendChild(document.createTextNode(s.slice(last, m.index)));
      var u = m[0]; // a ")" that closes a "(" inside the URL belongs to it: en.wikipedia.org/wiki/Foo_(bar)
      if (s[m.index + u.length] === ")" && u.split("(").length > u.split(")").length) URL_RE.lastIndex = m.index + (u += ")").length;
      var a = document.createElement("a"); // the regex only ever matches http:// or https://, so no javascript: links
      a.href = u; a.textContent = u; a.target = "_blank"; a.rel = "noopener noreferrer nofollow";
      parent.appendChild(a); last = m.index + u.length;
    }
    if (last < s.length) parent.appendChild(document.createTextNode(s.slice(last)));
  }
  function fmt(text) {
    var frag = document.createDocumentFragment(), st = {}, run = "", i = 0, m;
    function flush() {
      if (!run) return;
      var fg = st.fg, bg = st.bg;
      if (st.rev) { var t = fg; fg = bg || "var(--bg)"; bg = t || "var(--fg)"; }
      if (!(st.b || st.i || st.u || st.s || fg || bg)) linkify(frag, run);
      else {
        var e = document.createElement("span");
        if (st.b) e.style.fontWeight = "bold";
        if (st.i) e.style.fontStyle = "italic";
        if (st.u || st.s) e.style.textDecoration = (st.u ? "underline " : "") + (st.s ? "line-through" : "");
        if (fg && !bg) { e.className = "fgo"; e.style.setProperty("--c", fg); } // color alone: CSS darkens it in the light theme
        else if (fg) e.style.color = fg;
        if (bg) e.style.backgroundColor = bg;
        linkify(e, run); frag.appendChild(e);
      }
      run = "";
    }
    while (i < text.length) {
      var ch = text[i++];
      if (ch === "\x02") { flush(); st.b = !st.b; }
      else if (ch === "\x1d") { flush(); st.i = !st.i; }
      else if (ch === "\x1f") { flush(); st.u = !st.u; }
      else if (ch === "\x1e") { flush(); st.s = !st.s; }
      else if (ch === "\x16") { flush(); st.rev = !st.rev; }
      else if (ch === "\x0f") { flush(); st = {}; }
      else if (ch === "\x11") { /* monospace: the log already is */ }
      else if (ch === "\x03") {
        flush();
        m = /^(\d{1,2})(?:,(\d{1,2}))?/.exec(text.slice(i));
        if (!m) { st.fg = st.bg = null; continue; } // a bare ^K resets colors
        i += m[0].length;
        st.fg = COLORS[+m[1]] || (+m[1] === 99 ? null : st.fg); // 16-98 (extended palette) keep the current color
        if (m[2] !== undefined) st.bg = COLORS[+m[2]] || (+m[2] === 99 ? null : st.bg);
      } else run += ch;
    }
    flush();
    return frag;
  }

  function key(n) { return n.toLowerCase(); }
  function isChan(n) { return n[0] === "#" || n[0] === "&"; }
  function buf(name) {
    var k = key(name);
    if (!bufs[k]) { bufs[k] = { name: name, lines: [], users: {}, topic: "", unread: false, ids: {}, last: "" }; draw(); }
    return bufs[k];
  }
  // meta (optional): time = the server-time tag, id = msgid (a message already shown is skipped), hist = from CHATHISTORY,
  // from + kind ("msg", "act", "notice") = a message from someone: the nick is drawn in its own color.
  function say(name, text, cls, meta) {
    meta = meta || {};
    var b = buf(name);
    if (meta.id) { if (b.ids[meta.id]) return; b.ids[meta.id] = 1; }
    if (meta.time) { // seen live, with nothing unread above it: keep the "new messages" divider from jumping down to it
      if (key(name) === key(active) && !document.hidden && (!b.mark || b.mark >= b.last)) b.mark = meta.time;
      if (meta.time > b.last) b.last = meta.time;
    }
    var d = meta.time ? new Date(meta.time) : new Date(), t = d.toTimeString().slice(0, 5);
    if (d.toDateString() !== new Date().toDateString()) t = ("0" + (d.getMonth() + 1)).slice(-2) + "-" + ("0" + d.getDate()).slice(-2) + " " + t; // older than today: show the date
    b.lines.push({ t: t, text: text, cls: cls || "", id: meta.id, time: meta.time || "", from: meta.from, kind: meta.kind });
    if (b.lines.length > 500) { var old = b.lines.shift(); if (old.id) delete b.ids[old.id]; }
    if (key(name) === key(active)) {
      addLine(b.lines[b.lines.length - 1]); if (meta.time) markSoon();
      while (log.childElementCount > 500) log.removeChild(log.firstElementChild); // the shown log stays as short as the buffer
    }
    else if (!b.unread) { b.unread = true; drawTabs(); }
    if (document.hidden && !meta.hist && /\b(hl|msg)\b/.test(cls || "")) { unseen++; document.title = "(" + unseen + ") " + baseTitle; }
  }
  // a small glyph before each kind of event; the first class that matches wins, so specific kinds come before "evt"
  var EVT_ICONS = [["join", "\u2192"], ["part", "\u2190"], ["quit", "\u21d0"], ["kick", "\u2715"], ["nick", "\u21bb"], ["mode", "\u00b1"],
               ["topic", "\u270e"], ["invite", "\u2709"], ["away", "\u263e"], ["ctcp", "\u2699"], ["whois", "\u00bb"],
               ["notice", "\u25b8"], ["err", "!"], ["evt", "\u2022"]];
  function addLine(l) {
    var stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
    var d = document.createElement("div"); d.className = "ln " + l.cls;
    var s = document.createElement("span"); s.className = "ts"; s.textContent = l.t + " ";
    d.appendChild(s);
    var ic = EVT_ICONS.filter(function (i) { return d.classList.contains(i[0]); })[0];
    if (ic) { var g = document.createElement("span"); g.className = "ic"; g.textContent = ic[1] + "\uFE0E"; d.appendChild(g); } // FE0E: text glyph, never an emoji
    if (l.from) { // <nick> text, * nick text, -nick- text
      var nk = document.createElement("span"); nk.className = "nk"; nk.textContent = l.from; nk.style.setProperty("--h", hue(l.from));
      d.append(l.kind === "act" ? "* " : l.kind === "notice" ? "-" : "<", nk, l.kind === "act" ? " " : l.kind === "notice" ? "- " : "> ");
    }
    d.appendChild(fmt(l.text)); log.appendChild(d);
    if (stick) log.scrollTop = log.scrollHeight;
  }
  function hue(n) { // a stable color per nickname: the same nick always gets the same hue
    for (var h = 0, i = 0, k = key(n); i < k.length; i++) h = (h * 31 + k.charCodeAt(i)) >>> 0;
    return h % 360;
  }
  function nickAt(e) { var n = e.target.classList && e.target.classList.contains("nk") && e.target.textContent; return n && n.indexOf(".") < 0 ? n : ""; }
  log.addEventListener("click", function (e) { // a nick in the log: click to message them, tap (phones) for the menu
    var n = nickAt(e);
    if (!n) return;
    if (coarse) openMenu(n, e.clientX, e.clientY); else if (key(n) !== key(nick)) { query(n); input.focus(); }
  });
  // External links: confirm first, showing the real host (punycode, so a look-alike domain shows as xn--...).
  // Plain clicks only: ctrl/cmd/shift/middle click and "open in new tab" are a deliberate choice and go straight through.
  var linkDlg = document.createElement("dialog"), linkUrl = "", linkOk = false;
  linkDlg.className = "chat-dlg";
  linkDlg.innerHTML = '<form method="dialog"><h3>Open external link?</h3>' + // static markup; the URL goes in with textContent below
    '<p>This link was posted in the chat and leaves SekurNet. Check where it goes before you continue.</p>' +
    '<p class="host"></p><p class="puny" hidden>This address uses international characters, which can imitate another site.</p>' +
    '<p class="url"></p><label><input type="checkbox"> Don\'t ask again this session</label>' +
    '<div class="act"><button class="btn" value="no">Cancel</button><button class="btn primary" value="open">Open link</button></div></form>';
  app.appendChild(linkDlg);
  try { linkOk = sessionStorage.getItem("chat-links") === "ok"; } catch (e) {}
  linkDlg.addEventListener("close", function () {
    if (linkDlg.returnValue !== "open") return;
    if (linkDlg.querySelector("input").checked) { linkOk = true; try { sessionStorage.setItem("chat-links", "ok"); } catch (e) {} }
    window.open(linkUrl, "_blank", "noopener,noreferrer");
  });
  log.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest("a[href]"), u;
    if (!a || linkOk || e.button || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    try { u = new URL(a.href); } catch (x) { return; }
    if (/(^|\.)sekurnet\.org$/i.test(u.hostname)) return; // our own sites open without asking
    e.preventDefault();
    linkUrl = u.href;
    linkDlg.querySelector(".host").textContent = u.hostname;
    linkDlg.querySelector(".puny").hidden = !/(^|\.)xn--/i.test(u.hostname);
    linkDlg.querySelector(".url").textContent = u.href;
    linkDlg.querySelector("input").checked = false; linkDlg.returnValue = "";
    linkDlg.showModal();
  });
  log.addEventListener("contextmenu", function (e) { var n = nickAt(e); if (n) { e.preventDefault(); openMenu(n, e.clientX, e.clientY); } });
  function drawTabs() {
    tabs.textContent = "";
    Object.keys(bufs).forEach(function (k) {
      var b = bufs[k], a = document.createElement("button");
      a.type = "button"; a.textContent = b.name === "*" ? "status" : b.name;
      if (k === key(active)) { a.setAttribute("aria-current", "true"); setTimeout(function () { a.scrollIntoView({ block: "nearest", inline: "nearest" }); }); }
      if (b.unread) a.className = "unread";
      a.onclick = function () { active = b.name; b.unread = false; b.mark = b.read; draw(); markSoon(); input.focus(); };
      if (k !== "*") { // × closes the tab, same as /close
        var x = document.createElement("span"); x.className = "x"; x.textContent = "\u00D7"; x.title = "Close"; x.setAttribute("aria-label", "Close " + b.name);
        x.onclick = function (e) { e.stopPropagation(); closeBuf(b.name); };
        a.appendChild(x);
      }
      tabs.appendChild(a);
    });
  }
  function closeBuf(name) {
    if (isChan(name)) return send("PART " + name); // the PART echo closes the tab
    delete bufs[key(name)]; if (key(active) === key(name)) active = "*"; draw();
  }
  function draw() {
    var b = buf(active);
    drawTabs();
    log.textContent = "";
    var newAt = b.mark ? b.lines.findIndex(function (l) { return l.from && l.time > b.mark && l.cls.indexOf("me") < 0; }) : -1;
    b.lines.forEach(function (l, i) {
      if (l.from && ignored[key(l.from)] && l.cls.indexOf("me") < 0) return; // ignoring someone also hides what they said before
      if (i === newAt) { var nd = document.createElement("div"); nd.className = "ln new"; nd.textContent = "── new messages ──"; log.appendChild(nd); }
      addLine(l);
    });
    topic.textContent = ""; topic.title = b.topicBy || ""; topic.appendChild(fmt(b.topic || (b.name === "*" ? "SekurNet web chat" + (account ? " · logged in as " + account : "") : "")));
    users.textContent = "";
    GROUPS.forEach(function (g) {
      var names = Object.keys(b.users).filter(function (n) { return b.users[n] === g.prefix; })
        .sort(function (x, y) { return x.toLowerCase() < y.toLowerCase() ? -1 : 1; });
      if (!names.length) return;
      var h = document.createElement("div"); h.className = "grp g-" + g.cls; h.textContent = g.name + " (" + names.length + ")"; users.appendChild(h);
      names.forEach(function (n) {
        var d = document.createElement("div"); d.className = "g-" + g.cls + (ignored[key(n)] ? " ign" : ""); d.textContent = g.prefix + n;
        d.title = (ignored[key(n)] ? "Ignored. " : "") + (coarse ? "Tap for options" : "Click to message, right click for options");
        d.onclick = function (e) { if (coarse) return openMenu(n, e.clientX, e.clientY); if (key(n) !== key(nick)) { query(n); showUsers(false); input.focus(); } };
        d.oncontextmenu = function (e) { e.preventDefault(); openMenu(n, e.clientX, e.clientY); };
        users.appendChild(d);
      });
    });
    usersPane.hidden = usersBtn.hidden = !isChan(b.name);
    toBottom(); // last: the topic bar and the user list above change the log's size
  }
  function toBottom() { // the newest line, or the first unread one when there is a long backlog
    function go() {
      log.scrollTop = log.scrollHeight;
      var nl = log.querySelector(".new");
      if (nl && nl.offsetTop < log.scrollTop) log.scrollTop = nl.offsetTop - 8;
    }
    go(); requestAnimationFrame(go); // again after the browser has laid the tab out
  }
  // --- nick menu: right click (or tap on phones) a nick in the user list or the log ---
  // Small outline icons (24x24, drawn in the text color).
  var ICON_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">%</svg>';
  var ICONS = {
    msg: '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    at: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8"/>',
    info: '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>',
    client: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>',
    ping: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    eyeoff: '<path d="M17.94 17.94A10 10 0 0 1 12 20c-7 0-11-8-11-8a18 18 0 0 1 5.06-5.94M9.9 4.24A9 9 0 0 1 12 4c7 0 11 8 11 8a18 18 0 0 1-2.16 3.19M1 1l22 22"/>',
    eye: '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    mic: '<path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2M12 19v4"/>',
    kick: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    ban: '<circle cx="12" cy="12" r="10"/><path d="M4.93 4.93l14.14 14.14"/>',
    kickban: '<path d="M7.86 2h8.28L22 7.86v8.28L16.14 22H7.86L2 16.14V7.86z"/><path d="M15 9l-6 6M9 9l6 6"/>'
  };
  var menu = document.createElement("div");
  menu.className = "chat-menu"; menu.hidden = true; menu.setAttribute("role", "menu");
  root.appendChild(menu);
  function closeMenu() { menu.hidden = true; }
  function openMenu(n, x, y) {
    var b = bufs[key(active)], chan = b && isChan(b.name) ? b.name : "", self = key(n) === key(nick);
    var myRank = chan ? b.users[Object.keys(b.users).filter(function (u) { return key(u) === key(nick); })[0]] || "" : "";
    var theirs = chan ? b.users[n] || "" : "", op = "~&@".indexOf(myRank) >= 0 && myRank, half = op || myRank === "%";
    var mask = hosts[key(n)] ? "*!*@" + hosts[key(n)] : n + "!*@*";
    var groups = [ // [section, [icon, label, action, danger?] ...]; falsy entries are left out
      ["Talk", [!self && ["msg", "Send private message", function () { query(n); showUsers(false); }],
                !self && ["at", "Mention in message", function () { var v = input.value; input.value = v + (v && !/\s$/.test(v) ? " " : "") + n + (v ? " " : ": "); }]]],
      ["Info", [["info", "Whois", function () { send("WHOIS " + n + " " + n); }], // asking the user's own server also returns idle time
                !self && ["client", "Client version", function () { command("/ctcp " + n + " version"); }],
                !self && ["ping", "Ping (lag)", function () { command("/ctcp " + n + " ping"); }]]],
      ["Privacy", [!self && (ignored[key(n)] ? ["eye", "Unignore", function () { setIgnore(n, false); }] : ["eyeoff", "Ignore", function () { setIgnore(n, true); }])]],
      ["Moderate " + chan, [op && !self && "~&".indexOf(theirs || "x") < 0 && (theirs === "@" ? ["shield", "Remove op", function () { send("MODE " + chan + " -o " + n); }] : ["shield", "Give op", function () { send("MODE " + chan + " +o " + n); }]),
                half && (theirs === "+" ? ["mic", "Remove voice", function () { send("MODE " + chan + " -v " + n); }] : ["mic", "Give voice", function () { send("MODE " + chan + " +v " + n); }]),
                half && !self && ["kick", "Kick", function () { send("KICK " + chan + " " + n + " :Kicked"); }, 1],
                op && !self && ["ban", "Ban " + mask, function () { send("MODE " + chan + " +b " + mask); }, 1],
                op && !self && ["kickban", "Kick + ban", function () { send("MODE " + chan + " +b " + mask); send("KICK " + chan + " " + n + " :Banned"); }, 1]]]
    ];
    menu.textContent = "";
    var h = document.createElement("div"); h.className = "mh"; h.textContent = n + (ignored[key(n)] ? " (ignored)" : ""); menu.appendChild(h);
    groups.forEach(function (g) {
      var its = g[1].filter(Boolean);
      if (!its.length) return;
      var sec = document.createElement("div"); sec.className = "ms"; sec.textContent = g[0]; menu.appendChild(sec);
      its.forEach(function (it) {
        var bt = document.createElement("button"); bt.type = "button"; bt.setAttribute("role", "menuitem");
        if (it[3]) bt.className = "danger";
        bt.innerHTML = ICON_SVG.replace("%", ICONS[it[0]]); // static icon markup; the label goes in as text below
        bt.appendChild(document.createTextNode(it[1]));
        bt.onclick = function () { closeMenu(); it[2](); if (!coarse) input.focus(); };
        menu.appendChild(bt);
      });
    });
    menu.hidden = false;
    var r = menu.getBoundingClientRect(); // keep it on screen
    menu.style.left = Math.max(4, Math.min(x, innerWidth - r.width - 4)) + "px";
    menu.style.top = Math.max(4, Math.min(y, innerHeight - r.height - 4)) + "px";
    menu.querySelector("button").focus({ preventScroll: true });
  }
  document.addEventListener("mousedown", function (e) { if (!menu.hidden && !menu.contains(e.target)) closeMenu(); }, true);
  document.addEventListener("touchstart", function (e) { if (!menu.hidden && !menu.contains(e.target)) closeMenu(); }, true);
  document.addEventListener("keydown", function (e) {
    if (menu.hidden) return;
    if (e.key === "Escape") { closeMenu(); input.focus(); }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") { // move between items
      var bs = [].slice.call(menu.querySelectorAll("button")), i = bs.indexOf(document.activeElement);
      e.preventDefault(); bs[(i + (e.key === "ArrowDown" ? 1 : bs.length - 1)) % bs.length].focus();
    }
  });
  log.addEventListener("scroll", closeMenu); users.parentNode.addEventListener("scroll", closeMenu); addEventListener("resize", closeMenu);

  function setIgnore(n, on) {
    if (on) ignored[key(n)] = 1; else delete ignored[key(n)];
    try { localStorage.setItem("chat-ignore", JSON.stringify(Object.keys(ignored))); } catch (e) {}
    draw();
    say(active, on ? "Ignoring " + n + ": their messages, notices and CTCPs are hidden (in this browser). /unignore " + n + " to undo." : "No longer ignoring " + n + ".", "evt");
  }

  function showUsers(on) { usersPane.classList.toggle("closed", !on); usersBtn.setAttribute("aria-pressed", on); }
  usersBtn.onclick = function () { showUsers(usersPane.classList.contains("closed")); };
  function query(n) { // open (or switch to) a private chat; a new one loads its history when you are logged in
    var fresh = !bufs[key(n)];
    buf(n).unread = false; active = n; draw();
    if (fresh) history(n);
  }

  function send(line) {
    line = line.replace(/[\r\n\0]/g, " ").slice(0, 450); // one line per call: user text can never smuggle extra commands
    if (ws && ws.readyState === 1) ws.send(line);
  }

  function parse(raw) {
    var m = { tags: {}, prefix: "", cmd: "", params: [] }, s = raw;
    if (s[0] === "@") {
      var sp = s.indexOf(" ");
      s.slice(1, sp).split(";").forEach(function (t) {
        var e = t.indexOf("=");
        m.tags[e < 0 ? t : t.slice(0, e)] = e < 0 ? "" : t.slice(e + 1).replace(/\\(.)/g, function (_, c) { return { ":": ";", s: " ", r: "\r", n: "\n" }[c] || c; });
      });
      s = s.slice(sp + 1);
    }
    if (s[0] === ":") { var i = s.indexOf(" "); m.prefix = s.slice(1, i); s = s.slice(i + 1); }
    var ti = s.indexOf(" :"), tail = null;
    if (ti >= 0) { tail = s.slice(ti + 2); s = s.slice(0, ti); }
    m.params = s.split(" ").filter(Boolean); m.cmd = (m.params.shift() || "").toUpperCase();
    if (tail !== null) m.params.push(tail);
    m.nick = m.prefix.split("!")[0];
    return m;
  }

  // --- chat history (draft/chathistory): recent messages on join, everything missed after a reconnect ---
  function history(name) {
    if (!caps["draft/chathistory"] || !caps.batch || !registered) return;
    if (!isChan(name) && !account) return; // private history is kept only between logged-in accounts
    var b = buf(name);
    send(b.last ? "CHATHISTORY AFTER " + name + " timestamp=" + b.last + " 100" : "CHATHISTORY LATEST " + name + " * " + HISTORY_ON_JOIN);
  }

  // --- read markers (draft/read-marker): where you stopped reading, shared by every session of your account ---
  var markTimer;
  function markSoon() { clearTimeout(markTimer); markTimer = setTimeout(markRead, 1500); }
  function markRead() {
    var b = bufs[key(active)];
    if (!b || b.name === "*" || !caps["draft/read-marker"] || !account || document.hidden || !b.last || b.last <= (b.read || "")) return;
    b.read = b.last;
    send("MARKREAD " + b.name + " timestamp=" + b.last);
  }

  // --- SASL: SCRAM-SHA-256 (the password itself never crosses the wire), PLAIN as the fallback ---
  var enc = new TextEncoder();
  function b64(bytes) { var s = ""; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function unb64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
  function hmac(k, data) {
    return crypto.subtle.importKey("raw", k, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
      .then(function (key) { return crypto.subtle.sign("HMAC", key, enc.encode(data)); }).then(function (b) { return new Uint8Array(b); });
  }
  function startSasl() {
    var mechs = (avail.sasl || "PLAIN").split(",");
    sasl = { mech: mechs.indexOf("SCRAM-SHA-256") >= 0 && window.crypto && crypto.subtle ? "SCRAM-SHA-256" : "PLAIN", step: 0 };
    send("AUTHENTICATE " + sasl.mech);
  }
  function saslStep(token) {
    if (!sasl || !auth) return send("AUTHENTICATE *");
    if (sasl.mech === "PLAIN") return send("AUTHENTICATE " + b64(enc.encode(auth.user + "\0" + auth.user + "\0" + auth.pass)));
    var sock = ws;
    if (sasl.step === 0) {
      sasl.nonce = b64(crypto.getRandomValues(new Uint8Array(18)));
      sasl.bare = "n=" + auth.user.replace(/=/g, "=3D").replace(/,/g, "=2C") + ",r=" + sasl.nonce;
      sasl.step = 1;
      return send("AUTHENTICATE " + b64(enc.encode("n,," + sasl.bare)));
    }
    if (sasl.step === 1) {
      var first = new TextDecoder().decode(unb64(token)), a = {};
      first.split(",").forEach(function (kv) { a[kv[0]] = kv.slice(2); });
      if (!a.r || a.r.indexOf(sasl.nonce) !== 0 || !a.s || !(+a.i > 0)) return send("AUTHENTICATE *");
      sasl.step = 2;
      var bare = "c=biws,r=" + a.r, msg = sasl.bare + "," + first + "," + bare, salted, ckey;
      crypto.subtle.importKey("raw", enc.encode(auth.pass), "PBKDF2", false, ["deriveBits"])
        .then(function (k) { return crypto.subtle.deriveBits({ name: "PBKDF2", salt: unb64(a.s), iterations: +a.i, hash: "SHA-256" }, k, 256); })
        .then(function (bits) { salted = new Uint8Array(bits); return hmac(salted, "Client Key"); })
        .then(function (ck) { ckey = ck; return crypto.subtle.digest("SHA-256", ck); })
        .then(function (stored) { return hmac(new Uint8Array(stored), msg); })
        .then(function (sig) {
          var proof = ckey.map(function (x, i) { return x ^ sig[i]; });
          return hmac(salted, "Server Key").then(function (sk) { return hmac(sk, msg); }).then(function (ss) {
            sasl.expect = b64(ss);
            if (sock === ws) send("AUTHENTICATE " + b64(enc.encode(bare + ",p=" + b64(proof))));
          });
        })
        .catch(function () { if (sock === ws) send("AUTHENTICATE *"); });
      return;
    }
    // step 2: the server proves it knows the password too; anything else means a fake server, so abort
    var v = new TextDecoder().decode(unb64(token));
    if (v !== "v=" + sasl.expect) { say("*", "Login aborted: the server could not prove its identity.", "err"); return send("AUTHENTICATE *"); }
    send("AUTHENTICATE +");
  }

  // --- CTCP: replies to the common queries, rate limited so a CTCP flood cannot get us disconnected for flooding ---
  var ctcpTimes = [], pings = {};
  function ctcpReply(to, cmd, arg) {
    var now = Date.now();
    ctcpTimes = ctcpTimes.filter(function (t) { return now - t < 10000; });
    if (ctcpTimes.length >= 4) return; // at most 4 replies per 10 seconds; the rest are dropped silently
    ctcpTimes.push(now);
    send("NOTICE " + to + " :\x01" + cmd + (arg ? " " + arg : "") + "\x01");
  }
  function ctcp(from, cmd, arg) {
    say("*", "CTCP " + cmd + " from " + from, "evt ctcp");
    if (cmd === "VERSION") return ctcpReply(from, cmd, "\x02" + CLIENT + "\x02 v" + CLIENT_V + BAR + "IRCv3 over TLS WebSocket" + BAR + "SASL SCRAM-SHA-256" + BAR + SITE);
    if (cmd === "PING") return ctcpReply(from, cmd, (arg || "").slice(0, 64));
    if (cmd === "TIME") return ctcpReply(from, cmd, new Date().toString().replace(/ \(.*\)$/, ""));
    if (cmd === "CLIENTINFO") return ctcpReply(from, cmd, "ACTION CLIENTINFO PING SOURCE TIME VERSION");
    if (cmd === "SOURCE") return ctcpReply(from, cmd, "https://github.com/gcanosa/SekurIRCd/tree/main/web");
    // USERINFO, FINGER and the rest are not answered: they mostly exist to fingerprint users
  }
  function ctcpAnswer(from, cmd, arg) {
    if (cmd === "PING" && pings[key(from)] && arg === pings[key(from)].tok) {
      say(active, "PING reply from " + from + ": " + ((Date.now() - pings[key(from)].at) / 1000).toFixed(3) + "s", "evt ctcp");
      delete pings[key(from)];
      return;
    }
    say(active, "CTCP " + cmd + " reply from " + from + ": " + arg, "evt ctcp");
  }

  // --- a soft two-note chime when someone else messages, notices, mentions or invites you; synthesized (no audio file) ---
  var actx, lastChime = 0, sound = true;
  try { sound = localStorage.getItem("chat-sound") !== "off"; } catch (e) {}
  function unlockAudio() { // browsers (iOS above all) only allow audio after a tap: called from Connect and Send
    try { actx = actx || new (window.AudioContext || window.webkitAudioContext)(); if (actx.state === "suspended") actx.resume(); } catch (e) {}
  }
  function chime() {
    if (!sound || !actx || Date.now() - lastChime < 2000) return; // at most one every 2 seconds
    lastChime = Date.now();
    var t = actx.currentTime;
    [660, 990].forEach(function (f, i) {
      var o = actx.createOscillator(), g = actx.createGain(), at = t + i * 0.11;
      o.type = "sine"; o.frequency.value = f; o.connect(g); g.connect(actx.destination);
      g.gain.setValueAtTime(0.0001, at); g.gain.exponentialRampToValueAtTime(0.05, at + 0.015); g.gain.exponentialRampToValueAtTime(0.0001, at + 0.3);
      o.start(at); o.stop(at + 0.32);
    });
  }

  function onLine(raw) {
    var m = parse(raw), p = m.params, me = nick, c = m.cmd, isMe = function (n) { return key(n) === key(me); };
    var bt = m.tags.batch && batches[m.tags.batch], meta = { time: m.tags.time, id: m.tags.msgid, hist: !!bt };
    if (c === "PING") return send("PONG :" + (p[0] || ""));
    if (c === "CAP") {
      var sub = p[1], more = p[2] === "*", list = (more ? p[3] : p[2]) || "";
      if (sub === "LS") {
        list.split(" ").forEach(function (t) { if (t) { var e = t.indexOf("="); avail[e < 0 ? t : t.slice(0, e)] = e < 0 ? "" : t.slice(e + 1); } });
        if (more) return; // a long list arrives over several lines
        var want = WANT_CAPS.filter(function (x) { return x in avail; });
        if (auth && "sasl" in avail) want.push("sasl");
        else if (auth) say("*", "This server does not offer SASL login; continuing as a guest.", "err");
        return send(want.length ? "CAP REQ :" + want.join(" ") : "CAP END");
      }
      if (sub === "ACK") {
        list.split(" ").forEach(function (x) { if (x[0] === "-") delete caps[x.slice(1)]; else if (x) caps[x] = true; });
        if (!registered) { if (caps.sasl && auth) startSasl(); else send("CAP END"); }
        return;
      }
      if (sub === "NAK" && !registered) send("CAP END");
      return;
    }
    if (c === "AUTHENTICATE") return saslStep(p[0]);
    if (c === "MARKREAD") {
      var rb = bufs[key(p[0])], ts = (p[1] || "").replace(/^timestamp=/, "");
      if (!rb) return;
      rb.read = ts === "*" ? "" : ts;
      if (!rb.marked || key(rb.name) !== key(active) || document.hidden) { rb.mark = rb.read; rb.marked = true; } // the divider stays put while you read
      if (rb.unread && rb.read && rb.read >= rb.last) { rb.unread = false; drawTabs(); } // read on another device
      return;
    }
    if (c === "900") { account = p[2]; say("*", "Logged in as " + account + ".", "evt"); return; }
    if (c === "903") { sasl = null; return send("CAP END"); }
    if (c === "902" || c === "904" || c === "905") {
      // SCRAM refused before the server even answered: the account has no SCRAM key yet (made before SCRAM existed). PLAIN once creates it.
      if (sasl && sasl.mech === "SCRAM-SHA-256" && sasl.step <= 1) { sasl = { mech: "PLAIN", step: 0 }; return send("AUTHENTICATE PLAIN"); }
      sasl = null; auth = null; // a wrong password is not retried on reconnect
      say("*", "Login failed: wrong account name or password. You are connected as a guest.", "err");
      return send("CAP END");
    }
    if (c === "906" || c === "907" || c === "908") return;
    if (c === "BATCH") {
      var id = p[0].slice(1);
      if (p[0][0] === "+") batches[id] = { type: p[1], target: p[2], n: 0 };
      else if (batches[id]) {
        var done = batches[id]; delete batches[id];
        if (done.type === "chathistory" && done.n) {
          say(done.target, "── " + done.n + " message" + (done.n > 1 ? "s" : "") + " from history ──", "evt hist-end");
          if (key(done.target) === key(active)) { draw(); markSoon(); } // place the "new messages" divider
        }
      }
      return;
    }
    if (c === "FAIL" && p[0] === "CHATHISTORY") return; // e.g. no private history for guests: nothing to show
    if (c === "001") {
      registered = true; tries = 0; armAway(); nick = p[0]; say("*", p[1], "", meta);
      if (wantChan) send("JOIN " + wantChan);
      Object.keys(bufs).forEach(function (k) { if (k !== "*" && !isChan(k)) history(bufs[k].name); }); // private chats kept across a reconnect
      return;
    }
    if (c === "305" || c === "306") away = c === "306";
    if ((c === "433" || c === "432") && !registered) { // taken or refused: keep trying, never past NICKLEN
      nick = c === "433" && nick.length < 30 ? nick + "_" : guest();
      return send("NICK " + nick);
    }
    if (c === "353") { // names
      var b = bufs[key(p[2])];
      if (!b) return say(active, "Users in " + p[2] + ": " + p[3], "evt"); // /names of a channel you are not in: no tab for it
      b.pending = b.pending || {}; // a NAMES reply spans several 353s, swapped in at 366
      p[3].split(" ").forEach(function (n) { // "@nick", or "@nick!user@host" with userhost-in-names
        var mm = /^([~&@%+]*)([^!]+)(?:!([^@]*)@(.*))?$/.exec(n);
        if (mm) { b.pending[mm[2]] = mm[1].charAt(0); if (mm[4]) hosts[key(mm[2])] = mm[4]; }
      });
      return;
    }
    if (c === "366") { var nb = bufs[key(p[1])]; if (!nb) return; if (nb.pending) { nb.users = nb.pending; nb.pending = null; } return key(p[1]) === key(active) && draw(); }
    if (c === "MODE" && isChan(p[0])) {
      say(p[0], m.nick + " sets mode " + p.slice(1).join(" "), "evt mode", meta);
      if (/[qaohv]/.test(p[1] || "")) send("NAMES " + p[0]); // privilege changed: re-read the list
      return;
    }
    if (c === "332") {
      if (!bufs[key(p[1])]) return say(active, "Topic of " + p[1] + ": " + p[2], "evt topic");
      buf(p[1]).topic = p[2]; return key(p[1]) === key(active) && draw();
    }
    if (c === "333") { // who set the topic, and when: shown on hover over the topic bar
      if (bufs[key(p[1])]) bufs[key(p[1])].topicBy = "Set by " + p[2].split("!")[0] + (+p[3] ? " on " + new Date(p[3] * 1000).toLocaleString() : "");
      return key(p[1]) === key(active) && draw();
    }
    if (c === "329") return; // channel creation time: not worth a line
    if (c === "TOPIC") { buf(p[0]).topic = p[1]; buf(p[0]).topicBy = "Set by " + m.nick + " on " + new Date().toLocaleString(); say(p[0], m.nick + " set the topic: " + p[1], "evt topic", meta); return key(p[0]) === key(active) && draw(); }
    if (m.prefix.indexOf("@") > 0) hosts[key(m.nick)] = m.prefix.split("@")[1]; // keep the latest host of everyone we hear from
    if (c === "JOIN") {
      var ch = p[0];
      if (isMe(m.nick)) { var again = !!bufs[key(ch)]; buf(ch); active = ch; draw(); if (!again) say(ch, "Joined " + ch, "evt join"); history(ch); }
      else { buf(ch).users[m.nick] = ""; say(ch, m.nick + " joined", "evt join"); if (key(ch) === key(active)) draw(); }
      return;
    }
    if (c === "PART" || c === "KICK") {
      var who = c === "KICK" ? p[1] : m.nick, why = c === "KICK" ? p[2] : p[1];
      say(p[0], who + (c === "KICK" ? " was kicked by " + m.nick : " left") + (why ? " (" + why + ")" : ""), c === "KICK" ? "evt kick" : "evt part");
      if (isMe(who)) {
        delete bufs[key(p[0])]; if (key(active) === key(p[0])) active = "*";
        if (c === "KICK") say(active, "You were kicked from " + p[0] + " by " + m.nick + (why ? " (" + why + ")" : ""), "err kick"); // its tab is gone
        draw();
      }
      else { delete buf(p[0]).users[who]; if (key(p[0]) === key(active)) draw(); }
      return;
    }
    if (c === "QUIT") {
      Object.keys(bufs).forEach(function (k) { if (m.nick in bufs[k].users) { delete bufs[k].users[m.nick]; say(bufs[k].name, m.nick + " quit" + (p[0] ? " (" + p[0] + ")" : ""), "evt quit"); } });
      if (bufs[key(m.nick)]) say(m.nick, m.nick + " quit" + (p[0] ? " (" + p[0] + ")" : ""), "evt quit"); // their private chat
      return draw();
    }
    if (c === "NICK") {
      if (isMe(m.nick)) nick = p[0];
      if (hosts[key(m.nick)]) hosts[key(p[0])] = hosts[key(m.nick)];
      var q = bufs[key(m.nick)]; // a private chat follows the nick, so their next message lands in the same tab
      if (q && (key(m.nick) === key(p[0]) || !bufs[key(p[0])])) {
        delete bufs[key(m.nick)]; bufs[key(p[0])] = q; q.name = p[0];
        if (key(active) === key(m.nick)) active = p[0];
        say(p[0], m.nick + " is now " + p[0], "evt nick");
      }
      Object.keys(bufs).forEach(function (k) { var u = bufs[k].users; if (m.nick in u) { u[p[0]] = u[m.nick]; delete u[m.nick]; say(bufs[k].name, m.nick + " is now " + p[0], "evt nick"); } });
      return draw();
    }
    if (c === "PRIVMSG" || c === "NOTICE") {
      var mine = isMe(m.nick), server = m.prefix.indexOf("!") < 0;
      if (!mine && ignored[key(m.nick)]) return; // no line, no chime, no CTCP reply
      var target = isChan(p[0]) ? p[0] : server ? "*" : mine ? p[0] : m.nick; // our own echoed DM belongs in the recipient's tab
      var txt = p[1] || "", act = /^\x01ACTION (.*?)\x01?$/.exec(txt), cq = !act && /^\x01([^\s\x01]+) ?([^\x01]*)\x01?$/.exec(txt);
      if (cq) { // CTCP: never answered from history, never to ourselves
        if (!bt && !mine && !server) (c === "PRIVMSG" ? ctcp : ctcpAnswer)(m.nick, cq[1].toUpperCase(), cq[2]);
        return;
      }
      if (bt) bt.n++;
      // chime only for what others send you: a private message or action, a notice, or your nick in a channel. Never for your own lines.
      else if (!mine && !server && (c === "NOTICE" || !isChan(target) || mentions(txt, me))) chime();
      var cls = mine ? "me" : (c === "NOTICE" ? "notice " : "") + (mentions(txt, me) ? "hl" : !isChan(target) && !server ? "msg" : "");
      meta.from = m.nick; meta.kind = act ? "act" : c === "NOTICE" ? "notice" : "msg";
      say(target, act ? act[1] : mine ? masked(target, txt) : txt, cls, meta);
      return;
    }
    if (c === "INVITE" && isMe(p[0]) && !ignored[key(m.nick)]) {
      say(active, m.nick + " invites you to " + p[1] + ". Type /join " + p[1] + " to accept.", "evt hl invite", meta);
      return chime();
    }
    if (c === "ERROR") return say("*", "Server error: " + p[0], "err");
    if (/^(276|30[17]|31[1-46-9]|320|330|338|378|379|671)$/.test(c)) return say(active, whois(c, p), c === "301" ? "evt whois away" : "evt whois", meta); // WHOIS: where you asked
    if (/^\d+$/.test(c)) say(+c >= 400 ? active : "*", p.slice(1).join(" "), +c >= 400 ? "err" : c === "305" || c === "306" ? "evt away" : "", meta);
  }

  function ago(sec) { // 3725 -> "1h 2m 5s"
    sec = +sec || 0;
    var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60), out = [];
    if (d) out.push(d + "d"); if (h) out.push(h + "h"); if (m) out.push(m + "m"); if (!d && !h) out.push(sec % 60 + "s");
    return out.join(" ");
  }
  function whois(c, p) { // the common WHOIS replies as sentences; anything else as the server sent it
    var n = p[1];
    if (c === "311") return n + " is " + p[2] + "@" + p[3] + " (" + p[p.length - 1] + ")";
    if (c === "312") return n + " is on " + p[2] + " (" + p[3] + ")";
    if (c === "319") return n + " is in " + p[2];
    if (c === "317") return n + " has been idle " + ago(p[2]) + (+p[3] ? ", connected since " + new Date(p[3] * 1000).toLocaleString() : "");
    if (c === "330") return n + " is logged in as " + p[2];
    if (c === "301") return n + " is away: " + p[2];
    if (c === "313") return n + " is an IRC operator";
    if (c === "671") return n + " is using a secure connection";
    if (c === "318") return "\u2500\u2500 end of whois \u2500\u2500";
    return p.slice(1).join(" ");
  }

  function mentions(txt, n) { // the nick as a whole word, not inside another word
    var re = new RegExp("(^|[^A-Za-z0-9\\[\\]\\\\`_^{|}-])" + n.replace(/[\\^$.*+?()[\]{}|-]/g, "\\$&") + "($|[^A-Za-z0-9\\[\\]\\\\`_^{|}-])", "i");
    return re.test(txt);
  }

  // Any message or command you send counts as activity: it clears away and restarts the idle timer.
  function activity(text) {
    if (away && !/^\/away(\s|$)/i.test(text)) send("AWAY");
    armAway();
  }
  function armAway() { // also called on connect, so a user who only reads still goes away
    clearTimeout(awayTimer);
    awayTimer = setTimeout(function () {
      if (!registered || away) return;
      send("AWAY :Auto-away (idle 30 minutes)");
      say("*", "You were marked away after 30 minutes without activity. Send any message to come back.", "evt away");
    }, AWAY_AFTER);
  }

  function privmsg(to, text, act) { // with echo-message the server echoes it back (with its time and id), so show it then
    chunks(text).forEach(function (t) {
      send("PRIVMSG " + to + " :" + (act ? "\x01ACTION " + t + "\x01" : t));
      if (!caps["echo-message"]) say(to, act ? t : masked(to, t), "me", { from: nick, kind: act ? "act" : "msg" });
    });
  }
  // The server drops a whole line over 512 bytes, and accents, emoji or CJK get there well before the input's 400 characters:
  // long text goes out as several lines, cut at the last space unless that leaves a short line.
  var MAX_BODY = 350; // bytes per line, leaving room for "PRIVMSG target :" and the nick!user@host the server adds when relaying
  function chunks(text) {
    var cps = Array.from(text), out = [], start = 0, bytes = 0, sp = -1, spAt = 0; // code points, so an emoji is never cut in half
    for (var i = 0; i < cps.length; i++) {
      var n = enc.encode(cps[i]).length;
      if (bytes + n > MAX_BODY) {
        var cut = sp > start && spAt > MAX_BODY / 2 ? sp : i;
        out.push(cps.slice(start, cut).join("")); start = cut === sp ? sp + 1 : cut; sp = -1;
        bytes = enc.encode(cps.slice(start, i).join("")).length;
      }
      if (cps[i] === " ") { sp = i; spAt = bytes; }
      bytes += n;
    }
    out.push(cps.slice(start).join(""));
    return out;
  }
  function masked(to, text) { // what you tell NickServ (REGISTER, IDENTIFY ...) carries a password: show only the command
    return /^nickserv$/i.test(to) ? text.replace(/^(\S+)\s.*$/, "$1 ********") : text;
  }

  function command(text) {
    activity(text);
    if (text[0] !== "/" || text.slice(0, 2) === "//") {
      if (text.slice(0, 2) === "//") text = text.slice(1);
      if (active === "*") return say("*", "Join a channel first (/join #name).", "err");
      return privmsg(active, text);
    }
    var a = text.slice(1).split(" "), cmd = a.shift().toLowerCase(), rest = a.join(" ");
    if (cmd === "help") return say(active, "Commands: /join #chan, /part, /close, /nick name, /me action, /msg nick text, /whois nick, /topic text, " +
      "/notice nick text, /kick nick reason, /away text, /ctcp nick version|time|ping, /sound on|off, /ignore nick, /unignore nick, /quit. Right click a nick (tap on phones) for more. Accounts: /msg NickServ REGISTER password. Tab completes nicknames, Up/Down recall what you sent.", "evt");
    if (cmd === "sound") {
      sound = a[0] ? a[0].toLowerCase() !== "off" : !sound;
      try { localStorage.setItem("chat-sound", sound ? "on" : "off"); } catch (e) {}
      if (sound) { unlockAudio(); lastChime = 0; chime(); }
      return say(active, "Sound for private messages, notices, mentions and invites is " + (sound ? "on" : "off") + ".", "evt");
    }
    if (cmd === "ignore" || cmd === "unignore") {
      if (a[0]) return setIgnore(a[0], cmd === "ignore");
      var list = Object.keys(ignored);
      return say(active, list.length ? "Ignored: " + list.join(", ") : "You are not ignoring anyone.", "evt");
    }
    if (cmd === "join" && a[0]) return send("JOIN " + a[0].split(",").map(function (c) { return /^[#&]/.test(c) ? c : "#" + c; }).join(",") + (a[1] ? " " + a.slice(1).join(" ") : ""));
    if (cmd === "part" || cmd === "topic" || cmd === "kick") { // /part [#chan] [reason], /topic [#chan] [text], /kick [#chan] nick [reason]
      var ch = a[0] && isChan(a[0]) ? a.shift() : isChan(active) ? active : "", why = a.join(" "); // the channel defaults to the open tab
      if (!ch) return say(active, "Use it in a channel tab, or name the channel: /" + cmd + " #channel ...", "err");
      if (cmd === "part") return send("PART " + ch + (why ? " :" + why : ""));
      if (cmd === "topic") return send("TOPIC " + ch + (why ? " :" + why : ""));
      if (!a[0]) return say(active, "Usage: /kick [#channel] nick [reason]", "err");
      return send("KICK " + ch + " " + a[0] + " :" + (a.slice(1).join(" ") || "Kicked"));
    }
    if (cmd === "away") return send(rest ? "AWAY :" + rest : "AWAY");
    if (cmd === "notice" && a[1]) return send("NOTICE " + a[0] + " :" + a.slice(1).join(" "));
    if (cmd === "close") {
      if (active === "*") return say("*", "The status tab cannot be closed.", "err");
      return closeBuf(active);
    }
    if (cmd === "me") { if (active === "*" || !rest) return; return privmsg(active, rest, true); }
    if ((cmd === "msg" || cmd === "query") && a[0]) {
      var body = a.slice(1).join(" ");
      if (!isChan(a[0])) query(a[0]);
      if (body) privmsg(a[0], body);
      return;
    }
    if (cmd === "ctcp" && a[1]) {
      var what = a[1].toUpperCase(), arg = a.slice(2).join(" ");
      if (what === "PING") { arg = String(Date.now()); pings[key(a[0])] = { tok: arg, at: Date.now() }; }
      send("PRIVMSG " + a[0] + " :\x01" + what + (arg ? " " + arg : "") + "\x01");
      return say(active, "CTCP " + what + " sent to " + a[0], "evt ctcp");
    }
    if (cmd === "quit") {
      closing = true; clearTimeout(awayTimer); clearTimeout(timer);
      if (!ws || ws.readyState > 1) { app.hidden = true; form.hidden = false; return; } // already disconnected: nothing to wait for
      send("QUIT :" + (rest ? rest + BAR + CLIENT : QUIT_MSG)); // your own reason keeps a short client tag
      var s = ws; setTimeout(function () { if (s && s.readyState < 2) s.close(); }, 1500); // the server normally closes first; this is the fallback
      return;
    }
    send(a.length ? cmd.toUpperCase() + " " + rest : cmd.toUpperCase()); // /mode /whois /topic /nick ...: pass through
  }

  function connect() {
    clearTimeout(timer); registered = false; away = false; // a new connection starts un-away
    avail = {}; caps = {}; sasl = null; account = ""; batches = {};
    say("*", "Connecting to irc.sekurnet.org ...");
    var sock;
    try { sock = ws = new WebSocket(WS_URL); } catch (e) { return fail(); }
    var opened = false;
    ws.onopen = function () { opened = true; send("CAP LS 302"); send("NICK " + nick); send("USER webchat 0 * :" + CLIENT); };
    ws.onmessage = function (ev) { String(ev.data).split(/\r?\n/).forEach(function (l) { if (l) onLine(l); }); };
    ws.onclose = function () {
      if (sock !== ws) return; // a stale socket from before a quit/reconnect
      if (closing) { // /quit: back to the connect form so you can join again without reloading
        app.hidden = true; form.hidden = false;
        err.textContent = "You left SekurNet. Connect again below.";
        return;
      }
      if (!opened && !registered && tries === 0) return fail();
      if (document.hidden) return say("*", "Connection lost while the page was in the background. Reconnecting when you come back ...", "err");
      if (++tries > 5) return say("*", "Disconnected. Send any message or come back to this tab to try again.", "err");
      var wait = tries * 3000;
      say("*", "Connection lost. Reconnecting in " + wait / 1000 + "s ...", "err");
      timer = setTimeout(reconnect, wait);
    };
  }
  function reconnect() {
    wantChan = Object.keys(bufs).filter(isChan).map(function (k) { return bufs[k].name; }).join(",") || wantChan;
    connect();
  }
  function dead() { return !closing && !app.hidden && (!ws || ws.readyState > 1); }
  // Phones drop the socket when the tab is backgrounded or the screen locks: reconnect as soon as it is visible again.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) return;
    unseen = 0; document.title = baseTitle; markSoon();
    if (dead()) { tries = 0; clearTimeout(timer); reconnect(); }
  });
  window.addEventListener("online", function () { if (dead()) { tries = 0; clearTimeout(timer); reconnect(); } });

  // Phones: keep the full-screen chat inside the visible area, above the on-screen keyboard.
  var vv = window.visualViewport;
  if (vv) {
    var fit = function () { app.style.setProperty("--chat-h", vv.height + "px"); app.style.setProperty("--chat-top", vv.offsetTop + "px"); if (!app.hidden) toBottom(); };
    vv.addEventListener("resize", fit); vv.addEventListener("scroll", fit); fit();
  }
  function fail() {
    app.hidden = true; form.hidden = false;
    err.textContent = "Could not connect. The server may be down, or something is blocking the connection. If you use an ad or content blocker (uBlock, Privacy Badger, a firewall extension), allow irc.sekurnet.org for this page or turn the blocker off for this site, then try again.";
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault(); err.textContent = "";
    var n = nickIn.value.trim(), seen = {}, user = acctIn.value.trim(), pass = passIn.value;
    var cs = chanIn.value.split(/[\s,]+/).filter(Boolean).map(function (c) { return /^[#&]/.test(c) ? c : "#" + c; })
      .filter(function (c) { return !seen[key(c)] && (seen[key(c)] = true); });
    if (user && n === guestNick && NICK_RE.test(user)) n = user; // logging in without picking a nick: use the account name
    if (!NICK_RE.test(n)) return (err.textContent = "Nickname: letters, digits and [ ] \\ ` _ ^ { | } -, max 30, not starting with a digit or -.");
    if (!cs.length) return (err.textContent = "Enter at least one channel, e.g. #SekurNet.");
    if (cs.length > MAX_CHANS) return (err.textContent = "At most " + MAX_CHANS + " channels at once; join more later with /join.");
    var bad = cs.filter(function (c) { return !CHAN_RE.test(c); })[0];
    if (bad) return (err.textContent = "Invalid channel " + bad + ": max 50 characters, no control characters.");
    if (user && !pass) return (err.textContent = "Enter your password, or clear the account field to join as a guest.");
    if (user && /[\s,=]/.test(user)) return (err.textContent = "Account name: no spaces, commas or = signs.");
    auth = user ? { user: user, pass: pass } : null; // kept in memory only, so an automatic reconnect can log in again
    passIn.value = "";
    try { localStorage.setItem("chat-chan", cs.join(" ")); localStorage.setItem("chat-acct", user); } catch (x) {}
    nick = n; wantChan = cs.join(","); closing = false; tries = 0; bufs = {}; active = "*"; draw();
    form.hidden = true; app.hidden = false; showUsers(false); input.focus();
    unlockAudio(); connect();
  });
  $("send").addEventListener("submit", function (e) {
    e.preventDefault(); var t = input.value.trim(); input.value = ""; unlockAudio();
    if (t) { sent.push(t); if (sent.length > 50) sent.shift(); spos = sent.length; }
    if (dead() && tries > 5) { tries = 0; return reconnect(); } // gave up earlier: sending is the "try again" button
    if (t) command(t);
  });
  input.addEventListener("keydown", function (e) {
    if (e.key === "ArrowUp" || e.key === "ArrowDown") { // recall what you sent
      if (!sent.length) return;
      e.preventDefault();
      spos = Math.max(0, Math.min(sent.length, spos + (e.key === "ArrowUp" ? -1 : 1)));
      input.value = sent[spos] || "";
      return;
    }
    if (e.key !== "Tab" || e.shiftKey) return;
    var v = input.value, at = input.selectionStart, pre = v.slice(0, at), w = /(\S*)$/.exec(pre)[1];
    var b = bufs[key(active)];
    if (!w || !b) return;
    // first alphabetical match only (no cycling through several matches)
    var hit = Object.keys(b.users).filter(function (n) { return key(n).indexOf(key(w)) === 0; }).sort()[0];
    if (!hit) return;
    e.preventDefault();
    var ins = hit + (pre.length === w.length ? ": " : " ");
    input.value = pre.slice(0, at - w.length) + ins + v.slice(at);
    input.selectionStart = input.selectionEnd = at - w.length + ins.length;
  });
  $("quit-btn").onclick = function () { command("/quit"); };
  // Leaving the page: say goodbye with the quit message and let the server close the socket (closing it here would race the QUIT).
  // pagehide, not beforeunload: iOS Safari never fires beforeunload.
  window.addEventListener("pagehide", function () { if (ws && ws.readyState === 1 && !app.hidden) { closing = true; send("QUIT :" + QUIT_MSG); } });
  window.addEventListener("pageshow", function (e) { // back from the browser's page cache: reconnect where we were
    if (e.persisted && closing && !app.hidden) { closing = false; tries = 0; reconnect(); }
  });
})();
