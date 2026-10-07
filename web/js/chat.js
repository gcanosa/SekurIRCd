// SekurNet web chat: a small IRC-over-WebSocket client locked to ONE network.
// The endpoint is a constant on purpose: there is no host field and no URL parameter that can change it.
(function () {
  var WS_URL = "wss://sekurnet.duckdns.org:12155"; // [websocket] port with tls = true in sekurircd.toml
  var DEFAULT_CHAN = "#SekurNet";
  var NICK_RE = /^[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]{0,29}$/;
  var CHAN_RE = /^[#&][^\s,\x07]{1,49}$/;

  var $ = function (id) { return document.getElementById(id); };
  var form = $("connect"), app = $("chat"), nickIn = $("nick"), chanIn = $("chan"), err = $("conn-err");
  var tabs = $("tabs"), log = $("log"), users = $("users"), topic = $("topic"), input = $("input");

  var ws, nick, wantChan, registered, tries = 0, closing = false, timer;
  var bufs = {}, active = "*";

  try { nickIn.value = localStorage.getItem("chat-nick") || ""; chanIn.value = localStorage.getItem("chat-chan") || ""; } catch (e) {}
  if (!nickIn.value) nickIn.value = "Guest" + Math.floor(1000 + Math.random() * 9000);
  if (!chanIn.value) chanIn.value = DEFAULT_CHAN;

  function key(n) { return n.toLowerCase(); }
  function buf(name) {
    var k = key(name);
    if (!bufs[k]) { bufs[k] = { name: name, lines: [], users: {}, topic: "", unread: false }; draw(); }
    return bufs[k];
  }
  function say(name, text, cls) {
    var b = buf(name), t = new Date().toTimeString().slice(0, 5);
    b.lines.push({ t: t, text: text, cls: cls || "" });
    if (b.lines.length > 500) b.lines.shift();
    if (key(name) === key(active)) addLine(b.lines[b.lines.length - 1]); else { b.unread = true; drawTabs(); }
  }
  function addLine(l) {
    var stick = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
    var d = document.createElement("div"); d.className = "ln " + l.cls;
    var s = document.createElement("span"); s.className = "ts"; s.textContent = l.t + " ";
    d.append(s, document.createTextNode(l.text)); log.appendChild(d);
    if (stick) log.scrollTop = log.scrollHeight;
  }
  function drawTabs() {
    tabs.textContent = "";
    Object.keys(bufs).forEach(function (k) {
      var b = bufs[k], a = document.createElement("button");
      a.type = "button"; a.textContent = b.name === "*" ? "status" : b.name;
      if (k === key(active)) a.setAttribute("aria-current", "true");
      if (b.unread) a.className = "unread";
      a.onclick = function () { active = b.name; b.unread = false; draw(); input.focus(); };
      tabs.appendChild(a);
    });
  }
  function draw() {
    var b = buf(active);
    drawTabs();
    log.textContent = ""; b.lines.forEach(addLine); log.scrollTop = log.scrollHeight;
    topic.textContent = b.topic || (b.name === "*" ? "SekurNet web chat" : "");
    users.textContent = "";
    Object.keys(b.users).sort(function (x, y) { return x.toLowerCase() < y.toLowerCase() ? -1 : 1; }).forEach(function (n) {
      var d = document.createElement("div"); d.textContent = b.users[n] + n; users.appendChild(d);
    });
    users.parentNode.hidden = b.name[0] !== "#" && b.name[0] !== "&";
  }

  function send(line) {
    line = line.replace(/[\r\n\0]/g, " ").slice(0, 450); // one line per call: user text can never smuggle extra commands
    if (ws && ws.readyState === 1) ws.send(line);
  }

  function parse(raw) {
    var m = { prefix: "", cmd: "", params: [] }, s = raw;
    if (s[0] === "@") s = s.slice(s.indexOf(" ") + 1); // message tags: not used
    if (s[0] === ":") { var i = s.indexOf(" "); m.prefix = s.slice(1, i); s = s.slice(i + 1); }
    var ti = s.indexOf(" :"), tail = null;
    if (ti >= 0) { tail = s.slice(ti + 2); s = s.slice(0, ti); }
    m.params = s.split(" ").filter(Boolean); m.cmd = (m.params.shift() || "").toUpperCase();
    if (tail !== null) m.params.push(tail);
    m.nick = m.prefix.split("!")[0];
    return m;
  }

  function onLine(raw) {
    var m = parse(raw), p = m.params, me = nick, c = m.cmd;
    if (c === "PING") return send("PONG :" + (p[0] || ""));
    if (c === "001") { registered = true; tries = 0; nick = p[0]; say("*", p[1]); if (wantChan) send("JOIN " + wantChan); return; }
    if (c === "433" && !registered) { nick = nick + "_"; return send("NICK " + nick); }
    if (c === "353") { // names
      var b = buf(p[2]);
      p[3].split(" ").forEach(function (n) { var mm = /^([~&@%+]*)(.+)$/.exec(n); if (mm) b.users[mm[2]] = mm[1].charAt(0); });
      return key(p[2]) === key(active) && draw();
    }
    if (c === "366") return;
    if (c === "332") { buf(p[1]).topic = p[2]; return key(p[1]) === key(active) && draw(); }
    if (c === "TOPIC") { buf(p[0]).topic = p[1]; say(p[0], m.nick + " set the topic: " + p[1], "evt"); return key(p[0]) === key(active) && draw(); }
    if (c === "JOIN") {
      var ch = p[0];
      if (m.nick === me) { buf(ch); active = ch; draw(); say(ch, "Joined " + ch, "evt"); }
      else { buf(ch).users[m.nick] = ""; say(ch, m.nick + " joined", "evt"); if (key(ch) === key(active)) draw(); }
      return;
    }
    if (c === "PART" || c === "KICK") {
      var who = c === "KICK" ? p[1] : m.nick, why = c === "KICK" ? p[2] : p[1];
      say(p[0], who + (c === "KICK" ? " was kicked by " + m.nick : " left") + (why ? " (" + why + ")" : ""), "evt");
      if (who === me) { delete bufs[key(p[0])]; if (key(active) === key(p[0])) active = "*"; draw(); }
      else { delete buf(p[0]).users[who]; if (key(p[0]) === key(active)) draw(); }
      return;
    }
    if (c === "QUIT") {
      Object.keys(bufs).forEach(function (k) { if (m.nick in bufs[k].users) { delete bufs[k].users[m.nick]; say(bufs[k].name, m.nick + " quit" + (p[0] ? " (" + p[0] + ")" : ""), "evt"); } });
      return draw();
    }
    if (c === "NICK") {
      if (m.nick === me) nick = p[0];
      Object.keys(bufs).forEach(function (k) { var u = bufs[k].users; if (m.nick in u) { u[p[0]] = u[m.nick]; delete u[m.nick]; say(bufs[k].name, m.nick + " is now " + p[0], "evt"); } });
      return draw();
    }
    if (c === "PRIVMSG" || c === "NOTICE") {
      var target = p[0][0] === "#" || p[0][0] === "&" ? p[0] : (m.prefix.indexOf("!") < 0 ? "*" : m.nick);
      var txt = p[1], act = /^\x01ACTION (.*?)\x01?$/.exec(txt);
      if (!act && txt[0] === "\x01") return; // other CTCP: ignored
      say(target, act ? "* " + m.nick + " " + act[1] : "<" + m.nick + "> " + txt, (c === "NOTICE" ? "notice " : "") + (txt.toLowerCase().indexOf(me.toLowerCase()) >= 0 ? "hl" : ""));
      return;
    }
    if (c === "ERROR") return say("*", "Server error: " + p[0], "err");
    if (/^\d+$/.test(c)) say(+c >= 400 ? active : "*", p.slice(1).join(" "), +c >= 400 ? "err" : "");
  }

  function command(text) {
    if (text[0] !== "/" || text.slice(0, 2) === "//") {
      if (text.slice(0, 2) === "//") text = text.slice(1);
      if (active === "*") return say("*", "Join a channel first (/join #name).", "err");
      send("PRIVMSG " + active + " :" + text);
      return say(active, "<" + nick + "> " + text, "me");
    }
    var a = text.slice(1).split(" "), cmd = a.shift().toLowerCase(), rest = a.join(" ");
    if (cmd === "join" && rest) return send("JOIN " + (/^[#&]/.test(rest) ? rest : "#" + rest));
    if (cmd === "part") return send("PART " + (a[0] || active));
    if (cmd === "me") { if (active === "*") return; send("PRIVMSG " + active + " :\x01ACTION " + rest + "\x01"); return say(active, "* " + nick + " " + rest, "me"); }
    if ((cmd === "msg" || cmd === "query") && a[0]) {
      var body = a.slice(1).join(" "); buf(a[0]); active = a[0]; draw();
      if (body) { send("PRIVMSG " + a[0] + " :" + body); say(a[0], "<" + nick + "> " + body, "me"); }
      return;
    }
    if (cmd === "quit") { closing = true; send("QUIT :" + (rest || "Web chat closed")); return; }
    send(a.length ? cmd.toUpperCase() + " " + rest : cmd.toUpperCase()); // /mode /whois /topic /nick ...: pass through
  }

  function connect() {
    clearTimeout(timer); registered = false;
    say("*", "Connecting to sekurnet.duckdns.org ...");
    try { ws = new WebSocket(WS_URL); } catch (e) { return fail(); }
    var opened = false;
    ws.onopen = function () { opened = true; send("NICK " + nick); send("USER webchat 0 * :SekurNet web chat"); };
    ws.onmessage = function (ev) { String(ev.data).split(/\r?\n/).forEach(function (l) { if (l) onLine(l); }); };
    ws.onclose = function () {
      if (closing) return say("*", "Disconnected.", "err");
      if (!opened && !registered && tries === 0) return fail();
      if (++tries > 5) return say("*", "Disconnected. Reload the page to try again.", "err");
      var wait = tries * 3000;
      say("*", "Connection lost. Reconnecting in " + wait / 1000 + "s ...", "err");
      timer = setTimeout(function () { wantChan = Object.keys(bufs).filter(function (k) { return k[0] === "#" || k[0] === "&"; }).map(function (k) { return bufs[k].name; }).join(",") || wantChan; connect(); }, wait);
    };
  }
  function fail() {
    app.hidden = true; form.hidden = false;
    err.textContent = "Could not connect. The server may be down, or the browser does not trust its certificate (the WebSocket port needs a valid TLS certificate).";
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault(); err.textContent = "";
    var n = nickIn.value.trim(), c = chanIn.value.trim();
    if (c && c[0] !== "#" && c[0] !== "&") c = "#" + c;
    if (!NICK_RE.test(n)) return (err.textContent = "Nickname: letters, digits and [ ] \\ ` _ ^ { | } -, max 30, not starting with a digit or -.");
    if (!CHAN_RE.test(c)) return (err.textContent = "Channel: start with # and no spaces or commas.");
    try { localStorage.setItem("chat-nick", n); localStorage.setItem("chat-chan", c); } catch (x) {}
    nick = n; wantChan = c; closing = false; tries = 0; bufs = {}; active = "*"; draw();
    form.hidden = true; app.hidden = false; input.focus();
    connect();
  });
  $("send").addEventListener("submit", function (e) {
    e.preventDefault(); var t = input.value.trim(); input.value = ""; if (t) command(t);
  });
  window.addEventListener("beforeunload", function () { closing = true; if (ws) ws.close(); });
})();
