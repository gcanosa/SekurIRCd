#!/usr/bin/env python3
"""SekurIRCd config generator (Python 3.8+, stdlib only). The terminal twin of the web wizard
(https://gcanosa.github.io/SekurIRCd/docs/wizard.html).

Asks a few questions, then writes a complete sekurircd.toml and, if you run services (NickServ +
ChanServ), a services.toml whose link name/password match it, and, with the Protection bundle on,
a protection.toml (connection caps, flood guard, DNSBL, spam protection, proxy scanner), and with the
stats panel on, stats/stats.toml (stats/netstats.py, next to services). Passwords are stored as scrypt
hashes wherever the server allows it; files are written 0600, an existing file is backed up first,
and tools/confcheck.py (syntax, both daemons' --check, keys vs the templates, permissions) must
accept the result without errors, or the old files are put back.

  tools/makeconf.py                       write config/sekurircd.toml (+ services/services.toml)
  tools/makeconf.py -c my.toml -s svc.toml   other paths
  tools/makeconf.py --print               write nothing, print both files
  sekurircd --makeconf                    the same, started from the ircd binary
"""
import argparse, getpass, os, re, secrets, shutil, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from upgrade import ROOT, bold, dim, red, green, yellow  # noqa: E402
from linkmgmt import ask, yes, pick, chk_name, chk_port, scrypt_hash  # noqa: E402

LEVELS = ["INFO", "WARNING", "DEBUG", "ERROR"]


def q(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def arr(items):
    return "[" + ", ".join(q(x) for x in items) + "]"


def split(s):
    return [x for x in re.split(r"[,\s]+", s) if x]


def norm_fp(s):
    """"sha256:AB:CD..." / 64 hex digits -> "sha256:<lowercase hex>", or None if it isn't a SHA-256 fingerprint."""
    h = re.sub(r"^sha256:", "", s.strip(), flags=re.I).replace(":", "").lower()
    return "sha256:" + h if re.fullmatch(r"[0-9a-f]{64}", h) else None


def cert_fingerprint(path):
    """SHA-256 fingerprint of a PEM certificate file ("sha256:..."), or None (no openssl, no file)."""
    if not (shutil.which("openssl") and os.path.exists(path)):
        return None
    r = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256"], capture_output=True, text=True)
    return norm_fp(r.stdout.split("=", 1)[1]) if r.returncode == 0 and "=" in r.stdout else None


def render(a):
    """Answers dict -> (sekurircd.toml text or None, services.toml text or None). Pure: no prompts, no I/O.
    a["svc_where"]: "here" (services next to the ircd, the default), "remote" (this server is the hub of services that run on
    another machine: the second text is THEIR services.toml) or "only" (this machine runs only the services daemon: no ircd text)."""
    if a.get("svc_where") == "only":
        return None, render_services(a)
    L = ["# sekurircd.toml written by tools/makeconf.py",
         "# Every key not listed here uses its built-in default (see config/sekurircd.template.toml).", "",
         "[server]", f"name = {q(a['name'])}", f"network = {q(a['network'])}"]
    if a.get("sid"): L.append(f"sid = {q(a['sid'])}")
    L += [f"bind = {q(a['bind'])}", f"port = {a['port']}"]
    if a.get("ipv6"): L.append("ipv6 = true")

    L += ["", "[security]", f"host_masking = {str(a['cloak']).lower()}"]
    if a["cloak"]:
        L += ["# Keep this secret identical on every linked server, and out of version control.",
              f"host_masking_secret = {q(a['cloak_secret'])}"]
    L += [f"default_user_modes = {q(a['umodes'])}", f"oper_modes = {q(a['omodes'])}",
          f"klines_file = {q('klines.json' if a['klines'] else '')}",
          f"protection_file = {q('protection.toml' if a['protect'] else '')}"]
    if a.get("operjoin"): L.append(f"oper_auto_join = {q(a['operjoin'])}")

    if a.get("ws"):
        L += ["", "[websocket]", "enabled = true", f"port = {a['ws_port']}", f"tls = {str(a['ws_tls']).lower()}"]
        if a.get("ws_proxies"): L.append(f"trusted_proxies = {arr(a['ws_proxies'])}")

    L += ["", "[tls]", f"enabled = {str(a['tls']).lower()}"]
    if a["tls"]:
        L += [f"port = {a['tls_port']}", f"cert_file = {q(a['cert'])}", f"key_file = {q(a['key'])}"]

    if a.get("dbg"):
        L += ["", "[debug_channel]", "enabled = true", f"name = {q(a['dbg'])}", 'min_level = "WARNING"']
    if a.get("statsline"):  # read even with the channel off: every server's numbers for the network's stats panel
        if not a.get("dbg"): L += ["", "[debug_channel]", "enabled = false"]
        L += ["# Users, bans, DNSBL/scanner/spam filter, CPU and memory every 5 minutes, network-wide (stats panel).",
              "stats_interval = 300"]

    L += ["", "[messages]", 'motd = "ircd.motd"', 'oper_motd = "oper.motd"', 'rules = "ircd.rules"',
          f"history_size = {a['hist']}"]
    L += ["", "[logging]", "enabled = true", 'directory = "logs"', f"level = {q(a['loglevel'])}", 'file = "sekurircd.log"']
    L += ["", "[channels]", 'default_modes = "nt"', f"auto_join = {arr(a['autojoin'])}"]

    for o in a["opers"]:
        L += ["", "[[operators]]", f"name = {q(o['name'])}", f"password_hash = {q(o['hash'])}", f"hosts = {arr(o['hosts'])}"]

    if a.get("email"):
        L += ["", "[admin]", f"email = {q(a['email'])}"]

    if a.get("svc_where") == "remote":
        L += ["", "# NickServ/ChanServ run on another machine and link over TLS: this link carries every IDENTIFY and SASL password.",
              "# With [links] tls on, every other server that links here has to use TLS too (it reuses the [tls] certificate).",
              "[links]", "enabled = true", 'mode = "hub"', "tls = true", f"bind = {q(a['link_bind'])}", f"port = {a['link_port']}",
              "", "# The services daemon: hash of the plain [link] password in the services machine's services.toml.",
              "[[links.peers]]", f"name = {q(a['svc_name'])}", f"password_hash = {q(a['svc_hash'])}", f"allowed_ips = {arr(a['svc_ips'])}"]
        if a.get("svc_pin"): L += ["# Only the services daemon's own certificate gets in.", f"fingerprint = {q(a['svc_pin'])}"]
        return "\n".join(L) + "\n", render_services(a)
    if not a["svc"]:
        return "\n".join(L) + "\n", None

    L += ["", "[links]", "enabled = true", 'mode = "hub"',
          "# 127.0.0.1 = only local services can link; use 0.0.0.0 to accept other servers.",
          f"bind = {q('0.0.0.0' if a['other_links'] else '127.0.0.1')}", f"port = {a['link_port']}",
          "", "# The services daemon: hash of the plain [link] password in services.toml.",
          "[[links.peers]]", f"name = {q(a['svc_name'])}", f"password_hash = {q(a['svc_hash'])}", 'allowed_ips = ["127.0.0.1"]']
    return "\n".join(L) + "\n", render_services(a)


def render_services(a):
    """services.toml text. Next to the ircd it links on 127.0.0.1; for a hub on another machine it links over TLS."""
    remote = a.get("svc_where", "here") != "here"
    if remote:
        S = ["# services.toml written by tools/makeconf.py (bin/services: NickServ + ChanServ)",
             "# This daemon runs on its own machine and links to the hub over TLS: the link carries every IDENTIFY and SASL password.", "",
             "[link]", "# The hub's link listener ([links] port in its sekurircd.toml), not its client port.",
             f"host = {q(a['hub_host'])}", f"port = {a['link_port']}",
             "# Must match the hub's [[links.peers]] entry, and stay plain here (this side sends it).",
             f"name = {q(a['svc_name'])}", f"password = {q(a['svc_pass'])}",
             "tls = true", "# Never send a password in plain text to another machine.", "require_tls = true"]
        if a.get("hub_pin"): S += ["# The hub's certificate, pinned; checked before the password is sent.", f"fingerprint = {q(a['hub_pin'])}"]
        elif a.get("hub_ca"): S += ["# No pin: the hub's certificate must verify against this CA bundle, for the name in host.", f"ca_file = {q(a['hub_ca'])}"]
        elif a.get("hub_pin_want"): S += ["# FILL THIS IN: the hub's certificate fingerprint (on the hub: openssl x509 -in <its cert> -noout -fingerprint -sha256).",
                                          '#fingerprint = "sha256:..."']
        else: S += ["# No pin: the hub's certificate must verify against the system CAs, for the name in host."]
        if a.get("svc_cert"): S += ["# This daemon's own certificate: the hub pins it.", f"cert = {q(a['svc_cert'])}", f"key = {q(a['svc_key'])}"]
        S += [""]
    else:
        S = ["# services.toml written by tools/makeconf.py (bin/services: NickServ + ChanServ)", "",
             "[link]", "# The ircd's link listener, not its client port.", 'host = "127.0.0.1"', f"port = {a['link_port']}",
             "# Must match the [[links.peers]] entry in sekurircd.toml, and stay plain here (this side sends it).",
             f"name = {q(a['svc_name'])}", f"password = {q(a['svc_pass'])}", ""]
    S += ["[chanserv]", 'nick = "ChanServ"', 'user = "ChanServ"', f"host = {q(a['svc_name'])}",
         'realname = "Channel Registration Service"', f"founder_mode = {q(a['founder'])}", f"expire_days = {a.get('cs_expire', 0)}",
         "", "[nickserv]", f"enabled = {str(a['ns']).lower()}"]
    if a["ns"]:
        S += ['nick = "NickServ"', f"network = {q(a['network'])}", f"enforce_nicks = {str(a['enforce']).lower()}", "enforce_grace = 60"]
        if a.get("admins"): S.append(f"admins = {arr(a['admins'])}")
        S += ["# Drop accounts nobody logged in to for this many days (0 = never).", f"expire_days = {a.get('ns_expire', 0)}"]
    S += ["", "[storage]", "# Relative to the directory bin/services runs from.", 'path = "chanserv.json"', "backup_count = 5"]
    return "\n".join(S) + "\n"


EFNET_ZONE = ["[[blacklist.zone]]", "# EFnet RBL: IRC-focused (open proxies, drones, spam hosts), free, no query limits.",
              'name = "rbl.efnetrbl.org"', 'type = "reply"', "ban_unknown = true",
              'reason = "Blacklisted (%r) -- for more information, visit https://rbl.efnetrbl.org/?i=%i"',
              'replies = ["1:open proxy", "2:spamtrap666", "3:spamtrap50", "4:TOR", "5:drones / flooding"]']


def render_protection(a):
    """Answers -> protection.toml text, or None when the Protection bundle is off."""
    if not a["protect"]:
        return None
    P = ["# protection.toml written by tools/makeconf.py (the Protection bundle).",
         "# Every option is documented in config/protection.template.toml. Edit, then /REHASH.", "",
         "[exempt]", f"ips = {arr(a['exempt'])}", "",
         "[connection]", f"max_connections = {a['max_conn']}", f"max_connections_per_ip = {a['max_per_ip']}",
         f"connect_flood_max = {a['cflood']}", "connect_flood_window = 10.0", 'connect_flood_ban_duration = "10m"', "",
         "[flood]", f"max_msgs = {a['flood']}", "window = 1.0", "",
         "[spam]", f"enabled = {str(a['spam']).lower()}"]
    if a["spam"]:
        P += [f"limit_action = {q(a['spam_action'])}", 'filters_file = "spamfilters.conf"']
    P += ["", "[blacklist]", f"enabled = {str(a['dnsbl']).lower()}"]
    if a["dnsbl"]:
        P += [f"action = {q(a['dnsbl_action'])}", 'ban_duration = "1d"', "timeout = 5.0", "", *EFNET_ZONE]
    P += ["", "[scanner]", f"enabled = {str(a['scan']).lower()}"]
    if a["scan"]:
        P += [f"action = {q(a['scan_action'])}", 'ban_duration = "1d"',
              'protocols = ["http:80", "http:8080", "http:3128", "http:6588", "httppost:80", "httppost:8080", "socks4:1080", "socks5:1080"]', "",
              "[scanner.target]", f"ip = {q(a['scan_ip'])}", f"port = {a['port']}"]
    return "\n".join(P) + "\n"


def private_ip(ip):
    return re.match(r"(10|127)\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.", ip) is not None


# --- questions -----------------------------------------------------------------

def chk_sid(s):
    return None if not s or re.fullmatch(r"[0-9][0-9A-Z]{2}", s) else "3 characters: a digit, then two of 0-9 A-Z (e.g. 0AB)"


def chk_modes(s):
    return None if re.fullmatch(r"\+?[A-Za-z]*", s) else "mode letters only"


def chk_chans(s):
    return None if all(c[0] in "#&" for c in split(s)) else "channel names start with #"


def render_stats(a):
    """Answers -> stats/stats.toml text (the stats panel, stats/netstats.py), or None when it's off."""
    if not a.get("stats"):
        return None
    S = ["# stats.toml written by tools/makeconf.py (the stats panel: stats/netstats.py, collector in bin/services).",
         "# Every option is documented in stats/stats.template.toml. Logins: stats/netstats.py --user --status.", "",
         "[collector]", "enabled = true", "sample_seconds = 60", 'log = "events.log"', "",
         "[storage]", 'database = "stats.db"', "retention_days = 365", "",
         "[http]", "enabled = true", f"network_name = {q(a['network'])}", f"bind = {q(a['stats_bind'])}",
         f"port = {a['stats_port']}", f"tls_cert = {q(a.get('stats_cert', ''))}", f"tls_key = {q(a.get('stats_key', ''))}",
         f"public = {str(a['stats_public']).lower()}", f"hostname = {q(a.get('stats_host', ''))}", "",
         "[export]", 'public_html = ""', 'admin_html = ""', "",
         "[geoip]", 'file = "dbip-city-lite.csv.gz"', "",
         "[health]", f"ports = [{a['port']}{', ' + str(a['tls_port']) if a['tls'] else ''}]",
         f"tls_ports = [{a['tls_port'] if a['tls'] else ''}]", "interval = 300", "timeout = 5"]
    for u in a.get("stats_users", []):
        S += ["", "[[users]]", f"name = {q(u['name'])}", f"password = {q(u['hash'])}", f"role = {q(u['role'])}"]
    return "\n".join(S) + "\n"


def section(t):
    print("\n" + bold(f"-- {t} " + "-" * max(0, 50 - len(t))))


def password(prompt):
    while True:
        try:
            p1 = getpass.getpass(f"{prompt}: ")
            if not p1 or re.search(r"\s", p1): print(red("  not empty, no spaces")); continue
            if p1 == getpass.getpass("Again: "): return p1
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(1)
        print(red("  they don't match"))


def chk_fp(s):
    return None if norm_fp(s) else "a SHA-256 fingerprint: 64 hex digits (\"sha256:\" and ':' allowed)"


def chk_ips(s):
    ips = split(s)
    return None if ips and all(re.fullmatch(r"[0-9A-Fa-f:.*?/]+", x) for x in ips) else "one or more IP addresses (a CIDR or a * glob works too)"


def services_options(a):
    """NickServ / ChanServ choices: they go into services.toml wherever the daemon runs."""
    a["ns"] = yes("NickServ (accounts and SASL)?", True)
    a["enforce"] = a["ns"] and yes("Enforce nick ownership (rename to Guest after 60s)?", False)
    a["admins"] = split(ask("Services admins, by account name (empty = none)", "")) if a["ns"] else []
    days = lambda s: None if s.isdigit() and int(s) <= 3650 else "a number of days, 0..3650"
    a["ns_expire"] = int(ask("Drop accounts nobody logged in to for how many days? (0 = never)", "0", days)) if a["ns"] else 0
    a["cs_expire"] = int(ask("Drop channel registrations unused for how many days? (0 = never)", "0", days))
    a["founder"] = ["o", "q"][pick("Channel founder rank", ["o: channel op (@)", "q: channel owner (~)"], 1)]


def tls_client_options(a):
    """How the services daemon's TLS link to a hub on another machine is judged (services.toml [link])."""
    how = pick("The hub's certificate is checked by", ["its SHA-256 fingerprint (a pin: best for a self-signed certificate)",
                                                      "a CA this machine trusts, and the hub's name (a certificate from a CA)"], 1)
    if how == 0:
        fp = ask("Hub certificate fingerprint (empty = fill it in later)", "", lambda s: chk_fp(s) if s else None)
        a["hub_pin"] = norm_fp(fp) if fp else ""
        a["hub_pin_want"] = not a["hub_pin"]
    else:
        ca = ask("CA bundle file (empty = this machine's system CAs)", "")
        a["hub_ca"] = ca


def interview_services_only(a):
    """This machine runs only the services daemon, linked over TLS to a hub elsewhere: services.toml and nothing else."""
    section("the hub")
    print(dim("  Ask the hub's operator for its address, link port, and the services entry in its [[links.peers]]\n"
              "  (name and password). The link carries every IDENTIFY and SASL password, so it uses TLS."))
    a["hub_host"] = ask("Hub address (the name or IP of the server that runs sekurircd)", None, lambda s: None if s and " " not in s else "an address")
    a["link_port"] = int(ask("Hub link port ([links] port in its sekurircd.toml)", "7000", chk_port))
    a["svc_name"] = ask("Services name (the hub's [[links.peers]] name)", "services.sekurircd.local", chk_name)
    a["svc_pass"] = password("Link password (the hub's [[links.peers]] password)")
    a["network"] = ask("Network name", "ExampleNet", lambda s: None if s and " " not in s else "one word")
    tls_client_options(a)
    if yes("Present a certificate of this daemon's own, so the hub can pin it?", False):
        a["svc_cert"] = ask("Certificate file (relative to services.toml)", "tls/services.crt")
        a["svc_key"] = ask("Key file", "tls/services.key")
    section("services (NickServ + ChanServ)")
    a["svc"] = True
    services_options(a)
    a["stats"] = False
    print(dim("  The stats panel isn't set up here: it needs the ircd's ports and certificate. See stats/stats.template.toml."))
    return a


def interview():
    a = {}
    section("what this machine runs")
    a["svc_where"] = ["here", "remote", "only"][pick("This machine runs", [
        "an IRC server, with NickServ/ChanServ next to it (the usual setup)",
        "an IRC server whose NickServ/ChanServ run on another machine (this one is their hub)",
        "only the NickServ/ChanServ daemon, linked to an IRC server on another machine"], 1)]
    if a["svc_where"] == "only":
        return interview_services_only(a)
    section("server")
    a["name"] = ask("Server name (with a dot)", "irc.example.org", chk_name)
    a["network"] = ask("Network name", "ExampleNet", lambda s: None if s and " " not in s else "one word")
    a["sid"] = ask("Server ID for linking (empty = derived from the name)", "", lambda s: chk_sid(s.upper())).upper()
    a["bind"] = ask("Bind address (0.0.0.0 = all interfaces)", "0.0.0.0")
    a["port"] = int(ask("Plaintext port", "6667", chk_port))
    a["ipv6"] = yes("Also listen on IPv6?", False)
    if a["svc_where"] == "remote":
        a["leaf"] = False  # the hub of the services is not a leaf
    else:
        print(dim("  A leaf joins an existing network through its hub, and uses the hub's NickServ/ChanServ (and SASL)."))
        a["leaf"] = yes("Is this a leaf of an existing network (its hub runs services)?", False)

    section("tls")
    a["tls"] = True if a["svc_where"] == "remote" else yes("Enable TLS (port 6697)?", True)
    if a["svc_where"] == "remote":
        print(dim("  On: services link over TLS, with this server's certificate."))
    if a["tls"]:
        a["tls_port"] = int(ask("TLS port", "6697", chk_port))
        a["cert"] = ask("Certificate file (relative to the config's directory)", "tls/cert.pem")
        a["key"] = ask("Key file", "tls/key.pem")

    section("websocket")
    a["ws"] = yes("Accept browser clients over WebSocket?", False)
    if a["ws"]:
        a["ws_port"] = int(ask("WebSocket port", "8080", chk_port))
        a["ws_tls"] = a["tls"] and yes("Serve wss:// with the TLS certificate?", True)
        a["ws_proxies"] = split(ask("Trusted reverse proxy IPs (empty = none)", ""))

    section("privacy & security")
    a["cloak"] = yes("Hide user IPs behind a cloak?", True)
    a["cloak_secret"] = secrets.token_urlsafe(24)
    if a["cloak"] and a["leaf"]:  # cloaks must match across the network: a leaf takes the hub's secret
        theirs = ask("The hub's [security] host_masking_secret (tools/linkmgmt.py prints it; empty = make one, copy it to the hub)", "")
        a["cloak_secret"] = theirs or a["cloak_secret"]
    a["protect"] = yes("Use the Protection bundle (DNSBL, proxy scanner, limits)?", True)
    a["klines"] = yes("Keep K/G/Z-lines across restarts (klines.json)?", True)
    a["umodes"] = ask("Default user modes", "iw", chk_modes)
    a["omodes"] = ask("Oper modes", "+osw", chk_modes)

    if a["protect"]:
        num = lambda s: None if s.isdigit() else "a number (0 = off)"
        section("protection (protection.toml)")
        a["max_conn"] = int(ask("Most connections in total (0 = unlimited)", "0", num))
        a["max_per_ip"] = int(ask("Most connections from one IP (0 = unlimited)", "0", num))
        a["cflood"] = int(ask("Z-line an IP that connects more than N times in 10 seconds (0 = off)", "5", num))
        a["flood"] = int(ask("Disconnect a client sending more than N lines per second", "20",
                             lambda s: None if s.isdigit() and int(s) > 0 else "a number above 0"))
        a["exempt"] = split(ask("IPs never DNSBL-checked or scanned (globs)", "127.*"))
        a["dnsbl"] = yes("Check new clients against the EFnet DNSBL (open proxies, drones)?", True)
        if a["dnsbl"]:
            a["dnsbl_action"] = ["zline", "kline", "reject"][pick("A listed client gets", ["Z-line for 1 day", "K-line for 1 day", "refused, no ban"], 1)]
        a["spam"] = yes("Spam protection (new-user PM lock, filters, target limits)?", False)
        if a["spam"]:
            a["spam_action"] = ["warn", "block", "kill", "zline"][pick("When a client hits the limits",
                ["warn opers only (start here)", "block the message", "disconnect", "disconnect + Z-line 1h"], 1)]
        a["scan"] = yes("Open-proxy scanner (connects back to clients; check your host's policy)?", False)
        if a["scan"]:
            a["scan_ip"] = ask("This server's PUBLIC IPv4 address", None,
                               lambda s: "an IPv4 address" if not re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", s)
                               else "must be public, or the scanner never finds anything" if private_ip(s) else None)
            a["scan_action"] = ["reject", "zline"][pick("A confirmed proxy gets", ["refused, no ban (watch first)", "Z-line for 1 day"], 1)]

    section("channels")
    a["autojoin"] = split(ask("Auto-join channels (empty = none)", "", chk_chans))
    a["hist"] = int(ask("History lines per channel (0-500, 0 = off)", "50",
                        lambda s: None if s.isdigit() and int(s) <= 500 else "0-500"))

    section("operators")
    a["opers"] = []
    while yes("Add an operator?" if not a["opers"] else "Add another operator?", not a["opers"]):
        name = ask("  Login name", "admin" if not a["opers"] else None, lambda s: None if re.fullmatch(r"\S+", s) else "no spaces")
        pw = password("  Password")
        print(dim("  hashing..."))
        hosts = split(ask("  Allowed from (ident@host masks)", "*@*"))
        a["opers"].append({"name": name, "hash": scrypt_hash(pw), "hosts": hosts})
    a["operjoin"] = ask("Oper auto-join channel (empty = none)", "", chk_chans) if a["opers"] else ""
    a["dbg"] = ask("Oper-only debug channel with the live server log (empty = none)", "", chk_chans) if a["opers"] else ""

    section("admin & logging")
    a["email"] = ask("Admin contact email (empty = none)", "")
    a["loglevel"] = LEVELS[pick("Log level", LEVELS, 1)]

    section("services (NickServ + ChanServ)")
    if a["leaf"]:
        print(dim("  Skipped: a leaf uses its hub's NickServ/ChanServ (and SASL) over the link. A second services daemon\n"
                  "  would be refused by the network."))
        a["svc"] = False
        section("stats panel")
        print(dim("  The network's stats panel runs next to the hub's services; a leaf only reports its own numbers."))
        a["statsline"] = yes("Report this server's CPU, memory and protection numbers to the network (stats_interval)?", True)
        return a
    if a["svc_where"] == "remote":
        section("services on another machine")
        print(dim("  This server is the hub of a services daemon that runs elsewhere (run this wizard there and choose \"only the\n"
                  "  NickServ/ChanServ daemon\"). Their link uses TLS, and with [links] tls on, every other server that links here must too."))
        a["svc"] = True
        a["link_bind"] = ask("Address the link listener binds to (0.0.0.0 = all interfaces)", "0.0.0.0")
        a["link_port"] = int(ask("Link port (the services machine dials it; outside 6660-7000 gets less scanner noise)", "17000", chk_port))
        a["hub_host"] = ask("Address the services machine reaches this server at", a["name"], lambda s: None if s and " " not in s else "an address")
        a["svc_name"] = ask("Services name", "services.sekurircd.local",
                            lambda s: chk_name(s) or ("must differ from the server name" if s == a["name"] else None))
        a["svc_ips"] = split(ask("The services machine's IP address(es) (the hub only accepts them)", None, chk_ips))
        a["svc_pass"] = secrets.token_urlsafe(24)
        a["svc_hash"] = scrypt_hash(a["svc_pass"])
        print(dim("  The services machine will judge this server's certificate. A self-signed one is best pinned by its fingerprint\n"
                  "  (made after the certificate exists); one from a CA is checked by name."))
        how = pick("The services machine checks this server's certificate by", ["its fingerprint (a pin)", "a CA it trusts, and the name above"], 1)
        a["hub_pin_want"] = how == 0
        pin = ask("Fingerprint of the services machine's own certificate, so this hub pins it (empty = password only)", "",
                  lambda s: chk_fp(s) if s else None)
        if pin:
            a["svc_pin"] = norm_fp(pin)
            a["svc_cert"], a["svc_key"] = "tls/services.crt", "tls/services.key"
        services_options(a)
        section("stats panel")
        print(dim("  The panel runs next to services; this server only reports its numbers to it."))
        a["statsline"] = yes("Report this server's CPU, memory and protection numbers to the network (stats_interval)?", True)
        return a
    print(dim("  One services daemon per network, normally next to the hub. On a leaf whose hub already runs them, answer n:\n"
              "  the leaf reaches the hub's NickServ/ChanServ (and SASL) over the link. Two would collide."))
    a["svc"] = yes("Run services (accounts, SASL, nick and channel registration)?", True)
    if a["svc"]:
        a["link_port"] = int(ask("Link port (the ircd's link listener)", "7000", chk_port))
        a["svc_name"] = ask("Services name", "services.sekurircd.local",
                            lambda s: chk_name(s) or ("must differ from the server name" if s == a["name"] else None))
        a["svc_pass"] = secrets.token_urlsafe(24)
        a["svc_hash"] = scrypt_hash(a["svc_pass"])
        a["other_links"] = yes("Will this server also link to other servers?", False)
        services_options(a)

        section("stats panel (stats/stats.toml)")
        print(dim("  A web page for admins: world map of the servers, users over time, splits and their reasons, uptime,\n"
                  "  services, protection (DNSBL, proxy scanner, spam filter), bans and health checks. Collected by services."))
        a["stats"] = yes("Enable the network stats panel?", False)
        if a["stats"]:
            a["statsline"] = True
            a["stats_port"] = int(ask("Panel port", "8089", chk_port))
            print(dim("  127.0.0.1 = only through a reverse proxy (nginx/caddy) or an SSH tunnel; 0.0.0.0 = open to the internet."))
            a["stats_bind"] = ask("Panel bind address", "127.0.0.1")
            if a["stats_bind"] not in ("127.0.0.1", "::1", "localhost") and a["tls"] and \
                    yes("Serve the panel over HTTPS with the ircd's TLS certificate?", True):
                cfgdir = os.path.join(ROOT, "config")  # stats.toml paths are relative to stats/
                rel = lambda p: os.path.relpath(p if os.path.isabs(p) else os.path.join(cfgdir, p), os.path.join(ROOT, "stats"))
                a["stats_cert"], a["stats_key"] = rel(a["cert"]), rel(a["key"])
            if a["stats_bind"] in ("127.0.0.1", "::1", "localhost"):
                print(dim("  A hostname (e.g. stats.example.net) gets you the Caddy config for https://hostname/ (Caddy fetches the certificate)."))
                a["stats_host"] = ask("Panel hostname, through a reverse proxy (empty = none)", "",
                                      lambda s: None if not s or re.fullmatch(r"([A-Za-z0-9-]+\.)+[A-Za-z0-9-]{2,63}", s) else "a host name like stats.example.net").lower()
            if a["stats_bind"] not in ("127.0.0.1", "::1", "localhost") and not a.get("stats_cert"):
                print(yellow("  ! without HTTPS the panel's logins cross the network in clear text: prefer 127.0.0.1 behind an\n"
                             "    HTTPS reverse proxy, or set tls_cert/tls_key in stats/stats.toml"))
            a["stats_public"] = yes("Let anyone see the viewer page without logging in (no IPs, no security data)?", False)
            a["stats_users"] = []
            name = ask("  Admin login name for the panel", "admin", lambda s: None if re.fullmatch(r"[A-Za-z0-9_.@-]{1,40}", s) else "letters, digits, _ . @ -")
            pw = password("  Panel password")
            print(dim("  hashing..."))
            a["stats_users"].append({"name": name, "hash": scrypt_hash(pw), "role": "admin"})
            print(dim("  More logins later: stats/netstats.py --user --admin|--viewer --add NAME"))
    return a


# --- writing -------------------------------------------------------------------

def check(binary, path):
    exe = os.path.join(ROOT, "bin", binary)
    if not os.access(exe, os.X_OK):
        exe = shutil.which(binary)
    if not exe:
        print(yellow(f"  ! {binary} not built, skipped its --check (run make)")); return True
    r = subprocess.run([exe, "--config", path, "--check"], capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.abspath(path)))
    print(("  " + green("✔ ") if r.returncode == 0 else "  " + red("✘ ")) + (r.stdout + r.stderr).strip())
    return r.returncode == 0


def confcheck(files, svc_path, has_ircd=True):
    """Validate with tools/confcheck.py: TOML syntax, the daemons' own --check, keys against the templates, plain-text
    passwords and (default paths) file permissions. Its -c covers one sekurircd.toml only, so other paths get the
    services daemon's own --check next to it."""
    if not has_ircd:  # services alone: confcheck wants a sekurircd.toml, so the daemon's own --check is the validation
        return check("services", svc_path)
    cmd = [sys.executable, os.path.join(ROOT, "tools", "confcheck.py"), "-q", "--no-banner"]
    custom = os.path.abspath(files[0][0]) != os.path.join(ROOT, "config", "sekurircd.toml") or \
        (svc_path is not None and os.path.abspath(svc_path) != os.path.join(ROOT, "services", "services.toml"))
    r = subprocess.run(cmd + (["-c", files[0][0]] if custom else []), capture_output=True, text=True)
    print("\n".join(l for l in r.stdout.splitlines() if l.strip()))
    ok = r.returncode == 0  # errors refuse; warnings (maybe about files makeconf didn't write) are shown, not fatal
    if custom and svc_path:
        ok = check("services", svc_path) and ok
    return ok


def write_all(files, svc_path, has_ircd=True):
    """files: [(path, text)], sekurircd.toml first. Back up what exists, write 0600, confcheck, restore everything on failure."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backups = []
    for path, text in files:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        bak = None
        if os.path.exists(path):
            bak = f"{path}.bak-{stamp}"
            shutil.copy2(path, bak)
        backups.append((path, bak))
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
            fh.write(text)
        os.chmod(path, 0o600)
    print()
    ok = confcheck(files, svc_path, has_ircd)
    for path, _ in files:
        if os.path.basename(path) == "stats.toml":
            r = subprocess.run([sys.executable, os.path.join(ROOT, "stats", "netstats.py"), "-c", path, "check"],
                               capture_output=True, text=True)
            print(("  " + green("✔ ") if r.returncode == 0 else "  " + red("✘ ")) + (r.stdout + r.stderr).strip())
            ok = ok and r.returncode == 0
    if not ok:
        for path, bak in backups:
            if bak: shutil.move(bak, path)
            else: os.remove(path)
        sys.exit(red("confcheck did not accept the generated config, so nothing was changed. Please report this as a bug."))
    for path, bak in backups:
        print(green(f"  wrote {path}") + (dim(f"  (old file kept as {bak})") if bak else ""))


def write_remote_services(a, cfg_path):
    """The services.toml for the services machine, next to the hub's config: with the hub certificate's fingerprint filled in when
    that was asked for and the certificate exists. -> its path."""
    d = os.path.dirname(os.path.abspath(cfg_path))
    if a.get("hub_pin_want") and not a.get("hub_pin"):
        fp = cert_fingerprint(os.path.join(d, a["cert"]))
        if fp: a = dict(a, hub_pin=fp)
    path = os.path.join(d, "services-remote.toml")
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
        fh.write(render_services(a))
    os.chmod(path, 0o600)
    print(("  " + green("✔ ") if check_quiet("services", path) else "  " + red("✘ ")) + green(f"wrote {path}") + dim("  (for the services machine)"))
    return path, a.get("hub_pin", "")


def check_quiet(binary, path):
    exe = os.path.join(ROOT, "bin", binary)
    if not os.access(exe, os.X_OK): exe = shutil.which(binary)
    if not exe: return True
    return subprocess.run([exe, "--config", path, "--check"], capture_output=True, cwd=os.path.dirname(os.path.abspath(path))).returncode == 0


def extras(a, cfg):
    """A self-signed TLS certificate next to the config, if there's none yet and the user wants one."""
    d = os.path.dirname(os.path.abspath(cfg))
    if a["tls"]:
        cert, key = os.path.join(d, a["cert"]), os.path.join(d, a["key"])
        if not (os.path.exists(cert) and os.path.exists(key)) and shutil.which("openssl") and \
                yes(f"\nNo certificate at {a['cert']} yet. Make a self-signed one now?", True):
            os.makedirs(os.path.dirname(cert), exist_ok=True)
            r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825",
                                "-keyout", key, "-out", cert, "-subj", f"/CN={a['name']}"], capture_output=True, text=True)
            if r.returncode == 0:
                os.chmod(key, 0o600)
                print(green(f"  wrote {cert} and {key}") + dim(f"  (trusted cert instead: tools/mkcert.sh --domain {a['name']})"))
            else:
                print(yellow("  ! openssl failed: " + r.stderr.strip().splitlines()[-1]))


def selftest():
    a = dict(name="irc.test.org", network="TestNet", sid="0AB", bind="127.0.0.1", port=6667, ipv6=False, tls=False,
             ws=True, ws_port=8080, ws_tls=False, ws_proxies=["127.0.0.1"], cloak=True, cloak_secret="s\"x\\",
             protect=True, exempt=["127.*"], max_conn=0, max_per_ip=5, cflood=5, flood=20, dnsbl=True,
             dnsbl_action="zline", spam=True, spam_action="warn", scan=True, scan_ip="203.0.113.7", scan_action="reject",
             klines=True, umodes="iw", omodes="+osw", autojoin=["#lobby"], hist=50,
             opers=[{"name": "admin", "hash": scrypt_hash("pw"), "hosts": ["*@*"]}], operjoin="#opers", dbg="#dbg",
             email="a@b.c", loglevel="INFO", svc=True, link_port=7000, svc_name="services.test.org", svc_pass="p1",
             svc_hash=scrypt_hash("p1"), other_links=False, ns=True, enforce=True, admins=["alice"], founder="q", ns_expire=365, cs_expire=90,
             stats=True, statsline=True, stats_port=8089, stats_bind="0.0.0.0", stats_cert="../config/tls/cert.pem",
             stats_key="../config/tls/key.pem", stats_public=True, tls_port=6697,
             stats_users=[{"name": "admin", "hash": scrypt_hash("pw"), "role": "admin"}])
    ircd, svc = render(a)
    assert svc is not None
    try:
        import tomllib
        t, s = tomllib.loads(ircd), tomllib.loads(svc)
        assert t["security"]["host_masking_secret"] == "s\"x\\" and t["links"]["peers"][0]["name"] == s["link"]["name"]
        assert s["link"]["port"] == t["links"]["port"] and s["chanserv"]["founder_mode"] == "q"
    except ImportError:
        pass
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "s"))
        open(os.path.join(d, "x.toml"), "w").write(ircd)
        open(os.path.join(d, "s", "services.toml"), "w").write(svc)
        x = os.path.join(d, "x.toml")
        open(os.path.join(d, "protection.toml"), "w").write(render_protection(a) or "")
        if "tomllib" in sys.modules:
            pr = tomllib.loads(render_protection(a) or "")
            assert pr["scanner"]["target"]["ip"] == "203.0.113.7" and pr["blacklist"]["zone"][0]["name"] == "rbl.efnetrbl.org"
        assert private_ip("192.168.1.2") and private_ip("172.20.0.1") and not private_ip("203.0.113.7")
        assert check("sekurircd", x) and check("services", os.path.join(d, "s", "services.toml"))
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "confcheck.py"), "-q", "--no-banner", "-c", x],
                           capture_output=True, text=True)
        assert r.returncode == 0 and " ! " not in r.stdout, r.stdout  # confcheck has nothing to say about our output
    assert render(dict(a, svc=False))[1] is None and render_protection(dict(a, protect=False)) is None
    assert render_stats(dict(a, stats=False)) is None
    sys.path.insert(0, os.path.join(ROOT, "stats"))
    import netstats
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "stats.toml")
        open(p, "w").write(render_stats(a))
        c = netstats.load_config(p)
        assert c["users"][0]["role"] == "admin" and c["http"]["public"] and c["network"] == "TestNet"
        assert c["health"]["ports"] == [6667] and c["http"]["tls_cert"].endswith("config/tls/cert.pem")
        open(p, "w").write(render_stats(dict(a, stats_bind="127.0.0.1", stats_host="stats.test.org")))
        assert netstats.load_config(p)["http"]["hostname"] == "stats.test.org"
    if "tomllib" in sys.modules:
        assert tomllib.loads(ircd)["debug_channel"]["stats_interval"] == 300
        assert tomllib.loads(render(dict(a, dbg="", statsline=False))[0]).get("debug_channel") is None
    # services on another machine: this server is the hub (links over TLS), and the services machine gets its own file
    with tempfile.TemporaryDirectory() as d:
        if shutil.which("openssl"):
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-keyout", os.path.join(d, "k.pem"),
                            "-out", os.path.join(d, "c.pem"), "-subj", "/CN=irc.test.org"], capture_output=True, check=True)
            fp = cert_fingerprint(os.path.join(d, "c.pem"))
            assert fp and norm_fp(fp.upper().replace("SHA256:", "")) == fp
        r = dict(a, svc_where="remote", tls=True, tls_port=6697, cert="c.pem", key="k.pem", link_bind="0.0.0.0", link_port=17000,
                 hub_host="irc.test.org", svc_ips=["203.0.113.9"], svc_pin="sha256:" + "ab" * 32, svc_cert="tls/services.crt",
                 svc_key="tls/services.key", hub_pin="sha256:" + "cd" * 32, stats=False)
        ircd, svc = render(r)
        assert "[[links.peers]]" in ircd and "tls = true" in ircd and svc.count("[link]") == 1
        variants = [("pin", r), ("ca", dict(r, hub_pin="", hub_ca="ca.pem", svc_pin="", svc_cert="")),
                    ("later", dict(r, hub_pin="", hub_pin_want=True, svc_pin="", svc_cert="")), ("system", dict(r, hub_pin="", svc_pin="", svc_cert=""))]
        for name, v in variants:
            ircd, svc = render(v)
            x, s = os.path.join(d, f"{name}.toml"), os.path.join(d, f"{name}-services.toml")
            open(x, "w").write(ircd); open(s, "w").write(svc)
            if "tomllib" in sys.modules:
                ti, ts = tomllib.loads(ircd), tomllib.loads(svc)
                peer = ti["links"]["peers"][0]
                assert ti["links"]["tls"] is True and peer["allowed_ips"] == ["203.0.113.9"] and peer["name"] == ts["link"]["name"]
                assert peer.get("fingerprint") == (v["svc_pin"] or None) and ("cert" in ts["link"]) == bool(v["svc_cert"])
                assert ts["link"]["tls"] is True and ts["link"]["require_tls"] is True and ts["link"]["host"] == "irc.test.org"
                assert ts["link"].get("fingerprint") == (v["hub_pin"] or None) and ts["link"].get("ca_file") == (v.get("hub_ca") or None)
            assert check("sekurircd", x) and check("services", s), name
    # only the services daemon: no ircd file at all
    o = dict(svc_where="only", svc=True, hub_host="irc.test.org", link_port=7000, svc_name="services.test.org", svc_pass="p1",
             network="TestNet", hub_pin="sha256:" + "cd" * 32, ns=True, enforce=False, admins=["alice"], ns_expire=0, cs_expire=0, founder="o")
    ircd, svc = render(o)
    assert ircd is None
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "services.toml"), "w").write(svc)
        assert check("services", os.path.join(d, "services.toml"))
        if "tomllib" in sys.modules:
            assert tomllib.loads(svc)["link"]["fingerprint"] == o["hub_pin"] and "[nickserv]" in svc
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description="Write a complete sekurircd.toml (and services.toml) from a few questions.")
    ap.add_argument("-c", "--config", default=os.path.join(ROOT, "config", "sekurircd.toml"), help="sekurircd.toml to write")
    ap.add_argument("-s", "--services", default=os.path.join(ROOT, "services", "services.toml"), help="services.toml to write")
    ap.add_argument("--stats", default=os.path.join(ROOT, "stats", "stats.toml"), help="stats.toml to write (the stats panel)")
    ap.add_argument("--print", action="store_true", help="write nothing, print the files")
    ap.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    o = ap.parse_args()
    if o.selftest: return selftest()
    if not o.no_banner: subprocess.run(["bash", "-c", f'source "{ROOT}/tools/lib.sh"; banner'])
    print("A few questions, then a complete config. Enter keeps the [default]; Ctrl-C quits without writing.")
    print(dim("Prefer a browser? https://gcanosa.github.io/SekurIRCd/docs/wizard.html"))
    exists = [p for p in (o.config, o.services, os.path.join(os.path.dirname(os.path.abspath(o.config)), "protection.toml"),
                          o.stats) if os.path.exists(p)]
    if exists and not o.print:
        print(yellow("\nAlready there (a backup is kept if you overwrite): " + ", ".join(exists)))
    a = interview()
    where = a.get("svc_where", "here")
    ircd, svc = render(a)
    prot = render_protection(a) if ircd else None
    stats = render_stats(a) if ircd else None
    cfgdir = os.path.dirname(os.path.abspath(o.config))
    files = ([(o.config, ircd)] if ircd else []) + ([(o.services, svc)] if svc and where != "remote" else []) + \
        ([(os.path.join(cfgdir, "protection.toml"), prot)] if prot else []) + ([(o.stats, stats)] if stats else [])
    if o.print:
        for path, text in files:
            print("\n" + bold(f"# ---- {path}") + "\n" + text)
        if where == "remote": print("\n" + bold("# ---- services-remote.toml (for the services machine)") + "\n" + svc)
        return
    names = [p for p, _ in files]
    if not yes("\nWrite " + ", ".join(names[:-1]) + (" and " if len(names) > 1 else "") + names[-1] + "?", True):
        sys.exit("Nothing written.")
    write_all(files, o.services if svc and where != "remote" else None, has_ircd=where != "only")
    remote = None
    if where != "only":
        extras(a, o.config)
    if where == "remote":
        remote = write_remote_services(a, o.config)
    print("\n" + bold("Next:"))
    if where == "only":
        print(f"  the hub:       its operator adds this machine to the hub's [[links.peers]] entry for {a['svc_name']} (allowed_ips) and opens the link port")
        if a.get("svc_cert"):
            print(f"  certificate:   openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout {a['svc_key']} -out {a['svc_cert']} -subj /CN={a['svc_name']}")
            print(f"                 openssl x509 -in {a['svc_cert']} -noout -fingerprint -sha256   {dim('(give the hub operator this fingerprint: fingerprint = \"...\" on the entry)')}")
        if a.get("hub_pin_want"):
            print(yellow(f"  ! fill in the hub certificate's fingerprint in {o.services} ([link] fingerprint), or services refuse to link"))
        print(f"  start:         ./sekurircd start   {dim('(no config/sekurircd.toml here, so it manages services only)')}")
        return
    if where == "remote":
        print(f"  services:      copy {remote[0]} to the services machine as services/services.toml, then delete it here (it holds the link password)")
        print(f"                 {dim('there: ./sekurircd start (no config/sekurircd.toml there, so it manages services only)')}")
        print(f"  firewall:      open TCP {a['link_port']} for {', '.join(a['svc_ips'])} only")
        if a.get("hub_pin_want"):
            print(f"  pin:           {remote[1] or yellow('(no certificate yet: openssl x509 -in <cert> -noout -fingerprint -sha256, then [link] fingerprint there)')}")
        if a.get("svc_pin"):
            print(f"  its certificate: on the services machine, {a['svc_cert']} and {a['svc_key']} must be the certificate with fingerprint {a['svc_pin']}")
    if not a["opers"]: print(yellow("  ! no operators: nobody can /OPER until you add one ([[operators]])"))
    print(f"  edit the MOTD: {os.path.join(os.path.dirname(o.config), 'ircd.motd')} (made from the template on first start)")
    if a.get("leaf") or not svc:
        print(f"  link it:       tools/linkmgmt.py add   {dim('(choose: this server dials the hub; paste what it prints on the hub)')}")
        print(f"                 {dim('services stay off here: ./sekurircd status says so; an old services.toml? ./sekurircd disable-services')}")
    if stats:
        scheme = "https" if a.get("stats_cert") else "http"
        url = f"https://{a['stats_host']}/admin/" if a.get("stats_host") else f"{scheme}://{a['stats_bind']}:{a['stats_port']}/admin/"
        print(f"  stats panel:   {url}   {dim('(./sekurircd start runs it; on/off: ./sekurircd enable-stats|disable-stats)')}")
        print(f"                 {dim('map positions: stats/netstats.py geoip-update, or lat/lon per server in ' + o.stats)}")
        sys.path.insert(0, os.path.join(ROOT, "stats"))
        import netstats
        for n in netstats.exposure_notes({"bind": a["stats_bind"], "port": a["stats_port"], "tls_cert": a.get("stats_cert", ""),
                                          "hostname": a.get("stats_host", "")}):
            print("                 " + (yellow(n) if n.startswith("WARNING") else n))
    if os.path.abspath(o.config) == os.path.join(ROOT, "config", "sekurircd.toml"):
        print(f"  start:         ./sekurircd start   {dim('(the daemons, from ' + ROOT + ')')}")
    else:
        print(f"  start:         sekurircd --config {o.config}" + (f"   and   services --config {o.services}" if svc and where != "remote" else ""))


if __name__ == "__main__":
    main()
