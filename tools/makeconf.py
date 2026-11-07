#!/usr/bin/env python3
"""SekurIRCd config generator (Python 3.8+, stdlib only). The terminal twin of the web wizard
(https://gcanosa.github.io/SekurIRCd/docs/wizard.html).

Asks a few questions, then writes a complete sekurircd.toml and, if you run services (NickServ +
ChanServ), a services.toml whose link name/password match it, and, with the Protection bundle on,
a protection.toml (connection caps, flood guard, DNSBL, spam protection, proxy scanner). Passwords are stored as scrypt
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


def render(a):
    """Answers dict -> (sekurircd.toml text, services.toml text or None). Pure: no prompts, no I/O."""
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

    L += ["", "[messages]", 'motd = "ircd.motd"', 'oper_motd = "oper.motd"', 'rules = "ircd.rules"',
          f"history_size = {a['hist']}"]
    L += ["", "[logging]", "enabled = true", 'directory = "logs"', f"level = {q(a['loglevel'])}", 'file = "sekurircd.log"']
    L += ["", "[channels]", 'default_modes = "nt"', f"auto_join = {arr(a['autojoin'])}"]

    for o in a["opers"]:
        L += ["", "[[operators]]", f"name = {q(o['name'])}", f"password_hash = {q(o['hash'])}", f"hosts = {arr(o['hosts'])}"]

    if a.get("email"):
        L += ["", "[admin]", f"email = {q(a['email'])}"]

    if not a["svc"]:
        return "\n".join(L) + "\n", None

    L += ["", "[links]", "enabled = true", 'mode = "hub"',
          "# 127.0.0.1 = only local services can link; use 0.0.0.0 to accept other servers.",
          f"bind = {q('0.0.0.0' if a['other_links'] else '127.0.0.1')}", f"port = {a['link_port']}",
          "", "# The services daemon: hash of the plain [link] password in services.toml.",
          "[[links.peers]]", f"name = {q(a['svc_name'])}", f"password_hash = {q(a['svc_hash'])}", 'allowed_ips = ["127.0.0.1"]']

    S = ["# services.toml written by tools/makeconf.py (bin/services: NickServ + ChanServ)", "",
         "[link]", "# The ircd's link listener, not its client port.", 'host = "127.0.0.1"', f"port = {a['link_port']}",
         "# Must match the [[links.peers]] entry in sekurircd.toml, and stay plain here (this side sends it).",
         f"name = {q(a['svc_name'])}", f"password = {q(a['svc_pass'])}",
         "", "[chanserv]", 'nick = "ChanServ"', 'user = "ChanServ"', f"host = {q(a['svc_name'])}",
         'realname = "Channel Registration Service"', f"founder_mode = {q(a['founder'])}",
         "", "[nickserv]", f"enabled = {str(a['ns']).lower()}"]
    if a["ns"]:
        S += ['nick = "NickServ"', f"network = {q(a['network'])}", f"enforce_nicks = {str(a['enforce']).lower()}", "enforce_grace = 60"]
        if a.get("admins"): S.append(f"admins = {arr(a['admins'])}")
    S += ["", "[storage]", "# Relative to the directory bin/services runs from.", 'path = "chanserv.json"', "backup_count = 5"]
    return "\n".join(L) + "\n", "\n".join(S) + "\n"


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


def interview():
    a = {}
    section("server")
    a["name"] = ask("Server name (with a dot)", "irc.example.org", chk_name)
    a["network"] = ask("Network name", "ExampleNet", lambda s: None if s and " " not in s else "one word")
    a["sid"] = ask("Server ID for linking (empty = derived from the name)", "", lambda s: chk_sid(s.upper())).upper()
    a["bind"] = ask("Bind address (0.0.0.0 = all interfaces)", "0.0.0.0")
    a["port"] = int(ask("Plaintext port", "6667", chk_port))
    a["ipv6"] = yes("Also listen on IPv6?", False)

    section("tls")
    a["tls"] = yes("Enable TLS (port 6697)?", True)
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
    a["svc"] = yes("Run services (accounts, SASL, nick and channel registration)?", True)
    if a["svc"]:
        a["link_port"] = int(ask("Link port (the ircd's link listener)", "7000", chk_port))
        a["svc_name"] = ask("Services name", "services.sekurircd.local",
                            lambda s: chk_name(s) or ("must differ from the server name" if s == a["name"] else None))
        a["svc_pass"] = secrets.token_urlsafe(24)
        a["svc_hash"] = scrypt_hash(a["svc_pass"])
        a["other_links"] = yes("Will this server also link to other servers?", False)
        a["ns"] = yes("NickServ (accounts and SASL)?", True)
        a["enforce"] = a["ns"] and yes("Enforce nick ownership (rename to Guest after 60s)?", False)
        a["admins"] = split(ask("Services admins, by account name (empty = none)", "")) if a["ns"] else []
        a["founder"] = ["o", "q"][pick("Channel founder rank", ["o: channel op (@)", "q: channel owner (~)"], 1)]
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


def confcheck(files, svc_path):
    """Validate with tools/confcheck.py: TOML syntax, the daemons' own --check, keys against the templates, plain-text
    passwords and (default paths) file permissions. Its -c covers one sekurircd.toml only, so other paths get the
    services daemon's own --check next to it."""
    cmd = [sys.executable, os.path.join(ROOT, "tools", "confcheck.py"), "-q", "--no-banner"]
    custom = os.path.abspath(files[0][0]) != os.path.join(ROOT, "config", "sekurircd.toml") or \
        (svc_path is not None and os.path.abspath(svc_path) != os.path.join(ROOT, "services", "services.toml"))
    r = subprocess.run(cmd + (["-c", files[0][0]] if custom else []), capture_output=True, text=True)
    print("\n".join(l for l in r.stdout.splitlines() if l.strip()))
    ok = r.returncode == 0  # errors refuse; warnings (maybe about files makeconf didn't write) are shown, not fatal
    if custom and svc_path:
        ok = check("services", svc_path) and ok
    return ok


def write_all(files, svc_path):
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
    ok = confcheck(files, svc_path)
    if not ok:
        for path, bak in backups:
            if bak: shutil.move(bak, path)
            else: os.remove(path)
        sys.exit(red("confcheck did not accept the generated config, so nothing was changed. Please report this as a bug."))
    for path, bak in backups:
        print(green(f"  wrote {path}") + (dim(f"  (old file kept as {bak})") if bak else ""))


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
             svc_hash=scrypt_hash("p1"), other_links=False, ns=True, enforce=True, admins=["alice"], founder="q")
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
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description="Write a complete sekurircd.toml (and services.toml) from a few questions.")
    ap.add_argument("-c", "--config", default=os.path.join(ROOT, "config", "sekurircd.toml"), help="sekurircd.toml to write")
    ap.add_argument("-s", "--services", default=os.path.join(ROOT, "services", "services.toml"), help="services.toml to write")
    ap.add_argument("--print", action="store_true", help="write nothing, print the files")
    ap.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    o = ap.parse_args()
    if o.selftest: return selftest()
    if not o.no_banner: subprocess.run(["bash", "-c", f'source "{ROOT}/tools/lib.sh"; banner'])
    print("A few questions, then a complete config. Enter keeps the [default]; Ctrl-C quits without writing.")
    print(dim("Prefer a browser? https://gcanosa.github.io/SekurIRCd/docs/wizard.html"))
    exists = [p for p in (o.config, o.services, os.path.join(os.path.dirname(os.path.abspath(o.config)), "protection.toml"))
              if os.path.exists(p)]
    if exists and not o.print:
        print(yellow("\nAlready there (a backup is kept if you overwrite): " + ", ".join(exists)))
    a = interview()
    ircd, svc = render(a)
    prot = render_protection(a)
    files = [(o.config, ircd)] + ([(o.services, svc)] if svc else []) + \
        ([(os.path.join(os.path.dirname(os.path.abspath(o.config)), "protection.toml"), prot)] if prot else [])
    if o.print:
        for path, text in files:
            print("\n" + bold(f"# ---- {path}") + "\n" + text)
        return
    names = [p for p, _ in files]
    if not yes("\nWrite " + ", ".join(names[:-1]) + (" and " if len(names) > 1 else "") + names[-1] + "?", True):
        sys.exit("Nothing written.")
    write_all(files, o.services if svc else None)
    extras(a, o.config)
    print("\n" + bold("Next:"))
    if not a["opers"]: print(yellow("  ! no operators: nobody can /OPER until you add one ([[operators]])"))
    print(f"  edit the MOTD: {os.path.join(os.path.dirname(o.config), 'ircd.motd')} (made from the template on first start)")
    if os.path.abspath(o.config) == os.path.join(ROOT, "config", "sekurircd.toml"):
        print(f"  start:         ./sekurircd start   {dim('(both daemons, from ' + ROOT + ')')}")
    else:
        print(f"  start:         sekurircd --config {o.config}" + (f"   and   services --config {o.services}" if svc else ""))


if __name__ == "__main__":
    main()
