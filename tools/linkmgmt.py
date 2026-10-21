#!/usr/bin/env python3
"""SekurIRCd server-link wizard (Python 3.8+, stdlib only).

Asks a few questions, then writes THIS server's side into its config (after
showing the diff and asking; a backup is kept, and the ircd's own --check must
accept the result or it is restored) and prints the OTHER server's side to
paste there: its [[links.peers]] block, any [links] changes, a fresh shared
password (scrypt hash on the accepting side), and the steps to bring the link up.

  tools/linkmgmt.py                 menu
  tools/linkmgmt.py list            show this server's links
  tools/linkmgmt.py add             link a new server
  tools/linkmgmt.py edit            change a link (password, address, allowed IPs, who dials)
  tools/linkmgmt.py del             remove a link
  tools/linkmgmt.py test            optional network checks for a link: DNS, port open/firewall, TLS
  tools/linkmgmt.py test HOST PORT [--tls]   the same against any host (run it on the other server too); with
                                    --tls it also prints the certificate fingerprint to pin
  tools/linkmgmt.py fingerprint     this server's own certificate fingerprint (what the other side pins)
  tools/linkmgmt.py -c my.toml ...  another sekurircd config
  tools/linkmgmt.py --dry-run ...   change nothing: print this server's side to paste too
"""
import argparse, contextlib, difflib, fnmatch, io, hashlib, json, os, re, secrets, shutil, socket, ssl, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from upgrade import ROOT, SEC_RE, KEY_RE, bold, dim, red, green, yellow, cyan  # noqa: E402
from confcheck import is_comment, is_setting, value_end, toml_str, insert_at  # noqa: E402 -- same line surgery as --fix

try:
    import tomllib  # 3.11+
except ImportError:
    tomllib = None

DEFAULT_PORT = 7000


def read_config(path):
    """{section: {key: value}} plus 'peers': [ {..}, .. ].
    ponytail: single-line values only -- every [server]/[tls]/[links] key is; use tomllib if that ever changes."""
    cfg: dict = {"peers": []}
    sec = None
    for ln in open(path, encoding="utf-8"):
        ln = ln.strip()
        if ln.startswith("[[links.peers]]"):
            sec = {}; cfg["peers"].append(sec); continue
        m = re.match(r"\[([\w.]+)\]$", ln)
        if m:
            sec = cfg.setdefault(m[1], {}); continue
        m = re.match(r"(\w+)\s*=\s*(.+?)\s*(#[^\"\]]*)?$", ln)
        if m and sec is not None:
            v = m[2]
            try: sec[m[1]] = json.loads(v)
            except ValueError: sec[m[1]] = v
    return cfg


def scrypt_hash(pw):
    """Same format and cost as src/crypto.c crypto_hash_password (and `sekurircd --hash-password`)."""
    salt = secrets.token_bytes(16)
    d = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=64, maxmem=32 * 1024 * 1024)
    return f"scrypt$16384$8$1${salt.hex()}${d.hex()}"


def cert_fingerprint(pem_path):
    """'sha256:<hex>' of the first certificate in a PEM file, the form [[links.peers]] fingerprint takes."""
    with open(pem_path) as f:
        return "sha256:" + hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


def own_fingerprint(cfg, path):
    """(fingerprint or None, why not): this server's [tls] certificate, which it presents on links."""
    cert = cfg.get("tls", {}).get("cert_file", "tls/cert.pem")
    cert = os.path.join(os.path.dirname(os.path.abspath(path)), cert)
    try:
        return cert_fingerprint(cert), None
    except (OSError, ValueError) as e:
        return None, f"{cert}: {e}"


def chk_fp(a):
    h = re.sub(r"^sha256:", "", a.lower()).replace(":", "") if a else ""
    return None if not a or re.fullmatch(r"[0-9a-f]{64}", h) else "64 hex digits, as printed by linkmgmt.py fingerprint"


def mode_for(dials, accepts):
    """links.mode a server needs for `dials` outgoing and `accepts` incoming peers (src/config.c rules)."""
    if dials and accepts: return "both"
    if dials: return "leaf" if dials == 1 else "both"   # leaf = exactly one peer, its uplink
    return "hub"


def peer_block(name, pw=None, pw_hash=None, host=None, port=None, ips=None, fp=None):
    out = ["[[links.peers]]", f'name = "{name}"']
    if pw_hash: out.append(f'password_hash = "{pw_hash}"')
    elif pw: out.append(f'password = "{pw}"')
    if fp: out.append(f'fingerprint = "{fp}"')
    if host: out += [f'host = "{host}"', f"port = {port}"]
    if ips: out.append("allowed_ips = " + json.dumps(ips))
    return "\n".join(out)


def links_block(mode, port, tls, pinned=False):
    out = ["[links]", "enabled = true", f'mode = "{mode}"']
    if mode != "leaf": out += ['bind = "0.0.0.0"', f"port = {port}"]
    out.append(f"tls = {'true' if tls else 'false'}")
    if tls and mode != "hub" and not pinned: out.append("#tls_insecure_skip_verify = true   # only if the other side's cert is self-signed")
    return "\n".join(out)


# --- editing this server's config -----------------------------------------------
# Line surgery (confcheck's helpers), so comments and layout survive; only uncommented headers count, so the
# template's #[[links.peers]] examples are never touched.

def headers(lines):
    return [(i, SEC_RE.match(l)[1]) for i, l in enumerate(lines) if SEC_RE.match(l) and not is_comment(l)]


def body_end(lines, start, stop):
    """One past the last setting of the table whose header is lines[start] (comments after it belong to what follows)."""
    end, i = start + 1, start + 1
    while i < stop:
        if is_setting(lines[i]) and not is_comment(lines[i]):
            i = value_end(lines, i) + 1; end = i
        else:
            i += 1
    return end


def peer_spans(lines):
    """[(start, end, name)] of every [[links.peers]] block."""
    hs, out = headers(lines), []
    for n, (i, h) in enumerate(hs):
        if h != "[[links.peers]]": continue
        end = body_end(lines, i, hs[n + 1][0] if n + 1 < len(hs) else len(lines))
        name = next((toml_str(KEY_RE.match(l)[3]) for l in lines[i + 1:end]
                     if KEY_RE.match(l) and not is_comment(l) and KEY_RE.match(l)[2] == "name"), None)
        out.append((i, end, name))
    return out


def set_links_keys(lines, kv):
    """Set [links] key = value for each item (an existing line is replaced, a new one goes after the last setting)."""
    hs = headers(lines)
    at = next((n for n, (_, h) in enumerate(hs) if h == "[links]"), None)
    if at is None:
        pos = peer_spans(lines)[0][0] if peer_spans(lines) else len(lines)  # [links] before its peers
        lines[pos:pos] = ["[links]", *[f"{k} = {v}" for k, v in kv.items()], ""]
        return
    start = hs[at][0]
    stop = hs[at + 1][0] if at + 1 < len(hs) else len(lines)
    for k, v in kv.items():
        for i in range(start + 1, stop):
            m = KEY_RE.match(lines[i])
            if m and not is_comment(lines[i]) and m[2] == k:
                lines[i:value_end(lines, i) + 1] = [f"{k} = {v}"]
                break
        else:
            end = body_end(lines, start, stop)
            lines[end:end] = [f"{k} = {v}"]
        hs = headers(lines); stop = hs[at + 1][0] if at + 1 < len(hs) else len(lines)


def put_peer(lines, block, name=None):
    """Replace the [[links.peers]] block called `name` with `block` (lines), or add it after the last one (or [links])."""
    spans = peer_spans(lines)
    old = next(((a, e) for a, e, n in spans if n == name), None) if name else None
    if old:
        lines[old[0]:old[1]] = block
    elif spans:
        e = spans[-1][1]
        lines[e:e] = ["", *block]
    elif any(h == "[links]" for _, h in headers(lines)):
        e = insert_at(lines, "links")
        lines[e:e] = ["", *block]
    else:
        lines += ["", *block]


def drop_peer(lines, name):
    a, e = next((a, e) for a, e, n in peer_spans(lines) if n == name)
    del lines[a:e]
    while 0 < a < len(lines) and not lines[a - 1].strip() and not lines[a].strip():  # don't leave a double blank line
        del lines[a]
    while lines and a >= len(lines) and not lines[-1].strip():  # nor a blank one at the end of the file
        del lines[-1]


def write_config(path, new):
    """Backup (0600: it may hold passwords), atomic write, then the ircd's own --check; restored if it refuses.
    Returns the backup path, or None (nothing changed)."""
    if tomllib:
        try:
            tomllib.loads(new)
        except tomllib.TOMLDecodeError as e:  # a bug here, never the user's file
            print(red(f"The edited config would not parse ({e}) -- nothing written.")); return None
    bak = f"{path}.pre-linkmgmt-{time.strftime('%Y%m%d-%H%M%S')}"
    n = 1
    while os.path.exists(bak):  # two writes in the same second keep both backups
        n += 1; bak = f"{path}.pre-linkmgmt-{time.strftime('%Y%m%d-%H%M%S')}-{n}"
    shutil.copy2(path, bak); os.chmod(bak, 0o600)
    tmp = path + ".linkmgmt-tmp"
    with open(tmp, "w") as f:
        f.write(new)
    shutil.copymode(path, tmp)
    os.replace(tmp, path)
    binary = os.path.join(ROOT, "bin/sekurircd")
    if os.path.exists(binary):
        r = subprocess.run([binary, "--check", "-c", path], capture_output=True, text=True)
        if r.returncode:
            os.replace(bak, path)
            msg = (r.stdout + r.stderr).strip().splitlines()
            print(red(f"bin/sekurircd --check refused it: {msg[-1] if msg else r.returncode} -- your config was restored."))
            return None
    else:
        print(yellow("bin/sekurircd isn't built, so the result wasn't validated -- run make, then tools/confcheck.py."))
    return bak


def apply_local(path, edit, restart):
    """Run `edit(lines)` on a copy of the config, show the diff, ask, write. False if nothing was written."""
    old = open(path, encoding="utf-8").read()
    lines = old.splitlines()
    edit(lines)
    new = "\n".join(lines) + "\n"
    if new == old:
        print(dim("This server's config already has all of it.\n")); return True
    for l in list(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=1))[2:]:
        print("  " + (green(l) if l.startswith("+") else red(l) if l.startswith("-") else cyan(l) if l.startswith("@@") else dim(l)))
    print()
    if not yes(f"Write this to {rel(path)}?"):
        return False
    bak = write_config(path, new)
    if not bak:
        return False
    print(green(f"Written.") + dim(f"  Backup: {rel(bak)} (delete it once the link works: it may hold the old password)"))
    pidfile = os.path.join(ROOT, "sekurircd.pid")
    if restart:
        print(yellow("This change needs an ircd restart (the link listener / TLS / enabling links): ./sekurircd restart\n"))
    elif os.path.abspath(path) == os.path.join(ROOT, "config/sekurircd.toml") and os.path.exists(pidfile) and \
            yes("Rehash the running ircd now?"):
        r = subprocess.run([os.path.join(ROOT, "bin/sekurircd"), "--rehash", "--pidfile", pidfile], capture_output=True, text=True)
        print(green("Rehashed.\n") if r.returncode == 0 else red(f"Rehash failed: {(r.stdout + r.stderr).strip()} -- /REHASH by hand.\n"))
    else:
        print(dim("Then /REHASH (or bin/sekurircd --rehash).\n"))
    return True


def rel(p):
    """`p` relative to the repo when it's inside it, else absolute."""
    r = os.path.relpath(os.path.abspath(p), ROOT)
    return os.path.abspath(p) if r.startswith("..") else r


def save_remote(name, text):
    """Optionally keep the other server's part in a private file, to copy over instead of pasting."""
    if not yes("Save the other server's part to a file to copy over?", False): return
    f = os.path.join(ROOT, f"link-for-{re.sub(r'[^A-Za-z0-9._-]', '_', name)}.toml")
    with open(os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
        fh.write(text + "\n")
    print(green(f"Saved {rel(f)}") + dim(f" (0600). Copy it: scp {rel(f)} {name}:  -- then delete it "
                                                         "here, it holds the link password.\n"))


# --- prompts -------------------------------------------------------------------

def ask(q, default=None, check=None):
    while True:
        try:
            a = input(f"{q}{dim(f' [{default}]') if default not in (None, '') else ''}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); sys.exit(1)
        a = a or (default if default is not None else "")
        err = check(a) if check else None
        if not err: return a
        print(red("  " + err))


def yes(q, default=True):
    return ask(q + " (y/n)", "y" if default else "n", lambda a: None if a.lower()[:1] in ("y", "n") else "y or n").lower().startswith("y")


def pick(q, options, default=1):
    for i, o in enumerate(options, 1): print(f"  {cyan(str(i))}) {o}")
    return int(ask(q, str(default), lambda a: None if a.isdigit() and 1 <= int(a) <= len(options) else f"1-{len(options)}")) - 1


def chk_name(a):
    if not a or re.search(r"\s", a): return "a server name, no spaces"
    if "." not in a: return "use a dotted name like irc2.example.net (clients treat dotless names oddly)"


def chk_port(a):
    return None if a.isdigit() and 1 <= int(a) <= 65535 else "1-65535"


def chk_pw(a):
    return "no spaces" if re.search(r"\s", a) else None


def chk_ips(a):
    return None if all(re.fullmatch(r"[0-9a-fA-F:.*?/]+", x) for x in a.replace(",", " ").split()) else "IPs or globs, space separated"


# --- actions -------------------------------------------------------------------

def show(cfg):
    peers = cfg["peers"]
    lk = cfg.get("links", {})
    me = cfg.get("server", {}).get("name", "?")
    print(bold(f"\n{me}") + f"  links {'on' if lk.get('enabled') else 'OFF'}, mode {lk.get('mode', 'hub')}, "
          f"port {lk.get('port', DEFAULT_PORT)}, tls {'on' if lk.get('tls') else 'off'}")
    if not peers: print(dim("  no [[links.peers]]"))
    for i, p in enumerate(peers, 1):
        how = f"we dial {p['host']}:{p.get('port', '?')}" if p.get("host") else "it dials us"
        extra = f"  from {', '.join(p['allowed_ips'])}" if p.get("allowed_ips") else ""
        print(f"  {cyan(str(i))}) {p.get('name', '?'):32} {how}{extra}")
    print()


def choose(cfg, verb):
    # the services daemon's link is set in services/services.toml ([link]), not with a second ircd
    peers = [p for p in cfg["peers"] if not p.get("name", "").startswith("services.")]
    if not peers: sys.exit(red("No server links in this config (the services link is managed in services/services.toml)."))
    print(f"\nWhich link to {verb}?")
    return peers[pick("Link", [p.get("name", "?") for p in peers])]


def heading(t):
    print("\n" + bold(cyan("=" * 72)) + "\n" + bold(cyan(t)) + "\n" + bold(cyan("=" * 72)))


def snippet(t):
    print(green(t) + "\n")


def wizard(cfg, path, old=None, dry_run=False):
    """add (old=None) or edit `old`: writes this server's side (unless dry_run) and prints the other server's."""
    me = cfg.get("server", {}).get("name", "")
    lk = cfg.get("links", {})
    others = [p for p in cfg["peers"] if p is not old]
    if "." not in me:
        print(yellow(f"Note: this server's [server] name '{me}' has no dot -- the other side must use it as-is, "
                     "but a dotted name (irc1.example.net) is recommended."))

    name = old["name"] if old else ask("Name of the other server (its [server] name)", None,
                                       lambda a: chk_name(a) or ("already linked" if any(p.get("name") == a for p in others) else None))
    print("\nWho opens the connection?")
    we_dial = pick("Choice", [f"{name} dials {me}  (this server accepts -- usual for a new leaf)",
                              f"{me} dials {name}  ({name} accepts)"], 2 if old and old.get("host") else 1) == 1

    lport = lk.get("port", DEFAULT_PORT)
    if we_dial:
        rhost = ask(f"Public hostname or IP of {name} that this server will connect to", (old or {}).get("host"), lambda a: None if a and " " not in a else "required")
        rport = int(ask(f"Its link port", str(old.get("port", DEFAULT_PORT)) if old else str(DEFAULT_PORT), chk_port))
        ips = None
    else:
        guess = socket.getfqdn()
        rhost = ask(f"Public hostname or IP of THIS server ({me}) that {name} will connect to", guess if "." in guess and not guess.endswith((".arpa", ".local")) else None, lambda a: None if a and " " not in a else "required")
        rport = lport
        cur = " ".join(old.get("allowed_ips", [])) if old else ""
        ips = ask(f"IPs {name} connects from (locks the link port to them; empty = anywhere)", cur, chk_ips).replace(",", " ").split()

    tls = yes("Encrypt the link with TLS? (both sides' [links] tls must match)", bool(lk.get("tls")))
    my_fp = their_fp = None
    if tls and yes("Pin each side's certificate? (recommended: self-signed certs are fine, and a server only links "
                   "if it shows the certificate you pinned)", bool(old and old.get("fingerprint"))):
        my_fp, why = own_fingerprint(cfg, path)
        if not my_fp:
            print(yellow(f"  This server has no certificate to present ({why}) -- set [tls] cert_file/key_file first. "
                         f"{name} won't pin this side."))
        print(dim(f"  {name}'s fingerprint: run tools/linkmgmt.py fingerprint on it"
                  + (f", or tools/linkmgmt.py test {rhost} {rport} --tls from here once it listens" if we_dial else "")))
        their_fp = ask(f"{name}'s certificate fingerprint (empty = don't pin it)", (old or {}).get("fingerprint"), chk_fp) or None
    if old:
        a = ask("New link password (empty = keep the current one, 'gen' = generate)", "", chk_pw)
        pw = secrets.token_hex(24) if a == "gen" else a or old.get("password")  # None: only its hash is known
    else:
        pw = ask("Link password (empty = generate a strong one)", "", chk_pw) or secrets.token_hex(24)
    if we_dial and not pw:  # it used to dial us and we only kept a hash: dialing needs the real password
        pw = secrets.token_hex(24)
        print(yellow(f"  {me} now dials, so it needs the password in clear -- generated a new one (shown at the end)."))

    # --- this server
    dials = sum(1 for p in others if p.get("host")) + we_dial
    accepts = sum(1 for p in others if not p.get("host")) + (not we_dial)
    need_mode = mode_for(dials, accepts)
    heading(f"1) On THIS server ({me}) -- {rel(path)}")
    kv, changes = {}, []
    if not lk.get("enabled"): kv["enabled"] = "true"
    if lk.get("mode", "hub") != need_mode: kv["mode"] = f'"{need_mode}"'
    if bool(lk.get("tls")) != tls:
        kv["tls"] = "true" if tls else "false"
        print(yellow(f"[links] tls = {kv['tls']} applies to ALL links of this server."))
    if need_mode != "leaf" and "port" not in lk: kv["port"] = str(lport)
    if tls and need_mode != "leaf" and not cfg.get("tls", {}).get("enabled"):
        print(yellow("A TLS link listener reuses the client [tls] certificate: set [tls] enabled = true with cert_file/key_file "
                     "first, or the ircd will refuse this config."))
    changes = [f"{k} = {v}" for k, v in kv.items()]
    if we_dial:
        mine = peer_block(name, pw=pw, host=rhost, port=rport, fp=their_fp)
    elif pw:
        mine = peer_block(name, pw_hash=scrypt_hash(pw), ips=ips, fp=their_fp)
    else:  # edit, password kept: keep whatever it has (hash, plain, or only a fingerprint)
        mine = peer_block(name, pw_hash=old.get("password_hash"), pw=old.get("password"), ips=ips, fp=their_fp)
    restart = (not lk.get("enabled")) or "tls" in kv or (lk.get("mode", "hub") == "leaf" and need_mode != "leaf")

    def edit(lines):
        if kv: set_links_keys(lines, kv)
        put_peer(lines, mine.splitlines(), old["name"] if old else None)

    if dry_run or not apply_local(path, edit, restart):
        print("Not written. To do it by hand:" if not dry_run else "")
        if changes:
            print("In [links], set:")
            snippet("\n".join(changes))
        print(f"Replace the [[links.peers]] block with name = \"{name}\" by:" if old else "Add:")
        snippet(mine)

    # --- the other server
    heading(f"2) On the OTHER server ({name}) -- its config/sekurircd.toml (this tool can't reach it: paste these there)")
    print(f"[server] name must be exactly \"{name}\".\n")
    print("Its [links] section (if it already links elsewhere, keep its mode compatible: one dial-out + accepts = \"both\"):")
    theirs_links = links_block("hub" if we_dial else "leaf", rport, tls, pinned=bool(my_fp))
    snippet(theirs_links)
    print(("Replace its block for" if old else "Add") + (f' "{me}":' if old else ":"))
    if we_dial:
        theirs = peer_block(me, pw_hash=scrypt_hash(pw), fp=my_fp)
        snippet(theirs)
        print(dim(f"Optional, on {name}: allowed_ips = [\"<{me}'s public IP>\"] in that block.\n"))
    else:
        theirs = peer_block(me, pw=pw or "<the current password>", host=rhost, port=rport, fp=my_fp)
        snippet(theirs)
    if my_fp or their_fp:
        print(dim("Pinned: the link is refused unless the certificate matches. After renewing a certificate (e.g. a new "
                  "Let's Encrypt cert with a new key), update the other side's fingerprint, then /REHASH.\n"))

    save_remote(name, f"# for {name}, from tools/linkmgmt.py on {me}: merge into its config/sekurircd.toml\n"
                      f"# [server] name must be exactly \"{name}\"\n{theirs_links}\n\n{theirs}")

    # --- next steps
    heading("3) Then")
    if pw:
        print(f"Shared password (store it somewhere safe; only the dialing side keeps it in clear): {bold(pw)}\n")
    listen_side = name if we_dial else me
    steps = [
        f"Check both configs:  tools/confcheck.py",
        f"Open TCP {rport} on {listen_side}'s firewall to the other server.",
        f"{me}: {'restart the ircd (link listener / TLS / enabling links needs it)' if restart else '/REHASH (if not done above)'}",
        f"{name}: restart its ircd (or /REHASH if links were already on with the same port/tls)",
        f"Bring it up: /CONNECT {name if we_dial else me}  on {me if we_dial else name}"
        + "  (autoconnect does it by itself unless set to false)",
        "Verify: /MAP and /LINKS on either side.",
    ]
    for i, s in enumerate(steps, 1): print(f"  {i}. {s}")
    print()
    if yes("Run network checks now? (optional: DNS, ports, firewall, TLS)", False):
        nettest(cfg, name, we_dial, rhost, rport, tls, ips, fresh=True)


# --- network checks (optional) -------------------------------------------------

def probe(host, port, tls=False, timeout=5.0):
    """[(ok, text)] for DNS, TCP and (with tls) the TLS handshake to host:port. ok None = a note, not a failure."""
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except socket.gaierror as e:
        return [(False, f"DNS  {host} does not resolve ({e.strerror}) -- fix the DNS record or use the IP")]
    out = [(True, f"DNS  {host} -> {', '.join(ips)}")]
    for ip in ips:
        where = f"TCP  {ip} port {port}"
        try:
            s = socket.create_connection((ip, port), timeout)
        except ConnectionRefusedError:
            out.append((False, f"{where}: refused -- the host answers but nothing listens on that port "
                               "(ircd not running, links off / not restarted, or another port)")); continue
        except socket.timeout:
            out.append((False, f"{where}: no answer in {timeout:.0f}s -- a firewall drops it (ufw/firewalld/pf, "
                               "or the provider's security group) or the host is down")); continue
        except OSError as e:
            out.append((False, f"{where}: {e.strerror}")); continue
        out.append((True, f"{where}: open"))
        if tls: out.append(tls_check(s, host))
        s.close()
    return out


def tls_check(sock, host):
    peer = sock.getpeername()[:2]
    try:
        with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as t:
            fp = "sha256:" + hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()
            return (True, f"TLS  {t.version()}, certificate valid for {host}, fingerprint {fp}")
    except ssl.SSLCertVerificationError as e:
        try:  # see the certificate anyway, to pin it
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.create_connection(peer, 5), server_hostname=host) as t:
                fp = "sha256:" + hashlib.sha256(t.getpeercert(binary_form=True)).hexdigest()
        except (ssl.SSLError, OSError):
            fp = None
        return (None, f"TLS  works, but the certificate is not trusted ({e.verify_message}) -- "
                      + (f"pin it on the dialing side: fingerprint = \"{fp}\" (check it matches tools/linkmgmt.py "
                         "fingerprint on that server)" if fp else "the dialing side needs tls_insecure_skip_verify = true"))
    except (ssl.SSLError, OSError) as e:
        return (False, f"TLS  handshake failed ({e}) -- is [links] tls = true on that side?")


def listening(lk, port):
    """Is something listening on our link port right now?"""
    bind = lk.get("bind", "0.0.0.0")
    try:
        socket.create_connection(("127.0.0.1" if bind in ("0.0.0.0", "::", "") else bind, port), 2).close()
    except OSError:
        return (False, f"LOCAL  nothing listens on link port {port} here yet -- paste the config and restart the ircd")
    if not lk.get("enabled"):
        return (False, f"LOCAL  port {port} is already taken by another program (links are off here) -- pick another port")
    return (True, f"LOCAL  link listener is up on port {port}")


def allowed(name, ips):
    """Does `name` resolve to an address its allowed_ips accept?"""
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(name, None)}
    except socket.gaierror:
        return (None, f"ALLOW  {name} does not resolve, so allowed_ips {ips} can't be checked")
    hit = [a for a in addrs if any(fnmatch.fnmatchcase(a, g) for g in ips)]
    if hit: return (True, f"ALLOW  {name} ({', '.join(sorted(addrs))}) matches allowed_ips")
    return (None, f"ALLOW  {name} resolves to {', '.join(sorted(addrs))}, which allowed_ips {ips} does not match "
                  "-- fine if it connects from another address, otherwise the link will be refused")


def nettest(cfg, name, we_dial, host, port, tls, ips=None, fresh=False):
    heading(f"Network checks from this machine ({socket.gethostname()})")
    rows = []
    if we_dial:
        rows += probe(host, port, tls)
        if fresh: rows.append((None, f"Until {name} has its config pasted and is restarted, 'refused' is expected."))
    else:
        rows.append(listening(cfg.get("links", {}), port))
        rows += probe(host, port, tls)
        if ips: rows.append(allowed(name, ips))
        rows.append((None, f"This is only from inside. The real test is from {name}, after copying this tool there: "
                           f"tools/linkmgmt.py test {host} {port}{' --tls' if tls else ''}"))
    for ok, t in rows:
        print(f"  {green('OK  ') if ok else red('FAIL') if ok is False else yellow('NOTE')} {t}")
    bad = sum(1 for ok, _ in rows if ok is False)
    print("\n" + (red(f"{bad} problem(s) found.") if bad else green("No problems found.")) + "\n")


def test(cfg, target, tls):
    lk = cfg.get("links", {})
    if target:
        if len(target) != 2 or chk_port(target[1]): sys.exit(red("usage: tools/linkmgmt.py test HOST PORT [--tls]"))
        return nettest(cfg, target[0], True, target[0], int(target[1]), tls)
    p = choose(cfg, "test")
    if p.get("host"):
        return nettest(cfg, p["name"], True, p["host"], p.get("port", DEFAULT_PORT), bool(lk.get("tls")))
    me = cfg.get("server", {}).get("name", "")
    host = ask(f"Public hostname or IP of THIS server ({me}) that {p['name']} connects to", None,
               lambda a: None if a and " " not in a else "required")
    nettest(cfg, p["name"], False, host, lk.get("port", DEFAULT_PORT), bool(lk.get("tls")), p.get("allowed_ips"))


def delete(cfg, path, dry_run=False):
    me = cfg.get("server", {}).get("name", "")
    p = choose(cfg, "remove")
    name = p["name"]
    if not yes(f"Remove the link to {name}?"): return
    rest = [q for q in cfg["peers"] if q is not p]
    heading(f"1) On THIS server ({me}) -- {rel(path)}")
    kv = {}
    if not rest:
        kv["enabled"] = "false"
    else:
        m = mode_for(sum(1 for q in rest if q.get("host")), sum(1 for q in rest if not q.get("host")))
        if m != cfg.get("links", {}).get("mode", "hub"): kv["mode"] = f'"{m}"'

    def edit(lines):
        drop_peer(lines, name)
        if kv: set_links_keys(lines, kv)

    if dry_run or not apply_local(path, edit, restart=False):
        print(f"Delete the [[links.peers]] block with name = \"{name}\".")
        if kv: snippet("In [links]: " + ", ".join(f"{k} = {v}" for k, v in kv.items()) + ("   (no links left)" if not rest else ""))
        else: print()
    heading(f"2) On the OTHER server ({name})")
    print(f"Delete its [[links.peers]] block with name = \"{me}\"; if that was its only link, set [links] enabled = false.\n")
    heading("3) Then")
    for i, s in enumerate([f"Drop the live link: /SQUIT {name} :link removed", f"{name}: /REHASH (and {me}, if not done above)",
                           "tools/confcheck.py on both"], 1):
        print(f"  {i}. {s}")
    print()


def selftest():
    assert mode_for(0, 1) == "hub" and mode_for(1, 0) == "leaf" and mode_for(2, 0) == "both" and mode_for(1, 1) == "both"
    h = scrypt_hash("s3cret").split("$")
    assert h[:4] == ["scrypt", "16384", "8", "1"] and len(h[4]) == 32 and len(h[5]) == 128
    assert hashlib.scrypt(b"s3cret", salt=bytes.fromhex(h[4]), n=16384, r=8, p=1, dklen=64, maxmem=1 << 25).hex() == h[5]
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
        f.write('[server]\nname = "a.b"\n[links]\nenabled = true # on\nmode = "hub"\nport = 7070\n'
                '#[[links.peers]]\n[[links.peers]]\nname = "x.y"\npassword_hash = "scrypt$1"\nallowed_ips = ["1.2.3.4"]\n'
                '[[links.peers]]\nname = "z.y"\npassword = "p"\nhost = "h"\nport = 7000\n[tls]\nenabled = false\n')
    c = read_config(f.name); os.unlink(f.name)
    assert c["server"]["name"] == "a.b" and c["links"] == {"enabled": True, "mode": "hub", "port": 7070}
    assert [p["name"] for p in c["peers"]] == ["x.y", "z.y"] and c["peers"][0]["allowed_ips"] == ["1.2.3.4"]
    assert c["peers"][1]["port"] == 7000 and c["tls"]["enabled"] is False
    assert probe("nonexistent.invalid", 7000)[0][0] is False
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    r = probe("127.0.0.1", port); srv.close()
    assert r[0][0] and r[1] == (True, f"TCP  127.0.0.1 port {port}: open")
    assert probe("127.0.0.1", port)[1][0] is False  # closed now: refused
    assert allowed("localhost", ["127.0.0.*", "::1"])[0] is True and allowed("localhost", ["10.*"])[0] is None
    import base64
    der = b"\x30\x03\x02\x01\x01"  # any DER bytes: the fingerprint is the SHA-256 of them
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write("-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der).decode() + "\n-----END CERTIFICATE-----\n")
    assert cert_fingerprint(f.name) == "sha256:" + hashlib.sha256(der).hexdigest(); os.unlink(f.name)
    assert chk_fp("SHA256:" + ":".join(["AB"] * 32)) is None and chk_fp("abc") and chk_fp("") is None

    # editing: add, re-key [links], edit, delete -- the commented example, the services peer, a multi-line value and
    # the comment documenting the next section survive; every step parses and (when built) passes the ircd's --check
    base = ('[server]\nname = "a.test.net"\n[links]\nenabled = true\nmode = "hub" # was\nport = 7070\n'
            '#[[links.peers]]\n#name = "leaf1"\n[[links.peers]]\nname = "services.x"\npassword = "p"\n'
            'allowed_ips = [\n  "127.0.0.1",\n]\n\n# --- channels\n[channels]\ndefault_modes = "nt"\n')
    lines = base.splitlines()
    put_peer(lines, peer_block("b.test.net", pw_hash=scrypt_hash("x"), ips=["1.2.3.4"]).splitlines())
    assert [n for *_, n in peer_spans(lines)] == ["services.x", "b.test.net"]
    t = "\n".join(lines)
    assert t.index('name = "b.test.net"') < t.index("# --- channels") and '#[[links.peers]]\n#name = "leaf1"' in t
    set_links_keys(lines, {"mode": '"both"', "tls": "false"})
    t = "\n".join(lines)
    assert 'mode = "both"' in t and "# was" not in t and t.index("tls = false") < t.index("#[[links.peers]]")
    put_peer(lines, peer_block("b.test.net", pw="p2", host="b.example", port=7000).splitlines(), "b.test.net")
    assert len(peer_spans(lines)) == 2 and 'host = "b.example"' in "\n".join(lines) and "1.2.3.4" not in "\n".join(lines)
    if tomllib: tomllib.loads("\n".join(lines))
    drop_peer(lines, "b.test.net"); set_links_keys(lines, {"mode": '"hub"'})
    assert [n for *_, n in peer_spans(lines)] == ["services.x"] and "\n\n\n" not in "\n".join(lines)
    tail = '[server]\nname = "a.test.net"\n[links]\nenabled = true\n[[links.peers]]\nname = "services.x"\npassword = "p"'
    lines = tail.splitlines(); put_peer(lines, peer_block("b.c", pw="q", host="h", port=1).splitlines()); drop_peer(lines, "b.c")
    assert "\n".join(lines) == tail, lines  # add + del at the end of the file is a no-op
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "s.toml"); open(f, "w").write(base)
        lines = base.splitlines()
        put_peer(lines, peer_block("b.test.net", pw_hash=scrypt_hash("x")).splitlines())
        with contextlib.redirect_stdout(io.StringIO()):
            bak = write_config(f, "\n".join(lines) + "\n")
        assert bak and os.stat(bak).st_mode & 0o777 == 0o600 and 'name = "b.test.net"' in open(f).read()
        with contextlib.redirect_stdout(io.StringIO()):
            bak2 = write_config(f, open(f).read() + "\n")
        assert bak2 and bak2 != bak and os.path.exists(bak)  # same second: both backups kept
        if os.path.exists(os.path.join(ROOT, "bin/sekurircd")):  # a hub peer with a host is refused -> restored
            good = open(f).read()
            with contextlib.redirect_stdout(io.StringIO()):
                assert write_config(f, good.replace('name = "b.test.net"', 'name = "b.test.net"\nhost = "h"\nport = 1')) is None
            assert open(f).read() == good
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description="Server-link wizard: writes this server's side, prints the other server's.")
    ap.add_argument("action", nargs="?", choices=["list", "add", "edit", "del", "test", "fingerprint"])
    ap.add_argument("target", nargs="*", help="test only: HOST PORT")
    ap.add_argument("--tls", action="store_true", help="test HOST PORT: also try a TLS handshake")
    ap.add_argument("-c", "--config", default=os.path.join(ROOT, "config/sekurircd.toml"))
    ap.add_argument("--dry-run", action="store_true", help="write nothing: print this server's side to paste as well")
    ap.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.selftest: return selftest()
    if not a.no_banner: subprocess.run(["bash", "-c", f'source "{ROOT}/tools/lib.sh"; banner'])
    if not os.path.exists(a.config): sys.exit(red(f"{a.config} not found (use -c)"))
    cfg = read_config(a.config)
    if a.action == "fingerprint":
        fp, why = own_fingerprint(cfg, a.config)
        if not fp: sys.exit(red(f"No certificate to fingerprint: {why}"))
        print(f"\nThis server's certificate: {bold(fp)}\nOn the other server, put fingerprint = \"{fp}\" in its "
              f"[[links.peers]] block for {cfg.get('server', {}).get('name', 'this server')}.\n")
        return
    show(cfg)
    act = a.action or ["add", "edit", "del", "test", None][pick("What now?", ["Link a new server", "Edit a link", "Remove a link", "Test a link (network)", "Quit"])]
    if act == "add": wizard(cfg, a.config, dry_run=a.dry_run)
    elif act == "edit": wizard(cfg, a.config, choose(cfg, "edit"), dry_run=a.dry_run)
    elif act == "del": delete(cfg, a.config, dry_run=a.dry_run)
    elif act == "test": return test(cfg, a.target, a.tls)
    if a.dry_run and act in ("add", "edit", "del"):
        print(dim("--dry-run: nothing was written -- paste the blocks above into each server's config."))


if __name__ == "__main__":
    main()
