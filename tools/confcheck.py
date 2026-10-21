#!/usr/bin/env python3
"""SekurIRCd config checker (Python 3.8+, stdlib only). Changes nothing unless --fix --write.

For each live config (sekurircd.toml, protection.toml, services.toml):
  1. TOML syntax, with line/column (Python 3.11+; older Pythons rely on step 2)
  2. the daemon's own validation: `bin/sekurircd --check` / `bin/services --check`
     -- the exact rules the server applies at start and /REHASH (types, ranges,
     durations, required fields, the Protection bundle, ...)
  3. against its template: unknown keys (typos / removed options, with
     "did you mean") and options/sections the template has that yours lacks

  tools/confcheck.py                 check the default live files
  tools/confcheck.py -c my.toml      check one sekurircd config (protection.toml it points to included)
  tools/confcheck.py -q              errors and warnings only
  tools/confcheck.py --fix           show what --fix --write would change in the live files
  tools/confcheck.py --fix --write   apply it: deprecated/moved settings go where they live now, unknown
                                     ones are commented out, options you don't set are added commented out
                                     (the defaults). Backups <file>.pre-fix-<date>; the daemons validate the
                                     result and anything they reject is restored.

--fix never changes what the server does: a moved setting keeps its value (one already set in its new
home wins there today, so the old copy is just commented out), and everything else it adds or disables
is a comment or was already ignored. A [server] name without a dot is left for you. Plain-text passwords
the server can check as a hash ([[operators]], die/restart, link peers it only accepts from) become scrypt
password_hash lines: the same passwords keep working, and only the .pre-fix backup still holds them.

Exit status: 0 = OK (warnings allowed), 1 = errors found (--fix: refused / not applied),
2 = --fix found changes (preview only).
"""
import argparse, contextlib, difflib, glob, grp, io, json, os, pwd, re, shutil, stat, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from upgrade import ROOT, TEMPLATES, SEC_RE, KEY_RE, VAL_RE, parse_settings, bold, dim, red, green, yellow, cyan  # noqa: E402

try:
    import tomllib  # 3.11+
except ImportError:
    tomllib = None

CHECKERS = {  # live file -> daemon binary that validates it
    "config/sekurircd.toml": "bin/sekurircd",
    "services/services.toml": "bin/services" if os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin/services")) else "bin/chanserv",
}
P = "config/protection.toml"
S, SV = "config/sekurircd.toml", "services/services.toml"
# (section, key or None for the whole section) -> (section, key) in protection.toml, which overrides the old spot
# when it sets the key (src/config.c apply_protection); the server still reads the old spot
LEGACY = {
    ("dnsbl", None): ("blacklist", None),
    ("security", "flood_max_msgs"): ("flood", "max_msgs"),
    ("security", "flood_window"): ("flood", "window"),
    ("security", "max_connections"): ("connection", "max_connections"),
    ("security", "max_connections_per_ip"): ("connection", "max_connections_per_ip"),
    ("security", "connect_flood_max"): ("connection", "connect_flood_max"),
    ("security", "connect_flood_window"): ("connection", "connect_flood_window"),
    ("security", "connect_flood_kline_duration"): ("connection", "connect_flood_ban_duration"),
}
RETIRED = {  # sections the ircd no longer reads at all -> where the settings went (--fix moves them to RETIRED_TO)
    "accounts": "accounts are the services daemon's now: put these under [nickserv] in services/services.toml "
                "(its accounts.json is used in place)",
}
RETIRED_TO = {"accounts": (SV, "nickserv")}
OPTIONAL = {"config/protection.toml"}  # sekurircd.toml settings apply when it's absent

errors = warnings = 0


def ok(s): print(f"  {green('✔')} {s}")
def note(s): print(f"  {cyan('·')} {s}")


def err(s):
    global errors; errors += 1; print(f"  {red('✘')} {s}")


def warn(s):
    global warnings; warnings += 1; print(f"  {yellow('!')} {s}")


def check_syntax(path):
    if tomllib is None:
        return True
    try:
        with open(path, "rb") as f:
            tomllib.load(f)
        ok("TOML syntax")
        return True
    except tomllib.TOMLDecodeError as e:
        err(f"TOML syntax: {e}")
        return False


def check_daemon(path, binary):
    if not os.path.exists(binary):
        warn(f"{binary} not built -- skipped the server's own validation (run make)")
        return
    p = subprocess.run([binary, "--check", "-c", path], capture_output=True, text=True)
    msg = (p.stdout + p.stderr).strip()
    if p.returncode == 0:
        ok(f"{os.path.basename(binary)} --check")
    elif "unrecognized argument" in msg:
        warn(f"{binary} predates --check -- rebuild (make) for full validation")
    else:
        err(msg.splitlines()[-1] if msg else f"{binary} --check exited {p.returncode}")


def home_of(sec, tpl):
    """The live file whose template documents [sec], if it's not tpl (a section that moved)."""
    for t, live in TEMPLATES.items():
        if t != tpl and os.path.exists(t) and sec in parse_settings(open(t).read())[1]:
            return live
    return None


def legacy_where(sec, key):
    ns, nk = LEGACY[(sec, key)]
    return f"[{ns}]" + (f" {nk}" if nk else "") + f" in {P}"


def check_template(path, tpl, quiet, issues=None):
    """Warns about path vs its template; each warning --fix can act on is also appended to `issues`."""
    issues = [] if issues is None else issues
    live, live_secs = parse_settings(open(path).read())
    ref, ref_secs = parse_settings(open(tpl).read())
    moved = set()
    keys_by_sec = {}
    for sec, key in ref:
        keys_by_sec.setdefault(sec, []).append(key)

    for (sec, key), v in live.items():
        if not v["active"] or (sec, key) in ref:
            continue
        where = f"[{sec}] {key}" if sec else key
        if (sec, key) in LEGACY:
            warn(f"{where}: deprecated -- now {legacy_where(sec, key)} (still read here for now)")
            issues.append(("legacy", sec, key))
            continue
        if sec and sec not in ref_secs:
            if sec in moved:
                continue
            moved.add(sec)
            if sec in RETIRED:
                warn(f"[{sec}]: no longer read by the ircd -- {RETIRED[sec]}")
                issues.append(("retired", sec, None))
                continue
            if (sec, None) in LEGACY:
                warn(f"[{sec}]: deprecated -- now {legacy_where(sec, None)} (still read here for now)")
                issues.append(("legacy_sec", sec, None))
                continue
            home = home_of(sec, tpl)
            if home:
                warn(f"[{sec}]: has moved to {home} (still read here for now)")
                issues.append(("moved_sec", sec, home))
                continue
            hint = difflib.get_close_matches(sec, ref_secs, 1, 0.75)
            why = f"unknown section [{sec}]" + (f" -- did you mean [{hint[0]}]?" if hint else "")
            warn(f"{where}: {why}")
            issues.append(("unknown_sec", sec, why))
            continue
        hint = difflib.get_close_matches(key, keys_by_sec.get(sec, []), 1, 0.75)
        other = sorted(s for s, k in ref if k == key)
        if hint:
            why = f"unknown option -- did you mean {hint[0]}?"
        elif other:
            why = f"belongs in [{other[0]}], not [{sec}]"
        else:
            why = "not in the template -- typo or obsolete? (likely ignored)"
        warn(f"{where}: {why}")
        issues.append(("unknown", sec, key, why))

    name = live.get(("server", "name"), {})
    if name.get("active") and "." not in name["value"].split("#")[0]:
        warn(f"[server] name = {name['value'].strip()}: has no dot -- clients (TheLounge, irc-framework) "
             "read it as a nick, so oper notices land in the active channel; use a hostname like irc.example.org")

    missing_secs = sorted(ref_secs - live_secs)
    missing = [(s, k) for s, k in ref if (s, k) not in live and s not in missing_secs]
    if missing_secs:
        note(f"sections in the template you don't have: {', '.join(f'[{s}]' for s in missing_secs)}")
    if missing:
        note(f"{len(missing)} option(s) in the template you don't set (built-in defaults apply)"
             + ("" if quiet else ":"))
        if not quiet:
            for s, k in missing:
                print(f"      {dim(f'[{s}] ' if s else '')}{k} = {ref[(s, k)]['value']}")
    if not missing_secs and not missing:
        ok(f"has every option in {os.path.basename(tpl)}")


# ---------------------------------------------------------------- --fix
# Line surgery, so every comment and the layout survive. Sections and settings are found the way parse_settings
# finds them (a commented '# [sec]' / '# key = value' counts, for placing things next to the template's examples).
NOTE = "# confcheck --fix:"


def is_setting(ln):
    k = KEY_RE.match(ln)
    return bool(k and (not k[1] or (VAL_RE.match(k[3]) and not k[3].endswith("."))))


def is_comment(ln): return ln.lstrip().startswith("#")


def bracket_delta(s):
    d, q, i = 0, None, 0
    while i < len(s):
        ch = s[i]
        if q:
            if ch == "\\" and q == '"': i += 1
            elif ch == q: q = None
        elif ch in "\"'": q = ch
        elif ch == "#": break
        elif ch in "[{": d += 1
        elif ch in "]}": d -= 1
        i += 1
    return d


def value_end(lines, i):
    """Last line of the setting starting at lines[i]: arrays, inline tables and triple-quoted strings span lines."""
    v = KEY_RE.match(lines[i])[3]
    uncomment = (lambda s: s.lstrip().lstrip("#")) if is_comment(lines[i]) else (lambda s: s)
    for q in ('"""', "'''"):
        if v.startswith(q):
            j, rest = i, v[3:]
            while q not in rest and j + 1 < len(lines):
                j += 1; rest = uncomment(lines[j])
            return j
    j, depth = i, bracket_delta(v)
    while depth > 0 and j + 1 < len(lines):
        j += 1; depth += bracket_delta(uncomment(lines[j]))
    return j


def span(lines, sec, active=True):
    """(header line or -1 for the top level, next header of any kind, next active header) of the first [sec],
    or None. `active`: only an uncommented header counts as [sec]."""
    hs = [(i, SEC_RE.match(l)[1].strip("[]"), not is_comment(l)) for i, l in enumerate(lines) if SEC_RE.match(l)]
    for n, (i, s, act) in enumerate(hs):
        if (sec == "" and n == 0) or (s == sec and (act or not active)):
            start = -1 if sec == "" else i
            return (start, i if sec == "" else next((h[0] for h in hs[n + 1:]), len(lines)),
                    i if sec == "" else next((h[0] for h in hs[n + 1:] if h[2]), len(lines)))
    return (-1, len(lines), len(lines)) if sec == "" else None


def settings_in(lines, sec):
    """[(key, first line, last line)] of the active settings in [sec]."""
    sp, res = span(lines, sec), []
    if not sp:
        return res
    i = sp[0] + 1
    while i < sp[2]:
        if is_setting(lines[i]) and not is_comment(lines[i]):
            e = value_end(lines, i); res.append((KEY_RE.match(lines[i])[2], i, e)); i = e + 1
        else:
            i += 1
    return res


def insert_at(lines, sec, active=True):
    """Where to add to [sec]: after its last content, before a comment block that documents the next section."""
    s, end, _ = span(lines, sec, active)
    j = end
    while j > s + 1 and not lines[j - 1].strip():
        j -= 1
    if j == end:
        k = j
        while k > s + 1 and is_comment(lines[k - 1]) and not is_setting(lines[k - 1]):
            k -= 1
        if s + 1 < k < j and not lines[k - 1].strip():
            j = k - 1
            while j > s + 1 and not lines[j - 1].strip():
                j -= 1
    return j


def comment_out(lines, a, b, why):
    lines[a:b + 1] = [f"{NOTE} {why}", *commented(lines[a:b + 1])]


def set_key(lines, sec, val):
    """Add the setting `val` (its lines) to [sec], in place of a commented example of it if there is one."""
    key = KEY_RE.match(val[0])[2]
    sp = span(lines, sec)
    if not sp:
        lines += ["", f"[{sec}]", *val]
        return
    for i in range(sp[0] + 1, sp[1]):
        k = KEY_RE.match(lines[i])
        if k and k[1] and k[2] == key and is_setting(lines[i]):
            lines[i:value_end(lines, i) + 1] = val
            return
    i = insert_at(lines, sec)
    lines[i:i] = val


HASHABLE = {"operators": ("password",), "security": ("die_password", "restart_password"), "links.peers": ("password",)}


def toml_str(raw):
    """The string a single-line TOML value `raw` (maybe with a trailing comment) holds, or None."""
    if tomllib:
        try:
            v = tomllib.loads(f"v = {raw}")["v"]
            return v if isinstance(v, str) else None
        except tomllib.TOMLDecodeError:
            return None
    m = re.match(r"'([^']*)'\s*(#.*)?$", raw)  # ponytail: pre-3.11 fallback, basic and literal strings only
    if m:
        return m[1]
    with contextlib.suppress(ValueError):
        v, end = json.JSONDecoder().raw_decode(raw)
        if isinstance(v, str) and raw[end:].strip()[:1] in ("", "#"):
            return v
    return None


def plain_passwords(lines):
    """[(line, label, password)] for each plain-text password in a sekurircd.toml the server could check as a hash
    instead. A link peer with a host dials out and has to send the real password, so it's left alone."""
    res = []
    hs = [(n, SEC_RE.match(l)[1].strip("[]")) for n, l in enumerate(lines) if SEC_RE.match(l) and not is_comment(l)]
    count = {}
    for n, (start, sec) in enumerate(hs):
        end = hs[n + 1][0] if n + 1 < len(hs) else len(lines)
        idx = count[sec] = count.get(sec, -1) + 1
        if sec not in HASHABLE:
            continue
        keys, j = {}, start + 1
        while j < end:
            if is_setting(lines[j]) and not is_comment(lines[j]):
                e = value_end(lines, j); keys[KEY_RE.match(lines[j])[2]] = (j, e); j = e + 1
            else:
                j += 1
        if sec == "links.peers" and "host" in keys:
            continue
        for key in HASHABLE[sec]:
            if key in keys and keys[key][0] == keys[key][1]:
                pw = toml_str(KEY_RE.match(lines[keys[key][0]])[3])
                if pw:
                    label = f"[security] {key}" if sec == "security" else f"[[{sec}]] #{idx + 1} {key}"
                    res.append((keys[key][0], label, pw))
    return res


def hash_passwords(lines):
    from linkmgmt import scrypt_hash  # same format and cost as `sekurircd --hash-password`
    for i, label, pw in reversed(plain_passwords(lines)):
        k = KEY_RE.match(lines[i])
        indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
        lines[i:i + 1] = [f"{indent}{NOTE} was a plain-text password; this is its scrypt hash (log in with the same password)",
                          f'{indent}{k[2]}_hash = "{scrypt_hash(pw)}"']


def renamed(val, key):
    return [KEY_RE.sub(lambda m: m[0].replace(m[2], key, 1), val[0], 1), *val[1:]]


PIDFILES = ("sekurircd.pid", "services/services.pid", "services/chanserv.pid")  # as ./sekurircd writes them


def daemon_users():
    """Who the running ircd/services run as (they must still be able to read their files), from their pidfiles."""
    users = set()
    for f in PIDFILES:
        with contextlib.suppress(OSError, ValueError):
            pid = int(open(f).read().split()[0])
            r = subprocess.run(["ps", "-o", "user=", "-p", str(pid)], capture_output=True, text=True)
            if r.stdout.strip():
                users.add(r.stdout.strip())
    return users


def secret_files():
    """[(path, what it holds)] for the files that hold secrets, as they exist right now."""
    out = [(S, "oper/link passwords, cloak secret"), (SV, "the services link password"),
           (P, "DNSBL zone keys, if any")]
    if os.path.exists(S):
        v = parse_settings(open(S).read())[0].get(("tls", "key_file"))
        if v and v["active"]:
            out.append((os.path.normpath(os.path.join(os.path.dirname(S), v["value"].split("#")[0].strip().strip("\"'"))),
                        "the TLS private key"))
    out += [(f, "account password hashes and e-mails") for f in sorted(glob.glob("config/accounts.json*"))]
    out += [(f, "channel password hashes") for f in sorted(glob.glob("services/*.json*"))]
    out += [(f, "a --fix backup: may hold the old plain-text passwords") for f in sorted(glob.glob("*/*.pre-fix-*"))]
    out += [(f, "a linkmgmt backup: may hold link passwords") for f in sorted(glob.glob("*/*.pre-linkmgmt-*"))]
    out += [(f, "linkmgmt's part for another server: holds the link password") for f in sorted(glob.glob("link-for-*.toml"))]
    return [(f, what) for f, what in dict(out).items() if os.path.isfile(f)]


def check_permissions(paths=None):
    """Warns about secret files other local users can read or change, each with the exact command that fixes it."""
    me, users = pwd.getpwuid(os.getuid()).pw_name, daemon_users()
    bad = 0
    for d in ("config", "services", "config/tls"):
        if os.path.isdir(d) and os.stat(d).st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            warn(f"{d}/ is writable by {'everyone' if os.stat(d).st_mode & stat.S_IWOTH else 'its group'}: anyone who can "
                 f"write there can swap in their own config -- fix: {sudo_for(d, me)}chmod go-w {d}"); bad += 1
    for f, what in paths or secret_files():
        st = os.stat(f)
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
        others = users - {owner}
        # a daemon running as someone other than the owner reads it through the group: keep group read for it then
        via_group = others and all(st.st_gid in os.getgrouplist(u, pwd.getpwnam(u).pw_gid) for u in others)
        mode = st.st_mode & 0o777
        want = 0o640 if via_group else 0o600
        if not mode & ~want & 0o077:
            continue
        who = ("everyone on this machine" if mode & 0o006 else f"group {group}")
        how = "change" if mode & 0o022 else "read"
        if others and not via_group:  # chmod 600 alone would lock the daemon out
            u = sorted(others)[0]
            fix = f"sudo chown {u} {f} && sudo chmod 600 {f}  (the daemon runs as {u}; or add {u} to group {group} " \
                  f"and chmod 640 {f})"
        else:
            fix = f"{sudo_for(f, me)}chmod {want:o} {f}"
        warn(f"{f} ({what}) can be {how} by {who} ({mode:o}) -- fix: {fix}"); bad += 1
    if not bad:
        ok("secret files are private to their owner")


def sudo_for(path, me):
    return "" if me == "root" or pwd.getpwuid(os.stat(path).st_uid).pw_name == me else "sudo "


def protection_path(lines):
    """Where sekurircd.toml's protection file is (relative to ROOT), or None when it's turned off."""
    v = parse_settings("\n".join(lines))[0].get(("security", "protection_file"))
    f = v["value"].split("#")[0].strip().strip("\"'") if v and v["active"] else "protection.toml"
    return os.path.normpath(os.path.join(os.path.dirname(S), f)) if f else None


def commented(ls): return [l if not l.strip() or is_comment(l) else "# " + l for l in ls]


def doc_start(t, i, floor):
    """First line of the comment block right above t[i] (stops at a blank line, a setting or a header)."""
    while i - 1 > floor and is_comment(t[i - 1]) and not is_setting(t[i - 1]) and not SEC_RE.match(t[i - 1]):
        i -= 1
    return i


def tpl_block(t, sec, key):
    """The template's [sec] key -- its doc comment and the setting -- commented out. Any [sec] counts: they can
    repeat ([[links.peers]] has one example per role)."""
    h = -1
    for i, l in enumerate(t):
        if SEC_RE.match(l):
            h = i
            continue
        k = KEY_RE.match(l)
        if k and k[2] == key and is_setting(l) and (SEC_RE.match(t[h])[1].strip("[]") if h >= 0 else "") == sec:
            return commented(t[doc_start(t, i, h):value_end(t, i) + 1])
    return []


def tpl_section(t, sec):
    """The template's first [sec] with the comment block above it, commented out."""
    s = span(t, sec, active=False)[0]
    return commented(t[doc_start(t, s, -1):insert_at(t, sec, active=False)])


def fill_missing(lines, tpl):
    """Every option the template documents that `lines` lacks, added commented out (the built-in default applies)
    to its section; sections it lacks are appended whole, commented out."""
    t = open(tpl).read().splitlines()
    live, secs = parse_settings("\n".join(lines))
    ref, _ = parse_settings("\n".join(t))
    by_sec = {}
    for s, k in ref:
        if (s, k) not in live:
            by_sec.setdefault(s, []).append(k)
    for s, keys in by_sec.items():
        if s and s not in secs:
            lines += ["", *tpl_section(t, s)]
            continue
        body, prev = [], 0
        for k in keys:
            blk = tpl_block(t, s, k)
            body += ([""] if len(blk) > 1 or prev > 1 or not body else []) + blk
            prev = len(blk)
        i = insert_at(lines, s, active=False)
        lines[i:i] = body


def fix_dnsbl(F, prot):
    """Legacy [dnsbl] -> [blacklist] + one [[blacklist.zone]] per zone, exactly as src/config.c protection_legacy_dnsbl
    reads it, unless the protection file already has a [blacklist] (then [dnsbl] is ignored already)."""
    d = tomllib.loads("\n".join(F[S])).get("dnsbl", {})
    have = "blacklist" in tomllib.loads("\n".join(F[prot]))
    if d.get("enabled") and not have:
        url = d.get("lookup_url", "").replace("%", "%%").replace("{ip}", "%i")
        reason = "Proxy/Drone detected (%t)" + (f". Check {url} for details." if url else "")
        F[prot] += ["", "[blacklist]", "enabled = true", f"timeout = {float(d.get('timeout', 5.0))}",
                    f"action = {json.dumps('zline' if d.get('action', 'kline') == 'kline' else 'reject')}",
                    f"ban_duration = {json.dumps(d.get('kline_duration', '1d'))}"]
        for z in d.get("zones", []):
            F[prot] += ["", "[[blacklist.zone]]", f"name = {json.dumps(z)}", "ban_unknown = true", f"reason = {json.dumps(reason)}"]
        return f"converted to [blacklist] in {prot}"
    return f"{prot} has a [blacklist], which replaces it" if have else "it was disabled; [blacklist] in protection.toml replaces it"


def move_section(F, src, sec, dst, nsec, keymap=None):
    """Copy [sec]'s settings into [nsec] of dst where dst doesn't set them (dst's own values win there already),
    then comment [sec] out. keymap: key -> (new key, new value lines) or None to drop it."""
    have = parse_settings("\n".join(F[dst]))[0]
    for key, a, e in settings_in(F[src], sec):
        val = F[src][a:e + 1]
        if keymap:
            m = keymap(key, val)
            if not m:
                continue
            key, val = m
        if not have.get((nsec, key), {}).get("active"):
            set_key(F[dst], nsec, renamed(val, key))
    s, _, end = span(F[src], sec)
    comment_out(F[src], s, end - 1, f"[{sec}] moved to [{nsec}] in {dst} (values already set there were kept)")


def plan_fix():
    """{path: (old text or None, new text)} for the default live files. Run from ROOT."""
    F, orig = {}, {}

    def load(p):
        if p not in F:
            orig[p] = open(p).read() if os.path.exists(p) else None
            F[p] = orig[p].splitlines() if orig[p] is not None else []
        return F[p]

    global warnings
    tpl_of = {live: tpl for tpl, live in TEMPLATES.items()}
    prot = protection_path(load(S)) if os.path.exists(S) else None
    prot_tpl = tpl_of[P]
    issues, seen = {}, warnings
    with contextlib.redirect_stdout(io.StringIO()):  # the warnings were reported already; here they're just a to-do list
        for p in dict.fromkeys(x for x in (S, SV, P, prot) if x):
            if os.path.exists(p):
                check_template(p, prot_tpl if p == prot else tpl_of[p], True, issues.setdefault(p, []))
    warnings = seen

    for path, found in issues.items():
        load(path)
        for kind, sec, *rest in found:
            if kind == "legacy" and prot:
                ns, nk = LEGACY[(sec, rest[0])]
                load(prot)
                key = rest[0]
                sp = settings_in(F[path], sec)
                a, e = next((a, e) for k, a, e in sp if k == key)
                have = parse_settings("\n".join(F[prot]))[0].get((ns, nk), {})
                if have.get("active"):
                    why = f"{prot} sets [{ns}] {nk} = {have['value']}, which is what applies"
                else:
                    set_key(F[prot], ns, renamed(F[path][a:e + 1], nk)); why = f"moved to [{ns}] {nk} in {prot}"
                comment_out(F[path], a, e, why)
            elif kind == "legacy_sec" and sec == "dnsbl" and prot and tomllib:
                load(prot)
                why = fix_dnsbl(F, prot)
                s, _, end = span(F[path], sec)
                comment_out(F[path], s, end - 1, f"[dnsbl] {why}")
            elif kind == "retired" and sec in RETIRED_TO and os.path.exists(RETIRED_TO[sec][0]):
                dst, nsec = RETIRED_TO[sec]
                load(dst)
                known = {k for s, k in parse_settings(open(tpl_of[dst]).read())[0] if s == nsec}

                def keymap(key, val, dst=dst, known=known):
                    if key not in known:
                        return None
                    if key == "store_file":  # was relative to sekurircd.toml's directory, is to services.toml's
                        f = KEY_RE.match(val[0])[3].split("#")[0].strip().strip("\"'")
                        f = os.path.relpath(os.path.join(os.path.dirname(path), f), os.path.dirname(dst))
                        val = [f"store_file = {json.dumps(f)}"]
                    return key, val
                move_section(F, path, sec, dst, nsec, keymap)
            elif kind == "moved_sec":
                dst = prot if rest[0] == P else rest[0]
                if dst:
                    load(dst)
                    move_section(F, path, sec, dst, sec)
            elif kind == "unknown_sec":
                s, _, end = span(F[path], sec)
                comment_out(F[path], s, end - 1, f"{rest[0]} -- the server ignores it")
            elif kind == "unknown":
                a, e = next((a, e) for k, a, e in settings_in(F[path], sec) if k == rest[0])
                comment_out(F[path], a, e, rest[1].replace(" (likely ignored)", "") + " -- the server ignores it")

    if prot and prot in F and orig[prot] is None:
        if not F[prot]:
            del F[prot]
        else:  # first setting moved into it: start the file
            F[prot][:0] = [f"# SekurIRCd protection settings, started by tools/confcheck.py --fix.",
                           f"# Every option is documented in {prot_tpl}."]
    if os.path.exists(S):
        hash_passwords(load(S))
    for p in (S, SV, prot):
        if p and (p in F or os.path.exists(p)):
            fill_missing(load(p), prot_tpl if p == prot else tpl_of[p])
    res = {}
    for p, lines in F.items():
        new = "\n".join(lines) + "\n"
        if new != orig[p]:
            res[p] = (orig[p], new)
    return res


def show_diff(changes):
    for p, (old, new) in changes.items():
        print(f"\n{bold(p)}" + (dim("  (new file)") if old is None else ""))
        for l in list(difflib.unified_diff((old or "").splitlines(), new.splitlines(), lineterm="", n=1))[2:]:
            print("  " + (green(l) if l.startswith("+") else red(l) if l.startswith("-") else cyan(l) if l.startswith("@@") else dim(l)))


def apply_fix(changes):
    """Write `changes` (backups first), have the daemons validate the result, restore everything if they refuse."""
    if tomllib:
        for p, (_, new) in changes.items():
            try:
                tomllib.loads(new)
            except tomllib.TOMLDecodeError as e:  # a bug in --fix, never the user's file
                err(f"{p}: the fixed file would not parse ({e}) -- nothing written"); return False
    stamp, done = time.strftime("%Y%m%d-%H%M%S"), []
    for p, (old, new) in changes.items():
        bak = f"{p}.pre-fix-{stamp}" if old is not None else None
        if bak:
            shutil.copy2(p, bak)
            os.chmod(bak, 0o600)  # it may hold the plain-text passwords --fix just hashed
        tmp = p + ".fix-tmp"
        with open(tmp, "w") as f:
            f.write(new)
        shutil.copymode(p if old is not None else S, tmp)
        os.replace(tmp, p)
        done.append((p, bak))
    for path, binary in CHECKERS.items():
        if os.path.exists(path) and os.path.exists(binary):
            r = subprocess.run([binary, "--check", "-c", path], capture_output=True, text=True)
            if r.returncode and "unrecognized argument" not in r.stdout + r.stderr:
                msg = (r.stdout + r.stderr).strip().splitlines()
                err(f"{binary} --check rejects the fixed {path}: {msg[-1] if msg else r.returncode} -- restored your files")
                for p, bak in done:
                    os.replace(bak, p) if bak else os.remove(p)
                return False
    for p, bak in done:
        ok(f"wrote {p}" + (dim(f"  (backup: {bak})") if bak else dim("  (new file)")))
    return True


def selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        tpl, live = os.path.join(d, "t.toml"), os.path.join(d, "l.toml")
        open(tpl, "w").write('[server]\nport = 6667\n# motd = "x"\n[link]\nname = ""\n')
        open(live, "w").write('[server]\nprot = 1\nname = "a"\n[srever]\nx = 1\n[dnsbl]\nzones = []\n')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            check_template(live, tpl, True)
        o = buf.getvalue()
    assert "did you mean port?" in o and "belongs in [link]" in o and "did you mean [server]?" in o, o
    assert "[dnsbl]: deprecated" in o and "2 option(s)" in o and "[link]" in o and "has no dot" in o and warnings == 5, o

    # --fix: a deprecated key moves (into a protection.toml it starts), [dnsbl] converts, [accounts] goes to
    # [nickserv], an unknown key is commented out, missing options are added commented out -- and a second run is a no-op
    files = {
        "config/sekurircd.template.toml": '[server]\nname = "irc.x.org"\n# Doc.\n#motd = "m"\n[security]\nping = 1\n'
                                          '#[[operators]]\n#name = "x"\n#password_hash = "h"\n#password = "p"\n'
                                          '#[[links.peers]]\n#name = "x"\n#host = "h"\n#password_hash = "h"\n#password = "p"\n',
        "config/protection.template.toml": '[flood]\n#max_msgs = 20\n[blacklist]\n#enabled = true\n#timeout = 5.0\n'
                                           '#action = "zline"\n#ban_duration = "1d"\n#[[blacklist.zone]]\n#name = "z"\n'
                                           '#ban_unknown = true\n#reason = "r"\n',
        "services/services.template.toml": '[nickserv]\n#max_accounts = 0\n#store_file = "x"\n',
        S: '[server]\nname = "irc.x.org"\nbogus = [\n  1,\n]\n[security]\nping = 1\nflood_max_msgs = 7\n'
           '[accounts]\nmax_accounts = 9\nstore_file = "accounts.json"\n[dnsbl]\nenabled = true\nzones = ["z.org"]\n'
           '[[operators]]\nname = "a"\n  password = "s3cr#t"  # old\n[[links.peers]]\nname = "hub.x.org"\npassword = "p1"\n'
           '[[links.peers]]\nname = "leaf.x.org"\nhost = "1.2.3.4"\npassword = "p2"\n',
        SV: '[nickserv]\nmax_accounts = 3\n',
    }
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as d:
        os.chdir(d)
        try:
            for p, text in files.items():
                os.makedirs(os.path.dirname(p), exist_ok=True)
                open(p, "w").write(text)
            with contextlib.redirect_stdout(io.StringIO()):
                ch = plan_fix()
                ok1 = apply_fix(ch); again = plan_fix()
            assert ok1 and again == {}, (ok1, again)
            s, pr, sv = (open(p).read() for p in (S, P, SV))
        finally:
            os.chdir(cwd)
    assert "# bogus = [\n#   1,\n# ]" in s and '#motd = "m"' in s and "# flood_max_msgs = 7" in s and "# [dnsbl]" in s, s
    assert '  password_hash = "scrypt$16384$8$1$' in s and "s3cr#t" not in s and 'password = "p1"' not in s, s
    assert 'password = "p2"' in s and len(re.findall(r"password_hash = ", s)) == 2, s  # the dialing peer keeps its own
    import hashlib
    salt, dig = re.search(r'scrypt\$16384\$8\$1\$(\w+)\$(\w+)', s).groups()
    assert hashlib.scrypt(b"s3cr#t", salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=64).hex() == dig
    assert "max_msgs = 7\n" in pr and '[[blacklist.zone]]\nname = "z.org"' in pr and 'action = "zline"' in pr, pr
    assert "max_accounts = 3\n" in sv and 'store_file = "../config/accounts.json"' in sv, sv  # services' own value wins
    if tomllib:
        tomllib.loads(s); tomllib.loads(pr); tomllib.loads(sv)
    with tempfile.TemporaryDirectory() as d:  # permissions: the warning carries the exact fix
        f = os.path.join(d, "s.toml"); open(f, "w").write("")
        for mode, expect in ((0o644, f"everyone on this machine (644) -- fix: chmod 600 {f}"), (0o600, "private")):
            os.chmod(f, mode)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                check_permissions([(f, "x")])
            assert expect in buf.getvalue(), buf.getvalue()
    print("selftest ok")


def report(config, quiet):
    """The check of every live file (or just `config`); prints as it goes, leaves the counts in errors/warnings."""
    global errors, warnings
    errors = warnings = 0
    tpl_of = {live: tpl for tpl, live in TEMPLATES.items()}
    targets = [config] if config else list(tpl_of)
    for path in targets:
        print(f"\n{bold(path)}")
        if not os.path.exists(path):
            (note if path in OPTIONAL else err)(
                "not installed" + (" (optional)" if path in OPTIONAL else "")
                + (f" -- cp {tpl_of[path]} {path}" if path in tpl_of else ""))
            continue
        if not check_syntax(path):
            continue
        binary = CHECKERS.get(path, "bin/sekurircd" if config else None)
        if binary:
            check_daemon(path, binary)
        if path == S or config:
            for _, label, _ in plain_passwords(open(path).read().splitlines()):
                warn(f"{label} is plain text -- --fix --write turns it into a scrypt password_hash (same password)")
        tpl = tpl_of.get(path, "config/sekurircd.template.toml" if config else None)
        if tpl and os.path.exists(tpl):
            check_template(path, tpl, quiet)
        else:
            note("no template to compare against")
    if not config and os.path.exists("config/protection.toml"):
        note(dim("protection.toml is validated by sekurircd --check above"))
    if not config:
        print(f"\n{bold('file permissions')}")
        check_permissions()


def summary():
    print()
    if errors:
        print(f"  {red(bold(f'{errors} error(s)'))}, {warnings} warning(s) -- the server will refuse this config")
    else:
        print(f"  {green(bold('OK'))}" + (f", {warnings} warning(s)" if warnings else ""))


def fix(write, quiet):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        report(None, True)
        changes = plan_fix() if not errors else {}
    if errors:
        print(buf.getvalue()); summary()
        print(f"  {red('--fix only tidies a config the server accepts: fix the error(s) first.')}")
        return 1
    if not changes:
        ok("nothing for --fix to change")
        left = [l for l in buf.getvalue().splitlines() if l.lstrip().startswith(("!", "\033[33m!"))]
        if left:
            print(f"  {len(left)} warning(s) need you:")
            for l in left: print("  " + l)
        return 0
    show_diff(changes)
    print()
    if not write:
        print(f"  {bold(str(len(changes)))} file(s) would change. Apply with {bold('tools/confcheck.py --fix --write')} "
              f"{dim('(backups kept; the daemons validate the result first)')}")
        return 2
    hashed = S in changes and plain_passwords((changes[S][0] or "").splitlines())
    if not apply_fix(changes):
        return 1
    if hashed:
        warn(f"the {S}.pre-fix-* backup still has the plain-text password(s): delete it once /OPER works")
    note("running daemons pick this up at /REHASH (services: restart) -- nothing they do changes")
    report(None, quiet); summary()
    return 1 if errors else 0


def main():
    ap = argparse.ArgumentParser(description="Validate SekurIRCd config files (read-only unless --fix --write).")
    ap.add_argument("-c", "--config", help="check only this sekurircd config file")
    ap.add_argument("-q", "--quiet", action="store_true", help="don't list missing options one by one")
    ap.add_argument("--fix", action="store_true", help="show how the live files would be tidied (moved/unknown/missing options)")
    ap.add_argument("--write", action="store_true", help="with --fix: apply it (backups <file>.pre-fix-<date>)")
    ap.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)  # upgrade.py embeds our output
    ap.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.config and a.fix:
        ap.error("--fix works on the default live files; drop -c")
    if a.write and not a.fix:
        ap.error("--write goes with --fix")
    if a.config:
        a.config = os.path.abspath(a.config)
    os.chdir(ROOT)
    if not a.no_banner:
        subprocess.run(["bash", "-c", "source tools/lib.sh; banner"])
    if a.fix:
        sys.exit(fix(a.write, a.quiet))
    report(a.config, a.quiet)
    summary()
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
