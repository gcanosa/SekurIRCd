#!/usr/bin/env python3
"""SekurIRCd config checker (Python 3.8+, stdlib only). Changes nothing.

For each live config (sekurircd.toml, protection.toml, services.toml):
  1. TOML syntax, with line/column (Python 3.11+; older Pythons rely on step 2)
  2. the daemon's own validation: `bin/sekurircd --check` / `bin/chanserv --check`
     -- the exact rules the server applies at start and /REHASH (types, ranges,
     durations, required fields, the Protection bundle, ...)
  3. against its template: unknown keys (typos / removed options, with
     "did you mean") and options/sections the template has that yours lacks

  tools/confcheck.py                 check the default live files
  tools/confcheck.py -c my.toml      check one sekurircd config (protection.toml it points to included)
  tools/confcheck.py -q              errors and warnings only

Exit status: 0 = OK (warnings allowed), 1 = errors found.
"""
import argparse, difflib, os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from upgrade import ROOT, TEMPLATES, parse_settings, bold, dim, red, green, yellow, cyan  # noqa: E402

try:
    import tomllib  # 3.11+
except ImportError:
    tomllib = None

CHECKERS = {  # live file -> daemon binary that validates it
    "config/sekurircd.toml": "bin/sekurircd",
    "services/services.toml": "bin/chanserv",
}
P = "config/protection.toml"
LEGACY = {  # (section, key or None for the whole section) -> where it lives now; the server still reads the old spot
    ("dnsbl", None): f"[blacklist] in {P}",
    ("security", "flood_max_msgs"): f"[flood] max_msgs in {P}",
    ("security", "flood_window"): f"[flood] window in {P}",
    ("security", "max_connections"): f"[connection] max_connections in {P}",
    ("security", "max_connections_per_ip"): f"[connection] max_connections_per_ip in {P}",
    ("security", "connect_flood_max"): f"[connection] connect_flood_max in {P}",
    ("security", "connect_flood_window"): f"[connection] connect_flood_window in {P}",
    ("security", "connect_flood_kline_duration"): f"[connection] connect_flood_ban_duration in {P}",
}
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


def check_template(path, tpl, quiet):
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
            warn(f"{where}: deprecated -- now {LEGACY[(sec, key)]} (still read here for now)")
            continue
        if sec and sec not in ref_secs:
            if sec in moved:
                continue
            if (sec, None) in LEGACY:
                moved.add(sec)
                warn(f"[{sec}]: deprecated -- now {LEGACY[(sec, None)]} (still read here for now)")
                continue
            home = home_of(sec, tpl)
            if home:
                moved.add(sec)
                warn(f"[{sec}]: has moved to {home} (still read here for now)")
                continue
            hint = difflib.get_close_matches(sec, ref_secs, 1, 0.75)
            warn(f"{where}: unknown section [{sec}]" + (f" -- did you mean [{hint[0]}]?" if hint else ""))
            continue
        hint = difflib.get_close_matches(key, keys_by_sec.get(sec, []), 1, 0.75)
        other = sorted(s for s, k in ref if k == key)
        if hint:
            warn(f"{where}: unknown option -- did you mean {hint[0]}?")
        elif other:
            warn(f"{where}: belongs in [{other[0]}], not [{sec}]")
        else:
            warn(f"{where}: not in the template -- typo or obsolete? (likely ignored)")

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


def selftest():
    import io, tempfile, contextlib
    with tempfile.TemporaryDirectory() as d:
        tpl, live = os.path.join(d, "t.toml"), os.path.join(d, "l.toml")
        open(tpl, "w").write('[server]\nport = 6667\n# motd = "x"\n[link]\nname = ""\n')
        open(live, "w").write('[server]\nprot = 1\nname = "a"\n[srever]\nx = 1\n[dnsbl]\nzones = []\n')
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            check_template(live, tpl, True)
        o = buf.getvalue()
    assert "did you mean port?" in o and "belongs in [link]" in o and "did you mean [server]?" in o, o
    assert "[dnsbl]: deprecated" in o and "2 option(s)" in o and "[link]" in o and warnings == 4, o
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser(description="Validate SekurIRCd config files (read-only).")
    ap.add_argument("-c", "--config", help="check only this sekurircd config file")
    ap.add_argument("-q", "--quiet", action="store_true", help="don't list missing options one by one")
    ap.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)  # upgrade.py embeds our output
    ap.add_argument("--selftest", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.config:
        a.config = os.path.abspath(a.config)
    os.chdir(ROOT)
    if not a.no_banner:
        subprocess.run(["bash", "-c", "source tools/lib.sh; banner"])

    tpl_of = {live: tpl for tpl, live in TEMPLATES.items()}
    targets = [a.config] if a.config else list(tpl_of)
    for path in targets:
        print(f"\n{bold(path)}")
        if not os.path.exists(path):
            (note if path in OPTIONAL else err)(
                "not installed" + (" (optional)" if path in OPTIONAL else "")
                + (f" -- cp {tpl_of[path]} {path}" if path in tpl_of else ""))
            continue
        if not check_syntax(path):
            continue
        binary = CHECKERS.get(path, "bin/sekurircd" if a.config else None)
        if binary:
            check_daemon(path, binary)
        tpl = tpl_of.get(path, "config/sekurircd.template.toml" if a.config else None)
        if tpl and os.path.exists(tpl):
            check_template(path, tpl, a.quiet)
        else:
            note("no template to compare against")
    if not a.config and os.path.exists("config/protection.toml"):
        note(dim("protection.toml is validated by sekurircd --check above"))

    print()
    if errors:
        print(f"  {red(bold(f'{errors} error(s)'))}, {warnings} warning(s) -- the server will refuse this config")
    else:
        print(f"  {green(bold('OK'))}" + (f", {warnings} warning(s)" if warnings else ""))
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
