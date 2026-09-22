#!/usr/bin/env python3
"""SekurIRCd upgrade assistant (git-clone installs; Python 3.8+, stdlib only).

Pick the latest release or the latest main, review what changes (versions,
changelog, new config options), back everything up, build safely, install,
optionally restart -- and roll back if something goes wrong. Your live config
is never modified. Every run writes logs/SekurIRCd-upgrade-<date>.log.

  tools/upgrade.py                    interactive
  tools/upgrade.py --check            report new releases/commits only (exit 10 = updates)
  tools/upgrade.py --dry-run          show everything, change nothing
  tools/upgrade.py --channel release --yes --backup-dir /srv/backups
  tools/upgrade.py --rollback         undo the last upgrade
"""
import argparse, collections, getpass, glob, hashlib, json, os, platform, re
import shutil, socket, subprocess, sys, tarfile, textwrap, time, urllib.request
from typing import Any, NoReturn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TTY = sys.stdout.isatty()
ANSI = re.compile(r"\033\[[0-9;]*m")
STATE_FILE = "logs/upgrade-state.json"
TEMPLATES = {  # template -> the live file an admin copied it to
    "config/sekurircd.template.toml": "config/sekurircd.toml",
    "config/protection.template.toml": "config/protection.toml",
    "services/services.template.toml": "services/services.toml",
}
BACKUP_EXCLUDE = {".git", "build", "build-debug", "build.new", "bin.new", "logs",
                  "plans", ".codegraph", ".claude", "node_modules"}


def c(code, s): return f"\033[{code}m{s}\033[0m" if TTY else s
def bold(s): return c("1", s)
def dim(s): return c("2", s)
def red(s): return c("31", s)
def green(s): return c("32", s)
def yellow(s): return c("33", s)
def cyan(s): return c("36", s)


class Log:
    def __init__(self, kind):
        os.makedirs("logs", exist_ok=True)
        self.path = f"logs/SekurIRCd-{kind}-{time.strftime('%Y%m%d-%H%M%S')}.log"
        self.f = open(self.path, "a", buffering=1)

    def w(self, s=""):
        for line in ANSI.sub("", str(s)).splitlines() or [""]:
            self.f.write(f"{time.strftime('%H:%M:%S')}  {line}\n")


LOG: Log = None  # type: ignore  # set in main()
ARGS: argparse.Namespace = None  # type: ignore  # set in main()
_step = 0
_total = 9  # steps in a full upgrade run; main() sets 1 for --rollback


def out(s=""): print(s); LOG.w(s)
def info(s): out(f"  {s}")
def ok(s): out(f"  {green('✔')} {s}")
def warn(s): out(f"  {yellow('!')} {s}")
def fail(s): out(f"  {red('✘')} {s}")


def step(title):
    global _step
    _step += 1
    f = int(12 * _step / _total)
    out(); out(bold(cyan(f"━━ [{'█' * f}{'░' * (12 - f)}] Step {_step}/{_total}: {title}")))


def die(msg, code=1) -> NoReturn:
    fail(msg)
    LOG.w("RESULT: ABORTED")
    print(dim(f"  Log: {LOG.path}"))
    sys.exit(code)


def ask(q, default=True):
    if ARGS.yes:
        ans = default
    else:
        try:
            r = input(f"  {bold('?')} {q} {dim('[Y/n]' if default else '[y/N]')} ").strip().lower()
        except EOFError:
            die("no interactive terminal (use --yes)")
        ans = default if not r else r.startswith("y")
    LOG.w(f"? {q} -> {'yes' if ans else 'no'}")
    return ans


def prompt(q, default):
    if ARGS.yes:
        r = default
    else:
        try:
            r = input(f"  {bold('?')} {q} {dim('[' + default + ']')} ").strip() or default
        except EOFError:
            die("no interactive terminal (use --yes)")
    LOG.w(f"? {q} -> {r}")
    return r


def bar(i, n, label=""):
    if not TTY:
        return
    w = 24; f = int(w * i / max(n, 1))
    room = shutil.get_terminal_size().columns - w - 16
    print(f"\r  {cyan('[' + '█' * f + '░' * (w - f) + ']')} {i}/{n} {dim(label[-max(room, 10):])}\033[K", end="", flush=True)


def endbar():
    if TTY: print()


# ---------------------------------------------------------------- subprocess/git
class RunError(Exception):
    def __init__(self, cmd, p):
        self.cmd, self.p = cmd, p


def run(cmd, check=True, log_out=True):
    LOG.w("$ " + " ".join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if log_out:
        if p.stdout.strip(): LOG.w(p.stdout.rstrip())
        if p.stderr.strip(): LOG.w(p.stderr.rstrip())
    LOG.w(f"(exit {p.returncode})")
    if check and p.returncode:
        raise RunError(cmd, p)
    return p


def git(*a, check=True): return run(["git", *a], check).stdout.strip()


def gshow(ref, path):
    p = run(["git", "show", f"{ref}:{path}"], check=False, log_out=False)
    return p.stdout if p.returncode == 0 else None


def vt(v):
    n = [int(x) for x in re.findall(r"\d+", v or "0")[:3]]
    return tuple(n + [0] * (3 - len(n)))


def version_of(text):
    m = re.search(r'SEKURIRCD_VERSION\s+"([^"]+)"', text or "")
    return m.group(1) if m else None


def describe(ref) -> Any:
    p = run(["git", "rev-parse", "--verify", "--quiet", ref + "^{commit}"], check=False)
    if p.returncode:
        return None
    sha = p.stdout.strip()
    return {"ref": ref, "sha": sha, "short": sha[:7], "version": version_of(gshow(sha, "src/version.h")),
            "date": git("log", "-1", "--format=%cs", sha), "subject": git("log", "-1", "--format=%s", sha)}


def is_ancestor(a, b): return run(["git", "merge-base", "--is-ancestor", a, b], check=False).returncode == 0


def latest_release() -> Any:
    """(tag, title, source): gh CLI, then GitHub API, then newest local tag."""
    if shutil.which("gh"):
        p = run(["gh", "release", "list", "--limit", "1", "--exclude-drafts", "--exclude-pre-releases",
                 "--json", "tagName,name"], check=False)
        try:
            r = json.loads(p.stdout)[0]
            return r["tagName"], r["name"], "gh"
        except Exception:
            pass
    m = re.search(r"github\.com[:/](.+?)(?:\.git)?$", git("remote", "get-url", "origin", check=False))
    if m:
        try:
            req = urllib.request.Request(f"https://api.github.com/repos/{m[1]}/releases/latest",
                                         headers={"User-Agent": "sekurircd-upgrade"})
            with urllib.request.urlopen(req, timeout=8) as r:
                j = json.load(r)
            return j["tag_name"], j.get("name") or "", "GitHub API"
        except Exception as e:
            LOG.w(f"GitHub API failed: {e}")
    tags = git("tag", "--list", "v[0-9]*", "--sort=-v:refname").split()
    return (tags[0], "", "local git tags") if tags else None


# ---------------------------------------------------------------- config news
SEC_RE = re.compile(r"^\s*#?\s*(\[\[?[A-Za-z0-9_.-]+\]\]?)\s*$")
KEY_RE = re.compile(r"^\s*(#\s*)?([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*$")
VAL_RE = re.compile(r"""^("|'|-?\d|\[|\{|true\b|false\b)""")


def parse_settings(text):
    """{(section, key): {value, active, doc}}, {sections}. Commented example
    settings ('# key = value') count too -- templates document options that way."""
    d, secs, sec, doc = {}, set(), "", []
    for ln in (text or "").splitlines():
        s = SEC_RE.match(ln)
        if s:
            sec = s[1].strip("[]"); secs.add(sec); doc = []; continue
        k = KEY_RE.match(ln)
        if k and (not k[1] or (VAL_RE.match(k[3]) and not k[3].endswith("."))):
            d[(sec, k[2])] = {"value": k[3], "active": not k[1], "doc": doc[-6:]}; doc = []
        elif ln.strip().startswith("#"):
            t = ln.strip().lstrip("#").strip()
            if t and not set(t) <= set("-= "): doc.append(t)
        else:
            doc = []
    return d, secs


def diff_settings(old_text, new_text, live_text):
    old, osec = parse_settings(old_text)
    new, nsec = parse_settings(new_text)
    live, _ = parse_settings(live_text)
    return {
        "added": [(k, v, k in live) for k, v in new.items() if k not in old],
        "changed": [(k, old[k]["value"], v["value"]) for k, v in new.items() if k in old and old[k]["value"] != v["value"]],
        "removed": [(k, k in live and live[k]["active"]) for k in old if k not in new],
        "new_secs": sorted(nsec - osec),
    }


def config_news(old_ref, new_ref):
    res = []
    for tpl, live_path in TEMPLATES.items():
        new_t = gshow(new_ref, tpl)
        if new_t is None:
            continue
        old_t = gshow(old_ref, tpl)
        live_t = open(live_path).read() if os.path.exists(live_path) else None
        d = diff_settings(old_t, new_t, live_t)
        d.update(tpl=tpl, live=live_path, live_exists=live_t is not None, new_file=old_t is None)
        if d["added"] or d["changed"] or d["removed"] or d["new_secs"] or d["new_file"]:
            res.append(d)
    return res


def show_config_news(news, limit=25):
    if not news:
        ok("No new, changed or removed options in the config templates.")
        return
    info("Your config files are " + bold("never modified") + ". Compare, then copy what you want:")
    for d in news:
        out(); out(f"  {bold(d['live'])} {dim('(template: ' + d['tpl'] + ')')}")
        if d["new_file"]:
            warn("NEW template in this version" + ("" if d["live_exists"] else
                 f" -- optional; copy it to {d['live']} to enable"))
        if d["new_secs"]:
            info(f"{green('+ new sections:')} " + ", ".join(f"[{s}]" for s in d["new_secs"]))
        shown = 0
        for (sec, key), v, in_live in d["added"]:
            if d["new_file"]:
                break
            if shown == limit:
                info(dim(f"... {len(d['added']) - limit} more added options (see log)")); break
            shown += 1
            tag = dim("(already in your file)") if in_live else yellow("← missing from your file")
            info(f"{green('+ NEW')} [{sec}] {bold(key)} = {v['value']}  {tag}"
                 + ("" if v["active"] else dim("  (commented example)")))
            for line in v["doc"]:
                info(dim(f"      # {line}"))
        for (sec, key), a, b in d["changed"][:limit]:
            info(f"{yellow('~ DEFAULT CHANGED')} [{sec}] {bold(key)}: {a}  →  {b}")
        for (sec, key), active in d["removed"][:limit]:
            info(f"{red('- REMOVED')} [{sec}] {bold(key)}" + (yellow("  (still set in your file -- may be deprecated or moved; check the changelog)") if active else ""))
    LOG.w("(full config news above; long lists are capped on screen only)")
    for d in news:
        for (sec, key), v, in_live in d["added"]:
            LOG.w(f"CONFIG NEWS {d['live']}: +[{sec}] {key} = {v['value']} in_live={in_live}")


# ---------------------------------------------------------------- daemons (./sekurircd wrapper)
def daemon_status():
    p = run(["./sekurircd", "status"], check=False)
    return {m[1]: m[2] == "running" for ln in p.stdout.splitlines()
            if (m := re.match(r"(sekurircd|chanserv):\s+(\w+)", ln))}


def restart_daemons():
    out(); warn(bold("Restarting disconnects every connected user"))
    info("Users are dropped and must reconnect; ChanServ re-links after the ircd is back.")
    info("Usually a few seconds -- pick a quiet moment.")
    if ARGS.restart: go = True
    elif ARGS.no_restart: go = False
    else: go = ask("Stop the running services and start the new version now?", False)
    if not go:
        warn("Not restarting. The daemons keep running the " + bold("OLD") + " version until you do:")
        info(bold("./sekurircd stop && ./sekurircd start"))
        return False
    print(dim("  --- ./sekurircd stop")); run(["./sekurircd", "stop"], check=False)
    for _ in range(20):
        if not any(daemon_status().values()): break
        time.sleep(0.5)
    else:
        die("A daemon didn't stop (pidfile/process mismatch?). Not killing anything automatically -- "
            "use /restart-services, then run ./sekurircd start.")
    ok("stopped")
    run(["./sekurircd", "start"], check=False)
    time.sleep(2)
    st = daemon_status()
    for name, up in st.items():
        (ok if up else fail)(f"{name}: {'running' if up else 'NOT running'}")
    if not st.get("sekurircd"):
        info(dim("tail of logs/sekurircd.log:"))
        if os.path.exists("logs/sekurircd.log"):
            for l in open("logs/sekurircd.log", errors="replace").read().splitlines()[-8:]:
                info(dim("  " + l))
        return None
    return True


# ---------------------------------------------------------------- backups
def backup_dir():
    d = os.path.expanduser(ARGS.backup_dir or prompt("Where should backups be saved?", "~/sekurircd-backups"))
    if not ARGS.dry_run:
        os.makedirs(d, exist_ok=True)
        if not os.access(d, os.W_OK): die(f"{d} is not writable")
    return d


def config_backup(dest):
    p = run(["bash", "tools/backup-config.sh", dest], check=False)
    m = re.search(r"(\S*sekurircd-backup-\S+\.tar\.gz)", p.stdout)
    if p.returncode or not m: die("Config backup failed -- aborting before touching anything.")
    ok(f"Config backup: {bold(m[1])}")
    return m[1]


def full_backup(dest, cur):
    files = []
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in BACKUP_EXCLUDE and not d.endswith(".dSYM")]
        files += [os.path.join(dp, f) for f in fn
                  if not f.endswith((".pid", ".o", ".d", ".prev")) and f not in ("sekurircd-debug", "unit")]
    path = os.path.join(dest, f"sekurircd-full-{cur['version']}-{cur['short']}-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz")
    old = os.umask(0o077)
    try:
        with tarfile.open(path, "w:gz") as tf:
            for i, f in enumerate(files, 1):
                rel = os.path.relpath(f, ROOT)
                tf.add(f, arcname=f"sekurircd-{cur['version']}/{rel}", recursive=False)
                LOG.w(f"full backup + {rel}"); bar(i, len(files), rel)
    finally:
        os.umask(old)
    endbar()
    ok(f"Full backup ({len(files)} files, {os.path.getsize(path) // 1024} KB, source+binaries+config): {bold(path)}")
    info(dim("Excludes .git, build dirs and logs; the commit is recorded in the log."))
    return path


# ---------------------------------------------------------------- source switch / build / install
def dirty_files():
    p = run(["git", "status", "--porcelain", "--untracked-files=no"])
    return [l[3:] for l in p.stdout.splitlines()]  # not git(): its strip() would eat the first line's leading space


def switch(steps, target_sha, park=True):
    """Run git steps. Tracked files the admin edited locally (e.g. ircd.motd) that
    the target also changes would make git refuse; keep their edits, park the
    upstream copy next to them as <file>.upstream-<ver>."""
    cur = git("rev-parse", "HEAD")
    changed = set(git("diff", "--name-only", cur, target_sha).splitlines())
    dirty = dirty_files()
    keep = {f: open(f, "rb").read() for f in dirty if f in changed and os.path.isfile(f)}
    for f in keep:
        git("checkout", "--", f)
    try:
        for s in steps:
            git(*s)
    finally:
        ver = version_of(gshow(target_sha, "src/version.h")) or target_sha[:7]
        for f, data in keep.items():
            up = gshow(target_sha, f) if park else None
            if up is not None:
                open(f"{f}.upstream-{ver}", "w").write(up)
            open(f, "wb").write(data)
    return sorted(keep)


def build(expect_version):
    for d in ("bin.new", "build.new"): shutil.rmtree(d, ignore_errors=True)
    total = len(glob.glob("src/**/*.c", recursive=True)) + len(glob.glob("services/*.c"))
    cmd = ["make", f"-j{os.cpu_count() or 2}", "BIN_DIR=bin.new", "OBJ_DIR=build.new"]
    LOG.w("$ " + " ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    assert p.stdout
    n, tail = 0, collections.deque(maxlen=25)
    for line in p.stdout:
        LOG.w(line.rstrip()); tail.append(line.rstrip())
        if re.search(r"\s-c\s", line):
            n += 1; bar(min(n, total), total, "compiling")
    rc = p.wait(); endbar()
    if rc:
        for l in tail: info(dim(l))
        raise RuntimeError(f"make failed (exit {rc})")
    for name in ("sekurircd", "chanserv"):
        v = subprocess.run([f"bin.new/{name}", "--version"], capture_output=True, text=True).stdout.strip()
        LOG.w(f"bin.new/{name} --version -> {v}")
        # chanserv carries its own version number; only the ircd must match the release
        if not v.startswith(name) or (name == "sekurircd" and not v.endswith(expect_version)):
            raise RuntimeError(f"bin.new/{name} reports '{v}', expected {name} {expect_version if name == 'sekurircd' else '...'}")
    ok(f"Build OK: sekurircd {expect_version}, chanserv runs")


def install_binaries():
    had_prev = []
    for name in ("sekurircd", "chanserv"):
        cur = f"bin/{name}"
        if os.path.exists(cur):
            os.replace(cur, cur + ".prev"); had_prev.append(name)
        os.makedirs("bin", exist_ok=True)
        os.replace(f"bin.new/{name}", cur)
        sha = hashlib.sha256(open(cur, "rb").read()).hexdigest()
        ok(f"installed {cur}" + (f" {dim('(old kept as ' + name + '.prev)')}" if name in had_prev else ""))
        LOG.w(f"sha256 {cur} {sha}")
    shutil.rmtree("bin.new", ignore_errors=True); shutil.rmtree("build.new", ignore_errors=True)
    return had_prev


# ---------------------------------------------------------------- flow
def wrap(text, indent="      "):
    return textwrap.fill(text, width=min(shutil.get_terminal_size().columns, 110) - 2,
                         initial_indent=indent, subsequent_indent=indent + "  ")


def current_state():
    cur = describe("HEAD")
    cur["version"] = version_of(open("src/version.h").read()) or cur["version"]
    cur["branch"] = git("symbolic-ref", "-q", "--short", "HEAD", check=False) or None
    return cur


def preflight():
    step("Preflight")
    for tool in ("git", "make", os.environ.get("CC", "cc")):
        if not shutil.which(tool): die(f"required tool not found: {tool}")
    if run(["git", "rev-parse", "--is-inside-work-tree"], check=False).returncode:
        die("This upgrader needs a git clone of SekurIRCd.")
    p = run(["git", "fetch", "--tags", "origin"], check=False)
    (ok if p.returncode == 0 else warn)("fetched latest refs from origin" if p.returncode == 0
                                        else "could not reach origin -- using what's already fetched")
    cur = current_state()
    st = daemon_status()
    dirty = dirty_files()
    out()
    info(f"Installed  {bold('v' + cur['version'])}  {dim(cur['short'] + ' · ' + cur['date'])}  "
         f"on {cur['branch'] or 'detached HEAD'}")
    info("Running    " + ", ".join(f"{k}: {green('up') if v else dim('down')}" for k, v in st.items()))
    if dirty:
        warn(f"{len(dirty)} locally modified tracked file(s) -- they will be preserved:")
        for l in dirty[:8]: info(dim("  " + l))
    if not cur["branch"] and int(git("rev-list", "--count", "HEAD", "--not", "--remotes")):
        warn("HEAD is detached with commits that exist nowhere else -- they'd be left behind.")
    return cur, st


def choose_target(cur):
    step("Choose what to upgrade to")
    rel = latest_release()
    branch = (git("symbolic-ref", "--short", "refs/remotes/origin/HEAD", check=False) or "origin/main").split("/", 1)[1]
    opts = []
    if rel:
        d = describe(rel[0])
        if d:
            d.update(kind="release", title=rel[1], src=rel[2]); opts.append(d)
    m = describe(f"origin/{branch}")
    if m:
        m.update(kind="main", branch=branch); opts.append(m)

    def note(d):
        if d["sha"] == cur["sha"]: return green("← you are here")
        if is_ancestor(cur["sha"], d["sha"]):
            return yellow(f"{git('rev-list', '--count', cur['sha'] + '..' + d['sha'])} commit(s) ahead of you")
        if is_ancestor(d["sha"], cur["sha"]): return dim("already contained in your checkout")
        return red("diverged from your checkout")

    want = ARGS.channel
    if want:
        pick = next((o for o in opts if o["kind"] == want), None) or (describe(want) if want not in ("release", "main") else None)
        if not pick: die(f"can't resolve --channel {want}")
        pick.setdefault("kind", "ref")
        return pick
    out()
    if opts and all(o["sha"] == cur["sha"] for o in opts):
        ok("You're already on the latest release and latest commit -- nothing to upgrade to.")
        opts = []
    for i, o in enumerate(opts, 1):
        if o["kind"] == "release":
            info(f"{bold(f'[{i}]')} Latest {bold('release')}  {bold(o['ref'])} {o['title'] and '— ' + o['title'].split('—')[-1].strip()}"
                 f" {dim('(' + o['date'] + ', via ' + o['src'] + ')')}  {note(o)}")
        else:
            info(f"{bold(f'[{i}]')} Latest {bold('commits')}   origin/{o['branch']} @ {o['short']}"
                 f" {dim('(version ' + str(o['version']) + ', ' + o['date'] + ')')}  {note(o)}")
            info(dim(f"      newest commit: {o['subject']}"))
    info(f"{bold(f'[{len(opts) + 1}]')} A specific tag or commit")
    info(f"{bold('[q]')} Quit")
    while True:
        r = prompt("Choice", "1")
        if r.lower() == "q": sys.exit(0)
        if r.isdigit() and 1 <= int(r) <= len(opts): return opts[int(r) - 1]
        if r.isdigit() and int(r) == len(opts) + 1:
            d = describe(prompt("Tag or commit", ""))
            if d: d["kind"] = "ref"; return d
        warn("not a valid choice")


def review(cur, tgt):
    step("Review the change")
    out()
    tv, cv = vt(tgt["version"]), vt(cur["version"])
    arrow = "→" if tv >= cv else red("→ (DOWNGRADE)")
    info(f"{bold('v' + cur['version'])} {dim(cur['short'])}   {arrow}   {bold('v' + str(tgt['version']))} {dim(tgt['short'] + ' · ' + tgt['date'])}")
    if tv < cv: warn("Target is OLDER than what you run. Stored data (accounts, ChanServ) may not be readable by older code.")
    elif tgt["sha"] != cur["sha"] and is_ancestor(tgt["sha"], cur["sha"]):
        warn("Target is already contained in your checkout (you're ahead of it).")
    if tgt["sha"] == cur["sha"]:
        ok("Already on this exact commit -- nothing to do."); sys.exit(0)
    stat = git("diff", "--shortstat", cur["sha"], tgt["sha"])
    info(dim(stat))
    LOG.w(git("diff", "--stat", cur["sha"], tgt["sha"]))

    out(); out(bold("  Changelog"))
    entries = []
    try: entries = json.loads(gshow(tgt["sha"], "web/changelog.json") or "[]")
    except ValueError: pass
    new = [e for e in entries if cv < vt(e["tag"]) <= tv]
    for e in new:
        info(bold(green(f"{e['tag']}  ({e['date']})")))
        for ch in e["changes"]: out(wrap("• " + ch))
    if not new: info(dim("(no changelog entries newer than your version)"))
    commits = git("log", "--oneline", "--no-decorate", f"{cur['sha']}..{tgt['sha']}").splitlines()
    if commits and (tgt["kind"] != "release" or not new):
        out(); out(bold(f"  {len(commits)} commit(s) between you and target"))
        for l in commits[:15]: info(dim(l))
        if len(commits) > 15: info(dim(f"... and {len(commits) - 15} more"))

    out(); out(bold("  Config templates: what's new"))
    show_config_news(config_news(cur["sha"], tgt["sha"]))
    if tgt["kind"] == "main" and cur["branch"] == tgt["branch"] and not is_ancestor("HEAD", tgt["ref"]):
        die(f"Your local {cur['branch']} has commits that aren't on origin -- refusing to fast-forward over them.")


def upgrade(cur, st, tgt):
    step("Backups & plan")
    out()
    dest = backup_dir()
    plan = [f"Back up config to {dest}",
            "Back up the whole running install (optional)",
            f"Switch source to {tgt['ref']} ({tgt['short']})",
            "Build in a side directory (running binaries untouched until it succeeds)",
            "Install new binaries (old kept as bin/*.prev for instant rollback)",
            "Optionally restart the services"]
    for i, p in enumerate(plan, 1): info(f"{i}. {p}")
    if ARGS.dry_run:
        out(); warn(bold("DRY RUN -- nothing was changed.")); LOG.w("RESULT: DRY RUN"); return
    do_full = ask("Also make a COMPLETE backup of the running version (source, binaries, config)?", True)
    if not ask(f"Proceed with upgrade v{cur['version']} → v{tgt['version']}?", True):
        die("Cancelled -- nothing was changed.", 0)
    t0 = time.monotonic()
    backups = []

    step("Backing up")
    backups.append(config_backup(dest))
    if do_full: backups.append(full_backup(dest, cur))

    step("Updating source")
    steps = ([["checkout", tgt["branch"]], ["merge", "--ff-only", f"origin/{tgt['branch']}"]]
             if tgt["kind"] == "main" else [["checkout", "--detach", tgt["sha"]]])
    if tgt["kind"] == "main" and run(["git", "rev-parse", "--verify", "--quiet", tgt["branch"]], check=False).returncode:
        steps[0] = ["checkout", "-b", tgt["branch"], "--track", f"origin/{tgt['branch']}"]
    kept = switch(steps, tgt["sha"])
    ok(f"source is now at {tgt['short']}")
    for f in kept: warn(f"kept your local edits to {f}; upstream's new copy saved as {f}.upstream-{tgt['version']}")

    step("Building")
    try:
        build(tgt["version"])
    except RuntimeError as e:
        fail(str(e)); warn("Reverting the source tree; your running install was not touched.")
        revert(cur)
        for f in kept: os.remove(f"{f}.upstream-{tgt['version']}")
        LOG.w("RESULT: FAILED (build), reverted"); print(dim(f"  Log: {LOG.path}")); sys.exit(1)

    step("Installing")
    had_prev = install_binaries()
    state = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "from": {k: cur[k] for k in ("sha", "version", "branch")},
             "to": {k: tgt[k] for k in ("sha", "version")}, "prev_binaries": had_prev, "parked": [f"{f}.upstream-{tgt['version']}" for f in kept], "backups": backups, "log": LOG.path}
    json.dump(state, open(STATE_FILE, "w"), indent=2)

    step("Restart")
    result = restart_daemons() if any(st.values()) else None
    if not any(st.values()): info("No daemons were running -- start them with ./sekurircd start")
    if result is None and any(st.values()) and not ARGS.no_restart and ask("The new ircd did not come up. Roll back now?", True):
        rollback(); return

    out(); out(bold(green("━━ Upgrade complete")))
    info(f"v{cur['version']} → {bold('v' + tgt['version'])} in {time.monotonic() - t0:.0f}s")
    for b in backups: info(f"backup: {b}")
    info(f"log:    {LOG.path}")
    info(f"undo:   {bold('tools/upgrade.py --rollback')}")
    info(dim("Reminder: review the 'config templates: what's new' section above / in the log."))
    LOG.w("RESULT: SUCCESS")


def revert(prev):
    steps = [["checkout", "--detach", prev["sha"]]]
    if prev.get("branch"): steps += [["branch", "-f", prev["branch"], prev["sha"]], ["checkout", prev["branch"]]]
    switch(steps, prev["sha"], park=False)
    shutil.rmtree("bin.new", ignore_errors=True); shutil.rmtree("build.new", ignore_errors=True)


def rollback():
    global _step
    if not os.path.exists(STATE_FILE): die("No previous upgrade recorded (logs/upgrade-state.json missing).")
    s = json.load(open(STATE_FILE))
    step("Roll back")
    out(); info(f"Undo the upgrade from {s['time']}: v{s['to']['version']} → back to {bold('v' + s['from']['version'])}")
    if not ask("Roll back the source and binaries?", True): die("Cancelled.", 0)
    if ARGS.dry_run: warn("DRY RUN"); return
    prev = {"sha": s["from"]["sha"], "branch": s["from"]["branch"]}
    kept = switch([["checkout", "--detach", prev["sha"]]] + (
        [["branch", "-f", prev["branch"], prev["sha"]], ["checkout", prev["branch"]]] if prev["branch"] else []), prev["sha"], park=False)
    for f in kept: warn(f"kept your local edits to {f}")
    if len(s["prev_binaries"]) == 2 and all(os.path.exists(f"bin/{n}.prev") for n in ("sekurircd", "chanserv")):
        for n in ("sekurircd", "chanserv"): os.replace(f"bin/{n}.prev", f"bin/{n}")
        ok("restored previous binaries (no rebuild needed)")
    else:
        warn("previous binaries not available -- rebuilding"); build(s["from"]["version"]); install_binaries()
    st = daemon_status()
    if any(st.values()): restart_daemons()
    for f in s.get("parked", []):
        if os.path.exists(f): os.remove(f)
    os.remove(STATE_FILE)
    ok(bold("Rolled back.")); info(f"log: {LOG.path}"); LOG.w("RESULT: ROLLED BACK")


def check():
    """Report-only: is there a newer release, or new commits on origin's default branch?
    Exit 0 = up to date, 10 = updates available (handy for cron)."""
    p = run(["git", "fetch", "--tags", "origin"], check=False)
    if p.returncode: warn("could not reach origin -- reporting against what's already fetched")
    cur = current_state()
    out(); info(f"Installed  {bold('v' + cur['version'])}  {dim(cur['short'] + ' · ' + cur['date'])}  "
                f"on {cur['branch'] or 'detached HEAD'}")
    news = 0

    out(); out(bold(cyan("  Releases")))
    rel = latest_release()
    d = describe(rel[0]) if rel else None
    if not d:
        warn("could not determine the latest release")
    elif vt(rel[0]) > vt(cur["version"]):
        news += 1
        warn(f"{bold(yellow('NEW RELEASE'))} {bold(rel[0])} {dim('(' + d['date'] + ', via ' + rel[2] + ')')}"
             f"  — you run v{cur['version']}")
        try: entries = json.loads(gshow(d["sha"], "web/changelog.json") or "[]")
        except ValueError: entries = []
        for e in [e for e in entries if vt(cur["version"]) < vt(e["tag"]) <= vt(rel[0])]:
            info(bold(green(f"{e['tag']}  ({e['date']})")))
            for ch in e["changes"]: out(wrap("• " + ch))
    else:
        ok(f"Up to date with the latest release ({bold(rel[0])})")

    out(); out(bold(cyan("  Commits")))
    branch = (git("symbolic-ref", "--short", "refs/remotes/origin/HEAD", check=False) or "origin/main").split("/", 1)[1]
    m = describe(f"origin/{branch}")
    if not m:
        warn(f"origin/{branch} not found")
    elif m["sha"] == cur["sha"] or is_ancestor(m["sha"], cur["sha"]):
        ok(f"No new commits on origin/{branch}")
    elif is_ancestor(cur["sha"], m["sha"]):
        news += 1
        log = git("log", "--format=%h|%cs|%s", "--no-decorate", f"{cur['sha']}..{m['sha']}").splitlines()
        warn(f"{bold(yellow(str(len(log)) + ' new commit(s)'))} on origin/{branch} "
             f"{dim('(version ' + str(m['version']) + ')')} since your checkout")
        for l in log[:10]:
            h, dt, s = l.split("|", 2)
            info(f"  {cyan(h)} {dim(dt)} {s}")
        if len(log) > 10: info(dim(f"  ... and {len(log) - 10} more"))
    else:
        warn(red("Your checkout has diverged from ") + f"origin/{branch}" + " — upgrade would need a manual look")
        news += 1

    out()
    if news: out(bold(yellow("  ▲ Updates available")) + f"  — run {bold('tools/upgrade.py')} to upgrade")
    else: out(bold(green("  ✔ Everything is up to date")))
    LOG.w(f"RESULT: CHECK news={news}")
    sys.exit(10 if news else 0)


def selftest():
    assert vt("1.0.10") > vt("1.0.9") and vt("v1.2") == (1, 2, 0)
    old = "[a]\n# doc line\nx = 1\n"
    new = old + "\n[b]\n# new opt\n# y = \"z\"\nx = 2\n"
    d = diff_settings(old, new, "[a]\nx = 1\n")
    assert [k for k, _, _ in d["added"]] == [("b", "y"), ("b", "x")] and d["new_secs"] == ["b"]
    assert d["added"][0][1]["doc"] == ["new opt"] and not d["added"][0][1]["active"]
    d = diff_settings(new, old, "")
    assert [k for k, _ in d["removed"]] == [("b", "y"), ("b", "x")]
    assert diff_settings("[a]\nx = 1\n", "[a]\nx = 2\n", "")["changed"] == [(("a", "x"), "1", "2")]
    print("selftest ok")


def main():
    global ARGS, LOG, _total
    ap = argparse.ArgumentParser(description="SekurIRCd upgrade assistant")
    ap.add_argument("--channel", help="release | main | <tag or commit> (skips the menu)")
    ap.add_argument("-y", "--yes", action="store_true", help="accept defaults (restart stays off unless --restart)")
    ap.add_argument("--dry-run", action="store_true", help="show everything, change nothing")
    ap.add_argument("--backup-dir", help="where backups go (default: ask, ~/sekurircd-backups)")
    ap.add_argument("--restart", action="store_true", help="restart services without asking")
    ap.add_argument("--no-restart", action="store_true", help="never restart")
    ap.add_argument("--rollback", action="store_true", help="undo the last upgrade")
    ap.add_argument("--check", action="store_true", help="only report new releases/commits (exit 10 if any)")
    ap.add_argument("--selftest", action="store_true")
    ARGS = ap.parse_args()
    if ARGS.selftest: return selftest()
    os.chdir(ROOT)
    if ARGS.rollback: _total = 1
    kind = "rollback" if ARGS.rollback else "check" if ARGS.check else "upgrade"
    LOG = Log(kind)
    LOG.w(f"SekurIRCd {kind} log -- {time.strftime('%Y-%m-%d %H:%M:%S %z')}")
    LOG.w(f"host={socket.gethostname()} user={getpass.getuser()} os={platform.platform()} python={platform.python_version()}")
    LOG.w(f"cwd={ROOT} args={sys.argv[1:]}")
    subprocess.run(["bash", "-c", 'source tools/lib.sh; banner'])  # shared banner; clears the screen on a tty
    out(bold(cyan("  Upgrade assistant")) + (yellow("  [DRY RUN]") if ARGS.dry_run else ""))
    out(dim(f"  {ROOT}\n  log: {LOG.path}"))
    try:
        if ARGS.check:
            check()
        elif ARGS.rollback:
            rollback()
        else:
            cur, st = preflight()
            tgt = choose_target(cur)
            review(cur, tgt)
            upgrade(cur, st, tgt)
    except KeyboardInterrupt:
        out(); fail("Interrupted. Check `git status`; running binaries are untouched unless the install step had started.")
        LOG.w("RESULT: INTERRUPTED"); sys.exit(130)
    except RunError as e:
        fail(f"command failed: {' '.join(e.cmd)}")
        for l in (e.p.stderr or e.p.stdout).strip().splitlines()[-8:]: info(dim(l))
        LOG.w("RESULT: FAILED"); print(dim(f"  Log: {LOG.path}")); sys.exit(1)


if __name__ == "__main__":
    main()
