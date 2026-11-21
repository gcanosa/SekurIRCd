"""tools/upgrade.py on an install that is not a git checkout (a source tarball): --check and --rollback say so, an upgrade
offers to convert it and never does so on --yes alone, and the conversion writes nothing but .git."""
import importlib.util, os, shutil, subprocess, sys, tempfile
from argparse import Namespace

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HAVE_GIT = shutil.which("git") is not None  # the CI images without git have nothing to test here


def git(cwd, *a):
    return subprocess.run(["git", "-c", "user.email=t@example.org", "-c", "user.name=t", *a], cwd=cwd,
                          capture_output=True, text=True, check=True).stdout.strip()


def make_origin(d):
    """v1.0.0, then a commit on main that changes f.txt; version.h keeps saying 1.0.0 (as a tarball of main does)."""
    os.makedirs(d)
    git(d, "init", "-q")
    git(d, "symbolic-ref", "HEAD", "refs/heads/main")

    def commit(files, msg):
        for p, t in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, p)), exist_ok=True)
            with open(os.path.join(d, p), "w") as f:
                f.write(t)
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", msg)

    commit({"src/version.h": '#define SEKURIRCD_VERSION "1.0.0"\n', "f.txt": "one\n", ".gitignore": "/config/live.toml\n",
            **{f"a{i}.txt": f"{i}\n" for i in range(12)}}, "release")
    git(d, "tag", "v1.0.0")
    commit({"f.txt": "two\n"}, "after the release")
    return d


def tarball(origin, ref, dest):
    """What unpacking a source tarball of `ref` gives: the files, no .git, plus the upgrader where it lives."""
    os.makedirs(dest)
    data = subprocess.run(["git", "archive", "--format=tar", ref], cwd=origin, capture_output=True, check=True).stdout
    subprocess.run(["tar", "-xf", "-", "-C", dest], input=data, check=True)
    os.makedirs(f"{dest}/tools")
    for f in ("upgrade.py", "lib.sh"):
        shutil.copy(f"{REPO}/tools/{f}", f"{dest}/tools/{f}")


def snapshot(d):
    """Every file but .git and logs/: path -> bytes (what the conversion must leave exactly as it was)."""
    s = {}
    for r, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if x not in (".git", "logs")]
        for f in files:
            p = os.path.join(r, f)
            s[os.path.relpath(p, d)] = open(p, "rb").read()
    return s


def convert(dest, origin, yes=True):
    """convert_to_clone() inside `dest` (the module's own functions, as main() would call them)."""
    spec = importlib.util.spec_from_file_location("upgrade_under_test", f"{REPO}/tools/upgrade.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    cwd = os.getcwd()
    os.chdir(dest)
    try:
        m.ARGS = Namespace(yes=yes, convert=True, origin=origin, dry_run=False, check=False, rollback=False)
        m.LOG = m.Log("test")
        m.convert_to_clone()
        return m.clone_problem()
    finally:
        os.chdir(cwd)


def cli(dest, *args):
    p = subprocess.run([sys.executable, "tools/upgrade.py", *args], cwd=dest, capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout + p.stderr


def test_a_release_tarball_becomes_a_checkout_and_keeps_every_file():
    if not HAVE_GIT: return
    root = tempfile.mkdtemp(prefix="itest-upgclone-")
    try:
        origin = make_origin(f"{root}/origin")
        dest = f"{root}/SekurIRCd-1.0.0"
        tarball(origin, "v1.0.0", dest)
        with open(f"{dest}/f.txt", "w") as f:
            f.write("mine\n")  # a local edit
        os.makedirs(f"{dest}/config")
        with open(f"{dest}/config/live.toml", "w") as f:
            f.write("secret = 1\n")  # the live config: ignored by the repo's .gitignore
        before = snapshot(dest)
        assert convert(dest, origin) is None, "it is a checkout now"
        assert git(dest, "rev-parse", "HEAD") == git(origin, "rev-parse", "v1.0.0"), "the release the files match"
        assert git(dest, "symbolic-ref", "--short", "HEAD") == "main"
        assert git(dest, "branch", "--format=%(refname:short)") == "main", "no stray branch"
        assert git(dest, "rev-parse", "--abbrev-ref", "main@{upstream}") == "origin/main"
        assert git(dest, "status", "--porcelain", "--untracked-files=no") == "M f.txt", "the edit is an edit, nothing more"
        assert snapshot(dest) == before, "no file was written, removed or changed"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_tarball_of_main_matches_main_not_the_release_its_version_names():
    if not HAVE_GIT: return
    root = tempfile.mkdtemp(prefix="itest-upgclone-")
    try:
        origin = make_origin(f"{root}/origin")
        dest = f"{root}/snap"
        tarball(origin, "main", dest)  # version.h says 1.0.0, the code is newer than v1.0.0
        assert convert(dest, origin) is None
        assert git(dest, "rev-parse", "HEAD") == git(origin, "rev-parse", "main")
        assert git(dest, "status", "--porcelain", "--untracked-files=no") == ""
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_copy_that_matches_nothing_closely_is_refused_unattended_and_left_alone():
    if not HAVE_GIT: return
    root = tempfile.mkdtemp(prefix="itest-upgclone-")
    try:
        origin = make_origin(f"{root}/origin")
        dest = f"{root}/messy"
        tarball(origin, "v1.0.0", dest)
        for i in range(12):  # a snapshot between releases: more than a few files differ from any release
            with open(f"{dest}/a{i}.txt", "w") as f:
                f.write("changed\n")
        before = snapshot(dest)
        try:
            convert(dest, origin)  # --yes: the default answer to "use this?" is no
            assert False, "must refuse"
        except SystemExit as e:
            assert e.code == 11
        assert not os.path.exists(f"{dest}/.git"), "the .git it made is gone again"
        assert snapshot(dest) == before
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_an_unreachable_origin_changes_nothing():
    if not HAVE_GIT: return
    root = tempfile.mkdtemp(prefix="itest-upgclone-")
    try:
        origin = make_origin(f"{root}/origin")
        dest = f"{root}/offline"
        tarball(origin, "v1.0.0", dest)
        before = snapshot(dest)
        try:
            convert(dest, f"{root}/does-not-exist")
            assert False, "must stop"
        except SystemExit as e:
            assert e.code == 1
        assert not os.path.exists(f"{dest}/.git") and snapshot(dest) == before
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_no_mode_touches_a_tarball_without_being_asked():
    if not HAVE_GIT: return
    root = tempfile.mkdtemp(prefix="itest-upgclone-")
    try:
        origin = make_origin(f"{root}/origin")
        dest = f"{root}/SekurIRCd-1.0.0"
        tarball(origin, "v1.0.0", dest)
        before = snapshot(dest)
        # a copy inside someone else's repository: git answers for the outer one, which must not count
        outer = f"{root}/outer"
        os.makedirs(outer)
        git(outer, "init", "-q")
        git(outer, "commit", "-q", "--allow-empty", "-m", "outer")
        nested = f"{outer}/SekurIRCd"
        tarball(origin, "v1.0.0", nested)
        for d in (dest, nested):
            for args in (("--check",), ("--rollback",), ("--yes",)):
                rc, out = cli(d, *args)
                assert rc == 11, (d, args, rc, out)
                assert "Traceback" not in out and "Not a git checkout" in out, out
                assert not os.path.exists(f"{d}/.git"), f"{args} created a .git"
            rc, out = cli(d, "--dry-run")
            assert rc == 0 and "DRY RUN" in out and not os.path.exists(f"{d}/.git"), out
        assert git(outer, "status", "--porcelain", "--untracked-files=no") == "", "the outer repository was not touched"
        assert snapshot(dest) == before
    finally:
        shutil.rmtree(root, ignore_errors=True)
