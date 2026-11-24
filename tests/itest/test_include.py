"""include = [...] in the main config: more [sections] and [[tables]] from other files, read at start and at REHASH."""
import os, subprocess
from harness import Server, IRCD


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def include(s, line='include = ["conf.d/*.toml", "more.toml"]\n'):
    """The harness renders only tables, and `include` is a root key (above every table): put it first in each config it writes."""
    orig = s.write_config

    def write_config():
        orig()
        with open(s.cfg_path) as f:
            text = f.read()
        with open(s.cfg_path, "w") as f:
            f.write(line + text)
    s.write_config = write_config
    return s


def test_included_files_add_opers_and_settings_and_a_rehash_rereads_them():
    s = include(Server(cfg={"limits": {"silence_entries": 7}}))
    write(os.path.join(s.dir, "conf.d", "opers.toml"), '# the opers\n[[operators]]\nname = "inc"\npassword = "incpw"\nhosts = ["*@*"]\n')
    write(os.path.join(s.dir, "more.toml"), "[privacy]\nhide_idle = true\n")
    with s:
        a = s.client("a")
        assert "SILENCE=7" in " ".join(a.lines), "the main file's own sections still count"
        assert any(" 381 " in l for l in a.say("OPER inc incpw", 0.5)), "an oper from an included file"
        b = s.client("b")
        assert not any(" 317 " in l for l in b.say("WHOIS a", 0.4)), "hide_idle came from more.toml"
        write(os.path.join(s.dir, "conf.d", "opers.toml"), '[[operators]]\nname = "inc2"\npassword = "inc2pw"\nhosts = ["*@*"]\n')
        s.reload()
        d = s.client("d")
        assert any(" 381 " in l for l in d.say("OPER inc2 inc2pw", 0.5)), "the rehash re-read the included file"


def check(text_of_conf_d_file):
    s = include(Server(), 'include = ["conf.d/*.toml"]\n')
    s.write_config()
    write(os.path.join(s.dir, "conf.d", "x.toml"), text_of_conf_d_file)
    r = subprocess.run([IRCD, "--check", "-c", s.cfg_path], capture_output=True, text=True, cwd=s.dir)
    s.stop()
    return r.returncode, r.stdout + r.stderr


def test_a_bad_include_is_named_in_the_error():
    rc, out = check("[[classes]]\nname = oops\n")
    assert rc != 0 and "x.toml" in out and "line 2 of it" in out, out
    rc, out = check('stray = 1\n[server]\nname = "x.y"\n')
    assert rc != 0 and "must start with a [section]" in out, out
    rc, out = check("")
    assert rc == 0, out
