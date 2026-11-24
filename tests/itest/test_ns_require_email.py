"""[nickserv] require_email: REGISTER needs an email, and the account does nothing (no IDENTIFY, no SASL, no nick
enforcement) until VERIFY with the mailed code -- through NickServ or the ircd's draft/account-registration VERIFY. Existing
accounts are untouched, an admin can ACTIVATE, a registration never verified is dropped after verify_window_hours, and
require_email without email_command is refused."""
import hashlib, json, os, re, secrets, stat, subprocess, time
from harness import Server, SERVICES
from test_accounts2 import ns, sasl_plain
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
from linkmgmt import scrypt_hash  # the services' password format (falls back to bin/sekurircd where hashlib has no scrypt)


def last_code(mails, account):
    """The code of the newest mail to `account` (the mailer script logs its arguments: address code account network purpose)."""
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            hits = [l.split() for l in open(mails) if l.split()[2:3] == [account]]
        except FileNotFoundError:
            hits = []
        if hits:
            return hits[-1][1]
        time.sleep(0.2)
    raise AssertionError(f"no mail for {account}")


def server():
    s = Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json", "require_email": True, "enforce_nicks": True,
                                 "admins": ["boss"]}})
    mails = os.path.join(s.dir, "mails")
    mailer = os.path.join(s.dir, "mailer.sh")
    with open(mailer, "w") as f:
        f.write(f'#!/bin/sh\necho "$@" >> {mails}\n')
    os.chmod(mailer, stat.S_IRWXU)
    s.cfg["accounts"]["email_command"] = mailer
    now = int(time.time())
    json.dump({"boss": {"name": "boss", "pw_hash": scrypt_hash("bosspass1"), "created_at": now - 86400},           # from before
               "stale": {"name": "stale", "pw_hash": "scrypt$16384$8$1$00$00", "created_at": now - 2 * 86400, "unverified": True}},
              open(os.path.join(s.dir, "acc.json"), "w"))
    return s, mails


def test_registration_waits_for_the_email():
    s, mails = server()
    with s:
        p = s.client("probe")
        assert "No such account" in " ".join(ns(p, "INFO stale", 0.8)), "a registration never verified in time is dropped"
        b = s.client("boss")
        assert any("identified" in l for l in ns(b, "IDENTIFY bosspass1", 1.5)), "existing accounts keep working"

        n = s.client("newbie")
        assert any("needs an email address" in l for l in ns(n, "REGISTER newbiepass1", 1.2))
        assert any("A code was sent to nb@example.org" in l for l in ns(n, "REGISTER newbiepass1 nb@example.org", 1.5))
        code = last_code(mails, "newbie")
        assert not any(" 900 " in l for l in n.drain(0.3)), "not logged in yet"
        assert "Not active yet" in " ".join(ns(p, "INFO newbie", 0.8))
        assert any("not active yet" in l for l in ns(n, "IDENTIFY newbiepass1", 1.5))
        assert not sasl_plain(s, "sasltry", "newbie", "newbiepass1"), "no SASL either"
        assert not any("This nickname is registered" in l for l in s.client("newbie2").say("NICK newbie2", 0.3)), "nothing to protect yet"
        assert any("wrong or has expired" in l for l in ns(n, "VERIFY 00000000", 1.0))
        got = ns(n, f"VERIFY {code}", 1.5)
        assert any("active and you are logged in" in l for l in got), got
        assert "Email: nb@example.org (verified)" in " ".join(ns(n, "INFO", 0.8))

        # an admin can activate one whose mail never came
        w = s.client("waiting")
        ns(w, "REGISTER waitpass12 w@example.org", 1.5)
        assert any("activated account waiting" in l for l in ns(b, "ACTIVATE waiting", 1.0))
        assert any("identified" in l for l in ns(w, "IDENTIFY waitpass12", 1.5))


def test_ircv3_register_and_verify():
    """Its own server: every test client is 127.0.0.1, and registrations and wrong codes share one per-IP budget."""
    s, mails = server()
    with s:
        # draft/account-registration: the same through the ircd's REGISTER and VERIFY
        caps = ["draft/account-registration", "standard-replies"]
        assert any("FAIL REGISTER INVALID_EMAIL" in l for l in s.client("noemail", caps=caps).say("REGISTER * * :Secretpass123", 1.5))
        c = s.client("ircv3", caps=caps)
        got = c.say("REGISTER * v3@example.org :Secretpass123", 1.5)
        assert any("REGISTER VERIFICATION_REQUIRED ircv3" in l for l in got), got
        assert any("FAIL VERIFY INVALID_CODE" in l for l in c.say("VERIFY ircv3 deadbeef", 1.5))
        got = c.say(f"VERIFY ircv3 {last_code(mails, 'ircv3')}", 1.5)
        assert any("VERIFY SUCCESS ircv3" in l for l in got) and any(" 900 " in l for l in got), got


def test_require_email_needs_a_mailer(tmp_path=None):
    import tempfile
    d = tempfile.mkdtemp(prefix="itest-reqmail-")
    conf = os.path.join(d, "services.toml")
    with open(conf, "w") as f:
        f.write('[link]\nhost = "127.0.0.1"\nport = 1\nname = "x.y"\npassword = "p"\n[chanserv]\nnick = "ChanServ"\n'
                '[nickserv]\nrequire_email = true\n[storage]\npath = "cs.json"\n')
    r = subprocess.run([SERVICES, "-t", "-c", conf], capture_output=True, text=True, timeout=10)
    assert r.returncode != 0 and "require_email = true needs email_command" in r.stdout + r.stderr, r
