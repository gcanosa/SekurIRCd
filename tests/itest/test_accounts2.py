import base64, os, stat, tempfile, time
from harness import Server
from test_accounts import register, scram_login

ACC = {"accounts": {"enabled": True, "store_file": "acc.json"}}


def ns(c, line, wait=1.2):
    c.drain(0.05)
    c.send(f"PRIVMSG NickServ :{line}")
    time.sleep(wait)
    return [l for l in c.drain(0.2) if "NickServ" in l]


def sasl_plain(s, nick, account, pw):
    c = s.client(nick, register=False, extra=["CAP REQ :sasl"])
    c.send("AUTHENTICATE PLAIN")
    c.expect(r"AUTHENTICATE \+")
    c.send("AUTHENTICATE " + base64.b64encode(f"\0{account}\0{pw}".encode()).decode())
    return c.saw(r" 903 ", 3)


def test_set_password_changes_plain_and_scram():
    with Server(cfg=ACC) as s:
        c = register(s, "pw1", "pwacct", "oldpass123")
        r = ns(c, "SET PASSWORD wrongold newpass456")
        assert any("incorrect" in l for l in r), r
        r = ns(c, "SET PASSWORD oldpass123 newpass456", 2.0)
        assert any("Password changed" in l for l in r), r
        assert sasl_plain(s, "pw2", "pwacct", "newpass456"), "new password works"
        assert not sasl_plain(s, "pw3", "pwacct", "oldpass123"), "old password no longer works"
        assert scram_login(s, "pw4", "pwacct", "newpass456") == "ok", "SCRAM verifier follows the password change"


def test_drop_account_logs_out_and_removes():
    with Server(cfg=ACC) as s:
        c = register(s, "dr1", "dropme", "dropped123")
        assert any("incorrect" in l for l in ns(c, "DROP nopenope"))
        r = ns(c, "DROP dropped123", 2.0)
        assert any("dropped" in l for l in r), r
        assert any("not identified" in l for l in ns(c, "INFO")), "sessions are logged out"
        assert not sasl_plain(s, "dr2", "dropme", "dropped123")


def test_logout_and_info():
    with Server(cfg=ACC) as s:
        c = register(s, "li1", "liacct", "password1")
        r = ns(c, "INFO")
        assert any("Account liacct" in l for l in r), r
        c.drain()
        c.send("PRIVMSG NickServ :LOGOUT")
        assert c.saw(r" 901 ", 1.5)
        assert any("not identified" in l for l in ns(c, "INFO"))


def test_email_verification_flow():
    d = tempfile.mkdtemp(prefix="itest-mail-")
    out = os.path.join(d, "mail.txt")
    script = os.path.join(d, "send.sh")
    with open(script, "w") as f:
        f.write(f'#!/bin/sh\necho "$1 $2 $3 $4" > {out}\n')
    os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR)
    cfg = {"accounts": {"enabled": True, "store_file": "acc.json", "email_command": script}}
    with Server(cfg=cfg) as s:
        c = register(s, "em1", "emacct", "password1")
        assert any("valid email" in l for l in ns(c, "SET EMAIL not-an-email"))
        assert any("valid email" in l for l in ns(c, "SET EMAIL x;rm@e.com"))  # shell metacharacters never reach exec
        r = ns(c, "SET EMAIL me@example.org")
        assert any("verification code was sent" in l for l in r), r
        time.sleep(0.3)
        addr, code, account, network = open(out).read().split()
        assert addr == "me@example.org" and account == "emacct" and network == "TestNet", (addr, account, network)
        assert any("wrong or has expired" in l for l in ns(c, "VERIFY 00000000"))
        assert any("Email verified" in l for l in ns(c, f"VERIFY {code}"))
        assert any("(verified)" in l for l in ns(c, "INFO"))


def test_email_given_at_register_is_stored_without_command():
    with Server(cfg=ACC) as s:
        c = s.client("rg1")
        ns(c, "REGISTER password1 me@example.org", 1.8)
        r = ns(c, "INFO")
        assert any("me@example.org (unverified)" in l for l in r), r


def test_group_nick_identifies_and_is_enforced():
    cfg = {"accounts": {"enabled": True, "store_file": "acc.json", "enforce_nicks": True, "enforce_grace": 5}}
    with Server(cfg=cfg) as s:
        c = register(s, "main", "main", "password1")
        c.say("NICK alt")
        assert any("now part of account main" in l for l in ns(c, "GROUP")), "alt joins main's group"
        c.send("QUIT")
        squatter = s.client("alt")
        assert squatter.saw(r"This nickname is registered", 2)  # enforcement covers grouped nicks
        owner = s.client("tmpnick")
        owner.say("NICK alt2")
        assert squatter.saw(r"NICK :Guest\d+", 7.5)
        # identifying while using the grouped nick, with the account password, stops the rename
        s2 = s.client("alt")
        s2.send("PRIVMSG NickServ :IDENTIFY password1")
        assert s2.saw(r"identified for main", 3)
        time.sleep(6.5)
        assert not s2.saw(r"NICK :Guest", 0.3)
