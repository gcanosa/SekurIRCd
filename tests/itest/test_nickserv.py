import os, stat, tempfile, time
from harness import Server
from test_accounts import register
from test_accounts2 import ns, sasl_plain

OPERS = [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]},
         {"name": "helper", "password": "helperpw", "hosts": ["*@*"], "privileges": ["kill"]}]


def mail_script():
    d = tempfile.mkdtemp(prefix="itest-mail-")
    out = os.path.join(d, "mail.txt")
    script = os.path.join(d, "send.sh")
    with open(script, "w") as f:
        f.write(f'#!/bin/sh\necho "$1 $2 $3 $4 $5" >> {out}\n')
    os.chmod(script, os.stat(script).st_mode | stat.S_IXUSR)
    return script, out


def last_mail(out):
    time.sleep(0.3)
    return open(out).read().split("\n")[-2].split()


def test_resetpass_by_email_code():
    script, out = mail_script()
    with Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json", "email_command": script}}) as s:
        c = register(s, "rp1", "rpacct", "oldpass123")
        ns(c, "SET EMAIL me@example.org")
        assert last_mail(out)[4] == "verify"
        assert any("Email verified" in l for l in ns(c, f"VERIFY {last_mail(out)[1]}"))
        o = s.client("forgetful")
        unknown = ns(o, "RESETPASS nosuchacct")
        known = ns(o, "RESETPASS rpacct")
        assert any("If that account" in l for l in unknown) and any("If that account" in l for l in known), "same reply either way"
        addr, code, account, _, purpose = last_mail(out)
        assert (addr, account, purpose) == ("me@example.org", "rpacct", "reset"), (addr, account, purpose)
        assert any("wrong or has expired" in l for l in ns(o, "RESETPASS rpacct 000000000000 newpass456"))
        r = ns(o, f"RESETPASS rpacct {code} newpass456", 2.0)
        assert any("you are now identified" in l for l in r), r
        assert any("not identified" in l for l in ns(c, "INFO")), "the old session is logged out"
        assert any("wrong or has expired" in l for l in ns(o, f"RESETPASS rpacct {code} again12345")), "a code works once"
        assert sasl_plain(s, "rp2", "rpacct", "newpass456")
        assert not sasl_plain(s, "rp3", "rpacct", "oldpass123")


def test_resetpass_without_mail_is_unavailable():
    with Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json"}}) as s:
        c = s.client("rpx")
        assert any("not available" in l for l in ns(c, "RESETPASS whoever"))


def test_regain_renames_squatter_and_takes_nick():
    with Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json"}}) as s:
        c = register(s, "owner", "owner", "password1")
        c.say("NICK elsewhere")
        squatter = s.client("owner")
        assert any("IDENTIFY first" in l for l in ns(squatter, "REGAIN owner"))
        other = register(s, "other", "other", "password2")
        assert any("do not own" in l for l in ns(other, "REGAIN owner")), "identified, but as someone else"
        c.drain()
        r = ns(c, "REGAIN owner")
        assert any("regained owner" in l for l in r), r
        assert squatter.saw(r"NICK :Guest\d+", 1)
        assert any(" 311 elsewhere owner " in l or " 311 owner owner " in l for l in c.say("WHOIS owner"))


def test_oper_suspend_unsuspend_saset_fdrop():
    with Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json"}, "operators": OPERS}) as s:
        v = register(s, "victim", "victim", "password1")
        h = s.client("help1")
        h.say("OPER helper helperpw")
        assert any("Permission denied" in l for l in ns(h, "SUSPEND victim"))
        o = s.client("boss1")
        assert o.saw(r" 381 ", 0) or any(" 381 " in l for l in o.say("OPER boss bosspw"))
        v.drain()
        assert any("suspended account victim" in l for l in ns(o, "SUSPEND victim spamming"))
        assert v.saw(r" 901 ", 1), "suspension logs the account out"
        assert any("is suspended" in l for l in ns(v, "IDENTIFY password1"))
        assert not sasl_plain(s, "v2", "victim", "password1")
        assert any("Suspended by boss1: spamming" in l for l in ns(o, "INFO victim"))
        assert any("This account is suspended" in l for l in ns(h, "INFO victim")), "non-account opers see only the fact"
        assert any("unsuspended" in l for l in ns(o, "UNSUSPEND victim"))
        assert sasl_plain(s, "v3", "victim", "password1")
        assert any("Password of victim changed" in l for l in ns(o, "SASET PASSWORD victim newpass99", 2.0))
        assert sasl_plain(s, "v4", "victim", "newpass99")
        assert any("force-dropped" in l for l in ns(o, "FDROP victim"))
        assert any("No such account" in l for l in ns(o, "INFO victim"))


def test_whois_nickserv_and_service_aliases():
    with Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json"}}) as s:
        c = s.client("al1")
        r = c.say("WHOIS NickServ")
        assert any(" 311 al1 NickServ NickServ " in l and "Nickname Services" in l for l in r), r
        assert any(" 313 al1 NickServ " in l for l in r) and any(" 318 " in l for l in r), r
        c.drain()
        c.send("NS INFO")
        assert c.saw(r"NickServ.*not identified", 1)
        c.send("NICKSERV HELP")
        assert c.saw(r"NickServ.*REGAIN", 1)
    with Server() as s:
        c = s.client("al2")
        assert any(" 401 " in l for l in c.say("WHOIS NickServ")), "no virtual NickServ without accounts"
