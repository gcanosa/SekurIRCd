"""Account vhosts: an oper (on any server) gives an account hosts to choose from, services keep them, the person wears one
(applied again at every login, shown network-wide); and the per-server [[vhosts]] blocks that also take accounts and a password."""
import base64, os, sys, time
from harness import Network, Server

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
from linkmgmt import scrypt_hash  # the format `sekurircd --hash-password` writes
from test_accounts import register
from test_accounts2 import ns

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]},
                       {"name": "lowly", "password": "lowpw", "hosts": ["*@*"], "privileges": ["kill"]}]}
ACC = {"accounts": {"enabled": True, "store_file": "acc.json"}}


def host_of(observer, nick):
    """The host `observer` sees for `nick` (WHOIS 311: <me> <nick> <user> <host> * :<real>)."""
    for l in observer.say(f"WHOIS {nick}", 0.6):
        if " 311 " in l:
            return l.split()[5]
    return None


def oper(c, name="boss", pw="bosspw"):
    c.say(f"OPER {name} {pw}", 0.6)
    return c


def said(lines, text):
    return any(text in l for l in lines)


def sasl_login(s, nick, account, pw):
    c = s.client(nick, register=False, extra=["CAP REQ :sasl"])
    c.send("AUTHENTICATE PLAIN")
    c.expect(r"AUTHENTICATE \+")
    c.send("AUTHENTICATE " + base64.b64encode(f"\0{account}\0{pw}".encode()).decode())
    c.expect(r" 903 ", 3)
    c.send("CAP END")
    c.send(f"NICK {nick}")
    c.send(f"USER {nick} 0 * :t")
    c.expect(r" 001 ", 5)
    return c


def test_an_account_chooses_among_its_vhosts_and_keeps_it_at_login():
    s = Server(cfg=dict(OPERS, **ACC))
    with s:
        a = register(s, "alice", "alice", "password1")
        watch = s.client("watch")
        boss = oper(s.client("boss"))
        assert said(boss.say("VHOST ADD alice a.example.org", 1.0), "granted vhost a.example.org")
        assert said(boss.say("VHOST ADD alice b.example.org", 1.0), "granted vhost b.example.org")
        assert said(boss.say("VHOST ADD alice a.example.org", 1.0), "already has"), "no duplicates"
        assert said(boss.say("VHOST LIST alice", 1.0), "a.example.org, b.example.org")
        # she sees both through /VHOST, and wears one
        assert said(a.say("VHOST", 1.0), "a.example.org, b.example.org")
        assert said(a.say("VHOST c.example.org", 1.0), "no vhost c.example.org"), "not one she was given"
        a.say("VHOST b.example.org", 1.0)
        assert host_of(watch, "alice") == "b.example.org", "everyone sees it"
        assert said(a.say("VHOST", 1.0), "b.example.org [in use]")
        # logging out takes it off, logging in puts it back
        ns(a, "LOGOUT", 1.0)
        assert host_of(watch, "alice") != "b.example.org"
        ns(a, "IDENTIFY alice password1", 1.0)
        assert host_of(watch, "alice") == "b.example.org", "IDENTIFY applies the chosen vhost"
        # a new connection logging in by SASL gets it before anyone sees the user
        a2 = sasl_login(s, "alice2", "alice", "password1")
        time.sleep(0.6)  # services see the new user and answer with SVSHOST
        assert a2 and host_of(watch, "alice2") == "b.example.org", "SASL login applies it"
        # OFF forgets it, on every connection of the account
        a.say("VHOST OFF", 1.0)
        assert host_of(watch, "alice") != "b.example.org" and host_of(watch, "alice2") != "b.example.org"
        ns(a, "LOGOUT", 1.0); ns(a, "IDENTIFY alice password1", 1.0)
        assert host_of(watch, "alice") != "b.example.org", "nothing is applied after OFF"
        # taking away the one being worn takes it off at once
        a.say("VHOST a.example.org", 1.0)
        assert host_of(watch, "alice") == "a.example.org"
        assert said(boss.say("VHOST DEL alice a.example.org", 1.0), "removed vhost a.example.org")
        assert host_of(watch, "alice") != "a.example.org"
        assert said(a.say("VHOST", 1.0), "b.example.org") and not said(a.say("VHOST", 1.0), "a.example.org")


def test_only_opers_with_the_host_privilege_or_services_admins_edit_grants():
    s = Server(cfg=dict(OPERS, accounts=dict(ACC["accounts"], admins=["staffer"])))
    with s:
        a = register(s, "alice", "alice", "password1")
        plain = s.client("plain")
        assert not said(plain.say("VHOST ADD alice x.example.org", 1.0), "granted"), "a user's VHOST ADD is only a vhost name"
        assert said(ns(plain, "VHOST ADD alice x.example.org", 1.0), "Permission denied")
        low = oper(s.client("low"), "lowly", "lowpw")
        assert any(" 481 " in l for l in low.say("VHOST ADD alice x.example.org", 1.0)), "an oper without the host privilege"
        assert not said(a.say("VHOST", 1.0), "x.example.org")
        # a services admin may do it from NickServ itself
        st = register(s, "staffer", "staffer", "password1")
        assert said(ns(st, "VHOST ADD alice y.example.org", 1.0), "granted vhost y.example.org")
        assert said(a.say("VHOST", 1.0), "y.example.org")
        assert said(ns(st, "VHOST DEL alice y.example.org", 1.0), "removed")


def test_config_vhosts_take_accounts_and_an_optional_password():
    cfg = dict(OPERS, **ACC)
    cfg["vhosts"] = [{"host": "acct.example.org", "accounts": ["alice"]},
                     {"host": "pw.example.org", "password": "sesame"},
                     {"host": "both.example.org", "accounts": ["alice"], "password": "pw2"}]
    s = Server(cfg=cfg)
    with s:
        a = register(s, "alice", "alice", "password1")
        b = s.client("bobby")  # not logged in
        watch = s.client("watch")
        # alice sees the ones that name her (the password-only one stays hidden), flagged when they need a password
        out = " ".join(a.say("VHOST", 1.0))
        assert "acct.example.org" in out and "both.example.org (password)" in out and "pw.example.org" not in out, out
        assert not any("acct.example.org" in l for l in b.say("VHOST", 0.8)), "a stranger is not listed it"
        assert said(b.say("VHOST acct.example.org", 0.8), "not permitted"), "an account vhost is not for others"
        a.say("VHOST acct.example.org", 0.8)
        assert host_of(watch, "alice") == "acct.example.org", "no password asked of an account that is named"
        # a password with an account list: both are needed
        assert said(a.say("VHOST both.example.org", 0.8), "needs its password")
        assert said(a.say("VHOST both.example.org nope", 0.8), "Wrong password")
        a.say("VHOST both.example.org pw2", 0.8)
        assert host_of(watch, "alice") == "both.example.org"
        assert said(b.say("VHOST both.example.org pw2", 0.8), "not permitted"), "the password alone is not enough here"
        # a password and nobody named: anyone who knows it
        assert said(b.say("VHOST pw.example.org", 0.8), "needs its password")
        assert said(b.say("VHOST pw.example.org wrong", 0.8), "Wrong password")
        b.say("VHOST pw.example.org sesame", 0.8)
        assert host_of(watch, "bobby") == "pw.example.org"
        # guessing is limited like logins: after a few wrong tries from one address, even the right one waits
        c = s.client("guesser")
        outs = [" ".join(c.say("VHOST pw.example.org guess%d" % i, 0.4)) for i in range(7)]
        assert "Too many failed attempts" in outs[-1] and "Too many failed attempts" in " ".join(c.say("VHOST pw.example.org sesame", 0.4))
        # opers need no password and see everything
        boss = oper(s.client("boss"))
        assert "pw.example.org" in " ".join(boss.say("VHOST", 0.8))


def test_an_oper_on_a_leaf_gives_vhosts_the_whole_network_sees():
    n = Network(cfg=dict(OPERS, **ACC))  # one services daemon, on the hub
    n.add("hub")
    n.add("leaf", parent="hub")
    n.start()
    try:
        alice = n.client("hub", "alice")
        alice.say("REGISTER alice password1", 1.5)
        bob = n.client("leaf", "bob")
        bob.say("REGISTER bob password1", 1.5)
        boss = oper(n.client("leaf", "boss"))
        assert said(boss.say("VHOST ADD alice net.example.org", 1.5), "granted vhost net.example.org"), "an oper on the leaf edits the network's list"
        assert said(boss.say("VHOST ADD bob lf.example.org", 1.5), "granted vhost lf.example.org")
        alice.say("VHOST net.example.org", 1.5)
        bob.say("VHOST lf.example.org", 1.5)
        on_leaf, on_hub = n.client("leaf", "seeleaf"), n.client("hub", "seehub")
        assert host_of(on_leaf, "alice") == "net.example.org", "a user on the hub, seen from the leaf"
        assert host_of(on_hub, "bob") == "lf.example.org", "a user on the leaf, seen from the hub"
        assert host_of(on_hub, "alice") == "net.example.org"
        # a server that links later learns it in the burst, and a plain user's own /VHOST works from either side
        assert said(alice.say("VHOST", 1.0), "net.example.org [in use]")
        # DEL from the hub takes it off a user on the leaf
        hboss = oper(n.client("hub", "hboss"))
        assert said(hboss.say("VHOST DEL bob lf.example.org", 1.5), "removed vhost lf.example.org")
        assert host_of(on_leaf, "bob") != "lf.example.org"
    finally:
        n.stop()


def test_a_hub_can_keep_a_leafs_opers_from_editing_the_network_list():
    n = Network(cfg=dict(OPERS, **ACC))
    n.add("hub")
    n.add("leaf", parent="hub")
    n["hub"].cfg["links.peers"][0]["oper_scope"] = "local"  # the hub's entry for the leaf
    n.start()
    try:
        alice = n.client("hub", "alice")
        alice.say("REGISTER alice password1", 1.5)
        lop = oper(n.client("leaf", "lop"))
        assert said(lop.say("VHOST ADD alice no.example.org", 1.0), "oper_scope = local")
        assert not said(alice.say("VHOST", 1.0), "no.example.org")
        hop = oper(n.client("hub", "hop"))
        assert said(hop.say("VHOST ADD alice yes.example.org", 1.0), "granted"), "the hub's own opers are not limited"
        assert said(lop.say("VHOST LIST alice", 1.0), "oper_scope = local"), "even reading it reaches past their server"
    finally:
        n.stop()


def test_a_vhost_password_can_be_a_scrypt_hash_and_the_config_refuses_both():
    cfg = dict(OPERS)
    cfg["vhosts"] = [{"host": "hashed.example.org", "password_hash": scrypt_hash("sesame")}]
    s = Server(cfg=cfg)
    with s:
        b = s.client("bobby")
        watch = s.client("watch")
        assert said(b.say("VHOST hashed.example.org", 0.8), "needs its password")
        assert said(b.say("VHOST hashed.example.org wrong", 1.0), "Wrong password"), "checked on a worker, answered later"
        assert host_of(watch, "bobby") != "hashed.example.org"
        b.say("VHOST hashed.example.org sesame", 1.0)
        assert host_of(watch, "bobby") == "hashed.example.org"
        c = s.client("guesser")  # the same per-address limit as the plain password
        outs = [" ".join(c.say("VHOST hashed.example.org guess%d" % i, 0.5)) for i in range(8)]
        assert "Too many failed attempts" in outs[-1], outs
    both = Server(cfg=dict(OPERS, vhosts=[{"host": "x.example.org", "password": "a", "password_hash": scrypt_hash("a")}]))
    try:
        both.start()
    except RuntimeError as e:
        assert "not both" in str(e), e  # the config is refused with the reason, like an operator with both keys
    else:
        both.stop()
        raise AssertionError("a vhost with password and password_hash was accepted")
