import time
from harness import Server
from test_accounts import register
from test_accounts2 import ns, ACC


def raw_after(c, line, wait=2.5):
    """Send `line` and return every line the client gets back (ns() would throw away the channel traffic)."""
    c.drain(0.05)
    c.send(line)
    time.sleep(wait)
    return c.drain(0.5)


def test_set_ajoin_validation_and_login_join():
    with Server(cfg=ACC) as s:
        o = s.client("ajstranger")
        assert any("IDENTIFY first" in l for l in ns(o, "SET AJOIN #ajone")), "needs an identified account"
        c = register(s, "ajown", "ajowner", "password1")
        assert any("Not a valid channel name" in l for l in ns(c, "SET AJOIN notachannel")), "channel names are checked"
        assert any("At most 10" in l for l in ns(c, "SET AJOIN " + ",".join(f"#aj{i}" for i in range(11)))), "at most 10"
        # the owner makes #ajlocked invite-only, so a login that lists it must be refused there
        c.send("JOIN #ajlocked")
        c.send("MODE #ajlocked +i")
        c.drain(0.3)
        assert any("Auto-join set to #ajone,#ajlocked" in l for l in ns(c, "SET AJOIN #ajone,#ajlocked")), "accepted list"
        assert any("Auto-join: #ajone,#ajlocked" in l for l in ns(c, "INFO")), "INFO shows the owner their list"

        v = s.client("ajvisitor")
        got = raw_after(v, "PRIVMSG NickServ :IDENTIFY ajowner password1")
        assert any("You are now identified" in l for l in got), got
        assert any(" JOIN #ajone" in l for l in got), "joined #ajone at login"
        refused = [l for l in got if " 473 " in l and "#ajlocked" in l]
        assert len(refused) == 1, "+i refusal is announced like a typed JOIN, once, and never bypassed: %r" % refused
        assert not any(" JOIN #ajlocked" in l for l in got), "never joined the +i channel"

        assert any("Auto-join cleared" in l for l in ns(c, "SET AJOIN OFF"))
        w = s.client("ajlater")
        got = raw_after(w, "PRIVMSG NickServ :IDENTIFY ajowner password1")
        assert any("You are now identified" in l for l in got), got
        assert not any(" JOIN #ajone" in l for l in got), "OFF stops the auto-join"


def test_ajoin_applies_to_a_user_on_another_server():
    from harness import Network
    from test_netsync import OPERS
    n = Network(cfg={**OPERS, "accounts": {"enabled": True, "store_file": "acc.json"}})  # services link to a
    n.add("a")
    n.add("b", parent="a")
    n.start()
    try:
        owner = n.client("a", "ajnetacct")  # REGISTER names the account after the nick
        assert any("registered" in l for l in ns(owner, "REGISTER netpass1")), "registered"
        assert any("Auto-join set to #ajnet" in l for l in ns(owner, "SET AJOIN #ajnet")), "set"
        far = n.client("b", "ajnetfar")
        got = raw_after(far, "PRIVMSG NickServ :IDENTIFY ajnetacct netpass1", 3.0)
        assert any("You are now identified" in l for l in got), got
        assert any(" JOIN #ajnet" in l for l in got), "the leaf server's user joined the AJOIN channel"
        near = n.client("a", "ajnetnear")
        names = " ".join(l for l in near.say("NAMES #ajnet", 0.8) if " 353 " in l)
        assert "ajnetfar" in names, "the join reached the rest of the network: %r" % names
    finally:
        n.stop()


def test_ajoin_after_sasl_login():
    """SASL logs in before registration, so no SVCACCOUNT follows -- the SVCUSER path has to send the AJOIN."""
    import base64
    with Server(cfg=ACC) as s:
        c = register(s, "ajsasl", "ajsaslacct", "password1")
        assert any("Auto-join set to #ajsasl" in l for l in ns(c, "SET AJOIN #ajsasl")), "set"
        p = s.client("ajsaslnew", register=False, extra=["CAP REQ :sasl", "NICK ajsaslnew", "USER u 0 * :u"])
        p.send("AUTHENTICATE PLAIN")
        p.expect(r"AUTHENTICATE \+")
        p.send("AUTHENTICATE " + base64.b64encode(b"\0ajsaslacct\0password1").decode())
        assert p.saw(r" 903 ", 3)
        got = raw_after(p, "CAP END", 3.0)
        assert any(" JOIN #ajsasl" in l for l in got), "SASL login joined the AJOIN channel: %r" % got
