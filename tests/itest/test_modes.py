import time
from harness import Server

OPER = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def oper(s, nick):
    c = s.client(nick)
    c.say("OPER boss bosspw", 0.8)
    return c


def test_flood_mode_kicks_flooder():
    with Server() as s:
        op, u = s.client("op"), s.client("u1")
        op.say("JOIN #f")
        op.say("MODE #f +f 3:5")
        u.say("JOIN #f")
        for i in range(5):
            u.send(f"PRIVMSG #f :spam {i}")
        assert u.saw(r"KICK #f u1 :Channel flood", 1.0)


def test_flood_mode_ignores_typing_tagmsg():
    with Server() as s:
        op, u = s.client("op"), s.client("u1", caps=["message-tags"])
        op.say("JOIN #f")
        op.say("MODE #f +f 3:5")
        u.say("JOIN #f")
        for i in range(8):  # a web client repeats +typing while you type; that is not channel flood
            u.send("@+typing=active TAGMSG #f")
        assert not u.saw(r"KICK #f u1", 0.8)
        u.send("PRIVMSG #f :still here")
        assert not u.saw(r"KICK #f u1", 0.5)


def test_join_throttle():
    with Server() as s:
        op = s.client("op")
        op.say("JOIN #j")
        op.say("MODE #j +j 2:10")
        a, b, c = s.client("a1"), s.client("b1"), s.client("c1")
        a.say("JOIN #j")
        b.say("JOIN #j")
        r = c.say("JOIN #j")  # third join inside the window
        assert any(" 471 " in l and "+j" in l for l in r), r


def test_plus_P_is_oper_only():
    with Server(cfg=OPER) as s:
        u = s.client("user")
        u.say("JOIN #p")
        r = u.say("MODE #p +P")
        assert any(" 482 " in l and "operators only" in l for l in r), r
        o = oper(s, "boss")
        o.say("JOIN #p2")
        r = o.say("MODE #p2 +P")
        assert any("MODE #p2 +P" in l for l in r), r


def test_extbans_realname_and_secure():
    with Server() as s:
        op = s.client("op")
        v = s.client("vic", realname="very vic name")
        op.say("JOIN #e")
        op.say("MODE #e +b ~r:*vic*")
        assert any(" 474 " in l for l in v.say("JOIN #e")), "~r should block"
        op.say("MODE #e -b ~r:*vic*")
        assert any("JOIN" in l for l in v.say("JOIN #e")), "unbanned"


def test_owner_admin_ranks_and_protection():
    with Server(cfg=OPER) as s:
        boss = oper(s, "boss")
        a, b = s.client("opa"), s.client("opb", caps=["multi-prefix"])
        a.say("JOIN #r")
        b.say("JOIN #r")
        a.say("MODE #r +o opb")
        assert any(" 482 " in l for l in a.say("MODE #r +q opa")), "an op may not grant +q"
        boss.say("SAMODE #r +q opa")
        names = " ".join(b.say("NAMES #r"))
        assert "~@opa" in names and "@opb" in names, names
        assert any(" 482 " in l for l in b.say("KICK #r opa :x")), "junior op can't kick the owner"
        assert any(" 482 " in l for l in b.say("MODE #r -o opa")), "junior op can't deop the owner"
        a.say("MODE #r +a opb")
        assert "&@opb" in " ".join(b.say("NAMES #r"))


def test_caller_id_binds_to_connection():
    with Server() as s:
        ana, bob = s.client("ana"), s.client("bob")
        ana.say("MODE ana +g")
        r = bob.say("PRIVMSG ana :hello?")
        assert any(" 716 " in l for l in r), r
        ana.say("ACCEPT bob")
        bob.say("NICK bob2")
        r = bob.say("PRIVMSG ana :now?")
        assert not any(" 716 " in l for l in r) and ana.saw(r"now\?"), r
        impostor = s.client("bob")
        r = impostor.say("PRIVMSG ana :me?")
        assert any(" 716 " in l for l in r), r


def test_halfop_cannot_kick_op():
    with Server() as s:
        a, b, c = s.client("a1"), s.client("b1"), s.client("c1")
        a.say("JOIN #h")
        b.say("JOIN #h")
        c.say("JOIN #h")
        a.say("MODE #h +h b1")
        assert any(" 482 " in l for l in b.say("KICK #h a1 :no")), "halfop must not kick an op"


SPAM = dict(OPER, spam={"enabled": True, "filters_enabled": True})


def test_spamfilter_hide_drops_silently_but_echoes():
    with Server(cfg=SPAM) as s:
        o = oper(s, "boss")
        o.say("SPAMFILTER ADD c hide - ad buyspam", 0.5)
        rx, u = s.client("rx"), s.client("u1", caps=["echo-message"])
        rx.say("JOIN #h")
        u.say("JOIN #h")
        r = u.say("PRIVMSG #h :hey buyspam now")
        assert any("PRIVMSG #h :hey buyspam now" in l for l in r), r  # echoed: looks sent
        assert not any("blocked" in l for l in r), r                   # no notice to the sender
        assert not rx.saw(r"buyspam", 0.5)                             # nobody got it
        assert o.saw(r"Spam: u1!.* hide \(ad\)", 0.5)                  # opers still see it
        u.send("PRIVMSG #h :clean line")
        assert rx.saw(r"PRIVMSG #h :clean line", 1.0)                  # hide does not stick


def test_spamfilter_shun_sticks():
    with Server(cfg=SPAM) as s:
        o = oper(s, "boss")
        o.say("SPAMFILTER ADD c shun 10m ad buyspam", 0.5)
        rx, u = s.client("rx"), s.client("u1")
        rx.say("JOIN #h")
        u.say("JOIN #h")
        u.send("PRIVMSG #h :buyspam")
        assert not rx.saw(r"buyspam", 0.5)
        u.send("PRIVMSG #h :clean line")
        assert not rx.saw(r"clean line", 0.5)  # shunned: later messages vanish too
        assert u.say("PING :x") and not u.saw(r"ERROR", 0.2)  # still connected
