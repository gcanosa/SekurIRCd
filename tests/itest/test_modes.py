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
