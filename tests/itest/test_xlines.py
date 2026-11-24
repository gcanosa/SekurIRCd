"""Q-lines, RESVs and X-lines: refuse nicks, channel names and realnames by glob; network-wide, kept across restarts, and
a leaf the hub limits to itself keeps its own to itself."""
import os, time
from harness import Server, Client

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "xlinepw"


def oper(srv, nick):
    c = Client(srv.port, nick)
    c.send("OPER boss bosspw")
    c.expect(r" 381 ")
    return c


def pair(**peer_keys):
    hub = Server("hub.test.net", cfg=dict(OPERS), sid="1HB")
    leaf = Server("leaf.test.net", cfg=dict(OPERS), sid="2LF")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [dict({"name": leaf.name, "password": PW, "allowed_ips": ["127.0.0.1"]}, **peer_keys)]
    leaf.cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    leaf.cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    hub.auto_services = leaf.auto_services = False
    return hub, leaf


def test_a_qline_refuses_matching_nicks_but_not_existing_users_or_opers():
    with Server(cfg=OPERS) as s:
        old = s.client("evilold")
        o = oper(s, "boss")
        assert any("Q-line added" in l for l in o.say("QLINE evil* 1h trolls", 0.4))
        c = Client(s.port, "x1", register=False)
        c.send("NICK evilbob"); c.send("USER x 0 * :x")
        assert c.saw(r" 437 .*evilbob.*trolls", 1.0), c.lines
        assert old.say("PING a", 0.3), "the user who already had it is left alone"
        assert any("evil*" in l and "trolls" in l for l in o.say("QLINE", 0.4)), "listed"
        o.say("NICK evilboss", 0.4)  # an oper is exempt
        assert not any(" 437 " in l for l in o.lines[-3:])
        assert any("Removed" in l for l in o.say("UNQLINE evil*", 0.4))
        d = s.client("evilbob")
        assert d.nick == "evilbob"


def test_a_resv_refuses_joins_to_matching_channels():
    with Server(cfg=OPERS) as s:
        o = oper(s, "boss")
        o.say("RESV #warez* 1h pirates", 0.4)
        c = s.client("c")
        assert any(" 437 " in l and "pirates" in l for l in c.say("JOIN #warez-2024", 0.4))
        assert any(" 366 " in l for l in c.say("JOIN #fine", 0.4))
        assert any(" 366 " in l for l in o.say("JOIN #warez-ok", 0.4)), "opers have override"
        assert any("Removed" in l for l in o.say("UNRESV #warez*", 0.4))
        assert any(" 366 " in l for l in c.say("JOIN #warez-2024", 0.4))


def test_an_xline_refuses_matching_realnames_and_underscore_is_a_space():
    with Server(cfg=OPERS) as s:
        o = oper(s, "boss")
        o.say("XLINE buy_cheap_* 1h spambot", 0.4)
        c = Client(s.port, "x1", register=False)
        c.send("NICK x1"); c.send("USER x 0 * :Buy cheap pills now")
        assert c.saw(r"X-Lined: spambot", 1.5), c.lines
        ok = Client(s.port, "x2", realname="Buy a cheap pen")
        assert ok.nick == "x2"
        assert any("matches everything" in l for l in o.say("XLINE *", 0.3))


def test_everything_travels_to_linked_servers_and_comes_back_in_a_burst():
    hub, leaf = pair()
    hub.start()
    try:
        h = oper(hub, "hboss")
        h.say("QLINE bad* 1h x", 0.3); h.say("RESV #nope* 1h x", 0.3); h.say("XLINE spam_* 1h x", 0.3)
        leaf.start()
        time.sleep(1.6)  # linked: the burst carried all three
        lop = oper(leaf, "lboss")
        c = Client(leaf.port, "q1", register=False)
        c.send("NICK badguy"); c.send("USER q 0 * :q")
        assert c.saw(r" 437 ", 1.0), "burst Q-line enforced on the leaf"
        u = leaf.client("u")
        assert any(" 437 " in l for l in u.say("JOIN #nope1", 0.4))
        # a new one set on the leaf reaches the hub; lifting it on the hub lifts it on the leaf
        lop.say("QLINE worse* 1h y", 0.4)
        time.sleep(0.5)
        hc = Client(hub.port, "w1", register=False)
        hc.send("NICK worse1"); hc.send("USER w 0 * :w")
        assert hc.saw(r" 437 ", 1.0), "set on the leaf, enforced on the hub"
        h.say("UNQLINE worse*", 0.4)
        time.sleep(0.5)
        lc = Client(leaf.port, "w2", register=False)
        lc.send("NICK worse2"); lc.send("USER w 0 * :w")
        assert lc.saw(r" 001 ", 1.5), "lifted on the hub, lifted on the leaf"
    finally:
        hub.stop(); leaf.stop()


def test_a_leaf_the_hub_limits_to_itself_keeps_its_lines_local():
    hub, leaf = pair(oper_scope="local")
    hub.start(); leaf.start()
    try:
        time.sleep(1.6)
        lop = oper(leaf, "lboss")
        assert any("this server only" in l for l in lop.say("QLINE local* 1h x", 0.5))
        time.sleep(0.5)
        hc = Client(hub.port, "l1", register=False)
        hc.send("NICK localhost1"); hc.send("USER l 0 * :l")
        assert hc.saw(r" 001 ", 1.5), "the hub never heard of it"
        lc = Client(leaf.port, "l2", register=False)
        lc.send("NICK localhost2"); lc.send("USER l 0 * :l")
        assert lc.saw(r" 437 ", 1.0), "but the leaf enforces it"
    finally:
        hub.stop(); leaf.stop()


def test_lines_survive_a_restart_when_klines_are_kept():
    cfg = dict(OPERS, security={"klines_file": "klines.json"})
    s = Server(cfg=cfg)
    s.start()
    try:
        o = oper(s, "boss")
        o.say("QLINE keep* 1d x", 0.4)
        o.say("XLINE keep_me 1d x", 0.4)
        time.sleep(1.2)  # the batched flush
        s.restart()
        o = oper(s, "boss2")
        out = " ".join(o.say("QLINE", 0.5))
        assert "keep*" in out, out
        assert "keep_me" in " ".join(o.say("XLINE", 0.5))
        assert os.path.exists(os.path.join(s.dir, "xlines.json"))
    finally:
        s.stop()
