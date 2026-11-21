"""A hub with two real leaves (mode "hub" / "leaf", as linkmgmt.py writes them), leaf A limited (oper_scope = local): leaf-to-leaf
state goes through the hub, a split of one leaf leaves the other alone, a relink brings everything back the same on all three, and
opers reach exactly what their scope allows."""
import time
from harness import Server, Client
from test_hubleaf import same, query, num

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "starpw"


def star():
    hub = Server("hub.test.net", cfg=dict(OPERS), sid="1HB")
    a = Server("a.test.net", cfg=dict(OPERS), sid="2AA")
    b = Server("b.test.net", cfg=dict(OPERS), sid="3BB")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [{"name": a.name, "password": PW, "oper_scope": "local"}, {"name": b.name, "password": PW}]
    for leaf in (a, b):
        leaf.cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
        leaf.cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    for s in (hub, a, b):
        s.auto_services = False
        s.start()
    return hub, a, b


def linked(c, want=3, timeout=8):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if len(num(query(c, "LINKS", 365), 364)) == want:
            return
        time.sleep(0.3)
    raise AssertionError(f"LINKS never showed {want} servers")


def oper(port, nick):
    c = Client(port, nick)
    c.send("OPER boss bosspw")
    c.expect(r" 381 ")
    return c


def all_same(obs, chans, nicks):
    s = same(obs[0], obs[1], chans, nicks)
    assert same(obs[0], obs[2], chans, nicks) == s
    return s


def test_two_leaves_through_the_hub():
    hub, a, b = star()
    try:
        oh, oa, ob = Client(hub.port, "obsh"), Client(a.port, "obsa"), Client(b.port, "obsb")
        for o in (oh, oa, ob):
            linked(o)
        ua, ub = Client(a.port, "alice"), Client(b.port, "bob")
        ua.send("JOIN #star"); ua.expect(r" 366 ")
        ub.send("JOIN #star"); ub.expect(r" 366 ")
        ua.send("MODE #star +ntk-o+v sekrit bob bob"); ua.send("TOPIC #star :from a"); ua.send("MODE #star +b *!*@bad.example")
        time.sleep(0.6)
        ub.send("PRIVMSG #star :hi from b")
        assert ua.saw("hi from b", 2), "a leaf-to-leaf message crosses the hub"
        ua.send("PRIVMSG bob :private")
        assert ub.saw("private", 2)
        obs, chans, nicks = (oh, oa, ob), ["#star"], ["alice", "bob"]
        before = all_same(obs, chans, nicks)
        assert before["#star", "topic"] and "from a" in before["#star", "topic"][0]

        # leaf B splits (the hub drops it): A no longer sees bob, the hub's view and A's agree
        hop = oper(hub.port, "hop")
        hop.say("SQUIT b.test.net :maintenance", 0.6)
        assert ua.saw(r"QUIT :hub.test.net b.test.net", 3), "A sees B's users leave in the netsplit"
        assert num(query(oa, "WHOIS bob", 318), 401), "bob is gone from A"
        # B relinks on its own; everything comes back the same on all three
        ob2 = ob
        linked(oa, timeout=10)
        after = all_same(obs, chans, nicks)
        before.pop("users"); after.pop("users")  # our own oper client joined meanwhile
        assert after == before, "a relink restores the same state: " + str({k: (before.get(k), after.get(k)) for k in before if before.get(k) != after.get(k)})
        ub.send("PRIVMSG #star :back from b")
        assert ua.saw("back from b", 2), "B talks to A again after the relink"

        # leaf A's oper is limited to A; leaf B's isn't
        aop, bop = oper(a.port, "aop"), oper(b.port, "bop")
        time.sleep(0.4)
        out = " ".join(aop.say("KILL bob :no", 0.6))
        assert "oper_scope = local" in out, out
        assert any("PONG" in l for l in ub.say("PING :x", 0.4)), "bob survived A's oper"
        aop.say("SQUIT b.test.net :no", 0.5)
        assert len(num(query(oa, "LINKS", 365), 364)) == 3, "A's oper can't squit B"
        bop.say("KILL alice :from b", 0.6)
        assert ua.saw(r"KILL", 2), "B's (global) oper reaches a user on A through the hub"
        # a hub G-line reaches both leaves; A's own can't
        hop.say("GLINE *@203.0.113.9 :hub ban", 0.6)
        for c in (aop, bop):
            assert any("203.0.113.9" in l for l in c.say("STATS g", 0.6)), "the hub's G-line is on both leaves"
        aop.say("GLINE *@198.51.100.7 :a ban", 0.5)
        assert not any("198.51.100.7" in l for l in bop.say("STATS g", 0.6)), "A's G-line never reaches B"
        # B's oper squits A from afar (RSQUIT through the hub), and A comes back
        bop.say("SQUIT a.test.net :far squit", 0.6)
        deadline = time.time() + 3
        while time.time() < deadline and len(num(query(ob2, "LINKS", 365), 364)) == 3:
            time.sleep(0.2)
        linked(ob2, timeout=10)
    finally:
        for s in (b, a, hub):
            s.stop()
