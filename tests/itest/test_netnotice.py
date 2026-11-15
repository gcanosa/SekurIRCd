"""Network-wide oper notices: a rehash anywhere (REHASH, REHASH <server>, REHASH *, SIGHUP) is announced to opers on
every server, and the periodic stats line reaches every server's debug channel."""
import signal
import time
from harness import Network

CFG = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]},
                     {"name": "jr", "password": "jrpw", "hosts": ["*@*"], "privileges": ["kill"]}]}


def pair(cfg=None):
    n = Network(cfg=dict(CFG, **(cfg or {})))
    n.add("a")
    n.add("b", parent="a")
    return n


def oper(n, srv, nick, name="boss", pw="bosspw"):
    c = n.client(srv, nick)
    c.say(f"OPER {name} {pw}", 0.8)
    c.drain()
    return c


def test_rehash_is_announced_network_wide():
    with pair() as n:
        oa, ob = oper(n, "a", "opa"), oper(n, "b", "opb")
        local = ob.say("REHASH", 0.8)
        assert oa.saw(r"\*\*\* Notice -- \[b\.test\.net\] opb is rehashing server config file", 2)
        assert oa.saw(r"\[b\.test\.net\] Rehash done:", 1)
        assert any("Notice -- opb is rehashing" in l for l in local), local  # its own server: no [server] prefix


def test_remote_and_all_rehash():
    with pair() as n:
        oa, ob = oper(n, "a", "opa"), oper(n, "b", "opb")
        r = oa.say("REHASH b.test.net", 1.5)
        assert any("Rehash request sent to b.test.net" in l for l in r), r
        assert any(l.startswith(":b.test.net 382 opa ") for l in r), r          # b answers over the link
        assert any("*** Rehash b.test.net: " in l for l in r), r
        assert ob.saw(r"Notice -- opa on a\.test\.net is rehashing server config file", 1)
        oa.drain(); ob.drain()
        r = oa.say("REHASH *", 1.5)
        assert any(l.startswith(":a.test.net 382 ") for l in r) and any(l.startswith(":b.test.net 382 ") for l in r), r
        assert any(" 402 " in l for l in oa.say("REHASH nowhere.test.net", 0.4))
        jr = oper(n, "a", "junior", "jr", "jrpw")
        assert any(" 481 " in l for l in jr.say("REHASH b.test.net", 0.6)), "no rehash privilege, no remote rehash"
        plain = n.client("a", "plain")
        assert any(" 481 " in l for l in plain.say("REHASH b.test.net", 0.4))
        assert not ob.saw(r"(junior|plain) .*is rehashing", 0.8)


def test_sighup_is_announced_and_stats_reach_every_debug_channel():
    dbg = {"debug_channel": {"enabled": True, "name": "#dbg", "min_level": "INFO", "stats_interval": 1}}
    with pair(dbg) as n:
        oa = oper(n, "a", "opa")
        oa.say("JOIN #dbg", 0.4)
        n["b"].proc.send_signal(signal.SIGHUP)
        assert oa.saw(r"\[b\.test\.net\] The server \(SIGHUP\) is rehashing server config file", 3)
        oa.drain()
        time.sleep(2.5)
        lines = oa.drain(0.5)
        assert any("NOTICE #dbg" in l and "[b.test.net] users " in l and " local, " in l for l in lines), lines
        assert any("NOTICE #dbg" in l and "users " in l and "[b.test.net]" not in l for l in lines), lines  # its own too
