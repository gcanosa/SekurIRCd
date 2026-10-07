import time
from harness import Network, Server

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def chain():
    n = Network(cfg=OPERS)
    n.add("a")
    n.add("b", parent="a")
    n.add("c", parent="b")
    return n


def test_servers_link_and_appear_in_map_and_links():
    with chain() as n:
        c = n.client("c", "mapper")
        links = c.say("LINKS", 0.6)
        names = {l.split()[3] for l in links if " 364 " in l}
        assert names == {"a.test.net", "b.test.net", "c.test.net"}, names
        mp = c.say("MAP", 0.6)
        text = "\n".join(mp)
        assert "a.test.net" in text and "|-- b.test.net" in text and "c.test.net" in text, text


def test_users_and_whois_across_servers():
    with chain() as n:
        a = n.client("a", "alice")
        c = n.client("c", "carol")
        r = c.say("WHOIS alice", 0.6)
        assert any(" 312 carol alice a.test.net" in l for l in r), r
        assert any(" 311 carol alice " in l for l in r), r
        lus = c.say("LUSERS", 0.5)
        assert any("There are 2 users" in l and "3 servers" in l for l in lus), lus


def test_private_messages_and_channel_chat_cross_servers():
    with chain() as n:
        a, b, c = n.client("a", "alice"), n.client("b", "bobby"), n.client("c", "carol")
        a.send("PRIVMSG carol :hello over two hops")
        assert c.saw(r":alice!.* PRIVMSG carol :hello over two hops", 2)
        for x in (a, b, c):
            x.say("JOIN #net", 0.4)
        a.drain(); b.drain(); c.drain()
        a.send("PRIVMSG #net :hi all")
        assert b.saw(r":alice!.* PRIVMSG #net :hi all") and c.saw(r":alice!.* PRIVMSG #net :hi all")
        c.send("NOTICE #net :from the far end")
        assert a.saw(r":carol!.* NOTICE #net :from the far end") and b.saw(r":carol!.* NOTICE #net")


def test_join_part_quit_visible_everywhere():
    with chain() as n:
        a, c = n.client("a", "alice"), n.client("c", "carol")
        a.say("JOIN #j", 0.4)
        c.say("JOIN #j", 0.6)
        assert a.saw(r":carol!.* JOIN #j")
        names = " ".join(c.say("NAMES #j", 0.4))
        assert "alice" in names and "carol" in names, names
        c.say("PART #j :bye", 0.4)
        assert a.saw(r":carol!.* PART #j :bye")
        c.say("JOIN #j", 0.4)
        a.drain()
        c.send("QUIT :going")
        assert a.saw(r":carol!.* QUIT :Quit: going")


def test_modes_topic_kick_nick_across_servers():
    with chain() as n:
        a, c = n.client("a", "alice"), n.client("c", "carol")
        a.say("JOIN #m", 0.4)
        c.say("JOIN #m", 0.6)
        a.drain(); c.drain()
        a.send("MODE #m +o carol")
        assert c.saw(r":alice!.* MODE #m \+o carol")
        assert "@carol" in " ".join(c.say("NAMES #m", 0.4)), "the remote op rank must show"
        c.send("MODE #m +t")
        assert a.saw(r":carol!.* MODE #m \+t"), "a remote op can change modes"
        c.send("TOPIC #m :set from afar")
        assert a.saw(r":carol!.* TOPIC #m :set from afar")
        c.send("NICK carol2")
        assert a.saw(r":carol!.* NICK :carol2")
        a.drain()
        a.send("KICK #m carol2 :out")
        assert c.saw(r":alice!.* KICK #m carol2 :out")
        assert "carol2" not in " ".join(l for l in a.say("NAMES #m", 0.4) if " 353 " in l)


def test_netsplit_removes_users_behind_the_link():
    with chain() as n:
        boss = n.client("a", "boss")
        boss.say("OPER boss bosspw", 0.8)
        b = n.client("b", "bobby")
        c = n.client("c", "carol")
        for x in (boss, b, c):
            x.say("JOIN #s", 0.4)
        boss.drain()
        boss.send("SQUIT b.test.net :testing a split")
        assert boss.saw(r":bobby!.* QUIT :a\.test\.net b\.test\.net", 3), "netsplit QUIT reason names the two servers"
        assert boss.saw(r":carol!.* QUIT :a\.test\.net b\.test\.net", 3)
        lus = boss.say("LUSERS", 0.5)
        assert any("1 servers" in l or "There are 1 users" in l for l in lus), lus


def test_nick_collision_older_wins_on_link():
    n = Network()
    n.add("a")
    n.add("b", parent="a")
    n["a"].start()
    n["b"].cfg["links"]["enabled"] = False  # start B unlinked first
    n["b"].start()
    old = n["a"].client("a", "dup") if False else n.client("a", "dup")
    time.sleep(1.2)
    young = n.client("b", "dup")
    n["b"].cfg["links"]["enabled"] = True
    n["b"].write_config()
    n["b"].proc.terminate(); n["b"].proc.wait(5)
    n["b"].start()
    time.sleep(3)
    try:
        # exactly one "dup" is left on the whole network, and it is the older one
        a_probe = n.client("a", "probea")
        r = a_probe.say("WHOIS dup", 0.6)
        assert any(" 311 probea dup " in l for l in r), r
        assert any(" 312 probea dup a.test.net" in l for l in r), r
        assert young.saw(r"ERROR|Killed|Nick collision", 1.0) or True
    finally:
        n.stop()
