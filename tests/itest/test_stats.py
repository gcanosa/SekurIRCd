import re
from harness import Network, Server

CFG = {
    "operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]},
                  {"name": "junior", "password": "jrpw", "hosts": ["*@127.0.0.1"], "privileges": ["kline"]}],
    "classes": [{"name": "local", "hosts": ["127.0.0.1"], "max_clients": 50}],
    "security": {"reserved_nicks": ["Botty"]},
}


def oper(s, nick):
    c = s.client(nick)
    c.say("OPER boss bosspw", 0.6)
    return c


def stats(c, q, wait=0.4):
    r = c.say("STATS " + q, wait)
    assert any(" 219 " in l for l in r) or any(" 481 " in l or " 402 " in l for l in r), r
    return r


def has(lines, pat):
    return any(re.search(pat, l) for l in lines)


def test_public_letters_and_help():
    with Server(cfg=CFG) as s:
        u = s.client("user")
        u.say("PING x")
        assert has(stats(u, "m"), r" 212 user PING \d+ \d+ \d+$")
        r = stats(u, "u")
        assert has(r, r" 242 user :Server Up") and has(r, r" 250 user :Highest connection count")
        boss = oper(s, "boss")
        assert has(stats(u, "p"), r" 249 user p :\[O\] boss \(") and has(stats(u, "p"), r"1 OPER\(s\)")
        assert has(stats(u, "v"), r" 249 user v :irc\.test\.net \(")
        h = stats(u, "")  # no letter: what you may ask
        assert has(h, r" 210 user \* :mM - command usage") and not has(h, r"K-lines")
        assert has(stats(boss, "!"), r" 210 boss \* :kK - K-lines")
        own = stats(u, "l user")  # your own connection, no oper needed
        assert has(own, r" 211 user user\[~?\w+@127\.0\.0\.1\] \d+ \d+ \d+ \d+ \d+ :\d+ \d+"), own
        assert has(stats(u, "l boss"), r" 481 ")
        for q in "kgzsecihoyPqtZ?bfL":
            assert has(u.say("STATS " + q, 0.3), r" 481 "), q


def test_oper_letters():
    with Server(cfg=CFG) as s:
        boss = oper(s, "boss")
        watcher = oper(s, "watcher")
        boss.say("MODE boss +s", 0.2)
        boss.say("KLINE *@203.0.113.9 1h bad", 0.3)
        boss.say("SHUN *@198.51.100.7 10m quiet", 0.3)
        boss.say("ELINE *@192.0.2.1", 0.3)
        boss.say("ZLINE 203.0.113.0/24 :scanners", 0.3)
        assert has(stats(boss, "k"), r" 216 boss K \*@203\.0\.113\.9 boss \d+m\d+s|216 boss K \*@203\.0\.113\.9 \S+ (59m|1h)")
        assert has(stats(boss, "s"), r" 216 boss S \*@198\.51\.100\.7 ")
        assert has(stats(boss, "E"), r" 216 boss E \*@192\.0\.2\.1 \S+ permanent")
        assert has(stats(boss, "d"), r" 216 boss Z 203\.0\.113\.0/24 ") and has(stats(boss, "z"), r"1 Z-line$")
        assert has(stats(boss, "o"), r" 243 boss O \*@\* \* boss :all") and has(stats(boss, "o"), r" O \*@127\.0\.0\.1 \* junior :kline")
        assert has(stats(boss, "i"), r" 215 boss I 127\.0\.0\.1 \* 127\.0\.0\.1 0 local") and has(stats(boss, "i"), r" I \* \* \* 0 default")
        assert has(stats(boss, "y"), r" 218 boss Y local \d+ 0 50 \d+ [1-9]")
        assert has(stats(boss, "P"), r" 220 boss P %d plain " % s.port)
        assert has(stats(boss, "q"), r" 217 boss Q Botty :Reserved nick")
        t = stats(boss, "t")
        assert has(t, r"connections accepted") and has(t, r"clients: sent \d+ msgs")
        assert has(stats(boss, "Z"), r"process peak RSS \d+ KB")
        assert has(stats(boss, "b"), r"DNSBL (on|off)") and has(stats(boss, "f"), r"filters? loaded")
        assert has(stats(boss, "l"), r" 211 boss Name SendQ SendM SendKB RecvM RecvKB")
        assert has(stats(boss, "l watcher"), r" 211 boss watcher\[")
        assert has(stats(boss, "?"), r"0 links:")
        assert watcher.saw(r"STATS \? requested by boss \(", 0.3) or has(boss.say("PING z"), "PONG")
        assert has(stats(boss, "M watcher"), r" 212 ")  # a target that is a nick on this server: answered here
        assert has(stats(boss, "m nosuch.server"), r" 402 boss nosuch\.server ")


def test_remote_stats_over_a_link():
    n = Network(cfg=CFG)
    n.add("a")
    n.add("b", parent="a")
    with n:
        a = n.client("a", "alice")
        b = n.client("b", "bobop")
        b.say("OPER boss bosspw", 0.6)
        r = stats(a, "u b.test.net", 0.8)
        assert has(r, r":b\.test\.net 242 alice :Server Up"), r
        assert has(stats(a, "k b.test.net", 0.8), r" 481 ")  # the remote server checks the remote user's oper status
        lk = stats(b, "l a.test.net", 0.8)
        assert has(lk, r":a\.test\.net 211 bobop b\.test\.net\[127\.0\.0\.1\] \d+ \d+ \d+ \d+ \d+ :\d+ \d+"), lk
        assert has(stats(b, "? a.test.net", 0.8), r"b\.test\.net: sent \d+ msgs")
        assert has(stats(b, "l alice", 0.8), r":a\.test\.net 211 bobop alice\[")  # a remote nick: its server answers
        assert has(stats(b, "c"), r" 213 bobop C 127\.0\.0\.1 \* a\.test\.net \d+ A?L")
        assert has(stats(b, "h"), r" 244 bobop H \* \* a\.test\.net")
        assert has(stats(b, "v"), r"a\.test\.net \(1AB\) hops 1, uplink b\.test\.net")
