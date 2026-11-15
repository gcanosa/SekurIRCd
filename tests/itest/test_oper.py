import re
from harness import Server

CFG = {"operators": [
    {"name": "boss", "password": "bosspw", "hosts": ["*@*"]},
    {"name": "junior", "password": "juniorpw", "hosts": ["*@*"], "privileges": ["kline"]},
]}


def oper(s, nick, name="boss", pw="bosspw"):
    c = s.client(nick)
    c.say(f"OPER {name} {pw}", 0.8)
    return c


def test_privilege_classes():
    with Server(cfg=CFG) as s:
        jr = oper(s, "jr", "junior", "juniorpw")
        s.client("target")
        assert any(" 481 " in l for l in jr.say("KILL target :x")), "junior lacks kill"
        assert any("S-line added" in l for l in jr.say("SHUN *@127.0.0.1 10m test")), "junior has kline class"
        jr.say("UNSHUN *@127.0.0.1")


def test_shun_drops_messages_but_keeps_connection():
    with Server(cfg=CFG) as s:
        boss = oper(s, "boss")
        vic = s.client("vic")
        boss.say("SHUN vic!*@* 10m x")  # no-op mask style: use host mask instead
        boss.say("UNSHUN vic!*@*")
        boss.say("SHUN *@127.0.0.1 10m test")
        vic.say("PRIVMSG boss :muted?")
        assert not boss.saw(r"muted\?", 0.5)
        assert any("PONG" in l for l in vic.say("PING z"))
        boss.say("UNSHUN *@127.0.0.1")
        vic.say("PRIVMSG boss :heard")
        assert boss.saw(r"heard")


def test_eline_protects_from_kline():
    with Server(cfg=CFG) as s:
        boss = oper(s, "boss")
        vic = s.client("vic")
        boss.say("ELINE *@127.0.0.1")
        boss.say("KLINE *@127.0.0.1 1h nope")
        assert any("PONG" in l for l in vic.say("PING z")), "ELINE keeps the connected user"
        boss.say("UNELINE *@127.0.0.1")
        boss.say("UNKLINE *@127.0.0.1")


def test_sanick_chgident_globops():
    with Server(cfg=CFG) as s:
        boss = oper(s, "boss")
        t = s.client("tgt")
        boss.say("SANICK tgt newname")
        assert t.saw(r":tgt!.* NICK :newname")
        boss.say("CHGIDENT newname fresh")
        r = boss.say("WHOIS newname")
        assert any(re.search(r" 311 boss newname fresh \S+ \* :", l) for l in r), r  # RFC 2812: "*" before realname
        boss.send("GLOBOPS :hello opers")
        assert boss.saw(r"GLOBOPS :hello opers")


def test_oper_demotion_drops_oper_only_modes():
    with Server(cfg=CFG) as s:
        boss = oper(s, "boss")
        boss.say("MODE boss +q")
        r = boss.say("MODE boss -o")
        assert any("MODE boss :-o" in l or "-o" in l for l in r), r
        assert "q" not in " ".join(boss.say("MODE boss")).split(" 221 boss ")[-1]


def test_oper_modes_default_and_per_login():
    cfg = {"security": {"oper_modes": "+oswI"}, "operators": [
        {"name": "boss", "password": "bosspw", "hosts": ["*@*"], "modes": "+osW"},
        {"name": "junior", "password": "juniorpw", "hosts": ["*@*"]},
    ]}
    with Server(cfg=cfg) as s:
        boss = oper(s, "boss")
        umodes = boss.say("MODE boss")[-1].split()[-1]
        assert "W" in umodes and "I" not in umodes, umodes  # the login's own modes replace the default
        jr = oper(s, "jr", "junior", "juniorpw")
        umodes = jr.say("MODE jr")[-1].split()[-1]
        assert "I" in umodes and "o" in umodes and "W" not in umodes, umodes


def test_override_auspex_immune_privileges():
    cfg = {"operators": CFG["operators"] + [{"name": "old", "password": "oldpw", "hosts": ["*@*"], "privileges": ["accounts"]}]}
    with Server(cfg=cfg) as s:
        boss, jr = oper(s, "boss"), oper(s, "jr", "junior", "juniorpw")
        owner = s.client("owner")
        owner.say("JOIN #locked", 0.3)
        owner.say("MODE #locked +i", 0.3)
        assert any(" 473 jr #locked " in l for l in jr.say("JOIN #locked", 0.4)), "no override: +i holds"
        assert any(" JOIN " in l and "#locked" in l for l in boss.say("JOIN #locked", 0.4)), "override joins through +i"
        owner.say("MODE #locked -i+O", 0.3)
        assert any(" JOIN " in l and "#locked" in l for l in jr.say("JOIN #locked", 0.4)), "+O only needs +o"
        assert any(" 482 " in l for l in jr.say("KICK #locked owner :x", 0.4)), "no override: no kick without ops"
        assert any(" 354 boss 127.0.0.1" in l for l in boss.say("WHO owner %i", 0.4)), "auspex sees the IP"
        assert any(" 354 jr 255.255.255.255" in l for l in jr.say("WHO owner %i", 0.4)), "no auspex: no IP"
        boss.say("SHUN *@127.0.0.1 10m test", 0.3)
        jr.send("PRIVMSG owner :from jr")
        boss.send("PRIVMSG owner :from boss")
        assert owner.saw(r"from boss", 0.6) and not owner.saw(r"from jr", 0.4), "only immune opers skip SHUN"
        boss.say("UNSHUN *@127.0.0.1", 0.3)
        assert any(" 381 " in l for l in s.client("olduser").say("OPER old oldpw", 0.8)), "an old \"accounts\" login still loads and works"
        st = "\n".join(boss.say("STATS o", 0.4))
        assert "junior :kline" in st and "boss :all" in st and "accounts" not in st, st
