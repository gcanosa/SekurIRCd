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
        assert any(" 311 boss newname fresh " in l for l in r), r
        boss.send("GLOBOPS :hello opers")
        assert boss.saw(r"GLOBOPS :hello opers")


def test_oper_demotion_drops_oper_only_modes():
    with Server(cfg=CFG) as s:
        boss = oper(s, "boss")
        boss.say("MODE boss +q")
        r = boss.say("MODE boss -o")
        assert any("MODE boss :-o" in l or "-o" in l for l in r), r
        assert "q" not in " ".join(boss.say("MODE boss")).split(" 221 boss ")[-1]
