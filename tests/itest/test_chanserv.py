from harness import Server, ChanServ

LINK_PW = "svcsecret"


def net(extra=""):
    s = Server(cfg={"links": {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": 0}})
    s.cfg["links"]["port"] = s.link_port
    s.cfg["links.peers"] = [{"name": "services.test.net", "password": LINK_PW}]
    return s


def test_register_access_levels_and_owner_prefix():
    s = net()
    with s:
        with ChanServ(s, s.link_port, password=LINK_PW):
            f = s.client("fnd")
            f.say("JOIN #rk")
            f.say("PRIVMSG ChanServ :REGISTER #rk pw12345", 1.2)
            f.say("PRIVMSG ChanServ :JOIN #rk pw12345", 1.0)
            r = f.say("PRIVMSG ChanServ :ACCESS #rk ADD *!*@127.0.0.1 q pw12345", 1.0)
            assert any("now has q access" in l for l in r), r
            v = s.client("vip")
            v.say("JOIN #rk", 1.2)
            names = " ".join(f.say("NAMES #rk"))
            assert "~vip" in names, names  # ACCESS q auto-grants owner; the channel creator keeps @
            assert "@fnd" in names, names


def test_admin_owner_commands_and_founder_mode():
    s = net()
    with s:
        with ChanServ(s, s.link_port, password=LINK_PW, extra='founder_mode = "q"'):
            f = s.client("fnd")
            f.say("JOIN #fm")
            f.say("PRIVMSG ChanServ :REGISTER #fm pw12345", 1.2)
            f.say("PRIVMSG ChanServ :IDENTIFY #fm pw12345", 1.0)
            assert "~fnd" in " ".join(f.say("NAMES #fm"))
            u = s.client("usr")
            u.say("JOIN #fm")
            f.say("PRIVMSG ChanServ :ADMIN #fm usr pw12345", 1.0)
            assert "&usr" in " ".join(f.say("NAMES #fm"))
            f.say("PRIVMSG ChanServ :DEADMIN #fm usr pw12345", 1.0)
            assert "&usr" not in " ".join(f.say("NAMES #fm"))


def test_akick_dedupe_and_access_case_insensitive():
    s = net()
    with s:
        with ChanServ(s, s.link_port, password=LINK_PW):
            f = s.client("fnd")
            f.say("JOIN #ak")
            f.say("PRIVMSG ChanServ :REGISTER #ak pw12345", 1.2)
            r1 = f.say("PRIVMSG ChanServ :AKICK #ak ADD bad!*@x.y pw12345", 1.0)
            r2 = f.say("PRIVMSG ChanServ :AKICK #ak ADD BAD!*@x.y pw12345", 1.0)
            assert any("added" in l for l in r1) and any("already" in l for l in r2), (r1, r2)
