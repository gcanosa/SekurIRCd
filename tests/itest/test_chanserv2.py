import time
from harness import Server, ChanServ

PW = "svcsecret"


def net():
    s = Server(cfg={"links": {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": 0},
                    "accounts": {"enabled": True, "store_file": "acc.json"}})
    s.cfg["links"]["port"] = s.link_port
    s.cfg["links.peers"] = [{"name": "services.test.net", "password": PW}]
    return s


def cs(c, line, wait=1.0):
    c.drain(0.05)
    c.send(f"PRIVMSG ChanServ :{line}")
    time.sleep(wait)
    return [l for l in c.drain(0.2) if "ChanServ" in l or "NOTICE" in l]


def account_client(s, nick, account):
    c = s.client(nick)
    c.say(f"REGISTER {account} password1", 1.5)
    return c


def setup(s, cserv, nick="fnd", account="founder1", chan="#cs"):
    c = account_client(s, nick, account)
    c.say(f"JOIN {chan}")
    cs(c, f"REGISTER {chan} chanpass1", 1.4)
    cs(c, f"JOIN {chan} chanpass1")
    return c


def test_extended_mlock_enforced():
    s = net()
    with s, ChanServ(s, s.link_port, password=PW):
        f = setup(s, None)
        r = cs(f, "SET #cs MLOCK +ntk-s lockedkey chanpass1")
        assert any("is now" in l for l in r), r
        modes = " ".join(f.say("MODE #cs"))
        assert "+nt" in modes and "k lockedkey" in modes or ("lockedkey" in modes), modes
        f.send("MODE #cs -k lockedkey")
        time.sleep(0.8)
        assert "lockedkey" in " ".join(f.say("MODE #cs")), "a removed key is put back"
        f.send("MODE #cs +s")
        time.sleep(0.8)
        assert "s" not in " ".join(f.say("MODE #cs")).split(" 324 fnd #cs ")[-1].split(" ")[0], "a forbidden +s is taken off"
        r = cs(f, "SET #cs MLOCK +x chanpass1")
        assert any("MLOCK letters" in l for l in r), r
        r = cs(f, "SET #cs MLOCK +k chanpass1")
        assert any("needs a parameter" in l for l in r), r


def test_founder_account_star_password_and_autoop():
    s = net()
    with s, ChanServ(s, s.link_port, password=PW):
        f = setup(s, None, "fnd", "founder1")
        assert any("Founder account: founder1" in l for l in cs(f, "INFO #cs")), "registering while logged in sets the founder account"
        other = s.client("stranger")
        r = cs(other, "SET #cs DESC hello *")
        assert any("incorrect" in l or "Password" in l for l in r), r  # not the founder: * is refused
        # a second session of the founder account: * works, and joining gets the founder rank automatically
        f2 = s.client("fnd2", register=False, caps=["sasl"])
        import base64
        f2.send("AUTHENTICATE PLAIN")
        f2.expect(r"AUTHENTICATE \+")
        f2.send("AUTHENTICATE " + base64.b64encode(b"\0founder1\0password1").decode())
        f2.expect(r" 903 ")
        f2.send("NICK fnd2")
        f2.send("USER fnd2 0 * :x")
        f2.expect(r" 001 ")
        f2.say("JOIN #cs", 1.2)
        names = " ".join(f2.say("NAMES #cs"))
        assert "@fnd2" in names, names
        r = cs(f2, "SET #cs DESC by account *")
        assert any("is now" in l for l in r), r


def test_restricted_and_secureops():
    s = net()
    with s, ChanServ(s, s.link_port, password=PW):
        f = setup(s, None)
        cs(f, "ACCESS #cs ADD *!*@nowhere.invalid o chanpass1")
        assert any("RESTRICTED for #cs is now ON" in l for l in cs(f, "SET #cs RESTRICTED ON chanpass1"))
        stranger = s.client("stranger")
        r = stranger.say("JOIN #cs", 1.2)
        assert stranger.saw(r"KICK #cs stranger", 1.0) or any("KICK" in l for l in r), "restricted: a stranger is kicked"
        cs(f, "SET #cs RESTRICTED OFF chanpass1")
        cs(f, "SET #cs SECUREOPS ON chanpass1")
        friend = s.client("friend")
        friend.say("JOIN #cs", 1.0)
        f.say("MODE #cs +o friend")
        time.sleep(1.0)
        assert "@friend" not in " ".join(f.say("NAMES #cs")), "secureops takes ops away from someone ChanServ never granted them to"


def test_private_hidden_from_list():
    s = net()
    with s, ChanServ(s, s.link_port, password=PW):
        f = setup(s, None, chan="#visible")
        g = account_client(s, "gg", "founder2")
        g.say("JOIN #hidden")
        cs(g, "REGISTER #hidden chanpass2", 1.4)
        cs(g, "SET #hidden PRIVATE ON chanpass2")
        r = cs(f, "LIST")
        txt = " ".join(r)
        assert "#visible" in txt and "#hidden" not in txt, txt
        assert "#hidden" in " ".join(cs(g, "LIST")), "its founder still sees it"
