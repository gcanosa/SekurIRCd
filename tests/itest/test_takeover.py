"""Registered channels against takeovers: ops grabbed on another server, during a services outage, kicking ChanServ."""
import time
from harness import Network, Server, ChanServ

PW = "svcsecret"


def cs(c, line, wait=1.0):
    c.drain(0.05)
    c.send(f"PRIVMSG ChanServ :{line}")
    time.sleep(wait)
    return [l for l in c.drain(0.2) if "ChanServ" in l or "NOTICE" in l]


def names(c, chan):
    return " ".join(l for l in c.say(f"NAMES {chan}", 0.5) if " 353 " in l)


def single():
    s = Server(cfg={"links": {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": 0}})
    s.cfg["links"]["port"] = s.link_port
    s.cfg["links.peers"] = [{"name": "services.test.net", "password": PW}]
    return s


def test_registered_channel_created_on_a_leaf_loses_the_grabbed_ops():
    n = Network(cfg={"accounts": {"enabled": True, "store_file": "acc.json"}})  # services link to a
    n.add("a")
    n.add("b", parent="a")
    n.start()
    try:
        f = n.client("a", "founder")
        f.say("JOIN #tk", 0.5)
        assert any("is now registered" in l for l in cs(f, "REGISTER #tk tkpass1", 1.5))
        cs(f, "SET #tk SECUREOPS OFF tkpass1")  # a recreated channel is vetted whatever SECUREOPS says
        f.say("PART #tk", 0.8)                  # the channel is gone
        grab = n.client("b", "grabber")         # recreates it on the leaf, where no services are linked
        grab.say("JOIN #tk", 2.0)
        assert "@grabber" not in names(grab, "#tk"), "ops grabbed on another server are taken back"
        assert "+r" in " ".join(grab.say("MODE #tk", 0.5)) or "r" in " ".join(l for l in grab.say("MODE #tk", 0.5) if " 324 " in l)
    finally:
        n.stop()


def test_services_restart_sweeps_takeovers_access_and_akick():
    s = single()
    svc = ChanServ(s, s.link_port, password=PW)
    with s:
        try:
            svc.start()
            f = s.client("founder")
            f.say("JOIN #rs", 0.4)
            cs(f, "REGISTER #rs rspass1", 1.5)
            cs(f, "SET #rs SECUREOPS OFF rspass1")
            cs(f, "ACCESS #rs ADD friend!*@* o rspass1")  # rejected (bare *) -- use the host form below
            cs(f, "ACCESS #rs ADD friend!*@127.0.0.1 o rspass1")
            cs(f, "AKICK #rs ADD evil!*@127.0.0.1 rspass1")
            # #keep lives through the outage: an op someone legitimately gave there is left alone
            f.say("JOIN #keep", 0.4)
            cs(f, "REGISTER #keep keeppass1", 1.5)
            cs(f, "SET #keep SECUREOPS OFF keeppass1")
            pal = s.client("pal")
            pal.say("JOIN #keep", 0.4)
            f.say("MODE #keep +o pal", 0.5)
            f.say("PART #rs", 0.5)

            svc.proc.terminate()
            svc.proc.wait(5)
            time.sleep(1.2)

            grab = s.client("grab")
            grab.say("JOIN #rs", 0.5)  # first in: gets @
            friend = s.client("friend")
            friend.say("JOIN #rs", 0.4)
            evil = s.client("evil")
            evil.say("JOIN #rs", 0.4)
            grab.say("MODE #rs +ikL lockkey #elsewhere", 0.4)  # and locks everyone else out
            grab.say("MODE #rs +b *!*@nobody.invalid", 0.4)
            assert "@grab" in names(grab, "#rs")

            svc.start()
            time.sleep(2.0)
            nm = names(grab, "#rs")
            assert "@grab" not in nm, "ops taken while services were down are taken back: " + nm
            assert "@friend" in nm, "an ACCESS member who joined meanwhile gets their mode: " + nm
            assert "evil" not in nm, "an AKICK member who joined meanwhile is kicked: " + nm
            assert "@pal" in names(f, "#keep"), "a channel that lived through the outage keeps its ops"
            modes = " ".join(l for l in grab.say("MODE #rs", 0.5) if " 324 " in l)
            assert "lockkey" not in modes and "#elsewhere" not in modes and "i" not in modes.split()[4], modes
            assert "r" in modes.split()[4], "+r is back: " + modes
            assert not any("nobody.invalid" in l for l in grab.say("MODE #rs +b", 0.5)), "the grabber's bans are gone"
        finally:
            svc.stop()


def test_chanserv_cannot_be_kicked_or_deopped():
    s = single()
    with s, ChanServ(s, s.link_port, password=PW):
        f = s.client("founder")
        f.say("JOIN #g", 0.4)
        cs(f, "REGISTER #g gpass1", 1.5)
        cs(f, "JOIN #g gpass1", 1.0)
        assert "@ChanServ" in names(f, "#g")
        r = f.say("KICK #g ChanServ :bye", 0.6)
        assert any(" 484 " in l for l in r), r
        r = f.say("MODE #g -o ChanServ", 0.6)
        assert any(" 484 " in l for l in r), r
        assert "@ChanServ" in names(f, "#g")


def test_secureops_checks_the_access_level_against_the_rank():
    s = single()
    with s, ChanServ(s, s.link_port, password=PW):
        f = s.client("founder")
        f.say("JOIN #lv", 0.4)
        cs(f, "REGISTER #lv lvpass1", 1.5)
        cs(f, "JOIN #lv lvpass1", 1.0)  # GUARD: ChanServ sees the MODEs
        cs(f, "ACCESS #lv ADD vo!*@127.0.0.1 v lvpass1")
        cs(f, "ACCESS #lv ADD op!*@127.0.0.1 o lvpass1")
        vo = s.client("vo")
        vo.say("JOIN #lv", 1.0)
        op = s.client("op")
        op.say("JOIN #lv", 1.0)
        nm = names(f, "#lv")
        assert "+vo" in nm and "@op" in nm, nm
        f.say("MODE #lv +o vo", 1.2)
        assert "@vo" not in names(f, "#lv"), "a VOICE entry doesn't cover @"
        f.say("MODE #lv -o op", 0.4)
        f.say("MODE #lv +o op", 1.2)
        assert "@op" in names(f, "#lv"), "an OP entry re-opped by hand keeps it"


def test_modes_set_in_the_same_breath_as_the_grab_are_reset():
    s = single()
    with s, ChanServ(s, s.link_port, password=PW):
        f = s.client("founder")
        f.say("JOIN #race", 0.4)
        cs(f, "REGISTER #race racepass1", 1.5)
        f.say("PART #race", 0.8)
        grab = s.client("grab")
        grab.send("JOIN #race")
        grab.send("MODE #race +ik racekey")  # before ChanServ can react
        time.sleep(1.5)
        grab.drain(0.1)  # the JOIN's own NAMES still shows @grab
        assert "@grab" not in names(grab, "#race")
        modes = " ".join(l for l in grab.say("MODE #race", 0.5) if " 324 " in l)
        assert "racekey" not in modes and "i" not in modes.split()[4], modes


def test_a_registered_channel_relinking_from_a_leaf_is_not_a_takeover():
    n = Network(cfg={"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}],
                     "accounts": {"enabled": True, "store_file": "acc.json"}})
    n.add("a")
    n.add("b", parent="a")
    n["b"].cfg["links"]["autoconnect"] = False
    n["a"].start()
    n["b"].start()
    try:
        boss, bop = n.client("a", "boss"), n.client("b", "bop")
        boss.say("OPER boss bosspw", 0.8)
        bop.say("OPER boss bosspw", 0.8)
        bop.say("CONNECT a.test.net", 1.5)
        n.wait_converged()
        f = n.client("b", "founder")  # the channel only ever lives on the leaf
        f.say("JOIN #leaf", 0.5)
        assert any("is now registered" in l for l in cs(f, "REGISTER #leaf leafpass1", 1.5))
        cs(f, "SET #leaf SECUREOPS OFF leafpass1")
        pal = n.client("b", "pal")
        pal.say("JOIN #leaf", 0.5)
        f.say("MODE #leaf +o pal", 0.4)
        f.say("MODE #leaf +b *!*@banned.invalid", 0.6)
        boss.say("SQUIT b.test.net :split", 1.5)
        bop.say("CONNECT a.test.net", 1.5)
        n.wait_converged()
        time.sleep(1.5)
        assert "@pal" in names(f, "#leaf"), "the channel ChanServ already knows keeps its hand-given ops"
        assert any("banned.invalid" in l for l in f.say("MODE #leaf +b", 0.5)), "and its bans"
    finally:
        n.stop()
