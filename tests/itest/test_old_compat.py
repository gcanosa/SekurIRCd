"""A server of this tree linked with one of the release before it ($OLD_IRCD_BIN, a build of the previous version), in both orders:
the new link lines (XLN, UNXLN, CLASS) and config keys are ignored by the old side, users and channels still sync, and what
the new side keeps (Q-lines, global classes) still works locally. Does nothing when OLD_IRCD_BIN is not set."""
import os, time
import harness
from harness import Server, Client

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "oldcompatpw"
NEW_BIN = harness.IRCD


def old_available():
    return bool(os.environ.get("OLD_IRCD_BIN")) and os.path.exists(os.environ["OLD_IRCD_BIN"])


def start(srv, old):
    harness.IRCD = os.environ["OLD_IRCD_BIN"] if old else NEW_BIN
    try:
        srv.start()
    finally:
        harness.IRCD = NEW_BIN


def pair(hub_old):
    hub = Server("hub.test.net", cfg=dict(OPERS), sid="1HB")
    leaf = Server("leaf.test.net", cfg=dict(OPERS), sid="2LF")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [{"name": leaf.name, "password": PW, "allowed_ips": ["127.0.0.1"]}]
    leaf.cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    leaf.cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    hub.auto_services = leaf.auto_services = False
    if not hub_old:  # the new side carries every new knob; the old one would ignore the unknown keys, but keep its config plain
        hub.cfg["limits"] = {"channels_per_user": 50}
        hub.cfg["privacy"] = {"hide_idle": True}
        hub.cfg["classes"] = [{"name": "g", "hosts": ["127.0.0.1"], "max_per_ip": 40, "scope": "global"}]
    else:
        leaf.cfg["limits"] = {"channels_per_user": 50}
        leaf.cfg["classes"] = [{"name": "g", "hosts": ["127.0.0.1"], "max_per_ip": 40, "scope": "global"}]
    return hub, leaf


def oper(srv, nick):
    c = Client(srv.port, nick)
    c.send("OPER boss bosspw")
    c.expect(r" 381 ")
    return c


def exercise(hub_old):
    hub, leaf = pair(hub_old)
    start(hub, hub_old)
    start(leaf, not hub_old)
    try:
        time.sleep(2.0)
        new, old = (leaf, hub) if hub_old else (hub, leaf)
        a, b = Client(hub.port, "ha"), Client(leaf.port, "lb")
        a.say("JOIN #c", 0.3); b.say("JOIN #c", 0.3)
        time.sleep(0.5)
        assert "lb" in " ".join(a.say("NAMES #c", 0.5)), "users and channels sync across versions"
        a.say("PRIVMSG #c :hello over the link", 0.3)
        assert b.saw(r"PRIVMSG #c :hello over the link", 1.0)
        # the new side sets everything new: the link must survive the lines the old side does not know
        o = oper(new, "nboss")
        assert any("added" in l for l in o.say("QLINE zz* 1h x", 0.5))
        assert any("added" in l for l in o.say("RESV #zz* 1h x", 0.5))
        assert any("added" in l for l in o.say("XLINE zz_* 1h x", 0.5))
        assert any("added" in l for l in o.say("CLASS ADD GLOBAL cc 127.0.0.1 max_per_ip=30", 0.5))
        assert any("DEFCON 5" in l for l in o.say("DEFCON 5", 0.5))
        time.sleep(1.0)
        a.say("PRIVMSG #c :still linked", 0.3)
        assert b.saw(r"PRIVMSG #c :still linked", 1.0), "the link stayed up"
        # the new side enforces its own Q-line; the old side doesn't know it
        n = Client(new.port, "n1", register=False)
        n.send("NICK zzbad"); n.send("USER n 0 * :n")
        assert n.saw(r" 437 ", 1.0), "enforced on the new server"
        ob = Client(old.port, "o1", register=False)
        ob.send("NICK zzfine"); ob.send("USER o 0 * :o")
        assert ob.saw(r" 001 ", 1.5), "the old server ignores it and is unharmed"
        # a relink of the pair goes through a burst that now holds the new lines
        leaf.proc.terminate(); leaf.proc.wait(5)
        start(leaf, not hub_old)
        time.sleep(2.5)
        c = Client(leaf.port, "lc")
        c.say("JOIN #c", 0.3)
        a.say("PRIVMSG #c :after relink", 0.3)
        assert c.saw(r"PRIVMSG #c :after relink", 1.5), "relinked and syncing"
        for srv in (hub, leaf):
            assert "Traceback" not in srv.output() and "AddressSanitizer" not in srv.output()
    finally:
        hub.stop(); leaf.stop()


def test_new_leaf_under_an_old_hub():
    if old_available():
        exercise(hub_old=True)


def test_old_leaf_under_a_new_hub():
    if old_available():
        exercise(hub_old=False)
