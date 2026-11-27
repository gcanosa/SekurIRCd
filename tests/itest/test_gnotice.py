"""/GNOTICE: an oper's announcement reaches every user on every server, once; plain users, opers without the wallops
privilege and opers of a leaf the hub limits to itself can't send one."""
import time
from harness import Server, Client
from test_oper_scope import pair, oper, link_fake, read_all, OPERS


def got(c, text, wait=0.8):
    return [l for l in c.drain(wait) if " NOTICE " in l and l.endswith(" :[Announcement] " + text)]


def test_reaches_every_user_on_every_server_once():
    hub, leaf = pair()
    try:
        boss = oper(leaf.port, "boss")
        near, far = Client(leaf.port, "near"), Client(hub.port, "far")
        time.sleep(0.5)
        long = "restart at 22:00 UTC, " + "word " * 30 + "end"
        boss.send("GNOTICE :" + long)
        for c in (near, far, boss):
            assert len(got(c, long)) == 1, "one full copy each, the sender too"
        out = boss.say("GNOTICE restart at ten", 0.5)
        assert any("Usage: GNOTICE" in l for l in out), out
        assert not far.saw("Announcement", 0.5), "unquoted text is refused, not cut"
        assert any(" 481 " in l for l in near.say("GNOTICE :me too", 0.5)), "opers only"
        assert not far.saw("me too", 0.5)
    finally:
        hub.stop(); leaf.stop()


def test_needs_the_wallops_privilege():
    cfg = {"operators": [dict(OPERS["operators"][0], privileges=["kill"])]}
    with Server(cfg=cfg) as s:
        op, u = oper(s.port, "lim"), s.client("u")
        assert any(" 481 " in l for l in op.say("GNOTICE :nope", 0.5))
        assert not u.saw("nope", 0.5)


def test_a_limited_leaf_cannot_announce():
    hub, leaf = pair(oper_scope="local")
    try:
        op, far = oper(leaf.port, "lop"), Client(hub.port, "far")
        time.sleep(0.5)
        assert any("oper_scope = local" in l for l in op.say("GNOTICE :from the leaf", 0.5))
        assert not far.saw("from the leaf", 0.5)
    finally:
        hub.stop(); leaf.stop()


def test_hub_drops_a_limited_leafs_gnotice():
    hub = Server("hub.test.net", cfg=dict(OPERS), sid="1HB")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port}
    hub.cfg["links.peers"] = [{"name": "fake.test.net", "password": "pw1", "oper_scope": "local"},
                              {"name": "ctl.test.net", "password": "pw2"}]
    hub.auto_services = False
    hub.start()
    try:
        u = Client(hub.port, "u")
        for name, pw, sid, through in (("fake.test.net", "pw1", "7FK", False), ("ctl.test.net", "pw2", "8CT", True)):
            s, _ = link_fake(hub, name, pw, sid, "fop" + sid.lower())
            read_all(s)
            s.sendall(f":{sid} GNOTICE :spoken by {sid}\r\n".encode())
            assert bool(u.saw("spoken by " + sid, 0.8)) == through, name
            s.close()
            time.sleep(0.5)
    finally:
        hub.stop()
