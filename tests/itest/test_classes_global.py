"""CLASS: classes an oper adds at run time (kept across restarts), local or global; a global class (CLASS ADD GLOBAL, or
scope = "global" in [[classes]]) is applied by every linked server to its own connections; a server may refuse them."""
import socket, time
from harness import Server, Client

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "classpw"


def oper(srv, nick):
    c = Client(srv.port, nick)
    c.send("OPER boss bosspw")
    c.expect(r" 381 ")
    return c


def refused(port, nick):
    """Does a new connection get turned away by a class/IP cap (an ERROR before registration)?"""
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.settimeout(0.4)
    out = b""
    end = time.time() + 0.8
    while time.time() < end:
        try:
            d = s.recv(4096)
            if not d:
                break
            out += d
        except (socket.timeout, ConnectionResetError):
            pass
    s.close()
    return b"ERROR" in out


def pair(hub_cfg=None, leaf_cfg=None):
    hub = Server("hub.test.net", cfg=dict(OPERS, **(hub_cfg or {})), sid="1HB")
    leaf = Server("leaf.test.net", cfg=dict(OPERS, **(leaf_cfg or {})), sid="2LF")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [{"name": leaf.name, "password": PW, "allowed_ips": ["127.0.0.1"]}]
    leaf.cfg["links"] = dict({"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}, **(leaf_cfg or {}).get("links", {}))
    leaf.cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    hub.auto_services = leaf.auto_services = False
    return hub, leaf


def test_class_add_list_del_limits_and_survives_a_restart():
    s = Server(cfg=OPERS)
    s.start()
    try:
        o = oper(s, "boss")
        out = o.say("CLASS ADD tight 127.0.0.1 max_per_ip=2", 0.5)
        assert any("added (this server only)" in l for l in out), out
        assert any("tight [CLASS] 127.0.0.1 max_per_ip=2" in l for l in o.say("CLASS", 0.5))
        keep = s.client("k1")  # the oper and k1 fill the class: a third is turned away
        assert refused(s.port, "k2")
        assert any("exists already" in l for l in o.say("CLASS ADD tight 10.0.0.0/8", 0.4))
        s.restart()
        o = oper(s, "boss2")
        assert any("tight [CLASS]" in l for l in o.say("CLASS", 0.5)), "kept in classes.json"
        assert any("removed" in l for l in o.say("CLASS DEL tight", 0.4))
        assert any("No classes" in l for l in o.say("CLASS", 0.4))
        assert keep
    finally:
        s.stop()


def test_a_class_from_the_config_file_is_changed_there_not_with_class_del():
    cfg = dict(OPERS, classes=[{"name": "fromfile", "hosts": ["127.0.0.1"], "max_per_ip": 50}])
    with Server(cfg=cfg) as s:
        o = oper(s, "boss")
        assert any("fromfile [config file] 127.0.0.1 max_per_ip=50" in l for l in o.say("CLASS", 0.4))
        assert any("config file" in l and "REHASH" in l for l in o.say("CLASS DEL fromfile", 0.4))


def test_a_global_class_is_applied_by_the_other_server_and_removed_with_it():
    hub, leaf = pair()
    hub.start(); leaf.start()
    try:
        time.sleep(1.6)
        h = oper(hub, "hboss")
        assert any("on every linked server" in l for l in h.say("CLASS ADD GLOBAL cap 127.0.0.1 max_per_ip=3", 0.5))
        time.sleep(0.6)
        lo = oper(leaf, "lboss")
        assert any("cap [from hub.test.net, global] 127.0.0.1 max_per_ip=3" in l for l in lo.say("CLASS", 0.5)), "listed on the leaf, with its owner"
        keep = [leaf.client("l1"), leaf.client("l2")]  # three on the leaf with the oper: the fourth is refused
        assert refused(leaf.port, "l3")
        # the leaf's oper removes the hub's class: gone here at once, and the hub is asked to drop it at the source
        out = lo.say("CLASS DEL cap", 0.5)
        assert any("hub.test.net was asked" in l for l in out), out
        time.sleep(0.8)
        assert any("No classes" in l for l in h.say("CLASS", 0.4)), "the owner dropped it"
        assert not refused(leaf.port, "l4")
        assert keep
    finally:
        hub.stop(); leaf.stop()


def test_a_relink_brings_the_set_back_and_a_leaf_can_refuse_global_classes():
    hub, leaf = pair(leaf_cfg={"links": {"accept_global_classes": False}})
    hub.cfg["classes"] = [{"name": "filecls", "hosts": ["127.0.0.1"], "max_per_ip": 3, "scope": "global"}]
    hub.start(); leaf.start()
    try:
        time.sleep(1.6)
        lo = oper(leaf, "lboss")
        assert any("No classes" in l for l in lo.say("CLASS", 0.5)), "this leaf takes none of the hub's"
        # the same hub, towards a leaf that does accept them
    finally:
        hub.stop(); leaf.stop()
    hub, leaf = pair()
    hub.cfg["classes"] = [{"name": "filecls", "hosts": ["127.0.0.1"], "max_per_ip": 3, "scope": "global"}]
    hub.start()
    try:
        leaf.start()
        time.sleep(1.8)
        lo = oper(leaf, "lboss")
        assert any("filecls [from hub.test.net, global]" in l for l in lo.say("CLASS", 0.5)), "scope = global in [[classes]] travels in the burst"
        hub.proc.terminate(); hub.proc.wait(5)
        hub.start()
        time.sleep(2.5)  # the hub is back: its set is sent again, nothing doubles
        out = [l for l in lo.say("CLASS", 0.5) if "filecls" in l]
        assert len(out) == 1, out
    finally:
        hub.stop(); leaf.stop()


def test_a_leaf_the_hub_limits_to_itself_cannot_publish_a_class():
    hub, leaf = pair()
    hub.cfg["links.peers"][0]["oper_scope"] = "local"
    hub.start(); leaf.start()
    try:
        time.sleep(1.6)
        lo = oper(leaf, "lboss")
        assert any("refused" in l for l in lo.say("CLASS ADD GLOBAL x 127.0.0.1 max_per_ip=3", 0.5)), "the leaf refuses it up front"
        assert any("added (this server only)" in l for l in lo.say("CLASS ADD y 127.0.0.1 max_per_ip=30", 0.5))
        h = oper(hub, "hboss")
        assert any("No classes" in l for l in h.say("CLASS", 0.5))
    finally:
        hub.stop(); leaf.stop()
