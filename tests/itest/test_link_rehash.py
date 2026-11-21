"""/REHASH on a server closes the links whose [[links.peers]] entry is gone, or whose address the entry's allowed_ips no
longer lists, and refuses them from then on; a rehash that changes nothing about links leaves them alone."""
import time
from harness import Server, Client, SVC_NAME
from test_accounts import register

PW = "linkrehashpw"
# A hub must keep at least one entry that accepts a leaf (a rehash with none is refused and changes nothing), so every test
# keeps this one next to the leaf's entry.
SPARE = {"name": "spare.test.net", "password": "sparepw"}


def pair():
    hub = Server("hub.test.net", sid="1HB")
    leaf = Server("leaf.test.net", sid="2LF")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [{"name": leaf.name, "password": PW, "allowed_ips": ["127.0.0.1"]}, dict(SPARE)]
    leaf.cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    leaf.cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    hub.auto_services = leaf.auto_services = False
    hub.start(); leaf.start()
    time.sleep(1.5)
    return hub, leaf


def talk(a, b, text, wait=1.0):
    a.send(f"PRIVMSG #h :{text}")
    return bool(b.saw(rf"PRIVMSG #h :{text}", wait))


def linked(rx, u):
    """Does the hub still know the leaf's user, and do messages cross in both directions?"""
    return not any(" 401 " in l for l in rx.say("WHOIS u1", 0.5)) and talk(u, rx, "up to hub") and talk(rx, u, "down to leaf")


def wait_for(fn, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.4)
    return False


def users(hub, leaf):
    rx, u = Client(hub.port, "rx"), Client(leaf.port, "u1")
    rx.say("JOIN #h"); u.say("JOIN #h")
    time.sleep(0.6)
    return rx, u


def test_a_rehash_that_changes_nothing_keeps_the_link():
    hub, leaf = pair()
    try:
        rx, u = users(hub, leaf)
        assert linked(rx, u)
        hub.reload(); leaf.reload()
        time.sleep(1.0)
        assert linked(rx, u), "both sides rehashed with the same entries: nothing closed"
        assert "Link with leaf.test.net closed" not in hub.output()
    finally:
        hub.stop(); leaf.stop()


def test_removing_a_peer_entry_and_rehashing_closes_the_link_and_refuses_the_peer():
    hub, leaf = pair()
    try:
        rx, u = users(hub, leaf)
        assert linked(rx, u)
        entry = hub.cfg["links.peers"]
        hub.cfg["links.peers"] = [dict(SPARE)]
        hub.reload()
        time.sleep(1.0)
        assert any(" 401 " in l for l in rx.say("WHOIS u1", 0.5)), "the leaf's users left with the link"
        assert "Link with leaf.test.net closed: its [[links.peers]] entry was removed" in hub.output(), hub.output()[-1500:]
        assert "links: 1 closed" in hub.output()
        assert wait_for(lambda: "is closing the link: Closing link: its [[links.peers]] entry was removed" in leaf.output(), 3), \
            ("the leaf's log says why it was dropped", leaf.output()[-800:])
        # the leaf keeps dialing (autoconnect) and is refused each time, with the reason in the hub's log
        assert wait_for(lambda: "no [[links.peers]] entry has that name" in hub.output(), 6), hub.output()[-1500:]
        assert any(" 401 " in l for l in rx.say("WHOIS u1", 0.5)), "still apart"
        # put the entry back: the next dial is accepted
        hub.cfg["links.peers"] = entry
        hub.reload()
        assert wait_for(lambda: linked(rx, u), 12), "relinked once the entry is back"
    finally:
        hub.stop(); leaf.stop()


def test_an_allowed_ips_that_no_longer_lists_the_peers_address_closes_its_link():
    hub, leaf = pair()
    try:
        rx, u = users(hub, leaf)
        assert linked(rx, u)
        entry = hub.cfg["links.peers"]
        hub.cfg["links.peers"] = [dict(entry[0], allowed_ips=["203.0.113.7"]), dict(SPARE)]
        hub.reload()
        time.sleep(1.0)
        assert any(" 401 " in l for l in rx.say("WHOIS u1", 0.5)), "closed: 127.0.0.1 is no longer allowed"
        assert "its address is no longer in the entry's allowed_ips" in hub.output(), hub.output()[-1500:]
        time.sleep(3.0)
        assert any(" 401 " in l for l in rx.say("WHOIS u1", 0.5)), "and refused when it dials again"
        hub.cfg["links.peers"] = entry
        hub.reload()
        assert wait_for(lambda: linked(rx, u), 12), "relinked once its address is allowed again"
    finally:
        hub.stop(); leaf.stop()


def test_a_changed_password_does_not_split_a_working_link():
    hub, leaf = pair()
    try:
        rx, u = users(hub, leaf)
        assert linked(rx, u)
        hub.cfg["links.peers"] = [dict(hub.cfg["links.peers"][0], password="rotated-" + PW), dict(SPARE)]
        hub.reload()
        time.sleep(1.5)
        assert linked(rx, u), "rotating a password leaves the open link up (a /SQUIT ends it)"
        assert "closed:" not in hub.output().split("rehashed config")[-1]
    finally:
        hub.stop(); leaf.stop()


def test_removing_the_services_entry_drops_services_and_restoring_it_brings_them_back():
    s = Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json"}})
    s.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": s.link_port}
    s.cfg["links.peers"] = [dict(SPARE)]  # the harness adds the services entry next to it
    with s:
        c = register(s, "gera1", "gera", "password1")
        assert c is not None
        entry = s.cfg["links.peers"]
        assert any(p["name"] == SVC_NAME for p in entry), entry
        s.cfg["links.peers"] = [dict(SPARE)]
        s.reload()
        time.sleep(1.0)
        assert f"Link with {SVC_NAME} closed" in s.output(), s.output()[-1200:]
        s.cfg["links.peers"] = entry
        s.reload()
        s.wait_services(20)
        d = register(s, "plain", "plain", "password1")  # NickServ answers again
        assert d is not None
