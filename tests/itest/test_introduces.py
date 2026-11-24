"""[[links.peers]] introduces / leaf: which servers may appear behind a link. A server that does not fit is refused (its users never
show), the link stays up; with leaf = true any server behind the link closes it; tightening it at /REHASH acts on what is there."""
import subprocess, time
from harness import Server, Client, IRCD

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "introducespw"


def servers(hub_peer_extra=None, la_peer_extra=None, with_other_on_hub=False):
    """hub.sekurnet.org <- la.sekurnet.org <- {evil.example.com, ok.sekurnet.org}; the hub's entry for la takes `hub_peer_extra`."""
    S = {}
    for n, sid in (("hub.sekurnet.org", "1HB"), ("la.sekurnet.org", "2LA"), ("evil.example.com", "3EV"), ("ok.sekurnet.org", "4OK"), ("other.sekurnet.org", "5OT")):
        S[n] = Server(n, cfg=dict(OPERS), sid=sid)
        S[n].auto_services = False
    hub, la, evil, ok = S["hub.sekurnet.org"], S["la.sekurnet.org"], S["evil.example.com"], S["ok.sekurnet.org"]
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [dict({"name": la.name, "password": PW, "allowed_ips": ["127.0.0.1"]}, **(hub_peer_extra or {}))]
    if with_other_on_hub:
        hub.cfg["links.peers"].append({"name": "other.sekurnet.org", "password": PW, "allowed_ips": ["127.0.0.1"]})
        S["other.sekurnet.org"].cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
        S["other.sekurnet.org"].cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    la.cfg["links"] = {"enabled": True, "mode": "both", "bind": "127.0.0.1", "port": la.link_port, "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    la.cfg["links.peers"] = [dict({"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}, **(la_peer_extra or {})),
                             {"name": evil.name, "password": PW}, {"name": ok.name, "password": PW}]
    for leaf in (evil, ok):
        leaf.cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
        leaf.cfg["links.peers"] = [{"name": la.name, "password": PW, "host": "127.0.0.1", "port": la.link_port}]
    return S


def run(S, order, wait=3.0):
    for n in order:
        if n in S:
            S[n].start()
    time.sleep(wait)


def stop(S):
    for s in reversed(list(S.values())):
        try:
            s.stop()
        except Exception:
            pass


KEEP = []  # a Client that nothing refers to is closed by the garbage collector, and its user quits


def user(srv, nick):
    c = Client(srv.port, nick)
    KEEP.append(c)
    return c


def whois_hits(c, nick):
    return any(" 311 " in l for l in c.say(f"WHOIS {nick}", 0.5))


def test_a_server_outside_the_list_is_refused_and_its_users_never_show():
    S = servers(hub_peer_extra={"introduces": ["*.SekurNet.org"]})  # case does not matter
    try:
        run(S, ["hub.sekurnet.org", "la.sekurnet.org", "ok.sekurnet.org", "evil.example.com"])
        hub = S["hub.sekurnet.org"]
        user(S["la.sekurnet.org"], "ula"); user(S["ok.sekurnet.org"], "uok"); user(S["evil.example.com"], "uevil")
        time.sleep(1.0)
        o = Client(hub.port, "obs")
        assert whois_hits(o, "ula"), "the peer's own users show"
        assert whois_hits(o, "uok"), "a server that fits the list is accepted"
        assert not whois_hits(o, "uevil"), "the intruder's users never show"
        o.send("OPER boss bosspw"); o.expect(r" 381 ")
        links = " ".join(l for l in o.say("LINKS", 0.5) if " 364 " in l)  # (the server notice about the refusal names it too)
        assert "ok.sekurnet.org" in links and "evil.example.com" not in links, links
        assert "Refused server evil.example.com introduced by la.sekurnet.org" in hub.output(), hub.output()[-1500:]
        assert whois_hits(o, "ula"), "and the link stayed up"
    finally:
        stop(S)


def test_leaf_true_closes_a_link_that_announces_any_server():
    S = servers(hub_peer_extra={"leaf": True})
    try:
        run(S, ["hub.sekurnet.org", "la.sekurnet.org", "ok.sekurnet.org"])
        hub = S["hub.sekurnet.org"]
        out = hub.output()
        assert "says nothing may link behind it (leaf = true)" in out, out[-1500:]
        o = Client(hub.port, "obs"); o.send("OPER boss bosspw"); o.expect(r" 381 ")
        # la itself may be linked at any moment (it redials, and is clean while its own leaf is reconnecting to it); what may
        # never show here is a server behind it
        for _ in range(4):
            links = [l for l in o.say("LINKS", 0.5) if " 364 " in l]  # not the server notices, which name it
            assert not any("ok.sekurnet.org" in l for l in links), "no server behind a leaf = true peer is ever entered"
    finally:
        stop(S)


def test_a_leaf_with_nothing_behind_it_links_normally_under_leaf_true():
    S = servers(hub_peer_extra={"leaf": True})
    try:
        run(S, ["hub.sekurnet.org", "la.sekurnet.org"])  # la's own leaves never start: nothing is behind it
        hub = S["hub.sekurnet.org"]
        user(S["la.sekurnet.org"], "ula")
        time.sleep(0.8)
        assert whois_hits(Client(hub.port, "obs"), "ula")
    finally:
        stop(S)


def test_a_leaf_can_limit_what_its_hub_brings_in():
    S = servers(la_peer_extra={"introduces": ["*.eu.sekurnet.org"]}, with_other_on_hub=True)
    try:
        run(S, ["hub.sekurnet.org", "la.sekurnet.org", "other.sekurnet.org"])
        la = S["la.sekurnet.org"]
        user(S["other.sekurnet.org"], "uother"); user(S["hub.sekurnet.org"], "uhub")
        time.sleep(1.0)
        o = Client(la.port, "obs")
        assert whois_hits(o, "uhub"), "the hub itself is always accepted"
        assert not whois_hits(o, "uother"), "a server the hub brings that does not fit"
        assert "Refused server other.sekurnet.org introduced by hub.sekurnet.org" in la.output(), la.output()[-1500:]
    finally:
        stop(S)


def test_tightening_it_at_rehash_acts_on_what_is_already_linked():
    S = servers()
    try:
        run(S, ["hub.sekurnet.org", "la.sekurnet.org", "ok.sekurnet.org"])
        hub = S["hub.sekurnet.org"]
        user(S["ok.sekurnet.org"], "uok")
        time.sleep(0.8)
        o = Client(hub.port, "obs")
        assert whois_hits(o, "uok"), "no setting: everything is accepted, as before"
        hub.cfg["links.peers"][0]["introduces"] = ["*.nowhere.net"]
        hub.reload()
        time.sleep(0.5)
        assert "no longer allowed by its introduces / leaf setting" in hub.output(), hub.output()[-1500:]
        time.sleep(3.5)  # la dials again: the link is up, ok.sekurnet.org is refused this time
        o2 = Client(hub.port, "obs2")
        assert not whois_hits(o2, "uok")
    finally:
        stop(S)


def test_a_config_with_leaf_and_introduces_is_refused():
    s = Server("hub.sekurnet.org", cfg={"links": {"enabled": True, "mode": "hub", "port": 7000},
                                         "links.peers": [{"name": "la.sekurnet.org", "password": "x", "leaf": True, "introduces": ["*.x.net"]}]})
    s.write_config()
    r = subprocess.run([IRCD, "--check", "-c", s.cfg_path], capture_output=True, text=True, cwd=s.dir)
    s.stop()
    assert r.returncode != 0 and "leaf = true already means" in (r.stdout + r.stderr), (r.stdout, r.stderr)
