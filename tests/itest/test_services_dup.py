"""A second services daemon on the network: refused when it links, and when two halves that each run one link up,
the newer daemon is dropped cleanly (no ghost NickServ/ChanServ left behind)."""
import time
from harness import Network, Services, SVC_NAME, SVC_PW

CFG = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}], "accounts": {"enabled": True}}


def whois_server(n, server, nick, probe):
    r = n.client(server, probe).say(f"WHOIS {nick}", 0.5)
    return [l.split()[4] for l in r if " 312 " in l]


def test_second_services_daemon_is_refused():
    n = Network(cfg=CFG)
    n.add("a")
    n.add("b", parent="a")
    n["b"].cfg["links.peers"].append({"name": SVC_NAME, "password": SVC_PW})
    with n:
        boss = n.client("b", "boss")
        boss.say("OPER boss bosspw", 0.8)
        boss.drain()
        extra = Services(n["b"], n["b"].link_port)
        try:
            extra.start()
            assert boss.saw(r"Services link services\.test\.net dropped: Services already running on a\.test\.net", 3)
            time.sleep(0.5)
            assert "another services daemon already serves this network" in extra.output(), extra.output()
            assert whois_server(n, "b", "NickServ", "p1") == ["a.test.net"]
            assert whois_server(n, "a", "ChanServ", "p2") == ["a.test.net"]
        finally:
            extra.stop()


def test_two_halves_with_services_keep_the_older_daemon():
    n = Network(cfg=CFG)
    n.add("a")
    n.add("b", parent="a")
    n["b"].auto_services = True  # misconfigured: the leaf runs its own services too
    n["b"].cfg["links"]["autoconnect"] = False
    try:
        n["a"].start()
        time.sleep(1.2)  # a's daemon is the older one
        n["b"].start()
        watcher = n.client("a", "boss")
        watcher.say("OPER boss bosspw", 0.8)
        watcher.drain()
        linker = n.client("b", "linker")
        linker.say("OPER boss bosspw", 0.8)
        linker.say("CONNECT a.test.net", 1.5)
        n.wait_converged()
        time.sleep(1.0)
        assert linker.saw(r"both sides run a services daemon \(ours on b\.test\.net, theirs on a\.test\.net\)", 1) or \
            watcher.saw(r"both sides run a services daemon", 1)
        assert linker.saw(r"Services link services\.test\.net dropped: Services already running", 2) or \
            "Services already running" in n["b"].services.output(), n["b"].output()[-1500:]
        for srv in ("a", "b"):
            for nick in ("NickServ", "ChanServ"):
                assert whois_server(n, srv, nick, f"w{srv}{nick[0]}") == ["a.test.net"], (srv, nick)
        # no ghost: both servers count the same users
        probes = [n.client(srv, f"who{srv}") for srv in ("a", "b")]
        seen = [sorted(l.split()[7] for l in p.say("WHO *", 0.6) if " 352 " in l) for p in probes]
        assert seen[0] == seen[1] and seen[0].count("NickServ") == 1, seen
        time.sleep(1.0)
        assert "another services daemon already serves this network" in n["b"].services.output(), n["b"].services.output()[-800:]
    finally:
        for s in (n["a"], n["b"]):
            if s.services:
                s.services.stop()
        n.stop()
