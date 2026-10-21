"""[server] ipv6: off by default (IPv4 exactly as before), IPv6 twin listeners when on, CIDR masks, per-/64 limits."""
import socket, time
from harness import Server, Network, Client

V6 = {"server": {"ipv6": True, "bind6": "::1"}}
OPER = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def v6_refused(port):
    try:
        socket.create_connection(("::1", port), timeout=1).close()
        return False
    except OSError:
        return True


def test_off_by_default_ipv4_only():
    with Server() as s:
        assert v6_refused(s.port), "nothing may listen on IPv6 unless ipv6 = true"
        assert s.client("v4only")


def test_ipv6_client_is_shown_as_0_colon_form():
    with Server(cfg=V6) as s:
        c = s.client("six", host="::1")
        r = c.say("WHOIS six", 0.5)
        assert any(" 311 six six six 0::1 :" in l for l in r), r        # a middle param can't start with ':'
        assert any("0::1" in l for l in c.say("USERHOST six")), "USERHOST"
        four = s.client("four", host="127.0.0.1")                       # IPv4 alongside, unchanged
        assert four
        assert any(" 311 six four four 127.0.0.1 " in l for l in c.say("WHOIS four", 0.5))


def test_cidr_zline_bans_ipv6_and_keeps_ipv4():
    with Server(cfg={**V6, **OPER}) as s:
        op = s.client("op")
        op.say("OPER boss bosspw", 0.5)
        # typed as 0:0::0/64 (a parameter can't start with ':', so ::/64 is written 0::/64), stored canonical
        assert any("Z-line added: 0::/64" in l for l in op.say("ZLINE 0:0::0/64 10m v6 test", 0.5)), "normalized and added"
        sock = socket.create_connection(("::1", s.port), timeout=2)
        time.sleep(0.4)
        assert b"Z-Lined" in sock.recv(4096)
        sock.close()
        assert s.client("stillv4")
        assert any("matching every address" in l for l in op.say("KLINE 0::/0 x", 0.5)), "/0 refused"


def test_per_ip_limit_counts_ipv6():
    with Server(cfg={**V6, "security": {"max_connections_per_ip": 2}}) as s:
        a, b = s.client("a6", host="::1"), s.client("b6", host="::1")
        sock = socket.create_connection(("::1", s.port), timeout=2)
        time.sleep(0.4)
        assert b"Too many connections from your host" in sock.recv(4096)
        sock.close()
        assert a and b


def test_gateway_connections_dont_leak_the_per_ip_count():
    # WEBIRC changes the client's address after it was counted under the gateway's; the count used to go back down
    # under the new address, so every gateway user leaked one slot until the gateway hit max_connections_per_ip.
    cfg = {"webirc": [{"name": "gw", "password": "gwpass", "hosts": ["127.0.0.1"]}],
           "security": {"max_connections_per_ip": 2}}
    with Server(cfg=cfg) as s:
        for i in range(4):
            c = s.client(f"w{i}", register=False, extra=[f"WEBIRC gwpass kiwi h{i}.example.org 2001:db8::{i + 1}"])
            c.send(f"NICK w{i}")
            c.send(f"USER w{i} 0 * :x")
            c.expect(r" 001 ")
            assert any(f"2001:db8::{i + 1}" in l or f"h{i}.example.org" in l for l in c.say(f"WHOIS w{i}", 0.4))
            c.send("QUIT")
            c.close()
            time.sleep(0.3)


def test_rehash_turns_ipv6_on_and_off():
    with Server() as s:
        assert v6_refused(s.port)
        s.cfg["server"].update(V6["server"])
        s.reload()
        assert Client(s.port, "late6", host="::1")
        s.cfg["server"]["ipv6"] = False
        s.reload()
        assert v6_refused(s.port)


def test_server_link_over_ipv6():
    net = Network(cfg=V6)
    hub, leaf = net.add("hub"), net.add("leaf", parent="hub")
    for s in (hub, leaf):
        s.cfg["links"]["bind6"] = "::1"
    leaf.cfg["links.peers"][0]["host"] = "::1"
    net.start()
    try:
        h = net.client("hub", "onhub")
        c = net.client("leaf", "onleaf")
        assert h and any(" 311 onleaf onhub " in l for l in c.say("WHOIS onhub", 0.5))
        assert "inbound link connection accepted from 0::1" in hub.output()
    finally:
        net.stop()
