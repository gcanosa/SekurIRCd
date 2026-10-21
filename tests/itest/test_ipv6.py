"""[server] ipv6: off by default (IPv4 exactly as before), IPv6 twin listeners when on, CIDR masks, per-/64 limits."""
import os, socket, sys, time
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


def link_v6(s):
    s.cfg["server"].update(V6["server"])
    s.cfg["links"]["bind6"] = "::1"


def test_pinned_tls_link_over_ipv6_and_linkmgmt_sees_it():
    from test_linktls import tls_net
    import subprocess, os, re
    net, hub_fp, _ = tls_net(passwords=False)  # fingerprint-only: the certificate is the credential
    hub, leaf = net["hub"], net["leaf"]
    for s in (hub, leaf):
        link_v6(s)
    leaf.cfg["links.peers"][0]["host"] = "::1"
    with net:
        h, c = net.client("hub", "tlshub"), net.client("leaf", "tlsleaf")
        assert h and any(" 311 tlsleaf tlshub " in l for l in c.say("WHOIS tlshub", 0.5))
        out = hub.output()
        assert "inbound link connection accepted from 0::1" in out and "[TLS]" in out, out[-1500:]
        assert "is plain text" not in out  # the loopback sniff saw a TLS ClientHello, not a plain link
        assert "(TLS)" in leaf.output()
        tool = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "linkmgmt.py")
        r = subprocess.run([sys.executable, tool, "test", "::1", str(hub.link_port), "--tls", "--no-banner"],
                           capture_output=True, text=True, timeout=30)
        plain = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout)
        assert f"TCP  ::1 port {hub.link_port}: open" in plain, plain
        assert hub_fp in plain, plain  # self-signed, so it offers the fingerprint to pin -- the hub's real one


def test_three_servers_mixing_ipv6_and_ipv4_links():
    net = Network(cfg=V6)
    hub, mid, leaf = net.add("hub"), net.add("mid", parent="hub"), net.add("leaf", parent="mid")
    for s in (hub, mid, leaf):
        s.cfg["links"]["bind6"] = "::1"
    mid.cfg["links.peers"][0]["host"] = "::1"  # mid -> hub over IPv6; leaf -> mid stays on 127.0.0.1
    with net:
        a, z = net.client("hub", "athub"), net.client("leaf", "atleaf")
        assert a and any(" 311 atleaf athub " in l for l in z.say("WHOIS athub", 0.5))
        z.say("JOIN #mix", 0.3); a.say("JOIN #mix", 0.5)
        z.send("PRIVMSG #mix :across both links")
        assert a.saw("across both links", 1.0)
        assert "inbound link connection accepted from 0::1" in hub.output()
        assert "inbound link connection accepted from 127.0.0.1" in mid.output()


def test_link_host_name_prefers_ipv6_and_falls_back_to_ipv4():
    # "localhost" resolves to ::1 first here. Hub with IPv6: the leaf links over ::1.
    net = Network()
    hub, leaf = net.add("hub"), net.add("leaf", parent="hub")
    link_v6(hub); link_v6(leaf)
    leaf.cfg["links.peers"][0]["host"] = "localhost"
    with net:
        assert "inbound link connection accepted from 0::1" in hub.output()
    # Hub without IPv6: ::1 is refused, the next address (127.0.0.1) links.
    net = Network()
    hub, leaf = net.add("hub"), net.add("leaf", parent="hub")
    link_v6(leaf)
    leaf.cfg["links.peers"][0]["host"] = "localhost"
    with net:
        assert "inbound link connection accepted from 127.0.0.1" in hub.output()


def test_services_link_over_ipv6():
    from harness import Services
    s = Server(cfg={**V6, "accounts": {"enabled": True}})
    s.auto_services = False
    s._prepare_services()
    s.cfg["links"]["bind6"] = "::1"
    with s:
        svc = Services(s, s.link_port)
        p = os.path.join(svc.dir, "services.toml")
        conf = open(p).read()  # read before reopening for writing, which truncates it
        open(p, "w").write(conf.replace('host = "127.0.0.1"', 'host = "::1"'))
        s.services = svc
        try:
            svc.start()
            s.wait_services()
            c = s.client("svc6", host="::1")
            assert any(" 311 svc6 NickServ " in l for l in c.say("WHOIS NickServ", 0.5))
            assert "inbound link connection accepted from 0::1" in s.output()
        finally:
            svc.stop()
