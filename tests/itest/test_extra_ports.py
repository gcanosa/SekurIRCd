"""[server] extra_ports / [tls] extra_ports: more client listeners next to the main ones; rehash opens and closes them."""
import socket, ssl, subprocess, tempfile
from harness import IRCD, Server, Client, free_port
from test_conn import make_cert

OPER = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def registers(port, nick, tls=False, host="127.0.0.1"):
    """A full registration on `port` (True) or a refused/dead connection (False)."""
    try:
        sock = socket.create_connection((host, port), timeout=2)
    except OSError:
        return False
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname="localhost")
        sock.sendall(f"NICK {nick}\r\nUSER {nick} 0 * :x\r\n".encode())
        sock.settimeout(3)
        buf = b""
        while b" 001 " not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return False
            buf += chunk
        return True
    except (OSError, ssl.SSLError):
        return False
    finally:
        sock.close()


def refused(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return False
    except OSError:
        return True


def check(cfg):
    """`sekurircd --check` on a config: (exit status, its output)."""
    s = Server(cfg=cfg)
    s.write_config()
    r = subprocess.run([IRCD, "--check", "-c", s.cfg_path], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def test_extra_plain_ports_accept_clients():
    p1, p2 = free_port(), free_port()
    with Server(cfg={"server": {"extra_ports": [p1, p2]}}) as s:
        assert registers(s.port, "main") and registers(p1, "one") and registers(p2, "two")


def test_extra_tls_ports_accept_tls_clients_and_sts_names_the_main_one():
    d = tempfile.mkdtemp(prefix="itest-cert-")
    crt, key = make_cert(d)
    s = Server(cfg={"tls": {"enabled": True, "cert_file": crt, "key_file": key, "sts_duration": 600}})
    x1, x2 = free_port(), free_port()
    s.cfg["tls"].update(port=s.tls_port, extra_ports=[x1, x2])
    with s:
        assert registers(s.tls_port, "tmain", tls=True) and registers(x1, "tx1", tls=True) and registers(x2, "tx2", tls=True)
        assert not registers(x1, "plain-on-tls")             # a TLS port is not a plaintext one
        c = Client(s.port, "sts", register=False)
        c.send("CAP LS 302")
        caps = " ".join(c.drain(0.5))
        assert f"sts=port={s.tls_port}," in caps, caps       # the policy keeps pointing at the main TLS port


def test_rehash_opens_closes_and_keeps_extra_ports():
    a, b, c = free_port(), free_port(), free_port()
    with Server(cfg={"server": {"extra_ports": [a, b]}}) as s:
        keep = Client(a, "keeper")                           # connected through a port that stays
        gone = Client(b, "goner")                            # ... and through one that is dropped
        s.cfg["server"]["extra_ports"] = [a, c]
        s.reload()
        assert registers(a, "still-a") and registers(c, "new-c")
        assert refused(b), "a port removed from extra_ports must stop listening"
        for who in (keep, gone):                             # a rehash never drops connections, even ones accepted on a closed port
            assert any("PONG" in l for l in who.say("PING :still-here")), who
        s.cfg["server"].pop("extra_ports")
        s.reload()
        assert refused(a) and refused(c) and registers(s.port, "main-only")


def test_a_port_that_will_not_bind_is_skipped_not_fatal():
    busy = socket.socket()
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    taken, free = busy.getsockname()[1], free_port()
    try:
        with Server(cfg={"server": {"extra_ports": [taken, free]}}) as s:
            assert registers(s.port, "main") and registers(free, "other"), "the others still open"
            assert "could not bind extra client port" in open(s.dir + "/logs/sekurircd.log").read()
    finally:
        busy.close()


def test_stats_p_lists_the_extra_ports():
    p = free_port()
    with Server(cfg={"server": {"extra_ports": [p]}, **OPER}) as s:
        c = s.client("op")
        c.say("OPER boss bosspw", 0.5)
        rows = c.say("STATS P", 0.6)
        assert any(f" P {p} plain " in l for l in rows), rows


def test_bad_extra_ports_are_refused_with_a_reason():
    p = free_port()
    main = free_port()
    cases = [
        ({"server": {"port": main, "extra_ports": [main]}}, "already server.port"),
        ({"server": {"extra_ports": [p, p]}}, "twice"),
        ({"server": {"extra_ports": [70000]}}, "not a port"),
        ({"server": {"extra_ports": [0]}}, "not a port"),
        ({"server": {"extra_ports": "6668"}}, "array of port numbers"),
        ({"server": {"extra_ports": list(range(2000, 2017))}}, "too many entries"),
        ({"server": {"extra_ports": [6697]}, "tls": {"enabled": True, "port": 6697, "cert_file": "c", "key_file": "k"}}, "already tls.port"),
        ({"server": {"extra_ports": [p]}, "tls": {"enabled": True, "port": 6697, "extra_ports": [p], "cert_file": "c", "key_file": "k"}}, "both server.extra_ports and tls.extra_ports"),
    ]
    for cfg, why in cases:
        rc, out = check(cfg)
        assert rc != 0 and why in out, (cfg, rc, out)
    rc, out = check({"server": {"extra_ports": [p]}, "tls": {"enabled": False, "extra_ports": [p]}})
    assert rc == 0, out                                      # tls.extra_ports is ignored while TLS is off, so no clash


def test_extra_ports_get_ipv6_twins():
    p, q = free_port(), free_port()
    with Server(cfg={"server": {"ipv6": True, "bind6": "::1", "extra_ports": [p]}}) as s:
        assert registers(p, "v4", host="127.0.0.1") and registers(p, "v6", host="::1")
        s.cfg["server"]["extra_ports"] = [q]
        s.reload()
        assert registers(q, "v4b", host="127.0.0.1") and registers(q, "v6b", host="::1")
        assert refused(p) and not registers(p, "gone6", host="::1"), "both families closed with the port"
