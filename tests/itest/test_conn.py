import base64, os, socket, ssl, subprocess, time
from harness import Server, Client, ws_frame, ws_parse


def test_webirc_requires_host_and_password():
    cfg = {"webirc": [{"name": "gw", "password": "gwpass", "hosts": ["127.0.0.1"]}]}
    with Server(cfg=cfg) as s:
        c = s.client("w1", register=False, extra=["WEBIRC gwpass kiwi host.example.org 198.51.100.7"])
        c.send("NICK w1")
        c.send("USER w1 0 * :x")
        c.expect(r" 001 ")
        r = c.say("WHOIS w1")
        assert any(" 311 w1 w1 w1 198.51.100.7 " in l or "host.example.org" in l for l in r), r
        bad = s.client("w2", register=False, extra=["WEBIRC wrong kiwi h.example.org 198.51.100.8"])
        bad.send("NICK w2")
        bad.send("USER w2 0 * :x")
        assert not bad.saw(r" 001 ", 0.8)


def test_proxy_protocol_v1_and_enforcement():
    with Server(cfg={"server": {"proxy_protocol_hosts": ["127.0.0.1"]}}) as s:
        c = s.client("px", register=False, extra=["PROXY TCP4 198.51.100.9 10.0.0.1 40000 6667"])
        c.send("NICK px")
        c.send("USER px 0 * :x")
        c.expect(r" 001 ")
        assert any("198.51.100.9" in l for l in c.say("WHOIS px"))
        d = s.client("np", register=False)
        d.send("NICK np")
        d.send("USER np 0 * :x")
        assert not d.saw(r" 001 ", 0.8), "a proxy peer without a PROXY line must be dropped"


def ws_connect(port, headers="", sock=None):
    s = sock or socket.create_connection(("127.0.0.1", port), timeout=3)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(f"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
              f"Sec-WebSocket-Version: 13\r\n{headers}\r\n".encode())
    return s


def ws_read(s, wait=0.8):
    s.settimeout(0.2)
    buf, end = b"", time.time() + wait
    while time.time() < end:
        try:
            d = s.recv(65536)
            if not d:
                break
            buf += d
        except (socket.timeout, ssl.SSLWantReadError):
            pass
    return buf


def ws_session(sock, nick):
    buf = ws_read(sock)
    assert buf.startswith(b"HTTP/1.1 101"), buf[:80]
    sock.sendall(ws_frame(f"NICK {nick}") + ws_frame(f"USER {nick} 0 * :ws user"))
    frames, rest = ws_parse(buf[buf.index(b"\r\n\r\n") + 4:] + ws_read(sock, 1.2))
    return frames


def test_websocket_plain_and_forwarded_ip():
    cfg = {"websocket": {"enabled": True, "port": 0, "trusted_proxies": ["127.0.0.1"]}}
    s = Server(cfg=cfg)
    s.cfg["websocket"]["port"] = s.ws_port
    with s:
        sock = ws_connect(s.ws_port, "X-Forwarded-For: 203.0.113.77\r\n")
        frames = ws_session(sock, "wsu")
        assert any(" 001 " in t and "203.0.113.77" in t for o, t in frames), frames[:3]
        sock.sendall(ws_frame("PING :hi", 9))
        out, _ = ws_parse(ws_read(sock, 0.6))
        assert any(o == 10 for o, t in out), "ping frame must be answered with a pong frame"
        bad = socket.create_connection(("127.0.0.1", s.ws_port), timeout=2)
        bad.sendall(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
        assert ws_read(bad, 0.6).startswith(b"HTTP/1.1 400")


def make_cert(d):
    crt, key = os.path.join(d, "t.crt"), os.path.join(d, "t.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "1",
                    "-subj", "/CN=localhost"], check=True, capture_output=True)
    return crt, key


def test_websocket_over_tls_wss():
    import tempfile
    d = tempfile.mkdtemp(prefix="itest-cert-")
    crt, key = make_cert(d)
    s = Server(cfg={"tls": {"enabled": True, "port": 0, "cert_file": crt, "key_file": key},
                    "websocket": {"enabled": True, "port": 0, "tls": True}})
    s.cfg["tls"]["port"] = s.tls_port
    s.cfg["websocket"]["port"] = s.ws_port
    with s:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", s.ws_port), timeout=3)
        tls = ctx.wrap_socket(raw, server_hostname="localhost")
        ws_connect(0, sock=tls)
        frames = ws_session(tls, "wssu")
        assert any(" 001 " in t for o, t in frames), frames[:3]
        tls.sendall(ws_frame("MODE wssu"))
        out, _ = ws_parse(ws_read(tls, 0.8))
        assert any(" 221 " in t and "Z" in t for o, t in out), out  # +Z = secure connection


def test_connection_class_limits_clients():
    with Server(cfg={"classes": [{"name": "local", "hosts": ["127.0.0.*"], "max_clients": 2}]}) as s:
        socks = []
        for _ in range(4):
            sk = socket.create_connection(("127.0.0.1", s.port), timeout=2)
            sk.settimeout(0.6)
            socks.append(sk)
            time.sleep(0.15)
        verdicts = []
        for sk in socks:
            try:
                verdicts.append(b"ERROR" in sk.recv(400))
            except socket.timeout:
                verdicts.append(False)
        assert verdicts == [False, False, True, True], verdicts
        socks[0].close()
        time.sleep(0.5)
        again = socket.create_connection(("127.0.0.1", s.port), timeout=2)
        again.settimeout(0.6)
        assert b"ERROR" not in again.recv(400)


def test_link_allowed_ips_rejects_other_sources():
    cfg = {"links": {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": 0},
           "links.peers": []}
    s = Server(cfg={"links": {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": 0}})
    s.cfg["links"]["port"] = s.link_port
    s.cfg["links.peers"] = [{"name": "leaf1", "password": "pw", "allowed_ips": ["203.0.113.5"]}]
    with s:
        sk = socket.create_connection(("127.0.0.1", s.link_port), timeout=2)
        sk.settimeout(1.0)
        sk.sendall(b"PASS pw\r\nSERVER leaf1 1 :x\r\n")
        try:
            data = sk.recv(200)
        except socket.timeout:
            data = b"timeout"
        except ConnectionResetError:
            data = b""  # closed with our unread bytes still queued -> RST: also a rejection
        assert data in (b"", b"timeout") and b"SERVER" not in data, data
