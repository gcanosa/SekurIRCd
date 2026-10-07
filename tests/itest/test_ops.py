import socket, ssl, subprocess, tempfile, os, time
from harness import Server, free_port
from test_conn import make_cert


def can_connect(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


def test_rehash_rebinds_client_port_and_opens_websocket():
    with Server() as s:
        old = s.port
        new = free_port()
        ws = free_port()
        s.cfg["server"]["port"] = new
        s.cfg["websocket"] = {"enabled": True, "port": ws}
        c = s.client("stay")  # connected before the rehash: must survive it
        s.reload()
        assert can_connect(new), "new client port must be listening after rehash"
        assert not can_connect(old), "old client port must be closed"
        assert can_connect(ws), "websocket listener enabled by rehash"
        assert any("PONG" in l for l in c.say("PING x")), "existing connection survives the rebind"
        s.cfg["websocket"]["enabled"] = False
        s.reload()
        assert not can_connect(ws), "websocket listener closed when disabled"


def cert_fp(port):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as t:
            return t.getpeercert(binary_form=True)


def test_rehash_reloads_tls_certificate():
    d1, d2 = tempfile.mkdtemp(prefix="itest-c1-"), tempfile.mkdtemp(prefix="itest-c2-")
    crt1, key1 = make_cert(d1)
    crt2, key2 = make_cert(d2)
    s = Server(cfg={"tls": {"enabled": True, "port": 0, "cert_file": crt1, "key_file": key1}})
    s.cfg["tls"]["port"] = s.tls_port
    with s:
        before = cert_fp(s.tls_port)
        s.cfg["tls"]["cert_file"], s.cfg["tls"]["key_file"] = crt2, key2
        s.reload()
        after = cert_fp(s.tls_port)
        assert before != after, "a rehash must pick up the renewed certificate"


def test_rehash_bad_port_keeps_old_listener():
    with Server() as s:
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy = blocker.getsockname()[1]
        old = s.port
        s.cfg["server"]["port"] = busy  # already taken by someone else
        s.reload()
        assert can_connect(old), "failed rebind must leave the old listener alone"
        blocker.close()
