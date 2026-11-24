"""DEFCON: an oper tightens one server against an attack; ELINE'd addresses are never held to it; a duration puts it back."""
import socket, time
from harness import Server, Client

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def oper(srv, nick="boss"):
    c = Client(srv.port, nick)
    c.send("OPER boss bosspw")
    c.expect(r" 381 ")
    return c


def raw_connect(port, nick):
    """Connect, read what the server volunteers (a refusal at accept time arrives first), else register by hand; everything it
    sent until it settled or closed."""
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.settimeout(0.3)
    out = b""

    def pull(seconds):
        nonlocal out
        end = time.time() + seconds
        while time.time() < end:
            try:
                d = s.recv(4096)
                if not d:
                    return False
                out += d
            except socket.timeout:
                pass
            except ConnectionResetError:
                return False
        return True

    if pull(0.4):
        try:
            s.sendall(f"NICK {nick}\r\nUSER {nick} 0 * :{nick}\r\n".encode())
        except OSError:
            pass
        pull(1.5)
    s.close()
    return out.decode(errors="replace")


def test_only_opers_may_use_it_and_it_reports_the_level():
    with Server(cfg=OPERS) as s:
        c = s.client("c")
        assert any(" 481 " in l for l in c.say("DEFCON 3", 0.4))
        o = oper(s)
        assert any("DEFCON 5 (normal)" in l for l in o.say("DEFCON", 0.4))
        assert any("DEFCON 3" in l for l in o.say("DEFCON 3 10m", 0.4))
        out = " ".join(o.say("DEFCON", 0.4))
        assert "DEFCON 3" in out and "until" in out, out
        assert any("Usage" in l for l in o.say("DEFCON 9", 0.4))


def test_level_4_allows_two_connections_per_address():
    with Server(cfg=dict(OPERS, security={"max_connections_per_ip": 20})) as s:
        o = oper(s)
        o.say("DEFCON 4", 0.4)
        a = s.client("a")  # the oper is the first, a the second (kept: a dropped client would close its socket)
        extra = raw_connect(s.port, "b")
        assert "Too many connections from your host" in extra, extra
        o.say("DEFCON 5", 0.4)
        assert " 001 " in raw_connect(s.port, "c")
        assert a.say("PING keep", 0.3)


def test_level_3_wants_a_login_and_level_2_wants_tls_and_level_1_nothing():
    with Server(cfg=OPERS) as s:
        o = oper(s)
        o.say("DEFCON 3", 0.4)
        out = raw_connect(s.port, "x1")
        assert "DEFCON 3" in out and " 001 " not in out, out
        o.say("DEFCON 2", 0.4)
        out = raw_connect(s.port, "x2")
        assert "only TLS connections" in out and " 001 " not in out, out
        o.say("DEFCON 1", 0.4)
        out = raw_connect(s.port, "x3")
        assert "DEFCON 1" in out and " 001 " not in out, out
        o.say("DEFCON 5", 0.4)
        assert " 001 " in raw_connect(s.port, "x4"), "back to normal"


def test_an_eline_on_the_address_is_never_held_to_it():
    with Server(cfg=OPERS) as s:
        o = oper(s)
        o.say("ELINE 127.0.0.1 1h loopback", 0.4)
        o.say("DEFCON 1", 0.4)
        assert " 001 " in raw_connect(s.port, "x1"), "even a lockdown lets an ELINE'd address in"


def test_a_duration_puts_the_level_back_by_itself():
    with Server(cfg=OPERS) as s:
        o = oper(s)
        o.say("DEFCON 1 2s", 0.3)
        assert " 001 " not in raw_connect(s.port, "x1")
        time.sleep(2.2)
        assert " 001 " in raw_connect(s.port, "x2")
        assert any("DEFCON 5" in l for l in o.say("DEFCON", 0.4))
