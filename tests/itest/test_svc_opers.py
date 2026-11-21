"""[[opers]] in services.toml: an account's logged-in users become IRC operators (SVSOPER) on whichever server they are on;
the certificate condition, revocation on logout, and add/remove by /REHASH without anyone reconnecting."""
import hashlib, os, socket, ssl, subprocess, tempfile, time
from harness import Server, Client
from test_accounts import register
from test_accounts2 import ns
from test_conn import make_cert

BOSS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
ACC = {"accounts": {"enabled": True, "store_file": "acc.json"}}
KILLER = '[[opers]]\naccount = "gera"\npassword_only = true\nprivileges = ["kill"]\n'


def boss(s):
    c = s.client("boss")
    c.say("OPER boss bosspw", 0.6)
    return c


def is_oper(c, wait=0.0):
    """Is `c` an IRC operator now? Asks the server for its user modes (a 381 or MODE line may have been read already)."""
    time.sleep(wait)
    return any(__import__("re").search(r" 221 \S+ :\+\S*o", l) for l in c.say(f"MODE {c.nick}", 0.4))


def rehash(s, b):
    b.say("REHASH", 1.0)
    time.sleep(1.5)  # the hub tells services, which reloads services.toml and says SVSOPER again


def test_logging_in_makes_an_oper_with_exactly_the_named_privileges():
    s = Server(cfg=dict(BOSS, **ACC))
    s.services_tail = KILLER
    with s:
        c = register(s, "gera1", "gera", "password1")  # REGISTER logs in, so the account's oper status follows
        assert is_oper(c, 0.5), ("registered and logged in as the listed account", s.services.output()[-500:])
        victim = s.client("victim")
        assert not any(" 481 " in l for l in c.say("KILL victim :bye", 0.6)), "kill was granted"
        assert victim.saw(r"KILL|ERROR|Killed", 1.0)
        assert any(" 481 " in l for l in c.say("SHUN *@192.0.2.1 10m x", 0.6)), "kline was not"
        # a second login by IDENTIFY, on another connection
        d = s.client("gera2")
        ns(d, "IDENTIFY gera password1", 1.0)
        assert is_oper(d), "IDENTIFY makes an oper too"
        # somebody else's account gets nothing
        e = register(s, "plain", "plain", "password1")
        assert not is_oper(e, 0.3)
        # logging out takes it back
        ns(c, "LOGOUT", 1.0)
        assert not is_oper(c), "-o after LOGOUT"


def test_the_certificate_must_match_unless_password_only():
    d = tempfile.mkdtemp(prefix="itest-opercert-")
    scrt, skey = make_cert(d)
    sub = os.path.join(d, "good"); os.mkdir(sub)
    gcrt, gkey = make_cert(sub)
    sub2 = os.path.join(d, "other"); os.mkdir(sub2)
    ocrt, okey = make_cert(sub2)
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(gcrt).read())).hexdigest()
    s = Server(cfg=dict(BOSS, tls={"enabled": True, "port": 0, "cert_file": scrt, "key_file": skey, "request_client_cert": True}, **ACC))
    s.cfg["tls"]["port"] = s.tls_port
    s.services_tail = f'[[opers]]\naccount = "gera"\ncertfp = "{fp}"\nprivileges = ["all"]\n'

    def tls_client(nick, crt, key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(crt, key)
        raw = socket.create_connection(("127.0.0.1", s.tls_port), timeout=3)
        return Client(0, nick, sock=ctx.wrap_socket(raw, server_hostname="localhost"))

    with s:
        reg = register(s, "reg", "gera", "password1")
        assert not is_oper(reg, 0.3), "right account and password, but no certificate: no oper"
        ns(reg, "LOGOUT", 0.8)
        wrong = tls_client("wrong", ocrt, okey)
        ns(wrong, "IDENTIFY gera password1", 1.0)
        assert not is_oper(wrong), "another certificate: no oper"
        right = tls_client("right", gcrt, gkey)
        ns(right, "IDENTIFY gera password1", 1.0)
        assert is_oper(right), ("the matching certificate: oper", s.services.output()[-600:])
        ns(right, "LOGOUT", 1.0)
        assert not is_oper(right), "and not once logged out"


def test_rehash_adds_and_removes_opers_without_anyone_reconnecting():
    s = Server(cfg=dict(BOSS, **ACC))
    with s:
        b = boss(s)
        c = register(s, "gera1", "gera", "password1")
        assert not is_oper(c, 0.3), "no entry yet"
        s.services.write(KILLER)
        rehash(s, b)
        assert is_oper(c), "the entry was added: a user already logged in becomes an oper"
        s.services.write('[[opers]]\naccount = "gera"\npassword_only = true\nprivileges = ["nonsense"]\n')
        rehash(s, b)
        assert "rehash failed" in s.services.output(), s.services.output()[-500:]
        s.client("victim")
        assert not any(" 481 " in l for l in c.say("KILL victim :x", 0.6)), "a refused file leaves the old list"
        s.services.write("")
        rehash(s, b)
        assert not is_oper(c), ("the entry was removed: oper status is taken back", s.services.output()[-900:])


def test_a_server_can_refuse_grants_and_accept_them_after_a_rehash():
    s = Server(cfg=dict(BOSS, security={"accept_services_opers": False}, **ACC))
    s.services_tail = KILLER
    with s:
        c = register(s, "gera1", "gera", "password1")
        assert not is_oper(c, 0.3), "this server ignores grants from services"
        s.cfg["security"]["accept_services_opers"] = True
        s.reload()
        time.sleep(1.5)
        assert is_oper(c), "taken after the rehash: services says it again"
        s.cfg["security"]["accept_services_opers"] = False
        s.reload()
        time.sleep(0.5)
        assert not is_oper(c), "and taken back when the server stops accepting them"


def test_always_on_resume_tells_services_the_new_certificate():
    """An always-on session keeps its uid when a new connection resumes it, so services must hear that connection's
    certificate: first resumed WITH one (CERT ADD works, the certfp-bound oper grant arrives), then WITHOUT one (the grant
    goes -- it must never stay on a connection that didn't show the certificate)."""
    import base64
    d = tempfile.mkdtemp(prefix="itest-aocert-")
    scrt, skey = make_cert(d)
    sub = os.path.join(d, "good"); os.mkdir(sub)
    gcrt, gkey = make_cert(sub)
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(gcrt).read())).hexdigest()
    s = Server(cfg=dict(BOSS, tls={"enabled": True, "port": 0, "cert_file": scrt, "key_file": skey, "request_client_cert": True}, **ACC))
    s.cfg["tls"]["port"] = s.tls_port
    s.services_tail = f'[[opers]]\naccount = "gera"\ncertfp = "{fp}"\nprivileges = ["all"]\n'

    def resume(crt=None, key=None):
        """A new connection that SASLs in as gera (and so takes the detached session over), with or without the certificate."""
        sock = None
        if crt:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.load_cert_chain(crt, key)
            sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", s.tls_port), timeout=3), server_hostname="localhost")
        c = Client(0 if sock else s.port, "gera", register=False, sock=sock,  # another nick: the session's own comes back with it
                   extra=["CAP LS 302", "CAP REQ :sasl", "NICK resumer", "USER gera 0 * :gera"])
        c.send("AUTHENTICATE PLAIN")
        c.expect(r"AUTHENTICATE \+")
        c.send("AUTHENTICATE " + base64.b64encode(b"\0gera\0password1").decode())
        c.expect(r" 903 ", 3)
        c.send("CAP END")
        c.expect(r"Resumed your always-on session", 5)
        time.sleep(1.0)  # services hear the new certificate and settle the oper grant
        return c

    with s:
        first = register(s, "gera", "gera", "password1")  # plain connection, no certificate
        assert any("Always-on enabled" in l for l in ns(first, "SET ALWAYS-ON ON"))
        assert not is_oper(first, 0.3)
        first.close()
        time.sleep(0.8)
        withcert = resume(gcrt, gkey)
        got = " ".join(ns(withcert, "CERT ADD", 1.0))
        assert fp in got and "bound" in got, ("services see the resuming connection's certificate", got)
        assert is_oper(withcert), "the certfp-bound grant follows the certificate"
        withcert.close()
        time.sleep(0.8)
        nocert = resume()
        assert not is_oper(nocert), "resumed without the certificate: the grant must go"
