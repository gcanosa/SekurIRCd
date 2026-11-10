"""Always-on (NickServ SET ALWAYS-ON): the nick stays on the network after its connection drops, and a SASL login to
the same account takes the session over -- nobody else sees a QUIT or JOIN."""
import base64
import time
from harness import Server, Client
from test_accounts2 import ns, ACC

OPS = {**ACC, "operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def sasl_connect(s, nick, account, pw, caps=()):
    """A new connection that SASLs in and finishes registering; returns it with its welcome burst still buffered."""
    c = Client(s.port, nick, register=False, extra=["CAP LS 302", "CAP REQ :" + " ".join(("sasl",) + tuple(caps)),
                                                    f"NICK {nick}", f"USER {nick} 0 * :new realname"])
    c.send("AUTHENTICATE PLAIN")
    c.expect(r"AUTHENTICATE \+")
    c.send("AUTHENTICATE " + base64.b64encode(f"\0{account}\0{pw}".encode()).decode())
    c.expect(r" 903 ", 3)
    c.send("CAP END")
    c.lines = c.drain(1.5)  # the welcome burst stays readable through c.drain()
    assert any(" 001 " in l for l in c.lines), c.lines[-5:]
    return c


def register(s, nick, account, pw):
    c = s.client(nick)
    c.send(f"REGISTER {account} {pw}")
    c.expect(r" 900 ", 10)  # logged in (a fixed sleep is too short under ASan)
    c.drain(0.3)
    return c


def setup(s, nick="aonick", acct="aoacct", watcher=True):
    a = register(s, nick, acct, "password1")
    got = ns(a, "SET ALWAYS-ON ON")
    assert any("Always-on enabled" in l for l in got), got
    a.say("JOIN #ao", 0.5)
    if not watcher:
        return a, None
    b = s.client("aowatch", caps=["away-notify"])
    b.say("JOIN #ao", 0.5)
    return a, b


def test_detach_keeps_nick_and_resume_takes_it_over():
    with Server(cfg=ACC) as s:
        a, b = setup(s)
        a.close()  # the connection just drops
        seen = b.drain(1.5)
        assert not any(" QUIT" in l for l in seen), "no QUIT for a detached always-on user: %r" % seen
        assert any("AWAY :Detached" in l and l.startswith(":aonick!") for l in seen), "away-notify says it detached: %r" % seen
        names = " ".join(l for l in b.say("NAMES #ao", 0.5) if " 353 " in l)
        assert "aonick" in names, names
        got = b.say("PRIVMSG aonick :are you there", 0.5)
        assert any(" 301 " in l and "Detached" in l for l in got), "a message gets the away reply: %r" % got
        assert any(" 433 " in l for l in s.client("aothief", register=False).say("NICK aonick\r\nUSER x 0 * :x", 0.8)), \
            "the nick stays taken"

        c = sasl_connect(s, "aonew", "aoacct", "password1")
        burst = c.drain(1.5)
        assert any(" 001 aonick " in l for l in burst), "welcomed under the kept nick: %r" % burst[:3]
        assert any(l.startswith(":aonick!") and " JOIN #ao" in l for l in burst), "its channels are replayed: %r" % burst
        assert any(" 353 " in l and "#ao" in l for l in burst), "with NAMES"
        assert any("Resumed your always-on session (1 channel)" in l for l in burst), burst
        seen = b.drain(1.0)
        assert not any(" JOIN " in l or " QUIT" in l for l in seen), "the resume is silent for others: %r" % seen
        assert any("AWAY" in l and l.startswith(":aonick!") for l in seen), "only the away status clears: %r" % seen
        c.say("PRIVMSG #ao :back again", 0.3)
        assert b.saw(r":aonick!\S+ PRIVMSG #ao :back again", 2), "the resumed session talks as aonick"
        whois = b.say("WHOIS aonick", 0.6)
        assert not any(" 301 " in l for l in whois), "no longer away: %r" % whois


def test_new_login_takes_over_a_live_session():
    with Server(cfg=ACC) as s:
        a, b = setup(s, "aolive", "aoliveacct")
        c = sasl_connect(s, "aophone", "aoliveacct", "password1")
        assert a.saw(r"ERROR :Closing Link: Session taken over", 3), "the old connection is told and closed"
        burst = c.drain(1.0)
        assert any(" 001 aolive " in l for l in burst), burst[:3]
        seen = b.drain(1.0)
        assert not any(" QUIT" in l or " JOIN " in l or "AWAY" in l for l in seen), "nothing visible to others: %r" % seen
        c.say("PRIVMSG #ao :hi from the phone", 0.3)
        assert b.saw(r":aolive!\S+ PRIVMSG #ao :hi from the phone", 2)


def test_off_kill_and_logout_end_it():
    with Server(cfg=OPS) as s:
        a, b = setup(s, "aooff", "aooffacct")
        got = ns(a, "SET ALWAYS-ON OFF")
        assert any("Always-on disabled" in l for l in got), got
        a.close()
        assert b.saw(r":aooff!\S+ QUIT", 3), "off = a normal quit"

        a, _ = setup(s, "aokill", "aokillacct", False)
        a.close()
        time.sleep(0.5)
        b.drain(0.3)
        o = s.client("aoop")
        o.say("OPER boss bosspw", 0.5)
        o.say("KILL aokill :bye", 0.5)
        assert b.saw(r":aokill!\S+ QUIT", 3), "a KILL removes a detached client"
        assert not any(" 311 " in l for l in o.say("WHOIS aokill", 0.6)), "gone"

        # turning it off from another session ends a detached one
        a, _ = setup(s, "aoend", "aoendacct", False)
        a.close()
        time.sleep(0.5)
        b.drain(0.3)
        x = s.client("aoother")
        ns(x, "IDENTIFY aoendacct password1")
        ns(x, "SET ALWAYS-ON OFF")
        assert b.saw(r":aoend!\S+ QUIT :Always-on disabled", 3), "SET ALWAYS-ON OFF from elsewhere ends the kept session"


def test_admin_can_disable_it():
    with Server(cfg={"accounts": {**ACC["accounts"], "always_on": False}}) as s:
        a = register(s, "aonope", "aonopeacct", "password1")
        got = ns(a, "SET ALWAYS-ON ON")
        assert any("disabled on this network" in l for l in got), got
        b = s.client("aonopew")
        a.say("JOIN #ao", 0.3)
        b.say("JOIN #ao", 0.5)
        a.close()
        assert b.saw(r":aonope!\S+ QUIT", 3)


def test_detached_user_stays_on_the_rest_of_the_network():
    from harness import Network
    from test_netsync import OPERS
    n = Network(cfg={**OPERS, "accounts": {"enabled": True, "store_file": "acc.json"}})
    n.add("a")
    n.add("b", parent="a")
    n.start()
    try:
        a = n.client("a", "aonet")
        ns(a, "REGISTER netpass1")
        assert any("Always-on enabled" in l for l in ns(a, "SET ALWAYS-ON ON"))
        a.say("JOIN #aonet", 0.5)
        far = n.client("b", "aonetfar")
        far.say("JOIN #aonet", 1.0)
        a.close()
        seen = far.drain(2.0)
        assert not any(" QUIT" in l for l in seen), "the other server sees no QUIT: %r" % seen
        assert "aonet" in " ".join(l for l in far.say("NAMES #aonet", 0.8) if " 353 " in l)
        c = sasl_connect(n.servers["a"], "aonetnew", "aonet", "netpass1")
        assert any(" 001 aonet " in l for l in c.drain(1.0))
        c.say("PRIVMSG #aonet :resumed", 0.3)
        assert far.saw(r":aonet!\S+ PRIVMSG #aonet :resumed", 3), "the resumed session reaches the other server under the same uid"
        assert not any(" JOIN " in l or " QUIT" in l for l in far.drain(0.5))
    finally:
        n.stop()
