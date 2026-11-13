"""Always-on (NickServ SET ALWAYS-ON): the nick stays on the network after its connection drops, and a SASL login to
the same account takes the session over -- nobody else sees a QUIT or JOIN (on another server: a QUIT and JOIN)."""
import base64
import time
from harness import Server, Client
from test_accounts2 import ns, ACC

OPS = {**ACC, "operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def sasl_connect(s, nick, account, pw, caps=(), wait=1.5):
    """A new connection that SASLs in and finishes registering; returns it with its welcome burst still buffered."""
    c = Client(s.port, nick, register=False, extra=["CAP LS 302", "CAP REQ :" + " ".join(("sasl",) + tuple(caps)),
                                                    f"NICK {nick}", f"USER {nick} 0 * :new realname"])
    c.send("AUTHENTICATE PLAIN")
    c.expect(r"AUTHENTICATE \+")
    c.send("AUTHENTICATE " + base64.b64encode(f"\0{account}\0{pw}".encode()).decode())
    c.expect(r" 903 ", 3)
    c.send("CAP END")
    c.lines = c.drain(wait)  # the welcome burst stays readable through c.drain()
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


def test_survives_ircd_restart():
    """Detached and still-connected always-on users both come back (detached) after a restart, resumable as before."""
    with Server(cfg=ACC) as s:
        a, _ = setup(s, "aorst", "aorstacct", watcher=False)
        a.say("MODE #ao +v aorst", 0.3)  # a rank that has to come back too (it opped itself by creating #ao)
        a.close()
        time.sleep(0.5)
        live, _ = setup(s, "aolive2", "aolive2acct", watcher=False)  # still connected when the server stops
        s.restart()
        b = s.client("aorstw")
        names = " ".join(l for l in b.say("NAMES #ao", 0.6) if " 353 " in l)
        assert "@+aorst" in names or "@aorst" in names, "the detached user is back in #ao with its op: %r" % names
        assert "aolive2" in names, "the connected one is kept too: %r" % names
        assert any(" 301 " in l and "Detached" in l for l in b.say("WHOIS aolive2", 0.6)), "and is now detached"
        c = sasl_connect(s, "aorstnew", "aorstacct", "password1")
        burst = c.drain(1.0) + c.lines
        assert any(" 001 aorst " in l for l in burst), "resumed under the kept nick after the restart: %r" % burst[:3]
        assert any("Resumed your always-on session (1 channel)" in l for l in burst), burst


def test_channel_state_survives_restart():
    """An unregistered channel an always-on user is in comes back with its modes, key, topic and bans."""
    with Server(cfg=ACC) as s:
        a, _ = setup(s, "aochan", "aochanacct", watcher=False)
        a.say("MODE #ao +mk sekrit", 0.3)
        a.say("MODE #ao +b bad!*@*", 0.3)
        a.say("TOPIC #ao :kept across restarts", 0.3)
        a.close()
        time.sleep(0.5)
        s.restart()
        b = s.client("aochanw")
        modes = " ".join(l for l in b.say("MODE #ao", 0.6) if " 324 " in l)
        assert "m" in modes.split()[4] and "k" in modes.split()[4], modes
        assert any("bad!*@*" in l for l in b.say("MODE #ao b", 0.6) if " 367 " in l), "the ban is back"
        assert any(" 475 " in l for l in b.say("JOIN #ao", 0.6)), "and so is the key"
        assert any("kept across restarts" in l for l in b.say("JOIN #ao sekrit", 0.6) if " 332 " in l), "and the topic"


def test_resume_from_another_server():
    """A session detached on server a, resumed by logging in on server b: same nick, same channels, same rank."""
    from harness import Network
    from test_netsync import OPERS
    n = Network(cfg={**OPERS, "accounts": {"enabled": True, "store_file": "acc.json"}})
    n.add("a")
    n.add("b", parent="a")
    n.start()
    try:
        a = n.client("a", "aomove")
        ns(a, "REGISTER movepass1")
        assert any("Always-on enabled" in l for l in ns(a, "SET ALWAYS-ON ON"))
        a.say("JOIN #aomove", 0.5)  # created it: opped
        far = n.client("b", "aomovew")
        far.say("JOIN #aomove", 1.0)
        a.close()
        time.sleep(1.0)
        far.drain(0.5)
        c = sasl_connect(n.servers["b"], "aomovenew", "aomove", "movepass1", wait=4)  # waits for server a to drop it
        burst = c.drain(1.5) + c.lines
        assert any(" 001 aomove " in l for l in burst), "registered under the kept nick on the other server: %r" % burst[:3]
        assert any(l.startswith(":aomove!") and " JOIN #aomove" in l for l in burst), burst
        assert any("Resumed your always-on session (1 channel)" in l for l in burst), burst
        seen = far.drain(1.0)
        assert any("QUIT :Session resumed on" in l for l in seen), seen
        names = " ".join(l for l in far.say("NAMES #aomove", 0.8) if " 353 " in l)
        assert "@aomove" in names, "back with its op: %r" % names
        c.say("PRIVMSG #aomove :moved", 0.3)
        assert far.saw(r":aomove!\S+ PRIVMSG #aomove :moved", 3)
        aw = n.client("a", "aomovea")
        assert any(" 311 aomovea aomove " in l for l in aw.say("WHOIS aomove", 1.0)), "server a sees the new session"
    finally:
        n.stop()


def test_expiry_counts_through_restarts():
    """The detach time is saved, not reset by a restart: a session past its expiry doesn't come back."""
    import json, os
    with Server(cfg={"accounts": {**ACC["accounts"], "always_on_expire_days": 1}}) as s:
        a, _ = setup(s, "aoold", "aooldacct", watcher=False)
        a.close()
        time.sleep(0.5)
        s.proc.terminate()
        s.proc.wait(8)
        path = os.path.join(s.dir, "alwayson.json")
        saved = json.load(open(path))
        users = saved["users"]
        assert [e["nick"] for e in users] == ["aoold"] and users[0]["always_on"] == 86400, saved
        users[0]["detached_at"] -= 86400 + 60  # pretend it detached over a day ago
        json.dump(saved, open(path, "w"))
        s.start()
        b = s.client("aooldw")
        assert not any(" 311 " in l for l in b.say("WHOIS aoold", 0.6)), "expired while down: not restored"
