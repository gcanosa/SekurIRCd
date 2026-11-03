import base64
import re
from harness import Server
from test_netsync import unlinked_pair, link_now

ACC = {"accounts": {"enabled": True, "store_file": "acc.json"}}


def b64(s):
    return base64.b64encode(s.encode() if isinstance(s, str) else s).decode()


def batch_lines(c, kind, timeout=3):
    """Lines of the next `kind` batch (the BATCH +/- lines themselves excluded)."""
    start = c.expect(r"BATCH \+(\S+) " + kind, timeout)
    ref = start.split("BATCH +", 1)[1].split()[0]
    out = []
    while True:
        l = c.expect(r".", timeout)
        if re.search(r"BATCH -" + re.escape(ref) + r"\b", l):
            return out
        out.append(l)


def test_utf8only_icon_and_clienttagdeny_tokens():
    cfg = {"server": {"icon": "https://img.test/net.png"}, "messages": {"client_tag_deny": "typing"}}
    with Server(cfg=cfg) as s:
        a = s.client("u8a")
        isup = " ".join(l for l in a.drain() if " 005 " in l)
        assert " UTF8ONLY" in isup and "draft/ICON=https://img.test/net.png" in isup and "CLIENTTAGDENY=typing" in isup, isup
        b = s.client("u8b")
        a.say("JOIN #u8"); b.say("JOIN #u8"); b.drain()
        a.sock.sendall(b"PRIVMSG #u8 :caf\xe9\r\n")
        assert a.saw(r"FAIL PRIVMSG INVALID_UTF8 :"), "latin1 is refused"
        assert not b.saw(r"PRIVMSG #u8", 0.4), "and never relayed"
        a.send("PRIVMSG #u8 :café ✓")
        assert b.saw(r"PRIVMSG #u8 :café ✓")


def test_utf8only_can_be_turned_off():
    with Server(cfg={"messages": {"utf8_only": False}}) as s:
        a = s.client("l1a")
        assert not any("UTF8ONLY" in l for l in a.drain() if " 005 " in l)
        b = s.client("l1b")
        a.say("JOIN #l1"); b.say("JOIN #l1"); b.drain()
        a.sock.sendall(b"PRIVMSG #l1 :caf\xe9\r\n")
        assert b.saw(r"PRIVMSG #l1 :caf")


def test_extended_isupport_before_registration():
    with Server() as s:
        c = s.client("eis", register=False, extra=["CAP LS 302", "CAP REQ :draft/extended-isupport batch"])
        c.expect(r"CAP \* ACK")
        c.send("ISUPPORT")
        lines = batch_lines(c, "draft/isupport")
        assert lines and all(re.match(r"^@batch=\S+ :irc\.test\.net 005 \* ", l) for l in lines), lines
        assert any("NETWORK=TestNet" in l for l in lines)
        # registering still works, and the welcome's 005 list is batched the same way
        c.send("CAP END"); c.send("NICK eis"); c.send("USER eis 0 * :x")
        assert any(" 005 eis " in l for l in batch_lines(c, "draft/isupport", 5))
        # without the cap, an unregistered ISUPPORT gets nothing
        p = s.client("nocap", register=False)
        p.send("ISUPPORT")
        assert not p.saw(r" 005 ", 0.5)


def test_clienttagdeny_and_channel_context():
    cfg = {"messages": {"client_tag_deny": "*,-draft/react,-draft/channel-context"}}
    with Server(cfg=cfg) as s:
        a = s.client("cta", caps=["message-tags"])
        b = s.client("ctb", caps=["message-tags"])
        a.say("JOIN #ctx"); b.say("JOIN #ctx"); b.drain()
        a.send("@+draft/react=yes;+other=1 TAGMSG #ctx")
        l = b.expect(r"TAGMSG #ctx")
        assert "+draft/react=yes" in l and "+other" not in l, l
        a.send("@+draft/channel-context=#ctx PRIVMSG ctb :from the channel")
        assert "+draft/channel-context=#ctx" in b.expect(r"PRIVMSG ctb :from the channel")
        a.send("@+draft/channel-context=#elsewhere PRIVMSG ctb :spoofed")
        assert "channel-context" not in b.expect(r"PRIVMSG ctb :spoofed"), "a channel the sender isn't on is dropped"


def test_event_playback_and_stored_reactions():
    with Server() as s:
        a = s.client("eva", caps=["message-tags"])
        a.say("JOIN #ev")
        a.send("PRIVMSG #ev :hello")
        a.say("TOPIC #ev :new topic")
        a.say("@+typing=active TAGMSG #ev")
        a.say("@+draft/react=ok TAGMSG #ev")
        b = s.client("evb")
        b.say("JOIN #ev"); b.say("PART #ev :bye")
        a.drain()
        full = s.client("evc", caps=["batch", "draft/chathistory", "message-tags", "draft/event-playback"])
        full.say("JOIN #ev")
        full.send("CHATHISTORY LATEST #ev * 50")
        lines = batch_lines(full, "chathistory")
        verbs = [l.split()[2] for l in lines]
        assert verbs[:6] == ["JOIN", "PRIVMSG", "TOPIC", "TAGMSG", "JOIN", "PART"], lines
        assert ":eva!" in lines[0] and "#ev :new topic" in lines[2] and "+draft/react=ok" in lines[3]
        assert not any("+typing" in l for l in lines), "typing notifications are not history"
        assert all("msgid=" in l and "time=" in l for l in lines)
        old = s.client("evd", caps=["batch", "draft/chathistory"])
        old.say("JOIN #ev")
        old.send("CHATHISTORY LATEST #ev * 50")
        lines = batch_lines(old, "chathistory")
        assert [l.split()[2] for l in lines] == ["PRIVMSG"], "no event-playback: messages only"


def test_sasl_reauthentication_switches_account():
    with Server(cfg=ACC) as s:
        s.client("reg1").say("REGISTER acctone pencil1234", 1.5)
        c = s.client("reg2")
        c.say("REGISTER accttwo pencil5678", 1.5)
        c.send("AUTHENTICATE PLAIN")
        c.expect(r"AUTHENTICATE \+")
        c.send("AUTHENTICATE " + b64("\0acctone\0pencil1234"))
        assert c.saw(r" 900 reg2 \S+ acctone ", 3)
        assert c.saw(r" 903 ")
        c.send("AUTHENTICATE PLAIN")
        c.expect(r"AUTHENTICATE \+")
        c.send("AUTHENTICATE " + b64("\0accttwo\0wrongwrong"))
        assert c.saw(r" 904 ", 3)
        assert any("acctone" in l for l in c.say("WHOIS reg2", 0.5) if " 330 " in l), "a failed re-auth keeps the login"


def test_netjoin_and_netsplit_batches():
    n = unlinked_pair()
    try:
        watcher = n.client("a", "watch", caps=["batch"])
        watcher.say("JOIN #nj")
        far = n.client("b", "farguy")
        far.say("JOIN #nj")
        boss = link_now(n)
        lines = batch_lines(watcher, r"netjoin a\.test\.net b\.test\.net", 5)
        assert any(re.match(r"^@batch=\S+ :farguy!\S+ JOIN #nj", l) for l in lines), lines
        watcher.drain()
        boss.send("SQUIT a.test.net :split test")
        lines = batch_lines(watcher, r"netsplit a\.test\.net b\.test\.net", 5)
        assert any(re.match(r"^@batch=\S+ :farguy!\S+ QUIT :a\.test\.net b\.test\.net", l) for l in lines), lines
    finally:
        n.stop()
