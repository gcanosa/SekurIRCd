import re
from harness import Server

ACC = {"accounts": {"enabled": True, "store_file": "acc.json"}}
CH = ["batch", "draft/chathistory", "message-tags"]


def texts(lines, verb="PRIVMSG"):
    return [re.search(verb + r" \S+ :(.*)$", l).group(1) for l in lines if f" {verb} " in l]


def fetch(c, cmd, wait=0.6):
    c.drain(0.1)
    c.send(cmd)
    return c.drain(wait)


def test_history_outlives_an_emptied_channel():
    with Server() as s:
        a = s.client("ha")
        a.say("JOIN #gone")
        a.send("PRIVMSG #gone :remember me")
        a.drain(0.3)
        a.say("PART #gone")  # channel is destroyed
        b = s.client("hb", caps=CH)
        b.say("JOIN #gone")
        assert "remember me" in texts(fetch(b, "CHATHISTORY LATEST #gone * 10"))


def test_history_persists_across_restart():
    with Server(cfg={"messages": {"history_file": "history.json"}}) as s:
        a = s.client("ha")
        a.say("JOIN #keep")
        a.send("PRIVMSG #keep :survives a restart")
        a.drain(0.4)
        s.restart()
        b = s.client("hb", caps=CH)
        b.say("JOIN #keep")
        assert "survives a restart" in texts(fetch(b, "CHATHISTORY LATEST #keep * 10"))


def test_dm_history_between_accounts_and_targets():
    with Server(cfg=ACC) as s:
        a = s.client("al", caps=CH)
        a.say("REGISTER alice password1", 1.5)
        b = s.client("bo", caps=CH)
        b.say("REGISTER bobby password2", 1.5)
        a.send("PRIVMSG bo :hi bob")
        b.drain(0.3)  # let the server process one before the other (both sockets would otherwise race)
        b.send("PRIVMSG al :hi alice")
        a.drain(0.4); b.drain(0.4)
        got = texts(fetch(a, "CHATHISTORY LATEST bo * 10"))
        assert got == ["hi bob", "hi alice"], got
        got_b = texts(fetch(b, "CHATHISTORY LATEST al * 10"))
        assert got_b == ["hi bob", "hi alice"], got_b
        c = s.client("cc", caps=CH)
        c.say("REGISTER carol password3", 1.5)
        assert texts(fetch(c, "CHATHISTORY LATEST bo * 10")) == [], "a third account sees nothing of that conversation"
        a.say("JOIN #tgt")
        a.send("PRIVMSG #tgt :chan msg")
        a.drain(0.3)
        out = fetch(a, "CHATHISTORY TARGETS timestamp=2000-01-01T00:00:00.000Z timestamp=2100-01-01T00:00:00.000Z 10")
        names = [re.search(r"TARGETS (\S+) timestamp=", l).group(1) for l in out if " CHATHISTORY TARGETS " in l]
        assert "#tgt" in names and "bobby" in names, out


def test_read_marker_persists_with_history_file():
    with Server(cfg={**ACC, "messages": {"history_file": "history.json"}}) as s:
        a = s.client("rm1", caps=["draft/read-marker"])
        a.say("REGISTER rmuser password1", 1.5)
        a.say("JOIN #rm")
        a.send("MARKREAD #rm timestamp=2026-01-02T03:04:05.000Z")
        a.drain(0.4)
        # history is only "dirty" when something was said; say something so the file is written
        a.send("PRIVMSG #rm :x")
        a.drain(0.3)
        s.restart()
        b = s.client("rm2", register=False, caps=["draft/read-marker", "sasl"])
        b.send("AUTHENTICATE PLAIN")
        b.expect(r"AUTHENTICATE \+")
        import base64
        b.send("AUTHENTICATE " + base64.b64encode(b"\0rmuser\0password1").decode())
        b.expect(r" 903 ")
        b.send("NICK rm2")
        b.send("USER rm2 0 * :x")
        b.expect(r" 001 ")
        b.send("JOIN #rm")
        assert b.saw(r"MARKREAD #rm timestamp=2026-01-02T03:04:05.000Z", 1.5)
