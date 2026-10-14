"""Per-client MONITOR/WATCH/SILENCE/ACCEPT lists and a channel's INVITE list are allocated on first use and freed when
they empty; MONITOR/WATCH notifications go through an inverted index. These drive both past every growth step."""
import re
from harness import Server


def monitored(c):
    got = []
    for l in c.say("MONITOR L", 0.4):
        if " 732 " in l:
            got += l.split(" :", 1)[1].split(",")
    return got


def test_monitor_list_grows_shrinks_and_reallocates():
    with Server() as s:
        c = s.client("mon")
        nicks = [f"w{i:02d}" for i in range(20)]
        c.send("MONITOR + " + ",".join(nicks))
        c.drain(0.4)
        assert monitored(c) == nicks
        for n in nicks[:10]:
            c.send(f"MONITOR - {n}")
        c.drain(0.3)
        assert monitored(c) == nicks[10:]
        c.send("MONITOR C")
        c.drain(0.2)
        assert monitored(c) == []
        c.send("MONITOR + again")  # the freed list comes back
        c.drain(0.2)
        assert monitored(c) == ["again"]


def test_monitor_notifies_online_offline_and_nick_change():
    with Server() as s:
        w1 = s.client("w1"); w2 = s.client("w2"); w3 = s.client("w3")
        for w in (w1, w2):
            w.send("MONITOR + target,target2")
        w3.send("MONITOR + target")
        w3.send("MONITOR - target")  # unmonitored again: hears nothing
        for w in (w1, w2, w3):
            w.drain(0.3)
        t = s.client("target")
        assert w1.saw(r" 730 w1 :target!"), "first watcher told target is online"
        assert w2.saw(r" 730 w2 :target!"), "second watcher too"
        assert not w3.saw(r" 73[01] ", 0.3), "a removed entry is gone from the index"
        t.say("NICK target2")
        assert w1.saw(r" 731 w1 :target"), "old nick offline"
        assert w1.saw(r" 730 w1 :target2!"), "new nick online"
        w2.close()  # a watcher that disappears must not leave a dangling index entry
        s.client("w2b").close()
        t.say("QUIT :bye")
        assert w1.saw(r" 731 w1 :target2"), "quit reported offline"
        s.client("target")  # a fresh connection after everything was torn down: no crash, still notifies
        assert w1.saw(r" 730 w1 :target!")


def test_legacy_watch_list_notifies():
    with Server() as s:
        w = s.client("wa")
        w.send("WATCH +buddy +pal")
        w.drain(0.3)
        b = s.client("buddy")
        assert w.saw(r" 600 wa buddy ")
        w.send("WATCH -buddy")
        w.drain(0.2)
        b.say("QUIT :x")
        assert not w.saw(r" 601 ", 0.3)
        w.send("WATCH C")
        s.client("pal")
        assert not w.saw(r" 600 ", 0.3)


def test_silence_list_grows_filters_and_shrinks():
    with Server() as s:
        a = s.client("sa"); b = s.client("sb")
        masks = [f"*!*@host{i}.example" for i in range(6)]
        a.send("SILENCE " + " ".join("+" + m for m in masks))
        a.send("SILENCE +sb!*@*")
        out = a.say("SILENCE", 0.4)
        listed = [l.split()[-1] for l in out if " 271 " in l]
        assert listed == masks + ["sb!*@*"], listed
        b.say("PRIVMSG sa :hello")
        assert not a.saw(r"PRIVMSG sa :hello", 0.4), "silenced sender is dropped"
        a.send("SILENCE -sb!*@*")
        a.drain(0.2)
        b.say("PRIVMSG sa :hello again")
        assert a.saw(r"PRIVMSG sa :hello again"), "after removal messages flow"
        for m in masks:
            a.send("SILENCE -" + m)
        a.drain(0.3)
        assert not [l for l in a.say("SILENCE", 0.3) if " 271 " in l]
        a.send("SILENCE +*!*@back.example")  # reallocates after the list emptied
        assert [l for l in a.say("SILENCE", 0.3) if " 271 " in l]


def test_accept_list_for_caller_id():
    with Server() as s:
        a = s.client("ac")
        a.say("MODE ac +g")
        friends = [s.client(f"fr{i}") for i in range(6)]
        stranger = s.client("stranger")
        for f in friends:
            a.send(f"ACCEPT {f.nick}")
        a.drain(0.4)
        listed = [l for l in a.say("ACCEPT *", 0.4) if " 281 " in l]
        assert len(listed) == 6, listed
        friends[5].say("PRIVMSG ac :from a friend")
        assert a.saw(r"PRIVMSG ac :from a friend")
        stranger.say("PRIVMSG ac :let me in")
        assert not a.saw(r"PRIVMSG ac :let me in", 0.4)
        for f in friends:
            a.send(f"ACCEPT -{f.nick}")
        a.drain(0.3)
        assert not [l for l in a.say("ACCEPT *", 0.3) if " 281 " in l]
        friends[0].say("PRIVMSG ac :now blocked")
        assert not a.saw(r"PRIVMSG ac :now blocked", 0.4)


def test_invite_list_grows_and_is_consumed():
    with Server() as s:
        op = s.client("opr")
        op.say("JOIN #vip")
        op.say("MODE #vip +i")
        guests = [s.client(f"g{i}") for i in range(7)]
        for g in guests:
            op.send(f"INVITE {g.nick} #vip")
        op.drain(0.5)
        assert any(" 473 " in l for l in s.client("outsider").say("JOIN #vip")), "uninvited stays out"
        for g in guests:
            out = g.say("JOIN #vip", 0.4)
            assert any(" JOIN " in l for l in out), (g.nick, out)
        guests[0].say("PART #vip")
        assert any(" 473 " in l for l in guests[0].say("JOIN #vip", 0.4)), "an invite is used up by the JOIN"


def test_server_time_tag_is_added_once_next_to_other_tags():
    with Server() as s:
        a = s.client("ta", caps=["message-tags", "server-time"])
        b = s.client("tb", caps=["message-tags", "server-time"])
        plain = s.client("tc")
        for c in (a, b, plain):
            c.say("JOIN #tt")
        b.drain(0.3)
        a.send("@+example=1 PRIVMSG #tt :tagged")
        line = next(l for l in b.drain(0.5) if "PRIVMSG #tt :tagged" in l)
        tags = line[1:line.index(" ")].split(";")
        assert sum(t.startswith("time=") for t in tags) == 1, line
        assert any(t.startswith("msgid=") for t in tags) and "+example=1" in tags, line
        assert re.match(r"time=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$", [t for t in tags if t.startswith("time=")][0])
        got = [l for l in plain.drain(0.3) if "PRIVMSG #tt :tagged" in l]
        assert got and not got[0].startswith("@"), "a client without the caps gets the bare line"
