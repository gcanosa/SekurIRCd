"""Regressions found live-testing iSekur against SekurIRCd (1.3.2)."""
import re
from harness import Network, Server


def test_remote_server_sends_no_join_burst():
    n = Network()
    n.add("a")
    n.add("b", parent="a")
    with n:
        far = n.client("b", "far")
        far.say("JOIN #rb")
        near = n.client("a", "near")
        got = near.say("JOIN #rb", 1.0)
        assert sum(" 366 " in l for l in got) == 1, got
        assert all(not l.startswith(":b.test.net 3") for l in got), "b's own 331/353/366 reached a user on a"


def test_multiline_history_keeps_lines_and_length():
    with Server() as s:
        snd = s.client("mls", caps=["draft/multiline", "batch", "message-tags"])
        snd.say("JOIN #mh")
        a, b, c = "a" * 300, "b" * 300, "c" * 290 + "END"
        snd.send("BATCH +r draft/multiline #mh")
        snd.send(f"@batch=r PRIVMSG #mh :{a}")
        snd.send(f"@batch=r PRIVMSG #mh :{b}")
        snd.send(f"@batch=r;draft/multiline-concat PRIVMSG #mh :{c}")
        snd.send("BATCH -r")
        snd.drain(0.5)
        cap = s.client("mlc", caps=["draft/multiline", "batch", "message-tags", "draft/chathistory", "server-time"])
        cap.say("JOIN #mh")
        h = cap.say("CHATHISTORY LATEST #mh * 10", 0.6)
        assert any(re.search(r"BATCH \+hml\d+ draft/multiline #mh", l) and "msgid=" in l for l in h), h
        assert any(l.endswith(f"PRIVMSG #mh :{a}") for l in h) and any(l.endswith(f"PRIVMSG #mh :{b}") for l in h), h
        assert any("draft/multiline-concat" in l and l.endswith(f":{c}") for l in h), "the concat fragment, whole: " + str(h)
        plain = s.client("mlp", caps=["batch", "draft/chathistory", "server-time", "message-tags"])
        plain.say("JOIN #mh")
        p = [l for l in plain.say("CHATHISTORY LATEST #mh * 10", 0.6) if " PRIVMSG " in l]
        assert len(p) == 2 and p[0].endswith(f":{a}") and p[1].endswith(":" + (b + c)[:419]), p


def test_ident_tilde_consistent_everywhere():
    with Server() as s:
        u = s.client("tid", user="tid")
        w = s.client("watch", caps=["userhost-in-names"])
        u.say("JOIN #id")
        joined = w.say("JOIN #id", 0.5)
        assert any("tid!~tid@" in l for l in joined if " 353 " in l), joined
        assert any(" 311 watch tid ~tid " in l for l in w.say("WHOIS tid", 0.5))
        assert any(" 352 watch #id ~tid " in l for l in w.say("WHO #id", 0.5))
        assert any(l.endswith(" 354 watch 1 ~tid") for l in w.say("WHO #id %tu,1", 0.5))
        u.send("QUIT :bye")
        assert w.saw(r":tid!~tid@\S+ QUIT", 2)
        assert any(" 314 watch tid ~tid " in l for l in w.say("WHOWAS tid", 0.5))
        v = s.client("welc", register=False)
        v.send("NICK welc")
        v.send("USER welc 0 * :x")
        assert v.saw(r" 001 welc .*welc!~welc@")


def test_register_reply_carries_its_label():
    with Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json"}}) as s:
        c = s.client("lbl", caps=["labeled-response", "batch", "message-tags", "draft/account-registration", "standard-replies"])
        got = c.say("@label=r1 REGISTER * * :Secretpass123", 2.0)
        assert not any(" ACK" in l for l in got), got
        assert any("label=r1" in l and "REGISTER SUCCESS" in l for l in got) or \
            any("label=r1" in l and "BATCH +" in l for l in got), got


def test_cap_gated_commands_answer_without_the_cap():
    with Server() as s:
        c = s.client("nocap")
        c.say("JOIN #g")
        assert any("FAIL CHATHISTORY INVALID" in l for l in c.say("CHATHISTORY LATEST #g * 5", 0.4))
        assert any("FAIL MARKREAD INVALID #g" in l for l in c.say("MARKREAD #g", 0.4))


def test_liststart_and_default_modes():
    with Server() as s:
        c = s.client("lst")
        c.say("JOIN #new")
        assert any(" 324 lst #new +nt" in l for l in c.say("MODE #new", 0.4)), "default_modes defaults to nt"
        assert any(l.endswith(" 321 lst Channel :Users  Name") for l in c.say("LIST", 0.4))
