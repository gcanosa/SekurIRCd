import re
from harness import Server


def test_cap_302_multiline_and_values():
    with Server(cfg={"accounts": {"enabled": True, "store_file": "acc.json"}}) as s:
        c = s.client("c302", register=False)
        c.send("CAP LS 302")
        ls = c.expect(r"CAP \* LS")
        assert "sasl=PLAIN,SCRAM-SHA-256" in ls and "draft/chathistory" in ls and "labeled-response" in ls, ls
        d = s.client("c301", register=False)
        d.send("CAP LS")
        ls2 = d.expect(r"CAP \* LS")
        assert "sasl=" not in ls2 and "sasl" in ls2 and "sts" not in ls2, ls2


def test_msgid_tagmsg_and_client_tags():
    with Server() as s:
        a = s.client("ta", caps=["message-tags", "echo-message"])
        b = s.client("tb", caps=["message-tags"])
        c = s.client("tc")
        for x in (a, b, c):
            x.say("JOIN #m")
        a.drain(); b.drain(); c.drain()
        a.send("@+typing=active TAGMSG #m")
        assert b.saw(r"^@msgid=[^;]+;\+typing=active :ta!.* TAGMSG #m")
        assert a.saw(r"TAGMSG #m")  # echo-message
        assert not c.saw(r"TAGMSG", 0.4)  # no message-tags -> nothing
        a.send("@+draft/reply=abc PRIVMSG #m :hello")
        line = b.expect(r"PRIVMSG #m :hello")
        assert "+draft/reply=abc" in line and "msgid=" in line
        plain = c.expect(r"PRIVMSG #m :hello")
        assert not plain.startswith("@"), plain


def test_chathistory_latest_before_after():
    with Server() as s:
        a = s.client("ha")
        a.say("JOIN #h")
        for i in range(6):
            a.send(f"PRIVMSG #h :line {i}")
        a.drain(0.4)
        b = s.client("hb", caps=["batch", "draft/chathistory"])
        b.say("JOIN #h")
        b.send("CHATHISTORY LATEST #h * 3")
        assert b.saw(r"BATCH \+ch\d+ chathistory #h")
        got = [b.expect(r"PRIVMSG #h :line \d") for _ in range(3)]
        assert [re.search(r"line (\d)", g).group(1) for g in got] == ["3", "4", "5"]
        b.expect(r"BATCH -ch")
        mid = re.search(r"msgid=([^; ]+)", got[1]).group(1)
        b.send(f"CHATHISTORY BEFORE #h msgid={mid} 2")
        b.expect(r"BATCH \+ch")
        before = [b.expect(r"PRIVMSG #h :line \d") for _ in range(2)]
        assert [re.search(r"line (\d)", g).group(1) for g in before] == ["2", "3"]
        b.drain()
        b.send("CHATHISTORY LATEST #nochan * 5")
        assert b.saw(r"FAIL CHATHISTORY INVALID_TARGET")


def test_labeled_response_variants():
    with Server() as s:
        c = s.client("lab", caps=["batch", "labeled-response", "echo-message"])
        c.say("JOIN #l")
        c.send("@label=one PING hi")
        assert c.saw(r"^@label=one :.* PONG ")
        c.send("@label=ack PONG x")
        assert c.saw(r"^@label=ack :.* ACK")
        c.send("@label=many WHO #l")
        assert c.saw(r"^@label=many :.* BATCH \+lr\d+ labeled-response")
        assert c.saw(r"^@batch=lr\d+ :.* 352 ")
        assert c.saw(r"BATCH -lr")
        c.send("PING plain")
        line = c.expect(r"PONG")
        assert not line.startswith("@")


def test_registration_waits_for_cap_end():
    with Server() as s:
        c = s.client("late", register=False)
        c.send("CAP LS 302")
        c.send("NICK late")
        c.send("USER late 0 * :x")
        assert not c.saw(r" 001 ", 0.6)
        c.send("CAP END")
        c.expect(r" 001 ")
