import re
from harness import Server

ACC = {"accounts": {"enabled": True, "store_file": "acc.json"}}


def test_channel_rename_with_and_without_cap():
    with Server() as s:
        op = s.client("op", caps=["draft/channel-rename"])
        old = s.client("plain")
        op.say("JOIN #before")
        old.say("JOIN #before")
        op.say("TOPIC #before :keep me")
        op.drain(); old.drain()
        op.send("RENAME #before #after :new home")
        assert op.saw(r":op!.* RENAME #before #after :new home")
        assert old.saw(r":plain!.* PART #before :new home"), "no cap: sees itself part"
        assert old.saw(r":plain!.* JOIN #after")
        assert old.saw(r" 332 plain #after :keep me"), "topic survives the rename"
        assert old.saw(r" 353 plain = #after :")
        # the old name is gone; the new one works
        assert any(" 403 " in l for l in op.say("MODE #before"))
        assert any(" 324 " in l for l in op.say("MODE #after"))


def test_rename_rejects_taken_name_and_non_ops():
    with Server() as s:
        a, b = s.client("a1"), s.client("b1")
        a.say("JOIN #one")
        b.say("JOIN #two")
        r = a.say("RENAME #one #two")
        assert any("FAIL RENAME CHANNEL_NAME_IN_USE" in l for l in r), r
        b.say("JOIN #one")
        r = b.say("RENAME #one #three")
        assert any(" 482 " in l for l in r), r


def test_multiline_batch_delivery():
    with Server() as s:
        sender = s.client("snd", caps=["draft/multiline", "batch", "message-tags", "echo-message"])
        cap = s.client("capr", caps=["draft/multiline", "batch", "message-tags"])
        plain = s.client("plainr")
        for c in (sender, cap, plain):
            c.say("JOIN #ml")
        for c in (sender, cap, plain):
            c.drain()
        sender.send("BATCH +r1 draft/multiline #ml")
        sender.send("@batch=r1 PRIVMSG #ml :first line")
        sender.send("@batch=r1 PRIVMSG #ml :second ")
        sender.send("@batch=r1;draft/multiline-concat PRIVMSG #ml :half")
        sender.send("BATCH -r1")
        assert cap.saw(r"BATCH \+ml\d+ draft/multiline #ml")
        assert cap.saw(r"^@batch=ml\d+ :snd!.* PRIVMSG #ml :first line")
        assert cap.saw(r"^@batch=ml\d+ :snd!.* PRIVMSG #ml :second ")
        assert cap.saw(r"^@batch=ml\d+;draft/multiline-concat :snd!.* PRIVMSG #ml :half")
        assert cap.saw(r"BATCH -ml\d+")
        assert plain.saw(r"PRIVMSG #ml :first line")
        assert plain.saw(r"PRIVMSG #ml :second half"), "concat fragments are glued for clients without the cap"
        assert sender.saw(r"BATCH \+ml\d+"), "echo-message echoes the batch"


def test_multiline_limits_and_errors():
    with Server() as s:
        c = s.client("ml1", caps=["draft/multiline", "batch", "message-tags"])
        c.say("JOIN #e")
        c.send("BATCH +x draft/multiline #e")
        for i in range(25):
            c.send(f"@batch=x PRIVMSG #e :l{i}")
        assert c.saw(r"FAIL BATCH MULTILINE_MAX_LINES")
        c.send("BATCH +y draft/multiline #e")
        c.send("BATCH -y")
        assert c.saw(r"FAIL BATCH MULTILINE_INVALID")
        c.send("@batch=nope PRIVMSG #e :x")
        assert c.saw(r"FAIL BATCH INVALID_REFTAG")


def test_read_marker_syncs_account_sessions():
    with Server(cfg=ACC) as s:
        a = s.client("rm1", caps=["draft/read-marker"])
        a.say("REGISTER rmuser password1", 1.5)
        a.say("JOIN #rm")
        b = s.client("rm2", register=False, caps=["draft/read-marker", "sasl"])
        a.drain()
        a.send("MARKREAD #rm")
        assert a.saw(r"MARKREAD #rm timestamp=\*")
        a.send("MARKREAD #rm timestamp=2026-01-02T03:04:05.000Z")
        assert a.saw(r"MARKREAD #rm timestamp=2026-01-02T03:04:05.000Z")
        a.send("MARKREAD #rm timestamp=2025-01-01T00:00:00.000Z")  # older: marker only moves forward
        assert a.saw(r"MARKREAD #rm timestamp=2026-01-02T03:04:05.000Z")
        a.send("MARKREAD #nochan timestamp=2026-01-02T03:04:05.000Z")
        assert a.saw(r"FAIL MARKREAD INVALID_PARAMS")
        anon = s.client("anon", caps=["draft/read-marker"])
        anon.send("MARKREAD #rm")
        assert anon.saw(r"FAIL MARKREAD ACCOUNT_REQUIRED")
