from harness import Server


def test_redirect_on_full_channel():
    with Server() as s:
        op = s.client("op")
        op.say("JOIN #small")
        op.say("MODE #small +l 1")
        op.say("MODE #small +L #overflow")
        u = s.client("user")
        r = u.say("JOIN #small")
        assert any(" 470 user #small #overflow" in l for l in r), r
        assert any("JOIN #overflow" in l for l in r), r
        assert not any(" 471 " in l for l in r), r


def test_redirect_does_not_loop():
    with Server() as s:
        op = s.client("op")
        for ch, tgt in (("#a", "#b"), ("#b", "#a")):
            op.say(f"JOIN {ch}")
            op.say(f"MODE {ch} +l 1")
            op.say(f"MODE {ch} +L {tgt}")
        u = s.client("user")
        r = u.say("JOIN #a")
        assert any(" 471 " in l for l in r), r  # one hop only, then the normal refusal


def test_delayed_join_hidden_until_speaking():
    with Server() as s:
        op, lurker = s.client("op"), s.client("lurker")
        op.say("JOIN #d")
        op.say("MODE #d +D")
        r = lurker.say("JOIN #d")
        assert any("JOIN #d" in l for l in r), "the joiner sees their own join"
        assert not op.saw(r":lurker!.* JOIN #d", 0.5), "others are not told yet"
        assert "lurker" not in " ".join(op.say("NAMES #d"))
        lurker.say("PRIVMSG #d :hello")
        assert op.saw(r":lurker!.* JOIN #d"), "speaking reveals the member"
        assert op.saw(r"PRIVMSG #d :hello")
        assert "lurker" in " ".join(op.say("NAMES #d"))


def test_delayed_join_part_is_silent_and_unset_reveals():
    with Server() as s:
        op, a, b = s.client("op"), s.client("quiet1"), s.client("quiet2")
        op.say("JOIN #d2")
        op.say("MODE #d2 +D")
        a.say("JOIN #d2")
        b.say("JOIN #d2")
        a.say("PART #d2")
        assert not op.saw(r"quiet1.* PART", 0.5), "a never-revealed member leaves silently"
        op.send("MODE #d2 -D")
        assert op.saw(r":quiet2!.* JOIN #d2"), "-D reveals whoever is still hidden"


def test_auditorium_hides_ordinary_members():
    with Server() as s:
        op, v, m1, m2 = s.client("op"), s.client("vv"), s.client("m1"), s.client("m2")
        op.say("JOIN #u")
        op.say("MODE #u +u")
        v.say("JOIN #u")
        op.say("MODE #u +v vv")
        m1.say("JOIN #u")
        m2.say("JOIN #u")
        opnames = " ".join(op.say("NAMES #u"))
        assert "m1" in opnames and "m2" in opnames, opnames  # ops see everyone
        m1names = " ".join(m1.say("NAMES #u"))
        assert "m2" not in m1names and "op" in m1names and "vv" in m1names, m1names
        m1.drain(); m2.drain()
        m1.say("PRIVMSG #u :audience talk")
        assert op.saw(r"audience talk")
        assert not m2.saw(r"audience talk", 0.5), "ordinary members don't see each other"
        op.say("PRIVMSG #u :from the stage")
        assert m1.saw(r"from the stage") and m2.saw(r"from the stage")


def test_censor_mode_stars_configured_words():
    with Server(cfg={"messages": {"censor_words": ["darn", "heck"]}}) as s:
        a, b = s.client("a1"), s.client("b1")
        a.say("JOIN #c")
        b.say("JOIN #c")
        a.say("MODE #c +G")
        b.drain()
        a.say("PRIVMSG #c :oh DARN it, what the Heck")
        line = b.expect(r"PRIVMSG #c :")
        assert "oh **** it, what the ****" in line, line
        a.say("MODE #c -G")
        b.drain()
        a.say("PRIVMSG #c :darn")
        assert b.saw(r":darn")
