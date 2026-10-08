"""Behaviour popular clients depend on (irssi/WeeChat/HexChat usernames, gamja/Kiwi cap requests, MONITOR lists)."""
from harness import Server

ALL_CAPS = ("away-notify multi-prefix userhost-in-names setname chghost account-notify extended-join echo-message "
            "message-tags server-time account-tag invite-notify standard-replies cap-notify batch labeled-response "
            "draft/no-implicit-names draft/pre-away extended-monitor draft/channel-rename draft/multiline "
            "draft/read-marker draft/chathistory").split()


def test_os_style_username_is_sanitised_not_refused():
    with Server() as s:
        c = s.client("dotty", user="john.doe")
        assert any("johndoe" in l for l in c.say("WHOIS dotty")), "dots are dropped, connection survives"


def test_one_long_cap_req_is_acked():
    with Server() as s:
        c = s.client("capall", register=False)
        c.send("CAP LS 302")
        c.send("CAP REQ :" + " ".join(ALL_CAPS))
        assert c.saw(r"CAP \* ACK :away-notify .*draft/chathistory"), "a ~360-byte REQ must not be NAKed"


def test_monitor_lists_split_instead_of_truncating():
    with Server() as s:
        c = s.client("mon")
        nicks = [f"watched_nick_{i:03d}" for i in range(100)]
        c.drain()
        for i in range(0, 100, 25):  # 25 per line keeps each MONITOR + under 512 bytes
            c.send("MONITOR + " + ",".join(nicks[i:i + 25]))
        c.drain(0.5)
        got = []
        for l in c.say("MONITOR L", 0.5):
            if " 732 " in l:
                assert len(l) <= 512
                got += l.split(" :", 1)[1].split(",")
        assert got == nicks, f"{len(got)} of 100"


def test_join_zero_parts_everything():
    with Server() as s:
        c = s.client("jz")
        c.say("JOIN #a,#b,#c")
        out = c.say("JOIN 0")
        assert sum(" PART #" in l for l in out) == 3, out


def test_statusmsg_is_echoed():
    with Server() as s:
        op = s.client("sop", caps=["echo-message"])
        op.say("JOIN #st")
        op.drain()
        op.send("PRIVMSG @#st :ops only")
        assert op.saw(r":sop!.* PRIVMSG @#st :ops only")


def test_labeled_chathistory_keeps_one_batch_tag_per_line():
    with Server() as s:
        c = s.client("lab", caps=["batch", "labeled-response", "message-tags", "draft/chathistory"])
        c.say("JOIN #lh")
        c.say("PRIVMSG #lh :one")
        c.say("PRIVMSG #lh :two")
        out = c.say("@label=L1 CHATHISTORY LATEST #lh * 10", 0.6)
        tagged = [l for l in out if " PRIVMSG #lh " in l]
        assert len(tagged) == 2, out
        assert all(l.split(" ", 1)[0].count("batch=") == 1 for l in tagged), tagged
        assert any(l.startswith("@label=L1") and " BATCH +" in l for l in out), out


ACC = {"accounts": {"enabled": True, "store_file": "acc.json"}}


def whos(c, cmd):
    """Which of the two users under test a WHO reply lists (the nick column)."""
    return {l.split()[7] for l in c.say(cmd, 0.4) if " 352 " in l} & {"visible1", "hidden1"}


def test_who_mask_and_invisible_users():
    with Server() as s:
        vis, inv = s.client("visible1"), s.client("hidden1")
        inv.say("MODE hidden1 +i")
        vis.say("JOIN #w")
        inv.say("JOIN #w")
        out = s.client("outsider")
        assert whos(out, "WHO *1") == {"visible1"}, "a mask skips +i users you share no channel with"
        assert whos(out, "WHO #w") == {"visible1"}, "so does WHO #chan from outside"
        assert whos(out, "WHO hidden1") == {"hidden1"}, "an exact nick still answers"
        assert whos(vis, "WHO *1") == {"visible1", "hidden1"}, "sharing a channel makes +i users visible"
        assert whos(out, "WHO * o") == set(), "o: opers only"


def test_pass_logs_into_an_account():
    with Server(cfg=ACC) as s:
        s.client("owner").say("REGISTER passacct password1", 1.5)
        good = s.client("pa1", extra=["PASS passacct:password1"])
        assert any(" 330 " in l and "passacct" in l for l in good.say("WHOIS pa1")), "PASS account:password logs in"
        bad = s.client("pa2", extra=["PASS passacct:wrong"])
        assert not any(" 330 " in l for l in bad.say("WHOIS pa2", 0.5)), "a wrong PASS still connects, unidentified"


def test_rename_keeps_history():
    with Server() as s:
        c = s.client("rh", caps=["batch", "draft/chathistory", "message-tags", "draft/channel-rename"])
        c.say("JOIN #oldname")
        c.say("PRIVMSG #oldname :before the rename")
        c.say("RENAME #oldname #newname")
        out = c.say("CHATHISTORY LATEST #newname * 10", 0.6)
        assert any("PRIVMSG #newname :before the rename" in l for l in out), out


def test_cap_notify_values_only_for_302():
    with Server() as s:
        new = s.client("cn302", caps=["cap-notify"])  # harness sends CAP LS 302
        old = s.client("cn301", register=False)
        old.send("CAP LS")
        old.send("CAP REQ :cap-notify")
        old.send("CAP END")
        old.send("NICK cn301")
        old.send("USER cn301 0 * :x")
        old.expect(" 001 ")
        s.cfg["accounts"] = {"enabled": True, "store_file": "acc.json"}
        s.reload()
        assert new.saw(r"CAP cn302 NEW :sasl=PLAIN,SCRAM-SHA-256 ")
        assert old.saw(r"CAP cn301 NEW :sasl draft/account-registration$")
