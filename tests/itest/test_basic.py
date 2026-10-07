from harness import Server


def test_registration_and_isupport():
    with Server() as s:
        c = s.client("alice")
        c.send("VERSION")
        lines = c.drain(0.5)
        isupport = " ".join(l for l in lines if " 005 " in l)
        for tok in ("MODES=6", "MAXLIST=b:100,e:100,I:100", "PREFIX=(qaohv)~&@%+", "CHANMODES=beI,k,lfjL,", "CALLERID=g", "CHATHISTORY=50"):
            assert tok in isupport, (tok, isupport)


def test_notice_never_auto_replies():
    with Server() as s:
        a, b = s.client("alice"), s.client("bob")
        a.say("MODE alice +R")
        r = b.say("NOTICE alice :hi")
        assert not any(" 486 " in l for l in r), r
        r = b.say("PRIVMSG alice :hi")
        assert any(" 486 " in l for l in r), r


def test_mode_parameters_validated():
    with Server() as s:
        a = s.client("alice")
        a.say("JOIN #m")
        r = a.say("MODE #m +l abc")
        assert not any(" MODE #m +l" in l for l in r), r
        a.say("MODE #m +b x!*@*")
        r = a.say("MODE #m +b x!*@*")
        assert not any("MODE #m +b" in l for l in r), r  # duplicate: not announced again
        r = a.say("MODE #m +o nobody")
        assert any(" 401 " in l for l in r), r
        a.say("MODE #m +k secret")
        modes = a.say("MODE #m")
        assert any(" 324 alice #m +k secret" in l for l in modes), modes  # flag letters and args are separate parameters


def test_ban_list_full_and_cap():
    with Server() as s:
        a = s.client("alice")
        a.say("JOIN #b")
        for i in range(100):
            a.send(f"MODE #b +b n{i}!*@*")
        a.drain(1.0)
        r = a.say("MODE #b +b overflow!*@*")
        assert any(" 478 " in l for l in r), r


def test_who_names_ison():
    with Server() as s:
        a, b = s.client("alice"), s.client("bob")
        a.say("JOIN #w")
        r = b.say("WHO alice")
        assert sum(" 352 " in l for l in r) == 1 and any(" 315 " in l for l in r), r
        r = b.say("WHO nobody")
        assert any(" 401 " in l for l in r) and any(" 315 " in l for l in r), r
        r = b.say("ISON :alice bob zed")
        assert any(" 303 bob :alice bob" in l for l in r), r
        r = b.say("NAMES #nonexistent")
        assert any(" 366 " in l for l in r), r


def test_topic_and_channel_name_rules():
    with Server() as s:
        a = s.client("alice")
        r = a.say("JOIN ##c++")
        assert any("JOIN" in l for l in r), r
        r = a.say("JOIN #bad,name")  # comma = two channels, "name" has no '#': 403 for it
        a.say("JOIN #t")
        r = a.say("TOPIC #t :" + "x" * 500)
        line = next(l for l in r if " TOPIC #t " in l)
        assert len(line) < 512, len(line)


def test_pre_registration_cap_req_holds_welcome():
    with Server() as s:
        c = s.client("early", register=False)
        c.send("CAP REQ :multi-prefix")
        c.send("NICK early")
        c.send("USER early 0 * :x")
        assert not c.saw(r" 001 ", 0.8)
        c.send("CAP END")
        c.expect(r" 001 ", 3)


def test_invite_is_bound_to_connection():
    with Server() as s:
        op, guest = s.client("op"), s.client("guest")
        op.say("JOIN #inv")
        op.say("MODE #inv +i")
        op.say("INVITE guest #inv")
        guest.close()
        impostor = s.client("guest")  # same nick, different connection
        r = impostor.say("JOIN #inv")
        assert any(" 473 " in l for l in r), r
