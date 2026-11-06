import time
from harness import Server

OPER = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def oper(s, nick):
    c = s.client(nick)
    c.say("OPER boss bosspw", 0.8)
    return c


def test_flood_mode_kicks_flooder():
    with Server() as s:
        op, u = s.client("op"), s.client("u1")
        op.say("JOIN #f")
        op.say("MODE #f +f 3:5")
        u.say("JOIN #f")
        for i in range(5):
            u.send(f"PRIVMSG #f :spam {i}")
        assert u.saw(r"KICK #f u1 :Channel flood", 1.0)


def test_flood_mode_ignores_typing_tagmsg():
    with Server() as s:
        op, u = s.client("op"), s.client("u1", caps=["message-tags"])
        op.say("JOIN #f")
        op.say("MODE #f +f 3:5")
        u.say("JOIN #f")
        for i in range(8):  # a web client repeats +typing while you type; that is not channel flood
            u.send("@+typing=active TAGMSG #f")
        assert not u.saw(r"KICK #f u1", 0.8)
        u.send("PRIVMSG #f :still here")
        assert not u.saw(r"KICK #f u1", 0.5)


def test_join_throttle():
    with Server() as s:
        op = s.client("op")
        op.say("JOIN #j")
        op.say("MODE #j +j 2:10")
        a, b, c = s.client("a1"), s.client("b1"), s.client("c1")
        a.say("JOIN #j")
        b.say("JOIN #j")
        r = c.say("JOIN #j")  # third join inside the window
        assert any(" 471 " in l and "+j" in l for l in r), r


def test_plus_P_is_oper_only():
    with Server(cfg=OPER) as s:
        u = s.client("user")
        u.say("JOIN #p")
        r = u.say("MODE #p +P")
        assert any(" 482 " in l and "operators only" in l for l in r), r
        o = oper(s, "boss")
        o.say("JOIN #p2")
        r = o.say("MODE #p2 +P")
        assert any("MODE #p2 +P" in l for l in r), r


def test_extbans_realname_and_secure():
    with Server() as s:
        op = s.client("op")
        v = s.client("vic", realname="very vic name")
        op.say("JOIN #e")
        op.say("MODE #e +b ~r:*vic*")
        assert any(" 474 " in l for l in v.say("JOIN #e")), "~r should block"
        op.say("MODE #e -b ~r:*vic*")
        assert any("JOIN" in l for l in v.say("JOIN #e")), "unbanned"


def test_owner_admin_ranks_and_protection():
    with Server(cfg=OPER) as s:
        boss = oper(s, "boss")
        a, b = s.client("opa"), s.client("opb", caps=["multi-prefix"])
        a.say("JOIN #r")
        b.say("JOIN #r")
        a.say("MODE #r +o opb")
        assert any(" 482 " in l for l in a.say("MODE #r +q opa")), "an op may not grant +q"
        boss.say("SAMODE #r +q opa")
        names = " ".join(b.say("NAMES #r"))
        assert "~@opa" in names and "@opb" in names, names
        assert any(" 482 " in l for l in b.say("KICK #r opa :x")), "junior op can't kick the owner"
        assert any(" 482 " in l for l in b.say("MODE #r -o opa")), "junior op can't deop the owner"
        a.say("MODE #r +a opb")
        assert "&@opb" in " ".join(b.say("NAMES #r"))


def test_caller_id_binds_to_connection():
    with Server() as s:
        ana, bob = s.client("ana"), s.client("bob")
        ana.say("MODE ana +g")
        r = bob.say("PRIVMSG ana :hello?")
        assert any(" 716 " in l for l in r), r
        ana.say("ACCEPT bob")
        bob.say("NICK bob2")
        r = bob.say("PRIVMSG ana :now?")
        assert not any(" 716 " in l for l in r) and ana.saw(r"now\?"), r
        impostor = s.client("bob")
        r = impostor.say("PRIVMSG ana :me?")
        assert any(" 716 " in l for l in r), r


def test_halfop_cannot_kick_op():
    with Server() as s:
        a, b, c = s.client("a1"), s.client("b1"), s.client("c1")
        a.say("JOIN #h")
        b.say("JOIN #h")
        c.say("JOIN #h")
        a.say("MODE #h +h b1")
        assert any(" 482 " in l for l in b.say("KICK #h a1 :no")), "halfop must not kick an op"


SPAM = dict(OPER, spam={"enabled": True, "filters_enabled": True})


def test_spamfilter_hide_drops_silently_but_echoes():
    with Server(cfg=SPAM) as s:
        o = oper(s, "boss")
        o.say("SPAMFILTER ADD c hide - ad buyspam", 0.5)
        rx, u = s.client("rx"), s.client("u1", caps=["echo-message"])
        rx.say("JOIN #h")
        u.say("JOIN #h")
        r = u.say("PRIVMSG #h :hey buyspam now")
        assert any("PRIVMSG #h :hey buyspam now" in l for l in r), r  # echoed: looks sent
        assert not any("blocked" in l for l in r), r                   # no notice to the sender
        assert not rx.saw(r"buyspam", 0.5)                             # nobody got it
        assert o.saw(r"Spam: u1!.* hide \(ad\)", 0.5)                  # opers still see it
        u.send("PRIVMSG #h :clean line")
        assert rx.saw(r"PRIVMSG #h :clean line", 1.0)                  # hide does not stick


def test_spamfilter_sees_owner_and_admin_statusmsg():
    with Server(cfg=SPAM) as s:
        o = oper(s, "boss")
        o.say("SPAMFILTER ADD c block - ad buyspam", 0.5)
        u = s.client("u1")
        u.say("JOIN #h")
        for t in ("~#h", "&#h"):  # were treated as a nick: channel rules never ran
            assert any("blocked" in l for l in u.say(f"PRIVMSG {t} :buyspam")), t


def test_spamfilter_shun_sticks():
    with Server(cfg=SPAM) as s:
        o = oper(s, "boss")
        o.say("SPAMFILTER ADD c shun 10m ad buyspam", 0.5)
        rx, u = s.client("rx"), s.client("u1")
        rx.say("JOIN #h")
        u.say("JOIN #h")
        u.send("PRIVMSG #h :buyspam")
        assert not rx.saw(r"buyspam", 0.5)
        u.send("PRIVMSG #h :clean line")
        assert not rx.saw(r"clean line", 0.5)  # shunned: later messages vanish too
        assert u.say("PING :x") and not u.saw(r"ERROR", 0.2)  # still connected


def test_unreal_style_modes_deaf_noctcp_noknock_nickban_hostban():
    with Server() as s:
        op, u, d = s.client("op"), s.client("u1"), s.client("deafy")
        op.say("JOIN #u"); u.say("JOIN #u"); d.say("JOIN #u")
        # +d: deaf to channel messages, private ones still arrive
        d.send("MODE deafy +d")
        assert d.saw(r"MODE deafy :?\+d")
        u.send("PRIVMSG #u :hello room")
        assert op.saw(r"PRIVMSG #u :hello room") and not d.saw(r"hello room", 0.5)
        u.send("PRIVMSG deafy :hi you")
        assert d.saw(r"PRIVMSG deafy :hi you")
        # +T: CTCP to you is dropped (was +d)
        d.say("MODE deafy -d+T")
        u.send("PRIVMSG deafy :\x01VERSION\x01")
        assert not d.saw(r"VERSION", 0.5)
        # a no-op mode change is not echoed
        op.drain(); op.send("MODE #u +t")
        assert not op.saw(r"MODE #u \+t", 0.5)
        # +K: no knocking
        op.say("MODE #u +iK")
        x = s.client("knocker")
        x.send("KNOCK #u")
        assert x.saw(r" 480 knocker #u ")
        # ~n: no nick change (voice and up exempt); bare-host bans are stored canonically
        op.say("MODE #u -i")
        op.send("MODE #u +b ~nickchange:u1")
        assert op.saw(r"MODE #u \+b ~n:u1!\*@\*")
        u.send("NICK u2")
        assert u.saw(r" 447 u1 #u ")
        op.send("MODE #u +b 203.0.113.9")
        assert op.saw(r"MODE #u \+b \*!\*@203\.0\.113\.9")
        op.send("MODE #u -b 203.0.113.9")
        assert op.saw(r"MODE #u -b \*!\*@203\.0\.113\.9")


def test_banlist_setter_unreal_flood_and_secure_only_pm():
    with Server() as s:
        op, u = s.client("op"), s.client("u1")
        op.say("JOIN #f"); u.say("JOIN #f")
        # 367 carries the setter and the time, like other ircds
        op.say("MODE #f +b *!*@ban.example")
        op.send("MODE #f +b")
        assert op.saw(r" 367 op #f \*!\*@ban\.example op \d+")
        # UnrealIRCd +f: 3 messages in 30s, then the server sets +m
        op.send("MODE #f +f [3m,9r]:30")
        assert op.saw(r"MODE #f \+f \[3m,9r\]:30")
        for i in range(4):
            u.send(f"PRIVMSG #f :line {i}")
        assert op.saw(r"MODE #f \+m")
        # +Z: private messages only between TLS users (these test clients are plaintext)
        u.send("MODE u1 +Z")
        assert u.saw(r"MODE u1 :?\+Z")
        op.send("PRIVMSG u1 :hi")
        assert op.saw(r" 531 op u1 :You must be connected via SSL/TLS")
        u.send("PRIVMSG op :hi")
        assert u.saw(r" 531 u1 op :Message not sent")


def test_cloak_toggle_whois_notify_forward_ban_and_repeat_flood():
    cfg = dict(OPER)
    cfg["security"] = {"rdns_enabled": False, "ident_enabled": False, "flood_max_msgs": 1000, "connect_flood_max": 100000,
                       "host_masking": True}
    with Server(cfg=cfg) as s:
        boss, u = oper(s, "boss"), s.client("u1")
        # +x is on by default under host_masking; -x shows the real host (396), +x cloaks again
        assert "x" in " ".join(u.say("MODE u1", 0.4))
        u.send("MODE u1 -x")
        assert u.saw(r" 396 u1 127\.0\.0\.1 :is now your displayed host")
        u.send("MODE u1 +x")
        cl = u.expect(r" 396 u1 \S+ :is now your displayed host")
        assert "127.0.0.1" not in cl, cl
        # +W: an oper is told who WHOISed them; ordinary users can't set it
        boss.say("MODE boss +W")
        u.send("WHOIS boss")
        assert boss.saw(r"NOTICE boss :\*\*\* Notice -- u1 \(.*\) did a /WHOIS on you")
        u.send("MODE u1 +W")
        assert not u.saw(r"MODE u1 :?\+W", 0.5)
        # ~f: banned from #main, sent to #lobby instead
        boss.say("JOIN #main")
        boss.send("MODE #main +b ~forward:#lobby:u1")
        assert boss.saw(r"MODE #main \+b ~f:#lobby:u1!\*@\*")
        u.send("JOIN #main")
        assert u.saw(r" 470 u1 #main #lobby ") and u.saw(r":u1!\S+ JOIN :?#lobby")
        # +f r#d: the third identical line is dropped
        v = s.client("v1")
        v.say("JOIN #main")
        boss.say("MODE #main +f [2r#d]:30")
        for _ in range(3):
            v.send("PRIVMSG #main :buy now")
        assert v.saw(r" 404 v1 #main :Cannot send to channel \(\+f, repeated message\)")
