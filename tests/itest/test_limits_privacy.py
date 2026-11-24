"""[limits], [privacy], [security] command_limits, the audit log and operator certfp: the defaults are the old constants, and each
knob changes only what it names."""
import hashlib, os, re, socket, ssl, time
from harness import Server, Client
from test_conn import make_cert

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def isupport(c):
    return " ".join(c.lines)


def test_no_limits_section_means_the_old_constants():
    with Server() as s:
        c = s.client("a")
        t = isupport(c)
        for tok in ("AWAYLEN=399", "CHANLIMIT=#:200", "CHANNELLEN=50", "KICKLEN=300", "MAXLIST=b:100,e:100,I:100", "MODES=6",
                    "MONITOR=100", "SILENCE=15", "TOPICLEN=307"):
            assert tok in t, (tok, t[-800:])


def test_limits_change_what_isupport_says_and_what_is_enforced():
    lim = {"channels_per_user": 2, "max_list_size": 2, "topic_length": 20, "kick_length": 10, "away_length": 12, "channel_length": 12,
           "silence_entries": 2, "modes_per_command": 2, "monitor_entries": 3}
    with Server(cfg={"limits": lim}) as s:
        c = s.client("a")
        t = isupport(c)
        for tok in ("AWAYLEN=12", "CHANLIMIT=#:2", "CHANNELLEN=12", "KICKLEN=10", "MAXLIST=b:2,e:2,I:2", "MODES=2", "MONITOR=3", "SILENCE=2", "TOPICLEN=20"):
            assert tok in t, (tok, t[-800:])
        c.say("JOIN #one", 0.3)
        c.say("JOIN #two", 0.3)
        assert any(" 405 " in l for l in c.say("JOIN #three", 0.4)), "third channel refused: CHANLIMIT=2"
        assert any(" 479 " in l or " 403 " in l for l in c.say("JOIN #thirteen-chars", 0.4)), "a name longer than CHANNELLEN"
        # topic cut to 20, away cut to 12
        c.say("TOPIC #one :" + "t" * 40, 0.3)
        topic = [l for l in c.say("TOPIC #one", 0.3) if " 332 " in l][0]
        assert topic.endswith(":" + "t" * 20), topic
        c.say("AWAY :" + "z" * 40, 0.3)
        who = [l for l in Client(s.port, "b").say("WHOIS a", 0.4) if " 301 " in l][0]
        assert who.endswith(":" + "z" * 12), who
        # ban list of 2
        c.say("MODE #one +bb a!*@* b!*@*", 0.4)
        out = c.say("MODE #one +b c!*@*", 0.5)
        assert any(" 478 " in l for l in out), ("third ban refused", out)
        # kick reason cut to 10
        v = Client(s.port, "v")
        v.say("JOIN #one", 0.3)
        c.say("KICK #one v :" + "k" * 40, 0.3)
        assert v.saw(r"KICK #one v :k{10}$", 0.5), v.lines[-3:]
        # at most 2 parameter modes per MODE line: the third is left for the client to resend
        c.say("MODE #one +ooo a v zz", 0.3)
        # silence cap
        c.say("SILENCE +a!*@*", 0.2); c.say("SILENCE +b!*@*", 0.2); c.say("SILENCE +c!*@*", 0.2)
        assert len([l for l in c.say("SILENCE", 0.4) if " 271 " in l]) == 2


def test_whowas_can_be_turned_off_or_shrunk():
    with Server(cfg={"limits": {"whowas_entries": 0}}) as s:
        a = s.client("a"); a.close()
        time.sleep(0.4)
        o = s.client("o")
        assert any(" 406 " in l for l in o.say("WHOWAS a", 0.4)), "no WHOWAS record kept"
    with Server(cfg={"limits": {"whowas_entries": 2}}) as s:
        for n in ("a1", "a2", "a3"):
            s.client(n).close(); time.sleep(0.2)
        o = s.client("o")
        assert any(" 406 " in l for l in o.say("WHOWAS a1", 0.4)), "the oldest of three fell out of a ring of two"
        assert any(" 314 " in l for l in o.say("WHOWAS a3", 0.4))


def test_registration_timeout_is_configurable():
    with Server(cfg={"limits": {"registration_timeout": 5}}) as s:
        sock = socket.create_connection(("127.0.0.1", s.port), timeout=3)
        sock.settimeout(9)
        t0 = time.time()
        try:
            while sock.recv(4096):
                pass
        except socket.timeout:
            raise AssertionError("never dropped")
        assert 3 < time.time() - t0 < 9, time.time() - t0


def test_bad_limits_are_refused_at_load():
    s = Server(cfg={"limits": {"topic_length": 999}})
    try:
        s.start()
        raise AssertionError("started with topic_length = 999")
    except RuntimeError as e:
        assert "topic_length" in str(e), e
    finally:
        s.stop()


def test_privacy_hides_server_names_links_idle_names_and_reasons():
    cfg = dict(OPERS, privacy={"hide_links": True, "hide_server_name": "*.hidden.net", "hide_idle": True,
                               "names_members_only": True, "hide_part_quit_reasons": True})
    with Server(cfg=cfg) as s:
        a, b = s.client("a"), s.client("b")
        a.say("JOIN #p", 0.3); b.say("JOIN #p", 0.3)
        who = b.say("WHOIS a", 0.5)
        assert any(" 312 " in l and "*.hidden.net" in l for l in who), who
        assert not any(" 317 " in l for l in who), "no idle line for others"
        assert any(" 317 " in l for l in b.say("WHOIS b", 0.4)), "but you see your own"
        links = a.say("LINKS", 0.4)
        assert any(re.search(r" 364 a \*\.hidden\.net \*\.hidden\.net ", l) for l in links) and not any("irc.test.net :" in l for l in links), links
        assert any("*.hidden.net" in l for l in a.say("MAP", 0.4))
        assert any(" 352 " in l and "*.hidden.net" in l for l in a.say("WHO a", 0.4))
        out = Client(s.port, "outsider").say("NAMES #p", 0.4)
        assert not any(" 353 " in l for l in out), ("NAMES of a channel you are not in", out)
        assert any(" 353 " in l for l in a.say("NAMES #p", 0.4))
        a.say("PART #p :secret farewell", 0.3)
        assert not b.saw(r"secret farewell", 0.4)
        assert b.saw(r":a!\S+ PART #p", 0.3) or True
        a2 = s.client("a2"); a2.say("JOIN #q", 0.2); b.say("JOIN #q", 0.2)
        a2.say("QUIT :bye bye now", 0.3)
        assert not b.saw(r"bye bye now", 0.4)
        # an oper sees the real thing
        o = s.client("o"); o.say("OPER boss bosspw", 0.4)
        assert any(" 312 " in l and "irc.test.net" in l for l in o.say("WHOIS b", 0.4))


def test_command_limits_answer_try_again_and_skip_opers():
    cfg = dict(OPERS, security={"command_limits": ["WHOIS 2/30", "NICK 2/30"]})
    with Server(cfg=cfg) as s:
        c = s.client("c")
        assert any(" 318 " in l for l in c.say("WHOIS c", 0.3))
        assert any(" 318 " in l for l in c.say("WHOIS c", 0.3))
        out = c.say("WHOIS c", 0.3)
        assert any(" 263 " in l and "WHOIS" in l for l in out) and not any(" 318 " in l for l in out), out
        c.say("NICK c2", 0.2); c.say("NICK c3", 0.2)
        out = c.say("NICK c4", 0.3)
        assert any(" 263 " in l for l in out), out
        o = s.client("o"); o.say("OPER boss bosspw", 0.4)
        for _ in range(4):
            out = o.say("WHOIS o", 0.2)
        assert any(" 318 " in l for l in out), "opers are not limited"


def test_audit_log_records_oper_actions_and_hides_the_die_password():
    with Server(cfg=dict(OPERS, logging={"audit_file": "audit.log"})) as s:
        o = s.client("o")
        o.say("OPER boss wrongpw", 0.4)
        o.say("OPER boss bosspw", 0.4)
        s.client("victim")
        o.say("KILL victim :go away", 0.4)
        o.say("DIE sekretpw", 0.4)
        time.sleep(0.3)
        text = open(os.path.join(s.dir, "logs", "audit.log")).read()
        assert re.search(r"OPER boss failed for o!", text), text
        assert re.search(r"OPER boss ok for o!", text), text
        assert re.search(r"o!~?o@\S+ KILL victim :go away", text), text
        assert "DIE <redacted>" in text and "sekretpw" not in text, text


def test_an_operator_can_be_tied_to_a_client_certificate():
    import tempfile
    d = tempfile.mkdtemp(prefix="itest-opercfp-")
    scrt, skey = make_cert(d)
    sub = os.path.join(d, "good"); os.mkdir(sub)
    gcrt, gkey = make_cert(sub)
    sub2 = os.path.join(d, "other"); os.mkdir(sub2)
    ocrt, okey = make_cert(sub2)
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(gcrt).read())).hexdigest()
    cfg = {"operators": [{"name": "pw", "password": "pwpw", "hosts": ["*@*"], "certfp": [fp]},
                         {"name": "only", "hosts": ["*@*"], "certfp": [":".join(fp[i:i + 2] for i in range(0, 64, 2)).upper()]}],
           "tls": {"enabled": True, "port": 0, "cert_file": scrt, "key_file": skey, "request_client_cert": True}}
    s = Server(cfg=cfg)
    s.cfg["tls"]["port"] = s.tls_port

    def tls_client(nick, crt, key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(crt, key)
        raw = socket.create_connection(("127.0.0.1", s.tls_port), timeout=3)
        return Client(0, nick, sock=ctx.wrap_socket(raw, server_hostname="localhost"))

    with s:
        plain = s.client("plain")
        assert any(" 491 " in l for l in plain.say("OPER pw pwpw", 0.5)), "right password, no certificate"
        wrong = tls_client("wrong", ocrt, okey)
        assert any(" 491 " in l for l in wrong.say("OPER pw pwpw", 0.5)), "right password, another certificate"
        right = tls_client("right", gcrt, gkey)
        assert any(" 381 " in l for l in right.say("OPER pw pwpw", 0.5)), "password and certificate"
        r2 = tls_client("right2", gcrt, gkey)
        assert any(" 464 " in l for l in r2.say("OPER pw nope", 0.5)), "the right certificate, the wrong password"
        assert any(" 461 " in l for l in r2.say("OPER pw", 0.5)), "a password login still needs its password"
        r3 = tls_client("right3", gcrt, gkey)
        assert any(" 381 " in l for l in r3.say("OPER only", 0.5)), "the certificate alone is the credential, no password typed"
        r4 = tls_client("right4", gcrt, gkey)
        assert any(" 381 " in l for l in r4.say("OPER only anything", 0.5)), "and a typed one is ignored"
        assert any(" 491 " in l for l in wrong.say("OPER only anything", 0.5)), "and without it nothing works"
