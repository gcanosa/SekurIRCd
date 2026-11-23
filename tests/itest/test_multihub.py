"""Two hubs, each with two leaves, as a real deployment writes them: h1 is mode "hub" (accepts), h2 is mode "both" (dials h1 and
accepts its own leaves), the leaves are mode "leaf". Every server must tell an observer the same thing, across the hub-to-hub link
and through a split of it; opers, G-lines, spam filters and accounts must cross both hubs; a second route into the tree (a loop) is
refused without disturbing the network.
          l1a   l1b        l2a   l2b
            \\   /            \\   /
             h1 ------------- h2           (services, when a test wants them, link to h1)"""
import base64, os, time
import harness
from harness import Server, Client
from test_hubleaf import snapshot, query, num
from test_star import oper, linked

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "multihubpw"
ORDER = ["h1", "h2", "l1a", "l1b", "l2a", "l2b"]


def build(services=False, extra=None, l2a_peer=None, skip=(), old=None):
    old = old if old is not None else [n for n in os.environ.get("OLD_SERVERS", "").split(",") if n]
    """-> {name: Server}, all started. `extra[name]` is merged into that server's cfg; the servers in `old` run the binary
    named by $OLD_IRCD_BIN (a build of the version in production) instead of this tree's."""
    extra = extra or {}
    sids = dict(zip(ORDER, ["1H1", "2H2", "3LA", "4LB", "5LC", "6LD"]))
    s = {}
    for n in [n for n in ORDER if n not in skip]:
        cfg = dict(OPERS, **extra.get(n, {}))
        if services and n == "h1":
            cfg["accounts"] = {"enabled": True, "store_file": "acc.json"}
        s[n] = Server(f"{n}.test.net", cfg=cfg, sid=sids[n])
        s[n].auto_services = services and n == "h1"
    h1, h2 = s["h1"], s["h2"]
    h1.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": h1.link_port, "reconnect_delay": 1.0}
    h1.cfg["links.peers"] = [{"name": h2.name, "password": PW}] + [{"name": s[n].name, "password": PW} for n in ("l1a", "l1b") if n in s]
    h2.cfg["links"] = {"enabled": True, "mode": "both", "bind": "127.0.0.1", "port": h2.link_port, "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    h2.cfg["links.peers"] = [{"name": h1.name, "password": PW, "host": "127.0.0.1", "port": h1.link_port},
                             dict({"name": s["l2a"].name, "password": PW, "oper_scope": "local"}, **(l2a_peer or {})),
                             {"name": s["l2b"].name, "password": PW}]
    for leaf, hub in (("l1a", h1), ("l1b", h1), ("l2a", h2), ("l2b", h2)):
        if leaf in s:
            s[leaf].cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
            s[leaf].cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    new_bin = harness.IRCD
    try:
        for n in s:
            harness.IRCD = os.environ["OLD_IRCD_BIN"] if n in old else new_bin
            s[n].start()
    except Exception:
        stop(s)
        raise
    finally:
        harness.IRCD = new_bin
    return s


def stop(s):
    for srv in reversed(list(s.values())):
        try:
            srv.stop()
        except AssertionError:
            pass


def observers(s, want=None):
    want = want or len(s)
    obs = {n: Client(s[n].port, f"obs{n}") for n in s}
    for o in obs.values():
        linked(o, want, 15)
    return obs


def agree(obs, chans, nicks, timeout=10):
    """Until every observer snapshot matches the first (LUSERS' running maximum differs per server and is left out)."""
    deadline = time.time() + timeout
    while True:
        snaps = {n: snapshot(o, chans, nicks) for n, o in obs.items()}
        for sn in snaps.values():
            sn.pop("users", None)
        ref = next(iter(snaps.values()))
        bad = {n: {k: (ref.get(k), v.get(k)) for k in set(ref) | set(v) if ref.get(k) != v.get(k)} for n, v in snaps.items() if v != ref}
        if not bad:
            return ref
        if time.time() > deadline:
            raise AssertionError("servers disagree: " + str(bad))
        time.sleep(0.5)


def test_two_hubs_stay_in_sync_and_survive_a_hub_split():
    s = build()
    try:
        obs = observers(s)
        u = {n: Client(s[n].port, f"u{n}") for n in ORDER}
        time.sleep(0.6)
        chans, nicks = ["#m"], [f"u{n}" for n in ORDER]
        u["h1"].say("JOIN #m", 0.3)
        for n in ORDER[1:]:
            u[n].say("JOIN #m", 0.2)
        u["h1"].say("MODE #m +o ul2b", 0.4)  # an op at the far end of the tree
        u["l2b"].say("TOPIC #m :set four hops away", 0.3)
        u["l2b"].say("MODE #m +b *!*@bad.example", 0.3)
        u["l2b"].say("MODE #m +ov ul1a ul1b", 0.3)
        u["l2b"].say("MODE #m +l 20", 0.3)
        st = agree(obs, chans, nicks)
        assert "four hops" in st["#m", "topic"][0] and st["#m", "bans"] == ["*!*@bad.example"], st
        assert "@ul1a" in st["#m", "names"] and "+ul1b" in st["#m", "names"] and "@ul2b" in st["#m", "names"]

        # chat, notice, CTCP and away across the hub-to-hub link, both directions
        u["l1a"].say("PRIVMSG #m :hello from l1a", 0.2)
        for n in ("h2", "l2a", "l2b"):
            assert u[n].saw("hello from l1a", 2), n
        u["l2a"].say("PRIVMSG ul1b :\x01PING 1\x01", 0.2)
        assert u["l1b"].saw(r"PING 1", 2)
        u["l1b"].say("AWAY :lunch", 0.3)
        u["l2a"].send("PRIVMSG ul1b :you there?")
        u["l2a"].expect(r" 301 ul2a ul1b :lunch")
        u["l2a"].say("NICK renamed", 0.3)
        nicks[nicks.index("ul2a")] = "renamed"
        u["l2b"].say("KICK #m ul1a :out", 0.3)
        u["h1"].say("MODE #m +i", 0.3)
        u["l1a"].send("JOIN #m"); u["l1a"].expect(r" 473 ")
        u["l2b"].say("INVITE ul1a #m", 0.3)
        u["l1a"].send("JOIN #m"); u["l1a"].expect(r":ul1a!\S+ JOIN :?#m")
        agree(obs, chans, nicks)

        # the hubs split: each side keeps working and changes things, including a channel created on both sides
        oh = oper(s["h1"].port, "oh1")
        oh.say("SQUIT h2.test.net :hub split", 0.8)
        assert u["l1a"].saw(r"QUIT :h1.test.net h2.test.net", 3), "h1's side sees h2's side leave"
        assert u["l2b"].saw(r"QUIT :h2.test.net h1.test.net", 3), "and the other way"
        u["h1"].say("TOPIC #m :h1 side", 0.2)
        u["l2b"].say("MODE #m +m", 0.2)
        u["l1a"].say("JOIN #both", 0.4)
        time.sleep(1.3)  # a later timestamp on the other side
        u["l2b"].say("JOIN #both", 0.4)
        u["l2b"].say("JOIN #only2", 0.3)
        u["l1b"].say("JOIN #only1", 0.3)
        deadline = time.time() + 20
        while any(len(num(query(o, "LINKS", 365), 364)) < 6 for o in obs.values()):
            assert time.time() < deadline, "h2 did not relink:\n" + s["h2"].output()[-1500:]
            time.sleep(0.4)
        chans += ["#both", "#only1", "#only2"]
        st = agree(obs, chans, nicks, timeout=12)
        assert "@ul1a" in st["#both", "names"] and "ul2b" in st["#both", "names"], ("older channel wins the merge", st["#both", "names"])
        u["l2b"].say("PRIVMSG ul1a :after the relink", 0.2)
        assert u["l1a"].saw("after the relink", 2)

        # a leaf under h2 splits while the hubs stay linked: h1's side sees it go, then come back the same
        oh.say("SQUIT l2a.test.net :leaf split", 0.8)
        assert u["l1b"].saw(r"QUIT :h2.test.net l2a.test.net", 4), "a leaf of the other hub leaving is seen through both hubs"
        for o in obs.values():
            linked(o, 6, 15)
        agree(obs, chans, [n for n in nicks if n != "renamed"])
    finally:
        stop(s)


def test_opers_and_bans_cross_both_hubs():
    s = build()
    try:
        obs = observers(s)
        victim, bystander, far = Client(s["l1b"].port, "victim"), Client(s["l2a"].port, "bystander"), Client(s["l2b"].port, "far")
        bystander.say("JOIN #q", 0.2); far.say("JOIN #q", 0.3)  # a QUIT only reaches users who share a channel
        time.sleep(0.5)
        o1, o2, o3, oh = oper(s["l1a"].port, "o1"), oper(s["l2a"].port, "o2"), oper(s["l2b"].port, "o3"), oper(s["h1"].port, "oh1")
        ops = {n: oper(s[n].port, f"op{n}") for n in ORDER}  # STATS g is for opers
        time.sleep(0.5)

        def glines(n):
            return " ".join(l for l in ops[n].say("STATS g", 0.6) if " 216 " in l)
        # l2a is limited by h2 (oper_scope = local): it can't reach l1b, two hubs away
        assert "oper_scope = local" in " ".join(o2.say("KILL victim :no", 0.7))
        assert any("PONG" in l for l in victim.say("PING :x", 0.4)), "victim survived a limited oper"
        o2.say("GLINE *@198.51.100.7 :limited", 0.5)
        for n in ("h1", "l1a", "l1b", "l2b"):
            assert "198.51.100.7" not in glines(n), f"a limited leaf's G-line reached {n}"
        # l2b (global) is also under h2, and reaches everything
        o3.say("GLINE *@203.0.113.9 :from l2b", 0.7)
        for n in ("h1", "h2", "l1a", "l1b", "l2a"):
            assert "203.0.113.9" in glines(n), f"G-line missing on {n}"
        o1.say("UNGLINE *@203.0.113.9", 0.7)  # lifted from the far side of the tree
        for n in ("h1", "h2", "l1b", "l2a", "l2b"):
            assert "203.0.113.9" not in glines(n), f"UNGLINE did not reach {n}"
        o3.say("KILL victim :from far", 0.8)
        assert victim.saw(r"KILL|Killed|Closing", 3), "a global oper under h2 kills a user under h1"
        # an oper on h1 squits a leaf two hops away (RSQUIT through h2); it redials
        oh.say("SQUIT l2b.test.net :far squit", 0.8)
        assert bystander.saw(r"QUIT :h2.test.net l2b.test.net", 4)
        for o in obs.values():
            linked(o, 6, 15)
    finally:
        stop(s)


def test_global_spam_filters_cross_hubs():
    on, off = {"enabled": True, "filters_enabled": True}, {"enabled": False, "filters_enabled": True}
    s = build(extra={"l1a": {"spam": on}, "l2b": {"spam": off}})
    try:
        observers(s)
        a, rx, u = oper(s["l1a"].port, "adder"), Client(s["h1"].port, "rx"), Client(s["l2b"].port, "u1")
        rx.say("JOIN #h", 0.2); u.say("JOIN #h", 0.3)
        out = " ".join(a.say("SPAMFILTER ADD GLOBAL c block - ad :buyspam", 0.8))
        assert "Global spam filter added" in out, out
        time.sleep(1.0)
        l2b_op = oper(s["l2b"].port, "l2bop")
        assert any("[global" in l for l in l2b_op.say("SPAMFILTER", 0.6)), "listed on the far leaf, marked global"
        u.say("PRIVMSG #h :buyspam now", 0.6)
        assert not rx.saw(r"buyspam", 0.8), "a leaf of the other hub, with [spam] off, is bound by it"
        # removed on the far leaf's side: the owner (l1a) drops it, everywhere
        l2b_op.say("SPAMFILTER DEL 1", 0.8)
        time.sleep(1.0)
        u.say("PRIVMSG #h :buyspam again", 0.4)
        assert rx.saw(r"buyspam again", 2), "deleting it on l2b made the owner drop it"
    finally:
        stop(s)


def test_services_serve_the_whole_tree_and_come_back_after_a_hub_split():
    # no l1b: every link to h1 comes from 127.0.0.1 here, and a hub takes at most 3 links per source address (h2, l1a, services)
    s = build(services=True, skip=("l1b",))
    try:
        obs = {n: Client(srv.port, f"obs{n}") for n, srv in s.items()}  # the services daemon shows in h1's LINKS only
        for n, o in obs.items():
            linked(o, 6 if n == "h1" else 5, 15)

        def sasl(server, nick, account, pw):
            c = Client(s[server].port, nick, register=False, extra=["CAP REQ :sasl"])
            c.send("AUTHENTICATE PLAIN"); c.expect(r"AUTHENTICATE \+")
            c.send("AUTHENTICATE " + base64.b64encode(f"\0{account}\0{pw}".encode()).decode())
            ok = c.saw(r" 903 ", 3)
            if ok:  # finish registering and stay connected
                c.send("CAP END"); c.send(f"NICK {nick}"); c.send(f"USER {nick} 0 * :t")
                c.expect(r" 001 ", 5)
            return ok, c

        reg = Client(s["l1a"].port, "regger")
        reg.say("REGISTER shared password1", 1.5)
        time.sleep(0.8)
        ok, login1 = sasl("l2b", "login1", "shared", "password1")
        assert ok, "an account registered under h1 logs in under h2 (SASL through two hubs)"
        time.sleep(0.5)
        w = Client(s["l2a"].port, "watcher").say("WHOIS login1", 0.6)
        assert any(" 330 " in l and "shared" in l for l in w), ("the account shows on a server three hops from services", w)
        ns = Client(s["l2a"].port, "nsuser")
        ns.send("PRIVMSG NickServ :IDENTIFY shared password1")
        assert ns.saw(r"identified for shared", 3), "NickServ answers a user under h2"

        # the hubs split: h2's side loses services (no SASL offered), and gets them back on relink
        oper(s["h1"].port, "oh1").send("SQUIT h2.test.net :split")
        gone, end = False, time.time() + 4  # h2 redials within a second: catch the window in which it has no services
        while not gone and time.time() < end:
            probe = Client(s["l2b"].port, "capprobe", register=False)
            gone = "sasl" not in " ".join(probe.say("CAP LS 302", 0.15)).lower()
            probe.close()
        assert gone, "while the hubs are split, h2's side has no services (no SASL offered)"
        deadline = time.time() + 20
        while any(len(num(query(o, "LINKS", 365), 364)) < 5 for o in obs.values()):
            assert time.time() < deadline, "h2 did not relink"
            time.sleep(0.4)
        time.sleep(1.0)
        ok, login2 = sasl("l2b", "login2", "shared", "password1")
        assert ok, "SASL works under h2 again after the relink"
    finally:
        stop(s)


def test_a_second_route_into_the_tree_is_refused_and_harms_nothing():
    s = build()
    h3 = Server("h3.test.net", cfg=dict(OPERS), sid="7H3")
    h3.auto_services = False
    h3.cfg["links"] = {"enabled": True, "mode": "both", "bind": "127.0.0.1", "port": h3.link_port, "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    h3.cfg["links.peers"] = [{"name": s["h1"].name, "password": PW, "host": "127.0.0.1", "port": s["h1"].link_port},
                             {"name": s["h2"].name, "password": PW, "host": "127.0.0.1", "port": s["h2"].link_port}]
    for n in ("h1", "h2"):  # both hubs let h3 in: h3 dials both, and one of the two is a loop
        s[n].cfg["links.peers"].append({"name": h3.name, "password": PW})
        s[n].reload()
    try:
        h3.start()
        s["h3"] = h3
        time.sleep(5)
        obs = {n: Client(srv.port, f"obs{n}") for n, srv in s.items()}
        for n, o in obs.items():
            got = len(num(query(o, "LINKS", 365), 364))
            assert got == 7, f"{n} lists {got} servers, not 7 (a loop or a lost link):\n" + s[n].output()[-800:]
        a, z = Client(s["l1a"].port, "alpha"), Client(s["l2b"].port, "omega")
        h = Client(h3.port, "three")
        a.say("JOIN #loop", 0.2); z.say("JOIN #loop", 0.2); h.say("JOIN #loop", 0.3)
        a.say("PRIVMSG #loop :still one tree", 0.2)
        assert z.saw("still one tree", 2) and h.saw("still one tree", 2)
        agree(obs, ["#loop"], ["alpha", "omega", "three"])
        import glob
        logs = [open(f).read() for srv in s.values() for f in glob.glob(srv.dir + "/logs/*")] + [srv.output() for srv in s.values()]
        print("    refusals:", sorted({l.split("] ", 1)[-1][:110] for t in logs for l in t.splitlines() if "already exists" in l or "loop" in l.lower()})[:4])
    finally:
        stop(s)
