"""A real hub + leaf pair (mode "hub" / mode "leaf", as tools/linkmgmt.py writes them -- the Network harness runs every
server as "both"): after each step, both servers must tell an observer the same thing about every channel and user."""
import random, re, time
from harness import Server, Client

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "hubleafpw"


def pair(hub_sec=None, leaf_sec=None):
    hub = Server("hub.test.net", cfg=dict(OPERS, security=hub_sec or {}), sid="1HB")
    leaf = Server("leaf.test.net", cfg=dict(OPERS, security=leaf_sec or {}), sid="2LF")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [{"name": leaf.name, "password": PW, "allowed_ips": ["127.0.0.1"]}]
    leaf.cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    leaf.cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    hub.auto_services = leaf.auto_services = False
    hub.start(); leaf.start()
    return hub, leaf


def query(c, cmd, end):
    """Every reply line to `cmd` up to (and including) numeric `end`."""
    c.drain(0.05)
    c.send(cmd)
    out, deadline = [], time.time() + 4
    while time.time() < deadline:
        c._fill(0.1); c._split()
        while c.lines:
            l = c.lines.pop(0)
            out.append(l)
            if re.search(rf" {end} ", l): return out
    raise AssertionError(f"{cmd}: no {end}; got {out[-5:]}")


def num(lines, n):
    return [l.split(f" {n} ", 1)[1].split(" ", 1)[1] for l in lines if f" {n} " in l]  # drop our own nick


def snapshot(obs, chans, nicks):
    s = {}
    for ch in chans:
        s[ch, "names"] = sorted(w for l in num(query(obs, f"NAMES {ch}", 366), 353) for w in l.split(":", 1)[1].split())
        s[ch, "mode"] = num(query(obs, f"MODE {ch}", "(324|403)"), 324)
        s[ch, "bans"] = sorted(l.split()[1] for l in num(query(obs, f"MODE {ch} b", 368), 367))
        t = query(obs, f"TOPIC {ch}", "(331|332|403|442)")
        s[ch, "topic"] = num(t, 332)
        who = num(query(obs, f"WHO {ch}", 315), 352)
        s[ch, "who"] = sorted(re.sub(r" :\d+ ", " :", w) for w in who)  # hop count differs by side
        s[ch, "list"] = num(query(obs, f"LIST {ch}", 323), 322)
    for n in nicks:
        w = query(obs, f"WHOIS {n}", 318)
        s[n, "whois"] = (num(w, 311), num(w, 312), [sorted(x.split(":", 1)[1].split()) for x in num(w, 319)], num(w, 301), num(w, 401))
    s["users"] = num(query(obs, "LUSERS", 266), 266)[0].split(":")[0] if num(query(obs, "LUSERS", 266), 266) else None
    return s


def same(o1, o2, chans, nicks, timeout=6):
    """Until both observers agree; the diff otherwise."""
    deadline = time.time() + timeout
    while True:
        a, b = snapshot(o1, chans, nicks), snapshot(o2, chans, nicks)
        if a == b: return a
        if time.time() > deadline:
            raise AssertionError("out of sync:\n" + "\n".join(f"  {k}: hub={a.get(k)} leaf={b.get(k)}" for k in a if a.get(k) != b.get(k)))
        time.sleep(0.4)


def test_hub_and_leaf_stay_in_sync():
    hub, leaf = pair()
    try:
        obs_h, obs_l = Client(hub.port, "obsh"), Client(leaf.port, "obsl")
        time.sleep(1.0)
        assert len([l for l in obs_h.say("LINKS", 0.5) if " 364 " in l]) == 2, hub.output()[-1500:]
        a1, a2 = Client(hub.port, "a1"), Client(hub.port, "a2")
        b1, b2 = Client(leaf.port, "b1"), Client(leaf.port, "b2")
        time.sleep(0.5)
        chans, nicks = ["#sync"], ["a1", "a2", "b1", "b2"]

        # channel built from both sides
        a1.say("JOIN #sync", 0.3)
        for c in (b1, b2, a2): c.say("JOIN #sync", 0.2)
        a1.say("MODE #sync +o b1", 0.3)
        b1.say("MODE #sync +ntv b2", 0.3)
        a1.say("TOPIC #sync :from the hub", 0.3)
        b1.say("TOPIC #sync :from the leaf", 0.3)
        b1.say("MODE #sync +b *!*@bad.example", 0.3)
        a1.say("MODE #sync +l 20", 0.3)
        st = same(obs_h, obs_l, chans, nicks)
        assert st["#sync", "topic"] and "from the leaf" in st["#sync", "topic"][0]
        assert "@b1" in st["#sync", "names"] and "+b2" in st["#sync", "names"] and st["#sync", "bans"] == ["*!*@bad.example"]

        # messages, notice, CTCP, away both ways
        a1.say("PRIVMSG #sync :hi all", 0.1); b2.expect(r"PRIVMSG #sync :hi all")
        b2.say("NOTICE a2 :psst", 0.1); a2.expect(r":b2!\S+ NOTICE a2 :psst")
        a2.say("PRIVMSG b1 :\x01PING 123\x01", 0.1); b1.expect(r"PRIVMSG b1 :\x01PING 123\x01")
        b1.say("AWAY :lunch", 0.3)
        a2.send("PRIVMSG b1 :you there?"); a2.expect(r" 301 a2 b1 :lunch")

        # nick change on the leaf, kick from the leaf of a hub user, invite through +i
        b2.say("NICK b2new", 0.3); a1.expect(r":b2!\S+ NICK :?b2new")
        nicks[3] = "b2new"
        b1.say("KICK #sync a2 :out", 0.3); a2.expect(r"KICK #sync a2 :out")
        a1.say("MODE #sync +i", 0.3)
        a2.send("JOIN #sync"); a2.expect(r" 473 ")
        b1.say("INVITE a2 #sync", 0.3); a2.expect(r"INVITE a2 :?#sync")
        a2.send("JOIN #sync"); a2.expect(r":a2!\S+ JOIN :?#sync")
        same(obs_h, obs_l, chans, nicks)

        # oper actions across: KILL a leaf user from the hub, WALLOPS from the leaf
        oh, ol = Client(hub.port, "oh"), Client(leaf.port, "ol")
        oh.say("OPER boss bosspw", 0.6); ol.say("OPER boss bosspw", 0.6)
        oh.say("MODE oh +w", 0.3)
        ol.say("WALLOPS :leaf speaking", 0.1); oh.expect(r"WALLOPS :leaf speaking")
        oh.say("KILL b2new :bye", 0.5); a1.expect(r":b2new!\S+ QUIT ")
        nicks.remove("b2new")
        same(obs_h, obs_l, chans, nicks + ["b2new"])

        # a burst of mixed actions from both sides at once
        rnd = random.Random(7)
        extra = [Client(hub.port, f"h{i}") for i in range(4)] + [Client(leaf.port, f"l{i}") for i in range(4)]
        names = [c.nick for c in extra]
        chans += ["#one", "#two"]
        for c in extra: c.send("JOIN #one,#two")
        time.sleep(0.8)
        for step in range(80):
            i = rnd.randrange(len(extra)); c = extra[i]
            r = rnd.random()
            ch = rnd.choice(["#one", "#two"])
            if r < 0.2: c.send(f"PART {ch}")
            elif r < 0.4: c.send(f"JOIN {ch}")
            elif r < 0.55:
                new = f"{c.nick[0]}n{step}"; c.send(f"NICK {new}"); c.nick = names[i] = new
            elif r < 0.7: c.send(f"TOPIC {ch} :topic {step}")
            elif r < 0.85: c.send(f"MODE {ch} +v {rnd.choice(names)}")
            else: c.send(f"MODE {ch} -v {rnd.choice(names)}")
            time.sleep(0.02)
        time.sleep(1.0)
        for c in extra: c.drain(0.05)
        same(obs_h, obs_l, chans, nicks + names)

        # netsplit: the hub drops the leaf; both sides change things during the split; the leaf redials; they merge
        oh.say(f"SQUIT {leaf.name} :split test", 0.8)
        a1.expect(r":b1!\S+ QUIT ")
        a1.say("TOPIC #sync :changed during the split", 0.2)
        b1.say("MODE #sync +m", 0.2)
        b1.say("PART #two", 0.2)
        deadline = time.time() + 10
        while len([l for l in obs_h.say("LINKS", 0.4) if " 364 " in l]) < 2:
            assert time.time() < deadline, "leaf did not relink:\n" + leaf.output()[-1500:]
            time.sleep(0.3)
        st = same(obs_h, obs_l, chans, nicks + names, timeout=8)
        print("    after relink: #sync", st["#sync", "mode"], st["#sync", "topic"])
        assert "@b1" in st["#sync", "names"]
    finally:
        leaf.stop(); hub.stop()


def test_topic_readable_by_non_members_unless_secret():
    hub, leaf = pair()
    try:
        a, o = Client(hub.port, "a"), Client(leaf.port, "o")
        time.sleep(1.0)
        a.say("JOIN #pub", 0.3); a.say("TOPIC #pub :hello world", 0.5)
        assert any(" 332 o #pub :hello world" in l for l in o.say("TOPIC #pub", 0.5))  # remote, not a member
        assert any(" 442 o #pub " in l for l in o.say("TOPIC #pub :hijack", 0.5))     # changing it still needs membership
        for m in ("+s", "-s+p"):
            a.say(f"MODE #pub {m}", 0.5)
            assert any(" 442 o #pub " in l for l in o.say("TOPIC #pub", 0.5)), m
    finally:
        leaf.stop(); hub.stop()


def test_link_warns_when_cloak_secrets_differ():
    on = {"host_masking": True}
    differ, unset = "differs from ours", "has no [security] host_masking_secret"
    for hs, ls, want in ((dict(on, host_masking_secret="same"), dict(on, host_masking_secret="same"), None),
                         (dict(on, host_masking_secret="one"), dict(on, host_masking_secret="two"), differ),
                         (dict(on, host_masking_secret="one"), dict(on), unset)):
        hub, leaf = pair(hs, ls)
        try:
            time.sleep(1.5)
            assert "linked with server" in hub.output(), hub.output()[-1500:]  # a warning, never a refusal
            for s in (hub, leaf):
                out = s.output()
                assert (want in out) if want else (differ not in out and unset not in out), (want, out[-1500:])
            a, b = Client(hub.port, "ca"), Client(leaf.port, "cb")
            time.sleep(0.5)
            whois = [l for l in b.say("WHOIS ca", 0.5) if " 311 " in l]
            assert whois and "127.0.0.1" not in whois[0], whois  # cloaked, as its own server made it
        finally:
            leaf.stop(); hub.stop()
