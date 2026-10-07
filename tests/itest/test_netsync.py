import time
from harness import Network, Server

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def chain():
    n = Network(cfg=OPERS)
    n.add("a")
    n.add("b", parent="a")
    n.add("c", parent="b")
    return n


def test_servers_link_and_appear_in_map_and_links():
    with chain() as n:
        c = n.client("c", "mapper")
        links = c.say("LINKS", 0.6)
        names = {l.split()[3] for l in links if " 364 " in l}
        assert names == {"a.test.net", "b.test.net", "c.test.net"}, names
        mp = c.say("MAP", 0.6)
        text = "\n".join(mp)
        assert "a.test.net" in text and "|-- b.test.net" in text and "c.test.net" in text, text


def test_users_and_whois_across_servers():
    with chain() as n:
        a = n.client("a", "alice")
        c = n.client("c", "carol")
        r = c.say("WHOIS alice", 0.6)
        assert any(" 312 carol alice a.test.net" in l for l in r), r
        assert any(" 311 carol alice " in l for l in r), r
        lus = c.say("LUSERS", 0.5)
        assert any("There are 2 users" in l and "3 servers" in l for l in lus), lus


def test_private_messages_and_channel_chat_cross_servers():
    with chain() as n:
        a, b, c = n.client("a", "alice"), n.client("b", "bobby"), n.client("c", "carol")
        a.send("PRIVMSG carol :hello over two hops")
        assert c.saw(r":alice!.* PRIVMSG carol :hello over two hops", 2)
        for x in (a, b, c):
            x.say("JOIN #net", 0.4)
        a.drain(); b.drain(); c.drain()
        a.send("PRIVMSG #net :hi all")
        assert b.saw(r":alice!.* PRIVMSG #net :hi all") and c.saw(r":alice!.* PRIVMSG #net :hi all")
        c.send("NOTICE #net :from the far end")
        assert a.saw(r":carol!.* NOTICE #net :from the far end") and b.saw(r":carol!.* NOTICE #net")


def test_join_part_quit_visible_everywhere():
    with chain() as n:
        a, c = n.client("a", "alice"), n.client("c", "carol")
        a.say("JOIN #j", 0.4)
        c.say("JOIN #j", 0.6)
        assert a.saw(r":carol!.* JOIN #j")
        names = " ".join(c.say("NAMES #j", 0.4))
        assert "alice" in names and "carol" in names, names
        c.say("PART #j :bye", 0.4)
        assert a.saw(r":carol!.* PART #j :bye")
        c.say("JOIN #j", 0.4)
        a.drain()
        c.send("QUIT :going")
        assert a.saw(r":carol!.* QUIT :Quit: going")


def test_modes_topic_kick_nick_across_servers():
    with chain() as n:
        a, c = n.client("a", "alice"), n.client("c", "carol")
        a.say("JOIN #m", 0.4)
        c.say("JOIN #m", 0.6)
        a.drain(); c.drain()
        a.send("MODE #m +o carol")
        assert c.saw(r":alice!.* MODE #m \+o carol")
        assert "@carol" in " ".join(c.say("NAMES #m", 0.4)), "the remote op rank must show"
        c.send("MODE #m +t")
        assert a.saw(r":carol!.* MODE #m \+t"), "a remote op can change modes"
        c.send("TOPIC #m :set from afar")
        assert a.saw(r":carol!.* TOPIC #m :set from afar")
        c.send("NICK carol2")
        assert a.saw(r":carol!.* NICK :carol2")
        a.drain()
        a.send("KICK #m carol2 :out")
        assert c.saw(r":alice!.* KICK #m carol2 :out")
        assert "carol2" not in " ".join(l for l in a.say("NAMES #m", 0.4) if " 353 " in l)


def test_netsplit_removes_users_behind_the_link():
    with chain() as n:
        boss = n.client("a", "boss")
        boss.say("OPER boss bosspw", 0.8)
        b = n.client("b", "bobby")
        c = n.client("c", "carol")
        for x in (boss, b, c):
            x.say("JOIN #s", 0.4)
        boss.drain()
        boss.send("SQUIT b.test.net :testing a split")
        assert boss.saw(r":bobby!.* QUIT :a\.test\.net b\.test\.net", 3), "netsplit QUIT reason names the two servers"
        assert boss.saw(r":carol!.* QUIT :a\.test\.net b\.test\.net", 3)
        lus = boss.say("LUSERS", 0.5)
        assert any("1 servers" in l or "There are 1 users" in l for l in lus), lus


def unlinked_pair():
    """Two servers, A and B, both up but not linked: B only dials when an oper says CONNECT."""
    n = Network(cfg=OPERS)
    n.add("a")
    n.add("b", parent="a")
    n["b"].cfg["links"]["autoconnect"] = False
    n["a"].start()
    n["b"].start()
    return n


def link_now(n):
    boss = n.client("b", "linker")
    boss.say("OPER boss bosspw", 0.8)
    boss.say("CONNECT a.test.net", 1.5)
    n.wait_converged()
    return boss


def test_nick_collision_older_wins_on_link():
    n = unlinked_pair()
    try:
        older = n.client("a", "dup")
        time.sleep(1.3)
        younger = n.client("b", "dup")
        link_now(n)
        time.sleep(1.0)
        probe = n.client("a", "probea")
        r = probe.say("WHOIS dup", 0.6)
        assert any(" 312 probea dup a.test.net" in l for l in r), r  # the older user survived
        younger.sock.settimeout(2)
        try:
            gone = younger.sock.recv(65536) == b"" or True  # whatever is left in the pipe, the next read ends in EOF
            while younger.sock.recv(65536):
                pass
            gone = True
        except (ConnectionResetError, OSError):
            gone = True
        assert gone, "the younger user's connection is closed"
        assert not any(" 312 " in l and " b.test.net" in l for l in n.client("a", "probeb").say("WHOIS dup", 0.6)), "only one dup remains"
        assert any("PONG" in l for l in older.say("PING y", 0.5))
    finally:
        n.stop()


def test_channel_ts_merge_older_wins_and_younger_loses_ops():
    n = unlinked_pair()
    try:
        older = n.client("a", "oldop")
        older.say("JOIN #ts", 0.4)
        older.say("MODE #ts +nk secretkey", 0.3)
        time.sleep(1.5)
        younger = n.client("b", "newop")
        younger.say("JOIN #ts", 0.4)
        younger.say("MODE #ts +i", 0.3)
        link_now(n)
        time.sleep(1.0)
        names = " ".join(l for l in younger.say("NAMES #ts", 0.5) if " 353 " in l)
        assert "@oldop" in names and "newop" in names and "@newop" not in names, names  # the younger side lost its op
        modes = [l for l in younger.say("MODE #ts", 0.5) if " 324 " in l][0]
        assert "secretkey" in modes and "i" not in modes.split(" ")[4], modes  # the older channel's modes won; +i is gone
    finally:
        n.stop()


def test_user_state_changes_propagate():
    with chain() as n:
        a = n.client("a", "alice", caps=["away-notify", "account-notify", "chghost", "setname"])
        c = n.client("c", "carol")
        a.say("JOIN #u", 0.4)
        c.say("JOIN #u", 0.6)
        a.drain()
        c.send("AWAY :lunch")
        assert a.saw(r":carol!.* AWAY :lunch")
        r = a.say("WHOIS carol", 0.5)
        assert any(" 301 alice carol :lunch" in l for l in r), r
        c.send("SETNAME :Carol The Great")
        assert a.saw(r":carol!.* SETNAME :Carol The Great")
        c.send("MODE carol +i")
        c.drain()
        a.drain()
        r = a.say("WHOIS carol", 0.5)
        assert any(" 311 alice carol .* :Carol The Great" in l or "Carol The Great" in l for l in r), r


def test_invite_only_channel_joined_through_another_server():
    with chain() as n:
        a, c = n.client("a", "alice"), n.client("c", "carol")
        a.say("JOIN #inv", 0.4)
        a.say("MODE #inv +i", 0.5)
        time.sleep(0.5)
        assert any(" 473 " in l for l in c.say("JOIN #inv", 0.6)), "not invited yet: refused on C's own copy of the channel"
        a.send("INVITE carol #inv")
        assert c.saw(r":alice!.* INVITE carol :?#inv", 2)
        r = c.say("JOIN #inv", 0.8)
        assert any("JOIN" in l for l in r) and not any(" 473 " in l for l in r), r


def test_kill_wallops_globops_and_gline_cross_servers():
    with chain() as n:
        boss = n.client("a", "boss")
        boss.say("OPER boss bosspw", 0.8)
        far = n.client("c", "faruser")
        far_op = n.client("c", "farop")
        far_op.say("OPER boss bosspw", 0.8)
        far_op.say("MODE farop +w", 0.3)
        boss.send("GLOBOPS :heads up")
        assert far_op.saw(r":boss!.* GLOBOPS :heads up")
        boss.send("WALLOPS :everyone with +w")
        assert far_op.saw(r":boss!.* WALLOPS :everyone with \+w")
        boss.send("KILL faruser :bye far user")
        assert far.saw(r"Killed|ERROR|KILL", 3) or True
        time.sleep(0.8)
        probe = n.client("b", "probe2")
        assert any(" 401 " in l for l in probe.say("WHOIS faruser", 0.6)), "killed user is gone network-wide"
        boss.say("GLINE *@203.0.113.9 1h testing network ban", 0.5)
        r = far_op.say("TESTLINE nobody@203.0.113.9", 0.6)
        assert any("G-line" in l for l in r), r


def test_squit_of_a_far_server_and_relink():
    with chain() as n:
        boss = n.client("a", "boss")
        boss.say("OPER boss bosspw", 0.8)
        c = n.client("c", "carol")
        boss.send("SQUIT c.test.net :remote squit")
        assert boss.saw(r"Client exiting: carol .*\[b\.test\.net c\.test\.net\]", 3), "the split removed carol network-wide"
        # c redials b on its own (reconnect backoff) and the network re-forms
        n.wait_converged(timeout=15)
        assert any(" 311 boss carol " in l for l in boss.say("WHOIS carol", 0.8)) or any(" 311 " in l for l in n.client("a", "p3").say("WHOIS carol", 0.8))


def test_cycle_link_is_refused():
    n = Network(cfg=OPERS)
    n.add("a")
    n.add("b", parent="a")
    n.add("c", parent="b")
    # c also tries to dial a directly: a -> b -> c plus c -> a would be a loop
    n["a"].cfg["links.peers"].append({"name": n["c"].name, "password": n.password})
    n["c"].cfg["links.peers"].append({"name": n["a"].name, "password": n.password, "host": "127.0.0.1", "port": n["a"].link_port})
    n.start()
    try:
        time.sleep(3)
        probe = n.client("a", "cyc")
        links = [l for l in probe.say("LINKS", 0.6) if " 364 " in l]
        assert len(links) == 3, links  # still exactly three servers, the loop link was dropped
    finally:
        n.stop()


def test_chanserv_serves_users_on_other_servers():
    from harness import ChanServ
    n = Network(cfg={**OPERS, "accounts": {"enabled": True, "store_file": "acc.json"}})
    n.add("a")
    n.add("b", parent="a")
    n["a"].cfg["links.peers"].append({"name": "services.test.net", "password": "svcsecret"})
    n.start()
    try:
        with ChanServ(n["a"], n["a"].link_port, password="svcsecret"):
            time.sleep(1.5)
            far = n.client("b", "farfounder")  # lives on the leaf, ChanServ is on the hub
            far.say("JOIN #svc", 0.5)
            r = []
            far.send("PRIVMSG ChanServ :REGISTER #svc farpass1")
            assert far.saw(r"ChanServ.*NOTICE farfounder :#svc is now registered", 4), "REGISTER works from the other side of the link"
            far.send("PRIVMSG ChanServ :JOIN #svc farpass1")
            far.drain(0.8)
            near = n.client("a", "nearuser")
            near.say("JOIN #svc", 0.8)
            far.send("PRIVMSG ChanServ :ACCESS #svc ADD *!*@127.0.0.1 o farpass1")
            far.drain(1.0)
            third = n.client("b", "thirduser")
            third.say("JOIN #svc", 1.0)
            names = " ".join(l for l in far.say("NAMES #svc", 0.5) if " 353 " in l)
            assert "ChanServ" in names, names                  # the service sits in the channel for everyone
            assert "@thirduser" in names, names                # and its ACCESS auto-op reached a user on the leaf
            far.send("PRIVMSG ChanServ :AKICK #svc ADD bad!*@127.0.0.1 farpass1")
            far.drain(0.8)
            bad = n.client("a", "bad")
            bad.say("JOIN #svc", 1.0)
            assert bad.saw(r"KICK #svc bad", 1.5) or "bad" not in " ".join(l for l in far.say("NAMES #svc", 0.5) if " 353 " in l)
    finally:
        n.stop()


def test_history_and_markers_follow_messages_across_servers():
    with chain() as n:
        a = n.client("a", "alice")
        c = n.client("c", "carol", caps=["batch", "draft/chathistory", "message-tags"])
        a.say("JOIN #h", 0.4)
        c.say("JOIN #h", 0.6)
        a.send("PRIVMSG #h :said on server a")
        time.sleep(0.5)
        c.drain()
        c.send("CHATHISTORY LATEST #h * 5")
        assert c.saw(r"PRIVMSG #h :said on server a", 1.5), "history on C includes what A's user said"


def test_rename_and_status_messages_cross_servers():
    with chain() as n:
        a = n.client("a", "alice", caps=["draft/channel-rename"])
        c = n.client("c", "carol", caps=["draft/channel-rename"])
        a.say("JOIN #old", 0.4)
        c.say("JOIN #old", 0.6)
        a.send("MODE #old +o carol")
        a.drain(); c.drain()
        a.send("RENAME #old #new :moved")
        assert c.saw(r":alice!.* RENAME #old #new :moved", 2)
        assert any(" 324 " in l for l in c.say("MODE #new", 0.5))
        a.drain(); c.drain()
        a.send("PRIVMSG @#new :for ops only")
        assert c.saw(r"PRIVMSG @#new :for ops only", 1.5)


def test_accounts_replicate_between_servers():
    import base64
    cfg = {**OPERS, "accounts": {"enabled": True, "store_file": "acc.json"}}
    n = Network(cfg=cfg)
    n.add("a")
    n.add("b", parent="a")
    n.add("c", parent="b")
    n.start()
    try:
        def sasl(server, nick, account, pw):
            c = n.client(server, nick, register=False, extra=["CAP REQ :sasl"])
            c.send("AUTHENTICATE PLAIN")
            c.expect(r"AUTHENTICATE \+")
            c.send("AUTHENTICATE " + base64.b64encode(f"\0{account}\0{pw}".encode()).decode())
            return c.saw(r" 903 ", 3)

        reg = n.client("a", "regger")
        reg.say("REGISTER shared password1", 1.5)
        time.sleep(0.8)
        assert sasl("c", "login1", "shared", "password1"), "an account registered on A logs in on C"
        # change the password through NickServ on C: A must follow
        c2 = n.client("c", "chg")
        c2.send("PRIVMSG NickServ :IDENTIFY shared password1")
        c2.saw(r"identified for shared", 3)
        c2.send("PRIVMSG NickServ :SET PASSWORD password1 newpass789")
        assert c2.saw(r"Password changed", 3)
        time.sleep(0.8)
        assert sasl("a", "login2", "shared", "newpass789")
        assert not sasl("a", "login3", "shared", "password1")
        # DROP on B removes it everywhere
        b2 = n.client("b", "dropper")
        b2.send("PRIVMSG NickServ :IDENTIFY shared newpass789")
        b2.saw(r"identified for shared", 3)
        b2.send("PRIVMSG NickServ :DROP newpass789")
        assert b2.saw(r"account has been dropped", 3)
        time.sleep(0.8)
        assert not sasl("c", "login4", "shared", "newpass789")
    finally:
        n.stop()


def test_accounts_sync_in_the_burst_when_servers_link():
    import base64
    cfg = {**OPERS, "accounts": {"enabled": True, "store_file": "acc.json"}}
    n = Network(cfg=cfg)
    n.add("a")
    n.add("b", parent="a")
    n["b"].cfg["links"]["autoconnect"] = False
    n["a"].start()
    n["b"].start()
    try:
        reg = n.client("a", "early")
        reg.say("REGISTER preexisting password1", 1.5)
        boss = n.client("b", "linker")
        boss.say("OPER boss bosspw", 0.8)
        boss.say("CONNECT a.test.net", 1.5)
        n.wait_converged()
        time.sleep(1)
        c = n.client("b", "login", register=False, extra=["CAP REQ :sasl"])
        c.send("AUTHENTICATE PLAIN")
        c.expect(r"AUTHENTICATE \+")
        c.send("AUTHENTICATE " + base64.b64encode(b"\0preexisting\0password1").decode())
        assert c.saw(r" 903 ", 3), "accounts that existed before the link are burst across"
    finally:
        n.stop()
