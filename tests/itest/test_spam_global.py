"""Global spam filters: a rule added on one server (SPAMFILTER ADD GLOBAL, or a `global` line in spamfilters.conf) is enforced
on every linked server, even where [spam] is off; the global rules are checked before a server's own, so a leaf can't undo
one (the exception is a global `allow` ahead of it on the hub); a relink restores them; a leaf the hub limits to its own
server (oper_scope = local) can't publish one."""
import re, time
from harness import Server, Client

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "spamglobalpw"
ON = {"enabled": True, "filters_enabled": True}
OFF = {"enabled": False, "filters_enabled": True}  # the module off on that server


def pair(leaf_spam, **peer_keys):
    hub = Server("hub.test.net", cfg=dict(OPERS, spam=dict(ON)), sid="1HB")
    leaf = Server("leaf.test.net", cfg=dict(OPERS, spam=dict(leaf_spam)), sid="2LF")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [dict({"name": leaf.name, "password": PW, "allowed_ips": ["127.0.0.1"]}, **peer_keys)]
    leaf.cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    leaf.cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    hub.auto_services = leaf.auto_services = False
    hub.start(); leaf.start()
    time.sleep(1.5)
    return hub, leaf


def oper(srv, nick):
    c = Client(srv.port, nick)
    c.send("OPER boss bosspw")
    c.expect(r" 381 ")
    return c


def delivered(sender, rx, text, wait=1.0):
    """Does `text`, sent to #h by `sender`, reach `rx`? (rx and sender are on different servers.)"""
    sender.send(f"PRIVMSG #h :{text}")
    return bool(rx.saw(rf"PRIVMSG #h :{text}", wait))


def test_a_global_rule_binds_a_leaf_that_has_spam_off():
    hub, leaf = pair(OFF)
    try:
        hop, lop = oper(hub, "hop"), oper(leaf, "lop")
        out = " ".join(hop.say("SPAMFILTER ADD GLOBAL pcnN block - hosting_ad :vps.*promo", 0.8))
        assert "Global spam filter added" in out, out
        rx, u = Client(hub.port, "rx"), Client(leaf.port, "u1")
        rx.say("JOIN #h"); u.say("JOIN #h")
        time.sleep(0.5)
        assert any("hub.test.net" in l and "[global" in l for l in lop.say("SPAMFILTER", 0.6)), "listed on the leaf, marked global"
        r = u.say("PRIVMSG #h :Action VPS 1GB PROMO now", 0.6)
        assert any("blocked" in l and "hosting ad" in l for l in r), r
        assert not rx.saw(r"PROMO", 0.5), "the hub user never saw it"
        assert delivered(u, rx, "just chatting"), "other text still goes through"
        # the hub removes it: the leaf lets it through again
        assert "removed" in " ".join(hop.say("SPAMFILTER DEL 1", 0.6))
        time.sleep(0.6)
        assert delivered(u, rx, "vps promo after delete"), "removing it on the hub removes it on the leaf"
        assert not any(re.search(r":#\d+ .*hosting ad", l) for l in lop.say("SPAMFILTER", 0.5)), "and from the leaf's list"
    finally:
        hub.stop(); leaf.stop()


def test_global_rules_come_first_a_leaf_cannot_undo_them_and_a_relink_restores_the_set():
    hub, leaf = pair(ON)
    try:
        hop, lop = oper(hub, "hop"), oper(leaf, "lop")
        hop.say("SPAMFILTER ADD GLOBAL c block - ad :buyspam", 0.6)
        hop.say("SPAMFILTER ADD GLOBAL c block - ad2 :cheapstuff", 0.6)
        rx, u = Client(hub.port, "rx"), Client(leaf.port, "u1")
        rx.say("JOIN #h"); u.say("JOIN #h")
        time.sleep(0.5)
        assert not delivered(u, rx, "buyspam here")
        assert not delivered(u, rx, "cheapstuff here")
        # the leaf's own `allow` does not undo the hub's rule: the hub's rules are checked first
        lop.say("SPAMFILTER ADD c allow - ok :buyspam", 0.6)
        assert not delivered(u, rx, "buyspam here"), "a leaf's allow can't override the hub's rule"
        assert not delivered(u, rx, "cheapstuff here")
        out = lop.say("SPAMFILTER", 0.6)
        assert any("#1 [global from hub.test.net]" in l for l in out) and any("#3 " in l and "allow" in l for l in out), \
            ("listed in the order they are checked: the hub's rules, then the leaf's own", out)
        # its own rules still add to the hub's
        lop.say("SPAMFILTER ADD c block - mine :localword", 0.6)
        assert not delivered(u, rx, "a localword here"), "the leaf's own rule works next to the global ones"
        # the exception is made on the hub: a global allow ahead of the block (delete the block, add allow, add the block back)
        hop.say("SPAMFILTER DEL 1", 0.6)
        hop.say("SPAMFILTER ADD GLOBAL c allow - friends :buyspam for friends", 0.6)
        hop.say("SPAMFILTER ADD GLOBAL c block - ad :buyspam", 0.6)
        time.sleep(0.6)
        assert delivered(u, rx, "buyspam for friends"), "the hub's allow lets that text through on the leaf"
        assert not delivered(u, rx, "buyspam here"), "and the block still bites the rest"
        # the leaf restarts: the hub's burst brings the set back, in order (the leaf's own rules are in its file)
        u.close(); lop.close()
        leaf.restart()
        time.sleep(2.5)
        u = Client(leaf.port, "u2")
        u.say("JOIN #h")
        time.sleep(0.5)
        assert not delivered(u, rx, "cheapstuff after relink"), "global rule back after the leaf restarted"
        assert delivered(u, rx, "buyspam for friends"), "the hub's allow came back too"
        assert not delivered(u, rx, "buyspam after relink")
        assert not delivered(u, rx, "a localword after relink"), "and the leaf's own rule came back from its file"
    finally:
        hub.stop(); leaf.stop()


def test_a_global_line_in_the_file_is_published_on_rehash():
    hub, leaf = pair(ON)
    try:
        import os
        with open(os.path.join(hub.dir, "spamfilters.conf"), "a") as f:
            f.write('global pc block - "from the file" fileword\n')
        hub.reload()
        time.sleep(0.8)
        rx, u = Client(hub.port, "rx"), Client(leaf.port, "u1")
        rx.say("JOIN #h"); u.say("JOIN #h")
        time.sleep(0.5)
        assert not delivered(u, rx, "has fileword inside"), "a `global` line reached the leaf"
        assert delivered(u, rx, "plain words"), "the rest is untouched"
    finally:
        hub.stop(); leaf.stop()


def test_a_limited_leaf_cannot_publish_a_global_rule():
    hub, leaf = pair(ON, oper_scope="local")
    try:
        lop, hop = oper(leaf, "lop"), oper(hub, "hop")
        out = " ".join(lop.say("SPAMFILTER ADD GLOBAL c block - ad :buyspam", 0.8))
        assert "oper_scope = local" in out, out
        hop.say("SPAMFILTER ADD GLOBAL c block - hubad :hubword", 0.6)
        time.sleep(0.5)
        out = " ".join(lop.say("SPAMFILTER DEL 1", 0.6))
        assert "oper_scope = local" in out, ("a limited leaf can't delete the hub's rule", out)
        assert any("hubad" in l for l in hop.say("SPAMFILTER", 0.5)), "it is still on the hub"
        # a plain local rule still works there (the hub drop of a leaf that publishes anyway is the last test)
        lop.say("SPAMFILTER ADD c block - ad :buyspam", 0.6)
        rx, u = Client(hub.port, "rx"), Client(leaf.port, "u1")
        rx.say("JOIN #h"); u.say("JOIN #h")
        time.sleep(0.5)
        assert not delivered(u, rx, "buyspam here"), "its own local rule works on the leaf"
        hub_side = Client(hub.port, "hubby")
        hub_side.say("JOIN #h")
        assert delivered(hub_side, u, "buyspam from the hub"), "and did not spread to the hub"
    finally:
        hub.stop(); leaf.stop()


def test_hub_drops_global_rules_from_a_limited_peer_but_takes_an_unlimited_ones():
    from test_oper_scope import link_fake
    hub = Server("hub.test.net", cfg=dict(OPERS, spam=dict(ON)), sid="1HB")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port}
    hub.cfg["links.peers"] = [{"name": "fake.test.net", "password": "pw1", "oper_scope": "local"},
                              {"name": "ctl.test.net", "password": "pw2"}]  # the control: the same lines from an unlimited peer must work
    hub.auto_services = False
    hub.start()
    try:
        got = {}
        for name, pw, sid in (("fake.test.net", "pw1", "7FK"), ("ctl.test.net", "pw2", "8CT")):
            word = "word" + sid.lower()
            s, uid = link_fake(hub, name, pw, sid, "fop")
            s.sendall(f':{sid} SPAMFILTER CLEAR\r\n:{sid} SPAMFILTER ADD :pc block - "x" {word}\r\n'.encode())
            time.sleep(0.6)
            u = Client(hub.port, "hubby" + sid.lower())
            u.say("JOIN #h", 0.3)
            got[sid] = any("blocked" in l for l in u.say(f"PRIVMSG #h :a {word} b", 0.6))
            s.close()
            time.sleep(0.5)
        assert got == {"7FK": False, "8CT": True}, got
    finally:
        hub.stop()


def test_two_hubs_share_their_global_rules_with_each_others_leaves():
    from harness import Network
    net = Network(cfg=dict(OPERS, spam=dict(ON)))
    h1 = net.add("h1"); h2 = net.add("h2", parent="h1")
    l1 = net.add("l1", parent="h1", cfg={"spam": dict(OFF)}); l2 = net.add("l2", parent="h2", cfg={"spam": dict(OFF)})
    for srv in (h1, h2, l1, l2): srv.auto_services = False
    net.start()
    try:
        o1, o2 = oper(h1, "op1"), oper(h2, "op2")
        rx1, rx2 = Client(h1.port, "rx1"), Client(h2.port, "rx2")
        u1, u2 = Client(l1.port, "u1"), Client(l2.port, "u2")
        for c in (rx1, rx2, u1, u2): c.say("JOIN #h", 0.2)
        time.sleep(0.5)
        # added on one hub: both hubs and both leaves enforce it, the leaves with their [spam] off
        assert "added" in " ".join(o2.say("SPAMFILTER ADD GLOBAL c block - from_h2 :h2word", 0.8))
        time.sleep(0.6)
        assert not delivered(u1, rx2, "has h2word in it"), "h2's rule reached h1's leaf"
        assert not delivered(u2, rx1, "has h2word in it"), "and its own leaf"
        assert any("[global from h2.test.net]" in l for l in o1.say("SPAMFILTER", 0.5)), "h1 lists it, marked with its owner"
        # added on the other hub
        o1.say("SPAMFILTER ADD GLOBAL c block - from_h1 :h1word", 0.8)
        time.sleep(0.6)
        assert not delivered(u2, rx1, "has h1word in it"), "h1's rule reached h2's leaf"
        # either hub can delete either's rule: h1's oper removes h2's, and it goes everywhere
        lines = o1.say("SPAMFILTER", 0.5)
        num = next(l.split("#")[1].split()[0] for l in lines if "[global from h2.test.net]" in l)
        out = " ".join(o1.say(f"SPAMFILTER DEL {num}", 0.8))
        assert "h2.test.net was asked" in out, out
        time.sleep(0.8)
        assert delivered(u1, rx2, "has h2word in it"), "removed on h1's leaf"
        assert delivered(u2, rx1, "has h2word in it"), "removed on h2's leaf: the owner dropped it and told everyone"
        assert not any("from_h2" in l or "from h2" in l for l in o2.say("SPAMFILTER", 0.5)), "gone from h2's own list and file"
        assert not delivered(u2, rx1, "still h1word here"), "h1's own rule is untouched"
    finally:
        net.stop()
