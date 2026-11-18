"""[[links.peers]] oper_scope / oper_deny: the hub limits what a leaf's opers can reach. A real hub + leaf pair for the
leaf's own refusals and for a rehash lifting the limit; a hand-made leaf speaking the link protocol for the hub's backstop
(what an older or modified leaf would send anyway)."""
import socket, time
from harness import Server, Client

OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}
PW = "scopepw"
LIMIT = "oper_scope"


def pair(**peer_keys):
    hub = Server("hub.test.net", cfg=dict(OPERS), sid="1HB")
    leaf = Server("leaf.test.net", cfg=dict(OPERS), sid="2LF")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port, "reconnect_delay": 1.0}
    hub.cfg["links.peers"] = [dict({"name": leaf.name, "password": PW, "allowed_ips": ["127.0.0.1"]}, **peer_keys)]
    leaf.cfg["links"] = {"enabled": True, "mode": "leaf", "reconnect_delay": 1.0, "reconnect_delay_max": 2.0}
    leaf.cfg["links.peers"] = [{"name": hub.name, "password": PW, "host": "127.0.0.1", "port": hub.link_port}]
    hub.auto_services = leaf.auto_services = False
    hub.start(); leaf.start()
    time.sleep(1.5)
    return hub, leaf


def oper(port, nick):
    c = Client(port, nick)
    c.send("OPER boss bosspw")
    c.expect(r" 381 ")
    return c


def alive(c):
    return any("PONG" in l for l in c.say("PING :alive", 0.5))


def test_leaf_opers_stay_on_their_server():
    hub, leaf = pair(oper_scope="local")
    try:
        op, leafy = oper(leaf.port, "lop"), Client(leaf.port, "leafy")
        hubby, hub2 = Client(hub.port, "hubby"), Client(hub.port, "hub2")
        time.sleep(0.5)
        for cmd in ("KILL hubby :bye", "GLINE *@192.0.2.1 :no", "SHUN *@192.0.2.1 :no", "UNGLINE *@192.0.2.1",
                    "SAJOIN hubby #x", "CHGHOST hubby x.y", "REHASH hub.test.net", "STATS o hub.test.net"):
            out = " ".join(op.say(cmd, 0.5))
            assert "oper_scope = local" in out, (cmd, out)
        assert alive(hubby), "the hub user is still there"
        assert not any("192.0.2.1" in l for l in op.say("GLINE", 0.4)), "the refused G-line was not kept locally either"
        # what stays theirs
        assert any("K-line added" in l for l in op.say("KLINE *@192.0.2.1 :local", 0.5))
        op.say("CHGHOST leafy leaf.vhost", 0.4)
        assert any("leaf.vhost" in l for l in op.say("WHOIS leafy", 0.5)), "CHGHOST on their own user works"
        op.say("KILL leafy :bye", 0.5)
        assert leafy.saw(r"KILL", 1.5), "KILL of their own user works"
        # hub opers keep their reach: nothing here limits the hub's side
        hop = oper(hub.port, "hop")
        lv = Client(leaf.port, "leafy2")
        time.sleep(0.5)
        hop.say("KILL leafy2 :from the hub", 0.8)
        assert lv.saw(r"KILL", 2), "a hub oper reaches leaf users"
        assert alive(hub2)
        # a shared channel with remote members: no SAMODE past its ranks
        hubby.say("JOIN #shared", 0.4); op.say("JOIN #shared", 0.6)
        assert "oper_scope = local" in " ".join(op.say("SAMODE #shared +m", 0.5))
    finally:
        hub.stop(); leaf.stop()


def test_oper_deny_override_and_a_rehash_lifts_it():
    hub, leaf = pair(oper_deny=["override"])
    try:
        op, hubby = oper(leaf.port, "lop"), Client(hub.port, "hubby")
        hubby.say("JOIN #shared", 0.4); op.say("JOIN #shared", 0.8)
        assert any(" 482 " in l for l in op.say("KICK #shared hubby :x", 0.6)), "no override: a plain member can't kick"
        assert alive(hubby)
        # a plain user's own rank still works: the limit is on the oper power, not on the user
        op.say("PRIVMSG #shared :hi", 0.2)
        # lifting it on the hub reaches the linked leaf by itself
        hub.cfg["links.peers"][0].pop("oper_deny")
        hub.reload()
        time.sleep(1.0)
        out = op.say("KICK #shared hubby :now it works", 0.8)
        assert not any(" 482 " in l for l in out) and hubby.saw(r"KICK #shared hubby", 1), out
        # and the other way: the hub adds the limit again
        hub.cfg["links.peers"][0]["oper_deny"] = ["override", "auspex"]
        hub.reload()
        time.sleep(1.0)
        hubby.say("JOIN #shared", 0.4)
        assert any(" 482 " in l for l in op.say("KICK #shared hubby :again", 0.6))
    finally:
        hub.stop(); leaf.stop()


def link_fake(hub, name, pw, sid, uid_nick):
    """A leaf made by hand: links to `hub`, introduces one oper user, returns (socket, that user's UID, the hub user UIDs it was told)."""
    s = socket.create_connection(("127.0.0.1", hub.link_port), timeout=3)
    s.sendall(f"PASS {pw}\r\nCAPAB :SEKURNET\r\nSERVER {name} 1 {sid} :fake\r\n".encode())
    time.sleep(0.8)
    uid = sid + "AAAAAA"
    s.sendall(f":{sid} UID {uid_nick} 1 1700000000 +o fake fake.host fake.host 127.0.0.9 {uid} * 0 :fake oper\r\n:{sid} EOB\r\n".encode())
    time.sleep(0.5)
    return s, uid


def read_all(s, wait=0.6):
    s.settimeout(wait)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors="replace")


def uid_of(burst, nick):
    for l in burst.splitlines():
        t = l.split()
        if len(t) > 10 and t[1] == "UID" and t[2] == nick: return t[10]
    raise AssertionError(f"no UID line for {nick} in {burst[-600:]}")


def test_hub_drops_what_a_limited_leaf_sends_anyway():
    hub = Server("hub.test.net", cfg=dict(OPERS), sid="1HB")
    hub.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": hub.link_port}
    hub.cfg["links.peers"] = [{"name": "fake.test.net", "password": "pw1", "oper_scope": "local"},
                              {"name": "ctl.test.net", "password": "pw2"}]  # the control: the same lines from an unlimited peer must work
    hub.auto_services = False
    hub.start()
    try:
        boss = oper(hub.port, "boss")
        results = {}
        for name, pw, sid in (("fake.test.net", "pw1", "7FK"), ("ctl.test.net", "pw2", "8CT")):
            hubby = Client(hub.port, "hubby" + sid.lower())
            s, uid = link_fake(hub, name, pw, sid, "fop")
            burst = read_all(s)
            if sid == "7FK": assert "OPERSCOPE local -" in burst, burst[-400:]
            else: assert "OPERSCOPE global -" in burst, burst[-400:]
            target = uid_of(burst, "hubby" + sid.lower())
            s.sendall((f":{uid} ENCAP {target} SANICK renamed\r\n"
                       f":{sid} GLINE *@192.0.2.77 fop 0 :lined\r\n"
                       f":{uid} RQUERY 1HB REHASH\r\n"
                       f":{sid} RSQUIT 7ZZ :far away\r\n"
                       f":{uid} KILL {target} :gone\r\n").encode())
            time.sleep(0.8)
            gl = " ".join(boss.say("GLINE", 0.5))
            results[sid] = (hubby.saw(r"NICK :?renamed", 0.5), "192.0.2.77" in gl, hubby.saw(r"KILL", 0.5))
            s.close()
            time.sleep(0.5)
            boss.say("UNGLINE *@192.0.2.77", 0.3)
        assert results["8CT"] == (True, True, True), f"control (unlimited peer) must get all three through: {results}"
        assert results["7FK"] == (False, False, False), f"limited peer: nothing may get through: {results}"
        out = hub.output()
        assert "Refused ENCAP" not in out and "oper_scope = local" in out
        for what in ("SANICK", "KILL", "REHASH", "SQUIT of another server"):
            assert f"Refused {what}" in out, (what, out[-1500:])
    finally:
        hub.stop()


def test_config_checks():
    import subprocess
    from harness import IRCD
    def check(peer):
        s = Server("hub.test.net", cfg=dict(OPERS))
        s.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": s.link_port}
        s.cfg["links.peers"] = [dict({"name": "a.test.net", "password": "pw"}, **peer)]
        s.write_config()
        try:
            r = subprocess.run([IRCD, "-c", s.cfg_path, "--check"], capture_output=True, text=True, cwd=s.dir)
            return r.returncode, r.stdout + r.stderr
        finally:
            s.stop()
    assert check({"oper_scope": "local", "oper_deny": ["override", "auspex", "all"]})[0] == 0
    rc, out = check({"oper_scope": "regional"}); assert rc != 0 and "oper_scope" in out, out
    rc, out = check({"oper_deny": ["telepathy"]}); assert rc != 0 and "telepathy" in out, out
    rc, out = check({"host": "x.example", "port": 7000, "oper_scope": "local"}); assert rc != 0 and "oper_scope" in out, out
