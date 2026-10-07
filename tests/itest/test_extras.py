import struct
from harness import Server

OPER = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]},
                      {"name": "second", "password": "secondpw", "hosts": ["*@*"]}]}


def test_no_implicit_names_and_pre_away():
    with Server() as s:
        c = s.client("nn", caps=["draft/no-implicit-names"])
        r = c.say("JOIN #n")
        assert not any(" 353 " in l for l in r), r
        assert any(" 353 " in l for l in c.say("NAMES #n"))
        p = s.client("pa", register=False, caps=["draft/pre-away"])
        p.send("AWAY :out for lunch")
        p.send("NICK pa")
        p.send("USER pa 0 * :x")
        p.expect(r" 001 ")
        w = s.client("viewer")
        assert any(" 301 viewer pa :out for lunch" in l for l in w.say("WHOIS pa")), "away set before registration"


def test_extended_monitor_without_shared_channel():
    with Server() as s:
        watcher = s.client("watcher", caps=["extended-monitor", "away-notify", "setname"])
        target = s.client("target")
        watcher.say("MONITOR + target")
        watcher.drain()
        target.say("AWAY :brb")
        assert watcher.saw(r":target!.* AWAY :brb"), "extended-monitor must deliver AWAY without a shared channel"
        target.say("SETNAME :new real name")
        assert watcher.saw(r":target!.* SETNAME :new real name")


def test_statusmsg_owner_admin_prefix():
    with Server(cfg=OPER) as s:
        boss = s.client("boss")
        boss.say("OPER boss bosspw", 0.8)
        a, b = s.client("own"), s.client("reg")
        a.say("JOIN #sm")
        b.say("JOIN #sm")
        boss.say("SAMODE #sm +q own")
        a.drain(); b.drain()
        a.say("PRIVMSG ~#sm :owners only")
        assert not b.saw(r"owners only", 0.4)
        b.say("PRIVMSG #sm :hello all")
        assert a.saw(r"hello all")


def test_locops_operwall_testline():
    with Server(cfg=OPER) as s:
        boss, other = s.client("boss"), s.client("sec")
        boss.say("OPER boss bosspw", 0.8)
        other.say("OPER second secondpw", 0.8)
        boss.drain(); other.drain()
        boss.send("LOCOPS :local only")
        assert other.saw(r"LOCOPS :local only")
        boss.send("OPERWALL :to all opers")
        assert other.saw(r"GLOBOPS :to all opers|OPERWALL :to all opers")
        boss.say("KLINE nobody@203.0.113.9 1h testing")
        r = boss.say("TESTLINE nobody@203.0.113.9")
        assert any("K-line nobody@203.0.113.9" in l for l in r), r
        assert any("No active line" in l for l in boss.say("TESTLINE 198.51.100.1"))


def test_proxy_protocol_v2_binary_header():
    with Server(cfg={"server": {"proxy_protocol_hosts": ["127.0.0.1"]}}) as s:
        sig = b"\r\n\r\n\x00\r\nQUIT\n"
        hdr = sig + bytes([0x21, 0x11]) + struct.pack(">H", 12) + bytes([198, 51, 100, 77, 10, 0, 0, 1]) + struct.pack(">HH", 40000, 6667)
        c = s.client("v2", register=False)
        c.sock.sendall(hdr + b"NICK v2\r\nUSER v2 0 * :x\r\n")
        c.expect(r" 001 ")
        assert any("198.51.100.77" in l for l in c.say("WHOIS v2"))
