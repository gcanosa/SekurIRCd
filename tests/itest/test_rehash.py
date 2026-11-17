"""What /REHASH can change without a restart, and what it keeps (with the reason in its report): the server's name and
SID stay, [logging] moves, an oper whose login is removed is de-opered, a new klines_file is merged in; and the services
daemon reloads services.toml on --rehash (SIGHUP) and keeps its link and bots."""
import json, os, signal, time
from harness import Server, Client

OPERS = [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}, {"name": "temp", "password": "temppw", "hosts": ["*@*"]}]


def test_rehash_applies_or_explains():
    s = Server("irc.test.net", cfg={"operators": OPERS, "security": {"klines_file": "a.json"}})
    s.start()
    try:
        boss, temp = Client(s.port, "boss"), Client(s.port, "temp")
        boss.say("OPER boss bosspw", 0.5); temp.say("OPER temp temppw", 0.5)
        boss.say("KLINE *@192.0.2.1 1h :from a", 0.5)
        with open(os.path.join(s.dir, "b.json"), "w") as f:
            json.dump([{"mask": "*@198.51.100.9", "reason": "from b", "set_by": "x", "line_type": "G", "expires_at": 0}], f)

        s.cfg["server"]["name"] = "renamed.test.net"
        s.cfg["operators"] = OPERS[:1]
        s.cfg["security"]["klines_file"] = "b.json"
        s.cfg["logging"]["file"] = "moved.log"
        s.write_config()
        temp.drain()
        r = boss.say("REHASH", 1.0)
        assert any("server.name stays irc.test.net until a restart" in l for l in r), r
        assert any(l.startswith(":irc.test.net ") for l in boss.say("PING x", 0.3)), "the name must not change live"
        assert any("opers: 1 logged out" in l for l in r), r
        got = temp.drain(0.5)
        assert any(" MODE temp -o" in l or " MODE temp :-o" in l for l in got), got
        assert any(" 481 " in l for l in temp.say("KLINE *@203.0.113.1 :x", 0.3))  # no longer an oper
        listing = boss.say("KLINE", 0.5)
        assert not any(" 481 " in l for l in listing), "boss's login is still there: still an oper"
        lines = " ".join(listing)
        assert "192.0.2.1" in lines and "198.51.100.9" in lines, lines  # ours, plus the new file's
        time.sleep(1.5)  # saved on the next tick
        saved = open(os.path.join(s.dir, "b.json")).read()
        assert "192.0.2.1" in saved and "198.51.100.9" in saved, saved

        boss.say("REHASH", 0.8)  # something to log after the move
        moved = os.path.join(s.dir, "logs", "moved.log")
        assert os.path.exists(moved) and "rehash" in open(moved).read().lower(), "[logging] file did not move"
    finally:
        s.stop()


def test_services_rehash_reloads_and_keeps_what_needs_a_restart():
    s = Server("irc.test.net", cfg={"accounts": {"enabled": True}})
    s.start()
    try:
        svc = s.services
        path = os.path.join(svc.dir, "services.toml")
        conf = open(path).read()
        open(path, "w").write(conf.replace('nick = "ChanServ"', 'nick = "CS2"\nfounder_mode = "q"\nexpire_days = 90'))
        os.kill(svc.proc.pid, signal.SIGHUP)
        time.sleep(1.5)
        assert svc.proc.poll() is None, "SIGHUP must not kill services:\n" + svc.output()[-1500:]
        out = svc.output()
        assert "rehashed" in out and "[chanserv] nick/user/host/realname" in out, out[-1500:]
        c = Client(s.port, "who")
        assert any(" 311 who ChanServ " in l for l in c.say("WHOIS ChanServ", 0.5)), "the bot keeps its nick until a restart"

        open(path, "w").write("[link]\nthis is not toml = = =\n")
        os.kill(svc.proc.pid, signal.SIGHUP)
        time.sleep(1.0)
        assert svc.proc.poll() is None and "rehash failed" in svc.output(), svc.output()[-1000:]
        assert any(" 311 who NickServ " in l for l in c.say("WHOIS NickServ", 0.5))
    finally:
        s.stop()
