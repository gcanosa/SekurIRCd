import re
import time

from harness import Server


def idle_of(asker, nick):
    r = asker.say(f"WHOIS {nick}")
    for l in r:
        m = re.search(rf" 317 \S+ {nick} (\d+) (\d+) ", l)
        if m:
            return int(m.group(1))
    raise AssertionError(f"no 317 for {nick}: {r}")


def test_whois_idle_only_resets_on_privmsg():
    with Server() as s:
        a, b = s.client("alice"), s.client("bob")
        time.sleep(3)
        assert idle_of(b, "alice") >= 3
        # liveness traffic and automatic replies are not "interaction"
        a.send("PING :keepalive")
        a.send("PONG :whatever")
        a.send("NOTICE bob :ctcp-style auto reply")
        a.drain(0.3)
        assert idle_of(b, "alice") >= 3, "PING/PONG/NOTICE reset the idle time"
        # a message that never went anywhere doesn't count either
        a.say("PRIVMSG nosuchnick :hi")
        assert idle_of(b, "alice") >= 3, "a PRIVMSG to a missing nick reset the idle time"
        # a real PRIVMSG does
        a.say("PRIVMSG bob :hello")
        assert idle_of(b, "alice") <= 1


def test_whox_idle_follows_whois_and_honours_hideidle():
    with Server() as s:
        a, b = s.client("alice"), s.client("bob")
        time.sleep(2)
        a.send("PING :x")
        a.drain(0.2)
        r = b.say("WHO alice %nl")
        row = next(l for l in r if " 354 " in l)
        assert int(row.split()[-1]) >= 2, row
        a.say("MODE alice +I")
        r = b.say("WHO alice %nl")
        row = next(l for l in r if " 354 " in l)
        assert row.split()[-1] == "0", row  # +I: not leaked through WHOX either
