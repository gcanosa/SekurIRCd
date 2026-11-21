"""[nickserv] expire_days: an account nobody logged in to for that long is dropped at the next hourly check (the first one
runs at startup), and leaves its channels as founder, =account access entry and successor, so nobody inherits them by
registering the name again. Admins, NOEXPIRE, suspended accounts and accounts in use never expire; an account with no
login on record starts its clock instead."""
import hashlib, json, os, secrets, time
from harness import Server, Services, SVC_NAME, SVC_PW
from test_accounts2 import ns
from test_chanserv2 import cs

DAY = 86400


def scrypt_hash(pw):  # the services' password format
    salt = secrets.token_bytes(16)
    d = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, dklen=64, maxmem=32 * 1024 * 1024)
    return f"scrypt$16384$8$1${salt.hex()}${d.hex()}"


def test_unused_accounts_expire_and_leave_their_channels():
    s = Server(cfg={"links": {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": 0}})
    s.cfg["links"]["port"] = s.link_port
    s.cfg["links.peers"] = [{"name": SVC_NAME, "password": SVC_PW}]
    s.auto_services = False
    now, old = int(time.time()), int(time.time()) - 100 * DAY
    with s:
        acc_path = os.path.join(s.dir, "acc.json")
        acc = {}
        for name, extra in (("olduser", {}), ("frozen", {"noexpire": True}), ("boss", {}), ("keeper", {"last_login_at": now}),
                            ("banned", {"suspended": {"by": "boss", "reason": "spam", "at": old}}), ("fresh", {"last_login_at": None})):
            rec = {"name": name, "pw_hash": "scrypt$16384$8$1$00$00", "created_at": old, "last_login_at": old}
            rec.update(extra)
            acc[name] = {k: v for k, v in rec.items() if v is not None}
        acc["boss"]["pw_hash"] = scrypt_hash("bosspass1")
        json.dump(acc, open(acc_path, "w"))
        svc = Services(s, s.link_port, nickserv='expire_days = 30\nadmins = ["boss"]', store=acc_path)
        json.dump({"#oldchan": {"name": "#oldchan", "pw_hash": "x", "registered_at": old, "founder": "olduser", "successor": "=olduser",
                                "access": {"=olduser": "o", "=keeper": "v"}, "akick": {"=olduser": "x"}}},
                  open(os.path.join(svc.dir, "cs.json"), "w"))
        with svc:
            s.wait_services()
            p = s.client("probe")
            info = lambda a: " ".join(ns(p, f"INFO {a}", 0.8))
            assert "No such account" in info("olduser"), "100 days without a login: dropped"
            for kept in ("frozen", "boss", "keeper", "banned", "fresh"):
                assert f"Account {kept}" in info(kept), kept
            admin = s.client("boss")
            assert any("identified" in l.lower() or "logged in" in l.lower() for l in ns(admin, "IDENTIFY bosspass1", 1.5))
            seen = " ".join(ns(admin, "INFO keeper", 0.8))
            assert "Expires: in 30 day" in seen or "Expires: in 31 day" in seen, seen
            assert "Expires: never" in " ".join(ns(admin, "INFO frozen", 0.8))
            chan = " ".join(cs(p, "INFO #oldchan", 0.8))
            assert "Founder account" not in chan and "Successor" not in chan, chan
            out = svc.output()
            assert "account olduser expired after 30 days" in out and "removed as founder/access/successor" in out, out[-1500:]
            deadline = time.time() + 15  # ChanServ writes its store on its next flush
            while time.time() < deadline:
                rec = json.load(open(os.path.join(svc.dir, "cs.json")))["#oldchan"]
                if "=olduser" not in rec["access"]:
                    break
                time.sleep(0.5)
            assert rec["access"] == {"=keeper": "v"} and rec["founder"] == "" and "=olduser" in rec["akick"], rec
            # someone registering the freed name gets none of it
            n = s.client("olduser")
            assert any("registered" in l.lower() for l in ns(n, "REGISTER newpass123", 1.5))
            assert "Founder account" not in " ".join(cs(p, "INFO #oldchan", 0.8))
            # NOEXPIRE is an admin command
            assert any("Permission denied" in l for l in ns(n, "NOEXPIRE keeper ON", 0.8))
