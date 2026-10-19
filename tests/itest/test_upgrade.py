"""Upgrading from the built-in NickServ: the old data must be used in place and nothing lost."""
import base64, hashlib, json, os, shutil, subprocess, tempfile, time
from harness import Server, Client, SERVICES, SVC_NAME, SVC_PW


def scrypt_hash(pw):  # the ircd's format: scrypt$N$r$p$<salt hex>$<digest hex>
    salt = os.urandom(16)
    d = hashlib.scrypt(pw.encode(), salt=salt, n=16384, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=64)
    return f"scrypt$16384$8$1${salt.hex()}${d.hex()}"


def old_install():
    """A git-clone layout as the previous release left it: config/accounts.json (Python-era record shape: float
    created_at, no SCRAM verifier) and services/ with chanserv.json + a services.toml that has no [nickserv]."""
    root = tempfile.mkdtemp(prefix="itest-upg-")
    os.makedirs(f"{root}/config")
    os.makedirs(f"{root}/services")
    accounts = {"oldtimer": {"name": "OldTimer", "pw_hash": scrypt_hash("oldpass123"), "created_at": 1789387239.137449,
                             "email": "old@example.org", "nicks": ["oldalt"]}}
    chans = {"#oldchan": {"name": "#oldchan", "pw_hash": scrypt_hash("chanpw123"), "registered_at": 1789387000,
                          "guard": False}}
    with open(f"{root}/config/accounts.json", "w") as f:
        json.dump(accounts, f)
    with open(f"{root}/services/chanserv.json", "w") as f:
        json.dump(chans, f)
    return root


def test_old_accounts_and_channels_survive_the_upgrade():
    root = old_install()
    acc_before = open(f"{root}/config/accounts.json", "rb").read()
    cs_before = open(f"{root}/services/chanserv.json", "rb").read()
    # the old ircd config still has [accounts]: it must load (with a warning), not fail
    s = Server(cfg={"accounts": {"enabled": True, "store_file": "accounts.json", "max_accounts": 10000}})
    s.auto_services = False
    s.cfg["links"] = {"enabled": True, "mode": "hub", "bind": "127.0.0.1", "port": s.link_port}
    s.cfg["links.peers"] = [{"name": SVC_NAME, "password": SVC_PW}]
    proc = None
    try:
        s.start()
        assert "[accounts] in" in s.output() and "no longer used" in s.output()
        with open(f"{root}/services/services.toml", "w") as f:  # the old file: no [nickserv] section at all
            f.write(f'[link]\nhost = "127.0.0.1"\nport = {s.link_port}\nname = "{SVC_NAME}"\npassword = "{SVC_PW}"\n'
                    f'[chanserv]\nnick = "ChanServ"\n[storage]\npath = "chanserv.json"\nbackup_count = 5\n')
        proc = subprocess.Popen([SERVICES, "-c", "services.toml"], cwd=f"{root}/services",
                                stdout=open(f"{root}/svc.out", "w"), stderr=subprocess.STDOUT)
        s.wait_services()
        out = open(f"{root}/svc.out").read()
        assert "config/accounts.json (1 accounts)" in out, out  # found the existing database by itself

        c = Client(s.port, "u1", register=False, extra=["CAP REQ :sasl"])
        c.send("AUTHENTICATE PLAIN")
        c.expect(r"AUTHENTICATE \+")
        c.send("AUTHENTICATE " + base64.b64encode(b"\0OldTimer\0oldpass123").decode())
        assert c.saw(r" 903 ", 3), "the old password still works"
        g = s.client("oldalt")
        g.send("PRIVMSG NickServ :IDENTIFY oldpass123")
        assert g.saw(r"identified for OldTimer", 3), "grouped nicks still belong to the account"
        g.send("PRIVMSG NickServ :INFO")
        assert g.saw(r"Email: old@example.org", 2)
        g.send("PRIVMSG ChanServ :INFO #oldchan")
        assert g.saw(r"#oldchan", 2) and not g.saw(r"not registered", 0.3), "ChanServ registrations are intact"
        g.send("JOIN #oldchan")
        g.send("PRIVMSG ChanServ :IDENTIFY #oldchan chanpw123")
        assert g.saw(r"MODE #oldchan \+[oq] oldalt", 3), "the channel password still works"

        time.sleep(1.5)  # the SCRAM verifier derived at login is written back
        data = json.load(open(f"{root}/config/accounts.json"))
        rec = data["oldtimer"]
        orig = json.loads(acc_before)["oldtimer"]
        assert rec["pw_hash"] == orig["pw_hash"] and rec["created_at"] == orig["created_at"] and rec["nicks"] == ["oldalt"]
        assert "scram" in json.dumps(rec), "only additions"
        assert open(f"{root}/config/accounts.json.bak1", "rb").read() == acc_before, "the pre-upgrade file is kept as .bak1"
        assert json.load(open(f"{root}/services/chanserv.json"))["#oldchan"]["pw_hash"] == json.loads(cs_before)["#oldchan"]["pw_hash"]
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            proc.wait(5)
        s.stop()
        shutil.rmtree(root, ignore_errors=True)


def test_a_corrupt_account_file_is_never_replaced_by_an_empty_one():
    root = old_install()
    with open(f"{root}/config/accounts.json", "w") as f:
        f.write('{"oldtimer": {"name": "OldTi')  # truncated
    bad = open(f"{root}/config/accounts.json", "rb").read()
    with open(f"{root}/services/services.toml", "w") as f:
        f.write(f'[link]\nhost = "127.0.0.1"\nport = 1\nname = "{SVC_NAME}"\npassword = "{SVC_PW}"\n[storage]\npath = "chanserv.json"\n')
    try:
        p = subprocess.run([SERVICES, "-c", "services.toml"], cwd=f"{root}/services", capture_output=True, text=True, timeout=10)
        assert p.returncode != 0 and "refusing to start" in p.stdout + p.stderr, p.stdout + p.stderr
        assert open(f"{root}/config/accounts.json", "rb").read() == bad, "left untouched"
        # with a good backup it recovers from that instead
        shutil.copy(f"{root}/config/accounts.json", f"{root}/keep")
        with open(f"{root}/config/accounts.json.bak1", "w") as f:
            json.dump({"oldtimer": {"name": "OldTimer", "pw_hash": "x", "created_at": 1}}, f)
        p = subprocess.Popen([SERVICES, "-c", "services.toml"], cwd=f"{root}/services", stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        time.sleep(1.5)
        p.terminate()
        out = p.communicate(timeout=5)[0]
        assert "loaded backup" in out and "(1 accounts)" in out, out
        assert open(f"{root}/config/accounts.json.corrupt", "rb").read() == bad, "the bad file is kept aside"
    finally:
        shutil.rmtree(root, ignore_errors=True)
