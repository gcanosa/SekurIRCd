"""The stats feed (link.c SVCSTATS -> services/stats.c -> stats/events.log -> stats/netstats.py): with
stats/stats.toml [collector] enabled, services logs network snapshots, splits with their real reason, bans and every
server's stats line, and netstats turns a split into an outage."""
import json, os, shutil, sqlite3, subprocess, sys, tempfile, time
from harness import Network, SVC_NAME, SVC_PW, SERVICES

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OPERS = {"operators": [{"name": "boss", "password": "bosspw", "hosts": ["*@*"]}]}


def records(path):
    try:
        return [json.loads(l) for l in open(path) if l.strip()]
    except FileNotFoundError:
        return []


def wait_for(path, pred, what, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        recs = records(path)
        if pred(recs):
            return recs
        time.sleep(0.3)
    raise AssertionError(f"no {what} in {path}: {records(path)[-8:]}")


def test_stats_feed():
    base = tempfile.mkdtemp(prefix="itest-stats-")
    os.makedirs(f"{base}/services")
    os.makedirs(f"{base}/stats")
    log = f"{base}/stats/events.log"
    with open(f"{base}/stats/stats.toml", "w") as f:
        f.write('[collector]\nenabled = true\nsample_seconds = 10\n')
    net = Network(cfg=dict(OPERS, debug_channel={"stats_interval": 1}))
    hub = net.add("hub")
    net.add("leaf", parent="hub")
    for s in net.servers.values():
        s.auto_services = False
    hub.cfg["links.peers"].append({"name": SVC_NAME, "password": SVC_PW})
    svc = None
    try:
        net.start()
        with open(f"{base}/services/services.toml", "w") as f:
            f.write(f'[link]\nhost = "127.0.0.1"\nport = {hub.link_port}\nname = "{SVC_NAME}"\npassword = "{SVC_PW}"\n'
                    '[chanserv]\nnick = "ChanServ"\n[nickserv]\nstore_file = "accounts.json"\n[storage]\npath = "cs.json"\n')
        svc = subprocess.Popen([SERVICES, "-c", "services/services.toml"], cwd=base,
                               stdout=open(f"{base}/svc.out", "w"), stderr=subprocess.STDOUT)
        alice = net.client("leaf", "alice")
        op = net.client("hub", "boss")
        op.say("OPER boss bosspw", 0.5)
        # the first snapshot comes right after services link (SVCSTATS at session start)
        recs = wait_for(log, lambda r: any(x["k"] == "end" for x in r), "snapshot")
        kinds = [r["k"] for r in recs]
        assert kinds[:2] == ["svc", "session"], kinds[:4]
        i = kinds.index("net")
        assert kinds[i + 1:i + 3] == ["srv", "srv"] and "end" in kinds[i:], kinds
        # a later snapshot, once alice and boss are in (the first may predate them)
        recs = wait_for(log, lambda r: any(x["k"] == "net" and x["users"] >= 2 and x["opers"] >= 1 for x in r), "users", 25)
        last = max(i for i, r in enumerate(recs) if r["k"] == "net")
        srvs = {r["name"]: r for r in recs[last:] if r["k"] == "srv"}
        assert srvs["hub.test.net"]["hop"] == 0 and srvs["leaf.test.net"]["uplink"] == "hub.test.net", srvs
        assert srvs["hub.test.net"]["users"] == 1, "boss only: the services bots are not users"
        assert srvs["leaf.test.net"]["users"] == 1, "alice"

        op.say("GLINE *@203.0.113.7 1h :Spam bot", 0.5)
        wait_for(log, lambda r: any(x["k"] == "ban" and x["type"] == "G" and x["mask"] == "*@203.0.113.7" and
                                    x["reason"] == "Spam bot" and x["dur"] == 3600 for x in r), "G-line")
        wait_for(log, lambda r: any(x["k"] == "statline" and x["name"] == "leaf.test.net" and "sekurircd " in x["text"]
                                    for x in r), "the leaf's stats line")

        op.say("SQUIT leaf.test.net :maintenance", 1)
        recs = wait_for(log, lambda r: any(x["k"] == "link" and x["name"] == "leaf.test.net" for x in r), "relink")
        split = [r for r in recs if r["k"] == "split"]
        assert split and split[0]["name"] == "leaf.test.net" and split[0]["reason"] == "SQUIT by boss: maintenance", split
        alice.close()

        # netstats: the log becomes rows, the split an outage closed by the relink
        r = subprocess.run([sys.executable, f"{REPO}/stats/netstats.py", "-c", f"{base}/stats/stats.toml", "ingest"],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stdout + r.stderr
        db = sqlite3.connect(f"{base}/stats/stats.db")
        out = db.execute("SELECT name, end IS NOT NULL, reason FROM outages").fetchall()
        assert ("leaf.test.net", 1, "SQUIT by boss: maintenance") in out, out
        assert db.execute("SELECT COUNT(*) FROM bans WHERE type='G'").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM statline").fetchone()[0] >= 1
    finally:
        if svc and svc.poll() is None:
            svc.terminate()
            svc.wait(5)
        net.stop()
        shutil.rmtree(base, ignore_errors=True)


def test_collector_off_writes_nothing():
    """No stats/stats.toml: services never asks for the feed and writes no log."""
    base = tempfile.mkdtemp(prefix="itest-stats-")
    os.makedirs(f"{base}/services")
    net = Network()
    hub = net.add("hub")
    hub.auto_services = False
    hub.cfg["links.peers"].append({"name": SVC_NAME, "password": SVC_PW})
    svc = None
    try:
        net.start()
        with open(f"{base}/services/services.toml", "w") as f:
            f.write(f'[link]\nhost = "127.0.0.1"\nport = {hub.link_port}\nname = "{SVC_NAME}"\npassword = "{SVC_PW}"\n'
                    '[nickserv]\nenabled = false\n[storage]\npath = "cs.json"\n')
        svc = subprocess.Popen([SERVICES, "-c", "services/services.toml"], cwd=base,
                               stdout=open(f"{base}/svc.out", "w"), stderr=subprocess.STDOUT)
        time.sleep(2.5)
        assert svc.poll() is None, open(f"{base}/svc.out").read()
        assert not os.path.exists(f"{base}/stats"), "nothing created"
        assert "SVCSTATS" not in hub.output(), "never asked"
    finally:
        if svc and svc.poll() is None:
            svc.terminate()
            svc.wait(5)
        net.stop()
        shutil.rmtree(base, ignore_errors=True)


def test_collector_config_beside_services_toml():
    """make install keeps every config in one directory: stats.toml next to services.toml turns the collector on."""
    base = tempfile.mkdtemp(prefix="itest-stats-")
    log = f"{base}/state/events.log"
    os.makedirs(f"{base}/state")
    with open(f"{base}/stats.toml", "w") as f:
        f.write(f'[collector]\nenabled = true\nlog = "{log}"\n')
    net = Network()
    hub = net.add("hub")
    hub.auto_services = False
    hub.cfg["links.peers"].append({"name": SVC_NAME, "password": SVC_PW})
    svc = None
    try:
        net.start()
        with open(f"{base}/services.toml", "w") as f:
            f.write(f'[link]\nhost = "127.0.0.1"\nport = {hub.link_port}\nname = "{SVC_NAME}"\npassword = "{SVC_PW}"\n'
                    '[nickserv]\nenabled = false\n[storage]\npath = "cs.json"\n')
        svc = subprocess.Popen([SERVICES, "-c", f"{base}/services.toml"], cwd=base,
                               stdout=open(f"{base}/svc.out", "w"), stderr=subprocess.STDOUT)
        wait_for(log, lambda r: any(x["k"] == "end" for x in r), "snapshot at the absolute log path")
    finally:
        if svc and svc.poll() is None:
            svc.terminate()
            svc.wait(5)
        net.stop()
        shutil.rmtree(base, ignore_errors=True)
